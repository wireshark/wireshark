/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-h225.c                                                            */
/* ../../tools/asn2wrs.py -e -p h225 -c h225.cnf -s packet-h225-template h225.asn */

/* Input file: packet-h225-template.c */

#line 1 "packet-h225-template.c"
/* packet-h225.c
 * Routines for h225 packet dissection
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
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
 * To quote the author of the previous H323/H225/H245 dissector:
 *   "This is a complete replacement of the previous limitied dissector
 * that Ronnie was crazy enough to write by hand. It was a lot of time
 * to hack it by hand, but it is incomplete and buggy and it is good when
 * it will go away."
 * Ronnie did a great job and all the VoIP users had made good use of it!
 * Credit to Tomas Kukosa for developing the Asn2eth compiler.
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include <epan/prefs.h>
#include <epan/oid_resolv.h>
#include "tap.h"
#include "packet-tpkt.h"
#include "packet-per.h"
#include "packet-h225.h"
#include <epan/t35.h>
#include <epan/h225-persistentdata.h>
#include "packet-h235.h"
#include "packet-h245.h"
#include "packet-q931.h"

/*---------------------------------------------------------------------------*/
/* next tvb list - can be moved to some more common file if other dissector needs it */

#include <epan/emem.h>

typedef struct next_tvb_item {
  struct next_tvb_item *next;
  struct next_tvb_item *previous;
  dissector_handle_t handle;
  tvbuff_t *tvb;
  proto_tree *tree;
} next_tvb_item_t;

typedef struct {
  next_tvb_item_t *first;
  next_tvb_item_t *last;
  int count;
} next_tvb_list_t;

void next_tvb_init(next_tvb_list_t *list);
void next_tvb_add(next_tvb_list_t *list, tvbuff_t *tvb, proto_tree *tree, dissector_handle_t handle);
void next_tvb_call(next_tvb_list_t *list, packet_info *pinfo, proto_tree *tree, dissector_handle_t handle, dissector_handle_t data_handle);

void next_tvb_init(next_tvb_list_t *list) {
  list->first = NULL;
  list->last = NULL;
  list->count = 0;
}

void next_tvb_add(next_tvb_list_t *list, tvbuff_t *tvb, proto_tree *tree, dissector_handle_t handle) {
  next_tvb_item_t *item;

  item = ep_alloc(sizeof(next_tvb_item_t));

  item->handle = handle;
  item->tvb = tvb;
  item->tree = tree;

  if (list->last) {
    list->last->next = item;
  } else {
    list->first = item;
  }
  item->next = NULL;
  item->previous = list->last;
  list->last = item;
  list->count++;
}

void next_tvb_call(next_tvb_list_t *list, packet_info *pinfo, proto_tree *tree, dissector_handle_t handle, dissector_handle_t data_handle) {
  next_tvb_item_t *item;

  item = list->first;
  while (item) {
    if (item->tvb && tvb_length(item->tvb)) {
      call_dissector((item->handle) ? item->handle : ((handle) ? handle : data_handle), item->tvb, pinfo, (item->tree) ? item->tree : tree);
    }
    item = item->next;
  }
}

/*---------------------------------------------------------------------------*/

#define PNAME  "H323-MESSAGES"
#define PSNAME "H.225.0"
#define PFNAME "h225"

#define UDP_PORT_RAS1 1718
#define UDP_PORT_RAS2 1719
#define TCP_PORT_CS   1720

static void reset_h225_packet_info(h225_packet_info *pi);
static void ras_call_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, h225_packet_info *pi);
static int dissect_h225_H323UserInformation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static h225_packet_info pi_arr[5]; /* We assuming a maximum of 5 H225 messaages per packet */
static int pi_current=0;
h225_packet_info *h225_pi=NULL;

static dissector_handle_t h225ras_handle;
static dissector_handle_t H323UserInformation_handle;
static dissector_handle_t data_handle;
/* Subdissector tables */
static dissector_table_t nsp_object_dissector_table;
static dissector_table_t nsp_h221_dissector_table;
static dissector_table_t tp_dissector_table;


static dissector_handle_t h245_handle=NULL;
static dissector_handle_t h245dg_handle=NULL;
static dissector_handle_t h4501_handle=NULL;

static dissector_handle_t nsp_handle;
static dissector_handle_t tp_handle;

static next_tvb_list_t h245_list;
static next_tvb_list_t tp_list;

/* Initialize the protocol and registered fields */
static int h225_tap = -1;
static int proto_h225 = -1;

static int hf_h225_H323_UserInformation = -1;
static int hf_h225_RasMessage = -1;
static int hf_h221Manufacturer = -1;
static int hf_h225_ras_req_frame = -1;
static int hf_h225_ras_rsp_frame = -1;
static int hf_h225_ras_dup = -1;
static int hf_h225_ras_deltatime = -1;
static int hf_h225_fastStart_item_length = -1; 


/*--- Included file: packet-h225-hf.c ---*/
#line 1 "packet-h225-hf.c"
static int hf_h225_h323_uu_pdu = -1;              /* H323_UU_PDU */
static int hf_h225_user_data = -1;                /* T_user_data */
static int hf_h225_protocol_discriminator = -1;   /* INTEGER_0_255 */
static int hf_h225_user_information = -1;         /* OCTET_STRING_SIZE_1_131 */
static int hf_h225_h323_message_body = -1;        /* T_h323_message_body */
static int hf_h225_setup = -1;                    /* Setup_UUIE */
static int hf_h225_callProceeding = -1;           /* CallProceeding_UUIE */
static int hf_h225_connect = -1;                  /* Connect_UUIE */
static int hf_h225_alerting = -1;                 /* Alerting_UUIE */
static int hf_h225_information = -1;              /* Information_UUIE */
static int hf_h225_releaseComplete = -1;          /* ReleaseComplete_UUIE */
static int hf_h225_facility = -1;                 /* Facility_UUIE */
static int hf_h225_progress = -1;                 /* Progress_UUIE */
static int hf_h225_empty_flg = -1;                /* T_empty */
static int hf_h225_status = -1;                   /* Status_UUIE */
static int hf_h225_statusInquiry = -1;            /* StatusInquiry_UUIE */
static int hf_h225_setupAcknowledge = -1;         /* SetupAcknowledge_UUIE */
static int hf_h225_notify = -1;                   /* Notify_UUIE */
static int hf_h225_nonStandardData = -1;          /* NonStandardParameter */
static int hf_h225_h4501SupplementaryService = -1;  /* T_h4501SupplementaryService */
static int hf_h225_h4501SupplementaryService_item = -1;  /* T_h4501SupplementaryService_item */
static int hf_h225_h245Tunneling = -1;            /* T_h245Tunneling */
static int hf_h225_h245Control = -1;              /* H245Control */
static int hf_h225_nonStandardControl = -1;       /* SEQUENCE_OF_NonStandardParameter */
static int hf_h225_nonStandardControl_item = -1;  /* NonStandardParameter */
static int hf_h225_callLinkage = -1;              /* CallLinkage */
static int hf_h225_tunnelledSignallingMessage = -1;  /* T_tunnelledSignallingMessage */
static int hf_h225_tunnelledProtocolID = -1;      /* TunnelledProtocol */
static int hf_h225_messageContent = -1;           /* T_messageContent */
static int hf_h225_messageContent_item = -1;      /* T_messageContent_item */
static int hf_h225_tunnellingRequired = -1;       /* NULL */
static int hf_h225_provisionalRespToH245Tunneling = -1;  /* NULL */
static int hf_h225_stimulusControl = -1;          /* StimulusControl */
static int hf_h225_genericData = -1;              /* SEQUENCE_OF_GenericData */
static int hf_h225_genericData_item = -1;         /* GenericData */
static int hf_h225_H245Control_item = -1;         /* H245Control_item */
static int hf_h225_nonStandard = -1;              /* NonStandardParameter */
static int hf_h225_isText = -1;                   /* NULL */
static int hf_h225_h248Message = -1;              /* OCTET_STRING */
static int hf_h225_protocolIdentifier = -1;       /* ProtocolIdentifier */
static int hf_h225_uUIE_destinationInfo = -1;     /* EndpointType */
static int hf_h225_h245Address = -1;              /* H245TransportAddress */
static int hf_h225_callIdentifier = -1;           /* CallIdentifier */
static int hf_h225_h245SecurityMode = -1;         /* H245Security */
static int hf_h225_tokens = -1;                   /* SEQUENCE_OF_ClearToken */
static int hf_h225_tokens_item = -1;              /* ClearToken */
static int hf_h225_cryptoTokens = -1;             /* SEQUENCE_OF_CryptoH323Token */
static int hf_h225_cryptoTokens_item = -1;        /* CryptoH323Token */
static int hf_h225_fastStart = -1;                /* FastStart */
static int hf_h225_multipleCalls = -1;            /* BOOLEAN */
static int hf_h225_maintainConnection = -1;       /* BOOLEAN */
static int hf_h225_alertingAddress = -1;          /* SEQUENCE_OF_AliasAddress */
static int hf_h225_alertingAddress_item = -1;     /* AliasAddress */
static int hf_h225_presentationIndicator = -1;    /* PresentationIndicator */
static int hf_h225_screeningIndicator = -1;       /* ScreeningIndicator */
static int hf_h225_fastConnectRefused = -1;       /* NULL */
static int hf_h225_serviceControl = -1;           /* SEQUENCE_OF_ServiceControlSession */
static int hf_h225_serviceControl_item = -1;      /* ServiceControlSession */
static int hf_h225_capacity = -1;                 /* CallCapacity */
static int hf_h225_featureSet = -1;               /* FeatureSet */
static int hf_h225_conferenceID = -1;             /* ConferenceIdentifier */
static int hf_h225_language = -1;                 /* Language */
static int hf_h225_language_item = -1;            /* IA5String_SIZE_1_32 */
static int hf_h225_connectedAddress = -1;         /* SEQUENCE_OF_AliasAddress */
static int hf_h225_connectedAddress_item = -1;    /* AliasAddress */
static int hf_h225_circuitInfo = -1;              /* CircuitInfo */
static int hf_h225_releaseCompleteReason = -1;    /* ReleaseCompleteReason */
static int hf_h225_busyAddress = -1;              /* SEQUENCE_OF_AliasAddress */
static int hf_h225_busyAddress_item = -1;         /* AliasAddress */
static int hf_h225_noBandwidth = -1;              /* NULL */
static int hf_h225_gatekeeperResources = -1;      /* NULL */
static int hf_h225_unreachableDestination = -1;   /* NULL */
static int hf_h225_destinationRejection = -1;     /* NULL */
static int hf_h225_invalidRevision = -1;          /* NULL */
static int hf_h225_noPermission = -1;             /* NULL */
static int hf_h225_unreachableGatekeeper = -1;    /* NULL */
static int hf_h225_gatewayResources = -1;         /* NULL */
static int hf_h225_badFormatAddress = -1;         /* NULL */
static int hf_h225_adaptiveBusy = -1;             /* NULL */
static int hf_h225_inConf = -1;                   /* NULL */
static int hf_h225_undefinedReason = -1;          /* NULL */
static int hf_h225_facilityCallDeflection = -1;   /* NULL */
static int hf_h225_securityDenied = -1;           /* NULL */
static int hf_h225_calledPartyNotRegistered = -1;  /* NULL */
static int hf_h225_callerNotRegistered = -1;      /* NULL */
static int hf_h225_newConnectionNeeded = -1;      /* NULL */
static int hf_h225_nonStandardReason = -1;        /* NonStandardParameter */
static int hf_h225_replaceWithConferenceInvite = -1;  /* ConferenceIdentifier */
static int hf_h225_genericDataReason = -1;        /* NULL */
static int hf_h225_neededFeatureNotSupported = -1;  /* NULL */
static int hf_h225_tunnelledSignallingRejected = -1;  /* NULL */
static int hf_h225_invalidCID = -1;               /* NULL */
static int hf_h225_rLC_securityError = -1;        /* SecurityErrors */
static int hf_h225_hopCountExceeded = -1;         /* NULL */
static int hf_h225_sourceAddress = -1;            /* SEQUENCE_OF_AliasAddress */
static int hf_h225_sourceAddress_item = -1;       /* AliasAddress */
static int hf_h225_setup_UUIE_sourceInfo = -1;    /* EndpointType */
static int hf_h225_destinationAddress = -1;       /* SEQUENCE_OF_AliasAddress */
static int hf_h225_destinationAddress_item = -1;  /* AliasAddress */
static int hf_h225_destCallSignalAddress = -1;    /* TransportAddress */
static int hf_h225_destExtraCallInfo = -1;        /* SEQUENCE_OF_AliasAddress */
static int hf_h225_destExtraCallInfo_item = -1;   /* AliasAddress */
static int hf_h225_destExtraCRV = -1;             /* SEQUENCE_OF_CallReferenceValue */
static int hf_h225_destExtraCRV_item = -1;        /* CallReferenceValue */
static int hf_h225_activeMC = -1;                 /* BOOLEAN */
static int hf_h225_conferenceGoal = -1;           /* T_conferenceGoal */
static int hf_h225_create = -1;                   /* NULL */
static int hf_h225_join = -1;                     /* NULL */
static int hf_h225_invite = -1;                   /* NULL */
static int hf_h225_capability_negotiation = -1;   /* NULL */
static int hf_h225_callIndependentSupplementaryService = -1;  /* NULL */
static int hf_h225_callServices = -1;             /* QseriesOptions */
static int hf_h225_callType = -1;                 /* CallType */
static int hf_h225_sourceCallSignalAddress = -1;  /* TransportAddress */
static int hf_h225_uUIE_remoteExtensionAddress = -1;  /* AliasAddress */
static int hf_h225_h245SecurityCapability = -1;   /* SEQUENCE_OF_H245Security */
static int hf_h225_h245SecurityCapability_item = -1;  /* H245Security */
static int hf_h225_mediaWaitForConnect = -1;      /* BOOLEAN */
static int hf_h225_canOverlapSend = -1;           /* BOOLEAN */
static int hf_h225_endpointIdentifier = -1;       /* EndpointIdentifier */
static int hf_h225_connectionParameters = -1;     /* T_connectionParameters */
static int hf_h225_connectionType = -1;           /* ScnConnectionType */
static int hf_h225_numberOfScnConnections = -1;   /* INTEGER_0_65535 */
static int hf_h225_connectionAggregation = -1;    /* ScnConnectionAggregation */
static int hf_h225_symmetricOperationRequired = -1;  /* NULL */
static int hf_h225_desiredProtocols = -1;         /* SEQUENCE_OF_SupportedProtocols */
static int hf_h225_desiredProtocols_item = -1;    /* SupportedProtocols */
static int hf_h225_neededFeatures = -1;           /* SEQUENCE_OF_FeatureDescriptor */
static int hf_h225_neededFeatures_item = -1;      /* FeatureDescriptor */
static int hf_h225_desiredFeatures = -1;          /* SEQUENCE_OF_FeatureDescriptor */
static int hf_h225_desiredFeatures_item = -1;     /* FeatureDescriptor */
static int hf_h225_supportedFeatures = -1;        /* SEQUENCE_OF_FeatureDescriptor */
static int hf_h225_supportedFeatures_item = -1;   /* FeatureDescriptor */
static int hf_h225_parallelH245Control = -1;      /* ParallelH245Control */
static int hf_h225_additionalSourceAddresses = -1;  /* SEQUENCE_OF_ExtendedAliasAddress */
static int hf_h225_additionalSourceAddresses_item = -1;  /* ExtendedAliasAddress */
static int hf_h225_hopCount_1_31 = -1;            /* INTEGER_1_31 */
static int hf_h225_ParallelH245Control_item = -1;  /* ParallelH245Control_item */
static int hf_h225_unknown = -1;                  /* NULL */
static int hf_h225_bChannel = -1;                 /* NULL */
static int hf_h225_hybrid2x64 = -1;               /* NULL */
static int hf_h225_hybrid384 = -1;                /* NULL */
static int hf_h225_hybrid1536 = -1;               /* NULL */
static int hf_h225_hybrid1920 = -1;               /* NULL */
static int hf_h225_multirate = -1;                /* NULL */
static int hf_h225_auto = -1;                     /* NULL */
static int hf_h225_none = -1;                     /* NULL */
static int hf_h225_h221 = -1;                     /* NULL */
static int hf_h225_bonded_mode1 = -1;             /* NULL */
static int hf_h225_bonded_mode2 = -1;             /* NULL */
static int hf_h225_bonded_mode3 = -1;             /* NULL */
static int hf_h225_presentationAllowed = -1;      /* NULL */
static int hf_h225_presentationRestricted = -1;   /* NULL */
static int hf_h225_addressNotAvailable = -1;      /* NULL */
static int hf_h225_alternativeAddress = -1;       /* TransportAddress */
static int hf_h225_alternativeAliasAddress = -1;  /* SEQUENCE_OF_AliasAddress */
static int hf_h225_alternativeAliasAddress_item = -1;  /* AliasAddress */
static int hf_h225_facilityReason = -1;           /* FacilityReason */
static int hf_h225_conferences = -1;              /* SEQUENCE_OF_ConferenceList */
static int hf_h225_conferences_item = -1;         /* ConferenceList */
static int hf_h225_conferenceAlias = -1;          /* AliasAddress */
static int hf_h225_routeCallToGatekeeper = -1;    /* NULL */
static int hf_h225_callForwarded = -1;            /* NULL */
static int hf_h225_routeCallToMC = -1;            /* NULL */
static int hf_h225_conferenceListChoice = -1;     /* NULL */
static int hf_h225_startH245 = -1;                /* NULL */
static int hf_h225_noH245 = -1;                   /* NULL */
static int hf_h225_newTokens = -1;                /* NULL */
static int hf_h225_featureSetUpdate = -1;         /* NULL */
static int hf_h225_forwardedElements = -1;        /* NULL */
static int hf_h225_transportedInformation = -1;   /* NULL */
static int hf_h225_FastStart_item = -1;           /* FastStart_item */
static int hf_h225_ipAddress = -1;                /* T_ipAddress */
static int hf_h225_ipV4 = -1;                     /* IpV4 */
static int hf_h225_ipV4_port = -1;                /* INTEGER_0_65535 */
static int hf_h225_ipSourceRoute = -1;            /* T_ipSourceRoute */
static int hf_h225_src_route_ipV4 = -1;           /* OCTET_STRING_SIZE_4 */
static int hf_h225_ipV4_src_port = -1;            /* INTEGER_0_65535 */
static int hf_h225_route = -1;                    /* T_route */
static int hf_h225_route_item = -1;               /* OCTET_STRING_SIZE_4 */
static int hf_h225_routing = -1;                  /* T_routing */
static int hf_h225_strict = -1;                   /* NULL */
static int hf_h225_loose = -1;                    /* NULL */
static int hf_h225_ipxAddress = -1;               /* T_ipxAddress */
static int hf_h225_node = -1;                     /* OCTET_STRING_SIZE_6 */
static int hf_h225_netnum = -1;                   /* OCTET_STRING_SIZE_4 */
static int hf_h225_ipx_port = -1;                 /* OCTET_STRING_SIZE_2 */
static int hf_h225_ip6Address = -1;               /* T_ip6Address */
static int hf_h225_ipV6 = -1;                     /* OCTET_STRING_SIZE_16 */
static int hf_h225_ipV6_port = -1;                /* INTEGER_0_65535 */
static int hf_h225_netBios = -1;                  /* OCTET_STRING_SIZE_16 */
static int hf_h225_nsap = -1;                     /* OCTET_STRING_SIZE_1_20 */
static int hf_h225_nonStandardAddress = -1;       /* NonStandardParameter */
static int hf_h225_h245ipAddress = -1;            /* T_h245ipAddress */
static int hf_h225_h245ipv4 = -1;                 /* T_h245ipv4 */
static int hf_h225_h245ipv4port = -1;             /* T_h245ipv4port */
static int hf_h225_h245ipSourceRoute = -1;        /* T_h245ipSourceRoute */
static int hf_h225_h245routeip = -1;              /* OCTET_STRING_SIZE_4 */
static int hf_h225_h245routeport = -1;            /* INTEGER_0_65535 */
static int hf_h225_h245route = -1;                /* T_h245route */
static int hf_h225_h245route_item = -1;           /* OCTET_STRING_SIZE_4 */
static int hf_h225_h245routing = -1;              /* T_h245routing */
static int hf_h225_h245ipxAddress = -1;           /* T_h245ipxAddress */
static int hf_h225_h245ipxport = -1;              /* OCTET_STRING_SIZE_2 */
static int hf_h225_h245ip6Address = -1;           /* T_h245ip6Address */
static int hf_h225_h245ipv6 = -1;                 /* OCTET_STRING_SIZE_16 */
static int hf_h225_h245ipv6port = -1;             /* INTEGER_0_65535 */
static int hf_h225_h245netBios = -1;              /* OCTET_STRING_SIZE_16 */
static int hf_h225_h245nsap = -1;                 /* OCTET_STRING_SIZE_1_20 */
static int hf_h225_vendor = -1;                   /* VendorIdentifier */
static int hf_h225_gatekeeper = -1;               /* GatekeeperInfo */
static int hf_h225_gateway = -1;                  /* GatewayInfo */
static int hf_h225_mcu = -1;                      /* McuInfo */
static int hf_h225_terminal = -1;                 /* TerminalInfo */
static int hf_h225_mc = -1;                       /* BOOLEAN */
static int hf_h225_undefinedNode = -1;            /* BOOLEAN */
static int hf_h225_set = -1;                      /* BIT_STRING_SIZE_32 */
static int hf_h225_supportedTunnelledProtocols = -1;  /* SEQUENCE_OF_TunnelledProtocol */
static int hf_h225_supportedTunnelledProtocols_item = -1;  /* TunnelledProtocol */
static int hf_h225_protocol = -1;                 /* SEQUENCE_OF_SupportedProtocols */
static int hf_h225_protocol_item = -1;            /* SupportedProtocols */
static int hf_h225_h310 = -1;                     /* H310Caps */
static int hf_h225_h320 = -1;                     /* H320Caps */
static int hf_h225_h321 = -1;                     /* H321Caps */
static int hf_h225_h322 = -1;                     /* H322Caps */
static int hf_h225_h323 = -1;                     /* H323Caps */
static int hf_h225_h324 = -1;                     /* H324Caps */
static int hf_h225_voice = -1;                    /* VoiceCaps */
static int hf_h225_t120_only = -1;                /* T120OnlyCaps */
static int hf_h225_nonStandardProtocol = -1;      /* NonStandardProtocol */
static int hf_h225_t38FaxAnnexbOnly = -1;         /* T38FaxAnnexbOnlyCaps */
static int hf_h225_sip = -1;                      /* SIPCaps */
static int hf_h225_dataRatesSupported = -1;       /* SEQUENCE_OF_DataRate */
static int hf_h225_dataRatesSupported_item = -1;  /* DataRate */
static int hf_h225_supportedPrefixes = -1;        /* SEQUENCE_OF_SupportedPrefix */
static int hf_h225_supportedPrefixes_item = -1;   /* SupportedPrefix */
static int hf_h225_t38FaxProtocol = -1;           /* DataProtocolCapability */
static int hf_h225_t38FaxProfile = -1;            /* T38FaxProfile */
static int hf_h225_vendorIdentifier_vendor = -1;  /* H221NonStandard */
static int hf_h225_productId = -1;                /* OCTET_STRING_SIZE_1_256 */
static int hf_h225_versionId = -1;                /* OCTET_STRING_SIZE_1_256 */
static int hf_h225_enterpriseNumber = -1;         /* OBJECT_IDENTIFIER */
static int hf_h225_t35CountryCode = -1;           /* T_t35CountryCode */
static int hf_h225_t35Extension = -1;             /* T_t35Extension */
static int hf_h225_manufacturerCode = -1;         /* T_manufacturerCode */
static int hf_h225_tunnelledProtocol_id = -1;     /* TunnelledProtocol_id */
static int hf_h225_tunnelledProtocolObjectID = -1;  /* T_tunnelledProtocolObjectID */
static int hf_h225_tunnelledProtocolAlternateID = -1;  /* TunnelledProtocolAlternateIdentifier */
static int hf_h225_subIdentifier = -1;            /* IA5String_SIZE_1_64 */
static int hf_h225_protocolType = -1;             /* IA5String_SIZE_1_64 */
static int hf_h225_protocolVariant = -1;          /* IA5String_SIZE_1_64 */
static int hf_h225_nonStandardIdentifier = -1;    /* NonStandardIdentifier */
static int hf_h225_nsp_data = -1;                 /* T_data */
static int hf_h225_nsiOID = -1;                   /* T_object */
static int hf_h225_h221NonStandard = -1;          /* H221NonStandard */
static int hf_h225_dialedDigits = -1;             /* DialedDigits */
static int hf_h225_h323_ID = -1;                  /* BMPString_SIZE_1_256 */
static int hf_h225_url_ID = -1;                   /* IA5String_SIZE_1_512 */
static int hf_h225_transportID = -1;              /* TransportAddress */
static int hf_h225_email_ID = -1;                 /* IA5String_SIZE_1_512 */
static int hf_h225_partyNumber = -1;              /* PartyNumber */
static int hf_h225_mobileUIM = -1;                /* MobileUIM */
static int hf_h225_wildcard = -1;                 /* AliasAddress */
static int hf_h225_range = -1;                    /* T_range */
static int hf_h225_startOfRange = -1;             /* PartyNumber */
static int hf_h225_endOfRange = -1;               /* PartyNumber */
static int hf_h225_e164Number = -1;               /* PublicPartyNumber */
static int hf_h225_dataPartyNumber = -1;          /* NumberDigits */
static int hf_h225_telexPartyNumber = -1;         /* NumberDigits */
static int hf_h225_privateNumber = -1;            /* PrivatePartyNumber */
static int hf_h225_nationalStandardPartyNumber = -1;  /* NumberDigits */
static int hf_h225_publicTypeOfNumber = -1;       /* PublicTypeOfNumber */
static int hf_h225_publicNumberDigits = -1;       /* NumberDigits */
static int hf_h225_privateTypeOfNumber = -1;      /* PrivateTypeOfNumber */
static int hf_h225_privateNumberDigits = -1;      /* NumberDigits */
static int hf_h225_internationalNumber = -1;      /* NULL */
static int hf_h225_nationalNumber = -1;           /* NULL */
static int hf_h225_networkSpecificNumber = -1;    /* NULL */
static int hf_h225_subscriberNumber = -1;         /* NULL */
static int hf_h225_abbreviatedNumber = -1;        /* NULL */
static int hf_h225_level2RegionalNumber = -1;     /* NULL */
static int hf_h225_level1RegionalNumber = -1;     /* NULL */
static int hf_h225_pISNSpecificNumber = -1;       /* NULL */
static int hf_h225_localNumber = -1;              /* NULL */
static int hf_h225_ansi_41_uim = -1;              /* ANSI_41_UIM */
static int hf_h225_gsm_uim = -1;                  /* GSM_UIM */
static int hf_h225_imsi = -1;                     /* TBCD_STRING */
static int hf_h225_min = -1;                      /* TBCD_STRING */
static int hf_h225_mdn = -1;                      /* TBCD_STRING */
static int hf_h225_msisdn = -1;                   /* TBCD_STRING */
static int hf_h225_esn = -1;                      /* TBCD_STRING */
static int hf_h225_mscid = -1;                    /* TBCD_STRING */
static int hf_h225_system_id = -1;                /* T_system_id */
static int hf_h225_sid = -1;                      /* TBCD_STRING */
static int hf_h225_mid = -1;                      /* TBCD_STRING */
static int hf_h225_systemMyTypeCode = -1;         /* OCTET_STRING_SIZE_1 */
static int hf_h225_systemAccessType = -1;         /* OCTET_STRING_SIZE_1 */
static int hf_h225_qualificationInformationCode = -1;  /* OCTET_STRING_SIZE_1 */
static int hf_h225_sesn = -1;                     /* TBCD_STRING */
static int hf_h225_soc = -1;                      /* TBCD_STRING */
static int hf_h225_tmsi = -1;                     /* OCTET_STRING_SIZE_1_4 */
static int hf_h225_imei = -1;                     /* TBCD_STRING */
static int hf_h225_hplmn = -1;                    /* TBCD_STRING */
static int hf_h225_vplmn = -1;                    /* TBCD_STRING */
static int hf_h225_address = -1;                  /* AliasAddress */
static int hf_h225_aliasAddress = -1;             /* SEQUENCE_OF_AliasAddress */
static int hf_h225_aliasAddress_item = -1;        /* AliasAddress */
static int hf_h225_callSignalAddress = -1;        /* SEQUENCE_OF_TransportAddress */
static int hf_h225_callSignalAddress_item = -1;   /* TransportAddress */
static int hf_h225_rasAddress = -1;               /* SEQUENCE_OF_TransportAddress */
static int hf_h225_rasAddress_item = -1;          /* TransportAddress */
static int hf_h225_endpointType = -1;             /* EndpointType */
static int hf_h225_priority = -1;                 /* INTEGER_0_127 */
static int hf_h225_remoteExtensionAddress = -1;   /* SEQUENCE_OF_AliasAddress */
static int hf_h225_remoteExtensionAddress_item = -1;  /* AliasAddress */
static int hf_h225_alternateTransportAddresses = -1;  /* AlternateTransportAddresses */
static int hf_h225_annexE = -1;                   /* SEQUENCE_OF_TransportAddress */
static int hf_h225_annexE_item = -1;              /* TransportAddress */
static int hf_h225_sctp = -1;                     /* SEQUENCE_OF_TransportAddress */
static int hf_h225_sctp_item = -1;                /* TransportAddress */
static int hf_h225_tcp = -1;                      /* NULL */
static int hf_h225_annexE_flg = -1;               /* NULL */
static int hf_h225_sctp_flg = -1;                 /* NULL */
static int hf_h225_alternateGK_rasAddress = -1;   /* TransportAddress */
static int hf_h225_gatekeeperIdentifier = -1;     /* GatekeeperIdentifier */
static int hf_h225_needToRegister = -1;           /* BOOLEAN */
static int hf_h225_alternateGatekeeper = -1;      /* SEQUENCE_OF_AlternateGK */
static int hf_h225_alternateGatekeeper_item = -1;  /* AlternateGK */
static int hf_h225_altGKisPermanent = -1;         /* BOOLEAN */
static int hf_h225_default = -1;                  /* NULL */
static int hf_h225_encryption = -1;               /* SecurityServiceMode */
static int hf_h225_authenticaton = -1;            /* SecurityServiceMode */
static int hf_h225_securityCapabilities_integrity = -1;  /* SecurityServiceMode */
static int hf_h225_securityWrongSyncTime = -1;    /* NULL */
static int hf_h225_securityReplay = -1;           /* NULL */
static int hf_h225_securityWrongGeneralID = -1;   /* NULL */
static int hf_h225_securityWrongSendersID = -1;   /* NULL */
static int hf_h225_securityIntegrityFailed = -1;  /* NULL */
static int hf_h225_securityWrongOID = -1;         /* NULL */
static int hf_h225_securityDHmismatch = -1;       /* NULL */
static int hf_h225_securityCertificateExpired = -1;  /* NULL */
static int hf_h225_securityCertificateDateInvalid = -1;  /* NULL */
static int hf_h225_securityCertificateRevoked = -1;  /* NULL */
static int hf_h225_securityCertificateNotReadable = -1;  /* NULL */
static int hf_h225_securityCertificateSignatureInvalid = -1;  /* NULL */
static int hf_h225_securityCertificateMissing = -1;  /* NULL */
static int hf_h225_securityCertificateIncomplete = -1;  /* NULL */
static int hf_h225_securityUnsupportedCertificateAlgOID = -1;  /* NULL */
static int hf_h225_securityUnknownCA = -1;        /* NULL */
static int hf_h225_noSecurity = -1;               /* NULL */
static int hf_h225_tls = -1;                      /* SecurityCapabilities */
static int hf_h225_ipsec = -1;                    /* SecurityCapabilities */
static int hf_h225_q932Full = -1;                 /* BOOLEAN */
static int hf_h225_q951Full = -1;                 /* BOOLEAN */
static int hf_h225_q952Full = -1;                 /* BOOLEAN */
static int hf_h225_q953Full = -1;                 /* BOOLEAN */
static int hf_h225_q955Full = -1;                 /* BOOLEAN */
static int hf_h225_q956Full = -1;                 /* BOOLEAN */
static int hf_h225_q957Full = -1;                 /* BOOLEAN */
static int hf_h225_q954Info = -1;                 /* Q954Details */
static int hf_h225_conferenceCalling = -1;        /* BOOLEAN */
static int hf_h225_threePartyService = -1;        /* BOOLEAN */
static int hf_h225_guid = -1;                     /* T_guid */
static int hf_h225_isoAlgorithm = -1;             /* OBJECT_IDENTIFIER */
static int hf_h225_hMAC_MD5 = -1;                 /* NULL */
static int hf_h225_hMAC_iso10118_2_s = -1;        /* EncryptIntAlg */
static int hf_h225_hMAC_iso10118_2_l = -1;        /* EncryptIntAlg */
static int hf_h225_hMAC_iso10118_3 = -1;          /* OBJECT_IDENTIFIER */
static int hf_h225_digSig = -1;                   /* NULL */
static int hf_h225_iso9797 = -1;                  /* OBJECT_IDENTIFIER */
static int hf_h225_nonIsoIM = -1;                 /* NonIsoIntegrityMechanism */
static int hf_h225_algorithmOID = -1;             /* OBJECT_IDENTIFIER */
static int hf_h225_icv = -1;                      /* BIT_STRING */
static int hf_h225_cryptoEPPwdHash = -1;          /* T_cryptoEPPwdHash */
static int hf_h225_alias = -1;                    /* AliasAddress */
static int hf_h225_timeStamp = -1;                /* TimeStamp */
static int hf_h225_token = -1;                    /* HASHEDxxx */
static int hf_h225_cryptoGKPwdHash = -1;          /* T_cryptoGKPwdHash */
static int hf_h225_gatekeeperId = -1;             /* GatekeeperIdentifier */
static int hf_h225_cryptoEPPwdEncr = -1;          /* ENCRYPTEDxxx */
static int hf_h225_cryptoGKPwdEncr = -1;          /* ENCRYPTEDxxx */
static int hf_h225_cryptoEPCert = -1;             /* SIGNEDxxx */
static int hf_h225_cryptoGKCert = -1;             /* SIGNEDxxx */
static int hf_h225_cryptoFastStart = -1;          /* SIGNEDxxx */
static int hf_h225_nestedcryptoToken = -1;        /* CryptoToken */
static int hf_h225_channelRate = -1;              /* BandWidth */
static int hf_h225_channelMultiplier = -1;        /* INTEGER_1_256 */
static int hf_h225_globalCallId = -1;             /* GloballyUniqueID */
static int hf_h225_threadId = -1;                 /* GloballyUniqueID */
static int hf_h225_prefix = -1;                   /* AliasAddress */
static int hf_h225_canReportCallCapacity = -1;    /* BOOLEAN */
static int hf_h225_capacityReportingSpecification_when = -1;  /* CapacityReportingSpecification_when */
static int hf_h225_callStart = -1;                /* NULL */
static int hf_h225_callEnd = -1;                  /* NULL */
static int hf_h225_maximumCallCapacity = -1;      /* CallCapacityInfo */
static int hf_h225_currentCallCapacity = -1;      /* CallCapacityInfo */
static int hf_h225_voiceGwCallsAvailable = -1;    /* SEQUENCE_OF_CallsAvailable */
static int hf_h225_voiceGwCallsAvailable_item = -1;  /* CallsAvailable */
static int hf_h225_h310GwCallsAvailable = -1;     /* SEQUENCE_OF_CallsAvailable */
static int hf_h225_h310GwCallsAvailable_item = -1;  /* CallsAvailable */
static int hf_h225_h320GwCallsAvailable = -1;     /* SEQUENCE_OF_CallsAvailable */
static int hf_h225_h320GwCallsAvailable_item = -1;  /* CallsAvailable */
static int hf_h225_h321GwCallsAvailable = -1;     /* SEQUENCE_OF_CallsAvailable */
static int hf_h225_h321GwCallsAvailable_item = -1;  /* CallsAvailable */
static int hf_h225_h322GwCallsAvailable = -1;     /* SEQUENCE_OF_CallsAvailable */
static int hf_h225_h322GwCallsAvailable_item = -1;  /* CallsAvailable */
static int hf_h225_h323GwCallsAvailable = -1;     /* SEQUENCE_OF_CallsAvailable */
static int hf_h225_h323GwCallsAvailable_item = -1;  /* CallsAvailable */
static int hf_h225_h324GwCallsAvailable = -1;     /* SEQUENCE_OF_CallsAvailable */
static int hf_h225_h324GwCallsAvailable_item = -1;  /* CallsAvailable */
static int hf_h225_t120OnlyGwCallsAvailable = -1;  /* SEQUENCE_OF_CallsAvailable */
static int hf_h225_t120OnlyGwCallsAvailable_item = -1;  /* CallsAvailable */
static int hf_h225_t38FaxAnnexbOnlyGwCallsAvailable = -1;  /* SEQUENCE_OF_CallsAvailable */
static int hf_h225_t38FaxAnnexbOnlyGwCallsAvailable_item = -1;  /* CallsAvailable */
static int hf_h225_terminalCallsAvailable = -1;   /* SEQUENCE_OF_CallsAvailable */
static int hf_h225_terminalCallsAvailable_item = -1;  /* CallsAvailable */
static int hf_h225_mcuCallsAvailable = -1;        /* SEQUENCE_OF_CallsAvailable */
static int hf_h225_mcuCallsAvailable_item = -1;   /* CallsAvailable */
static int hf_h225_sipGwCallsAvailable = -1;      /* SEQUENCE_OF_CallsAvailable */
static int hf_h225_sipGwCallsAvailable_item = -1;  /* CallsAvailable */
static int hf_h225_calls = -1;                    /* INTEGER_0_4294967295 */
static int hf_h225_group_IA5String = -1;          /* IA5String_SIZE_1_128 */
static int hf_h225_carrier = -1;                  /* CarrierInfo */
static int hf_h225_sourceCircuitID = -1;          /* CircuitIdentifier */
static int hf_h225_destinationCircuitID = -1;     /* CircuitIdentifier */
static int hf_h225_cic = -1;                      /* CicInfo */
static int hf_h225_group = -1;                    /* GroupID */
static int hf_h225_cic_2_4 = -1;                  /* T_cic */
static int hf_h225_cic_item = -1;                 /* OCTET_STRING_SIZE_2_4 */
static int hf_h225_pointCode = -1;                /* OCTET_STRING_SIZE_2_5 */
static int hf_h225_member = -1;                   /* T_member */
static int hf_h225_member_item = -1;              /* INTEGER_0_65535 */
static int hf_h225_carrierIdentificationCode = -1;  /* OCTET_STRING_SIZE_3_4 */
static int hf_h225_carrierName = -1;              /* IA5String_SIZE_1_128 */
static int hf_h225_url = -1;                      /* IA5String_SIZE_0_512 */
static int hf_h225_signal = -1;                   /* H248SignalsDescriptor */
static int hf_h225_callCreditServiceControl = -1;  /* CallCreditServiceControl */
static int hf_h225_sessionId_0_255 = -1;          /* INTEGER_0_255 */
static int hf_h225_contents = -1;                 /* ServiceControlDescriptor */
static int hf_h225_reason = -1;                   /* ServiceControlSession_reason */
static int hf_h225_open = -1;                     /* NULL */
static int hf_h225_refresh = -1;                  /* NULL */
static int hf_h225_close = -1;                    /* NULL */
static int hf_h225_nonStandardUsageTypes = -1;    /* SEQUENCE_OF_NonStandardParameter */
static int hf_h225_nonStandardUsageTypes_item = -1;  /* NonStandardParameter */
static int hf_h225_startTime = -1;                /* NULL */
static int hf_h225_endTime_flg = -1;              /* NULL */
static int hf_h225_terminationCause_flg = -1;     /* NULL */
static int hf_h225_when = -1;                     /* RasUsageSpecification_when */
static int hf_h225_start = -1;                    /* NULL */
static int hf_h225_end = -1;                      /* NULL */
static int hf_h225_inIrr = -1;                    /* NULL */
static int hf_h225_ras_callStartingPoint = -1;    /* RasUsageSpecificationcallStartingPoint */
static int hf_h225_alerting_flg = -1;             /* NULL */
static int hf_h225_connect_flg = -1;              /* NULL */
static int hf_h225_required = -1;                 /* RasUsageInfoTypes */
static int hf_h225_nonStandardUsageFields = -1;   /* SEQUENCE_OF_NonStandardParameter */
static int hf_h225_nonStandardUsageFields_item = -1;  /* NonStandardParameter */
static int hf_h225_alertingTime = -1;             /* TimeStamp */
static int hf_h225_connectTime = -1;              /* TimeStamp */
static int hf_h225_endTime = -1;                  /* TimeStamp */
static int hf_h225_releaseCompleteCauseIE = -1;   /* OCTET_STRING_SIZE_2_32 */
static int hf_h225_sender = -1;                   /* BOOLEAN */
static int hf_h225_multicast = -1;                /* BOOLEAN */
static int hf_h225_bandwidth = -1;                /* BandWidth */
static int hf_h225_rtcpAddresses = -1;            /* TransportChannelInfo */
static int hf_h225_canDisplayAmountString = -1;   /* BOOLEAN */
static int hf_h225_canEnforceDurationLimit = -1;  /* BOOLEAN */
static int hf_h225_amountString = -1;             /* BMPString_SIZE_1_512 */
static int hf_h225_billingMode = -1;              /* T_billingMode */
static int hf_h225_credit = -1;                   /* NULL */
static int hf_h225_debit = -1;                    /* NULL */
static int hf_h225_callDurationLimit = -1;        /* INTEGER_1_4294967295 */
static int hf_h225_enforceCallDurationLimit = -1;  /* BOOLEAN */
static int hf_h225_callStartingPoint = -1;        /* CallCreditServiceControl_callStartingPoint */
static int hf_h225_id = -1;                       /* GenericIdentifier */
static int hf_h225_parameters = -1;               /* SEQUENCE_SIZE_1_512_OF_EnumeratedParameter */
static int hf_h225_parameters_item = -1;          /* EnumeratedParameter */
static int hf_h225_standard = -1;                 /* INTEGER_0_16383_ */
static int hf_h225_oid = -1;                      /* OBJECT_IDENTIFIER */
static int hf_h225_genericIdentifier_nonStandard = -1;  /* GloballyUniqueID */
static int hf_h225_content = -1;                  /* Content */
static int hf_h225_raw = -1;                      /* OCTET_STRING */
static int hf_h225_text = -1;                     /* IA5String */
static int hf_h225_unicode = -1;                  /* BMPString */
static int hf_h225_bool = -1;                     /* BOOLEAN */
static int hf_h225_number8 = -1;                  /* INTEGER_0_255 */
static int hf_h225_number16 = -1;                 /* INTEGER_0_65535 */
static int hf_h225_number32 = -1;                 /* INTEGER_0_4294967295 */
static int hf_h225_transport = -1;                /* TransportAddress */
static int hf_h225_compound = -1;                 /* SEQUENCE_SIZE_1_512_OF_EnumeratedParameter */
static int hf_h225_compound_item = -1;            /* EnumeratedParameter */
static int hf_h225_nested = -1;                   /* SEQUENCE_SIZE_1_16_OF_GenericData */
static int hf_h225_nested_item = -1;              /* GenericData */
static int hf_h225_replacementFeatureSet = -1;    /* BOOLEAN */
static int hf_h225_sendAddress = -1;              /* TransportAddress */
static int hf_h225_recvAddress = -1;              /* TransportAddress */
static int hf_h225_rtpAddress = -1;               /* TransportChannelInfo */
static int hf_h225_rtcpAddress = -1;              /* TransportChannelInfo */
static int hf_h225_cname = -1;                    /* PrintableString */
static int hf_h225_ssrc = -1;                     /* INTEGER_1_4294967295 */
static int hf_h225_sessionId = -1;                /* INTEGER_1_255 */
static int hf_h225_associatedSessionIds = -1;     /* T_associatedSessionIds */
static int hf_h225_associatedSessionIds_item = -1;  /* INTEGER_1_255 */
static int hf_h225_multicast_flg = -1;            /* NULL */
static int hf_h225_gatekeeperRequest = -1;        /* GatekeeperRequest */
static int hf_h225_gatekeeperConfirm = -1;        /* GatekeeperConfirm */
static int hf_h225_gatekeeperReject = -1;         /* GatekeeperReject */
static int hf_h225_registrationRequest = -1;      /* RegistrationRequest */
static int hf_h225_registrationConfirm = -1;      /* RegistrationConfirm */
static int hf_h225_registrationReject = -1;       /* RegistrationReject */
static int hf_h225_unregistrationRequest = -1;    /* UnregistrationRequest */
static int hf_h225_unregistrationConfirm = -1;    /* UnregistrationConfirm */
static int hf_h225_unregistrationReject = -1;     /* UnregistrationReject */
static int hf_h225_admissionRequest = -1;         /* AdmissionRequest */
static int hf_h225_admissionConfirm = -1;         /* AdmissionConfirm */
static int hf_h225_admissionReject = -1;          /* AdmissionReject */
static int hf_h225_bandwidthRequest = -1;         /* BandwidthRequest */
static int hf_h225_bandwidthConfirm = -1;         /* BandwidthConfirm */
static int hf_h225_bandwidthReject = -1;          /* BandwidthReject */
static int hf_h225_disengageRequest = -1;         /* DisengageRequest */
static int hf_h225_disengageConfirm = -1;         /* DisengageConfirm */
static int hf_h225_disengageReject = -1;          /* DisengageReject */
static int hf_h225_locationRequest = -1;          /* LocationRequest */
static int hf_h225_locationConfirm = -1;          /* LocationConfirm */
static int hf_h225_locationReject = -1;           /* LocationReject */
static int hf_h225_infoRequest = -1;              /* InfoRequest */
static int hf_h225_infoRequestResponse = -1;      /* InfoRequestResponse */
static int hf_h225_nonStandardMessage = -1;       /* NonStandardMessage */
static int hf_h225_unknownMessageResponse = -1;   /* UnknownMessageResponse */
static int hf_h225_requestInProgress = -1;        /* RequestInProgress */
static int hf_h225_resourcesAvailableIndicate = -1;  /* ResourcesAvailableIndicate */
static int hf_h225_resourcesAvailableConfirm = -1;  /* ResourcesAvailableConfirm */
static int hf_h225_infoRequestAck = -1;           /* InfoRequestAck */
static int hf_h225_infoRequestNak = -1;           /* InfoRequestNak */
static int hf_h225_serviceControlIndication = -1;  /* ServiceControlIndication */
static int hf_h225_serviceControlResponse = -1;   /* ServiceControlResponse */
static int hf_h225_admissionConfirmSequence = -1;  /* SEQUENCE_OF_AdmissionConfirm */
static int hf_h225_admissionConfirmSequence_item = -1;  /* AdmissionConfirm */
static int hf_h225_requestSeqNum = -1;            /* RequestSeqNum */
static int hf_h225_gatekeeperRequest_rasAddress = -1;  /* TransportAddress */
static int hf_h225_endpointAlias = -1;            /* SEQUENCE_OF_AliasAddress */
static int hf_h225_endpointAlias_item = -1;       /* AliasAddress */
static int hf_h225_alternateEndpoints = -1;       /* SEQUENCE_OF_Endpoint */
static int hf_h225_alternateEndpoints_item = -1;  /* Endpoint */
static int hf_h225_authenticationCapability = -1;  /* SEQUENCE_OF_AuthenticationMechanism */
static int hf_h225_authenticationCapability_item = -1;  /* AuthenticationMechanism */
static int hf_h225_algorithmOIDs = -1;            /* T_algorithmOIDs */
static int hf_h225_algorithmOIDs_item = -1;       /* OBJECT_IDENTIFIER */
static int hf_h225_integrity = -1;                /* SEQUENCE_OF_IntegrityMechanism */
static int hf_h225_integrity_item = -1;           /* IntegrityMechanism */
static int hf_h225_integrityCheckValue = -1;      /* ICV */
static int hf_h225_supportsAltGK = -1;            /* NULL */
static int hf_h225_gatekeeperConfirm_rasAddress = -1;  /* TransportAddress */
static int hf_h225_authenticationMode = -1;       /* AuthenticationMechanism */
static int hf_h225_gatekeeperRejectReason = -1;   /* GatekeeperRejectReason */
static int hf_h225_altGKInfo = -1;                /* AltGKInfo */
static int hf_h225_resourceUnavailable = -1;      /* NULL */
static int hf_h225_terminalExcluded = -1;         /* NULL */
static int hf_h225_securityDenial = -1;           /* NULL */
static int hf_h225_gkRej_securityError = -1;      /* SecurityErrors */
static int hf_h225_discoveryComplete = -1;        /* BOOLEAN */
static int hf_h225_terminalType = -1;             /* EndpointType */
static int hf_h225_terminalAlias = -1;            /* SEQUENCE_OF_AliasAddress */
static int hf_h225_terminalAlias_item = -1;       /* AliasAddress */
static int hf_h225_endpointVendor = -1;           /* VendorIdentifier */
static int hf_h225_timeToLive = -1;               /* TimeToLive */
static int hf_h225_keepAlive = -1;                /* BOOLEAN */
static int hf_h225_willSupplyUUIEs = -1;          /* BOOLEAN */
static int hf_h225_additiveRegistration = -1;     /* NULL */
static int hf_h225_terminalAliasPattern = -1;     /* SEQUENCE_OF_AddressPattern */
static int hf_h225_terminalAliasPattern_item = -1;  /* AddressPattern */
static int hf_h225_usageReportingCapability = -1;  /* RasUsageInfoTypes */
static int hf_h225_supportedH248Packages = -1;    /* SEQUENCE_OF_H248PackagesDescriptor */
static int hf_h225_supportedH248Packages_item = -1;  /* H248PackagesDescriptor */
static int hf_h225_callCreditCapability = -1;     /* CallCreditCapability */
static int hf_h225_capacityReportingCapability = -1;  /* CapacityReportingCapability */
static int hf_h225_restart = -1;                  /* NULL */
static int hf_h225_supportsACFSequences = -1;     /* NULL */
static int hf_h225_willRespondToIRR = -1;         /* BOOLEAN */
static int hf_h225_preGrantedARQ = -1;            /* T_preGrantedARQ */
static int hf_h225_makeCall = -1;                 /* BOOLEAN */
static int hf_h225_useGKCallSignalAddressToMakeCall = -1;  /* BOOLEAN */
static int hf_h225_answerCall = -1;               /* BOOLEAN */
static int hf_h225_useGKCallSignalAddressToAnswer = -1;  /* BOOLEAN */
static int hf_h225_irrFrequencyInCall = -1;       /* INTEGER_1_65535 */
static int hf_h225_totalBandwidthRestriction = -1;  /* BandWidth */
static int hf_h225_useSpecifiedTransport = -1;    /* UseSpecifiedTransport */
static int hf_h225_supportsAdditiveRegistration = -1;  /* NULL */
static int hf_h225_usageSpec = -1;                /* SEQUENCE_OF_RasUsageSpecification */
static int hf_h225_usageSpec_item = -1;           /* RasUsageSpecification */
static int hf_h225_featureServerAlias = -1;       /* AliasAddress */
static int hf_h225_capacityReportingSpec = -1;    /* CapacityReportingSpecification */
static int hf_h225_registrationRejectReason = -1;  /* RegistrationRejectReason */
static int hf_h225_discoveryRequired = -1;        /* NULL */
static int hf_h225_invalidCallSignalAddress = -1;  /* NULL */
static int hf_h225_invalidRASAddress = -1;        /* NULL */
static int hf_h225_duplicateAlias = -1;           /* SEQUENCE_OF_AliasAddress */
static int hf_h225_duplicateAlias_item = -1;      /* AliasAddress */
static int hf_h225_invalidTerminalType = -1;      /* NULL */
static int hf_h225_transportNotSupported = -1;    /* NULL */
static int hf_h225_transportQOSNotSupported = -1;  /* NULL */
static int hf_h225_invalidAlias = -1;             /* NULL */
static int hf_h225_fullRegistrationRequired = -1;  /* NULL */
static int hf_h225_additiveRegistrationNotSupported = -1;  /* NULL */
static int hf_h225_invalidTerminalAliases = -1;   /* T_invalidTerminalAliases */
static int hf_h225_reg_securityError = -1;        /* SecurityErrors */
static int hf_h225_unregRequestReason = -1;       /* UnregRequestReason */
static int hf_h225_endpointAliasPattern = -1;     /* SEQUENCE_OF_AddressPattern */
static int hf_h225_endpointAliasPattern_item = -1;  /* AddressPattern */
static int hf_h225_reregistrationRequired = -1;   /* NULL */
static int hf_h225_ttlExpired = -1;               /* NULL */
static int hf_h225_maintenance = -1;              /* NULL */
static int hf_h225_securityError = -1;            /* SecurityErrors2 */
static int hf_h225_unregRejectReason = -1;        /* UnregRejectReason */
static int hf_h225_notCurrentlyRegistered = -1;   /* NULL */
static int hf_h225_callInProgress = -1;           /* NULL */
static int hf_h225_permissionDenied = -1;         /* NULL */
static int hf_h225_callModel = -1;                /* CallModel */
static int hf_h225_destinationInfo = -1;          /* DestinationInfo */
static int hf_h225_srcInfo = -1;                  /* SEQUENCE_OF_AliasAddress */
static int hf_h225_srcInfo_item = -1;             /* AliasAddress */
static int hf_h225_srcCallSignalAddress = -1;     /* TransportAddress */
static int hf_h225_bandWidth = -1;                /* BandWidth */
static int hf_h225_callReferenceValue = -1;       /* CallReferenceValue */
static int hf_h225_canMapAlias = -1;              /* BOOLEAN */
static int hf_h225_srcAlternatives = -1;          /* SEQUENCE_OF_Endpoint */
static int hf_h225_srcAlternatives_item = -1;     /* Endpoint */
static int hf_h225_destAlternatives = -1;         /* SEQUENCE_OF_Endpoint */
static int hf_h225_destAlternatives_item = -1;    /* Endpoint */
static int hf_h225_transportQOS = -1;             /* TransportQOS */
static int hf_h225_gatewayDataRate = -1;          /* DataRate */
static int hf_h225_desiredTunnelledProtocol = -1;  /* TunnelledProtocol */
static int hf_h225_canMapSrcAlias = -1;           /* BOOLEAN */
static int hf_h225_DestinationInfo_item = -1;     /* DestinationInfo_item */
static int hf_h225_pointToPoint = -1;             /* NULL */
static int hf_h225_oneToN = -1;                   /* NULL */
static int hf_h225_nToOne = -1;                   /* NULL */
static int hf_h225_nToN = -1;                     /* NULL */
static int hf_h225_direct = -1;                   /* NULL */
static int hf_h225_gatekeeperRouted = -1;         /* NULL */
static int hf_h225_endpointControlled = -1;       /* NULL */
static int hf_h225_gatekeeperControlled = -1;     /* NULL */
static int hf_h225_noControl = -1;                /* NULL */
static int hf_h225_irrFrequency = -1;             /* INTEGER_1_65535 */
static int hf_h225_destinationType = -1;          /* EndpointType */
static int hf_h225_uuiesRequested = -1;           /* UUIEsRequested */
static int hf_h225_supportedProtocols = -1;       /* SEQUENCE_OF_SupportedProtocols */
static int hf_h225_supportedProtocols_item = -1;  /* SupportedProtocols */
static int hf_h225_modifiedSrcInfo = -1;          /* SEQUENCE_OF_AliasAddress */
static int hf_h225_modifiedSrcInfo_item = -1;     /* AliasAddress */
static int hf_h225_setup_bool = -1;               /* BOOLEAN */
static int hf_h225_callProceeding_flg = -1;       /* BOOLEAN */
static int hf_h225_connect_bool = -1;             /* BOOLEAN */
static int hf_h225_alerting_bool = -1;            /* BOOLEAN */
static int hf_h225_information_bool = -1;         /* BOOLEAN */
static int hf_h225_releaseComplete_bool = -1;     /* BOOLEAN */
static int hf_h225_facility_bool = -1;            /* BOOLEAN */
static int hf_h225_progress_bool = -1;            /* BOOLEAN */
static int hf_h225_empty = -1;                    /* BOOLEAN */
static int hf_h225_status_bool = -1;              /* BOOLEAN */
static int hf_h225_statusInquiry_bool = -1;       /* BOOLEAN */
static int hf_h225_setupAcknowledge_bool = -1;    /* BOOLEAN */
static int hf_h225_notify_bool = -1;              /* BOOLEAN */
static int hf_h225_rejectReason = -1;             /* AdmissionRejectReason */
static int hf_h225_invalidPermission = -1;        /* NULL */
static int hf_h225_requestDenied = -1;            /* NULL */
static int hf_h225_invalidEndpointIdentifier = -1;  /* NULL */
static int hf_h225_qosControlNotSupported = -1;   /* NULL */
static int hf_h225_incompleteAddress = -1;        /* NULL */
static int hf_h225_aliasesInconsistent = -1;      /* NULL */
static int hf_h225_routeCallToSCN = -1;           /* SEQUENCE_OF_PartyNumber */
static int hf_h225_routeCallToSCN_item = -1;      /* PartyNumber */
static int hf_h225_exceedsCallCapacity = -1;      /* NULL */
static int hf_h225_collectDestination = -1;       /* NULL */
static int hf_h225_collectPIN = -1;               /* NULL */
static int hf_h225_noRouteToDestination = -1;     /* NULL */
static int hf_h225_unallocatedNumber = -1;        /* NULL */
static int hf_h225_answeredCall = -1;             /* BOOLEAN */
static int hf_h225_usageInformation = -1;         /* RasUsageInformation */
static int hf_h225_bandwidthDetails = -1;         /* SEQUENCE_OF_BandwidthDetails */
static int hf_h225_bandwidthDetails_item = -1;    /* BandwidthDetails */
static int hf_h225_bandRejectReason = -1;         /* BandRejectReason */
static int hf_h225_allowedBandWidth = -1;         /* BandWidth */
static int hf_h225_notBound = -1;                 /* NULL */
static int hf_h225_invalidConferenceID = -1;      /* NULL */
static int hf_h225_insufficientResources = -1;    /* NULL */
static int hf_h225_replyAddress = -1;             /* TransportAddress */
static int hf_h225_sourceInfo = -1;               /* SEQUENCE_OF_AliasAddress */
static int hf_h225_sourceInfo_item = -1;          /* AliasAddress */
static int hf_h225_hopCount = -1;                 /* INTEGER_1_255 */
static int hf_h225_sourceEndpointInfo = -1;       /* SEQUENCE_OF_AliasAddress */
static int hf_h225_sourceEndpointInfo_item = -1;  /* AliasAddress */
static int hf_h225_locationConfirm_callSignalAddress = -1;  /* TransportAddress */
static int hf_h225_locationConfirm_rasAddress = -1;  /* TransportAddress */
static int hf_h225_locationRejectReason = -1;     /* LocationRejectReason */
static int hf_h225_notRegistered = -1;            /* NULL */
static int hf_h225_routeCalltoSCN = -1;           /* SEQUENCE_OF_PartyNumber */
static int hf_h225_routeCalltoSCN_item = -1;      /* PartyNumber */
static int hf_h225_disengageReason = -1;          /* DisengageReason */
static int hf_h225_terminationCause = -1;         /* CallTerminationCause */
static int hf_h225_forcedDrop = -1;               /* NULL */
static int hf_h225_normalDrop = -1;               /* NULL */
static int hf_h225_disengageRejectReason = -1;    /* DisengageRejectReason */
static int hf_h225_requestToDropOther = -1;       /* NULL */
static int hf_h225_usageInfoRequested = -1;       /* RasUsageInfoTypes */
static int hf_h225_segmentedResponseSupported = -1;  /* NULL */
static int hf_h225_nextSegmentRequested = -1;     /* INTEGER_0_65535 */
static int hf_h225_capacityInfoRequested = -1;    /* NULL */
static int hf_h225_infoRequestResponse_rasAddress = -1;  /* TransportAddress */
static int hf_h225_perCallInfo = -1;              /* T_perCallInfo */
static int hf_h225_perCallInfo_item = -1;         /* T_perCallInfo_item */
static int hf_h225_originator = -1;               /* BOOLEAN */
static int hf_h225_audio = -1;                    /* SEQUENCE_OF_RTPSession */
static int hf_h225_audio_item = -1;               /* RTPSession */
static int hf_h225_video = -1;                    /* SEQUENCE_OF_RTPSession */
static int hf_h225_video_item = -1;               /* RTPSession */
static int hf_h225_data = -1;                     /* SEQUENCE_OF_TransportChannelInfo */
static int hf_h225_data_item = -1;                /* TransportChannelInfo */
static int hf_h225_h245 = -1;                     /* TransportChannelInfo */
static int hf_h225_callSignaling = -1;            /* TransportChannelInfo */
static int hf_h225_substituteConfIDs = -1;        /* SEQUENCE_OF_ConferenceIdentifier */
static int hf_h225_substituteConfIDs_item = -1;   /* ConferenceIdentifier */
static int hf_h225_pdu = -1;                      /* T_pdu */
static int hf_h225_pdu_item = -1;                 /* T_pdu_item */
static int hf_h225_h323pdu = -1;                  /* H323_UU_PDU */
static int hf_h225_sent = -1;                     /* BOOLEAN */
static int hf_h225_needResponse = -1;             /* BOOLEAN */
static int hf_h225_irrStatus = -1;                /* InfoRequestResponseStatus */
static int hf_h225_unsolicited = -1;              /* BOOLEAN */
static int hf_h225_complete = -1;                 /* NULL */
static int hf_h225_incomplete = -1;               /* NULL */
static int hf_h225_segment = -1;                  /* INTEGER_0_65535 */
static int hf_h225_invalidCall = -1;              /* NULL */
static int hf_h225_nakReason = -1;                /* InfoRequestNakReason */
static int hf_h225_messageNotUnderstood = -1;     /* OCTET_STRING */
static int hf_h225_delay = -1;                    /* INTEGER_1_65535 */
static int hf_h225_protocols = -1;                /* SEQUENCE_OF_SupportedProtocols */
static int hf_h225_protocols_item = -1;           /* SupportedProtocols */
static int hf_h225_almostOutOfResources = -1;     /* BOOLEAN */
static int hf_h225_callSpecific = -1;             /* T_callSpecific */
static int hf_h225_result = -1;                   /* T_result */
static int hf_h225_started = -1;                  /* NULL */
static int hf_h225_failed = -1;                   /* NULL */
static int hf_h225_stopped = -1;                  /* NULL */
static int hf_h225_notAvailable = -1;             /* NULL */

/*--- End of included file: packet-h225-hf.c ---*/
#line 170 "packet-h225-template.c"

/* Initialize the subtree pointers */
static gint ett_h225 = -1;

/*--- Included file: packet-h225-ett.c ---*/
#line 1 "packet-h225-ett.c"
static gint ett_h225_H323_UserInformation = -1;
static gint ett_h225_T_user_data = -1;
static gint ett_h225_H323_UU_PDU = -1;
static gint ett_h225_T_h323_message_body = -1;
static gint ett_h225_T_h4501SupplementaryService = -1;
static gint ett_h225_SEQUENCE_OF_NonStandardParameter = -1;
static gint ett_h225_T_tunnelledSignallingMessage = -1;
static gint ett_h225_T_messageContent = -1;
static gint ett_h225_SEQUENCE_OF_GenericData = -1;
static gint ett_h225_H245Control = -1;
static gint ett_h225_StimulusControl = -1;
static gint ett_h225_Alerting_UUIE = -1;
static gint ett_h225_SEQUENCE_OF_ClearToken = -1;
static gint ett_h225_SEQUENCE_OF_CryptoH323Token = -1;
static gint ett_h225_SEQUENCE_OF_AliasAddress = -1;
static gint ett_h225_SEQUENCE_OF_ServiceControlSession = -1;
static gint ett_h225_CallProceeding_UUIE = -1;
static gint ett_h225_Connect_UUIE = -1;
static gint ett_h225_Language = -1;
static gint ett_h225_Information_UUIE = -1;
static gint ett_h225_ReleaseComplete_UUIE = -1;
static gint ett_h225_ReleaseCompleteReason = -1;
static gint ett_h225_Setup_UUIE = -1;
static gint ett_h225_SEQUENCE_OF_CallReferenceValue = -1;
static gint ett_h225_T_conferenceGoal = -1;
static gint ett_h225_SEQUENCE_OF_H245Security = -1;
static gint ett_h225_T_connectionParameters = -1;
static gint ett_h225_SEQUENCE_OF_SupportedProtocols = -1;
static gint ett_h225_SEQUENCE_OF_FeatureDescriptor = -1;
static gint ett_h225_SEQUENCE_OF_ExtendedAliasAddress = -1;
static gint ett_h225_ParallelH245Control = -1;
static gint ett_h225_ScnConnectionType = -1;
static gint ett_h225_ScnConnectionAggregation = -1;
static gint ett_h225_PresentationIndicator = -1;
static gint ett_h225_Facility_UUIE = -1;
static gint ett_h225_SEQUENCE_OF_ConferenceList = -1;
static gint ett_h225_ConferenceList = -1;
static gint ett_h225_FacilityReason = -1;
static gint ett_h225_Progress_UUIE = -1;
static gint ett_h225_FastStart = -1;
static gint ett_h225_TransportAddress = -1;
static gint ett_h225_T_ipAddress = -1;
static gint ett_h225_T_ipSourceRoute = -1;
static gint ett_h225_T_route = -1;
static gint ett_h225_T_routing = -1;
static gint ett_h225_T_ipxAddress = -1;
static gint ett_h225_T_ip6Address = -1;
static gint ett_h225_H245TransportAddress = -1;
static gint ett_h225_T_h245ipAddress = -1;
static gint ett_h225_T_h245ipSourceRoute = -1;
static gint ett_h225_T_h245route = -1;
static gint ett_h225_T_h245routing = -1;
static gint ett_h225_T_h245ipxAddress = -1;
static gint ett_h225_T_h245ip6Address = -1;
static gint ett_h225_Status_UUIE = -1;
static gint ett_h225_StatusInquiry_UUIE = -1;
static gint ett_h225_SetupAcknowledge_UUIE = -1;
static gint ett_h225_Notify_UUIE = -1;
static gint ett_h225_EndpointType = -1;
static gint ett_h225_SEQUENCE_OF_TunnelledProtocol = -1;
static gint ett_h225_GatewayInfo = -1;
static gint ett_h225_SupportedProtocols = -1;
static gint ett_h225_H310Caps = -1;
static gint ett_h225_SEQUENCE_OF_DataRate = -1;
static gint ett_h225_SEQUENCE_OF_SupportedPrefix = -1;
static gint ett_h225_H320Caps = -1;
static gint ett_h225_H321Caps = -1;
static gint ett_h225_H322Caps = -1;
static gint ett_h225_H323Caps = -1;
static gint ett_h225_H324Caps = -1;
static gint ett_h225_VoiceCaps = -1;
static gint ett_h225_T120OnlyCaps = -1;
static gint ett_h225_NonStandardProtocol = -1;
static gint ett_h225_T38FaxAnnexbOnlyCaps = -1;
static gint ett_h225_SIPCaps = -1;
static gint ett_h225_McuInfo = -1;
static gint ett_h225_TerminalInfo = -1;
static gint ett_h225_GatekeeperInfo = -1;
static gint ett_h225_VendorIdentifier = -1;
static gint ett_h225_H221NonStandard = -1;
static gint ett_h225_TunnelledProtocol = -1;
static gint ett_h225_TunnelledProtocol_id = -1;
static gint ett_h225_TunnelledProtocolAlternateIdentifier = -1;
static gint ett_h225_NonStandardParameter = -1;
static gint ett_h225_NonStandardIdentifier = -1;
static gint ett_h225_AliasAddress = -1;
static gint ett_h225_AddressPattern = -1;
static gint ett_h225_T_range = -1;
static gint ett_h225_PartyNumber = -1;
static gint ett_h225_PublicPartyNumber = -1;
static gint ett_h225_PrivatePartyNumber = -1;
static gint ett_h225_PublicTypeOfNumber = -1;
static gint ett_h225_PrivateTypeOfNumber = -1;
static gint ett_h225_MobileUIM = -1;
static gint ett_h225_ANSI_41_UIM = -1;
static gint ett_h225_T_system_id = -1;
static gint ett_h225_GSM_UIM = -1;
static gint ett_h225_ExtendedAliasAddress = -1;
static gint ett_h225_Endpoint = -1;
static gint ett_h225_SEQUENCE_OF_TransportAddress = -1;
static gint ett_h225_AlternateTransportAddresses = -1;
static gint ett_h225_UseSpecifiedTransport = -1;
static gint ett_h225_AlternateGK = -1;
static gint ett_h225_AltGKInfo = -1;
static gint ett_h225_SEQUENCE_OF_AlternateGK = -1;
static gint ett_h225_SecurityServiceMode = -1;
static gint ett_h225_SecurityCapabilities = -1;
static gint ett_h225_SecurityErrors = -1;
static gint ett_h225_SecurityErrors2 = -1;
static gint ett_h225_H245Security = -1;
static gint ett_h225_QseriesOptions = -1;
static gint ett_h225_Q954Details = -1;
static gint ett_h225_CallIdentifier = -1;
static gint ett_h225_EncryptIntAlg = -1;
static gint ett_h225_NonIsoIntegrityMechanism = -1;
static gint ett_h225_IntegrityMechanism = -1;
static gint ett_h225_ICV = -1;
static gint ett_h225_CryptoH323Token = -1;
static gint ett_h225_T_cryptoEPPwdHash = -1;
static gint ett_h225_T_cryptoGKPwdHash = -1;
static gint ett_h225_DataRate = -1;
static gint ett_h225_CallLinkage = -1;
static gint ett_h225_SupportedPrefix = -1;
static gint ett_h225_CapacityReportingCapability = -1;
static gint ett_h225_CapacityReportingSpecification = -1;
static gint ett_h225_CapacityReportingSpecification_when = -1;
static gint ett_h225_CallCapacity = -1;
static gint ett_h225_CallCapacityInfo = -1;
static gint ett_h225_SEQUENCE_OF_CallsAvailable = -1;
static gint ett_h225_CallsAvailable = -1;
static gint ett_h225_CircuitInfo = -1;
static gint ett_h225_CircuitIdentifier = -1;
static gint ett_h225_CicInfo = -1;
static gint ett_h225_T_cic = -1;
static gint ett_h225_GroupID = -1;
static gint ett_h225_T_member = -1;
static gint ett_h225_CarrierInfo = -1;
static gint ett_h225_ServiceControlDescriptor = -1;
static gint ett_h225_ServiceControlSession = -1;
static gint ett_h225_ServiceControlSession_reason = -1;
static gint ett_h225_RasUsageInfoTypes = -1;
static gint ett_h225_RasUsageSpecification = -1;
static gint ett_h225_RasUsageSpecification_when = -1;
static gint ett_h225_RasUsageSpecificationcallStartingPoint = -1;
static gint ett_h225_RasUsageInformation = -1;
static gint ett_h225_CallTerminationCause = -1;
static gint ett_h225_BandwidthDetails = -1;
static gint ett_h225_CallCreditCapability = -1;
static gint ett_h225_CallCreditServiceControl = -1;
static gint ett_h225_T_billingMode = -1;
static gint ett_h225_CallCreditServiceControl_callStartingPoint = -1;
static gint ett_h225_GenericData = -1;
static gint ett_h225_SEQUENCE_SIZE_1_512_OF_EnumeratedParameter = -1;
static gint ett_h225_GenericIdentifier = -1;
static gint ett_h225_EnumeratedParameter = -1;
static gint ett_h225_Content = -1;
static gint ett_h225_SEQUENCE_SIZE_1_16_OF_GenericData = -1;
static gint ett_h225_FeatureSet = -1;
static gint ett_h225_TransportChannelInfo = -1;
static gint ett_h225_RTPSession = -1;
static gint ett_h225_T_associatedSessionIds = -1;
static gint ett_h225_RasMessage = -1;
static gint ett_h225_SEQUENCE_OF_AdmissionConfirm = -1;
static gint ett_h225_GatekeeperRequest = -1;
static gint ett_h225_SEQUENCE_OF_Endpoint = -1;
static gint ett_h225_SEQUENCE_OF_AuthenticationMechanism = -1;
static gint ett_h225_T_algorithmOIDs = -1;
static gint ett_h225_SEQUENCE_OF_IntegrityMechanism = -1;
static gint ett_h225_GatekeeperConfirm = -1;
static gint ett_h225_GatekeeperReject = -1;
static gint ett_h225_GatekeeperRejectReason = -1;
static gint ett_h225_RegistrationRequest = -1;
static gint ett_h225_SEQUENCE_OF_AddressPattern = -1;
static gint ett_h225_SEQUENCE_OF_H248PackagesDescriptor = -1;
static gint ett_h225_RegistrationConfirm = -1;
static gint ett_h225_T_preGrantedARQ = -1;
static gint ett_h225_SEQUENCE_OF_RasUsageSpecification = -1;
static gint ett_h225_RegistrationReject = -1;
static gint ett_h225_RegistrationRejectReason = -1;
static gint ett_h225_T_invalidTerminalAliases = -1;
static gint ett_h225_UnregistrationRequest = -1;
static gint ett_h225_UnregRequestReason = -1;
static gint ett_h225_UnregistrationConfirm = -1;
static gint ett_h225_UnregistrationReject = -1;
static gint ett_h225_UnregRejectReason = -1;
static gint ett_h225_AdmissionRequest = -1;
static gint ett_h225_DestinationInfo = -1;
static gint ett_h225_CallType = -1;
static gint ett_h225_CallModel = -1;
static gint ett_h225_TransportQOS = -1;
static gint ett_h225_AdmissionConfirm = -1;
static gint ett_h225_UUIEsRequested = -1;
static gint ett_h225_AdmissionReject = -1;
static gint ett_h225_AdmissionRejectReason = -1;
static gint ett_h225_SEQUENCE_OF_PartyNumber = -1;
static gint ett_h225_BandwidthRequest = -1;
static gint ett_h225_SEQUENCE_OF_BandwidthDetails = -1;
static gint ett_h225_BandwidthConfirm = -1;
static gint ett_h225_BandwidthReject = -1;
static gint ett_h225_BandRejectReason = -1;
static gint ett_h225_LocationRequest = -1;
static gint ett_h225_LocationConfirm = -1;
static gint ett_h225_LocationReject = -1;
static gint ett_h225_LocationRejectReason = -1;
static gint ett_h225_DisengageRequest = -1;
static gint ett_h225_DisengageReason = -1;
static gint ett_h225_DisengageConfirm = -1;
static gint ett_h225_DisengageReject = -1;
static gint ett_h225_DisengageRejectReason = -1;
static gint ett_h225_InfoRequest = -1;
static gint ett_h225_InfoRequestResponse = -1;
static gint ett_h225_T_perCallInfo = -1;
static gint ett_h225_T_perCallInfo_item = -1;
static gint ett_h225_SEQUENCE_OF_RTPSession = -1;
static gint ett_h225_SEQUENCE_OF_TransportChannelInfo = -1;
static gint ett_h225_SEQUENCE_OF_ConferenceIdentifier = -1;
static gint ett_h225_T_pdu = -1;
static gint ett_h225_T_pdu_item = -1;
static gint ett_h225_InfoRequestResponseStatus = -1;
static gint ett_h225_InfoRequestAck = -1;
static gint ett_h225_InfoRequestNak = -1;
static gint ett_h225_InfoRequestNakReason = -1;
static gint ett_h225_NonStandardMessage = -1;
static gint ett_h225_UnknownMessageResponse = -1;
static gint ett_h225_RequestInProgress = -1;
static gint ett_h225_ResourcesAvailableIndicate = -1;
static gint ett_h225_ResourcesAvailableConfirm = -1;
static gint ett_h225_ServiceControlIndication = -1;
static gint ett_h225_T_callSpecific = -1;
static gint ett_h225_ServiceControlResponse = -1;
static gint ett_h225_T_result = -1;

/*--- End of included file: packet-h225-ett.c ---*/
#line 174 "packet-h225-template.c"

/* Preferences */
static gboolean h225_reassembly = TRUE;
static gboolean h225_h245_in_tree = TRUE;
static gboolean h225_tp_in_tree = TRUE;

/* Global variables */
static guint32  ipv4_address;
static guint32  ipv4_port;
guint32 T38_manufacturer_code;
guint32 value;
static gboolean contains_faststart = FALSE;

/* NonStandardParameter */
static const char *nsiOID;
static guint32 h221NonStandard;
static guint32 t35CountryCode;
static guint32 t35Extension;
static guint32 manufacturerCode;

/* TunnelledProtocol */
static const char *tpOID;


/*--- Included file: packet-h225-fn.c ---*/
#line 1 "packet-h225-fn.c"
/*--- Cyclic dependencies ---*/

/* EnumeratedParameter -> Content -> Content/compound -> EnumeratedParameter */
static int dissect_h225_EnumeratedParameter(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree, int hf_index);

static int dissect_parameters_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_EnumeratedParameter(tvb, offset, actx, tree, hf_h225_parameters_item);
}
static int dissect_compound_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_EnumeratedParameter(tvb, offset, actx, tree, hf_h225_compound_item);
}

/* GenericData -> GenericData/parameters -> EnumeratedParameter -> Content -> Content/nested -> GenericData */
int dissect_h225_GenericData(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree, int hf_index);

static int dissect_genericData_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GenericData(tvb, offset, actx, tree, hf_h225_genericData_item);
}
static int dissect_nested_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GenericData(tvb, offset, actx, tree, hf_h225_nested_item);
}


/*--- Fields for imported types ---*/

static int dissect_tokens_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_ClearToken(tvb, offset, actx, tree, hf_h225_tokens_item);
}
static int dissect_t38FaxProtocol(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h245_DataProtocolCapability(tvb, offset, actx, tree, hf_h225_t38FaxProtocol);
}
static int dissect_t38FaxProfile(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h245_T38FaxProfile(tvb, offset, actx, tree, hf_h225_t38FaxProfile);
}
static int dissect_timeStamp(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_TimeStamp(tvb, offset, actx, tree, hf_h225_timeStamp);
}
static int dissect_token(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_HASHEDxxx(tvb, offset, actx, tree, hf_h225_token);
}
static int dissect_cryptoEPPwdEncr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_ENCRYPTEDxxx(tvb, offset, actx, tree, hf_h225_cryptoEPPwdEncr);
}
static int dissect_cryptoGKPwdEncr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_ENCRYPTEDxxx(tvb, offset, actx, tree, hf_h225_cryptoGKPwdEncr);
}
static int dissect_cryptoEPCert(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_SIGNEDxxx(tvb, offset, actx, tree, hf_h225_cryptoEPCert);
}
static int dissect_cryptoGKCert(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_SIGNEDxxx(tvb, offset, actx, tree, hf_h225_cryptoGKCert);
}
static int dissect_cryptoFastStart(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_SIGNEDxxx(tvb, offset, actx, tree, hf_h225_cryptoFastStart);
}
static int dissect_nestedcryptoToken(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_CryptoToken(tvb, offset, actx, tree, hf_h225_nestedcryptoToken);
}
static int dissect_alertingTime(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_TimeStamp(tvb, offset, actx, tree, hf_h225_alertingTime);
}
static int dissect_connectTime(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_TimeStamp(tvb, offset, actx, tree, hf_h225_connectTime);
}
static int dissect_endTime(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_TimeStamp(tvb, offset, actx, tree, hf_h225_endTime);
}
static int dissect_authenticationCapability_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_AuthenticationMechanism(tvb, offset, actx, tree, hf_h225_authenticationCapability_item);
}
static int dissect_authenticationMode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h235_AuthenticationMechanism(tvb, offset, actx, tree, hf_h225_authenticationMode);
}



static int
dissect_h225_ProtocolIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}
static int dissect_protocolIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ProtocolIdentifier(tvb, offset, actx, tree, hf_h225_protocolIdentifier);
}



static int
dissect_h225_T_h245ipv4(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 215 "h225.cnf"
  tvbuff_t *value_tvb;

  ipv4_address = 0;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, &value_tvb);

  if (value_tvb)
    ipv4_address = tvb_get_ipv4(value_tvb, 0);


  return offset;
}
static int dissect_h245ipv4(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_h245ipv4(tvb, offset, actx, tree, hf_h225_h245ipv4);
}



static int
dissect_h225_T_h245ipv4port(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, &ipv4_port, FALSE);

  return offset;
}
static int dissect_h245ipv4port(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_h245ipv4port(tvb, offset, actx, tree, hf_h225_h245ipv4port);
}


static const per_sequence_t T_h245ipAddress_sequence[] = {
  { "h245ipv4"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245ipv4 },
  { "h245ipv4port"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245ipv4port },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_h245ipAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_h245ipAddress, T_h245ipAddress_sequence);

  return offset;
}
static int dissect_h245ipAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_h245ipAddress(tvb, offset, actx, tree, hf_h225_h245ipAddress);
}



static int
dissect_h225_OCTET_STRING_SIZE_4(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, NULL);

  return offset;
}
static int dissect_src_route_ipV4(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_4(tvb, offset, actx, tree, hf_h225_src_route_ipV4);
}
static int dissect_route_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_4(tvb, offset, actx, tree, hf_h225_route_item);
}
static int dissect_netnum(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_4(tvb, offset, actx, tree, hf_h225_netnum);
}
static int dissect_h245routeip(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_4(tvb, offset, actx, tree, hf_h225_h245routeip);
}
static int dissect_h245route_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_4(tvb, offset, actx, tree, hf_h225_h245route_item);
}



static int
dissect_h225_INTEGER_0_65535(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_numberOfScnConnections(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_65535(tvb, offset, actx, tree, hf_h225_numberOfScnConnections);
}
static int dissect_ipV4_port(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_65535(tvb, offset, actx, tree, hf_h225_ipV4_port);
}
static int dissect_ipV4_src_port(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_65535(tvb, offset, actx, tree, hf_h225_ipV4_src_port);
}
static int dissect_ipV6_port(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_65535(tvb, offset, actx, tree, hf_h225_ipV6_port);
}
static int dissect_h245routeport(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_65535(tvb, offset, actx, tree, hf_h225_h245routeport);
}
static int dissect_h245ipv6port(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_65535(tvb, offset, actx, tree, hf_h225_h245ipv6port);
}
static int dissect_member_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_65535(tvb, offset, actx, tree, hf_h225_member_item);
}
static int dissect_number16(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_65535(tvb, offset, actx, tree, hf_h225_number16);
}
static int dissect_nextSegmentRequested(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_65535(tvb, offset, actx, tree, hf_h225_nextSegmentRequested);
}
static int dissect_segment(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_65535(tvb, offset, actx, tree, hf_h225_segment);
}


static const per_sequence_t T_h245route_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245route_item },
};

static int
dissect_h225_T_h245route(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_T_h245route, T_h245route_sequence_of);

  return offset;
}
static int dissect_h245route(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_h245route(tvb, offset, actx, tree, hf_h225_h245route);
}



static int
dissect_h225_NULL(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_tunnellingRequired(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_tunnellingRequired);
}
static int dissect_provisionalRespToH245Tunneling(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_provisionalRespToH245Tunneling);
}
static int dissect_isText(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_isText);
}
static int dissect_fastConnectRefused(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_fastConnectRefused);
}
static int dissect_noBandwidth(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_noBandwidth);
}
static int dissect_gatekeeperResources(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_gatekeeperResources);
}
static int dissect_unreachableDestination(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_unreachableDestination);
}
static int dissect_destinationRejection(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_destinationRejection);
}
static int dissect_invalidRevision(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_invalidRevision);
}
static int dissect_noPermission(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_noPermission);
}
static int dissect_unreachableGatekeeper(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_unreachableGatekeeper);
}
static int dissect_gatewayResources(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_gatewayResources);
}
static int dissect_badFormatAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_badFormatAddress);
}
static int dissect_adaptiveBusy(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_adaptiveBusy);
}
static int dissect_inConf(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_inConf);
}
static int dissect_undefinedReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_undefinedReason);
}
static int dissect_facilityCallDeflection(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_facilityCallDeflection);
}
static int dissect_securityDenied(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityDenied);
}
static int dissect_calledPartyNotRegistered(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_calledPartyNotRegistered);
}
static int dissect_callerNotRegistered(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_callerNotRegistered);
}
static int dissect_newConnectionNeeded(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_newConnectionNeeded);
}
static int dissect_genericDataReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_genericDataReason);
}
static int dissect_neededFeatureNotSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_neededFeatureNotSupported);
}
static int dissect_tunnelledSignallingRejected(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_tunnelledSignallingRejected);
}
static int dissect_invalidCID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_invalidCID);
}
static int dissect_hopCountExceeded(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_hopCountExceeded);
}
static int dissect_create(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_create);
}
static int dissect_join(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_join);
}
static int dissect_invite(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_invite);
}
static int dissect_capability_negotiation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_capability_negotiation);
}
static int dissect_callIndependentSupplementaryService(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_callIndependentSupplementaryService);
}
static int dissect_symmetricOperationRequired(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_symmetricOperationRequired);
}
static int dissect_unknown(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_unknown);
}
static int dissect_bChannel(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_bChannel);
}
static int dissect_hybrid2x64(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_hybrid2x64);
}
static int dissect_hybrid384(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_hybrid384);
}
static int dissect_hybrid1536(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_hybrid1536);
}
static int dissect_hybrid1920(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_hybrid1920);
}
static int dissect_multirate(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_multirate);
}
static int dissect_auto(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_auto);
}
static int dissect_none(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_none);
}
static int dissect_h221(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_h221);
}
static int dissect_bonded_mode1(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_bonded_mode1);
}
static int dissect_bonded_mode2(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_bonded_mode2);
}
static int dissect_bonded_mode3(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_bonded_mode3);
}
static int dissect_presentationAllowed(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_presentationAllowed);
}
static int dissect_presentationRestricted(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_presentationRestricted);
}
static int dissect_addressNotAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_addressNotAvailable);
}
static int dissect_routeCallToGatekeeper(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_routeCallToGatekeeper);
}
static int dissect_callForwarded(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_callForwarded);
}
static int dissect_routeCallToMC(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_routeCallToMC);
}
static int dissect_conferenceListChoice(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_conferenceListChoice);
}
static int dissect_startH245(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_startH245);
}
static int dissect_noH245(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_noH245);
}
static int dissect_newTokens(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_newTokens);
}
static int dissect_featureSetUpdate(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_featureSetUpdate);
}
static int dissect_forwardedElements(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_forwardedElements);
}
static int dissect_transportedInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_transportedInformation);
}
static int dissect_strict(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_strict);
}
static int dissect_loose(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_loose);
}
static int dissect_internationalNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_internationalNumber);
}
static int dissect_nationalNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_nationalNumber);
}
static int dissect_networkSpecificNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_networkSpecificNumber);
}
static int dissect_subscriberNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_subscriberNumber);
}
static int dissect_abbreviatedNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_abbreviatedNumber);
}
static int dissect_level2RegionalNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_level2RegionalNumber);
}
static int dissect_level1RegionalNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_level1RegionalNumber);
}
static int dissect_pISNSpecificNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_pISNSpecificNumber);
}
static int dissect_localNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_localNumber);
}
static int dissect_tcp(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_tcp);
}
static int dissect_annexE_flg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_annexE_flg);
}
static int dissect_sctp_flg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_sctp_flg);
}
static int dissect_default(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_default);
}
static int dissect_securityWrongSyncTime(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityWrongSyncTime);
}
static int dissect_securityReplay(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityReplay);
}
static int dissect_securityWrongGeneralID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityWrongGeneralID);
}
static int dissect_securityWrongSendersID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityWrongSendersID);
}
static int dissect_securityIntegrityFailed(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityIntegrityFailed);
}
static int dissect_securityWrongOID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityWrongOID);
}
static int dissect_securityDHmismatch(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityDHmismatch);
}
static int dissect_securityCertificateExpired(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityCertificateExpired);
}
static int dissect_securityCertificateDateInvalid(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityCertificateDateInvalid);
}
static int dissect_securityCertificateRevoked(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityCertificateRevoked);
}
static int dissect_securityCertificateNotReadable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityCertificateNotReadable);
}
static int dissect_securityCertificateSignatureInvalid(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityCertificateSignatureInvalid);
}
static int dissect_securityCertificateMissing(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityCertificateMissing);
}
static int dissect_securityCertificateIncomplete(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityCertificateIncomplete);
}
static int dissect_securityUnsupportedCertificateAlgOID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityUnsupportedCertificateAlgOID);
}
static int dissect_securityUnknownCA(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityUnknownCA);
}
static int dissect_noSecurity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_noSecurity);
}
static int dissect_hMAC_MD5(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_hMAC_MD5);
}
static int dissect_digSig(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_digSig);
}
static int dissect_callStart(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_callStart);
}
static int dissect_callEnd(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_callEnd);
}
static int dissect_open(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_open);
}
static int dissect_refresh(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_refresh);
}
static int dissect_close(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_close);
}
static int dissect_startTime(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_startTime);
}
static int dissect_endTime_flg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_endTime_flg);
}
static int dissect_terminationCause_flg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_terminationCause_flg);
}
static int dissect_start(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_start);
}
static int dissect_end(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_end);
}
static int dissect_inIrr(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_inIrr);
}
static int dissect_alerting_flg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_alerting_flg);
}
static int dissect_connect_flg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_connect_flg);
}
static int dissect_credit(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_credit);
}
static int dissect_debit(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_debit);
}
static int dissect_multicast_flg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_multicast_flg);
}
static int dissect_supportsAltGK(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_supportsAltGK);
}
static int dissect_resourceUnavailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_resourceUnavailable);
}
static int dissect_terminalExcluded(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_terminalExcluded);
}
static int dissect_securityDenial(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_securityDenial);
}
static int dissect_additiveRegistration(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_additiveRegistration);
}
static int dissect_restart(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_restart);
}
static int dissect_supportsACFSequences(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_supportsACFSequences);
}
static int dissect_supportsAdditiveRegistration(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_supportsAdditiveRegistration);
}
static int dissect_discoveryRequired(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_discoveryRequired);
}
static int dissect_invalidCallSignalAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_invalidCallSignalAddress);
}
static int dissect_invalidRASAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_invalidRASAddress);
}
static int dissect_invalidTerminalType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_invalidTerminalType);
}
static int dissect_transportNotSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_transportNotSupported);
}
static int dissect_transportQOSNotSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_transportQOSNotSupported);
}
static int dissect_invalidAlias(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_invalidAlias);
}
static int dissect_fullRegistrationRequired(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_fullRegistrationRequired);
}
static int dissect_additiveRegistrationNotSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_additiveRegistrationNotSupported);
}
static int dissect_reregistrationRequired(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_reregistrationRequired);
}
static int dissect_ttlExpired(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_ttlExpired);
}
static int dissect_maintenance(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_maintenance);
}
static int dissect_notCurrentlyRegistered(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_notCurrentlyRegistered);
}
static int dissect_callInProgress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_callInProgress);
}
static int dissect_permissionDenied(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_permissionDenied);
}
static int dissect_pointToPoint(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_pointToPoint);
}
static int dissect_oneToN(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_oneToN);
}
static int dissect_nToOne(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_nToOne);
}
static int dissect_nToN(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_nToN);
}
static int dissect_direct(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_direct);
}
static int dissect_gatekeeperRouted(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_gatekeeperRouted);
}
static int dissect_endpointControlled(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_endpointControlled);
}
static int dissect_gatekeeperControlled(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_gatekeeperControlled);
}
static int dissect_noControl(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_noControl);
}
static int dissect_invalidPermission(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_invalidPermission);
}
static int dissect_requestDenied(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_requestDenied);
}
static int dissect_invalidEndpointIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_invalidEndpointIdentifier);
}
static int dissect_qosControlNotSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_qosControlNotSupported);
}
static int dissect_incompleteAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_incompleteAddress);
}
static int dissect_aliasesInconsistent(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_aliasesInconsistent);
}
static int dissect_exceedsCallCapacity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_exceedsCallCapacity);
}
static int dissect_collectDestination(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_collectDestination);
}
static int dissect_collectPIN(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_collectPIN);
}
static int dissect_noRouteToDestination(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_noRouteToDestination);
}
static int dissect_unallocatedNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_unallocatedNumber);
}
static int dissect_notBound(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_notBound);
}
static int dissect_invalidConferenceID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_invalidConferenceID);
}
static int dissect_insufficientResources(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_insufficientResources);
}
static int dissect_notRegistered(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_notRegistered);
}
static int dissect_forcedDrop(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_forcedDrop);
}
static int dissect_normalDrop(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_normalDrop);
}
static int dissect_requestToDropOther(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_requestToDropOther);
}
static int dissect_segmentedResponseSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_segmentedResponseSupported);
}
static int dissect_capacityInfoRequested(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_capacityInfoRequested);
}
static int dissect_complete(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_complete);
}
static int dissect_incomplete(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_incomplete);
}
static int dissect_invalidCall(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_invalidCall);
}
static int dissect_started(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_started);
}
static int dissect_failed(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_failed);
}
static int dissect_stopped(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_stopped);
}
static int dissect_notAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NULL(tvb, offset, actx, tree, hf_h225_notAvailable);
}


static const value_string h225_T_h245routing_vals[] = {
  {   0, "strict" },
  {   1, "loose" },
  { 0, NULL }
};

static const per_choice_t T_h245routing_choice[] = {
  {   0, "strict"                      , ASN1_EXTENSION_ROOT    , dissect_strict },
  {   1, "loose"                       , ASN1_EXTENSION_ROOT    , dissect_loose },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_T_h245routing(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_T_h245routing, T_h245routing_choice,
                                 NULL);

  return offset;
}
static int dissect_h245routing(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_h245routing(tvb, offset, actx, tree, hf_h225_h245routing);
}


static const per_sequence_t T_h245ipSourceRoute_sequence[] = {
  { "h245routeip"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245routeip },
  { "h245routeport"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245routeport },
  { "h245route"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245route },
  { "h245routing"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245routing },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_h245ipSourceRoute(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_h245ipSourceRoute, T_h245ipSourceRoute_sequence);

  return offset;
}
static int dissect_h245ipSourceRoute(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_h245ipSourceRoute(tvb, offset, actx, tree, hf_h225_h245ipSourceRoute);
}



static int
dissect_h225_OCTET_STRING_SIZE_6(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       6, 6, NULL);

  return offset;
}
static int dissect_node(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_6(tvb, offset, actx, tree, hf_h225_node);
}



static int
dissect_h225_OCTET_STRING_SIZE_2(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 2, NULL);

  return offset;
}
static int dissect_ipx_port(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_2(tvb, offset, actx, tree, hf_h225_ipx_port);
}
static int dissect_h245ipxport(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_2(tvb, offset, actx, tree, hf_h225_h245ipxport);
}


static const per_sequence_t T_h245ipxAddress_sequence[] = {
  { "node"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_node },
  { "netnum"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_netnum },
  { "h245ipxport"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245ipxport },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_h245ipxAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_h245ipxAddress, T_h245ipxAddress_sequence);

  return offset;
}
static int dissect_h245ipxAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_h245ipxAddress(tvb, offset, actx, tree, hf_h225_h245ipxAddress);
}



static int
dissect_h225_OCTET_STRING_SIZE_16(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, NULL);

  return offset;
}
static int dissect_ipV6(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_16(tvb, offset, actx, tree, hf_h225_ipV6);
}
static int dissect_netBios(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_16(tvb, offset, actx, tree, hf_h225_netBios);
}
static int dissect_h245ipv6(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_16(tvb, offset, actx, tree, hf_h225_h245ipv6);
}
static int dissect_h245netBios(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_16(tvb, offset, actx, tree, hf_h225_h245netBios);
}


static const per_sequence_t T_h245ip6Address_sequence[] = {
  { "h245ipv6"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245ipv6 },
  { "h245ipv6port"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245ipv6port },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_h245ip6Address(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_h245ip6Address, T_h245ip6Address_sequence);

  return offset;
}
static int dissect_h245ip6Address(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_h245ip6Address(tvb, offset, actx, tree, hf_h225_h245ip6Address);
}



static int
dissect_h225_OCTET_STRING_SIZE_1_20(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 20, NULL);

  return offset;
}
static int dissect_nsap(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_1_20(tvb, offset, actx, tree, hf_h225_nsap);
}
static int dissect_h245nsap(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_1_20(tvb, offset, actx, tree, hf_h225_h245nsap);
}



static int
dissect_h225_T_object(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_object_identifier_str(tvb, offset, actx, tree, hf_index, &nsiOID);

  return offset;
}
static int dissect_nsiOID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_object(tvb, offset, actx, tree, hf_h225_nsiOID);
}



static int
dissect_h225_T_t35CountryCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, &t35CountryCode, FALSE);

  return offset;
}
static int dissect_t35CountryCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_t35CountryCode(tvb, offset, actx, tree, hf_h225_t35CountryCode);
}



static int
dissect_h225_T_t35Extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, &t35Extension, FALSE);

  return offset;
}
static int dissect_t35Extension(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_t35Extension(tvb, offset, actx, tree, hf_h225_t35Extension);
}



static int
dissect_h225_T_manufacturerCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, &manufacturerCode, FALSE);

  return offset;
}
static int dissect_manufacturerCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_manufacturerCode(tvb, offset, actx, tree, hf_h225_manufacturerCode);
}


static const per_sequence_t H221NonStandard_sequence[] = {
  { "t35CountryCode"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t35CountryCode },
  { "t35Extension"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t35Extension },
  { "manufacturerCode"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_manufacturerCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_H221NonStandard(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 509 "h225.cnf"
  t35CountryCode = 0;
  t35Extension = 0;
  manufacturerCode = 0;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_H221NonStandard, H221NonStandard_sequence);

#line 513 "h225.cnf"
  h221NonStandard = ((t35CountryCode * 256) + t35Extension) * 65536 + manufacturerCode;
  proto_tree_add_uint(tree, hf_h221Manufacturer, tvb, (offset>>3)-4, 4, h221NonStandard);

  return offset;
}
static int dissect_vendorIdentifier_vendor(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H221NonStandard(tvb, offset, actx, tree, hf_h225_vendorIdentifier_vendor);
}
static int dissect_h221NonStandard(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H221NonStandard(tvb, offset, actx, tree, hf_h225_h221NonStandard);
}


static const value_string h225_NonStandardIdentifier_vals[] = {
  {   0, "object" },
  {   1, "h221NonStandard" },
  { 0, NULL }
};

static const per_choice_t NonStandardIdentifier_choice[] = {
  {   0, "object"                      , ASN1_EXTENSION_ROOT    , dissect_nsiOID },
  {   1, "h221NonStandard"             , ASN1_EXTENSION_ROOT    , dissect_h221NonStandard },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_NonStandardIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 490 "h225.cnf"
	guint32 value;

	nsiOID = "";
	h221NonStandard = 0;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_NonStandardIdentifier, NonStandardIdentifier_choice,
                                 &value);

	switch (value) {
		case 0 :  /* object */
			nsp_handle = dissector_get_string_handle(nsp_object_dissector_table, nsiOID);
			break;
		case 1 :  /* h221NonStandard */
			nsp_handle = dissector_get_port_handle(nsp_h221_dissector_table, h221NonStandard);
			break;
		default :
			nsp_handle = NULL;
    }


  return offset;
}
static int dissect_nonStandardIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NonStandardIdentifier(tvb, offset, actx, tree, hf_h225_nonStandardIdentifier);
}



static int
dissect_h225_T_data(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 524 "h225.cnf"
  tvbuff_t *next_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, &next_tvb);

  if (next_tvb && tvb_length(next_tvb)) {
    call_dissector((nsp_handle)?nsp_handle:data_handle, next_tvb, actx->pinfo, tree);
  }


  return offset;
}
static int dissect_nsp_data(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_data(tvb, offset, actx, tree, hf_h225_nsp_data);
}


static const per_sequence_t NonStandardParameter_sequence[] = {
  { "nonStandardIdentifier"       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nonStandardIdentifier },
  { "data"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nsp_data },
  { NULL, 0, 0, NULL }
};

int
dissect_h225_NonStandardParameter(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 522 "h225.cnf"
  nsp_handle = NULL;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_NonStandardParameter, NonStandardParameter_sequence);

  return offset;
}
static int dissect_nonStandardData(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NonStandardParameter(tvb, offset, actx, tree, hf_h225_nonStandardData);
}
static int dissect_nonStandardControl_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NonStandardParameter(tvb, offset, actx, tree, hf_h225_nonStandardControl_item);
}
static int dissect_nonStandard(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NonStandardParameter(tvb, offset, actx, tree, hf_h225_nonStandard);
}
static int dissect_nonStandardReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NonStandardParameter(tvb, offset, actx, tree, hf_h225_nonStandardReason);
}
static int dissect_nonStandardAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NonStandardParameter(tvb, offset, actx, tree, hf_h225_nonStandardAddress);
}
static int dissect_nonStandardUsageTypes_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NonStandardParameter(tvb, offset, actx, tree, hf_h225_nonStandardUsageTypes_item);
}
static int dissect_nonStandardUsageFields_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NonStandardParameter(tvb, offset, actx, tree, hf_h225_nonStandardUsageFields_item);
}


static const value_string h225_H245TransportAddress_vals[] = {
  {   0, "h245ipAddress" },
  {   1, "h245ipSourceRoute" },
  {   2, "h245ipxAddress" },
  {   3, "h245ip6Address" },
  {   4, "h245netBios" },
  {   5, "h245nsap" },
  {   6, "nonStandardAddress" },
  { 0, NULL }
};

static const per_choice_t H245TransportAddress_choice[] = {
  {   0, "h245ipAddress"               , ASN1_EXTENSION_ROOT    , dissect_h245ipAddress },
  {   1, "h245ipSourceRoute"           , ASN1_EXTENSION_ROOT    , dissect_h245ipSourceRoute },
  {   2, "h245ipxAddress"              , ASN1_EXTENSION_ROOT    , dissect_h245ipxAddress },
  {   3, "h245ip6Address"              , ASN1_EXTENSION_ROOT    , dissect_h245ip6Address },
  {   4, "h245netBios"                 , ASN1_EXTENSION_ROOT    , dissect_h245netBios },
  {   5, "h245nsap"                    , ASN1_EXTENSION_ROOT    , dissect_h245nsap },
  {   6, "nonStandardAddress"          , ASN1_EXTENSION_ROOT    , dissect_nonStandardAddress },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_H245TransportAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 319 "h225.cnf"
	ipv4_address=0;
	ipv4_port=0;


  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_H245TransportAddress, H245TransportAddress_choice,
                                 NULL);

#line 325 "h225.cnf"
	/* we need this info for TAPing */
	h225_pi->is_h245 = TRUE;
	h225_pi->h245_address = ipv4_address;	
	h225_pi->h245_port = ipv4_port;	

	if((!actx->pinfo->fd->flags.visited) && ipv4_address!=0 && ipv4_port!=0 && h245_handle){
		address src_addr;
		conversation_t *conv=NULL;

		src_addr.type=AT_IPv4;
		src_addr.len=4;
		src_addr.data=(const guint8 *)&ipv4_address;

		conv=find_conversation(actx->pinfo->fd->num, &src_addr, &src_addr, PT_TCP, ipv4_port, ipv4_port, NO_ADDR_B|NO_PORT_B);
		if(!conv){
			conv=conversation_new(actx->pinfo->fd->num, &src_addr, &src_addr, PT_TCP, ipv4_port, ipv4_port, NO_ADDR2|NO_PORT2);
			conversation_set_dissector(conv, h245_handle);
		}
	}


  return offset;
}
static int dissect_h245Address(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H245TransportAddress(tvb, offset, actx, tree, hf_h225_h245Address);
}



static int
dissect_h225_DialedDigits(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 197 "h225.cnf"
  tvbuff_t *value_tvb = NULL;
  guint len = 0;

  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 128, "0123456789#*,", strlen("0123456789#*,"),
                                                      &value_tvb);

  if (h225_pi->is_destinationInfo == TRUE) {
    if (value_tvb) {
      len = tvb_length(value_tvb);
      /* XXX - should this be allocated as an ephemeral string? */
      if (len > sizeof h225_pi->dialedDigits - 1)
        len = sizeof h225_pi->dialedDigits - 1;
      tvb_memcpy(value_tvb, (guint8*)h225_pi->dialedDigits, 0, len);
    }
    h225_pi->dialedDigits[len] = '\0';
    h225_pi->is_destinationInfo = FALSE;
  }


  return offset;
}
static int dissect_dialedDigits(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_DialedDigits(tvb, offset, actx, tree, hf_h225_dialedDigits);
}



static int
dissect_h225_BMPString_SIZE_1_256(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          1, 256);

  return offset;
}
static int dissect_h323_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BMPString_SIZE_1_256(tvb, offset, actx, tree, hf_h225_h323_ID);
}



static int
dissect_h225_IA5String_SIZE_1_512(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 512);

  return offset;
}
static int dissect_url_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_IA5String_SIZE_1_512(tvb, offset, actx, tree, hf_h225_url_ID);
}
static int dissect_email_ID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_IA5String_SIZE_1_512(tvb, offset, actx, tree, hf_h225_email_ID);
}



static int
dissect_h225_IpV4(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, NULL);

  return offset;
}
static int dissect_ipV4(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_IpV4(tvb, offset, actx, tree, hf_h225_ipV4);
}


static const per_sequence_t T_ipAddress_sequence[] = {
  { "ip"                          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ipV4 },
  { "port"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ipV4_port },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_ipAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_ipAddress, T_ipAddress_sequence);

  return offset;
}
static int dissect_ipAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_ipAddress(tvb, offset, actx, tree, hf_h225_ipAddress);
}


static const per_sequence_t T_route_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_route_item },
};

static int
dissect_h225_T_route(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_T_route, T_route_sequence_of);

  return offset;
}
static int dissect_route(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_route(tvb, offset, actx, tree, hf_h225_route);
}


static const value_string h225_T_routing_vals[] = {
  {   0, "strict" },
  {   1, "loose" },
  { 0, NULL }
};

static const per_choice_t T_routing_choice[] = {
  {   0, "strict"                      , ASN1_EXTENSION_ROOT    , dissect_strict },
  {   1, "loose"                       , ASN1_EXTENSION_ROOT    , dissect_loose },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_T_routing(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_T_routing, T_routing_choice,
                                 NULL);

  return offset;
}
static int dissect_routing(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_routing(tvb, offset, actx, tree, hf_h225_routing);
}


static const per_sequence_t T_ipSourceRoute_sequence[] = {
  { "ip"                          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_src_route_ipV4 },
  { "port"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ipV4_src_port },
  { "route"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_route },
  { "routing"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_routing },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_ipSourceRoute(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_ipSourceRoute, T_ipSourceRoute_sequence);

  return offset;
}
static int dissect_ipSourceRoute(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_ipSourceRoute(tvb, offset, actx, tree, hf_h225_ipSourceRoute);
}


static const per_sequence_t T_ipxAddress_sequence[] = {
  { "node"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_node },
  { "netnum"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_netnum },
  { "port"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ipx_port },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_ipxAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_ipxAddress, T_ipxAddress_sequence);

  return offset;
}
static int dissect_ipxAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_ipxAddress(tvb, offset, actx, tree, hf_h225_ipxAddress);
}


static const per_sequence_t T_ip6Address_sequence[] = {
  { "ip"                          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ipV6 },
  { "port"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ipV6_port },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_ip6Address(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_ip6Address, T_ip6Address_sequence);

  return offset;
}
static int dissect_ip6Address(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_ip6Address(tvb, offset, actx, tree, hf_h225_ip6Address);
}


static const value_string h225_TransportAddress_vals[] = {
  {   0, "ipAddress" },
  {   1, "ipSourceRoute" },
  {   2, "ipxAddress" },
  {   3, "ip6Address" },
  {   4, "netBios" },
  {   5, "nsap" },
  {   6, "nonStandardAddress" },
  { 0, NULL }
};

static const per_choice_t TransportAddress_choice[] = {
  {   0, "ipAddress"                   , ASN1_EXTENSION_ROOT    , dissect_ipAddress },
  {   1, "ipSourceRoute"               , ASN1_EXTENSION_ROOT    , dissect_ipSourceRoute },
  {   2, "ipxAddress"                  , ASN1_EXTENSION_ROOT    , dissect_ipxAddress },
  {   3, "ip6Address"                  , ASN1_EXTENSION_ROOT    , dissect_ip6Address },
  {   4, "netBios"                     , ASN1_EXTENSION_ROOT    , dissect_netBios },
  {   5, "nsap"                        , ASN1_EXTENSION_ROOT    , dissect_nsap },
  {   6, "nonStandardAddress"          , ASN1_EXTENSION_ROOT    , dissect_nonStandardAddress },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_TransportAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_TransportAddress, TransportAddress_choice,
                                 NULL);

  return offset;
}
static int dissect_destCallSignalAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_destCallSignalAddress);
}
static int dissect_sourceCallSignalAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_sourceCallSignalAddress);
}
static int dissect_alternativeAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_alternativeAddress);
}
static int dissect_transportID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_transportID);
}
static int dissect_callSignalAddress_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_callSignalAddress_item);
}
static int dissect_rasAddress_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_rasAddress_item);
}
static int dissect_annexE_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_annexE_item);
}
static int dissect_sctp_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_sctp_item);
}
static int dissect_alternateGK_rasAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_alternateGK_rasAddress);
}
static int dissect_transport(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_transport);
}
static int dissect_sendAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_sendAddress);
}
static int dissect_recvAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_recvAddress);
}
static int dissect_gatekeeperRequest_rasAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_gatekeeperRequest_rasAddress);
}
static int dissect_gatekeeperConfirm_rasAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_gatekeeperConfirm_rasAddress);
}
static int dissect_srcCallSignalAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_srcCallSignalAddress);
}
static int dissect_replyAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_replyAddress);
}
static int dissect_locationConfirm_callSignalAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_locationConfirm_callSignalAddress);
}
static int dissect_locationConfirm_rasAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_locationConfirm_rasAddress);
}
static int dissect_infoRequestResponse_rasAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportAddress(tvb, offset, actx, tree, hf_h225_infoRequestResponse_rasAddress);
}


static const value_string h225_PublicTypeOfNumber_vals[] = {
  {   0, "unknown" },
  {   1, "internationalNumber" },
  {   2, "nationalNumber" },
  {   3, "networkSpecificNumber" },
  {   4, "subscriberNumber" },
  {   5, "abbreviatedNumber" },
  { 0, NULL }
};

static const per_choice_t PublicTypeOfNumber_choice[] = {
  {   0, "unknown"                     , ASN1_EXTENSION_ROOT    , dissect_unknown },
  {   1, "internationalNumber"         , ASN1_EXTENSION_ROOT    , dissect_internationalNumber },
  {   2, "nationalNumber"              , ASN1_EXTENSION_ROOT    , dissect_nationalNumber },
  {   3, "networkSpecificNumber"       , ASN1_EXTENSION_ROOT    , dissect_networkSpecificNumber },
  {   4, "subscriberNumber"            , ASN1_EXTENSION_ROOT    , dissect_subscriberNumber },
  {   5, "abbreviatedNumber"           , ASN1_EXTENSION_ROOT    , dissect_abbreviatedNumber },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_PublicTypeOfNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_PublicTypeOfNumber, PublicTypeOfNumber_choice,
                                 NULL);

  return offset;
}
static int dissect_publicTypeOfNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PublicTypeOfNumber(tvb, offset, actx, tree, hf_h225_publicTypeOfNumber);
}



static int
dissect_h225_NumberDigits(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 128, "0123456789#*,", strlen("0123456789#*,"),
                                                      NULL);

  return offset;
}
static int dissect_dataPartyNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NumberDigits(tvb, offset, actx, tree, hf_h225_dataPartyNumber);
}
static int dissect_telexPartyNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NumberDigits(tvb, offset, actx, tree, hf_h225_telexPartyNumber);
}
static int dissect_nationalStandardPartyNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NumberDigits(tvb, offset, actx, tree, hf_h225_nationalStandardPartyNumber);
}
static int dissect_publicNumberDigits(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NumberDigits(tvb, offset, actx, tree, hf_h225_publicNumberDigits);
}
static int dissect_privateNumberDigits(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NumberDigits(tvb, offset, actx, tree, hf_h225_privateNumberDigits);
}


static const per_sequence_t PublicPartyNumber_sequence[] = {
  { "publicTypeOfNumber"          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_publicTypeOfNumber },
  { "publicNumberDigits"          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_publicNumberDigits },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_PublicPartyNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_PublicPartyNumber, PublicPartyNumber_sequence);

  return offset;
}
static int dissect_e164Number(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PublicPartyNumber(tvb, offset, actx, tree, hf_h225_e164Number);
}


static const value_string h225_PrivateTypeOfNumber_vals[] = {
  {   0, "unknown" },
  {   1, "level2RegionalNumber" },
  {   2, "level1RegionalNumber" },
  {   3, "pISNSpecificNumber" },
  {   4, "localNumber" },
  {   5, "abbreviatedNumber" },
  { 0, NULL }
};

static const per_choice_t PrivateTypeOfNumber_choice[] = {
  {   0, "unknown"                     , ASN1_EXTENSION_ROOT    , dissect_unknown },
  {   1, "level2RegionalNumber"        , ASN1_EXTENSION_ROOT    , dissect_level2RegionalNumber },
  {   2, "level1RegionalNumber"        , ASN1_EXTENSION_ROOT    , dissect_level1RegionalNumber },
  {   3, "pISNSpecificNumber"          , ASN1_EXTENSION_ROOT    , dissect_pISNSpecificNumber },
  {   4, "localNumber"                 , ASN1_EXTENSION_ROOT    , dissect_localNumber },
  {   5, "abbreviatedNumber"           , ASN1_EXTENSION_ROOT    , dissect_abbreviatedNumber },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_PrivateTypeOfNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_PrivateTypeOfNumber, PrivateTypeOfNumber_choice,
                                 NULL);

  return offset;
}
static int dissect_privateTypeOfNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PrivateTypeOfNumber(tvb, offset, actx, tree, hf_h225_privateTypeOfNumber);
}


static const per_sequence_t PrivatePartyNumber_sequence[] = {
  { "privateTypeOfNumber"         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_privateTypeOfNumber },
  { "privateNumberDigits"         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_privateNumberDigits },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_PrivatePartyNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_PrivatePartyNumber, PrivatePartyNumber_sequence);

  return offset;
}
static int dissect_privateNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PrivatePartyNumber(tvb, offset, actx, tree, hf_h225_privateNumber);
}


const value_string h225_PartyNumber_vals[] = {
  {   0, "e164Number" },
  {   1, "dataPartyNumber" },
  {   2, "telexPartyNumber" },
  {   3, "privateNumber" },
  {   4, "nationalStandardPartyNumber" },
  { 0, NULL }
};

static const per_choice_t PartyNumber_choice[] = {
  {   0, "e164Number"                  , ASN1_EXTENSION_ROOT    , dissect_e164Number },
  {   1, "dataPartyNumber"             , ASN1_EXTENSION_ROOT    , dissect_dataPartyNumber },
  {   2, "telexPartyNumber"            , ASN1_EXTENSION_ROOT    , dissect_telexPartyNumber },
  {   3, "privateNumber"               , ASN1_EXTENSION_ROOT    , dissect_privateNumber },
  {   4, "nationalStandardPartyNumber" , ASN1_EXTENSION_ROOT    , dissect_nationalStandardPartyNumber },
  { 0, NULL, 0, NULL }
};

int
dissect_h225_PartyNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_PartyNumber, PartyNumber_choice,
                                 NULL);

  return offset;
}
static int dissect_partyNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PartyNumber(tvb, offset, actx, tree, hf_h225_partyNumber);
}
static int dissect_startOfRange(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PartyNumber(tvb, offset, actx, tree, hf_h225_startOfRange);
}
static int dissect_endOfRange(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PartyNumber(tvb, offset, actx, tree, hf_h225_endOfRange);
}
static int dissect_routeCallToSCN_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PartyNumber(tvb, offset, actx, tree, hf_h225_routeCallToSCN_item);
}
static int dissect_routeCalltoSCN_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PartyNumber(tvb, offset, actx, tree, hf_h225_routeCalltoSCN_item);
}



static int
dissect_h225_TBCD_STRING(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      NO_BOUND, NO_BOUND, "0123456789#*abc", strlen("0123456789#*abc"),
                                                      NULL);

  return offset;
}
static int dissect_imsi(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TBCD_STRING(tvb, offset, actx, tree, hf_h225_imsi);
}
static int dissect_min(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TBCD_STRING(tvb, offset, actx, tree, hf_h225_min);
}
static int dissect_mdn(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TBCD_STRING(tvb, offset, actx, tree, hf_h225_mdn);
}
static int dissect_msisdn(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TBCD_STRING(tvb, offset, actx, tree, hf_h225_msisdn);
}
static int dissect_esn(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TBCD_STRING(tvb, offset, actx, tree, hf_h225_esn);
}
static int dissect_mscid(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TBCD_STRING(tvb, offset, actx, tree, hf_h225_mscid);
}
static int dissect_sid(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TBCD_STRING(tvb, offset, actx, tree, hf_h225_sid);
}
static int dissect_mid(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TBCD_STRING(tvb, offset, actx, tree, hf_h225_mid);
}
static int dissect_sesn(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TBCD_STRING(tvb, offset, actx, tree, hf_h225_sesn);
}
static int dissect_soc(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TBCD_STRING(tvb, offset, actx, tree, hf_h225_soc);
}
static int dissect_imei(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TBCD_STRING(tvb, offset, actx, tree, hf_h225_imei);
}
static int dissect_hplmn(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TBCD_STRING(tvb, offset, actx, tree, hf_h225_hplmn);
}
static int dissect_vplmn(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TBCD_STRING(tvb, offset, actx, tree, hf_h225_vplmn);
}


static const value_string h225_T_system_id_vals[] = {
  {   0, "sid" },
  {   1, "mid" },
  { 0, NULL }
};

static const per_choice_t T_system_id_choice[] = {
  {   0, "sid"                         , ASN1_EXTENSION_ROOT    , dissect_sid },
  {   1, "mid"                         , ASN1_EXTENSION_ROOT    , dissect_mid },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_T_system_id(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_T_system_id, T_system_id_choice,
                                 NULL);

  return offset;
}
static int dissect_system_id(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_system_id(tvb, offset, actx, tree, hf_h225_system_id);
}



static int
dissect_h225_OCTET_STRING_SIZE_1(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 1, NULL);

  return offset;
}
static int dissect_systemMyTypeCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_1(tvb, offset, actx, tree, hf_h225_systemMyTypeCode);
}
static int dissect_systemAccessType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_1(tvb, offset, actx, tree, hf_h225_systemAccessType);
}
static int dissect_qualificationInformationCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_1(tvb, offset, actx, tree, hf_h225_qualificationInformationCode);
}


static const per_sequence_t ANSI_41_UIM_sequence[] = {
  { "imsi"                        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_imsi },
  { "min"                         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_min },
  { "mdn"                         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_mdn },
  { "msisdn"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_msisdn },
  { "esn"                         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_esn },
  { "mscid"                       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_mscid },
  { "system-id"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_system_id },
  { "systemMyTypeCode"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_systemMyTypeCode },
  { "systemAccessType"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_systemAccessType },
  { "qualificationInformationCode", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_qualificationInformationCode },
  { "sesn"                        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sesn },
  { "soc"                         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_soc },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_ANSI_41_UIM(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_ANSI_41_UIM, ANSI_41_UIM_sequence);

  return offset;
}
static int dissect_ansi_41_uim(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ANSI_41_UIM(tvb, offset, actx, tree, hf_h225_ansi_41_uim);
}



static int
dissect_h225_OCTET_STRING_SIZE_1_4(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 4, NULL);

  return offset;
}
static int dissect_tmsi(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_1_4(tvb, offset, actx, tree, hf_h225_tmsi);
}


static const per_sequence_t GSM_UIM_sequence[] = {
  { "imsi"                        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_imsi },
  { "tmsi"                        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tmsi },
  { "msisdn"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_msisdn },
  { "imei"                        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_imei },
  { "hplmn"                       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_hplmn },
  { "vplmn"                       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_vplmn },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_GSM_UIM(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_GSM_UIM, GSM_UIM_sequence);

  return offset;
}
static int dissect_gsm_uim(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GSM_UIM(tvb, offset, actx, tree, hf_h225_gsm_uim);
}


static const value_string h225_MobileUIM_vals[] = {
  {   0, "ansi-41-uim" },
  {   1, "gsm-uim" },
  { 0, NULL }
};

static const per_choice_t MobileUIM_choice[] = {
  {   0, "ansi-41-uim"                 , ASN1_EXTENSION_ROOT    , dissect_ansi_41_uim },
  {   1, "gsm-uim"                     , ASN1_EXTENSION_ROOT    , dissect_gsm_uim },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_MobileUIM(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_MobileUIM, MobileUIM_choice,
                                 NULL);

  return offset;
}
static int dissect_mobileUIM(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_MobileUIM(tvb, offset, actx, tree, hf_h225_mobileUIM);
}


const value_string AliasAddress_vals[] = {
  {   0, "dialedDigits" },
  {   1, "h323-ID" },
  {   2, "url-ID" },
  {   3, "transportID" },
  {   4, "email-ID" },
  {   5, "partyNumber" },
  {   6, "mobileUIM" },
  { 0, NULL }
};

static const per_choice_t AliasAddress_choice[] = {
  {   0, "dialedDigits"                , ASN1_EXTENSION_ROOT    , dissect_dialedDigits },
  {   1, "h323-ID"                     , ASN1_EXTENSION_ROOT    , dissect_h323_ID },
  {   2, "url-ID"                      , ASN1_NOT_EXTENSION_ROOT, dissect_url_ID },
  {   3, "transportID"                 , ASN1_NOT_EXTENSION_ROOT, dissect_transportID },
  {   4, "email-ID"                    , ASN1_NOT_EXTENSION_ROOT, dissect_email_ID },
  {   5, "partyNumber"                 , ASN1_NOT_EXTENSION_ROOT, dissect_partyNumber },
  {   6, "mobileUIM"                   , ASN1_NOT_EXTENSION_ROOT, dissect_mobileUIM },
  { 0, NULL, 0, NULL }
};

int
dissect_h225_AliasAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_AliasAddress, AliasAddress_choice,
                                 NULL);

  return offset;
}
static int dissect_alertingAddress_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_alertingAddress_item);
}
static int dissect_connectedAddress_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_connectedAddress_item);
}
static int dissect_busyAddress_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_busyAddress_item);
}
static int dissect_sourceAddress_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_sourceAddress_item);
}
static int dissect_destinationAddress_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_destinationAddress_item);
}
static int dissect_destExtraCallInfo_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_destExtraCallInfo_item);
}
static int dissect_uUIE_remoteExtensionAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_uUIE_remoteExtensionAddress);
}
static int dissect_alternativeAliasAddress_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_alternativeAliasAddress_item);
}
static int dissect_conferenceAlias(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_conferenceAlias);
}
static int dissect_wildcard(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_wildcard);
}
static int dissect_address(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_address);
}
static int dissect_aliasAddress_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_aliasAddress_item);
}
static int dissect_remoteExtensionAddress_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_remoteExtensionAddress_item);
}
static int dissect_alias(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_alias);
}
static int dissect_prefix(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_prefix);
}
static int dissect_endpointAlias_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_endpointAlias_item);
}
static int dissect_terminalAlias_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_terminalAlias_item);
}
static int dissect_featureServerAlias(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_featureServerAlias);
}
static int dissect_duplicateAlias_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_duplicateAlias_item);
}
static int dissect_srcInfo_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_srcInfo_item);
}
static int dissect_modifiedSrcInfo_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_modifiedSrcInfo_item);
}
static int dissect_sourceInfo_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_sourceInfo_item);
}
static int dissect_sourceEndpointInfo_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_h225_sourceEndpointInfo_item);
}


static const per_sequence_t SEQUENCE_OF_AliasAddress_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_alertingAddress_item },
};

static int
dissect_h225_SEQUENCE_OF_AliasAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_AliasAddress, SEQUENCE_OF_AliasAddress_sequence_of);

  return offset;
}
static int dissect_alertingAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_alertingAddress);
}
static int dissect_connectedAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_connectedAddress);
}
static int dissect_busyAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_busyAddress);
}
static int dissect_sourceAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_sourceAddress);
}
static int dissect_destinationAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_destinationAddress);
}
static int dissect_destExtraCallInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_destExtraCallInfo);
}
static int dissect_alternativeAliasAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_alternativeAliasAddress);
}
static int dissect_aliasAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_aliasAddress);
}
static int dissect_remoteExtensionAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_remoteExtensionAddress);
}
static int dissect_endpointAlias(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_endpointAlias);
}
static int dissect_terminalAlias(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_terminalAlias);
}
static int dissect_duplicateAlias(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_duplicateAlias);
}
static int dissect_srcInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_srcInfo);
}
static int dissect_modifiedSrcInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_modifiedSrcInfo);
}
static int dissect_sourceInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_sourceInfo);
}
static int dissect_sourceEndpointInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AliasAddress(tvb, offset, actx, tree, hf_h225_sourceEndpointInfo);
}



static int
dissect_h225_OCTET_STRING_SIZE_1_256(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 256, NULL);

  return offset;
}
static int dissect_productId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_1_256(tvb, offset, actx, tree, hf_h225_productId);
}
static int dissect_versionId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_1_256(tvb, offset, actx, tree, hf_h225_versionId);
}



static int
dissect_h225_OBJECT_IDENTIFIER(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}
static int dissect_enterpriseNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OBJECT_IDENTIFIER(tvb, offset, actx, tree, hf_h225_enterpriseNumber);
}
static int dissect_isoAlgorithm(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OBJECT_IDENTIFIER(tvb, offset, actx, tree, hf_h225_isoAlgorithm);
}
static int dissect_hMAC_iso10118_3(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OBJECT_IDENTIFIER(tvb, offset, actx, tree, hf_h225_hMAC_iso10118_3);
}
static int dissect_iso9797(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OBJECT_IDENTIFIER(tvb, offset, actx, tree, hf_h225_iso9797);
}
static int dissect_algorithmOID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OBJECT_IDENTIFIER(tvb, offset, actx, tree, hf_h225_algorithmOID);
}
static int dissect_oid(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OBJECT_IDENTIFIER(tvb, offset, actx, tree, hf_h225_oid);
}
static int dissect_algorithmOIDs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OBJECT_IDENTIFIER(tvb, offset, actx, tree, hf_h225_algorithmOIDs_item);
}


static const per_sequence_t VendorIdentifier_sequence[] = {
  { "vendor"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_vendorIdentifier_vendor },
  { "productId"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_productId },
  { "versionId"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_versionId },
  { "enterpriseNumber"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_enterpriseNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_VendorIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_VendorIdentifier, VendorIdentifier_sequence);

  return offset;
}
static int dissect_vendor(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_VendorIdentifier(tvb, offset, actx, tree, hf_h225_vendor);
}
static int dissect_endpointVendor(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_VendorIdentifier(tvb, offset, actx, tree, hf_h225_endpointVendor);
}


static const per_sequence_t GatekeeperInfo_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_GatekeeperInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_GatekeeperInfo, GatekeeperInfo_sequence);

  return offset;
}
static int dissect_gatekeeper(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GatekeeperInfo(tvb, offset, actx, tree, hf_h225_gatekeeper);
}



static int
dissect_h225_BandWidth(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 4294967295U, NULL, FALSE);

  return offset;
}
static int dissect_channelRate(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BandWidth(tvb, offset, actx, tree, hf_h225_channelRate);
}
static int dissect_bandwidth(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BandWidth(tvb, offset, actx, tree, hf_h225_bandwidth);
}
static int dissect_totalBandwidthRestriction(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BandWidth(tvb, offset, actx, tree, hf_h225_totalBandwidthRestriction);
}
static int dissect_bandWidth(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BandWidth(tvb, offset, actx, tree, hf_h225_bandWidth);
}
static int dissect_allowedBandWidth(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BandWidth(tvb, offset, actx, tree, hf_h225_allowedBandWidth);
}



static int
dissect_h225_INTEGER_1_256(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 256U, NULL, FALSE);

  return offset;
}
static int dissect_channelMultiplier(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_1_256(tvb, offset, actx, tree, hf_h225_channelMultiplier);
}


static const per_sequence_t DataRate_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "channelRate"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_channelRate },
  { "channelMultiplier"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_channelMultiplier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_DataRate(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_DataRate, DataRate_sequence);

  return offset;
}
static int dissect_dataRatesSupported_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_DataRate(tvb, offset, actx, tree, hf_h225_dataRatesSupported_item);
}
static int dissect_gatewayDataRate(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_DataRate(tvb, offset, actx, tree, hf_h225_gatewayDataRate);
}


static const per_sequence_t SEQUENCE_OF_DataRate_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_dataRatesSupported_item },
};

static int
dissect_h225_SEQUENCE_OF_DataRate(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_DataRate, SEQUENCE_OF_DataRate_sequence_of);

  return offset;
}
static int dissect_dataRatesSupported(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_DataRate(tvb, offset, actx, tree, hf_h225_dataRatesSupported);
}


static const per_sequence_t SupportedPrefix_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "prefix"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_prefix },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_SupportedPrefix(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_SupportedPrefix, SupportedPrefix_sequence);

  return offset;
}
static int dissect_supportedPrefixes_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SupportedPrefix(tvb, offset, actx, tree, hf_h225_supportedPrefixes_item);
}


static const per_sequence_t SEQUENCE_OF_SupportedPrefix_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_supportedPrefixes_item },
};

static int
dissect_h225_SEQUENCE_OF_SupportedPrefix(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_SupportedPrefix, SEQUENCE_OF_SupportedPrefix_sequence_of);

  return offset;
}
static int dissect_supportedPrefixes(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_SupportedPrefix(tvb, offset, actx, tree, hf_h225_supportedPrefixes);
}


static const per_sequence_t H310Caps_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "dataRatesSupported"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_dataRatesSupported },
  { "supportedPrefixes"           , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_supportedPrefixes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_H310Caps(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_H310Caps, H310Caps_sequence);

  return offset;
}
static int dissect_h310(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H310Caps(tvb, offset, actx, tree, hf_h225_h310);
}


static const per_sequence_t H320Caps_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "dataRatesSupported"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_dataRatesSupported },
  { "supportedPrefixes"           , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_supportedPrefixes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_H320Caps(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_H320Caps, H320Caps_sequence);

  return offset;
}
static int dissect_h320(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H320Caps(tvb, offset, actx, tree, hf_h225_h320);
}


static const per_sequence_t H321Caps_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "dataRatesSupported"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_dataRatesSupported },
  { "supportedPrefixes"           , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_supportedPrefixes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_H321Caps(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_H321Caps, H321Caps_sequence);

  return offset;
}
static int dissect_h321(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H321Caps(tvb, offset, actx, tree, hf_h225_h321);
}


static const per_sequence_t H322Caps_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "dataRatesSupported"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_dataRatesSupported },
  { "supportedPrefixes"           , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_supportedPrefixes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_H322Caps(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_H322Caps, H322Caps_sequence);

  return offset;
}
static int dissect_h322(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H322Caps(tvb, offset, actx, tree, hf_h225_h322);
}


static const per_sequence_t H323Caps_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "dataRatesSupported"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_dataRatesSupported },
  { "supportedPrefixes"           , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_supportedPrefixes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_H323Caps(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_H323Caps, H323Caps_sequence);

  return offset;
}
static int dissect_h323(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H323Caps(tvb, offset, actx, tree, hf_h225_h323);
}


static const per_sequence_t H324Caps_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "dataRatesSupported"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_dataRatesSupported },
  { "supportedPrefixes"           , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_supportedPrefixes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_H324Caps(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_H324Caps, H324Caps_sequence);

  return offset;
}
static int dissect_h324(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H324Caps(tvb, offset, actx, tree, hf_h225_h324);
}


static const per_sequence_t VoiceCaps_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "dataRatesSupported"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_dataRatesSupported },
  { "supportedPrefixes"           , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_supportedPrefixes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_VoiceCaps(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_VoiceCaps, VoiceCaps_sequence);

  return offset;
}
static int dissect_voice(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_VoiceCaps(tvb, offset, actx, tree, hf_h225_voice);
}


static const per_sequence_t T120OnlyCaps_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "dataRatesSupported"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_dataRatesSupported },
  { "supportedPrefixes"           , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_supportedPrefixes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T120OnlyCaps(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T120OnlyCaps, T120OnlyCaps_sequence);

  return offset;
}
static int dissect_t120_only(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T120OnlyCaps(tvb, offset, actx, tree, hf_h225_t120_only);
}


static const per_sequence_t NonStandardProtocol_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "dataRatesSupported"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dataRatesSupported },
  { "supportedPrefixes"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_supportedPrefixes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_NonStandardProtocol(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_NonStandardProtocol, NonStandardProtocol_sequence);

  return offset;
}
static int dissect_nonStandardProtocol(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NonStandardProtocol(tvb, offset, actx, tree, hf_h225_nonStandardProtocol);
}


static const per_sequence_t T38FaxAnnexbOnlyCaps_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "dataRatesSupported"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dataRatesSupported },
  { "supportedPrefixes"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_supportedPrefixes },
  { "t38FaxProtocol"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t38FaxProtocol },
  { "t38FaxProfile"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_t38FaxProfile },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T38FaxAnnexbOnlyCaps(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T38FaxAnnexbOnlyCaps, T38FaxAnnexbOnlyCaps_sequence);

  return offset;
}
static int dissect_t38FaxAnnexbOnly(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T38FaxAnnexbOnlyCaps(tvb, offset, actx, tree, hf_h225_t38FaxAnnexbOnly);
}


static const per_sequence_t SIPCaps_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "dataRatesSupported"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_dataRatesSupported },
  { "supportedPrefixes"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_supportedPrefixes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_SIPCaps(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_SIPCaps, SIPCaps_sequence);

  return offset;
}
static int dissect_sip(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SIPCaps(tvb, offset, actx, tree, hf_h225_sip);
}


static const value_string h225_SupportedProtocols_vals[] = {
  {   0, "nonStandardData" },
  {   1, "h310" },
  {   2, "h320" },
  {   3, "h321" },
  {   4, "h322" },
  {   5, "h323" },
  {   6, "h324" },
  {   7, "voice" },
  {   8, "t120-only" },
  {   9, "nonStandardProtocol" },
  {  10, "t38FaxAnnexbOnly" },
  {  11, "sip" },
  { 0, NULL }
};

static const per_choice_t SupportedProtocols_choice[] = {
  {   0, "nonStandardData"             , ASN1_EXTENSION_ROOT    , dissect_nonStandardData },
  {   1, "h310"                        , ASN1_EXTENSION_ROOT    , dissect_h310 },
  {   2, "h320"                        , ASN1_EXTENSION_ROOT    , dissect_h320 },
  {   3, "h321"                        , ASN1_EXTENSION_ROOT    , dissect_h321 },
  {   4, "h322"                        , ASN1_EXTENSION_ROOT    , dissect_h322 },
  {   5, "h323"                        , ASN1_EXTENSION_ROOT    , dissect_h323 },
  {   6, "h324"                        , ASN1_EXTENSION_ROOT    , dissect_h324 },
  {   7, "voice"                       , ASN1_EXTENSION_ROOT    , dissect_voice },
  {   8, "t120-only"                   , ASN1_EXTENSION_ROOT    , dissect_t120_only },
  {   9, "nonStandardProtocol"         , ASN1_NOT_EXTENSION_ROOT, dissect_nonStandardProtocol },
  {  10, "t38FaxAnnexbOnly"            , ASN1_NOT_EXTENSION_ROOT, dissect_t38FaxAnnexbOnly },
  {  11, "sip"                         , ASN1_NOT_EXTENSION_ROOT, dissect_sip },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_SupportedProtocols(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_SupportedProtocols, SupportedProtocols_choice,
                                 NULL);

  return offset;
}
static int dissect_desiredProtocols_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SupportedProtocols(tvb, offset, actx, tree, hf_h225_desiredProtocols_item);
}
static int dissect_protocol_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SupportedProtocols(tvb, offset, actx, tree, hf_h225_protocol_item);
}
static int dissect_supportedProtocols_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SupportedProtocols(tvb, offset, actx, tree, hf_h225_supportedProtocols_item);
}
static int dissect_protocols_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SupportedProtocols(tvb, offset, actx, tree, hf_h225_protocols_item);
}


static const per_sequence_t SEQUENCE_OF_SupportedProtocols_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_desiredProtocols_item },
};

static int
dissect_h225_SEQUENCE_OF_SupportedProtocols(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_SupportedProtocols, SEQUENCE_OF_SupportedProtocols_sequence_of);

  return offset;
}
static int dissect_desiredProtocols(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_SupportedProtocols(tvb, offset, actx, tree, hf_h225_desiredProtocols);
}
static int dissect_protocol(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_SupportedProtocols(tvb, offset, actx, tree, hf_h225_protocol);
}
static int dissect_supportedProtocols(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_SupportedProtocols(tvb, offset, actx, tree, hf_h225_supportedProtocols);
}
static int dissect_protocols(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_SupportedProtocols(tvb, offset, actx, tree, hf_h225_protocols);
}


static const per_sequence_t GatewayInfo_sequence[] = {
  { "protocol"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocol },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_GatewayInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_GatewayInfo, GatewayInfo_sequence);

  return offset;
}
static int dissect_gateway(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GatewayInfo(tvb, offset, actx, tree, hf_h225_gateway);
}


static const per_sequence_t McuInfo_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "protocol"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_protocol },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_McuInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_McuInfo, McuInfo_sequence);

  return offset;
}
static int dissect_mcu(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_McuInfo(tvb, offset, actx, tree, hf_h225_mcu);
}


static const per_sequence_t TerminalInfo_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_TerminalInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_TerminalInfo, TerminalInfo_sequence);

  return offset;
}
static int dissect_terminal(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TerminalInfo(tvb, offset, actx, tree, hf_h225_terminal);
}



static int
dissect_h225_BOOLEAN(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}
static int dissect_multipleCalls(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_multipleCalls);
}
static int dissect_maintainConnection(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_maintainConnection);
}
static int dissect_activeMC(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_activeMC);
}
static int dissect_mediaWaitForConnect(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_mediaWaitForConnect);
}
static int dissect_canOverlapSend(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_canOverlapSend);
}
static int dissect_mc(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_mc);
}
static int dissect_undefinedNode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_undefinedNode);
}
static int dissect_needToRegister(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_needToRegister);
}
static int dissect_altGKisPermanent(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_altGKisPermanent);
}
static int dissect_q932Full(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_q932Full);
}
static int dissect_q951Full(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_q951Full);
}
static int dissect_q952Full(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_q952Full);
}
static int dissect_q953Full(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_q953Full);
}
static int dissect_q955Full(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_q955Full);
}
static int dissect_q956Full(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_q956Full);
}
static int dissect_q957Full(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_q957Full);
}
static int dissect_conferenceCalling(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_conferenceCalling);
}
static int dissect_threePartyService(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_threePartyService);
}
static int dissect_canReportCallCapacity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_canReportCallCapacity);
}
static int dissect_sender(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_sender);
}
static int dissect_multicast(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_multicast);
}
static int dissect_canDisplayAmountString(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_canDisplayAmountString);
}
static int dissect_canEnforceDurationLimit(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_canEnforceDurationLimit);
}
static int dissect_enforceCallDurationLimit(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_enforceCallDurationLimit);
}
static int dissect_bool(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_bool);
}
static int dissect_replacementFeatureSet(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_replacementFeatureSet);
}
static int dissect_discoveryComplete(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_discoveryComplete);
}
static int dissect_keepAlive(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_keepAlive);
}
static int dissect_willSupplyUUIEs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_willSupplyUUIEs);
}
static int dissect_willRespondToIRR(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_willRespondToIRR);
}
static int dissect_makeCall(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_makeCall);
}
static int dissect_useGKCallSignalAddressToMakeCall(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_useGKCallSignalAddressToMakeCall);
}
static int dissect_answerCall(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_answerCall);
}
static int dissect_useGKCallSignalAddressToAnswer(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_useGKCallSignalAddressToAnswer);
}
static int dissect_canMapAlias(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_canMapAlias);
}
static int dissect_canMapSrcAlias(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_canMapSrcAlias);
}
static int dissect_setup_bool(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_setup_bool);
}
static int dissect_callProceeding_flg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_callProceeding_flg);
}
static int dissect_connect_bool(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_connect_bool);
}
static int dissect_alerting_bool(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_alerting_bool);
}
static int dissect_information_bool(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_information_bool);
}
static int dissect_releaseComplete_bool(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_releaseComplete_bool);
}
static int dissect_facility_bool(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_facility_bool);
}
static int dissect_progress_bool(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_progress_bool);
}
static int dissect_empty(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_empty);
}
static int dissect_status_bool(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_status_bool);
}
static int dissect_statusInquiry_bool(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_statusInquiry_bool);
}
static int dissect_setupAcknowledge_bool(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_setupAcknowledge_bool);
}
static int dissect_notify_bool(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_notify_bool);
}
static int dissect_answeredCall(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_answeredCall);
}
static int dissect_originator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_originator);
}
static int dissect_sent(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_sent);
}
static int dissect_needResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_needResponse);
}
static int dissect_unsolicited(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_unsolicited);
}
static int dissect_almostOutOfResources(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BOOLEAN(tvb, offset, actx, tree, hf_h225_almostOutOfResources);
}



static int
dissect_h225_BIT_STRING_SIZE_32(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, FALSE);

  return offset;
}
static int dissect_set(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BIT_STRING_SIZE_32(tvb, offset, actx, tree, hf_h225_set);
}



static int
dissect_h225_T_tunnelledProtocolObjectID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_object_identifier_str(tvb, offset, actx, tree, hf_index, &tpOID);

  return offset;
}
static int dissect_tunnelledProtocolObjectID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_tunnelledProtocolObjectID(tvb, offset, actx, tree, hf_h225_tunnelledProtocolObjectID);
}



static int
dissect_h225_IA5String_SIZE_1_64(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 64);

  return offset;
}
static int dissect_subIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_IA5String_SIZE_1_64(tvb, offset, actx, tree, hf_h225_subIdentifier);
}
static int dissect_protocolType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_IA5String_SIZE_1_64(tvb, offset, actx, tree, hf_h225_protocolType);
}
static int dissect_protocolVariant(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_IA5String_SIZE_1_64(tvb, offset, actx, tree, hf_h225_protocolVariant);
}


static const per_sequence_t TunnelledProtocolAlternateIdentifier_sequence[] = {
  { "protocolType"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolType },
  { "protocolVariant"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_protocolVariant },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_TunnelledProtocolAlternateIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_TunnelledProtocolAlternateIdentifier, TunnelledProtocolAlternateIdentifier_sequence);

  return offset;
}
static int dissect_tunnelledProtocolAlternateID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TunnelledProtocolAlternateIdentifier(tvb, offset, actx, tree, hf_h225_tunnelledProtocolAlternateID);
}


static const value_string h225_TunnelledProtocol_id_vals[] = {
  {   0, "tunnelledProtocolObjectID" },
  {   1, "tunnelledProtocolAlternateID" },
  { 0, NULL }
};

static const per_choice_t TunnelledProtocol_id_choice[] = {
  {   0, "tunnelledProtocolObjectID"   , ASN1_EXTENSION_ROOT    , dissect_tunnelledProtocolObjectID },
  {   1, "tunnelledProtocolAlternateID", ASN1_EXTENSION_ROOT    , dissect_tunnelledProtocolAlternateID },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_TunnelledProtocol_id(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_TunnelledProtocol_id, TunnelledProtocol_id_choice,
                                 NULL);

  return offset;
}
static int dissect_tunnelledProtocol_id(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TunnelledProtocol_id(tvb, offset, actx, tree, hf_h225_tunnelledProtocol_id);
}


static const per_sequence_t TunnelledProtocol_sequence[] = {
  { "id"                          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_tunnelledProtocol_id },
  { "subIdentifier"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_subIdentifier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_TunnelledProtocol(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 467 "h225.cnf"
  tpOID = "";

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_TunnelledProtocol, TunnelledProtocol_sequence);

#line 469 "h225.cnf"
  tp_handle = dissector_get_string_handle(tp_dissector_table, tpOID);

  return offset;
}
static int dissect_tunnelledProtocolID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TunnelledProtocol(tvb, offset, actx, tree, hf_h225_tunnelledProtocolID);
}
static int dissect_supportedTunnelledProtocols_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TunnelledProtocol(tvb, offset, actx, tree, hf_h225_supportedTunnelledProtocols_item);
}
static int dissect_desiredTunnelledProtocol(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TunnelledProtocol(tvb, offset, actx, tree, hf_h225_desiredTunnelledProtocol);
}


static const per_sequence_t SEQUENCE_OF_TunnelledProtocol_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_supportedTunnelledProtocols_item },
};

static int
dissect_h225_SEQUENCE_OF_TunnelledProtocol(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_TunnelledProtocol, SEQUENCE_OF_TunnelledProtocol_sequence_of);

  return offset;
}
static int dissect_supportedTunnelledProtocols(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_TunnelledProtocol(tvb, offset, actx, tree, hf_h225_supportedTunnelledProtocols);
}


static const per_sequence_t EndpointType_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "vendor"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_vendor },
  { "gatekeeper"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gatekeeper },
  { "gateway"                     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gateway },
  { "mcu"                         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_mcu },
  { "terminal"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_terminal },
  { "mc"                          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_mc },
  { "undefinedNode"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_undefinedNode },
  { "set"                         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_set },
  { "supportedTunnelledProtocols" , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_supportedTunnelledProtocols },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_EndpointType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_EndpointType, EndpointType_sequence);

  return offset;
}
static int dissect_uUIE_destinationInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_EndpointType(tvb, offset, actx, tree, hf_h225_uUIE_destinationInfo);
}
static int dissect_setup_UUIE_sourceInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_EndpointType(tvb, offset, actx, tree, hf_h225_setup_UUIE_sourceInfo);
}
static int dissect_endpointType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_EndpointType(tvb, offset, actx, tree, hf_h225_endpointType);
}
static int dissect_terminalType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_EndpointType(tvb, offset, actx, tree, hf_h225_terminalType);
}
static int dissect_destinationType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_EndpointType(tvb, offset, actx, tree, hf_h225_destinationType);
}



static int
dissect_h225_CallReferenceValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_destExtraCRV_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallReferenceValue(tvb, offset, actx, tree, hf_h225_destExtraCRV_item);
}
static int dissect_callReferenceValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallReferenceValue(tvb, offset, actx, tree, hf_h225_callReferenceValue);
}


static const per_sequence_t SEQUENCE_OF_CallReferenceValue_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_destExtraCRV_item },
};

static int
dissect_h225_SEQUENCE_OF_CallReferenceValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_CallReferenceValue, SEQUENCE_OF_CallReferenceValue_sequence_of);

  return offset;
}
static int dissect_destExtraCRV(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CallReferenceValue(tvb, offset, actx, tree, hf_h225_destExtraCRV);
}



static int
dissect_h225_GloballyUniqueID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, NULL);

  return offset;
}
static int dissect_globalCallId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GloballyUniqueID(tvb, offset, actx, tree, hf_h225_globalCallId);
}
static int dissect_threadId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GloballyUniqueID(tvb, offset, actx, tree, hf_h225_threadId);
}
static int dissect_genericIdentifier_nonStandard(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GloballyUniqueID(tvb, offset, actx, tree, hf_h225_genericIdentifier_nonStandard);
}



static int
dissect_h225_ConferenceIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h225_GloballyUniqueID(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_conferenceID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ConferenceIdentifier(tvb, offset, actx, tree, hf_h225_conferenceID);
}
static int dissect_replaceWithConferenceInvite(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ConferenceIdentifier(tvb, offset, actx, tree, hf_h225_replaceWithConferenceInvite);
}
static int dissect_substituteConfIDs_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ConferenceIdentifier(tvb, offset, actx, tree, hf_h225_substituteConfIDs_item);
}


static const value_string h225_T_conferenceGoal_vals[] = {
  {   0, "create" },
  {   1, "join" },
  {   2, "invite" },
  {   3, "capability-negotiation" },
  {   4, "callIndependentSupplementaryService" },
  { 0, NULL }
};

static const per_choice_t T_conferenceGoal_choice[] = {
  {   0, "create"                      , ASN1_EXTENSION_ROOT    , dissect_create },
  {   1, "join"                        , ASN1_EXTENSION_ROOT    , dissect_join },
  {   2, "invite"                      , ASN1_EXTENSION_ROOT    , dissect_invite },
  {   3, "capability-negotiation"      , ASN1_NOT_EXTENSION_ROOT, dissect_capability_negotiation },
  {   4, "callIndependentSupplementaryService", ASN1_NOT_EXTENSION_ROOT, dissect_callIndependentSupplementaryService },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_T_conferenceGoal(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_T_conferenceGoal, T_conferenceGoal_choice,
                                 NULL);

  return offset;
}
static int dissect_conferenceGoal(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_conferenceGoal(tvb, offset, actx, tree, hf_h225_conferenceGoal);
}


static const per_sequence_t Q954Details_sequence[] = {
  { "conferenceCalling"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_conferenceCalling },
  { "threePartyService"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_threePartyService },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_Q954Details(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_Q954Details, Q954Details_sequence);

  return offset;
}
static int dissect_q954Info(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Q954Details(tvb, offset, actx, tree, hf_h225_q954Info);
}


static const per_sequence_t QseriesOptions_sequence[] = {
  { "q932Full"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_q932Full },
  { "q951Full"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_q951Full },
  { "q952Full"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_q952Full },
  { "q953Full"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_q953Full },
  { "q955Full"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_q955Full },
  { "q956Full"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_q956Full },
  { "q957Full"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_q957Full },
  { "q954Info"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_q954Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_QseriesOptions(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_QseriesOptions, QseriesOptions_sequence);

  return offset;
}
static int dissect_callServices(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_QseriesOptions(tvb, offset, actx, tree, hf_h225_callServices);
}


static const value_string h225_CallType_vals[] = {
  {   0, "pointToPoint" },
  {   1, "oneToN" },
  {   2, "nToOne" },
  {   3, "nToN" },
  { 0, NULL }
};

static const per_choice_t CallType_choice[] = {
  {   0, "pointToPoint"                , ASN1_EXTENSION_ROOT    , dissect_pointToPoint },
  {   1, "oneToN"                      , ASN1_EXTENSION_ROOT    , dissect_oneToN },
  {   2, "nToOne"                      , ASN1_EXTENSION_ROOT    , dissect_nToOne },
  {   3, "nToN"                        , ASN1_EXTENSION_ROOT    , dissect_nToN },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_CallType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_CallType, CallType_choice,
                                 NULL);

  return offset;
}
static int dissect_callType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallType(tvb, offset, actx, tree, hf_h225_callType);
}



static int
dissect_h225_T_guid(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 446 "h225.cnf"
  tvbuff_t *guid_tvb;

  offset = dissect_per_octet_string(tvb,offset,actx,tree,hf_index,GUID_LEN,GUID_LEN,&guid_tvb);
  tvb_memcpy(guid_tvb,(guint8 *)&h225_pi->guid,0,GUID_LEN);


  return offset;
}
static int dissect_guid(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_guid(tvb, offset, actx, tree, hf_h225_guid);
}


static const per_sequence_t CallIdentifier_sequence[] = {
  { "guid"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_guid },
  { NULL, 0, 0, NULL }
};

int
dissect_h225_CallIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CallIdentifier, CallIdentifier_sequence);

  return offset;
}
static int dissect_callIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallIdentifier(tvb, offset, actx, tree, hf_h225_callIdentifier);
}


static const value_string h225_SecurityServiceMode_vals[] = {
  {   0, "nonStandard" },
  {   1, "none" },
  {   2, "default" },
  { 0, NULL }
};

static const per_choice_t SecurityServiceMode_choice[] = {
  {   0, "nonStandard"                 , ASN1_EXTENSION_ROOT    , dissect_nonStandard },
  {   1, "none"                        , ASN1_EXTENSION_ROOT    , dissect_none },
  {   2, "default"                     , ASN1_EXTENSION_ROOT    , dissect_default },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_SecurityServiceMode(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_SecurityServiceMode, SecurityServiceMode_choice,
                                 NULL);

  return offset;
}
static int dissect_encryption(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SecurityServiceMode(tvb, offset, actx, tree, hf_h225_encryption);
}
static int dissect_authenticaton(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SecurityServiceMode(tvb, offset, actx, tree, hf_h225_authenticaton);
}
static int dissect_securityCapabilities_integrity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SecurityServiceMode(tvb, offset, actx, tree, hf_h225_securityCapabilities_integrity);
}


static const per_sequence_t SecurityCapabilities_sequence[] = {
  { "nonStandard"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandard },
  { "encryption"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_encryption },
  { "authenticaton"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_authenticaton },
  { "integrity"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_securityCapabilities_integrity },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_SecurityCapabilities(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_SecurityCapabilities, SecurityCapabilities_sequence);

  return offset;
}
static int dissect_tls(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SecurityCapabilities(tvb, offset, actx, tree, hf_h225_tls);
}
static int dissect_ipsec(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SecurityCapabilities(tvb, offset, actx, tree, hf_h225_ipsec);
}


static const value_string h225_H245Security_vals[] = {
  {   0, "nonStandard" },
  {   1, "noSecurity" },
  {   2, "tls" },
  {   3, "ipsec" },
  { 0, NULL }
};

static const per_choice_t H245Security_choice[] = {
  {   0, "nonStandard"                 , ASN1_EXTENSION_ROOT    , dissect_nonStandard },
  {   1, "noSecurity"                  , ASN1_EXTENSION_ROOT    , dissect_noSecurity },
  {   2, "tls"                         , ASN1_EXTENSION_ROOT    , dissect_tls },
  {   3, "ipsec"                       , ASN1_EXTENSION_ROOT    , dissect_ipsec },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_H245Security(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_H245Security, H245Security_choice,
                                 NULL);

  return offset;
}
static int dissect_h245SecurityMode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H245Security(tvb, offset, actx, tree, hf_h225_h245SecurityMode);
}
static int dissect_h245SecurityCapability_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H245Security(tvb, offset, actx, tree, hf_h225_h245SecurityCapability_item);
}


static const per_sequence_t SEQUENCE_OF_H245Security_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h245SecurityCapability_item },
};

static int
dissect_h225_SEQUENCE_OF_H245Security(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_H245Security, SEQUENCE_OF_H245Security_sequence_of);

  return offset;
}
static int dissect_h245SecurityCapability(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_H245Security(tvb, offset, actx, tree, hf_h225_h245SecurityCapability);
}


static const per_sequence_t SEQUENCE_OF_ClearToken_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tokens_item },
};

static int
dissect_h225_SEQUENCE_OF_ClearToken(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_ClearToken, SEQUENCE_OF_ClearToken_sequence_of);

  return offset;
}
static int dissect_tokens(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_ClearToken(tvb, offset, actx, tree, hf_h225_tokens);
}


static const per_sequence_t T_cryptoEPPwdHash_sequence[] = {
  { "alias"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_alias },
  { "timeStamp"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_timeStamp },
  { "token"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_token },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_cryptoEPPwdHash(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_cryptoEPPwdHash, T_cryptoEPPwdHash_sequence);

  return offset;
}
static int dissect_cryptoEPPwdHash(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_cryptoEPPwdHash(tvb, offset, actx, tree, hf_h225_cryptoEPPwdHash);
}



static int
dissect_h225_GatekeeperIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          1, 128);

  return offset;
}
static int dissect_gatekeeperIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GatekeeperIdentifier(tvb, offset, actx, tree, hf_h225_gatekeeperIdentifier);
}
static int dissect_gatekeeperId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GatekeeperIdentifier(tvb, offset, actx, tree, hf_h225_gatekeeperId);
}


static const per_sequence_t T_cryptoGKPwdHash_sequence[] = {
  { "gatekeeperId"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_gatekeeperId },
  { "timeStamp"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_timeStamp },
  { "token"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_token },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_cryptoGKPwdHash(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_cryptoGKPwdHash, T_cryptoGKPwdHash_sequence);

  return offset;
}
static int dissect_cryptoGKPwdHash(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_cryptoGKPwdHash(tvb, offset, actx, tree, hf_h225_cryptoGKPwdHash);
}


static const value_string h225_CryptoH323Token_vals[] = {
  {   0, "cryptoEPPwdHash" },
  {   1, "cryptoGKPwdHash" },
  {   2, "cryptoEPPwdEncr" },
  {   3, "cryptoGKPwdEncr" },
  {   4, "cryptoEPCert" },
  {   5, "cryptoGKCert" },
  {   6, "cryptoFastStart" },
  {   7, "nestedcryptoToken" },
  { 0, NULL }
};

static const per_choice_t CryptoH323Token_choice[] = {
  {   0, "cryptoEPPwdHash"             , ASN1_EXTENSION_ROOT    , dissect_cryptoEPPwdHash },
  {   1, "cryptoGKPwdHash"             , ASN1_EXTENSION_ROOT    , dissect_cryptoGKPwdHash },
  {   2, "cryptoEPPwdEncr"             , ASN1_EXTENSION_ROOT    , dissect_cryptoEPPwdEncr },
  {   3, "cryptoGKPwdEncr"             , ASN1_EXTENSION_ROOT    , dissect_cryptoGKPwdEncr },
  {   4, "cryptoEPCert"                , ASN1_EXTENSION_ROOT    , dissect_cryptoEPCert },
  {   5, "cryptoGKCert"                , ASN1_EXTENSION_ROOT    , dissect_cryptoGKCert },
  {   6, "cryptoFastStart"             , ASN1_EXTENSION_ROOT    , dissect_cryptoFastStart },
  {   7, "nestedcryptoToken"           , ASN1_EXTENSION_ROOT    , dissect_nestedcryptoToken },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_CryptoH323Token(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_CryptoH323Token, CryptoH323Token_choice,
                                 NULL);

  return offset;
}
static int dissect_cryptoTokens_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CryptoH323Token(tvb, offset, actx, tree, hf_h225_cryptoTokens_item);
}


static const per_sequence_t SEQUENCE_OF_CryptoH323Token_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cryptoTokens_item },
};

static int
dissect_h225_SEQUENCE_OF_CryptoH323Token(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_CryptoH323Token, SEQUENCE_OF_CryptoH323Token_sequence_of);

  return offset;
}
static int dissect_cryptoTokens(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CryptoH323Token(tvb, offset, actx, tree, hf_h225_cryptoTokens);
}



static int
dissect_h225_FastStart_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 164 "h225.cnf"
	tvbuff_t *value_tvb = NULL;
	char codec_str[50];

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, &value_tvb);

	if (value_tvb && tvb_length(value_tvb)) {
		dissect_h245_OpenLogicalChannelCodec(value_tvb, actx->pinfo, tree, codec_str);
	}

    /* Add to packet info */
    g_snprintf(h225_pi->frame_label, 50, "%s %s", h225_pi->frame_label, codec_str);

	contains_faststart = TRUE;
	h225_pi->is_faststart = TRUE;


  return offset;
}
static int dissect_FastStart_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_FastStart_item(tvb, offset, actx, tree, hf_h225_FastStart_item);
}


static const per_sequence_t FastStart_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_FastStart_item },
};

static int
dissect_h225_FastStart(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_FastStart, FastStart_sequence_of);

  return offset;
}
static int dissect_fastStart(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_FastStart(tvb, offset, actx, tree, hf_h225_fastStart);
}



static int
dissect_h225_EndpointIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          1, 128);

  return offset;
}
static int dissect_endpointIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_EndpointIdentifier(tvb, offset, actx, tree, hf_h225_endpointIdentifier);
}


static const value_string h225_ScnConnectionType_vals[] = {
  {   0, "unknown" },
  {   1, "bChannel" },
  {   2, "hybrid2x64" },
  {   3, "hybrid384" },
  {   4, "hybrid1536" },
  {   5, "hybrid1920" },
  {   6, "multirate" },
  { 0, NULL }
};

static const per_choice_t ScnConnectionType_choice[] = {
  {   0, "unknown"                     , ASN1_EXTENSION_ROOT    , dissect_unknown },
  {   1, "bChannel"                    , ASN1_EXTENSION_ROOT    , dissect_bChannel },
  {   2, "hybrid2x64"                  , ASN1_EXTENSION_ROOT    , dissect_hybrid2x64 },
  {   3, "hybrid384"                   , ASN1_EXTENSION_ROOT    , dissect_hybrid384 },
  {   4, "hybrid1536"                  , ASN1_EXTENSION_ROOT    , dissect_hybrid1536 },
  {   5, "hybrid1920"                  , ASN1_EXTENSION_ROOT    , dissect_hybrid1920 },
  {   6, "multirate"                   , ASN1_EXTENSION_ROOT    , dissect_multirate },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_ScnConnectionType(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_ScnConnectionType, ScnConnectionType_choice,
                                 NULL);

  return offset;
}
static int dissect_connectionType(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ScnConnectionType(tvb, offset, actx, tree, hf_h225_connectionType);
}


static const value_string h225_ScnConnectionAggregation_vals[] = {
  {   0, "auto" },
  {   1, "none" },
  {   2, "h221" },
  {   3, "bonded-mode1" },
  {   4, "bonded-mode2" },
  {   5, "bonded-mode3" },
  { 0, NULL }
};

static const per_choice_t ScnConnectionAggregation_choice[] = {
  {   0, "auto"                        , ASN1_EXTENSION_ROOT    , dissect_auto },
  {   1, "none"                        , ASN1_EXTENSION_ROOT    , dissect_none },
  {   2, "h221"                        , ASN1_EXTENSION_ROOT    , dissect_h221 },
  {   3, "bonded-mode1"                , ASN1_EXTENSION_ROOT    , dissect_bonded_mode1 },
  {   4, "bonded-mode2"                , ASN1_EXTENSION_ROOT    , dissect_bonded_mode2 },
  {   5, "bonded-mode3"                , ASN1_EXTENSION_ROOT    , dissect_bonded_mode3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_ScnConnectionAggregation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_ScnConnectionAggregation, ScnConnectionAggregation_choice,
                                 NULL);

  return offset;
}
static int dissect_connectionAggregation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ScnConnectionAggregation(tvb, offset, actx, tree, hf_h225_connectionAggregation);
}


static const per_sequence_t T_connectionParameters_sequence[] = {
  { "connectionType"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_connectionType },
  { "numberOfScnConnections"      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_numberOfScnConnections },
  { "connectionAggregation"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_connectionAggregation },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_connectionParameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_connectionParameters, T_connectionParameters_sequence);

  return offset;
}
static int dissect_connectionParameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_connectionParameters(tvb, offset, actx, tree, hf_h225_connectionParameters);
}



static int
dissect_h225_IA5String_SIZE_1_32(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 32);

  return offset;
}
static int dissect_language_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_IA5String_SIZE_1_32(tvb, offset, actx, tree, hf_h225_language_item);
}


static const per_sequence_t Language_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_language_item },
};

static int
dissect_h225_Language(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_Language, Language_sequence_of);

  return offset;
}
static int dissect_language(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Language(tvb, offset, actx, tree, hf_h225_language);
}


const value_string h225_PresentationIndicator_vals[] = {
  {   0, "presentationAllowed" },
  {   1, "presentationRestricted" },
  {   2, "addressNotAvailable" },
  { 0, NULL }
};

static const per_choice_t PresentationIndicator_choice[] = {
  {   0, "presentationAllowed"         , ASN1_EXTENSION_ROOT    , dissect_presentationAllowed },
  {   1, "presentationRestricted"      , ASN1_EXTENSION_ROOT    , dissect_presentationRestricted },
  {   2, "addressNotAvailable"         , ASN1_EXTENSION_ROOT    , dissect_addressNotAvailable },
  { 0, NULL, 0, NULL }
};

int
dissect_h225_PresentationIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_PresentationIndicator, PresentationIndicator_choice,
                                 NULL);

  return offset;
}
static int dissect_presentationIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PresentationIndicator(tvb, offset, actx, tree, hf_h225_presentationIndicator);
}


const value_string h225_ScreeningIndicator_vals[] = {
  {   0, "userProvidedNotScreened" },
  {   1, "userProvidedVerifiedAndPassed" },
  {   2, "userProvidedVerifiedAndFailed" },
  {   3, "networkProvided" },
  { 0, NULL }
};


int
dissect_h225_ScreeningIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_screeningIndicator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ScreeningIndicator(tvb, offset, actx, tree, hf_h225_screeningIndicator);
}



static int
dissect_h225_INTEGER_0_255(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);

  return offset;
}
static int dissect_protocol_discriminator(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_255(tvb, offset, actx, tree, hf_h225_protocol_discriminator);
}
static int dissect_sessionId_0_255(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_255(tvb, offset, actx, tree, hf_h225_sessionId_0_255);
}
static int dissect_number8(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_255(tvb, offset, actx, tree, hf_h225_number8);
}



static int
dissect_h225_IA5String_SIZE_0_512(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          0, 512);

  return offset;
}
static int dissect_url(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_IA5String_SIZE_0_512(tvb, offset, actx, tree, hf_h225_url);
}



static int
dissect_h225_H248SignalsDescriptor(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_signal(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H248SignalsDescriptor(tvb, offset, actx, tree, hf_h225_signal);
}



static int
dissect_h225_BMPString_SIZE_1_512(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          1, 512);

  return offset;
}
static int dissect_amountString(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BMPString_SIZE_1_512(tvb, offset, actx, tree, hf_h225_amountString);
}


static const value_string h225_T_billingMode_vals[] = {
  {   0, "credit" },
  {   1, "debit" },
  { 0, NULL }
};

static const per_choice_t T_billingMode_choice[] = {
  {   0, "credit"                      , ASN1_EXTENSION_ROOT    , dissect_credit },
  {   1, "debit"                       , ASN1_EXTENSION_ROOT    , dissect_debit },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_T_billingMode(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_T_billingMode, T_billingMode_choice,
                                 NULL);

  return offset;
}
static int dissect_billingMode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_billingMode(tvb, offset, actx, tree, hf_h225_billingMode);
}



static int
dissect_h225_INTEGER_1_4294967295(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 4294967295U, NULL, FALSE);

  return offset;
}
static int dissect_callDurationLimit(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_1_4294967295(tvb, offset, actx, tree, hf_h225_callDurationLimit);
}
static int dissect_ssrc(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_1_4294967295(tvb, offset, actx, tree, hf_h225_ssrc);
}


static const value_string h225_CallCreditServiceControl_callStartingPoint_vals[] = {
  {   0, "alerting" },
  {   1, "connect" },
  { 0, NULL }
};

static const per_choice_t CallCreditServiceControl_callStartingPoint_choice[] = {
  {   0, "alerting"                    , ASN1_EXTENSION_ROOT    , dissect_alerting_flg },
  {   1, "connect"                     , ASN1_EXTENSION_ROOT    , dissect_connect_flg },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_CallCreditServiceControl_callStartingPoint(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_CallCreditServiceControl_callStartingPoint, CallCreditServiceControl_callStartingPoint_choice,
                                 NULL);

  return offset;
}
static int dissect_callStartingPoint(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallCreditServiceControl_callStartingPoint(tvb, offset, actx, tree, hf_h225_callStartingPoint);
}


static const per_sequence_t CallCreditServiceControl_sequence[] = {
  { "amountString"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_amountString },
  { "billingMode"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_billingMode },
  { "callDurationLimit"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callDurationLimit },
  { "enforceCallDurationLimit"    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_enforceCallDurationLimit },
  { "callStartingPoint"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callStartingPoint },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CallCreditServiceControl(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CallCreditServiceControl, CallCreditServiceControl_sequence);

  return offset;
}
static int dissect_callCreditServiceControl(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallCreditServiceControl(tvb, offset, actx, tree, hf_h225_callCreditServiceControl);
}


static const value_string h225_ServiceControlDescriptor_vals[] = {
  {   0, "url" },
  {   1, "signal" },
  {   2, "nonStandard" },
  {   3, "callCreditServiceControl" },
  { 0, NULL }
};

static const per_choice_t ServiceControlDescriptor_choice[] = {
  {   0, "url"                         , ASN1_EXTENSION_ROOT    , dissect_url },
  {   1, "signal"                      , ASN1_EXTENSION_ROOT    , dissect_signal },
  {   2, "nonStandard"                 , ASN1_EXTENSION_ROOT    , dissect_nonStandard },
  {   3, "callCreditServiceControl"    , ASN1_EXTENSION_ROOT    , dissect_callCreditServiceControl },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_ServiceControlDescriptor(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_ServiceControlDescriptor, ServiceControlDescriptor_choice,
                                 NULL);

  return offset;
}
static int dissect_contents(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ServiceControlDescriptor(tvb, offset, actx, tree, hf_h225_contents);
}


static const value_string h225_ServiceControlSession_reason_vals[] = {
  {   0, "open" },
  {   1, "refresh" },
  {   2, "close" },
  { 0, NULL }
};

static const per_choice_t ServiceControlSession_reason_choice[] = {
  {   0, "open"                        , ASN1_EXTENSION_ROOT    , dissect_open },
  {   1, "refresh"                     , ASN1_EXTENSION_ROOT    , dissect_refresh },
  {   2, "close"                       , ASN1_EXTENSION_ROOT    , dissect_close },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_ServiceControlSession_reason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_ServiceControlSession_reason, ServiceControlSession_reason_choice,
                                 NULL);

  return offset;
}
static int dissect_reason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ServiceControlSession_reason(tvb, offset, actx, tree, hf_h225_reason);
}


static const per_sequence_t ServiceControlSession_sequence[] = {
  { "sessionId"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sessionId_0_255 },
  { "contents"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_contents },
  { "reason"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_reason },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_ServiceControlSession(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_ServiceControlSession, ServiceControlSession_sequence);

  return offset;
}
static int dissect_serviceControl_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ServiceControlSession(tvb, offset, actx, tree, hf_h225_serviceControl_item);
}


static const per_sequence_t SEQUENCE_OF_ServiceControlSession_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_serviceControl_item },
};

static int
dissect_h225_SEQUENCE_OF_ServiceControlSession(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_ServiceControlSession, SEQUENCE_OF_ServiceControlSession_sequence_of);

  return offset;
}
static int dissect_serviceControl(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_ServiceControlSession(tvb, offset, actx, tree, hf_h225_serviceControl);
}



static int
dissect_h225_INTEGER_0_4294967295(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 4294967295U, NULL, FALSE);

  return offset;
}
static int dissect_calls(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_4294967295(tvb, offset, actx, tree, hf_h225_calls);
}
static int dissect_number32(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_4294967295(tvb, offset, actx, tree, hf_h225_number32);
}



static int
dissect_h225_IA5String_SIZE_1_128(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 128);

  return offset;
}
static int dissect_group_IA5String(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_IA5String_SIZE_1_128(tvb, offset, actx, tree, hf_h225_group_IA5String);
}
static int dissect_carrierName(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_IA5String_SIZE_1_128(tvb, offset, actx, tree, hf_h225_carrierName);
}



static int
dissect_h225_OCTET_STRING_SIZE_3_4(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 4, NULL);

  return offset;
}
static int dissect_carrierIdentificationCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_3_4(tvb, offset, actx, tree, hf_h225_carrierIdentificationCode);
}


static const per_sequence_t CarrierInfo_sequence[] = {
  { "carrierIdentificationCode"   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_carrierIdentificationCode },
  { "carrierName"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_carrierName },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CarrierInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CarrierInfo, CarrierInfo_sequence);

  return offset;
}
static int dissect_carrier(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CarrierInfo(tvb, offset, actx, tree, hf_h225_carrier);
}


static const per_sequence_t CallsAvailable_sequence[] = {
  { "calls"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_calls },
  { "group"                       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_group_IA5String },
  { "carrier"                     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_carrier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CallsAvailable, CallsAvailable_sequence);

  return offset;
}
static int dissect_voiceGwCallsAvailable_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallsAvailable(tvb, offset, actx, tree, hf_h225_voiceGwCallsAvailable_item);
}
static int dissect_h310GwCallsAvailable_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallsAvailable(tvb, offset, actx, tree, hf_h225_h310GwCallsAvailable_item);
}
static int dissect_h320GwCallsAvailable_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallsAvailable(tvb, offset, actx, tree, hf_h225_h320GwCallsAvailable_item);
}
static int dissect_h321GwCallsAvailable_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallsAvailable(tvb, offset, actx, tree, hf_h225_h321GwCallsAvailable_item);
}
static int dissect_h322GwCallsAvailable_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallsAvailable(tvb, offset, actx, tree, hf_h225_h322GwCallsAvailable_item);
}
static int dissect_h323GwCallsAvailable_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallsAvailable(tvb, offset, actx, tree, hf_h225_h323GwCallsAvailable_item);
}
static int dissect_h324GwCallsAvailable_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallsAvailable(tvb, offset, actx, tree, hf_h225_h324GwCallsAvailable_item);
}
static int dissect_t120OnlyGwCallsAvailable_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallsAvailable(tvb, offset, actx, tree, hf_h225_t120OnlyGwCallsAvailable_item);
}
static int dissect_t38FaxAnnexbOnlyGwCallsAvailable_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallsAvailable(tvb, offset, actx, tree, hf_h225_t38FaxAnnexbOnlyGwCallsAvailable_item);
}
static int dissect_terminalCallsAvailable_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallsAvailable(tvb, offset, actx, tree, hf_h225_terminalCallsAvailable_item);
}
static int dissect_mcuCallsAvailable_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallsAvailable(tvb, offset, actx, tree, hf_h225_mcuCallsAvailable_item);
}
static int dissect_sipGwCallsAvailable_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallsAvailable(tvb, offset, actx, tree, hf_h225_sipGwCallsAvailable_item);
}


static const per_sequence_t SEQUENCE_OF_CallsAvailable_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_voiceGwCallsAvailable_item },
};

static int
dissect_h225_SEQUENCE_OF_CallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_CallsAvailable, SEQUENCE_OF_CallsAvailable_sequence_of);

  return offset;
}
static int dissect_voiceGwCallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CallsAvailable(tvb, offset, actx, tree, hf_h225_voiceGwCallsAvailable);
}
static int dissect_h310GwCallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CallsAvailable(tvb, offset, actx, tree, hf_h225_h310GwCallsAvailable);
}
static int dissect_h320GwCallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CallsAvailable(tvb, offset, actx, tree, hf_h225_h320GwCallsAvailable);
}
static int dissect_h321GwCallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CallsAvailable(tvb, offset, actx, tree, hf_h225_h321GwCallsAvailable);
}
static int dissect_h322GwCallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CallsAvailable(tvb, offset, actx, tree, hf_h225_h322GwCallsAvailable);
}
static int dissect_h323GwCallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CallsAvailable(tvb, offset, actx, tree, hf_h225_h323GwCallsAvailable);
}
static int dissect_h324GwCallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CallsAvailable(tvb, offset, actx, tree, hf_h225_h324GwCallsAvailable);
}
static int dissect_t120OnlyGwCallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CallsAvailable(tvb, offset, actx, tree, hf_h225_t120OnlyGwCallsAvailable);
}
static int dissect_t38FaxAnnexbOnlyGwCallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CallsAvailable(tvb, offset, actx, tree, hf_h225_t38FaxAnnexbOnlyGwCallsAvailable);
}
static int dissect_terminalCallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CallsAvailable(tvb, offset, actx, tree, hf_h225_terminalCallsAvailable);
}
static int dissect_mcuCallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CallsAvailable(tvb, offset, actx, tree, hf_h225_mcuCallsAvailable);
}
static int dissect_sipGwCallsAvailable(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_CallsAvailable(tvb, offset, actx, tree, hf_h225_sipGwCallsAvailable);
}


static const per_sequence_t CallCapacityInfo_sequence[] = {
  { "voiceGwCallsAvailable"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_voiceGwCallsAvailable },
  { "h310GwCallsAvailable"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h310GwCallsAvailable },
  { "h320GwCallsAvailable"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h320GwCallsAvailable },
  { "h321GwCallsAvailable"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h321GwCallsAvailable },
  { "h322GwCallsAvailable"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h322GwCallsAvailable },
  { "h323GwCallsAvailable"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h323GwCallsAvailable },
  { "h324GwCallsAvailable"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h324GwCallsAvailable },
  { "t120OnlyGwCallsAvailable"    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t120OnlyGwCallsAvailable },
  { "t38FaxAnnexbOnlyGwCallsAvailable", ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_t38FaxAnnexbOnlyGwCallsAvailable },
  { "terminalCallsAvailable"      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_terminalCallsAvailable },
  { "mcuCallsAvailable"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_mcuCallsAvailable },
  { "sipGwCallsAvailable"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_sipGwCallsAvailable },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CallCapacityInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CallCapacityInfo, CallCapacityInfo_sequence);

  return offset;
}
static int dissect_maximumCallCapacity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallCapacityInfo(tvb, offset, actx, tree, hf_h225_maximumCallCapacity);
}
static int dissect_currentCallCapacity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallCapacityInfo(tvb, offset, actx, tree, hf_h225_currentCallCapacity);
}


static const per_sequence_t CallCapacity_sequence[] = {
  { "maximumCallCapacity"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_maximumCallCapacity },
  { "currentCallCapacity"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_currentCallCapacity },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CallCapacity(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CallCapacity, CallCapacity_sequence);

  return offset;
}
static int dissect_capacity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallCapacity(tvb, offset, actx, tree, hf_h225_capacity);
}



static int
dissect_h225_OCTET_STRING_SIZE_2_4(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 4, NULL);

  return offset;
}
static int dissect_cic_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_2_4(tvb, offset, actx, tree, hf_h225_cic_item);
}


static const per_sequence_t T_cic_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cic_item },
};

static int
dissect_h225_T_cic(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_T_cic, T_cic_sequence_of);

  return offset;
}
static int dissect_cic_2_4(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_cic(tvb, offset, actx, tree, hf_h225_cic_2_4);
}



static int
dissect_h225_OCTET_STRING_SIZE_2_5(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 5, NULL);

  return offset;
}
static int dissect_pointCode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_2_5(tvb, offset, actx, tree, hf_h225_pointCode);
}


static const per_sequence_t CicInfo_sequence[] = {
  { "cic"                         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cic_2_4 },
  { "pointCode"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_pointCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CicInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CicInfo, CicInfo_sequence);

  return offset;
}
static int dissect_cic(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CicInfo(tvb, offset, actx, tree, hf_h225_cic);
}


static const per_sequence_t T_member_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_member_item },
};

static int
dissect_h225_T_member(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_T_member, T_member_sequence_of);

  return offset;
}
static int dissect_member(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_member(tvb, offset, actx, tree, hf_h225_member);
}


static const per_sequence_t GroupID_sequence[] = {
  { "member"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_member },
  { "group"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_group_IA5String },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_GroupID(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_GroupID, GroupID_sequence);

  return offset;
}
static int dissect_group(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GroupID(tvb, offset, actx, tree, hf_h225_group);
}


static const per_sequence_t CircuitIdentifier_sequence[] = {
  { "cic"                         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cic },
  { "group"                       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_group },
  { "carrier"                     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_carrier },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CircuitIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CircuitIdentifier, CircuitIdentifier_sequence);

  return offset;
}
static int dissect_sourceCircuitID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CircuitIdentifier(tvb, offset, actx, tree, hf_h225_sourceCircuitID);
}
static int dissect_destinationCircuitID(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CircuitIdentifier(tvb, offset, actx, tree, hf_h225_destinationCircuitID);
}



static int
dissect_h225_INTEGER_0_16383_(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 16383U, NULL, TRUE);

  return offset;
}
static int dissect_standard(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_16383_(tvb, offset, actx, tree, hf_h225_standard);
}


static const value_string h225_GenericIdentifier_vals[] = {
  {   0, "standard" },
  {   1, "oid" },
  {   2, "nonStandard" },
  { 0, NULL }
};

static const per_choice_t GenericIdentifier_choice[] = {
  {   0, "standard"                    , ASN1_EXTENSION_ROOT    , dissect_standard },
  {   1, "oid"                         , ASN1_EXTENSION_ROOT    , dissect_oid },
  {   2, "nonStandard"                 , ASN1_EXTENSION_ROOT    , dissect_genericIdentifier_nonStandard },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_GenericIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_GenericIdentifier, GenericIdentifier_choice,
                                 NULL);

  return offset;
}
static int dissect_id(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GenericIdentifier(tvb, offset, actx, tree, hf_h225_id);
}



static int
dissect_h225_OCTET_STRING(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_h248Message(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING(tvb, offset, actx, tree, hf_h225_h248Message);
}
static int dissect_raw(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING(tvb, offset, actx, tree, hf_h225_raw);
}
static int dissect_messageNotUnderstood(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING(tvb, offset, actx, tree, hf_h225_messageNotUnderstood);
}



static int
dissect_h225_IA5String(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND);

  return offset;
}
static int dissect_text(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_IA5String(tvb, offset, actx, tree, hf_h225_text);
}



static int
dissect_h225_BMPString(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_BMPString(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND);

  return offset;
}
static int dissect_unicode(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BMPString(tvb, offset, actx, tree, hf_h225_unicode);
}


static const per_sequence_t SEQUENCE_SIZE_1_512_OF_EnumeratedParameter_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_parameters_item },
};

static int
dissect_h225_SEQUENCE_SIZE_1_512_OF_EnumeratedParameter(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h225_SEQUENCE_SIZE_1_512_OF_EnumeratedParameter, SEQUENCE_SIZE_1_512_OF_EnumeratedParameter_sequence_of,
                                                  1, 512);

  return offset;
}
static int dissect_parameters(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_SIZE_1_512_OF_EnumeratedParameter(tvb, offset, actx, tree, hf_h225_parameters);
}
static int dissect_compound(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_SIZE_1_512_OF_EnumeratedParameter(tvb, offset, actx, tree, hf_h225_compound);
}


static const per_sequence_t SEQUENCE_SIZE_1_16_OF_GenericData_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nested_item },
};

static int
dissect_h225_SEQUENCE_SIZE_1_16_OF_GenericData(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_h225_SEQUENCE_SIZE_1_16_OF_GenericData, SEQUENCE_SIZE_1_16_OF_GenericData_sequence_of,
                                                  1, 16);

  return offset;
}
static int dissect_nested(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_SIZE_1_16_OF_GenericData(tvb, offset, actx, tree, hf_h225_nested);
}


static const value_string h225_Content_vals[] = {
  {   0, "raw" },
  {   1, "text" },
  {   2, "unicode" },
  {   3, "bool" },
  {   4, "number8" },
  {   5, "number16" },
  {   6, "number32" },
  {   7, "id" },
  {   8, "alias" },
  {   9, "transport" },
  {  10, "compound" },
  {  11, "nested" },
  { 0, NULL }
};

static const per_choice_t Content_choice[] = {
  {   0, "raw"                         , ASN1_EXTENSION_ROOT    , dissect_raw },
  {   1, "text"                        , ASN1_EXTENSION_ROOT    , dissect_text },
  {   2, "unicode"                     , ASN1_EXTENSION_ROOT    , dissect_unicode },
  {   3, "bool"                        , ASN1_EXTENSION_ROOT    , dissect_bool },
  {   4, "number8"                     , ASN1_EXTENSION_ROOT    , dissect_number8 },
  {   5, "number16"                    , ASN1_EXTENSION_ROOT    , dissect_number16 },
  {   6, "number32"                    , ASN1_EXTENSION_ROOT    , dissect_number32 },
  {   7, "id"                          , ASN1_EXTENSION_ROOT    , dissect_id },
  {   8, "alias"                       , ASN1_EXTENSION_ROOT    , dissect_alias },
  {   9, "transport"                   , ASN1_EXTENSION_ROOT    , dissect_transport },
  {  10, "compound"                    , ASN1_EXTENSION_ROOT    , dissect_compound },
  {  11, "nested"                      , ASN1_EXTENSION_ROOT    , dissect_nested },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_Content(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_Content, Content_choice,
                                 NULL);

  return offset;
}
static int dissect_content(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Content(tvb, offset, actx, tree, hf_h225_content);
}


static const per_sequence_t EnumeratedParameter_sequence[] = {
  { "id"                          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_id },
  { "content"                     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_content },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_EnumeratedParameter(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_EnumeratedParameter, EnumeratedParameter_sequence);

  return offset;
}


static const per_sequence_t GenericData_sequence[] = {
  { "id"                          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_id },
  { "parameters"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_parameters },
  { NULL, 0, 0, NULL }
};

int
dissect_h225_GenericData(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_GenericData, GenericData_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_OF_GenericData_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_genericData_item },
};

static int
dissect_h225_SEQUENCE_OF_GenericData(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_GenericData, SEQUENCE_OF_GenericData_sequence_of);

  return offset;
}
static int dissect_genericData(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_GenericData(tvb, offset, actx, tree, hf_h225_genericData);
}


static const per_sequence_t CircuitInfo_sequence[] = {
  { "sourceCircuitID"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sourceCircuitID },
  { "destinationCircuitID"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_destinationCircuitID },
  { "genericData"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CircuitInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CircuitInfo, CircuitInfo_sequence);

  return offset;
}
static int dissect_circuitInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CircuitInfo(tvb, offset, actx, tree, hf_h225_circuitInfo);
}



static int
dissect_h225_FeatureDescriptor(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h225_GenericData(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_neededFeatures_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_FeatureDescriptor(tvb, offset, actx, tree, hf_h225_neededFeatures_item);
}
static int dissect_desiredFeatures_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_FeatureDescriptor(tvb, offset, actx, tree, hf_h225_desiredFeatures_item);
}
static int dissect_supportedFeatures_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_FeatureDescriptor(tvb, offset, actx, tree, hf_h225_supportedFeatures_item);
}


static const per_sequence_t SEQUENCE_OF_FeatureDescriptor_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_neededFeatures_item },
};

static int
dissect_h225_SEQUENCE_OF_FeatureDescriptor(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_FeatureDescriptor, SEQUENCE_OF_FeatureDescriptor_sequence_of);

  return offset;
}
static int dissect_neededFeatures(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_FeatureDescriptor(tvb, offset, actx, tree, hf_h225_neededFeatures);
}
static int dissect_desiredFeatures(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_FeatureDescriptor(tvb, offset, actx, tree, hf_h225_desiredFeatures);
}
static int dissect_supportedFeatures(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_FeatureDescriptor(tvb, offset, actx, tree, hf_h225_supportedFeatures);
}



static int
dissect_h225_ParallelH245Control_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 226 "h225.cnf"
	tvbuff_t *h245_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, &h245_tvb);

  next_tvb_add(&h245_list, h245_tvb, (h225_h245_in_tree)?tree:NULL, h245dg_handle);


  return offset;
}
static int dissect_ParallelH245Control_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ParallelH245Control_item(tvb, offset, actx, tree, hf_h225_ParallelH245Control_item);
}


static const per_sequence_t ParallelH245Control_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ParallelH245Control_item },
};

static int
dissect_h225_ParallelH245Control(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_ParallelH245Control, ParallelH245Control_sequence_of);

  return offset;
}
static int dissect_parallelH245Control(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ParallelH245Control(tvb, offset, actx, tree, hf_h225_parallelH245Control);
}


static const per_sequence_t ExtendedAliasAddress_sequence[] = {
  { "address"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_address },
  { "presentationIndicator"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_presentationIndicator },
  { "screeningIndicator"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_screeningIndicator },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_ExtendedAliasAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_ExtendedAliasAddress, ExtendedAliasAddress_sequence);

  return offset;
}
static int dissect_additionalSourceAddresses_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ExtendedAliasAddress(tvb, offset, actx, tree, hf_h225_additionalSourceAddresses_item);
}


static const per_sequence_t SEQUENCE_OF_ExtendedAliasAddress_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_additionalSourceAddresses_item },
};

static int
dissect_h225_SEQUENCE_OF_ExtendedAliasAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_ExtendedAliasAddress, SEQUENCE_OF_ExtendedAliasAddress_sequence_of);

  return offset;
}
static int dissect_additionalSourceAddresses(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_ExtendedAliasAddress(tvb, offset, actx, tree, hf_h225_additionalSourceAddresses);
}



static int
dissect_h225_INTEGER_1_31(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 31U, NULL, FALSE);

  return offset;
}
static int dissect_hopCount_1_31(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_1_31(tvb, offset, actx, tree, hf_h225_hopCount_1_31);
}


static const per_sequence_t Setup_UUIE_sequence[] = {
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "h245Address"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245Address },
  { "sourceAddress"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sourceAddress },
  { "sourceInfo"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_setup_UUIE_sourceInfo },
  { "destinationAddress"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_destinationAddress },
  { "destCallSignalAddress"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_destCallSignalAddress },
  { "destExtraCallInfo"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_destExtraCallInfo },
  { "destExtraCRV"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_destExtraCRV },
  { "activeMC"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_activeMC },
  { "conferenceID"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_conferenceID },
  { "conferenceGoal"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_conferenceGoal },
  { "callServices"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callServices },
  { "callType"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callType },
  { "sourceCallSignalAddress"     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_sourceCallSignalAddress },
  { "remoteExtensionAddress"      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_uUIE_remoteExtensionAddress },
  { "callIdentifier"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "h245SecurityCapability"      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245SecurityCapability },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "fastStart"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_fastStart },
  { "mediaWaitForConnect"         , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_mediaWaitForConnect },
  { "canOverlapSend"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_canOverlapSend },
  { "endpointIdentifier"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_endpointIdentifier },
  { "multipleCalls"               , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_multipleCalls },
  { "maintainConnection"          , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_maintainConnection },
  { "connectionParameters"        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_connectionParameters },
  { "language"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_language },
  { "presentationIndicator"       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_presentationIndicator },
  { "screeningIndicator"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_screeningIndicator },
  { "serviceControl"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_serviceControl },
  { "symmetricOperationRequired"  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_symmetricOperationRequired },
  { "capacity"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacity },
  { "circuitInfo"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_circuitInfo },
  { "desiredProtocols"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_desiredProtocols },
  { "neededFeatures"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_neededFeatures },
  { "desiredFeatures"             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_desiredFeatures },
  { "supportedFeatures"           , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_supportedFeatures },
  { "parallelH245Control"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_parallelH245Control },
  { "additionalSourceAddresses"   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_additionalSourceAddresses },
  { "hopCount"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_hopCount_1_31 },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_Setup_UUIE(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 273 "h225.cnf"
  contains_faststart = FALSE;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_Setup_UUIE, Setup_UUIE_sequence);

#line 277 "h225.cnf"
  /* Add to packet info */
  h225_pi->cs_type = H225_SETUP;
  if (contains_faststart == TRUE )
      g_snprintf(h225_pi->frame_label, 50, "%s OLC (%s)", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"), h225_pi->frame_label);
  else
      g_snprintf(h225_pi->frame_label, 50, "%s", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"));

  return offset;
}
static int dissect_setup(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Setup_UUIE(tvb, offset, actx, tree, hf_h225_setup);
}


static const per_sequence_t FeatureSet_sequence[] = {
  { "replacementFeatureSet"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_replacementFeatureSet },
  { "neededFeatures"              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_neededFeatures },
  { "desiredFeatures"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_desiredFeatures },
  { "supportedFeatures"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_supportedFeatures },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_FeatureSet(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_FeatureSet, FeatureSet_sequence);

  return offset;
}
static int dissect_featureSet(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_FeatureSet(tvb, offset, actx, tree, hf_h225_featureSet);
}


static const per_sequence_t CallProceeding_UUIE_sequence[] = {
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "destinationInfo"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uUIE_destinationInfo },
  { "h245Address"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245Address },
  { "callIdentifier"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "h245SecurityMode"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245SecurityMode },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "fastStart"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_fastStart },
  { "multipleCalls"               , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_multipleCalls },
  { "maintainConnection"          , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_maintainConnection },
  { "fastConnectRefused"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_fastConnectRefused },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CallProceeding_UUIE(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CallProceeding_UUIE, CallProceeding_UUIE_sequence);

#line 286 "h225.cnf"
  /* Add to packet info */
  h225_pi->cs_type = H225_CALL_PROCEDING;
  if (contains_faststart == TRUE )
        g_snprintf(h225_pi->frame_label, 50, "%s OLC (%s)", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"), h225_pi->frame_label);
  else
        g_snprintf(h225_pi->frame_label, 50, "%s", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"));

  return offset;
}
static int dissect_callProceeding(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallProceeding_UUIE(tvb, offset, actx, tree, hf_h225_callProceeding);
}


static const per_sequence_t Connect_UUIE_sequence[] = {
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "h245Address"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245Address },
  { "destinationInfo"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uUIE_destinationInfo },
  { "conferenceID"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_conferenceID },
  { "callIdentifier"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "h245SecurityMode"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245SecurityMode },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "fastStart"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_fastStart },
  { "multipleCalls"               , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_multipleCalls },
  { "maintainConnection"          , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_maintainConnection },
  { "language"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_language },
  { "connectedAddress"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_connectedAddress },
  { "presentationIndicator"       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_presentationIndicator },
  { "screeningIndicator"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_screeningIndicator },
  { "fastConnectRefused"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_fastConnectRefused },
  { "serviceControl"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_serviceControl },
  { "capacity"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacity },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_Connect_UUIE(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_Connect_UUIE, Connect_UUIE_sequence);

#line 310 "h225.cnf"
  /* Add to packet info */
  h225_pi->cs_type = H225_CONNECT;
  if (contains_faststart == TRUE )
      g_snprintf(h225_pi->frame_label, 50, "%s OLC (%s)", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"), h225_pi->frame_label);
  else 
      g_snprintf(h225_pi->frame_label, 50, "%s", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"));

  return offset;
}
static int dissect_connect(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Connect_UUIE(tvb, offset, actx, tree, hf_h225_connect);
}


static const per_sequence_t Alerting_UUIE_sequence[] = {
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "destinationInfo"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uUIE_destinationInfo },
  { "h245Address"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245Address },
  { "callIdentifier"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "h245SecurityMode"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245SecurityMode },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "fastStart"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_fastStart },
  { "multipleCalls"               , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_multipleCalls },
  { "maintainConnection"          , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_maintainConnection },
  { "alertingAddress"             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alertingAddress },
  { "presentationIndicator"       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_presentationIndicator },
  { "screeningIndicator"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_screeningIndicator },
  { "fastConnectRefused"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_fastConnectRefused },
  { "serviceControl"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_serviceControl },
  { "capacity"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacity },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_Alerting_UUIE(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_Alerting_UUIE, Alerting_UUIE_sequence);

#line 295 "h225.cnf"
  /* Add to packet info */
  h225_pi->cs_type = H225_ALERTING;
  if (contains_faststart == TRUE )
       g_snprintf(h225_pi->frame_label, 50, "%s OLC (%s)", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"), h225_pi->frame_label);
  else 
       g_snprintf(h225_pi->frame_label, 50, "%s", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"));

  return offset;
}
static int dissect_alerting(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Alerting_UUIE(tvb, offset, actx, tree, hf_h225_alerting);
}


static const per_sequence_t Information_UUIE_sequence[] = {
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "callIdentifier"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "fastStart"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_fastStart },
  { "fastConnectRefused"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_fastConnectRefused },
  { "circuitInfo"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_circuitInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_Information_UUIE(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_Information_UUIE, Information_UUIE_sequence);

#line 250 "h225.cnf"
  /* Add to packet info */
  h225_pi->cs_type = H225_INFORMATION;
  g_snprintf(h225_pi->frame_label, 50, "%s", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"));

  return offset;
}
static int dissect_information(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Information_UUIE(tvb, offset, actx, tree, hf_h225_information);
}


static const value_string h225_SecurityErrors_vals[] = {
  {   0, "securityWrongSyncTime" },
  {   1, "securityReplay" },
  {   2, "securityWrongGeneralID" },
  {   3, "securityWrongSendersID" },
  {   4, "securityIntegrityFailed" },
  {   5, "securityWrongOID" },
  {   6, "securityDHmismatch" },
  {   7, "securityCertificateExpired" },
  {   8, "securityCertificateDateInvalid" },
  {   9, "securityCertificateRevoked" },
  {  10, "securityCertificateNotReadable" },
  {  11, "securityCertificateSignatureInvalid" },
  {  12, "securityCertificateMissing" },
  {  13, "securityCertificateIncomplete" },
  {  14, "securityUnsupportedCertificateAlgOID" },
  {  15, "securityUnknownCA" },
  { 0, NULL }
};

static const per_choice_t SecurityErrors_choice[] = {
  {   0, "securityWrongSyncTime"       , ASN1_EXTENSION_ROOT    , dissect_securityWrongSyncTime },
  {   1, "securityReplay"              , ASN1_EXTENSION_ROOT    , dissect_securityReplay },
  {   2, "securityWrongGeneralID"      , ASN1_EXTENSION_ROOT    , dissect_securityWrongGeneralID },
  {   3, "securityWrongSendersID"      , ASN1_EXTENSION_ROOT    , dissect_securityWrongSendersID },
  {   4, "securityIntegrityFailed"     , ASN1_EXTENSION_ROOT    , dissect_securityIntegrityFailed },
  {   5, "securityWrongOID"            , ASN1_EXTENSION_ROOT    , dissect_securityWrongOID },
  {   6, "securityDHmismatch"          , ASN1_EXTENSION_ROOT    , dissect_securityDHmismatch },
  {   7, "securityCertificateExpired"  , ASN1_EXTENSION_ROOT    , dissect_securityCertificateExpired },
  {   8, "securityCertificateDateInvalid", ASN1_EXTENSION_ROOT    , dissect_securityCertificateDateInvalid },
  {   9, "securityCertificateRevoked"  , ASN1_EXTENSION_ROOT    , dissect_securityCertificateRevoked },
  {  10, "securityCertificateNotReadable", ASN1_EXTENSION_ROOT    , dissect_securityCertificateNotReadable },
  {  11, "securityCertificateSignatureInvalid", ASN1_EXTENSION_ROOT    , dissect_securityCertificateSignatureInvalid },
  {  12, "securityCertificateMissing"  , ASN1_EXTENSION_ROOT    , dissect_securityCertificateMissing },
  {  13, "securityCertificateIncomplete", ASN1_EXTENSION_ROOT    , dissect_securityCertificateIncomplete },
  {  14, "securityUnsupportedCertificateAlgOID", ASN1_EXTENSION_ROOT    , dissect_securityUnsupportedCertificateAlgOID },
  {  15, "securityUnknownCA"           , ASN1_EXTENSION_ROOT    , dissect_securityUnknownCA },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_SecurityErrors(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_SecurityErrors, SecurityErrors_choice,
                                 NULL);

  return offset;
}
static int dissect_rLC_securityError(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SecurityErrors(tvb, offset, actx, tree, hf_h225_rLC_securityError);
}
static int dissect_gkRej_securityError(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SecurityErrors(tvb, offset, actx, tree, hf_h225_gkRej_securityError);
}
static int dissect_reg_securityError(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SecurityErrors(tvb, offset, actx, tree, hf_h225_reg_securityError);
}


const value_string ReleaseCompleteReason_vals[] = {
  {   0, "noBandwidth" },
  {   1, "gatekeeperResources" },
  {   2, "unreachableDestination" },
  {   3, "destinationRejection" },
  {   4, "invalidRevision" },
  {   5, "noPermission" },
  {   6, "unreachableGatekeeper" },
  {   7, "gatewayResources" },
  {   8, "badFormatAddress" },
  {   9, "adaptiveBusy" },
  {  10, "inConf" },
  {  11, "undefinedReason" },
  {  12, "facilityCallDeflection" },
  {  13, "securityDenied" },
  {  14, "calledPartyNotRegistered" },
  {  15, "callerNotRegistered" },
  {  16, "newConnectionNeeded" },
  {  17, "nonStandardReason" },
  {  18, "replaceWithConferenceInvite" },
  {  19, "genericDataReason" },
  {  20, "neededFeatureNotSupported" },
  {  21, "tunnelledSignallingRejected" },
  {  22, "invalidCID" },
  {  23, "securityError" },
  {  24, "hopCountExceeded" },
  { 0, NULL }
};

static const per_choice_t ReleaseCompleteReason_choice[] = {
  {   0, "noBandwidth"                 , ASN1_EXTENSION_ROOT    , dissect_noBandwidth },
  {   1, "gatekeeperResources"         , ASN1_EXTENSION_ROOT    , dissect_gatekeeperResources },
  {   2, "unreachableDestination"      , ASN1_EXTENSION_ROOT    , dissect_unreachableDestination },
  {   3, "destinationRejection"        , ASN1_EXTENSION_ROOT    , dissect_destinationRejection },
  {   4, "invalidRevision"             , ASN1_EXTENSION_ROOT    , dissect_invalidRevision },
  {   5, "noPermission"                , ASN1_EXTENSION_ROOT    , dissect_noPermission },
  {   6, "unreachableGatekeeper"       , ASN1_EXTENSION_ROOT    , dissect_unreachableGatekeeper },
  {   7, "gatewayResources"            , ASN1_EXTENSION_ROOT    , dissect_gatewayResources },
  {   8, "badFormatAddress"            , ASN1_EXTENSION_ROOT    , dissect_badFormatAddress },
  {   9, "adaptiveBusy"                , ASN1_EXTENSION_ROOT    , dissect_adaptiveBusy },
  {  10, "inConf"                      , ASN1_EXTENSION_ROOT    , dissect_inConf },
  {  11, "undefinedReason"             , ASN1_EXTENSION_ROOT    , dissect_undefinedReason },
  {  12, "facilityCallDeflection"      , ASN1_NOT_EXTENSION_ROOT, dissect_facilityCallDeflection },
  {  13, "securityDenied"              , ASN1_NOT_EXTENSION_ROOT, dissect_securityDenied },
  {  14, "calledPartyNotRegistered"    , ASN1_NOT_EXTENSION_ROOT, dissect_calledPartyNotRegistered },
  {  15, "callerNotRegistered"         , ASN1_NOT_EXTENSION_ROOT, dissect_callerNotRegistered },
  {  16, "newConnectionNeeded"         , ASN1_NOT_EXTENSION_ROOT, dissect_newConnectionNeeded },
  {  17, "nonStandardReason"           , ASN1_NOT_EXTENSION_ROOT, dissect_nonStandardReason },
  {  18, "replaceWithConferenceInvite" , ASN1_NOT_EXTENSION_ROOT, dissect_replaceWithConferenceInvite },
  {  19, "genericDataReason"           , ASN1_NOT_EXTENSION_ROOT, dissect_genericDataReason },
  {  20, "neededFeatureNotSupported"   , ASN1_NOT_EXTENSION_ROOT, dissect_neededFeatureNotSupported },
  {  21, "tunnelledSignallingRejected" , ASN1_NOT_EXTENSION_ROOT, dissect_tunnelledSignallingRejected },
  {  22, "invalidCID"                  , ASN1_NOT_EXTENSION_ROOT, dissect_invalidCID },
  {  23, "securityError"               , ASN1_NOT_EXTENSION_ROOT, dissect_rLC_securityError },
  {  24, "hopCountExceeded"            , ASN1_NOT_EXTENSION_ROOT, dissect_hopCountExceeded },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_ReleaseCompleteReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 439 "h225.cnf"
  guint32 value;
	
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_ReleaseCompleteReason, ReleaseCompleteReason_choice,
                                 &value);

  h225_pi->reason = value;


  return offset;
}
static int dissect_releaseCompleteReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ReleaseCompleteReason(tvb, offset, actx, tree, hf_h225_releaseCompleteReason);
}


static const per_sequence_t ReleaseComplete_UUIE_sequence[] = {
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "reason"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_releaseCompleteReason },
  { "callIdentifier"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "busyAddress"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_busyAddress },
  { "presentationIndicator"       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_presentationIndicator },
  { "screeningIndicator"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_screeningIndicator },
  { "capacity"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacity },
  { "serviceControl"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_serviceControl },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_ReleaseComplete_UUIE(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_ReleaseComplete_UUIE, ReleaseComplete_UUIE_sequence);

#line 304 "h225.cnf"
  /* Add to packet info */
  h225_pi->cs_type = H225_RELEASE_COMPLET;
  g_snprintf(h225_pi->frame_label, 50, "%s", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"));

  return offset;
}
static int dissect_releaseComplete(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ReleaseComplete_UUIE(tvb, offset, actx, tree, hf_h225_releaseComplete);
}


const value_string FacilityReason_vals[] = {
  {   0, "routeCallToGatekeeper" },
  {   1, "callForwarded" },
  {   2, "routeCallToMC" },
  {   3, "undefinedReason" },
  {   4, "conferenceListChoice" },
  {   5, "startH245" },
  {   6, "noH245" },
  {   7, "newTokens" },
  {   8, "featureSetUpdate" },
  {   9, "forwardedElements" },
  {  10, "transportedInformation" },
  { 0, NULL }
};

static const per_choice_t FacilityReason_choice[] = {
  {   0, "routeCallToGatekeeper"       , ASN1_EXTENSION_ROOT    , dissect_routeCallToGatekeeper },
  {   1, "callForwarded"               , ASN1_EXTENSION_ROOT    , dissect_callForwarded },
  {   2, "routeCallToMC"               , ASN1_EXTENSION_ROOT    , dissect_routeCallToMC },
  {   3, "undefinedReason"             , ASN1_EXTENSION_ROOT    , dissect_undefinedReason },
  {   4, "conferenceListChoice"        , ASN1_NOT_EXTENSION_ROOT, dissect_conferenceListChoice },
  {   5, "startH245"                   , ASN1_NOT_EXTENSION_ROOT, dissect_startH245 },
  {   6, "noH245"                      , ASN1_NOT_EXTENSION_ROOT, dissect_noH245 },
  {   7, "newTokens"                   , ASN1_NOT_EXTENSION_ROOT, dissect_newTokens },
  {   8, "featureSetUpdate"            , ASN1_NOT_EXTENSION_ROOT, dissect_featureSetUpdate },
  {   9, "forwardedElements"           , ASN1_NOT_EXTENSION_ROOT, dissect_forwardedElements },
  {  10, "transportedInformation"      , ASN1_NOT_EXTENSION_ROOT, dissect_transportedInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_FacilityReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 363 "h225.cnf"
	guint32 value;
	
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_FacilityReason, FacilityReason_choice,
                                 &value);

	h225_pi->reason = value;


  return offset;
}
static int dissect_facilityReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_FacilityReason(tvb, offset, actx, tree, hf_h225_facilityReason);
}


static const per_sequence_t ConferenceList_sequence[] = {
  { "conferenceID"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_conferenceID },
  { "conferenceAlias"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_conferenceAlias },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_ConferenceList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_ConferenceList, ConferenceList_sequence);

  return offset;
}
static int dissect_conferences_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ConferenceList(tvb, offset, actx, tree, hf_h225_conferences_item);
}


static const per_sequence_t SEQUENCE_OF_ConferenceList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_conferences_item },
};

static int
dissect_h225_SEQUENCE_OF_ConferenceList(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_ConferenceList, SEQUENCE_OF_ConferenceList_sequence_of);

  return offset;
}
static int dissect_conferences(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_ConferenceList(tvb, offset, actx, tree, hf_h225_conferences);
}


static const per_sequence_t Facility_UUIE_sequence[] = {
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "alternativeAddress"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_alternativeAddress },
  { "alternativeAliasAddress"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_alternativeAliasAddress },
  { "conferenceID"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_conferenceID },
  { "reason"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_facilityReason },
  { "callIdentifier"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "destExtraCallInfo"           , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_destExtraCallInfo },
  { "remoteExtensionAddress"      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_uUIE_remoteExtensionAddress },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "conferences"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_conferences },
  { "h245Address"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245Address },
  { "fastStart"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_fastStart },
  { "multipleCalls"               , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_multipleCalls },
  { "maintainConnection"          , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_maintainConnection },
  { "fastConnectRefused"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_fastConnectRefused },
  { "serviceControl"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_serviceControl },
  { "circuitInfo"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_circuitInfo },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "destinationInfo"             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_uUIE_destinationInfo },
  { "h245SecurityMode"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245SecurityMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_Facility_UUIE(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_Facility_UUIE, Facility_UUIE_sequence);

#line 265 "h225.cnf"
  /* Add to packet info */
  h225_pi->cs_type = H225_FACILITY;
  g_snprintf(h225_pi->frame_label, 50, "%s", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"));

  return offset;
}
static int dissect_facility(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Facility_UUIE(tvb, offset, actx, tree, hf_h225_facility);
}


static const per_sequence_t Progress_UUIE_sequence[] = {
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "destinationInfo"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uUIE_destinationInfo },
  { "h245Address"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245Address },
  { "callIdentifier"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "h245SecurityMode"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h245SecurityMode },
  { "tokens"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "fastStart"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_fastStart },
  { "multipleCalls"               , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_multipleCalls },
  { "maintainConnection"          , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_maintainConnection },
  { "fastConnectRefused"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_fastConnectRefused },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_Progress_UUIE(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_Progress_UUIE, Progress_UUIE_sequence);

#line 256 "h225.cnf"
  /* Add to packet info */
  h225_pi->cs_type = H225_PROGRESS;
  if (contains_faststart == TRUE )
        g_snprintf(h225_pi->frame_label, 50, "%s OLC (%s)", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"), h225_pi->frame_label);
  else 
        g_snprintf(h225_pi->frame_label, 50, "%s", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"));

  return offset;
}
static int dissect_progress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Progress_UUIE(tvb, offset, actx, tree, hf_h225_progress);
}



static int
dissect_h225_T_empty(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

#line 240 "h225.cnf"
  h225_pi->cs_type = H225_EMPTY;

  return offset;
}
static int dissect_empty_flg(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_empty(tvb, offset, actx, tree, hf_h225_empty_flg);
}


static const per_sequence_t Status_UUIE_sequence[] = {
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "callIdentifier"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "tokens"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cryptoTokens },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_Status_UUIE(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_Status_UUIE, Status_UUIE_sequence);

#line 244 "h225.cnf"
  /* Add to packet info */
  h225_pi->cs_type = H225_STATUS;
  g_snprintf(h225_pi->frame_label, 50, "%s", val_to_str(h225_pi->cs_type, T_h323_message_body_vals, "<unknown>"));

  return offset;
}
static int dissect_status(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Status_UUIE(tvb, offset, actx, tree, hf_h225_status);
}


static const per_sequence_t StatusInquiry_UUIE_sequence[] = {
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "callIdentifier"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "tokens"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cryptoTokens },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_StatusInquiry_UUIE(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_StatusInquiry_UUIE, StatusInquiry_UUIE_sequence);

  return offset;
}
static int dissect_statusInquiry(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_StatusInquiry_UUIE(tvb, offset, actx, tree, hf_h225_statusInquiry);
}


static const per_sequence_t SetupAcknowledge_UUIE_sequence[] = {
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "callIdentifier"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "tokens"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cryptoTokens },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_SetupAcknowledge_UUIE(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_SetupAcknowledge_UUIE, SetupAcknowledge_UUIE_sequence);

  return offset;
}
static int dissect_setupAcknowledge(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SetupAcknowledge_UUIE(tvb, offset, actx, tree, hf_h225_setupAcknowledge);
}


static const per_sequence_t Notify_UUIE_sequence[] = {
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "callIdentifier"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "tokens"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cryptoTokens },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_Notify_UUIE(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_Notify_UUIE, Notify_UUIE_sequence);

  return offset;
}
static int dissect_notify(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Notify_UUIE(tvb, offset, actx, tree, hf_h225_notify);
}


const value_string T_h323_message_body_vals[] = {
  {   0, "setup" },
  {   1, "callProceeding" },
  {   2, "connect" },
  {   3, "alerting" },
  {   4, "information" },
  {   5, "releaseComplete" },
  {   6, "facility" },
  {   7, "progress" },
  {   8, "empty" },
  {   9, "status" },
  {  10, "statusInquiry" },
  {  11, "setupAcknowledge" },
  {  12, "notify" },
  { 0, NULL }
};

static const per_choice_t T_h323_message_body_choice[] = {
  {   0, "setup"                       , ASN1_EXTENSION_ROOT    , dissect_setup },
  {   1, "callProceeding"              , ASN1_EXTENSION_ROOT    , dissect_callProceeding },
  {   2, "connect"                     , ASN1_EXTENSION_ROOT    , dissect_connect },
  {   3, "alerting"                    , ASN1_EXTENSION_ROOT    , dissect_alerting },
  {   4, "information"                 , ASN1_EXTENSION_ROOT    , dissect_information },
  {   5, "releaseComplete"             , ASN1_EXTENSION_ROOT    , dissect_releaseComplete },
  {   6, "facility"                    , ASN1_EXTENSION_ROOT    , dissect_facility },
  {   7, "progress"                    , ASN1_NOT_EXTENSION_ROOT, dissect_progress },
  {   8, "empty"                       , ASN1_NOT_EXTENSION_ROOT, dissect_empty_flg },
  {   9, "status"                      , ASN1_NOT_EXTENSION_ROOT, dissect_status },
  {  10, "statusInquiry"               , ASN1_NOT_EXTENSION_ROOT, dissect_statusInquiry },
  {  11, "setupAcknowledge"            , ASN1_NOT_EXTENSION_ROOT, dissect_setupAcknowledge },
  {  12, "notify"                      , ASN1_NOT_EXTENSION_ROOT, dissect_notify },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_T_h323_message_body(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 137 "h225.cnf"
	guint32 message_body_val;

	contains_faststart = FALSE;
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_T_h323_message_body, T_h323_message_body_choice,
                                 &message_body_val);

	if (check_col(actx->pinfo->cinfo, COL_INFO)){
		col_append_fstr(actx->pinfo->cinfo, COL_INFO, "CS: %s ",
			val_to_str(message_body_val, T_h323_message_body_vals, "<unknown>"));
        }

	if (h225_pi->msg_type == H225_CS) {
		/* Don't override msg_tag value from IRR */
		h225_pi->msg_tag = message_body_val;
	}

	if (contains_faststart == TRUE )
	{
		if (check_col(actx->pinfo->cinfo, COL_INFO))
		{
			col_append_str(actx->pinfo->cinfo, COL_INFO, "OpenLogicalChannel " );
		}
	}

	col_set_fence(actx->pinfo->cinfo,COL_INFO);



  return offset;
}
static int dissect_h323_message_body(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_h323_message_body(tvb, offset, actx, tree, hf_h225_h323_message_body);
}



static int
dissect_h225_T_h4501SupplementaryService_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 455 "h225.cnf"
	tvbuff_t *h4501_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, &h4501_tvb);

	if (h4501_tvb && tvb_length(h4501_tvb)) {
		call_dissector(h4501_handle, h4501_tvb, actx->pinfo, tree);
	}


  return offset;
}
static int dissect_h4501SupplementaryService_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_h4501SupplementaryService_item(tvb, offset, actx, tree, hf_h225_h4501SupplementaryService_item);
}


static const per_sequence_t T_h4501SupplementaryService_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h4501SupplementaryService_item },
};

static int
dissect_h225_T_h4501SupplementaryService(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_T_h4501SupplementaryService, T_h4501SupplementaryService_sequence_of);

  return offset;
}
static int dissect_h4501SupplementaryService(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_h4501SupplementaryService(tvb, offset, actx, tree, hf_h225_h4501SupplementaryService);
}



static int
dissect_h225_T_h245Tunneling(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, &(h225_pi->is_h245Tunneling));

  return offset;
}
static int dissect_h245Tunneling(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_h245Tunneling(tvb, offset, actx, tree, hf_h225_h245Tunneling);
}



static int
dissect_h225_H245Control_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 233 "h225.cnf"
	tvbuff_t *h245_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, &h245_tvb);

  next_tvb_add(&h245_list, h245_tvb, (h225_h245_in_tree)?tree:NULL, h245dg_handle);


  return offset;
}
static int dissect_H245Control_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H245Control_item(tvb, offset, actx, tree, hf_h225_H245Control_item);
}


static const per_sequence_t H245Control_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_H245Control_item },
};

static int
dissect_h225_H245Control(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_H245Control, H245Control_sequence_of);

  return offset;
}
static int dissect_h245Control(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H245Control(tvb, offset, actx, tree, hf_h225_h245Control);
}


static const per_sequence_t SEQUENCE_OF_NonStandardParameter_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nonStandardControl_item },
};

static int
dissect_h225_SEQUENCE_OF_NonStandardParameter(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_NonStandardParameter, SEQUENCE_OF_NonStandardParameter_sequence_of);

  return offset;
}
static int dissect_nonStandardControl(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_NonStandardParameter(tvb, offset, actx, tree, hf_h225_nonStandardControl);
}
static int dissect_nonStandardUsageTypes(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_NonStandardParameter(tvb, offset, actx, tree, hf_h225_nonStandardUsageTypes);
}
static int dissect_nonStandardUsageFields(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_NonStandardParameter(tvb, offset, actx, tree, hf_h225_nonStandardUsageFields);
}


static const per_sequence_t CallLinkage_sequence[] = {
  { "globalCallId"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_globalCallId },
  { "threadId"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_threadId },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CallLinkage(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CallLinkage, CallLinkage_sequence);

  return offset;
}
static int dissect_callLinkage(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallLinkage(tvb, offset, actx, tree, hf_h225_callLinkage);
}



static int
dissect_h225_T_messageContent_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 477 "h225.cnf"
  tvbuff_t *next_tvb = NULL;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, &next_tvb);

  next_tvb_add(&tp_list, next_tvb, (h225_tp_in_tree)?tree:NULL, tp_handle);


  return offset;
}
static int dissect_messageContent_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_messageContent_item(tvb, offset, actx, tree, hf_h225_messageContent_item);
}


static const per_sequence_t T_messageContent_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_messageContent_item },
};

static int
dissect_h225_T_messageContent(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_T_messageContent, T_messageContent_sequence_of);

  return offset;
}
static int dissect_messageContent(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_messageContent(tvb, offset, actx, tree, hf_h225_messageContent);
}


static const per_sequence_t T_tunnelledSignallingMessage_sequence[] = {
  { "tunnelledProtocolID"         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_tunnelledProtocolID },
  { "messageContent"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_messageContent },
  { "tunnellingRequired"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tunnellingRequired },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_tunnelledSignallingMessage(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 475 "h225.cnf"
  tp_handle = NULL;

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_tunnelledSignallingMessage, T_tunnelledSignallingMessage_sequence);

  return offset;
}
static int dissect_tunnelledSignallingMessage(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_tunnelledSignallingMessage(tvb, offset, actx, tree, hf_h225_tunnelledSignallingMessage);
}


static const per_sequence_t StimulusControl_sequence[] = {
  { "nonStandard"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandard },
  { "isText"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_isText },
  { "h248Message"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_h248Message },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_StimulusControl(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_StimulusControl, StimulusControl_sequence);

  return offset;
}
static int dissect_stimulusControl(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_StimulusControl(tvb, offset, actx, tree, hf_h225_stimulusControl);
}


static const per_sequence_t H323_UU_PDU_sequence[] = {
  { "h323-message-body"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h323_message_body },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "h4501SupplementaryService"   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h4501SupplementaryService },
  { "h245Tunneling"               , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_h245Tunneling },
  { "h245Control"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_h245Control },
  { "nonStandardControl"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_nonStandardControl },
  { "callLinkage"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_callLinkage },
  { "tunnelledSignallingMessage"  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tunnelledSignallingMessage },
  { "provisionalRespToH245Tunneling", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_provisionalRespToH245Tunneling },
  { "stimulusControl"             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_stimulusControl },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_H323_UU_PDU(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_H323_UU_PDU, H323_UU_PDU_sequence);

  return offset;
}
static int dissect_h323_uu_pdu(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H323_UU_PDU(tvb, offset, actx, tree, hf_h225_h323_uu_pdu);
}
static int dissect_h323pdu(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H323_UU_PDU(tvb, offset, actx, tree, hf_h225_h323pdu);
}



static int
dissect_h225_OCTET_STRING_SIZE_1_131(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 131, NULL);

  return offset;
}
static int dissect_user_information(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_1_131(tvb, offset, actx, tree, hf_h225_user_information);
}


static const per_sequence_t T_user_data_sequence[] = {
  { "protocol-discriminator"      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocol_discriminator },
  { "user-information"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_user_information },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_user_data(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_user_data, T_user_data_sequence);

  return offset;
}
static int dissect_user_data(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_user_data(tvb, offset, actx, tree, hf_h225_user_data);
}


static const per_sequence_t H323_UserInformation_sequence[] = {
  { "h323-uu-pdu"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h323_uu_pdu },
  { "user-data"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_user_data },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_H323_UserInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_H323_UserInformation, H323_UserInformation_sequence);

  return offset;
}


static const per_sequence_t T_range_sequence[] = {
  { "startOfRange"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_startOfRange },
  { "endOfRange"                  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_endOfRange },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_range(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_range, T_range_sequence);

  return offset;
}
static int dissect_range(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_range(tvb, offset, actx, tree, hf_h225_range);
}


static const value_string h225_AddressPattern_vals[] = {
  {   0, "wildcard" },
  {   1, "range" },
  { 0, NULL }
};

static const per_choice_t AddressPattern_choice[] = {
  {   0, "wildcard"                    , ASN1_EXTENSION_ROOT    , dissect_wildcard },
  {   1, "range"                       , ASN1_EXTENSION_ROOT    , dissect_range },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_AddressPattern(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_AddressPattern, AddressPattern_choice,
                                 NULL);

  return offset;
}
static int dissect_terminalAliasPattern_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AddressPattern(tvb, offset, actx, tree, hf_h225_terminalAliasPattern_item);
}
static int dissect_endpointAliasPattern_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AddressPattern(tvb, offset, actx, tree, hf_h225_endpointAliasPattern_item);
}


static const per_sequence_t SEQUENCE_OF_TransportAddress_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_callSignalAddress_item },
};

static int
dissect_h225_SEQUENCE_OF_TransportAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_TransportAddress, SEQUENCE_OF_TransportAddress_sequence_of);

  return offset;
}
static int dissect_callSignalAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_TransportAddress(tvb, offset, actx, tree, hf_h225_callSignalAddress);
}
static int dissect_rasAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_TransportAddress(tvb, offset, actx, tree, hf_h225_rasAddress);
}
static int dissect_annexE(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_TransportAddress(tvb, offset, actx, tree, hf_h225_annexE);
}
static int dissect_sctp(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_TransportAddress(tvb, offset, actx, tree, hf_h225_sctp);
}



static int
dissect_h225_INTEGER_0_127(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 127U, NULL, FALSE);

  return offset;
}
static int dissect_priority(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_0_127(tvb, offset, actx, tree, hf_h225_priority);
}


static const per_sequence_t AlternateTransportAddresses_sequence[] = {
  { "annexE"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_annexE },
  { "sctp"                        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_sctp },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_AlternateTransportAddresses(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_AlternateTransportAddresses, AlternateTransportAddresses_sequence);

  return offset;
}
static int dissect_alternateTransportAddresses(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AlternateTransportAddresses(tvb, offset, actx, tree, hf_h225_alternateTransportAddresses);
}


static const per_sequence_t Endpoint_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "aliasAddress"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_aliasAddress },
  { "callSignalAddress"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callSignalAddress },
  { "rasAddress"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rasAddress },
  { "endpointType"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_endpointType },
  { "tokens"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "priority"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_priority },
  { "remoteExtensionAddress"      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_remoteExtensionAddress },
  { "destExtraCallInfo"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_destExtraCallInfo },
  { "alternateTransportAddresses" , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alternateTransportAddresses },
  { "circuitInfo"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_circuitInfo },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_Endpoint(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_Endpoint, Endpoint_sequence);

  return offset;
}
static int dissect_alternateEndpoints_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Endpoint(tvb, offset, actx, tree, hf_h225_alternateEndpoints_item);
}
static int dissect_srcAlternatives_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Endpoint(tvb, offset, actx, tree, hf_h225_srcAlternatives_item);
}
static int dissect_destAlternatives_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_Endpoint(tvb, offset, actx, tree, hf_h225_destAlternatives_item);
}


static const value_string h225_UseSpecifiedTransport_vals[] = {
  {   0, "tcp" },
  {   1, "annexE" },
  {   2, "sctp" },
  { 0, NULL }
};

static const per_choice_t UseSpecifiedTransport_choice[] = {
  {   0, "tcp"                         , ASN1_EXTENSION_ROOT    , dissect_tcp },
  {   1, "annexE"                      , ASN1_EXTENSION_ROOT    , dissect_annexE_flg },
  {   2, "sctp"                        , ASN1_NOT_EXTENSION_ROOT, dissect_sctp_flg },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_UseSpecifiedTransport(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_UseSpecifiedTransport, UseSpecifiedTransport_choice,
                                 NULL);

  return offset;
}
static int dissect_useSpecifiedTransport(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_UseSpecifiedTransport(tvb, offset, actx, tree, hf_h225_useSpecifiedTransport);
}


static const per_sequence_t AlternateGK_sequence[] = {
  { "rasAddress"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_alternateGK_rasAddress },
  { "gatekeeperIdentifier"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gatekeeperIdentifier },
  { "needToRegister"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_needToRegister },
  { "priority"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_priority },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_AlternateGK(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_AlternateGK, AlternateGK_sequence);

  return offset;
}
static int dissect_alternateGatekeeper_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AlternateGK(tvb, offset, actx, tree, hf_h225_alternateGatekeeper_item);
}


static const per_sequence_t SEQUENCE_OF_AlternateGK_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_alternateGatekeeper_item },
};

static int
dissect_h225_SEQUENCE_OF_AlternateGK(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_AlternateGK, SEQUENCE_OF_AlternateGK_sequence_of);

  return offset;
}
static int dissect_alternateGatekeeper(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AlternateGK(tvb, offset, actx, tree, hf_h225_alternateGatekeeper);
}


static const per_sequence_t AltGKInfo_sequence[] = {
  { "alternateGatekeeper"         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_alternateGatekeeper },
  { "altGKisPermanent"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_altGKisPermanent },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_AltGKInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_AltGKInfo, AltGKInfo_sequence);

  return offset;
}
static int dissect_altGKInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AltGKInfo(tvb, offset, actx, tree, hf_h225_altGKInfo);
}


static const value_string h225_SecurityErrors2_vals[] = {
  {   0, "securityWrongSyncTime" },
  {   1, "securityReplay" },
  {   2, "securityWrongGeneralID" },
  {   3, "securityWrongSendersID" },
  {   4, "securityIntegrityFailed" },
  {   5, "securityWrongOID" },
  { 0, NULL }
};

static const per_choice_t SecurityErrors2_choice[] = {
  {   0, "securityWrongSyncTime"       , ASN1_EXTENSION_ROOT    , dissect_securityWrongSyncTime },
  {   1, "securityReplay"              , ASN1_EXTENSION_ROOT    , dissect_securityReplay },
  {   2, "securityWrongGeneralID"      , ASN1_EXTENSION_ROOT    , dissect_securityWrongGeneralID },
  {   3, "securityWrongSendersID"      , ASN1_EXTENSION_ROOT    , dissect_securityWrongSendersID },
  {   4, "securityIntegrityFailed"     , ASN1_EXTENSION_ROOT    , dissect_securityIntegrityFailed },
  {   5, "securityWrongOID"            , ASN1_EXTENSION_ROOT    , dissect_securityWrongOID },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_SecurityErrors2(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_SecurityErrors2, SecurityErrors2_choice,
                                 NULL);

  return offset;
}
static int dissect_securityError(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SecurityErrors2(tvb, offset, actx, tree, hf_h225_securityError);
}



static int
dissect_h225_RequestSeqNum(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 65535U, &(h225_pi->requestSeqNum), FALSE);

  return offset;
}
static int dissect_requestSeqNum(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RequestSeqNum(tvb, offset, actx, tree, hf_h225_requestSeqNum);
}



static int
dissect_h225_TimeToLive(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 4294967295U, NULL, FALSE);

  return offset;
}
static int dissect_timeToLive(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TimeToLive(tvb, offset, actx, tree, hf_h225_timeToLive);
}



static int
dissect_h225_H248PackagesDescriptor(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       NO_BOUND, NO_BOUND, NULL);

  return offset;
}
static int dissect_supportedH248Packages_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_H248PackagesDescriptor(tvb, offset, actx, tree, hf_h225_supportedH248Packages_item);
}


static const value_string h225_EncryptIntAlg_vals[] = {
  {   0, "nonStandard" },
  {   1, "isoAlgorithm" },
  { 0, NULL }
};

static const per_choice_t EncryptIntAlg_choice[] = {
  {   0, "nonStandard"                 , ASN1_EXTENSION_ROOT    , dissect_nonStandard },
  {   1, "isoAlgorithm"                , ASN1_EXTENSION_ROOT    , dissect_isoAlgorithm },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_EncryptIntAlg(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_EncryptIntAlg, EncryptIntAlg_choice,
                                 NULL);

  return offset;
}
static int dissect_hMAC_iso10118_2_s(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_EncryptIntAlg(tvb, offset, actx, tree, hf_h225_hMAC_iso10118_2_s);
}
static int dissect_hMAC_iso10118_2_l(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_EncryptIntAlg(tvb, offset, actx, tree, hf_h225_hMAC_iso10118_2_l);
}


static const value_string h225_NonIsoIntegrityMechanism_vals[] = {
  {   0, "hMAC-MD5" },
  {   1, "hMAC-iso10118-2-s" },
  {   2, "hMAC-iso10118-2-l" },
  {   3, "hMAC-iso10118-3" },
  { 0, NULL }
};

static const per_choice_t NonIsoIntegrityMechanism_choice[] = {
  {   0, "hMAC-MD5"                    , ASN1_EXTENSION_ROOT    , dissect_hMAC_MD5 },
  {   1, "hMAC-iso10118-2-s"           , ASN1_EXTENSION_ROOT    , dissect_hMAC_iso10118_2_s },
  {   2, "hMAC-iso10118-2-l"           , ASN1_EXTENSION_ROOT    , dissect_hMAC_iso10118_2_l },
  {   3, "hMAC-iso10118-3"             , ASN1_EXTENSION_ROOT    , dissect_hMAC_iso10118_3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_NonIsoIntegrityMechanism(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_NonIsoIntegrityMechanism, NonIsoIntegrityMechanism_choice,
                                 NULL);

  return offset;
}
static int dissect_nonIsoIM(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NonIsoIntegrityMechanism(tvb, offset, actx, tree, hf_h225_nonIsoIM);
}


static const value_string h225_IntegrityMechanism_vals[] = {
  {   0, "nonStandard" },
  {   1, "digSig" },
  {   2, "iso9797" },
  {   3, "nonIsoIM" },
  { 0, NULL }
};

static const per_choice_t IntegrityMechanism_choice[] = {
  {   0, "nonStandard"                 , ASN1_EXTENSION_ROOT    , dissect_nonStandard },
  {   1, "digSig"                      , ASN1_EXTENSION_ROOT    , dissect_digSig },
  {   2, "iso9797"                     , ASN1_EXTENSION_ROOT    , dissect_iso9797 },
  {   3, "nonIsoIM"                    , ASN1_EXTENSION_ROOT    , dissect_nonIsoIM },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_IntegrityMechanism(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_IntegrityMechanism, IntegrityMechanism_choice,
                                 NULL);

  return offset;
}
static int dissect_integrity_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_IntegrityMechanism(tvb, offset, actx, tree, hf_h225_integrity_item);
}



static int
dissect_h225_BIT_STRING(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     NO_BOUND, NO_BOUND, FALSE);

  return offset;
}
static int dissect_icv(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BIT_STRING(tvb, offset, actx, tree, hf_h225_icv);
}


static const per_sequence_t ICV_sequence[] = {
  { "algorithmOID"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_algorithmOID },
  { "icv"                         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_icv },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_ICV(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_ICV, ICV_sequence);

  return offset;
}
static int dissect_integrityCheckValue(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ICV(tvb, offset, actx, tree, hf_h225_integrityCheckValue);
}



static int
dissect_h225_FastStartToken(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_h235_ClearToken(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t CapacityReportingCapability_sequence[] = {
  { "canReportCallCapacity"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_canReportCallCapacity },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CapacityReportingCapability(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CapacityReportingCapability, CapacityReportingCapability_sequence);

  return offset;
}
static int dissect_capacityReportingCapability(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CapacityReportingCapability(tvb, offset, actx, tree, hf_h225_capacityReportingCapability);
}


static const per_sequence_t CapacityReportingSpecification_when_sequence[] = {
  { "callStart"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callStart },
  { "callEnd"                     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callEnd },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CapacityReportingSpecification_when(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CapacityReportingSpecification_when, CapacityReportingSpecification_when_sequence);

  return offset;
}
static int dissect_capacityReportingSpecification_when(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CapacityReportingSpecification_when(tvb, offset, actx, tree, hf_h225_capacityReportingSpecification_when);
}


static const per_sequence_t CapacityReportingSpecification_sequence[] = {
  { "when"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_capacityReportingSpecification_when },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CapacityReportingSpecification(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CapacityReportingSpecification, CapacityReportingSpecification_sequence);

  return offset;
}
static int dissect_capacityReportingSpec(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CapacityReportingSpecification(tvb, offset, actx, tree, hf_h225_capacityReportingSpec);
}


static const per_sequence_t RasUsageInfoTypes_sequence[] = {
  { "nonStandardUsageTypes"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nonStandardUsageTypes },
  { "startTime"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_startTime },
  { "endTime"                     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_endTime_flg },
  { "terminationCause"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_terminationCause_flg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_RasUsageInfoTypes(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_RasUsageInfoTypes, RasUsageInfoTypes_sequence);

  return offset;
}
static int dissect_required(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RasUsageInfoTypes(tvb, offset, actx, tree, hf_h225_required);
}
static int dissect_usageReportingCapability(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RasUsageInfoTypes(tvb, offset, actx, tree, hf_h225_usageReportingCapability);
}
static int dissect_usageInfoRequested(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RasUsageInfoTypes(tvb, offset, actx, tree, hf_h225_usageInfoRequested);
}


static const per_sequence_t RasUsageSpecification_when_sequence[] = {
  { "start"                       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_start },
  { "end"                         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_end },
  { "inIrr"                       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_inIrr },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_RasUsageSpecification_when(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_RasUsageSpecification_when, RasUsageSpecification_when_sequence);

  return offset;
}
static int dissect_when(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RasUsageSpecification_when(tvb, offset, actx, tree, hf_h225_when);
}


static const per_sequence_t RasUsageSpecificationcallStartingPoint_sequence[] = {
  { "alerting"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_alerting_flg },
  { "connect"                     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_connect_flg },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_RasUsageSpecificationcallStartingPoint(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_RasUsageSpecificationcallStartingPoint, RasUsageSpecificationcallStartingPoint_sequence);

  return offset;
}
static int dissect_ras_callStartingPoint(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RasUsageSpecificationcallStartingPoint(tvb, offset, actx, tree, hf_h225_ras_callStartingPoint);
}


static const per_sequence_t RasUsageSpecification_sequence[] = {
  { "when"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_when },
  { "callStartingPoint"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ras_callStartingPoint },
  { "required"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_required },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_RasUsageSpecification(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_RasUsageSpecification, RasUsageSpecification_sequence);

  return offset;
}
static int dissect_usageSpec_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RasUsageSpecification(tvb, offset, actx, tree, hf_h225_usageSpec_item);
}


static const per_sequence_t RasUsageInformation_sequence[] = {
  { "nonStandardUsageFields"      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nonStandardUsageFields },
  { "alertingTime"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_alertingTime },
  { "connectTime"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_connectTime },
  { "endTime"                     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_endTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_RasUsageInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_RasUsageInformation, RasUsageInformation_sequence);

  return offset;
}
static int dissect_usageInformation(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RasUsageInformation(tvb, offset, actx, tree, hf_h225_usageInformation);
}



static int
dissect_h225_OCTET_STRING_SIZE_2_32(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       2, 32, NULL);

  return offset;
}
static int dissect_releaseCompleteCauseIE(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_OCTET_STRING_SIZE_2_32(tvb, offset, actx, tree, hf_h225_releaseCompleteCauseIE);
}


static const value_string h225_CallTerminationCause_vals[] = {
  {   0, "releaseCompleteReason" },
  {   1, "releaseCompleteCauseIE" },
  { 0, NULL }
};

static const per_choice_t CallTerminationCause_choice[] = {
  {   0, "releaseCompleteReason"       , ASN1_EXTENSION_ROOT    , dissect_releaseCompleteReason },
  {   1, "releaseCompleteCauseIE"      , ASN1_EXTENSION_ROOT    , dissect_releaseCompleteCauseIE },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_CallTerminationCause(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_CallTerminationCause, CallTerminationCause_choice,
                                 NULL);

  return offset;
}
static int dissect_terminationCause(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallTerminationCause(tvb, offset, actx, tree, hf_h225_terminationCause);
}


static const per_sequence_t TransportChannelInfo_sequence[] = {
  { "sendAddress"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sendAddress },
  { "recvAddress"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_recvAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_TransportChannelInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_TransportChannelInfo, TransportChannelInfo_sequence);

  return offset;
}
static int dissect_rtcpAddresses(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportChannelInfo(tvb, offset, actx, tree, hf_h225_rtcpAddresses);
}
static int dissect_rtpAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportChannelInfo(tvb, offset, actx, tree, hf_h225_rtpAddress);
}
static int dissect_rtcpAddress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportChannelInfo(tvb, offset, actx, tree, hf_h225_rtcpAddress);
}
static int dissect_data_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportChannelInfo(tvb, offset, actx, tree, hf_h225_data_item);
}
static int dissect_h245(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportChannelInfo(tvb, offset, actx, tree, hf_h225_h245);
}
static int dissect_callSignaling(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportChannelInfo(tvb, offset, actx, tree, hf_h225_callSignaling);
}


static const per_sequence_t BandwidthDetails_sequence[] = {
  { "sender"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sender },
  { "multicast"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_multicast },
  { "bandwidth"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_bandwidth },
  { "rtcpAddresses"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rtcpAddresses },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_BandwidthDetails(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_BandwidthDetails, BandwidthDetails_sequence);

  return offset;
}
static int dissect_bandwidthDetails_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BandwidthDetails(tvb, offset, actx, tree, hf_h225_bandwidthDetails_item);
}


static const per_sequence_t CallCreditCapability_sequence[] = {
  { "canDisplayAmountString"      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_canDisplayAmountString },
  { "canEnforceDurationLimit"     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_canEnforceDurationLimit },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_CallCreditCapability(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_CallCreditCapability, CallCreditCapability_sequence);

  return offset;
}
static int dissect_callCreditCapability(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallCreditCapability(tvb, offset, actx, tree, hf_h225_callCreditCapability);
}



static int
dissect_h225_PrintableString(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_PrintableString(tvb, offset, actx, tree, hf_index,
                                          NO_BOUND, NO_BOUND);

  return offset;
}
static int dissect_cname(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_PrintableString(tvb, offset, actx, tree, hf_h225_cname);
}



static int
dissect_h225_INTEGER_1_255(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 255U, NULL, FALSE);

  return offset;
}
static int dissect_sessionId(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_1_255(tvb, offset, actx, tree, hf_h225_sessionId);
}
static int dissect_associatedSessionIds_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_1_255(tvb, offset, actx, tree, hf_h225_associatedSessionIds_item);
}
static int dissect_hopCount(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_1_255(tvb, offset, actx, tree, hf_h225_hopCount);
}


static const per_sequence_t T_associatedSessionIds_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_associatedSessionIds_item },
};

static int
dissect_h225_T_associatedSessionIds(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_T_associatedSessionIds, T_associatedSessionIds_sequence_of);

  return offset;
}
static int dissect_associatedSessionIds(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_associatedSessionIds(tvb, offset, actx, tree, hf_h225_associatedSessionIds);
}


static const per_sequence_t RTPSession_sequence[] = {
  { "rtpAddress"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rtpAddress },
  { "rtcpAddress"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rtcpAddress },
  { "cname"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cname },
  { "ssrc"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ssrc },
  { "sessionId"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sessionId },
  { "associatedSessionIds"        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_associatedSessionIds },
  { "multicast"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_multicast_flg },
  { "bandwidth"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_bandwidth },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_RTPSession(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_RTPSession, RTPSession_sequence);

  return offset;
}
static int dissect_audio_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RTPSession(tvb, offset, actx, tree, hf_h225_audio_item);
}
static int dissect_video_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RTPSession(tvb, offset, actx, tree, hf_h225_video_item);
}


static const per_sequence_t SEQUENCE_OF_Endpoint_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_alternateEndpoints_item },
};

static int
dissect_h225_SEQUENCE_OF_Endpoint(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_Endpoint, SEQUENCE_OF_Endpoint_sequence_of);

  return offset;
}
static int dissect_alternateEndpoints(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_Endpoint(tvb, offset, actx, tree, hf_h225_alternateEndpoints);
}
static int dissect_srcAlternatives(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_Endpoint(tvb, offset, actx, tree, hf_h225_srcAlternatives);
}
static int dissect_destAlternatives(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_Endpoint(tvb, offset, actx, tree, hf_h225_destAlternatives);
}


static const per_sequence_t SEQUENCE_OF_AuthenticationMechanism_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_authenticationCapability_item },
};

static int
dissect_h225_SEQUENCE_OF_AuthenticationMechanism(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_AuthenticationMechanism, SEQUENCE_OF_AuthenticationMechanism_sequence_of);

  return offset;
}
static int dissect_authenticationCapability(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AuthenticationMechanism(tvb, offset, actx, tree, hf_h225_authenticationCapability);
}


static const per_sequence_t T_algorithmOIDs_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_algorithmOIDs_item },
};

static int
dissect_h225_T_algorithmOIDs(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_T_algorithmOIDs, T_algorithmOIDs_sequence_of);

  return offset;
}
static int dissect_algorithmOIDs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_algorithmOIDs(tvb, offset, actx, tree, hf_h225_algorithmOIDs);
}


static const per_sequence_t SEQUENCE_OF_IntegrityMechanism_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_integrity_item },
};

static int
dissect_h225_SEQUENCE_OF_IntegrityMechanism(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_IntegrityMechanism, SEQUENCE_OF_IntegrityMechanism_sequence_of);

  return offset;
}
static int dissect_integrity(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_IntegrityMechanism(tvb, offset, actx, tree, hf_h225_integrity);
}


static const per_sequence_t GatekeeperRequest_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "rasAddress"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_gatekeeperRequest_rasAddress },
  { "endpointType"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_endpointType },
  { "gatekeeperIdentifier"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gatekeeperIdentifier },
  { "callServices"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callServices },
  { "endpointAlias"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_endpointAlias },
  { "alternateEndpoints"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alternateEndpoints },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "authenticationCapability"    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_authenticationCapability },
  { "algorithmOIDs"               , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_algorithmOIDs },
  { "integrity"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrity },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "supportsAltGK"               , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_supportsAltGK },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_GatekeeperRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_GatekeeperRequest, GatekeeperRequest_sequence);

  return offset;
}
static int dissect_gatekeeperRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GatekeeperRequest(tvb, offset, actx, tree, hf_h225_gatekeeperRequest);
}


static const per_sequence_t GatekeeperConfirm_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "gatekeeperIdentifier"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gatekeeperIdentifier },
  { "rasAddress"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_gatekeeperConfirm_rasAddress },
  { "alternateGatekeeper"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alternateGatekeeper },
  { "authenticationMode"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_authenticationMode },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "algorithmOID"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_algorithmOID },
  { "integrity"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrity },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_GatekeeperConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_GatekeeperConfirm, GatekeeperConfirm_sequence);

  return offset;
}
static int dissect_gatekeeperConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GatekeeperConfirm(tvb, offset, actx, tree, hf_h225_gatekeeperConfirm);
}


const value_string GatekeeperRejectReason_vals[] = {
  {   0, "resourceUnavailable" },
  {   1, "terminalExcluded" },
  {   2, "invalidRevision" },
  {   3, "undefinedReason" },
  {   4, "securityDenial" },
  {   5, "genericDataReason" },
  {   6, "neededFeatureNotSupported" },
  {   7, "securityError" },
  { 0, NULL }
};

static const per_choice_t GatekeeperRejectReason_choice[] = {
  {   0, "resourceUnavailable"         , ASN1_EXTENSION_ROOT    , dissect_resourceUnavailable },
  {   1, "terminalExcluded"            , ASN1_EXTENSION_ROOT    , dissect_terminalExcluded },
  {   2, "invalidRevision"             , ASN1_EXTENSION_ROOT    , dissect_invalidRevision },
  {   3, "undefinedReason"             , ASN1_EXTENSION_ROOT    , dissect_undefinedReason },
  {   4, "securityDenial"              , ASN1_NOT_EXTENSION_ROOT, dissect_securityDenial },
  {   5, "genericDataReason"           , ASN1_NOT_EXTENSION_ROOT, dissect_genericDataReason },
  {   6, "neededFeatureNotSupported"   , ASN1_NOT_EXTENSION_ROOT, dissect_neededFeatureNotSupported },
  {   7, "securityError"               , ASN1_NOT_EXTENSION_ROOT, dissect_gkRej_securityError },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_GatekeeperRejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 370 "h225.cnf"
  guint32 value;
	
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_GatekeeperRejectReason, GatekeeperRejectReason_choice,
                                 &value);

  h225_pi->reason = value;


  return offset;
}
static int dissect_gatekeeperRejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GatekeeperRejectReason(tvb, offset, actx, tree, hf_h225_gatekeeperRejectReason);
}


static const per_sequence_t GatekeeperReject_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "gatekeeperIdentifier"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gatekeeperIdentifier },
  { "rejectReason"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_gatekeeperRejectReason },
  { "altGKInfo"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_altGKInfo },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_GatekeeperReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_GatekeeperReject, GatekeeperReject_sequence);

  return offset;
}
static int dissect_gatekeeperReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_GatekeeperReject(tvb, offset, actx, tree, hf_h225_gatekeeperReject);
}


static const per_sequence_t SEQUENCE_OF_AddressPattern_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_terminalAliasPattern_item },
};

static int
dissect_h225_SEQUENCE_OF_AddressPattern(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_AddressPattern, SEQUENCE_OF_AddressPattern_sequence_of);

  return offset;
}
static int dissect_terminalAliasPattern(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AddressPattern(tvb, offset, actx, tree, hf_h225_terminalAliasPattern);
}
static int dissect_endpointAliasPattern(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AddressPattern(tvb, offset, actx, tree, hf_h225_endpointAliasPattern);
}


static const per_sequence_t SEQUENCE_OF_H248PackagesDescriptor_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_supportedH248Packages_item },
};

static int
dissect_h225_SEQUENCE_OF_H248PackagesDescriptor(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_H248PackagesDescriptor, SEQUENCE_OF_H248PackagesDescriptor_sequence_of);

  return offset;
}
static int dissect_supportedH248Packages(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_H248PackagesDescriptor(tvb, offset, actx, tree, hf_h225_supportedH248Packages);
}


static const per_sequence_t RegistrationRequest_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "discoveryComplete"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_discoveryComplete },
  { "callSignalAddress"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callSignalAddress },
  { "rasAddress"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rasAddress },
  { "terminalType"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_terminalType },
  { "terminalAlias"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_terminalAlias },
  { "gatekeeperIdentifier"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gatekeeperIdentifier },
  { "endpointVendor"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_endpointVendor },
  { "alternateEndpoints"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alternateEndpoints },
  { "timeToLive"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_timeToLive },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "keepAlive"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_keepAlive },
  { "endpointIdentifier"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_endpointIdentifier },
  { "willSupplyUUIEs"             , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_willSupplyUUIEs },
  { "maintainConnection"          , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_maintainConnection },
  { "alternateTransportAddresses" , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alternateTransportAddresses },
  { "additiveRegistration"        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_additiveRegistration },
  { "terminalAliasPattern"        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_terminalAliasPattern },
  { "supportsAltGK"               , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_supportsAltGK },
  { "usageReportingCapability"    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_usageReportingCapability },
  { "multipleCalls"               , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_multipleCalls },
  { "supportedH248Packages"       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_supportedH248Packages },
  { "callCreditCapability"        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_callCreditCapability },
  { "capacityReportingCapability" , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacityReportingCapability },
  { "capacity"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacity },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { "restart"                     , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_restart },
  { "supportsACFSequences"        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_supportsACFSequences },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_RegistrationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_RegistrationRequest, RegistrationRequest_sequence);

  return offset;
}
static int dissect_registrationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RegistrationRequest(tvb, offset, actx, tree, hf_h225_registrationRequest);
}



static int
dissect_h225_INTEGER_1_65535(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              1U, 65535U, NULL, FALSE);

  return offset;
}
static int dissect_irrFrequencyInCall(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_1_65535(tvb, offset, actx, tree, hf_h225_irrFrequencyInCall);
}
static int dissect_irrFrequency(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_1_65535(tvb, offset, actx, tree, hf_h225_irrFrequency);
}
static int dissect_delay(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_INTEGER_1_65535(tvb, offset, actx, tree, hf_h225_delay);
}


static const per_sequence_t T_preGrantedARQ_sequence[] = {
  { "makeCall"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_makeCall },
  { "useGKCallSignalAddressToMakeCall", ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_useGKCallSignalAddressToMakeCall },
  { "answerCall"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_answerCall },
  { "useGKCallSignalAddressToAnswer", ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_useGKCallSignalAddressToAnswer },
  { "irrFrequencyInCall"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_irrFrequencyInCall },
  { "totalBandwidthRestriction"   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_totalBandwidthRestriction },
  { "alternateTransportAddresses" , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alternateTransportAddresses },
  { "useSpecifiedTransport"       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_useSpecifiedTransport },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_preGrantedARQ(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_preGrantedARQ, T_preGrantedARQ_sequence);

  return offset;
}
static int dissect_preGrantedARQ(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_preGrantedARQ(tvb, offset, actx, tree, hf_h225_preGrantedARQ);
}


static const per_sequence_t SEQUENCE_OF_RasUsageSpecification_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_usageSpec_item },
};

static int
dissect_h225_SEQUENCE_OF_RasUsageSpecification(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_RasUsageSpecification, SEQUENCE_OF_RasUsageSpecification_sequence_of);

  return offset;
}
static int dissect_usageSpec(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_RasUsageSpecification(tvb, offset, actx, tree, hf_h225_usageSpec);
}


static const per_sequence_t RegistrationConfirm_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "callSignalAddress"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callSignalAddress },
  { "terminalAlias"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_terminalAlias },
  { "gatekeeperIdentifier"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gatekeeperIdentifier },
  { "endpointIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_endpointIdentifier },
  { "alternateGatekeeper"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alternateGatekeeper },
  { "timeToLive"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_timeToLive },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "willRespondToIRR"            , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_willRespondToIRR },
  { "preGrantedARQ"               , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_preGrantedARQ },
  { "maintainConnection"          , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_maintainConnection },
  { "serviceControl"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_serviceControl },
  { "supportsAdditiveRegistration", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_supportsAdditiveRegistration },
  { "terminalAliasPattern"        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_terminalAliasPattern },
  { "supportedPrefixes"           , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_supportedPrefixes },
  { "usageSpec"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_usageSpec },
  { "featureServerAlias"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureServerAlias },
  { "capacityReportingSpec"       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacityReportingSpec },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_RegistrationConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_RegistrationConfirm, RegistrationConfirm_sequence);

  return offset;
}
static int dissect_registrationConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RegistrationConfirm(tvb, offset, actx, tree, hf_h225_registrationConfirm);
}


static const per_sequence_t T_invalidTerminalAliases_sequence[] = {
  { "terminalAlias"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_terminalAlias },
  { "terminalAliasPattern"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_terminalAliasPattern },
  { "supportedPrefixes"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_supportedPrefixes },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_invalidTerminalAliases(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_invalidTerminalAliases, T_invalidTerminalAliases_sequence);

  return offset;
}
static int dissect_invalidTerminalAliases(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_invalidTerminalAliases(tvb, offset, actx, tree, hf_h225_invalidTerminalAliases);
}


const value_string RegistrationRejectReason_vals[] = {
  {   0, "discoveryRequired" },
  {   1, "invalidRevision" },
  {   2, "invalidCallSignalAddress" },
  {   3, "invalidRASAddress" },
  {   4, "duplicateAlias" },
  {   5, "invalidTerminalType" },
  {   6, "undefinedReason" },
  {   7, "transportNotSupported" },
  {   8, "transportQOSNotSupported" },
  {   9, "resourceUnavailable" },
  {  10, "invalidAlias" },
  {  11, "securityDenial" },
  {  12, "fullRegistrationRequired" },
  {  13, "additiveRegistrationNotSupported" },
  {  14, "invalidTerminalAliases" },
  {  15, "genericDataReason" },
  {  16, "neededFeatureNotSupported" },
  {  17, "securityError" },
  { 0, NULL }
};

static const per_choice_t RegistrationRejectReason_choice[] = {
  {   0, "discoveryRequired"           , ASN1_EXTENSION_ROOT    , dissect_discoveryRequired },
  {   1, "invalidRevision"             , ASN1_EXTENSION_ROOT    , dissect_invalidRevision },
  {   2, "invalidCallSignalAddress"    , ASN1_EXTENSION_ROOT    , dissect_invalidCallSignalAddress },
  {   3, "invalidRASAddress"           , ASN1_EXTENSION_ROOT    , dissect_invalidRASAddress },
  {   4, "duplicateAlias"              , ASN1_EXTENSION_ROOT    , dissect_duplicateAlias },
  {   5, "invalidTerminalType"         , ASN1_EXTENSION_ROOT    , dissect_invalidTerminalType },
  {   6, "undefinedReason"             , ASN1_EXTENSION_ROOT    , dissect_undefinedReason },
  {   7, "transportNotSupported"       , ASN1_EXTENSION_ROOT    , dissect_transportNotSupported },
  {   8, "transportQOSNotSupported"    , ASN1_NOT_EXTENSION_ROOT, dissect_transportQOSNotSupported },
  {   9, "resourceUnavailable"         , ASN1_NOT_EXTENSION_ROOT, dissect_resourceUnavailable },
  {  10, "invalidAlias"                , ASN1_NOT_EXTENSION_ROOT, dissect_invalidAlias },
  {  11, "securityDenial"              , ASN1_NOT_EXTENSION_ROOT, dissect_securityDenial },
  {  12, "fullRegistrationRequired"    , ASN1_NOT_EXTENSION_ROOT, dissect_fullRegistrationRequired },
  {  13, "additiveRegistrationNotSupported", ASN1_NOT_EXTENSION_ROOT, dissect_additiveRegistrationNotSupported },
  {  14, "invalidTerminalAliases"      , ASN1_NOT_EXTENSION_ROOT, dissect_invalidTerminalAliases },
  {  15, "genericDataReason"           , ASN1_NOT_EXTENSION_ROOT, dissect_genericDataReason },
  {  16, "neededFeatureNotSupported"   , ASN1_NOT_EXTENSION_ROOT, dissect_neededFeatureNotSupported },
  {  17, "securityError"               , ASN1_NOT_EXTENSION_ROOT, dissect_reg_securityError },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_RegistrationRejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 425 "h225.cnf"
  guint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_RegistrationRejectReason, RegistrationRejectReason_choice,
                                 &value);

  h225_pi->reason = value;


  return offset;
}
static int dissect_registrationRejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RegistrationRejectReason(tvb, offset, actx, tree, hf_h225_registrationRejectReason);
}


static const per_sequence_t RegistrationReject_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "rejectReason"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_registrationRejectReason },
  { "gatekeeperIdentifier"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gatekeeperIdentifier },
  { "altGKInfo"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_altGKInfo },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_RegistrationReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_RegistrationReject, RegistrationReject_sequence);

  return offset;
}
static int dissect_registrationReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RegistrationReject(tvb, offset, actx, tree, hf_h225_registrationReject);
}


const value_string UnregRequestReason_vals[] = {
  {   0, "reregistrationRequired" },
  {   1, "ttlExpired" },
  {   2, "securityDenial" },
  {   3, "undefinedReason" },
  {   4, "maintenance" },
  {   5, "securityError" },
  { 0, NULL }
};

static const per_choice_t UnregRequestReason_choice[] = {
  {   0, "reregistrationRequired"      , ASN1_EXTENSION_ROOT    , dissect_reregistrationRequired },
  {   1, "ttlExpired"                  , ASN1_EXTENSION_ROOT    , dissect_ttlExpired },
  {   2, "securityDenial"              , ASN1_EXTENSION_ROOT    , dissect_securityDenial },
  {   3, "undefinedReason"             , ASN1_EXTENSION_ROOT    , dissect_undefinedReason },
  {   4, "maintenance"                 , ASN1_NOT_EXTENSION_ROOT, dissect_maintenance },
  {   5, "securityError"               , ASN1_NOT_EXTENSION_ROOT, dissect_securityError },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_UnregRequestReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 377 "h225.cnf"
  guint32 value;
	
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_UnregRequestReason, UnregRequestReason_choice,
                                 &value);

  h225_pi->reason = value;


  return offset;
}
static int dissect_unregRequestReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_UnregRequestReason(tvb, offset, actx, tree, hf_h225_unregRequestReason);
}


static const per_sequence_t UnregistrationRequest_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "callSignalAddress"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callSignalAddress },
  { "endpointAlias"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_endpointAlias },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "endpointIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_endpointIdentifier },
  { "alternateEndpoints"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alternateEndpoints },
  { "gatekeeperIdentifier"        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_gatekeeperIdentifier },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "reason"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_unregRequestReason },
  { "endpointAliasPattern"        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_endpointAliasPattern },
  { "supportedPrefixes"           , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_supportedPrefixes },
  { "alternateGatekeeper"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alternateGatekeeper },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_UnregistrationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_UnregistrationRequest, UnregistrationRequest_sequence);

  return offset;
}
static int dissect_unregistrationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_UnregistrationRequest(tvb, offset, actx, tree, hf_h225_unregistrationRequest);
}


static const per_sequence_t UnregistrationConfirm_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_UnregistrationConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_UnregistrationConfirm, UnregistrationConfirm_sequence);

  return offset;
}
static int dissect_unregistrationConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_UnregistrationConfirm(tvb, offset, actx, tree, hf_h225_unregistrationConfirm);
}


const value_string UnregRejectReason_vals[] = {
  {   0, "notCurrentlyRegistered" },
  {   1, "callInProgress" },
  {   2, "undefinedReason" },
  {   3, "permissionDenied" },
  {   4, "securityDenial" },
  {   5, "securityError" },
  { 0, NULL }
};

static const per_choice_t UnregRejectReason_choice[] = {
  {   0, "notCurrentlyRegistered"      , ASN1_EXTENSION_ROOT    , dissect_notCurrentlyRegistered },
  {   1, "callInProgress"              , ASN1_EXTENSION_ROOT    , dissect_callInProgress },
  {   2, "undefinedReason"             , ASN1_EXTENSION_ROOT    , dissect_undefinedReason },
  {   3, "permissionDenied"            , ASN1_NOT_EXTENSION_ROOT, dissect_permissionDenied },
  {   4, "securityDenial"              , ASN1_NOT_EXTENSION_ROOT, dissect_securityDenial },
  {   5, "securityError"               , ASN1_NOT_EXTENSION_ROOT, dissect_securityError },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_UnregRejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 384 "h225.cnf"
  guint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_UnregRejectReason, UnregRejectReason_choice,
                                 &value);

  h225_pi->reason = value;


  return offset;
}
static int dissect_unregRejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_UnregRejectReason(tvb, offset, actx, tree, hf_h225_unregRejectReason);
}


static const per_sequence_t UnregistrationReject_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "rejectReason"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_unregRejectReason },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "altGKInfo"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_altGKInfo },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_UnregistrationReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_UnregistrationReject, UnregistrationReject_sequence);

  return offset;
}
static int dissect_unregistrationReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_UnregistrationReject(tvb, offset, actx, tree, hf_h225_unregistrationReject);
}


static const value_string h225_CallModel_vals[] = {
  {   0, "direct" },
  {   1, "gatekeeperRouted" },
  { 0, NULL }
};

static const per_choice_t CallModel_choice[] = {
  {   0, "direct"                      , ASN1_EXTENSION_ROOT    , dissect_direct },
  {   1, "gatekeeperRouted"            , ASN1_EXTENSION_ROOT    , dissect_gatekeeperRouted },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_CallModel(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_CallModel, CallModel_choice,
                                 NULL);

  return offset;
}
static int dissect_callModel(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_CallModel(tvb, offset, actx, tree, hf_h225_callModel);
}



static int
dissect_h225_DestinationInfo_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 192 "h225.cnf"

  h225_pi->is_destinationInfo = TRUE;

  offset = dissect_h225_AliasAddress(tvb, offset, actx, tree, hf_index);

  return offset;
}
static int dissect_DestinationInfo_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_DestinationInfo_item(tvb, offset, actx, tree, hf_h225_DestinationInfo_item);
}


static const per_sequence_t DestinationInfo_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_DestinationInfo_item },
};

static int
dissect_h225_DestinationInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_DestinationInfo, DestinationInfo_sequence_of);

  return offset;
}
static int dissect_destinationInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_DestinationInfo(tvb, offset, actx, tree, hf_h225_destinationInfo);
}


static const value_string h225_TransportQOS_vals[] = {
  {   0, "endpointControlled" },
  {   1, "gatekeeperControlled" },
  {   2, "noControl" },
  { 0, NULL }
};

static const per_choice_t TransportQOS_choice[] = {
  {   0, "endpointControlled"          , ASN1_EXTENSION_ROOT    , dissect_endpointControlled },
  {   1, "gatekeeperControlled"        , ASN1_EXTENSION_ROOT    , dissect_gatekeeperControlled },
  {   2, "noControl"                   , ASN1_EXTENSION_ROOT    , dissect_noControl },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_TransportQOS(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_TransportQOS, TransportQOS_choice,
                                 NULL);

  return offset;
}
static int dissect_transportQOS(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_TransportQOS(tvb, offset, actx, tree, hf_h225_transportQOS);
}


static const per_sequence_t AdmissionRequest_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "callType"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callType },
  { "callModel"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callModel },
  { "endpointIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_endpointIdentifier },
  { "destinationInfo"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_destinationInfo },
  { "destCallSignalAddress"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_destCallSignalAddress },
  { "destExtraCallInfo"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_destExtraCallInfo },
  { "srcInfo"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_srcInfo },
  { "srcCallSignalAddress"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_srcCallSignalAddress },
  { "bandWidth"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_bandWidth },
  { "callReferenceValue"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callReferenceValue },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "callServices"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callServices },
  { "conferenceID"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_conferenceID },
  { "activeMC"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_activeMC },
  { "answerCall"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_answerCall },
  { "canMapAlias"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_canMapAlias },
  { "callIdentifier"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "srcAlternatives"             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_srcAlternatives },
  { "destAlternatives"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_destAlternatives },
  { "gatekeeperIdentifier"        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_gatekeeperIdentifier },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "transportQOS"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_transportQOS },
  { "willSupplyUUIEs"             , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_willSupplyUUIEs },
  { "callLinkage"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_callLinkage },
  { "gatewayDataRate"             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_gatewayDataRate },
  { "capacity"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacity },
  { "circuitInfo"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_circuitInfo },
  { "desiredProtocols"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_desiredProtocols },
  { "desiredTunnelledProtocol"    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_desiredTunnelledProtocol },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { "canMapSrcAlias"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_canMapSrcAlias },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_AdmissionRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_AdmissionRequest, AdmissionRequest_sequence);

  return offset;
}
static int dissect_admissionRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AdmissionRequest(tvb, offset, actx, tree, hf_h225_admissionRequest);
}


static const per_sequence_t UUIEsRequested_sequence[] = {
  { "setup"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_setup_bool },
  { "callProceeding"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callProceeding_flg },
  { "connect"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_connect_bool },
  { "alerting"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_alerting_bool },
  { "information"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_information_bool },
  { "releaseComplete"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_releaseComplete_bool },
  { "facility"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_facility_bool },
  { "progress"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_progress_bool },
  { "empty"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_empty },
  { "status"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_status_bool },
  { "statusInquiry"               , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_statusInquiry_bool },
  { "setupAcknowledge"            , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_setupAcknowledge_bool },
  { "notify"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_notify_bool },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_UUIEsRequested(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_UUIEsRequested, UUIEsRequested_sequence);

  return offset;
}
static int dissect_uuiesRequested(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_UUIEsRequested(tvb, offset, actx, tree, hf_h225_uuiesRequested);
}


static const per_sequence_t AdmissionConfirm_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "bandWidth"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_bandWidth },
  { "callModel"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callModel },
  { "destCallSignalAddress"       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_destCallSignalAddress },
  { "irrFrequency"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_irrFrequency },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "destinationInfo"             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_destinationInfo },
  { "destExtraCallInfo"           , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_destExtraCallInfo },
  { "destinationType"             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_destinationType },
  { "remoteExtensionAddress"      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_remoteExtensionAddress },
  { "alternateEndpoints"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alternateEndpoints },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "transportQOS"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_transportQOS },
  { "willRespondToIRR"            , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_willRespondToIRR },
  { "uuiesRequested"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_uuiesRequested },
  { "language"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_language },
  { "alternateTransportAddresses" , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alternateTransportAddresses },
  { "useSpecifiedTransport"       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_useSpecifiedTransport },
  { "circuitInfo"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_circuitInfo },
  { "usageSpec"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_usageSpec },
  { "supportedProtocols"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_supportedProtocols },
  { "serviceControl"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_serviceControl },
  { "multipleCalls"               , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_multipleCalls },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { "modifiedSrcInfo"             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_modifiedSrcInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_AdmissionConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_AdmissionConfirm, AdmissionConfirm_sequence);

  return offset;
}
static int dissect_admissionConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AdmissionConfirm(tvb, offset, actx, tree, hf_h225_admissionConfirm);
}
static int dissect_admissionConfirmSequence_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AdmissionConfirm(tvb, offset, actx, tree, hf_h225_admissionConfirmSequence_item);
}


static const per_sequence_t SEQUENCE_OF_PartyNumber_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_routeCallToSCN_item },
};

static int
dissect_h225_SEQUENCE_OF_PartyNumber(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_PartyNumber, SEQUENCE_OF_PartyNumber_sequence_of);

  return offset;
}
static int dissect_routeCallToSCN(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_PartyNumber(tvb, offset, actx, tree, hf_h225_routeCallToSCN);
}
static int dissect_routeCalltoSCN(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_PartyNumber(tvb, offset, actx, tree, hf_h225_routeCalltoSCN);
}


const value_string AdmissionRejectReason_vals[] = {
  {   0, "calledPartyNotRegistered" },
  {   1, "invalidPermission" },
  {   2, "requestDenied" },
  {   3, "undefinedReason" },
  {   4, "callerNotRegistered" },
  {   5, "routeCallToGatekeeper" },
  {   6, "invalidEndpointIdentifier" },
  {   7, "resourceUnavailable" },
  {   8, "securityDenial" },
  {   9, "qosControlNotSupported" },
  {  10, "incompleteAddress" },
  {  11, "aliasesInconsistent" },
  {  12, "routeCallToSCN" },
  {  13, "exceedsCallCapacity" },
  {  14, "collectDestination" },
  {  15, "collectPIN" },
  {  16, "genericDataReason" },
  {  17, "neededFeatureNotSupported" },
  {  18, "securityError" },
  {  19, "securityDHmismatch" },
  {  20, "noRouteToDestination" },
  {  21, "unallocatedNumber" },
  { 0, NULL }
};

static const per_choice_t AdmissionRejectReason_choice[] = {
  {   0, "calledPartyNotRegistered"    , ASN1_EXTENSION_ROOT    , dissect_calledPartyNotRegistered },
  {   1, "invalidPermission"           , ASN1_EXTENSION_ROOT    , dissect_invalidPermission },
  {   2, "requestDenied"               , ASN1_EXTENSION_ROOT    , dissect_requestDenied },
  {   3, "undefinedReason"             , ASN1_EXTENSION_ROOT    , dissect_undefinedReason },
  {   4, "callerNotRegistered"         , ASN1_EXTENSION_ROOT    , dissect_callerNotRegistered },
  {   5, "routeCallToGatekeeper"       , ASN1_EXTENSION_ROOT    , dissect_routeCallToGatekeeper },
  {   6, "invalidEndpointIdentifier"   , ASN1_EXTENSION_ROOT    , dissect_invalidEndpointIdentifier },
  {   7, "resourceUnavailable"         , ASN1_EXTENSION_ROOT    , dissect_resourceUnavailable },
  {   8, "securityDenial"              , ASN1_NOT_EXTENSION_ROOT, dissect_securityDenial },
  {   9, "qosControlNotSupported"      , ASN1_NOT_EXTENSION_ROOT, dissect_qosControlNotSupported },
  {  10, "incompleteAddress"           , ASN1_NOT_EXTENSION_ROOT, dissect_incompleteAddress },
  {  11, "aliasesInconsistent"         , ASN1_NOT_EXTENSION_ROOT, dissect_aliasesInconsistent },
  {  12, "routeCallToSCN"              , ASN1_NOT_EXTENSION_ROOT, dissect_routeCallToSCN },
  {  13, "exceedsCallCapacity"         , ASN1_NOT_EXTENSION_ROOT, dissect_exceedsCallCapacity },
  {  14, "collectDestination"          , ASN1_NOT_EXTENSION_ROOT, dissect_collectDestination },
  {  15, "collectPIN"                  , ASN1_NOT_EXTENSION_ROOT, dissect_collectPIN },
  {  16, "genericDataReason"           , ASN1_NOT_EXTENSION_ROOT, dissect_genericDataReason },
  {  17, "neededFeatureNotSupported"   , ASN1_NOT_EXTENSION_ROOT, dissect_neededFeatureNotSupported },
  {  18, "securityError"               , ASN1_NOT_EXTENSION_ROOT, dissect_securityError },
  {  19, "securityDHmismatch"          , ASN1_NOT_EXTENSION_ROOT, dissect_securityDHmismatch },
  {  20, "noRouteToDestination"        , ASN1_NOT_EXTENSION_ROOT, dissect_noRouteToDestination },
  {  21, "unallocatedNumber"           , ASN1_NOT_EXTENSION_ROOT, dissect_unallocatedNumber },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_AdmissionRejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 411 "h225.cnf"
  guint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_AdmissionRejectReason, AdmissionRejectReason_choice,
                                 &value);

  h225_pi->reason = value;


  return offset;
}
static int dissect_rejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AdmissionRejectReason(tvb, offset, actx, tree, hf_h225_rejectReason);
}


static const per_sequence_t AdmissionReject_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "rejectReason"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rejectReason },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "altGKInfo"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_altGKInfo },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "callSignalAddress"           , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_callSignalAddress },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "serviceControl"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_serviceControl },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_AdmissionReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_AdmissionReject, AdmissionReject_sequence);

  return offset;
}
static int dissect_admissionReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_AdmissionReject(tvb, offset, actx, tree, hf_h225_admissionReject);
}


static const per_sequence_t SEQUENCE_OF_BandwidthDetails_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_bandwidthDetails_item },
};

static int
dissect_h225_SEQUENCE_OF_BandwidthDetails(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_BandwidthDetails, SEQUENCE_OF_BandwidthDetails_sequence_of);

  return offset;
}
static int dissect_bandwidthDetails(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_BandwidthDetails(tvb, offset, actx, tree, hf_h225_bandwidthDetails);
}


static const per_sequence_t BandwidthRequest_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "endpointIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_endpointIdentifier },
  { "conferenceID"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_conferenceID },
  { "callReferenceValue"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callReferenceValue },
  { "callType"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callType },
  { "bandWidth"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_bandWidth },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "callIdentifier"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "gatekeeperIdentifier"        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_gatekeeperIdentifier },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "answeredCall"                , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_answeredCall },
  { "callLinkage"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_callLinkage },
  { "capacity"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacity },
  { "usageInformation"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_usageInformation },
  { "bandwidthDetails"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_bandwidthDetails },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_BandwidthRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_BandwidthRequest, BandwidthRequest_sequence);

  return offset;
}
static int dissect_bandwidthRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BandwidthRequest(tvb, offset, actx, tree, hf_h225_bandwidthRequest);
}


static const per_sequence_t BandwidthConfirm_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "bandWidth"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_bandWidth },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "capacity"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacity },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_BandwidthConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_BandwidthConfirm, BandwidthConfirm_sequence);

  return offset;
}
static int dissect_bandwidthConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BandwidthConfirm(tvb, offset, actx, tree, hf_h225_bandwidthConfirm);
}


const value_string BandRejectReason_vals[] = {
  {   0, "notBound" },
  {   1, "invalidConferenceID" },
  {   2, "invalidPermission" },
  {   3, "insufficientResources" },
  {   4, "invalidRevision" },
  {   5, "undefinedReason" },
  {   6, "securityDenial" },
  {   7, "securityError" },
  { 0, NULL }
};

static const per_choice_t BandRejectReason_choice[] = {
  {   0, "notBound"                    , ASN1_EXTENSION_ROOT    , dissect_notBound },
  {   1, "invalidConferenceID"         , ASN1_EXTENSION_ROOT    , dissect_invalidConferenceID },
  {   2, "invalidPermission"           , ASN1_EXTENSION_ROOT    , dissect_invalidPermission },
  {   3, "insufficientResources"       , ASN1_EXTENSION_ROOT    , dissect_insufficientResources },
  {   4, "invalidRevision"             , ASN1_EXTENSION_ROOT    , dissect_invalidRevision },
  {   5, "undefinedReason"             , ASN1_EXTENSION_ROOT    , dissect_undefinedReason },
  {   6, "securityDenial"              , ASN1_NOT_EXTENSION_ROOT, dissect_securityDenial },
  {   7, "securityError"               , ASN1_NOT_EXTENSION_ROOT, dissect_securityError },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_BandRejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 391 "h225.cnf"
  guint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_BandRejectReason, BandRejectReason_choice,
                                 &value);

  h225_pi->reason = value;


  return offset;
}
static int dissect_bandRejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BandRejectReason(tvb, offset, actx, tree, hf_h225_bandRejectReason);
}


static const per_sequence_t BandwidthReject_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "rejectReason"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_bandRejectReason },
  { "allowedBandWidth"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_allowedBandWidth },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "altGKInfo"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_altGKInfo },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_BandwidthReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_BandwidthReject, BandwidthReject_sequence);

  return offset;
}
static int dissect_bandwidthReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_BandwidthReject(tvb, offset, actx, tree, hf_h225_bandwidthReject);
}


const value_string DisengageReason_vals[] = {
  {   0, "forcedDrop" },
  {   1, "normalDrop" },
  {   2, "undefinedReason" },
  { 0, NULL }
};

static const per_choice_t DisengageReason_choice[] = {
  {   0, "forcedDrop"                  , ASN1_EXTENSION_ROOT    , dissect_forcedDrop },
  {   1, "normalDrop"                  , ASN1_EXTENSION_ROOT    , dissect_normalDrop },
  {   2, "undefinedReason"             , ASN1_EXTENSION_ROOT    , dissect_undefinedReason },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_DisengageReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 398 "h225.cnf"
  guint32 value;
	
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_DisengageReason, DisengageReason_choice,
                                 &value);

  h225_pi->reason = value;


  return offset;
}
static int dissect_disengageReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_DisengageReason(tvb, offset, actx, tree, hf_h225_disengageReason);
}


static const per_sequence_t DisengageRequest_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "endpointIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_endpointIdentifier },
  { "conferenceID"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_conferenceID },
  { "callReferenceValue"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callReferenceValue },
  { "disengageReason"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_disengageReason },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "callIdentifier"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "gatekeeperIdentifier"        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_gatekeeperIdentifier },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "answeredCall"                , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_answeredCall },
  { "callLinkage"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_callLinkage },
  { "capacity"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacity },
  { "circuitInfo"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_circuitInfo },
  { "usageInformation"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_usageInformation },
  { "terminationCause"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_terminationCause },
  { "serviceControl"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_serviceControl },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_DisengageRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_DisengageRequest, DisengageRequest_sequence);

  return offset;
}
static int dissect_disengageRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_DisengageRequest(tvb, offset, actx, tree, hf_h225_disengageRequest);
}


static const per_sequence_t DisengageConfirm_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "capacity"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacity },
  { "circuitInfo"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_circuitInfo },
  { "usageInformation"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_usageInformation },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_DisengageConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_DisengageConfirm, DisengageConfirm_sequence);

  return offset;
}
static int dissect_disengageConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_DisengageConfirm(tvb, offset, actx, tree, hf_h225_disengageConfirm);
}


const value_string DisengageRejectReason_vals[] = {
  {   0, "notRegistered" },
  {   1, "requestToDropOther" },
  {   2, "securityDenial" },
  {   3, "securityError" },
  { 0, NULL }
};

static const per_choice_t DisengageRejectReason_choice[] = {
  {   0, "notRegistered"               , ASN1_EXTENSION_ROOT    , dissect_notRegistered },
  {   1, "requestToDropOther"          , ASN1_EXTENSION_ROOT    , dissect_requestToDropOther },
  {   2, "securityDenial"              , ASN1_NOT_EXTENSION_ROOT, dissect_securityDenial },
  {   3, "securityError"               , ASN1_NOT_EXTENSION_ROOT, dissect_securityError },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_DisengageRejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 404 "h225.cnf"
  guint32 value;
	
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_DisengageRejectReason, DisengageRejectReason_choice,
                                 &value);

  h225_pi->reason = value;


  return offset;
}
static int dissect_disengageRejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_DisengageRejectReason(tvb, offset, actx, tree, hf_h225_disengageRejectReason);
}


static const per_sequence_t DisengageReject_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "rejectReason"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_disengageRejectReason },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "altGKInfo"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_altGKInfo },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_DisengageReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_DisengageReject, DisengageReject_sequence);

  return offset;
}
static int dissect_disengageReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_DisengageReject(tvb, offset, actx, tree, hf_h225_disengageReject);
}


static const per_sequence_t LocationRequest_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "endpointIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_endpointIdentifier },
  { "destinationInfo"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_destinationInfo },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "replyAddress"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_replyAddress },
  { "sourceInfo"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_sourceInfo },
  { "canMapAlias"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_canMapAlias },
  { "gatekeeperIdentifier"        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_gatekeeperIdentifier },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "desiredProtocols"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_desiredProtocols },
  { "desiredTunnelledProtocol"    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_desiredTunnelledProtocol },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { "hopCount"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_hopCount },
  { "circuitInfo"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_circuitInfo },
  { "callIdentifier"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_callIdentifier },
  { "bandWidth"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_bandWidth },
  { "sourceEndpointInfo"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_sourceEndpointInfo },
  { "canMapSrcAlias"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_canMapSrcAlias },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_LocationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_LocationRequest, LocationRequest_sequence);

  return offset;
}
static int dissect_locationRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_LocationRequest(tvb, offset, actx, tree, hf_h225_locationRequest);
}


static const per_sequence_t LocationConfirm_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "callSignalAddress"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_locationConfirm_callSignalAddress },
  { "rasAddress"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_locationConfirm_rasAddress },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "destinationInfo"             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_destinationInfo },
  { "destExtraCallInfo"           , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_destExtraCallInfo },
  { "destinationType"             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_destinationType },
  { "remoteExtensionAddress"      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_remoteExtensionAddress },
  { "alternateEndpoints"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alternateEndpoints },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "alternateTransportAddresses" , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_alternateTransportAddresses },
  { "supportedProtocols"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_supportedProtocols },
  { "multipleCalls"               , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_multipleCalls },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { "circuitInfo"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_circuitInfo },
  { "serviceControl"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_serviceControl },
  { "modifiedSrcInfo"             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_modifiedSrcInfo },
  { "bandWidth"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_bandWidth },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_LocationConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_LocationConfirm, LocationConfirm_sequence);

  return offset;
}
static int dissect_locationConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_LocationConfirm(tvb, offset, actx, tree, hf_h225_locationConfirm);
}


const value_string LocationRejectReason_vals[] = {
  {   0, "notRegistered" },
  {   1, "invalidPermission" },
  {   2, "requestDenied" },
  {   3, "undefinedReason" },
  {   4, "securityDenial" },
  {   5, "aliasesInconsistent" },
  {   6, "routeCalltoSCN" },
  {   7, "resourceUnavailable" },
  {   8, "genericDataReason" },
  {   9, "neededFeatureNotSupported" },
  {  10, "hopCountExceeded" },
  {  11, "incompleteAddress" },
  {  12, "securityError" },
  {  13, "securityDHmismatch" },
  {  14, "noRouteToDestination" },
  {  15, "unallocatedNumber" },
  { 0, NULL }
};

static const per_choice_t LocationRejectReason_choice[] = {
  {   0, "notRegistered"               , ASN1_EXTENSION_ROOT    , dissect_notRegistered },
  {   1, "invalidPermission"           , ASN1_EXTENSION_ROOT    , dissect_invalidPermission },
  {   2, "requestDenied"               , ASN1_EXTENSION_ROOT    , dissect_requestDenied },
  {   3, "undefinedReason"             , ASN1_EXTENSION_ROOT    , dissect_undefinedReason },
  {   4, "securityDenial"              , ASN1_NOT_EXTENSION_ROOT, dissect_securityDenial },
  {   5, "aliasesInconsistent"         , ASN1_NOT_EXTENSION_ROOT, dissect_aliasesInconsistent },
  {   6, "routeCalltoSCN"              , ASN1_NOT_EXTENSION_ROOT, dissect_routeCalltoSCN },
  {   7, "resourceUnavailable"         , ASN1_NOT_EXTENSION_ROOT, dissect_resourceUnavailable },
  {   8, "genericDataReason"           , ASN1_NOT_EXTENSION_ROOT, dissect_genericDataReason },
  {   9, "neededFeatureNotSupported"   , ASN1_NOT_EXTENSION_ROOT, dissect_neededFeatureNotSupported },
  {  10, "hopCountExceeded"            , ASN1_NOT_EXTENSION_ROOT, dissect_hopCountExceeded },
  {  11, "incompleteAddress"           , ASN1_NOT_EXTENSION_ROOT, dissect_incompleteAddress },
  {  12, "securityError"               , ASN1_NOT_EXTENSION_ROOT, dissect_securityError },
  {  13, "securityDHmismatch"          , ASN1_NOT_EXTENSION_ROOT, dissect_securityDHmismatch },
  {  14, "noRouteToDestination"        , ASN1_NOT_EXTENSION_ROOT, dissect_noRouteToDestination },
  {  15, "unallocatedNumber"           , ASN1_NOT_EXTENSION_ROOT, dissect_unallocatedNumber },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_LocationRejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 418 "h225.cnf"
  guint32 value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_LocationRejectReason, LocationRejectReason_choice,
                                 &value);

  h225_pi->reason = value;


  return offset;
}
static int dissect_locationRejectReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_LocationRejectReason(tvb, offset, actx, tree, hf_h225_locationRejectReason);
}


static const per_sequence_t LocationReject_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "rejectReason"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_locationRejectReason },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "altGKInfo"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_altGKInfo },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { "serviceControl"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_serviceControl },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_LocationReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_LocationReject, LocationReject_sequence);

  return offset;
}
static int dissect_locationReject(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_LocationReject(tvb, offset, actx, tree, hf_h225_locationReject);
}


static const per_sequence_t InfoRequest_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "callReferenceValue"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callReferenceValue },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "replyAddress"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_replyAddress },
  { "callIdentifier"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "uuiesRequested"              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_uuiesRequested },
  { "callLinkage"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_callLinkage },
  { "usageInfoRequested"          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_usageInfoRequested },
  { "segmentedResponseSupported"  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_segmentedResponseSupported },
  { "nextSegmentRequested"        , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_nextSegmentRequested },
  { "capacityInfoRequested"       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacityInfoRequested },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_InfoRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_InfoRequest, InfoRequest_sequence);

  return offset;
}
static int dissect_infoRequest(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_InfoRequest(tvb, offset, actx, tree, hf_h225_infoRequest);
}


static const per_sequence_t SEQUENCE_OF_RTPSession_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_audio_item },
};

static int
dissect_h225_SEQUENCE_OF_RTPSession(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_RTPSession, SEQUENCE_OF_RTPSession_sequence_of);

  return offset;
}
static int dissect_audio(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_RTPSession(tvb, offset, actx, tree, hf_h225_audio);
}
static int dissect_video(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_RTPSession(tvb, offset, actx, tree, hf_h225_video);
}


static const per_sequence_t SEQUENCE_OF_TransportChannelInfo_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_data_item },
};

static int
dissect_h225_SEQUENCE_OF_TransportChannelInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_TransportChannelInfo, SEQUENCE_OF_TransportChannelInfo_sequence_of);

  return offset;
}
static int dissect_data(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_TransportChannelInfo(tvb, offset, actx, tree, hf_h225_data);
}


static const per_sequence_t SEQUENCE_OF_ConferenceIdentifier_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_substituteConfIDs_item },
};

static int
dissect_h225_SEQUENCE_OF_ConferenceIdentifier(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_ConferenceIdentifier, SEQUENCE_OF_ConferenceIdentifier_sequence_of);

  return offset;
}
static int dissect_substituteConfIDs(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_ConferenceIdentifier(tvb, offset, actx, tree, hf_h225_substituteConfIDs);
}


static const per_sequence_t T_pdu_item_sequence[] = {
  { "h323pdu"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_h323pdu },
  { "sent"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sent },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_pdu_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_pdu_item, T_pdu_item_sequence);

  return offset;
}
static int dissect_pdu_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_pdu_item(tvb, offset, actx, tree, hf_h225_pdu_item);
}


static const per_sequence_t T_pdu_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pdu_item },
};

static int
dissect_h225_T_pdu(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_T_pdu, T_pdu_sequence_of);

  return offset;
}
static int dissect_pdu(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_pdu(tvb, offset, actx, tree, hf_h225_pdu);
}


static const per_sequence_t T_perCallInfo_item_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "callReferenceValue"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callReferenceValue },
  { "conferenceID"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_conferenceID },
  { "originator"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_originator },
  { "audio"                       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_audio },
  { "video"                       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_video },
  { "data"                        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_data },
  { "h245"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_h245 },
  { "callSignaling"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callSignaling },
  { "callType"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callType },
  { "bandWidth"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_bandWidth },
  { "callModel"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callModel },
  { "callIdentifier"              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "substituteConfIDs"           , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_substituteConfIDs },
  { "pdu"                         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_pdu },
  { "callLinkage"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_callLinkage },
  { "usageInformation"            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_usageInformation },
  { "circuitInfo"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_circuitInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_perCallInfo_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_perCallInfo_item, T_perCallInfo_item_sequence);

  return offset;
}
static int dissect_perCallInfo_item(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_perCallInfo_item(tvb, offset, actx, tree, hf_h225_perCallInfo_item);
}


static const per_sequence_t T_perCallInfo_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_perCallInfo_item },
};

static int
dissect_h225_T_perCallInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_T_perCallInfo, T_perCallInfo_sequence_of);

  return offset;
}
static int dissect_perCallInfo(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_perCallInfo(tvb, offset, actx, tree, hf_h225_perCallInfo);
}


static const value_string h225_InfoRequestResponseStatus_vals[] = {
  {   0, "complete" },
  {   1, "incomplete" },
  {   2, "segment" },
  {   3, "invalidCall" },
  { 0, NULL }
};

static const per_choice_t InfoRequestResponseStatus_choice[] = {
  {   0, "complete"                    , ASN1_EXTENSION_ROOT    , dissect_complete },
  {   1, "incomplete"                  , ASN1_EXTENSION_ROOT    , dissect_incomplete },
  {   2, "segment"                     , ASN1_EXTENSION_ROOT    , dissect_segment },
  {   3, "invalidCall"                 , ASN1_EXTENSION_ROOT    , dissect_invalidCall },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_InfoRequestResponseStatus(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_InfoRequestResponseStatus, InfoRequestResponseStatus_choice,
                                 NULL);

  return offset;
}
static int dissect_irrStatus(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_InfoRequestResponseStatus(tvb, offset, actx, tree, hf_h225_irrStatus);
}


static const per_sequence_t InfoRequestResponse_sequence[] = {
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "endpointType"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_endpointType },
  { "endpointIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_endpointIdentifier },
  { "rasAddress"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_infoRequestResponse_rasAddress },
  { "callSignalAddress"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callSignalAddress },
  { "endpointAlias"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_endpointAlias },
  { "perCallInfo"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_perCallInfo },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "needResponse"                , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_needResponse },
  { "capacity"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacity },
  { "irrStatus"                   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_irrStatus },
  { "unsolicited"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_unsolicited },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_InfoRequestResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_InfoRequestResponse, InfoRequestResponse_sequence);

  return offset;
}
static int dissect_infoRequestResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_InfoRequestResponse(tvb, offset, actx, tree, hf_h225_infoRequestResponse);
}


static const per_sequence_t NonStandardMessage_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nonStandardData },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "featureSet"                  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_NonStandardMessage(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_NonStandardMessage, NonStandardMessage_sequence);

  return offset;
}
static int dissect_nonStandardMessage(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_NonStandardMessage(tvb, offset, actx, tree, hf_h225_nonStandardMessage);
}


static const per_sequence_t UnknownMessageResponse_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "tokens"                      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "messageNotUnderstood"        , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_messageNotUnderstood },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_UnknownMessageResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_UnknownMessageResponse, UnknownMessageResponse_sequence);

  return offset;
}
static int dissect_unknownMessageResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_UnknownMessageResponse(tvb, offset, actx, tree, hf_h225_unknownMessageResponse);
}


static const per_sequence_t RequestInProgress_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "tokens"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "delay"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_delay },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_RequestInProgress(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_RequestInProgress, RequestInProgress_sequence);

  return offset;
}
static int dissect_requestInProgress(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_RequestInProgress(tvb, offset, actx, tree, hf_h225_requestInProgress);
}


static const per_sequence_t ResourcesAvailableIndicate_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "endpointIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_endpointIdentifier },
  { "protocols"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocols },
  { "almostOutOfResources"        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_almostOutOfResources },
  { "tokens"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "capacity"                    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_capacity },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_ResourcesAvailableIndicate(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_ResourcesAvailableIndicate, ResourcesAvailableIndicate_sequence);

  return offset;
}
static int dissect_resourcesAvailableIndicate(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ResourcesAvailableIndicate(tvb, offset, actx, tree, hf_h225_resourcesAvailableIndicate);
}


static const per_sequence_t ResourcesAvailableConfirm_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "protocolIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_protocolIdentifier },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "tokens"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "genericData"                 , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_ResourcesAvailableConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_ResourcesAvailableConfirm, ResourcesAvailableConfirm_sequence);

  return offset;
}
static int dissect_resourcesAvailableConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ResourcesAvailableConfirm(tvb, offset, actx, tree, hf_h225_resourcesAvailableConfirm);
}


static const per_sequence_t InfoRequestAck_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "tokens"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_InfoRequestAck(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_InfoRequestAck, InfoRequestAck_sequence);

  return offset;
}
static int dissect_infoRequestAck(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_InfoRequestAck(tvb, offset, actx, tree, hf_h225_infoRequestAck);
}


const value_string InfoRequestNakReason_vals[] = {
  {   0, "notRegistered" },
  {   1, "securityDenial" },
  {   2, "undefinedReason" },
  {   3, "securityError" },
  { 0, NULL }
};

static const per_choice_t InfoRequestNakReason_choice[] = {
  {   0, "notRegistered"               , ASN1_EXTENSION_ROOT    , dissect_notRegistered },
  {   1, "securityDenial"              , ASN1_EXTENSION_ROOT    , dissect_securityDenial },
  {   2, "undefinedReason"             , ASN1_EXTENSION_ROOT    , dissect_undefinedReason },
  {   3, "securityError"               , ASN1_NOT_EXTENSION_ROOT, dissect_securityError },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_InfoRequestNakReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 432 "h225.cnf"
  guint32 value;
	
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_InfoRequestNakReason, InfoRequestNakReason_choice,
                                 &value);

  h225_pi->reason = value;


  return offset;
}
static int dissect_nakReason(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_InfoRequestNakReason(tvb, offset, actx, tree, hf_h225_nakReason);
}


static const per_sequence_t InfoRequestNak_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "nakReason"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nakReason },
  { "altGKInfo"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_altGKInfo },
  { "tokens"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_InfoRequestNak(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_InfoRequestNak, InfoRequestNak_sequence);

  return offset;
}
static int dissect_infoRequestNak(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_InfoRequestNak(tvb, offset, actx, tree, hf_h225_infoRequestNak);
}


static const per_sequence_t T_callSpecific_sequence[] = {
  { "callIdentifier"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_callIdentifier },
  { "conferenceID"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_conferenceID },
  { "answeredCall"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_answeredCall },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_T_callSpecific(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_T_callSpecific, T_callSpecific_sequence);

  return offset;
}
static int dissect_callSpecific(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_callSpecific(tvb, offset, actx, tree, hf_h225_callSpecific);
}


static const per_sequence_t ServiceControlIndication_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "serviceControl"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_serviceControl },
  { "endpointIdentifier"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_endpointIdentifier },
  { "callSpecific"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_callSpecific },
  { "tokens"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "featureSet"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_ServiceControlIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_ServiceControlIndication, ServiceControlIndication_sequence);

  return offset;
}
static int dissect_serviceControlIndication(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ServiceControlIndication(tvb, offset, actx, tree, hf_h225_serviceControlIndication);
}


static const value_string h225_T_result_vals[] = {
  {   0, "started" },
  {   1, "failed" },
  {   2, "stopped" },
  {   3, "notAvailable" },
  {   4, "neededFeatureNotSupported" },
  { 0, NULL }
};

static const per_choice_t T_result_choice[] = {
  {   0, "started"                     , ASN1_EXTENSION_ROOT    , dissect_started },
  {   1, "failed"                      , ASN1_EXTENSION_ROOT    , dissect_failed },
  {   2, "stopped"                     , ASN1_EXTENSION_ROOT    , dissect_stopped },
  {   3, "notAvailable"                , ASN1_EXTENSION_ROOT    , dissect_notAvailable },
  {   4, "neededFeatureNotSupported"   , ASN1_EXTENSION_ROOT    , dissect_neededFeatureNotSupported },
  { 0, NULL, 0, NULL }
};

static int
dissect_h225_T_result(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_T_result, T_result_choice,
                                 NULL);

  return offset;
}
static int dissect_result(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_T_result(tvb, offset, actx, tree, hf_h225_result);
}


static const per_sequence_t ServiceControlResponse_sequence[] = {
  { "requestSeqNum"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_requestSeqNum },
  { "result"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_result },
  { "nonStandardData"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nonStandardData },
  { "tokens"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tokens },
  { "cryptoTokens"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_cryptoTokens },
  { "integrityCheckValue"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_integrityCheckValue },
  { "featureSet"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_featureSet },
  { "genericData"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_genericData },
  { NULL, 0, 0, NULL }
};

static int
dissect_h225_ServiceControlResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_h225_ServiceControlResponse, ServiceControlResponse_sequence);

  return offset;
}
static int dissect_serviceControlResponse(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_ServiceControlResponse(tvb, offset, actx, tree, hf_h225_serviceControlResponse);
}


static const per_sequence_t SEQUENCE_OF_AdmissionConfirm_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_admissionConfirmSequence_item },
};

static int
dissect_h225_SEQUENCE_OF_AdmissionConfirm(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence_of(tvb, offset, actx, tree, hf_index,
                                      ett_h225_SEQUENCE_OF_AdmissionConfirm, SEQUENCE_OF_AdmissionConfirm_sequence_of);

  return offset;
}
static int dissect_admissionConfirmSequence(tvbuff_t *tvb, int offset, asn_ctx_t *actx, proto_tree *tree) {
  return dissect_h225_SEQUENCE_OF_AdmissionConfirm(tvb, offset, actx, tree, hf_h225_admissionConfirmSequence);
}


const value_string RasMessage_vals[] = {
  {   0, "gatekeeperRequest" },
  {   1, "gatekeeperConfirm" },
  {   2, "gatekeeperReject" },
  {   3, "registrationRequest" },
  {   4, "registrationConfirm" },
  {   5, "registrationReject" },
  {   6, "unregistrationRequest" },
  {   7, "unregistrationConfirm" },
  {   8, "unregistrationReject" },
  {   9, "admissionRequest" },
  {  10, "admissionConfirm" },
  {  11, "admissionReject" },
  {  12, "bandwidthRequest" },
  {  13, "bandwidthConfirm" },
  {  14, "bandwidthReject" },
  {  15, "disengageRequest" },
  {  16, "disengageConfirm" },
  {  17, "disengageReject" },
  {  18, "locationRequest" },
  {  19, "locationConfirm" },
  {  20, "locationReject" },
  {  21, "infoRequest" },
  {  22, "infoRequestResponse" },
  {  23, "nonStandardMessage" },
  {  24, "unknownMessageResponse" },
  {  25, "requestInProgress" },
  {  26, "resourcesAvailableIndicate" },
  {  27, "resourcesAvailableConfirm" },
  {  28, "infoRequestAck" },
  {  29, "infoRequestNak" },
  {  30, "serviceControlIndication" },
  {  31, "serviceControlResponse" },
  {  32, "admissionConfirmSequence" },
  { 0, NULL }
};

static const per_choice_t RasMessage_choice[] = {
  {   0, "gatekeeperRequest"           , ASN1_EXTENSION_ROOT    , dissect_gatekeeperRequest },
  {   1, "gatekeeperConfirm"           , ASN1_EXTENSION_ROOT    , dissect_gatekeeperConfirm },
  {   2, "gatekeeperReject"            , ASN1_EXTENSION_ROOT    , dissect_gatekeeperReject },
  {   3, "registrationRequest"         , ASN1_EXTENSION_ROOT    , dissect_registrationRequest },
  {   4, "registrationConfirm"         , ASN1_EXTENSION_ROOT    , dissect_registrationConfirm },
  {   5, "registrationReject"          , ASN1_EXTENSION_ROOT    , dissect_registrationReject },
  {   6, "unregistrationRequest"       , ASN1_EXTENSION_ROOT    , dissect_unregistrationRequest },
  {   7, "unregistrationConfirm"       , ASN1_EXTENSION_ROOT    , dissect_unregistrationConfirm },
  {   8, "unregistrationReject"        , ASN1_EXTENSION_ROOT    , dissect_unregistrationReject },
  {   9, "admissionRequest"            , ASN1_EXTENSION_ROOT    , dissect_admissionRequest },
  {  10, "admissionConfirm"            , ASN1_EXTENSION_ROOT    , dissect_admissionConfirm },
  {  11, "admissionReject"             , ASN1_EXTENSION_ROOT    , dissect_admissionReject },
  {  12, "bandwidthRequest"            , ASN1_EXTENSION_ROOT    , dissect_bandwidthRequest },
  {  13, "bandwidthConfirm"            , ASN1_EXTENSION_ROOT    , dissect_bandwidthConfirm },
  {  14, "bandwidthReject"             , ASN1_EXTENSION_ROOT    , dissect_bandwidthReject },
  {  15, "disengageRequest"            , ASN1_EXTENSION_ROOT    , dissect_disengageRequest },
  {  16, "disengageConfirm"            , ASN1_EXTENSION_ROOT    , dissect_disengageConfirm },
  {  17, "disengageReject"             , ASN1_EXTENSION_ROOT    , dissect_disengageReject },
  {  18, "locationRequest"             , ASN1_EXTENSION_ROOT    , dissect_locationRequest },
  {  19, "locationConfirm"             , ASN1_EXTENSION_ROOT    , dissect_locationConfirm },
  {  20, "locationReject"              , ASN1_EXTENSION_ROOT    , dissect_locationReject },
  {  21, "infoRequest"                 , ASN1_EXTENSION_ROOT    , dissect_infoRequest },
  {  22, "infoRequestResponse"         , ASN1_EXTENSION_ROOT    , dissect_infoRequestResponse },
  {  23, "nonStandardMessage"          , ASN1_EXTENSION_ROOT    , dissect_nonStandardMessage },
  {  24, "unknownMessageResponse"      , ASN1_EXTENSION_ROOT    , dissect_unknownMessageResponse },
  {  25, "requestInProgress"           , ASN1_NOT_EXTENSION_ROOT, dissect_requestInProgress },
  {  26, "resourcesAvailableIndicate"  , ASN1_NOT_EXTENSION_ROOT, dissect_resourcesAvailableIndicate },
  {  27, "resourcesAvailableConfirm"   , ASN1_NOT_EXTENSION_ROOT, dissect_resourcesAvailableConfirm },
  {  28, "infoRequestAck"              , ASN1_NOT_EXTENSION_ROOT, dissect_infoRequestAck },
  {  29, "infoRequestNak"              , ASN1_NOT_EXTENSION_ROOT, dissect_infoRequestNak },
  {  30, "serviceControlIndication"    , ASN1_NOT_EXTENSION_ROOT, dissect_serviceControlIndication },
  {  31, "serviceControlResponse"      , ASN1_NOT_EXTENSION_ROOT, dissect_serviceControlResponse },
  {  32, "admissionConfirmSequence"    , ASN1_NOT_EXTENSION_ROOT, dissect_admissionConfirmSequence },
  { 0, NULL, 0, NULL }
};

int
dissect_h225_RasMessage(tvbuff_t *tvb, int offset, asn_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 180 "h225.cnf"
  	guint32 rasmessage_value;

  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_h225_RasMessage, RasMessage_choice,
                                 &rasmessage_value);

	if (check_col(actx->pinfo->cinfo, COL_INFO)){
		col_add_fstr(actx->pinfo->cinfo, COL_INFO, "RAS: %s ",
			val_to_str(rasmessage_value, RasMessage_vals, "<unknown>"));
	}

	h225_pi->msg_tag = rasmessage_value;


  return offset;
}


/*--- End of included file: packet-h225-fn.c ---*/
#line 198 "packet-h225-template.c"


static int
dissect_h225_H323UserInformation(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *it;
	proto_tree *tr;
	int offset = 0;
	asn_ctx_t asn_ctx;

    pi_current++;
    if(pi_current==5){
      pi_current=0;
    }
    h225_pi=&pi_arr[pi_current];

	/* Init struct for collecting h225_packet_info */
    reset_h225_packet_info(h225_pi);
    h225_pi->msg_type = H225_CS;

	next_tvb_init(&h245_list);
	next_tvb_init(&tp_list);

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
	}
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_clear(pinfo->cinfo, COL_INFO);
	}

	it=proto_tree_add_protocol_format(tree, proto_h225, tvb, 0, tvb_length(tvb), PSNAME" CS");
	tr=proto_item_add_subtree(it, ett_h225);

	asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
	offset = dissect_h225_H323_UserInformation(tvb, offset, &asn_ctx, tr, hf_h225_H323_UserInformation);

	if (h245_list.count && check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_append_str(pinfo->cinfo, COL_PROTOCOL, "/");
		col_set_fence(pinfo->cinfo, COL_PROTOCOL);
	}

	next_tvb_call(&h245_list, pinfo, tree, h245dg_handle, data_handle);
	next_tvb_call(&tp_list, pinfo, tree, NULL, data_handle);

	tap_queue_packet(h225_tap, pinfo, h225_pi);

	return offset;
}
static int
dissect_h225_h225_RasMessage(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	proto_item *it;
	proto_tree *tr;
	guint32 offset=0;
	asn_ctx_t asn_ctx;

    pi_current++;
    if(pi_current==5){
        pi_current=0;
    }
    h225_pi=&pi_arr[pi_current];

	/* Init struct for collecting h225_packet_info */
    reset_h225_packet_info(h225_pi);
    h225_pi->msg_type = H225_RAS;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)){
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
	}

	it=proto_tree_add_protocol_format(tree, proto_h225, tvb, offset, tvb_length(tvb), PSNAME" RAS");
	tr=proto_item_add_subtree(it, ett_h225);

	asn_ctx_init(&asn_ctx, ASN_ENC_PER, TRUE, pinfo);
	offset = dissect_h225_RasMessage(tvb, 0, &asn_ctx, tr, hf_h225_RasMessage );

	ras_call_matching(tvb, pinfo, tr, h225_pi);

	tap_queue_packet(h225_tap, pinfo, h225_pi);

	return offset;
}

/*--- proto_register_h225 -------------------------------------------*/
void proto_register_h225(void) {

  /* List of fields */
  static hf_register_info hf[] = {
	{ &hf_h225_H323_UserInformation,
		{ "H323_UserInformation", "h225.H323_UserInformation", FT_NONE, BASE_NONE,
		NULL, 0, "H323_UserInformation sequence", HFILL }},
	{ &hf_h225_RasMessage,
		{ "RasMessage", "h225.RasMessage", FT_UINT32, BASE_DEC,
		VALS(RasMessage_vals), 0, "RasMessage choice", HFILL }},
	{ &hf_h221Manufacturer,
		{ "H.221 Manufacturer", "h221.Manufacturer", FT_UINT32, BASE_HEX,
		VALS(H221ManufacturerCode_vals), 0, "H.221 Manufacturer", HFILL }},
	{ &hf_h225_ras_req_frame,
      		{ "RAS Request Frame", "h225.ras.reqframe", FT_FRAMENUM, BASE_NONE,
      		NULL, 0, "RAS Request Frame", HFILL }},
  	{ &hf_h225_ras_rsp_frame,
      		{ "RAS Response Frame", "h225.ras.rspframe", FT_FRAMENUM, BASE_NONE,
      		NULL, 0, "RAS Response Frame", HFILL }},
  	{ &hf_h225_ras_dup,
      		{ "Duplicate RAS Message", "h225.ras.dup", FT_UINT32, BASE_DEC,
		NULL, 0, "Duplicate RAS Message", HFILL }},
  	{ &hf_h225_ras_deltatime,
      		{ "RAS Service Response Time", "h225.ras.timedelta", FT_RELATIVE_TIME, BASE_NONE,
      		NULL, 0, "Timedelta between RAS-Request and RAS-Response", HFILL }},
	{ &hf_h225_fastStart_item_length,
		{ "fastStart item length", "h225.fastStart_item_length", FT_UINT32, BASE_DEC,
		NULL, 0, "fastStart item length", HFILL }},


/*--- Included file: packet-h225-hfarr.c ---*/
#line 1 "packet-h225-hfarr.c"
    { &hf_h225_h323_uu_pdu,
      { "h323-uu-pdu", "h225.h323_uu_pdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UserInformation/h323-uu-pdu", HFILL }},
    { &hf_h225_user_data,
      { "user-data", "h225.user_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UserInformation/user-data", HFILL }},
    { &hf_h225_protocol_discriminator,
      { "protocol-discriminator", "h225.protocol_discriminator",
        FT_UINT32, BASE_DEC, VALS(q931_protocol_discriminator_vals), 0,
        "H323-UserInformation/user-data/protocol-discriminator", HFILL }},
    { &hf_h225_user_information,
      { "user-information", "h225.user_information",
        FT_BYTES, BASE_HEX, NULL, 0,
        "H323-UserInformation/user-data/user-information", HFILL }},
    { &hf_h225_h323_message_body,
      { "h323-message-body", "h225.h323_message_body",
        FT_UINT32, BASE_DEC, VALS(T_h323_message_body_vals), 0,
        "H323-UU-PDU/h323-message-body", HFILL }},
    { &hf_h225_setup,
      { "setup", "h225.setup",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/h323-message-body/setup", HFILL }},
    { &hf_h225_callProceeding,
      { "callProceeding", "h225.callProceeding",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/h323-message-body/callProceeding", HFILL }},
    { &hf_h225_connect,
      { "connect", "h225.connect",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/h323-message-body/connect", HFILL }},
    { &hf_h225_alerting,
      { "alerting", "h225.alerting",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/h323-message-body/alerting", HFILL }},
    { &hf_h225_information,
      { "information", "h225.information",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/h323-message-body/information", HFILL }},
    { &hf_h225_releaseComplete,
      { "releaseComplete", "h225.releaseComplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/h323-message-body/releaseComplete", HFILL }},
    { &hf_h225_facility,
      { "facility", "h225.facility",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/h323-message-body/facility", HFILL }},
    { &hf_h225_progress,
      { "progress", "h225.progress",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/h323-message-body/progress", HFILL }},
    { &hf_h225_empty_flg,
      { "empty", "h225.empty",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/h323-message-body/empty", HFILL }},
    { &hf_h225_status,
      { "status", "h225.status",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/h323-message-body/status", HFILL }},
    { &hf_h225_statusInquiry,
      { "statusInquiry", "h225.statusInquiry",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/h323-message-body/statusInquiry", HFILL }},
    { &hf_h225_setupAcknowledge,
      { "setupAcknowledge", "h225.setupAcknowledge",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/h323-message-body/setupAcknowledge", HFILL }},
    { &hf_h225_notify,
      { "notify", "h225.notify",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/h323-message-body/notify", HFILL }},
    { &hf_h225_nonStandardData,
      { "nonStandardData", "h225.nonStandardData",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_h4501SupplementaryService,
      { "h4501SupplementaryService", "h225.h4501SupplementaryService",
        FT_UINT32, BASE_DEC, NULL, 0,
        "H323-UU-PDU/h4501SupplementaryService", HFILL }},
    { &hf_h225_h4501SupplementaryService_item,
      { "Item", "h225.h4501SupplementaryService_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "H323-UU-PDU/h4501SupplementaryService/_item", HFILL }},
    { &hf_h225_h245Tunneling,
      { "h245Tunneling", "h225.h245Tunneling",
        FT_BOOLEAN, 8, NULL, 0,
        "H323-UU-PDU/h245Tunneling", HFILL }},
    { &hf_h225_h245Control,
      { "h245Control", "h225.h245Control",
        FT_UINT32, BASE_DEC, NULL, 0,
        "H323-UU-PDU/h245Control", HFILL }},
    { &hf_h225_nonStandardControl,
      { "nonStandardControl", "h225.nonStandardControl",
        FT_UINT32, BASE_DEC, NULL, 0,
        "H323-UU-PDU/nonStandardControl", HFILL }},
    { &hf_h225_nonStandardControl_item,
      { "Item", "h225.nonStandardControl_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/nonStandardControl/_item", HFILL }},
    { &hf_h225_callLinkage,
      { "callLinkage", "h225.callLinkage",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_tunnelledSignallingMessage,
      { "tunnelledSignallingMessage", "h225.tunnelledSignallingMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/tunnelledSignallingMessage", HFILL }},
    { &hf_h225_tunnelledProtocolID,
      { "tunnelledProtocolID", "h225.tunnelledProtocolID",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/tunnelledSignallingMessage/tunnelledProtocolID", HFILL }},
    { &hf_h225_messageContent,
      { "messageContent", "h225.messageContent",
        FT_UINT32, BASE_DEC, NULL, 0,
        "H323-UU-PDU/tunnelledSignallingMessage/messageContent", HFILL }},
    { &hf_h225_messageContent_item,
      { "Item", "h225.messageContent_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "H323-UU-PDU/tunnelledSignallingMessage/messageContent/_item", HFILL }},
    { &hf_h225_tunnellingRequired,
      { "tunnellingRequired", "h225.tunnellingRequired",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/tunnelledSignallingMessage/tunnellingRequired", HFILL }},
    { &hf_h225_provisionalRespToH245Tunneling,
      { "provisionalRespToH245Tunneling", "h225.provisionalRespToH245Tunneling",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/provisionalRespToH245Tunneling", HFILL }},
    { &hf_h225_stimulusControl,
      { "stimulusControl", "h225.stimulusControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "H323-UU-PDU/stimulusControl", HFILL }},
    { &hf_h225_genericData,
      { "genericData", "h225.genericData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_genericData_item,
      { "Item", "h225.genericData_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_H245Control_item,
      { "Item", "h225.H245Control_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "H245Control/_item", HFILL }},
    { &hf_h225_nonStandard,
      { "nonStandard", "h225.nonStandard",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_isText,
      { "isText", "h225.isText",
        FT_NONE, BASE_NONE, NULL, 0,
        "StimulusControl/isText", HFILL }},
    { &hf_h225_h248Message,
      { "h248Message", "h225.h248Message",
        FT_BYTES, BASE_HEX, NULL, 0,
        "StimulusControl/h248Message", HFILL }},
    { &hf_h225_protocolIdentifier,
      { "protocolIdentifier", "h225.protocolIdentifier",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_uUIE_destinationInfo,
      { "destinationInfo", "h225.destinationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_h245Address,
      { "h245Address", "h225.h245Address",
        FT_UINT32, BASE_DEC, VALS(h225_H245TransportAddress_vals), 0,
        "", HFILL }},
    { &hf_h225_callIdentifier,
      { "callIdentifier", "h225.callIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_h245SecurityMode,
      { "h245SecurityMode", "h225.h245SecurityMode",
        FT_UINT32, BASE_DEC, VALS(h225_H245Security_vals), 0,
        "", HFILL }},
    { &hf_h225_tokens,
      { "tokens", "h225.tokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_tokens_item,
      { "Item", "h225.tokens_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_cryptoTokens,
      { "cryptoTokens", "h225.cryptoTokens",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_cryptoTokens_item,
      { "Item", "h225.cryptoTokens_item",
        FT_UINT32, BASE_DEC, VALS(h225_CryptoH323Token_vals), 0,
        "", HFILL }},
    { &hf_h225_fastStart,
      { "fastStart", "h225.fastStart",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_multipleCalls,
      { "multipleCalls", "h225.multipleCalls",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_h225_maintainConnection,
      { "maintainConnection", "h225.maintainConnection",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_h225_alertingAddress,
      { "alertingAddress", "h225.alertingAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Alerting-UUIE/alertingAddress", HFILL }},
    { &hf_h225_alertingAddress_item,
      { "Item", "h225.alertingAddress_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "Alerting-UUIE/alertingAddress/_item", HFILL }},
    { &hf_h225_presentationIndicator,
      { "presentationIndicator", "h225.presentationIndicator",
        FT_UINT32, BASE_DEC, VALS(h225_PresentationIndicator_vals), 0,
        "", HFILL }},
    { &hf_h225_screeningIndicator,
      { "screeningIndicator", "h225.screeningIndicator",
        FT_UINT32, BASE_DEC, VALS(h225_ScreeningIndicator_vals), 0,
        "", HFILL }},
    { &hf_h225_fastConnectRefused,
      { "fastConnectRefused", "h225.fastConnectRefused",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_serviceControl,
      { "serviceControl", "h225.serviceControl",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_serviceControl_item,
      { "Item", "h225.serviceControl_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_capacity,
      { "capacity", "h225.capacity",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_featureSet,
      { "featureSet", "h225.featureSet",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_conferenceID,
      { "conferenceID", "h225.conferenceID",
        FT_GUID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_language,
      { "language", "h225.language",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_language_item,
      { "Item", "h225.language_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_connectedAddress,
      { "connectedAddress", "h225.connectedAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Connect-UUIE/connectedAddress", HFILL }},
    { &hf_h225_connectedAddress_item,
      { "Item", "h225.connectedAddress_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "Connect-UUIE/connectedAddress/_item", HFILL }},
    { &hf_h225_circuitInfo,
      { "circuitInfo", "h225.circuitInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_releaseCompleteReason,
      { "reason", "h225.reason",
        FT_UINT32, BASE_DEC, VALS(ReleaseCompleteReason_vals), 0,
        "", HFILL }},
    { &hf_h225_busyAddress,
      { "busyAddress", "h225.busyAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ReleaseComplete-UUIE/busyAddress", HFILL }},
    { &hf_h225_busyAddress_item,
      { "Item", "h225.busyAddress_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "ReleaseComplete-UUIE/busyAddress/_item", HFILL }},
    { &hf_h225_noBandwidth,
      { "noBandwidth", "h225.noBandwidth",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/noBandwidth", HFILL }},
    { &hf_h225_gatekeeperResources,
      { "gatekeeperResources", "h225.gatekeeperResources",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/gatekeeperResources", HFILL }},
    { &hf_h225_unreachableDestination,
      { "unreachableDestination", "h225.unreachableDestination",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/unreachableDestination", HFILL }},
    { &hf_h225_destinationRejection,
      { "destinationRejection", "h225.destinationRejection",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/destinationRejection", HFILL }},
    { &hf_h225_invalidRevision,
      { "invalidRevision", "h225.invalidRevision",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_noPermission,
      { "noPermission", "h225.noPermission",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/noPermission", HFILL }},
    { &hf_h225_unreachableGatekeeper,
      { "unreachableGatekeeper", "h225.unreachableGatekeeper",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/unreachableGatekeeper", HFILL }},
    { &hf_h225_gatewayResources,
      { "gatewayResources", "h225.gatewayResources",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/gatewayResources", HFILL }},
    { &hf_h225_badFormatAddress,
      { "badFormatAddress", "h225.badFormatAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/badFormatAddress", HFILL }},
    { &hf_h225_adaptiveBusy,
      { "adaptiveBusy", "h225.adaptiveBusy",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/adaptiveBusy", HFILL }},
    { &hf_h225_inConf,
      { "inConf", "h225.inConf",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/inConf", HFILL }},
    { &hf_h225_undefinedReason,
      { "undefinedReason", "h225.undefinedReason",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_facilityCallDeflection,
      { "facilityCallDeflection", "h225.facilityCallDeflection",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/facilityCallDeflection", HFILL }},
    { &hf_h225_securityDenied,
      { "securityDenied", "h225.securityDenied",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/securityDenied", HFILL }},
    { &hf_h225_calledPartyNotRegistered,
      { "calledPartyNotRegistered", "h225.calledPartyNotRegistered",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_callerNotRegistered,
      { "callerNotRegistered", "h225.callerNotRegistered",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_newConnectionNeeded,
      { "newConnectionNeeded", "h225.newConnectionNeeded",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/newConnectionNeeded", HFILL }},
    { &hf_h225_nonStandardReason,
      { "nonStandardReason", "h225.nonStandardReason",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/nonStandardReason", HFILL }},
    { &hf_h225_replaceWithConferenceInvite,
      { "replaceWithConferenceInvite", "h225.replaceWithConferenceInvite",
        FT_GUID, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/replaceWithConferenceInvite", HFILL }},
    { &hf_h225_genericDataReason,
      { "genericDataReason", "h225.genericDataReason",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_neededFeatureNotSupported,
      { "neededFeatureNotSupported", "h225.neededFeatureNotSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_tunnelledSignallingRejected,
      { "tunnelledSignallingRejected", "h225.tunnelledSignallingRejected",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/tunnelledSignallingRejected", HFILL }},
    { &hf_h225_invalidCID,
      { "invalidCID", "h225.invalidCID",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReleaseCompleteReason/invalidCID", HFILL }},
    { &hf_h225_rLC_securityError,
      { "securityError", "h225.securityError",
        FT_UINT32, BASE_DEC, VALS(h225_SecurityErrors_vals), 0,
        "ReleaseCompleteReason/securityError", HFILL }},
    { &hf_h225_hopCountExceeded,
      { "hopCountExceeded", "h225.hopCountExceeded",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_sourceAddress,
      { "sourceAddress", "h225.sourceAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Setup-UUIE/sourceAddress", HFILL }},
    { &hf_h225_sourceAddress_item,
      { "Item", "h225.sourceAddress_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "Setup-UUIE/sourceAddress/_item", HFILL }},
    { &hf_h225_setup_UUIE_sourceInfo,
      { "sourceInfo", "h225.sourceInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "Setup-UUIE/sourceInfo", HFILL }},
    { &hf_h225_destinationAddress,
      { "destinationAddress", "h225.destinationAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Setup-UUIE/destinationAddress", HFILL }},
    { &hf_h225_destinationAddress_item,
      { "Item", "h225.destinationAddress_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "Setup-UUIE/destinationAddress/_item", HFILL }},
    { &hf_h225_destCallSignalAddress,
      { "destCallSignalAddress", "h225.destCallSignalAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "", HFILL }},
    { &hf_h225_destExtraCallInfo,
      { "destExtraCallInfo", "h225.destExtraCallInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_destExtraCallInfo_item,
      { "Item", "h225.destExtraCallInfo_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "", HFILL }},
    { &hf_h225_destExtraCRV,
      { "destExtraCRV", "h225.destExtraCRV",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Setup-UUIE/destExtraCRV", HFILL }},
    { &hf_h225_destExtraCRV_item,
      { "Item", "h225.destExtraCRV_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Setup-UUIE/destExtraCRV/_item", HFILL }},
    { &hf_h225_activeMC,
      { "activeMC", "h225.activeMC",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_h225_conferenceGoal,
      { "conferenceGoal", "h225.conferenceGoal",
        FT_UINT32, BASE_DEC, VALS(h225_T_conferenceGoal_vals), 0,
        "Setup-UUIE/conferenceGoal", HFILL }},
    { &hf_h225_create,
      { "create", "h225.create",
        FT_NONE, BASE_NONE, NULL, 0,
        "Setup-UUIE/conferenceGoal/create", HFILL }},
    { &hf_h225_join,
      { "join", "h225.join",
        FT_NONE, BASE_NONE, NULL, 0,
        "Setup-UUIE/conferenceGoal/join", HFILL }},
    { &hf_h225_invite,
      { "invite", "h225.invite",
        FT_NONE, BASE_NONE, NULL, 0,
        "Setup-UUIE/conferenceGoal/invite", HFILL }},
    { &hf_h225_capability_negotiation,
      { "capability-negotiation", "h225.capability_negotiation",
        FT_NONE, BASE_NONE, NULL, 0,
        "Setup-UUIE/conferenceGoal/capability-negotiation", HFILL }},
    { &hf_h225_callIndependentSupplementaryService,
      { "callIndependentSupplementaryService", "h225.callIndependentSupplementaryService",
        FT_NONE, BASE_NONE, NULL, 0,
        "Setup-UUIE/conferenceGoal/callIndependentSupplementaryService", HFILL }},
    { &hf_h225_callServices,
      { "callServices", "h225.callServices",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_callType,
      { "callType", "h225.callType",
        FT_UINT32, BASE_DEC, VALS(h225_CallType_vals), 0,
        "", HFILL }},
    { &hf_h225_sourceCallSignalAddress,
      { "sourceCallSignalAddress", "h225.sourceCallSignalAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "Setup-UUIE/sourceCallSignalAddress", HFILL }},
    { &hf_h225_uUIE_remoteExtensionAddress,
      { "remoteExtensionAddress", "h225.remoteExtensionAddress",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "", HFILL }},
    { &hf_h225_h245SecurityCapability,
      { "h245SecurityCapability", "h225.h245SecurityCapability",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Setup-UUIE/h245SecurityCapability", HFILL }},
    { &hf_h225_h245SecurityCapability_item,
      { "Item", "h225.h245SecurityCapability_item",
        FT_UINT32, BASE_DEC, VALS(h225_H245Security_vals), 0,
        "Setup-UUIE/h245SecurityCapability/_item", HFILL }},
    { &hf_h225_mediaWaitForConnect,
      { "mediaWaitForConnect", "h225.mediaWaitForConnect",
        FT_BOOLEAN, 8, NULL, 0,
        "Setup-UUIE/mediaWaitForConnect", HFILL }},
    { &hf_h225_canOverlapSend,
      { "canOverlapSend", "h225.canOverlapSend",
        FT_BOOLEAN, 8, NULL, 0,
        "Setup-UUIE/canOverlapSend", HFILL }},
    { &hf_h225_endpointIdentifier,
      { "endpointIdentifier", "h225.endpointIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_connectionParameters,
      { "connectionParameters", "h225.connectionParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "Setup-UUIE/connectionParameters", HFILL }},
    { &hf_h225_connectionType,
      { "connectionType", "h225.connectionType",
        FT_UINT32, BASE_DEC, VALS(h225_ScnConnectionType_vals), 0,
        "Setup-UUIE/connectionParameters/connectionType", HFILL }},
    { &hf_h225_numberOfScnConnections,
      { "numberOfScnConnections", "h225.numberOfScnConnections",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Setup-UUIE/connectionParameters/numberOfScnConnections", HFILL }},
    { &hf_h225_connectionAggregation,
      { "connectionAggregation", "h225.connectionAggregation",
        FT_UINT32, BASE_DEC, VALS(h225_ScnConnectionAggregation_vals), 0,
        "Setup-UUIE/connectionParameters/connectionAggregation", HFILL }},
    { &hf_h225_symmetricOperationRequired,
      { "symmetricOperationRequired", "h225.symmetricOperationRequired",
        FT_NONE, BASE_NONE, NULL, 0,
        "Setup-UUIE/symmetricOperationRequired", HFILL }},
    { &hf_h225_desiredProtocols,
      { "desiredProtocols", "h225.desiredProtocols",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_desiredProtocols_item,
      { "Item", "h225.desiredProtocols_item",
        FT_UINT32, BASE_DEC, VALS(h225_SupportedProtocols_vals), 0,
        "", HFILL }},
    { &hf_h225_neededFeatures,
      { "neededFeatures", "h225.neededFeatures",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_neededFeatures_item,
      { "Item", "h225.neededFeatures_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_desiredFeatures,
      { "desiredFeatures", "h225.desiredFeatures",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_desiredFeatures_item,
      { "Item", "h225.desiredFeatures_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_supportedFeatures,
      { "supportedFeatures", "h225.supportedFeatures",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_supportedFeatures_item,
      { "Item", "h225.supportedFeatures_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_parallelH245Control,
      { "parallelH245Control", "h225.parallelH245Control",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Setup-UUIE/parallelH245Control", HFILL }},
    { &hf_h225_additionalSourceAddresses,
      { "additionalSourceAddresses", "h225.additionalSourceAddresses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Setup-UUIE/additionalSourceAddresses", HFILL }},
    { &hf_h225_additionalSourceAddresses_item,
      { "Item", "h225.additionalSourceAddresses_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Setup-UUIE/additionalSourceAddresses/_item", HFILL }},
    { &hf_h225_hopCount_1_31,
      { "hopCount", "h225.hopCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Setup-UUIE/hopCount", HFILL }},
    { &hf_h225_ParallelH245Control_item,
      { "Item", "h225.ParallelH245Control_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ParallelH245Control/_item", HFILL }},
    { &hf_h225_unknown,
      { "unknown", "h225.unknown",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_bChannel,
      { "bChannel", "h225.bChannel",
        FT_NONE, BASE_NONE, NULL, 0,
        "ScnConnectionType/bChannel", HFILL }},
    { &hf_h225_hybrid2x64,
      { "hybrid2x64", "h225.hybrid2x64",
        FT_NONE, BASE_NONE, NULL, 0,
        "ScnConnectionType/hybrid2x64", HFILL }},
    { &hf_h225_hybrid384,
      { "hybrid384", "h225.hybrid384",
        FT_NONE, BASE_NONE, NULL, 0,
        "ScnConnectionType/hybrid384", HFILL }},
    { &hf_h225_hybrid1536,
      { "hybrid1536", "h225.hybrid1536",
        FT_NONE, BASE_NONE, NULL, 0,
        "ScnConnectionType/hybrid1536", HFILL }},
    { &hf_h225_hybrid1920,
      { "hybrid1920", "h225.hybrid1920",
        FT_NONE, BASE_NONE, NULL, 0,
        "ScnConnectionType/hybrid1920", HFILL }},
    { &hf_h225_multirate,
      { "multirate", "h225.multirate",
        FT_NONE, BASE_NONE, NULL, 0,
        "ScnConnectionType/multirate", HFILL }},
    { &hf_h225_auto,
      { "auto", "h225.auto",
        FT_NONE, BASE_NONE, NULL, 0,
        "ScnConnectionAggregation/auto", HFILL }},
    { &hf_h225_none,
      { "none", "h225.none",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_h221,
      { "h221", "h225.h221",
        FT_NONE, BASE_NONE, NULL, 0,
        "ScnConnectionAggregation/h221", HFILL }},
    { &hf_h225_bonded_mode1,
      { "bonded-mode1", "h225.bonded_mode1",
        FT_NONE, BASE_NONE, NULL, 0,
        "ScnConnectionAggregation/bonded-mode1", HFILL }},
    { &hf_h225_bonded_mode2,
      { "bonded-mode2", "h225.bonded_mode2",
        FT_NONE, BASE_NONE, NULL, 0,
        "ScnConnectionAggregation/bonded-mode2", HFILL }},
    { &hf_h225_bonded_mode3,
      { "bonded-mode3", "h225.bonded_mode3",
        FT_NONE, BASE_NONE, NULL, 0,
        "ScnConnectionAggregation/bonded-mode3", HFILL }},
    { &hf_h225_presentationAllowed,
      { "presentationAllowed", "h225.presentationAllowed",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentationIndicator/presentationAllowed", HFILL }},
    { &hf_h225_presentationRestricted,
      { "presentationRestricted", "h225.presentationRestricted",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentationIndicator/presentationRestricted", HFILL }},
    { &hf_h225_addressNotAvailable,
      { "addressNotAvailable", "h225.addressNotAvailable",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentationIndicator/addressNotAvailable", HFILL }},
    { &hf_h225_alternativeAddress,
      { "alternativeAddress", "h225.alternativeAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "Facility-UUIE/alternativeAddress", HFILL }},
    { &hf_h225_alternativeAliasAddress,
      { "alternativeAliasAddress", "h225.alternativeAliasAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Facility-UUIE/alternativeAliasAddress", HFILL }},
    { &hf_h225_alternativeAliasAddress_item,
      { "Item", "h225.alternativeAliasAddress_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "Facility-UUIE/alternativeAliasAddress/_item", HFILL }},
    { &hf_h225_facilityReason,
      { "reason", "h225.reason",
        FT_UINT32, BASE_DEC, VALS(FacilityReason_vals), 0,
        "Facility-UUIE/reason", HFILL }},
    { &hf_h225_conferences,
      { "conferences", "h225.conferences",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Facility-UUIE/conferences", HFILL }},
    { &hf_h225_conferences_item,
      { "Item", "h225.conferences_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Facility-UUIE/conferences/_item", HFILL }},
    { &hf_h225_conferenceAlias,
      { "conferenceAlias", "h225.conferenceAlias",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "ConferenceList/conferenceAlias", HFILL }},
    { &hf_h225_routeCallToGatekeeper,
      { "routeCallToGatekeeper", "h225.routeCallToGatekeeper",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_callForwarded,
      { "callForwarded", "h225.callForwarded",
        FT_NONE, BASE_NONE, NULL, 0,
        "FacilityReason/callForwarded", HFILL }},
    { &hf_h225_routeCallToMC,
      { "routeCallToMC", "h225.routeCallToMC",
        FT_NONE, BASE_NONE, NULL, 0,
        "FacilityReason/routeCallToMC", HFILL }},
    { &hf_h225_conferenceListChoice,
      { "conferenceListChoice", "h225.conferenceListChoice",
        FT_NONE, BASE_NONE, NULL, 0,
        "FacilityReason/conferenceListChoice", HFILL }},
    { &hf_h225_startH245,
      { "startH245", "h225.startH245",
        FT_NONE, BASE_NONE, NULL, 0,
        "FacilityReason/startH245", HFILL }},
    { &hf_h225_noH245,
      { "noH245", "h225.noH245",
        FT_NONE, BASE_NONE, NULL, 0,
        "FacilityReason/noH245", HFILL }},
    { &hf_h225_newTokens,
      { "newTokens", "h225.newTokens",
        FT_NONE, BASE_NONE, NULL, 0,
        "FacilityReason/newTokens", HFILL }},
    { &hf_h225_featureSetUpdate,
      { "featureSetUpdate", "h225.featureSetUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        "FacilityReason/featureSetUpdate", HFILL }},
    { &hf_h225_forwardedElements,
      { "forwardedElements", "h225.forwardedElements",
        FT_NONE, BASE_NONE, NULL, 0,
        "FacilityReason/forwardedElements", HFILL }},
    { &hf_h225_transportedInformation,
      { "transportedInformation", "h225.transportedInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "FacilityReason/transportedInformation", HFILL }},
    { &hf_h225_FastStart_item,
      { "Item", "h225.FastStart_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FastStart/_item", HFILL }},
    { &hf_h225_ipAddress,
      { "ipAddress", "h225.ipAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransportAddress/ipAddress", HFILL }},
    { &hf_h225_ipV4,
      { "ip", "h225.ip",
        FT_IPv4, BASE_NONE, NULL, 0,
        "TransportAddress/ipAddress/ip", HFILL }},
    { &hf_h225_ipV4_port,
      { "port", "h225.port",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TransportAddress/ipAddress/port", HFILL }},
    { &hf_h225_ipSourceRoute,
      { "ipSourceRoute", "h225.ipSourceRoute",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransportAddress/ipSourceRoute", HFILL }},
    { &hf_h225_src_route_ipV4,
      { "ip", "h225.ip",
        FT_BYTES, BASE_HEX, NULL, 0,
        "TransportAddress/ipSourceRoute/ip", HFILL }},
    { &hf_h225_ipV4_src_port,
      { "port", "h225.port",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TransportAddress/ipSourceRoute/port", HFILL }},
    { &hf_h225_route,
      { "route", "h225.route",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TransportAddress/ipSourceRoute/route", HFILL }},
    { &hf_h225_route_item,
      { "Item", "h225.route_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "TransportAddress/ipSourceRoute/route/_item", HFILL }},
    { &hf_h225_routing,
      { "routing", "h225.routing",
        FT_UINT32, BASE_DEC, VALS(h225_T_routing_vals), 0,
        "TransportAddress/ipSourceRoute/routing", HFILL }},
    { &hf_h225_strict,
      { "strict", "h225.strict",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_loose,
      { "loose", "h225.loose",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_ipxAddress,
      { "ipxAddress", "h225.ipxAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransportAddress/ipxAddress", HFILL }},
    { &hf_h225_node,
      { "node", "h225.node",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_h225_netnum,
      { "netnum", "h225.netnum",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_h225_ipx_port,
      { "port", "h225.port",
        FT_BYTES, BASE_HEX, NULL, 0,
        "TransportAddress/ipxAddress/port", HFILL }},
    { &hf_h225_ip6Address,
      { "ip6Address", "h225.ip6Address",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransportAddress/ip6Address", HFILL }},
    { &hf_h225_ipV6,
      { "ip", "h225.ip",
        FT_IPv6, BASE_NONE, NULL, 0,
        "TransportAddress/ip6Address/ip", HFILL }},
    { &hf_h225_ipV6_port,
      { "port", "h225.port",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TransportAddress/ip6Address/port", HFILL }},
    { &hf_h225_netBios,
      { "netBios", "h225.netBios",
        FT_BYTES, BASE_HEX, NULL, 0,
        "TransportAddress/netBios", HFILL }},
    { &hf_h225_nsap,
      { "nsap", "h225.nsap",
        FT_BYTES, BASE_HEX, NULL, 0,
        "TransportAddress/nsap", HFILL }},
    { &hf_h225_nonStandardAddress,
      { "nonStandardAddress", "h225.nonStandardAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_h245ipAddress,
      { "h245ipAddress", "h225.h245ipAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "H245TransportAddress/h245ipAddress", HFILL }},
    { &hf_h225_h245ipv4,
      { "h245ipv4", "h225.h245ipv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        "H245TransportAddress/h245ipAddress/h245ipv4", HFILL }},
    { &hf_h225_h245ipv4port,
      { "h245ipv4port", "h225.h245ipv4port",
        FT_UINT32, BASE_DEC, NULL, 0,
        "H245TransportAddress/h245ipAddress/h245ipv4port", HFILL }},
    { &hf_h225_h245ipSourceRoute,
      { "h245ipSourceRoute", "h225.h245ipSourceRoute",
        FT_NONE, BASE_NONE, NULL, 0,
        "H245TransportAddress/h245ipSourceRoute", HFILL }},
    { &hf_h225_h245routeip,
      { "h245routeip", "h225.h245routeip",
        FT_BYTES, BASE_HEX, NULL, 0,
        "H245TransportAddress/h245ipSourceRoute/h245routeip", HFILL }},
    { &hf_h225_h245routeport,
      { "h245routeport", "h225.h245routeport",
        FT_UINT32, BASE_DEC, NULL, 0,
        "H245TransportAddress/h245ipSourceRoute/h245routeport", HFILL }},
    { &hf_h225_h245route,
      { "h245route", "h225.h245route",
        FT_UINT32, BASE_DEC, NULL, 0,
        "H245TransportAddress/h245ipSourceRoute/h245route", HFILL }},
    { &hf_h225_h245route_item,
      { "Item", "h225.h245route_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "H245TransportAddress/h245ipSourceRoute/h245route/_item", HFILL }},
    { &hf_h225_h245routing,
      { "h245routing", "h225.h245routing",
        FT_UINT32, BASE_DEC, VALS(h225_T_h245routing_vals), 0,
        "H245TransportAddress/h245ipSourceRoute/h245routing", HFILL }},
    { &hf_h225_h245ipxAddress,
      { "h245ipxAddress", "h225.h245ipxAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "H245TransportAddress/h245ipxAddress", HFILL }},
    { &hf_h225_h245ipxport,
      { "h245ipxport", "h225.h245ipxport",
        FT_BYTES, BASE_HEX, NULL, 0,
        "H245TransportAddress/h245ipxAddress/h245ipxport", HFILL }},
    { &hf_h225_h245ip6Address,
      { "h245ip6Address", "h225.h245ip6Address",
        FT_NONE, BASE_NONE, NULL, 0,
        "H245TransportAddress/h245ip6Address", HFILL }},
    { &hf_h225_h245ipv6,
      { "h245ipv6", "h225.h245ipv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        "H245TransportAddress/h245ip6Address/h245ipv6", HFILL }},
    { &hf_h225_h245ipv6port,
      { "h245ipv6port", "h225.h245ipv6port",
        FT_UINT32, BASE_DEC, NULL, 0,
        "H245TransportAddress/h245ip6Address/h245ipv6port", HFILL }},
    { &hf_h225_h245netBios,
      { "h245netBios", "h225.h245netBios",
        FT_BYTES, BASE_HEX, NULL, 0,
        "H245TransportAddress/h245netBios", HFILL }},
    { &hf_h225_h245nsap,
      { "h245nsap", "h225.h245nsap",
        FT_BYTES, BASE_HEX, NULL, 0,
        "H245TransportAddress/h245nsap", HFILL }},
    { &hf_h225_vendor,
      { "vendor", "h225.vendor",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointType/vendor", HFILL }},
    { &hf_h225_gatekeeper,
      { "gatekeeper", "h225.gatekeeper",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointType/gatekeeper", HFILL }},
    { &hf_h225_gateway,
      { "gateway", "h225.gateway",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointType/gateway", HFILL }},
    { &hf_h225_mcu,
      { "mcu", "h225.mcu",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointType/mcu", HFILL }},
    { &hf_h225_terminal,
      { "terminal", "h225.terminal",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointType/terminal", HFILL }},
    { &hf_h225_mc,
      { "mc", "h225.mc",
        FT_BOOLEAN, 8, NULL, 0,
        "EndpointType/mc", HFILL }},
    { &hf_h225_undefinedNode,
      { "undefinedNode", "h225.undefinedNode",
        FT_BOOLEAN, 8, NULL, 0,
        "EndpointType/undefinedNode", HFILL }},
    { &hf_h225_set,
      { "set", "h225.set",
        FT_BYTES, BASE_HEX, NULL, 0,
        "EndpointType/set", HFILL }},
    { &hf_h225_supportedTunnelledProtocols,
      { "supportedTunnelledProtocols", "h225.supportedTunnelledProtocols",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EndpointType/supportedTunnelledProtocols", HFILL }},
    { &hf_h225_supportedTunnelledProtocols_item,
      { "Item", "h225.supportedTunnelledProtocols_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "EndpointType/supportedTunnelledProtocols/_item", HFILL }},
    { &hf_h225_protocol,
      { "protocol", "h225.protocol",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_protocol_item,
      { "Item", "h225.protocol_item",
        FT_UINT32, BASE_DEC, VALS(h225_SupportedProtocols_vals), 0,
        "", HFILL }},
    { &hf_h225_h310,
      { "h310", "h225.h310",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupportedProtocols/h310", HFILL }},
    { &hf_h225_h320,
      { "h320", "h225.h320",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupportedProtocols/h320", HFILL }},
    { &hf_h225_h321,
      { "h321", "h225.h321",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupportedProtocols/h321", HFILL }},
    { &hf_h225_h322,
      { "h322", "h225.h322",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupportedProtocols/h322", HFILL }},
    { &hf_h225_h323,
      { "h323", "h225.h323",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupportedProtocols/h323", HFILL }},
    { &hf_h225_h324,
      { "h324", "h225.h324",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupportedProtocols/h324", HFILL }},
    { &hf_h225_voice,
      { "voice", "h225.voice",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupportedProtocols/voice", HFILL }},
    { &hf_h225_t120_only,
      { "t120-only", "h225.t120_only",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupportedProtocols/t120-only", HFILL }},
    { &hf_h225_nonStandardProtocol,
      { "nonStandardProtocol", "h225.nonStandardProtocol",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupportedProtocols/nonStandardProtocol", HFILL }},
    { &hf_h225_t38FaxAnnexbOnly,
      { "t38FaxAnnexbOnly", "h225.t38FaxAnnexbOnly",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupportedProtocols/t38FaxAnnexbOnly", HFILL }},
    { &hf_h225_sip,
      { "sip", "h225.sip",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupportedProtocols/sip", HFILL }},
    { &hf_h225_dataRatesSupported,
      { "dataRatesSupported", "h225.dataRatesSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_dataRatesSupported_item,
      { "Item", "h225.dataRatesSupported_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_supportedPrefixes,
      { "supportedPrefixes", "h225.supportedPrefixes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_supportedPrefixes_item,
      { "Item", "h225.supportedPrefixes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_t38FaxProtocol,
      { "t38FaxProtocol", "h225.t38FaxProtocol",
        FT_UINT32, BASE_DEC, VALS(DataProtocolCapability_vals), 0,
        "T38FaxAnnexbOnlyCaps/t38FaxProtocol", HFILL }},
    { &hf_h225_t38FaxProfile,
      { "t38FaxProfile", "h225.t38FaxProfile",
        FT_NONE, BASE_NONE, NULL, 0,
        "T38FaxAnnexbOnlyCaps/t38FaxProfile", HFILL }},
    { &hf_h225_vendorIdentifier_vendor,
      { "vendor", "h225.vendor",
        FT_NONE, BASE_NONE, NULL, 0,
        "VendorIdentifier/vendor", HFILL }},
    { &hf_h225_productId,
      { "productId", "h225.productId",
        FT_STRING, BASE_HEX, NULL, 0,
        "VendorIdentifier/productId", HFILL }},
    { &hf_h225_versionId,
      { "versionId", "h225.versionId",
        FT_STRING, BASE_HEX, NULL, 0,
        "VendorIdentifier/versionId", HFILL }},
    { &hf_h225_enterpriseNumber,
      { "enterpriseNumber", "h225.enterpriseNumber",
        FT_OID, BASE_NONE, NULL, 0,
        "VendorIdentifier/enterpriseNumber", HFILL }},
    { &hf_h225_t35CountryCode,
      { "t35CountryCode", "h225.t35CountryCode",
        FT_UINT32, BASE_DEC, VALS(T35CountryCode_vals), 0,
        "H221NonStandard/t35CountryCode", HFILL }},
    { &hf_h225_t35Extension,
      { "t35Extension", "h225.t35Extension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "H221NonStandard/t35Extension", HFILL }},
    { &hf_h225_manufacturerCode,
      { "manufacturerCode", "h225.manufacturerCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "H221NonStandard/manufacturerCode", HFILL }},
    { &hf_h225_tunnelledProtocol_id,
      { "id", "h225.id",
        FT_UINT32, BASE_DEC, VALS(h225_TunnelledProtocol_id_vals), 0,
        "TunnelledProtocol/id", HFILL }},
    { &hf_h225_tunnelledProtocolObjectID,
      { "tunnelledProtocolObjectID", "h225.tunnelledProtocolObjectID",
        FT_OID, BASE_NONE, NULL, 0,
        "TunnelledProtocol/id/tunnelledProtocolObjectID", HFILL }},
    { &hf_h225_tunnelledProtocolAlternateID,
      { "tunnelledProtocolAlternateID", "h225.tunnelledProtocolAlternateID",
        FT_NONE, BASE_NONE, NULL, 0,
        "TunnelledProtocol/id/tunnelledProtocolAlternateID", HFILL }},
    { &hf_h225_subIdentifier,
      { "subIdentifier", "h225.subIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "TunnelledProtocol/subIdentifier", HFILL }},
    { &hf_h225_protocolType,
      { "protocolType", "h225.protocolType",
        FT_STRING, BASE_NONE, NULL, 0,
        "TunnelledProtocolAlternateIdentifier/protocolType", HFILL }},
    { &hf_h225_protocolVariant,
      { "protocolVariant", "h225.protocolVariant",
        FT_STRING, BASE_NONE, NULL, 0,
        "TunnelledProtocolAlternateIdentifier/protocolVariant", HFILL }},
    { &hf_h225_nonStandardIdentifier,
      { "nonStandardIdentifier", "h225.nonStandardIdentifier",
        FT_UINT32, BASE_DEC, VALS(h225_NonStandardIdentifier_vals), 0,
        "NonStandardParameter/nonStandardIdentifier", HFILL }},
    { &hf_h225_nsp_data,
      { "data", "h225.data",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NonStandardParameter/data", HFILL }},
    { &hf_h225_nsiOID,
      { "object", "h225.object",
        FT_OID, BASE_NONE, NULL, 0,
        "NonStandardIdentifier/object", HFILL }},
    { &hf_h225_h221NonStandard,
      { "h221NonStandard", "h225.h221NonStandard",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonStandardIdentifier/h221NonStandard", HFILL }},
    { &hf_h225_dialedDigits,
      { "dialedDigits", "h225.dialedDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "AliasAddress/dialedDigits", HFILL }},
    { &hf_h225_h323_ID,
      { "h323-ID", "h225.h323_ID",
        FT_STRING, BASE_NONE, NULL, 0,
        "AliasAddress/h323-ID", HFILL }},
    { &hf_h225_url_ID,
      { "url-ID", "h225.url_ID",
        FT_STRING, BASE_NONE, NULL, 0,
        "AliasAddress/url-ID", HFILL }},
    { &hf_h225_transportID,
      { "transportID", "h225.transportID",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "AliasAddress/transportID", HFILL }},
    { &hf_h225_email_ID,
      { "email-ID", "h225.email_ID",
        FT_STRING, BASE_NONE, NULL, 0,
        "AliasAddress/email-ID", HFILL }},
    { &hf_h225_partyNumber,
      { "partyNumber", "h225.partyNumber",
        FT_UINT32, BASE_DEC, VALS(h225_PartyNumber_vals), 0,
        "AliasAddress/partyNumber", HFILL }},
    { &hf_h225_mobileUIM,
      { "mobileUIM", "h225.mobileUIM",
        FT_UINT32, BASE_DEC, VALS(h225_MobileUIM_vals), 0,
        "AliasAddress/mobileUIM", HFILL }},
    { &hf_h225_wildcard,
      { "wildcard", "h225.wildcard",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AddressPattern/wildcard", HFILL }},
    { &hf_h225_range,
      { "range", "h225.range",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressPattern/range", HFILL }},
    { &hf_h225_startOfRange,
      { "startOfRange", "h225.startOfRange",
        FT_UINT32, BASE_DEC, VALS(h225_PartyNumber_vals), 0,
        "AddressPattern/range/startOfRange", HFILL }},
    { &hf_h225_endOfRange,
      { "endOfRange", "h225.endOfRange",
        FT_UINT32, BASE_DEC, VALS(h225_PartyNumber_vals), 0,
        "AddressPattern/range/endOfRange", HFILL }},
    { &hf_h225_e164Number,
      { "e164Number", "h225.e164Number",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyNumber/e164Number", HFILL }},
    { &hf_h225_dataPartyNumber,
      { "dataPartyNumber", "h225.dataPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "PartyNumber/dataPartyNumber", HFILL }},
    { &hf_h225_telexPartyNumber,
      { "telexPartyNumber", "h225.telexPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "PartyNumber/telexPartyNumber", HFILL }},
    { &hf_h225_privateNumber,
      { "privateNumber", "h225.privateNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyNumber/privateNumber", HFILL }},
    { &hf_h225_nationalStandardPartyNumber,
      { "nationalStandardPartyNumber", "h225.nationalStandardPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "PartyNumber/nationalStandardPartyNumber", HFILL }},
    { &hf_h225_publicTypeOfNumber,
      { "publicTypeOfNumber", "h225.publicTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(h225_PublicTypeOfNumber_vals), 0,
        "PublicPartyNumber/publicTypeOfNumber", HFILL }},
    { &hf_h225_publicNumberDigits,
      { "publicNumberDigits", "h225.publicNumberDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "PublicPartyNumber/publicNumberDigits", HFILL }},
    { &hf_h225_privateTypeOfNumber,
      { "privateTypeOfNumber", "h225.privateTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(h225_PrivateTypeOfNumber_vals), 0,
        "PrivatePartyNumber/privateTypeOfNumber", HFILL }},
    { &hf_h225_privateNumberDigits,
      { "privateNumberDigits", "h225.privateNumberDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrivatePartyNumber/privateNumberDigits", HFILL }},
    { &hf_h225_internationalNumber,
      { "internationalNumber", "h225.internationalNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "PublicTypeOfNumber/internationalNumber", HFILL }},
    { &hf_h225_nationalNumber,
      { "nationalNumber", "h225.nationalNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "PublicTypeOfNumber/nationalNumber", HFILL }},
    { &hf_h225_networkSpecificNumber,
      { "networkSpecificNumber", "h225.networkSpecificNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "PublicTypeOfNumber/networkSpecificNumber", HFILL }},
    { &hf_h225_subscriberNumber,
      { "subscriberNumber", "h225.subscriberNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "PublicTypeOfNumber/subscriberNumber", HFILL }},
    { &hf_h225_abbreviatedNumber,
      { "abbreviatedNumber", "h225.abbreviatedNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_level2RegionalNumber,
      { "level2RegionalNumber", "h225.level2RegionalNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateTypeOfNumber/level2RegionalNumber", HFILL }},
    { &hf_h225_level1RegionalNumber,
      { "level1RegionalNumber", "h225.level1RegionalNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateTypeOfNumber/level1RegionalNumber", HFILL }},
    { &hf_h225_pISNSpecificNumber,
      { "pISNSpecificNumber", "h225.pISNSpecificNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateTypeOfNumber/pISNSpecificNumber", HFILL }},
    { &hf_h225_localNumber,
      { "localNumber", "h225.localNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateTypeOfNumber/localNumber", HFILL }},
    { &hf_h225_ansi_41_uim,
      { "ansi-41-uim", "h225.ansi_41_uim",
        FT_NONE, BASE_NONE, NULL, 0,
        "MobileUIM/ansi-41-uim", HFILL }},
    { &hf_h225_gsm_uim,
      { "gsm-uim", "h225.gsm_uim",
        FT_NONE, BASE_NONE, NULL, 0,
        "MobileUIM/gsm-uim", HFILL }},
    { &hf_h225_imsi,
      { "imsi", "h225.imsi",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_min,
      { "min", "h225.min",
        FT_STRING, BASE_NONE, NULL, 0,
        "ANSI-41-UIM/min", HFILL }},
    { &hf_h225_mdn,
      { "mdn", "h225.mdn",
        FT_STRING, BASE_NONE, NULL, 0,
        "ANSI-41-UIM/mdn", HFILL }},
    { &hf_h225_msisdn,
      { "msisdn", "h225.msisdn",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_esn,
      { "esn", "h225.esn",
        FT_STRING, BASE_NONE, NULL, 0,
        "ANSI-41-UIM/esn", HFILL }},
    { &hf_h225_mscid,
      { "mscid", "h225.mscid",
        FT_STRING, BASE_NONE, NULL, 0,
        "ANSI-41-UIM/mscid", HFILL }},
    { &hf_h225_system_id,
      { "system-id", "h225.system_id",
        FT_UINT32, BASE_DEC, VALS(h225_T_system_id_vals), 0,
        "ANSI-41-UIM/system-id", HFILL }},
    { &hf_h225_sid,
      { "sid", "h225.sid",
        FT_STRING, BASE_NONE, NULL, 0,
        "ANSI-41-UIM/system-id/sid", HFILL }},
    { &hf_h225_mid,
      { "mid", "h225.mid",
        FT_STRING, BASE_NONE, NULL, 0,
        "ANSI-41-UIM/system-id/mid", HFILL }},
    { &hf_h225_systemMyTypeCode,
      { "systemMyTypeCode", "h225.systemMyTypeCode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ANSI-41-UIM/systemMyTypeCode", HFILL }},
    { &hf_h225_systemAccessType,
      { "systemAccessType", "h225.systemAccessType",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ANSI-41-UIM/systemAccessType", HFILL }},
    { &hf_h225_qualificationInformationCode,
      { "qualificationInformationCode", "h225.qualificationInformationCode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ANSI-41-UIM/qualificationInformationCode", HFILL }},
    { &hf_h225_sesn,
      { "sesn", "h225.sesn",
        FT_STRING, BASE_NONE, NULL, 0,
        "ANSI-41-UIM/sesn", HFILL }},
    { &hf_h225_soc,
      { "soc", "h225.soc",
        FT_STRING, BASE_NONE, NULL, 0,
        "ANSI-41-UIM/soc", HFILL }},
    { &hf_h225_tmsi,
      { "tmsi", "h225.tmsi",
        FT_BYTES, BASE_HEX, NULL, 0,
        "GSM-UIM/tmsi", HFILL }},
    { &hf_h225_imei,
      { "imei", "h225.imei",
        FT_STRING, BASE_NONE, NULL, 0,
        "GSM-UIM/imei", HFILL }},
    { &hf_h225_hplmn,
      { "hplmn", "h225.hplmn",
        FT_STRING, BASE_NONE, NULL, 0,
        "GSM-UIM/hplmn", HFILL }},
    { &hf_h225_vplmn,
      { "vplmn", "h225.vplmn",
        FT_STRING, BASE_NONE, NULL, 0,
        "GSM-UIM/vplmn", HFILL }},
    { &hf_h225_address,
      { "address", "h225.address",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "ExtendedAliasAddress/address", HFILL }},
    { &hf_h225_aliasAddress,
      { "aliasAddress", "h225.aliasAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Endpoint/aliasAddress", HFILL }},
    { &hf_h225_aliasAddress_item,
      { "Item", "h225.aliasAddress_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "Endpoint/aliasAddress/_item", HFILL }},
    { &hf_h225_callSignalAddress,
      { "callSignalAddress", "h225.callSignalAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_callSignalAddress_item,
      { "Item", "h225.callSignalAddress_item",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "", HFILL }},
    { &hf_h225_rasAddress,
      { "rasAddress", "h225.rasAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_rasAddress_item,
      { "Item", "h225.rasAddress_item",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "", HFILL }},
    { &hf_h225_endpointType,
      { "endpointType", "h225.endpointType",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_priority,
      { "priority", "h225.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_remoteExtensionAddress,
      { "remoteExtensionAddress", "h225.remoteExtensionAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_remoteExtensionAddress_item,
      { "Item", "h225.remoteExtensionAddress_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "", HFILL }},
    { &hf_h225_alternateTransportAddresses,
      { "alternateTransportAddresses", "h225.alternateTransportAddresses",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_annexE,
      { "annexE", "h225.annexE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AlternateTransportAddresses/annexE", HFILL }},
    { &hf_h225_annexE_item,
      { "Item", "h225.annexE_item",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "AlternateTransportAddresses/annexE/_item", HFILL }},
    { &hf_h225_sctp,
      { "sctp", "h225.sctp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AlternateTransportAddresses/sctp", HFILL }},
    { &hf_h225_sctp_item,
      { "Item", "h225.sctp_item",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "AlternateTransportAddresses/sctp/_item", HFILL }},
    { &hf_h225_tcp,
      { "tcp", "h225.tcp",
        FT_NONE, BASE_NONE, NULL, 0,
        "UseSpecifiedTransport/tcp", HFILL }},
    { &hf_h225_annexE_flg,
      { "annexE", "h225.annexE",
        FT_NONE, BASE_NONE, NULL, 0,
        "UseSpecifiedTransport/annexE", HFILL }},
    { &hf_h225_sctp_flg,
      { "sctp", "h225.sctp",
        FT_NONE, BASE_NONE, NULL, 0,
        "UseSpecifiedTransport/sctp", HFILL }},
    { &hf_h225_alternateGK_rasAddress,
      { "rasAddress", "h225.rasAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "AlternateGK/rasAddress", HFILL }},
    { &hf_h225_gatekeeperIdentifier,
      { "gatekeeperIdentifier", "h225.gatekeeperIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_needToRegister,
      { "needToRegister", "h225.needToRegister",
        FT_BOOLEAN, 8, NULL, 0,
        "AlternateGK/needToRegister", HFILL }},
    { &hf_h225_alternateGatekeeper,
      { "alternateGatekeeper", "h225.alternateGatekeeper",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_alternateGatekeeper_item,
      { "Item", "h225.alternateGatekeeper_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_altGKisPermanent,
      { "altGKisPermanent", "h225.altGKisPermanent",
        FT_BOOLEAN, 8, NULL, 0,
        "AltGKInfo/altGKisPermanent", HFILL }},
    { &hf_h225_default,
      { "default", "h225.default",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityServiceMode/default", HFILL }},
    { &hf_h225_encryption,
      { "encryption", "h225.encryption",
        FT_UINT32, BASE_DEC, VALS(h225_SecurityServiceMode_vals), 0,
        "SecurityCapabilities/encryption", HFILL }},
    { &hf_h225_authenticaton,
      { "authenticaton", "h225.authenticaton",
        FT_UINT32, BASE_DEC, VALS(h225_SecurityServiceMode_vals), 0,
        "SecurityCapabilities/authenticaton", HFILL }},
    { &hf_h225_securityCapabilities_integrity,
      { "integrity", "h225.integrity",
        FT_UINT32, BASE_DEC, VALS(h225_SecurityServiceMode_vals), 0,
        "SecurityCapabilities/integrity", HFILL }},
    { &hf_h225_securityWrongSyncTime,
      { "securityWrongSyncTime", "h225.securityWrongSyncTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_securityReplay,
      { "securityReplay", "h225.securityReplay",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_securityWrongGeneralID,
      { "securityWrongGeneralID", "h225.securityWrongGeneralID",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_securityWrongSendersID,
      { "securityWrongSendersID", "h225.securityWrongSendersID",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_securityIntegrityFailed,
      { "securityIntegrityFailed", "h225.securityIntegrityFailed",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_securityWrongOID,
      { "securityWrongOID", "h225.securityWrongOID",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_securityDHmismatch,
      { "securityDHmismatch", "h225.securityDHmismatch",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_securityCertificateExpired,
      { "securityCertificateExpired", "h225.securityCertificateExpired",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrors/securityCertificateExpired", HFILL }},
    { &hf_h225_securityCertificateDateInvalid,
      { "securityCertificateDateInvalid", "h225.securityCertificateDateInvalid",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrors/securityCertificateDateInvalid", HFILL }},
    { &hf_h225_securityCertificateRevoked,
      { "securityCertificateRevoked", "h225.securityCertificateRevoked",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrors/securityCertificateRevoked", HFILL }},
    { &hf_h225_securityCertificateNotReadable,
      { "securityCertificateNotReadable", "h225.securityCertificateNotReadable",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrors/securityCertificateNotReadable", HFILL }},
    { &hf_h225_securityCertificateSignatureInvalid,
      { "securityCertificateSignatureInvalid", "h225.securityCertificateSignatureInvalid",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrors/securityCertificateSignatureInvalid", HFILL }},
    { &hf_h225_securityCertificateMissing,
      { "securityCertificateMissing", "h225.securityCertificateMissing",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrors/securityCertificateMissing", HFILL }},
    { &hf_h225_securityCertificateIncomplete,
      { "securityCertificateIncomplete", "h225.securityCertificateIncomplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrors/securityCertificateIncomplete", HFILL }},
    { &hf_h225_securityUnsupportedCertificateAlgOID,
      { "securityUnsupportedCertificateAlgOID", "h225.securityUnsupportedCertificateAlgOID",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrors/securityUnsupportedCertificateAlgOID", HFILL }},
    { &hf_h225_securityUnknownCA,
      { "securityUnknownCA", "h225.securityUnknownCA",
        FT_NONE, BASE_NONE, NULL, 0,
        "SecurityErrors/securityUnknownCA", HFILL }},
    { &hf_h225_noSecurity,
      { "noSecurity", "h225.noSecurity",
        FT_NONE, BASE_NONE, NULL, 0,
        "H245Security/noSecurity", HFILL }},
    { &hf_h225_tls,
      { "tls", "h225.tls",
        FT_NONE, BASE_NONE, NULL, 0,
        "H245Security/tls", HFILL }},
    { &hf_h225_ipsec,
      { "ipsec", "h225.ipsec",
        FT_NONE, BASE_NONE, NULL, 0,
        "H245Security/ipsec", HFILL }},
    { &hf_h225_q932Full,
      { "q932Full", "h225.q932Full",
        FT_BOOLEAN, 8, NULL, 0,
        "QseriesOptions/q932Full", HFILL }},
    { &hf_h225_q951Full,
      { "q951Full", "h225.q951Full",
        FT_BOOLEAN, 8, NULL, 0,
        "QseriesOptions/q951Full", HFILL }},
    { &hf_h225_q952Full,
      { "q952Full", "h225.q952Full",
        FT_BOOLEAN, 8, NULL, 0,
        "QseriesOptions/q952Full", HFILL }},
    { &hf_h225_q953Full,
      { "q953Full", "h225.q953Full",
        FT_BOOLEAN, 8, NULL, 0,
        "QseriesOptions/q953Full", HFILL }},
    { &hf_h225_q955Full,
      { "q955Full", "h225.q955Full",
        FT_BOOLEAN, 8, NULL, 0,
        "QseriesOptions/q955Full", HFILL }},
    { &hf_h225_q956Full,
      { "q956Full", "h225.q956Full",
        FT_BOOLEAN, 8, NULL, 0,
        "QseriesOptions/q956Full", HFILL }},
    { &hf_h225_q957Full,
      { "q957Full", "h225.q957Full",
        FT_BOOLEAN, 8, NULL, 0,
        "QseriesOptions/q957Full", HFILL }},
    { &hf_h225_q954Info,
      { "q954Info", "h225.q954Info",
        FT_NONE, BASE_NONE, NULL, 0,
        "QseriesOptions/q954Info", HFILL }},
    { &hf_h225_conferenceCalling,
      { "conferenceCalling", "h225.conferenceCalling",
        FT_BOOLEAN, 8, NULL, 0,
        "Q954Details/conferenceCalling", HFILL }},
    { &hf_h225_threePartyService,
      { "threePartyService", "h225.threePartyService",
        FT_BOOLEAN, 8, NULL, 0,
        "Q954Details/threePartyService", HFILL }},
    { &hf_h225_guid,
      { "guid", "h225.guid",
        FT_GUID, BASE_NONE, NULL, 0,
        "CallIdentifier/guid", HFILL }},
    { &hf_h225_isoAlgorithm,
      { "isoAlgorithm", "h225.isoAlgorithm",
        FT_OID, BASE_NONE, NULL, 0,
        "EncryptIntAlg/isoAlgorithm", HFILL }},
    { &hf_h225_hMAC_MD5,
      { "hMAC-MD5", "h225.hMAC_MD5",
        FT_NONE, BASE_NONE, NULL, 0,
        "NonIsoIntegrityMechanism/hMAC-MD5", HFILL }},
    { &hf_h225_hMAC_iso10118_2_s,
      { "hMAC-iso10118-2-s", "h225.hMAC_iso10118_2_s",
        FT_UINT32, BASE_DEC, VALS(h225_EncryptIntAlg_vals), 0,
        "NonIsoIntegrityMechanism/hMAC-iso10118-2-s", HFILL }},
    { &hf_h225_hMAC_iso10118_2_l,
      { "hMAC-iso10118-2-l", "h225.hMAC_iso10118_2_l",
        FT_UINT32, BASE_DEC, VALS(h225_EncryptIntAlg_vals), 0,
        "NonIsoIntegrityMechanism/hMAC-iso10118-2-l", HFILL }},
    { &hf_h225_hMAC_iso10118_3,
      { "hMAC-iso10118-3", "h225.hMAC_iso10118_3",
        FT_OID, BASE_NONE, NULL, 0,
        "NonIsoIntegrityMechanism/hMAC-iso10118-3", HFILL }},
    { &hf_h225_digSig,
      { "digSig", "h225.digSig",
        FT_NONE, BASE_NONE, NULL, 0,
        "IntegrityMechanism/digSig", HFILL }},
    { &hf_h225_iso9797,
      { "iso9797", "h225.iso9797",
        FT_OID, BASE_NONE, NULL, 0,
        "IntegrityMechanism/iso9797", HFILL }},
    { &hf_h225_nonIsoIM,
      { "nonIsoIM", "h225.nonIsoIM",
        FT_UINT32, BASE_DEC, VALS(h225_NonIsoIntegrityMechanism_vals), 0,
        "IntegrityMechanism/nonIsoIM", HFILL }},
    { &hf_h225_algorithmOID,
      { "algorithmOID", "h225.algorithmOID",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_icv,
      { "icv", "h225.icv",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ICV/icv", HFILL }},
    { &hf_h225_cryptoEPPwdHash,
      { "cryptoEPPwdHash", "h225.cryptoEPPwdHash",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoH323Token/cryptoEPPwdHash", HFILL }},
    { &hf_h225_alias,
      { "alias", "h225.alias",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "", HFILL }},
    { &hf_h225_timeStamp,
      { "timeStamp", "h225.timeStamp",
        FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_token,
      { "token", "h225.token",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_cryptoGKPwdHash,
      { "cryptoGKPwdHash", "h225.cryptoGKPwdHash",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoH323Token/cryptoGKPwdHash", HFILL }},
    { &hf_h225_gatekeeperId,
      { "gatekeeperId", "h225.gatekeeperId",
        FT_STRING, BASE_NONE, NULL, 0,
        "CryptoH323Token/cryptoGKPwdHash/gatekeeperId", HFILL }},
    { &hf_h225_cryptoEPPwdEncr,
      { "cryptoEPPwdEncr", "h225.cryptoEPPwdEncr",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoH323Token/cryptoEPPwdEncr", HFILL }},
    { &hf_h225_cryptoGKPwdEncr,
      { "cryptoGKPwdEncr", "h225.cryptoGKPwdEncr",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoH323Token/cryptoGKPwdEncr", HFILL }},
    { &hf_h225_cryptoEPCert,
      { "cryptoEPCert", "h225.cryptoEPCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoH323Token/cryptoEPCert", HFILL }},
    { &hf_h225_cryptoGKCert,
      { "cryptoGKCert", "h225.cryptoGKCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoH323Token/cryptoGKCert", HFILL }},
    { &hf_h225_cryptoFastStart,
      { "cryptoFastStart", "h225.cryptoFastStart",
        FT_NONE, BASE_NONE, NULL, 0,
        "CryptoH323Token/cryptoFastStart", HFILL }},
    { &hf_h225_nestedcryptoToken,
      { "nestedcryptoToken", "h225.nestedcryptoToken",
        FT_UINT32, BASE_DEC, VALS(h235_CryptoToken_vals), 0,
        "CryptoH323Token/nestedcryptoToken", HFILL }},
    { &hf_h225_channelRate,
      { "channelRate", "h225.channelRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DataRate/channelRate", HFILL }},
    { &hf_h225_channelMultiplier,
      { "channelMultiplier", "h225.channelMultiplier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DataRate/channelMultiplier", HFILL }},
    { &hf_h225_globalCallId,
      { "globalCallId", "h225.globalCallId",
        FT_GUID, BASE_NONE, NULL, 0,
        "CallLinkage/globalCallId", HFILL }},
    { &hf_h225_threadId,
      { "threadId", "h225.threadId",
        FT_GUID, BASE_NONE, NULL, 0,
        "CallLinkage/threadId", HFILL }},
    { &hf_h225_prefix,
      { "prefix", "h225.prefix",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "SupportedPrefix/prefix", HFILL }},
    { &hf_h225_canReportCallCapacity,
      { "canReportCallCapacity", "h225.canReportCallCapacity",
        FT_BOOLEAN, 8, NULL, 0,
        "CapacityReportingCapability/canReportCallCapacity", HFILL }},
    { &hf_h225_capacityReportingSpecification_when,
      { "when", "h225.when",
        FT_NONE, BASE_NONE, NULL, 0,
        "CapacityReportingSpecification/when", HFILL }},
    { &hf_h225_callStart,
      { "callStart", "h225.callStart",
        FT_NONE, BASE_NONE, NULL, 0,
        "CapacityReportingSpecification/when/callStart", HFILL }},
    { &hf_h225_callEnd,
      { "callEnd", "h225.callEnd",
        FT_NONE, BASE_NONE, NULL, 0,
        "CapacityReportingSpecification/when/callEnd", HFILL }},
    { &hf_h225_maximumCallCapacity,
      { "maximumCallCapacity", "h225.maximumCallCapacity",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacity/maximumCallCapacity", HFILL }},
    { &hf_h225_currentCallCapacity,
      { "currentCallCapacity", "h225.currentCallCapacity",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacity/currentCallCapacity", HFILL }},
    { &hf_h225_voiceGwCallsAvailable,
      { "voiceGwCallsAvailable", "h225.voiceGwCallsAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallCapacityInfo/voiceGwCallsAvailable", HFILL }},
    { &hf_h225_voiceGwCallsAvailable_item,
      { "Item", "h225.voiceGwCallsAvailable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacityInfo/voiceGwCallsAvailable/_item", HFILL }},
    { &hf_h225_h310GwCallsAvailable,
      { "h310GwCallsAvailable", "h225.h310GwCallsAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallCapacityInfo/h310GwCallsAvailable", HFILL }},
    { &hf_h225_h310GwCallsAvailable_item,
      { "Item", "h225.h310GwCallsAvailable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacityInfo/h310GwCallsAvailable/_item", HFILL }},
    { &hf_h225_h320GwCallsAvailable,
      { "h320GwCallsAvailable", "h225.h320GwCallsAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallCapacityInfo/h320GwCallsAvailable", HFILL }},
    { &hf_h225_h320GwCallsAvailable_item,
      { "Item", "h225.h320GwCallsAvailable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacityInfo/h320GwCallsAvailable/_item", HFILL }},
    { &hf_h225_h321GwCallsAvailable,
      { "h321GwCallsAvailable", "h225.h321GwCallsAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallCapacityInfo/h321GwCallsAvailable", HFILL }},
    { &hf_h225_h321GwCallsAvailable_item,
      { "Item", "h225.h321GwCallsAvailable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacityInfo/h321GwCallsAvailable/_item", HFILL }},
    { &hf_h225_h322GwCallsAvailable,
      { "h322GwCallsAvailable", "h225.h322GwCallsAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallCapacityInfo/h322GwCallsAvailable", HFILL }},
    { &hf_h225_h322GwCallsAvailable_item,
      { "Item", "h225.h322GwCallsAvailable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacityInfo/h322GwCallsAvailable/_item", HFILL }},
    { &hf_h225_h323GwCallsAvailable,
      { "h323GwCallsAvailable", "h225.h323GwCallsAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallCapacityInfo/h323GwCallsAvailable", HFILL }},
    { &hf_h225_h323GwCallsAvailable_item,
      { "Item", "h225.h323GwCallsAvailable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacityInfo/h323GwCallsAvailable/_item", HFILL }},
    { &hf_h225_h324GwCallsAvailable,
      { "h324GwCallsAvailable", "h225.h324GwCallsAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallCapacityInfo/h324GwCallsAvailable", HFILL }},
    { &hf_h225_h324GwCallsAvailable_item,
      { "Item", "h225.h324GwCallsAvailable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacityInfo/h324GwCallsAvailable/_item", HFILL }},
    { &hf_h225_t120OnlyGwCallsAvailable,
      { "t120OnlyGwCallsAvailable", "h225.t120OnlyGwCallsAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallCapacityInfo/t120OnlyGwCallsAvailable", HFILL }},
    { &hf_h225_t120OnlyGwCallsAvailable_item,
      { "Item", "h225.t120OnlyGwCallsAvailable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacityInfo/t120OnlyGwCallsAvailable/_item", HFILL }},
    { &hf_h225_t38FaxAnnexbOnlyGwCallsAvailable,
      { "t38FaxAnnexbOnlyGwCallsAvailable", "h225.t38FaxAnnexbOnlyGwCallsAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallCapacityInfo/t38FaxAnnexbOnlyGwCallsAvailable", HFILL }},
    { &hf_h225_t38FaxAnnexbOnlyGwCallsAvailable_item,
      { "Item", "h225.t38FaxAnnexbOnlyGwCallsAvailable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacityInfo/t38FaxAnnexbOnlyGwCallsAvailable/_item", HFILL }},
    { &hf_h225_terminalCallsAvailable,
      { "terminalCallsAvailable", "h225.terminalCallsAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallCapacityInfo/terminalCallsAvailable", HFILL }},
    { &hf_h225_terminalCallsAvailable_item,
      { "Item", "h225.terminalCallsAvailable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacityInfo/terminalCallsAvailable/_item", HFILL }},
    { &hf_h225_mcuCallsAvailable,
      { "mcuCallsAvailable", "h225.mcuCallsAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallCapacityInfo/mcuCallsAvailable", HFILL }},
    { &hf_h225_mcuCallsAvailable_item,
      { "Item", "h225.mcuCallsAvailable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacityInfo/mcuCallsAvailable/_item", HFILL }},
    { &hf_h225_sipGwCallsAvailable,
      { "sipGwCallsAvailable", "h225.sipGwCallsAvailable",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallCapacityInfo/sipGwCallsAvailable", HFILL }},
    { &hf_h225_sipGwCallsAvailable_item,
      { "Item", "h225.sipGwCallsAvailable_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCapacityInfo/sipGwCallsAvailable/_item", HFILL }},
    { &hf_h225_calls,
      { "calls", "h225.calls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallsAvailable/calls", HFILL }},
    { &hf_h225_group_IA5String,
      { "group", "h225.group",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_carrier,
      { "carrier", "h225.carrier",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_sourceCircuitID,
      { "sourceCircuitID", "h225.sourceCircuitID",
        FT_NONE, BASE_NONE, NULL, 0,
        "CircuitInfo/sourceCircuitID", HFILL }},
    { &hf_h225_destinationCircuitID,
      { "destinationCircuitID", "h225.destinationCircuitID",
        FT_NONE, BASE_NONE, NULL, 0,
        "CircuitInfo/destinationCircuitID", HFILL }},
    { &hf_h225_cic,
      { "cic", "h225.cic",
        FT_NONE, BASE_NONE, NULL, 0,
        "CircuitIdentifier/cic", HFILL }},
    { &hf_h225_group,
      { "group", "h225.group",
        FT_NONE, BASE_NONE, NULL, 0,
        "CircuitIdentifier/group", HFILL }},
    { &hf_h225_cic_2_4,
      { "cic", "h225.cic",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CicInfo/cic", HFILL }},
    { &hf_h225_cic_item,
      { "Item", "h225.cic_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CicInfo/cic/_item", HFILL }},
    { &hf_h225_pointCode,
      { "pointCode", "h225.pointCode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CicInfo/pointCode", HFILL }},
    { &hf_h225_member,
      { "member", "h225.member",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GroupID/member", HFILL }},
    { &hf_h225_member_item,
      { "Item", "h225.member_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GroupID/member/_item", HFILL }},
    { &hf_h225_carrierIdentificationCode,
      { "carrierIdentificationCode", "h225.carrierIdentificationCode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CarrierInfo/carrierIdentificationCode", HFILL }},
    { &hf_h225_carrierName,
      { "carrierName", "h225.carrierName",
        FT_STRING, BASE_NONE, NULL, 0,
        "CarrierInfo/carrierName", HFILL }},
    { &hf_h225_url,
      { "url", "h225.url",
        FT_STRING, BASE_NONE, NULL, 0,
        "ServiceControlDescriptor/url", HFILL }},
    { &hf_h225_signal,
      { "signal", "h225.signal",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ServiceControlDescriptor/signal", HFILL }},
    { &hf_h225_callCreditServiceControl,
      { "callCreditServiceControl", "h225.callCreditServiceControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceControlDescriptor/callCreditServiceControl", HFILL }},
    { &hf_h225_sessionId_0_255,
      { "sessionId", "h225.sessionId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServiceControlSession/sessionId", HFILL }},
    { &hf_h225_contents,
      { "contents", "h225.contents",
        FT_UINT32, BASE_DEC, VALS(h225_ServiceControlDescriptor_vals), 0,
        "ServiceControlSession/contents", HFILL }},
    { &hf_h225_reason,
      { "reason", "h225.reason",
        FT_UINT32, BASE_DEC, VALS(h225_ServiceControlSession_reason_vals), 0,
        "ServiceControlSession/reason", HFILL }},
    { &hf_h225_open,
      { "open", "h225.open",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceControlSession/reason/open", HFILL }},
    { &hf_h225_refresh,
      { "refresh", "h225.refresh",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceControlSession/reason/refresh", HFILL }},
    { &hf_h225_close,
      { "close", "h225.close",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceControlSession/reason/close", HFILL }},
    { &hf_h225_nonStandardUsageTypes,
      { "nonStandardUsageTypes", "h225.nonStandardUsageTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RasUsageInfoTypes/nonStandardUsageTypes", HFILL }},
    { &hf_h225_nonStandardUsageTypes_item,
      { "Item", "h225.nonStandardUsageTypes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasUsageInfoTypes/nonStandardUsageTypes/_item", HFILL }},
    { &hf_h225_startTime,
      { "startTime", "h225.startTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasUsageInfoTypes/startTime", HFILL }},
    { &hf_h225_endTime_flg,
      { "endTime", "h225.endTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasUsageInfoTypes/endTime", HFILL }},
    { &hf_h225_terminationCause_flg,
      { "terminationCause", "h225.terminationCause",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasUsageInfoTypes/terminationCause", HFILL }},
    { &hf_h225_when,
      { "when", "h225.when",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasUsageSpecification/when", HFILL }},
    { &hf_h225_start,
      { "start", "h225.start",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasUsageSpecification/when/start", HFILL }},
    { &hf_h225_end,
      { "end", "h225.end",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasUsageSpecification/when/end", HFILL }},
    { &hf_h225_inIrr,
      { "inIrr", "h225.inIrr",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasUsageSpecification/when/inIrr", HFILL }},
    { &hf_h225_ras_callStartingPoint,
      { "callStartingPoint", "h225.callStartingPoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasUsageSpecification/callStartingPoint", HFILL }},
    { &hf_h225_alerting_flg,
      { "alerting", "h225.alerting",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_connect_flg,
      { "connect", "h225.connect",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_required,
      { "required", "h225.required",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasUsageSpecification/required", HFILL }},
    { &hf_h225_nonStandardUsageFields,
      { "nonStandardUsageFields", "h225.nonStandardUsageFields",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RasUsageInformation/nonStandardUsageFields", HFILL }},
    { &hf_h225_nonStandardUsageFields_item,
      { "Item", "h225.nonStandardUsageFields_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasUsageInformation/nonStandardUsageFields/_item", HFILL }},
    { &hf_h225_alertingTime,
      { "alertingTime", "h225.alertingTime",
        FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0,
        "RasUsageInformation/alertingTime", HFILL }},
    { &hf_h225_connectTime,
      { "connectTime", "h225.connectTime",
        FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0,
        "RasUsageInformation/connectTime", HFILL }},
    { &hf_h225_endTime,
      { "endTime", "h225.endTime",
        FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0,
        "RasUsageInformation/endTime", HFILL }},
    { &hf_h225_releaseCompleteCauseIE,
      { "releaseCompleteCauseIE", "h225.releaseCompleteCauseIE",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CallTerminationCause/releaseCompleteCauseIE", HFILL }},
    { &hf_h225_sender,
      { "sender", "h225.sender",
        FT_BOOLEAN, 8, NULL, 0,
        "BandwidthDetails/sender", HFILL }},
    { &hf_h225_multicast,
      { "multicast", "h225.multicast",
        FT_BOOLEAN, 8, NULL, 0,
        "BandwidthDetails/multicast", HFILL }},
    { &hf_h225_bandwidth,
      { "bandwidth", "h225.bandwidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_rtcpAddresses,
      { "rtcpAddresses", "h225.rtcpAddresses",
        FT_NONE, BASE_NONE, NULL, 0,
        "BandwidthDetails/rtcpAddresses", HFILL }},
    { &hf_h225_canDisplayAmountString,
      { "canDisplayAmountString", "h225.canDisplayAmountString",
        FT_BOOLEAN, 8, NULL, 0,
        "CallCreditCapability/canDisplayAmountString", HFILL }},
    { &hf_h225_canEnforceDurationLimit,
      { "canEnforceDurationLimit", "h225.canEnforceDurationLimit",
        FT_BOOLEAN, 8, NULL, 0,
        "CallCreditCapability/canEnforceDurationLimit", HFILL }},
    { &hf_h225_amountString,
      { "amountString", "h225.amountString",
        FT_STRING, BASE_NONE, NULL, 0,
        "CallCreditServiceControl/amountString", HFILL }},
    { &hf_h225_billingMode,
      { "billingMode", "h225.billingMode",
        FT_UINT32, BASE_DEC, VALS(h225_T_billingMode_vals), 0,
        "CallCreditServiceControl/billingMode", HFILL }},
    { &hf_h225_credit,
      { "credit", "h225.credit",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCreditServiceControl/billingMode/credit", HFILL }},
    { &hf_h225_debit,
      { "debit", "h225.debit",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallCreditServiceControl/billingMode/debit", HFILL }},
    { &hf_h225_callDurationLimit,
      { "callDurationLimit", "h225.callDurationLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallCreditServiceControl/callDurationLimit", HFILL }},
    { &hf_h225_enforceCallDurationLimit,
      { "enforceCallDurationLimit", "h225.enforceCallDurationLimit",
        FT_BOOLEAN, 8, NULL, 0,
        "CallCreditServiceControl/enforceCallDurationLimit", HFILL }},
    { &hf_h225_callStartingPoint,
      { "callStartingPoint", "h225.callStartingPoint",
        FT_UINT32, BASE_DEC, VALS(h225_CallCreditServiceControl_callStartingPoint_vals), 0,
        "CallCreditServiceControl/callStartingPoint", HFILL }},
    { &hf_h225_id,
      { "id", "h225.id",
        FT_UINT32, BASE_DEC, VALS(h225_GenericIdentifier_vals), 0,
        "", HFILL }},
    { &hf_h225_parameters,
      { "parameters", "h225.parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GenericData/parameters", HFILL }},
    { &hf_h225_parameters_item,
      { "Item", "h225.parameters_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "GenericData/parameters/_item", HFILL }},
    { &hf_h225_standard,
      { "standard", "h225.standard",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GenericIdentifier/standard", HFILL }},
    { &hf_h225_oid,
      { "oid", "h225.oid",
        FT_OID, BASE_NONE, NULL, 0,
        "GenericIdentifier/oid", HFILL }},
    { &hf_h225_genericIdentifier_nonStandard,
      { "nonStandard", "h225.nonStandard",
        FT_GUID, BASE_NONE, NULL, 0,
        "GenericIdentifier/nonStandard", HFILL }},
    { &hf_h225_content,
      { "content", "h225.content",
        FT_UINT32, BASE_DEC, VALS(h225_Content_vals), 0,
        "EnumeratedParameter/content", HFILL }},
    { &hf_h225_raw,
      { "raw", "h225.raw",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Content/raw", HFILL }},
    { &hf_h225_text,
      { "text", "h225.text",
        FT_STRING, BASE_NONE, NULL, 0,
        "Content/text", HFILL }},
    { &hf_h225_unicode,
      { "unicode", "h225.unicode",
        FT_STRING, BASE_NONE, NULL, 0,
        "Content/unicode", HFILL }},
    { &hf_h225_bool,
      { "bool", "h225.bool",
        FT_BOOLEAN, 8, NULL, 0,
        "Content/bool", HFILL }},
    { &hf_h225_number8,
      { "number8", "h225.number8",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Content/number8", HFILL }},
    { &hf_h225_number16,
      { "number16", "h225.number16",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Content/number16", HFILL }},
    { &hf_h225_number32,
      { "number32", "h225.number32",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Content/number32", HFILL }},
    { &hf_h225_transport,
      { "transport", "h225.transport",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "Content/transport", HFILL }},
    { &hf_h225_compound,
      { "compound", "h225.compound",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Content/compound", HFILL }},
    { &hf_h225_compound_item,
      { "Item", "h225.compound_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Content/compound/_item", HFILL }},
    { &hf_h225_nested,
      { "nested", "h225.nested",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Content/nested", HFILL }},
    { &hf_h225_nested_item,
      { "Item", "h225.nested_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Content/nested/_item", HFILL }},
    { &hf_h225_replacementFeatureSet,
      { "replacementFeatureSet", "h225.replacementFeatureSet",
        FT_BOOLEAN, 8, NULL, 0,
        "FeatureSet/replacementFeatureSet", HFILL }},
    { &hf_h225_sendAddress,
      { "sendAddress", "h225.sendAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "TransportChannelInfo/sendAddress", HFILL }},
    { &hf_h225_recvAddress,
      { "recvAddress", "h225.recvAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "TransportChannelInfo/recvAddress", HFILL }},
    { &hf_h225_rtpAddress,
      { "rtpAddress", "h225.rtpAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTPSession/rtpAddress", HFILL }},
    { &hf_h225_rtcpAddress,
      { "rtcpAddress", "h225.rtcpAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTPSession/rtcpAddress", HFILL }},
    { &hf_h225_cname,
      { "cname", "h225.cname",
        FT_STRING, BASE_NONE, NULL, 0,
        "RTPSession/cname", HFILL }},
    { &hf_h225_ssrc,
      { "ssrc", "h225.ssrc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RTPSession/ssrc", HFILL }},
    { &hf_h225_sessionId,
      { "sessionId", "h225.sessionId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RTPSession/sessionId", HFILL }},
    { &hf_h225_associatedSessionIds,
      { "associatedSessionIds", "h225.associatedSessionIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RTPSession/associatedSessionIds", HFILL }},
    { &hf_h225_associatedSessionIds_item,
      { "Item", "h225.associatedSessionIds_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RTPSession/associatedSessionIds/_item", HFILL }},
    { &hf_h225_multicast_flg,
      { "multicast", "h225.multicast",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTPSession/multicast", HFILL }},
    { &hf_h225_gatekeeperRequest,
      { "gatekeeperRequest", "h225.gatekeeperRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/gatekeeperRequest", HFILL }},
    { &hf_h225_gatekeeperConfirm,
      { "gatekeeperConfirm", "h225.gatekeeperConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/gatekeeperConfirm", HFILL }},
    { &hf_h225_gatekeeperReject,
      { "gatekeeperReject", "h225.gatekeeperReject",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/gatekeeperReject", HFILL }},
    { &hf_h225_registrationRequest,
      { "registrationRequest", "h225.registrationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/registrationRequest", HFILL }},
    { &hf_h225_registrationConfirm,
      { "registrationConfirm", "h225.registrationConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/registrationConfirm", HFILL }},
    { &hf_h225_registrationReject,
      { "registrationReject", "h225.registrationReject",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/registrationReject", HFILL }},
    { &hf_h225_unregistrationRequest,
      { "unregistrationRequest", "h225.unregistrationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/unregistrationRequest", HFILL }},
    { &hf_h225_unregistrationConfirm,
      { "unregistrationConfirm", "h225.unregistrationConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/unregistrationConfirm", HFILL }},
    { &hf_h225_unregistrationReject,
      { "unregistrationReject", "h225.unregistrationReject",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/unregistrationReject", HFILL }},
    { &hf_h225_admissionRequest,
      { "admissionRequest", "h225.admissionRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/admissionRequest", HFILL }},
    { &hf_h225_admissionConfirm,
      { "admissionConfirm", "h225.admissionConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/admissionConfirm", HFILL }},
    { &hf_h225_admissionReject,
      { "admissionReject", "h225.admissionReject",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/admissionReject", HFILL }},
    { &hf_h225_bandwidthRequest,
      { "bandwidthRequest", "h225.bandwidthRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/bandwidthRequest", HFILL }},
    { &hf_h225_bandwidthConfirm,
      { "bandwidthConfirm", "h225.bandwidthConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/bandwidthConfirm", HFILL }},
    { &hf_h225_bandwidthReject,
      { "bandwidthReject", "h225.bandwidthReject",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/bandwidthReject", HFILL }},
    { &hf_h225_disengageRequest,
      { "disengageRequest", "h225.disengageRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/disengageRequest", HFILL }},
    { &hf_h225_disengageConfirm,
      { "disengageConfirm", "h225.disengageConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/disengageConfirm", HFILL }},
    { &hf_h225_disengageReject,
      { "disengageReject", "h225.disengageReject",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/disengageReject", HFILL }},
    { &hf_h225_locationRequest,
      { "locationRequest", "h225.locationRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/locationRequest", HFILL }},
    { &hf_h225_locationConfirm,
      { "locationConfirm", "h225.locationConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/locationConfirm", HFILL }},
    { &hf_h225_locationReject,
      { "locationReject", "h225.locationReject",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/locationReject", HFILL }},
    { &hf_h225_infoRequest,
      { "infoRequest", "h225.infoRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/infoRequest", HFILL }},
    { &hf_h225_infoRequestResponse,
      { "infoRequestResponse", "h225.infoRequestResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/infoRequestResponse", HFILL }},
    { &hf_h225_nonStandardMessage,
      { "nonStandardMessage", "h225.nonStandardMessage",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/nonStandardMessage", HFILL }},
    { &hf_h225_unknownMessageResponse,
      { "unknownMessageResponse", "h225.unknownMessageResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/unknownMessageResponse", HFILL }},
    { &hf_h225_requestInProgress,
      { "requestInProgress", "h225.requestInProgress",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/requestInProgress", HFILL }},
    { &hf_h225_resourcesAvailableIndicate,
      { "resourcesAvailableIndicate", "h225.resourcesAvailableIndicate",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/resourcesAvailableIndicate", HFILL }},
    { &hf_h225_resourcesAvailableConfirm,
      { "resourcesAvailableConfirm", "h225.resourcesAvailableConfirm",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/resourcesAvailableConfirm", HFILL }},
    { &hf_h225_infoRequestAck,
      { "infoRequestAck", "h225.infoRequestAck",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/infoRequestAck", HFILL }},
    { &hf_h225_infoRequestNak,
      { "infoRequestNak", "h225.infoRequestNak",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/infoRequestNak", HFILL }},
    { &hf_h225_serviceControlIndication,
      { "serviceControlIndication", "h225.serviceControlIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/serviceControlIndication", HFILL }},
    { &hf_h225_serviceControlResponse,
      { "serviceControlResponse", "h225.serviceControlResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/serviceControlResponse", HFILL }},
    { &hf_h225_admissionConfirmSequence,
      { "admissionConfirmSequence", "h225.admissionConfirmSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RasMessage/admissionConfirmSequence", HFILL }},
    { &hf_h225_admissionConfirmSequence_item,
      { "Item", "h225.admissionConfirmSequence_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RasMessage/admissionConfirmSequence/_item", HFILL }},
    { &hf_h225_requestSeqNum,
      { "requestSeqNum", "h225.requestSeqNum",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_gatekeeperRequest_rasAddress,
      { "rasAddress", "h225.rasAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "GatekeeperRequest/rasAddress", HFILL }},
    { &hf_h225_endpointAlias,
      { "endpointAlias", "h225.endpointAlias",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_endpointAlias_item,
      { "Item", "h225.endpointAlias_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "", HFILL }},
    { &hf_h225_alternateEndpoints,
      { "alternateEndpoints", "h225.alternateEndpoints",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_alternateEndpoints_item,
      { "Item", "h225.alternateEndpoints_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_authenticationCapability,
      { "authenticationCapability", "h225.authenticationCapability",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GatekeeperRequest/authenticationCapability", HFILL }},
    { &hf_h225_authenticationCapability_item,
      { "Item", "h225.authenticationCapability_item",
        FT_UINT32, BASE_DEC, VALS(h235_AuthenticationMechanism_vals), 0,
        "GatekeeperRequest/authenticationCapability/_item", HFILL }},
    { &hf_h225_algorithmOIDs,
      { "algorithmOIDs", "h225.algorithmOIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GatekeeperRequest/algorithmOIDs", HFILL }},
    { &hf_h225_algorithmOIDs_item,
      { "Item", "h225.algorithmOIDs_item",
        FT_OID, BASE_NONE, NULL, 0,
        "GatekeeperRequest/algorithmOIDs/_item", HFILL }},
    { &hf_h225_integrity,
      { "integrity", "h225.integrity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_integrity_item,
      { "Item", "h225.integrity_item",
        FT_UINT32, BASE_DEC, VALS(h225_IntegrityMechanism_vals), 0,
        "", HFILL }},
    { &hf_h225_integrityCheckValue,
      { "integrityCheckValue", "h225.integrityCheckValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_supportsAltGK,
      { "supportsAltGK", "h225.supportsAltGK",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_gatekeeperConfirm_rasAddress,
      { "rasAddress", "h225.rasAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "GatekeeperConfirm/rasAddress", HFILL }},
    { &hf_h225_authenticationMode,
      { "authenticationMode", "h225.authenticationMode",
        FT_UINT32, BASE_DEC, VALS(h235_AuthenticationMechanism_vals), 0,
        "GatekeeperConfirm/authenticationMode", HFILL }},
    { &hf_h225_gatekeeperRejectReason,
      { "rejectReason", "h225.rejectReason",
        FT_UINT32, BASE_DEC, VALS(GatekeeperRejectReason_vals), 0,
        "GatekeeperReject/rejectReason", HFILL }},
    { &hf_h225_altGKInfo,
      { "altGKInfo", "h225.altGKInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_resourceUnavailable,
      { "resourceUnavailable", "h225.resourceUnavailable",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_terminalExcluded,
      { "terminalExcluded", "h225.terminalExcluded",
        FT_NONE, BASE_NONE, NULL, 0,
        "GatekeeperRejectReason/terminalExcluded", HFILL }},
    { &hf_h225_securityDenial,
      { "securityDenial", "h225.securityDenial",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_gkRej_securityError,
      { "securityError", "h225.securityError",
        FT_UINT32, BASE_DEC, VALS(h225_SecurityErrors_vals), 0,
        "GatekeeperRejectReason/securityError", HFILL }},
    { &hf_h225_discoveryComplete,
      { "discoveryComplete", "h225.discoveryComplete",
        FT_BOOLEAN, 8, NULL, 0,
        "RegistrationRequest/discoveryComplete", HFILL }},
    { &hf_h225_terminalType,
      { "terminalType", "h225.terminalType",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRequest/terminalType", HFILL }},
    { &hf_h225_terminalAlias,
      { "terminalAlias", "h225.terminalAlias",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_terminalAlias_item,
      { "Item", "h225.terminalAlias_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "", HFILL }},
    { &hf_h225_endpointVendor,
      { "endpointVendor", "h225.endpointVendor",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRequest/endpointVendor", HFILL }},
    { &hf_h225_timeToLive,
      { "timeToLive", "h225.timeToLive",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_keepAlive,
      { "keepAlive", "h225.keepAlive",
        FT_BOOLEAN, 8, NULL, 0,
        "RegistrationRequest/keepAlive", HFILL }},
    { &hf_h225_willSupplyUUIEs,
      { "willSupplyUUIEs", "h225.willSupplyUUIEs",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_h225_additiveRegistration,
      { "additiveRegistration", "h225.additiveRegistration",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRequest/additiveRegistration", HFILL }},
    { &hf_h225_terminalAliasPattern,
      { "terminalAliasPattern", "h225.terminalAliasPattern",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_terminalAliasPattern_item,
      { "Item", "h225.terminalAliasPattern_item",
        FT_UINT32, BASE_DEC, VALS(h225_AddressPattern_vals), 0,
        "", HFILL }},
    { &hf_h225_usageReportingCapability,
      { "usageReportingCapability", "h225.usageReportingCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRequest/usageReportingCapability", HFILL }},
    { &hf_h225_supportedH248Packages,
      { "supportedH248Packages", "h225.supportedH248Packages",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RegistrationRequest/supportedH248Packages", HFILL }},
    { &hf_h225_supportedH248Packages_item,
      { "Item", "h225.supportedH248Packages_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RegistrationRequest/supportedH248Packages/_item", HFILL }},
    { &hf_h225_callCreditCapability,
      { "callCreditCapability", "h225.callCreditCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRequest/callCreditCapability", HFILL }},
    { &hf_h225_capacityReportingCapability,
      { "capacityReportingCapability", "h225.capacityReportingCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRequest/capacityReportingCapability", HFILL }},
    { &hf_h225_restart,
      { "restart", "h225.restart",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRequest/restart", HFILL }},
    { &hf_h225_supportsACFSequences,
      { "supportsACFSequences", "h225.supportsACFSequences",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRequest/supportsACFSequences", HFILL }},
    { &hf_h225_willRespondToIRR,
      { "willRespondToIRR", "h225.willRespondToIRR",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_h225_preGrantedARQ,
      { "preGrantedARQ", "h225.preGrantedARQ",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationConfirm/preGrantedARQ", HFILL }},
    { &hf_h225_makeCall,
      { "makeCall", "h225.makeCall",
        FT_BOOLEAN, 8, NULL, 0,
        "RegistrationConfirm/preGrantedARQ/makeCall", HFILL }},
    { &hf_h225_useGKCallSignalAddressToMakeCall,
      { "useGKCallSignalAddressToMakeCall", "h225.useGKCallSignalAddressToMakeCall",
        FT_BOOLEAN, 8, NULL, 0,
        "RegistrationConfirm/preGrantedARQ/useGKCallSignalAddressToMakeCall", HFILL }},
    { &hf_h225_answerCall,
      { "answerCall", "h225.answerCall",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_h225_useGKCallSignalAddressToAnswer,
      { "useGKCallSignalAddressToAnswer", "h225.useGKCallSignalAddressToAnswer",
        FT_BOOLEAN, 8, NULL, 0,
        "RegistrationConfirm/preGrantedARQ/useGKCallSignalAddressToAnswer", HFILL }},
    { &hf_h225_irrFrequencyInCall,
      { "irrFrequencyInCall", "h225.irrFrequencyInCall",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RegistrationConfirm/preGrantedARQ/irrFrequencyInCall", HFILL }},
    { &hf_h225_totalBandwidthRestriction,
      { "totalBandwidthRestriction", "h225.totalBandwidthRestriction",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RegistrationConfirm/preGrantedARQ/totalBandwidthRestriction", HFILL }},
    { &hf_h225_useSpecifiedTransport,
      { "useSpecifiedTransport", "h225.useSpecifiedTransport",
        FT_UINT32, BASE_DEC, VALS(h225_UseSpecifiedTransport_vals), 0,
        "", HFILL }},
    { &hf_h225_supportsAdditiveRegistration,
      { "supportsAdditiveRegistration", "h225.supportsAdditiveRegistration",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationConfirm/supportsAdditiveRegistration", HFILL }},
    { &hf_h225_usageSpec,
      { "usageSpec", "h225.usageSpec",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_usageSpec_item,
      { "Item", "h225.usageSpec_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_featureServerAlias,
      { "featureServerAlias", "h225.featureServerAlias",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "RegistrationConfirm/featureServerAlias", HFILL }},
    { &hf_h225_capacityReportingSpec,
      { "capacityReportingSpec", "h225.capacityReportingSpec",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationConfirm/capacityReportingSpec", HFILL }},
    { &hf_h225_registrationRejectReason,
      { "rejectReason", "h225.rejectReason",
        FT_UINT32, BASE_DEC, VALS(RegistrationRejectReason_vals), 0,
        "RegistrationReject/rejectReason", HFILL }},
    { &hf_h225_discoveryRequired,
      { "discoveryRequired", "h225.discoveryRequired",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRejectReason/discoveryRequired", HFILL }},
    { &hf_h225_invalidCallSignalAddress,
      { "invalidCallSignalAddress", "h225.invalidCallSignalAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRejectReason/invalidCallSignalAddress", HFILL }},
    { &hf_h225_invalidRASAddress,
      { "invalidRASAddress", "h225.invalidRASAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRejectReason/invalidRASAddress", HFILL }},
    { &hf_h225_duplicateAlias,
      { "duplicateAlias", "h225.duplicateAlias",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RegistrationRejectReason/duplicateAlias", HFILL }},
    { &hf_h225_duplicateAlias_item,
      { "Item", "h225.duplicateAlias_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "RegistrationRejectReason/duplicateAlias/_item", HFILL }},
    { &hf_h225_invalidTerminalType,
      { "invalidTerminalType", "h225.invalidTerminalType",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRejectReason/invalidTerminalType", HFILL }},
    { &hf_h225_transportNotSupported,
      { "transportNotSupported", "h225.transportNotSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRejectReason/transportNotSupported", HFILL }},
    { &hf_h225_transportQOSNotSupported,
      { "transportQOSNotSupported", "h225.transportQOSNotSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRejectReason/transportQOSNotSupported", HFILL }},
    { &hf_h225_invalidAlias,
      { "invalidAlias", "h225.invalidAlias",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRejectReason/invalidAlias", HFILL }},
    { &hf_h225_fullRegistrationRequired,
      { "fullRegistrationRequired", "h225.fullRegistrationRequired",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRejectReason/fullRegistrationRequired", HFILL }},
    { &hf_h225_additiveRegistrationNotSupported,
      { "additiveRegistrationNotSupported", "h225.additiveRegistrationNotSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRejectReason/additiveRegistrationNotSupported", HFILL }},
    { &hf_h225_invalidTerminalAliases,
      { "invalidTerminalAliases", "h225.invalidTerminalAliases",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegistrationRejectReason/invalidTerminalAliases", HFILL }},
    { &hf_h225_reg_securityError,
      { "securityError", "h225.securityError",
        FT_UINT32, BASE_DEC, VALS(h225_SecurityErrors_vals), 0,
        "RegistrationRejectReason/securityError", HFILL }},
    { &hf_h225_unregRequestReason,
      { "reason", "h225.reason",
        FT_UINT32, BASE_DEC, VALS(UnregRequestReason_vals), 0,
        "UnregistrationRequest/reason", HFILL }},
    { &hf_h225_endpointAliasPattern,
      { "endpointAliasPattern", "h225.endpointAliasPattern",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UnregistrationRequest/endpointAliasPattern", HFILL }},
    { &hf_h225_endpointAliasPattern_item,
      { "Item", "h225.endpointAliasPattern_item",
        FT_UINT32, BASE_DEC, VALS(h225_AddressPattern_vals), 0,
        "UnregistrationRequest/endpointAliasPattern/_item", HFILL }},
    { &hf_h225_reregistrationRequired,
      { "reregistrationRequired", "h225.reregistrationRequired",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnregRequestReason/reregistrationRequired", HFILL }},
    { &hf_h225_ttlExpired,
      { "ttlExpired", "h225.ttlExpired",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnregRequestReason/ttlExpired", HFILL }},
    { &hf_h225_maintenance,
      { "maintenance", "h225.maintenance",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnregRequestReason/maintenance", HFILL }},
    { &hf_h225_securityError,
      { "securityError", "h225.securityError",
        FT_UINT32, BASE_DEC, VALS(h225_SecurityErrors2_vals), 0,
        "", HFILL }},
    { &hf_h225_unregRejectReason,
      { "rejectReason", "h225.rejectReason",
        FT_UINT32, BASE_DEC, VALS(UnregRejectReason_vals), 0,
        "UnregistrationReject/rejectReason", HFILL }},
    { &hf_h225_notCurrentlyRegistered,
      { "notCurrentlyRegistered", "h225.notCurrentlyRegistered",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnregRejectReason/notCurrentlyRegistered", HFILL }},
    { &hf_h225_callInProgress,
      { "callInProgress", "h225.callInProgress",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnregRejectReason/callInProgress", HFILL }},
    { &hf_h225_permissionDenied,
      { "permissionDenied", "h225.permissionDenied",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnregRejectReason/permissionDenied", HFILL }},
    { &hf_h225_callModel,
      { "callModel", "h225.callModel",
        FT_UINT32, BASE_DEC, VALS(h225_CallModel_vals), 0,
        "", HFILL }},
    { &hf_h225_destinationInfo,
      { "destinationInfo", "h225.destinationInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_srcInfo,
      { "srcInfo", "h225.srcInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AdmissionRequest/srcInfo", HFILL }},
    { &hf_h225_srcInfo_item,
      { "Item", "h225.srcInfo_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "AdmissionRequest/srcInfo/_item", HFILL }},
    { &hf_h225_srcCallSignalAddress,
      { "srcCallSignalAddress", "h225.srcCallSignalAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "AdmissionRequest/srcCallSignalAddress", HFILL }},
    { &hf_h225_bandWidth,
      { "bandWidth", "h225.bandWidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_callReferenceValue,
      { "callReferenceValue", "h225.callReferenceValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_canMapAlias,
      { "canMapAlias", "h225.canMapAlias",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_h225_srcAlternatives,
      { "srcAlternatives", "h225.srcAlternatives",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AdmissionRequest/srcAlternatives", HFILL }},
    { &hf_h225_srcAlternatives_item,
      { "Item", "h225.srcAlternatives_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AdmissionRequest/srcAlternatives/_item", HFILL }},
    { &hf_h225_destAlternatives,
      { "destAlternatives", "h225.destAlternatives",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AdmissionRequest/destAlternatives", HFILL }},
    { &hf_h225_destAlternatives_item,
      { "Item", "h225.destAlternatives_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AdmissionRequest/destAlternatives/_item", HFILL }},
    { &hf_h225_transportQOS,
      { "transportQOS", "h225.transportQOS",
        FT_UINT32, BASE_DEC, VALS(h225_TransportQOS_vals), 0,
        "", HFILL }},
    { &hf_h225_gatewayDataRate,
      { "gatewayDataRate", "h225.gatewayDataRate",
        FT_NONE, BASE_NONE, NULL, 0,
        "AdmissionRequest/gatewayDataRate", HFILL }},
    { &hf_h225_desiredTunnelledProtocol,
      { "desiredTunnelledProtocol", "h225.desiredTunnelledProtocol",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_canMapSrcAlias,
      { "canMapSrcAlias", "h225.canMapSrcAlias",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_h225_DestinationInfo_item,
      { "Item", "h225.DestinationInfo_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "DestinationInfo/_item", HFILL }},
    { &hf_h225_pointToPoint,
      { "pointToPoint", "h225.pointToPoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallType/pointToPoint", HFILL }},
    { &hf_h225_oneToN,
      { "oneToN", "h225.oneToN",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallType/oneToN", HFILL }},
    { &hf_h225_nToOne,
      { "nToOne", "h225.nToOne",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallType/nToOne", HFILL }},
    { &hf_h225_nToN,
      { "nToN", "h225.nToN",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallType/nToN", HFILL }},
    { &hf_h225_direct,
      { "direct", "h225.direct",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallModel/direct", HFILL }},
    { &hf_h225_gatekeeperRouted,
      { "gatekeeperRouted", "h225.gatekeeperRouted",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallModel/gatekeeperRouted", HFILL }},
    { &hf_h225_endpointControlled,
      { "endpointControlled", "h225.endpointControlled",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransportQOS/endpointControlled", HFILL }},
    { &hf_h225_gatekeeperControlled,
      { "gatekeeperControlled", "h225.gatekeeperControlled",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransportQOS/gatekeeperControlled", HFILL }},
    { &hf_h225_noControl,
      { "noControl", "h225.noControl",
        FT_NONE, BASE_NONE, NULL, 0,
        "TransportQOS/noControl", HFILL }},
    { &hf_h225_irrFrequency,
      { "irrFrequency", "h225.irrFrequency",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AdmissionConfirm/irrFrequency", HFILL }},
    { &hf_h225_destinationType,
      { "destinationType", "h225.destinationType",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_uuiesRequested,
      { "uuiesRequested", "h225.uuiesRequested",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_supportedProtocols,
      { "supportedProtocols", "h225.supportedProtocols",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_supportedProtocols_item,
      { "Item", "h225.supportedProtocols_item",
        FT_UINT32, BASE_DEC, VALS(h225_SupportedProtocols_vals), 0,
        "", HFILL }},
    { &hf_h225_modifiedSrcInfo,
      { "modifiedSrcInfo", "h225.modifiedSrcInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_h225_modifiedSrcInfo_item,
      { "Item", "h225.modifiedSrcInfo_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "", HFILL }},
    { &hf_h225_setup_bool,
      { "setup", "h225.setup",
        FT_BOOLEAN, 8, NULL, 0,
        "UUIEsRequested/setup", HFILL }},
    { &hf_h225_callProceeding_flg,
      { "callProceeding", "h225.callProceeding",
        FT_BOOLEAN, 8, NULL, 0,
        "UUIEsRequested/callProceeding", HFILL }},
    { &hf_h225_connect_bool,
      { "connect", "h225.connect",
        FT_BOOLEAN, 8, NULL, 0,
        "UUIEsRequested/connect", HFILL }},
    { &hf_h225_alerting_bool,
      { "alerting", "h225.alerting",
        FT_BOOLEAN, 8, NULL, 0,
        "UUIEsRequested/alerting", HFILL }},
    { &hf_h225_information_bool,
      { "information", "h225.information",
        FT_BOOLEAN, 8, NULL, 0,
        "UUIEsRequested/information", HFILL }},
    { &hf_h225_releaseComplete_bool,
      { "releaseComplete", "h225.releaseComplete",
        FT_BOOLEAN, 8, NULL, 0,
        "UUIEsRequested/releaseComplete", HFILL }},
    { &hf_h225_facility_bool,
      { "facility", "h225.facility",
        FT_BOOLEAN, 8, NULL, 0,
        "UUIEsRequested/facility", HFILL }},
    { &hf_h225_progress_bool,
      { "progress", "h225.progress",
        FT_BOOLEAN, 8, NULL, 0,
        "UUIEsRequested/progress", HFILL }},
    { &hf_h225_empty,
      { "empty", "h225.empty",
        FT_BOOLEAN, 8, NULL, 0,
        "UUIEsRequested/empty", HFILL }},
    { &hf_h225_status_bool,
      { "status", "h225.status",
        FT_BOOLEAN, 8, NULL, 0,
        "UUIEsRequested/status", HFILL }},
    { &hf_h225_statusInquiry_bool,
      { "statusInquiry", "h225.statusInquiry",
        FT_BOOLEAN, 8, NULL, 0,
        "UUIEsRequested/statusInquiry", HFILL }},
    { &hf_h225_setupAcknowledge_bool,
      { "setupAcknowledge", "h225.setupAcknowledge",
        FT_BOOLEAN, 8, NULL, 0,
        "UUIEsRequested/setupAcknowledge", HFILL }},
    { &hf_h225_notify_bool,
      { "notify", "h225.notify",
        FT_BOOLEAN, 8, NULL, 0,
        "UUIEsRequested/notify", HFILL }},
    { &hf_h225_rejectReason,
      { "rejectReason", "h225.rejectReason",
        FT_UINT32, BASE_DEC, VALS(AdmissionRejectReason_vals), 0,
        "AdmissionReject/rejectReason", HFILL }},
    { &hf_h225_invalidPermission,
      { "invalidPermission", "h225.invalidPermission",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_requestDenied,
      { "requestDenied", "h225.requestDenied",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_invalidEndpointIdentifier,
      { "invalidEndpointIdentifier", "h225.invalidEndpointIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "AdmissionRejectReason/invalidEndpointIdentifier", HFILL }},
    { &hf_h225_qosControlNotSupported,
      { "qosControlNotSupported", "h225.qosControlNotSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "AdmissionRejectReason/qosControlNotSupported", HFILL }},
    { &hf_h225_incompleteAddress,
      { "incompleteAddress", "h225.incompleteAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_aliasesInconsistent,
      { "aliasesInconsistent", "h225.aliasesInconsistent",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_routeCallToSCN,
      { "routeCallToSCN", "h225.routeCallToSCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AdmissionRejectReason/routeCallToSCN", HFILL }},
    { &hf_h225_routeCallToSCN_item,
      { "Item", "h225.routeCallToSCN_item",
        FT_UINT32, BASE_DEC, VALS(h225_PartyNumber_vals), 0,
        "AdmissionRejectReason/routeCallToSCN/_item", HFILL }},
    { &hf_h225_exceedsCallCapacity,
      { "exceedsCallCapacity", "h225.exceedsCallCapacity",
        FT_NONE, BASE_NONE, NULL, 0,
        "AdmissionRejectReason/exceedsCallCapacity", HFILL }},
    { &hf_h225_collectDestination,
      { "collectDestination", "h225.collectDestination",
        FT_NONE, BASE_NONE, NULL, 0,
        "AdmissionRejectReason/collectDestination", HFILL }},
    { &hf_h225_collectPIN,
      { "collectPIN", "h225.collectPIN",
        FT_NONE, BASE_NONE, NULL, 0,
        "AdmissionRejectReason/collectPIN", HFILL }},
    { &hf_h225_noRouteToDestination,
      { "noRouteToDestination", "h225.noRouteToDestination",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_unallocatedNumber,
      { "unallocatedNumber", "h225.unallocatedNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_answeredCall,
      { "answeredCall", "h225.answeredCall",
        FT_BOOLEAN, 8, NULL, 0,
        "", HFILL }},
    { &hf_h225_usageInformation,
      { "usageInformation", "h225.usageInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_bandwidthDetails,
      { "bandwidthDetails", "h225.bandwidthDetails",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BandwidthRequest/bandwidthDetails", HFILL }},
    { &hf_h225_bandwidthDetails_item,
      { "Item", "h225.bandwidthDetails_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "BandwidthRequest/bandwidthDetails/_item", HFILL }},
    { &hf_h225_bandRejectReason,
      { "rejectReason", "h225.rejectReason",
        FT_UINT32, BASE_DEC, VALS(BandRejectReason_vals), 0,
        "BandwidthReject/rejectReason", HFILL }},
    { &hf_h225_allowedBandWidth,
      { "allowedBandWidth", "h225.allowedBandWidth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BandwidthReject/allowedBandWidth", HFILL }},
    { &hf_h225_notBound,
      { "notBound", "h225.notBound",
        FT_NONE, BASE_NONE, NULL, 0,
        "BandRejectReason/notBound", HFILL }},
    { &hf_h225_invalidConferenceID,
      { "invalidConferenceID", "h225.invalidConferenceID",
        FT_NONE, BASE_NONE, NULL, 0,
        "BandRejectReason/invalidConferenceID", HFILL }},
    { &hf_h225_insufficientResources,
      { "insufficientResources", "h225.insufficientResources",
        FT_NONE, BASE_NONE, NULL, 0,
        "BandRejectReason/insufficientResources", HFILL }},
    { &hf_h225_replyAddress,
      { "replyAddress", "h225.replyAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "", HFILL }},
    { &hf_h225_sourceInfo,
      { "sourceInfo", "h225.sourceInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocationRequest/sourceInfo", HFILL }},
    { &hf_h225_sourceInfo_item,
      { "Item", "h225.sourceInfo_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "LocationRequest/sourceInfo/_item", HFILL }},
    { &hf_h225_hopCount,
      { "hopCount", "h225.hopCount",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocationRequest/hopCount", HFILL }},
    { &hf_h225_sourceEndpointInfo,
      { "sourceEndpointInfo", "h225.sourceEndpointInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocationRequest/sourceEndpointInfo", HFILL }},
    { &hf_h225_sourceEndpointInfo_item,
      { "Item", "h225.sourceEndpointInfo_item",
        FT_UINT32, BASE_DEC, VALS(AliasAddress_vals), 0,
        "LocationRequest/sourceEndpointInfo/_item", HFILL }},
    { &hf_h225_locationConfirm_callSignalAddress,
      { "callSignalAddress", "h225.callSignalAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "LocationConfirm/callSignalAddress", HFILL }},
    { &hf_h225_locationConfirm_rasAddress,
      { "rasAddress", "h225.rasAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "LocationConfirm/rasAddress", HFILL }},
    { &hf_h225_locationRejectReason,
      { "rejectReason", "h225.rejectReason",
        FT_UINT32, BASE_DEC, VALS(LocationRejectReason_vals), 0,
        "LocationReject/rejectReason", HFILL }},
    { &hf_h225_notRegistered,
      { "notRegistered", "h225.notRegistered",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_h225_routeCalltoSCN,
      { "routeCalltoSCN", "h225.routeCalltoSCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocationRejectReason/routeCalltoSCN", HFILL }},
    { &hf_h225_routeCalltoSCN_item,
      { "Item", "h225.routeCalltoSCN_item",
        FT_UINT32, BASE_DEC, VALS(h225_PartyNumber_vals), 0,
        "LocationRejectReason/routeCalltoSCN/_item", HFILL }},
    { &hf_h225_disengageReason,
      { "disengageReason", "h225.disengageReason",
        FT_UINT32, BASE_DEC, VALS(DisengageReason_vals), 0,
        "DisengageRequest/disengageReason", HFILL }},
    { &hf_h225_terminationCause,
      { "terminationCause", "h225.terminationCause",
        FT_UINT32, BASE_DEC, VALS(h225_CallTerminationCause_vals), 0,
        "DisengageRequest/terminationCause", HFILL }},
    { &hf_h225_forcedDrop,
      { "forcedDrop", "h225.forcedDrop",
        FT_NONE, BASE_NONE, NULL, 0,
        "DisengageReason/forcedDrop", HFILL }},
    { &hf_h225_normalDrop,
      { "normalDrop", "h225.normalDrop",
        FT_NONE, BASE_NONE, NULL, 0,
        "DisengageReason/normalDrop", HFILL }},
    { &hf_h225_disengageRejectReason,
      { "rejectReason", "h225.rejectReason",
        FT_UINT32, BASE_DEC, VALS(DisengageRejectReason_vals), 0,
        "DisengageReject/rejectReason", HFILL }},
    { &hf_h225_requestToDropOther,
      { "requestToDropOther", "h225.requestToDropOther",
        FT_NONE, BASE_NONE, NULL, 0,
        "DisengageRejectReason/requestToDropOther", HFILL }},
    { &hf_h225_usageInfoRequested,
      { "usageInfoRequested", "h225.usageInfoRequested",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequest/usageInfoRequested", HFILL }},
    { &hf_h225_segmentedResponseSupported,
      { "segmentedResponseSupported", "h225.segmentedResponseSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequest/segmentedResponseSupported", HFILL }},
    { &hf_h225_nextSegmentRequested,
      { "nextSegmentRequested", "h225.nextSegmentRequested",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InfoRequest/nextSegmentRequested", HFILL }},
    { &hf_h225_capacityInfoRequested,
      { "capacityInfoRequested", "h225.capacityInfoRequested",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequest/capacityInfoRequested", HFILL }},
    { &hf_h225_infoRequestResponse_rasAddress,
      { "rasAddress", "h225.rasAddress",
        FT_UINT32, BASE_DEC, VALS(h225_TransportAddress_vals), 0,
        "InfoRequestResponse/rasAddress", HFILL }},
    { &hf_h225_perCallInfo,
      { "perCallInfo", "h225.perCallInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InfoRequestResponse/perCallInfo", HFILL }},
    { &hf_h225_perCallInfo_item,
      { "Item", "h225.perCallInfo_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item", HFILL }},
    { &hf_h225_originator,
      { "originator", "h225.originator",
        FT_BOOLEAN, 8, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/originator", HFILL }},
    { &hf_h225_audio,
      { "audio", "h225.audio",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/audio", HFILL }},
    { &hf_h225_audio_item,
      { "Item", "h225.audio_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/audio/_item", HFILL }},
    { &hf_h225_video,
      { "video", "h225.video",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/video", HFILL }},
    { &hf_h225_video_item,
      { "Item", "h225.video_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/video/_item", HFILL }},
    { &hf_h225_data,
      { "data", "h225.data",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/data", HFILL }},
    { &hf_h225_data_item,
      { "Item", "h225.data_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/data/_item", HFILL }},
    { &hf_h225_h245,
      { "h245", "h225.h245",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/h245", HFILL }},
    { &hf_h225_callSignaling,
      { "callSignaling", "h225.callSignaling",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/callSignaling", HFILL }},
    { &hf_h225_substituteConfIDs,
      { "substituteConfIDs", "h225.substituteConfIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/substituteConfIDs", HFILL }},
    { &hf_h225_substituteConfIDs_item,
      { "Item", "h225.substituteConfIDs_item",
        FT_GUID, BASE_NONE, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/substituteConfIDs/_item", HFILL }},
    { &hf_h225_pdu,
      { "pdu", "h225.pdu",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/pdu", HFILL }},
    { &hf_h225_pdu_item,
      { "Item", "h225.pdu_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/pdu/_item", HFILL }},
    { &hf_h225_h323pdu,
      { "h323pdu", "h225.h323pdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/pdu/_item/h323pdu", HFILL }},
    { &hf_h225_sent,
      { "sent", "h225.sent",
        FT_BOOLEAN, 8, NULL, 0,
        "InfoRequestResponse/perCallInfo/_item/pdu/_item/sent", HFILL }},
    { &hf_h225_needResponse,
      { "needResponse", "h225.needResponse",
        FT_BOOLEAN, 8, NULL, 0,
        "InfoRequestResponse/needResponse", HFILL }},
    { &hf_h225_irrStatus,
      { "irrStatus", "h225.irrStatus",
        FT_UINT32, BASE_DEC, VALS(h225_InfoRequestResponseStatus_vals), 0,
        "InfoRequestResponse/irrStatus", HFILL }},
    { &hf_h225_unsolicited,
      { "unsolicited", "h225.unsolicited",
        FT_BOOLEAN, 8, NULL, 0,
        "InfoRequestResponse/unsolicited", HFILL }},
    { &hf_h225_complete,
      { "complete", "h225.complete",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequestResponseStatus/complete", HFILL }},
    { &hf_h225_incomplete,
      { "incomplete", "h225.incomplete",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequestResponseStatus/incomplete", HFILL }},
    { &hf_h225_segment,
      { "segment", "h225.segment",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InfoRequestResponseStatus/segment", HFILL }},
    { &hf_h225_invalidCall,
      { "invalidCall", "h225.invalidCall",
        FT_NONE, BASE_NONE, NULL, 0,
        "InfoRequestResponseStatus/invalidCall", HFILL }},
    { &hf_h225_nakReason,
      { "nakReason", "h225.nakReason",
        FT_UINT32, BASE_DEC, VALS(InfoRequestNakReason_vals), 0,
        "InfoRequestNak/nakReason", HFILL }},
    { &hf_h225_messageNotUnderstood,
      { "messageNotUnderstood", "h225.messageNotUnderstood",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UnknownMessageResponse/messageNotUnderstood", HFILL }},
    { &hf_h225_delay,
      { "delay", "h225.delay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RequestInProgress/delay", HFILL }},
    { &hf_h225_protocols,
      { "protocols", "h225.protocols",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResourcesAvailableIndicate/protocols", HFILL }},
    { &hf_h225_protocols_item,
      { "Item", "h225.protocols_item",
        FT_UINT32, BASE_DEC, VALS(h225_SupportedProtocols_vals), 0,
        "ResourcesAvailableIndicate/protocols/_item", HFILL }},
    { &hf_h225_almostOutOfResources,
      { "almostOutOfResources", "h225.almostOutOfResources",
        FT_BOOLEAN, 8, NULL, 0,
        "ResourcesAvailableIndicate/almostOutOfResources", HFILL }},
    { &hf_h225_callSpecific,
      { "callSpecific", "h225.callSpecific",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceControlIndication/callSpecific", HFILL }},
    { &hf_h225_result,
      { "result", "h225.result",
        FT_UINT32, BASE_DEC, VALS(h225_T_result_vals), 0,
        "ServiceControlResponse/result", HFILL }},
    { &hf_h225_started,
      { "started", "h225.started",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceControlResponse/result/started", HFILL }},
    { &hf_h225_failed,
      { "failed", "h225.failed",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceControlResponse/result/failed", HFILL }},
    { &hf_h225_stopped,
      { "stopped", "h225.stopped",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceControlResponse/result/stopped", HFILL }},
    { &hf_h225_notAvailable,
      { "notAvailable", "h225.notAvailable",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceControlResponse/result/notAvailable", HFILL }},

/*--- End of included file: packet-h225-hfarr.c ---*/
#line 311 "packet-h225-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_h225,

/*--- Included file: packet-h225-ettarr.c ---*/
#line 1 "packet-h225-ettarr.c"
    &ett_h225_H323_UserInformation,
    &ett_h225_T_user_data,
    &ett_h225_H323_UU_PDU,
    &ett_h225_T_h323_message_body,
    &ett_h225_T_h4501SupplementaryService,
    &ett_h225_SEQUENCE_OF_NonStandardParameter,
    &ett_h225_T_tunnelledSignallingMessage,
    &ett_h225_T_messageContent,
    &ett_h225_SEQUENCE_OF_GenericData,
    &ett_h225_H245Control,
    &ett_h225_StimulusControl,
    &ett_h225_Alerting_UUIE,
    &ett_h225_SEQUENCE_OF_ClearToken,
    &ett_h225_SEQUENCE_OF_CryptoH323Token,
    &ett_h225_SEQUENCE_OF_AliasAddress,
    &ett_h225_SEQUENCE_OF_ServiceControlSession,
    &ett_h225_CallProceeding_UUIE,
    &ett_h225_Connect_UUIE,
    &ett_h225_Language,
    &ett_h225_Information_UUIE,
    &ett_h225_ReleaseComplete_UUIE,
    &ett_h225_ReleaseCompleteReason,
    &ett_h225_Setup_UUIE,
    &ett_h225_SEQUENCE_OF_CallReferenceValue,
    &ett_h225_T_conferenceGoal,
    &ett_h225_SEQUENCE_OF_H245Security,
    &ett_h225_T_connectionParameters,
    &ett_h225_SEQUENCE_OF_SupportedProtocols,
    &ett_h225_SEQUENCE_OF_FeatureDescriptor,
    &ett_h225_SEQUENCE_OF_ExtendedAliasAddress,
    &ett_h225_ParallelH245Control,
    &ett_h225_ScnConnectionType,
    &ett_h225_ScnConnectionAggregation,
    &ett_h225_PresentationIndicator,
    &ett_h225_Facility_UUIE,
    &ett_h225_SEQUENCE_OF_ConferenceList,
    &ett_h225_ConferenceList,
    &ett_h225_FacilityReason,
    &ett_h225_Progress_UUIE,
    &ett_h225_FastStart,
    &ett_h225_TransportAddress,
    &ett_h225_T_ipAddress,
    &ett_h225_T_ipSourceRoute,
    &ett_h225_T_route,
    &ett_h225_T_routing,
    &ett_h225_T_ipxAddress,
    &ett_h225_T_ip6Address,
    &ett_h225_H245TransportAddress,
    &ett_h225_T_h245ipAddress,
    &ett_h225_T_h245ipSourceRoute,
    &ett_h225_T_h245route,
    &ett_h225_T_h245routing,
    &ett_h225_T_h245ipxAddress,
    &ett_h225_T_h245ip6Address,
    &ett_h225_Status_UUIE,
    &ett_h225_StatusInquiry_UUIE,
    &ett_h225_SetupAcknowledge_UUIE,
    &ett_h225_Notify_UUIE,
    &ett_h225_EndpointType,
    &ett_h225_SEQUENCE_OF_TunnelledProtocol,
    &ett_h225_GatewayInfo,
    &ett_h225_SupportedProtocols,
    &ett_h225_H310Caps,
    &ett_h225_SEQUENCE_OF_DataRate,
    &ett_h225_SEQUENCE_OF_SupportedPrefix,
    &ett_h225_H320Caps,
    &ett_h225_H321Caps,
    &ett_h225_H322Caps,
    &ett_h225_H323Caps,
    &ett_h225_H324Caps,
    &ett_h225_VoiceCaps,
    &ett_h225_T120OnlyCaps,
    &ett_h225_NonStandardProtocol,
    &ett_h225_T38FaxAnnexbOnlyCaps,
    &ett_h225_SIPCaps,
    &ett_h225_McuInfo,
    &ett_h225_TerminalInfo,
    &ett_h225_GatekeeperInfo,
    &ett_h225_VendorIdentifier,
    &ett_h225_H221NonStandard,
    &ett_h225_TunnelledProtocol,
    &ett_h225_TunnelledProtocol_id,
    &ett_h225_TunnelledProtocolAlternateIdentifier,
    &ett_h225_NonStandardParameter,
    &ett_h225_NonStandardIdentifier,
    &ett_h225_AliasAddress,
    &ett_h225_AddressPattern,
    &ett_h225_T_range,
    &ett_h225_PartyNumber,
    &ett_h225_PublicPartyNumber,
    &ett_h225_PrivatePartyNumber,
    &ett_h225_PublicTypeOfNumber,
    &ett_h225_PrivateTypeOfNumber,
    &ett_h225_MobileUIM,
    &ett_h225_ANSI_41_UIM,
    &ett_h225_T_system_id,
    &ett_h225_GSM_UIM,
    &ett_h225_ExtendedAliasAddress,
    &ett_h225_Endpoint,
    &ett_h225_SEQUENCE_OF_TransportAddress,
    &ett_h225_AlternateTransportAddresses,
    &ett_h225_UseSpecifiedTransport,
    &ett_h225_AlternateGK,
    &ett_h225_AltGKInfo,
    &ett_h225_SEQUENCE_OF_AlternateGK,
    &ett_h225_SecurityServiceMode,
    &ett_h225_SecurityCapabilities,
    &ett_h225_SecurityErrors,
    &ett_h225_SecurityErrors2,
    &ett_h225_H245Security,
    &ett_h225_QseriesOptions,
    &ett_h225_Q954Details,
    &ett_h225_CallIdentifier,
    &ett_h225_EncryptIntAlg,
    &ett_h225_NonIsoIntegrityMechanism,
    &ett_h225_IntegrityMechanism,
    &ett_h225_ICV,
    &ett_h225_CryptoH323Token,
    &ett_h225_T_cryptoEPPwdHash,
    &ett_h225_T_cryptoGKPwdHash,
    &ett_h225_DataRate,
    &ett_h225_CallLinkage,
    &ett_h225_SupportedPrefix,
    &ett_h225_CapacityReportingCapability,
    &ett_h225_CapacityReportingSpecification,
    &ett_h225_CapacityReportingSpecification_when,
    &ett_h225_CallCapacity,
    &ett_h225_CallCapacityInfo,
    &ett_h225_SEQUENCE_OF_CallsAvailable,
    &ett_h225_CallsAvailable,
    &ett_h225_CircuitInfo,
    &ett_h225_CircuitIdentifier,
    &ett_h225_CicInfo,
    &ett_h225_T_cic,
    &ett_h225_GroupID,
    &ett_h225_T_member,
    &ett_h225_CarrierInfo,
    &ett_h225_ServiceControlDescriptor,
    &ett_h225_ServiceControlSession,
    &ett_h225_ServiceControlSession_reason,
    &ett_h225_RasUsageInfoTypes,
    &ett_h225_RasUsageSpecification,
    &ett_h225_RasUsageSpecification_when,
    &ett_h225_RasUsageSpecificationcallStartingPoint,
    &ett_h225_RasUsageInformation,
    &ett_h225_CallTerminationCause,
    &ett_h225_BandwidthDetails,
    &ett_h225_CallCreditCapability,
    &ett_h225_CallCreditServiceControl,
    &ett_h225_T_billingMode,
    &ett_h225_CallCreditServiceControl_callStartingPoint,
    &ett_h225_GenericData,
    &ett_h225_SEQUENCE_SIZE_1_512_OF_EnumeratedParameter,
    &ett_h225_GenericIdentifier,
    &ett_h225_EnumeratedParameter,
    &ett_h225_Content,
    &ett_h225_SEQUENCE_SIZE_1_16_OF_GenericData,
    &ett_h225_FeatureSet,
    &ett_h225_TransportChannelInfo,
    &ett_h225_RTPSession,
    &ett_h225_T_associatedSessionIds,
    &ett_h225_RasMessage,
    &ett_h225_SEQUENCE_OF_AdmissionConfirm,
    &ett_h225_GatekeeperRequest,
    &ett_h225_SEQUENCE_OF_Endpoint,
    &ett_h225_SEQUENCE_OF_AuthenticationMechanism,
    &ett_h225_T_algorithmOIDs,
    &ett_h225_SEQUENCE_OF_IntegrityMechanism,
    &ett_h225_GatekeeperConfirm,
    &ett_h225_GatekeeperReject,
    &ett_h225_GatekeeperRejectReason,
    &ett_h225_RegistrationRequest,
    &ett_h225_SEQUENCE_OF_AddressPattern,
    &ett_h225_SEQUENCE_OF_H248PackagesDescriptor,
    &ett_h225_RegistrationConfirm,
    &ett_h225_T_preGrantedARQ,
    &ett_h225_SEQUENCE_OF_RasUsageSpecification,
    &ett_h225_RegistrationReject,
    &ett_h225_RegistrationRejectReason,
    &ett_h225_T_invalidTerminalAliases,
    &ett_h225_UnregistrationRequest,
    &ett_h225_UnregRequestReason,
    &ett_h225_UnregistrationConfirm,
    &ett_h225_UnregistrationReject,
    &ett_h225_UnregRejectReason,
    &ett_h225_AdmissionRequest,
    &ett_h225_DestinationInfo,
    &ett_h225_CallType,
    &ett_h225_CallModel,
    &ett_h225_TransportQOS,
    &ett_h225_AdmissionConfirm,
    &ett_h225_UUIEsRequested,
    &ett_h225_AdmissionReject,
    &ett_h225_AdmissionRejectReason,
    &ett_h225_SEQUENCE_OF_PartyNumber,
    &ett_h225_BandwidthRequest,
    &ett_h225_SEQUENCE_OF_BandwidthDetails,
    &ett_h225_BandwidthConfirm,
    &ett_h225_BandwidthReject,
    &ett_h225_BandRejectReason,
    &ett_h225_LocationRequest,
    &ett_h225_LocationConfirm,
    &ett_h225_LocationReject,
    &ett_h225_LocationRejectReason,
    &ett_h225_DisengageRequest,
    &ett_h225_DisengageReason,
    &ett_h225_DisengageConfirm,
    &ett_h225_DisengageReject,
    &ett_h225_DisengageRejectReason,
    &ett_h225_InfoRequest,
    &ett_h225_InfoRequestResponse,
    &ett_h225_T_perCallInfo,
    &ett_h225_T_perCallInfo_item,
    &ett_h225_SEQUENCE_OF_RTPSession,
    &ett_h225_SEQUENCE_OF_TransportChannelInfo,
    &ett_h225_SEQUENCE_OF_ConferenceIdentifier,
    &ett_h225_T_pdu,
    &ett_h225_T_pdu_item,
    &ett_h225_InfoRequestResponseStatus,
    &ett_h225_InfoRequestAck,
    &ett_h225_InfoRequestNak,
    &ett_h225_InfoRequestNakReason,
    &ett_h225_NonStandardMessage,
    &ett_h225_UnknownMessageResponse,
    &ett_h225_RequestInProgress,
    &ett_h225_ResourcesAvailableIndicate,
    &ett_h225_ResourcesAvailableConfirm,
    &ett_h225_ServiceControlIndication,
    &ett_h225_T_callSpecific,
    &ett_h225_ServiceControlResponse,
    &ett_h225_T_result,

/*--- End of included file: packet-h225-ettarr.c ---*/
#line 317 "packet-h225-template.c"
  };
  module_t *h225_module;

  /* Register protocol */
  proto_h225 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_h225, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  h225_module = prefs_register_protocol(proto_h225, NULL);
  prefs_register_bool_preference(h225_module, "reassembly",
		"Reassemble H.225 messages spanning multiple TCP segments",
		"Whether the H.225 dissector should reassemble messages spanning multiple TCP segments."
		" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&h225_reassembly);
  prefs_register_bool_preference(h225_module, "h245_in_tree",
		"Display tunnelled H.245 inside H.225.0 tree",
		"ON - display tunnelled H.245 inside H.225.0 tree, OFF - display tunnelled H.245 in root tree after H.225.0",
		&h225_h245_in_tree);
  prefs_register_bool_preference(h225_module, "tp_in_tree",
		"Display tunnelled protocols inside H.225.0 tree",
		"ON - display tunnelled protocols inside H.225.0 tree, OFF - display tunnelled protocols in root tree after H.225.0",
		&h225_tp_in_tree);

  new_register_dissector("h225", dissect_h225_H323UserInformation, proto_h225);
  new_register_dissector("h323ui",dissect_h225_H323UserInformation, proto_h225);

  nsp_object_dissector_table = register_dissector_table("h225.nsp.object", "H.225 NonStandardParameter (object)", FT_STRING, BASE_NONE);
  nsp_h221_dissector_table = register_dissector_table("h225.nsp.h221", "H.225 NonStandardParameter (h221)", FT_UINT32, BASE_HEX);
  tp_dissector_table = register_dissector_table("h225.tp", "H.225 TunnelledProtocol", FT_STRING, BASE_NONE);

  register_init_routine(&h225_init_routine);
  h225_tap = register_tap("h225");
  add_oid_str_name("0.0.8.2250.0.2","itu-t(0) recommendation(0) h(8) h225-0(2250) version(0) 2");
  add_oid_str_name("0.0.8.2250.0.4","itu-t(0) recommendation(0) h(8) h225-0(2250) version(0) 4");


}


/*--- proto_reg_handoff_h225 ---------------------------------------*/
void
proto_reg_handoff_h225(void)
{
	h225ras_handle=new_create_dissector_handle(dissect_h225_h225_RasMessage, proto_h225);
	H323UserInformation_handle=find_dissector("h323ui");

	h245_handle = find_dissector("h245");
	h245dg_handle = find_dissector("h245dg");
	h4501_handle = find_dissector("h4501");
	data_handle = find_dissector("data");

	dissector_add("udp.port", UDP_PORT_RAS1, h225ras_handle);
	dissector_add("udp.port", UDP_PORT_RAS2, h225ras_handle);
}


static void reset_h225_packet_info(h225_packet_info *pi)
{
	if(pi == NULL) {
		return;
	}

	pi->msg_type = H225_OTHERS;
	pi->cs_type = H225_OTHER;
	pi->msg_tag = -1;
	pi->reason = -1;
	pi->requestSeqNum = 0;
	memset(&pi->guid,0,sizeof pi->guid);
	pi->is_duplicate = FALSE;
	pi->request_available = FALSE;
	pi->is_faststart = FALSE;
	pi->is_h245 = FALSE;
	pi->is_h245Tunneling = FALSE;
	pi->h245_address = 0;
	pi->h245_port = 0;
	pi->frame_label[0] = '\0';
	pi->dialedDigits[0] = '\0';
	pi->is_destinationInfo = FALSE;
}

/*
	The following function contains the routines for RAS request/response matching.
	A RAS response matches with a request, if both messages have the same
	RequestSequenceNumber, belong to the same IP conversation and belong to the same
	RAS "category" (e.g. Admission, Registration).

	We use hashtables to access the lists of RAS calls (request/response pairs).
	We have one hashtable for each RAS category. The hashkeys consist of the
	non-unique 16-bit RequestSequenceNumber and values representing the conversation.

	In big capture files, we might get different requests with identical keys.
	These requests aren't necessarily duplicates. They might be valid new requests.
	At the moment we just use the timedelta between the last valid and the new request
	to decide if the new request is a duplicate or not. There might be better ways.
	Two thresholds are defined below.

	However the decision is made, another problem arises. We can't just add those
	requests to our hashtables. Instead we create lists of RAS calls with identical keys.
	The hashtables for RAS calls contain now pointers to the first RAS call in a list of
	RAS calls with identical keys.
	These lists aren't expected to contain more than 3 items and are usually single item
	lists. So we don't need an expensive but intelligent way to access these lists
	(e.g. hashtables). Just walk through such a list.
*/

#define THRESHOLD_REPEATED_RESPONDED_CALL 300
#define THRESHOLD_REPEATED_NOT_RESPONDED_CALL 1800

static void ras_call_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, h225_packet_info *pi)
{
	conversation_t* conversation = NULL;
	h225ras_call_info_key h225ras_call_key;
	h225ras_call_t *h225ras_call = NULL;
	nstime_t delta;
	guint msg_category;

	if(pi->msg_type == H225_RAS && pi->msg_tag < 21) {
		/* make RAS request/response matching only for tags from 0 to 20 for now */

		msg_category = pi->msg_tag / 3;
		if(pi->msg_tag % 3 == 0) {		/* Request Message */
			conversation = find_conversation(pinfo->fd->num, &pinfo->src,
				&pinfo->dst, pinfo->ptype, pinfo->srcport,
				pinfo->destport, 0);

			if (conversation == NULL) {
				/* It's not part of any conversation - create a new one. */
				conversation = conversation_new(pinfo->fd->num, &pinfo->src,
				    &pinfo->dst, pinfo->ptype, pinfo->srcport,
				    pinfo->destport, 0);

			}

			/* prepare the key data */
			h225ras_call_key.reqSeqNum = pi->requestSeqNum;
			h225ras_call_key.conversation = conversation;

			/* look up the request */
			h225ras_call = find_h225ras_call(&h225ras_call_key ,msg_category);

			if (h225ras_call != NULL) {
				/* We've seen requests with this reqSeqNum, with the same
				   source and destination, before - do we have
				   *this* request already? */
				/* Walk through list of ras requests with identical keys */
				do {
					if (pinfo->fd->num == h225ras_call->req_num) {
						/* We have seen this request before -> do nothing */
						break;
					}

					/* if end of list is reached, exit loop and decide if request is duplicate or not. */
					if (h225ras_call->next_call == NULL) {
						if ( (pinfo->fd->num > h225ras_call->rsp_num && h225ras_call->rsp_num != 0
						   && pinfo->fd->abs_ts.secs > (h225ras_call->req_time.secs + THRESHOLD_REPEATED_RESPONDED_CALL) )
						   ||(pinfo->fd->num > h225ras_call->req_num && h225ras_call->rsp_num == 0
						   && pinfo->fd->abs_ts.secs > (h225ras_call->req_time.secs + THRESHOLD_REPEATED_NOT_RESPONDED_CALL) ) )
						{
							/* if last request has been responded
							   and this request appears after last response (has bigger frame number)
							   and last request occured more than 300 seconds ago,
							   or if last request hasn't been responded
							   and this request appears after last request (has bigger frame number)
							   and last request occured more than 1800 seconds ago,
							   we decide that we have a new request */
							/* Append new ras call to list */
							h225ras_call = append_h225ras_call(h225ras_call, pinfo, &pi->guid, msg_category);
						} else {
							/* No, so it's a duplicate request.
							   Mark it as such. */
							pi->is_duplicate = TRUE;
							proto_tree_add_uint_hidden(tree, hf_h225_ras_dup, tvb, 0,0, pi->requestSeqNum);
						}
						break;
					}
					h225ras_call = h225ras_call->next_call;
				} while (h225ras_call != NULL );
			}
			else {
				h225ras_call = new_h225ras_call(&h225ras_call_key, pinfo, &pi->guid, msg_category);
			}

			/* add link to response frame, if available */
			if(h225ras_call->rsp_num != 0){
				proto_item *ti =
				proto_tree_add_uint_format(tree, hf_h225_ras_rsp_frame, tvb, 0, 0, h225ras_call->rsp_num,
					                           "The response to this request is in frame %u",
					                           h225ras_call->rsp_num);
				PROTO_ITEM_SET_GENERATED(ti);
			}

  		/* end of request message handling*/
		}
		else { 					/* Confirm or Reject Message */
			conversation = find_conversation(pinfo->fd->num, &pinfo->src,
    				&pinfo->dst, pinfo->ptype, pinfo->srcport,
  				pinfo->destport, 0);
  			if (conversation != NULL) {
				/* look only for matching request, if
				   matching conversation is available. */
				h225ras_call_key.reqSeqNum = pi->requestSeqNum;
				h225ras_call_key.conversation = conversation;
				h225ras_call = find_h225ras_call(&h225ras_call_key ,msg_category);
				if(h225ras_call) {
					/* find matching ras_call in list of ras calls with identical keys */
					do {
						if (pinfo->fd->num == h225ras_call->rsp_num) {
							/* We have seen this response before -> stop now with matching ras call */
							break;
						}

						/* Break when list end is reached */
						if(h225ras_call->next_call == NULL) {
							break;
						}
						h225ras_call = h225ras_call->next_call;
					} while (h225ras_call != NULL) ;

					/* if this is an ACF, ARJ or DCF, DRJ, give guid to tap and make it filterable */
					if (msg_category == 3 || msg_category == 5) {
						pi->guid = h225ras_call->guid;
						proto_tree_add_guid_hidden(tree, hf_h225_guid, tvb, 0, GUID_LEN, &pi->guid);
					}

					if (h225ras_call->rsp_num == 0) {
						/* We have not yet seen a response to that call, so
						   this must be the first response; remember its
						   frame number. */
						h225ras_call->rsp_num = pinfo->fd->num;
					}
					else {
						/* We have seen a response to this call - but was it
						   *this* response? */
						if (h225ras_call->rsp_num != pinfo->fd->num) {
							/* No, so it's a duplicate response.
							   Mark it as such. */
							pi->is_duplicate = TRUE;
							proto_tree_add_uint_hidden(tree, hf_h225_ras_dup, tvb, 0,0, pi->requestSeqNum);
						}
					}

					if(h225ras_call->req_num != 0){
						proto_item *ti;
						h225ras_call->responded = TRUE;
						pi->request_available = TRUE;

						/* Indicate the frame to which this is a reply. */
						ti = proto_tree_add_uint_format(tree, hf_h225_ras_req_frame, tvb, 0, 0, h225ras_call->req_num,
							"This is a response to a request in frame %u", h225ras_call->req_num);
						PROTO_ITEM_SET_GENERATED(ti);

						/* Calculate RAS Service Response Time */
						nstime_delta(&delta, &pinfo->fd->abs_ts, &h225ras_call->req_time);
						pi->delta_time = delta; /* give it to tap */

						/* display Ras Service Response Time and make it filterable */
						ti = proto_tree_add_time(tree, hf_h225_ras_deltatime, tvb, 0, 0, &(pi->delta_time));
						PROTO_ITEM_SET_GENERATED(ti);
					}
				}
			}
		}
	}
}





