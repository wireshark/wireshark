/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-gsm_map.c                                                         */
/* ../../tools/asn2eth.py -X -b -e -p gsm_map -c gsmmap.cnf -s packet-gsm_map-template GSMMAP.asn */

/* Input file: packet-gsm_map-template.c */

/* packet-gsm_map-template.c
 * Routines for GSM MobileApplication packet dissection
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
 * Based on the dissector by:
 * Felix Fei <felix.fei [AT] utstar.com>
 * and Michael Lum <mlum [AT] telostech.com>
 *
 * $Id$
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
 * References: ETSI TS 129 002
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/tap.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-q931.h"
#include "packet-gsm_map.h"

#define PNAME  "GSM_MobileAPplication"
#define PSNAME "GSM_MAP"
#define PFNAME "gsm_map"

/* Initialize the protocol and registered fields */
int proto_gsm_map = -1;
static int hf_gsm_map_invokeCmd = -1;             /* Opcode */
static int hf_gsm_map_invokeid = -1;              /* INTEGER */
static int hf_gsm_map_absent = -1;                /* NULL */
static int hf_gsm_map_invokeId = -1;              /* InvokeId */
static int hf_gsm_map_invoke = -1;                /* InvokePDU */
static int hf_gsm_map_returnResult = -1;          /* InvokePDU */
static int hf_gsm_map_returnResult_result = -1;
static int hf_gsm_map_returnError = -1;
static int hf_gsm_map_SendAuthenticationInfoArg = -1;
static int hf_gsm_mapSendEndSignal = -1;
static int hf_gsm_map_getPassword = -1;  
static int hf_gsm_map_currentPassword = -1;
static int hf_gsm_map_extension = -1;
static int hf_gsm_map_nature_of_number = -1;
static int hf_gsm_map_number_plan = -1;
static int hf_gsm_map_misdn_digits = -1;
static int hf_gsm_map_servicecentreaddress_digits = -1;
static int hf_gsm_map_imsi_digits = -1;
static int hf_gsm_map_map_gmsc_address_digits = -1;
static int hf_gsm_map_map_RoamingNumber_digits = -1;
static int hf_gsm_map_map_hlr_number_digits = -1;
static int hf_gsm_map_Ss_Status_unused = -1;
static int hf_gsm_map_Ss_Status_q_bit = -1;
static int hf_gsm_map_Ss_Status_p_bit = -1;
static int hf_gsm_map_Ss_Status_r_bit = -1;
static int hf_gsm_map_Ss_Status_a_bit = -1;


/*--- Included file: packet-gsm_map-hf.c ---*/

static int hf_gsm_map_protocolId = -1;            /* ProtocolId */
static int hf_gsm_map_signalInfo = -1;            /* SignalInfo */
static int hf_gsm_map_extensionContainer = -1;    /* ExtensionContainer */
static int hf_gsm_map_accessNetworkProtocolId = -1;  /* T_accessNetworkProtocolId */
static int hf_gsm_map_signalInfo2 = -1;           /* SignalInfo2 */
static int hf_gsm_map_supportedCamelPhases = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_solsaSupportIndicator = -1;  /* NULL */
static int hf_gsm_map_imsi = -1;                  /* Imsi */
static int hf_gsm_map_msc_Number = -1;            /* Msc_Number */
static int hf_gsm_map_vlr_Number = -1;            /* Vlr_Number */
static int hf_gsm_map_lmsi = -1;                  /* Lmsi */
static int hf_gsm_map_vlr_Capability = -1;        /* Vlr_Capability */
static int hf_gsm_map_hlr_Number = -1;            /* Hlr_Number */
static int hf_gsm_map_PrivateExtensionList_item = -1;  /* PrivateExtension */
static int hf_gsm_map_extId = -1;                 /* OBJECT_IDENTIFIER */
static int hf_gsm_map_extType = -1;               /* OCTET_STRING */
static int hf_gsm_map_identity = -1;              /* T_identity */
static int hf_gsm_map_imsi_WithLMSI = -1;         /* T_imsi_WithLMSI */
static int hf_gsm_map_cancellationType = -1;      /* CancellationType */
static int hf_gsm_map_sgsn_Number = -1;           /* Sgsn_Number */
static int hf_gsm_map_freezeTMSI = -1;            /* NULL */
static int hf_gsm_map_freezeP_TMSI = -1;          /* NULL */
static int hf_gsm_map_authenticationSetList = -1;  /* T_authenticationSetList */
static int hf_gsm_map_authenticationSetList_item = -1;  /* T_authenticationSetList_item */
static int hf_gsm_map_rand = -1;                  /* OCTET_STRING_SIZE_16 */
static int hf_gsm_map_sres = -1;                  /* OCTET_STRING_SIZE_4 */
static int hf_gsm_map_kc = -1;                    /* OCTET_STRING_SIZE_8 */
static int hf_gsm_map_targetCellId = -1;          /* OCTET_STRING_SIZE_5_7 */
static int hf_gsm_map_ho_NumberNotRequired = -1;  /* NULL */
static int hf_gsm_map_bss_APDU = -1;              /* Bss_APDU */
static int hf_gsm_map_handoverNumber = -1;        /* T_handoverNumber */
static int hf_gsm_map_an_APDU = -1;               /* An_APDU */
static int hf_gsm_map_targetMSC_Number = -1;      /* T_targetMSC_Number */
static int hf_gsm_map_numberOfRequestedVectors = -1;  /* INTEGER_1_5 */
static int hf_gsm_map_segmentationProhibited = -1;  /* NULL */
static int hf_gsm_map_immediateResponsePreferred = -1;  /* NULL */
static int hf_gsm_map_re_synchronisationInfo = -1;  /* T_re_synchronisationInfo */
static int hf_gsm_map_auts = -1;                  /* OCTET_STRING_SIZE_14 */
static int hf_gsm_map_requestingNodeType = -1;    /* T_requestingNodeType */
static int hf_gsm_map_requestingPLMN_Id = -1;     /* OCTET_STRING_SIZE_3 */
static int hf_gsm_map_SendAuthenticationInfoRes_item = -1;  /* SendAuthenticationInfoRes_item */
static int hf_gsm_map_bearerService = -1;         /* OCTET_STRING */
static int hf_gsm_map_teleservice = -1;           /* Teleservice */
static int hf_gsm_map_BasicServiceGroupList_item = -1;  /* BasicService */
static int hf_gsm_map_bcsmTriggerDetectionPoint = -1;  /* BcsmTriggerDetectionPoint */
static int hf_gsm_map_serviceKey = -1;            /* ServiceKey */
static int hf_gsm_map_gsmSCFAddress = -1;         /* GsmSCF_Address */
static int hf_gsm_map_defaultCallHandling = -1;   /* DefaultCallHandling */
static int hf_gsm_map_BcsmCamelTDPDataList_item = -1;  /* BcsmCamelTDPData */
static int hf_gsm_map_o_BcsmCamelTDPDataList = -1;  /* BcsmCamelTDPDataList */
static int hf_gsm_map_camelCapabilityHandling = -1;  /* INTEGER_1_16 */
static int hf_gsm_map_msisdn = -1;                /* Msisdn */
static int hf_gsm_map_category = -1;              /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_subscriberStatus = -1;      /* SubscriberStatus */
static int hf_gsm_map_bearerServiceList = -1;     /* bearerServiceList */
static int hf_gsm_map_bearerServiceList_item = -1;  /* OCTET_STRING_SIZE_1_5 */
static int hf_gsm_map_teleserviceList = -1;       /* SEQUENCE_SIZE_1_20_OF_Teleservice */
static int hf_gsm_map_teleserviceList_item = -1;  /* Teleservice */
static int hf_gsm_map_provisionedSS = -1;         /* T_provisionedSS */
static int hf_gsm_map_provisionedSS_item = -1;    /* T_provisionedSS_item */
static int hf_gsm_map_forwardingInfo = -1;        /* ForwardingInfo */
static int hf_gsm_map_callBarringInfo = -1;       /* CallBarringInfo */
static int hf_gsm_map_cug_Info = -1;              /* T_cug_Info */
static int hf_gsm_map_cug_SubscriptionList = -1;  /* T_cug_SubscriptionList */
static int hf_gsm_map_cug_SubscriptionList_item = -1;  /* T_cug_SubscriptionList_item */
static int hf_gsm_map_cug_Index = -1;             /* INTEGER_0_32767 */
static int hf_gsm_map_cug_Interlock = -1;         /* OCTET_STRING_SIZE_4 */
static int hf_gsm_map_intraCUG_Options = -1;      /* IntraCUG_Options */
static int hf_gsm_map_basicServiceGroupList = -1;  /* BasicServiceGroupList */
static int hf_gsm_map_cug_FeatureList = -1;       /* T_cug_FeatureList */
static int hf_gsm_map_cug_FeatureList_item = -1;  /* T_cug_FeatureList_item */
static int hf_gsm_map_basicService = -1;          /* BasicService */
static int hf_gsm_map_preferentialCUG_Indicator = -1;  /* INTEGER_0_32767 */
static int hf_gsm_map_interCUG_Restrictions = -1;  /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_ss_Data2 = -1;              /* T_ss_Data2 */
static int hf_gsm_map_ss_Code = -1;               /* Ss_Code */
static int hf_gsm_map_ss_Status = -1;             /* Ss_Status */
static int hf_gsm_map_ss_SubscriptionOption = -1;  /* Ss_SubscriptionOption */
static int hf_gsm_map_emlpp_Info = -1;            /* T_emlpp_Info */
static int hf_gsm_map_maximumentitledPriority = -1;  /* INTEGER_0_15 */
static int hf_gsm_map_defaultPriority = -1;       /* INTEGER_0_15 */
static int hf_gsm_map_odb_Data = -1;              /* T_odb_Data */
static int hf_gsm_map_odb_GeneralData = -1;       /* Odb_GeneralData */
static int hf_gsm_map_odb_HPLMN_Data = -1;        /* Odb_HPLMN_Data */
static int hf_gsm_map_roamingRestrictionDueToUnsupportedFeature = -1;  /* NULL */
static int hf_gsm_map_regionalSubscriptionData = -1;  /* T_regionalSubscriptionData */
static int hf_gsm_map_regionalSubscriptionData_item = -1;  /* OCTET_STRING_SIZE_2 */
static int hf_gsm_map_vbsSubscriptionData = -1;   /* T_vbsSubscriptionData */
static int hf_gsm_map_vbsSubscriptionData_item = -1;  /* T_vbsSubscriptionData_item */
static int hf_gsm_map_groupid = -1;               /* OCTET_STRING_SIZE_3 */
static int hf_gsm_map_broadcastInitEntitlement = -1;  /* NULL */
static int hf_gsm_map_vgcsSubscriptionData = -1;  /* T_vgcsSubscriptionData */
static int hf_gsm_map_vgcsSubscriptionData_item = -1;  /* T_vgcsSubscriptionData_item */
static int hf_gsm_map_groupId = -1;               /* OCTET_STRING_SIZE_3 */
static int hf_gsm_map_vlrCamelSubscriptionInfo = -1;  /* T_vlrCamelSubscriptionInfo */
static int hf_gsm_map_o_CSI = -1;                 /* O_CSI */
static int hf_gsm_map_ss_CSI = -1;                /* T_ss_CSI */
static int hf_gsm_map_ss_CamelData = -1;          /* T_ss_CamelData */
static int hf_gsm_map_ss_EventList = -1;          /* T_ss_EventList */
static int hf_gsm_map_ss_EventList_item = -1;     /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_gsmSCF_Address = -1;        /* GsmSCF_Address */
static int hf_gsm_map_o_BcsmCamelTDP_CriteriaList = -1;  /* O_BcsmCamelTDP_CriteriaList */
static int hf_gsm_map_tif_CSI = -1;               /* NULL */
static int hf_gsm_map_naea_PreferredCI = -1;      /* Naea_PreferredCI */
static int hf_gsm_map_gprsSubscriptionData = -1;  /* T_gprsSubscriptionData */
static int hf_gsm_map_completeDataListIncluded = -1;  /* NULL */
static int hf_gsm_map_gprsDataList = -1;          /* T_gprsDataList */
static int hf_gsm_map_gprsDataList_item = -1;     /* T_gprsDataList_item */
static int hf_gsm_map_pdp_ContextId = -1;         /* INTEGER_1_50 */
static int hf_gsm_map_pdp_Type = -1;              /* OCTET_STRING_SIZE_2 */
static int hf_gsm_map_pdp_Address = -1;           /* OCTET_STRING_SIZE_1_16 */
static int hf_gsm_map_qos_Subscribed = -1;        /* OCTET_STRING_SIZE_3 */
static int hf_gsm_map_vplmnAddressAllowed = -1;   /* NULL */
static int hf_gsm_map_apn = -1;                   /* OCTET_STRING_SIZE_2_63 */
static int hf_gsm_map_roamingRestrictedInSgsnDueToUnsupportedFeature = -1;  /* NULL */
static int hf_gsm_map_networkAccessMode = -1;     /* T_networkAccessMode */
static int hf_gsm_map_lsaInformation = -1;        /* T_lsaInformation */
static int hf_gsm_map_lsaOnlyAccessIndicator = -1;  /* T_lsaOnlyAccessIndicator */
static int hf_gsm_map_lsaDataList = -1;           /* T_lsaDataList */
static int hf_gsm_map_lsaDataList_item = -1;      /* T_lsaDataList_item */
static int hf_gsm_map_lsaIdentity = -1;           /* OCTET_STRING_SIZE_3 */
static int hf_gsm_map_lsaAttributes = -1;         /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_lsaActiveModeIndicator = -1;  /* NULL */
static int hf_gsm_map_lmu_Indicator = -1;         /* NULL */
static int hf_gsm_map_lcsInformation = -1;        /* T_lcsInformation */
static int hf_gsm_map_gmlc_List = -1;             /* T_gmlc_List */
static int hf_gsm_map_gmlc_List_item = -1;        /* T_gmlc_List_item */
static int hf_gsm_map_lcs_PrivacyExceptionList = -1;  /* T_lcs_PrivacyExceptionList */
static int hf_gsm_map_lcs_PrivacyExceptionList_item = -1;  /* T_lcs_PrivacyExceptionList_item */
static int hf_gsm_map_notificationToMSUser = -1;  /* NotificationToMSUser */
static int hf_gsm_map_externalClientList = -1;    /* T_externalClientList */
static int hf_gsm_map_externalClientList_item = -1;  /* T_externalClientList_item */
static int hf_gsm_map_clientIdentity = -1;        /* T_clientIdentity */
static int hf_gsm_map_externalAddress = -1;       /* OCTET_STRING_SIZE_1_20 */
static int hf_gsm_map_gmlc_Restriction = -1;      /* T_gmlc_Restriction */
static int hf_gsm_map_plmnClientList = -1;        /* T_plmnClientList */
static int hf_gsm_map_plmnClientList_item = -1;   /* T_plmnClientList_item */
static int hf_gsm_map_molr_List = -1;             /* T_molr_List */
static int hf_gsm_map_molr_List_item = -1;        /* T_molr_List_item */
static int hf_gsm_map_ss_List = -1;               /* ss_List */
static int hf_gsm_map_ss_List_item = -1;          /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_regionalSubscriptionResponse = -1;  /* RegionalSubscriptionResponse */
static int hf_gsm_map_callBarringFeatureList = -1;  /* T_callBarringFeatureList */
static int hf_gsm_map_callBarringFeatureList_item = -1;  /* T_callBarringFeatureList_item */
static int hf_gsm_map_forwardedToNumber = -1;     /* ForwardedToNumber */
static int hf_gsm_map_forwardedToSubaddress = -1;  /* ForwardedToSubaddress */
static int hf_gsm_map_forwardingOptions = -1;     /* ForwardingOptions */
static int hf_gsm_map_noReplyConditionTime = -1;  /* INTEGER */
static int hf_gsm_map_matchType = -1;             /* MatchType */
static int hf_gsm_map_destinationNumberList = -1;  /* T_destinationNumberList */
static int hf_gsm_map_destinationNumberList_item = -1;  /* T_destinationNumberList_item */
static int hf_gsm_map_destinationNumberLengthList = -1;  /* T_destinationNumberLengthList */
static int hf_gsm_map_destinationNumberLengthList_item = -1;  /* INTEGER_1_15 */
static int hf_gsm_map_forwardingFeatureList_1_32 = -1;  /* SEQUENCE_SIZE_1_32_OF_ForwardingFeatureList */
static int hf_gsm_map_forwardingFeatureList_item = -1;  /* ForwardingFeatureList */
static int hf_gsm_map_naea_PreferredCIC = -1;     /* OCTET_STRING_SIZE_3 */
static int hf_gsm_map_O_BcsmCamelTDP_CriteriaList_item = -1;  /* O_BcsmCamelTDP_CriteriaList_item */
static int hf_gsm_map_o_BcsmTriggerDetectionPoint = -1;  /* BcsmTriggerDetectionPoint */
static int hf_gsm_map_destinationNumberCriteria = -1;  /* DestinationNumberCriteria */
static int hf_gsm_map_basicServiceCriteria = -1;  /* BasicServiceGroupList */
static int hf_gsm_map_callTypeCriteria = -1;      /* CallTypeCriteria */
static int hf_gsm_map_cliRestrictionOption = -1;  /* CliRestrictionOption */
static int hf_gsm_map_overrideCategory = -1;      /* OverrideCategory */
static int hf_gsm_map_basicServiceList = -1;      /* BasicServiceGroupList */
static int hf_gsm_map_regionalSubscriptionIdentifier = -1;  /* OCTET_STRING_SIZE_2 */
static int hf_gsm_map_vbsGroupIndication = -1;    /* NULL */
static int hf_gsm_map_vgcsGroupIndication = -1;   /* NULL */
static int hf_gsm_map_camelSubscriptionInfoWithdraw = -1;  /* NULL */
static int hf_gsm_map_gprsSubscriptionDataWithdraw = -1;  /* T_gprsSubscriptionDataWithdraw */
static int hf_gsm_map_allGPRSData = -1;           /* NULL */
static int hf_gsm_map_contextIdList = -1;         /* T_contextIdList */
static int hf_gsm_map_contextIdList_item = -1;    /* INTEGER_1_50 */
static int hf_gsm_map_roamingRestrictedInSgsnDueToUnsuppportedFeature = -1;  /* NULL */
static int hf_gsm_map_lsaInformationWithdraw = -1;  /* T_lsaInformationWithdraw */
static int hf_gsm_map_allLSAData = -1;            /* NULL */
static int hf_gsm_map_lsaIdentityList = -1;       /* T_lsaIdentityList */
static int hf_gsm_map_lsaIdentityList_item = -1;  /* OCTET_STRING_SIZE_3 */
static int hf_gsm_map_gmlc_ListWithdraw = -1;     /* NULL */
static int hf_gsm_map_hlr_List = -1;              /* T_hlr_List */
static int hf_gsm_map_hlr_List_item = -1;         /* OCTET_STRING_SIZE_3_8 */
static int hf_gsm_map_msNotReachable = -1;        /* NULL */
static int hf_gsm_map_traceReference = -1;        /* OCTET_STRING_SIZE_1_2 */
static int hf_gsm_map_traceType = -1;             /* INTEGER_0_255 */
static int hf_gsm_map_omc_Id = -1;                /* OCTET_STRING_SIZE_1_20 */
static int hf_gsm_map_cug_CheckInfo = -1;         /* Cug_CheckInfo */
static int hf_gsm_map_numberOfForwarding = -1;    /* INTEGER_1_5 */
static int hf_gsm_map_interrogationType = -1;     /* T_interrogationType */
static int hf_gsm_map_or_Interrogation = -1;      /* NULL */
static int hf_gsm_map_or_Capability = -1;         /* INTEGER_1_127 */
static int hf_gsm_map_gmsc_Address = -1;          /* Gmsc_Address */
static int hf_gsm_map_callReferenceNumber = -1;   /* OCTET_STRING_SIZE_1_8 */
static int hf_gsm_map_forwardingReason = -1;      /* T_forwardingReason */
static int hf_gsm_map_basicServiceGroup = -1;     /* BasicService */
static int hf_gsm_map_networkSignalInfo = -1;     /* Bss_APDU */
static int hf_gsm_map_camelInfo = -1;             /* T_camelInfo */
static int hf_gsm_map_suppress_T_CSI = -1;        /* NULL */
static int hf_gsm_map_suppressionOfAnnouncement = -1;  /* NULL */
static int hf_gsm_map_alertingPattern = -1;       /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_ccbs_Call = -1;             /* NULL */
static int hf_gsm_map_supportedCCBS_Phase = -1;   /* INTEGER_1_127 */
static int hf_gsm_map_additionalSignalInfo = -1;  /* AdditionalSignalInfo */
static int hf_gsm_map_extendedRoutingInfo = -1;   /* T_extendedRoutingInfo */
static int hf_gsm_map_routingInfo = -1;           /* T_routingInfo */
static int hf_gsm_map_roamingNumber = -1;         /* RoamingNumber */
static int hf_gsm_map_forwardingData = -1;        /* ForwardingData */
static int hf_gsm_map_camelRoutingInfo = -1;      /* T_camelRoutingInfo */
static int hf_gsm_map_gmscCamelSubscriptionInfo = -1;  /* T_gmscCamelSubscriptionInfo */
static int hf_gsm_map_t_CSI = -1;                 /* T_t_CSI */
static int hf_gsm_map_t_BcsmCamelTDPDataList = -1;  /* BcsmCamelTDPDataList */
static int hf_gsm_map_cugSubscriptionFlag = -1;   /* NULL */
static int hf_gsm_map_subscriberInfo = -1;        /* SubscriberInfo */
static int hf_gsm_map_forwardingInterrogationRequired = -1;  /* NULL */
static int hf_gsm_map_vmsc_Address = -1;          /* T_vmsc_Address */
static int hf_gsm_map_ccbs_Indicators = -1;       /* T_ccbs_Indicators */
static int hf_gsm_map_ccbs_Possible = -1;         /* NULL */
static int hf_gsm_map_keepCCBS_CallIndicator = -1;  /* NULL */
static int hf_gsm_map_numberPortabilityStatus = -1;  /* T_numberPortabilityStatus */
static int hf_gsm_map_assumedIdle = -1;           /* NULL */
static int hf_gsm_map_camelBusy = -1;             /* NULL */
static int hf_gsm_map_notProvidedFromVLR = -1;    /* NULL */
static int hf_gsm_map_ageOfLocationInformation = -1;  /* INTEGER_0_32767 */
static int hf_gsm_map_geographicalInformation = -1;  /* OCTET_STRING_SIZE_8 */
static int hf_gsm_map_vlr_number = -1;            /* Vlr_Number */
static int hf_gsm_map_locationNumber = -1;        /* OCTET_STRING_SIZE_2_10 */
static int hf_gsm_map_cellIdOrLAI = -1;           /* T_cellIdOrLAI */
static int hf_gsm_map_cellIdFixedLength = -1;     /* OCTET_STRING_SIZE_7 */
static int hf_gsm_map_laiFixedLength = -1;        /* OCTET_STRING_SIZE_5 */
static int hf_gsm_map_locationInformation = -1;   /* LocationInformation */
static int hf_gsm_map_subscriberState = -1;       /* SubscriberState */
static int hf_gsm_map_ext_ProtocolId = -1;        /* T_ext_ProtocolId */
static int hf_gsm_map_ext_signalInfo = -1;        /* ExtSignalInfo */
static int hf_gsm_map_cug_OutgoingAccess = -1;    /* NULL */
static int hf_gsm_map_gsm_BearerCapability = -1;  /* Bss_APDU */
static int hf_gsm_map_supportedCamelPhasesInGMSC = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_orNotSupportedInGMSC = -1;  /* NULL */
static int hf_gsm_map_uu_Data = -1;               /* T_uu_Data */
static int hf_gsm_map_uuIndicator = -1;           /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_uui = -1;                   /* OCTET_STRING_SIZE_1_131 */
static int hf_gsm_map_uusCFInteraction = -1;      /* NULL */
static int hf_gsm_map_allInformationSent = -1;    /* NULL */
static int hf_gsm_map_isdn_BearerCapability = -1;  /* Bss_APDU */
static int hf_gsm_map_call_Direction = -1;        /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_b_Subscriber_Address = -1;  /* T_b_Subscriber_Address */
static int hf_gsm_map_chosenChannel = -1;         /* Bss_APDU */
static int hf_gsm_map_lowerLayerCompatibility = -1;  /* Bss_APDU */
static int hf_gsm_map_highLayerCompatibility = -1;  /* Bss_APDU */
static int hf_gsm_map_sIWFSNumber = -1;           /* T_sIWFSNumber */
static int hf_gsm_map_channelType = -1;           /* Bss_APDU */
static int hf_gsm_map_ccbs_Monitoring = -1;       /* Ccbs_Monitoring */
static int hf_gsm_map_ccbs_SubscriberStatus = -1;  /* Ccbs_SubscriberStatus */
static int hf_gsm_map_eventReportData = -1;       /* T_eventReportData */
static int hf_gsm_map_callReportdata = -1;        /* T_callReportdata */
static int hf_gsm_map_monitoringMode = -1;        /* MonitoringMode */
static int hf_gsm_map_callOutcome = -1;           /* CallOutcome */
static int hf_gsm_map_callInfo = -1;              /* Bss_APDU */
static int hf_gsm_map_ccbs_Feature = -1;          /* Ccbs_Feature */
static int hf_gsm_map_translatedB_Number = -1;    /* TranslatedB_Number */
static int hf_gsm_map_replaceB_Number = -1;       /* NULL */
static int hf_gsm_map_ruf_Outcome = -1;           /* Ruf_Outcome */
static int hf_gsm_map_ss_Data = -1;               /* Ss_Data */
static int hf_gsm_map_ccbs_Index = -1;            /* INTEGER_1_5 */
static int hf_gsm_map_b_subscriberNumber = -1;    /* B_subscriberNumber */
static int hf_gsm_map_b_subscriberSubaddress = -1;  /* OCTET_STRING_SIZE_1_21 */
static int hf_gsm_map_forwardingFeatureList = -1;  /* SEQUENCE_SIZE_1_13_OF_ForwardingFeatureList */
static int hf_gsm_map_genericServiceInfo = -1;    /* T_genericServiceInfo */
static int hf_gsm_map_maximumEntitledPriority = -1;  /* INTEGER_0_15 */
static int hf_gsm_map_ccbs_FeatureList = -1;      /* T_ccbs_FeatureList */
static int hf_gsm_map_ccbs_FeatureList_item = -1;  /* T_ccbs_FeatureList_item */
static int hf_gsm_map_ussd_DataCodingScheme = -1;  /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_ussd_String = -1;           /* OCTET_STRING_SIZE_1_160 */
static int hf_gsm_map_ccbs_Data = -1;             /* T_ccbs_Data */
static int hf_gsm_map_serviceIndicator = -1;      /* ServiceIndicator */
static int hf_gsm_map_sm_RP_PRI = -1;             /* BOOLEAN */
static int hf_gsm_map_serviceCentreAddress = -1;  /* ServiceCentreAddress */
static int hf_gsm_map_gprsSupportIndicator = -1;  /* NULL */
static int hf_gsm_map_sm_RP_MTI = -1;             /* INTEGER_0_10 */
static int hf_gsm_map_sm_RP_SMEA = -1;            /* OCTET_STRING_SIZE_1_12 */
static int hf_gsm_map_locationInfoWithLMSI = -1;  /* T_locationInfoWithLMSI */
static int hf_gsm_map_networkNode_Number = -1;    /* T_networkNode_Number */
static int hf_gsm_map_gprsNodeIndicator = -1;     /* NULL */
static int hf_gsm_map_additional_Number = -1;     /* T_additional_Number */
static int hf_gsm_map_sm_RP_DA = -1;              /* Sm_RP_DA */
static int hf_gsm_map_sm_RP_OA = -1;              /* Sm_RP_OA */
static int hf_gsm_map_sm_RP_UI = -1;              /* Sm_RP_UI */
static int hf_gsm_map_serviceCentreAddressOA = -1;  /* ServiceCentreAddress */
static int hf_gsm_map_noSM_RP_OA = -1;            /* NULL */
static int hf_gsm_map_serviceCentreAddressDA = -1;  /* ServiceCentreAddress */
static int hf_gsm_map_noSM_RP_DA = -1;            /* NULL */
static int hf_gsm_map_moreMessagesToSend = -1;    /* NULL */
static int hf_gsm_map_sm_DeliveryOutcome = -1;    /* Sm_DeliveryOutcome */
static int hf_gsm_map_absentSubscriberDiagnosticSM = -1;  /* INTEGER_0_255 */
static int hf_gsm_map_deliveryOutcomeIndicator = -1;  /* NULL */
static int hf_gsm_map_additionalSM_DeliveryOutcome = -1;  /* Sm_DeliveryOutcome */
static int hf_gsm_map_additionalAbsentSubscriberDiagnosticSM = -1;  /* INTEGER_0_255 */
static int hf_gsm_map_storedMSISDN = -1;          /* StoredMSISDN */
static int hf_gsm_map_mw_Status = -1;             /* T_mw_Status */
static int hf_gsm_map_alertReason = -1;           /* T_alertReason */
static int hf_gsm_map_alertReasonIndicator = -1;  /* NULL */
static int hf_gsm_map_requestedInfo = -1;         /* RequestedInfo */
static int hf_gsm_map_locationInformationFlag = -1;  /* NULL */
static int hf_gsm_map_subscriberStateFlag = -1;   /* NULL */
static int hf_gsm_map_subscriberIdentity = -1;    /* T_subscriberIdentity */
static int hf_gsm_map_ss_Event = -1;              /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_ss_EventSpecification = -1;  /* T_ss_EventSpecification */
static int hf_gsm_map_ss_EventSpecification_item = -1;  /* OCTET_STRING_SIZE_1_20 */
static int hf_gsm_map_asciCallReference = -1;     /* OCTET_STRING_SIZE_1_8 */
static int hf_gsm_map_codec_Info = -1;            /* OCTET_STRING_SIZE_5_10 */
static int hf_gsm_map_cipheringAlgorithm = -1;    /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_groupKeyNumber = -1;        /* INTEGER_0_15 */
static int hf_gsm_map_groupKey = -1;              /* OCTET_STRING_SIZE_8 */
static int hf_gsm_map_priority = -1;              /* INTEGER_0_15 */
static int hf_gsm_map_uplinkFree = -1;            /* NULL */
static int hf_gsm_map_groupCallNumber = -1;       /* T_groupCallNumber */
static int hf_gsm_map_uplinkRequest = -1;         /* NULL */
static int hf_gsm_map_uplinkReleaseIndication = -1;  /* NULL */
static int hf_gsm_map_releaseGroupCall = -1;      /* NULL */
static int hf_gsm_map_uplinkRequestAck = -1;      /* NULL */
static int hf_gsm_map_uplinkRejectCommand = -1;   /* NULL */
static int hf_gsm_map_uplinkSeizedCommand = -1;   /* NULL */
static int hf_gsm_map_uplinkReleaseCommand = -1;  /* NULL */
static int hf_gsm_map_sgsn_Address = -1;          /* OCTET_STRING_SIZE_5_17 */
static int hf_gsm_map_sgsn_Capability = -1;       /* T_sgsn_Capability */
static int hf_gsm_map_ggsn_Address = -1;          /* Ggsn_Address */
static int hf_gsm_map_ggsn_Number = -1;           /* Ggsn_Number */
static int hf_gsm_map_mobileNotReachableReason = -1;  /* INTEGER_0_255 */
static int hf_gsm_map_dataCodingScheme = -1;      /* OCTET_STRING */
static int hf_gsm_map_nameString = -1;            /* OCTET_STRING */
static int hf_gsm_map_lcsClientType = -1;         /* LcsClientType */
static int hf_gsm_map_lcsClientExternalID = -1;   /* LcsClientExternalID */
static int hf_gsm_map_lcsClientDialedByMS = -1;   /* OCTET_STRING */
static int hf_gsm_map_lcsClientInternalID = -1;   /* LcsClientInternalID */
static int hf_gsm_map_lcsClientName = -1;         /* LcsClientName */
static int hf_gsm_map_locationType = -1;          /* T_locationType */
static int hf_gsm_map_locationEstimateType = -1;  /* T_locationEstimateType */
static int hf_gsm_map_mlc_Number = -1;            /* T_mlc_Number */
static int hf_gsm_map_lcs_ClientID = -1;          /* Lcs_ClientID */
static int hf_gsm_map_privacyOverride = -1;       /* NULL */
static int hf_gsm_map_imei = -1;                  /* Imei */
static int hf_gsm_map_lcs_Priority = -1;          /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_lcs_QoS = -1;               /* T_lcs_QoS */
static int hf_gsm_map_horizontal_accuracy = -1;   /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_verticalCoordinateRequest = -1;  /* NULL */
static int hf_gsm_map_vertical_accuracy = -1;     /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_responseTime = -1;          /* T_responseTime */
static int hf_gsm_map_responseTimeCategory = -1;  /* T_responseTimeCategory */
static int hf_gsm_map_locationEstimate = -1;      /* OCTET_STRING_SIZE_1_20 */
static int hf_gsm_map_ageOfLocationEstimate = -1;  /* INTEGER_0_32767 */
static int hf_gsm_map_mlcNumber = -1;             /* T_mlcNumber */
static int hf_gsm_map_targetMS = -1;              /* TargetMS */
static int hf_gsm_map_lcsLocationInfo = -1;       /* LcsLocationInfo */
static int hf_gsm_map_lcs_Event = -1;             /* Lcs_Event */
static int hf_gsm_map_na_ESRD = -1;               /* T_na_ESRD */
static int hf_gsm_map_na_ESRK = -1;               /* T_na_ESRK */
static int hf_gsm_map_networkResource = -1;       /* NetworkResource */
static int hf_gsm_map_extensibleSystemFailureParam = -1;  /* T_extensibleSystemFailureParam */
static int hf_gsm_map_unknownSubscriberDiagnostic = -1;  /* T_unknownSubscriberDiagnostic */
static int hf_gsm_map_roamingNotAllowedCause = -1;  /* T_roamingNotAllowedCause */
static int hf_gsm_map_absentSubscriberReason = -1;  /* T_absentSubscriberReason */
static int hf_gsm_map_ccbs_Busy = -1;             /* NULL */
static int hf_gsm_map_callBarringCause = -1;      /* CallBarringCause */
static int hf_gsm_map_extensibleCallBarredParam = -1;  /* T_extensibleCallBarredParam */
static int hf_gsm_map_unauthorisedMessageOriginator = -1;  /* NULL */
static int hf_gsm_map_cug_RejectCause = -1;       /* T_cug_RejectCause */
static int hf_gsm_map_gprsConnectionSuspended = -1;  /* NULL */
static int hf_gsm_map_sm_EnumeratedDeliveryFailureCause = -1;  /* T_sm_EnumeratedDeliveryFailureCause */
static int hf_gsm_map_diagnosticInfo = -1;        /* OCTET_STRING_SIZE_1_200 */
static int hf_gsm_map_unauthorizedLCSClient_Diagnostic = -1;  /* T_unauthorizedLCSClient_Diagnostic */
static int hf_gsm_map_positionMethodFailure_Diagnostic = -1;  /* T_positionMethodFailure_Diagnostic */
static int hf_gsm_map_privateExtensionList = -1;  /* PrivateExtensionList */
static int hf_gsm_map_pcsExtensions = -1;         /* PcsExtensions */
/* named bits */
static int hf_gsm_map_SupportedCamelPhases_phase1 = -1;
static int hf_gsm_map_SupportedCamelPhases_phase2 = -1;
static int hf_gsm_map_Odb_GeneralData_allOGCallsBarred = -1;
static int hf_gsm_map_Odb_GeneralData_internationalOGCallsBarred = -1;
static int hf_gsm_map_Odb_GeneralData_internationalOGCallsNotToHPLMNCountryBarred = -1;
static int hf_gsm_map_Odb_GeneralData_premiumRateInformationOGCallsBarred = -1;
static int hf_gsm_map_Odb_GeneralData_premiumRateEntertainementOGCallsBarred = -1;
static int hf_gsm_map_Odb_GeneralData_ssAccessBarred = -1;
static int hf_gsm_map_Odb_GeneralData_interzonalOGCallsBarred = -1;
static int hf_gsm_map_Odb_GeneralData_interzonalOGCallsNotToHPLMNCountryBarred = -1;
static int hf_gsm_map_Odb_GeneralData_interzonalOGCallsAndIntOGCallsNotToHPLMNCountryBarred = -1;
static int hf_gsm_map_Odb_GeneralData_allECTBarred = -1;
static int hf_gsm_map_Odb_GeneralData_chargeableECTBarred = -1;
static int hf_gsm_map_Odb_GeneralData_internationalECTBarred = -1;
static int hf_gsm_map_Odb_GeneralData_interzonalECTBarred = -1;
static int hf_gsm_map_Odb_GeneralData_doublyChargeableECTBarred = -1;
static int hf_gsm_map_Odb_GeneralData_multipleECTBarred = -1;
static int hf_gsm_map_Odb_HPLMN_Data_plmnSpecificBarringType1 = -1;
static int hf_gsm_map_Odb_HPLMN_Data_plmnSpecificBarringType2 = -1;
static int hf_gsm_map_Odb_HPLMN_Data_plmnSpecificBarringType3 = -1;
static int hf_gsm_map_Odb_HPLMN_Data_plmnSpecificBarringType4 = -1;
static int hf_gsm_map_ServiceIndicator_clirInvoked = -1;
static int hf_gsm_map_ServiceIndicator_camelInvoked = -1;
static int hf_gsm_map_T_mw_Status_scAddressNotIncluded = -1;
static int hf_gsm_map_T_mw_Status_mnrfSet = -1;
static int hf_gsm_map_T_mw_Status_mcefSet = -1;
static int hf_gsm_map_T_mw_Status_mnrgSet = -1;

/*--- End of included file: packet-gsm_map-hf.c ---*/


/* Initialize the subtree pointers */
static gint ett_gsm_map = -1;
static gint ett_gsm_map_InvokeId = -1;
static gint ett_gsm_map_InvokePDU = -1;
static gint ett_gsm_map_ReturnResultPDU = -1;
static gint ett_gsm_map_ReturnErrorPDU = -1;
static gint ett_gsm_map_ReturnResult_result = -1;
static gint ett_gsm_map_ReturnError_result = -1;
static gint ett_gsm_map_GSMMAPPDU = -1;


/*--- Included file: packet-gsm_map-ett.c ---*/

static gint ett_gsm_map_Bss_APDU = -1;
static gint ett_gsm_map_An_APDU = -1;
static gint ett_gsm_map_SupportedCamelPhases = -1;
static gint ett_gsm_map_Vlr_Capability = -1;
static gint ett_gsm_map_UpdateLocationArg = -1;
static gint ett_gsm_map_UpdateLocationRes = -1;
static gint ett_gsm_map_PrivateExtensionList = -1;
static gint ett_gsm_map_PrivateExtension = -1;
static gint ett_gsm_map_PcsExtensions = -1;
static gint ett_gsm_map_CancelLocationArg = -1;
static gint ett_gsm_map_T_identity = -1;
static gint ett_gsm_map_T_imsi_WithLMSI = -1;
static gint ett_gsm_map_CancelLocationRes = -1;
static gint ett_gsm_map_PurgeMS_Arg = -1;
static gint ett_gsm_map_PurgeMS_Res = -1;
static gint ett_gsm_map_SendIdentificationRes = -1;
static gint ett_gsm_map_T_authenticationSetList = -1;
static gint ett_gsm_map_T_authenticationSetList_item = -1;
static gint ett_gsm_map_PrepareHO_Arg = -1;
static gint ett_gsm_map_PrepareHO_Res = -1;
static gint ett_gsm_map_SendEndSignalV9Arg = -1;
static gint ett_gsm_map_PrepareSubsequentHO_Arg = -1;
static gint ett_gsm_map_SendAuthenticationInfoArgV3 = -1;
static gint ett_gsm_map_T_re_synchronisationInfo = -1;
static gint ett_gsm_map_SendAuthenticationInfoRes = -1;
static gint ett_gsm_map_SendAuthenticationInfoRes_item = -1;
static gint ett_gsm_map_BasicService = -1;
static gint ett_gsm_map_BasicServiceGroupList = -1;
static gint ett_gsm_map_Odb_GeneralData = -1;
static gint ett_gsm_map_Odb_HPLMN_Data = -1;
static gint ett_gsm_map_BcsmCamelTDPData = -1;
static gint ett_gsm_map_BcsmCamelTDPDataList = -1;
static gint ett_gsm_map_O_CSI = -1;
static gint ett_gsm_map_InsertSubscriberDataArg = -1;
static gint ett_gsm_map_bearerServiceList = -1;
static gint ett_gsm_map_SEQUENCE_SIZE_1_20_OF_Teleservice = -1;
static gint ett_gsm_map_T_provisionedSS = -1;
static gint ett_gsm_map_T_provisionedSS_item = -1;
static gint ett_gsm_map_T_cug_Info = -1;
static gint ett_gsm_map_T_cug_SubscriptionList = -1;
static gint ett_gsm_map_T_cug_SubscriptionList_item = -1;
static gint ett_gsm_map_T_cug_FeatureList = -1;
static gint ett_gsm_map_T_cug_FeatureList_item = -1;
static gint ett_gsm_map_T_ss_Data2 = -1;
static gint ett_gsm_map_T_emlpp_Info = -1;
static gint ett_gsm_map_T_odb_Data = -1;
static gint ett_gsm_map_T_regionalSubscriptionData = -1;
static gint ett_gsm_map_T_vbsSubscriptionData = -1;
static gint ett_gsm_map_T_vbsSubscriptionData_item = -1;
static gint ett_gsm_map_T_vgcsSubscriptionData = -1;
static gint ett_gsm_map_T_vgcsSubscriptionData_item = -1;
static gint ett_gsm_map_T_vlrCamelSubscriptionInfo = -1;
static gint ett_gsm_map_T_ss_CSI = -1;
static gint ett_gsm_map_T_ss_CamelData = -1;
static gint ett_gsm_map_T_ss_EventList = -1;
static gint ett_gsm_map_T_gprsSubscriptionData = -1;
static gint ett_gsm_map_T_gprsDataList = -1;
static gint ett_gsm_map_T_gprsDataList_item = -1;
static gint ett_gsm_map_T_lsaInformation = -1;
static gint ett_gsm_map_T_lsaDataList = -1;
static gint ett_gsm_map_T_lsaDataList_item = -1;
static gint ett_gsm_map_T_lcsInformation = -1;
static gint ett_gsm_map_T_gmlc_List = -1;
static gint ett_gsm_map_T_lcs_PrivacyExceptionList = -1;
static gint ett_gsm_map_T_lcs_PrivacyExceptionList_item = -1;
static gint ett_gsm_map_T_externalClientList = -1;
static gint ett_gsm_map_T_externalClientList_item = -1;
static gint ett_gsm_map_T_clientIdentity = -1;
static gint ett_gsm_map_T_plmnClientList = -1;
static gint ett_gsm_map_T_molr_List = -1;
static gint ett_gsm_map_T_molr_List_item = -1;
static gint ett_gsm_map_InsertSubscriberDataRes = -1;
static gint ett_gsm_map_ss_List = -1;
static gint ett_gsm_map_CallBarringInfo = -1;
static gint ett_gsm_map_T_callBarringFeatureList = -1;
static gint ett_gsm_map_T_callBarringFeatureList_item = -1;
static gint ett_gsm_map_ForwardingFeatureList = -1;
static gint ett_gsm_map_DestinationNumberCriteria = -1;
static gint ett_gsm_map_T_destinationNumberList = -1;
static gint ett_gsm_map_T_destinationNumberLengthList = -1;
static gint ett_gsm_map_ForwardingInfo = -1;
static gint ett_gsm_map_SEQUENCE_SIZE_1_32_OF_ForwardingFeatureList = -1;
static gint ett_gsm_map_Naea_PreferredCI = -1;
static gint ett_gsm_map_O_BcsmCamelTDP_CriteriaList = -1;
static gint ett_gsm_map_O_BcsmCamelTDP_CriteriaList_item = -1;
static gint ett_gsm_map_Ss_SubscriptionOption = -1;
static gint ett_gsm_map_DeleteSubscriberDataArg = -1;
static gint ett_gsm_map_T_gprsSubscriptionDataWithdraw = -1;
static gint ett_gsm_map_T_contextIdList = -1;
static gint ett_gsm_map_T_lsaInformationWithdraw = -1;
static gint ett_gsm_map_T_lsaIdentityList = -1;
static gint ett_gsm_map_DeleteSubscriberDataRes = -1;
static gint ett_gsm_map_ResetArg = -1;
static gint ett_gsm_map_T_hlr_List = -1;
static gint ett_gsm_map_RestoreDataArg = -1;
static gint ett_gsm_map_RestoreDataRes = -1;
static gint ett_gsm_map_ActivateTraceModeArg = -1;
static gint ett_gsm_map_ActivateTraceModeRes = -1;
static gint ett_gsm_map_DeactivateTraceModeArg = -1;
static gint ett_gsm_map_DeactivateTraceModeRes = -1;
static gint ett_gsm_map_SendRoutingInfoArg = -1;
static gint ett_gsm_map_T_camelInfo = -1;
static gint ett_gsm_map_SendRoutingInfoRes = -1;
static gint ett_gsm_map_T_extendedRoutingInfo = -1;
static gint ett_gsm_map_T_routingInfo = -1;
static gint ett_gsm_map_T_camelRoutingInfo = -1;
static gint ett_gsm_map_T_gmscCamelSubscriptionInfo = -1;
static gint ett_gsm_map_T_t_CSI = -1;
static gint ett_gsm_map_T_ccbs_Indicators = -1;
static gint ett_gsm_map_SubscriberState = -1;
static gint ett_gsm_map_LocationInformation = -1;
static gint ett_gsm_map_T_cellIdOrLAI = -1;
static gint ett_gsm_map_SubscriberInfo = -1;
static gint ett_gsm_map_AdditionalSignalInfo = -1;
static gint ett_gsm_map_Cug_CheckInfo = -1;
static gint ett_gsm_map_ForwardingData = -1;
static gint ett_gsm_map_ProvideRoamingNumberArg = -1;
static gint ett_gsm_map_ProvideRoamingNumberRes = -1;
static gint ett_gsm_map_ResumeCallHandlingArg = -1;
static gint ett_gsm_map_T_uu_Data = -1;
static gint ett_gsm_map_ResumeCallHandlingRes = -1;
static gint ett_gsm_map_ProvideSIWFSNumberArg = -1;
static gint ett_gsm_map_ProvideSIWFSNumberRes = -1;
static gint ett_gsm_map_SIWFSSignallingModifyArg = -1;
static gint ett_gsm_map_SIWFSSignallingModifyRes = -1;
static gint ett_gsm_map_SetReportingStateArg = -1;
static gint ett_gsm_map_SetReportingStateRes = -1;
static gint ett_gsm_map_StatusReportArg = -1;
static gint ett_gsm_map_T_eventReportData = -1;
static gint ett_gsm_map_T_callReportdata = -1;
static gint ett_gsm_map_StatusReportRes = -1;
static gint ett_gsm_map_RemoteUserFreeArg = -1;
static gint ett_gsm_map_RemoteUserFreeRes = -1;
static gint ett_gsm_map_Ss_Data = -1;
static gint ett_gsm_map_RegisterSS_Arg = -1;
static gint ett_gsm_map_Ss_Info = -1;
static gint ett_gsm_map_Ccbs_Feature = -1;
static gint ett_gsm_map_Ss_ForBS = -1;
static gint ett_gsm_map_InterrogateSS_Res = -1;
static gint ett_gsm_map_SEQUENCE_SIZE_1_13_OF_ForwardingFeatureList = -1;
static gint ett_gsm_map_T_genericServiceInfo = -1;
static gint ett_gsm_map_T_ccbs_FeatureList = -1;
static gint ett_gsm_map_T_ccbs_FeatureList_item = -1;
static gint ett_gsm_map_Ussd_Arg = -1;
static gint ett_gsm_map_Ussd_Res = -1;
static gint ett_gsm_map_ServiceIndicator = -1;
static gint ett_gsm_map_RegisterCC_EntryArg = -1;
static gint ett_gsm_map_T_ccbs_Data = -1;
static gint ett_gsm_map_RegisterCC_EntryRes = -1;
static gint ett_gsm_map_EraseCC_EntryArg = -1;
static gint ett_gsm_map_EraseCC_EntryRes = -1;
static gint ett_gsm_map_RoutingInfoForSMArg = -1;
static gint ett_gsm_map_RoutingInfoForSMRes = -1;
static gint ett_gsm_map_T_locationInfoWithLMSI = -1;
static gint ett_gsm_map_T_additional_Number = -1;
static gint ett_gsm_map_Mo_forwardSM_Arg = -1;
static gint ett_gsm_map_Mo_forwardSM_Res = -1;
static gint ett_gsm_map_Sm_RP_OA = -1;
static gint ett_gsm_map_Sm_RP_DA = -1;
static gint ett_gsm_map_Mt_forwardSM_Arg = -1;
static gint ett_gsm_map_Mt_forwardSM_Res = -1;
static gint ett_gsm_map_ReportSM_DeliveryStatusArg = -1;
static gint ett_gsm_map_ReportSM_DeliveryStatusRes = -1;
static gint ett_gsm_map_InformServiceCentreArg = -1;
static gint ett_gsm_map_T_mw_Status = -1;
static gint ett_gsm_map_AlertServiceCentreArg = -1;
static gint ett_gsm_map_ReadyForSM_Arg = -1;
static gint ett_gsm_map_ReadyForSM_Res = -1;
static gint ett_gsm_map_ProvideSubscriberInfoArg = -1;
static gint ett_gsm_map_ProvideSubscriberInfoRes = -1;
static gint ett_gsm_map_RequestedInfo = -1;
static gint ett_gsm_map_AnyTimeInterrogationArg = -1;
static gint ett_gsm_map_T_subscriberIdentity = -1;
static gint ett_gsm_map_AnyTimeInterrogationRes = -1;
static gint ett_gsm_map_Ss_InvocationNotificationArg = -1;
static gint ett_gsm_map_T_ss_EventSpecification = -1;
static gint ett_gsm_map_Ss_InvocationNotificationRes = -1;
static gint ett_gsm_map_PrepareGroupCallArg = -1;
static gint ett_gsm_map_PrepareGroupCallRes = -1;
static gint ett_gsm_map_SendGroupCallEndSignalArg = -1;
static gint ett_gsm_map_SendGroupCallEndSignalRes = -1;
static gint ett_gsm_map_ProcessGroupCallSignallingArg = -1;
static gint ett_gsm_map_ForwardGroupCallSignallingArg = -1;
static gint ett_gsm_map_UpdateGprsLocationArg = -1;
static gint ett_gsm_map_T_sgsn_Capability = -1;
static gint ett_gsm_map_UpdateGprsLocationRes = -1;
static gint ett_gsm_map_SendRoutingInfoForGprsArg = -1;
static gint ett_gsm_map_SendRoutingInfoForGprsRes = -1;
static gint ett_gsm_map_FailureReportArg = -1;
static gint ett_gsm_map_FailureReportRes = -1;
static gint ett_gsm_map_NoteMsPresentForGprsArg = -1;
static gint ett_gsm_map_NoteMsPresentForGprsRes = -1;
static gint ett_gsm_map_LcsClientExternalID = -1;
static gint ett_gsm_map_LcsClientName = -1;
static gint ett_gsm_map_Lcs_ClientID = -1;
static gint ett_gsm_map_LcsLocationInfo = -1;
static gint ett_gsm_map_ProvideSubscriberLocation_Arg = -1;
static gint ett_gsm_map_T_locationType = -1;
static gint ett_gsm_map_T_lcs_QoS = -1;
static gint ett_gsm_map_T_responseTime = -1;
static gint ett_gsm_map_ProvideSubscriberLocation_Res = -1;
static gint ett_gsm_map_TargetMS = -1;
static gint ett_gsm_map_RoutingInfoForLCS_Arg = -1;
static gint ett_gsm_map_RoutingInfoForLCS_Res = -1;
static gint ett_gsm_map_SubscriberLocationReport_Arg = -1;
static gint ett_gsm_map_SubscriberLocationReport_Res = -1;
static gint ett_gsm_map_SystemFailureParam = -1;
static gint ett_gsm_map_T_extensibleSystemFailureParam = -1;
static gint ett_gsm_map_DataMissingParam = -1;
static gint ett_gsm_map_UnexpectedDataParam = -1;
static gint ett_gsm_map_FacilityNotSupParam = -1;
static gint ett_gsm_map_IncompatibleTerminalParam = -1;
static gint ett_gsm_map_ResourceLimitationParam = -1;
static gint ett_gsm_map_UnknownSubscriberParam = -1;
static gint ett_gsm_map_NumberChangedParam = -1;
static gint ett_gsm_map_UnidentifiedSubParam = -1;
static gint ett_gsm_map_RoamingNotAllowedParam = -1;
static gint ett_gsm_map_IllegalSubscriberParam = -1;
static gint ett_gsm_map_IllegalEquipmentParam = -1;
static gint ett_gsm_map_BearerServNotProvParam = -1;
static gint ett_gsm_map_TeleservNotProvParam = -1;
static gint ett_gsm_map_TracingBufferFullParam = -1;
static gint ett_gsm_map_NoRoamingNbParam = -1;
static gint ett_gsm_map_AbsentSubscriberParam = -1;
static gint ett_gsm_map_BusySubscriberParam = -1;
static gint ett_gsm_map_NoSubscriberReplyParam = -1;
static gint ett_gsm_map_CallBarredParam = -1;
static gint ett_gsm_map_T_extensibleCallBarredParam = -1;
static gint ett_gsm_map_ForwardingFailedParam = -1;
static gint ett_gsm_map_Or_NotAllowedParam = -1;
static gint ett_gsm_map_ForwardingViolationParam = -1;
static gint ett_gsm_map_Cug_RejectParam = -1;
static gint ett_gsm_map_Ati_NotAllowedParam = -1;
static gint ett_gsm_map_NoGroupCallNbParam = -1;
static gint ett_gsm_map_Ss_IncompatibilityCause = -1;
static gint ett_gsm_map_ShortTermDenialParam = -1;
static gint ett_gsm_map_LongTermDenialParam = -1;
static gint ett_gsm_map_SubBusyForMT_SMS_Param = -1;
static gint ett_gsm_map_Sm_DeliveryFailureCause = -1;
static gint ett_gsm_map_MessageWaitListFullParam = -1;
static gint ett_gsm_map_AbsentSubscriberSM_Param = -1;
static gint ett_gsm_map_UnauthorizedRequestingNetwork_Param = -1;
static gint ett_gsm_map_UnauthorizedLCSClient_Param = -1;
static gint ett_gsm_map_PositionMethodFailure_Param = -1;
static gint ett_gsm_map_UnknownOrUnreachableLCSClient_Param = -1;
static gint ett_gsm_map_ExtensionContainer = -1;

/*--- End of included file: packet-gsm_map-ett.c ---*/


static dissector_table_t	sms_dissector_table;	/* SMS TPDU */
/* Preferenc settings default */
static guint tcap_itu_ssn1 = 6;
static guint tcap_itu_ssn2 = 7;
static guint tcap_itu_ssn3 = 8;
static guint tcap_itu_ssn4 = 9;

static guint global_tcap_itu_ssn1 = 6;
static guint global_tcap_itu_ssn2 = 7;
static guint global_tcap_itu_ssn3 = 8;
static guint global_tcap_itu_ssn4 = 9;

/* Global variables */
static proto_tree *top_tree;
int application_context_version;
gint protocolId;
static int gsm_map_tap = -1;


static char*
unpack_digits(tvbuff_t *tvb, int offset){

	int length;
	guint8 octet;
	int i=0;
	char *digit_str;

	length = tvb_length(tvb);
	length = length - offset;
	digit_str = g_malloc(length+1);

	while ( offset < length ){

		octet = tvb_get_guint8(tvb,offset);
		digit_str[i] = ((octet & 0x0f) + 0x30);
		i++;

		/*
		 * unpack second value in byte
		 */
		octet = octet >> 4;

		if (octet == 0x0f)	/* odd number bytes - hit filler */
			break;

		digit_str[i] = ((octet & 0x0f) + 0x30);
		i++;
		offset++;

	}
	digit_str[i]= '\0';
	return digit_str;
}



/*--- Included file: packet-gsm_map-fn.c ---*/

/*--- Fields for imported types ---*/



static const value_string gsm_map_ProtocolId_vals[] = {
  {   1, "gsm-0408" },
  {   2, "gsm-0806" },
  {   3, "gsm-BSSMAP" },
  {   4, "ets-300102-1" },
  { 0, NULL }
};


static int
dissect_gsm_map_ProtocolId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, &protocolId);


  return offset;
}
static int dissect_protocolId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ProtocolId(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_protocolId);
}


static int
dissect_gsm_map_SignalInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

 tvbuff_t	*parameter_tvb;
 guint8		octet;
 guint8		length;

 offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    &parameter_tvb);
 if (!parameter_tvb)
	return offset;
 switch (protocolId){
	/* gsm-0408 */
	case 1:
		break;
 	/* gsm-0806 */
	case 2:
		break;
	/* gsm-BSSMAP */
	case 3:
		break;
	/* ets-300102-1 (~Q.931 ) */
	case 4:
		octet = tvb_get_guint8(parameter_tvb,0);
		length = tvb_get_guint8(parameter_tvb,1);
		if ( octet == 4 )
			dissect_q931_bearer_capability_ie(parameter_tvb, 2, length, tree);
		break;
	default:
		break;
}


  return offset;
}
static int dissect_signalInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SignalInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_signalInfo);
}


static int
dissect_gsm_map_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset,
                                         hf_index, NULL);

  return offset;
}
static int dissect_extId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_extId);
}


static int
dissect_gsm_map_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_extType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_extType);
}
static int dissect_bearerService_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_bearerService);
}
static int dissect_dataCodingScheme_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_dataCodingScheme);
}
static int dissect_nameString_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_nameString);
}
static int dissect_lcsClientDialedByMS_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsClientDialedByMS);
}

static const ber_sequence_t PrivateExtension_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_extId },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extType },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PrivateExtension(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PrivateExtension_sequence, hf_index, ett_gsm_map_PrivateExtension);

  return offset;
}
static int dissect_PrivateExtensionList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PrivateExtension(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_PrivateExtensionList_item);
}

static const ber_sequence_t PrivateExtensionList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_PrivateExtensionList_item },
};

static int
dissect_gsm_map_PrivateExtensionList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   PrivateExtensionList_sequence_of, hf_index, ett_gsm_map_PrivateExtensionList);

  return offset;
}
static int dissect_privateExtensionList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PrivateExtensionList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_privateExtensionList);
}

static const ber_sequence_t PcsExtensions_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PcsExtensions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PcsExtensions_sequence, hf_index, ett_gsm_map_PcsExtensions);

  return offset;
}
static int dissect_pcsExtensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PcsExtensions(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_pcsExtensions);
}

static const ber_sequence_t ExtensionContainer_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_privateExtensionList_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pcsExtensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ExtensionContainer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ExtensionContainer_sequence, hf_index, ett_gsm_map_ExtensionContainer);

  return offset;
}
static int dissect_extensionContainer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExtensionContainer(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_extensionContainer);
}
static int dissect_extensionContainer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExtensionContainer(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_extensionContainer);
}

static const ber_sequence_t Bss_APDU_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_protocolId },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_signalInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Bss_APDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Bss_APDU_sequence, hf_index, ett_gsm_map_Bss_APDU);

  return offset;
}
static int dissect_bss_APDU(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Bss_APDU(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_bss_APDU);
}
static int dissect_networkSignalInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Bss_APDU(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_networkSignalInfo);
}
static int dissect_gsm_BearerCapability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Bss_APDU(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gsm_BearerCapability);
}
static int dissect_isdn_BearerCapability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Bss_APDU(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_isdn_BearerCapability);
}
static int dissect_chosenChannel_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Bss_APDU(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_chosenChannel);
}
static int dissect_lowerLayerCompatibility_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Bss_APDU(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lowerLayerCompatibility);
}
static int dissect_highLayerCompatibility_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Bss_APDU(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_highLayerCompatibility);
}
static int dissect_channelType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Bss_APDU(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_channelType);
}
static int dissect_callInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Bss_APDU(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callInfo);
}


static const value_string gsm_map_T_accessNetworkProtocolId_vals[] = {
  {   1, "ts3G-48006" },
  {   2, "ts3G-25413" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_accessNetworkProtocolId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_accessNetworkProtocolId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_accessNetworkProtocolId(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_accessNetworkProtocolId);
}


static int
dissect_gsm_map_SignalInfo2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_signalInfo2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SignalInfo2(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_signalInfo2);
}

static const ber_sequence_t An_APDU_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_accessNetworkProtocolId },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_signalInfo2 },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_An_APDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                An_APDU_sequence, hf_index, ett_gsm_map_An_APDU);

  return offset;
}
static int dissect_an_APDU(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_An_APDU(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_an_APDU);
}

static const asn_namedbit SupportedCamelPhases_bits[] = {
  {  0, &hf_gsm_map_SupportedCamelPhases_phase1, -1, -1, NULL, NULL },
  {  1, &hf_gsm_map_SupportedCamelPhases_phase2, -1, -1, NULL, NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_SupportedCamelPhases(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 SupportedCamelPhases_bits, hf_index, ett_gsm_map_SupportedCamelPhases,
                                 NULL);

  return offset;
}
static int dissect_supportedCamelPhases(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedCamelPhases(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_supportedCamelPhases);
}
static int dissect_supportedCamelPhases_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedCamelPhases(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_supportedCamelPhases);
}
static int dissect_supportedCamelPhasesInGMSC_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedCamelPhases(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_supportedCamelPhasesInGMSC);
}


static int
dissect_gsm_map_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  { proto_item *ti_tmp;
  ti_tmp = proto_tree_add_item(tree, hf_index, tvb, offset>>8, 0, FALSE);
  proto_item_append_text(ti_tmp, ": NULL");
  }

  return offset;
}
static int dissect_solsaSupportIndicator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_solsaSupportIndicator);
}
static int dissect_solsaSupportIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_solsaSupportIndicator);
}
static int dissect_freezeTMSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_freezeTMSI);
}
static int dissect_freezeP_TMSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_freezeP_TMSI);
}
static int dissect_ho_NumberNotRequired(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ho_NumberNotRequired);
}
static int dissect_segmentationProhibited(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_segmentationProhibited);
}
static int dissect_immediateResponsePreferred_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_immediateResponsePreferred);
}
static int dissect_roamingRestrictionDueToUnsupportedFeature_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_roamingRestrictionDueToUnsupportedFeature);
}
static int dissect_broadcastInitEntitlement(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_broadcastInitEntitlement);
}
static int dissect_tif_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_tif_CSI);
}
static int dissect_completeDataListIncluded(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_completeDataListIncluded);
}
static int dissect_vplmnAddressAllowed_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vplmnAddressAllowed);
}
static int dissect_roamingRestrictedInSgsnDueToUnsupportedFeature_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_roamingRestrictedInSgsnDueToUnsupportedFeature);
}
static int dissect_lsaActiveModeIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lsaActiveModeIndicator);
}
static int dissect_lmu_Indicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lmu_Indicator);
}
static int dissect_vbsGroupIndication_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vbsGroupIndication);
}
static int dissect_vgcsGroupIndication_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vgcsGroupIndication);
}
static int dissect_camelSubscriptionInfoWithdraw_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_camelSubscriptionInfoWithdraw);
}
static int dissect_allGPRSData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_allGPRSData);
}
static int dissect_roamingRestrictedInSgsnDueToUnsuppportedFeature_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_roamingRestrictedInSgsnDueToUnsuppportedFeature);
}
static int dissect_allLSAData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_allLSAData);
}
static int dissect_gmlc_ListWithdraw_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gmlc_ListWithdraw);
}
static int dissect_msNotReachable(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_msNotReachable);
}
static int dissect_or_Interrogation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_or_Interrogation);
}
static int dissect_suppress_T_CSI(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_suppress_T_CSI);
}
static int dissect_suppressionOfAnnouncement_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_suppressionOfAnnouncement);
}
static int dissect_ccbs_Call_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Call);
}
static int dissect_cugSubscriptionFlag_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cugSubscriptionFlag);
}
static int dissect_forwardingInterrogationRequired_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingInterrogationRequired);
}
static int dissect_ccbs_Possible_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Possible);
}
static int dissect_keepCCBS_CallIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_keepCCBS_CallIndicator);
}
static int dissect_assumedIdle_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_assumedIdle);
}
static int dissect_camelBusy_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_camelBusy);
}
static int dissect_notProvidedFromVLR_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_notProvidedFromVLR);
}
static int dissect_cug_OutgoingAccess(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_OutgoingAccess);
}
static int dissect_orNotSupportedInGMSC_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_orNotSupportedInGMSC);
}
static int dissect_uusCFInteraction_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uusCFInteraction);
}
static int dissect_allInformationSent_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_allInformationSent);
}
static int dissect_replaceB_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_replaceB_Number);
}
static int dissect_gprsSupportIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gprsSupportIndicator);
}
static int dissect_gprsNodeIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gprsNodeIndicator);
}
static int dissect_noSM_RP_OA_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_noSM_RP_OA);
}
static int dissect_noSM_RP_DA_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_noSM_RP_DA);
}
static int dissect_moreMessagesToSend(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_moreMessagesToSend);
}
static int dissect_deliveryOutcomeIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_deliveryOutcomeIndicator);
}
static int dissect_alertReasonIndicator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_alertReasonIndicator);
}
static int dissect_locationInformationFlag_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_locationInformationFlag);
}
static int dissect_subscriberStateFlag_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_subscriberStateFlag);
}
static int dissect_uplinkFree_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uplinkFree);
}
static int dissect_uplinkRequest_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uplinkRequest);
}
static int dissect_uplinkReleaseIndication_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uplinkReleaseIndication);
}
static int dissect_releaseGroupCall_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_releaseGroupCall);
}
static int dissect_uplinkRequestAck_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uplinkRequestAck);
}
static int dissect_uplinkRejectCommand_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uplinkRejectCommand);
}
static int dissect_uplinkSeizedCommand_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uplinkSeizedCommand);
}
static int dissect_uplinkReleaseCommand_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uplinkReleaseCommand);
}
static int dissect_privacyOverride_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_privacyOverride);
}
static int dissect_verticalCoordinateRequest_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_verticalCoordinateRequest);
}
static int dissect_ccbs_Busy_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Busy);
}
static int dissect_unauthorisedMessageOriginator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_unauthorisedMessageOriginator);
}
static int dissect_gprsConnectionSuspended(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_gprsConnectionSuspended);
}

static const ber_sequence_t Vlr_Capability_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedCamelPhases_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_solsaSupportIndicator_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Vlr_Capability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Vlr_Capability_sequence, hf_index, ett_gsm_map_Vlr_Capability);

  return offset;
}
static int dissect_vlr_Capability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Vlr_Capability(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vlr_Capability);
}


static int
dissect_gsm_map_Imsi(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

 tvbuff_t	*parameter_tvb;
 char		*digit_str;

 offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    &parameter_tvb);
 if (!parameter_tvb)
	return offset;

 digit_str = unpack_digits(parameter_tvb, 0);

 proto_tree_add_string(tree, hf_gsm_map_imsi_digits, parameter_tvb, 0, -1, digit_str);
 



  return offset;
}
static int dissect_imsi(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Imsi(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_imsi);
}
static int dissect_imsi_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Imsi(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_imsi);
}


static int
dissect_gsm_map_Lmsi(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_lmsi(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Lmsi(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lmsi);
}
static int dissect_lmsi_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Lmsi(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lmsi);
}


static int
dissect_gsm_map_Msc_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_msc_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Msc_Number(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_msc_Number);
}
static int dissect_msc_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Msc_Number(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_msc_Number);
}


static int
dissect_gsm_map_Vlr_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_vlr_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Vlr_Number(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_vlr_Number);
}
static int dissect_vlr_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Vlr_Number(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vlr_Number);
}
static int dissect_vlr_number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Vlr_Number(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vlr_number);
}

static const ber_sequence_t UpdateLocationArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_msc_Number_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_vlr_Number },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lmsi_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vlr_Capability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UpdateLocationArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                UpdateLocationArg_sequence, hf_index, ett_gsm_map_UpdateLocationArg);

  return offset;
}


static int
dissect_gsm_map_Hlr_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

 tvbuff_t	*parameter_tvb;
 char		*digit_str;

 offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    &parameter_tvb);

 if (!parameter_tvb)
	return offset;

 proto_tree_add_item(tree, hf_gsm_map_extension, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(tree, hf_gsm_map_nature_of_number, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(tree, hf_gsm_map_number_plan, parameter_tvb, 0,1,FALSE);

 digit_str = unpack_digits(parameter_tvb, 1);

 proto_tree_add_string(tree, hf_gsm_map_map_hlr_number_digits, parameter_tvb, 1, -1, digit_str);
 g_free(digit_str);



  return offset;
}
static int dissect_hlr_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Hlr_Number(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_hlr_Number);
}

static const ber_sequence_t UpdateLocationRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_hlr_Number },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UpdateLocationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                UpdateLocationRes_sequence, hf_index, ett_gsm_map_UpdateLocationRes);

  return offset;
}


static int
dissect_gsm_map_Teleservice(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_teleservice(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Teleservice(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_teleservice);
}
static int dissect_teleservice_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Teleservice(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_teleservice);
}
static int dissect_teleserviceList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Teleservice(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_teleserviceList_item);
}


static const value_string gsm_map_CancellationType_vals[] = {
  {   0, "updateProcedure" },
  {   1, "subscriptionWithdraw" },
  { 0, NULL }
};


static int
dissect_gsm_map_CancellationType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_cancellationType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CancellationType(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cancellationType);
}

static const ber_sequence_t T_imsi_WithLMSI_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_lmsi },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_imsi_WithLMSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_imsi_WithLMSI_sequence, hf_index, ett_gsm_map_T_imsi_WithLMSI);

  return offset;
}
static int dissect_imsi_WithLMSI(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_imsi_WithLMSI(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_imsi_WithLMSI);
}


static const value_string gsm_map_T_identity_vals[] = {
  {   0, "imsi" },
  {   1, "imsi-WithLMSI" },
  { 0, NULL }
};

static const ber_choice_t T_identity_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_imsi_WithLMSI },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_identity(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              T_identity_choice, hf_index, ett_gsm_map_T_identity);

  return offset;
}
static int dissect_identity(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_identity(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_identity);
}

static const ber_sequence_t CancelLocationArg_sequence[] = {
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_identity },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cancellationType },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CancelLocationArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                CancelLocationArg_sequence, hf_index, ett_gsm_map_CancelLocationArg);

  return offset;
}

static const ber_sequence_t CancelLocationRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CancelLocationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                CancelLocationRes_sequence, hf_index, ett_gsm_map_CancelLocationRes);

  return offset;
}


static int
dissect_gsm_map_Sgsn_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_sgsn_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Sgsn_Number(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sgsn_Number);
}
static int dissect_sgsn_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Sgsn_Number(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sgsn_Number);
}

static const ber_sequence_t PurgeMS_Arg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vlr_Number_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgsn_Number_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PurgeMS_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PurgeMS_Arg_sequence, hf_index, ett_gsm_map_PurgeMS_Arg);

  return offset;
}

static const ber_sequence_t PurgeMS_Res_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_freezeTMSI_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_freezeP_TMSI_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PurgeMS_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PurgeMS_Res_sequence, hf_index, ett_gsm_map_PurgeMS_Res);

  return offset;
}


static int
dissect_gsm_map_Tmsi(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_16(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_rand(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_16(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_rand);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_4(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_sres(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_4(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sres);
}
static int dissect_cug_Interlock(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_4(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_Interlock);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_8(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_kc(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_8(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_kc);
}
static int dissect_geographicalInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_8(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_geographicalInformation);
}
static int dissect_groupKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_8(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_groupKey);
}

static const ber_sequence_t T_authenticationSetList_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_rand },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sres },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_kc },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_authenticationSetList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_authenticationSetList_item_sequence, hf_index, ett_gsm_map_T_authenticationSetList_item);

  return offset;
}
static int dissect_authenticationSetList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_authenticationSetList_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_authenticationSetList_item);
}

static const ber_sequence_t T_authenticationSetList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_authenticationSetList_item },
};

static int
dissect_gsm_map_T_authenticationSetList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_authenticationSetList_sequence_of, hf_index, ett_gsm_map_T_authenticationSetList);

  return offset;
}
static int dissect_authenticationSetList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_authenticationSetList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_authenticationSetList);
}

static const ber_sequence_t SendIdentificationRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_authenticationSetList },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendIdentificationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SendIdentificationRes_sequence, hf_index, ett_gsm_map_SendIdentificationRes);

  return offset;
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_5_7(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_targetCellId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_5_7(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_targetCellId);
}

static const ber_sequence_t PrepareHO_Arg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_targetCellId },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ho_NumberNotRequired },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_bss_APDU },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PrepareHO_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PrepareHO_Arg_sequence, hf_index, ett_gsm_map_PrepareHO_Arg);

  return offset;
}


static int
dissect_gsm_map_T_handoverNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_handoverNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_handoverNumber(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_handoverNumber);
}

static const ber_sequence_t PrepareHO_Res_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_handoverNumber },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_bss_APDU },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PrepareHO_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PrepareHO_Res_sequence, hf_index, ett_gsm_map_PrepareHO_Res);

  return offset;
}

static const ber_sequence_t SendEndSignalV9Arg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_an_APDU },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendEndSignalV9Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SendEndSignalV9Arg_sequence, hf_index, ett_gsm_map_SendEndSignalV9Arg);

  return offset;
}


static int
dissect_gsm_map_T_targetMSC_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_targetMSC_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_targetMSC_Number(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_targetMSC_Number);
}

static const ber_sequence_t PrepareSubsequentHO_Arg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_targetCellId },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_targetMSC_Number },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_bss_APDU },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PrepareSubsequentHO_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PrepareSubsequentHO_Arg_sequence, hf_index, ett_gsm_map_PrepareSubsequentHO_Arg);

  return offset;
}


static int
dissect_gsm_map_SendAuthenticationInfoArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_Imsi(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_gsm_map_INTEGER_1_5(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_numberOfRequestedVectors(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_1_5(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_numberOfRequestedVectors);
}
static int dissect_numberOfForwarding_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_1_5(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_numberOfForwarding);
}
static int dissect_ccbs_Index_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_1_5(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Index);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_14(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_auts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_14(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_auts);
}

static const ber_sequence_t T_re_synchronisationInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_rand },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_auts },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_re_synchronisationInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_re_synchronisationInfo_sequence, hf_index, ett_gsm_map_T_re_synchronisationInfo);

  return offset;
}
static int dissect_re_synchronisationInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_re_synchronisationInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_re_synchronisationInfo);
}


static const value_string gsm_map_T_requestingNodeType_vals[] = {
  {   0, "vlr" },
  {   1, "sgsn" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_requestingNodeType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_requestingNodeType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_requestingNodeType(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_requestingNodeType);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_requestingPLMN_Id_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_3(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_requestingPLMN_Id);
}
static int dissect_groupid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_3(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_groupid);
}
static int dissect_groupId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_3(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_groupId);
}
static int dissect_qos_Subscribed_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_3(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_qos_Subscribed);
}
static int dissect_lsaIdentity_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_3(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lsaIdentity);
}
static int dissect_naea_PreferredCIC_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_3(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_naea_PreferredCIC);
}
static int dissect_lsaIdentityList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_3(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lsaIdentityList_item);
}

static const ber_sequence_t SendAuthenticationInfoArgV3_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_numberOfRequestedVectors },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_segmentationProhibited },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_immediateResponsePreferred_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_re_synchronisationInfo },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_requestingNodeType_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_requestingPLMN_Id_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendAuthenticationInfoArgV3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SendAuthenticationInfoArgV3_sequence, hf_index, ett_gsm_map_SendAuthenticationInfoArgV3);

  return offset;
}

static const ber_sequence_t SendAuthenticationInfoRes_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_rand },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sres },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_kc },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendAuthenticationInfoRes_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SendAuthenticationInfoRes_item_sequence, hf_index, ett_gsm_map_SendAuthenticationInfoRes_item);

  return offset;
}
static int dissect_SendAuthenticationInfoRes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SendAuthenticationInfoRes_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_SendAuthenticationInfoRes_item);
}

static const ber_sequence_t SendAuthenticationInfoRes_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_SendAuthenticationInfoRes_item },
};

static int
dissect_gsm_map_SendAuthenticationInfoRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   SendAuthenticationInfoRes_sequence_of, hf_index, ett_gsm_map_SendAuthenticationInfoRes);

  return offset;
}


static int
dissect_gsm_map_Imei(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_imei_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Imei(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_imei);
}


static int
dissect_gsm_map_CheckIMEIArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_Imei(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const value_string gsm_map_EquipmentStatus_vals[] = {
  {   0, "whiteListed" },
  {   1, "blackListed" },
  {   2, "greyListed" },
  { 0, NULL }
};


static int
dissect_gsm_map_EquipmentStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string gsm_map_OverrideCategory_vals[] = {
  {   0, "overrideEnabled" },
  {   1, "overrideDisabled" },
  { 0, NULL }
};


static int
dissect_gsm_map_OverrideCategory(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_overrideCategory_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OverrideCategory(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_overrideCategory);
}


static const value_string gsm_map_BasicService_vals[] = {
  {   2, "bearerService" },
  {   3, "teleservice" },
  { 0, NULL }
};

static const ber_choice_t BasicService_choice[] = {
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_bearerService_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_teleservice_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_BasicService(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              BasicService_choice, hf_index, ett_gsm_map_BasicService);

  return offset;
}
static int dissect_BasicServiceGroupList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicService(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_BasicServiceGroupList_item);
}
static int dissect_basicService(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicService(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_basicService);
}
static int dissect_basicServiceGroup(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicService(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_basicServiceGroup);
}

static const ber_sequence_t BasicServiceGroupList_sequence_of[1] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_BasicServiceGroupList_item },
};

static int
dissect_gsm_map_BasicServiceGroupList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   BasicServiceGroupList_sequence_of, hf_index, ett_gsm_map_BasicServiceGroupList);

  return offset;
}
static int dissect_basicServiceGroupList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicServiceGroupList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_basicServiceGroupList);
}
static int dissect_basicServiceGroupList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicServiceGroupList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_basicServiceGroupList);
}
static int dissect_basicServiceCriteria_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicServiceGroupList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_basicServiceCriteria);
}
static int dissect_basicServiceList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicServiceGroupList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_basicServiceList);
}


static const value_string gsm_map_IntraCUG_Options_vals[] = {
  {   0, "noCUG-Restrictions" },
  {   1, "cugIC-CallBarred" },
  {   2, "cugOG-CallBarred" },
  { 0, NULL }
};


static int
dissect_gsm_map_IntraCUG_Options(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_intraCUG_Options(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IntraCUG_Options(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_intraCUG_Options);
}

static const asn_namedbit Odb_GeneralData_bits[] = {
  {  0, &hf_gsm_map_Odb_GeneralData_allOGCallsBarred, -1, -1, NULL, NULL },
  {  1, &hf_gsm_map_Odb_GeneralData_internationalOGCallsBarred, -1, -1, NULL, NULL },
  {  2, &hf_gsm_map_Odb_GeneralData_internationalOGCallsNotToHPLMNCountryBarred, -1, -1, NULL, NULL },
  {  3, &hf_gsm_map_Odb_GeneralData_premiumRateInformationOGCallsBarred, -1, -1, NULL, NULL },
  {  4, &hf_gsm_map_Odb_GeneralData_premiumRateEntertainementOGCallsBarred, -1, -1, NULL, NULL },
  {  5, &hf_gsm_map_Odb_GeneralData_ssAccessBarred, -1, -1, NULL, NULL },
  {  6, &hf_gsm_map_Odb_GeneralData_interzonalOGCallsBarred, -1, -1, NULL, NULL },
  {  7, &hf_gsm_map_Odb_GeneralData_interzonalOGCallsNotToHPLMNCountryBarred, -1, -1, NULL, NULL },
  {  8, &hf_gsm_map_Odb_GeneralData_interzonalOGCallsAndIntOGCallsNotToHPLMNCountryBarred, -1, -1, NULL, NULL },
  {  9, &hf_gsm_map_Odb_GeneralData_allECTBarred, -1, -1, NULL, NULL },
  { 10, &hf_gsm_map_Odb_GeneralData_chargeableECTBarred, -1, -1, NULL, NULL },
  { 11, &hf_gsm_map_Odb_GeneralData_internationalECTBarred, -1, -1, NULL, NULL },
  { 12, &hf_gsm_map_Odb_GeneralData_interzonalECTBarred, -1, -1, NULL, NULL },
  { 13, &hf_gsm_map_Odb_GeneralData_doublyChargeableECTBarred, -1, -1, NULL, NULL },
  { 14, &hf_gsm_map_Odb_GeneralData_multipleECTBarred, -1, -1, NULL, NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_Odb_GeneralData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 Odb_GeneralData_bits, hf_index, ett_gsm_map_Odb_GeneralData,
                                 NULL);

  return offset;
}
static int dissect_odb_GeneralData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Odb_GeneralData(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_odb_GeneralData);
}
static int dissect_odb_GeneralData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Odb_GeneralData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_odb_GeneralData);
}

static const asn_namedbit Odb_HPLMN_Data_bits[] = {
  {  0, &hf_gsm_map_Odb_HPLMN_Data_plmnSpecificBarringType1, -1, -1, NULL, NULL },
  {  1, &hf_gsm_map_Odb_HPLMN_Data_plmnSpecificBarringType2, -1, -1, NULL, NULL },
  {  2, &hf_gsm_map_Odb_HPLMN_Data_plmnSpecificBarringType3, -1, -1, NULL, NULL },
  {  3, &hf_gsm_map_Odb_HPLMN_Data_plmnSpecificBarringType4, -1, -1, NULL, NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_Odb_HPLMN_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 Odb_HPLMN_Data_bits, hf_index, ett_gsm_map_Odb_HPLMN_Data,
                                 NULL);

  return offset;
}
static int dissect_odb_HPLMN_Data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Odb_HPLMN_Data(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_odb_HPLMN_Data);
}


static const value_string gsm_map_SubscriberStatus_vals[] = {
  {   0, "serviceGranted" },
  {   1, "operatorDeterminedBarring" },
  { 0, NULL }
};


static int
dissect_gsm_map_SubscriberStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_subscriberStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SubscriberStatus(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_subscriberStatus);
}


static const value_string gsm_map_BcsmTriggerDetectionPoint_vals[] = {
  {   2, "collectedInfo" },
  {  12, "termAttemptAuthorized" },
  { 0, NULL }
};


static int
dissect_gsm_map_BcsmTriggerDetectionPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_bcsmTriggerDetectionPoint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BcsmTriggerDetectionPoint(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_bcsmTriggerDetectionPoint);
}
static int dissect_o_BcsmTriggerDetectionPoint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BcsmTriggerDetectionPoint(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_o_BcsmTriggerDetectionPoint);
}



static int
dissect_gsm_map_ServiceKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_serviceKey(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ServiceKey(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_serviceKey);
}


static int
dissect_gsm_map_GsmSCF_Address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_gsmSCFAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GsmSCF_Address(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gsmSCFAddress);
}
static int dissect_gsmSCF_Address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GsmSCF_Address(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_gsmSCF_Address);
}
static int dissect_gsmSCF_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GsmSCF_Address(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gsmSCF_Address);
}


static const value_string gsm_map_DefaultCallHandling_vals[] = {
  {   0, "continueCall" },
  {   1, "releaseCall" },
  { 0, NULL }
};


static int
dissect_gsm_map_DefaultCallHandling(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_defaultCallHandling_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_DefaultCallHandling(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_defaultCallHandling);
}

static const ber_sequence_t BcsmCamelTDPData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_bcsmTriggerDetectionPoint },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serviceKey },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gsmSCFAddress_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_defaultCallHandling_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_BcsmCamelTDPData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                BcsmCamelTDPData_sequence, hf_index, ett_gsm_map_BcsmCamelTDPData);

  return offset;
}
static int dissect_BcsmCamelTDPDataList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BcsmCamelTDPData(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_BcsmCamelTDPDataList_item);
}

static const ber_sequence_t BcsmCamelTDPDataList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_BcsmCamelTDPDataList_item },
};

static int
dissect_gsm_map_BcsmCamelTDPDataList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   BcsmCamelTDPDataList_sequence_of, hf_index, ett_gsm_map_BcsmCamelTDPDataList);

  return offset;
}
static int dissect_o_BcsmCamelTDPDataList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BcsmCamelTDPDataList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_o_BcsmCamelTDPDataList);
}
static int dissect_t_BcsmCamelTDPDataList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BcsmCamelTDPDataList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_t_BcsmCamelTDPDataList);
}



static int
dissect_gsm_map_INTEGER_1_16(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_camelCapabilityHandling_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_1_16(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_camelCapabilityHandling);
}

static const ber_sequence_t O_CSI_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_o_BcsmCamelTDPDataList },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camelCapabilityHandling_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_O_CSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                O_CSI_sequence, hf_index, ett_gsm_map_O_CSI);

  return offset;
}
static int dissect_o_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_O_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_o_CSI);
}


static int
dissect_gsm_map_Msisdn(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

 tvbuff_t	*parameter_tvb;
 char		*digit_str;

 offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    &parameter_tvb);

 if (!parameter_tvb)
	return offset;

 proto_tree_add_item(tree, hf_gsm_map_extension, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(tree, hf_gsm_map_nature_of_number, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(tree, hf_gsm_map_number_plan, parameter_tvb, 0,1,FALSE);

 digit_str = unpack_digits(parameter_tvb, 1);

 proto_tree_add_string(tree, hf_gsm_map_misdn_digits, parameter_tvb, 1, -1, digit_str);
 g_free(digit_str);



  return offset;
}
static int dissect_msisdn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Msisdn(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_msisdn);
}
static int dissect_msisdn_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Msisdn(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_msisdn);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_category_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_category);
}
static int dissect_interCUG_Restrictions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_interCUG_Restrictions);
}
static int dissect_ss_EventList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_EventList_item);
}
static int dissect_lsaAttributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lsaAttributes);
}
static int dissect_ss_List_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_List_item);
}
static int dissect_alertingPattern(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_alertingPattern);
}
static int dissect_alertingPattern_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_alertingPattern);
}
static int dissect_uuIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uuIndicator);
}
static int dissect_call_Direction_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_call_Direction);
}
static int dissect_ussd_DataCodingScheme(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ussd_DataCodingScheme);
}
static int dissect_ss_Event_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Event);
}
static int dissect_cipheringAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cipheringAlgorithm);
}
static int dissect_lcs_Priority_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_Priority);
}
static int dissect_horizontal_accuracy_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_horizontal_accuracy);
}
static int dissect_vertical_accuracy_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vertical_accuracy);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_1_5(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_bearerServiceList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_5(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_bearerServiceList_item);
}

static const ber_sequence_t bearerServiceList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_bearerServiceList_item },
};

static int
dissect_gsm_map_bearerServiceList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   bearerServiceList_sequence_of, hf_index, ett_gsm_map_bearerServiceList);

  return offset;
}
static int dissect_bearerServiceList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_bearerServiceList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_bearerServiceList);
}

static const ber_sequence_t SEQUENCE_SIZE_1_20_OF_Teleservice_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_teleserviceList_item },
};

static int
dissect_gsm_map_SEQUENCE_SIZE_1_20_OF_Teleservice(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   SEQUENCE_SIZE_1_20_OF_Teleservice_sequence_of, hf_index, ett_gsm_map_SEQUENCE_SIZE_1_20_OF_Teleservice);

  return offset;
}
static int dissect_teleserviceList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SEQUENCE_SIZE_1_20_OF_Teleservice(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_teleserviceList);
}


static int
dissect_gsm_map_Ss_Code(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_ss_Code(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ss_Code(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Code);
}
static int dissect_ss_Code_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ss_Code(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Code);
}


static int
dissect_gsm_map_Ss_Status(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

 tvbuff_t	*parameter_tvb;
 guint8		octet;

 offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    &parameter_tvb);
 if (!parameter_tvb)
	return offset;

 octet = tvb_get_guint8(parameter_tvb,0);

 proto_tree_add_uint(tree, hf_gsm_map_Ss_Status_unused, parameter_tvb, 0,1,octet);
 if ((octet & 0x01)== 1)	
	proto_tree_add_boolean(tree, hf_gsm_map_Ss_Status_q_bit, parameter_tvb, 0,1,octet);
										
 proto_tree_add_boolean(tree, hf_gsm_map_Ss_Status_p_bit, parameter_tvb, 0,1,octet);									
 proto_tree_add_boolean(tree, hf_gsm_map_Ss_Status_r_bit, parameter_tvb, 0,1,octet);									
 proto_tree_add_boolean(tree, hf_gsm_map_Ss_Status_a_bit, parameter_tvb, 0,1,octet);									



  return offset;
}
static int dissect_ss_Status(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ss_Status(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Status);
}
static int dissect_ss_Status_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ss_Status(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Status);
}


static int
dissect_gsm_map_ForwardedToNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_forwardedToNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ForwardedToNumber(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardedToNumber);
}


static int
dissect_gsm_map_ForwardedToSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_forwardedToSubaddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ForwardedToSubaddress(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardedToSubaddress);
}


static int
dissect_gsm_map_ForwardingOptions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_forwardingOptions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ForwardingOptions(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingOptions);
}



static int
dissect_gsm_map_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_noReplyConditionTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_noReplyConditionTime);
}

static const ber_sequence_t ForwardingFeatureList_sequence[] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_basicService },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ss_Status_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToSubaddress_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardingOptions_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noReplyConditionTime_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ForwardingFeatureList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ForwardingFeatureList_sequence, hf_index, ett_gsm_map_ForwardingFeatureList);

  return offset;
}
static int dissect_forwardingFeatureList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ForwardingFeatureList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingFeatureList_item);
}

static const ber_sequence_t SEQUENCE_SIZE_1_32_OF_ForwardingFeatureList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_forwardingFeatureList_item },
};

static int
dissect_gsm_map_SEQUENCE_SIZE_1_32_OF_ForwardingFeatureList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   SEQUENCE_SIZE_1_32_OF_ForwardingFeatureList_sequence_of, hf_index, ett_gsm_map_SEQUENCE_SIZE_1_32_OF_ForwardingFeatureList);

  return offset;
}
static int dissect_forwardingFeatureList_1_32(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SEQUENCE_SIZE_1_32_OF_ForwardingFeatureList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingFeatureList_1_32);
}

static const ber_sequence_t ForwardingInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_forwardingFeatureList_1_32 },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ForwardingInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ForwardingInfo_sequence, hf_index, ett_gsm_map_ForwardingInfo);

  return offset;
}
static int dissect_forwardingInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ForwardingInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingInfo);
}

static const ber_sequence_t T_callBarringFeatureList_item_sequence[] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_basicService },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ss_Status_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_callBarringFeatureList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_callBarringFeatureList_item_sequence, hf_index, ett_gsm_map_T_callBarringFeatureList_item);

  return offset;
}
static int dissect_callBarringFeatureList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_callBarringFeatureList_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_callBarringFeatureList_item);
}

static const ber_sequence_t T_callBarringFeatureList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_callBarringFeatureList_item },
};

static int
dissect_gsm_map_T_callBarringFeatureList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_callBarringFeatureList_sequence_of, hf_index, ett_gsm_map_T_callBarringFeatureList);

  return offset;
}
static int dissect_callBarringFeatureList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_callBarringFeatureList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_callBarringFeatureList);
}

static const ber_sequence_t CallBarringInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_callBarringFeatureList },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CallBarringInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                CallBarringInfo_sequence, hf_index, ett_gsm_map_CallBarringInfo);

  return offset;
}
static int dissect_callBarringInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallBarringInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callBarringInfo);
}



static int
dissect_gsm_map_INTEGER_0_32767(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_cug_Index(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_32767(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_Index);
}
static int dissect_preferentialCUG_Indicator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_32767(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_preferentialCUG_Indicator);
}
static int dissect_ageOfLocationInformation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_32767(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ageOfLocationInformation);
}
static int dissect_ageOfLocationEstimate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_32767(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ageOfLocationEstimate);
}

static const ber_sequence_t T_cug_SubscriptionList_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cug_Index },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cug_Interlock },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_intraCUG_Options },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_basicServiceGroupList },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_cug_SubscriptionList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_cug_SubscriptionList_item_sequence, hf_index, ett_gsm_map_T_cug_SubscriptionList_item);

  return offset;
}
static int dissect_cug_SubscriptionList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_cug_SubscriptionList_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_SubscriptionList_item);
}

static const ber_sequence_t T_cug_SubscriptionList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cug_SubscriptionList_item },
};

static int
dissect_gsm_map_T_cug_SubscriptionList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_cug_SubscriptionList_sequence_of, hf_index, ett_gsm_map_T_cug_SubscriptionList);

  return offset;
}
static int dissect_cug_SubscriptionList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_cug_SubscriptionList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_SubscriptionList);
}

static const ber_sequence_t T_cug_FeatureList_item_sequence[] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_basicService },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_preferentialCUG_Indicator },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_interCUG_Restrictions },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_cug_FeatureList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_cug_FeatureList_item_sequence, hf_index, ett_gsm_map_T_cug_FeatureList_item);

  return offset;
}
static int dissect_cug_FeatureList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_cug_FeatureList_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_FeatureList_item);
}

static const ber_sequence_t T_cug_FeatureList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cug_FeatureList_item },
};

static int
dissect_gsm_map_T_cug_FeatureList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_cug_FeatureList_sequence_of, hf_index, ett_gsm_map_T_cug_FeatureList);

  return offset;
}
static int dissect_cug_FeatureList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_cug_FeatureList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_FeatureList);
}

static const ber_sequence_t T_cug_Info_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cug_SubscriptionList },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cug_FeatureList },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_cug_Info(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_cug_Info_sequence, hf_index, ett_gsm_map_T_cug_Info);

  return offset;
}
static int dissect_cug_Info_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_cug_Info(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cug_Info);
}


static const value_string gsm_map_CliRestrictionOption_vals[] = {
  {   0, "permanent" },
  {   1, "temporaryDefaultRestricted" },
  {   2, "temporaryDefaultAllowed" },
  { 0, NULL }
};


static int
dissect_gsm_map_CliRestrictionOption(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_cliRestrictionOption_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CliRestrictionOption(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cliRestrictionOption);
}


static const value_string gsm_map_Ss_SubscriptionOption_vals[] = {
  {   2, "cliRestrictionOption" },
  {   1, "overrideCategory" },
  { 0, NULL }
};

static const ber_choice_t Ss_SubscriptionOption_choice[] = {
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cliRestrictionOption_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_overrideCategory_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ss_SubscriptionOption(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              Ss_SubscriptionOption_choice, hf_index, ett_gsm_map_Ss_SubscriptionOption);

  return offset;
}
static int dissect_ss_SubscriptionOption(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ss_SubscriptionOption(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_SubscriptionOption);
}

static const ber_sequence_t T_ss_Data2_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ss_Status_impl },
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ss_SubscriptionOption },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_basicServiceGroupList },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_ss_Data2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_ss_Data2_sequence, hf_index, ett_gsm_map_T_ss_Data2);

  return offset;
}
static int dissect_ss_Data2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_ss_Data2(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Data2);
}



static int
dissect_gsm_map_INTEGER_0_15(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_maximumentitledPriority(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_15(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_maximumentitledPriority);
}
static int dissect_defaultPriority(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_15(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_defaultPriority);
}
static int dissect_defaultPriority_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_15(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_defaultPriority);
}
static int dissect_maximumEntitledPriority_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_15(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_maximumEntitledPriority);
}
static int dissect_groupKeyNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_15(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_groupKeyNumber);
}
static int dissect_priority_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_15(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_priority);
}

static const ber_sequence_t T_emlpp_Info_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_maximumentitledPriority },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_defaultPriority },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_emlpp_Info(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_emlpp_Info_sequence, hf_index, ett_gsm_map_T_emlpp_Info);

  return offset;
}
static int dissect_emlpp_Info_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_emlpp_Info(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_emlpp_Info);
}


static const value_string gsm_map_T_provisionedSS_item_vals[] = {
  {   0, "forwardingInfo" },
  {   1, "callBarringInfo" },
  {   2, "cug-Info" },
  {   3, "ss-Data2" },
  {   4, "emlpp-Info" },
  { 0, NULL }
};

static const ber_choice_t T_provisionedSS_item_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_forwardingInfo_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_callBarringInfo_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cug_Info_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ss_Data2_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_emlpp_Info_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_provisionedSS_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              T_provisionedSS_item_choice, hf_index, ett_gsm_map_T_provisionedSS_item);

  return offset;
}
static int dissect_provisionedSS_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_provisionedSS_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_provisionedSS_item);
}

static const ber_sequence_t T_provisionedSS_sequence_of[1] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_provisionedSS_item },
};

static int
dissect_gsm_map_T_provisionedSS(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_provisionedSS_sequence_of, hf_index, ett_gsm_map_T_provisionedSS);

  return offset;
}
static int dissect_provisionedSS_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_provisionedSS(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_provisionedSS);
}

static const ber_sequence_t T_odb_Data_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_odb_GeneralData },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_odb_HPLMN_Data },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_odb_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_odb_Data_sequence, hf_index, ett_gsm_map_T_odb_Data);

  return offset;
}
static int dissect_odb_Data_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_odb_Data(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_odb_Data);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_regionalSubscriptionData_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_2(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_regionalSubscriptionData_item);
}
static int dissect_pdp_Type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_2(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_pdp_Type);
}
static int dissect_regionalSubscriptionIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_2(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_regionalSubscriptionIdentifier);
}

static const ber_sequence_t T_regionalSubscriptionData_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_regionalSubscriptionData_item },
};

static int
dissect_gsm_map_T_regionalSubscriptionData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_regionalSubscriptionData_sequence_of, hf_index, ett_gsm_map_T_regionalSubscriptionData);

  return offset;
}
static int dissect_regionalSubscriptionData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_regionalSubscriptionData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_regionalSubscriptionData);
}

static const ber_sequence_t T_vbsSubscriptionData_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_groupid },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_broadcastInitEntitlement },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_vbsSubscriptionData_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_vbsSubscriptionData_item_sequence, hf_index, ett_gsm_map_T_vbsSubscriptionData_item);

  return offset;
}
static int dissect_vbsSubscriptionData_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_vbsSubscriptionData_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_vbsSubscriptionData_item);
}

static const ber_sequence_t T_vbsSubscriptionData_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_vbsSubscriptionData_item },
};

static int
dissect_gsm_map_T_vbsSubscriptionData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_vbsSubscriptionData_sequence_of, hf_index, ett_gsm_map_T_vbsSubscriptionData);

  return offset;
}
static int dissect_vbsSubscriptionData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_vbsSubscriptionData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vbsSubscriptionData);
}

static const ber_sequence_t T_vgcsSubscriptionData_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_groupId },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_vgcsSubscriptionData_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_vgcsSubscriptionData_item_sequence, hf_index, ett_gsm_map_T_vgcsSubscriptionData_item);

  return offset;
}
static int dissect_vgcsSubscriptionData_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_vgcsSubscriptionData_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_vgcsSubscriptionData_item);
}

static const ber_sequence_t T_vgcsSubscriptionData_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_vgcsSubscriptionData_item },
};

static int
dissect_gsm_map_T_vgcsSubscriptionData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_vgcsSubscriptionData_sequence_of, hf_index, ett_gsm_map_T_vgcsSubscriptionData);

  return offset;
}
static int dissect_vgcsSubscriptionData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_vgcsSubscriptionData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vgcsSubscriptionData);
}

static const ber_sequence_t T_ss_EventList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_EventList_item },
};

static int
dissect_gsm_map_T_ss_EventList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_ss_EventList_sequence_of, hf_index, ett_gsm_map_T_ss_EventList);

  return offset;
}
static int dissect_ss_EventList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_ss_EventList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_EventList);
}

static const ber_sequence_t T_ss_CamelData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ss_EventList },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_gsmSCF_Address },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_ss_CamelData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_ss_CamelData_sequence, hf_index, ett_gsm_map_T_ss_CamelData);

  return offset;
}
static int dissect_ss_CamelData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_ss_CamelData(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_CamelData);
}

static const ber_sequence_t T_ss_CSI_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ss_CamelData },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_ss_CSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_ss_CSI_sequence, hf_index, ett_gsm_map_T_ss_CSI);

  return offset;
}
static int dissect_ss_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_ss_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_CSI);
}


static const value_string gsm_map_MatchType_vals[] = {
  {   0, "inhibiting" },
  {   1, "enabling" },
  { 0, NULL }
};


static int
dissect_gsm_map_MatchType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_matchType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MatchType(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_matchType);
}


static int
dissect_gsm_map_T_destinationNumberList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_destinationNumberList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_destinationNumberList_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_destinationNumberList_item);
}

static const ber_sequence_t T_destinationNumberList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_destinationNumberList_item },
};

static int
dissect_gsm_map_T_destinationNumberList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_destinationNumberList_sequence_of, hf_index, ett_gsm_map_T_destinationNumberList);

  return offset;
}
static int dissect_destinationNumberList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_destinationNumberList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_destinationNumberList);
}



static int
dissect_gsm_map_INTEGER_1_15(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_destinationNumberLengthList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_1_15(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_destinationNumberLengthList_item);
}

static const ber_sequence_t T_destinationNumberLengthList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_destinationNumberLengthList_item },
};

static int
dissect_gsm_map_T_destinationNumberLengthList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_destinationNumberLengthList_sequence_of, hf_index, ett_gsm_map_T_destinationNumberLengthList);

  return offset;
}
static int dissect_destinationNumberLengthList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_destinationNumberLengthList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_destinationNumberLengthList);
}

static const ber_sequence_t DestinationNumberCriteria_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_matchType_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationNumberList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationNumberLengthList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_DestinationNumberCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                DestinationNumberCriteria_sequence, hf_index, ett_gsm_map_DestinationNumberCriteria);

  return offset;
}
static int dissect_destinationNumberCriteria_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_DestinationNumberCriteria(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_destinationNumberCriteria);
}


static const value_string gsm_map_CallTypeCriteria_vals[] = {
  {   0, "forwarded" },
  {   1, "notForwarded" },
  { 0, NULL }
};


static int
dissect_gsm_map_CallTypeCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_callTypeCriteria_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallTypeCriteria(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callTypeCriteria);
}

static const ber_sequence_t O_BcsmCamelTDP_CriteriaList_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_o_BcsmTriggerDetectionPoint },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationNumberCriteria_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_basicServiceCriteria_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callTypeCriteria_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_O_BcsmCamelTDP_CriteriaList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                O_BcsmCamelTDP_CriteriaList_item_sequence, hf_index, ett_gsm_map_O_BcsmCamelTDP_CriteriaList_item);

  return offset;
}
static int dissect_O_BcsmCamelTDP_CriteriaList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_O_BcsmCamelTDP_CriteriaList_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_O_BcsmCamelTDP_CriteriaList_item);
}

static const ber_sequence_t O_BcsmCamelTDP_CriteriaList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_O_BcsmCamelTDP_CriteriaList_item },
};

static int
dissect_gsm_map_O_BcsmCamelTDP_CriteriaList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   O_BcsmCamelTDP_CriteriaList_sequence_of, hf_index, ett_gsm_map_O_BcsmCamelTDP_CriteriaList);

  return offset;
}
static int dissect_o_BcsmCamelTDP_CriteriaList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_O_BcsmCamelTDP_CriteriaList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_o_BcsmCamelTDP_CriteriaList);
}

static const ber_sequence_t T_vlrCamelSubscriptionInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_CSI_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_CSI_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_BcsmCamelTDP_CriteriaList_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tif_CSI_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_vlrCamelSubscriptionInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_vlrCamelSubscriptionInfo_sequence, hf_index, ett_gsm_map_T_vlrCamelSubscriptionInfo);

  return offset;
}
static int dissect_vlrCamelSubscriptionInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_vlrCamelSubscriptionInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vlrCamelSubscriptionInfo);
}

static const ber_sequence_t Naea_PreferredCI_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_naea_PreferredCIC_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Naea_PreferredCI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Naea_PreferredCI_sequence, hf_index, ett_gsm_map_Naea_PreferredCI);

  return offset;
}
static int dissect_naea_PreferredCI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Naea_PreferredCI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_naea_PreferredCI);
}



static int
dissect_gsm_map_INTEGER_1_50(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_pdp_ContextId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_1_50(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_pdp_ContextId);
}
static int dissect_contextIdList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_1_50(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_contextIdList_item);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_1_16(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_pdp_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_16(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_pdp_Address);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_2_63(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_apn_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_2_63(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_apn);
}

static const ber_sequence_t T_gprsDataList_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pdp_ContextId },
  { BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_pdp_Type_impl },
  { BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pdp_Address_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_qos_Subscribed_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vplmnAddressAllowed_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_apn_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_gprsDataList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_gprsDataList_item_sequence, hf_index, ett_gsm_map_T_gprsDataList_item);

  return offset;
}
static int dissect_gprsDataList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_gprsDataList_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_gprsDataList_item);
}

static const ber_sequence_t T_gprsDataList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprsDataList_item },
};

static int
dissect_gsm_map_T_gprsDataList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_gprsDataList_sequence_of, hf_index, ett_gsm_map_T_gprsDataList);

  return offset;
}
static int dissect_gprsDataList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_gprsDataList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gprsDataList);
}

static const ber_sequence_t T_gprsSubscriptionData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_completeDataListIncluded },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprsDataList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_gprsSubscriptionData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_gprsSubscriptionData_sequence, hf_index, ett_gsm_map_T_gprsSubscriptionData);

  return offset;
}
static int dissect_gprsSubscriptionData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_gprsSubscriptionData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gprsSubscriptionData);
}


static const value_string gsm_map_T_networkAccessMode_vals[] = {
  {   0, "bothMSCAndSGSN" },
  {   1, "onlyMSC" },
  {   2, "onlySGSN" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_networkAccessMode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_networkAccessMode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_networkAccessMode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_networkAccessMode);
}


static const value_string gsm_map_T_lsaOnlyAccessIndicator_vals[] = {
  {   0, "accessOutsideLSAsAllowed" },
  {   1, "accessOutsideLSAsRestricted" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_lsaOnlyAccessIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_lsaOnlyAccessIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_lsaOnlyAccessIndicator(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lsaOnlyAccessIndicator);
}

static const ber_sequence_t T_lsaDataList_item_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_lsaIdentity_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lsaAttributes_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lsaActiveModeIndicator_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_lsaDataList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_lsaDataList_item_sequence, hf_index, ett_gsm_map_T_lsaDataList_item);

  return offset;
}
static int dissect_lsaDataList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_lsaDataList_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lsaDataList_item);
}

static const ber_sequence_t T_lsaDataList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lsaDataList_item },
};

static int
dissect_gsm_map_T_lsaDataList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_lsaDataList_sequence_of, hf_index, ett_gsm_map_T_lsaDataList);

  return offset;
}
static int dissect_lsaDataList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_lsaDataList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lsaDataList);
}

static const ber_sequence_t T_lsaInformation_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_completeDataListIncluded },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lsaOnlyAccessIndicator_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lsaDataList_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_lsaInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_lsaInformation_sequence, hf_index, ett_gsm_map_T_lsaInformation);

  return offset;
}
static int dissect_lsaInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_lsaInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lsaInformation);
}


static int
dissect_gsm_map_T_gmlc_List_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_gmlc_List_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_gmlc_List_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_gmlc_List_item);
}

static const ber_sequence_t T_gmlc_List_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_gmlc_List_item },
};

static int
dissect_gsm_map_T_gmlc_List(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_gmlc_List_sequence_of, hf_index, ett_gsm_map_T_gmlc_List);

  return offset;
}
static int dissect_gmlc_List_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_gmlc_List(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gmlc_List);
}


static const value_string gsm_map_NotificationToMSUser_vals[] = {
  {   0, "notifyLocationAllowed" },
  {   1, "notifyAndVerify-LocationAllowedIfNoResponse" },
  {   2, "notifyAndVerify-LocationNotAllowedIfNoResponse" },
  { 0, NULL }
};


static int
dissect_gsm_map_NotificationToMSUser(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_notificationToMSUser_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NotificationToMSUser(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_notificationToMSUser);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_1_20(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_externalAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_20(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_externalAddress);
}
static int dissect_omc_Id_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_20(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_omc_Id);
}
static int dissect_ss_EventSpecification_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_20(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_EventSpecification_item);
}
static int dissect_locationEstimate(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_20(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_locationEstimate);
}
static int dissect_locationEstimate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_20(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_locationEstimate);
}

static const ber_sequence_t T_clientIdentity_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_externalAddress_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_clientIdentity(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_clientIdentity_sequence, hf_index, ett_gsm_map_T_clientIdentity);

  return offset;
}
static int dissect_clientIdentity(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_clientIdentity(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_clientIdentity);
}


static const value_string gsm_map_T_gmlc_Restriction_vals[] = {
  {   0, "gmlc-List" },
  {   1, "home-Country" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_gmlc_Restriction(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_gmlc_Restriction_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_gmlc_Restriction(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gmlc_Restriction);
}

static const ber_sequence_t T_externalClientList_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_clientIdentity },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gmlc_Restriction_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToMSUser_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_externalClientList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_externalClientList_item_sequence, hf_index, ett_gsm_map_T_externalClientList_item);

  return offset;
}
static int dissect_externalClientList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_externalClientList_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_externalClientList_item);
}

static const ber_sequence_t T_externalClientList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_externalClientList_item },
};

static int
dissect_gsm_map_T_externalClientList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_externalClientList_sequence_of, hf_index, ett_gsm_map_T_externalClientList);

  return offset;
}
static int dissect_externalClientList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_externalClientList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_externalClientList);
}


static const value_string gsm_map_T_plmnClientList_item_vals[] = {
  {   0, "broadcastService" },
  {   1, "o-andM-HPLMN" },
  {   2, "o-andM-VPLMN" },
  {   3, "anonymousLocation" },
  {   4, "targetMSsubscribedService" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_plmnClientList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_plmnClientList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_plmnClientList_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_plmnClientList_item);
}

static const ber_sequence_t T_plmnClientList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_plmnClientList_item },
};

static int
dissect_gsm_map_T_plmnClientList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_plmnClientList_sequence_of, hf_index, ett_gsm_map_T_plmnClientList);

  return offset;
}
static int dissect_plmnClientList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_plmnClientList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_plmnClientList);
}

static const ber_sequence_t T_lcs_PrivacyExceptionList_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Status },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToMSUser_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_externalClientList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_plmnClientList_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_lcs_PrivacyExceptionList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_lcs_PrivacyExceptionList_item_sequence, hf_index, ett_gsm_map_T_lcs_PrivacyExceptionList_item);

  return offset;
}
static int dissect_lcs_PrivacyExceptionList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_lcs_PrivacyExceptionList_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_PrivacyExceptionList_item);
}

static const ber_sequence_t T_lcs_PrivacyExceptionList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lcs_PrivacyExceptionList_item },
};

static int
dissect_gsm_map_T_lcs_PrivacyExceptionList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_lcs_PrivacyExceptionList_sequence_of, hf_index, ett_gsm_map_T_lcs_PrivacyExceptionList);

  return offset;
}
static int dissect_lcs_PrivacyExceptionList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_lcs_PrivacyExceptionList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_PrivacyExceptionList);
}

static const ber_sequence_t T_molr_List_item_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Status },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_molr_List_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_molr_List_item_sequence, hf_index, ett_gsm_map_T_molr_List_item);

  return offset;
}
static int dissect_molr_List_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_molr_List_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_molr_List_item);
}

static const ber_sequence_t T_molr_List_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_molr_List_item },
};

static int
dissect_gsm_map_T_molr_List(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_molr_List_sequence_of, hf_index, ett_gsm_map_T_molr_List);

  return offset;
}
static int dissect_molr_List_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_molr_List(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_molr_List);
}

static const ber_sequence_t T_lcsInformation_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gmlc_List_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcs_PrivacyExceptionList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_molr_List_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_lcsInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_lcsInformation_sequence, hf_index, ett_gsm_map_T_lcsInformation);

  return offset;
}
static int dissect_lcsInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_lcsInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsInformation);
}

static const ber_sequence_t InsertSubscriberDataArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_category_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_subscriberStatus_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_bearerServiceList_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_teleserviceList_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_provisionedSS_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_odb_Data_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_roamingRestrictionDueToUnsupportedFeature_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_regionalSubscriptionData_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vbsSubscriptionData_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vgcsSubscriptionData_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vlrCamelSubscriptionInfo_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_naea_PreferredCI_impl },
  { BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprsSubscriptionData_impl },
  { BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_roamingRestrictedInSgsnDueToUnsupportedFeature_impl },
  { BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_networkAccessMode_impl },
  { BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lsaInformation_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lmu_Indicator_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsInformation_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_InsertSubscriberDataArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                InsertSubscriberDataArg_sequence, hf_index, ett_gsm_map_InsertSubscriberDataArg);

  return offset;
}

static const ber_sequence_t ss_List_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_List_item },
};

static int
dissect_gsm_map_ss_List(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   ss_List_sequence_of, hf_index, ett_gsm_map_ss_List);

  return offset;
}
static int dissect_ss_List_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ss_List(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_List);
}


static const value_string gsm_map_RegionalSubscriptionResponse_vals[] = {
  {   0, "networkNodeAreaRestricted" },
  {   1, "tooManyZoneCodes" },
  {   2, "zoneCodesConflict" },
  {   3, "regionalSubscNotSupported" },
  { 0, NULL }
};


static int
dissect_gsm_map_RegionalSubscriptionResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_regionalSubscriptionResponse_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RegionalSubscriptionResponse(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_regionalSubscriptionResponse);
}

static const ber_sequence_t InsertSubscriberDataRes_sequence[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_teleserviceList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_bearerServiceList_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_List_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_odb_GeneralData_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_regionalSubscriptionResponse_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedCamelPhases_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_InsertSubscriberDataRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                InsertSubscriberDataRes_sequence, hf_index, ett_gsm_map_InsertSubscriberDataRes);

  return offset;
}

static const ber_sequence_t T_contextIdList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_contextIdList_item },
};

static int
dissect_gsm_map_T_contextIdList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_contextIdList_sequence_of, hf_index, ett_gsm_map_T_contextIdList);

  return offset;
}
static int dissect_contextIdList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_contextIdList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_contextIdList);
}


static const value_string gsm_map_T_gprsSubscriptionDataWithdraw_vals[] = {
  {   0, "allGPRSData" },
  {   1, "contextIdList" },
  { 0, NULL }
};

static const ber_choice_t T_gprsSubscriptionDataWithdraw_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_allGPRSData },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_contextIdList },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_gprsSubscriptionDataWithdraw(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              T_gprsSubscriptionDataWithdraw_choice, hf_index, ett_gsm_map_T_gprsSubscriptionDataWithdraw);

  return offset;
}
static int dissect_gprsSubscriptionDataWithdraw(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_gprsSubscriptionDataWithdraw(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_gprsSubscriptionDataWithdraw);
}

static const ber_sequence_t T_lsaIdentityList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_lsaIdentityList_item },
};

static int
dissect_gsm_map_T_lsaIdentityList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_lsaIdentityList_sequence_of, hf_index, ett_gsm_map_T_lsaIdentityList);

  return offset;
}
static int dissect_lsaIdentityList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_lsaIdentityList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lsaIdentityList);
}


static const value_string gsm_map_T_lsaInformationWithdraw_vals[] = {
  {   0, "allLSAData" },
  {   1, "lsaIdentityList" },
  { 0, NULL }
};

static const ber_choice_t T_lsaInformationWithdraw_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_allLSAData },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lsaIdentityList },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_lsaInformationWithdraw(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              T_lsaInformationWithdraw_choice, hf_index, ett_gsm_map_T_lsaInformationWithdraw);

  return offset;
}
static int dissect_lsaInformationWithdraw(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_lsaInformationWithdraw(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lsaInformationWithdraw);
}

static const ber_sequence_t DeleteSubscriberDataArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_basicServiceList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_List_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_roamingRestrictionDueToUnsupportedFeature_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_regionalSubscriptionIdentifier_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vbsGroupIndication_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vgcsGroupIndication_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camelSubscriptionInfoWithdraw_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_gprsSubscriptionDataWithdraw },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_roamingRestrictedInSgsnDueToUnsuppportedFeature_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_lsaInformationWithdraw },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gmlc_ListWithdraw_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_DeleteSubscriberDataArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                DeleteSubscriberDataArg_sequence, hf_index, ett_gsm_map_DeleteSubscriberDataArg);

  return offset;
}

static const ber_sequence_t DeleteSubscriberDataRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_regionalSubscriptionResponse_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_DeleteSubscriberDataRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                DeleteSubscriberDataRes_sequence, hf_index, ett_gsm_map_DeleteSubscriberDataRes);

  return offset;
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_3_8(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_hlr_List_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_3_8(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_hlr_List_item);
}

static const ber_sequence_t T_hlr_List_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_hlr_List_item },
};

static int
dissect_gsm_map_T_hlr_List(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_hlr_List_sequence_of, hf_index, ett_gsm_map_T_hlr_List);

  return offset;
}
static int dissect_hlr_List(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_hlr_List(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_hlr_List);
}

static const ber_sequence_t ResetArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_hlr_Number },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_hlr_List },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ResetArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ResetArg_sequence, hf_index, ett_gsm_map_ResetArg);

  return offset;
}

static const ber_sequence_t RestoreDataArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_lmsi },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vlr_Capability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RestoreDataArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                RestoreDataArg_sequence, hf_index, ett_gsm_map_RestoreDataArg);

  return offset;
}

static const ber_sequence_t RestoreDataRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_hlr_Number },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_msNotReachable },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RestoreDataRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                RestoreDataRes_sequence, hf_index, ett_gsm_map_RestoreDataRes);

  return offset;
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_1_2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_traceReference_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_2(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_traceReference);
}



static int
dissect_gsm_map_INTEGER_0_255(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_traceType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_255(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_traceType);
}
static int dissect_absentSubscriberDiagnosticSM(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_255(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_absentSubscriberDiagnosticSM);
}
static int dissect_absentSubscriberDiagnosticSM_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_255(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_absentSubscriberDiagnosticSM);
}
static int dissect_additionalAbsentSubscriberDiagnosticSM_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_255(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_additionalAbsentSubscriberDiagnosticSM);
}
static int dissect_mobileNotReachableReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_255(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_mobileNotReachableReason);
}

static const ber_sequence_t ActivateTraceModeArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_traceReference_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_traceType_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_omc_Id_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ActivateTraceModeArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ActivateTraceModeArg_sequence, hf_index, ett_gsm_map_ActivateTraceModeArg);

  return offset;
}

static const ber_sequence_t ActivateTraceModeRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ActivateTraceModeRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ActivateTraceModeRes_sequence, hf_index, ett_gsm_map_ActivateTraceModeRes);

  return offset;
}

static const ber_sequence_t DeactivateTraceModeArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_traceReference_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_DeactivateTraceModeArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                DeactivateTraceModeArg_sequence, hf_index, ett_gsm_map_DeactivateTraceModeArg);

  return offset;
}

static const ber_sequence_t DeactivateTraceModeRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_DeactivateTraceModeRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                DeactivateTraceModeRes_sequence, hf_index, ett_gsm_map_DeactivateTraceModeRes);

  return offset;
}

static const ber_sequence_t Cug_CheckInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cug_Interlock },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cug_OutgoingAccess },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Cug_CheckInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Cug_CheckInfo_sequence, hf_index, ett_gsm_map_Cug_CheckInfo);

  return offset;
}
static int dissect_cug_CheckInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Cug_CheckInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cug_CheckInfo);
}


static const value_string gsm_map_T_interrogationType_vals[] = {
  {   0, "basicCall" },
  {   1, "forwarding" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_interrogationType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_interrogationType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_interrogationType(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_interrogationType);
}



static int
dissect_gsm_map_INTEGER_1_127(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_or_Capability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_1_127(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_or_Capability);
}
static int dissect_supportedCCBS_Phase_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_1_127(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_supportedCCBS_Phase);
}


static int
dissect_gsm_map_Gmsc_Address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

 tvbuff_t	*parameter_tvb;
 char		*digit_str;

 offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    &parameter_tvb);

 if (!parameter_tvb)
	return offset;

 proto_tree_add_item(tree, hf_gsm_map_extension, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(tree, hf_gsm_map_nature_of_number, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(tree, hf_gsm_map_number_plan, parameter_tvb, 0,1,FALSE);

 digit_str = unpack_digits(parameter_tvb, 1);

 proto_tree_add_string(tree, hf_gsm_map_map_gmsc_address_digits, parameter_tvb, 1, -1, digit_str);
 g_free(digit_str);



  return offset;
}
static int dissect_gmsc_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Gmsc_Address(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gmsc_Address);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_1_8(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_callReferenceNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_8(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callReferenceNumber);
}
static int dissect_asciCallReference(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_8(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_asciCallReference);
}


static const value_string gsm_map_T_forwardingReason_vals[] = {
  {   0, "notReachable" },
  {   1, "busy" },
  {   2, "noReply" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_forwardingReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_forwardingReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_forwardingReason(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingReason);
}

static const ber_sequence_t T_camelInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_supportedCamelPhases },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_suppress_T_CSI },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_camelInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_camelInfo_sequence, hf_index, ett_gsm_map_T_camelInfo);

  return offset;
}
static int dissect_camelInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_camelInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_camelInfo);
}


static const value_string gsm_map_T_ext_ProtocolId_vals[] = {
  {   1, "ets-300356" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_ext_ProtocolId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_ext_ProtocolId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_ext_ProtocolId(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ext_ProtocolId);
}


static int
dissect_gsm_map_ExtSignalInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_ext_signalInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExtSignalInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ext_signalInfo);
}

static const ber_sequence_t AdditionalSignalInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ext_ProtocolId },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ext_signalInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AdditionalSignalInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                AdditionalSignalInfo_sequence, hf_index, ett_gsm_map_AdditionalSignalInfo);

  return offset;
}
static int dissect_additionalSignalInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AdditionalSignalInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_additionalSignalInfo);
}

static const ber_sequence_t SendRoutingInfoArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cug_CheckInfo_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_numberOfForwarding_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_interrogationType_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_or_Interrogation_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_or_Capability_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gmsc_Address_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callReferenceNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardingReason_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_basicServiceGroup },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_networkSignalInfo_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camelInfo_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_suppressionOfAnnouncement_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertingPattern_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Call_impl },
  { BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedCCBS_Phase_impl },
  { BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additionalSignalInfo_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendRoutingInfoArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SendRoutingInfoArg_sequence, hf_index, ett_gsm_map_SendRoutingInfoArg);

  return offset;
}


static int
dissect_gsm_map_RoamingNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

 tvbuff_t	*parameter_tvb;
 char		*digit_str;

 offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    &parameter_tvb);

 if (!parameter_tvb)
	return offset;

 proto_tree_add_item(tree, hf_gsm_map_extension, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(tree, hf_gsm_map_nature_of_number, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(tree, hf_gsm_map_number_plan, parameter_tvb, 0,1,FALSE);

 digit_str = unpack_digits(parameter_tvb, 1);

 proto_tree_add_string(tree, hf_gsm_map_map_RoamingNumber_digits, parameter_tvb, 1, -1, digit_str);
 g_free(digit_str);



  return offset;
}
static int dissect_roamingNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RoamingNumber(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_roamingNumber);
}

static const ber_sequence_t ForwardingData_sequence[] = {
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToNumber_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToSubaddress_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardingOptions_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ForwardingData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ForwardingData_sequence, hf_index, ett_gsm_map_ForwardingData);

  return offset;
}
static int dissect_forwardingData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ForwardingData(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingData);
}
static int dissect_forwardingData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ForwardingData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingData);
}


static const value_string gsm_map_T_routingInfo_vals[] = {
  {   0, "roamingNumber" },
  {   1, "forwardingData" },
  { 0, NULL }
};

static const ber_choice_t T_routingInfo_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_roamingNumber },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_forwardingData },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_routingInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              T_routingInfo_choice, hf_index, ett_gsm_map_T_routingInfo);

  return offset;
}
static int dissect_routingInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_routingInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_routingInfo);
}

static const ber_sequence_t T_t_CSI_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_t_BcsmCamelTDPDataList },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camelCapabilityHandling_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_t_CSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_t_CSI_sequence, hf_index, ett_gsm_map_T_t_CSI);

  return offset;
}
static int dissect_t_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_t_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_t_CSI);
}

static const ber_sequence_t T_gmscCamelSubscriptionInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_t_CSI_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_CSI_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_BcsmCamelTDP_CriteriaList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_gmscCamelSubscriptionInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_gmscCamelSubscriptionInfo_sequence, hf_index, ett_gsm_map_T_gmscCamelSubscriptionInfo);

  return offset;
}
static int dissect_gmscCamelSubscriptionInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_gmscCamelSubscriptionInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gmscCamelSubscriptionInfo);
}

static const ber_sequence_t T_camelRoutingInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_forwardingData },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gmscCamelSubscriptionInfo_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_camelRoutingInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_camelRoutingInfo_sequence, hf_index, ett_gsm_map_T_camelRoutingInfo);

  return offset;
}
static int dissect_camelRoutingInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_camelRoutingInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_camelRoutingInfo);
}


static const value_string gsm_map_T_extendedRoutingInfo_vals[] = {
  {   0, "routingInfo" },
  {   1, "camelRoutingInfo" },
  { 0, NULL }
};

static const ber_choice_t T_extendedRoutingInfo_choice[] = {
  {   0, BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_routingInfo },
  {   1, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_camelRoutingInfo_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_extendedRoutingInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              T_extendedRoutingInfo_choice, hf_index, ett_gsm_map_T_extendedRoutingInfo);

  return offset;
}
static int dissect_extendedRoutingInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_extendedRoutingInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_extendedRoutingInfo);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_2_10(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_locationNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_2_10(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_locationNumber);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_7(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_cellIdFixedLength_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_7(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cellIdFixedLength);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_5(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_laiFixedLength_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_5(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_laiFixedLength);
}


static const value_string gsm_map_T_cellIdOrLAI_vals[] = {
  {   0, "cellIdFixedLength" },
  {   1, "laiFixedLength" },
  { 0, NULL }
};

static const ber_choice_t T_cellIdOrLAI_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cellIdFixedLength_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_laiFixedLength_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_cellIdOrLAI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              T_cellIdOrLAI_choice, hf_index, ett_gsm_map_T_cellIdOrLAI);

  return offset;
}
static int dissect_cellIdOrLAI(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_cellIdOrLAI(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cellIdOrLAI);
}

static const ber_sequence_t LocationInformation_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ageOfLocationInformation },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_geographicalInformation_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vlr_number_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationNumber_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_cellIdOrLAI },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LocationInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                LocationInformation_sequence, hf_index, ett_gsm_map_LocationInformation);

  return offset;
}
static int dissect_locationInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LocationInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_locationInformation);
}


static const value_string gsm_map_SubscriberState_vals[] = {
  {   0, "assumedIdle" },
  {   1, "camelBusy" },
  {   2, "notProvidedFromVLR" },
  { 0, NULL }
};

static const ber_choice_t SubscriberState_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_assumedIdle_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_camelBusy_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_notProvidedFromVLR_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SubscriberState(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              SubscriberState_choice, hf_index, ett_gsm_map_SubscriberState);

  return offset;
}
static int dissect_subscriberState(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SubscriberState(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_subscriberState);
}

static const ber_sequence_t SubscriberInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationInformation_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_subscriberState },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SubscriberInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SubscriberInfo_sequence, hf_index, ett_gsm_map_SubscriberInfo);

  return offset;
}
static int dissect_subscriberInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SubscriberInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_subscriberInfo);
}
static int dissect_subscriberInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SubscriberInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_subscriberInfo);
}


static int
dissect_gsm_map_T_vmsc_Address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_vmsc_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_vmsc_Address(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vmsc_Address);
}

static const ber_sequence_t T_ccbs_Indicators_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Possible_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_keepCCBS_CallIndicator_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_ccbs_Indicators(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_ccbs_Indicators_sequence, hf_index, ett_gsm_map_T_ccbs_Indicators);

  return offset;
}
static int dissect_ccbs_Indicators_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_ccbs_Indicators(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Indicators);
}


static const value_string gsm_map_T_numberPortabilityStatus_vals[] = {
  {   0, "notKnownToBePorted" },
  {   1, "ownNumberPortedOut" },
  {   2, "foreignNumberPortedToForeignNetwork" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_numberPortabilityStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_numberPortabilityStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_numberPortabilityStatus(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_numberPortabilityStatus);
}

static const ber_sequence_t SendRoutingInfoRes_sequence[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { -1/*choice*/ , -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extendedRoutingInfo },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cug_CheckInfo_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cugSubscriptionFlag_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_subscriberInfo_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_List_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_basicService },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardingInterrogationRequired_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vmsc_Address_impl },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_naea_PreferredCI_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Indicators_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_numberPortabilityStatus_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendRoutingInfoRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SendRoutingInfoRes_sequence, hf_index, ett_gsm_map_SendRoutingInfoRes);

  return offset;
}


static const value_string gsm_map_NetDetNotReachable_vals[] = {
  {   0, "msPurged" },
  {   1, "imsiDetached" },
  {   2, "restrictedArea" },
  {   3, "notRegistered" },
  { 0, NULL }
};


static int
dissect_gsm_map_NetDetNotReachable(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}

static const ber_sequence_t ProvideRoamingNumberArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_msc_Number_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lmsi_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_BearerCapability_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_networkSignalInfo_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_suppressionOfAnnouncement_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gmsc_Address_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callReferenceNumber_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_or_Interrogation_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertingPattern_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Call_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedCamelPhasesInGMSC_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additionalSignalInfo_impl },
  { BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_orNotSupportedInGMSC_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ProvideRoamingNumberArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ProvideRoamingNumberArg_sequence, hf_index, ett_gsm_map_ProvideRoamingNumberArg);

  return offset;
}

static const ber_sequence_t ProvideRoamingNumberRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_roamingNumber },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ProvideRoamingNumberRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ProvideRoamingNumberRes_sequence, hf_index, ett_gsm_map_ProvideRoamingNumberRes);

  return offset;
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_1_131(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_uui_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_131(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uui);
}

static const ber_sequence_t T_uu_Data_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uuIndicator_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uui_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uusCFInteraction_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_uu_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_uu_Data_sequence, hf_index, ett_gsm_map_T_uu_Data);

  return offset;
}
static int dissect_uu_Data_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_uu_Data(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uu_Data);
}

static const ber_sequence_t ResumeCallHandlingArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callReferenceNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_basicServiceGroup },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardingData_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cug_CheckInfo_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_CSI_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Possible_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uu_Data_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_allInformationSent_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ResumeCallHandlingArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ResumeCallHandlingArg_sequence, hf_index, ett_gsm_map_ResumeCallHandlingArg);

  return offset;
}

static const ber_sequence_t ResumeCallHandlingRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ResumeCallHandlingRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ResumeCallHandlingRes_sequence, hf_index, ett_gsm_map_ResumeCallHandlingRes);

  return offset;
}


static int
dissect_gsm_map_T_b_Subscriber_Address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_b_Subscriber_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_b_Subscriber_Address(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_b_Subscriber_Address);
}

static const ber_sequence_t ProvideSIWFSNumberArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gsm_BearerCapability_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_BearerCapability_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_call_Direction_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_b_Subscriber_Address_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_chosenChannel_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lowerLayerCompatibility_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_highLayerCompatibility_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ProvideSIWFSNumberArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ProvideSIWFSNumberArg_sequence, hf_index, ett_gsm_map_ProvideSIWFSNumberArg);

  return offset;
}


static int
dissect_gsm_map_T_sIWFSNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_sIWFSNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_sIWFSNumber(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sIWFSNumber);
}

static const ber_sequence_t ProvideSIWFSNumberRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sIWFSNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ProvideSIWFSNumberRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ProvideSIWFSNumberRes_sequence, hf_index, ett_gsm_map_ProvideSIWFSNumberRes);

  return offset;
}

static const ber_sequence_t SIWFSSignallingModifyArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_channelType_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_chosenChannel_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SIWFSSignallingModifyArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SIWFSSignallingModifyArg_sequence, hf_index, ett_gsm_map_SIWFSSignallingModifyArg);

  return offset;
}

static const ber_sequence_t SIWFSSignallingModifyRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_chosenChannel_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SIWFSSignallingModifyRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SIWFSSignallingModifyRes_sequence, hf_index, ett_gsm_map_SIWFSSignallingModifyRes);

  return offset;
}


static const value_string gsm_map_Ccbs_Monitoring_vals[] = {
  {   0, "stopMonitoring" },
  {   1, "startMonitoring" },
  { 0, NULL }
};


static int
dissect_gsm_map_Ccbs_Monitoring(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_ccbs_Monitoring_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ccbs_Monitoring(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Monitoring);
}

static const ber_sequence_t SetReportingStateArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lmsi_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Monitoring_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SetReportingStateArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SetReportingStateArg_sequence, hf_index, ett_gsm_map_SetReportingStateArg);

  return offset;
}


static const value_string gsm_map_Ccbs_SubscriberStatus_vals[] = {
  {   0, "ccbsNotIdle" },
  {   1, "ccbsIdle" },
  {   2, "ccbsNotReachable" },
  { 0, NULL }
};


static int
dissect_gsm_map_Ccbs_SubscriberStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_ccbs_SubscriberStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ccbs_SubscriberStatus(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_SubscriberStatus);
}

static const ber_sequence_t SetReportingStateRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_SubscriberStatus_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SetReportingStateRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SetReportingStateRes_sequence, hf_index, ett_gsm_map_SetReportingStateRes);

  return offset;
}


static const value_string gsm_map_MonitoringMode_vals[] = {
  {   0, "a-side" },
  {   1, "b-side" },
  { 0, NULL }
};


static int
dissect_gsm_map_MonitoringMode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_monitoringMode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MonitoringMode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_monitoringMode);
}


static const value_string gsm_map_CallOutcome_vals[] = {
  {   0, "success" },
  {   1, "failure" },
  {   2, "busy" },
  { 0, NULL }
};


static int
dissect_gsm_map_CallOutcome(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_callOutcome_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallOutcome(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callOutcome);
}

static const ber_sequence_t T_eventReportData_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_SubscriberStatus_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_eventReportData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_eventReportData_sequence, hf_index, ett_gsm_map_T_eventReportData);

  return offset;
}
static int dissect_eventReportData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_eventReportData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_eventReportData);
}

static const ber_sequence_t T_callReportdata_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_monitoringMode_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callOutcome_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_callReportdata(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_callReportdata_sequence, hf_index, ett_gsm_map_T_callReportdata);

  return offset;
}
static int dissect_callReportdata_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_callReportdata(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callReportdata);
}

static const ber_sequence_t StatusReportArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_eventReportData_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callReportdata_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_StatusReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                StatusReportArg_sequence, hf_index, ett_gsm_map_StatusReportArg);

  return offset;
}

static const ber_sequence_t StatusReportRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_StatusReportRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                StatusReportRes_sequence, hf_index, ett_gsm_map_StatusReportRes);

  return offset;
}


static const value_string gsm_map_Ruf_Outcome_vals[] = {
  {   0, "accepted" },
  {   1, "rejected" },
  {   2, "noResponseFromFreeMS" },
  {   3, "noResponseFromBusyMS" },
  {   4, "udubFromFreeMS" },
  {   5, "udubFromBusyMS" },
  { 0, NULL }
};


static int
dissect_gsm_map_Ruf_Outcome(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_ruf_Outcome_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ruf_Outcome(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ruf_Outcome);
}


static int
dissect_gsm_map_B_subscriberNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_b_subscriberNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_B_subscriberNumber(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_b_subscriberNumber);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_1_21(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_b_subscriberSubaddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_21(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_b_subscriberSubaddress);
}

static const ber_sequence_t Ccbs_Feature_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Index_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_b_subscriberNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_b_subscriberSubaddress_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_basicServiceGroup },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ccbs_Feature(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Ccbs_Feature_sequence, hf_index, ett_gsm_map_Ccbs_Feature);

  return offset;
}
static int dissect_ccbs_Feature_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ccbs_Feature(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Feature);
}


static int
dissect_gsm_map_TranslatedB_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_translatedB_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_TranslatedB_Number(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_translatedB_Number);
}

static const ber_sequence_t RemoteUserFreeArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_callInfo_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ccbs_Feature_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_translatedB_Number_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_replaceB_Number_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertingPattern_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RemoteUserFreeArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                RemoteUserFreeArg_sequence, hf_index, ett_gsm_map_RemoteUserFreeArg);

  return offset;
}

static const ber_sequence_t RemoteUserFreeRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ruf_Outcome_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RemoteUserFreeRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                RemoteUserFreeRes_sequence, hf_index, ett_gsm_map_RemoteUserFreeRes);

  return offset;
}

static const ber_sequence_t Ss_Data_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_Status_impl },
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ss_SubscriptionOption },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_basicServiceGroupList },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_defaultPriority },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ss_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Ss_Data_sequence, hf_index, ett_gsm_map_Ss_Data);

  return offset;
}
static int dissect_ss_Data_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ss_Data(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Data);
}

static const ber_sequence_t RegisterSS_Arg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_basicService },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToNumber_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToSubaddress_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noReplyConditionTime_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_defaultPriority_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RegisterSS_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                RegisterSS_Arg_sequence, hf_index, ett_gsm_map_RegisterSS_Arg);

  return offset;
}


static const value_string gsm_map_Ss_Info_vals[] = {
  {   0, "forwardingInfo" },
  {   1, "callBarringInfo" },
  {   3, "ss-Data" },
  { 0, NULL }
};

static const ber_choice_t Ss_Info_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_forwardingInfo_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_callBarringInfo_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ss_Data_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ss_Info(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              Ss_Info_choice, hf_index, ett_gsm_map_Ss_Info);

  return offset;
}

static const ber_sequence_t Ss_ForBS_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_basicService },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ss_ForBS(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Ss_ForBS_sequence, hf_index, ett_gsm_map_Ss_ForBS);

  return offset;
}

static const ber_sequence_t SEQUENCE_SIZE_1_13_OF_ForwardingFeatureList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_forwardingFeatureList_item },
};

static int
dissect_gsm_map_SEQUENCE_SIZE_1_13_OF_ForwardingFeatureList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   SEQUENCE_SIZE_1_13_OF_ForwardingFeatureList_sequence_of, hf_index, ett_gsm_map_SEQUENCE_SIZE_1_13_OF_ForwardingFeatureList);

  return offset;
}
static int dissect_forwardingFeatureList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SEQUENCE_SIZE_1_13_OF_ForwardingFeatureList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingFeatureList);
}

static const ber_sequence_t T_ccbs_FeatureList_item_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Index_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_b_subscriberNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_b_subscriberSubaddress_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_basicServiceGroup },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_ccbs_FeatureList_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_ccbs_FeatureList_item_sequence, hf_index, ett_gsm_map_T_ccbs_FeatureList_item);

  return offset;
}
static int dissect_ccbs_FeatureList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_ccbs_FeatureList_item(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_FeatureList_item);
}

static const ber_sequence_t T_ccbs_FeatureList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ccbs_FeatureList_item },
};

static int
dissect_gsm_map_T_ccbs_FeatureList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_ccbs_FeatureList_sequence_of, hf_index, ett_gsm_map_T_ccbs_FeatureList);

  return offset;
}
static int dissect_ccbs_FeatureList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_ccbs_FeatureList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_FeatureList);
}

static const ber_sequence_t T_genericServiceInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Status },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cliRestrictionOption_impl },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_maximumEntitledPriority_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_defaultPriority_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_FeatureList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_genericServiceInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_genericServiceInfo_sequence, hf_index, ett_gsm_map_T_genericServiceInfo);

  return offset;
}
static int dissect_genericServiceInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_genericServiceInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_genericServiceInfo);
}


static const value_string gsm_map_InterrogateSS_Res_vals[] = {
  {   0, "ss-Status" },
  {   2, "basicServiceGroupList" },
  {   3, "forwardingFeatureList" },
  {   4, "genericServiceInfo" },
  { 0, NULL }
};

static const ber_choice_t InterrogateSS_Res_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ss_Status_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_basicServiceGroupList_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_forwardingFeatureList_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_genericServiceInfo_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_InterrogateSS_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              InterrogateSS_Res_choice, hf_index, ett_gsm_map_InterrogateSS_Res);

  return offset;
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_1_160(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_ussd_String(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_160(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ussd_String);
}

static const ber_sequence_t Ussd_Arg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ussd_DataCodingScheme },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ussd_String },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_alertingPattern },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ussd_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Ussd_Arg_sequence, hf_index, ett_gsm_map_Ussd_Arg);

  return offset;
}

static const ber_sequence_t Ussd_Res_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ussd_DataCodingScheme },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ussd_String },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ussd_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Ussd_Res_sequence, hf_index, ett_gsm_map_Ussd_Res);

  return offset;
}


static int
dissect_gsm_map_NewPassword(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}


static const value_string gsm_map_GetPasswordArg_vals[] = {
  {   0, "enterPW" },
  {   1, "enterNewPW" },
  {   2, "enterNewPW-Again" },
  { 0, NULL }
};


static int
dissect_gsm_map_GetPasswordArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static int
dissect_gsm_map_CurrentPassword(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}

static const asn_namedbit ServiceIndicator_bits[] = {
  {  0, &hf_gsm_map_ServiceIndicator_clirInvoked, -1, -1, NULL, NULL },
  {  1, &hf_gsm_map_ServiceIndicator_camelInvoked, -1, -1, NULL, NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_ServiceIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 ServiceIndicator_bits, hf_index, ett_gsm_map_ServiceIndicator,
                                 NULL);

  return offset;
}
static int dissect_serviceIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ServiceIndicator(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_serviceIndicator);
}

static const ber_sequence_t T_ccbs_Data_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ccbs_Feature_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_translatedB_Number_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceIndicator_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_callInfo_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_networkSignalInfo_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_ccbs_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_ccbs_Data_sequence, hf_index, ett_gsm_map_T_ccbs_Data);

  return offset;
}
static int dissect_ccbs_Data_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_ccbs_Data(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Data);
}

static const ber_sequence_t RegisterCC_EntryArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ss_Code_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Data_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RegisterCC_EntryArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                RegisterCC_EntryArg_sequence, hf_index, ett_gsm_map_RegisterCC_EntryArg);

  return offset;
}

static const ber_sequence_t RegisterCC_EntryRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Feature_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RegisterCC_EntryRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                RegisterCC_EntryRes_sequence, hf_index, ett_gsm_map_RegisterCC_EntryRes);

  return offset;
}

static const ber_sequence_t EraseCC_EntryArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ss_Code_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Index_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_EraseCC_EntryArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                EraseCC_EntryArg_sequence, hf_index, ett_gsm_map_EraseCC_EntryArg);

  return offset;
}

static const ber_sequence_t EraseCC_EntryRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ss_Code_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_Status_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_EraseCC_EntryRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                EraseCC_EntryRes_sequence, hf_index, ett_gsm_map_EraseCC_EntryRes);

  return offset;
}


static int
dissect_gsm_map_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_sm_RP_PRI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sm_RP_PRI);
}


static int
dissect_gsm_map_ServiceCentreAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

 tvbuff_t	*parameter_tvb;
 char		*digit_str;

 offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    &parameter_tvb);
 if (!parameter_tvb)
	return offset;

 proto_tree_add_item(tree, hf_gsm_map_extension, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(tree, hf_gsm_map_nature_of_number, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(tree, hf_gsm_map_number_plan, parameter_tvb, 0,1,FALSE);

 digit_str = unpack_digits(parameter_tvb, 1);

 proto_tree_add_string(tree, hf_gsm_map_servicecentreaddress_digits, parameter_tvb, 1, -1, digit_str);
 g_free(digit_str);



  return offset;
}
static int dissect_serviceCentreAddress(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ServiceCentreAddress(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_serviceCentreAddress);
}
static int dissect_serviceCentreAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ServiceCentreAddress(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_serviceCentreAddress);
}
static int dissect_serviceCentreAddressOA_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ServiceCentreAddress(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_serviceCentreAddressOA);
}
static int dissect_serviceCentreAddressDA_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ServiceCentreAddress(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_serviceCentreAddressDA);
}



static int
dissect_gsm_map_INTEGER_0_10(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_sm_RP_MTI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_10(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sm_RP_MTI);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_1_12(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_sm_RP_SMEA_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_12(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sm_RP_SMEA);
}

static const ber_sequence_t RoutingInfoForSMArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sm_RP_PRI_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_serviceCentreAddress_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprsSupportIndicator_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sm_RP_MTI_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sm_RP_SMEA_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RoutingInfoForSMArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                RoutingInfoForSMArg_sequence, hf_index, ett_gsm_map_RoutingInfoForSMArg);

  return offset;
}


static int
dissect_gsm_map_T_networkNode_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_networkNode_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_networkNode_Number(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_networkNode_Number);
}


static const value_string gsm_map_T_additional_Number_vals[] = {
  {   0, "msc-Number" },
  {   1, "sgsn-Number" },
  { 0, NULL }
};

static const ber_choice_t T_additional_Number_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_msc_Number_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgsn_Number_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_additional_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              T_additional_Number_choice, hf_index, ett_gsm_map_T_additional_Number);

  return offset;
}
static int dissect_additional_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_additional_Number(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_additional_Number);
}

static const ber_sequence_t T_locationInfoWithLMSI_sequence[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_networkNode_Number_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_lmsi },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprsNodeIndicator_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_additional_Number },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_locationInfoWithLMSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_locationInfoWithLMSI_sequence, hf_index, ett_gsm_map_T_locationInfoWithLMSI);

  return offset;
}
static int dissect_locationInfoWithLMSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_locationInfoWithLMSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_locationInfoWithLMSI);
}

static const ber_sequence_t RoutingInfoForSMRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_locationInfoWithLMSI_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RoutingInfoForSMRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                RoutingInfoForSMRes_sequence, hf_index, ett_gsm_map_RoutingInfoForSMRes);

  return offset;
}


static const value_string gsm_map_Sm_RP_DA_vals[] = {
  {   0, "imsi" },
  {   1, "lmsi" },
  {   4, "serviceCentreAddressDA" },
  {   5, "noSM-RP-DA" },
  { 0, NULL }
};

static const ber_choice_t Sm_RP_DA_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lmsi_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_serviceCentreAddressDA_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_noSM_RP_DA_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Sm_RP_DA(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              Sm_RP_DA_choice, hf_index, ett_gsm_map_Sm_RP_DA);

  return offset;
}
static int dissect_sm_RP_DA(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Sm_RP_DA(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sm_RP_DA);
}


static const value_string gsm_map_Sm_RP_OA_vals[] = {
  {   2, "msisdn" },
  {   4, "serviceCentreAddressOA" },
  {   5, "noSM-RP-OA" },
  { 0, NULL }
};

static const ber_choice_t Sm_RP_OA_choice[] = {
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_serviceCentreAddressOA_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_noSM_RP_OA_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Sm_RP_OA(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              Sm_RP_OA_choice, hf_index, ett_gsm_map_Sm_RP_OA);

  return offset;
}
static int dissect_sm_RP_OA(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Sm_RP_OA(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sm_RP_OA);
}


static int
dissect_gsm_map_Sm_RP_UI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

  tvbuff_t	*tpdu_tvb;
  	
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    &tpdu_tvb);
    /*
     * dissect the embedded TPDU message
     */
 if (!tpdu_tvb)
	return offset;

    dissector_try_port(sms_dissector_table, 0, tpdu_tvb, pinfo, top_tree);

  return offset;
}
static int dissect_sm_RP_UI(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Sm_RP_UI(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sm_RP_UI);
}

static const ber_sequence_t Mo_forwardSM_Arg_sequence[] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sm_RP_DA },
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sm_RP_OA },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sm_RP_UI },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_imsi },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Mo_forwardSM_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Mo_forwardSM_Arg_sequence, hf_index, ett_gsm_map_Mo_forwardSM_Arg);

  return offset;
}

static const ber_sequence_t Mo_forwardSM_Res_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sm_RP_UI },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Mo_forwardSM_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Mo_forwardSM_Res_sequence, hf_index, ett_gsm_map_Mo_forwardSM_Res);

  return offset;
}

static const ber_sequence_t Mt_forwardSM_Arg_sequence[] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sm_RP_DA },
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sm_RP_OA },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sm_RP_UI },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_moreMessagesToSend },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Mt_forwardSM_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Mt_forwardSM_Arg_sequence, hf_index, ett_gsm_map_Mt_forwardSM_Arg);

  return offset;
}

static const ber_sequence_t Mt_forwardSM_Res_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sm_RP_UI },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Mt_forwardSM_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Mt_forwardSM_Res_sequence, hf_index, ett_gsm_map_Mt_forwardSM_Res);

  return offset;
}


static int
dissect_gsm_map_StoredMSISDN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_Msisdn(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_storedMSISDN(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_StoredMSISDN(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_storedMSISDN);
}


static const value_string gsm_map_Sm_DeliveryOutcome_vals[] = {
  {   0, "memoryCapacityExceeded" },
  {   1, "absentSubscriber" },
  {   2, "successfulTransfer" },
  { 0, NULL }
};


static int
dissect_gsm_map_Sm_DeliveryOutcome(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_sm_DeliveryOutcome(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Sm_DeliveryOutcome(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sm_DeliveryOutcome);
}
static int dissect_additionalSM_DeliveryOutcome_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Sm_DeliveryOutcome(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_additionalSM_DeliveryOutcome);
}

static const ber_sequence_t ReportSM_DeliveryStatusArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_msisdn },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_serviceCentreAddress },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_sm_DeliveryOutcome },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_absentSubscriberDiagnosticSM_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprsSupportIndicator_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deliveryOutcomeIndicator_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additionalSM_DeliveryOutcome_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additionalAbsentSubscriberDiagnosticSM_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ReportSM_DeliveryStatusArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ReportSM_DeliveryStatusArg_sequence, hf_index, ett_gsm_map_ReportSM_DeliveryStatusArg);

  return offset;
}

static const ber_sequence_t ReportSM_DeliveryStatusRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_storedMSISDN },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ReportSM_DeliveryStatusRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ReportSM_DeliveryStatusRes_sequence, hf_index, ett_gsm_map_ReportSM_DeliveryStatusRes);

  return offset;
}

static const asn_namedbit T_mw_Status_bits[] = {
  {  0, &hf_gsm_map_T_mw_Status_scAddressNotIncluded, -1, -1, NULL, NULL },
  {  1, &hf_gsm_map_T_mw_Status_mnrfSet, -1, -1, NULL, NULL },
  {  2, &hf_gsm_map_T_mw_Status_mcefSet, -1, -1, NULL, NULL },
  {  3, &hf_gsm_map_T_mw_Status_mnrgSet, -1, -1, NULL, NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_T_mw_Status(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 T_mw_Status_bits, hf_index, ett_gsm_map_T_mw_Status,
                                 NULL);

  return offset;
}
static int dissect_mw_Status(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_mw_Status(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_mw_Status);
}

static const ber_sequence_t InformServiceCentreArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_storedMSISDN },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_mw_Status },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_InformServiceCentreArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                InformServiceCentreArg_sequence, hf_index, ett_gsm_map_InformServiceCentreArg);

  return offset;
}

static const ber_sequence_t AlertServiceCentreArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_msisdn },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_serviceCentreAddress },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AlertServiceCentreArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                AlertServiceCentreArg_sequence, hf_index, ett_gsm_map_AlertServiceCentreArg);

  return offset;
}


static const value_string gsm_map_T_alertReason_vals[] = {
  {   0, "msPresent" },
  {   1, "memoryAvailable" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_alertReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_alertReason(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_alertReason(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_alertReason);
}

static const ber_sequence_t ReadyForSM_Arg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_alertReason },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_alertReasonIndicator },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ReadyForSM_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ReadyForSM_Arg_sequence, hf_index, ett_gsm_map_ReadyForSM_Arg);

  return offset;
}

static const ber_sequence_t ReadyForSM_Res_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ReadyForSM_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ReadyForSM_Res_sequence, hf_index, ett_gsm_map_ReadyForSM_Res);

  return offset;
}

static const ber_sequence_t RequestedInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationInformationFlag_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_subscriberStateFlag_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RequestedInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                RequestedInfo_sequence, hf_index, ett_gsm_map_RequestedInfo);

  return offset;
}
static int dissect_requestedInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RequestedInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_requestedInfo);
}

static const ber_sequence_t ProvideSubscriberInfoArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lmsi_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_requestedInfo_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ProvideSubscriberInfoArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ProvideSubscriberInfoArg_sequence, hf_index, ett_gsm_map_ProvideSubscriberInfoArg);

  return offset;
}

static const ber_sequence_t ProvideSubscriberInfoRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_subscriberInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ProvideSubscriberInfoRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ProvideSubscriberInfoRes_sequence, hf_index, ett_gsm_map_ProvideSubscriberInfoRes);

  return offset;
}


static const value_string gsm_map_T_subscriberIdentity_vals[] = {
  {   0, "imsi" },
  {   1, "msisdn" },
  { 0, NULL }
};

static const ber_choice_t T_subscriberIdentity_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_subscriberIdentity(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              T_subscriberIdentity_choice, hf_index, ett_gsm_map_T_subscriberIdentity);

  return offset;
}
static int dissect_subscriberIdentity(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_subscriberIdentity(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_subscriberIdentity);
}

static const ber_sequence_t AnyTimeInterrogationArg_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_subscriberIdentity },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_requestedInfo_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gsmSCF_Address_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AnyTimeInterrogationArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                AnyTimeInterrogationArg_sequence, hf_index, ett_gsm_map_AnyTimeInterrogationArg);

  return offset;
}

static const ber_sequence_t AnyTimeInterrogationRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_subscriberInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AnyTimeInterrogationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                AnyTimeInterrogationRes_sequence, hf_index, ett_gsm_map_AnyTimeInterrogationRes);

  return offset;
}

static const ber_sequence_t T_ss_EventSpecification_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_EventSpecification_item },
};

static int
dissect_gsm_map_T_ss_EventSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   T_ss_EventSpecification_sequence_of, hf_index, ett_gsm_map_T_ss_EventSpecification);

  return offset;
}
static int dissect_ss_EventSpecification_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_ss_EventSpecification(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_EventSpecification);
}

static const ber_sequence_t Ss_InvocationNotificationArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ss_Event_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_EventSpecification_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ss_InvocationNotificationArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Ss_InvocationNotificationArg_sequence, hf_index, ett_gsm_map_Ss_InvocationNotificationArg);

  return offset;
}

static const ber_sequence_t Ss_InvocationNotificationRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ss_InvocationNotificationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Ss_InvocationNotificationRes_sequence, hf_index, ett_gsm_map_Ss_InvocationNotificationRes);

  return offset;
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_5_10(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_codec_Info(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_5_10(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_codec_Info);
}

static const ber_sequence_t PrepareGroupCallArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_teleservice },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_asciCallReference },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_codec_Info },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cipheringAlgorithm },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupKeyNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupKey_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_priority_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uplinkFree_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PrepareGroupCallArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PrepareGroupCallArg_sequence, hf_index, ett_gsm_map_PrepareGroupCallArg);

  return offset;
}


static int
dissect_gsm_map_T_groupCallNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_groupCallNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_groupCallNumber(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_groupCallNumber);
}

static const ber_sequence_t PrepareGroupCallRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_groupCallNumber },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PrepareGroupCallRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PrepareGroupCallRes_sequence, hf_index, ett_gsm_map_PrepareGroupCallRes);

  return offset;
}

static const ber_sequence_t SendGroupCallEndSignalArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendGroupCallEndSignalArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SendGroupCallEndSignalArg_sequence, hf_index, ett_gsm_map_SendGroupCallEndSignalArg);

  return offset;
}

static const ber_sequence_t SendGroupCallEndSignalRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendGroupCallEndSignalRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SendGroupCallEndSignalRes_sequence, hf_index, ett_gsm_map_SendGroupCallEndSignalRes);

  return offset;
}

static const ber_sequence_t ProcessGroupCallSignallingArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uplinkRequest_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uplinkReleaseIndication_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseGroupCall_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ProcessGroupCallSignallingArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ProcessGroupCallSignallingArg_sequence, hf_index, ett_gsm_map_ProcessGroupCallSignallingArg);

  return offset;
}

static const ber_sequence_t ForwardGroupCallSignallingArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uplinkRequestAck_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uplinkReleaseIndication_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uplinkRejectCommand_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uplinkSeizedCommand_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uplinkReleaseCommand_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ForwardGroupCallSignallingArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ForwardGroupCallSignallingArg_sequence, hf_index, ett_gsm_map_ForwardGroupCallSignallingArg);

  return offset;
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_5_17(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_sgsn_Address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_5_17(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sgsn_Address);
}
static int dissect_sgsn_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_5_17(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sgsn_Address);
}

static const ber_sequence_t T_sgsn_Capability_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_solsaSupportIndicator },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_sgsn_Capability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_sgsn_Capability_sequence, hf_index, ett_gsm_map_T_sgsn_Capability);

  return offset;
}
static int dissect_sgsn_Capability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_sgsn_Capability(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sgsn_Capability);
}

static const ber_sequence_t UpdateGprsLocationArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sgsn_Number },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sgsn_Address },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgsn_Capability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UpdateGprsLocationArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                UpdateGprsLocationArg_sequence, hf_index, ett_gsm_map_UpdateGprsLocationArg);

  return offset;
}

static const ber_sequence_t UpdateGprsLocationRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_hlr_Number },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UpdateGprsLocationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                UpdateGprsLocationRes_sequence, hf_index, ett_gsm_map_UpdateGprsLocationRes);

  return offset;
}


static int
dissect_gsm_map_Ggsn_Address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_ggsn_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ggsn_Address(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ggsn_Address);
}


static int
dissect_gsm_map_Ggsn_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_ggsn_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ggsn_Number(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ggsn_Number);
}

static const ber_sequence_t SendRoutingInfoForGprsArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ggsn_Address_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ggsn_Number_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendRoutingInfoForGprsArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SendRoutingInfoForGprsArg_sequence, hf_index, ett_gsm_map_SendRoutingInfoForGprsArg);

  return offset;
}

static const ber_sequence_t SendRoutingInfoForGprsRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sgsn_Address_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ggsn_Address_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mobileNotReachableReason_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendRoutingInfoForGprsRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SendRoutingInfoForGprsRes_sequence, hf_index, ett_gsm_map_SendRoutingInfoForGprsRes);

  return offset;
}

static const ber_sequence_t FailureReportArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ggsn_Number_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ggsn_Address_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_FailureReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                FailureReportArg_sequence, hf_index, ett_gsm_map_FailureReportArg);

  return offset;
}

static const ber_sequence_t FailureReportRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ggsn_Address_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_FailureReportRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                FailureReportRes_sequence, hf_index, ett_gsm_map_FailureReportRes);

  return offset;
}

static const ber_sequence_t NoteMsPresentForGprsArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgsn_Address_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ggsn_Address_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_NoteMsPresentForGprsArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                NoteMsPresentForGprsArg_sequence, hf_index, ett_gsm_map_NoteMsPresentForGprsArg);

  return offset;
}

static const ber_sequence_t NoteMsPresentForGprsRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_NoteMsPresentForGprsRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                NoteMsPresentForGprsRes_sequence, hf_index, ett_gsm_map_NoteMsPresentForGprsRes);

  return offset;
}


static const value_string gsm_map_LcsClientType_vals[] = {
  {   0, "emergencyServices" },
  {   1, "valueAddedServices" },
  {   2, "plmnOperatorServices" },
  {   3, "lawfulInterceptServices" },
  { 0, NULL }
};


static int
dissect_gsm_map_LcsClientType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_lcsClientType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LcsClientType(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsClientType);
}

static const ber_sequence_t LcsClientExternalID_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_externalAddress_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LcsClientExternalID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                LcsClientExternalID_sequence, hf_index, ett_gsm_map_LcsClientExternalID);

  return offset;
}
static int dissect_lcsClientExternalID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LcsClientExternalID(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsClientExternalID);
}


static const value_string gsm_map_LcsClientInternalID_vals[] = {
  {   0, "broadcastService" },
  {   1, "o-andM-HPLMN" },
  {   2, "o-andM-VPLMN" },
  {   3, "anonymousLocation" },
  {   4, "targetMSsubscribedService" },
  { 0, NULL }
};


static int
dissect_gsm_map_LcsClientInternalID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_lcsClientInternalID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LcsClientInternalID(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsClientInternalID);
}

static const ber_sequence_t LcsClientName_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dataCodingScheme_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_nameString_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LcsClientName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                LcsClientName_sequence, hf_index, ett_gsm_map_LcsClientName);

  return offset;
}
static int dissect_lcsClientName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LcsClientName(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsClientName);
}

static const ber_sequence_t Lcs_ClientID_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_lcsClientType_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsClientExternalID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsClientDialedByMS_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsClientInternalID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsClientName_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Lcs_ClientID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Lcs_ClientID_sequence, hf_index, ett_gsm_map_Lcs_ClientID);

  return offset;
}
static int dissect_lcs_ClientID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Lcs_ClientID(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_ClientID);
}
static int dissect_lcs_ClientID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Lcs_ClientID(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_ClientID);
}


static const value_string gsm_map_Lcs_Event_vals[] = {
  {   0, "emergencyCallOrigination" },
  {   1, "emergencyCallRelease" },
  {   2, "mo-lr" },
  { 0, NULL }
};


static int
dissect_gsm_map_Lcs_Event(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_lcs_Event(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Lcs_Event(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_Event);
}

static const ber_sequence_t LcsLocationInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_msc_Number },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lmsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LcsLocationInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                LcsLocationInfo_sequence, hf_index, ett_gsm_map_LcsLocationInfo);

  return offset;
}
static int dissect_lcsLocationInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LcsLocationInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lcsLocationInfo);
}
static int dissect_lcsLocationInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LcsLocationInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsLocationInfo);
}


static const value_string gsm_map_T_locationEstimateType_vals[] = {
  {   0, "currentLocation" },
  {   1, "currentOrLastKnownLocation" },
  {   2, "initialLocation" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_locationEstimateType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_locationEstimateType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_locationEstimateType(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_locationEstimateType);
}

static const ber_sequence_t T_locationType_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_locationEstimateType_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_locationType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_locationType_sequence, hf_index, ett_gsm_map_T_locationType);

  return offset;
}
static int dissect_locationType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_locationType(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_locationType);
}


static int
dissect_gsm_map_T_mlc_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_mlc_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_mlc_Number(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_mlc_Number);
}


static const value_string gsm_map_T_responseTimeCategory_vals[] = {
  {   0, "lowdelay" },
  {   1, "delaytolerant" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_responseTimeCategory(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_responseTimeCategory(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_responseTimeCategory(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_responseTimeCategory);
}

static const ber_sequence_t T_responseTime_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_responseTimeCategory },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_responseTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_responseTime_sequence, hf_index, ett_gsm_map_T_responseTime);

  return offset;
}
static int dissect_responseTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_responseTime(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_responseTime);
}

static const ber_sequence_t T_lcs_QoS_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_horizontal_accuracy_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_verticalCoordinateRequest_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vertical_accuracy_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_responseTime_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_lcs_QoS(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_lcs_QoS_sequence, hf_index, ett_gsm_map_T_lcs_QoS);

  return offset;
}
static int dissect_lcs_QoS_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_lcs_QoS(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_QoS);
}

static const ber_sequence_t ProvideSubscriberLocation_Arg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_locationType },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_mlc_Number },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcs_ClientID_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_privacyOverride_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lmsi_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imei_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcs_Priority_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcs_QoS_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ProvideSubscriberLocation_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ProvideSubscriberLocation_Arg_sequence, hf_index, ett_gsm_map_ProvideSubscriberLocation_Arg);

  return offset;
}

static const ber_sequence_t ProvideSubscriberLocation_Res_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_locationEstimate },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ageOfLocationEstimate_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ProvideSubscriberLocation_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ProvideSubscriberLocation_Res_sequence, hf_index, ett_gsm_map_ProvideSubscriberLocation_Res);

  return offset;
}


static const value_string gsm_map_TargetMS_vals[] = {
  {   0, "imsi" },
  {   1, "msisdn" },
  { 0, NULL }
};

static const ber_choice_t TargetMS_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_TargetMS(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              TargetMS_choice, hf_index, ett_gsm_map_TargetMS);

  return offset;
}
static int dissect_targetMS(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_TargetMS(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_targetMS);
}


static int
dissect_gsm_map_T_mlcNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_mlcNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_mlcNumber(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_mlcNumber);
}

static const ber_sequence_t RoutingInfoForLCS_Arg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mlcNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_targetMS },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RoutingInfoForLCS_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                RoutingInfoForLCS_Arg_sequence, hf_index, ett_gsm_map_RoutingInfoForLCS_Arg);

  return offset;
}

static const ber_sequence_t RoutingInfoForLCS_Res_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_targetMS },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lcsLocationInfo_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RoutingInfoForLCS_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                RoutingInfoForLCS_Res_sequence, hf_index, ett_gsm_map_RoutingInfoForLCS_Res);

  return offset;
}


static int
dissect_gsm_map_T_na_ESRD(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_na_ESRD_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_na_ESRD(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_na_ESRD);
}


static int
dissect_gsm_map_T_na_ESRK(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_na_ESRK_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_na_ESRK(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_na_ESRK);
}

static const ber_sequence_t SubscriberLocationReport_Arg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_lcs_Event },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lcs_ClientID },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lcsLocationInfo },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imei_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_na_ESRD_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_na_ESRK_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationEstimate_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ageOfLocationEstimate_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SubscriberLocationReport_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SubscriberLocationReport_Arg_sequence, hf_index, ett_gsm_map_SubscriberLocationReport_Arg);

  return offset;
}

static const ber_sequence_t SubscriberLocationReport_Res_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SubscriberLocationReport_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SubscriberLocationReport_Res_sequence, hf_index, ett_gsm_map_SubscriberLocationReport_Res);

  return offset;
}


static const value_string gsm_map_NetworkResource_vals[] = {
  {   0, "plmn" },
  {   1, "hlr" },
  {   2, "vlr" },
  {   3, "pvlr" },
  {   4, "controllingMSC" },
  {   5, "vmsc" },
  {   6, "eir" },
  {   7, "rss" },
  { 0, NULL }
};


static int
dissect_gsm_map_NetworkResource(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_networkResource(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NetworkResource(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_networkResource);
}

static const ber_sequence_t T_extensibleSystemFailureParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_networkResource },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_extensibleSystemFailureParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_extensibleSystemFailureParam_sequence, hf_index, ett_gsm_map_T_extensibleSystemFailureParam);

  return offset;
}
static int dissect_extensibleSystemFailureParam(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_extensibleSystemFailureParam(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_extensibleSystemFailureParam);
}


static const value_string gsm_map_SystemFailureParam_vals[] = {
  {   0, "networkResource" },
  {   1, "extensibleSystemFailureParam" },
  { 0, NULL }
};

static const ber_choice_t SystemFailureParam_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_networkResource },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_extensibleSystemFailureParam },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SystemFailureParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              SystemFailureParam_choice, hf_index, ett_gsm_map_SystemFailureParam);

  return offset;
}

static const ber_sequence_t DataMissingParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_DataMissingParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                DataMissingParam_sequence, hf_index, ett_gsm_map_DataMissingParam);

  return offset;
}

static const ber_sequence_t UnexpectedDataParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UnexpectedDataParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                UnexpectedDataParam_sequence, hf_index, ett_gsm_map_UnexpectedDataParam);

  return offset;
}

static const ber_sequence_t FacilityNotSupParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_FacilityNotSupParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                FacilityNotSupParam_sequence, hf_index, ett_gsm_map_FacilityNotSupParam);

  return offset;
}

static const ber_sequence_t IncompatibleTerminalParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_IncompatibleTerminalParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                IncompatibleTerminalParam_sequence, hf_index, ett_gsm_map_IncompatibleTerminalParam);

  return offset;
}

static const ber_sequence_t ResourceLimitationParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ResourceLimitationParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ResourceLimitationParam_sequence, hf_index, ett_gsm_map_ResourceLimitationParam);

  return offset;
}


static const value_string gsm_map_T_unknownSubscriberDiagnostic_vals[] = {
  {   0, "imsiUnknown" },
  {   1, "gprsSubscriptionUnknown" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_unknownSubscriberDiagnostic(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_unknownSubscriberDiagnostic(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_unknownSubscriberDiagnostic(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_unknownSubscriberDiagnostic);
}

static const ber_sequence_t UnknownSubscriberParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_unknownSubscriberDiagnostic },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UnknownSubscriberParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                UnknownSubscriberParam_sequence, hf_index, ett_gsm_map_UnknownSubscriberParam);

  return offset;
}

static const ber_sequence_t NumberChangedParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_NumberChangedParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                NumberChangedParam_sequence, hf_index, ett_gsm_map_NumberChangedParam);

  return offset;
}

static const ber_sequence_t UnidentifiedSubParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UnidentifiedSubParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                UnidentifiedSubParam_sequence, hf_index, ett_gsm_map_UnidentifiedSubParam);

  return offset;
}


static const value_string gsm_map_T_roamingNotAllowedCause_vals[] = {
  {   0, "plmnRoamingNotAllowed" },
  {   3, "operatorDeterminedBarring" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_roamingNotAllowedCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_roamingNotAllowedCause(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_roamingNotAllowedCause(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_roamingNotAllowedCause);
}

static const ber_sequence_t RoamingNotAllowedParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_roamingNotAllowedCause },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RoamingNotAllowedParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                RoamingNotAllowedParam_sequence, hf_index, ett_gsm_map_RoamingNotAllowedParam);

  return offset;
}

static const ber_sequence_t IllegalSubscriberParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_IllegalSubscriberParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                IllegalSubscriberParam_sequence, hf_index, ett_gsm_map_IllegalSubscriberParam);

  return offset;
}

static const ber_sequence_t IllegalEquipmentParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_IllegalEquipmentParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                IllegalEquipmentParam_sequence, hf_index, ett_gsm_map_IllegalEquipmentParam);

  return offset;
}

static const ber_sequence_t BearerServNotProvParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_BearerServNotProvParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                BearerServNotProvParam_sequence, hf_index, ett_gsm_map_BearerServNotProvParam);

  return offset;
}

static const ber_sequence_t TeleservNotProvParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_TeleservNotProvParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                TeleservNotProvParam_sequence, hf_index, ett_gsm_map_TeleservNotProvParam);

  return offset;
}

static const ber_sequence_t TracingBufferFullParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_TracingBufferFullParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                TracingBufferFullParam_sequence, hf_index, ett_gsm_map_TracingBufferFullParam);

  return offset;
}

static const ber_sequence_t NoRoamingNbParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_NoRoamingNbParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                NoRoamingNbParam_sequence, hf_index, ett_gsm_map_NoRoamingNbParam);

  return offset;
}


static const value_string gsm_map_T_absentSubscriberReason_vals[] = {
  {   0, "imsiDetach" },
  {   1, "restrictedArea" },
  {   2, "noPageResponse" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_absentSubscriberReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_absentSubscriberReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_absentSubscriberReason(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_absentSubscriberReason);
}

static const ber_sequence_t AbsentSubscriberParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_absentSubscriberReason_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AbsentSubscriberParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                AbsentSubscriberParam_sequence, hf_index, ett_gsm_map_AbsentSubscriberParam);

  return offset;
}

static const ber_sequence_t BusySubscriberParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Possible_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Busy_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_BusySubscriberParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                BusySubscriberParam_sequence, hf_index, ett_gsm_map_BusySubscriberParam);

  return offset;
}

static const ber_sequence_t NoSubscriberReplyParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_NoSubscriberReplyParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                NoSubscriberReplyParam_sequence, hf_index, ett_gsm_map_NoSubscriberReplyParam);

  return offset;
}


static const value_string gsm_map_CallBarringCause_vals[] = {
  {   0, "barringServiceActive" },
  {   1, "operatorBarring" },
  { 0, NULL }
};


static int
dissect_gsm_map_CallBarringCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_callBarringCause(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallBarringCause(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_callBarringCause);
}

static const ber_sequence_t T_extensibleCallBarredParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_callBarringCause },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_unauthorisedMessageOriginator_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_extensibleCallBarredParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_extensibleCallBarredParam_sequence, hf_index, ett_gsm_map_T_extensibleCallBarredParam);

  return offset;
}
static int dissect_extensibleCallBarredParam(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_extensibleCallBarredParam(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_extensibleCallBarredParam);
}


static const value_string gsm_map_CallBarredParam_vals[] = {
  {   0, "callBarringCause" },
  {   1, "extensibleCallBarredParam" },
  { 0, NULL }
};

static const ber_choice_t CallBarredParam_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_callBarringCause },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_extensibleCallBarredParam },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CallBarredParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              CallBarredParam_choice, hf_index, ett_gsm_map_CallBarredParam);

  return offset;
}

static const ber_sequence_t ForwardingFailedParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ForwardingFailedParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ForwardingFailedParam_sequence, hf_index, ett_gsm_map_ForwardingFailedParam);

  return offset;
}

static const ber_sequence_t Or_NotAllowedParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Or_NotAllowedParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Or_NotAllowedParam_sequence, hf_index, ett_gsm_map_Or_NotAllowedParam);

  return offset;
}

static const ber_sequence_t ForwardingViolationParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ForwardingViolationParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ForwardingViolationParam_sequence, hf_index, ett_gsm_map_ForwardingViolationParam);

  return offset;
}


static const value_string gsm_map_T_cug_RejectCause_vals[] = {
  {   0, "incomingCallsBarredWithinCUG" },
  {   1, "subscriberNotMemberOfCUG" },
  {   5, "requestedBasicServiceViolatesCUG-Constraints" },
  {   7, "calledPartySS-InteractionViolation" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_cug_RejectCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_cug_RejectCause(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_cug_RejectCause(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_RejectCause);
}

static const ber_sequence_t Cug_RejectParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cug_RejectCause },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Cug_RejectParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Cug_RejectParam_sequence, hf_index, ett_gsm_map_Cug_RejectParam);

  return offset;
}

static const ber_sequence_t Ati_NotAllowedParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ati_NotAllowedParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Ati_NotAllowedParam_sequence, hf_index, ett_gsm_map_Ati_NotAllowedParam);

  return offset;
}

static const ber_sequence_t NoGroupCallNbParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_NoGroupCallNbParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                NoGroupCallNbParam_sequence, hf_index, ett_gsm_map_NoGroupCallNbParam);

  return offset;
}

static const ber_sequence_t Ss_IncompatibilityCause_sequence[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_Code_impl },
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_basicService },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_Status_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ss_IncompatibilityCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Ss_IncompatibilityCause_sequence, hf_index, ett_gsm_map_Ss_IncompatibilityCause);

  return offset;
}


static const value_string gsm_map_Pw_RegistrationFailureCause_vals[] = {
  {   0, "undetermined" },
  {   1, "invalidFormat" },
  {   2, "newPasswordsMismatch" },
  { 0, NULL }
};


static int
dissect_gsm_map_Pw_RegistrationFailureCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}

static const ber_sequence_t ShortTermDenialParam_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ShortTermDenialParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ShortTermDenialParam_sequence, hf_index, ett_gsm_map_ShortTermDenialParam);

  return offset;
}

static const ber_sequence_t LongTermDenialParam_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LongTermDenialParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                LongTermDenialParam_sequence, hf_index, ett_gsm_map_LongTermDenialParam);

  return offset;
}

static const ber_sequence_t SubBusyForMT_SMS_Param_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gprsConnectionSuspended },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SubBusyForMT_SMS_Param(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                SubBusyForMT_SMS_Param_sequence, hf_index, ett_gsm_map_SubBusyForMT_SMS_Param);

  return offset;
}


static const value_string gsm_map_T_sm_EnumeratedDeliveryFailureCause_vals[] = {
  {   0, "memoryCapacityExceeded" },
  {   1, "equipmentProtocolError" },
  {   2, "equipmentNotSM-Equipped" },
  {   3, "unknownServiceCentre" },
  {   4, "sc-Congestion" },
  {   5, "invalidSME-Address" },
  {   6, "subscriberNotSC-Subscriber" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_sm_EnumeratedDeliveryFailureCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_sm_EnumeratedDeliveryFailureCause(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_sm_EnumeratedDeliveryFailureCause(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sm_EnumeratedDeliveryFailureCause);
}


static int
dissect_gsm_map_OCTET_STRING_SIZE_1_200(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_diagnosticInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_200(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_diagnosticInfo);
}

static const ber_sequence_t Sm_DeliveryFailureCause_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_sm_EnumeratedDeliveryFailureCause },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_diagnosticInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Sm_DeliveryFailureCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                Sm_DeliveryFailureCause_sequence, hf_index, ett_gsm_map_Sm_DeliveryFailureCause);

  return offset;
}

static const ber_sequence_t MessageWaitListFullParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_MessageWaitListFullParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                MessageWaitListFullParam_sequence, hf_index, ett_gsm_map_MessageWaitListFullParam);

  return offset;
}

static const ber_sequence_t AbsentSubscriberSM_Param_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_absentSubscriberDiagnosticSM },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additionalAbsentSubscriberDiagnosticSM_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AbsentSubscriberSM_Param(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                AbsentSubscriberSM_Param_sequence, hf_index, ett_gsm_map_AbsentSubscriberSM_Param);

  return offset;
}

static const ber_sequence_t UnauthorizedRequestingNetwork_Param_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UnauthorizedRequestingNetwork_Param(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                UnauthorizedRequestingNetwork_Param_sequence, hf_index, ett_gsm_map_UnauthorizedRequestingNetwork_Param);

  return offset;
}


static const value_string gsm_map_T_unauthorizedLCSClient_Diagnostic_vals[] = {
  {   0, "noAdditionalInformation" },
  {   1, "clientNotInMSPrivacyExceptionList" },
  {   2, "callToClientNotSetup" },
  {   3, "privacyOverrideNotApplicable" },
  {   4, "disallowedByLocalRegulatoryRequirements" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_unauthorizedLCSClient_Diagnostic(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_unauthorizedLCSClient_Diagnostic_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_unauthorizedLCSClient_Diagnostic(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_unauthorizedLCSClient_Diagnostic);
}

static const ber_sequence_t UnauthorizedLCSClient_Param_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_unauthorizedLCSClient_Diagnostic_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UnauthorizedLCSClient_Param(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                UnauthorizedLCSClient_Param_sequence, hf_index, ett_gsm_map_UnauthorizedLCSClient_Param);

  return offset;
}


static const value_string gsm_map_T_positionMethodFailure_Diagnostic_vals[] = {
  {   0, "congestion" },
  {   1, "insufficientResources" },
  {   2, "insufficientMeasurementData" },
  {   3, "inconsistentMeasurementData" },
  {   4, "locationProcedureNotCompleted" },
  {   5, "locationProcedureNotSupportedByTargetMS" },
  {   6, "qoSNotAttainable" },
  {   7, "positionMethodNotAvailableInNetwork" },
  {   8, "positionMethodNotAvailableInLocationArea" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_positionMethodFailure_Diagnostic(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_positionMethodFailure_Diagnostic_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_positionMethodFailure_Diagnostic(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_positionMethodFailure_Diagnostic);
}

static const ber_sequence_t PositionMethodFailure_Param_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_positionMethodFailure_Diagnostic_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PositionMethodFailure_Param(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PositionMethodFailure_Param_sequence, hf_index, ett_gsm_map_PositionMethodFailure_Param);

  return offset;
}

static const ber_sequence_t UnknownOrUnreachableLCSClient_Param_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UnknownOrUnreachableLCSClient_Param(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                UnknownOrUnreachableLCSClient_Param_sequence, hf_index, ett_gsm_map_UnknownOrUnreachableLCSClient_Param);

  return offset;
}


/*--- End of included file: packet-gsm_map-fn.c ---*/


/* Stuff included from the "old" packet-gsm_map.c for tapping purposes */
static gchar *
my_match_strval(guint32 val, const value_string *vs, gint *idx)
{
    gint	i = 0;

    while (vs[i].strptr) {
	if (vs[i].value == val)
	{
	    *idx = i;
	    return(vs[i].strptr);
	}

	i++;
    }

    *idx = -1;
    return(NULL);
}
/* End includes from old" packet-gsm_map.c */

const value_string gsm_map_opr_code_strings[] = {
  {   2, "updateLocation" },
  {   3, "cancelLocation" },
  {   4, "provideRoamingNumber" },
  {   6, "resumeCallHandling" },
  {   7, "insertSubscriberData" },
  {   8, "deleteSubscriberData" },
  {   9, "sendParameters" },					/* map-ac infoRetrieval (14) version1 (1)*/
  {  10, "registerSS" },
  {  11, "eraseSS" },
  {  12, "activateSS" },
  {  13, "deactivateSS" },
  {  14, "interrogateSS" },
  {  17, "registerPassword" },
  {  18, "getPassword" },
  {  19, "processUnstructuredSS-Data" },		/* map-ac networkFunctionalSs (18) version1 (1) */
  {  22, "sendRoutingInfo" },
  {  23, "updateGprsLocation" },
  {  24, "sendRoutingInfoForGprs" },
  {  25, "failureReport" },
  {  26, "noteMsPresentForGprs" },
  {  28, "performHandover" },					/* map-ac handoverControl (11) version1 (1)*/
  {  29, "sendEndSignal" },
  {  30, "performSubsequentHandover" },			/* map-ac handoverControl (11) version1 (1) */
  {  31, "provideSIWFSNumber" },
  {  32, "sIWFSSignallingModify" },
  {  33, "processAccessSignalling" },
  {  34, "forwardAccessSignalling" },
  {  35, "noteInternalHandover" },				/* map-ac handoverControl (11) version1 (1) */
  {  37, "reset" },
  {  38, "forwardCheckSS-Indication" },
  {  39, "prepareGroupCall" },
  {  40, "sendGroupCallEndSignal" },
  {  41, "processGroupCallSignalling" },
  {  42, "forwardGroupCallSignalling" },
  {  43, "checkIMEI" },
  {  44, "mt-forwardSM" },
  {  45, "sendRoutingInfoForSM" },
  {  46, "mo-forwardSM" },
  {  47, "reportSM-DeliveryStatus" },
  {  48, "noteSubscriberPresent" },				/* map-ac mwdMngt (24) version1 (1) */
  {  49, "alertServiceCentreWithoutResult" },	/* map-ac shortMsgAlert (23) version1 (1) */
  {  50, "activateTraceMode" },
  {  51, "deactivateTraceMode" },
  {  52, "traceSubscriberActivity" },			/* map-ac handoverControl (11) version1 (1) */
  {  54, "beginSubscriberActivity" },			/* map-ac networkFunctionalSs (18) version1 (1) */
  {  55, "sendIdentification" },
  {  56, "sendAuthenticationInfo" },
  {  57, "restoreData" },
  {  58, "sendIMSI" },
  {  59, "processUnstructuredSS-Request" },
  {  60, "unstructuredSS-Request" },
  {  61, "unstructuredSS-Notify" },
  {  63, "informServiceCentre" },
  {  64, "alertServiceCentre" },
  {  66, "readyForSM" },
  {  67, "purgeMS" },
  {  68, "prepareHandover" },
  {  69, "prepareSubsequentHandover" },
  {  70, "provideSubscriberInfo" },
  {  71, "anyTimeInterrogation" },
  {  72, "ss-InvocationNotification" },
  {  73, "setReportingState" },
  {  74, "statusReport" },
  {  75, "remoteUserFree" },
  {  76, "registerCC-Entry" },
  {  77, "eraseCC-Entry" },
  {  83, "provideSubscriberLocation" },
  {  85, "sendRoutingInfoForLCS" },
  {  86, "subscriberLocationReport" },
  { 0, NULL }
};

static const true_false_string gsm_map_extension_value = {
  "No Extension",
  "Extension"
};
static const value_string gsm_map_nature_of_number_values[] = {
	{   0x00,	"unknown" },
	{   0x01,	"International Number" },
	{   0x02,	"National Significant Number" },
	{   0x03,	"Network Specific Number" },
	{   0x04,	"Subscriber Number" },
	{   0x05,	"Reserved" },
	{   0x06,	"Abbreviated Number" },
	{   0x07,	"Reserved for extension" },
	{ 0, NULL }
};
static const value_string gsm_map_number_plan_values[] = {
	{   0x00,	"unknown" },
	{   0x01,	"ISDN/Telephony Numbering (Rec ITU-T E.164)" },
	{   0x02,	"spare" },
	{   0x03,	"Data Numbering (ITU-T Rec. X.121)" },
	{   0x04,	"Telex Numbering (ITU-T Rec. F.69)" },
	{   0x05,	"spare" },
	{   0x06,	"Land Mobile Numbering (ITU-T Rec. E.212)" },
	{   0x07,	"spare" },
	{   0x08,	"National Numbering" },
	{   0x09,	"Private Numbering" },
	{   0x0f,	"Reserved for extension" },
	{ 0, NULL }
};

static const true_false_string gsm_map_Ss_Status_q_bit_values = {
  "Quiescent",
  "Operative"
};
static const true_false_string gsm_map_Ss_Status_p_values = {
  "Provisioned",
  "Not Provisioned"
};
static const true_false_string gsm_map_Ss_Status_r_values = {
  "Registered",
  "Not Registered"
};
static const true_false_string gsm_map_Ss_Status_a_values = {
  "Active",
  "not Active"
};

static guint32 opcode=0;

static int
dissect_gsm_map_Opcode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_index, &opcode);

  if (check_col(pinfo->cinfo, COL_INFO)){
    col_append_fstr(pinfo->cinfo, COL_INFO, val_to_str(opcode, gsm_map_opr_code_strings, "Unknown GSM-MAP (%u)"));
  }

  return offset;
}

static int dissect_invokeData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {

	guint8 octet;

  switch(opcode){
  case  2: /*updateLocation*/
    offset=dissect_gsm_map_UpdateLocationArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  3: /*cancelLocation*/
    offset=dissect_gsm_map_CancelLocationArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  4: /*provideRoamingNumber*/
    offset=dissect_gsm_map_ProvideRoamingNumberArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  6: /*resumeCallHandling*/
    offset=dissect_gsm_map_ResumeCallHandlingArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  7: /*insertSubscriberData*/
    offset=dissect_gsm_map_InsertSubscriberDataArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  8: /*deleteSubscriberData*/
    offset=dissect_gsm_map_DeleteSubscriberDataArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
	/* TODO find out why this isn't in the ASN1 file
  case  9: sendParameters
    offset=dissect_gsm_map_DeleteSubscriberDataArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
	*/
  case  10: /*registerSS*/
    offset=dissect_gsm_map_RegisterSS_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  11: /*eraseSS*/
    offset=dissect_gsm_map_Ss_ForBS(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 12: /*activateSS*/
    offset=dissect_gsm_map_Ss_ForBS(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 13: /*deactivateSS*/
    offset=dissect_gsm_map_Ss_ForBS(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 14: /*interrogateSS*/
    offset=dissect_gsm_map_InterrogateSS_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 17: /*registerPassword*/
    offset=dissect_gsm_map_Ss_Code(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Code);
    break;
  case 18: /*getPassword*/
    offset=dissect_gsm_map_GetPasswordArg(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_getPassword);
    break;
  case 22: /*sendRoutingInfo*/
    offset=dissect_gsm_map_SendRoutingInfoArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 23: /*updateGprsLocation*/
    offset=dissect_gsm_map_UpdateGprsLocationArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 24: /*sendRoutingInfoForGprs*/
    offset=dissect_gsm_map_SendRoutingInfoForGprsArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 25: /*failureReport*/
    offset=dissect_gsm_map_FailureReportArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 26: /*noteMsPresentForGprs*/
    offset=dissect_gsm_map_NoteMsPresentForGprsArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 29: /*sendEndSignal*/
	octet = tvb_get_guint8(tvb,0) & 0xf;
	if ( octet == 3){ /* This is a V9 message ??? */
		offset = offset +2;
		offset=dissect_gsm_map_SendEndSignalV9Arg(TRUE, tvb, offset, pinfo, tree, hf_gsm_mapSendEndSignal);
	}else{
		offset=dissect_gsm_map_Bss_APDU(FALSE, tvb, offset, pinfo, tree, hf_gsm_mapSendEndSignal);
	}
    break;
  case 31: /*provideSIWFSNumbe*/
    offset=dissect_gsm_map_ProvideSIWFSNumberArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 32: /*sIWFSSignallingModify*/
    offset=dissect_gsm_map_SIWFSSignallingModifyArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 33: /*processAccessSignalling*/
    offset=dissect_gsm_map_Bss_APDU(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 34: /*forwardAccessSignalling*/
    offset=dissect_gsm_map_Bss_APDU(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 37: /*reset*/
    offset=dissect_gsm_map_ResetArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 38: /*forwardCheckSS-Indication*/
    return offset;
    break;
  case 39: /*prepareGroupCall*/
    offset=dissect_gsm_map_PrepareGroupCallArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 40: /*sendGroupCallEndSignal*/
    dissect_gsm_map_SendGroupCallEndSignalArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 42: /*processGroupCallSignalling*/
    offset=dissect_gsm_map_ProcessGroupCallSignallingArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 43: /*checkIMEI*/
    offset=dissect_gsm_map_CheckIMEIArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 44: /*mt-forwardSM*/
    offset=dissect_gsm_map_CheckIMEIArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 45: /*sendRoutingInfoForSM*/
    offset=dissect_gsm_map_RoutingInfoForSMRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 46: /*mo-forwardSM*/
    offset=dissect_gsm_map_Mo_forwardSM_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 47: /*reportSM-DeliveryStatus*/
    offset=dissect_gsm_map_ReportSM_DeliveryStatusArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 50: /*activateTraceMode*/
    offset=dissect_gsm_map_ActivateTraceModeArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 51: /*deactivateTraceMode*/
    offset=dissect_gsm_map_DeactivateTraceModeArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 55: /*sendIdentification*/
    offset=dissect_gsm_map_Tmsi(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 56: /*sendAuthenticationInfo*/
	  if (application_context_version < 3 ){
		  offset=dissect_gsm_map_SendAuthenticationInfoArg(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_imsi);
	  }else{
		  offset=dissect_gsm_map_SendAuthenticationInfoArgV3(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_SendAuthenticationInfoArg);
	  }
	break;
  case 57: /*restoreData*/
	offset=dissect_gsm_map_RestoreDataArg(FALSE, tvb, offset, pinfo, tree, -1);
	break;
  case 58: /*sendIMSI*/
	offset=dissect_gsm_map_Msisdn(FALSE, tvb, offset, pinfo, tree, -1);
	break;
  case 59: /*processUnstructuredSS-Request*/
    offset=dissect_gsm_map_Ussd_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 60: /*unstructuredSS-Request*/
    offset=dissect_gsm_map_Ussd_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 61: /*unstructuredSS-Notify*/
    offset=dissect_gsm_map_Ussd_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 63: /*informServiceCentre*/
    offset=dissect_gsm_map_InformServiceCentreArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 64: /*alertServiceCentre*/
    offset=dissect_gsm_map_AlertServiceCentreArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 66: /*readyForSM*/
    offset=dissect_gsm_map_ReadyForSM_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 67: /*purgeMS*/
    offset=dissect_gsm_map_PurgeMS_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 68: /*prepareHandover*/
    offset=dissect_gsm_map_PrepareHO_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 69: /*prepareSubsequentHandover*/
    offset=dissect_gsm_map_PrepareSubsequentHO_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 70: /*provideSubscriberInfo*/
    offset=dissect_gsm_map_ProvideSubscriberInfoArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 71: /*anyTimeInterrogation*/
    offset=dissect_gsm_map_AnyTimeInterrogationArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 72: /*ss-InvocationNotificatio*/
    offset=dissect_gsm_map_Ss_InvocationNotificationArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 73: /*setReportingState*/
    offset=dissect_gsm_map_SetReportingStateArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 74: /*statusReport*/
    offset=dissect_gsm_map_StatusReportArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 75: /*remoteUserFree*/
    offset=dissect_gsm_map_RemoteUserFreeArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 76: /*registerCC-Entry*/
    offset=dissect_gsm_map_RegisterCC_EntryArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 77: /*eraseCC-Entry*/
    offset=dissect_gsm_map_EraseCC_EntryArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 83: /*provideSubscriberLocation*/
    offset=dissect_gsm_map_ProvideSubscriberLocation_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 85: /*sendRoutingInfoForLCS*/
    offset=dissect_gsm_map_RoutingInfoForLCS_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 86: /*subscriberLocationReport*/
    offset=dissect_gsm_map_SubscriberLocationReport_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  default:
    proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
  }
  return offset;
}


static int dissect_returnResultData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  switch(opcode){
  case  2: /*updateLocation*/
    offset=dissect_gsm_map_UpdateLocationRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  3: /*cancelLocation*/
    offset=dissect_gsm_map_CancelLocationRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  4: /*provideRoamingNumber*/
    offset=dissect_gsm_map_ProvideRoamingNumberRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  6: /*resumeCallHandling*/
    offset=dissect_gsm_map_ResumeCallHandlingRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  7: /*insertSubscriberData*/
    offset=dissect_gsm_map_InsertSubscriberDataRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  8: /*deleteSubscriberData*/
    offset=dissect_gsm_map_DeleteSubscriberDataRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
	/* TODO find out why this isn't in the ASN1 file
  case  9: sendParameters
    offset=dissect_gsm_map_DeleteSubscriberDataArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
	*/
  case  10: /*registerSS*/
    offset=dissect_gsm_map_Ss_Info(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  11: /*eraseSS*/
    offset=dissect_gsm_map_Ss_Info(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 12: /*activateSS*/
    offset=dissect_gsm_map_Ss_Info(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 13: /*deactivateSS*/
    offset=dissect_gsm_map_Ss_Info(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 14: /*interrogateSS*/
    offset=dissect_gsm_map_InterrogateSS_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 17: /*registerPassword*/
    offset=dissect_gsm_map_NewPassword(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Code);
    break;
  case 18: /*getPassword*/
    offset=dissect_gsm_map_CurrentPassword(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_currentPassword);
    break;
  case 22: /*sendRoutingInfo*/
	  /* This is done to get around a problem with IMPLICIT tag:s */
    offset = offset +2;
    offset=dissect_gsm_map_SendRoutingInfoRes(TRUE, tvb, offset, pinfo, tree, -1);
    break;
  case 23: /*updateGprsLocation*/
    offset=dissect_gsm_map_UpdateGprsLocationRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 24: /*sendRoutingInfoForGprs*/
    offset=dissect_gsm_map_SendRoutingInfoForGprsRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 25: /*failureReport*/
    offset=dissect_gsm_map_FailureReportRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 26: /*noteMsPresentForGprs*/
    offset=dissect_gsm_map_NoteMsPresentForGprsRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 29: /*sendEndSignal*/
	  /* Taken from MAP-MobileServiceOperations{ 0 identified-organization (4) etsi (0) mobileDomain 
	   * (0) gsm-Network (1) modules (3) map-MobileServiceOperations (5) version9 (9) }
	   */
    offset=dissect_gsm_map_ExtensionContainer(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 31: /*provideSIWFSNumbe*/
    offset=dissect_gsm_map_ProvideSIWFSNumberRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 32: /*provideSIWFSNumbe*/
    offset=dissect_gsm_map_SIWFSSignallingModifyRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 39: /*prepareGroupCall*/
    offset=dissect_gsm_map_PrepareGroupCallRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 40: /*sendGroupCallEndSignal*/
    dissect_gsm_map_SendGroupCallEndSignalRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 43: /*checkIMEI*/
    offset=dissect_gsm_map_EquipmentStatus(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 45: /*sendRoutingInfoForSM*/
    offset=dissect_gsm_map_RoutingInfoForSMRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 46: /*mo-forwardSM*/
    offset=dissect_gsm_map_Mo_forwardSM_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 48: /*reportSM-DeliveryStatus*/
    offset=dissect_gsm_map_ReportSM_DeliveryStatusArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 50: /*activateTraceMode*/
    offset=dissect_gsm_map_ActivateTraceModeRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 51: /*deactivateTraceMode*/
    offset=dissect_gsm_map_DeactivateTraceModeRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 55: /*sendIdentification*/
    offset=dissect_gsm_map_SendIdentificationRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 57: /*restoreData*/
	offset=dissect_gsm_map_RestoreDataRes(FALSE, tvb, offset, pinfo, tree, -1);
	break;
  case 58: /*sendIMSI*/
	offset=dissect_gsm_map_Imsi(FALSE, tvb, offset, pinfo, tree,hf_gsm_map_imsi);
	break;
  case 59: /*unstructuredSS-Request*/
    offset=dissect_gsm_map_Ussd_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 60: /*unstructuredSS-Request*/
    offset=dissect_gsm_map_Ussd_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 61: /*unstructuredSS-Notify*/
    /* TRUE ? */
    proto_tree_add_text(tree, tvb, offset, -1, "Unknown returnResultData blob");
    break;
  case 66: /*readyForSM*/
    offset=dissect_gsm_map_ReadyForSM_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 67: /*purgeMS*/
    offset=dissect_gsm_map_PurgeMS_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 68: /*prepareHandover*/
    offset=dissect_gsm_map_PrepareHO_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 69: /*prepareSubsequentHandover*/
     offset=dissect_gsm_map_Bss_APDU(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 70: /*provideSubscriberInfo*/
    offset=dissect_gsm_map_ProvideSubscriberInfoRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 71: /*anyTimeInterrogation*/
    offset=dissect_gsm_map_AnyTimeInterrogationRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 72: /*ss-InvocationNotificatio*/
    offset=dissect_gsm_map_Ss_InvocationNotificationRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 73: /*setReportingState*/
    offset=dissect_gsm_map_SetReportingStateRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 74: /*statusReport*/
    offset=dissect_gsm_map_StatusReportRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 75: /*remoteUserFree*/
    offset=dissect_gsm_map_RemoteUserFreeRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 76: /*registerCC-Entry*/
    offset=dissect_gsm_map_RegisterCC_EntryRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 77: /*eraseCC-Entry*/
    offset=dissect_gsm_map_EraseCC_EntryRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 83: /*provideSubscriberLocation*/
    offset=dissect_gsm_map_ProvideSubscriberLocation_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 85: /*sendRoutingInfoForLCS*/
    offset=dissect_gsm_map_RoutingInfoForLCS_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 86: /*subscriberLocationReport*/
    offset=dissect_gsm_map_SubscriberLocationReport_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
 default:
    proto_tree_add_text(tree, tvb, offset, -1, "Unknown returnResultData blob");
  }
  return offset;
}

static int 
dissect_invokeCmd(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Opcode(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_invokeCmd);
}

static int dissect_invokeid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_gsm_map_invokeid, NULL);
}


static const value_string InvokeId_vals[] = {
  {   0, "invokeid" },
  {   1, "absent" },
  { 0, NULL }
};

static int dissect_absent(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_absent);
}


static const ber_choice_t InvokeId_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeid },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_absent },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_InvokeId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              InvokeId_choice, hf_index, ett_gsm_map_InvokeId);

  return offset;
}
static int dissect_invokeId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_InvokeId(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_invokeId);
}

static const ber_sequence_t InvokePDU_sequence[] = {
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeCmd },
  { BER_CLASS_UNI, -1/*depends on Cmd*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeData },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_InvokePDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                InvokePDU_sequence, hf_index, ett_gsm_map_InvokePDU);

  return offset;
}
static int dissect_invoke_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_InvokePDU(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_invoke);
}

static const ber_sequence_t ReturnResult_result_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeCmd },
  { BER_CLASS_UNI, -1/*depends on Cmd*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_returnResultData },
  { 0, 0, 0, NULL }
};
static int
dissect_returnResult_result(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  offset = dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset,
                                ReturnResult_result_sequence, hf_gsm_map_returnResult_result, ett_gsm_map_ReturnResult_result);

  return offset;
}

static const ber_sequence_t ReturnResultPDU_sequence[] = {
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_returnResult_result },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_returnResultPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ReturnResultPDU_sequence, hf_index, ett_gsm_map_ReturnResultPDU);

  return offset;
}
static int dissect_returnResult_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_returnResultPDU(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_returnResult);
}
/* TODO code this part
static const ber_sequence_t ReturnError_result_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_errorCode },
  { BER_CLASS_UNI, -1 depends on Cmd, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_errorCodeparam },
  { 0, 0, 0, NULL }
};
*/
static int
dissect_ReturnError_result(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
		return tvb_length_remaining(tvb,offset);
		/*
  offset = dissect_ber_sequence(FALSE, pinfo, tree, tvb, offset,
                                ReturnError_result_sequence, hf_gsm_map_returnResult_result, ett_gsm_map_ReturnError_result);
*/
  return offset;
}

static const ber_sequence_t ReturnErrorPDU_sequence[] = {
  { BER_CLASS_UNI, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeId },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ReturnError_result },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ReturnErrorPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ReturnErrorPDU_sequence, hf_index, ett_gsm_map_ReturnErrorPDU);

  return offset;
}
static int dissect_returnError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ReturnErrorPDU(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_returnError);
}


static const value_string GSMMAPPDU_vals[] = {
  {   1, "Invoke " },
  {   2, "ReturnResult " },
  {   3, "ReturnError " },
  {   4, "Reject " },
  { 0, NULL }
};

static const ber_choice_t GSMMAPPDU_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_invoke_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_returnResult_impl },
#ifdef REMOVED
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_returnError_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_reject_impl },
#endif
  { 0, 0, 0, 0, NULL }
};

static guint8 gsmmap_pdu_type = 0;
static guint8 gsm_map_pdu_size = 0;

static int
dissect_gsm_map_GSMMAPPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo , proto_tree *tree, int hf_index) {

	char *version_ptr, *version_str;

	opcode = 0;
	application_context_version = 0;
	if (pinfo->private_data != NULL){
		version_ptr = strrchr(pinfo->private_data,'.');
		version_str = g_strdup(version_ptr+1);
		application_context_version = atoi(version_str);
	}

  gsmmap_pdu_type = tvb_get_guint8(tvb, offset)&0x0f;
  /* Get the length and add 2 */
  gsm_map_pdu_size = tvb_get_guint8(tvb, offset+1)+2;

  if (check_col(pinfo->cinfo, COL_INFO)){
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str(gsmmap_pdu_type, GSMMAPPDU_vals, "Unknown GSM-MAP PDU (%u)"));
  }

  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              GSMMAPPDU_choice, hf_index, ett_gsm_map_GSMMAPPDU);


  return offset;
}




static void
dissect_gsm_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item		*item=NULL;
    proto_tree		*tree=NULL;
	/* Used for gsm_map TAP */
	static			gsm_map_tap_rec_t tap_rec;
	gint			op_idx;
    gchar			*str = NULL;


    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSM MAP");
    }

	top_tree = parent_tree;

    /* create display subtree for the protocol */
    if(parent_tree){
       item = proto_tree_add_item(parent_tree, proto_gsm_map, tvb, 0, -1, FALSE);
       tree = proto_item_add_subtree(item, ett_gsm_map);
    }

    dissect_gsm_map_GSMMAPPDU(FALSE, tvb, 0, pinfo, tree, -1);
	str = my_match_strval(opcode, gsm_map_opr_code_strings, &op_idx);

	tap_rec.invoke = FALSE;
	if ( gsmmap_pdu_type  == 1 )
		tap_rec.invoke = TRUE;
	tap_rec.opr_code_idx = op_idx;
	tap_rec.size = gsm_map_pdu_size;
	tap_queue_packet(gsm_map_tap, pinfo, &tap_rec);
	


}

static const value_string ssCode_vals[] = {
  { 0x00, "allSS - all SS" },
  { 0x10 ,"allLineIdentificationSS - all line identification SS" },
  { 0x11 ,"clip - calling line identification presentation" },
  { 0x12 ,"clir - calling line identification restriction" },
  { 0x13 ,"colp - connected line identification presentation" },
  { 0x14 ,"colr - connected line identification restriction" },
  { 0x15 ,"mci - malicious call identification" },
  { 0x18 ,"allNameIdentificationSS - all name indentification SS" },
  { 0x19 ,"cnap - calling name presentation" },
  { 0x20 ,"allForwardingSS - all forwarding SS" },
  { 0x21 ,"cfu - call forwarding unconditional" },
  { 0x28 ,"allCondForwardingSS - all conditional forwarding SS" },
  { 0x29 ,"cfb - call forwarding busy" },
  { 0x2a ,"cfnry - call forwarding on no reply" },
  { 0x2b ,"cfnrc - call forwarding on mobile subscriber not reachable" },
  { 0x24 ,"cd - call deflection" },
  { 0x30 ,"allCallOfferingSS - all call offering SS includes also all forwarding SS" },
  { 0x31 ,"ect - explicit call transfer" },
  { 0x32 ,"mah - mobile access hunting" },
  { 0x40 ,"allCallCompletionSS - all Call completion SS" },
  { 0x41 ,"cw - call waiting" },
  { 0x42 ,"hold - call hold" },
  { 0x43 ,"ccbs-A - completion of call to busy subscribers, originating side" },
  { 0x44 ,"ccbs-B - completion of call to busy subscribers, destination side" },
  { 0x45 ,"mc - multicall" },
  { 0x50 ,"allMultiPartySS - all multiparty SS" },
  { 0x51 ,"multiPTY - multiparty" },
  { 0x60 ,"allCommunityOfInterestSS - all community of interest SS" },
  { 0x61 ,"cug - closed user group" },
  { 0x70 ,"allChargingSS - all charging SS" },
  { 0x71 ,"aoci - advice of charge information" },
  { 0x72 ,"aocc - advice of charge charging" },
  { 0x80 ,"allAdditionalInfoTransferSS - all additional information transfer SS" },
  { 0x81 ,"uus1 - UUS1 user-to-user signalling" },
  { 0x82 ,"uus2 - UUS2 user-to-user signalling" },
  { 0x83 ,"uus3 - UUS3 user-to-user signalling" },
  { 0x90 ,"allCallRestrictionSS - all Callrestriction SS" },
  { 0x91 ,"barringOfOutgoingCalls" },
  { 0x92 ,"baoc - barring of all outgoing calls" },
  { 0x93 ,"boic - barring of outgoing international calls" },
  { 0x94 ,"boicExHC - barring of outgoing international calls except those directed to the home PLMN" },
  { 0x99 ,"barringOfIncomingCalls" },
  { 0x9a ,"baic - barring of all incoming calls" },
  { 0x9b ,"bicRoam - barring of incoming calls when roaming outside home PLMN Country" },
  { 0xf0 ,"allPLMN-specificSS" },
  { 0xa0 ,"allCallPrioritySS - all call priority SS" },
  { 0xa1 ,"emlpp - enhanced Multilevel Precedence Pre-emption (EMLPP) service" },
  { 0xb0 ,"allLCSPrivacyException - all LCS Privacy Exception Classes" },
  { 0xb1 ,"universal - allow location by any LCS client" },
  { 0xb2 ,"callrelated - allow location by any value added LCS client to which a call is established from the target MS" },
  { 0xb3 ,"callunrelated - allow location by designated external value added LCS clients" },
  { 0xb4 ,"plmnoperator - allow location by designated PLMN operator LCS clients" },
  { 0xc0 ,"allMOLR-SS - all Mobile Originating Location Request Classes" },
  { 0xc1 ,"basicSelfLocation - allow an MS to request its own location" },
  { 0xc2 ,"autonomousSelfLocation - allow an MS to perform self location without interaction with the PLMN for a predetermined period of time" },
  { 0xc3 ,"transferToThirdParty - allow an MS to request transfer of its location to another LCS client" },

  { 0xf1 ,"plmn-specificSS-1" },
  { 0xf2 ,"plmn-specificSS-2" },
  { 0xf3 ,"plmn-specificSS-3" },
  { 0xf4 ,"plmn-specificSS-4" },
  { 0xf5 ,"plmn-specificSS-5" },
  { 0xf6 ,"plmn-specificSS-6" },
  { 0xf7 ,"plmn-specificSS-7" },
  { 0xf8 ,"plmn-specificSS-8" },
  { 0xf9 ,"plmn-specificSS-9" },
  { 0xfa ,"plmn-specificSS-a" },
  { 0xfb ,"plmn-specificSS-b" },
  { 0xfc ,"plmn-specificSS-c" },
  { 0xfd ,"plmn-specificSS-d" },
  { 0xfe ,"plmn-specificSS-e" },
  { 0xff ,"plmn-specificSS-f" },
  { 0, NULL }
};

static const value_string Teleservice_vals[] = {
{0x00, "allTeleservices" },
{0x10, "allSpeechTransmissionServices" },
{0x11, "telephony" },
{0x12, "emergencyCalls" },
{0x20, "allShortMessageServices" },
{0x21, "shortMessageMT-PP" },
{0x22, "shortMessageMO-PP" },
{0x60, "allFacsimileTransmissionServices" },
{0x61, "facsimileGroup3AndAlterSpeech" },
{0x62, "automaticFacsimileGroup3" },
{0x63, "facsimileGroup4" },

{0x70, "allDataTeleservices" },
{0x80, "allTeleservices-ExeptSMS" },

{0x90, "allVoiceGroupCallServices" },
{0x91, "voiceGroupCall" },
{0x92, "voiceBroadcastCall" },

{0xd0, "allPLMN-specificTS" },
{0xd1, "plmn-specificTS-1" },
{0xd2, "plmn-specificTS-2" },
{0xd3, "plmn-specificTS-3" },
{0xd4, "plmn-specificTS-4" },
{0xd5, "plmn-specificTS-5" },
{0xd6, "plmn-specificTS-6" },
{0xd7, "plmn-specificTS-7" },
{0xd8, "plmn-specificTS-8" },
{0xd9, "plmn-specificTS-9" },
{0xda, "plmn-specificTS-A" },
{0xdb, "plmn-specificTS-B" },
{0xdc, "plmn-specificTS-C" },
{0xdd, "plmn-specificTS-D" },
{0xde, "plmn-specificTS-E" },
{0xdf, "plmn-specificTS-F" },
  { 0, NULL }
};
/*--- proto_reg_handoff_gsm_map ---------------------------------------*/
void proto_reg_handoff_gsm_map(void) {
    dissector_handle_t	map_handle;
	static int map_prefs_initialized = FALSE;

    map_handle = create_dissector_handle(dissect_gsm_map, proto_gsm_map);

	if (!map_prefs_initialized) {
		map_prefs_initialized = TRUE;
	}
	else {
		dissector_delete("tcap.itu_ssn", tcap_itu_ssn1, map_handle);
		dissector_delete("tcap.itu_ssn", tcap_itu_ssn2, map_handle);
		dissector_delete("tcap.itu_ssn", tcap_itu_ssn3, map_handle);
		dissector_delete("tcap.itu_ssn", tcap_itu_ssn4, map_handle);
	}
		/* Set our sub system number for future use */
	tcap_itu_ssn1 = global_tcap_itu_ssn1;
	tcap_itu_ssn2 = global_tcap_itu_ssn2;
	tcap_itu_ssn3 = global_tcap_itu_ssn3;
	tcap_itu_ssn4 = global_tcap_itu_ssn4;

    dissector_add("tcap.itu_ssn", tcap_itu_ssn1, map_handle);
    dissector_add("tcap.itu_ssn", tcap_itu_ssn2, map_handle);
    dissector_add("tcap.itu_ssn", tcap_itu_ssn3, map_handle);
    dissector_add("tcap.itu_ssn", tcap_itu_ssn4, map_handle);
}

/*--- proto_register_gsm_map -------------------------------------------*/
void proto_register_gsm_map(void) {
	module_t *gsm_map_module;

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_gsm_map_invokeCmd,
      { "invokeCmd", "gsm_map.invokeCmd",
        FT_UINT32, BASE_DEC, VALS(gsm_map_opr_code_strings), 0,
        "InvokePDU/invokeCmd", HFILL }},
    { &hf_gsm_map_invokeid,
      { "invokeid", "gsm_map.invokeid",
        FT_INT32, BASE_DEC, NULL, 0,
        "InvokeId/invokeid", HFILL }},
    { &hf_gsm_map_absent,
      { "absent", "gsm_map.absent",
        FT_NONE, BASE_NONE, NULL, 0,
        "InvokeId/absent", HFILL }},
    { &hf_gsm_map_invokeId,
      { "invokeId", "gsm_map.invokeId",
        FT_UINT32, BASE_DEC, VALS(InvokeId_vals), 0,
        "InvokePDU/invokeId", HFILL }},
	{ &hf_gsm_map_SendAuthenticationInfoArg,
      { "SendAuthenticationInfoArg", "gsm_map.SendAuthenticationInfoArg",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SendAuthenticationInfoArg", HFILL }},
    { &hf_gsm_map_currentPassword,
      { "currentPassword", "gsm_map.currentPassword",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
	{ &hf_gsm_mapSendEndSignal,
      { "mapSendEndSignalArg", "gsm_map.mapsendendsignalarg",
        FT_BYTES, BASE_NONE, NULL, 0,
        "mapSendEndSignalArg", HFILL }},
    { &hf_gsm_map_invoke,
      { "invoke", "gsm_map.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSMMAPPDU/invoke", HFILL }},
    { &hf_gsm_map_returnResult,
      { "returnResult", "gsm_map.returnResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSMMAPPDU/returnResult", HFILL }},
	{&hf_gsm_map_returnError,
      { "returnError", "gsm_map.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSMMAPPDU/returnError", HFILL }},
    { &hf_gsm_map_getPassword,
      { "Password", "gsm_map.password",
        FT_UINT8, BASE_DEC, VALS(gsm_map_GetPasswordArg_vals), 0,
        "Password", HFILL }},
    { &hf_gsm_map_extension,
      { "Extension", "gsm_map.extension",
        FT_BOOLEAN, 8, TFS(&gsm_map_extension_value), 0x80,
        "Extension", HFILL }},
    { &hf_gsm_map_nature_of_number,
      { "Nature of number", "gsm_map.nature_of_number",
        FT_UINT8, BASE_HEX, VALS(gsm_map_nature_of_number_values), 0x70,
        "ature of number", HFILL }},
    { &hf_gsm_map_number_plan,
      { "Number plan", "gsm_map.number_plan",
        FT_UINT8, BASE_HEX, VALS(gsm_map_number_plan_values), 0x0f,
        "Number plan", HFILL }},
	{ &hf_gsm_map_misdn_digits,
      { "Misdn digits", "gsm_map.misdn_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "Misdn digits", HFILL }},
	{ &hf_gsm_map_servicecentreaddress_digits,
      { "ServiceCentreAddress digits", "gsm_map.servicecentreaddress_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "ServiceCentreAddress digits", HFILL }},
	{ &hf_gsm_map_map_gmsc_address_digits,
      { "Gmsc Address digits digits", "gsm_map.gmsc_address_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "Gmsc Address digits", HFILL }},
	{ &hf_gsm_map_imsi_digits,
      { "Imsi digits", "gsm_map.imsi_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "Imsi digits", HFILL }},
	{&hf_gsm_map_map_RoamingNumber_digits,
      { "RoamingNumber digits", "gsm_map.RoamingNumber_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "RoamingNumber digits", HFILL }},
	{&hf_gsm_map_map_hlr_number_digits,
      { "Hlr-Number digits", "gsm_map.hlr_number_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "Hlr-Number digits", HFILL }},
	{ &hf_gsm_map_Ss_Status_unused,
      { "Unused", "gsm_map.unused",
        FT_UINT8, BASE_HEX, NULL, 0xf0,
        "Unused", HFILL }},
	{ &hf_gsm_map_Ss_Status_q_bit,
      { "Q bit", "gsm_map.ss_status_q_bit",
        FT_BOOLEAN, 8, TFS(&gsm_map_Ss_Status_q_bit_values), 0x08,
        "Q bit", HFILL }},
	{ &hf_gsm_map_Ss_Status_p_bit,
      { "P bit", "gsm_map.ss_status_p_bit",
        FT_BOOLEAN, 8, TFS(&gsm_map_Ss_Status_p_values), 0x04,
        "P bit", HFILL }},
	{ &hf_gsm_map_Ss_Status_r_bit,
      { "R bit", "ss_status_r_bit",
        FT_BOOLEAN, 8, TFS(&gsm_map_Ss_Status_r_values), 0x02,
        "R bit", HFILL }},
	{ &hf_gsm_map_Ss_Status_a_bit,
      { "A bit", "ss_status_a_bit",
        FT_BOOLEAN, 8, TFS(&gsm_map_Ss_Status_a_values), 0x01,
        "A bit", HFILL }},


/*--- Included file: packet-gsm_map-hfarr.c ---*/

    { &hf_gsm_map_protocolId,
      { "protocolId", "gsm_map.protocolId",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ProtocolId_vals), 0,
        "Bss-APDU/protocolId", HFILL }},
    { &hf_gsm_map_signalInfo,
      { "signalInfo", "gsm_map.signalInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Bss-APDU/signalInfo", HFILL }},
    { &hf_gsm_map_extensionContainer,
      { "extensionContainer", "gsm_map.extensionContainer",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_accessNetworkProtocolId,
      { "accessNetworkProtocolId", "gsm_map.accessNetworkProtocolId",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_accessNetworkProtocolId_vals), 0,
        "An-APDU/accessNetworkProtocolId", HFILL }},
    { &hf_gsm_map_signalInfo2,
      { "signalInfo2", "gsm_map.signalInfo2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "An-APDU/signalInfo2", HFILL }},
    { &hf_gsm_map_supportedCamelPhases,
      { "supportedCamelPhases", "gsm_map.supportedCamelPhases",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_solsaSupportIndicator,
      { "solsaSupportIndicator", "gsm_map.solsaSupportIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_imsi,
      { "imsi", "gsm_map.imsi",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_msc_Number,
      { "msc-Number", "gsm_map.msc_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_vlr_Number,
      { "vlr-Number", "gsm_map.vlr_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_lmsi,
      { "lmsi", "gsm_map.lmsi",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_vlr_Capability,
      { "vlr-Capability", "gsm_map.vlr_Capability",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_hlr_Number,
      { "hlr-Number", "gsm_map.hlr_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_PrivateExtensionList_item,
      { "Item", "gsm_map.PrivateExtensionList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateExtensionList/_item", HFILL }},
    { &hf_gsm_map_extId,
      { "extId", "gsm_map.extId",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrivateExtension/extId", HFILL }},
    { &hf_gsm_map_extType,
      { "extType", "gsm_map.extType",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PrivateExtension/extType", HFILL }},
    { &hf_gsm_map_identity,
      { "identity", "gsm_map.identity",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_identity_vals), 0,
        "CancelLocationArg/identity", HFILL }},
    { &hf_gsm_map_imsi_WithLMSI,
      { "imsi-WithLMSI", "gsm_map.imsi_WithLMSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "CancelLocationArg/identity/imsi-WithLMSI", HFILL }},
    { &hf_gsm_map_cancellationType,
      { "cancellationType", "gsm_map.cancellationType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CancellationType_vals), 0,
        "CancelLocationArg/cancellationType", HFILL }},
    { &hf_gsm_map_sgsn_Number,
      { "sgsn-Number", "gsm_map.sgsn_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_freezeTMSI,
      { "freezeTMSI", "gsm_map.freezeTMSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "PurgeMS-Res/freezeTMSI", HFILL }},
    { &hf_gsm_map_freezeP_TMSI,
      { "freezeP-TMSI", "gsm_map.freezeP_TMSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "PurgeMS-Res/freezeP-TMSI", HFILL }},
    { &hf_gsm_map_authenticationSetList,
      { "authenticationSetList", "gsm_map.authenticationSetList",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendIdentificationRes/authenticationSetList", HFILL }},
    { &hf_gsm_map_authenticationSetList_item,
      { "Item", "gsm_map.authenticationSetList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendIdentificationRes/authenticationSetList/_item", HFILL }},
    { &hf_gsm_map_rand,
      { "rand", "gsm_map.rand",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_sres,
      { "sres", "gsm_map.sres",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_kc,
      { "kc", "gsm_map.kc",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_targetCellId,
      { "targetCellId", "gsm_map.targetCellId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ho_NumberNotRequired,
      { "ho-NumberNotRequired", "gsm_map.ho_NumberNotRequired",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrepareHO-Arg/ho-NumberNotRequired", HFILL }},
    { &hf_gsm_map_bss_APDU,
      { "bss-APDU", "gsm_map.bss_APDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_handoverNumber,
      { "handoverNumber", "gsm_map.handoverNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PrepareHO-Res/handoverNumber", HFILL }},
    { &hf_gsm_map_an_APDU,
      { "an-APDU", "gsm_map.an_APDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendEndSignalV9Arg/an-APDU", HFILL }},
    { &hf_gsm_map_targetMSC_Number,
      { "targetMSC-Number", "gsm_map.targetMSC_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PrepareSubsequentHO-Arg/targetMSC-Number", HFILL }},
    { &hf_gsm_map_numberOfRequestedVectors,
      { "numberOfRequestedVectors", "gsm_map.numberOfRequestedVectors",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SendAuthenticationInfoArgV3/numberOfRequestedVectors", HFILL }},
    { &hf_gsm_map_segmentationProhibited,
      { "segmentationProhibited", "gsm_map.segmentationProhibited",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendAuthenticationInfoArgV3/segmentationProhibited", HFILL }},
    { &hf_gsm_map_immediateResponsePreferred,
      { "immediateResponsePreferred", "gsm_map.immediateResponsePreferred",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendAuthenticationInfoArgV3/immediateResponsePreferred", HFILL }},
    { &hf_gsm_map_re_synchronisationInfo,
      { "re-synchronisationInfo", "gsm_map.re_synchronisationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendAuthenticationInfoArgV3/re-synchronisationInfo", HFILL }},
    { &hf_gsm_map_auts,
      { "auts", "gsm_map.auts",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SendAuthenticationInfoArgV3/re-synchronisationInfo/auts", HFILL }},
    { &hf_gsm_map_requestingNodeType,
      { "requestingNodeType", "gsm_map.requestingNodeType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_requestingNodeType_vals), 0,
        "SendAuthenticationInfoArgV3/requestingNodeType", HFILL }},
    { &hf_gsm_map_requestingPLMN_Id,
      { "requestingPLMN-Id", "gsm_map.requestingPLMN_Id",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SendAuthenticationInfoArgV3/requestingPLMN-Id", HFILL }},
    { &hf_gsm_map_SendAuthenticationInfoRes_item,
      { "Item", "gsm_map.SendAuthenticationInfoRes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendAuthenticationInfoRes/_item", HFILL }},
    { &hf_gsm_map_bearerService,
      { "bearerService", "gsm_map.bearerService",
        FT_BYTES, BASE_HEX, NULL, 0,
        "BasicService/bearerService", HFILL }},
    { &hf_gsm_map_teleservice,
      { "teleservice", "gsm_map.teleservice",
        FT_UINT8, BASE_DEC, VALS(Teleservice_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_BasicServiceGroupList_item,
      { "Item", "gsm_map.BasicServiceGroupList_item",
        FT_UINT32, BASE_DEC, VALS(gsm_map_BasicService_vals), 0,
        "BasicServiceGroupList/_item", HFILL }},
    { &hf_gsm_map_bcsmTriggerDetectionPoint,
      { "bcsmTriggerDetectionPoint", "gsm_map.bcsmTriggerDetectionPoint",
        FT_UINT32, BASE_DEC, VALS(gsm_map_BcsmTriggerDetectionPoint_vals), 0,
        "BcsmCamelTDPData/bcsmTriggerDetectionPoint", HFILL }},
    { &hf_gsm_map_serviceKey,
      { "serviceKey", "gsm_map.serviceKey",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BcsmCamelTDPData/serviceKey", HFILL }},
    { &hf_gsm_map_gsmSCFAddress,
      { "gsmSCFAddress", "gsm_map.gsmSCFAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "BcsmCamelTDPData/gsmSCFAddress", HFILL }},
    { &hf_gsm_map_defaultCallHandling,
      { "defaultCallHandling", "gsm_map.defaultCallHandling",
        FT_UINT32, BASE_DEC, VALS(gsm_map_DefaultCallHandling_vals), 0,
        "BcsmCamelTDPData/defaultCallHandling", HFILL }},
    { &hf_gsm_map_BcsmCamelTDPDataList_item,
      { "Item", "gsm_map.BcsmCamelTDPDataList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "BcsmCamelTDPDataList/_item", HFILL }},
    { &hf_gsm_map_o_BcsmCamelTDPDataList,
      { "o-BcsmCamelTDPDataList", "gsm_map.o_BcsmCamelTDPDataList",
        FT_NONE, BASE_NONE, NULL, 0,
        "O-CSI/o-BcsmCamelTDPDataList", HFILL }},
    { &hf_gsm_map_camelCapabilityHandling,
      { "camelCapabilityHandling", "gsm_map.camelCapabilityHandling",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_msisdn,
      { "msisdn", "gsm_map.msisdn",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_category,
      { "category", "gsm_map.category",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/category", HFILL }},
    { &hf_gsm_map_subscriberStatus,
      { "subscriberStatus", "gsm_map.subscriberStatus",
        FT_UINT32, BASE_DEC, VALS(gsm_map_SubscriberStatus_vals), 0,
        "InsertSubscriberDataArg/subscriberStatus", HFILL }},
    { &hf_gsm_map_bearerServiceList,
      { "bearerServiceList", "gsm_map.bearerServiceList",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_bearerServiceList_item,
      { "Item", "gsm_map.bearerServiceList_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_teleserviceList,
      { "teleserviceList", "gsm_map.teleserviceList",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_teleserviceList_item,
      { "Item", "gsm_map.teleserviceList_item",
        FT_UINT8, BASE_DEC, VALS(Teleservice_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_provisionedSS,
      { "provisionedSS", "gsm_map.provisionedSS",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/provisionedSS", HFILL }},
    { &hf_gsm_map_provisionedSS_item,
      { "Item", "gsm_map.provisionedSS_item",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_provisionedSS_item_vals), 0,
        "InsertSubscriberDataArg/provisionedSS/_item", HFILL }},
    { &hf_gsm_map_forwardingInfo,
      { "forwardingInfo", "gsm_map.forwardingInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_callBarringInfo,
      { "callBarringInfo", "gsm_map.callBarringInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_cug_Info,
      { "cug-Info", "gsm_map.cug_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/provisionedSS/_item/cug-Info", HFILL }},
    { &hf_gsm_map_cug_SubscriptionList,
      { "cug-SubscriptionList", "gsm_map.cug_SubscriptionList",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/provisionedSS/_item/cug-Info/cug-SubscriptionList", HFILL }},
    { &hf_gsm_map_cug_SubscriptionList_item,
      { "Item", "gsm_map.cug_SubscriptionList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/provisionedSS/_item/cug-Info/cug-SubscriptionList/_item", HFILL }},
    { &hf_gsm_map_cug_Index,
      { "cug-Index", "gsm_map.cug_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InsertSubscriberDataArg/provisionedSS/_item/cug-Info/cug-SubscriptionList/_item/cug-Index", HFILL }},
    { &hf_gsm_map_cug_Interlock,
      { "cug-Interlock", "gsm_map.cug_Interlock",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_intraCUG_Options,
      { "intraCUG-Options", "gsm_map.intraCUG_Options",
        FT_UINT32, BASE_DEC, VALS(gsm_map_IntraCUG_Options_vals), 0,
        "InsertSubscriberDataArg/provisionedSS/_item/cug-Info/cug-SubscriptionList/_item/intraCUG-Options", HFILL }},
    { &hf_gsm_map_basicServiceGroupList,
      { "basicServiceGroupList", "gsm_map.basicServiceGroupList",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_cug_FeatureList,
      { "cug-FeatureList", "gsm_map.cug_FeatureList",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/provisionedSS/_item/cug-Info/cug-FeatureList", HFILL }},
    { &hf_gsm_map_cug_FeatureList_item,
      { "Item", "gsm_map.cug_FeatureList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/provisionedSS/_item/cug-Info/cug-FeatureList/_item", HFILL }},
    { &hf_gsm_map_basicService,
      { "basicService", "gsm_map.basicService",
        FT_UINT32, BASE_DEC, VALS(gsm_map_BasicService_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_preferentialCUG_Indicator,
      { "preferentialCUG-Indicator", "gsm_map.preferentialCUG_Indicator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InsertSubscriberDataArg/provisionedSS/_item/cug-Info/cug-FeatureList/_item/preferentialCUG-Indicator", HFILL }},
    { &hf_gsm_map_interCUG_Restrictions,
      { "interCUG-Restrictions", "gsm_map.interCUG_Restrictions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/provisionedSS/_item/cug-Info/cug-FeatureList/_item/interCUG-Restrictions", HFILL }},
    { &hf_gsm_map_ss_Data2,
      { "ss-Data2", "gsm_map.ss_Data2",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/provisionedSS/_item/ss-Data2", HFILL }},
    { &hf_gsm_map_ss_Code,
      { "ss-Code", "gsm_map.ss_Code",
        FT_UINT8, BASE_DEC, VALS(ssCode_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_ss_Status,
      { "ss-Status", "gsm_map.ss_Status",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ss_SubscriptionOption,
      { "ss-SubscriptionOption", "gsm_map.ss_SubscriptionOption",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ss_SubscriptionOption_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_emlpp_Info,
      { "emlpp-Info", "gsm_map.emlpp_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/provisionedSS/_item/emlpp-Info", HFILL }},
    { &hf_gsm_map_maximumentitledPriority,
      { "maximumentitledPriority", "gsm_map.maximumentitledPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InsertSubscriberDataArg/provisionedSS/_item/emlpp-Info/maximumentitledPriority", HFILL }},
    { &hf_gsm_map_defaultPriority,
      { "defaultPriority", "gsm_map.defaultPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_odb_Data,
      { "odb-Data", "gsm_map.odb_Data",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/odb-Data", HFILL }},
    { &hf_gsm_map_odb_GeneralData,
      { "odb-GeneralData", "gsm_map.odb_GeneralData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_odb_HPLMN_Data,
      { "odb-HPLMN-Data", "gsm_map.odb_HPLMN_Data",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/odb-Data/odb-HPLMN-Data", HFILL }},
    { &hf_gsm_map_roamingRestrictionDueToUnsupportedFeature,
      { "roamingRestrictionDueToUnsupportedFeature", "gsm_map.roamingRestrictionDueToUnsupportedFeature",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_regionalSubscriptionData,
      { "regionalSubscriptionData", "gsm_map.regionalSubscriptionData",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/regionalSubscriptionData", HFILL }},
    { &hf_gsm_map_regionalSubscriptionData_item,
      { "Item", "gsm_map.regionalSubscriptionData_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/regionalSubscriptionData/_item", HFILL }},
    { &hf_gsm_map_vbsSubscriptionData,
      { "vbsSubscriptionData", "gsm_map.vbsSubscriptionData",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/vbsSubscriptionData", HFILL }},
    { &hf_gsm_map_vbsSubscriptionData_item,
      { "Item", "gsm_map.vbsSubscriptionData_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/vbsSubscriptionData/_item", HFILL }},
    { &hf_gsm_map_groupid,
      { "groupid", "gsm_map.groupid",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/vbsSubscriptionData/_item/groupid", HFILL }},
    { &hf_gsm_map_broadcastInitEntitlement,
      { "broadcastInitEntitlement", "gsm_map.broadcastInitEntitlement",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/vbsSubscriptionData/_item/broadcastInitEntitlement", HFILL }},
    { &hf_gsm_map_vgcsSubscriptionData,
      { "vgcsSubscriptionData", "gsm_map.vgcsSubscriptionData",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/vgcsSubscriptionData", HFILL }},
    { &hf_gsm_map_vgcsSubscriptionData_item,
      { "Item", "gsm_map.vgcsSubscriptionData_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/vgcsSubscriptionData/_item", HFILL }},
    { &hf_gsm_map_groupId,
      { "groupId", "gsm_map.groupId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/vgcsSubscriptionData/_item/groupId", HFILL }},
    { &hf_gsm_map_vlrCamelSubscriptionInfo,
      { "vlrCamelSubscriptionInfo", "gsm_map.vlrCamelSubscriptionInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/vlrCamelSubscriptionInfo", HFILL }},
    { &hf_gsm_map_o_CSI,
      { "o-CSI", "gsm_map.o_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ss_CSI,
      { "ss-CSI", "gsm_map.ss_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/vlrCamelSubscriptionInfo/ss-CSI", HFILL }},
    { &hf_gsm_map_ss_CamelData,
      { "ss-CamelData", "gsm_map.ss_CamelData",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/vlrCamelSubscriptionInfo/ss-CSI/ss-CamelData", HFILL }},
    { &hf_gsm_map_ss_EventList,
      { "ss-EventList", "gsm_map.ss_EventList",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/vlrCamelSubscriptionInfo/ss-CSI/ss-CamelData/ss-EventList", HFILL }},
    { &hf_gsm_map_ss_EventList_item,
      { "Item", "gsm_map.ss_EventList_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/vlrCamelSubscriptionInfo/ss-CSI/ss-CamelData/ss-EventList/_item", HFILL }},
    { &hf_gsm_map_gsmSCF_Address,
      { "gsmSCF-Address", "gsm_map.gsmSCF_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_o_BcsmCamelTDP_CriteriaList,
      { "o-BcsmCamelTDP-CriteriaList", "gsm_map.o_BcsmCamelTDP_CriteriaList",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_tif_CSI,
      { "tif-CSI", "gsm_map.tif_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/vlrCamelSubscriptionInfo/tif-CSI", HFILL }},
    { &hf_gsm_map_naea_PreferredCI,
      { "naea-PreferredCI", "gsm_map.naea_PreferredCI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_gprsSubscriptionData,
      { "gprsSubscriptionData", "gsm_map.gprsSubscriptionData",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/gprsSubscriptionData", HFILL }},
    { &hf_gsm_map_completeDataListIncluded,
      { "completeDataListIncluded", "gsm_map.completeDataListIncluded",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_gprsDataList,
      { "gprsDataList", "gsm_map.gprsDataList",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/gprsSubscriptionData/gprsDataList", HFILL }},
    { &hf_gsm_map_gprsDataList_item,
      { "Item", "gsm_map.gprsDataList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/gprsSubscriptionData/gprsDataList/_item", HFILL }},
    { &hf_gsm_map_pdp_ContextId,
      { "pdp-ContextId", "gsm_map.pdp_ContextId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InsertSubscriberDataArg/gprsSubscriptionData/gprsDataList/_item/pdp-ContextId", HFILL }},
    { &hf_gsm_map_pdp_Type,
      { "pdp-Type", "gsm_map.pdp_Type",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/gprsSubscriptionData/gprsDataList/_item/pdp-Type", HFILL }},
    { &hf_gsm_map_pdp_Address,
      { "pdp-Address", "gsm_map.pdp_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/gprsSubscriptionData/gprsDataList/_item/pdp-Address", HFILL }},
    { &hf_gsm_map_qos_Subscribed,
      { "qos-Subscribed", "gsm_map.qos_Subscribed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/gprsSubscriptionData/gprsDataList/_item/qos-Subscribed", HFILL }},
    { &hf_gsm_map_vplmnAddressAllowed,
      { "vplmnAddressAllowed", "gsm_map.vplmnAddressAllowed",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/gprsSubscriptionData/gprsDataList/_item/vplmnAddressAllowed", HFILL }},
    { &hf_gsm_map_apn,
      { "apn", "gsm_map.apn",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/gprsSubscriptionData/gprsDataList/_item/apn", HFILL }},
    { &hf_gsm_map_roamingRestrictedInSgsnDueToUnsupportedFeature,
      { "roamingRestrictedInSgsnDueToUnsupportedFeature", "gsm_map.roamingRestrictedInSgsnDueToUnsupportedFeature",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/roamingRestrictedInSgsnDueToUnsupportedFeature", HFILL }},
    { &hf_gsm_map_networkAccessMode,
      { "networkAccessMode", "gsm_map.networkAccessMode",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_networkAccessMode_vals), 0,
        "InsertSubscriberDataArg/networkAccessMode", HFILL }},
    { &hf_gsm_map_lsaInformation,
      { "lsaInformation", "gsm_map.lsaInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lsaInformation", HFILL }},
    { &hf_gsm_map_lsaOnlyAccessIndicator,
      { "lsaOnlyAccessIndicator", "gsm_map.lsaOnlyAccessIndicator",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_lsaOnlyAccessIndicator_vals), 0,
        "InsertSubscriberDataArg/lsaInformation/lsaOnlyAccessIndicator", HFILL }},
    { &hf_gsm_map_lsaDataList,
      { "lsaDataList", "gsm_map.lsaDataList",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lsaInformation/lsaDataList", HFILL }},
    { &hf_gsm_map_lsaDataList_item,
      { "Item", "gsm_map.lsaDataList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lsaInformation/lsaDataList/_item", HFILL }},
    { &hf_gsm_map_lsaIdentity,
      { "lsaIdentity", "gsm_map.lsaIdentity",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/lsaInformation/lsaDataList/_item/lsaIdentity", HFILL }},
    { &hf_gsm_map_lsaAttributes,
      { "lsaAttributes", "gsm_map.lsaAttributes",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/lsaInformation/lsaDataList/_item/lsaAttributes", HFILL }},
    { &hf_gsm_map_lsaActiveModeIndicator,
      { "lsaActiveModeIndicator", "gsm_map.lsaActiveModeIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lsaInformation/lsaDataList/_item/lsaActiveModeIndicator", HFILL }},
    { &hf_gsm_map_lmu_Indicator,
      { "lmu-Indicator", "gsm_map.lmu_Indicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lmu-Indicator", HFILL }},
    { &hf_gsm_map_lcsInformation,
      { "lcsInformation", "gsm_map.lcsInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lcsInformation", HFILL }},
    { &hf_gsm_map_gmlc_List,
      { "gmlc-List", "gsm_map.gmlc_List",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lcsInformation/gmlc-List", HFILL }},
    { &hf_gsm_map_gmlc_List_item,
      { "Item", "gsm_map.gmlc_List_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/lcsInformation/gmlc-List/_item", HFILL }},
    { &hf_gsm_map_lcs_PrivacyExceptionList,
      { "lcs-PrivacyExceptionList", "gsm_map.lcs_PrivacyExceptionList",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lcsInformation/lcs-PrivacyExceptionList", HFILL }},
    { &hf_gsm_map_lcs_PrivacyExceptionList_item,
      { "Item", "gsm_map.lcs_PrivacyExceptionList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lcsInformation/lcs-PrivacyExceptionList/_item", HFILL }},
    { &hf_gsm_map_notificationToMSUser,
      { "notificationToMSUser", "gsm_map.notificationToMSUser",
        FT_UINT32, BASE_DEC, VALS(gsm_map_NotificationToMSUser_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_externalClientList,
      { "externalClientList", "gsm_map.externalClientList",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lcsInformation/lcs-PrivacyExceptionList/_item/externalClientList", HFILL }},
    { &hf_gsm_map_externalClientList_item,
      { "Item", "gsm_map.externalClientList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lcsInformation/lcs-PrivacyExceptionList/_item/externalClientList/_item", HFILL }},
    { &hf_gsm_map_clientIdentity,
      { "clientIdentity", "gsm_map.clientIdentity",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lcsInformation/lcs-PrivacyExceptionList/_item/externalClientList/_item/clientIdentity", HFILL }},
    { &hf_gsm_map_externalAddress,
      { "externalAddress", "gsm_map.externalAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_gmlc_Restriction,
      { "gmlc-Restriction", "gsm_map.gmlc_Restriction",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_gmlc_Restriction_vals), 0,
        "InsertSubscriberDataArg/lcsInformation/lcs-PrivacyExceptionList/_item/externalClientList/_item/gmlc-Restriction", HFILL }},
    { &hf_gsm_map_plmnClientList,
      { "plmnClientList", "gsm_map.plmnClientList",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lcsInformation/lcs-PrivacyExceptionList/_item/plmnClientList", HFILL }},
    { &hf_gsm_map_plmnClientList_item,
      { "Item", "gsm_map.plmnClientList_item",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_plmnClientList_item_vals), 0,
        "InsertSubscriberDataArg/lcsInformation/lcs-PrivacyExceptionList/_item/plmnClientList/_item", HFILL }},
    { &hf_gsm_map_molr_List,
      { "molr-List", "gsm_map.molr_List",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lcsInformation/molr-List", HFILL }},
    { &hf_gsm_map_molr_List_item,
      { "Item", "gsm_map.molr_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lcsInformation/molr-List/_item", HFILL }},
    { &hf_gsm_map_ss_List,
      { "ss-List", "gsm_map.ss_List",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ss_List_item,
      { "Item", "gsm_map.ss_List_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_regionalSubscriptionResponse,
      { "regionalSubscriptionResponse", "gsm_map.regionalSubscriptionResponse",
        FT_UINT32, BASE_DEC, VALS(gsm_map_RegionalSubscriptionResponse_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_callBarringFeatureList,
      { "callBarringFeatureList", "gsm_map.callBarringFeatureList",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallBarringInfo/callBarringFeatureList", HFILL }},
    { &hf_gsm_map_callBarringFeatureList_item,
      { "Item", "gsm_map.callBarringFeatureList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallBarringInfo/callBarringFeatureList/_item", HFILL }},
    { &hf_gsm_map_forwardedToNumber,
      { "forwardedToNumber", "gsm_map.forwardedToNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_forwardedToSubaddress,
      { "forwardedToSubaddress", "gsm_map.forwardedToSubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_forwardingOptions,
      { "forwardingOptions", "gsm_map.forwardingOptions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_noReplyConditionTime,
      { "noReplyConditionTime", "gsm_map.noReplyConditionTime",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_matchType,
      { "matchType", "gsm_map.matchType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_MatchType_vals), 0,
        "DestinationNumberCriteria/matchType", HFILL }},
    { &hf_gsm_map_destinationNumberList,
      { "destinationNumberList", "gsm_map.destinationNumberList",
        FT_NONE, BASE_NONE, NULL, 0,
        "DestinationNumberCriteria/destinationNumberList", HFILL }},
    { &hf_gsm_map_destinationNumberList_item,
      { "Item", "gsm_map.destinationNumberList_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DestinationNumberCriteria/destinationNumberList/_item", HFILL }},
    { &hf_gsm_map_destinationNumberLengthList,
      { "destinationNumberLengthList", "gsm_map.destinationNumberLengthList",
        FT_NONE, BASE_NONE, NULL, 0,
        "DestinationNumberCriteria/destinationNumberLengthList", HFILL }},
    { &hf_gsm_map_destinationNumberLengthList_item,
      { "Item", "gsm_map.destinationNumberLengthList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DestinationNumberCriteria/destinationNumberLengthList/_item", HFILL }},
    { &hf_gsm_map_forwardingFeatureList_1_32,
      { "forwardingFeatureList", "gsm_map.forwardingFeatureList",
        FT_NONE, BASE_NONE, NULL, 0,
        "ForwardingInfo/forwardingFeatureList", HFILL }},
    { &hf_gsm_map_forwardingFeatureList_item,
      { "Item", "gsm_map.forwardingFeatureList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_naea_PreferredCIC,
      { "naea-PreferredCIC", "gsm_map.naea_PreferredCIC",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Naea-PreferredCI/naea-PreferredCIC", HFILL }},
    { &hf_gsm_map_O_BcsmCamelTDP_CriteriaList_item,
      { "Item", "gsm_map.O_BcsmCamelTDP_CriteriaList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "O-BcsmCamelTDP-CriteriaList/_item", HFILL }},
    { &hf_gsm_map_o_BcsmTriggerDetectionPoint,
      { "o-BcsmTriggerDetectionPoint", "gsm_map.o_BcsmTriggerDetectionPoint",
        FT_UINT32, BASE_DEC, VALS(gsm_map_BcsmTriggerDetectionPoint_vals), 0,
        "O-BcsmCamelTDP-CriteriaList/_item/o-BcsmTriggerDetectionPoint", HFILL }},
    { &hf_gsm_map_destinationNumberCriteria,
      { "destinationNumberCriteria", "gsm_map.destinationNumberCriteria",
        FT_NONE, BASE_NONE, NULL, 0,
        "O-BcsmCamelTDP-CriteriaList/_item/destinationNumberCriteria", HFILL }},
    { &hf_gsm_map_basicServiceCriteria,
      { "basicServiceCriteria", "gsm_map.basicServiceCriteria",
        FT_NONE, BASE_NONE, NULL, 0,
        "O-BcsmCamelTDP-CriteriaList/_item/basicServiceCriteria", HFILL }},
    { &hf_gsm_map_callTypeCriteria,
      { "callTypeCriteria", "gsm_map.callTypeCriteria",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CallTypeCriteria_vals), 0,
        "O-BcsmCamelTDP-CriteriaList/_item/callTypeCriteria", HFILL }},
    { &hf_gsm_map_cliRestrictionOption,
      { "cliRestrictionOption", "gsm_map.cliRestrictionOption",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CliRestrictionOption_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_overrideCategory,
      { "overrideCategory", "gsm_map.overrideCategory",
        FT_UINT32, BASE_DEC, VALS(gsm_map_OverrideCategory_vals), 0,
        "Ss-SubscriptionOption/overrideCategory", HFILL }},
    { &hf_gsm_map_basicServiceList,
      { "basicServiceList", "gsm_map.basicServiceList",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSubscriberDataArg/basicServiceList", HFILL }},
    { &hf_gsm_map_regionalSubscriptionIdentifier,
      { "regionalSubscriptionIdentifier", "gsm_map.regionalSubscriptionIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DeleteSubscriberDataArg/regionalSubscriptionIdentifier", HFILL }},
    { &hf_gsm_map_vbsGroupIndication,
      { "vbsGroupIndication", "gsm_map.vbsGroupIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSubscriberDataArg/vbsGroupIndication", HFILL }},
    { &hf_gsm_map_vgcsGroupIndication,
      { "vgcsGroupIndication", "gsm_map.vgcsGroupIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSubscriberDataArg/vgcsGroupIndication", HFILL }},
    { &hf_gsm_map_camelSubscriptionInfoWithdraw,
      { "camelSubscriptionInfoWithdraw", "gsm_map.camelSubscriptionInfoWithdraw",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSubscriberDataArg/camelSubscriptionInfoWithdraw", HFILL }},
    { &hf_gsm_map_gprsSubscriptionDataWithdraw,
      { "gprsSubscriptionDataWithdraw", "gsm_map.gprsSubscriptionDataWithdraw",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_gprsSubscriptionDataWithdraw_vals), 0,
        "DeleteSubscriberDataArg/gprsSubscriptionDataWithdraw", HFILL }},
    { &hf_gsm_map_allGPRSData,
      { "allGPRSData", "gsm_map.allGPRSData",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSubscriberDataArg/gprsSubscriptionDataWithdraw/allGPRSData", HFILL }},
    { &hf_gsm_map_contextIdList,
      { "contextIdList", "gsm_map.contextIdList",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSubscriberDataArg/gprsSubscriptionDataWithdraw/contextIdList", HFILL }},
    { &hf_gsm_map_contextIdList_item,
      { "Item", "gsm_map.contextIdList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DeleteSubscriberDataArg/gprsSubscriptionDataWithdraw/contextIdList/_item", HFILL }},
    { &hf_gsm_map_roamingRestrictedInSgsnDueToUnsuppportedFeature,
      { "roamingRestrictedInSgsnDueToUnsuppportedFeature", "gsm_map.roamingRestrictedInSgsnDueToUnsuppportedFeature",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSubscriberDataArg/roamingRestrictedInSgsnDueToUnsuppportedFeature", HFILL }},
    { &hf_gsm_map_lsaInformationWithdraw,
      { "lsaInformationWithdraw", "gsm_map.lsaInformationWithdraw",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_lsaInformationWithdraw_vals), 0,
        "DeleteSubscriberDataArg/lsaInformationWithdraw", HFILL }},
    { &hf_gsm_map_allLSAData,
      { "allLSAData", "gsm_map.allLSAData",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSubscriberDataArg/lsaInformationWithdraw/allLSAData", HFILL }},
    { &hf_gsm_map_lsaIdentityList,
      { "lsaIdentityList", "gsm_map.lsaIdentityList",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSubscriberDataArg/lsaInformationWithdraw/lsaIdentityList", HFILL }},
    { &hf_gsm_map_lsaIdentityList_item,
      { "Item", "gsm_map.lsaIdentityList_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DeleteSubscriberDataArg/lsaInformationWithdraw/lsaIdentityList/_item", HFILL }},
    { &hf_gsm_map_gmlc_ListWithdraw,
      { "gmlc-ListWithdraw", "gsm_map.gmlc_ListWithdraw",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSubscriberDataArg/gmlc-ListWithdraw", HFILL }},
    { &hf_gsm_map_hlr_List,
      { "hlr-List", "gsm_map.hlr_List",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResetArg/hlr-List", HFILL }},
    { &hf_gsm_map_hlr_List_item,
      { "Item", "gsm_map.hlr_List_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ResetArg/hlr-List/_item", HFILL }},
    { &hf_gsm_map_msNotReachable,
      { "msNotReachable", "gsm_map.msNotReachable",
        FT_NONE, BASE_NONE, NULL, 0,
        "RestoreDataRes/msNotReachable", HFILL }},
    { &hf_gsm_map_traceReference,
      { "traceReference", "gsm_map.traceReference",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_traceType,
      { "traceType", "gsm_map.traceType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ActivateTraceModeArg/traceType", HFILL }},
    { &hf_gsm_map_omc_Id,
      { "omc-Id", "gsm_map.omc_Id",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ActivateTraceModeArg/omc-Id", HFILL }},
    { &hf_gsm_map_cug_CheckInfo,
      { "cug-CheckInfo", "gsm_map.cug_CheckInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_numberOfForwarding,
      { "numberOfForwarding", "gsm_map.numberOfForwarding",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SendRoutingInfoArg/numberOfForwarding", HFILL }},
    { &hf_gsm_map_interrogationType,
      { "interrogationType", "gsm_map.interrogationType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_interrogationType_vals), 0,
        "SendRoutingInfoArg/interrogationType", HFILL }},
    { &hf_gsm_map_or_Interrogation,
      { "or-Interrogation", "gsm_map.or_Interrogation",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_or_Capability,
      { "or-Capability", "gsm_map.or_Capability",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SendRoutingInfoArg/or-Capability", HFILL }},
    { &hf_gsm_map_gmsc_Address,
      { "gmsc-Address", "gsm_map.gmsc_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_callReferenceNumber,
      { "callReferenceNumber", "gsm_map.callReferenceNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_forwardingReason,
      { "forwardingReason", "gsm_map.forwardingReason",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_forwardingReason_vals), 0,
        "SendRoutingInfoArg/forwardingReason", HFILL }},
    { &hf_gsm_map_basicServiceGroup,
      { "basicServiceGroup", "gsm_map.basicServiceGroup",
        FT_UINT32, BASE_DEC, VALS(gsm_map_BasicService_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_networkSignalInfo,
      { "networkSignalInfo", "gsm_map.networkSignalInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_camelInfo,
      { "camelInfo", "gsm_map.camelInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoArg/camelInfo", HFILL }},
    { &hf_gsm_map_suppress_T_CSI,
      { "suppress-T-CSI", "gsm_map.suppress_T_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoArg/camelInfo/suppress-T-CSI", HFILL }},
    { &hf_gsm_map_suppressionOfAnnouncement,
      { "suppressionOfAnnouncement", "gsm_map.suppressionOfAnnouncement",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_alertingPattern,
      { "alertingPattern", "gsm_map.alertingPattern",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ccbs_Call,
      { "ccbs-Call", "gsm_map.ccbs_Call",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_supportedCCBS_Phase,
      { "supportedCCBS-Phase", "gsm_map.supportedCCBS_Phase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SendRoutingInfoArg/supportedCCBS-Phase", HFILL }},
    { &hf_gsm_map_additionalSignalInfo,
      { "additionalSignalInfo", "gsm_map.additionalSignalInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_extendedRoutingInfo,
      { "extendedRoutingInfo", "gsm_map.extendedRoutingInfo",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_extendedRoutingInfo_vals), 0,
        "SendRoutingInfoRes/extendedRoutingInfo", HFILL }},
    { &hf_gsm_map_routingInfo,
      { "routingInfo", "gsm_map.routingInfo",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_routingInfo_vals), 0,
        "SendRoutingInfoRes/extendedRoutingInfo/routingInfo", HFILL }},
    { &hf_gsm_map_roamingNumber,
      { "roamingNumber", "gsm_map.roamingNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_forwardingData,
      { "forwardingData", "gsm_map.forwardingData",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_camelRoutingInfo,
      { "camelRoutingInfo", "gsm_map.camelRoutingInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoRes/extendedRoutingInfo/camelRoutingInfo", HFILL }},
    { &hf_gsm_map_gmscCamelSubscriptionInfo,
      { "gmscCamelSubscriptionInfo", "gsm_map.gmscCamelSubscriptionInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoRes/extendedRoutingInfo/camelRoutingInfo/gmscCamelSubscriptionInfo", HFILL }},
    { &hf_gsm_map_t_CSI,
      { "t-CSI", "gsm_map.t_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoRes/extendedRoutingInfo/camelRoutingInfo/gmscCamelSubscriptionInfo/t-CSI", HFILL }},
    { &hf_gsm_map_t_BcsmCamelTDPDataList,
      { "t-BcsmCamelTDPDataList", "gsm_map.t_BcsmCamelTDPDataList",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoRes/extendedRoutingInfo/camelRoutingInfo/gmscCamelSubscriptionInfo/t-CSI/t-BcsmCamelTDPDataList", HFILL }},
    { &hf_gsm_map_cugSubscriptionFlag,
      { "cugSubscriptionFlag", "gsm_map.cugSubscriptionFlag",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoRes/cugSubscriptionFlag", HFILL }},
    { &hf_gsm_map_subscriberInfo,
      { "subscriberInfo", "gsm_map.subscriberInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_forwardingInterrogationRequired,
      { "forwardingInterrogationRequired", "gsm_map.forwardingInterrogationRequired",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoRes/forwardingInterrogationRequired", HFILL }},
    { &hf_gsm_map_vmsc_Address,
      { "vmsc-Address", "gsm_map.vmsc_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SendRoutingInfoRes/vmsc-Address", HFILL }},
    { &hf_gsm_map_ccbs_Indicators,
      { "ccbs-Indicators", "gsm_map.ccbs_Indicators",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoRes/ccbs-Indicators", HFILL }},
    { &hf_gsm_map_ccbs_Possible,
      { "ccbs-Possible", "gsm_map.ccbs_Possible",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_keepCCBS_CallIndicator,
      { "keepCCBS-CallIndicator", "gsm_map.keepCCBS_CallIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoRes/ccbs-Indicators/keepCCBS-CallIndicator", HFILL }},
    { &hf_gsm_map_numberPortabilityStatus,
      { "numberPortabilityStatus", "gsm_map.numberPortabilityStatus",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_numberPortabilityStatus_vals), 0,
        "SendRoutingInfoRes/numberPortabilityStatus", HFILL }},
    { &hf_gsm_map_assumedIdle,
      { "assumedIdle", "gsm_map.assumedIdle",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubscriberState/assumedIdle", HFILL }},
    { &hf_gsm_map_camelBusy,
      { "camelBusy", "gsm_map.camelBusy",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubscriberState/camelBusy", HFILL }},
    { &hf_gsm_map_notProvidedFromVLR,
      { "notProvidedFromVLR", "gsm_map.notProvidedFromVLR",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubscriberState/notProvidedFromVLR", HFILL }},
    { &hf_gsm_map_ageOfLocationInformation,
      { "ageOfLocationInformation", "gsm_map.ageOfLocationInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocationInformation/ageOfLocationInformation", HFILL }},
    { &hf_gsm_map_geographicalInformation,
      { "geographicalInformation", "gsm_map.geographicalInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LocationInformation/geographicalInformation", HFILL }},
    { &hf_gsm_map_vlr_number,
      { "vlr-number", "gsm_map.vlr_number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LocationInformation/vlr-number", HFILL }},
    { &hf_gsm_map_locationNumber,
      { "locationNumber", "gsm_map.locationNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LocationInformation/locationNumber", HFILL }},
    { &hf_gsm_map_cellIdOrLAI,
      { "cellIdOrLAI", "gsm_map.cellIdOrLAI",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_cellIdOrLAI_vals), 0,
        "LocationInformation/cellIdOrLAI", HFILL }},
    { &hf_gsm_map_cellIdFixedLength,
      { "cellIdFixedLength", "gsm_map.cellIdFixedLength",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LocationInformation/cellIdOrLAI/cellIdFixedLength", HFILL }},
    { &hf_gsm_map_laiFixedLength,
      { "laiFixedLength", "gsm_map.laiFixedLength",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LocationInformation/cellIdOrLAI/laiFixedLength", HFILL }},
    { &hf_gsm_map_locationInformation,
      { "locationInformation", "gsm_map.locationInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubscriberInfo/locationInformation", HFILL }},
    { &hf_gsm_map_subscriberState,
      { "subscriberState", "gsm_map.subscriberState",
        FT_UINT32, BASE_DEC, VALS(gsm_map_SubscriberState_vals), 0,
        "SubscriberInfo/subscriberState", HFILL }},
    { &hf_gsm_map_ext_ProtocolId,
      { "ext-ProtocolId", "gsm_map.ext_ProtocolId",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_ext_ProtocolId_vals), 0,
        "AdditionalSignalInfo/ext-ProtocolId", HFILL }},
    { &hf_gsm_map_ext_signalInfo,
      { "signalInfo", "gsm_map.signalInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AdditionalSignalInfo/signalInfo", HFILL }},
    { &hf_gsm_map_cug_OutgoingAccess,
      { "cug-OutgoingAccess", "gsm_map.cug_OutgoingAccess",
        FT_NONE, BASE_NONE, NULL, 0,
        "Cug-CheckInfo/cug-OutgoingAccess", HFILL }},
    { &hf_gsm_map_gsm_BearerCapability,
      { "gsm-BearerCapability", "gsm_map.gsm_BearerCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_supportedCamelPhasesInGMSC,
      { "supportedCamelPhasesInGMSC", "gsm_map.supportedCamelPhasesInGMSC",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProvideRoamingNumberArg/supportedCamelPhasesInGMSC", HFILL }},
    { &hf_gsm_map_orNotSupportedInGMSC,
      { "orNotSupportedInGMSC", "gsm_map.orNotSupportedInGMSC",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideRoamingNumberArg/orNotSupportedInGMSC", HFILL }},
    { &hf_gsm_map_uu_Data,
      { "uu-Data", "gsm_map.uu_Data",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResumeCallHandlingArg/uu-Data", HFILL }},
    { &hf_gsm_map_uuIndicator,
      { "uuIndicator", "gsm_map.uuIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ResumeCallHandlingArg/uu-Data/uuIndicator", HFILL }},
    { &hf_gsm_map_uui,
      { "uui", "gsm_map.uui",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ResumeCallHandlingArg/uu-Data/uui", HFILL }},
    { &hf_gsm_map_uusCFInteraction,
      { "uusCFInteraction", "gsm_map.uusCFInteraction",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResumeCallHandlingArg/uu-Data/uusCFInteraction", HFILL }},
    { &hf_gsm_map_allInformationSent,
      { "allInformationSent", "gsm_map.allInformationSent",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResumeCallHandlingArg/allInformationSent", HFILL }},
    { &hf_gsm_map_isdn_BearerCapability,
      { "isdn-BearerCapability", "gsm_map.isdn_BearerCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSIWFSNumberArg/isdn-BearerCapability", HFILL }},
    { &hf_gsm_map_call_Direction,
      { "call-Direction", "gsm_map.call_Direction",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProvideSIWFSNumberArg/call-Direction", HFILL }},
    { &hf_gsm_map_b_Subscriber_Address,
      { "b-Subscriber-Address", "gsm_map.b_Subscriber_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProvideSIWFSNumberArg/b-Subscriber-Address", HFILL }},
    { &hf_gsm_map_chosenChannel,
      { "chosenChannel", "gsm_map.chosenChannel",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_lowerLayerCompatibility,
      { "lowerLayerCompatibility", "gsm_map.lowerLayerCompatibility",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSIWFSNumberArg/lowerLayerCompatibility", HFILL }},
    { &hf_gsm_map_highLayerCompatibility,
      { "highLayerCompatibility", "gsm_map.highLayerCompatibility",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSIWFSNumberArg/highLayerCompatibility", HFILL }},
    { &hf_gsm_map_sIWFSNumber,
      { "sIWFSNumber", "gsm_map.sIWFSNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProvideSIWFSNumberRes/sIWFSNumber", HFILL }},
    { &hf_gsm_map_channelType,
      { "channelType", "gsm_map.channelType",
        FT_NONE, BASE_NONE, NULL, 0,
        "SIWFSSignallingModifyArg/channelType", HFILL }},
    { &hf_gsm_map_ccbs_Monitoring,
      { "ccbs-Monitoring", "gsm_map.ccbs_Monitoring",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ccbs_Monitoring_vals), 0,
        "SetReportingStateArg/ccbs-Monitoring", HFILL }},
    { &hf_gsm_map_ccbs_SubscriberStatus,
      { "ccbs-SubscriberStatus", "gsm_map.ccbs_SubscriberStatus",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ccbs_SubscriberStatus_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_eventReportData,
      { "eventReportData", "gsm_map.eventReportData",
        FT_NONE, BASE_NONE, NULL, 0,
        "StatusReportArg/eventReportData", HFILL }},
    { &hf_gsm_map_callReportdata,
      { "callReportdata", "gsm_map.callReportdata",
        FT_NONE, BASE_NONE, NULL, 0,
        "StatusReportArg/callReportdata", HFILL }},
    { &hf_gsm_map_monitoringMode,
      { "monitoringMode", "gsm_map.monitoringMode",
        FT_UINT32, BASE_DEC, VALS(gsm_map_MonitoringMode_vals), 0,
        "StatusReportArg/callReportdata/monitoringMode", HFILL }},
    { &hf_gsm_map_callOutcome,
      { "callOutcome", "gsm_map.callOutcome",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CallOutcome_vals), 0,
        "StatusReportArg/callReportdata/callOutcome", HFILL }},
    { &hf_gsm_map_callInfo,
      { "callInfo", "gsm_map.callInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ccbs_Feature,
      { "ccbs-Feature", "gsm_map.ccbs_Feature",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_translatedB_Number,
      { "translatedB-Number", "gsm_map.translatedB_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_replaceB_Number,
      { "replaceB-Number", "gsm_map.replaceB_Number",
        FT_NONE, BASE_NONE, NULL, 0,
        "RemoteUserFreeArg/replaceB-Number", HFILL }},
    { &hf_gsm_map_ruf_Outcome,
      { "ruf-Outcome", "gsm_map.ruf_Outcome",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ruf_Outcome_vals), 0,
        "RemoteUserFreeRes/ruf-Outcome", HFILL }},
    { &hf_gsm_map_ss_Data,
      { "ss-Data", "gsm_map.ss_Data",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ss-Info/ss-Data", HFILL }},
    { &hf_gsm_map_ccbs_Index,
      { "ccbs-Index", "gsm_map.ccbs_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_b_subscriberNumber,
      { "b-subscriberNumber", "gsm_map.b_subscriberNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_b_subscriberSubaddress,
      { "b-subscriberSubaddress", "gsm_map.b_subscriberSubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_forwardingFeatureList,
      { "forwardingFeatureList", "gsm_map.forwardingFeatureList",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterrogateSS-Res/forwardingFeatureList", HFILL }},
    { &hf_gsm_map_genericServiceInfo,
      { "genericServiceInfo", "gsm_map.genericServiceInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterrogateSS-Res/genericServiceInfo", HFILL }},
    { &hf_gsm_map_maximumEntitledPriority,
      { "maximumEntitledPriority", "gsm_map.maximumEntitledPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InterrogateSS-Res/genericServiceInfo/maximumEntitledPriority", HFILL }},
    { &hf_gsm_map_ccbs_FeatureList,
      { "ccbs-FeatureList", "gsm_map.ccbs_FeatureList",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterrogateSS-Res/genericServiceInfo/ccbs-FeatureList", HFILL }},
    { &hf_gsm_map_ccbs_FeatureList_item,
      { "Item", "gsm_map.ccbs_FeatureList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterrogateSS-Res/genericServiceInfo/ccbs-FeatureList/_item", HFILL }},
    { &hf_gsm_map_ussd_DataCodingScheme,
      { "ussd-DataCodingScheme", "gsm_map.ussd_DataCodingScheme",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ussd_String,
      { "ussd-String", "gsm_map.ussd_String",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ccbs_Data,
      { "ccbs-Data", "gsm_map.ccbs_Data",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegisterCC-EntryArg/ccbs-Data", HFILL }},
    { &hf_gsm_map_serviceIndicator,
      { "serviceIndicator", "gsm_map.serviceIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RegisterCC-EntryArg/ccbs-Data/serviceIndicator", HFILL }},
    { &hf_gsm_map_sm_RP_PRI,
      { "sm-RP-PRI", "gsm_map.sm_RP_PRI",
        FT_BOOLEAN, 8, NULL, 0,
        "RoutingInfoForSMArg/sm-RP-PRI", HFILL }},
    { &hf_gsm_map_serviceCentreAddress,
      { "serviceCentreAddress", "gsm_map.serviceCentreAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_gprsSupportIndicator,
      { "gprsSupportIndicator", "gsm_map.gprsSupportIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_sm_RP_MTI,
      { "sm-RP-MTI", "gsm_map.sm_RP_MTI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RoutingInfoForSMArg/sm-RP-MTI", HFILL }},
    { &hf_gsm_map_sm_RP_SMEA,
      { "sm-RP-SMEA", "gsm_map.sm_RP_SMEA",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RoutingInfoForSMArg/sm-RP-SMEA", HFILL }},
    { &hf_gsm_map_locationInfoWithLMSI,
      { "locationInfoWithLMSI", "gsm_map.locationInfoWithLMSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "RoutingInfoForSMRes/locationInfoWithLMSI", HFILL }},
    { &hf_gsm_map_networkNode_Number,
      { "networkNode-Number", "gsm_map.networkNode_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RoutingInfoForSMRes/locationInfoWithLMSI/networkNode-Number", HFILL }},
    { &hf_gsm_map_gprsNodeIndicator,
      { "gprsNodeIndicator", "gsm_map.gprsNodeIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "RoutingInfoForSMRes/locationInfoWithLMSI/gprsNodeIndicator", HFILL }},
    { &hf_gsm_map_additional_Number,
      { "additional-Number", "gsm_map.additional_Number",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_additional_Number_vals), 0,
        "RoutingInfoForSMRes/locationInfoWithLMSI/additional-Number", HFILL }},
    { &hf_gsm_map_sm_RP_DA,
      { "sm-RP-DA", "gsm_map.sm_RP_DA",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Sm_RP_DA_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_sm_RP_OA,
      { "sm-RP-OA", "gsm_map.sm_RP_OA",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Sm_RP_OA_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_sm_RP_UI,
      { "sm-RP-UI", "gsm_map.sm_RP_UI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_serviceCentreAddressOA,
      { "serviceCentreAddressOA", "gsm_map.serviceCentreAddressOA",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Sm-RP-OA/serviceCentreAddressOA", HFILL }},
    { &hf_gsm_map_noSM_RP_OA,
      { "noSM-RP-OA", "gsm_map.noSM_RP_OA",
        FT_NONE, BASE_NONE, NULL, 0,
        "Sm-RP-OA/noSM-RP-OA", HFILL }},
    { &hf_gsm_map_serviceCentreAddressDA,
      { "serviceCentreAddressDA", "gsm_map.serviceCentreAddressDA",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Sm-RP-DA/serviceCentreAddressDA", HFILL }},
    { &hf_gsm_map_noSM_RP_DA,
      { "noSM-RP-DA", "gsm_map.noSM_RP_DA",
        FT_NONE, BASE_NONE, NULL, 0,
        "Sm-RP-DA/noSM-RP-DA", HFILL }},
    { &hf_gsm_map_moreMessagesToSend,
      { "moreMessagesToSend", "gsm_map.moreMessagesToSend",
        FT_NONE, BASE_NONE, NULL, 0,
        "Mt-forwardSM-Arg/moreMessagesToSend", HFILL }},
    { &hf_gsm_map_sm_DeliveryOutcome,
      { "sm-DeliveryOutcome", "gsm_map.sm_DeliveryOutcome",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Sm_DeliveryOutcome_vals), 0,
        "ReportSM-DeliveryStatusArg/sm-DeliveryOutcome", HFILL }},
    { &hf_gsm_map_absentSubscriberDiagnosticSM,
      { "absentSubscriberDiagnosticSM", "gsm_map.absentSubscriberDiagnosticSM",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_deliveryOutcomeIndicator,
      { "deliveryOutcomeIndicator", "gsm_map.deliveryOutcomeIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportSM-DeliveryStatusArg/deliveryOutcomeIndicator", HFILL }},
    { &hf_gsm_map_additionalSM_DeliveryOutcome,
      { "additionalSM-DeliveryOutcome", "gsm_map.additionalSM_DeliveryOutcome",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Sm_DeliveryOutcome_vals), 0,
        "ReportSM-DeliveryStatusArg/additionalSM-DeliveryOutcome", HFILL }},
    { &hf_gsm_map_additionalAbsentSubscriberDiagnosticSM,
      { "additionalAbsentSubscriberDiagnosticSM", "gsm_map.additionalAbsentSubscriberDiagnosticSM",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_storedMSISDN,
      { "storedMSISDN", "gsm_map.storedMSISDN",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_mw_Status,
      { "mw-Status", "gsm_map.mw_Status",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InformServiceCentreArg/mw-Status", HFILL }},
    { &hf_gsm_map_alertReason,
      { "alertReason", "gsm_map.alertReason",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_alertReason_vals), 0,
        "ReadyForSM-Arg/alertReason", HFILL }},
    { &hf_gsm_map_alertReasonIndicator,
      { "alertReasonIndicator", "gsm_map.alertReasonIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReadyForSM-Arg/alertReasonIndicator", HFILL }},
    { &hf_gsm_map_requestedInfo,
      { "requestedInfo", "gsm_map.requestedInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_locationInformationFlag,
      { "locationInformation", "gsm_map.locationInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedInfo/locationInformation", HFILL }},
    { &hf_gsm_map_subscriberStateFlag,
      { "subscriberState", "gsm_map.subscriberState",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedInfo/subscriberState", HFILL }},
    { &hf_gsm_map_subscriberIdentity,
      { "subscriberIdentity", "gsm_map.subscriberIdentity",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_subscriberIdentity_vals), 0,
        "AnyTimeInterrogationArg/subscriberIdentity", HFILL }},
    { &hf_gsm_map_ss_Event,
      { "ss-Event", "gsm_map.ss_Event",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Ss-InvocationNotificationArg/ss-Event", HFILL }},
    { &hf_gsm_map_ss_EventSpecification,
      { "ss-EventSpecification", "gsm_map.ss_EventSpecification",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ss-InvocationNotificationArg/ss-EventSpecification", HFILL }},
    { &hf_gsm_map_ss_EventSpecification_item,
      { "Item", "gsm_map.ss_EventSpecification_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Ss-InvocationNotificationArg/ss-EventSpecification/_item", HFILL }},
    { &hf_gsm_map_asciCallReference,
      { "asciCallReference", "gsm_map.asciCallReference",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PrepareGroupCallArg/asciCallReference", HFILL }},
    { &hf_gsm_map_codec_Info,
      { "codec-Info", "gsm_map.codec_Info",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PrepareGroupCallArg/codec-Info", HFILL }},
    { &hf_gsm_map_cipheringAlgorithm,
      { "cipheringAlgorithm", "gsm_map.cipheringAlgorithm",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PrepareGroupCallArg/cipheringAlgorithm", HFILL }},
    { &hf_gsm_map_groupKeyNumber,
      { "groupKeyNumber", "gsm_map.groupKeyNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrepareGroupCallArg/groupKeyNumber", HFILL }},
    { &hf_gsm_map_groupKey,
      { "groupKey", "gsm_map.groupKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PrepareGroupCallArg/groupKey", HFILL }},
    { &hf_gsm_map_priority,
      { "priority", "gsm_map.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrepareGroupCallArg/priority", HFILL }},
    { &hf_gsm_map_uplinkFree,
      { "uplinkFree", "gsm_map.uplinkFree",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrepareGroupCallArg/uplinkFree", HFILL }},
    { &hf_gsm_map_groupCallNumber,
      { "groupCallNumber", "gsm_map.groupCallNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PrepareGroupCallRes/groupCallNumber", HFILL }},
    { &hf_gsm_map_uplinkRequest,
      { "uplinkRequest", "gsm_map.uplinkRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProcessGroupCallSignallingArg/uplinkRequest", HFILL }},
    { &hf_gsm_map_uplinkReleaseIndication,
      { "uplinkReleaseIndication", "gsm_map.uplinkReleaseIndication",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_releaseGroupCall,
      { "releaseGroupCall", "gsm_map.releaseGroupCall",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProcessGroupCallSignallingArg/releaseGroupCall", HFILL }},
    { &hf_gsm_map_uplinkRequestAck,
      { "uplinkRequestAck", "gsm_map.uplinkRequestAck",
        FT_NONE, BASE_NONE, NULL, 0,
        "ForwardGroupCallSignallingArg/uplinkRequestAck", HFILL }},
    { &hf_gsm_map_uplinkRejectCommand,
      { "uplinkRejectCommand", "gsm_map.uplinkRejectCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        "ForwardGroupCallSignallingArg/uplinkRejectCommand", HFILL }},
    { &hf_gsm_map_uplinkSeizedCommand,
      { "uplinkSeizedCommand", "gsm_map.uplinkSeizedCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        "ForwardGroupCallSignallingArg/uplinkSeizedCommand", HFILL }},
    { &hf_gsm_map_uplinkReleaseCommand,
      { "uplinkReleaseCommand", "gsm_map.uplinkReleaseCommand",
        FT_NONE, BASE_NONE, NULL, 0,
        "ForwardGroupCallSignallingArg/uplinkReleaseCommand", HFILL }},
    { &hf_gsm_map_sgsn_Address,
      { "sgsn-Address", "gsm_map.sgsn_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_sgsn_Capability,
      { "sgsn-Capability", "gsm_map.sgsn_Capability",
        FT_NONE, BASE_NONE, NULL, 0,
        "UpdateGprsLocationArg/sgsn-Capability", HFILL }},
    { &hf_gsm_map_ggsn_Address,
      { "ggsn-Address", "gsm_map.ggsn_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ggsn_Number,
      { "ggsn-Number", "gsm_map.ggsn_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_mobileNotReachableReason,
      { "mobileNotReachableReason", "gsm_map.mobileNotReachableReason",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SendRoutingInfoForGprsRes/mobileNotReachableReason", HFILL }},
    { &hf_gsm_map_dataCodingScheme,
      { "dataCodingScheme", "gsm_map.dataCodingScheme",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LcsClientName/dataCodingScheme", HFILL }},
    { &hf_gsm_map_nameString,
      { "nameString", "gsm_map.nameString",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LcsClientName/nameString", HFILL }},
    { &hf_gsm_map_lcsClientType,
      { "lcsClientType", "gsm_map.lcsClientType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_LcsClientType_vals), 0,
        "Lcs-ClientID/lcsClientType", HFILL }},
    { &hf_gsm_map_lcsClientExternalID,
      { "lcsClientExternalID", "gsm_map.lcsClientExternalID",
        FT_NONE, BASE_NONE, NULL, 0,
        "Lcs-ClientID/lcsClientExternalID", HFILL }},
    { &hf_gsm_map_lcsClientDialedByMS,
      { "lcsClientDialedByMS", "gsm_map.lcsClientDialedByMS",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Lcs-ClientID/lcsClientDialedByMS", HFILL }},
    { &hf_gsm_map_lcsClientInternalID,
      { "lcsClientInternalID", "gsm_map.lcsClientInternalID",
        FT_UINT32, BASE_DEC, VALS(gsm_map_LcsClientInternalID_vals), 0,
        "Lcs-ClientID/lcsClientInternalID", HFILL }},
    { &hf_gsm_map_lcsClientName,
      { "lcsClientName", "gsm_map.lcsClientName",
        FT_NONE, BASE_NONE, NULL, 0,
        "Lcs-ClientID/lcsClientName", HFILL }},
    { &hf_gsm_map_locationType,
      { "locationType", "gsm_map.locationType",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSubscriberLocation-Arg/locationType", HFILL }},
    { &hf_gsm_map_locationEstimateType,
      { "locationEstimateType", "gsm_map.locationEstimateType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_locationEstimateType_vals), 0,
        "ProvideSubscriberLocation-Arg/locationType/locationEstimateType", HFILL }},
    { &hf_gsm_map_mlc_Number,
      { "mlc-Number", "gsm_map.mlc_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProvideSubscriberLocation-Arg/mlc-Number", HFILL }},
    { &hf_gsm_map_lcs_ClientID,
      { "lcs-ClientID", "gsm_map.lcs_ClientID",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_privacyOverride,
      { "privacyOverride", "gsm_map.privacyOverride",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSubscriberLocation-Arg/privacyOverride", HFILL }},
    { &hf_gsm_map_imei,
      { "imei", "gsm_map.imei",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_lcs_Priority,
      { "lcs-Priority", "gsm_map.lcs_Priority",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProvideSubscriberLocation-Arg/lcs-Priority", HFILL }},
    { &hf_gsm_map_lcs_QoS,
      { "lcs-QoS", "gsm_map.lcs_QoS",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSubscriberLocation-Arg/lcs-QoS", HFILL }},
    { &hf_gsm_map_horizontal_accuracy,
      { "horizontal-accuracy", "gsm_map.horizontal_accuracy",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProvideSubscriberLocation-Arg/lcs-QoS/horizontal-accuracy", HFILL }},
    { &hf_gsm_map_verticalCoordinateRequest,
      { "verticalCoordinateRequest", "gsm_map.verticalCoordinateRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSubscriberLocation-Arg/lcs-QoS/verticalCoordinateRequest", HFILL }},
    { &hf_gsm_map_vertical_accuracy,
      { "vertical-accuracy", "gsm_map.vertical_accuracy",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProvideSubscriberLocation-Arg/lcs-QoS/vertical-accuracy", HFILL }},
    { &hf_gsm_map_responseTime,
      { "responseTime", "gsm_map.responseTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSubscriberLocation-Arg/lcs-QoS/responseTime", HFILL }},
    { &hf_gsm_map_responseTimeCategory,
      { "responseTimeCategory", "gsm_map.responseTimeCategory",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_responseTimeCategory_vals), 0,
        "ProvideSubscriberLocation-Arg/lcs-QoS/responseTime/responseTimeCategory", HFILL }},
    { &hf_gsm_map_locationEstimate,
      { "locationEstimate", "gsm_map.locationEstimate",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ageOfLocationEstimate,
      { "ageOfLocationEstimate", "gsm_map.ageOfLocationEstimate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_mlcNumber,
      { "mlcNumber", "gsm_map.mlcNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RoutingInfoForLCS-Arg/mlcNumber", HFILL }},
    { &hf_gsm_map_targetMS,
      { "targetMS", "gsm_map.targetMS",
        FT_UINT32, BASE_DEC, VALS(gsm_map_TargetMS_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_lcsLocationInfo,
      { "lcsLocationInfo", "gsm_map.lcsLocationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_lcs_Event,
      { "lcs-Event", "gsm_map.lcs_Event",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Lcs_Event_vals), 0,
        "SubscriberLocationReport-Arg/lcs-Event", HFILL }},
    { &hf_gsm_map_na_ESRD,
      { "na-ESRD", "gsm_map.na_ESRD",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SubscriberLocationReport-Arg/na-ESRD", HFILL }},
    { &hf_gsm_map_na_ESRK,
      { "na-ESRK", "gsm_map.na_ESRK",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SubscriberLocationReport-Arg/na-ESRK", HFILL }},
    { &hf_gsm_map_networkResource,
      { "networkResource", "gsm_map.networkResource",
        FT_UINT32, BASE_DEC, VALS(gsm_map_NetworkResource_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_extensibleSystemFailureParam,
      { "extensibleSystemFailureParam", "gsm_map.extensibleSystemFailureParam",
        FT_NONE, BASE_NONE, NULL, 0,
        "SystemFailureParam/extensibleSystemFailureParam", HFILL }},
    { &hf_gsm_map_unknownSubscriberDiagnostic,
      { "unknownSubscriberDiagnostic", "gsm_map.unknownSubscriberDiagnostic",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_unknownSubscriberDiagnostic_vals), 0,
        "UnknownSubscriberParam/unknownSubscriberDiagnostic", HFILL }},
    { &hf_gsm_map_roamingNotAllowedCause,
      { "roamingNotAllowedCause", "gsm_map.roamingNotAllowedCause",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_roamingNotAllowedCause_vals), 0,
        "RoamingNotAllowedParam/roamingNotAllowedCause", HFILL }},
    { &hf_gsm_map_absentSubscriberReason,
      { "absentSubscriberReason", "gsm_map.absentSubscriberReason",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_absentSubscriberReason_vals), 0,
        "AbsentSubscriberParam/absentSubscriberReason", HFILL }},
    { &hf_gsm_map_ccbs_Busy,
      { "ccbs-Busy", "gsm_map.ccbs_Busy",
        FT_NONE, BASE_NONE, NULL, 0,
        "BusySubscriberParam/ccbs-Busy", HFILL }},
    { &hf_gsm_map_callBarringCause,
      { "callBarringCause", "gsm_map.callBarringCause",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CallBarringCause_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_extensibleCallBarredParam,
      { "extensibleCallBarredParam", "gsm_map.extensibleCallBarredParam",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallBarredParam/extensibleCallBarredParam", HFILL }},
    { &hf_gsm_map_unauthorisedMessageOriginator,
      { "unauthorisedMessageOriginator", "gsm_map.unauthorisedMessageOriginator",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallBarredParam/extensibleCallBarredParam/unauthorisedMessageOriginator", HFILL }},
    { &hf_gsm_map_cug_RejectCause,
      { "cug-RejectCause", "gsm_map.cug_RejectCause",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_cug_RejectCause_vals), 0,
        "Cug-RejectParam/cug-RejectCause", HFILL }},
    { &hf_gsm_map_gprsConnectionSuspended,
      { "gprsConnectionSuspended", "gsm_map.gprsConnectionSuspended",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubBusyForMT-SMS-Param/gprsConnectionSuspended", HFILL }},
    { &hf_gsm_map_sm_EnumeratedDeliveryFailureCause,
      { "sm-EnumeratedDeliveryFailureCause", "gsm_map.sm_EnumeratedDeliveryFailureCause",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_sm_EnumeratedDeliveryFailureCause_vals), 0,
        "Sm-DeliveryFailureCause/sm-EnumeratedDeliveryFailureCause", HFILL }},
    { &hf_gsm_map_diagnosticInfo,
      { "diagnosticInfo", "gsm_map.diagnosticInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Sm-DeliveryFailureCause/diagnosticInfo", HFILL }},
    { &hf_gsm_map_unauthorizedLCSClient_Diagnostic,
      { "unauthorizedLCSClient-Diagnostic", "gsm_map.unauthorizedLCSClient_Diagnostic",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_unauthorizedLCSClient_Diagnostic_vals), 0,
        "UnauthorizedLCSClient-Param/unauthorizedLCSClient-Diagnostic", HFILL }},
    { &hf_gsm_map_positionMethodFailure_Diagnostic,
      { "positionMethodFailure-Diagnostic", "gsm_map.positionMethodFailure_Diagnostic",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_positionMethodFailure_Diagnostic_vals), 0,
        "PositionMethodFailure-Param/positionMethodFailure-Diagnostic", HFILL }},
    { &hf_gsm_map_privateExtensionList,
      { "privateExtensionList", "gsm_map.privateExtensionList",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtensionContainer/privateExtensionList", HFILL }},
    { &hf_gsm_map_pcsExtensions,
      { "pcsExtensions", "gsm_map.pcsExtensions",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtensionContainer/pcsExtensions", HFILL }},
    { &hf_gsm_map_SupportedCamelPhases_phase1,
      { "phase1", "gsm_map.phase1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_SupportedCamelPhases_phase2,
      { "phase2", "gsm_map.phase2",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_allOGCallsBarred,
      { "allOGCallsBarred", "gsm_map.allOGCallsBarred",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_internationalOGCallsBarred,
      { "internationalOGCallsBarred", "gsm_map.internationalOGCallsBarred",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_internationalOGCallsNotToHPLMNCountryBarred,
      { "internationalOGCallsNotToHPLMNCountryBarred", "gsm_map.internationalOGCallsNotToHPLMNCountryBarred",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_premiumRateInformationOGCallsBarred,
      { "premiumRateInformationOGCallsBarred", "gsm_map.premiumRateInformationOGCallsBarred",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_premiumRateEntertainementOGCallsBarred,
      { "premiumRateEntertainementOGCallsBarred", "gsm_map.premiumRateEntertainementOGCallsBarred",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_ssAccessBarred,
      { "ssAccessBarred", "gsm_map.ssAccessBarred",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_interzonalOGCallsBarred,
      { "interzonalOGCallsBarred", "gsm_map.interzonalOGCallsBarred",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_interzonalOGCallsNotToHPLMNCountryBarred,
      { "interzonalOGCallsNotToHPLMNCountryBarred", "gsm_map.interzonalOGCallsNotToHPLMNCountryBarred",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_interzonalOGCallsAndIntOGCallsNotToHPLMNCountryBarred,
      { "interzonalOGCallsAndIntOGCallsNotToHPLMNCountryBarred", "gsm_map.interzonalOGCallsAndIntOGCallsNotToHPLMNCountryBarred",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_allECTBarred,
      { "allECTBarred", "gsm_map.allECTBarred",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_chargeableECTBarred,
      { "chargeableECTBarred", "gsm_map.chargeableECTBarred",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_internationalECTBarred,
      { "internationalECTBarred", "gsm_map.internationalECTBarred",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_interzonalECTBarred,
      { "interzonalECTBarred", "gsm_map.interzonalECTBarred",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_doublyChargeableECTBarred,
      { "doublyChargeableECTBarred", "gsm_map.doublyChargeableECTBarred",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_gsm_map_Odb_GeneralData_multipleECTBarred,
      { "multipleECTBarred", "gsm_map.multipleECTBarred",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_gsm_map_Odb_HPLMN_Data_plmnSpecificBarringType1,
      { "plmnSpecificBarringType1", "gsm_map.plmnSpecificBarringType1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_Odb_HPLMN_Data_plmnSpecificBarringType2,
      { "plmnSpecificBarringType2", "gsm_map.plmnSpecificBarringType2",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_Odb_HPLMN_Data_plmnSpecificBarringType3,
      { "plmnSpecificBarringType3", "gsm_map.plmnSpecificBarringType3",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_Odb_HPLMN_Data_plmnSpecificBarringType4,
      { "plmnSpecificBarringType4", "gsm_map.plmnSpecificBarringType4",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_ServiceIndicator_clirInvoked,
      { "clirInvoked", "gsm_map.clirInvoked",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_ServiceIndicator_camelInvoked,
      { "camelInvoked", "gsm_map.camelInvoked",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_T_mw_Status_scAddressNotIncluded,
      { "scAddressNotIncluded", "gsm_map.scAddressNotIncluded",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_T_mw_Status_mnrfSet,
      { "mnrfSet", "gsm_map.mnrfSet",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_T_mw_Status_mcefSet,
      { "mcefSet", "gsm_map.mcefSet",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_T_mw_Status_mnrgSet,
      { "mnrgSet", "gsm_map.mnrgSet",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},

/*--- End of included file: packet-gsm_map-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_gsm_map,
    &ett_gsm_map_InvokeId,
    &ett_gsm_map_InvokePDU,
    &ett_gsm_map_ReturnResultPDU,
	&ett_gsm_map_ReturnErrorPDU,
    &ett_gsm_map_ReturnResult_result,
	&ett_gsm_map_ReturnError_result,
    &ett_gsm_map_GSMMAPPDU,

/*--- Included file: packet-gsm_map-ettarr.c ---*/

    &ett_gsm_map_Bss_APDU,
    &ett_gsm_map_An_APDU,
    &ett_gsm_map_SupportedCamelPhases,
    &ett_gsm_map_Vlr_Capability,
    &ett_gsm_map_UpdateLocationArg,
    &ett_gsm_map_UpdateLocationRes,
    &ett_gsm_map_PrivateExtensionList,
    &ett_gsm_map_PrivateExtension,
    &ett_gsm_map_PcsExtensions,
    &ett_gsm_map_CancelLocationArg,
    &ett_gsm_map_T_identity,
    &ett_gsm_map_T_imsi_WithLMSI,
    &ett_gsm_map_CancelLocationRes,
    &ett_gsm_map_PurgeMS_Arg,
    &ett_gsm_map_PurgeMS_Res,
    &ett_gsm_map_SendIdentificationRes,
    &ett_gsm_map_T_authenticationSetList,
    &ett_gsm_map_T_authenticationSetList_item,
    &ett_gsm_map_PrepareHO_Arg,
    &ett_gsm_map_PrepareHO_Res,
    &ett_gsm_map_SendEndSignalV9Arg,
    &ett_gsm_map_PrepareSubsequentHO_Arg,
    &ett_gsm_map_SendAuthenticationInfoArgV3,
    &ett_gsm_map_T_re_synchronisationInfo,
    &ett_gsm_map_SendAuthenticationInfoRes,
    &ett_gsm_map_SendAuthenticationInfoRes_item,
    &ett_gsm_map_BasicService,
    &ett_gsm_map_BasicServiceGroupList,
    &ett_gsm_map_Odb_GeneralData,
    &ett_gsm_map_Odb_HPLMN_Data,
    &ett_gsm_map_BcsmCamelTDPData,
    &ett_gsm_map_BcsmCamelTDPDataList,
    &ett_gsm_map_O_CSI,
    &ett_gsm_map_InsertSubscriberDataArg,
    &ett_gsm_map_bearerServiceList,
    &ett_gsm_map_SEQUENCE_SIZE_1_20_OF_Teleservice,
    &ett_gsm_map_T_provisionedSS,
    &ett_gsm_map_T_provisionedSS_item,
    &ett_gsm_map_T_cug_Info,
    &ett_gsm_map_T_cug_SubscriptionList,
    &ett_gsm_map_T_cug_SubscriptionList_item,
    &ett_gsm_map_T_cug_FeatureList,
    &ett_gsm_map_T_cug_FeatureList_item,
    &ett_gsm_map_T_ss_Data2,
    &ett_gsm_map_T_emlpp_Info,
    &ett_gsm_map_T_odb_Data,
    &ett_gsm_map_T_regionalSubscriptionData,
    &ett_gsm_map_T_vbsSubscriptionData,
    &ett_gsm_map_T_vbsSubscriptionData_item,
    &ett_gsm_map_T_vgcsSubscriptionData,
    &ett_gsm_map_T_vgcsSubscriptionData_item,
    &ett_gsm_map_T_vlrCamelSubscriptionInfo,
    &ett_gsm_map_T_ss_CSI,
    &ett_gsm_map_T_ss_CamelData,
    &ett_gsm_map_T_ss_EventList,
    &ett_gsm_map_T_gprsSubscriptionData,
    &ett_gsm_map_T_gprsDataList,
    &ett_gsm_map_T_gprsDataList_item,
    &ett_gsm_map_T_lsaInformation,
    &ett_gsm_map_T_lsaDataList,
    &ett_gsm_map_T_lsaDataList_item,
    &ett_gsm_map_T_lcsInformation,
    &ett_gsm_map_T_gmlc_List,
    &ett_gsm_map_T_lcs_PrivacyExceptionList,
    &ett_gsm_map_T_lcs_PrivacyExceptionList_item,
    &ett_gsm_map_T_externalClientList,
    &ett_gsm_map_T_externalClientList_item,
    &ett_gsm_map_T_clientIdentity,
    &ett_gsm_map_T_plmnClientList,
    &ett_gsm_map_T_molr_List,
    &ett_gsm_map_T_molr_List_item,
    &ett_gsm_map_InsertSubscriberDataRes,
    &ett_gsm_map_ss_List,
    &ett_gsm_map_CallBarringInfo,
    &ett_gsm_map_T_callBarringFeatureList,
    &ett_gsm_map_T_callBarringFeatureList_item,
    &ett_gsm_map_ForwardingFeatureList,
    &ett_gsm_map_DestinationNumberCriteria,
    &ett_gsm_map_T_destinationNumberList,
    &ett_gsm_map_T_destinationNumberLengthList,
    &ett_gsm_map_ForwardingInfo,
    &ett_gsm_map_SEQUENCE_SIZE_1_32_OF_ForwardingFeatureList,
    &ett_gsm_map_Naea_PreferredCI,
    &ett_gsm_map_O_BcsmCamelTDP_CriteriaList,
    &ett_gsm_map_O_BcsmCamelTDP_CriteriaList_item,
    &ett_gsm_map_Ss_SubscriptionOption,
    &ett_gsm_map_DeleteSubscriberDataArg,
    &ett_gsm_map_T_gprsSubscriptionDataWithdraw,
    &ett_gsm_map_T_contextIdList,
    &ett_gsm_map_T_lsaInformationWithdraw,
    &ett_gsm_map_T_lsaIdentityList,
    &ett_gsm_map_DeleteSubscriberDataRes,
    &ett_gsm_map_ResetArg,
    &ett_gsm_map_T_hlr_List,
    &ett_gsm_map_RestoreDataArg,
    &ett_gsm_map_RestoreDataRes,
    &ett_gsm_map_ActivateTraceModeArg,
    &ett_gsm_map_ActivateTraceModeRes,
    &ett_gsm_map_DeactivateTraceModeArg,
    &ett_gsm_map_DeactivateTraceModeRes,
    &ett_gsm_map_SendRoutingInfoArg,
    &ett_gsm_map_T_camelInfo,
    &ett_gsm_map_SendRoutingInfoRes,
    &ett_gsm_map_T_extendedRoutingInfo,
    &ett_gsm_map_T_routingInfo,
    &ett_gsm_map_T_camelRoutingInfo,
    &ett_gsm_map_T_gmscCamelSubscriptionInfo,
    &ett_gsm_map_T_t_CSI,
    &ett_gsm_map_T_ccbs_Indicators,
    &ett_gsm_map_SubscriberState,
    &ett_gsm_map_LocationInformation,
    &ett_gsm_map_T_cellIdOrLAI,
    &ett_gsm_map_SubscriberInfo,
    &ett_gsm_map_AdditionalSignalInfo,
    &ett_gsm_map_Cug_CheckInfo,
    &ett_gsm_map_ForwardingData,
    &ett_gsm_map_ProvideRoamingNumberArg,
    &ett_gsm_map_ProvideRoamingNumberRes,
    &ett_gsm_map_ResumeCallHandlingArg,
    &ett_gsm_map_T_uu_Data,
    &ett_gsm_map_ResumeCallHandlingRes,
    &ett_gsm_map_ProvideSIWFSNumberArg,
    &ett_gsm_map_ProvideSIWFSNumberRes,
    &ett_gsm_map_SIWFSSignallingModifyArg,
    &ett_gsm_map_SIWFSSignallingModifyRes,
    &ett_gsm_map_SetReportingStateArg,
    &ett_gsm_map_SetReportingStateRes,
    &ett_gsm_map_StatusReportArg,
    &ett_gsm_map_T_eventReportData,
    &ett_gsm_map_T_callReportdata,
    &ett_gsm_map_StatusReportRes,
    &ett_gsm_map_RemoteUserFreeArg,
    &ett_gsm_map_RemoteUserFreeRes,
    &ett_gsm_map_Ss_Data,
    &ett_gsm_map_RegisterSS_Arg,
    &ett_gsm_map_Ss_Info,
    &ett_gsm_map_Ccbs_Feature,
    &ett_gsm_map_Ss_ForBS,
    &ett_gsm_map_InterrogateSS_Res,
    &ett_gsm_map_SEQUENCE_SIZE_1_13_OF_ForwardingFeatureList,
    &ett_gsm_map_T_genericServiceInfo,
    &ett_gsm_map_T_ccbs_FeatureList,
    &ett_gsm_map_T_ccbs_FeatureList_item,
    &ett_gsm_map_Ussd_Arg,
    &ett_gsm_map_Ussd_Res,
    &ett_gsm_map_ServiceIndicator,
    &ett_gsm_map_RegisterCC_EntryArg,
    &ett_gsm_map_T_ccbs_Data,
    &ett_gsm_map_RegisterCC_EntryRes,
    &ett_gsm_map_EraseCC_EntryArg,
    &ett_gsm_map_EraseCC_EntryRes,
    &ett_gsm_map_RoutingInfoForSMArg,
    &ett_gsm_map_RoutingInfoForSMRes,
    &ett_gsm_map_T_locationInfoWithLMSI,
    &ett_gsm_map_T_additional_Number,
    &ett_gsm_map_Mo_forwardSM_Arg,
    &ett_gsm_map_Mo_forwardSM_Res,
    &ett_gsm_map_Sm_RP_OA,
    &ett_gsm_map_Sm_RP_DA,
    &ett_gsm_map_Mt_forwardSM_Arg,
    &ett_gsm_map_Mt_forwardSM_Res,
    &ett_gsm_map_ReportSM_DeliveryStatusArg,
    &ett_gsm_map_ReportSM_DeliveryStatusRes,
    &ett_gsm_map_InformServiceCentreArg,
    &ett_gsm_map_T_mw_Status,
    &ett_gsm_map_AlertServiceCentreArg,
    &ett_gsm_map_ReadyForSM_Arg,
    &ett_gsm_map_ReadyForSM_Res,
    &ett_gsm_map_ProvideSubscriberInfoArg,
    &ett_gsm_map_ProvideSubscriberInfoRes,
    &ett_gsm_map_RequestedInfo,
    &ett_gsm_map_AnyTimeInterrogationArg,
    &ett_gsm_map_T_subscriberIdentity,
    &ett_gsm_map_AnyTimeInterrogationRes,
    &ett_gsm_map_Ss_InvocationNotificationArg,
    &ett_gsm_map_T_ss_EventSpecification,
    &ett_gsm_map_Ss_InvocationNotificationRes,
    &ett_gsm_map_PrepareGroupCallArg,
    &ett_gsm_map_PrepareGroupCallRes,
    &ett_gsm_map_SendGroupCallEndSignalArg,
    &ett_gsm_map_SendGroupCallEndSignalRes,
    &ett_gsm_map_ProcessGroupCallSignallingArg,
    &ett_gsm_map_ForwardGroupCallSignallingArg,
    &ett_gsm_map_UpdateGprsLocationArg,
    &ett_gsm_map_T_sgsn_Capability,
    &ett_gsm_map_UpdateGprsLocationRes,
    &ett_gsm_map_SendRoutingInfoForGprsArg,
    &ett_gsm_map_SendRoutingInfoForGprsRes,
    &ett_gsm_map_FailureReportArg,
    &ett_gsm_map_FailureReportRes,
    &ett_gsm_map_NoteMsPresentForGprsArg,
    &ett_gsm_map_NoteMsPresentForGprsRes,
    &ett_gsm_map_LcsClientExternalID,
    &ett_gsm_map_LcsClientName,
    &ett_gsm_map_Lcs_ClientID,
    &ett_gsm_map_LcsLocationInfo,
    &ett_gsm_map_ProvideSubscriberLocation_Arg,
    &ett_gsm_map_T_locationType,
    &ett_gsm_map_T_lcs_QoS,
    &ett_gsm_map_T_responseTime,
    &ett_gsm_map_ProvideSubscriberLocation_Res,
    &ett_gsm_map_TargetMS,
    &ett_gsm_map_RoutingInfoForLCS_Arg,
    &ett_gsm_map_RoutingInfoForLCS_Res,
    &ett_gsm_map_SubscriberLocationReport_Arg,
    &ett_gsm_map_SubscriberLocationReport_Res,
    &ett_gsm_map_SystemFailureParam,
    &ett_gsm_map_T_extensibleSystemFailureParam,
    &ett_gsm_map_DataMissingParam,
    &ett_gsm_map_UnexpectedDataParam,
    &ett_gsm_map_FacilityNotSupParam,
    &ett_gsm_map_IncompatibleTerminalParam,
    &ett_gsm_map_ResourceLimitationParam,
    &ett_gsm_map_UnknownSubscriberParam,
    &ett_gsm_map_NumberChangedParam,
    &ett_gsm_map_UnidentifiedSubParam,
    &ett_gsm_map_RoamingNotAllowedParam,
    &ett_gsm_map_IllegalSubscriberParam,
    &ett_gsm_map_IllegalEquipmentParam,
    &ett_gsm_map_BearerServNotProvParam,
    &ett_gsm_map_TeleservNotProvParam,
    &ett_gsm_map_TracingBufferFullParam,
    &ett_gsm_map_NoRoamingNbParam,
    &ett_gsm_map_AbsentSubscriberParam,
    &ett_gsm_map_BusySubscriberParam,
    &ett_gsm_map_NoSubscriberReplyParam,
    &ett_gsm_map_CallBarredParam,
    &ett_gsm_map_T_extensibleCallBarredParam,
    &ett_gsm_map_ForwardingFailedParam,
    &ett_gsm_map_Or_NotAllowedParam,
    &ett_gsm_map_ForwardingViolationParam,
    &ett_gsm_map_Cug_RejectParam,
    &ett_gsm_map_Ati_NotAllowedParam,
    &ett_gsm_map_NoGroupCallNbParam,
    &ett_gsm_map_Ss_IncompatibilityCause,
    &ett_gsm_map_ShortTermDenialParam,
    &ett_gsm_map_LongTermDenialParam,
    &ett_gsm_map_SubBusyForMT_SMS_Param,
    &ett_gsm_map_Sm_DeliveryFailureCause,
    &ett_gsm_map_MessageWaitListFullParam,
    &ett_gsm_map_AbsentSubscriberSM_Param,
    &ett_gsm_map_UnauthorizedRequestingNetwork_Param,
    &ett_gsm_map_UnauthorizedLCSClient_Param,
    &ett_gsm_map_PositionMethodFailure_Param,
    &ett_gsm_map_UnknownOrUnreachableLCSClient_Param,
    &ett_gsm_map_ExtensionContainer,

/*--- End of included file: packet-gsm_map-ettarr.c ---*/

  };

  /* Register protocol */
  proto_gsm_map = proto_register_protocol(PNAME, PSNAME, PFNAME);
/*XXX  register_dissector("gsm_map", dissect_gsm_map, proto_gsm_map);*/
  /* Register fields and subtrees */
  proto_register_field_array(proto_gsm_map, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

	sms_dissector_table = register_dissector_table("gsm_map.sms_tpdu", 
		"GSM SMS TPDU",FT_UINT8, BASE_DEC);

	gsm_map_tap = register_tap("gsm_map");
	register_ber_oid_name("0.4.0.0.1.0.1.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) networkLocUp(1) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.2.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) locationCancel(2) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.2.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) locationCancel(2) version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.3.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) roamingNbEnquiry(3) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.3.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) roamingNbEnquiry(3) version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.5.3","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) locInfoRetrieval(5) version3(3)" );
	register_ber_oid_name("0.4.0.0.1.0.5.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) locInfoRetrieval(5) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.5.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) locInfoRetrieval(5) version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.10.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) reset(10) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.10.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) reset(10) version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.11.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) handoverControl(11) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.11.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) handoverControl(11) version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.26.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) imsiRetrieval(26) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.13.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) equipmentMngt(13) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.13.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) equipmentMngt(13) version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.14.3","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) infoRetrieval(14) version3(3)" );
	register_ber_oid_name("0.4.0.0.1.0.14.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) infoRetrieval(14) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.14.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) infoRetrieval(14) version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.15.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) interVlrInfoRetrieval(15) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.16.3","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) subscriberDataMngt(16) version3(3)" );
	register_ber_oid_name("0.4.0.0.1.0.16.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) subscriberDataMngt(16) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.16.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) subscriberDataMngt(16) version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.17.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) tracing(17) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.17.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) tracing(17) version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.18.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) networkFunctionalSs(18) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.18.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) networkFunctionalSs(18) version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.19.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) networkUnstructuredSs(19) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.20.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgGateway(20) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.20.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgGateway(20) version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.21.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgMO-Relay(21) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.21.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) --shortMsgRelay--21 version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.23.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgAlert(23) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.23.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgAlert(23) version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.24.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) mwdMngt(24) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.24.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) mwdMngt(24) version1(1)" );
	register_ber_oid_name("0.4.0.0.1.0.25.2","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgMT-Relay(25) version2(2)" );
	register_ber_oid_name("0.4.0.0.1.0.25.1","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) msPurging(27) version2(2)" );

	/* Register our configuration options, particularly our ssn:s */

	gsm_map_module = prefs_register_protocol(proto_gsm_map, proto_reg_handoff_gsm_map);
	prefs_register_uint_preference(gsm_map_module, "tcap.itu_ssn1",
		"Subsystem number used for GSM MAP 1",
		"Set Subsystem number used for GSM MAP",
		10, &global_tcap_itu_ssn1);
	prefs_register_uint_preference(gsm_map_module, "tcap.itu_ssn2",
		"Subsystem number used for GSM MAP 2",
		"Set Subsystem number used for GSM MAP",
		10, &global_tcap_itu_ssn2);
	prefs_register_uint_preference(gsm_map_module, "tcap.itu_ssn3",
		"Subsystem number used for GSM MAP 3",
		"Set Subsystem number used for GSM MAP",
		10, &global_tcap_itu_ssn3);
	prefs_register_uint_preference(gsm_map_module, "tcap.itu_ssn4",
		"Subsystem number used for GSM MAP 4",
		"Set Subsystem number used for GSM MAP",
		10, &global_tcap_itu_ssn4);


}


