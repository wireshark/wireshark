/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-gsm_map.c                                                         */
/* ../../tools/asn2wrs.py -b -e -p gsm_map -c gsmmap.cnf -s packet-gsm_map-template GSMMAP.asn */

/* Input file: packet-gsm_map-template.c */

#line 1 "packet-gsm_map-template.c"
/* packet-gsm_map-template.c
 * Routines for GSM MobileApplication packet dissection
 * Copyright 2004 - 2006 , Anders Broman <anders.broman [AT] ericsson.com>
 * Based on the dissector by:
 * Felix Fei <felix.fei [AT] utstar.com>
 * and Michael Lum <mlum [AT] telostech.com>
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
 * References: ETSI TS 129 002
 * Updated to ETSI TS 129 002 V6.9.0 (2005-3GPP TS 29.002 version 6.9.0 Release 6)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <math.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/emem.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-q931.h"
#include "packet-gsm_map.h"
#include "packet-gsm_a.h"
#include "packet-tcap.h"
#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-smpp.h"
#include "packet-gsm_sms.h"

#define PNAME  "GSM Mobile Application"
#define PSNAME "GSM_MAP"
#define PFNAME "gsm_map"

/* Initialize the protocol and registered fields */
int proto_gsm_map = -1;
/*
static int hf_gsm_map_invokeCmd = -1;             / Opcode /
static int hf_gsm_map_invokeid = -1;              / INTEGER /
static int hf_gsm_map_absent = -1;                / NULL /
static int hf_gsm_map_invokeId = -1;              / InvokeId /
static int hf_gsm_map_invoke = -1;                / InvokePDU /
static int hf_gsm_map_returnResult = -1;          / InvokePDU /
static int hf_gsm_map_returnResult_result = -1;
static int hf_gsm_map_returnError_result = -1;
static int hf_gsm_map_returnError = -1;
static int hf_gsm_map_local_errorCode = -1;
static int hf_gsm_map_global_errorCode_oid = -1;
static int hf_gsm_map_global_errorCode = -1;
*/
static int hf_gsm_map_SendAuthenticationInfoArg = -1;
static int hf_gsm_map_SendAuthenticationInfoRes = -1;
static int hf_gsm_mapSendEndSignal = -1;
static int hf_gsm_map_getPassword = -1;
static int hf_gsm_map_CheckIMEIArg = -1;
static int hf_gsm_map_currentPassword = -1;
static int hf_gsm_map_extension = -1;
static int hf_gsm_map_nature_of_number = -1;
static int hf_gsm_map_number_plan = -1;
static int hf_gsm_map_isdn_address_digits = -1;
static int hf_gsm_map_address_digits = -1;
static int hf_gsm_map_servicecentreaddress_digits = -1;
static int hf_gsm_map_imsi_digits = -1;
static int hf_gsm_map_Ss_Status_unused = -1;
static int hf_gsm_map_Ss_Status_q_bit = -1;
static int hf_gsm_map_Ss_Status_p_bit = -1;
static int hf_gsm_map_Ss_Status_r_bit = -1;
static int hf_gsm_map_Ss_Status_a_bit = -1;
static int hf_gsm_map_notification_to_forwarding_party = -1;
static int hf_gsm_map_redirecting_presentation = -1;
static int hf_gsm_map_notification_to_calling_party = -1;
static int hf_gsm_map_forwarding_reason = -1;
static int hf_gsm_map_pdp_type_org = -1;
static int hf_gsm_map_etsi_pdp_type_number = -1;
static int hf_gsm_map_ietf_pdp_type_number = -1;
static int hf_gsm_map_ext_qos_subscribed_pri = -1;

static int hf_gsm_map_qos_traffic_cls = -1;
static int hf_gsm_map_qos_del_order = -1;
static int hf_gsm_map_qos_del_of_err_sdu = -1;
static int hf_gsm_map_qos_ber = -1;
static int hf_gsm_map_qos_sdu_err_rat = -1;
static int hf_gsm_map_qos_traff_hdl_pri = -1;
static int hf_gsm_map_qos_max_sdu = -1;
static int hf_gsm_map_max_brate_ulink = -1;
static int hf_gsm_map_max_brate_dlink = -1;
static int hf_gsm_map_qos_transfer_delay = -1;
static int hf_gsm_map_guaranteed_max_brate_ulink = -1;
static int hf_gsm_map_guaranteed_max_brate_dlink = -1;
static int hf_gsm_map_GSNAddress_IPv4 = -1;
static int hf_gsm_map_GSNAddress_IPv6 = -1;
static int hf_geo_loc_type_of_shape = -1;
static int hf_geo_loc_sign_of_lat	= -1;
static int hf_geo_loc_deg_of_lat =-1;
static int hf_geo_loc_deg_of_long =-1;
static int hf_geo_loc_uncertainty_code = -1;
static int hf_geo_loc_uncertainty_semi_major = -1;
static int hf_geo_loc_uncertainty_semi_minor = -1;
static int hf_geo_loc_orientation_of_major_axis = -1;
static int hf_geo_loc_uncertainty_altitude = -1;
static int hf_geo_loc_confidence = -1;
static int hf_geo_loc_no_of_points = -1;
static int hf_geo_loc_D = -1;
static int hf_geo_loc_altitude = -1;
static int hf_geo_loc_inner_radius = -1;
static int hf_geo_loc_uncertainty_radius = -1;
static int hf_geo_loc_offset_angle = -1;
static int hf_geo_loc_included_angle = -1;


/*--- Included file: packet-gsm_map-hf.c ---*/
#line 1 "packet-gsm_map-hf.c"
static int hf_gsm_map_Component_PDU = -1;         /* Component */
static int hf_gsm_map_invoke = -1;                /* Invoke */
static int hf_gsm_map_returnResultLast = -1;      /* ReturnResult */
static int hf_gsm_map_returnError = -1;           /* ReturnError */
static int hf_gsm_map_reject = -1;                /* Reject */
static int hf_gsm_map_invokeID = -1;              /* InvokeIdType */
static int hf_gsm_map_linkedID = -1;              /* InvokeIdType */
static int hf_gsm_map_opCode = -1;                /* OPERATION */
static int hf_gsm_map_invokeparameter = -1;       /* InvokeParameter */
static int hf_gsm_map_resultretres = -1;          /* T_resultretres */
static int hf_gsm_map_returnparameter = -1;       /* ReturnResultParameter */
static int hf_gsm_map_returnErrorCode = -1;       /* ERROR */
static int hf_gsm_map_parameter = -1;             /* ReturnErrorParameter */
static int hf_gsm_map_invokeIDRej = -1;           /* T_invokeIDRej */
static int hf_gsm_map_derivable = -1;             /* InvokeIdType */
static int hf_gsm_map_not_derivable = -1;         /* NULL */
static int hf_gsm_map_problem = -1;               /* T_problem */
static int hf_gsm_map_generalProblem = -1;        /* GeneralProblem */
static int hf_gsm_map_invokeProblem = -1;         /* InvokeProblem */
static int hf_gsm_map_returnResultProblem = -1;   /* ReturnResultProblem */
static int hf_gsm_map_returnErrorProblem = -1;    /* ReturnErrorProblem */
static int hf_gsm_map_operationLocalvalue = -1;   /* OperationLocalvalue */
static int hf_gsm_map_globalValue = -1;           /* OBJECT_IDENTIFIER */
static int hf_gsm_map_localErrorcode = -1;        /* LocalErrorcode */
static int hf_gsm_map_protocolId = -1;            /* ProtocolId */
static int hf_gsm_map_signalInfo = -1;            /* SignalInfo */
static int hf_gsm_map_extensionContainer = -1;    /* ExtensionContainer */
static int hf_gsm_map_imsi = -1;                  /* IMSI */
static int hf_gsm_map_msc_Number = -1;            /* ISDN_AddressString */
static int hf_gsm_map_vlr_Number = -1;            /* ISDN_AddressString */
static int hf_gsm_map_lmsi = -1;                  /* LMSI */
static int hf_gsm_map_vlr_Capability = -1;        /* VLR_Capability */
static int hf_gsm_map_informPreviousNetworkEntity = -1;  /* NULL */
static int hf_gsm_map_cs_LCS_NotSupportedByUE = -1;  /* NULL */
static int hf_gsm_map_v_gmlc_Address = -1;        /* GSN_Address */
static int hf_gsm_map_add_info = -1;              /* ADD_Info */
static int hf_gsm_map_hlr_Number = -1;            /* ISDN_AddressString */
static int hf_gsm_map_add_Capability = -1;        /* NULL */
static int hf_gsm_map_supportedCamelPhases = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_solsaSupportIndicator = -1;  /* NULL */
static int hf_gsm_map_istSupportIndicator = -1;   /* IST_SupportIndicator */
static int hf_gsm_map_superChargerSupportedInServingNetworkEntity = -1;  /* SuperChargerInfo */
static int hf_gsm_map_longFTN_Supported = -1;     /* NULL */
static int hf_gsm_map_supportedLCS_CapabilitySets = -1;  /* SupportedLCS_CapabilitySets */
static int hf_gsm_map_offeredCamel4CSIs = -1;     /* OfferedCamel4CSIs */
static int hf_gsm_map_sendSubscriberData = -1;    /* NULL */
static int hf_gsm_map_subscriberDataStored = -1;  /* AgeIndicator */
static int hf_gsm_map_imeisv = -1;                /* IMEI */
static int hf_gsm_map_skipSubscriberDataUpdate = -1;  /* NULL */
static int hf_gsm_map_PrivateExtensionList_item = -1;  /* PrivateExtension */
static int hf_gsm_map_extId = -1;                 /* OBJECT_IDENTIFIER */
static int hf_gsm_map_extType = -1;               /* T_extType */
static int hf_gsm_map_privateExtensionList = -1;  /* PrivateExtensionList */
static int hf_gsm_map_slr_Arg_PCS_Extensions = -1;  /* SLR_Arg_PCS_Extensions */
static int hf_gsm_map_na_ESRK_Request = -1;       /* NULL */
static int hf_gsm_map_identity = -1;              /* Identity */
static int hf_gsm_map_cancellationType = -1;      /* CancellationType */
static int hf_gsm_map_imsi_WithLMSI = -1;         /* IMSI_WithLMSI */
static int hf_gsm_map_sgsn_Number = -1;           /* ISDN_AddressString */
static int hf_gsm_map_freezeTMSI = -1;            /* NULL */
static int hf_gsm_map_freezeP_TMSI = -1;          /* NULL */
static int hf_gsm_map_tmsi = -1;                  /* TMSI */
static int hf_gsm_map_numberOfRequestedVectors = -1;  /* NumberOfRequestedVectors */
static int hf_gsm_map_segmentationProhibited = -1;  /* NULL */
static int hf_gsm_map_previous_LAI = -1;          /* LAIFixedLength */
static int hf_gsm_map_hopCounter = -1;            /* HopCounter */
static int hf_gsm_map_authenticationSetList = -1;  /* AuthenticationSetList */
static int hf_gsm_map_currentSecurityContext = -1;  /* CurrentSecurityContext */
static int hf_gsm_map_tripletList = -1;           /* TripletList */
static int hf_gsm_map_quintupletList = -1;        /* QuintupletList */
static int hf_gsm_map_TripletList_item = -1;      /* AuthenticationTriplet */
static int hf_gsm_map_QuintupletList_item = -1;   /* AuthenticationQuintuplet */
static int hf_gsm_map_rand = -1;                  /* RAND */
static int hf_gsm_map_sres = -1;                  /* SRES */
static int hf_gsm_map_kc = -1;                    /* Kc */
static int hf_gsm_map_xres = -1;                  /* XRES */
static int hf_gsm_map_ck = -1;                    /* CK */
static int hf_gsm_map_ik = -1;                    /* IK */
static int hf_gsm_map_autn = -1;                  /* AUTN */
static int hf_gsm_map_gsm_SecurityContextData = -1;  /* GSM_SecurityContextData */
static int hf_gsm_map_umts_SecurityContextData = -1;  /* UMTS_SecurityContextData */
static int hf_gsm_map_cksn = -1;                  /* Cksn */
static int hf_gsm_map_ksi = -1;                   /* KSI */
static int hf_gsm_map_targetCellId = -1;          /* GlobalCellId */
static int hf_gsm_map_ho_NumberNotRequired = -1;  /* NULL */
static int hf_gsm_map_bss_APDU = -1;              /* Bss_APDU */
static int hf_gsm_map_targetRNCId = -1;           /* RNCId */
static int hf_gsm_map_an_APDU = -1;               /* AccessNetworkSignalInfo */
static int hf_gsm_map_multipleBearerRequested = -1;  /* NULL */
static int hf_gsm_map_integrityProtectionInfo = -1;  /* IntegrityProtectionInformation */
static int hf_gsm_map_encryptionInfo = -1;        /* EncryptionInformation */
static int hf_gsm_map_radioResourceInformation = -1;  /* RadioResourceInformation */
static int hf_gsm_map_allowedGSM_Algorithms = -1;  /* AllowedGSM_Algorithms */
static int hf_gsm_map_allowedUMTS_Algorithms = -1;  /* AllowedUMTS_Algorithms */
static int hf_gsm_map_radioResourceList = -1;     /* RadioResourceList */
static int hf_gsm_map_rab_Id = -1;                /* RAB_Id */
static int hf_gsm_map_bssmap_ServiceHandover = -1;  /* BSSMAP_ServiceHandover */
static int hf_gsm_map_ranap_ServiceHandover = -1;  /* RANAP_ServiceHandover */
static int hf_gsm_map_bssmap_ServiceHandoverList = -1;  /* BSSMAP_ServiceHandoverList */
static int hf_gsm_map_asciCallReference = -1;     /* ASCI_CallReference */
static int hf_gsm_map_geran_classmark = -1;       /* GERAN_Classmark */
static int hf_gsm_map_iuCurrentlyUsedCodec = -1;  /* Codec */
static int hf_gsm_map_iuSupportedCodecsList = -1;  /* SupportedCodecsList */
static int hf_gsm_map_rab_ConfigurationIndicator = -1;  /* NULL */
static int hf_gsm_map_uesbi_Iu = -1;              /* UESBI_Iu */
static int hf_gsm_map_BSSMAP_ServiceHandoverList_item = -1;  /* BSSMAP_ServiceHandoverInfo */
static int hf_gsm_map_RadioResourceList_item = -1;  /* RadioResource */
static int hf_gsm_map_handoverNumber = -1;        /* ISDN_AddressString */
static int hf_gsm_map_relocationNumberList = -1;  /* RelocationNumberList */
static int hf_gsm_map_multicallBearerInfo = -1;   /* MulticallBearerInfo */
static int hf_gsm_map_multipleBearerNotSupported = -1;  /* NULL */
static int hf_gsm_map_selectedUMTS_Algorithms = -1;  /* SelectedUMTS_Algorithms */
static int hf_gsm_map_chosenRadioResourceInformation = -1;  /* ChosenRadioResourceInformation */
static int hf_gsm_map_iuSelectedCodec = -1;       /* Codec */
static int hf_gsm_map_iuAvailableCodecsList = -1;  /* CodecList */
static int hf_gsm_map_integrityProtectionAlgorithm = -1;  /* ChosenIntegrityProtectionAlgorithm */
static int hf_gsm_map_encryptionAlgorithm = -1;   /* ChosenEncryptionAlgorithm */
static int hf_gsm_map_chosenChannelInfo = -1;     /* ChosenChannelInfo */
static int hf_gsm_map_chosenSpeechVersion = -1;   /* ChosenSpeechVersion */
static int hf_gsm_map_RelocationNumberList_item = -1;  /* RelocationNumber */
static int hf_gsm_map_selectedGSM_Algorithm = -1;  /* SelectedGSM_Algorithm */
static int hf_gsm_map_selectedRab_Id = -1;        /* RAB_Id */
static int hf_gsm_map_iUSelectedCodec = -1;       /* Codec */
static int hf_gsm_map_utranCodecList = -1;        /* CodecList */
static int hf_gsm_map_geranCodecList = -1;        /* CodecList */
static int hf_gsm_map_codec1 = -1;                /* Codec */
static int hf_gsm_map_codec2 = -1;                /* Codec */
static int hf_gsm_map_codec3 = -1;                /* Codec */
static int hf_gsm_map_codec4 = -1;                /* Codec */
static int hf_gsm_map_codec5 = -1;                /* Codec */
static int hf_gsm_map_codec6 = -1;                /* Codec */
static int hf_gsm_map_codec7 = -1;                /* Codec */
static int hf_gsm_map_codec8 = -1;                /* Codec */
static int hf_gsm_map_keyStatus = -1;             /* KeyStatus */
static int hf_gsm_map_currentlyUsedCodec = -1;    /* Codec */
static int hf_gsm_map_integrityProtectionAlgorithms = -1;  /* PermittedIntegrityProtectionAlgorithms */
static int hf_gsm_map_encryptionAlgorithms = -1;  /* PermittedEncryptionAlgorithms */
static int hf_gsm_map_targetMSC_Number = -1;      /* ISDN_AddressString */
static int hf_gsm_map_immediateResponsePreferred = -1;  /* NULL */
static int hf_gsm_map_re_synchronisationInfo = -1;  /* Re_synchronisationInfo */
static int hf_gsm_map_requestingNodeType = -1;    /* RequestingNodeType */
static int hf_gsm_map_requestingPLMN_Id = -1;     /* PLMN_Id */
static int hf_gsm_map_SendAuthenticationInfoRes_item = -1;  /* SendAuthenticationInfoRes_item */
static int hf_gsm_map_auts = -1;                  /* AUTS */
static int hf_gsm_map_imei = -1;                  /* IMEI */
static int hf_gsm_map_requestedEquipmentInfo = -1;  /* RequestedEquipmentInfo */
static int hf_gsm_map_equipmentStatus = -1;       /* EquipmentStatus */
static int hf_gsm_map_bmuef = -1;                 /* UESBI_Iu */
static int hf_gsm_map_uesbi_IuA = -1;             /* UESBI_IuA */
static int hf_gsm_map_uesbi_IuB = -1;             /* UESBI_IuB */
static int hf_gsm_map_bearerservice = -1;         /* Bearerservice */
static int hf_gsm_map_teleservice = -1;           /* Teleservice */
static int hf_gsm_map_BasicServiceGroupList_item = -1;  /* BasicService */
static int hf_gsm_map_bcsmTriggerDetectionPoint = -1;  /* BcsmTriggerDetectionPoint */
static int hf_gsm_map_serviceKey = -1;            /* ServiceKey */
static int hf_gsm_map_gsmSCFAddress = -1;         /* GsmSCF_Address */
static int hf_gsm_map_defaultCallHandling = -1;   /* DefaultCallHandling */
static int hf_gsm_map_BcsmCamelTDPDataList_item = -1;  /* BcsmCamelTDPData */
static int hf_gsm_map_o_BcsmCamelTDPDataList = -1;  /* O_BcsmCamelTDPDataList */
static int hf_gsm_map_camelCapabilityHandling = -1;  /* CamelCapabilityHandling */
static int hf_gsm_map_notificationToCSE = -1;     /* NULL */
static int hf_gsm_map_csiActive = -1;             /* NULL */
static int hf_gsm_map_O_BcsmCamelTDPDataList_item = -1;  /* O_BcsmCamelTDPData */
static int hf_gsm_map_o_BcsmTriggerDetectionPoint = -1;  /* O_BcsmTriggerDetectionPoint */
static int hf_gsm_map_gsmSCF_Address = -1;        /* ISDN_AddressString */
static int hf_gsm_map_msisdn = -1;                /* ISDN_AddressString */
static int hf_gsm_map_category = -1;              /* Category */
static int hf_gsm_map_subscriberStatus = -1;      /* SubscriberStatus */
static int hf_gsm_map_bearerserviceList = -1;     /* BearerServiceList */
static int hf_gsm_map_teleserviceList = -1;       /* TeleserviceList */
static int hf_gsm_map_provisionedSS = -1;         /* Ext_SS_InfoList */
static int hf_gsm_map_odb_Data = -1;              /* ODB_Data */
static int hf_gsm_map_roamingRestrictionDueToUnsupportedFeature = -1;  /* NULL */
static int hf_gsm_map_regionalSubscriptionData = -1;  /* ZoneCodeList */
static int hf_gsm_map_vbsSubscriptionData = -1;   /* VBSDataList */
static int hf_gsm_map_vgcsSubscriptionData = -1;  /* VGCSDataList */
static int hf_gsm_map_vlrCamelSubscriptionInfo = -1;  /* VlrCamelSubscriptionInfo */
static int hf_gsm_map_naea_PreferredCI = -1;      /* NAEA_PreferredCI */
static int hf_gsm_map_gprsSubscriptionData = -1;  /* GPRSSubscriptionData */
static int hf_gsm_map_roamingRestrictedInSgsnDueToUnsupportedFeature = -1;  /* NULL */
static int hf_gsm_map_networkAccessMode = -1;     /* NetworkAccessMode */
static int hf_gsm_map_lsaInformation = -1;        /* LSAInformation */
static int hf_gsm_map_lmu_Indicator = -1;         /* NULL */
static int hf_gsm_map_lcsInformation = -1;        /* LCSInformation */
static int hf_gsm_map_istAlertTimer = -1;         /* IST_AlertTimerValue */
static int hf_gsm_map_superChargerSupportedInHLR = -1;  /* AgeIndicator */
static int hf_gsm_map_mc_SS_Info = -1;            /* MC_SS_Info */
static int hf_gsm_map_cs_AllocationRetentionPriority = -1;  /* CS_AllocationRetentionPriority */
static int hf_gsm_map_sgsn_CAMEL_SubscriptionInfo = -1;  /* SGSN_CAMEL_SubscriptionInfo */
static int hf_gsm_map_chargingCharacteristics = -1;  /* ChargingCharacteristics */
static int hf_gsm_map_accessRestrictionData = -1;  /* AccessRestrictionData */
static int hf_gsm_map_gmlc_List = -1;             /* GMLC_List */
static int hf_gsm_map_lcs_PrivacyExceptionList = -1;  /* LCS_PrivacyExceptionList */
static int hf_gsm_map_molr_List = -1;             /* MOLR_List */
static int hf_gsm_map_add_lcs_PrivacyExceptionList = -1;  /* LCS_PrivacyExceptionList */
static int hf_gsm_map_GMLC_List_item = -1;        /* ISDN_AddressString */
static int hf_gsm_map_GPRSDataList_item = -1;     /* PDP_Context */
static int hf_gsm_map_pdp_ContextId = -1;         /* ContextId */
static int hf_gsm_map_pdp_Type = -1;              /* PDP_Type */
static int hf_gsm_map_pdp_Address = -1;           /* PDP_Address */
static int hf_gsm_map_qos_Subscribed = -1;        /* QoS_Subscribed */
static int hf_gsm_map_vplmnAddressAllowed = -1;   /* NULL */
static int hf_gsm_map_apn = -1;                   /* APN */
static int hf_gsm_map_ext_QoS_Subscribed = -1;    /* Ext_QoS_Subscribed */
static int hf_gsm_map_pdp_ChargingCharacteristics = -1;  /* ChargingCharacteristics */
static int hf_gsm_map_ext2_QoS_Subscribed = -1;   /* Ext2_QoS_Subscribed */
static int hf_gsm_map_completeDataListIncluded = -1;  /* NULL */
static int hf_gsm_map_gprsDataList = -1;          /* GPRSDataList */
static int hf_gsm_map_gprs_CSI = -1;              /* GPRS_CSI */
static int hf_gsm_map_mo_sms_CSI = -1;            /* SMS_CSI */
static int hf_gsm_map_mt_sms_CSI = -1;            /* SMS_CSI */
static int hf_gsm_map_mt_smsCAMELTDP_CriteriaList = -1;  /* MT_smsCAMELTDP_CriteriaList */
static int hf_gsm_map_mg_csi = -1;                /* MG_CSI */
static int hf_gsm_map_gprs_CamelTDPDataList = -1;  /* GPRS_CamelTDPDataList */
static int hf_gsm_map_csi_Active = -1;            /* NULL */
static int hf_gsm_map_GPRS_CamelTDPDataList_item = -1;  /* GPRS_CamelTDPData */
static int hf_gsm_map_gprs_TriggerDetectionPoint = -1;  /* GPRS_TriggerDetectionPoint */
static int hf_gsm_map_defaultSessionHandling = -1;  /* DefaultGPRS_Handling */
static int hf_gsm_map_LSADataList_item = -1;      /* LSAData */
static int hf_gsm_map_lsaIdentity = -1;           /* LSAIdentity */
static int hf_gsm_map_lsaAttributes = -1;         /* LSAAttributes */
static int hf_gsm_map_lsaActiveModeIndicator = -1;  /* NULL */
static int hf_gsm_map_lsaOnlyAccessIndicator = -1;  /* LSAOnlyAccessIndicator */
static int hf_gsm_map_lsaDataList = -1;           /* LSADataList */
static int hf_gsm_map_bearerServiceList = -1;     /* BearerServiceList */
static int hf_gsm_map_ss_List = -1;               /* SS_List */
static int hf_gsm_map_odb_GeneralData = -1;       /* ODB_GeneralData */
static int hf_gsm_map_regionalSubscriptionResponse = -1;  /* RegionalSubscriptionResponse */
static int hf_gsm_map_basicServiceList = -1;      /* BasicServiceList */
static int hf_gsm_map_regionalSubscriptionIdentifier = -1;  /* ZoneCode */
static int hf_gsm_map_vbsGroupIndication = -1;    /* NULL */
static int hf_gsm_map_vgcsGroupIndication = -1;   /* NULL */
static int hf_gsm_map_camelSubscriptionInfoWithdraw = -1;  /* NULL */
static int hf_gsm_map_gprsSubscriptionDataWithdraw = -1;  /* GPRSSubscriptionDataWithdraw */
static int hf_gsm_map_roamingRestrictedInSgsnDueToUnsuppportedFeature = -1;  /* NULL */
static int hf_gsm_map_lsaInformationWithdraw = -1;  /* LSAInformationWithdraw */
static int hf_gsm_map_gmlc_ListWithdraw = -1;     /* NULL */
static int hf_gsm_map_istInformationWithdraw = -1;  /* NULL */
static int hf_gsm_map_specificCSI_Withdraw = -1;  /* SpecificCSI_Withdraw */
static int hf_gsm_map_chargingCharacteristicsWithdraw = -1;  /* NULL */
static int hf_gsm_map_allGPRSData = -1;           /* NULL */
static int hf_gsm_map_contextIdList = -1;         /* ContextIdList */
static int hf_gsm_map_ContextIdList_item = -1;    /* ContextId */
static int hf_gsm_map_allLSAData = -1;            /* NULL */
static int hf_gsm_map_lsaIdentityList = -1;       /* LSAIdentityList */
static int hf_gsm_map_LSAIdentityList_item = -1;  /* LSAIdentity */
static int hf_gsm_map_BasicServiceList_item = -1;  /* Ext_BasicServiceCode */
static int hf_gsm_map_o_CSI = -1;                 /* O_CSI */
static int hf_gsm_map_ss_CSI = -1;                /* SS_CSI */
static int hf_gsm_map_o_BcsmCamelTDP_CriteriaList = -1;  /* O_BcsmCamelTDPCriteriaList */
static int hf_gsm_map_tif_CSI = -1;               /* NULL */
static int hf_gsm_map_m_CSI = -1;                 /* M_CSI */
static int hf_gsm_map_vt_CSI = -1;                /* T_CSI */
static int hf_gsm_map_t_BCSM_CAMEL_TDP_CriteriaList = -1;  /* T_BCSM_CAMEL_TDP_CriteriaList */
static int hf_gsm_map_d_CSI = -1;                 /* D_CSI */
static int hf_gsm_map_MT_smsCAMELTDP_CriteriaList_item = -1;  /* MT_smsCAMELTDP_Criteria */
static int hf_gsm_map_sms_TriggerDetectionPoint = -1;  /* SMS_TriggerDetectionPoint */
static int hf_gsm_map_tpdu_TypeCriterion = -1;    /* TPDU_TypeCriterion */
static int hf_gsm_map_TPDU_TypeCriterion_item = -1;  /* MT_SMS_TPDU_Type */
static int hf_gsm_map_dp_AnalysedInfoCriteriaList = -1;  /* DP_AnalysedInfoCriteriaList */
static int hf_gsm_map_DP_AnalysedInfoCriteriaList_item = -1;  /* DP_AnalysedInfoCriterium */
static int hf_gsm_map_dialledNumber = -1;         /* ISDN_AddressString */
static int hf_gsm_map_ss_CamelData = -1;          /* SS_CamelData */
static int hf_gsm_map_ss_EventList = -1;          /* SS_EventList */
static int hf_gsm_map_mobilityTriggers = -1;      /* MobilityTriggers */
static int hf_gsm_map_BearerServiceList_item = -1;  /* Ext_BearerServiceCode */
static int hf_gsm_map_TeleserviceList_item = -1;  /* Ext_TeleserviceCode */
static int hf_gsm_map_Ext_SS_InfoList_item = -1;  /* Ext_SS_Info */
static int hf_gsm_map_ext_forwardingInfo = -1;    /* Ext_ForwInfo */
static int hf_gsm_map_ext_callBarringInfo = -1;   /* Ext_CallBarInfo */
static int hf_gsm_map_cug_Info = -1;              /* CUG_Info */
static int hf_gsm_map_ext_ss_Data = -1;           /* Ext_SS_Data */
static int hf_gsm_map_emlpp_Info = -1;            /* EMLPP_Info */
static int hf_gsm_map_ss_Code = -1;               /* SS_Code */
static int hf_gsm_map_ext_forwardingFeatureList = -1;  /* Ext_ForwFeatureList */
static int hf_gsm_map_Ext_ForwFeatureList_item = -1;  /* Ext_ForwFeature */
static int hf_gsm_map_ext_basicService = -1;      /* Ext_BasicServiceCode */
static int hf_gsm_map_ext_ss_Status = -1;         /* Ext_SS_Status */
static int hf_gsm_map_forwardedToNumber = -1;     /* ISDN_AddressString */
static int hf_gsm_map_forwardedToSubaddress = -1;  /* ISDN_SubaddressString */
static int hf_gsm_map_ext_forwardingOptions = -1;  /* T_ext_forwardingOptions */
static int hf_gsm_map_ext_noReplyConditionTime = -1;  /* Ext_NoRepCondTime */
static int hf_gsm_map_longForwardedToNumber = -1;  /* FTN_AddressString */
static int hf_gsm_map_ext_callBarringFeatureList = -1;  /* Ext_CallBarFeatureList */
static int hf_gsm_map_Ext_CallBarFeatureList_item = -1;  /* Ext_CallBarringFeature */
static int hf_gsm_map_ZoneCodeList_item = -1;     /* ZoneCode */
static int hf_gsm_map_maximumentitledPriority = -1;  /* EMLPP_Priority */
static int hf_gsm_map_defaultPriority = -1;       /* EMLPP_Priority */
static int hf_gsm_map_cug_SubscriptionList = -1;  /* CUG_SubscriptionList */
static int hf_gsm_map_cug_FeatureList = -1;       /* CUG_FeatureList */
static int hf_gsm_map_CUG_SubscriptionList_item = -1;  /* CUG_Subscription */
static int hf_gsm_map_cug_Index = -1;             /* CUG_Index */
static int hf_gsm_map_cug_Interlock = -1;         /* CUG_Interlock */
static int hf_gsm_map_intraCUG_Options = -1;      /* IntraCUG_Options */
static int hf_gsm_map_basicServiceGroupList = -1;  /* Ext_BasicServiceGroupList */
static int hf_gsm_map_CUG_FeatureList_item = -1;  /* CUG_Feature */
static int hf_gsm_map_Ext_BasicServiceGroupList_item = -1;  /* Ext_BasicServiceCode */
static int hf_gsm_map_preferentialCUG_Indicator = -1;  /* CUG_Index */
static int hf_gsm_map_interCUG_Restrictions = -1;  /* InterCUG_Restrictions */
static int hf_gsm_map_ss_SubscriptionOption = -1;  /* SS_SubscriptionOption */
static int hf_gsm_map_LCS_PrivacyExceptionList_item = -1;  /* LCS_PrivacyClass */
static int hf_gsm_map_notificationToMSUser = -1;  /* NotificationToMSUser */
static int hf_gsm_map_externalClientList = -1;    /* ExternalClientList */
static int hf_gsm_map_plmnClientList = -1;        /* PLMNClientList */
static int hf_gsm_map_ext_externalClientList = -1;  /* Ext_ExternalClientList */
static int hf_gsm_map_serviceTypeList = -1;       /* ServiceTypeList */
static int hf_gsm_map_ExternalClientList_item = -1;  /* ExternalClient */
static int hf_gsm_map_PLMNClientList_item = -1;   /* LCSClientInternalID */
static int hf_gsm_map_Ext_ExternalClientList_item = -1;  /* ExternalClient */
static int hf_gsm_map_clientIdentity = -1;        /* LCSClientExternalID */
static int hf_gsm_map_gmlc_Restriction = -1;      /* GMLC_Restriction */
static int hf_gsm_map_ServiceTypeList_item = -1;  /* ServiceType */
static int hf_gsm_map_serviceTypeIdentity = -1;   /* LCSServiceTypeID */
static int hf_gsm_map_MOLR_List_item = -1;        /* MOLR_Class */
static int hf_gsm_map_CallBarringFeatureList_item = -1;  /* CallBarringFeature */
static int hf_gsm_map_basicService = -1;          /* BasicServiceCode */
static int hf_gsm_map_ss_Status = -1;             /* SS_Status */
static int hf_gsm_map_ForwardingFeatureList_item = -1;  /* ForwardingFeature */
static int hf_gsm_map_forwardingOptions = -1;     /* ForwardingOptions */
static int hf_gsm_map_noReplyConditionTime = -1;  /* NoReplyConditionTime */
static int hf_gsm_map_matchType = -1;             /* MatchType */
static int hf_gsm_map_destinationNumberList = -1;  /* DestinationNumberList */
static int hf_gsm_map_destinationNumberLengthList = -1;  /* DestinationNumberLengthList */
static int hf_gsm_map_DestinationNumberList_item = -1;  /* ISDN_AddressString */
static int hf_gsm_map_DestinationNumberLengthList_item = -1;  /* INTEGER_1_15 */
static int hf_gsm_map_forwardingFeatureList = -1;  /* ForwardingFeatureList */
static int hf_gsm_map_callBarringFeatureList = -1;  /* CallBarringFeatureList */
static int hf_gsm_map_nbrSB = -1;                 /* MaxMC_Bearers */
static int hf_gsm_map_nbrUser = -1;               /* MC_Bearers */
static int hf_gsm_map_hlr_List = -1;              /* HLR_List */
static int hf_gsm_map_msNotReachable = -1;        /* NULL */
static int hf_gsm_map_VBSDataList_item = -1;      /* VoiceBroadcastData */
static int hf_gsm_map_VGCSDataList_item = -1;     /* VoiceGroupCallData */
static int hf_gsm_map_groupId = -1;               /* GroupId */
static int hf_gsm_map_groupid = -1;               /* GroupId */
static int hf_gsm_map_broadcastInitEntitlement = -1;  /* NULL */
static int hf_gsm_map_traceReference = -1;        /* OCTET_STRING_SIZE_1_2 */
static int hf_gsm_map_traceType = -1;             /* INTEGER_0_255 */
static int hf_gsm_map_omc_Id = -1;                /* OCTET_STRING_SIZE_1_20 */
static int hf_gsm_map_cug_CheckInfo = -1;         /* CUG_CheckInfo */
static int hf_gsm_map_numberOfForwarding = -1;    /* NumberOfForwarding */
static int hf_gsm_map_interrogationType = -1;     /* InterrogationType */
static int hf_gsm_map_or_Interrogation = -1;      /* NULL */
static int hf_gsm_map_or_Capability = -1;         /* OR_Phase */
static int hf_gsm_map_gmsc_OrGsmSCF_Address = -1;  /* ISDN_AddressString */
static int hf_gsm_map_callReferenceNumber = -1;   /* CallReferenceNumber */
static int hf_gsm_map_forwardingReason = -1;      /* ForwardingReason */
static int hf_gsm_map_ext_basicServiceGroup = -1;  /* Ext_BasicServiceCode */
static int hf_gsm_map_networkSignalInfo = -1;     /* ExternalSignalInfo */
static int hf_gsm_map_camelInfo = -1;             /* CamelInfo */
static int hf_gsm_map_suppressionOfAnnouncement = -1;  /* SuppressionOfAnnouncement */
static int hf_gsm_map_alertingPattern = -1;       /* AlertingPattern */
static int hf_gsm_map_ccbs_Call = -1;             /* NULL */
static int hf_gsm_map_supportedCCBS_Phase = -1;   /* SupportedCCBS_Phase */
static int hf_gsm_map_additionalSignalInfo = -1;  /* Ext_ExternalSignalInfo */
static int hf_gsm_map_pre_pagingSupported = -1;   /* NULL */
static int hf_gsm_map_callDiversionTreatmentIndicator = -1;  /* CallDiversionTreatmentIndicator */
static int hf_gsm_map_suppress_VT_CSI = -1;       /* NULL */
static int hf_gsm_map_suppressIncomingCallBarring = -1;  /* NULL */
static int hf_gsm_map_gsmSCF_InitiatedCall = -1;  /* NULL */
static int hf_gsm_map_basicServiceGroup2 = -1;    /* Ext_BasicServiceCode */
static int hf_gsm_map_networkSignalInfo2 = -1;    /* ExternalSignalInfo */
static int hf_gsm_map_extendedRoutingInfo = -1;   /* ExtendedRoutingInfo */
static int hf_gsm_map_cugSubscriptionFlag = -1;   /* NULL */
static int hf_gsm_map_subscriberInfo = -1;        /* SubscriberInfo */
static int hf_gsm_map_forwardingInterrogationRequired = -1;  /* NULL */
static int hf_gsm_map_vmsc_Address = -1;          /* ISDN_AddressString */
static int hf_gsm_map_ccbs_Indicators = -1;       /* CCBS_Indicators */
static int hf_gsm_map_numberPortabilityStatus = -1;  /* NumberPortabilityStatus */
static int hf_gsm_map_supportedCamelPhasesInVMSC = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_offeredCamel4CSIsInVMSC = -1;  /* OfferedCamel4CSIs */
static int hf_gsm_map_routingInfo2 = -1;          /* RoutingInfo */
static int hf_gsm_map_ss_List2 = -1;              /* SS_List */
static int hf_gsm_map_basicService2 = -1;         /* Ext_BasicServiceCode */
static int hf_gsm_map_allowedServices = -1;       /* AllowedServices */
static int hf_gsm_map_unavailabilityCause = -1;   /* UnavailabilityCause */
static int hf_gsm_map_releaseResourcesSupported = -1;  /* NULL */
static int hf_gsm_map_ext_ProtocolId = -1;        /* Ext_ProtocolId */
static int hf_gsm_map_accessNetworkProtocolId = -1;  /* AccessNetworkProtocolId */
static int hf_gsm_map_longsignalInfo = -1;        /* LongSignalInfo */
static int hf_gsm_map_suppress_T_CSI = -1;        /* NULL */
static int hf_gsm_map_HLR_List_item = -1;         /* HLR_Id */
static int hf_gsm_map_SS_List_item = -1;          /* SS_Code */
static int hf_gsm_map_naea_PreferredCIC = -1;     /* NAEA_CIC */
static int hf_gsm_map_externalAddress = -1;       /* ISDN_AddressString */
static int hf_gsm_map_cellGlobalIdOrServiceAreaIdFixedLength = -1;  /* CellGlobalIdOrServiceAreaIdFixedLength */
static int hf_gsm_map_laiFixedLength = -1;        /* LAIFixedLength */
static int hf_gsm_map_ccbs_Possible = -1;         /* NULL */
static int hf_gsm_map_keepCCBS_CallIndicator = -1;  /* NULL */
static int hf_gsm_map_roamingNumber = -1;         /* ISDN_AddressString */
static int hf_gsm_map_forwardingData = -1;        /* ForwardingData */
static int hf_gsm_map_routingInfo = -1;           /* RoutingInfo */
static int hf_gsm_map_camelRoutingInfo = -1;      /* CamelRoutingInfo */
static int hf_gsm_map_gmscCamelSubscriptionInfo = -1;  /* GmscCamelSubscriptionInfo */
static int hf_gsm_map_t_CSI = -1;                 /* T_CSI */
static int hf_gsm_map_d_csi = -1;                 /* D_CSI */
static int hf_gsm_map_ageOfLocationInformation = -1;  /* AgeOfLocationInformation */
static int hf_gsm_map_geographicalInformation = -1;  /* GeographicalInformation */
static int hf_gsm_map_vlr_number = -1;            /* ISDN_AddressString */
static int hf_gsm_map_locationNumber = -1;        /* LocationNumber */
static int hf_gsm_map_cellGlobalIdOrServiceAreaIdOrLAI = -1;  /* CellGlobalIdOrServiceAreaIdOrLAI */
static int hf_gsm_map_selectedLSA_Id = -1;        /* LSAIdentity */
static int hf_gsm_map_geodeticInformation = -1;   /* GeodeticInformation */
static int hf_gsm_map_currentLocationRetrieved = -1;  /* NULL */
static int hf_gsm_map_sai_Present = -1;           /* NULL */
static int hf_gsm_map_routeingAreaIdentity = -1;  /* RAIdentity */
static int hf_gsm_map_selectedLSAIdentity = -1;   /* LSAIdentity */
static int hf_gsm_map_assumedIdle = -1;           /* NULL */
static int hf_gsm_map_camelBusy = -1;             /* NULL */
static int hf_gsm_map_notProvidedFromVLR = -1;    /* NULL */
static int hf_gsm_map_notProvidedFromSGSN = -1;   /* NULL */
static int hf_gsm_map_ps_Detached = -1;           /* NULL */
static int hf_gsm_map_ps_AttachedNotReachableForPaging = -1;  /* NULL */
static int hf_gsm_map_ps_AttachedReachableForPaging = -1;  /* NULL */
static int hf_gsm_map_ps_PDP_ActiveNotReachableForPaging = -1;  /* PDP_ContextInfoList */
static int hf_gsm_map_ps_PDP_ActiveReachableForPaging = -1;  /* PDP_ContextInfoList */
static int hf_gsm_map_netDetNotReachable = -1;    /* NotReachableReason */
static int hf_gsm_map_PDP_ContextInfoList_item = -1;  /* PDP_ContextInfo */
static int hf_gsm_map_pdp_ContextIdentifier = -1;  /* ContextId */
static int hf_gsm_map_pdp_ContextActive = -1;     /* NULL */
static int hf_gsm_map_apn_Subscribed = -1;        /* APN */
static int hf_gsm_map_apn_InUse = -1;             /* APN */
static int hf_gsm_map_nsapi = -1;                 /* NSAPI */
static int hf_gsm_map_transactionId = -1;         /* TransactionId */
static int hf_gsm_map_teid_ForGnAndGp = -1;       /* TEID */
static int hf_gsm_map_teid_ForIu = -1;            /* TEID */
static int hf_gsm_map_ggsn_Address = -1;          /* GSN_Address */
static int hf_gsm_map_ext_qos_Subscribed = -1;    /* Ext_QoS_Subscribed */
static int hf_gsm_map_qos_Requested = -1;         /* Ext_QoS_Subscribed */
static int hf_gsm_map_qos_Negotiated = -1;        /* Ext_QoS_Subscribed */
static int hf_gsm_map_chargingId = -1;            /* GPRSChargingID */
static int hf_gsm_map_rnc_Address = -1;           /* GSN_Address */
static int hf_gsm_map_qos2_Subscribed = -1;       /* Ext2_QoS_Subscribed */
static int hf_gsm_map_qos2_Requested = -1;        /* Ext2_QoS_Subscribed */
static int hf_gsm_map_qos2_Negotiated = -1;       /* Ext2_QoS_Subscribed */
static int hf_gsm_map_cug_OutgoingAccess = -1;    /* NULL */
static int hf_gsm_map_gsm_BearerCapability = -1;  /* ExternalSignalInfo */
static int hf_gsm_map_gmsc_Address = -1;          /* ISDN_AddressString */
static int hf_gsm_map_supportedCamelPhasesInInterrogatingNode = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_orNotSupportedInGMSC = -1;  /* NULL */
static int hf_gsm_map_offeredCamel4CSIsInInterrogatingNode = -1;  /* OfferedCamel4CSIs */
static int hf_gsm_map_uu_Data = -1;               /* UU_Data */
static int hf_gsm_map_allInformationSent = -1;    /* NULL */
static int hf_gsm_map_o_BcsmCamelTDPCriteriaList = -1;  /* O_BcsmCamelTDPCriteriaList */
static int hf_gsm_map_uuIndicator = -1;           /* UUIndicator */
static int hf_gsm_map_uui = -1;                   /* UUI */
static int hf_gsm_map_uusCFInteraction = -1;      /* NULL */
static int hf_gsm_map_isdn_BearerCapability = -1;  /* ExternalSignalInfo */
static int hf_gsm_map_call_Direction = -1;        /* CallDirection */
static int hf_gsm_map_b_Subscriber_Address = -1;  /* ISDN_AddressString */
static int hf_gsm_map_chosenChannel = -1;         /* ExternalSignalInfo */
static int hf_gsm_map_lowerLayerCompatibility = -1;  /* ExternalSignalInfo */
static int hf_gsm_map_highLayerCompatibility = -1;  /* ExternalSignalInfo */
static int hf_gsm_map_sIWFSNumber = -1;           /* ISDN_AddressString */
static int hf_gsm_map_channelType = -1;           /* ExternalSignalInfo */
static int hf_gsm_map_ccbs_Monitoring = -1;       /* ReportingState */
static int hf_gsm_map_ccbs_SubscriberStatus = -1;  /* CCBS_SubscriberStatus */
static int hf_gsm_map_eventReportData = -1;       /* EventReportData */
static int hf_gsm_map_callReportdata = -1;        /* CallReportData */
static int hf_gsm_map_monitoringMode = -1;        /* MonitoringMode */
static int hf_gsm_map_callOutcome = -1;           /* CallOutcome */
static int hf_gsm_map_callTerminationIndicator = -1;  /* CallTerminationIndicator */
static int hf_gsm_map_msrn = -1;                  /* ISDN_AddressString */
static int hf_gsm_map_callInfo = -1;              /* ExternalSignalInfo */
static int hf_gsm_map_ccbs_Feature = -1;          /* CCBS_Feature */
static int hf_gsm_map_translatedB_Number = -1;    /* ISDN_AddressString */
static int hf_gsm_map_replaceB_Number = -1;       /* NULL */
static int hf_gsm_map_ruf_Outcome = -1;           /* Ruf_Outcome */
static int hf_gsm_map_ext_basicServiceGroupList = -1;  /* BasicServiceGroupList */
static int hf_gsm_map_cliRestrictionOption = -1;  /* CliRestrictionOption */
static int hf_gsm_map_overrideCategory = -1;      /* OverrideCategory */
static int hf_gsm_map_forwardedToNumber_addr = -1;  /* AddressString */
static int hf_gsm_map_forwardingInfo = -1;        /* ForwardingInfo */
static int hf_gsm_map_callBarringInfo = -1;       /* CallBarringInfo */
static int hf_gsm_map_ss_Data = -1;               /* SS_Data */
static int hf_gsm_map_genericServiceInfo = -1;    /* GenericServiceInfo */
static int hf_gsm_map_ussd_DataCodingScheme = -1;  /* USSD_DataCodingScheme */
static int hf_gsm_map_ussd_String = -1;           /* USSD_String */
static int hf_gsm_map_failureCause = -1;          /* FailureCause */
static int hf_gsm_map_re_attempt = -1;            /* BOOLEAN */
static int hf_gsm_map_accessType = -1;            /* AccessType */
static int hf_gsm_map_ccbs_Data = -1;             /* CCBS_Data */
static int hf_gsm_map_serviceIndicator = -1;      /* ServiceIndicator */
static int hf_gsm_map_ccbs_Index = -1;            /* CCBS_Index */
static int hf_gsm_map_sm_RP_PRI = -1;             /* BOOLEAN */
static int hf_gsm_map_serviceCentreAddress = -1;  /* ServiceCentreAddress */
static int hf_gsm_map_gprsSupportIndicator = -1;  /* NULL */
static int hf_gsm_map_sm_RP_MTI = -1;             /* INTEGER_0_10 */
static int hf_gsm_map_sm_RP_SMEA = -1;            /* OCTET_STRING_SIZE_1_12 */
static int hf_gsm_map_locationInfoWithLMSI = -1;  /* LocationInfoWithLMSI */
static int hf_gsm_map_networkNode_Number = -1;    /* ISDN_AddressString */
static int hf_gsm_map_gprsNodeIndicator = -1;     /* NULL */
static int hf_gsm_map_additional_Number = -1;     /* Additional_Number */
static int hf_gsm_map_sm_RP_DA = -1;              /* Sm_RP_DA */
static int hf_gsm_map_sm_RP_OA = -1;              /* Sm_RP_OA */
static int hf_gsm_map_sm_RP_UI = -1;              /* Sm_RP_UI */
static int hf_gsm_map_serviceCentreAddressOA = -1;  /* ServiceCentreAddress */
static int hf_gsm_map_noSM_RP_OA = -1;            /* NULL */
static int hf_gsm_map_serviceCentreAddressDA = -1;  /* ServiceCentreAddress */
static int hf_gsm_map_noSM_RP_DA = -1;            /* NULL */
static int hf_gsm_map_moreMessagesToSend = -1;    /* NULL */
static int hf_gsm_map_sm_DeliveryOutcome = -1;    /* Sm_DeliveryOutcome */
static int hf_gsm_map_absentSubscriberDiagnosticSM = -1;  /* AbsentSubscriberDiagnosticSM */
static int hf_gsm_map_deliveryOutcomeIndicator = -1;  /* NULL */
static int hf_gsm_map_additionalSM_DeliveryOutcome = -1;  /* Sm_DeliveryOutcome */
static int hf_gsm_map_additionalAbsentSubscriberDiagnosticSM = -1;  /* AbsentSubscriberDiagnosticSM */
static int hf_gsm_map_storedMSISDN = -1;          /* StoredMSISDN */
static int hf_gsm_map_mw_Status = -1;             /* T_mw_Status */
static int hf_gsm_map_alertReason = -1;           /* T_alertReason */
static int hf_gsm_map_alertReasonIndicator = -1;  /* NULL */
static int hf_gsm_map_requestedInfo = -1;         /* RequestedInfo */
static int hf_gsm_map_locationInformation = -1;   /* LocationInformation */
static int hf_gsm_map_subscriberState = -1;       /* SubscriberState */
static int hf_gsm_map_locationInformationGPRS = -1;  /* LocationInformationGPRS */
static int hf_gsm_map_ps_SubscriberState = -1;    /* PS_SubscriberState */
static int hf_gsm_map_ms_Classmark2 = -1;         /* MS_Classmark2 */
static int hf_gsm_map_gprs_MS_Class = -1;         /* GPRSMSClass */
static int hf_gsm_map_mnpInfoRes = -1;            /* MNPInfoRes */
static int hf_gsm_map_routeingNumber = -1;        /* RouteingNumber */
static int hf_gsm_map_mSNetworkCapability = -1;   /* MSNetworkCapability */
static int hf_gsm_map_mSRadioAccessCapability = -1;  /* MSRadioAccessCapability */
static int hf_gsm_map_locationInformation_flg = -1;  /* NULL */
static int hf_gsm_map_subscriberState_flg = -1;   /* NULL */
static int hf_gsm_map_currentLocation = -1;       /* NULL */
static int hf_gsm_map_requestedDomain = -1;       /* T_requestedDomain */
static int hf_gsm_map_imei_flg = -1;              /* NULL */
static int hf_gsm_map_ms_classmark = -1;          /* NULL */
static int hf_gsm_map_mnpRequestedInfo = -1;      /* NULL */
static int hf_gsm_map_subscriberIdentity = -1;    /* SubscriberIdentity */
static int hf_gsm_map_requestedSubscriptionInfo = -1;  /* RequestedSubscriptionInfo */
static int hf_gsm_map_callForwardingData = -1;    /* CallForwardingData */
static int hf_gsm_map_callBarringData = -1;       /* CallBarringData */
static int hf_gsm_map_odb_Info = -1;              /* ODB_Info */
static int hf_gsm_map_camel_SubscriptionInfo = -1;  /* CAMEL_SubscriptionInfo */
static int hf_gsm_map_supportedVLR_CAMEL_Phases = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_supportedSGSN_CAMEL_Phases = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_offeredCamel4CSIsInVLR = -1;  /* OfferedCamel4CSIs */
static int hf_gsm_map_offeredCamel4CSIsInSGSN = -1;  /* OfferedCamel4CSIs */
static int hf_gsm_map_requestedSS_Info = -1;      /* SS_ForBS_Code */
static int hf_gsm_map_odb = -1;                   /* NULL */
static int hf_gsm_map_requestedCAMEL_SubscriptionInfo = -1;  /* RequestedCAMEL_SubscriptionInfo */
static int hf_gsm_map_supportedVLR_CAMEL_Phases_flg = -1;  /* NULL */
static int hf_gsm_map_supportedSGSN_CAMEL_Phases_flg = -1;  /* NULL */
static int hf_gsm_map_additionalRequestedCAMEL_SubscriptionInfo = -1;  /* AdditionalRequestedCAMEL_SubscriptionInfo */
static int hf_gsm_map_password = -1;              /* Password */
static int hf_gsm_map_wrongPasswordAttemptsCounter = -1;  /* WrongPasswordAttemptsCounter */
static int hf_gsm_map_bearerService = -1;         /* BearerServiceCode */
static int hf_gsm_map_teleservice_code = -1;      /* TeleserviceCode */
static int hf_gsm_map_O_BcsmCamelTDPCriteriaList_item = -1;  /* O_BcsmCamelTDP_Criteria */
static int hf_gsm_map_T_BCSM_CAMEL_TDP_CriteriaList_item = -1;  /* T_BCSM_CAMEL_TDP_Criteria */
static int hf_gsm_map_destinationNumberCriteria = -1;  /* DestinationNumberCriteria */
static int hf_gsm_map_basicServiceCriteria = -1;  /* BasicServiceCriteria */
static int hf_gsm_map_callTypeCriteria = -1;      /* CallTypeCriteria */
static int hf_gsm_map_o_CauseValueCriteria = -1;  /* O_CauseValueCriteria */
static int hf_gsm_map_t_BCSM_TriggerDetectionPoint = -1;  /* T_BcsmTriggerDetectionPoint */
static int hf_gsm_map_t_CauseValueCriteria = -1;  /* T_CauseValueCriteria */
static int hf_gsm_map_maximumEntitledPriority = -1;  /* EMLPP_Priority */
static int hf_gsm_map_ccbs_FeatureList = -1;      /* CCBS_FeatureList */
static int hf_gsm_map_nbrSN = -1;                 /* MC_Bearers */
static int hf_gsm_map_CCBS_FeatureList_item = -1;  /* CCBS_Feature */
static int hf_gsm_map_b_subscriberNumber = -1;    /* ISDN_AddressString */
static int hf_gsm_map_b_subscriberSubaddress = -1;  /* ISDN_SubaddressString */
static int hf_gsm_map_basicServiceGroup = -1;     /* BasicServiceCode */
static int hf_gsm_map_T_CauseValueCriteria_item = -1;  /* CauseValue */
static int hf_gsm_map_O_CauseValueCriteria_item = -1;  /* CauseValue */
static int hf_gsm_map_BasicServiceCriteria_item = -1;  /* Ext_BasicServiceCode */
static int hf_gsm_map_modificationRequestFor_CF_Info = -1;  /* ModificationRequestFor_CF_Info */
static int hf_gsm_map_modificationRequestFor_CB_Info = -1;  /* ModificationRequestFor_CB_Info */
static int hf_gsm_map_modificationRequestFor_CSI = -1;  /* ModificationRequestFor_CSI */
static int hf_gsm_map_modificationRequestFor_ODB_data = -1;  /* ModificationRequestFor_ODB_data */
static int hf_gsm_map_ss_InfoFor_CSE = -1;        /* Ext_SS_InfoFor_CSE */
static int hf_gsm_map_modifyNotificationToCSE = -1;  /* ModificationInstruction */
static int hf_gsm_map_odb_data = -1;              /* ODB_Data */
static int hf_gsm_map_requestedCamel_SubscriptionInfo = -1;  /* RequestedCAMEL_SubscriptionInfo */
static int hf_gsm_map_modifyCSI_State = -1;       /* ModificationInstruction */
static int hf_gsm_map_forwardingInfoFor_CSE = -1;  /* Ext_ForwardingInfoFor_CSE */
static int hf_gsm_map_callBarringInfoFor_CSE = -1;  /* Ext_CallBarringInfoFor_CSE */
static int hf_gsm_map_eventMet = -1;              /* MM_Code */
static int hf_gsm_map_supportedCAMELPhases = -1;  /* SupportedCamelPhases */
static int hf_gsm_map_offeredCamel4Functionalities = -1;  /* OfferedCamel4Functionalities */
static int hf_gsm_map_vt_BCSM_CAMEL_TDP_CriteriaList = -1;  /* T_BCSM_CAMEL_TDP_CriteriaList */
static int hf_gsm_map_tif_CSI_NotificationToCSE = -1;  /* NULL */
static int hf_gsm_map_specificCSIDeletedList = -1;  /* SpecificCSI_Withdraw */
static int hf_gsm_map_o_IM_CSI = -1;              /* O_CSI */
static int hf_gsm_map_o_IM_BcsmCamelTDP_CriteriaList = -1;  /* O_BcsmCamelTDPCriteriaList */
static int hf_gsm_map_d_IM_CSI = -1;              /* D_CSI */
static int hf_gsm_map_vt_IM_CSI = -1;             /* T_CSI */
static int hf_gsm_map_vt_IM_BCSM_CAMEL_TDP_CriteriaList = -1;  /* T_BCSM_CAMEL_TDP_CriteriaList */
static int hf_gsm_map_ext_BearerService = -1;     /* Ext_BearerServiceCode */
static int hf_gsm_map_ext_Teleservice = -1;       /* Ext_TeleserviceCode */
static int hf_gsm_map_odb_HPLMN_Data = -1;        /* ODB_HPLMN_Data */
static int hf_gsm_map_SS_EventList_item = -1;     /* SS_Code */
static int hf_gsm_map_t_BcsmCamelTDPDataList = -1;  /* T_BcsmCamelTDPDataList */
static int hf_gsm_map_T_BcsmCamelTDPDataList_item = -1;  /* T_BcsmCamelTDPData */
static int hf_gsm_map_t_BcsmTriggerDetectionPoint = -1;  /* T_BcsmTriggerDetectionPoint */
static int hf_gsm_map_sms_CAMEL_TDP_DataList = -1;  /* SMS_CAMEL_TDP_DataList */
static int hf_gsm_map_SMS_CAMEL_TDP_DataList_item = -1;  /* SMS_CAMEL_TDP_Data */
static int hf_gsm_map_defaultSMS_Handling = -1;   /* DefaultSMS_Handling */
static int hf_gsm_map_MobilityTriggers_item = -1;  /* MM_Code */
static int hf_gsm_map_ss_Event = -1;              /* OCTET_STRING_SIZE_1 */
static int hf_gsm_map_ss_EventSpecification = -1;  /* T_ss_EventSpecification */
static int hf_gsm_map_ss_EventSpecification_item = -1;  /* OCTET_STRING_SIZE_1_20 */
static int hf_gsm_map_ext_teleservice = -1;       /* Ext_TeleserviceCode */
static int hf_gsm_map_codec_Info = -1;            /* CODEC_Info */
static int hf_gsm_map_cipheringAlgorithm = -1;    /* CipheringAlgorithm */
static int hf_gsm_map_groupKeyNumber_Vk_Id = -1;  /* GroupKeyNumber */
static int hf_gsm_map_groupKey = -1;              /* Kc */
static int hf_gsm_map_priority = -1;              /* EMLPP_Priority */
static int hf_gsm_map_uplinkFree = -1;            /* NULL */
static int hf_gsm_map_vstk = -1;                  /* VSTK */
static int hf_gsm_map_vstk_rand = -1;             /* VSTK_RAND */
static int hf_gsm_map_groupCallNumber = -1;       /* ISDN_AddressString */
static int hf_gsm_map_uplinkRequest = -1;         /* NULL */
static int hf_gsm_map_uplinkReleaseIndication = -1;  /* NULL */
static int hf_gsm_map_releaseGroupCall = -1;      /* NULL */
static int hf_gsm_map_uplinkRequestAck = -1;      /* NULL */
static int hf_gsm_map_uplinkRejectCommand = -1;   /* NULL */
static int hf_gsm_map_uplinkSeizedCommand = -1;   /* NULL */
static int hf_gsm_map_uplinkReleaseCommand = -1;  /* NULL */
static int hf_gsm_map_sgsn_Address = -1;          /* GSN_Address */
static int hf_gsm_map_sgsn_Capability = -1;       /* SGSN_Capability */
static int hf_gsm_map_ps_LCS_NotSupportedByUE = -1;  /* NULL */
static int hf_gsm_map_gprsEnhancementsSupportIndicator = -1;  /* NULL */
static int hf_gsm_map_smsCallBarringSupportIndicator = -1;  /* NULL */
static int hf_gsm_map_ggsn_Number = -1;           /* ISDN_AddressString */
static int hf_gsm_map_mobileNotReachableReason = -1;  /* AbsentSubscriberDiagnosticSM */
static int hf_gsm_map_locationType = -1;          /* LocationType */
static int hf_gsm_map_mlc_Number = -1;            /* ISDN_AddressString */
static int hf_gsm_map_lcs_ClientID = -1;          /* LCS_ClientID */
static int hf_gsm_map_privacyOverride = -1;       /* NULL */
static int hf_gsm_map_lcs_Priority = -1;          /* LCS_Priority */
static int hf_gsm_map_lcs_QoS = -1;               /* LCS_QoS */
static int hf_gsm_map_supportedGADShapes = -1;    /* SupportedGADShapes */
static int hf_gsm_map_lcs_ReferenceNumber = -1;   /* LCS_ReferenceNumber */
static int hf_gsm_map_lcsServiceTypeID = -1;      /* LCSServiceTypeID */
static int hf_gsm_map_lcsCodeword = -1;           /* LCSCodeword */
static int hf_gsm_map_lcs_PrivacyCheck = -1;      /* LCS_PrivacyCheck */
static int hf_gsm_map_areaEventInfo = -1;         /* AreaEventInfo */
static int hf_gsm_map_h_gmlc_Address = -1;        /* GSN_Address */
static int hf_gsm_map_locationEstimateType = -1;  /* LocationEstimateType */
static int hf_gsm_map_deferredLocationEventType = -1;  /* DeferredLocationEventType */
static int hf_gsm_map_lcsClientType = -1;         /* LCSClientType */
static int hf_gsm_map_lcsClientExternalID = -1;   /* LCSClientExternalID */
static int hf_gsm_map_lcsClientDialedByMS = -1;   /* AddressString */
static int hf_gsm_map_lcsClientInternalID = -1;   /* LCSClientInternalID */
static int hf_gsm_map_lcsClientName = -1;         /* LCSClientName */
static int hf_gsm_map_lcsAPN = -1;                /* APN */
static int hf_gsm_map_lcsRequestorID = -1;        /* LCSRequestorID */
static int hf_gsm_map_dataCodingScheme = -1;      /* USSD_DataCodingScheme */
static int hf_gsm_map_nameString = -1;            /* NameString */
static int hf_gsm_map_lcs_FormatIndicator = -1;   /* LCS_FormatIndicator */
static int hf_gsm_map_requestorIDString = -1;     /* RequestorIDString */
static int hf_gsm_map_horizontal_accuracy = -1;   /* Horizontal_Accuracy */
static int hf_gsm_map_verticalCoordinateRequest = -1;  /* NULL */
static int hf_gsm_map_vertical_accuracy = -1;     /* Vertical_Accuracy */
static int hf_gsm_map_responseTime = -1;          /* ResponseTime */
static int hf_gsm_map_responseTimeCategory = -1;  /* ResponseTimeCategory */
static int hf_gsm_map_lcsCodewordString = -1;     /* LCSCodewordString */
static int hf_gsm_map_callSessionUnrelated = -1;  /* PrivacyCheckRelatedAction */
static int hf_gsm_map_callSessionRelated = -1;    /* PrivacyCheckRelatedAction */
static int hf_gsm_map_areaDefinition = -1;        /* AreaDefinition */
static int hf_gsm_map_occurrenceInfo = -1;        /* OccurrenceInfo */
static int hf_gsm_map_intervalTime = -1;          /* IntervalTime */
static int hf_gsm_map_areaList = -1;              /* AreaList */
static int hf_gsm_map_AreaList_item = -1;         /* Area */
static int hf_gsm_map_areaType = -1;              /* AreaType */
static int hf_gsm_map_areaIdentification = -1;    /* AreaIdentification */
static int hf_gsm_map_locationEstimate = -1;      /* Ext_GeographicalInformation */
static int hf_gsm_map_ageOfLocationEstimate = -1;  /* AgeOfLocationInformation */
static int hf_gsm_map_add_LocationEstimate = -1;  /* Add_GeographicalInformation */
static int hf_gsm_map_deferredmt_lrResponseIndicator = -1;  /* NULL */
static int hf_gsm_map_geranPositioningData = -1;  /* PositioningDataInformation */
static int hf_gsm_map_utranPositioningData = -1;  /* UtranPositioningDataInfo */
static int hf_gsm_map_cellIdOrSai = -1;           /* CellGlobalIdOrServiceAreaIdOrLAI */
static int hf_gsm_map_mlcNumber = -1;             /* ISDN_AddressString */
static int hf_gsm_map_targetMS = -1;              /* SubscriberIdentity */
static int hf_gsm_map_lcsLocationInfo = -1;       /* LCSLocationInfo */
static int hf_gsm_map_ppr_Address = -1;           /* GSN_Address */
static int hf_gsm_map_additional_v_gmlc_Address = -1;  /* GSN_Address */
static int hf_gsm_map_additional_LCS_CapabilitySets = -1;  /* SupportedLCS_CapabilitySets */
static int hf_gsm_map_lcs_Event = -1;             /* LCS_Event */
static int hf_gsm_map_na_ESRD = -1;               /* ISDN_AddressString */
static int hf_gsm_map_na_ESRK = -1;               /* ISDN_AddressString */
static int hf_gsm_map_slr_ArgExtensionContainer = -1;  /* SLR_ArgExtensionContainer */
static int hf_gsm_map_deferredmt_lrData = -1;     /* Deferredmt_lrData */
static int hf_gsm_map_pseudonymIndicator = -1;    /* NULL */
static int hf_gsm_map_terminationCause = -1;      /* TerminationCause */
static int hf_gsm_map_securityHeader = -1;        /* SecurityHeader */
static int hf_gsm_map_protectedPayload = -1;      /* ProtectedPayload */
static int hf_gsm_map_securityParametersIndex = -1;  /* SecurityParametersIndex */
static int hf_gsm_map_originalComponentIdentifier = -1;  /* OriginalComponentIdentifier */
static int hf_gsm_map_initialisationVector = -1;  /* InitialisationVector */
static int hf_gsm_map_operationCode = -1;         /* OperationCode */
static int hf_gsm_map_errorCode = -1;             /* ErrorCode */
static int hf_gsm_map_userInfo = -1;              /* NULL */
static int hf_gsm_map_localValue = -1;            /* INTEGER */
static int hf_gsm_map_networkResource = -1;       /* NetworkResource */
static int hf_gsm_map_extensibleSystemFailureParam = -1;  /* T_extensibleSystemFailureParam */
static int hf_gsm_map_unknownSubscriberDiagnostic = -1;  /* T_unknownSubscriberDiagnostic */
static int hf_gsm_map_roamingNotAllowedCause = -1;  /* T_roamingNotAllowedCause */
static int hf_gsm_map_absentSubscriberReason = -1;  /* AbsentSubscriberReason */
static int hf_gsm_map_ccbs_Busy = -1;             /* NULL */
static int hf_gsm_map_gprsConnectionSuspended = -1;  /* NULL */
static int hf_gsm_map_callBarringCause = -1;      /* CallBarringCause */
static int hf_gsm_map_extensibleCallBarredParam = -1;  /* ExtensibleCallBarredParam */
static int hf_gsm_map_unauthorisedMessageOriginator = -1;  /* NULL */
static int hf_gsm_map_cug_RejectCause = -1;       /* CUG_RejectCause */
static int hf_gsm_map_sm_EnumeratedDeliveryFailureCause = -1;  /* SM_EnumeratedDeliveryFailureCause */
static int hf_gsm_map_diagnosticInfo = -1;        /* SignalInfo */
static int hf_gsm_map_unauthorizedLCSClient_Diagnostic = -1;  /* T_unauthorizedLCSClient_Diagnostic */
static int hf_gsm_map_positionMethodFailure_Diagnostic = -1;  /* PositionMethodFailure_Diagnostic */
static int hf_gsm_map_pcsExtensions = -1;         /* PcsExtensions */
static int hf_gsm_map_access = -1;                /* Access */
static int hf_gsm_map_version = -1;               /* Version */
/* named bits */
static int hf_gsm_map_SupportedCamelPhases_phase1 = -1;
static int hf_gsm_map_SupportedCamelPhases_phase2 = -1;
static int hf_gsm_map_SupportedCamelPhases_phase3 = -1;
static int hf_gsm_map_SupportedCamelPhases_phase4 = -1;
static int hf_gsm_map_SupportedLCS_CapabilitySets_lcsCapabilitySet1 = -1;
static int hf_gsm_map_SupportedLCS_CapabilitySets_lcsCapabilitySet2 = -1;
static int hf_gsm_map_SupportedLCS_CapabilitySets_lcsCapabilitySet3 = -1;
static int hf_gsm_map_SupportedLCS_CapabilitySets_lcsCapabilitySet4 = -1;
static int hf_gsm_map_RequestedEquipmentInfo_equipmentStatus = -1;
static int hf_gsm_map_RequestedEquipmentInfo_bmuef = -1;
static int hf_gsm_map_ODB_GeneralData_allOG_CallsBarred = -1;
static int hf_gsm_map_ODB_GeneralData_internationalOGCallsBarred = -1;
static int hf_gsm_map_ODB_GeneralData_internationalOGCallsNotToHPLMN_CountryBarred = -1;
static int hf_gsm_map_ODB_GeneralData_interzonalOGCallsBarred = -1;
static int hf_gsm_map_ODB_GeneralData_interzonalOGCallsNotToHPLMN_CountryBarred = -1;
static int hf_gsm_map_ODB_GeneralData_interzonalOGCallsAndInternationalOGCallsNotToHPLMN_CountryBarred = -1;
static int hf_gsm_map_ODB_GeneralData_premiumRateInformationOGCallsBarred = -1;
static int hf_gsm_map_ODB_GeneralData_premiumRateEntertainementOGCallsBarred = -1;
static int hf_gsm_map_ODB_GeneralData_ss_AccessBarred = -1;
static int hf_gsm_map_ODB_GeneralData_allECT_Barred = -1;
static int hf_gsm_map_ODB_GeneralData_chargeableECT_Barred = -1;
static int hf_gsm_map_ODB_GeneralData_internationalECT_Barred = -1;
static int hf_gsm_map_ODB_GeneralData_interzonalECT_Barred = -1;
static int hf_gsm_map_ODB_GeneralData_doublyChargeableECT_Barred = -1;
static int hf_gsm_map_ODB_GeneralData_multipleECT_Barred = -1;
static int hf_gsm_map_ODB_GeneralData_allPacketOrientedServicesBarred = -1;
static int hf_gsm_map_ODB_GeneralData_roamerAccessToHPLMN_AP_Barred = -1;
static int hf_gsm_map_ODB_GeneralData_roamerAccessToVPLMN_AP_Barred = -1;
static int hf_gsm_map_ODB_GeneralData_roamingOutsidePLMNOG_CallsBarred = -1;
static int hf_gsm_map_ODB_GeneralData_allIC_CallsBarred = -1;
static int hf_gsm_map_ODB_GeneralData_roamingOutsidePLMNIC_CallsBarred = -1;
static int hf_gsm_map_ODB_GeneralData_roamingOutsidePLMNICountryIC_CallsBarred = -1;
static int hf_gsm_map_ODB_GeneralData_roamingOutsidePLMN_Barred = -1;
static int hf_gsm_map_ODB_GeneralData_roamingOutsidePLMN_CountryBarred = -1;
static int hf_gsm_map_ODB_GeneralData_registrationAllCF_Barred = -1;
static int hf_gsm_map_ODB_GeneralData_registrationCFNotToHPLMN_Barred = -1;
static int hf_gsm_map_ODB_GeneralData_registrationInterzonalCF_Barred = -1;
static int hf_gsm_map_ODB_GeneralData_registrationInterzonalCFNotToHPLMN_Barred = -1;
static int hf_gsm_map_ODB_GeneralData_registrationInternationalCF_Barred = -1;
static int hf_gsm_map_ODB_HPLMN_Data_plmn_SpecificBarringType1 = -1;
static int hf_gsm_map_ODB_HPLMN_Data_plmn_SpecificBarringType2 = -1;
static int hf_gsm_map_ODB_HPLMN_Data_plmn_SpecificBarringType3 = -1;
static int hf_gsm_map_ODB_HPLMN_Data_plmn_SpecificBarringType4 = -1;
static int hf_gsm_map_AccessRestrictionData_utranNotAllowed = -1;
static int hf_gsm_map_AccessRestrictionData_geranNotAllowed = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_o_csi = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_ss_csi = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_tif_csi = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_d_csi = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_vt_csi = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_mo_sms_csi = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_m_csi = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_gprs_csi = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_t_csi = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_mt_sms_csi = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_mg_csi = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_o_IM_CSI = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_d_IM_CSI = -1;
static int hf_gsm_map_SpecificCSI_Withdraw_vt_IM_CSI = -1;
static int hf_gsm_map_AllowedServices_firstServiceAllowed = -1;
static int hf_gsm_map_AllowedServices_secondServiceAllowed = -1;
static int hf_gsm_map_ServiceIndicator_clir_invoked = -1;
static int hf_gsm_map_ServiceIndicator_camel_invoked = -1;
static int hf_gsm_map_T_mw_Status_scAddressNotIncluded = -1;
static int hf_gsm_map_T_mw_Status_mnrfSet = -1;
static int hf_gsm_map_T_mw_Status_mcefSet = -1;
static int hf_gsm_map_T_mw_Status_mnrgSet = -1;
static int hf_gsm_map_OfferedCamel4CSIs_o_csi = -1;
static int hf_gsm_map_OfferedCamel4CSIs_d_csi = -1;
static int hf_gsm_map_OfferedCamel4CSIs_vt_csi = -1;
static int hf_gsm_map_OfferedCamel4CSIs_t_csi = -1;
static int hf_gsm_map_OfferedCamel4CSIs_mt_sms_csi = -1;
static int hf_gsm_map_OfferedCamel4CSIs_mg_csi = -1;
static int hf_gsm_map_OfferedCamel4CSIs_psi_enhancements = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_initiateCallAttempt = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_splitLeg = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_moveLeg = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_disconnectLeg = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_entityReleased = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_dfc_WithArgument = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_playTone = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_dtmf_MidCall = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_chargingIndicator = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_alertingDP = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_locationAtAlerting = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_changeOfPositionDP = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_or_Interactions = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_warningToneEnhancements = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_cf_Enhancements = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_subscribedEnhancedDialledServices = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_servingNetworkEnhancedDialledServices = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_criteriaForChangeOfPositionDP = -1;
static int hf_gsm_map_OfferedCamel4Functionalities_serviceChangeDP = -1;
static int hf_gsm_map_DeferredLocationEventType_msAvailable = -1;
static int hf_gsm_map_DeferredLocationEventType_enteringIntoArea = -1;
static int hf_gsm_map_DeferredLocationEventType_leavingFromArea = -1;
static int hf_gsm_map_DeferredLocationEventType_beingInsideArea = -1;
static int hf_gsm_map_SupportedGADShapes_ellipsoidPoint = -1;
static int hf_gsm_map_SupportedGADShapes_ellipsoidPointWithUncertaintyCircle = -1;
static int hf_gsm_map_SupportedGADShapes_ellipsoidPointWithUncertaintyEllipse = -1;
static int hf_gsm_map_SupportedGADShapes_polygon = -1;
static int hf_gsm_map_SupportedGADShapes_ellipsoidPointWithAltitude = -1;
static int hf_gsm_map_SupportedGADShapes_ellipsoidPointWithAltitudeAndUncertaintyElipsoid = -1;
static int hf_gsm_map_SupportedGADShapes_ellipsoidArc = -1;

/*--- End of included file: packet-gsm_map-hf.c ---*/
#line 136 "packet-gsm_map-template.c"

/* Initialize the subtree pointers */
static gint ett_gsm_map = -1;
static gint ett_gsm_map_InvokeId = -1;
static gint ett_gsm_map_InvokePDU = -1;
static gint ett_gsm_map_ReturnResultPDU = -1;
static gint ett_gsm_map_ReturnErrorPDU = -1;
static gint ett_gsm_map_ReturnResult_result = -1;
static gint ett_gsm_map_ReturnError_result = -1;
static gint ett_gsm_map_GSMMAPPDU = -1;
static gint ett_gsm_map_ext_qos_subscribed = -1;
static gint ett_gsm_map_pdptypenumber = -1;
static gint ett_gsm_map_RAIdentity = -1; 
static gint ett_gsm_map_LAIFixedLength = -1;
static gint ett_gsm_map_isdn_address_string = -1;
static gint ett_gsm_map_geo_desc = -1;


/*--- Included file: packet-gsm_map-ett.c ---*/
#line 1 "packet-gsm_map-ett.c"
static gint ett_gsm_map_Component = -1;
static gint ett_gsm_map_Invoke = -1;
static gint ett_gsm_map_ReturnResult = -1;
static gint ett_gsm_map_T_resultretres = -1;
static gint ett_gsm_map_ReturnError = -1;
static gint ett_gsm_map_Reject = -1;
static gint ett_gsm_map_T_invokeIDRej = -1;
static gint ett_gsm_map_T_problem = -1;
static gint ett_gsm_map_OPERATION = -1;
static gint ett_gsm_map_ERROR = -1;
static gint ett_gsm_map_Bss_APDU = -1;
static gint ett_gsm_map_SupportedCamelPhases = -1;
static gint ett_gsm_map_UpdateLocationArg = -1;
static gint ett_gsm_map_UpdateLocationRes = -1;
static gint ett_gsm_map_VLR_Capability = -1;
static gint ett_gsm_map_SuperChargerInfo = -1;
static gint ett_gsm_map_SupportedLCS_CapabilitySets = -1;
static gint ett_gsm_map_ADD_Info = -1;
static gint ett_gsm_map_PrivateExtensionList = -1;
static gint ett_gsm_map_PrivateExtension = -1;
static gint ett_gsm_map_SLR_ArgExtensionContainer = -1;
static gint ett_gsm_map_PcsExtensions = -1;
static gint ett_gsm_map_SLR_Arg_PCS_Extensions = -1;
static gint ett_gsm_map_CancelLocationArg = -1;
static gint ett_gsm_map_CancelLocationArgV2 = -1;
static gint ett_gsm_map_CancelLocationRes = -1;
static gint ett_gsm_map_PurgeMSArg = -1;
static gint ett_gsm_map_PurgeMSRes = -1;
static gint ett_gsm_map_SendIdentificationArg = -1;
static gint ett_gsm_map_SendIdentificationRes = -1;
static gint ett_gsm_map_AuthenticationSetList = -1;
static gint ett_gsm_map_TripletList = -1;
static gint ett_gsm_map_QuintupletList = -1;
static gint ett_gsm_map_AuthenticationTriplet = -1;
static gint ett_gsm_map_AuthenticationQuintuplet = -1;
static gint ett_gsm_map_CurrentSecurityContext = -1;
static gint ett_gsm_map_GSM_SecurityContextData = -1;
static gint ett_gsm_map_UMTS_SecurityContextData = -1;
static gint ett_gsm_map_PrepareHO_Arg = -1;
static gint ett_gsm_map_PrepareHO_ArgV3 = -1;
static gint ett_gsm_map_BSSMAP_ServiceHandoverList = -1;
static gint ett_gsm_map_BSSMAP_ServiceHandoverInfo = -1;
static gint ett_gsm_map_RadioResourceList = -1;
static gint ett_gsm_map_RadioResource = -1;
static gint ett_gsm_map_PrepareHO_Res = -1;
static gint ett_gsm_map_PrepareHO_ResV3 = -1;
static gint ett_gsm_map_SelectedUMTS_Algorithms = -1;
static gint ett_gsm_map_ChosenRadioResourceInformation = -1;
static gint ett_gsm_map_SendEndSignalArgV3 = -1;
static gint ett_gsm_map_SendEndSignalRes = -1;
static gint ett_gsm_map_RelocationNumberList = -1;
static gint ett_gsm_map_RelocationNumber = -1;
static gint ett_gsm_map_ProcessAccessSignallingArgV3 = -1;
static gint ett_gsm_map_SupportedCodecsList = -1;
static gint ett_gsm_map_CodecList = -1;
static gint ett_gsm_map_ForwardAccessSignallingArgV3 = -1;
static gint ett_gsm_map_AllowedUMTS_Algorithms = -1;
static gint ett_gsm_map_PrepareSubsequentHOArg = -1;
static gint ett_gsm_map_PrepareSubsequentHOArgV3 = -1;
static gint ett_gsm_map_PrepareSubsequentHOResV3 = -1;
static gint ett_gsm_map_SendAuthenticationInfoArgV2 = -1;
static gint ett_gsm_map_SendAuthenticationInfoRes = -1;
static gint ett_gsm_map_SendAuthenticationInfoRes_item = -1;
static gint ett_gsm_map_SendAuthenticationInfoResV3 = -1;
static gint ett_gsm_map_Re_synchronisationInfo = -1;
static gint ett_gsm_map_CheckIMEIArgV3 = -1;
static gint ett_gsm_map_CheckIMEIRes = -1;
static gint ett_gsm_map_RequestedEquipmentInfo = -1;
static gint ett_gsm_map_UESBI_Iu = -1;
static gint ett_gsm_map_BasicService = -1;
static gint ett_gsm_map_BasicServiceGroupList = -1;
static gint ett_gsm_map_ODB_GeneralData = -1;
static gint ett_gsm_map_ODB_HPLMN_Data = -1;
static gint ett_gsm_map_BcsmCamelTDPData = -1;
static gint ett_gsm_map_BcsmCamelTDPDataList = -1;
static gint ett_gsm_map_O_CSI = -1;
static gint ett_gsm_map_O_BcsmCamelTDPDataList = -1;
static gint ett_gsm_map_O_BcsmCamelTDPData = -1;
static gint ett_gsm_map_InsertSubscriberDataArg = -1;
static gint ett_gsm_map_AccessRestrictionData = -1;
static gint ett_gsm_map_LCSInformation = -1;
static gint ett_gsm_map_GMLC_List = -1;
static gint ett_gsm_map_GPRSDataList = -1;
static gint ett_gsm_map_PDP_Context = -1;
static gint ett_gsm_map_GPRSSubscriptionData = -1;
static gint ett_gsm_map_SGSN_CAMEL_SubscriptionInfo = -1;
static gint ett_gsm_map_GPRS_CSI = -1;
static gint ett_gsm_map_GPRS_CamelTDPDataList = -1;
static gint ett_gsm_map_GPRS_CamelTDPData = -1;
static gint ett_gsm_map_LSADataList = -1;
static gint ett_gsm_map_LSAData = -1;
static gint ett_gsm_map_LSAInformation = -1;
static gint ett_gsm_map_InsertSubscriberDataRes = -1;
static gint ett_gsm_map_DeleteSubscriberDataArg = -1;
static gint ett_gsm_map_DeleteSubscriberDataRes = -1;
static gint ett_gsm_map_SpecificCSI_Withdraw = -1;
static gint ett_gsm_map_GPRSSubscriptionDataWithdraw = -1;
static gint ett_gsm_map_ContextIdList = -1;
static gint ett_gsm_map_LSAInformationWithdraw = -1;
static gint ett_gsm_map_LSAIdentityList = -1;
static gint ett_gsm_map_BasicServiceList = -1;
static gint ett_gsm_map_VlrCamelSubscriptionInfo = -1;
static gint ett_gsm_map_MT_smsCAMELTDP_CriteriaList = -1;
static gint ett_gsm_map_MT_smsCAMELTDP_Criteria = -1;
static gint ett_gsm_map_TPDU_TypeCriterion = -1;
static gint ett_gsm_map_D_CSI = -1;
static gint ett_gsm_map_DP_AnalysedInfoCriteriaList = -1;
static gint ett_gsm_map_DP_AnalysedInfoCriterium = -1;
static gint ett_gsm_map_SS_CSI = -1;
static gint ett_gsm_map_SS_CamelData = -1;
static gint ett_gsm_map_MG_CSI = -1;
static gint ett_gsm_map_BearerServiceList = -1;
static gint ett_gsm_map_TeleserviceList = -1;
static gint ett_gsm_map_Ext_SS_InfoList = -1;
static gint ett_gsm_map_Ext_SS_Info = -1;
static gint ett_gsm_map_Ext_ForwInfo = -1;
static gint ett_gsm_map_Ext_ForwFeatureList = -1;
static gint ett_gsm_map_Ext_ForwFeature = -1;
static gint ett_gsm_map_Ext_CallBarInfo = -1;
static gint ett_gsm_map_Ext_CallBarFeatureList = -1;
static gint ett_gsm_map_Ext_CallBarringFeature = -1;
static gint ett_gsm_map_ZoneCodeList = -1;
static gint ett_gsm_map_EMLPP_Info = -1;
static gint ett_gsm_map_CUG_Info = -1;
static gint ett_gsm_map_CUG_SubscriptionList = -1;
static gint ett_gsm_map_CUG_Subscription = -1;
static gint ett_gsm_map_CUG_FeatureList = -1;
static gint ett_gsm_map_Ext_BasicServiceGroupList = -1;
static gint ett_gsm_map_CUG_Feature = -1;
static gint ett_gsm_map_Ext_SS_Data = -1;
static gint ett_gsm_map_LCS_PrivacyExceptionList = -1;
static gint ett_gsm_map_LCS_PrivacyClass = -1;
static gint ett_gsm_map_ExternalClientList = -1;
static gint ett_gsm_map_PLMNClientList = -1;
static gint ett_gsm_map_Ext_ExternalClientList = -1;
static gint ett_gsm_map_ExternalClient = -1;
static gint ett_gsm_map_ServiceTypeList = -1;
static gint ett_gsm_map_ServiceType = -1;
static gint ett_gsm_map_MOLR_List = -1;
static gint ett_gsm_map_MOLR_Class = -1;
static gint ett_gsm_map_CallBarringFeatureList = -1;
static gint ett_gsm_map_CallBarringFeature = -1;
static gint ett_gsm_map_ForwardingFeatureList = -1;
static gint ett_gsm_map_ForwardingFeature = -1;
static gint ett_gsm_map_DestinationNumberCriteria = -1;
static gint ett_gsm_map_DestinationNumberList = -1;
static gint ett_gsm_map_DestinationNumberLengthList = -1;
static gint ett_gsm_map_ForwardingInfo = -1;
static gint ett_gsm_map_CallBarringInfo = -1;
static gint ett_gsm_map_MC_SS_Info = -1;
static gint ett_gsm_map_ResetArg = -1;
static gint ett_gsm_map_RestoreDataArg = -1;
static gint ett_gsm_map_RestoreDataRes = -1;
static gint ett_gsm_map_VBSDataList = -1;
static gint ett_gsm_map_VGCSDataList = -1;
static gint ett_gsm_map_VoiceGroupCallData = -1;
static gint ett_gsm_map_VoiceBroadcastData = -1;
static gint ett_gsm_map_ActivateTraceModeArg = -1;
static gint ett_gsm_map_ActivateTraceModeRes = -1;
static gint ett_gsm_map_DeactivateTraceModeArg = -1;
static gint ett_gsm_map_DeactivateTraceModeRes = -1;
static gint ett_gsm_map_SendRoutingInfoArg = -1;
static gint ett_gsm_map_SendRoutingInfoRes = -1;
static gint ett_gsm_map_ExternalSignalInfo = -1;
static gint ett_gsm_map_Ext_ExternalSignalInfo = -1;
static gint ett_gsm_map_AccessNetworkSignalInfo = -1;
static gint ett_gsm_map_CamelInfo = -1;
static gint ett_gsm_map_Identity = -1;
static gint ett_gsm_map_IMSI_WithLMSI = -1;
static gint ett_gsm_map_SubscriberId = -1;
static gint ett_gsm_map_HLR_List = -1;
static gint ett_gsm_map_SS_List = -1;
static gint ett_gsm_map_NAEA_PreferredCI = -1;
static gint ett_gsm_map_SubscriberIdentity = -1;
static gint ett_gsm_map_LCSClientExternalID = -1;
static gint ett_gsm_map_CellGlobalIdOrServiceAreaIdOrLAI = -1;
static gint ett_gsm_map_AllowedServices = -1;
static gint ett_gsm_map_CCBS_Indicators = -1;
static gint ett_gsm_map_RoutingInfo = -1;
static gint ett_gsm_map_ExtendedRoutingInfo = -1;
static gint ett_gsm_map_CamelRoutingInfo = -1;
static gint ett_gsm_map_GmscCamelSubscriptionInfo = -1;
static gint ett_gsm_map_LocationInformation = -1;
static gint ett_gsm_map_LocationInformationGPRS = -1;
static gint ett_gsm_map_SubscriberState = -1;
static gint ett_gsm_map_PS_SubscriberState = -1;
static gint ett_gsm_map_PDP_ContextInfoList = -1;
static gint ett_gsm_map_PDP_ContextInfo = -1;
static gint ett_gsm_map_CUG_CheckInfo = -1;
static gint ett_gsm_map_ForwardingData = -1;
static gint ett_gsm_map_ProvideRoamingNumberArg = -1;
static gint ett_gsm_map_ProvideRoamingNumberRes = -1;
static gint ett_gsm_map_ResumeCallHandlingArg = -1;
static gint ett_gsm_map_ResumeCallHandlingRes = -1;
static gint ett_gsm_map_UU_Data = -1;
static gint ett_gsm_map_ProvideSIWFSNumberArg = -1;
static gint ett_gsm_map_ProvideSIWFSNumberRes = -1;
static gint ett_gsm_map_SIWFSSignallingModifyArg = -1;
static gint ett_gsm_map_SIWFSSignallingModifyRes = -1;
static gint ett_gsm_map_SetReportingStateArg = -1;
static gint ett_gsm_map_SetReportingStateRes = -1;
static gint ett_gsm_map_StatusReportArg = -1;
static gint ett_gsm_map_StatusReportRes = -1;
static gint ett_gsm_map_EventReportData = -1;
static gint ett_gsm_map_CallReportData = -1;
static gint ett_gsm_map_IST_AlertArg = -1;
static gint ett_gsm_map_IST_AlertRes = -1;
static gint ett_gsm_map_IST_CommandArg = -1;
static gint ett_gsm_map_IST_CommandRes = -1;
static gint ett_gsm_map_ReleaseResourcesArg = -1;
static gint ett_gsm_map_ReleaseResourcesRes = -1;
static gint ett_gsm_map_RemoteUserFreeArg = -1;
static gint ett_gsm_map_RemoteUserFreeRes = -1;
static gint ett_gsm_map_SS_Data = -1;
static gint ett_gsm_map_SS_SubscriptionOption = -1;
static gint ett_gsm_map_RegisterSS_Arg = -1;
static gint ett_gsm_map_SS_Info = -1;
static gint ett_gsm_map_InterrogateSS_Res = -1;
static gint ett_gsm_map_Ussd_Arg = -1;
static gint ett_gsm_map_Ussd_Res = -1;
static gint ett_gsm_map_AuthenticationFailureReportArg = -1;
static gint ett_gsm_map_AuthenticationFailureReportRes = -1;
static gint ett_gsm_map_RegisterCC_EntryArg = -1;
static gint ett_gsm_map_RegisterCC_EntryRes = -1;
static gint ett_gsm_map_CCBS_Data = -1;
static gint ett_gsm_map_ServiceIndicator = -1;
static gint ett_gsm_map_EraseCC_EntryArg = -1;
static gint ett_gsm_map_EraseCC_EntryRes = -1;
static gint ett_gsm_map_RoutingInfoForSMArg = -1;
static gint ett_gsm_map_RoutingInfoForSM_Res = -1;
static gint ett_gsm_map_LocationInfoWithLMSI = -1;
static gint ett_gsm_map_Additional_Number = -1;
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
static gint ett_gsm_map_SubscriberInfo = -1;
static gint ett_gsm_map_MNPInfoRes = -1;
static gint ett_gsm_map_GPRSMSClass = -1;
static gint ett_gsm_map_RequestedInfo = -1;
static gint ett_gsm_map_AnyTimeInterrogationArg = -1;
static gint ett_gsm_map_AnyTimeInterrogationRes = -1;
static gint ett_gsm_map_AnyTimeSubscriptionInterrogationArg = -1;
static gint ett_gsm_map_AnyTimeSubscriptionInterrogationRes = -1;
static gint ett_gsm_map_RequestedSubscriptionInfo = -1;
static gint ett_gsm_map_CallForwardingData = -1;
static gint ett_gsm_map_CallBarringData = -1;
static gint ett_gsm_map_BasicServiceCode = -1;
static gint ett_gsm_map_O_BcsmCamelTDPCriteriaList = -1;
static gint ett_gsm_map_T_BCSM_CAMEL_TDP_CriteriaList = -1;
static gint ett_gsm_map_O_BcsmCamelTDP_Criteria = -1;
static gint ett_gsm_map_T_BCSM_CAMEL_TDP_Criteria = -1;
static gint ett_gsm_map_OfferedCamel4CSIs = -1;
static gint ett_gsm_map_OfferedCamel4Functionalities = -1;
static gint ett_gsm_map_SS_ForBS_Code = -1;
static gint ett_gsm_map_GenericServiceInfo = -1;
static gint ett_gsm_map_CCBS_FeatureList = -1;
static gint ett_gsm_map_CCBS_Feature = -1;
static gint ett_gsm_map_T_CauseValueCriteria = -1;
static gint ett_gsm_map_O_CauseValueCriteria = -1;
static gint ett_gsm_map_BasicServiceCriteria = -1;
static gint ett_gsm_map_AnyTimeModificationArg = -1;
static gint ett_gsm_map_AnyTimeModificationRes = -1;
static gint ett_gsm_map_ModificationRequestFor_CF_Info = -1;
static gint ett_gsm_map_ModificationRequestFor_CB_Info = -1;
static gint ett_gsm_map_ModificationRequestFor_ODB_data = -1;
static gint ett_gsm_map_ModificationRequestFor_CSI = -1;
static gint ett_gsm_map_Ext_SS_InfoFor_CSE = -1;
static gint ett_gsm_map_NoteSubscriberDataModifiedArg = -1;
static gint ett_gsm_map_NoteSubscriberDataModifiedRes = -1;
static gint ett_gsm_map_NoteMM_EventArg = -1;
static gint ett_gsm_map_NoteMM_EventRes = -1;
static gint ett_gsm_map_CAMEL_SubscriptionInfo = -1;
static gint ett_gsm_map_Ext_ForwardingInfoFor_CSE = -1;
static gint ett_gsm_map_Ext_BasicServiceCode = -1;
static gint ett_gsm_map_Ext_CallBarringInfoFor_CSE = -1;
static gint ett_gsm_map_ODB_Info = -1;
static gint ett_gsm_map_ODB_Data = -1;
static gint ett_gsm_map_M_CSI = -1;
static gint ett_gsm_map_SS_EventList = -1;
static gint ett_gsm_map_T_CSI = -1;
static gint ett_gsm_map_T_BcsmCamelTDPDataList = -1;
static gint ett_gsm_map_T_BcsmCamelTDPData = -1;
static gint ett_gsm_map_SMS_CSI = -1;
static gint ett_gsm_map_SMS_CAMEL_TDP_DataList = -1;
static gint ett_gsm_map_SMS_CAMEL_TDP_Data = -1;
static gint ett_gsm_map_MobilityTriggers = -1;
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
static gint ett_gsm_map_UpdateGprsLocationRes = -1;
static gint ett_gsm_map_SGSN_Capability = -1;
static gint ett_gsm_map_SendRoutingInfoForGprsArg = -1;
static gint ett_gsm_map_SendRoutingInfoForGprsRes = -1;
static gint ett_gsm_map_FailureReportArg = -1;
static gint ett_gsm_map_FailureReportRes = -1;
static gint ett_gsm_map_NoteMsPresentForGprsArg = -1;
static gint ett_gsm_map_NoteMsPresentForGprsRes = -1;
static gint ett_gsm_map_ProvideSubscriberLocation_Arg = -1;
static gint ett_gsm_map_LocationType = -1;
static gint ett_gsm_map_DeferredLocationEventType = -1;
static gint ett_gsm_map_LCS_ClientID = -1;
static gint ett_gsm_map_LCSClientName = -1;
static gint ett_gsm_map_LCSRequestorID = -1;
static gint ett_gsm_map_LCS_QoS = -1;
static gint ett_gsm_map_ResponseTime = -1;
static gint ett_gsm_map_SupportedGADShapes = -1;
static gint ett_gsm_map_LCSCodeword = -1;
static gint ett_gsm_map_LCS_PrivacyCheck = -1;
static gint ett_gsm_map_AreaEventInfo = -1;
static gint ett_gsm_map_AreaDefinition = -1;
static gint ett_gsm_map_AreaList = -1;
static gint ett_gsm_map_Area = -1;
static gint ett_gsm_map_ProvideSubscriberLocation_Res = -1;
static gint ett_gsm_map_TargetMS = -1;
static gint ett_gsm_map_RoutingInfoForLCS_Arg = -1;
static gint ett_gsm_map_RoutingInfoForLCS_Res = -1;
static gint ett_gsm_map_LCSLocationInfo = -1;
static gint ett_gsm_map_SubscriberLocationReport_Arg = -1;
static gint ett_gsm_map_Deferredmt_lrData = -1;
static gint ett_gsm_map_SubscriberLocationReport_Res = -1;
static gint ett_gsm_map_SecureTransportArg = -1;
static gint ett_gsm_map_SecureTransportRes = -1;
static gint ett_gsm_map_SecurityHeader = -1;
static gint ett_gsm_map_OriginalComponentIdentifier = -1;
static gint ett_gsm_map_OperationCode = -1;
static gint ett_gsm_map_ErrorCode = -1;
static gint ett_gsm_map_SystemFailureParam = -1;
static gint ett_gsm_map_T_extensibleSystemFailureParam = -1;
static gint ett_gsm_map_DataMissingParam = -1;
static gint ett_gsm_map_UnexpectedDataParam = -1;
static gint ett_gsm_map_FacilityNotSupParam = -1;
static gint ett_gsm_map_OR_NotAllowedParam = -1;
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
static gint ett_gsm_map_ForwardingViolationParam = -1;
static gint ett_gsm_map_ForwardingFailedParam = -1;
static gint ett_gsm_map_ATI_NotAllowedParam = -1;
static gint ett_gsm_map_ATSI_NotAllowedParam = -1;
static gint ett_gsm_map_ATM_NotAllowedParam = -1;
static gint ett_gsm_map_IllegalSS_OperationParam = -1;
static gint ett_gsm_map_SS_NotAvailableParam = -1;
static gint ett_gsm_map_SS_SubscriptionViolationParam = -1;
static gint ett_gsm_map_InformationNotAvailableParam = -1;
static gint ett_gsm_map_SubBusyForMT_SMS_Param = -1;
static gint ett_gsm_map_CallBarredParam = -1;
static gint ett_gsm_map_ExtensibleCallBarredParam = -1;
static gint ett_gsm_map_CUG_RejectParam = -1;
static gint ett_gsm_map_Or_NotAllowedParam = -1;
static gint ett_gsm_map_NoGroupCallNbParam = -1;
static gint ett_gsm_map_SS_IncompatibilityCause = -1;
static gint ett_gsm_map_ShortTermDenialParam = -1;
static gint ett_gsm_map_LongTermDenialParam = -1;
static gint ett_gsm_map_SM_DeliveryFailureCause = -1;
static gint ett_gsm_map_MessageWaitListFullParam = -1;
static gint ett_gsm_map_AbsentSubscriberSM_Param = -1;
static gint ett_gsm_map_UnauthorizedRequestingNetwork_Param = -1;
static gint ett_gsm_map_UnauthorizedLCSClient_Param = -1;
static gint ett_gsm_map_PositionMethodFailure_Param = -1;
static gint ett_gsm_map_UnknownOrUnreachableLCSClient_Param = -1;
static gint ett_gsm_map_MM_EventNotSupported_Param = -1;
static gint ett_gsm_map_TargetCellOutsideGCA_Param = -1;
static gint ett_gsm_map_SecureTransportErrorParam = -1;
static gint ett_gsm_map_ExtensionContainer = -1;
static gint ett_gsm_map_AccessTypePriv = -1;

/*--- End of included file: packet-gsm_map-ett.c ---*/
#line 154 "packet-gsm_map-template.c"

static dissector_table_t	sms_dissector_table;	/* SMS TPDU */
static dissector_handle_t data_handle;

/* Preferenc settings default */
#define MAX_SSN 254
static range_t *global_ssn_range;
static range_t *ssn_range;
dissector_handle_t	map_handle;

/* Global variables */
static guint32 opcode=0;
static guint32 errorCode;
static proto_tree *top_tree;
static int application_context_version;
gint protocolId;
gint AccessNetworkProtocolId;
const char *obj_id = NULL;
static int gsm_map_tap = -1;

/* Forward declarations */
static int dissect_invokeData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_returnResultData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);
static int dissect_returnErrorData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);

/* Value strings */

const value_string gsm_map_PDP_Type_Organisation_vals[] = {
  {  0, "ETSI" },
  {  1, "IETF" },
  { 0, NULL }
};

const value_string gsm_map_ietf_defined_pdp_vals[] = {
  {  0x21, "IPv4 Address" },
  {  0x57, "IPv6 Address" },
  { 0, NULL }
};

const value_string gsm_map_etsi_defined_pdp_vals[] = {
  {  1, "PPP" },
  { 0, NULL }
};

char*
unpack_digits(tvbuff_t *tvb, int offset){

	int length;
	guint8 octet;
	int i=0;
	char *digit_str;

	length = tvb_length(tvb);
	if (length < offset)
		return "";
	digit_str = ep_alloc((length - offset)*2+1);

	while ( offset < length ){

		octet = tvb_get_guint8(tvb,offset);
		digit_str[i] = ((octet & 0x0f) + '0');
		i++;

		/*
		 * unpack second value in byte
		 */
		octet = octet >> 4;

		if (octet == 0x0f)	/* odd number bytes - hit filler */
			break;

		digit_str[i] = ((octet & 0x0f) + '0');
		i++;
		offset++;

	}
	digit_str[i]= '\0';
	return digit_str;
}

/* returns value in kb/s */
static guint
gsm_map_calc_bitrate(guint8 value){

	guint8 granularity;
	guint returnvalue; 

	if (value == 0xff)
		return 0;

	granularity = value >> 6;
	returnvalue = value & 0x7f;
	switch (granularity){
	case 0:
		break;
	case 1:
		returnvalue = ((returnvalue - 0x40) << 3)+64;
		break;
	case 2:
		returnvalue = (returnvalue << 6)+576;
		break;
	case 3:
		returnvalue = (returnvalue << 6)+576;
		break;
	}
	return returnvalue;

}

static void 
dissect_gsm_map_ext_qos_subscribed(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){
	int offset = 0;
    proto_item *item;
    proto_tree *subtree;
	guint8 octet;
	guint16 value;

	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_gsm_map_ext_qos_subscribed);
	/*  OCTET 1:
		Allocation/Retention Priority (This octet encodes each priority level defined in
		23.107 as the binary value of the priority level, declaration in 29.060)
		Octets 2-9 are coded according to 3GPP TS 24.008[35] Quality of Service Octets
		6-13.
	 */
	/* Allocation/Retention Priority */
	proto_tree_add_item(subtree, hf_gsm_map_ext_qos_subscribed_pri, tvb, offset, 1, FALSE);
	offset++;

	/* Quality of Service Octets 6-13.( Octet 2 - 9 Here) */

	/* Traffic class, octet 6 (see 3GPP TS 23.107) Bits 8 7 6 */
	proto_tree_add_item(subtree, hf_gsm_map_qos_traffic_cls, tvb, offset, 1, FALSE);
	/* Delivery order, octet 6 (see 3GPP TS 23.107) Bits 5 4 */
	proto_tree_add_item(subtree, hf_gsm_map_qos_del_order, tvb, offset, 1, FALSE);
	/* Delivery of erroneous SDUs, octet 6 (see 3GPP TS 23.107) Bits 3 2 1 */
	proto_tree_add_item(subtree, hf_gsm_map_qos_del_of_err_sdu, tvb, offset, 1, FALSE);
	offset++;

	/* Maximum SDU size, octet 7 (see 3GPP TS 23.107) */
	octet = tvb_get_guint8(tvb,offset);
	switch (octet){
	case 0:
		proto_tree_add_text(subtree, tvb, offset, 1, "Subscribed Maximum SDU size/Reserved");
		break;
	case 0x93:
		value = 1502;
		proto_tree_add_uint(subtree, hf_gsm_map_qos_max_sdu, tvb, offset, 1, value);
		break;
	case 0x98:
		value = 1510;
		proto_tree_add_uint(subtree, hf_gsm_map_qos_max_sdu, tvb, offset, 1, value);
		break;
	case 0x99:
		value = 1532;
		proto_tree_add_uint(subtree, hf_gsm_map_qos_max_sdu, tvb, offset, 1, value);
		break;
	default:
		if (octet<0x97){
			value = octet * 10;
			proto_tree_add_uint(subtree, hf_gsm_map_qos_max_sdu, tvb, offset, 1, value);
		}else{
			proto_tree_add_text(subtree, tvb, offset, 1, "Maximum SDU size value 0x%x not defined in TS 24.008",octet);
		}			
	}
	offset++;

	/* Maximum bit rate for uplink, octet 8 */
	octet = tvb_get_guint8(tvb,offset);
	if (octet == 0 ){
		proto_tree_add_text(subtree, tvb, offset, 1, "Subscribed Maximum bit rate for uplink/Reserved"  );
	}else{
		proto_tree_add_uint(subtree, hf_gsm_map_max_brate_ulink, tvb, offset, 1, gsm_map_calc_bitrate(octet));
	}
	offset++;
	/* Maximum bit rate for downlink, octet 9 (see 3GPP TS 23.107) */
	octet = tvb_get_guint8(tvb,offset);
	if (octet == 0 ){
		proto_tree_add_text(subtree, tvb, offset, 1, "Subscribed Maximum bit rate for downlink/Reserved"  );
	}else{
		proto_tree_add_uint(subtree, hf_gsm_map_max_brate_dlink, tvb, offset, 1, gsm_map_calc_bitrate(octet));
	}
	offset++;
	/* Residual Bit Error Rate (BER), octet 10 (see 3GPP TS 23.107) Bits 8 7 6 5 */ 
	proto_tree_add_item(subtree, hf_gsm_map_qos_ber, tvb, offset, 1, FALSE);
	/* SDU error ratio, octet 10 (see 3GPP TS 23.107) */
	proto_tree_add_item(subtree, hf_gsm_map_qos_sdu_err_rat, tvb, offset, 1, FALSE);
	offset++;

	/* Transfer delay, octet 11 (See 3GPP TS 23.107) Bits 8 7 6 5 4 3 */
	proto_tree_add_item(subtree, hf_gsm_map_qos_transfer_delay, tvb, offset, 1, FALSE);
	/* Traffic handling priority, octet 11 (see 3GPP TS 23.107) Bits 2 1 */
	proto_tree_add_item(subtree, hf_gsm_map_qos_traff_hdl_pri, tvb, offset, 1, FALSE);
	offset++;

	/*	Guaranteed bit rate for uplink, octet 12 (See 3GPP TS 23.107)
		Coding is identical to that of Maximum bit rate for uplink.
	 */
	octet = tvb_get_guint8(tvb,offset);
	if (octet == 0 ){
		proto_tree_add_text(subtree, tvb, offset, 1, "Subscribed Guaranteed bit rate for uplink/Reserved"  );
	}else{
		proto_tree_add_uint(subtree, hf_gsm_map_guaranteed_max_brate_ulink, tvb, offset, 1, gsm_map_calc_bitrate(octet));
	}
	offset++;

	/*	Guaranteed bit rate for downlink, octet 13(See 3GPP TS 23.107)
		Coding is identical to that of Maximum bit rate for uplink.
	 */
	octet = tvb_get_guint8(tvb,offset);
	if (octet == 0 ){
		proto_tree_add_text(subtree, tvb, offset, 1, "Subscribed Guaranteed bit rate for downlink/Reserved"  );
	}else{
		proto_tree_add_uint(subtree, hf_gsm_map_guaranteed_max_brate_dlink, tvb, offset, 1, gsm_map_calc_bitrate(octet));
	}

}

#define  ELLIPSOID_POINT 0


/* TS 23 032 Table 2a: Coding of Type of Shape */
static const value_string type_of_shape_vals[] = {
	{ ELLIPSOID_POINT,		"Ellipsoid Point"},
	{ 1,		"Ellipsoid point with uncertainty Circle"},
	{ 3,		"Ellipsoid point with uncertainty Ellipse"},
	{ 5,		"Polygon"},
	{ 8,		"Ellipsoid point with altitude"},
	{ 9,		"Ellipsoid point with altitude and uncertainty Ellipsoid"},
	{ 10,		"Ellipsoid Arc"},
	{ 0,	NULL }
};

/* 3GPP TS 23.032 7.3.1 */
static const value_string sign_of_latitude_vals[] = {
	{ 0,		"North"},
	{ 1,		"South"},
	{ 0,	NULL }
};

static const value_string dir_of_alt_vals[] = {
	{ 0,		"Altitude expresses height"},
	{ 1,		"Altitude expresses depth"},
	{ 0,	NULL }
};


void
dissect_geographical_description(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree){

	proto_item *lat_item, *long_item, *major_item, *minor_item, *alt_item;
	/*proto_tree *subtree; */

	guint8 type_of_shape;
	guint8 no_of_points;
	int offset = 0;
	int length;
	guint8 value;
	guint32 value32;

	/*subtree = proto_item_add_subtree(item, ett_gsm_map_geo_desc);*/

	length = tvb_reported_length_remaining(tvb,0);
	/* Geographical Location 
	 * The Location Estimate field is composed of 1 or more octets with an internal structure 
	 * according to section 7 in [23.032].
	 */
	proto_tree_add_item(tree, hf_geo_loc_type_of_shape, tvb, 0, 1, FALSE);
	if (length<2)
		return;
	type_of_shape = tvb_get_guint8(tvb,offset)>>4;
	switch (type_of_shape){
	case ELLIPSOID_POINT:	/* Ellipsoid Point */
	case 2:					/* Ellipsoid Point with uncertainty Circle */
	case 3:					/* Ellipsoid Point with uncertainty Ellipse */
	case 8:					/* Ellipsoid Point with Altitude */
	case 9:					/* Ellipsoid Point with altitude and uncertainty ellipsoid */
	case 10:				/* Ellipsoid Arc */
		offset++;
		if (length<4)
			return;
		proto_tree_add_item(tree, hf_geo_loc_sign_of_lat, tvb, offset, 1, FALSE);

		value32 = tvb_get_ntoh24(tvb,offset)&0x7fffff;
		/* convert degrees (X/0x7fffff) * 90 = degrees */
		lat_item = proto_tree_add_item(tree, hf_geo_loc_deg_of_lat, tvb, offset, 3, FALSE);
		proto_item_append_text(lat_item,"(%.2f degrees)", (((double)value32/8388607) * 90));
		if (length<7)
			return;
		offset = offset + 3;
		value32 = tvb_get_ntoh24(tvb,offset)&0x7fffff;
		long_item = proto_tree_add_item(tree, hf_geo_loc_deg_of_long, tvb, offset, 3, FALSE);
		/* (X/0xffffff) *360 = degrees */
		proto_item_append_text(long_item,"(%.2f degrees)", (((double)value32/16777215) * 260));
		offset = offset + 3;
		if(type_of_shape==2){
			/* Ellipsoid Point with uncertainty Circle */
			if (length<8)
				return;
			/* Uncertainty code */
			proto_tree_add_item(tree, hf_geo_loc_uncertainty_code, tvb, offset, 1, FALSE);
		}else if(type_of_shape==3){
			/* Ellipsoid Point with uncertainty Ellipse */
			/* Uncertainty semi-major octet 10
			 * To convert to metres 10*(((1.1)^X)-1) 
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f; 
			major_item = proto_tree_add_item(tree, hf_geo_loc_uncertainty_semi_major, tvb, offset, 1, FALSE);
			proto_item_append_text(major_item,"(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
			offset++;
			/* Uncertainty semi-minor Octet 11
			 * To convert to metres 10*(((1.1)^X)-1) 
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f; 
			minor_item = proto_tree_add_item(tree, hf_geo_loc_uncertainty_semi_minor, tvb, offset, 1, FALSE);
			proto_item_append_text(minor_item,"(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
			offset++;
			/* Orientation of major axis octet 12
			 * allowed value from 0-179 to convert 
			 * to actual degrees multiply by 2.
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f;
			proto_tree_add_uint(tree, hf_geo_loc_orientation_of_major_axis, tvb, offset, 1, value*2);
			offset++;
			/* Confidence */
			proto_tree_add_item(tree, hf_geo_loc_confidence, tvb, offset, 1, FALSE);
		}else if(type_of_shape==8){
			/* Ellipsoid Point with Altitude */
			/*D: Direction of Altitude */
			proto_tree_add_item(tree, hf_geo_loc_D, tvb, offset, 1, FALSE);
			/* Altitude */
			proto_tree_add_item(tree, hf_geo_loc_altitude, tvb, offset, 2, FALSE);
		}else if(type_of_shape==9){
			/* Ellipsoid Point with altitude and uncertainty ellipsoid */
			/*D: Direction of Altitude octet 8,9 */
			proto_tree_add_item(tree, hf_geo_loc_D, tvb, offset, 1, FALSE);
			/* Altitude Octet 8,9*/
			proto_tree_add_item(tree, hf_geo_loc_altitude, tvb, offset, 2, FALSE);
			offset = offset +2;
			/* Uncertainty semi-major octet 10
			 * To convert to metres 10*(((1.1)^X)-1) 
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f; 
			major_item = proto_tree_add_item(tree, hf_geo_loc_uncertainty_semi_major, tvb, offset, 1, FALSE);
			proto_item_append_text(major_item,"(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
			offset++;
			/* Uncertainty semi-minor Octet 11
			 * To convert to metres 10*(((1.1)^X)-1) 
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f; 
			minor_item = proto_tree_add_item(tree, hf_geo_loc_uncertainty_semi_minor, tvb, offset, 1, FALSE);
			proto_item_append_text(minor_item,"(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
			offset++;
			/* Orientation of major axis octet 12
			 * allowed value from 0-179 to convert 
			 * to actual degrees multiply by 2.
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f;
			proto_tree_add_uint(tree, hf_geo_loc_orientation_of_major_axis, tvb, offset, 1, value*2);
			offset++;
			/* Uncertainty Altitude 13
			 * to convert to metres 45*(((1.025)^X)-1) 
			 */
			value = tvb_get_guint8(tvb,offset)&0x7f; 
			alt_item = proto_tree_add_item(tree, hf_geo_loc_uncertainty_altitude, tvb, offset, 1, FALSE);
			proto_item_append_text(alt_item,"(%.1f m)", 45 * (pow(1.025, (double)value) - 1));
			offset++;
			/* Confidence octet 14
			 */
			proto_tree_add_item(tree, hf_geo_loc_confidence, tvb, offset, 1, FALSE);
		}else if(type_of_shape==10){
			/* Ellipsoid Arc */
			offset++;
			/* Inner radius */
			proto_tree_add_item(tree, hf_geo_loc_inner_radius, tvb, offset, 2, FALSE);
			offset= offset +2;
			/* Uncertainty radius */
			proto_tree_add_item(tree, hf_geo_loc_uncertainty_radius, tvb, offset, 1, FALSE);
			offset++;
			/* Offset angle */
			proto_tree_add_item(tree, hf_geo_loc_offset_angle, tvb, offset, 1, FALSE);
			offset++;
			/* Included angle */
			proto_tree_add_item(tree, hf_geo_loc_included_angle, tvb, offset, 1, FALSE);
			offset++;
			/* Confidence */
			proto_tree_add_item(tree, hf_geo_loc_confidence, tvb, offset, 1, FALSE);
		}

		break;
	case 5:					/* Polygon */
		/* Number of points */
		no_of_points = tvb_get_guint8(tvb,offset)&0x0f;
		proto_tree_add_item(tree, hf_geo_loc_no_of_points, tvb, offset, 1, FALSE);
		/*
		while ( no_of_points > 0){
			offset++;

			no_of_points--;
		}
		*/
		break;
	default:
		break;
	}

}

/*--- Included file: packet-gsm_map-fn.c ---*/
#line 1 "packet-gsm_map-fn.c"
/*--- Fields for imported types ---*/




static int
dissect_gsm_map_InvokeIdType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_invokeID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_InvokeIdType(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_invokeID);
}
static int dissect_linkedID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_InvokeIdType(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_linkedID);
}
static int dissect_derivable(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_InvokeIdType(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_derivable);
}


static const value_string gsm_map_OperationLocalvalue_vals[] = {
  {   2, "updateLocation" },
  {   3, "cancelLocation" },
  {   4, "provideRoamingNumber" },
  {   5, "noteSubscriberDataModified" },
  {   6, "resumeCallHandling" },
  {   7, "insertSubscriberData" },
  {   8, "deleteSubscriberData" },
  {   9, "sendParameters" },
  {  10, "registerSS" },
  {  11, "eraseSS" },
  {  12, "activateSS" },
  {  13, "deactivateSS" },
  {  14, "interrogateSS" },
  {  15, "authenticationFailureReport" },
  {  17, "registerPassword" },
  {  18, "getPassword" },
  {  19, "processUnstructuredSS-Data" },
  {  20, "releaseResources" },
  {  22, "sendRoutingInfo" },
  {  23, "updateGprsLocation" },
  {  24, "sendRoutingInfoForGprs" },
  {  25, "failureReport" },
  {  26, "noteMsPresentForGprs" },
  {  28, "performHandover" },
  {  29, "sendEndSignal" },
  {  30, "performSubsequentHandover" },
  {  31, "provideSIWFSNumber" },
  {  32, "sIWFSSignallingModify" },
  {  33, "processAccessSignalling" },
  {  34, "forwardAccessSignalling" },
  {  35, "noteInternalHandover" },
  {  37, "reset" },
  {  38, "forwardCheckSS" },
  {  39, "prepareGroupCall" },
  {  40, "sendGroupCallEndSignal" },
  {  41, "processGroupCallSignalling" },
  {  42, "forwardGroupCallSignalling" },
  {  43, "checkIMEI" },
  {  44, "mt-forwardSM" },
  {  45, "sendRoutingInfoForSM" },
  {  46, "mo-forwardSM" },
  {  47, "reportSM-DeliveryStatus" },
  {  48, "noteSubscriberPresent" },
  {  49, "alertServiceCentreWithoutResult" },
  {  50, "activateTraceMode" },
  {  51, "deactivateTraceMode" },
  {  52, "traceSubscriberActivity" },
  {  54, "beginSubscriberActivity" },
  {  55, "sendIdentification" },
  {  56, "sendAuthenticationInfo" },
  {  57, "restoreData" },
  {  58, "sendIMSI" },
  {  59, "processUnstructuredSS-Request" },
  {  60, "unstructuredSS-Request" },
  {  61, "unstructuredSS-Notify" },
  {  62, "anyTimeSubscriptionInterrogation" },
  {  63, "informServiceCentre" },
  {  64, "alertServiceCentre" },
  {  65, "anyTimeModification" },
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
  {  78, "secureTransportClass1" },
  {  79, "secureTransportClass2" },
  {  80, "secureTransportClass3" },
  {  81, "secureTransportClass4" },
  {  83, "provideSubscriberLocation" },
  {  85, "sendRoutingInfoForLCS" },
  {  86, "subscriberLocationReport" },
  {  87, "ist-Alert" },
  {  88, "ist-Command" },
  {  89, "noteMM-Event" },
  { 0, NULL }
};


static int
dissect_gsm_map_OperationLocalvalue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 142 "gsmmap.cnf"

  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &opcode);
 
  if (check_col(pinfo->cinfo, COL_INFO)){
    col_append_fstr(pinfo->cinfo, COL_INFO, val_to_str(opcode, gsm_map_opr_code_strings, "Unknown GSM-MAP (%u)"));
  }



  return offset;
}
static int dissect_operationLocalvalue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OperationLocalvalue(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_operationLocalvalue);
}



static int
dissect_gsm_map_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_index, &obj_id);

  return offset;
}
static int dissect_globalValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_globalValue);
}
static int dissect_extId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_extId);
}


static const value_string gsm_map_OPERATION_vals[] = {
  {   0, "localValue" },
  {   1, "globalValue" },
  { 0, NULL }
};

static const ber_choice_t OPERATION_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_operationLocalvalue },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_globalValue },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_OPERATION(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 OPERATION_choice, hf_index, ett_gsm_map_OPERATION,
                                 NULL);

  return offset;
}
static int dissect_opCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OPERATION(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_opCode);
}



static int
dissect_gsm_map_InvokeParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 129 "gsmmap.cnf"
	offset = dissect_invokeData(pinfo, tree, tvb, offset);



  return offset;
}
static int dissect_invokeparameter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_InvokeParameter(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_invokeparameter);
}


static const ber_sequence_t Invoke_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeID },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_linkedID_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_opCode },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_invokeparameter },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Invoke(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Invoke_sequence, hf_index, ett_gsm_map_Invoke);

  return offset;
}
static int dissect_invoke_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Invoke(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_invoke);
}



static int
dissect_gsm_map_ReturnResultParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 132 "gsmmap.cnf"
	offset = dissect_returnResultData(pinfo, tree, tvb, offset);



  return offset;
}
static int dissect_returnparameter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ReturnResultParameter(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_returnparameter);
}


static const ber_sequence_t T_resultretres_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_opCode },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_returnparameter },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_resultretres(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_resultretres_sequence, hf_index, ett_gsm_map_T_resultretres);

  return offset;
}
static int dissect_resultretres(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_resultretres(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_resultretres);
}


static const ber_sequence_t ReturnResult_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeID },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_resultretres },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ReturnResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReturnResult_sequence, hf_index, ett_gsm_map_ReturnResult);

  return offset;
}
static int dissect_returnResultLast_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ReturnResult(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_returnResultLast);
}


const value_string gsm_map_LocalErrorcode_vals[] = {
  {  34, "systemFailure" },
  {  35, "dataMissing" },
  {  36, "unexpectedDataValue" },
  {  21, "facilityNotSupported" },
  {  28, "incompatibleTerminal" },
  {  51, "resourceLimitation" },
  {   1, "unknownSubscriber" },
  {  44, "numberChanged" },
  {   3, "unknownMSC" },
  {   5, "unidentifiedSubscriber" },
  {   7, "unknownEquipment" },
  {   8, "roamingNotAllowed" },
  {   9, "illegalSubscriber" },
  {  12, "illegalEquipment" },
  {  10, "bearerServiceNotProvisioned" },
  {  11, "teleserviceNotProvisioned" },
  {  25, "noHandoverNumberAvailable" },
  {  26, "subsequentHandoverFailure" },
  {  42, "targetCellOutsideGroupCallArea" },
  {  40, "tracingBufferFull" },
  {  39, "noRoamingNumberAvailable" },
  {  27, "absentSubscriber" },
  {  45, "busySubscriber" },
  {  46, "noSubscriberReply" },
  {  13, "callBarred" },
  {  14, "forwardingViolation" },
  {  47, "forwardingFailed" },
  {  15, "cug-Reject" },
  {  48, "or-NotAllowed" },
  {  49, "ati-NotAllowed" },
  {  60, "atsi-NotAllowed" },
  {  61, "atm-NotAllowed" },
  {  62, "informationNotAvailabl" },
  {  16, "illegalSS-Operation" },
  {  17, "ss-ErrorStatus" },
  {  18, "ss-NotAvailable" },
  {  19, "ss-SubscriptionViolatio" },
  {  20, "ss-Incompatibility" },
  {  71, "unknownAlphabe" },
  {  72, "ussd-Busy" },
  {  37, "pw-RegistrationFailur" },
  {  38, "negativePW-Check" },
  {  43, "numberOfPW-AttemptsViolation" },
  {  29, "shortTermDenial" },
  {  30, "longTermDenial" },
  {  31, "subscriberBusyForMT-SMS" },
  {  32, "sm-DeliveryFailure" },
  {  33, "messageWaitingListFull" },
  {   6, "absentSubscriberSM" },
  {  50, "noGroupCallNumberAvailable" },
  {  52, "unauthorizedRequestingNetwork" },
  {  53, "unauthorizedLCSClient" },
  {  54, "positionMethodFailure" },
  {  58, "unknownOrUnreachableLCSClient" },
  {  59, "mm-EventNotSupported" },
  {   4, "secureTransportError" },
  { 0, NULL }
};


int
dissect_gsm_map_LocalErrorcode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &errorCode);

  return offset;
}
static int dissect_localErrorcode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LocalErrorcode(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_localErrorcode);
}


static const value_string gsm_map_ERROR_vals[] = {
  {   0, "localValue" },
  {   1, "globalValue" },
  { 0, NULL }
};

static const ber_choice_t ERROR_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_localErrorcode },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_globalValue },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ERROR(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ERROR_choice, hf_index, ett_gsm_map_ERROR,
                                 NULL);

  return offset;
}
static int dissect_returnErrorCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ERROR(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_returnErrorCode);
}



static int
dissect_gsm_map_ReturnErrorParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 135 "gsmmap.cnf"
	offset = dissect_returnErrorData(pinfo, tree, tvb, offset);



  return offset;
}
static int dissect_parameter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ReturnErrorParameter(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_parameter);
}


static const ber_sequence_t ReturnError_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_invokeID },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_returnErrorCode },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_parameter },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ReturnError(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReturnError_sequence, hf_index, ett_gsm_map_ReturnError);

  return offset;
}
static int dissect_returnError_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ReturnError(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_returnError);
}



static int
dissect_gsm_map_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_not_derivable(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_not_derivable);
}
static int dissect_informPreviousNetworkEntity_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_informPreviousNetworkEntity);
}
static int dissect_cs_LCS_NotSupportedByUE_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cs_LCS_NotSupportedByUE);
}
static int dissect_add_Capability(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_add_Capability);
}
static int dissect_solsaSupportIndicator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_solsaSupportIndicator);
}
static int dissect_solsaSupportIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_solsaSupportIndicator);
}
static int dissect_longFTN_Supported_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_longFTN_Supported);
}
static int dissect_sendSubscriberData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sendSubscriberData);
}
static int dissect_skipSubscriberDataUpdate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_skipSubscriberDataUpdate);
}
static int dissect_na_ESRK_Request_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_na_ESRK_Request);
}
static int dissect_freezeTMSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_freezeTMSI);
}
static int dissect_freezeP_TMSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_freezeP_TMSI);
}
static int dissect_segmentationProhibited(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_segmentationProhibited);
}
static int dissect_ho_NumberNotRequired(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ho_NumberNotRequired);
}
static int dissect_multipleBearerRequested_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_multipleBearerRequested);
}
static int dissect_rab_ConfigurationIndicator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_rab_ConfigurationIndicator);
}
static int dissect_rab_ConfigurationIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_rab_ConfigurationIndicator);
}
static int dissect_multipleBearerNotSupported(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_multipleBearerNotSupported);
}
static int dissect_immediateResponsePreferred_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_immediateResponsePreferred);
}
static int dissect_notificationToCSE(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_notificationToCSE);
}
static int dissect_notificationToCSE_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_notificationToCSE);
}
static int dissect_csiActive_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_csiActive);
}
static int dissect_roamingRestrictionDueToUnsupportedFeature_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_roamingRestrictionDueToUnsupportedFeature);
}
static int dissect_roamingRestrictedInSgsnDueToUnsupportedFeature_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_roamingRestrictedInSgsnDueToUnsupportedFeature);
}
static int dissect_lmu_Indicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lmu_Indicator);
}
static int dissect_vplmnAddressAllowed_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vplmnAddressAllowed);
}
static int dissect_completeDataListIncluded(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_completeDataListIncluded);
}
static int dissect_csi_Active_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_csi_Active);
}
static int dissect_lsaActiveModeIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lsaActiveModeIndicator);
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
static int dissect_roamingRestrictedInSgsnDueToUnsuppportedFeature_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_roamingRestrictedInSgsnDueToUnsuppportedFeature);
}
static int dissect_gmlc_ListWithdraw_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gmlc_ListWithdraw);
}
static int dissect_istInformationWithdraw(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_istInformationWithdraw);
}
static int dissect_istInformationWithdraw_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_istInformationWithdraw);
}
static int dissect_chargingCharacteristicsWithdraw_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_chargingCharacteristicsWithdraw);
}
static int dissect_allGPRSData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_allGPRSData);
}
static int dissect_allLSAData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_allLSAData);
}
static int dissect_tif_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_tif_CSI);
}
static int dissect_msNotReachable(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_msNotReachable);
}
static int dissect_broadcastInitEntitlement(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_broadcastInitEntitlement);
}
static int dissect_or_Interrogation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_or_Interrogation);
}
static int dissect_ccbs_Call_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Call);
}
static int dissect_pre_pagingSupported_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_pre_pagingSupported);
}
static int dissect_suppress_VT_CSI(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_suppress_VT_CSI);
}
static int dissect_suppress_VT_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_suppress_VT_CSI);
}
static int dissect_suppressIncomingCallBarring(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_suppressIncomingCallBarring);
}
static int dissect_gsmSCF_InitiatedCall(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_gsmSCF_InitiatedCall);
}
static int dissect_cugSubscriptionFlag_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cugSubscriptionFlag);
}
static int dissect_forwardingInterrogationRequired_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingInterrogationRequired);
}
static int dissect_releaseResourcesSupported(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_releaseResourcesSupported);
}
static int dissect_releaseResourcesSupported_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_releaseResourcesSupported);
}
static int dissect_suppress_T_CSI(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_suppress_T_CSI);
}
static int dissect_ccbs_Possible_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Possible);
}
static int dissect_keepCCBS_CallIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_keepCCBS_CallIndicator);
}
static int dissect_currentLocationRetrieved(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_currentLocationRetrieved);
}
static int dissect_currentLocationRetrieved_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_currentLocationRetrieved);
}
static int dissect_sai_Present(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sai_Present);
}
static int dissect_sai_Present_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sai_Present);
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
static int dissect_notProvidedFromSGSN_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_notProvidedFromSGSN);
}
static int dissect_ps_Detached_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ps_Detached);
}
static int dissect_ps_AttachedNotReachableForPaging_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ps_AttachedNotReachableForPaging);
}
static int dissect_ps_AttachedReachableForPaging_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ps_AttachedReachableForPaging);
}
static int dissect_pdp_ContextActive_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_pdp_ContextActive);
}
static int dissect_cug_OutgoingAccess(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_OutgoingAccess);
}
static int dissect_orNotSupportedInGMSC_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_orNotSupportedInGMSC);
}
static int dissect_allInformationSent(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_allInformationSent);
}
static int dissect_allInformationSent_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_allInformationSent);
}
static int dissect_uusCFInteraction_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uusCFInteraction);
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
static int dissect_locationInformation_flg_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_locationInformation_flg);
}
static int dissect_subscriberState_flg_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_subscriberState_flg);
}
static int dissect_currentLocation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_currentLocation);
}
static int dissect_imei_flg_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_imei_flg);
}
static int dissect_ms_classmark_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ms_classmark);
}
static int dissect_mnpRequestedInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_mnpRequestedInfo);
}
static int dissect_odb_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_odb);
}
static int dissect_supportedVLR_CAMEL_Phases_flg_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_supportedVLR_CAMEL_Phases_flg);
}
static int dissect_supportedSGSN_CAMEL_Phases_flg_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_supportedSGSN_CAMEL_Phases_flg);
}
static int dissect_tif_CSI_NotificationToCSE_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_tif_CSI_NotificationToCSE);
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
static int dissect_ps_LCS_NotSupportedByUE_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ps_LCS_NotSupportedByUE);
}
static int dissect_gprsEnhancementsSupportIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gprsEnhancementsSupportIndicator);
}
static int dissect_smsCallBarringSupportIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_smsCallBarringSupportIndicator);
}
static int dissect_privacyOverride_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_privacyOverride);
}
static int dissect_verticalCoordinateRequest_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_verticalCoordinateRequest);
}
static int dissect_deferredmt_lrResponseIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_deferredmt_lrResponseIndicator);
}
static int dissect_pseudonymIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_pseudonymIndicator);
}
static int dissect_userInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_userInfo);
}
static int dissect_ccbs_Busy_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Busy);
}
static int dissect_gprsConnectionSuspended(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_gprsConnectionSuspended);
}
static int dissect_unauthorisedMessageOriginator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NULL(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_unauthorisedMessageOriginator);
}


static const value_string gsm_map_T_invokeIDRej_vals[] = {
  {   0, "derivable" },
  {   1, "not-derivable" },
  { 0, NULL }
};

static const ber_choice_t T_invokeIDRej_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_derivable },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_not_derivable },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_invokeIDRej(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_invokeIDRej_choice, hf_index, ett_gsm_map_T_invokeIDRej,
                                 NULL);

  return offset;
}
static int dissect_invokeIDRej(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_invokeIDRej(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_invokeIDRej);
}


static const value_string gsm_map_GeneralProblem_vals[] = {
  {   0, "unrecognizedComponent" },
  {   1, "mistypedComponent" },
  {   2, "badlyStructuredComponent" },
  { 0, NULL }
};


static int
dissect_gsm_map_GeneralProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_generalProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GeneralProblem(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_generalProblem);
}


static const value_string gsm_map_InvokeProblem_vals[] = {
  {   0, "duplicateInvokeID" },
  {   1, "unrecognizedOperation" },
  {   2, "mistypedParameter" },
  {   3, "resourceLimitation" },
  {   4, "initiatingRelease" },
  {   5, "unrecognizedLinkedID" },
  {   6, "linkedResponseUnexpected" },
  {   7, "unexpectedLinkedOperation" },
  { 0, NULL }
};


static int
dissect_gsm_map_InvokeProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_invokeProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_InvokeProblem(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_invokeProblem);
}


static const value_string gsm_map_ReturnResultProblem_vals[] = {
  {   0, "unrecognizedInvokeID" },
  {   1, "returnResultUnexpected" },
  {   2, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_gsm_map_ReturnResultProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_returnResultProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ReturnResultProblem(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_returnResultProblem);
}


static const value_string gsm_map_ReturnErrorProblem_vals[] = {
  {   0, "unrecognizedInvokeID" },
  {   1, "returnErrorUnexpected" },
  {   2, "unrecognizedError" },
  {   3, "unexpectedError" },
  {   4, "mistypedParameter" },
  { 0, NULL }
};


static int
dissect_gsm_map_ReturnErrorProblem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_returnErrorProblem_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ReturnErrorProblem(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_returnErrorProblem);
}


static const value_string gsm_map_T_problem_vals[] = {
  {   0, "generalProblem" },
  {   1, "invokeProblem" },
  {   2, "returnResultProblem" },
  {   3, "returnErrorProblem" },
  { 0, NULL }
};

static const ber_choice_t T_problem_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_generalProblem_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_invokeProblem_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_returnResultProblem_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_returnErrorProblem_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_problem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_problem_choice, hf_index, ett_gsm_map_T_problem,
                                 NULL);

  return offset;
}
static int dissect_problem(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_problem(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_problem);
}


static const ber_sequence_t Reject_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_invokeIDRej },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_problem },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Reject(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Reject_sequence, hf_index, ett_gsm_map_Reject);

  return offset;
}
static int dissect_reject_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Reject(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_reject);
}


static const value_string gsm_map_Component_vals[] = {
  {   1, "invoke" },
  {   2, "returnResultLast" },
  {   3, "returnError" },
  {   4, "reject" },
  { 0, NULL }
};

static const ber_choice_t Component_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_invoke_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_returnResultLast_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_returnError_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_reject_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Component(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Component_choice, hf_index, ett_gsm_map_Component,
                                 NULL);

  return offset;
}


static const value_string gsm_map_ProtocolId_vals[] = {
  {   1, "gsm-0408" },
  {   2, "gsm-0806" },
  {   3, "gsm-BSSMAP" },
  {   4, "ets-300102-1" },
  { 0, NULL }
};


static int
dissect_gsm_map_ProtocolId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &protocolId);

  return offset;
}
static int dissect_protocolId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ProtocolId(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_protocolId);
}



static int
dissect_gsm_map_SignalInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 366 "gsmmap.cnf"

 tvbuff_t	*parameter_tvb;
 guint8		octet;
 guint8		length;
 tvbuff_t	*next_tvb;


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
	/* gsm-BSSMAP TODO Is it correct to stripp off two first octets here?*/
	case 3:
		octet = tvb_get_guint8(parameter_tvb,0);
		length = tvb_get_guint8(parameter_tvb,1);
		if ( octet == 0) {/* DISCRIMINATION TS 48 006 */
			next_tvb = tvb_new_subset(parameter_tvb, 2, -1, -1);
			dissect_bssmap(next_tvb, pinfo, tree);
		}
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
static int dissect_diagnosticInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SignalInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_diagnosticInfo);
}



static int
dissect_gsm_map_T_extType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 513 "gsmmap.cnf"

	
  proto_tree_add_text(tree, tvb, offset, -1, "Extension Data");
  if (obj_id){
	 offset=call_ber_oid_callback(obj_id, tvb, offset, pinfo, tree);
  }else{
	 call_dissector(data_handle, tvb, pinfo, tree);
	 offset = tvb_length_remaining(tvb,offset);
  }	
 		



  return offset;
}
static int dissect_extType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_extType(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_extType);
}


static const ber_sequence_t PrivateExtension_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_extId },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extType },
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

int
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



static int
dissect_gsm_map_SignalInfo2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const asn_namedbit SupportedCamelPhases_bits[] = {
  {  0, &hf_gsm_map_SupportedCamelPhases_phase1, -1, -1, "phase1", NULL },
  {  1, &hf_gsm_map_SupportedCamelPhases_phase2, -1, -1, "phase2", NULL },
  {  2, &hf_gsm_map_SupportedCamelPhases_phase3, -1, -1, "phase3", NULL },
  {  3, &hf_gsm_map_SupportedCamelPhases_phase4, -1, -1, "phase4", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
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
static int dissect_supportedCamelPhasesInVMSC_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedCamelPhases(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_supportedCamelPhasesInVMSC);
}
static int dissect_supportedCamelPhasesInInterrogatingNode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedCamelPhases(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_supportedCamelPhasesInInterrogatingNode);
}
static int dissect_supportedVLR_CAMEL_Phases_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedCamelPhases(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_supportedVLR_CAMEL_Phases);
}
static int dissect_supportedSGSN_CAMEL_Phases_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedCamelPhases(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_supportedSGSN_CAMEL_Phases);
}
static int dissect_supportedCAMELPhases_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedCamelPhases(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_supportedCAMELPhases);
}



int
dissect_gsm_map_IMSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 176 "gsmmap.cnf"

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
  return dissect_gsm_map_IMSI(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_imsi);
}
static int dissect_imsi_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IMSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_imsi);
}



int
dissect_gsm_map_ISDN_AddressString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 223 "gsmmap.cnf"

 tvbuff_t	*parameter_tvb;
 char		*digit_str;
 guint8		octet;
 guint8		na;
 guint8		np;
 proto_item *item;
 proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;

 item = get_ber_last_created_item();
 subtree = proto_item_add_subtree(item, ett_gsm_map_isdn_address_string);

 proto_tree_add_item(subtree, hf_gsm_map_extension, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(subtree, hf_gsm_map_nature_of_number, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(subtree, hf_gsm_map_number_plan, parameter_tvb, 0,1,FALSE);

 digit_str = unpack_digits(parameter_tvb, 1);

 proto_tree_add_string(subtree, hf_gsm_map_isdn_address_digits, parameter_tvb, 1, -1, digit_str);

 octet = tvb_get_guint8(parameter_tvb,0);
 na = (octet & 0x70)>>4;
 np = octet & 0x0f;
 if ((na == 1) && (np==1))/*International Number & E164*/
	dissect_e164_cc(parameter_tvb, subtree, 1, TRUE);

 pinfo->p2p_dir = P2P_DIR_RECV;




  return offset;
}
static int dissect_msc_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_msc_Number);
}
static int dissect_msc_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_msc_Number);
}
static int dissect_vlr_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_vlr_Number);
}
static int dissect_vlr_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vlr_Number);
}
static int dissect_hlr_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_hlr_Number);
}
static int dissect_sgsn_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sgsn_Number);
}
static int dissect_sgsn_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sgsn_Number);
}
static int dissect_handoverNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_handoverNumber);
}
static int dissect_handoverNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_handoverNumber);
}
static int dissect_targetMSC_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_targetMSC_Number);
}
static int dissect_targetMSC_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_targetMSC_Number);
}
static int dissect_gsmSCF_Address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_gsmSCF_Address);
}
static int dissect_gsmSCF_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gsmSCF_Address);
}
static int dissect_msisdn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_msisdn);
}
static int dissect_msisdn_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_msisdn);
}
static int dissect_GMLC_List_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_GMLC_List_item);
}
static int dissect_dialledNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_dialledNumber);
}
static int dissect_forwardedToNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardedToNumber);
}
static int dissect_DestinationNumberList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_DestinationNumberList_item);
}
static int dissect_gmsc_OrGsmSCF_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gmsc_OrGsmSCF_Address);
}
static int dissect_vmsc_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vmsc_Address);
}
static int dissect_externalAddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_externalAddress);
}
static int dissect_roamingNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_roamingNumber);
}
static int dissect_vlr_number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vlr_number);
}
static int dissect_gmsc_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gmsc_Address);
}
static int dissect_b_Subscriber_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_b_Subscriber_Address);
}
static int dissect_sIWFSNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sIWFSNumber);
}
static int dissect_msrn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_msrn);
}
static int dissect_translatedB_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_translatedB_Number);
}
static int dissect_translatedB_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_translatedB_Number);
}
static int dissect_networkNode_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_networkNode_Number);
}
static int dissect_networkNode_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_networkNode_Number);
}
static int dissect_b_subscriberNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_b_subscriberNumber);
}
static int dissect_groupCallNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_groupCallNumber);
}
static int dissect_ggsn_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ggsn_Number);
}
static int dissect_mlc_Number(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_mlc_Number);
}
static int dissect_mlcNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_mlcNumber);
}
static int dissect_na_ESRD_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_na_ESRD);
}
static int dissect_na_ESRK_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_na_ESRK);
}



static int
dissect_gsm_map_LMSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_lmsi(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LMSI(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lmsi);
}
static int dissect_lmsi_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LMSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lmsi);
}


static const value_string gsm_map_IST_SupportIndicator_vals[] = {
  {   0, "basicISTSupported" },
  {   1, "istCommandSupported" },
  { 0, NULL }
};


static int
dissect_gsm_map_IST_SupportIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_istSupportIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IST_SupportIndicator(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_istSupportIndicator);
}



static int
dissect_gsm_map_AgeIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_subscriberDataStored_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AgeIndicator(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_subscriberDataStored);
}
static int dissect_superChargerSupportedInHLR_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AgeIndicator(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_superChargerSupportedInHLR);
}


static const value_string gsm_map_SuperChargerInfo_vals[] = {
  {   0, "sendSubscriberData" },
  {   1, "subscriberDataStored" },
  { 0, NULL }
};

static const ber_choice_t SuperChargerInfo_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sendSubscriberData_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_subscriberDataStored_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SuperChargerInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SuperChargerInfo_choice, hf_index, ett_gsm_map_SuperChargerInfo,
                                 NULL);

  return offset;
}
static int dissect_superChargerSupportedInServingNetworkEntity(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SuperChargerInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_superChargerSupportedInServingNetworkEntity);
}
static int dissect_superChargerSupportedInServingNetworkEntity_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SuperChargerInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_superChargerSupportedInServingNetworkEntity);
}


static const asn_namedbit SupportedLCS_CapabilitySets_bits[] = {
  {  0, &hf_gsm_map_SupportedLCS_CapabilitySets_lcsCapabilitySet1, -1, -1, "lcsCapabilitySet1", NULL },
  {  1, &hf_gsm_map_SupportedLCS_CapabilitySets_lcsCapabilitySet2, -1, -1, "lcsCapabilitySet2", NULL },
  {  2, &hf_gsm_map_SupportedLCS_CapabilitySets_lcsCapabilitySet3, -1, -1, "lcsCapabilitySet3", NULL },
  {  3, &hf_gsm_map_SupportedLCS_CapabilitySets_lcsCapabilitySet4, -1, -1, "lcsCapabilitySet4", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_SupportedLCS_CapabilitySets(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    SupportedLCS_CapabilitySets_bits, hf_index, ett_gsm_map_SupportedLCS_CapabilitySets,
                                    NULL);

  return offset;
}
static int dissect_supportedLCS_CapabilitySets_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedLCS_CapabilitySets(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_supportedLCS_CapabilitySets);
}
static int dissect_additional_LCS_CapabilitySets_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedLCS_CapabilitySets(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_additional_LCS_CapabilitySets);
}


static const asn_namedbit OfferedCamel4CSIs_bits[] = {
  {  0, &hf_gsm_map_OfferedCamel4CSIs_o_csi, -1, -1, "o-csi", NULL },
  {  1, &hf_gsm_map_OfferedCamel4CSIs_d_csi, -1, -1, "d-csi", NULL },
  {  2, &hf_gsm_map_OfferedCamel4CSIs_vt_csi, -1, -1, "vt-csi", NULL },
  {  3, &hf_gsm_map_OfferedCamel4CSIs_t_csi, -1, -1, "t-csi", NULL },
  {  4, &hf_gsm_map_OfferedCamel4CSIs_mt_sms_csi, -1, -1, "mt-sms-csi", NULL },
  {  5, &hf_gsm_map_OfferedCamel4CSIs_mg_csi, -1, -1, "mg-csi", NULL },
  {  6, &hf_gsm_map_OfferedCamel4CSIs_psi_enhancements, -1, -1, "psi-enhancements", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_OfferedCamel4CSIs(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    OfferedCamel4CSIs_bits, hf_index, ett_gsm_map_OfferedCamel4CSIs,
                                    NULL);

  return offset;
}
static int dissect_offeredCamel4CSIs_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OfferedCamel4CSIs(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_offeredCamel4CSIs);
}
static int dissect_offeredCamel4CSIsInVMSC_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OfferedCamel4CSIs(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_offeredCamel4CSIsInVMSC);
}
static int dissect_offeredCamel4CSIsInInterrogatingNode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OfferedCamel4CSIs(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_offeredCamel4CSIsInInterrogatingNode);
}
static int dissect_offeredCamel4CSIsInVLR_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OfferedCamel4CSIs(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_offeredCamel4CSIsInVLR);
}
static int dissect_offeredCamel4CSIsInSGSN_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OfferedCamel4CSIs(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_offeredCamel4CSIsInSGSN);
}


static const ber_sequence_t VLR_Capability_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedCamelPhases_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_solsaSupportIndicator_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_istSupportIndicator_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_superChargerSupportedInServingNetworkEntity },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_longFTN_Supported_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedLCS_CapabilitySets_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_offeredCamel4CSIs_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_VLR_Capability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   VLR_Capability_sequence, hf_index, ett_gsm_map_VLR_Capability);

  return offset;
}
static int dissect_vlr_Capability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_VLR_Capability(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vlr_Capability);
}



int
dissect_gsm_map_GSN_Address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 597 "gsmmap.cnf"

	tvbuff_t	*parameter_tvb;
	guint8		octet;
	proto_item *item;
	proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


	if (!parameter_tvb)
		return offset;
	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_gsm_map_pdptypenumber);

	octet = tvb_get_guint8(parameter_tvb,0);
	switch(octet){
	case 0x04: /* IPv4 */
		proto_tree_add_item(subtree, hf_gsm_map_GSNAddress_IPv4, parameter_tvb, 1, tvb_length_remaining(parameter_tvb, 1), FALSE);
		break;
	case 0x50: /* IPv4 */
		proto_tree_add_item(subtree, hf_gsm_map_GSNAddress_IPv4, parameter_tvb, 1, tvb_length_remaining(parameter_tvb, 1), FALSE);
		break;
	default:
		break;
	}



  return offset;
}
static int dissect_v_gmlc_Address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GSN_Address(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_v_gmlc_Address);
}
static int dissect_v_gmlc_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GSN_Address(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_v_gmlc_Address);
}
static int dissect_ggsn_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GSN_Address(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ggsn_Address);
}
static int dissect_rnc_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GSN_Address(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_rnc_Address);
}
static int dissect_sgsn_Address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GSN_Address(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sgsn_Address);
}
static int dissect_sgsn_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GSN_Address(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sgsn_Address);
}
static int dissect_h_gmlc_Address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GSN_Address(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_h_gmlc_Address);
}
static int dissect_h_gmlc_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GSN_Address(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_h_gmlc_Address);
}
static int dissect_ppr_Address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GSN_Address(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ppr_Address);
}
static int dissect_additional_v_gmlc_Address(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GSN_Address(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_additional_v_gmlc_Address);
}



static int
dissect_gsm_map_TBCD_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



int
dissect_gsm_map_IMEI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_TBCD_STRING(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_imeisv_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IMEI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_imeisv);
}
static int dissect_imei(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IMEI(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_imei);
}
static int dissect_imei_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IMEI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_imei);
}


static const ber_sequence_t ADD_Info_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imeisv_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_skipSubscriberDataUpdate_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ADD_Info(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ADD_Info_sequence, hf_index, ett_gsm_map_ADD_Info);

  return offset;
}
static int dissect_add_info_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ADD_Info(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_add_info);
}


static const ber_sequence_t UpdateLocationArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_msc_Number_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_vlr_Number },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lmsi_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vlr_Capability_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_informPreviousNetworkEntity_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cs_LCS_NotSupportedByUE_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_v_gmlc_Address_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_add_info_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UpdateLocationArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   UpdateLocationArg_sequence, hf_index, ett_gsm_map_UpdateLocationArg);

  return offset;
}


static const ber_sequence_t UpdateLocationRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_hlr_Number },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_add_Capability },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UpdateLocationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   UpdateLocationRes_sequence, hf_index, ett_gsm_map_UpdateLocationRes);

  return offset;
}


static const ber_sequence_t SLR_Arg_PCS_Extensions_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_na_ESRK_Request_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SLR_Arg_PCS_Extensions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SLR_Arg_PCS_Extensions_sequence, hf_index, ett_gsm_map_SLR_Arg_PCS_Extensions);

  return offset;
}
static int dissect_slr_Arg_PCS_Extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SLR_Arg_PCS_Extensions(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_slr_Arg_PCS_Extensions);
}


static const ber_sequence_t SLR_ArgExtensionContainer_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_privateExtensionList_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_slr_Arg_PCS_Extensions_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SLR_ArgExtensionContainer(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SLR_ArgExtensionContainer_sequence, hf_index, ett_gsm_map_SLR_ArgExtensionContainer);

  return offset;
}
static int dissect_slr_ArgExtensionContainer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SLR_ArgExtensionContainer(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_slr_ArgExtensionContainer);
}



static int
dissect_gsm_map_Teleservice(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_teleservice_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Teleservice(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_teleservice);
}



static int
dissect_gsm_map_Bearerservice(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_bearerservice_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Bearerservice(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_bearerservice);
}



static int
dissect_gsm_map_Msc_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t IMSI_WithLMSI_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_lmsi },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_IMSI_WithLMSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IMSI_WithLMSI_sequence, hf_index, ett_gsm_map_IMSI_WithLMSI);

  return offset;
}
static int dissect_imsi_WithLMSI(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IMSI_WithLMSI(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_imsi_WithLMSI);
}


static const value_string gsm_map_Identity_vals[] = {
  {   0, "imsi" },
  {   1, "imsi-WithLMSI" },
  { 0, NULL }
};

static const ber_choice_t Identity_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_imsi_WithLMSI },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Identity(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Identity_choice, hf_index, ett_gsm_map_Identity,
                                 NULL);

  return offset;
}
static int dissect_identity(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Identity(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_identity);
}


static const value_string gsm_map_CancellationType_vals[] = {
  {   0, "updateProcedure" },
  {   1, "subscriptionWithdraw" },
  { 0, NULL }
};


static int
dissect_gsm_map_CancellationType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cancellationType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CancellationType(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cancellationType);
}


static const ber_sequence_t CancelLocationArg_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_identity },
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


static const value_string gsm_map_CancelLocationArgV2_vals[] = {
  {   0, "imsi" },
  {   1, "imsi-WithLMSI" },
  { 0, NULL }
};

static const ber_choice_t CancelLocationArgV2_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_imsi_WithLMSI },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CancelLocationArgV2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CancelLocationArgV2_choice, hf_index, ett_gsm_map_CancelLocationArgV2,
                                 NULL);

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


static const ber_sequence_t PurgeMSArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vlr_Number_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgsn_Number_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PurgeMSArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PurgeMSArg_sequence, hf_index, ett_gsm_map_PurgeMSArg);

  return offset;
}


static const ber_sequence_t PurgeMSRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_freezeTMSI_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_freezeP_TMSI_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PurgeMSRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PurgeMSRes_sequence, hf_index, ett_gsm_map_PurgeMSRes);

  return offset;
}



static int
dissect_gsm_map_TMSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_tmsi(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_TMSI(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_tmsi);
}



static int
dissect_gsm_map_NumberOfRequestedVectors(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_numberOfRequestedVectors(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NumberOfRequestedVectors(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_numberOfRequestedVectors);
}



int
dissect_gsm_map_LAIFixedLength(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 645 "gsmmap.cnf"

        tvbuff_t        *parameter_tvb; 
        proto_item *item; 
        proto_tree *subtree; 

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);
 

         if (!parameter_tvb) 
                return offset; 
        item = get_ber_last_created_item(); 
        subtree = proto_item_add_subtree(item, ett_gsm_map_LAIFixedLength); 
        dissect_e212_mcc_mnc(parameter_tvb, subtree, 0); 



  return offset;
}
static int dissect_previous_LAI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LAIFixedLength(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_previous_LAI);
}
static int dissect_laiFixedLength_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LAIFixedLength(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_laiFixedLength);
}



static int
dissect_gsm_map_HopCounter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_hopCounter_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_HopCounter(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_hopCounter);
}


static const ber_sequence_t SendIdentificationArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_tmsi },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_numberOfRequestedVectors },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_segmentationProhibited },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_msc_Number },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_previous_LAI_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_hopCounter_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendIdentificationArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SendIdentificationArg_sequence, hf_index, ett_gsm_map_SendIdentificationArg);

  return offset;
}



static int
dissect_gsm_map_RAND(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_rand(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RAND(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_rand);
}



static int
dissect_gsm_map_SRES(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_sres(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SRES(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sres);
}



static int
dissect_gsm_map_Kc(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_kc(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Kc(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_kc);
}
static int dissect_groupKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Kc(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_groupKey);
}


static const ber_sequence_t AuthenticationTriplet_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_rand },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sres },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_kc },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AuthenticationTriplet(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AuthenticationTriplet_sequence, hf_index, ett_gsm_map_AuthenticationTriplet);

  return offset;
}
static int dissect_TripletList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AuthenticationTriplet(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_TripletList_item);
}


static const ber_sequence_t TripletList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_TripletList_item },
};

static int
dissect_gsm_map_TripletList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      TripletList_sequence_of, hf_index, ett_gsm_map_TripletList);

  return offset;
}
static int dissect_tripletList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_TripletList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_tripletList);
}



static int
dissect_gsm_map_XRES(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_xres(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_XRES(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_xres);
}



static int
dissect_gsm_map_CK(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_ck(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CK(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ck);
}



static int
dissect_gsm_map_IK(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_ik(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IK(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ik);
}



static int
dissect_gsm_map_AUTN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_autn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AUTN(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_autn);
}


static const ber_sequence_t AuthenticationQuintuplet_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_rand },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_xres },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ck },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ik },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_autn },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AuthenticationQuintuplet(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AuthenticationQuintuplet_sequence, hf_index, ett_gsm_map_AuthenticationQuintuplet);

  return offset;
}
static int dissect_QuintupletList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AuthenticationQuintuplet(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_QuintupletList_item);
}


static const ber_sequence_t QuintupletList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_QuintupletList_item },
};

static int
dissect_gsm_map_QuintupletList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      QuintupletList_sequence_of, hf_index, ett_gsm_map_QuintupletList);

  return offset;
}
static int dissect_quintupletList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_QuintupletList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_quintupletList);
}


static const value_string gsm_map_AuthenticationSetList_vals[] = {
  {   0, "tripletList" },
  {   1, "quintupletList" },
  { 0, NULL }
};

static const ber_choice_t AuthenticationSetList_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_tripletList_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_quintupletList_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AuthenticationSetList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 AuthenticationSetList_choice, hf_index, ett_gsm_map_AuthenticationSetList,
                                 NULL);

  return offset;
}
static int dissect_authenticationSetList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AuthenticationSetList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_authenticationSetList);
}



static int
dissect_gsm_map_Cksn(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cksn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Cksn(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cksn);
}


static const ber_sequence_t GSM_SecurityContextData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_kc },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cksn },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_GSM_SecurityContextData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GSM_SecurityContextData_sequence, hf_index, ett_gsm_map_GSM_SecurityContextData);

  return offset;
}
static int dissect_gsm_SecurityContextData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GSM_SecurityContextData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gsm_SecurityContextData);
}



static int
dissect_gsm_map_KSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_ksi(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_KSI(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ksi);
}


static const ber_sequence_t UMTS_SecurityContextData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ck },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ik },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ksi },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UMTS_SecurityContextData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   UMTS_SecurityContextData_sequence, hf_index, ett_gsm_map_UMTS_SecurityContextData);

  return offset;
}
static int dissect_umts_SecurityContextData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_UMTS_SecurityContextData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_umts_SecurityContextData);
}


static const value_string gsm_map_CurrentSecurityContext_vals[] = {
  {   0, "gsm-SecurityContextData" },
  {   1, "umts-SecurityContextData" },
  { 0, NULL }
};

static const ber_choice_t CurrentSecurityContext_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gsm_SecurityContextData_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_umts_SecurityContextData_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CurrentSecurityContext(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CurrentSecurityContext_choice, hf_index, ett_gsm_map_CurrentSecurityContext,
                                 NULL);

  return offset;
}
static int dissect_currentSecurityContext_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CurrentSecurityContext(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_currentSecurityContext);
}


static const ber_sequence_t SendIdentificationRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_authenticationSetList },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_currentSecurityContext_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendIdentificationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SendIdentificationRes_sequence, hf_index, ett_gsm_map_SendIdentificationRes);

  return offset;
}



static int
dissect_gsm_map_AUTS(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_auts(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AUTS(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_auts);
}



static int
dissect_gsm_map_GlobalCellId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_targetCellId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GlobalCellId(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_targetCellId);
}
static int dissect_targetCellId_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GlobalCellId(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_targetCellId);
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
dissect_gsm_map_RNCId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_targetRNCId_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RNCId(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_targetRNCId);
}


static const value_string gsm_map_AccessNetworkProtocolId_vals[] = {
  {   1, "ts3G-48006" },
  {   2, "ts3G-25413" },
  { 0, NULL }
};


static int
dissect_gsm_map_AccessNetworkProtocolId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  &AccessNetworkProtocolId);

  return offset;
}
static int dissect_accessNetworkProtocolId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AccessNetworkProtocolId(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_accessNetworkProtocolId);
}



static int
dissect_gsm_map_LongSignalInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 410 "gsmmap.cnf"

 tvbuff_t	*parameter_tvb;
 guint8		octet;
 guint8		length;
 tvbuff_t	*next_tvb;


  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;
 switch (AccessNetworkProtocolId){
	/* ts3G-48006 */
	case 1:
		octet = tvb_get_guint8(parameter_tvb,0);
		length = tvb_get_guint8(parameter_tvb,1);
		if ( octet == 0) {/* DISCRIMINATION TS 48 006 */
			/* gsm-BSSMAP? */
			next_tvb = tvb_new_subset(parameter_tvb, 2, -1, -1);
			dissect_bssmap(next_tvb, pinfo, tree);
		}
		break;
 	/* ts3G-25413 */
	case 2:
		break;
	default:
		break;

 }
 


  return offset;
}
static int dissect_longsignalInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LongSignalInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_longsignalInfo);
}


static const ber_sequence_t AccessNetworkSignalInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_accessNetworkProtocolId },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_longsignalInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AccessNetworkSignalInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AccessNetworkSignalInfo_sequence, hf_index, ett_gsm_map_AccessNetworkSignalInfo);

  return offset;
}
static int dissect_an_APDU(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AccessNetworkSignalInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_an_APDU);
}
static int dissect_an_APDU_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AccessNetworkSignalInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_an_APDU);
}



static int
dissect_gsm_map_IntegrityProtectionInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_integrityProtectionInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IntegrityProtectionInformation(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_integrityProtectionInfo);
}
static int dissect_integrityProtectionInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IntegrityProtectionInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_integrityProtectionInfo);
}



static int
dissect_gsm_map_EncryptionInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_encryptionInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_EncryptionInformation(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_encryptionInfo);
}
static int dissect_encryptionInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_EncryptionInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_encryptionInfo);
}



static int
dissect_gsm_map_RadioResourceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_radioResourceInformation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RadioResourceInformation(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_radioResourceInformation);
}
static int dissect_radioResourceInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RadioResourceInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_radioResourceInformation);
}



static int
dissect_gsm_map_AllowedGSM_Algorithms(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_allowedGSM_Algorithms(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AllowedGSM_Algorithms(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_allowedGSM_Algorithms);
}
static int dissect_allowedGSM_Algorithms_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AllowedGSM_Algorithms(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_allowedGSM_Algorithms);
}



static int
dissect_gsm_map_PermittedIntegrityProtectionAlgorithms(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_integrityProtectionAlgorithms_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PermittedIntegrityProtectionAlgorithms(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_integrityProtectionAlgorithms);
}



static int
dissect_gsm_map_PermittedEncryptionAlgorithms(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_encryptionAlgorithms_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PermittedEncryptionAlgorithms(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_encryptionAlgorithms);
}


static const ber_sequence_t AllowedUMTS_Algorithms_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_integrityProtectionAlgorithms_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_encryptionAlgorithms_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AllowedUMTS_Algorithms(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AllowedUMTS_Algorithms_sequence, hf_index, ett_gsm_map_AllowedUMTS_Algorithms);

  return offset;
}
static int dissect_allowedUMTS_Algorithms(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AllowedUMTS_Algorithms(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_allowedUMTS_Algorithms);
}
static int dissect_allowedUMTS_Algorithms_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AllowedUMTS_Algorithms(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_allowedUMTS_Algorithms);
}



static int
dissect_gsm_map_RAB_Id(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_rab_Id(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RAB_Id(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_rab_Id);
}
static int dissect_rab_Id_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RAB_Id(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_rab_Id);
}
static int dissect_selectedRab_Id_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RAB_Id(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_selectedRab_Id);
}


static const ber_sequence_t RadioResource_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_radioResourceInformation },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_rab_Id },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RadioResource(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RadioResource_sequence, hf_index, ett_gsm_map_RadioResource);

  return offset;
}
static int dissect_RadioResourceList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RadioResource(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_RadioResourceList_item);
}


static const ber_sequence_t RadioResourceList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RadioResourceList_item },
};

static int
dissect_gsm_map_RadioResourceList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RadioResourceList_sequence_of, hf_index, ett_gsm_map_RadioResourceList);

  return offset;
}
static int dissect_radioResourceList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RadioResourceList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_radioResourceList);
}
static int dissect_radioResourceList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RadioResourceList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_radioResourceList);
}



static int
dissect_gsm_map_BSSMAP_ServiceHandover(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_bssmap_ServiceHandover(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BSSMAP_ServiceHandover(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_bssmap_ServiceHandover);
}
static int dissect_bssmap_ServiceHandover_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BSSMAP_ServiceHandover(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_bssmap_ServiceHandover);
}



static int
dissect_gsm_map_RANAP_ServiceHandover(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_ranap_ServiceHandover(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RANAP_ServiceHandover(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ranap_ServiceHandover);
}
static int dissect_ranap_ServiceHandover_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RANAP_ServiceHandover(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ranap_ServiceHandover);
}


static const ber_sequence_t BSSMAP_ServiceHandoverInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_bssmap_ServiceHandover },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_rab_Id },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_BSSMAP_ServiceHandoverInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   BSSMAP_ServiceHandoverInfo_sequence, hf_index, ett_gsm_map_BSSMAP_ServiceHandoverInfo);

  return offset;
}
static int dissect_BSSMAP_ServiceHandoverList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BSSMAP_ServiceHandoverInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_BSSMAP_ServiceHandoverList_item);
}


static const ber_sequence_t BSSMAP_ServiceHandoverList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_BSSMAP_ServiceHandoverList_item },
};

static int
dissect_gsm_map_BSSMAP_ServiceHandoverList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      BSSMAP_ServiceHandoverList_sequence_of, hf_index, ett_gsm_map_BSSMAP_ServiceHandoverList);

  return offset;
}
static int dissect_bssmap_ServiceHandoverList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BSSMAP_ServiceHandoverList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_bssmap_ServiceHandoverList);
}
static int dissect_bssmap_ServiceHandoverList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BSSMAP_ServiceHandoverList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_bssmap_ServiceHandoverList);
}



static int
dissect_gsm_map_ASCI_CallReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_TBCD_STRING(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_asciCallReference(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ASCI_CallReference(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_asciCallReference);
}
static int dissect_asciCallReference_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ASCI_CallReference(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_asciCallReference);
}



static int
dissect_gsm_map_GERAN_Classmark(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_geran_classmark_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GERAN_Classmark(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_geran_classmark);
}



static int
dissect_gsm_map_Codec(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_iuCurrentlyUsedCodec_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Codec(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_iuCurrentlyUsedCodec);
}
static int dissect_iuSelectedCodec(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Codec(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_iuSelectedCodec);
}
static int dissect_iUSelectedCodec_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Codec(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_iUSelectedCodec);
}
static int dissect_codec1_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Codec(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_codec1);
}
static int dissect_codec2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Codec(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_codec2);
}
static int dissect_codec3_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Codec(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_codec3);
}
static int dissect_codec4_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Codec(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_codec4);
}
static int dissect_codec5_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Codec(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_codec5);
}
static int dissect_codec6_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Codec(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_codec6);
}
static int dissect_codec7_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Codec(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_codec7);
}
static int dissect_codec8_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Codec(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_codec8);
}
static int dissect_currentlyUsedCodec(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Codec(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_currentlyUsedCodec);
}


static const ber_sequence_t CodecList_sequence[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_codec1_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_codec2_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_codec3_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_codec4_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_codec5_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_codec6_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_codec7_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_codec8_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CodecList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CodecList_sequence, hf_index, ett_gsm_map_CodecList);

  return offset;
}
static int dissect_iuAvailableCodecsList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CodecList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_iuAvailableCodecsList);
}
static int dissect_iuAvailableCodecsList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CodecList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_iuAvailableCodecsList);
}
static int dissect_utranCodecList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CodecList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_utranCodecList);
}
static int dissect_geranCodecList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CodecList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_geranCodecList);
}


static const ber_sequence_t SupportedCodecsList_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_utranCodecList_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_geranCodecList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SupportedCodecsList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SupportedCodecsList_sequence, hf_index, ett_gsm_map_SupportedCodecsList);

  return offset;
}
static int dissect_iuSupportedCodecsList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedCodecsList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_iuSupportedCodecsList);
}
static int dissect_iuSupportedCodecsList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedCodecsList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_iuSupportedCodecsList);
}



static int
dissect_gsm_map_UESBI_IuA(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_uesbi_IuA_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_UESBI_IuA(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uesbi_IuA);
}



static int
dissect_gsm_map_UESBI_IuB(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_uesbi_IuB_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_UESBI_IuB(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uesbi_IuB);
}


static const ber_sequence_t UESBI_Iu_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uesbi_IuA_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uesbi_IuB_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UESBI_Iu(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   UESBI_Iu_sequence, hf_index, ett_gsm_map_UESBI_Iu);

  return offset;
}
static int dissect_uesbi_Iu_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_UESBI_Iu(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uesbi_Iu);
}
static int dissect_bmuef(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_UESBI_Iu(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_bmuef);
}


static const ber_sequence_t PrepareHO_ArgV3_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_targetCellId_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ho_NumberNotRequired },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_targetRNCId_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_an_APDU_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_multipleBearerRequested_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_integrityProtectionInfo_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_encryptionInfo_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_radioResourceInformation_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_allowedGSM_Algorithms_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_allowedUMTS_Algorithms_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_radioResourceList_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rab_Id_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_bssmap_ServiceHandover_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ranap_ServiceHandover_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_bssmap_ServiceHandoverList_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_asciCallReference_impl },
  { BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_geran_classmark_impl },
  { BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iuCurrentlyUsedCodec_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iuSupportedCodecsList_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rab_ConfigurationIndicator_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uesbi_Iu_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imeisv_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PrepareHO_ArgV3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PrepareHO_ArgV3_sequence, hf_index, ett_gsm_map_PrepareHO_ArgV3);

  return offset;
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



static int
dissect_gsm_map_HandoverNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t RelocationNumber_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_handoverNumber },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_rab_Id },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RelocationNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RelocationNumber_sequence, hf_index, ett_gsm_map_RelocationNumber);

  return offset;
}
static int dissect_RelocationNumberList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RelocationNumber(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_RelocationNumberList_item);
}


static const ber_sequence_t RelocationNumberList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RelocationNumberList_item },
};

static int
dissect_gsm_map_RelocationNumberList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RelocationNumberList_sequence_of, hf_index, ett_gsm_map_RelocationNumberList);

  return offset;
}
static int dissect_relocationNumberList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RelocationNumberList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_relocationNumberList);
}



static int
dissect_gsm_map_MulticallBearerInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_multicallBearerInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MulticallBearerInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_multicallBearerInfo);
}



static int
dissect_gsm_map_ChosenIntegrityProtectionAlgorithm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_integrityProtectionAlgorithm_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ChosenIntegrityProtectionAlgorithm(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_integrityProtectionAlgorithm);
}



static int
dissect_gsm_map_ChosenEncryptionAlgorithm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_encryptionAlgorithm_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ChosenEncryptionAlgorithm(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_encryptionAlgorithm);
}


static const ber_sequence_t SelectedUMTS_Algorithms_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_integrityProtectionAlgorithm_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_encryptionAlgorithm_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SelectedUMTS_Algorithms(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SelectedUMTS_Algorithms_sequence, hf_index, ett_gsm_map_SelectedUMTS_Algorithms);

  return offset;
}
static int dissect_selectedUMTS_Algorithms_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SelectedUMTS_Algorithms(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_selectedUMTS_Algorithms);
}



static int
dissect_gsm_map_ChosenChannelInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_chosenChannelInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ChosenChannelInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_chosenChannelInfo);
}



static int
dissect_gsm_map_ChosenSpeechVersion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_chosenSpeechVersion_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ChosenSpeechVersion(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_chosenSpeechVersion);
}


static const ber_sequence_t ChosenRadioResourceInformation_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_chosenChannelInfo_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_chosenSpeechVersion_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ChosenRadioResourceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ChosenRadioResourceInformation_sequence, hf_index, ett_gsm_map_ChosenRadioResourceInformation);

  return offset;
}
static int dissect_chosenRadioResourceInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ChosenRadioResourceInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_chosenRadioResourceInformation);
}


static const ber_sequence_t PrepareHO_ResV3_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_handoverNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_relocationNumberList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_an_APDU_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_multicallBearerInfo_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_multipleBearerNotSupported },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_selectedUMTS_Algorithms_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_chosenRadioResourceInformation_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_iuSelectedCodec },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_iuAvailableCodecsList },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PrepareHO_ResV3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PrepareHO_ResV3_sequence, hf_index, ett_gsm_map_PrepareHO_ResV3);

  return offset;
}



static int
dissect_gsm_map_Sgsn_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gsm_map_Vlr_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SendEndSignalArgV3_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_an_APDU },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendEndSignalArgV3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SendEndSignalArgV3_sequence, hf_index, ett_gsm_map_SendEndSignalArgV3);

  return offset;
}


static const ber_sequence_t SendEndSignalRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendEndSignalRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SendEndSignalRes_sequence, hf_index, ett_gsm_map_SendEndSignalRes);

  return offset;
}



static int
dissect_gsm_map_SelectedGSM_Algorithm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_selectedGSM_Algorithm_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SelectedGSM_Algorithm(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_selectedGSM_Algorithm);
}


static const ber_sequence_t ProcessAccessSignallingArgV3_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_an_APDU },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_selectedUMTS_Algorithms_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_selectedGSM_Algorithm_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_chosenRadioResourceInformation_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_selectedRab_Id_impl },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iUSelectedCodec_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_iuAvailableCodecsList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ProcessAccessSignallingArgV3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ProcessAccessSignallingArgV3_sequence, hf_index, ett_gsm_map_ProcessAccessSignallingArgV3);

  return offset;
}


static const value_string gsm_map_KeyStatus_vals[] = {
  {   0, "old" },
  {   1, "new" },
  { 0, NULL }
};


static int
dissect_gsm_map_KeyStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_keyStatus(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_KeyStatus(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_keyStatus);
}


static const ber_sequence_t ForwardAccessSignallingArgV3_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_an_APDU },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_integrityProtectionInfo },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_encryptionInfo },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_keyStatus },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_allowedGSM_Algorithms },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_allowedUMTS_Algorithms },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_radioResourceInformation },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_extensionContainer },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_radioResourceList },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_bssmap_ServiceHandover },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_ranap_ServiceHandover },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_bssmap_ServiceHandoverList },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_currentlyUsedCodec },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL, dissect_iuSupportedCodecsList },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL, dissect_rab_ConfigurationIndicator },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_iuSelectedCodec },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ForwardAccessSignallingArgV3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ForwardAccessSignallingArgV3_sequence, hf_index, ett_gsm_map_ForwardAccessSignallingArgV3);

  return offset;
}


static const ber_sequence_t PrepareSubsequentHOArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_targetCellId },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_targetMSC_Number },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_bss_APDU },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PrepareSubsequentHOArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PrepareSubsequentHOArg_sequence, hf_index, ett_gsm_map_PrepareSubsequentHOArg);

  return offset;
}


static const ber_sequence_t PrepareSubsequentHOArgV3_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_targetCellId_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_targetMSC_Number_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_targetRNCId_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_an_APDU_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_selectedRab_Id_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_geran_classmark_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rab_ConfigurationIndicator_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PrepareSubsequentHOArgV3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PrepareSubsequentHOArgV3_sequence, hf_index, ett_gsm_map_PrepareSubsequentHOArgV3);

  return offset;
}


static const ber_sequence_t PrepareSubsequentHOResV3_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_an_APDU },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PrepareSubsequentHOResV3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PrepareSubsequentHOResV3_sequence, hf_index, ett_gsm_map_PrepareSubsequentHOResV3);

  return offset;
}



static int
dissect_gsm_map_SendAuthenticationInfoArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_IMSI(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}


static const ber_sequence_t Re_synchronisationInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_rand },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_auts },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Re_synchronisationInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Re_synchronisationInfo_sequence, hf_index, ett_gsm_map_Re_synchronisationInfo);

  return offset;
}
static int dissect_re_synchronisationInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Re_synchronisationInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_re_synchronisationInfo);
}


static const value_string gsm_map_RequestingNodeType_vals[] = {
  {   0, "vlr" },
  {   1, "sgsn" },
  { 0, NULL }
};


static int
dissect_gsm_map_RequestingNodeType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_requestingNodeType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RequestingNodeType(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_requestingNodeType);
}



static int
dissect_gsm_map_PLMN_Id(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_requestingPLMN_Id_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PLMN_Id(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_requestingPLMN_Id);
}


static const ber_sequence_t SendAuthenticationInfoArgV2_sequence[] = {
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
dissect_gsm_map_SendAuthenticationInfoArgV2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SendAuthenticationInfoArgV2_sequence, hf_index, ett_gsm_map_SendAuthenticationInfoArgV2);

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


static const ber_sequence_t SendAuthenticationInfoResV3_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_authenticationSetList },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendAuthenticationInfoResV3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SendAuthenticationInfoResV3_sequence, hf_index, ett_gsm_map_SendAuthenticationInfoResV3);

  return offset;
}


static const asn_namedbit RequestedEquipmentInfo_bits[] = {
  {  0, &hf_gsm_map_RequestedEquipmentInfo_equipmentStatus, -1, -1, "equipmentStatus", NULL },
  {  1, &hf_gsm_map_RequestedEquipmentInfo_bmuef, -1, -1, "bmuef", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_RequestedEquipmentInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    RequestedEquipmentInfo_bits, hf_index, ett_gsm_map_RequestedEquipmentInfo,
                                    NULL);

  return offset;
}
static int dissect_requestedEquipmentInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RequestedEquipmentInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_requestedEquipmentInfo);
}


static const ber_sequence_t CheckIMEIArgV3_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imei },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_requestedEquipmentInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CheckIMEIArgV3(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CheckIMEIArgV3_sequence, hf_index, ett_gsm_map_CheckIMEIArgV3);

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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_equipmentStatus(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_EquipmentStatus(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_equipmentStatus);
}


static const ber_sequence_t CheckIMEIRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_equipmentStatus },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_bmuef },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CheckIMEIRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CheckIMEIRes_sequence, hf_index, ett_gsm_map_CheckIMEIRes);

  return offset;
}


static const value_string gsm_map_OverrideCategory_vals[] = {
  {   0, "overrideEnabled" },
  {   1, "overrideDisabled" },
  { 0, NULL }
};


static int
dissect_gsm_map_OverrideCategory(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_overrideCategory_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OverrideCategory(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_overrideCategory);
}


static const value_string gsm_map_BasicService_vals[] = {
  {   2, "bearerservice" },
  {   3, "teleservice" },
  { 0, NULL }
};

static const ber_choice_t BasicService_choice[] = {
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_bearerservice_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_teleservice_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_BasicService(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 BasicService_choice, hf_index, ett_gsm_map_BasicService,
                                 NULL);

  return offset;
}
static int dissect_BasicServiceGroupList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicService(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_BasicServiceGroupList_item);
}


static const ber_sequence_t BasicServiceGroupList_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_BasicServiceGroupList_item },
};

static int
dissect_gsm_map_BasicServiceGroupList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      BasicServiceGroupList_sequence_of, hf_index, ett_gsm_map_BasicServiceGroupList);

  return offset;
}
static int dissect_ext_basicServiceGroupList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicServiceGroupList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ext_basicServiceGroupList);
}
static int dissect_ext_basicServiceGroupList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicServiceGroupList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_basicServiceGroupList);
}


static const asn_namedbit ODB_GeneralData_bits[] = {
  {  0, &hf_gsm_map_ODB_GeneralData_allOG_CallsBarred, -1, -1, "allOG-CallsBarred", NULL },
  {  1, &hf_gsm_map_ODB_GeneralData_internationalOGCallsBarred, -1, -1, "internationalOGCallsBarred", NULL },
  {  2, &hf_gsm_map_ODB_GeneralData_internationalOGCallsNotToHPLMN_CountryBarred, -1, -1, "internationalOGCallsNotToHPLMN-CountryBarred", NULL },
  {  6, &hf_gsm_map_ODB_GeneralData_interzonalOGCallsBarred, -1, -1, "interzonalOGCallsBarred", NULL },
  {  7, &hf_gsm_map_ODB_GeneralData_interzonalOGCallsNotToHPLMN_CountryBarred, -1, -1, "interzonalOGCallsNotToHPLMN-CountryBarred", NULL },
  {  8, &hf_gsm_map_ODB_GeneralData_interzonalOGCallsAndInternationalOGCallsNotToHPLMN_CountryBarred, -1, -1, "interzonalOGCallsAndInternationalOGCallsNotToHPLMN-CountryBarred", NULL },
  {  3, &hf_gsm_map_ODB_GeneralData_premiumRateInformationOGCallsBarred, -1, -1, "premiumRateInformationOGCallsBarred", NULL },
  {  4, &hf_gsm_map_ODB_GeneralData_premiumRateEntertainementOGCallsBarred, -1, -1, "premiumRateEntertainementOGCallsBarred", NULL },
  {  5, &hf_gsm_map_ODB_GeneralData_ss_AccessBarred, -1, -1, "ss-AccessBarred", NULL },
  {  9, &hf_gsm_map_ODB_GeneralData_allECT_Barred, -1, -1, "allECT-Barred", NULL },
  { 10, &hf_gsm_map_ODB_GeneralData_chargeableECT_Barred, -1, -1, "chargeableECT-Barred", NULL },
  { 11, &hf_gsm_map_ODB_GeneralData_internationalECT_Barred, -1, -1, "internationalECT-Barred", NULL },
  { 12, &hf_gsm_map_ODB_GeneralData_interzonalECT_Barred, -1, -1, "interzonalECT-Barred", NULL },
  { 13, &hf_gsm_map_ODB_GeneralData_doublyChargeableECT_Barred, -1, -1, "doublyChargeableECT-Barred", NULL },
  { 14, &hf_gsm_map_ODB_GeneralData_multipleECT_Barred, -1, -1, "multipleECT-Barred", NULL },
  { 15, &hf_gsm_map_ODB_GeneralData_allPacketOrientedServicesBarred, -1, -1, "allPacketOrientedServicesBarred", NULL },
  { 16, &hf_gsm_map_ODB_GeneralData_roamerAccessToHPLMN_AP_Barred, -1, -1, "roamerAccessToHPLMN-AP-Barred", NULL },
  { 17, &hf_gsm_map_ODB_GeneralData_roamerAccessToVPLMN_AP_Barred, -1, -1, "roamerAccessToVPLMN-AP-Barred", NULL },
  { 18, &hf_gsm_map_ODB_GeneralData_roamingOutsidePLMNOG_CallsBarred, -1, -1, "roamingOutsidePLMNOG-CallsBarred", NULL },
  { 19, &hf_gsm_map_ODB_GeneralData_allIC_CallsBarred, -1, -1, "allIC-CallsBarred", NULL },
  { 20, &hf_gsm_map_ODB_GeneralData_roamingOutsidePLMNIC_CallsBarred, -1, -1, "roamingOutsidePLMNIC-CallsBarred", NULL },
  { 21, &hf_gsm_map_ODB_GeneralData_roamingOutsidePLMNICountryIC_CallsBarred, -1, -1, "roamingOutsidePLMNICountryIC-CallsBarred", NULL },
  { 22, &hf_gsm_map_ODB_GeneralData_roamingOutsidePLMN_Barred, -1, -1, "roamingOutsidePLMN-Barred", NULL },
  { 23, &hf_gsm_map_ODB_GeneralData_roamingOutsidePLMN_CountryBarred, -1, -1, "roamingOutsidePLMN-CountryBarred", NULL },
  { 24, &hf_gsm_map_ODB_GeneralData_registrationAllCF_Barred, -1, -1, "registrationAllCF-Barred", NULL },
  { 25, &hf_gsm_map_ODB_GeneralData_registrationCFNotToHPLMN_Barred, -1, -1, "registrationCFNotToHPLMN-Barred", NULL },
  { 26, &hf_gsm_map_ODB_GeneralData_registrationInterzonalCF_Barred, -1, -1, "registrationInterzonalCF-Barred", NULL },
  { 27, &hf_gsm_map_ODB_GeneralData_registrationInterzonalCFNotToHPLMN_Barred, -1, -1, "registrationInterzonalCFNotToHPLMN-Barred", NULL },
  { 28, &hf_gsm_map_ODB_GeneralData_registrationInternationalCF_Barred, -1, -1, "registrationInternationalCF-Barred", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_ODB_GeneralData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    ODB_GeneralData_bits, hf_index, ett_gsm_map_ODB_GeneralData,
                                    NULL);

  return offset;
}
static int dissect_odb_GeneralData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ODB_GeneralData(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_odb_GeneralData);
}
static int dissect_odb_GeneralData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ODB_GeneralData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_odb_GeneralData);
}


static const asn_namedbit ODB_HPLMN_Data_bits[] = {
  {  0, &hf_gsm_map_ODB_HPLMN_Data_plmn_SpecificBarringType1, -1, -1, "plmn-SpecificBarringType1", NULL },
  {  1, &hf_gsm_map_ODB_HPLMN_Data_plmn_SpecificBarringType2, -1, -1, "plmn-SpecificBarringType2", NULL },
  {  2, &hf_gsm_map_ODB_HPLMN_Data_plmn_SpecificBarringType3, -1, -1, "plmn-SpecificBarringType3", NULL },
  {  3, &hf_gsm_map_ODB_HPLMN_Data_plmn_SpecificBarringType4, -1, -1, "plmn-SpecificBarringType4", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_ODB_HPLMN_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    ODB_HPLMN_Data_bits, hf_index, ett_gsm_map_ODB_HPLMN_Data,
                                    NULL);

  return offset;
}
static int dissect_odb_HPLMN_Data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ODB_HPLMN_Data(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_odb_HPLMN_Data);
}


static const value_string gsm_map_SubscriberStatus_vals[] = {
  {   0, "serviceGranted" },
  {   1, "operatorDeterminedBarring" },
  { 0, NULL }
};


static int
dissect_gsm_map_SubscriberStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_subscriberStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SubscriberStatus(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_subscriberStatus);
}


static const value_string gsm_map_BcsmTriggerDetectionPoint_vals[] = {
  {   2, "collectedInfo" },
  {   4, "routeSelectFailure" },
  {  12, "termAttemptAuthorized" },
  {  13, "tBusy" },
  {  14, "tNoAnswer" },
  { 0, NULL }
};


static int
dissect_gsm_map_BcsmTriggerDetectionPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_bcsmTriggerDetectionPoint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BcsmTriggerDetectionPoint(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_bcsmTriggerDetectionPoint);
}



static int
dissect_gsm_map_ServiceKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_serviceKey(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ServiceKey(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_serviceKey);
}
static int dissect_serviceKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ServiceKey(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_serviceKey);
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


static const value_string gsm_map_DefaultCallHandling_vals[] = {
  {   0, "continueCall" },
  {   1, "releaseCall" },
  { 0, NULL }
};


static int
dissect_gsm_map_DefaultCallHandling(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_defaultCallHandling(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_DefaultCallHandling(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_defaultCallHandling);
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


static const value_string gsm_map_O_BcsmTriggerDetectionPoint_vals[] = {
  {   2, "collectedInfo" },
  {   4, "routeSelectFailure" },
  { 0, NULL }
};


static int
dissect_gsm_map_O_BcsmTriggerDetectionPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_o_BcsmTriggerDetectionPoint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_O_BcsmTriggerDetectionPoint(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_o_BcsmTriggerDetectionPoint);
}


static const ber_sequence_t O_BcsmCamelTDPData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_o_BcsmTriggerDetectionPoint },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serviceKey },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gsmSCF_Address_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_defaultCallHandling_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_O_BcsmCamelTDPData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   O_BcsmCamelTDPData_sequence, hf_index, ett_gsm_map_O_BcsmCamelTDPData);

  return offset;
}
static int dissect_O_BcsmCamelTDPDataList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_O_BcsmCamelTDPData(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_O_BcsmCamelTDPDataList_item);
}


static const ber_sequence_t O_BcsmCamelTDPDataList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_O_BcsmCamelTDPDataList_item },
};

static int
dissect_gsm_map_O_BcsmCamelTDPDataList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      O_BcsmCamelTDPDataList_sequence_of, hf_index, ett_gsm_map_O_BcsmCamelTDPDataList);

  return offset;
}
static int dissect_o_BcsmCamelTDPDataList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_O_BcsmCamelTDPDataList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_o_BcsmCamelTDPDataList);
}



static int
dissect_gsm_map_CamelCapabilityHandling(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_camelCapabilityHandling_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CamelCapabilityHandling(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_camelCapabilityHandling);
}


static const ber_sequence_t O_CSI_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_o_BcsmCamelTDPDataList },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camelCapabilityHandling_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToCSE_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_csiActive_impl },
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
static int dissect_o_IM_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_O_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_o_IM_CSI);
}



static int
dissect_gsm_map_Category(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_category_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Category(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_category);
}



static int
dissect_gsm_map_Ext_BearerServiceCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_BearerServiceList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_BearerServiceCode(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_BearerServiceList_item);
}
static int dissect_ext_BearerService_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_BearerServiceCode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_BearerService);
}


static const ber_sequence_t BearerServiceList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_BearerServiceList_item },
};

static int
dissect_gsm_map_BearerServiceList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      BearerServiceList_sequence_of, hf_index, ett_gsm_map_BearerServiceList);

  return offset;
}
static int dissect_bearerserviceList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BearerServiceList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_bearerserviceList);
}
static int dissect_bearerServiceList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BearerServiceList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_bearerServiceList);
}



static int
dissect_gsm_map_Ext_TeleserviceCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_TeleserviceList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_TeleserviceCode(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_TeleserviceList_item);
}
static int dissect_ext_Teleservice_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_TeleserviceCode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_Teleservice);
}
static int dissect_ext_teleservice(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_TeleserviceCode(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ext_teleservice);
}


static const ber_sequence_t TeleserviceList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_TeleserviceList_item },
};

static int
dissect_gsm_map_TeleserviceList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      TeleserviceList_sequence_of, hf_index, ett_gsm_map_TeleserviceList);

  return offset;
}
static int dissect_teleserviceList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_TeleserviceList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_teleserviceList);
}



int
dissect_gsm_map_SS_Code(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_ss_Code(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SS_Code(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Code);
}
static int dissect_ss_Code_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SS_Code(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Code);
}
static int dissect_SS_List_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SS_Code(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_SS_List_item);
}
static int dissect_SS_EventList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SS_Code(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_SS_EventList_item);
}


const value_string gsm_map_Ext_BasicServiceCode_vals[] = {
  {   2, "ext-BearerService" },
  {   3, "ext-Teleservice" },
  { 0, NULL }
};

static const ber_choice_t Ext_BasicServiceCode_choice[] = {
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ext_BearerService_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ext_Teleservice_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_gsm_map_Ext_BasicServiceCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Ext_BasicServiceCode_choice, hf_index, ett_gsm_map_Ext_BasicServiceCode,
                                 NULL);

  return offset;
}
static int dissect_BasicServiceList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_BasicServiceCode(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_BasicServiceList_item);
}
static int dissect_ext_basicService(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_BasicServiceCode(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ext_basicService);
}
static int dissect_ext_basicService_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_BasicServiceCode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_basicService);
}
static int dissect_Ext_BasicServiceGroupList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_BasicServiceCode(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_Ext_BasicServiceGroupList_item);
}
static int dissect_ext_basicServiceGroup(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_BasicServiceCode(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ext_basicServiceGroup);
}
static int dissect_ext_basicServiceGroup_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_BasicServiceCode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_basicServiceGroup);
}
static int dissect_basicServiceGroup2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_BasicServiceCode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_basicServiceGroup2);
}
static int dissect_basicService2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_BasicServiceCode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_basicService2);
}
static int dissect_BasicServiceCriteria_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_BasicServiceCode(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_BasicServiceCriteria_item);
}



static int
dissect_gsm_map_Ext_SS_Status(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 328 "gsmmap.cnf"
 /* Note Ext-SS-Status can have more than one byte */

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
static int dissect_ext_ss_Status(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_SS_Status(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ext_ss_Status);
}
static int dissect_ext_ss_Status_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_SS_Status(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_ss_Status);
}



int
dissect_gsm_map_ISDN_SubaddressString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_forwardedToSubaddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_SubaddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardedToSubaddress);
}
static int dissect_b_subscriberSubaddress_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ISDN_SubaddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_b_subscriberSubaddress);
}



static int
dissect_gsm_map_Ext_ForwOptions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gsm_map_T_ext_forwardingOptions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_Ext_ForwOptions(implicit_tag, tvb, offset, pinfo, tree, hf_index);

#line 532 "gsmmap.cnf"

	proto_tree_add_item(tree, hf_gsm_map_notification_to_forwarding_party, tvb, 0,1,FALSE);
	proto_tree_add_item(tree, hf_gsm_map_redirecting_presentation, tvb, 0,1,FALSE);
	proto_tree_add_item(tree, hf_gsm_map_notification_to_calling_party, tvb, 0,1,FALSE);
	proto_tree_add_item(tree, hf_gsm_map_forwarding_reason, tvb, 0,1,FALSE);


  return offset;
}
static int dissect_ext_forwardingOptions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_ext_forwardingOptions(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_forwardingOptions);
}



static int
dissect_gsm_map_Ext_NoRepCondTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_ext_noReplyConditionTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_NoRepCondTime(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_noReplyConditionTime);
}



int
dissect_gsm_map_AddressString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 264 "gsmmap.cnf"

 tvbuff_t	*parameter_tvb;
 char		*digit_str;
 guint8		octet;
 guint8		na;
 guint8		np;
 proto_item *item;
 proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;

 item = get_ber_last_created_item();
 subtree = proto_item_add_subtree(item, ett_gsm_map_isdn_address_string);

 proto_tree_add_item(tree, hf_gsm_map_extension, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(tree, hf_gsm_map_nature_of_number, parameter_tvb, 0,1,FALSE);
 proto_tree_add_item(tree, hf_gsm_map_number_plan, parameter_tvb, 0,1,FALSE);

 digit_str = unpack_digits(parameter_tvb, 1);

 proto_tree_add_string(tree, hf_gsm_map_address_digits, parameter_tvb, 1, -1, digit_str);

 octet = tvb_get_guint8(parameter_tvb,0);
 na = (octet & 0x70)>>4;
 np = octet & 0x0f;
 if ((na == 1) && (np==1))/*International Number & E164*/
	dissect_e164_cc(parameter_tvb, subtree, 1, TRUE);



  return offset;
}
static int dissect_forwardedToNumber_addr_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardedToNumber_addr);
}
static int dissect_lcsClientDialedByMS_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsClientDialedByMS);
}



static int
dissect_gsm_map_FTN_AddressString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_AddressString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_longForwardedToNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_FTN_AddressString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_longForwardedToNumber);
}


static const ber_sequence_t Ext_ForwFeature_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ext_basicService },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ext_ss_Status_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToSubaddress_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ext_forwardingOptions_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ext_noReplyConditionTime_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_longForwardedToNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ext_ForwFeature(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Ext_ForwFeature_sequence, hf_index, ett_gsm_map_Ext_ForwFeature);

  return offset;
}
static int dissect_Ext_ForwFeatureList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_ForwFeature(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_Ext_ForwFeatureList_item);
}


static const ber_sequence_t Ext_ForwFeatureList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_Ext_ForwFeatureList_item },
};

static int
dissect_gsm_map_Ext_ForwFeatureList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Ext_ForwFeatureList_sequence_of, hf_index, ett_gsm_map_Ext_ForwFeatureList);

  return offset;
}
static int dissect_ext_forwardingFeatureList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_ForwFeatureList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ext_forwardingFeatureList);
}
static int dissect_ext_forwardingFeatureList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_ForwFeatureList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_forwardingFeatureList);
}


static const ber_sequence_t Ext_ForwInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ext_forwardingFeatureList },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ext_ForwInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Ext_ForwInfo_sequence, hf_index, ett_gsm_map_Ext_ForwInfo);

  return offset;
}
static int dissect_ext_forwardingInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_ForwInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_forwardingInfo);
}


static const ber_sequence_t Ext_CallBarringFeature_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ext_basicService },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ext_ss_Status_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ext_CallBarringFeature(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Ext_CallBarringFeature_sequence, hf_index, ett_gsm_map_Ext_CallBarringFeature);

  return offset;
}
static int dissect_Ext_CallBarFeatureList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_CallBarringFeature(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_Ext_CallBarFeatureList_item);
}


static const ber_sequence_t Ext_CallBarFeatureList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_Ext_CallBarFeatureList_item },
};

static int
dissect_gsm_map_Ext_CallBarFeatureList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Ext_CallBarFeatureList_sequence_of, hf_index, ett_gsm_map_Ext_CallBarFeatureList);

  return offset;
}
static int dissect_ext_callBarringFeatureList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_CallBarFeatureList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ext_callBarringFeatureList);
}
static int dissect_ext_callBarringFeatureList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_CallBarFeatureList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_callBarringFeatureList);
}


static const ber_sequence_t Ext_CallBarInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ext_callBarringFeatureList },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ext_CallBarInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Ext_CallBarInfo_sequence, hf_index, ett_gsm_map_Ext_CallBarInfo);

  return offset;
}
static int dissect_ext_callBarringInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_CallBarInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_callBarringInfo);
}



int
dissect_gsm_map_CUG_Index(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cug_Index(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CUG_Index(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_Index);
}
static int dissect_preferentialCUG_Indicator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CUG_Index(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_preferentialCUG_Indicator);
}



int
dissect_gsm_map_CUG_Interlock(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cug_Interlock(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CUG_Interlock(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_Interlock);
}


static const value_string gsm_map_IntraCUG_Options_vals[] = {
  {   0, "noCUG-Restrictions" },
  {   1, "cugIC-CallBarred" },
  {   2, "cugOG-CallBarred" },
  { 0, NULL }
};


static int
dissect_gsm_map_IntraCUG_Options(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_intraCUG_Options(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IntraCUG_Options(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_intraCUG_Options);
}


static const ber_sequence_t Ext_BasicServiceGroupList_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_Ext_BasicServiceGroupList_item },
};

static int
dissect_gsm_map_Ext_BasicServiceGroupList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Ext_BasicServiceGroupList_sequence_of, hf_index, ett_gsm_map_Ext_BasicServiceGroupList);

  return offset;
}
static int dissect_basicServiceGroupList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_BasicServiceGroupList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_basicServiceGroupList);
}


static const ber_sequence_t CUG_Subscription_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_cug_Index },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cug_Interlock },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_intraCUG_Options },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_basicServiceGroupList },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CUG_Subscription(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CUG_Subscription_sequence, hf_index, ett_gsm_map_CUG_Subscription);

  return offset;
}
static int dissect_CUG_SubscriptionList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CUG_Subscription(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_CUG_SubscriptionList_item);
}


static const ber_sequence_t CUG_SubscriptionList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CUG_SubscriptionList_item },
};

static int
dissect_gsm_map_CUG_SubscriptionList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CUG_SubscriptionList_sequence_of, hf_index, ett_gsm_map_CUG_SubscriptionList);

  return offset;
}
static int dissect_cug_SubscriptionList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CUG_SubscriptionList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_SubscriptionList);
}



static int
dissect_gsm_map_InterCUG_Restrictions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_interCUG_Restrictions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_InterCUG_Restrictions(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_interCUG_Restrictions);
}


static const ber_sequence_t CUG_Feature_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ext_basicService },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_preferentialCUG_Indicator },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_interCUG_Restrictions },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CUG_Feature(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CUG_Feature_sequence, hf_index, ett_gsm_map_CUG_Feature);

  return offset;
}
static int dissect_CUG_FeatureList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CUG_Feature(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_CUG_FeatureList_item);
}


static const ber_sequence_t CUG_FeatureList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CUG_FeatureList_item },
};

static int
dissect_gsm_map_CUG_FeatureList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CUG_FeatureList_sequence_of, hf_index, ett_gsm_map_CUG_FeatureList);

  return offset;
}
static int dissect_cug_FeatureList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CUG_FeatureList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_FeatureList);
}


static const ber_sequence_t CUG_Info_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_cug_SubscriptionList },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cug_FeatureList },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_CUG_Info(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CUG_Info_sequence, hf_index, ett_gsm_map_CUG_Info);

  return offset;
}
static int dissect_cug_Info_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CUG_Info(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cug_Info);
}


static const value_string gsm_map_CliRestrictionOption_vals[] = {
  {   0, "permanent" },
  {   1, "temporaryDefaultRestricted" },
  {   2, "temporaryDefaultAllowed" },
  { 0, NULL }
};


static int
dissect_gsm_map_CliRestrictionOption(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cliRestrictionOption(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CliRestrictionOption(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cliRestrictionOption);
}
static int dissect_cliRestrictionOption_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CliRestrictionOption(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cliRestrictionOption);
}


static const value_string gsm_map_SS_SubscriptionOption_vals[] = {
  {   2, "cliRestrictionOption" },
  {   1, "overrideCategory" },
  { 0, NULL }
};

static const ber_choice_t SS_SubscriptionOption_choice[] = {
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cliRestrictionOption_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_overrideCategory_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SS_SubscriptionOption(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SS_SubscriptionOption_choice, hf_index, ett_gsm_map_SS_SubscriptionOption,
                                 NULL);

  return offset;
}
static int dissect_ss_SubscriptionOption(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SS_SubscriptionOption(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_SubscriptionOption);
}


static const ber_sequence_t Ext_SS_Data_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ext_ss_Status_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ss_SubscriptionOption },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_basicServiceGroupList },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ext_SS_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Ext_SS_Data_sequence, hf_index, ett_gsm_map_Ext_SS_Data);

  return offset;
}
static int dissect_ext_ss_Data_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_SS_Data(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_ss_Data);
}



static int
dissect_gsm_map_EMLPP_Priority(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_maximumentitledPriority(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_EMLPP_Priority(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_maximumentitledPriority);
}
static int dissect_defaultPriority(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_EMLPP_Priority(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_defaultPriority);
}
static int dissect_defaultPriority_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_EMLPP_Priority(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_defaultPriority);
}
static int dissect_maximumEntitledPriority_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_EMLPP_Priority(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_maximumEntitledPriority);
}
static int dissect_priority_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_EMLPP_Priority(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_priority);
}


static const ber_sequence_t EMLPP_Info_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_maximumentitledPriority },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_defaultPriority },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_EMLPP_Info(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EMLPP_Info_sequence, hf_index, ett_gsm_map_EMLPP_Info);

  return offset;
}
static int dissect_emlpp_Info_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_EMLPP_Info(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_emlpp_Info);
}


static const value_string gsm_map_Ext_SS_Info_vals[] = {
  {   0, "forwardingInfo" },
  {   1, "callBarringInfo" },
  {   2, "cug-Info" },
  {   3, "ss-Data" },
  {   4, "emlpp-Info" },
  { 0, NULL }
};

static const ber_choice_t Ext_SS_Info_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ext_forwardingInfo_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ext_callBarringInfo_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_cug_Info_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ext_ss_Data_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_emlpp_Info_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ext_SS_Info(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Ext_SS_Info_choice, hf_index, ett_gsm_map_Ext_SS_Info,
                                 NULL);

  return offset;
}
static int dissect_Ext_SS_InfoList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_SS_Info(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_Ext_SS_InfoList_item);
}


static const ber_sequence_t Ext_SS_InfoList_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_Ext_SS_InfoList_item },
};

static int
dissect_gsm_map_Ext_SS_InfoList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Ext_SS_InfoList_sequence_of, hf_index, ett_gsm_map_Ext_SS_InfoList);

  return offset;
}
static int dissect_provisionedSS_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_SS_InfoList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_provisionedSS);
}


static const ber_sequence_t ODB_Data_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_odb_GeneralData },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_odb_HPLMN_Data },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ODB_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ODB_Data_sequence, hf_index, ett_gsm_map_ODB_Data);

  return offset;
}
static int dissect_odb_Data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ODB_Data(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_odb_Data);
}
static int dissect_odb_Data_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ODB_Data(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_odb_Data);
}
static int dissect_odb_data_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ODB_Data(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_odb_data);
}



static int
dissect_gsm_map_ZoneCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_regionalSubscriptionIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ZoneCode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_regionalSubscriptionIdentifier);
}
static int dissect_ZoneCodeList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ZoneCode(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ZoneCodeList_item);
}


static const ber_sequence_t ZoneCodeList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ZoneCodeList_item },
};

static int
dissect_gsm_map_ZoneCodeList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ZoneCodeList_sequence_of, hf_index, ett_gsm_map_ZoneCodeList);

  return offset;
}
static int dissect_regionalSubscriptionData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ZoneCodeList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_regionalSubscriptionData);
}



static int
dissect_gsm_map_GroupId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_TBCD_STRING(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_groupId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GroupId(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_groupId);
}
static int dissect_groupid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GroupId(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_groupid);
}


static const ber_sequence_t VoiceBroadcastData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_groupid },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_broadcastInitEntitlement },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_VoiceBroadcastData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   VoiceBroadcastData_sequence, hf_index, ett_gsm_map_VoiceBroadcastData);

  return offset;
}
static int dissect_VBSDataList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_VoiceBroadcastData(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_VBSDataList_item);
}


static const ber_sequence_t VBSDataList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_VBSDataList_item },
};

static int
dissect_gsm_map_VBSDataList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      VBSDataList_sequence_of, hf_index, ett_gsm_map_VBSDataList);

  return offset;
}
static int dissect_vbsSubscriptionData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_VBSDataList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vbsSubscriptionData);
}


static const ber_sequence_t VoiceGroupCallData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_groupId },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_VoiceGroupCallData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   VoiceGroupCallData_sequence, hf_index, ett_gsm_map_VoiceGroupCallData);

  return offset;
}
static int dissect_VGCSDataList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_VoiceGroupCallData(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_VGCSDataList_item);
}


static const ber_sequence_t VGCSDataList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_VGCSDataList_item },
};

static int
dissect_gsm_map_VGCSDataList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      VGCSDataList_sequence_of, hf_index, ett_gsm_map_VGCSDataList);

  return offset;
}
static int dissect_vgcsSubscriptionData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_VGCSDataList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vgcsSubscriptionData);
}


static const ber_sequence_t SS_EventList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_SS_EventList_item },
};

static int
dissect_gsm_map_SS_EventList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SS_EventList_sequence_of, hf_index, ett_gsm_map_SS_EventList);

  return offset;
}
static int dissect_ss_EventList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SS_EventList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_EventList);
}


static const ber_sequence_t SS_CamelData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ss_EventList },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_gsmSCF_Address },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SS_CamelData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SS_CamelData_sequence, hf_index, ett_gsm_map_SS_CamelData);

  return offset;
}
static int dissect_ss_CamelData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SS_CamelData(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_CamelData);
}


static const ber_sequence_t SS_CSI_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ss_CamelData },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToCSE_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_csi_Active_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SS_CSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SS_CSI_sequence, hf_index, ett_gsm_map_SS_CSI);

  return offset;
}
static int dissect_ss_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SS_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_CSI);
}


static const value_string gsm_map_MatchType_vals[] = {
  {   0, "inhibiting" },
  {   1, "enabling" },
  { 0, NULL }
};


static int
dissect_gsm_map_MatchType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_matchType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MatchType(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_matchType);
}


static const ber_sequence_t DestinationNumberList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_DestinationNumberList_item },
};

static int
dissect_gsm_map_DestinationNumberList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      DestinationNumberList_sequence_of, hf_index, ett_gsm_map_DestinationNumberList);

  return offset;
}
static int dissect_destinationNumberList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_DestinationNumberList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_destinationNumberList);
}



static int
dissect_gsm_map_INTEGER_1_15(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_DestinationNumberLengthList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_1_15(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_DestinationNumberLengthList_item);
}


static const ber_sequence_t DestinationNumberLengthList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_DestinationNumberLengthList_item },
};

static int
dissect_gsm_map_DestinationNumberLengthList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      DestinationNumberLengthList_sequence_of, hf_index, ett_gsm_map_DestinationNumberLengthList);

  return offset;
}
static int dissect_destinationNumberLengthList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_DestinationNumberLengthList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_destinationNumberLengthList);
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


static const ber_sequence_t BasicServiceCriteria_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_BasicServiceCriteria_item },
};

static int
dissect_gsm_map_BasicServiceCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      BasicServiceCriteria_sequence_of, hf_index, ett_gsm_map_BasicServiceCriteria);

  return offset;
}
static int dissect_basicServiceCriteria_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicServiceCriteria(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_basicServiceCriteria);
}


static const value_string gsm_map_CallTypeCriteria_vals[] = {
  {   0, "forwarded" },
  {   1, "notForwarded" },
  { 0, NULL }
};


static int
dissect_gsm_map_CallTypeCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_callTypeCriteria_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallTypeCriteria(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callTypeCriteria);
}



static int
dissect_gsm_map_CauseValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_T_CauseValueCriteria_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CauseValue(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_T_CauseValueCriteria_item);
}
static int dissect_O_CauseValueCriteria_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CauseValue(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_O_CauseValueCriteria_item);
}


static const ber_sequence_t O_CauseValueCriteria_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_O_CauseValueCriteria_item },
};

static int
dissect_gsm_map_O_CauseValueCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      O_CauseValueCriteria_sequence_of, hf_index, ett_gsm_map_O_CauseValueCriteria);

  return offset;
}
static int dissect_o_CauseValueCriteria_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_O_CauseValueCriteria(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_o_CauseValueCriteria);
}


static const ber_sequence_t O_BcsmCamelTDP_Criteria_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_o_BcsmTriggerDetectionPoint },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationNumberCriteria_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_basicServiceCriteria_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callTypeCriteria_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_CauseValueCriteria_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_O_BcsmCamelTDP_Criteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   O_BcsmCamelTDP_Criteria_sequence, hf_index, ett_gsm_map_O_BcsmCamelTDP_Criteria);

  return offset;
}
static int dissect_O_BcsmCamelTDPCriteriaList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_O_BcsmCamelTDP_Criteria(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_O_BcsmCamelTDPCriteriaList_item);
}


static const ber_sequence_t O_BcsmCamelTDPCriteriaList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_O_BcsmCamelTDPCriteriaList_item },
};

static int
dissect_gsm_map_O_BcsmCamelTDPCriteriaList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      O_BcsmCamelTDPCriteriaList_sequence_of, hf_index, ett_gsm_map_O_BcsmCamelTDPCriteriaList);

  return offset;
}
static int dissect_o_BcsmCamelTDP_CriteriaList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_O_BcsmCamelTDPCriteriaList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_o_BcsmCamelTDP_CriteriaList);
}
static int dissect_o_BcsmCamelTDPCriteriaList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_O_BcsmCamelTDPCriteriaList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_o_BcsmCamelTDPCriteriaList);
}
static int dissect_o_IM_BcsmCamelTDP_CriteriaList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_O_BcsmCamelTDPCriteriaList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_o_IM_BcsmCamelTDP_CriteriaList);
}



static int
dissect_gsm_map_MM_Code(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_eventMet_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MM_Code(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_eventMet);
}
static int dissect_MobilityTriggers_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MM_Code(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_MobilityTriggers_item);
}


static const ber_sequence_t MobilityTriggers_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_MobilityTriggers_item },
};

static int
dissect_gsm_map_MobilityTriggers(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      MobilityTriggers_sequence_of, hf_index, ett_gsm_map_MobilityTriggers);

  return offset;
}
static int dissect_mobilityTriggers(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MobilityTriggers(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_mobilityTriggers);
}


static const ber_sequence_t M_CSI_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mobilityTriggers },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serviceKey },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gsmSCF_Address_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToCSE_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_csi_Active_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_M_CSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   M_CSI_sequence, hf_index, ett_gsm_map_M_CSI);

  return offset;
}
static int dissect_m_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_M_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_m_CSI);
}


static const value_string gsm_map_SMS_TriggerDetectionPoint_vals[] = {
  {   1, "sms-CollectedInfo" },
  {   2, "sms-DeliveryRequest" },
  { 0, NULL }
};


static int
dissect_gsm_map_SMS_TriggerDetectionPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_sms_TriggerDetectionPoint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SMS_TriggerDetectionPoint(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sms_TriggerDetectionPoint);
}
static int dissect_sms_TriggerDetectionPoint_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SMS_TriggerDetectionPoint(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sms_TriggerDetectionPoint);
}


static const value_string gsm_map_DefaultSMS_Handling_vals[] = {
  {   0, "continueTransaction" },
  {   1, "releaseTransaction" },
  { 0, NULL }
};


static int
dissect_gsm_map_DefaultSMS_Handling(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_defaultSMS_Handling_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_DefaultSMS_Handling(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_defaultSMS_Handling);
}


static const ber_sequence_t SMS_CAMEL_TDP_Data_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_sms_TriggerDetectionPoint_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  { BER_CLASS_CON, 2, 0, dissect_gsmSCF_Address },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_defaultSMS_Handling_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SMS_CAMEL_TDP_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SMS_CAMEL_TDP_Data_sequence, hf_index, ett_gsm_map_SMS_CAMEL_TDP_Data);

  return offset;
}
static int dissect_SMS_CAMEL_TDP_DataList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SMS_CAMEL_TDP_Data(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_SMS_CAMEL_TDP_DataList_item);
}


static const ber_sequence_t SMS_CAMEL_TDP_DataList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_SMS_CAMEL_TDP_DataList_item },
};

static int
dissect_gsm_map_SMS_CAMEL_TDP_DataList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SMS_CAMEL_TDP_DataList_sequence_of, hf_index, ett_gsm_map_SMS_CAMEL_TDP_DataList);

  return offset;
}
static int dissect_sms_CAMEL_TDP_DataList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SMS_CAMEL_TDP_DataList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sms_CAMEL_TDP_DataList);
}


static const ber_sequence_t SMS_CSI_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sms_CAMEL_TDP_DataList_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camelCapabilityHandling_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToCSE_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_csi_Active_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SMS_CSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SMS_CSI_sequence, hf_index, ett_gsm_map_SMS_CSI);

  return offset;
}
static int dissect_mo_sms_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SMS_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_mo_sms_CSI);
}
static int dissect_mt_sms_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SMS_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_mt_sms_CSI);
}


static const value_string gsm_map_T_BcsmTriggerDetectionPoint_vals[] = {
  {  12, "termAttemptAuthorized" },
  {  13, "tBusy" },
  {  14, "tNoAnswer" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_BcsmTriggerDetectionPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_t_BCSM_TriggerDetectionPoint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_BcsmTriggerDetectionPoint(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_t_BCSM_TriggerDetectionPoint);
}
static int dissect_t_BcsmTriggerDetectionPoint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_BcsmTriggerDetectionPoint(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_t_BcsmTriggerDetectionPoint);
}


static const ber_sequence_t T_BcsmCamelTDPData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t_BcsmTriggerDetectionPoint },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serviceKey },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gsmSCF_Address_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_defaultCallHandling_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_BcsmCamelTDPData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_BcsmCamelTDPData_sequence, hf_index, ett_gsm_map_T_BcsmCamelTDPData);

  return offset;
}
static int dissect_T_BcsmCamelTDPDataList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_BcsmCamelTDPData(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_T_BcsmCamelTDPDataList_item);
}


static const ber_sequence_t T_BcsmCamelTDPDataList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_T_BcsmCamelTDPDataList_item },
};

static int
dissect_gsm_map_T_BcsmCamelTDPDataList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_BcsmCamelTDPDataList_sequence_of, hf_index, ett_gsm_map_T_BcsmCamelTDPDataList);

  return offset;
}
static int dissect_t_BcsmCamelTDPDataList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_BcsmCamelTDPDataList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_t_BcsmCamelTDPDataList);
}


static const ber_sequence_t T_CSI_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_t_BcsmCamelTDPDataList },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camelCapabilityHandling_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToCSE_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_csi_Active_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_CSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_CSI_sequence, hf_index, ett_gsm_map_T_CSI);

  return offset;
}
static int dissect_vt_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vt_CSI);
}
static int dissect_t_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_t_CSI);
}
static int dissect_vt_IM_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vt_IM_CSI);
}


static const ber_sequence_t T_CauseValueCriteria_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_T_CauseValueCriteria_item },
};

static int
dissect_gsm_map_T_CauseValueCriteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_CauseValueCriteria_sequence_of, hf_index, ett_gsm_map_T_CauseValueCriteria);

  return offset;
}
static int dissect_t_CauseValueCriteria_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_CauseValueCriteria(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_t_CauseValueCriteria);
}


static const ber_sequence_t T_BCSM_CAMEL_TDP_Criteria_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_t_BCSM_TriggerDetectionPoint },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_basicServiceCriteria_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_t_CauseValueCriteria_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_T_BCSM_CAMEL_TDP_Criteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_BCSM_CAMEL_TDP_Criteria_sequence, hf_index, ett_gsm_map_T_BCSM_CAMEL_TDP_Criteria);

  return offset;
}
static int dissect_T_BCSM_CAMEL_TDP_CriteriaList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_BCSM_CAMEL_TDP_Criteria(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_T_BCSM_CAMEL_TDP_CriteriaList_item);
}


static const ber_sequence_t T_BCSM_CAMEL_TDP_CriteriaList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_T_BCSM_CAMEL_TDP_CriteriaList_item },
};

static int
dissect_gsm_map_T_BCSM_CAMEL_TDP_CriteriaList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      T_BCSM_CAMEL_TDP_CriteriaList_sequence_of, hf_index, ett_gsm_map_T_BCSM_CAMEL_TDP_CriteriaList);

  return offset;
}
static int dissect_t_BCSM_CAMEL_TDP_CriteriaList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_BCSM_CAMEL_TDP_CriteriaList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_t_BCSM_CAMEL_TDP_CriteriaList);
}
static int dissect_vt_BCSM_CAMEL_TDP_CriteriaList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_BCSM_CAMEL_TDP_CriteriaList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vt_BCSM_CAMEL_TDP_CriteriaList);
}
static int dissect_vt_IM_BCSM_CAMEL_TDP_CriteriaList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_BCSM_CAMEL_TDP_CriteriaList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vt_IM_BCSM_CAMEL_TDP_CriteriaList);
}


static const ber_sequence_t DP_AnalysedInfoCriterium_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_dialledNumber },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serviceKey },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_gsmSCF_Address },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_defaultCallHandling },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_DP_AnalysedInfoCriterium(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DP_AnalysedInfoCriterium_sequence, hf_index, ett_gsm_map_DP_AnalysedInfoCriterium);

  return offset;
}
static int dissect_DP_AnalysedInfoCriteriaList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_DP_AnalysedInfoCriterium(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_DP_AnalysedInfoCriteriaList_item);
}


static const ber_sequence_t DP_AnalysedInfoCriteriaList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_DP_AnalysedInfoCriteriaList_item },
};

static int
dissect_gsm_map_DP_AnalysedInfoCriteriaList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      DP_AnalysedInfoCriteriaList_sequence_of, hf_index, ett_gsm_map_DP_AnalysedInfoCriteriaList);

  return offset;
}
static int dissect_dp_AnalysedInfoCriteriaList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_DP_AnalysedInfoCriteriaList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_dp_AnalysedInfoCriteriaList);
}


static const ber_sequence_t D_CSI_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dp_AnalysedInfoCriteriaList_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camelCapabilityHandling_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToCSE_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_csi_Active_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_D_CSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   D_CSI_sequence, hf_index, ett_gsm_map_D_CSI);

  return offset;
}
static int dissect_d_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_D_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_d_CSI);
}
static int dissect_d_csi_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_D_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_d_csi);
}
static int dissect_d_IM_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_D_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_d_IM_CSI);
}


static const value_string gsm_map_MT_SMS_TPDU_Type_vals[] = {
  {   0, "sms-DELIVER" },
  {   1, "sms-SUBMIT-REPORT" },
  {   2, "sms-STATUS-REPORT" },
  { 0, NULL }
};


static int
dissect_gsm_map_MT_SMS_TPDU_Type(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_TPDU_TypeCriterion_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MT_SMS_TPDU_Type(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_TPDU_TypeCriterion_item);
}


static const ber_sequence_t TPDU_TypeCriterion_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_TPDU_TypeCriterion_item },
};

static int
dissect_gsm_map_TPDU_TypeCriterion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      TPDU_TypeCriterion_sequence_of, hf_index, ett_gsm_map_TPDU_TypeCriterion);

  return offset;
}
static int dissect_tpdu_TypeCriterion_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_TPDU_TypeCriterion(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_tpdu_TypeCriterion);
}


static const ber_sequence_t MT_smsCAMELTDP_Criteria_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_sms_TriggerDetectionPoint },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tpdu_TypeCriterion_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_MT_smsCAMELTDP_Criteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MT_smsCAMELTDP_Criteria_sequence, hf_index, ett_gsm_map_MT_smsCAMELTDP_Criteria);

  return offset;
}
static int dissect_MT_smsCAMELTDP_CriteriaList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MT_smsCAMELTDP_Criteria(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_MT_smsCAMELTDP_CriteriaList_item);
}


static const ber_sequence_t MT_smsCAMELTDP_CriteriaList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_MT_smsCAMELTDP_CriteriaList_item },
};

static int
dissect_gsm_map_MT_smsCAMELTDP_CriteriaList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      MT_smsCAMELTDP_CriteriaList_sequence_of, hf_index, ett_gsm_map_MT_smsCAMELTDP_CriteriaList);

  return offset;
}
static int dissect_mt_smsCAMELTDP_CriteriaList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MT_smsCAMELTDP_CriteriaList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_mt_smsCAMELTDP_CriteriaList);
}


static const ber_sequence_t VlrCamelSubscriptionInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_CSI_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_CSI_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_BcsmCamelTDP_CriteriaList_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tif_CSI_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_m_CSI_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mo_sms_CSI_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vt_CSI_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_t_BCSM_CAMEL_TDP_CriteriaList_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_d_CSI_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mt_sms_CSI_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mt_smsCAMELTDP_CriteriaList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_VlrCamelSubscriptionInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   VlrCamelSubscriptionInfo_sequence, hf_index, ett_gsm_map_VlrCamelSubscriptionInfo);

  return offset;
}
static int dissect_vlrCamelSubscriptionInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_VlrCamelSubscriptionInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vlrCamelSubscriptionInfo);
}



static int
dissect_gsm_map_NAEA_CIC(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_naea_PreferredCIC_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NAEA_CIC(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_naea_PreferredCIC);
}


static const ber_sequence_t NAEA_PreferredCI_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_naea_PreferredCIC_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_NAEA_PreferredCI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NAEA_PreferredCI_sequence, hf_index, ett_gsm_map_NAEA_PreferredCI);

  return offset;
}
static int dissect_naea_PreferredCI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NAEA_PreferredCI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_naea_PreferredCI);
}



static int
dissect_gsm_map_ContextId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_pdp_ContextId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ContextId(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_pdp_ContextId);
}
static int dissect_ContextIdList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ContextId(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ContextIdList_item);
}
static int dissect_pdp_ContextIdentifier_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ContextId(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_pdp_ContextIdentifier);
}



static int
dissect_gsm_map_PDP_Type(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 543 "gsmmap.cnf"
	guint8 pdp_type_org;
	tvbuff_t	*parameter_tvb;


  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


 if (!parameter_tvb)
	return offset;
	proto_tree_add_item(tree, hf_gsm_map_pdp_type_org, parameter_tvb, 0,1,FALSE);
	pdp_type_org = tvb_get_guint8(parameter_tvb,1);
	switch (pdp_type_org){
		case 0: /* ETSI */
			proto_tree_add_item(tree, hf_gsm_map_etsi_pdp_type_number, parameter_tvb, 0,1,FALSE);
			break;
		case 1: /* IETF */
			proto_tree_add_item(tree, hf_gsm_map_ietf_pdp_type_number, parameter_tvb, 0,1,FALSE);
			break;
		default:
		break;
	}



  return offset;
}
static int dissect_pdp_Type_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PDP_Type(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_pdp_Type);
}



static int
dissect_gsm_map_PDP_Address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_pdp_Address_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PDP_Address(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_pdp_Address);
}



int
dissect_gsm_map_QoS_Subscribed(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 569 "gsmmap.cnf"

	tvbuff_t	*parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


	 if (!parameter_tvb)
		return offset;
	de_sm_qos(parameter_tvb, tree, 0, 3, NULL,0);



  return offset;
}
static int dissect_qos_Subscribed_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_QoS_Subscribed(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_qos_Subscribed);
}



static int
dissect_gsm_map_APN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_apn_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_APN(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_apn);
}
static int dissect_apn_Subscribed_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_APN(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_apn_Subscribed);
}
static int dissect_apn_InUse_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_APN(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_apn_InUse);
}
static int dissect_lcsAPN_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_APN(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsAPN);
}



int
dissect_gsm_map_Ext_QoS_Subscribed(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 583 "gsmmap.cnf"

	tvbuff_t	*parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


	if (!parameter_tvb)
		return offset;
	dissect_gsm_map_ext_qos_subscribed(tvb, pinfo, tree);



  return offset;
}
static int dissect_ext_QoS_Subscribed_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_QoS_Subscribed(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_QoS_Subscribed);
}
static int dissect_ext_qos_Subscribed_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_QoS_Subscribed(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_qos_Subscribed);
}
static int dissect_qos_Requested_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_QoS_Subscribed(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_qos_Requested);
}
static int dissect_qos_Negotiated_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_QoS_Subscribed(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_qos_Negotiated);
}



static int
dissect_gsm_map_ChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_chargingCharacteristics_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ChargingCharacteristics(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_chargingCharacteristics);
}
static int dissect_pdp_ChargingCharacteristics_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ChargingCharacteristics(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_pdp_ChargingCharacteristics);
}



int
dissect_gsm_map_Ext2_QoS_Subscribed(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_ext2_QoS_Subscribed_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext2_QoS_Subscribed(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext2_QoS_Subscribed);
}
static int dissect_qos2_Subscribed_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext2_QoS_Subscribed(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_qos2_Subscribed);
}
static int dissect_qos2_Requested_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext2_QoS_Subscribed(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_qos2_Requested);
}
static int dissect_qos2_Negotiated_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext2_QoS_Subscribed(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_qos2_Negotiated);
}


static const ber_sequence_t PDP_Context_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pdp_ContextId },
  { BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_pdp_Type_impl },
  { BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pdp_Address_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_qos_Subscribed_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vplmnAddressAllowed_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_apn_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ext_QoS_Subscribed_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pdp_ChargingCharacteristics_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ext2_QoS_Subscribed_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PDP_Context(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PDP_Context_sequence, hf_index, ett_gsm_map_PDP_Context);

  return offset;
}
static int dissect_GPRSDataList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PDP_Context(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_GPRSDataList_item);
}


static const ber_sequence_t GPRSDataList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_GPRSDataList_item },
};

static int
dissect_gsm_map_GPRSDataList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      GPRSDataList_sequence_of, hf_index, ett_gsm_map_GPRSDataList);

  return offset;
}
static int dissect_gprsDataList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GPRSDataList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gprsDataList);
}


static const ber_sequence_t GPRSSubscriptionData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_completeDataListIncluded },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprsDataList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_GPRSSubscriptionData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GPRSSubscriptionData_sequence, hf_index, ett_gsm_map_GPRSSubscriptionData);

  return offset;
}
static int dissect_gprsSubscriptionData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GPRSSubscriptionData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gprsSubscriptionData);
}


static const value_string gsm_map_NetworkAccessMode_vals[] = {
  {   0, "bothMSCAndSGSN" },
  {   1, "onlyMSC" },
  {   2, "onlySGSN" },
  { 0, NULL }
};


static int
dissect_gsm_map_NetworkAccessMode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_networkAccessMode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NetworkAccessMode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_networkAccessMode);
}


static const value_string gsm_map_LSAOnlyAccessIndicator_vals[] = {
  {   0, "accessOutsideLSAsAllowed" },
  {   1, "accessOutsideLSAsRestricted" },
  { 0, NULL }
};


static int
dissect_gsm_map_LSAOnlyAccessIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_lsaOnlyAccessIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LSAOnlyAccessIndicator(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lsaOnlyAccessIndicator);
}



int
dissect_gsm_map_LSAIdentity(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_lsaIdentity_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LSAIdentity(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lsaIdentity);
}
static int dissect_LSAIdentityList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LSAIdentity(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_LSAIdentityList_item);
}
static int dissect_selectedLSA_Id_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LSAIdentity(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_selectedLSA_Id);
}
static int dissect_selectedLSAIdentity(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LSAIdentity(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_selectedLSAIdentity);
}



static int
dissect_gsm_map_LSAAttributes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_lsaAttributes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LSAAttributes(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lsaAttributes);
}


static const ber_sequence_t LSAData_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_lsaIdentity_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lsaAttributes_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lsaActiveModeIndicator_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LSAData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LSAData_sequence, hf_index, ett_gsm_map_LSAData);

  return offset;
}
static int dissect_LSADataList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LSAData(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_LSADataList_item);
}


static const ber_sequence_t LSADataList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_LSADataList_item },
};

static int
dissect_gsm_map_LSADataList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      LSADataList_sequence_of, hf_index, ett_gsm_map_LSADataList);

  return offset;
}
static int dissect_lsaDataList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LSADataList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lsaDataList);
}


static const ber_sequence_t LSAInformation_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_completeDataListIncluded },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lsaOnlyAccessIndicator_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lsaDataList_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LSAInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LSAInformation_sequence, hf_index, ett_gsm_map_LSAInformation);

  return offset;
}
static int dissect_lsaInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LSAInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lsaInformation);
}


static const ber_sequence_t GMLC_List_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_GMLC_List_item },
};

static int
dissect_gsm_map_GMLC_List(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      GMLC_List_sequence_of, hf_index, ett_gsm_map_GMLC_List);

  return offset;
}
static int dissect_gmlc_List_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GMLC_List(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gmlc_List);
}


const value_string gsm_map_NotificationToMSUser_vals[] = {
  {   0, "notifyLocationAllowed" },
  {   1, "notifyAndVerify-LocationAllowedIfNoResponse" },
  {   2, "notifyAndVerify-LocationNotAllowedIfNoResponse" },
  {   3, "locationNotAllowed" },
  { 0, NULL }
};


int
dissect_gsm_map_NotificationToMSUser(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_notificationToMSUser_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NotificationToMSUser(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_notificationToMSUser);
}


static const ber_sequence_t LCSClientExternalID_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_externalAddress_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_LCSClientExternalID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LCSClientExternalID_sequence, hf_index, ett_gsm_map_LCSClientExternalID);

  return offset;
}
static int dissect_clientIdentity(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSClientExternalID(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_clientIdentity);
}
static int dissect_lcsClientExternalID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSClientExternalID(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsClientExternalID);
}


static const value_string gsm_map_GMLC_Restriction_vals[] = {
  {   0, "gmlc-List" },
  {   1, "home-Country" },
  { 0, NULL }
};


static int
dissect_gsm_map_GMLC_Restriction(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_gmlc_Restriction_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GMLC_Restriction(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gmlc_Restriction);
}


static const ber_sequence_t ExternalClient_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_clientIdentity },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gmlc_Restriction_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToMSUser_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ExternalClient(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ExternalClient_sequence, hf_index, ett_gsm_map_ExternalClient);

  return offset;
}
static int dissect_ExternalClientList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalClient(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ExternalClientList_item);
}
static int dissect_Ext_ExternalClientList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalClient(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_Ext_ExternalClientList_item);
}


static const ber_sequence_t ExternalClientList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ExternalClientList_item },
};

static int
dissect_gsm_map_ExternalClientList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ExternalClientList_sequence_of, hf_index, ett_gsm_map_ExternalClientList);

  return offset;
}
static int dissect_externalClientList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalClientList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_externalClientList);
}


static const value_string gsm_map_LCSClientInternalID_vals[] = {
  {   0, "broadcastService" },
  {   1, "o-andM-HPLMN" },
  {   2, "o-andM-VPLMN" },
  {   3, "anonymousLocation" },
  {   4, "targetMSsubscribedService" },
  { 0, NULL }
};


static int
dissect_gsm_map_LCSClientInternalID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_PLMNClientList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSClientInternalID(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_PLMNClientList_item);
}
static int dissect_lcsClientInternalID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSClientInternalID(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsClientInternalID);
}


static const ber_sequence_t PLMNClientList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_PLMNClientList_item },
};

static int
dissect_gsm_map_PLMNClientList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      PLMNClientList_sequence_of, hf_index, ett_gsm_map_PLMNClientList);

  return offset;
}
static int dissect_plmnClientList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PLMNClientList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_plmnClientList);
}


static const ber_sequence_t Ext_ExternalClientList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_Ext_ExternalClientList_item },
};

static int
dissect_gsm_map_Ext_ExternalClientList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Ext_ExternalClientList_sequence_of, hf_index, ett_gsm_map_Ext_ExternalClientList);

  return offset;
}
static int dissect_ext_externalClientList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_ExternalClientList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ext_externalClientList);
}



int
dissect_gsm_map_LCSServiceTypeID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_serviceTypeIdentity(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSServiceTypeID(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_serviceTypeIdentity);
}
static int dissect_lcsServiceTypeID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSServiceTypeID(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsServiceTypeID);
}


static const ber_sequence_t ServiceType_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serviceTypeIdentity },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gmlc_Restriction_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToMSUser_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ServiceType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ServiceType_sequence, hf_index, ett_gsm_map_ServiceType);

  return offset;
}
static int dissect_ServiceTypeList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ServiceType(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ServiceTypeList_item);
}


static const ber_sequence_t ServiceTypeList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ServiceTypeList_item },
};

static int
dissect_gsm_map_ServiceTypeList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ServiceTypeList_sequence_of, hf_index, ett_gsm_map_ServiceTypeList);

  return offset;
}
static int dissect_serviceTypeList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ServiceTypeList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_serviceTypeList);
}


static const ber_sequence_t LCS_PrivacyClass_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ext_ss_Status },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToMSUser_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_externalClientList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_plmnClientList_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ext_externalClientList_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serviceTypeList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LCS_PrivacyClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LCS_PrivacyClass_sequence, hf_index, ett_gsm_map_LCS_PrivacyClass);

  return offset;
}
static int dissect_LCS_PrivacyExceptionList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCS_PrivacyClass(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_LCS_PrivacyExceptionList_item);
}


static const ber_sequence_t LCS_PrivacyExceptionList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_LCS_PrivacyExceptionList_item },
};

static int
dissect_gsm_map_LCS_PrivacyExceptionList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      LCS_PrivacyExceptionList_sequence_of, hf_index, ett_gsm_map_LCS_PrivacyExceptionList);

  return offset;
}
static int dissect_lcs_PrivacyExceptionList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCS_PrivacyExceptionList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_PrivacyExceptionList);
}
static int dissect_add_lcs_PrivacyExceptionList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCS_PrivacyExceptionList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_add_lcs_PrivacyExceptionList);
}


static const ber_sequence_t MOLR_Class_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ext_ss_Status },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_MOLR_Class(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MOLR_Class_sequence, hf_index, ett_gsm_map_MOLR_Class);

  return offset;
}
static int dissect_MOLR_List_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MOLR_Class(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_MOLR_List_item);
}


static const ber_sequence_t MOLR_List_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_MOLR_List_item },
};

static int
dissect_gsm_map_MOLR_List(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      MOLR_List_sequence_of, hf_index, ett_gsm_map_MOLR_List);

  return offset;
}
static int dissect_molr_List_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MOLR_List(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_molr_List);
}


static const ber_sequence_t LCSInformation_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gmlc_List_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcs_PrivacyExceptionList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_molr_List_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_add_lcs_PrivacyExceptionList },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LCSInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LCSInformation_sequence, hf_index, ett_gsm_map_LCSInformation);

  return offset;
}
static int dissect_lcsInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsInformation);
}



static int
dissect_gsm_map_IST_AlertTimerValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_istAlertTimer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IST_AlertTimerValue(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_istAlertTimer);
}



static int
dissect_gsm_map_MaxMC_Bearers(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_nbrSB_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MaxMC_Bearers(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_nbrSB);
}



static int
dissect_gsm_map_MC_Bearers(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_nbrUser_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MC_Bearers(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_nbrUser);
}
static int dissect_nbrSN_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MC_Bearers(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_nbrSN);
}


static const ber_sequence_t MC_SS_Info_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ss_Code_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ext_ss_Status_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_nbrSB_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_nbrUser_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_MC_SS_Info(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MC_SS_Info_sequence, hf_index, ett_gsm_map_MC_SS_Info);

  return offset;
}
static int dissect_mc_SS_Info_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MC_SS_Info(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_mc_SS_Info);
}



static int
dissect_gsm_map_CS_AllocationRetentionPriority(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cs_AllocationRetentionPriority_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CS_AllocationRetentionPriority(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cs_AllocationRetentionPriority);
}


static const value_string gsm_map_GPRS_TriggerDetectionPoint_vals[] = {
  {   1, "attach" },
  {   2, "attachChangeOfPosition" },
  {  11, "pdp-ContextEstablishment" },
  {  12, "pdp-ContextEstablishmentAcknowledgement" },
  {  14, "pdp-ContextChangeOfPosition" },
  { 0, NULL }
};


static int
dissect_gsm_map_GPRS_TriggerDetectionPoint(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_gprs_TriggerDetectionPoint_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GPRS_TriggerDetectionPoint(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gprs_TriggerDetectionPoint);
}


static const value_string gsm_map_DefaultGPRS_Handling_vals[] = {
  {   0, "continueTransaction" },
  {   1, "releaseTransaction" },
  { 0, NULL }
};


static int
dissect_gsm_map_DefaultGPRS_Handling(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_defaultSessionHandling_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_DefaultGPRS_Handling(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_defaultSessionHandling);
}


static const ber_sequence_t GPRS_CamelTDPData_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprs_TriggerDetectionPoint_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_serviceKey_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gsmSCF_Address_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_defaultSessionHandling_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_GPRS_CamelTDPData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GPRS_CamelTDPData_sequence, hf_index, ett_gsm_map_GPRS_CamelTDPData);

  return offset;
}
static int dissect_GPRS_CamelTDPDataList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GPRS_CamelTDPData(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_GPRS_CamelTDPDataList_item);
}


static const ber_sequence_t GPRS_CamelTDPDataList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_GPRS_CamelTDPDataList_item },
};

static int
dissect_gsm_map_GPRS_CamelTDPDataList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      GPRS_CamelTDPDataList_sequence_of, hf_index, ett_gsm_map_GPRS_CamelTDPDataList);

  return offset;
}
static int dissect_gprs_CamelTDPDataList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GPRS_CamelTDPDataList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gprs_CamelTDPDataList);
}


static const ber_sequence_t GPRS_CSI_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprs_CamelTDPDataList_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camelCapabilityHandling_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToCSE_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_csi_Active_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_GPRS_CSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GPRS_CSI_sequence, hf_index, ett_gsm_map_GPRS_CSI);

  return offset;
}
static int dissect_gprs_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GPRS_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gprs_CSI);
}


static const ber_sequence_t MG_CSI_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mobilityTriggers },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serviceKey },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gsmSCF_Address_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToCSE_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_csi_Active_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_MG_CSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MG_CSI_sequence, hf_index, ett_gsm_map_MG_CSI);

  return offset;
}
static int dissect_mg_csi_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MG_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_mg_csi);
}


static const ber_sequence_t SGSN_CAMEL_SubscriptionInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprs_CSI_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mo_sms_CSI_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mt_sms_CSI_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mt_smsCAMELTDP_CriteriaList_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mg_csi_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SGSN_CAMEL_SubscriptionInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SGSN_CAMEL_SubscriptionInfo_sequence, hf_index, ett_gsm_map_SGSN_CAMEL_SubscriptionInfo);

  return offset;
}
static int dissect_sgsn_CAMEL_SubscriptionInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SGSN_CAMEL_SubscriptionInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sgsn_CAMEL_SubscriptionInfo);
}


static const asn_namedbit AccessRestrictionData_bits[] = {
  {  0, &hf_gsm_map_AccessRestrictionData_utranNotAllowed, -1, -1, "utranNotAllowed", NULL },
  {  1, &hf_gsm_map_AccessRestrictionData_geranNotAllowed, -1, -1, "geranNotAllowed", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_AccessRestrictionData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    AccessRestrictionData_bits, hf_index, ett_gsm_map_AccessRestrictionData,
                                    NULL);

  return offset;
}
static int dissect_accessRestrictionData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AccessRestrictionData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_accessRestrictionData);
}


static const ber_sequence_t InsertSubscriberDataArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_category_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_subscriberStatus_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_bearerserviceList_impl },
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
  { BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_istAlertTimer_impl },
  { BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_superChargerSupportedInHLR_impl },
  { BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mc_SS_Info_impl },
  { BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cs_AllocationRetentionPriority_impl },
  { BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgsn_CAMEL_SubscriptionInfo_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_chargingCharacteristics_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_accessRestrictionData_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_InsertSubscriberDataArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InsertSubscriberDataArg_sequence, hf_index, ett_gsm_map_InsertSubscriberDataArg);

  return offset;
}


static const ber_sequence_t SS_List_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_SS_List_item },
};

static int
dissect_gsm_map_SS_List(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SS_List_sequence_of, hf_index, ett_gsm_map_SS_List);

  return offset;
}
static int dissect_ss_List_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SS_List(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_List);
}
static int dissect_ss_List2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SS_List(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_List2);
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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

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
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_offeredCamel4CSIs_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_InsertSubscriberDataRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InsertSubscriberDataRes_sequence, hf_index, ett_gsm_map_InsertSubscriberDataRes);

  return offset;
}


static const ber_sequence_t BasicServiceList_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_BasicServiceList_item },
};

static int
dissect_gsm_map_BasicServiceList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      BasicServiceList_sequence_of, hf_index, ett_gsm_map_BasicServiceList);

  return offset;
}
static int dissect_basicServiceList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicServiceList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_basicServiceList);
}


static const ber_sequence_t ContextIdList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_ContextIdList_item },
};

static int
dissect_gsm_map_ContextIdList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ContextIdList_sequence_of, hf_index, ett_gsm_map_ContextIdList);

  return offset;
}
static int dissect_contextIdList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ContextIdList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_contextIdList);
}


static const value_string gsm_map_GPRSSubscriptionDataWithdraw_vals[] = {
  {   0, "allGPRSData" },
  {   1, "contextIdList" },
  { 0, NULL }
};

static const ber_choice_t GPRSSubscriptionDataWithdraw_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_allGPRSData },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_contextIdList },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_GPRSSubscriptionDataWithdraw(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 GPRSSubscriptionDataWithdraw_choice, hf_index, ett_gsm_map_GPRSSubscriptionDataWithdraw,
                                 NULL);

  return offset;
}
static int dissect_gprsSubscriptionDataWithdraw_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GPRSSubscriptionDataWithdraw(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gprsSubscriptionDataWithdraw);
}


static const ber_sequence_t LSAIdentityList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_LSAIdentityList_item },
};

static int
dissect_gsm_map_LSAIdentityList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      LSAIdentityList_sequence_of, hf_index, ett_gsm_map_LSAIdentityList);

  return offset;
}
static int dissect_lsaIdentityList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LSAIdentityList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lsaIdentityList);
}


static const value_string gsm_map_LSAInformationWithdraw_vals[] = {
  {   0, "allLSAData" },
  {   1, "lsaIdentityList" },
  { 0, NULL }
};

static const ber_choice_t LSAInformationWithdraw_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_allLSAData },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_lsaIdentityList },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LSAInformationWithdraw(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 LSAInformationWithdraw_choice, hf_index, ett_gsm_map_LSAInformationWithdraw,
                                 NULL);

  return offset;
}
static int dissect_lsaInformationWithdraw_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LSAInformationWithdraw(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lsaInformationWithdraw);
}


static const asn_namedbit SpecificCSI_Withdraw_bits[] = {
  {  0, &hf_gsm_map_SpecificCSI_Withdraw_o_csi, -1, -1, "o-csi", NULL },
  {  1, &hf_gsm_map_SpecificCSI_Withdraw_ss_csi, -1, -1, "ss-csi", NULL },
  {  2, &hf_gsm_map_SpecificCSI_Withdraw_tif_csi, -1, -1, "tif-csi", NULL },
  {  3, &hf_gsm_map_SpecificCSI_Withdraw_d_csi, -1, -1, "d-csi", NULL },
  {  4, &hf_gsm_map_SpecificCSI_Withdraw_vt_csi, -1, -1, "vt-csi", NULL },
  {  5, &hf_gsm_map_SpecificCSI_Withdraw_mo_sms_csi, -1, -1, "mo-sms-csi", NULL },
  {  6, &hf_gsm_map_SpecificCSI_Withdraw_m_csi, -1, -1, "m-csi", NULL },
  {  7, &hf_gsm_map_SpecificCSI_Withdraw_gprs_csi, -1, -1, "gprs-csi", NULL },
  {  8, &hf_gsm_map_SpecificCSI_Withdraw_t_csi, -1, -1, "t-csi", NULL },
  {  9, &hf_gsm_map_SpecificCSI_Withdraw_mt_sms_csi, -1, -1, "mt-sms-csi", NULL },
  { 10, &hf_gsm_map_SpecificCSI_Withdraw_mg_csi, -1, -1, "mg-csi", NULL },
  { 11, &hf_gsm_map_SpecificCSI_Withdraw_o_IM_CSI, -1, -1, "o-IM-CSI", NULL },
  { 12, &hf_gsm_map_SpecificCSI_Withdraw_d_IM_CSI, -1, -1, "d-IM-CSI", NULL },
  { 13, &hf_gsm_map_SpecificCSI_Withdraw_vt_IM_CSI, -1, -1, "vt-IM-CSI", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_SpecificCSI_Withdraw(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    SpecificCSI_Withdraw_bits, hf_index, ett_gsm_map_SpecificCSI_Withdraw,
                                    NULL);

  return offset;
}
static int dissect_specificCSI_Withdraw_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SpecificCSI_Withdraw(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_specificCSI_Withdraw);
}
static int dissect_specificCSIDeletedList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SpecificCSI_Withdraw(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_specificCSIDeletedList);
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
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprsSubscriptionDataWithdraw_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_roamingRestrictedInSgsnDueToUnsuppportedFeature_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_lsaInformationWithdraw_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gmlc_ListWithdraw_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL, dissect_istInformationWithdraw },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_specificCSI_Withdraw_impl },
  { BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_chargingCharacteristicsWithdraw_impl },
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



int
dissect_gsm_map_SS_Status(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 301 "gsmmap.cnf"

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
  return dissect_gsm_map_SS_Status(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Status);
}
static int dissect_ss_Status_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SS_Status(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Status);
}



static int
dissect_gsm_map_BearerServiceCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_bearerService_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BearerServiceCode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_bearerService);
}



static int
dissect_gsm_map_TeleserviceCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_teleservice_code_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_TeleserviceCode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_teleservice_code);
}


static const value_string gsm_map_BasicServiceCode_vals[] = {
  {   2, "bearerService" },
  {   3, "teleservice" },
  { 0, NULL }
};

static const ber_choice_t BasicServiceCode_choice[] = {
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_bearerService_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_teleservice_code_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_BasicServiceCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 BasicServiceCode_choice, hf_index, ett_gsm_map_BasicServiceCode,
                                 NULL);

  return offset;
}
static int dissect_basicService(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicServiceCode(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_basicService);
}
static int dissect_basicServiceGroup_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BasicServiceCode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_basicServiceGroup);
}


static const ber_sequence_t CallBarringFeature_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_basicService },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_Status_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CallBarringFeature(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CallBarringFeature_sequence, hf_index, ett_gsm_map_CallBarringFeature);

  return offset;
}
static int dissect_CallBarringFeatureList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallBarringFeature(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_CallBarringFeatureList_item);
}


static const ber_sequence_t CallBarringFeatureList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CallBarringFeatureList_item },
};

static int
dissect_gsm_map_CallBarringFeatureList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CallBarringFeatureList_sequence_of, hf_index, ett_gsm_map_CallBarringFeatureList);

  return offset;
}
static int dissect_callBarringFeatureList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallBarringFeatureList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_callBarringFeatureList);
}



static int
dissect_gsm_map_ForwardingOptions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

#line 526 "gsmmap.cnf"

	proto_tree_add_item(tree, hf_gsm_map_notification_to_forwarding_party, tvb, 0,1,FALSE);
	proto_tree_add_item(tree, hf_gsm_map_redirecting_presentation, tvb, 0,1,FALSE);
	proto_tree_add_item(tree, hf_gsm_map_notification_to_calling_party, tvb, 0,1,FALSE);
	proto_tree_add_item(tree, hf_gsm_map_forwarding_reason, tvb, 0,1,FALSE);

  return offset;
}
static int dissect_forwardingOptions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ForwardingOptions(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingOptions);
}



static int
dissect_gsm_map_NoReplyConditionTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_noReplyConditionTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NoReplyConditionTime(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_noReplyConditionTime);
}


static const ber_sequence_t ForwardingFeature_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_basicService },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_Status_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToSubaddress_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardingOptions_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noReplyConditionTime_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_longForwardedToNumber_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ForwardingFeature(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ForwardingFeature_sequence, hf_index, ett_gsm_map_ForwardingFeature);

  return offset;
}
static int dissect_ForwardingFeatureList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ForwardingFeature(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ForwardingFeatureList_item);
}


static const ber_sequence_t ForwardingFeatureList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ForwardingFeatureList_item },
};

static int
dissect_gsm_map_ForwardingFeatureList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      ForwardingFeatureList_sequence_of, hf_index, ett_gsm_map_ForwardingFeatureList);

  return offset;
}
static int dissect_forwardingFeatureList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ForwardingFeatureList(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingFeatureList);
}
static int dissect_forwardingFeatureList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ForwardingFeatureList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingFeatureList);
}



static int
dissect_gsm_map_LongForwardedToNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ForwardingInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_forwardingFeatureList },
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


static const ber_sequence_t CallBarringInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_callBarringFeatureList },
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
dissect_gsm_map_HLR_Id(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_IMSI(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_HLR_List_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_HLR_Id(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_HLR_List_item);
}


static const ber_sequence_t HLR_List_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HLR_List_item },
};

static int
dissect_gsm_map_HLR_List(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      HLR_List_sequence_of, hf_index, ett_gsm_map_HLR_List);

  return offset;
}
static int dissect_hlr_List(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_HLR_List(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_hlr_List);
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



static int
dissect_gsm_map_Hlr_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_traceType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER_0_255(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_traceType);
}



static int
dissect_gsm_map_OCTET_STRING_SIZE_1_20(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_omc_Id_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_20(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_omc_Id);
}
static int dissect_ss_EventSpecification_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1_20(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_EventSpecification_item);
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


static const ber_sequence_t CUG_CheckInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cug_Interlock },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cug_OutgoingAccess },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CUG_CheckInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CUG_CheckInfo_sequence, hf_index, ett_gsm_map_CUG_CheckInfo);

  return offset;
}
static int dissect_cug_CheckInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CUG_CheckInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cug_CheckInfo);
}



static int
dissect_gsm_map_NumberOfForwarding(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_numberOfForwarding_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NumberOfForwarding(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_numberOfForwarding);
}


static const value_string gsm_map_InterrogationType_vals[] = {
  {   0, "basicCall" },
  {   1, "forwarding" },
  { 0, NULL }
};


static int
dissect_gsm_map_InterrogationType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_interrogationType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_InterrogationType(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_interrogationType);
}



static int
dissect_gsm_map_OR_Phase(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_or_Capability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OR_Phase(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_or_Capability);
}



static int
dissect_gsm_map_CallReferenceNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_callReferenceNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallReferenceNumber(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callReferenceNumber);
}


static const value_string gsm_map_ForwardingReason_vals[] = {
  {   0, "notReachable" },
  {   1, "busy" },
  {   2, "noReply" },
  { 0, NULL }
};


static int
dissect_gsm_map_ForwardingReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_forwardingReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ForwardingReason(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingReason);
}


static const ber_sequence_t ExternalSignalInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_protocolId },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_signalInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ExternalSignalInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ExternalSignalInfo_sequence, hf_index, ett_gsm_map_ExternalSignalInfo);

  return offset;
}
static int dissect_networkSignalInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalSignalInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_networkSignalInfo);
}
static int dissect_networkSignalInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalSignalInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_networkSignalInfo);
}
static int dissect_networkSignalInfo2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalSignalInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_networkSignalInfo2);
}
static int dissect_gsm_BearerCapability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalSignalInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gsm_BearerCapability);
}
static int dissect_isdn_BearerCapability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalSignalInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_isdn_BearerCapability);
}
static int dissect_chosenChannel_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalSignalInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_chosenChannel);
}
static int dissect_lowerLayerCompatibility_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalSignalInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lowerLayerCompatibility);
}
static int dissect_highLayerCompatibility_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalSignalInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_highLayerCompatibility);
}
static int dissect_channelType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalSignalInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_channelType);
}
static int dissect_callInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalSignalInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_callInfo);
}
static int dissect_callInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExternalSignalInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callInfo);
}


static const ber_sequence_t CamelInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_supportedCamelPhases },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_suppress_T_CSI },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_offeredCamel4CSIs_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CamelInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CamelInfo_sequence, hf_index, ett_gsm_map_CamelInfo);

  return offset;
}
static int dissect_camelInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CamelInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_camelInfo);
}



static int
dissect_gsm_map_SuppressionOfAnnouncement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_suppressionOfAnnouncement_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SuppressionOfAnnouncement(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_suppressionOfAnnouncement);
}



int
dissect_gsm_map_AlertingPattern(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_alertingPattern(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AlertingPattern(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_alertingPattern);
}
static int dissect_alertingPattern_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AlertingPattern(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_alertingPattern);
}



static int
dissect_gsm_map_SupportedCCBS_Phase(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_supportedCCBS_Phase_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedCCBS_Phase(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_supportedCCBS_Phase);
}


static const value_string gsm_map_Ext_ProtocolId_vals[] = {
  {   1, "ets-300356" },
  { 0, NULL }
};


static int
dissect_gsm_map_Ext_ProtocolId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_ext_ProtocolId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_ProtocolId(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ext_ProtocolId);
}


static const ber_sequence_t Ext_ExternalSignalInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ext_ProtocolId },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_signalInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ext_ExternalSignalInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Ext_ExternalSignalInfo_sequence, hf_index, ett_gsm_map_Ext_ExternalSignalInfo);

  return offset;
}
static int dissect_additionalSignalInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_ExternalSignalInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_additionalSignalInfo);
}



static int
dissect_gsm_map_CallDiversionTreatmentIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_callDiversionTreatmentIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallDiversionTreatmentIndicator(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callDiversionTreatmentIndicator);
}


static const ber_sequence_t SendRoutingInfoArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cug_CheckInfo_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_numberOfForwarding_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_interrogationType_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_or_Interrogation_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_or_Capability_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gmsc_OrGsmSCF_Address_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callReferenceNumber_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardingReason_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_ext_basicServiceGroup_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_networkSignalInfo_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camelInfo_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_suppressionOfAnnouncement_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_alertingPattern_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Call_impl },
  { BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedCCBS_Phase_impl },
  { BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additionalSignalInfo_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_istSupportIndicator_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pre_pagingSupported_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callDiversionTreatmentIndicator_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_longFTN_Supported_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL, dissect_suppress_VT_CSI },
  { BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL, dissect_suppressIncomingCallBarring },
  { BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL, dissect_gsmSCF_InitiatedCall },
  { BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_basicServiceGroup2_impl },
  { BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_networkSignalInfo2_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendRoutingInfoArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SendRoutingInfoArg_sequence, hf_index, ett_gsm_map_SendRoutingInfoArg);

  return offset;
}


static const ber_sequence_t ForwardingData_sequence[] = {
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToNumber_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToSubaddress_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardingOptions_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_longForwardedToNumber_impl },
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


static const value_string gsm_map_RoutingInfo_vals[] = {
  {   0, "roamingNumber" },
  {   1, "forwardingData" },
  { 0, NULL }
};

static const ber_choice_t RoutingInfo_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_roamingNumber },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_forwardingData },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RoutingInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 RoutingInfo_choice, hf_index, ett_gsm_map_RoutingInfo,
                                 NULL);

  return offset;
}
static int dissect_routingInfo2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RoutingInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_routingInfo2);
}
static int dissect_routingInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RoutingInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_routingInfo);
}


static const ber_sequence_t GmscCamelSubscriptionInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_t_CSI_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_CSI_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_BcsmCamelTDP_CriteriaList_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_t_BCSM_CAMEL_TDP_CriteriaList_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_d_csi_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_GmscCamelSubscriptionInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GmscCamelSubscriptionInfo_sequence, hf_index, ett_gsm_map_GmscCamelSubscriptionInfo);

  return offset;
}
static int dissect_gmscCamelSubscriptionInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GmscCamelSubscriptionInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gmscCamelSubscriptionInfo);
}


static const ber_sequence_t CamelRoutingInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_forwardingData },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gmscCamelSubscriptionInfo_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CamelRoutingInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CamelRoutingInfo_sequence, hf_index, ett_gsm_map_CamelRoutingInfo);

  return offset;
}
static int dissect_camelRoutingInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CamelRoutingInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_camelRoutingInfo);
}


static const value_string gsm_map_ExtendedRoutingInfo_vals[] = {
  {   0, "routingInfo" },
  {   1, "camelRoutingInfo" },
  { 0, NULL }
};

static const ber_choice_t ExtendedRoutingInfo_choice[] = {
  {   0, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_routingInfo },
  {   1, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_camelRoutingInfo_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ExtendedRoutingInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ExtendedRoutingInfo_choice, hf_index, ett_gsm_map_ExtendedRoutingInfo,
                                 NULL);

  return offset;
}
static int dissect_extendedRoutingInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExtendedRoutingInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_extendedRoutingInfo);
}



int
dissect_gsm_map_AgeOfLocationInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_ageOfLocationInformation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AgeOfLocationInformation(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ageOfLocationInformation);
}
static int dissect_ageOfLocationEstimate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AgeOfLocationInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ageOfLocationEstimate);
}



int
dissect_gsm_map_GeographicalInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_geographicalInformation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GeographicalInformation(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_geographicalInformation);
}
static int dissect_geographicalInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GeographicalInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_geographicalInformation);
}



static int
dissect_gsm_map_LocationNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_locationNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LocationNumber(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_locationNumber);
}



int
dissect_gsm_map_CellGlobalIdOrServiceAreaIdFixedLength(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cellGlobalIdOrServiceAreaIdFixedLength_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CellGlobalIdOrServiceAreaIdFixedLength(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cellGlobalIdOrServiceAreaIdFixedLength);
}


static const value_string gsm_map_CellGlobalIdOrServiceAreaIdOrLAI_vals[] = {
  {   0, "cellGlobalIdOrServiceAreaIdFixedLength" },
  {   1, "laiFixedLength" },
  { 0, NULL }
};

static const ber_choice_t CellGlobalIdOrServiceAreaIdOrLAI_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_cellGlobalIdOrServiceAreaIdFixedLength_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_laiFixedLength_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CellGlobalIdOrServiceAreaIdOrLAI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CellGlobalIdOrServiceAreaIdOrLAI_choice, hf_index, ett_gsm_map_CellGlobalIdOrServiceAreaIdOrLAI,
                                 NULL);

  return offset;
}
static int dissect_cellGlobalIdOrServiceAreaIdOrLAI(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CellGlobalIdOrServiceAreaIdOrLAI(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cellGlobalIdOrServiceAreaIdOrLAI);
}
static int dissect_cellGlobalIdOrServiceAreaIdOrLAI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CellGlobalIdOrServiceAreaIdOrLAI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cellGlobalIdOrServiceAreaIdOrLAI);
}
static int dissect_cellIdOrSai_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CellGlobalIdOrServiceAreaIdOrLAI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_cellIdOrSai);
}



static int
dissect_gsm_map_GeodeticInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_geodeticInformation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GeodeticInformation(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_geodeticInformation);
}
static int dissect_geodeticInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GeodeticInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_geodeticInformation);
}


static const ber_sequence_t LocationInformation_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ageOfLocationInformation },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_geographicalInformation_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vlr_number_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationNumber_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_cellGlobalIdOrServiceAreaIdOrLAI_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_selectedLSA_Id_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msc_Number_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_geodeticInformation_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_currentLocationRetrieved_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sai_Present_impl },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_LocationInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LocationInformation_sequence, hf_index, ett_gsm_map_LocationInformation);

  return offset;
}
static int dissect_locationInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LocationInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_locationInformation);
}


const value_string gsm_map_SubscriberState_vals[] = {
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

int
dissect_gsm_map_SubscriberState(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SubscriberState_choice, hf_index, ett_gsm_map_SubscriberState,
                                 NULL);

  return offset;
}
static int dissect_subscriberState(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SubscriberState(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_subscriberState);
}



int
dissect_gsm_map_RAIdentity(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 627 "gsmmap.cnf"

	tvbuff_t	*parameter_tvb;
	proto_item *item;
	proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


	 if (!parameter_tvb)
		return offset;
	item = get_ber_last_created_item();
	subtree = proto_item_add_subtree(item, ett_gsm_map_RAIdentity);
	de_gmm_rai(parameter_tvb, subtree, 0, 3, NULL,0);



  return offset;
}
static int dissect_routeingAreaIdentity(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RAIdentity(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_routeingAreaIdentity);
}


static const ber_sequence_t LocationInformationGPRS_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_cellGlobalIdOrServiceAreaIdOrLAI },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_routeingAreaIdentity },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_geographicalInformation },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_sgsn_Number },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_selectedLSAIdentity },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_extensionContainer },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_sai_Present },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_geodeticInformation },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_currentLocationRetrieved },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL, dissect_ageOfLocationInformation },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LocationInformationGPRS(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LocationInformationGPRS_sequence, hf_index, ett_gsm_map_LocationInformationGPRS);

  return offset;
}
static int dissect_locationInformationGPRS(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LocationInformationGPRS(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_locationInformationGPRS);
}
static int dissect_locationInformationGPRS_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LocationInformationGPRS(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_locationInformationGPRS);
}



static int
dissect_gsm_map_NSAPI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_nsapi_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NSAPI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_nsapi);
}



static int
dissect_gsm_map_TransactionId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_transactionId_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_TransactionId(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_transactionId);
}



static int
dissect_gsm_map_TEID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_teid_ForGnAndGp_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_TEID(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_teid_ForGnAndGp);
}
static int dissect_teid_ForIu_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_TEID(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_teid_ForIu);
}



int
dissect_gsm_map_GPRSChargingID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_chargingId_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GPRSChargingID(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_chargingId);
}


static const ber_sequence_t PDP_ContextInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pdp_ContextIdentifier_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pdp_ContextActive_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_pdp_Type_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pdp_Address_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_apn_Subscribed_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_apn_InUse_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nsapi_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_transactionId_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_teid_ForGnAndGp_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_teid_ForIu_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ggsn_Address_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ext_qos_Subscribed_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qos_Requested_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qos_Negotiated_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_chargingId_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_chargingCharacteristics_impl },
  { BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rnc_Address_impl },
  { BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qos2_Subscribed_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qos2_Requested_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qos2_Negotiated_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PDP_ContextInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PDP_ContextInfo_sequence, hf_index, ett_gsm_map_PDP_ContextInfo);

  return offset;
}
static int dissect_PDP_ContextInfoList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PDP_ContextInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_PDP_ContextInfoList_item);
}


static const ber_sequence_t PDP_ContextInfoList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_PDP_ContextInfoList_item },
};

static int
dissect_gsm_map_PDP_ContextInfoList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      PDP_ContextInfoList_sequence_of, hf_index, ett_gsm_map_PDP_ContextInfoList);

  return offset;
}
static int dissect_ps_PDP_ActiveNotReachableForPaging_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PDP_ContextInfoList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ps_PDP_ActiveNotReachableForPaging);
}
static int dissect_ps_PDP_ActiveReachableForPaging_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PDP_ContextInfoList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ps_PDP_ActiveReachableForPaging);
}


static const value_string gsm_map_NotReachableReason_vals[] = {
  {   0, "msPurged" },
  {   1, "imsiDetached" },
  {   2, "restrictedArea" },
  {   3, "notRegistered" },
  { 0, NULL }
};


static int
dissect_gsm_map_NotReachableReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_netDetNotReachable(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NotReachableReason(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_netDetNotReachable);
}


static const value_string gsm_map_PS_SubscriberState_vals[] = {
  {   0, "notProvidedFromSGSN" },
  {   1, "ps-Detached" },
  {   2, "ps-AttachedNotReachableForPaging" },
  {   3, "ps-AttachedReachableForPaging" },
  {   4, "ps-PDP-ActiveNotReachableForPaging" },
  {   5, "ps-PDP-ActiveReachableForPaging" },
  {   6, "netDetNotReachable" },
  { 0, NULL }
};

static const ber_choice_t PS_SubscriberState_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_notProvidedFromSGSN_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ps_Detached_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ps_AttachedNotReachableForPaging_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ps_AttachedReachableForPaging_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_ps_PDP_ActiveNotReachableForPaging_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_ps_PDP_ActiveReachableForPaging_impl },
  {   6, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_netDetNotReachable },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PS_SubscriberState(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PS_SubscriberState_choice, hf_index, ett_gsm_map_PS_SubscriberState,
                                 NULL);

  return offset;
}
static int dissect_ps_SubscriberState_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PS_SubscriberState(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ps_SubscriberState);
}



int
dissect_gsm_map_MS_Classmark2(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_ms_Classmark2_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MS_Classmark2(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ms_Classmark2);
}



static int
dissect_gsm_map_MSNetworkCapability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_mSNetworkCapability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MSNetworkCapability(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_mSNetworkCapability);
}



static int
dissect_gsm_map_MSRadioAccessCapability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_mSRadioAccessCapability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MSRadioAccessCapability(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_mSRadioAccessCapability);
}


static const ber_sequence_t GPRSMSClass_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mSNetworkCapability_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mSRadioAccessCapability_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_GPRSMSClass(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GPRSMSClass_sequence, hf_index, ett_gsm_map_GPRSMSClass);

  return offset;
}
static int dissect_gprs_MS_Class_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GPRSMSClass(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_gprs_MS_Class);
}



static int
dissect_gsm_map_RouteingNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_TBCD_STRING(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_routeingNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RouteingNumber(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_routeingNumber);
}


static const value_string gsm_map_NumberPortabilityStatus_vals[] = {
  {   0, "notKnownToBePorted" },
  {   1, "ownNumberPortedOut" },
  {   2, "foreignNumberPortedToForeignNetwork" },
  {   4, "ownNumberNotPortedOut" },
  {   5, "foreignNumberPortedIn" },
  { 0, NULL }
};


static int
dissect_gsm_map_NumberPortabilityStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_numberPortabilityStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NumberPortabilityStatus(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_numberPortabilityStatus);
}


static const ber_sequence_t MNPInfoRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_routeingNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_numberPortabilityStatus_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_MNPInfoRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MNPInfoRes_sequence, hf_index, ett_gsm_map_MNPInfoRes);

  return offset;
}
static int dissect_mnpInfoRes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_MNPInfoRes(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_mnpInfoRes);
}


static const ber_sequence_t SubscriberInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationInformation_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_subscriberState },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationInformationGPRS_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_ps_SubscriberState_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imei_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ms_Classmark2_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprs_MS_Class_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mnpInfoRes_impl },
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


static const ber_sequence_t CCBS_Indicators_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Possible_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_keepCCBS_CallIndicator_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CCBS_Indicators(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CCBS_Indicators_sequence, hf_index, ett_gsm_map_CCBS_Indicators);

  return offset;
}
static int dissect_ccbs_Indicators_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CCBS_Indicators(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Indicators);
}


static const asn_namedbit AllowedServices_bits[] = {
  {  0, &hf_gsm_map_AllowedServices_firstServiceAllowed, -1, -1, "firstServiceAllowed", NULL },
  {  1, &hf_gsm_map_AllowedServices_secondServiceAllowed, -1, -1, "secondServiceAllowed", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_AllowedServices(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    AllowedServices_bits, hf_index, ett_gsm_map_AllowedServices,
                                    NULL);

  return offset;
}
static int dissect_allowedServices_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AllowedServices(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_allowedServices);
}


static const value_string gsm_map_UnavailabilityCause_vals[] = {
  {   1, "bearerServiceNotProvisioned" },
  {   2, "teleserviceNotProvisioned" },
  {   3, "absentSubscriber" },
  {   4, "busySubscriber" },
  {   5, "callBarred" },
  {   6, "cug-Reject" },
  { 0, NULL }
};


static int
dissect_gsm_map_UnavailabilityCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_unavailabilityCause_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_UnavailabilityCause(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_unavailabilityCause);
}


static const ber_sequence_t SendRoutingInfoRes_sequence[] = {
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extendedRoutingInfo },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cug_CheckInfo_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cugSubscriptionFlag_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_subscriberInfo_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_List_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_ext_basicService_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardingInterrogationRequired_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vmsc_Address_impl },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_naea_PreferredCI_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Indicators_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_numberPortabilityStatus_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_istAlertTimer_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedCamelPhasesInVMSC_impl },
  { BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_offeredCamel4CSIsInVMSC_impl },
  { BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_routingInfo2_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_List2_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_basicService2_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_allowedServices_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_unavailabilityCause_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_releaseResourcesSupported_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SendRoutingInfoRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SendRoutingInfoRes_sequence, hf_index, ett_gsm_map_SendRoutingInfoRes);

  return offset;
}


static const value_string gsm_map_SubscriberId_vals[] = {
  {   0, "imsi" },
  {   1, "tmsi" },
  { 0, NULL }
};

static const ber_choice_t SubscriberId_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_imsi },
  {   1, BER_CLASS_CON, 1, 0, dissect_tmsi },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SubscriberId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SubscriberId_choice, hf_index, ett_gsm_map_SubscriberId,
                                 NULL);

  return offset;
}


static const value_string gsm_map_SubscriberIdentity_vals[] = {
  {   0, "imsi" },
  {   1, "msisdn" },
  { 0, NULL }
};

static const ber_choice_t SubscriberIdentity_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SubscriberIdentity(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SubscriberIdentity_choice, hf_index, ett_gsm_map_SubscriberIdentity,
                                 NULL);

  return offset;
}
static int dissect_subscriberIdentity(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SubscriberIdentity(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_subscriberIdentity);
}
static int dissect_subscriberIdentity_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SubscriberIdentity(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_subscriberIdentity);
}
static int dissect_targetMS(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SubscriberIdentity(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_targetMS);
}
static int dissect_targetMS_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SubscriberIdentity(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_targetMS);
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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gsm_map_RoamingNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gsm_map_Qos_Subscribed(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gsm_map_ExtSignalInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gsm_map_Gmsc_Address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

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
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedCamelPhasesInInterrogatingNode_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additionalSignalInfo_impl },
  { BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_orNotSupportedInGMSC_impl },
  { BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pre_pagingSupported_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_longFTN_Supported_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_suppress_VT_CSI_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_offeredCamel4CSIsInInterrogatingNode_impl },
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
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_releaseResourcesSupported },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ProvideRoamingNumberRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ProvideRoamingNumberRes_sequence, hf_index, ett_gsm_map_ProvideRoamingNumberRes);

  return offset;
}



static int
dissect_gsm_map_UUIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_uuIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_UUIndicator(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uuIndicator);
}



static int
dissect_gsm_map_UUI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_uui_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_UUI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uui);
}


static const ber_sequence_t UU_Data_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uuIndicator_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uui_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uusCFInteraction_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_UU_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   UU_Data_sequence, hf_index, ett_gsm_map_UU_Data);

  return offset;
}
static int dissect_uu_Data_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_UU_Data(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_uu_Data);
}


static const ber_sequence_t ResumeCallHandlingArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callReferenceNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_ext_basicServiceGroup },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardingData_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_cug_CheckInfo_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_CSI_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Possible_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uu_Data_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_allInformationSent_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_d_csi_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_BcsmCamelTDPCriteriaList_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_basicServiceGroup2_impl },
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
dissect_gsm_map_CallDirection(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_call_Direction_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallDirection(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_call_Direction);
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
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_channelType_impl },
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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string gsm_map_ReportingState_vals[] = {
  {   0, "stopMonitoring" },
  {   1, "startMonitoring" },
  { 0, NULL }
};


static int
dissect_gsm_map_ReportingState(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_ccbs_Monitoring(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ReportingState(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Monitoring);
}


static const ber_sequence_t SetReportingStateArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_imsi },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_lmsi },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_ccbs_Monitoring },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SetReportingStateArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SetReportingStateArg_sequence, hf_index, ett_gsm_map_SetReportingStateArg);

  return offset;
}


static const value_string gsm_map_CCBS_SubscriberStatus_vals[] = {
  {   0, "ccbsNotIdle" },
  {   1, "ccbsIdle" },
  {   2, "ccbsNotReachable" },
  { 0, NULL }
};


static int
dissect_gsm_map_CCBS_SubscriberStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_ccbs_SubscriberStatus_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CCBS_SubscriberStatus(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_SubscriberStatus);
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


static const ber_sequence_t EventReportData_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_SubscriberStatus_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_EventReportData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EventReportData_sequence, hf_index, ett_gsm_map_EventReportData);

  return offset;
}
static int dissect_eventReportData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_EventReportData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_eventReportData);
}


static const value_string gsm_map_MonitoringMode_vals[] = {
  {   0, "a-side" },
  {   1, "b-side" },
  { 0, NULL }
};


static int
dissect_gsm_map_MonitoringMode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_callOutcome_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallOutcome(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callOutcome);
}


static const ber_sequence_t CallReportData_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_monitoringMode_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callOutcome_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CallReportData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CallReportData_sequence, hf_index, ett_gsm_map_CallReportData);

  return offset;
}
static int dissect_callReportdata_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallReportData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callReportdata);
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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_ruf_Outcome_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ruf_Outcome(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ruf_Outcome);
}


static const ber_sequence_t IST_AlertArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_IST_AlertArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IST_AlertArg_sequence, hf_index, ett_gsm_map_IST_AlertArg);

  return offset;
}


static const value_string gsm_map_CallTerminationIndicator_vals[] = {
  {   0, "terminateCallActivityReferred" },
  {   1, "terminateAllCallActivities" },
  { 0, NULL }
};


static int
dissect_gsm_map_CallTerminationIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_callTerminationIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallTerminationIndicator(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callTerminationIndicator);
}


static const ber_sequence_t IST_AlertRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_istAlertTimer_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_istInformationWithdraw_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callTerminationIndicator_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_IST_AlertRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IST_AlertRes_sequence, hf_index, ett_gsm_map_IST_AlertRes);

  return offset;
}


static const ber_sequence_t IST_CommandArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_IST_CommandArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IST_CommandArg_sequence, hf_index, ett_gsm_map_IST_CommandArg);

  return offset;
}


static const ber_sequence_t IST_CommandRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_IST_CommandRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IST_CommandRes_sequence, hf_index, ett_gsm_map_IST_CommandRes);

  return offset;
}


static const ber_sequence_t ReleaseResourcesArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_msrn },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ReleaseResourcesArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReleaseResourcesArg_sequence, hf_index, ett_gsm_map_ReleaseResourcesArg);

  return offset;
}


static const ber_sequence_t ReleaseResourcesRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ReleaseResourcesRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ReleaseResourcesRes_sequence, hf_index, ett_gsm_map_ReleaseResourcesRes);

  return offset;
}



static int
dissect_gsm_map_CCBS_Index(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_ccbs_Index_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CCBS_Index(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Index);
}


static const ber_sequence_t CCBS_Feature_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_Index_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_b_subscriberNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_b_subscriberSubaddress_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_basicServiceGroup_impl },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_CCBS_Feature(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CCBS_Feature_sequence, hf_index, ett_gsm_map_CCBS_Feature);

  return offset;
}
static int dissect_ccbs_Feature(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CCBS_Feature(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Feature);
}
static int dissect_ccbs_Feature_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CCBS_Feature(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Feature);
}
static int dissect_CCBS_FeatureList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CCBS_Feature(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_CCBS_FeatureList_item);
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



static int
dissect_gsm_map_TranslatedB_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SS_Data_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_Status_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ss_SubscriptionOption },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_ext_basicServiceGroupList },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_defaultPriority },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nbrUser_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SS_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SS_Data_sequence, hf_index, ett_gsm_map_SS_Data);

  return offset;
}
static int dissect_ss_Data_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SS_Data(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Data);
}


static const ber_sequence_t RegisterSS_Arg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_basicService },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToNumber_addr_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToSubaddress_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_noReplyConditionTime_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_defaultPriority_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nbrUser_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_longFTN_Supported_impl },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_RegisterSS_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RegisterSS_Arg_sequence, hf_index, ett_gsm_map_RegisterSS_Arg);

  return offset;
}


const value_string gsm_map_SS_Info_vals[] = {
  {   0, "forwardingInfo" },
  {   1, "callBarringInfo" },
  {   3, "ss-Data" },
  { 0, NULL }
};

static const ber_choice_t SS_Info_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_forwardingInfo_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_callBarringInfo_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_ss_Data_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_gsm_map_SS_Info(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SS_Info_choice, hf_index, ett_gsm_map_SS_Info,
                                 NULL);

  return offset;
}



static int
dissect_gsm_map_B_subscriberNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t CCBS_FeatureList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CCBS_FeatureList_item },
};

static int
dissect_gsm_map_CCBS_FeatureList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CCBS_FeatureList_sequence_of, hf_index, ett_gsm_map_CCBS_FeatureList);

  return offset;
}
static int dissect_ccbs_FeatureList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CCBS_FeatureList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_FeatureList);
}


static const ber_sequence_t GenericServiceInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Status },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cliRestrictionOption },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_maximumEntitledPriority_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_defaultPriority_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ccbs_FeatureList_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nbrSB_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nbrUser_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_nbrSN_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_GenericServiceInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   GenericServiceInfo_sequence, hf_index, ett_gsm_map_GenericServiceInfo);

  return offset;
}
static int dissect_genericServiceInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GenericServiceInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_genericServiceInfo);
}


const value_string gsm_map_InterrogateSS_Res_vals[] = {
  {   0, "ss-Status" },
  {   2, "basicServiceGroupList" },
  {   3, "forwardingFeatureList" },
  {   4, "genericServiceInfo" },
  { 0, NULL }
};

static const ber_choice_t InterrogateSS_Res_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ss_Status_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ext_basicServiceGroupList_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_forwardingFeatureList_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_genericServiceInfo_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_gsm_map_InterrogateSS_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 InterrogateSS_Res_choice, hf_index, ett_gsm_map_InterrogateSS_Res,
                                 NULL);

  return offset;
}



int
dissect_gsm_map_USSD_DataCodingScheme(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 446 "gsmmap.cnf"
 /*The structure of the USSD-DataCodingScheme is defined by
  * the Cell Broadcast Data Coding Scheme as described in
  * TS 3GPP TS 23.038
  * TODO: Should smpp_handle_dcs return encoding type? - like 7bit Alphabet
  */
  int CodingScheme_offset = 0;
  tvbuff_t	*parameter_tvb;
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

  if (!parameter_tvb)
     return offset;
  smpp_handle_dcs(tree, parameter_tvb, &CodingScheme_offset);



  return offset;
}
static int dissect_ussd_DataCodingScheme(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_USSD_DataCodingScheme(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ussd_DataCodingScheme);
}
static int dissect_dataCodingScheme_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_USSD_DataCodingScheme(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_dataCodingScheme);
}



int
dissect_gsm_map_USSD_String(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 468 "gsmmap.cnf"

  tvbuff_t	*parameter_tvb;
  int			length;
  guint8		out_len;
  /* XXX - The maximum item label length is 240.  Does this really need to be 1024? 
   * use ep_alloc ?
   * TODO: Shouldent this function use USSD-DataCodingScheme to chose decoding method???
   */
  static char bigbuf[1024];

  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

  if (!parameter_tvb)
     return offset;

  length = tvb_length_remaining(parameter_tvb,0);

  out_len = gsm_sms_char_7bit_unpack(0, length, sizeof(bigbuf),
              tvb_get_ptr(parameter_tvb, 0, length), bigbuf);

  bigbuf[out_len] = '\0';
  gsm_sms_char_ascii_decode(bigbuf, bigbuf, out_len);
  bigbuf[1023] = '\0';
  proto_tree_add_text(tree, parameter_tvb, 0, length, "USSD String: %s", bigbuf);






  return offset;
}
static int dissect_ussd_String(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_USSD_String(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ussd_String);
}


static const ber_sequence_t Ussd_Arg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ussd_DataCodingScheme },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ussd_String },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_alertingPattern },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { 0, 0, 0, NULL }
};

int
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

int
dissect_gsm_map_Ussd_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Ussd_Res_sequence, hf_index, ett_gsm_map_Ussd_Res);

  return offset;
}


static const value_string gsm_map_FailureCause_vals[] = {
  {   0, "wrongUserResponse" },
  {   1, "wrongNetworkSignature" },
  { 0, NULL }
};


static int
dissect_gsm_map_FailureCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_failureCause(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_FailureCause(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_failureCause);
}



static int
dissect_gsm_map_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_re_attempt(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_re_attempt);
}
static int dissect_sm_RP_PRI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sm_RP_PRI);
}


static const value_string gsm_map_AccessType_vals[] = {
  {   0, "call" },
  {   1, "emergencyCall" },
  {   2, "locationUpdating" },
  {   3, "supplementaryService" },
  {   4, "shortMessage" },
  {   5, "gprsAttach" },
  {   6, "routingAreaUpdating" },
  {   7, "serviceRequest" },
  {   8, "pdpContextActivation" },
  {   9, "pdpContextDeactivation" },
  {  10, "gprsDetach" },
  { 0, NULL }
};


static int
dissect_gsm_map_AccessType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_accessType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AccessType(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_accessType);
}


static const ber_sequence_t AuthenticationFailureReportArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_failureCause },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_re_attempt },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_accessType },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_rand },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vlr_Number_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgsn_Number_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AuthenticationFailureReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AuthenticationFailureReportArg_sequence, hf_index, ett_gsm_map_AuthenticationFailureReportArg);

  return offset;
}


static const ber_sequence_t AuthenticationFailureReportRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AuthenticationFailureReportRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AuthenticationFailureReportRes_sequence, hf_index, ett_gsm_map_AuthenticationFailureReportRes);

  return offset;
}



int
dissect_gsm_map_NewPassword(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


const value_string gsm_map_GetPasswordArg_vals[] = {
  {   0, "enterPW" },
  {   1, "enterNewPW" },
  {   2, "enterNewPW-Again" },
  { 0, NULL }
};


int
dissect_gsm_map_GetPasswordArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



int
dissect_gsm_map_CurrentPassword(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const asn_namedbit ServiceIndicator_bits[] = {
  {  0, &hf_gsm_map_ServiceIndicator_clir_invoked, -1, -1, "clir-invoked", NULL },
  {  1, &hf_gsm_map_ServiceIndicator_camel_invoked, -1, -1, "camel-invoked", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_gsm_map_ServiceIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    ServiceIndicator_bits, hf_index, ett_gsm_map_ServiceIndicator,
                                    NULL);

  return offset;
}
static int dissect_serviceIndicator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ServiceIndicator(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_serviceIndicator);
}


static const ber_sequence_t CCBS_Data_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_ccbs_Feature },
  { BER_CLASS_CON, 1, 0, dissect_translatedB_Number },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_serviceIndicator },
  { BER_CLASS_CON, 3, 0, dissect_callInfo },
  { BER_CLASS_CON, 4, 0, dissect_networkSignalInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CCBS_Data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CCBS_Data_sequence, hf_index, ett_gsm_map_CCBS_Data);

  return offset;
}
static int dissect_ccbs_Data_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CCBS_Data(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ccbs_Data);
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

int
dissect_gsm_map_RegisterCC_EntryRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RegisterCC_EntryRes_sequence, hf_index, ett_gsm_map_RegisterCC_EntryRes);

  return offset;
}


static const ber_sequence_t EraseCC_EntryArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ss_Code_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ccbs_Index_impl },
  { 0, 0, 0, NULL }
};

int
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

int
dissect_gsm_map_EraseCC_EntryRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EraseCC_EntryRes_sequence, hf_index, ett_gsm_map_EraseCC_EntryRes);

  return offset;
}



static int
dissect_gsm_map_ServiceCentreAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 198 "gsmmap.cnf"

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
 pinfo->p2p_dir = P2P_DIR_SENT;



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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

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


static const value_string gsm_map_Additional_Number_vals[] = {
  {   0, "msc-Number" },
  {   1, "sgsn-Number" },
  { 0, NULL }
};

static const ber_choice_t Additional_Number_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_msc_Number_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_sgsn_Number_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Additional_Number(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Additional_Number_choice, hf_index, ett_gsm_map_Additional_Number,
                                 NULL);

  return offset;
}
static int dissect_additional_Number_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Additional_Number(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_additional_Number);
}


static const ber_sequence_t LocationInfoWithLMSI_sequence[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_networkNode_Number_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_lmsi },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprsNodeIndicator_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_additional_Number_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LocationInfoWithLMSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LocationInfoWithLMSI_sequence, hf_index, ett_gsm_map_LocationInfoWithLMSI);

  return offset;
}
static int dissect_locationInfoWithLMSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LocationInfoWithLMSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_locationInfoWithLMSI);
}


static const ber_sequence_t RoutingInfoForSM_Res_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_locationInfoWithLMSI_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RoutingInfoForSM_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RoutingInfoForSM_Res_sequence, hf_index, ett_gsm_map_RoutingInfoForSM_Res);

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
                                 Sm_RP_DA_choice, hf_index, ett_gsm_map_Sm_RP_DA,
                                 NULL);

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
                                 Sm_RP_OA_choice, hf_index, ett_gsm_map_Sm_RP_OA,
                                 NULL);

  return offset;
}
static int dissect_sm_RP_OA(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Sm_RP_OA(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sm_RP_OA);
}



static int
dissect_gsm_map_Sm_RP_UI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 157 "gsmmap.cnf"

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
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sm_RP_DA },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sm_RP_OA },
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
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sm_RP_DA },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_sm_RP_OA },
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
  offset = dissect_gsm_map_ISDN_AddressString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_sm_DeliveryOutcome(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Sm_DeliveryOutcome(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sm_DeliveryOutcome);
}
static int dissect_additionalSM_DeliveryOutcome_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Sm_DeliveryOutcome(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_additionalSM_DeliveryOutcome);
}



static int
dissect_gsm_map_AbsentSubscriberDiagnosticSM(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_absentSubscriberDiagnosticSM(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AbsentSubscriberDiagnosticSM(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_absentSubscriberDiagnosticSM);
}
static int dissect_absentSubscriberDiagnosticSM_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AbsentSubscriberDiagnosticSM(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_absentSubscriberDiagnosticSM);
}
static int dissect_additionalAbsentSubscriberDiagnosticSM_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AbsentSubscriberDiagnosticSM(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_additionalAbsentSubscriberDiagnosticSM);
}
static int dissect_mobileNotReachableReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AbsentSubscriberDiagnosticSM(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_mobileNotReachableReason);
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
  {  0, &hf_gsm_map_T_mw_Status_scAddressNotIncluded, -1, -1, "scAddressNotIncluded", NULL },
  {  1, &hf_gsm_map_T_mw_Status_mnrfSet, -1, -1, "mnrfSet", NULL },
  {  2, &hf_gsm_map_T_mw_Status_mcefSet, -1, -1, "mcefSet", NULL },
  {  3, &hf_gsm_map_T_mw_Status_mnrgSet, -1, -1, "mnrgSet", NULL },
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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

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


static const value_string gsm_map_T_requestedDomain_vals[] = {
  {   0, "cs-Domain" },
  {   1, "ps-Domain" },
  { 0, NULL }
};


static int
dissect_gsm_map_T_requestedDomain(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_requestedDomain_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_T_requestedDomain(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_requestedDomain);
}


static const ber_sequence_t RequestedInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationInformation_flg_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_subscriberState_flg_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_currentLocation_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_requestedDomain_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_imei_flg_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ms_classmark_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mnpRequestedInfo_impl },
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


static const ber_sequence_t AnyTimeInterrogationArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_subscriberIdentity },
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


static const ber_sequence_t SS_ForBS_Code_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ss_Code },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_basicService },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_longFTN_Supported_impl },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_SS_ForBS_Code(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SS_ForBS_Code_sequence, hf_index, ett_gsm_map_SS_ForBS_Code);

  return offset;
}
static int dissect_requestedSS_Info_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SS_ForBS_Code(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_requestedSS_Info);
}


static const value_string gsm_map_RequestedCAMEL_SubscriptionInfo_vals[] = {
  {   0, "o-CSI" },
  {   1, "t-CSI" },
  {   2, "vt-CSI" },
  {   3, "tif-CSI" },
  {   4, "gprs-CSI" },
  {   5, "mo-sms-CSI" },
  {   6, "ss-CSI" },
  {   7, "m-CSI" },
  {   8, "d-csi" },
  { 0, NULL }
};


static int
dissect_gsm_map_RequestedCAMEL_SubscriptionInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_requestedCAMEL_SubscriptionInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RequestedCAMEL_SubscriptionInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_requestedCAMEL_SubscriptionInfo);
}
static int dissect_requestedCamel_SubscriptionInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RequestedCAMEL_SubscriptionInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_requestedCamel_SubscriptionInfo);
}


static const value_string gsm_map_AdditionalRequestedCAMEL_SubscriptionInfo_vals[] = {
  {   0, "mt-sms-CSI" },
  {   1, "mg-csi" },
  {   2, "o-IM-CSI" },
  {   3, "d-IM-CSI" },
  {   4, "vt-IM-CSI" },
  { 0, NULL }
};


static int
dissect_gsm_map_AdditionalRequestedCAMEL_SubscriptionInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_additionalRequestedCAMEL_SubscriptionInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AdditionalRequestedCAMEL_SubscriptionInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_additionalRequestedCAMEL_SubscriptionInfo);
}


static const ber_sequence_t RequestedSubscriptionInfo_sequence[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_requestedSS_Info_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_odb_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_requestedCAMEL_SubscriptionInfo_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedVLR_CAMEL_Phases_flg_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedSGSN_CAMEL_Phases_flg_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_additionalRequestedCAMEL_SubscriptionInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RequestedSubscriptionInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RequestedSubscriptionInfo_sequence, hf_index, ett_gsm_map_RequestedSubscriptionInfo);

  return offset;
}
static int dissect_requestedSubscriptionInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RequestedSubscriptionInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_requestedSubscriptionInfo);
}


static const ber_sequence_t AnyTimeSubscriptionInterrogationArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_subscriberIdentity_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_requestedSubscriptionInfo_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gsmSCF_Address_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_longFTN_Supported_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AnyTimeSubscriptionInterrogationArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AnyTimeSubscriptionInterrogationArg_sequence, hf_index, ett_gsm_map_AnyTimeSubscriptionInterrogationArg);

  return offset;
}


static const ber_sequence_t CallForwardingData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ext_forwardingFeatureList },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_notificationToCSE },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CallForwardingData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CallForwardingData_sequence, hf_index, ett_gsm_map_CallForwardingData);

  return offset;
}
static int dissect_callForwardingData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallForwardingData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callForwardingData);
}



static int
dissect_gsm_map_Password(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_password(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Password(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_password);
}
static int dissect_password_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Password(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_password);
}



static int
dissect_gsm_map_WrongPasswordAttemptsCounter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_wrongPasswordAttemptsCounter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_WrongPasswordAttemptsCounter(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_wrongPasswordAttemptsCounter);
}
static int dissect_wrongPasswordAttemptsCounter_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_WrongPasswordAttemptsCounter(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_wrongPasswordAttemptsCounter);
}


static const ber_sequence_t CallBarringData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ext_callBarringFeatureList },
  { BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_password },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_wrongPasswordAttemptsCounter },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_notificationToCSE },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CallBarringData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CallBarringData_sequence, hf_index, ett_gsm_map_CallBarringData);

  return offset;
}
static int dissect_callBarringData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallBarringData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callBarringData);
}


static const ber_sequence_t ODB_Info_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_odb_Data },
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_notificationToCSE },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ODB_Info(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ODB_Info_sequence, hf_index, ett_gsm_map_ODB_Info);

  return offset;
}
static int dissect_odb_Info_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ODB_Info(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_odb_Info);
}


static const ber_sequence_t CAMEL_SubscriptionInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_CSI_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_BcsmCamelTDP_CriteriaList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_d_CSI_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_t_CSI_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_t_BCSM_CAMEL_TDP_CriteriaList_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vt_CSI_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vt_BCSM_CAMEL_TDP_CriteriaList_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tif_CSI_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_tif_CSI_NotificationToCSE_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprs_CSI_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mo_sms_CSI_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_CSI_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_m_CSI_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_specificCSIDeletedList_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mt_sms_CSI_impl },
  { BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mt_smsCAMELTDP_CriteriaList_impl },
  { BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_mg_csi_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_IM_CSI_impl },
  { BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_o_IM_BcsmCamelTDP_CriteriaList_impl },
  { BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_d_IM_CSI_impl },
  { BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vt_IM_CSI_impl },
  { BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vt_IM_BCSM_CAMEL_TDP_CriteriaList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CAMEL_SubscriptionInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CAMEL_SubscriptionInfo_sequence, hf_index, ett_gsm_map_CAMEL_SubscriptionInfo);

  return offset;
}
static int dissect_camel_SubscriptionInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CAMEL_SubscriptionInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_camel_SubscriptionInfo);
}


static const ber_sequence_t AnyTimeSubscriptionInterrogationRes_sequence[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callForwardingData_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callBarringData_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_odb_Info_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_SubscriptionInfo_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedVLR_CAMEL_Phases_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedSGSN_CAMEL_Phases_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_offeredCamel4CSIsInVLR_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_offeredCamel4CSIsInSGSN_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AnyTimeSubscriptionInterrogationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AnyTimeSubscriptionInterrogationRes_sequence, hf_index, ett_gsm_map_AnyTimeSubscriptionInterrogationRes);

  return offset;
}


static const asn_namedbit OfferedCamel4Functionalities_bits[] = {
  {  0, &hf_gsm_map_OfferedCamel4Functionalities_initiateCallAttempt, -1, -1, "initiateCallAttempt", NULL },
  {  1, &hf_gsm_map_OfferedCamel4Functionalities_splitLeg, -1, -1, "splitLeg", NULL },
  {  2, &hf_gsm_map_OfferedCamel4Functionalities_moveLeg, -1, -1, "moveLeg", NULL },
  {  3, &hf_gsm_map_OfferedCamel4Functionalities_disconnectLeg, -1, -1, "disconnectLeg", NULL },
  {  4, &hf_gsm_map_OfferedCamel4Functionalities_entityReleased, -1, -1, "entityReleased", NULL },
  {  5, &hf_gsm_map_OfferedCamel4Functionalities_dfc_WithArgument, -1, -1, "dfc-WithArgument", NULL },
  {  6, &hf_gsm_map_OfferedCamel4Functionalities_playTone, -1, -1, "playTone", NULL },
  {  7, &hf_gsm_map_OfferedCamel4Functionalities_dtmf_MidCall, -1, -1, "dtmf-MidCall", NULL },
  {  8, &hf_gsm_map_OfferedCamel4Functionalities_chargingIndicator, -1, -1, "chargingIndicator", NULL },
  {  9, &hf_gsm_map_OfferedCamel4Functionalities_alertingDP, -1, -1, "alertingDP", NULL },
  { 10, &hf_gsm_map_OfferedCamel4Functionalities_locationAtAlerting, -1, -1, "locationAtAlerting", NULL },
  { 11, &hf_gsm_map_OfferedCamel4Functionalities_changeOfPositionDP, -1, -1, "changeOfPositionDP", NULL },
  { 12, &hf_gsm_map_OfferedCamel4Functionalities_or_Interactions, -1, -1, "or-Interactions", NULL },
  { 13, &hf_gsm_map_OfferedCamel4Functionalities_warningToneEnhancements, -1, -1, "warningToneEnhancements", NULL },
  { 14, &hf_gsm_map_OfferedCamel4Functionalities_cf_Enhancements, -1, -1, "cf-Enhancements", NULL },
  { 15, &hf_gsm_map_OfferedCamel4Functionalities_subscribedEnhancedDialledServices, -1, -1, "subscribedEnhancedDialledServices", NULL },
  { 16, &hf_gsm_map_OfferedCamel4Functionalities_servingNetworkEnhancedDialledServices, -1, -1, "servingNetworkEnhancedDialledServices", NULL },
  { 17, &hf_gsm_map_OfferedCamel4Functionalities_criteriaForChangeOfPositionDP, -1, -1, "criteriaForChangeOfPositionDP", NULL },
  { 18, &hf_gsm_map_OfferedCamel4Functionalities_serviceChangeDP, -1, -1, "serviceChangeDP", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_gsm_map_OfferedCamel4Functionalities(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    OfferedCamel4Functionalities_bits, hf_index, ett_gsm_map_OfferedCamel4Functionalities,
                                    NULL);

  return offset;
}
static int dissect_offeredCamel4Functionalities(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OfferedCamel4Functionalities(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_offeredCamel4Functionalities);
}


static const value_string gsm_map_ModificationInstruction_vals[] = {
  {   0, "deactivate" },
  {   1, "activate" },
  { 0, NULL }
};


static int
dissect_gsm_map_ModificationInstruction(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_modifyNotificationToCSE_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ModificationInstruction(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_modifyNotificationToCSE);
}
static int dissect_modifyCSI_State_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ModificationInstruction(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_modifyCSI_State);
}


static const ber_sequence_t ModificationRequestFor_CF_Info_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ss_Code_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_ext_basicService_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ext_ss_Status_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToNumber_addr_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardedToSubaddress_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ext_noReplyConditionTime_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_modifyNotificationToCSE_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ModificationRequestFor_CF_Info(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ModificationRequestFor_CF_Info_sequence, hf_index, ett_gsm_map_ModificationRequestFor_CF_Info);

  return offset;
}
static int dissect_modificationRequestFor_CF_Info_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ModificationRequestFor_CF_Info(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_modificationRequestFor_CF_Info);
}


static const ber_sequence_t ModificationRequestFor_CB_Info_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ss_Code_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_ext_basicService_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ext_ss_Status_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_password_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_wrongPasswordAttemptsCounter_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_modifyNotificationToCSE_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ModificationRequestFor_CB_Info(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ModificationRequestFor_CB_Info_sequence, hf_index, ett_gsm_map_ModificationRequestFor_CB_Info);

  return offset;
}
static int dissect_modificationRequestFor_CB_Info_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ModificationRequestFor_CB_Info(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_modificationRequestFor_CB_Info);
}


static const ber_sequence_t ModificationRequestFor_CSI_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_requestedCamel_SubscriptionInfo_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_modifyNotificationToCSE_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_modifyCSI_State_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_additionalRequestedCAMEL_SubscriptionInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ModificationRequestFor_CSI(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ModificationRequestFor_CSI_sequence, hf_index, ett_gsm_map_ModificationRequestFor_CSI);

  return offset;
}
static int dissect_modificationRequestFor_CSI_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ModificationRequestFor_CSI(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_modificationRequestFor_CSI);
}


static const ber_sequence_t ModificationRequestFor_ODB_data_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_odb_data_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_modifyNotificationToCSE_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ModificationRequestFor_ODB_data(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ModificationRequestFor_ODB_data_sequence, hf_index, ett_gsm_map_ModificationRequestFor_ODB_data);

  return offset;
}
static int dissect_modificationRequestFor_ODB_data(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ModificationRequestFor_ODB_data(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_modificationRequestFor_ODB_data);
}


static const ber_sequence_t AnyTimeModificationArg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_subscriberIdentity_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gsmSCF_Address_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_modificationRequestFor_CF_Info_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_modificationRequestFor_CB_Info_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_modificationRequestFor_CSI_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_longFTN_Supported_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_modificationRequestFor_ODB_data },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AnyTimeModificationArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AnyTimeModificationArg_sequence, hf_index, ett_gsm_map_AnyTimeModificationArg);

  return offset;
}


static const ber_sequence_t Ext_ForwardingInfoFor_CSE_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ss_Code_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ext_forwardingFeatureList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToCSE_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ext_ForwardingInfoFor_CSE(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Ext_ForwardingInfoFor_CSE_sequence, hf_index, ett_gsm_map_Ext_ForwardingInfoFor_CSE);

  return offset;
}
static int dissect_forwardingInfoFor_CSE_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_ForwardingInfoFor_CSE(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_forwardingInfoFor_CSE);
}


static const ber_sequence_t Ext_CallBarringInfoFor_CSE_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ss_Code_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ext_callBarringFeatureList_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_password_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_wrongPasswordAttemptsCounter_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_notificationToCSE_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ext_CallBarringInfoFor_CSE(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Ext_CallBarringInfoFor_CSE_sequence, hf_index, ett_gsm_map_Ext_CallBarringInfoFor_CSE);

  return offset;
}
static int dissect_callBarringInfoFor_CSE_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_CallBarringInfoFor_CSE(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callBarringInfoFor_CSE);
}


static const value_string gsm_map_Ext_SS_InfoFor_CSE_vals[] = {
  {   0, "forwardingInfoFor-CSE" },
  {   1, "callBarringInfoFor-CSE" },
  { 0, NULL }
};

static const ber_choice_t Ext_SS_InfoFor_CSE_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_forwardingInfoFor_CSE_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_callBarringInfoFor_CSE_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Ext_SS_InfoFor_CSE(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Ext_SS_InfoFor_CSE_choice, hf_index, ett_gsm_map_Ext_SS_InfoFor_CSE,
                                 NULL);

  return offset;
}
static int dissect_ss_InfoFor_CSE_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_SS_InfoFor_CSE(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_InfoFor_CSE);
}


static const ber_sequence_t AnyTimeModificationRes_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_ss_InfoFor_CSE_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_SubscriptionInfo_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_odb_Info_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AnyTimeModificationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AnyTimeModificationRes_sequence, hf_index, ett_gsm_map_AnyTimeModificationRes);

  return offset;
}


static const ber_sequence_t NoteSubscriberDataModifiedArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_msisdn },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_forwardingInfoFor_CSE_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callBarringInfoFor_CSE_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_odb_Info_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_camel_SubscriptionInfo_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_allInformationSent },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_NoteSubscriberDataModifiedArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NoteSubscriberDataModifiedArg_sequence, hf_index, ett_gsm_map_NoteSubscriberDataModifiedArg);

  return offset;
}


static const ber_sequence_t NoteSubscriberDataModifiedRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_NoteSubscriberDataModifiedRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NoteSubscriberDataModifiedRes_sequence, hf_index, ett_gsm_map_NoteSubscriberDataModifiedRes);

  return offset;
}


static const ber_sequence_t NoteMM_EventArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serviceKey },
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_eventMet_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_imsi_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_msisdn_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_locationInformation_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedCAMELPhases_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_locationInformationGPRS },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_offeredCamel4Functionalities },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_NoteMM_EventArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NoteMM_EventArg_sequence, hf_index, ett_gsm_map_NoteMM_EventArg);

  return offset;
}


static const ber_sequence_t NoteMM_EventRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_NoteMM_EventRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NoteMM_EventRes_sequence, hf_index, ett_gsm_map_NoteMM_EventRes);

  return offset;
}


static const value_string gsm_map_ModifyNotificationToCSE_vals[] = {
  {   0, "deactivate" },
  {   1, "activate" },
  { 0, NULL }
};


static int
dissect_gsm_map_ModifyNotificationToCSE(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gsm_map_OCTET_STRING_SIZE_1(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_ss_Event_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OCTET_STRING_SIZE_1(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Event);
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
dissect_gsm_map_CODEC_Info(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_codec_Info(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CODEC_Info(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_codec_Info);
}



static int
dissect_gsm_map_CipheringAlgorithm(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_cipheringAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CipheringAlgorithm(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cipheringAlgorithm);
}



static int
dissect_gsm_map_GroupKeyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_groupKeyNumber_Vk_Id_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_GroupKeyNumber(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_groupKeyNumber_Vk_Id);
}



static int
dissect_gsm_map_VSTK(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_vstk_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_VSTK(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vstk);
}



static int
dissect_gsm_map_VSTK_RAND(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_vstk_rand_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_VSTK_RAND(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vstk_rand);
}


static const ber_sequence_t PrepareGroupCallArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ext_teleservice },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_asciCallReference },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_codec_Info },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_cipheringAlgorithm },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupKeyNumber_Vk_Id_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_groupKey_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_priority_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_uplinkFree_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vstk_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vstk_rand_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_PrepareGroupCallArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PrepareGroupCallArg_sequence, hf_index, ett_gsm_map_PrepareGroupCallArg);

  return offset;
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


static const ber_sequence_t SGSN_Capability_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_solsaSupportIndicator },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_superChargerSupportedInServingNetworkEntity_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprsEnhancementsSupportIndicator_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedCamelPhases_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedLCS_CapabilitySets_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_offeredCamel4CSIs_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_smsCallBarringSupportIndicator_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SGSN_Capability(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SGSN_Capability_sequence, hf_index, ett_gsm_map_SGSN_Capability);

  return offset;
}
static int dissect_sgsn_Capability_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SGSN_Capability(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_sgsn_Capability);
}


static const ber_sequence_t UpdateGprsLocationArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_imsi },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sgsn_Number },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_sgsn_Address },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sgsn_Capability_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_informPreviousNetworkEntity_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ps_LCS_NotSupportedByUE_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_v_gmlc_Address_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_add_info_impl },
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
  { BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_add_Capability },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_UpdateGprsLocationRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   UpdateGprsLocationRes_sequence, hf_index, ett_gsm_map_UpdateGprsLocationRes);

  return offset;
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


static const value_string gsm_map_LocationEstimateType_vals[] = {
  {   0, "currentLocation" },
  {   1, "currentOrLastKnownLocation" },
  {   2, "initialLocation" },
  {   3, "activateDeferredLocation" },
  {   4, "cancelDeferredLocation" },
  { 0, NULL }
};


static int
dissect_gsm_map_LocationEstimateType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_locationEstimateType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LocationEstimateType(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_locationEstimateType);
}


static const asn_namedbit DeferredLocationEventType_bits[] = {
  {  0, &hf_gsm_map_DeferredLocationEventType_msAvailable, -1, -1, "msAvailable", NULL },
  {  1, &hf_gsm_map_DeferredLocationEventType_enteringIntoArea, -1, -1, "enteringIntoArea", NULL },
  {  2, &hf_gsm_map_DeferredLocationEventType_leavingFromArea, -1, -1, "leavingFromArea", NULL },
  {  3, &hf_gsm_map_DeferredLocationEventType_beingInsideArea, -1, -1, "beingInsideArea", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_gsm_map_DeferredLocationEventType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    DeferredLocationEventType_bits, hf_index, ett_gsm_map_DeferredLocationEventType,
                                    NULL);

  return offset;
}
static int dissect_deferredLocationEventType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_DeferredLocationEventType(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_deferredLocationEventType);
}
static int dissect_deferredLocationEventType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_DeferredLocationEventType(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_deferredLocationEventType);
}


static const ber_sequence_t LocationType_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_locationEstimateType_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deferredLocationEventType_impl },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_LocationType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LocationType_sequence, hf_index, ett_gsm_map_LocationType);

  return offset;
}
static int dissect_locationType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LocationType(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_locationType);
}


static const value_string gsm_map_LCSClientType_vals[] = {
  {   0, "emergencyServices" },
  {   1, "valueAddedServices" },
  {   2, "plmnOperatorServices" },
  {   3, "lawfulInterceptServices" },
  { 0, NULL }
};


static int
dissect_gsm_map_LCSClientType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_lcsClientType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSClientType(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsClientType);
}



static int
dissect_gsm_map_NameString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_USSD_String(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_nameString_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_NameString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_nameString);
}


static const value_string gsm_map_LCS_FormatIndicator_vals[] = {
  {   0, "logicalName" },
  {   1, "e-mailAddress" },
  {   2, "msisdn" },
  {   3, "url" },
  {   4, "sipUrl" },
  { 0, NULL }
};


static int
dissect_gsm_map_LCS_FormatIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_lcs_FormatIndicator_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCS_FormatIndicator(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_FormatIndicator);
}


static const ber_sequence_t LCSClientName_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dataCodingScheme_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_nameString_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcs_FormatIndicator_impl },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_LCSClientName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LCSClientName_sequence, hf_index, ett_gsm_map_LCSClientName);

  return offset;
}
static int dissect_lcsClientName_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSClientName(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsClientName);
}



static int
dissect_gsm_map_RequestorIDString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_USSD_String(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_requestorIDString_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_RequestorIDString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_requestorIDString);
}


static const ber_sequence_t LCSRequestorID_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dataCodingScheme_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_requestorIDString_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcs_FormatIndicator_impl },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_LCSRequestorID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LCSRequestorID_sequence, hf_index, ett_gsm_map_LCSRequestorID);

  return offset;
}
static int dissect_lcsRequestorID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSRequestorID(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsRequestorID);
}


static const ber_sequence_t LCS_ClientID_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_lcsClientType_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsClientExternalID_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsClientDialedByMS_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsClientInternalID_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsClientName_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsAPN_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsRequestorID_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LCS_ClientID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LCS_ClientID_sequence, hf_index, ett_gsm_map_LCS_ClientID);

  return offset;
}
static int dissect_lcs_ClientID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCS_ClientID(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_ClientID);
}
static int dissect_lcs_ClientID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCS_ClientID(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_ClientID);
}



static int
dissect_gsm_map_LCS_Priority(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_lcs_Priority_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCS_Priority(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_Priority);
}



static int
dissect_gsm_map_Horizontal_Accuracy(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_horizontal_accuracy_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Horizontal_Accuracy(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_horizontal_accuracy);
}



static int
dissect_gsm_map_Vertical_Accuracy(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_vertical_accuracy_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Vertical_Accuracy(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_vertical_accuracy);
}


static const value_string gsm_map_ResponseTimeCategory_vals[] = {
  {   0, "lowdelay" },
  {   1, "delaytolerant" },
  { 0, NULL }
};


static int
dissect_gsm_map_ResponseTimeCategory(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_responseTimeCategory(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ResponseTimeCategory(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_responseTimeCategory);
}


static const ber_sequence_t ResponseTime_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_responseTimeCategory },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ResponseTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ResponseTime_sequence, hf_index, ett_gsm_map_ResponseTime);

  return offset;
}
static int dissect_responseTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ResponseTime(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_responseTime);
}


static const ber_sequence_t LCS_QoS_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_horizontal_accuracy_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_verticalCoordinateRequest_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_vertical_accuracy_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_responseTime_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_LCS_QoS(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LCS_QoS_sequence, hf_index, ett_gsm_map_LCS_QoS);

  return offset;
}
static int dissect_lcs_QoS_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCS_QoS(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_QoS);
}


static const asn_namedbit SupportedGADShapes_bits[] = {
  {  0, &hf_gsm_map_SupportedGADShapes_ellipsoidPoint, -1, -1, "ellipsoidPoint", NULL },
  {  1, &hf_gsm_map_SupportedGADShapes_ellipsoidPointWithUncertaintyCircle, -1, -1, "ellipsoidPointWithUncertaintyCircle", NULL },
  {  2, &hf_gsm_map_SupportedGADShapes_ellipsoidPointWithUncertaintyEllipse, -1, -1, "ellipsoidPointWithUncertaintyEllipse", NULL },
  {  3, &hf_gsm_map_SupportedGADShapes_polygon, -1, -1, "polygon", NULL },
  {  4, &hf_gsm_map_SupportedGADShapes_ellipsoidPointWithAltitude, -1, -1, "ellipsoidPointWithAltitude", NULL },
  {  5, &hf_gsm_map_SupportedGADShapes_ellipsoidPointWithAltitudeAndUncertaintyElipsoid, -1, -1, "ellipsoidPointWithAltitudeAndUncertaintyElipsoid", NULL },
  {  6, &hf_gsm_map_SupportedGADShapes_ellipsoidArc, -1, -1, "ellipsoidArc", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

int
dissect_gsm_map_SupportedGADShapes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    SupportedGADShapes_bits, hf_index, ett_gsm_map_SupportedGADShapes,
                                    NULL);

  return offset;
}
static int dissect_supportedGADShapes_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SupportedGADShapes(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_supportedGADShapes);
}



int
dissect_gsm_map_LCS_ReferenceNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_lcs_ReferenceNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCS_ReferenceNumber(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_ReferenceNumber);
}



static int
dissect_gsm_map_LCSCodewordString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_gsm_map_USSD_String(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_lcsCodewordString_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSCodewordString(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsCodewordString);
}


static const ber_sequence_t LCSCodeword_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_dataCodingScheme_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lcsCodewordString_impl },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_LCSCodeword(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LCSCodeword_sequence, hf_index, ett_gsm_map_LCSCodeword);

  return offset;
}
static int dissect_lcsCodeword_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSCodeword(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsCodeword);
}


static const value_string gsm_map_PrivacyCheckRelatedAction_vals[] = {
  {   0, "allowedWithoutNotification" },
  {   1, "allowedWithNotification" },
  {   2, "allowedIfNoResponse" },
  {   3, "restrictedIfNoResponse" },
  {   4, "notAllowed" },
  { 0, NULL }
};


static int
dissect_gsm_map_PrivacyCheckRelatedAction(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_callSessionUnrelated_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PrivacyCheckRelatedAction(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callSessionUnrelated);
}
static int dissect_callSessionRelated_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PrivacyCheckRelatedAction(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_callSessionRelated);
}


static const ber_sequence_t LCS_PrivacyCheck_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_callSessionUnrelated_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_callSessionRelated_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LCS_PrivacyCheck(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LCS_PrivacyCheck_sequence, hf_index, ett_gsm_map_LCS_PrivacyCheck);

  return offset;
}
static int dissect_lcs_PrivacyCheck_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCS_PrivacyCheck(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_PrivacyCheck);
}


static const value_string gsm_map_AreaType_vals[] = {
  {   0, "countryCode" },
  {   1, "plmnId" },
  {   2, "locationAreaId" },
  {   3, "routingAreaId" },
  {   4, "cellGlobalId" },
  { 0, NULL }
};


static int
dissect_gsm_map_AreaType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_areaType_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AreaType(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_areaType);
}



static int
dissect_gsm_map_AreaIdentification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_areaIdentification_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AreaIdentification(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_areaIdentification);
}


static const ber_sequence_t Area_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_areaType_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_areaIdentification_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Area(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Area_sequence, hf_index, ett_gsm_map_Area);

  return offset;
}
static int dissect_AreaList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Area(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_AreaList_item);
}


static const ber_sequence_t AreaList_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_AreaList_item },
};

static int
dissect_gsm_map_AreaList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      AreaList_sequence_of, hf_index, ett_gsm_map_AreaList);

  return offset;
}
static int dissect_areaList_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AreaList(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_areaList);
}


static const ber_sequence_t AreaDefinition_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_areaList_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AreaDefinition(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AreaDefinition_sequence, hf_index, ett_gsm_map_AreaDefinition);

  return offset;
}
static int dissect_areaDefinition_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AreaDefinition(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_areaDefinition);
}


static const value_string gsm_map_OccurrenceInfo_vals[] = {
  {   0, "oneTimeEvent" },
  {   1, "multipleTimeEvent" },
  { 0, NULL }
};


static int
dissect_gsm_map_OccurrenceInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_occurrenceInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OccurrenceInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_occurrenceInfo);
}



static int
dissect_gsm_map_IntervalTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_intervalTime_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_IntervalTime(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_intervalTime);
}


static const ber_sequence_t AreaEventInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_areaDefinition_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_occurrenceInfo_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_intervalTime_impl },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_AreaEventInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AreaEventInfo_sequence, hf_index, ett_gsm_map_AreaEventInfo);

  return offset;
}
static int dissect_areaEventInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AreaEventInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_areaEventInfo);
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
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedGADShapes_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcs_ReferenceNumber_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsServiceTypeID_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsCodeword_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcs_PrivacyCheck_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_areaEventInfo_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h_gmlc_Address_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ProvideSubscriberLocation_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ProvideSubscriberLocation_Arg_sequence, hf_index, ett_gsm_map_ProvideSubscriberLocation_Arg);

  return offset;
}



int
dissect_gsm_map_Ext_GeographicalInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_locationEstimate(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_GeographicalInformation(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_locationEstimate);
}
static int dissect_locationEstimate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Ext_GeographicalInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_locationEstimate);
}



int
dissect_gsm_map_Add_GeographicalInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_add_LocationEstimate_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Add_GeographicalInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_add_LocationEstimate);
}



static int
dissect_gsm_map_PositioningDataInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_geranPositioningData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PositioningDataInformation(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_geranPositioningData);
}



static int
dissect_gsm_map_UtranPositioningDataInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_utranPositioningData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_UtranPositioningDataInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_utranPositioningData);
}


static const ber_sequence_t ProvideSubscriberLocation_Res_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_locationEstimate },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ageOfLocationEstimate_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_add_LocationEstimate_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deferredmt_lrResponseIndicator_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_geranPositioningData_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_utranPositioningData_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_cellIdOrSai_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sai_Present_impl },
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
                                 TargetMS_choice, hf_index, ett_gsm_map_TargetMS,
                                 NULL);

  return offset;
}


static const ber_sequence_t RoutingInfoForLCS_Arg_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_mlcNumber_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_targetMS_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RoutingInfoForLCS_Arg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RoutingInfoForLCS_Arg_sequence, hf_index, ett_gsm_map_RoutingInfoForLCS_Arg);

  return offset;
}


static const ber_sequence_t LCSLocationInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_networkNode_Number },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lmsi_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensionContainer_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprsNodeIndicator_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_additional_Number_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_supportedLCS_CapabilitySets_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additional_LCS_CapabilitySets_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_LCSLocationInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   LCSLocationInfo_sequence, hf_index, ett_gsm_map_LCSLocationInfo);

  return offset;
}
static int dissect_lcsLocationInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSLocationInfo(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lcsLocationInfo);
}
static int dissect_lcsLocationInfo_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCSLocationInfo(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_lcsLocationInfo);
}


static const ber_sequence_t RoutingInfoForLCS_Res_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_NOTCHKTAG, dissect_targetMS },
  { BER_CLASS_CON, 1, 0, dissect_lcsLocationInfo },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_extensionContainer },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_v_gmlc_Address },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_h_gmlc_Address },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_ppr_Address },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_additional_v_gmlc_Address },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_RoutingInfoForLCS_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RoutingInfoForLCS_Res_sequence, hf_index, ett_gsm_map_RoutingInfoForLCS_Res);

  return offset;
}


static const value_string gsm_map_LCS_Event_vals[] = {
  {   0, "emergencyCallOrigination" },
  {   1, "emergencyCallRelease" },
  {   2, "mo-lr" },
  {   3, "deferredmt-lrResponse" },
  { 0, NULL }
};


static int
dissect_gsm_map_LCS_Event(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_lcs_Event(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_LCS_Event(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_lcs_Event);
}


static const value_string gsm_map_TerminationCause_vals[] = {
  {   0, "normal" },
  {   1, "errorundefined" },
  {   2, "internalTimeout" },
  {   3, "congestion" },
  {   4, "mt-lrRestart" },
  {   5, "privacyViolation" },
  {   6, "shapeOfLocationEstimateNotSupported" },
  { 0, NULL }
};


static int
dissect_gsm_map_TerminationCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_terminationCause_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_TerminationCause(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_terminationCause);
}


static const ber_sequence_t Deferredmt_lrData_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_deferredLocationEventType },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_terminationCause_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsLocationInfo_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_Deferredmt_lrData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Deferredmt_lrData_sequence, hf_index, ett_gsm_map_Deferredmt_lrData);

  return offset;
}
static int dissect_deferredmt_lrData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Deferredmt_lrData(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_deferredmt_lrData);
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
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_slr_ArgExtensionContainer_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_add_LocationEstimate_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_deferredmt_lrData_impl },
  { BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcs_ReferenceNumber_impl },
  { BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_geranPositioningData_impl },
  { BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_utranPositioningData_impl },
  { BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_cellIdOrSai_impl },
  { BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_h_gmlc_Address_impl },
  { BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lcsServiceTypeID_impl },
  { BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_sai_Present_impl },
  { BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_pseudonymIndicator_impl },
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
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_na_ESRK_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_na_ESRD_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SubscriberLocationReport_Res(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SubscriberLocationReport_Res_sequence, hf_index, ett_gsm_map_SubscriberLocationReport_Res);

  return offset;
}



static int
dissect_gsm_map_SecurityParametersIndex(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_securityParametersIndex(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SecurityParametersIndex(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_securityParametersIndex);
}



static int
dissect_gsm_map_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_localValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_localValue);
}


static const value_string gsm_map_OperationCode_vals[] = {
  {   0, "localValue" },
  {   1, "globalValue" },
  { 0, NULL }
};

static const ber_choice_t OperationCode_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_localValue },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_globalValue },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_OperationCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 OperationCode_choice, hf_index, ett_gsm_map_OperationCode,
                                 NULL);

  return offset;
}
static int dissect_operationCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OperationCode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_operationCode);
}


static const value_string gsm_map_ErrorCode_vals[] = {
  {   0, "localValue" },
  {   1, "globalValue" },
  { 0, NULL }
};

static const ber_choice_t ErrorCode_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_localValue },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_globalValue },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ErrorCode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ErrorCode_choice, hf_index, ett_gsm_map_ErrorCode,
                                 NULL);

  return offset;
}
static int dissect_errorCode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ErrorCode(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_errorCode);
}


static const value_string gsm_map_OriginalComponentIdentifier_vals[] = {
  {   0, "operationCode" },
  {   1, "errorCode" },
  {   2, "userInfo" },
  { 0, NULL }
};

static const ber_choice_t OriginalComponentIdentifier_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_operationCode_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_errorCode_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_userInfo_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_gsm_map_OriginalComponentIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 OriginalComponentIdentifier_choice, hf_index, ett_gsm_map_OriginalComponentIdentifier,
                                 NULL);

  return offset;
}
static int dissect_originalComponentIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_OriginalComponentIdentifier(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_originalComponentIdentifier);
}



static int
dissect_gsm_map_InitialisationVector(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_initialisationVector(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_InitialisationVector(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_initialisationVector);
}


static const ber_sequence_t SecurityHeader_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_securityParametersIndex },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_originalComponentIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_initialisationVector },
  { 0, 0, 0, NULL }
};

int
dissect_gsm_map_SecurityHeader(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SecurityHeader_sequence, hf_index, ett_gsm_map_SecurityHeader);

  return offset;
}
static int dissect_securityHeader(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SecurityHeader(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_securityHeader);
}



int
dissect_gsm_map_ProtectedPayload(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_protectedPayload(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ProtectedPayload(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_protectedPayload);
}


static const ber_sequence_t SecureTransportArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_securityHeader },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_protectedPayload },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SecureTransportArg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SecureTransportArg_sequence, hf_index, ett_gsm_map_SecureTransportArg);

  return offset;
}


static const ber_sequence_t SecureTransportRes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_securityHeader },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_protectedPayload },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SecureTransportRes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SecureTransportRes_sequence, hf_index, ett_gsm_map_SecureTransportRes);

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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

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
                                 SystemFailureParam_choice, hf_index, ett_gsm_map_SystemFailureParam,
                                 NULL);

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


static const ber_sequence_t OR_NotAllowedParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_OR_NotAllowedParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OR_NotAllowedParam_sequence, hf_index, ett_gsm_map_OR_NotAllowedParam);

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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

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


static const value_string gsm_map_AbsentSubscriberReason_vals[] = {
  {   0, "imsiDetach" },
  {   1, "restrictedArea" },
  {   2, "noPageResponse" },
  {   3, "purgedMS" },
  { 0, NULL }
};


static int
dissect_gsm_map_AbsentSubscriberReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_absentSubscriberReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AbsentSubscriberReason(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_absentSubscriberReason);
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


static const ber_sequence_t ATI_NotAllowedParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ATI_NotAllowedParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ATI_NotAllowedParam_sequence, hf_index, ett_gsm_map_ATI_NotAllowedParam);

  return offset;
}


static const ber_sequence_t ATSI_NotAllowedParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ATSI_NotAllowedParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ATSI_NotAllowedParam_sequence, hf_index, ett_gsm_map_ATSI_NotAllowedParam);

  return offset;
}


static const ber_sequence_t ATM_NotAllowedParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ATM_NotAllowedParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ATM_NotAllowedParam_sequence, hf_index, ett_gsm_map_ATM_NotAllowedParam);

  return offset;
}


static const ber_sequence_t IllegalSS_OperationParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_IllegalSS_OperationParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IllegalSS_OperationParam_sequence, hf_index, ett_gsm_map_IllegalSS_OperationParam);

  return offset;
}


static const ber_sequence_t SS_NotAvailableParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SS_NotAvailableParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SS_NotAvailableParam_sequence, hf_index, ett_gsm_map_SS_NotAvailableParam);

  return offset;
}


static const ber_sequence_t SS_SubscriptionViolationParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SS_SubscriptionViolationParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SS_SubscriptionViolationParam_sequence, hf_index, ett_gsm_map_SS_SubscriptionViolationParam);

  return offset;
}


static const ber_sequence_t InformationNotAvailableParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_InformationNotAvailableParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InformationNotAvailableParam_sequence, hf_index, ett_gsm_map_InformationNotAvailableParam);

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


static const value_string gsm_map_CallBarringCause_vals[] = {
  {   0, "barringServiceActive" },
  {   1, "operatorBarring" },
  { 0, NULL }
};


static int
dissect_gsm_map_CallBarringCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_callBarringCause(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CallBarringCause(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_callBarringCause);
}


static const ber_sequence_t ExtensibleCallBarredParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_callBarringCause },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_unauthorisedMessageOriginator },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_ExtensibleCallBarredParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ExtensibleCallBarredParam_sequence, hf_index, ett_gsm_map_ExtensibleCallBarredParam);

  return offset;
}
static int dissect_extensibleCallBarredParam(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExtensibleCallBarredParam(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_extensibleCallBarredParam);
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
                                 CallBarredParam_choice, hf_index, ett_gsm_map_CallBarredParam,
                                 NULL);

  return offset;
}


static const value_string gsm_map_CUG_RejectCause_vals[] = {
  {   0, "incomingCallsBarredWithinCUG" },
  {   1, "subscriberNotMemberOfCUG" },
  {   5, "requestedBasicServiceViolatesCUG-Constraints" },
  {   7, "calledPartySS-InteractionViolation" },
  { 0, NULL }
};


static int
dissect_gsm_map_CUG_RejectCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cug_RejectCause(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_CUG_RejectCause(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_cug_RejectCause);
}


static const ber_sequence_t CUG_RejectParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cug_RejectCause },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_CUG_RejectParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CUG_RejectParam_sequence, hf_index, ett_gsm_map_CUG_RejectParam);

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


static const ber_sequence_t SS_IncompatibilityCause_sequence[] = {
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_Code_impl },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_basicService },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_ss_Status_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SS_IncompatibilityCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SS_IncompatibilityCause_sequence, hf_index, ett_gsm_map_SS_IncompatibilityCause);

  return offset;
}


static const value_string gsm_map_PW_RegistrationFailureCause_vals[] = {
  {   0, "undetermined" },
  {   1, "invalidFormat" },
  {   2, "newPasswordsMismatch" },
  { 0, NULL }
};


static int
dissect_gsm_map_PW_RegistrationFailureCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

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


static const value_string gsm_map_SM_EnumeratedDeliveryFailureCause_vals[] = {
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
dissect_gsm_map_SM_EnumeratedDeliveryFailureCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_sm_EnumeratedDeliveryFailureCause(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SM_EnumeratedDeliveryFailureCause(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_sm_EnumeratedDeliveryFailureCause);
}


static const ber_sequence_t SM_DeliveryFailureCause_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_sm_EnumeratedDeliveryFailureCause },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_diagnosticInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SM_DeliveryFailureCause(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SM_DeliveryFailureCause_sequence, hf_index, ett_gsm_map_SM_DeliveryFailureCause);

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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

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


static const value_string gsm_map_PositionMethodFailure_Diagnostic_vals[] = {
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
dissect_gsm_map_PositionMethodFailure_Diagnostic(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_positionMethodFailure_Diagnostic_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_PositionMethodFailure_Diagnostic(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_positionMethodFailure_Diagnostic);
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


static const ber_sequence_t MM_EventNotSupported_Param_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_MM_EventNotSupported_Param(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MM_EventNotSupported_Param_sequence, hf_index, ett_gsm_map_MM_EventNotSupported_Param);

  return offset;
}


static const ber_sequence_t TargetCellOutsideGCA_Param_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_TargetCellOutsideGCA_Param(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TargetCellOutsideGCA_Param_sequence, hf_index, ett_gsm_map_TargetCellOutsideGCA_Param);

  return offset;
}


static const ber_sequence_t SecureTransportErrorParam_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_securityHeader },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_protectedPayload },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_SecureTransportErrorParam(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SecureTransportErrorParam_sequence, hf_index, ett_gsm_map_SecureTransportErrorParam);

  return offset;
}


static const value_string gsm_map_Access_vals[] = {
  {   1, "gsm" },
  {   2, "geran" },
  {   3, "utran" },
  { 0, NULL }
};


static int
dissect_gsm_map_Access(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_access(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Access(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_access);
}



static int
dissect_gsm_map_Version(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_version(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_Version(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_version);
}


static const ber_sequence_t AccessTypePriv_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_access },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_version },
  { 0, 0, 0, NULL }
};

static int
dissect_gsm_map_AccessTypePriv(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AccessTypePriv_sequence, hf_index, ett_gsm_map_AccessTypePriv);

  return offset;
}

/*--- PDUs ---*/

static void dissect_Component_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_gsm_map_Component(FALSE, tvb, 0, pinfo, tree, hf_gsm_map_Component_PDU);
}


/*--- End of included file: packet-gsm_map-fn.c ---*/
#line 562 "packet-gsm_map-template.c"

const value_string gsm_map_opr_code_strings[] = {
  {   2, "updateLocation" },
  {   3, "cancelLocation" },
  {   4, "provideRoamingNumber" },
  {	  5, "noteSubscriberDataModified" },	
  {   6, "resumeCallHandling" },
  {   7, "insertSubscriberData" },
  {   8, "deleteSubscriberData" },
  {   9, "sendParameters" },					/* map-ac infoRetrieval (14) version1 (1)*/
  {  10, "registerSS" },
  {  11, "eraseSS" },
  {  12, "activateSS" },
  {  13, "deactivateSS" },
  {  14, "interrogateSS" },
  {	 15, "authenticationFailureReport" },	
  {  17, "registerPassword" },
  {  18, "getPassword" },
  {  19, "processUnstructuredSS-Data" },		/* map-ac networkFunctionalSs (18) version1 (1) */
  {  20, "releaseResources" },
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
  {  62, "anyTimeSubscriptionInterrogation" },
  {  63, "informServiceCentre" },
  {  64, "alertServiceCentre" },
  {  65, "anyTimeModification" },
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
  {  78, "secureTransportClass1" },
  {  79, "secureTransportClass2" },
  {  80, "secureTransportClass3" },
  {  81, "secureTransportClass4" },
  {  83, "provideSubscriberLocation" },
  {  85, "sendRoutingInfoForLCS" },
  {  86, "subscriberLocationReport" },
  {	 87, "ist-Alert" },
  {	 88, "ist-Command" },
  {  89, "noteMM-Event" },
  { 0, NULL }
};
static const value_string gsm_map_err_code_string_vals[] = {
    { 1,	"Unknown Subscriber" },
    { 3,	"Unknown MSC" },
    { 5,	"Unidentified Subscriber" },
    { 6,	"Absent Subscriber SM" },
    { 7,	"Unknown Equipment" },
    { 8,	"Roaming Not Allowed" },
    { 9,	"Illegal Subscriber" },
    { 10,	"Bearer Service Not Provisioned" },
    { 11,	"Teleservice Not Provisioned" },
    { 12,	"Illegal Equipment" },
    { 13,	"Call Barred" },
    { 14,	"Forwarding Violation" },
    { 15,	"CUG Reject" },
    { 16,	"Illegal SS Operation" },
    { 17,	"SS Error Status" },
    { 18,	"SS Not Available" },
    { 19,	"SS Subscription Violation" },
    { 20,	"SS Incompatibility" },
    { 21,	"Facility Not Supported" },
    { 25,	"No Handover Number Available" },
    { 26,	"Subsequent Handover Failure" },
    { 27,	"Absent Subscriber" },
    { 28,	"Incompatible Terminal" },
    { 29,	"Short Term Denial" },
    { 30,	"Long Term Denial" },
    { 31,	"Subscriber Busy For MT SMS" },
    { 32,	"SM Delivery Failure" },
    { 33,	"Message Waiting List Full" },
    { 34,	"System Failure" },
    { 35,	"Data Missing" },
    { 36,	"Unexpected Data Value" },
    { 37,	"PW Registration Failure" },
    { 38,	"Negative PW Check" },
    { 39,	"No Roaming Number Available" },
    { 40,	"Tracing Buffer Full" },
    { 42,	"Target Cell Outside Group Call Area" },
    { 43,	"Number Of PW Attempts Violation" },
    { 44,	"Number Changed" },
    { 45,	"Busy Subscriber" },
    { 46,	"No Subscriber Reply" },
    { 47,	"Forwarding Failed" },
    { 48,	"OR Not Allowed" },
    { 49,	"ATI Not Allowed" },
    { 50,	"No Group Call Number Available" },
    { 51,	"Resource Limitation" },
    { 52,	"Unauthorized Requesting Network" },
    { 53,	"Unauthorized LCS Client" },
    { 54,	"Position Method Failure" },
    { 58,	"Unknown Or Unreachable LCS Client" },
    { 59,	"MM Event Not Supported" },
    { 60,	"ATSI Not Allowed" },
    { 61,	"ATM Not Allowed" },
    { 62,	"Information Not Available" },
    { 71,	"Unknown Alphabet" },
    { 72,	"USSD Busy" },
    { 120,	"Nbr Sb Exceeded" },
    { 121,	"Rejected By User" },
    { 122,	"Rejected By Network" },
    { 123,	"Deflection To Served Subscriber" },
    { 124,	"Special Service Code" },
    { 125,	"Invalid Deflected To Number" },
    { 126,	"Max Number Of MPTY Participants Exceeded" },
    { 127,	"Resources Not Available" },
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


static int
dissect_gsm_map_Opcode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset, hf_index, &opcode);

  if (check_col(pinfo->cinfo, COL_INFO)){
    col_append_fstr(pinfo->cinfo, COL_INFO, val_to_str(opcode, gsm_map_opr_code_strings, "Unknown GSM-MAP (%u)"));
  }

  return offset;
}

static int dissect_invokeData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
 
  gint8 bug_class;
  gboolean bug_pc, bug_ind_field;
  gint32 bug_tag;
  guint32 bug_len1;
  
  guint8 octet;

  switch(opcode){
  case  2: /*updateLocation*/	
	  offset=dissect_gsm_map_UpdateLocationArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  3: /*cancelLocation*/
 	octet = tvb_get_guint8(tvb,0) & 0xf;
	if ( octet == 3){ /*   */ 
	  /* XXX  asn2wrs can not yet handle tagged assignment yes so this
	   * XXX is some conformance file magic to work around that bug
	   */
	  offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
	  offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
		offset=dissect_gsm_map_CancelLocationArg(TRUE, tvb, offset, pinfo, tree, -1);
	}else{
    offset=dissect_gsm_map_CancelLocationArgV2(FALSE, tvb, offset, pinfo, tree, -1);
	}
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
    offset=dissect_gsm_map_SS_ForBS_Code(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 12: /*activateSS*/
    offset=dissect_gsm_map_SS_ForBS_Code(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 13: /*deactivateSS*/
    offset=dissect_gsm_map_SS_ForBS_Code(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 14: /*interrogateSS*/
    offset=dissect_gsm_map_SS_ForBS_Code(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 15: /*authenticationFailureReport*/
	  offset=dissect_gsm_map_AuthenticationFailureReportArg(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 17: /*registerPassword*/
    offset=dissect_gsm_map_SS_Code(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Code);
    break;
  case 18: /*getPassword*/
    offset=dissect_gsm_map_GetPasswordArg(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_getPassword);
    break;
  case 20: /*releaseResources*/
    offset=dissect_gsm_map_ReleaseResourcesArg(FALSE, tvb, offset, pinfo, tree, -1);
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
	if ( octet == 3){ /* This is a V3 message ??? */ 
	  /* XXX  asn2wrs can not yet handle tagged assignment yes so this
	   * XXX is some conformance file magic to work around that bug
	   */
	  offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
	  offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
		offset=dissect_gsm_map_SendEndSignalArgV3(TRUE, tvb, offset, pinfo, tree, hf_gsm_mapSendEndSignal);
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
	octet = tvb_get_guint8(tvb,0) & 0xf;
	if ( octet == 3){ /* This is a V3 message ??? */ 
	  /* XXX  asn2wrs can not yet handle tagged assignment yes so this
	   * XXX is some conformance file magic to work around that bug
	   */
	  offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
	  offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
		offset = dissect_gsm_map_ProcessAccessSignallingArgV3(TRUE, tvb, offset, pinfo, tree, -1);
	}else{
    offset=dissect_gsm_map_Bss_APDU(FALSE, tvb, offset, pinfo, tree, -1);
	}
    break;
  case 34: /*forwardAccessSignalling*/
	octet = tvb_get_guint8(tvb,0) & 0xf;
	if ( octet == 3){ /* This is a V3 message ??? */
	  /* XXX  asn2wrs can not yet handle tagged assignment yes so this
	   * XXX is some conformance file magic to work around that bug
	   */
	  offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
	  offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
		offset=dissect_gsm_map_ForwardAccessSignallingArgV3(TRUE, tvb, offset, pinfo, tree, -1);
	}else{
		 offset=dissect_gsm_map_Bss_APDU(FALSE, tvb, offset, pinfo, tree, -1);
	}
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
	  if (application_context_version < 3 ){
		  offset = dissect_gsm_map_IMEI(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_imei);
	  }else{
		  offset=dissect_gsm_map_CheckIMEIArgV3(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_CheckIMEIArg);
	  }
    break;
  case 44: /*mt-forwardSM*/
    offset=dissect_gsm_map_Mt_forwardSM_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 45: /*sendRoutingInfoForSM*/
    offset=dissect_gsm_map_RoutingInfoForSMArg(FALSE, tvb, offset, pinfo, tree, -1);
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
    offset=dissect_gsm_map_SendIdentificationArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 56: /*sendAuthenticationInfo*/
	  if (application_context_version < 3 ){
		  offset=dissect_gsm_map_SendAuthenticationInfoArg(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_SendAuthenticationInfoArg);
	  }else{
		  offset=dissect_gsm_map_SendAuthenticationInfoArgV2(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_SendAuthenticationInfoArg);
	  }
	break;
  case 57: /*restoreData*/
	offset=dissect_gsm_map_RestoreDataArg(FALSE, tvb, offset, pinfo, tree, -1);
	break;
  case 58: /*sendIMSI*/
	offset = dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_msisdn);
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
  case 62: /*AnyTimeSubscriptionInterrogation*/
	  offset=dissect_gsm_map_AnyTimeSubscriptionInterrogationArg(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 63: /*informServiceCentre*/
    offset=dissect_gsm_map_InformServiceCentreArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 64: /*alertServiceCentre*/
    offset=dissect_gsm_map_AlertServiceCentreArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 65: /*AnyTimeModification*/
	  offset=dissect_gsm_map_AnyTimeModificationArg(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 66: /*readyForSM*/
    offset=dissect_gsm_map_ReadyForSM_Arg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 67: /*purgeMS*/
	/* XXX  asn2wrs can not yet handle tagged assignment yes so this
	 * XXX is some conformance file magic to work around that bug
	 */
	offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
	offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
    offset=dissect_gsm_map_PurgeMSArg(TRUE, tvb, offset, pinfo, tree, -1);
    break;
  case 68: /*prepareHandover*/
	octet = tvb_get_guint8(tvb,0) & 0xf;
	if ( octet == 3){ /* This is a V3 message ??? */ 
		/* XXX  asn2wrs can not yet handle tagged assignment yes so this
		 * XXX is some conformance file magic to work around that bug
		 */
		offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
		offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
		offset=dissect_gsm_map_PrepareHO_ArgV3(TRUE, tvb, offset, pinfo, tree, -1);
	}else{
		offset=dissect_gsm_map_PrepareHO_Arg(FALSE, tvb, offset, pinfo, tree, -1);
	}
    break;
  case 69: /*prepareSubsequentHandover*/
    offset=dissect_gsm_map_PrepareSubsequentHOArg(FALSE, tvb, offset, pinfo, tree, -1);
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
  case 78: /*secureTransportClass1*/
  case 79: /*secureTransportClass1*/
  case 80: /*secureTransportClass1*/
  case 81: /*secureTransportClass1*/
    offset=dissect_gsm_map_SecureTransportArg(FALSE, tvb, offset, pinfo, tree, -1);
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
  case 87: /*ist-Alert*/
    offset=dissect_gsm_map_IST_AlertArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 88: /*ist-Command*/
    offset=dissect_gsm_map_IST_CommandArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 89: /*noteMM-Event*/
    offset=dissect_gsm_map_NoteMM_EventArg(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  default:
    proto_tree_add_text(tree, tvb, offset, -1, "Unknown invokeData blob");
  }
  return offset;
}


static int dissect_returnResultData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {

 gint8 bug_class;
 gboolean bug_pc, bug_ind_field;
 gint32 bug_tag;
 guint32 bug_len1;
	
  guint8 octet;
  switch(opcode){
  case  2: /*updateLocation*/
	octet = tvb_get_guint8(tvb,offset);
	/* As it seems like SEQUENCE OF sometimes is omitted, find out if it's there */
	if ( octet == 0x30 ){ /* Class 0 Univerasl, P/C 1 Constructed,Tag 16 Sequence OF */
		offset=dissect_gsm_map_UpdateLocationRes(FALSE, tvb, offset, pinfo, tree, -1);
	}else{ /* Try decoding with IMPLICIT flag set */ 
		offset=dissect_gsm_map_UpdateLocationRes(TRUE, tvb, offset, pinfo, tree, -1);
	  }
    break;
  case  3: /*cancelLocation*/
    offset=dissect_gsm_map_CancelLocationRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  4: /*provideRoamingNumber*/
    offset=dissect_gsm_map_ProvideRoamingNumberRes(FALSE, tvb, offset, pinfo, tree, -1); /* TRUE florent */
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
    offset=dissect_gsm_map_SS_Info(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case  11: /*eraseSS*/
    offset=dissect_gsm_map_SS_Info(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 12: /*activateSS*/
    offset=dissect_gsm_map_SS_Info(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 13: /*deactivateSS*/
    offset=dissect_gsm_map_SS_Info(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 14: /*interrogateSS*/
    offset=dissect_gsm_map_InterrogateSS_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 15: /*authenticationFailureReport*/
	offset=dissect_gsm_map_AuthenticationFailureReportRes(FALSE, tvb, offset, pinfo, tree, -1);
	break;
  case 17: /*registerPassword*/
    offset=dissect_gsm_map_NewPassword(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_ss_Code);
    break;
  case 18: /*getPassword*/
    offset=dissect_gsm_map_CurrentPassword(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_currentPassword);
    break;
  case 20: /*releaseResources*/
    offset=dissect_gsm_map_ReleaseResourcesRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 22: /*sendRoutingInfo*/
	  /* This is done to get around a problem with IMPLICIT tag:s */
	offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
	offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
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
    offset=dissect_gsm_map_SendEndSignalRes(FALSE, tvb, offset, pinfo, tree, -1);
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
	if (application_context_version < 3 ){
		offset = dissect_gsm_map_EquipmentStatus(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_equipmentStatus);
	}else{
		offset=dissect_gsm_map_CheckIMEIRes(FALSE, tvb, offset, pinfo, tree, -1);
	}
    break;
  case 44: /*mt-forwardSM*/
    offset=dissect_gsm_map_Mt_forwardSM_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 45: /*sendRoutingInfoForSM*/
    offset=dissect_gsm_map_RoutingInfoForSM_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 46: /*mo-forwardSM*/
    offset=dissect_gsm_map_Mo_forwardSM_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 48: /*reportSM-DeliveryStatus*/
    offset=dissect_gsm_map_ReportSM_DeliveryStatusRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 50: /*activateTraceMode*/
    offset=dissect_gsm_map_ActivateTraceModeRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 51: /*deactivateTraceMode*/
    offset=dissect_gsm_map_DeactivateTraceModeRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 55: /*sendIdentification
			* In newer versions IMSI and authenticationSetList is OPTIONAL and two new parameters added
			* however if the tag (3) is stripped of it should work with the 'new' def.(?) 
			*/
	octet = tvb_get_guint8(tvb,0) & 0xf;
	if ( octet == 3){ /* This is a V3 message ??? */ 
	  /* XXX  asn2wrs can not yet handle tagged assignment yes so this
	   * XXX is some conformance file magic to work around that bug
	   */
	  offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
	  offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
	}
	offset=dissect_gsm_map_SendIdentificationRes(TRUE, tvb, offset, pinfo, tree, -1);
    break;
  case 56: /*sendAuthenticationInfo*/
    octet = tvb_get_guint8(tvb,0) & 0xf;
    if ( octet == 3){ /* This is a V3 message ??? */
      /* XXX  asn2wrs can not yet handle tagged assignment yes so this
       * XXX is some conformance file magic to work around that bug
       */
		offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
		offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
 
		offset=dissect_gsm_map_SendAuthenticationInfoResV3(TRUE, tvb, offset, pinfo, tree, hf_gsm_map_SendAuthenticationInfoRes);
	}else{
		offset=dissect_gsm_map_SendAuthenticationInfoRes(FALSE, tvb, offset, pinfo, tree, -1);
	}
	break;
  case 57: /*restoreData*/
    offset=dissect_gsm_map_RestoreDataRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 58: /*sendIMSI*/
    offset=dissect_gsm_map_IMSI(FALSE, tvb, offset, pinfo, tree, hf_gsm_map_imsi);
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
  case 62: /*AnyTimeSubscriptionInterrogation*/
	offset=dissect_gsm_map_AnyTimeSubscriptionInterrogationRes(FALSE, tvb, offset, pinfo, tree, -1);
	break;
  case 65: /*AnyTimeModification*/
	offset=dissect_gsm_map_AnyTimeModificationRes(FALSE, tvb, offset, pinfo, tree, -1);
	break;
  case 66: /*readyForSM*/
    offset=dissect_gsm_map_ReadyForSM_Res(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 67: /*purgeMS*/
    offset=dissect_gsm_map_PurgeMSRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 68: /*prepareHandover*/
	octet = tvb_get_guint8(tvb,0) & 0xf;
	if ( octet == 3){ /* This is a V3 message ??? */
	  /* XXX  asn2wrs can not yet handle tagged assignment yes so this
	   * XXX is some conformance file magic to work around that bug
	   */
		offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
		offset = get_ber_length(tree, tvb, offset, &bug_len1, &bug_ind_field);
		offset=dissect_gsm_map_PrepareHO_ResV3(TRUE, tvb, offset, pinfo, tree, hf_gsm_mapSendEndSignal);
	}else{
		offset=dissect_gsm_map_PrepareHO_Res(FALSE, tvb, offset, pinfo, tree, -1);
	}
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
  case 78: /*secureTransportClass1*/
  case 79: /*secureTransportClass2*/
  case 80: /*secureTransportClass3*/
  case 81: /*secureTransportClass4*/
    offset=dissect_gsm_map_SecureTransportRes(FALSE, tvb, offset, pinfo, tree, -1);
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
  case 87: /*ist-Alert*/
    offset=dissect_gsm_map_IST_AlertRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 88: /*ist-Command*/
    offset=dissect_gsm_map_IST_CommandRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
  case 89: /*noteMM-Event*/
    offset=dissect_gsm_map_NoteMM_EventRes(FALSE, tvb, offset, pinfo, tree, -1);
    break;
 default:
    proto_tree_add_text(tree, tvb, offset, -1, "Unknown returnResultData blob");
  }
  return offset;
}



static int dissect_returnErrorData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
	
  switch(errorCode){
  case 1: /* UnknownSubscriberParam */
	  offset=dissect_gsm_map_UnknownSubscriberParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 4: /* SecureTransportErrorParam */
	  offset=dissect_gsm_map_SecureTransportErrorParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 5: /* UnidentifiedSubParam */
	  offset=dissect_gsm_map_UnidentifiedSubParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 6: /* AbsentSubscriberSM-Param */
	  offset=dissect_gsm_map_AbsentSubscriberSM_Param(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 8: /* RoamingNotAllowedParam */
	  offset=dissect_gsm_map_RoamingNotAllowedParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 9: /* IllegalSubscriberParam */
	  offset=dissect_gsm_map_IllegalSubscriberParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 10: /* BearerServNotProvParam */
	  offset=dissect_gsm_map_BearerServNotProvParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 11: /* TeleservNotProvParam */
	  offset=dissect_gsm_map_TeleservNotProvParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 12: /* IllegalEquipmentParam */
	  offset=dissect_gsm_map_IllegalEquipmentParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 13: /* CallBarredParam */
	  offset=dissect_gsm_map_CallBarredParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 14: /* ForwardingViolationParam */
	  offset=dissect_gsm_map_ForwardingViolationParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 15: /* CUG-RejectParam */
	  offset=dissect_gsm_map_CUG_RejectParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 16: /* IllegalSS-OperationParam */
	  offset=dissect_gsm_map_IllegalSS_OperationParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 18: /* SS-NotAvailableParam */
	  offset=dissect_gsm_map_SS_NotAvailableParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 19: /* SS-SubscriptionViolationParam */
	  offset=dissect_gsm_map_SS_SubscriptionViolationParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 20: /* SS-IncompatibilityCause */
	  offset=dissect_gsm_map_SS_IncompatibilityCause(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 21: /* FacilityNotSupParam */
	  offset=dissect_gsm_map_FacilityNotSupParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 27: /* AbsentSubscriberParam */
	  offset=dissect_gsm_map_AbsentSubscriberParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 28: /* IncompatibleTerminalParam */
	  offset=dissect_gsm_map_IncompatibleTerminalParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 29: /* ShortTermDenialParam */
	  offset=dissect_gsm_map_ShortTermDenialParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 30: /* LongTermDenialParam */
	  offset=dissect_gsm_map_LongTermDenialParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 31: /* SubBusyForMT-SMS-Param */
	  offset=dissect_gsm_map_SubBusyForMT_SMS_Param(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 32: /* SM-DeliveryFailureCause */
	  offset=dissect_gsm_map_SM_DeliveryFailureCause(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 33: /* MessageWaitListFullParam */
	  offset=dissect_gsm_map_MessageWaitListFullParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 34: /* SystemFailureParam */
	  offset=dissect_gsm_map_SystemFailureParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 35: /* DataMissingParam */
	  offset=dissect_gsm_map_DataMissingParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 36: /* UnexpectedDataParam */
	  offset=dissect_gsm_map_UnexpectedDataParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 37: /* PW-RegistrationFailureCause */
	  offset=dissect_gsm_map_PW_RegistrationFailureCause(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 39: /* NoRoamingNbParam */
	  offset=dissect_gsm_map_NoRoamingNbParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 40: /* TracingBufferFullParam */
	  offset=dissect_gsm_map_TracingBufferFullParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 42: /* TargetCellOutsideGCA-Param */
	  offset=dissect_gsm_map_TargetCellOutsideGCA_Param(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 44: /* NumberChangedParam */
	  offset=dissect_gsm_map_NumberChangedParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 45: /* BusySubscriberParam */
	  offset=dissect_gsm_map_BusySubscriberParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 46: /* NoSubscriberReplyParam */
	  offset=dissect_gsm_map_NoSubscriberReplyParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 47: /* ForwardingFailedParam */
	  offset=dissect_gsm_map_ForwardingFailedParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 48: /* OR-NotAllowedParam */
	  offset=dissect_gsm_map_OR_NotAllowedParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 49: /* ATI-NotAllowedParam */
	  offset=dissect_gsm_map_ATI_NotAllowedParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 50: /* NoGroupCallNbParam */
	  offset=dissect_gsm_map_NoGroupCallNbParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 51: /* ResourceLimitationParam */
	  offset=dissect_gsm_map_ResourceLimitationParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 52: /* UnauthorizedRequestingNetwork-Param */
	  offset=dissect_gsm_map_UnauthorizedRequestingNetwork_Param(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 53: /* UnauthorizedLCSClient-Param */
	  offset=dissect_gsm_map_UnauthorizedLCSClient_Param(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 54: /* PositionMethodFailure-Param */
	  offset=dissect_gsm_map_PositionMethodFailure_Param(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 58: /* UnknownOrUnreachableLCSClient-Param */
	  offset=dissect_gsm_map_UnknownOrUnreachableLCSClient_Param(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 59: /* MM-EventNotSupported-Param */
	  offset=dissect_gsm_map_MM_EventNotSupported_Param(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 60: /* ATSI-NotAllowedParam */
	  offset=dissect_gsm_map_ATSI_NotAllowedParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 61: /* ATM-NotAllowedParam */
	  offset=dissect_gsm_map_ATM_NotAllowedParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  case 62: /* InformationNotAvailableParam */
	  offset=dissect_gsm_map_InformationNotAvailableParam(FALSE, tvb, offset, pinfo, tree, -1);
	  break;
  default:
	  proto_tree_add_text(tree, tvb, offset, -1, "Unknown returnErrorData blob");
	  break;
  }
  return offset;
}
static guint8 gsmmap_pdu_type = 0;
static guint8 gsm_map_pdu_size = 0;

static int
dissect_gsm_map_GSMMAPPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo , proto_tree *tree, int hf_index) {

  char *version_ptr;

  opcode = 0;
  application_context_version = 0;
  if (pinfo->private_data != NULL){
    version_ptr = strrchr(pinfo->private_data,'.');
	if (version_ptr) {
		application_context_version = atoi(version_ptr+1);
	}
  }

  gsmmap_pdu_type = tvb_get_guint8(tvb, offset)&0x0f;
  /* Get the length and add 2 */
  gsm_map_pdu_size = tvb_get_guint8(tvb, offset+1)+2;

  if (check_col(pinfo->cinfo, COL_INFO)){
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str(gsmmap_pdu_type, gsm_map_Component_vals, "Unknown GSM-MAP PDU (%u)"));
	col_append_fstr(pinfo->cinfo, COL_INFO, " ");
  }
  offset = dissect_gsm_map_Component(FALSE, tvb, 0, pinfo, tree, hf_gsm_map_Component_PDU);
  return offset;
/*
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              GSMMAPPDU_choice, hf_index, ett_gsm_map_GSMMAPPDU, NULL);
*/

  return offset;
}




static void
dissect_gsm_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
    proto_item		*item=NULL;
    proto_tree		*tree=NULL;
    /* Used for gsm_map TAP */
    static		gsm_map_tap_rec_t tap_rec;
    gint		op_idx;


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
    match_strval_idx(opcode, gsm_map_opr_code_strings, &op_idx);

    tap_rec.invoke = FALSE;
    if ( gsmmap_pdu_type  == 1 )
	tap_rec.invoke = TRUE;
    tap_rec.opr_code_idx = op_idx;
    tap_rec.size = gsm_map_pdu_size;

    tap_queue_packet(gsm_map_tap, pinfo, &tap_rec);
}

const value_string ssCode_vals[] = {
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

static const value_string Bearerservice_vals[] = {
{0x00, "allBearerServices" },
{0x10, "allDataCDA-Services" },
{0x11, "dataCDA-300bps" },
{0x12, "dataCDA-1200bps" },
{0x13, "dataCDA-1200-75bps" },
{0x14, "dataCDA-2400bps" },
{0x15, "dataCDA-4800bps" },
{0x16, "dataCDA-9600bps" },
{0x17, "general-dataCDA" },

{0x18, "allDataCDS-Services" },
{0x1A, "dataCDS-1200bps" },
{0x1C, "dataCDS-2400bps" },
{0x1D, "dataCDS-4800bps" },
{0x1E, "dataCDS-9600bps" },
{0x1F, "general-dataCDS" },

{0x20, "allPadAccessCA-Services" },
{0x21, "padAccessCA-300bps" },
{0x22, "padAccessCA-1200bps" },
{0x23, "padAccessCA-1200-75bps" },
{0x24, "padAccessCA-2400bps" },
{0x25, "padAccessCA-4800bps" },
{0x26, "padAccessCA-9600bps" },
{0x27, "general-padAccessCA" },

{0x28, "allDataPDS-Services" },
{0x2C, "dataPDS-2400bps" },
{0x2D, "dataPDS-4800bps" },
{0x2E, "dataPDS-9600bps" },
{0x2F, "general-dataPDS" },

{0x30, "allAlternateSpeech-DataCDA" },
{0x38, "allAlternateSpeech-DataCDS" },
{0x40, "allSpeechFollowedByDataCDA" },
{0x48, "allSpeechFollowedByDataCDS" },

{0x50, "allDataCircuitAsynchronous" },
{0x60, "allAsynchronousServices" },
{0x58, "allDataCircuitSynchronous" },
{0x68, "allSynchronousServices" },

{0xD0, "allPLMN-specificBS" },
{0xD1, "plmn-specificBS-1" },
{0xD2, "plmn-specificBS-2" },
{0xD3, "plmn-specificBS-3" },
{0xD4, "plmn-specificBS-4" },
{0xD5, "plmn-specificBS-5" },
{0xD6, "plmn-specificBS-6" },
{0xD7, "plmn-specificBS-7" },
{0xD8, "plmn-specificBS-8" },
{0xD9, "plmn-specificBS-9" },
{0xDA, "plmn-specificBS-A" },
{0xDB, "plmn-specificBS-B" },
{0xDC, "plmn-specificBS-C" },
{0xDD, "plmn-specificBS-D" },
{0xDE, "plmn-specificBS-E" },
{0xDF, "plmn-specificBS-F" },

{ 0, NULL }
};

/* ForwardingOptions 

-- bit 8: notification to forwarding party
-- 0 no notification
-- 1 notification
*/
static const true_false_string notification_value  = {
  "Notification",
  "No notification"
};
/*
-- bit 7: redirecting presentation
-- 0 no presentation
-- 1 presentation
*/
static const true_false_string redirecting_presentation_value  = {
  "Presentation",
  "No presentationn"
};
/*
-- bit 6: notification to calling party
-- 0 no notification
-- 1 notification
*/
/*
-- bit 5: 0 (unused)
-- bits 43: forwarding reason
-- 00 ms not reachable
-- 01 ms busy
-- 10 no reply
-- 11 unconditional when used in a SRI Result,
-- or call deflection when used in a RCH Argument
*/
static const value_string forwarding_reason_values[] = {
{0x0, "ms not reachable" },
{0x1, "ms busy" },
{0x2, "no reply" },
{0x3, "unconditional when used in a SRI Result or call deflection when used in a RCH Argument" },
{ 0, NULL }
};
/*
-- bits 21: 00 (unused)
*/

static const value_string pdp_type_org_values[] = {
{0x0, "ETSI" },
{0x1, "IETF" },
{0xf, "Empty PDP type" },
{ 0, NULL }
};

static const value_string etsi_pdp_type_number_values[] = {
{0x0, "Reserved, used in earlier version of this protocol" },
{0x1, "PPP" },
{ 0, NULL }
};

static const value_string ietf_pdp_type_number_values[] = {
{0x21, "IPv4 Address" },
{0x57, "IPv6 Address" },
{ 0, NULL }
};

/*
ChargingCharacteristics ::= OCTET STRING (SIZE (2))
-- Octets are coded according to 3GPP TS 32.015.
-- From 3GPP TS 32.015.
--
-- Descriptions for the bits of the flag set:
--
-- Bit 1: H (Hot billing) := '00000001'B
-- Bit 2: F (Flat rate) := '00000010'B
-- Bit 3: P (Prepaid service) := '00000100'B
-- Bit 4: N (Normal billing) := '00001000'B
-- Bit 5: - (Reserved, set to 0) := '00010000'B
-- Bit 6: - (Reserved, set to 0) := '00100000'B
-- Bit 7: - (Reserved, set to 0) := '01000000'B
-- Bit 8: - (Reserved, set to 0) := '10000000'B
*/
static const value_string chargingcharacteristics_values[] = {
{0x1, "H (Hot billing)" },
{0x2, "F (Flat rate)" },
{0x4, "P (Prepaid service)" },
{0x8, "N (Normal billing)" },
{ 0, NULL }
};
/*--- proto_reg_handoff_gsm_map ---------------------------------------*/
static void range_delete_callback(guint32 ssn)
{
    if (ssn) {
	delete_itu_tcap_subdissector(ssn, map_handle);
    }
}

static void range_add_callback(guint32 ssn)
{
    if (ssn) {
	add_itu_tcap_subdissector(ssn, map_handle);
    }
}

void proto_reg_handoff_gsm_map(void) {

    static int map_prefs_initialized = FALSE;
    data_handle = find_dissector("data");

    if (!map_prefs_initialized) {
	map_prefs_initialized = TRUE;
	map_handle = create_dissector_handle(dissect_gsm_map, proto_gsm_map);
  register_ber_oid_dissector_handle("0.4.0.0.1.0.1.3", map_handle, proto_gsm_map, "itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) networkLocUp(1) version3(3)");  
  register_ber_oid_dissector_handle("0.4.0.0.1.0.1.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) networkLocUp(1) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.2.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) locationCancel(2) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.2.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) locationCancel(2) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.2.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) locationCancel(2) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.3.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) roamingNbEnquiry(3) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.3.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) roamingNbEnquiry(3) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.3.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) roamingNbEnquiry(3) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.5.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) locInfoRetrieval(5) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.5.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) locInfoRetrieval(5) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.5.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) locInfoRetrieval(5) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.6.4", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) callControlTransfer(6) version4(4)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.7.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) reporting(7) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.8.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) callCompletion(8) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.10.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) reset(10) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.10.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) reset(10) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.11.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) handoverControl(11) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.11.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) handoverControl(11) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.11.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) handoverControl(11) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.12.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) sIWFSAllocation(12) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.13.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) equipmentMngt(13) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.13.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) equipmentMngt(13) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.14.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) infoRetrieval(14) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.14.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) infoRetrieval(14) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.14.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) infoRetrieval(14) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.15.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) interVlrInfoRetrieval(15) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.15.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) interVlrInfoRetrieval(15) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.15.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) interVlrInfoRetrieval(15) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.16.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) subscriberDataMngt(16) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.16.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) subscriberDataMngt(16) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.16.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) subscriberDataMngt(16) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.17.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) tracing(17) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.17.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) tracing(17) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.18.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) networkFunctionalSs(18) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.18.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) networkFunctionalSs(18) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.19.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) networkUnstructuredSs(19) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.20.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgGateway(20) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.20.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgGateway(20) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.20.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgGateway(20) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.21.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgMO-Relay(21) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.21.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) --shortMsgRelay--21 version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.22.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) subscriberDataModificationNotification(22) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.23.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgAlert(23) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.23.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgAlert(23) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.24.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) mwdMngt(24) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.24.1", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) mwdMngt(24) version1(1)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.25.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgMT-Relay(25) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.25.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) shortMsgMT-Relay(25) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.26.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) imsiRetrieval(26) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.27.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) msPurging(27) version2(2)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.27.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) msPurging(27) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.29.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) anyTimeInfoEnquiry(29) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.31.2", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) oupCallControl(31) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.32.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) gprsLocationUpdate(32) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.33.4", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) rsLocationInfoRetrieval(33) version4(4)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.34.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) failureReport(34) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.36.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) ss-InvocationNotification(36) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.37.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) locationSvcGateway(37) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.38.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) locationSvcEnquiry(38) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.39.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) authenticationFailureReport(39) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.40.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) secureTransportHandling(40) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.42.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) mm-EventReporting(42) version3(3)" );
  register_ber_oid_dissector_handle("0.4.0.0.1.0.43.3", map_handle, proto_gsm_map,"itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) anyTimeInfoHandling(43) version3(3)" );
    }
    else {
	range_foreach(ssn_range, range_delete_callback);
    }

    g_free(ssn_range);
    ssn_range = range_copy(global_ssn_range);

    range_foreach(ssn_range, range_add_callback);

}

/*--- proto_register_gsm_map -------------------------------------------*/
void proto_register_gsm_map(void) {
	module_t *gsm_map_module;

  /* List of fields */
  static hf_register_info hf[] = {
	  /*
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
    { &hf_gsm_map_invoke,
      { "invoke", "gsm_map.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSMMAPPDU/invoke", HFILL }},
    { &hf_gsm_map_returnResult,
      { "returnResult", "gsm_map.returnResult",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSMMAPPDU/returnResult", HFILL }},
	{&hf_gsm_map_returnResult_result,
      { "returnResult_result", "gsm_map.returnresultresult",
        FT_BYTES, BASE_NONE, NULL, 0,
        "returnResult_result", HFILL }},
	{&hf_gsm_map_returnError_result,
      { "returnError_result", "gsm_map.returnerrorresult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "returnError_result", HFILL }},
	{&hf_gsm_map_returnError,
      { "returnError", "gsm_map.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSMMAPPDU/returnError", HFILL }},
	{&hf_gsm_map_local_errorCode,
      { "Local Error Code", "gsm_map.localerrorCode",
        FT_UINT32, BASE_DEC, VALS(gsm_map_err_code_string_vals), 0,
        "localerrorCode", HFILL }},
	{&hf_gsm_map_global_errorCode_oid,
      { "Global Error Code OID", "gsm_map.hlobalerrorCodeoid",
        FT_STRING, BASE_NONE, NULL, 0,
        "globalerrorCodeoid", HFILL }},
	{&hf_gsm_map_global_errorCode,
      { "Global Error Code", "gsm_map.globalerrorCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "globalerrorCode", HFILL }},
    { &hf_gsm_map_getPassword,
      { "Password", "gsm_map.password",
        FT_UINT8, BASE_DEC, VALS(gsm_map_GetPasswordArg_vals), 0,
        "Password", HFILL }},

		*/
	{ &hf_gsm_map_SendAuthenticationInfoArg,
      { "SendAuthenticationInfoArg", "gsm_map.SendAuthenticationInfoArg",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SendAuthenticationInfoArg", HFILL }},
	{ &hf_gsm_map_SendAuthenticationInfoRes,
      { "SendAuthenticationInfoRes", "gsm_map.SendAuthenticationInfoRes",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SendAuthenticationInfoRes", HFILL }},
    { &hf_gsm_map_currentPassword,
      { "currentPassword", "gsm_map.currentPassword",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
	{ &hf_gsm_mapSendEndSignal,
      { "mapSendEndSignalArg", "gsm_map.mapsendendsignalarg",
        FT_BYTES, BASE_NONE, NULL, 0,
        "mapSendEndSignalArg", HFILL }},
	{ &hf_gsm_map_CheckIMEIArg,
      { "gsm_CheckIMEIArg", "gsm_map.CheckIMEIArg",
        FT_BYTES, BASE_NONE, NULL, 0,
        "gsm_CheckIMEIArg", HFILL }},
    { &hf_gsm_map_extension,
      { "Extension", "gsm_map.extension",
        FT_BOOLEAN, 8, TFS(&gsm_map_extension_value), 0x80,
        "Extension", HFILL }},
    { &hf_gsm_map_nature_of_number,
      { "Nature of number", "gsm_map.nature_of_number",
        FT_UINT8, BASE_HEX, VALS(gsm_map_nature_of_number_values), 0x70,
        "Nature of number", HFILL }},
    { &hf_gsm_map_number_plan,
      { "Number plan", "gsm_map.number_plan",
        FT_UINT8, BASE_HEX, VALS(gsm_map_number_plan_values), 0x0f,
        "Number plan", HFILL }},
	{ &hf_gsm_map_isdn_address_digits,
      { "ISDN Address digits", "gsm_map.isdn.address.digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "ISDN Address digits", HFILL }},
	{ &hf_gsm_map_address_digits,
      { "Address digits", "gsm_map.address.digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "Address digits", HFILL }},
	{ &hf_gsm_map_servicecentreaddress_digits,
      { "ServiceCentreAddress digits", "gsm_map.servicecentreaddress_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "ServiceCentreAddress digits", HFILL }},
	{ &hf_gsm_map_imsi_digits,
      { "Imsi digits", "gsm_map.imsi_digits",
        FT_STRING, BASE_NONE, NULL, 0,
        "Imsi digits", HFILL }},
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
      { "R bit", "gsm_map.ss_status_r_bit",
        FT_BOOLEAN, 8, TFS(&gsm_map_Ss_Status_r_values), 0x02,
        "R bit", HFILL }},
	{ &hf_gsm_map_Ss_Status_a_bit,
      { "A bit", "gsm_map.ss_status_a_bit",
        FT_BOOLEAN, 8, TFS(&gsm_map_Ss_Status_a_values), 0x01,
        "A bit", HFILL }},
	{ &hf_gsm_map_notification_to_forwarding_party,
      { "Notification to forwarding party", "gsm_map.notification_to_forwarding_party",
        FT_BOOLEAN, 8, TFS(&notification_value), 0x80,
        "Notification to forwarding party", HFILL }},
	{ &hf_gsm_map_redirecting_presentation,
      { "Redirecting presentation", "gsm_map.redirecting_presentation",
        FT_BOOLEAN, 8, TFS(&redirecting_presentation_value), 0x40,
        "Redirecting presentation", HFILL }},
	{ &hf_gsm_map_notification_to_calling_party,
      { "Notification to calling party", "gsm_map.notification_to_clling_party",
        FT_BOOLEAN, 8, TFS(&notification_value), 0x20,
        "Notification to calling party", HFILL }},
    { &hf_gsm_map_forwarding_reason,
      { "Forwarding reason", "gsm_map.forwarding_reason",
        FT_UINT8, BASE_HEX, VALS(forwarding_reason_values), 0x0c,
        "forwarding reason", HFILL }},
    { &hf_gsm_map_pdp_type_org,
      { "PDP Type Organization", "gsm_map.pdp_type_org",
        FT_UINT8, BASE_HEX, VALS(pdp_type_org_values), 0x0f,
        "PDP Type Organization", HFILL }},
    { &hf_gsm_map_etsi_pdp_type_number,
      { "PDP Type Number", "gsm_map.pdp_type_org",
        FT_UINT8, BASE_HEX, VALS(etsi_pdp_type_number_values), 0,
        "ETSI PDP Type Number", HFILL }},
    { &hf_gsm_map_ietf_pdp_type_number,
      { "PDP Type Number", "gsm_map.ietf_pdp_type_number",
        FT_UINT8, BASE_HEX, VALS(ietf_pdp_type_number_values), 0,
        "IETF PDP Type Number", HFILL }},
    { &hf_gsm_map_ext_qos_subscribed_pri,
      { "Allocation/Retention priority", "gsm_map.ext_qos_subscribed_pri",
        FT_UINT8, BASE_DEC, NULL, 0xff,
        "Allocation/Retention priority", HFILL }},
    { &hf_gsm_map_qos_traffic_cls,
      { "Traffic class", "gsm_map.qos.traffic_cls",
        FT_UINT8, BASE_DEC, VALS(gsm_a_qos_traffic_cls_vals), 0xe0,
        "Traffic class", HFILL }},
    { &hf_gsm_map_qos_del_order,
      { "Delivery order", "gsm_map.qos.del_order",
        FT_UINT8, BASE_DEC, VALS(gsm_a_qos_traffic_cls_vals), 0x18,
        "Delivery order", HFILL }},
    { &hf_gsm_map_qos_del_of_err_sdu,
      { "Delivery of erroneous SDUs", "gsm_map.qos.del_of_err_sdu",
        FT_UINT8, BASE_DEC, VALS(gsm_a_qos_del_of_err_sdu_vals), 0x03,
        "Delivery of erroneous SDUs", HFILL }},
    { &hf_gsm_map_qos_ber,
      { "Residual Bit Error Rate (BER)", "gsm_map.qos.ber",
        FT_UINT8, BASE_DEC, VALS(gsm_a_qos_ber_vals), 0xf0,
        "Residual Bit Error Rate (BER)", HFILL }},
    { &hf_gsm_map_qos_sdu_err_rat,
      { "SDU error ratio", "gsm_map.qos.sdu_err_rat",
        FT_UINT8, BASE_DEC, VALS(gsm_a_qos_sdu_err_rat_vals), 0x0f,
        "SDU error ratio", HFILL }},
    { &hf_gsm_map_qos_traff_hdl_pri,
      { "Traffic handling priority", "gsm_map.qos.traff_hdl_pri",
        FT_UINT8, BASE_DEC, VALS(gsm_a_qos_traff_hdl_pri_vals), 0x03,
        "Traffic handling priority", HFILL }},

    { &hf_gsm_map_qos_max_sdu,
      { "Maximum SDU size", "gsm_map.qos.max_sdu",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Maximum SDU size", HFILL }},		
    { &hf_gsm_map_max_brate_ulink,
      { "Maximum bit rate for uplink in kbit/s", "gsm_map.qos.max_brate_ulink",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Maximum bit rate for uplink", HFILL }},
    { &hf_gsm_map_max_brate_dlink,
      { "Maximum bit rate for downlink in kbit/s", "gsm_map.qos.max_brate_dlink",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Maximum bit rate for downlink", HFILL }},
    { &hf_gsm_map_qos_transfer_delay,
      { "Transfer delay (Raw data see TS 24.008 for interpretation)", "gsm_map.qos.transfer_delay",
        FT_UINT8, BASE_DEC, NULL, 0xfc,
        "Transfer delay", HFILL }},
    { &hf_gsm_map_guaranteed_max_brate_ulink,
      { "Guaranteed bit rate for uplink in kbit/s", "gsm_map.qos.brate_ulink",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Guaranteed bit rate for uplink", HFILL }},
    { &hf_gsm_map_guaranteed_max_brate_dlink,
      { "Guaranteed bit rate for downlink in kbit/s", "gsm_map.qos.brate_dlink",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "Guaranteed bit rate for downlink", HFILL }},
   { &hf_gsm_map_GSNAddress_IPv4,
      { "GSN-Address IPv4",  "gsm_map.gsnaddress_ipv4",
	  FT_IPv4, BASE_NONE, NULL, 0,
	  "IPAddress IPv4", HFILL }},
   { &hf_gsm_map_GSNAddress_IPv6,
      { "GSN Address IPv6",  "gsm_map.gsnaddress_ipv6",
	  FT_IPv4, BASE_NONE, NULL, 0,
	  "IPAddress IPv6", HFILL }},
	{ &hf_geo_loc_type_of_shape,
		{ "Location estimate","gad.location_estimate",
		FT_UINT8,BASE_DEC, VALS(type_of_shape_vals), 0xf0,          
		"Location estimate", HFILL }
	},
	{ &hf_geo_loc_sign_of_lat,
		{ "Sign of latitude","gad.sign_of_latitude",
		FT_UINT8,BASE_DEC, VALS(sign_of_latitude_vals), 0x80,          
		"Sign of latitude", HFILL }
	},
	{ &hf_geo_loc_deg_of_lat,
		{ "Degrees of latitude","gad.sign_of_latitude",
		FT_UINT24,BASE_DEC, NULL, 0x7fffff,          
		"Degrees of latitude", HFILL }
	},
	{ &hf_geo_loc_deg_of_long,
		{ "Degrees of longitude","gad.sign_of_longitude",
		FT_UINT24,BASE_DEC, NULL, 0xffffff,          
		"Degrees of longitude", HFILL }
	},
	{ &hf_geo_loc_uncertainty_code,
		{ "Uncertainty code","gad.uncertainty_code",
		FT_UINT8,BASE_DEC, NULL, 0x7f,          
		"Uncertainty code", HFILL }
	},
	{ &hf_geo_loc_uncertainty_semi_major,
		{ "Uncertainty semi-major","gad.uncertainty_semi_major",
		FT_UINT8,BASE_DEC, NULL, 0x7f,          
		"Uncertainty semi-major", HFILL }
	},
	{ &hf_geo_loc_uncertainty_semi_minor,
		{ "Uncertainty semi-minor","gad.uncertainty_semi_minor",
		FT_UINT8,BASE_DEC, NULL, 0x7f,          
		"Uncertainty semi-minor", HFILL }
	},
	{ &hf_geo_loc_orientation_of_major_axis,
		{ "Orientation of major axis","gad.orientation_of_major_axis",
		FT_UINT8,BASE_DEC, NULL, 0x0,          
		"Orientation of major axis", HFILL }
	},
	{ &hf_geo_loc_uncertainty_altitude,
		{ "Uncertainty Altitude","gad.uncertainty_altitude",
		FT_UINT8,BASE_DEC, NULL, 0x7f,          
		"Uncertainty Altitude", HFILL }
	},
	{ &hf_geo_loc_confidence,
		{ "Confidence(%)","gad.confidence",
		FT_UINT8,BASE_DEC, NULL, 0x7f,          
		"Confidence(%)", HFILL }
	},
	{ &hf_geo_loc_no_of_points,
		{ "Number of points","gad.no_of_points",
		FT_UINT8,BASE_DEC, NULL, 0x0f,          
		"Number of points", HFILL }
	},
	{ &hf_geo_loc_D,
		{ "D: Direction of Altitude","gad.D",
		FT_UINT16,BASE_DEC, VALS(dir_of_alt_vals), 0x8000,          
		"D: Direction of Altitude", HFILL }
	},
	{ &hf_geo_loc_altitude,
		{ "Altitude in meters","gad.altitude",
		FT_UINT16,BASE_DEC, NULL, 0x7fff,          
		"Altitude", HFILL }
	},
	{ &hf_geo_loc_inner_radius,
		{ "Inner radius","gad.altitude",
		FT_UINT16,BASE_DEC, NULL, 0x0,          
		"Inner radius", HFILL }
	},
	{ &hf_geo_loc_uncertainty_radius,
		{ "Uncertainty radius","gad.no_of_points",
		FT_UINT8,BASE_DEC, NULL, 0x7f,          
		"Uncertainty radius", HFILL }
	},
	{ &hf_geo_loc_offset_angle,
		{ "Offset angle","gad.offset_angle",
		FT_UINT8,BASE_DEC, NULL, 0x0,          
		"Offset angle", HFILL }
	},
	{ &hf_geo_loc_included_angle,
		{ "Included angle","gad.included_angle",
		FT_UINT8,BASE_DEC, NULL, 0x0,          
		"Included angle", HFILL }
	},


/*--- Included file: packet-gsm_map-hfarr.c ---*/
#line 1 "packet-gsm_map-hfarr.c"
    { &hf_gsm_map_Component_PDU,
      { "Component", "gsm_map.Component",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Component_vals), 0,
        "Component", HFILL }},
    { &hf_gsm_map_invoke,
      { "invoke", "gsm_map.invoke",
        FT_NONE, BASE_NONE, NULL, 0,
        "Component/invoke", HFILL }},
    { &hf_gsm_map_returnResultLast,
      { "returnResultLast", "gsm_map.returnResultLast",
        FT_NONE, BASE_NONE, NULL, 0,
        "Component/returnResultLast", HFILL }},
    { &hf_gsm_map_returnError,
      { "returnError", "gsm_map.returnError",
        FT_NONE, BASE_NONE, NULL, 0,
        "Component/returnError", HFILL }},
    { &hf_gsm_map_reject,
      { "reject", "gsm_map.reject",
        FT_NONE, BASE_NONE, NULL, 0,
        "Component/reject", HFILL }},
    { &hf_gsm_map_invokeID,
      { "invokeID", "gsm_map.invokeID",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_linkedID,
      { "linkedID", "gsm_map.linkedID",
        FT_INT32, BASE_DEC, NULL, 0,
        "Invoke/linkedID", HFILL }},
    { &hf_gsm_map_opCode,
      { "opCode", "gsm_map.opCode",
        FT_UINT32, BASE_DEC, VALS(gsm_map_OPERATION_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_invokeparameter,
      { "invokeparameter", "gsm_map.invokeparameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "Invoke/invokeparameter", HFILL }},
    { &hf_gsm_map_resultretres,
      { "resultretres", "gsm_map.resultretres",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnResult/resultretres", HFILL }},
    { &hf_gsm_map_returnparameter,
      { "returnparameter", "gsm_map.returnparameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnResult/resultretres/returnparameter", HFILL }},
    { &hf_gsm_map_returnErrorCode,
      { "errorCode", "gsm_map.errorCode",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ERROR_vals), 0,
        "ReturnError/errorCode", HFILL }},
    { &hf_gsm_map_parameter,
      { "parameter", "gsm_map.parameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReturnError/parameter", HFILL }},
    { &hf_gsm_map_invokeIDRej,
      { "invokeIDRej", "gsm_map.invokeIDRej",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_invokeIDRej_vals), 0,
        "Reject/invokeIDRej", HFILL }},
    { &hf_gsm_map_derivable,
      { "derivable", "gsm_map.derivable",
        FT_INT32, BASE_DEC, NULL, 0,
        "Reject/invokeIDRej/derivable", HFILL }},
    { &hf_gsm_map_not_derivable,
      { "not-derivable", "gsm_map.not_derivable",
        FT_NONE, BASE_NONE, NULL, 0,
        "Reject/invokeIDRej/not-derivable", HFILL }},
    { &hf_gsm_map_problem,
      { "problem", "gsm_map.problem",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_problem_vals), 0,
        "Reject/problem", HFILL }},
    { &hf_gsm_map_generalProblem,
      { "generalProblem", "gsm_map.generalProblem",
        FT_INT32, BASE_DEC, VALS(gsm_map_GeneralProblem_vals), 0,
        "Reject/problem/generalProblem", HFILL }},
    { &hf_gsm_map_invokeProblem,
      { "invokeProblem", "gsm_map.invokeProblem",
        FT_INT32, BASE_DEC, VALS(gsm_map_InvokeProblem_vals), 0,
        "Reject/problem/invokeProblem", HFILL }},
    { &hf_gsm_map_returnResultProblem,
      { "returnResultProblem", "gsm_map.returnResultProblem",
        FT_INT32, BASE_DEC, VALS(gsm_map_ReturnResultProblem_vals), 0,
        "Reject/problem/returnResultProblem", HFILL }},
    { &hf_gsm_map_returnErrorProblem,
      { "returnErrorProblem", "gsm_map.returnErrorProblem",
        FT_INT32, BASE_DEC, VALS(gsm_map_ReturnErrorProblem_vals), 0,
        "Reject/problem/returnErrorProblem", HFILL }},
    { &hf_gsm_map_operationLocalvalue,
      { "localValue", "gsm_map.localValue",
        FT_INT32, BASE_DEC, VALS(gsm_map_OperationLocalvalue_vals), 0,
        "OPERATION/localValue", HFILL }},
    { &hf_gsm_map_globalValue,
      { "globalValue", "gsm_map.globalValue",
        FT_OID, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_localErrorcode,
      { "localValue", "gsm_map.localValue",
        FT_INT32, BASE_DEC, VALS(gsm_map_LocalErrorcode_vals), 0,
        "ERROR/localValue", HFILL }},
    { &hf_gsm_map_protocolId,
      { "protocolId", "gsm_map.protocolId",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ProtocolId_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_signalInfo,
      { "signalInfo", "gsm_map.signalInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_extensionContainer,
      { "extensionContainer", "gsm_map.extensionContainer",
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
    { &hf_gsm_map_informPreviousNetworkEntity,
      { "informPreviousNetworkEntity", "gsm_map.informPreviousNetworkEntity",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_cs_LCS_NotSupportedByUE,
      { "cs-LCS-NotSupportedByUE", "gsm_map.cs_LCS_NotSupportedByUE",
        FT_NONE, BASE_NONE, NULL, 0,
        "UpdateLocationArg/cs-LCS-NotSupportedByUE", HFILL }},
    { &hf_gsm_map_v_gmlc_Address,
      { "v-gmlc-Address", "gsm_map.v_gmlc_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_add_info,
      { "add-info", "gsm_map.add_info",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_hlr_Number,
      { "hlr-Number", "gsm_map.hlr_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_add_Capability,
      { "add-Capability", "gsm_map.add_Capability",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_supportedCamelPhases,
      { "supportedCamelPhases", "gsm_map.supportedCamelPhases",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_solsaSupportIndicator,
      { "solsaSupportIndicator", "gsm_map.solsaSupportIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_istSupportIndicator,
      { "istSupportIndicator", "gsm_map.istSupportIndicator",
        FT_UINT32, BASE_DEC, VALS(gsm_map_IST_SupportIndicator_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_superChargerSupportedInServingNetworkEntity,
      { "superChargerSupportedInServingNetworkEntity", "gsm_map.superChargerSupportedInServingNetworkEntity",
        FT_UINT32, BASE_DEC, VALS(gsm_map_SuperChargerInfo_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_longFTN_Supported,
      { "longFTN-Supported", "gsm_map.longFTN_Supported",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_supportedLCS_CapabilitySets,
      { "supportedLCS-CapabilitySets", "gsm_map.supportedLCS_CapabilitySets",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_offeredCamel4CSIs,
      { "offeredCamel4CSIs", "gsm_map.offeredCamel4CSIs",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_sendSubscriberData,
      { "sendSubscriberData", "gsm_map.sendSubscriberData",
        FT_NONE, BASE_NONE, NULL, 0,
        "SuperChargerInfo/sendSubscriberData", HFILL }},
    { &hf_gsm_map_subscriberDataStored,
      { "subscriberDataStored", "gsm_map.subscriberDataStored",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SuperChargerInfo/subscriberDataStored", HFILL }},
    { &hf_gsm_map_imeisv,
      { "imeisv", "gsm_map.imeisv",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_skipSubscriberDataUpdate,
      { "skipSubscriberDataUpdate", "gsm_map.skipSubscriberDataUpdate",
        FT_NONE, BASE_NONE, NULL, 0,
        "ADD-Info/skipSubscriberDataUpdate", HFILL }},
    { &hf_gsm_map_PrivateExtensionList_item,
      { "Item", "gsm_map.PrivateExtensionList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateExtensionList/_item", HFILL }},
    { &hf_gsm_map_extId,
      { "extId", "gsm_map.extId",
        FT_OID, BASE_NONE, NULL, 0,
        "PrivateExtension/extId", HFILL }},
    { &hf_gsm_map_extType,
      { "extType", "gsm_map.extType",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrivateExtension/extType", HFILL }},
    { &hf_gsm_map_privateExtensionList,
      { "privateExtensionList", "gsm_map.privateExtensionList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_slr_Arg_PCS_Extensions,
      { "slr-Arg-PCS-Extensions", "gsm_map.slr_Arg_PCS_Extensions",
        FT_NONE, BASE_NONE, NULL, 0,
        "SLR-ArgExtensionContainer/slr-Arg-PCS-Extensions", HFILL }},
    { &hf_gsm_map_na_ESRK_Request,
      { "na-ESRK-Request", "gsm_map.na_ESRK_Request",
        FT_NONE, BASE_NONE, NULL, 0,
        "SLR-Arg-PCS-Extensions/na-ESRK-Request", HFILL }},
    { &hf_gsm_map_identity,
      { "identity", "gsm_map.identity",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Identity_vals), 0,
        "CancelLocationArg/identity", HFILL }},
    { &hf_gsm_map_cancellationType,
      { "cancellationType", "gsm_map.cancellationType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CancellationType_vals), 0,
        "CancelLocationArg/cancellationType", HFILL }},
    { &hf_gsm_map_imsi_WithLMSI,
      { "imsi-WithLMSI", "gsm_map.imsi_WithLMSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_sgsn_Number,
      { "sgsn-Number", "gsm_map.sgsn_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_freezeTMSI,
      { "freezeTMSI", "gsm_map.freezeTMSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "PurgeMSRes/freezeTMSI", HFILL }},
    { &hf_gsm_map_freezeP_TMSI,
      { "freezeP-TMSI", "gsm_map.freezeP_TMSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "PurgeMSRes/freezeP-TMSI", HFILL }},
    { &hf_gsm_map_tmsi,
      { "tmsi", "gsm_map.tmsi",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_numberOfRequestedVectors,
      { "numberOfRequestedVectors", "gsm_map.numberOfRequestedVectors",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_segmentationProhibited,
      { "segmentationProhibited", "gsm_map.segmentationProhibited",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_previous_LAI,
      { "previous-LAI", "gsm_map.previous_LAI",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SendIdentificationArg/previous-LAI", HFILL }},
    { &hf_gsm_map_hopCounter,
      { "hopCounter", "gsm_map.hopCounter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SendIdentificationArg/hopCounter", HFILL }},
    { &hf_gsm_map_authenticationSetList,
      { "authenticationSetList", "gsm_map.authenticationSetList",
        FT_UINT32, BASE_DEC, VALS(gsm_map_AuthenticationSetList_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_currentSecurityContext,
      { "currentSecurityContext", "gsm_map.currentSecurityContext",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CurrentSecurityContext_vals), 0,
        "SendIdentificationRes/currentSecurityContext", HFILL }},
    { &hf_gsm_map_tripletList,
      { "tripletList", "gsm_map.tripletList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AuthenticationSetList/tripletList", HFILL }},
    { &hf_gsm_map_quintupletList,
      { "quintupletList", "gsm_map.quintupletList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AuthenticationSetList/quintupletList", HFILL }},
    { &hf_gsm_map_TripletList_item,
      { "Item", "gsm_map.TripletList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "TripletList/_item", HFILL }},
    { &hf_gsm_map_QuintupletList_item,
      { "Item", "gsm_map.QuintupletList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "QuintupletList/_item", HFILL }},
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
    { &hf_gsm_map_xres,
      { "xres", "gsm_map.xres",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AuthenticationQuintuplet/xres", HFILL }},
    { &hf_gsm_map_ck,
      { "ck", "gsm_map.ck",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ik,
      { "ik", "gsm_map.ik",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_autn,
      { "autn", "gsm_map.autn",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AuthenticationQuintuplet/autn", HFILL }},
    { &hf_gsm_map_gsm_SecurityContextData,
      { "gsm-SecurityContextData", "gsm_map.gsm_SecurityContextData",
        FT_NONE, BASE_NONE, NULL, 0,
        "CurrentSecurityContext/gsm-SecurityContextData", HFILL }},
    { &hf_gsm_map_umts_SecurityContextData,
      { "umts-SecurityContextData", "gsm_map.umts_SecurityContextData",
        FT_NONE, BASE_NONE, NULL, 0,
        "CurrentSecurityContext/umts-SecurityContextData", HFILL }},
    { &hf_gsm_map_cksn,
      { "cksn", "gsm_map.cksn",
        FT_BYTES, BASE_HEX, NULL, 0,
        "GSM-SecurityContextData/cksn", HFILL }},
    { &hf_gsm_map_ksi,
      { "ksi", "gsm_map.ksi",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UMTS-SecurityContextData/ksi", HFILL }},
    { &hf_gsm_map_targetCellId,
      { "targetCellId", "gsm_map.targetCellId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ho_NumberNotRequired,
      { "ho-NumberNotRequired", "gsm_map.ho_NumberNotRequired",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_bss_APDU,
      { "bss-APDU", "gsm_map.bss_APDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_targetRNCId,
      { "targetRNCId", "gsm_map.targetRNCId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_an_APDU,
      { "an-APDU", "gsm_map.an_APDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_multipleBearerRequested,
      { "multipleBearerRequested", "gsm_map.multipleBearerRequested",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrepareHO-ArgV3/multipleBearerRequested", HFILL }},
    { &hf_gsm_map_integrityProtectionInfo,
      { "integrityProtectionInfo", "gsm_map.integrityProtectionInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_encryptionInfo,
      { "encryptionInfo", "gsm_map.encryptionInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_radioResourceInformation,
      { "radioResourceInformation", "gsm_map.radioResourceInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_allowedGSM_Algorithms,
      { "allowedGSM-Algorithms", "gsm_map.allowedGSM_Algorithms",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_allowedUMTS_Algorithms,
      { "allowedUMTS-Algorithms", "gsm_map.allowedUMTS_Algorithms",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_radioResourceList,
      { "radioResourceList", "gsm_map.radioResourceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_rab_Id,
      { "rab-Id", "gsm_map.rab_Id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_bssmap_ServiceHandover,
      { "bssmap-ServiceHandover", "gsm_map.bssmap_ServiceHandover",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ranap_ServiceHandover,
      { "ranap-ServiceHandover", "gsm_map.ranap_ServiceHandover",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_bssmap_ServiceHandoverList,
      { "bssmap-ServiceHandoverList", "gsm_map.bssmap_ServiceHandoverList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_asciCallReference,
      { "asciCallReference", "gsm_map.asciCallReference",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_geran_classmark,
      { "geran-classmark", "gsm_map.geran_classmark",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_iuCurrentlyUsedCodec,
      { "iuCurrentlyUsedCodec", "gsm_map.iuCurrentlyUsedCodec",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PrepareHO-ArgV3/iuCurrentlyUsedCodec", HFILL }},
    { &hf_gsm_map_iuSupportedCodecsList,
      { "iuSupportedCodecsList", "gsm_map.iuSupportedCodecsList",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_rab_ConfigurationIndicator,
      { "rab-ConfigurationIndicator", "gsm_map.rab_ConfigurationIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_uesbi_Iu,
      { "uesbi-Iu", "gsm_map.uesbi_Iu",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrepareHO-ArgV3/uesbi-Iu", HFILL }},
    { &hf_gsm_map_BSSMAP_ServiceHandoverList_item,
      { "Item", "gsm_map.BSSMAP_ServiceHandoverList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "BSSMAP-ServiceHandoverList/_item", HFILL }},
    { &hf_gsm_map_RadioResourceList_item,
      { "Item", "gsm_map.RadioResourceList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RadioResourceList/_item", HFILL }},
    { &hf_gsm_map_handoverNumber,
      { "handoverNumber", "gsm_map.handoverNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_relocationNumberList,
      { "relocationNumberList", "gsm_map.relocationNumberList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrepareHO-ResV3/relocationNumberList", HFILL }},
    { &hf_gsm_map_multicallBearerInfo,
      { "multicallBearerInfo", "gsm_map.multicallBearerInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrepareHO-ResV3/multicallBearerInfo", HFILL }},
    { &hf_gsm_map_multipleBearerNotSupported,
      { "multipleBearerNotSupported", "gsm_map.multipleBearerNotSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrepareHO-ResV3/multipleBearerNotSupported", HFILL }},
    { &hf_gsm_map_selectedUMTS_Algorithms,
      { "selectedUMTS-Algorithms", "gsm_map.selectedUMTS_Algorithms",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_chosenRadioResourceInformation,
      { "chosenRadioResourceInformation", "gsm_map.chosenRadioResourceInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_iuSelectedCodec,
      { "iuSelectedCodec", "gsm_map.iuSelectedCodec",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_iuAvailableCodecsList,
      { "iuAvailableCodecsList", "gsm_map.iuAvailableCodecsList",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_integrityProtectionAlgorithm,
      { "integrityProtectionAlgorithm", "gsm_map.integrityProtectionAlgorithm",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SelectedUMTS-Algorithms/integrityProtectionAlgorithm", HFILL }},
    { &hf_gsm_map_encryptionAlgorithm,
      { "encryptionAlgorithm", "gsm_map.encryptionAlgorithm",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SelectedUMTS-Algorithms/encryptionAlgorithm", HFILL }},
    { &hf_gsm_map_chosenChannelInfo,
      { "chosenChannelInfo", "gsm_map.chosenChannelInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ChosenRadioResourceInformation/chosenChannelInfo", HFILL }},
    { &hf_gsm_map_chosenSpeechVersion,
      { "chosenSpeechVersion", "gsm_map.chosenSpeechVersion",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ChosenRadioResourceInformation/chosenSpeechVersion", HFILL }},
    { &hf_gsm_map_RelocationNumberList_item,
      { "Item", "gsm_map.RelocationNumberList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelocationNumberList/_item", HFILL }},
    { &hf_gsm_map_selectedGSM_Algorithm,
      { "selectedGSM-Algorithm", "gsm_map.selectedGSM_Algorithm",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProcessAccessSignallingArgV3/selectedGSM-Algorithm", HFILL }},
    { &hf_gsm_map_selectedRab_Id,
      { "selectedRab-Id", "gsm_map.selectedRab_Id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_iUSelectedCodec,
      { "iUSelectedCodec", "gsm_map.iUSelectedCodec",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProcessAccessSignallingArgV3/iUSelectedCodec", HFILL }},
    { &hf_gsm_map_utranCodecList,
      { "utranCodecList", "gsm_map.utranCodecList",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupportedCodecsList/utranCodecList", HFILL }},
    { &hf_gsm_map_geranCodecList,
      { "geranCodecList", "gsm_map.geranCodecList",
        FT_NONE, BASE_NONE, NULL, 0,
        "SupportedCodecsList/geranCodecList", HFILL }},
    { &hf_gsm_map_codec1,
      { "codec1", "gsm_map.codec1",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CodecList/codec1", HFILL }},
    { &hf_gsm_map_codec2,
      { "codec2", "gsm_map.codec2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CodecList/codec2", HFILL }},
    { &hf_gsm_map_codec3,
      { "codec3", "gsm_map.codec3",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CodecList/codec3", HFILL }},
    { &hf_gsm_map_codec4,
      { "codec4", "gsm_map.codec4",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CodecList/codec4", HFILL }},
    { &hf_gsm_map_codec5,
      { "codec5", "gsm_map.codec5",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CodecList/codec5", HFILL }},
    { &hf_gsm_map_codec6,
      { "codec6", "gsm_map.codec6",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CodecList/codec6", HFILL }},
    { &hf_gsm_map_codec7,
      { "codec7", "gsm_map.codec7",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CodecList/codec7", HFILL }},
    { &hf_gsm_map_codec8,
      { "codec8", "gsm_map.codec8",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CodecList/codec8", HFILL }},
    { &hf_gsm_map_keyStatus,
      { "keyStatus", "gsm_map.keyStatus",
        FT_UINT32, BASE_DEC, VALS(gsm_map_KeyStatus_vals), 0,
        "ForwardAccessSignallingArgV3/keyStatus", HFILL }},
    { &hf_gsm_map_currentlyUsedCodec,
      { "currentlyUsedCodec", "gsm_map.currentlyUsedCodec",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ForwardAccessSignallingArgV3/currentlyUsedCodec", HFILL }},
    { &hf_gsm_map_integrityProtectionAlgorithms,
      { "integrityProtectionAlgorithms", "gsm_map.integrityProtectionAlgorithms",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AllowedUMTS-Algorithms/integrityProtectionAlgorithms", HFILL }},
    { &hf_gsm_map_encryptionAlgorithms,
      { "encryptionAlgorithms", "gsm_map.encryptionAlgorithms",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AllowedUMTS-Algorithms/encryptionAlgorithms", HFILL }},
    { &hf_gsm_map_targetMSC_Number,
      { "targetMSC-Number", "gsm_map.targetMSC_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_immediateResponsePreferred,
      { "immediateResponsePreferred", "gsm_map.immediateResponsePreferred",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendAuthenticationInfoArgV2/immediateResponsePreferred", HFILL }},
    { &hf_gsm_map_re_synchronisationInfo,
      { "re-synchronisationInfo", "gsm_map.re_synchronisationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendAuthenticationInfoArgV2/re-synchronisationInfo", HFILL }},
    { &hf_gsm_map_requestingNodeType,
      { "requestingNodeType", "gsm_map.requestingNodeType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_RequestingNodeType_vals), 0,
        "SendAuthenticationInfoArgV2/requestingNodeType", HFILL }},
    { &hf_gsm_map_requestingPLMN_Id,
      { "requestingPLMN-Id", "gsm_map.requestingPLMN_Id",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SendAuthenticationInfoArgV2/requestingPLMN-Id", HFILL }},
    { &hf_gsm_map_SendAuthenticationInfoRes_item,
      { "Item", "gsm_map.SendAuthenticationInfoRes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendAuthenticationInfoRes/_item", HFILL }},
    { &hf_gsm_map_auts,
      { "auts", "gsm_map.auts",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Re-synchronisationInfo/auts", HFILL }},
    { &hf_gsm_map_imei,
      { "imei", "gsm_map.imei",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_requestedEquipmentInfo,
      { "requestedEquipmentInfo", "gsm_map.requestedEquipmentInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CheckIMEIArgV3/requestedEquipmentInfo", HFILL }},
    { &hf_gsm_map_equipmentStatus,
      { "equipmentStatus", "gsm_map.equipmentStatus",
        FT_UINT32, BASE_DEC, VALS(gsm_map_EquipmentStatus_vals), 0,
        "CheckIMEIRes/equipmentStatus", HFILL }},
    { &hf_gsm_map_bmuef,
      { "bmuef", "gsm_map.bmuef",
        FT_NONE, BASE_NONE, NULL, 0,
        "CheckIMEIRes/bmuef", HFILL }},
    { &hf_gsm_map_uesbi_IuA,
      { "uesbi-IuA", "gsm_map.uesbi_IuA",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UESBI-Iu/uesbi-IuA", HFILL }},
    { &hf_gsm_map_uesbi_IuB,
      { "uesbi-IuB", "gsm_map.uesbi_IuB",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UESBI-Iu/uesbi-IuB", HFILL }},
    { &hf_gsm_map_bearerservice,
      { "bearerservice", "gsm_map.bearerservice",
        FT_UINT8, BASE_DEC, VALS(Bearerservice_vals), 0,
        "BasicService/bearerservice", HFILL }},
    { &hf_gsm_map_teleservice,
      { "teleservice", "gsm_map.teleservice",
        FT_UINT8, BASE_DEC, VALS(Teleservice_vals), 0,
        "BasicService/teleservice", HFILL }},
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
        "", HFILL }},
    { &hf_gsm_map_gsmSCFAddress,
      { "gsmSCFAddress", "gsm_map.gsmSCFAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "BcsmCamelTDPData/gsmSCFAddress", HFILL }},
    { &hf_gsm_map_defaultCallHandling,
      { "defaultCallHandling", "gsm_map.defaultCallHandling",
        FT_UINT32, BASE_DEC, VALS(gsm_map_DefaultCallHandling_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_BcsmCamelTDPDataList_item,
      { "Item", "gsm_map.BcsmCamelTDPDataList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "BcsmCamelTDPDataList/_item", HFILL }},
    { &hf_gsm_map_o_BcsmCamelTDPDataList,
      { "o-BcsmCamelTDPDataList", "gsm_map.o_BcsmCamelTDPDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "O-CSI/o-BcsmCamelTDPDataList", HFILL }},
    { &hf_gsm_map_camelCapabilityHandling,
      { "camelCapabilityHandling", "gsm_map.camelCapabilityHandling",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_notificationToCSE,
      { "notificationToCSE", "gsm_map.notificationToCSE",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_csiActive,
      { "csiActive", "gsm_map.csiActive",
        FT_NONE, BASE_NONE, NULL, 0,
        "O-CSI/csiActive", HFILL }},
    { &hf_gsm_map_O_BcsmCamelTDPDataList_item,
      { "Item", "gsm_map.O_BcsmCamelTDPDataList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "O-BcsmCamelTDPDataList/_item", HFILL }},
    { &hf_gsm_map_o_BcsmTriggerDetectionPoint,
      { "o-BcsmTriggerDetectionPoint", "gsm_map.o_BcsmTriggerDetectionPoint",
        FT_UINT32, BASE_DEC, VALS(gsm_map_O_BcsmTriggerDetectionPoint_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_gsmSCF_Address,
      { "gsmSCF-Address", "gsm_map.gsmSCF_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
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
    { &hf_gsm_map_bearerserviceList,
      { "bearerserviceList", "gsm_map.bearerserviceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InsertSubscriberDataArg/bearerserviceList", HFILL }},
    { &hf_gsm_map_teleserviceList,
      { "teleserviceList", "gsm_map.teleserviceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_provisionedSS,
      { "provisionedSS", "gsm_map.provisionedSS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InsertSubscriberDataArg/provisionedSS", HFILL }},
    { &hf_gsm_map_odb_Data,
      { "odb-Data", "gsm_map.odb_Data",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_roamingRestrictionDueToUnsupportedFeature,
      { "roamingRestrictionDueToUnsupportedFeature", "gsm_map.roamingRestrictionDueToUnsupportedFeature",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_regionalSubscriptionData,
      { "regionalSubscriptionData", "gsm_map.regionalSubscriptionData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InsertSubscriberDataArg/regionalSubscriptionData", HFILL }},
    { &hf_gsm_map_vbsSubscriptionData,
      { "vbsSubscriptionData", "gsm_map.vbsSubscriptionData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InsertSubscriberDataArg/vbsSubscriptionData", HFILL }},
    { &hf_gsm_map_vgcsSubscriptionData,
      { "vgcsSubscriptionData", "gsm_map.vgcsSubscriptionData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InsertSubscriberDataArg/vgcsSubscriptionData", HFILL }},
    { &hf_gsm_map_vlrCamelSubscriptionInfo,
      { "vlrCamelSubscriptionInfo", "gsm_map.vlrCamelSubscriptionInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/vlrCamelSubscriptionInfo", HFILL }},
    { &hf_gsm_map_naea_PreferredCI,
      { "naea-PreferredCI", "gsm_map.naea_PreferredCI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_gprsSubscriptionData,
      { "gprsSubscriptionData", "gsm_map.gprsSubscriptionData",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/gprsSubscriptionData", HFILL }},
    { &hf_gsm_map_roamingRestrictedInSgsnDueToUnsupportedFeature,
      { "roamingRestrictedInSgsnDueToUnsupportedFeature", "gsm_map.roamingRestrictedInSgsnDueToUnsupportedFeature",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/roamingRestrictedInSgsnDueToUnsupportedFeature", HFILL }},
    { &hf_gsm_map_networkAccessMode,
      { "networkAccessMode", "gsm_map.networkAccessMode",
        FT_UINT32, BASE_DEC, VALS(gsm_map_NetworkAccessMode_vals), 0,
        "InsertSubscriberDataArg/networkAccessMode", HFILL }},
    { &hf_gsm_map_lsaInformation,
      { "lsaInformation", "gsm_map.lsaInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lsaInformation", HFILL }},
    { &hf_gsm_map_lmu_Indicator,
      { "lmu-Indicator", "gsm_map.lmu_Indicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lmu-Indicator", HFILL }},
    { &hf_gsm_map_lcsInformation,
      { "lcsInformation", "gsm_map.lcsInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/lcsInformation", HFILL }},
    { &hf_gsm_map_istAlertTimer,
      { "istAlertTimer", "gsm_map.istAlertTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_superChargerSupportedInHLR,
      { "superChargerSupportedInHLR", "gsm_map.superChargerSupportedInHLR",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/superChargerSupportedInHLR", HFILL }},
    { &hf_gsm_map_mc_SS_Info,
      { "mc-SS-Info", "gsm_map.mc_SS_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/mc-SS-Info", HFILL }},
    { &hf_gsm_map_cs_AllocationRetentionPriority,
      { "cs-AllocationRetentionPriority", "gsm_map.cs_AllocationRetentionPriority",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/cs-AllocationRetentionPriority", HFILL }},
    { &hf_gsm_map_sgsn_CAMEL_SubscriptionInfo,
      { "sgsn-CAMEL-SubscriptionInfo", "gsm_map.sgsn_CAMEL_SubscriptionInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "InsertSubscriberDataArg/sgsn-CAMEL-SubscriptionInfo", HFILL }},
    { &hf_gsm_map_chargingCharacteristics,
      { "chargingCharacteristics", "gsm_map.chargingCharacteristics",
        FT_UINT16, BASE_DEC, VALS(chargingcharacteristics_values), 0x0f00,
        "", HFILL }},
    { &hf_gsm_map_accessRestrictionData,
      { "accessRestrictionData", "gsm_map.accessRestrictionData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "InsertSubscriberDataArg/accessRestrictionData", HFILL }},
    { &hf_gsm_map_gmlc_List,
      { "gmlc-List", "gsm_map.gmlc_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LCSInformation/gmlc-List", HFILL }},
    { &hf_gsm_map_lcs_PrivacyExceptionList,
      { "lcs-PrivacyExceptionList", "gsm_map.lcs_PrivacyExceptionList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LCSInformation/lcs-PrivacyExceptionList", HFILL }},
    { &hf_gsm_map_molr_List,
      { "molr-List", "gsm_map.molr_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LCSInformation/molr-List", HFILL }},
    { &hf_gsm_map_add_lcs_PrivacyExceptionList,
      { "add-lcs-PrivacyExceptionList", "gsm_map.add_lcs_PrivacyExceptionList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LCSInformation/add-lcs-PrivacyExceptionList", HFILL }},
    { &hf_gsm_map_GMLC_List_item,
      { "Item", "gsm_map.GMLC_List_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "GMLC-List/_item", HFILL }},
    { &hf_gsm_map_GPRSDataList_item,
      { "Item", "gsm_map.GPRSDataList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPRSDataList/_item", HFILL }},
    { &hf_gsm_map_pdp_ContextId,
      { "pdp-ContextId", "gsm_map.pdp_ContextId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDP-Context/pdp-ContextId", HFILL }},
    { &hf_gsm_map_pdp_Type,
      { "pdp-Type", "gsm_map.pdp_Type",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_pdp_Address,
      { "pdp-Address", "gsm_map.pdp_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_qos_Subscribed,
      { "qos-Subscribed", "gsm_map.qos_Subscribed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-Context/qos-Subscribed", HFILL }},
    { &hf_gsm_map_vplmnAddressAllowed,
      { "vplmnAddressAllowed", "gsm_map.vplmnAddressAllowed",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDP-Context/vplmnAddressAllowed", HFILL }},
    { &hf_gsm_map_apn,
      { "apn", "gsm_map.apn",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-Context/apn", HFILL }},
    { &hf_gsm_map_ext_QoS_Subscribed,
      { "ext-QoS-Subscribed", "gsm_map.ext_QoS_Subscribed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-Context/ext-QoS-Subscribed", HFILL }},
    { &hf_gsm_map_pdp_ChargingCharacteristics,
      { "pdp-ChargingCharacteristics", "gsm_map.pdp_ChargingCharacteristics",
        FT_UINT16, BASE_DEC, VALS(chargingcharacteristics_values), 0x0f00,
        "PDP-Context/pdp-ChargingCharacteristics", HFILL }},
    { &hf_gsm_map_ext2_QoS_Subscribed,
      { "ext2-QoS-Subscribed", "gsm_map.ext2_QoS_Subscribed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-Context/ext2-QoS-Subscribed", HFILL }},
    { &hf_gsm_map_completeDataListIncluded,
      { "completeDataListIncluded", "gsm_map.completeDataListIncluded",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_gprsDataList,
      { "gprsDataList", "gsm_map.gprsDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPRSSubscriptionData/gprsDataList", HFILL }},
    { &hf_gsm_map_gprs_CSI,
      { "gprs-CSI", "gsm_map.gprs_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_mo_sms_CSI,
      { "mo-sms-CSI", "gsm_map.mo_sms_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_mt_sms_CSI,
      { "mt-sms-CSI", "gsm_map.mt_sms_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_mt_smsCAMELTDP_CriteriaList,
      { "mt-smsCAMELTDP-CriteriaList", "gsm_map.mt_smsCAMELTDP_CriteriaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_mg_csi,
      { "mg-csi", "gsm_map.mg_csi",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_gprs_CamelTDPDataList,
      { "gprs-CamelTDPDataList", "gsm_map.gprs_CamelTDPDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPRS-CSI/gprs-CamelTDPDataList", HFILL }},
    { &hf_gsm_map_csi_Active,
      { "csi-Active", "gsm_map.csi_Active",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_GPRS_CamelTDPDataList_item,
      { "Item", "gsm_map.GPRS_CamelTDPDataList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPRS-CamelTDPDataList/_item", HFILL }},
    { &hf_gsm_map_gprs_TriggerDetectionPoint,
      { "gprs-TriggerDetectionPoint", "gsm_map.gprs_TriggerDetectionPoint",
        FT_UINT32, BASE_DEC, VALS(gsm_map_GPRS_TriggerDetectionPoint_vals), 0,
        "GPRS-CamelTDPData/gprs-TriggerDetectionPoint", HFILL }},
    { &hf_gsm_map_defaultSessionHandling,
      { "defaultSessionHandling", "gsm_map.defaultSessionHandling",
        FT_UINT32, BASE_DEC, VALS(gsm_map_DefaultGPRS_Handling_vals), 0,
        "GPRS-CamelTDPData/defaultSessionHandling", HFILL }},
    { &hf_gsm_map_LSADataList_item,
      { "Item", "gsm_map.LSADataList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "LSADataList/_item", HFILL }},
    { &hf_gsm_map_lsaIdentity,
      { "lsaIdentity", "gsm_map.lsaIdentity",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LSAData/lsaIdentity", HFILL }},
    { &hf_gsm_map_lsaAttributes,
      { "lsaAttributes", "gsm_map.lsaAttributes",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LSAData/lsaAttributes", HFILL }},
    { &hf_gsm_map_lsaActiveModeIndicator,
      { "lsaActiveModeIndicator", "gsm_map.lsaActiveModeIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "LSAData/lsaActiveModeIndicator", HFILL }},
    { &hf_gsm_map_lsaOnlyAccessIndicator,
      { "lsaOnlyAccessIndicator", "gsm_map.lsaOnlyAccessIndicator",
        FT_UINT32, BASE_DEC, VALS(gsm_map_LSAOnlyAccessIndicator_vals), 0,
        "LSAInformation/lsaOnlyAccessIndicator", HFILL }},
    { &hf_gsm_map_lsaDataList,
      { "lsaDataList", "gsm_map.lsaDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LSAInformation/lsaDataList", HFILL }},
    { &hf_gsm_map_bearerServiceList,
      { "bearerServiceList", "gsm_map.bearerServiceList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "InsertSubscriberDataRes/bearerServiceList", HFILL }},
    { &hf_gsm_map_ss_List,
      { "ss-List", "gsm_map.ss_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_odb_GeneralData,
      { "odb-GeneralData", "gsm_map.odb_GeneralData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_regionalSubscriptionResponse,
      { "regionalSubscriptionResponse", "gsm_map.regionalSubscriptionResponse",
        FT_UINT32, BASE_DEC, VALS(gsm_map_RegionalSubscriptionResponse_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_basicServiceList,
      { "basicServiceList", "gsm_map.basicServiceList",
        FT_UINT32, BASE_DEC, NULL, 0,
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
        FT_UINT32, BASE_DEC, VALS(gsm_map_GPRSSubscriptionDataWithdraw_vals), 0,
        "DeleteSubscriberDataArg/gprsSubscriptionDataWithdraw", HFILL }},
    { &hf_gsm_map_roamingRestrictedInSgsnDueToUnsuppportedFeature,
      { "roamingRestrictedInSgsnDueToUnsuppportedFeature", "gsm_map.roamingRestrictedInSgsnDueToUnsuppportedFeature",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSubscriberDataArg/roamingRestrictedInSgsnDueToUnsuppportedFeature", HFILL }},
    { &hf_gsm_map_lsaInformationWithdraw,
      { "lsaInformationWithdraw", "gsm_map.lsaInformationWithdraw",
        FT_UINT32, BASE_DEC, VALS(gsm_map_LSAInformationWithdraw_vals), 0,
        "DeleteSubscriberDataArg/lsaInformationWithdraw", HFILL }},
    { &hf_gsm_map_gmlc_ListWithdraw,
      { "gmlc-ListWithdraw", "gsm_map.gmlc_ListWithdraw",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSubscriberDataArg/gmlc-ListWithdraw", HFILL }},
    { &hf_gsm_map_istInformationWithdraw,
      { "istInformationWithdraw", "gsm_map.istInformationWithdraw",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_specificCSI_Withdraw,
      { "specificCSI-Withdraw", "gsm_map.specificCSI_Withdraw",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DeleteSubscriberDataArg/specificCSI-Withdraw", HFILL }},
    { &hf_gsm_map_chargingCharacteristicsWithdraw,
      { "chargingCharacteristicsWithdraw", "gsm_map.chargingCharacteristicsWithdraw",
        FT_NONE, BASE_NONE, NULL, 0,
        "DeleteSubscriberDataArg/chargingCharacteristicsWithdraw", HFILL }},
    { &hf_gsm_map_allGPRSData,
      { "allGPRSData", "gsm_map.allGPRSData",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPRSSubscriptionDataWithdraw/allGPRSData", HFILL }},
    { &hf_gsm_map_contextIdList,
      { "contextIdList", "gsm_map.contextIdList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPRSSubscriptionDataWithdraw/contextIdList", HFILL }},
    { &hf_gsm_map_ContextIdList_item,
      { "Item", "gsm_map.ContextIdList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ContextIdList/_item", HFILL }},
    { &hf_gsm_map_allLSAData,
      { "allLSAData", "gsm_map.allLSAData",
        FT_NONE, BASE_NONE, NULL, 0,
        "LSAInformationWithdraw/allLSAData", HFILL }},
    { &hf_gsm_map_lsaIdentityList,
      { "lsaIdentityList", "gsm_map.lsaIdentityList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LSAInformationWithdraw/lsaIdentityList", HFILL }},
    { &hf_gsm_map_LSAIdentityList_item,
      { "Item", "gsm_map.LSAIdentityList_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LSAIdentityList/_item", HFILL }},
    { &hf_gsm_map_BasicServiceList_item,
      { "Item", "gsm_map.BasicServiceList_item",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ext_BasicServiceCode_vals), 0,
        "BasicServiceList/_item", HFILL }},
    { &hf_gsm_map_o_CSI,
      { "o-CSI", "gsm_map.o_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ss_CSI,
      { "ss-CSI", "gsm_map.ss_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_o_BcsmCamelTDP_CriteriaList,
      { "o-BcsmCamelTDP-CriteriaList", "gsm_map.o_BcsmCamelTDP_CriteriaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_tif_CSI,
      { "tif-CSI", "gsm_map.tif_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_m_CSI,
      { "m-CSI", "gsm_map.m_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_vt_CSI,
      { "vt-CSI", "gsm_map.vt_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_t_BCSM_CAMEL_TDP_CriteriaList,
      { "t-BCSM-CAMEL-TDP-CriteriaList", "gsm_map.t_BCSM_CAMEL_TDP_CriteriaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_d_CSI,
      { "d-CSI", "gsm_map.d_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_MT_smsCAMELTDP_CriteriaList_item,
      { "Item", "gsm_map.MT_smsCAMELTDP_CriteriaList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MT-smsCAMELTDP-CriteriaList/_item", HFILL }},
    { &hf_gsm_map_sms_TriggerDetectionPoint,
      { "sms-TriggerDetectionPoint", "gsm_map.sms_TriggerDetectionPoint",
        FT_UINT32, BASE_DEC, VALS(gsm_map_SMS_TriggerDetectionPoint_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_tpdu_TypeCriterion,
      { "tpdu-TypeCriterion", "gsm_map.tpdu_TypeCriterion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MT-smsCAMELTDP-Criteria/tpdu-TypeCriterion", HFILL }},
    { &hf_gsm_map_TPDU_TypeCriterion_item,
      { "Item", "gsm_map.TPDU_TypeCriterion_item",
        FT_UINT32, BASE_DEC, VALS(gsm_map_MT_SMS_TPDU_Type_vals), 0,
        "TPDU-TypeCriterion/_item", HFILL }},
    { &hf_gsm_map_dp_AnalysedInfoCriteriaList,
      { "dp-AnalysedInfoCriteriaList", "gsm_map.dp_AnalysedInfoCriteriaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "D-CSI/dp-AnalysedInfoCriteriaList", HFILL }},
    { &hf_gsm_map_DP_AnalysedInfoCriteriaList_item,
      { "Item", "gsm_map.DP_AnalysedInfoCriteriaList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "DP-AnalysedInfoCriteriaList/_item", HFILL }},
    { &hf_gsm_map_dialledNumber,
      { "dialledNumber", "gsm_map.dialledNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DP-AnalysedInfoCriterium/dialledNumber", HFILL }},
    { &hf_gsm_map_ss_CamelData,
      { "ss-CamelData", "gsm_map.ss_CamelData",
        FT_NONE, BASE_NONE, NULL, 0,
        "SS-CSI/ss-CamelData", HFILL }},
    { &hf_gsm_map_ss_EventList,
      { "ss-EventList", "gsm_map.ss_EventList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SS-CamelData/ss-EventList", HFILL }},
    { &hf_gsm_map_mobilityTriggers,
      { "mobilityTriggers", "gsm_map.mobilityTriggers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_BearerServiceList_item,
      { "Item", "gsm_map.BearerServiceList_item",
        FT_UINT8, BASE_DEC, VALS(Bearerservice_vals), 0,
        "BearerServiceList/_item", HFILL }},
    { &hf_gsm_map_TeleserviceList_item,
      { "Item", "gsm_map.TeleserviceList_item",
        FT_UINT8, BASE_DEC, VALS(Teleservice_vals), 0,
        "TeleserviceList/_item", HFILL }},
    { &hf_gsm_map_Ext_SS_InfoList_item,
      { "Item", "gsm_map.Ext_SS_InfoList_item",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ext_SS_Info_vals), 0,
        "Ext-SS-InfoList/_item", HFILL }},
    { &hf_gsm_map_ext_forwardingInfo,
      { "forwardingInfo", "gsm_map.forwardingInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ext-SS-Info/forwardingInfo", HFILL }},
    { &hf_gsm_map_ext_callBarringInfo,
      { "callBarringInfo", "gsm_map.callBarringInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ext-SS-Info/callBarringInfo", HFILL }},
    { &hf_gsm_map_cug_Info,
      { "cug-Info", "gsm_map.cug_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ext-SS-Info/cug-Info", HFILL }},
    { &hf_gsm_map_ext_ss_Data,
      { "ss-Data", "gsm_map.ss_Data",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ext-SS-Info/ss-Data", HFILL }},
    { &hf_gsm_map_emlpp_Info,
      { "emlpp-Info", "gsm_map.emlpp_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ext-SS-Info/emlpp-Info", HFILL }},
    { &hf_gsm_map_ss_Code,
      { "ss-Code", "gsm_map.ss_Code",
        FT_UINT8, BASE_DEC, VALS(ssCode_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_ext_forwardingFeatureList,
      { "forwardingFeatureList", "gsm_map.forwardingFeatureList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_Ext_ForwFeatureList_item,
      { "Item", "gsm_map.Ext_ForwFeatureList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ext-ForwFeatureList/_item", HFILL }},
    { &hf_gsm_map_ext_basicService,
      { "basicService", "gsm_map.basicService",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ext_BasicServiceCode_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_ext_ss_Status,
      { "ss-Status", "gsm_map.ss_Status",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_forwardedToNumber,
      { "forwardedToNumber", "gsm_map.forwardedToNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_forwardedToSubaddress,
      { "forwardedToSubaddress", "gsm_map.forwardedToSubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ext_forwardingOptions,
      { "forwardingOptions", "gsm_map.forwardingOptions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Ext-ForwFeature/forwardingOptions", HFILL }},
    { &hf_gsm_map_ext_noReplyConditionTime,
      { "noReplyConditionTime", "gsm_map.noReplyConditionTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_longForwardedToNumber,
      { "longForwardedToNumber", "gsm_map.longForwardedToNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ext_callBarringFeatureList,
      { "callBarringFeatureList", "gsm_map.callBarringFeatureList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_Ext_CallBarFeatureList_item,
      { "Item", "gsm_map.Ext_CallBarFeatureList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ext-CallBarFeatureList/_item", HFILL }},
    { &hf_gsm_map_ZoneCodeList_item,
      { "Item", "gsm_map.ZoneCodeList_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ZoneCodeList/_item", HFILL }},
    { &hf_gsm_map_maximumentitledPriority,
      { "maximumentitledPriority", "gsm_map.maximumentitledPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EMLPP-Info/maximumentitledPriority", HFILL }},
    { &hf_gsm_map_defaultPriority,
      { "defaultPriority", "gsm_map.defaultPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_cug_SubscriptionList,
      { "cug-SubscriptionList", "gsm_map.cug_SubscriptionList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CUG-Info/cug-SubscriptionList", HFILL }},
    { &hf_gsm_map_cug_FeatureList,
      { "cug-FeatureList", "gsm_map.cug_FeatureList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CUG-Info/cug-FeatureList", HFILL }},
    { &hf_gsm_map_CUG_SubscriptionList_item,
      { "Item", "gsm_map.CUG_SubscriptionList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CUG-SubscriptionList/_item", HFILL }},
    { &hf_gsm_map_cug_Index,
      { "cug-Index", "gsm_map.cug_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CUG-Subscription/cug-Index", HFILL }},
    { &hf_gsm_map_cug_Interlock,
      { "cug-Interlock", "gsm_map.cug_Interlock",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_intraCUG_Options,
      { "intraCUG-Options", "gsm_map.intraCUG_Options",
        FT_UINT32, BASE_DEC, VALS(gsm_map_IntraCUG_Options_vals), 0,
        "CUG-Subscription/intraCUG-Options", HFILL }},
    { &hf_gsm_map_basicServiceGroupList,
      { "basicServiceGroupList", "gsm_map.basicServiceGroupList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_CUG_FeatureList_item,
      { "Item", "gsm_map.CUG_FeatureList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CUG-FeatureList/_item", HFILL }},
    { &hf_gsm_map_Ext_BasicServiceGroupList_item,
      { "Item", "gsm_map.Ext_BasicServiceGroupList_item",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ext_BasicServiceCode_vals), 0,
        "Ext-BasicServiceGroupList/_item", HFILL }},
    { &hf_gsm_map_preferentialCUG_Indicator,
      { "preferentialCUG-Indicator", "gsm_map.preferentialCUG_Indicator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CUG-Feature/preferentialCUG-Indicator", HFILL }},
    { &hf_gsm_map_interCUG_Restrictions,
      { "interCUG-Restrictions", "gsm_map.interCUG_Restrictions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CUG-Feature/interCUG-Restrictions", HFILL }},
    { &hf_gsm_map_ss_SubscriptionOption,
      { "ss-SubscriptionOption", "gsm_map.ss_SubscriptionOption",
        FT_UINT32, BASE_DEC, VALS(gsm_map_SS_SubscriptionOption_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_LCS_PrivacyExceptionList_item,
      { "Item", "gsm_map.LCS_PrivacyExceptionList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "LCS-PrivacyExceptionList/_item", HFILL }},
    { &hf_gsm_map_notificationToMSUser,
      { "notificationToMSUser", "gsm_map.notificationToMSUser",
        FT_UINT32, BASE_DEC, VALS(gsm_map_NotificationToMSUser_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_externalClientList,
      { "externalClientList", "gsm_map.externalClientList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LCS-PrivacyClass/externalClientList", HFILL }},
    { &hf_gsm_map_plmnClientList,
      { "plmnClientList", "gsm_map.plmnClientList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LCS-PrivacyClass/plmnClientList", HFILL }},
    { &hf_gsm_map_ext_externalClientList,
      { "ext-externalClientList", "gsm_map.ext_externalClientList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LCS-PrivacyClass/ext-externalClientList", HFILL }},
    { &hf_gsm_map_serviceTypeList,
      { "serviceTypeList", "gsm_map.serviceTypeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LCS-PrivacyClass/serviceTypeList", HFILL }},
    { &hf_gsm_map_ExternalClientList_item,
      { "Item", "gsm_map.ExternalClientList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExternalClientList/_item", HFILL }},
    { &hf_gsm_map_PLMNClientList_item,
      { "Item", "gsm_map.PLMNClientList_item",
        FT_UINT32, BASE_DEC, VALS(gsm_map_LCSClientInternalID_vals), 0,
        "PLMNClientList/_item", HFILL }},
    { &hf_gsm_map_Ext_ExternalClientList_item,
      { "Item", "gsm_map.Ext_ExternalClientList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ext-ExternalClientList/_item", HFILL }},
    { &hf_gsm_map_clientIdentity,
      { "clientIdentity", "gsm_map.clientIdentity",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExternalClient/clientIdentity", HFILL }},
    { &hf_gsm_map_gmlc_Restriction,
      { "gmlc-Restriction", "gsm_map.gmlc_Restriction",
        FT_UINT32, BASE_DEC, VALS(gsm_map_GMLC_Restriction_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_ServiceTypeList_item,
      { "Item", "gsm_map.ServiceTypeList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceTypeList/_item", HFILL }},
    { &hf_gsm_map_serviceTypeIdentity,
      { "serviceTypeIdentity", "gsm_map.serviceTypeIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServiceType/serviceTypeIdentity", HFILL }},
    { &hf_gsm_map_MOLR_List_item,
      { "Item", "gsm_map.MOLR_List_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MOLR-List/_item", HFILL }},
    { &hf_gsm_map_CallBarringFeatureList_item,
      { "Item", "gsm_map.CallBarringFeatureList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallBarringFeatureList/_item", HFILL }},
    { &hf_gsm_map_basicService,
      { "basicService", "gsm_map.basicService",
        FT_UINT32, BASE_DEC, VALS(gsm_map_BasicServiceCode_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_ss_Status,
      { "ss-Status", "gsm_map.ss_Status",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ForwardingFeatureList_item,
      { "Item", "gsm_map.ForwardingFeatureList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ForwardingFeatureList/_item", HFILL }},
    { &hf_gsm_map_forwardingOptions,
      { "forwardingOptions", "gsm_map.forwardingOptions",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_noReplyConditionTime,
      { "noReplyConditionTime", "gsm_map.noReplyConditionTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_matchType,
      { "matchType", "gsm_map.matchType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_MatchType_vals), 0,
        "DestinationNumberCriteria/matchType", HFILL }},
    { &hf_gsm_map_destinationNumberList,
      { "destinationNumberList", "gsm_map.destinationNumberList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DestinationNumberCriteria/destinationNumberList", HFILL }},
    { &hf_gsm_map_destinationNumberLengthList,
      { "destinationNumberLengthList", "gsm_map.destinationNumberLengthList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DestinationNumberCriteria/destinationNumberLengthList", HFILL }},
    { &hf_gsm_map_DestinationNumberList_item,
      { "Item", "gsm_map.DestinationNumberList_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "DestinationNumberList/_item", HFILL }},
    { &hf_gsm_map_DestinationNumberLengthList_item,
      { "Item", "gsm_map.DestinationNumberLengthList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DestinationNumberLengthList/_item", HFILL }},
    { &hf_gsm_map_forwardingFeatureList,
      { "forwardingFeatureList", "gsm_map.forwardingFeatureList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_callBarringFeatureList,
      { "callBarringFeatureList", "gsm_map.callBarringFeatureList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CallBarringInfo/callBarringFeatureList", HFILL }},
    { &hf_gsm_map_nbrSB,
      { "nbrSB", "gsm_map.nbrSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_nbrUser,
      { "nbrUser", "gsm_map.nbrUser",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_hlr_List,
      { "hlr-List", "gsm_map.hlr_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResetArg/hlr-List", HFILL }},
    { &hf_gsm_map_msNotReachable,
      { "msNotReachable", "gsm_map.msNotReachable",
        FT_NONE, BASE_NONE, NULL, 0,
        "RestoreDataRes/msNotReachable", HFILL }},
    { &hf_gsm_map_VBSDataList_item,
      { "Item", "gsm_map.VBSDataList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "VBSDataList/_item", HFILL }},
    { &hf_gsm_map_VGCSDataList_item,
      { "Item", "gsm_map.VGCSDataList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "VGCSDataList/_item", HFILL }},
    { &hf_gsm_map_groupId,
      { "groupId", "gsm_map.groupId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "VoiceGroupCallData/groupId", HFILL }},
    { &hf_gsm_map_groupid,
      { "groupid", "gsm_map.groupid",
        FT_BYTES, BASE_HEX, NULL, 0,
        "VoiceBroadcastData/groupid", HFILL }},
    { &hf_gsm_map_broadcastInitEntitlement,
      { "broadcastInitEntitlement", "gsm_map.broadcastInitEntitlement",
        FT_NONE, BASE_NONE, NULL, 0,
        "VoiceBroadcastData/broadcastInitEntitlement", HFILL }},
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
        FT_UINT32, BASE_DEC, VALS(gsm_map_InterrogationType_vals), 0,
        "SendRoutingInfoArg/interrogationType", HFILL }},
    { &hf_gsm_map_or_Interrogation,
      { "or-Interrogation", "gsm_map.or_Interrogation",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_or_Capability,
      { "or-Capability", "gsm_map.or_Capability",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SendRoutingInfoArg/or-Capability", HFILL }},
    { &hf_gsm_map_gmsc_OrGsmSCF_Address,
      { "gmsc-OrGsmSCF-Address", "gsm_map.gmsc_OrGsmSCF_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SendRoutingInfoArg/gmsc-OrGsmSCF-Address", HFILL }},
    { &hf_gsm_map_callReferenceNumber,
      { "callReferenceNumber", "gsm_map.callReferenceNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_forwardingReason,
      { "forwardingReason", "gsm_map.forwardingReason",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ForwardingReason_vals), 0,
        "SendRoutingInfoArg/forwardingReason", HFILL }},
    { &hf_gsm_map_ext_basicServiceGroup,
      { "basicServiceGroup", "gsm_map.basicServiceGroup",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ext_BasicServiceCode_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_networkSignalInfo,
      { "networkSignalInfo", "gsm_map.networkSignalInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_camelInfo,
      { "camelInfo", "gsm_map.camelInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoArg/camelInfo", HFILL }},
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
    { &hf_gsm_map_pre_pagingSupported,
      { "pre-pagingSupported", "gsm_map.pre_pagingSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_callDiversionTreatmentIndicator,
      { "callDiversionTreatmentIndicator", "gsm_map.callDiversionTreatmentIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SendRoutingInfoArg/callDiversionTreatmentIndicator", HFILL }},
    { &hf_gsm_map_suppress_VT_CSI,
      { "suppress-VT-CSI", "gsm_map.suppress_VT_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_suppressIncomingCallBarring,
      { "suppressIncomingCallBarring", "gsm_map.suppressIncomingCallBarring",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoArg/suppressIncomingCallBarring", HFILL }},
    { &hf_gsm_map_gsmSCF_InitiatedCall,
      { "gsmSCF-InitiatedCall", "gsm_map.gsmSCF_InitiatedCall",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoArg/gsmSCF-InitiatedCall", HFILL }},
    { &hf_gsm_map_basicServiceGroup2,
      { "basicServiceGroup2", "gsm_map.basicServiceGroup2",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ext_BasicServiceCode_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_networkSignalInfo2,
      { "networkSignalInfo2", "gsm_map.networkSignalInfo2",
        FT_NONE, BASE_NONE, NULL, 0,
        "SendRoutingInfoArg/networkSignalInfo2", HFILL }},
    { &hf_gsm_map_extendedRoutingInfo,
      { "extendedRoutingInfo", "gsm_map.extendedRoutingInfo",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ExtendedRoutingInfo_vals), 0,
        "SendRoutingInfoRes/extendedRoutingInfo", HFILL }},
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
    { &hf_gsm_map_numberPortabilityStatus,
      { "numberPortabilityStatus", "gsm_map.numberPortabilityStatus",
        FT_UINT32, BASE_DEC, VALS(gsm_map_NumberPortabilityStatus_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_supportedCamelPhasesInVMSC,
      { "supportedCamelPhasesInVMSC", "gsm_map.supportedCamelPhasesInVMSC",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SendRoutingInfoRes/supportedCamelPhasesInVMSC", HFILL }},
    { &hf_gsm_map_offeredCamel4CSIsInVMSC,
      { "offeredCamel4CSIsInVMSC", "gsm_map.offeredCamel4CSIsInVMSC",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SendRoutingInfoRes/offeredCamel4CSIsInVMSC", HFILL }},
    { &hf_gsm_map_routingInfo2,
      { "routingInfo2", "gsm_map.routingInfo2",
        FT_UINT32, BASE_DEC, VALS(gsm_map_RoutingInfo_vals), 0,
        "SendRoutingInfoRes/routingInfo2", HFILL }},
    { &hf_gsm_map_ss_List2,
      { "ss-List2", "gsm_map.ss_List2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SendRoutingInfoRes/ss-List2", HFILL }},
    { &hf_gsm_map_basicService2,
      { "basicService2", "gsm_map.basicService2",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ext_BasicServiceCode_vals), 0,
        "SendRoutingInfoRes/basicService2", HFILL }},
    { &hf_gsm_map_allowedServices,
      { "allowedServices", "gsm_map.allowedServices",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SendRoutingInfoRes/allowedServices", HFILL }},
    { &hf_gsm_map_unavailabilityCause,
      { "unavailabilityCause", "gsm_map.unavailabilityCause",
        FT_UINT32, BASE_DEC, VALS(gsm_map_UnavailabilityCause_vals), 0,
        "SendRoutingInfoRes/unavailabilityCause", HFILL }},
    { &hf_gsm_map_releaseResourcesSupported,
      { "releaseResourcesSupported", "gsm_map.releaseResourcesSupported",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ext_ProtocolId,
      { "ext-ProtocolId", "gsm_map.ext_ProtocolId",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ext_ProtocolId_vals), 0,
        "Ext-ExternalSignalInfo/ext-ProtocolId", HFILL }},
    { &hf_gsm_map_accessNetworkProtocolId,
      { "accessNetworkProtocolId", "gsm_map.accessNetworkProtocolId",
        FT_UINT32, BASE_DEC, VALS(gsm_map_AccessNetworkProtocolId_vals), 0,
        "AccessNetworkSignalInfo/accessNetworkProtocolId", HFILL }},
    { &hf_gsm_map_longsignalInfo,
      { "signalInfo", "gsm_map.signalInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AccessNetworkSignalInfo/signalInfo", HFILL }},
    { &hf_gsm_map_suppress_T_CSI,
      { "suppress-T-CSI", "gsm_map.suppress_T_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "CamelInfo/suppress-T-CSI", HFILL }},
    { &hf_gsm_map_HLR_List_item,
      { "Item", "gsm_map.HLR_List_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "HLR-List/_item", HFILL }},
    { &hf_gsm_map_SS_List_item,
      { "Item", "gsm_map.SS_List_item",
        FT_UINT8, BASE_DEC, VALS(ssCode_vals), 0,
        "SS-List/_item", HFILL }},
    { &hf_gsm_map_naea_PreferredCIC,
      { "naea-PreferredCIC", "gsm_map.naea_PreferredCIC",
        FT_BYTES, BASE_HEX, NULL, 0,
        "NAEA-PreferredCI/naea-PreferredCIC", HFILL }},
    { &hf_gsm_map_externalAddress,
      { "externalAddress", "gsm_map.externalAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LCSClientExternalID/externalAddress", HFILL }},
    { &hf_gsm_map_cellGlobalIdOrServiceAreaIdFixedLength,
      { "cellGlobalIdOrServiceAreaIdFixedLength", "gsm_map.cellGlobalIdOrServiceAreaIdFixedLength",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CellGlobalIdOrServiceAreaIdOrLAI/cellGlobalIdOrServiceAreaIdFixedLength", HFILL }},
    { &hf_gsm_map_laiFixedLength,
      { "laiFixedLength", "gsm_map.laiFixedLength",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CellGlobalIdOrServiceAreaIdOrLAI/laiFixedLength", HFILL }},
    { &hf_gsm_map_ccbs_Possible,
      { "ccbs-Possible", "gsm_map.ccbs_Possible",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_keepCCBS_CallIndicator,
      { "keepCCBS-CallIndicator", "gsm_map.keepCCBS_CallIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "CCBS-Indicators/keepCCBS-CallIndicator", HFILL }},
    { &hf_gsm_map_roamingNumber,
      { "roamingNumber", "gsm_map.roamingNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_forwardingData,
      { "forwardingData", "gsm_map.forwardingData",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_routingInfo,
      { "routingInfo", "gsm_map.routingInfo",
        FT_UINT32, BASE_DEC, VALS(gsm_map_RoutingInfo_vals), 0,
        "ExtendedRoutingInfo/routingInfo", HFILL }},
    { &hf_gsm_map_camelRoutingInfo,
      { "camelRoutingInfo", "gsm_map.camelRoutingInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedRoutingInfo/camelRoutingInfo", HFILL }},
    { &hf_gsm_map_gmscCamelSubscriptionInfo,
      { "gmscCamelSubscriptionInfo", "gsm_map.gmscCamelSubscriptionInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "CamelRoutingInfo/gmscCamelSubscriptionInfo", HFILL }},
    { &hf_gsm_map_t_CSI,
      { "t-CSI", "gsm_map.t_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_d_csi,
      { "d-csi", "gsm_map.d_csi",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ageOfLocationInformation,
      { "ageOfLocationInformation", "gsm_map.ageOfLocationInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_geographicalInformation,
      { "geographicalInformation", "gsm_map.geographicalInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_vlr_number,
      { "vlr-number", "gsm_map.vlr_number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LocationInformation/vlr-number", HFILL }},
    { &hf_gsm_map_locationNumber,
      { "locationNumber", "gsm_map.locationNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LocationInformation/locationNumber", HFILL }},
    { &hf_gsm_map_cellGlobalIdOrServiceAreaIdOrLAI,
      { "cellGlobalIdOrServiceAreaIdOrLAI", "gsm_map.cellGlobalIdOrServiceAreaIdOrLAI",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CellGlobalIdOrServiceAreaIdOrLAI_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_selectedLSA_Id,
      { "selectedLSA-Id", "gsm_map.selectedLSA_Id",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LocationInformation/selectedLSA-Id", HFILL }},
    { &hf_gsm_map_geodeticInformation,
      { "geodeticInformation", "gsm_map.geodeticInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_currentLocationRetrieved,
      { "currentLocationRetrieved", "gsm_map.currentLocationRetrieved",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_sai_Present,
      { "sai-Present", "gsm_map.sai_Present",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_routeingAreaIdentity,
      { "routeingAreaIdentity", "gsm_map.routeingAreaIdentity",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LocationInformationGPRS/routeingAreaIdentity", HFILL }},
    { &hf_gsm_map_selectedLSAIdentity,
      { "selectedLSAIdentity", "gsm_map.selectedLSAIdentity",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LocationInformationGPRS/selectedLSAIdentity", HFILL }},
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
    { &hf_gsm_map_notProvidedFromSGSN,
      { "notProvidedFromSGSN", "gsm_map.notProvidedFromSGSN",
        FT_NONE, BASE_NONE, NULL, 0,
        "PS-SubscriberState/notProvidedFromSGSN", HFILL }},
    { &hf_gsm_map_ps_Detached,
      { "ps-Detached", "gsm_map.ps_Detached",
        FT_NONE, BASE_NONE, NULL, 0,
        "PS-SubscriberState/ps-Detached", HFILL }},
    { &hf_gsm_map_ps_AttachedNotReachableForPaging,
      { "ps-AttachedNotReachableForPaging", "gsm_map.ps_AttachedNotReachableForPaging",
        FT_NONE, BASE_NONE, NULL, 0,
        "PS-SubscriberState/ps-AttachedNotReachableForPaging", HFILL }},
    { &hf_gsm_map_ps_AttachedReachableForPaging,
      { "ps-AttachedReachableForPaging", "gsm_map.ps_AttachedReachableForPaging",
        FT_NONE, BASE_NONE, NULL, 0,
        "PS-SubscriberState/ps-AttachedReachableForPaging", HFILL }},
    { &hf_gsm_map_ps_PDP_ActiveNotReachableForPaging,
      { "ps-PDP-ActiveNotReachableForPaging", "gsm_map.ps_PDP_ActiveNotReachableForPaging",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PS-SubscriberState/ps-PDP-ActiveNotReachableForPaging", HFILL }},
    { &hf_gsm_map_ps_PDP_ActiveReachableForPaging,
      { "ps-PDP-ActiveReachableForPaging", "gsm_map.ps_PDP_ActiveReachableForPaging",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PS-SubscriberState/ps-PDP-ActiveReachableForPaging", HFILL }},
    { &hf_gsm_map_netDetNotReachable,
      { "netDetNotReachable", "gsm_map.netDetNotReachable",
        FT_UINT32, BASE_DEC, VALS(gsm_map_NotReachableReason_vals), 0,
        "PS-SubscriberState/netDetNotReachable", HFILL }},
    { &hf_gsm_map_PDP_ContextInfoList_item,
      { "Item", "gsm_map.PDP_ContextInfoList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDP-ContextInfoList/_item", HFILL }},
    { &hf_gsm_map_pdp_ContextIdentifier,
      { "pdp-ContextIdentifier", "gsm_map.pdp_ContextIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDP-ContextInfo/pdp-ContextIdentifier", HFILL }},
    { &hf_gsm_map_pdp_ContextActive,
      { "pdp-ContextActive", "gsm_map.pdp_ContextActive",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDP-ContextInfo/pdp-ContextActive", HFILL }},
    { &hf_gsm_map_apn_Subscribed,
      { "apn-Subscribed", "gsm_map.apn_Subscribed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-ContextInfo/apn-Subscribed", HFILL }},
    { &hf_gsm_map_apn_InUse,
      { "apn-InUse", "gsm_map.apn_InUse",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-ContextInfo/apn-InUse", HFILL }},
    { &hf_gsm_map_nsapi,
      { "nsapi", "gsm_map.nsapi",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDP-ContextInfo/nsapi", HFILL }},
    { &hf_gsm_map_transactionId,
      { "transactionId", "gsm_map.transactionId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-ContextInfo/transactionId", HFILL }},
    { &hf_gsm_map_teid_ForGnAndGp,
      { "teid-ForGnAndGp", "gsm_map.teid_ForGnAndGp",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-ContextInfo/teid-ForGnAndGp", HFILL }},
    { &hf_gsm_map_teid_ForIu,
      { "teid-ForIu", "gsm_map.teid_ForIu",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-ContextInfo/teid-ForIu", HFILL }},
    { &hf_gsm_map_ggsn_Address,
      { "ggsn-Address", "gsm_map.ggsn_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ext_qos_Subscribed,
      { "qos-Subscribed", "gsm_map.qos_Subscribed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-ContextInfo/qos-Subscribed", HFILL }},
    { &hf_gsm_map_qos_Requested,
      { "qos-Requested", "gsm_map.qos_Requested",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-ContextInfo/qos-Requested", HFILL }},
    { &hf_gsm_map_qos_Negotiated,
      { "qos-Negotiated", "gsm_map.qos_Negotiated",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-ContextInfo/qos-Negotiated", HFILL }},
    { &hf_gsm_map_chargingId,
      { "chargingId", "gsm_map.chargingId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-ContextInfo/chargingId", HFILL }},
    { &hf_gsm_map_rnc_Address,
      { "rnc-Address", "gsm_map.rnc_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-ContextInfo/rnc-Address", HFILL }},
    { &hf_gsm_map_qos2_Subscribed,
      { "qos2-Subscribed", "gsm_map.qos2_Subscribed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-ContextInfo/qos2-Subscribed", HFILL }},
    { &hf_gsm_map_qos2_Requested,
      { "qos2-Requested", "gsm_map.qos2_Requested",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-ContextInfo/qos2-Requested", HFILL }},
    { &hf_gsm_map_qos2_Negotiated,
      { "qos2-Negotiated", "gsm_map.qos2_Negotiated",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PDP-ContextInfo/qos2-Negotiated", HFILL }},
    { &hf_gsm_map_cug_OutgoingAccess,
      { "cug-OutgoingAccess", "gsm_map.cug_OutgoingAccess",
        FT_NONE, BASE_NONE, NULL, 0,
        "CUG-CheckInfo/cug-OutgoingAccess", HFILL }},
    { &hf_gsm_map_gsm_BearerCapability,
      { "gsm-BearerCapability", "gsm_map.gsm_BearerCapability",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_gmsc_Address,
      { "gmsc-Address", "gsm_map.gmsc_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProvideRoamingNumberArg/gmsc-Address", HFILL }},
    { &hf_gsm_map_supportedCamelPhasesInInterrogatingNode,
      { "supportedCamelPhasesInInterrogatingNode", "gsm_map.supportedCamelPhasesInInterrogatingNode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProvideRoamingNumberArg/supportedCamelPhasesInInterrogatingNode", HFILL }},
    { &hf_gsm_map_orNotSupportedInGMSC,
      { "orNotSupportedInGMSC", "gsm_map.orNotSupportedInGMSC",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideRoamingNumberArg/orNotSupportedInGMSC", HFILL }},
    { &hf_gsm_map_offeredCamel4CSIsInInterrogatingNode,
      { "offeredCamel4CSIsInInterrogatingNode", "gsm_map.offeredCamel4CSIsInInterrogatingNode",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProvideRoamingNumberArg/offeredCamel4CSIsInInterrogatingNode", HFILL }},
    { &hf_gsm_map_uu_Data,
      { "uu-Data", "gsm_map.uu_Data",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResumeCallHandlingArg/uu-Data", HFILL }},
    { &hf_gsm_map_allInformationSent,
      { "allInformationSent", "gsm_map.allInformationSent",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_o_BcsmCamelTDPCriteriaList,
      { "o-BcsmCamelTDPCriteriaList", "gsm_map.o_BcsmCamelTDPCriteriaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResumeCallHandlingArg/o-BcsmCamelTDPCriteriaList", HFILL }},
    { &hf_gsm_map_uuIndicator,
      { "uuIndicator", "gsm_map.uuIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UU-Data/uuIndicator", HFILL }},
    { &hf_gsm_map_uui,
      { "uui", "gsm_map.uui",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UU-Data/uui", HFILL }},
    { &hf_gsm_map_uusCFInteraction,
      { "uusCFInteraction", "gsm_map.uusCFInteraction",
        FT_NONE, BASE_NONE, NULL, 0,
        "UU-Data/uusCFInteraction", HFILL }},
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
        "", HFILL }},
    { &hf_gsm_map_ccbs_Monitoring,
      { "ccbs-Monitoring", "gsm_map.ccbs_Monitoring",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ReportingState_vals), 0,
        "SetReportingStateArg/ccbs-Monitoring", HFILL }},
    { &hf_gsm_map_ccbs_SubscriberStatus,
      { "ccbs-SubscriberStatus", "gsm_map.ccbs_SubscriberStatus",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CCBS_SubscriberStatus_vals), 0,
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
        "CallReportData/monitoringMode", HFILL }},
    { &hf_gsm_map_callOutcome,
      { "callOutcome", "gsm_map.callOutcome",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CallOutcome_vals), 0,
        "CallReportData/callOutcome", HFILL }},
    { &hf_gsm_map_callTerminationIndicator,
      { "callTerminationIndicator", "gsm_map.callTerminationIndicator",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CallTerminationIndicator_vals), 0,
        "IST-AlertRes/callTerminationIndicator", HFILL }},
    { &hf_gsm_map_msrn,
      { "msrn", "gsm_map.msrn",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ReleaseResourcesArg/msrn", HFILL }},
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
    { &hf_gsm_map_ext_basicServiceGroupList,
      { "basicServiceGroupList", "gsm_map.basicServiceGroupList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_cliRestrictionOption,
      { "cliRestrictionOption", "gsm_map.cliRestrictionOption",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CliRestrictionOption_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_overrideCategory,
      { "overrideCategory", "gsm_map.overrideCategory",
        FT_UINT32, BASE_DEC, VALS(gsm_map_OverrideCategory_vals), 0,
        "SS-SubscriptionOption/overrideCategory", HFILL }},
    { &hf_gsm_map_forwardedToNumber_addr,
      { "forwardedToNumber", "gsm_map.forwardedToNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_forwardingInfo,
      { "forwardingInfo", "gsm_map.forwardingInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "SS-Info/forwardingInfo", HFILL }},
    { &hf_gsm_map_callBarringInfo,
      { "callBarringInfo", "gsm_map.callBarringInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "SS-Info/callBarringInfo", HFILL }},
    { &hf_gsm_map_ss_Data,
      { "ss-Data", "gsm_map.ss_Data",
        FT_NONE, BASE_NONE, NULL, 0,
        "SS-Info/ss-Data", HFILL }},
    { &hf_gsm_map_genericServiceInfo,
      { "genericServiceInfo", "gsm_map.genericServiceInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "InterrogateSS-Res/genericServiceInfo", HFILL }},
    { &hf_gsm_map_ussd_DataCodingScheme,
      { "ussd-DataCodingScheme", "gsm_map.ussd_DataCodingScheme",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ussd_String,
      { "ussd-String", "gsm_map.ussd_String",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_failureCause,
      { "failureCause", "gsm_map.failureCause",
        FT_UINT32, BASE_DEC, VALS(gsm_map_FailureCause_vals), 0,
        "AuthenticationFailureReportArg/failureCause", HFILL }},
    { &hf_gsm_map_re_attempt,
      { "re-attempt", "gsm_map.re_attempt",
        FT_BOOLEAN, 8, NULL, 0,
        "AuthenticationFailureReportArg/re-attempt", HFILL }},
    { &hf_gsm_map_accessType,
      { "accessType", "gsm_map.accessType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_AccessType_vals), 0,
        "AuthenticationFailureReportArg/accessType", HFILL }},
    { &hf_gsm_map_ccbs_Data,
      { "ccbs-Data", "gsm_map.ccbs_Data",
        FT_NONE, BASE_NONE, NULL, 0,
        "RegisterCC-EntryArg/ccbs-Data", HFILL }},
    { &hf_gsm_map_serviceIndicator,
      { "serviceIndicator", "gsm_map.serviceIndicator",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CCBS-Data/serviceIndicator", HFILL }},
    { &hf_gsm_map_ccbs_Index,
      { "ccbs-Index", "gsm_map.ccbs_Index",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
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
        "RoutingInfoForSM-Res/locationInfoWithLMSI", HFILL }},
    { &hf_gsm_map_networkNode_Number,
      { "networkNode-Number", "gsm_map.networkNode_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_gprsNodeIndicator,
      { "gprsNodeIndicator", "gsm_map.gprsNodeIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_additional_Number,
      { "additional-Number", "gsm_map.additional_Number",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Additional_Number_vals), 0,
        "", HFILL }},
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
    { &hf_gsm_map_locationInformation,
      { "locationInformation", "gsm_map.locationInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_subscriberState,
      { "subscriberState", "gsm_map.subscriberState",
        FT_UINT32, BASE_DEC, VALS(gsm_map_SubscriberState_vals), 0,
        "SubscriberInfo/subscriberState", HFILL }},
    { &hf_gsm_map_locationInformationGPRS,
      { "locationInformationGPRS", "gsm_map.locationInformationGPRS",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ps_SubscriberState,
      { "ps-SubscriberState", "gsm_map.ps_SubscriberState",
        FT_UINT32, BASE_DEC, VALS(gsm_map_PS_SubscriberState_vals), 0,
        "SubscriberInfo/ps-SubscriberState", HFILL }},
    { &hf_gsm_map_ms_Classmark2,
      { "ms-Classmark2", "gsm_map.ms_Classmark2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SubscriberInfo/ms-Classmark2", HFILL }},
    { &hf_gsm_map_gprs_MS_Class,
      { "gprs-MS-Class", "gsm_map.gprs_MS_Class",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubscriberInfo/gprs-MS-Class", HFILL }},
    { &hf_gsm_map_mnpInfoRes,
      { "mnpInfoRes", "gsm_map.mnpInfoRes",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubscriberInfo/mnpInfoRes", HFILL }},
    { &hf_gsm_map_routeingNumber,
      { "routeingNumber", "gsm_map.routeingNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "MNPInfoRes/routeingNumber", HFILL }},
    { &hf_gsm_map_mSNetworkCapability,
      { "mSNetworkCapability", "gsm_map.mSNetworkCapability",
        FT_BYTES, BASE_HEX, NULL, 0,
        "GPRSMSClass/mSNetworkCapability", HFILL }},
    { &hf_gsm_map_mSRadioAccessCapability,
      { "mSRadioAccessCapability", "gsm_map.mSRadioAccessCapability",
        FT_BYTES, BASE_HEX, NULL, 0,
        "GPRSMSClass/mSRadioAccessCapability", HFILL }},
    { &hf_gsm_map_locationInformation_flg,
      { "locationInformation", "gsm_map.locationInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedInfo/locationInformation", HFILL }},
    { &hf_gsm_map_subscriberState_flg,
      { "subscriberState", "gsm_map.subscriberState",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedInfo/subscriberState", HFILL }},
    { &hf_gsm_map_currentLocation,
      { "currentLocation", "gsm_map.currentLocation",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedInfo/currentLocation", HFILL }},
    { &hf_gsm_map_requestedDomain,
      { "requestedDomain", "gsm_map.requestedDomain",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_requestedDomain_vals), 0,
        "RequestedInfo/requestedDomain", HFILL }},
    { &hf_gsm_map_imei_flg,
      { "imei", "gsm_map.imei",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedInfo/imei", HFILL }},
    { &hf_gsm_map_ms_classmark,
      { "ms-classmark", "gsm_map.ms_classmark",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedInfo/ms-classmark", HFILL }},
    { &hf_gsm_map_mnpRequestedInfo,
      { "mnpRequestedInfo", "gsm_map.mnpRequestedInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedInfo/mnpRequestedInfo", HFILL }},
    { &hf_gsm_map_subscriberIdentity,
      { "subscriberIdentity", "gsm_map.subscriberIdentity",
        FT_UINT32, BASE_DEC, VALS(gsm_map_SubscriberIdentity_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_requestedSubscriptionInfo,
      { "requestedSubscriptionInfo", "gsm_map.requestedSubscriptionInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "AnyTimeSubscriptionInterrogationArg/requestedSubscriptionInfo", HFILL }},
    { &hf_gsm_map_callForwardingData,
      { "callForwardingData", "gsm_map.callForwardingData",
        FT_NONE, BASE_NONE, NULL, 0,
        "AnyTimeSubscriptionInterrogationRes/callForwardingData", HFILL }},
    { &hf_gsm_map_callBarringData,
      { "callBarringData", "gsm_map.callBarringData",
        FT_NONE, BASE_NONE, NULL, 0,
        "AnyTimeSubscriptionInterrogationRes/callBarringData", HFILL }},
    { &hf_gsm_map_odb_Info,
      { "odb-Info", "gsm_map.odb_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_camel_SubscriptionInfo,
      { "camel-SubscriptionInfo", "gsm_map.camel_SubscriptionInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_supportedVLR_CAMEL_Phases,
      { "supportedVLR-CAMEL-Phases", "gsm_map.supportedVLR_CAMEL_Phases",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AnyTimeSubscriptionInterrogationRes/supportedVLR-CAMEL-Phases", HFILL }},
    { &hf_gsm_map_supportedSGSN_CAMEL_Phases,
      { "supportedSGSN-CAMEL-Phases", "gsm_map.supportedSGSN_CAMEL_Phases",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AnyTimeSubscriptionInterrogationRes/supportedSGSN-CAMEL-Phases", HFILL }},
    { &hf_gsm_map_offeredCamel4CSIsInVLR,
      { "offeredCamel4CSIsInVLR", "gsm_map.offeredCamel4CSIsInVLR",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AnyTimeSubscriptionInterrogationRes/offeredCamel4CSIsInVLR", HFILL }},
    { &hf_gsm_map_offeredCamel4CSIsInSGSN,
      { "offeredCamel4CSIsInSGSN", "gsm_map.offeredCamel4CSIsInSGSN",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AnyTimeSubscriptionInterrogationRes/offeredCamel4CSIsInSGSN", HFILL }},
    { &hf_gsm_map_requestedSS_Info,
      { "requestedSS-Info", "gsm_map.requestedSS_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedSubscriptionInfo/requestedSS-Info", HFILL }},
    { &hf_gsm_map_odb,
      { "odb", "gsm_map.odb",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedSubscriptionInfo/odb", HFILL }},
    { &hf_gsm_map_requestedCAMEL_SubscriptionInfo,
      { "requestedCAMEL-SubscriptionInfo", "gsm_map.requestedCAMEL_SubscriptionInfo",
        FT_UINT32, BASE_DEC, VALS(gsm_map_RequestedCAMEL_SubscriptionInfo_vals), 0,
        "RequestedSubscriptionInfo/requestedCAMEL-SubscriptionInfo", HFILL }},
    { &hf_gsm_map_supportedVLR_CAMEL_Phases_flg,
      { "supportedVLR-CAMEL-Phases", "gsm_map.supportedVLR_CAMEL_Phases",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedSubscriptionInfo/supportedVLR-CAMEL-Phases", HFILL }},
    { &hf_gsm_map_supportedSGSN_CAMEL_Phases_flg,
      { "supportedSGSN-CAMEL-Phases", "gsm_map.supportedSGSN_CAMEL_Phases",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedSubscriptionInfo/supportedSGSN-CAMEL-Phases", HFILL }},
    { &hf_gsm_map_additionalRequestedCAMEL_SubscriptionInfo,
      { "additionalRequestedCAMEL-SubscriptionInfo", "gsm_map.additionalRequestedCAMEL_SubscriptionInfo",
        FT_UINT32, BASE_DEC, VALS(gsm_map_AdditionalRequestedCAMEL_SubscriptionInfo_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_password,
      { "password", "gsm_map.password",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_wrongPasswordAttemptsCounter,
      { "wrongPasswordAttemptsCounter", "gsm_map.wrongPasswordAttemptsCounter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_bearerService,
      { "bearerService", "gsm_map.bearerService",
        FT_UINT8, BASE_DEC, VALS(Bearerservice_vals), 0,
        "BasicServiceCode/bearerService", HFILL }},
    { &hf_gsm_map_teleservice_code,
      { "teleservice", "gsm_map.teleservice",
        FT_UINT8, BASE_DEC, VALS(Teleservice_vals), 0,
        "BasicServiceCode/teleservice", HFILL }},
    { &hf_gsm_map_O_BcsmCamelTDPCriteriaList_item,
      { "Item", "gsm_map.O_BcsmCamelTDPCriteriaList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "O-BcsmCamelTDPCriteriaList/_item", HFILL }},
    { &hf_gsm_map_T_BCSM_CAMEL_TDP_CriteriaList_item,
      { "Item", "gsm_map.T_BCSM_CAMEL_TDP_CriteriaList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "T-BCSM-CAMEL-TDP-CriteriaList/_item", HFILL }},
    { &hf_gsm_map_destinationNumberCriteria,
      { "destinationNumberCriteria", "gsm_map.destinationNumberCriteria",
        FT_NONE, BASE_NONE, NULL, 0,
        "O-BcsmCamelTDP-Criteria/destinationNumberCriteria", HFILL }},
    { &hf_gsm_map_basicServiceCriteria,
      { "basicServiceCriteria", "gsm_map.basicServiceCriteria",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_callTypeCriteria,
      { "callTypeCriteria", "gsm_map.callTypeCriteria",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CallTypeCriteria_vals), 0,
        "O-BcsmCamelTDP-Criteria/callTypeCriteria", HFILL }},
    { &hf_gsm_map_o_CauseValueCriteria,
      { "o-CauseValueCriteria", "gsm_map.o_CauseValueCriteria",
        FT_UINT32, BASE_DEC, NULL, 0,
        "O-BcsmCamelTDP-Criteria/o-CauseValueCriteria", HFILL }},
    { &hf_gsm_map_t_BCSM_TriggerDetectionPoint,
      { "t-BCSM-TriggerDetectionPoint", "gsm_map.t_BCSM_TriggerDetectionPoint",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_BcsmTriggerDetectionPoint_vals), 0,
        "T-BCSM-CAMEL-TDP-Criteria/t-BCSM-TriggerDetectionPoint", HFILL }},
    { &hf_gsm_map_t_CauseValueCriteria,
      { "t-CauseValueCriteria", "gsm_map.t_CauseValueCriteria",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T-BCSM-CAMEL-TDP-Criteria/t-CauseValueCriteria", HFILL }},
    { &hf_gsm_map_maximumEntitledPriority,
      { "maximumEntitledPriority", "gsm_map.maximumEntitledPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GenericServiceInfo/maximumEntitledPriority", HFILL }},
    { &hf_gsm_map_ccbs_FeatureList,
      { "ccbs-FeatureList", "gsm_map.ccbs_FeatureList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GenericServiceInfo/ccbs-FeatureList", HFILL }},
    { &hf_gsm_map_nbrSN,
      { "nbrSN", "gsm_map.nbrSN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GenericServiceInfo/nbrSN", HFILL }},
    { &hf_gsm_map_CCBS_FeatureList_item,
      { "Item", "gsm_map.CCBS_FeatureList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CCBS-FeatureList/_item", HFILL }},
    { &hf_gsm_map_b_subscriberNumber,
      { "b-subscriberNumber", "gsm_map.b_subscriberNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CCBS-Feature/b-subscriberNumber", HFILL }},
    { &hf_gsm_map_b_subscriberSubaddress,
      { "b-subscriberSubaddress", "gsm_map.b_subscriberSubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CCBS-Feature/b-subscriberSubaddress", HFILL }},
    { &hf_gsm_map_basicServiceGroup,
      { "basicServiceGroup", "gsm_map.basicServiceGroup",
        FT_UINT32, BASE_DEC, VALS(gsm_map_BasicServiceCode_vals), 0,
        "CCBS-Feature/basicServiceGroup", HFILL }},
    { &hf_gsm_map_T_CauseValueCriteria_item,
      { "Item", "gsm_map.T_CauseValueCriteria_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "T-CauseValueCriteria/_item", HFILL }},
    { &hf_gsm_map_O_CauseValueCriteria_item,
      { "Item", "gsm_map.O_CauseValueCriteria_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "O-CauseValueCriteria/_item", HFILL }},
    { &hf_gsm_map_BasicServiceCriteria_item,
      { "Item", "gsm_map.BasicServiceCriteria_item",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ext_BasicServiceCode_vals), 0,
        "BasicServiceCriteria/_item", HFILL }},
    { &hf_gsm_map_modificationRequestFor_CF_Info,
      { "modificationRequestFor-CF-Info", "gsm_map.modificationRequestFor_CF_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        "AnyTimeModificationArg/modificationRequestFor-CF-Info", HFILL }},
    { &hf_gsm_map_modificationRequestFor_CB_Info,
      { "modificationRequestFor-CB-Info", "gsm_map.modificationRequestFor_CB_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        "AnyTimeModificationArg/modificationRequestFor-CB-Info", HFILL }},
    { &hf_gsm_map_modificationRequestFor_CSI,
      { "modificationRequestFor-CSI", "gsm_map.modificationRequestFor_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "AnyTimeModificationArg/modificationRequestFor-CSI", HFILL }},
    { &hf_gsm_map_modificationRequestFor_ODB_data,
      { "modificationRequestFor-ODB-data", "gsm_map.modificationRequestFor_ODB_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "AnyTimeModificationArg/modificationRequestFor-ODB-data", HFILL }},
    { &hf_gsm_map_ss_InfoFor_CSE,
      { "ss-InfoFor-CSE", "gsm_map.ss_InfoFor_CSE",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Ext_SS_InfoFor_CSE_vals), 0,
        "AnyTimeModificationRes/ss-InfoFor-CSE", HFILL }},
    { &hf_gsm_map_modifyNotificationToCSE,
      { "modifyNotificationToCSE", "gsm_map.modifyNotificationToCSE",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ModificationInstruction_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_odb_data,
      { "odb-data", "gsm_map.odb_data",
        FT_NONE, BASE_NONE, NULL, 0,
        "ModificationRequestFor-ODB-data/odb-data", HFILL }},
    { &hf_gsm_map_requestedCamel_SubscriptionInfo,
      { "requestedCamel-SubscriptionInfo", "gsm_map.requestedCamel_SubscriptionInfo",
        FT_UINT32, BASE_DEC, VALS(gsm_map_RequestedCAMEL_SubscriptionInfo_vals), 0,
        "ModificationRequestFor-CSI/requestedCamel-SubscriptionInfo", HFILL }},
    { &hf_gsm_map_modifyCSI_State,
      { "modifyCSI-State", "gsm_map.modifyCSI_State",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ModificationInstruction_vals), 0,
        "ModificationRequestFor-CSI/modifyCSI-State", HFILL }},
    { &hf_gsm_map_forwardingInfoFor_CSE,
      { "forwardingInfoFor-CSE", "gsm_map.forwardingInfoFor_CSE",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_callBarringInfoFor_CSE,
      { "callBarringInfoFor-CSE", "gsm_map.callBarringInfoFor_CSE",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_eventMet,
      { "eventMet", "gsm_map.eventMet",
        FT_BYTES, BASE_HEX, NULL, 0,
        "NoteMM-EventArg/eventMet", HFILL }},
    { &hf_gsm_map_supportedCAMELPhases,
      { "supportedCAMELPhases", "gsm_map.supportedCAMELPhases",
        FT_BYTES, BASE_HEX, NULL, 0,
        "NoteMM-EventArg/supportedCAMELPhases", HFILL }},
    { &hf_gsm_map_offeredCamel4Functionalities,
      { "offeredCamel4Functionalities", "gsm_map.offeredCamel4Functionalities",
        FT_BYTES, BASE_HEX, NULL, 0,
        "NoteMM-EventArg/offeredCamel4Functionalities", HFILL }},
    { &hf_gsm_map_vt_BCSM_CAMEL_TDP_CriteriaList,
      { "vt-BCSM-CAMEL-TDP-CriteriaList", "gsm_map.vt_BCSM_CAMEL_TDP_CriteriaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CAMEL-SubscriptionInfo/vt-BCSM-CAMEL-TDP-CriteriaList", HFILL }},
    { &hf_gsm_map_tif_CSI_NotificationToCSE,
      { "tif-CSI-NotificationToCSE", "gsm_map.tif_CSI_NotificationToCSE",
        FT_NONE, BASE_NONE, NULL, 0,
        "CAMEL-SubscriptionInfo/tif-CSI-NotificationToCSE", HFILL }},
    { &hf_gsm_map_specificCSIDeletedList,
      { "specificCSIDeletedList", "gsm_map.specificCSIDeletedList",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CAMEL-SubscriptionInfo/specificCSIDeletedList", HFILL }},
    { &hf_gsm_map_o_IM_CSI,
      { "o-IM-CSI", "gsm_map.o_IM_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "CAMEL-SubscriptionInfo/o-IM-CSI", HFILL }},
    { &hf_gsm_map_o_IM_BcsmCamelTDP_CriteriaList,
      { "o-IM-BcsmCamelTDP-CriteriaList", "gsm_map.o_IM_BcsmCamelTDP_CriteriaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CAMEL-SubscriptionInfo/o-IM-BcsmCamelTDP-CriteriaList", HFILL }},
    { &hf_gsm_map_d_IM_CSI,
      { "d-IM-CSI", "gsm_map.d_IM_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "CAMEL-SubscriptionInfo/d-IM-CSI", HFILL }},
    { &hf_gsm_map_vt_IM_CSI,
      { "vt-IM-CSI", "gsm_map.vt_IM_CSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "CAMEL-SubscriptionInfo/vt-IM-CSI", HFILL }},
    { &hf_gsm_map_vt_IM_BCSM_CAMEL_TDP_CriteriaList,
      { "vt-IM-BCSM-CAMEL-TDP-CriteriaList", "gsm_map.vt_IM_BCSM_CAMEL_TDP_CriteriaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CAMEL-SubscriptionInfo/vt-IM-BCSM-CAMEL-TDP-CriteriaList", HFILL }},
    { &hf_gsm_map_ext_BearerService,
      { "ext-BearerService", "gsm_map.ext_BearerService",
        FT_UINT8, BASE_DEC, VALS(Bearerservice_vals), 0,
        "Ext-BasicServiceCode/ext-BearerService", HFILL }},
    { &hf_gsm_map_ext_Teleservice,
      { "ext-Teleservice", "gsm_map.ext_Teleservice",
        FT_UINT8, BASE_DEC, VALS(Teleservice_vals), 0,
        "Ext-BasicServiceCode/ext-Teleservice", HFILL }},
    { &hf_gsm_map_odb_HPLMN_Data,
      { "odb-HPLMN-Data", "gsm_map.odb_HPLMN_Data",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ODB-Data/odb-HPLMN-Data", HFILL }},
    { &hf_gsm_map_SS_EventList_item,
      { "Item", "gsm_map.SS_EventList_item",
        FT_UINT8, BASE_DEC, VALS(ssCode_vals), 0,
        "SS-EventList/_item", HFILL }},
    { &hf_gsm_map_t_BcsmCamelTDPDataList,
      { "t-BcsmCamelTDPDataList", "gsm_map.t_BcsmCamelTDPDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T-CSI/t-BcsmCamelTDPDataList", HFILL }},
    { &hf_gsm_map_T_BcsmCamelTDPDataList_item,
      { "Item", "gsm_map.T_BcsmCamelTDPDataList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "T-BcsmCamelTDPDataList/_item", HFILL }},
    { &hf_gsm_map_t_BcsmTriggerDetectionPoint,
      { "t-BcsmTriggerDetectionPoint", "gsm_map.t_BcsmTriggerDetectionPoint",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_BcsmTriggerDetectionPoint_vals), 0,
        "T-BcsmCamelTDPData/t-BcsmTriggerDetectionPoint", HFILL }},
    { &hf_gsm_map_sms_CAMEL_TDP_DataList,
      { "sms-CAMEL-TDP-DataList", "gsm_map.sms_CAMEL_TDP_DataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SMS-CSI/sms-CAMEL-TDP-DataList", HFILL }},
    { &hf_gsm_map_SMS_CAMEL_TDP_DataList_item,
      { "Item", "gsm_map.SMS_CAMEL_TDP_DataList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMS-CAMEL-TDP-DataList/_item", HFILL }},
    { &hf_gsm_map_defaultSMS_Handling,
      { "defaultSMS-Handling", "gsm_map.defaultSMS_Handling",
        FT_UINT32, BASE_DEC, VALS(gsm_map_DefaultSMS_Handling_vals), 0,
        "SMS-CAMEL-TDP-Data/defaultSMS-Handling", HFILL }},
    { &hf_gsm_map_MobilityTriggers_item,
      { "Item", "gsm_map.MobilityTriggers_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "MobilityTriggers/_item", HFILL }},
    { &hf_gsm_map_ss_Event,
      { "ss-Event", "gsm_map.ss_Event",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Ss-InvocationNotificationArg/ss-Event", HFILL }},
    { &hf_gsm_map_ss_EventSpecification,
      { "ss-EventSpecification", "gsm_map.ss_EventSpecification",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Ss-InvocationNotificationArg/ss-EventSpecification", HFILL }},
    { &hf_gsm_map_ss_EventSpecification_item,
      { "Item", "gsm_map.ss_EventSpecification_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Ss-InvocationNotificationArg/ss-EventSpecification/_item", HFILL }},
    { &hf_gsm_map_ext_teleservice,
      { "teleservice", "gsm_map.teleservice",
        FT_UINT8, BASE_DEC, VALS(Teleservice_vals), 0,
        "PrepareGroupCallArg/teleservice", HFILL }},
    { &hf_gsm_map_codec_Info,
      { "codec-Info", "gsm_map.codec_Info",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PrepareGroupCallArg/codec-Info", HFILL }},
    { &hf_gsm_map_cipheringAlgorithm,
      { "cipheringAlgorithm", "gsm_map.cipheringAlgorithm",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PrepareGroupCallArg/cipheringAlgorithm", HFILL }},
    { &hf_gsm_map_groupKeyNumber_Vk_Id,
      { "groupKeyNumber-Vk-Id", "gsm_map.groupKeyNumber_Vk_Id",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PrepareGroupCallArg/groupKeyNumber-Vk-Id", HFILL }},
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
    { &hf_gsm_map_vstk,
      { "vstk", "gsm_map.vstk",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PrepareGroupCallArg/vstk", HFILL }},
    { &hf_gsm_map_vstk_rand,
      { "vstk-rand", "gsm_map.vstk_rand",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PrepareGroupCallArg/vstk-rand", HFILL }},
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
    { &hf_gsm_map_ps_LCS_NotSupportedByUE,
      { "ps-LCS-NotSupportedByUE", "gsm_map.ps_LCS_NotSupportedByUE",
        FT_NONE, BASE_NONE, NULL, 0,
        "UpdateGprsLocationArg/ps-LCS-NotSupportedByUE", HFILL }},
    { &hf_gsm_map_gprsEnhancementsSupportIndicator,
      { "gprsEnhancementsSupportIndicator", "gsm_map.gprsEnhancementsSupportIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "SGSN-Capability/gprsEnhancementsSupportIndicator", HFILL }},
    { &hf_gsm_map_smsCallBarringSupportIndicator,
      { "smsCallBarringSupportIndicator", "gsm_map.smsCallBarringSupportIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "SGSN-Capability/smsCallBarringSupportIndicator", HFILL }},
    { &hf_gsm_map_ggsn_Number,
      { "ggsn-Number", "gsm_map.ggsn_Number",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_mobileNotReachableReason,
      { "mobileNotReachableReason", "gsm_map.mobileNotReachableReason",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SendRoutingInfoForGprsRes/mobileNotReachableReason", HFILL }},
    { &hf_gsm_map_locationType,
      { "locationType", "gsm_map.locationType",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSubscriberLocation-Arg/locationType", HFILL }},
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
    { &hf_gsm_map_lcs_Priority,
      { "lcs-Priority", "gsm_map.lcs_Priority",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProvideSubscriberLocation-Arg/lcs-Priority", HFILL }},
    { &hf_gsm_map_lcs_QoS,
      { "lcs-QoS", "gsm_map.lcs_QoS",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSubscriberLocation-Arg/lcs-QoS", HFILL }},
    { &hf_gsm_map_supportedGADShapes,
      { "supportedGADShapes", "gsm_map.supportedGADShapes",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProvideSubscriberLocation-Arg/supportedGADShapes", HFILL }},
    { &hf_gsm_map_lcs_ReferenceNumber,
      { "lcs-ReferenceNumber", "gsm_map.lcs_ReferenceNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_lcsServiceTypeID,
      { "lcsServiceTypeID", "gsm_map.lcsServiceTypeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_lcsCodeword,
      { "lcsCodeword", "gsm_map.lcsCodeword",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSubscriberLocation-Arg/lcsCodeword", HFILL }},
    { &hf_gsm_map_lcs_PrivacyCheck,
      { "lcs-PrivacyCheck", "gsm_map.lcs_PrivacyCheck",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSubscriberLocation-Arg/lcs-PrivacyCheck", HFILL }},
    { &hf_gsm_map_areaEventInfo,
      { "areaEventInfo", "gsm_map.areaEventInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSubscriberLocation-Arg/areaEventInfo", HFILL }},
    { &hf_gsm_map_h_gmlc_Address,
      { "h-gmlc-Address", "gsm_map.h_gmlc_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_locationEstimateType,
      { "locationEstimateType", "gsm_map.locationEstimateType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_LocationEstimateType_vals), 0,
        "LocationType/locationEstimateType", HFILL }},
    { &hf_gsm_map_deferredLocationEventType,
      { "deferredLocationEventType", "gsm_map.deferredLocationEventType",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_lcsClientType,
      { "lcsClientType", "gsm_map.lcsClientType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_LCSClientType_vals), 0,
        "LCS-ClientID/lcsClientType", HFILL }},
    { &hf_gsm_map_lcsClientExternalID,
      { "lcsClientExternalID", "gsm_map.lcsClientExternalID",
        FT_NONE, BASE_NONE, NULL, 0,
        "LCS-ClientID/lcsClientExternalID", HFILL }},
    { &hf_gsm_map_lcsClientDialedByMS,
      { "lcsClientDialedByMS", "gsm_map.lcsClientDialedByMS",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LCS-ClientID/lcsClientDialedByMS", HFILL }},
    { &hf_gsm_map_lcsClientInternalID,
      { "lcsClientInternalID", "gsm_map.lcsClientInternalID",
        FT_UINT32, BASE_DEC, VALS(gsm_map_LCSClientInternalID_vals), 0,
        "LCS-ClientID/lcsClientInternalID", HFILL }},
    { &hf_gsm_map_lcsClientName,
      { "lcsClientName", "gsm_map.lcsClientName",
        FT_NONE, BASE_NONE, NULL, 0,
        "LCS-ClientID/lcsClientName", HFILL }},
    { &hf_gsm_map_lcsAPN,
      { "lcsAPN", "gsm_map.lcsAPN",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LCS-ClientID/lcsAPN", HFILL }},
    { &hf_gsm_map_lcsRequestorID,
      { "lcsRequestorID", "gsm_map.lcsRequestorID",
        FT_NONE, BASE_NONE, NULL, 0,
        "LCS-ClientID/lcsRequestorID", HFILL }},
    { &hf_gsm_map_dataCodingScheme,
      { "dataCodingScheme", "gsm_map.dataCodingScheme",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_nameString,
      { "nameString", "gsm_map.nameString",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LCSClientName/nameString", HFILL }},
    { &hf_gsm_map_lcs_FormatIndicator,
      { "lcs-FormatIndicator", "gsm_map.lcs_FormatIndicator",
        FT_UINT32, BASE_DEC, VALS(gsm_map_LCS_FormatIndicator_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_requestorIDString,
      { "requestorIDString", "gsm_map.requestorIDString",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LCSRequestorID/requestorIDString", HFILL }},
    { &hf_gsm_map_horizontal_accuracy,
      { "horizontal-accuracy", "gsm_map.horizontal_accuracy",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LCS-QoS/horizontal-accuracy", HFILL }},
    { &hf_gsm_map_verticalCoordinateRequest,
      { "verticalCoordinateRequest", "gsm_map.verticalCoordinateRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "LCS-QoS/verticalCoordinateRequest", HFILL }},
    { &hf_gsm_map_vertical_accuracy,
      { "vertical-accuracy", "gsm_map.vertical_accuracy",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LCS-QoS/vertical-accuracy", HFILL }},
    { &hf_gsm_map_responseTime,
      { "responseTime", "gsm_map.responseTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "LCS-QoS/responseTime", HFILL }},
    { &hf_gsm_map_responseTimeCategory,
      { "responseTimeCategory", "gsm_map.responseTimeCategory",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ResponseTimeCategory_vals), 0,
        "ResponseTime/responseTimeCategory", HFILL }},
    { &hf_gsm_map_lcsCodewordString,
      { "lcsCodewordString", "gsm_map.lcsCodewordString",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LCSCodeword/lcsCodewordString", HFILL }},
    { &hf_gsm_map_callSessionUnrelated,
      { "callSessionUnrelated", "gsm_map.callSessionUnrelated",
        FT_UINT32, BASE_DEC, VALS(gsm_map_PrivacyCheckRelatedAction_vals), 0,
        "LCS-PrivacyCheck/callSessionUnrelated", HFILL }},
    { &hf_gsm_map_callSessionRelated,
      { "callSessionRelated", "gsm_map.callSessionRelated",
        FT_UINT32, BASE_DEC, VALS(gsm_map_PrivacyCheckRelatedAction_vals), 0,
        "LCS-PrivacyCheck/callSessionRelated", HFILL }},
    { &hf_gsm_map_areaDefinition,
      { "areaDefinition", "gsm_map.areaDefinition",
        FT_NONE, BASE_NONE, NULL, 0,
        "AreaEventInfo/areaDefinition", HFILL }},
    { &hf_gsm_map_occurrenceInfo,
      { "occurrenceInfo", "gsm_map.occurrenceInfo",
        FT_UINT32, BASE_DEC, VALS(gsm_map_OccurrenceInfo_vals), 0,
        "AreaEventInfo/occurrenceInfo", HFILL }},
    { &hf_gsm_map_intervalTime,
      { "intervalTime", "gsm_map.intervalTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AreaEventInfo/intervalTime", HFILL }},
    { &hf_gsm_map_areaList,
      { "areaList", "gsm_map.areaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AreaDefinition/areaList", HFILL }},
    { &hf_gsm_map_AreaList_item,
      { "Item", "gsm_map.AreaList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AreaList/_item", HFILL }},
    { &hf_gsm_map_areaType,
      { "areaType", "gsm_map.areaType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_AreaType_vals), 0,
        "Area/areaType", HFILL }},
    { &hf_gsm_map_areaIdentification,
      { "areaIdentification", "gsm_map.areaIdentification",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Area/areaIdentification", HFILL }},
    { &hf_gsm_map_locationEstimate,
      { "locationEstimate", "gsm_map.locationEstimate",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ageOfLocationEstimate,
      { "ageOfLocationEstimate", "gsm_map.ageOfLocationEstimate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_add_LocationEstimate,
      { "add-LocationEstimate", "gsm_map.add_LocationEstimate",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_deferredmt_lrResponseIndicator,
      { "deferredmt-lrResponseIndicator", "gsm_map.deferredmt_lrResponseIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProvideSubscriberLocation-Res/deferredmt-lrResponseIndicator", HFILL }},
    { &hf_gsm_map_geranPositioningData,
      { "geranPositioningData", "gsm_map.geranPositioningData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_utranPositioningData,
      { "utranPositioningData", "gsm_map.utranPositioningData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_cellIdOrSai,
      { "cellIdOrSai", "gsm_map.cellIdOrSai",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CellGlobalIdOrServiceAreaIdOrLAI_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_mlcNumber,
      { "mlcNumber", "gsm_map.mlcNumber",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RoutingInfoForLCS-Arg/mlcNumber", HFILL }},
    { &hf_gsm_map_targetMS,
      { "targetMS", "gsm_map.targetMS",
        FT_UINT32, BASE_DEC, VALS(gsm_map_SubscriberIdentity_vals), 0,
        "", HFILL }},
    { &hf_gsm_map_lcsLocationInfo,
      { "lcsLocationInfo", "gsm_map.lcsLocationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_ppr_Address,
      { "ppr-Address", "gsm_map.ppr_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RoutingInfoForLCS-Res/ppr-Address", HFILL }},
    { &hf_gsm_map_additional_v_gmlc_Address,
      { "additional-v-gmlc-Address", "gsm_map.additional_v_gmlc_Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RoutingInfoForLCS-Res/additional-v-gmlc-Address", HFILL }},
    { &hf_gsm_map_additional_LCS_CapabilitySets,
      { "additional-LCS-CapabilitySets", "gsm_map.additional_LCS_CapabilitySets",
        FT_BYTES, BASE_HEX, NULL, 0,
        "LCSLocationInfo/additional-LCS-CapabilitySets", HFILL }},
    { &hf_gsm_map_lcs_Event,
      { "lcs-Event", "gsm_map.lcs_Event",
        FT_UINT32, BASE_DEC, VALS(gsm_map_LCS_Event_vals), 0,
        "SubscriberLocationReport-Arg/lcs-Event", HFILL }},
    { &hf_gsm_map_na_ESRD,
      { "na-ESRD", "gsm_map.na_ESRD",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_na_ESRK,
      { "na-ESRK", "gsm_map.na_ESRK",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_slr_ArgExtensionContainer,
      { "slr-ArgExtensionContainer", "gsm_map.slr_ArgExtensionContainer",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubscriberLocationReport-Arg/slr-ArgExtensionContainer", HFILL }},
    { &hf_gsm_map_deferredmt_lrData,
      { "deferredmt-lrData", "gsm_map.deferredmt_lrData",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubscriberLocationReport-Arg/deferredmt-lrData", HFILL }},
    { &hf_gsm_map_pseudonymIndicator,
      { "pseudonymIndicator", "gsm_map.pseudonymIndicator",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubscriberLocationReport-Arg/pseudonymIndicator", HFILL }},
    { &hf_gsm_map_terminationCause,
      { "terminationCause", "gsm_map.terminationCause",
        FT_UINT32, BASE_DEC, VALS(gsm_map_TerminationCause_vals), 0,
        "Deferredmt-lrData/terminationCause", HFILL }},
    { &hf_gsm_map_securityHeader,
      { "securityHeader", "gsm_map.securityHeader",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_protectedPayload,
      { "protectedPayload", "gsm_map.protectedPayload",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_gsm_map_securityParametersIndex,
      { "securityParametersIndex", "gsm_map.securityParametersIndex",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SecurityHeader/securityParametersIndex", HFILL }},
    { &hf_gsm_map_originalComponentIdentifier,
      { "originalComponentIdentifier", "gsm_map.originalComponentIdentifier",
        FT_UINT32, BASE_DEC, VALS(gsm_map_OriginalComponentIdentifier_vals), 0,
        "SecurityHeader/originalComponentIdentifier", HFILL }},
    { &hf_gsm_map_initialisationVector,
      { "initialisationVector", "gsm_map.initialisationVector",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SecurityHeader/initialisationVector", HFILL }},
    { &hf_gsm_map_operationCode,
      { "operationCode", "gsm_map.operationCode",
        FT_UINT32, BASE_DEC, VALS(gsm_map_OperationCode_vals), 0,
        "OriginalComponentIdentifier/operationCode", HFILL }},
    { &hf_gsm_map_errorCode,
      { "errorCode", "gsm_map.errorCode",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ErrorCode_vals), 0,
        "OriginalComponentIdentifier/errorCode", HFILL }},
    { &hf_gsm_map_userInfo,
      { "userInfo", "gsm_map.userInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "OriginalComponentIdentifier/userInfo", HFILL }},
    { &hf_gsm_map_localValue,
      { "localValue", "gsm_map.localValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
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
        FT_UINT32, BASE_DEC, VALS(gsm_map_AbsentSubscriberReason_vals), 0,
        "AbsentSubscriberParam/absentSubscriberReason", HFILL }},
    { &hf_gsm_map_ccbs_Busy,
      { "ccbs-Busy", "gsm_map.ccbs_Busy",
        FT_NONE, BASE_NONE, NULL, 0,
        "BusySubscriberParam/ccbs-Busy", HFILL }},
    { &hf_gsm_map_gprsConnectionSuspended,
      { "gprsConnectionSuspended", "gsm_map.gprsConnectionSuspended",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubBusyForMT-SMS-Param/gprsConnectionSuspended", HFILL }},
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
        "ExtensibleCallBarredParam/unauthorisedMessageOriginator", HFILL }},
    { &hf_gsm_map_cug_RejectCause,
      { "cug-RejectCause", "gsm_map.cug_RejectCause",
        FT_UINT32, BASE_DEC, VALS(gsm_map_CUG_RejectCause_vals), 0,
        "CUG-RejectParam/cug-RejectCause", HFILL }},
    { &hf_gsm_map_sm_EnumeratedDeliveryFailureCause,
      { "sm-EnumeratedDeliveryFailureCause", "gsm_map.sm_EnumeratedDeliveryFailureCause",
        FT_UINT32, BASE_DEC, VALS(gsm_map_SM_EnumeratedDeliveryFailureCause_vals), 0,
        "SM-DeliveryFailureCause/sm-EnumeratedDeliveryFailureCause", HFILL }},
    { &hf_gsm_map_diagnosticInfo,
      { "diagnosticInfo", "gsm_map.diagnosticInfo",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SM-DeliveryFailureCause/diagnosticInfo", HFILL }},
    { &hf_gsm_map_unauthorizedLCSClient_Diagnostic,
      { "unauthorizedLCSClient-Diagnostic", "gsm_map.unauthorizedLCSClient_Diagnostic",
        FT_UINT32, BASE_DEC, VALS(gsm_map_T_unauthorizedLCSClient_Diagnostic_vals), 0,
        "UnauthorizedLCSClient-Param/unauthorizedLCSClient-Diagnostic", HFILL }},
    { &hf_gsm_map_positionMethodFailure_Diagnostic,
      { "positionMethodFailure-Diagnostic", "gsm_map.positionMethodFailure_Diagnostic",
        FT_UINT32, BASE_DEC, VALS(gsm_map_PositionMethodFailure_Diagnostic_vals), 0,
        "PositionMethodFailure-Param/positionMethodFailure-Diagnostic", HFILL }},
    { &hf_gsm_map_pcsExtensions,
      { "pcsExtensions", "gsm_map.pcsExtensions",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtensionContainer/pcsExtensions", HFILL }},
    { &hf_gsm_map_access,
      { "access", "gsm_map.access",
        FT_UINT32, BASE_DEC, VALS(gsm_map_Access_vals), 0,
        "AccessTypePriv/access", HFILL }},
    { &hf_gsm_map_version,
      { "version", "gsm_map.version",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AccessTypePriv/version", HFILL }},
    { &hf_gsm_map_SupportedCamelPhases_phase1,
      { "phase1", "gsm_map.phase1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_SupportedCamelPhases_phase2,
      { "phase2", "gsm_map.phase2",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_SupportedCamelPhases_phase3,
      { "phase3", "gsm_map.phase3",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_SupportedCamelPhases_phase4,
      { "phase4", "gsm_map.phase4",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_SupportedLCS_CapabilitySets_lcsCapabilitySet1,
      { "lcsCapabilitySet1", "gsm_map.lcsCapabilitySet1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_SupportedLCS_CapabilitySets_lcsCapabilitySet2,
      { "lcsCapabilitySet2", "gsm_map.lcsCapabilitySet2",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_SupportedLCS_CapabilitySets_lcsCapabilitySet3,
      { "lcsCapabilitySet3", "gsm_map.lcsCapabilitySet3",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_SupportedLCS_CapabilitySets_lcsCapabilitySet4,
      { "lcsCapabilitySet4", "gsm_map.lcsCapabilitySet4",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_RequestedEquipmentInfo_equipmentStatus,
      { "equipmentStatus", "gsm_map.equipmentStatus",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_RequestedEquipmentInfo_bmuef,
      { "bmuef", "gsm_map.bmuef",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_allOG_CallsBarred,
      { "allOG-CallsBarred", "gsm_map.allOG-CallsBarred",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_internationalOGCallsBarred,
      { "internationalOGCallsBarred", "gsm_map.internationalOGCallsBarred",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_internationalOGCallsNotToHPLMN_CountryBarred,
      { "internationalOGCallsNotToHPLMN-CountryBarred", "gsm_map.internationalOGCallsNotToHPLMN-CountryBarred",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_interzonalOGCallsBarred,
      { "interzonalOGCallsBarred", "gsm_map.interzonalOGCallsBarred",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_interzonalOGCallsNotToHPLMN_CountryBarred,
      { "interzonalOGCallsNotToHPLMN-CountryBarred", "gsm_map.interzonalOGCallsNotToHPLMN-CountryBarred",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_interzonalOGCallsAndInternationalOGCallsNotToHPLMN_CountryBarred,
      { "interzonalOGCallsAndInternationalOGCallsNotToHPLMN-CountryBarred", "gsm_map.interzonalOGCallsAndInternationalOGCallsNotToHPLMN-CountryBarred",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_premiumRateInformationOGCallsBarred,
      { "premiumRateInformationOGCallsBarred", "gsm_map.premiumRateInformationOGCallsBarred",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_premiumRateEntertainementOGCallsBarred,
      { "premiumRateEntertainementOGCallsBarred", "gsm_map.premiumRateEntertainementOGCallsBarred",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_ss_AccessBarred,
      { "ss-AccessBarred", "gsm_map.ss-AccessBarred",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_allECT_Barred,
      { "allECT-Barred", "gsm_map.allECT-Barred",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_chargeableECT_Barred,
      { "chargeableECT-Barred", "gsm_map.chargeableECT-Barred",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_internationalECT_Barred,
      { "internationalECT-Barred", "gsm_map.internationalECT-Barred",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_interzonalECT_Barred,
      { "interzonalECT-Barred", "gsm_map.interzonalECT-Barred",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_doublyChargeableECT_Barred,
      { "doublyChargeableECT-Barred", "gsm_map.doublyChargeableECT-Barred",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_multipleECT_Barred,
      { "multipleECT-Barred", "gsm_map.multipleECT-Barred",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_allPacketOrientedServicesBarred,
      { "allPacketOrientedServicesBarred", "gsm_map.allPacketOrientedServicesBarred",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_roamerAccessToHPLMN_AP_Barred,
      { "roamerAccessToHPLMN-AP-Barred", "gsm_map.roamerAccessToHPLMN-AP-Barred",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_roamerAccessToVPLMN_AP_Barred,
      { "roamerAccessToVPLMN-AP-Barred", "gsm_map.roamerAccessToVPLMN-AP-Barred",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_roamingOutsidePLMNOG_CallsBarred,
      { "roamingOutsidePLMNOG-CallsBarred", "gsm_map.roamingOutsidePLMNOG-CallsBarred",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_allIC_CallsBarred,
      { "allIC-CallsBarred", "gsm_map.allIC-CallsBarred",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_roamingOutsidePLMNIC_CallsBarred,
      { "roamingOutsidePLMNIC-CallsBarred", "gsm_map.roamingOutsidePLMNIC-CallsBarred",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_roamingOutsidePLMNICountryIC_CallsBarred,
      { "roamingOutsidePLMNICountryIC-CallsBarred", "gsm_map.roamingOutsidePLMNICountryIC-CallsBarred",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_roamingOutsidePLMN_Barred,
      { "roamingOutsidePLMN-Barred", "gsm_map.roamingOutsidePLMN-Barred",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_roamingOutsidePLMN_CountryBarred,
      { "roamingOutsidePLMN-CountryBarred", "gsm_map.roamingOutsidePLMN-CountryBarred",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_registrationAllCF_Barred,
      { "registrationAllCF-Barred", "gsm_map.registrationAllCF-Barred",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_registrationCFNotToHPLMN_Barred,
      { "registrationCFNotToHPLMN-Barred", "gsm_map.registrationCFNotToHPLMN-Barred",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_registrationInterzonalCF_Barred,
      { "registrationInterzonalCF-Barred", "gsm_map.registrationInterzonalCF-Barred",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_registrationInterzonalCFNotToHPLMN_Barred,
      { "registrationInterzonalCFNotToHPLMN-Barred", "gsm_map.registrationInterzonalCFNotToHPLMN-Barred",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_ODB_GeneralData_registrationInternationalCF_Barred,
      { "registrationInternationalCF-Barred", "gsm_map.registrationInternationalCF-Barred",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_gsm_map_ODB_HPLMN_Data_plmn_SpecificBarringType1,
      { "plmn-SpecificBarringType1", "gsm_map.plmn-SpecificBarringType1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_ODB_HPLMN_Data_plmn_SpecificBarringType2,
      { "plmn-SpecificBarringType2", "gsm_map.plmn-SpecificBarringType2",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_ODB_HPLMN_Data_plmn_SpecificBarringType3,
      { "plmn-SpecificBarringType3", "gsm_map.plmn-SpecificBarringType3",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_ODB_HPLMN_Data_plmn_SpecificBarringType4,
      { "plmn-SpecificBarringType4", "gsm_map.plmn-SpecificBarringType4",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_AccessRestrictionData_utranNotAllowed,
      { "utranNotAllowed", "gsm_map.utranNotAllowed",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_AccessRestrictionData_geranNotAllowed,
      { "geranNotAllowed", "gsm_map.geranNotAllowed",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_o_csi,
      { "o-csi", "gsm_map.o-csi",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_ss_csi,
      { "ss-csi", "gsm_map.ss-csi",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_tif_csi,
      { "tif-csi", "gsm_map.tif-csi",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_d_csi,
      { "d-csi", "gsm_map.d-csi",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_vt_csi,
      { "vt-csi", "gsm_map.vt-csi",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_mo_sms_csi,
      { "mo-sms-csi", "gsm_map.mo-sms-csi",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_m_csi,
      { "m-csi", "gsm_map.m-csi",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_gprs_csi,
      { "gprs-csi", "gsm_map.gprs-csi",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_t_csi,
      { "t-csi", "gsm_map.t-csi",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_mt_sms_csi,
      { "mt-sms-csi", "gsm_map.mt-sms-csi",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_mg_csi,
      { "mg-csi", "gsm_map.mg-csi",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_o_IM_CSI,
      { "o-IM-CSI", "gsm_map.o-IM-CSI",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_d_IM_CSI,
      { "d-IM-CSI", "gsm_map.d-IM-CSI",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_gsm_map_SpecificCSI_Withdraw_vt_IM_CSI,
      { "vt-IM-CSI", "gsm_map.vt-IM-CSI",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_gsm_map_AllowedServices_firstServiceAllowed,
      { "firstServiceAllowed", "gsm_map.firstServiceAllowed",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_AllowedServices_secondServiceAllowed,
      { "secondServiceAllowed", "gsm_map.secondServiceAllowed",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_ServiceIndicator_clir_invoked,
      { "clir-invoked", "gsm_map.clir-invoked",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_ServiceIndicator_camel_invoked,
      { "camel-invoked", "gsm_map.camel-invoked",
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
    { &hf_gsm_map_OfferedCamel4CSIs_o_csi,
      { "o-csi", "gsm_map.o-csi",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4CSIs_d_csi,
      { "d-csi", "gsm_map.d-csi",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4CSIs_vt_csi,
      { "vt-csi", "gsm_map.vt-csi",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4CSIs_t_csi,
      { "t-csi", "gsm_map.t-csi",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4CSIs_mt_sms_csi,
      { "mt-sms-csi", "gsm_map.mt-sms-csi",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4CSIs_mg_csi,
      { "mg-csi", "gsm_map.mg-csi",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4CSIs_psi_enhancements,
      { "psi-enhancements", "gsm_map.psi-enhancements",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_initiateCallAttempt,
      { "initiateCallAttempt", "gsm_map.initiateCallAttempt",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_splitLeg,
      { "splitLeg", "gsm_map.splitLeg",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_moveLeg,
      { "moveLeg", "gsm_map.moveLeg",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_disconnectLeg,
      { "disconnectLeg", "gsm_map.disconnectLeg",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_entityReleased,
      { "entityReleased", "gsm_map.entityReleased",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_dfc_WithArgument,
      { "dfc-WithArgument", "gsm_map.dfc-WithArgument",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_playTone,
      { "playTone", "gsm_map.playTone",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_dtmf_MidCall,
      { "dtmf-MidCall", "gsm_map.dtmf-MidCall",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_chargingIndicator,
      { "chargingIndicator", "gsm_map.chargingIndicator",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_alertingDP,
      { "alertingDP", "gsm_map.alertingDP",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_locationAtAlerting,
      { "locationAtAlerting", "gsm_map.locationAtAlerting",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_changeOfPositionDP,
      { "changeOfPositionDP", "gsm_map.changeOfPositionDP",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_or_Interactions,
      { "or-Interactions", "gsm_map.or-Interactions",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_warningToneEnhancements,
      { "warningToneEnhancements", "gsm_map.warningToneEnhancements",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_cf_Enhancements,
      { "cf-Enhancements", "gsm_map.cf-Enhancements",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_subscribedEnhancedDialledServices,
      { "subscribedEnhancedDialledServices", "gsm_map.subscribedEnhancedDialledServices",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_servingNetworkEnhancedDialledServices,
      { "servingNetworkEnhancedDialledServices", "gsm_map.servingNetworkEnhancedDialledServices",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_criteriaForChangeOfPositionDP,
      { "criteriaForChangeOfPositionDP", "gsm_map.criteriaForChangeOfPositionDP",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_OfferedCamel4Functionalities_serviceChangeDP,
      { "serviceChangeDP", "gsm_map.serviceChangeDP",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_DeferredLocationEventType_msAvailable,
      { "msAvailable", "gsm_map.msAvailable",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_DeferredLocationEventType_enteringIntoArea,
      { "enteringIntoArea", "gsm_map.enteringIntoArea",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_DeferredLocationEventType_leavingFromArea,
      { "leavingFromArea", "gsm_map.leavingFromArea",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_DeferredLocationEventType_beingInsideArea,
      { "beingInsideArea", "gsm_map.beingInsideArea",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_SupportedGADShapes_ellipsoidPoint,
      { "ellipsoidPoint", "gsm_map.ellipsoidPoint",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_gsm_map_SupportedGADShapes_ellipsoidPointWithUncertaintyCircle,
      { "ellipsoidPointWithUncertaintyCircle", "gsm_map.ellipsoidPointWithUncertaintyCircle",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_gsm_map_SupportedGADShapes_ellipsoidPointWithUncertaintyEllipse,
      { "ellipsoidPointWithUncertaintyEllipse", "gsm_map.ellipsoidPointWithUncertaintyEllipse",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_gsm_map_SupportedGADShapes_polygon,
      { "polygon", "gsm_map.polygon",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_gsm_map_SupportedGADShapes_ellipsoidPointWithAltitude,
      { "ellipsoidPointWithAltitude", "gsm_map.ellipsoidPointWithAltitude",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_gsm_map_SupportedGADShapes_ellipsoidPointWithAltitudeAndUncertaintyElipsoid,
      { "ellipsoidPointWithAltitudeAndUncertaintyElipsoid", "gsm_map.ellipsoidPointWithAltitudeAndUncertaintyElipsoid",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_gsm_map_SupportedGADShapes_ellipsoidArc,
      { "ellipsoidArc", "gsm_map.ellipsoidArc",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},

/*--- End of included file: packet-gsm_map-hfarr.c ---*/
#line 2205 "packet-gsm_map-template.c"
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
	&ett_gsm_map_ext_qos_subscribed,
	&ett_gsm_map_pdptypenumber,
	&ett_gsm_map_RAIdentity,
	&ett_gsm_map_LAIFixedLength,
	&ett_gsm_map_isdn_address_string,
	&ett_gsm_map_geo_desc,


/*--- Included file: packet-gsm_map-ettarr.c ---*/
#line 1 "packet-gsm_map-ettarr.c"
    &ett_gsm_map_Component,
    &ett_gsm_map_Invoke,
    &ett_gsm_map_ReturnResult,
    &ett_gsm_map_T_resultretres,
    &ett_gsm_map_ReturnError,
    &ett_gsm_map_Reject,
    &ett_gsm_map_T_invokeIDRej,
    &ett_gsm_map_T_problem,
    &ett_gsm_map_OPERATION,
    &ett_gsm_map_ERROR,
    &ett_gsm_map_Bss_APDU,
    &ett_gsm_map_SupportedCamelPhases,
    &ett_gsm_map_UpdateLocationArg,
    &ett_gsm_map_UpdateLocationRes,
    &ett_gsm_map_VLR_Capability,
    &ett_gsm_map_SuperChargerInfo,
    &ett_gsm_map_SupportedLCS_CapabilitySets,
    &ett_gsm_map_ADD_Info,
    &ett_gsm_map_PrivateExtensionList,
    &ett_gsm_map_PrivateExtension,
    &ett_gsm_map_SLR_ArgExtensionContainer,
    &ett_gsm_map_PcsExtensions,
    &ett_gsm_map_SLR_Arg_PCS_Extensions,
    &ett_gsm_map_CancelLocationArg,
    &ett_gsm_map_CancelLocationArgV2,
    &ett_gsm_map_CancelLocationRes,
    &ett_gsm_map_PurgeMSArg,
    &ett_gsm_map_PurgeMSRes,
    &ett_gsm_map_SendIdentificationArg,
    &ett_gsm_map_SendIdentificationRes,
    &ett_gsm_map_AuthenticationSetList,
    &ett_gsm_map_TripletList,
    &ett_gsm_map_QuintupletList,
    &ett_gsm_map_AuthenticationTriplet,
    &ett_gsm_map_AuthenticationQuintuplet,
    &ett_gsm_map_CurrentSecurityContext,
    &ett_gsm_map_GSM_SecurityContextData,
    &ett_gsm_map_UMTS_SecurityContextData,
    &ett_gsm_map_PrepareHO_Arg,
    &ett_gsm_map_PrepareHO_ArgV3,
    &ett_gsm_map_BSSMAP_ServiceHandoverList,
    &ett_gsm_map_BSSMAP_ServiceHandoverInfo,
    &ett_gsm_map_RadioResourceList,
    &ett_gsm_map_RadioResource,
    &ett_gsm_map_PrepareHO_Res,
    &ett_gsm_map_PrepareHO_ResV3,
    &ett_gsm_map_SelectedUMTS_Algorithms,
    &ett_gsm_map_ChosenRadioResourceInformation,
    &ett_gsm_map_SendEndSignalArgV3,
    &ett_gsm_map_SendEndSignalRes,
    &ett_gsm_map_RelocationNumberList,
    &ett_gsm_map_RelocationNumber,
    &ett_gsm_map_ProcessAccessSignallingArgV3,
    &ett_gsm_map_SupportedCodecsList,
    &ett_gsm_map_CodecList,
    &ett_gsm_map_ForwardAccessSignallingArgV3,
    &ett_gsm_map_AllowedUMTS_Algorithms,
    &ett_gsm_map_PrepareSubsequentHOArg,
    &ett_gsm_map_PrepareSubsequentHOArgV3,
    &ett_gsm_map_PrepareSubsequentHOResV3,
    &ett_gsm_map_SendAuthenticationInfoArgV2,
    &ett_gsm_map_SendAuthenticationInfoRes,
    &ett_gsm_map_SendAuthenticationInfoRes_item,
    &ett_gsm_map_SendAuthenticationInfoResV3,
    &ett_gsm_map_Re_synchronisationInfo,
    &ett_gsm_map_CheckIMEIArgV3,
    &ett_gsm_map_CheckIMEIRes,
    &ett_gsm_map_RequestedEquipmentInfo,
    &ett_gsm_map_UESBI_Iu,
    &ett_gsm_map_BasicService,
    &ett_gsm_map_BasicServiceGroupList,
    &ett_gsm_map_ODB_GeneralData,
    &ett_gsm_map_ODB_HPLMN_Data,
    &ett_gsm_map_BcsmCamelTDPData,
    &ett_gsm_map_BcsmCamelTDPDataList,
    &ett_gsm_map_O_CSI,
    &ett_gsm_map_O_BcsmCamelTDPDataList,
    &ett_gsm_map_O_BcsmCamelTDPData,
    &ett_gsm_map_InsertSubscriberDataArg,
    &ett_gsm_map_AccessRestrictionData,
    &ett_gsm_map_LCSInformation,
    &ett_gsm_map_GMLC_List,
    &ett_gsm_map_GPRSDataList,
    &ett_gsm_map_PDP_Context,
    &ett_gsm_map_GPRSSubscriptionData,
    &ett_gsm_map_SGSN_CAMEL_SubscriptionInfo,
    &ett_gsm_map_GPRS_CSI,
    &ett_gsm_map_GPRS_CamelTDPDataList,
    &ett_gsm_map_GPRS_CamelTDPData,
    &ett_gsm_map_LSADataList,
    &ett_gsm_map_LSAData,
    &ett_gsm_map_LSAInformation,
    &ett_gsm_map_InsertSubscriberDataRes,
    &ett_gsm_map_DeleteSubscriberDataArg,
    &ett_gsm_map_DeleteSubscriberDataRes,
    &ett_gsm_map_SpecificCSI_Withdraw,
    &ett_gsm_map_GPRSSubscriptionDataWithdraw,
    &ett_gsm_map_ContextIdList,
    &ett_gsm_map_LSAInformationWithdraw,
    &ett_gsm_map_LSAIdentityList,
    &ett_gsm_map_BasicServiceList,
    &ett_gsm_map_VlrCamelSubscriptionInfo,
    &ett_gsm_map_MT_smsCAMELTDP_CriteriaList,
    &ett_gsm_map_MT_smsCAMELTDP_Criteria,
    &ett_gsm_map_TPDU_TypeCriterion,
    &ett_gsm_map_D_CSI,
    &ett_gsm_map_DP_AnalysedInfoCriteriaList,
    &ett_gsm_map_DP_AnalysedInfoCriterium,
    &ett_gsm_map_SS_CSI,
    &ett_gsm_map_SS_CamelData,
    &ett_gsm_map_MG_CSI,
    &ett_gsm_map_BearerServiceList,
    &ett_gsm_map_TeleserviceList,
    &ett_gsm_map_Ext_SS_InfoList,
    &ett_gsm_map_Ext_SS_Info,
    &ett_gsm_map_Ext_ForwInfo,
    &ett_gsm_map_Ext_ForwFeatureList,
    &ett_gsm_map_Ext_ForwFeature,
    &ett_gsm_map_Ext_CallBarInfo,
    &ett_gsm_map_Ext_CallBarFeatureList,
    &ett_gsm_map_Ext_CallBarringFeature,
    &ett_gsm_map_ZoneCodeList,
    &ett_gsm_map_EMLPP_Info,
    &ett_gsm_map_CUG_Info,
    &ett_gsm_map_CUG_SubscriptionList,
    &ett_gsm_map_CUG_Subscription,
    &ett_gsm_map_CUG_FeatureList,
    &ett_gsm_map_Ext_BasicServiceGroupList,
    &ett_gsm_map_CUG_Feature,
    &ett_gsm_map_Ext_SS_Data,
    &ett_gsm_map_LCS_PrivacyExceptionList,
    &ett_gsm_map_LCS_PrivacyClass,
    &ett_gsm_map_ExternalClientList,
    &ett_gsm_map_PLMNClientList,
    &ett_gsm_map_Ext_ExternalClientList,
    &ett_gsm_map_ExternalClient,
    &ett_gsm_map_ServiceTypeList,
    &ett_gsm_map_ServiceType,
    &ett_gsm_map_MOLR_List,
    &ett_gsm_map_MOLR_Class,
    &ett_gsm_map_CallBarringFeatureList,
    &ett_gsm_map_CallBarringFeature,
    &ett_gsm_map_ForwardingFeatureList,
    &ett_gsm_map_ForwardingFeature,
    &ett_gsm_map_DestinationNumberCriteria,
    &ett_gsm_map_DestinationNumberList,
    &ett_gsm_map_DestinationNumberLengthList,
    &ett_gsm_map_ForwardingInfo,
    &ett_gsm_map_CallBarringInfo,
    &ett_gsm_map_MC_SS_Info,
    &ett_gsm_map_ResetArg,
    &ett_gsm_map_RestoreDataArg,
    &ett_gsm_map_RestoreDataRes,
    &ett_gsm_map_VBSDataList,
    &ett_gsm_map_VGCSDataList,
    &ett_gsm_map_VoiceGroupCallData,
    &ett_gsm_map_VoiceBroadcastData,
    &ett_gsm_map_ActivateTraceModeArg,
    &ett_gsm_map_ActivateTraceModeRes,
    &ett_gsm_map_DeactivateTraceModeArg,
    &ett_gsm_map_DeactivateTraceModeRes,
    &ett_gsm_map_SendRoutingInfoArg,
    &ett_gsm_map_SendRoutingInfoRes,
    &ett_gsm_map_ExternalSignalInfo,
    &ett_gsm_map_Ext_ExternalSignalInfo,
    &ett_gsm_map_AccessNetworkSignalInfo,
    &ett_gsm_map_CamelInfo,
    &ett_gsm_map_Identity,
    &ett_gsm_map_IMSI_WithLMSI,
    &ett_gsm_map_SubscriberId,
    &ett_gsm_map_HLR_List,
    &ett_gsm_map_SS_List,
    &ett_gsm_map_NAEA_PreferredCI,
    &ett_gsm_map_SubscriberIdentity,
    &ett_gsm_map_LCSClientExternalID,
    &ett_gsm_map_CellGlobalIdOrServiceAreaIdOrLAI,
    &ett_gsm_map_AllowedServices,
    &ett_gsm_map_CCBS_Indicators,
    &ett_gsm_map_RoutingInfo,
    &ett_gsm_map_ExtendedRoutingInfo,
    &ett_gsm_map_CamelRoutingInfo,
    &ett_gsm_map_GmscCamelSubscriptionInfo,
    &ett_gsm_map_LocationInformation,
    &ett_gsm_map_LocationInformationGPRS,
    &ett_gsm_map_SubscriberState,
    &ett_gsm_map_PS_SubscriberState,
    &ett_gsm_map_PDP_ContextInfoList,
    &ett_gsm_map_PDP_ContextInfo,
    &ett_gsm_map_CUG_CheckInfo,
    &ett_gsm_map_ForwardingData,
    &ett_gsm_map_ProvideRoamingNumberArg,
    &ett_gsm_map_ProvideRoamingNumberRes,
    &ett_gsm_map_ResumeCallHandlingArg,
    &ett_gsm_map_ResumeCallHandlingRes,
    &ett_gsm_map_UU_Data,
    &ett_gsm_map_ProvideSIWFSNumberArg,
    &ett_gsm_map_ProvideSIWFSNumberRes,
    &ett_gsm_map_SIWFSSignallingModifyArg,
    &ett_gsm_map_SIWFSSignallingModifyRes,
    &ett_gsm_map_SetReportingStateArg,
    &ett_gsm_map_SetReportingStateRes,
    &ett_gsm_map_StatusReportArg,
    &ett_gsm_map_StatusReportRes,
    &ett_gsm_map_EventReportData,
    &ett_gsm_map_CallReportData,
    &ett_gsm_map_IST_AlertArg,
    &ett_gsm_map_IST_AlertRes,
    &ett_gsm_map_IST_CommandArg,
    &ett_gsm_map_IST_CommandRes,
    &ett_gsm_map_ReleaseResourcesArg,
    &ett_gsm_map_ReleaseResourcesRes,
    &ett_gsm_map_RemoteUserFreeArg,
    &ett_gsm_map_RemoteUserFreeRes,
    &ett_gsm_map_SS_Data,
    &ett_gsm_map_SS_SubscriptionOption,
    &ett_gsm_map_RegisterSS_Arg,
    &ett_gsm_map_SS_Info,
    &ett_gsm_map_InterrogateSS_Res,
    &ett_gsm_map_Ussd_Arg,
    &ett_gsm_map_Ussd_Res,
    &ett_gsm_map_AuthenticationFailureReportArg,
    &ett_gsm_map_AuthenticationFailureReportRes,
    &ett_gsm_map_RegisterCC_EntryArg,
    &ett_gsm_map_RegisterCC_EntryRes,
    &ett_gsm_map_CCBS_Data,
    &ett_gsm_map_ServiceIndicator,
    &ett_gsm_map_EraseCC_EntryArg,
    &ett_gsm_map_EraseCC_EntryRes,
    &ett_gsm_map_RoutingInfoForSMArg,
    &ett_gsm_map_RoutingInfoForSM_Res,
    &ett_gsm_map_LocationInfoWithLMSI,
    &ett_gsm_map_Additional_Number,
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
    &ett_gsm_map_SubscriberInfo,
    &ett_gsm_map_MNPInfoRes,
    &ett_gsm_map_GPRSMSClass,
    &ett_gsm_map_RequestedInfo,
    &ett_gsm_map_AnyTimeInterrogationArg,
    &ett_gsm_map_AnyTimeInterrogationRes,
    &ett_gsm_map_AnyTimeSubscriptionInterrogationArg,
    &ett_gsm_map_AnyTimeSubscriptionInterrogationRes,
    &ett_gsm_map_RequestedSubscriptionInfo,
    &ett_gsm_map_CallForwardingData,
    &ett_gsm_map_CallBarringData,
    &ett_gsm_map_BasicServiceCode,
    &ett_gsm_map_O_BcsmCamelTDPCriteriaList,
    &ett_gsm_map_T_BCSM_CAMEL_TDP_CriteriaList,
    &ett_gsm_map_O_BcsmCamelTDP_Criteria,
    &ett_gsm_map_T_BCSM_CAMEL_TDP_Criteria,
    &ett_gsm_map_OfferedCamel4CSIs,
    &ett_gsm_map_OfferedCamel4Functionalities,
    &ett_gsm_map_SS_ForBS_Code,
    &ett_gsm_map_GenericServiceInfo,
    &ett_gsm_map_CCBS_FeatureList,
    &ett_gsm_map_CCBS_Feature,
    &ett_gsm_map_T_CauseValueCriteria,
    &ett_gsm_map_O_CauseValueCriteria,
    &ett_gsm_map_BasicServiceCriteria,
    &ett_gsm_map_AnyTimeModificationArg,
    &ett_gsm_map_AnyTimeModificationRes,
    &ett_gsm_map_ModificationRequestFor_CF_Info,
    &ett_gsm_map_ModificationRequestFor_CB_Info,
    &ett_gsm_map_ModificationRequestFor_ODB_data,
    &ett_gsm_map_ModificationRequestFor_CSI,
    &ett_gsm_map_Ext_SS_InfoFor_CSE,
    &ett_gsm_map_NoteSubscriberDataModifiedArg,
    &ett_gsm_map_NoteSubscriberDataModifiedRes,
    &ett_gsm_map_NoteMM_EventArg,
    &ett_gsm_map_NoteMM_EventRes,
    &ett_gsm_map_CAMEL_SubscriptionInfo,
    &ett_gsm_map_Ext_ForwardingInfoFor_CSE,
    &ett_gsm_map_Ext_BasicServiceCode,
    &ett_gsm_map_Ext_CallBarringInfoFor_CSE,
    &ett_gsm_map_ODB_Info,
    &ett_gsm_map_ODB_Data,
    &ett_gsm_map_M_CSI,
    &ett_gsm_map_SS_EventList,
    &ett_gsm_map_T_CSI,
    &ett_gsm_map_T_BcsmCamelTDPDataList,
    &ett_gsm_map_T_BcsmCamelTDPData,
    &ett_gsm_map_SMS_CSI,
    &ett_gsm_map_SMS_CAMEL_TDP_DataList,
    &ett_gsm_map_SMS_CAMEL_TDP_Data,
    &ett_gsm_map_MobilityTriggers,
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
    &ett_gsm_map_UpdateGprsLocationRes,
    &ett_gsm_map_SGSN_Capability,
    &ett_gsm_map_SendRoutingInfoForGprsArg,
    &ett_gsm_map_SendRoutingInfoForGprsRes,
    &ett_gsm_map_FailureReportArg,
    &ett_gsm_map_FailureReportRes,
    &ett_gsm_map_NoteMsPresentForGprsArg,
    &ett_gsm_map_NoteMsPresentForGprsRes,
    &ett_gsm_map_ProvideSubscriberLocation_Arg,
    &ett_gsm_map_LocationType,
    &ett_gsm_map_DeferredLocationEventType,
    &ett_gsm_map_LCS_ClientID,
    &ett_gsm_map_LCSClientName,
    &ett_gsm_map_LCSRequestorID,
    &ett_gsm_map_LCS_QoS,
    &ett_gsm_map_ResponseTime,
    &ett_gsm_map_SupportedGADShapes,
    &ett_gsm_map_LCSCodeword,
    &ett_gsm_map_LCS_PrivacyCheck,
    &ett_gsm_map_AreaEventInfo,
    &ett_gsm_map_AreaDefinition,
    &ett_gsm_map_AreaList,
    &ett_gsm_map_Area,
    &ett_gsm_map_ProvideSubscriberLocation_Res,
    &ett_gsm_map_TargetMS,
    &ett_gsm_map_RoutingInfoForLCS_Arg,
    &ett_gsm_map_RoutingInfoForLCS_Res,
    &ett_gsm_map_LCSLocationInfo,
    &ett_gsm_map_SubscriberLocationReport_Arg,
    &ett_gsm_map_Deferredmt_lrData,
    &ett_gsm_map_SubscriberLocationReport_Res,
    &ett_gsm_map_SecureTransportArg,
    &ett_gsm_map_SecureTransportRes,
    &ett_gsm_map_SecurityHeader,
    &ett_gsm_map_OriginalComponentIdentifier,
    &ett_gsm_map_OperationCode,
    &ett_gsm_map_ErrorCode,
    &ett_gsm_map_SystemFailureParam,
    &ett_gsm_map_T_extensibleSystemFailureParam,
    &ett_gsm_map_DataMissingParam,
    &ett_gsm_map_UnexpectedDataParam,
    &ett_gsm_map_FacilityNotSupParam,
    &ett_gsm_map_OR_NotAllowedParam,
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
    &ett_gsm_map_ForwardingViolationParam,
    &ett_gsm_map_ForwardingFailedParam,
    &ett_gsm_map_ATI_NotAllowedParam,
    &ett_gsm_map_ATSI_NotAllowedParam,
    &ett_gsm_map_ATM_NotAllowedParam,
    &ett_gsm_map_IllegalSS_OperationParam,
    &ett_gsm_map_SS_NotAvailableParam,
    &ett_gsm_map_SS_SubscriptionViolationParam,
    &ett_gsm_map_InformationNotAvailableParam,
    &ett_gsm_map_SubBusyForMT_SMS_Param,
    &ett_gsm_map_CallBarredParam,
    &ett_gsm_map_ExtensibleCallBarredParam,
    &ett_gsm_map_CUG_RejectParam,
    &ett_gsm_map_Or_NotAllowedParam,
    &ett_gsm_map_NoGroupCallNbParam,
    &ett_gsm_map_SS_IncompatibilityCause,
    &ett_gsm_map_ShortTermDenialParam,
    &ett_gsm_map_LongTermDenialParam,
    &ett_gsm_map_SM_DeliveryFailureCause,
    &ett_gsm_map_MessageWaitListFullParam,
    &ett_gsm_map_AbsentSubscriberSM_Param,
    &ett_gsm_map_UnauthorizedRequestingNetwork_Param,
    &ett_gsm_map_UnauthorizedLCSClient_Param,
    &ett_gsm_map_PositionMethodFailure_Param,
    &ett_gsm_map_UnknownOrUnreachableLCSClient_Param,
    &ett_gsm_map_MM_EventNotSupported_Param,
    &ett_gsm_map_TargetCellOutsideGCA_Param,
    &ett_gsm_map_SecureTransportErrorParam,
    &ett_gsm_map_ExtensionContainer,
    &ett_gsm_map_AccessTypePriv,

/*--- End of included file: packet-gsm_map-ettarr.c ---*/
#line 2225 "packet-gsm_map-template.c"
  };

  /* Register protocol */
  proto_gsm_map = proto_register_protocol(PNAME, PSNAME, PFNAME);
/*XXX  register_dissector("gsm_map", dissect_gsm_map, proto_gsm_map);*/
  /* Register fields and subtrees */
  proto_register_field_array(proto_gsm_map, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  sms_dissector_table = register_dissector_table("gsm_map.sms_tpdu", 
						 "GSM SMS TPDU", FT_UINT8,
						 BASE_DEC);

  gsm_map_tap = register_tap("gsm_map");

/* #include "packet-gsm_map-dis-tab.c" */
  register_ber_oid_name("1.2.826.0.1249.58.1.0","iso(1) member-body(2) bsi(826) disc(0) ericsson(1249) gsmNetworkApplicationsDefinition(58) gsm-Map(1) gsm-Map-Ext(0)" );
  register_ber_oid_name("1.3.12.2.1107.3.66.1.2","accessTypeNotAllowed-id" );
  /*register_ber_oid_name("0.4.0.0.1.0.1.3","itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) map-ac(0) networkLocUp(1) version3(3)" );
   *
   * Register our configuration options, particularly our ssn:s
   * Set default SSNs
   */
  range_convert_str(&global_ssn_range, "6-9", MAX_SSN);
  ssn_range = range_empty();


  gsm_map_module = prefs_register_protocol(proto_gsm_map, proto_reg_handoff_gsm_map);

  prefs_register_range_preference(gsm_map_module, "tcap.ssn", "TCAP SSNs",
				  "TCAP Subsystem numbers used for GSM MAP",
				  &global_ssn_range, MAX_SSN);
}


