/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-HI2Operations.c                                                     */
/* ../../tools/asn2wrs.py -b -p HI2Operations -c ./HI2Operations.cnf -s ./packet-HI2Operations-template -D . -O ../../epan/dissectors HI2Operations_ver11.asn UmtsHI2Operations.asn TS101909201.asn PCESP.asn EN301040.asn */

/* Input file: packet-HI2Operations-template.c */

#line 1 "../../asn1/HI2Operations/packet-HI2Operations-template.c"
/* packet-HI2Operations.c
 * Routines for HI2 (ETSI TS 101 671 V3.5.1 (2009-11))
 *  Erwin van Eijk 2010
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"

#define PNAME  "HI2Operations"
#define PSNAME "HI2OPERATIONS"
#define PFNAME "hi2operations"

/* Initialize the protocol and registered fields */
int proto_HI2Operations = -1;

/*--- Included file: packet-HI2Operations-hf.c ---*/
#line 1 "../../asn1/HI2Operations/packet-HI2Operations-hf.c"
static int hf_HI2Operations_IRIsContent_PDU = -1;  /* IRIsContent */
static int hf_HI2Operations_iRIContent = -1;      /* IRIContent */
static int hf_HI2Operations_iRISequence = -1;     /* IRISequence */
static int hf_HI2Operations_IRISequence_item = -1;  /* IRIContent */
static int hf_HI2Operations_iRI_Begin_record = -1;  /* IRI_Parameters */
static int hf_HI2Operations_iRI_End_record = -1;  /* IRI_Parameters */
static int hf_HI2Operations_iRI_Continue_record = -1;  /* IRI_Parameters */
static int hf_HI2Operations_iRI_Report_record = -1;  /* IRI_Parameters */
static int hf_HI2Operations_domainID = -1;        /* OBJECT_IDENTIFIER */
static int hf_HI2Operations_iRIversion = -1;      /* T_iRIversion */
static int hf_HI2Operations_lawfulInterceptionIdentifier = -1;  /* LawfulInterceptionIdentifier */
static int hf_HI2Operations_communicationIdentifier = -1;  /* CommunicationIdentifier */
static int hf_HI2Operations_timeStamp = -1;       /* TimeStamp */
static int hf_HI2Operations_intercepted_Call_Direct = -1;  /* T_intercepted_Call_Direct */
static int hf_HI2Operations_intercepted_Call_State = -1;  /* Intercepted_Call_State */
static int hf_HI2Operations_ringingDuration = -1;  /* OCTET_STRING_SIZE_3 */
static int hf_HI2Operations_conversationDuration = -1;  /* OCTET_STRING_SIZE_3 */
static int hf_HI2Operations_locationOfTheTarget = -1;  /* Location */
static int hf_HI2Operations_partyInformation = -1;  /* SET_SIZE_1_10_OF_PartyInformation */
static int hf_HI2Operations_partyInformation_item = -1;  /* PartyInformation */
static int hf_HI2Operations_callContentLinkInformation = -1;  /* T_callContentLinkInformation */
static int hf_HI2Operations_cCLink1Characteristics = -1;  /* CallContentLinkCharacteristics */
static int hf_HI2Operations_cCLink2Characteristics = -1;  /* CallContentLinkCharacteristics */
static int hf_HI2Operations_release_Reason_Of_Intercepted_Call = -1;  /* OCTET_STRING_SIZE_2 */
static int hf_HI2Operations_nature_Of_The_intercepted_call = -1;  /* T_nature_Of_The_intercepted_call */
static int hf_HI2Operations_serverCenterAddress = -1;  /* PartyInformation */
static int hf_HI2Operations_sMS = -1;             /* SMS_report */
static int hf_HI2Operations_cC_Link_Identifier = -1;  /* CC_Link_Identifier */
static int hf_HI2Operations_national_Parameters = -1;  /* National_Parameters */
static int hf_HI2Operations_gPRSCorrelationNumber = -1;  /* GPRSCorrelationNumber */
static int hf_HI2Operations_gPRSevent = -1;       /* GPRSEvent */
static int hf_HI2Operations_sgsnAddress = -1;     /* DataNodeAddress */
static int hf_HI2Operations_gPRSOperationErrorCode = -1;  /* GPRSOperationErrorCode */
static int hf_HI2Operations_ggsnAddress = -1;     /* DataNodeAddress */
static int hf_HI2Operations_qOS = -1;             /* UmtsQos */
static int hf_HI2Operations_networkIdentifier = -1;  /* Network_Identifier */
static int hf_HI2Operations_sMSOriginatingAddress = -1;  /* DataNodeAddress */
static int hf_HI2Operations_sMSTerminatingAddress = -1;  /* DataNodeAddress */
static int hf_HI2Operations_iMSevent = -1;        /* IMSevent */
static int hf_HI2Operations_sIPMessage = -1;      /* OCTET_STRING */
static int hf_HI2Operations_servingSGSN_number = -1;  /* OCTET_STRING_SIZE_1_20 */
static int hf_HI2Operations_servingSGSN_address = -1;  /* OCTET_STRING_SIZE_5_17 */
static int hf_HI2Operations_tARGETACTIVITYMONITOR = -1;  /* TARGETACTIVITYMONITOR_1 */
static int hf_HI2Operations_ldiEvent = -1;        /* LDIevent */
static int hf_HI2Operations_correlation = -1;     /* CorrelationValues */
static int hf_HI2Operations_tARGETACTIVITYMONITORind = -1;  /* TARGETACTIVITYMONITORind */
static int hf_HI2Operations_tARGETCOMMSMONITORind = -1;  /* TARGETCOMMSMONITORind */
static int hf_HI2Operations_tTRAFFICind = -1;     /* TTRAFFICind */
static int hf_HI2Operations_cTTRAFFICind = -1;    /* CTTRAFFICind */
static int hf_HI2Operations_national_HI2_ASN1parameters = -1;  /* National_HI2_ASN1parameters */
static int hf_HI2Operations_communication_Identity_Number = -1;  /* OCTET_STRING_SIZE_1_8 */
static int hf_HI2Operations_network_Identifier = -1;  /* Network_Identifier */
static int hf_HI2Operations_operator_Identifier = -1;  /* OCTET_STRING_SIZE_1_5 */
static int hf_HI2Operations_network_Element_Identifier = -1;  /* Network_Element_Identifier */
static int hf_HI2Operations_e164_Format = -1;     /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_x25_Format = -1;      /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_iP_Format = -1;       /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_dNS_Format = -1;      /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_iP_Address = -1;      /* IPAddress */
static int hf_HI2Operations_localTime = -1;       /* LocalTimeStamp */
static int hf_HI2Operations_utcTime = -1;         /* UTCTime */
static int hf_HI2Operations_generalizedTime = -1;  /* GeneralizedTime */
static int hf_HI2Operations_winterSummerIndication = -1;  /* T_winterSummerIndication */
static int hf_HI2Operations_party_Qualifier = -1;  /* T_party_Qualifier */
static int hf_HI2Operations_partyIdentity = -1;   /* T_partyIdentity */
static int hf_HI2Operations_imei = -1;            /* OCTET_STRING_SIZE_8 */
static int hf_HI2Operations_tei = -1;             /* OCTET_STRING_SIZE_1_15 */
static int hf_HI2Operations_imsi = -1;            /* OCTET_STRING_SIZE_3_8 */
static int hf_HI2Operations_callingPartyNumber = -1;  /* CallingPartyNumber */
static int hf_HI2Operations_calledPartyNumber = -1;  /* CalledPartyNumber */
static int hf_HI2Operations_msISDN = -1;          /* OCTET_STRING_SIZE_1_9 */
static int hf_HI2Operations_sip_uri = -1;         /* OCTET_STRING */
static int hf_HI2Operations_tel_url = -1;         /* OCTET_STRING */
static int hf_HI2Operations_services_Information = -1;  /* Services_Information */
static int hf_HI2Operations_supplementary_Services_Information = -1;  /* Supplementary_Services */
static int hf_HI2Operations_services_Data_Information = -1;  /* Services_Data_Information */
static int hf_HI2Operations_iSUP_Format = -1;     /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_dSS1_Format = -1;     /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_mAP_Format = -1;      /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_e164_Number = -1;     /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_globalCellID = -1;    /* OCTET_STRING_SIZE_5_7 */
static int hf_HI2Operations_tetraLocation = -1;   /* TetraLocation */
static int hf_HI2Operations_rAI = -1;             /* OCTET_STRING_SIZE_6 */
static int hf_HI2Operations_gsmLocation = -1;     /* GSMLocation */
static int hf_HI2Operations_umtsLocation = -1;    /* UMTSLocation */
static int hf_HI2Operations_sAI = -1;             /* OCTET_STRING_SIZE_7 */
static int hf_HI2Operations_oldRAI = -1;          /* OCTET_STRING_SIZE_6 */
static int hf_HI2Operations_ms_Loc = -1;          /* T_ms_Loc */
static int hf_HI2Operations_mcc = -1;             /* INTEGER_0_1023 */
static int hf_HI2Operations_mnc = -1;             /* INTEGER_0_16383 */
static int hf_HI2Operations_lai = -1;             /* INTEGER_0_65535 */
static int hf_HI2Operations_ci = -1;              /* INTEGER */
static int hf_HI2Operations_ls_Loc = -1;          /* INTEGER */
static int hf_HI2Operations_geoCoordinates = -1;  /* T_geoCoordinates */
static int hf_HI2Operations_latitude = -1;        /* PrintableString_SIZE_7_10 */
static int hf_HI2Operations_longitude = -1;       /* PrintableString_SIZE_8_11 */
static int hf_HI2Operations_mapDatum = -1;        /* MapDatum */
static int hf_HI2Operations_azimuth = -1;         /* INTEGER_0_359 */
static int hf_HI2Operations_utmCoordinates = -1;  /* T_utmCoordinates */
static int hf_HI2Operations_utm_East = -1;        /* PrintableString_SIZE_10 */
static int hf_HI2Operations_utm_North = -1;       /* PrintableString_SIZE_7 */
static int hf_HI2Operations_utmRefCoordinates = -1;  /* T_utmRefCoordinates */
static int hf_HI2Operations_utmref_string = -1;   /* PrintableString_SIZE_13 */
static int hf_HI2Operations_wGS84Coordinates = -1;  /* OCTET_STRING */
static int hf_HI2Operations_point = -1;           /* GA_Point */
static int hf_HI2Operations_pointWithUnCertainty = -1;  /* GA_PointWithUnCertainty */
static int hf_HI2Operations_polygon = -1;         /* GA_Polygon */
static int hf_HI2Operations_latitudeSign = -1;    /* T_latitudeSign */
static int hf_HI2Operations_latitude_01 = -1;     /* INTEGER_0_8388607 */
static int hf_HI2Operations_longitude_01 = -1;    /* INTEGER_M8388608_8388607 */
static int hf_HI2Operations_geographicalCoordinates = -1;  /* GeographicalCoordinates */
static int hf_HI2Operations_uncertaintyCode = -1;  /* INTEGER_0_127 */
static int hf_HI2Operations_GA_Polygon_item = -1;  /* GA_Polygon_item */
static int hf_HI2Operations_cCLink_State = -1;    /* CCLink_State */
static int hf_HI2Operations_release_Time = -1;    /* TimeStamp */
static int hf_HI2Operations_release_Reason = -1;  /* OCTET_STRING_SIZE_2 */
static int hf_HI2Operations_lEMF_Address = -1;    /* CalledPartyNumber */
static int hf_HI2Operations_iSUP_parameters = -1;  /* ISUP_parameters */
static int hf_HI2Operations_dSS1_parameters_codeset_0 = -1;  /* DSS1_parameters_codeset_0 */
static int hf_HI2Operations_mAP_parameters = -1;  /* MAP_parameters */
static int hf_HI2Operations_ISUP_parameters_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_parameters_codeset_0_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_MAP_parameters_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_standard_Supplementary_Services = -1;  /* Standard_Supplementary_Services */
static int hf_HI2Operations_non_Standard_Supplementary_Services = -1;  /* Non_Standard_Supplementary_Services */
static int hf_HI2Operations_other_Services = -1;  /* Other_Services */
static int hf_HI2Operations_iSUP_SS_parameters = -1;  /* ISUP_SS_parameters */
static int hf_HI2Operations_dSS1_SS_parameters_codeset_0 = -1;  /* DSS1_SS_parameters_codeset_0 */
static int hf_HI2Operations_dSS1_SS_parameters_codeset_4 = -1;  /* DSS1_SS_parameters_codeset_4 */
static int hf_HI2Operations_dSS1_SS_parameters_codeset_5 = -1;  /* DSS1_SS_parameters_codeset_5 */
static int hf_HI2Operations_dSS1_SS_parameters_codeset_6 = -1;  /* DSS1_SS_parameters_codeset_6 */
static int hf_HI2Operations_dSS1_SS_parameters_codeset_7 = -1;  /* DSS1_SS_parameters_codeset_7 */
static int hf_HI2Operations_dSS1_SS_Invoke_components = -1;  /* DSS1_SS_Invoke_Components */
static int hf_HI2Operations_mAP_SS_Parameters = -1;  /* MAP_SS_Parameters */
static int hf_HI2Operations_mAP_SS_Invoke_Components = -1;  /* MAP_SS_Invoke_Components */
static int hf_HI2Operations_Non_Standard_Supplementary_Services_item = -1;  /* Non_Standard_Supplementary_Services_item */
static int hf_HI2Operations_simpleIndication = -1;  /* SimpleIndication */
static int hf_HI2Operations_sciData = -1;         /* SciDataMode */
static int hf_HI2Operations_Other_Services_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_ISUP_SS_parameters_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_SS_parameters_codeset_0_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_SS_parameters_codeset_4_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_SS_parameters_codeset_5_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_SS_parameters_codeset_6_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_SS_parameters_codeset_7_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_SS_Invoke_Components_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_MAP_SS_Invoke_Components_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_MAP_SS_Parameters_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_sMS_Contents = -1;    /* T_sMS_Contents */
static int hf_HI2Operations_initiator = -1;       /* T_initiator */
static int hf_HI2Operations_transfer_status = -1;  /* T_transfer_status */
static int hf_HI2Operations_other_message = -1;   /* T_other_message */
static int hf_HI2Operations_content = -1;         /* OCTET_STRING_SIZE_1_270 */
static int hf_HI2Operations_National_Parameters_item = -1;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_gPRS_parameters = -1;  /* GPRS_parameters */
static int hf_HI2Operations_pDP_address_allocated_to_the_target = -1;  /* DataNodeAddress */
static int hf_HI2Operations_aPN = -1;             /* OCTET_STRING_SIZE_1_100 */
static int hf_HI2Operations_pDP_type = -1;        /* OCTET_STRING_SIZE_2 */
static int hf_HI2Operations_ipAddress = -1;       /* IPAddress */
static int hf_HI2Operations_x25Address = -1;      /* X25Address */
static int hf_HI2Operations_iP_type = -1;         /* T_iP_type */
static int hf_HI2Operations_iP_value = -1;        /* IP_value */
static int hf_HI2Operations_iP_assignment = -1;   /* T_iP_assignment */
static int hf_HI2Operations_iPBinaryAddress = -1;  /* OCTET_STRING_SIZE_4_16 */
static int hf_HI2Operations_iPTextAddress = -1;   /* IA5String_SIZE_7_45 */
static int hf_HI2Operations_countryCode = -1;     /* PrintableString_SIZE_2 */
static int hf_HI2Operations_qosMobileRadio = -1;  /* OCTET_STRING */
static int hf_HI2Operations_qosGn = -1;           /* OCTET_STRING */
static int hf_HI2Operations_iri_to_CC = -1;       /* IRI_to_CC_Correlation */
static int hf_HI2Operations_iri_to_iri = -1;      /* IRI_to_IRI_Correlation */
static int hf_HI2Operations_both_IRI_CC = -1;     /* T_both_IRI_CC */
static int hf_HI2Operations_iri_CC = -1;          /* IRI_to_CC_Correlation */
static int hf_HI2Operations_iri_IRI = -1;         /* IRI_to_IRI_Correlation */
static int hf_HI2Operations_cc = -1;              /* T_cc */
static int hf_HI2Operations_cc_item = -1;         /* OCTET_STRING */
static int hf_HI2Operations_iri = -1;             /* OCTET_STRING */
static int hf_HI2Operations_version = -1;         /* INTEGER */
static int hf_HI2Operations_lIInstanceid = -1;    /* LIIDType */
static int hf_HI2Operations_timestamp = -1;       /* UTCTime */
static int hf_HI2Operations_targetLocation = -1;  /* LocationType */
static int hf_HI2Operations_direction = -1;       /* DirectionType */
static int hf_HI2Operations_iRITransaction = -1;  /* IRITransactionType */
static int hf_HI2Operations_iRITransactionNumber = -1;  /* INTEGER */
static int hf_HI2Operations_userSignal = -1;      /* UserSignalType */
static int hf_HI2Operations_cryptoCheckSum = -1;  /* BIT_STRING */
static int hf_HI2Operations_copySignal = -1;      /* BIT_STRING */
static int hf_HI2Operations_interpretedSignal = -1;  /* INTEGER */
static int hf_HI2Operations_cdcPdu = -1;          /* CdcPdu */
static int hf_HI2Operations_geodeticData = -1;    /* BIT_STRING */
static int hf_HI2Operations_nameAddress = -1;     /* PrintableString_SIZE_1_100 */
static int hf_HI2Operations_protocolVersion = -1;  /* ProtocolVersion */
static int hf_HI2Operations_message = -1;         /* Message */
static int hf_HI2Operations_answer = -1;          /* Answer */
static int hf_HI2Operations_ccclose = -1;         /* CCClose */
static int hf_HI2Operations_ccopen = -1;          /* CCOpen */
static int hf_HI2Operations_reserved0 = -1;       /* NULL */
static int hf_HI2Operations_origination = -1;     /* Origination */
static int hf_HI2Operations_reserved1 = -1;       /* NULL */
static int hf_HI2Operations_redirection = -1;     /* Redirection */
static int hf_HI2Operations_release = -1;         /* Release */
static int hf_HI2Operations_reserved2 = -1;       /* NULL */
static int hf_HI2Operations_terminationattempt = -1;  /* TerminationAttempt */
static int hf_HI2Operations_reserved = -1;        /* NULL */
static int hf_HI2Operations_ccchange = -1;        /* CCChange */
static int hf_HI2Operations_reserved3 = -1;       /* NULL */
static int hf_HI2Operations_reserved4 = -1;       /* NULL */
static int hf_HI2Operations_reserved5 = -1;       /* NULL */
static int hf_HI2Operations_networksignal = -1;   /* NetworkSignal */
static int hf_HI2Operations_subjectsignal = -1;   /* SubjectSignal */
static int hf_HI2Operations_mediareport = -1;     /* MediaReport */
static int hf_HI2Operations_serviceinstance = -1;  /* ServiceInstance */
static int hf_HI2Operations_caseId = -1;          /* CaseId */
static int hf_HI2Operations_accessingElementId = -1;  /* AccessingElementId */
static int hf_HI2Operations_eventTime = -1;       /* EventTime */
static int hf_HI2Operations_callId = -1;          /* CallId */
static int hf_HI2Operations_answering = -1;       /* PartyId */
static int hf_HI2Operations_cCCId = -1;           /* CCCId */
static int hf_HI2Operations_subject = -1;         /* SDP */
static int hf_HI2Operations_associate = -1;       /* SDP */
static int hf_HI2Operations_flowDirection = -1;   /* FlowDirection */
static int hf_HI2Operations_resourceState = -1;   /* ResourceState */
static int hf_HI2Operations_ccOpenOption = -1;    /* T_ccOpenOption */
static int hf_HI2Operations_ccOpenTime = -1;      /* SEQUENCE_OF_CallId */
static int hf_HI2Operations_ccOpenTime_item = -1;  /* CallId */
static int hf_HI2Operations_alertingSignal = -1;  /* AlertingSignal */
static int hf_HI2Operations_subjectAudibleSignal = -1;  /* AudibleSignal */
static int hf_HI2Operations_terminalDisplayInfo = -1;  /* TerminalDisplayInfo */
static int hf_HI2Operations_other = -1;           /* VisibleString_SIZE_1_128_ */
static int hf_HI2Operations_calling = -1;         /* PartyId */
static int hf_HI2Operations_called = -1;          /* PartyId */
static int hf_HI2Operations_input = -1;           /* T_input */
static int hf_HI2Operations_userinput = -1;       /* VisibleString_SIZE_1_32_ */
static int hf_HI2Operations_translationinput = -1;  /* VisibleString_SIZE_1_32_ */
static int hf_HI2Operations_transitCarrierId = -1;  /* TransitCarrierId */
static int hf_HI2Operations_old = -1;             /* CallId */
static int hf_HI2Operations_redirectedto = -1;    /* PartyId */
static int hf_HI2Operations_new = -1;             /* CallId */
static int hf_HI2Operations_redirectedfrom = -1;  /* PartyId */
static int hf_HI2Operations_relatedCallId = -1;   /* CallId */
static int hf_HI2Operations_serviceName = -1;     /* VisibleString_SIZE_1_128_ */
static int hf_HI2Operations_firstCallCalling = -1;  /* PartyId */
static int hf_HI2Operations_secondCallCalling = -1;  /* PartyId */
static int hf_HI2Operations_signal = -1;          /* T_signal */
static int hf_HI2Operations_switchhookFlash = -1;  /* VisibleString_SIZE_1_128_ */
static int hf_HI2Operations_dialedDigits = -1;    /* VisibleString_SIZE_1_128_ */
static int hf_HI2Operations_featureKey = -1;      /* VisibleString_SIZE_1_128_ */
static int hf_HI2Operations_otherSignalingInformation = -1;  /* VisibleString_SIZE_1_128_ */
static int hf_HI2Operations_redirectedFromInfo = -1;  /* RedirectedFromInfo */
static int hf_HI2Operations_sequencenumber = -1;  /* VisibleString_SIZE_1_25_ */
static int hf_HI2Operations_systemidentity = -1;  /* VisibleString_SIZE_1_15_ */
static int hf_HI2Operations_combCCC = -1;         /* VisibleString_SIZE_1_20_ */
static int hf_HI2Operations_sepCCCpair = -1;      /* T_sepCCCpair */
static int hf_HI2Operations_sepXmitCCC = -1;      /* VisibleString_SIZE_1_20_ */
static int hf_HI2Operations_sepRecvCCC = -1;      /* VisibleString_SIZE_1_20_ */
static int hf_HI2Operations_dn = -1;              /* VisibleString_SIZE_1_15_ */
static int hf_HI2Operations_userProvided = -1;    /* VisibleString_SIZE_1_15_ */
static int hf_HI2Operations_reserved6 = -1;       /* NULL */
static int hf_HI2Operations_reserved7 = -1;       /* NULL */
static int hf_HI2Operations_ipAddress_01 = -1;    /* VisibleString_SIZE_1_32_ */
static int hf_HI2Operations_reserved8 = -1;       /* NULL */
static int hf_HI2Operations_trunkId = -1;         /* VisibleString_SIZE_1_32_ */
static int hf_HI2Operations_reserved9 = -1;       /* NULL */
static int hf_HI2Operations_genericAddress = -1;  /* VisibleString_SIZE_1_32_ */
static int hf_HI2Operations_genericDigits = -1;   /* VisibleString_SIZE_1_32_ */
static int hf_HI2Operations_genericName = -1;     /* VisibleString_SIZE_1_48_ */
static int hf_HI2Operations_port = -1;            /* VisibleString_SIZE_1_32_ */
static int hf_HI2Operations_context = -1;         /* VisibleString_SIZE_1_32_ */
static int hf_HI2Operations_lastRedirecting = -1;  /* PartyId */
static int hf_HI2Operations_originalCalled = -1;  /* PartyId */
static int hf_HI2Operations_numRedirections = -1;  /* INTEGER_1_100_ */
static int hf_HI2Operations_generalDisplay = -1;  /* VisibleString_SIZE_1_80_ */
static int hf_HI2Operations_calledNumber = -1;    /* VisibleString_SIZE_1_40_ */
static int hf_HI2Operations_callingNumber = -1;   /* VisibleString_SIZE_1_40_ */
static int hf_HI2Operations_callingName = -1;     /* VisibleString_SIZE_1_40_ */
static int hf_HI2Operations_originalCalledNumber = -1;  /* VisibleString_SIZE_1_40_ */
static int hf_HI2Operations_lastRedirectingNumber = -1;  /* VisibleString_SIZE_1_40_ */
static int hf_HI2Operations_redirectingName = -1;  /* VisibleString_SIZE_1_40_ */
static int hf_HI2Operations_redirectingReason = -1;  /* VisibleString_SIZE_1_40_ */
static int hf_HI2Operations_messageWaitingNotif = -1;  /* VisibleString_SIZE_1_40_ */
static int hf_HI2Operations_tLIInstanceid = -1;   /* TLIIdType */
static int hf_HI2Operations_targetLocation_01 = -1;  /* LocationType_en301040 */
static int hf_HI2Operations_targetAction = -1;    /* ActivityType */
static int hf_HI2Operations_supplementaryTargetaddress = -1;  /* AddressType */
static int hf_HI2Operations_cotargetaddress = -1;  /* SEQUENCE_OF_AddressType */
static int hf_HI2Operations_cotargetaddress_item = -1;  /* AddressType */
static int hf_HI2Operations_cotargetlocation = -1;  /* SEQUENCE_OF_LocationType_en301040 */
static int hf_HI2Operations_cotargetlocation_item = -1;  /* LocationType_en301040 */
static int hf_HI2Operations_targetlocation = -1;  /* LocationType_en301040 */
static int hf_HI2Operations_targetcommsid = -1;   /* CircuitIdType */
static int hf_HI2Operations_cotargetcommsid = -1;  /* SEQUENCE_OF_CircuitIdType */
static int hf_HI2Operations_cotargetcommsid_item = -1;  /* CircuitIdType */
static int hf_HI2Operations_trafficPacket = -1;   /* BIT_STRING */
static int hf_HI2Operations_cctivity = -1;        /* ActivityClassType */
static int hf_HI2Operations_callRelation = -1;    /* T_callRelation */
static int hf_HI2Operations_direction_01 = -1;    /* T_direction */
static int hf_HI2Operations_scope = -1;           /* T_scope */
static int hf_HI2Operations_cPlaneData = -1;      /* BIT_STRING */
static int hf_HI2Operations_sStype = -1;          /* SSType */
static int hf_HI2Operations_tSI = -1;             /* TSIType */
static int hf_HI2Operations_supplementaryAddress = -1;  /* SEQUENCE_OF_TETRAAddressType */
static int hf_HI2Operations_supplementaryAddress_item = -1;  /* TETRAAddressType */
static int hf_HI2Operations_tETRAaddress = -1;    /* TSIType */
static int hf_HI2Operations_pISNaddress = -1;     /* NumericString_SIZE_20 */
static int hf_HI2Operations_iP4address = -1;      /* BIT_STRING_SIZE_32 */
static int hf_HI2Operations_iP6address = -1;      /* BIT_STRING_SIZE_128 */
static int hf_HI2Operations_e164address = -1;     /* NumericString_SIZE_20 */
static int hf_HI2Operations_tEI = -1;             /* TEIType */
static int hf_HI2Operations_mSLoc = -1;           /* TETRACGIType */
static int hf_HI2Operations_lSLoc = -1;           /* TETRAAddressType */
static int hf_HI2Operations_mcc_01 = -1;          /* MCCType */
static int hf_HI2Operations_mnc_01 = -1;          /* MNCType */
static int hf_HI2Operations_lai_01 = -1;          /* LocationAreaType */
static int hf_HI2Operations_cI = -1;              /* CellIdType */
static int hf_HI2Operations_ssi = -1;             /* SSIType */

/*--- End of included file: packet-HI2Operations-hf.c ---*/
#line 43 "../../asn1/HI2Operations/packet-HI2Operations-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-HI2Operations-ett.c ---*/
#line 1 "../../asn1/HI2Operations/packet-HI2Operations-ett.c"
static gint ett_HI2Operations_IRIsContent = -1;
static gint ett_HI2Operations_IRISequence = -1;
static gint ett_HI2Operations_IRIContent = -1;
static gint ett_HI2Operations_IRI_Parameters = -1;
static gint ett_HI2Operations_SET_SIZE_1_10_OF_PartyInformation = -1;
static gint ett_HI2Operations_T_callContentLinkInformation = -1;
static gint ett_HI2Operations_CommunicationIdentifier = -1;
static gint ett_HI2Operations_Network_Identifier = -1;
static gint ett_HI2Operations_Network_Element_Identifier = -1;
static gint ett_HI2Operations_TimeStamp = -1;
static gint ett_HI2Operations_LocalTimeStamp = -1;
static gint ett_HI2Operations_PartyInformation = -1;
static gint ett_HI2Operations_T_partyIdentity = -1;
static gint ett_HI2Operations_CallingPartyNumber = -1;
static gint ett_HI2Operations_CalledPartyNumber = -1;
static gint ett_HI2Operations_Location = -1;
static gint ett_HI2Operations_TetraLocation = -1;
static gint ett_HI2Operations_T_ms_Loc = -1;
static gint ett_HI2Operations_GSMLocation = -1;
static gint ett_HI2Operations_T_geoCoordinates = -1;
static gint ett_HI2Operations_T_utmCoordinates = -1;
static gint ett_HI2Operations_T_utmRefCoordinates = -1;
static gint ett_HI2Operations_UMTSLocation = -1;
static gint ett_HI2Operations_GeographicalCoordinates = -1;
static gint ett_HI2Operations_GA_Point = -1;
static gint ett_HI2Operations_GA_PointWithUnCertainty = -1;
static gint ett_HI2Operations_GA_Polygon = -1;
static gint ett_HI2Operations_GA_Polygon_item = -1;
static gint ett_HI2Operations_CallContentLinkCharacteristics = -1;
static gint ett_HI2Operations_Services_Information = -1;
static gint ett_HI2Operations_ISUP_parameters = -1;
static gint ett_HI2Operations_DSS1_parameters_codeset_0 = -1;
static gint ett_HI2Operations_MAP_parameters = -1;
static gint ett_HI2Operations_Supplementary_Services = -1;
static gint ett_HI2Operations_Standard_Supplementary_Services = -1;
static gint ett_HI2Operations_Non_Standard_Supplementary_Services = -1;
static gint ett_HI2Operations_Non_Standard_Supplementary_Services_item = -1;
static gint ett_HI2Operations_Other_Services = -1;
static gint ett_HI2Operations_ISUP_SS_parameters = -1;
static gint ett_HI2Operations_DSS1_SS_parameters_codeset_0 = -1;
static gint ett_HI2Operations_DSS1_SS_parameters_codeset_4 = -1;
static gint ett_HI2Operations_DSS1_SS_parameters_codeset_5 = -1;
static gint ett_HI2Operations_DSS1_SS_parameters_codeset_6 = -1;
static gint ett_HI2Operations_DSS1_SS_parameters_codeset_7 = -1;
static gint ett_HI2Operations_DSS1_SS_Invoke_Components = -1;
static gint ett_HI2Operations_MAP_SS_Invoke_Components = -1;
static gint ett_HI2Operations_MAP_SS_Parameters = -1;
static gint ett_HI2Operations_SMS_report = -1;
static gint ett_HI2Operations_T_sMS_Contents = -1;
static gint ett_HI2Operations_National_Parameters = -1;
static gint ett_HI2Operations_Services_Data_Information = -1;
static gint ett_HI2Operations_GPRS_parameters = -1;
static gint ett_HI2Operations_DataNodeAddress = -1;
static gint ett_HI2Operations_IPAddress = -1;
static gint ett_HI2Operations_IP_value = -1;
static gint ett_HI2Operations_National_HI2_ASN1parameters = -1;
static gint ett_HI2Operations_UmtsQos = -1;
static gint ett_HI2Operations_CorrelationValues = -1;
static gint ett_HI2Operations_T_both_IRI_CC = -1;
static gint ett_HI2Operations_IRI_to_CC_Correlation = -1;
static gint ett_HI2Operations_T_cc = -1;
static gint ett_HI2Operations_TARGETACTIVITYMONITOR_1 = -1;
static gint ett_HI2Operations_UserSignalType = -1;
static gint ett_HI2Operations_LocationType = -1;
static gint ett_HI2Operations_CdcPdu = -1;
static gint ett_HI2Operations_Message = -1;
static gint ett_HI2Operations_Answer = -1;
static gint ett_HI2Operations_CCChange = -1;
static gint ett_HI2Operations_CCClose = -1;
static gint ett_HI2Operations_CCOpen = -1;
static gint ett_HI2Operations_T_ccOpenOption = -1;
static gint ett_HI2Operations_SEQUENCE_OF_CallId = -1;
static gint ett_HI2Operations_MediaReport = -1;
static gint ett_HI2Operations_NetworkSignal = -1;
static gint ett_HI2Operations_Origination = -1;
static gint ett_HI2Operations_T_input = -1;
static gint ett_HI2Operations_Redirection = -1;
static gint ett_HI2Operations_Release = -1;
static gint ett_HI2Operations_ServiceInstance = -1;
static gint ett_HI2Operations_SubjectSignal = -1;
static gint ett_HI2Operations_T_signal = -1;
static gint ett_HI2Operations_TerminationAttempt = -1;
static gint ett_HI2Operations_CallId = -1;
static gint ett_HI2Operations_CCCId = -1;
static gint ett_HI2Operations_T_sepCCCpair = -1;
static gint ett_HI2Operations_PartyId = -1;
static gint ett_HI2Operations_RedirectedFromInfo = -1;
static gint ett_HI2Operations_TerminalDisplayInfo = -1;
static gint ett_HI2Operations_TARGETACTIVITYMONITORind = -1;
static gint ett_HI2Operations_SEQUENCE_OF_AddressType = -1;
static gint ett_HI2Operations_SEQUENCE_OF_LocationType_en301040 = -1;
static gint ett_HI2Operations_TARGETCOMMSMONITORind = -1;
static gint ett_HI2Operations_SEQUENCE_OF_CircuitIdType = -1;
static gint ett_HI2Operations_TTRAFFICind = -1;
static gint ett_HI2Operations_CTTRAFFICind = -1;
static gint ett_HI2Operations_ActivityType = -1;
static gint ett_HI2Operations_AddressType = -1;
static gint ett_HI2Operations_SEQUENCE_OF_TETRAAddressType = -1;
static gint ett_HI2Operations_TETRAAddressType = -1;
static gint ett_HI2Operations_LocationType_en301040 = -1;
static gint ett_HI2Operations_TETRACGIType = -1;
static gint ett_HI2Operations_TSIType = -1;

/*--- End of included file: packet-HI2Operations-ett.c ---*/
#line 46 "../../asn1/HI2Operations/packet-HI2Operations-template.c"


/*--- Included file: packet-HI2Operations-fn.c ---*/
#line 1 "../../asn1/HI2Operations/packet-HI2Operations-fn.c"


static int
dissect_HI2Operations_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string HI2Operations_T_iRIversion_vals[] = {
  {   2, "version2" },
  {   3, "version3" },
  {   4, "version4" },
  {   5, "version5" },
  {   6, "version6" },
  {   7, "version7" },
  {   8, "lastVersion" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_iRIversion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_LawfulInterceptionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_8(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_5(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_25(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string HI2Operations_T_iP_type_vals[] = {
  {   0, "iPV4" },
  {   1, "iPV6" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_iP_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_4_16(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_IA5String_SIZE_7_45(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string HI2Operations_IP_value_vals[] = {
  {   1, "iPBinaryAddress" },
  {   2, "iPTextAddress" },
  { 0, NULL }
};

static const ber_choice_t IP_value_choice[] = {
  {   1, &hf_HI2Operations_iPBinaryAddress, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_4_16 },
  {   2, &hf_HI2Operations_iPTextAddress, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IA5String_SIZE_7_45 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_IP_value(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IP_value_choice, hf_index, ett_HI2Operations_IP_value,
                                 NULL);

  return offset;
}


static const value_string HI2Operations_T_iP_assignment_vals[] = {
  {   1, "static" },
  {   2, "dynamic" },
  {   3, "notKnown" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_iP_assignment(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t IPAddress_sequence[] = {
  { &hf_HI2Operations_iP_type, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_iP_type },
  { &hf_HI2Operations_iP_value, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_IP_value },
  { &hf_HI2Operations_iP_assignment, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_iP_assignment },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_IPAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPAddress_sequence, hf_index, ett_HI2Operations_IPAddress);

  return offset;
}


static const value_string HI2Operations_Network_Element_Identifier_vals[] = {
  {   1, "e164-Format" },
  {   2, "x25-Format" },
  {   3, "iP-Format" },
  {   4, "dNS-Format" },
  {   5, "iP-Address" },
  { 0, NULL }
};

static const ber_choice_t Network_Element_Identifier_choice[] = {
  {   1, &hf_HI2Operations_e164_Format, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  {   2, &hf_HI2Operations_x25_Format, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  {   3, &hf_HI2Operations_iP_Format, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  {   4, &hf_HI2Operations_dNS_Format, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  {   5, &hf_HI2Operations_iP_Address, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IPAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Network_Element_Identifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Network_Element_Identifier_choice, hf_index, ett_HI2Operations_Network_Element_Identifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t Network_Identifier_sequence[] = {
  { &hf_HI2Operations_operator_Identifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_5 },
  { &hf_HI2Operations_network_Element_Identifier, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_Network_Element_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Network_Identifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Network_Identifier_sequence, hf_index, ett_HI2Operations_Network_Identifier);

  return offset;
}


static const ber_sequence_t CommunicationIdentifier_sequence[] = {
  { &hf_HI2Operations_communication_Identity_Number, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_8 },
  { &hf_HI2Operations_network_Identifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_Network_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CommunicationIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CommunicationIdentifier_sequence, hf_index, ett_HI2Operations_CommunicationIdentifier);

  return offset;
}



static int
dissect_HI2Operations_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string HI2Operations_T_winterSummerIndication_vals[] = {
  {   0, "notProvided" },
  {   1, "winterTime" },
  {   2, "summerTime" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_winterSummerIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t LocalTimeStamp_sequence[] = {
  { &hf_HI2Operations_generalizedTime, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_GeneralizedTime },
  { &hf_HI2Operations_winterSummerIndication, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_winterSummerIndication },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_LocalTimeStamp(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LocalTimeStamp_sequence, hf_index, ett_HI2Operations_LocalTimeStamp);

  return offset;
}



static int
dissect_HI2Operations_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string HI2Operations_TimeStamp_vals[] = {
  {   0, "localTime" },
  {   1, "utcTime" },
  { 0, NULL }
};

static const ber_choice_t TimeStamp_choice[] = {
  {   0, &hf_HI2Operations_localTime, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_LocalTimeStamp },
  {   1, &hf_HI2Operations_utcTime, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTCTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_TimeStamp(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TimeStamp_choice, hf_index, ett_HI2Operations_TimeStamp,
                                 NULL);

  return offset;
}


static const value_string HI2Operations_T_intercepted_Call_Direct_vals[] = {
  {   0, "not-Available" },
  {   1, "originating-Target" },
  {   2, "terminating-Target" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_intercepted_Call_Direct(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_Intercepted_Call_State_vals[] = {
  {   1, "idle" },
  {   2, "setUpInProcess" },
  {   3, "connected" },
  { 0, NULL }
};


static int
dissect_HI2Operations_Intercepted_Call_State(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_3(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_5_7(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_0_1023(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_0_16383(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_0_65535(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_HI2Operations_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_ms_Loc_sequence[] = {
  { &hf_HI2Operations_mcc   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_1023 },
  { &hf_HI2Operations_mnc   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_16383 },
  { &hf_HI2Operations_lai   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_65535 },
  { &hf_HI2Operations_ci    , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_ms_Loc(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_ms_Loc_sequence, hf_index, ett_HI2Operations_T_ms_Loc);

  return offset;
}


static const value_string HI2Operations_TetraLocation_vals[] = {
  {   1, "ms-Loc" },
  {   2, "ls-Loc" },
  { 0, NULL }
};

static const ber_choice_t TetraLocation_choice[] = {
  {   1, &hf_HI2Operations_ms_Loc, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_ms_Loc },
  {   2, &hf_HI2Operations_ls_Loc, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_TetraLocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TetraLocation_choice, hf_index, ett_HI2Operations_TetraLocation,
                                 NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_6(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_7_10(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_8_11(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string HI2Operations_MapDatum_vals[] = {
  {   0, "wGS84" },
  {   1, "wGS72" },
  {   2, "eD50" },
  { 0, NULL }
};


static int
dissect_HI2Operations_MapDatum(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_0_359(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_geoCoordinates_sequence[] = {
  { &hf_HI2Operations_latitude, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString_SIZE_7_10 },
  { &hf_HI2Operations_longitude, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString_SIZE_8_11 },
  { &hf_HI2Operations_mapDatum, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_MapDatum },
  { &hf_HI2Operations_azimuth, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_359 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_geoCoordinates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_geoCoordinates_sequence, hf_index, ett_HI2Operations_T_geoCoordinates);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_10(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_7(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t T_utmCoordinates_sequence[] = {
  { &hf_HI2Operations_utm_East, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString_SIZE_10 },
  { &hf_HI2Operations_utm_North, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString_SIZE_7 },
  { &hf_HI2Operations_mapDatum, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_MapDatum },
  { &hf_HI2Operations_azimuth, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_359 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_utmCoordinates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_utmCoordinates_sequence, hf_index, ett_HI2Operations_T_utmCoordinates);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_13(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t T_utmRefCoordinates_sequence[] = {
  { &hf_HI2Operations_utmref_string, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString_SIZE_13 },
  { &hf_HI2Operations_mapDatum, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_MapDatum },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_utmRefCoordinates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_utmRefCoordinates_sequence, hf_index, ett_HI2Operations_T_utmRefCoordinates);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string HI2Operations_GSMLocation_vals[] = {
  {   1, "geoCoordinates" },
  {   2, "utmCoordinates" },
  {   3, "utmRefCoordinates" },
  {   4, "wGS84Coordinates" },
  { 0, NULL }
};

static const ber_choice_t GSMLocation_choice[] = {
  {   1, &hf_HI2Operations_geoCoordinates, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_geoCoordinates },
  {   2, &hf_HI2Operations_utmCoordinates, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_utmCoordinates },
  {   3, &hf_HI2Operations_utmRefCoordinates, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_utmRefCoordinates },
  {   4, &hf_HI2Operations_wGS84Coordinates, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_GSMLocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GSMLocation_choice, hf_index, ett_HI2Operations_GSMLocation,
                                 NULL);

  return offset;
}


static const value_string HI2Operations_T_latitudeSign_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_latitudeSign(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_0_8388607(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_M8388608_8388607(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t GeographicalCoordinates_sequence[] = {
  { &hf_HI2Operations_latitudeSign, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_latitudeSign },
  { &hf_HI2Operations_latitude_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_8388607 },
  { &hf_HI2Operations_longitude_01, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_M8388608_8388607 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_GeographicalCoordinates(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GeographicalCoordinates_sequence, hf_index, ett_HI2Operations_GeographicalCoordinates);

  return offset;
}


static const ber_sequence_t GA_Point_sequence[] = {
  { &hf_HI2Operations_geographicalCoordinates, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_GeographicalCoordinates },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_GA_Point(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GA_Point_sequence, hf_index, ett_HI2Operations_GA_Point);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_0_127(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t GA_PointWithUnCertainty_sequence[] = {
  { &hf_HI2Operations_geographicalCoordinates, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_GeographicalCoordinates },
  { &hf_HI2Operations_uncertaintyCode, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_127 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_GA_PointWithUnCertainty(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GA_PointWithUnCertainty_sequence, hf_index, ett_HI2Operations_GA_PointWithUnCertainty);

  return offset;
}


static const ber_sequence_t GA_Polygon_item_sequence[] = {
  { &hf_HI2Operations_geographicalCoordinates, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_GeographicalCoordinates },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_GA_Polygon_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GA_Polygon_item_sequence, hf_index, ett_HI2Operations_GA_Polygon_item);

  return offset;
}


static const ber_sequence_t GA_Polygon_sequence_of[1] = {
  { &hf_HI2Operations_GA_Polygon_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_GA_Polygon_item },
};

static int
dissect_HI2Operations_GA_Polygon(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      GA_Polygon_sequence_of, hf_index, ett_HI2Operations_GA_Polygon);

  return offset;
}


static const value_string HI2Operations_UMTSLocation_vals[] = {
  {   1, "point" },
  {   2, "pointWithUnCertainty" },
  {   3, "polygon" },
  { 0, NULL }
};

static const ber_choice_t UMTSLocation_choice[] = {
  {   1, &hf_HI2Operations_point , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_GA_Point },
  {   2, &hf_HI2Operations_pointWithUnCertainty, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_GA_PointWithUnCertainty },
  {   3, &hf_HI2Operations_polygon, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_GA_Polygon },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_UMTSLocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UMTSLocation_choice, hf_index, ett_HI2Operations_UMTSLocation,
                                 NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_7(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t Location_sequence[] = {
  { &hf_HI2Operations_e164_Number, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  { &hf_HI2Operations_globalCellID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_5_7 },
  { &hf_HI2Operations_tetraLocation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_TetraLocation },
  { &hf_HI2Operations_rAI   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_6 },
  { &hf_HI2Operations_gsmLocation, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_GSMLocation },
  { &hf_HI2Operations_umtsLocation, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_UMTSLocation },
  { &hf_HI2Operations_sAI   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_7 },
  { &hf_HI2Operations_oldRAI, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_6 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Location(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Location_sequence, hf_index, ett_HI2Operations_Location);

  return offset;
}


static const value_string HI2Operations_T_party_Qualifier_vals[] = {
  {   0, "originating-Party" },
  {   1, "terminating-Party" },
  {   2, "forwarded-to-Party" },
  {   3, "gPRS-Target" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_party_Qualifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_8(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_15(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_3_8(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string HI2Operations_CallingPartyNumber_vals[] = {
  {   1, "iSUP-Format" },
  {   2, "dSS1-Format" },
  {   3, "mAP-Format" },
  { 0, NULL }
};

static const ber_choice_t CallingPartyNumber_choice[] = {
  {   1, &hf_HI2Operations_iSUP_Format, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  {   2, &hf_HI2Operations_dSS1_Format, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  {   3, &hf_HI2Operations_mAP_Format, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CallingPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CallingPartyNumber_choice, hf_index, ett_HI2Operations_CallingPartyNumber,
                                 NULL);

  return offset;
}


static const value_string HI2Operations_CalledPartyNumber_vals[] = {
  {   1, "iSUP-Format" },
  {   2, "mAP-Format" },
  {   3, "dSS1-Format" },
  { 0, NULL }
};

static const ber_choice_t CalledPartyNumber_choice[] = {
  {   1, &hf_HI2Operations_iSUP_Format, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  {   2, &hf_HI2Operations_mAP_Format, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  {   3, &hf_HI2Operations_dSS1_Format, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CalledPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CalledPartyNumber_choice, hf_index, ett_HI2Operations_CalledPartyNumber,
                                 NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_9(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t T_partyIdentity_sequence[] = {
  { &hf_HI2Operations_imei  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_8 },
  { &hf_HI2Operations_tei   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_15 },
  { &hf_HI2Operations_imsi  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_3_8 },
  { &hf_HI2Operations_callingPartyNumber, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_CallingPartyNumber },
  { &hf_HI2Operations_calledPartyNumber, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_CalledPartyNumber },
  { &hf_HI2Operations_msISDN, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_9 },
  { &hf_HI2Operations_e164_Format, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  { &hf_HI2Operations_sip_uri, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_tel_url, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_partyIdentity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_partyIdentity_sequence, hf_index, ett_HI2Operations_T_partyIdentity);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_256(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ISUP_parameters_set_of[1] = {
  { &hf_HI2Operations_ISUP_parameters_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_ISUP_parameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ISUP_parameters_set_of, hf_index, ett_HI2Operations_ISUP_parameters);

  return offset;
}


static const ber_sequence_t DSS1_parameters_codeset_0_set_of[1] = {
  { &hf_HI2Operations_DSS1_parameters_codeset_0_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_parameters_codeset_0(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_parameters_codeset_0_set_of, hf_index, ett_HI2Operations_DSS1_parameters_codeset_0);

  return offset;
}


static const ber_sequence_t MAP_parameters_set_of[1] = {
  { &hf_HI2Operations_MAP_parameters_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_MAP_parameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 MAP_parameters_set_of, hf_index, ett_HI2Operations_MAP_parameters);

  return offset;
}


static const ber_sequence_t Services_Information_sequence[] = {
  { &hf_HI2Operations_iSUP_parameters, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_ISUP_parameters },
  { &hf_HI2Operations_dSS1_parameters_codeset_0, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_DSS1_parameters_codeset_0 },
  { &hf_HI2Operations_mAP_parameters, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_MAP_parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Services_Information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Services_Information_sequence, hf_index, ett_HI2Operations_Services_Information);

  return offset;
}


static const ber_sequence_t ISUP_SS_parameters_set_of[1] = {
  { &hf_HI2Operations_ISUP_SS_parameters_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_ISUP_SS_parameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ISUP_SS_parameters_set_of, hf_index, ett_HI2Operations_ISUP_SS_parameters);

  return offset;
}


static const ber_sequence_t DSS1_SS_parameters_codeset_0_set_of[1] = {
  { &hf_HI2Operations_DSS1_SS_parameters_codeset_0_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_SS_parameters_codeset_0(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_SS_parameters_codeset_0_set_of, hf_index, ett_HI2Operations_DSS1_SS_parameters_codeset_0);

  return offset;
}


static const ber_sequence_t DSS1_SS_parameters_codeset_4_set_of[1] = {
  { &hf_HI2Operations_DSS1_SS_parameters_codeset_4_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_SS_parameters_codeset_4(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_SS_parameters_codeset_4_set_of, hf_index, ett_HI2Operations_DSS1_SS_parameters_codeset_4);

  return offset;
}


static const ber_sequence_t DSS1_SS_parameters_codeset_5_set_of[1] = {
  { &hf_HI2Operations_DSS1_SS_parameters_codeset_5_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_SS_parameters_codeset_5(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_SS_parameters_codeset_5_set_of, hf_index, ett_HI2Operations_DSS1_SS_parameters_codeset_5);

  return offset;
}


static const ber_sequence_t DSS1_SS_parameters_codeset_6_set_of[1] = {
  { &hf_HI2Operations_DSS1_SS_parameters_codeset_6_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_SS_parameters_codeset_6(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_SS_parameters_codeset_6_set_of, hf_index, ett_HI2Operations_DSS1_SS_parameters_codeset_6);

  return offset;
}


static const ber_sequence_t DSS1_SS_parameters_codeset_7_set_of[1] = {
  { &hf_HI2Operations_DSS1_SS_parameters_codeset_7_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_SS_parameters_codeset_7(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_SS_parameters_codeset_7_set_of, hf_index, ett_HI2Operations_DSS1_SS_parameters_codeset_7);

  return offset;
}


static const ber_sequence_t DSS1_SS_Invoke_Components_set_of[1] = {
  { &hf_HI2Operations_DSS1_SS_Invoke_Components_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_SS_Invoke_Components(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_SS_Invoke_Components_set_of, hf_index, ett_HI2Operations_DSS1_SS_Invoke_Components);

  return offset;
}


static const ber_sequence_t MAP_SS_Parameters_set_of[1] = {
  { &hf_HI2Operations_MAP_SS_Parameters_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_MAP_SS_Parameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 MAP_SS_Parameters_set_of, hf_index, ett_HI2Operations_MAP_SS_Parameters);

  return offset;
}


static const ber_sequence_t MAP_SS_Invoke_Components_set_of[1] = {
  { &hf_HI2Operations_MAP_SS_Invoke_Components_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_MAP_SS_Invoke_Components(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 MAP_SS_Invoke_Components_set_of, hf_index, ett_HI2Operations_MAP_SS_Invoke_Components);

  return offset;
}


static const ber_sequence_t Standard_Supplementary_Services_sequence[] = {
  { &hf_HI2Operations_iSUP_SS_parameters, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_ISUP_SS_parameters },
  { &hf_HI2Operations_dSS1_SS_parameters_codeset_0, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_DSS1_SS_parameters_codeset_0 },
  { &hf_HI2Operations_dSS1_SS_parameters_codeset_4, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_DSS1_SS_parameters_codeset_4 },
  { &hf_HI2Operations_dSS1_SS_parameters_codeset_5, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_DSS1_SS_parameters_codeset_5 },
  { &hf_HI2Operations_dSS1_SS_parameters_codeset_6, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_DSS1_SS_parameters_codeset_6 },
  { &hf_HI2Operations_dSS1_SS_parameters_codeset_7, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_DSS1_SS_parameters_codeset_7 },
  { &hf_HI2Operations_dSS1_SS_Invoke_components, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_DSS1_SS_Invoke_Components },
  { &hf_HI2Operations_mAP_SS_Parameters, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_MAP_SS_Parameters },
  { &hf_HI2Operations_mAP_SS_Invoke_Components, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_MAP_SS_Invoke_Components },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Standard_Supplementary_Services(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Standard_Supplementary_Services_sequence, hf_index, ett_HI2Operations_Standard_Supplementary_Services);

  return offset;
}


static const value_string HI2Operations_SimpleIndication_vals[] = {
  {   0, "call-Waiting-Indication" },
  {   1, "add-conf-Indication" },
  {   2, "call-on-hold-Indication" },
  {   3, "retrieve-Indication" },
  {   4, "suspend-Indication" },
  {   5, "resume-Indication" },
  {   6, "answer-Indication" },
  { 0, NULL }
};


static int
dissect_HI2Operations_SimpleIndication(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_SciDataMode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string HI2Operations_Non_Standard_Supplementary_Services_item_vals[] = {
  {   1, "simpleIndication" },
  {   2, "sciData" },
  { 0, NULL }
};

static const ber_choice_t Non_Standard_Supplementary_Services_item_choice[] = {
  {   1, &hf_HI2Operations_simpleIndication, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_SimpleIndication },
  {   2, &hf_HI2Operations_sciData, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_SciDataMode },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Non_Standard_Supplementary_Services_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Non_Standard_Supplementary_Services_item_choice, hf_index, ett_HI2Operations_Non_Standard_Supplementary_Services_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t Non_Standard_Supplementary_Services_set_of[1] = {
  { &hf_HI2Operations_Non_Standard_Supplementary_Services_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_Non_Standard_Supplementary_Services_item },
};

static int
dissect_HI2Operations_Non_Standard_Supplementary_Services(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 Non_Standard_Supplementary_Services_set_of, hf_index, ett_HI2Operations_Non_Standard_Supplementary_Services);

  return offset;
}


static const ber_sequence_t Other_Services_set_of[1] = {
  { &hf_HI2Operations_Other_Services_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_Other_Services(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 Other_Services_set_of, hf_index, ett_HI2Operations_Other_Services);

  return offset;
}


static const ber_sequence_t Supplementary_Services_sequence[] = {
  { &hf_HI2Operations_standard_Supplementary_Services, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Standard_Supplementary_Services },
  { &hf_HI2Operations_non_Standard_Supplementary_Services, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Non_Standard_Supplementary_Services },
  { &hf_HI2Operations_other_Services, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Other_Services },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Supplementary_Services(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Supplementary_Services_sequence, hf_index, ett_HI2Operations_Supplementary_Services);

  return offset;
}



static int
dissect_HI2Operations_X25Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string HI2Operations_DataNodeAddress_vals[] = {
  {   1, "ipAddress" },
  {   2, "x25Address" },
  { 0, NULL }
};

static const ber_choice_t DataNodeAddress_choice[] = {
  {   1, &hf_HI2Operations_ipAddress, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IPAddress },
  {   2, &hf_HI2Operations_x25Address, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_X25Address },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_DataNodeAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DataNodeAddress_choice, hf_index, ett_HI2Operations_DataNodeAddress,
                                 NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_100(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t GPRS_parameters_sequence[] = {
  { &hf_HI2Operations_pDP_address_allocated_to_the_target, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_DataNodeAddress },
  { &hf_HI2Operations_aPN   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_100 },
  { &hf_HI2Operations_pDP_type, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_2 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_GPRS_parameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GPRS_parameters_sequence, hf_index, ett_HI2Operations_GPRS_parameters);

  return offset;
}


static const ber_sequence_t Services_Data_Information_sequence[] = {
  { &hf_HI2Operations_gPRS_parameters, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_GPRS_parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Services_Data_Information(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Services_Data_Information_sequence, hf_index, ett_HI2Operations_Services_Data_Information);

  return offset;
}


static const ber_sequence_t PartyInformation_sequence[] = {
  { &hf_HI2Operations_party_Qualifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_party_Qualifier },
  { &hf_HI2Operations_partyIdentity, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_partyIdentity },
  { &hf_HI2Operations_services_Information, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Services_Information },
  { &hf_HI2Operations_supplementary_Services_Information, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Supplementary_Services },
  { &hf_HI2Operations_services_Data_Information, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Services_Data_Information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_PartyInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PartyInformation_sequence, hf_index, ett_HI2Operations_PartyInformation);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_10_OF_PartyInformation_set_of[1] = {
  { &hf_HI2Operations_partyInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_PartyInformation },
};

static int
dissect_HI2Operations_SET_SIZE_1_10_OF_PartyInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_1_10_OF_PartyInformation_set_of, hf_index, ett_HI2Operations_SET_SIZE_1_10_OF_PartyInformation);

  return offset;
}


static const value_string HI2Operations_CCLink_State_vals[] = {
  {   1, "setUpInProcess" },
  {   2, "callActive" },
  {   3, "callReleased" },
  {   4, "lack-of-resource" },
  { 0, NULL }
};


static int
dissect_HI2Operations_CCLink_State(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t CallContentLinkCharacteristics_sequence[] = {
  { &hf_HI2Operations_cCLink_State, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_CCLink_State },
  { &hf_HI2Operations_release_Time, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_TimeStamp },
  { &hf_HI2Operations_release_Reason, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_2 },
  { &hf_HI2Operations_lEMF_Address, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_CalledPartyNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CallContentLinkCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallContentLinkCharacteristics_sequence, hf_index, ett_HI2Operations_CallContentLinkCharacteristics);

  return offset;
}


static const ber_sequence_t T_callContentLinkInformation_sequence[] = {
  { &hf_HI2Operations_cCLink1Characteristics, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallContentLinkCharacteristics },
  { &hf_HI2Operations_cCLink2Characteristics, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallContentLinkCharacteristics },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_callContentLinkInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_callContentLinkInformation_sequence, hf_index, ett_HI2Operations_T_callContentLinkInformation);

  return offset;
}


static const value_string HI2Operations_T_nature_Of_The_intercepted_call_vals[] = {
  {   0, "gSM-ISDN-PSTN-circuit-call" },
  {   1, "gSM-SMS-Message" },
  {   2, "uUS4-Messages" },
  {   3, "tETRA-circuit-call" },
  {   4, "teTRA-Packet-Data" },
  {   5, "gPRS-Packet-Data" },
  {   6, "uMTS-circuit-call" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_nature_Of_The_intercepted_call(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_T_initiator_vals[] = {
  {   0, "target" },
  {   1, "server" },
  {   2, "undefined-party" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_initiator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_T_transfer_status_vals[] = {
  {   0, "succeed-transfer" },
  {   1, "not-succeed-transfer" },
  {   2, "undefined" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_transfer_status(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_T_other_message_vals[] = {
  {   0, "yes" },
  {   1, "no" },
  {   2, "undefined" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_other_message(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_270(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t T_sMS_Contents_sequence[] = {
  { &hf_HI2Operations_initiator, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_initiator },
  { &hf_HI2Operations_transfer_status, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_transfer_status },
  { &hf_HI2Operations_other_message, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_other_message },
  { &hf_HI2Operations_content, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_270 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_sMS_Contents(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_sMS_Contents_sequence, hf_index, ett_HI2Operations_T_sMS_Contents);

  return offset;
}


static const ber_sequence_t SMS_report_sequence[] = {
  { &hf_HI2Operations_communicationIdentifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CommunicationIdentifier },
  { &hf_HI2Operations_timeStamp, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_TimeStamp },
  { &hf_HI2Operations_sMS_Contents, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_sMS_Contents },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_SMS_report(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMS_report_sequence, hf_index, ett_HI2Operations_SMS_report);

  return offset;
}



static int
dissect_HI2Operations_CC_Link_Identifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t National_Parameters_set_of[1] = {
  { &hf_HI2Operations_National_Parameters_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_National_Parameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 National_Parameters_set_of, hf_index, ett_HI2Operations_National_Parameters);

  return offset;
}



static int
dissect_HI2Operations_GPRSCorrelationNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string HI2Operations_GPRSEvent_vals[] = {
  {   1, "pDPContextActivation" },
  {   2, "startOfInterceptionWithPDPContextActive" },
  {   4, "pDPContextDeactivation" },
  {   5, "gPRSAttach" },
  {   6, "gPRSDetach" },
  {  10, "cellOrRAUpdate" },
  {  11, "sMS" },
  {  13, "pDPContextModification" },
  { 0, NULL }
};


static int
dissect_HI2Operations_GPRSEvent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_GPRSOperationErrorCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string HI2Operations_UmtsQos_vals[] = {
  {   1, "qosMobileRadio" },
  {   2, "qosGn" },
  { 0, NULL }
};

static const ber_choice_t UmtsQos_choice[] = {
  {   1, &hf_HI2Operations_qosMobileRadio, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  {   2, &hf_HI2Operations_qosGn , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_UmtsQos(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UmtsQos_choice, hf_index, ett_HI2Operations_UmtsQos,
                                 NULL);

  return offset;
}


static const value_string HI2Operations_IMSevent_vals[] = {
  {   1, "unfilteredSIPmessage" },
  {   2, "sIPheaderOnly" },
  { 0, NULL }
};


static int
dissect_HI2Operations_IMSevent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_20(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_5_17(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_LIIDType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_HI2Operations_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_1_100(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string HI2Operations_LocationType_vals[] = {
  {   0, "geodeticData" },
  {   1, "nameAddress" },
  { 0, NULL }
};

static const ber_choice_t LocationType_choice[] = {
  {   0, &hf_HI2Operations_geodeticData, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BIT_STRING },
  {   1, &hf_HI2Operations_nameAddress, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString_SIZE_1_100 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_LocationType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 LocationType_choice, hf_index, ett_HI2Operations_LocationType,
                                 NULL);

  return offset;
}


static const value_string HI2Operations_DirectionType_vals[] = {
  {   0, "toTarget" },
  {   1, "fromTarget" },
  {   2, "unknown" },
  { 0, NULL }
};


static int
dissect_HI2Operations_DirectionType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_IRITransactionType_vals[] = {
  {   0, "iRIbegin" },
  {   1, "iRIcontinue" },
  {   2, "iRIend" },
  {   3, "iRIreport" },
  { 0, NULL }
};


static int
dissect_HI2Operations_IRITransactionType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_ProtocolVersion_vals[] = {
  {   3, "io3" },
  { 0, NULL }
};


static int
dissect_HI2Operations_ProtocolVersion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_CaseId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_HI2Operations_AccessingElementId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_HI2Operations_EventTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_HI2Operations_VisibleString_SIZE_1_25_(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_HI2Operations_VisibleString_SIZE_1_15_(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t CallId_sequence[] = {
  { &hf_HI2Operations_sequencenumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_25_ },
  { &hf_HI2Operations_systemidentity, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_15_ },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CallId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallId_sequence, hf_index, ett_HI2Operations_CallId);

  return offset;
}



static int
dissect_HI2Operations_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_HI2Operations_VisibleString_SIZE_1_32_(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_HI2Operations_VisibleString_SIZE_1_48_(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t PartyId_sequence[] = {
  { &hf_HI2Operations_reserved0, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_reserved1, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_reserved2, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_reserved3, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_reserved4, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_reserved5, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_dn    , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_15_ },
  { &hf_HI2Operations_userProvided, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_15_ },
  { &hf_HI2Operations_reserved6, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_reserved7, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_ipAddress_01, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_32_ },
  { &hf_HI2Operations_reserved8, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_trunkId, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_32_ },
  { &hf_HI2Operations_reserved9, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_genericAddress, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_32_ },
  { &hf_HI2Operations_genericDigits, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_32_ },
  { &hf_HI2Operations_genericName, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_48_ },
  { &hf_HI2Operations_port  , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_32_ },
  { &hf_HI2Operations_context, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_32_ },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_PartyId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PartyId_sequence, hf_index, ett_HI2Operations_PartyId);

  return offset;
}


static const ber_sequence_t Answer_sequence[] = {
  { &hf_HI2Operations_caseId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CaseId },
  { &hf_HI2Operations_accessingElementId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_AccessingElementId },
  { &hf_HI2Operations_eventTime, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_EventTime },
  { &hf_HI2Operations_callId, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallId },
  { &hf_HI2Operations_answering, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Answer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Answer_sequence, hf_index, ett_HI2Operations_Answer);

  return offset;
}



static int
dissect_HI2Operations_VisibleString_SIZE_1_20_(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t T_sepCCCpair_sequence[] = {
  { &hf_HI2Operations_sepXmitCCC, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_20_ },
  { &hf_HI2Operations_sepRecvCCC, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_20_ },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_sepCCCpair(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_sepCCCpair_sequence, hf_index, ett_HI2Operations_T_sepCCCpair);

  return offset;
}


static const value_string HI2Operations_CCCId_vals[] = {
  {   0, "combCCC" },
  {   1, "sepCCCpair" },
  { 0, NULL }
};

static const ber_choice_t CCCId_choice[] = {
  {   0, &hf_HI2Operations_combCCC, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_20_ },
  {   1, &hf_HI2Operations_sepCCCpair, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_sepCCCpair },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CCCId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CCCId_choice, hf_index, ett_HI2Operations_CCCId,
                                 NULL);

  return offset;
}


static const value_string HI2Operations_FlowDirection_vals[] = {
  {   1, "downstream" },
  {   2, "upstream" },
  {   3, "downstream-and-upstream" },
  { 0, NULL }
};


static int
dissect_HI2Operations_FlowDirection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t CCClose_sequence[] = {
  { &hf_HI2Operations_caseId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CaseId },
  { &hf_HI2Operations_accessingElementId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_AccessingElementId },
  { &hf_HI2Operations_eventTime, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_EventTime },
  { &hf_HI2Operations_cCCId , BER_CLASS_CON, 3, BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_CCCId },
  { &hf_HI2Operations_flowDirection, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_FlowDirection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CCClose(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CCClose_sequence, hf_index, ett_HI2Operations_CCClose);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CallId_sequence_of[1] = {
  { &hf_HI2Operations_ccOpenTime_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_CallId },
};

static int
dissect_HI2Operations_SEQUENCE_OF_CallId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CallId_sequence_of, hf_index, ett_HI2Operations_SEQUENCE_OF_CallId);

  return offset;
}


static const value_string HI2Operations_T_ccOpenOption_vals[] = {
  {   3, "ccOpenTime" },
  {   4, "reserved0" },
  { 0, NULL }
};

static const ber_choice_t T_ccOpenOption_choice[] = {
  {   3, &hf_HI2Operations_ccOpenTime, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_SEQUENCE_OF_CallId },
  {   4, &hf_HI2Operations_reserved0, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_ccOpenOption(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_ccOpenOption_choice, hf_index, ett_HI2Operations_T_ccOpenOption,
                                 NULL);

  return offset;
}



static int
dissect_HI2Operations_SDP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t CCOpen_sequence[] = {
  { &hf_HI2Operations_caseId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CaseId },
  { &hf_HI2Operations_accessingElementId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_AccessingElementId },
  { &hf_HI2Operations_eventTime, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_EventTime },
  { &hf_HI2Operations_ccOpenOption, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_T_ccOpenOption },
  { &hf_HI2Operations_cCCId , BER_CLASS_CON, 5, BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_CCCId },
  { &hf_HI2Operations_subject, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SDP },
  { &hf_HI2Operations_associate, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SDP },
  { &hf_HI2Operations_flowDirection, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_HI2Operations_FlowDirection },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CCOpen(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CCOpen_sequence, hf_index, ett_HI2Operations_CCOpen);

  return offset;
}


static const value_string HI2Operations_T_input_vals[] = {
  {   6, "userinput" },
  {   7, "translationinput" },
  { 0, NULL }
};

static const ber_choice_t T_input_choice[] = {
  {   6, &hf_HI2Operations_userinput, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_32_ },
  {   7, &hf_HI2Operations_translationinput, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_32_ },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_input(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_input_choice, hf_index, ett_HI2Operations_T_input,
                                 NULL);

  return offset;
}



static int
dissect_HI2Operations_TransitCarrierId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t Origination_sequence[] = {
  { &hf_HI2Operations_caseId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CaseId },
  { &hf_HI2Operations_accessingElementId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_AccessingElementId },
  { &hf_HI2Operations_eventTime, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_EventTime },
  { &hf_HI2Operations_callId, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallId },
  { &hf_HI2Operations_calling, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyId },
  { &hf_HI2Operations_called, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyId },
  { &hf_HI2Operations_input , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_T_input },
  { &hf_HI2Operations_reserved0, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_transitCarrierId, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_TransitCarrierId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Origination(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Origination_sequence, hf_index, ett_HI2Operations_Origination);

  return offset;
}


static const ber_sequence_t Redirection_sequence[] = {
  { &hf_HI2Operations_caseId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CaseId },
  { &hf_HI2Operations_accessingElementId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_AccessingElementId },
  { &hf_HI2Operations_eventTime, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_EventTime },
  { &hf_HI2Operations_old   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallId },
  { &hf_HI2Operations_redirectedto, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyId },
  { &hf_HI2Operations_transitCarrierId, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_TransitCarrierId },
  { &hf_HI2Operations_reserved0, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_reserved1, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_new   , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallId },
  { &hf_HI2Operations_redirectedfrom, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Redirection(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Redirection_sequence, hf_index, ett_HI2Operations_Redirection);

  return offset;
}


static const ber_sequence_t Release_sequence[] = {
  { &hf_HI2Operations_caseId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CaseId },
  { &hf_HI2Operations_accessingElementId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_AccessingElementId },
  { &hf_HI2Operations_eventTime, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_EventTime },
  { &hf_HI2Operations_callId, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Release(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Release_sequence, hf_index, ett_HI2Operations_Release);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_1_100_(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RedirectedFromInfo_sequence[] = {
  { &hf_HI2Operations_lastRedirecting, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyId },
  { &hf_HI2Operations_originalCalled, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyId },
  { &hf_HI2Operations_numRedirections, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_1_100_ },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_RedirectedFromInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RedirectedFromInfo_sequence, hf_index, ett_HI2Operations_RedirectedFromInfo);

  return offset;
}


static const ber_sequence_t TerminationAttempt_sequence[] = {
  { &hf_HI2Operations_caseId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CaseId },
  { &hf_HI2Operations_accessingElementId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_AccessingElementId },
  { &hf_HI2Operations_eventTime, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_EventTime },
  { &hf_HI2Operations_callId, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallId },
  { &hf_HI2Operations_calling, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyId },
  { &hf_HI2Operations_called, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyId },
  { &hf_HI2Operations_reserved0, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_redirectedFromInfo, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_RedirectedFromInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_TerminationAttempt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TerminationAttempt_sequence, hf_index, ett_HI2Operations_TerminationAttempt);

  return offset;
}


static const value_string HI2Operations_ResourceState_vals[] = {
  {   1, "reserved" },
  {   2, "committed" },
  { 0, NULL }
};


static int
dissect_HI2Operations_ResourceState(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t CCChange_sequence[] = {
  { &hf_HI2Operations_caseId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CaseId },
  { &hf_HI2Operations_accessingElementId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_AccessingElementId },
  { &hf_HI2Operations_eventTime, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_EventTime },
  { &hf_HI2Operations_callId, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallId },
  { &hf_HI2Operations_cCCId , BER_CLASS_CON, 4, BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_CCCId },
  { &hf_HI2Operations_subject, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SDP },
  { &hf_HI2Operations_associate, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SDP },
  { &hf_HI2Operations_flowDirection, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_HI2Operations_FlowDirection },
  { &hf_HI2Operations_resourceState, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_ResourceState },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CCChange(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CCChange_sequence, hf_index, ett_HI2Operations_CCChange);

  return offset;
}


static const value_string HI2Operations_AlertingSignal_vals[] = {
  {   0, "notUsed" },
  {   1, "alertingPattern0" },
  {   2, "alertingPattern1" },
  {   3, "alertingPattern2" },
  {   4, "alertingPattern3" },
  {   5, "alertingPattern4" },
  {   6, "callWaitingPattern1" },
  {   7, "callWaitingPattern2" },
  {   8, "callWaitingPattern3" },
  {   9, "callWaitingPattern4" },
  {  10, "bargeInTone" },
  {  11, "alertingPattern5" },
  {  12, "alertingPattern6" },
  {  13, "alertingPattern7" },
  {  14, "alertingPattern8" },
  {  15, "alertingPattern9" },
  { 0, NULL }
};


static int
dissect_HI2Operations_AlertingSignal(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_AudibleSignal_vals[] = {
  {   0, "notUsed" },
  {   1, "dialTone" },
  {   2, "recallDialTone" },
  {   3, "ringbackTone" },
  {   4, "reorderTone" },
  {   5, "busyTone" },
  {   6, "confirmationTone" },
  {   7, "expensiveRouteTone" },
  {   8, "messageWaitingTone" },
  {   9, "receiverOffHookTone" },
  {  10, "specialInfoTone" },
  {  11, "denialTone" },
  {  12, "interceptTone" },
  {  13, "answerTone" },
  {  14, "tonesOff" },
  {  15, "pipTone" },
  {  16, "abbreviatedIntercept" },
  {  17, "abbreviatedCongestion" },
  {  18, "warningTone" },
  {  19, "dialToneBurst" },
  {  20, "numberUnObtainableTone" },
  {  21, "authenticationFailureTone" },
  { 0, NULL }
};


static int
dissect_HI2Operations_AudibleSignal(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_VisibleString_SIZE_1_80_(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_HI2Operations_VisibleString_SIZE_1_40_(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t TerminalDisplayInfo_sequence[] = {
  { &hf_HI2Operations_generalDisplay, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_80_ },
  { &hf_HI2Operations_calledNumber, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_40_ },
  { &hf_HI2Operations_callingNumber, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_40_ },
  { &hf_HI2Operations_callingName, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_40_ },
  { &hf_HI2Operations_originalCalledNumber, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_40_ },
  { &hf_HI2Operations_lastRedirectingNumber, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_40_ },
  { &hf_HI2Operations_redirectingName, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_40_ },
  { &hf_HI2Operations_redirectingReason, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_40_ },
  { &hf_HI2Operations_messageWaitingNotif, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_40_ },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_TerminalDisplayInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TerminalDisplayInfo_sequence, hf_index, ett_HI2Operations_TerminalDisplayInfo);

  return offset;
}



static int
dissect_HI2Operations_VisibleString_SIZE_1_128_(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t NetworkSignal_sequence[] = {
  { &hf_HI2Operations_caseId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CaseId },
  { &hf_HI2Operations_accessingElementId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_AccessingElementId },
  { &hf_HI2Operations_eventTime, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_EventTime },
  { &hf_HI2Operations_callId, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallId },
  { &hf_HI2Operations_alertingSignal, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_AlertingSignal },
  { &hf_HI2Operations_subjectAudibleSignal, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_AudibleSignal },
  { &hf_HI2Operations_terminalDisplayInfo, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_TerminalDisplayInfo },
  { &hf_HI2Operations_other , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_128_ },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_NetworkSignal(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NetworkSignal_sequence, hf_index, ett_HI2Operations_NetworkSignal);

  return offset;
}


static const ber_sequence_t T_signal_sequence[] = {
  { &hf_HI2Operations_switchhookFlash, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_128_ },
  { &hf_HI2Operations_dialedDigits, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_128_ },
  { &hf_HI2Operations_featureKey, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_128_ },
  { &hf_HI2Operations_otherSignalingInformation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_128_ },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_signal(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_signal_sequence, hf_index, ett_HI2Operations_T_signal);

  return offset;
}


static const ber_sequence_t SubjectSignal_sequence[] = {
  { &hf_HI2Operations_caseId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CaseId },
  { &hf_HI2Operations_accessingElementId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_AccessingElementId },
  { &hf_HI2Operations_eventTime, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_EventTime },
  { &hf_HI2Operations_callId, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallId },
  { &hf_HI2Operations_signal, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_signal },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_SubjectSignal(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SubjectSignal_sequence, hf_index, ett_HI2Operations_SubjectSignal);

  return offset;
}


static const ber_sequence_t MediaReport_sequence[] = {
  { &hf_HI2Operations_caseId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CaseId },
  { &hf_HI2Operations_accessingElementId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_AccessingElementId },
  { &hf_HI2Operations_eventTime, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_EventTime },
  { &hf_HI2Operations_callId, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallId },
  { &hf_HI2Operations_subject, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SDP },
  { &hf_HI2Operations_associate, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SDP },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_MediaReport(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MediaReport_sequence, hf_index, ett_HI2Operations_MediaReport);

  return offset;
}


static const ber_sequence_t ServiceInstance_sequence[] = {
  { &hf_HI2Operations_caseId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CaseId },
  { &hf_HI2Operations_accessingElementId, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_AccessingElementId },
  { &hf_HI2Operations_eventTime, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_EventTime },
  { &hf_HI2Operations_callId, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallId },
  { &hf_HI2Operations_relatedCallId, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_CallId },
  { &hf_HI2Operations_serviceName, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString_SIZE_1_128_ },
  { &hf_HI2Operations_firstCallCalling, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyId },
  { &hf_HI2Operations_secondCallCalling, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyId },
  { &hf_HI2Operations_called, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyId },
  { &hf_HI2Operations_calling, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_ServiceInstance(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceInstance_sequence, hf_index, ett_HI2Operations_ServiceInstance);

  return offset;
}


static const value_string HI2Operations_Message_vals[] = {
  {   1, "answer" },
  {   2, "ccclose" },
  {   3, "ccopen" },
  {   4, "reserved0" },
  {   5, "origination" },
  {   6, "reserved1" },
  {   7, "redirection" },
  {   8, "release" },
  {   9, "reserved2" },
  {  10, "terminationattempt" },
  {  11, "reserved" },
  {  12, "ccchange" },
  {  13, "reserved3" },
  {  14, "reserved4" },
  {  15, "reserved5" },
  {  16, "networksignal" },
  {  17, "subjectsignal" },
  {  18, "mediareport" },
  {  19, "serviceinstance" },
  { 0, NULL }
};

static const ber_choice_t Message_choice[] = {
  {   1, &hf_HI2Operations_answer, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_Answer },
  {   2, &hf_HI2Operations_ccclose, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CCClose },
  {   3, &hf_HI2Operations_ccopen, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CCOpen },
  {   4, &hf_HI2Operations_reserved0, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  {   5, &hf_HI2Operations_origination, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_HI2Operations_Origination },
  {   6, &hf_HI2Operations_reserved1, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  {   7, &hf_HI2Operations_redirection, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_HI2Operations_Redirection },
  {   8, &hf_HI2Operations_release, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_HI2Operations_Release },
  {   9, &hf_HI2Operations_reserved2, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  {  10, &hf_HI2Operations_terminationattempt, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TerminationAttempt },
  {  11, &hf_HI2Operations_reserved, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  {  12, &hf_HI2Operations_ccchange, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CCChange },
  {  13, &hf_HI2Operations_reserved3, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  {  14, &hf_HI2Operations_reserved4, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  {  15, &hf_HI2Operations_reserved5, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  {  16, &hf_HI2Operations_networksignal, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NetworkSignal },
  {  17, &hf_HI2Operations_subjectsignal, BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_HI2Operations_SubjectSignal },
  {  18, &hf_HI2Operations_mediareport, BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_HI2Operations_MediaReport },
  {  19, &hf_HI2Operations_serviceinstance, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_HI2Operations_ServiceInstance },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Message(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Message_choice, hf_index, ett_HI2Operations_Message,
                                 NULL);

  return offset;
}


static const ber_sequence_t CdcPdu_sequence[] = {
  { &hf_HI2Operations_protocolVersion, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_ProtocolVersion },
  { &hf_HI2Operations_message, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_Message },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CdcPdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CdcPdu_sequence, hf_index, ett_HI2Operations_CdcPdu);

  return offset;
}


static const value_string HI2Operations_UserSignalType_vals[] = {
  {   0, "copySignal" },
  {   1, "interpretedSignal" },
  {   2, "cdcPdu" },
  { 0, NULL }
};

static const ber_choice_t UserSignalType_choice[] = {
  {   0, &hf_HI2Operations_copySignal, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BIT_STRING },
  {   1, &hf_HI2Operations_interpretedSignal, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  {   2, &hf_HI2Operations_cdcPdu, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CdcPdu },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_UserSignalType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UserSignalType_choice, hf_index, ett_HI2Operations_UserSignalType,
                                 NULL);

  return offset;
}


static const ber_sequence_t TARGETACTIVITYMONITOR_1_sequence[] = {
  { &hf_HI2Operations_version, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  { &hf_HI2Operations_lIInstanceid, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_LIIDType },
  { &hf_HI2Operations_timestamp, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTCTime },
  { &hf_HI2Operations_targetLocation, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_LocationType },
  { &hf_HI2Operations_direction, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_DirectionType },
  { &hf_HI2Operations_iRITransaction, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRITransactionType },
  { &hf_HI2Operations_iRITransactionNumber, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  { &hf_HI2Operations_userSignal, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_UserSignalType },
  { &hf_HI2Operations_cryptoCheckSum, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_TARGETACTIVITYMONITOR_1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TARGETACTIVITYMONITOR_1_sequence, hf_index, ett_HI2Operations_TARGETACTIVITYMONITOR_1);

  return offset;
}


static const value_string HI2Operations_LDIevent_vals[] = {
  {   1, "targetEntersIA" },
  {   2, "targetLeavesIA" },
  { 0, NULL }
};


static int
dissect_HI2Operations_LDIevent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_cc_set_of[1] = {
  { &hf_HI2Operations_cc_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING },
};

static int
dissect_HI2Operations_T_cc(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_cc_set_of, hf_index, ett_HI2Operations_T_cc);

  return offset;
}


static const ber_sequence_t IRI_to_CC_Correlation_sequence[] = {
  { &hf_HI2Operations_cc    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_cc },
  { &hf_HI2Operations_iri   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_IRI_to_CC_Correlation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IRI_to_CC_Correlation_sequence, hf_index, ett_HI2Operations_IRI_to_CC_Correlation);

  return offset;
}



static int
dissect_HI2Operations_IRI_to_IRI_Correlation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t T_both_IRI_CC_sequence[] = {
  { &hf_HI2Operations_iri_CC, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_to_CC_Correlation },
  { &hf_HI2Operations_iri_IRI, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_to_IRI_Correlation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_both_IRI_CC(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_both_IRI_CC_sequence, hf_index, ett_HI2Operations_T_both_IRI_CC);

  return offset;
}


static const value_string HI2Operations_CorrelationValues_vals[] = {
  {   0, "iri-to-CC" },
  {   1, "iri-to-iri" },
  {   2, "both-IRI-CC" },
  { 0, NULL }
};

static const ber_choice_t CorrelationValues_choice[] = {
  {   0, &hf_HI2Operations_iri_to_CC, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_to_CC_Correlation },
  {   1, &hf_HI2Operations_iri_to_iri, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_to_IRI_Correlation },
  {   2, &hf_HI2Operations_both_IRI_CC, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_both_IRI_CC },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CorrelationValues(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CorrelationValues_choice, hf_index, ett_HI2Operations_CorrelationValues,
                                 NULL);

  return offset;
}



static int
dissect_HI2Operations_TLIIdType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_HI2Operations_MCCType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_HI2Operations_MNCType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_HI2Operations_LocationAreaType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_HI2Operations_CellIdType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t TETRACGIType_sequence[] = {
  { &hf_HI2Operations_mcc_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_MCCType },
  { &hf_HI2Operations_mnc_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_MNCType },
  { &hf_HI2Operations_lai_01, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_LocationAreaType },
  { &hf_HI2Operations_cI    , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_CellIdType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_TETRACGIType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TETRACGIType_sequence, hf_index, ett_HI2Operations_TETRACGIType);

  return offset;
}



static int
dissect_HI2Operations_SSIType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t TSIType_sequence[] = {
  { &hf_HI2Operations_mcc_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_MCCType },
  { &hf_HI2Operations_mnc_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_MNCType },
  { &hf_HI2Operations_ssi   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_SSIType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_TSIType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TSIType_sequence, hf_index, ett_HI2Operations_TSIType);

  return offset;
}



static int
dissect_HI2Operations_NumericString_SIZE_20(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_HI2Operations_BIT_STRING_SIZE_32(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_HI2Operations_BIT_STRING_SIZE_128(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_HI2Operations_TEIType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const value_string HI2Operations_TETRAAddressType_vals[] = {
  {   0, "tETRAaddress" },
  {   1, "pISNaddress" },
  {   2, "iP4address" },
  {   3, "iP6address" },
  {   4, "e164address" },
  {   5, "tEI" },
  { 0, NULL }
};

static const ber_choice_t TETRAAddressType_choice[] = {
  {   0, &hf_HI2Operations_tETRAaddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TSIType },
  {   1, &hf_HI2Operations_pISNaddress, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NumericString_SIZE_20 },
  {   2, &hf_HI2Operations_iP4address, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BIT_STRING_SIZE_32 },
  {   3, &hf_HI2Operations_iP6address, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BIT_STRING_SIZE_128 },
  {   4, &hf_HI2Operations_e164address, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NumericString_SIZE_20 },
  {   5, &hf_HI2Operations_tEI   , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TEIType },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_TETRAAddressType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TETRAAddressType_choice, hf_index, ett_HI2Operations_TETRAAddressType,
                                 NULL);

  return offset;
}


static const value_string HI2Operations_LocationType_en301040_vals[] = {
  {   0, "mSLoc" },
  {   1, "lSLoc" },
  { 0, NULL }
};

static const ber_choice_t LocationType_en301040_choice[] = {
  {   0, &hf_HI2Operations_mSLoc , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TETRACGIType },
  {   1, &hf_HI2Operations_lSLoc , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TETRAAddressType },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_LocationType_en301040(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 LocationType_en301040_choice, hf_index, ett_HI2Operations_LocationType_en301040,
                                 NULL);

  return offset;
}


static const value_string HI2Operations_ActivityClassType_vals[] = {
  {   0, "allServices" },
  {   1, "tETRASpeech" },
  {   2, "singleSlotData24" },
  {   3, "singleSlotData48" },
  {   4, "singleSlotData72" },
  {   5, "multiSlotData224" },
  {   6, "multiSlotData248" },
  {   7, "multiSlotData272" },
  {   8, "multiSlotData324" },
  {   9, "multiSlotData348" },
  {  10, "multiSlotData372" },
  {  11, "multiSlotData424" },
  {  12, "multiSlotData448" },
  {  13, "multiSlotData472" },
  {  14, "sDSType1" },
  {  15, "sDSType2" },
  {  16, "sDSType3" },
  {  17, "sDSType4" },
  {  18, "status" },
  {  19, "sDSACKType1" },
  {  20, "sDSACKType2" },
  {  21, "sDSACKType3" },
  {  22, "sDSACKType4" },
  {  23, "statusack" },
  {  24, "sDSAcknowledgementsuccess" },
  {  25, "sDSAcknowledgementfail" },
  {  26, "sCLNSPacketData" },
  {  27, "cONSPacketData" },
  {  28, "internetProtocol" },
  {  29, "swMIauthenticationsuccess" },
  {  30, "swMIauthenticationfail" },
  {  31, "iTSIauthenticationsuccess" },
  {  32, "iTSIauthenticationfail" },
  {  33, "oTARSCKsuccess" },
  {  34, "oTARSCKfail" },
  {  35, "oTARGCKsuccess" },
  {  36, "oTARGCKfail" },
  {  37, "oTARCCKsuccess" },
  {  38, "oTARCCKfail" },
  {  39, "tARGETSUSCRIPTIONDISABLEDT" },
  {  40, "tARGETEQUIPMENTDISABLEDT" },
  {  41, "tARGETSUSCRIPTIONDISABLEDP" },
  {  42, "tARGETEQUIPEMENTDISABLEDP" },
  {  43, "tARGETSUBSCRIPTIONENABLED" },
  {  44, "tARGETEQUIPMENTENABLED" },
  {  45, "sessionregistration" },
  {  46, "sessionderegistration" },
  {  47, "mIGRATION" },
  {  48, "rOAMING" },
  {  49, "supplementaryService" },
  { 0, NULL }
};


static int
dissect_HI2Operations_ActivityClassType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_T_callRelation_vals[] = {
  {   0, "begin" },
  {   1, "end" },
  {   2, "continue" },
  {   3, "report" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_callRelation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_T_direction_vals[] = {
  {   0, "toTarget" },
  {   1, "fromTarget" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_direction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_T_scope_vals[] = {
  {   0, "point2Point" },
  {   1, "point2MultiPoint" },
  {   2, "broadcast" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_scope(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_SSType_vals[] = {
  {   0, "ambienceListening" },
  {   1, "adviceofCharge" },
  {   2, "accessPriority" },
  {   3, "areaSelection" },
  {   4, "barringofIncomingCalls" },
  {   5, "barringofOutgoingCalls" },
  {   6, "callAuthorizedbyDispatcher" },
  {   7, "callCompletiontoBusySubscriber" },
  {   8, "callCompletiononNoReply" },
  {   9, "callForwardingonBusy" },
  {  10, "callForwardingonNoReply" },
  {  11, "callForwardingonNotReachable" },
  {  12, "callForwardingUnconditional" },
  {  13, "callingLineIdentificationPresentation" },
  {  14, "callingConnectedLineIdentificationRestriction" },
  {  15, "connectedLineIdentificationPresentation" },
  {  16, "callReport" },
  {  17, "callRetention" },
  {  18, "callWaiting" },
  {  19, "dynamicGroupNumberAssignment" },
  {  20, "discreetListening" },
  {  21, "callHold" },
  {  22, "includeCall" },
  {  23, "lateEntry" },
  {  24, "listSearchCall" },
  {  25, "priorityCall" },
  {  26, "preemptivePriorityCall" },
  {  27, "shortNumberAddressing" },
  {  28, "transferofControl" },
  {  29, "talkingPartyIdentification" },
  { 0, NULL }
};


static int
dissect_HI2Operations_SSType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t ActivityType_sequence[] = {
  { &hf_HI2Operations_cctivity, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_ActivityClassType },
  { &hf_HI2Operations_callRelation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_callRelation },
  { &hf_HI2Operations_direction_01, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_direction },
  { &hf_HI2Operations_scope , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_scope },
  { &hf_HI2Operations_cPlaneData, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_BIT_STRING },
  { &hf_HI2Operations_sStype, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SSType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_ActivityType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActivityType_sequence, hf_index, ett_HI2Operations_ActivityType);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_TETRAAddressType_sequence_of[1] = {
  { &hf_HI2Operations_supplementaryAddress_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_TETRAAddressType },
};

static int
dissect_HI2Operations_SEQUENCE_OF_TETRAAddressType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_TETRAAddressType_sequence_of, hf_index, ett_HI2Operations_SEQUENCE_OF_TETRAAddressType);

  return offset;
}


static const ber_sequence_t AddressType_sequence[] = {
  { &hf_HI2Operations_tSI   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TSIType },
  { &hf_HI2Operations_supplementaryAddress, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SEQUENCE_OF_TETRAAddressType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_AddressType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AddressType_sequence, hf_index, ett_HI2Operations_AddressType);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AddressType_sequence_of[1] = {
  { &hf_HI2Operations_cotargetaddress_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_AddressType },
};

static int
dissect_HI2Operations_SEQUENCE_OF_AddressType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AddressType_sequence_of, hf_index, ett_HI2Operations_SEQUENCE_OF_AddressType);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_LocationType_en301040_sequence_of[1] = {
  { &hf_HI2Operations_cotargetlocation_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_LocationType_en301040 },
};

static int
dissect_HI2Operations_SEQUENCE_OF_LocationType_en301040(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_LocationType_en301040_sequence_of, hf_index, ett_HI2Operations_SEQUENCE_OF_LocationType_en301040);

  return offset;
}


static const ber_sequence_t TARGETACTIVITYMONITORind_sequence[] = {
  { &hf_HI2Operations_tLIInstanceid, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TLIIdType },
  { &hf_HI2Operations_timestamp, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTCTime },
  { &hf_HI2Operations_targetLocation_01, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_LocationType_en301040 },
  { &hf_HI2Operations_targetAction, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_ActivityType },
  { &hf_HI2Operations_supplementaryTargetaddress, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_AddressType },
  { &hf_HI2Operations_cotargetaddress, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SEQUENCE_OF_AddressType },
  { &hf_HI2Operations_cotargetlocation, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SEQUENCE_OF_LocationType_en301040 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_TARGETACTIVITYMONITORind(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TARGETACTIVITYMONITORind_sequence, hf_index, ett_HI2Operations_TARGETACTIVITYMONITORind);

  return offset;
}



static int
dissect_HI2Operations_CircuitIdType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CircuitIdType_sequence_of[1] = {
  { &hf_HI2Operations_cotargetcommsid_item, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_CircuitIdType },
};

static int
dissect_HI2Operations_SEQUENCE_OF_CircuitIdType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CircuitIdType_sequence_of, hf_index, ett_HI2Operations_SEQUENCE_OF_CircuitIdType);

  return offset;
}


static const ber_sequence_t TARGETCOMMSMONITORind_sequence[] = {
  { &hf_HI2Operations_tLIInstanceid, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TLIIdType },
  { &hf_HI2Operations_timestamp, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTCTime },
  { &hf_HI2Operations_targetlocation, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_LocationType_en301040 },
  { &hf_HI2Operations_supplementaryTargetaddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_AddressType },
  { &hf_HI2Operations_targetcommsid, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CircuitIdType },
  { &hf_HI2Operations_cotargetaddress, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SEQUENCE_OF_AddressType },
  { &hf_HI2Operations_cotargetcommsid, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SEQUENCE_OF_CircuitIdType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_TARGETCOMMSMONITORind(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TARGETCOMMSMONITORind_sequence, hf_index, ett_HI2Operations_TARGETCOMMSMONITORind);

  return offset;
}


static const ber_sequence_t TTRAFFICind_sequence[] = {
  { &hf_HI2Operations_tLIInstanceid, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TLIIdType },
  { &hf_HI2Operations_trafficPacket, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_TTRAFFICind(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TTRAFFICind_sequence, hf_index, ett_HI2Operations_TTRAFFICind);

  return offset;
}


static const ber_sequence_t CTTRAFFICind_sequence[] = {
  { &hf_HI2Operations_tLIInstanceid, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TLIIdType },
  { &hf_HI2Operations_trafficPacket, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CTTRAFFICind(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CTTRAFFICind_sequence, hf_index, ett_HI2Operations_CTTRAFFICind);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t National_HI2_ASN1parameters_sequence[] = {
  { &hf_HI2Operations_countryCode, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString_SIZE_2 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_National_HI2_ASN1parameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   National_HI2_ASN1parameters_sequence, hf_index, ett_HI2Operations_National_HI2_ASN1parameters);

  return offset;
}


static const ber_sequence_t IRI_Parameters_sequence[] = {
  { &hf_HI2Operations_domainID, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OBJECT_IDENTIFIER },
  { &hf_HI2Operations_iRIversion, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_iRIversion },
  { &hf_HI2Operations_lawfulInterceptionIdentifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_LawfulInterceptionIdentifier },
  { &hf_HI2Operations_communicationIdentifier, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CommunicationIdentifier },
  { &hf_HI2Operations_timeStamp, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_TimeStamp },
  { &hf_HI2Operations_intercepted_Call_Direct, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_intercepted_Call_Direct },
  { &hf_HI2Operations_intercepted_Call_State, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Intercepted_Call_State },
  { &hf_HI2Operations_ringingDuration, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_3 },
  { &hf_HI2Operations_conversationDuration, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_3 },
  { &hf_HI2Operations_locationOfTheTarget, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Location },
  { &hf_HI2Operations_partyInformation, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SET_SIZE_1_10_OF_PartyInformation },
  { &hf_HI2Operations_callContentLinkInformation, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_callContentLinkInformation },
  { &hf_HI2Operations_release_Reason_Of_Intercepted_Call, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_2 },
  { &hf_HI2Operations_nature_Of_The_intercepted_call, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_nature_Of_The_intercepted_call },
  { &hf_HI2Operations_serverCenterAddress, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_sMS   , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SMS_report },
  { &hf_HI2Operations_cC_Link_Identifier, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_CC_Link_Identifier },
  { &hf_HI2Operations_national_Parameters, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_National_Parameters },
  { &hf_HI2Operations_gPRSCorrelationNumber, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_GPRSCorrelationNumber },
  { &hf_HI2Operations_gPRSevent, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_GPRSEvent },
  { &hf_HI2Operations_sgsnAddress, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_DataNodeAddress },
  { &hf_HI2Operations_gPRSOperationErrorCode, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_GPRSOperationErrorCode },
  { &hf_HI2Operations_ggsnAddress, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_DataNodeAddress },
  { &hf_HI2Operations_qOS   , BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_UmtsQos },
  { &hf_HI2Operations_networkIdentifier, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Network_Identifier },
  { &hf_HI2Operations_sMSOriginatingAddress, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_DataNodeAddress },
  { &hf_HI2Operations_sMSTerminatingAddress, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_DataNodeAddress },
  { &hf_HI2Operations_iMSevent, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_IMSevent },
  { &hf_HI2Operations_sIPMessage, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_servingSGSN_number, BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_20 },
  { &hf_HI2Operations_servingSGSN_address, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_5_17 },
  { &hf_HI2Operations_tARGETACTIVITYMONITOR, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_TARGETACTIVITYMONITOR_1 },
  { &hf_HI2Operations_ldiEvent, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_LDIevent },
  { &hf_HI2Operations_correlation, BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_CorrelationValues },
  { &hf_HI2Operations_tARGETACTIVITYMONITORind, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_TARGETACTIVITYMONITORind },
  { &hf_HI2Operations_tARGETCOMMSMONITORind, BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_TARGETCOMMSMONITORind },
  { &hf_HI2Operations_tTRAFFICind, BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_TTRAFFICind },
  { &hf_HI2Operations_cTTRAFFICind, BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_CTTRAFFICind },
  { &hf_HI2Operations_national_HI2_ASN1parameters, BER_CLASS_CON, 255, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_National_HI2_ASN1parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_IRI_Parameters(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IRI_Parameters_sequence, hf_index, ett_HI2Operations_IRI_Parameters);

  return offset;
}


static const value_string HI2Operations_IRIContent_vals[] = {
  {   1, "iRI-Begin-record" },
  {   2, "iRI-End-record" },
  {   3, "iRI-Continue-record" },
  {   4, "iRI-Report-record" },
  { 0, NULL }
};

static const ber_choice_t IRIContent_choice[] = {
  {   1, &hf_HI2Operations_iRI_Begin_record, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_Parameters },
  {   2, &hf_HI2Operations_iRI_End_record, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_Parameters },
  {   3, &hf_HI2Operations_iRI_Continue_record, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_Parameters },
  {   4, &hf_HI2Operations_iRI_Report_record, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_Parameters },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_IRIContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IRIContent_choice, hf_index, ett_HI2Operations_IRIContent,
                                 NULL);

  return offset;
}


static const ber_sequence_t IRISequence_sequence_of[1] = {
  { &hf_HI2Operations_IRISequence_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_IRIContent },
};

static int
dissect_HI2Operations_IRISequence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      IRISequence_sequence_of, hf_index, ett_HI2Operations_IRISequence);

  return offset;
}


static const value_string HI2Operations_IRIsContent_vals[] = {
  {   0, "iRIContent" },
  {   1, "iRISequence" },
  { 0, NULL }
};

static const ber_choice_t IRIsContent_choice[] = {
  {   0, &hf_HI2Operations_iRIContent, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRIContent },
  {   1, &hf_HI2Operations_iRISequence, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRISequence },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_IRIsContent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IRIsContent_choice, hf_index, ett_HI2Operations_IRIsContent,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_IRIsContent_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_HI2Operations_IRIsContent(FALSE, tvb, 0, &asn1_ctx, tree, hf_HI2Operations_IRIsContent_PDU);
}


/*--- End of included file: packet-HI2Operations-fn.c ---*/
#line 48 "../../asn1/HI2Operations/packet-HI2Operations-template.c"


/*--- proto_register_HI2Operations ----------------------------------------------*/
void proto_register_HI2Operations(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-HI2Operations-hfarr.c ---*/
#line 1 "../../asn1/HI2Operations/packet-HI2Operations-hfarr.c"
    { &hf_HI2Operations_IRIsContent_PDU,
      { "IRIsContent", "HI2Operations.IRIsContent",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_IRIsContent_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_iRIContent,
      { "iRIContent", "HI2Operations.iRIContent",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_IRIContent_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_iRISequence,
      { "iRISequence", "HI2Operations.iRISequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_IRISequence_item,
      { "IRIContent", "HI2Operations.IRIContent",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_IRIContent_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_iRI_Begin_record,
      { "iRI-Begin-record", "HI2Operations.iRI_Begin_record",
        FT_NONE, BASE_NONE, NULL, 0,
        "IRI_Parameters", HFILL }},
    { &hf_HI2Operations_iRI_End_record,
      { "iRI-End-record", "HI2Operations.iRI_End_record",
        FT_NONE, BASE_NONE, NULL, 0,
        "IRI_Parameters", HFILL }},
    { &hf_HI2Operations_iRI_Continue_record,
      { "iRI-Continue-record", "HI2Operations.iRI_Continue_record",
        FT_NONE, BASE_NONE, NULL, 0,
        "IRI_Parameters", HFILL }},
    { &hf_HI2Operations_iRI_Report_record,
      { "iRI-Report-record", "HI2Operations.iRI_Report_record",
        FT_NONE, BASE_NONE, NULL, 0,
        "IRI_Parameters", HFILL }},
    { &hf_HI2Operations_domainID,
      { "domainID", "HI2Operations.domainID",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_HI2Operations_iRIversion,
      { "iRIversion", "HI2Operations.iRIversion",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_iRIversion_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_lawfulInterceptionIdentifier,
      { "lawfulInterceptionIdentifier", "HI2Operations.lawfulInterceptionIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_communicationIdentifier,
      { "communicationIdentifier", "HI2Operations.communicationIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_timeStamp,
      { "timeStamp", "HI2Operations.timeStamp",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_TimeStamp_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_intercepted_Call_Direct,
      { "intercepted-Call-Direct", "HI2Operations.intercepted_Call_Direct",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_intercepted_Call_Direct_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_intercepted_Call_State,
      { "intercepted-Call-State", "HI2Operations.intercepted_Call_State",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_Intercepted_Call_State_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ringingDuration,
      { "ringingDuration", "HI2Operations.ringingDuration",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_HI2Operations_conversationDuration,
      { "conversationDuration", "HI2Operations.conversationDuration",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_HI2Operations_locationOfTheTarget,
      { "locationOfTheTarget", "HI2Operations.locationOfTheTarget",
        FT_NONE, BASE_NONE, NULL, 0,
        "Location", HFILL }},
    { &hf_HI2Operations_partyInformation,
      { "partyInformation", "HI2Operations.partyInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_10_OF_PartyInformation", HFILL }},
    { &hf_HI2Operations_partyInformation_item,
      { "PartyInformation", "HI2Operations.PartyInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_callContentLinkInformation,
      { "callContentLinkInformation", "HI2Operations.callContentLinkInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_cCLink1Characteristics,
      { "cCLink1Characteristics", "HI2Operations.cCLink1Characteristics",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallContentLinkCharacteristics", HFILL }},
    { &hf_HI2Operations_cCLink2Characteristics,
      { "cCLink2Characteristics", "HI2Operations.cCLink2Characteristics",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallContentLinkCharacteristics", HFILL }},
    { &hf_HI2Operations_release_Reason_Of_Intercepted_Call,
      { "release-Reason-Of-Intercepted-Call", "HI2Operations.release_Reason_Of_Intercepted_Call",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_HI2Operations_nature_Of_The_intercepted_call,
      { "nature-Of-The-intercepted-call", "HI2Operations.nature_Of_The_intercepted_call",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_nature_Of_The_intercepted_call_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_serverCenterAddress,
      { "serverCenterAddress", "HI2Operations.serverCenterAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_sMS,
      { "sMS", "HI2Operations.sMS",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMS_report", HFILL }},
    { &hf_HI2Operations_cC_Link_Identifier,
      { "cC-Link-Identifier", "HI2Operations.cC_Link_Identifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_national_Parameters,
      { "national-Parameters", "HI2Operations.national_Parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_gPRSCorrelationNumber,
      { "gPRSCorrelationNumber", "HI2Operations.gPRSCorrelationNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_gPRSevent,
      { "gPRSevent", "HI2Operations.gPRSevent",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_GPRSEvent_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_sgsnAddress,
      { "sgsnAddress", "HI2Operations.sgsnAddress",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_DataNodeAddress_vals), 0,
        "DataNodeAddress", HFILL }},
    { &hf_HI2Operations_gPRSOperationErrorCode,
      { "gPRSOperationErrorCode", "HI2Operations.gPRSOperationErrorCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ggsnAddress,
      { "ggsnAddress", "HI2Operations.ggsnAddress",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_DataNodeAddress_vals), 0,
        "DataNodeAddress", HFILL }},
    { &hf_HI2Operations_qOS,
      { "qOS", "HI2Operations.qOS",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_UmtsQos_vals), 0,
        "UmtsQos", HFILL }},
    { &hf_HI2Operations_networkIdentifier,
      { "networkIdentifier", "HI2Operations.networkIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "Network_Identifier", HFILL }},
    { &hf_HI2Operations_sMSOriginatingAddress,
      { "sMSOriginatingAddress", "HI2Operations.sMSOriginatingAddress",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_DataNodeAddress_vals), 0,
        "DataNodeAddress", HFILL }},
    { &hf_HI2Operations_sMSTerminatingAddress,
      { "sMSTerminatingAddress", "HI2Operations.sMSTerminatingAddress",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_DataNodeAddress_vals), 0,
        "DataNodeAddress", HFILL }},
    { &hf_HI2Operations_iMSevent,
      { "iMSevent", "HI2Operations.iMSevent",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_IMSevent_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_sIPMessage,
      { "sIPMessage", "HI2Operations.sIPMessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_servingSGSN_number,
      { "servingSGSN-number", "HI2Operations.servingSGSN_number",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_20", HFILL }},
    { &hf_HI2Operations_servingSGSN_address,
      { "servingSGSN-address", "HI2Operations.servingSGSN_address",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_5_17", HFILL }},
    { &hf_HI2Operations_tARGETACTIVITYMONITOR,
      { "tARGETACTIVITYMONITOR", "HI2Operations.tARGETACTIVITYMONITOR",
        FT_NONE, BASE_NONE, NULL, 0,
        "TARGETACTIVITYMONITOR_1", HFILL }},
    { &hf_HI2Operations_ldiEvent,
      { "ldiEvent", "HI2Operations.ldiEvent",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_LDIevent_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_correlation,
      { "correlation", "HI2Operations.correlation",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_CorrelationValues_vals), 0,
        "CorrelationValues", HFILL }},
    { &hf_HI2Operations_tARGETACTIVITYMONITORind,
      { "tARGETACTIVITYMONITORind", "HI2Operations.tARGETACTIVITYMONITORind",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_tARGETCOMMSMONITORind,
      { "tARGETCOMMSMONITORind", "HI2Operations.tARGETCOMMSMONITORind",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_tTRAFFICind,
      { "tTRAFFICind", "HI2Operations.tTRAFFICind",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_cTTRAFFICind,
      { "cTTRAFFICind", "HI2Operations.cTTRAFFICind",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_national_HI2_ASN1parameters,
      { "national-HI2-ASN1parameters", "HI2Operations.national_HI2_ASN1parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_communication_Identity_Number,
      { "communication-Identity-Number", "HI2Operations.communication_Identity_Number",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_8", HFILL }},
    { &hf_HI2Operations_network_Identifier,
      { "network-Identifier", "HI2Operations.network_Identifier",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_operator_Identifier,
      { "operator-Identifier", "HI2Operations.operator_Identifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_5", HFILL }},
    { &hf_HI2Operations_network_Element_Identifier,
      { "network-Element-Identifier", "HI2Operations.network_Element_Identifier",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_Network_Element_Identifier_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_e164_Format,
      { "e164-Format", "HI2Operations.e164_Format",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_25", HFILL }},
    { &hf_HI2Operations_x25_Format,
      { "x25-Format", "HI2Operations.x25_Format",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_25", HFILL }},
    { &hf_HI2Operations_iP_Format,
      { "iP-Format", "HI2Operations.iP_Format",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_25", HFILL }},
    { &hf_HI2Operations_dNS_Format,
      { "dNS-Format", "HI2Operations.dNS_Format",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_25", HFILL }},
    { &hf_HI2Operations_iP_Address,
      { "iP-Address", "HI2Operations.iP_Address",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPAddress", HFILL }},
    { &hf_HI2Operations_localTime,
      { "localTime", "HI2Operations.localTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "LocalTimeStamp", HFILL }},
    { &hf_HI2Operations_utcTime,
      { "utcTime", "HI2Operations.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_generalizedTime,
      { "generalizedTime", "HI2Operations.generalizedTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_winterSummerIndication,
      { "winterSummerIndication", "HI2Operations.winterSummerIndication",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_winterSummerIndication_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_party_Qualifier,
      { "party-Qualifier", "HI2Operations.party_Qualifier",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_party_Qualifier_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_partyIdentity,
      { "partyIdentity", "HI2Operations.partyIdentity",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_imei,
      { "imei", "HI2Operations.imei",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_8", HFILL }},
    { &hf_HI2Operations_tei,
      { "tei", "HI2Operations.tei",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_15", HFILL }},
    { &hf_HI2Operations_imsi,
      { "imsi", "HI2Operations.imsi",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3_8", HFILL }},
    { &hf_HI2Operations_callingPartyNumber,
      { "callingPartyNumber", "HI2Operations.callingPartyNumber",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_CallingPartyNumber_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_calledPartyNumber,
      { "calledPartyNumber", "HI2Operations.calledPartyNumber",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_CalledPartyNumber_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_msISDN,
      { "msISDN", "HI2Operations.msISDN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_9", HFILL }},
    { &hf_HI2Operations_sip_uri,
      { "sip-uri", "HI2Operations.sip_uri",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_tel_url,
      { "tel-url", "HI2Operations.tel_url",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_services_Information,
      { "services-Information", "HI2Operations.services_Information",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_supplementary_Services_Information,
      { "supplementary-Services-Information", "HI2Operations.supplementary_Services_Information",
        FT_NONE, BASE_NONE, NULL, 0,
        "Supplementary_Services", HFILL }},
    { &hf_HI2Operations_services_Data_Information,
      { "services-Data-Information", "HI2Operations.services_Data_Information",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_iSUP_Format,
      { "iSUP-Format", "HI2Operations.iSUP_Format",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_25", HFILL }},
    { &hf_HI2Operations_dSS1_Format,
      { "dSS1-Format", "HI2Operations.dSS1_Format",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_25", HFILL }},
    { &hf_HI2Operations_mAP_Format,
      { "mAP-Format", "HI2Operations.mAP_Format",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_25", HFILL }},
    { &hf_HI2Operations_e164_Number,
      { "e164-Number", "HI2Operations.e164_Number",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_25", HFILL }},
    { &hf_HI2Operations_globalCellID,
      { "globalCellID", "HI2Operations.globalCellID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_5_7", HFILL }},
    { &hf_HI2Operations_tetraLocation,
      { "tetraLocation", "HI2Operations.tetraLocation",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_TetraLocation_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_rAI,
      { "rAI", "HI2Operations.rAI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_6", HFILL }},
    { &hf_HI2Operations_gsmLocation,
      { "gsmLocation", "HI2Operations.gsmLocation",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_GSMLocation_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_umtsLocation,
      { "umtsLocation", "HI2Operations.umtsLocation",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_UMTSLocation_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_sAI,
      { "sAI", "HI2Operations.sAI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_7", HFILL }},
    { &hf_HI2Operations_oldRAI,
      { "oldRAI", "HI2Operations.oldRAI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_6", HFILL }},
    { &hf_HI2Operations_ms_Loc,
      { "ms-Loc", "HI2Operations.ms_Loc",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_mcc,
      { "mcc", "HI2Operations.mcc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_HI2Operations_mnc,
      { "mnc", "HI2Operations.mnc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_HI2Operations_lai,
      { "lai", "HI2Operations.lai",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_HI2Operations_ci,
      { "ci", "HI2Operations.ci",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_HI2Operations_ls_Loc,
      { "ls-Loc", "HI2Operations.ls_Loc",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_HI2Operations_geoCoordinates,
      { "geoCoordinates", "HI2Operations.geoCoordinates",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_latitude,
      { "latitude", "HI2Operations.latitude",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_7_10", HFILL }},
    { &hf_HI2Operations_longitude,
      { "longitude", "HI2Operations.longitude",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_8_11", HFILL }},
    { &hf_HI2Operations_mapDatum,
      { "mapDatum", "HI2Operations.mapDatum",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_MapDatum_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_azimuth,
      { "azimuth", "HI2Operations.azimuth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_359", HFILL }},
    { &hf_HI2Operations_utmCoordinates,
      { "utmCoordinates", "HI2Operations.utmCoordinates",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_utm_East,
      { "utm-East", "HI2Operations.utm_East",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_10", HFILL }},
    { &hf_HI2Operations_utm_North,
      { "utm-North", "HI2Operations.utm_North",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_7", HFILL }},
    { &hf_HI2Operations_utmRefCoordinates,
      { "utmRefCoordinates", "HI2Operations.utmRefCoordinates",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_utmref_string,
      { "utmref-string", "HI2Operations.utmref_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_13", HFILL }},
    { &hf_HI2Operations_wGS84Coordinates,
      { "wGS84Coordinates", "HI2Operations.wGS84Coordinates",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_point,
      { "point", "HI2Operations.point",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_Point", HFILL }},
    { &hf_HI2Operations_pointWithUnCertainty,
      { "pointWithUnCertainty", "HI2Operations.pointWithUnCertainty",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_PointWithUnCertainty", HFILL }},
    { &hf_HI2Operations_polygon,
      { "polygon", "HI2Operations.polygon",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GA_Polygon", HFILL }},
    { &hf_HI2Operations_latitudeSign,
      { "latitudeSign", "HI2Operations.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_latitudeSign_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_latitude_01,
      { "latitude", "HI2Operations.latitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_HI2Operations_longitude_01,
      { "longitude", "HI2Operations.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_HI2Operations_geographicalCoordinates,
      { "geographicalCoordinates", "HI2Operations.geographicalCoordinates",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_uncertaintyCode,
      { "uncertaintyCode", "HI2Operations.uncertaintyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_HI2Operations_GA_Polygon_item,
      { "GA-Polygon item", "HI2Operations.GA_Polygon_item",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_cCLink_State,
      { "cCLink-State", "HI2Operations.cCLink_State",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_CCLink_State_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_release_Time,
      { "release-Time", "HI2Operations.release_Time",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_TimeStamp_vals), 0,
        "TimeStamp", HFILL }},
    { &hf_HI2Operations_release_Reason,
      { "release-Reason", "HI2Operations.release_Reason",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_HI2Operations_lEMF_Address,
      { "lEMF-Address", "HI2Operations.lEMF_Address",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_CalledPartyNumber_vals), 0,
        "CalledPartyNumber", HFILL }},
    { &hf_HI2Operations_iSUP_parameters,
      { "iSUP-parameters", "HI2Operations.iSUP_parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_dSS1_parameters_codeset_0,
      { "dSS1-parameters-codeset-0", "HI2Operations.dSS1_parameters_codeset_0",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_mAP_parameters,
      { "mAP-parameters", "HI2Operations.mAP_parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ISUP_parameters_item,
      { "ISUP-parameters item", "HI2Operations.ISUP_parameters_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_DSS1_parameters_codeset_0_item,
      { "DSS1-parameters-codeset-0 item", "HI2Operations.DSS1_parameters_codeset_0_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_MAP_parameters_item,
      { "MAP-parameters item", "HI2Operations.MAP_parameters_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_standard_Supplementary_Services,
      { "standard-Supplementary-Services", "HI2Operations.standard_Supplementary_Services",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_non_Standard_Supplementary_Services,
      { "non-Standard-Supplementary-Services", "HI2Operations.non_Standard_Supplementary_Services",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_other_Services,
      { "other-Services", "HI2Operations.other_Services",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_iSUP_SS_parameters,
      { "iSUP-SS-parameters", "HI2Operations.iSUP_SS_parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_dSS1_SS_parameters_codeset_0,
      { "dSS1-SS-parameters-codeset-0", "HI2Operations.dSS1_SS_parameters_codeset_0",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_dSS1_SS_parameters_codeset_4,
      { "dSS1-SS-parameters-codeset-4", "HI2Operations.dSS1_SS_parameters_codeset_4",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_dSS1_SS_parameters_codeset_5,
      { "dSS1-SS-parameters-codeset-5", "HI2Operations.dSS1_SS_parameters_codeset_5",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_dSS1_SS_parameters_codeset_6,
      { "dSS1-SS-parameters-codeset-6", "HI2Operations.dSS1_SS_parameters_codeset_6",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_dSS1_SS_parameters_codeset_7,
      { "dSS1-SS-parameters-codeset-7", "HI2Operations.dSS1_SS_parameters_codeset_7",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_dSS1_SS_Invoke_components,
      { "dSS1-SS-Invoke-components", "HI2Operations.dSS1_SS_Invoke_components",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_mAP_SS_Parameters,
      { "mAP-SS-Parameters", "HI2Operations.mAP_SS_Parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_mAP_SS_Invoke_Components,
      { "mAP-SS-Invoke-Components", "HI2Operations.mAP_SS_Invoke_Components",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_Non_Standard_Supplementary_Services_item,
      { "Non-Standard-Supplementary-Services item", "HI2Operations.Non_Standard_Supplementary_Services_item",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_Non_Standard_Supplementary_Services_item_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_simpleIndication,
      { "simpleIndication", "HI2Operations.simpleIndication",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_SimpleIndication_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_sciData,
      { "sciData", "HI2Operations.sciData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SciDataMode", HFILL }},
    { &hf_HI2Operations_Other_Services_item,
      { "Other-Services item", "HI2Operations.Other_Services_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_ISUP_SS_parameters_item,
      { "ISUP-SS-parameters item", "HI2Operations.ISUP_SS_parameters_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_DSS1_SS_parameters_codeset_0_item,
      { "DSS1-SS-parameters-codeset-0 item", "HI2Operations.DSS1_SS_parameters_codeset_0_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_DSS1_SS_parameters_codeset_4_item,
      { "DSS1-SS-parameters-codeset-4 item", "HI2Operations.DSS1_SS_parameters_codeset_4_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_DSS1_SS_parameters_codeset_5_item,
      { "DSS1-SS-parameters-codeset-5 item", "HI2Operations.DSS1_SS_parameters_codeset_5_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_DSS1_SS_parameters_codeset_6_item,
      { "DSS1-SS-parameters-codeset-6 item", "HI2Operations.DSS1_SS_parameters_codeset_6_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_DSS1_SS_parameters_codeset_7_item,
      { "DSS1-SS-parameters-codeset-7 item", "HI2Operations.DSS1_SS_parameters_codeset_7_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_DSS1_SS_Invoke_Components_item,
      { "DSS1-SS-Invoke-Components item", "HI2Operations.DSS1_SS_Invoke_Components_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_MAP_SS_Invoke_Components_item,
      { "MAP-SS-Invoke-Components item", "HI2Operations.MAP_SS_Invoke_Components_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_MAP_SS_Parameters_item,
      { "MAP-SS-Parameters item", "HI2Operations.MAP_SS_Parameters_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_sMS_Contents,
      { "sMS-Contents", "HI2Operations.sMS_Contents",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_initiator,
      { "initiator", "HI2Operations.initiator",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_initiator_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_transfer_status,
      { "transfer-status", "HI2Operations.transfer_status",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_transfer_status_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_other_message,
      { "other-message", "HI2Operations.other_message",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_other_message_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_content,
      { "content", "HI2Operations.content",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_270", HFILL }},
    { &hf_HI2Operations_National_Parameters_item,
      { "National-Parameters item", "HI2Operations.National_Parameters_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_gPRS_parameters,
      { "gPRS-parameters", "HI2Operations.gPRS_parameters",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_pDP_address_allocated_to_the_target,
      { "pDP-address-allocated-to-the-target", "HI2Operations.pDP_address_allocated_to_the_target",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_DataNodeAddress_vals), 0,
        "DataNodeAddress", HFILL }},
    { &hf_HI2Operations_aPN,
      { "aPN", "HI2Operations.aPN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_100", HFILL }},
    { &hf_HI2Operations_pDP_type,
      { "pDP-type", "HI2Operations.pDP_type",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_HI2Operations_ipAddress,
      { "ipAddress", "HI2Operations.ipAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_x25Address,
      { "x25Address", "HI2Operations.x25Address",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_iP_type,
      { "iP-type", "HI2Operations.iP_type",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_iP_type_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_iP_value,
      { "iP-value", "HI2Operations.iP_value",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_IP_value_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_iP_assignment,
      { "iP-assignment", "HI2Operations.iP_assignment",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_iP_assignment_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_iPBinaryAddress,
      { "iPBinaryAddress", "HI2Operations.iPBinaryAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4_16", HFILL }},
    { &hf_HI2Operations_iPTextAddress,
      { "iPTextAddress", "HI2Operations.iPTextAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_7_45", HFILL }},
    { &hf_HI2Operations_countryCode,
      { "countryCode", "HI2Operations.countryCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_2", HFILL }},
    { &hf_HI2Operations_qosMobileRadio,
      { "qosMobileRadio", "HI2Operations.qosMobileRadio",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_qosGn,
      { "qosGn", "HI2Operations.qosGn",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_iri_to_CC,
      { "iri-to-CC", "HI2Operations.iri_to_CC",
        FT_NONE, BASE_NONE, NULL, 0,
        "IRI_to_CC_Correlation", HFILL }},
    { &hf_HI2Operations_iri_to_iri,
      { "iri-to-iri", "HI2Operations.iri_to_iri",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IRI_to_IRI_Correlation", HFILL }},
    { &hf_HI2Operations_both_IRI_CC,
      { "both-IRI-CC", "HI2Operations.both_IRI_CC",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_iri_CC,
      { "iri-CC", "HI2Operations.iri_CC",
        FT_NONE, BASE_NONE, NULL, 0,
        "IRI_to_CC_Correlation", HFILL }},
    { &hf_HI2Operations_iri_IRI,
      { "iri-IRI", "HI2Operations.iri_IRI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IRI_to_IRI_Correlation", HFILL }},
    { &hf_HI2Operations_cc,
      { "cc", "HI2Operations.cc",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_cc_item,
      { "cc item", "HI2Operations.cc_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_iri,
      { "iri", "HI2Operations.iri",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_version,
      { "version", "HI2Operations.version",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_HI2Operations_lIInstanceid,
      { "lIInstanceid", "HI2Operations.lIInstanceid",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LIIDType", HFILL }},
    { &hf_HI2Operations_timestamp,
      { "timestamp", "HI2Operations.timestamp",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTCTime", HFILL }},
    { &hf_HI2Operations_targetLocation,
      { "targetLocation", "HI2Operations.targetLocation",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_LocationType_vals), 0,
        "LocationType", HFILL }},
    { &hf_HI2Operations_direction,
      { "direction", "HI2Operations.direction",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_DirectionType_vals), 0,
        "DirectionType", HFILL }},
    { &hf_HI2Operations_iRITransaction,
      { "iRITransaction", "HI2Operations.iRITransaction",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_IRITransactionType_vals), 0,
        "IRITransactionType", HFILL }},
    { &hf_HI2Operations_iRITransactionNumber,
      { "iRITransactionNumber", "HI2Operations.iRITransactionNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_HI2Operations_userSignal,
      { "userSignal", "HI2Operations.userSignal",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_UserSignalType_vals), 0,
        "UserSignalType", HFILL }},
    { &hf_HI2Operations_cryptoCheckSum,
      { "cryptoCheckSum", "HI2Operations.cryptoCheckSum",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_HI2Operations_copySignal,
      { "copySignal", "HI2Operations.copySignal",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_HI2Operations_interpretedSignal,
      { "interpretedSignal", "HI2Operations.interpretedSignal",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_HI2Operations_cdcPdu,
      { "cdcPdu", "HI2Operations.cdcPdu",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_geodeticData,
      { "geodeticData", "HI2Operations.geodeticData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_HI2Operations_nameAddress,
      { "nameAddress", "HI2Operations.nameAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_100", HFILL }},
    { &hf_HI2Operations_protocolVersion,
      { "protocolVersion", "HI2Operations.protocolVersion",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_ProtocolVersion_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_message,
      { "message", "HI2Operations.message",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_Message_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_answer,
      { "answer", "HI2Operations.answer",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ccclose,
      { "ccclose", "HI2Operations.ccclose",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ccopen,
      { "ccopen", "HI2Operations.ccopen",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_reserved0,
      { "reserved0", "HI2Operations.reserved0",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_origination,
      { "origination", "HI2Operations.origination",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_reserved1,
      { "reserved1", "HI2Operations.reserved1",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_redirection,
      { "redirection", "HI2Operations.redirection",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_release,
      { "release", "HI2Operations.release",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_reserved2,
      { "reserved2", "HI2Operations.reserved2",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_terminationattempt,
      { "terminationattempt", "HI2Operations.terminationattempt",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_reserved,
      { "reserved", "HI2Operations.reserved",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ccchange,
      { "ccchange", "HI2Operations.ccchange",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_reserved3,
      { "reserved3", "HI2Operations.reserved3",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_reserved4,
      { "reserved4", "HI2Operations.reserved4",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_reserved5,
      { "reserved5", "HI2Operations.reserved5",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_networksignal,
      { "networksignal", "HI2Operations.networksignal",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_subjectsignal,
      { "subjectsignal", "HI2Operations.subjectsignal",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_mediareport,
      { "mediareport", "HI2Operations.mediareport",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_serviceinstance,
      { "serviceinstance", "HI2Operations.serviceinstance",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_caseId,
      { "caseId", "HI2Operations.caseId",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_accessingElementId,
      { "accessingElementId", "HI2Operations.accessingElementId",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_eventTime,
      { "eventTime", "HI2Operations.eventTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_callId,
      { "callId", "HI2Operations.callId",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_answering,
      { "answering", "HI2Operations.answering",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyId", HFILL }},
    { &hf_HI2Operations_cCCId,
      { "cCCId", "HI2Operations.cCCId",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_CCCId_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_subject,
      { "subject", "HI2Operations.subject",
        FT_STRING, BASE_NONE, NULL, 0,
        "SDP", HFILL }},
    { &hf_HI2Operations_associate,
      { "associate", "HI2Operations.associate",
        FT_STRING, BASE_NONE, NULL, 0,
        "SDP", HFILL }},
    { &hf_HI2Operations_flowDirection,
      { "flowDirection", "HI2Operations.flowDirection",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_FlowDirection_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_resourceState,
      { "resourceState", "HI2Operations.resourceState",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_ResourceState_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ccOpenOption,
      { "ccOpenOption", "HI2Operations.ccOpenOption",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_ccOpenOption_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ccOpenTime,
      { "ccOpenTime", "HI2Operations.ccOpenTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CallId", HFILL }},
    { &hf_HI2Operations_ccOpenTime_item,
      { "CallId", "HI2Operations.CallId",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_alertingSignal,
      { "alertingSignal", "HI2Operations.alertingSignal",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_AlertingSignal_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_subjectAudibleSignal,
      { "subjectAudibleSignal", "HI2Operations.subjectAudibleSignal",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_AudibleSignal_vals), 0,
        "AudibleSignal", HFILL }},
    { &hf_HI2Operations_terminalDisplayInfo,
      { "terminalDisplayInfo", "HI2Operations.terminalDisplayInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_other,
      { "other", "HI2Operations.other",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_128_", HFILL }},
    { &hf_HI2Operations_calling,
      { "calling", "HI2Operations.calling",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyId", HFILL }},
    { &hf_HI2Operations_called,
      { "called", "HI2Operations.called",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyId", HFILL }},
    { &hf_HI2Operations_input,
      { "input", "HI2Operations.input",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_input_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_userinput,
      { "userinput", "HI2Operations.userinput",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_32_", HFILL }},
    { &hf_HI2Operations_translationinput,
      { "translationinput", "HI2Operations.translationinput",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_32_", HFILL }},
    { &hf_HI2Operations_transitCarrierId,
      { "transitCarrierId", "HI2Operations.transitCarrierId",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_old,
      { "old", "HI2Operations.old",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallId", HFILL }},
    { &hf_HI2Operations_redirectedto,
      { "redirectedto", "HI2Operations.redirectedto",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyId", HFILL }},
    { &hf_HI2Operations_new,
      { "new", "HI2Operations.new",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallId", HFILL }},
    { &hf_HI2Operations_redirectedfrom,
      { "redirectedfrom", "HI2Operations.redirectedfrom",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyId", HFILL }},
    { &hf_HI2Operations_relatedCallId,
      { "relatedCallId", "HI2Operations.relatedCallId",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallId", HFILL }},
    { &hf_HI2Operations_serviceName,
      { "serviceName", "HI2Operations.serviceName",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_128_", HFILL }},
    { &hf_HI2Operations_firstCallCalling,
      { "firstCallCalling", "HI2Operations.firstCallCalling",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyId", HFILL }},
    { &hf_HI2Operations_secondCallCalling,
      { "secondCallCalling", "HI2Operations.secondCallCalling",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyId", HFILL }},
    { &hf_HI2Operations_signal,
      { "signal", "HI2Operations.signal",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_switchhookFlash,
      { "switchhookFlash", "HI2Operations.switchhookFlash",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_128_", HFILL }},
    { &hf_HI2Operations_dialedDigits,
      { "dialedDigits", "HI2Operations.dialedDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_128_", HFILL }},
    { &hf_HI2Operations_featureKey,
      { "featureKey", "HI2Operations.featureKey",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_128_", HFILL }},
    { &hf_HI2Operations_otherSignalingInformation,
      { "otherSignalingInformation", "HI2Operations.otherSignalingInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_128_", HFILL }},
    { &hf_HI2Operations_redirectedFromInfo,
      { "redirectedFromInfo", "HI2Operations.redirectedFromInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_sequencenumber,
      { "sequencenumber", "HI2Operations.sequencenumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_25_", HFILL }},
    { &hf_HI2Operations_systemidentity,
      { "systemidentity", "HI2Operations.systemidentity",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_15_", HFILL }},
    { &hf_HI2Operations_combCCC,
      { "combCCC", "HI2Operations.combCCC",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_20_", HFILL }},
    { &hf_HI2Operations_sepCCCpair,
      { "sepCCCpair", "HI2Operations.sepCCCpair",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_sepXmitCCC,
      { "sepXmitCCC", "HI2Operations.sepXmitCCC",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_20_", HFILL }},
    { &hf_HI2Operations_sepRecvCCC,
      { "sepRecvCCC", "HI2Operations.sepRecvCCC",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_20_", HFILL }},
    { &hf_HI2Operations_dn,
      { "dn", "HI2Operations.dn",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_15_", HFILL }},
    { &hf_HI2Operations_userProvided,
      { "userProvided", "HI2Operations.userProvided",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_15_", HFILL }},
    { &hf_HI2Operations_reserved6,
      { "reserved6", "HI2Operations.reserved6",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_reserved7,
      { "reserved7", "HI2Operations.reserved7",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ipAddress_01,
      { "ipAddress", "HI2Operations.ipAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_32_", HFILL }},
    { &hf_HI2Operations_reserved8,
      { "reserved8", "HI2Operations.reserved8",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_trunkId,
      { "trunkId", "HI2Operations.trunkId",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_32_", HFILL }},
    { &hf_HI2Operations_reserved9,
      { "reserved9", "HI2Operations.reserved9",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_genericAddress,
      { "genericAddress", "HI2Operations.genericAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_32_", HFILL }},
    { &hf_HI2Operations_genericDigits,
      { "genericDigits", "HI2Operations.genericDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_32_", HFILL }},
    { &hf_HI2Operations_genericName,
      { "genericName", "HI2Operations.genericName",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_48_", HFILL }},
    { &hf_HI2Operations_port,
      { "port", "HI2Operations.port",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_32_", HFILL }},
    { &hf_HI2Operations_context,
      { "context", "HI2Operations.context",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_32_", HFILL }},
    { &hf_HI2Operations_lastRedirecting,
      { "lastRedirecting", "HI2Operations.lastRedirecting",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyId", HFILL }},
    { &hf_HI2Operations_originalCalled,
      { "originalCalled", "HI2Operations.originalCalled",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyId", HFILL }},
    { &hf_HI2Operations_numRedirections,
      { "numRedirections", "HI2Operations.numRedirections",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_100_", HFILL }},
    { &hf_HI2Operations_generalDisplay,
      { "generalDisplay", "HI2Operations.generalDisplay",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_80_", HFILL }},
    { &hf_HI2Operations_calledNumber,
      { "calledNumber", "HI2Operations.calledNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_40_", HFILL }},
    { &hf_HI2Operations_callingNumber,
      { "callingNumber", "HI2Operations.callingNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_40_", HFILL }},
    { &hf_HI2Operations_callingName,
      { "callingName", "HI2Operations.callingName",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_40_", HFILL }},
    { &hf_HI2Operations_originalCalledNumber,
      { "originalCalledNumber", "HI2Operations.originalCalledNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_40_", HFILL }},
    { &hf_HI2Operations_lastRedirectingNumber,
      { "lastRedirectingNumber", "HI2Operations.lastRedirectingNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_40_", HFILL }},
    { &hf_HI2Operations_redirectingName,
      { "redirectingName", "HI2Operations.redirectingName",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_40_", HFILL }},
    { &hf_HI2Operations_redirectingReason,
      { "redirectingReason", "HI2Operations.redirectingReason",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_40_", HFILL }},
    { &hf_HI2Operations_messageWaitingNotif,
      { "messageWaitingNotif", "HI2Operations.messageWaitingNotif",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString_SIZE_1_40_", HFILL }},
    { &hf_HI2Operations_tLIInstanceid,
      { "tLIInstanceid", "HI2Operations.tLIInstanceid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TLIIdType", HFILL }},
    { &hf_HI2Operations_targetLocation_01,
      { "targetLocation", "HI2Operations.targetLocation",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_LocationType_en301040_vals), 0,
        "LocationType_en301040", HFILL }},
    { &hf_HI2Operations_targetAction,
      { "targetAction", "HI2Operations.targetAction",
        FT_NONE, BASE_NONE, NULL, 0,
        "ActivityType", HFILL }},
    { &hf_HI2Operations_supplementaryTargetaddress,
      { "supplementaryTargetaddress", "HI2Operations.supplementaryTargetaddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressType", HFILL }},
    { &hf_HI2Operations_cotargetaddress,
      { "cotargetaddress", "HI2Operations.cotargetaddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AddressType", HFILL }},
    { &hf_HI2Operations_cotargetaddress_item,
      { "AddressType", "HI2Operations.AddressType",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_cotargetlocation,
      { "cotargetlocation", "HI2Operations.cotargetlocation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_LocationType_en301040", HFILL }},
    { &hf_HI2Operations_cotargetlocation_item,
      { "LocationType-en301040", "HI2Operations.LocationType_en301040",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_LocationType_en301040_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_targetlocation,
      { "targetlocation", "HI2Operations.targetlocation",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_LocationType_en301040_vals), 0,
        "LocationType_en301040", HFILL }},
    { &hf_HI2Operations_targetcommsid,
      { "targetcommsid", "HI2Operations.targetcommsid",
        FT_STRING, BASE_NONE, NULL, 0,
        "CircuitIdType", HFILL }},
    { &hf_HI2Operations_cotargetcommsid,
      { "cotargetcommsid", "HI2Operations.cotargetcommsid",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CircuitIdType", HFILL }},
    { &hf_HI2Operations_cotargetcommsid_item,
      { "CircuitIdType", "HI2Operations.CircuitIdType",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_trafficPacket,
      { "trafficPacket", "HI2Operations.trafficPacket",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_HI2Operations_cctivity,
      { "cctivity", "HI2Operations.cctivity",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_ActivityClassType_vals), 0,
        "ActivityClassType", HFILL }},
    { &hf_HI2Operations_callRelation,
      { "callRelation", "HI2Operations.callRelation",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_callRelation_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_direction_01,
      { "direction", "HI2Operations.direction",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_direction_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_scope,
      { "scope", "HI2Operations.scope",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_scope_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_cPlaneData,
      { "cPlaneData", "HI2Operations.cPlaneData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_HI2Operations_sStype,
      { "sStype", "HI2Operations.sStype",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_SSType_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_tSI,
      { "tSI", "HI2Operations.tSI",
        FT_NONE, BASE_NONE, NULL, 0,
        "TSIType", HFILL }},
    { &hf_HI2Operations_supplementaryAddress,
      { "supplementaryAddress", "HI2Operations.supplementaryAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_TETRAAddressType", HFILL }},
    { &hf_HI2Operations_supplementaryAddress_item,
      { "TETRAAddressType", "HI2Operations.TETRAAddressType",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_TETRAAddressType_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_tETRAaddress,
      { "tETRAaddress", "HI2Operations.tETRAaddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "TSIType", HFILL }},
    { &hf_HI2Operations_pISNaddress,
      { "pISNaddress", "HI2Operations.pISNaddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumericString_SIZE_20", HFILL }},
    { &hf_HI2Operations_iP4address,
      { "iP4address", "HI2Operations.iP4address",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_HI2Operations_iP6address,
      { "iP6address", "HI2Operations.iP6address",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_128", HFILL }},
    { &hf_HI2Operations_e164address,
      { "e164address", "HI2Operations.e164address",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumericString_SIZE_20", HFILL }},
    { &hf_HI2Operations_tEI,
      { "tEI", "HI2Operations.tEI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TEIType", HFILL }},
    { &hf_HI2Operations_mSLoc,
      { "mSLoc", "HI2Operations.mSLoc",
        FT_NONE, BASE_NONE, NULL, 0,
        "TETRACGIType", HFILL }},
    { &hf_HI2Operations_lSLoc,
      { "lSLoc", "HI2Operations.lSLoc",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_TETRAAddressType_vals), 0,
        "TETRAAddressType", HFILL }},
    { &hf_HI2Operations_mcc_01,
      { "mcc", "HI2Operations.mcc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "MCCType", HFILL }},
    { &hf_HI2Operations_mnc_01,
      { "mnc", "HI2Operations.mnc",
        FT_BYTES, BASE_NONE, NULL, 0,
        "MNCType", HFILL }},
    { &hf_HI2Operations_lai_01,
      { "lai", "HI2Operations.lai",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LocationAreaType", HFILL }},
    { &hf_HI2Operations_cI,
      { "cI", "HI2Operations.cI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CellIdType", HFILL }},
    { &hf_HI2Operations_ssi,
      { "ssi", "HI2Operations.ssi",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SSIType", HFILL }},

/*--- End of included file: packet-HI2Operations-hfarr.c ---*/
#line 56 "../../asn1/HI2Operations/packet-HI2Operations-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-HI2Operations-ettarr.c ---*/
#line 1 "../../asn1/HI2Operations/packet-HI2Operations-ettarr.c"
    &ett_HI2Operations_IRIsContent,
    &ett_HI2Operations_IRISequence,
    &ett_HI2Operations_IRIContent,
    &ett_HI2Operations_IRI_Parameters,
    &ett_HI2Operations_SET_SIZE_1_10_OF_PartyInformation,
    &ett_HI2Operations_T_callContentLinkInformation,
    &ett_HI2Operations_CommunicationIdentifier,
    &ett_HI2Operations_Network_Identifier,
    &ett_HI2Operations_Network_Element_Identifier,
    &ett_HI2Operations_TimeStamp,
    &ett_HI2Operations_LocalTimeStamp,
    &ett_HI2Operations_PartyInformation,
    &ett_HI2Operations_T_partyIdentity,
    &ett_HI2Operations_CallingPartyNumber,
    &ett_HI2Operations_CalledPartyNumber,
    &ett_HI2Operations_Location,
    &ett_HI2Operations_TetraLocation,
    &ett_HI2Operations_T_ms_Loc,
    &ett_HI2Operations_GSMLocation,
    &ett_HI2Operations_T_geoCoordinates,
    &ett_HI2Operations_T_utmCoordinates,
    &ett_HI2Operations_T_utmRefCoordinates,
    &ett_HI2Operations_UMTSLocation,
    &ett_HI2Operations_GeographicalCoordinates,
    &ett_HI2Operations_GA_Point,
    &ett_HI2Operations_GA_PointWithUnCertainty,
    &ett_HI2Operations_GA_Polygon,
    &ett_HI2Operations_GA_Polygon_item,
    &ett_HI2Operations_CallContentLinkCharacteristics,
    &ett_HI2Operations_Services_Information,
    &ett_HI2Operations_ISUP_parameters,
    &ett_HI2Operations_DSS1_parameters_codeset_0,
    &ett_HI2Operations_MAP_parameters,
    &ett_HI2Operations_Supplementary_Services,
    &ett_HI2Operations_Standard_Supplementary_Services,
    &ett_HI2Operations_Non_Standard_Supplementary_Services,
    &ett_HI2Operations_Non_Standard_Supplementary_Services_item,
    &ett_HI2Operations_Other_Services,
    &ett_HI2Operations_ISUP_SS_parameters,
    &ett_HI2Operations_DSS1_SS_parameters_codeset_0,
    &ett_HI2Operations_DSS1_SS_parameters_codeset_4,
    &ett_HI2Operations_DSS1_SS_parameters_codeset_5,
    &ett_HI2Operations_DSS1_SS_parameters_codeset_6,
    &ett_HI2Operations_DSS1_SS_parameters_codeset_7,
    &ett_HI2Operations_DSS1_SS_Invoke_Components,
    &ett_HI2Operations_MAP_SS_Invoke_Components,
    &ett_HI2Operations_MAP_SS_Parameters,
    &ett_HI2Operations_SMS_report,
    &ett_HI2Operations_T_sMS_Contents,
    &ett_HI2Operations_National_Parameters,
    &ett_HI2Operations_Services_Data_Information,
    &ett_HI2Operations_GPRS_parameters,
    &ett_HI2Operations_DataNodeAddress,
    &ett_HI2Operations_IPAddress,
    &ett_HI2Operations_IP_value,
    &ett_HI2Operations_National_HI2_ASN1parameters,
    &ett_HI2Operations_UmtsQos,
    &ett_HI2Operations_CorrelationValues,
    &ett_HI2Operations_T_both_IRI_CC,
    &ett_HI2Operations_IRI_to_CC_Correlation,
    &ett_HI2Operations_T_cc,
    &ett_HI2Operations_TARGETACTIVITYMONITOR_1,
    &ett_HI2Operations_UserSignalType,
    &ett_HI2Operations_LocationType,
    &ett_HI2Operations_CdcPdu,
    &ett_HI2Operations_Message,
    &ett_HI2Operations_Answer,
    &ett_HI2Operations_CCChange,
    &ett_HI2Operations_CCClose,
    &ett_HI2Operations_CCOpen,
    &ett_HI2Operations_T_ccOpenOption,
    &ett_HI2Operations_SEQUENCE_OF_CallId,
    &ett_HI2Operations_MediaReport,
    &ett_HI2Operations_NetworkSignal,
    &ett_HI2Operations_Origination,
    &ett_HI2Operations_T_input,
    &ett_HI2Operations_Redirection,
    &ett_HI2Operations_Release,
    &ett_HI2Operations_ServiceInstance,
    &ett_HI2Operations_SubjectSignal,
    &ett_HI2Operations_T_signal,
    &ett_HI2Operations_TerminationAttempt,
    &ett_HI2Operations_CallId,
    &ett_HI2Operations_CCCId,
    &ett_HI2Operations_T_sepCCCpair,
    &ett_HI2Operations_PartyId,
    &ett_HI2Operations_RedirectedFromInfo,
    &ett_HI2Operations_TerminalDisplayInfo,
    &ett_HI2Operations_TARGETACTIVITYMONITORind,
    &ett_HI2Operations_SEQUENCE_OF_AddressType,
    &ett_HI2Operations_SEQUENCE_OF_LocationType_en301040,
    &ett_HI2Operations_TARGETCOMMSMONITORind,
    &ett_HI2Operations_SEQUENCE_OF_CircuitIdType,
    &ett_HI2Operations_TTRAFFICind,
    &ett_HI2Operations_CTTRAFFICind,
    &ett_HI2Operations_ActivityType,
    &ett_HI2Operations_AddressType,
    &ett_HI2Operations_SEQUENCE_OF_TETRAAddressType,
    &ett_HI2Operations_TETRAAddressType,
    &ett_HI2Operations_LocationType_en301040,
    &ett_HI2Operations_TETRACGIType,
    &ett_HI2Operations_TSIType,

/*--- End of included file: packet-HI2Operations-ettarr.c ---*/
#line 61 "../../asn1/HI2Operations/packet-HI2Operations-template.c"
  };

  /* Register protocol */
  proto_HI2Operations = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_HI2Operations, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("HI2Operations", dissect_IRIsContent_PDU, proto_HI2Operations);
}


/*--- proto_reg_handoff_HI2Operations -------------------------------------------*/
void proto_reg_handoff_HI2Operations(void) {
}

