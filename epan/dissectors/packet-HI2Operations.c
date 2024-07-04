/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-HI2Operations.c                                                     */
/* asn2wrs.py -b -q -L -p HI2Operations -c ./HI2Operations.cnf -s ./packet-HI2Operations-template -D . -O ../.. HI2Operations_ver18.asn HI3CCLinkData.asn EpsHI2Operations.asn UmtsHI2Operations.asn */

/* packet-HI2Operations.c
 * Routines for HI2 (ETSI TS 101 671 V3.15.1 (2018-06))
 *  Erwin van Eijk 2010
 *  Joakim Karlsson 2023
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-isup.h"
#include "packet-q931.h"

#define PNAME  "HI2Operations"
#define PSNAME "HI2OPERATIONS"
#define PFNAME "HI2operations"

void proto_register_HI2Operations(void);
void proto_reg_handoff_HI2Operations(void);

/* Initialize the protocol and registered fields */
int proto_HI2Operations;
static int hf_HI2Operations_IRIsContent_PDU;      /* IRIsContent */
static int hf_HI2Operations_UUS1_Content_PDU;     /* UUS1_Content */
static int hf_HI2Operations_communication_Identity_Number;  /* OCTET_STRING_SIZE_1_8 */
static int hf_HI2Operations_network_Identifier;   /* Network_Identifier */
static int hf_HI2Operations_operator_Identifier;  /* OCTET_STRING_SIZE_1_5 */
static int hf_HI2Operations_network_Element_Identifier;  /* Network_Element_Identifier */
static int hf_HI2Operations_e164_Format;          /* T_e164_Format */
static int hf_HI2Operations_x25_Format;           /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_iP_Format;            /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_dNS_Format;           /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_iP_Address;           /* IPAddress */
static int hf_HI2Operations_localTime;            /* LocalTimeStamp */
static int hf_HI2Operations_utcTime;              /* UTCTime */
static int hf_HI2Operations_generalizedTime;      /* GeneralizedTime */
static int hf_HI2Operations_winterSummerIndication;  /* T_winterSummerIndication */
static int hf_HI2Operations_party_Qualifier;      /* T_party_Qualifier */
static int hf_HI2Operations_partyIdentity;        /* T_partyIdentity */
static int hf_HI2Operations_imei;                 /* OCTET_STRING_SIZE_8 */
static int hf_HI2Operations_tei;                  /* OCTET_STRING_SIZE_1_15 */
static int hf_HI2Operations_imsi;                 /* OCTET_STRING_SIZE_3_8 */
static int hf_HI2Operations_callingPartyNumber;   /* CallingPartyNumber */
static int hf_HI2Operations_calledPartyNumber;    /* CalledPartyNumber */
static int hf_HI2Operations_msISDN;               /* OCTET_STRING_SIZE_1_9 */
static int hf_HI2Operations_e164_Format_01;       /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_sip_uri;              /* OCTET_STRING */
static int hf_HI2Operations_tel_url;              /* OCTET_STRING */
static int hf_HI2Operations_nai;                  /* OCTET_STRING */
static int hf_HI2Operations_x_3GPP_Asserted_Identity;  /* OCTET_STRING */
static int hf_HI2Operations_xUI;                  /* OCTET_STRING */
static int hf_HI2Operations_iMPI;                 /* OCTET_STRING */
static int hf_HI2Operations_extID;                /* UTF8String */
static int hf_HI2Operations_services_Information;  /* Services_Information */
static int hf_HI2Operations_supplementary_Services_Information;  /* Supplementary_Services */
static int hf_HI2Operations_services_Data_Information;  /* Services_Data_Information */
static int hf_HI2Operations_iSUP_Format;          /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_dSS1_Format;          /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_mAP_Format;           /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_geoCoordinates;       /* T_geoCoordinates */
static int hf_HI2Operations_geoCoordinates_latitude;  /* PrintableString_SIZE_7_10 */
static int hf_HI2Operations_geoCoordinates_longitude;  /* PrintableString_SIZE_8_11 */
static int hf_HI2Operations_mapDatum;             /* MapDatum */
static int hf_HI2Operations_azimuth;              /* INTEGER_0_359 */
static int hf_HI2Operations_utmCoordinates;       /* T_utmCoordinates */
static int hf_HI2Operations_utm_East;             /* PrintableString_SIZE_10 */
static int hf_HI2Operations_utm_North;            /* PrintableString_SIZE_7 */
static int hf_HI2Operations_utmRefCoordinates;    /* T_utmRefCoordinates */
static int hf_HI2Operations_utmref_string;        /* PrintableString_SIZE_13 */
static int hf_HI2Operations_wGS84Coordinates;     /* OCTET_STRING */
static int hf_HI2Operations_point;                /* GA_Point */
static int hf_HI2Operations_pointWithUnCertainty;  /* GA_PointWithUnCertainty */
static int hf_HI2Operations_polygon;              /* GA_Polygon */
static int hf_HI2Operations_latitudeSign;         /* T_latitudeSign */
static int hf_HI2Operations_latitude;             /* INTEGER_0_8388607 */
static int hf_HI2Operations_longitude;            /* INTEGER_M8388608_8388607 */
static int hf_HI2Operations_geographicalCoordinates;  /* GeographicalCoordinates */
static int hf_HI2Operations_uncertaintyCode;      /* INTEGER_0_127 */
static int hf_HI2Operations_GA_Polygon_item;      /* GA_Polygon_item */
static int hf_HI2Operations_iSUP_parameters;      /* ISUP_parameters */
static int hf_HI2Operations_dSS1_parameters_codeset_0;  /* DSS1_parameters_codeset_0 */
static int hf_HI2Operations_mAP_parameters;       /* MAP_parameters */
static int hf_HI2Operations_ISUP_parameters_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_parameters_codeset_0_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_MAP_parameters_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_standard_Supplementary_Services;  /* Standard_Supplementary_Services */
static int hf_HI2Operations_non_Standard_Supplementary_Services;  /* Non_Standard_Supplementary_Services */
static int hf_HI2Operations_other_Services;       /* Other_Services */
static int hf_HI2Operations_iSUP_SS_parameters;   /* ISUP_SS_parameters */
static int hf_HI2Operations_dSS1_SS_parameters_codeset_0;  /* DSS1_SS_parameters_codeset_0 */
static int hf_HI2Operations_dSS1_SS_parameters_codeset_4;  /* DSS1_SS_parameters_codeset_4 */
static int hf_HI2Operations_dSS1_SS_parameters_codeset_5;  /* DSS1_SS_parameters_codeset_5 */
static int hf_HI2Operations_dSS1_SS_parameters_codeset_6;  /* DSS1_SS_parameters_codeset_6 */
static int hf_HI2Operations_dSS1_SS_parameters_codeset_7;  /* DSS1_SS_parameters_codeset_7 */
static int hf_HI2Operations_dSS1_SS_Invoke_components;  /* DSS1_SS_Invoke_Components */
static int hf_HI2Operations_mAP_SS_Parameters;    /* MAP_SS_Parameters */
static int hf_HI2Operations_mAP_SS_Invoke_Components;  /* MAP_SS_Invoke_Components */
static int hf_HI2Operations_Non_Standard_Supplementary_Services_item;  /* Non_Standard_Supplementary_Services_item */
static int hf_HI2Operations_simpleIndication;     /* SimpleIndication */
static int hf_HI2Operations_sciData;              /* SciDataMode */
static int hf_HI2Operations_Other_Services_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_ISUP_SS_parameters_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_SS_parameters_codeset_0_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_SS_parameters_codeset_4_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_SS_parameters_codeset_5_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_SS_parameters_codeset_6_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_SS_parameters_codeset_7_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_DSS1_SS_Invoke_Components_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_MAP_SS_Invoke_Components_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_MAP_SS_Parameters_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_communicationIdentifier;  /* CommunicationIdentifier */
static int hf_HI2Operations_timeStamp;            /* TimeStamp */
static int hf_HI2Operations_sMS_Contents;         /* T_sMS_Contents */
static int hf_HI2Operations_initiator;            /* T_initiator */
static int hf_HI2Operations_transfer_status;      /* T_transfer_status */
static int hf_HI2Operations_other_message;        /* T_other_message */
static int hf_HI2Operations_content;              /* OCTET_STRING_SIZE_1_270 */
static int hf_HI2Operations_enhancedContent;      /* T_enhancedContent */
static int hf_HI2Operations_content_01;           /* OCTET_STRING */
static int hf_HI2Operations_character_encoding;   /* T_character_encoding */
static int hf_HI2Operations_National_Parameters_item;  /* OCTET_STRING_SIZE_1_256 */
static int hf_HI2Operations_gPRS_parameters;      /* GPRS_parameters */
static int hf_HI2Operations_ipAddress;            /* IPAddress */
static int hf_HI2Operations_x25Address;           /* X25Address */
static int hf_HI2Operations_iP_type;              /* T_iP_type */
static int hf_HI2Operations_iP_value;             /* IP_value */
static int hf_HI2Operations_iP_assignment;        /* T_iP_assignment */
static int hf_HI2Operations_iPv6PrefixLength;     /* INTEGER_1_128 */
static int hf_HI2Operations_iPv4SubnetMask;       /* OCTET_STRING_SIZE_4 */
static int hf_HI2Operations_iPBinaryAddress;      /* OCTET_STRING_SIZE_4_16 */
static int hf_HI2Operations_iPTextAddress;        /* IA5String_SIZE_7_45 */
static int hf_HI2Operations_countryCode;          /* PrintableString_SIZE_2 */
static int hf_HI2Operations_domainID;             /* OBJECT_IDENTIFIER */
static int hf_HI2Operations_lawfullInterceptionIdentifier;  /* LawfulInterceptionIdentifier */
static int hf_HI2Operations_cC_Link_Identifier;   /* CC_Link_Identifier */
static int hf_HI2Operations_direction_Indication;  /* Direction_Indication */
static int hf_HI2Operations_bearer_capability;    /* T_bearer_capability */
static int hf_HI2Operations_service_Information;  /* Service_Information */
static int hf_HI2Operations_high_layer_capability;  /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_tMR;                  /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_bearerServiceCode;    /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_teleServiceCode;      /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_epsiRIContent;        /* EpsIRIContent */
static int hf_HI2Operations_epsIRISequence;       /* EpsIRISequence */
static int hf_HI2Operations_EpsIRISequence_item;  /* EpsIRIContent */
static int hf_HI2Operations_iRI_Begin_record;     /* IRI_Parameters */
static int hf_HI2Operations_iRI_End_record;       /* IRI_Parameters */
static int hf_HI2Operations_iRI_Continue_record;  /* IRI_Parameters */
static int hf_HI2Operations_iRI_Report_record;    /* IRI_Parameters */
static int hf_HI2Operations_hi2epsDomainId;       /* OBJECT_IDENTIFIER */
static int hf_HI2Operations_lawfulInterceptionIdentifier;  /* LawfulInterceptionIdentifier */
static int hf_HI2Operations_initiator_01;         /* T_initiator_01 */
static int hf_HI2Operations_locationOfTheTarget;  /* Location */
static int hf_HI2Operations_partyInformation;     /* SET_SIZE_1_10_OF_PartyInformation */
static int hf_HI2Operations_partyInformation_item;  /* PartyInformation */
static int hf_HI2Operations_serviceCenterAddress;  /* PartyInformation */
static int hf_HI2Operations_sMS;                  /* SMS_report */
static int hf_HI2Operations_national_Parameters;  /* National_Parameters */
static int hf_HI2Operations_ePSCorrelationNumber;  /* EPSCorrelationNumber */
static int hf_HI2Operations_ePSevent;             /* EPSEvent */
static int hf_HI2Operations_sgsnAddress;          /* DataNodeAddress */
static int hf_HI2Operations_gPRSOperationErrorCode;  /* GPRSOperationErrorCode */
static int hf_HI2Operations_ggsnAddress;          /* DataNodeAddress */
static int hf_HI2Operations_qOS;                  /* UmtsQos */
static int hf_HI2Operations_networkIdentifier;    /* Network_Identifier */
static int hf_HI2Operations_sMSOriginatingAddress;  /* DataNodeAddress */
static int hf_HI2Operations_sMSTerminatingAddress;  /* DataNodeAddress */
static int hf_HI2Operations_iMSevent;             /* IMSevent */
static int hf_HI2Operations_sIPMessage;           /* OCTET_STRING */
static int hf_HI2Operations_servingSGSN_number;   /* OCTET_STRING_SIZE_1_20 */
static int hf_HI2Operations_servingSGSN_address;  /* OCTET_STRING_SIZE_5_17 */
static int hf_HI2Operations_ldiEvent;             /* LDIevent */
static int hf_HI2Operations_correlation;          /* CorrelationValues */
static int hf_HI2Operations_ePS_GTPV2_specificParameters;  /* EPS_GTPV2_SpecificParameters */
static int hf_HI2Operations_ePS_PMIP_specificParameters;  /* EPS_PMIP_SpecificParameters */
static int hf_HI2Operations_ePS_DSMIP_SpecificParameters;  /* EPS_DSMIP_SpecificParameters */
static int hf_HI2Operations_ePS_MIP_SpecificParameters;  /* EPS_MIP_SpecificParameters */
static int hf_HI2Operations_servingNodeAddress;   /* OCTET_STRING */
static int hf_HI2Operations_visitedNetworkId;     /* UTF8String */
static int hf_HI2Operations_mediaDecryption_info;  /* MediaDecryption_info */
static int hf_HI2Operations_servingS4_SGSN_address;  /* OCTET_STRING */
static int hf_HI2Operations_sipMessageHeaderOffer;  /* OCTET_STRING */
static int hf_HI2Operations_sipMessageHeaderAnswer;  /* OCTET_STRING */
static int hf_HI2Operations_sdpOffer;             /* OCTET_STRING */
static int hf_HI2Operations_sdpAnswer;            /* OCTET_STRING */
static int hf_HI2Operations_uLITimestamp;         /* OCTET_STRING_SIZE_8 */
static int hf_HI2Operations_packetDataHeaderInformation;  /* PacketDataHeaderInformation */
static int hf_HI2Operations_mediaSecFailureIndication;  /* MediaSecFailureIndication */
static int hf_HI2Operations_csgIdentity;          /* OCTET_STRING_SIZE_4 */
static int hf_HI2Operations_heNBIdentity;         /* OCTET_STRING */
static int hf_HI2Operations_heNBiPAddress;        /* IPAddress */
static int hf_HI2Operations_heNBLocation;         /* HeNBLocation */
static int hf_HI2Operations_tunnelProtocol;       /* TunnelProtocol */
static int hf_HI2Operations_pANI_Header_Info;     /* SEQUENCE_OF_PANI_Header_Info */
static int hf_HI2Operations_pANI_Header_Info_item;  /* PANI_Header_Info */
static int hf_HI2Operations_imsVoIP;              /* IMS_VoIP_Correlation */
static int hf_HI2Operations_xCAPmessage;          /* OCTET_STRING */
static int hf_HI2Operations_logicalFunctionInformation;  /* DataNodeIdentifier */
static int hf_HI2Operations_ccUnavailableReason;  /* PrintableString */
static int hf_HI2Operations_carrierSpecificData;  /* OCTET_STRING */
static int hf_HI2Operations_current_previous_systems;  /* Current_Previous_Systems */
static int hf_HI2Operations_change_Of_Target_Identity;  /* Change_Of_Target_Identity */
static int hf_HI2Operations_requesting_Network_Identifier;  /* OCTET_STRING */
static int hf_HI2Operations_requesting_Node_Type;  /* Requesting_Node_Type */
static int hf_HI2Operations_serving_System_Identifier;  /* OCTET_STRING */
static int hf_HI2Operations_proSeTargetType;      /* ProSeTargetType */
static int hf_HI2Operations_proSeRelayMSISDN;     /* OCTET_STRING_SIZE_1_9 */
static int hf_HI2Operations_proSeRelayIMSI;       /* OCTET_STRING_SIZE_3_8 */
static int hf_HI2Operations_proSeRelayIMEI;       /* OCTET_STRING_SIZE_8 */
static int hf_HI2Operations_extendedLocParameters;  /* ExtendedLocParameters */
static int hf_HI2Operations_locationErrorCode;    /* LocationErrorCode */
static int hf_HI2Operations_otherIdentities;      /* SEQUENCE_OF_PartyInformation */
static int hf_HI2Operations_otherIdentities_item;  /* PartyInformation */
static int hf_HI2Operations_deregistrationReason;  /* DeregistrationReason */
static int hf_HI2Operations_requesting_Node_Identifier;  /* OCTET_STRING */
static int hf_HI2Operations_roamingIndication;    /* VoIPRoamingIndication */
static int hf_HI2Operations_cSREvent;             /* CSREvent */
static int hf_HI2Operations_ptc;                  /* PTC */
static int hf_HI2Operations_ptcEncryption;        /* PTCEncryptionInfo */
static int hf_HI2Operations_additionalCellIDs;    /* SEQUENCE_OF_AdditionalCellID */
static int hf_HI2Operations_additionalCellIDs_item;  /* AdditionalCellID */
static int hf_HI2Operations_scefID;               /* UTF8String */
static int hf_HI2Operations_national_HI2_ASN1parameters;  /* National_HI2_ASN1parameters */
static int hf_HI2Operations_dataNodeAddress;      /* DataNodeAddress */
static int hf_HI2Operations_logicalFunctionType;  /* LogicalFunctionType */
static int hf_HI2Operations_dataNodeName;         /* PrintableString_SIZE_7_25 */
static int hf_HI2Operations_access_Type;          /* OCTET_STRING */
static int hf_HI2Operations_access_Class;         /* OCTET_STRING */
static int hf_HI2Operations_network_Provided;     /* NULL */
static int hf_HI2Operations_pANI_Location;        /* PANI_Location */
static int hf_HI2Operations_raw_Location;         /* OCTET_STRING */
static int hf_HI2Operations_location;             /* Location */
static int hf_HI2Operations_ePSLocation;          /* EPSLocation */
static int hf_HI2Operations_e164_Number;          /* OCTET_STRING_SIZE_1_25 */
static int hf_HI2Operations_globalCellID;         /* GlobalCellID */
static int hf_HI2Operations_rAI;                  /* Rai */
static int hf_HI2Operations_gsmLocation;          /* GSMLocation */
static int hf_HI2Operations_umtsLocation;         /* UMTSLocation */
static int hf_HI2Operations_sAI;                  /* Sai */
static int hf_HI2Operations_oldRAI;               /* Rai */
static int hf_HI2Operations_civicAddress;         /* CivicAddress */
static int hf_HI2Operations_operatorSpecificInfo;  /* OCTET_STRING */
static int hf_HI2Operations_uELocationTimestamp;  /* T_uELocationTimestamp */
static int hf_HI2Operations_timestamp;            /* TimeStamp */
static int hf_HI2Operations_timestampUnknown;     /* NULL */
static int hf_HI2Operations_nCGI;                 /* NCGI */
static int hf_HI2Operations_timeOfLocation;       /* GeneralizedTime */
static int hf_HI2Operations_mCC;                  /* MCC */
static int hf_HI2Operations_mNC;                  /* MNC */
static int hf_HI2Operations_pLMNID;               /* PLMNID */
static int hf_HI2Operations_nRCellID;             /* NRCellID */
static int hf_HI2Operations_iri_to_CC;            /* IRI_to_CC_Correlation */
static int hf_HI2Operations_iri_to_iri;           /* IRI_to_IRI_Correlation */
static int hf_HI2Operations_both_IRI_CC;          /* T_both_IRI_CC */
static int hf_HI2Operations_iri_CC;               /* IRI_to_CC_Correlation */
static int hf_HI2Operations_iri_IRI;              /* IRI_to_IRI_Correlation */
static int hf_HI2Operations_IMS_VoIP_Correlation_item;  /* IMS_VoIP_Correlation_item */
static int hf_HI2Operations_ims_iri;              /* IRI_to_IRI_Correlation */
static int hf_HI2Operations_ims_cc;               /* IRI_to_CC_Correlation */
static int hf_HI2Operations_cc;                   /* T_cc */
static int hf_HI2Operations_cc_item;              /* OCTET_STRING */
static int hf_HI2Operations_iri;                  /* OCTET_STRING */
static int hf_HI2Operations_pDP_address_allocated_to_the_target;  /* DataNodeAddress */
static int hf_HI2Operations_aPN;                  /* OCTET_STRING_SIZE_1_100 */
static int hf_HI2Operations_pDP_type;             /* OCTET_STRING_SIZE_2 */
static int hf_HI2Operations_nSAPI;                /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_additionalIPaddress;  /* DataNodeAddress */
static int hf_HI2Operations_qosMobileRadio;       /* OCTET_STRING */
static int hf_HI2Operations_qosGn;                /* OCTET_STRING */
static int hf_HI2Operations_pDNAddressAllocation;  /* OCTET_STRING */
static int hf_HI2Operations_protConfigOptions;    /* ProtConfigOptions */
static int hf_HI2Operations_attachType;           /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_ePSBearerIdentity;    /* OCTET_STRING */
static int hf_HI2Operations_detachType;           /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_rATType;              /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_failedBearerActivationReason;  /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_ePSBearerQoS;         /* OCTET_STRING */
static int hf_HI2Operations_bearerActivationType;  /* TypeOfBearer */
static int hf_HI2Operations_aPN_AMBR;             /* OCTET_STRING */
static int hf_HI2Operations_procedureTransactionId;  /* OCTET_STRING */
static int hf_HI2Operations_linkedEPSBearerId;    /* OCTET_STRING */
static int hf_HI2Operations_tFT;                  /* OCTET_STRING */
static int hf_HI2Operations_handoverIndication;   /* NULL */
static int hf_HI2Operations_failedBearerModReason;  /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_trafficAggregateDescription;  /* OCTET_STRING */
static int hf_HI2Operations_failedTAUReason;      /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_failedEUTRANAttachReason;  /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_servingMMEaddress;    /* OCTET_STRING */
static int hf_HI2Operations_bearerDeactivationType;  /* TypeOfBearer */
static int hf_HI2Operations_bearerDeactivationCause;  /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_ePSlocationOfTheTarget;  /* EPSLocation */
static int hf_HI2Operations_pDNType;              /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_requestType;          /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_uEReqPDNConnFailReason;  /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_extendedHandoverIndication;  /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_uELocalIPAddress;     /* OCTET_STRING */
static int hf_HI2Operations_uEUdpPort;            /* OCTET_STRING_SIZE_2 */
static int hf_HI2Operations_tWANIdentifier;       /* OCTET_STRING */
static int hf_HI2Operations_tWANIdentifierTimestamp;  /* OCTET_STRING_SIZE_4 */
static int hf_HI2Operations_proSeRemoteUeContextConnected;  /* RemoteUeContextConnected */
static int hf_HI2Operations_proSeRemoteUeContextDisconnected;  /* RemoteUeContextDisconnected */
static int hf_HI2Operations_secondaryRATUsageIndication;  /* NULL */
static int hf_HI2Operations_userLocationInfo;     /* OCTET_STRING_SIZE_1_39 */
static int hf_HI2Operations_olduserLocationInfo;  /* OCTET_STRING_SIZE_1_39 */
static int hf_HI2Operations_lastVisitedTAI;       /* OCTET_STRING_SIZE_1_5 */
static int hf_HI2Operations_tAIlist;              /* OCTET_STRING_SIZE_7_97 */
static int hf_HI2Operations_threeGPP2Bsid;        /* OCTET_STRING_SIZE_1_12 */
static int hf_HI2Operations_uELocationTimestamp_01;  /* T_uELocationTimestamp_01 */
static int hf_HI2Operations_ueToNetwork;          /* OCTET_STRING_SIZE_1_251 */
static int hf_HI2Operations_networkToUe;          /* OCTET_STRING_SIZE_1_251 */
static int hf_HI2Operations_RemoteUeContextConnected_item;  /* RemoteUEContext */
static int hf_HI2Operations_remoteUserID;         /* RemoteUserID */
static int hf_HI2Operations_remoteUEIPInformation;  /* RemoteUEIPInformation */
static int hf_HI2Operations_lifetime;             /* INTEGER_0_65535 */
static int hf_HI2Operations_accessTechnologyType;  /* OCTET_STRING_SIZE_4 */
static int hf_HI2Operations_iPv6HomeNetworkPrefix;  /* OCTET_STRING_SIZE_20 */
static int hf_HI2Operations_protConfigurationOption;  /* OCTET_STRING */
static int hf_HI2Operations_handoverIndication_01;  /* OCTET_STRING_SIZE_4 */
static int hf_HI2Operations_status;               /* INTEGER_0_255 */
static int hf_HI2Operations_revocationTrigger;    /* INTEGER_0_255 */
static int hf_HI2Operations_iPv4HomeAddress;      /* OCTET_STRING_SIZE_4 */
static int hf_HI2Operations_iPv6careOfAddress;    /* OCTET_STRING */
static int hf_HI2Operations_iPv4careOfAddress;    /* OCTET_STRING */
static int hf_HI2Operations_servingNetwork;       /* OCTET_STRING_SIZE_3 */
static int hf_HI2Operations_dHCPv4AddressAllocationInd;  /* OCTET_STRING_SIZE_1 */
static int hf_HI2Operations_requestedIPv6HomePrefix;  /* OCTET_STRING_SIZE_25 */
static int hf_HI2Operations_homeAddress;          /* OCTET_STRING_SIZE_8 */
static int hf_HI2Operations_iPv4careOfAddress_01;  /* OCTET_STRING_SIZE_8 */
static int hf_HI2Operations_iPv6careOfAddress_01;  /* OCTET_STRING_SIZE_16 */
static int hf_HI2Operations_hSS_AAA_address;      /* OCTET_STRING */
static int hf_HI2Operations_targetPDN_GW_Address;  /* OCTET_STRING */
static int hf_HI2Operations_homeAddress_01;       /* OCTET_STRING_SIZE_4 */
static int hf_HI2Operations_careOfAddress;        /* OCTET_STRING_SIZE_4 */
static int hf_HI2Operations_homeAgentAddress;     /* OCTET_STRING_SIZE_4 */
static int hf_HI2Operations_code;                 /* INTEGER_0_255 */
static int hf_HI2Operations_foreignDomainAddress;  /* OCTET_STRING_SIZE_4 */
static int hf_HI2Operations_MediaDecryption_info_item;  /* CCKeyInfo */
static int hf_HI2Operations_cCCSID;               /* OCTET_STRING */
static int hf_HI2Operations_cCDecKey;             /* OCTET_STRING */
static int hf_HI2Operations_cCSalt;               /* OCTET_STRING */
static int hf_HI2Operations_packetDataHeader;     /* PacketDataHeaderReport */
static int hf_HI2Operations_packetDataSummary;    /* PacketDataSummaryReport */
static int hf_HI2Operations_packetDataHeaderMapped;  /* PacketDataHeaderMapped */
static int hf_HI2Operations_packetDataHeaderCopy;  /* PacketDataHeaderCopy */
static int hf_HI2Operations_sourceIPAddress;      /* IPAddress */
static int hf_HI2Operations_sourcePortNumber;     /* INTEGER_0_65535 */
static int hf_HI2Operations_destinationIPAddress;  /* IPAddress */
static int hf_HI2Operations_destinationPortNumber;  /* INTEGER_0_65535 */
static int hf_HI2Operations_transportProtocol;    /* INTEGER */
static int hf_HI2Operations_packetsize;           /* INTEGER */
static int hf_HI2Operations_flowLabel;            /* INTEGER */
static int hf_HI2Operations_packetCount;          /* INTEGER */
static int hf_HI2Operations_direction;            /* TPDU_direction */
static int hf_HI2Operations_headerCopy;           /* OCTET_STRING */
static int hf_HI2Operations_PacketDataSummaryReport_item;  /* PacketFlowSummary */
static int hf_HI2Operations_summaryPeriod;        /* ReportInterval */
static int hf_HI2Operations_sumOfPacketSizes;     /* INTEGER */
static int hf_HI2Operations_packetDataSummaryReason;  /* ReportReason */
static int hf_HI2Operations_firstPacketTimeStamp;  /* TimeStamp */
static int hf_HI2Operations_lastPacketTimeStamp;  /* TimeStamp */
static int hf_HI2Operations_rfc2868ValueField;    /* OCTET_STRING */
static int hf_HI2Operations_nativeIPSec;          /* NULL */
static int hf_HI2Operations_new_MSISDN;           /* PartyInformation */
static int hf_HI2Operations_new_A_MSISDN;         /* PartyInformation */
static int hf_HI2Operations_old_MSISDN;           /* PartyInformation */
static int hf_HI2Operations_old_A_MSISDN;         /* PartyInformation */
static int hf_HI2Operations_new_IMSI;             /* PartyInformation */
static int hf_HI2Operations_old_IMSI;             /* PartyInformation */
static int hf_HI2Operations_new_IMEI;             /* PartyInformation */
static int hf_HI2Operations_old_IMEI;             /* PartyInformation */
static int hf_HI2Operations_new_IMPI;             /* PartyInformation */
static int hf_HI2Operations_old_IMPI;             /* PartyInformation */
static int hf_HI2Operations_new_SIP_URI;          /* PartyInformation */
static int hf_HI2Operations_old_SIP_URI;          /* PartyInformation */
static int hf_HI2Operations_new_TEL_URI;          /* PartyInformation */
static int hf_HI2Operations_old_TEL_URI;          /* PartyInformation */
static int hf_HI2Operations_current_Serving_MME_Address;  /* DataNodeIdentifier */
static int hf_HI2Operations_previous_Serving_System_Identifier;  /* OCTET_STRING */
static int hf_HI2Operations_previous_Serving_MME_Address;  /* DataNodeIdentifier */
static int hf_HI2Operations_reason_CodeAVP;       /* INTEGER */
static int hf_HI2Operations_server_AssignmentType;  /* INTEGER */
static int hf_HI2Operations_cipher;               /* UTF8String */
static int hf_HI2Operations_cryptoContext;        /* UTF8String */
static int hf_HI2Operations_key;                  /* UTF8String */
static int hf_HI2Operations_keyEncoding;          /* UTF8String */
static int hf_HI2Operations_salt;                 /* UTF8String */
static int hf_HI2Operations_pTCOther;             /* UTF8String */
static int hf_HI2Operations_abandonCause;         /* UTF8String */
static int hf_HI2Operations_accessPolicyFailure;  /* UTF8String */
static int hf_HI2Operations_accessPolicyType;     /* AccessPolicyType */
static int hf_HI2Operations_alertIndicator;       /* AlertIndicator */
static int hf_HI2Operations_associatePresenceStatus;  /* AssociatePresenceStatus */
static int hf_HI2Operations_bearer_capability_01;  /* UTF8String */
static int hf_HI2Operations_broadcastIndicator;   /* BOOLEAN */
static int hf_HI2Operations_contactID;            /* UTF8String */
static int hf_HI2Operations_emergency;            /* Emergency */
static int hf_HI2Operations_emergencyGroupState;  /* EmergencyGroupState */
static int hf_HI2Operations_pTCType;              /* PTCType */
static int hf_HI2Operations_failureCode;          /* UTF8String */
static int hf_HI2Operations_floorActivity;        /* FloorActivity */
static int hf_HI2Operations_floorSpeakerID;       /* PTCAddress */
static int hf_HI2Operations_groupAdSender;        /* UTF8String */
static int hf_HI2Operations_groupAuthRule;        /* GroupAuthRule */
static int hf_HI2Operations_groupCharacteristics;  /* UTF8String */
static int hf_HI2Operations_holdRetrieveInd;      /* BOOLEAN */
static int hf_HI2Operations_imminentPerilInd;     /* ImminentPerilInd */
static int hf_HI2Operations_implicitFloorReq;     /* ImplicitFloorReq */
static int hf_HI2Operations_initiationCause;      /* InitiationCause */
static int hf_HI2Operations_invitationCause;      /* UTF8String */
static int hf_HI2Operations_iPAPartyID;           /* UTF8String */
static int hf_HI2Operations_iPADirection;         /* IPADirection */
static int hf_HI2Operations_listManagementAction;  /* ListManagementAction */
static int hf_HI2Operations_listManagementFailure;  /* UTF8String */
static int hf_HI2Operations_listManagementType;   /* ListManagementType */
static int hf_HI2Operations_maxTBTime;            /* UTF8String */
static int hf_HI2Operations_mCPTTGroupID;         /* UTF8String */
static int hf_HI2Operations_mCPTTID;              /* UTF8String */
static int hf_HI2Operations_mCPTTInd;             /* BOOLEAN */
static int hf_HI2Operations_mCPTTOrganizationName;  /* UTF8String */
static int hf_HI2Operations_mediaStreamAvail;     /* BOOLEAN */
static int hf_HI2Operations_priority_Level;       /* Priority_Level */
static int hf_HI2Operations_preEstSessionID;      /* UTF8String */
static int hf_HI2Operations_preEstStatus;         /* PreEstStatus */
static int hf_HI2Operations_pTCGroupID;           /* UTF8String */
static int hf_HI2Operations_pTCIDList;            /* UTF8String */
static int hf_HI2Operations_pTCMediaCapability;   /* UTF8String */
static int hf_HI2Operations_pTCOriginatingId;     /* UTF8String */
static int hf_HI2Operations_pTCParticipants;      /* UTF8String */
static int hf_HI2Operations_pTCParty;             /* UTF8String */
static int hf_HI2Operations_pTCPartyDrop;         /* UTF8String */
static int hf_HI2Operations_pTCSessionInfo;       /* UTF8String */
static int hf_HI2Operations_pTCServerURI;         /* UTF8String */
static int hf_HI2Operations_pTCUserAccessPolicy;  /* UTF8String */
static int hf_HI2Operations_pTCAddress;           /* PTCAddress */
static int hf_HI2Operations_queuedFloorControl;   /* BOOLEAN */
static int hf_HI2Operations_queuedPosition;       /* UTF8String */
static int hf_HI2Operations_registrationRequest;  /* RegistrationRequest */
static int hf_HI2Operations_registrationOutcome;  /* RegistrationOutcome */
static int hf_HI2Operations_retrieveID;           /* UTF8String */
static int hf_HI2Operations_rTPSetting;           /* RTPSetting */
static int hf_HI2Operations_talkBurstPriority;    /* Priority_Level */
static int hf_HI2Operations_talkBurstReason;      /* Talk_burst_reason_code */
static int hf_HI2Operations_talkburstControlSetting;  /* TalkburstControlSetting */
static int hf_HI2Operations_targetPresenceStatus;  /* UTF8String */
static int hf_HI2Operations_port_Number;          /* INTEGER_0_65535 */
static int hf_HI2Operations_userAccessPolicyAttempt;  /* BOOLEAN */
static int hf_HI2Operations_groupAuthorizationRulesAttempt;  /* BOOLEAN */
static int hf_HI2Operations_userAccessPolicyQuery;  /* BOOLEAN */
static int hf_HI2Operations_groupAuthorizationRulesQuery;  /* BOOLEAN */
static int hf_HI2Operations_userAccessPolicyResult;  /* UTF8String */
static int hf_HI2Operations_groupAuthorizationRulesResult;  /* UTF8String */
static int hf_HI2Operations_presenceID;           /* UTF8String */
static int hf_HI2Operations_presenceType;         /* PresenceType */
static int hf_HI2Operations_presenceStatus;       /* BOOLEAN */
static int hf_HI2Operations_clientEmergencyState;  /* T_clientEmergencyState */
static int hf_HI2Operations_groupEmergencyState;  /* T_groupEmergencyState */
static int hf_HI2Operations_tBCP_Request;         /* BOOLEAN */
static int hf_HI2Operations_tBCP_Granted;         /* BOOLEAN */
static int hf_HI2Operations_tBCP_Deny;            /* BOOLEAN */
static int hf_HI2Operations_tBCP_Queued;          /* BOOLEAN */
static int hf_HI2Operations_tBCP_Release;         /* BOOLEAN */
static int hf_HI2Operations_tBCP_Revoke;          /* BOOLEAN */
static int hf_HI2Operations_tBCP_Taken;           /* BOOLEAN */
static int hf_HI2Operations_tBCP_Idle;            /* BOOLEAN */
static int hf_HI2Operations_uri;                  /* UTF8String */
static int hf_HI2Operations_privacy_setting;      /* BOOLEAN */
static int hf_HI2Operations_privacy_alias;        /* VisibleString */
static int hf_HI2Operations_nickname;             /* UTF8String */
static int hf_HI2Operations_ip_address;           /* IPAddress */
static int hf_HI2Operations_port_number;          /* Port_Number */
static int hf_HI2Operations_talk_BurstControlProtocol;  /* UTF8String */
static int hf_HI2Operations_talk_Burst_parameters;  /* T_talk_Burst_parameters */
static int hf_HI2Operations_talk_Burst_parameters_item;  /* VisibleString */
static int hf_HI2Operations_tBCP_PortNumber;      /* INTEGER_0_65535 */
static int hf_HI2Operations_detailedCivicAddress;  /* SET_OF_DetailedCivicAddress */
static int hf_HI2Operations_detailedCivicAddress_item;  /* DetailedCivicAddress */
static int hf_HI2Operations_xmlCivicAddress;      /* XmlCivicAddress */
static int hf_HI2Operations_building;             /* UTF8String */
static int hf_HI2Operations_room;                 /* UTF8String */
static int hf_HI2Operations_placeType;            /* UTF8String */
static int hf_HI2Operations_postalCommunityName;  /* UTF8String */
static int hf_HI2Operations_additionalCode;       /* UTF8String */
static int hf_HI2Operations_seat;                 /* UTF8String */
static int hf_HI2Operations_primaryRoad;          /* UTF8String */
static int hf_HI2Operations_primaryRoadDirection;  /* UTF8String */
static int hf_HI2Operations_trailingStreetSuffix;  /* UTF8String */
static int hf_HI2Operations_streetSuffix;         /* UTF8String */
static int hf_HI2Operations_houseNumber;          /* UTF8String */
static int hf_HI2Operations_houseNumberSuffix;    /* UTF8String */
static int hf_HI2Operations_landmarkAddress;      /* UTF8String */
static int hf_HI2Operations_additionalLocation;   /* UTF8String */
static int hf_HI2Operations_name;                 /* UTF8String */
static int hf_HI2Operations_floor;                /* UTF8String */
static int hf_HI2Operations_primaryStreet;        /* UTF8String */
static int hf_HI2Operations_primaryStreetDirection;  /* UTF8String */
static int hf_HI2Operations_roadSection;          /* UTF8String */
static int hf_HI2Operations_roadBranch;           /* UTF8String */
static int hf_HI2Operations_roadSubBranch;        /* UTF8String */
static int hf_HI2Operations_roadPreModifier;      /* UTF8String */
static int hf_HI2Operations_roadPostModifier;     /* UTF8String */
static int hf_HI2Operations_postalCode;           /* UTF8String */
static int hf_HI2Operations_town;                 /* UTF8String */
static int hf_HI2Operations_county;               /* UTF8String */
static int hf_HI2Operations_country;              /* UTF8String */
static int hf_HI2Operations_language;             /* UTF8String */
static int hf_HI2Operations_posMethod;            /* PrintableString */
static int hf_HI2Operations_mapData;              /* T_mapData */
static int hf_HI2Operations_base64Map;            /* PrintableString */
static int hf_HI2Operations_url;                  /* PrintableString */
static int hf_HI2Operations_altitude;             /* T_altitude */
static int hf_HI2Operations_alt;                  /* PrintableString */
static int hf_HI2Operations_alt_uncertainty;      /* PrintableString */
static int hf_HI2Operations_speed;                /* PrintableString */
static int hf_HI2Operations_direction_01;         /* PrintableString */
static int hf_HI2Operations_level_conf;           /* PrintableString */
static int hf_HI2Operations_qOS_not_met;          /* BOOLEAN */
static int hf_HI2Operations_motionStateList;      /* T_motionStateList */
static int hf_HI2Operations_primaryMotionState;   /* PrintableString */
static int hf_HI2Operations_secondaryMotionState;  /* T_secondaryMotionState */
static int hf_HI2Operations_secondaryMotionState_item;  /* PrintableString */
static int hf_HI2Operations_confidence;           /* PrintableString */
static int hf_HI2Operations_floor_01;             /* T_floor */
static int hf_HI2Operations_floor_number;         /* PrintableString */
static int hf_HI2Operations_floor_number_uncertainty;  /* PrintableString */
static int hf_HI2Operations_additional_info;      /* PrintableString */
static int hf_HI2Operations_lALS_rawMLPPosData;   /* UTF8String */

/* Initialize the subtree pointers */
static int ett_HI2Operations_CommunicationIdentifier;
static int ett_HI2Operations_Network_Identifier;
static int ett_HI2Operations_Network_Element_Identifier;
static int ett_HI2Operations_TimeStamp;
static int ett_HI2Operations_LocalTimeStamp;
static int ett_HI2Operations_PartyInformation;
static int ett_HI2Operations_T_partyIdentity;
static int ett_HI2Operations_CallingPartyNumber;
static int ett_HI2Operations_CalledPartyNumber;
static int ett_HI2Operations_GSMLocation;
static int ett_HI2Operations_T_geoCoordinates;
static int ett_HI2Operations_T_utmCoordinates;
static int ett_HI2Operations_T_utmRefCoordinates;
static int ett_HI2Operations_UMTSLocation;
static int ett_HI2Operations_GeographicalCoordinates;
static int ett_HI2Operations_GA_Point;
static int ett_HI2Operations_GA_PointWithUnCertainty;
static int ett_HI2Operations_GA_Polygon;
static int ett_HI2Operations_GA_Polygon_item;
static int ett_HI2Operations_Services_Information;
static int ett_HI2Operations_ISUP_parameters;
static int ett_HI2Operations_DSS1_parameters_codeset_0;
static int ett_HI2Operations_MAP_parameters;
static int ett_HI2Operations_Supplementary_Services;
static int ett_HI2Operations_Standard_Supplementary_Services;
static int ett_HI2Operations_Non_Standard_Supplementary_Services;
static int ett_HI2Operations_Non_Standard_Supplementary_Services_item;
static int ett_HI2Operations_Other_Services;
static int ett_HI2Operations_ISUP_SS_parameters;
static int ett_HI2Operations_DSS1_SS_parameters_codeset_0;
static int ett_HI2Operations_DSS1_SS_parameters_codeset_4;
static int ett_HI2Operations_DSS1_SS_parameters_codeset_5;
static int ett_HI2Operations_DSS1_SS_parameters_codeset_6;
static int ett_HI2Operations_DSS1_SS_parameters_codeset_7;
static int ett_HI2Operations_DSS1_SS_Invoke_Components;
static int ett_HI2Operations_MAP_SS_Invoke_Components;
static int ett_HI2Operations_MAP_SS_Parameters;
static int ett_HI2Operations_SMS_report;
static int ett_HI2Operations_T_sMS_Contents;
static int ett_HI2Operations_T_enhancedContent;
static int ett_HI2Operations_National_Parameters;
static int ett_HI2Operations_Services_Data_Information;
static int ett_HI2Operations_DataNodeAddress;
static int ett_HI2Operations_IPAddress;
static int ett_HI2Operations_IP_value;
static int ett_HI2Operations_National_HI2_ASN1parameters;
static int ett_HI2Operations_UUS1_Content;
static int ett_HI2Operations_Service_Information;
static int ett_HI2Operations_EpsIRIsContent;
static int ett_HI2Operations_EpsIRISequence;
static int ett_HI2Operations_EpsIRIContent;
static int ett_HI2Operations_IRI_Parameters;
static int ett_HI2Operations_SET_SIZE_1_10_OF_PartyInformation;
static int ett_HI2Operations_SEQUENCE_OF_PANI_Header_Info;
static int ett_HI2Operations_SEQUENCE_OF_PartyInformation;
static int ett_HI2Operations_SEQUENCE_OF_AdditionalCellID;
static int ett_HI2Operations_DataNodeIdentifier;
static int ett_HI2Operations_PANI_Header_Info;
static int ett_HI2Operations_PANI_Location;
static int ett_HI2Operations_Location;
static int ett_HI2Operations_T_uELocationTimestamp;
static int ett_HI2Operations_AdditionalCellID;
static int ett_HI2Operations_PLMNID;
static int ett_HI2Operations_NCGI;
static int ett_HI2Operations_CorrelationValues;
static int ett_HI2Operations_T_both_IRI_CC;
static int ett_HI2Operations_IMS_VoIP_Correlation;
static int ett_HI2Operations_IMS_VoIP_Correlation_item;
static int ett_HI2Operations_IRI_to_CC_Correlation;
static int ett_HI2Operations_T_cc;
static int ett_HI2Operations_GPRS_parameters;
static int ett_HI2Operations_UmtsQos;
static int ett_HI2Operations_EPS_GTPV2_SpecificParameters;
static int ett_HI2Operations_EPSLocation;
static int ett_HI2Operations_T_uELocationTimestamp_01;
static int ett_HI2Operations_ProtConfigOptions;
static int ett_HI2Operations_RemoteUeContextConnected;
static int ett_HI2Operations_RemoteUEContext;
static int ett_HI2Operations_EPS_PMIP_SpecificParameters;
static int ett_HI2Operations_EPS_DSMIP_SpecificParameters;
static int ett_HI2Operations_EPS_MIP_SpecificParameters;
static int ett_HI2Operations_MediaDecryption_info;
static int ett_HI2Operations_CCKeyInfo;
static int ett_HI2Operations_PacketDataHeaderInformation;
static int ett_HI2Operations_PacketDataHeaderReport;
static int ett_HI2Operations_PacketDataHeaderMapped;
static int ett_HI2Operations_PacketDataHeaderCopy;
static int ett_HI2Operations_PacketDataSummaryReport;
static int ett_HI2Operations_PacketFlowSummary;
static int ett_HI2Operations_ReportInterval;
static int ett_HI2Operations_TunnelProtocol;
static int ett_HI2Operations_Change_Of_Target_Identity;
static int ett_HI2Operations_Current_Previous_Systems;
static int ett_HI2Operations_DeregistrationReason;
static int ett_HI2Operations_PTCEncryptionInfo;
static int ett_HI2Operations_PTC;
static int ett_HI2Operations_AccessPolicyType;
static int ett_HI2Operations_AssociatePresenceStatus;
static int ett_HI2Operations_EmergencyGroupState;
static int ett_HI2Operations_FloorActivity;
static int ett_HI2Operations_PTCAddress;
static int ett_HI2Operations_RTPSetting;
static int ett_HI2Operations_TalkburstControlSetting;
static int ett_HI2Operations_T_talk_Burst_parameters;
static int ett_HI2Operations_CivicAddress;
static int ett_HI2Operations_SET_OF_DetailedCivicAddress;
static int ett_HI2Operations_DetailedCivicAddress;
static int ett_HI2Operations_ExtendedLocParameters;
static int ett_HI2Operations_T_mapData;
static int ett_HI2Operations_T_altitude;
static int ett_HI2Operations_T_motionStateList;
static int ett_HI2Operations_T_secondaryMotionState;
static int ett_HI2Operations_T_floor;



static int
dissect_HI2Operations_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_HI2Operations_LawfulInterceptionIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_T_winterSummerIndication(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_LocalTimeStamp(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LocalTimeStamp_sequence, hf_index, ett_HI2Operations_LocalTimeStamp);

  return offset;
}



static int
dissect_HI2Operations_UTCTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index, NULL, NULL);

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
dissect_HI2Operations_TimeStamp(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TimeStamp_choice, hf_index, ett_HI2Operations_TimeStamp,
                                 NULL);

  return offset;
}


static const value_string HI2Operations_T_initiator_01_vals[] = {
  {   0, "not-Available" },
  {   1, "originating-Target" },
  {   2, "terminating-Target" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_initiator_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_25(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_GlobalCellID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_Rai(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_7_10(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_8_11(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_MapDatum(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_0_359(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_geoCoordinates_sequence[] = {
  { &hf_HI2Operations_geoCoordinates_latitude, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString_SIZE_7_10 },
  { &hf_HI2Operations_geoCoordinates_longitude, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString_SIZE_8_11 },
  { &hf_HI2Operations_mapDatum, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_MapDatum },
  { &hf_HI2Operations_azimuth, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_359 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_geoCoordinates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_geoCoordinates_sequence, hf_index, ett_HI2Operations_T_geoCoordinates);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_10(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_7(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_T_utmCoordinates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_utmCoordinates_sequence, hf_index, ett_HI2Operations_T_utmCoordinates);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_13(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t T_utmRefCoordinates_sequence[] = {
  { &hf_HI2Operations_utmref_string, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_PrintableString_SIZE_13 },
  { &hf_HI2Operations_mapDatum, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_HI2Operations_MapDatum },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_utmRefCoordinates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_utmRefCoordinates_sequence, hf_index, ett_HI2Operations_T_utmRefCoordinates);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_GSMLocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_T_latitudeSign(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_0_8388607(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_M8388608_8388607(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t GeographicalCoordinates_sequence[] = {
  { &hf_HI2Operations_latitudeSign, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_T_latitudeSign },
  { &hf_HI2Operations_latitude, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_INTEGER_0_8388607 },
  { &hf_HI2Operations_longitude, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_INTEGER_M8388608_8388607 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_GeographicalCoordinates(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GeographicalCoordinates_sequence, hf_index, ett_HI2Operations_GeographicalCoordinates);

  return offset;
}


static const ber_sequence_t GA_Point_sequence[] = {
  { &hf_HI2Operations_geographicalCoordinates, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_GeographicalCoordinates },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_GA_Point(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GA_Point_sequence, hf_index, ett_HI2Operations_GA_Point);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_0_127(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t GA_PointWithUnCertainty_sequence[] = {
  { &hf_HI2Operations_geographicalCoordinates, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_GeographicalCoordinates },
  { &hf_HI2Operations_uncertaintyCode, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_INTEGER_0_127 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_GA_PointWithUnCertainty(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GA_PointWithUnCertainty_sequence, hf_index, ett_HI2Operations_GA_PointWithUnCertainty);

  return offset;
}


static const ber_sequence_t GA_Polygon_item_sequence[] = {
  { &hf_HI2Operations_geographicalCoordinates, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_GeographicalCoordinates },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_GA_Polygon_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GA_Polygon_item_sequence, hf_index, ett_HI2Operations_GA_Polygon_item);

  return offset;
}


static const ber_sequence_t GA_Polygon_sequence_of[1] = {
  { &hf_HI2Operations_GA_Polygon_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_GA_Polygon_item },
};

static int
dissect_HI2Operations_GA_Polygon(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_UMTSLocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UMTSLocation_choice, hf_index, ett_HI2Operations_UMTSLocation,
                                 NULL);

  return offset;
}



static int
dissect_HI2Operations_Sai(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_UTF8String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t DetailedCivicAddress_sequence[] = {
  { &hf_HI2Operations_building, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_room  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_placeType, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_postalCommunityName, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_additionalCode, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_seat  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_primaryRoad, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_primaryRoadDirection, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_trailingStreetSuffix, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_streetSuffix, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_houseNumber, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_houseNumberSuffix, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_landmarkAddress, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_additionalLocation, BER_CLASS_CON, 114, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_name  , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_floor , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_primaryStreet, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_primaryStreetDirection, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_roadSection, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_roadBranch, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_roadSubBranch, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_roadPreModifier, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_roadPostModifier, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_postalCode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_town  , BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_county, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_country, BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_language, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_DetailedCivicAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DetailedCivicAddress_sequence, hf_index, ett_HI2Operations_DetailedCivicAddress);

  return offset;
}


static const ber_sequence_t SET_OF_DetailedCivicAddress_set_of[1] = {
  { &hf_HI2Operations_detailedCivicAddress_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_DetailedCivicAddress },
};

static int
dissect_HI2Operations_SET_OF_DetailedCivicAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_DetailedCivicAddress_set_of, hf_index, ett_HI2Operations_SET_OF_DetailedCivicAddress);

  return offset;
}



static int
dissect_HI2Operations_XmlCivicAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string HI2Operations_CivicAddress_vals[] = {
  {   0, "detailedCivicAddress" },
  {   1, "xmlCivicAddress" },
  { 0, NULL }
};

static const ber_choice_t CivicAddress_choice[] = {
  {   0, &hf_HI2Operations_detailedCivicAddress, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_SET_OF_DetailedCivicAddress },
  {   1, &hf_HI2Operations_xmlCivicAddress, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_XmlCivicAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CivicAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CivicAddress_choice, hf_index, ett_HI2Operations_CivicAddress,
                                 NULL);

  return offset;
}



static int
dissect_HI2Operations_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string HI2Operations_T_uELocationTimestamp_vals[] = {
  {   0, "timestamp" },
  {   1, "timestampUnknown" },
  { 0, NULL }
};

static const ber_choice_t T_uELocationTimestamp_choice[] = {
  {   0, &hf_HI2Operations_timestamp, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TimeStamp },
  {   1, &hf_HI2Operations_timestampUnknown, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_uELocationTimestamp(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_uELocationTimestamp_choice, hf_index, ett_HI2Operations_T_uELocationTimestamp,
                                 NULL);

  return offset;
}


static const ber_sequence_t Location_sequence[] = {
  { &hf_HI2Operations_e164_Number, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  { &hf_HI2Operations_globalCellID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_GlobalCellID },
  { &hf_HI2Operations_rAI   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Rai },
  { &hf_HI2Operations_gsmLocation, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_GSMLocation },
  { &hf_HI2Operations_umtsLocation, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_UMTSLocation },
  { &hf_HI2Operations_sAI   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Sai },
  { &hf_HI2Operations_oldRAI, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Rai },
  { &hf_HI2Operations_civicAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_CivicAddress },
  { &hf_HI2Operations_operatorSpecificInfo, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_uELocationTimestamp, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_uELocationTimestamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Location(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_T_party_Qualifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_15(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_3_8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_CallingPartyNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_CalledPartyNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CalledPartyNumber_choice, hf_index, ett_HI2Operations_CalledPartyNumber,
                                 NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_9(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
  { &hf_HI2Operations_e164_Format_01, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  { &hf_HI2Operations_sip_uri, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_tel_url, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_nai   , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_x_3GPP_Asserted_Identity, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_xUI   , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_iMPI  , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_extID , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_partyIdentity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_partyIdentity_sequence, hf_index, ett_HI2Operations_T_partyIdentity);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_256(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ISUP_parameters_set_of[1] = {
  { &hf_HI2Operations_ISUP_parameters_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_ISUP_parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ISUP_parameters_set_of, hf_index, ett_HI2Operations_ISUP_parameters);

  return offset;
}


static const ber_sequence_t DSS1_parameters_codeset_0_set_of[1] = {
  { &hf_HI2Operations_DSS1_parameters_codeset_0_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_parameters_codeset_0(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_parameters_codeset_0_set_of, hf_index, ett_HI2Operations_DSS1_parameters_codeset_0);

  return offset;
}


static const ber_sequence_t MAP_parameters_set_of[1] = {
  { &hf_HI2Operations_MAP_parameters_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_MAP_parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_Services_Information(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Services_Information_sequence, hf_index, ett_HI2Operations_Services_Information);

  return offset;
}


static const ber_sequence_t ISUP_SS_parameters_set_of[1] = {
  { &hf_HI2Operations_ISUP_SS_parameters_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_ISUP_SS_parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ISUP_SS_parameters_set_of, hf_index, ett_HI2Operations_ISUP_SS_parameters);

  return offset;
}


static const ber_sequence_t DSS1_SS_parameters_codeset_0_set_of[1] = {
  { &hf_HI2Operations_DSS1_SS_parameters_codeset_0_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_SS_parameters_codeset_0(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_SS_parameters_codeset_0_set_of, hf_index, ett_HI2Operations_DSS1_SS_parameters_codeset_0);

  return offset;
}


static const ber_sequence_t DSS1_SS_parameters_codeset_4_set_of[1] = {
  { &hf_HI2Operations_DSS1_SS_parameters_codeset_4_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_SS_parameters_codeset_4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_SS_parameters_codeset_4_set_of, hf_index, ett_HI2Operations_DSS1_SS_parameters_codeset_4);

  return offset;
}


static const ber_sequence_t DSS1_SS_parameters_codeset_5_set_of[1] = {
  { &hf_HI2Operations_DSS1_SS_parameters_codeset_5_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_SS_parameters_codeset_5(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_SS_parameters_codeset_5_set_of, hf_index, ett_HI2Operations_DSS1_SS_parameters_codeset_5);

  return offset;
}


static const ber_sequence_t DSS1_SS_parameters_codeset_6_set_of[1] = {
  { &hf_HI2Operations_DSS1_SS_parameters_codeset_6_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_SS_parameters_codeset_6(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_SS_parameters_codeset_6_set_of, hf_index, ett_HI2Operations_DSS1_SS_parameters_codeset_6);

  return offset;
}


static const ber_sequence_t DSS1_SS_parameters_codeset_7_set_of[1] = {
  { &hf_HI2Operations_DSS1_SS_parameters_codeset_7_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_SS_parameters_codeset_7(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_SS_parameters_codeset_7_set_of, hf_index, ett_HI2Operations_DSS1_SS_parameters_codeset_7);

  return offset;
}


static const ber_sequence_t DSS1_SS_Invoke_Components_set_of[1] = {
  { &hf_HI2Operations_DSS1_SS_Invoke_Components_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_DSS1_SS_Invoke_Components(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 DSS1_SS_Invoke_Components_set_of, hf_index, ett_HI2Operations_DSS1_SS_Invoke_Components);

  return offset;
}


static const ber_sequence_t MAP_SS_Parameters_set_of[1] = {
  { &hf_HI2Operations_MAP_SS_Parameters_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_MAP_SS_Parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 MAP_SS_Parameters_set_of, hf_index, ett_HI2Operations_MAP_SS_Parameters);

  return offset;
}


static const ber_sequence_t MAP_SS_Invoke_Components_set_of[1] = {
  { &hf_HI2Operations_MAP_SS_Invoke_Components_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_MAP_SS_Invoke_Components(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_Standard_Supplementary_Services(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_SimpleIndication(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_SciDataMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_Non_Standard_Supplementary_Services_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Non_Standard_Supplementary_Services_item_choice, hf_index, ett_HI2Operations_Non_Standard_Supplementary_Services_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t Non_Standard_Supplementary_Services_set_of[1] = {
  { &hf_HI2Operations_Non_Standard_Supplementary_Services_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_Non_Standard_Supplementary_Services_item },
};

static int
dissect_HI2Operations_Non_Standard_Supplementary_Services(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 Non_Standard_Supplementary_Services_set_of, hf_index, ett_HI2Operations_Non_Standard_Supplementary_Services);

  return offset;
}


static const ber_sequence_t Other_Services_set_of[1] = {
  { &hf_HI2Operations_Other_Services_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_Other_Services(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_Supplementary_Services(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Supplementary_Services_sequence, hf_index, ett_HI2Operations_Supplementary_Services);

  return offset;
}


static const value_string HI2Operations_T_iP_type_vals[] = {
  {   0, "iPV4" },
  {   1, "iPV6" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_iP_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_4_16(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_IA5String_SIZE_7_45(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_IP_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_T_iP_assignment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_1_128(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_4(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t IPAddress_sequence[] = {
  { &hf_HI2Operations_iP_type, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_iP_type },
  { &hf_HI2Operations_iP_value, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_IP_value },
  { &hf_HI2Operations_iP_assignment, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_iP_assignment },
  { &hf_HI2Operations_iPv6PrefixLength, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_1_128 },
  { &hf_HI2Operations_iPv4SubnetMask, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_4 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_IPAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPAddress_sequence, hf_index, ett_HI2Operations_IPAddress);

  return offset;
}



static int
dissect_HI2Operations_X25Address(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_DataNodeAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DataNodeAddress_choice, hf_index, ett_HI2Operations_DataNodeAddress,
                                 NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_100(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t GPRS_parameters_sequence[] = {
  { &hf_HI2Operations_pDP_address_allocated_to_the_target, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_DataNodeAddress },
  { &hf_HI2Operations_aPN   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_100 },
  { &hf_HI2Operations_pDP_type, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_2 },
  { &hf_HI2Operations_nSAPI , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_additionalIPaddress, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_DataNodeAddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_GPRS_parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GPRS_parameters_sequence, hf_index, ett_HI2Operations_GPRS_parameters);

  return offset;
}


static const ber_sequence_t Services_Data_Information_sequence[] = {
  { &hf_HI2Operations_gPRS_parameters, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_GPRS_parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Services_Data_Information(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_PartyInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PartyInformation_sequence, hf_index, ett_HI2Operations_PartyInformation);

  return offset;
}


static const ber_sequence_t SET_SIZE_1_10_OF_PartyInformation_set_of[1] = {
  { &hf_HI2Operations_partyInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_PartyInformation },
};

static int
dissect_HI2Operations_SET_SIZE_1_10_OF_PartyInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_SIZE_1_10_OF_PartyInformation_set_of, hf_index, ett_HI2Operations_SET_SIZE_1_10_OF_PartyInformation);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_5(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_T_e164_Format(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb=NULL;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);

  if (!parameter_tvb)
    return offset;

  dissect_isup_calling_party_number_parameter(parameter_tvb, actx->pinfo, tree, NULL);


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
  {   1, &hf_HI2Operations_e164_Format, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_e164_Format },
  {   2, &hf_HI2Operations_x25_Format, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  {   3, &hf_HI2Operations_iP_Format, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  {   4, &hf_HI2Operations_dNS_Format, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_25 },
  {   5, &hf_HI2Operations_iP_Address, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IPAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Network_Element_Identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_Network_Identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_CommunicationIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CommunicationIdentifier_sequence, hf_index, ett_HI2Operations_CommunicationIdentifier);

  return offset;
}


static const value_string HI2Operations_T_initiator_vals[] = {
  {   0, "target" },
  {   1, "server" },
  {   2, "undefined-party" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_initiator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_T_transfer_status(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_T_other_message(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_270(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string HI2Operations_T_character_encoding_vals[] = {
  {   0, "gsm-7-bit-ascii" },
  {   1, "eight-bit-ascii" },
  {   2, "eight-bit-binary" },
  {   3, "ucs-2" },
  {   4, "utf-8" },
  {   5, "utf-16" },
  {   6, "other" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_character_encoding(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_enhancedContent_sequence[] = {
  { &hf_HI2Operations_content_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_character_encoding, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_character_encoding },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_enhancedContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_enhancedContent_sequence, hf_index, ett_HI2Operations_T_enhancedContent);

  return offset;
}


static const ber_sequence_t T_sMS_Contents_sequence[] = {
  { &hf_HI2Operations_initiator, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_initiator },
  { &hf_HI2Operations_transfer_status, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_transfer_status },
  { &hf_HI2Operations_other_message, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_other_message },
  { &hf_HI2Operations_content, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_270 },
  { &hf_HI2Operations_enhancedContent, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_enhancedContent },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_sMS_Contents(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_SMS_report(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SMS_report_sequence, hf_index, ett_HI2Operations_SMS_report);

  return offset;
}


static const ber_sequence_t National_Parameters_set_of[1] = {
  { &hf_HI2Operations_National_Parameters_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_256 },
};

static int
dissect_HI2Operations_National_Parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 National_Parameters_set_of, hf_index, ett_HI2Operations_National_Parameters);

  return offset;
}



static int
dissect_HI2Operations_EPSCorrelationNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string HI2Operations_EPSEvent_vals[] = {
  {   1, "pDPContextActivation" },
  {   2, "startOfInterceptionWithPDPContextActive" },
  {   4, "pDPContextDeactivation" },
  {   5, "gPRSAttach" },
  {   6, "gPRSDetach" },
  {  10, "locationInfoUpdate" },
  {  11, "sMS" },
  {  13, "pDPContextModification" },
  {  14, "servingSystem" },
  {  15, "startOfInterceptionWithMSAttached" },
  {  16, "e-UTRANAttach" },
  {  17, "e-UTRANDetach" },
  {  18, "bearerActivation" },
  {  19, "startOfInterceptionWithActiveBearer" },
  {  20, "bearerModification" },
  {  21, "bearerDeactivation" },
  {  22, "uERequestedBearerResourceModification" },
  {  23, "uERequestedPDNConnectivity" },
  {  24, "uERequestedPDNDisconnection" },
  {  25, "trackingAreaEpsLocationUpdate" },
  {  26, "servingEvolvedPacketSystem" },
  {  27, "pMIPAttachTunnelActivation" },
  {  28, "pMIPDetachTunnelDeactivation" },
  {  29, "startOfInterceptWithActivePMIPTunnel" },
  {  30, "pMIPPdnGwInitiatedPdnDisconnection" },
  {  31, "mIPRegistrationTunnelActivation" },
  {  32, "mIPDeregistrationTunnelDeactivation" },
  {  33, "startOfInterceptWithActiveMIPTunnel" },
  {  34, "dSMIPRegistrationTunnelActivation" },
  {  35, "dSMIPDeregistrationTunnelDeactivation" },
  {  36, "startOfInterceptWithActiveDsmipTunnel" },
  {  37, "dSMipHaSwitch" },
  {  38, "pMIPResourceAllocationDeactivation" },
  {  39, "mIPResourceAllocationDeactivation" },
  {  40, "pMIPsessionModification" },
  {  41, "startOfInterceptWithEUTRANAttachedUE" },
  {  42, "dSMIPSessionModification" },
  {  43, "packetDataHeaderInformation" },
  {  44, "hSS-Subscriber-Record-Change" },
  {  45, "registration-Termination" },
  {  46, "location-Up-Date" },
  {  47, "cancel-Location" },
  {  48, "register-Location" },
  {  49, "location-Information-Request" },
  {  50, "proSeRemoteUEReport" },
  {  51, "proSeRemoteUEStartOfCommunication" },
  {  52, "proSeRemoteUEEndOfCommunication" },
  {  53, "startOfLIwithProSeRemoteUEOngoingComm" },
  {  54, "startOfLIforProSeUEtoNWRelay" },
  {  55, "scefRequestednonIPPDNDisconnection" },
  { 0, NULL }
};


static int
dissect_HI2Operations_EPSEvent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_GPRSOperationErrorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_UmtsQos(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UmtsQos_choice, hf_index, ett_HI2Operations_UmtsQos,
                                 NULL);

  return offset;
}


static const value_string HI2Operations_IMSevent_vals[] = {
  {   1, "unfilteredSIPmessage" },
  {   2, "sIPheaderOnly" },
  {   3, "decryptionKeysAvailable" },
  {   4, "startOfInterceptionForIMSEstablishedSession" },
  {   5, "xCAPRequest" },
  {   6, "xCAPResponse" },
  {   7, "ccUnavailable" },
  {   8, "sMSOverIMS" },
  {   9, "servingSystem" },
  {  10, "subscriberRecordChange" },
  {  11, "registrationTermination" },
  {  12, "locationInformationRequest" },
  { 0, NULL }
};


static int
dissect_HI2Operations_IMSevent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_20(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_5_17(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string HI2Operations_LDIevent_vals[] = {
  {   1, "targetEntersIA" },
  {   2, "targetLeavesIA" },
  { 0, NULL }
};


static int
dissect_HI2Operations_LDIevent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t T_cc_set_of[1] = {
  { &hf_HI2Operations_cc_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_OCTET_STRING },
};

static int
dissect_HI2Operations_T_cc(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_IRI_to_CC_Correlation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IRI_to_CC_Correlation_sequence, hf_index, ett_HI2Operations_IRI_to_CC_Correlation);

  return offset;
}



static int
dissect_HI2Operations_IRI_to_IRI_Correlation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_T_both_IRI_CC(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_CorrelationValues(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CorrelationValues_choice, hf_index, ett_HI2Operations_CorrelationValues,
                                 NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_251(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t ProtConfigOptions_sequence[] = {
  { &hf_HI2Operations_ueToNetwork, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_251 },
  { &hf_HI2Operations_networkToUe, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_251 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_ProtConfigOptions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProtConfigOptions_sequence, hf_index, ett_HI2Operations_ProtConfigOptions);

  return offset;
}


static const value_string HI2Operations_TypeOfBearer_vals[] = {
  {   1, "defaultBearer" },
  {   2, "dedicatedBearer" },
  { 0, NULL }
};


static int
dissect_HI2Operations_TypeOfBearer(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_39(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_7_97(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_1_12(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string HI2Operations_T_uELocationTimestamp_01_vals[] = {
  {   0, "timestamp" },
  {   1, "timestampUnknown" },
  { 0, NULL }
};

static const ber_choice_t T_uELocationTimestamp_01_choice[] = {
  {   0, &hf_HI2Operations_timestamp, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TimeStamp },
  {   1, &hf_HI2Operations_timestampUnknown, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_uELocationTimestamp_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_uELocationTimestamp_01_choice, hf_index, ett_HI2Operations_T_uELocationTimestamp_01,
                                 NULL);

  return offset;
}


static const ber_sequence_t EPSLocation_sequence[] = {
  { &hf_HI2Operations_userLocationInfo, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_39 },
  { &hf_HI2Operations_gsmLocation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_GSMLocation },
  { &hf_HI2Operations_umtsLocation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_UMTSLocation },
  { &hf_HI2Operations_olduserLocationInfo, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_39 },
  { &hf_HI2Operations_lastVisitedTAI, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_5 },
  { &hf_HI2Operations_tAIlist, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_7_97 },
  { &hf_HI2Operations_threeGPP2Bsid, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_12 },
  { &hf_HI2Operations_civicAddress, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_CivicAddress },
  { &hf_HI2Operations_operatorSpecificInfo, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_uELocationTimestamp_01, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_uELocationTimestamp_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_EPSLocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EPSLocation_sequence, hf_index, ett_HI2Operations_EPSLocation);

  return offset;
}



static int
dissect_HI2Operations_RemoteUserID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_RemoteUEIPInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t RemoteUEContext_sequence[] = {
  { &hf_HI2Operations_remoteUserID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_RemoteUserID },
  { &hf_HI2Operations_remoteUEIPInformation, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_RemoteUEIPInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_RemoteUEContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RemoteUEContext_sequence, hf_index, ett_HI2Operations_RemoteUEContext);

  return offset;
}


static const ber_sequence_t RemoteUeContextConnected_sequence_of[1] = {
  { &hf_HI2Operations_RemoteUeContextConnected_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_RemoteUEContext },
};

static int
dissect_HI2Operations_RemoteUeContextConnected(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      RemoteUeContextConnected_sequence_of, hf_index, ett_HI2Operations_RemoteUeContextConnected);

  return offset;
}



static int
dissect_HI2Operations_RemoteUeContextDisconnected(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_HI2Operations_RemoteUserID(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t EPS_GTPV2_SpecificParameters_sequence[] = {
  { &hf_HI2Operations_pDNAddressAllocation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_aPN   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_100 },
  { &hf_HI2Operations_protConfigOptions, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_ProtConfigOptions },
  { &hf_HI2Operations_attachType, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_ePSBearerIdentity, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_detachType, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_rATType, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_failedBearerActivationReason, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_ePSBearerQoS, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_bearerActivationType, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_TypeOfBearer },
  { &hf_HI2Operations_aPN_AMBR, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_procedureTransactionId, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_linkedEPSBearerId, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_tFT   , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_handoverIndication, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_failedBearerModReason, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_trafficAggregateDescription, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_failedTAUReason, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_failedEUTRANAttachReason, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_servingMMEaddress, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_bearerDeactivationType, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_TypeOfBearer },
  { &hf_HI2Operations_bearerDeactivationCause, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_ePSlocationOfTheTarget, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_EPSLocation },
  { &hf_HI2Operations_pDNType, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_requestType, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_uEReqPDNConnFailReason, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_extendedHandoverIndication, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_uLITimestamp, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_8 },
  { &hf_HI2Operations_uELocalIPAddress, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_uEUdpPort, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_2 },
  { &hf_HI2Operations_tWANIdentifier, BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_tWANIdentifierTimestamp, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_4 },
  { &hf_HI2Operations_proSeRemoteUeContextConnected, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_RemoteUeContextConnected },
  { &hf_HI2Operations_proSeRemoteUeContextDisconnected, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_RemoteUeContextDisconnected },
  { &hf_HI2Operations_secondaryRATUsageIndication, BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_EPS_GTPV2_SpecificParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EPS_GTPV2_SpecificParameters_sequence, hf_index, ett_HI2Operations_EPS_GTPV2_SpecificParameters);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_0_65535(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_20(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_INTEGER_0_255(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t EPS_PMIP_SpecificParameters_sequence[] = {
  { &hf_HI2Operations_lifetime, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_65535 },
  { &hf_HI2Operations_accessTechnologyType, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_4 },
  { &hf_HI2Operations_aPN   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_100 },
  { &hf_HI2Operations_iPv6HomeNetworkPrefix, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_20 },
  { &hf_HI2Operations_protConfigurationOption, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_handoverIndication_01, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_4 },
  { &hf_HI2Operations_status, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_255 },
  { &hf_HI2Operations_revocationTrigger, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_255 },
  { &hf_HI2Operations_iPv4HomeAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_4 },
  { &hf_HI2Operations_iPv6careOfAddress, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_iPv4careOfAddress, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_servingNetwork, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_3 },
  { &hf_HI2Operations_dHCPv4AddressAllocationInd, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_ePSlocationOfTheTarget, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_EPSLocation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_EPS_PMIP_SpecificParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EPS_PMIP_SpecificParameters_sequence, hf_index, ett_HI2Operations_EPS_PMIP_SpecificParameters);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_25(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_HI2Operations_OCTET_STRING_SIZE_16(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t EPS_DSMIP_SpecificParameters_sequence[] = {
  { &hf_HI2Operations_lifetime, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_65535 },
  { &hf_HI2Operations_requestedIPv6HomePrefix, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_25 },
  { &hf_HI2Operations_homeAddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_8 },
  { &hf_HI2Operations_iPv4careOfAddress_01, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_8 },
  { &hf_HI2Operations_iPv6careOfAddress_01, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_16 },
  { &hf_HI2Operations_aPN   , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_100 },
  { &hf_HI2Operations_status, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_255 },
  { &hf_HI2Operations_hSS_AAA_address, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_targetPDN_GW_Address, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_EPS_DSMIP_SpecificParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EPS_DSMIP_SpecificParameters_sequence, hf_index, ett_HI2Operations_EPS_DSMIP_SpecificParameters);

  return offset;
}


static const ber_sequence_t EPS_MIP_SpecificParameters_sequence[] = {
  { &hf_HI2Operations_lifetime, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_65535 },
  { &hf_HI2Operations_homeAddress_01, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_4 },
  { &hf_HI2Operations_careOfAddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_4 },
  { &hf_HI2Operations_homeAgentAddress, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_4 },
  { &hf_HI2Operations_code  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_255 },
  { &hf_HI2Operations_foreignDomainAddress, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_4 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_EPS_MIP_SpecificParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EPS_MIP_SpecificParameters_sequence, hf_index, ett_HI2Operations_EPS_MIP_SpecificParameters);

  return offset;
}


static const ber_sequence_t CCKeyInfo_sequence[] = {
  { &hf_HI2Operations_cCCSID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_cCDecKey, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_cCSalt, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_CCKeyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CCKeyInfo_sequence, hf_index, ett_HI2Operations_CCKeyInfo);

  return offset;
}


static const ber_sequence_t MediaDecryption_info_sequence_of[1] = {
  { &hf_HI2Operations_MediaDecryption_info_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_CCKeyInfo },
};

static int
dissect_HI2Operations_MediaDecryption_info(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      MediaDecryption_info_sequence_of, hf_index, ett_HI2Operations_MediaDecryption_info);

  return offset;
}



static int
dissect_HI2Operations_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string HI2Operations_TPDU_direction_vals[] = {
  {   1, "from-target" },
  {   2, "to-target" },
  {   3, "unknown" },
  { 0, NULL }
};


static int
dissect_HI2Operations_TPDU_direction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PacketDataHeaderMapped_sequence[] = {
  { &hf_HI2Operations_sourceIPAddress, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IPAddress },
  { &hf_HI2Operations_sourcePortNumber, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_65535 },
  { &hf_HI2Operations_destinationIPAddress, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IPAddress },
  { &hf_HI2Operations_destinationPortNumber, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_65535 },
  { &hf_HI2Operations_transportProtocol, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  { &hf_HI2Operations_packetsize, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  { &hf_HI2Operations_flowLabel, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  { &hf_HI2Operations_packetCount, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  { &hf_HI2Operations_direction, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TPDU_direction },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_PacketDataHeaderMapped(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PacketDataHeaderMapped_sequence, hf_index, ett_HI2Operations_PacketDataHeaderMapped);

  return offset;
}


static const ber_sequence_t PacketDataHeaderCopy_sequence[] = {
  { &hf_HI2Operations_direction, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_TPDU_direction },
  { &hf_HI2Operations_headerCopy, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_PacketDataHeaderCopy(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PacketDataHeaderCopy_sequence, hf_index, ett_HI2Operations_PacketDataHeaderCopy);

  return offset;
}


static const value_string HI2Operations_PacketDataHeaderReport_vals[] = {
  {   1, "packetDataHeaderMapped" },
  {   2, "packetDataHeaderCopy" },
  { 0, NULL }
};

static const ber_choice_t PacketDataHeaderReport_choice[] = {
  {   1, &hf_HI2Operations_packetDataHeaderMapped, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PacketDataHeaderMapped },
  {   2, &hf_HI2Operations_packetDataHeaderCopy, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PacketDataHeaderCopy },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_PacketDataHeaderReport(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PacketDataHeaderReport_choice, hf_index, ett_HI2Operations_PacketDataHeaderReport,
                                 NULL);

  return offset;
}


static const ber_sequence_t ReportInterval_sequence[] = {
  { &hf_HI2Operations_firstPacketTimeStamp, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_TimeStamp },
  { &hf_HI2Operations_lastPacketTimeStamp, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_TimeStamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_ReportInterval(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ReportInterval_sequence, hf_index, ett_HI2Operations_ReportInterval);

  return offset;
}


static const value_string HI2Operations_ReportReason_vals[] = {
  {   0, "timerExpired" },
  {   1, "countThresholdHit" },
  {   2, "pDPComtextDeactivated" },
  {   3, "pDPContextModification" },
  {   4, "otherOrUnknown" },
  { 0, NULL }
};


static int
dissect_HI2Operations_ReportReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PacketFlowSummary_sequence[] = {
  { &hf_HI2Operations_sourceIPAddress, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IPAddress },
  { &hf_HI2Operations_sourcePortNumber, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_65535 },
  { &hf_HI2Operations_destinationIPAddress, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IPAddress },
  { &hf_HI2Operations_destinationPortNumber, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_65535 },
  { &hf_HI2Operations_transportProtocol, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  { &hf_HI2Operations_flowLabel, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  { &hf_HI2Operations_summaryPeriod, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_HI2Operations_ReportInterval },
  { &hf_HI2Operations_packetCount, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  { &hf_HI2Operations_sumOfPacketSizes, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  { &hf_HI2Operations_packetDataSummaryReason, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_HI2Operations_ReportReason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_PacketFlowSummary(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PacketFlowSummary_sequence, hf_index, ett_HI2Operations_PacketFlowSummary);

  return offset;
}


static const ber_sequence_t PacketDataSummaryReport_sequence_of[1] = {
  { &hf_HI2Operations_PacketDataSummaryReport_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_PacketFlowSummary },
};

static int
dissect_HI2Operations_PacketDataSummaryReport(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PacketDataSummaryReport_sequence_of, hf_index, ett_HI2Operations_PacketDataSummaryReport);

  return offset;
}


static const value_string HI2Operations_PacketDataHeaderInformation_vals[] = {
  {   1, "packetDataHeader" },
  {   2, "packetDataSummary" },
  { 0, NULL }
};

static const ber_choice_t PacketDataHeaderInformation_choice[] = {
  {   1, &hf_HI2Operations_packetDataHeader, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PacketDataHeaderReport },
  {   2, &hf_HI2Operations_packetDataSummary, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PacketDataSummaryReport },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_PacketDataHeaderInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PacketDataHeaderInformation_choice, hf_index, ett_HI2Operations_PacketDataHeaderInformation,
                                 NULL);

  return offset;
}


static const value_string HI2Operations_MediaSecFailureIndication_vals[] = {
  {   0, "genericFailure" },
  { 0, NULL }
};


static int
dissect_HI2Operations_MediaSecFailureIndication(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_HeNBLocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_HI2Operations_EPSLocation(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string HI2Operations_TunnelProtocol_vals[] = {
  {   0, "rfc2868ValueField" },
  {   1, "nativeIPSec" },
  { 0, NULL }
};

static const ber_choice_t TunnelProtocol_choice[] = {
  {   0, &hf_HI2Operations_rfc2868ValueField, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  {   1, &hf_HI2Operations_nativeIPSec, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_TunnelProtocol(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TunnelProtocol_choice, hf_index, ett_HI2Operations_TunnelProtocol,
                                 NULL);

  return offset;
}


static const ber_sequence_t PANI_Location_sequence[] = {
  { &hf_HI2Operations_raw_Location, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_location, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Location },
  { &hf_HI2Operations_ePSLocation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_EPSLocation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_PANI_Location(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PANI_Location_sequence, hf_index, ett_HI2Operations_PANI_Location);

  return offset;
}


static const ber_sequence_t PANI_Header_Info_sequence[] = {
  { &hf_HI2Operations_access_Type, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_access_Class, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_network_Provided, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_NULL },
  { &hf_HI2Operations_pANI_Location, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PANI_Location },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_PANI_Header_Info(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PANI_Header_Info_sequence, hf_index, ett_HI2Operations_PANI_Header_Info);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_PANI_Header_Info_sequence_of[1] = {
  { &hf_HI2Operations_pANI_Header_Info_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_PANI_Header_Info },
};

static int
dissect_HI2Operations_SEQUENCE_OF_PANI_Header_Info(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PANI_Header_Info_sequence_of, hf_index, ett_HI2Operations_SEQUENCE_OF_PANI_Header_Info);

  return offset;
}


static const ber_sequence_t IMS_VoIP_Correlation_item_sequence[] = {
  { &hf_HI2Operations_ims_iri, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_to_IRI_Correlation },
  { &hf_HI2Operations_ims_cc, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_to_CC_Correlation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_IMS_VoIP_Correlation_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IMS_VoIP_Correlation_item_sequence, hf_index, ett_HI2Operations_IMS_VoIP_Correlation_item);

  return offset;
}


static const ber_sequence_t IMS_VoIP_Correlation_set_of[1] = {
  { &hf_HI2Operations_IMS_VoIP_Correlation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_IMS_VoIP_Correlation_item },
};

static int
dissect_HI2Operations_IMS_VoIP_Correlation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 IMS_VoIP_Correlation_set_of, hf_index, ett_HI2Operations_IMS_VoIP_Correlation);

  return offset;
}


static const value_string HI2Operations_LogicalFunctionType_vals[] = {
  {   0, "pDNGW" },
  {   1, "mME" },
  {   2, "sGW" },
  {   3, "ePDG" },
  {   4, "hSS" },
  { 0, NULL }
};


static int
dissect_HI2Operations_LogicalFunctionType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_7_25(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t DataNodeIdentifier_sequence[] = {
  { &hf_HI2Operations_dataNodeAddress, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_DataNodeAddress },
  { &hf_HI2Operations_logicalFunctionType, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_LogicalFunctionType },
  { &hf_HI2Operations_dataNodeName, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString_SIZE_7_25 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_DataNodeIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DataNodeIdentifier_sequence, hf_index, ett_HI2Operations_DataNodeIdentifier);

  return offset;
}



static int
dissect_HI2Operations_PrintableString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t Current_Previous_Systems_sequence[] = {
  { &hf_HI2Operations_serving_System_Identifier, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_current_Serving_MME_Address, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_DataNodeIdentifier },
  { &hf_HI2Operations_previous_Serving_System_Identifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_previous_Serving_MME_Address, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_DataNodeIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Current_Previous_Systems(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Current_Previous_Systems_sequence, hf_index, ett_HI2Operations_Current_Previous_Systems);

  return offset;
}


static const ber_sequence_t Change_Of_Target_Identity_sequence[] = {
  { &hf_HI2Operations_new_MSISDN, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_new_A_MSISDN, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_old_MSISDN, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_old_A_MSISDN, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_new_IMSI, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_old_IMSI, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_new_IMEI, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_old_IMEI, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_new_IMPI, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_old_IMPI, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_new_SIP_URI, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_old_SIP_URI, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_new_TEL_URI, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_old_TEL_URI, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Change_Of_Target_Identity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Change_Of_Target_Identity_sequence, hf_index, ett_HI2Operations_Change_Of_Target_Identity);

  return offset;
}


static const value_string HI2Operations_Requesting_Node_Type_vals[] = {
  {   1, "mSC" },
  {   2, "sMS-Centre" },
  {   3, "gMLC" },
  {   4, "mME" },
  {   5, "sGSN" },
  { 0, NULL }
};


static int
dissect_HI2Operations_Requesting_Node_Type(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_ProSeTargetType_vals[] = {
  {   1, "pRoSeRemoteUE" },
  {   2, "pRoSeUEtoNwRelay" },
  { 0, NULL }
};


static int
dissect_HI2Operations_ProSeTargetType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_T_mapData_vals[] = {
  {   0, "base64Map" },
  {   1, "url" },
  { 0, NULL }
};

static const ber_choice_t T_mapData_choice[] = {
  {   0, &hf_HI2Operations_base64Map, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString },
  {   1, &hf_HI2Operations_url   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_mapData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_mapData_choice, hf_index, ett_HI2Operations_T_mapData,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_altitude_sequence[] = {
  { &hf_HI2Operations_alt   , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_PrintableString },
  { &hf_HI2Operations_alt_uncertainty, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_HI2Operations_PrintableString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_altitude(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_altitude_sequence, hf_index, ett_HI2Operations_T_altitude);

  return offset;
}



static int
dissect_HI2Operations_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t T_secondaryMotionState_sequence_of[1] = {
  { &hf_HI2Operations_secondaryMotionState_item, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_PrintableString },
};

static int
dissect_HI2Operations_T_secondaryMotionState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_secondaryMotionState_sequence_of, hf_index, ett_HI2Operations_T_secondaryMotionState);

  return offset;
}


static const ber_sequence_t T_motionStateList_sequence[] = {
  { &hf_HI2Operations_primaryMotionState, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString },
  { &hf_HI2Operations_secondaryMotionState, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_secondaryMotionState },
  { &hf_HI2Operations_confidence, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_motionStateList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_motionStateList_sequence, hf_index, ett_HI2Operations_T_motionStateList);

  return offset;
}


static const ber_sequence_t T_floor_sequence[] = {
  { &hf_HI2Operations_floor_number, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_PrintableString },
  { &hf_HI2Operations_floor_number_uncertainty, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_HI2Operations_PrintableString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_T_floor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_floor_sequence, hf_index, ett_HI2Operations_T_floor);

  return offset;
}


static const ber_sequence_t ExtendedLocParameters_sequence[] = {
  { &hf_HI2Operations_posMethod, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString },
  { &hf_HI2Operations_mapData, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_mapData },
  { &hf_HI2Operations_altitude, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_altitude },
  { &hf_HI2Operations_speed , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString },
  { &hf_HI2Operations_direction_01, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString },
  { &hf_HI2Operations_level_conf, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString },
  { &hf_HI2Operations_qOS_not_met, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_motionStateList, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_motionStateList },
  { &hf_HI2Operations_floor_01, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_floor },
  { &hf_HI2Operations_additional_info, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString },
  { &hf_HI2Operations_lALS_rawMLPPosData, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_ExtendedLocParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ExtendedLocParameters_sequence, hf_index, ett_HI2Operations_ExtendedLocParameters);

  return offset;
}



static int
dissect_HI2Operations_LocationErrorCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_PartyInformation_sequence_of[1] = {
  { &hf_HI2Operations_otherIdentities_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_PartyInformation },
};

static int
dissect_HI2Operations_SEQUENCE_OF_PartyInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PartyInformation_sequence_of, hf_index, ett_HI2Operations_SEQUENCE_OF_PartyInformation);

  return offset;
}


static const value_string HI2Operations_DeregistrationReason_vals[] = {
  {   1, "reason-CodeAVP" },
  {   2, "server-AssignmentType" },
  { 0, NULL }
};

static const ber_choice_t DeregistrationReason_choice[] = {
  {   1, &hf_HI2Operations_reason_CodeAVP, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  {   2, &hf_HI2Operations_server_AssignmentType, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_DeregistrationReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DeregistrationReason_choice, hf_index, ett_HI2Operations_DeregistrationReason,
                                 NULL);

  return offset;
}


static const value_string HI2Operations_VoIPRoamingIndication_vals[] = {
  {   1, "roamingLBO" },
  {   2, "roamingS8HR" },
  { 0, NULL }
};


static int
dissect_HI2Operations_VoIPRoamingIndication(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_CSREvent_vals[] = {
  {   1, "cSREventMessage" },
  { 0, NULL }
};


static int
dissect_HI2Operations_CSREvent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AccessPolicyType_sequence[] = {
  { &hf_HI2Operations_userAccessPolicyAttempt, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_groupAuthorizationRulesAttempt, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_userAccessPolicyQuery, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_groupAuthorizationRulesQuery, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_userAccessPolicyResult, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_groupAuthorizationRulesResult, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_AccessPolicyType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AccessPolicyType_sequence, hf_index, ett_HI2Operations_AccessPolicyType);

  return offset;
}


static const value_string HI2Operations_AlertIndicator_vals[] = {
  {   1, "sent" },
  {   2, "received" },
  {   3, "cancelled" },
  { 0, NULL }
};


static int
dissect_HI2Operations_AlertIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_PresenceType_vals[] = {
  {   1, "pTCClient" },
  {   2, "pTCGroup" },
  { 0, NULL }
};


static int
dissect_HI2Operations_PresenceType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t AssociatePresenceStatus_sequence[] = {
  { &hf_HI2Operations_presenceID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_presenceType, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PresenceType },
  { &hf_HI2Operations_presenceStatus, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_AssociatePresenceStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AssociatePresenceStatus_sequence, hf_index, ett_HI2Operations_AssociatePresenceStatus);

  return offset;
}


static const value_string HI2Operations_Emergency_vals[] = {
  {   1, "imminent" },
  {   2, "peril" },
  {   3, "cancel" },
  { 0, NULL }
};


static int
dissect_HI2Operations_Emergency(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_T_clientEmergencyState_vals[] = {
  {   1, "inform" },
  {   2, "response" },
  {   3, "cancelInform" },
  {   4, "cancelResponse" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_clientEmergencyState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_T_groupEmergencyState_vals[] = {
  {   1, "inForm" },
  {   2, "reSponse" },
  {   3, "cancelInform" },
  {   4, "cancelResponse" },
  { 0, NULL }
};


static int
dissect_HI2Operations_T_groupEmergencyState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t EmergencyGroupState_sequence[] = {
  { &hf_HI2Operations_clientEmergencyState, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_clientEmergencyState },
  { &hf_HI2Operations_groupEmergencyState, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_groupEmergencyState },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_EmergencyGroupState(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EmergencyGroupState_sequence, hf_index, ett_HI2Operations_EmergencyGroupState);

  return offset;
}


static const value_string HI2Operations_PTCType_vals[] = {
  {   1, "pTCStartofInterception" },
  {   2, "pTCServinSystem" },
  {   3, "pTCSessionInitiation" },
  {   4, "pTCSessionAbandonEndRecord" },
  {   5, "pTCSessionStartContinueRecord" },
  {   6, "pTCSessionEndRecord" },
  {   7, "pTCPre-EstablishedSessionSessionRecord" },
  {   8, "pTCInstantPersonalAlert" },
  {   9, "pTCPartyJoin" },
  {  10, "pTCPartyDrop" },
  {  11, "pTCPartyHold-RetrieveRecord" },
  {  12, "pTCMediaModification" },
  {  13, "pTCGroupAdvertizement" },
  {  14, "pTCFloorConttrol" },
  {  15, "pTCTargetPressence" },
  {  16, "pTCAssociatePressence" },
  {  17, "pTCListManagementEvents" },
  {  18, "pTCAccessPolicyEvents" },
  {  19, "pTCMediaTypeNotification" },
  {  20, "pTCGroupCallRequest" },
  {  21, "pTCGroupCallCancel" },
  {  22, "pTCGroupCallResponse" },
  {  23, "pTCGroupCallInterrogate" },
  {  24, "pTCMCPTTImminentGroupCall" },
  {  25, "pTCCC" },
  {  26, "pTCRegistration" },
  {  27, "pTCEncryption" },
  { 0, NULL }
};


static int
dissect_HI2Operations_PTCType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t FloorActivity_sequence[] = {
  { &hf_HI2Operations_tBCP_Request, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_tBCP_Granted, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_tBCP_Deny, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_tBCP_Queued, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_tBCP_Release, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_tBCP_Revoke, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_tBCP_Taken, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_tBCP_Idle, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_FloorActivity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FloorActivity_sequence, hf_index, ett_HI2Operations_FloorActivity);

  return offset;
}



static int
dissect_HI2Operations_VisibleString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t PTCAddress_sequence[] = {
  { &hf_HI2Operations_uri   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_privacy_setting, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_privacy_alias, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VisibleString },
  { &hf_HI2Operations_nickname, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_PTCAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCAddress_sequence, hf_index, ett_HI2Operations_PTCAddress);

  return offset;
}


static const value_string HI2Operations_GroupAuthRule_vals[] = {
  {   0, "allow-Initiating-PtcSession" },
  {   1, "block-Initiating-PtcSession" },
  {   2, "allow-Joining-PtcSession" },
  {   3, "block-Joining-PtcSession" },
  {   4, "allow-Add-Participants" },
  {   5, "block-Add-Participants" },
  {   6, "allow-Subscription-PtcSession-State" },
  {   7, "block-Subscription-PtcSession-State" },
  {   8, "allow-Anonymity" },
  {   9, "forbid-Anonymity" },
  { 0, NULL }
};


static int
dissect_HI2Operations_GroupAuthRule(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_ImminentPerilInd_vals[] = {
  {   1, "request" },
  {   2, "response" },
  {   3, "cancel" },
  { 0, NULL }
};


static int
dissect_HI2Operations_ImminentPerilInd(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_ImplicitFloorReq_vals[] = {
  {   1, "join" },
  {   2, "rejoin" },
  {   3, "release" },
  { 0, NULL }
};


static int
dissect_HI2Operations_ImplicitFloorReq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_InitiationCause_vals[] = {
  {   1, "requests" },
  {   2, "received" },
  {   3, "pTCOriginatingId" },
  { 0, NULL }
};


static int
dissect_HI2Operations_InitiationCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_IPADirection_vals[] = {
  {   0, "toTarget" },
  {   1, "fromTarget" },
  { 0, NULL }
};


static int
dissect_HI2Operations_IPADirection(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_ListManagementAction_vals[] = {
  {   1, "create" },
  {   2, "modify" },
  {   3, "retrieve" },
  {   4, "delete" },
  {   5, "notify" },
  { 0, NULL }
};


static int
dissect_HI2Operations_ListManagementAction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_ListManagementType_vals[] = {
  {   1, "contactListManagementAttempt" },
  {   2, "groupListManagementAttempt" },
  {   3, "contactListManagementResult" },
  {   4, "groupListManagementResult" },
  {   5, "requestSuccessful" },
  { 0, NULL }
};


static int
dissect_HI2Operations_ListManagementType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_Priority_Level_vals[] = {
  {   0, "pre-emptive" },
  {   1, "high-priority" },
  {   2, "normal-priority" },
  {   3, "listen-only" },
  { 0, NULL }
};


static int
dissect_HI2Operations_Priority_Level(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_PreEstStatus_vals[] = {
  {   1, "established" },
  {   2, "modify" },
  {   3, "released" },
  { 0, NULL }
};


static int
dissect_HI2Operations_PreEstStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_RegistrationRequest_vals[] = {
  {   1, "register" },
  {   2, "re-register" },
  {   3, "de-register" },
  { 0, NULL }
};


static int
dissect_HI2Operations_RegistrationRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string HI2Operations_RegistrationOutcome_vals[] = {
  {   0, "success" },
  {   1, "failure" },
  { 0, NULL }
};


static int
dissect_HI2Operations_RegistrationOutcome(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_Port_Number(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RTPSetting_sequence[] = {
  { &hf_HI2Operations_ip_address, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IPAddress },
  { &hf_HI2Operations_port_number, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_Port_Number },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_RTPSetting(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RTPSetting_sequence, hf_index, ett_HI2Operations_RTPSetting);

  return offset;
}



static int
dissect_HI2Operations_Talk_burst_reason_code(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t T_talk_Burst_parameters_set_of[1] = {
  { &hf_HI2Operations_talk_Burst_parameters_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_VisibleString },
};

static int
dissect_HI2Operations_T_talk_Burst_parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_talk_Burst_parameters_set_of, hf_index, ett_HI2Operations_T_talk_Burst_parameters);

  return offset;
}


static const ber_sequence_t TalkburstControlSetting_sequence[] = {
  { &hf_HI2Operations_talk_BurstControlProtocol, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_talk_Burst_parameters, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_talk_Burst_parameters },
  { &hf_HI2Operations_tBCP_PortNumber, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_65535 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_TalkburstControlSetting(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TalkburstControlSetting_sequence, hf_index, ett_HI2Operations_TalkburstControlSetting);

  return offset;
}


static const ber_sequence_t PTC_sequence[] = {
  { &hf_HI2Operations_abandonCause, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_accessPolicyFailure, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_accessPolicyType, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_AccessPolicyType },
  { &hf_HI2Operations_alertIndicator, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_AlertIndicator },
  { &hf_HI2Operations_associatePresenceStatus, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_AssociatePresenceStatus },
  { &hf_HI2Operations_bearer_capability_01, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_broadcastIndicator, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_contactID, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_emergency, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Emergency },
  { &hf_HI2Operations_emergencyGroupState, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_EmergencyGroupState },
  { &hf_HI2Operations_timeStamp, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_TimeStamp },
  { &hf_HI2Operations_pTCType, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PTCType },
  { &hf_HI2Operations_failureCode, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_floorActivity, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_FloorActivity },
  { &hf_HI2Operations_floorSpeakerID, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PTCAddress },
  { &hf_HI2Operations_groupAdSender, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_groupAuthRule, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_GroupAuthRule },
  { &hf_HI2Operations_groupCharacteristics, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_holdRetrieveInd, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_imminentPerilInd, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_ImminentPerilInd },
  { &hf_HI2Operations_implicitFloorReq, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_ImplicitFloorReq },
  { &hf_HI2Operations_initiationCause, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_InitiationCause },
  { &hf_HI2Operations_invitationCause, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_iPAPartyID, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_iPADirection, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_IPADirection },
  { &hf_HI2Operations_listManagementAction, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_ListManagementAction },
  { &hf_HI2Operations_listManagementFailure, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_listManagementType, BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_ListManagementType },
  { &hf_HI2Operations_maxTBTime, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_mCPTTGroupID, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_mCPTTID, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_mCPTTInd, BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_location, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Location },
  { &hf_HI2Operations_mCPTTOrganizationName, BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_mediaStreamAvail, BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_priority_Level, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Priority_Level },
  { &hf_HI2Operations_preEstSessionID, BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_preEstStatus, BER_CLASS_CON, 42, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PreEstStatus },
  { &hf_HI2Operations_pTCGroupID, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_pTCIDList, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_pTCMediaCapability, BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_pTCOriginatingId, BER_CLASS_CON, 46, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_pTCOther, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_pTCParticipants, BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_pTCParty, BER_CLASS_CON, 49, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_pTCPartyDrop, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_pTCSessionInfo, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_pTCServerURI, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_pTCUserAccessPolicy, BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_pTCAddress, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PTCAddress },
  { &hf_HI2Operations_queuedFloorControl, BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_BOOLEAN },
  { &hf_HI2Operations_queuedPosition, BER_CLASS_CON, 56, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_registrationRequest, BER_CLASS_CON, 57, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_RegistrationRequest },
  { &hf_HI2Operations_registrationOutcome, BER_CLASS_CON, 58, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_RegistrationOutcome },
  { &hf_HI2Operations_retrieveID, BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_rTPSetting, BER_CLASS_CON, 60, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_RTPSetting },
  { &hf_HI2Operations_talkBurstPriority, BER_CLASS_CON, 61, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Priority_Level },
  { &hf_HI2Operations_talkBurstReason, BER_CLASS_CON, 62, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Talk_burst_reason_code },
  { &hf_HI2Operations_talkburstControlSetting, BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_TalkburstControlSetting },
  { &hf_HI2Operations_targetPresenceStatus, BER_CLASS_CON, 64, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_port_Number, BER_CLASS_CON, 65, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_INTEGER_0_65535 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_PTC(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTC_sequence, hf_index, ett_HI2Operations_PTC);

  return offset;
}


static const ber_sequence_t PTCEncryptionInfo_sequence[] = {
  { &hf_HI2Operations_cipher, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_cryptoContext, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_key   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_keyEncoding, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_salt  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_pTCOther, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_PTCEncryptionInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PTCEncryptionInfo_sequence, hf_index, ett_HI2Operations_PTCEncryptionInfo);

  return offset;
}



static int
dissect_HI2Operations_MCC(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_HI2Operations_MNC(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t PLMNID_sequence[] = {
  { &hf_HI2Operations_mCC   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_MCC },
  { &hf_HI2Operations_mNC   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_MNC },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_PLMNID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PLMNID_sequence, hf_index, ett_HI2Operations_PLMNID);

  return offset;
}



static int
dissect_HI2Operations_NRCellID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t NCGI_sequence[] = {
  { &hf_HI2Operations_pLMNID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_PLMNID },
  { &hf_HI2Operations_nRCellID, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NRCellID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_NCGI(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NCGI_sequence, hf_index, ett_HI2Operations_NCGI);

  return offset;
}


static const ber_sequence_t AdditionalCellID_sequence[] = {
  { &hf_HI2Operations_nCGI  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_NCGI },
  { &hf_HI2Operations_gsmLocation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_GSMLocation },
  { &hf_HI2Operations_umtsLocation, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_UMTSLocation },
  { &hf_HI2Operations_timeOfLocation, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_AdditionalCellID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AdditionalCellID_sequence, hf_index, ett_HI2Operations_AdditionalCellID);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AdditionalCellID_sequence_of[1] = {
  { &hf_HI2Operations_additionalCellIDs_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_AdditionalCellID },
};

static int
dissect_HI2Operations_SEQUENCE_OF_AdditionalCellID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AdditionalCellID_sequence_of, hf_index, ett_HI2Operations_SEQUENCE_OF_AdditionalCellID);

  return offset;
}



static int
dissect_HI2Operations_PrintableString_SIZE_2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_HI2Operations_National_HI2_ASN1parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   National_HI2_ASN1parameters_sequence, hf_index, ett_HI2Operations_National_HI2_ASN1parameters);

  return offset;
}


static const ber_sequence_t IRI_Parameters_sequence[] = {
  { &hf_HI2Operations_hi2epsDomainId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_OBJECT_IDENTIFIER },
  { &hf_HI2Operations_lawfulInterceptionIdentifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_LawfulInterceptionIdentifier },
  { &hf_HI2Operations_timeStamp, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_TimeStamp },
  { &hf_HI2Operations_initiator_01, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_initiator_01 },
  { &hf_HI2Operations_locationOfTheTarget, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Location },
  { &hf_HI2Operations_partyInformation, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SET_SIZE_1_10_OF_PartyInformation },
  { &hf_HI2Operations_serviceCenterAddress, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PartyInformation },
  { &hf_HI2Operations_sMS   , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SMS_report },
  { &hf_HI2Operations_national_Parameters, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_National_Parameters },
  { &hf_HI2Operations_ePSCorrelationNumber, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_EPSCorrelationNumber },
  { &hf_HI2Operations_ePSevent, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_EPSEvent },
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
  { &hf_HI2Operations_ldiEvent, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_LDIevent },
  { &hf_HI2Operations_correlation, BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_CorrelationValues },
  { &hf_HI2Operations_ePS_GTPV2_specificParameters, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_EPS_GTPV2_SpecificParameters },
  { &hf_HI2Operations_ePS_PMIP_specificParameters, BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_EPS_PMIP_SpecificParameters },
  { &hf_HI2Operations_ePS_DSMIP_SpecificParameters, BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_EPS_DSMIP_SpecificParameters },
  { &hf_HI2Operations_ePS_MIP_SpecificParameters, BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_EPS_MIP_SpecificParameters },
  { &hf_HI2Operations_servingNodeAddress, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_visitedNetworkId, BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_mediaDecryption_info, BER_CLASS_CON, 42, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_MediaDecryption_info },
  { &hf_HI2Operations_servingS4_SGSN_address, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_sipMessageHeaderOffer, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_sipMessageHeaderAnswer, BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_sdpOffer, BER_CLASS_CON, 46, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_sdpAnswer, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_uLITimestamp, BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_8 },
  { &hf_HI2Operations_packetDataHeaderInformation, BER_CLASS_CON, 49, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_PacketDataHeaderInformation },
  { &hf_HI2Operations_mediaSecFailureIndication, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_MediaSecFailureIndication },
  { &hf_HI2Operations_csgIdentity, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_4 },
  { &hf_HI2Operations_heNBIdentity, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_heNBiPAddress, BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_IPAddress },
  { &hf_HI2Operations_heNBLocation, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_HeNBLocation },
  { &hf_HI2Operations_tunnelProtocol, BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_TunnelProtocol },
  { &hf_HI2Operations_pANI_Header_Info, BER_CLASS_CON, 56, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SEQUENCE_OF_PANI_Header_Info },
  { &hf_HI2Operations_imsVoIP, BER_CLASS_CON, 57, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_IMS_VoIP_Correlation },
  { &hf_HI2Operations_xCAPmessage, BER_CLASS_CON, 58, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_logicalFunctionInformation, BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_DataNodeIdentifier },
  { &hf_HI2Operations_ccUnavailableReason, BER_CLASS_CON, 60, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PrintableString },
  { &hf_HI2Operations_carrierSpecificData, BER_CLASS_CON, 61, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_current_previous_systems, BER_CLASS_CON, 62, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Current_Previous_Systems },
  { &hf_HI2Operations_change_Of_Target_Identity, BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Change_Of_Target_Identity },
  { &hf_HI2Operations_requesting_Network_Identifier, BER_CLASS_CON, 64, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_requesting_Node_Type, BER_CLASS_CON, 65, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Requesting_Node_Type },
  { &hf_HI2Operations_serving_System_Identifier, BER_CLASS_CON, 66, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_proSeTargetType, BER_CLASS_CON, 67, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_ProSeTargetType },
  { &hf_HI2Operations_proSeRelayMSISDN, BER_CLASS_CON, 68, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1_9 },
  { &hf_HI2Operations_proSeRelayIMSI, BER_CLASS_CON, 69, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_3_8 },
  { &hf_HI2Operations_proSeRelayIMEI, BER_CLASS_CON, 70, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_8 },
  { &hf_HI2Operations_extendedLocParameters, BER_CLASS_CON, 71, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_ExtendedLocParameters },
  { &hf_HI2Operations_locationErrorCode, BER_CLASS_CON, 72, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_LocationErrorCode },
  { &hf_HI2Operations_otherIdentities, BER_CLASS_CON, 73, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SEQUENCE_OF_PartyInformation },
  { &hf_HI2Operations_deregistrationReason, BER_CLASS_CON, 74, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_DeregistrationReason },
  { &hf_HI2Operations_requesting_Node_Identifier, BER_CLASS_CON, 75, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING },
  { &hf_HI2Operations_roamingIndication, BER_CLASS_CON, 76, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_VoIPRoamingIndication },
  { &hf_HI2Operations_cSREvent, BER_CLASS_CON, 77, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_CSREvent },
  { &hf_HI2Operations_ptc   , BER_CLASS_CON, 78, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PTC },
  { &hf_HI2Operations_ptcEncryption, BER_CLASS_CON, 79, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_PTCEncryptionInfo },
  { &hf_HI2Operations_additionalCellIDs, BER_CLASS_CON, 80, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_SEQUENCE_OF_AdditionalCellID },
  { &hf_HI2Operations_scefID, BER_CLASS_CON, 81, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_UTF8String },
  { &hf_HI2Operations_national_HI2_ASN1parameters, BER_CLASS_CON, 255, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_National_HI2_ASN1parameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_IRI_Parameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IRI_Parameters_sequence, hf_index, ett_HI2Operations_IRI_Parameters);

  return offset;
}


static const value_string HI2Operations_EpsIRIContent_vals[] = {
  {   1, "iRI-Begin-record" },
  {   2, "iRI-End-record" },
  {   3, "iRI-Continue-record" },
  {   4, "iRI-Report-record" },
  { 0, NULL }
};

static const ber_choice_t EpsIRIContent_choice[] = {
  {   1, &hf_HI2Operations_iRI_Begin_record, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_Parameters },
  {   2, &hf_HI2Operations_iRI_End_record, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_Parameters },
  {   3, &hf_HI2Operations_iRI_Continue_record, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_Parameters },
  {   4, &hf_HI2Operations_iRI_Report_record, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_Parameters },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_EpsIRIContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EpsIRIContent_choice, hf_index, ett_HI2Operations_EpsIRIContent,
                                 NULL);

  return offset;
}


static const ber_sequence_t EpsIRISequence_sequence_of[1] = {
  { &hf_HI2Operations_EpsIRISequence_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_HI2Operations_EpsIRIContent },
};

static int
dissect_HI2Operations_EpsIRISequence(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      EpsIRISequence_sequence_of, hf_index, ett_HI2Operations_EpsIRISequence);

  return offset;
}


static const value_string HI2Operations_EpsIRIsContent_vals[] = {
  {   0, "epsiRIContent" },
  {   1, "epsIRISequence" },
  { 0, NULL }
};

static const ber_choice_t EpsIRIsContent_choice[] = {
  {   0, &hf_HI2Operations_epsiRIContent, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_EpsIRIContent },
  {   1, &hf_HI2Operations_epsIRISequence, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_HI2Operations_EpsIRISequence },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_EpsIRIsContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EpsIRIsContent_choice, hf_index, ett_HI2Operations_EpsIRIsContent,
                                 NULL);

  return offset;
}



static int
dissect_HI2Operations_IRIsContent(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_HI2Operations_EpsIRIsContent(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_HI2Operations_CC_Link_Identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string HI2Operations_Direction_Indication_vals[] = {
  {   0, "mono-mode" },
  {   1, "cc-from-target" },
  {   2, "cc-from-other-party" },
  {   3, "direction-unknown" },
  { 0, NULL }
};


static int
dissect_HI2Operations_Direction_Indication(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_HI2Operations_T_bearer_capability(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  dissect_q931_bearer_capability_ie(parameter_tvb, 0, tvb_reported_length_remaining(parameter_tvb,0), tree);


  return offset;
}


static const ber_sequence_t Service_Information_set[] = {
  { &hf_HI2Operations_high_layer_capability, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_tMR   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_bearerServiceCode, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { &hf_HI2Operations_teleServiceCode, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OCTET_STRING_SIZE_1 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_Service_Information(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              Service_Information_set, hf_index, ett_HI2Operations_Service_Information);

  return offset;
}


static const ber_sequence_t UUS1_Content_sequence[] = {
  { &hf_HI2Operations_domainID, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_OBJECT_IDENTIFIER },
  { &hf_HI2Operations_lawfullInterceptionIdentifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_LawfulInterceptionIdentifier },
  { &hf_HI2Operations_communicationIdentifier, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_HI2Operations_CommunicationIdentifier },
  { &hf_HI2Operations_cC_Link_Identifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_CC_Link_Identifier },
  { &hf_HI2Operations_direction_Indication, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_HI2Operations_Direction_Indication },
  { &hf_HI2Operations_bearer_capability, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_T_bearer_capability },
  { &hf_HI2Operations_service_Information, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_Service_Information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_HI2Operations_UUS1_Content(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

/* Heuristic test to see if it's our content */
    int8_t   tmp_class;
    bool tmp_pc;
    int32_t  tmp_tag;
    int      tmp_offset;
    unsigned length = tvb_captured_length(tvb);
    uint32_t tmp_length;
    bool tmp_ind;

    /* Check for min length */
    if (length < 6){
      return 0;
    }
    /* We start with UUS1-Content ::= SEQUENCE */
    tmp_offset = get_ber_identifier(tvb, offset, &tmp_class, &tmp_pc, &tmp_tag);
    if(tmp_class != BER_CLASS_UNI){
      return 0;
    }
    if(tmp_pc != 1){
      return 0;
    }
    if(tmp_tag != BER_UNI_TAG_SEQUENCE){
      return 0;
    }
    /* Get length just to move offset forward */
    tmp_offset = get_ber_length(tvb, tmp_offset, &tmp_length, &tmp_ind);

    /* Next 2 mandatorry elements
     *  lawfullInterceptionIdentifier [1] LawfulInterceptionIdentifier,
     *  communicationIdentifier       [2] CommunicationIdentifier,
     */
    get_ber_identifier(tvb, tmp_offset, &tmp_class, &tmp_pc, &tmp_tag);
    if(tmp_class != BER_CLASS_CON){
      return 0;
    }
    if(tmp_pc != 0){
      return 0;
    }
    if(tmp_tag != 1){
      return 0;
    }

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UUS1_Content_sequence, hf_index, ett_HI2Operations_UUS1_Content);

  return offset;
}

/*--- PDUs ---*/

static int dissect_IRIsContent_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_HI2Operations_IRIsContent(false, tvb, offset, &asn1_ctx, tree, hf_HI2Operations_IRIsContent_PDU);
  return offset;
}
static int dissect_UUS1_Content_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_HI2Operations_UUS1_Content(false, tvb, offset, &asn1_ctx, tree, hf_HI2Operations_UUS1_Content_PDU);
  return offset;
}


static bool
dissect_UUS1_Content_PDU_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  return dissect_UUS1_Content_PDU(tvb, pinfo, tree, data) > 0;
}

/*--- proto_register_HI2Operations ----------------------------------------------*/
void proto_register_HI2Operations(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_HI2Operations_IRIsContent_PDU,
      { "IRIsContent", "HI2Operations.IRIsContent",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_EpsIRIsContent_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_UUS1_Content_PDU,
      { "UUS1-Content", "HI2Operations.UUS1_Content_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_communication_Identity_Number,
      { "communication-Identity-Number", "HI2Operations.communication_Identity_Number",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_8", HFILL }},
    { &hf_HI2Operations_network_Identifier,
      { "network-Identifier", "HI2Operations.network_Identifier_element",
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
        NULL, HFILL }},
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
      { "iP-Address", "HI2Operations.iP_Address_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPAddress", HFILL }},
    { &hf_HI2Operations_localTime,
      { "localTime", "HI2Operations.localTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LocalTimeStamp", HFILL }},
    { &hf_HI2Operations_utcTime,
      { "utcTime", "HI2Operations.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_generalizedTime,
      { "generalizedTime", "HI2Operations.generalizedTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
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
      { "partyIdentity", "HI2Operations.partyIdentity_element",
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
    { &hf_HI2Operations_e164_Format_01,
      { "e164-Format", "HI2Operations.e164_Format",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_25", HFILL }},
    { &hf_HI2Operations_sip_uri,
      { "sip-uri", "HI2Operations.sip_uri",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_tel_url,
      { "tel-url", "HI2Operations.tel_url",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_nai,
      { "nai", "HI2Operations.nai",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_x_3GPP_Asserted_Identity,
      { "x-3GPP-Asserted-Identity", "HI2Operations.x_3GPP_Asserted_Identity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_xUI,
      { "xUI", "HI2Operations.xUI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_iMPI,
      { "iMPI", "HI2Operations.iMPI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_extID,
      { "extID", "HI2Operations.extID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_services_Information,
      { "services-Information", "HI2Operations.services_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_supplementary_Services_Information,
      { "supplementary-Services-Information", "HI2Operations.supplementary_Services_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Supplementary_Services", HFILL }},
    { &hf_HI2Operations_services_Data_Information,
      { "services-Data-Information", "HI2Operations.services_Data_Information_element",
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
    { &hf_HI2Operations_geoCoordinates,
      { "geoCoordinates", "HI2Operations.geoCoordinates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_geoCoordinates_latitude,
      { "latitude", "HI2Operations.geoCoordinates.latitude",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_7_10", HFILL }},
    { &hf_HI2Operations_geoCoordinates_longitude,
      { "longitude", "HI2Operations.geoCoordinates.longitude",
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
      { "utmCoordinates", "HI2Operations.utmCoordinates_element",
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
      { "utmRefCoordinates", "HI2Operations.utmRefCoordinates_element",
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
      { "point", "HI2Operations.point_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GA_Point", HFILL }},
    { &hf_HI2Operations_pointWithUnCertainty,
      { "pointWithUnCertainty", "HI2Operations.pointWithUnCertainty_element",
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
    { &hf_HI2Operations_latitude,
      { "latitude", "HI2Operations.latitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_HI2Operations_longitude,
      { "longitude", "HI2Operations.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_HI2Operations_geographicalCoordinates,
      { "geographicalCoordinates", "HI2Operations.geographicalCoordinates_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_uncertaintyCode,
      { "uncertaintyCode", "HI2Operations.uncertaintyCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_HI2Operations_GA_Polygon_item,
      { "GA-Polygon item", "HI2Operations.GA_Polygon_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
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
      { "standard-Supplementary-Services", "HI2Operations.standard_Supplementary_Services_element",
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
    { &hf_HI2Operations_communicationIdentifier,
      { "communicationIdentifier", "HI2Operations.communicationIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_timeStamp,
      { "timeStamp", "HI2Operations.timeStamp",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_TimeStamp_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_sMS_Contents,
      { "sMS-Contents", "HI2Operations.sMS_Contents_element",
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
    { &hf_HI2Operations_enhancedContent,
      { "enhancedContent", "HI2Operations.enhancedContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_content_01,
      { "content", "HI2Operations.content",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_character_encoding,
      { "character-encoding", "HI2Operations.character_encoding",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_character_encoding_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_National_Parameters_item,
      { "National-Parameters item", "HI2Operations.National_Parameters_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_256", HFILL }},
    { &hf_HI2Operations_gPRS_parameters,
      { "gPRS-parameters", "HI2Operations.gPRS_parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ipAddress,
      { "ipAddress", "HI2Operations.ipAddress_element",
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
    { &hf_HI2Operations_iPv6PrefixLength,
      { "iPv6PrefixLength", "HI2Operations.iPv6PrefixLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_128", HFILL }},
    { &hf_HI2Operations_iPv4SubnetMask,
      { "iPv4SubnetMask", "HI2Operations.iPv4SubnetMask",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
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
    { &hf_HI2Operations_domainID,
      { "domainID", "HI2Operations.domainID",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_HI2Operations_lawfullInterceptionIdentifier,
      { "lawfullInterceptionIdentifier", "HI2Operations.lawfullInterceptionIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LawfulInterceptionIdentifier", HFILL }},
    { &hf_HI2Operations_cC_Link_Identifier,
      { "cC-Link-Identifier", "HI2Operations.cC_Link_Identifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_direction_Indication,
      { "direction-Indication", "HI2Operations.direction_Indication",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_Direction_Indication_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_bearer_capability,
      { "bearer-capability", "HI2Operations.bearer_capability",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_service_Information,
      { "service-Information", "HI2Operations.service_Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_high_layer_capability,
      { "high-layer-capability", "HI2Operations.high_layer_capability",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_tMR,
      { "tMR", "HI2Operations.tMR",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_bearerServiceCode,
      { "bearerServiceCode", "HI2Operations.bearerServiceCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_teleServiceCode,
      { "teleServiceCode", "HI2Operations.teleServiceCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_epsiRIContent,
      { "epsiRIContent", "HI2Operations.epsiRIContent",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_EpsIRIContent_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_epsIRISequence,
      { "epsIRISequence", "HI2Operations.epsIRISequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_EpsIRISequence_item,
      { "EpsIRIContent", "HI2Operations.EpsIRIContent",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_EpsIRIContent_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_iRI_Begin_record,
      { "iRI-Begin-record", "HI2Operations.iRI_Begin_record_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IRI_Parameters", HFILL }},
    { &hf_HI2Operations_iRI_End_record,
      { "iRI-End-record", "HI2Operations.iRI_End_record_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IRI_Parameters", HFILL }},
    { &hf_HI2Operations_iRI_Continue_record,
      { "iRI-Continue-record", "HI2Operations.iRI_Continue_record_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IRI_Parameters", HFILL }},
    { &hf_HI2Operations_iRI_Report_record,
      { "iRI-Report-record", "HI2Operations.iRI_Report_record_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IRI_Parameters", HFILL }},
    { &hf_HI2Operations_hi2epsDomainId,
      { "hi2epsDomainId", "HI2Operations.hi2epsDomainId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_HI2Operations_lawfulInterceptionIdentifier,
      { "lawfulInterceptionIdentifier", "HI2Operations.lawfulInterceptionIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_initiator_01,
      { "initiator", "HI2Operations.initiator",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_initiator_01_vals), 0,
        "T_initiator_01", HFILL }},
    { &hf_HI2Operations_locationOfTheTarget,
      { "locationOfTheTarget", "HI2Operations.locationOfTheTarget_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Location", HFILL }},
    { &hf_HI2Operations_partyInformation,
      { "partyInformation", "HI2Operations.partyInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_SIZE_1_10_OF_PartyInformation", HFILL }},
    { &hf_HI2Operations_partyInformation_item,
      { "PartyInformation", "HI2Operations.PartyInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_serviceCenterAddress,
      { "serviceCenterAddress", "HI2Operations.serviceCenterAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_sMS,
      { "sMS", "HI2Operations.sMS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SMS_report", HFILL }},
    { &hf_HI2Operations_national_Parameters,
      { "national-Parameters", "HI2Operations.national_Parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ePSCorrelationNumber,
      { "ePSCorrelationNumber", "HI2Operations.ePSCorrelationNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ePSevent,
      { "ePSevent", "HI2Operations.ePSevent",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_EPSEvent_vals), 0,
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
      { "networkIdentifier", "HI2Operations.networkIdentifier_element",
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
    { &hf_HI2Operations_ldiEvent,
      { "ldiEvent", "HI2Operations.ldiEvent",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_LDIevent_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_correlation,
      { "correlation", "HI2Operations.correlation",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_CorrelationValues_vals), 0,
        "CorrelationValues", HFILL }},
    { &hf_HI2Operations_ePS_GTPV2_specificParameters,
      { "ePS-GTPV2-specificParameters", "HI2Operations.ePS_GTPV2_specificParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ePS_PMIP_specificParameters,
      { "ePS-PMIP-specificParameters", "HI2Operations.ePS_PMIP_specificParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ePS_DSMIP_SpecificParameters,
      { "ePS-DSMIP-SpecificParameters", "HI2Operations.ePS_DSMIP_SpecificParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ePS_MIP_SpecificParameters,
      { "ePS-MIP-SpecificParameters", "HI2Operations.ePS_MIP_SpecificParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_servingNodeAddress,
      { "servingNodeAddress", "HI2Operations.servingNodeAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_visitedNetworkId,
      { "visitedNetworkId", "HI2Operations.visitedNetworkId",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_mediaDecryption_info,
      { "mediaDecryption-info", "HI2Operations.mediaDecryption_info",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_servingS4_SGSN_address,
      { "servingS4-SGSN-address", "HI2Operations.servingS4_SGSN_address",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_sipMessageHeaderOffer,
      { "sipMessageHeaderOffer", "HI2Operations.sipMessageHeaderOffer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_sipMessageHeaderAnswer,
      { "sipMessageHeaderAnswer", "HI2Operations.sipMessageHeaderAnswer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_sdpOffer,
      { "sdpOffer", "HI2Operations.sdpOffer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_sdpAnswer,
      { "sdpAnswer", "HI2Operations.sdpAnswer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_uLITimestamp,
      { "uLITimestamp", "HI2Operations.uLITimestamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_8", HFILL }},
    { &hf_HI2Operations_packetDataHeaderInformation,
      { "packetDataHeaderInformation", "HI2Operations.packetDataHeaderInformation",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_PacketDataHeaderInformation_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_mediaSecFailureIndication,
      { "mediaSecFailureIndication", "HI2Operations.mediaSecFailureIndication",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_MediaSecFailureIndication_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_csgIdentity,
      { "csgIdentity", "HI2Operations.csgIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_HI2Operations_heNBIdentity,
      { "heNBIdentity", "HI2Operations.heNBIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_heNBiPAddress,
      { "heNBiPAddress", "HI2Operations.heNBiPAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPAddress", HFILL }},
    { &hf_HI2Operations_heNBLocation,
      { "heNBLocation", "HI2Operations.heNBLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_tunnelProtocol,
      { "tunnelProtocol", "HI2Operations.tunnelProtocol",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_TunnelProtocol_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_pANI_Header_Info,
      { "pANI-Header-Info", "HI2Operations.pANI_Header_Info",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PANI_Header_Info", HFILL }},
    { &hf_HI2Operations_pANI_Header_Info_item,
      { "PANI-Header-Info", "HI2Operations.PANI_Header_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_imsVoIP,
      { "imsVoIP", "HI2Operations.imsVoIP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "IMS_VoIP_Correlation", HFILL }},
    { &hf_HI2Operations_xCAPmessage,
      { "xCAPmessage", "HI2Operations.xCAPmessage",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_logicalFunctionInformation,
      { "logicalFunctionInformation", "HI2Operations.logicalFunctionInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataNodeIdentifier", HFILL }},
    { &hf_HI2Operations_ccUnavailableReason,
      { "ccUnavailableReason", "HI2Operations.ccUnavailableReason",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_carrierSpecificData,
      { "carrierSpecificData", "HI2Operations.carrierSpecificData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_current_previous_systems,
      { "current-previous-systems", "HI2Operations.current_previous_systems_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_change_Of_Target_Identity,
      { "change-Of-Target-Identity", "HI2Operations.change_Of_Target_Identity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_requesting_Network_Identifier,
      { "requesting-Network-Identifier", "HI2Operations.requesting_Network_Identifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_requesting_Node_Type,
      { "requesting-Node-Type", "HI2Operations.requesting_Node_Type",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_Requesting_Node_Type_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_serving_System_Identifier,
      { "serving-System-Identifier", "HI2Operations.serving_System_Identifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_proSeTargetType,
      { "proSeTargetType", "HI2Operations.proSeTargetType",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_ProSeTargetType_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_proSeRelayMSISDN,
      { "proSeRelayMSISDN", "HI2Operations.proSeRelayMSISDN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_9", HFILL }},
    { &hf_HI2Operations_proSeRelayIMSI,
      { "proSeRelayIMSI", "HI2Operations.proSeRelayIMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3_8", HFILL }},
    { &hf_HI2Operations_proSeRelayIMEI,
      { "proSeRelayIMEI", "HI2Operations.proSeRelayIMEI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_8", HFILL }},
    { &hf_HI2Operations_extendedLocParameters,
      { "extendedLocParameters", "HI2Operations.extendedLocParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_locationErrorCode,
      { "locationErrorCode", "HI2Operations.locationErrorCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_otherIdentities,
      { "otherIdentities", "HI2Operations.otherIdentities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PartyInformation", HFILL }},
    { &hf_HI2Operations_otherIdentities_item,
      { "PartyInformation", "HI2Operations.PartyInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_deregistrationReason,
      { "deregistrationReason", "HI2Operations.deregistrationReason",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_DeregistrationReason_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_requesting_Node_Identifier,
      { "requesting-Node-Identifier", "HI2Operations.requesting_Node_Identifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_roamingIndication,
      { "roamingIndication", "HI2Operations.roamingIndication",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_VoIPRoamingIndication_vals), 0,
        "VoIPRoamingIndication", HFILL }},
    { &hf_HI2Operations_cSREvent,
      { "cSREvent", "HI2Operations.cSREvent",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_CSREvent_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ptc,
      { "ptc", "HI2Operations.ptc_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ptcEncryption,
      { "ptcEncryption", "HI2Operations.ptcEncryption_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCEncryptionInfo", HFILL }},
    { &hf_HI2Operations_additionalCellIDs,
      { "additionalCellIDs", "HI2Operations.additionalCellIDs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AdditionalCellID", HFILL }},
    { &hf_HI2Operations_additionalCellIDs_item,
      { "AdditionalCellID", "HI2Operations.AdditionalCellID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_scefID,
      { "scefID", "HI2Operations.scefID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_national_HI2_ASN1parameters,
      { "national-HI2-ASN1parameters", "HI2Operations.national_HI2_ASN1parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_dataNodeAddress,
      { "dataNodeAddress", "HI2Operations.dataNodeAddress",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_DataNodeAddress_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_logicalFunctionType,
      { "logicalFunctionType", "HI2Operations.logicalFunctionType",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_LogicalFunctionType_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_dataNodeName,
      { "dataNodeName", "HI2Operations.dataNodeName",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_7_25", HFILL }},
    { &hf_HI2Operations_access_Type,
      { "access-Type", "HI2Operations.access_Type",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_access_Class,
      { "access-Class", "HI2Operations.access_Class",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_network_Provided,
      { "network-Provided", "HI2Operations.network_Provided_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_pANI_Location,
      { "pANI-Location", "HI2Operations.pANI_Location_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_raw_Location,
      { "raw-Location", "HI2Operations.raw_Location",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_location,
      { "location", "HI2Operations.location_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ePSLocation,
      { "ePSLocation", "HI2Operations.ePSLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_e164_Number,
      { "e164-Number", "HI2Operations.e164_Number",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_25", HFILL }},
    { &hf_HI2Operations_globalCellID,
      { "globalCellID", "HI2Operations.globalCellID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_rAI,
      { "rAI", "HI2Operations.rAI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
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
        NULL, HFILL }},
    { &hf_HI2Operations_oldRAI,
      { "oldRAI", "HI2Operations.oldRAI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Rai", HFILL }},
    { &hf_HI2Operations_civicAddress,
      { "civicAddress", "HI2Operations.civicAddress",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_CivicAddress_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_operatorSpecificInfo,
      { "operatorSpecificInfo", "HI2Operations.operatorSpecificInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_uELocationTimestamp,
      { "uELocationTimestamp", "HI2Operations.uELocationTimestamp",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_uELocationTimestamp_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_timestamp,
      { "timestamp", "HI2Operations.timestamp",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_TimeStamp_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_timestampUnknown,
      { "timestampUnknown", "HI2Operations.timestampUnknown_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_nCGI,
      { "nCGI", "HI2Operations.nCGI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_timeOfLocation,
      { "timeOfLocation", "HI2Operations.timeOfLocation",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_HI2Operations_mCC,
      { "mCC", "HI2Operations.mCC",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_mNC,
      { "mNC", "HI2Operations.mNC",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_pLMNID,
      { "pLMNID", "HI2Operations.pLMNID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_nRCellID,
      { "nRCellID", "HI2Operations.nRCellID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_iri_to_CC,
      { "iri-to-CC", "HI2Operations.iri_to_CC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IRI_to_CC_Correlation", HFILL }},
    { &hf_HI2Operations_iri_to_iri,
      { "iri-to-iri", "HI2Operations.iri_to_iri",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IRI_to_IRI_Correlation", HFILL }},
    { &hf_HI2Operations_both_IRI_CC,
      { "both-IRI-CC", "HI2Operations.both_IRI_CC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_iri_CC,
      { "iri-CC", "HI2Operations.iri_CC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IRI_to_CC_Correlation", HFILL }},
    { &hf_HI2Operations_iri_IRI,
      { "iri-IRI", "HI2Operations.iri_IRI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IRI_to_IRI_Correlation", HFILL }},
    { &hf_HI2Operations_IMS_VoIP_Correlation_item,
      { "IMS-VoIP-Correlation item", "HI2Operations.IMS_VoIP_Correlation_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_ims_iri,
      { "ims-iri", "HI2Operations.ims_iri",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IRI_to_IRI_Correlation", HFILL }},
    { &hf_HI2Operations_ims_cc,
      { "ims-cc", "HI2Operations.ims_cc_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IRI_to_CC_Correlation", HFILL }},
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
    { &hf_HI2Operations_nSAPI,
      { "nSAPI", "HI2Operations.nSAPI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_additionalIPaddress,
      { "additionalIPaddress", "HI2Operations.additionalIPaddress",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_DataNodeAddress_vals), 0,
        "DataNodeAddress", HFILL }},
    { &hf_HI2Operations_qosMobileRadio,
      { "qosMobileRadio", "HI2Operations.qosMobileRadio",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_qosGn,
      { "qosGn", "HI2Operations.qosGn",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_pDNAddressAllocation,
      { "pDNAddressAllocation", "HI2Operations.pDNAddressAllocation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_protConfigOptions,
      { "protConfigOptions", "HI2Operations.protConfigOptions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_attachType,
      { "attachType", "HI2Operations.attachType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_ePSBearerIdentity,
      { "ePSBearerIdentity", "HI2Operations.ePSBearerIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_detachType,
      { "detachType", "HI2Operations.detachType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_rATType,
      { "rATType", "HI2Operations.rATType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_failedBearerActivationReason,
      { "failedBearerActivationReason", "HI2Operations.failedBearerActivationReason",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_ePSBearerQoS,
      { "ePSBearerQoS", "HI2Operations.ePSBearerQoS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_bearerActivationType,
      { "bearerActivationType", "HI2Operations.bearerActivationType",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_TypeOfBearer_vals), 0,
        "TypeOfBearer", HFILL }},
    { &hf_HI2Operations_aPN_AMBR,
      { "aPN-AMBR", "HI2Operations.aPN_AMBR",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_procedureTransactionId,
      { "procedureTransactionId", "HI2Operations.procedureTransactionId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_linkedEPSBearerId,
      { "linkedEPSBearerId", "HI2Operations.linkedEPSBearerId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_tFT,
      { "tFT", "HI2Operations.tFT",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_handoverIndication,
      { "handoverIndication", "HI2Operations.handoverIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_failedBearerModReason,
      { "failedBearerModReason", "HI2Operations.failedBearerModReason",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_trafficAggregateDescription,
      { "trafficAggregateDescription", "HI2Operations.trafficAggregateDescription",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_failedTAUReason,
      { "failedTAUReason", "HI2Operations.failedTAUReason",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_failedEUTRANAttachReason,
      { "failedEUTRANAttachReason", "HI2Operations.failedEUTRANAttachReason",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_servingMMEaddress,
      { "servingMMEaddress", "HI2Operations.servingMMEaddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_bearerDeactivationType,
      { "bearerDeactivationType", "HI2Operations.bearerDeactivationType",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_TypeOfBearer_vals), 0,
        "TypeOfBearer", HFILL }},
    { &hf_HI2Operations_bearerDeactivationCause,
      { "bearerDeactivationCause", "HI2Operations.bearerDeactivationCause",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_ePSlocationOfTheTarget,
      { "ePSlocationOfTheTarget", "HI2Operations.ePSlocationOfTheTarget_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EPSLocation", HFILL }},
    { &hf_HI2Operations_pDNType,
      { "pDNType", "HI2Operations.pDNType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_requestType,
      { "requestType", "HI2Operations.requestType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_uEReqPDNConnFailReason,
      { "uEReqPDNConnFailReason", "HI2Operations.uEReqPDNConnFailReason",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_extendedHandoverIndication,
      { "extendedHandoverIndication", "HI2Operations.extendedHandoverIndication",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_uELocalIPAddress,
      { "uELocalIPAddress", "HI2Operations.uELocalIPAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_uEUdpPort,
      { "uEUdpPort", "HI2Operations.uEUdpPort",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_HI2Operations_tWANIdentifier,
      { "tWANIdentifier", "HI2Operations.tWANIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_tWANIdentifierTimestamp,
      { "tWANIdentifierTimestamp", "HI2Operations.tWANIdentifierTimestamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_HI2Operations_proSeRemoteUeContextConnected,
      { "proSeRemoteUeContextConnected", "HI2Operations.proSeRemoteUeContextConnected",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RemoteUeContextConnected", HFILL }},
    { &hf_HI2Operations_proSeRemoteUeContextDisconnected,
      { "proSeRemoteUeContextDisconnected", "HI2Operations.proSeRemoteUeContextDisconnected",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RemoteUeContextDisconnected", HFILL }},
    { &hf_HI2Operations_secondaryRATUsageIndication,
      { "secondaryRATUsageIndication", "HI2Operations.secondaryRATUsageIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_userLocationInfo,
      { "userLocationInfo", "HI2Operations.userLocationInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_39", HFILL }},
    { &hf_HI2Operations_olduserLocationInfo,
      { "olduserLocationInfo", "HI2Operations.olduserLocationInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_39", HFILL }},
    { &hf_HI2Operations_lastVisitedTAI,
      { "lastVisitedTAI", "HI2Operations.lastVisitedTAI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_5", HFILL }},
    { &hf_HI2Operations_tAIlist,
      { "tAIlist", "HI2Operations.tAIlist",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_7_97", HFILL }},
    { &hf_HI2Operations_threeGPP2Bsid,
      { "threeGPP2Bsid", "HI2Operations.threeGPP2Bsid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_12", HFILL }},
    { &hf_HI2Operations_uELocationTimestamp_01,
      { "uELocationTimestamp", "HI2Operations.uELocationTimestamp",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_uELocationTimestamp_01_vals), 0,
        "T_uELocationTimestamp_01", HFILL }},
    { &hf_HI2Operations_ueToNetwork,
      { "ueToNetwork", "HI2Operations.ueToNetwork",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_251", HFILL }},
    { &hf_HI2Operations_networkToUe,
      { "networkToUe", "HI2Operations.networkToUe",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_251", HFILL }},
    { &hf_HI2Operations_RemoteUeContextConnected_item,
      { "RemoteUEContext", "HI2Operations.RemoteUEContext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_remoteUserID,
      { "remoteUserID", "HI2Operations.remoteUserID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_remoteUEIPInformation,
      { "remoteUEIPInformation", "HI2Operations.remoteUEIPInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_lifetime,
      { "lifetime", "HI2Operations.lifetime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_HI2Operations_accessTechnologyType,
      { "accessTechnologyType", "HI2Operations.accessTechnologyType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_HI2Operations_iPv6HomeNetworkPrefix,
      { "iPv6HomeNetworkPrefix", "HI2Operations.iPv6HomeNetworkPrefix",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_20", HFILL }},
    { &hf_HI2Operations_protConfigurationOption,
      { "protConfigurationOption", "HI2Operations.protConfigurationOption",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_handoverIndication_01,
      { "handoverIndication", "HI2Operations.handoverIndication",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_HI2Operations_status,
      { "status", "HI2Operations.status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_HI2Operations_revocationTrigger,
      { "revocationTrigger", "HI2Operations.revocationTrigger",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_HI2Operations_iPv4HomeAddress,
      { "iPv4HomeAddress", "HI2Operations.iPv4HomeAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_HI2Operations_iPv6careOfAddress,
      { "iPv6careOfAddress", "HI2Operations.iPv6careOfAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_iPv4careOfAddress,
      { "iPv4careOfAddress", "HI2Operations.iPv4careOfAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_servingNetwork,
      { "servingNetwork", "HI2Operations.servingNetwork",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_HI2Operations_dHCPv4AddressAllocationInd,
      { "dHCPv4AddressAllocationInd", "HI2Operations.dHCPv4AddressAllocationInd",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1", HFILL }},
    { &hf_HI2Operations_requestedIPv6HomePrefix,
      { "requestedIPv6HomePrefix", "HI2Operations.requestedIPv6HomePrefix",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_25", HFILL }},
    { &hf_HI2Operations_homeAddress,
      { "homeAddress", "HI2Operations.homeAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_8", HFILL }},
    { &hf_HI2Operations_iPv4careOfAddress_01,
      { "iPv4careOfAddress", "HI2Operations.iPv4careOfAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_8", HFILL }},
    { &hf_HI2Operations_iPv6careOfAddress_01,
      { "iPv6careOfAddress", "HI2Operations.iPv6careOfAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_HI2Operations_hSS_AAA_address,
      { "hSS-AAA-address", "HI2Operations.hSS_AAA_address",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_targetPDN_GW_Address,
      { "targetPDN-GW-Address", "HI2Operations.targetPDN_GW_Address",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_homeAddress_01,
      { "homeAddress", "HI2Operations.homeAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_HI2Operations_careOfAddress,
      { "careOfAddress", "HI2Operations.careOfAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_HI2Operations_homeAgentAddress,
      { "homeAgentAddress", "HI2Operations.homeAgentAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_HI2Operations_code,
      { "code", "HI2Operations.code",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_HI2Operations_foreignDomainAddress,
      { "foreignDomainAddress", "HI2Operations.foreignDomainAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_HI2Operations_MediaDecryption_info_item,
      { "CCKeyInfo", "HI2Operations.CCKeyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_cCCSID,
      { "cCCSID", "HI2Operations.cCCSID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_cCDecKey,
      { "cCDecKey", "HI2Operations.cCDecKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_cCSalt,
      { "cCSalt", "HI2Operations.cCSalt",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_packetDataHeader,
      { "packetDataHeader", "HI2Operations.packetDataHeader",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_PacketDataHeaderReport_vals), 0,
        "PacketDataHeaderReport", HFILL }},
    { &hf_HI2Operations_packetDataSummary,
      { "packetDataSummary", "HI2Operations.packetDataSummary",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PacketDataSummaryReport", HFILL }},
    { &hf_HI2Operations_packetDataHeaderMapped,
      { "packetDataHeaderMapped", "HI2Operations.packetDataHeaderMapped_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_packetDataHeaderCopy,
      { "packetDataHeaderCopy", "HI2Operations.packetDataHeaderCopy_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_sourceIPAddress,
      { "sourceIPAddress", "HI2Operations.sourceIPAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPAddress", HFILL }},
    { &hf_HI2Operations_sourcePortNumber,
      { "sourcePortNumber", "HI2Operations.sourcePortNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_HI2Operations_destinationIPAddress,
      { "destinationIPAddress", "HI2Operations.destinationIPAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPAddress", HFILL }},
    { &hf_HI2Operations_destinationPortNumber,
      { "destinationPortNumber", "HI2Operations.destinationPortNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_HI2Operations_transportProtocol,
      { "transportProtocol", "HI2Operations.transportProtocol",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_HI2Operations_packetsize,
      { "packetsize", "HI2Operations.packetsize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_HI2Operations_flowLabel,
      { "flowLabel", "HI2Operations.flowLabel",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_HI2Operations_packetCount,
      { "packetCount", "HI2Operations.packetCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_HI2Operations_direction,
      { "direction", "HI2Operations.direction",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_TPDU_direction_vals), 0,
        "TPDU_direction", HFILL }},
    { &hf_HI2Operations_headerCopy,
      { "headerCopy", "HI2Operations.headerCopy",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_PacketDataSummaryReport_item,
      { "PacketFlowSummary", "HI2Operations.PacketFlowSummary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_summaryPeriod,
      { "summaryPeriod", "HI2Operations.summaryPeriod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportInterval", HFILL }},
    { &hf_HI2Operations_sumOfPacketSizes,
      { "sumOfPacketSizes", "HI2Operations.sumOfPacketSizes",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_HI2Operations_packetDataSummaryReason,
      { "packetDataSummaryReason", "HI2Operations.packetDataSummaryReason",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_ReportReason_vals), 0,
        "ReportReason", HFILL }},
    { &hf_HI2Operations_firstPacketTimeStamp,
      { "firstPacketTimeStamp", "HI2Operations.firstPacketTimeStamp",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_TimeStamp_vals), 0,
        "TimeStamp", HFILL }},
    { &hf_HI2Operations_lastPacketTimeStamp,
      { "lastPacketTimeStamp", "HI2Operations.lastPacketTimeStamp",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_TimeStamp_vals), 0,
        "TimeStamp", HFILL }},
    { &hf_HI2Operations_rfc2868ValueField,
      { "rfc2868ValueField", "HI2Operations.rfc2868ValueField",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_nativeIPSec,
      { "nativeIPSec", "HI2Operations.nativeIPSec_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_new_MSISDN,
      { "new-MSISDN", "HI2Operations.new_MSISDN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_new_A_MSISDN,
      { "new-A-MSISDN", "HI2Operations.new_A_MSISDN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_old_MSISDN,
      { "old-MSISDN", "HI2Operations.old_MSISDN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_old_A_MSISDN,
      { "old-A-MSISDN", "HI2Operations.old_A_MSISDN_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_new_IMSI,
      { "new-IMSI", "HI2Operations.new_IMSI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_old_IMSI,
      { "old-IMSI", "HI2Operations.old_IMSI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_new_IMEI,
      { "new-IMEI", "HI2Operations.new_IMEI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_old_IMEI,
      { "old-IMEI", "HI2Operations.old_IMEI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_new_IMPI,
      { "new-IMPI", "HI2Operations.new_IMPI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_old_IMPI,
      { "old-IMPI", "HI2Operations.old_IMPI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_new_SIP_URI,
      { "new-SIP-URI", "HI2Operations.new_SIP_URI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_old_SIP_URI,
      { "old-SIP-URI", "HI2Operations.old_SIP_URI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_new_TEL_URI,
      { "new-TEL-URI", "HI2Operations.new_TEL_URI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_old_TEL_URI,
      { "old-TEL-URI", "HI2Operations.old_TEL_URI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PartyInformation", HFILL }},
    { &hf_HI2Operations_current_Serving_MME_Address,
      { "current-Serving-MME-Address", "HI2Operations.current_Serving_MME_Address_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataNodeIdentifier", HFILL }},
    { &hf_HI2Operations_previous_Serving_System_Identifier,
      { "previous-Serving-System-Identifier", "HI2Operations.previous_Serving_System_Identifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_HI2Operations_previous_Serving_MME_Address,
      { "previous-Serving-MME-Address", "HI2Operations.previous_Serving_MME_Address_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DataNodeIdentifier", HFILL }},
    { &hf_HI2Operations_reason_CodeAVP,
      { "reason-CodeAVP", "HI2Operations.reason_CodeAVP",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_HI2Operations_server_AssignmentType,
      { "server-AssignmentType", "HI2Operations.server_AssignmentType",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_HI2Operations_cipher,
      { "cipher", "HI2Operations.cipher",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_cryptoContext,
      { "cryptoContext", "HI2Operations.cryptoContext",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_key,
      { "key", "HI2Operations.key",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_keyEncoding,
      { "keyEncoding", "HI2Operations.keyEncoding",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_salt,
      { "salt", "HI2Operations.salt",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_pTCOther,
      { "pTCOther", "HI2Operations.pTCOther",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_abandonCause,
      { "abandonCause", "HI2Operations.abandonCause",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_accessPolicyFailure,
      { "accessPolicyFailure", "HI2Operations.accessPolicyFailure",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_accessPolicyType,
      { "accessPolicyType", "HI2Operations.accessPolicyType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_alertIndicator,
      { "alertIndicator", "HI2Operations.alertIndicator",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_AlertIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_associatePresenceStatus,
      { "associatePresenceStatus", "HI2Operations.associatePresenceStatus_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_bearer_capability_01,
      { "bearer-capability", "HI2Operations.bearer_capability",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_broadcastIndicator,
      { "broadcastIndicator", "HI2Operations.broadcastIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_contactID,
      { "contactID", "HI2Operations.contactID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_emergency,
      { "emergency", "HI2Operations.emergency",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_Emergency_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_emergencyGroupState,
      { "emergencyGroupState", "HI2Operations.emergencyGroupState_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_pTCType,
      { "pTCType", "HI2Operations.pTCType",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_PTCType_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_failureCode,
      { "failureCode", "HI2Operations.failureCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_floorActivity,
      { "floorActivity", "HI2Operations.floorActivity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_floorSpeakerID,
      { "floorSpeakerID", "HI2Operations.floorSpeakerID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PTCAddress", HFILL }},
    { &hf_HI2Operations_groupAdSender,
      { "groupAdSender", "HI2Operations.groupAdSender",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_groupAuthRule,
      { "groupAuthRule", "HI2Operations.groupAuthRule",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_GroupAuthRule_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_groupCharacteristics,
      { "groupCharacteristics", "HI2Operations.groupCharacteristics",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_holdRetrieveInd,
      { "holdRetrieveInd", "HI2Operations.holdRetrieveInd",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_imminentPerilInd,
      { "imminentPerilInd", "HI2Operations.imminentPerilInd",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_ImminentPerilInd_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_implicitFloorReq,
      { "implicitFloorReq", "HI2Operations.implicitFloorReq",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_ImplicitFloorReq_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_initiationCause,
      { "initiationCause", "HI2Operations.initiationCause",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_InitiationCause_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_invitationCause,
      { "invitationCause", "HI2Operations.invitationCause",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_iPAPartyID,
      { "iPAPartyID", "HI2Operations.iPAPartyID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_iPADirection,
      { "iPADirection", "HI2Operations.iPADirection",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_IPADirection_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_listManagementAction,
      { "listManagementAction", "HI2Operations.listManagementAction",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_ListManagementAction_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_listManagementFailure,
      { "listManagementFailure", "HI2Operations.listManagementFailure",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_listManagementType,
      { "listManagementType", "HI2Operations.listManagementType",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_ListManagementType_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_maxTBTime,
      { "maxTBTime", "HI2Operations.maxTBTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_mCPTTGroupID,
      { "mCPTTGroupID", "HI2Operations.mCPTTGroupID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_mCPTTID,
      { "mCPTTID", "HI2Operations.mCPTTID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_mCPTTInd,
      { "mCPTTInd", "HI2Operations.mCPTTInd",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_mCPTTOrganizationName,
      { "mCPTTOrganizationName", "HI2Operations.mCPTTOrganizationName",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_mediaStreamAvail,
      { "mediaStreamAvail", "HI2Operations.mediaStreamAvail",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_priority_Level,
      { "priority-Level", "HI2Operations.priority_Level",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_Priority_Level_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_preEstSessionID,
      { "preEstSessionID", "HI2Operations.preEstSessionID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_preEstStatus,
      { "preEstStatus", "HI2Operations.preEstStatus",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_PreEstStatus_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_pTCGroupID,
      { "pTCGroupID", "HI2Operations.pTCGroupID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_pTCIDList,
      { "pTCIDList", "HI2Operations.pTCIDList",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_pTCMediaCapability,
      { "pTCMediaCapability", "HI2Operations.pTCMediaCapability",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_pTCOriginatingId,
      { "pTCOriginatingId", "HI2Operations.pTCOriginatingId",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_pTCParticipants,
      { "pTCParticipants", "HI2Operations.pTCParticipants",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_pTCParty,
      { "pTCParty", "HI2Operations.pTCParty",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_pTCPartyDrop,
      { "pTCPartyDrop", "HI2Operations.pTCPartyDrop",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_pTCSessionInfo,
      { "pTCSessionInfo", "HI2Operations.pTCSessionInfo",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_pTCServerURI,
      { "pTCServerURI", "HI2Operations.pTCServerURI",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_pTCUserAccessPolicy,
      { "pTCUserAccessPolicy", "HI2Operations.pTCUserAccessPolicy",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_pTCAddress,
      { "pTCAddress", "HI2Operations.pTCAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_queuedFloorControl,
      { "queuedFloorControl", "HI2Operations.queuedFloorControl",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_queuedPosition,
      { "queuedPosition", "HI2Operations.queuedPosition",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_registrationRequest,
      { "registrationRequest", "HI2Operations.registrationRequest",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_RegistrationRequest_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_registrationOutcome,
      { "registrationOutcome", "HI2Operations.registrationOutcome",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_RegistrationOutcome_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_retrieveID,
      { "retrieveID", "HI2Operations.retrieveID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_rTPSetting,
      { "rTPSetting", "HI2Operations.rTPSetting_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_talkBurstPriority,
      { "talkBurstPriority", "HI2Operations.talkBurstPriority",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_Priority_Level_vals), 0,
        "Priority_Level", HFILL }},
    { &hf_HI2Operations_talkBurstReason,
      { "talkBurstReason", "HI2Operations.talkBurstReason",
        FT_STRING, BASE_NONE, NULL, 0,
        "Talk_burst_reason_code", HFILL }},
    { &hf_HI2Operations_talkburstControlSetting,
      { "talkburstControlSetting", "HI2Operations.talkburstControlSetting_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_targetPresenceStatus,
      { "targetPresenceStatus", "HI2Operations.targetPresenceStatus",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_port_Number,
      { "port-Number", "HI2Operations.port_Number",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_HI2Operations_userAccessPolicyAttempt,
      { "userAccessPolicyAttempt", "HI2Operations.userAccessPolicyAttempt",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_groupAuthorizationRulesAttempt,
      { "groupAuthorizationRulesAttempt", "HI2Operations.groupAuthorizationRulesAttempt",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_userAccessPolicyQuery,
      { "userAccessPolicyQuery", "HI2Operations.userAccessPolicyQuery",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_groupAuthorizationRulesQuery,
      { "groupAuthorizationRulesQuery", "HI2Operations.groupAuthorizationRulesQuery",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_userAccessPolicyResult,
      { "userAccessPolicyResult", "HI2Operations.userAccessPolicyResult",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_groupAuthorizationRulesResult,
      { "groupAuthorizationRulesResult", "HI2Operations.groupAuthorizationRulesResult",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_presenceID,
      { "presenceID", "HI2Operations.presenceID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_presenceType,
      { "presenceType", "HI2Operations.presenceType",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_PresenceType_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_presenceStatus,
      { "presenceStatus", "HI2Operations.presenceStatus",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_clientEmergencyState,
      { "clientEmergencyState", "HI2Operations.clientEmergencyState",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_clientEmergencyState_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_groupEmergencyState,
      { "groupEmergencyState", "HI2Operations.groupEmergencyState",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_groupEmergencyState_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_tBCP_Request,
      { "tBCP-Request", "HI2Operations.tBCP_Request",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_tBCP_Granted,
      { "tBCP-Granted", "HI2Operations.tBCP_Granted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_tBCP_Deny,
      { "tBCP-Deny", "HI2Operations.tBCP_Deny",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_tBCP_Queued,
      { "tBCP-Queued", "HI2Operations.tBCP_Queued",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_tBCP_Release,
      { "tBCP-Release", "HI2Operations.tBCP_Release",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_tBCP_Revoke,
      { "tBCP-Revoke", "HI2Operations.tBCP_Revoke",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_tBCP_Taken,
      { "tBCP-Taken", "HI2Operations.tBCP_Taken",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_tBCP_Idle,
      { "tBCP-Idle", "HI2Operations.tBCP_Idle",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_uri,
      { "uri", "HI2Operations.uri",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_privacy_setting,
      { "privacy-setting", "HI2Operations.privacy_setting",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_privacy_alias,
      { "privacy-alias", "HI2Operations.privacy_alias",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_HI2Operations_nickname,
      { "nickname", "HI2Operations.nickname",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_ip_address,
      { "ip-address", "HI2Operations.ip_address_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPAddress", HFILL }},
    { &hf_HI2Operations_port_number,
      { "port-number", "HI2Operations.port_number",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_talk_BurstControlProtocol,
      { "talk-BurstControlProtocol", "HI2Operations.talk_BurstControlProtocol",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_talk_Burst_parameters,
      { "talk-Burst-parameters", "HI2Operations.talk_Burst_parameters",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_talk_Burst_parameters", HFILL }},
    { &hf_HI2Operations_talk_Burst_parameters_item,
      { "talk-Burst-parameters item", "HI2Operations.talk_Burst_parameters_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_HI2Operations_tBCP_PortNumber,
      { "tBCP-PortNumber", "HI2Operations.tBCP_PortNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_HI2Operations_detailedCivicAddress,
      { "detailedCivicAddress", "HI2Operations.detailedCivicAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_DetailedCivicAddress", HFILL }},
    { &hf_HI2Operations_detailedCivicAddress_item,
      { "DetailedCivicAddress", "HI2Operations.DetailedCivicAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_xmlCivicAddress,
      { "xmlCivicAddress", "HI2Operations.xmlCivicAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_building,
      { "building", "HI2Operations.building",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_room,
      { "room", "HI2Operations.room",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_placeType,
      { "placeType", "HI2Operations.placeType",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_postalCommunityName,
      { "postalCommunityName", "HI2Operations.postalCommunityName",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_additionalCode,
      { "additionalCode", "HI2Operations.additionalCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_seat,
      { "seat", "HI2Operations.seat",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_primaryRoad,
      { "primaryRoad", "HI2Operations.primaryRoad",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_primaryRoadDirection,
      { "primaryRoadDirection", "HI2Operations.primaryRoadDirection",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_trailingStreetSuffix,
      { "trailingStreetSuffix", "HI2Operations.trailingStreetSuffix",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_streetSuffix,
      { "streetSuffix", "HI2Operations.streetSuffix",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_houseNumber,
      { "houseNumber", "HI2Operations.houseNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_houseNumberSuffix,
      { "houseNumberSuffix", "HI2Operations.houseNumberSuffix",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_landmarkAddress,
      { "landmarkAddress", "HI2Operations.landmarkAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_additionalLocation,
      { "additionalLocation", "HI2Operations.additionalLocation",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_name,
      { "name", "HI2Operations.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_floor,
      { "floor", "HI2Operations.floor",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_primaryStreet,
      { "primaryStreet", "HI2Operations.primaryStreet",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_primaryStreetDirection,
      { "primaryStreetDirection", "HI2Operations.primaryStreetDirection",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_roadSection,
      { "roadSection", "HI2Operations.roadSection",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_roadBranch,
      { "roadBranch", "HI2Operations.roadBranch",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_roadSubBranch,
      { "roadSubBranch", "HI2Operations.roadSubBranch",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_roadPreModifier,
      { "roadPreModifier", "HI2Operations.roadPreModifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_roadPostModifier,
      { "roadPostModifier", "HI2Operations.roadPostModifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_postalCode,
      { "postalCode", "HI2Operations.postalCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_town,
      { "town", "HI2Operations.town",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_county,
      { "county", "HI2Operations.county",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_country,
      { "country", "HI2Operations.country",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_language,
      { "language", "HI2Operations.language",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_HI2Operations_posMethod,
      { "posMethod", "HI2Operations.posMethod",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_mapData,
      { "mapData", "HI2Operations.mapData",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_T_mapData_vals), 0,
        NULL, HFILL }},
    { &hf_HI2Operations_base64Map,
      { "base64Map", "HI2Operations.base64Map",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_url,
      { "url", "HI2Operations.url",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_altitude,
      { "altitude", "HI2Operations.altitude_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_alt,
      { "alt", "HI2Operations.alt",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_alt_uncertainty,
      { "alt-uncertainty", "HI2Operations.alt_uncertainty",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_speed,
      { "speed", "HI2Operations.speed",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_direction_01,
      { "direction", "HI2Operations.direction",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_level_conf,
      { "level-conf", "HI2Operations.level_conf",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_qOS_not_met,
      { "qOS-not-met", "HI2Operations.qOS_not_met",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_HI2Operations_motionStateList,
      { "motionStateList", "HI2Operations.motionStateList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_primaryMotionState,
      { "primaryMotionState", "HI2Operations.primaryMotionState",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_secondaryMotionState,
      { "secondaryMotionState", "HI2Operations.secondaryMotionState",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_secondaryMotionState_item,
      { "secondaryMotionState item", "HI2Operations.secondaryMotionState_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_confidence,
      { "confidence", "HI2Operations.confidence",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_floor_01,
      { "floor", "HI2Operations.floor_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_HI2Operations_floor_number,
      { "floor-number", "HI2Operations.floor_number",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_floor_number_uncertainty,
      { "floor-number-uncertainty", "HI2Operations.floor_number_uncertainty",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_additional_info,
      { "additional-info", "HI2Operations.additional_info",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_HI2Operations_lALS_rawMLPPosData,
      { "lALS-rawMLPPosData", "HI2Operations.lALS_rawMLPPosData",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_HI2Operations_CommunicationIdentifier,
    &ett_HI2Operations_Network_Identifier,
    &ett_HI2Operations_Network_Element_Identifier,
    &ett_HI2Operations_TimeStamp,
    &ett_HI2Operations_LocalTimeStamp,
    &ett_HI2Operations_PartyInformation,
    &ett_HI2Operations_T_partyIdentity,
    &ett_HI2Operations_CallingPartyNumber,
    &ett_HI2Operations_CalledPartyNumber,
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
    &ett_HI2Operations_T_enhancedContent,
    &ett_HI2Operations_National_Parameters,
    &ett_HI2Operations_Services_Data_Information,
    &ett_HI2Operations_DataNodeAddress,
    &ett_HI2Operations_IPAddress,
    &ett_HI2Operations_IP_value,
    &ett_HI2Operations_National_HI2_ASN1parameters,
    &ett_HI2Operations_UUS1_Content,
    &ett_HI2Operations_Service_Information,
    &ett_HI2Operations_EpsIRIsContent,
    &ett_HI2Operations_EpsIRISequence,
    &ett_HI2Operations_EpsIRIContent,
    &ett_HI2Operations_IRI_Parameters,
    &ett_HI2Operations_SET_SIZE_1_10_OF_PartyInformation,
    &ett_HI2Operations_SEQUENCE_OF_PANI_Header_Info,
    &ett_HI2Operations_SEQUENCE_OF_PartyInformation,
    &ett_HI2Operations_SEQUENCE_OF_AdditionalCellID,
    &ett_HI2Operations_DataNodeIdentifier,
    &ett_HI2Operations_PANI_Header_Info,
    &ett_HI2Operations_PANI_Location,
    &ett_HI2Operations_Location,
    &ett_HI2Operations_T_uELocationTimestamp,
    &ett_HI2Operations_AdditionalCellID,
    &ett_HI2Operations_PLMNID,
    &ett_HI2Operations_NCGI,
    &ett_HI2Operations_CorrelationValues,
    &ett_HI2Operations_T_both_IRI_CC,
    &ett_HI2Operations_IMS_VoIP_Correlation,
    &ett_HI2Operations_IMS_VoIP_Correlation_item,
    &ett_HI2Operations_IRI_to_CC_Correlation,
    &ett_HI2Operations_T_cc,
    &ett_HI2Operations_GPRS_parameters,
    &ett_HI2Operations_UmtsQos,
    &ett_HI2Operations_EPS_GTPV2_SpecificParameters,
    &ett_HI2Operations_EPSLocation,
    &ett_HI2Operations_T_uELocationTimestamp_01,
    &ett_HI2Operations_ProtConfigOptions,
    &ett_HI2Operations_RemoteUeContextConnected,
    &ett_HI2Operations_RemoteUEContext,
    &ett_HI2Operations_EPS_PMIP_SpecificParameters,
    &ett_HI2Operations_EPS_DSMIP_SpecificParameters,
    &ett_HI2Operations_EPS_MIP_SpecificParameters,
    &ett_HI2Operations_MediaDecryption_info,
    &ett_HI2Operations_CCKeyInfo,
    &ett_HI2Operations_PacketDataHeaderInformation,
    &ett_HI2Operations_PacketDataHeaderReport,
    &ett_HI2Operations_PacketDataHeaderMapped,
    &ett_HI2Operations_PacketDataHeaderCopy,
    &ett_HI2Operations_PacketDataSummaryReport,
    &ett_HI2Operations_PacketFlowSummary,
    &ett_HI2Operations_ReportInterval,
    &ett_HI2Operations_TunnelProtocol,
    &ett_HI2Operations_Change_Of_Target_Identity,
    &ett_HI2Operations_Current_Previous_Systems,
    &ett_HI2Operations_DeregistrationReason,
    &ett_HI2Operations_PTCEncryptionInfo,
    &ett_HI2Operations_PTC,
    &ett_HI2Operations_AccessPolicyType,
    &ett_HI2Operations_AssociatePresenceStatus,
    &ett_HI2Operations_EmergencyGroupState,
    &ett_HI2Operations_FloorActivity,
    &ett_HI2Operations_PTCAddress,
    &ett_HI2Operations_RTPSetting,
    &ett_HI2Operations_TalkburstControlSetting,
    &ett_HI2Operations_T_talk_Burst_parameters,
    &ett_HI2Operations_CivicAddress,
    &ett_HI2Operations_SET_OF_DetailedCivicAddress,
    &ett_HI2Operations_DetailedCivicAddress,
    &ett_HI2Operations_ExtendedLocParameters,
    &ett_HI2Operations_T_mapData,
    &ett_HI2Operations_T_altitude,
    &ett_HI2Operations_T_motionStateList,
    &ett_HI2Operations_T_secondaryMotionState,
    &ett_HI2Operations_T_floor,
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

    heur_dissector_add("q931_user", dissect_UUS1_Content_PDU_heur, "HI3CCLinkData", "hi3cclinkdata",
        proto_HI2Operations, HEURISTIC_ENABLE);

}

