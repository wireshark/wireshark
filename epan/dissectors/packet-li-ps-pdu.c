/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-li-ps-pdu.c                                                         */
/* asn2wrs.py -b -q -L -p li-ps-pdu -c ./li-ps-pdu.cnf -s ./packet-li-ps-pdu-template -D . -O ../.. LI-PS-PDU.asn IPAccessPDU.asn Common-Parameters.asn */

/* packet-li-ps-pdu-template.c
 * Routines for ETSI TS 102 232-1 LI-PS-PDU dissection
 *
 * See ETSI TS 102 232-1 V3.38.1 (2026-08), with ETSI TS 102 232-3 (IP access)
 * and ETSI TS 103 280 (common parameters)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/asn1.h>
#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-HI2Operations.h"
#include "packet-li-ps-pdu.h"
#include "packet-lix2.h"

#define PNAME  "ETSI TS 102 232-1 LI-PS-PDU"
#define PSNAME "LI-PS-PDU"
#define PFNAME "li-ps-pdu"

void proto_register_li_ps_pdu(void);
void proto_reg_handoff_li_ps_pdu(void);

static int proto_li_ps_pdu;

static dissector_handle_t ip_handle;

static int hf_li_ps_pdu_PS_PDU_PDU;               /* PS_PDU */
static int hf_li_ps_pdu_Payload_PDU;              /* Payload */
static int hf_li_ps_pdu_pSHeader;                 /* PSHeader */
static int hf_li_ps_pdu_payload;                  /* Payload */
static int hf_li_ps_pdu_li_psDomainId;            /* OBJECT_IDENTIFIER */
static int hf_li_ps_pdu_lawfulInterceptionIdentifier;  /* LawfulInterceptionIdentifier */
static int hf_li_ps_pdu_authorizationCountryCode;  /* PrintableString_SIZE_2 */
static int hf_li_ps_pdu_communicationIdentifier;  /* CommunicationIdentifier */
static int hf_li_ps_pdu_sequenceNumber;           /* INTEGER_0_4294967295 */
static int hf_li_ps_pdu_timeStamp;                /* GeneralizedTime */
static int hf_li_ps_pdu_interceptionPointID;      /* PrintableString_SIZE_1_8 */
static int hf_li_ps_pdu_microSecondTimeStamp;     /* MicroSecondTimeStamp */
static int hf_li_ps_pdu_timeStampQualifier;       /* TimeStampQualifier */
static int hf_li_ps_pdu_extendedInterceptionPointID;  /* OCTET_STRING_SIZE_1_65535 */
static int hf_li_ps_pdu_networkFunctionIdentifier;  /* OCTET_STRING_SIZE_1_65535 */
static int hf_li_ps_pdu_iRIPayloadSequence;       /* SEQUENCE_OF_IRIPayload */
static int hf_li_ps_pdu_iRIPayloadSequence_item;  /* IRIPayload */
static int hf_li_ps_pdu_cCPayloadSequence;        /* SEQUENCE_OF_CCPayload */
static int hf_li_ps_pdu_cCPayloadSequence_item;   /* CCPayload */
static int hf_li_ps_pdu_tRIPayload;               /* TRIPayload */
static int hf_li_ps_pdu_hI1_Operation;            /* HI1_Operation */
static int hf_li_ps_pdu_encryptionContainer;      /* EncryptionContainer */
static int hf_li_ps_pdu_threeGPP_HI1_Operation;   /* ThreeGPP_HI1_Operation */
static int hf_li_ps_pdu_iLHIPayload;              /* SEQUENCE_OF_ILHIPayload */
static int hf_li_ps_pdu_iLHIPayload_item;         /* ILHIPayload */
static int hf_li_ps_pdu_hI4Payload;               /* SEQUENCE_OF_HI4Payload */
static int hf_li_ps_pdu_hI4Payload_item;          /* HI4Payload */
static int hf_li_ps_pdu_threeGPP_LI_Notification;  /* LINotificationPayload */
static int hf_li_ps_pdu_hi4Notification;          /* HI4Notification */
static int hf_li_ps_pdu_networkIdentifier;        /* NetworkIdentifier */
static int hf_li_ps_pdu_communicationIdentityNumber;  /* INTEGER_0_4294967295 */
static int hf_li_ps_pdu_deliveryCountryCode;      /* PrintableString_SIZE_2 */
static int hf_li_ps_pdu_cINExtension;             /* CorrelationValues */
static int hf_li_ps_pdu_operatorIdentifier;       /* OCTET_STRING_SIZE_1_16 */
static int hf_li_ps_pdu_networkElementIdentifier;  /* OCTET_STRING_SIZE_1_16 */
static int hf_li_ps_pdu_eTSI671NEID;              /* Network_Element_Identifier */
static int hf_li_ps_pdu_payloadDirection;         /* PayloadDirection */
static int hf_li_ps_pdu_cCContents;               /* CCContents */
static int hf_li_ps_pdu_emailCC;                  /* EmailCC */
static int hf_li_ps_pdu_iPCC;                     /* IPCC */
static int hf_li_ps_pdu_uMTSCC;                   /* OCTET_STRING */
static int hf_li_ps_pdu_l2CC;                     /* L2CC */
static int hf_li_ps_pdu_tTRAFFIC_1;               /* TTRAFFIC */
static int hf_li_ps_pdu_cTTRAFFIC_1;              /* CTTRAFFIC */
static int hf_li_ps_pdu_tTRAFFIC_2;               /* TS101909202_TTRAFFIC */
static int hf_li_ps_pdu_cTTRAFFIC_2;              /* TS101909202_CTTRAFFIC */
static int hf_li_ps_pdu_pstnIsdnCC;               /* PstnIsdnCC */
static int hf_li_ps_pdu_iPMMCC;                   /* IPMMCC */
static int hf_li_ps_pdu_messagingCC;              /* MessagingCC */
static int hf_li_ps_pdu_ePSCC;                    /* OCTET_STRING */
static int hf_li_ps_pdu_uMTSCC_CC_PDU;            /* CC_PDU */
static int hf_li_ps_pdu_ePSCC_CC_PDU;             /* Eps_HI3_PS_CC_PDU */
static int hf_li_ps_pdu_messagingMMCC;            /* MessagingMMCC */
static int hf_li_ps_pdu_confCC_CC_PDU;            /* Conf_CC_PDU */
static int hf_li_ps_pdu_voipCC_CC_PDU;            /* Voip_CC_PDU */
static int hf_li_ps_pdu_gcseCC_CC_PDU;            /* Gcse_CC_PDU */
static int hf_li_ps_pdu_cSvoice_CC_PDU;           /* CSvoice_CC_PDU */
static int hf_li_ps_pdu_threeGPP33128DefinedCC;   /* T_threeGPP33128DefinedCC */
static int hf_li_ps_pdu_seconds;                  /* INTEGER_0_18446744073709551615 */
static int hf_li_ps_pdu_microSeconds;             /* INTEGER_0_999999 */
static int hf_li_ps_pdu_iRIType;                  /* IRIType */
static int hf_li_ps_pdu_iRIContents;              /* IRIContents */
static int hf_li_ps_pdu_sessionDirection;         /* PayloadDirection */
static int hf_li_ps_pdu_emailIRI;                 /* EmailIRI */
static int hf_li_ps_pdu_iPIRI;                    /* IPIRI */
static int hf_li_ps_pdu_iPIRIOnly;                /* IPIRIOnly */
static int hf_li_ps_pdu_uMTSIRI;                  /* UMTSIRI */
static int hf_li_ps_pdu_eTSI671IRI;               /* ETSI671IRI */
static int hf_li_ps_pdu_l2IRI;                    /* L2IRI */
static int hf_li_ps_pdu_l2IRIOnly;                /* L2IRIOnly */
static int hf_li_ps_pdu_tARGETACTIVITYMONITOR_1;  /* TARGETACTIVITYMONITOR_1 */
static int hf_li_ps_pdu_tARGETACTIVITYMONITOR_2;  /* TARGETACTIVITYMONITOR */
static int hf_li_ps_pdu_pstnIsdnIRI;              /* PstnIsdnIRI */
static int hf_li_ps_pdu_iPMMIRI;                  /* IPMMIRI */
static int hf_li_ps_pdu_messagingIRI;             /* MessagingIRI */
static int hf_li_ps_pdu_ePSIRI;                   /* EPSIRI */
static int hf_li_ps_pdu_confIRI;                  /* ConfIRI */
static int hf_li_ps_pdu_proseIRI;                 /* ProSeIRI */
static int hf_li_ps_pdu_gcseIRI;                  /* GcseIRI */
static int hf_li_ps_pdu_threeGPP33128DefinedIRI;  /* T_threeGPP33128DefinedIRI */
static int hf_li_ps_pdu_iPIRIPacketReport;        /* IPIRIPacketReport */
static int hf_li_ps_pdu_iRI_Parameters;           /* UmtsHI2Operations_IRI_Parameters */
static int hf_li_ps_pdu_umtsIRIsContent;          /* UmtsIRIsContent */
static int hf_li_ps_pdu_iRI_CS_Parameters;        /* UmtsCS_HI2Operations_IRI_Parameters */
static int hf_li_ps_pdu_umtsCS_IRIsContent;       /* UmtsCS_IRIsContent */
static int hf_li_ps_pdu_iRI_Parameters_01;        /* IRI_Parameters */
static int hf_li_ps_pdu_iRIsContent;              /* IRIsContent */
static int hf_li_ps_pdu_iRI_EPS_Parameters;       /* EpsHI2Operations_IRI_Parameters */
static int hf_li_ps_pdu_epsIRIsContent;           /* EpsIRIsContent */
static int hf_li_ps_pdu_iRI_Conf_Parameters;      /* CONFHI2Operations_IRI_Parameters */
static int hf_li_ps_pdu_confIRIsContent;          /* ConfIRIsContent */
static int hf_li_ps_pdu_iRI_ProSe_Parameters;     /* ProSeHI2Operations_IRI_Parameters */
static int hf_li_ps_pdu_proseIRIsContent;         /* ProSeIRIsContent */
static int hf_li_ps_pdu_iRI_Gcse_Parameters;      /* GCSEHI2Operations_IRI_Parameters */
static int hf_li_ps_pdu_gcseIRIsContent;          /* GcseIRIsContent */
static int hf_li_ps_pdu_integrityCheck;           /* IntegrityCheck */
static int hf_li_ps_pdu_testPDU;                  /* NULL */
static int hf_li_ps_pdu_paddingPDU;               /* OCTET_STRING */
static int hf_li_ps_pdu_keep_alive;               /* NULL */
static int hf_li_ps_pdu_keep_aliveResponse;       /* NULL */
static int hf_li_ps_pdu_firstSegmentFlag;         /* NULL */
static int hf_li_ps_pdu_lastSegmentFlag;          /* NULL */
static int hf_li_ps_pdu_cINReset;                 /* NULL */
static int hf_li_ps_pdu_operatorLeaMessage;       /* OperatorLeaMessage */
static int hf_li_ps_pdu_optionRequest;            /* OptionRequest */
static int hf_li_ps_pdu_optionResponse;           /* OptionResponse */
static int hf_li_ps_pdu_optionComplete;           /* NULL */
static int hf_li_ps_pdu_pDUAcknowledgementRequest;  /* NULL */
static int hf_li_ps_pdu_pDUAcknowledgementResponse;  /* NULL */
static int hf_li_ps_pdu_includedSequenceNumbers;  /* T_includedSequenceNumbers */
static int hf_li_ps_pdu_includedSequenceNumbers_item;  /* INTEGER_0_4294967295 */
static int hf_li_ps_pdu_checkType;                /* CheckType */
static int hf_li_ps_pdu_dataType;                 /* DataType */
static int hf_li_ps_pdu_checkValue;               /* OCTET_STRING */
static int hf_li_ps_pdu_hashAlgorithm;            /* HashAlgorithm */
static int hf_li_ps_pdu_signatureAlgorithm;       /* SignatureAlgorithm */
static int hf_li_ps_pdu_pDUAcknowledgement;       /* NULL */
static int hf_li_ps_pdu_requestedOptions;         /* SEQUENCE_OF_Option */
static int hf_li_ps_pdu_requestedOptions_item;    /* Option */
static int hf_li_ps_pdu_acceptedOptions;          /* SEQUENCE_OF_Option */
static int hf_li_ps_pdu_acceptedOptions_item;     /* Option */
static int hf_li_ps_pdu_declinedOptions;          /* SEQUENCE_OF_Option */
static int hf_li_ps_pdu_declinedOptions_item;     /* Option */
static int hf_li_ps_pdu_messagePriority;          /* OperatorLeaMessagePriority */
static int hf_li_ps_pdu_message;                  /* OCTET_STRING_SIZE_1_255 */
static int hf_li_ps_pdu_encryptionType;           /* EncryptionType */
static int hf_li_ps_pdu_encryptedPayload;         /* OCTET_STRING */
static int hf_li_ps_pdu_encryptedPayloadType;     /* EncryptedPayloadType */
static int hf_li_ps_pdu_liActivated;              /* HI4LINotification */
static int hf_li_ps_pdu_liDeactivated;            /* HI4LINotification */
static int hf_li_ps_pdu_liModified;               /* HI4LINotification */
static int hf_li_ps_pdu_activationTime;           /* GeneralizedTime */
static int hf_li_ps_pdu_deactivationTime;         /* GeneralizedTime */
static int hf_li_ps_pdu_targetIdentifiers;        /* SEQUENCE_OF_TargetIdentifier */
static int hf_li_ps_pdu_targetIdentifiers_item;   /* TargetIdentifier */
static int hf_li_ps_pdu_serviceType;              /* DictionaryEntry */
static int hf_li_ps_pdu_targetIdentifierSubtype;  /* DictionaryEntry */
static int hf_li_ps_pdu_interceptType;            /* InterceptType */
static int hf_li_ps_pdu_ownerIdentifier;          /* ShortString */
static int hf_li_ps_pdu_authorizationReference;   /* LongString */
static int hf_li_ps_pdu_targetIdentifierFormat;   /* TargetIdentifierFormat */
static int hf_li_ps_pdu_formatOwner;              /* ShortString */
static int hf_li_ps_pdu_formatName;               /* ShortString */
static int hf_li_ps_pdu_targetValue;              /* LongString */
static int hf_li_ps_pdu_owner;                    /* ShortString */
static int hf_li_ps_pdu_name;                     /* ShortString */
static int hf_li_ps_pdu_value;                    /* ShortString */
static int hf_li_ps_pdu_umtsHI2Location;          /* UmtsHI2Operations_Location */
static int hf_li_ps_pdu_epsLocation;              /* EPSLocation */
static int hf_li_ps_pdu_wlanLocationAttributes;   /* WlanLocationAttributes */
static int hf_li_ps_pdu_eTSI671HI2Location;       /* HI2Operations_Location */
static int hf_li_ps_pdu_threeGPP33128UserLocation;  /* UserLocation */
static int hf_li_ps_pdu_cPEProvidedLocationAttributes;  /* CPEProvidedLocationAttributes */
static int hf_li_ps_pdu_wlanAPMACAddress;         /* OCTET_STRING_SIZE_6 */
static int hf_li_ps_pdu_wGS84CoordinateDecimal;   /* WGS84CoordinateDecimal */
static int hf_li_ps_pdu_gNSSLocation;             /* GNSSLocation */
static int hf_li_ps_pdu_iP_type;                  /* T_iP_type */
static int hf_li_ps_pdu_iP_value;                 /* IP_value */
static int hf_li_ps_pdu_iP_assignment;            /* T_iP_assignment */
static int hf_li_ps_pdu_iPv6PrefixLength;         /* INTEGER_1_128 */
static int hf_li_ps_pdu_iPv4SubnetMask;           /* OCTET_STRING_SIZE_4 */
static int hf_li_ps_pdu_iP_NAT_translated;        /* BOOLEAN */
static int hf_li_ps_pdu_iPBinaryAddress;          /* OCTET_STRING_SIZE_4_16 */
static int hf_li_ps_pdu_iPTextAddress;            /* IA5String_SIZE_7_45 */
static int hf_li_ps_pdu_iPCCObjId;                /* RELATIVE_OID */
static int hf_li_ps_pdu_iPCCContents;             /* IPCCContents */
static int hf_li_ps_pdu_iPPackets;                /* T_iPPackets */
static int hf_li_ps_pdu_iPTruncatedPacket;        /* IPTruncatedPacket */
static int hf_li_ps_pdu_truncatedPacket;          /* OCTET_STRING */
static int hf_li_ps_pdu_originalLength;           /* INTEGER */
static int hf_li_ps_pdu_iPIRIObjId;               /* RELATIVE_OID */
static int hf_li_ps_pdu_iPIRIContents;            /* IPIRIContents */
static int hf_li_ps_pdu_accessEventType;          /* AccessEventType */
static int hf_li_ps_pdu_targetUsername;           /* OCTET_STRING */
static int hf_li_ps_pdu_internetAccessType;       /* InternetAccessType */
static int hf_li_ps_pdu_iPVersion;                /* IPVersion */
static int hf_li_ps_pdu_targetIPAddress;          /* IPAddress */
static int hf_li_ps_pdu_targetNetworkID;          /* UTF8String_SIZE_1_20 */
static int hf_li_ps_pdu_targetCPEID;              /* UTF8String_SIZE_1_128 */
static int hf_li_ps_pdu_targetLocation;           /* UTF8String_SIZE_1_64 */
static int hf_li_ps_pdu_pOPPortNumber;            /* INTEGER_0_4294967295 */
static int hf_li_ps_pdu_callBackNumber;           /* UTF8String_SIZE_1_20 */
static int hf_li_ps_pdu_startTime;                /* GeneralizedTime */
static int hf_li_ps_pdu_endTime;                  /* GeneralizedTime */
static int hf_li_ps_pdu_endReason;                /* EndReason */
static int hf_li_ps_pdu_octetsReceived;           /* INTEGER_0_18446744073709551615 */
static int hf_li_ps_pdu_octetsTransmitted;        /* INTEGER_0_18446744073709551615 */
static int hf_li_ps_pdu_rawAAAData;               /* OCTET_STRING */
static int hf_li_ps_pdu_expectedEndTime;          /* GeneralizedTime */
static int hf_li_ps_pdu_pOPPhoneNumber;           /* UTF8String_SIZE_1_20 */
static int hf_li_ps_pdu_pOPIdentifier;            /* IPIRIIDType */
static int hf_li_ps_pdu_pOPIPAddress;             /* IPAddress */
static int hf_li_ps_pdu_nationalIPIRIParameters;  /* NationalIPIRIParameters */
static int hf_li_ps_pdu_additionalIPAddress;      /* IPAddress */
static int hf_li_ps_pdu_authenticationType;       /* AuthenticationType */
static int hf_li_ps_pdu_otherTargetIdentifiers;   /* SEQUENCE_OF_OtherTargetIdentifiers */
static int hf_li_ps_pdu_otherTargetIdentifiers_item;  /* OtherTargetIdentifiers */
static int hf_li_ps_pdu_location;                 /* Location */
static int hf_li_ps_pdu_pOPPortID;                /* OCTET_STRING */
static int hf_li_ps_pdu_framedRoutes;             /* SEQUENCE_OF_FramedRoute */
static int hf_li_ps_pdu_framedRoutes_item;        /* FramedRoute */
static int hf_li_ps_pdu_printableIDType;          /* UTF8String_SIZE_1_128 */
static int hf_li_ps_pdu_macAddressType;           /* OCTET_STRING_SIZE_6 */
static int hf_li_ps_pdu_ipAddressType;            /* IPAddress */
static int hf_li_ps_pdu_countryCode;              /* PrintableString_SIZE_2 */
static int hf_li_ps_pdu_iPAddress;                /* IPAddress */
static int hf_li_ps_pdu_framedRoute;              /* OCTET_STRING */
static int hf_li_ps_pdu_iPIRIOnlyObjId;           /* RELATIVE_OID */
static int hf_li_ps_pdu_iPInformation;            /* IPInformation */
static int hf_li_ps_pdu_protocolInformation;      /* ProtocolInformation */
static int hf_li_ps_pdu_iPAggregatedNbrOfPackets;  /* INTEGER */
static int hf_li_ps_pdu_iPAggregatedNbrOfBytes;   /* INTEGER */
static int hf_li_ps_pdu_pDSRInformation;          /* PDSRInformation */
static int hf_li_ps_pdu_iPv4Information;          /* IPv4Information */
static int hf_li_ps_pdu_iPv6Information;          /* IPv6Information */
static int hf_li_ps_pdu_none;                     /* NULL */
static int hf_li_ps_pdu_tCPInformation;           /* TCPInformation */
static int hf_li_ps_pdu_uDPInformation;           /* UDPInformation */
static int hf_li_ps_pdu_headerLength;             /* OCTET_STRING */
static int hf_li_ps_pdu_typeOfService;            /* OCTET_STRING */
static int hf_li_ps_pdu_totalLength;              /* OCTET_STRING_SIZE_2 */
static int hf_li_ps_pdu_identification;           /* OCTET_STRING_SIZE_2 */
static int hf_li_ps_pdu_fragment;                 /* OCTET_STRING_SIZE_2 */
static int hf_li_ps_pdu_ttl;                      /* OCTET_STRING */
static int hf_li_ps_pdu_protocol;                 /* OCTET_STRING */
static int hf_li_ps_pdu_headerChecksum;           /* OCTET_STRING_SIZE_2 */
static int hf_li_ps_pdu_source;                   /* OCTET_STRING_SIZE_4 */
static int hf_li_ps_pdu_destination;              /* OCTET_STRING_SIZE_4 */
static int hf_li_ps_pdu_options;                  /* OCTET_STRING_SIZE_0_40 */
static int hf_li_ps_pdu_trafficClass;             /* OCTET_STRING */
static int hf_li_ps_pdu_flowLabel;                /* OCTET_STRING_SIZE_20 */
static int hf_li_ps_pdu_payloadLength;            /* OCTET_STRING_SIZE_4 */
static int hf_li_ps_pdu_nextHeader;               /* OCTET_STRING */
static int hf_li_ps_pdu_hopLimit;                 /* OCTET_STRING */
static int hf_li_ps_pdu_source_01;                /* OCTET_STRING_SIZE_16 */
static int hf_li_ps_pdu_destination_01;           /* OCTET_STRING_SIZE_16 */
static int hf_li_ps_pdu_sourcePort;               /* OCTET_STRING_SIZE_2 */
static int hf_li_ps_pdu_destinationPort;          /* OCTET_STRING_SIZE_2 */
static int hf_li_ps_pdu_tcpinformation_sequenceNumber;  /* OCTET_STRING_SIZE_4 */
static int hf_li_ps_pdu_ackNumber;                /* OCTET_STRING_SIZE_4 */
static int hf_li_ps_pdu_dataOffset;               /* BIT_STRING_SIZE_4 */
static int hf_li_ps_pdu_controlBits;              /* BIT_STRING_SIZE_6 */
static int hf_li_ps_pdu_windowSize;               /* OCTET_STRING_SIZE_2 */
static int hf_li_ps_pdu_checkSum;                 /* OCTET_STRING_SIZE_2 */
static int hf_li_ps_pdu_urgentPointer;            /* OCTET_STRING_SIZE_2 */
static int hf_li_ps_pdu_length;                   /* OCTET_STRING_SIZE_2 */
static int hf_li_ps_pdu_summaryTrigger;           /* PDSRSummaryTriggerIPaccess */
static int hf_li_ps_pdu_firstPacketTimestamp;     /* GeneralizedTime */
static int hf_li_ps_pdu_lastPacketTimestamp;      /* GeneralizedTime */
static int hf_li_ps_pdu_packetCount;              /* INTEGER */
static int hf_li_ps_pdu_byteCount;                /* INTEGER */
static int hf_li_ps_pdu_iPIRIPacketReportObjId;   /* RELATIVE_OID */
static int hf_li_ps_pdu_report;                   /* PacketReport */
static int hf_li_ps_pdu_header;                   /* PacketReportHeader */
static int hf_li_ps_pdu_summary;                  /* PacketReportSummary */
static int hf_li_ps_pdu_header_01;                /* OCTET_STRING */
static int hf_li_ps_pdu_indications;              /* PacketReportIndications */
static int hf_li_ps_pdu_trigger;                  /* PacketReportTrigger */
static int hf_li_ps_pdu_firstTimestamp;           /* GeneralizedTime */
static int hf_li_ps_pdu_lastTimestamp;            /* GeneralizedTime */
static int hf_li_ps_pdu_latitude;                 /* WGS84LatitudeDecimal */
static int hf_li_ps_pdu_longitude;                /* WGS84LongitudeDecimal */
static int hf_li_ps_pdu_latitude_01;              /* WGS84LatitudeAngular */
static int hf_li_ps_pdu_longitude_01;             /* WGS84LongitudeAngular */
static int hf_li_ps_pdu_altitudeAboveGroundLevel;  /* AltitudeMeters */
static int hf_li_ps_pdu_altitudeAboveMeanSeaLevel;  /* AltitudeMeters */
static int hf_li_ps_pdu_location_01;              /* GeoShape */
static int hf_li_ps_pdu_fixMode;                  /* FixMode */
static int hf_li_ps_pdu_location_02;              /* WGS84Coordinate */
static int hf_li_ps_pdu_altitude;                 /* Altitude */
static int hf_li_ps_pdu_decimal;                  /* WGS84CoordinateDecimal */
static int hf_li_ps_pdu_angular;                  /* WGS84CoordinateAngular */
static int hf_li_ps_pdu_shape;                    /* GMLShape */
static int hf_li_ps_pdu_confidence;               /* Percentage */
static int hf_li_ps_pdu_point;                    /* GeoPoint */
static int hf_li_ps_pdu_sphere;                   /* GeoSphere */
static int hf_li_ps_pdu_xyEllipsoid;              /* XYEllipsoid */
static int hf_li_ps_pdu_wGS84Point;               /* WGS84Location */
static int hf_li_ps_pdu_centerPoint;              /* GeoPoint */
static int hf_li_ps_pdu_radiusMeters;             /* UncertaintyMeters */
static int hf_li_ps_pdu_uncertaintyLongitude;     /* UncertaintyMeters */
static int hf_li_ps_pdu_uncertaintyLatitude;      /* UncertaintyMeters */
static int hf_li_ps_pdu_uncertaintyAltitude;      /* UncertaintyMeters */
/* named bits */
static int hf_li_ps_pdu_PacketReportIndications_zeroedIPv4TotalLength;
static int hf_li_ps_pdu_PacketReportIndications_zeroedIPv4Flags;
static int hf_li_ps_pdu_PacketReportIndications_zeroedIPv4TimeToLive;
static int hf_li_ps_pdu_PacketReportIndications_zeroedIPv4HeaderChecksum;
static int hf_li_ps_pdu_PacketReportIndications_zeroedIPv6PayloadLength;
static int hf_li_ps_pdu_PacketReportIndications_removedIPv6ExtensionHeaders;
static int hf_li_ps_pdu_PacketReportIndications_zeroedTCPSequenceNumber;
static int hf_li_ps_pdu_PacketReportIndications_zeroedTCPAcknowledgementNumber;
static int hf_li_ps_pdu_PacketReportIndications_zeroedTCPFlags;
static int hf_li_ps_pdu_PacketReportIndications_zeroedTCPWindowSize;
static int hf_li_ps_pdu_PacketReportIndications_zeroedTCPChecksum;
static int hf_li_ps_pdu_PacketReportIndications_zeroedUDPLength;
static int hf_li_ps_pdu_PacketReportIndications_zeroedUDPChecksum;
static int hf_li_ps_pdu_IRIPayload_element;
static int hf_li_ps_pdu_CCPayload_element;
static int hf_li_ps_pdu_not_decoded;

static int ett_li_ps_pdu;
static int ett_li_ps_pdu_contents;
static int ett_li_ps_pdu_PS_PDU;
static int ett_li_ps_pdu_PSHeader;
static int ett_li_ps_pdu_Payload;
static int ett_li_ps_pdu_SEQUENCE_OF_IRIPayload;
static int ett_li_ps_pdu_SEQUENCE_OF_CCPayload;
static int ett_li_ps_pdu_SEQUENCE_OF_ILHIPayload;
static int ett_li_ps_pdu_SEQUENCE_OF_HI4Payload;
static int ett_li_ps_pdu_HI4Payload;
static int ett_li_ps_pdu_CommunicationIdentifier;
static int ett_li_ps_pdu_NetworkIdentifier;
static int ett_li_ps_pdu_CCPayload;
static int ett_li_ps_pdu_CCContents;
static int ett_li_ps_pdu_MicroSecondTimeStamp;
static int ett_li_ps_pdu_IRIPayload;
static int ett_li_ps_pdu_IRIContents;
static int ett_li_ps_pdu_UMTSIRI;
static int ett_li_ps_pdu_ETSI671IRI;
static int ett_li_ps_pdu_EPSIRI;
static int ett_li_ps_pdu_ConfIRI;
static int ett_li_ps_pdu_ProSeIRI;
static int ett_li_ps_pdu_GcseIRI;
static int ett_li_ps_pdu_TRIPayload;
static int ett_li_ps_pdu_IntegrityCheck;
static int ett_li_ps_pdu_T_includedSequenceNumbers;
static int ett_li_ps_pdu_Option;
static int ett_li_ps_pdu_OptionRequest;
static int ett_li_ps_pdu_SEQUENCE_OF_Option;
static int ett_li_ps_pdu_OptionResponse;
static int ett_li_ps_pdu_OperatorLeaMessage;
static int ett_li_ps_pdu_EncryptionContainer;
static int ett_li_ps_pdu_HI4Notification;
static int ett_li_ps_pdu_HI4LINotification;
static int ett_li_ps_pdu_SEQUENCE_OF_TargetIdentifier;
static int ett_li_ps_pdu_TargetIdentifier;
static int ett_li_ps_pdu_TargetIdentifierFormat;
static int ett_li_ps_pdu_DictionaryEntry;
static int ett_li_ps_pdu_Location;
static int ett_li_ps_pdu_WlanLocationAttributes;
static int ett_li_ps_pdu_CPEProvidedLocationAttributes;
static int ett_li_ps_pdu_IPAddress;
static int ett_li_ps_pdu_IP_value;
static int ett_li_ps_pdu_IPCC;
static int ett_li_ps_pdu_IPCCContents;
static int ett_li_ps_pdu_IPTruncatedPacket;
static int ett_li_ps_pdu_IPIRI;
static int ett_li_ps_pdu_IPIRIContents;
static int ett_li_ps_pdu_SEQUENCE_OF_OtherTargetIdentifiers;
static int ett_li_ps_pdu_SEQUENCE_OF_FramedRoute;
static int ett_li_ps_pdu_IPIRIIDType;
static int ett_li_ps_pdu_NationalIPIRIParameters;
static int ett_li_ps_pdu_OtherTargetIdentifiers;
static int ett_li_ps_pdu_FramedRoute;
static int ett_li_ps_pdu_IPIRIOnly;
static int ett_li_ps_pdu_IPInformation;
static int ett_li_ps_pdu_ProtocolInformation;
static int ett_li_ps_pdu_IPv4Information;
static int ett_li_ps_pdu_IPv6Information;
static int ett_li_ps_pdu_TCPInformation;
static int ett_li_ps_pdu_UDPInformation;
static int ett_li_ps_pdu_PDSRInformation;
static int ett_li_ps_pdu_IPIRIPacketReport;
static int ett_li_ps_pdu_PacketReport;
static int ett_li_ps_pdu_PacketReportHeader;
static int ett_li_ps_pdu_PacketReportSummary;
static int ett_li_ps_pdu_PacketReportIndications;
static int ett_li_ps_pdu_WGS84CoordinateDecimal;
static int ett_li_ps_pdu_WGS84CoordinateAngular;
static int ett_li_ps_pdu_Altitude;
static int ett_li_ps_pdu_GNSSLocation;
static int ett_li_ps_pdu_WGS84Location;
static int ett_li_ps_pdu_WGS84Coordinate;
static int ett_li_ps_pdu_GeoShape;
static int ett_li_ps_pdu_GMLShape;
static int ett_li_ps_pdu_GeoPoint;
static int ett_li_ps_pdu_GeoSphere;
static int ett_li_ps_pdu_XYEllipsoid;

static expert_field ei_li_ps_pdu_not_decoded;

/* A type of a module that Wireshark does not have (see the .MODULE of
 * li-ps-pdu.cnf): its element is shown as bytes. ber.c gives the element
 * in a tvb of its own: its contents, or the whole element without a tag of
 * its own. */
static unsigned
dissect_li_ps_pdu_not_decoded(bool implicit_tag _U_, tvbuff_t *tvb, unsigned offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index)
{
  unsigned len = tvb_reported_length_remaining(tvb, offset);
  proto_item *ti;

  if (hf_index > 0 && proto_registrar_get_ftype(hf_index) == FT_NONE) {
    ti = proto_tree_add_item(tree, hf_index, tvb, offset, len, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_li_ps_pdu_contents);
  }
  ti = proto_tree_add_item(tree, hf_li_ps_pdu_not_decoded, tvb, offset, len, ENC_NA);
  expert_add_info(actx->pinfo, ti, &ei_li_ps_pdu_not_decoded);

  return offset + len;
}

#define dissect_li_ps_pdu_not_decoded_CC_PDU dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_CSvoice_CC_PDU dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_CTTRAFFIC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_Conf_CC_PDU dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_ConfIRIsContent dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_CorrelationValues dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_EmailCC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_EmailIRI dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_Gcse_CC_PDU dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_GcseIRIsContent dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_HI1_Operation dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_ILHIPayload dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_IPMMCC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_IPMMIRI dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_IRI_Parameters dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_IRIsContent dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_L2CC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_L2IRI dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_L2IRIOnly dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_Location dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_MessagingCC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_MessagingIRI dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_MessagingMMCC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_Network_Element_Identifier dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_ProSeIRIsContent dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_PstnIsdnCC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_PstnIsdnIRI dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_TARGETACTIVITYMONITOR dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_TARGETACTIVITYMONITOR_1 dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_TTRAFFIC dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_ThreeGPP_HI1_Operation dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_UmtsCS_IRIsContent dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_UmtsIRIsContent dissect_li_ps_pdu_not_decoded
#define dissect_li_ps_pdu_not_decoded_Voip_CC_PDU dissect_li_ps_pdu_not_decoded



static unsigned
dissect_li_ps_pdu_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_LIID(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   1, 25, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_LawfulInterceptionIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_li_ps_pdu_LIID(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static unsigned
dissect_li_ps_pdu_PrintableString_SIZE_2(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        2, 2, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_OCTET_STRING_SIZE_1_16(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   1, 16, hf_index, NULL);

  return offset;
}


static const ber_sequence_t NetworkIdentifier_sequence[] = {
  { &hf_li_ps_pdu_operatorIdentifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_1_16 },
  { &hf_li_ps_pdu_networkElementIdentifier, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_1_16 },
  { &hf_li_ps_pdu_eTSI671NEID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_Network_Element_Identifier },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_NetworkIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NetworkIdentifier_sequence, hf_index, ett_li_ps_pdu_NetworkIdentifier);

  return offset;
}



static unsigned
dissect_li_ps_pdu_INTEGER_0_4294967295(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, 4294967295U, hf_index, NULL);

  return offset;
}


static const ber_sequence_t CommunicationIdentifier_sequence[] = {
  { &hf_li_ps_pdu_networkIdentifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_NetworkIdentifier },
  { &hf_li_ps_pdu_communicationIdentityNumber, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER_0_4294967295 },
  { &hf_li_ps_pdu_deliveryCountryCode, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PrintableString_SIZE_2 },
  { &hf_li_ps_pdu_cINExtension, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_CorrelationValues },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_CommunicationIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CommunicationIdentifier_sequence, hf_index, ett_li_ps_pdu_CommunicationIdentifier);

  return offset;
}



static unsigned
dissect_li_ps_pdu_GeneralizedTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static unsigned
dissect_li_ps_pdu_PrintableString_SIZE_1_8(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                                        actx, tree, tvb, offset,
                                                        1, 8, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_INTEGER_0_18446744073709551615(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer64(implicit_tag, actx, tree, tvb, offset,
                                                            0U, UINT64_C(18446744073709551615), hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_INTEGER_0_999999(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, 999999U, hf_index, NULL);

  return offset;
}


static const ber_sequence_t MicroSecondTimeStamp_sequence[] = {
  { &hf_li_ps_pdu_seconds   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER_0_18446744073709551615 },
  { &hf_li_ps_pdu_microSeconds, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER_0_999999 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_MicroSecondTimeStamp(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MicroSecondTimeStamp_sequence, hf_index, ett_li_ps_pdu_MicroSecondTimeStamp);

  return offset;
}


static const value_string li_ps_pdu_TimeStampQualifier_vals[] = {
  {   0, "unknown" },
  {   1, "timeOfInterception" },
  {   2, "timeOfMediation" },
  {   3, "timeOfAggregation" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_TimeStampQualifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_OCTET_STRING_SIZE_1_65535(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   1, 65535, hf_index, NULL);

  return offset;
}


static const ber_sequence_t PSHeader_sequence[] = {
  { &hf_li_ps_pdu_li_psDomainId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OBJECT_IDENTIFIER },
  { &hf_li_ps_pdu_lawfulInterceptionIdentifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_LawfulInterceptionIdentifier },
  { &hf_li_ps_pdu_authorizationCountryCode, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PrintableString_SIZE_2 },
  { &hf_li_ps_pdu_communicationIdentifier, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_CommunicationIdentifier },
  { &hf_li_ps_pdu_sequenceNumber, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER_0_4294967295 },
  { &hf_li_ps_pdu_timeStamp , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeneralizedTime },
  { &hf_li_ps_pdu_interceptionPointID, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PrintableString_SIZE_1_8 },
  { &hf_li_ps_pdu_microSecondTimeStamp, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_MicroSecondTimeStamp },
  { &hf_li_ps_pdu_timeStampQualifier, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_TimeStampQualifier },
  { &hf_li_ps_pdu_extendedInterceptionPointID, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_1_65535 },
  { &hf_li_ps_pdu_networkFunctionIdentifier, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_1_65535 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_PSHeader(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PSHeader_sequence, hf_index, ett_li_ps_pdu_PSHeader);

  return offset;
}


static const value_string li_ps_pdu_IRIType_vals[] = {
  {   1, "iRI-Begin" },
  {   2, "iRI-End" },
  {   3, "iRI-Continue" },
  {   4, "iRI-Report" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_IRIType(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_RELATIVE_OID(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_relative_oid(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string li_ps_pdu_AccessEventType_vals[] = {
  {   0, "accessAttempt" },
  {   1, "accessAccept" },
  {   2, "accessReject" },
  {   3, "accessFailed" },
  {   4, "sessionStart" },
  {   5, "sessionEnd" },
  {   6, "interimUpdate" },
  {   7, "startOfInterceptionWithSessionActive" },
  {   8, "accessEnd" },
  {   9, "endOfInterceptionWithSessionActive" },
  {  10, "unknown" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_AccessEventType(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string li_ps_pdu_InternetAccessType_vals[] = {
  {   0, "undefined" },
  {   1, "dialUp" },
  {   2, "xDSL" },
  {   3, "cableModem" },
  {   4, "lAN" },
  {   5, "wirelessLAN" },
  {   6, "fTTx" },
  {   7, "wIMAX-HIPERMAN" },
  {   8, "satellite" },
  {   9, "wireless-other" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_InternetAccessType(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string li_ps_pdu_IPVersion_vals[] = {
  {   1, "iPV4" },
  {   2, "iPV6" },
  {   3, "iPV4andV6" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_IPVersion(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string li_ps_pdu_T_iP_type_vals[] = {
  {   0, "iPV4" },
  {   1, "iPV6" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_T_iP_type(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_OCTET_STRING_SIZE_4_16(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   4, 16, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_IA5String_SIZE_7_45(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                                        actx, tree, tvb, offset,
                                                        7, 45, hf_index, NULL);

  return offset;
}


static const value_string li_ps_pdu_IP_value_vals[] = {
  {   1, "iPBinaryAddress" },
  {   2, "iPTextAddress" },
  { 0, NULL }
};

static const ber_choice_t IP_value_choice[] = {
  {   1, &hf_li_ps_pdu_iPBinaryAddress, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_4_16 },
  {   2, &hf_li_ps_pdu_iPTextAddress, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IA5String_SIZE_7_45 },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IP_value(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IP_value_choice, hf_index, ett_li_ps_pdu_IP_value,
                                 NULL);

  return offset;
}


static const value_string li_ps_pdu_T_iP_assignment_vals[] = {
  {   1, "static" },
  {   2, "dynamic" },
  {   3, "notKnown" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_T_iP_assignment(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_INTEGER_1_128(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            1U, 128U, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_OCTET_STRING_SIZE_4(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   4, 4, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t IPAddress_sequence[] = {
  { &hf_li_ps_pdu_iP_type   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_T_iP_type },
  { &hf_li_ps_pdu_iP_value  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_IP_value },
  { &hf_li_ps_pdu_iP_assignment, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_T_iP_assignment },
  { &hf_li_ps_pdu_iPv6PrefixLength, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER_1_128 },
  { &hf_li_ps_pdu_iPv4SubnetMask, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_4 },
  { &hf_li_ps_pdu_iP_NAT_translated, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IPAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPAddress_sequence, hf_index, ett_li_ps_pdu_IPAddress);

  return offset;
}



static unsigned
dissect_li_ps_pdu_UTF8String_SIZE_1_20(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                                        actx, tree, tvb, offset,
                                                        1, 20, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_UTF8String_SIZE_1_128(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                                        actx, tree, tvb, offset,
                                                        1, 128, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_UTF8String_SIZE_1_64(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                                        actx, tree, tvb, offset,
                                                        1, 64, hf_index, NULL);

  return offset;
}


static const value_string li_ps_pdu_EndReason_vals[] = {
  {   0, "undefined" },
  {   1, "regularLogoff" },
  {   2, "connectionLoss" },
  {   3, "connectionTimeout" },
  {   4, "leaseExpired" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_EndReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_OCTET_STRING_SIZE_6(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   6, 6, hf_index, NULL);

  return offset;
}


static const value_string li_ps_pdu_IPIRIIDType_vals[] = {
  {   0, "printableIDType" },
  {   1, "macAddressType" },
  {   2, "ipAddressType" },
  { 0, NULL }
};

static const ber_choice_t IPIRIIDType_choice[] = {
  {   0, &hf_li_ps_pdu_printableIDType, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_UTF8String_SIZE_1_128 },
  {   1, &hf_li_ps_pdu_macAddressType, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_6 },
  {   2, &hf_li_ps_pdu_ipAddressType, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IPIRIIDType(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IPIRIIDType_choice, hf_index, ett_li_ps_pdu_IPIRIIDType,
                                 NULL);

  return offset;
}


static const ber_sequence_t NationalIPIRIParameters_sequence[] = {
  { &hf_li_ps_pdu_countryCode, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PrintableString_SIZE_2 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_NationalIPIRIParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NationalIPIRIParameters_sequence, hf_index, ett_li_ps_pdu_NationalIPIRIParameters);

  return offset;
}


static const value_string li_ps_pdu_AuthenticationType_vals[] = {
  {   0, "unknown" },
  {   1, "static" },
  {   2, "radiusAAA" },
  {   3, "dhcpAAA" },
  {   4, "diameterAAA" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_AuthenticationType(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string li_ps_pdu_OtherTargetIdentifiers_vals[] = {
  {   0, "iPAddress" },
  { 0, NULL }
};

static const ber_choice_t OtherTargetIdentifiers_choice[] = {
  {   0, &hf_li_ps_pdu_iPAddress , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_OtherTargetIdentifiers(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 OtherTargetIdentifiers_choice, hf_index, ett_li_ps_pdu_OtherTargetIdentifiers,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_OtherTargetIdentifiers_sequence_of[1] = {
  { &hf_li_ps_pdu_otherTargetIdentifiers_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_OtherTargetIdentifiers },
};

static unsigned
dissect_li_ps_pdu_SEQUENCE_OF_OtherTargetIdentifiers(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_OtherTargetIdentifiers_sequence_of, hf_index, ett_li_ps_pdu_SEQUENCE_OF_OtherTargetIdentifiers);

  return offset;
}


static const ber_sequence_t WlanLocationAttributes_sequence[] = {
  { &hf_li_ps_pdu_wlanAPMACAddress, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_6 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_WlanLocationAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   WlanLocationAttributes_sequence, hf_index, ett_li_ps_pdu_WlanLocationAttributes);

  return offset;
}



static unsigned
dissect_li_ps_pdu_WGS84LatitudeDecimal(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   10, 10, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_WGS84LongitudeDecimal(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   11, 11, hf_index, NULL);

  return offset;
}


static const ber_sequence_t WGS84CoordinateDecimal_sequence[] = {
  { &hf_li_ps_pdu_latitude  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_WGS84LatitudeDecimal },
  { &hf_li_ps_pdu_longitude , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_WGS84LongitudeDecimal },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_WGS84CoordinateDecimal(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   WGS84CoordinateDecimal_sequence, hf_index, ett_li_ps_pdu_WGS84CoordinateDecimal);

  return offset;
}



static unsigned
dissect_li_ps_pdu_WGS84LatitudeAngular(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   10, 10, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_WGS84LongitudeAngular(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   11, 11, hf_index, NULL);

  return offset;
}


static const ber_sequence_t WGS84CoordinateAngular_sequence[] = {
  { &hf_li_ps_pdu_latitude_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_WGS84LatitudeAngular },
  { &hf_li_ps_pdu_longitude_01, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_WGS84LongitudeAngular },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_WGS84CoordinateAngular(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   WGS84CoordinateAngular_sequence, hf_index, ett_li_ps_pdu_WGS84CoordinateAngular);

  return offset;
}


static const value_string li_ps_pdu_WGS84Coordinate_vals[] = {
  {   0, "decimal" },
  {   1, "angular" },
  { 0, NULL }
};

static const ber_choice_t WGS84Coordinate_choice[] = {
  {   0, &hf_li_ps_pdu_decimal   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_WGS84CoordinateDecimal },
  {   1, &hf_li_ps_pdu_angular   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_WGS84CoordinateAngular },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_WGS84Coordinate(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 WGS84Coordinate_choice, hf_index, ett_li_ps_pdu_WGS84Coordinate,
                                 NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_AltitudeMeters(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            -1000, 50000U, hf_index, NULL);

  return offset;
}


static const value_string li_ps_pdu_Altitude_vals[] = {
  {   0, "altitudeAboveGroundLevel" },
  {   1, "altitudeAboveMeanSeaLevel" },
  { 0, NULL }
};

static const ber_choice_t Altitude_choice[] = {
  {   0, &hf_li_ps_pdu_altitudeAboveGroundLevel, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_AltitudeMeters },
  {   1, &hf_li_ps_pdu_altitudeAboveMeanSeaLevel, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_AltitudeMeters },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_Altitude(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Altitude_choice, hf_index, ett_li_ps_pdu_Altitude,
                                 NULL);

  return offset;
}


static const ber_sequence_t WGS84Location_sequence[] = {
  { &hf_li_ps_pdu_location_02, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_WGS84Coordinate },
  { &hf_li_ps_pdu_altitude  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_Altitude },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_WGS84Location(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   WGS84Location_sequence, hf_index, ett_li_ps_pdu_WGS84Location);

  return offset;
}


static const value_string li_ps_pdu_GeoPoint_vals[] = {
  {   0, "wGS84Point" },
  { 0, NULL }
};

static const ber_choice_t GeoPoint_choice[] = {
  {   0, &hf_li_ps_pdu_wGS84Point, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_WGS84Location },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_GeoPoint(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GeoPoint_choice, hf_index, ett_li_ps_pdu_GeoPoint,
                                 NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_UncertaintyMeters(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer64(implicit_tag, actx, tree, tvb, offset,
                                                            1U, NO_BOUND, hf_index, NULL);

  return offset;
}


static const ber_sequence_t GeoSphere_sequence[] = {
  { &hf_li_ps_pdu_centerPoint, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_GeoPoint },
  { &hf_li_ps_pdu_radiusMeters, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_UncertaintyMeters },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_GeoSphere(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GeoSphere_sequence, hf_index, ett_li_ps_pdu_GeoSphere);

  return offset;
}


static const ber_sequence_t XYEllipsoid_sequence[] = {
  { &hf_li_ps_pdu_centerPoint, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_GeoPoint },
  { &hf_li_ps_pdu_uncertaintyLongitude, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_UncertaintyMeters },
  { &hf_li_ps_pdu_uncertaintyLatitude, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_UncertaintyMeters },
  { &hf_li_ps_pdu_uncertaintyAltitude, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_UncertaintyMeters },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_XYEllipsoid(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   XYEllipsoid_sequence, hf_index, ett_li_ps_pdu_XYEllipsoid);

  return offset;
}


static const value_string li_ps_pdu_GMLShape_vals[] = {
  {   0, "point" },
  {   1, "sphere" },
  {   2, "xyEllipsoid" },
  { 0, NULL }
};

static const ber_choice_t GMLShape_choice[] = {
  {   0, &hf_li_ps_pdu_point     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeoPoint },
  {   1, &hf_li_ps_pdu_sphere    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeoSphere },
  {   2, &hf_li_ps_pdu_xyEllipsoid, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_XYEllipsoid },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_GMLShape(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GMLShape_choice, hf_index, ett_li_ps_pdu_GMLShape,
                                 NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_Percentage(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_integer(implicit_tag, actx, tree, tvb, offset,
                                                            0U, 100U, hf_index, NULL);

  return offset;
}


static const ber_sequence_t GeoShape_sequence[] = {
  { &hf_li_ps_pdu_shape     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_GMLShape },
  { &hf_li_ps_pdu_confidence, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_Percentage },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_GeoShape(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GeoShape_sequence, hf_index, ett_li_ps_pdu_GeoShape);

  return offset;
}


static const value_string li_ps_pdu_FixMode_vals[] = {
  {   0, "unknown" },
  {   1, "noFix" },
  {   2, "fix2D" },
  {   3, "fix3D" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_FixMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t GNSSLocation_sequence[] = {
  { &hf_li_ps_pdu_location_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeoShape },
  { &hf_li_ps_pdu_fixMode   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_FixMode },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_GNSSLocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GNSSLocation_sequence, hf_index, ett_li_ps_pdu_GNSSLocation);

  return offset;
}


static const ber_sequence_t CPEProvidedLocationAttributes_sequence[] = {
  { &hf_li_ps_pdu_wGS84CoordinateDecimal, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_WGS84CoordinateDecimal },
  { &hf_li_ps_pdu_gNSSLocation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GNSSLocation },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_CPEProvidedLocationAttributes(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CPEProvidedLocationAttributes_sequence, hf_index, ett_li_ps_pdu_CPEProvidedLocationAttributes);

  return offset;
}


static const ber_sequence_t Location_sequence[] = {
  { &hf_li_ps_pdu_umtsHI2Location, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_Location },
  { &hf_li_ps_pdu_epsLocation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_HI2Operations_EPSLocation },
  { &hf_li_ps_pdu_wlanLocationAttributes, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_WlanLocationAttributes },
  { &hf_li_ps_pdu_eTSI671HI2Location, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_Location },
  { &hf_li_ps_pdu_threeGPP33128UserLocation, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_lix2_UserLocation },
  { &hf_li_ps_pdu_cPEProvidedLocationAttributes, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_CPEProvidedLocationAttributes },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_Location(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Location_sequence, hf_index, ett_li_ps_pdu_Location);

  return offset;
}


static const value_string li_ps_pdu_FramedRoute_vals[] = {
  {   0, "framedRoute" },
  { 0, NULL }
};

static const ber_choice_t FramedRoute_choice[] = {
  {   0, &hf_li_ps_pdu_framedRoute, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_FramedRoute(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 FramedRoute_choice, hf_index, ett_li_ps_pdu_FramedRoute,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_FramedRoute_sequence_of[1] = {
  { &hf_li_ps_pdu_framedRoutes_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_FramedRoute },
};

static unsigned
dissect_li_ps_pdu_SEQUENCE_OF_FramedRoute(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_FramedRoute_sequence_of, hf_index, ett_li_ps_pdu_SEQUENCE_OF_FramedRoute);

  return offset;
}


static const ber_sequence_t IPIRIContents_sequence[] = {
  { &hf_li_ps_pdu_accessEventType, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_AccessEventType },
  { &hf_li_ps_pdu_targetUsername, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_internetAccessType, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_InternetAccessType },
  { &hf_li_ps_pdu_iPVersion , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPVersion },
  { &hf_li_ps_pdu_targetIPAddress, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPAddress },
  { &hf_li_ps_pdu_targetNetworkID, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_UTF8String_SIZE_1_20 },
  { &hf_li_ps_pdu_targetCPEID, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_UTF8String_SIZE_1_128 },
  { &hf_li_ps_pdu_targetLocation, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_UTF8String_SIZE_1_64 },
  { &hf_li_ps_pdu_pOPPortNumber, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER_0_4294967295 },
  { &hf_li_ps_pdu_callBackNumber, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_UTF8String_SIZE_1_20 },
  { &hf_li_ps_pdu_startTime , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeneralizedTime },
  { &hf_li_ps_pdu_endTime   , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeneralizedTime },
  { &hf_li_ps_pdu_endReason , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_EndReason },
  { &hf_li_ps_pdu_octetsReceived, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER_0_18446744073709551615 },
  { &hf_li_ps_pdu_octetsTransmitted, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER_0_18446744073709551615 },
  { &hf_li_ps_pdu_rawAAAData, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_expectedEndTime, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeneralizedTime },
  { &hf_li_ps_pdu_pOPPhoneNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_UTF8String_SIZE_1_20 },
  { &hf_li_ps_pdu_pOPIdentifier, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_IPIRIIDType },
  { &hf_li_ps_pdu_pOPIPAddress, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPAddress },
  { &hf_li_ps_pdu_nationalIPIRIParameters, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_NationalIPIRIParameters },
  { &hf_li_ps_pdu_additionalIPAddress, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPAddress },
  { &hf_li_ps_pdu_authenticationType, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_AuthenticationType },
  { &hf_li_ps_pdu_otherTargetIdentifiers, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_SEQUENCE_OF_OtherTargetIdentifiers },
  { &hf_li_ps_pdu_location  , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_Location },
  { &hf_li_ps_pdu_pOPPortID , BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_framedRoutes, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_SEQUENCE_OF_FramedRoute },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IPIRIContents(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPIRIContents_sequence, hf_index, ett_li_ps_pdu_IPIRIContents);

  return offset;
}


static const ber_sequence_t IPIRI_sequence[] = {
  { &hf_li_ps_pdu_iPIRIObjId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_RELATIVE_OID },
  { &hf_li_ps_pdu_iPIRIContents, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPIRIContents },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IPIRI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPIRI_sequence, hf_index, ett_li_ps_pdu_IPIRI);

  return offset;
}



static unsigned
dissect_li_ps_pdu_OCTET_STRING_SIZE_2(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   2, 2, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_OCTET_STRING_SIZE_0_40(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   0, 40, hf_index, NULL);

  return offset;
}


static const ber_sequence_t IPv4Information_sequence[] = {
  { &hf_li_ps_pdu_headerLength, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_typeOfService, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_totalLength, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_2 },
  { &hf_li_ps_pdu_identification, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_2 },
  { &hf_li_ps_pdu_fragment  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_2 },
  { &hf_li_ps_pdu_ttl       , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_protocol  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_headerChecksum, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_2 },
  { &hf_li_ps_pdu_source    , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_4 },
  { &hf_li_ps_pdu_destination, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_4 },
  { &hf_li_ps_pdu_options   , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_0_40 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IPv4Information(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPv4Information_sequence, hf_index, ett_li_ps_pdu_IPv4Information);

  return offset;
}



static unsigned
dissect_li_ps_pdu_OCTET_STRING_SIZE_20(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   20, 20, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_OCTET_STRING_SIZE_16(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   16, 16, hf_index, NULL);

  return offset;
}


static const ber_sequence_t IPv6Information_sequence[] = {
  { &hf_li_ps_pdu_trafficClass, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_flowLabel , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_20 },
  { &hf_li_ps_pdu_payloadLength, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_4 },
  { &hf_li_ps_pdu_nextHeader, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_hopLimit  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_source_01 , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_16 },
  { &hf_li_ps_pdu_destination_01, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_16 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IPv6Information(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPv6Information_sequence, hf_index, ett_li_ps_pdu_IPv6Information);

  return offset;
}


static const value_string li_ps_pdu_IPInformation_vals[] = {
  {   0, "iPv4Information" },
  {   1, "iPv6Information" },
  { 0, NULL }
};

static const ber_choice_t IPInformation_choice[] = {
  {   0, &hf_li_ps_pdu_iPv4Information, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPv4Information },
  {   1, &hf_li_ps_pdu_iPv6Information, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPv6Information },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IPInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IPInformation_choice, hf_index, ett_li_ps_pdu_IPInformation,
                                 NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static unsigned
dissect_li_ps_pdu_BIT_STRING_SIZE_4(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_bitstring(implicit_tag, actx, tree, tvb, offset,
                                                4, 4, NULL, 0, hf_index, -1,
                                                NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_BIT_STRING_SIZE_6(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_bitstring(implicit_tag, actx, tree, tvb, offset,
                                                6, 6, NULL, 0, hf_index, -1,
                                                NULL);

  return offset;
}


static const ber_sequence_t TCPInformation_sequence[] = {
  { &hf_li_ps_pdu_sourcePort, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_2 },
  { &hf_li_ps_pdu_destinationPort, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_2 },
  { &hf_li_ps_pdu_tcpinformation_sequenceNumber, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_4 },
  { &hf_li_ps_pdu_ackNumber , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_4 },
  { &hf_li_ps_pdu_dataOffset, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_BIT_STRING_SIZE_4 },
  { &hf_li_ps_pdu_controlBits, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_BIT_STRING_SIZE_6 },
  { &hf_li_ps_pdu_windowSize, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_2 },
  { &hf_li_ps_pdu_checkSum  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_2 },
  { &hf_li_ps_pdu_urgentPointer, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_2 },
  { &hf_li_ps_pdu_options   , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_0_40 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_TCPInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TCPInformation_sequence, hf_index, ett_li_ps_pdu_TCPInformation);

  return offset;
}


static const ber_sequence_t UDPInformation_sequence[] = {
  { &hf_li_ps_pdu_sourcePort, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_2 },
  { &hf_li_ps_pdu_destinationPort, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_2 },
  { &hf_li_ps_pdu_length    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_2 },
  { &hf_li_ps_pdu_checkSum  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_2 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_UDPInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UDPInformation_sequence, hf_index, ett_li_ps_pdu_UDPInformation);

  return offset;
}


static const value_string li_ps_pdu_ProtocolInformation_vals[] = {
  {   0, "none" },
  {   1, "tCPInformation" },
  {   2, "uDPInformation" },
  { 0, NULL }
};

static const ber_choice_t ProtocolInformation_choice[] = {
  {   0, &hf_li_ps_pdu_none      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_NULL },
  {   1, &hf_li_ps_pdu_tCPInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_TCPInformation },
  {   2, &hf_li_ps_pdu_uDPInformation, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_UDPInformation },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_ProtocolInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ProtocolInformation_choice, hf_index, ett_li_ps_pdu_ProtocolInformation,
                                 NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string li_ps_pdu_PDSRSummaryTriggerIPaccess_vals[] = {
  {   0, "startOfFlow" },
  {   1, "timerExpiry" },
  {   2, "packetCount" },
  {   3, "byteCount" },
  {   4, "endOfFlow" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_PDSRSummaryTriggerIPaccess(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PDSRInformation_sequence[] = {
  { &hf_li_ps_pdu_summaryTrigger, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PDSRSummaryTriggerIPaccess },
  { &hf_li_ps_pdu_firstPacketTimestamp, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeneralizedTime },
  { &hf_li_ps_pdu_lastPacketTimestamp, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeneralizedTime },
  { &hf_li_ps_pdu_packetCount, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER },
  { &hf_li_ps_pdu_byteCount , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_PDSRInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PDSRInformation_sequence, hf_index, ett_li_ps_pdu_PDSRInformation);

  return offset;
}


static const ber_sequence_t IPIRIOnly_sequence[] = {
  { &hf_li_ps_pdu_iPIRIOnlyObjId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_RELATIVE_OID },
  { &hf_li_ps_pdu_iPInformation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_IPInformation },
  { &hf_li_ps_pdu_protocolInformation, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_ProtocolInformation },
  { &hf_li_ps_pdu_iPAggregatedNbrOfPackets, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER },
  { &hf_li_ps_pdu_iPAggregatedNbrOfBytes, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER },
  { &hf_li_ps_pdu_pDSRInformation, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PDSRInformation },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IPIRIOnly(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPIRIOnly_sequence, hf_index, ett_li_ps_pdu_IPIRIOnly);

  return offset;
}


static const value_string li_ps_pdu_UMTSIRI_vals[] = {
  {   0, "iRI-Parameters" },
  {   1, "umtsIRIsContent" },
  {   2, "iRI-CS-Parameters" },
  {   3, "umtsCS-IRIsContent" },
  { 0, NULL }
};

static const ber_choice_t UMTSIRI_choice[] = {
  {   0, &hf_li_ps_pdu_iRI_Parameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_IRI_Parameters },
  {   1, &hf_li_ps_pdu_umtsIRIsContent, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_UmtsIRIsContent },
  {   2, &hf_li_ps_pdu_iRI_CS_Parameters, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_IRI_Parameters },
  {   3, &hf_li_ps_pdu_umtsCS_IRIsContent, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_UmtsCS_IRIsContent },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_UMTSIRI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 UMTSIRI_choice, hf_index, ett_li_ps_pdu_UMTSIRI,
                                 NULL);

  return offset;
}


static const value_string li_ps_pdu_ETSI671IRI_vals[] = {
  {   0, "iRI-Parameters" },
  {   1, "iRIsContent" },
  { 0, NULL }
};

static const ber_choice_t ETSI671IRI_choice[] = {
  {   0, &hf_li_ps_pdu_iRI_Parameters_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_IRI_Parameters },
  {   1, &hf_li_ps_pdu_iRIsContent, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_IRIsContent },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_ETSI671IRI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ETSI671IRI_choice, hf_index, ett_li_ps_pdu_ETSI671IRI,
                                 NULL);

  return offset;
}


static const value_string li_ps_pdu_EPSIRI_vals[] = {
  {   0, "iRI-EPS-Parameters" },
  {   1, "epsIRIsContent" },
  { 0, NULL }
};

static const ber_choice_t EPSIRI_choice[] = {
  {   0, &hf_li_ps_pdu_iRI_EPS_Parameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_HI2Operations_IRI_Parameters },
  {   1, &hf_li_ps_pdu_epsIRIsContent, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_HI2Operations_EpsIRIsContent },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_EPSIRI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 EPSIRI_choice, hf_index, ett_li_ps_pdu_EPSIRI,
                                 NULL);

  return offset;
}


static const value_string li_ps_pdu_ConfIRI_vals[] = {
  {   0, "iRI-Conf-Parameters" },
  {   1, "confIRIsContent" },
  { 0, NULL }
};

static const ber_choice_t ConfIRI_choice[] = {
  {   0, &hf_li_ps_pdu_iRI_Conf_Parameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_IRI_Parameters },
  {   1, &hf_li_ps_pdu_confIRIsContent, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_ConfIRIsContent },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_ConfIRI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ConfIRI_choice, hf_index, ett_li_ps_pdu_ConfIRI,
                                 NULL);

  return offset;
}


static const value_string li_ps_pdu_ProSeIRI_vals[] = {
  {   0, "iRI-ProSe-Parameters" },
  {   1, "proseIRIsContent" },
  { 0, NULL }
};

static const ber_choice_t ProSeIRI_choice[] = {
  {   0, &hf_li_ps_pdu_iRI_ProSe_Parameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_IRI_Parameters },
  {   1, &hf_li_ps_pdu_proseIRIsContent, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_ProSeIRIsContent },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_ProSeIRI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ProSeIRI_choice, hf_index, ett_li_ps_pdu_ProSeIRI,
                                 NULL);

  return offset;
}


static const value_string li_ps_pdu_GcseIRI_vals[] = {
  {   0, "iRI-Gcse-Parameters" },
  {   1, "gcseIRIsContent" },
  { 0, NULL }
};

static const ber_choice_t GcseIRI_choice[] = {
  {   0, &hf_li_ps_pdu_iRI_Gcse_Parameters, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_IRI_Parameters },
  {   1, &hf_li_ps_pdu_gcseIRIsContent, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_GcseIRIsContent },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_GcseIRI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GcseIRI_choice, hf_index, ett_li_ps_pdu_GcseIRI,
                                 NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_T_threeGPP33128DefinedIRI(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *iri_tvb = NULL;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &iri_tvb);

  if (iri_tvb) {
    dissect_lix2_IRIPayload(false, iri_tvb, 0, actx,
                            proto_item_add_subtree(actx->created_item, ett_li_ps_pdu_contents),
                            hf_li_ps_pdu_IRIPayload_element);
  }


  return offset;
}


static const ber_sequence_t PacketReportHeader_sequence[] = {
  { &hf_li_ps_pdu_header_01 , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_PacketReportHeader(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PacketReportHeader_sequence, hf_index, ett_li_ps_pdu_PacketReportHeader);

  return offset;
}


static int * const PacketReportIndications_bits[] = {
  &hf_li_ps_pdu_PacketReportIndications_zeroedIPv4TotalLength,
  &hf_li_ps_pdu_PacketReportIndications_zeroedIPv4Flags,
  &hf_li_ps_pdu_PacketReportIndications_zeroedIPv4TimeToLive,
  &hf_li_ps_pdu_PacketReportIndications_zeroedIPv4HeaderChecksum,
  &hf_li_ps_pdu_PacketReportIndications_zeroedIPv6PayloadLength,
  &hf_li_ps_pdu_PacketReportIndications_removedIPv6ExtensionHeaders,
  &hf_li_ps_pdu_PacketReportIndications_zeroedTCPSequenceNumber,
  &hf_li_ps_pdu_PacketReportIndications_zeroedTCPAcknowledgementNumber,
  &hf_li_ps_pdu_PacketReportIndications_zeroedTCPFlags,
  &hf_li_ps_pdu_PacketReportIndications_zeroedTCPWindowSize,
  &hf_li_ps_pdu_PacketReportIndications_zeroedTCPChecksum,
  &hf_li_ps_pdu_PacketReportIndications_zeroedUDPLength,
  &hf_li_ps_pdu_PacketReportIndications_zeroedUDPChecksum,
  NULL
};

static unsigned
dissect_li_ps_pdu_PacketReportIndications(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    PacketReportIndications_bits, 13, hf_index, ett_li_ps_pdu_PacketReportIndications,
                                    NULL);

  return offset;
}


static const value_string li_ps_pdu_PacketReportTrigger_vals[] = {
  {   1, "flowStart" },
  {   2, "flowEnd" },
  {   3, "flowTimeout" },
  {   4, "flowTimerExpiration" },
  {   5, "flowPacketCount" },
  {   6, "flowByteCount" },
  {   7, "sessionTimerExpiration" },
  {   8, "sessionPacketCount" },
  {   9, "sessionByteCount" },
  {  10, "reportEnd" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_PacketReportTrigger(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PacketReportSummary_sequence[] = {
  { &hf_li_ps_pdu_header_01 , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_indications, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PacketReportIndications },
  { &hf_li_ps_pdu_trigger   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PacketReportTrigger },
  { &hf_li_ps_pdu_packetCount, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER },
  { &hf_li_ps_pdu_byteCount , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER },
  { &hf_li_ps_pdu_firstTimestamp, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeneralizedTime },
  { &hf_li_ps_pdu_lastTimestamp, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_PacketReportSummary(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PacketReportSummary_sequence, hf_index, ett_li_ps_pdu_PacketReportSummary);

  return offset;
}


static const value_string li_ps_pdu_PacketReport_vals[] = {
  {   1, "header" },
  {   2, "summary" },
  { 0, NULL }
};

static const ber_choice_t PacketReport_choice[] = {
  {   1, &hf_li_ps_pdu_header    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PacketReportHeader },
  {   2, &hf_li_ps_pdu_summary   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PacketReportSummary },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_PacketReport(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PacketReport_choice, hf_index, ett_li_ps_pdu_PacketReport,
                                 NULL);

  return offset;
}


static const ber_sequence_t IPIRIPacketReport_sequence[] = {
  { &hf_li_ps_pdu_iPIRIPacketReportObjId, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_RELATIVE_OID },
  { &hf_li_ps_pdu_report    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_PacketReport },
  { NULL, 0, 0, 0, NULL }
};

unsigned
dissect_li_ps_pdu_IPIRIPacketReport(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPIRIPacketReport_sequence, hf_index, ett_li_ps_pdu_IPIRIPacketReport);

  return offset;
}


static const value_string li_ps_pdu_IRIContents_vals[] = {
  {   1, "emailIRI" },
  {   2, "iPIRI" },
  {   3, "iPIRIOnly" },
  {   4, "uMTSIRI" },
  {   5, "eTSI671IRI" },
  {   6, "l2IRI" },
  {   7, "l2IRIOnly" },
  {   8, "tARGETACTIVITYMONITOR-1" },
  {   9, "tARGETACTIVITYMONITOR-2" },
  {  10, "pstnIsdnIRI" },
  {  11, "iPMMIRI" },
  {  14, "messagingIRI" },
  {  15, "ePSIRI" },
  {  16, "confIRI" },
  {  17, "proseIRI" },
  {  18, "gcseIRI" },
  {  19, "threeGPP33128DefinedIRI" },
  {  20, "iPIRIPacketReport" },
  { 0, NULL }
};

static const ber_choice_t IRIContents_choice[] = {
  {   1, &hf_li_ps_pdu_emailIRI  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_EmailIRI },
  {   2, &hf_li_ps_pdu_iPIRI     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPIRI },
  {   3, &hf_li_ps_pdu_iPIRIOnly , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPIRIOnly },
  {   4, &hf_li_ps_pdu_uMTSIRI   , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_UMTSIRI },
  {   5, &hf_li_ps_pdu_eTSI671IRI, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_ETSI671IRI },
  {   6, &hf_li_ps_pdu_l2IRI     , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_L2IRI },
  {   7, &hf_li_ps_pdu_l2IRIOnly , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_L2IRIOnly },
  {   8, &hf_li_ps_pdu_tARGETACTIVITYMONITOR_1, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_TARGETACTIVITYMONITOR_1 },
  {   9, &hf_li_ps_pdu_tARGETACTIVITYMONITOR_2, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_TARGETACTIVITYMONITOR },
  {  10, &hf_li_ps_pdu_pstnIsdnIRI, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_PstnIsdnIRI },
  {  11, &hf_li_ps_pdu_iPMMIRI   , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_IPMMIRI },
  {  14, &hf_li_ps_pdu_messagingIRI, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_MessagingIRI },
  {  15, &hf_li_ps_pdu_ePSIRI    , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_EPSIRI },
  {  16, &hf_li_ps_pdu_confIRI   , BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_ConfIRI },
  {  17, &hf_li_ps_pdu_proseIRI  , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_ProSeIRI },
  {  18, &hf_li_ps_pdu_gcseIRI   , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GcseIRI },
  {  19, &hf_li_ps_pdu_threeGPP33128DefinedIRI, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_T_threeGPP33128DefinedIRI },
  {  20, &hf_li_ps_pdu_iPIRIPacketReport, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPIRIPacketReport },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IRIContents(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IRIContents_choice, hf_index, ett_li_ps_pdu_IRIContents,
                                 NULL);

  return offset;
}


static const value_string li_ps_pdu_PayloadDirection_vals[] = {
  {   0, "fromTarget" },
  {   1, "toTarget" },
  {   2, "indeterminate" },
  {   3, "combined" },
  {   4, "notapplicable" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_PayloadDirection(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t IRIPayload_sequence[] = {
  { &hf_li_ps_pdu_iRIType   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IRIType },
  { &hf_li_ps_pdu_timeStamp , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeneralizedTime },
  { &hf_li_ps_pdu_iRIContents, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_IRIContents },
  { &hf_li_ps_pdu_microSecondTimeStamp, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_MicroSecondTimeStamp },
  { &hf_li_ps_pdu_timeStampQualifier, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_TimeStampQualifier },
  { &hf_li_ps_pdu_sessionDirection, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PayloadDirection },
  { &hf_li_ps_pdu_payloadDirection, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PayloadDirection },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IRIPayload(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IRIPayload_sequence, hf_index, ett_li_ps_pdu_IRIPayload);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_IRIPayload_sequence_of[1] = {
  { &hf_li_ps_pdu_iRIPayloadSequence_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_li_ps_pdu_IRIPayload },
};

static unsigned
dissect_li_ps_pdu_SEQUENCE_OF_IRIPayload(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_IRIPayload_sequence_of, hf_index, ett_li_ps_pdu_SEQUENCE_OF_IRIPayload);

  return offset;
}



static unsigned
dissect_li_ps_pdu_T_iPPackets(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *packet_tvb = NULL;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &packet_tvb);

  if (packet_tvb) {
    call_dissector(ip_handle, packet_tvb, actx->pinfo,
                   proto_item_add_subtree(actx->created_item, ett_li_ps_pdu_contents));
  }


  return offset;
}


static const ber_sequence_t IPTruncatedPacket_sequence[] = {
  { &hf_li_ps_pdu_truncatedPacket, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_originalLength, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IPTruncatedPacket(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPTruncatedPacket_sequence, hf_index, ett_li_ps_pdu_IPTruncatedPacket);

  return offset;
}


static const value_string li_ps_pdu_IPCCContents_vals[] = {
  {   0, "iPPackets" },
  {   1, "iPTruncatedPacket" },
  { 0, NULL }
};

static const ber_choice_t IPCCContents_choice[] = {
  {   0, &hf_li_ps_pdu_iPPackets , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_T_iPPackets },
  {   1, &hf_li_ps_pdu_iPTruncatedPacket, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPTruncatedPacket },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IPCCContents(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IPCCContents_choice, hf_index, ett_li_ps_pdu_IPCCContents,
                                 NULL);

  return offset;
}


static const ber_sequence_t IPCC_sequence[] = {
  { &hf_li_ps_pdu_iPCCObjId , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_RELATIVE_OID },
  { &hf_li_ps_pdu_iPCCContents, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_IPCCContents },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IPCC(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPCC_sequence, hf_index, ett_li_ps_pdu_IPCC);

  return offset;
}



static unsigned
dissect_li_ps_pdu_T_threeGPP33128DefinedCC(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *cc_tvb = NULL;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &cc_tvb);

  if (cc_tvb) {
    dissect_lix2_CCPayload(false, cc_tvb, 0, actx,
                           proto_item_add_subtree(actx->created_item, ett_li_ps_pdu_contents),
                           hf_li_ps_pdu_CCPayload_element);
  }



  return offset;
}


static const value_string li_ps_pdu_CCContents_vals[] = {
  {   1, "emailCC" },
  {   2, "iPCC" },
  {   4, "uMTSCC" },
  {   6, "l2CC" },
  {   7, "tTRAFFIC-1" },
  {   8, "cTTRAFFIC-1" },
  {   9, "tTRAFFIC-2" },
  {  10, "cTTRAFFIC-2" },
  {  11, "pstnIsdnCC" },
  {  12, "iPMMCC" },
  {  14, "messagingCC" },
  {  15, "ePSCC" },
  {  16, "uMTSCC-CC-PDU" },
  {  17, "ePSCC-CC-PDU" },
  {  18, "messagingMMCC" },
  {  19, "confCC-CC-PDU" },
  {  20, "voipCC-CC-PDU" },
  {  21, "gcseCC-CC-PDU" },
  {  22, "cSvoice-CC-PDU" },
  {  23, "threeGPP33128DefinedCC" },
  { 0, NULL }
};

static const ber_choice_t CCContents_choice[] = {
  {   1, &hf_li_ps_pdu_emailCC   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_EmailCC },
  {   2, &hf_li_ps_pdu_iPCC      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IPCC },
  {   4, &hf_li_ps_pdu_uMTSCC    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  {   6, &hf_li_ps_pdu_l2CC      , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_L2CC },
  {   7, &hf_li_ps_pdu_tTRAFFIC_1, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_TTRAFFIC },
  {   8, &hf_li_ps_pdu_cTTRAFFIC_1, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_CTTRAFFIC },
  {   9, &hf_li_ps_pdu_tTRAFFIC_2, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_TTRAFFIC },
  {  10, &hf_li_ps_pdu_cTTRAFFIC_2, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_CTTRAFFIC },
  {  11, &hf_li_ps_pdu_pstnIsdnCC, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_PstnIsdnCC },
  {  12, &hf_li_ps_pdu_iPMMCC    , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_IPMMCC },
  {  14, &hf_li_ps_pdu_messagingCC, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_MessagingCC },
  {  15, &hf_li_ps_pdu_ePSCC     , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  {  16, &hf_li_ps_pdu_uMTSCC_CC_PDU, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_CC_PDU },
  {  17, &hf_li_ps_pdu_ePSCC_CC_PDU, BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_CC_PDU },
  {  18, &hf_li_ps_pdu_messagingMMCC, BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_MessagingMMCC },
  {  19, &hf_li_ps_pdu_confCC_CC_PDU, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_Conf_CC_PDU },
  {  20, &hf_li_ps_pdu_voipCC_CC_PDU, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_Voip_CC_PDU },
  {  21, &hf_li_ps_pdu_gcseCC_CC_PDU, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_Gcse_CC_PDU },
  {  22, &hf_li_ps_pdu_cSvoice_CC_PDU, BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_CSvoice_CC_PDU },
  {  23, &hf_li_ps_pdu_threeGPP33128DefinedCC, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_T_threeGPP33128DefinedCC },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_CCContents(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CCContents_choice, hf_index, ett_li_ps_pdu_CCContents,
                                 NULL);

  return offset;
}


static const ber_sequence_t CCPayload_sequence[] = {
  { &hf_li_ps_pdu_payloadDirection, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PayloadDirection },
  { &hf_li_ps_pdu_timeStamp , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeneralizedTime },
  { &hf_li_ps_pdu_cCContents, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_CCContents },
  { &hf_li_ps_pdu_microSecondTimeStamp, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_MicroSecondTimeStamp },
  { &hf_li_ps_pdu_timeStampQualifier, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_TimeStampQualifier },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_CCPayload(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CCPayload_sequence, hf_index, ett_li_ps_pdu_CCPayload);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_CCPayload_sequence_of[1] = {
  { &hf_li_ps_pdu_cCPayloadSequence_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_li_ps_pdu_CCPayload },
};

static unsigned
dissect_li_ps_pdu_SEQUENCE_OF_CCPayload(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_CCPayload_sequence_of, hf_index, ett_li_ps_pdu_SEQUENCE_OF_CCPayload);

  return offset;
}


static const ber_sequence_t T_includedSequenceNumbers_sequence_of[1] = {
  { &hf_li_ps_pdu_includedSequenceNumbers_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_li_ps_pdu_INTEGER_0_4294967295 },
};

static unsigned
dissect_li_ps_pdu_T_includedSequenceNumbers(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_includedSequenceNumbers_sequence_of, hf_index, ett_li_ps_pdu_T_includedSequenceNumbers);

  return offset;
}


static const value_string li_ps_pdu_CheckType_vals[] = {
  {   1, "hash" },
  {   2, "signature" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_CheckType(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string li_ps_pdu_DataType_vals[] = {
  {   1, "iRI" },
  {   2, "cC" },
  {   3, "iLHI" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_DataType(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string li_ps_pdu_HashAlgorithm_vals[] = {
  {   1, "sHA-1" },
  {   2, "sHA-256" },
  {   3, "sHA-384" },
  {   4, "sHA-512" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_HashAlgorithm(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string li_ps_pdu_SignatureAlgorithm_vals[] = {
  {   1, "dSA" },
  {   2, "eCDSA" },
  {   3, "edDSA" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_SignatureAlgorithm(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t IntegrityCheck_sequence[] = {
  { &hf_li_ps_pdu_includedSequenceNumbers, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_T_includedSequenceNumbers },
  { &hf_li_ps_pdu_checkType , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_CheckType },
  { &hf_li_ps_pdu_dataType  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_DataType },
  { &hf_li_ps_pdu_checkValue, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_hashAlgorithm, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_HashAlgorithm },
  { &hf_li_ps_pdu_signatureAlgorithm, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_SignatureAlgorithm },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_IntegrityCheck(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IntegrityCheck_sequence, hf_index, ett_li_ps_pdu_IntegrityCheck);

  return offset;
}


static const value_string li_ps_pdu_OperatorLeaMessagePriority_vals[] = {
  {   1, "error" },
  {   2, "informational" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_OperatorLeaMessagePriority(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_OCTET_STRING_SIZE_1_255(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_octet_string(implicit_tag, actx, tree, tvb, offset,
                                                   1, 255, hf_index, NULL);

  return offset;
}


static const ber_sequence_t OperatorLeaMessage_sequence[] = {
  { &hf_li_ps_pdu_messagePriority, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OperatorLeaMessagePriority },
  { &hf_li_ps_pdu_message   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING_SIZE_1_255 },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_OperatorLeaMessage(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OperatorLeaMessage_sequence, hf_index, ett_li_ps_pdu_OperatorLeaMessage);

  return offset;
}


static const value_string li_ps_pdu_Option_vals[] = {
  {   0, "pDUAcknowledgement" },
  { 0, NULL }
};

static const ber_choice_t Option_choice[] = {
  {   0, &hf_li_ps_pdu_pDUAcknowledgement, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_Option(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Option_choice, hf_index, ett_li_ps_pdu_Option,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Option_sequence_of[1] = {
  { &hf_li_ps_pdu_requestedOptions_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_Option },
};

static unsigned
dissect_li_ps_pdu_SEQUENCE_OF_Option(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Option_sequence_of, hf_index, ett_li_ps_pdu_SEQUENCE_OF_Option);

  return offset;
}


static const ber_sequence_t OptionRequest_sequence[] = {
  { &hf_li_ps_pdu_requestedOptions, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_SEQUENCE_OF_Option },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_OptionRequest(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OptionRequest_sequence, hf_index, ett_li_ps_pdu_OptionRequest);

  return offset;
}


static const ber_sequence_t OptionResponse_sequence[] = {
  { &hf_li_ps_pdu_acceptedOptions, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_SEQUENCE_OF_Option },
  { &hf_li_ps_pdu_declinedOptions, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_SEQUENCE_OF_Option },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_OptionResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OptionResponse_sequence, hf_index, ett_li_ps_pdu_OptionResponse);

  return offset;
}


static const value_string li_ps_pdu_TRIPayload_vals[] = {
  {   0, "integrityCheck" },
  {   1, "testPDU" },
  {   2, "paddingPDU" },
  {   3, "keep-alive" },
  {   4, "keep-aliveResponse" },
  {   5, "firstSegmentFlag" },
  {   6, "lastSegmentFlag" },
  {   7, "cINReset" },
  {   8, "operatorLeaMessage" },
  {   9, "optionRequest" },
  {  10, "optionResponse" },
  {  11, "optionComplete" },
  {  12, "pDUAcknowledgementRequest" },
  {  13, "pDUAcknowledgementResponse" },
  { 0, NULL }
};

static const ber_choice_t TRIPayload_choice[] = {
  {   0, &hf_li_ps_pdu_integrityCheck, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_IntegrityCheck },
  {   1, &hf_li_ps_pdu_testPDU   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_NULL },
  {   2, &hf_li_ps_pdu_paddingPDU, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  {   3, &hf_li_ps_pdu_keep_alive, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_NULL },
  {   4, &hf_li_ps_pdu_keep_aliveResponse, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_NULL },
  {   5, &hf_li_ps_pdu_firstSegmentFlag, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_NULL },
  {   6, &hf_li_ps_pdu_lastSegmentFlag, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_NULL },
  {   7, &hf_li_ps_pdu_cINReset  , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_NULL },
  {   8, &hf_li_ps_pdu_operatorLeaMessage, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OperatorLeaMessage },
  {   9, &hf_li_ps_pdu_optionRequest, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OptionRequest },
  {  10, &hf_li_ps_pdu_optionResponse, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OptionResponse },
  {  11, &hf_li_ps_pdu_optionComplete, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_NULL },
  {  12, &hf_li_ps_pdu_pDUAcknowledgementRequest, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_NULL },
  {  13, &hf_li_ps_pdu_pDUAcknowledgementResponse, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_TRIPayload(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TRIPayload_choice, hf_index, ett_li_ps_pdu_TRIPayload,
                                 NULL);

  return offset;
}


static const value_string li_ps_pdu_EncryptionType_vals[] = {
  {   1, "none" },
  {   2, "national-option" },
  {   3, "aES-192-CBC" },
  {   4, "aES-256-CBC" },
  {   5, "blowfish-192-CBC" },
  {   6, "blowfish-256-CBC" },
  {   7, "threedes-cbc" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_EncryptionType(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string li_ps_pdu_EncryptedPayloadType_vals[] = {
  {   1, "unknown" },
  {   2, "part2" },
  {   3, "part3" },
  {   4, "part4" },
  {   5, "part5" },
  {   6, "part6" },
  {   7, "part7" },
  {   8, "part1" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_EncryptedPayloadType(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t EncryptionContainer_sequence[] = {
  { &hf_li_ps_pdu_encryptionType, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_EncryptionType },
  { &hf_li_ps_pdu_encryptedPayload, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_OCTET_STRING },
  { &hf_li_ps_pdu_encryptedPayloadType, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_EncryptedPayloadType },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_EncryptionContainer(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EncryptionContainer_sequence, hf_index, ett_li_ps_pdu_EncryptionContainer);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ILHIPayload_sequence_of[1] = {
  { &hf_li_ps_pdu_iLHIPayload_item, BER_CLASS_ANY, -1, BER_FLAGS_NOOWNTAG, dissect_li_ps_pdu_not_decoded_ILHIPayload },
};

static unsigned
dissect_li_ps_pdu_SEQUENCE_OF_ILHIPayload(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ILHIPayload_sequence_of, hf_index, ett_li_ps_pdu_SEQUENCE_OF_ILHIPayload);

  return offset;
}



static unsigned
dissect_li_ps_pdu_ShortString(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                                        actx, tree, tvb, offset,
                                                        0, 255, hf_index, NULL);

  return offset;
}



static unsigned
dissect_li_ps_pdu_LongString(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_constrained_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                                        actx, tree, tvb, offset,
                                                        0, 65535, hf_index, NULL);

  return offset;
}


static const ber_sequence_t TargetIdentifierFormat_sequence[] = {
  { &hf_li_ps_pdu_formatOwner, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_ShortString },
  { &hf_li_ps_pdu_formatName, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_ShortString },
  { &hf_li_ps_pdu_targetValue, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_LongString },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_TargetIdentifierFormat(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TargetIdentifierFormat_sequence, hf_index, ett_li_ps_pdu_TargetIdentifierFormat);

  return offset;
}


static const value_string li_ps_pdu_TargetIdentifier_vals[] = {
  {   1, "targetIdentifierFormat" },
  { 0, NULL }
};

static const ber_choice_t TargetIdentifier_choice[] = {
  {   1, &hf_li_ps_pdu_targetIdentifierFormat, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_TargetIdentifierFormat },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_TargetIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TargetIdentifier_choice, hf_index, ett_li_ps_pdu_TargetIdentifier,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_TargetIdentifier_sequence_of[1] = {
  { &hf_li_ps_pdu_targetIdentifiers_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_TargetIdentifier },
};

static unsigned
dissect_li_ps_pdu_SEQUENCE_OF_TargetIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_TargetIdentifier_sequence_of, hf_index, ett_li_ps_pdu_SEQUENCE_OF_TargetIdentifier);

  return offset;
}


static const ber_sequence_t DictionaryEntry_sequence[] = {
  { &hf_li_ps_pdu_owner     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_ShortString },
  { &hf_li_ps_pdu_name      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_ShortString },
  { &hf_li_ps_pdu_value     , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_ShortString },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_DictionaryEntry(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DictionaryEntry_sequence, hf_index, ett_li_ps_pdu_DictionaryEntry);

  return offset;
}


static const value_string li_ps_pdu_InterceptType_vals[] = {
  {   1, "iriAndCc" },
  {   2, "iriOnly" },
  {   3, "ccOnly" },
  { 0, NULL }
};


static unsigned
dissect_li_ps_pdu_InterceptType(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t HI4LINotification_sequence[] = {
  { &hf_li_ps_pdu_activationTime, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeneralizedTime },
  { &hf_li_ps_pdu_deactivationTime, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_GeneralizedTime },
  { &hf_li_ps_pdu_targetIdentifiers, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_SEQUENCE_OF_TargetIdentifier },
  { &hf_li_ps_pdu_serviceType, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_DictionaryEntry },
  { &hf_li_ps_pdu_targetIdentifierSubtype, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_DictionaryEntry },
  { &hf_li_ps_pdu_interceptType, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_InterceptType },
  { &hf_li_ps_pdu_ownerIdentifier, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_ShortString },
  { &hf_li_ps_pdu_authorizationReference, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_LongString },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_HI4LINotification(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   HI4LINotification_sequence, hf_index, ett_li_ps_pdu_HI4LINotification);

  return offset;
}


static const value_string li_ps_pdu_HI4Notification_vals[] = {
  {   1, "liActivated" },
  {   2, "liDeactivated" },
  {   3, "liModified" },
  { 0, NULL }
};

static const ber_choice_t HI4Notification_choice[] = {
  {   1, &hf_li_ps_pdu_liActivated, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_HI4LINotification },
  {   2, &hf_li_ps_pdu_liDeactivated, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_HI4LINotification },
  {   3, &hf_li_ps_pdu_liModified, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_HI4LINotification },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_HI4Notification(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 HI4Notification_choice, hf_index, ett_li_ps_pdu_HI4Notification,
                                 NULL);

  return offset;
}


static const value_string li_ps_pdu_HI4Payload_vals[] = {
  {   1, "threeGPP-LI-Notification" },
  {   2, "hi4Notification" },
  { 0, NULL }
};

static const ber_choice_t HI4Payload_choice[] = {
  {   1, &hf_li_ps_pdu_threeGPP_LI_Notification, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_lix2_LINotificationPayload },
  {   2, &hf_li_ps_pdu_hi4Notification, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_HI4Notification },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_HI4Payload(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 HI4Payload_choice, hf_index, ett_li_ps_pdu_HI4Payload,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_HI4Payload_sequence_of[1] = {
  { &hf_li_ps_pdu_hI4Payload_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_HI4Payload },
};

static unsigned
dissect_li_ps_pdu_SEQUENCE_OF_HI4Payload(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_HI4Payload_sequence_of, hf_index, ett_li_ps_pdu_SEQUENCE_OF_HI4Payload);

  return offset;
}


static const value_string li_ps_pdu_Payload_vals[] = {
  {   0, "iRIPayloadSequence" },
  {   1, "cCPayloadSequence" },
  {   2, "tRIPayload" },
  {   3, "hI1-Operation" },
  {   4, "encryptionContainer" },
  {   5, "threeGPP-HI1-Operation" },
  {   6, "iLHIPayload" },
  {   7, "hI4Payload" },
  { 0, NULL }
};

static const ber_choice_t Payload_choice[] = {
  {   0, &hf_li_ps_pdu_iRIPayloadSequence, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_SEQUENCE_OF_IRIPayload },
  {   1, &hf_li_ps_pdu_cCPayloadSequence, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_SEQUENCE_OF_CCPayload },
  {   2, &hf_li_ps_pdu_tRIPayload, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_TRIPayload },
  {   3, &hf_li_ps_pdu_hI1_Operation, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_HI1_Operation },
  {   4, &hf_li_ps_pdu_encryptionContainer, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_EncryptionContainer },
  {   5, &hf_li_ps_pdu_threeGPP_HI1_Operation, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_not_decoded_ThreeGPP_HI1_Operation },
  {   6, &hf_li_ps_pdu_iLHIPayload, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_SEQUENCE_OF_ILHIPayload },
  {   7, &hf_li_ps_pdu_hI4Payload, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_SEQUENCE_OF_HI4Payload },
  { 0, NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_Payload(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Payload_choice, hf_index, ett_li_ps_pdu_Payload,
                                 NULL);

  return offset;
}


static const ber_sequence_t PS_PDU_sequence[] = {
  { &hf_li_ps_pdu_pSHeader  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_li_ps_pdu_PSHeader },
  { &hf_li_ps_pdu_payload   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_li_ps_pdu_Payload },
  { NULL, 0, 0, 0, NULL }
};

static unsigned
dissect_li_ps_pdu_PS_PDU(bool implicit_tag _U_, tvbuff_t *tvb _U_, unsigned offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PS_PDU_sequence, hf_index, ett_li_ps_pdu_PS_PDU);

  return offset;
}

/*--- PDUs ---*/

static int dissect_PS_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_li_ps_pdu_PS_PDU(false, tvb, offset, &asn1_ctx, tree, hf_li_ps_pdu_PS_PDU_PDU);
  return offset;
}
static int dissect_Payload_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  unsigned offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_li_ps_pdu_Payload(false, tvb, offset, &asn1_ctx, tree, hf_li_ps_pdu_Payload_PDU);
  return offset;
}


/* The PS-PDU and its Payload, under a protocol item */
static int
dissect_li_ps_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  int8_t ber_class;
  bool pc;
  int32_t tag;
  proto_item *ti;

  /* PS-PDU is a SEQUENCE */
  get_ber_identifier(tvb, 0, &ber_class, &pc, &tag);
  if (ber_class != BER_CLASS_UNI || !pc || tag != BER_UNI_TAG_SEQUENCE)
    return 0;

  ti = proto_tree_add_item(tree, proto_li_ps_pdu, tvb, 0, -1, ENC_NA);
  return dissect_PS_PDU_PDU(tvb, pinfo, proto_item_add_subtree(ti, ett_li_ps_pdu), data);
}

static int
dissect_li_ps_pdu_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  int8_t ber_class;
  proto_item *ti;

  /* Payload is a CHOICE of context-specific tags */
  get_ber_identifier(tvb, 0, &ber_class, NULL, NULL);
  if (ber_class != BER_CLASS_CON)
    return 0;

  ti = proto_tree_add_item(tree, proto_li_ps_pdu, tvb, 0, -1, ENC_NA);
  return dissect_Payload_PDU(tvb, pinfo, proto_item_add_subtree(ti, ett_li_ps_pdu), data);
}

/*--- proto_register_li_ps_pdu ----------------------------------------------*/
void proto_register_li_ps_pdu(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_li_ps_pdu_PS_PDU_PDU,
      { "PS-PDU", "li-ps-pdu.PS_PDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_Payload_PDU,
      { "Payload", "li-ps-pdu.Payload",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_Payload_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_pSHeader,
      { "pSHeader", "li-ps-pdu.pSHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_payload,
      { "payload", "li-ps-pdu.payload",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_Payload_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_li_psDomainId,
      { "li-psDomainId", "li-ps-pdu.li_psDomainId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_li_ps_pdu_lawfulInterceptionIdentifier,
      { "lawfulInterceptionIdentifier", "li-ps-pdu.lawfulInterceptionIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_authorizationCountryCode,
      { "authorizationCountryCode", "li-ps-pdu.authorizationCountryCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_2", HFILL }},
    { &hf_li_ps_pdu_communicationIdentifier,
      { "communicationIdentifier", "li-ps-pdu.communicationIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_sequenceNumber,
      { "sequenceNumber", "li-ps-pdu.sequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_li_ps_pdu_timeStamp,
      { "timeStamp", "li-ps-pdu.timeStamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_li_ps_pdu_interceptionPointID,
      { "interceptionPointID", "li-ps-pdu.interceptionPointID",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_1_8", HFILL }},
    { &hf_li_ps_pdu_microSecondTimeStamp,
      { "microSecondTimeStamp", "li-ps-pdu.microSecondTimeStamp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_timeStampQualifier,
      { "timeStampQualifier", "li-ps-pdu.timeStampQualifier",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_TimeStampQualifier_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_extendedInterceptionPointID,
      { "extendedInterceptionPointID", "li-ps-pdu.extendedInterceptionPointID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_65535", HFILL }},
    { &hf_li_ps_pdu_networkFunctionIdentifier,
      { "networkFunctionIdentifier", "li-ps-pdu.networkFunctionIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_65535", HFILL }},
    { &hf_li_ps_pdu_iRIPayloadSequence,
      { "iRIPayloadSequence", "li-ps-pdu.iRIPayloadSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_IRIPayload", HFILL }},
    { &hf_li_ps_pdu_iRIPayloadSequence_item,
      { "IRIPayload", "li-ps-pdu.IRIPayload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_cCPayloadSequence,
      { "cCPayloadSequence", "li-ps-pdu.cCPayloadSequence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_CCPayload", HFILL }},
    { &hf_li_ps_pdu_cCPayloadSequence_item,
      { "CCPayload", "li-ps-pdu.CCPayload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_tRIPayload,
      { "tRIPayload", "li-ps-pdu.tRIPayload",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_TRIPayload_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_hI1_Operation,
      { "hI1-Operation", "li-ps-pdu.hI1_Operation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_encryptionContainer,
      { "encryptionContainer", "li-ps-pdu.encryptionContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_threeGPP_HI1_Operation,
      { "threeGPP-HI1-Operation", "li-ps-pdu.threeGPP_HI1_Operation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iLHIPayload,
      { "iLHIPayload", "li-ps-pdu.iLHIPayload",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ILHIPayload", HFILL }},
    { &hf_li_ps_pdu_iLHIPayload_item,
      { "ILHIPayload", "li-ps-pdu.ILHIPayload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_hI4Payload,
      { "hI4Payload", "li-ps-pdu.hI4Payload",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_HI4Payload", HFILL }},
    { &hf_li_ps_pdu_hI4Payload_item,
      { "HI4Payload", "li-ps-pdu.HI4Payload",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_HI4Payload_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_threeGPP_LI_Notification,
      { "threeGPP-LI-Notification", "li-ps-pdu.threeGPP_LI_Notification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LINotificationPayload", HFILL }},
    { &hf_li_ps_pdu_hi4Notification,
      { "hi4Notification", "li-ps-pdu.hi4Notification",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_HI4Notification_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_networkIdentifier,
      { "networkIdentifier", "li-ps-pdu.networkIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_communicationIdentityNumber,
      { "communicationIdentityNumber", "li-ps-pdu.communicationIdentityNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_li_ps_pdu_deliveryCountryCode,
      { "deliveryCountryCode", "li-ps-pdu.deliveryCountryCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_2", HFILL }},
    { &hf_li_ps_pdu_cINExtension,
      { "cINExtension", "li-ps-pdu.cINExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CorrelationValues", HFILL }},
    { &hf_li_ps_pdu_operatorIdentifier,
      { "operatorIdentifier", "li-ps-pdu.operatorIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_16", HFILL }},
    { &hf_li_ps_pdu_networkElementIdentifier,
      { "networkElementIdentifier", "li-ps-pdu.networkElementIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_16", HFILL }},
    { &hf_li_ps_pdu_eTSI671NEID,
      { "eTSI671NEID", "li-ps-pdu.eTSI671NEID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Network_Element_Identifier", HFILL }},
    { &hf_li_ps_pdu_payloadDirection,
      { "payloadDirection", "li-ps-pdu.payloadDirection",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_PayloadDirection_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_cCContents,
      { "cCContents", "li-ps-pdu.cCContents",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_CCContents_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_emailCC,
      { "emailCC", "li-ps-pdu.emailCC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iPCC,
      { "iPCC", "li-ps-pdu.iPCC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_uMTSCC,
      { "uMTSCC", "li-ps-pdu.uMTSCC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_l2CC,
      { "l2CC", "li-ps-pdu.l2CC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_tTRAFFIC_1,
      { "tTRAFFIC-1", "li-ps-pdu.tTRAFFIC_1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TTRAFFIC", HFILL }},
    { &hf_li_ps_pdu_cTTRAFFIC_1,
      { "cTTRAFFIC-1", "li-ps-pdu.cTTRAFFIC_1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CTTRAFFIC", HFILL }},
    { &hf_li_ps_pdu_tTRAFFIC_2,
      { "tTRAFFIC-2", "li-ps-pdu.tTRAFFIC_2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TS101909202_TTRAFFIC", HFILL }},
    { &hf_li_ps_pdu_cTTRAFFIC_2,
      { "cTTRAFFIC-2", "li-ps-pdu.cTTRAFFIC_2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TS101909202_CTTRAFFIC", HFILL }},
    { &hf_li_ps_pdu_pstnIsdnCC,
      { "pstnIsdnCC", "li-ps-pdu.pstnIsdnCC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iPMMCC,
      { "iPMMCC", "li-ps-pdu.iPMMCC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_messagingCC,
      { "messagingCC", "li-ps-pdu.messagingCC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_ePSCC,
      { "ePSCC", "li-ps-pdu.ePSCC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_uMTSCC_CC_PDU,
      { "uMTSCC-CC-PDU", "li-ps-pdu.uMTSCC_CC_PDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CC_PDU", HFILL }},
    { &hf_li_ps_pdu_ePSCC_CC_PDU,
      { "ePSCC-CC-PDU", "li-ps-pdu.ePSCC_CC_PDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Eps_HI3_PS_CC_PDU", HFILL }},
    { &hf_li_ps_pdu_messagingMMCC,
      { "messagingMMCC", "li-ps-pdu.messagingMMCC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_confCC_CC_PDU,
      { "confCC-CC-PDU", "li-ps-pdu.confCC_CC_PDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Conf_CC_PDU", HFILL }},
    { &hf_li_ps_pdu_voipCC_CC_PDU,
      { "voipCC-CC-PDU", "li-ps-pdu.voipCC_CC_PDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Voip_CC_PDU", HFILL }},
    { &hf_li_ps_pdu_gcseCC_CC_PDU,
      { "gcseCC-CC-PDU", "li-ps-pdu.gcseCC_CC_PDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Gcse_CC_PDU", HFILL }},
    { &hf_li_ps_pdu_cSvoice_CC_PDU,
      { "cSvoice-CC-PDU", "li-ps-pdu.cSvoice_CC_PDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_threeGPP33128DefinedCC,
      { "threeGPP33128DefinedCC", "li-ps-pdu.threeGPP33128DefinedCC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_seconds,
      { "seconds", "li-ps-pdu.seconds",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_18446744073709551615", HFILL }},
    { &hf_li_ps_pdu_microSeconds,
      { "microSeconds", "li-ps-pdu.microSeconds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_999999", HFILL }},
    { &hf_li_ps_pdu_iRIType,
      { "iRIType", "li-ps-pdu.iRIType",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_IRIType_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iRIContents,
      { "iRIContents", "li-ps-pdu.iRIContents",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_IRIContents_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_sessionDirection,
      { "sessionDirection", "li-ps-pdu.sessionDirection",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_PayloadDirection_vals), 0,
        "PayloadDirection", HFILL }},
    { &hf_li_ps_pdu_emailIRI,
      { "emailIRI", "li-ps-pdu.emailIRI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iPIRI,
      { "iPIRI", "li-ps-pdu.iPIRI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iPIRIOnly,
      { "iPIRIOnly", "li-ps-pdu.iPIRIOnly_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_uMTSIRI,
      { "uMTSIRI", "li-ps-pdu.uMTSIRI",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_UMTSIRI_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_eTSI671IRI,
      { "eTSI671IRI", "li-ps-pdu.eTSI671IRI",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_ETSI671IRI_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_l2IRI,
      { "l2IRI", "li-ps-pdu.l2IRI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_l2IRIOnly,
      { "l2IRIOnly", "li-ps-pdu.l2IRIOnly_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_tARGETACTIVITYMONITOR_1,
      { "tARGETACTIVITYMONITOR-1", "li-ps-pdu.tARGETACTIVITYMONITOR_1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_tARGETACTIVITYMONITOR_2,
      { "tARGETACTIVITYMONITOR-2", "li-ps-pdu.tARGETACTIVITYMONITOR_2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TARGETACTIVITYMONITOR", HFILL }},
    { &hf_li_ps_pdu_pstnIsdnIRI,
      { "pstnIsdnIRI", "li-ps-pdu.pstnIsdnIRI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iPMMIRI,
      { "iPMMIRI", "li-ps-pdu.iPMMIRI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_messagingIRI,
      { "messagingIRI", "li-ps-pdu.messagingIRI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_ePSIRI,
      { "ePSIRI", "li-ps-pdu.ePSIRI",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_EPSIRI_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_confIRI,
      { "confIRI", "li-ps-pdu.confIRI",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_ConfIRI_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_proseIRI,
      { "proseIRI", "li-ps-pdu.proseIRI",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_ProSeIRI_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_gcseIRI,
      { "gcseIRI", "li-ps-pdu.gcseIRI",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_GcseIRI_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_threeGPP33128DefinedIRI,
      { "threeGPP33128DefinedIRI", "li-ps-pdu.threeGPP33128DefinedIRI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iPIRIPacketReport,
      { "iPIRIPacketReport", "li-ps-pdu.iPIRIPacketReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iRI_Parameters,
      { "iRI-Parameters", "li-ps-pdu.iRI_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UmtsHI2Operations_IRI_Parameters", HFILL }},
    { &hf_li_ps_pdu_umtsIRIsContent,
      { "umtsIRIsContent", "li-ps-pdu.umtsIRIsContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iRI_CS_Parameters,
      { "iRI-CS-Parameters", "li-ps-pdu.iRI_CS_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UmtsCS_HI2Operations_IRI_Parameters", HFILL }},
    { &hf_li_ps_pdu_umtsCS_IRIsContent,
      { "umtsCS-IRIsContent", "li-ps-pdu.umtsCS_IRIsContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iRI_Parameters_01,
      { "iRI-Parameters", "li-ps-pdu.iRI_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iRIsContent,
      { "iRIsContent", "li-ps-pdu.iRIsContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iRI_EPS_Parameters,
      { "iRI-EPS-Parameters", "li-ps-pdu.iRI_EPS_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EpsHI2Operations_IRI_Parameters", HFILL }},
    { &hf_li_ps_pdu_epsIRIsContent,
      { "epsIRIsContent", "li-ps-pdu.epsIRIsContent",
        FT_UINT32, BASE_DEC, VALS(HI2Operations_EpsIRIsContent_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iRI_Conf_Parameters,
      { "iRI-Conf-Parameters", "li-ps-pdu.iRI_Conf_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CONFHI2Operations_IRI_Parameters", HFILL }},
    { &hf_li_ps_pdu_confIRIsContent,
      { "confIRIsContent", "li-ps-pdu.confIRIsContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iRI_ProSe_Parameters,
      { "iRI-ProSe-Parameters", "li-ps-pdu.iRI_ProSe_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProSeHI2Operations_IRI_Parameters", HFILL }},
    { &hf_li_ps_pdu_proseIRIsContent,
      { "proseIRIsContent", "li-ps-pdu.proseIRIsContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iRI_Gcse_Parameters,
      { "iRI-Gcse-Parameters", "li-ps-pdu.iRI_Gcse_Parameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GCSEHI2Operations_IRI_Parameters", HFILL }},
    { &hf_li_ps_pdu_gcseIRIsContent,
      { "gcseIRIsContent", "li-ps-pdu.gcseIRIsContent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_integrityCheck,
      { "integrityCheck", "li-ps-pdu.integrityCheck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_testPDU,
      { "testPDU", "li-ps-pdu.testPDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_paddingPDU,
      { "paddingPDU", "li-ps-pdu.paddingPDU",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_keep_alive,
      { "keep-alive", "li-ps-pdu.keep_alive_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_keep_aliveResponse,
      { "keep-aliveResponse", "li-ps-pdu.keep_aliveResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_firstSegmentFlag,
      { "firstSegmentFlag", "li-ps-pdu.firstSegmentFlag_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_lastSegmentFlag,
      { "lastSegmentFlag", "li-ps-pdu.lastSegmentFlag_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_cINReset,
      { "cINReset", "li-ps-pdu.cINReset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_operatorLeaMessage,
      { "operatorLeaMessage", "li-ps-pdu.operatorLeaMessage_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_optionRequest,
      { "optionRequest", "li-ps-pdu.optionRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_optionResponse,
      { "optionResponse", "li-ps-pdu.optionResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_optionComplete,
      { "optionComplete", "li-ps-pdu.optionComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_pDUAcknowledgementRequest,
      { "pDUAcknowledgementRequest", "li-ps-pdu.pDUAcknowledgementRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_pDUAcknowledgementResponse,
      { "pDUAcknowledgementResponse", "li-ps-pdu.pDUAcknowledgementResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_includedSequenceNumbers,
      { "includedSequenceNumbers", "li-ps-pdu.includedSequenceNumbers",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_includedSequenceNumbers_item,
      { "includedSequenceNumbers item", "li-ps-pdu.includedSequenceNumbers_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_li_ps_pdu_checkType,
      { "checkType", "li-ps-pdu.checkType",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_CheckType_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_dataType,
      { "dataType", "li-ps-pdu.dataType",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_DataType_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_checkValue,
      { "checkValue", "li-ps-pdu.checkValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_hashAlgorithm,
      { "hashAlgorithm", "li-ps-pdu.hashAlgorithm",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_HashAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_signatureAlgorithm,
      { "signatureAlgorithm", "li-ps-pdu.signatureAlgorithm",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_SignatureAlgorithm_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_pDUAcknowledgement,
      { "pDUAcknowledgement", "li-ps-pdu.pDUAcknowledgement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_requestedOptions,
      { "requestedOptions", "li-ps-pdu.requestedOptions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Option", HFILL }},
    { &hf_li_ps_pdu_requestedOptions_item,
      { "Option", "li-ps-pdu.Option",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_Option_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_acceptedOptions,
      { "acceptedOptions", "li-ps-pdu.acceptedOptions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Option", HFILL }},
    { &hf_li_ps_pdu_acceptedOptions_item,
      { "Option", "li-ps-pdu.Option",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_Option_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_declinedOptions,
      { "declinedOptions", "li-ps-pdu.declinedOptions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Option", HFILL }},
    { &hf_li_ps_pdu_declinedOptions_item,
      { "Option", "li-ps-pdu.Option",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_Option_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_messagePriority,
      { "messagePriority", "li-ps-pdu.messagePriority",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_OperatorLeaMessagePriority_vals), 0,
        "OperatorLeaMessagePriority", HFILL }},
    { &hf_li_ps_pdu_message,
      { "message", "li-ps-pdu.message",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_255", HFILL }},
    { &hf_li_ps_pdu_encryptionType,
      { "encryptionType", "li-ps-pdu.encryptionType",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_EncryptionType_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_encryptedPayload,
      { "encryptedPayload", "li-ps-pdu.encryptedPayload",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_encryptedPayloadType,
      { "encryptedPayloadType", "li-ps-pdu.encryptedPayloadType",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_EncryptedPayloadType_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_liActivated,
      { "liActivated", "li-ps-pdu.liActivated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HI4LINotification", HFILL }},
    { &hf_li_ps_pdu_liDeactivated,
      { "liDeactivated", "li-ps-pdu.liDeactivated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HI4LINotification", HFILL }},
    { &hf_li_ps_pdu_liModified,
      { "liModified", "li-ps-pdu.liModified_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HI4LINotification", HFILL }},
    { &hf_li_ps_pdu_activationTime,
      { "activationTime", "li-ps-pdu.activationTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_li_ps_pdu_deactivationTime,
      { "deactivationTime", "li-ps-pdu.deactivationTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_li_ps_pdu_targetIdentifiers,
      { "targetIdentifiers", "li-ps-pdu.targetIdentifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_TargetIdentifier", HFILL }},
    { &hf_li_ps_pdu_targetIdentifiers_item,
      { "TargetIdentifier", "li-ps-pdu.TargetIdentifier",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_TargetIdentifier_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_serviceType,
      { "serviceType", "li-ps-pdu.serviceType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DictionaryEntry", HFILL }},
    { &hf_li_ps_pdu_targetIdentifierSubtype,
      { "targetIdentifierSubtype", "li-ps-pdu.targetIdentifierSubtype_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DictionaryEntry", HFILL }},
    { &hf_li_ps_pdu_interceptType,
      { "interceptType", "li-ps-pdu.interceptType",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_InterceptType_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_ownerIdentifier,
      { "ownerIdentifier", "li-ps-pdu.ownerIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "ShortString", HFILL }},
    { &hf_li_ps_pdu_authorizationReference,
      { "authorizationReference", "li-ps-pdu.authorizationReference",
        FT_STRING, BASE_NONE, NULL, 0,
        "LongString", HFILL }},
    { &hf_li_ps_pdu_targetIdentifierFormat,
      { "targetIdentifierFormat", "li-ps-pdu.targetIdentifierFormat_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_formatOwner,
      { "formatOwner", "li-ps-pdu.formatOwner",
        FT_STRING, BASE_NONE, NULL, 0,
        "ShortString", HFILL }},
    { &hf_li_ps_pdu_formatName,
      { "formatName", "li-ps-pdu.formatName",
        FT_STRING, BASE_NONE, NULL, 0,
        "ShortString", HFILL }},
    { &hf_li_ps_pdu_targetValue,
      { "targetValue", "li-ps-pdu.targetValue",
        FT_STRING, BASE_NONE, NULL, 0,
        "LongString", HFILL }},
    { &hf_li_ps_pdu_owner,
      { "owner", "li-ps-pdu.owner",
        FT_STRING, BASE_NONE, NULL, 0,
        "ShortString", HFILL }},
    { &hf_li_ps_pdu_name,
      { "name", "li-ps-pdu.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "ShortString", HFILL }},
    { &hf_li_ps_pdu_value,
      { "value", "li-ps-pdu.value",
        FT_STRING, BASE_NONE, NULL, 0,
        "ShortString", HFILL }},
    { &hf_li_ps_pdu_umtsHI2Location,
      { "umtsHI2Location", "li-ps-pdu.umtsHI2Location_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UmtsHI2Operations_Location", HFILL }},
    { &hf_li_ps_pdu_epsLocation,
      { "epsLocation", "li-ps-pdu.epsLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_wlanLocationAttributes,
      { "wlanLocationAttributes", "li-ps-pdu.wlanLocationAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_eTSI671HI2Location,
      { "eTSI671HI2Location", "li-ps-pdu.eTSI671HI2Location_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HI2Operations_Location", HFILL }},
    { &hf_li_ps_pdu_threeGPP33128UserLocation,
      { "threeGPP33128UserLocation", "li-ps-pdu.threeGPP33128UserLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UserLocation", HFILL }},
    { &hf_li_ps_pdu_cPEProvidedLocationAttributes,
      { "cPEProvidedLocationAttributes", "li-ps-pdu.cPEProvidedLocationAttributes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_wlanAPMACAddress,
      { "wlanAPMACAddress", "li-ps-pdu.wlanAPMACAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_6", HFILL }},
    { &hf_li_ps_pdu_wGS84CoordinateDecimal,
      { "wGS84CoordinateDecimal", "li-ps-pdu.wGS84CoordinateDecimal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_gNSSLocation,
      { "gNSSLocation", "li-ps-pdu.gNSSLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iP_type,
      { "iP-type", "li-ps-pdu.iP_type",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_T_iP_type_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iP_value,
      { "iP-value", "li-ps-pdu.iP_value",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_IP_value_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iP_assignment,
      { "iP-assignment", "li-ps-pdu.iP_assignment",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_T_iP_assignment_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iPv6PrefixLength,
      { "iPv6PrefixLength", "li-ps-pdu.iPv6PrefixLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_128", HFILL }},
    { &hf_li_ps_pdu_iPv4SubnetMask,
      { "iPv4SubnetMask", "li-ps-pdu.iPv4SubnetMask",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_li_ps_pdu_iP_NAT_translated,
      { "iP-NAT-translated", "li-ps-pdu.iP_NAT_translated",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_li_ps_pdu_iPBinaryAddress,
      { "iPBinaryAddress", "li-ps-pdu.iPBinaryAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4_16", HFILL }},
    { &hf_li_ps_pdu_iPTextAddress,
      { "iPTextAddress", "li-ps-pdu.iPTextAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_7_45", HFILL }},
    { &hf_li_ps_pdu_iPCCObjId,
      { "iPCCObjId", "li-ps-pdu.iPCCObjId",
        FT_REL_OID, BASE_NONE, NULL, 0,
        "RELATIVE_OID", HFILL }},
    { &hf_li_ps_pdu_iPCCContents,
      { "iPCCContents", "li-ps-pdu.iPCCContents",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_IPCCContents_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iPPackets,
      { "iPPackets", "li-ps-pdu.iPPackets",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iPTruncatedPacket,
      { "iPTruncatedPacket", "li-ps-pdu.iPTruncatedPacket_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_truncatedPacket,
      { "truncatedPacket", "li-ps-pdu.truncatedPacket",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_originalLength,
      { "originalLength", "li-ps-pdu.originalLength",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_li_ps_pdu_iPIRIObjId,
      { "iPIRIObjId", "li-ps-pdu.iPIRIObjId",
        FT_REL_OID, BASE_NONE, NULL, 0,
        "RELATIVE_OID", HFILL }},
    { &hf_li_ps_pdu_iPIRIContents,
      { "iPIRIContents", "li-ps-pdu.iPIRIContents_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_accessEventType,
      { "accessEventType", "li-ps-pdu.accessEventType",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_AccessEventType_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_targetUsername,
      { "targetUsername", "li-ps-pdu.targetUsername",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_internetAccessType,
      { "internetAccessType", "li-ps-pdu.internetAccessType",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_InternetAccessType_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iPVersion,
      { "iPVersion", "li-ps-pdu.iPVersion",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_IPVersion_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_targetIPAddress,
      { "targetIPAddress", "li-ps-pdu.targetIPAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPAddress", HFILL }},
    { &hf_li_ps_pdu_targetNetworkID,
      { "targetNetworkID", "li-ps-pdu.targetNetworkID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_1_20", HFILL }},
    { &hf_li_ps_pdu_targetCPEID,
      { "targetCPEID", "li-ps-pdu.targetCPEID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_1_128", HFILL }},
    { &hf_li_ps_pdu_targetLocation,
      { "targetLocation", "li-ps-pdu.targetLocation",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_1_64", HFILL }},
    { &hf_li_ps_pdu_pOPPortNumber,
      { "pOPPortNumber", "li-ps-pdu.pOPPortNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_li_ps_pdu_callBackNumber,
      { "callBackNumber", "li-ps-pdu.callBackNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_1_20", HFILL }},
    { &hf_li_ps_pdu_startTime,
      { "startTime", "li-ps-pdu.startTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_li_ps_pdu_endTime,
      { "endTime", "li-ps-pdu.endTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_li_ps_pdu_endReason,
      { "endReason", "li-ps-pdu.endReason",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_EndReason_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_octetsReceived,
      { "octetsReceived", "li-ps-pdu.octetsReceived",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_18446744073709551615", HFILL }},
    { &hf_li_ps_pdu_octetsTransmitted,
      { "octetsTransmitted", "li-ps-pdu.octetsTransmitted",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_18446744073709551615", HFILL }},
    { &hf_li_ps_pdu_rawAAAData,
      { "rawAAAData", "li-ps-pdu.rawAAAData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_expectedEndTime,
      { "expectedEndTime", "li-ps-pdu.expectedEndTime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_li_ps_pdu_pOPPhoneNumber,
      { "pOPPhoneNumber", "li-ps-pdu.pOPPhoneNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_1_20", HFILL }},
    { &hf_li_ps_pdu_pOPIdentifier,
      { "pOPIdentifier", "li-ps-pdu.pOPIdentifier",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_IPIRIIDType_vals), 0,
        "IPIRIIDType", HFILL }},
    { &hf_li_ps_pdu_pOPIPAddress,
      { "pOPIPAddress", "li-ps-pdu.pOPIPAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPAddress", HFILL }},
    { &hf_li_ps_pdu_nationalIPIRIParameters,
      { "nationalIPIRIParameters", "li-ps-pdu.nationalIPIRIParameters_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_additionalIPAddress,
      { "additionalIPAddress", "li-ps-pdu.additionalIPAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPAddress", HFILL }},
    { &hf_li_ps_pdu_authenticationType,
      { "authenticationType", "li-ps-pdu.authenticationType",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_AuthenticationType_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_otherTargetIdentifiers,
      { "otherTargetIdentifiers", "li-ps-pdu.otherTargetIdentifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_OtherTargetIdentifiers", HFILL }},
    { &hf_li_ps_pdu_otherTargetIdentifiers_item,
      { "OtherTargetIdentifiers", "li-ps-pdu.OtherTargetIdentifiers",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_OtherTargetIdentifiers_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_location,
      { "location", "li-ps-pdu.location_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_pOPPortID,
      { "pOPPortID", "li-ps-pdu.pOPPortID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_framedRoutes,
      { "framedRoutes", "li-ps-pdu.framedRoutes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_FramedRoute", HFILL }},
    { &hf_li_ps_pdu_framedRoutes_item,
      { "FramedRoute", "li-ps-pdu.FramedRoute",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_FramedRoute_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_printableIDType,
      { "printableIDType", "li-ps-pdu.printableIDType",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String_SIZE_1_128", HFILL }},
    { &hf_li_ps_pdu_macAddressType,
      { "macAddressType", "li-ps-pdu.macAddressType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_6", HFILL }},
    { &hf_li_ps_pdu_ipAddressType,
      { "ipAddressType", "li-ps-pdu.ipAddressType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPAddress", HFILL }},
    { &hf_li_ps_pdu_countryCode,
      { "countryCode", "li-ps-pdu.countryCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString_SIZE_2", HFILL }},
    { &hf_li_ps_pdu_iPAddress,
      { "iPAddress", "li-ps-pdu.iPAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_framedRoute,
      { "framedRoute", "li-ps-pdu.framedRoute",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_iPIRIOnlyObjId,
      { "iPIRIOnlyObjId", "li-ps-pdu.iPIRIOnlyObjId",
        FT_REL_OID, BASE_NONE, NULL, 0,
        "RELATIVE_OID", HFILL }},
    { &hf_li_ps_pdu_iPInformation,
      { "iPInformation", "li-ps-pdu.iPInformation",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_IPInformation_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_protocolInformation,
      { "protocolInformation", "li-ps-pdu.protocolInformation",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_ProtocolInformation_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iPAggregatedNbrOfPackets,
      { "iPAggregatedNbrOfPackets", "li-ps-pdu.iPAggregatedNbrOfPackets",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_li_ps_pdu_iPAggregatedNbrOfBytes,
      { "iPAggregatedNbrOfBytes", "li-ps-pdu.iPAggregatedNbrOfBytes",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_li_ps_pdu_pDSRInformation,
      { "pDSRInformation", "li-ps-pdu.pDSRInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iPv4Information,
      { "iPv4Information", "li-ps-pdu.iPv4Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_iPv6Information,
      { "iPv6Information", "li-ps-pdu.iPv6Information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_none,
      { "none", "li-ps-pdu.none_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_tCPInformation,
      { "tCPInformation", "li-ps-pdu.tCPInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_uDPInformation,
      { "uDPInformation", "li-ps-pdu.uDPInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_headerLength,
      { "headerLength", "li-ps-pdu.headerLength",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_typeOfService,
      { "typeOfService", "li-ps-pdu.typeOfService",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_totalLength,
      { "totalLength", "li-ps-pdu.totalLength",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_li_ps_pdu_identification,
      { "identification", "li-ps-pdu.identification",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_li_ps_pdu_fragment,
      { "fragment", "li-ps-pdu.fragment",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_li_ps_pdu_ttl,
      { "ttl", "li-ps-pdu.ttl",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_protocol,
      { "protocol", "li-ps-pdu.protocol",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_headerChecksum,
      { "headerChecksum", "li-ps-pdu.headerChecksum",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_li_ps_pdu_source,
      { "source", "li-ps-pdu.source",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_li_ps_pdu_destination,
      { "destination", "li-ps-pdu.destination",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_li_ps_pdu_options,
      { "options", "li-ps-pdu.options",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_0_40", HFILL }},
    { &hf_li_ps_pdu_trafficClass,
      { "trafficClass", "li-ps-pdu.trafficClass",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_flowLabel,
      { "flowLabel", "li-ps-pdu.flowLabel",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_20", HFILL }},
    { &hf_li_ps_pdu_payloadLength,
      { "payloadLength", "li-ps-pdu.payloadLength",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_li_ps_pdu_nextHeader,
      { "nextHeader", "li-ps-pdu.nextHeader",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_hopLimit,
      { "hopLimit", "li-ps-pdu.hopLimit",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_source_01,
      { "source", "li-ps-pdu.source",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_li_ps_pdu_destination_01,
      { "destination", "li-ps-pdu.destination",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_li_ps_pdu_sourcePort,
      { "sourcePort", "li-ps-pdu.sourcePort",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_li_ps_pdu_destinationPort,
      { "destinationPort", "li-ps-pdu.destinationPort",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_li_ps_pdu_tcpinformation_sequenceNumber,
      { "sequenceNumber", "li-ps-pdu.tcpinformation_sequenceNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_li_ps_pdu_ackNumber,
      { "ackNumber", "li-ps-pdu.ackNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_li_ps_pdu_dataOffset,
      { "dataOffset", "li-ps-pdu.dataOffset",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_li_ps_pdu_controlBits,
      { "controlBits", "li-ps-pdu.controlBits",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_li_ps_pdu_windowSize,
      { "windowSize", "li-ps-pdu.windowSize",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_li_ps_pdu_checkSum,
      { "checkSum", "li-ps-pdu.checkSum",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_li_ps_pdu_urgentPointer,
      { "urgentPointer", "li-ps-pdu.urgentPointer",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_li_ps_pdu_length,
      { "length", "li-ps-pdu.length",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_li_ps_pdu_summaryTrigger,
      { "summaryTrigger", "li-ps-pdu.summaryTrigger",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_PDSRSummaryTriggerIPaccess_vals), 0,
        "PDSRSummaryTriggerIPaccess", HFILL }},
    { &hf_li_ps_pdu_firstPacketTimestamp,
      { "firstPacketTimestamp", "li-ps-pdu.firstPacketTimestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_li_ps_pdu_lastPacketTimestamp,
      { "lastPacketTimestamp", "li-ps-pdu.lastPacketTimestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_li_ps_pdu_packetCount,
      { "packetCount", "li-ps-pdu.packetCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_li_ps_pdu_byteCount,
      { "byteCount", "li-ps-pdu.byteCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_li_ps_pdu_iPIRIPacketReportObjId,
      { "iPIRIPacketReportObjId", "li-ps-pdu.iPIRIPacketReportObjId",
        FT_REL_OID, BASE_NONE, NULL, 0,
        "RELATIVE_OID", HFILL }},
    { &hf_li_ps_pdu_report,
      { "report", "li-ps-pdu.report",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_PacketReport_vals), 0,
        "PacketReport", HFILL }},
    { &hf_li_ps_pdu_header,
      { "header", "li-ps-pdu.header_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PacketReportHeader", HFILL }},
    { &hf_li_ps_pdu_summary,
      { "summary", "li-ps-pdu.summary_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PacketReportSummary", HFILL }},
    { &hf_li_ps_pdu_header_01,
      { "header", "li-ps-pdu.header",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_li_ps_pdu_indications,
      { "indications", "li-ps-pdu.indications",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PacketReportIndications", HFILL }},
    { &hf_li_ps_pdu_trigger,
      { "trigger", "li-ps-pdu.trigger",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_PacketReportTrigger_vals), 0,
        "PacketReportTrigger", HFILL }},
    { &hf_li_ps_pdu_firstTimestamp,
      { "firstTimestamp", "li-ps-pdu.firstTimestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_li_ps_pdu_lastTimestamp,
      { "lastTimestamp", "li-ps-pdu.lastTimestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_li_ps_pdu_latitude,
      { "latitude", "li-ps-pdu.latitude",
        FT_STRING, BASE_NONE, NULL, 0,
        "WGS84LatitudeDecimal", HFILL }},
    { &hf_li_ps_pdu_longitude,
      { "longitude", "li-ps-pdu.longitude",
        FT_STRING, BASE_NONE, NULL, 0,
        "WGS84LongitudeDecimal", HFILL }},
    { &hf_li_ps_pdu_latitude_01,
      { "latitude", "li-ps-pdu.latitude",
        FT_STRING, BASE_NONE, NULL, 0,
        "WGS84LatitudeAngular", HFILL }},
    { &hf_li_ps_pdu_longitude_01,
      { "longitude", "li-ps-pdu.longitude",
        FT_STRING, BASE_NONE, NULL, 0,
        "WGS84LongitudeAngular", HFILL }},
    { &hf_li_ps_pdu_altitudeAboveGroundLevel,
      { "altitudeAboveGroundLevel", "li-ps-pdu.altitudeAboveGroundLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "AltitudeMeters", HFILL }},
    { &hf_li_ps_pdu_altitudeAboveMeanSeaLevel,
      { "altitudeAboveMeanSeaLevel", "li-ps-pdu.altitudeAboveMeanSeaLevel",
        FT_INT32, BASE_DEC, NULL, 0,
        "AltitudeMeters", HFILL }},
    { &hf_li_ps_pdu_location_01,
      { "location", "li-ps-pdu.location_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeoShape", HFILL }},
    { &hf_li_ps_pdu_fixMode,
      { "fixMode", "li-ps-pdu.fixMode",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_FixMode_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_location_02,
      { "location", "li-ps-pdu.location",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_WGS84Coordinate_vals), 0,
        "WGS84Coordinate", HFILL }},
    { &hf_li_ps_pdu_altitude,
      { "altitude", "li-ps-pdu.altitude",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_Altitude_vals), 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_decimal,
      { "decimal", "li-ps-pdu.decimal_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WGS84CoordinateDecimal", HFILL }},
    { &hf_li_ps_pdu_angular,
      { "angular", "li-ps-pdu.angular_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WGS84CoordinateAngular", HFILL }},
    { &hf_li_ps_pdu_shape,
      { "shape", "li-ps-pdu.shape",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_GMLShape_vals), 0,
        "GMLShape", HFILL }},
    { &hf_li_ps_pdu_confidence,
      { "confidence", "li-ps-pdu.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Percentage", HFILL }},
    { &hf_li_ps_pdu_point,
      { "point", "li-ps-pdu.point",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_GeoPoint_vals), 0,
        "GeoPoint", HFILL }},
    { &hf_li_ps_pdu_sphere,
      { "sphere", "li-ps-pdu.sphere_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GeoSphere", HFILL }},
    { &hf_li_ps_pdu_xyEllipsoid,
      { "xyEllipsoid", "li-ps-pdu.xyEllipsoid_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_li_ps_pdu_wGS84Point,
      { "wGS84Point", "li-ps-pdu.wGS84Point_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WGS84Location", HFILL }},
    { &hf_li_ps_pdu_centerPoint,
      { "centerPoint", "li-ps-pdu.centerPoint",
        FT_UINT32, BASE_DEC, VALS(li_ps_pdu_GeoPoint_vals), 0,
        "GeoPoint", HFILL }},
    { &hf_li_ps_pdu_radiusMeters,
      { "radiusMeters", "li-ps-pdu.radiusMeters",
        FT_UINT64, BASE_DEC, NULL, 0,
        "UncertaintyMeters", HFILL }},
    { &hf_li_ps_pdu_uncertaintyLongitude,
      { "uncertaintyLongitude", "li-ps-pdu.uncertaintyLongitude",
        FT_UINT64, BASE_DEC, NULL, 0,
        "UncertaintyMeters", HFILL }},
    { &hf_li_ps_pdu_uncertaintyLatitude,
      { "uncertaintyLatitude", "li-ps-pdu.uncertaintyLatitude",
        FT_UINT64, BASE_DEC, NULL, 0,
        "UncertaintyMeters", HFILL }},
    { &hf_li_ps_pdu_uncertaintyAltitude,
      { "uncertaintyAltitude", "li-ps-pdu.uncertaintyAltitude",
        FT_UINT64, BASE_DEC, NULL, 0,
        "UncertaintyMeters", HFILL }},
    { &hf_li_ps_pdu_PacketReportIndications_zeroedIPv4TotalLength,
      { "zeroedIPv4TotalLength", "li.ps.pdu.PacketReportIndications.zeroedIPv4TotalLength",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_li_ps_pdu_PacketReportIndications_zeroedIPv4Flags,
      { "zeroedIPv4Flags", "li.ps.pdu.PacketReportIndications.zeroedIPv4Flags",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_li_ps_pdu_PacketReportIndications_zeroedIPv4TimeToLive,
      { "zeroedIPv4TimeToLive", "li.ps.pdu.PacketReportIndications.zeroedIPv4TimeToLive",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_li_ps_pdu_PacketReportIndications_zeroedIPv4HeaderChecksum,
      { "zeroedIPv4HeaderChecksum", "li.ps.pdu.PacketReportIndications.zeroedIPv4HeaderChecksum",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_li_ps_pdu_PacketReportIndications_zeroedIPv6PayloadLength,
      { "zeroedIPv6PayloadLength", "li.ps.pdu.PacketReportIndications.zeroedIPv6PayloadLength",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_li_ps_pdu_PacketReportIndications_removedIPv6ExtensionHeaders,
      { "removedIPv6ExtensionHeaders", "li.ps.pdu.PacketReportIndications.removedIPv6ExtensionHeaders",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_li_ps_pdu_PacketReportIndications_zeroedTCPSequenceNumber,
      { "zeroedTCPSequenceNumber", "li.ps.pdu.PacketReportIndications.zeroedTCPSequenceNumber",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_li_ps_pdu_PacketReportIndications_zeroedTCPAcknowledgementNumber,
      { "zeroedTCPAcknowledgementNumber", "li.ps.pdu.PacketReportIndications.zeroedTCPAcknowledgementNumber",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_li_ps_pdu_PacketReportIndications_zeroedTCPFlags,
      { "zeroedTCPFlags", "li.ps.pdu.PacketReportIndications.zeroedTCPFlags",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_li_ps_pdu_PacketReportIndications_zeroedTCPWindowSize,
      { "zeroedTCPWindowSize", "li.ps.pdu.PacketReportIndications.zeroedTCPWindowSize",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_li_ps_pdu_PacketReportIndications_zeroedTCPChecksum,
      { "zeroedTCPChecksum", "li.ps.pdu.PacketReportIndications.zeroedTCPChecksum",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_li_ps_pdu_PacketReportIndications_zeroedUDPLength,
      { "zeroedUDPLength", "li.ps.pdu.PacketReportIndications.zeroedUDPLength",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_li_ps_pdu_PacketReportIndications_zeroedUDPChecksum,
      { "zeroedUDPChecksum", "li.ps.pdu.PacketReportIndications.zeroedUDPChecksum",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_li_ps_pdu_IRIPayload_element,
      { "IRIPayload", "li-ps-pdu.IRIPayload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TS33128Payloads.IRIPayload", HFILL }},
    { &hf_li_ps_pdu_CCPayload_element,
      { "CCPayload", "li-ps-pdu.CCPayload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TS33128Payloads.CCPayload", HFILL }},
    { &hf_li_ps_pdu_not_decoded,
      { "Not decoded", "li-ps-pdu.not_decoded",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_li_ps_pdu,
    &ett_li_ps_pdu_contents,
    &ett_li_ps_pdu_PS_PDU,
    &ett_li_ps_pdu_PSHeader,
    &ett_li_ps_pdu_Payload,
    &ett_li_ps_pdu_SEQUENCE_OF_IRIPayload,
    &ett_li_ps_pdu_SEQUENCE_OF_CCPayload,
    &ett_li_ps_pdu_SEQUENCE_OF_ILHIPayload,
    &ett_li_ps_pdu_SEQUENCE_OF_HI4Payload,
    &ett_li_ps_pdu_HI4Payload,
    &ett_li_ps_pdu_CommunicationIdentifier,
    &ett_li_ps_pdu_NetworkIdentifier,
    &ett_li_ps_pdu_CCPayload,
    &ett_li_ps_pdu_CCContents,
    &ett_li_ps_pdu_MicroSecondTimeStamp,
    &ett_li_ps_pdu_IRIPayload,
    &ett_li_ps_pdu_IRIContents,
    &ett_li_ps_pdu_UMTSIRI,
    &ett_li_ps_pdu_ETSI671IRI,
    &ett_li_ps_pdu_EPSIRI,
    &ett_li_ps_pdu_ConfIRI,
    &ett_li_ps_pdu_ProSeIRI,
    &ett_li_ps_pdu_GcseIRI,
    &ett_li_ps_pdu_TRIPayload,
    &ett_li_ps_pdu_IntegrityCheck,
    &ett_li_ps_pdu_T_includedSequenceNumbers,
    &ett_li_ps_pdu_Option,
    &ett_li_ps_pdu_OptionRequest,
    &ett_li_ps_pdu_SEQUENCE_OF_Option,
    &ett_li_ps_pdu_OptionResponse,
    &ett_li_ps_pdu_OperatorLeaMessage,
    &ett_li_ps_pdu_EncryptionContainer,
    &ett_li_ps_pdu_HI4Notification,
    &ett_li_ps_pdu_HI4LINotification,
    &ett_li_ps_pdu_SEQUENCE_OF_TargetIdentifier,
    &ett_li_ps_pdu_TargetIdentifier,
    &ett_li_ps_pdu_TargetIdentifierFormat,
    &ett_li_ps_pdu_DictionaryEntry,
    &ett_li_ps_pdu_Location,
    &ett_li_ps_pdu_WlanLocationAttributes,
    &ett_li_ps_pdu_CPEProvidedLocationAttributes,
    &ett_li_ps_pdu_IPAddress,
    &ett_li_ps_pdu_IP_value,
    &ett_li_ps_pdu_IPCC,
    &ett_li_ps_pdu_IPCCContents,
    &ett_li_ps_pdu_IPTruncatedPacket,
    &ett_li_ps_pdu_IPIRI,
    &ett_li_ps_pdu_IPIRIContents,
    &ett_li_ps_pdu_SEQUENCE_OF_OtherTargetIdentifiers,
    &ett_li_ps_pdu_SEQUENCE_OF_FramedRoute,
    &ett_li_ps_pdu_IPIRIIDType,
    &ett_li_ps_pdu_NationalIPIRIParameters,
    &ett_li_ps_pdu_OtherTargetIdentifiers,
    &ett_li_ps_pdu_FramedRoute,
    &ett_li_ps_pdu_IPIRIOnly,
    &ett_li_ps_pdu_IPInformation,
    &ett_li_ps_pdu_ProtocolInformation,
    &ett_li_ps_pdu_IPv4Information,
    &ett_li_ps_pdu_IPv6Information,
    &ett_li_ps_pdu_TCPInformation,
    &ett_li_ps_pdu_UDPInformation,
    &ett_li_ps_pdu_PDSRInformation,
    &ett_li_ps_pdu_IPIRIPacketReport,
    &ett_li_ps_pdu_PacketReport,
    &ett_li_ps_pdu_PacketReportHeader,
    &ett_li_ps_pdu_PacketReportSummary,
    &ett_li_ps_pdu_PacketReportIndications,
    &ett_li_ps_pdu_WGS84CoordinateDecimal,
    &ett_li_ps_pdu_WGS84CoordinateAngular,
    &ett_li_ps_pdu_Altitude,
    &ett_li_ps_pdu_GNSSLocation,
    &ett_li_ps_pdu_WGS84Location,
    &ett_li_ps_pdu_WGS84Coordinate,
    &ett_li_ps_pdu_GeoShape,
    &ett_li_ps_pdu_GMLShape,
    &ett_li_ps_pdu_GeoPoint,
    &ett_li_ps_pdu_GeoSphere,
    &ett_li_ps_pdu_XYEllipsoid,
  };

  static ei_register_info ei[] = {
    { &ei_li_ps_pdu_not_decoded,
      { "li-ps-pdu.not_decoded.expert", PI_UNDECODED, PI_NOTE,
        "Not decoded: Wireshark does not have the ASN.1 module of this type", EXPFILL }},
  };

  expert_module_t *expert_li_ps_pdu;

  /* Register protocol */
  proto_li_ps_pdu = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_li_ps_pdu, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_li_ps_pdu = expert_register_protocol(proto_li_ps_pdu);
  expert_register_field_array(expert_li_ps_pdu, ei, array_length(ei));

  register_dissector("li-ps-pdu", dissect_li_ps_pdu, proto_li_ps_pdu);
  register_dissector("li-ps-pdu.payload", dissect_li_ps_pdu_payload, proto_li_ps_pdu);
}

/*--- proto_reg_handoff_li_ps_pdu -------------------------------------------*/
void proto_reg_handoff_li_ps_pdu(void) {

  ip_handle = find_dissector_add_dependency("ip", proto_li_ps_pdu);
}
