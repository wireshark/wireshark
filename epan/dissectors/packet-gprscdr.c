/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-gprscdr.c                                                           */
/* asn2wrs.py -b -q -L -p gprscdr -c ./gprscdr.cnf -s ./packet-gprscdr-template -D . -O ../.. GenericChargingDataTypes.asn GPRSChargingDataTypesV641.asn GPRSChargingDataTypes.asn */

/* packet-gprscdr-template.c
 * Copyright 2011 , Anders Broman <anders.broman [AT] ericsson.com>
 *
 * Updates and corrections:
 * Copyright 2018-2022, Joakim Karlsson <oakimk@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * References: 3GPP TS 32.298 V17.4.0
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-gsm_map.h"
#include "packet-gsm_a_common.h"
#include "packet-e212.h"
#include "packet-gprscdr.h"
#include "packet-gtp.h"
#include "packet-gtpv2.h"

#define PNAME  "GPRS CDR"
#define PSNAME "GPRSCDR"
#define PFNAME "gprscdr"

void proto_register_gprscdr(void);

/* Define the GPRS CDR proto */
static int proto_gprscdr;

static int hf_gprscdr_gprscdr_GPRSCallEventRecord_PDU;  /* GPRSCallEventRecord */
static int hf_gprscdr_gprscdr_GPRSRecord_PDU;     /* GPRSRecord */
static int hf_gprscdr_gprscdr_CAMELInformationPDP_PDU;  /* CAMELInformationPDP */
static int hf_gprscdr_gsm0408Cause;               /* INTEGER */
static int hf_gprscdr_gsm0902MapErrorValue;       /* INTEGER */
static int hf_gprscdr_itu_tQ767Cause;             /* INTEGER */
static int hf_gprscdr_networkSpecificCause;       /* ManagementExtension */
static int hf_gprscdr_manufacturerSpecificCause;  /* ManagementExtension */
static int hf_gprscdr_positionMethodFailureCause;  /* PositionMethodFailure_Diagnostic */
static int hf_gprscdr_unauthorizedLCSClientCause;  /* UnauthorizedLCSClient_Diagnostic */
static int hf_gprscdr_diameterResultCodeAndExperimentalResult;  /* INTEGER */
static int hf_gprscdr_plmnId;                     /* PLMN_Id */
static int hf_gprscdr_eutraCellId;                /* EutraCellId */
static int hf_gprscdr_nid;                        /* Nid */
static int hf_gprscdr_rANNASCause;                /* SEQUENCE_OF_RANNASCause */
static int hf_gprscdr_rANNASCause_item;           /* RANNASCause */
static int hf_gprscdr_sIP_URI;                    /* GraphicString */
static int hf_gprscdr_tEL_URI;                    /* GraphicString */
static int hf_gprscdr_uRN;                        /* GraphicString */
static int hf_gprscdr_iSDN_E164;                  /* GraphicString */
static int hf_gprscdr_externalId;                 /* UTF8String */
static int hf_gprscdr_iPBinaryAddress;            /* IPBinaryAddress */
static int hf_gprscdr_iPTextRepresentedAddress;   /* IPTextRepresentedAddress */
static int hf_gprscdr_iPBinV4Address;             /* IPBinV4Address */
static int hf_gprscdr_iPBinV6Address_choice;      /* IPBinV6AddressWithOrWithoutPrefixLength */
static int hf_gprscdr_iPBinV6Address;             /* IPBinV6Address */
static int hf_gprscdr_iPBinV6AddressWithPrefix;   /* IPBinV6AddressWithPrefixLength */
static int hf_gprscdr_pDPAddressPrefixLength;     /* PDPAddressPrefixLength */
static int hf_gprscdr_iPTextV4Address;            /* IA5String_SIZE_7_15 */
static int hf_gprscdr_iPTextV6Address;            /* IA5String_SIZE_15_45 */
static int hf_gprscdr_lcsClientExternalID;        /* LCSClientExternalID */
static int hf_gprscdr_lcsClientDialedByMS;        /* AddressString */
static int hf_gprscdr_lcsClientInternalID;        /* LCSClientInternalID */
static int hf_gprscdr_locationAreaCode;           /* LocationAreaCode */
static int hf_gprscdr_cellId;                     /* CellId */
static int hf_gprscdr_mCC_MNC;                    /* MCC_MNC */
static int hf_gprscdr_ManagementExtensions_item;  /* ManagementExtension */
static int hf_gprscdr_tMGI;                       /* TMGI */
static int hf_gprscdr_mBMSSessionIdentity;        /* MBMSSessionIdentity */
static int hf_gprscdr_mBMSServiceType;            /* MBMSServiceType */
static int hf_gprscdr_mBMSUserServiceType;        /* MBMSUserServiceType */
static int hf_gprscdr_mBMS2G3GIndicator;          /* MBMS2G3GIndicator */
static int hf_gprscdr_fileRepairSupported;        /* BOOLEAN */
static int hf_gprscdr_rAI;                        /* RoutingAreaCode */
static int hf_gprscdr_mBMSServiceArea;            /* MBMSServiceArea */
static int hf_gprscdr_requiredMBMSBearerCaps;     /* RequiredMBMSBearerCapabilities */
static int hf_gprscdr_mBMSGWAddress;              /* GSNAddress */
static int hf_gprscdr_cNIPMulticastDistribution;  /* CNIPMulticastDistribution */
static int hf_gprscdr_mBMSDataTransferStart;      /* MBMSTime */
static int hf_gprscdr_mBMSDataTransferStop;       /* MBMSTime */
static int hf_gprscdr_nrCellId;                   /* NrCellId */
static int hf_gprscdr_iPAddress;                  /* IPAddress */
static int hf_gprscdr_nRcgi;                      /* Ncgi */
static int hf_gprscdr_ecgi;                       /* Ecgi */
static int hf_gprscdr_sCSAddress;                 /* IPAddress */
static int hf_gprscdr_sCSRealm;                   /* DiameterIdentity */
static int hf_gprscdr_serviceSpecificData;        /* GraphicString */
static int hf_gprscdr_serviceSpecificType;        /* INTEGER */
static int hf_gprscdr_subscriptionIDType;         /* SubscriptionIDType */
static int hf_gprscdr_subscriptionIDData;         /* UTF8String */
static int hf_gprscdr_identifier;                 /* T_identifier */
static int hf_gprscdr_significance;               /* BOOLEAN */
static int hf_gprscdr_information;                /* T_information */
static int hf_gprscdr_sgsnPDPRecord;              /* SGSNPDPRecordV651 */
static int hf_gprscdr_ggsnPDPRecord;              /* GGSNPDPRecord */
static int hf_gprscdr_sgsnMMRecord;               /* SGSNMMRecord */
static int hf_gprscdr_sgsnSMORecord;              /* SGSNSMORecordV651 */
static int hf_gprscdr_sgsnSMTRecord;              /* SGSNSMTRecordV651 */
static int hf_gprscdr_egsnPDPRecord;              /* EGSNPDPRecord */
static int hf_gprscdr_recordType;                 /* CallEventRecordType */
static int hf_gprscdr_networkInitiation;          /* NetworkInitiatedPDPContext */
static int hf_gprscdr_servedIMSI;                 /* IMSI */
static int hf_gprscdr_ggsnAddress;                /* GSNAddress */
static int hf_gprscdr_chargingID;                 /* ChargingID */
static int hf_gprscdr_sgsnAddress;                /* SEQUENCE_OF_GSNAddress */
static int hf_gprscdr_sgsnAddress_item;           /* GSNAddress */
static int hf_gprscdr_accessPointNameNI;          /* AccessPointNameNI */
static int hf_gprscdr_pdpType;                    /* PDPType */
static int hf_gprscdr_servedPDPAddress;           /* PDPAddress */
static int hf_gprscdr_dynamicAddressFlag;         /* DynamicAddressFlag */
static int hf_gprscdr_listOfTrafficVolumes;       /* SEQUENCE_OF_ChangeOfCharConditionV651 */
static int hf_gprscdr_listOfTrafficVolumes_item;  /* ChangeOfCharConditionV651 */
static int hf_gprscdr_recordOpeningTime;          /* TimeStamp */
static int hf_gprscdr_duration;                   /* CallDuration */
static int hf_gprscdr_causeForRecClosing;         /* CauseForRecClosingV651 */
static int hf_gprscdr_diagnostics;                /* Diagnostics */
static int hf_gprscdr_recordSequenceNumber;       /* INTEGER */
static int hf_gprscdr_nodeID;                     /* NodeID */
static int hf_gprscdr_recordExtensions;           /* ManagementExtensions */
static int hf_gprscdr_localSequenceNumber;        /* LocalSequenceNumber */
static int hf_gprscdr_apnSelectionMode;           /* APNSelectionMode */
static int hf_gprscdr_servedMSISDN;               /* MSISDN */
static int hf_gprscdr_chargingCharacteristics;    /* ChargingCharacteristics */
static int hf_gprscdr_chChSelectionMode;          /* ChChSelectionMode */
static int hf_gprscdr_iMSsignalingContext;        /* NULL */
static int hf_gprscdr_externalChargingID;         /* OCTET_STRING */
static int hf_gprscdr_sgsnPLMNIdentifier;         /* PLMN_Id */
static int hf_gprscdr_servedIMEISV;               /* IMEI */
static int hf_gprscdr_rATType;                    /* RATType */
static int hf_gprscdr_mSTimeZone;                 /* MSTimeZone */
static int hf_gprscdr_userLocationInformation;    /* T_userLocationInformation */
static int hf_gprscdr_cAMELChargingInformation;   /* OCTET_STRING */
static int hf_gprscdr_recordType_01;              /* RecordType */
static int hf_gprscdr_causeForRecClosing_01;      /* CauseForRecClosing */
static int hf_gprscdr_userLocationInformation_01;  /* T_userLocationInformation_01 */
static int hf_gprscdr_pSFurnishChargingInformation;  /* PSFurnishChargingInformation */
static int hf_gprscdr_userLocationInformation_02;  /* T_userLocationInformation_02 */
static int hf_gprscdr_listOfServiceData;          /* SEQUENCE_OF_ChangeOfServiceConditionV651 */
static int hf_gprscdr_listOfServiceData_item;     /* ChangeOfServiceConditionV651 */
static int hf_gprscdr_userLocationInformation_03;  /* T_userLocationInformation_03 */
static int hf_gprscdr_listOfServiceData_01;       /* SEQUENCE_OF_ChangeOfServiceConditionV750 */
static int hf_gprscdr_listOfServiceData_item_01;  /* ChangeOfServiceConditionV750 */
static int hf_gprscdr_servedIMEI;                 /* IMEI */
static int hf_gprscdr_sgsnAddress_01;             /* GSNAddress */
static int hf_gprscdr_msNetworkCapability;        /* MSNetworkCapability */
static int hf_gprscdr_routingArea;                /* RoutingAreaCode */
static int hf_gprscdr_cellIdentifier;             /* CellId */
static int hf_gprscdr_ggsnAddressUsed;            /* GSNAddress */
static int hf_gprscdr_sgsnChange;                 /* SGSNChange */
static int hf_gprscdr_accessPointNameOI;          /* AccessPointNameOI */
static int hf_gprscdr_cAMELInformationPDP;        /* CAMELInformationPDP */
static int hf_gprscdr_rNCUnsentDownlinkVolume;    /* DataVolumeGPRS */
static int hf_gprscdr_serviceCentre;              /* AddressString */
static int hf_gprscdr_recordingEntity;            /* RecordingEntity */
static int hf_gprscdr_locationArea;               /* LocationAreaCode */
static int hf_gprscdr_messageReference;           /* MessageReference */
static int hf_gprscdr_eventTimeStamp;             /* TimeStamp */
static int hf_gprscdr_smsResult;                  /* SMSResult */
static int hf_gprscdr_destinationNumber;          /* SmsTpDestinationNumber */
static int hf_gprscdr_cAMELInformationSMS;        /* CAMELInformationSMS */
static int hf_gprscdr_qosRequested;               /* QoSInformation */
static int hf_gprscdr_qosNegotiated;              /* QoSInformation */
static int hf_gprscdr_dataVolumeGPRSUplink;       /* DataVolumeGPRS */
static int hf_gprscdr_dataVolumeGPRSDownlink;     /* DataVolumeGPRS */
static int hf_gprscdr_changeCondition;            /* ChangeConditionV651 */
static int hf_gprscdr_changeTime;                 /* TimeStamp */
static int hf_gprscdr_failureHandlingContinue;    /* FailureHandlingContinue */
static int hf_gprscdr_userLocationInformation_04;  /* T_userLocationInformation_04 */
static int hf_gprscdr_ratingGroup;                /* RatingGroupId */
static int hf_gprscdr_chargingRuleBaseName;       /* ChargingRuleBaseName */
static int hf_gprscdr_resultCode;                 /* ResultCode */
static int hf_gprscdr_timeOfFirstUsage;           /* TimeStamp */
static int hf_gprscdr_timeOfLastUsage;            /* TimeStamp */
static int hf_gprscdr_timeUsage;                  /* CallDuration */
static int hf_gprscdr_serviceConditionChange;     /* ServiceConditionChangeV651 */
static int hf_gprscdr_qoSInformationNeg;          /* QoSInformation */
static int hf_gprscdr_sgsn_Address;               /* GSNAddress */
static int hf_gprscdr_sGSNPLMNIdentifier;         /* PLMN_Id */
static int hf_gprscdr_datavolumeFBCUplink;        /* DataVolumeGPRS */
static int hf_gprscdr_datavolumeFBCDownlink;      /* DataVolumeGPRS */
static int hf_gprscdr_timeOfReport;               /* TimeStamp */
static int hf_gprscdr_serviceIdentifier;          /* ServiceIdentifier */
static int hf_gprscdr_serviceConditionChangeV750;  /* ServiceConditionChangeV750 */
static int hf_gprscdr_aFRecordInformation;        /* SEQUENCE_OF_AFRecordInformation */
static int hf_gprscdr_aFRecordInformation_item;   /* AFRecordInformation */
static int hf_gprscdr_userLocationInformation_05;  /* T_userLocationInformation_05 */
static int hf_gprscdr_eventBasedChargingInformation;  /* EventBasedChargingInformation */
static int hf_gprscdr_timeQuotaMechanism;         /* TimeQuotaMechanism */
static int hf_gprscdr_sgsnPDPRecord_01;           /* SGSNPDPRecord */
static int hf_gprscdr_ggsnPDPRecord_01;           /* GGSNPDPRecordV750 */
static int hf_gprscdr_sgsnSMORecord_01;           /* SGSNSMORecord */
static int hf_gprscdr_sgsnSMTRecord_01;           /* SGSNSMTRecord */
static int hf_gprscdr_sgsnMTLCSRecord;            /* SGSNMTLCSRecord */
static int hf_gprscdr_sgsnMOLCSRecord;            /* SGSNMOLCSRecord */
static int hf_gprscdr_sgsnNILCSRecord;            /* SGSNNILCSRecord */
static int hf_gprscdr_egsnPDPRecord_01;           /* EGSNPDPRecordV750 */
static int hf_gprscdr_sgsnMBMSRecord;             /* SGSNMBMSRecord */
static int hf_gprscdr_ggsnMBMSRecord;             /* GGSNMBMSRecord */
static int hf_gprscdr_sGWRecord;                  /* SGWRecord */
static int hf_gprscdr_pGWRecord;                  /* PGWRecord */
static int hf_gprscdr_gwMBMSRecord;               /* GWMBMSRecord */
static int hf_gprscdr_tDFRecord;                  /* TDFRecord */
static int hf_gprscdr_iPERecord;                  /* IPERecord */
static int hf_gprscdr_ePDGRecord;                 /* EPDGRecord */
static int hf_gprscdr_tWAGRecord;                 /* TWAGRecord */
static int hf_gprscdr_s_GWAddress;                /* GSNAddress */
static int hf_gprscdr_servingNodeAddress;         /* SEQUENCE_OF_GSNAddress */
static int hf_gprscdr_servingNodeAddress_item;    /* GSNAddress */
static int hf_gprscdr_pdpPDNType;                 /* PDPType */
static int hf_gprscdr_servedPDPPDNAddress;        /* PDPAddress */
static int hf_gprscdr_listOfTrafficVolumes_01;    /* SEQUENCE_OF_ChangeOfCharCondition */
static int hf_gprscdr_listOfTrafficVolumes_item_01;  /* ChangeOfCharCondition */
static int hf_gprscdr_servingNodePLMNIdentifier;  /* PLMN_Id */
static int hf_gprscdr_userLocationInformation_06;  /* T_userLocationInformation_06 */
static int hf_gprscdr_sGWChange;                  /* SGWChange */
static int hf_gprscdr_servingNodeType;            /* SEQUENCE_OF_ServingNodeType */
static int hf_gprscdr_servingNodeType_item;       /* ServingNodeType */
static int hf_gprscdr_p_GWAddressUsed;            /* GSNAddress */
static int hf_gprscdr_p_GWPLMNIdentifier;         /* PLMN_Id */
static int hf_gprscdr_startTime;                  /* TimeStamp */
static int hf_gprscdr_stopTime;                   /* TimeStamp */
static int hf_gprscdr_pDNConnectionChargingID;    /* ChargingID */
static int hf_gprscdr_iMSIunauthenticatedFlag;    /* NULL */
static int hf_gprscdr_userCSGInformation;         /* UserCSGInformation */
static int hf_gprscdr_servedPDPPDNAddressExt;     /* PDPAddress */
static int hf_gprscdr_lowPriorityIndicator;       /* NULL */
static int hf_gprscdr_dynamicAddressFlagExt;      /* DynamicAddressFlag */
static int hf_gprscdr_s_GWiPv6Address;            /* GSNAddress */
static int hf_gprscdr_servingNodeiPv6Address;     /* SEQUENCE_OF_GSNAddress */
static int hf_gprscdr_servingNodeiPv6Address_item;  /* GSNAddress */
static int hf_gprscdr_p_GWiPv6AddressUsed;        /* GSNAddress */
static int hf_gprscdr_retransmission;             /* NULL */
static int hf_gprscdr_userLocationInfoTime;       /* TimeStamp */
static int hf_gprscdr_cNOperatorSelectionEnt;     /* CNOperatorSelectionEntity */
static int hf_gprscdr_presenceReportingAreaInfo;  /* PresenceReportingAreaInfo */
static int hf_gprscdr_lastUserLocationInformation;  /* T_lastUserLocationInformation */
static int hf_gprscdr_lastMSTimeZone;             /* MSTimeZone */
static int hf_gprscdr_enhancedDiagnostics;        /* EnhancedDiagnostics */
static int hf_gprscdr_cPCIoTEPSOptimisationIndicator;  /* CPCIoTEPSOptimisationIndicator */
static int hf_gprscdr_uNIPDUCPOnlyFlag;           /* UNIPDUCPOnlyFlag */
static int hf_gprscdr_servingPLMNRateControl;     /* ServingPLMNRateControl */
static int hf_gprscdr_pDPPDNTypeExtension;        /* PDPPDNTypeExtension */
static int hf_gprscdr_mOExceptionDataCounter;     /* MOExceptionDataCounter */
static int hf_gprscdr_listOfRANSecondaryRATUsageReports;  /* SEQUENCE_OF_RANSecondaryRATUsageReport */
static int hf_gprscdr_listOfRANSecondaryRATUsageReports_item;  /* RANSecondaryRATUsageReport */
static int hf_gprscdr_pSCellInformation;          /* PSCellInformation */
static int hf_gprscdr_p_GWAddress;                /* GSNAddress */
static int hf_gprscdr_userLocationInformation_07;  /* T_userLocationInformation_07 */
static int hf_gprscdr_listOfServiceData_02;       /* SEQUENCE_OF_ChangeOfServiceCondition */
static int hf_gprscdr_listOfServiceData_item_02;  /* ChangeOfServiceCondition */
static int hf_gprscdr_servedMNNAI;                /* SubscriptionID */
static int hf_gprscdr_served3gpp2MEID;            /* OCTET_STRING */
static int hf_gprscdr_threeGPP2UserLocationInformation;  /* OCTET_STRING */
static int hf_gprscdr_tWANUserLocationInformation;  /* TWANUserLocationInfo */
static int hf_gprscdr_ePCQoSInformation;          /* EPCQoSInformation */
static int hf_gprscdr_lastUserLocationInformation_01;  /* T_lastUserLocationInformation_01 */
static int hf_gprscdr_nBIFOMMode;                 /* NBIFOMMode */
static int hf_gprscdr_nBIFOMSupport;              /* NBIFOMSupport */
static int hf_gprscdr_uWANUserLocationInformation;  /* UWANUserLocationInfo */
static int hf_gprscdr_sGiPtPTunnellingMethod;     /* SGiPtPTunnellingMethod */
static int hf_gprscdr_aPNRateControl;             /* APNRateControl */
static int hf_gprscdr_chargingPerIPCANSessionIndicator;  /* ChargingPerIPCANSessionIndicator */
static int hf_gprscdr_threeGPPPSDataOffStatus;    /* ThreeGPPPSDataOffStatus */
static int hf_gprscdr_sCSASAddress;               /* SCSASAddress */
static int hf_gprscdr_userLocationInformation_08;  /* OCTET_STRING */
static int hf_gprscdr_tDFAddress;                 /* GSNAddress */
static int hf_gprscdr_tDFiPv6AddressUsed;         /* GSNAddress */
static int hf_gprscdr_tDFPLMNIdentifier;          /* PLMN_Id */
static int hf_gprscdr_servedFixedSubsID;          /* FixedSubsID */
static int hf_gprscdr_accessLineIdentifier;       /* AccessLineIdentifier */
static int hf_gprscdr_fixedUserLocationInformation;  /* FixedUserLocationInformation */
static int hf_gprscdr_iPEdgeAddress;              /* GSNAddress */
static int hf_gprscdr_iPCANsessionType;           /* PDPType */
static int hf_gprscdr_servedIPCANsessionAddress;  /* PDPAddress */
static int hf_gprscdr_iPEdgeOperatorIdentifier;   /* PLMN_Id */
static int hf_gprscdr_servedIPCANsessionAddressExt;  /* PDPAddress */
static int hf_gprscdr_iPEdgeiPv6AddressUsed;      /* GSNAddress */
static int hf_gprscdr_ePDGAddressUsed;            /* GSNAddress */
static int hf_gprscdr_ePDGiPv6AddressUsed;        /* GSNAddress */
static int hf_gprscdr_tWAGAddressUsed;            /* GSNAddress */
static int hf_gprscdr_tWAGiPv6AddressUsed;        /* GSNAddress */
static int hf_gprscdr_changeLocation;             /* SEQUENCE_OF_ChangeLocation */
static int hf_gprscdr_changeLocation_item;        /* ChangeLocation */
static int hf_gprscdr_cAMELInformationMM;         /* CAMELInformationMM */
static int hf_gprscdr_cellPLMNId;                 /* PLMN_Id */
static int hf_gprscdr_servingNodeType_01;         /* ServingNodeType */
static int hf_gprscdr_servingNodeAddress_01;      /* GSNAddress */
static int hf_gprscdr_servingNodeiPv6Address_01;  /* GSNAddress */
static int hf_gprscdr_mMEName;                    /* DiameterIdentity */
static int hf_gprscdr_mMERealm;                   /* DiameterIdentity */
static int hf_gprscdr_originatingAddress;         /* AddressString */
static int hf_gprscdr_lcsClientType;              /* LCSClientType */
static int hf_gprscdr_lcsClientIdentity;          /* LCSClientIdentity */
static int hf_gprscdr_locationType;               /* LocationType */
static int hf_gprscdr_lcsQos;                     /* LCSQoSInfo */
static int hf_gprscdr_lcsPriority;                /* LCS_Priority */
static int hf_gprscdr_mlcNumber;                  /* ISDN_AddressString */
static int hf_gprscdr_measurementDuration;        /* CallDuration */
static int hf_gprscdr_notificationToMSUser;       /* NotificationToMSUser */
static int hf_gprscdr_privacyOverride;            /* NULL */
static int hf_gprscdr_location;                   /* LocationAreaAndCell */
static int hf_gprscdr_locationEstimate;           /* Ext_GeographicalInformation */
static int hf_gprscdr_positioningData;            /* PositioningData */
static int hf_gprscdr_lcsCause;                   /* LCSCause */
static int hf_gprscdr_locationMethod;             /* LocationMethod */
static int hf_gprscdr_listofRAs;                  /* SEQUENCE_OF_RAIdentity */
static int hf_gprscdr_listofRAs_item;             /* RAIdentity */
static int hf_gprscdr_listOfTrafficVolumes_02;    /* SEQUENCE_OF_ChangeOfMBMSCondition */
static int hf_gprscdr_listOfTrafficVolumes_item_02;  /* ChangeOfMBMSCondition */
static int hf_gprscdr_numberofReceivingUE;        /* INTEGER */
static int hf_gprscdr_mbmsInformation;            /* MBMSInformation */
static int hf_gprscdr_listofDownstreamNodes;      /* SEQUENCE_OF_GSNAddress */
static int hf_gprscdr_listofDownstreamNodes_item;  /* GSNAddress */
static int hf_gprscdr_mbmsGWAddress;              /* GSNAddress */
static int hf_gprscdr_commonTeid;                 /* CTEID */
static int hf_gprscdr_iPMulticastSourceAddress;   /* PDPAddress */
static int hf_gprscdr_physicalAccessID;           /* UTF8String */
static int hf_gprscdr_logicalAccessID;            /* OCTET_STRING */
static int hf_gprscdr_aFChargingIdentifier;       /* AFChargingIdentifier */
static int hf_gprscdr_flows;                      /* Flows */
static int hf_gprscdr_aPNRateControlUplink;       /* APNRateControlParameters */
static int hf_gprscdr_aPNRateControlDownlink;     /* APNRateControlParameters */
static int hf_gprscdr_additionalExceptionReports;  /* AdditionalExceptionReports */
static int hf_gprscdr_rateControlTimeUnit;        /* RateControlTimeUnit */
static int hf_gprscdr_rateControlMaxRate;         /* INTEGER */
static int hf_gprscdr_rateControlMaxMessageSize;  /* DataVolumeGPRS */
static int hf_gprscdr_called_Party_Address;       /* InvolvedParty */
static int hf_gprscdr_requested_Party_Address;    /* InvolvedParty */
static int hf_gprscdr_list_Of_Called_Asserted_Identity;  /* SEQUENCE_OF_InvolvedParty */
static int hf_gprscdr_list_Of_Called_Asserted_Identity_item;  /* InvolvedParty */
static int hf_gprscdr_sCFAddress;                 /* SCFAddress */
static int hf_gprscdr_serviceKey;                 /* ServiceKey */
static int hf_gprscdr_defaultTransactionHandling;  /* DefaultGPRS_Handling */
static int hf_gprscdr_numberOfDPEncountered;      /* NumberOfDPEncountered */
static int hf_gprscdr_levelOfCAMELService;        /* LevelOfCAMELService */
static int hf_gprscdr_freeFormatData;             /* FreeFormatData */
static int hf_gprscdr_fFDAppendIndicator;         /* FFDAppendIndicator */
static int hf_gprscdr_cAMELAccessPointNameNI;     /* CAMELAccessPointNameNI */
static int hf_gprscdr_cAMELAccessPointNameOI;     /* CAMELAccessPointNameOI */
static int hf_gprscdr_defaultSMSHandling;         /* DefaultSMS_Handling */
static int hf_gprscdr_cAMELCallingPartyNumber;    /* CallingNumber */
static int hf_gprscdr_cAMELDestinationSubscriberNumber;  /* SmsTpDestinationNumber */
static int hf_gprscdr_cAMELSMSCAddress;           /* AddressString */
static int hf_gprscdr_smsReferenceNumber;         /* CallReferenceNumber */
static int hf_gprscdr_changeCondition_01;         /* ChangeCondition */
static int hf_gprscdr_userLocationInformation_09;  /* T_userLocationInformation_08 */
static int hf_gprscdr_presenceReportingAreaStatus;  /* PresenceReportingAreaStatus */
static int hf_gprscdr_accessAvailabilityChangeReason;  /* AccessAvailabilityChangeReason */
static int hf_gprscdr_relatedChangeOfCharCondition;  /* RelatedChangeOfCharCondition */
static int hf_gprscdr_listOfPresenceReportingAreaInformation;  /* SEQUENCE_OF_PresenceReportingAreaInfo */
static int hf_gprscdr_listOfPresenceReportingAreaInformation_item;  /* PresenceReportingAreaInfo */
static int hf_gprscdr_dataVolumeMBMSUplink;       /* DataVolumeMBMS */
static int hf_gprscdr_dataVolumeMBMSDownlink;     /* DataVolumeMBMS */
static int hf_gprscdr_serviceConditionChange_01;  /* ServiceConditionChange */
static int hf_gprscdr_qoSInformationNeg_01;       /* EPCQoSInformation */
static int hf_gprscdr_userLocationInformation_10;  /* T_userLocationInformation_09 */
static int hf_gprscdr_serviceSpecificInfo;        /* SEQUENCE_OF_ServiceSpecificInfo */
static int hf_gprscdr_serviceSpecificInfo_item;   /* ServiceSpecificInfo */
static int hf_gprscdr_sponsorIdentity;            /* OCTET_STRING */
static int hf_gprscdr_applicationServiceProviderIdentity;  /* OCTET_STRING */
static int hf_gprscdr_aDCRuleBaseName;            /* ADCRuleBaseName */
static int hf_gprscdr_relatedChangeOfServiceCondition;  /* RelatedChangeOfServiceCondition */
static int hf_gprscdr_trafficSteeringPolicyIDDownlink;  /* TrafficSteeringPolicyIDDownlink */
static int hf_gprscdr_trafficSteeringPolicyIDUplink;  /* TrafficSteeringPolicyIDUplink */
static int hf_gprscdr_voLTEInformation;           /* VoLTEInformation */
static int hf_gprscdr_routingAreaCode;            /* RoutingAreaCode */
static int hf_gprscdr_mCC_MNC_01;                 /* PLMN_Id */
static int hf_gprscdr_qCI;                        /* INTEGER */
static int hf_gprscdr_maxRequestedBandwithUL;     /* INTEGER */
static int hf_gprscdr_maxRequestedBandwithDL;     /* INTEGER */
static int hf_gprscdr_guaranteedBitrateUL;        /* INTEGER */
static int hf_gprscdr_guaranteedBitrateDL;        /* INTEGER */
static int hf_gprscdr_aRP;                        /* T_aRP */
static int hf_gprscdr_aPNAggregateMaxBitrateUL;   /* INTEGER */
static int hf_gprscdr_aPNAggregateMaxBitrateDL;   /* INTEGER */
static int hf_gprscdr_extendedMaxRequestedBWUL;   /* INTEGER */
static int hf_gprscdr_extendedMaxRequestedBWDL;   /* INTEGER */
static int hf_gprscdr_extendedGBRUL;              /* INTEGER */
static int hf_gprscdr_extendedGBRDL;              /* INTEGER */
static int hf_gprscdr_extendedAPNAMBRUL;          /* INTEGER */
static int hf_gprscdr_extendedAPNAMBRDL;          /* INTEGER */
static int hf_gprscdr_numberOfEvents;             /* INTEGER */
static int hf_gprscdr_eventTimeStamps;            /* SEQUENCE_OF_TimeStamp */
static int hf_gprscdr_eventTimeStamps_item;       /* TimeStamp */
static int hf_gprscdr_sSID;                       /* OCTET_STRING */
static int hf_gprscdr_bSSID;                      /* OCTET_STRING */
static int hf_gprscdr_mediaComponentNumber;       /* INTEGER */
static int hf_gprscdr_flowNumber;                 /* T_flowNumber */
static int hf_gprscdr_flowNumber_item;            /* INTEGER */
static int hf_gprscdr_counterValue;               /* INTEGER */
static int hf_gprscdr_counterTimestamp;           /* TimeStamp */
static int hf_gprscdr_presenceReportingAreaIdentifier;  /* OCTET_STRING */
static int hf_gprscdr_presenceReportingAreaElementsList;  /* PresenceReportingAreaElementsList */
static int hf_gprscdr_presenceReportingAreaNode;  /* PresenceReportingAreaNode */
static int hf_gprscdr_pSFreeFormatData;           /* FreeFormatData */
static int hf_gprscdr_pSFFDAppendIndicator;       /* FFDAppendIndicator */
static int hf_gprscdr_dataVolumeUplink;           /* DataVolumeGPRS */
static int hf_gprscdr_dataVolumeDownlink;         /* DataVolumeGPRS */
static int hf_gprscdr_rANStartTime;               /* TimeStamp */
static int hf_gprscdr_rANEndTime;                 /* TimeStamp */
static int hf_gprscdr_secondaryRATType;           /* SecondaryRATType */
static int hf_gprscdr_userLocationInformation_11;  /* T_userLocationInformation_10 */
static int hf_gprscdr_userLocationInformation_12;  /* T_userLocationInformation_11 */
static int hf_gprscdr_relatedServiceConditionChange;  /* ServiceConditionChange */
static int hf_gprscdr_sPLMNDLRateControlValue;    /* INTEGER */
static int hf_gprscdr_sPLMNULRateControlValue;    /* INTEGER */
static int hf_gprscdr_timeQuotaType;              /* TimeQuotaType */
static int hf_gprscdr_baseTimeInterval;           /* INTEGER */
static int hf_gprscdr_civicAddressInformation;    /* CivicAddressInformation */
static int hf_gprscdr_wLANOperatorId;             /* WLANOperatorId */
static int hf_gprscdr_cSGId;                      /* CSGId */
static int hf_gprscdr_cSGAccessMode;              /* CSGAccessMode */
static int hf_gprscdr_cSGMembershipIndication;    /* NULL */
static int hf_gprscdr_uELocalIPAddress;           /* IPAddress */
static int hf_gprscdr_uDPSourcePort;              /* OCTET_STRING_SIZE_2 */
static int hf_gprscdr_tCPSourcePort;              /* OCTET_STRING_SIZE_2 */
static int hf_gprscdr_callerInformation;          /* SEQUENCE_OF_InvolvedParty */
static int hf_gprscdr_callerInformation_item;     /* InvolvedParty */
static int hf_gprscdr_calleeInformation;          /* CalleePartyInformation */
static int hf_gprscdr_wLANOperatorName;           /* OCTET_STRING */
static int hf_gprscdr_wLANPLMNId;                 /* PLMN_Id */
/* named bits */
static int hf_gprscdr_LevelOfCAMELService_basic;
static int hf_gprscdr_LevelOfCAMELService_callDurationSupervision;
static int hf_gprscdr_LevelOfCAMELService_onlineCharging;
static int hf_gprscdr_ServiceConditionChangeV651_qoSChange;
static int hf_gprscdr_ServiceConditionChangeV651_sGSNChange;
static int hf_gprscdr_ServiceConditionChangeV651_sGSNPLMNIDChange;
static int hf_gprscdr_ServiceConditionChangeV651_tariffTimeSwitch;
static int hf_gprscdr_ServiceConditionChangeV651_pDPContextRelease;
static int hf_gprscdr_ServiceConditionChangeV651_rATChange;
static int hf_gprscdr_ServiceConditionChangeV651_serviceIdledOut;
static int hf_gprscdr_ServiceConditionChangeV651_qCTExpiry;
static int hf_gprscdr_ServiceConditionChangeV651_configurationChange;
static int hf_gprscdr_ServiceConditionChangeV651_serviceStop;
static int hf_gprscdr_ServiceConditionChangeV651_timeThresholdReached;
static int hf_gprscdr_ServiceConditionChangeV651_volumeThresholdReached;
static int hf_gprscdr_ServiceConditionChangeV651_spare_bit12;
static int hf_gprscdr_ServiceConditionChangeV651_timeExhausted;
static int hf_gprscdr_ServiceConditionChangeV651_volumeExhausted;
static int hf_gprscdr_ServiceConditionChangeV651_timeout;
static int hf_gprscdr_ServiceConditionChangeV651_returnRequested;
static int hf_gprscdr_ServiceConditionChangeV651_reauthorisationRequest;
static int hf_gprscdr_ServiceConditionChangeV651_continueOngoingSession;
static int hf_gprscdr_ServiceConditionChangeV651_retryAndTerminateOngoingSession;
static int hf_gprscdr_ServiceConditionChangeV651_terminateOngoingSession;
static int hf_gprscdr_ServiceConditionChangeV750_qoSChange;
static int hf_gprscdr_ServiceConditionChangeV750_sGSNChange;
static int hf_gprscdr_ServiceConditionChangeV750_sGSNPLMNIDChange;
static int hf_gprscdr_ServiceConditionChangeV750_tariffTimeSwitch;
static int hf_gprscdr_ServiceConditionChangeV750_pDPContextRelease;
static int hf_gprscdr_ServiceConditionChangeV750_rATChange;
static int hf_gprscdr_ServiceConditionChangeV750_serviceIdledOut;
static int hf_gprscdr_ServiceConditionChangeV750_reserved;
static int hf_gprscdr_ServiceConditionChangeV750_configurationChange;
static int hf_gprscdr_ServiceConditionChangeV750_serviceStop;
static int hf_gprscdr_ServiceConditionChangeV750_dCCATimeThresholdReached;
static int hf_gprscdr_ServiceConditionChangeV750_dCCAVolumeThresholdReached;
static int hf_gprscdr_ServiceConditionChangeV750_dCCAServiceSpecificUnitThresholdReached;
static int hf_gprscdr_ServiceConditionChangeV750_dCCATimeExhausted;
static int hf_gprscdr_ServiceConditionChangeV750_dCCAVolumeExhausted;
static int hf_gprscdr_ServiceConditionChangeV750_dCCAValidityTimeout;
static int hf_gprscdr_ServiceConditionChangeV750_reserved2;
static int hf_gprscdr_ServiceConditionChangeV750_dCCAReauthorisationRequest;
static int hf_gprscdr_ServiceConditionChangeV750_dCCAContinueOngoingSession;
static int hf_gprscdr_ServiceConditionChangeV750_dCCARetryAndTerminateOngoingSession;
static int hf_gprscdr_ServiceConditionChangeV750_dCCATerminateOngoingSession;
static int hf_gprscdr_ServiceConditionChangeV750_cGI_SAIChange;
static int hf_gprscdr_ServiceConditionChangeV750_rAIChange;
static int hf_gprscdr_ServiceConditionChangeV750_dCCAServiceSpecificUnitExhausted;
static int hf_gprscdr_ServiceConditionChangeV750_recordClosure;
static int hf_gprscdr_ServiceConditionChangeV750_timeLimit;
static int hf_gprscdr_ServiceConditionChangeV750_volumeLimit;
static int hf_gprscdr_ServiceConditionChangeV750_serviceSpecificUnitLimit;
static int hf_gprscdr_ServiceConditionChangeV750_envelopeClosure;
static int hf_gprscdr_PresenceReportingAreaNode_oCS;
static int hf_gprscdr_PresenceReportingAreaNode_pCRF;
static int hf_gprscdr_ServiceConditionChange_qoSChange;
static int hf_gprscdr_ServiceConditionChange_sGSNChange;
static int hf_gprscdr_ServiceConditionChange_sGSNPLMNIDChange;
static int hf_gprscdr_ServiceConditionChange_tariffTimeSwitch;
static int hf_gprscdr_ServiceConditionChange_pDPContextRelease;
static int hf_gprscdr_ServiceConditionChange_rATChange;
static int hf_gprscdr_ServiceConditionChange_serviceIdledOut;
static int hf_gprscdr_ServiceConditionChange_reserved;
static int hf_gprscdr_ServiceConditionChange_configurationChange;
static int hf_gprscdr_ServiceConditionChange_serviceStop;
static int hf_gprscdr_ServiceConditionChange_dCCATimeThresholdReached;
static int hf_gprscdr_ServiceConditionChange_dCCAVolumeThresholdReached;
static int hf_gprscdr_ServiceConditionChange_dCCAServiceSpecificUnitThresholdReached;
static int hf_gprscdr_ServiceConditionChange_dCCATimeExhausted;
static int hf_gprscdr_ServiceConditionChange_dCCAVolumeExhausted;
static int hf_gprscdr_ServiceConditionChange_dCCAValidityTimeout;
static int hf_gprscdr_ServiceConditionChange_reserved1;
static int hf_gprscdr_ServiceConditionChange_dCCAReauthorisationRequest;
static int hf_gprscdr_ServiceConditionChange_dCCAContinueOngoingSession;
static int hf_gprscdr_ServiceConditionChange_dCCARetryAndTerminateOngoingSession;
static int hf_gprscdr_ServiceConditionChange_dCCATerminateOngoingSession;
static int hf_gprscdr_ServiceConditionChange_cGI_SAIChange;
static int hf_gprscdr_ServiceConditionChange_rAIChange;
static int hf_gprscdr_ServiceConditionChange_dCCAServiceSpecificUnitExhausted;
static int hf_gprscdr_ServiceConditionChange_recordClosure;
static int hf_gprscdr_ServiceConditionChange_timeLimit;
static int hf_gprscdr_ServiceConditionChange_volumeLimit;
static int hf_gprscdr_ServiceConditionChange_serviceSpecificUnitLimit;
static int hf_gprscdr_ServiceConditionChange_envelopeClosure;
static int hf_gprscdr_ServiceConditionChange_eCGIChange;
static int hf_gprscdr_ServiceConditionChange_tAIChange;
static int hf_gprscdr_ServiceConditionChange_userLocationChange;
static int hf_gprscdr_ServiceConditionChange_userCSGInformationChange;
static int hf_gprscdr_ServiceConditionChange_presenceInPRAChange;
static int hf_gprscdr_ServiceConditionChange_accessChangeOfSDF;
static int hf_gprscdr_ServiceConditionChange_indirectServiceConditionChange;
static int hf_gprscdr_ServiceConditionChange_servingPLMNRateControlChange;
static int hf_gprscdr_ServiceConditionChange_aPNRateControlChange;

static int ett_gprscdr;
static int ett_gprscdr_timestamp;
static int ett_gprscdr_plmn_id;
static int ett_gprscdr_pdp_pdn_type;
static int ett_gprscdr_eps_qos_arp;
static int ett_gprscdr_managementextension_information;
static int ett_gprscdr_userlocationinformation;
static int ett_gprscdr_Diagnostics;
static int ett_gprscdr_Ecgi;
static int ett_gprscdr_EnhancedDiagnostics;
static int ett_gprscdr_SEQUENCE_OF_RANNASCause;
static int ett_gprscdr_InvolvedParty;
static int ett_gprscdr_IPAddress;
static int ett_gprscdr_IPBinaryAddress;
static int ett_gprscdr_IPBinV6AddressWithOrWithoutPrefixLength;
static int ett_gprscdr_IPBinV6AddressWithPrefixLength;
static int ett_gprscdr_IPTextRepresentedAddress;
static int ett_gprscdr_LCSClientIdentity;
static int ett_gprscdr_LevelOfCAMELService;
static int ett_gprscdr_LocationAreaAndCell;
static int ett_gprscdr_ManagementExtensions;
static int ett_gprscdr_MBMSInformation;
static int ett_gprscdr_Ncgi;
static int ett_gprscdr_PDPAddress;
static int ett_gprscdr_PSCellInformation;
static int ett_gprscdr_SCSASAddress;
static int ett_gprscdr_ServiceSpecificInfo;
static int ett_gprscdr_SubscriptionID;
static int ett_gprscdr_ManagementExtension;
static int ett_gprscdr_GPRSCallEventRecord;
static int ett_gprscdr_GGSNPDPRecord;
static int ett_gprscdr_SEQUENCE_OF_GSNAddress;
static int ett_gprscdr_SEQUENCE_OF_ChangeOfCharConditionV651;
static int ett_gprscdr_GGSNPDPRecordV750;
static int ett_gprscdr_EGSNPDPRecord;
static int ett_gprscdr_SEQUENCE_OF_ChangeOfServiceConditionV651;
static int ett_gprscdr_EGSNPDPRecordV750;
static int ett_gprscdr_SEQUENCE_OF_ChangeOfServiceConditionV750;
static int ett_gprscdr_SGSNPDPRecordV651;
static int ett_gprscdr_SGSNSMORecordV651;
static int ett_gprscdr_SGSNSMTRecordV651;
static int ett_gprscdr_ChangeOfCharConditionV651;
static int ett_gprscdr_ChangeOfServiceConditionV651;
static int ett_gprscdr_ChangeOfServiceConditionV750;
static int ett_gprscdr_SEQUENCE_OF_AFRecordInformation;
static int ett_gprscdr_ServiceConditionChangeV651;
static int ett_gprscdr_ServiceConditionChangeV750;
static int ett_gprscdr_GPRSRecord;
static int ett_gprscdr_SGWRecord;
static int ett_gprscdr_SEQUENCE_OF_ChangeOfCharCondition;
static int ett_gprscdr_SEQUENCE_OF_ServingNodeType;
static int ett_gprscdr_SEQUENCE_OF_RANSecondaryRATUsageReport;
static int ett_gprscdr_PGWRecord;
static int ett_gprscdr_SEQUENCE_OF_ChangeOfServiceCondition;
static int ett_gprscdr_TDFRecord;
static int ett_gprscdr_IPERecord;
static int ett_gprscdr_EPDGRecord;
static int ett_gprscdr_TWAGRecord;
static int ett_gprscdr_SGSNMMRecord;
static int ett_gprscdr_SEQUENCE_OF_ChangeLocation;
static int ett_gprscdr_SGSNPDPRecord;
static int ett_gprscdr_SGSNSMORecord;
static int ett_gprscdr_SGSNSMTRecord;
static int ett_gprscdr_SGSNMTLCSRecord;
static int ett_gprscdr_SGSNMOLCSRecord;
static int ett_gprscdr_SGSNNILCSRecord;
static int ett_gprscdr_SGSNMBMSRecord;
static int ett_gprscdr_SEQUENCE_OF_RAIdentity;
static int ett_gprscdr_SEQUENCE_OF_ChangeOfMBMSCondition;
static int ett_gprscdr_GGSNMBMSRecord;
static int ett_gprscdr_GWMBMSRecord;
static int ett_gprscdr_AccessLineIdentifier;
static int ett_gprscdr_AFRecordInformation;
static int ett_gprscdr_APNRateControl;
static int ett_gprscdr_APNRateControlParameters;
static int ett_gprscdr_CalleePartyInformation;
static int ett_gprscdr_SEQUENCE_OF_InvolvedParty;
static int ett_gprscdr_CAMELInformationMM;
static int ett_gprscdr_CAMELInformationPDP;
static int ett_gprscdr_CAMELInformationSMS;
static int ett_gprscdr_ChangeOfCharCondition;
static int ett_gprscdr_SEQUENCE_OF_PresenceReportingAreaInfo;
static int ett_gprscdr_ChangeOfMBMSCondition;
static int ett_gprscdr_ChangeOfServiceCondition;
static int ett_gprscdr_SEQUENCE_OF_ServiceSpecificInfo;
static int ett_gprscdr_ChangeLocation;
static int ett_gprscdr_EPCQoSInformation;
static int ett_gprscdr_EventBasedChargingInformation;
static int ett_gprscdr_SEQUENCE_OF_TimeStamp;
static int ett_gprscdr_FixedUserLocationInformation;
static int ett_gprscdr_Flows;
static int ett_gprscdr_T_flowNumber;
static int ett_gprscdr_MOExceptionDataCounter;
static int ett_gprscdr_PresenceReportingAreaInfo;
static int ett_gprscdr_PresenceReportingAreaNode;
static int ett_gprscdr_PSFurnishChargingInformation;
static int ett_gprscdr_RANSecondaryRATUsageReport;
static int ett_gprscdr_RelatedChangeOfCharCondition;
static int ett_gprscdr_RelatedChangeOfServiceCondition;
static int ett_gprscdr_ServiceConditionChange;
static int ett_gprscdr_ServingPLMNRateControl;
static int ett_gprscdr_TimeQuotaMechanism;
static int ett_gprscdr_TWANUserLocationInfo;
static int ett_gprscdr_UserCSGInformation;
static int ett_gprscdr_UWANUserLocationInfo;
static int ett_gprscdr_VoLTEInformation;
static int ett_gprscdr_WLANOperatorId;

static expert_field ei_gprscdr_not_dissected;
static expert_field ei_gprscdr_choice_not_found;

/* Global variables */
static const char *obj_id;

static const value_string gprscdr_daylight_saving_time_vals[] = {
    {0, "No adjustment"},
    {1, "+1 hour adjustment for Daylight Saving Time"},
    {2, "+2 hours adjustment for Daylight Saving Time"},
    {3, "Reserved"},
    {0, NULL}
};

/* 3GPP-RAT-Type
*  3GPP TS 29.061
*/
static const value_string gprscdr_rat_type_vals[] = {
    {0, "Reserved"},
    {1, "UTRAN"},
    {2, "GERAN"},
    {3, "WLAN"},
    {4, "GAN"},
    {5, "HSPA Evolution"},
    {6, "EUTRAN"},
    {7, "Virtual"},
    {8, "EUTRAN-NB-IoT"},
    {9, "LTE-M"},
    {10, "NR"},
    /* 11-100 Spare for future use TS 29.061 */
    {101, "IEEE 802.16e"},
    {102, "3GPP2 eHRPD"},
    {103, "3GPP2 HRPD"},
    /* 104-255 Spare for future use TS 29.061 */
    {0, NULL}
};

static int
dissect_gprscdr_uli(tvbuff_t *tvb _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int type) {
  proto_tree *ext_tree_uli;
  unsigned    length;

  length = tvb_reported_length(tvb);
  ext_tree_uli = proto_tree_add_subtree(tree, tvb, 0, length, ett_gprscdr_userlocationinformation, NULL, "UserLocationInformation");

  switch (type) {
  case 1:
      /* For GGSN/EGGSN-CDR,
       * this octet string is a 1:1 copy of the contents (i.e. starting with octet 4) of the
       * User Location Information (ULI) information element specified in 29.060, ch7.7.51.
       */
      dissect_gtp_uli(tvb, 0, actx->pinfo, ext_tree_uli, NULL);
      break;
  case 2:
      /* For SGW/PGW-CDR,
       * this octet string is a 1:1 copy of the contents (i.e. starting with octet 5) of the
       * User Location Information (ULI) information element specified in 29.274, ch8.21.
       */
      dissect_gtpv2_uli(tvb, actx->pinfo, ext_tree_uli, NULL, length, 0, 0, NULL);
      break;
  default:
      proto_tree_add_expert(ext_tree_uli, actx->pinfo, &ei_gprscdr_not_dissected, tvb, 0, length);
      break;
  }

  return length;
}



static int
dissect_gprscdr_BCDDirectoryNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_CallDuration(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string gprscdr_CallEventRecordType_vals[] = {
  {   0, "moCallRecord" },
  {   1, "mtCallRecord" },
  {   2, "roamingRecord" },
  {   3, "incGatewayRecord" },
  {   4, "outGatewayRecord" },
  {   5, "transitCallRecord" },
  {   6, "moSMSRecord" },
  {   7, "mtSMSRecord" },
  {   8, "moSMSIWRecord" },
  {   9, "mtSMSGWRecord" },
  {  10, "ssActionRecord" },
  {  11, "hlrIntRecord" },
  {  12, "locUpdateHLRRecord" },
  {  13, "locUpdateVLRRecord" },
  {  14, "commonEquipRecord" },
  {  15, "moTraceRecord" },
  {  16, "mtTraceRecord" },
  {  17, "termCAMELRecord" },
  {  18, "sgsnPDPRecord" },
  {  19, "ggsnPDPRecord" },
  {  20, "sgsnMMRecord" },
  {  21, "sgsnSMORecord" },
  {  22, "sgsnSMTRecord" },
  {  23, "mtLCSRecord" },
  {  24, "moLCSRecord" },
  {  25, "niLCSRecord" },
  {  26, "sgsnMtLCSRecord" },
  {  27, "sgsnMoLCSRecord" },
  {  28, "sgsnNiLCSRecord" },
  {  29, "mmO1SRecord" },
  {  30, "mmO4FRqRecord" },
  {  31, "mmO4FRsRecord" },
  {  32, "mmO4DRecord" },
  {  33, "mmO1DRecord" },
  {  34, "mmO4RRecord" },
  {  35, "mmO1RRecord" },
  {  36, "mmOMDRecord" },
  {  37, "mmR4FRecord" },
  {  38, "mmR1NRqRecord" },
  {  39, "mmR1NRsRecord" },
  {  40, "mmR1RtRecord" },
  {  42, "mmR1AFRecord" },
  {  43, "mmR4DRqRecord" },
  {  44, "mmR4DRsRecord" },
  {  45, "mmR1RRRecord" },
  {  46, "mmR4RRqRecord" },
  {  47, "mmR4RRsRecord" },
  {  48, "mmRMDRecord" },
  {  49, "mmFRecord" },
  {  50, "mmBx1SRecord" },
  {  51, "mmBx1VRecord" },
  {  52, "mmBx1URecord" },
  {  53, "mmBx1DRecord" },
  {  54, "mM7SRecord" },
  {  55, "mM7DRqRecord" },
  {  56, "mM7DRsRecord" },
  {  57, "mM7CRecord" },
  {  58, "mM7RRecord" },
  {  59, "mM7DRRqRecord" },
  {  60, "mM7DRRsRecord" },
  {  61, "mM7RRqRecord" },
  {  62, "mM7RRsRecord" },
  {  63, "s-CSCFRecord" },
  {  64, "p-CSCFRecord" },
  {  65, "i-CSCFRecord" },
  {  66, "mRFCRecord" },
  {  67, "mGCFRecord" },
  {  68, "bGCFRecord" },
  {  69, "aSRecord" },
  {  70, "egsnPDPRecord" },
  {  71, "lCSGMORecord" },
  {  72, "lCSRGMTRecord" },
  {  73, "lCSHGMTRecord" },
  {  74, "lCSVGMTRecord" },
  {  75, "lCSGNIRecord" },
  {  76, "sgsnMBMSRecord" },
  {  77, "ggsnMBMSRecord" },
  {  78, "subBMSCRecord" },
  {  79, "contentBMSCRecord" },
  {  80, "pPFRecord" },
  {  81, "cPFRecord" },
  { 0, NULL }
};


static int
dissect_gprscdr_CallEventRecordType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_CallingNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gprscdr_BCDDirectoryNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_CellId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string gprscdr_CauseForRecClosing_vals[] = {
  {   0, "normalRelease" },
  {   1, "partialRecord" },
  {   4, "abnormalRelease" },
  {   5, "cAMELInitCallRelease" },
  {  16, "volumeLimit" },
  {  17, "timeLimit" },
  {  18, "servingNodeChange" },
  {  19, "maxChangeCond" },
  {  20, "managementIntervention" },
  {  21, "intraSGSNIntersystemChange" },
  {  22, "rATChange" },
  {  23, "mSTimeZoneChange" },
  {  24, "sGSNPLMNIDChange" },
  {  25, "sGWChange" },
  {  26, "aPNAMBRChange" },
  {  27, "mOExceptionDataCounterReceipt" },
  {  52, "unauthorizedRequestingNetwork" },
  {  53, "unauthorizedLCSClient" },
  {  54, "positionMethodFailure" },
  {  58, "unknownOrUnreachableLCSClient" },
  {  59, "listofDownstreamNodeChange" },
  { 0, NULL }
};


static int
dissect_gprscdr_CauseForRecClosing(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_ChargingID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_CivicAddressInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string gprscdr_CNIPMulticastDistribution_vals[] = {
  {   0, "nO-IP-MULTICAST" },
  {   1, "iP-MULTICAST" },
  { 0, NULL }
};


static int
dissect_gprscdr_CNIPMulticastDistribution(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gprscdr_DynamicAddressFlag(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_gprscdr_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_T_identifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &obj_id);

  return offset;
}



static int
dissect_gprscdr_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_gprscdr_T_information(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  proto_tree *ext_tree;
  ext_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_gprscdr_managementextension_information, NULL, "Information");
  if (obj_id){
    offset=call_ber_oid_callback(obj_id, tvb, offset, actx->pinfo, ext_tree, NULL);
  }else{
    proto_tree_add_expert(ext_tree, actx->pinfo, &ei_gprscdr_not_dissected, tvb, offset, -1);
  }


  return offset;
}


static const ber_sequence_t ManagementExtension_sequence[] = {
  { &hf_gprscdr_identifier  , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_gprscdr_T_identifier },
  { &hf_gprscdr_significance, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_BOOLEAN },
  { &hf_gprscdr_information , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gprscdr_T_information },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ManagementExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ManagementExtension_sequence, hf_index, ett_gprscdr_ManagementExtension);

  return offset;
}


static const value_string gprscdr_Diagnostics_vals[] = {
  {   0, "gsm0408Cause" },
  {   1, "gsm0902MapErrorValue" },
  {   2, "itu-tQ767Cause" },
  {   3, "networkSpecificCause" },
  {   4, "manufacturerSpecificCause" },
  {   5, "positionMethodFailureCause" },
  {   6, "unauthorizedLCSClientCause" },
  {   7, "diameterResultCodeAndExperimentalResult" },
  { 0, NULL }
};

static const ber_choice_t Diagnostics_choice[] = {
  {   0, &hf_gprscdr_gsm0408Cause, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  {   1, &hf_gprscdr_gsm0902MapErrorValue, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  {   2, &hf_gprscdr_itu_tQ767Cause, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  {   3, &hf_gprscdr_networkSpecificCause, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtension },
  {   4, &hf_gprscdr_manufacturerSpecificCause, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtension },
  {   5, &hf_gprscdr_positionMethodFailureCause, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gsm_map_er_PositionMethodFailure_Diagnostic },
  {   6, &hf_gprscdr_unauthorizedLCSClientCause, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gsm_map_er_UnauthorizedLCSClient_Diagnostic },
  {   7, &hf_gprscdr_diameterResultCodeAndExperimentalResult, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_Diagnostics(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Diagnostics_choice, hf_index, ett_gprscdr_Diagnostics,
                                 NULL);

  return offset;
}



static int
dissect_gprscdr_DiameterIdentity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_PLMN_Id(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *parameter_tvb;
  proto_tree *subtree;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  subtree = proto_item_add_subtree(actx->created_item, ett_gprscdr_plmn_id);
  dissect_e212_mcc_mnc(parameter_tvb, actx->pinfo, subtree, 0, E212_NONE, true);


  return offset;
}



static int
dissect_gprscdr_EutraCellId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gprscdr_Nid(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t Ecgi_sequence[] = {
  { &hf_gprscdr_plmnId      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_eutraCellId , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_EutraCellId },
  { &hf_gprscdr_nid         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_Nid },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_Ecgi(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Ecgi_sequence, hf_index, ett_gprscdr_Ecgi);

  return offset;
}



static int
dissect_gprscdr_RANNASCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_RANNASCause_sequence_of[1] = {
  { &hf_gprscdr_rANNASCause_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_gprscdr_RANNASCause },
};

static int
dissect_gprscdr_SEQUENCE_OF_RANNASCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_RANNASCause_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_RANNASCause);

  return offset;
}


static const ber_sequence_t EnhancedDiagnostics_sequence[] = {
  { &hf_gprscdr_rANNASCause , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_RANNASCause },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_EnhancedDiagnostics(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EnhancedDiagnostics_sequence, hf_index, ett_gprscdr_EnhancedDiagnostics);

  return offset;
}



static int
dissect_gprscdr_IPBinV4Address(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_IPBinV6Address(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_PDPAddressPrefixLength(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t IPBinV6AddressWithPrefixLength_sequence[] = {
  { &hf_gprscdr_iPBinV6Address, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_gprscdr_IPBinV6Address },
  { &hf_gprscdr_pDPAddressPrefixLength, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_gprscdr_PDPAddressPrefixLength },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_IPBinV6AddressWithPrefixLength(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IPBinV6AddressWithPrefixLength_sequence, hf_index, ett_gprscdr_IPBinV6AddressWithPrefixLength);

  return offset;
}


static const value_string gprscdr_IPBinV6AddressWithOrWithoutPrefixLength_vals[] = {
  {   1, "iPBinV6Address" },
  {   4, "iPBinV6AddressWithPrefix" },
  { 0, NULL }
};

static const ber_choice_t IPBinV6AddressWithOrWithoutPrefixLength_choice[] = {
  {   1, &hf_gprscdr_iPBinV6Address, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_IPBinV6Address },
  {   4, &hf_gprscdr_iPBinV6AddressWithPrefix, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_gprscdr_IPBinV6AddressWithPrefixLength },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_IPBinV6AddressWithOrWithoutPrefixLength(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IPBinV6AddressWithOrWithoutPrefixLength_choice, hf_index, ett_gprscdr_IPBinV6AddressWithOrWithoutPrefixLength,
                                 NULL);

  return offset;
}


static const value_string gprscdr_IPBinaryAddress_vals[] = {
  {   0, "iPBinV4Address" },
  {   1, "iPBinV6Address" },
  { 0, NULL }
};

static const ber_choice_t IPBinaryAddress_choice[] = {
  {   0, &hf_gprscdr_iPBinV4Address, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_IPBinV4Address },
  {   1, &hf_gprscdr_iPBinV6Address_choice, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_gprscdr_IPBinV6AddressWithOrWithoutPrefixLength },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_IPBinaryAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IPBinaryAddress_choice, hf_index, ett_gprscdr_IPBinaryAddress,
                                 NULL);

  return offset;
}



static int
dissect_gprscdr_IA5String_SIZE_7_15(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gprscdr_IA5String_SIZE_15_45(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string gprscdr_IPTextRepresentedAddress_vals[] = {
  {   2, "iPTextV4Address" },
  {   3, "iPTextV6Address" },
  { 0, NULL }
};

static const ber_choice_t IPTextRepresentedAddress_choice[] = {
  {   2, &hf_gprscdr_iPTextV4Address, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gprscdr_IA5String_SIZE_7_15 },
  {   3, &hf_gprscdr_iPTextV6Address, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gprscdr_IA5String_SIZE_15_45 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_IPTextRepresentedAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IPTextRepresentedAddress_choice, hf_index, ett_gprscdr_IPTextRepresentedAddress,
                                 NULL);

  return offset;
}


static const value_string gprscdr_IPAddress_vals[] = {
  { -1/*choice*/, "iPBinaryAddress" },
  { -1/*choice*/, "iPTextRepresentedAddress" },
  { 0, NULL }
};

static const ber_choice_t IPAddress_choice[] = {
  { -1/*choice*/, &hf_gprscdr_iPBinaryAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_gprscdr_IPBinaryAddress },
  { -1/*choice*/, &hf_gprscdr_iPTextRepresentedAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_gprscdr_IPTextRepresentedAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_IPAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IPAddress_choice, hf_index, ett_gprscdr_IPAddress,
                                 NULL);

  return offset;
}



static int
dissect_gprscdr_GSNAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gprscdr_IPAddress(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_GraphicString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gprscdr_UTF8String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string gprscdr_InvolvedParty_vals[] = {
  {   0, "sIP-URI" },
  {   1, "tEL-URI" },
  {   2, "uRN" },
  {   3, "iSDN-E164" },
  {   4, "externalId" },
  { 0, NULL }
};

static const ber_choice_t InvolvedParty_choice[] = {
  {   0, &hf_gprscdr_sIP_URI     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_GraphicString },
  {   1, &hf_gprscdr_tEL_URI     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_GraphicString },
  {   2, &hf_gprscdr_uRN         , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gprscdr_GraphicString },
  {   3, &hf_gprscdr_iSDN_E164   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gprscdr_GraphicString },
  {   4, &hf_gprscdr_externalId  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_gprscdr_UTF8String },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_InvolvedParty(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 InvolvedParty_choice, hf_index, ett_gprscdr_InvolvedParty,
                                 NULL);

  return offset;
}



static int
dissect_gprscdr_LCSCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t LCSClientIdentity_sequence[] = {
  { &hf_gprscdr_lcsClientExternalID, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_LCSClientExternalID },
  { &hf_gprscdr_lcsClientDialedByMS, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_AddressString },
  { &hf_gprscdr_lcsClientInternalID, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_LCSClientInternalID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_LCSClientIdentity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LCSClientIdentity_sequence, hf_index, ett_gprscdr_LCSClientIdentity);

  return offset;
}



static int
dissect_gprscdr_LCSQoSInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static int * const LevelOfCAMELService_bits[] = {
  &hf_gprscdr_LevelOfCAMELService_basic,
  &hf_gprscdr_LevelOfCAMELService_callDurationSupervision,
  &hf_gprscdr_LevelOfCAMELService_onlineCharging,
  NULL
};

static int
dissect_gprscdr_LevelOfCAMELService(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    LevelOfCAMELService_bits, 3, hf_index, ett_gprscdr_LevelOfCAMELService,
                                    NULL);

  return offset;
}



static int
dissect_gprscdr_LocalSequenceNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_LocationAreaCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_MCC_MNC(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t LocationAreaAndCell_sequence[] = {
  { &hf_gprscdr_locationAreaCode, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_cellId      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_mCC_MNC     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MCC_MNC },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_LocationAreaAndCell(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   LocationAreaAndCell_sequence, hf_index, ett_gprscdr_LocationAreaAndCell);

  return offset;
}


static const ber_sequence_t ManagementExtensions_set_of[1] = {
  { &hf_gprscdr_ManagementExtensions_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ManagementExtension },
};

static int
dissect_gprscdr_ManagementExtensions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ManagementExtensions_set_of, hf_index, ett_gprscdr_ManagementExtensions);

  return offset;
}


static const value_string gprscdr_MBMS2G3GIndicator_vals[] = {
  {   0, "twoG" },
  {   1, "threeG" },
  {   2, "twoG-AND-threeG" },
  { 0, NULL }
};


static int
dissect_gprscdr_MBMS2G3GIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gprscdr_TMGI(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_MBMSSessionIdentity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string gprscdr_MBMSServiceType_vals[] = {
  {   0, "mULTICAST" },
  {   1, "bROADCAST" },
  { 0, NULL }
};


static int
dissect_gprscdr_MBMSServiceType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string gprscdr_MBMSUserServiceType_vals[] = {
  {   0, "dOWNLOAD" },
  {   1, "sTREAMING" },
  { 0, NULL }
};


static int
dissect_gprscdr_MBMSUserServiceType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gprscdr_RoutingAreaCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_MBMSServiceArea(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_RequiredMBMSBearerCapabilities(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_MBMSTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t MBMSInformation_set[] = {
  { &hf_gprscdr_tMGI        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TMGI },
  { &hf_gprscdr_mBMSSessionIdentity, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MBMSSessionIdentity },
  { &hf_gprscdr_mBMSServiceType, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MBMSServiceType },
  { &hf_gprscdr_mBMSUserServiceType, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MBMSUserServiceType },
  { &hf_gprscdr_mBMS2G3GIndicator, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MBMS2G3GIndicator },
  { &hf_gprscdr_fileRepairSupported, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_BOOLEAN },
  { &hf_gprscdr_rAI         , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_mBMSServiceArea, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MBMSServiceArea },
  { &hf_gprscdr_requiredMBMSBearerCaps, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RequiredMBMSBearerCapabilities },
  { &hf_gprscdr_mBMSGWAddress, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_cNIPMulticastDistribution, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CNIPMulticastDistribution },
  { &hf_gprscdr_mBMSDataTransferStart, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MBMSTime },
  { &hf_gprscdr_mBMSDataTransferStop, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MBMSTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_MBMSInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              MBMSInformation_set, hf_index, ett_gprscdr_MBMSInformation);

  return offset;
}



static int
dissect_gprscdr_MessageReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_MSISDN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gsm_map_ISDN_AddressString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_MSTimeZone(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/*
 *
 * 1.Octet: Time Zone and 2. Octet: Daylight saving time, see TS 29.060 [75]
 */
  tvbuff_t *parameter_tvb;
  uint8_t data, data2;
  char sign;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  data = tvb_get_uint8(parameter_tvb, 0);
  sign = (data & 0x08) ? '-' : '+';
  data = (data >> 4) + (data & 0x07) * 10;

  data2 = tvb_get_uint8(tvb, 1) & 0x3;

  proto_item_append_text(actx->created_item, " (GMT %c %d hours %d minutes %s)",
                         sign,
                         data / 4,
                         data % 4 * 15,
                         val_to_str_const(data2, gprscdr_daylight_saving_time_vals, "Unknown")
                        );


  return offset;
}



static int
dissect_gprscdr_NrCellId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t Ncgi_sequence[] = {
  { &hf_gprscdr_plmnId      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_nrCellId    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_NrCellId },
  { &hf_gprscdr_nid         , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_Nid },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_Ncgi(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Ncgi_sequence, hf_index, ett_gprscdr_Ncgi);

  return offset;
}



static int
dissect_gprscdr_NodeID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string gprscdr_PDPAddress_vals[] = {
  {   0, "iPAddress" },
  { 0, NULL }
};

static const ber_choice_t PDPAddress_choice[] = {
  {   0, &hf_gprscdr_iPAddress   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_IPAddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_PDPAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PDPAddress_choice, hf_index, ett_gprscdr_PDPAddress,
                                 NULL);

  return offset;
}



static int
dissect_gprscdr_PositioningData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t PSCellInformation_sequence[] = {
  { &hf_gprscdr_nRcgi       , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_Ncgi },
  { &hf_gprscdr_ecgi        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_Ecgi },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_PSCellInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PSCellInformation_sequence, hf_index, ett_gprscdr_PSCellInformation);

  return offset;
}



static int
dissect_gprscdr_RATType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_RecordingEntity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gsm_map_AddressString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string gprscdr_RecordType_vals[] = {
  {   0, "moCallRecord" },
  {   1, "mtCallRecord" },
  {   2, "roamingRecord" },
  {   3, "incGatewayRecord" },
  {   4, "outGatewayRecord" },
  {   5, "transitCallRecord" },
  {   6, "moSMSRecord" },
  {   7, "mtSMSRecord" },
  {   8, "moSMSIWRecord" },
  {   9, "mtSMSGWRecord" },
  {  10, "ssActionRecord" },
  {  11, "hlrIntRecord" },
  {  12, "locUpdateHLRRecord" },
  {  13, "locUpdateVLRRecord" },
  {  14, "commonEquipRecord" },
  {  15, "moTraceRecord" },
  {  16, "mtTraceRecord" },
  {  17, "termCAMELRecord" },
  {  18, "sgsnPDPRecord" },
  {  20, "sgsnMMRecord" },
  {  21, "sgsnSMORecord" },
  {  22, "sgsnSMTRecord" },
  {  23, "mtLCSRecord" },
  {  24, "moLCSRecord" },
  {  25, "niLCSRecord" },
  {  26, "sgsnMTLCSRecord" },
  {  27, "sgsnMOLCSRecord" },
  {  28, "sgsnNILCSRecord" },
  {  30, "mMO1SRecord" },
  {  31, "mMO4FRqRecord" },
  {  32, "mMO4FRsRecord" },
  {  33, "mMO4DRecord" },
  {  34, "mMO1DRecord" },
  {  35, "mMO4RRecord" },
  {  36, "mMO1RRecord" },
  {  37, "mMOMDRecord" },
  {  38, "mMR4FRecord" },
  {  39, "mMR1NRqRecord" },
  {  40, "mMR1NRsRecord" },
  {  41, "mMR1RtRecord" },
  {  42, "mMR1AFRecord" },
  {  43, "mMR4DRqRecord" },
  {  44, "mMR4DRsRecord" },
  {  45, "mMR1RRRecord" },
  {  46, "mMR4RRqRecord" },
  {  47, "mMR4RRsRecord" },
  {  48, "mMRMDRecord" },
  {  49, "mMFRecord" },
  {  50, "mMBx1SRecord" },
  {  51, "mMBx1VRecord" },
  {  52, "mMBx1URecord" },
  {  53, "mMBx1DRecord" },
  {  54, "mM7SRecord" },
  {  55, "mM7DRqRecord" },
  {  56, "mM7DRsRecord" },
  {  57, "mM7CRecord" },
  {  58, "mM7RRecord" },
  {  59, "mM7DRRqRecord" },
  {  60, "mM7DRRsRecord" },
  {  61, "mM7RRqRecord" },
  {  62, "mM7RRsRecord" },
  {  63, "sCSCFRecord" },
  {  64, "pCSCFRecord" },
  {  65, "iCSCFRecord" },
  {  66, "mRFCRecord" },
  {  67, "mGCFRecord" },
  {  68, "bGCFRecord" },
  {  69, "aSRecord" },
  {  70, "eCSCFRecord" },
  {  82, "iBCFRecord" },
  {  89, "tRFRecord" },
  {  90, "tFRecord" },
  {  91, "aTCFRecord" },
  {  71, "lCSGMORecord" },
  {  72, "lCSRGMTRecord" },
  {  73, "lCSHGMTRecord" },
  {  74, "lCSVGMTRecord" },
  {  75, "lCSGNIRecord" },
  {  76, "sgsnMBMSRecord" },
  {  77, "ggsnMBMSRecord" },
  {  86, "gwMBMSRecord" },
  {  78, "sUBBMSCRecord" },
  {  79, "cONTENTBMSCRecord" },
  {  80, "pPFRecord" },
  {  81, "cPFRecord" },
  {  84, "sGWRecord" },
  {  85, "pGWRecord" },
  {  92, "tDFRecord" },
  {  95, "iPERecord" },
  {  96, "ePDGRecord" },
  {  97, "tWAGRecord" },
  {  83, "mMTelRecord" },
  {  87, "mSCsRVCCRecord" },
  {  88, "mMTRFRecord" },
  {  99, "iCSRegisterRecord" },
  {  93, "sCSMORecord" },
  {  94, "sCSMTRecord" },
  { 100, "pFDDRecord" },
  { 101, "pFEDRecord" },
  { 102, "pFDCRecord" },
  { 103, "mECORecord" },
  { 104, "mERERecord" },
  { 105, "cPDTSCERecord" },
  { 106, "cPDTSNNRecord" },
  { 110, "sCDVTT4Record" },
  { 111, "sCSMOT4Record" },
  { 112, "iSMSMORecord" },
  { 113, "iSMSMTRecord" },
  { 120, "eASCERecord" },
  { 200, "chargingFunctionRecord" },
  { 0, NULL }
};


static int
dissect_gprscdr_RecordType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t SCSASAddress_set[] = {
  { &hf_gprscdr_sCSAddress  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_IPAddress },
  { &hf_gprscdr_sCSRealm    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gprscdr_DiameterIdentity },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SCSASAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SCSASAddress_set, hf_index, ett_gprscdr_SCSASAddress);

  return offset;
}


static const ber_sequence_t ServiceSpecificInfo_sequence[] = {
  { &hf_gprscdr_serviceSpecificData, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_GraphicString },
  { &hf_gprscdr_serviceSpecificType, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ServiceSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceSpecificInfo_sequence, hf_index, ett_gprscdr_ServiceSpecificInfo);

  return offset;
}



static int
dissect_gprscdr_SMSResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gprscdr_Diagnostics(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_SmsTpDestinationNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string gprscdr_SubscriptionIDType_vals[] = {
  {   0, "eND-USER-E164" },
  {   1, "eND-USER-IMSI" },
  {   2, "eND-USER-SIP-URI" },
  {   3, "eND-USER-NAI" },
  {   4, "eND-USER-PRIVATE" },
  { 0, NULL }
};


static int
dissect_gprscdr_SubscriptionIDType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SubscriptionID_set[] = {
  { &hf_gprscdr_subscriptionIDType, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_SubscriptionIDType },
  { &hf_gprscdr_subscriptionIDData, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_UTF8String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SubscriptionID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SubscriptionID_set, hf_index, ett_gprscdr_SubscriptionID);

  return offset;
}


static const value_string gprscdr_ThreeGPPPSDataOffStatus_vals[] = {
  {   0, "active" },
  {   1, "inactive" },
  { 0, NULL }
};


static int
dissect_gprscdr_ThreeGPPPSDataOffStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gprscdr_TimeStamp(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
/*
 *
 * The contents of this field are a compact form of the UTCTime format
 * containing local time plus an offset to universal time. Binary coded
 * decimal encoding is employed for the digits to reduce the storage and
 * transmission overhead
 * e.g. YYMMDDhhmmssShhmm
 * where
 * YY   =       Year 00 to 99           BCD encoded
 * MM   =       Month 01 to 12          BCD encoded
 * DD   =       Day 01 to 31            BCD encoded
 * hh   =       hour 00 to 23           BCD encoded
 * mm   =       minute 00 to 59         BCD encoded
 * ss   =       second 00 to 59         BCD encoded
 * S    =       Sign 0 = "+", "-"       ASCII encoded
 * hh   =       hour 00 to 23           BCD encoded
 * mm   =       minute 00 to 59         BCD encoded
 */

 tvbuff_t *parameter_tvb;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &parameter_tvb);


  if (!parameter_tvb)
    return offset;

  proto_item_append_text(actx->created_item, " (UTC %x-%x-%x %x:%x:%x %s%x:%x)",
                         tvb_get_uint8(parameter_tvb,0),                        /* Year */
                         tvb_get_uint8(parameter_tvb,1),                        /* Month */
                         tvb_get_uint8(parameter_tvb,2),                        /* Day */
                         tvb_get_uint8(parameter_tvb,3),                        /* Hour */
                         tvb_get_uint8(parameter_tvb,4),                        /* Minute */
                         tvb_get_uint8(parameter_tvb,5),                        /* Second */
                         tvb_get_string_enc(actx->pinfo->pool, parameter_tvb,6,1,ENC_ASCII|ENC_NA), /* Sign */
                         tvb_get_uint8(parameter_tvb,7),                        /* Hour */
                         tvb_get_uint8(parameter_tvb,8)                         /* Minute */
                        );


  return offset;
}



static int
dissect_gprscdr_NetworkInitiatedPDPContext(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_gprscdr_MSNetworkCapability(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_AccessPointNameNI(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gprscdr_PDPType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  proto_tree *ext_tree_pdp_pdn_type;
  unsigned length;

  length = tvb_reported_length(tvb);

  if(length == 1) {
    /*
     * PDN/EPS Bearer
     * TS 29.274
     * 8.34 PDN Type
     */
    ext_tree_pdp_pdn_type = proto_tree_add_subtree(tree, tvb, 0, length, ett_gprscdr_pdp_pdn_type, NULL, "pDNType");
    dissect_gtpv2_pdn_type(tvb, actx->pinfo, ext_tree_pdp_pdn_type, NULL, length, 0, 0, NULL);
    offset = length;
  }
  else {
    /* PDP context
     * TS 29.060
     * 7.7.27 End User Address
     * Octet 4-5
     */
    ext_tree_pdp_pdn_type = proto_tree_add_subtree(tree, tvb, 0, length, ett_gprscdr_pdp_pdn_type, NULL, "pDPType");
    offset = de_sm_pdp_addr(tvb, ext_tree_pdp_pdn_type, actx->pinfo, 0, length, NULL, 0);
  }



  return offset;
}



static int
dissect_gprscdr_QoSInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  /* This octet string is a 1:1 copy of the contents (i.e. starting with octet 4) of the
   * Quality of Service (QoS) Profile information element specified in 29.060, ch7.7.34.
   *
   */

  header_field_info *hfi;
  hfi = proto_registrar_get_nth(hf_index);

  offset = decode_qos_umts(tvb, 0, actx->pinfo, tree, hfi->name, 0);


  return offset;
}



static int
dissect_gprscdr_DataVolumeGPRS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string gprscdr_ChangeConditionV651_vals[] = {
  {   0, "qoSChange" },
  {   1, "tariffTime" },
  {   2, "recordClosure" },
  {   3, "failureHandlingContinueOngoing" },
  {   4, "failureHandlingRetryandTerminateOngoing" },
  {   5, "failureHandlingTerminateOngoing" },
  {   6, "cGI-SAICHange" },
  {   7, "rAIChange" },
  {   8, "dT-Establishment" },
  {   9, "dT-Removal" },
  { 0, NULL }
};


static int
dissect_gprscdr_ChangeConditionV651(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gprscdr_FailureHandlingContinue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_gprscdr_T_userLocationInformation_04(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 1);


  return offset;
}


static const ber_sequence_t ChangeOfCharConditionV651_sequence[] = {
  { &hf_gprscdr_qosRequested, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_QoSInformation },
  { &hf_gprscdr_qosNegotiated, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_QoSInformation },
  { &hf_gprscdr_dataVolumeGPRSUplink, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_dataVolumeGPRSDownlink, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_changeCondition, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChangeConditionV651 },
  { &hf_gprscdr_changeTime  , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_failureHandlingContinue, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FailureHandlingContinue },
  { &hf_gprscdr_userLocationInformation_04, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_userLocationInformation_04 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ChangeOfCharConditionV651(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChangeOfCharConditionV651_sequence, hf_index, ett_gprscdr_ChangeOfCharConditionV651);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ChangeOfCharConditionV651_sequence_of[1] = {
  { &hf_gprscdr_listOfTrafficVolumes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ChangeOfCharConditionV651 },
};

static int
dissect_gprscdr_SEQUENCE_OF_ChangeOfCharConditionV651(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ChangeOfCharConditionV651_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_ChangeOfCharConditionV651);

  return offset;
}



static int
dissect_gprscdr_SGSNChange(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string gprscdr_CauseForRecClosingV651_vals[] = {
  {   0, "normalRelease" },
  {   4, "abnormalRelease" },
  {   5, "cAMELInitCallRelease" },
  {  16, "volumeLimit" },
  {  17, "timeLimit" },
  {  18, "sGSNChange" },
  {  19, "maxChangeCond" },
  {  20, "managementIntervention" },
  {  21, "intraSGSNIntersystemChange" },
  {  22, "rATChange" },
  {  23, "mSTimeZoneChange" },
  {  24, "sGSNPLMNIDChange" },
  {  52, "unauthorizedRequestingNetwork" },
  {  53, "unauthorizedLCSClient" },
  {  54, "positionMethodFailure" },
  {  58, "unknownOrUnreachableLCSClient" },
  {  59, "listofDownstreamNodeChange" },
  { 0, NULL }
};


static int
dissect_gprscdr_CauseForRecClosingV651(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string gprscdr_APNSelectionMode_vals[] = {
  {   0, "mSorNetworkProvidedSubscriptionVerified" },
  {   1, "mSProvidedSubscriptionNotVerified" },
  {   2, "networkProvidedSubscriptionNotVerified" },
  { 0, NULL }
};


static int
dissect_gprscdr_APNSelectionMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gprscdr_AccessPointNameOI(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gprscdr_ChargingCharacteristics(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_SCFAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gsm_map_AddressString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_CAMELAccessPointNameNI(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gprscdr_AccessPointNameNI(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_CAMELAccessPointNameOI(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_gprscdr_AccessPointNameOI(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_gprscdr_NumberOfDPEncountered(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_FreeFormatData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_FFDAppendIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t CAMELInformationPDP_set[] = {
  { &hf_gprscdr_sCFAddress  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SCFAddress },
  { &hf_gprscdr_serviceKey  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_ServiceKey },
  { &hf_gprscdr_defaultTransactionHandling, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_DefaultGPRS_Handling },
  { &hf_gprscdr_cAMELAccessPointNameNI, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELAccessPointNameNI },
  { &hf_gprscdr_cAMELAccessPointNameOI, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELAccessPointNameOI },
  { &hf_gprscdr_numberOfDPEncountered, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NumberOfDPEncountered },
  { &hf_gprscdr_levelOfCAMELService, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LevelOfCAMELService },
  { &hf_gprscdr_freeFormatData, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FreeFormatData },
  { &hf_gprscdr_fFDAppendIndicator, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FFDAppendIndicator },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_gprscdr_CAMELInformationPDP(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CAMELInformationPDP_set, hf_index, ett_gprscdr_CAMELInformationPDP);

  return offset;
}


static const value_string gprscdr_ChChSelectionMode_vals[] = {
  {   0, "servingNodeSupplied" },
  {   1, "subscriptionSpecific" },
  {   2, "aPNSpecific" },
  {   3, "homeDefault" },
  {   4, "roamingDefault" },
  {   5, "visitingDefault" },
  {   6, "fixedDefault" },
  { 0, NULL }
};


static int
dissect_gprscdr_ChChSelectionMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SGSNPDPRecordV651_set[] = {
  { &hf_gprscdr_recordType  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallEventRecordType },
  { &hf_gprscdr_networkInitiation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NetworkInitiatedPDPContext },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_sgsnAddress_01, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_msNetworkCapability, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSNetworkCapability },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_locationAreaCode, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_cellIdentifier, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_ggsnAddressUsed, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpType     , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPAddress, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_listOfTrafficVolumes, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharConditionV651 },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_sgsnChange  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNChange },
  { &hf_gprscdr_causeForRecClosing, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosingV651 },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_accessPointNameOI, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameOI },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_cAMELInformationPDP, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELInformationPDP },
  { &hf_gprscdr_rNCUnsentDownlinkVolume, BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNPDPRecordV651(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNPDPRecordV651_set, hf_index, ett_gprscdr_SGSNPDPRecordV651);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_GSNAddress_sequence_of[1] = {
  { &hf_gprscdr_sgsnAddress_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
};

static int
dissect_gprscdr_SEQUENCE_OF_GSNAddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_GSNAddress_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_GSNAddress);

  return offset;
}



static int
dissect_gprscdr_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_gprscdr_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_T_userLocationInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 1);


  return offset;
}


static const ber_sequence_t GGSNPDPRecord_set[] = {
  { &hf_gprscdr_recordType  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallEventRecordType },
  { &hf_gprscdr_networkInitiation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NetworkInitiatedPDPContext },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_ggsnAddress , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_sgsnAddress , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpType     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_listOfTrafficVolumes, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharConditionV651 },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosingV651 },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_iMSsignalingContext, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_externalChargingID, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_sgsnPLMNIdentifier, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_servedIMEISV, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_mSTimeZone  , BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSTimeZone },
  { &hf_gprscdr_userLocationInformation, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_userLocationInformation },
  { &hf_gprscdr_cAMELChargingInformation, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_GGSNPDPRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              GGSNPDPRecord_set, hf_index, ett_gprscdr_GGSNPDPRecord);

  return offset;
}


static const ber_sequence_t ChangeLocation_sequence[] = {
  { &hf_gprscdr_locationAreaCode, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_routingAreaCode, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_cellId      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_changeTime  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_mCC_MNC_01  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ChangeLocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChangeLocation_sequence, hf_index, ett_gprscdr_ChangeLocation);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ChangeLocation_sequence_of[1] = {
  { &hf_gprscdr_changeLocation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ChangeLocation },
};

static int
dissect_gprscdr_SEQUENCE_OF_ChangeLocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ChangeLocation_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_ChangeLocation);

  return offset;
}


static const ber_sequence_t CAMELInformationMM_set[] = {
  { &hf_gprscdr_sCFAddress  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SCFAddress },
  { &hf_gprscdr_serviceKey  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_ServiceKey },
  { &hf_gprscdr_defaultTransactionHandling, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_DefaultGPRS_Handling },
  { &hf_gprscdr_numberOfDPEncountered, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NumberOfDPEncountered },
  { &hf_gprscdr_levelOfCAMELService, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LevelOfCAMELService },
  { &hf_gprscdr_freeFormatData, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FreeFormatData },
  { &hf_gprscdr_fFDAppendIndicator, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FFDAppendIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_CAMELInformationMM(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CAMELInformationMM_set, hf_index, ett_gprscdr_CAMELInformationMM);

  return offset;
}


static const value_string gprscdr_CNOperatorSelectionEntity_vals[] = {
  {   0, "servCNSelectedbyUE" },
  {   1, "servCNSelectedbyNtw" },
  { 0, NULL }
};


static int
dissect_gprscdr_CNOperatorSelectionEntity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SGSNMMRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_sgsnAddress_01, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_msNetworkCapability, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSNetworkCapability },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_locationAreaCode, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_cellIdentifier, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_changeLocation, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeLocation },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_sgsnChange  , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNChange },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_cAMELInformationMM, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELInformationMM },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_cellPLMNId  , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_servingNodePLMNIdentifier, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_cNOperatorSelectionEnt, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CNOperatorSelectionEntity },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNMMRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNMMRecord_set, hf_index, ett_gprscdr_SGSNMMRecord);

  return offset;
}


static const ber_sequence_t CAMELInformationSMS_set[] = {
  { &hf_gprscdr_sCFAddress  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SCFAddress },
  { &hf_gprscdr_serviceKey  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_ServiceKey },
  { &hf_gprscdr_defaultSMSHandling, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_DefaultSMS_Handling },
  { &hf_gprscdr_cAMELCallingPartyNumber, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CallingNumber },
  { &hf_gprscdr_cAMELDestinationSubscriberNumber, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SmsTpDestinationNumber },
  { &hf_gprscdr_cAMELSMSCAddress, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_AddressString },
  { &hf_gprscdr_freeFormatData, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FreeFormatData },
  { &hf_gprscdr_smsReferenceNumber, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ch_CallReferenceNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_CAMELInformationSMS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              CAMELInformationSMS_set, hf_index, ett_gprscdr_CAMELInformationSMS);

  return offset;
}


static const ber_sequence_t SGSNSMORecordV651_set[] = {
  { &hf_gprscdr_recordType  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallEventRecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_msNetworkCapability, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSNetworkCapability },
  { &hf_gprscdr_serviceCentre, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_AddressString },
  { &hf_gprscdr_recordingEntity, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordingEntity },
  { &hf_gprscdr_locationArea, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_cellIdentifier, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_messageReference, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_gprscdr_MessageReference },
  { &hf_gprscdr_eventTimeStamp, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_smsResult   , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_SMSResult },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_destinationNumber, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SmsTpDestinationNumber },
  { &hf_gprscdr_cAMELInformationSMS, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELInformationSMS },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNSMORecordV651(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNSMORecordV651_set, hf_index, ett_gprscdr_SGSNSMORecordV651);

  return offset;
}


static const ber_sequence_t SGSNSMTRecordV651_set[] = {
  { &hf_gprscdr_recordType  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallEventRecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_msNetworkCapability, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSNetworkCapability },
  { &hf_gprscdr_serviceCentre, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_AddressString },
  { &hf_gprscdr_recordingEntity, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordingEntity },
  { &hf_gprscdr_locationArea, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_cellIdentifier, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_eventTimeStamp, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_smsResult   , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_SMSResult },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_cAMELInformationSMS, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELInformationSMS },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNSMTRecordV651(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNSMTRecordV651_set, hf_index, ett_gprscdr_SGSNSMTRecordV651);

  return offset;
}


static const ber_sequence_t PSFurnishChargingInformation_sequence[] = {
  { &hf_gprscdr_pSFreeFormatData, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_FreeFormatData },
  { &hf_gprscdr_pSFFDAppendIndicator, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FFDAppendIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_PSFurnishChargingInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PSFurnishChargingInformation_sequence, hf_index, ett_gprscdr_PSFurnishChargingInformation);

  return offset;
}



static int
dissect_gprscdr_T_userLocationInformation_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 1);


  return offset;
}



static int
dissect_gprscdr_RatingGroupId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_ChargingRuleBaseName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gprscdr_ResultCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static int * const ServiceConditionChangeV651_bits[] = {
  &hf_gprscdr_ServiceConditionChangeV651_qoSChange,
  &hf_gprscdr_ServiceConditionChangeV651_sGSNChange,
  &hf_gprscdr_ServiceConditionChangeV651_sGSNPLMNIDChange,
  &hf_gprscdr_ServiceConditionChangeV651_tariffTimeSwitch,
  &hf_gprscdr_ServiceConditionChangeV651_pDPContextRelease,
  &hf_gprscdr_ServiceConditionChangeV651_rATChange,
  &hf_gprscdr_ServiceConditionChangeV651_serviceIdledOut,
  &hf_gprscdr_ServiceConditionChangeV651_qCTExpiry,
  &hf_gprscdr_ServiceConditionChangeV651_configurationChange,
  &hf_gprscdr_ServiceConditionChangeV651_serviceStop,
  &hf_gprscdr_ServiceConditionChangeV651_timeThresholdReached,
  &hf_gprscdr_ServiceConditionChangeV651_volumeThresholdReached,
  &hf_gprscdr_ServiceConditionChangeV651_spare_bit12,
  &hf_gprscdr_ServiceConditionChangeV651_timeExhausted,
  &hf_gprscdr_ServiceConditionChangeV651_volumeExhausted,
  &hf_gprscdr_ServiceConditionChangeV651_timeout,
  &hf_gprscdr_ServiceConditionChangeV651_returnRequested,
  &hf_gprscdr_ServiceConditionChangeV651_reauthorisationRequest,
  &hf_gprscdr_ServiceConditionChangeV651_continueOngoingSession,
  &hf_gprscdr_ServiceConditionChangeV651_retryAndTerminateOngoingSession,
  &hf_gprscdr_ServiceConditionChangeV651_terminateOngoingSession,
  NULL
};

static int
dissect_gprscdr_ServiceConditionChangeV651(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ServiceConditionChangeV651_bits, 21, hf_index, ett_gprscdr_ServiceConditionChangeV651,
                                    NULL);

  return offset;
}



static int
dissect_gprscdr_ServiceIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ChangeOfServiceConditionV651_sequence[] = {
  { &hf_gprscdr_ratingGroup , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_RatingGroupId },
  { &hf_gprscdr_chargingRuleBaseName, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingRuleBaseName },
  { &hf_gprscdr_resultCode  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ResultCode },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_timeOfFirstUsage, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_timeOfLastUsage, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_timeUsage   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_serviceConditionChange, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_gprscdr_ServiceConditionChangeV651 },
  { &hf_gprscdr_qoSInformationNeg, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_QoSInformation },
  { &hf_gprscdr_sgsn_Address, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_sGSNPLMNIdentifier, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_datavolumeFBCUplink, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_datavolumeFBCDownlink, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_timeOfReport, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_failureHandlingContinue, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FailureHandlingContinue },
  { &hf_gprscdr_serviceIdentifier, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ServiceIdentifier },
  { &hf_gprscdr_pSFurnishChargingInformation, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PSFurnishChargingInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ChangeOfServiceConditionV651(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChangeOfServiceConditionV651_sequence, hf_index, ett_gprscdr_ChangeOfServiceConditionV651);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ChangeOfServiceConditionV651_sequence_of[1] = {
  { &hf_gprscdr_listOfServiceData_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ChangeOfServiceConditionV651 },
};

static int
dissect_gprscdr_SEQUENCE_OF_ChangeOfServiceConditionV651(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ChangeOfServiceConditionV651_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_ChangeOfServiceConditionV651);

  return offset;
}


static const ber_sequence_t EGSNPDPRecord_set[] = {
  { &hf_gprscdr_recordType  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallEventRecordType },
  { &hf_gprscdr_networkInitiation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NetworkInitiatedPDPContext },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_ggsnAddress , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_sgsnAddress , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpType     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_listOfTrafficVolumes, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharConditionV651 },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosingV651 },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_iMSsignalingContext, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_externalChargingID, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_sgsnPLMNIdentifier, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_pSFurnishChargingInformation, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PSFurnishChargingInformation },
  { &hf_gprscdr_servedIMEISV, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_mSTimeZone  , BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSTimeZone },
  { &hf_gprscdr_userLocationInformation_02, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_userLocationInformation_02 },
  { &hf_gprscdr_cAMELChargingInformation, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_listOfServiceData, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfServiceConditionV651 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_EGSNPDPRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              EGSNPDPRecord_set, hf_index, ett_gprscdr_EGSNPDPRecord);

  return offset;
}


const value_string gprscdr_GPRSCallEventRecord_vals[] = {
  {  20, "sgsnPDPRecord" },
  {  21, "ggsnPDPRecord" },
  {  22, "sgsnMMRecord" },
  {  23, "sgsnSMORecord" },
  {  24, "sgsnSMTRecord" },
  {  28, "egsnPDPRecord" },
  { 0, NULL }
};

static const ber_choice_t GPRSCallEventRecord_choice[] = {
  {  20, &hf_gprscdr_sgsnPDPRecord, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNPDPRecordV651 },
  {  21, &hf_gprscdr_ggsnPDPRecord, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_gprscdr_GGSNPDPRecord },
  {  22, &hf_gprscdr_sgsnMMRecord, BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNMMRecord },
  {  23, &hf_gprscdr_sgsnSMORecord, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNSMORecordV651 },
  {  24, &hf_gprscdr_sgsnSMTRecord, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNSMTRecordV651 },
  {  28, &hf_gprscdr_egsnPDPRecord, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_gprscdr_EGSNPDPRecord },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_gprscdr_GPRSCallEventRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GPRSCallEventRecord_choice, hf_index, ett_gprscdr_GPRSCallEventRecord,
                                 NULL);

  return offset;
}



static int
dissect_gprscdr_T_userLocationInformation_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 1);


  return offset;
}


static const ber_sequence_t GGSNPDPRecordV750_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_networkInitiation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NetworkInitiatedPDPContext },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_ggsnAddress , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_sgsnAddress , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpType     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_listOfTrafficVolumes, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharConditionV651 },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_iMSsignalingContext, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_externalChargingID, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_sgsnPLMNIdentifier, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_servedIMEISV, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_mSTimeZone  , BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSTimeZone },
  { &hf_gprscdr_userLocationInformation_01, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_userLocationInformation_01 },
  { &hf_gprscdr_cAMELChargingInformation, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_GGSNPDPRecordV750(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              GGSNPDPRecordV750_set, hf_index, ett_gprscdr_GGSNPDPRecordV750);

  return offset;
}



static int
dissect_gprscdr_T_userLocationInformation_03(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 1);


  return offset;
}


static int * const ServiceConditionChangeV750_bits[] = {
  &hf_gprscdr_ServiceConditionChangeV750_qoSChange,
  &hf_gprscdr_ServiceConditionChangeV750_sGSNChange,
  &hf_gprscdr_ServiceConditionChangeV750_sGSNPLMNIDChange,
  &hf_gprscdr_ServiceConditionChangeV750_tariffTimeSwitch,
  &hf_gprscdr_ServiceConditionChangeV750_pDPContextRelease,
  &hf_gprscdr_ServiceConditionChangeV750_rATChange,
  &hf_gprscdr_ServiceConditionChangeV750_serviceIdledOut,
  &hf_gprscdr_ServiceConditionChangeV750_reserved,
  &hf_gprscdr_ServiceConditionChangeV750_configurationChange,
  &hf_gprscdr_ServiceConditionChangeV750_serviceStop,
  &hf_gprscdr_ServiceConditionChangeV750_dCCATimeThresholdReached,
  &hf_gprscdr_ServiceConditionChangeV750_dCCAVolumeThresholdReached,
  &hf_gprscdr_ServiceConditionChangeV750_dCCAServiceSpecificUnitThresholdReached,
  &hf_gprscdr_ServiceConditionChangeV750_dCCATimeExhausted,
  &hf_gprscdr_ServiceConditionChangeV750_dCCAVolumeExhausted,
  &hf_gprscdr_ServiceConditionChangeV750_dCCAValidityTimeout,
  &hf_gprscdr_ServiceConditionChangeV750_reserved2,
  &hf_gprscdr_ServiceConditionChangeV750_dCCAReauthorisationRequest,
  &hf_gprscdr_ServiceConditionChangeV750_dCCAContinueOngoingSession,
  &hf_gprscdr_ServiceConditionChangeV750_dCCARetryAndTerminateOngoingSession,
  &hf_gprscdr_ServiceConditionChangeV750_dCCATerminateOngoingSession,
  &hf_gprscdr_ServiceConditionChangeV750_cGI_SAIChange,
  &hf_gprscdr_ServiceConditionChangeV750_rAIChange,
  &hf_gprscdr_ServiceConditionChangeV750_dCCAServiceSpecificUnitExhausted,
  &hf_gprscdr_ServiceConditionChangeV750_recordClosure,
  &hf_gprscdr_ServiceConditionChangeV750_timeLimit,
  &hf_gprscdr_ServiceConditionChangeV750_volumeLimit,
  &hf_gprscdr_ServiceConditionChangeV750_serviceSpecificUnitLimit,
  &hf_gprscdr_ServiceConditionChangeV750_envelopeClosure,
  NULL
};

static int
dissect_gprscdr_ServiceConditionChangeV750(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ServiceConditionChangeV750_bits, 29, hf_index, ett_gprscdr_ServiceConditionChangeV750,
                                    NULL);

  return offset;
}



static int
dissect_gprscdr_AFChargingIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t T_flowNumber_sequence_of[1] = {
  { &hf_gprscdr_flowNumber_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_gprscdr_INTEGER },
};

static int
dissect_gprscdr_T_flowNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_flowNumber_sequence_of, hf_index, ett_gprscdr_T_flowNumber);

  return offset;
}


static const ber_sequence_t Flows_sequence[] = {
  { &hf_gprscdr_mediaComponentNumber, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_flowNumber  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_flowNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_Flows(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Flows_sequence, hf_index, ett_gprscdr_Flows);

  return offset;
}


static const ber_sequence_t AFRecordInformation_sequence[] = {
  { &hf_gprscdr_aFChargingIdentifier, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_AFChargingIdentifier },
  { &hf_gprscdr_flows       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_Flows },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_AFRecordInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AFRecordInformation_sequence, hf_index, ett_gprscdr_AFRecordInformation);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AFRecordInformation_sequence_of[1] = {
  { &hf_gprscdr_aFRecordInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_AFRecordInformation },
};

static int
dissect_gprscdr_SEQUENCE_OF_AFRecordInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AFRecordInformation_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_AFRecordInformation);

  return offset;
}



static int
dissect_gprscdr_T_userLocationInformation_05(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 1);


  return offset;
}


static const ber_sequence_t SEQUENCE_OF_TimeStamp_sequence_of[1] = {
  { &hf_gprscdr_eventTimeStamps_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_gprscdr_TimeStamp },
};

static int
dissect_gprscdr_SEQUENCE_OF_TimeStamp(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_TimeStamp_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_TimeStamp);

  return offset;
}


static const ber_sequence_t EventBasedChargingInformation_sequence[] = {
  { &hf_gprscdr_numberOfEvents, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_eventTimeStamps, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_TimeStamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_EventBasedChargingInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EventBasedChargingInformation_sequence, hf_index, ett_gprscdr_EventBasedChargingInformation);

  return offset;
}


static const value_string gprscdr_TimeQuotaType_vals[] = {
  {   0, "dISCRETETIMEPERIOD" },
  {   1, "cONTINUOUSTIMEPERIOD" },
  { 0, NULL }
};


static int
dissect_gprscdr_TimeQuotaType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t TimeQuotaMechanism_sequence[] = {
  { &hf_gprscdr_timeQuotaType, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeQuotaType },
  { &hf_gprscdr_baseTimeInterval, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_TimeQuotaMechanism(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TimeQuotaMechanism_sequence, hf_index, ett_gprscdr_TimeQuotaMechanism);

  return offset;
}


static const ber_sequence_t ChangeOfServiceConditionV750_sequence[] = {
  { &hf_gprscdr_ratingGroup , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_RatingGroupId },
  { &hf_gprscdr_chargingRuleBaseName, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingRuleBaseName },
  { &hf_gprscdr_resultCode  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ResultCode },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_timeOfFirstUsage, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_timeOfLastUsage, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_timeUsage   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_serviceConditionChangeV750, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_gprscdr_ServiceConditionChangeV750 },
  { &hf_gprscdr_qoSInformationNeg, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_QoSInformation },
  { &hf_gprscdr_sgsn_Address, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_sGSNPLMNIdentifier, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_datavolumeFBCUplink, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_datavolumeFBCDownlink, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_timeOfReport, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_failureHandlingContinue, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FailureHandlingContinue },
  { &hf_gprscdr_serviceIdentifier, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ServiceIdentifier },
  { &hf_gprscdr_pSFurnishChargingInformation, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PSFurnishChargingInformation },
  { &hf_gprscdr_aFRecordInformation, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_AFRecordInformation },
  { &hf_gprscdr_userLocationInformation_05, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_userLocationInformation_05 },
  { &hf_gprscdr_eventBasedChargingInformation, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_EventBasedChargingInformation },
  { &hf_gprscdr_timeQuotaMechanism, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeQuotaMechanism },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ChangeOfServiceConditionV750(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChangeOfServiceConditionV750_sequence, hf_index, ett_gprscdr_ChangeOfServiceConditionV750);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ChangeOfServiceConditionV750_sequence_of[1] = {
  { &hf_gprscdr_listOfServiceData_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ChangeOfServiceConditionV750 },
};

static int
dissect_gprscdr_SEQUENCE_OF_ChangeOfServiceConditionV750(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ChangeOfServiceConditionV750_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_ChangeOfServiceConditionV750);

  return offset;
}


static const ber_sequence_t EGSNPDPRecordV750_set[] = {
  { &hf_gprscdr_recordType  , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallEventRecordType },
  { &hf_gprscdr_networkInitiation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NetworkInitiatedPDPContext },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_ggsnAddress , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_sgsnAddress , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpType     , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_listOfTrafficVolumes, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharConditionV651 },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosingV651 },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_iMSsignalingContext, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_externalChargingID, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_sgsnPLMNIdentifier, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_pSFurnishChargingInformation, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PSFurnishChargingInformation },
  { &hf_gprscdr_servedIMEISV, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_mSTimeZone  , BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSTimeZone },
  { &hf_gprscdr_userLocationInformation_03, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_userLocationInformation_03 },
  { &hf_gprscdr_cAMELChargingInformation, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_listOfServiceData_01, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfServiceConditionV750 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_EGSNPDPRecordV750(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              EGSNPDPRecordV750_set, hf_index, ett_gprscdr_EGSNPDPRecordV750);

  return offset;
}


static const value_string gprscdr_ChangeCondition_vals[] = {
  {   0, "qoSChange" },
  {   1, "tariffTime" },
  {   2, "recordClosure" },
  {   3, "failureHandlingContinueOngoing" },
  {   4, "failureHandlingRetryandTerminateOngoing" },
  {   5, "failureHandlingTerminateOngoing" },
  {   6, "cGI-SAICHange" },
  {   7, "rAIChange" },
  {   8, "dT-Establishment" },
  {   9, "dT-Removal" },
  {  10, "eCGIChange" },
  {  11, "tAIChange" },
  {  12, "userLocationChange" },
  {  13, "userCSGInformationChange" },
  {  14, "presenceInPRAChange" },
  {  15, "removalOfAccess" },
  {  16, "unusabilityOfAccess" },
  {  17, "indirectChangeCondition" },
  {  18, "userPlaneToUEChange" },
  {  19, "servingPLMNRateControlChange" },
  {  20, "threeGPPPSDataOffStatusChange" },
  {  21, "aPNRateControlChange" },
  { 0, NULL }
};


static int
dissect_gprscdr_ChangeCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gprscdr_T_userLocationInformation_08(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 2);


  return offset;
}



static int
dissect_gprscdr_T_aRP(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  proto_tree *ext_tree_arp;
  unsigned length;

  /*
   * 8.86 Allocation/Retention Priority (ARP)
   * 3GPP TS 29.274
   */

  length = tvb_reported_length(tvb);
  ext_tree_arp = proto_tree_add_subtree(tree, tvb, 0, length, ett_gprscdr_eps_qos_arp, NULL, "aRP");

  dissect_gtpv2_arp(tvb, actx->pinfo, ext_tree_arp, NULL, length, 0, 0, NULL);

  offset = length;



  return offset;
}


static const ber_sequence_t EPCQoSInformation_sequence[] = {
  { &hf_gprscdr_qCI         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_maxRequestedBandwithUL, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_maxRequestedBandwithDL, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_guaranteedBitrateUL, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_guaranteedBitrateDL, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_aRP         , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_aRP },
  { &hf_gprscdr_aPNAggregateMaxBitrateUL, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_aPNAggregateMaxBitrateDL, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_extendedMaxRequestedBWUL, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_extendedMaxRequestedBWDL, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_extendedGBRUL, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_extendedGBRDL, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_extendedAPNAMBRUL, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_extendedAPNAMBRDL, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_EPCQoSInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EPCQoSInformation_sequence, hf_index, ett_gprscdr_EPCQoSInformation);

  return offset;
}


static const value_string gprscdr_PresenceReportingAreaStatus_vals[] = {
  {   0, "insideArea" },
  {   1, "outsideArea" },
  {   2, "inactive" },
  {   3, "unknown" },
  { 0, NULL }
};


static int
dissect_gprscdr_PresenceReportingAreaStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_gprscdr_CSGId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string gprscdr_CSGAccessMode_vals[] = {
  {   0, "closedMode" },
  {   1, "hybridMode" },
  { 0, NULL }
};


static int
dissect_gprscdr_CSGAccessMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t UserCSGInformation_sequence[] = {
  { &hf_gprscdr_cSGId       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_CSGId },
  { &hf_gprscdr_cSGAccessMode, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_CSGAccessMode },
  { &hf_gprscdr_cSGMembershipIndication, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_UserCSGInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UserCSGInformation_sequence, hf_index, ett_gprscdr_UserCSGInformation);

  return offset;
}



static int
dissect_gprscdr_AccessAvailabilityChangeReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_gprscdr_OCTET_STRING_SIZE_2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t WLANOperatorId_sequence[] = {
  { &hf_gprscdr_wLANOperatorName, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_wLANPLMNId  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_WLANOperatorId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   WLANOperatorId_sequence, hf_index, ett_gprscdr_WLANOperatorId);

  return offset;
}


static const ber_sequence_t UWANUserLocationInfo_sequence[] = {
  { &hf_gprscdr_uELocalIPAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_IPAddress },
  { &hf_gprscdr_uDPSourcePort, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING_SIZE_2 },
  { &hf_gprscdr_sSID        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_bSSID       , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_tCPSourcePort, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING_SIZE_2 },
  { &hf_gprscdr_civicAddressInformation, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CivicAddressInformation },
  { &hf_gprscdr_wLANOperatorId, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_WLANOperatorId },
  { &hf_gprscdr_logicalAccessID, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_UWANUserLocationInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UWANUserLocationInfo_sequence, hf_index, ett_gprscdr_UWANUserLocationInfo);

  return offset;
}



static int
dissect_gprscdr_T_userLocationInformation_10(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 2);


  return offset;
}


static const ber_sequence_t RelatedChangeOfCharCondition_sequence[] = {
  { &hf_gprscdr_changeCondition_01, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChangeCondition },
  { &hf_gprscdr_changeTime  , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_userLocationInformation_11, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_userLocationInformation_10 },
  { &hf_gprscdr_presenceReportingAreaStatus, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PresenceReportingAreaStatus },
  { &hf_gprscdr_userCSGInformation, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UserCSGInformation },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_uWANUserLocationInformation, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UWANUserLocationInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_RelatedChangeOfCharCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RelatedChangeOfCharCondition_sequence, hf_index, ett_gprscdr_RelatedChangeOfCharCondition);

  return offset;
}



static int
dissect_gprscdr_CPCIoTEPSOptimisationIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t ServingPLMNRateControl_sequence[] = {
  { &hf_gprscdr_sPLMNDLRateControlValue, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_sPLMNULRateControlValue, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ServingPLMNRateControl(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServingPLMNRateControl_sequence, hf_index, ett_gprscdr_ServingPLMNRateControl);

  return offset;
}



static int
dissect_gprscdr_PresenceReportingAreaElementsList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static int * const PresenceReportingAreaNode_bits[] = {
  &hf_gprscdr_PresenceReportingAreaNode_oCS,
  &hf_gprscdr_PresenceReportingAreaNode_pCRF,
  NULL
};

static int
dissect_gprscdr_PresenceReportingAreaNode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    PresenceReportingAreaNode_bits, 2, hf_index, ett_gprscdr_PresenceReportingAreaNode,
                                    NULL);

  return offset;
}


static const ber_sequence_t PresenceReportingAreaInfo_sequence[] = {
  { &hf_gprscdr_presenceReportingAreaIdentifier, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_presenceReportingAreaStatus, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PresenceReportingAreaStatus },
  { &hf_gprscdr_presenceReportingAreaElementsList, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PresenceReportingAreaElementsList },
  { &hf_gprscdr_presenceReportingAreaNode, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PresenceReportingAreaNode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_PresenceReportingAreaInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PresenceReportingAreaInfo_sequence, hf_index, ett_gprscdr_PresenceReportingAreaInfo);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_PresenceReportingAreaInfo_sequence_of[1] = {
  { &hf_gprscdr_listOfPresenceReportingAreaInformation_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_PresenceReportingAreaInfo },
};

static int
dissect_gprscdr_SEQUENCE_OF_PresenceReportingAreaInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_PresenceReportingAreaInfo_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_PresenceReportingAreaInfo);

  return offset;
}


static const value_string gprscdr_AdditionalExceptionReports_vals[] = {
  {   0, "notAllowed" },
  {   1, "allowed" },
  { 0, NULL }
};


static int
dissect_gprscdr_AdditionalExceptionReports(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string gprscdr_RateControlTimeUnit_vals[] = {
  {   0, "unrestricted" },
  {   1, "minute" },
  {   2, "hour" },
  {   3, "day" },
  {   4, "week" },
  { 0, NULL }
};


static int
dissect_gprscdr_RateControlTimeUnit(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t APNRateControlParameters_sequence[] = {
  { &hf_gprscdr_additionalExceptionReports, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AdditionalExceptionReports },
  { &hf_gprscdr_rateControlTimeUnit, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RateControlTimeUnit },
  { &hf_gprscdr_rateControlMaxRate, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_rateControlMaxMessageSize, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_APNRateControlParameters(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   APNRateControlParameters_sequence, hf_index, ett_gprscdr_APNRateControlParameters);

  return offset;
}


static const ber_sequence_t APNRateControl_sequence[] = {
  { &hf_gprscdr_aPNRateControlUplink, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNRateControlParameters },
  { &hf_gprscdr_aPNRateControlDownlink, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNRateControlParameters },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_APNRateControl(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   APNRateControl_sequence, hf_index, ett_gprscdr_APNRateControl);

  return offset;
}


static const ber_sequence_t ChangeOfCharCondition_sequence[] = {
  { &hf_gprscdr_qosRequested, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_QoSInformation },
  { &hf_gprscdr_qosNegotiated, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_QoSInformation },
  { &hf_gprscdr_dataVolumeGPRSUplink, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_dataVolumeGPRSDownlink, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_changeCondition_01, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChangeCondition },
  { &hf_gprscdr_changeTime  , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_userLocationInformation_09, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_userLocationInformation_08 },
  { &hf_gprscdr_ePCQoSInformation, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_EPCQoSInformation },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_presenceReportingAreaStatus, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PresenceReportingAreaStatus },
  { &hf_gprscdr_userCSGInformation, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UserCSGInformation },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_enhancedDiagnostics, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_EnhancedDiagnostics },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_accessAvailabilityChangeReason, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessAvailabilityChangeReason },
  { &hf_gprscdr_uWANUserLocationInformation, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UWANUserLocationInfo },
  { &hf_gprscdr_relatedChangeOfCharCondition, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RelatedChangeOfCharCondition },
  { &hf_gprscdr_cPCIoTEPSOptimisationIndicator, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CPCIoTEPSOptimisationIndicator },
  { &hf_gprscdr_servingPLMNRateControl, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ServingPLMNRateControl },
  { &hf_gprscdr_threeGPPPSDataOffStatus, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ThreeGPPPSDataOffStatus },
  { &hf_gprscdr_listOfPresenceReportingAreaInformation, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_PresenceReportingAreaInfo },
  { &hf_gprscdr_aPNRateControl, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNRateControl },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ChangeOfCharCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChangeOfCharCondition_sequence, hf_index, ett_gprscdr_ChangeOfCharCondition);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ChangeOfCharCondition_sequence_of[1] = {
  { &hf_gprscdr_listOfTrafficVolumes_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ChangeOfCharCondition },
};

static int
dissect_gprscdr_SEQUENCE_OF_ChangeOfCharCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ChangeOfCharCondition_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_ChangeOfCharCondition);

  return offset;
}


static const ber_sequence_t SGSNPDPRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_networkInitiation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NetworkInitiatedPDPContext },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_sgsnAddress_01, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_msNetworkCapability, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSNetworkCapability },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_locationAreaCode, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_cellIdentifier, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_ggsnAddressUsed, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpType     , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPAddress, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_listOfTrafficVolumes_01, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharCondition },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_sgsnChange  , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNChange },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 19, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_accessPointNameOI, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameOI },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 28, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_cAMELInformationPDP, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELInformationPDP },
  { &hf_gprscdr_rNCUnsentDownlinkVolume, BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_iMSIunauthenticatedFlag, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_userCSGInformation, BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UserCSGInformation },
  { &hf_gprscdr_servedPDPPDNAddressExt, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_lowPriorityIndicator, BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_servingNodePLMNIdentifier, BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_cNOperatorSelectionEnt, BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CNOperatorSelectionEntity },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNPDPRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNPDPRecord_set, hf_index, ett_gprscdr_SGSNPDPRecord);

  return offset;
}


static const value_string gprscdr_ServingNodeType_vals[] = {
  {   0, "sGSN" },
  {   1, "pMIPSGW" },
  {   2, "gTPSGW" },
  {   3, "ePDG" },
  {   4, "hSGW" },
  {   5, "mME" },
  {   6, "tWAN" },
  { 0, NULL }
};


static int
dissect_gprscdr_ServingNodeType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t SGSNSMORecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_msNetworkCapability, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSNetworkCapability },
  { &hf_gprscdr_serviceCentre, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_AddressString },
  { &hf_gprscdr_recordingEntity, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordingEntity },
  { &hf_gprscdr_locationArea, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_cellIdentifier, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_messageReference, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_gprscdr_MessageReference },
  { &hf_gprscdr_eventTimeStamp, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_smsResult   , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_SMSResult },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_destinationNumber, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SmsTpDestinationNumber },
  { &hf_gprscdr_cAMELInformationSMS, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELInformationSMS },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_servingNodeType_01, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_gprscdr_ServingNodeType },
  { &hf_gprscdr_servingNodeAddress_01, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_servingNodeiPv6Address_01, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_mMEName     , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DiameterIdentity },
  { &hf_gprscdr_mMERealm    , BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DiameterIdentity },
  { &hf_gprscdr_userLocationInformation_08, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_retransmission, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_servingNodePLMNIdentifier, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_userLocationInfoTime, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_cNOperatorSelectionEnt, BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CNOperatorSelectionEntity },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNSMORecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNSMORecord_set, hf_index, ett_gprscdr_SGSNSMORecord);

  return offset;
}


static const ber_sequence_t SGSNSMTRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_msNetworkCapability, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSNetworkCapability },
  { &hf_gprscdr_serviceCentre, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_AddressString },
  { &hf_gprscdr_recordingEntity, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordingEntity },
  { &hf_gprscdr_locationArea, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaCode },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_cellIdentifier, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CellId },
  { &hf_gprscdr_eventTimeStamp, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_smsResult   , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_SMSResult },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_cAMELInformationSMS, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CAMELInformationSMS },
  { &hf_gprscdr_originatingAddress, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_AddressString },
  { &hf_gprscdr_servingNodeType_01, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_gprscdr_ServingNodeType },
  { &hf_gprscdr_servingNodeAddress_01, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_servingNodeiPv6Address_01, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_mMEName     , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DiameterIdentity },
  { &hf_gprscdr_mMERealm    , BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DiameterIdentity },
  { &hf_gprscdr_userLocationInformation_08, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_retransmission, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_servingNodePLMNIdentifier, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_userLocationInfoTime, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_cNOperatorSelectionEnt, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CNOperatorSelectionEntity },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNSMTRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNSMTRecord_set, hf_index, ett_gprscdr_SGSNSMTRecord);

  return offset;
}


static const ber_sequence_t SGSNMTLCSRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_recordingEntity, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordingEntity },
  { &hf_gprscdr_lcsClientType, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gsm_map_lcs_LCSClientType },
  { &hf_gprscdr_lcsClientIdentity, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gprscdr_LCSClientIdentity },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_sgsnAddress_01, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_locationType, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_gsm_map_lcs_LocationType },
  { &hf_gprscdr_lcsQos      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LCSQoSInfo },
  { &hf_gprscdr_lcsPriority , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_lcs_LCS_Priority },
  { &hf_gprscdr_mlcNumber   , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_gsm_map_ISDN_AddressString },
  { &hf_gprscdr_eventTimeStamp, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_measurementDuration, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_notificationToMSUser, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ms_NotificationToMSUser },
  { &hf_gprscdr_privacyOverride, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_location    , BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaAndCell },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_locationEstimate, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_lcs_Ext_GeographicalInformation },
  { &hf_gprscdr_positioningData, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PositioningData },
  { &hf_gprscdr_lcsCause    , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LCSCause },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_servingNodePLMNIdentifier, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_cNOperatorSelectionEnt, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CNOperatorSelectionEntity },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNMTLCSRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNMTLCSRecord_set, hf_index, ett_gprscdr_SGSNMTLCSRecord);

  return offset;
}


static const ber_sequence_t SGSNMOLCSRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_recordingEntity, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordingEntity },
  { &hf_gprscdr_lcsClientType, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_lcs_LCSClientType },
  { &hf_gprscdr_lcsClientIdentity, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LCSClientIdentity },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_sgsnAddress_01, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_locationMethod, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_gsm_ss_LocationMethod },
  { &hf_gprscdr_lcsQos      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LCSQoSInfo },
  { &hf_gprscdr_lcsPriority , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_lcs_LCS_Priority },
  { &hf_gprscdr_mlcNumber   , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ISDN_AddressString },
  { &hf_gprscdr_eventTimeStamp, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_measurementDuration, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_location    , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaAndCell },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_locationEstimate, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_lcs_Ext_GeographicalInformation },
  { &hf_gprscdr_positioningData, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PositioningData },
  { &hf_gprscdr_lcsCause    , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LCSCause },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_servingNodePLMNIdentifier, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_cNOperatorSelectionEnt, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CNOperatorSelectionEntity },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNMOLCSRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNMOLCSRecord_set, hf_index, ett_gprscdr_SGSNMOLCSRecord);

  return offset;
}


static const ber_sequence_t SGSNNILCSRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_recordingEntity, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordingEntity },
  { &hf_gprscdr_lcsClientType, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_lcs_LCSClientType },
  { &hf_gprscdr_lcsClientIdentity, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LCSClientIdentity },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_sgsnAddress_01, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_lcsQos      , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LCSQoSInfo },
  { &hf_gprscdr_lcsPriority , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_lcs_LCS_Priority },
  { &hf_gprscdr_mlcNumber   , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_ISDN_AddressString },
  { &hf_gprscdr_eventTimeStamp, BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_measurementDuration, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_location    , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocationAreaAndCell },
  { &hf_gprscdr_routingArea , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RoutingAreaCode },
  { &hf_gprscdr_locationEstimate, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_lcs_Ext_GeographicalInformation },
  { &hf_gprscdr_positioningData, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PositioningData },
  { &hf_gprscdr_lcsCause    , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LCSCause },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_servingNodePLMNIdentifier, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_cNOperatorSelectionEnt, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CNOperatorSelectionEntity },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNNILCSRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNNILCSRecord_set, hf_index, ett_gprscdr_SGSNNILCSRecord);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_RAIdentity_sequence_of[1] = {
  { &hf_gprscdr_listofRAs_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_gsm_map_RAIdentity },
};

static int
dissect_gprscdr_SEQUENCE_OF_RAIdentity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_RAIdentity_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_RAIdentity);

  return offset;
}



static int
dissect_gprscdr_DataVolumeMBMS(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ChangeOfMBMSCondition_sequence[] = {
  { &hf_gprscdr_qosRequested, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_QoSInformation },
  { &hf_gprscdr_qosNegotiated, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_QoSInformation },
  { &hf_gprscdr_dataVolumeMBMSUplink, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeMBMS },
  { &hf_gprscdr_dataVolumeMBMSDownlink, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeMBMS },
  { &hf_gprscdr_changeCondition_01, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChangeCondition },
  { &hf_gprscdr_changeTime  , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_failureHandlingContinue, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FailureHandlingContinue },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ChangeOfMBMSCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChangeOfMBMSCondition_sequence, hf_index, ett_gprscdr_ChangeOfMBMSCondition);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ChangeOfMBMSCondition_sequence_of[1] = {
  { &hf_gprscdr_listOfTrafficVolumes_item_02, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ChangeOfMBMSCondition },
};

static int
dissect_gprscdr_SEQUENCE_OF_ChangeOfMBMSCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ChangeOfMBMSCondition_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_ChangeOfMBMSCondition);

  return offset;
}


static const ber_sequence_t SGSNMBMSRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_ggsnAddress , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_listofRAs   , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_RAIdentity },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_servedPDPAddress, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_listOfTrafficVolumes_02, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfMBMSCondition },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_sgsnPLMNIdentifier, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_numberofReceivingUE, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_mbmsInformation, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MBMSInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGSNMBMSRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGSNMBMSRecord_set, hf_index, ett_gprscdr_SGSNMBMSRecord);

  return offset;
}


static const ber_sequence_t GGSNMBMSRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_ggsnAddress , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_listofDownstreamNodes, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_servedPDPAddress, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_listOfTrafficVolumes_02, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfMBMSCondition },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_mbmsInformation, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MBMSInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_GGSNMBMSRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              GGSNMBMSRecord_set, hf_index, ett_gprscdr_GGSNMBMSRecord);

  return offset;
}



static int
dissect_gprscdr_T_userLocationInformation_06(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 2);


  return offset;
}



static int
dissect_gprscdr_SGWChange(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ServingNodeType_sequence_of[1] = {
  { &hf_gprscdr_servingNodeType_item, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ServingNodeType },
};

static int
dissect_gprscdr_SEQUENCE_OF_ServingNodeType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ServingNodeType_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_ServingNodeType);

  return offset;
}



static int
dissect_gprscdr_T_lastUserLocationInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 2);


  return offset;
}



static int
dissect_gprscdr_UNIPDUCPOnlyFlag(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_gprscdr_PDPPDNTypeExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t MOExceptionDataCounter_sequence[] = {
  { &hf_gprscdr_counterValue, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_counterTimestamp, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_MOExceptionDataCounter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MOExceptionDataCounter_sequence, hf_index, ett_gprscdr_MOExceptionDataCounter);

  return offset;
}


static const value_string gprscdr_SecondaryRATType_vals[] = {
  {   0, "nR" },
  { 0, NULL }
};


static int
dissect_gprscdr_SecondaryRATType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t RANSecondaryRATUsageReport_sequence[] = {
  { &hf_gprscdr_dataVolumeUplink, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_dataVolumeDownlink, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_rANStartTime, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_rANEndTime  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_secondaryRATType, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SecondaryRATType },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_RANSecondaryRATUsageReport(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RANSecondaryRATUsageReport_sequence, hf_index, ett_gprscdr_RANSecondaryRATUsageReport);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_RANSecondaryRATUsageReport_sequence_of[1] = {
  { &hf_gprscdr_listOfRANSecondaryRATUsageReports_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_RANSecondaryRATUsageReport },
};

static int
dissect_gprscdr_SEQUENCE_OF_RANSecondaryRATUsageReport(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_RANSecondaryRATUsageReport_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_RANSecondaryRATUsageReport);

  return offset;
}


static const ber_sequence_t SGWRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_s_GWAddress , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_servingNodeAddress, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpPDNType  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPPDNAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_listOfTrafficVolumes_01, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharCondition },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_iMSsignalingContext, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_servingNodePLMNIdentifier, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_mSTimeZone  , BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSTimeZone },
  { &hf_gprscdr_userLocationInformation_06, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_userLocationInformation_06 },
  { &hf_gprscdr_sGWChange   , BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SGWChange },
  { &hf_gprscdr_servingNodeType, BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ServingNodeType },
  { &hf_gprscdr_p_GWAddressUsed, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_p_GWPLMNIdentifier, BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_startTime   , BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_stopTime    , BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_pDNConnectionChargingID, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_iMSIunauthenticatedFlag, BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_userCSGInformation, BER_CLASS_CON, 42, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UserCSGInformation },
  { &hf_gprscdr_servedPDPPDNAddressExt, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_lowPriorityIndicator, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_dynamicAddressFlagExt, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_s_GWiPv6Address, BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_servingNodeiPv6Address, BER_CLASS_CON, 49, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_p_GWiPv6AddressUsed, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_retransmission, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_userLocationInfoTime, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_cNOperatorSelectionEnt, BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CNOperatorSelectionEntity },
  { &hf_gprscdr_presenceReportingAreaInfo, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PresenceReportingAreaInfo },
  { &hf_gprscdr_lastUserLocationInformation, BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_lastUserLocationInformation },
  { &hf_gprscdr_lastMSTimeZone, BER_CLASS_CON, 56, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSTimeZone },
  { &hf_gprscdr_enhancedDiagnostics, BER_CLASS_CON, 57, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_EnhancedDiagnostics },
  { &hf_gprscdr_cPCIoTEPSOptimisationIndicator, BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CPCIoTEPSOptimisationIndicator },
  { &hf_gprscdr_uNIPDUCPOnlyFlag, BER_CLASS_CON, 60, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UNIPDUCPOnlyFlag },
  { &hf_gprscdr_servingPLMNRateControl, BER_CLASS_CON, 61, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ServingPLMNRateControl },
  { &hf_gprscdr_pDPPDNTypeExtension, BER_CLASS_CON, 62, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPPDNTypeExtension },
  { &hf_gprscdr_mOExceptionDataCounter, BER_CLASS_CON, 63, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MOExceptionDataCounter },
  { &hf_gprscdr_listOfRANSecondaryRATUsageReports, BER_CLASS_CON, 64, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_RANSecondaryRATUsageReport },
  { &hf_gprscdr_pSCellInformation, BER_CLASS_CON, 65, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PSCellInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_SGWRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              SGWRecord_set, hf_index, ett_gprscdr_SGWRecord);

  return offset;
}



static int
dissect_gprscdr_T_userLocationInformation_07(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 2);


  return offset;
}


static int * const ServiceConditionChange_bits[] = {
  &hf_gprscdr_ServiceConditionChange_qoSChange,
  &hf_gprscdr_ServiceConditionChange_sGSNChange,
  &hf_gprscdr_ServiceConditionChange_sGSNPLMNIDChange,
  &hf_gprscdr_ServiceConditionChange_tariffTimeSwitch,
  &hf_gprscdr_ServiceConditionChange_pDPContextRelease,
  &hf_gprscdr_ServiceConditionChange_rATChange,
  &hf_gprscdr_ServiceConditionChange_serviceIdledOut,
  &hf_gprscdr_ServiceConditionChange_reserved,
  &hf_gprscdr_ServiceConditionChange_configurationChange,
  &hf_gprscdr_ServiceConditionChange_serviceStop,
  &hf_gprscdr_ServiceConditionChange_dCCATimeThresholdReached,
  &hf_gprscdr_ServiceConditionChange_dCCAVolumeThresholdReached,
  &hf_gprscdr_ServiceConditionChange_dCCAServiceSpecificUnitThresholdReached,
  &hf_gprscdr_ServiceConditionChange_dCCATimeExhausted,
  &hf_gprscdr_ServiceConditionChange_dCCAVolumeExhausted,
  &hf_gprscdr_ServiceConditionChange_dCCAValidityTimeout,
  &hf_gprscdr_ServiceConditionChange_reserved1,
  &hf_gprscdr_ServiceConditionChange_dCCAReauthorisationRequest,
  &hf_gprscdr_ServiceConditionChange_dCCAContinueOngoingSession,
  &hf_gprscdr_ServiceConditionChange_dCCARetryAndTerminateOngoingSession,
  &hf_gprscdr_ServiceConditionChange_dCCATerminateOngoingSession,
  &hf_gprscdr_ServiceConditionChange_cGI_SAIChange,
  &hf_gprscdr_ServiceConditionChange_rAIChange,
  &hf_gprscdr_ServiceConditionChange_dCCAServiceSpecificUnitExhausted,
  &hf_gprscdr_ServiceConditionChange_recordClosure,
  &hf_gprscdr_ServiceConditionChange_timeLimit,
  &hf_gprscdr_ServiceConditionChange_volumeLimit,
  &hf_gprscdr_ServiceConditionChange_serviceSpecificUnitLimit,
  &hf_gprscdr_ServiceConditionChange_envelopeClosure,
  &hf_gprscdr_ServiceConditionChange_eCGIChange,
  &hf_gprscdr_ServiceConditionChange_tAIChange,
  &hf_gprscdr_ServiceConditionChange_userLocationChange,
  &hf_gprscdr_ServiceConditionChange_userCSGInformationChange,
  &hf_gprscdr_ServiceConditionChange_presenceInPRAChange,
  &hf_gprscdr_ServiceConditionChange_accessChangeOfSDF,
  &hf_gprscdr_ServiceConditionChange_indirectServiceConditionChange,
  &hf_gprscdr_ServiceConditionChange_servingPLMNRateControlChange,
  &hf_gprscdr_ServiceConditionChange_aPNRateControlChange,
  NULL
};

static int
dissect_gprscdr_ServiceConditionChange(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    ServiceConditionChange_bits, 38, hf_index, ett_gprscdr_ServiceConditionChange,
                                    NULL);

  return offset;
}



static int
dissect_gprscdr_T_userLocationInformation_09(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 2);


  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ServiceSpecificInfo_sequence_of[1] = {
  { &hf_gprscdr_serviceSpecificInfo_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ServiceSpecificInfo },
};

static int
dissect_gprscdr_SEQUENCE_OF_ServiceSpecificInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ServiceSpecificInfo_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_ServiceSpecificInfo);

  return offset;
}



static int
dissect_gprscdr_ADCRuleBaseName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_gprscdr_T_userLocationInformation_11(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 2);


  return offset;
}


static const ber_sequence_t RelatedChangeOfServiceCondition_sequence[] = {
  { &hf_gprscdr_userLocationInformation_12, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_userLocationInformation_11 },
  { &hf_gprscdr_threeGPP2UserLocationInformation, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_presenceReportingAreaStatus, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PresenceReportingAreaStatus },
  { &hf_gprscdr_userCSGInformation, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UserCSGInformation },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_uWANUserLocationInformation, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UWANUserLocationInfo },
  { &hf_gprscdr_relatedServiceConditionChange, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ServiceConditionChange },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_RelatedChangeOfServiceCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RelatedChangeOfServiceCondition_sequence, hf_index, ett_gprscdr_RelatedChangeOfServiceCondition);

  return offset;
}



static int
dissect_gprscdr_TrafficSteeringPolicyIDDownlink(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_gprscdr_TrafficSteeringPolicyIDUplink(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t TWANUserLocationInfo_sequence[] = {
  { &hf_gprscdr_sSID        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_bSSID       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_civicAddressInformation, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CivicAddressInformation },
  { &hf_gprscdr_wLANOperatorId, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_WLANOperatorId },
  { &hf_gprscdr_logicalAccessID, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_TWANUserLocationInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TWANUserLocationInfo_sequence, hf_index, ett_gprscdr_TWANUserLocationInfo);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_InvolvedParty_sequence_of[1] = {
  { &hf_gprscdr_list_Of_Called_Asserted_Identity_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_InvolvedParty },
};

static int
dissect_gprscdr_SEQUENCE_OF_InvolvedParty(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_InvolvedParty_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_InvolvedParty);

  return offset;
}


static const ber_sequence_t CalleePartyInformation_sequence[] = {
  { &hf_gprscdr_called_Party_Address, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_InvolvedParty },
  { &hf_gprscdr_requested_Party_Address, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_InvolvedParty },
  { &hf_gprscdr_list_Of_Called_Asserted_Identity, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_InvolvedParty },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_CalleePartyInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CalleePartyInformation_sequence, hf_index, ett_gprscdr_CalleePartyInformation);

  return offset;
}


static const ber_sequence_t VoLTEInformation_sequence[] = {
  { &hf_gprscdr_callerInformation, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_InvolvedParty },
  { &hf_gprscdr_calleeInformation, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CalleePartyInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_VoLTEInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   VoLTEInformation_sequence, hf_index, ett_gprscdr_VoLTEInformation);

  return offset;
}


static const ber_sequence_t ChangeOfServiceCondition_sequence[] = {
  { &hf_gprscdr_ratingGroup , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_gprscdr_RatingGroupId },
  { &hf_gprscdr_chargingRuleBaseName, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingRuleBaseName },
  { &hf_gprscdr_resultCode  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ResultCode },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_timeOfFirstUsage, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_timeOfLastUsage, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_timeUsage   , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_serviceConditionChange_01, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_gprscdr_ServiceConditionChange },
  { &hf_gprscdr_qoSInformationNeg_01, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_EPCQoSInformation },
  { &hf_gprscdr_servingNodeAddress_01, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_datavolumeFBCUplink, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_datavolumeFBCDownlink, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DataVolumeGPRS },
  { &hf_gprscdr_timeOfReport, BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_failureHandlingContinue, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FailureHandlingContinue },
  { &hf_gprscdr_serviceIdentifier, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ServiceIdentifier },
  { &hf_gprscdr_pSFurnishChargingInformation, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PSFurnishChargingInformation },
  { &hf_gprscdr_aFRecordInformation, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_AFRecordInformation },
  { &hf_gprscdr_userLocationInformation_10, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_userLocationInformation_09 },
  { &hf_gprscdr_eventBasedChargingInformation, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_EventBasedChargingInformation },
  { &hf_gprscdr_timeQuotaMechanism, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeQuotaMechanism },
  { &hf_gprscdr_serviceSpecificInfo, BER_CLASS_CON, 23, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ServiceSpecificInfo },
  { &hf_gprscdr_threeGPP2UserLocationInformation, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_sponsorIdentity, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_applicationServiceProviderIdentity, BER_CLASS_CON, 26, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_aDCRuleBaseName, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ADCRuleBaseName },
  { &hf_gprscdr_presenceReportingAreaStatus, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PresenceReportingAreaStatus },
  { &hf_gprscdr_userCSGInformation, BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UserCSGInformation },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_uWANUserLocationInformation, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UWANUserLocationInfo },
  { &hf_gprscdr_relatedChangeOfServiceCondition, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RelatedChangeOfServiceCondition },
  { &hf_gprscdr_servingPLMNRateControl, BER_CLASS_CON, 35, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ServingPLMNRateControl },
  { &hf_gprscdr_aPNRateControl, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNRateControl },
  { &hf_gprscdr_threeGPPPSDataOffStatus, BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ThreeGPPPSDataOffStatus },
  { &hf_gprscdr_trafficSteeringPolicyIDDownlink, BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TrafficSteeringPolicyIDDownlink },
  { &hf_gprscdr_trafficSteeringPolicyIDUplink, BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TrafficSteeringPolicyIDUplink },
  { &hf_gprscdr_tWANUserLocationInformation, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TWANUserLocationInfo },
  { &hf_gprscdr_listOfPresenceReportingAreaInformation, BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_PresenceReportingAreaInfo },
  { &hf_gprscdr_voLTEInformation, BER_CLASS_CON, 42, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_VoLTEInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_ChangeOfServiceCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ChangeOfServiceCondition_sequence, hf_index, ett_gprscdr_ChangeOfServiceCondition);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_ChangeOfServiceCondition_sequence_of[1] = {
  { &hf_gprscdr_listOfServiceData_item_02, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_gprscdr_ChangeOfServiceCondition },
};

static int
dissect_gprscdr_SEQUENCE_OF_ChangeOfServiceCondition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_ChangeOfServiceCondition_sequence_of, hf_index, ett_gprscdr_SEQUENCE_OF_ChangeOfServiceCondition);

  return offset;
}



static int
dissect_gprscdr_T_lastUserLocationInformation_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

  offset = dissect_gprscdr_uli(tvb, actx, tree, 2);


  return offset;
}


static const value_string gprscdr_NBIFOMMode_vals[] = {
  {   0, "uEINITIATED" },
  {   1, "nETWORKINITIATED" },
  { 0, NULL }
};


static int
dissect_gprscdr_NBIFOMMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string gprscdr_NBIFOMSupport_vals[] = {
  {   0, "nBIFOMNotSupported" },
  {   1, "nBIFOMSupported" },
  { 0, NULL }
};


static int
dissect_gprscdr_NBIFOMSupport(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string gprscdr_SGiPtPTunnellingMethod_vals[] = {
  {   0, "uDPIPbased" },
  {   1, "others" },
  { 0, NULL }
};


static int
dissect_gprscdr_SGiPtPTunnellingMethod(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string gprscdr_ChargingPerIPCANSessionIndicator_vals[] = {
  {   0, "inactive" },
  {   1, "active" },
  { 0, NULL }
};


static int
dissect_gprscdr_ChargingPerIPCANSessionIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PGWRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_p_GWAddress , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_servingNodeAddress, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpPDNType  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPPDNAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_listOfTrafficVolumes_01, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharCondition },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_iMSsignalingContext, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_servingNodePLMNIdentifier, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_pSFurnishChargingInformation, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PSFurnishChargingInformation },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_mSTimeZone  , BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSTimeZone },
  { &hf_gprscdr_userLocationInformation_07, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_userLocationInformation_07 },
  { &hf_gprscdr_cAMELChargingInformation, BER_CLASS_CON, 33, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_listOfServiceData_02, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfServiceCondition },
  { &hf_gprscdr_servingNodeType, BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ServingNodeType },
  { &hf_gprscdr_servedMNNAI , BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SubscriptionID },
  { &hf_gprscdr_p_GWPLMNIdentifier, BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_startTime   , BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_stopTime    , BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_served3gpp2MEID, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_pDNConnectionChargingID, BER_CLASS_CON, 41, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_iMSIunauthenticatedFlag, BER_CLASS_CON, 42, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_userCSGInformation, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UserCSGInformation },
  { &hf_gprscdr_threeGPP2UserLocationInformation, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_servedPDPPDNAddressExt, BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_lowPriorityIndicator, BER_CLASS_CON, 46, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_dynamicAddressFlagExt, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_servingNodeiPv6Address, BER_CLASS_CON, 49, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_p_GWiPv6AddressUsed, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_tWANUserLocationInformation, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TWANUserLocationInfo },
  { &hf_gprscdr_retransmission, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_userLocationInfoTime, BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_cNOperatorSelectionEnt, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CNOperatorSelectionEntity },
  { &hf_gprscdr_ePCQoSInformation, BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_EPCQoSInformation },
  { &hf_gprscdr_presenceReportingAreaInfo, BER_CLASS_CON, 56, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PresenceReportingAreaInfo },
  { &hf_gprscdr_lastUserLocationInformation_01, BER_CLASS_CON, 57, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_T_lastUserLocationInformation_01 },
  { &hf_gprscdr_lastMSTimeZone, BER_CLASS_CON, 58, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSTimeZone },
  { &hf_gprscdr_enhancedDiagnostics, BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_EnhancedDiagnostics },
  { &hf_gprscdr_nBIFOMMode  , BER_CLASS_CON, 60, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NBIFOMMode },
  { &hf_gprscdr_nBIFOMSupport, BER_CLASS_CON, 61, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NBIFOMSupport },
  { &hf_gprscdr_uWANUserLocationInformation, BER_CLASS_CON, 62, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UWANUserLocationInfo },
  { &hf_gprscdr_sGiPtPTunnellingMethod, BER_CLASS_CON, 64, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SGiPtPTunnellingMethod },
  { &hf_gprscdr_uNIPDUCPOnlyFlag, BER_CLASS_CON, 65, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UNIPDUCPOnlyFlag },
  { &hf_gprscdr_servingPLMNRateControl, BER_CLASS_CON, 66, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ServingPLMNRateControl },
  { &hf_gprscdr_aPNRateControl, BER_CLASS_CON, 67, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNRateControl },
  { &hf_gprscdr_pDPPDNTypeExtension, BER_CLASS_CON, 68, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPPDNTypeExtension },
  { &hf_gprscdr_mOExceptionDataCounter, BER_CLASS_CON, 69, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MOExceptionDataCounter },
  { &hf_gprscdr_chargingPerIPCANSessionIndicator, BER_CLASS_CON, 70, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingPerIPCANSessionIndicator },
  { &hf_gprscdr_threeGPPPSDataOffStatus, BER_CLASS_CON, 71, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ThreeGPPPSDataOffStatus },
  { &hf_gprscdr_sCSASAddress, BER_CLASS_CON, 72, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SCSASAddress },
  { &hf_gprscdr_listOfRANSecondaryRATUsageReports, BER_CLASS_CON, 73, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_RANSecondaryRATUsageReport },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_PGWRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              PGWRecord_set, hf_index, ett_gprscdr_PGWRecord);

  return offset;
}



static int
dissect_gprscdr_CTEID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t GWMBMSRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_mbmsGWAddress, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_listofDownstreamNodes, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpPDNType  , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPPDNAddress, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_listOfTrafficVolumes_02, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfMBMSCondition },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 15, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_mbmsInformation, BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MBMSInformation },
  { &hf_gprscdr_commonTeid  , BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_CTEID },
  { &hf_gprscdr_iPMulticastSourceAddress, BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_GWMBMSRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              GWMBMSRecord_set, hf_index, ett_gprscdr_GWMBMSRecord);

  return offset;
}



static int
dissect_gprscdr_FixedSubsID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t AccessLineIdentifier_sequence[] = {
  { &hf_gprscdr_physicalAccessID, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UTF8String },
  { &hf_gprscdr_logicalAccessID, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_AccessLineIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AccessLineIdentifier_sequence, hf_index, ett_gprscdr_AccessLineIdentifier);

  return offset;
}


static const ber_sequence_t FixedUserLocationInformation_sequence[] = {
  { &hf_gprscdr_sSID        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_bSSID       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_accessLineIdentifier, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessLineIdentifier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_FixedUserLocationInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FixedUserLocationInformation_sequence, hf_index, ett_gprscdr_FixedUserLocationInformation);

  return offset;
}


static const ber_sequence_t TDFRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_p_GWAddress , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_servingNodeAddress, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpPDNType  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPPDNAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_servingNodePLMNIdentifier, BER_CLASS_CON, 27, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_pSFurnishChargingInformation, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PSFurnishChargingInformation },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_mSTimeZone  , BER_CLASS_CON, 31, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSTimeZone },
  { &hf_gprscdr_userLocationInformation_08, BER_CLASS_CON, 32, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_listOfServiceData_02, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfServiceCondition },
  { &hf_gprscdr_servingNodeType, BER_CLASS_CON, 35, BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ServingNodeType },
  { &hf_gprscdr_servedMNNAI , BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SubscriptionID },
  { &hf_gprscdr_p_GWPLMNIdentifier, BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_startTime   , BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_stopTime    , BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_served3gpp2MEID, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_pDNConnectionChargingID, BER_CLASS_CON, 41, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_userCSGInformation, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UserCSGInformation },
  { &hf_gprscdr_threeGPP2UserLocationInformation, BER_CLASS_CON, 44, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_OCTET_STRING },
  { &hf_gprscdr_servedPDPPDNAddressExt, BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlagExt, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_servingNodeiPv6Address, BER_CLASS_CON, 49, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_GSNAddress },
  { &hf_gprscdr_p_GWiPv6AddressUsed, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_tWANUserLocationInformation, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TWANUserLocationInfo },
  { &hf_gprscdr_retransmission, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_tDFAddress  , BER_CLASS_CON, 53, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_tDFiPv6AddressUsed, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_tDFPLMNIdentifier, BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_servedFixedSubsID, BER_CLASS_CON, 56, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FixedSubsID },
  { &hf_gprscdr_accessLineIdentifier, BER_CLASS_CON, 57, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessLineIdentifier },
  { &hf_gprscdr_fixedUserLocationInformation, BER_CLASS_CON, 59, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FixedUserLocationInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_TDFRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              TDFRecord_set, hf_index, ett_gprscdr_TDFRecord);

  return offset;
}


static const ber_sequence_t IPERecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_iPEdgeAddress, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_iPCANsessionType, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedIPCANsessionAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_listOfTrafficVolumes_01, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharCondition },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_pSFurnishChargingInformation, BER_CLASS_CON, 28, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PSFurnishChargingInformation },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_listOfServiceData_02, BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfServiceCondition },
  { &hf_gprscdr_servedMNNAI , BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SubscriptionID },
  { &hf_gprscdr_iPEdgeOperatorIdentifier, BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_startTime   , BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_stopTime    , BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_servedIPCANsessionAddressExt, BER_CLASS_CON, 45, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlagExt, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_iPEdgeiPv6AddressUsed, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_retransmission, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_servedFixedSubsID, BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FixedSubsID },
  { &hf_gprscdr_accessLineIdentifier, BER_CLASS_CON, 56, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessLineIdentifier },
  { &hf_gprscdr_fixedUserLocationInformation, BER_CLASS_CON, 57, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_FixedUserLocationInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_IPERecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              IPERecord_set, hf_index, ett_gprscdr_IPERecord);

  return offset;
}


static const ber_sequence_t EPDGRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_ePDGAddressUsed, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpPDNType  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPPDNAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_listOfTrafficVolumes_01, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharCondition },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_iMSsignalingContext, BER_CLASS_CON, 25, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_sGWChange   , BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SGWChange },
  { &hf_gprscdr_p_GWAddressUsed, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_p_GWPLMNIdentifier, BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_startTime   , BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_stopTime    , BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_pDNConnectionChargingID, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_servedPDPPDNAddressExt, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlagExt, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_ePDGiPv6AddressUsed, BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_p_GWiPv6AddressUsed, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_retransmission, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_enhancedDiagnostics, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_EnhancedDiagnostics },
  { &hf_gprscdr_uWANUserLocationInformation, BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_UWANUserLocationInfo },
  { &hf_gprscdr_userLocationInfoTime, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_iMSIunauthenticatedFlag, BER_CLASS_CON, 55, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_EPDGRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              EPDGRecord_set, hf_index, ett_gprscdr_EPDGRecord);

  return offset;
}


static const ber_sequence_t TWAGRecord_set[] = {
  { &hf_gprscdr_recordType_01, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_gprscdr_RecordType },
  { &hf_gprscdr_servedIMSI  , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMSI },
  { &hf_gprscdr_tWAGAddressUsed, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_chargingID  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_accessPointNameNI, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_AccessPointNameNI },
  { &hf_gprscdr_pdpPDNType  , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PDPType },
  { &hf_gprscdr_servedPDPPDNAddress, BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlag, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_listOfTrafficVolumes_01, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SEQUENCE_OF_ChangeOfCharCondition },
  { &hf_gprscdr_recordOpeningTime, BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_duration    , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_gprscdr_CallDuration },
  { &hf_gprscdr_causeForRecClosing_01, BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_gprscdr_CauseForRecClosing },
  { &hf_gprscdr_diagnostics , BER_CLASS_CON, 16, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_Diagnostics },
  { &hf_gprscdr_recordSequenceNumber, BER_CLASS_CON, 17, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_INTEGER },
  { &hf_gprscdr_nodeID      , BER_CLASS_CON, 18, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NodeID },
  { &hf_gprscdr_recordExtensions, BER_CLASS_CON, 19, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ManagementExtensions },
  { &hf_gprscdr_localSequenceNumber, BER_CLASS_CON, 20, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_LocalSequenceNumber },
  { &hf_gprscdr_apnSelectionMode, BER_CLASS_CON, 21, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_APNSelectionMode },
  { &hf_gprscdr_servedMSISDN, BER_CLASS_CON, 22, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_MSISDN },
  { &hf_gprscdr_chargingCharacteristics, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingCharacteristics },
  { &hf_gprscdr_chChSelectionMode, BER_CLASS_CON, 24, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChChSelectionMode },
  { &hf_gprscdr_servedIMEI  , BER_CLASS_CON, 29, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gsm_map_IMEI },
  { &hf_gprscdr_rATType     , BER_CLASS_CON, 30, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_RATType },
  { &hf_gprscdr_sGWChange   , BER_CLASS_CON, 34, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_SGWChange },
  { &hf_gprscdr_p_GWAddressUsed, BER_CLASS_CON, 36, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_p_GWPLMNIdentifier, BER_CLASS_CON, 37, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_PLMN_Id },
  { &hf_gprscdr_startTime   , BER_CLASS_CON, 38, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_stopTime    , BER_CLASS_CON, 39, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TimeStamp },
  { &hf_gprscdr_pDNConnectionChargingID, BER_CLASS_CON, 40, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_ChargingID },
  { &hf_gprscdr_servedPDPPDNAddressExt, BER_CLASS_CON, 43, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_PDPAddress },
  { &hf_gprscdr_dynamicAddressFlagExt, BER_CLASS_CON, 47, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_DynamicAddressFlag },
  { &hf_gprscdr_tWAGiPv6AddressUsed, BER_CLASS_CON, 48, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_p_GWiPv6AddressUsed, BER_CLASS_CON, 50, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_gprscdr_GSNAddress },
  { &hf_gprscdr_retransmission, BER_CLASS_CON, 51, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { &hf_gprscdr_enhancedDiagnostics, BER_CLASS_CON, 52, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_EnhancedDiagnostics },
  { &hf_gprscdr_tWANUserLocationInformation, BER_CLASS_CON, 53, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_TWANUserLocationInfo },
  { &hf_gprscdr_iMSIunauthenticatedFlag, BER_CLASS_CON, 54, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_gprscdr_NULL },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_gprscdr_TWAGRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              TWAGRecord_set, hf_index, ett_gprscdr_TWAGRecord);

  return offset;
}


const value_string gprscdr_GPRSRecord_vals[] = {
  {  20, "sgsnPDPRecord" },
  {  21, "ggsnPDPRecord" },
  {  22, "sgsnMMRecord" },
  {  23, "sgsnSMORecord" },
  {  24, "sgsnSMTRecord" },
  {  25, "sgsnMTLCSRecord" },
  {  26, "sgsnMOLCSRecord" },
  {  27, "sgsnNILCSRecord" },
  {  70, "egsnPDPRecord" },
  {  76, "sgsnMBMSRecord" },
  {  77, "ggsnMBMSRecord" },
  {  78, "sGWRecord" },
  {  79, "pGWRecord" },
  {  86, "gwMBMSRecord" },
  {  92, "tDFRecord" },
  {  95, "iPERecord" },
  {  96, "ePDGRecord" },
  {  97, "tWAGRecord" },
  { 0, NULL }
};

static const ber_choice_t GPRSRecord_choice[] = {
  {  20, &hf_gprscdr_sgsnPDPRecord_01, BER_CLASS_CON, 20, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNPDPRecord },
  {  21, &hf_gprscdr_ggsnPDPRecord_01, BER_CLASS_CON, 21, BER_FLAGS_IMPLTAG, dissect_gprscdr_GGSNPDPRecordV750 },
  {  22, &hf_gprscdr_sgsnMMRecord, BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNMMRecord },
  {  23, &hf_gprscdr_sgsnSMORecord_01, BER_CLASS_CON, 23, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNSMORecord },
  {  24, &hf_gprscdr_sgsnSMTRecord_01, BER_CLASS_CON, 24, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNSMTRecord },
  {  25, &hf_gprscdr_sgsnMTLCSRecord, BER_CLASS_CON, 25, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNMTLCSRecord },
  {  26, &hf_gprscdr_sgsnMOLCSRecord, BER_CLASS_CON, 26, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNMOLCSRecord },
  {  27, &hf_gprscdr_sgsnNILCSRecord, BER_CLASS_CON, 27, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNNILCSRecord },
  {  70, &hf_gprscdr_egsnPDPRecord_01, BER_CLASS_CON, 70, BER_FLAGS_IMPLTAG, dissect_gprscdr_EGSNPDPRecordV750 },
  {  76, &hf_gprscdr_sgsnMBMSRecord, BER_CLASS_CON, 76, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGSNMBMSRecord },
  {  77, &hf_gprscdr_ggsnMBMSRecord, BER_CLASS_CON, 77, BER_FLAGS_IMPLTAG, dissect_gprscdr_GGSNMBMSRecord },
  {  78, &hf_gprscdr_sGWRecord   , BER_CLASS_CON, 78, BER_FLAGS_IMPLTAG, dissect_gprscdr_SGWRecord },
  {  79, &hf_gprscdr_pGWRecord   , BER_CLASS_CON, 79, BER_FLAGS_IMPLTAG, dissect_gprscdr_PGWRecord },
  {  86, &hf_gprscdr_gwMBMSRecord, BER_CLASS_CON, 86, BER_FLAGS_IMPLTAG, dissect_gprscdr_GWMBMSRecord },
  {  92, &hf_gprscdr_tDFRecord   , BER_CLASS_CON, 92, BER_FLAGS_IMPLTAG, dissect_gprscdr_TDFRecord },
  {  95, &hf_gprscdr_iPERecord   , BER_CLASS_CON, 95, BER_FLAGS_IMPLTAG, dissect_gprscdr_IPERecord },
  {  96, &hf_gprscdr_ePDGRecord  , BER_CLASS_CON, 96, BER_FLAGS_IMPLTAG, dissect_gprscdr_EPDGRecord },
  {  97, &hf_gprscdr_tWAGRecord  , BER_CLASS_CON, 97, BER_FLAGS_IMPLTAG, dissect_gprscdr_TWAGRecord },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_gprscdr_GPRSRecord(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
proto_item *item;
int branch_taken, t_offset = offset;
int32_t  tag;

    offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GPRSRecord_choice, hf_index, ett_gprscdr_GPRSRecord,
                                 &branch_taken);


  if(branch_taken == -1){
    get_ber_identifier(tvb, t_offset, NULL, NULL, &tag);
    item = proto_tree_add_uint(tree, hf_index, tvb, t_offset, 1, tag);
    dissect_ber_identifier(actx->pinfo, tree, tvb, t_offset, NULL, NULL, &tag);
    expert_add_info_format(actx->pinfo, item, &ei_gprscdr_choice_not_found,
              "Record type(BER choice) not found: %u", tag);
 }

  return offset;
}

/*--- PDUs ---*/

int dissect_gprscdr_GPRSCallEventRecord_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_gprscdr_GPRSCallEventRecord(false, tvb, offset, &asn1_ctx, tree, hf_gprscdr_gprscdr_GPRSCallEventRecord_PDU);
  return offset;
}
int dissect_gprscdr_GPRSRecord_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_gprscdr_GPRSRecord(false, tvb, offset, &asn1_ctx, tree, hf_gprscdr_gprscdr_GPRSRecord_PDU);
  return offset;
}
int dissect_gprscdr_CAMELInformationPDP_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_gprscdr_CAMELInformationPDP(false, tvb, offset, &asn1_ctx, tree, hf_gprscdr_gprscdr_CAMELInformationPDP_PDU);
  return offset;
}




/* Register all the bits needed with the filtering engine */
void
proto_register_gprscdr(void)
{
  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_gprscdr_gprscdr_GPRSCallEventRecord_PDU,
      { "GPRSCallEventRecord", "gprscdr.GPRSCallEventRecord",
        FT_UINT32, BASE_DEC, VALS(gprscdr_GPRSCallEventRecord_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_gprscdr_GPRSRecord_PDU,
      { "GPRSRecord", "gprscdr.GPRSRecord",
        FT_UINT32, BASE_DEC, VALS(gprscdr_GPRSRecord_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_gprscdr_CAMELInformationPDP_PDU,
      { "CAMELInformationPDP", "gprscdr.CAMELInformationPDP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_gsm0408Cause,
      { "gsm0408Cause", "gprscdr.gsm0408Cause",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_gsm0902MapErrorValue,
      { "gsm0902MapErrorValue", "gprscdr.gsm0902MapErrorValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_itu_tQ767Cause,
      { "itu-tQ767Cause", "gprscdr.itu_tQ767Cause",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_networkSpecificCause,
      { "networkSpecificCause", "gprscdr.networkSpecificCause_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ManagementExtension", HFILL }},
    { &hf_gprscdr_manufacturerSpecificCause,
      { "manufacturerSpecificCause", "gprscdr.manufacturerSpecificCause_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ManagementExtension", HFILL }},
    { &hf_gprscdr_positionMethodFailureCause,
      { "positionMethodFailureCause", "gprscdr.positionMethodFailureCause",
        FT_UINT32, BASE_DEC, VALS(gsm_map_er_PositionMethodFailure_Diagnostic_vals), 0,
        "PositionMethodFailure_Diagnostic", HFILL }},
    { &hf_gprscdr_unauthorizedLCSClientCause,
      { "unauthorizedLCSClientCause", "gprscdr.unauthorizedLCSClientCause",
        FT_UINT32, BASE_DEC, VALS(gsm_map_er_UnauthorizedLCSClient_Diagnostic_vals), 0,
        "UnauthorizedLCSClient_Diagnostic", HFILL }},
    { &hf_gprscdr_diameterResultCodeAndExperimentalResult,
      { "diameterResultCodeAndExperimentalResult", "gprscdr.diameterResultCodeAndExperimentalResult",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_plmnId,
      { "plmnId", "gprscdr.plmnId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Id", HFILL }},
    { &hf_gprscdr_eutraCellId,
      { "eutraCellId", "gprscdr.eutraCellId",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_nid,
      { "nid", "gprscdr.nid",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_rANNASCause,
      { "rANNASCause", "gprscdr.rANNASCause",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_RANNASCause", HFILL }},
    { &hf_gprscdr_rANNASCause_item,
      { "RANNASCause", "gprscdr.RANNASCause",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sIP_URI,
      { "sIP-URI", "gprscdr.sIP_URI",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_gprscdr_tEL_URI,
      { "tEL-URI", "gprscdr.tEL_URI",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_gprscdr_uRN,
      { "uRN", "gprscdr.uRN",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_gprscdr_iSDN_E164,
      { "iSDN-E164", "gprscdr.iSDN_E164",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_gprscdr_externalId,
      { "externalId", "gprscdr.externalId",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_gprscdr_iPBinaryAddress,
      { "iPBinaryAddress", "gprscdr.iPBinaryAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPBinaryAddress_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_iPTextRepresentedAddress,
      { "iPTextRepresentedAddress", "gprscdr.iPTextRepresentedAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPTextRepresentedAddress_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_iPBinV4Address,
      { "iPBinV4Address", "gprscdr.iPBinV4Address",
        FT_IPv4, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_iPBinV6Address_choice,
      { "iPBinV6Address", "gprscdr.iPBinV6Address_choice",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPBinV6AddressWithOrWithoutPrefixLength_vals), 0,
        "IPBinV6AddressWithOrWithoutPrefixLength", HFILL }},
    { &hf_gprscdr_iPBinV6Address,
      { "iPBinV6Address", "gprscdr.iPBinV6Address",
        FT_IPv6, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_iPBinV6AddressWithPrefix,
      { "iPBinV6AddressWithPrefix", "gprscdr.iPBinV6AddressWithPrefix_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IPBinV6AddressWithPrefixLength", HFILL }},
    { &hf_gprscdr_pDPAddressPrefixLength,
      { "pDPAddressPrefixLength", "gprscdr.pDPAddressPrefixLength",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_iPTextV4Address,
      { "iPTextV4Address", "gprscdr.iPTextV4Address",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_7_15", HFILL }},
    { &hf_gprscdr_iPTextV6Address,
      { "iPTextV6Address", "gprscdr.iPTextV6Address",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_15_45", HFILL }},
    { &hf_gprscdr_lcsClientExternalID,
      { "lcsClientExternalID", "gprscdr.lcsClientExternalID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_lcsClientDialedByMS,
      { "lcsClientDialedByMS", "gprscdr.lcsClientDialedByMS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AddressString", HFILL }},
    { &hf_gprscdr_lcsClientInternalID,
      { "lcsClientInternalID", "gprscdr.lcsClientInternalID",
        FT_UINT32, BASE_DEC, VALS(gsm_map_LCSClientInternalID_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_locationAreaCode,
      { "locationAreaCode", "gprscdr.locationAreaCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cellId,
      { "cellId", "gprscdr.cellId",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_mCC_MNC,
      { "mCC-MNC", "gprscdr.mCC_MNC",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_ManagementExtensions_item,
      { "ManagementExtension", "gprscdr.ManagementExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_tMGI,
      { "tMGI", "gprscdr.tMGI",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_mBMSSessionIdentity,
      { "mBMSSessionIdentity", "gprscdr.mBMSSessionIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_mBMSServiceType,
      { "mBMSServiceType", "gprscdr.mBMSServiceType",
        FT_UINT32, BASE_DEC, VALS(gprscdr_MBMSServiceType_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_mBMSUserServiceType,
      { "mBMSUserServiceType", "gprscdr.mBMSUserServiceType",
        FT_UINT32, BASE_DEC, VALS(gprscdr_MBMSUserServiceType_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_mBMS2G3GIndicator,
      { "mBMS2G3GIndicator", "gprscdr.mBMS2G3GIndicator",
        FT_UINT32, BASE_DEC, VALS(gprscdr_MBMS2G3GIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_fileRepairSupported,
      { "fileRepairSupported", "gprscdr.fileRepairSupported",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_gprscdr_rAI,
      { "rAI", "gprscdr.rAI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RoutingAreaCode", HFILL }},
    { &hf_gprscdr_mBMSServiceArea,
      { "mBMSServiceArea", "gprscdr.mBMSServiceArea",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_requiredMBMSBearerCaps,
      { "requiredMBMSBearerCaps", "gprscdr.requiredMBMSBearerCaps",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RequiredMBMSBearerCapabilities", HFILL }},
    { &hf_gprscdr_mBMSGWAddress,
      { "mBMSGWAddress", "gprscdr.mBMSGWAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_cNIPMulticastDistribution,
      { "cNIPMulticastDistribution", "gprscdr.cNIPMulticastDistribution",
        FT_UINT32, BASE_DEC, VALS(gprscdr_CNIPMulticastDistribution_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_mBMSDataTransferStart,
      { "mBMSDataTransferStart", "gprscdr.mBMSDataTransferStart",
        FT_BYTES, BASE_NONE, NULL, 0,
        "MBMSTime", HFILL }},
    { &hf_gprscdr_mBMSDataTransferStop,
      { "mBMSDataTransferStop", "gprscdr.mBMSDataTransferStop",
        FT_BYTES, BASE_NONE, NULL, 0,
        "MBMSTime", HFILL }},
    { &hf_gprscdr_nrCellId,
      { "nrCellId", "gprscdr.nrCellId",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_iPAddress,
      { "iPAddress", "gprscdr.iPAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_nRcgi,
      { "nRcgi", "gprscdr.nRcgi_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ncgi", HFILL }},
    { &hf_gprscdr_ecgi,
      { "ecgi", "gprscdr.ecgi_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sCSAddress,
      { "sCSAddress", "gprscdr.sCSAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "IPAddress", HFILL }},
    { &hf_gprscdr_sCSRealm,
      { "sCSRealm", "gprscdr.sCSRealm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DiameterIdentity", HFILL }},
    { &hf_gprscdr_serviceSpecificData,
      { "serviceSpecificData", "gprscdr.serviceSpecificData",
        FT_STRING, BASE_NONE, NULL, 0,
        "GraphicString", HFILL }},
    { &hf_gprscdr_serviceSpecificType,
      { "serviceSpecificType", "gprscdr.serviceSpecificType",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_subscriptionIDType,
      { "subscriptionIDType", "gprscdr.subscriptionIDType",
        FT_UINT32, BASE_DEC, VALS(gprscdr_SubscriptionIDType_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_subscriptionIDData,
      { "subscriptionIDData", "gprscdr.subscriptionIDData",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_gprscdr_identifier,
      { "identifier", "gprscdr.identifier",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_significance,
      { "significance", "gprscdr.significance",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_gprscdr_information,
      { "information", "gprscdr.information_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnPDPRecord,
      { "sgsnPDPRecord", "gprscdr.sgsnPDPRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SGSNPDPRecordV651", HFILL }},
    { &hf_gprscdr_ggsnPDPRecord,
      { "ggsnPDPRecord", "gprscdr.ggsnPDPRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnMMRecord,
      { "sgsnMMRecord", "gprscdr.sgsnMMRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnSMORecord,
      { "sgsnSMORecord", "gprscdr.sgsnSMORecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SGSNSMORecordV651", HFILL }},
    { &hf_gprscdr_sgsnSMTRecord,
      { "sgsnSMTRecord", "gprscdr.sgsnSMTRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SGSNSMTRecordV651", HFILL }},
    { &hf_gprscdr_egsnPDPRecord,
      { "egsnPDPRecord", "gprscdr.egsnPDPRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_recordType,
      { "recordType", "gprscdr.recordType",
        FT_INT32, BASE_DEC, VALS(gprscdr_CallEventRecordType_vals), 0,
        "CallEventRecordType", HFILL }},
    { &hf_gprscdr_networkInitiation,
      { "networkInitiation", "gprscdr.networkInitiation",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "NetworkInitiatedPDPContext", HFILL }},
    { &hf_gprscdr_servedIMSI,
      { "servedIMSI", "gprscdr.servedIMSI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IMSI", HFILL }},
    { &hf_gprscdr_ggsnAddress,
      { "ggsnAddress", "gprscdr.ggsnAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_chargingID,
      { "chargingID", "gprscdr.chargingID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnAddress,
      { "sgsnAddress", "gprscdr.sgsnAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_GSNAddress", HFILL }},
    { &hf_gprscdr_sgsnAddress_item,
      { "GSNAddress", "gprscdr.GSNAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_accessPointNameNI,
      { "accessPointNameNI", "gprscdr.accessPointNameNI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_pdpType,
      { "pdpType", "gprscdr.pdpType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_servedPDPAddress,
      { "servedPDPAddress", "gprscdr.servedPDPAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_PDPAddress_vals), 0,
        "PDPAddress", HFILL }},
    { &hf_gprscdr_dynamicAddressFlag,
      { "dynamicAddressFlag", "gprscdr.dynamicAddressFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_listOfTrafficVolumes,
      { "listOfTrafficVolumes", "gprscdr.listOfTrafficVolumes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ChangeOfCharConditionV651", HFILL }},
    { &hf_gprscdr_listOfTrafficVolumes_item,
      { "ChangeOfCharConditionV651", "gprscdr.ChangeOfCharConditionV651_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_recordOpeningTime,
      { "recordOpeningTime", "gprscdr.recordOpeningTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_duration,
      { "duration", "gprscdr.duration",
        FT_INT32, BASE_DEC, NULL, 0,
        "CallDuration", HFILL }},
    { &hf_gprscdr_causeForRecClosing,
      { "causeForRecClosing", "gprscdr.causeForRecClosing",
        FT_INT32, BASE_DEC, VALS(gprscdr_CauseForRecClosingV651_vals), 0,
        "CauseForRecClosingV651", HFILL }},
    { &hf_gprscdr_diagnostics,
      { "diagnostics", "gprscdr.diagnostics",
        FT_UINT32, BASE_DEC, VALS(gprscdr_Diagnostics_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_recordSequenceNumber,
      { "recordSequenceNumber", "gprscdr.recordSequenceNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_nodeID,
      { "nodeID", "gprscdr.nodeID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_recordExtensions,
      { "recordExtensions", "gprscdr.recordExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ManagementExtensions", HFILL }},
    { &hf_gprscdr_localSequenceNumber,
      { "localSequenceNumber", "gprscdr.localSequenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_apnSelectionMode,
      { "apnSelectionMode", "gprscdr.apnSelectionMode",
        FT_UINT32, BASE_DEC, VALS(gprscdr_APNSelectionMode_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_servedMSISDN,
      { "servedMSISDN", "gprscdr.servedMSISDN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "MSISDN", HFILL }},
    { &hf_gprscdr_chargingCharacteristics,
      { "chargingCharacteristics", "gprscdr.chargingCharacteristics",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_chChSelectionMode,
      { "chChSelectionMode", "gprscdr.chChSelectionMode",
        FT_UINT32, BASE_DEC, VALS(gprscdr_ChChSelectionMode_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_iMSsignalingContext,
      { "iMSsignalingContext", "gprscdr.iMSsignalingContext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_externalChargingID,
      { "externalChargingID", "gprscdr.externalChargingID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_sgsnPLMNIdentifier,
      { "sgsnPLMNIdentifier", "gprscdr.sgsnPLMNIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Id", HFILL }},
    { &hf_gprscdr_servedIMEISV,
      { "servedIMEISV", "gprscdr.servedIMEISV",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IMEI", HFILL }},
    { &hf_gprscdr_rATType,
      { "rATType", "gprscdr.rATType",
        FT_UINT32, BASE_DEC, VALS(gprscdr_rat_type_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_mSTimeZone,
      { "mSTimeZone", "gprscdr.mSTimeZone",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_userLocationInformation,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cAMELChargingInformation,
      { "cAMELChargingInformation", "gprscdr.cAMELChargingInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_recordType_01,
      { "recordType", "gprscdr.recordType",
        FT_INT32, BASE_DEC, VALS(gprscdr_RecordType_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_causeForRecClosing_01,
      { "causeForRecClosing", "gprscdr.causeForRecClosing",
        FT_INT32, BASE_DEC, VALS(gprscdr_CauseForRecClosing_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_userLocationInformation_01,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userLocationInformation_01", HFILL }},
    { &hf_gprscdr_pSFurnishChargingInformation,
      { "pSFurnishChargingInformation", "gprscdr.pSFurnishChargingInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_userLocationInformation_02,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userLocationInformation_02", HFILL }},
    { &hf_gprscdr_listOfServiceData,
      { "listOfServiceData", "gprscdr.listOfServiceData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ChangeOfServiceConditionV651", HFILL }},
    { &hf_gprscdr_listOfServiceData_item,
      { "ChangeOfServiceConditionV651", "gprscdr.ChangeOfServiceConditionV651_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_userLocationInformation_03,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userLocationInformation_03", HFILL }},
    { &hf_gprscdr_listOfServiceData_01,
      { "listOfServiceData", "gprscdr.listOfServiceData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ChangeOfServiceConditionV750", HFILL }},
    { &hf_gprscdr_listOfServiceData_item_01,
      { "ChangeOfServiceConditionV750", "gprscdr.ChangeOfServiceConditionV750_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_servedIMEI,
      { "servedIMEI", "gprscdr.servedIMEI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "IMEI", HFILL }},
    { &hf_gprscdr_sgsnAddress_01,
      { "sgsnAddress", "gprscdr.sgsnAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_msNetworkCapability,
      { "msNetworkCapability", "gprscdr.msNetworkCapability",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_routingArea,
      { "routingArea", "gprscdr.routingArea",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RoutingAreaCode", HFILL }},
    { &hf_gprscdr_cellIdentifier,
      { "cellIdentifier", "gprscdr.cellIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CellId", HFILL }},
    { &hf_gprscdr_ggsnAddressUsed,
      { "ggsnAddressUsed", "gprscdr.ggsnAddressUsed",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_sgsnChange,
      { "sgsnChange", "gprscdr.sgsnChange",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_accessPointNameOI,
      { "accessPointNameOI", "gprscdr.accessPointNameOI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cAMELInformationPDP,
      { "cAMELInformationPDP", "gprscdr.cAMELInformationPDP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_rNCUnsentDownlinkVolume,
      { "rNCUnsentDownlinkVolume", "gprscdr.rNCUnsentDownlinkVolume",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeGPRS", HFILL }},
    { &hf_gprscdr_serviceCentre,
      { "serviceCentre", "gprscdr.serviceCentre",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AddressString", HFILL }},
    { &hf_gprscdr_recordingEntity,
      { "recordingEntity", "gprscdr.recordingEntity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_locationArea,
      { "locationArea", "gprscdr.locationArea",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LocationAreaCode", HFILL }},
    { &hf_gprscdr_messageReference,
      { "messageReference", "gprscdr.messageReference",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_eventTimeStamp,
      { "eventTimeStamp", "gprscdr.eventTimeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_smsResult,
      { "smsResult", "gprscdr.smsResult",
        FT_UINT32, BASE_DEC, VALS(gprscdr_Diagnostics_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_destinationNumber,
      { "destinationNumber", "gprscdr.destinationNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SmsTpDestinationNumber", HFILL }},
    { &hf_gprscdr_cAMELInformationSMS,
      { "cAMELInformationSMS", "gprscdr.cAMELInformationSMS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_qosRequested,
      { "qosRequested", "gprscdr.qosRequested",
        FT_BYTES, BASE_NONE, NULL, 0,
        "QoSInformation", HFILL }},
    { &hf_gprscdr_qosNegotiated,
      { "qosNegotiated", "gprscdr.qosNegotiated",
        FT_BYTES, BASE_NONE, NULL, 0,
        "QoSInformation", HFILL }},
    { &hf_gprscdr_dataVolumeGPRSUplink,
      { "dataVolumeGPRSUplink", "gprscdr.dataVolumeGPRSUplink",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeGPRS", HFILL }},
    { &hf_gprscdr_dataVolumeGPRSDownlink,
      { "dataVolumeGPRSDownlink", "gprscdr.dataVolumeGPRSDownlink",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeGPRS", HFILL }},
    { &hf_gprscdr_changeCondition,
      { "changeCondition", "gprscdr.changeCondition",
        FT_UINT32, BASE_DEC, VALS(gprscdr_ChangeConditionV651_vals), 0,
        "ChangeConditionV651", HFILL }},
    { &hf_gprscdr_changeTime,
      { "changeTime", "gprscdr.changeTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_failureHandlingContinue,
      { "failureHandlingContinue", "gprscdr.failureHandlingContinue",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_userLocationInformation_04,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userLocationInformation_04", HFILL }},
    { &hf_gprscdr_ratingGroup,
      { "ratingGroup", "gprscdr.ratingGroup",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RatingGroupId", HFILL }},
    { &hf_gprscdr_chargingRuleBaseName,
      { "chargingRuleBaseName", "gprscdr.chargingRuleBaseName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_resultCode,
      { "resultCode", "gprscdr.resultCode",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_timeOfFirstUsage,
      { "timeOfFirstUsage", "gprscdr.timeOfFirstUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_timeOfLastUsage,
      { "timeOfLastUsage", "gprscdr.timeOfLastUsage",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_timeUsage,
      { "timeUsage", "gprscdr.timeUsage",
        FT_INT32, BASE_DEC, NULL, 0,
        "CallDuration", HFILL }},
    { &hf_gprscdr_serviceConditionChange,
      { "serviceConditionChange", "gprscdr.serviceConditionChange",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ServiceConditionChangeV651", HFILL }},
    { &hf_gprscdr_qoSInformationNeg,
      { "qoSInformationNeg", "gprscdr.qoSInformationNeg",
        FT_BYTES, BASE_NONE, NULL, 0,
        "QoSInformation", HFILL }},
    { &hf_gprscdr_sgsn_Address,
      { "sgsn-Address", "gprscdr.sgsn_Address",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_sGSNPLMNIdentifier,
      { "sGSNPLMNIdentifier", "gprscdr.sGSNPLMNIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Id", HFILL }},
    { &hf_gprscdr_datavolumeFBCUplink,
      { "datavolumeFBCUplink", "gprscdr.datavolumeFBCUplink",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeGPRS", HFILL }},
    { &hf_gprscdr_datavolumeFBCDownlink,
      { "datavolumeFBCDownlink", "gprscdr.datavolumeFBCDownlink",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeGPRS", HFILL }},
    { &hf_gprscdr_timeOfReport,
      { "timeOfReport", "gprscdr.timeOfReport",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_serviceIdentifier,
      { "serviceIdentifier", "gprscdr.serviceIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_serviceConditionChangeV750,
      { "serviceConditionChangeV750", "gprscdr.serviceConditionChangeV750",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_aFRecordInformation,
      { "aFRecordInformation", "gprscdr.aFRecordInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AFRecordInformation", HFILL }},
    { &hf_gprscdr_aFRecordInformation_item,
      { "AFRecordInformation", "gprscdr.AFRecordInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_userLocationInformation_05,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userLocationInformation_05", HFILL }},
    { &hf_gprscdr_eventBasedChargingInformation,
      { "eventBasedChargingInformation", "gprscdr.eventBasedChargingInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_timeQuotaMechanism,
      { "timeQuotaMechanism", "gprscdr.timeQuotaMechanism_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnPDPRecord_01,
      { "sgsnPDPRecord", "gprscdr.sgsnPDPRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_ggsnPDPRecord_01,
      { "ggsnPDPRecord", "gprscdr.ggsnPDPRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GGSNPDPRecordV750", HFILL }},
    { &hf_gprscdr_sgsnSMORecord_01,
      { "sgsnSMORecord", "gprscdr.sgsnSMORecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnSMTRecord_01,
      { "sgsnSMTRecord", "gprscdr.sgsnSMTRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnMTLCSRecord,
      { "sgsnMTLCSRecord", "gprscdr.sgsnMTLCSRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnMOLCSRecord,
      { "sgsnMOLCSRecord", "gprscdr.sgsnMOLCSRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sgsnNILCSRecord,
      { "sgsnNILCSRecord", "gprscdr.sgsnNILCSRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_egsnPDPRecord_01,
      { "egsnPDPRecord", "gprscdr.egsnPDPRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EGSNPDPRecordV750", HFILL }},
    { &hf_gprscdr_sgsnMBMSRecord,
      { "sgsnMBMSRecord", "gprscdr.sgsnMBMSRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_ggsnMBMSRecord,
      { "ggsnMBMSRecord", "gprscdr.ggsnMBMSRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sGWRecord,
      { "sGWRecord", "gprscdr.sGWRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_pGWRecord,
      { "pGWRecord", "gprscdr.pGWRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_gwMBMSRecord,
      { "gwMBMSRecord", "gprscdr.gwMBMSRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_tDFRecord,
      { "tDFRecord", "gprscdr.tDFRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_iPERecord,
      { "iPERecord", "gprscdr.iPERecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_ePDGRecord,
      { "ePDGRecord", "gprscdr.ePDGRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_tWAGRecord,
      { "tWAGRecord", "gprscdr.tWAGRecord_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_s_GWAddress,
      { "s-GWAddress", "gprscdr.s_GWAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_servingNodeAddress,
      { "servingNodeAddress", "gprscdr.servingNodeAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_GSNAddress", HFILL }},
    { &hf_gprscdr_servingNodeAddress_item,
      { "GSNAddress", "gprscdr.GSNAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_pdpPDNType,
      { "pdpPDNType", "gprscdr.pdpPDNType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PDPType", HFILL }},
    { &hf_gprscdr_servedPDPPDNAddress,
      { "servedPDPPDNAddress", "gprscdr.servedPDPPDNAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_PDPAddress_vals), 0,
        "PDPAddress", HFILL }},
    { &hf_gprscdr_listOfTrafficVolumes_01,
      { "listOfTrafficVolumes", "gprscdr.listOfTrafficVolumes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ChangeOfCharCondition", HFILL }},
    { &hf_gprscdr_listOfTrafficVolumes_item_01,
      { "ChangeOfCharCondition", "gprscdr.ChangeOfCharCondition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_servingNodePLMNIdentifier,
      { "servingNodePLMNIdentifier", "gprscdr.servingNodePLMNIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Id", HFILL }},
    { &hf_gprscdr_userLocationInformation_06,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userLocationInformation_06", HFILL }},
    { &hf_gprscdr_sGWChange,
      { "sGWChange", "gprscdr.sGWChange",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_servingNodeType,
      { "servingNodeType", "gprscdr.servingNodeType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ServingNodeType", HFILL }},
    { &hf_gprscdr_servingNodeType_item,
      { "ServingNodeType", "gprscdr.ServingNodeType",
        FT_UINT32, BASE_DEC, VALS(gprscdr_ServingNodeType_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_p_GWAddressUsed,
      { "p-GWAddressUsed", "gprscdr.p_GWAddressUsed",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_p_GWPLMNIdentifier,
      { "p-GWPLMNIdentifier", "gprscdr.p_GWPLMNIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Id", HFILL }},
    { &hf_gprscdr_startTime,
      { "startTime", "gprscdr.startTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_stopTime,
      { "stopTime", "gprscdr.stopTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_pDNConnectionChargingID,
      { "pDNConnectionChargingID", "gprscdr.pDNConnectionChargingID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ChargingID", HFILL }},
    { &hf_gprscdr_iMSIunauthenticatedFlag,
      { "iMSIunauthenticatedFlag", "gprscdr.iMSIunauthenticatedFlag_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_userCSGInformation,
      { "userCSGInformation", "gprscdr.userCSGInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_servedPDPPDNAddressExt,
      { "servedPDPPDNAddressExt", "gprscdr.servedPDPPDNAddressExt",
        FT_UINT32, BASE_DEC, VALS(gprscdr_PDPAddress_vals), 0,
        "PDPAddress", HFILL }},
    { &hf_gprscdr_lowPriorityIndicator,
      { "lowPriorityIndicator", "gprscdr.lowPriorityIndicator_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_dynamicAddressFlagExt,
      { "dynamicAddressFlagExt", "gprscdr.dynamicAddressFlagExt",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "DynamicAddressFlag", HFILL }},
    { &hf_gprscdr_s_GWiPv6Address,
      { "s-GWiPv6Address", "gprscdr.s_GWiPv6Address",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_servingNodeiPv6Address,
      { "servingNodeiPv6Address", "gprscdr.servingNodeiPv6Address",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_GSNAddress", HFILL }},
    { &hf_gprscdr_servingNodeiPv6Address_item,
      { "GSNAddress", "gprscdr.GSNAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_p_GWiPv6AddressUsed,
      { "p-GWiPv6AddressUsed", "gprscdr.p_GWiPv6AddressUsed",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_retransmission,
      { "retransmission", "gprscdr.retransmission_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_userLocationInfoTime,
      { "userLocationInfoTime", "gprscdr.userLocationInfoTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_cNOperatorSelectionEnt,
      { "cNOperatorSelectionEnt", "gprscdr.cNOperatorSelectionEnt",
        FT_UINT32, BASE_DEC, VALS(gprscdr_CNOperatorSelectionEntity_vals), 0,
        "CNOperatorSelectionEntity", HFILL }},
    { &hf_gprscdr_presenceReportingAreaInfo,
      { "presenceReportingAreaInfo", "gprscdr.presenceReportingAreaInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_lastUserLocationInformation,
      { "lastUserLocationInformation", "gprscdr.lastUserLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_lastMSTimeZone,
      { "lastMSTimeZone", "gprscdr.lastMSTimeZone",
        FT_BYTES, BASE_NONE, NULL, 0,
        "MSTimeZone", HFILL }},
    { &hf_gprscdr_enhancedDiagnostics,
      { "enhancedDiagnostics", "gprscdr.enhancedDiagnostics_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cPCIoTEPSOptimisationIndicator,
      { "cPCIoTEPSOptimisationIndicator", "gprscdr.cPCIoTEPSOptimisationIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_uNIPDUCPOnlyFlag,
      { "uNIPDUCPOnlyFlag", "gprscdr.uNIPDUCPOnlyFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_servingPLMNRateControl,
      { "servingPLMNRateControl", "gprscdr.servingPLMNRateControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_pDPPDNTypeExtension,
      { "pDPPDNTypeExtension", "gprscdr.pDPPDNTypeExtension",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_mOExceptionDataCounter,
      { "mOExceptionDataCounter", "gprscdr.mOExceptionDataCounter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_listOfRANSecondaryRATUsageReports,
      { "listOfRANSecondaryRATUsageReports", "gprscdr.listOfRANSecondaryRATUsageReports",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_RANSecondaryRATUsageReport", HFILL }},
    { &hf_gprscdr_listOfRANSecondaryRATUsageReports_item,
      { "RANSecondaryRATUsageReport", "gprscdr.RANSecondaryRATUsageReport_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_pSCellInformation,
      { "pSCellInformation", "gprscdr.pSCellInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_p_GWAddress,
      { "p-GWAddress", "gprscdr.p_GWAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_userLocationInformation_07,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userLocationInformation_07", HFILL }},
    { &hf_gprscdr_listOfServiceData_02,
      { "listOfServiceData", "gprscdr.listOfServiceData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ChangeOfServiceCondition", HFILL }},
    { &hf_gprscdr_listOfServiceData_item_02,
      { "ChangeOfServiceCondition", "gprscdr.ChangeOfServiceCondition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_servedMNNAI,
      { "servedMNNAI", "gprscdr.servedMNNAI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubscriptionID", HFILL }},
    { &hf_gprscdr_served3gpp2MEID,
      { "served3gpp2MEID", "gprscdr.served3gpp2MEID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_threeGPP2UserLocationInformation,
      { "threeGPP2UserLocationInformation", "gprscdr.threeGPP2UserLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_tWANUserLocationInformation,
      { "tWANUserLocationInformation", "gprscdr.tWANUserLocationInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TWANUserLocationInfo", HFILL }},
    { &hf_gprscdr_ePCQoSInformation,
      { "ePCQoSInformation", "gprscdr.ePCQoSInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_lastUserLocationInformation_01,
      { "lastUserLocationInformation", "gprscdr.lastUserLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_lastUserLocationInformation_01", HFILL }},
    { &hf_gprscdr_nBIFOMMode,
      { "nBIFOMMode", "gprscdr.nBIFOMMode",
        FT_UINT32, BASE_DEC, VALS(gprscdr_NBIFOMMode_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_nBIFOMSupport,
      { "nBIFOMSupport", "gprscdr.nBIFOMSupport",
        FT_UINT32, BASE_DEC, VALS(gprscdr_NBIFOMSupport_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_uWANUserLocationInformation,
      { "uWANUserLocationInformation", "gprscdr.uWANUserLocationInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UWANUserLocationInfo", HFILL }},
    { &hf_gprscdr_sGiPtPTunnellingMethod,
      { "sGiPtPTunnellingMethod", "gprscdr.sGiPtPTunnellingMethod",
        FT_UINT32, BASE_DEC, VALS(gprscdr_SGiPtPTunnellingMethod_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_aPNRateControl,
      { "aPNRateControl", "gprscdr.aPNRateControl_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_chargingPerIPCANSessionIndicator,
      { "chargingPerIPCANSessionIndicator", "gprscdr.chargingPerIPCANSessionIndicator",
        FT_UINT32, BASE_DEC, VALS(gprscdr_ChargingPerIPCANSessionIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_threeGPPPSDataOffStatus,
      { "threeGPPPSDataOffStatus", "gprscdr.threeGPPPSDataOffStatus",
        FT_UINT32, BASE_DEC, VALS(gprscdr_ThreeGPPPSDataOffStatus_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_sCSASAddress,
      { "sCSASAddress", "gprscdr.sCSASAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_userLocationInformation_08,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_tDFAddress,
      { "tDFAddress", "gprscdr.tDFAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_tDFiPv6AddressUsed,
      { "tDFiPv6AddressUsed", "gprscdr.tDFiPv6AddressUsed",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_tDFPLMNIdentifier,
      { "tDFPLMNIdentifier", "gprscdr.tDFPLMNIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Id", HFILL }},
    { &hf_gprscdr_servedFixedSubsID,
      { "servedFixedSubsID", "gprscdr.servedFixedSubsID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "FixedSubsID", HFILL }},
    { &hf_gprscdr_accessLineIdentifier,
      { "accessLineIdentifier", "gprscdr.accessLineIdentifier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_fixedUserLocationInformation,
      { "fixedUserLocationInformation", "gprscdr.fixedUserLocationInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_iPEdgeAddress,
      { "iPEdgeAddress", "gprscdr.iPEdgeAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_iPCANsessionType,
      { "iPCANsessionType", "gprscdr.iPCANsessionType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PDPType", HFILL }},
    { &hf_gprscdr_servedIPCANsessionAddress,
      { "servedIPCANsessionAddress", "gprscdr.servedIPCANsessionAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_PDPAddress_vals), 0,
        "PDPAddress", HFILL }},
    { &hf_gprscdr_iPEdgeOperatorIdentifier,
      { "iPEdgeOperatorIdentifier", "gprscdr.iPEdgeOperatorIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Id", HFILL }},
    { &hf_gprscdr_servedIPCANsessionAddressExt,
      { "servedIPCANsessionAddressExt", "gprscdr.servedIPCANsessionAddressExt",
        FT_UINT32, BASE_DEC, VALS(gprscdr_PDPAddress_vals), 0,
        "PDPAddress", HFILL }},
    { &hf_gprscdr_iPEdgeiPv6AddressUsed,
      { "iPEdgeiPv6AddressUsed", "gprscdr.iPEdgeiPv6AddressUsed",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_ePDGAddressUsed,
      { "ePDGAddressUsed", "gprscdr.ePDGAddressUsed",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_ePDGiPv6AddressUsed,
      { "ePDGiPv6AddressUsed", "gprscdr.ePDGiPv6AddressUsed",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_tWAGAddressUsed,
      { "tWAGAddressUsed", "gprscdr.tWAGAddressUsed",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_tWAGiPv6AddressUsed,
      { "tWAGiPv6AddressUsed", "gprscdr.tWAGiPv6AddressUsed",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_changeLocation,
      { "changeLocation", "gprscdr.changeLocation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ChangeLocation", HFILL }},
    { &hf_gprscdr_changeLocation_item,
      { "ChangeLocation", "gprscdr.ChangeLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cAMELInformationMM,
      { "cAMELInformationMM", "gprscdr.cAMELInformationMM_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cellPLMNId,
      { "cellPLMNId", "gprscdr.cellPLMNId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Id", HFILL }},
    { &hf_gprscdr_servingNodeType_01,
      { "servingNodeType", "gprscdr.servingNodeType",
        FT_UINT32, BASE_DEC, VALS(gprscdr_ServingNodeType_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_servingNodeAddress_01,
      { "servingNodeAddress", "gprscdr.servingNodeAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_servingNodeiPv6Address_01,
      { "servingNodeiPv6Address", "gprscdr.servingNodeiPv6Address",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_mMEName,
      { "mMEName", "gprscdr.mMEName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DiameterIdentity", HFILL }},
    { &hf_gprscdr_mMERealm,
      { "mMERealm", "gprscdr.mMERealm",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DiameterIdentity", HFILL }},
    { &hf_gprscdr_originatingAddress,
      { "originatingAddress", "gprscdr.originatingAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AddressString", HFILL }},
    { &hf_gprscdr_lcsClientType,
      { "lcsClientType", "gprscdr.lcsClientType",
        FT_UINT32, BASE_DEC, VALS(gsm_map_lcs_LCSClientType_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_lcsClientIdentity,
      { "lcsClientIdentity", "gprscdr.lcsClientIdentity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_locationType,
      { "locationType", "gprscdr.locationType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_lcsQos,
      { "lcsQos", "gprscdr.lcsQos",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LCSQoSInfo", HFILL }},
    { &hf_gprscdr_lcsPriority,
      { "lcsPriority", "gprscdr.lcsPriority",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LCS_Priority", HFILL }},
    { &hf_gprscdr_mlcNumber,
      { "mlcNumber", "gprscdr.mlcNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ISDN_AddressString", HFILL }},
    { &hf_gprscdr_measurementDuration,
      { "measurementDuration", "gprscdr.measurementDuration",
        FT_INT32, BASE_DEC, NULL, 0,
        "CallDuration", HFILL }},
    { &hf_gprscdr_notificationToMSUser,
      { "notificationToMSUser", "gprscdr.notificationToMSUser",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ms_NotificationToMSUser_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_privacyOverride,
      { "privacyOverride", "gprscdr.privacyOverride_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_location,
      { "location", "gprscdr.location_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LocationAreaAndCell", HFILL }},
    { &hf_gprscdr_locationEstimate,
      { "locationEstimate", "gprscdr.locationEstimate",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Ext_GeographicalInformation", HFILL }},
    { &hf_gprscdr_positioningData,
      { "positioningData", "gprscdr.positioningData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_lcsCause,
      { "lcsCause", "gprscdr.lcsCause",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_locationMethod,
      { "locationMethod", "gprscdr.locationMethod",
        FT_UINT32, BASE_DEC, VALS(gsm_ss_LocationMethod_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_listofRAs,
      { "listofRAs", "gprscdr.listofRAs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_RAIdentity", HFILL }},
    { &hf_gprscdr_listofRAs_item,
      { "RAIdentity", "gprscdr.RAIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_listOfTrafficVolumes_02,
      { "listOfTrafficVolumes", "gprscdr.listOfTrafficVolumes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ChangeOfMBMSCondition", HFILL }},
    { &hf_gprscdr_listOfTrafficVolumes_item_02,
      { "ChangeOfMBMSCondition", "gprscdr.ChangeOfMBMSCondition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_numberofReceivingUE,
      { "numberofReceivingUE", "gprscdr.numberofReceivingUE",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_mbmsInformation,
      { "mbmsInformation", "gprscdr.mbmsInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_listofDownstreamNodes,
      { "listofDownstreamNodes", "gprscdr.listofDownstreamNodes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_GSNAddress", HFILL }},
    { &hf_gprscdr_listofDownstreamNodes_item,
      { "GSNAddress", "gprscdr.GSNAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_mbmsGWAddress,
      { "mbmsGWAddress", "gprscdr.mbmsGWAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "GSNAddress", HFILL }},
    { &hf_gprscdr_commonTeid,
      { "commonTeid", "gprscdr.commonTeid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CTEID", HFILL }},
    { &hf_gprscdr_iPMulticastSourceAddress,
      { "iPMulticastSourceAddress", "gprscdr.iPMulticastSourceAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_PDPAddress_vals), 0,
        "PDPAddress", HFILL }},
    { &hf_gprscdr_physicalAccessID,
      { "physicalAccessID", "gprscdr.physicalAccessID",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_gprscdr_logicalAccessID,
      { "logicalAccessID", "gprscdr.logicalAccessID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_aFChargingIdentifier,
      { "aFChargingIdentifier", "gprscdr.aFChargingIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_flows,
      { "flows", "gprscdr.flows_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_aPNRateControlUplink,
      { "aPNRateControlUplink", "gprscdr.aPNRateControlUplink_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "APNRateControlParameters", HFILL }},
    { &hf_gprscdr_aPNRateControlDownlink,
      { "aPNRateControlDownlink", "gprscdr.aPNRateControlDownlink_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "APNRateControlParameters", HFILL }},
    { &hf_gprscdr_additionalExceptionReports,
      { "additionalExceptionReports", "gprscdr.additionalExceptionReports",
        FT_UINT32, BASE_DEC, VALS(gprscdr_AdditionalExceptionReports_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_rateControlTimeUnit,
      { "rateControlTimeUnit", "gprscdr.rateControlTimeUnit",
        FT_INT32, BASE_DEC, VALS(gprscdr_RateControlTimeUnit_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_rateControlMaxRate,
      { "rateControlMaxRate", "gprscdr.rateControlMaxRate",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_rateControlMaxMessageSize,
      { "rateControlMaxMessageSize", "gprscdr.rateControlMaxMessageSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeGPRS", HFILL }},
    { &hf_gprscdr_called_Party_Address,
      { "called-Party-Address", "gprscdr.called_Party_Address",
        FT_UINT32, BASE_DEC, VALS(gprscdr_InvolvedParty_vals), 0,
        "InvolvedParty", HFILL }},
    { &hf_gprscdr_requested_Party_Address,
      { "requested-Party-Address", "gprscdr.requested_Party_Address",
        FT_UINT32, BASE_DEC, VALS(gprscdr_InvolvedParty_vals), 0,
        "InvolvedParty", HFILL }},
    { &hf_gprscdr_list_Of_Called_Asserted_Identity,
      { "list-Of-Called-Asserted-Identity", "gprscdr.list_Of_Called_Asserted_Identity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_InvolvedParty", HFILL }},
    { &hf_gprscdr_list_Of_Called_Asserted_Identity_item,
      { "InvolvedParty", "gprscdr.InvolvedParty",
        FT_UINT32, BASE_DEC, VALS(gprscdr_InvolvedParty_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_sCFAddress,
      { "sCFAddress", "gprscdr.sCFAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_serviceKey,
      { "serviceKey", "gprscdr.serviceKey",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_defaultTransactionHandling,
      { "defaultTransactionHandling", "gprscdr.defaultTransactionHandling",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ms_DefaultGPRS_Handling_vals), 0,
        "DefaultGPRS_Handling", HFILL }},
    { &hf_gprscdr_numberOfDPEncountered,
      { "numberOfDPEncountered", "gprscdr.numberOfDPEncountered",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_levelOfCAMELService,
      { "levelOfCAMELService", "gprscdr.levelOfCAMELService",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_freeFormatData,
      { "freeFormatData", "gprscdr.freeFormatData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_fFDAppendIndicator,
      { "fFDAppendIndicator", "gprscdr.fFDAppendIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cAMELAccessPointNameNI,
      { "cAMELAccessPointNameNI", "gprscdr.cAMELAccessPointNameNI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cAMELAccessPointNameOI,
      { "cAMELAccessPointNameOI", "gprscdr.cAMELAccessPointNameOI",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_defaultSMSHandling,
      { "defaultSMSHandling", "gprscdr.defaultSMSHandling",
        FT_UINT32, BASE_DEC, VALS(gsm_map_ms_DefaultSMS_Handling_vals), 0,
        "DefaultSMS_Handling", HFILL }},
    { &hf_gprscdr_cAMELCallingPartyNumber,
      { "cAMELCallingPartyNumber", "gprscdr.cAMELCallingPartyNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CallingNumber", HFILL }},
    { &hf_gprscdr_cAMELDestinationSubscriberNumber,
      { "cAMELDestinationSubscriberNumber", "gprscdr.cAMELDestinationSubscriberNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "SmsTpDestinationNumber", HFILL }},
    { &hf_gprscdr_cAMELSMSCAddress,
      { "cAMELSMSCAddress", "gprscdr.cAMELSMSCAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "AddressString", HFILL }},
    { &hf_gprscdr_smsReferenceNumber,
      { "smsReferenceNumber", "gprscdr.smsReferenceNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "CallReferenceNumber", HFILL }},
    { &hf_gprscdr_changeCondition_01,
      { "changeCondition", "gprscdr.changeCondition",
        FT_UINT32, BASE_DEC, VALS(gprscdr_ChangeCondition_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_userLocationInformation_09,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userLocationInformation_08", HFILL }},
    { &hf_gprscdr_presenceReportingAreaStatus,
      { "presenceReportingAreaStatus", "gprscdr.presenceReportingAreaStatus",
        FT_UINT32, BASE_DEC, VALS(gprscdr_PresenceReportingAreaStatus_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_accessAvailabilityChangeReason,
      { "accessAvailabilityChangeReason", "gprscdr.accessAvailabilityChangeReason",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_relatedChangeOfCharCondition,
      { "relatedChangeOfCharCondition", "gprscdr.relatedChangeOfCharCondition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_listOfPresenceReportingAreaInformation,
      { "listOfPresenceReportingAreaInformation", "gprscdr.listOfPresenceReportingAreaInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_PresenceReportingAreaInfo", HFILL }},
    { &hf_gprscdr_listOfPresenceReportingAreaInformation_item,
      { "PresenceReportingAreaInfo", "gprscdr.PresenceReportingAreaInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_dataVolumeMBMSUplink,
      { "dataVolumeMBMSUplink", "gprscdr.dataVolumeMBMSUplink",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeMBMS", HFILL }},
    { &hf_gprscdr_dataVolumeMBMSDownlink,
      { "dataVolumeMBMSDownlink", "gprscdr.dataVolumeMBMSDownlink",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeMBMS", HFILL }},
    { &hf_gprscdr_serviceConditionChange_01,
      { "serviceConditionChange", "gprscdr.serviceConditionChange",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_qoSInformationNeg_01,
      { "qoSInformationNeg", "gprscdr.qoSInformationNeg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EPCQoSInformation", HFILL }},
    { &hf_gprscdr_userLocationInformation_10,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userLocationInformation_09", HFILL }},
    { &hf_gprscdr_serviceSpecificInfo,
      { "serviceSpecificInfo", "gprscdr.serviceSpecificInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_ServiceSpecificInfo", HFILL }},
    { &hf_gprscdr_serviceSpecificInfo_item,
      { "ServiceSpecificInfo", "gprscdr.ServiceSpecificInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sponsorIdentity,
      { "sponsorIdentity", "gprscdr.sponsorIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_applicationServiceProviderIdentity,
      { "applicationServiceProviderIdentity", "gprscdr.applicationServiceProviderIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_aDCRuleBaseName,
      { "aDCRuleBaseName", "gprscdr.aDCRuleBaseName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_relatedChangeOfServiceCondition,
      { "relatedChangeOfServiceCondition", "gprscdr.relatedChangeOfServiceCondition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_trafficSteeringPolicyIDDownlink,
      { "trafficSteeringPolicyIDDownlink", "gprscdr.trafficSteeringPolicyIDDownlink",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_trafficSteeringPolicyIDUplink,
      { "trafficSteeringPolicyIDUplink", "gprscdr.trafficSteeringPolicyIDUplink",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_voLTEInformation,
      { "voLTEInformation", "gprscdr.voLTEInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_routingAreaCode,
      { "routingAreaCode", "gprscdr.routingAreaCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_mCC_MNC_01,
      { "mCC-MNC", "gprscdr.mCC_MNC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Id", HFILL }},
    { &hf_gprscdr_qCI,
      { "qCI", "gprscdr.qCI",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_maxRequestedBandwithUL,
      { "maxRequestedBandwithUL", "gprscdr.maxRequestedBandwithUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_maxRequestedBandwithDL,
      { "maxRequestedBandwithDL", "gprscdr.maxRequestedBandwithDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_guaranteedBitrateUL,
      { "guaranteedBitrateUL", "gprscdr.guaranteedBitrateUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_guaranteedBitrateDL,
      { "guaranteedBitrateDL", "gprscdr.guaranteedBitrateDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_aRP,
      { "aRP", "gprscdr.aRP",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_aPNAggregateMaxBitrateUL,
      { "aPNAggregateMaxBitrateUL", "gprscdr.aPNAggregateMaxBitrateUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_aPNAggregateMaxBitrateDL,
      { "aPNAggregateMaxBitrateDL", "gprscdr.aPNAggregateMaxBitrateDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_extendedMaxRequestedBWUL,
      { "extendedMaxRequestedBWUL", "gprscdr.extendedMaxRequestedBWUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_extendedMaxRequestedBWDL,
      { "extendedMaxRequestedBWDL", "gprscdr.extendedMaxRequestedBWDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_extendedGBRUL,
      { "extendedGBRUL", "gprscdr.extendedGBRUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_extendedGBRDL,
      { "extendedGBRDL", "gprscdr.extendedGBRDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_extendedAPNAMBRUL,
      { "extendedAPNAMBRUL", "gprscdr.extendedAPNAMBRUL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_extendedAPNAMBRDL,
      { "extendedAPNAMBRDL", "gprscdr.extendedAPNAMBRDL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_numberOfEvents,
      { "numberOfEvents", "gprscdr.numberOfEvents",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_eventTimeStamps,
      { "eventTimeStamps", "gprscdr.eventTimeStamps",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_TimeStamp", HFILL }},
    { &hf_gprscdr_eventTimeStamps_item,
      { "TimeStamp", "gprscdr.TimeStamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_sSID,
      { "sSID", "gprscdr.sSID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_bSSID,
      { "bSSID", "gprscdr.bSSID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_mediaComponentNumber,
      { "mediaComponentNumber", "gprscdr.mediaComponentNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_flowNumber,
      { "flowNumber", "gprscdr.flowNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_flowNumber_item,
      { "flowNumber item", "gprscdr.flowNumber_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_counterValue,
      { "counterValue", "gprscdr.counterValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_counterTimestamp,
      { "counterTimestamp", "gprscdr.counterTimestamp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_presenceReportingAreaIdentifier,
      { "presenceReportingAreaIdentifier", "gprscdr.presenceReportingAreaIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_presenceReportingAreaElementsList,
      { "presenceReportingAreaElementsList", "gprscdr.presenceReportingAreaElementsList",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_presenceReportingAreaNode,
      { "presenceReportingAreaNode", "gprscdr.presenceReportingAreaNode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_pSFreeFormatData,
      { "pSFreeFormatData", "gprscdr.pSFreeFormatData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "FreeFormatData", HFILL }},
    { &hf_gprscdr_pSFFDAppendIndicator,
      { "pSFFDAppendIndicator", "gprscdr.pSFFDAppendIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "FFDAppendIndicator", HFILL }},
    { &hf_gprscdr_dataVolumeUplink,
      { "dataVolumeUplink", "gprscdr.dataVolumeUplink",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeGPRS", HFILL }},
    { &hf_gprscdr_dataVolumeDownlink,
      { "dataVolumeDownlink", "gprscdr.dataVolumeDownlink",
        FT_INT32, BASE_DEC, NULL, 0,
        "DataVolumeGPRS", HFILL }},
    { &hf_gprscdr_rANStartTime,
      { "rANStartTime", "gprscdr.rANStartTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_rANEndTime,
      { "rANEndTime", "gprscdr.rANEndTime",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_gprscdr_secondaryRATType,
      { "secondaryRATType", "gprscdr.secondaryRATType",
        FT_INT32, BASE_DEC, VALS(gprscdr_SecondaryRATType_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_userLocationInformation_11,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userLocationInformation_10", HFILL }},
    { &hf_gprscdr_userLocationInformation_12,
      { "userLocationInformation", "gprscdr.userLocationInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_userLocationInformation_11", HFILL }},
    { &hf_gprscdr_relatedServiceConditionChange,
      { "relatedServiceConditionChange", "gprscdr.relatedServiceConditionChange",
        FT_BYTES, BASE_NONE, NULL, 0,
        "ServiceConditionChange", HFILL }},
    { &hf_gprscdr_sPLMNDLRateControlValue,
      { "sPLMNDLRateControlValue", "gprscdr.sPLMNDLRateControlValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_sPLMNULRateControlValue,
      { "sPLMNULRateControlValue", "gprscdr.sPLMNULRateControlValue",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_timeQuotaType,
      { "timeQuotaType", "gprscdr.timeQuotaType",
        FT_UINT32, BASE_DEC, VALS(gprscdr_TimeQuotaType_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_baseTimeInterval,
      { "baseTimeInterval", "gprscdr.baseTimeInterval",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_gprscdr_civicAddressInformation,
      { "civicAddressInformation", "gprscdr.civicAddressInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_wLANOperatorId,
      { "wLANOperatorId", "gprscdr.wLANOperatorId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cSGId,
      { "cSGId", "gprscdr.cSGId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_cSGAccessMode,
      { "cSGAccessMode", "gprscdr.cSGAccessMode",
        FT_UINT32, BASE_DEC, VALS(gprscdr_CSGAccessMode_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_cSGMembershipIndication,
      { "cSGMembershipIndication", "gprscdr.cSGMembershipIndication_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_gprscdr_uELocalIPAddress,
      { "uELocalIPAddress", "gprscdr.uELocalIPAddress",
        FT_UINT32, BASE_DEC, VALS(gprscdr_IPAddress_vals), 0,
        "IPAddress", HFILL }},
    { &hf_gprscdr_uDPSourcePort,
      { "uDPSourcePort", "gprscdr.uDPSourcePort",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_gprscdr_tCPSourcePort,
      { "tCPSourcePort", "gprscdr.tCPSourcePort",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_2", HFILL }},
    { &hf_gprscdr_callerInformation,
      { "callerInformation", "gprscdr.callerInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_InvolvedParty", HFILL }},
    { &hf_gprscdr_callerInformation_item,
      { "InvolvedParty", "gprscdr.InvolvedParty",
        FT_UINT32, BASE_DEC, VALS(gprscdr_InvolvedParty_vals), 0,
        NULL, HFILL }},
    { &hf_gprscdr_calleeInformation,
      { "calleeInformation", "gprscdr.calleeInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CalleePartyInformation", HFILL }},
    { &hf_gprscdr_wLANOperatorName,
      { "wLANOperatorName", "gprscdr.wLANOperatorName",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_gprscdr_wLANPLMNId,
      { "wLANPLMNId", "gprscdr.wLANPLMNId",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PLMN_Id", HFILL }},
    { &hf_gprscdr_LevelOfCAMELService_basic,
      { "basic", "gprscdr.LevelOfCAMELService.basic",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_LevelOfCAMELService_callDurationSupervision,
      { "callDurationSupervision", "gprscdr.LevelOfCAMELService.callDurationSupervision",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_LevelOfCAMELService_onlineCharging,
      { "onlineCharging", "gprscdr.LevelOfCAMELService.onlineCharging",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_qoSChange,
      { "qoSChange", "gprscdr.ServiceConditionChangeV651.qoSChange",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_sGSNChange,
      { "sGSNChange", "gprscdr.ServiceConditionChangeV651.sGSNChange",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_sGSNPLMNIDChange,
      { "sGSNPLMNIDChange", "gprscdr.ServiceConditionChangeV651.sGSNPLMNIDChange",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_tariffTimeSwitch,
      { "tariffTimeSwitch", "gprscdr.ServiceConditionChangeV651.tariffTimeSwitch",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_pDPContextRelease,
      { "pDPContextRelease", "gprscdr.ServiceConditionChangeV651.pDPContextRelease",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_rATChange,
      { "rATChange", "gprscdr.ServiceConditionChangeV651.rATChange",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_serviceIdledOut,
      { "serviceIdledOut", "gprscdr.ServiceConditionChangeV651.serviceIdledOut",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_qCTExpiry,
      { "qCTExpiry", "gprscdr.ServiceConditionChangeV651.qCTExpiry",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_configurationChange,
      { "configurationChange", "gprscdr.ServiceConditionChangeV651.configurationChange",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_serviceStop,
      { "serviceStop", "gprscdr.ServiceConditionChangeV651.serviceStop",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_timeThresholdReached,
      { "timeThresholdReached", "gprscdr.ServiceConditionChangeV651.timeThresholdReached",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_volumeThresholdReached,
      { "volumeThresholdReached", "gprscdr.ServiceConditionChangeV651.volumeThresholdReached",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_spare_bit12,
      { "spare_bit12", "gprscdr.ServiceConditionChangeV651.spare.bit12",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_timeExhausted,
      { "timeExhausted", "gprscdr.ServiceConditionChangeV651.timeExhausted",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_volumeExhausted,
      { "volumeExhausted", "gprscdr.ServiceConditionChangeV651.volumeExhausted",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_timeout,
      { "timeout", "gprscdr.ServiceConditionChangeV651.timeout",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_returnRequested,
      { "returnRequested", "gprscdr.ServiceConditionChangeV651.returnRequested",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_reauthorisationRequest,
      { "reauthorisationRequest", "gprscdr.ServiceConditionChangeV651.reauthorisationRequest",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_continueOngoingSession,
      { "continueOngoingSession", "gprscdr.ServiceConditionChangeV651.continueOngoingSession",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_retryAndTerminateOngoingSession,
      { "retryAndTerminateOngoingSession", "gprscdr.ServiceConditionChangeV651.retryAndTerminateOngoingSession",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV651_terminateOngoingSession,
      { "terminateOngoingSession", "gprscdr.ServiceConditionChangeV651.terminateOngoingSession",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_qoSChange,
      { "qoSChange", "gprscdr.ServiceConditionChangeV750.qoSChange",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_sGSNChange,
      { "sGSNChange", "gprscdr.ServiceConditionChangeV750.sGSNChange",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_sGSNPLMNIDChange,
      { "sGSNPLMNIDChange", "gprscdr.ServiceConditionChangeV750.sGSNPLMNIDChange",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_tariffTimeSwitch,
      { "tariffTimeSwitch", "gprscdr.ServiceConditionChangeV750.tariffTimeSwitch",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_pDPContextRelease,
      { "pDPContextRelease", "gprscdr.ServiceConditionChangeV750.pDPContextRelease",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_rATChange,
      { "rATChange", "gprscdr.ServiceConditionChangeV750.rATChange",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_serviceIdledOut,
      { "serviceIdledOut", "gprscdr.ServiceConditionChangeV750.serviceIdledOut",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_reserved,
      { "reserved", "gprscdr.ServiceConditionChangeV750.reserved",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_configurationChange,
      { "configurationChange", "gprscdr.ServiceConditionChangeV750.configurationChange",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_serviceStop,
      { "serviceStop", "gprscdr.ServiceConditionChangeV750.serviceStop",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_dCCATimeThresholdReached,
      { "dCCATimeThresholdReached", "gprscdr.ServiceConditionChangeV750.dCCATimeThresholdReached",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_dCCAVolumeThresholdReached,
      { "dCCAVolumeThresholdReached", "gprscdr.ServiceConditionChangeV750.dCCAVolumeThresholdReached",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_dCCAServiceSpecificUnitThresholdReached,
      { "dCCAServiceSpecificUnitThresholdReached", "gprscdr.ServiceConditionChangeV750.dCCAServiceSpecificUnitThresholdReached",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_dCCATimeExhausted,
      { "dCCATimeExhausted", "gprscdr.ServiceConditionChangeV750.dCCATimeExhausted",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_dCCAVolumeExhausted,
      { "dCCAVolumeExhausted", "gprscdr.ServiceConditionChangeV750.dCCAVolumeExhausted",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_dCCAValidityTimeout,
      { "dCCAValidityTimeout", "gprscdr.ServiceConditionChangeV750.dCCAValidityTimeout",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_reserved2,
      { "reserved2", "gprscdr.ServiceConditionChangeV750.reserved2",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_dCCAReauthorisationRequest,
      { "dCCAReauthorisationRequest", "gprscdr.ServiceConditionChangeV750.dCCAReauthorisationRequest",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_dCCAContinueOngoingSession,
      { "dCCAContinueOngoingSession", "gprscdr.ServiceConditionChangeV750.dCCAContinueOngoingSession",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_dCCARetryAndTerminateOngoingSession,
      { "dCCARetryAndTerminateOngoingSession", "gprscdr.ServiceConditionChangeV750.dCCARetryAndTerminateOngoingSession",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_dCCATerminateOngoingSession,
      { "dCCATerminateOngoingSession", "gprscdr.ServiceConditionChangeV750.dCCATerminateOngoingSession",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_cGI_SAIChange,
      { "cGI-SAIChange", "gprscdr.ServiceConditionChangeV750.cGI.SAIChange",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_rAIChange,
      { "rAIChange", "gprscdr.ServiceConditionChangeV750.rAIChange",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_dCCAServiceSpecificUnitExhausted,
      { "dCCAServiceSpecificUnitExhausted", "gprscdr.ServiceConditionChangeV750.dCCAServiceSpecificUnitExhausted",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_recordClosure,
      { "recordClosure", "gprscdr.ServiceConditionChangeV750.recordClosure",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_timeLimit,
      { "timeLimit", "gprscdr.ServiceConditionChangeV750.timeLimit",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_volumeLimit,
      { "volumeLimit", "gprscdr.ServiceConditionChangeV750.volumeLimit",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_serviceSpecificUnitLimit,
      { "serviceSpecificUnitLimit", "gprscdr.ServiceConditionChangeV750.serviceSpecificUnitLimit",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChangeV750_envelopeClosure,
      { "envelopeClosure", "gprscdr.ServiceConditionChangeV750.envelopeClosure",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_gprscdr_PresenceReportingAreaNode_oCS,
      { "oCS", "gprscdr.PresenceReportingAreaNode.oCS",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_PresenceReportingAreaNode_pCRF,
      { "pCRF", "gprscdr.PresenceReportingAreaNode.pCRF",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_qoSChange,
      { "qoSChange", "gprscdr.ServiceConditionChange.qoSChange",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_sGSNChange,
      { "sGSNChange", "gprscdr.ServiceConditionChange.sGSNChange",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_sGSNPLMNIDChange,
      { "sGSNPLMNIDChange", "gprscdr.ServiceConditionChange.sGSNPLMNIDChange",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_tariffTimeSwitch,
      { "tariffTimeSwitch", "gprscdr.ServiceConditionChange.tariffTimeSwitch",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_pDPContextRelease,
      { "pDPContextRelease", "gprscdr.ServiceConditionChange.pDPContextRelease",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_rATChange,
      { "rATChange", "gprscdr.ServiceConditionChange.rATChange",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_serviceIdledOut,
      { "serviceIdledOut", "gprscdr.ServiceConditionChange.serviceIdledOut",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_reserved,
      { "reserved", "gprscdr.ServiceConditionChange.reserved",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_configurationChange,
      { "configurationChange", "gprscdr.ServiceConditionChange.configurationChange",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_serviceStop,
      { "serviceStop", "gprscdr.ServiceConditionChange.serviceStop",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_dCCATimeThresholdReached,
      { "dCCATimeThresholdReached", "gprscdr.ServiceConditionChange.dCCATimeThresholdReached",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_dCCAVolumeThresholdReached,
      { "dCCAVolumeThresholdReached", "gprscdr.ServiceConditionChange.dCCAVolumeThresholdReached",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_dCCAServiceSpecificUnitThresholdReached,
      { "dCCAServiceSpecificUnitThresholdReached", "gprscdr.ServiceConditionChange.dCCAServiceSpecificUnitThresholdReached",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_dCCATimeExhausted,
      { "dCCATimeExhausted", "gprscdr.ServiceConditionChange.dCCATimeExhausted",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_dCCAVolumeExhausted,
      { "dCCAVolumeExhausted", "gprscdr.ServiceConditionChange.dCCAVolumeExhausted",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_dCCAValidityTimeout,
      { "dCCAValidityTimeout", "gprscdr.ServiceConditionChange.dCCAValidityTimeout",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_reserved1,
      { "reserved1", "gprscdr.ServiceConditionChange.reserved1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_dCCAReauthorisationRequest,
      { "dCCAReauthorisationRequest", "gprscdr.ServiceConditionChange.dCCAReauthorisationRequest",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_dCCAContinueOngoingSession,
      { "dCCAContinueOngoingSession", "gprscdr.ServiceConditionChange.dCCAContinueOngoingSession",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_dCCARetryAndTerminateOngoingSession,
      { "dCCARetryAndTerminateOngoingSession", "gprscdr.ServiceConditionChange.dCCARetryAndTerminateOngoingSession",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_dCCATerminateOngoingSession,
      { "dCCATerminateOngoingSession", "gprscdr.ServiceConditionChange.dCCATerminateOngoingSession",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_cGI_SAIChange,
      { "cGI-SAIChange", "gprscdr.ServiceConditionChange.cGI.SAIChange",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_rAIChange,
      { "rAIChange", "gprscdr.ServiceConditionChange.rAIChange",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_dCCAServiceSpecificUnitExhausted,
      { "dCCAServiceSpecificUnitExhausted", "gprscdr.ServiceConditionChange.dCCAServiceSpecificUnitExhausted",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_recordClosure,
      { "recordClosure", "gprscdr.ServiceConditionChange.recordClosure",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_timeLimit,
      { "timeLimit", "gprscdr.ServiceConditionChange.timeLimit",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_volumeLimit,
      { "volumeLimit", "gprscdr.ServiceConditionChange.volumeLimit",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_serviceSpecificUnitLimit,
      { "serviceSpecificUnitLimit", "gprscdr.ServiceConditionChange.serviceSpecificUnitLimit",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_envelopeClosure,
      { "envelopeClosure", "gprscdr.ServiceConditionChange.envelopeClosure",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_eCGIChange,
      { "eCGIChange", "gprscdr.ServiceConditionChange.eCGIChange",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_tAIChange,
      { "tAIChange", "gprscdr.ServiceConditionChange.tAIChange",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_userLocationChange,
      { "userLocationChange", "gprscdr.ServiceConditionChange.userLocationChange",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_userCSGInformationChange,
      { "userCSGInformationChange", "gprscdr.ServiceConditionChange.userCSGInformationChange",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_presenceInPRAChange,
      { "presenceInPRAChange", "gprscdr.ServiceConditionChange.presenceInPRAChange",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_accessChangeOfSDF,
      { "accessChangeOfSDF", "gprscdr.ServiceConditionChange.accessChangeOfSDF",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_indirectServiceConditionChange,
      { "indirectServiceConditionChange", "gprscdr.ServiceConditionChange.indirectServiceConditionChange",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_servingPLMNRateControlChange,
      { "servingPLMNRateControlChange", "gprscdr.ServiceConditionChange.servingPLMNRateControlChange",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_gprscdr_ServiceConditionChange_aPNRateControlChange,
      { "aPNRateControlChange", "gprscdr.ServiceConditionChange.aPNRateControlChange",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_gprscdr,
    &ett_gprscdr_timestamp,
    &ett_gprscdr_plmn_id,
    &ett_gprscdr_pdp_pdn_type,
    &ett_gprscdr_eps_qos_arp,
    &ett_gprscdr_managementextension_information,
    &ett_gprscdr_userlocationinformation,
    &ett_gprscdr_Diagnostics,
    &ett_gprscdr_Ecgi,
    &ett_gprscdr_EnhancedDiagnostics,
    &ett_gprscdr_SEQUENCE_OF_RANNASCause,
    &ett_gprscdr_InvolvedParty,
    &ett_gprscdr_IPAddress,
    &ett_gprscdr_IPBinaryAddress,
    &ett_gprscdr_IPBinV6AddressWithOrWithoutPrefixLength,
    &ett_gprscdr_IPBinV6AddressWithPrefixLength,
    &ett_gprscdr_IPTextRepresentedAddress,
    &ett_gprscdr_LCSClientIdentity,
    &ett_gprscdr_LevelOfCAMELService,
    &ett_gprscdr_LocationAreaAndCell,
    &ett_gprscdr_ManagementExtensions,
    &ett_gprscdr_MBMSInformation,
    &ett_gprscdr_Ncgi,
    &ett_gprscdr_PDPAddress,
    &ett_gprscdr_PSCellInformation,
    &ett_gprscdr_SCSASAddress,
    &ett_gprscdr_ServiceSpecificInfo,
    &ett_gprscdr_SubscriptionID,
    &ett_gprscdr_ManagementExtension,
    &ett_gprscdr_GPRSCallEventRecord,
    &ett_gprscdr_GGSNPDPRecord,
    &ett_gprscdr_SEQUENCE_OF_GSNAddress,
    &ett_gprscdr_SEQUENCE_OF_ChangeOfCharConditionV651,
    &ett_gprscdr_GGSNPDPRecordV750,
    &ett_gprscdr_EGSNPDPRecord,
    &ett_gprscdr_SEQUENCE_OF_ChangeOfServiceConditionV651,
    &ett_gprscdr_EGSNPDPRecordV750,
    &ett_gprscdr_SEQUENCE_OF_ChangeOfServiceConditionV750,
    &ett_gprscdr_SGSNPDPRecordV651,
    &ett_gprscdr_SGSNSMORecordV651,
    &ett_gprscdr_SGSNSMTRecordV651,
    &ett_gprscdr_ChangeOfCharConditionV651,
    &ett_gprscdr_ChangeOfServiceConditionV651,
    &ett_gprscdr_ChangeOfServiceConditionV750,
    &ett_gprscdr_SEQUENCE_OF_AFRecordInformation,
    &ett_gprscdr_ServiceConditionChangeV651,
    &ett_gprscdr_ServiceConditionChangeV750,
    &ett_gprscdr_GPRSRecord,
    &ett_gprscdr_SGWRecord,
    &ett_gprscdr_SEQUENCE_OF_ChangeOfCharCondition,
    &ett_gprscdr_SEQUENCE_OF_ServingNodeType,
    &ett_gprscdr_SEQUENCE_OF_RANSecondaryRATUsageReport,
    &ett_gprscdr_PGWRecord,
    &ett_gprscdr_SEQUENCE_OF_ChangeOfServiceCondition,
    &ett_gprscdr_TDFRecord,
    &ett_gprscdr_IPERecord,
    &ett_gprscdr_EPDGRecord,
    &ett_gprscdr_TWAGRecord,
    &ett_gprscdr_SGSNMMRecord,
    &ett_gprscdr_SEQUENCE_OF_ChangeLocation,
    &ett_gprscdr_SGSNPDPRecord,
    &ett_gprscdr_SGSNSMORecord,
    &ett_gprscdr_SGSNSMTRecord,
    &ett_gprscdr_SGSNMTLCSRecord,
    &ett_gprscdr_SGSNMOLCSRecord,
    &ett_gprscdr_SGSNNILCSRecord,
    &ett_gprscdr_SGSNMBMSRecord,
    &ett_gprscdr_SEQUENCE_OF_RAIdentity,
    &ett_gprscdr_SEQUENCE_OF_ChangeOfMBMSCondition,
    &ett_gprscdr_GGSNMBMSRecord,
    &ett_gprscdr_GWMBMSRecord,
    &ett_gprscdr_AccessLineIdentifier,
    &ett_gprscdr_AFRecordInformation,
    &ett_gprscdr_APNRateControl,
    &ett_gprscdr_APNRateControlParameters,
    &ett_gprscdr_CalleePartyInformation,
    &ett_gprscdr_SEQUENCE_OF_InvolvedParty,
    &ett_gprscdr_CAMELInformationMM,
    &ett_gprscdr_CAMELInformationPDP,
    &ett_gprscdr_CAMELInformationSMS,
    &ett_gprscdr_ChangeOfCharCondition,
    &ett_gprscdr_SEQUENCE_OF_PresenceReportingAreaInfo,
    &ett_gprscdr_ChangeOfMBMSCondition,
    &ett_gprscdr_ChangeOfServiceCondition,
    &ett_gprscdr_SEQUENCE_OF_ServiceSpecificInfo,
    &ett_gprscdr_ChangeLocation,
    &ett_gprscdr_EPCQoSInformation,
    &ett_gprscdr_EventBasedChargingInformation,
    &ett_gprscdr_SEQUENCE_OF_TimeStamp,
    &ett_gprscdr_FixedUserLocationInformation,
    &ett_gprscdr_Flows,
    &ett_gprscdr_T_flowNumber,
    &ett_gprscdr_MOExceptionDataCounter,
    &ett_gprscdr_PresenceReportingAreaInfo,
    &ett_gprscdr_PresenceReportingAreaNode,
    &ett_gprscdr_PSFurnishChargingInformation,
    &ett_gprscdr_RANSecondaryRATUsageReport,
    &ett_gprscdr_RelatedChangeOfCharCondition,
    &ett_gprscdr_RelatedChangeOfServiceCondition,
    &ett_gprscdr_ServiceConditionChange,
    &ett_gprscdr_ServingPLMNRateControl,
    &ett_gprscdr_TimeQuotaMechanism,
    &ett_gprscdr_TWANUserLocationInfo,
    &ett_gprscdr_UserCSGInformation,
    &ett_gprscdr_UWANUserLocationInfo,
    &ett_gprscdr_VoLTEInformation,
    &ett_gprscdr_WLANOperatorId,
        };

  static ei_register_info ei[] = {
    { &ei_gprscdr_not_dissected, { "gprscdr.not_dissected", PI_UNDECODED, PI_WARN, "Not dissected", EXPFILL }},
    { &ei_gprscdr_choice_not_found, { "gprscdr.error.choice_not_found", PI_MALFORMED, PI_WARN, "GPRS CDR Error: This choice field(Record type) was not found", EXPFILL }},
  };

  expert_module_t* expert_gprscdr;

  proto_gprscdr = proto_register_protocol(PNAME, PSNAME, PFNAME);

  proto_register_field_array(proto_gprscdr, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_gprscdr = expert_register_protocol(proto_gprscdr);
  expert_register_field_array(expert_gprscdr, ei, array_length(ei));
}

/* The registration hand-off routine */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
