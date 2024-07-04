/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ulp.c                                                               */
/* asn2wrs.py -q -L -p ulp -c ./ulp.cnf -s ./packet-ulp-template -D . -O ../.. ULP.asn SUPL.asn ULP-Components.asn */

/* packet-ulp.c
 * Routines for OMA UserPlane Location Protocol packet dissection
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
 * Copyright 2014-2019, Pascal Quantin <pascal@wireshark.org>
 * Copyright 2020, Stig Bjorlykke <stig@bjorlykke.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * ref OMA-TS-ULP-V2_0_5-20191028-A
 * http://www.openmobilealliance.org
 */

#include "config.h"

#include "math.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-tcp.h"
#include "packet-gsm_map.h"
#include "packet-e164.h"
#include "packet-e212.h"

#define PNAME  "OMA UserPlane Location Protocol"
#define PSNAME "ULP"
#define PFNAME "ulp"

void proto_register_ulp(void);

static dissector_handle_t rrlp_handle;
static dissector_handle_t lpp_handle;

/* IANA Registered Ports
 * oma-ulp         7275/tcp    OMA UserPlane Location
 * oma-ulp         7275/udp    OMA UserPlane Location
 */
#define ULP_PORT    7275

/* Initialize the protocol and registered fields */
static int proto_ulp;


#define ULP_HEADER_SIZE 2

static bool ulp_desegment = true;

static int hf_ulp_ULP_PDU_PDU;                    /* ULP_PDU */
static int hf_ulp_length;                         /* INTEGER_0_65535 */
static int hf_ulp_version;                        /* Version */
static int hf_ulp_sessionID;                      /* SessionID */
static int hf_ulp_message;                        /* UlpMessage */
static int hf_ulp_msSUPLINIT;                     /* SUPLINIT */
static int hf_ulp_msSUPLSTART;                    /* SUPLSTART */
static int hf_ulp_msSUPLRESPONSE;                 /* SUPLRESPONSE */
static int hf_ulp_msSUPLPOSINIT;                  /* SUPLPOSINIT */
static int hf_ulp_msSUPLPOS;                      /* SUPLPOS */
static int hf_ulp_msSUPLEND;                      /* SUPLEND */
static int hf_ulp_msSUPLAUTHREQ;                  /* SUPLAUTHREQ */
static int hf_ulp_msSUPLAUTHRESP;                 /* SUPLAUTHRESP */
static int hf_ulp_msSUPLTRIGGEREDSTART;           /* Ver2_SUPLTRIGGEREDSTART */
static int hf_ulp_msSUPLTRIGGEREDRESPONSE;        /* Ver2_SUPLTRIGGEREDRESPONSE */
static int hf_ulp_msSUPLTRIGGEREDSTOP;            /* Ver2_SUPLTRIGGEREDSTOP */
static int hf_ulp_msSUPLNOTIFY;                   /* Ver2_SUPLNOTIFY */
static int hf_ulp_msSUPLNOTIFYRESPONSE;           /* Ver2_SUPLNOTIFYRESPONSE */
static int hf_ulp_msSUPLSETINIT;                  /* Ver2_SUPLSETINIT */
static int hf_ulp_msSUPLREPORT;                   /* Ver2_SUPLREPORT */
static int hf_ulp_posMethod;                      /* PosMethod */
static int hf_ulp_notification;                   /* Notification */
static int hf_ulp_sLPAddress;                     /* SLPAddress */
static int hf_ulp_qoP;                            /* QoP */
static int hf_ulp_sLPMode;                        /* SLPMode */
static int hf_ulp_mac;                            /* MAC */
static int hf_ulp_keyIdentity;                    /* KeyIdentity */
static int hf_ulp_ver2_SUPL_INIT_extension;       /* Ver2_SUPL_INIT_extension */
static int hf_ulp_notificationType;               /* NotificationType */
static int hf_ulp_encodingType;                   /* EncodingType */
static int hf_ulp_requestorId;                    /* T_requestorId */
static int hf_ulp_requestorIdType;                /* FormatIndicator */
static int hf_ulp_clientName;                     /* T_clientName */
static int hf_ulp_clientNameType;                 /* FormatIndicator */
static int hf_ulp_ver2_Notification_extension;    /* Ver2_Notification_extension */
static int hf_ulp_sETCapabilities;                /* SETCapabilities */
static int hf_ulp_locationId;                     /* LocationId */
static int hf_ulp_ver2_SUPL_START_extension;      /* Ver2_SUPL_START_extension */
static int hf_ulp_posTechnology;                  /* PosTechnology */
static int hf_ulp_prefMethod;                     /* PrefMethod */
static int hf_ulp_posProtocol;                    /* PosProtocol */
static int hf_ulp_ver2_SETCapabilities_extension;  /* Ver2_SETCapabilities_extension */
static int hf_ulp_agpsSETassisted;                /* BOOLEAN */
static int hf_ulp_agpsSETBased;                   /* BOOLEAN */
static int hf_ulp_autonomousGPS;                  /* BOOLEAN */
static int hf_ulp_aflt;                           /* BOOLEAN */
static int hf_ulp_ecid;                           /* BOOLEAN */
static int hf_ulp_eotd;                           /* BOOLEAN */
static int hf_ulp_otdoa;                          /* BOOLEAN */
static int hf_ulp_ver2_PosTechnology_extension;   /* Ver2_PosTechnology_extension */
static int hf_ulp_tia801;                         /* BOOLEAN */
static int hf_ulp_rrlp;                           /* BOOLEAN */
static int hf_ulp_rrc;                            /* BOOLEAN */
static int hf_ulp_ver2_PosProtocol_extension;     /* Ver2_PosProtocol_extension */
static int hf_ulp_sETAuthKey;                     /* SETAuthKey */
static int hf_ulp_keyIdentity4;                   /* KeyIdentity4 */
static int hf_ulp_ver2_SUPL_RESPONSE_extension;   /* Ver2_SUPL_RESPONSE_extension */
static int hf_ulp_shortKey;                       /* BIT_STRING_SIZE_128 */
static int hf_ulp_longKey;                        /* BIT_STRING_SIZE_256 */
static int hf_ulp_requestedAssistData;            /* RequestedAssistData */
static int hf_ulp_position;                       /* Position */
static int hf_ulp_suplpos;                        /* SUPLPOS */
static int hf_ulp_ver;                            /* Ver */
static int hf_ulp_ver2_SUPL_POS_INIT_extension;   /* Ver2_SUPL_POS_INIT_extension */
static int hf_ulp_almanacRequested;               /* BOOLEAN */
static int hf_ulp_utcModelRequested;              /* BOOLEAN */
static int hf_ulp_ionosphericModelRequested;      /* BOOLEAN */
static int hf_ulp_dgpsCorrectionsRequested;       /* BOOLEAN */
static int hf_ulp_referenceLocationRequested;     /* BOOLEAN */
static int hf_ulp_referenceTimeRequested;         /* BOOLEAN */
static int hf_ulp_acquisitionAssistanceRequested;  /* BOOLEAN */
static int hf_ulp_realTimeIntegrityRequested;     /* BOOLEAN */
static int hf_ulp_navigationModelRequested;       /* BOOLEAN */
static int hf_ulp_navigationModelData;            /* NavigationModel */
static int hf_ulp_ver2_RequestedAssistData_extension;  /* Ver2_RequestedAssistData_extension */
static int hf_ulp_gpsWeek;                        /* INTEGER_0_1023 */
static int hf_ulp_gpsToe;                         /* INTEGER_0_167 */
static int hf_ulp_nsat;                           /* INTEGER_0_31 */
static int hf_ulp_toeLimit;                       /* INTEGER_0_10 */
static int hf_ulp_satInfo;                        /* SatelliteInfo */
static int hf_ulp_SatelliteInfo_item;             /* SatelliteInfoElement */
static int hf_ulp_satId;                          /* INTEGER_0_63 */
static int hf_ulp_iode;                           /* INTEGER_0_255 */
static int hf_ulp_posPayLoad;                     /* PosPayLoad */
static int hf_ulp_velocity;                       /* Velocity */
static int hf_ulp_ver2_SUPL_POS_extension;        /* Ver2_SUPL_POS_extension */
static int hf_ulp_tia801payload;                  /* OCTET_STRING_SIZE_1_8192 */
static int hf_ulp_rrcPayload;                     /* OCTET_STRING_SIZE_1_8192 */
static int hf_ulp_rrlpPayload;                    /* T_rrlpPayload */
static int hf_ulp_ver2_PosPayLoad_extension;      /* Ver2_PosPayLoad_extension */
static int hf_ulp_statusCode;                     /* StatusCode */
static int hf_ulp_ver2_SUPL_END_extension;        /* Ver2_SUPL_END_extension */
static int hf_ulp_sPCSETKey;                      /* SPCSETKey */
static int hf_ulp_spctid;                         /* SPCTID */
static int hf_ulp_sPCSETKeylifetime;              /* SPCSETKeylifetime */
static int hf_ulp_notificationResponse;           /* NotificationResponse */
static int hf_ulp_targetSETID;                    /* SETId */
static int hf_ulp_applicationID;                  /* ApplicationID */
static int hf_ulp_multipleLocationIds;            /* MultipleLocationIds */
static int hf_ulp_thirdParty;                     /* ThirdParty */
static int hf_ulp_triggerType;                    /* TriggerType */
static int hf_ulp_triggerParams;                  /* TriggerParams */
static int hf_ulp_reportingCap;                   /* ReportingCap */
static int hf_ulp_causeCode;                      /* CauseCode */
static int hf_ulp_periodicParams;                 /* PeriodicParams */
static int hf_ulp_areaEventParams;                /* AreaEventParams */
static int hf_ulp_numberOfFixes;                  /* INTEGER_1_8639999 */
static int hf_ulp_intervalBetweenFixes;           /* INTEGER_1_8639999 */
static int hf_ulp_startTime;                      /* INTEGER_0_2678400 */
static int hf_ulp_areaEventType;                  /* AreaEventType */
static int hf_ulp_locationEstimate;               /* BOOLEAN */
static int hf_ulp_repeatedReportingParams;        /* RepeatedReportingParams */
static int hf_ulp_stopTime;                       /* INTEGER_0_11318399 */
static int hf_ulp_geographicTargetAreaList;       /* GeographicTargetAreaList */
static int hf_ulp_areaIdLists;                    /* SEQUENCE_SIZE_1_maxAreaIdList_OF_AreaIdList */
static int hf_ulp_areaIdLists_item;               /* AreaIdList */
static int hf_ulp_minimumIntervalTime;            /* INTEGER_1_604800 */
static int hf_ulp_maximumNumberOfReports;         /* INTEGER_1_1024 */
static int hf_ulp_GeographicTargetAreaList_item;  /* GeographicTargetArea */
static int hf_ulp_circularArea;                   /* CircularArea */
static int hf_ulp_ellipticalArea;                 /* EllipticalArea */
static int hf_ulp_polygonArea;                    /* PolygonArea */
static int hf_ulp_areaIdSet;                      /* AreaIdSet */
static int hf_ulp_areaIdSetType;                  /* AreaIdSetType */
static int hf_ulp_geoAreaMappingList;             /* GeoAreaMappingList */
static int hf_ulp_AreaIdSet_item;                 /* AreaId */
static int hf_ulp_gSMAreaId;                      /* GSMAreaId */
static int hf_ulp_wCDMAAreaId;                    /* WCDMAAreaId */
static int hf_ulp_cDMAAreaId;                     /* CDMAAreaId */
static int hf_ulp_hRPDAreaId;                     /* HRPDAreaId */
static int hf_ulp_uMBAreaId;                      /* UMBAreaId */
static int hf_ulp_lTEAreaId;                      /* LTEAreaId */
static int hf_ulp_wLANAreaId;                     /* WLANAreaId */
static int hf_ulp_wiMAXAreaId;                    /* WimaxAreaId */
static int hf_ulp_nRAreaId;                       /* NRAreaId */
static int hf_ulp_refMCC;                         /* INTEGER_0_999 */
static int hf_ulp_refMNC;                         /* INTEGER_0_999 */
static int hf_ulp_refLAC;                         /* INTEGER_0_65535 */
static int hf_ulp_refCI;                          /* INTEGER_0_65535 */
static int hf_ulp_refUC;                          /* INTEGER_0_268435455 */
static int hf_ulp_refSID;                         /* INTEGER_0_65535 */
static int hf_ulp_refNID;                         /* INTEGER_0_32767 */
static int hf_ulp_refBASEID;                      /* INTEGER_0_65535 */
static int hf_ulp_refSECTORID;                    /* BIT_STRING_SIZE_128 */
static int hf_ulp_refCI_01;                       /* BIT_STRING_SIZE_29 */
static int hf_ulp_apMACAddress;                   /* T_apMACAddress */
static int hf_ulp_bsID_MSB;                       /* BIT_STRING_SIZE_24 */
static int hf_ulp_bsID_LSB;                       /* BIT_STRING_SIZE_24 */
static int hf_ulp_refCI_02;                       /* BIT_STRING_SIZE_36 */
static int hf_ulp_GeoAreaMappingList_item;        /* GeoAreaIndex */
static int hf_ulp_supportedNetworkInformation;    /* SupportedNetworkInformation */
static int hf_ulp_reportingMode;                  /* ReportingMode */
static int hf_ulp_gnssPosTechnology;              /* GNSSPosTechnology */
static int hf_ulp_repMode;                        /* RepModee */
static int hf_ulp_batchRepConditions;             /* BatchRepConditions */
static int hf_ulp_batchRepType;                   /* BatchRepType */
static int hf_ulp_num_interval;                   /* INTEGER_1_1024 */
static int hf_ulp_num_minutes;                    /* INTEGER_1_2048 */
static int hf_ulp_endofsession;                   /* NULL */
static int hf_ulp_reportPosition;                 /* BOOLEAN */
static int hf_ulp_reportMeasurements;             /* BOOLEAN */
static int hf_ulp_intermediateReports;            /* BOOLEAN */
static int hf_ulp_discardOldest;                  /* BOOLEAN */
static int hf_ulp_sessionList;                    /* SessionList */
static int hf_ulp_reportDataList;                 /* ReportDataList */
static int hf_ulp_moreComponents;                 /* NULL */
static int hf_ulp_SessionList_item;               /* SessionInformation */
static int hf_ulp_ReportDataList_item;            /* ReportData */
static int hf_ulp_positionData;                   /* PositionData */
static int hf_ulp_resultCode;                     /* ResultCode */
static int hf_ulp_timestamp;                      /* TimeStamp */
static int hf_ulp_ganssSignalsInfo;               /* GANSSsignalsInfo */
static int hf_ulp_GANSSsignalsInfo_item;          /* GANSSSignalsDescription */
static int hf_ulp_ganssId;                        /* INTEGER_0_15 */
static int hf_ulp_gANSSSignals;                   /* GANSSSignals */
static int hf_ulp_absoluteTime;                   /* UTCTime */
static int hf_ulp_relativeTime;                   /* INTEGER_0_31536000 */
static int hf_ulp_notificationMode;               /* NotificationMode */
static int hf_ulp_e_SLPAddress;                   /* SLPAddress */
static int hf_ulp_historicReporting;              /* HistoricReporting */
static int hf_ulp_protectionLevel;                /* ProtectionLevel */
static int hf_ulp_minimumMajorVersion;            /* INTEGER_0_255 */
static int hf_ulp_allowedReportingType;           /* AllowedReportingType */
static int hf_ulp_reportingCriteria;              /* ReportingCriteria */
static int hf_ulp_timeWindow;                     /* TimeWindow */
static int hf_ulp_maxNumberofReports;             /* INTEGER_1_65536 */
static int hf_ulp_minTimeInterval;                /* INTEGER_1_86400 */
static int hf_ulp_startTime_01;                   /* INTEGER_M525600_M1 */
static int hf_ulp_stopTime_01;                    /* INTEGER_M525599_0 */
static int hf_ulp_protlevel;                      /* ProtLevel */
static int hf_ulp_basicProtectionParams;          /* BasicProtectionParams */
static int hf_ulp_keyIdentifier;                  /* OCTET_STRING_SIZE_8 */
static int hf_ulp_basicReplayCounter;             /* INTEGER_0_65535 */
static int hf_ulp_basicMAC;                       /* BIT_STRING_SIZE_32 */
static int hf_ulp_initialApproximateposition;     /* Position */
static int hf_ulp_utran_GPSReferenceTimeResult;   /* UTRAN_GPSReferenceTimeResult */
static int hf_ulp_utran_GANSSReferenceTimeResult;  /* UTRAN_GANSSReferenceTimeResult */
static int hf_ulp_utran_GPSReferenceTimeAssistance;  /* UTRAN_GPSReferenceTimeAssistance */
static int hf_ulp_utran_GANSSReferenceTimeAssistance;  /* UTRAN_GANSSReferenceTimeAssistance */
static int hf_ulp_ver2_HighAccuracyPosition;      /* Ver2_HighAccuracyPosition */
static int hf_ulp_emergencyCallLocation;          /* NULL */
static int hf_ulp_serviceCapabilities;            /* ServiceCapabilities */
static int hf_ulp_supportedBearers;               /* SupportedBearers */
static int hf_ulp_servicesSupported;              /* ServicesSupported */
static int hf_ulp_reportingCapabilities;          /* ReportingCap */
static int hf_ulp_eventTriggerCapabilities;       /* EventTriggerCapabilities */
static int hf_ulp_sessionCapabilities;            /* SessionCapabilities */
static int hf_ulp_periodicTrigger;                /* BOOLEAN */
static int hf_ulp_areaEventTrigger;               /* BOOLEAN */
static int hf_ulp_geoAreaShapesSupported;         /* GeoAreaShapesSupported */
static int hf_ulp_maxNumGeoAreaSupported;         /* INTEGER_0_maxNumGeoArea */
static int hf_ulp_maxAreaIdListSupported;         /* INTEGER_0_maxAreaIdList */
static int hf_ulp_maxAreaIdSupportedPerList;      /* INTEGER_0_maxAreaId */
static int hf_ulp_ellipticalArea_01;              /* BOOLEAN */
static int hf_ulp_polygonArea_01;                 /* BOOLEAN */
static int hf_ulp_maxNumberTotalSessions;         /* INTEGER_1_128 */
static int hf_ulp_maxNumberPeriodicSessions;      /* INTEGER_1_32 */
static int hf_ulp_maxNumberTriggeredSessions;     /* INTEGER_1_32 */
static int hf_ulp_gsm;                            /* BOOLEAN */
static int hf_ulp_wcdma;                          /* BOOLEAN */
static int hf_ulp_lte;                            /* BOOLEAN */
static int hf_ulp_cdma;                           /* BOOLEAN */
static int hf_ulp_hprd;                           /* BOOLEAN */
static int hf_ulp_umb;                            /* BOOLEAN */
static int hf_ulp_wlan;                           /* BOOLEAN */
static int hf_ulp_wiMAX;                          /* BOOLEAN */
static int hf_ulp_nr;                             /* BOOLEAN */
static int hf_ulp_lpp;                            /* BOOLEAN */
static int hf_ulp_posProtocolVersionRRLP;         /* PosProtocolVersion3GPP */
static int hf_ulp_posProtocolVersionRRC;          /* PosProtocolVersion3GPP */
static int hf_ulp_posProtocolVersionTIA801;       /* PosProtocolVersion3GPP2 */
static int hf_ulp_posProtocolVersionLPP;          /* PosProtocolVersion3GPP */
static int hf_ulp_lppe;                           /* BOOLEAN */
static int hf_ulp_posProtocolVersionLPPe;         /* PosProtocolVersionOMA */
static int hf_ulp_majorVersionField;              /* INTEGER_0_255 */
static int hf_ulp_technicalVersionField;          /* INTEGER_0_255 */
static int hf_ulp_editorialVersionField;          /* INTEGER_0_255 */
static int hf_ulp_PosProtocolVersion3GPP2_item;   /* Supported3GPP2PosProtocolVersion */
static int hf_ulp_revisionNumber;                 /* BIT_STRING_SIZE_6 */
static int hf_ulp_pointReleaseNumber;             /* INTEGER_0_255 */
static int hf_ulp_internalEditLevel;              /* INTEGER_0_255 */
static int hf_ulp_minorVersionField;              /* INTEGER_0_255 */
static int hf_ulp_gANSSPositionMethods;           /* GANSSPositionMethods */
static int hf_ulp_additionalPositioningMethods;   /* AdditionalPositioningMethods */
static int hf_ulp_GANSSPositionMethods_item;      /* GANSSPositionMethod */
static int hf_ulp_ganssSBASid;                    /* T_ganssSBASid */
static int hf_ulp_gANSSPositioningMethodTypes;    /* GANSSPositioningMethodTypes */
static int hf_ulp_rtk;                            /* RTK */
static int hf_ulp_osr;                            /* BOOLEAN */
static int hf_ulp_setAssisted;                    /* BOOLEAN */
static int hf_ulp_setBased;                       /* BOOLEAN */
static int hf_ulp_autonomous;                     /* BOOLEAN */
static int hf_ulp_AdditionalPositioningMethods_item;  /* AddPosSupport_Element */
static int hf_ulp_addPosID;                       /* T_addPosID */
static int hf_ulp_addPosMode;                     /* T_addPosMode */
static int hf_ulp_ganssRequestedCommonAssistanceDataList;  /* GanssRequestedCommonAssistanceDataList */
static int hf_ulp_ganssRequestedGenericAssistanceDataList;  /* GanssRequestedGenericAssistanceDataList */
static int hf_ulp_extendedEphemeris;              /* ExtendedEphemeris */
static int hf_ulp_extendedEphemerisCheck;         /* ExtendedEphCheck */
static int hf_ulp_ganssReferenceTime;             /* BOOLEAN */
static int hf_ulp_ganssIonosphericModel;          /* BOOLEAN */
static int hf_ulp_ganssAdditionalIonosphericModelForDataID00;  /* BOOLEAN */
static int hf_ulp_ganssAdditionalIonosphericModelForDataID11;  /* BOOLEAN */
static int hf_ulp_ganssEarthOrientationParameters;  /* BOOLEAN */
static int hf_ulp_ganssAdditionalIonosphericModelForDataID01;  /* BOOLEAN */
static int hf_ulp_GanssRequestedGenericAssistanceDataList_item;  /* GanssReqGenericData */
static int hf_ulp_ganssId_01;                     /* T_ganssId */
static int hf_ulp_ganssSBASid_01;                 /* T_ganssSBASid_01 */
static int hf_ulp_ganssRealTimeIntegrity;         /* BOOLEAN */
static int hf_ulp_ganssDifferentialCorrection;    /* DGANSS_Sig_Id_Req */
static int hf_ulp_ganssAlmanac;                   /* BOOLEAN */
static int hf_ulp_ganssNavigationModelData;       /* GanssNavigationModelData */
static int hf_ulp_ganssTimeModels;                /* T_ganssTimeModels */
static int hf_ulp_ganssReferenceMeasurementInfo;  /* BOOLEAN */
static int hf_ulp_ganssDataBits;                  /* GanssDataBits */
static int hf_ulp_ganssUTCModel;                  /* BOOLEAN */
static int hf_ulp_ganssAdditionalDataChoices;     /* GanssAdditionalDataChoices */
static int hf_ulp_ganssAuxiliaryInformation;      /* BOOLEAN */
static int hf_ulp_ganssExtendedEphemeris;         /* ExtendedEphemeris */
static int hf_ulp_ganssExtendedEphemerisCheck;    /* GanssExtendedEphCheck */
static int hf_ulp_bds_DifferentialCorrection;     /* BDS_Sig_Id_Req */
static int hf_ulp_bds_GridModelReq;               /* BOOLEAN */
static int hf_ulp_ganssWeek;                      /* T_ganssWeek */
static int hf_ulp_ganssToe;                       /* T_ganssToe */
static int hf_ulp_t_toeLimit;                     /* T_t_toeLimit */
static int hf_ulp_satellitesListRelatedDataList;  /* SatellitesListRelatedDataList */
static int hf_ulp_SatellitesListRelatedDataList_item;  /* SatellitesListRelatedData */
static int hf_ulp_iod;                            /* INTEGER_0_1023 */
static int hf_ulp_ganssTODmin;                    /* INTEGER_0_59 */
static int hf_ulp_reqDataBitAssistanceList;       /* ReqDataBitAssistanceList */
static int hf_ulp_gnssSignals;                    /* GANSSSignals */
static int hf_ulp_ganssDataBitInterval;           /* INTEGER_0_15 */
static int hf_ulp_ganssDataBitSatList;            /* T_ganssDataBitSatList */
static int hf_ulp_ganssDataBitSatList_item;       /* INTEGER_0_63 */
static int hf_ulp_orbitModelID;                   /* INTEGER_0_7 */
static int hf_ulp_clockModelID;                   /* INTEGER_0_7 */
static int hf_ulp_utcModelID;                     /* INTEGER_0_7 */
static int hf_ulp_almanacModelID;                 /* INTEGER_0_7 */
static int hf_ulp_validity;                       /* INTEGER_1_256 */
static int hf_ulp_beginTime;                      /* GPSTime */
static int hf_ulp_endTime;                        /* GPSTime */
static int hf_ulp_beginTime_01;                   /* GANSSextEphTime */
static int hf_ulp_endTime_01;                     /* GANSSextEphTime */
static int hf_ulp_gPSWeek;                        /* INTEGER_0_1023 */
static int hf_ulp_gPSTOWhour;                     /* INTEGER_0_167 */
static int hf_ulp_gANSSday;                       /* INTEGER_0_8191 */
static int hf_ulp_gANSSTODhour;                   /* INTEGER_0_23 */
static int hf_ulp_lPPPayload;                     /* T_lPPPayload */
static int hf_ulp_lPPPayload_item;                /* T_lPPPayload_item */
static int hf_ulp_tia801Payload;                  /* T_tia801Payload */
static int hf_ulp_tia801Payload_item;             /* OCTET_STRING_SIZE_1_60000 */
static int hf_ulp_maj;                            /* INTEGER_0_255 */
static int hf_ulp_min;                            /* INTEGER_0_255 */
static int hf_ulp_servind;                        /* INTEGER_0_255 */
static int hf_ulp_setSessionID;                   /* SetSessionID */
static int hf_ulp_slpSessionID;                   /* SlpSessionID */
static int hf_ulp_sessionId;                      /* INTEGER_0_65535 */
static int hf_ulp_setId;                          /* SETId */
static int hf_ulp_msisdn;                         /* T_msisdn */
static int hf_ulp_mdn;                            /* T_mdn */
static int hf_ulp_minsi;                          /* BIT_STRING_SIZE_34 */
static int hf_ulp_imsi;                           /* T_imsi */
static int hf_ulp_nai;                            /* IA5String_SIZE_1_1000 */
static int hf_ulp_iPAddress;                      /* IPAddress */
static int hf_ulp_ver2_imei;                      /* OCTET_STRING_SIZE_8 */
static int hf_ulp_sessionSlpID;                   /* OCTET_STRING_SIZE_4 */
static int hf_ulp_slpId;                          /* SLPAddress */
static int hf_ulp_ipv4Address;                    /* OCTET_STRING_SIZE_4 */
static int hf_ulp_ipv6Address;                    /* OCTET_STRING_SIZE_16 */
static int hf_ulp_fqdn;                           /* FQDN */
static int hf_ulp_cellInfo;                       /* CellInfo */
static int hf_ulp_status;                         /* Status */
static int hf_ulp_gsmCell;                        /* GsmCellInformation */
static int hf_ulp_wcdmaCell;                      /* WcdmaCellInformation */
static int hf_ulp_cdmaCell;                       /* CdmaCellInformation */
static int hf_ulp_ver2_CellInfo_extension;        /* Ver2_CellInfo_extension */
static int hf_ulp_timestamp_01;                   /* UTCTime */
static int hf_ulp_positionEstimate;               /* PositionEstimate */
static int hf_ulp_latitudeSign;                   /* T_latitudeSign */
static int hf_ulp_latitude;                       /* INTEGER_0_8388607 */
static int hf_ulp_longitude;                      /* INTEGER_M8388608_8388607 */
static int hf_ulp_uncertainty;                    /* T_uncertainty */
static int hf_ulp_uncertaintySemiMajor;           /* INTEGER_0_127 */
static int hf_ulp_uncertaintySemiMinor;           /* INTEGER_0_127 */
static int hf_ulp_orientationMajorAxis;           /* INTEGER_0_180 */
static int hf_ulp_confidence;                     /* INTEGER_0_100 */
static int hf_ulp_altitudeInfo;                   /* AltitudeInfo */
static int hf_ulp_altitudeDirection;              /* T_altitudeDirection */
static int hf_ulp_altitude;                       /* INTEGER_0_32767 */
static int hf_ulp_altUncertainty;                 /* INTEGER_0_127 */
static int hf_ulp_refNID_01;                      /* INTEGER_0_65535 */
static int hf_ulp_refSID_01;                      /* INTEGER_0_32767 */
static int hf_ulp_refBASELAT;                     /* INTEGER_0_4194303 */
static int hf_ulp_reBASELONG;                     /* INTEGER_0_8388607 */
static int hf_ulp_refREFPN;                       /* INTEGER_0_511 */
static int hf_ulp_refWeekNumber;                  /* INTEGER_0_65535 */
static int hf_ulp_refSeconds;                     /* INTEGER_0_4194303 */
static int hf_ulp_nmr;                            /* NMR */
static int hf_ulp_ta;                             /* INTEGER_0_255 */
static int hf_ulp_frequencyInfo;                  /* FrequencyInfo */
static int hf_ulp_primaryScramblingCode;          /* INTEGER_0_511 */
static int hf_ulp_measuredResultsList;            /* MeasuredResultsList */
static int hf_ulp_cellParametersId;               /* INTEGER_0_127 */
static int hf_ulp_timingAdvance;                  /* TimingAdvance */
static int hf_ulp_ta_01;                          /* INTEGER_0_8191 */
static int hf_ulp_tAResolution;                   /* TAResolution */
static int hf_ulp_chipRate;                       /* ChipRate */
static int hf_ulp_modeSpecificFrequencyInfo;      /* FrequencySpecificInfo */
static int hf_ulp_fdd_fr;                         /* FrequencyInfoFDD */
static int hf_ulp_tdd_fr;                         /* FrequencyInfoTDD */
static int hf_ulp_uarfcn_UL;                      /* UARFCN */
static int hf_ulp_uarfcn_DL;                      /* UARFCN */
static int hf_ulp_uarfcn_Nt;                      /* UARFCN */
static int hf_ulp_NMR_item;                       /* NMRelement */
static int hf_ulp_arfcn;                          /* INTEGER_0_1023 */
static int hf_ulp_bsic;                           /* INTEGER_0_63 */
static int hf_ulp_rxLev;                          /* INTEGER_0_63 */
static int hf_ulp_MeasuredResultsList_item;       /* MeasuredResults */
static int hf_ulp_utra_CarrierRSSI;               /* UTRA_CarrierRSSI */
static int hf_ulp_cellMeasuredResultsList;        /* CellMeasuredResultsList */
static int hf_ulp_CellMeasuredResultsList_item;   /* CellMeasuredResults */
static int hf_ulp_cellIdentity;                   /* INTEGER_0_268435455 */
static int hf_ulp_modeSpecificInfo;               /* T_modeSpecificInfo */
static int hf_ulp_fdd;                            /* T_fdd */
static int hf_ulp_primaryCPICH_Info;              /* PrimaryCPICH_Info */
static int hf_ulp_cpich_Ec_N0;                    /* CPICH_Ec_N0 */
static int hf_ulp_cpich_RSCP;                     /* CPICH_RSCP */
static int hf_ulp_pathloss;                       /* Pathloss */
static int hf_ulp_tdd;                            /* T_tdd */
static int hf_ulp_cellParametersID;               /* CellParametersID */
static int hf_ulp_proposedTGSN;                   /* TGSN */
static int hf_ulp_primaryCCPCH_RSCP;              /* PrimaryCCPCH_RSCP */
static int hf_ulp_timeslotISCP_List;              /* TimeslotISCP_List */
static int hf_ulp_TimeslotISCP_List_item;         /* TimeslotISCP */
static int hf_ulp_horacc;                         /* INTEGER_0_127 */
static int hf_ulp_veracc;                         /* INTEGER_0_127 */
static int hf_ulp_maxLocAge;                      /* INTEGER_0_65535 */
static int hf_ulp_delay;                          /* INTEGER_0_7 */
static int hf_ulp_ver2_responseTime;              /* INTEGER_1_128 */
static int hf_ulp_horvel;                         /* Horvel */
static int hf_ulp_horandvervel;                   /* Horandvervel */
static int hf_ulp_horveluncert;                   /* Horveluncert */
static int hf_ulp_horandveruncert;                /* Horandveruncert */
static int hf_ulp_bearing;                        /* T_bearing */
static int hf_ulp_horspeed;                       /* T_horspeed */
static int hf_ulp_verdirect;                      /* T_verdirect */
static int hf_ulp_bearing_01;                     /* T_bearing_01 */
static int hf_ulp_horspeed_01;                    /* T_horspeed_01 */
static int hf_ulp_verspeed;                       /* T_verspeed */
static int hf_ulp_bearing_02;                     /* T_bearing_02 */
static int hf_ulp_horspeed_02;                    /* T_horspeed_02 */
static int hf_ulp_uncertspeed;                    /* T_uncertspeed */
static int hf_ulp_verdirect_01;                   /* T_verdirect_01 */
static int hf_ulp_bearing_03;                     /* T_bearing_03 */
static int hf_ulp_horspeed_03;                    /* T_horspeed_03 */
static int hf_ulp_verspeed_01;                    /* T_verspeed_01 */
static int hf_ulp_horuncertspeed;                 /* T_horuncertspeed */
static int hf_ulp_veruncertspeed;                 /* T_veruncertspeed */
static int hf_ulp_MultipleLocationIds_item;       /* LocationIdData */
static int hf_ulp_relativetimestamp;              /* RelativeTime */
static int hf_ulp_servingFlag;                    /* BOOLEAN */
static int hf_ulp_supportedWLANInfo;              /* SupportedWLANInfo */
static int hf_ulp_supportedWLANApsList;           /* SupportedWLANApsList */
static int hf_ulp_supportedWCDMAInfo;             /* SupportedWCDMAInfo */
static int hf_ulp_hrdp;                           /* BOOLEAN */
static int hf_ulp_wimax;                          /* BOOLEAN */
static int hf_ulp_historic;                       /* BOOLEAN */
static int hf_ulp_nonServing;                     /* BOOLEAN */
static int hf_ulp_uTRANGPSReferenceTime;          /* BOOLEAN */
static int hf_ulp_uTRANGANSSReferenceTime;        /* BOOLEAN */
static int hf_ulp_apTP;                           /* BOOLEAN */
static int hf_ulp_apAG;                           /* BOOLEAN */
static int hf_ulp_apSN;                           /* BOOLEAN */
static int hf_ulp_apDevType;                      /* BOOLEAN */
static int hf_ulp_apRSSI;                         /* BOOLEAN */
static int hf_ulp_apChanFreq;                     /* BOOLEAN */
static int hf_ulp_apRTD;                          /* BOOLEAN */
static int hf_ulp_setTP;                          /* BOOLEAN */
static int hf_ulp_setAG;                          /* BOOLEAN */
static int hf_ulp_setSN;                          /* BOOLEAN */
static int hf_ulp_setRSSI;                        /* BOOLEAN */
static int hf_ulp_apRepLoc;                       /* BOOLEAN */
static int hf_ulp_apRL;                           /* BOOLEAN */
static int hf_ulp_opClass;                        /* BOOLEAN */
static int hf_ulp_apSSID;                         /* BOOLEAN */
static int hf_ulp_apPHYType;                      /* BOOLEAN */
static int hf_ulp_setMACAddress;                  /* BOOLEAN */
static int hf_ulp_supportedWLANApDataList;        /* SEQUENCE_SIZE_1_maxWLANApDataSize_OF_SupportedWLANApData */
static int hf_ulp_supportedWLANApDataList_item;   /* SupportedWLANApData */
static int hf_ulp_supportedWLANapsChannel11a;     /* SupportedWLANApsChannel11a */
static int hf_ulp_supportedWLANapsChannel11bg;    /* SupportedWLANApsChannel11bg */
static int hf_ulp_ch34;                           /* BOOLEAN */
static int hf_ulp_ch36;                           /* BOOLEAN */
static int hf_ulp_ch38;                           /* BOOLEAN */
static int hf_ulp_ch40;                           /* BOOLEAN */
static int hf_ulp_ch42;                           /* BOOLEAN */
static int hf_ulp_ch44;                           /* BOOLEAN */
static int hf_ulp_ch46;                           /* BOOLEAN */
static int hf_ulp_ch48;                           /* BOOLEAN */
static int hf_ulp_ch52;                           /* BOOLEAN */
static int hf_ulp_ch56;                           /* BOOLEAN */
static int hf_ulp_ch60;                           /* BOOLEAN */
static int hf_ulp_ch64;                           /* BOOLEAN */
static int hf_ulp_ch149;                          /* BOOLEAN */
static int hf_ulp_ch153;                          /* BOOLEAN */
static int hf_ulp_ch157;                          /* BOOLEAN */
static int hf_ulp_ch161;                          /* BOOLEAN */
static int hf_ulp_ch1;                            /* BOOLEAN */
static int hf_ulp_ch2;                            /* BOOLEAN */
static int hf_ulp_ch3;                            /* BOOLEAN */
static int hf_ulp_ch4;                            /* BOOLEAN */
static int hf_ulp_ch5;                            /* BOOLEAN */
static int hf_ulp_ch6;                            /* BOOLEAN */
static int hf_ulp_ch7;                            /* BOOLEAN */
static int hf_ulp_ch8;                            /* BOOLEAN */
static int hf_ulp_ch9;                            /* BOOLEAN */
static int hf_ulp_ch10;                           /* BOOLEAN */
static int hf_ulp_ch11;                           /* BOOLEAN */
static int hf_ulp_ch12;                           /* BOOLEAN */
static int hf_ulp_ch13;                           /* BOOLEAN */
static int hf_ulp_ch14;                           /* BOOLEAN */
static int hf_ulp_apMACAddress_01;                /* T_apMACAddress_01 */
static int hf_ulp_apDevType_01;                   /* T_apDevType */
static int hf_ulp_mrl;                            /* BOOLEAN */
static int hf_ulp_hrpdCell;                       /* HrpdCellInformation */
static int hf_ulp_umbCell;                        /* UmbCellInformation */
static int hf_ulp_lteCell;                        /* LteCellInformation */
static int hf_ulp_wlanAP;                         /* WlanAPInformation */
static int hf_ulp_wimaxBS;                        /* WimaxBSInformation */
static int hf_ulp_nrCell;                         /* NRCellInformation */
static int hf_ulp_cellGlobalIdEUTRA;              /* CellGlobalIdEUTRA */
static int hf_ulp_physCellId;                     /* PhysCellId */
static int hf_ulp_trackingAreaCode;               /* TrackingAreaCode */
static int hf_ulp_rsrpResult;                     /* RSRP_Range */
static int hf_ulp_rsrqResult;                     /* RSRQ_Range */
static int hf_ulp_ta_02;                          /* INTEGER_0_1282 */
static int hf_ulp_measResultListEUTRA;            /* MeasResultListEUTRA */
static int hf_ulp_earfcn;                         /* INTEGER_0_65535 */
static int hf_ulp_earfcn_ext;                     /* INTEGER_65536_262143 */
static int hf_ulp_rsrpResult_ext;                 /* RSRP_Range_Ext */
static int hf_ulp_rsrqResult_ext;                 /* RSRQ_Range_Ext */
static int hf_ulp_rs_sinrResult;                  /* RS_SINR_Range */
static int hf_ulp_servingInformation5G;           /* ServingInformation5G */
static int hf_ulp_MeasResultListEUTRA_item;       /* MeasResultEUTRA */
static int hf_ulp_cgi_Info;                       /* T_cgi_Info */
static int hf_ulp_cellGlobalId;                   /* CellGlobalIdEUTRA */
static int hf_ulp_measResult;                     /* T_measResult */
static int hf_ulp_neighbourInformation5G;         /* NeighbourInformation5G */
static int hf_ulp_plmn_Identity;                  /* PLMN_Identity */
static int hf_ulp_cellIdentity_01;                /* CellIdentity */
static int hf_ulp_mcc;                            /* MCC */
static int hf_ulp_mnc;                            /* MNC */
static int hf_ulp_MCC_item;                       /* MCC_MNC_Digit */
static int hf_ulp_MNC_item;                       /* MCC_MNC_Digit */
static int hf_ulp_trackingAreaCode_01;            /* TrackingAreaCodeNR */
static int hf_ulp_apMACAddress_02;                /* T_apMACAddress_02 */
static int hf_ulp_apTransmitPower;                /* INTEGER_M127_128 */
static int hf_ulp_apAntennaGain;                  /* INTEGER_M127_128 */
static int hf_ulp_apSignaltoNoise;                /* INTEGER_M127_128 */
static int hf_ulp_apDeviceType;                   /* T_apDeviceType */
static int hf_ulp_apSignalStrength;               /* INTEGER_M127_128 */
static int hf_ulp_apChannelFrequency;             /* INTEGER_0_256 */
static int hf_ulp_apRoundTripDelay;               /* RTD */
static int hf_ulp_setTransmitPower;               /* INTEGER_M127_128 */
static int hf_ulp_setAntennaGain;                 /* INTEGER_M127_128 */
static int hf_ulp_setSignaltoNoise;               /* INTEGER_M127_128 */
static int hf_ulp_setSignalStrength;              /* INTEGER_M127_128 */
static int hf_ulp_apReportedLocation;             /* ReportedLocation */
static int hf_ulp_apRepLocation;                  /* RepLocation */
static int hf_ulp_apSignalStrengthDelta;          /* INTEGER_0_1 */
static int hf_ulp_apSignaltoNoiseDelta;           /* INTEGER_0_1 */
static int hf_ulp_setSignalStrengthDelta;         /* INTEGER_0_1 */
static int hf_ulp_setSignaltoNoiseDelta;          /* INTEGER_0_1 */
static int hf_ulp_operatingClass;                 /* INTEGER_0_255 */
static int hf_ulp_apSSID_01;                      /* T_apSSID */
static int hf_ulp_apPHYType_01;                   /* T_apPHYType */
static int hf_ulp_setMACAddress_01;               /* T_setMACAddress */
static int hf_ulp_rTDValue;                       /* INTEGER_0_16777216 */
static int hf_ulp_rTDUnits;                       /* RTDUnits */
static int hf_ulp_rTDAccuracy;                    /* INTEGER_0_255 */
static int hf_ulp_locationEncodingDescriptor;     /* LocationEncodingDescriptor */
static int hf_ulp_locationData;                   /* LocationData */
static int hf_ulp_locationAccuracy;               /* INTEGER_0_4294967295 */
static int hf_ulp_locationValue;                  /* OCTET_STRING_SIZE_1_128 */
static int hf_ulp_lciLocData;                     /* LciLocData */
static int hf_ulp_locationDataLCI;                /* LocationDataLCI */
static int hf_ulp_latitudeResolution;             /* BIT_STRING_SIZE_6 */
static int hf_ulp_latitude_01;                    /* BIT_STRING_SIZE_34 */
static int hf_ulp_longitudeResolution;            /* BIT_STRING_SIZE_6 */
static int hf_ulp_longitude_01;                   /* BIT_STRING_SIZE_34 */
static int hf_ulp_altitudeType;                   /* BIT_STRING_SIZE_4 */
static int hf_ulp_altitudeResolution;             /* BIT_STRING_SIZE_6 */
static int hf_ulp_altitude_01;                    /* BIT_STRING_SIZE_30 */
static int hf_ulp_datum;                          /* BIT_STRING_SIZE_8 */
static int hf_ulp_wimaxBsID;                      /* WimaxBsID */
static int hf_ulp_wimaxRTD;                       /* WimaxRTD */
static int hf_ulp_wimaxNMRList;                   /* WimaxNMRList */
static int hf_ulp_rtd;                            /* INTEGER_0_65535 */
static int hf_ulp_rTDstd;                         /* INTEGER_0_1023 */
static int hf_ulp_WimaxNMRList_item;              /* WimaxNMR */
static int hf_ulp_relDelay;                       /* INTEGER_M32768_32767 */
static int hf_ulp_relDelaystd;                    /* INTEGER_0_1023 */
static int hf_ulp_rssi;                           /* INTEGER_0_255 */
static int hf_ulp_rSSIstd;                        /* INTEGER_0_63 */
static int hf_ulp_bSTxPower;                      /* INTEGER_0_255 */
static int hf_ulp_cinr;                           /* INTEGER_0_255 */
static int hf_ulp_cINRstd;                        /* INTEGER_0_63 */
static int hf_ulp_bSLocation;                     /* ReportedLocation */
static int hf_ulp_servingCellInformation;         /* ServingCellInformationNR */
static int hf_ulp_measuredResultsListNR;          /* MeasResultListNR */
static int hf_ulp_ServingCellInformationNR_item;  /* ServCellNR */
static int hf_ulp_physCellId_01;                  /* PhysCellIdNR */
static int hf_ulp_arfcn_NR;                       /* ARFCN_NR */
static int hf_ulp_cellGlobalId_01;                /* CellGlobalIdNR */
static int hf_ulp_ssb_Measurements;               /* NR_Measurements */
static int hf_ulp_csi_rs_Measurements;            /* NR_Measurements */
static int hf_ulp_ta_03;                          /* INTEGER_0_3846 */
static int hf_ulp_MeasResultListNR_item;          /* MeasResultNR */
static int hf_ulp_cellIdentityNR;                 /* CellIdentityNR */
static int hf_ulp_rsrp_Range;                     /* INTEGER_0_127 */
static int hf_ulp_rsrq_Range;                     /* INTEGER_0_127 */
static int hf_ulp_sinr_Range;                     /* INTEGER_0_127 */
static int hf_ulp_utran_GPSReferenceTime;         /* UTRAN_GPSReferenceTime */
static int hf_ulp_gpsReferenceTimeUncertainty;    /* INTEGER_0_127 */
static int hf_ulp_utranGPSDriftRate;              /* UTRANGPSDriftRate */
static int hf_ulp_utran_GPSTimingOfCell;          /* T_utran_GPSTimingOfCell */
static int hf_ulp_ms_part;                        /* INTEGER_0_1023 */
static int hf_ulp_ls_part;                        /* INTEGER_0_4294967295 */
static int hf_ulp_modeSpecificInfo_01;            /* T_modeSpecificInfo_01 */
static int hf_ulp_fdd_01;                         /* T_fdd_01 */
static int hf_ulp_referenceIdentity;              /* PrimaryCPICH_Info */
static int hf_ulp_tdd_01;                         /* T_tdd_01 */
static int hf_ulp_referenceIdentity_01;           /* CellParametersID */
static int hf_ulp_sfn;                            /* INTEGER_0_4095 */
static int hf_ulp_set_GPSTimingOfCell;            /* T_set_GPSTimingOfCell */
static int hf_ulp_ms_part_01;                     /* INTEGER_0_16383 */
static int hf_ulp_modeSpecificInfo_02;            /* T_modeSpecificInfo_02 */
static int hf_ulp_fdd_02;                         /* T_fdd_02 */
static int hf_ulp_tdd_02;                         /* T_tdd_02 */
static int hf_ulp_ganssDay;                       /* INTEGER_0_8191 */
static int hf_ulp_ganssTimeID;                    /* INTEGER_0_15 */
static int hf_ulp_utran_GANSSReferenceTime;       /* UTRAN_GANSSReferenceTime */
static int hf_ulp_utranGANSSDriftRate;            /* UTRANGANSSDriftRate */
static int hf_ulp_ganssTOD;                       /* INTEGER_0_86399 */
static int hf_ulp_utran_GANSSTimingOfCell;        /* INTEGER_0_3999999 */
static int hf_ulp_modeSpecificInfo_03;            /* T_modeSpecificInfo_03 */
static int hf_ulp_fdd_03;                         /* T_fdd_03 */
static int hf_ulp_tdd_03;                         /* T_tdd_03 */
static int hf_ulp_ganss_TODUncertainty;           /* INTEGER_0_127 */
static int hf_ulp_set_GANSSReferenceTime;         /* SET_GANSSReferenceTime */
static int hf_ulp_set_GANSSTimingOfCell;          /* T_set_GANSSTimingOfCell */
static int hf_ulp_ms_part_02;                     /* INTEGER_0_80 */
static int hf_ulp_modeSpecificInfo_04;            /* T_modeSpecificInfo_04 */
static int hf_ulp_fdd_04;                         /* T_fdd_04 */
static int hf_ulp_tdd_04;                         /* T_tdd_04 */
static int hf_ulp_gps;                            /* BOOLEAN */
static int hf_ulp_galileo;                        /* BOOLEAN */
static int hf_ulp_sbas;                           /* BOOLEAN */
static int hf_ulp_modernized_gps;                 /* BOOLEAN */
static int hf_ulp_qzss;                           /* BOOLEAN */
static int hf_ulp_glonass;                        /* BOOLEAN */
static int hf_ulp_bds;                            /* BOOLEAN */
static int hf_ulp_rtk_osr;                        /* BOOLEAN */
static int hf_ulp_rand;                           /* BIT_STRING_SIZE_128 */
static int hf_ulp_slpFQDN;                        /* FQDN */
static int hf_ulp_ThirdParty_item;                /* ThirdPartyID */
static int hf_ulp_logicalName;                    /* IA5String_SIZE_1_1000 */
static int hf_ulp_msisdn_01;                      /* T_msisdn_01 */
static int hf_ulp_emailaddr;                      /* IA5String_SIZE_1_1000 */
static int hf_ulp_sip_uri;                        /* T_sip_uri */
static int hf_ulp_ims_public_identity;            /* T_ims_public_identity */
static int hf_ulp_min_01;                         /* BIT_STRING_SIZE_34 */
static int hf_ulp_mdn_01;                         /* T_mdn_01 */
static int hf_ulp_uri;                            /* T_uri */
static int hf_ulp_appProvider;                    /* IA5String_SIZE_1_24 */
static int hf_ulp_appName;                        /* IA5String_SIZE_1_32 */
static int hf_ulp_appVersion;                     /* IA5String_SIZE_1_8 */
static int hf_ulp_minInt;                         /* INTEGER_1_3600 */
static int hf_ulp_maxInt;                         /* INTEGER_1_1440 */
static int hf_ulp_repMode_01;                     /* RepMode */
static int hf_ulp_batchRepCap;                    /* BatchRepCap */
static int hf_ulp_realtime;                       /* BOOLEAN */
static int hf_ulp_quasirealtime;                  /* BOOLEAN */
static int hf_ulp_batch;                          /* BOOLEAN */
static int hf_ulp_report_position;                /* BOOLEAN */
static int hf_ulp_report_measurements;            /* BOOLEAN */
static int hf_ulp_max_num_positions;              /* INTEGER_1_1024 */
static int hf_ulp_max_num_measurements;           /* INTEGER_1_1024 */
static int hf_ulp_latitudeSign_01;                /* T_latitudeSign_01 */
static int hf_ulp_coordinateLatitude;             /* INTEGER_0_8388607 */
static int hf_ulp_coordinateLongitude;            /* INTEGER_M8388608_8388607 */
static int hf_ulp_coordinate;                     /* Coordinate */
static int hf_ulp_radius;                         /* INTEGER_1_1000000 */
static int hf_ulp_radius_min;                     /* INTEGER_1_1000000 */
static int hf_ulp_radius_max;                     /* INTEGER_1_1500000 */
static int hf_ulp_semiMajor;                      /* INTEGER_1_1000000 */
static int hf_ulp_semiMajor_min;                  /* INTEGER_1_1000000 */
static int hf_ulp_semiMajor_max;                  /* INTEGER_1_1500000 */
static int hf_ulp_semiMinor;                      /* INTEGER_1_1000000 */
static int hf_ulp_semiMinor_min;                  /* INTEGER_1_1000000 */
static int hf_ulp_semiMinor_max;                  /* INTEGER_1_1500000 */
static int hf_ulp_angle;                          /* INTEGER_0_179 */
static int hf_ulp_polygonDescription;             /* PolygonDescription */
static int hf_ulp_polygonHysteresis;              /* INTEGER_1_100000 */
static int hf_ulp_PolygonDescription_item;        /* Coordinate */
static int hf_ulp_highAccuracyPositionEstimate;   /* HighAccuracyPositionEstimate */
static int hf_ulp_degreesLatitude;                /* INTEGER_M2147483648_2147483647 */
static int hf_ulp_degreesLongitude;               /* INTEGER_M2147483648_2147483647 */
static int hf_ulp_uncertaintySemiMajor_01;        /* INTEGER_0_255 */
static int hf_ulp_uncertaintySemiMinor_01;        /* INTEGER_0_255 */
static int hf_ulp_orientationMajorAxis_01;        /* INTEGER_0_179 */
static int hf_ulp_horizontalConfidence;           /* INTEGER_0_100 */
static int hf_ulp_highAccuracyAltitudeInfo;       /* HighAccuracyAltitudeInfo */
static int hf_ulp_altitude_02;                    /* INTEGER_64000_1280000 */
static int hf_ulp_uncertaintyAltitude;            /* INTEGER_0_255 */
static int hf_ulp_verticalConfidence;             /* INTEGER_0_100 */
/* named bits */
static int hf_ulp_T_addPosMode_standalone;
static int hf_ulp_T_addPosMode_setBased;
static int hf_ulp_T_addPosMode_setAssisted;
static int hf_ulp_GANSSSignals_signal1;
static int hf_ulp_GANSSSignals_signal2;
static int hf_ulp_GANSSSignals_signal3;
static int hf_ulp_GANSSSignals_signal4;
static int hf_ulp_GANSSSignals_signal5;
static int hf_ulp_GANSSSignals_signal6;
static int hf_ulp_GANSSSignals_signal7;
static int hf_ulp_GANSSSignals_signal8;
static int hf_ulp_mobile_directory_number;
static int hf_ulp_ganssTimeModels_bit0;
static int hf_ulp_ganssTimeModels_bit1;
static int hf_ulp_ganssTimeModels_bit2;
static int hf_ulp_ganssTimeModels_bit3;
static int hf_ulp_ganssTimeModels_bit4;
static int hf_ulp_ganssTimeModels_spare;

/* Initialize the subtree pointers */
static int ett_ulp;
static int ett_ulp_setid;
static int ett_ulp_thirdPartyId;
static int ett_ulp_ganssTimeModels;
static int ett_ulp_ULP_PDU;
static int ett_ulp_UlpMessage;
static int ett_ulp_SUPLINIT;
static int ett_ulp_Notification;
static int ett_ulp_SUPLSTART;
static int ett_ulp_SETCapabilities;
static int ett_ulp_PosTechnology;
static int ett_ulp_PosProtocol;
static int ett_ulp_SUPLRESPONSE;
static int ett_ulp_SETAuthKey;
static int ett_ulp_SUPLPOSINIT;
static int ett_ulp_RequestedAssistData;
static int ett_ulp_NavigationModel;
static int ett_ulp_SatelliteInfo;
static int ett_ulp_SatelliteInfoElement;
static int ett_ulp_SUPLPOS;
static int ett_ulp_PosPayLoad;
static int ett_ulp_SUPLEND;
static int ett_ulp_SUPLAUTHREQ;
static int ett_ulp_SUPLAUTHRESP;
static int ett_ulp_Ver2_SUPLNOTIFY;
static int ett_ulp_Ver2_SUPLNOTIFYRESPONSE;
static int ett_ulp_Ver2_SUPLSETINIT;
static int ett_ulp_Ver2_SUPLTRIGGEREDSTART;
static int ett_ulp_TriggerParams;
static int ett_ulp_PeriodicParams;
static int ett_ulp_AreaEventParams;
static int ett_ulp_SEQUENCE_SIZE_1_maxAreaIdList_OF_AreaIdList;
static int ett_ulp_RepeatedReportingParams;
static int ett_ulp_GeographicTargetAreaList;
static int ett_ulp_GeographicTargetArea;
static int ett_ulp_AreaIdList;
static int ett_ulp_AreaIdSet;
static int ett_ulp_AreaId;
static int ett_ulp_GSMAreaId;
static int ett_ulp_WCDMAAreaId;
static int ett_ulp_CDMAAreaId;
static int ett_ulp_HRPDAreaId;
static int ett_ulp_UMBAreaId;
static int ett_ulp_LTEAreaId;
static int ett_ulp_WLANAreaId;
static int ett_ulp_WimaxAreaId;
static int ett_ulp_NRAreaId;
static int ett_ulp_GeoAreaMappingList;
static int ett_ulp_Ver2_SUPLTRIGGEREDRESPONSE;
static int ett_ulp_ReportingMode;
static int ett_ulp_BatchRepConditions;
static int ett_ulp_BatchRepType;
static int ett_ulp_Ver2_SUPLREPORT;
static int ett_ulp_SessionList;
static int ett_ulp_SessionInformation;
static int ett_ulp_ReportDataList;
static int ett_ulp_ReportData;
static int ett_ulp_PositionData;
static int ett_ulp_GANSSsignalsInfo;
static int ett_ulp_GANSSSignalsDescription;
static int ett_ulp_TimeStamp;
static int ett_ulp_Ver2_SUPLTRIGGEREDSTOP;
static int ett_ulp_Ver2_SUPL_INIT_extension;
static int ett_ulp_HistoricReporting;
static int ett_ulp_ReportingCriteria;
static int ett_ulp_TimeWindow;
static int ett_ulp_ProtectionLevel;
static int ett_ulp_BasicProtectionParams;
static int ett_ulp_Ver2_SUPL_START_extension;
static int ett_ulp_Ver2_SUPL_RESPONSE_extension;
static int ett_ulp_Ver2_SUPL_POS_INIT_extension;
static int ett_ulp_Ver2_SUPL_POS_extension;
static int ett_ulp_Ver2_SUPL_END_extension;
static int ett_ulp_Ver2_Notification_extension;
static int ett_ulp_Ver2_SETCapabilities_extension;
static int ett_ulp_ServiceCapabilities;
static int ett_ulp_ServicesSupported;
static int ett_ulp_EventTriggerCapabilities;
static int ett_ulp_GeoAreaShapesSupported;
static int ett_ulp_SessionCapabilities;
static int ett_ulp_SupportedBearers;
static int ett_ulp_Ver2_PosProtocol_extension;
static int ett_ulp_PosProtocolVersion3GPP;
static int ett_ulp_PosProtocolVersion3GPP2;
static int ett_ulp_Supported3GPP2PosProtocolVersion;
static int ett_ulp_PosProtocolVersionOMA;
static int ett_ulp_Ver2_PosTechnology_extension;
static int ett_ulp_GANSSPositionMethods;
static int ett_ulp_GANSSPositionMethod;
static int ett_ulp_RTK;
static int ett_ulp_GANSSPositioningMethodTypes;
static int ett_ulp_AdditionalPositioningMethods;
static int ett_ulp_AddPosSupport_Element;
static int ett_ulp_T_addPosMode;
static int ett_ulp_Ver2_RequestedAssistData_extension;
static int ett_ulp_GanssRequestedCommonAssistanceDataList;
static int ett_ulp_GanssRequestedGenericAssistanceDataList;
static int ett_ulp_GanssReqGenericData;
static int ett_ulp_GanssNavigationModelData;
static int ett_ulp_SatellitesListRelatedDataList;
static int ett_ulp_SatellitesListRelatedData;
static int ett_ulp_GanssDataBits;
static int ett_ulp_ReqDataBitAssistanceList;
static int ett_ulp_T_ganssDataBitSatList;
static int ett_ulp_GanssAdditionalDataChoices;
static int ett_ulp_ExtendedEphemeris;
static int ett_ulp_ExtendedEphCheck;
static int ett_ulp_GanssExtendedEphCheck;
static int ett_ulp_GPSTime;
static int ett_ulp_GANSSextEphTime;
static int ett_ulp_Ver2_PosPayLoad_extension;
static int ett_ulp_T_lPPPayload;
static int ett_ulp_T_tia801Payload;
static int ett_ulp_Version;
static int ett_ulp_SessionID;
static int ett_ulp_SetSessionID;
static int ett_ulp_SETId;
static int ett_ulp_SlpSessionID;
static int ett_ulp_IPAddress;
static int ett_ulp_SLPAddress;
static int ett_ulp_LocationId;
static int ett_ulp_CellInfo;
static int ett_ulp_Position;
static int ett_ulp_PositionEstimate;
static int ett_ulp_T_uncertainty;
static int ett_ulp_AltitudeInfo;
static int ett_ulp_CdmaCellInformation;
static int ett_ulp_GsmCellInformation;
static int ett_ulp_WcdmaCellInformation;
static int ett_ulp_TimingAdvance;
static int ett_ulp_FrequencyInfo;
static int ett_ulp_FrequencySpecificInfo;
static int ett_ulp_FrequencyInfoFDD;
static int ett_ulp_FrequencyInfoTDD;
static int ett_ulp_NMR;
static int ett_ulp_NMRelement;
static int ett_ulp_MeasuredResultsList;
static int ett_ulp_MeasuredResults;
static int ett_ulp_CellMeasuredResultsList;
static int ett_ulp_CellMeasuredResults;
static int ett_ulp_T_modeSpecificInfo;
static int ett_ulp_T_fdd;
static int ett_ulp_T_tdd;
static int ett_ulp_TimeslotISCP_List;
static int ett_ulp_PrimaryCPICH_Info;
static int ett_ulp_QoP;
static int ett_ulp_Velocity;
static int ett_ulp_Horvel;
static int ett_ulp_Horandvervel;
static int ett_ulp_Horveluncert;
static int ett_ulp_Horandveruncert;
static int ett_ulp_MultipleLocationIds;
static int ett_ulp_LocationIdData;
static int ett_ulp_SupportedNetworkInformation;
static int ett_ulp_SupportedWLANInfo;
static int ett_ulp_SupportedWLANApsList;
static int ett_ulp_SEQUENCE_SIZE_1_maxWLANApDataSize_OF_SupportedWLANApData;
static int ett_ulp_SupportedWLANApsChannel11a;
static int ett_ulp_SupportedWLANApsChannel11bg;
static int ett_ulp_SupportedWLANApData;
static int ett_ulp_SupportedWCDMAInfo;
static int ett_ulp_Ver2_CellInfo_extension;
static int ett_ulp_HrpdCellInformation;
static int ett_ulp_UmbCellInformation;
static int ett_ulp_LteCellInformation;
static int ett_ulp_MeasResultListEUTRA;
static int ett_ulp_MeasResultEUTRA;
static int ett_ulp_T_cgi_Info;
static int ett_ulp_T_measResult;
static int ett_ulp_CellGlobalIdEUTRA;
static int ett_ulp_PLMN_Identity;
static int ett_ulp_MCC;
static int ett_ulp_MNC;
static int ett_ulp_ServingInformation5G;
static int ett_ulp_NeighbourInformation5G;
static int ett_ulp_WlanAPInformation;
static int ett_ulp_RTD;
static int ett_ulp_ReportedLocation;
static int ett_ulp_LocationData;
static int ett_ulp_RepLocation;
static int ett_ulp_LciLocData;
static int ett_ulp_LocationDataLCI;
static int ett_ulp_WimaxBSInformation;
static int ett_ulp_WimaxBsID;
static int ett_ulp_WimaxRTD;
static int ett_ulp_WimaxNMRList;
static int ett_ulp_WimaxNMR;
static int ett_ulp_NRCellInformation;
static int ett_ulp_ServingCellInformationNR;
static int ett_ulp_ServCellNR;
static int ett_ulp_MeasResultListNR;
static int ett_ulp_MeasResultNR;
static int ett_ulp_CellGlobalIdNR;
static int ett_ulp_NR_Measurements;
static int ett_ulp_UTRAN_GPSReferenceTimeAssistance;
static int ett_ulp_UTRAN_GPSReferenceTime;
static int ett_ulp_T_utran_GPSTimingOfCell;
static int ett_ulp_T_modeSpecificInfo_01;
static int ett_ulp_T_fdd_01;
static int ett_ulp_T_tdd_01;
static int ett_ulp_UTRAN_GPSReferenceTimeResult;
static int ett_ulp_T_set_GPSTimingOfCell;
static int ett_ulp_T_modeSpecificInfo_02;
static int ett_ulp_T_fdd_02;
static int ett_ulp_T_tdd_02;
static int ett_ulp_UTRAN_GANSSReferenceTimeAssistance;
static int ett_ulp_UTRAN_GANSSReferenceTime;
static int ett_ulp_T_modeSpecificInfo_03;
static int ett_ulp_T_fdd_03;
static int ett_ulp_T_tdd_03;
static int ett_ulp_UTRAN_GANSSReferenceTimeResult;
static int ett_ulp_SET_GANSSReferenceTime;
static int ett_ulp_T_set_GANSSTimingOfCell;
static int ett_ulp_T_modeSpecificInfo_04;
static int ett_ulp_T_fdd_04;
static int ett_ulp_T_tdd_04;
static int ett_ulp_GNSSPosTechnology;
static int ett_ulp_GANSSSignals;
static int ett_ulp_SPCTID;
static int ett_ulp_ThirdParty;
static int ett_ulp_ThirdPartyID;
static int ett_ulp_ApplicationID;
static int ett_ulp_ReportingCap;
static int ett_ulp_RepMode;
static int ett_ulp_BatchRepCap;
static int ett_ulp_Coordinate;
static int ett_ulp_CircularArea;
static int ett_ulp_EllipticalArea;
static int ett_ulp_PolygonArea;
static int ett_ulp_PolygonDescription;
static int ett_ulp_Ver2_HighAccuracyPosition;
static int ett_ulp_HighAccuracyPositionEstimate;
static int ett_ulp_HighAccuracyAltitudeInfo;

static dissector_handle_t ulp_tcp_handle;
static dissector_handle_t ulp_pdu_handle;

static const value_string ulp_ganss_id_vals[] = {
  {  0, "Galileo"},
  {  1, "SBAS"},
  {  2, "Modernized GPS"},
  {  3, "QZSS"},
  {  4, "GLONASS"},
  {  5, "BDS"},
  {  0, NULL},
};

static const value_string ulp_ganss_sbas_id_vals[] = {
  {  0, "WAAS"},
  {  1, "EGNOS"},
  {  2, "MSAS"},
  {  3, "GAGAN"},
  {  0, NULL},
};

static void
ulp_ganssDataBitInterval_fmt(char *s, uint32_t v)
{
  if (v == 15) {
    snprintf(s, ITEM_LABEL_LENGTH, "Time interval is not specified (15)");
  } else {
    double interval = (0.1*pow(2, (double)v));

    snprintf(s, ITEM_LABEL_LENGTH, "%gs (%u)", interval, v);
  }
}

static void
ulp_ExtendedEphemeris_validity_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%uh (%u)", 4*v, v);
}

static void
ulp_PositionEstimate_latitude_fmt(char *s, uint32_t v)
{
  double latitude = ((double)v*90)/pow(2,23);

  snprintf(s, ITEM_LABEL_LENGTH, "%g degrees (%u)", latitude, v);
}

static void
ulp_PositionEstimate_longitude_fmt(char *s, uint32_t v)
{
  double longitude = ((double)(int32_t)v*360)/pow(2,24);

  snprintf(s, ITEM_LABEL_LENGTH, "%g degrees (%u)", longitude, v);
}

static void
ulp_NMRelement_rxLev_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RxLev < -110dBm (0)");
  } else if (v == 63) {
    snprintf(s, ITEM_LABEL_LENGTH, "RxLev >= -48dBm (63)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RxLev < %ddBm (%u)", -111+v, -110+v, v);
  }
}

static void
ulp_UTRA_CarrierRSSI_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSSI < -100dBm (0)");
  } else if (v == 76) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSSI >= -25dBm (76)");
  } else if (v > 76) {
    snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RSSI < %ddBm (%u)", -101+v, -100+v, v);
  }
}

static void
ulp_PrimaryCCPCH_RSCP_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSCP < -115dBm (0)");
  } else if (v == 91) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSCP >= -25dBm (91)");
  } else if (v > 91) {
    snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RSCP < %ddBm (%u)", -116+v, -115+v, v);
  }
}

static void
ulp_CPICH_Ec_N0_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "CPICH Ec/N0 < -24dB (0)");
  } else if (v == 49) {
    snprintf(s, ITEM_LABEL_LENGTH, "CPICH Ec/N0 >= 0dB (49)");
  } else if (v > 49) {
    snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= CPICH Ec/N0 < %.1fdB (%u)", -24.5+((float)v/2), -24+((float)v/2), v);
  }
}

static void
ulp_CPICH_RSCP_fmt(char *s, uint32_t v)
{
  if (v == 123) {
    snprintf(s, ITEM_LABEL_LENGTH, "CPICH RSCP < -120dBm (123)");
  } else if (v > 123) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= CPICH RSCP < %ddBm (%u)", -244+v, -243+v, v);
  } else if (v == 91) {
    snprintf(s, ITEM_LABEL_LENGTH, "CPICH RSCP >= -25dBm (91)");
  } else if (v < 91) {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm < CPICH RSCP <= %ddBm (%u)", -116+v, -115+v, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "Spare (%u)", v);
  }
}

static void
ulp_QoP_horacc_fmt(char *s, uint32_t v)
{
  double uncertainty = 10*(pow(1.1, (double)v)-1);

  if (uncertainty < 1000) {
    snprintf(s, ITEM_LABEL_LENGTH, "%fm (%u)", uncertainty, v);
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%fkm (%u)", uncertainty/1000, v);
  }
}

static void
ulp_QoP_veracc_fmt(char *s, uint32_t v)
{
  double uncertainty = 45*(pow(1.025, (double)v)-1);

  snprintf(s, ITEM_LABEL_LENGTH, "%fm (%u)", uncertainty, v);
}

static void
ulp_QoP_delay_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%gs (%u)", pow(2, (double)v), v);
}

static const true_false_string ulp_vertical_dir_val = {
  "Downward",
  "Upward"
};

static void
ulp_RelativeTime_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fs (%u)", 0.01*v, v);
}

static void
ulp_RSRP_Range_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRP < -140dBm (0)");
  } else if (v == 97) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRP >= -44dBm (97)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%ddBm <= RSRP < %ddBm (%u)", -141+v, -140+v, v);
  }
}

static void
ulp_RSRQ_Range_fmt(char *s, uint32_t v)
{
  if (v == 0) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRQ < -19.5dB (0)");
  } else if (v == 64) {
    snprintf(s, ITEM_LABEL_LENGTH, "RSRQ >= -3dB (34)");
  } else {
    snprintf(s, ITEM_LABEL_LENGTH, "%.1fdB <= RSRQ < %.1fdB (%u)", -20+((float)v/2), -19.5+((float)v/2), v);
  }
}

static void
ulp_SignalDelta_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%sdB (%u)", v ? "0.5" : "0", v);
}

static void
ulp_locationAccuracy_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.1fm (%u)", 0.1*v, v);
}

static void
ulp_WimaxRTD_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fus (%u)", 0.01*v, v);
}

static void
ulp_WimaxNMR_rssi_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fdBm (%u)", -103.75+(0.25*v), v);
}

static void
ulp_UTRAN_gpsReferenceTimeUncertainty_fmt(char *s, uint32_t v)
{
  double uncertainty = 0.0022*(pow(1.18, (double)v)-1);

  snprintf(s, ITEM_LABEL_LENGTH, "%fus (%u)", uncertainty, v);
}

static const value_string ulp_ganss_time_id_vals[] = {
  {  0, "Galileo"},
  {  1, "QZSS"},
  {  2, "GLONASS"},
  {  3, "BDS"},
  {  0, NULL},
};

static void
ulp_utran_GANSSTimingOfCell_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%.2fus (%u)", 0.25*v, v);
}

static void
ulp_Coordinate_latitude_fmt(char *s, uint32_t v)
{
  snprintf(s, ITEM_LABEL_LENGTH, "%f degrees (%u)",
             ((float)v/8388607.0)*90, v);
}

static void
ulp_Coordinate_longitude_fmt(char *s, uint32_t v)
{
  int32_t longitude = (int32_t) v;

  snprintf(s, ITEM_LABEL_LENGTH, "%f degrees (%d)",
             ((float)longitude/8388608.0)*180, longitude);
}

/* Include constants */
#define maxReqLength                   50
#define maxClientLength                50
#define maxNumGeoArea                  32
#define maxAreaId                      256
#define maxAreaIdList                  32
#define maxnumSessions                 64
#define maxGANSS                       16
#define maxGANSSSat                    32
#define maxCellMeas                    32
#define maxFreq                        8
#define maxTS                          14
#define maxLidSize                     64
#define maxWLANApDataSize              128
#define maxCellReport                  8
#define maxWimaxBSMeas                 32
#define maxNRServingCell               32
#define maxCellReportNR                32

typedef struct
{
  uint8_t notif_enc_type;
  uint8_t ganss_req_gen_data_ganss_id;
} ulp_private_data_t;

static ulp_private_data_t* ulp_get_private_data(asn1_ctx_t *actx)
{
  if (actx->private_data == NULL) {
    actx->private_data = wmem_new0(actx->pinfo->pool, ulp_private_data_t);
  }
  return (ulp_private_data_t*)actx->private_data;
}



static int
dissect_ulp_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t Version_sequence[] = {
  { &hf_ulp_maj             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_min             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_servind         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Version(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Version, Version_sequence);

  return offset;
}



static int
dissect_ulp_T_msisdn(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *msisdn_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, &msisdn_tvb);

  if (msisdn_tvb) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_ulp_setid);
    dissect_e164_msisdn(msisdn_tvb, subtree, 0, 8, E164_ENC_BCD);
  }


  return offset;
}



static int
dissect_ulp_T_mdn(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *mdn_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, &mdn_tvb);

  if (mdn_tvb) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_ulp_setid);
    proto_tree_add_item(subtree, hf_ulp_mobile_directory_number, mdn_tvb, 0, 8, ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN);
  }


  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_34(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     34, 34, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ulp_T_imsi(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *imsi_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, &imsi_tvb);

  if (imsi_tvb) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_ulp_setid);
    dissect_e212_imsi(imsi_tvb, actx->pinfo, subtree, 0, 8, false);
  }


  return offset;
}



static int
dissect_ulp_IA5String_SIZE_1_1000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 1000, false,
                                          NULL);

  return offset;
}



static int
dissect_ulp_OCTET_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}



static int
dissect_ulp_OCTET_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, false, NULL);

  return offset;
}


static const value_string ulp_IPAddress_vals[] = {
  {   0, "ipv4Address" },
  {   1, "ipv6Address" },
  { 0, NULL }
};

static const per_choice_t IPAddress_choice[] = {
  {   0, &hf_ulp_ipv4Address     , ASN1_NO_EXTENSIONS     , dissect_ulp_OCTET_STRING_SIZE_4 },
  {   1, &hf_ulp_ipv6Address     , ASN1_NO_EXTENSIONS     , dissect_ulp_OCTET_STRING_SIZE_16 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_IPAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_IPAddress, IPAddress_choice,
                                 NULL);

  return offset;
}



static int
dissect_ulp_OCTET_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}


static const value_string ulp_SETId_vals[] = {
  {   0, "msisdn" },
  {   1, "mdn" },
  {   2, "min" },
  {   3, "imsi" },
  {   4, "nai" },
  {   5, "iPAddress" },
  {   6, "ver2-imei" },
  { 0, NULL }
};

static const per_choice_t SETId_choice[] = {
  {   0, &hf_ulp_msisdn          , ASN1_EXTENSION_ROOT    , dissect_ulp_T_msisdn },
  {   1, &hf_ulp_mdn             , ASN1_EXTENSION_ROOT    , dissect_ulp_T_mdn },
  {   2, &hf_ulp_minsi           , ASN1_EXTENSION_ROOT    , dissect_ulp_BIT_STRING_SIZE_34 },
  {   3, &hf_ulp_imsi            , ASN1_EXTENSION_ROOT    , dissect_ulp_T_imsi },
  {   4, &hf_ulp_nai             , ASN1_EXTENSION_ROOT    , dissect_ulp_IA5String_SIZE_1_1000 },
  {   5, &hf_ulp_iPAddress       , ASN1_EXTENSION_ROOT    , dissect_ulp_IPAddress },
  {   6, &hf_ulp_ver2_imei       , ASN1_NOT_EXTENSION_ROOT, dissect_ulp_OCTET_STRING_SIZE_8 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_SETId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_SETId, SETId_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SetSessionID_sequence[] = {
  { &hf_ulp_sessionId       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_setId           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_SETId },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SetSessionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SetSessionID, SetSessionID_sequence);

  return offset;
}



static int
dissect_ulp_FQDN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 255, false, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-", 64,
                                                      NULL);

  return offset;
}


static const value_string ulp_SLPAddress_vals[] = {
  {   0, "iPAddress" },
  {   1, "fqdn" },
  { 0, NULL }
};

static const per_choice_t SLPAddress_choice[] = {
  {   0, &hf_ulp_iPAddress       , ASN1_EXTENSION_ROOT    , dissect_ulp_IPAddress },
  {   1, &hf_ulp_fqdn            , ASN1_EXTENSION_ROOT    , dissect_ulp_FQDN },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_SLPAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_SLPAddress, SLPAddress_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SlpSessionID_sequence[] = {
  { &hf_ulp_sessionSlpID    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_OCTET_STRING_SIZE_4 },
  { &hf_ulp_slpId           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_SLPAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SlpSessionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SlpSessionID, SlpSessionID_sequence);

  return offset;
}


static const per_sequence_t SessionID_sequence[] = {
  { &hf_ulp_setSessionID    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_SetSessionID },
  { &hf_ulp_slpSessionID    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_SlpSessionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SessionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SessionID, SessionID_sequence);

  return offset;
}


static const value_string ulp_PosMethod_vals[] = {
  {   0, "agpsSETassisted" },
  {   1, "agpsSETbased" },
  {   2, "agpsSETassistedpref" },
  {   3, "agpsSETbasedpref" },
  {   4, "autonomousGPS" },
  {   5, "aflt" },
  {   6, "ecid" },
  {   7, "eotd" },
  {   8, "otdoa" },
  {   9, "noPosition" },
  {  10, "ver2-historicalDataRetrieval" },
  {  11, "ver2-agnssSETassisted" },
  {  12, "ver2-agnssSETbased" },
  {  13, "ver2-agnssSETassistedpref" },
  {  14, "ver2-agnssSETbasedpref" },
  {  15, "ver2-autonomousGNSS" },
  {  16, "ver2-sessioninfoquery" },
  {  17, "ver2-mbs" },
  { 0, NULL }
};


static int
dissect_ulp_PosMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     10, NULL, true, 8, NULL);

  return offset;
}


static const value_string ulp_NotificationType_vals[] = {
  {   0, "noNotificationNoVerification" },
  {   1, "notificationOnly" },
  {   2, "notificationAndVerficationAllowedNA" },
  {   3, "notificationAndVerficationDeniedNA" },
  {   4, "privacyOverride" },
  { 0, NULL }
};


static int
dissect_ulp_NotificationType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const value_string ulp_EncodingType_vals[] = {
  {   0, "ucs2" },
  {   1, "gsmDefault" },
  {   2, "utf8" },
  { 0, NULL }
};


static int
dissect_ulp_EncodingType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t val;
  ulp_private_data_t *ulp_priv = ulp_get_private_data(actx);

  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, &val, true, 0, NULL);

  ulp_priv->notif_enc_type = (uint8_t) val;


  return offset;
}



static int
dissect_ulp_T_requestorId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       1, maxReqLength, false, &val_tvb);

  if (val_tvb) {
    ulp_private_data_t *ulp_priv = ulp_get_private_data(actx);
    switch(ulp_priv->notif_enc_type) {
      case 0: /* UCS-2 */
        actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0,
                                                 tvb_reported_length(val_tvb),
                                                 ENC_UCS_2|ENC_BIG_ENDIAN);
        break;
      case 1: /* GSM 7bits */
        actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0,
                                                 tvb_reported_length(val_tvb), ENC_3GPP_TS_23_038_7BITS|ENC_NA);
        break;
      case 2: /* UTF-8 */
        actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0,
                                                 tvb_reported_length(val_tvb), ENC_UTF_8|ENC_NA);
        break;
      default:
        actx->created_item = proto_tree_add_string(tree, hf_index, val_tvb, 0,
                                                   tvb_reported_length(val_tvb),
                                                   tvb_bytes_to_str(actx->pinfo->pool, val_tvb, 0,
                                                                    tvb_reported_length(val_tvb)));
        break;
    }
  }


  return offset;
}


static const value_string ulp_FormatIndicator_vals[] = {
  {   0, "logicalName" },
  {   1, "e-mailAddress" },
  {   2, "msisdn" },
  {   3, "url" },
  {   4, "sipUrl" },
  {   5, "min" },
  {   6, "mdn" },
  {   7, "iMSPublicidentity" },
  { 0, NULL }
};


static int
dissect_ulp_FormatIndicator(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     8, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ulp_T_clientName(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       1, maxClientLength, false, &val_tvb);

  if (val_tvb) {
    ulp_private_data_t *ulp_priv = ulp_get_private_data(actx);
    switch(ulp_priv->notif_enc_type) {
      case 0: /* UCS-2 */
        actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0,
                                                 tvb_reported_length(val_tvb),
                                                 ENC_UCS_2|ENC_BIG_ENDIAN);
        break;
      case 1: /* GSM 7bits */
        actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0,
                                                 tvb_reported_length(val_tvb), ENC_3GPP_TS_23_038_7BITS|ENC_NA);
        break;
      case 2: /* UTF-8 */
        actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0,
                                                 tvb_reported_length(val_tvb), ENC_UTF_8|ENC_NA);
        break;
      default:
        actx->created_item = proto_tree_add_string(tree, hf_index, val_tvb, 0,
                                                   tvb_reported_length(val_tvb),
                                                   tvb_bytes_to_str(actx->pinfo->pool, val_tvb, 0,
                                                                    tvb_reported_length(val_tvb)));
        break;
    }
  }


  return offset;
}



static int
dissect_ulp_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t Ver2_Notification_extension_sequence[] = {
  { &hf_ulp_emergencyCallLocation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_Notification_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_Notification_extension, Ver2_Notification_extension_sequence);

  return offset;
}


static const per_sequence_t Notification_sequence[] = {
  { &hf_ulp_notificationType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_NotificationType },
  { &hf_ulp_encodingType    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_EncodingType },
  { &hf_ulp_requestorId     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_requestorId },
  { &hf_ulp_requestorIdType , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_FormatIndicator },
  { &hf_ulp_clientName      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_clientName },
  { &hf_ulp_clientNameType  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_FormatIndicator },
  { &hf_ulp_ver2_Notification_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_Ver2_Notification_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Notification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ulp_private_data_t *ulp_priv = ulp_get_private_data(actx);

  ulp_priv->notif_enc_type = -1;
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Notification, Notification_sequence);



  return offset;
}



static int
dissect_ulp_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_1_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 128U, NULL, false);

  return offset;
}


static const per_sequence_t QoP_sequence[] = {
  { &hf_ulp_horacc          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_127 },
  { &hf_ulp_veracc          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_127 },
  { &hf_ulp_maxLocAge       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_delay           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_7 },
  { &hf_ulp_ver2_responseTime, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_INTEGER_1_128 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_QoP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_QoP, QoP_sequence);

  return offset;
}


static const value_string ulp_SLPMode_vals[] = {
  {   0, "proxy" },
  {   1, "nonProxy" },
  { 0, NULL }
};


static int
dissect_ulp_SLPMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_ulp_MAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ulp_KeyIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string ulp_NotificationMode_vals[] = {
  {   0, "normal" },
  {   1, "basedOnLocation" },
  { 0, NULL }
};


static int
dissect_ulp_NotificationMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ulp_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t SupportedWLANInfo_sequence[] = {
  { &hf_ulp_apTP            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_apAG            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_apSN            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_apDevType       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_apRSSI          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_apChanFreq      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_apRTD           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_setTP           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_setAG           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_setSN           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_setRSSI         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_apRepLoc        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_apRL            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_BOOLEAN },
  { &hf_ulp_opClass         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_BOOLEAN },
  { &hf_ulp_apSSID          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_BOOLEAN },
  { &hf_ulp_apPHYType       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_BOOLEAN },
  { &hf_ulp_setMACAddress   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SupportedWLANInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SupportedWLANInfo, SupportedWLANInfo_sequence);

  return offset;
}



static int
dissect_ulp_T_apMACAddress_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     48, 48, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    proto_tree_add_item(tree, hf_index, val_tvb, 0, 6, ENC_NA);
  }


  return offset;
}


static const value_string ulp_T_apDevType_vals[] = {
  {   0, "wlan802-11a" },
  {   1, "wlan802-11b" },
  {   2, "wlan802-11g" },
  { 0, NULL }
};


static int
dissect_ulp_T_apDevType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t SupportedWLANApData_sequence[] = {
  { &hf_ulp_apMACAddress_01 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_apMACAddress_01 },
  { &hf_ulp_apDevType_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_apDevType },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SupportedWLANApData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SupportedWLANApData, SupportedWLANApData_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxWLANApDataSize_OF_SupportedWLANApData_sequence_of[1] = {
  { &hf_ulp_supportedWLANApDataList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_SupportedWLANApData },
};

static int
dissect_ulp_SEQUENCE_SIZE_1_maxWLANApDataSize_OF_SupportedWLANApData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_SEQUENCE_SIZE_1_maxWLANApDataSize_OF_SupportedWLANApData, SEQUENCE_SIZE_1_maxWLANApDataSize_OF_SupportedWLANApData_sequence_of,
                                                  1, maxWLANApDataSize, false);

  return offset;
}


static const per_sequence_t SupportedWLANApsChannel11a_sequence[] = {
  { &hf_ulp_ch34            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch36            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch38            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch40            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch42            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch44            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch46            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch48            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch52            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch56            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch60            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch64            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch149           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch153           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch157           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch161           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SupportedWLANApsChannel11a(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SupportedWLANApsChannel11a, SupportedWLANApsChannel11a_sequence);

  return offset;
}


static const per_sequence_t SupportedWLANApsChannel11bg_sequence[] = {
  { &hf_ulp_ch1             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch2             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch3             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch4             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch5             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch6             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch7             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch8             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch9             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch10            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch11            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch12            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch13            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ch14            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SupportedWLANApsChannel11bg(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SupportedWLANApsChannel11bg, SupportedWLANApsChannel11bg_sequence);

  return offset;
}


static const per_sequence_t SupportedWLANApsList_sequence[] = {
  { &hf_ulp_supportedWLANApDataList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SEQUENCE_SIZE_1_maxWLANApDataSize_OF_SupportedWLANApData },
  { &hf_ulp_supportedWLANapsChannel11a, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SupportedWLANApsChannel11a },
  { &hf_ulp_supportedWLANapsChannel11bg, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SupportedWLANApsChannel11bg },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SupportedWLANApsList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SupportedWLANApsList, SupportedWLANApsList_sequence);

  return offset;
}


static const per_sequence_t SupportedWCDMAInfo_sequence[] = {
  { &hf_ulp_mrl             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SupportedWCDMAInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SupportedWCDMAInfo, SupportedWCDMAInfo_sequence);

  return offset;
}


static const per_sequence_t SupportedNetworkInformation_sequence[] = {
  { &hf_ulp_wlan            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_supportedWLANInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SupportedWLANInfo },
  { &hf_ulp_supportedWLANApsList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SupportedWLANApsList },
  { &hf_ulp_gsm             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_wcdma           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_supportedWCDMAInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SupportedWCDMAInfo },
  { &hf_ulp_cdma            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_hrdp            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_umb             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_lte             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_wimax           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_historic        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_nonServing      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_uTRANGPSReferenceTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_uTRANGANSSReferenceTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_nr              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SupportedNetworkInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SupportedNetworkInformation, SupportedNetworkInformation_sequence);

  return offset;
}


static const value_string ulp_TriggerType_vals[] = {
  {   0, "periodic" },
  {   1, "areaEvent" },
  { 0, NULL }
};


static int
dissect_ulp_TriggerType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const value_string ulp_AllowedReportingType_vals[] = {
  {   0, "positionsOnly" },
  {   1, "measurementsOnly" },
  {   2, "positionsAndMeasurements" },
  { 0, NULL }
};


static int
dissect_ulp_AllowedReportingType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ulp_INTEGER_M525600_M1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -525600, -1, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_M525599_0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -525599, 0U, NULL, false);

  return offset;
}


static const per_sequence_t TimeWindow_sequence[] = {
  { &hf_ulp_startTime_01    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_M525600_M1 },
  { &hf_ulp_stopTime_01     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_M525599_0 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_TimeWindow(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_TimeWindow, TimeWindow_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_1_65536(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 65536U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_1_86400(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 86400U, NULL, false);

  return offset;
}


static const per_sequence_t ReportingCriteria_sequence[] = {
  { &hf_ulp_timeWindow      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_TimeWindow },
  { &hf_ulp_maxNumberofReports, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_1_65536 },
  { &hf_ulp_minTimeInterval , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_1_86400 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ReportingCriteria(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ReportingCriteria, ReportingCriteria_sequence);

  return offset;
}


static const per_sequence_t HistoricReporting_sequence[] = {
  { &hf_ulp_allowedReportingType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_AllowedReportingType },
  { &hf_ulp_reportingCriteria, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ReportingCriteria },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_HistoricReporting(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_HistoricReporting, HistoricReporting_sequence);

  return offset;
}


static const value_string ulp_ProtLevel_vals[] = {
  {   0, "nullProtection" },
  {   1, "basicProtection" },
  { 0, NULL }
};


static int
dissect_ulp_ProtLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t BasicProtectionParams_sequence[] = {
  { &hf_ulp_keyIdentifier   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_OCTET_STRING_SIZE_8 },
  { &hf_ulp_basicReplayCounter, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_basicMAC        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_32 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_BasicProtectionParams(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_BasicProtectionParams, BasicProtectionParams_sequence);

  return offset;
}


static const per_sequence_t ProtectionLevel_sequence[] = {
  { &hf_ulp_protlevel       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_ProtLevel },
  { &hf_ulp_basicProtectionParams, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_BasicProtectionParams },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ProtectionLevel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ProtectionLevel, ProtectionLevel_sequence);

  return offset;
}


static const per_sequence_t GNSSPosTechnology_sequence[] = {
  { &hf_ulp_gps             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_galileo         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_sbas            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_modernized_gps  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_qzss            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_glonass         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_bds             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_BOOLEAN },
  { &hf_ulp_rtk_osr         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GNSSPosTechnology(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GNSSPosTechnology, GNSSPosTechnology_sequence);

  return offset;
}


static const per_sequence_t Ver2_SUPL_INIT_extension_sequence[] = {
  { &hf_ulp_notificationMode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_NotificationMode },
  { &hf_ulp_supportedNetworkInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SupportedNetworkInformation },
  { &hf_ulp_triggerType     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_TriggerType },
  { &hf_ulp_e_SLPAddress    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SLPAddress },
  { &hf_ulp_historicReporting, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_HistoricReporting },
  { &hf_ulp_protectionLevel , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ProtectionLevel },
  { &hf_ulp_gnssPosTechnology, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_GNSSPosTechnology },
  { &hf_ulp_minimumMajorVersion, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SUPL_INIT_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SUPL_INIT_extension, Ver2_SUPL_INIT_extension_sequence);

  return offset;
}


static const per_sequence_t SUPLINIT_sequence[] = {
  { &hf_ulp_posMethod       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PosMethod },
  { &hf_ulp_notification    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Notification },
  { &hf_ulp_sLPAddress      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SLPAddress },
  { &hf_ulp_qoP             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_QoP },
  { &hf_ulp_sLPMode         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SLPMode },
  { &hf_ulp_mac             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_MAC },
  { &hf_ulp_keyIdentity     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_KeyIdentity },
  { &hf_ulp_ver2_SUPL_INIT_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_Ver2_SUPL_INIT_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLINIT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLINIT, SUPLINIT_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}



static int
dissect_ulp_T_ganssSBASid(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     3, 3, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    proto_tree_add_bits_item(tree, hf_index, val_tvb, 0, 3, ENC_NA);
  }


  return offset;
}


static const per_sequence_t GANSSPositioningMethodTypes_sequence[] = {
  { &hf_ulp_setAssisted     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_setBased        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_autonomous      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GANSSPositioningMethodTypes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GANSSPositioningMethodTypes, GANSSPositioningMethodTypes_sequence);

  return offset;
}


static int * const GANSSSignals_bits[] = {
  &hf_ulp_GANSSSignals_signal1,
  &hf_ulp_GANSSSignals_signal2,
  &hf_ulp_GANSSSignals_signal3,
  &hf_ulp_GANSSSignals_signal4,
  &hf_ulp_GANSSSignals_signal5,
  &hf_ulp_GANSSSignals_signal6,
  &hf_ulp_GANSSSignals_signal7,
  &hf_ulp_GANSSSignals_signal8,
  NULL
};

static int
dissect_ulp_GANSSSignals(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 8, false, GANSSSignals_bits, 8, NULL, NULL);

  return offset;
}


static const per_sequence_t RTK_sequence[] = {
  { &hf_ulp_osr             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_RTK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_RTK, RTK_sequence);

  return offset;
}


static const per_sequence_t GANSSPositionMethod_sequence[] = {
  { &hf_ulp_ganssId         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_15 },
  { &hf_ulp_ganssSBASid     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_ganssSBASid },
  { &hf_ulp_gANSSPositioningMethodTypes, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_GANSSPositioningMethodTypes },
  { &hf_ulp_gANSSSignals    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_GANSSSignals },
  { &hf_ulp_rtk             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_RTK },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GANSSPositionMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GANSSPositionMethod, GANSSPositionMethod_sequence);

  return offset;
}


static const per_sequence_t GANSSPositionMethods_sequence_of[1] = {
  { &hf_ulp_GANSSPositionMethods_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_GANSSPositionMethod },
};

static int
dissect_ulp_GANSSPositionMethods(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_GANSSPositionMethods, GANSSPositionMethods_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const value_string ulp_T_addPosID_vals[] = {
  {   0, "mBS" },
  { 0, NULL }
};


static int
dissect_ulp_T_addPosID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static int * const T_addPosMode_bits[] = {
  &hf_ulp_T_addPosMode_standalone,
  &hf_ulp_T_addPosMode_setBased,
  &hf_ulp_T_addPosMode_setAssisted,
  NULL
};

static int
dissect_ulp_T_addPosMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 8, false, T_addPosMode_bits, 3, NULL, NULL);

  return offset;
}


static const per_sequence_t AddPosSupport_Element_sequence[] = {
  { &hf_ulp_addPosID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_addPosID },
  { &hf_ulp_addPosMode      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_addPosMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_AddPosSupport_Element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_AddPosSupport_Element, AddPosSupport_Element_sequence);

  return offset;
}


static const per_sequence_t AdditionalPositioningMethods_sequence_of[1] = {
  { &hf_ulp_AdditionalPositioningMethods_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_AddPosSupport_Element },
};

static int
dissect_ulp_AdditionalPositioningMethods(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_AdditionalPositioningMethods, AdditionalPositioningMethods_sequence_of,
                                                  1, 8, false);

  return offset;
}


static const per_sequence_t Ver2_PosTechnology_extension_sequence[] = {
  { &hf_ulp_gANSSPositionMethods, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_GANSSPositionMethods },
  { &hf_ulp_additionalPositioningMethods, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_AdditionalPositioningMethods },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_PosTechnology_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_PosTechnology_extension, Ver2_PosTechnology_extension_sequence);

  return offset;
}


static const per_sequence_t PosTechnology_sequence[] = {
  { &hf_ulp_agpsSETassisted , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_agpsSETBased    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_autonomousGPS   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_aflt            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ecid            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_eotd            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_otdoa           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ver2_PosTechnology_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_Ver2_PosTechnology_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PosTechnology(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_PosTechnology, PosTechnology_sequence);

  return offset;
}


static const value_string ulp_PrefMethod_vals[] = {
  {   0, "agpsSETassistedPreferred" },
  {   1, "agpsSETBasedPreferred" },
  {   2, "noPreference" },
  { 0, NULL }
};


static int
dissect_ulp_PrefMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t PosProtocolVersion3GPP_sequence[] = {
  { &hf_ulp_majorVersionField, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_technicalVersionField, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_editorialVersionField, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PosProtocolVersion3GPP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_PosProtocolVersion3GPP, PosProtocolVersion3GPP_sequence);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t Supported3GPP2PosProtocolVersion_sequence[] = {
  { &hf_ulp_revisionNumber  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_6 },
  { &hf_ulp_pointReleaseNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_internalEditLevel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Supported3GPP2PosProtocolVersion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Supported3GPP2PosProtocolVersion, Supported3GPP2PosProtocolVersion_sequence);

  return offset;
}


static const per_sequence_t PosProtocolVersion3GPP2_sequence_of[1] = {
  { &hf_ulp_PosProtocolVersion3GPP2_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_Supported3GPP2PosProtocolVersion },
};

static int
dissect_ulp_PosProtocolVersion3GPP2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_PosProtocolVersion3GPP2, PosProtocolVersion3GPP2_sequence_of,
                                                  1, 8, false);

  return offset;
}


static const per_sequence_t PosProtocolVersionOMA_sequence[] = {
  { &hf_ulp_majorVersionField, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_minorVersionField, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PosProtocolVersionOMA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_PosProtocolVersionOMA, PosProtocolVersionOMA_sequence);

  return offset;
}


static const per_sequence_t Ver2_PosProtocol_extension_sequence[] = {
  { &hf_ulp_lpp             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_posProtocolVersionRRLP, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_PosProtocolVersion3GPP },
  { &hf_ulp_posProtocolVersionRRC, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_PosProtocolVersion3GPP },
  { &hf_ulp_posProtocolVersionTIA801, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_PosProtocolVersion3GPP2 },
  { &hf_ulp_posProtocolVersionLPP, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_PosProtocolVersion3GPP },
  { &hf_ulp_lppe            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_BOOLEAN },
  { &hf_ulp_posProtocolVersionLPPe, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_PosProtocolVersionOMA },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_PosProtocol_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_PosProtocol_extension, Ver2_PosProtocol_extension_sequence);

  return offset;
}


static const per_sequence_t PosProtocol_sequence[] = {
  { &hf_ulp_tia801          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_rrlp            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_rrc             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ver2_PosProtocol_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_Ver2_PosProtocol_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PosProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_PosProtocol, PosProtocol_sequence);

  return offset;
}


static const per_sequence_t ServicesSupported_sequence[] = {
  { &hf_ulp_periodicTrigger , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_areaEventTrigger, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ServicesSupported(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ServicesSupported, ServicesSupported_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_1_3600(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 3600U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_1_1440(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1440U, NULL, false);

  return offset;
}


static const per_sequence_t RepMode_sequence[] = {
  { &hf_ulp_realtime        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_quasirealtime   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_batch           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_RepMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_RepMode, RepMode_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_1_1024(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1024U, NULL, false);

  return offset;
}


static const per_sequence_t BatchRepCap_sequence[] = {
  { &hf_ulp_report_position , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_report_measurements, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_max_num_positions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_1_1024 },
  { &hf_ulp_max_num_measurements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_1_1024 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_BatchRepCap(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_BatchRepCap, BatchRepCap_sequence);

  return offset;
}


static const per_sequence_t ReportingCap_sequence[] = {
  { &hf_ulp_minInt          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_1_3600 },
  { &hf_ulp_maxInt          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_1_1440 },
  { &hf_ulp_repMode_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_RepMode },
  { &hf_ulp_batchRepCap     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_BatchRepCap },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ReportingCap(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ReportingCap, ReportingCap_sequence);

  return offset;
}


static const per_sequence_t GeoAreaShapesSupported_sequence[] = {
  { &hf_ulp_ellipticalArea_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_polygonArea_01  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GeoAreaShapesSupported(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GeoAreaShapesSupported, GeoAreaShapesSupported_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_maxNumGeoArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxNumGeoArea, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_maxAreaIdList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxAreaIdList, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_maxAreaId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, maxAreaId, NULL, false);

  return offset;
}


static const per_sequence_t EventTriggerCapabilities_sequence[] = {
  { &hf_ulp_geoAreaShapesSupported, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_GeoAreaShapesSupported },
  { &hf_ulp_maxNumGeoAreaSupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_maxNumGeoArea },
  { &hf_ulp_maxAreaIdListSupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_maxAreaIdList },
  { &hf_ulp_maxAreaIdSupportedPerList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_maxAreaId },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_EventTriggerCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_EventTriggerCapabilities, EventTriggerCapabilities_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, false);

  return offset;
}


static const per_sequence_t SessionCapabilities_sequence[] = {
  { &hf_ulp_maxNumberTotalSessions, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_1_128 },
  { &hf_ulp_maxNumberPeriodicSessions, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_1_32 },
  { &hf_ulp_maxNumberTriggeredSessions, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_1_32 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SessionCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SessionCapabilities, SessionCapabilities_sequence);

  return offset;
}


static const per_sequence_t ServiceCapabilities_sequence[] = {
  { &hf_ulp_servicesSupported, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_ServicesSupported },
  { &hf_ulp_reportingCapabilities, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ReportingCap },
  { &hf_ulp_eventTriggerCapabilities, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_EventTriggerCapabilities },
  { &hf_ulp_sessionCapabilities, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SessionCapabilities },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ServiceCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ServiceCapabilities, ServiceCapabilities_sequence);

  return offset;
}


static const per_sequence_t SupportedBearers_sequence[] = {
  { &hf_ulp_gsm             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_wcdma           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_lte             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_cdma            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_hprd            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_umb             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_wlan            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_wiMAX           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_nr              , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SupportedBearers(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SupportedBearers, SupportedBearers_sequence);

  return offset;
}


static const per_sequence_t Ver2_SETCapabilities_extension_sequence[] = {
  { &hf_ulp_serviceCapabilities, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ServiceCapabilities },
  { &hf_ulp_supportedBearers, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_SupportedBearers },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SETCapabilities_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SETCapabilities_extension, Ver2_SETCapabilities_extension_sequence);

  return offset;
}


static const per_sequence_t SETCapabilities_sequence[] = {
  { &hf_ulp_posTechnology   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PosTechnology },
  { &hf_ulp_prefMethod      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PrefMethod },
  { &hf_ulp_posProtocol     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PosProtocol },
  { &hf_ulp_ver2_SETCapabilities_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_Ver2_SETCapabilities_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SETCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SETCapabilities, SETCapabilities_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 999U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}


static const per_sequence_t NMRelement_sequence[] = {
  { &hf_ulp_arfcn           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_1023 },
  { &hf_ulp_bsic            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_63 },
  { &hf_ulp_rxLev           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_63 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_NMRelement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_NMRelement, NMRelement_sequence);

  return offset;
}


static const per_sequence_t NMR_sequence_of[1] = {
  { &hf_ulp_NMR_item        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_NMRelement },
};

static int
dissect_ulp_NMR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_NMR, NMR_sequence_of,
                                                  1, 15, false);

  return offset;
}


static const per_sequence_t GsmCellInformation_sequence[] = {
  { &hf_ulp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refLAC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_refCI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_nmr             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_NMR },
  { &hf_ulp_ta              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GsmCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GsmCellInformation, GsmCellInformation_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_268435455(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 268435455U, NULL, false);

  return offset;
}



static int
dissect_ulp_UARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, false);

  return offset;
}


static const per_sequence_t FrequencyInfoFDD_sequence[] = {
  { &hf_ulp_uarfcn_UL       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_UARFCN },
  { &hf_ulp_uarfcn_DL       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_UARFCN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_FrequencyInfoFDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_FrequencyInfoFDD, FrequencyInfoFDD_sequence);

  return offset;
}


static const per_sequence_t FrequencyInfoTDD_sequence[] = {
  { &hf_ulp_uarfcn_Nt       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_UARFCN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_FrequencyInfoTDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_FrequencyInfoTDD, FrequencyInfoTDD_sequence);

  return offset;
}


static const value_string ulp_FrequencySpecificInfo_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t FrequencySpecificInfo_choice[] = {
  {   0, &hf_ulp_fdd_fr          , ASN1_EXTENSION_ROOT    , dissect_ulp_FrequencyInfoFDD },
  {   1, &hf_ulp_tdd_fr          , ASN1_EXTENSION_ROOT    , dissect_ulp_FrequencyInfoTDD },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_FrequencySpecificInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_FrequencySpecificInfo, FrequencySpecificInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t FrequencyInfo_sequence[] = {
  { &hf_ulp_modeSpecificFrequencyInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_FrequencySpecificInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_FrequencyInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_FrequencyInfo, FrequencyInfo_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_511(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, false);

  return offset;
}



static int
dissect_ulp_UTRA_CarrierRSSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t PrimaryCPICH_Info_sequence[] = {
  { &hf_ulp_primaryScramblingCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_511 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PrimaryCPICH_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_PrimaryCPICH_Info, PrimaryCPICH_Info_sequence);

  return offset;
}



static int
dissect_ulp_CPICH_Ec_N0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}



static int
dissect_ulp_CPICH_RSCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_ulp_Pathloss(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            46U, 173U, NULL, false);

  return offset;
}


static const per_sequence_t T_fdd_sequence[] = {
  { &hf_ulp_primaryCPICH_Info, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_PrimaryCPICH_Info },
  { &hf_ulp_cpich_Ec_N0     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_CPICH_Ec_N0 },
  { &hf_ulp_cpich_RSCP      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_CPICH_RSCP },
  { &hf_ulp_pathloss        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_Pathloss },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_fdd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_fdd, T_fdd_sequence);

  return offset;
}



static int
dissect_ulp_CellParametersID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_ulp_TGSN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 14U, NULL, false);

  return offset;
}



static int
dissect_ulp_PrimaryCCPCH_RSCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_ulp_TimeslotISCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t TimeslotISCP_List_sequence_of[1] = {
  { &hf_ulp_TimeslotISCP_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_TimeslotISCP },
};

static int
dissect_ulp_TimeslotISCP_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_TimeslotISCP_List, TimeslotISCP_List_sequence_of,
                                                  1, maxTS, false);

  return offset;
}


static const per_sequence_t T_tdd_sequence[] = {
  { &hf_ulp_cellParametersID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_CellParametersID },
  { &hf_ulp_proposedTGSN    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_TGSN },
  { &hf_ulp_primaryCCPCH_RSCP, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_PrimaryCCPCH_RSCP },
  { &hf_ulp_pathloss        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_Pathloss },
  { &hf_ulp_timeslotISCP_List, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_TimeslotISCP_List },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_tdd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_tdd, T_tdd_sequence);

  return offset;
}


static const value_string ulp_T_modeSpecificInfo_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_choice[] = {
  {   0, &hf_ulp_fdd             , ASN1_NO_EXTENSIONS     , dissect_ulp_T_fdd },
  {   1, &hf_ulp_tdd             , ASN1_NO_EXTENSIONS     , dissect_ulp_T_tdd },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_T_modeSpecificInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_T_modeSpecificInfo, T_modeSpecificInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CellMeasuredResults_sequence[] = {
  { &hf_ulp_cellIdentity    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_268435455 },
  { &hf_ulp_modeSpecificInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_T_modeSpecificInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_CellMeasuredResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_CellMeasuredResults, CellMeasuredResults_sequence);

  return offset;
}


static const per_sequence_t CellMeasuredResultsList_sequence_of[1] = {
  { &hf_ulp_CellMeasuredResultsList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_CellMeasuredResults },
};

static int
dissect_ulp_CellMeasuredResultsList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_CellMeasuredResultsList, CellMeasuredResultsList_sequence_of,
                                                  1, maxCellMeas, false);

  return offset;
}


static const per_sequence_t MeasuredResults_sequence[] = {
  { &hf_ulp_frequencyInfo   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_FrequencyInfo },
  { &hf_ulp_utra_CarrierRSSI, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_UTRA_CarrierRSSI },
  { &hf_ulp_cellMeasuredResultsList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_CellMeasuredResultsList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_MeasuredResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_MeasuredResults, MeasuredResults_sequence);

  return offset;
}


static const per_sequence_t MeasuredResultsList_sequence_of[1] = {
  { &hf_ulp_MeasuredResultsList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_MeasuredResults },
};

static int
dissect_ulp_MeasuredResultsList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_MeasuredResultsList, MeasuredResultsList_sequence_of,
                                                  1, maxFreq, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_8191(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8191U, NULL, false);

  return offset;
}


static const value_string ulp_TAResolution_vals[] = {
  {   0, "res10chip" },
  {   1, "res05chip" },
  {   2, "res0125chip" },
  { 0, NULL }
};


static int
dissect_ulp_TAResolution(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string ulp_ChipRate_vals[] = {
  {   0, "tdd128" },
  {   1, "tdd384" },
  {   2, "tdd768" },
  { 0, NULL }
};


static int
dissect_ulp_ChipRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TimingAdvance_sequence[] = {
  { &hf_ulp_ta_01           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_8191 },
  { &hf_ulp_tAResolution    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_TAResolution },
  { &hf_ulp_chipRate        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ChipRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_TimingAdvance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_TimingAdvance, TimingAdvance_sequence);

  return offset;
}


static const per_sequence_t WcdmaCellInformation_sequence[] = {
  { &hf_ulp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refUC           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_268435455 },
  { &hf_ulp_frequencyInfo   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_FrequencyInfo },
  { &hf_ulp_primaryScramblingCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_511 },
  { &hf_ulp_measuredResultsList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_MeasuredResultsList },
  { &hf_ulp_cellParametersId, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_127 },
  { &hf_ulp_timingAdvance   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_TimingAdvance },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_WcdmaCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_WcdmaCellInformation, WcdmaCellInformation_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_4194303(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4194303U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, NULL, false);

  return offset;
}


static const per_sequence_t CdmaCellInformation_sequence[] = {
  { &hf_ulp_refNID_01       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_refSID_01       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_32767 },
  { &hf_ulp_refBASEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_refBASELAT      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4194303 },
  { &hf_ulp_reBASELONG      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_8388607 },
  { &hf_ulp_refREFPN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_511 },
  { &hf_ulp_refWeekNumber   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_refSeconds      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4194303 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_CdmaCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_CdmaCellInformation, CdmaCellInformation_sequence);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t HrpdCellInformation_sequence[] = {
  { &hf_ulp_refSECTORID     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_BIT_STRING_SIZE_128 },
  { &hf_ulp_refBASELAT      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4194303 },
  { &hf_ulp_reBASELONG      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_8388607 },
  { &hf_ulp_refWeekNumber   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_refSeconds      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4194303 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_HrpdCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_HrpdCellInformation, HrpdCellInformation_sequence);

  return offset;
}


static const per_sequence_t UmbCellInformation_sequence[] = {
  { &hf_ulp_refSECTORID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_128 },
  { &hf_ulp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refBASELAT      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4194303 },
  { &hf_ulp_reBASELONG      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_8388607 },
  { &hf_ulp_refWeekNumber   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_refSeconds      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4194303 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_UmbCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_UmbCellInformation, UmbCellInformation_sequence);

  return offset;
}



static int
dissect_ulp_MCC_MNC_Digit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, false);

  return offset;
}


static const per_sequence_t MCC_sequence_of[1] = {
  { &hf_ulp_MCC_item        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_MCC_MNC_Digit },
};

static int
dissect_ulp_MCC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_MCC, MCC_sequence_of,
                                                  3, 3, false);

  return offset;
}


static const per_sequence_t MNC_sequence_of[1] = {
  { &hf_ulp_MNC_item        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_MCC_MNC_Digit },
};

static int
dissect_ulp_MNC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_MNC, MNC_sequence_of,
                                                  2, 3, false);

  return offset;
}


static const per_sequence_t PLMN_Identity_sequence[] = {
  { &hf_ulp_mcc             , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_MCC },
  { &hf_ulp_mnc             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_MNC },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_PLMN_Identity, PLMN_Identity_sequence);

  return offset;
}



static int
dissect_ulp_CellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t CellGlobalIdEUTRA_sequence[] = {
  { &hf_ulp_plmn_Identity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PLMN_Identity },
  { &hf_ulp_cellIdentity_01 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_CellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_CellGlobalIdEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_CellGlobalIdEUTRA, CellGlobalIdEUTRA_sequence);

  return offset;
}



static int
dissect_ulp_PhysCellId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 503U, NULL, false);

  return offset;
}



static int
dissect_ulp_TrackingAreaCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ulp_RSRP_Range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 97U, NULL, false);

  return offset;
}



static int
dissect_ulp_RSRQ_Range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 34U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_1282(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1282U, NULL, false);

  return offset;
}


static const per_sequence_t T_cgi_Info_sequence[] = {
  { &hf_ulp_cellGlobalId    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_CellGlobalIdEUTRA },
  { &hf_ulp_trackingAreaCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_TrackingAreaCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_cgi_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_cgi_Info, T_cgi_Info_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_65536_262143(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            65536U, 262143U, NULL, false);

  return offset;
}



static int
dissect_ulp_RSRP_Range_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -17, -1, NULL, false);

  return offset;
}



static int
dissect_ulp_RSRQ_Range_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -30, 46U, NULL, false);

  return offset;
}



static int
dissect_ulp_RS_SINR_Range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_ulp_TrackingAreaCodeNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NeighbourInformation5G_sequence[] = {
  { &hf_ulp_trackingAreaCode_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_TrackingAreaCodeNR },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_NeighbourInformation5G(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_NeighbourInformation5G, NeighbourInformation5G_sequence);

  return offset;
}


static const per_sequence_t T_measResult_sequence[] = {
  { &hf_ulp_rsrpResult      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_RSRP_Range },
  { &hf_ulp_rsrqResult      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_RSRQ_Range },
  { &hf_ulp_earfcn          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_earfcn_ext      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_INTEGER_65536_262143 },
  { &hf_ulp_rsrpResult_ext  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_RSRP_Range_Ext },
  { &hf_ulp_rsrqResult_ext  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_RSRQ_Range_Ext },
  { &hf_ulp_rs_sinrResult   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_RS_SINR_Range },
  { &hf_ulp_neighbourInformation5G, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_NeighbourInformation5G },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_measResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_measResult, T_measResult_sequence);

  return offset;
}


static const per_sequence_t MeasResultEUTRA_sequence[] = {
  { &hf_ulp_physCellId      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_PhysCellId },
  { &hf_ulp_cgi_Info        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_T_cgi_Info },
  { &hf_ulp_measResult      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_T_measResult },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_MeasResultEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_MeasResultEUTRA, MeasResultEUTRA_sequence);

  return offset;
}


static const per_sequence_t MeasResultListEUTRA_sequence_of[1] = {
  { &hf_ulp_MeasResultListEUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_MeasResultEUTRA },
};

static int
dissect_ulp_MeasResultListEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_MeasResultListEUTRA, MeasResultListEUTRA_sequence_of,
                                                  1, maxCellReport, false);

  return offset;
}


static const per_sequence_t ServingInformation5G_sequence[] = {
  { &hf_ulp_trackingAreaCode_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_TrackingAreaCodeNR },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ServingInformation5G(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ServingInformation5G, ServingInformation5G_sequence);

  return offset;
}


static const per_sequence_t LteCellInformation_sequence[] = {
  { &hf_ulp_cellGlobalIdEUTRA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_CellGlobalIdEUTRA },
  { &hf_ulp_physCellId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PhysCellId },
  { &hf_ulp_trackingAreaCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_TrackingAreaCode },
  { &hf_ulp_rsrpResult      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_RSRP_Range },
  { &hf_ulp_rsrqResult      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_RSRQ_Range },
  { &hf_ulp_ta_02           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_1282 },
  { &hf_ulp_measResultListEUTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_MeasResultListEUTRA },
  { &hf_ulp_earfcn          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_earfcn_ext      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_INTEGER_65536_262143 },
  { &hf_ulp_rsrpResult_ext  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_RSRP_Range_Ext },
  { &hf_ulp_rsrqResult_ext  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_RSRQ_Range_Ext },
  { &hf_ulp_rs_sinrResult   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_RS_SINR_Range },
  { &hf_ulp_servingInformation5G, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_ServingInformation5G },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_LteCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_LteCellInformation, LteCellInformation_sequence);

  return offset;
}



static int
dissect_ulp_T_apMACAddress_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     48, 48, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    proto_tree_add_item(tree, hf_index, val_tvb, 0, 6, ENC_NA);
  }


  return offset;
}



static int
dissect_ulp_INTEGER_M127_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 128U, NULL, false);

  return offset;
}


static const value_string ulp_T_apDeviceType_vals[] = {
  {   0, "wlan802-11a" },
  {   1, "wlan802-11b" },
  {   2, "wlan802-11g" },
  {   3, "wlan802-11n" },
  {   4, "wlan802-11ac" },
  {   5, "wlan802-11ad" },
  { 0, NULL }
};


static int
dissect_ulp_T_apDeviceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 3, NULL);

  return offset;
}



static int
dissect_ulp_INTEGER_0_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 256U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_16777216(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777216U, NULL, false);

  return offset;
}


static const value_string ulp_RTDUnits_vals[] = {
  {   0, "microseconds" },
  {   1, "hundredsofnanoseconds" },
  {   2, "tensofnanoseconds" },
  {   3, "nanoseconds" },
  {   4, "tenthsofnanoseconds" },
  { 0, NULL }
};


static int
dissect_ulp_RTDUnits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t RTD_sequence[] = {
  { &hf_ulp_rTDValue        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_16777216 },
  { &hf_ulp_rTDUnits        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_RTDUnits },
  { &hf_ulp_rTDAccuracy     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_RTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_RTD, RTD_sequence);

  return offset;
}


static const value_string ulp_LocationEncodingDescriptor_vals[] = {
  {   0, "lci" },
  {   1, "asn1" },
  { 0, NULL }
};


static int
dissect_ulp_LocationEncodingDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ulp_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_ulp_OCTET_STRING_SIZE_1_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 128, false, NULL);

  return offset;
}


static const per_sequence_t LocationData_sequence[] = {
  { &hf_ulp_locationAccuracy, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_4294967295 },
  { &hf_ulp_locationValue   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_OCTET_STRING_SIZE_1_128 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_LocationData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_LocationData, LocationData_sequence);

  return offset;
}


static const per_sequence_t ReportedLocation_sequence[] = {
  { &hf_ulp_locationEncodingDescriptor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_LocationEncodingDescriptor },
  { &hf_ulp_locationData    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_LocationData },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ReportedLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ReportedLocation, ReportedLocation_sequence);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_30(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     30, 30, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t LocationDataLCI_sequence[] = {
  { &hf_ulp_latitudeResolution, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_6 },
  { &hf_ulp_latitude_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_34 },
  { &hf_ulp_longitudeResolution, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_6 },
  { &hf_ulp_longitude_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_34 },
  { &hf_ulp_altitudeType    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_4 },
  { &hf_ulp_altitudeResolution, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_6 },
  { &hf_ulp_altitude_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_30 },
  { &hf_ulp_datum           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_LocationDataLCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_LocationDataLCI, LocationDataLCI_sequence);

  return offset;
}


static const per_sequence_t LciLocData_sequence[] = {
  { &hf_ulp_locationDataLCI , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_LocationDataLCI },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_LciLocData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_LciLocData, LciLocData_sequence);

  return offset;
}


static const value_string ulp_RepLocation_vals[] = {
  {   0, "lciLocData" },
  { 0, NULL }
};

static const per_choice_t RepLocation_choice[] = {
  {   0, &hf_ulp_lciLocData      , ASN1_EXTENSION_ROOT    , dissect_ulp_LciLocData },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_RepLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_RepLocation, RepLocation_choice,
                                 NULL);

  return offset;
}



static int
dissect_ulp_INTEGER_0_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, false);

  return offset;
}



static int
dissect_ulp_T_apSSID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *ssid_tvb;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, -1,
                                       1, 32, false, &ssid_tvb);

  if (ssid_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, ssid_tvb, 0, -1, ENC_ASCII|ENC_NA);
  }


  return offset;
}


static const value_string ulp_T_apPHYType_vals[] = {
  {   0, "unknown" },
  {   1, "any" },
  {   2, "fhss" },
  {   3, "dsss" },
  {   4, "irbaseband" },
  {   5, "ofdm" },
  {   6, "hrdsss" },
  {   7, "erp" },
  {   8, "ht" },
  {   9, "ihv" },
  { 0, NULL }
};


static int
dissect_ulp_T_apPHYType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     10, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ulp_T_setMACAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     48, 48, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    proto_tree_add_item(tree, hf_index, val_tvb, 0, 6, ENC_NA);
  }


  return offset;
}


static const per_sequence_t WlanAPInformation_sequence[] = {
  { &hf_ulp_apMACAddress_02 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_apMACAddress_02 },
  { &hf_ulp_apTransmitPower , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_M127_128 },
  { &hf_ulp_apAntennaGain   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_M127_128 },
  { &hf_ulp_apSignaltoNoise , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_M127_128 },
  { &hf_ulp_apDeviceType    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_apDeviceType },
  { &hf_ulp_apSignalStrength, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_M127_128 },
  { &hf_ulp_apChannelFrequency, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_256 },
  { &hf_ulp_apRoundTripDelay, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_RTD },
  { &hf_ulp_setTransmitPower, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_M127_128 },
  { &hf_ulp_setAntennaGain  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_M127_128 },
  { &hf_ulp_setSignaltoNoise, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_M127_128 },
  { &hf_ulp_setSignalStrength, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_M127_128 },
  { &hf_ulp_apReportedLocation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ReportedLocation },
  { &hf_ulp_apRepLocation   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_RepLocation },
  { &hf_ulp_apSignalStrengthDelta, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_1 },
  { &hf_ulp_apSignaltoNoiseDelta, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_1 },
  { &hf_ulp_setSignalStrengthDelta, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_1 },
  { &hf_ulp_setSignaltoNoiseDelta, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_1 },
  { &hf_ulp_operatingClass  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_apSSID_01       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_T_apSSID },
  { &hf_ulp_apPHYType_01    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_T_apPHYType },
  { &hf_ulp_setMACAddress_01, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_T_setMACAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_WlanAPInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_WlanAPInformation, WlanAPInformation_sequence);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t WimaxBsID_sequence[] = {
  { &hf_ulp_bsID_MSB        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_BIT_STRING_SIZE_24 },
  { &hf_ulp_bsID_LSB        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_24 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_WimaxBsID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_WimaxBsID, WimaxBsID_sequence);

  return offset;
}


static const per_sequence_t WimaxRTD_sequence[] = {
  { &hf_ulp_rtd             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_rTDstd          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_1023 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_WimaxRTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_WimaxRTD, WimaxRTD_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_M32768_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32768, 32767U, NULL, false);

  return offset;
}


static const per_sequence_t WimaxNMR_sequence[] = {
  { &hf_ulp_wimaxBsID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_WimaxBsID },
  { &hf_ulp_relDelay        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_M32768_32767 },
  { &hf_ulp_relDelaystd     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_1023 },
  { &hf_ulp_rssi            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_rSSIstd         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_63 },
  { &hf_ulp_bSTxPower       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_cinr            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_cINRstd         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_63 },
  { &hf_ulp_bSLocation      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ReportedLocation },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_WimaxNMR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_WimaxNMR, WimaxNMR_sequence);

  return offset;
}


static const per_sequence_t WimaxNMRList_sequence_of[1] = {
  { &hf_ulp_WimaxNMRList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_WimaxNMR },
};

static int
dissect_ulp_WimaxNMRList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_WimaxNMRList, WimaxNMRList_sequence_of,
                                                  1, maxWimaxBSMeas, false);

  return offset;
}


static const per_sequence_t WimaxBSInformation_sequence[] = {
  { &hf_ulp_wimaxBsID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_WimaxBsID },
  { &hf_ulp_wimaxRTD        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_WimaxRTD },
  { &hf_ulp_wimaxNMRList    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_WimaxNMRList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_WimaxBSInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_WimaxBSInformation, WimaxBSInformation_sequence);

  return offset;
}



static int
dissect_ulp_PhysCellIdNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1007U, NULL, false);

  return offset;
}



static int
dissect_ulp_ARFCN_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3279165U, NULL, false);

  return offset;
}



static int
dissect_ulp_CellIdentityNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t CellGlobalIdNR_sequence[] = {
  { &hf_ulp_plmn_Identity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PLMN_Identity },
  { &hf_ulp_cellIdentityNR  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_CellIdentityNR },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_CellGlobalIdNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_CellGlobalIdNR, CellGlobalIdNR_sequence);

  return offset;
}


static const per_sequence_t NR_Measurements_sequence[] = {
  { &hf_ulp_rsrp_Range      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_127 },
  { &hf_ulp_rsrq_Range      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_127 },
  { &hf_ulp_sinr_Range      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_NR_Measurements(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_NR_Measurements, NR_Measurements_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_3846(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3846U, NULL, false);

  return offset;
}


static const per_sequence_t ServCellNR_sequence[] = {
  { &hf_ulp_physCellId_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PhysCellIdNR },
  { &hf_ulp_arfcn_NR        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_ARFCN_NR },
  { &hf_ulp_cellGlobalId_01 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_CellGlobalIdNR },
  { &hf_ulp_trackingAreaCode_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_TrackingAreaCodeNR },
  { &hf_ulp_ssb_Measurements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_NR_Measurements },
  { &hf_ulp_csi_rs_Measurements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_NR_Measurements },
  { &hf_ulp_ta_03           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_3846 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ServCellNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ServCellNR, ServCellNR_sequence);

  return offset;
}


static const per_sequence_t ServingCellInformationNR_sequence_of[1] = {
  { &hf_ulp_ServingCellInformationNR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_ServCellNR },
};

static int
dissect_ulp_ServingCellInformationNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_ServingCellInformationNR, ServingCellInformationNR_sequence_of,
                                                  1, maxNRServingCell, false);

  return offset;
}


static const per_sequence_t MeasResultNR_sequence[] = {
  { &hf_ulp_physCellId_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PhysCellIdNR },
  { &hf_ulp_arfcn_NR        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_ARFCN_NR },
  { &hf_ulp_cellGlobalId_01 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_CellGlobalIdNR },
  { &hf_ulp_trackingAreaCode_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_TrackingAreaCodeNR },
  { &hf_ulp_ssb_Measurements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_NR_Measurements },
  { &hf_ulp_csi_rs_Measurements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_NR_Measurements },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_MeasResultNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_MeasResultNR, MeasResultNR_sequence);

  return offset;
}


static const per_sequence_t MeasResultListNR_sequence_of[1] = {
  { &hf_ulp_MeasResultListNR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_MeasResultNR },
};

static int
dissect_ulp_MeasResultListNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_MeasResultListNR, MeasResultListNR_sequence_of,
                                                  1, maxCellReportNR, false);

  return offset;
}


static const per_sequence_t NRCellInformation_sequence[] = {
  { &hf_ulp_servingCellInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_ServingCellInformationNR },
  { &hf_ulp_measuredResultsListNR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_MeasResultListNR },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_NRCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_NRCellInformation, NRCellInformation_sequence);

  return offset;
}


static const value_string ulp_Ver2_CellInfo_extension_vals[] = {
  {   0, "hrpdCell" },
  {   1, "umbCell" },
  {   2, "lteCell" },
  {   3, "wlanAP" },
  {   4, "wimaxBS" },
  {   5, "nrCell" },
  { 0, NULL }
};

static const per_choice_t Ver2_CellInfo_extension_choice[] = {
  {   0, &hf_ulp_hrpdCell        , ASN1_EXTENSION_ROOT    , dissect_ulp_HrpdCellInformation },
  {   1, &hf_ulp_umbCell         , ASN1_EXTENSION_ROOT    , dissect_ulp_UmbCellInformation },
  {   2, &hf_ulp_lteCell         , ASN1_EXTENSION_ROOT    , dissect_ulp_LteCellInformation },
  {   3, &hf_ulp_wlanAP          , ASN1_EXTENSION_ROOT    , dissect_ulp_WlanAPInformation },
  {   4, &hf_ulp_wimaxBS         , ASN1_EXTENSION_ROOT    , dissect_ulp_WimaxBSInformation },
  {   5, &hf_ulp_nrCell          , ASN1_NOT_EXTENSION_ROOT, dissect_ulp_NRCellInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_Ver2_CellInfo_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_Ver2_CellInfo_extension, Ver2_CellInfo_extension_choice,
                                 NULL);

  return offset;
}


static const value_string ulp_CellInfo_vals[] = {
  {   0, "gsmCell" },
  {   1, "wcdmaCell" },
  {   2, "cdmaCell" },
  {   3, "ver2-CellInfo-extension" },
  { 0, NULL }
};

static const per_choice_t CellInfo_choice[] = {
  {   0, &hf_ulp_gsmCell         , ASN1_EXTENSION_ROOT    , dissect_ulp_GsmCellInformation },
  {   1, &hf_ulp_wcdmaCell       , ASN1_EXTENSION_ROOT    , dissect_ulp_WcdmaCellInformation },
  {   2, &hf_ulp_cdmaCell        , ASN1_EXTENSION_ROOT    , dissect_ulp_CdmaCellInformation },
  {   3, &hf_ulp_ver2_CellInfo_extension, ASN1_NOT_EXTENSION_ROOT, dissect_ulp_Ver2_CellInfo_extension },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_CellInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_CellInfo, CellInfo_choice,
                                 NULL);

  return offset;
}


static const value_string ulp_Status_vals[] = {
  {   0, "stale" },
  {   1, "current" },
  {   2, "unknown" },
  { 0, NULL }
};


static int
dissect_ulp_Status(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t LocationId_sequence[] = {
  { &hf_ulp_cellInfo        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_CellInfo },
  { &hf_ulp_status          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_Status },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_LocationId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_LocationId, LocationId_sequence);

  return offset;
}



static int
dissect_ulp_RelativeTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const per_sequence_t LocationIdData_sequence[] = {
  { &hf_ulp_locationId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_LocationId },
  { &hf_ulp_relativetimestamp, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_RelativeTime },
  { &hf_ulp_servingFlag     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_LocationIdData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_LocationIdData, LocationIdData_sequence);

  return offset;
}


static const per_sequence_t MultipleLocationIds_sequence_of[1] = {
  { &hf_ulp_MultipleLocationIds_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_LocationIdData },
};

static int
dissect_ulp_MultipleLocationIds(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_MultipleLocationIds, MultipleLocationIds_sequence_of,
                                                  1, maxLidSize, false);

  return offset;
}



static int
dissect_ulp_T_msisdn_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *msisdn_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, &msisdn_tvb);

  if (msisdn_tvb) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_ulp_thirdPartyId);
    dissect_e164_msisdn(msisdn_tvb, subtree, 0, 8, E164_ENC_BCD);
  }


  return offset;
}



static int
dissect_ulp_T_sip_uri(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 255, false, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:./-_~%#@?", 72,
                                                      NULL);

  return offset;
}



static int
dissect_ulp_T_ims_public_identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 255, false, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789:./-_~%#@?", 72,
                                                      NULL);

  return offset;
}



static int
dissect_ulp_T_mdn_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *mdn_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, &mdn_tvb);

  if (mdn_tvb) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_ulp_thirdPartyId);
    proto_tree_add_string(subtree, hf_ulp_mobile_directory_number, mdn_tvb, 0, 8, tvb_bcd_dig_to_str(actx->pinfo->pool, mdn_tvb, 0, 8, NULL, false));
  }


  return offset;
}



static int
dissect_ulp_T_uri(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 255, false, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./-_~%#", 69,
                                                      NULL);


  return offset;
}


static const value_string ulp_ThirdPartyID_vals[] = {
  {   0, "logicalName" },
  {   1, "msisdn" },
  {   2, "emailaddr" },
  {   3, "sip-uri" },
  {   4, "ims-public-identity" },
  {   5, "min" },
  {   6, "mdn" },
  {   7, "uri" },
  { 0, NULL }
};

static const per_choice_t ThirdPartyID_choice[] = {
  {   0, &hf_ulp_logicalName     , ASN1_EXTENSION_ROOT    , dissect_ulp_IA5String_SIZE_1_1000 },
  {   1, &hf_ulp_msisdn_01       , ASN1_EXTENSION_ROOT    , dissect_ulp_T_msisdn_01 },
  {   2, &hf_ulp_emailaddr       , ASN1_EXTENSION_ROOT    , dissect_ulp_IA5String_SIZE_1_1000 },
  {   3, &hf_ulp_sip_uri         , ASN1_EXTENSION_ROOT    , dissect_ulp_T_sip_uri },
  {   4, &hf_ulp_ims_public_identity, ASN1_EXTENSION_ROOT    , dissect_ulp_T_ims_public_identity },
  {   5, &hf_ulp_min_01          , ASN1_EXTENSION_ROOT    , dissect_ulp_BIT_STRING_SIZE_34 },
  {   6, &hf_ulp_mdn_01          , ASN1_EXTENSION_ROOT    , dissect_ulp_T_mdn_01 },
  {   7, &hf_ulp_uri             , ASN1_EXTENSION_ROOT    , dissect_ulp_T_uri },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_ThirdPartyID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_ThirdPartyID, ThirdPartyID_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ThirdParty_sequence_of[1] = {
  { &hf_ulp_ThirdParty_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_ThirdPartyID },
};

static int
dissect_ulp_ThirdParty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_ThirdParty, ThirdParty_sequence_of,
                                                  1, 64, false);

  return offset;
}



static int
dissect_ulp_IA5String_SIZE_1_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 24, false,
                                          NULL);

  return offset;
}



static int
dissect_ulp_IA5String_SIZE_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 32, false,
                                          NULL);

  return offset;
}



static int
dissect_ulp_IA5String_SIZE_1_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 8, false,
                                          NULL);

  return offset;
}


static const per_sequence_t ApplicationID_sequence[] = {
  { &hf_ulp_appProvider     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_IA5String_SIZE_1_24 },
  { &hf_ulp_appName         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_IA5String_SIZE_1_32 },
  { &hf_ulp_appVersion      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_IA5String_SIZE_1_8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ApplicationID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ApplicationID, ApplicationID_sequence);

  return offset;
}



static int
dissect_ulp_UTCTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_VisibleString(tvb, offset, actx, tree, hf_index,
                                        NO_BOUND, NO_BOUND, false,
                                        NULL);

  return offset;
}


static const value_string ulp_T_latitudeSign_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_ulp_T_latitudeSign(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_ulp_INTEGER_M8388608_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_180(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 180U, NULL, false);

  return offset;
}


static const per_sequence_t T_uncertainty_sequence[] = {
  { &hf_ulp_uncertaintySemiMajor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_127 },
  { &hf_ulp_uncertaintySemiMinor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_127 },
  { &hf_ulp_orientationMajorAxis, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_180 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_uncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_uncertainty, T_uncertainty_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_100(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, false);

  return offset;
}


static const value_string ulp_T_altitudeDirection_vals[] = {
  {   0, "height" },
  {   1, "depth" },
  { 0, NULL }
};


static int
dissect_ulp_T_altitudeDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t AltitudeInfo_sequence[] = {
  { &hf_ulp_altitudeDirection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_altitudeDirection },
  { &hf_ulp_altitude        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_32767 },
  { &hf_ulp_altUncertainty  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_AltitudeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_AltitudeInfo, AltitudeInfo_sequence);

  return offset;
}


static const per_sequence_t PositionEstimate_sequence[] = {
  { &hf_ulp_latitudeSign    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_latitudeSign },
  { &hf_ulp_latitude        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_8388607 },
  { &hf_ulp_longitude       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_M8388608_8388607 },
  { &hf_ulp_uncertainty     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_uncertainty },
  { &hf_ulp_confidence      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_100 },
  { &hf_ulp_altitudeInfo    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_AltitudeInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PositionEstimate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_PositionEstimate, PositionEstimate_sequence);

  return offset;
}



static int
dissect_ulp_T_bearing(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     9, 9, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_bits_item(tree, hf_index, val_tvb, 0, 9, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_ulp_T_horspeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     16, 16, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0, 2, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const per_sequence_t Horvel_sequence[] = {
  { &hf_ulp_bearing         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_bearing },
  { &hf_ulp_horspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_horspeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Horvel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Horvel, Horvel_sequence);

  return offset;
}



static int
dissect_ulp_T_verdirect(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     1, 1, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_bits_item(tree, hf_index, val_tvb, 0, 1, ENC_NA);
  }


  return offset;
}



static int
dissect_ulp_T_bearing_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     9, 9, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_bits_item(tree, hf_index, val_tvb, 0, 9, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_ulp_T_horspeed_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     16, 16, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0, 2, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_ulp_T_verspeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     8, 8, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0, 1, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const per_sequence_t Horandvervel_sequence[] = {
  { &hf_ulp_verdirect       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_verdirect },
  { &hf_ulp_bearing_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_bearing_01 },
  { &hf_ulp_horspeed_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_horspeed_01 },
  { &hf_ulp_verspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_verspeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Horandvervel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Horandvervel, Horandvervel_sequence);

  return offset;
}



static int
dissect_ulp_T_bearing_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     9, 9, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_bits_item(tree, hf_index, val_tvb, 0, 9, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_ulp_T_horspeed_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     16, 16, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0, 2, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_ulp_T_uncertspeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     8, 8, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0, 1, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const per_sequence_t Horveluncert_sequence[] = {
  { &hf_ulp_bearing_02      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_bearing_02 },
  { &hf_ulp_horspeed_02     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_horspeed_02 },
  { &hf_ulp_uncertspeed     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_uncertspeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Horveluncert(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Horveluncert, Horveluncert_sequence);

  return offset;
}



static int
dissect_ulp_T_verdirect_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     1, 1, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_bits_item(tree, hf_index, val_tvb, 0, 1, ENC_NA);
  }


  return offset;
}



static int
dissect_ulp_T_bearing_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     9, 9, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_bits_item(tree, hf_index, val_tvb, 0, 9, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_ulp_T_horspeed_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     16, 16, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0, 2, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_ulp_T_verspeed_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     8, 8, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0, 1, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_ulp_T_horuncertspeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     8, 8, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0, 1, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_ulp_T_veruncertspeed(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     8, 8, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    actx->created_item = proto_tree_add_item(tree, hf_index, val_tvb, 0, 1, ENC_BIG_ENDIAN);
  }


  return offset;
}


static const per_sequence_t Horandveruncert_sequence[] = {
  { &hf_ulp_verdirect_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_verdirect_01 },
  { &hf_ulp_bearing_03      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_bearing_03 },
  { &hf_ulp_horspeed_03     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_horspeed_03 },
  { &hf_ulp_verspeed_01     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_verspeed_01 },
  { &hf_ulp_horuncertspeed  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_horuncertspeed },
  { &hf_ulp_veruncertspeed  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_veruncertspeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Horandveruncert(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Horandveruncert, Horandveruncert_sequence);

  return offset;
}


static const value_string ulp_Velocity_vals[] = {
  {   0, "horvel" },
  {   1, "horandvervel" },
  {   2, "horveluncert" },
  {   3, "horandveruncert" },
  { 0, NULL }
};

static const per_choice_t Velocity_choice[] = {
  {   0, &hf_ulp_horvel          , ASN1_EXTENSION_ROOT    , dissect_ulp_Horvel },
  {   1, &hf_ulp_horandvervel    , ASN1_EXTENSION_ROOT    , dissect_ulp_Horandvervel },
  {   2, &hf_ulp_horveluncert    , ASN1_EXTENSION_ROOT    , dissect_ulp_Horveluncert },
  {   3, &hf_ulp_horandveruncert , ASN1_EXTENSION_ROOT    , dissect_ulp_Horandveruncert },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_Velocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_Velocity, Velocity_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Position_sequence[] = {
  { &hf_ulp_timestamp_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_UTCTime },
  { &hf_ulp_positionEstimate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PositionEstimate },
  { &hf_ulp_velocity        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Velocity },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Position(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Position, Position_sequence);

  return offset;
}


static const per_sequence_t Ver2_SUPL_START_extension_sequence[] = {
  { &hf_ulp_multipleLocationIds, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_MultipleLocationIds },
  { &hf_ulp_thirdParty      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ThirdParty },
  { &hf_ulp_applicationID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ApplicationID },
  { &hf_ulp_position        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Position },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SUPL_START_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SUPL_START_extension, Ver2_SUPL_START_extension_sequence);

  return offset;
}


static const per_sequence_t SUPLSTART_sequence[] = {
  { &hf_ulp_sETCapabilities , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SETCapabilities },
  { &hf_ulp_locationId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_LocationId },
  { &hf_ulp_qoP             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_QoP },
  { &hf_ulp_ver2_SUPL_START_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_Ver2_SUPL_START_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLSTART(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLSTART, SUPLSTART_sequence);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, false, NULL, 0, NULL, NULL);

  return offset;
}


static const value_string ulp_SETAuthKey_vals[] = {
  {   0, "shortKey" },
  {   1, "longKey" },
  { 0, NULL }
};

static const per_choice_t SETAuthKey_choice[] = {
  {   0, &hf_ulp_shortKey        , ASN1_EXTENSION_ROOT    , dissect_ulp_BIT_STRING_SIZE_128 },
  {   1, &hf_ulp_longKey         , ASN1_EXTENSION_ROOT    , dissect_ulp_BIT_STRING_SIZE_256 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_SETAuthKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_SETAuthKey, SETAuthKey_choice,
                                 NULL);

  return offset;
}



static int
dissect_ulp_KeyIdentity4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ulp_SPCSETKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t SPCTID_sequence[] = {
  { &hf_ulp_rand            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_128 },
  { &hf_ulp_slpFQDN         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_FQDN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SPCTID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SPCTID, SPCTID_sequence);

  return offset;
}



static int
dissect_ulp_SPCSETKeylifetime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 24U, NULL, false);

  return offset;
}


static const per_sequence_t Ver2_SUPL_RESPONSE_extension_sequence[] = {
  { &hf_ulp_supportedNetworkInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SupportedNetworkInformation },
  { &hf_ulp_sPCSETKey       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SPCSETKey },
  { &hf_ulp_spctid          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SPCTID },
  { &hf_ulp_sPCSETKeylifetime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SPCSETKeylifetime },
  { &hf_ulp_initialApproximateposition, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Position },
  { &hf_ulp_gnssPosTechnology, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_GNSSPosTechnology },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SUPL_RESPONSE_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SUPL_RESPONSE_extension, Ver2_SUPL_RESPONSE_extension_sequence);

  return offset;
}


static const per_sequence_t SUPLRESPONSE_sequence[] = {
  { &hf_ulp_posMethod       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PosMethod },
  { &hf_ulp_sLPAddress      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SLPAddress },
  { &hf_ulp_sETAuthKey      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SETAuthKey },
  { &hf_ulp_keyIdentity4    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_KeyIdentity4 },
  { &hf_ulp_ver2_SUPL_RESPONSE_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_Ver2_SUPL_RESPONSE_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLRESPONSE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLRESPONSE, SUPLRESPONSE_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_167(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 167U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 10U, NULL, false);

  return offset;
}


static const per_sequence_t SatelliteInfoElement_sequence[] = {
  { &hf_ulp_satId           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_63 },
  { &hf_ulp_iode            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SatelliteInfoElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SatelliteInfoElement, SatelliteInfoElement_sequence);

  return offset;
}


static const per_sequence_t SatelliteInfo_sequence_of[1] = {
  { &hf_ulp_SatelliteInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_SatelliteInfoElement },
};

static int
dissect_ulp_SatelliteInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_SatelliteInfo, SatelliteInfo_sequence_of,
                                                  1, 31, false);

  return offset;
}


static const per_sequence_t NavigationModel_sequence[] = {
  { &hf_ulp_gpsWeek         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_1023 },
  { &hf_ulp_gpsToe          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_167 },
  { &hf_ulp_nsat            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_31 },
  { &hf_ulp_toeLimit        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_10 },
  { &hf_ulp_satInfo         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SatelliteInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_NavigationModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_NavigationModel, NavigationModel_sequence);

  return offset;
}


static const per_sequence_t GanssRequestedCommonAssistanceDataList_sequence[] = {
  { &hf_ulp_ganssReferenceTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ganssIonosphericModel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ganssAdditionalIonosphericModelForDataID00, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ganssAdditionalIonosphericModelForDataID11, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ganssEarthOrientationParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ganssAdditionalIonosphericModelForDataID01, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GanssRequestedCommonAssistanceDataList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GanssRequestedCommonAssistanceDataList, GanssRequestedCommonAssistanceDataList_sequence);

  return offset;
}



static int
dissect_ulp_T_ganssId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t val;
  ulp_private_data_t *ulp_priv = ulp_get_private_data(actx);

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, &val, false);

  ulp_priv->ganss_req_gen_data_ganss_id = (uint8_t) val;


  return offset;
}



static int
dissect_ulp_T_ganssSBASid_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     3, 3, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    proto_tree_add_bits_item(tree, hf_index, val_tvb, 0, 3, ENC_NA);
  }


  return offset;
}



static int
dissect_ulp_DGANSS_Sig_Id_Req(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ulp_T_ganssWeek(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  ulp_private_data_t *ulp_priv = ulp_get_private_data(actx);

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  if (ulp_priv->ganss_req_gen_data_ganss_id != 4) {
    /* Not GLONASS */
    proto_item_append_text(actx->created_item, "wk");
  } else {
    proto_item_append_text(actx->created_item, "d");
  }


  return offset;
}



static int
dissect_ulp_T_ganssToe(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t val;
  ulp_private_data_t *ulp_priv = ulp_get_private_data(actx);

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 167U, &val, false);



  if (ulp_priv->ganss_req_gen_data_ganss_id != 4) {
    /* Not GLONASS */
    proto_item_append_text(actx->created_item, "h");
  } else {
    proto_item_set_text(actx->created_item, "%umin (%u)", 15*val, val);
  }

  return offset;
}



static int
dissect_ulp_T_t_toeLimit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  uint32_t val;
  ulp_private_data_t *ulp_priv = ulp_get_private_data(actx);

  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, &val, false);



  if (ulp_priv->ganss_req_gen_data_ganss_id != 4) {
    /* Not GLONASS */
    proto_item_append_text(actx->created_item, "h");
  } else {
    proto_item_set_text(actx->created_item, "%umin (%u)", 30*val, val);
  }

  return offset;
}


static const per_sequence_t SatellitesListRelatedData_sequence[] = {
  { &hf_ulp_satId           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_63 },
  { &hf_ulp_iod             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_1023 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SatellitesListRelatedData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SatellitesListRelatedData, SatellitesListRelatedData_sequence);

  return offset;
}


static const per_sequence_t SatellitesListRelatedDataList_sequence_of[1] = {
  { &hf_ulp_SatellitesListRelatedDataList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_SatellitesListRelatedData },
};

static int
dissect_ulp_SatellitesListRelatedDataList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_SatellitesListRelatedDataList, SatellitesListRelatedDataList_sequence_of,
                                                  0, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t GanssNavigationModelData_sequence[] = {
  { &hf_ulp_ganssWeek       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_ganssWeek },
  { &hf_ulp_ganssToe        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_ganssToe },
  { &hf_ulp_t_toeLimit      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_t_toeLimit },
  { &hf_ulp_satellitesListRelatedDataList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SatellitesListRelatedDataList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GanssNavigationModelData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GanssNavigationModelData, GanssNavigationModelData_sequence);

  return offset;
}



static int
dissect_ulp_T_ganssTimeModels(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    proto_tree *subtree = proto_item_add_subtree(actx->created_item, ett_ulp_ganssTimeModels);
    proto_tree_add_item(subtree, hf_ulp_ganssTimeModels_bit0, val_tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ulp_ganssTimeModels_bit1, val_tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ulp_ganssTimeModels_bit2, val_tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ulp_ganssTimeModels_bit3, val_tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ulp_ganssTimeModels_bit4, val_tvb, 0, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_ulp_ganssTimeModels_spare, val_tvb, 0, 2, ENC_BIG_ENDIAN);
  }


  return offset;
}



static int
dissect_ulp_INTEGER_0_59(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, false);

  return offset;
}


static const per_sequence_t T_ganssDataBitSatList_sequence_of[1] = {
  { &hf_ulp_ganssDataBitSatList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_63 },
};

static int
dissect_ulp_T_ganssDataBitSatList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_T_ganssDataBitSatList, T_ganssDataBitSatList_sequence_of,
                                                  1, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t ReqDataBitAssistanceList_sequence[] = {
  { &hf_ulp_gnssSignals     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_GANSSSignals },
  { &hf_ulp_ganssDataBitInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_15 },
  { &hf_ulp_ganssDataBitSatList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_ganssDataBitSatList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ReqDataBitAssistanceList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ReqDataBitAssistanceList, ReqDataBitAssistanceList_sequence);

  return offset;
}


static const per_sequence_t GanssDataBits_sequence[] = {
  { &hf_ulp_ganssTODmin     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_59 },
  { &hf_ulp_reqDataBitAssistanceList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_ReqDataBitAssistanceList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GanssDataBits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GanssDataBits, GanssDataBits_sequence);

  return offset;
}


static const per_sequence_t GanssAdditionalDataChoices_sequence[] = {
  { &hf_ulp_orbitModelID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_7 },
  { &hf_ulp_clockModelID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_7 },
  { &hf_ulp_utcModelID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_7 },
  { &hf_ulp_almanacModelID  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GanssAdditionalDataChoices(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GanssAdditionalDataChoices, GanssAdditionalDataChoices_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_1_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, false);

  return offset;
}


static const per_sequence_t ExtendedEphemeris_sequence[] = {
  { &hf_ulp_validity        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_1_256 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ExtendedEphemeris(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ExtendedEphemeris, ExtendedEphemeris_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_23(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 23U, NULL, false);

  return offset;
}


static const per_sequence_t GANSSextEphTime_sequence[] = {
  { &hf_ulp_gANSSday        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_8191 },
  { &hf_ulp_gANSSTODhour    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_23 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GANSSextEphTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GANSSextEphTime, GANSSextEphTime_sequence);

  return offset;
}


static const per_sequence_t GanssExtendedEphCheck_sequence[] = {
  { &hf_ulp_beginTime_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_GANSSextEphTime },
  { &hf_ulp_endTime_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_GANSSextEphTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GanssExtendedEphCheck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GanssExtendedEphCheck, GanssExtendedEphCheck_sequence);

  return offset;
}



static int
dissect_ulp_BDS_Sig_Id_Req(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GanssReqGenericData_sequence[] = {
  { &hf_ulp_ganssId_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_ganssId },
  { &hf_ulp_ganssSBASid_01  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_ganssSBASid_01 },
  { &hf_ulp_ganssRealTimeIntegrity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ganssDifferentialCorrection, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_DGANSS_Sig_Id_Req },
  { &hf_ulp_ganssAlmanac    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ganssNavigationModelData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_GanssNavigationModelData },
  { &hf_ulp_ganssTimeModels , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_ganssTimeModels },
  { &hf_ulp_ganssReferenceMeasurementInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ganssDataBits   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_GanssDataBits },
  { &hf_ulp_ganssUTCModel   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ganssAdditionalDataChoices, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_GanssAdditionalDataChoices },
  { &hf_ulp_ganssAuxiliaryInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ganssExtendedEphemeris, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ExtendedEphemeris },
  { &hf_ulp_ganssExtendedEphemerisCheck, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_GanssExtendedEphCheck },
  { &hf_ulp_bds_DifferentialCorrection, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_BDS_Sig_Id_Req },
  { &hf_ulp_bds_GridModelReq, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GanssReqGenericData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GanssReqGenericData, GanssReqGenericData_sequence);

  return offset;
}


static const per_sequence_t GanssRequestedGenericAssistanceDataList_sequence_of[1] = {
  { &hf_ulp_GanssRequestedGenericAssistanceDataList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_GanssReqGenericData },
};

static int
dissect_ulp_GanssRequestedGenericAssistanceDataList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_GanssRequestedGenericAssistanceDataList, GanssRequestedGenericAssistanceDataList_sequence_of,
                                                  1, maxGANSS, false);

  return offset;
}


static const per_sequence_t GPSTime_sequence[] = {
  { &hf_ulp_gPSWeek         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_1023 },
  { &hf_ulp_gPSTOWhour      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_167 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GPSTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GPSTime, GPSTime_sequence);

  return offset;
}


static const per_sequence_t ExtendedEphCheck_sequence[] = {
  { &hf_ulp_beginTime       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_GPSTime },
  { &hf_ulp_endTime         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_GPSTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ExtendedEphCheck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ExtendedEphCheck, ExtendedEphCheck_sequence);

  return offset;
}


static const per_sequence_t Ver2_RequestedAssistData_extension_sequence[] = {
  { &hf_ulp_ganssRequestedCommonAssistanceDataList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_GanssRequestedCommonAssistanceDataList },
  { &hf_ulp_ganssRequestedGenericAssistanceDataList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_GanssRequestedGenericAssistanceDataList },
  { &hf_ulp_extendedEphemeris, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ExtendedEphemeris },
  { &hf_ulp_extendedEphemerisCheck, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ExtendedEphCheck },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_RequestedAssistData_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_RequestedAssistData_extension, Ver2_RequestedAssistData_extension_sequence);

  return offset;
}


static const per_sequence_t RequestedAssistData_sequence[] = {
  { &hf_ulp_almanacRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_utcModelRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_ionosphericModelRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_dgpsCorrectionsRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_referenceLocationRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_referenceTimeRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_acquisitionAssistanceRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_realTimeIntegrityRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_navigationModelRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_navigationModelData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_NavigationModel },
  { &hf_ulp_ver2_RequestedAssistData_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_Ver2_RequestedAssistData_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_RequestedAssistData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_RequestedAssistData, RequestedAssistData_sequence);

  return offset;
}



static int
dissect_ulp_OCTET_STRING_SIZE_1_8192(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 8192, false, NULL);

  return offset;
}



static int
dissect_ulp_T_rrlpPayload(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
 tvbuff_t *rrlp_tvb;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 8192, false, &rrlp_tvb);


  if (rrlp_tvb && rrlp_handle) {
    call_dissector(rrlp_handle, rrlp_tvb, actx->pinfo, tree);
  }


  return offset;
}



static int
dissect_ulp_T_lPPPayload_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
 tvbuff_t *lpp_tvb;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 60000, false, &lpp_tvb);


  if (lpp_tvb && lpp_handle) {
    call_dissector(lpp_handle, lpp_tvb, actx->pinfo, tree);
  }


  return offset;
}


static const per_sequence_t T_lPPPayload_sequence_of[1] = {
  { &hf_ulp_lPPPayload_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_T_lPPPayload_item },
};

static int
dissect_ulp_T_lPPPayload(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_T_lPPPayload, T_lPPPayload_sequence_of,
                                                  1, 3, false);

  return offset;
}



static int
dissect_ulp_OCTET_STRING_SIZE_1_60000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 60000, false, NULL);

  return offset;
}


static const per_sequence_t T_tia801Payload_sequence_of[1] = {
  { &hf_ulp_tia801Payload_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_OCTET_STRING_SIZE_1_60000 },
};

static int
dissect_ulp_T_tia801Payload(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_T_tia801Payload, T_tia801Payload_sequence_of,
                                                  1, 3, false);

  return offset;
}


static const per_sequence_t Ver2_PosPayLoad_extension_sequence[] = {
  { &hf_ulp_lPPPayload      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_lPPPayload },
  { &hf_ulp_tia801Payload   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_tia801Payload },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_PosPayLoad_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_PosPayLoad_extension, Ver2_PosPayLoad_extension_sequence);

  return offset;
}


static const value_string ulp_PosPayLoad_vals[] = {
  {   0, "tia801payload" },
  {   1, "rrcPayload" },
  {   2, "rrlpPayload" },
  {   3, "ver2-PosPayLoad-extension" },
  { 0, NULL }
};

static const per_choice_t PosPayLoad_choice[] = {
  {   0, &hf_ulp_tia801payload   , ASN1_EXTENSION_ROOT    , dissect_ulp_OCTET_STRING_SIZE_1_8192 },
  {   1, &hf_ulp_rrcPayload      , ASN1_EXTENSION_ROOT    , dissect_ulp_OCTET_STRING_SIZE_1_8192 },
  {   2, &hf_ulp_rrlpPayload     , ASN1_EXTENSION_ROOT    , dissect_ulp_T_rrlpPayload },
  {   3, &hf_ulp_ver2_PosPayLoad_extension, ASN1_NOT_EXTENSION_ROOT, dissect_ulp_Ver2_PosPayLoad_extension },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_PosPayLoad(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_PosPayLoad, PosPayLoad_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t T_utran_GPSTimingOfCell_sequence[] = {
  { &hf_ulp_ms_part         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_1023 },
  { &hf_ulp_ls_part         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_utran_GPSTimingOfCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_utran_GPSTimingOfCell, T_utran_GPSTimingOfCell_sequence);

  return offset;
}


static const per_sequence_t T_fdd_01_sequence[] = {
  { &hf_ulp_referenceIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_PrimaryCPICH_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_fdd_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_fdd_01, T_fdd_01_sequence);

  return offset;
}


static const per_sequence_t T_tdd_01_sequence[] = {
  { &hf_ulp_referenceIdentity_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_CellParametersID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_tdd_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_tdd_01, T_tdd_01_sequence);

  return offset;
}


static const value_string ulp_T_modeSpecificInfo_01_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_01_choice[] = {
  {   0, &hf_ulp_fdd_01          , ASN1_NO_EXTENSIONS     , dissect_ulp_T_fdd_01 },
  {   1, &hf_ulp_tdd_01          , ASN1_NO_EXTENSIONS     , dissect_ulp_T_tdd_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_T_modeSpecificInfo_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_T_modeSpecificInfo_01, T_modeSpecificInfo_01_choice,
                                 NULL);

  return offset;
}



static int
dissect_ulp_INTEGER_0_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}


static const per_sequence_t UTRAN_GPSReferenceTime_sequence[] = {
  { &hf_ulp_utran_GPSTimingOfCell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_T_utran_GPSTimingOfCell },
  { &hf_ulp_modeSpecificInfo_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_T_modeSpecificInfo_01 },
  { &hf_ulp_sfn             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4095 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_UTRAN_GPSReferenceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_UTRAN_GPSReferenceTime, UTRAN_GPSReferenceTime_sequence);

  return offset;
}


static const value_string ulp_UTRANGPSDriftRate_vals[] = {
  {   0, "utran-GPSDrift0" },
  {   1, "utran-GPSDrift1" },
  {   2, "utran-GPSDrift2" },
  {   3, "utran-GPSDrift5" },
  {   4, "utran-GPSDrift10" },
  {   5, "utran-GPSDrift15" },
  {   6, "utran-GPSDrift25" },
  {   7, "utran-GPSDrift50" },
  {   8, "utran-GPSDrift-1" },
  {   9, "utran-GPSDrift-2" },
  {  10, "utran-GPSDrift-5" },
  {  11, "utran-GPSDrift-10" },
  {  12, "utran-GPSDrift-15" },
  {  13, "utran-GPSDrift-25" },
  {  14, "utran-GPSDrift-50" },
  { 0, NULL }
};


static int
dissect_ulp_UTRANGPSDriftRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     15, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t UTRAN_GPSReferenceTimeAssistance_sequence[] = {
  { &hf_ulp_utran_GPSReferenceTime, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_UTRAN_GPSReferenceTime },
  { &hf_ulp_gpsReferenceTimeUncertainty, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_127 },
  { &hf_ulp_utranGPSDriftRate, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_UTRANGPSDriftRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_UTRAN_GPSReferenceTimeAssistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_UTRAN_GPSReferenceTimeAssistance, UTRAN_GPSReferenceTimeAssistance_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_16383(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, false);

  return offset;
}


static const per_sequence_t T_set_GPSTimingOfCell_sequence[] = {
  { &hf_ulp_ms_part_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_16383 },
  { &hf_ulp_ls_part         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_set_GPSTimingOfCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_set_GPSTimingOfCell, T_set_GPSTimingOfCell_sequence);

  return offset;
}


static const per_sequence_t T_fdd_02_sequence[] = {
  { &hf_ulp_referenceIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_PrimaryCPICH_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_fdd_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_fdd_02, T_fdd_02_sequence);

  return offset;
}


static const per_sequence_t T_tdd_02_sequence[] = {
  { &hf_ulp_referenceIdentity_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_CellParametersID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_tdd_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_tdd_02, T_tdd_02_sequence);

  return offset;
}


static const value_string ulp_T_modeSpecificInfo_02_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_02_choice[] = {
  {   0, &hf_ulp_fdd_02          , ASN1_NO_EXTENSIONS     , dissect_ulp_T_fdd_02 },
  {   1, &hf_ulp_tdd_02          , ASN1_NO_EXTENSIONS     , dissect_ulp_T_tdd_02 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_T_modeSpecificInfo_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_T_modeSpecificInfo_02, T_modeSpecificInfo_02_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UTRAN_GPSReferenceTimeResult_sequence[] = {
  { &hf_ulp_set_GPSTimingOfCell, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_set_GPSTimingOfCell },
  { &hf_ulp_modeSpecificInfo_02, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_modeSpecificInfo_02 },
  { &hf_ulp_sfn             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4095 },
  { &hf_ulp_gpsReferenceTimeUncertainty, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_UTRAN_GPSReferenceTimeResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_UTRAN_GPSReferenceTimeResult, UTRAN_GPSReferenceTimeResult_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_86399(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 86399U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_3999999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3999999U, NULL, false);

  return offset;
}


static const per_sequence_t T_fdd_03_sequence[] = {
  { &hf_ulp_referenceIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_PrimaryCPICH_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_fdd_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_fdd_03, T_fdd_03_sequence);

  return offset;
}


static const per_sequence_t T_tdd_03_sequence[] = {
  { &hf_ulp_referenceIdentity_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_CellParametersID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_tdd_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_tdd_03, T_tdd_03_sequence);

  return offset;
}


static const value_string ulp_T_modeSpecificInfo_03_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_03_choice[] = {
  {   0, &hf_ulp_fdd_03          , ASN1_NO_EXTENSIONS     , dissect_ulp_T_fdd_03 },
  {   1, &hf_ulp_tdd_03          , ASN1_NO_EXTENSIONS     , dissect_ulp_T_tdd_03 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_T_modeSpecificInfo_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_T_modeSpecificInfo_03, T_modeSpecificInfo_03_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UTRAN_GANSSReferenceTime_sequence[] = {
  { &hf_ulp_ganssTOD        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_86399 },
  { &hf_ulp_utran_GANSSTimingOfCell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_3999999 },
  { &hf_ulp_modeSpecificInfo_03, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_modeSpecificInfo_03 },
  { &hf_ulp_sfn             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4095 },
  { &hf_ulp_ganss_TODUncertainty, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_UTRAN_GANSSReferenceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_UTRAN_GANSSReferenceTime, UTRAN_GANSSReferenceTime_sequence);

  return offset;
}


static const value_string ulp_UTRANGANSSDriftRate_vals[] = {
  {   0, "utran-GANSSDrift0" },
  {   1, "utran-GANSSDrift1" },
  {   2, "utran-GANSSDrift2" },
  {   3, "utran-GANSSDrift5" },
  {   4, "utran-GANSSDrift10" },
  {   5, "utran-GANSSDrift15" },
  {   6, "utran-GANSSDrift25" },
  {   7, "utran-GANSSDrift50" },
  {   8, "utran-GANSSDrift-1" },
  {   9, "utran-GANSSDrift-2" },
  {  10, "utran-GANSSDrift-5" },
  {  11, "utran-GANSSDrift-10" },
  {  12, "utran-GANSSDrift-15" },
  {  13, "utran-GANSSDrift-25" },
  {  14, "utran-GANSSDrift-50" },
  { 0, NULL }
};


static int
dissect_ulp_UTRANGANSSDriftRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     15, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t UTRAN_GANSSReferenceTimeAssistance_sequence[] = {
  { &hf_ulp_ganssDay        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_8191 },
  { &hf_ulp_ganssTimeID     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_15 },
  { &hf_ulp_utran_GANSSReferenceTime, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_UTRAN_GANSSReferenceTime },
  { &hf_ulp_utranGANSSDriftRate, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_UTRANGANSSDriftRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_UTRAN_GANSSReferenceTimeAssistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_UTRAN_GANSSReferenceTimeAssistance, UTRAN_GANSSReferenceTimeAssistance_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_80(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 80U, NULL, false);

  return offset;
}


static const per_sequence_t T_set_GANSSTimingOfCell_sequence[] = {
  { &hf_ulp_ms_part_02      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_80 },
  { &hf_ulp_ls_part         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_set_GANSSTimingOfCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_set_GANSSTimingOfCell, T_set_GANSSTimingOfCell_sequence);

  return offset;
}


static const per_sequence_t T_fdd_04_sequence[] = {
  { &hf_ulp_referenceIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_PrimaryCPICH_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_fdd_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_fdd_04, T_fdd_04_sequence);

  return offset;
}


static const per_sequence_t T_tdd_04_sequence[] = {
  { &hf_ulp_referenceIdentity_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_CellParametersID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_tdd_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_tdd_04, T_tdd_04_sequence);

  return offset;
}


static const value_string ulp_T_modeSpecificInfo_04_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_04_choice[] = {
  {   0, &hf_ulp_fdd_04          , ASN1_NO_EXTENSIONS     , dissect_ulp_T_fdd_04 },
  {   1, &hf_ulp_tdd_04          , ASN1_NO_EXTENSIONS     , dissect_ulp_T_tdd_04 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_T_modeSpecificInfo_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_T_modeSpecificInfo_04, T_modeSpecificInfo_04_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SET_GANSSReferenceTime_sequence[] = {
  { &hf_ulp_set_GANSSTimingOfCell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_set_GANSSTimingOfCell },
  { &hf_ulp_modeSpecificInfo_04, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_T_modeSpecificInfo_04 },
  { &hf_ulp_sfn             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4095 },
  { &hf_ulp_ganss_TODUncertainty, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SET_GANSSReferenceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SET_GANSSReferenceTime, SET_GANSSReferenceTime_sequence);

  return offset;
}


static const per_sequence_t UTRAN_GANSSReferenceTimeResult_sequence[] = {
  { &hf_ulp_ganssTimeID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_15 },
  { &hf_ulp_set_GANSSReferenceTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SET_GANSSReferenceTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_UTRAN_GANSSReferenceTimeResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_UTRAN_GANSSReferenceTimeResult, UTRAN_GANSSReferenceTimeResult_sequence);

  return offset;
}


static const per_sequence_t Ver2_SUPL_POS_extension_sequence[] = {
  { &hf_ulp_utran_GPSReferenceTimeAssistance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_UTRAN_GPSReferenceTimeAssistance },
  { &hf_ulp_utran_GPSReferenceTimeResult, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_UTRAN_GPSReferenceTimeResult },
  { &hf_ulp_utran_GANSSReferenceTimeAssistance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_UTRAN_GANSSReferenceTimeAssistance },
  { &hf_ulp_utran_GANSSReferenceTimeResult, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_UTRAN_GANSSReferenceTimeResult },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SUPL_POS_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SUPL_POS_extension, Ver2_SUPL_POS_extension_sequence);

  return offset;
}


static const per_sequence_t SUPLPOS_sequence[] = {
  { &hf_ulp_posPayLoad      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PosPayLoad },
  { &hf_ulp_velocity        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Velocity },
  { &hf_ulp_ver2_SUPL_POS_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_Ver2_SUPL_POS_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLPOS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLPOS, SUPLPOS_sequence);

  return offset;
}



static int
dissect_ulp_Ver(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t Ver2_SUPL_POS_INIT_extension_sequence[] = {
  { &hf_ulp_multipleLocationIds, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_MultipleLocationIds },
  { &hf_ulp_utran_GPSReferenceTimeResult, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_UTRAN_GPSReferenceTimeResult },
  { &hf_ulp_utran_GANSSReferenceTimeResult, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_UTRAN_GANSSReferenceTimeResult },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SUPL_POS_INIT_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SUPL_POS_INIT_extension, Ver2_SUPL_POS_INIT_extension_sequence);

  return offset;
}


static const per_sequence_t SUPLPOSINIT_sequence[] = {
  { &hf_ulp_sETCapabilities , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SETCapabilities },
  { &hf_ulp_requestedAssistData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_RequestedAssistData },
  { &hf_ulp_locationId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_LocationId },
  { &hf_ulp_position        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Position },
  { &hf_ulp_suplpos         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SUPLPOS },
  { &hf_ulp_ver             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Ver },
  { &hf_ulp_ver2_SUPL_POS_INIT_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_Ver2_SUPL_POS_INIT_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLPOSINIT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLPOSINIT, SUPLPOSINIT_sequence);

  return offset;
}


static const value_string ulp_StatusCode_vals[] = {
  {   0, "unspecified" },
  {   1, "systemFailure" },
  {   2, "unexpectedMessage" },
  {   3, "protocolError" },
  {   4, "dataMissing" },
  {   5, "unexpectedDataValue" },
  {   6, "posMethodFailure" },
  {   7, "posMethodMismatch" },
  {   8, "posProtocolMismatch" },
  {   9, "targetSETnotReachable" },
  {  10, "versionNotSupported" },
  {  11, "resourceShortage" },
  {  12, "invalidSessionId" },
  {  13, "nonProxyModeNotSupported" },
  {  14, "proxyModeNotSupported" },
  {  15, "positioningNotPermitted" },
  {  16, "authNetFailure" },
  {  17, "authSuplinitFailure" },
  { 100, "consentDeniedByUser" },
  { 101, "consentGrantedByUser" },
  {  18, "ver2-incompatibleProtectionLevel" },
  {  19, "ver2-serviceNotSupported" },
  {  20, "ver2-insufficientInterval" },
  {  21, "ver2-noSUPLCoverage" },
  { 102, "ver2-sessionStopped" },
  { 103, "ver2-appIdDenied" },
  { 0, NULL }
};

static uint32_t StatusCode_value_map[20+6] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 100, 101, 18, 19, 20, 21, 102, 103};

static int
dissect_ulp_StatusCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     20, NULL, true, 6, StatusCode_value_map);

  return offset;
}



static int
dissect_ulp_INTEGER_M2147483648_2147483647(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            INT32_MIN, 2147483647U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_179(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 179U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_64000_1280000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            64000U, 1280000U, NULL, false);

  return offset;
}


static const per_sequence_t HighAccuracyAltitudeInfo_sequence[] = {
  { &hf_ulp_altitude_02     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_64000_1280000 },
  { &hf_ulp_uncertaintyAltitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_verticalConfidence, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_100 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_HighAccuracyAltitudeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_HighAccuracyAltitudeInfo, HighAccuracyAltitudeInfo_sequence);

  return offset;
}


static const per_sequence_t HighAccuracyPositionEstimate_sequence[] = {
  { &hf_ulp_degreesLatitude , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_M2147483648_2147483647 },
  { &hf_ulp_degreesLongitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_M2147483648_2147483647 },
  { &hf_ulp_uncertaintySemiMajor_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_uncertaintySemiMinor_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_orientationMajorAxis_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_179 },
  { &hf_ulp_horizontalConfidence, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_100 },
  { &hf_ulp_highAccuracyAltitudeInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_HighAccuracyAltitudeInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_HighAccuracyPositionEstimate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_HighAccuracyPositionEstimate, HighAccuracyPositionEstimate_sequence);

  return offset;
}


static const per_sequence_t Ver2_HighAccuracyPosition_sequence[] = {
  { &hf_ulp_timestamp_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_UTCTime },
  { &hf_ulp_highAccuracyPositionEstimate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_HighAccuracyPositionEstimate },
  { &hf_ulp_velocity        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Velocity },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_HighAccuracyPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_HighAccuracyPosition, Ver2_HighAccuracyPosition_sequence);

  return offset;
}


static const per_sequence_t Ver2_SUPL_END_extension_sequence[] = {
  { &hf_ulp_sETCapabilities , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SETCapabilities },
  { &hf_ulp_ver2_HighAccuracyPosition, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_Ver2_HighAccuracyPosition },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SUPL_END_extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SUPL_END_extension, Ver2_SUPL_END_extension_sequence);

  return offset;
}


static const per_sequence_t SUPLEND_sequence[] = {
  { &hf_ulp_position        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Position },
  { &hf_ulp_statusCode      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_StatusCode },
  { &hf_ulp_ver             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Ver },
  { &hf_ulp_ver2_SUPL_END_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ulp_Ver2_SUPL_END_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLEND(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLEND, SUPLEND_sequence);

  return offset;
}


static const per_sequence_t SUPLAUTHREQ_sequence[] = {
  { &hf_ulp_ver             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Ver },
  { &hf_ulp_sETCapabilities , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SETCapabilities },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLAUTHREQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLAUTHREQ, SUPLAUTHREQ_sequence);

  return offset;
}


static const per_sequence_t SUPLAUTHRESP_sequence[] = {
  { &hf_ulp_sPCSETKey       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SPCSETKey },
  { &hf_ulp_spctid          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SPCTID },
  { &hf_ulp_sPCSETKeylifetime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SPCSETKeylifetime },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLAUTHRESP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLAUTHRESP, SUPLAUTHRESP_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_1_8639999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8639999U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_0_2678400(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2678400U, NULL, false);

  return offset;
}


static const per_sequence_t PeriodicParams_sequence[] = {
  { &hf_ulp_numberOfFixes   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_1_8639999 },
  { &hf_ulp_intervalBetweenFixes, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_1_8639999 },
  { &hf_ulp_startTime       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_2678400 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PeriodicParams(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_PeriodicParams, PeriodicParams_sequence);

  return offset;
}


static const value_string ulp_AreaEventType_vals[] = {
  {   0, "enteringArea" },
  {   1, "insideArea" },
  {   2, "outsideArea" },
  {   3, "leavingArea" },
  { 0, NULL }
};


static int
dissect_ulp_AreaEventType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ulp_INTEGER_1_604800(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 604800U, NULL, false);

  return offset;
}


static const per_sequence_t RepeatedReportingParams_sequence[] = {
  { &hf_ulp_minimumIntervalTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_1_604800 },
  { &hf_ulp_maximumNumberOfReports, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_1_1024 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_RepeatedReportingParams(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_RepeatedReportingParams, RepeatedReportingParams_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_11318399(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 11318399U, NULL, false);

  return offset;
}


static const value_string ulp_T_latitudeSign_01_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_ulp_T_latitudeSign_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t Coordinate_sequence[] = {
  { &hf_ulp_latitudeSign_01 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_T_latitudeSign_01 },
  { &hf_ulp_coordinateLatitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_8388607 },
  { &hf_ulp_coordinateLongitude, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_M8388608_8388607 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Coordinate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Coordinate, Coordinate_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_1_1000000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1000000U, NULL, false);

  return offset;
}



static int
dissect_ulp_INTEGER_1_1500000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1500000U, NULL, false);

  return offset;
}


static const per_sequence_t CircularArea_sequence[] = {
  { &hf_ulp_coordinate      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_Coordinate },
  { &hf_ulp_radius          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_1_1000000 },
  { &hf_ulp_radius_min      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_INTEGER_1_1000000 },
  { &hf_ulp_radius_max      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_INTEGER_1_1500000 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_CircularArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_CircularArea, CircularArea_sequence);

  return offset;
}


static const per_sequence_t EllipticalArea_sequence[] = {
  { &hf_ulp_coordinate      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_Coordinate },
  { &hf_ulp_semiMajor       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_1_1000000 },
  { &hf_ulp_semiMajor_min   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_INTEGER_1_1000000 },
  { &hf_ulp_semiMajor_max   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_INTEGER_1_1500000 },
  { &hf_ulp_semiMinor       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_1_1000000 },
  { &hf_ulp_semiMinor_min   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_INTEGER_1_1000000 },
  { &hf_ulp_semiMinor_max   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_INTEGER_1_1500000 },
  { &hf_ulp_angle           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_179 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_EllipticalArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_EllipticalArea, EllipticalArea_sequence);

  return offset;
}


static const per_sequence_t PolygonDescription_sequence_of[1] = {
  { &hf_ulp_PolygonDescription_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_Coordinate },
};

static int
dissect_ulp_PolygonDescription(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_PolygonDescription, PolygonDescription_sequence_of,
                                                  3, 15, false);

  return offset;
}



static int
dissect_ulp_INTEGER_1_100000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 100000U, NULL, false);

  return offset;
}


static const per_sequence_t PolygonArea_sequence[] = {
  { &hf_ulp_polygonDescription, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_PolygonDescription },
  { &hf_ulp_polygonHysteresis, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_INTEGER_1_100000 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PolygonArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_PolygonArea, PolygonArea_sequence);

  return offset;
}


static const value_string ulp_GeographicTargetArea_vals[] = {
  {   0, "circularArea" },
  {   1, "ellipticalArea" },
  {   2, "polygonArea" },
  { 0, NULL }
};

static const per_choice_t GeographicTargetArea_choice[] = {
  {   0, &hf_ulp_circularArea    , ASN1_EXTENSION_ROOT    , dissect_ulp_CircularArea },
  {   1, &hf_ulp_ellipticalArea  , ASN1_EXTENSION_ROOT    , dissect_ulp_EllipticalArea },
  {   2, &hf_ulp_polygonArea     , ASN1_EXTENSION_ROOT    , dissect_ulp_PolygonArea },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_GeographicTargetArea(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_GeographicTargetArea, GeographicTargetArea_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GeographicTargetAreaList_sequence_of[1] = {
  { &hf_ulp_GeographicTargetAreaList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_GeographicTargetArea },
};

static int
dissect_ulp_GeographicTargetAreaList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_GeographicTargetAreaList, GeographicTargetAreaList_sequence_of,
                                                  1, maxNumGeoArea, false);

  return offset;
}


static const per_sequence_t GSMAreaId_sequence[] = {
  { &hf_ulp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refLAC          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_refCI           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GSMAreaId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GSMAreaId, GSMAreaId_sequence);

  return offset;
}


static const per_sequence_t WCDMAAreaId_sequence[] = {
  { &hf_ulp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refLAC          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_refUC           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_268435455 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_WCDMAAreaId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_WCDMAAreaId, WCDMAAreaId_sequence);

  return offset;
}


static const per_sequence_t CDMAAreaId_sequence[] = {
  { &hf_ulp_refSID          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_refNID          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_32767 },
  { &hf_ulp_refBASEID       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_CDMAAreaId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_CDMAAreaId, CDMAAreaId_sequence);

  return offset;
}


static const per_sequence_t HRPDAreaId_sequence[] = {
  { &hf_ulp_refSECTORID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_128 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_HRPDAreaId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_HRPDAreaId, HRPDAreaId_sequence);

  return offset;
}


static const per_sequence_t UMBAreaId_sequence[] = {
  { &hf_ulp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refSECTORID     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_BIT_STRING_SIZE_128 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_UMBAreaId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_UMBAreaId, UMBAreaId_sequence);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_29(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     29, 29, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t LTEAreaId_sequence[] = {
  { &hf_ulp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refCI_01        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_BIT_STRING_SIZE_29 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_LTEAreaId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_LTEAreaId, LTEAreaId_sequence);

  return offset;
}



static int
dissect_ulp_T_apMACAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *val_tvb;

  offset = dissect_per_bit_string(tvb, offset, actx, tree, -1,
                                     48, 48, false, NULL, 0, &val_tvb, NULL);

  if (val_tvb) {
    proto_tree_add_item(tree, hf_index, val_tvb, 0, 6, ENC_NA);
  }


  return offset;
}


static const per_sequence_t WLANAreaId_sequence[] = {
  { &hf_ulp_apMACAddress    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_apMACAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_WLANAreaId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_WLANAreaId, WLANAreaId_sequence);

  return offset;
}


static const per_sequence_t WimaxAreaId_sequence[] = {
  { &hf_ulp_bsID_MSB        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_BIT_STRING_SIZE_24 },
  { &hf_ulp_bsID_LSB        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_24 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_WimaxAreaId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_WimaxAreaId, WimaxAreaId_sequence);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_36(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NRAreaId_sequence[] = {
  { &hf_ulp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refCI_02        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_BIT_STRING_SIZE_36 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_NRAreaId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_NRAreaId, NRAreaId_sequence);

  return offset;
}


static const value_string ulp_AreaId_vals[] = {
  {   0, "gSMAreaId" },
  {   1, "wCDMAAreaId" },
  {   2, "cDMAAreaId" },
  {   3, "hRPDAreaId" },
  {   4, "uMBAreaId" },
  {   5, "lTEAreaId" },
  {   6, "wLANAreaId" },
  {   7, "wiMAXAreaId" },
  {   8, "nRAreaId" },
  { 0, NULL }
};

static const per_choice_t AreaId_choice[] = {
  {   0, &hf_ulp_gSMAreaId       , ASN1_EXTENSION_ROOT    , dissect_ulp_GSMAreaId },
  {   1, &hf_ulp_wCDMAAreaId     , ASN1_EXTENSION_ROOT    , dissect_ulp_WCDMAAreaId },
  {   2, &hf_ulp_cDMAAreaId      , ASN1_EXTENSION_ROOT    , dissect_ulp_CDMAAreaId },
  {   3, &hf_ulp_hRPDAreaId      , ASN1_EXTENSION_ROOT    , dissect_ulp_HRPDAreaId },
  {   4, &hf_ulp_uMBAreaId       , ASN1_EXTENSION_ROOT    , dissect_ulp_UMBAreaId },
  {   5, &hf_ulp_lTEAreaId       , ASN1_EXTENSION_ROOT    , dissect_ulp_LTEAreaId },
  {   6, &hf_ulp_wLANAreaId      , ASN1_EXTENSION_ROOT    , dissect_ulp_WLANAreaId },
  {   7, &hf_ulp_wiMAXAreaId     , ASN1_EXTENSION_ROOT    , dissect_ulp_WimaxAreaId },
  {   8, &hf_ulp_nRAreaId        , ASN1_NOT_EXTENSION_ROOT, dissect_ulp_NRAreaId },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_AreaId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_AreaId, AreaId_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AreaIdSet_sequence_of[1] = {
  { &hf_ulp_AreaIdSet_item  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_AreaId },
};

static int
dissect_ulp_AreaIdSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_AreaIdSet, AreaIdSet_sequence_of,
                                                  1, maxAreaId, false);

  return offset;
}


static const value_string ulp_AreaIdSetType_vals[] = {
  {   0, "border" },
  {   1, "within" },
  { 0, NULL }
};


static int
dissect_ulp_AreaIdSetType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ulp_GeoAreaIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, maxNumGeoArea, NULL, false);

  return offset;
}


static const per_sequence_t GeoAreaMappingList_sequence_of[1] = {
  { &hf_ulp_GeoAreaMappingList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_GeoAreaIndex },
};

static int
dissect_ulp_GeoAreaMappingList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_GeoAreaMappingList, GeoAreaMappingList_sequence_of,
                                                  1, maxNumGeoArea, false);

  return offset;
}


static const per_sequence_t AreaIdList_sequence[] = {
  { &hf_ulp_areaIdSet       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_AreaIdSet },
  { &hf_ulp_areaIdSetType   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_AreaIdSetType },
  { &hf_ulp_geoAreaMappingList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_GeoAreaMappingList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_AreaIdList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_AreaIdList, AreaIdList_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_maxAreaIdList_OF_AreaIdList_sequence_of[1] = {
  { &hf_ulp_areaIdLists_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_AreaIdList },
};

static int
dissect_ulp_SEQUENCE_SIZE_1_maxAreaIdList_OF_AreaIdList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_SEQUENCE_SIZE_1_maxAreaIdList_OF_AreaIdList, SEQUENCE_SIZE_1_maxAreaIdList_OF_AreaIdList_sequence_of,
                                                  1, maxAreaIdList, false);

  return offset;
}


static const per_sequence_t AreaEventParams_sequence[] = {
  { &hf_ulp_areaEventType   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_AreaEventType },
  { &hf_ulp_locationEstimate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_repeatedReportingParams, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_RepeatedReportingParams },
  { &hf_ulp_startTime       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_2678400 },
  { &hf_ulp_stopTime        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_11318399 },
  { &hf_ulp_geographicTargetAreaList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_GeographicTargetAreaList },
  { &hf_ulp_areaIdLists     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SEQUENCE_SIZE_1_maxAreaIdList_OF_AreaIdList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_AreaEventParams(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_AreaEventParams, AreaEventParams_sequence);

  return offset;
}


static const value_string ulp_TriggerParams_vals[] = {
  {   0, "periodicParams" },
  {   1, "areaEventParams" },
  { 0, NULL }
};

static const per_choice_t TriggerParams_choice[] = {
  {   0, &hf_ulp_periodicParams  , ASN1_EXTENSION_ROOT    , dissect_ulp_PeriodicParams },
  {   1, &hf_ulp_areaEventParams , ASN1_EXTENSION_ROOT    , dissect_ulp_AreaEventParams },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_TriggerParams(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_TriggerParams, TriggerParams_choice,
                                 NULL);

  return offset;
}


static const value_string ulp_CauseCode_vals[] = {
  {   0, "servingNetWorkNotInAreaIdList" },
  {   1, "sETCapabilitiesChanged" },
  {   2, "noSUPLCoverage" },
  { 0, NULL }
};


static int
dissect_ulp_CauseCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t Ver2_SUPLTRIGGEREDSTART_sequence[] = {
  { &hf_ulp_sETCapabilities , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SETCapabilities },
  { &hf_ulp_locationId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_LocationId },
  { &hf_ulp_ver             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Ver },
  { &hf_ulp_qoP             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_QoP },
  { &hf_ulp_multipleLocationIds, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_MultipleLocationIds },
  { &hf_ulp_thirdParty      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ThirdParty },
  { &hf_ulp_applicationID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ApplicationID },
  { &hf_ulp_triggerType     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_TriggerType },
  { &hf_ulp_triggerParams   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_TriggerParams },
  { &hf_ulp_position        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Position },
  { &hf_ulp_reportingCap    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ReportingCap },
  { &hf_ulp_causeCode       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_CauseCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SUPLTRIGGEREDSTART(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SUPLTRIGGEREDSTART, Ver2_SUPLTRIGGEREDSTART_sequence);

  return offset;
}


static const value_string ulp_RepModee_vals[] = {
  {   1, "realtime" },
  {   2, "quasirealtime" },
  {   3, "batch" },
  { 0, NULL }
};

static uint32_t RepModee_value_map[3+0] = {1, 2, 3};

static int
dissect_ulp_RepModee(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, RepModee_value_map);

  return offset;
}



static int
dissect_ulp_INTEGER_1_2048(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 2048U, NULL, false);

  return offset;
}


static const value_string ulp_BatchRepConditions_vals[] = {
  {   0, "num-interval" },
  {   1, "num-minutes" },
  {   2, "endofsession" },
  { 0, NULL }
};

static const per_choice_t BatchRepConditions_choice[] = {
  {   0, &hf_ulp_num_interval    , ASN1_EXTENSION_ROOT    , dissect_ulp_INTEGER_1_1024 },
  {   1, &hf_ulp_num_minutes     , ASN1_EXTENSION_ROOT    , dissect_ulp_INTEGER_1_2048 },
  {   2, &hf_ulp_endofsession    , ASN1_EXTENSION_ROOT    , dissect_ulp_NULL },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_BatchRepConditions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_BatchRepConditions, BatchRepConditions_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t BatchRepType_sequence[] = {
  { &hf_ulp_reportPosition  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_reportMeasurements, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_intermediateReports, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_discardOldest   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_BatchRepType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_BatchRepType, BatchRepType_sequence);

  return offset;
}


static const per_sequence_t ReportingMode_sequence[] = {
  { &hf_ulp_repMode         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_RepModee },
  { &hf_ulp_batchRepConditions, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_BatchRepConditions },
  { &hf_ulp_batchRepType    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_BatchRepType },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ReportingMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ReportingMode, ReportingMode_sequence);

  return offset;
}


static const per_sequence_t Ver2_SUPLTRIGGEREDRESPONSE_sequence[] = {
  { &hf_ulp_posMethod       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PosMethod },
  { &hf_ulp_triggerParams   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_TriggerParams },
  { &hf_ulp_sLPAddress      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SLPAddress },
  { &hf_ulp_supportedNetworkInformation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SupportedNetworkInformation },
  { &hf_ulp_reportingMode   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ReportingMode },
  { &hf_ulp_sPCSETKey       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SPCSETKey },
  { &hf_ulp_spctid          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SPCTID },
  { &hf_ulp_sPCSETKeylifetime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SPCSETKeylifetime },
  { &hf_ulp_gnssPosTechnology, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_GNSSPosTechnology },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SUPLTRIGGEREDRESPONSE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SUPLTRIGGEREDRESPONSE, Ver2_SUPLTRIGGEREDRESPONSE_sequence);

  return offset;
}


static const per_sequence_t Ver2_SUPLTRIGGEREDSTOP_sequence[] = {
  { &hf_ulp_statusCode      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_StatusCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SUPLTRIGGEREDSTOP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SUPLTRIGGEREDSTOP, Ver2_SUPLTRIGGEREDSTOP_sequence);

  return offset;
}


static const per_sequence_t Ver2_SUPLNOTIFY_sequence[] = {
  { &hf_ulp_notification    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_Notification },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SUPLNOTIFY(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SUPLNOTIFY, Ver2_SUPLNOTIFY_sequence);

  return offset;
}


static const value_string ulp_NotificationResponse_vals[] = {
  {   0, "allowed" },
  {   1, "notAllowed" },
  { 0, NULL }
};


static int
dissect_ulp_NotificationResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t Ver2_SUPLNOTIFYRESPONSE_sequence[] = {
  { &hf_ulp_notificationResponse, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_NotificationResponse },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SUPLNOTIFYRESPONSE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SUPLNOTIFYRESPONSE, Ver2_SUPLNOTIFYRESPONSE_sequence);

  return offset;
}


static const per_sequence_t Ver2_SUPLSETINIT_sequence[] = {
  { &hf_ulp_targetSETID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SETId },
  { &hf_ulp_qoP             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_QoP },
  { &hf_ulp_applicationID   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ApplicationID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SUPLSETINIT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SUPLSETINIT, Ver2_SUPLSETINIT_sequence);

  return offset;
}


static const per_sequence_t SessionInformation_sequence[] = {
  { &hf_ulp_sessionID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SessionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SessionInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SessionInformation, SessionInformation_sequence);

  return offset;
}


static const per_sequence_t SessionList_sequence_of[1] = {
  { &hf_ulp_SessionList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_SessionInformation },
};

static int
dissect_ulp_SessionList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_SessionList, SessionList_sequence_of,
                                                  1, maxnumSessions, false);

  return offset;
}


static const per_sequence_t GANSSSignalsDescription_sequence[] = {
  { &hf_ulp_ganssId         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_15 },
  { &hf_ulp_gANSSSignals    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_GANSSSignals },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GANSSSignalsDescription(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GANSSSignalsDescription, GANSSSignalsDescription_sequence);

  return offset;
}


static const per_sequence_t GANSSsignalsInfo_sequence_of[1] = {
  { &hf_ulp_GANSSsignalsInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_GANSSSignalsDescription },
};

static int
dissect_ulp_GANSSsignalsInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_GANSSsignalsInfo, GANSSsignalsInfo_sequence_of,
                                                  1, maxGANSS, false);

  return offset;
}


static const per_sequence_t PositionData_sequence[] = {
  { &hf_ulp_position        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_Position },
  { &hf_ulp_posMethod       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_PosMethod },
  { &hf_ulp_gnssPosTechnology, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_GNSSPosTechnology },
  { &hf_ulp_ganssSignalsInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_GANSSsignalsInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PositionData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_PositionData, PositionData_sequence);

  return offset;
}


static const value_string ulp_ResultCode_vals[] = {
  {   1, "outofradiocoverage" },
  {   2, "noposition" },
  {   3, "nomeasurement" },
  {   4, "nopositionnomeasurement" },
  {   5, "outofmemory" },
  {   6, "outofmemoryintermediatereporting" },
  {   7, "other" },
  { 0, NULL }
};

static uint32_t ResultCode_value_map[7+0] = {1, 2, 3, 4, 5, 6, 7};

static int
dissect_ulp_ResultCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, true, 0, ResultCode_value_map);

  return offset;
}



static int
dissect_ulp_INTEGER_0_31536000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31536000U, NULL, false);

  return offset;
}


static const value_string ulp_TimeStamp_vals[] = {
  {   0, "absoluteTime" },
  {   1, "relativeTime" },
  { 0, NULL }
};

static const per_choice_t TimeStamp_choice[] = {
  {   0, &hf_ulp_absoluteTime    , ASN1_NO_EXTENSIONS     , dissect_ulp_UTCTime },
  {   1, &hf_ulp_relativeTime    , ASN1_NO_EXTENSIONS     , dissect_ulp_INTEGER_0_31536000 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_TimeStamp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_TimeStamp, TimeStamp_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t ReportData_sequence[] = {
  { &hf_ulp_positionData    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_PositionData },
  { &hf_ulp_multipleLocationIds, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_MultipleLocationIds },
  { &hf_ulp_resultCode      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ResultCode },
  { &hf_ulp_timestamp       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_TimeStamp },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ReportData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ReportData, ReportData_sequence);

  return offset;
}


static const per_sequence_t ReportDataList_sequence_of[1] = {
  { &hf_ulp_ReportDataList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_ReportData },
};

static int
dissect_ulp_ReportDataList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_ReportDataList, ReportDataList_sequence_of,
                                                  1, 1024, false);

  return offset;
}


static const per_sequence_t Ver2_SUPLREPORT_sequence[] = {
  { &hf_ulp_sessionList     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SessionList },
  { &hf_ulp_sETCapabilities , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SETCapabilities },
  { &hf_ulp_reportDataList  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_ReportDataList },
  { &hf_ulp_ver             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Ver },
  { &hf_ulp_moreComponents  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Ver2_SUPLREPORT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Ver2_SUPLREPORT, Ver2_SUPLREPORT_sequence);

  return offset;
}


static const value_string ulp_UlpMessage_vals[] = {
  {   0, "msSUPLINIT" },
  {   1, "msSUPLSTART" },
  {   2, "msSUPLRESPONSE" },
  {   3, "msSUPLPOSINIT" },
  {   4, "msSUPLPOS" },
  {   5, "msSUPLEND" },
  {   6, "msSUPLAUTHREQ" },
  {   7, "msSUPLAUTHRESP" },
  {   8, "msSUPLTRIGGEREDSTART" },
  {   9, "msSUPLTRIGGEREDRESPONSE" },
  {  10, "msSUPLTRIGGEREDSTOP" },
  {  11, "msSUPLNOTIFY" },
  {  12, "msSUPLNOTIFYRESPONSE" },
  {  13, "msSUPLSETINIT" },
  {  14, "msSUPLREPORT" },
  { 0, NULL }
};

static const per_choice_t UlpMessage_choice[] = {
  {   0, &hf_ulp_msSUPLINIT      , ASN1_EXTENSION_ROOT    , dissect_ulp_SUPLINIT },
  {   1, &hf_ulp_msSUPLSTART     , ASN1_EXTENSION_ROOT    , dissect_ulp_SUPLSTART },
  {   2, &hf_ulp_msSUPLRESPONSE  , ASN1_EXTENSION_ROOT    , dissect_ulp_SUPLRESPONSE },
  {   3, &hf_ulp_msSUPLPOSINIT   , ASN1_EXTENSION_ROOT    , dissect_ulp_SUPLPOSINIT },
  {   4, &hf_ulp_msSUPLPOS       , ASN1_EXTENSION_ROOT    , dissect_ulp_SUPLPOS },
  {   5, &hf_ulp_msSUPLEND       , ASN1_EXTENSION_ROOT    , dissect_ulp_SUPLEND },
  {   6, &hf_ulp_msSUPLAUTHREQ   , ASN1_EXTENSION_ROOT    , dissect_ulp_SUPLAUTHREQ },
  {   7, &hf_ulp_msSUPLAUTHRESP  , ASN1_EXTENSION_ROOT    , dissect_ulp_SUPLAUTHRESP },
  {   8, &hf_ulp_msSUPLTRIGGEREDSTART, ASN1_NOT_EXTENSION_ROOT, dissect_ulp_Ver2_SUPLTRIGGEREDSTART },
  {   9, &hf_ulp_msSUPLTRIGGEREDRESPONSE, ASN1_NOT_EXTENSION_ROOT, dissect_ulp_Ver2_SUPLTRIGGEREDRESPONSE },
  {  10, &hf_ulp_msSUPLTRIGGEREDSTOP, ASN1_NOT_EXTENSION_ROOT, dissect_ulp_Ver2_SUPLTRIGGEREDSTOP },
  {  11, &hf_ulp_msSUPLNOTIFY    , ASN1_NOT_EXTENSION_ROOT, dissect_ulp_Ver2_SUPLNOTIFY },
  {  12, &hf_ulp_msSUPLNOTIFYRESPONSE, ASN1_NOT_EXTENSION_ROOT, dissect_ulp_Ver2_SUPLNOTIFYRESPONSE },
  {  13, &hf_ulp_msSUPLSETINIT   , ASN1_NOT_EXTENSION_ROOT, dissect_ulp_Ver2_SUPLSETINIT },
  {  14, &hf_ulp_msSUPLREPORT    , ASN1_NOT_EXTENSION_ROOT, dissect_ulp_Ver2_SUPLREPORT },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_UlpMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

uint32_t UlpMessage;

    offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_UlpMessage, UlpMessage_choice,
                                 &UlpMessage);


  col_prepend_fstr(actx->pinfo->cinfo, COL_INFO, "%s ", val_to_str_const(UlpMessage,ulp_UlpMessage_vals,"Unknown"));


  return offset;
}


static const per_sequence_t ULP_PDU_sequence[] = {
  { &hf_ulp_length          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_version         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_Version },
  { &hf_ulp_sessionID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_SessionID },
  { &hf_ulp_message         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_UlpMessage },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ULP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  proto_item *it;
  proto_tree *ulp_tree;

  it = proto_tree_add_item(tree, proto_ulp, tvb, 0, -1, ENC_NA);
  ulp_tree = proto_item_add_subtree(it, ett_ulp);

  col_set_str(actx->pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear(actx->pinfo->cinfo, COL_INFO);
  offset = dissect_per_sequence(tvb, offset, actx, ulp_tree, hf_index,
                                   ett_ulp_ULP_PDU, ULP_PDU_sequence);


  return offset;
}

/*--- PDUs ---*/

static int dissect_ULP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, false, pinfo);
  offset = dissect_ulp_ULP_PDU(tvb, offset, &asn1_ctx, tree, hf_ulp_ULP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}



static unsigned
get_ulp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  /* PDU length = Message length */
  return tvb_get_ntohs(tvb,offset);
}

static int
dissect_ulp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, ulp_desegment, ULP_HEADER_SIZE,
                   get_ulp_pdu_len, dissect_ULP_PDU_PDU, data);
  return tvb_captured_length(tvb);
}

void proto_reg_handoff_ulp(void);

/*--- proto_register_ulp -------------------------------------------*/
void proto_register_ulp(void) {

  /* List of fields */
  static hf_register_info hf[] = {

    { &hf_ulp_ULP_PDU_PDU,
      { "ULP-PDU", "ulp.ULP_PDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_length,
      { "length", "ulp.length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ulp_version,
      { "version", "ulp.version_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_sessionID,
      { "sessionID", "ulp.sessionID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_message,
      { "message", "ulp.message",
        FT_UINT32, BASE_DEC, VALS(ulp_UlpMessage_vals), 0,
        "UlpMessage", HFILL }},
    { &hf_ulp_msSUPLINIT,
      { "msSUPLINIT", "ulp.msSUPLINIT_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SUPLINIT", HFILL }},
    { &hf_ulp_msSUPLSTART,
      { "msSUPLSTART", "ulp.msSUPLSTART_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SUPLSTART", HFILL }},
    { &hf_ulp_msSUPLRESPONSE,
      { "msSUPLRESPONSE", "ulp.msSUPLRESPONSE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SUPLRESPONSE", HFILL }},
    { &hf_ulp_msSUPLPOSINIT,
      { "msSUPLPOSINIT", "ulp.msSUPLPOSINIT_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SUPLPOSINIT", HFILL }},
    { &hf_ulp_msSUPLPOS,
      { "msSUPLPOS", "ulp.msSUPLPOS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SUPLPOS", HFILL }},
    { &hf_ulp_msSUPLEND,
      { "msSUPLEND", "ulp.msSUPLEND_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SUPLEND", HFILL }},
    { &hf_ulp_msSUPLAUTHREQ,
      { "msSUPLAUTHREQ", "ulp.msSUPLAUTHREQ_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SUPLAUTHREQ", HFILL }},
    { &hf_ulp_msSUPLAUTHRESP,
      { "msSUPLAUTHRESP", "ulp.msSUPLAUTHRESP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SUPLAUTHRESP", HFILL }},
    { &hf_ulp_msSUPLTRIGGEREDSTART,
      { "msSUPLTRIGGEREDSTART", "ulp.msSUPLTRIGGEREDSTART_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ver2_SUPLTRIGGEREDSTART", HFILL }},
    { &hf_ulp_msSUPLTRIGGEREDRESPONSE,
      { "msSUPLTRIGGEREDRESPONSE", "ulp.msSUPLTRIGGEREDRESPONSE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ver2_SUPLTRIGGEREDRESPONSE", HFILL }},
    { &hf_ulp_msSUPLTRIGGEREDSTOP,
      { "msSUPLTRIGGEREDSTOP", "ulp.msSUPLTRIGGEREDSTOP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ver2_SUPLTRIGGEREDSTOP", HFILL }},
    { &hf_ulp_msSUPLNOTIFY,
      { "msSUPLNOTIFY", "ulp.msSUPLNOTIFY_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ver2_SUPLNOTIFY", HFILL }},
    { &hf_ulp_msSUPLNOTIFYRESPONSE,
      { "msSUPLNOTIFYRESPONSE", "ulp.msSUPLNOTIFYRESPONSE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ver2_SUPLNOTIFYRESPONSE", HFILL }},
    { &hf_ulp_msSUPLSETINIT,
      { "msSUPLSETINIT", "ulp.msSUPLSETINIT_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ver2_SUPLSETINIT", HFILL }},
    { &hf_ulp_msSUPLREPORT,
      { "msSUPLREPORT", "ulp.msSUPLREPORT_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Ver2_SUPLREPORT", HFILL }},
    { &hf_ulp_posMethod,
      { "posMethod", "ulp.posMethod",
        FT_UINT32, BASE_DEC, VALS(ulp_PosMethod_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_notification,
      { "notification", "ulp.notification_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_sLPAddress,
      { "sLPAddress", "ulp.sLPAddress",
        FT_UINT32, BASE_DEC, VALS(ulp_SLPAddress_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_qoP,
      { "qoP", "ulp.qoP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_sLPMode,
      { "sLPMode", "ulp.sLPMode",
        FT_UINT32, BASE_DEC, VALS(ulp_SLPMode_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_mac,
      { "mac", "ulp.mac",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_keyIdentity,
      { "keyIdentity", "ulp.keyIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ver2_SUPL_INIT_extension,
      { "ver2-SUPL-INIT-extension", "ulp.ver2_SUPL_INIT_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_notificationType,
      { "notificationType", "ulp.notificationType",
        FT_UINT32, BASE_DEC, VALS(ulp_NotificationType_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_encodingType,
      { "encodingType", "ulp.encodingType",
        FT_UINT32, BASE_DEC, VALS(ulp_EncodingType_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_requestorId,
      { "requestorId", "ulp.requestorId",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_requestorIdType,
      { "requestorIdType", "ulp.requestorIdType",
        FT_UINT32, BASE_DEC, VALS(ulp_FormatIndicator_vals), 0,
        "FormatIndicator", HFILL }},
    { &hf_ulp_clientName,
      { "clientName", "ulp.clientName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_clientNameType,
      { "clientNameType", "ulp.clientNameType",
        FT_UINT32, BASE_DEC, VALS(ulp_FormatIndicator_vals), 0,
        "FormatIndicator", HFILL }},
    { &hf_ulp_ver2_Notification_extension,
      { "ver2-Notification-extension", "ulp.ver2_Notification_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_sETCapabilities,
      { "sETCapabilities", "ulp.sETCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_locationId,
      { "locationId", "ulp.locationId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ver2_SUPL_START_extension,
      { "ver2-SUPL-START-extension", "ulp.ver2_SUPL_START_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_posTechnology,
      { "posTechnology", "ulp.posTechnology_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_prefMethod,
      { "prefMethod", "ulp.prefMethod",
        FT_UINT32, BASE_DEC, VALS(ulp_PrefMethod_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_posProtocol,
      { "posProtocol", "ulp.posProtocol_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ver2_SETCapabilities_extension,
      { "ver2-SETCapabilities-extension", "ulp.ver2_SETCapabilities_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_agpsSETassisted,
      { "agpsSETassisted", "ulp.agpsSETassisted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_agpsSETBased,
      { "agpsSETBased", "ulp.agpsSETBased",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_autonomousGPS,
      { "autonomousGPS", "ulp.autonomousGPS",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_aflt,
      { "aflt", "ulp.aflt",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ecid,
      { "ecid", "ulp.ecid",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_eotd,
      { "eotd", "ulp.eotd",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_otdoa,
      { "otdoa", "ulp.otdoa",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ver2_PosTechnology_extension,
      { "ver2-PosTechnology-extension", "ulp.ver2_PosTechnology_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_tia801,
      { "tia801", "ulp.tia801",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_rrlp,
      { "rrlp", "ulp.rrlp",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_rrc,
      { "rrc", "ulp.rrc",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ver2_PosProtocol_extension,
      { "ver2-PosProtocol-extension", "ulp.ver2_PosProtocol_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_sETAuthKey,
      { "sETAuthKey", "ulp.sETAuthKey",
        FT_UINT32, BASE_DEC, VALS(ulp_SETAuthKey_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_keyIdentity4,
      { "keyIdentity4", "ulp.keyIdentity4",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ver2_SUPL_RESPONSE_extension,
      { "ver2-SUPL-RESPONSE-extension", "ulp.ver2_SUPL_RESPONSE_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_shortKey,
      { "shortKey", "ulp.shortKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_128", HFILL }},
    { &hf_ulp_longKey,
      { "longKey", "ulp.longKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_256", HFILL }},
    { &hf_ulp_requestedAssistData,
      { "requestedAssistData", "ulp.requestedAssistData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_position,
      { "position", "ulp.position_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_suplpos,
      { "suplpos", "ulp.suplpos_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ver,
      { "ver", "ulp.ver",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ver2_SUPL_POS_INIT_extension,
      { "ver2-SUPL-POS-INIT-extension", "ulp.ver2_SUPL_POS_INIT_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_almanacRequested,
      { "almanacRequested", "ulp.almanacRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_utcModelRequested,
      { "utcModelRequested", "ulp.utcModelRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ionosphericModelRequested,
      { "ionosphericModelRequested", "ulp.ionosphericModelRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_dgpsCorrectionsRequested,
      { "dgpsCorrectionsRequested", "ulp.dgpsCorrectionsRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_referenceLocationRequested,
      { "referenceLocationRequested", "ulp.referenceLocationRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_referenceTimeRequested,
      { "referenceTimeRequested", "ulp.referenceTimeRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_acquisitionAssistanceRequested,
      { "acquisitionAssistanceRequested", "ulp.acquisitionAssistanceRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_realTimeIntegrityRequested,
      { "realTimeIntegrityRequested", "ulp.realTimeIntegrityRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_navigationModelRequested,
      { "navigationModelRequested", "ulp.navigationModelRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_navigationModelData,
      { "navigationModelData", "ulp.navigationModelData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavigationModel", HFILL }},
    { &hf_ulp_ver2_RequestedAssistData_extension,
      { "ver2-RequestedAssistData-extension", "ulp.ver2_RequestedAssistData_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_gpsWeek,
      { "gpsWeek", "ulp.gpsWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ulp_gpsToe,
      { "gpsToe", "ulp.gpsToe",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_hours, 0,
        "INTEGER_0_167", HFILL }},
    { &hf_ulp_nsat,
      { "nsat", "ulp.nsat",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_ulp_toeLimit,
      { "toeLimit", "ulp.toeLimit",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_hours, 0,
        "INTEGER_0_10", HFILL }},
    { &hf_ulp_satInfo,
      { "satInfo", "ulp.satInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SatelliteInfo", HFILL }},
    { &hf_ulp_SatelliteInfo_item,
      { "SatelliteInfoElement", "ulp.SatelliteInfoElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_satId,
      { "satId", "ulp.satId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_ulp_iode,
      { "iode", "ulp.iode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_posPayLoad,
      { "posPayLoad", "ulp.posPayLoad",
        FT_UINT32, BASE_DEC, VALS(ulp_PosPayLoad_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_velocity,
      { "velocity", "ulp.velocity",
        FT_UINT32, BASE_DEC, VALS(ulp_Velocity_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_ver2_SUPL_POS_extension,
      { "ver2-SUPL-POS-extension", "ulp.ver2_SUPL_POS_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_tia801payload,
      { "tia801payload", "ulp.tia801payload",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_8192", HFILL }},
    { &hf_ulp_rrcPayload,
      { "rrcPayload", "ulp.rrcPayload",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_8192", HFILL }},
    { &hf_ulp_rrlpPayload,
      { "rrlpPayload", "ulp.rrlpPayload",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ver2_PosPayLoad_extension,
      { "ver2-PosPayLoad-extension", "ulp.ver2_PosPayLoad_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_statusCode,
      { "statusCode", "ulp.statusCode",
        FT_UINT32, BASE_DEC, VALS(ulp_StatusCode_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_ver2_SUPL_END_extension,
      { "ver2-SUPL-END-extension", "ulp.ver2_SUPL_END_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_sPCSETKey,
      { "sPCSETKey", "ulp.sPCSETKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_spctid,
      { "spctid", "ulp.spctid_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_sPCSETKeylifetime,
      { "sPCSETKeylifetime", "ulp.sPCSETKeylifetime",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_notificationResponse,
      { "notificationResponse", "ulp.notificationResponse",
        FT_UINT32, BASE_DEC, VALS(ulp_NotificationResponse_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_targetSETID,
      { "targetSETID", "ulp.targetSETID",
        FT_UINT32, BASE_DEC, VALS(ulp_SETId_vals), 0,
        "SETId", HFILL }},
    { &hf_ulp_applicationID,
      { "applicationID", "ulp.applicationID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_multipleLocationIds,
      { "multipleLocationIds", "ulp.multipleLocationIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_thirdParty,
      { "thirdParty", "ulp.thirdParty",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_triggerType,
      { "triggerType", "ulp.triggerType",
        FT_UINT32, BASE_DEC, VALS(ulp_TriggerType_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_triggerParams,
      { "triggerParams", "ulp.triggerParams",
        FT_UINT32, BASE_DEC, VALS(ulp_TriggerParams_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_reportingCap,
      { "reportingCap", "ulp.reportingCap_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_causeCode,
      { "causeCode", "ulp.causeCode",
        FT_UINT32, BASE_DEC, VALS(ulp_CauseCode_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_periodicParams,
      { "periodicParams", "ulp.periodicParams_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_areaEventParams,
      { "areaEventParams", "ulp.areaEventParams_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_numberOfFixes,
      { "numberOfFixes", "ulp.numberOfFixes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8639999", HFILL }},
    { &hf_ulp_intervalBetweenFixes,
      { "intervalBetweenFixes", "ulp.intervalBetweenFixes",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "INTEGER_1_8639999", HFILL }},
    { &hf_ulp_startTime,
      { "startTime", "ulp.startTime",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "INTEGER_0_2678400", HFILL }},
    { &hf_ulp_areaEventType,
      { "areaEventType", "ulp.areaEventType",
        FT_UINT32, BASE_DEC, VALS(ulp_AreaEventType_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_locationEstimate,
      { "locationEstimate", "ulp.locationEstimate",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_repeatedReportingParams,
      { "repeatedReportingParams", "ulp.repeatedReportingParams_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_stopTime,
      { "stopTime", "ulp.stopTime",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "INTEGER_0_11318399", HFILL }},
    { &hf_ulp_geographicTargetAreaList,
      { "geographicTargetAreaList", "ulp.geographicTargetAreaList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_areaIdLists,
      { "areaIdLists", "ulp.areaIdLists",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxAreaIdList_OF_AreaIdList", HFILL }},
    { &hf_ulp_areaIdLists_item,
      { "AreaIdList", "ulp.AreaIdList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_minimumIntervalTime,
      { "minimumIntervalTime", "ulp.minimumIntervalTime",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "INTEGER_1_604800", HFILL }},
    { &hf_ulp_maximumNumberOfReports,
      { "maximumNumberOfReports", "ulp.maximumNumberOfReports",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1024", HFILL }},
    { &hf_ulp_GeographicTargetAreaList_item,
      { "GeographicTargetArea", "ulp.GeographicTargetArea",
        FT_UINT32, BASE_DEC, VALS(ulp_GeographicTargetArea_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_circularArea,
      { "circularArea", "ulp.circularArea_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ellipticalArea,
      { "ellipticalArea", "ulp.ellipticalArea_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_polygonArea,
      { "polygonArea", "ulp.polygonArea_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_areaIdSet,
      { "areaIdSet", "ulp.areaIdSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_areaIdSetType,
      { "areaIdSetType", "ulp.areaIdSetType",
        FT_UINT32, BASE_DEC, VALS(ulp_AreaIdSetType_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_geoAreaMappingList,
      { "geoAreaMappingList", "ulp.geoAreaMappingList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_AreaIdSet_item,
      { "AreaId", "ulp.AreaId",
        FT_UINT32, BASE_DEC, VALS(ulp_AreaId_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_gSMAreaId,
      { "gSMAreaId", "ulp.gSMAreaId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_wCDMAAreaId,
      { "wCDMAAreaId", "ulp.wCDMAAreaId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_cDMAAreaId,
      { "cDMAAreaId", "ulp.cDMAAreaId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_hRPDAreaId,
      { "hRPDAreaId", "ulp.hRPDAreaId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_uMBAreaId,
      { "uMBAreaId", "ulp.uMBAreaId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_lTEAreaId,
      { "lTEAreaId", "ulp.lTEAreaId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_wLANAreaId,
      { "wLANAreaId", "ulp.wLANAreaId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_wiMAXAreaId,
      { "wiMAXAreaId", "ulp.wiMAXAreaId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_nRAreaId,
      { "nRAreaId", "ulp.nRAreaId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_refMCC,
      { "refMCC", "ulp.refMCC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_999", HFILL }},
    { &hf_ulp_refMNC,
      { "refMNC", "ulp.refMNC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_999", HFILL }},
    { &hf_ulp_refLAC,
      { "refLAC", "ulp.refLAC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ulp_refCI,
      { "refCI", "ulp.refCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ulp_refUC,
      { "refUC", "ulp.refUC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_268435455", HFILL }},
    { &hf_ulp_refSID,
      { "refSID", "ulp.refSID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ulp_refNID,
      { "refNID", "ulp.refNID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_ulp_refBASEID,
      { "refBASEID", "ulp.refBASEID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ulp_refSECTORID,
      { "refSECTORID", "ulp.refSECTORID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_128", HFILL }},
    { &hf_ulp_refCI_01,
      { "refCI", "ulp.refCI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_29", HFILL }},
    { &hf_ulp_apMACAddress,
      { "apMACAddress", "ulp.apMACAddress",
        FT_ETHER, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_bsID_MSB,
      { "bsID-MSB", "ulp.bsID_MSB",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_ulp_bsID_LSB,
      { "bsID-LSB", "ulp.bsID_LSB",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_ulp_refCI_02,
      { "refCI", "ulp.refCI",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_36", HFILL }},
    { &hf_ulp_GeoAreaMappingList_item,
      { "GeoAreaIndex", "ulp.GeoAreaIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_supportedNetworkInformation,
      { "supportedNetworkInformation", "ulp.supportedNetworkInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_reportingMode,
      { "reportingMode", "ulp.reportingMode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_gnssPosTechnology,
      { "gnssPosTechnology", "ulp.gnssPosTechnology_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_repMode,
      { "repMode", "ulp.repMode",
        FT_UINT32, BASE_DEC, VALS(ulp_RepModee_vals), 0,
        "RepModee", HFILL }},
    { &hf_ulp_batchRepConditions,
      { "batchRepConditions", "ulp.batchRepConditions",
        FT_UINT32, BASE_DEC, VALS(ulp_BatchRepConditions_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_batchRepType,
      { "batchRepType", "ulp.batchRepType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_num_interval,
      { "num-interval", "ulp.num_interval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1024", HFILL }},
    { &hf_ulp_num_minutes,
      { "num-minutes", "ulp.num_minutes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_2048", HFILL }},
    { &hf_ulp_endofsession,
      { "endofsession", "ulp.endofsession_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_reportPosition,
      { "reportPosition", "ulp.reportPosition",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_reportMeasurements,
      { "reportMeasurements", "ulp.reportMeasurements",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_intermediateReports,
      { "intermediateReports", "ulp.intermediateReports",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_discardOldest,
      { "discardOldest", "ulp.discardOldest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_sessionList,
      { "sessionList", "ulp.sessionList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_reportDataList,
      { "reportDataList", "ulp.reportDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_moreComponents,
      { "moreComponents", "ulp.moreComponents_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_SessionList_item,
      { "SessionInformation", "ulp.SessionInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ReportDataList_item,
      { "ReportData", "ulp.ReportData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_positionData,
      { "positionData", "ulp.positionData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_resultCode,
      { "resultCode", "ulp.resultCode",
        FT_UINT32, BASE_DEC, VALS(ulp_ResultCode_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_timestamp,
      { "timestamp", "ulp.timestamp",
        FT_UINT32, BASE_DEC, VALS(ulp_TimeStamp_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_ganssSignalsInfo,
      { "ganssSignalsInfo", "ulp.ganssSignalsInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_GANSSsignalsInfo_item,
      { "GANSSSignalsDescription", "ulp.GANSSSignalsDescription_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ganssId,
      { "ganssId", "ulp.ganssId",
        FT_UINT32, BASE_DEC, VALS(ulp_ganss_id_vals), 0,
        "INTEGER_0_15", HFILL }},
    { &hf_ulp_gANSSSignals,
      { "gANSSSignals", "ulp.gANSSSignals",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_absoluteTime,
      { "absoluteTime", "ulp.absoluteTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTCTime", HFILL }},
    { &hf_ulp_relativeTime,
      { "relativeTime", "ulp.relativeTime",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "INTEGER_0_31536000", HFILL }},
    { &hf_ulp_notificationMode,
      { "notificationMode", "ulp.notificationMode",
        FT_UINT32, BASE_DEC, VALS(ulp_NotificationMode_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_e_SLPAddress,
      { "e-SLPAddress", "ulp.e_SLPAddress",
        FT_UINT32, BASE_DEC, VALS(ulp_SLPAddress_vals), 0,
        "SLPAddress", HFILL }},
    { &hf_ulp_historicReporting,
      { "historicReporting", "ulp.historicReporting_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_protectionLevel,
      { "protectionLevel", "ulp.protectionLevel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_minimumMajorVersion,
      { "minimumMajorVersion", "ulp.minimumMajorVersion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_allowedReportingType,
      { "allowedReportingType", "ulp.allowedReportingType",
        FT_UINT32, BASE_DEC, VALS(ulp_AllowedReportingType_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_reportingCriteria,
      { "reportingCriteria", "ulp.reportingCriteria_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_timeWindow,
      { "timeWindow", "ulp.timeWindow_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_maxNumberofReports,
      { "maxNumberofReports", "ulp.maxNumberofReports",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_65536", HFILL }},
    { &hf_ulp_minTimeInterval,
      { "minTimeInterval", "ulp.minTimeInterval",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "INTEGER_1_86400", HFILL }},
    { &hf_ulp_startTime_01,
      { "startTime", "ulp.startTime",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_minutes, 0,
        "INTEGER_M525600_M1", HFILL }},
    { &hf_ulp_stopTime_01,
      { "stopTime", "ulp.stopTime",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_minutes, 0,
        "INTEGER_M525599_0", HFILL }},
    { &hf_ulp_protlevel,
      { "protlevel", "ulp.protlevel",
        FT_UINT32, BASE_DEC, VALS(ulp_ProtLevel_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_basicProtectionParams,
      { "basicProtectionParams", "ulp.basicProtectionParams_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_keyIdentifier,
      { "keyIdentifier", "ulp.keyIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_8", HFILL }},
    { &hf_ulp_basicReplayCounter,
      { "basicReplayCounter", "ulp.basicReplayCounter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ulp_basicMAC,
      { "basicMAC", "ulp.basicMAC",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_ulp_initialApproximateposition,
      { "initialApproximateposition", "ulp.initialApproximateposition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Position", HFILL }},
    { &hf_ulp_utran_GPSReferenceTimeResult,
      { "utran-GPSReferenceTimeResult", "ulp.utran_GPSReferenceTimeResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_utran_GANSSReferenceTimeResult,
      { "utran-GANSSReferenceTimeResult", "ulp.utran_GANSSReferenceTimeResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_utran_GPSReferenceTimeAssistance,
      { "utran-GPSReferenceTimeAssistance", "ulp.utran_GPSReferenceTimeAssistance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_utran_GANSSReferenceTimeAssistance,
      { "utran-GANSSReferenceTimeAssistance", "ulp.utran_GANSSReferenceTimeAssistance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ver2_HighAccuracyPosition,
      { "ver2-HighAccuracyPosition", "ulp.ver2_HighAccuracyPosition_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_emergencyCallLocation,
      { "emergencyCallLocation", "ulp.emergencyCallLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_serviceCapabilities,
      { "serviceCapabilities", "ulp.serviceCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_supportedBearers,
      { "supportedBearers", "ulp.supportedBearers_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_servicesSupported,
      { "servicesSupported", "ulp.servicesSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_reportingCapabilities,
      { "reportingCapabilities", "ulp.reportingCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportingCap", HFILL }},
    { &hf_ulp_eventTriggerCapabilities,
      { "eventTriggerCapabilities", "ulp.eventTriggerCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_sessionCapabilities,
      { "sessionCapabilities", "ulp.sessionCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_periodicTrigger,
      { "periodicTrigger", "ulp.periodicTrigger",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_areaEventTrigger,
      { "areaEventTrigger", "ulp.areaEventTrigger",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_geoAreaShapesSupported,
      { "geoAreaShapesSupported", "ulp.geoAreaShapesSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_maxNumGeoAreaSupported,
      { "maxNumGeoAreaSupported", "ulp.maxNumGeoAreaSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxNumGeoArea", HFILL }},
    { &hf_ulp_maxAreaIdListSupported,
      { "maxAreaIdListSupported", "ulp.maxAreaIdListSupported",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxAreaIdList", HFILL }},
    { &hf_ulp_maxAreaIdSupportedPerList,
      { "maxAreaIdSupportedPerList", "ulp.maxAreaIdSupportedPerList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_maxAreaId", HFILL }},
    { &hf_ulp_ellipticalArea_01,
      { "ellipticalArea", "ulp.ellipticalArea",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_polygonArea_01,
      { "polygonArea", "ulp.polygonArea",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_maxNumberTotalSessions,
      { "maxNumberTotalSessions", "ulp.maxNumberTotalSessions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_128", HFILL }},
    { &hf_ulp_maxNumberPeriodicSessions,
      { "maxNumberPeriodicSessions", "ulp.maxNumberPeriodicSessions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_ulp_maxNumberTriggeredSessions,
      { "maxNumberTriggeredSessions", "ulp.maxNumberTriggeredSessions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_ulp_gsm,
      { "gsm", "ulp.gsm",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_wcdma,
      { "wcdma", "ulp.wcdma",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_lte,
      { "lte", "ulp.lte",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_cdma,
      { "cdma", "ulp.cdma",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_hprd,
      { "hprd", "ulp.hprd",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_umb,
      { "umb", "ulp.umb",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_wlan,
      { "wlan", "ulp.wlan",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_wiMAX,
      { "wiMAX", "ulp.wiMAX",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_nr,
      { "nr", "ulp.nr",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_lpp,
      { "lpp", "ulp.lpp",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_posProtocolVersionRRLP,
      { "posProtocolVersionRRLP", "ulp.posProtocolVersionRRLP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosProtocolVersion3GPP", HFILL }},
    { &hf_ulp_posProtocolVersionRRC,
      { "posProtocolVersionRRC", "ulp.posProtocolVersionRRC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosProtocolVersion3GPP", HFILL }},
    { &hf_ulp_posProtocolVersionTIA801,
      { "posProtocolVersionTIA801", "ulp.posProtocolVersionTIA801",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PosProtocolVersion3GPP2", HFILL }},
    { &hf_ulp_posProtocolVersionLPP,
      { "posProtocolVersionLPP", "ulp.posProtocolVersionLPP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosProtocolVersion3GPP", HFILL }},
    { &hf_ulp_lppe,
      { "lppe", "ulp.lppe",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_posProtocolVersionLPPe,
      { "posProtocolVersionLPPe", "ulp.posProtocolVersionLPPe_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosProtocolVersionOMA", HFILL }},
    { &hf_ulp_majorVersionField,
      { "majorVersionField", "ulp.majorVersionField",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_technicalVersionField,
      { "technicalVersionField", "ulp.technicalVersionField",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_editorialVersionField,
      { "editorialVersionField", "ulp.editorialVersionField",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_PosProtocolVersion3GPP2_item,
      { "Supported3GPP2PosProtocolVersion", "ulp.Supported3GPP2PosProtocolVersion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_revisionNumber,
      { "revisionNumber", "ulp.revisionNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_ulp_pointReleaseNumber,
      { "pointReleaseNumber", "ulp.pointReleaseNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_internalEditLevel,
      { "internalEditLevel", "ulp.internalEditLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_minorVersionField,
      { "minorVersionField", "ulp.minorVersionField",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_gANSSPositionMethods,
      { "gANSSPositionMethods", "ulp.gANSSPositionMethods",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_additionalPositioningMethods,
      { "additionalPositioningMethods", "ulp.additionalPositioningMethods",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_GANSSPositionMethods_item,
      { "GANSSPositionMethod", "ulp.GANSSPositionMethod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ganssSBASid,
      { "ganssSBASid", "ulp.ganssSBASid",
        FT_UINT8, BASE_DEC, VALS(ulp_ganss_sbas_id_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_gANSSPositioningMethodTypes,
      { "gANSSPositioningMethodTypes", "ulp.gANSSPositioningMethodTypes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_rtk,
      { "rtk", "ulp.rtk_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_osr,
      { "osr", "ulp.osr",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_setAssisted,
      { "setAssisted", "ulp.setAssisted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_setBased,
      { "setBased", "ulp.setBased",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_autonomous,
      { "autonomous", "ulp.autonomous",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_AdditionalPositioningMethods_item,
      { "AddPosSupport-Element", "ulp.AddPosSupport_Element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_addPosID,
      { "addPosID", "ulp.addPosID",
        FT_UINT32, BASE_DEC, VALS(ulp_T_addPosID_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_addPosMode,
      { "addPosMode", "ulp.addPosMode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ganssRequestedCommonAssistanceDataList,
      { "ganssRequestedCommonAssistanceDataList", "ulp.ganssRequestedCommonAssistanceDataList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ganssRequestedGenericAssistanceDataList,
      { "ganssRequestedGenericAssistanceDataList", "ulp.ganssRequestedGenericAssistanceDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_extendedEphemeris,
      { "extendedEphemeris", "ulp.extendedEphemeris_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_extendedEphemerisCheck,
      { "extendedEphemerisCheck", "ulp.extendedEphemerisCheck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedEphCheck", HFILL }},
    { &hf_ulp_ganssReferenceTime,
      { "ganssReferenceTime", "ulp.ganssReferenceTime",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ganssIonosphericModel,
      { "ganssIonosphericModel", "ulp.ganssIonosphericModel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ganssAdditionalIonosphericModelForDataID00,
      { "ganssAdditionalIonosphericModelForDataID00", "ulp.ganssAdditionalIonosphericModelForDataID00",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ganssAdditionalIonosphericModelForDataID11,
      { "ganssAdditionalIonosphericModelForDataID11", "ulp.ganssAdditionalIonosphericModelForDataID11",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ganssEarthOrientationParameters,
      { "ganssEarthOrientationParameters", "ulp.ganssEarthOrientationParameters",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ganssAdditionalIonosphericModelForDataID01,
      { "ganssAdditionalIonosphericModelForDataID01", "ulp.ganssAdditionalIonosphericModelForDataID01",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_GanssRequestedGenericAssistanceDataList_item,
      { "GanssReqGenericData", "ulp.GanssReqGenericData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ganssId_01,
      { "ganssId", "ulp.ganssId",
        FT_UINT32, BASE_DEC, VALS(ulp_ganss_id_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_ganssSBASid_01,
      { "ganssSBASid", "ulp.ganssSBASid",
        FT_UINT8, BASE_DEC, VALS(ulp_ganss_sbas_id_vals), 0,
        "T_ganssSBASid_01", HFILL }},
    { &hf_ulp_ganssRealTimeIntegrity,
      { "ganssRealTimeIntegrity", "ulp.ganssRealTimeIntegrity",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ganssDifferentialCorrection,
      { "ganssDifferentialCorrection", "ulp.ganssDifferentialCorrection",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DGANSS_Sig_Id_Req", HFILL }},
    { &hf_ulp_ganssAlmanac,
      { "ganssAlmanac", "ulp.ganssAlmanac",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ganssNavigationModelData,
      { "ganssNavigationModelData", "ulp.ganssNavigationModelData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ganssTimeModels,
      { "ganssTimeModels", "ulp.ganssTimeModels",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ganssReferenceMeasurementInfo,
      { "ganssReferenceMeasurementInfo", "ulp.ganssReferenceMeasurementInfo",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ganssDataBits,
      { "ganssDataBits", "ulp.ganssDataBits_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ganssUTCModel,
      { "ganssUTCModel", "ulp.ganssUTCModel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ganssAdditionalDataChoices,
      { "ganssAdditionalDataChoices", "ulp.ganssAdditionalDataChoices_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ganssAuxiliaryInformation,
      { "ganssAuxiliaryInformation", "ulp.ganssAuxiliaryInformation",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ganssExtendedEphemeris,
      { "ganssExtendedEphemeris", "ulp.ganssExtendedEphemeris_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedEphemeris", HFILL }},
    { &hf_ulp_ganssExtendedEphemerisCheck,
      { "ganssExtendedEphemerisCheck", "ulp.ganssExtendedEphemerisCheck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GanssExtendedEphCheck", HFILL }},
    { &hf_ulp_bds_DifferentialCorrection,
      { "bds-DifferentialCorrection", "ulp.bds_DifferentialCorrection",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BDS_Sig_Id_Req", HFILL }},
    { &hf_ulp_bds_GridModelReq,
      { "bds-GridModelReq", "ulp.bds_GridModelReq",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ganssWeek,
      { "ganssWeek", "ulp.ganssWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ganssToe,
      { "ganssToe", "ulp.ganssToe",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_t_toeLimit,
      { "t-toeLimit", "ulp.t_toeLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_t_toeLimit", HFILL }},
    { &hf_ulp_satellitesListRelatedDataList,
      { "satellitesListRelatedDataList", "ulp.satellitesListRelatedDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_SatellitesListRelatedDataList_item,
      { "SatellitesListRelatedData", "ulp.SatellitesListRelatedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_iod,
      { "iod", "ulp.iod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ulp_ganssTODmin,
      { "ganssTODmin", "ulp.ganssTODmin",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "INTEGER_0_59", HFILL }},
    { &hf_ulp_reqDataBitAssistanceList,
      { "reqDataBitAssistanceList", "ulp.reqDataBitAssistanceList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_gnssSignals,
      { "gnssSignals", "ulp.gnssSignals",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GANSSSignals", HFILL }},
    { &hf_ulp_ganssDataBitInterval,
      { "ganssDataBitInterval", "ulp.ganssDataBitInterval",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_ganssDataBitInterval_fmt), 0,
        "INTEGER_0_15", HFILL }},
    { &hf_ulp_ganssDataBitSatList,
      { "ganssDataBitSatList", "ulp.ganssDataBitSatList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ganssDataBitSatList_item,
      { "ganssDataBitSatList item", "ulp.ganssDataBitSatList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_ulp_orbitModelID,
      { "orbitModelID", "ulp.orbitModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_ulp_clockModelID,
      { "clockModelID", "ulp.clockModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_ulp_utcModelID,
      { "utcModelID", "ulp.utcModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_ulp_almanacModelID,
      { "almanacModelID", "ulp.almanacModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_ulp_validity,
      { "validity", "ulp.validity",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_ExtendedEphemeris_validity_fmt), 0,
        "INTEGER_1_256", HFILL }},
    { &hf_ulp_beginTime,
      { "beginTime", "ulp.beginTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPSTime", HFILL }},
    { &hf_ulp_endTime,
      { "endTime", "ulp.endTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPSTime", HFILL }},
    { &hf_ulp_beginTime_01,
      { "beginTime", "ulp.beginTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSextEphTime", HFILL }},
    { &hf_ulp_endTime_01,
      { "endTime", "ulp.endTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSextEphTime", HFILL }},
    { &hf_ulp_gPSWeek,
      { "gPSWeek", "ulp.gPSWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ulp_gPSTOWhour,
      { "gPSTOWhour", "ulp.gPSTOWhour",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_167", HFILL }},
    { &hf_ulp_gANSSday,
      { "gANSSday", "ulp.gANSSday",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_ulp_gANSSTODhour,
      { "gANSSTODhour", "ulp.gANSSTODhour",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_23", HFILL }},
    { &hf_ulp_lPPPayload,
      { "lPPPayload", "ulp.lPPPayload",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_lPPPayload_item,
      { "lPPPayload item", "ulp.lPPPayload_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_tia801Payload,
      { "tia801Payload", "ulp.tia801Payload",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_tia801Payload_item,
      { "tia801Payload item", "ulp.tia801Payload_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_60000", HFILL }},
    { &hf_ulp_maj,
      { "maj", "ulp.maj",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_min,
      { "min", "ulp.min",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_servind,
      { "servind", "ulp.servind",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_setSessionID,
      { "setSessionID", "ulp.setSessionID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_slpSessionID,
      { "slpSessionID", "ulp.slpSessionID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_sessionId,
      { "sessionId", "ulp.sessionId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ulp_setId,
      { "setId", "ulp.setId",
        FT_UINT32, BASE_DEC, VALS(ulp_SETId_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_msisdn,
      { "msisdn", "ulp.msisdn",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_mdn,
      { "mdn", "ulp.mdn",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_minsi,
      { "min", "ulp.min",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_34", HFILL }},
    { &hf_ulp_imsi,
      { "imsi", "ulp.imsi",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_nai,
      { "nai", "ulp.nai",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_1000", HFILL }},
    { &hf_ulp_iPAddress,
      { "iPAddress", "ulp.iPAddress",
        FT_UINT32, BASE_DEC, VALS(ulp_IPAddress_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_ver2_imei,
      { "ver2-imei", "ulp.ver2_imei",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_8", HFILL }},
    { &hf_ulp_sessionSlpID,
      { "sessionID", "ulp.sessionID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_ulp_slpId,
      { "slpId", "ulp.slpId",
        FT_UINT32, BASE_DEC, VALS(ulp_SLPAddress_vals), 0,
        "SLPAddress", HFILL }},
    { &hf_ulp_ipv4Address,
      { "ipv4Address", "ulp.ipv4Address",
        FT_IPv4, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_ulp_ipv6Address,
      { "ipv6Address", "ulp.ipv6Address",
        FT_IPv6, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_ulp_fqdn,
      { "fqdn", "ulp.fqdn",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_cellInfo,
      { "cellInfo", "ulp.cellInfo",
        FT_UINT32, BASE_DEC, VALS(ulp_CellInfo_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_status,
      { "status", "ulp.status",
        FT_UINT32, BASE_DEC, VALS(ulp_Status_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_gsmCell,
      { "gsmCell", "ulp.gsmCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GsmCellInformation", HFILL }},
    { &hf_ulp_wcdmaCell,
      { "wcdmaCell", "ulp.wcdmaCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WcdmaCellInformation", HFILL }},
    { &hf_ulp_cdmaCell,
      { "cdmaCell", "ulp.cdmaCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CdmaCellInformation", HFILL }},
    { &hf_ulp_ver2_CellInfo_extension,
      { "ver2-CellInfo-extension", "ulp.ver2_CellInfo_extension",
        FT_UINT32, BASE_DEC, VALS(ulp_Ver2_CellInfo_extension_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_timestamp_01,
      { "timestamp", "ulp.timestamp",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTCTime", HFILL }},
    { &hf_ulp_positionEstimate,
      { "positionEstimate", "ulp.positionEstimate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_latitudeSign,
      { "latitudeSign", "ulp.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(ulp_T_latitudeSign_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_latitude,
      { "latitude", "ulp.latitude",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_PositionEstimate_latitude_fmt), 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_ulp_longitude,
      { "longitude", "ulp.longitude",
        FT_INT32, BASE_CUSTOM, CF_FUNC(ulp_PositionEstimate_longitude_fmt), 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_ulp_uncertainty,
      { "uncertainty", "ulp.uncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_uncertaintySemiMajor,
      { "uncertaintySemiMajor", "ulp.uncertaintySemiMajor",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_QoP_horacc_fmt), 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ulp_uncertaintySemiMinor,
      { "uncertaintySemiMinor", "ulp.uncertaintySemiMinor",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_QoP_horacc_fmt), 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ulp_orientationMajorAxis,
      { "orientationMajorAxis", "ulp.orientationMajorAxis",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_degree_degrees, 0,
        "INTEGER_0_180", HFILL }},
    { &hf_ulp_confidence,
      { "confidence", "ulp.confidence",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_percent, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_ulp_altitudeInfo,
      { "altitudeInfo", "ulp.altitudeInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_altitudeDirection,
      { "altitudeDirection", "ulp.altitudeDirection",
        FT_UINT32, BASE_DEC, VALS(ulp_T_altitudeDirection_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_altitude,
      { "altitude", "ulp.altitude",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_meters, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_ulp_altUncertainty,
      { "altUncertainty", "ulp.altUncertainty",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_QoP_veracc_fmt), 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ulp_refNID_01,
      { "refNID", "ulp.refNID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ulp_refSID_01,
      { "refSID", "ulp.refSID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_ulp_refBASELAT,
      { "refBASELAT", "ulp.refBASELAT",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4194303", HFILL }},
    { &hf_ulp_reBASELONG,
      { "reBASELONG", "ulp.reBASELONG",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_ulp_refREFPN,
      { "refREFPN", "ulp.refREFPN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_511", HFILL }},
    { &hf_ulp_refWeekNumber,
      { "refWeekNumber", "ulp.refWeekNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ulp_refSeconds,
      { "refSeconds", "ulp.refSeconds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4194303", HFILL }},
    { &hf_ulp_nmr,
      { "nmr", "ulp.nmr",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ta,
      { "ta", "ulp.ta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_frequencyInfo,
      { "frequencyInfo", "ulp.frequencyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_primaryScramblingCode,
      { "primaryScramblingCode", "ulp.primaryScramblingCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_511", HFILL }},
    { &hf_ulp_measuredResultsList,
      { "measuredResultsList", "ulp.measuredResultsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_cellParametersId,
      { "cellParametersId", "ulp.cellParametersId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ulp_timingAdvance,
      { "timingAdvance", "ulp.timingAdvance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ta_01,
      { "ta", "ulp.ta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_ulp_tAResolution,
      { "tAResolution", "ulp.tAResolution",
        FT_UINT32, BASE_DEC, VALS(ulp_TAResolution_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_chipRate,
      { "chipRate", "ulp.chipRate",
        FT_UINT32, BASE_DEC, VALS(ulp_ChipRate_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_modeSpecificFrequencyInfo,
      { "modeSpecificInfo", "ulp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ulp_FrequencySpecificInfo_vals), 0,
        "FrequencySpecificInfo", HFILL }},
    { &hf_ulp_fdd_fr,
      { "fdd", "ulp.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FrequencyInfoFDD", HFILL }},
    { &hf_ulp_tdd_fr,
      { "tdd", "ulp.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FrequencyInfoTDD", HFILL }},
    { &hf_ulp_uarfcn_UL,
      { "uarfcn-UL", "ulp.uarfcn_UL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UARFCN", HFILL }},
    { &hf_ulp_uarfcn_DL,
      { "uarfcn-DL", "ulp.uarfcn_DL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UARFCN", HFILL }},
    { &hf_ulp_uarfcn_Nt,
      { "uarfcn-Nt", "ulp.uarfcn_Nt",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UARFCN", HFILL }},
    { &hf_ulp_NMR_item,
      { "NMRelement", "ulp.NMRelement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_arfcn,
      { "arfcn", "ulp.arfcn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ulp_bsic,
      { "bsic", "ulp.bsic",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_ulp_rxLev,
      { "rxLev", "ulp.rxLev",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_NMRelement_rxLev_fmt), 0,
        "INTEGER_0_63", HFILL }},
    { &hf_ulp_MeasuredResultsList_item,
      { "MeasuredResults", "ulp.MeasuredResults_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_utra_CarrierRSSI,
      { "utra-CarrierRSSI", "ulp.utra_CarrierRSSI",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_UTRA_CarrierRSSI_fmt), 0,
        NULL, HFILL }},
    { &hf_ulp_cellMeasuredResultsList,
      { "cellMeasuredResultsList", "ulp.cellMeasuredResultsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_CellMeasuredResultsList_item,
      { "CellMeasuredResults", "ulp.CellMeasuredResults_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_cellIdentity,
      { "cellIdentity", "ulp.cellIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_268435455", HFILL }},
    { &hf_ulp_modeSpecificInfo,
      { "modeSpecificInfo", "ulp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ulp_T_modeSpecificInfo_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_fdd,
      { "fdd", "ulp.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_primaryCPICH_Info,
      { "primaryCPICH-Info", "ulp.primaryCPICH_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_cpich_Ec_N0,
      { "cpich-Ec-N0", "ulp.cpich_Ec_N0",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_CPICH_Ec_N0_fmt), 0,
        NULL, HFILL }},
    { &hf_ulp_cpich_RSCP,
      { "cpich-RSCP", "ulp.cpich_RSCP",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_CPICH_RSCP_fmt), 0,
        NULL, HFILL }},
    { &hf_ulp_pathloss,
      { "pathloss", "ulp.pathloss",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_tdd,
      { "tdd", "ulp.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_cellParametersID,
      { "cellParametersID", "ulp.cellParametersID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_proposedTGSN,
      { "proposedTGSN", "ulp.proposedTGSN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TGSN", HFILL }},
    { &hf_ulp_primaryCCPCH_RSCP,
      { "primaryCCPCH-RSCP", "ulp.primaryCCPCH_RSCP",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_PrimaryCCPCH_RSCP_fmt), 0,
        NULL, HFILL }},
    { &hf_ulp_timeslotISCP_List,
      { "timeslotISCP-List", "ulp.timeslotISCP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_TimeslotISCP_List_item,
      { "TimeslotISCP", "ulp.TimeslotISCP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_horacc,
      { "horacc", "ulp.horacc",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_QoP_horacc_fmt), 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ulp_veracc,
      { "veracc", "ulp.veracc",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_QoP_veracc_fmt), 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ulp_maxLocAge,
      { "maxLocAge", "ulp.maxLocAge",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ulp_delay,
      { "delay", "ulp.delay",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_QoP_delay_fmt), 0,
        "INTEGER_0_7", HFILL }},
    { &hf_ulp_ver2_responseTime,
      { "ver2-responseTime", "ulp.ver2_responseTime",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "INTEGER_1_128", HFILL }},
    { &hf_ulp_horvel,
      { "horvel", "ulp.horvel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_horandvervel,
      { "horandvervel", "ulp.horandvervel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_horveluncert,
      { "horveluncert", "ulp.horveluncert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_horandveruncert,
      { "horandveruncert", "ulp.horandveruncert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_bearing,
      { "bearing", "ulp.bearing",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_degree_degrees, 0,
        NULL, HFILL }},
    { &hf_ulp_horspeed,
      { "horspeed", "ulp.horspeed",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_kmh, 0,
        NULL, HFILL }},
    { &hf_ulp_verdirect,
      { "verdirect", "ulp.verdirect",
        FT_BOOLEAN, BASE_NONE, TFS(&ulp_vertical_dir_val), 0,
        NULL, HFILL }},
    { &hf_ulp_bearing_01,
      { "bearing", "ulp.bearing",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_degree_degrees, 0,
        "T_bearing_01", HFILL }},
    { &hf_ulp_horspeed_01,
      { "horspeed", "ulp.horspeed",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_kmh, 0,
        "T_horspeed_01", HFILL }},
    { &hf_ulp_verspeed,
      { "verspeed", "ulp.verspeed",
        FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_kmh, 0,
        NULL, HFILL }},
    { &hf_ulp_bearing_02,
      { "bearing", "ulp.bearing",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_degree_degrees, 0,
        "T_bearing_02", HFILL }},
    { &hf_ulp_horspeed_02,
      { "horspeed", "ulp.horspeed",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_kmh, 0,
        "T_horspeed_02", HFILL }},
    { &hf_ulp_uncertspeed,
      { "uncertspeed", "ulp.uncertspeed",
        FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_kmh, 0,
        NULL, HFILL }},
    { &hf_ulp_verdirect_01,
      { "verdirect", "ulp.verdirect",
        FT_BOOLEAN, BASE_NONE, TFS(&ulp_vertical_dir_val), 0,
        "T_verdirect_01", HFILL }},
    { &hf_ulp_bearing_03,
      { "bearing", "ulp.bearing",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_degree_degrees, 0,
        "T_bearing_03", HFILL }},
    { &hf_ulp_horspeed_03,
      { "horspeed", "ulp.horspeed",
        FT_UINT16, BASE_DEC|BASE_UNIT_STRING, &units_kmh, 0,
        "T_horspeed_03", HFILL }},
    { &hf_ulp_verspeed_01,
      { "verspeed", "ulp.verspeed",
        FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_kmh, 0,
        "T_verspeed_01", HFILL }},
    { &hf_ulp_horuncertspeed,
      { "horuncertspeed", "ulp.horuncertspeed",
        FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_kmh, 0,
        NULL, HFILL }},
    { &hf_ulp_veruncertspeed,
      { "veruncertspeed", "ulp.veruncertspeed",
        FT_UINT8, BASE_DEC|BASE_UNIT_STRING, &units_kmh, 0,
        NULL, HFILL }},
    { &hf_ulp_MultipleLocationIds_item,
      { "LocationIdData", "ulp.LocationIdData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_relativetimestamp,
      { "relativetimestamp", "ulp.relativetimestamp",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_RelativeTime_fmt), 0,
        "RelativeTime", HFILL }},
    { &hf_ulp_servingFlag,
      { "servingFlag", "ulp.servingFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_supportedWLANInfo,
      { "supportedWLANInfo", "ulp.supportedWLANInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_supportedWLANApsList,
      { "supportedWLANApsList", "ulp.supportedWLANApsList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_supportedWCDMAInfo,
      { "supportedWCDMAInfo", "ulp.supportedWCDMAInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_hrdp,
      { "hrdp", "ulp.hrdp",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_wimax,
      { "wimax", "ulp.wimax",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_historic,
      { "historic", "ulp.historic",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_nonServing,
      { "nonServing", "ulp.nonServing",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_uTRANGPSReferenceTime,
      { "uTRANGPSReferenceTime", "ulp.uTRANGPSReferenceTime",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_uTRANGANSSReferenceTime,
      { "uTRANGANSSReferenceTime", "ulp.uTRANGANSSReferenceTime",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_apTP,
      { "apTP", "ulp.apTP",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_apAG,
      { "apAG", "ulp.apAG",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_apSN,
      { "apSN", "ulp.apSN",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_apDevType,
      { "apDevType", "ulp.apDevType",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_apRSSI,
      { "apRSSI", "ulp.apRSSI",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_apChanFreq,
      { "apChanFreq", "ulp.apChanFreq",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_apRTD,
      { "apRTD", "ulp.apRTD",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_setTP,
      { "setTP", "ulp.setTP",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_setAG,
      { "setAG", "ulp.setAG",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_setSN,
      { "setSN", "ulp.setSN",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_setRSSI,
      { "setRSSI", "ulp.setRSSI",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_apRepLoc,
      { "apRepLoc", "ulp.apRepLoc",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_apRL,
      { "apRL", "ulp.apRL",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_opClass,
      { "opClass", "ulp.opClass",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_apSSID,
      { "apSSID", "ulp.apSSID",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_apPHYType,
      { "apPHYType", "ulp.apPHYType",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_setMACAddress,
      { "setMACAddress", "ulp.setMACAddress",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_supportedWLANApDataList,
      { "supportedWLANApDataList", "ulp.supportedWLANApDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_maxWLANApDataSize_OF_SupportedWLANApData", HFILL }},
    { &hf_ulp_supportedWLANApDataList_item,
      { "SupportedWLANApData", "ulp.SupportedWLANApData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_supportedWLANapsChannel11a,
      { "supportedWLANapsChannel11a", "ulp.supportedWLANapsChannel11a_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_supportedWLANapsChannel11bg,
      { "supportedWLANapsChannel11bg", "ulp.supportedWLANapsChannel11bg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ch34,
      { "ch34", "ulp.ch34",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch36,
      { "ch36", "ulp.ch36",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch38,
      { "ch38", "ulp.ch38",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch40,
      { "ch40", "ulp.ch40",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch42,
      { "ch42", "ulp.ch42",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch44,
      { "ch44", "ulp.ch44",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch46,
      { "ch46", "ulp.ch46",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch48,
      { "ch48", "ulp.ch48",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch52,
      { "ch52", "ulp.ch52",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch56,
      { "ch56", "ulp.ch56",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch60,
      { "ch60", "ulp.ch60",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch64,
      { "ch64", "ulp.ch64",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch149,
      { "ch149", "ulp.ch149",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch153,
      { "ch153", "ulp.ch153",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch157,
      { "ch157", "ulp.ch157",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch161,
      { "ch161", "ulp.ch161",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch1,
      { "ch1", "ulp.ch1",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch2,
      { "ch2", "ulp.ch2",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch3,
      { "ch3", "ulp.ch3",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch4,
      { "ch4", "ulp.ch4",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch5,
      { "ch5", "ulp.ch5",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch6,
      { "ch6", "ulp.ch6",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch7,
      { "ch7", "ulp.ch7",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch8,
      { "ch8", "ulp.ch8",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch9,
      { "ch9", "ulp.ch9",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch10,
      { "ch10", "ulp.ch10",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch11,
      { "ch11", "ulp.ch11",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch12,
      { "ch12", "ulp.ch12",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch13,
      { "ch13", "ulp.ch13",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_ch14,
      { "ch14", "ulp.ch14",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_apMACAddress_01,
      { "apMACAddress", "ulp.apMACAddress",
        FT_ETHER, BASE_NONE, NULL, 0,
        "T_apMACAddress_01", HFILL }},
    { &hf_ulp_apDevType_01,
      { "apDevType", "ulp.apDevType",
        FT_UINT32, BASE_DEC, VALS(ulp_T_apDevType_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_mrl,
      { "mrl", "ulp.mrl",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_hrpdCell,
      { "hrpdCell", "ulp.hrpdCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HrpdCellInformation", HFILL }},
    { &hf_ulp_umbCell,
      { "umbCell", "ulp.umbCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UmbCellInformation", HFILL }},
    { &hf_ulp_lteCell,
      { "lteCell", "ulp.lteCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LteCellInformation", HFILL }},
    { &hf_ulp_wlanAP,
      { "wlanAP", "ulp.wlanAP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WlanAPInformation", HFILL }},
    { &hf_ulp_wimaxBS,
      { "wimaxBS", "ulp.wimaxBS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WimaxBSInformation", HFILL }},
    { &hf_ulp_nrCell,
      { "nrCell", "ulp.nrCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRCellInformation", HFILL }},
    { &hf_ulp_cellGlobalIdEUTRA,
      { "cellGlobalIdEUTRA", "ulp.cellGlobalIdEUTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_physCellId,
      { "physCellId", "ulp.physCellId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_trackingAreaCode,
      { "trackingAreaCode", "ulp.trackingAreaCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_rsrpResult,
      { "rsrpResult", "ulp.rsrpResult",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_RSRP_Range_fmt), 0,
        "RSRP_Range", HFILL }},
    { &hf_ulp_rsrqResult,
      { "rsrqResult", "ulp.rsrqResult",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_RSRQ_Range_fmt), 0,
        "RSRQ_Range", HFILL }},
    { &hf_ulp_ta_02,
      { "ta", "ulp.ta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1282", HFILL }},
    { &hf_ulp_measResultListEUTRA,
      { "measResultListEUTRA", "ulp.measResultListEUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_earfcn,
      { "earfcn", "ulp.earfcn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ulp_earfcn_ext,
      { "earfcn-ext", "ulp.earfcn_ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_65536_262143", HFILL }},
    { &hf_ulp_rsrpResult_ext,
      { "rsrpResult-ext", "ulp.rsrpResult_ext",
        FT_INT32, BASE_DEC, NULL, 0,
        "RSRP_Range_Ext", HFILL }},
    { &hf_ulp_rsrqResult_ext,
      { "rsrqResult-ext", "ulp.rsrqResult_ext",
        FT_INT32, BASE_DEC, NULL, 0,
        "RSRQ_Range_Ext", HFILL }},
    { &hf_ulp_rs_sinrResult,
      { "rs-sinrResult", "ulp.rs_sinrResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RS_SINR_Range", HFILL }},
    { &hf_ulp_servingInformation5G,
      { "servingInformation5G", "ulp.servingInformation5G_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_MeasResultListEUTRA_item,
      { "MeasResultEUTRA", "ulp.MeasResultEUTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_cgi_Info,
      { "cgi-Info", "ulp.cgi_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_cellGlobalId,
      { "cellGlobalId", "ulp.cellGlobalId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellGlobalIdEUTRA", HFILL }},
    { &hf_ulp_measResult,
      { "measResult", "ulp.measResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_neighbourInformation5G,
      { "neighbourInformation5G", "ulp.neighbourInformation5G_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_plmn_Identity,
      { "plmn-Identity", "ulp.plmn_Identity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_cellIdentity_01,
      { "cellIdentity", "ulp.cellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_mcc,
      { "mcc", "ulp.mcc",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_mnc,
      { "mnc", "ulp.mnc",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_MCC_item,
      { "MCC-MNC-Digit", "ulp.MCC_MNC_Digit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_MNC_item,
      { "MCC-MNC-Digit", "ulp.MCC_MNC_Digit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_trackingAreaCode_01,
      { "trackingAreaCode", "ulp.trackingAreaCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TrackingAreaCodeNR", HFILL }},
    { &hf_ulp_apMACAddress_02,
      { "apMACAddress", "ulp.apMACAddress",
        FT_ETHER, BASE_NONE, NULL, 0,
        "T_apMACAddress_02", HFILL }},
    { &hf_ulp_apTransmitPower,
      { "apTransmitPower", "ulp.apTransmitPower",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ulp_apAntennaGain,
      { "apAntennaGain", "ulp.apAntennaGain",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbi, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ulp_apSignaltoNoise,
      { "apSignaltoNoise", "ulp.apSignaltoNoise",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ulp_apDeviceType,
      { "apDeviceType", "ulp.apDeviceType",
        FT_UINT32, BASE_DEC, VALS(ulp_T_apDeviceType_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_apSignalStrength,
      { "apSignalStrength", "ulp.apSignalStrength",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ulp_apChannelFrequency,
      { "apChannelFrequency", "ulp.apChannelFrequency",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_256", HFILL }},
    { &hf_ulp_apRoundTripDelay,
      { "apRoundTripDelay", "ulp.apRoundTripDelay_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTD", HFILL }},
    { &hf_ulp_setTransmitPower,
      { "setTransmitPower", "ulp.setTransmitPower",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ulp_setAntennaGain,
      { "setAntennaGain", "ulp.setAntennaGain",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbi, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ulp_setSignaltoNoise,
      { "setSignaltoNoise", "ulp.setSignaltoNoise",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ulp_setSignalStrength,
      { "setSignalStrength", "ulp.setSignalStrength",
        FT_INT32, BASE_DEC|BASE_UNIT_STRING, &units_dbm, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ulp_apReportedLocation,
      { "apReportedLocation", "ulp.apReportedLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportedLocation", HFILL }},
    { &hf_ulp_apRepLocation,
      { "apRepLocation", "ulp.apRepLocation",
        FT_UINT32, BASE_DEC, VALS(ulp_RepLocation_vals), 0,
        "RepLocation", HFILL }},
    { &hf_ulp_apSignalStrengthDelta,
      { "apSignalStrengthDelta", "ulp.apSignalStrengthDelta",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_SignalDelta_fmt), 0,
        "INTEGER_0_1", HFILL }},
    { &hf_ulp_apSignaltoNoiseDelta,
      { "apSignaltoNoiseDelta", "ulp.apSignaltoNoiseDelta",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_SignalDelta_fmt), 0,
        "INTEGER_0_1", HFILL }},
    { &hf_ulp_setSignalStrengthDelta,
      { "setSignalStrengthDelta", "ulp.setSignalStrengthDelta",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_SignalDelta_fmt), 0,
        "INTEGER_0_1", HFILL }},
    { &hf_ulp_setSignaltoNoiseDelta,
      { "setSignaltoNoiseDelta", "ulp.setSignaltoNoiseDelta",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_SignalDelta_fmt), 0,
        "INTEGER_0_1", HFILL }},
    { &hf_ulp_operatingClass,
      { "operatingClass", "ulp.operatingClass",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_apSSID_01,
      { "apSSID", "ulp.apSSID",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_apPHYType_01,
      { "apPHYType", "ulp.apPHYType",
        FT_UINT32, BASE_DEC, VALS(ulp_T_apPHYType_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_setMACAddress_01,
      { "setMACAddress", "ulp.setMACAddress",
        FT_ETHER, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_rTDValue,
      { "rTDValue", "ulp.rTDValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777216", HFILL }},
    { &hf_ulp_rTDUnits,
      { "rTDUnits", "ulp.rTDUnits",
        FT_UINT32, BASE_DEC, VALS(ulp_RTDUnits_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_rTDAccuracy,
      { "rTDAccuracy", "ulp.rTDAccuracy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_locationEncodingDescriptor,
      { "locationEncodingDescriptor", "ulp.locationEncodingDescriptor",
        FT_UINT32, BASE_DEC, VALS(ulp_LocationEncodingDescriptor_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_locationData,
      { "locationData", "ulp.locationData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_locationAccuracy,
      { "locationAccuracy", "ulp.locationAccuracy",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_locationAccuracy_fmt), 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_ulp_locationValue,
      { "locationValue", "ulp.locationValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_128", HFILL }},
    { &hf_ulp_lciLocData,
      { "lciLocData", "ulp.lciLocData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_locationDataLCI,
      { "locationDataLCI", "ulp.locationDataLCI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_latitudeResolution,
      { "latitudeResolution", "ulp.latitudeResolution",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_ulp_latitude_01,
      { "latitude", "ulp.latitude",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_34", HFILL }},
    { &hf_ulp_longitudeResolution,
      { "longitudeResolution", "ulp.longitudeResolution",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_ulp_longitude_01,
      { "longitude", "ulp.longitude",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_34", HFILL }},
    { &hf_ulp_altitudeType,
      { "altitudeType", "ulp.altitudeType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_ulp_altitudeResolution,
      { "altitudeResolution", "ulp.altitudeResolution",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_ulp_altitude_01,
      { "altitude", "ulp.altitude",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_30", HFILL }},
    { &hf_ulp_datum,
      { "datum", "ulp.datum",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_ulp_wimaxBsID,
      { "wimaxBsID", "ulp.wimaxBsID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_wimaxRTD,
      { "wimaxRTD", "ulp.wimaxRTD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_wimaxNMRList,
      { "wimaxNMRList", "ulp.wimaxNMRList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_rtd,
      { "rtd", "ulp.rtd",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_WimaxRTD_fmt), 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ulp_rTDstd,
      { "rTDstd", "ulp.rTDstd",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_WimaxRTD_fmt), 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ulp_WimaxNMRList_item,
      { "WimaxNMR", "ulp.WimaxNMR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_relDelay,
      { "relDelay", "ulp.relDelay",
        FT_INT32, BASE_CUSTOM, CF_FUNC(ulp_WimaxRTD_fmt), 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_ulp_relDelaystd,
      { "relDelaystd", "ulp.relDelaystd",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_WimaxRTD_fmt), 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ulp_rssi,
      { "rssi", "ulp.rssi",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_WimaxNMR_rssi_fmt), 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_rSSIstd,
      { "rSSIstd", "ulp.rSSIstd",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_ulp_bSTxPower,
      { "bSTxPower", "ulp.bSTxPower",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_WimaxNMR_rssi_fmt), 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_cinr,
      { "cinr", "ulp.cinr",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_cINRstd,
      { "cINRstd", "ulp.cINRstd",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_decibels, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_ulp_bSLocation,
      { "bSLocation", "ulp.bSLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportedLocation", HFILL }},
    { &hf_ulp_servingCellInformation,
      { "servingCellInformation", "ulp.servingCellInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServingCellInformationNR", HFILL }},
    { &hf_ulp_measuredResultsListNR,
      { "measuredResultsListNR", "ulp.measuredResultsListNR",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasResultListNR", HFILL }},
    { &hf_ulp_ServingCellInformationNR_item,
      { "ServCellNR", "ulp.ServCellNR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_physCellId_01,
      { "physCellId", "ulp.physCellId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PhysCellIdNR", HFILL }},
    { &hf_ulp_arfcn_NR,
      { "arfcn-NR", "ulp.arfcn_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_cellGlobalId_01,
      { "cellGlobalId", "ulp.cellGlobalId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellGlobalIdNR", HFILL }},
    { &hf_ulp_ssb_Measurements,
      { "ssb-Measurements", "ulp.ssb_Measurements_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_Measurements", HFILL }},
    { &hf_ulp_csi_rs_Measurements,
      { "csi-rs-Measurements", "ulp.csi_rs_Measurements_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_Measurements", HFILL }},
    { &hf_ulp_ta_03,
      { "ta", "ulp.ta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3846", HFILL }},
    { &hf_ulp_MeasResultListNR_item,
      { "MeasResultNR", "ulp.MeasResultNR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_cellIdentityNR,
      { "cellIdentityNR", "ulp.cellIdentityNR",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_rsrp_Range,
      { "rsrp-Range", "ulp.rsrp_Range",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ulp_rsrq_Range,
      { "rsrq-Range", "ulp.rsrq_Range",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ulp_sinr_Range,
      { "sinr-Range", "ulp.sinr_Range",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ulp_utran_GPSReferenceTime,
      { "utran-GPSReferenceTime", "ulp.utran_GPSReferenceTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_gpsReferenceTimeUncertainty,
      { "gpsReferenceTimeUncertainty", "ulp.gpsReferenceTimeUncertainty",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_UTRAN_gpsReferenceTimeUncertainty_fmt), 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ulp_utranGPSDriftRate,
      { "utranGPSDriftRate", "ulp.utranGPSDriftRate",
        FT_UINT32, BASE_DEC, VALS(ulp_UTRANGPSDriftRate_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_utran_GPSTimingOfCell,
      { "utran-GPSTimingOfCell", "ulp.utran_GPSTimingOfCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ms_part,
      { "ms-part", "ulp.ms_part",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ulp_ls_part,
      { "ls-part", "ulp.ls_part",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_ulp_modeSpecificInfo_01,
      { "modeSpecificInfo", "ulp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ulp_T_modeSpecificInfo_01_vals), 0,
        "T_modeSpecificInfo_01", HFILL }},
    { &hf_ulp_fdd_01,
      { "fdd", "ulp.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_fdd_01", HFILL }},
    { &hf_ulp_referenceIdentity,
      { "referenceIdentity", "ulp.referenceIdentity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrimaryCPICH_Info", HFILL }},
    { &hf_ulp_tdd_01,
      { "tdd", "ulp.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tdd_01", HFILL }},
    { &hf_ulp_referenceIdentity_01,
      { "referenceIdentity", "ulp.referenceIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellParametersID", HFILL }},
    { &hf_ulp_sfn,
      { "sfn", "ulp.sfn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_ulp_set_GPSTimingOfCell,
      { "set-GPSTimingOfCell", "ulp.set_GPSTimingOfCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_set_GPSTimingOfCell", HFILL }},
    { &hf_ulp_ms_part_01,
      { "ms-part", "ulp.ms_part",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_ulp_modeSpecificInfo_02,
      { "modeSpecificInfo", "ulp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ulp_T_modeSpecificInfo_02_vals), 0,
        "T_modeSpecificInfo_02", HFILL }},
    { &hf_ulp_fdd_02,
      { "fdd", "ulp.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_fdd_02", HFILL }},
    { &hf_ulp_tdd_02,
      { "tdd", "ulp.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tdd_02", HFILL }},
    { &hf_ulp_ganssDay,
      { "ganssDay", "ulp.ganssDay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_ulp_ganssTimeID,
      { "ganssTimeID", "ulp.ganssTimeID",
        FT_UINT32, BASE_DEC, VALS(ulp_ganss_time_id_vals), 0,
        "INTEGER_0_15", HFILL }},
    { &hf_ulp_utran_GANSSReferenceTime,
      { "utran-GANSSReferenceTime", "ulp.utran_GANSSReferenceTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_utranGANSSDriftRate,
      { "utranGANSSDriftRate", "ulp.utranGANSSDriftRate",
        FT_UINT32, BASE_DEC, VALS(ulp_UTRANGANSSDriftRate_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_ganssTOD,
      { "ganssTOD", "ulp.ganssTOD",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "INTEGER_0_86399", HFILL }},
    { &hf_ulp_utran_GANSSTimingOfCell,
      { "utran-GANSSTimingOfCell", "ulp.utran_GANSSTimingOfCell",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_utran_GANSSTimingOfCell_fmt), 0,
        "INTEGER_0_3999999", HFILL }},
    { &hf_ulp_modeSpecificInfo_03,
      { "modeSpecificInfo", "ulp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ulp_T_modeSpecificInfo_03_vals), 0,
        "T_modeSpecificInfo_03", HFILL }},
    { &hf_ulp_fdd_03,
      { "fdd", "ulp.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_fdd_03", HFILL }},
    { &hf_ulp_tdd_03,
      { "tdd", "ulp.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tdd_03", HFILL }},
    { &hf_ulp_ganss_TODUncertainty,
      { "ganss-TODUncertainty", "ulp.ganss_TODUncertainty",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_UTRAN_gpsReferenceTimeUncertainty_fmt), 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ulp_set_GANSSReferenceTime,
      { "set-GANSSReferenceTime", "ulp.set_GANSSReferenceTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_set_GANSSTimingOfCell,
      { "set-GANSSTimingOfCell", "ulp.set_GANSSTimingOfCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_set_GANSSTimingOfCell", HFILL }},
    { &hf_ulp_ms_part_02,
      { "ms-part", "ulp.ms_part",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_80", HFILL }},
    { &hf_ulp_modeSpecificInfo_04,
      { "modeSpecificInfo", "ulp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ulp_T_modeSpecificInfo_04_vals), 0,
        "T_modeSpecificInfo_04", HFILL }},
    { &hf_ulp_fdd_04,
      { "fdd", "ulp.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_fdd_04", HFILL }},
    { &hf_ulp_tdd_04,
      { "tdd", "ulp.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tdd_04", HFILL }},
    { &hf_ulp_gps,
      { "gps", "ulp.gps",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_galileo,
      { "galileo", "ulp.galileo",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_sbas,
      { "sbas", "ulp.sbas",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_modernized_gps,
      { "modernized-gps", "ulp.modernized_gps",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_qzss,
      { "qzss", "ulp.qzss",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_glonass,
      { "glonass", "ulp.glonass",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_bds,
      { "bds", "ulp.bds",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_rtk_osr,
      { "rtk-osr", "ulp.rtk_osr",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_rand,
      { "rand", "ulp.rand",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_128", HFILL }},
    { &hf_ulp_slpFQDN,
      { "slpFQDN", "ulp.slpFQDN",
        FT_STRING, BASE_NONE, NULL, 0,
        "FQDN", HFILL }},
    { &hf_ulp_ThirdParty_item,
      { "ThirdPartyID", "ulp.ThirdPartyID",
        FT_UINT32, BASE_DEC, VALS(ulp_ThirdPartyID_vals), 0,
        NULL, HFILL }},
    { &hf_ulp_logicalName,
      { "logicalName", "ulp.logicalName",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_1000", HFILL }},
    { &hf_ulp_msisdn_01,
      { "msisdn", "ulp.msisdn",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_msisdn_01", HFILL }},
    { &hf_ulp_emailaddr,
      { "emailaddr", "ulp.emailaddr",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_1000", HFILL }},
    { &hf_ulp_sip_uri,
      { "sip-uri", "ulp.sip_uri",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ims_public_identity,
      { "ims-public-identity", "ulp.ims_public_identity",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_min_01,
      { "min", "ulp.min",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_34", HFILL }},
    { &hf_ulp_mdn_01,
      { "mdn", "ulp.mdn",
        FT_BYTES, BASE_NONE, NULL, 0,
        "T_mdn_01", HFILL }},
    { &hf_ulp_uri,
      { "uri", "ulp.uri",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_appProvider,
      { "appProvider", "ulp.appProvider",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_24", HFILL }},
    { &hf_ulp_appName,
      { "appName", "ulp.appName",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_32", HFILL }},
    { &hf_ulp_appVersion,
      { "appVersion", "ulp.appVersion",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_8", HFILL }},
    { &hf_ulp_minInt,
      { "minInt", "ulp.minInt",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_seconds, 0,
        "INTEGER_1_3600", HFILL }},
    { &hf_ulp_maxInt,
      { "maxInt", "ulp.maxInt",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_minutes, 0,
        "INTEGER_1_1440", HFILL }},
    { &hf_ulp_repMode_01,
      { "repMode", "ulp.repMode_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_batchRepCap,
      { "batchRepCap", "ulp.batchRepCap_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_realtime,
      { "realtime", "ulp.realtime",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_quasirealtime,
      { "quasirealtime", "ulp.quasirealtime",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_batch,
      { "batch", "ulp.batch",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_report_position,
      { "report-position", "ulp.report_position",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_report_measurements,
      { "report-measurements", "ulp.report_measurements",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ulp_max_num_positions,
      { "max-num-positions", "ulp.max_num_positions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1024", HFILL }},
    { &hf_ulp_max_num_measurements,
      { "max-num-measurements", "ulp.max_num_measurements",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1024", HFILL }},
    { &hf_ulp_latitudeSign_01,
      { "latitudeSign", "ulp.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(ulp_T_latitudeSign_01_vals), 0,
        "T_latitudeSign_01", HFILL }},
    { &hf_ulp_coordinateLatitude,
      { "latitude", "ulp.latitude",
        FT_UINT32, BASE_CUSTOM, CF_FUNC(ulp_Coordinate_latitude_fmt), 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_ulp_coordinateLongitude,
      { "longitude", "ulp.longitude",
        FT_INT32, BASE_CUSTOM, CF_FUNC(ulp_Coordinate_longitude_fmt), 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_ulp_coordinate,
      { "coordinate", "ulp.coordinate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_radius,
      { "radius", "ulp.radius",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_meters, 0,
        "INTEGER_1_1000000", HFILL }},
    { &hf_ulp_radius_min,
      { "radius-min", "ulp.radius_min",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1000000", HFILL }},
    { &hf_ulp_radius_max,
      { "radius-max", "ulp.radius_max",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1500000", HFILL }},
    { &hf_ulp_semiMajor,
      { "semiMajor", "ulp.semiMajor",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_meters, 0,
        "INTEGER_1_1000000", HFILL }},
    { &hf_ulp_semiMajor_min,
      { "semiMajor-min", "ulp.semiMajor_min",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1000000", HFILL }},
    { &hf_ulp_semiMajor_max,
      { "semiMajor-max", "ulp.semiMajor_max",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1500000", HFILL }},
    { &hf_ulp_semiMinor,
      { "semiMinor", "ulp.semiMinor",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_meters, 0,
        "INTEGER_1_1000000", HFILL }},
    { &hf_ulp_semiMinor_min,
      { "semiMinor-min", "ulp.semiMinor_min",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1000000", HFILL }},
    { &hf_ulp_semiMinor_max,
      { "semiMinor-max", "ulp.semiMinor_max",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1500000", HFILL }},
    { &hf_ulp_angle,
      { "angle", "ulp.angle",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_degree_degrees, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_ulp_polygonDescription,
      { "polygonDescription", "ulp.polygonDescription",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_polygonHysteresis,
      { "polygonHysteresis", "ulp.polygonHysteresis",
        FT_UINT32, BASE_DEC|BASE_UNIT_STRING, &units_meters, 0,
        "INTEGER_1_100000", HFILL }},
    { &hf_ulp_PolygonDescription_item,
      { "Coordinate", "ulp.Coordinate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_highAccuracyPositionEstimate,
      { "highAccuracyPositionEstimate", "ulp.highAccuracyPositionEstimate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_degreesLatitude,
      { "degreesLatitude", "ulp.degreesLatitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_ulp_degreesLongitude,
      { "degreesLongitude", "ulp.degreesLongitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_ulp_uncertaintySemiMajor_01,
      { "uncertaintySemiMajor", "ulp.uncertaintySemiMajor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_uncertaintySemiMinor_01,
      { "uncertaintySemiMinor", "ulp.uncertaintySemiMinor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_orientationMajorAxis_01,
      { "orientationMajorAxis", "ulp.orientationMajorAxis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_179", HFILL }},
    { &hf_ulp_horizontalConfidence,
      { "horizontalConfidence", "ulp.horizontalConfidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_ulp_highAccuracyAltitudeInfo,
      { "highAccuracyAltitudeInfo", "ulp.highAccuracyAltitudeInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_altitude_02,
      { "altitude", "ulp.altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_64000_1280000", HFILL }},
    { &hf_ulp_uncertaintyAltitude,
      { "uncertaintyAltitude", "ulp.uncertaintyAltitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ulp_verticalConfidence,
      { "verticalConfidence", "ulp.verticalConfidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_ulp_T_addPosMode_standalone,
      { "standalone", "ulp.T.addPosMode.standalone",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ulp_T_addPosMode_setBased,
      { "setBased", "ulp.T.addPosMode.setBased",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ulp_T_addPosMode_setAssisted,
      { "setAssisted", "ulp.T.addPosMode.setAssisted",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ulp_GANSSSignals_signal1,
      { "signal1", "ulp.GANSSSignals.signal1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ulp_GANSSSignals_signal2,
      { "signal2", "ulp.GANSSSignals.signal2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ulp_GANSSSignals_signal3,
      { "signal3", "ulp.GANSSSignals.signal3",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ulp_GANSSSignals_signal4,
      { "signal4", "ulp.GANSSSignals.signal4",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ulp_GANSSSignals_signal5,
      { "signal5", "ulp.GANSSSignals.signal5",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ulp_GANSSSignals_signal6,
      { "signal6", "ulp.GANSSSignals.signal6",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ulp_GANSSSignals_signal7,
      { "signal7", "ulp.GANSSSignals.signal7",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ulp_GANSSSignals_signal8,
      { "signal8", "ulp.GANSSSignals.signal8",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ulp_mobile_directory_number,
      { "Mobile Directory Number", "ulp.mobile_directory_number",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ulp_ganssTimeModels_bit0,
      { "GPS", "ulp.ganssTimeModels.gps",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x8000,
        NULL, HFILL }},
    { &hf_ulp_ganssTimeModels_bit1,
      { "Galileo", "ulp.ganssTimeModels.galileo",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x4000,
        NULL, HFILL }},
    { &hf_ulp_ganssTimeModels_bit2,
      { "QZSS", "ulp.ganssTimeModels.qzss",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x2000,
        NULL, HFILL }},
    { &hf_ulp_ganssTimeModels_bit3,
      { "GLONASS", "ulp.ganssTimeModels.glonass",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x1000,
        NULL, HFILL }},
    { &hf_ulp_ganssTimeModels_bit4,
      { "BDS", "ulp.ganssTimeModels.bds",
        FT_BOOLEAN, 16, TFS(&tfs_yes_no), 0x0800,
        NULL, HFILL }},
    { &hf_ulp_ganssTimeModels_spare,
      { "Spare", "ulp.ganssTimeModels.spare",
        FT_UINT16, BASE_HEX, NULL, 0x07ff,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_ulp,
    &ett_ulp_setid,
    &ett_ulp_thirdPartyId,
    &ett_ulp_ganssTimeModels,
    &ett_ulp_ULP_PDU,
    &ett_ulp_UlpMessage,
    &ett_ulp_SUPLINIT,
    &ett_ulp_Notification,
    &ett_ulp_SUPLSTART,
    &ett_ulp_SETCapabilities,
    &ett_ulp_PosTechnology,
    &ett_ulp_PosProtocol,
    &ett_ulp_SUPLRESPONSE,
    &ett_ulp_SETAuthKey,
    &ett_ulp_SUPLPOSINIT,
    &ett_ulp_RequestedAssistData,
    &ett_ulp_NavigationModel,
    &ett_ulp_SatelliteInfo,
    &ett_ulp_SatelliteInfoElement,
    &ett_ulp_SUPLPOS,
    &ett_ulp_PosPayLoad,
    &ett_ulp_SUPLEND,
    &ett_ulp_SUPLAUTHREQ,
    &ett_ulp_SUPLAUTHRESP,
    &ett_ulp_Ver2_SUPLNOTIFY,
    &ett_ulp_Ver2_SUPLNOTIFYRESPONSE,
    &ett_ulp_Ver2_SUPLSETINIT,
    &ett_ulp_Ver2_SUPLTRIGGEREDSTART,
    &ett_ulp_TriggerParams,
    &ett_ulp_PeriodicParams,
    &ett_ulp_AreaEventParams,
    &ett_ulp_SEQUENCE_SIZE_1_maxAreaIdList_OF_AreaIdList,
    &ett_ulp_RepeatedReportingParams,
    &ett_ulp_GeographicTargetAreaList,
    &ett_ulp_GeographicTargetArea,
    &ett_ulp_AreaIdList,
    &ett_ulp_AreaIdSet,
    &ett_ulp_AreaId,
    &ett_ulp_GSMAreaId,
    &ett_ulp_WCDMAAreaId,
    &ett_ulp_CDMAAreaId,
    &ett_ulp_HRPDAreaId,
    &ett_ulp_UMBAreaId,
    &ett_ulp_LTEAreaId,
    &ett_ulp_WLANAreaId,
    &ett_ulp_WimaxAreaId,
    &ett_ulp_NRAreaId,
    &ett_ulp_GeoAreaMappingList,
    &ett_ulp_Ver2_SUPLTRIGGEREDRESPONSE,
    &ett_ulp_ReportingMode,
    &ett_ulp_BatchRepConditions,
    &ett_ulp_BatchRepType,
    &ett_ulp_Ver2_SUPLREPORT,
    &ett_ulp_SessionList,
    &ett_ulp_SessionInformation,
    &ett_ulp_ReportDataList,
    &ett_ulp_ReportData,
    &ett_ulp_PositionData,
    &ett_ulp_GANSSsignalsInfo,
    &ett_ulp_GANSSSignalsDescription,
    &ett_ulp_TimeStamp,
    &ett_ulp_Ver2_SUPLTRIGGEREDSTOP,
    &ett_ulp_Ver2_SUPL_INIT_extension,
    &ett_ulp_HistoricReporting,
    &ett_ulp_ReportingCriteria,
    &ett_ulp_TimeWindow,
    &ett_ulp_ProtectionLevel,
    &ett_ulp_BasicProtectionParams,
    &ett_ulp_Ver2_SUPL_START_extension,
    &ett_ulp_Ver2_SUPL_RESPONSE_extension,
    &ett_ulp_Ver2_SUPL_POS_INIT_extension,
    &ett_ulp_Ver2_SUPL_POS_extension,
    &ett_ulp_Ver2_SUPL_END_extension,
    &ett_ulp_Ver2_Notification_extension,
    &ett_ulp_Ver2_SETCapabilities_extension,
    &ett_ulp_ServiceCapabilities,
    &ett_ulp_ServicesSupported,
    &ett_ulp_EventTriggerCapabilities,
    &ett_ulp_GeoAreaShapesSupported,
    &ett_ulp_SessionCapabilities,
    &ett_ulp_SupportedBearers,
    &ett_ulp_Ver2_PosProtocol_extension,
    &ett_ulp_PosProtocolVersion3GPP,
    &ett_ulp_PosProtocolVersion3GPP2,
    &ett_ulp_Supported3GPP2PosProtocolVersion,
    &ett_ulp_PosProtocolVersionOMA,
    &ett_ulp_Ver2_PosTechnology_extension,
    &ett_ulp_GANSSPositionMethods,
    &ett_ulp_GANSSPositionMethod,
    &ett_ulp_RTK,
    &ett_ulp_GANSSPositioningMethodTypes,
    &ett_ulp_AdditionalPositioningMethods,
    &ett_ulp_AddPosSupport_Element,
    &ett_ulp_T_addPosMode,
    &ett_ulp_Ver2_RequestedAssistData_extension,
    &ett_ulp_GanssRequestedCommonAssistanceDataList,
    &ett_ulp_GanssRequestedGenericAssistanceDataList,
    &ett_ulp_GanssReqGenericData,
    &ett_ulp_GanssNavigationModelData,
    &ett_ulp_SatellitesListRelatedDataList,
    &ett_ulp_SatellitesListRelatedData,
    &ett_ulp_GanssDataBits,
    &ett_ulp_ReqDataBitAssistanceList,
    &ett_ulp_T_ganssDataBitSatList,
    &ett_ulp_GanssAdditionalDataChoices,
    &ett_ulp_ExtendedEphemeris,
    &ett_ulp_ExtendedEphCheck,
    &ett_ulp_GanssExtendedEphCheck,
    &ett_ulp_GPSTime,
    &ett_ulp_GANSSextEphTime,
    &ett_ulp_Ver2_PosPayLoad_extension,
    &ett_ulp_T_lPPPayload,
    &ett_ulp_T_tia801Payload,
    &ett_ulp_Version,
    &ett_ulp_SessionID,
    &ett_ulp_SetSessionID,
    &ett_ulp_SETId,
    &ett_ulp_SlpSessionID,
    &ett_ulp_IPAddress,
    &ett_ulp_SLPAddress,
    &ett_ulp_LocationId,
    &ett_ulp_CellInfo,
    &ett_ulp_Position,
    &ett_ulp_PositionEstimate,
    &ett_ulp_T_uncertainty,
    &ett_ulp_AltitudeInfo,
    &ett_ulp_CdmaCellInformation,
    &ett_ulp_GsmCellInformation,
    &ett_ulp_WcdmaCellInformation,
    &ett_ulp_TimingAdvance,
    &ett_ulp_FrequencyInfo,
    &ett_ulp_FrequencySpecificInfo,
    &ett_ulp_FrequencyInfoFDD,
    &ett_ulp_FrequencyInfoTDD,
    &ett_ulp_NMR,
    &ett_ulp_NMRelement,
    &ett_ulp_MeasuredResultsList,
    &ett_ulp_MeasuredResults,
    &ett_ulp_CellMeasuredResultsList,
    &ett_ulp_CellMeasuredResults,
    &ett_ulp_T_modeSpecificInfo,
    &ett_ulp_T_fdd,
    &ett_ulp_T_tdd,
    &ett_ulp_TimeslotISCP_List,
    &ett_ulp_PrimaryCPICH_Info,
    &ett_ulp_QoP,
    &ett_ulp_Velocity,
    &ett_ulp_Horvel,
    &ett_ulp_Horandvervel,
    &ett_ulp_Horveluncert,
    &ett_ulp_Horandveruncert,
    &ett_ulp_MultipleLocationIds,
    &ett_ulp_LocationIdData,
    &ett_ulp_SupportedNetworkInformation,
    &ett_ulp_SupportedWLANInfo,
    &ett_ulp_SupportedWLANApsList,
    &ett_ulp_SEQUENCE_SIZE_1_maxWLANApDataSize_OF_SupportedWLANApData,
    &ett_ulp_SupportedWLANApsChannel11a,
    &ett_ulp_SupportedWLANApsChannel11bg,
    &ett_ulp_SupportedWLANApData,
    &ett_ulp_SupportedWCDMAInfo,
    &ett_ulp_Ver2_CellInfo_extension,
    &ett_ulp_HrpdCellInformation,
    &ett_ulp_UmbCellInformation,
    &ett_ulp_LteCellInformation,
    &ett_ulp_MeasResultListEUTRA,
    &ett_ulp_MeasResultEUTRA,
    &ett_ulp_T_cgi_Info,
    &ett_ulp_T_measResult,
    &ett_ulp_CellGlobalIdEUTRA,
    &ett_ulp_PLMN_Identity,
    &ett_ulp_MCC,
    &ett_ulp_MNC,
    &ett_ulp_ServingInformation5G,
    &ett_ulp_NeighbourInformation5G,
    &ett_ulp_WlanAPInformation,
    &ett_ulp_RTD,
    &ett_ulp_ReportedLocation,
    &ett_ulp_LocationData,
    &ett_ulp_RepLocation,
    &ett_ulp_LciLocData,
    &ett_ulp_LocationDataLCI,
    &ett_ulp_WimaxBSInformation,
    &ett_ulp_WimaxBsID,
    &ett_ulp_WimaxRTD,
    &ett_ulp_WimaxNMRList,
    &ett_ulp_WimaxNMR,
    &ett_ulp_NRCellInformation,
    &ett_ulp_ServingCellInformationNR,
    &ett_ulp_ServCellNR,
    &ett_ulp_MeasResultListNR,
    &ett_ulp_MeasResultNR,
    &ett_ulp_CellGlobalIdNR,
    &ett_ulp_NR_Measurements,
    &ett_ulp_UTRAN_GPSReferenceTimeAssistance,
    &ett_ulp_UTRAN_GPSReferenceTime,
    &ett_ulp_T_utran_GPSTimingOfCell,
    &ett_ulp_T_modeSpecificInfo_01,
    &ett_ulp_T_fdd_01,
    &ett_ulp_T_tdd_01,
    &ett_ulp_UTRAN_GPSReferenceTimeResult,
    &ett_ulp_T_set_GPSTimingOfCell,
    &ett_ulp_T_modeSpecificInfo_02,
    &ett_ulp_T_fdd_02,
    &ett_ulp_T_tdd_02,
    &ett_ulp_UTRAN_GANSSReferenceTimeAssistance,
    &ett_ulp_UTRAN_GANSSReferenceTime,
    &ett_ulp_T_modeSpecificInfo_03,
    &ett_ulp_T_fdd_03,
    &ett_ulp_T_tdd_03,
    &ett_ulp_UTRAN_GANSSReferenceTimeResult,
    &ett_ulp_SET_GANSSReferenceTime,
    &ett_ulp_T_set_GANSSTimingOfCell,
    &ett_ulp_T_modeSpecificInfo_04,
    &ett_ulp_T_fdd_04,
    &ett_ulp_T_tdd_04,
    &ett_ulp_GNSSPosTechnology,
    &ett_ulp_GANSSSignals,
    &ett_ulp_SPCTID,
    &ett_ulp_ThirdParty,
    &ett_ulp_ThirdPartyID,
    &ett_ulp_ApplicationID,
    &ett_ulp_ReportingCap,
    &ett_ulp_RepMode,
    &ett_ulp_BatchRepCap,
    &ett_ulp_Coordinate,
    &ett_ulp_CircularArea,
    &ett_ulp_EllipticalArea,
    &ett_ulp_PolygonArea,
    &ett_ulp_PolygonDescription,
    &ett_ulp_Ver2_HighAccuracyPosition,
    &ett_ulp_HighAccuracyPositionEstimate,
    &ett_ulp_HighAccuracyAltitudeInfo,
  };

  module_t *ulp_module;


  /* Register protocol */
  proto_ulp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  ulp_tcp_handle = register_dissector("ulp", dissect_ulp_tcp, proto_ulp);
  ulp_pdu_handle = register_dissector("ulp.pdu", dissect_ULP_PDU_PDU, proto_ulp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ulp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ulp_module = prefs_register_protocol(proto_ulp, NULL);

  prefs_register_bool_preference(ulp_module, "desegment_ulp_messages",
    "Reassemble ULP messages spanning multiple TCP segments",
    "Whether the ULP dissector should reassemble messages spanning multiple TCP segments."
    " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
    &ulp_desegment);
}


/*--- proto_reg_handoff_ulp ---------------------------------------*/
void
proto_reg_handoff_ulp(void)
{
    rrlp_handle = find_dissector_add_dependency("rrlp", proto_ulp);
    lpp_handle = find_dissector_add_dependency("lpp", proto_ulp);

    dissector_add_string("media_type","application/oma-supl-ulp", ulp_pdu_handle);
    dissector_add_string("media_type","application/vnd.omaloc-supl-init", ulp_pdu_handle);
    dissector_add_uint_with_preference("tcp.port", ULP_PORT, ulp_tcp_handle);
    dissector_add_uint_with_preference("udp.port", ULP_PORT, ulp_pdu_handle);
}

