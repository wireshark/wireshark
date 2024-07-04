/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ilp.c                                                               */
/* asn2wrs.py -q -L -p ilp -c ./ilp.cnf -s ./packet-ilp-template -D . -O ../.. ILP.asn ILP-Components.asn */

/* packet-ilp.c
 * Routines for OMA Internal Location Protocol packet dissection
 * Copyright 2006, e.yimjia <jy.m12.0@gmail.com>
 * Copyright 2019, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * ref OMA-TS-ILP-V2_0_4-20181213-A
 * http://www.openmobilealliance.org
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-tcp.h"
#include "packet-gsm_map.h"
#include "packet-e164.h"
#include "packet-e212.h"

#define PNAME  "OMA Internal Location Protocol"
#define PSNAME "ILP"
#define PFNAME "ilp"

void proto_register_ilp(void);

static dissector_handle_t rrlp_handle;
static dissector_handle_t lpp_handle;
static dissector_handle_t ilp_tcp_handle;


/* IANA Registered Ports
 * oma-ilp         7276/tcp    OMA Internal Location
 */
#define ILP_TCP_PORT    7276

/* Initialize the protocol and registered fields */
static int proto_ilp;


#define ILP_HEADER_SIZE 2

static bool ilp_desegment = true;

static int hf_ilp_ILP_PDU_PDU;                    /* ILP_PDU */
static int hf_ilp_length;                         /* INTEGER_0_65535 */
static int hf_ilp_version;                        /* Version */
static int hf_ilp_sessionID2;                     /* SessionID2 */
static int hf_ilp_message;                        /* IlpMessage */
static int hf_ilp_msPREQ;                         /* PREQ */
static int hf_ilp_msPRES;                         /* PRES */
static int hf_ilp_msPRPT;                         /* PRPT */
static int hf_ilp_msPLREQ;                        /* PLREQ */
static int hf_ilp_msPLRES;                        /* PLRES */
static int hf_ilp_msPINIT;                        /* PINIT */
static int hf_ilp_msPAUTH;                        /* PAUTH */
static int hf_ilp_msPALIVE;                       /* PALIVE */
static int hf_ilp_msPEND;                         /* PEND */
static int hf_ilp_msPMESS;                        /* PMESS */
static int hf_ilp_sLPMode;                        /* SLPMode */
static int hf_ilp_approvedPosMethods;             /* PosTechnology */
static int hf_ilp_locationId;                     /* LocationId */
static int hf_ilp_multipleLocationIds;            /* MultipleLocationIds */
static int hf_ilp_position;                       /* Position */
static int hf_ilp_triggerParams;                  /* TriggerParams */
static int hf_ilp_sPCSETKey;                      /* SPCSETKey */
static int hf_ilp_spctid;                         /* SPCTID */
static int hf_ilp_sPCSETKeylifetime;              /* SPCSETKeylifetime */
static int hf_ilp_qoP;                            /* QoP */
static int hf_ilp_sETCapabilities;                /* SETCapabilities */
static int hf_ilp_notificationMode;               /* NotificationMode */
static int hf_ilp_triggerType;                    /* TriggerType */
static int hf_ilp_periodicTriggerParams;          /* PeriodicTriggerParams */
static int hf_ilp_numberOfFixes;                  /* INTEGER_1_8639999 */
static int hf_ilp_intervalBetweenFixes;           /* INTEGER_1_8639999 */
static int hf_ilp_startTime;                      /* INTEGER_0_2678400 */
static int hf_ilp_preferredPosMethod;             /* PosMethod */
static int hf_ilp_gnssPosTechnology;              /* GNSSPosTechnology */
static int hf_ilp_supportedPosMethods;            /* PosTechnology */
static int hf_ilp_sPCstatusCode;                  /* SPCStatusCode */
static int hf_ilp_fixNumber;                      /* INTEGER_1_8639999 */
static int hf_ilp_statusCode;                     /* StatusCode */
static int hf_ilp_positionResults;                /* PositionResults */
static int hf_ilp_PositionResults_item;           /* PositionResult */
static int hf_ilp_posMethod;                      /* PosMethod */
static int hf_ilp_requestedAssistData;            /* RequestedAssistData */
static int hf_ilp_posPayLoad;                     /* PosPayLoad */
static int hf_ilp_utran_GPSReferenceTimeResult;   /* UTRAN_GPSReferenceTimeResult */
static int hf_ilp_utran_GANSSReferenceTimeResult;  /* UTRAN_GANSSReferenceTimeResult */
static int hf_ilp_almanacRequested;               /* BOOLEAN */
static int hf_ilp_utcModelRequested;              /* BOOLEAN */
static int hf_ilp_ionosphericModelRequested;      /* BOOLEAN */
static int hf_ilp_dgpsCorrectionsRequested;       /* BOOLEAN */
static int hf_ilp_referenceLocationRequested;     /* BOOLEAN */
static int hf_ilp_referenceTimeRequested;         /* BOOLEAN */
static int hf_ilp_acquisitionAssistanceRequested;  /* BOOLEAN */
static int hf_ilp_realTimeIntegrityRequested;     /* BOOLEAN */
static int hf_ilp_navigationModelRequested;       /* BOOLEAN */
static int hf_ilp_navigationModelData;            /* NavigationModel */
static int hf_ilp_ganssRequestedCommonAssistanceDataList;  /* GanssRequestedCommonAssistanceDataList */
static int hf_ilp_ganssRequestedGenericAssistanceDataList;  /* GanssRequestedGenericAssistanceDataList */
static int hf_ilp_extendedEphemeris;              /* ExtendedEphemeris */
static int hf_ilp_extendedEphemerisCheck;         /* ExtendedEphCheck */
static int hf_ilp_validity;                       /* INTEGER_1_256 */
static int hf_ilp_beginTime;                      /* GPSTime */
static int hf_ilp_endTime;                        /* GPSTime */
static int hf_ilp_gPSWeek;                        /* INTEGER_0_1023 */
static int hf_ilp_gPSTOWhour;                     /* INTEGER_0_167 */
static int hf_ilp_ganssReferenceTime;             /* BOOLEAN */
static int hf_ilp_ganssIonosphericModel;          /* BOOLEAN */
static int hf_ilp_ganssAdditionalIonosphericModelForDataID00;  /* BOOLEAN */
static int hf_ilp_ganssAdditionalIonosphericModelForDataID11;  /* BOOLEAN */
static int hf_ilp_ganssEarthOrientationParameters;  /* BOOLEAN */
static int hf_ilp_ganssAdditionalIonosphericModelForDataID01;  /* BOOLEAN */
static int hf_ilp_GanssRequestedGenericAssistanceDataList_item;  /* GanssReqGenericData */
static int hf_ilp_ganssId;                        /* INTEGER_0_15 */
static int hf_ilp_ganssSBASid;                    /* BIT_STRING_SIZE_3 */
static int hf_ilp_ganssRealTimeIntegrity;         /* BOOLEAN */
static int hf_ilp_ganssDifferentialCorrection;    /* DGANSS_Sig_Id_Req */
static int hf_ilp_ganssAlmanac;                   /* BOOLEAN */
static int hf_ilp_ganssNavigationModelData;       /* GanssNavigationModelData */
static int hf_ilp_ganssTimeModels;                /* BIT_STRING_SIZE_16 */
static int hf_ilp_ganssReferenceMeasurementInfo;  /* BOOLEAN */
static int hf_ilp_ganssDataBits;                  /* GanssDataBits */
static int hf_ilp_ganssUTCModel;                  /* BOOLEAN */
static int hf_ilp_ganssAdditionalDataChoices;     /* GanssAdditionalDataChoices */
static int hf_ilp_ganssAuxiliaryInformation;      /* BOOLEAN */
static int hf_ilp_ganssExtendedEphemeris;         /* ExtendedEphemeris */
static int hf_ilp_ganssExtendedEphemerisCheck;    /* GanssExtendedEphCheck */
static int hf_ilp_bds_DifferentialCorrection;     /* BDS_Sig_Id_Req */
static int hf_ilp_bds_GridModelReq;               /* BOOLEAN */
static int hf_ilp_ganssWeek;                      /* INTEGER_0_4095 */
static int hf_ilp_ganssToe;                       /* INTEGER_0_167 */
static int hf_ilp_t_toeLimit;                     /* INTEGER_0_10 */
static int hf_ilp_satellitesListRelatedDataList;  /* SatellitesListRelatedDataList */
static int hf_ilp_SatellitesListRelatedDataList_item;  /* SatellitesListRelatedData */
static int hf_ilp_satId;                          /* INTEGER_0_63 */
static int hf_ilp_iod;                            /* INTEGER_0_1023 */
static int hf_ilp_ganssTODmin;                    /* INTEGER_0_59 */
static int hf_ilp_reqDataBitAssistanceList;       /* ReqDataBitAssistanceList */
static int hf_ilp_gnssSignals;                    /* GANSSSignals */
static int hf_ilp_ganssDataBitInterval;           /* INTEGER_0_15 */
static int hf_ilp_ganssDataBitSatList;            /* T_ganssDataBitSatList */
static int hf_ilp_ganssDataBitSatList_item;       /* INTEGER_0_63 */
static int hf_ilp_orbitModelID;                   /* INTEGER_0_7 */
static int hf_ilp_clockModelID;                   /* INTEGER_0_7 */
static int hf_ilp_utcModelID;                     /* INTEGER_0_7 */
static int hf_ilp_almanacModelID;                 /* INTEGER_0_7 */
static int hf_ilp_beginTime_01;                   /* GANSSextEphTime */
static int hf_ilp_endTime_01;                     /* GANSSextEphTime */
static int hf_ilp_gANSSday;                       /* INTEGER_0_8191 */
static int hf_ilp_gANSSTODhour;                   /* INTEGER_0_23 */
static int hf_ilp_gpsWeek;                        /* INTEGER_0_1023 */
static int hf_ilp_gpsToe;                         /* INTEGER_0_167 */
static int hf_ilp_nsat;                           /* INTEGER_0_31 */
static int hf_ilp_toeLimit;                       /* INTEGER_0_10 */
static int hf_ilp_satInfo;                        /* SatelliteInfo */
static int hf_ilp_SatelliteInfo_item;             /* SatelliteInfoElement */
static int hf_ilp_iode;                           /* INTEGER_0_255 */
static int hf_ilp_sPCStatusCode;                  /* SPCStatusCode */
static int hf_ilp_velocity;                       /* Velocity */
static int hf_ilp_utran_GPSReferenceTimeAssistance;  /* UTRAN_GPSReferenceTimeAssistance */
static int hf_ilp_utran_GANSSReferenceTimeAssistance;  /* UTRAN_GANSSReferenceTimeAssistance */
static int hf_ilp_maj;                            /* INTEGER_0_255 */
static int hf_ilp_min;                            /* INTEGER_0_255 */
static int hf_ilp_servind;                        /* INTEGER_0_255 */
static int hf_ilp_slcSessionID;                   /* SlcSessionID */
static int hf_ilp_setSessionID;                   /* SetSessionID */
static int hf_ilp_spcSessionID;                   /* SpcSessionID */
static int hf_ilp_sessionId;                      /* INTEGER_0_65535 */
static int hf_ilp_setId;                          /* SETId */
static int hf_ilp_msisdn;                         /* T_msisdn */
static int hf_ilp_mdn;                            /* T_mdn */
static int hf_ilp_minsi;                          /* BIT_STRING_SIZE_34 */
static int hf_ilp_imsi;                           /* T_imsi */
static int hf_ilp_nai;                            /* IA5String_SIZE_1_1000 */
static int hf_ilp_iPAddress;                      /* IPAddress */
static int hf_ilp_imei;                           /* OCTET_STRING_SIZE_8 */
static int hf_ilp_sessionID;                      /* OCTET_STRING_SIZE_4 */
static int hf_ilp_slcId;                          /* NodeAddress */
static int hf_ilp_spcId;                          /* NodeAddress */
static int hf_ilp_ipv4Address;                    /* OCTET_STRING_SIZE_4 */
static int hf_ilp_ipv6Address;                    /* OCTET_STRING_SIZE_16 */
static int hf_ilp_fqdn;                           /* FQDN */
static int hf_ilp_cellInfo;                       /* CellInfo */
static int hf_ilp_status;                         /* Status */
static int hf_ilp_MultipleLocationIds_item;       /* LocationIdData */
static int hf_ilp_relativetimestamp;              /* RelativeTime */
static int hf_ilp_servingFlag;                    /* BOOLEAN */
static int hf_ilp_posTechnology;                  /* PosTechnology */
static int hf_ilp_prefMethod;                     /* PrefMethod */
static int hf_ilp_posProtocol;                    /* PosProtocol */
static int hf_ilp_supportedBearers;               /* SupportedBearers */
static int hf_ilp_agpsSETassisted;                /* BOOLEAN */
static int hf_ilp_agpsSETBased;                   /* BOOLEAN */
static int hf_ilp_autonomousGPS;                  /* BOOLEAN */
static int hf_ilp_aflt;                           /* BOOLEAN */
static int hf_ilp_ecid;                           /* BOOLEAN */
static int hf_ilp_eotd;                           /* BOOLEAN */
static int hf_ilp_otdoa;                          /* BOOLEAN */
static int hf_ilp_gANSSPositionMethods;           /* GANSSPositionMethods */
static int hf_ilp_additionalPositioningMethods;   /* AdditionalPositioningMethods */
static int hf_ilp_GANSSPositionMethods_item;      /* GANSSPositionMethod */
static int hf_ilp_gANSSPositioningMethodTypes;    /* GANSSPositioningMethodTypes */
static int hf_ilp_gANSSSignals;                   /* GANSSSignals */
static int hf_ilp_setAssisted;                    /* BOOLEAN */
static int hf_ilp_setBased;                       /* BOOLEAN */
static int hf_ilp_autonomous;                     /* BOOLEAN */
static int hf_ilp_AdditionalPositioningMethods_item;  /* AddPosSupport_Element */
static int hf_ilp_addPosID;                       /* T_addPosID */
static int hf_ilp_addPosMode;                     /* T_addPosMode */
static int hf_ilp_tia801;                         /* BOOLEAN */
static int hf_ilp_rrlp;                           /* BOOLEAN */
static int hf_ilp_rrc;                            /* BOOLEAN */
static int hf_ilp_lpp;                            /* BOOLEAN */
static int hf_ilp_posProtocolVersionRRLP;         /* PosProtocolVersion3GPP */
static int hf_ilp_posProtocolVersionRRC;          /* PosProtocolVersion3GPP */
static int hf_ilp_posProtocolVersionTIA801;       /* PosProtocolVersion3GPP2 */
static int hf_ilp_posProtocolVersionLPP;          /* PosProtocolVersion3GPP */
static int hf_ilp_lppe;                           /* BOOLEAN */
static int hf_ilp_posProtocolVersionLPPe;         /* PosProtocolVersionOMA */
static int hf_ilp_majorVersionField;              /* INTEGER_0_255 */
static int hf_ilp_technicalVersionField;          /* INTEGER_0_255 */
static int hf_ilp_editorialVersionField;          /* INTEGER_0_255 */
static int hf_ilp_PosProtocolVersion3GPP2_item;   /* Supported3GPP2PosProtocolVersion */
static int hf_ilp_revisionNumber;                 /* BIT_STRING_SIZE_6 */
static int hf_ilp_pointReleaseNumber;             /* INTEGER_0_255 */
static int hf_ilp_internalEditLevel;              /* INTEGER_0_255 */
static int hf_ilp_minorVersionField;              /* INTEGER_0_255 */
static int hf_ilp_gsm;                            /* BOOLEAN */
static int hf_ilp_wcdma;                          /* BOOLEAN */
static int hf_ilp_lte;                            /* BOOLEAN */
static int hf_ilp_cdma;                           /* BOOLEAN */
static int hf_ilp_hprd;                           /* BOOLEAN */
static int hf_ilp_umb;                            /* BOOLEAN */
static int hf_ilp_wlan;                           /* BOOLEAN */
static int hf_ilp_wiMAX;                          /* BOOLEAN */
static int hf_ilp_nr;                             /* BOOLEAN */
static int hf_ilp_gsmCell;                        /* GsmCellInformation */
static int hf_ilp_wcdmaCell;                      /* WcdmaCellInformation */
static int hf_ilp_cdmaCell;                       /* CdmaCellInformation */
static int hf_ilp_hrpdCell;                       /* HrpdCellInformation */
static int hf_ilp_umbCell;                        /* UmbCellInformation */
static int hf_ilp_lteCell;                        /* LteCellInformation */
static int hf_ilp_wlanAP;                         /* WlanAPInformation */
static int hf_ilp_wimaxBS;                        /* WimaxBSInformation */
static int hf_ilp_nrCell;                         /* NRCellInformation */
static int hf_ilp_set_GPSTimingOfCell;            /* T_set_GPSTimingOfCell */
static int hf_ilp_ms_part;                        /* INTEGER_0_16383 */
static int hf_ilp_ls_part;                        /* INTEGER_0_4294967295 */
static int hf_ilp_modeSpecificInfo;               /* T_modeSpecificInfo */
static int hf_ilp_fdd;                            /* T_fdd */
static int hf_ilp_referenceIdentity;              /* PrimaryCPICH_Info */
static int hf_ilp_tdd;                            /* T_tdd */
static int hf_ilp_referenceIdentity_01;           /* CellParametersID */
static int hf_ilp_sfn;                            /* INTEGER_0_4095 */
static int hf_ilp_gpsReferenceTimeUncertainty;    /* INTEGER_0_127 */
static int hf_ilp_ganssTimeID;                    /* INTEGER_0_15 */
static int hf_ilp_set_GANSSReferenceTime;         /* SET_GANSSReferenceTime */
static int hf_ilp_set_GANSSTimingOfCell;          /* T_set_GANSSTimingOfCell */
static int hf_ilp_ms_part_01;                     /* INTEGER_0_80 */
static int hf_ilp_modeSpecificInfo_01;            /* T_modeSpecificInfo_01 */
static int hf_ilp_fdd_01;                         /* T_fdd_01 */
static int hf_ilp_tdd_01;                         /* T_tdd_01 */
static int hf_ilp_ganss_TODUncertainty;           /* INTEGER_0_127 */
static int hf_ilp_gps;                            /* BOOLEAN */
static int hf_ilp_galileo;                        /* BOOLEAN */
static int hf_ilp_sbas;                           /* BOOLEAN */
static int hf_ilp_modernized_gps;                 /* BOOLEAN */
static int hf_ilp_qzss;                           /* BOOLEAN */
static int hf_ilp_glonass;                        /* BOOLEAN */
static int hf_ilp_bds;                            /* BOOLEAN */
static int hf_ilp_timestamp;                      /* UTCTime */
static int hf_ilp_positionEstimate;               /* PositionEstimate */
static int hf_ilp_latitudeSign;                   /* T_latitudeSign */
static int hf_ilp_latitude;                       /* INTEGER_0_8388607 */
static int hf_ilp_longitude;                      /* INTEGER_M8388608_8388607 */
static int hf_ilp_uncertainty;                    /* T_uncertainty */
static int hf_ilp_uncertaintySemiMajor;           /* INTEGER_0_127 */
static int hf_ilp_uncertaintySemiMinor;           /* INTEGER_0_127 */
static int hf_ilp_orientationMajorAxis;           /* INTEGER_0_180 */
static int hf_ilp_confidence;                     /* INTEGER_0_100 */
static int hf_ilp_altitudeInfo;                   /* AltitudeInfo */
static int hf_ilp_altitudeDirection;              /* T_altitudeDirection */
static int hf_ilp_altitude;                       /* INTEGER_0_32767 */
static int hf_ilp_altUncertainty;                 /* INTEGER_0_127 */
static int hf_ilp_refNID;                         /* INTEGER_0_65535 */
static int hf_ilp_refSID;                         /* INTEGER_0_32767 */
static int hf_ilp_refBASEID;                      /* INTEGER_0_65535 */
static int hf_ilp_refBASELAT;                     /* INTEGER_0_4194303 */
static int hf_ilp_reBASELONG;                     /* INTEGER_0_8388607 */
static int hf_ilp_refREFPN;                       /* INTEGER_0_511 */
static int hf_ilp_refWeekNumber;                  /* INTEGER_0_65535 */
static int hf_ilp_refSeconds;                     /* INTEGER_0_4194303 */
static int hf_ilp_refMCC;                         /* INTEGER_0_999 */
static int hf_ilp_refMNC;                         /* INTEGER_0_999 */
static int hf_ilp_refLAC;                         /* INTEGER_0_65535 */
static int hf_ilp_refCI;                          /* INTEGER_0_65535 */
static int hf_ilp_nmr;                            /* NMR */
static int hf_ilp_ta;                             /* INTEGER_0_255 */
static int hf_ilp_refUC;                          /* INTEGER_0_268435455 */
static int hf_ilp_frequencyInfo;                  /* FrequencyInfo */
static int hf_ilp_primaryScramblingCode;          /* INTEGER_0_511 */
static int hf_ilp_measuredResultsList;            /* MeasuredResultsList */
static int hf_ilp_cellParametersId;               /* INTEGER_0_127 */
static int hf_ilp_timingAdvance;                  /* TimingAdvance */
static int hf_ilp_ta_01;                          /* INTEGER_0_8191 */
static int hf_ilp_tAResolution;                   /* TAResolution */
static int hf_ilp_chipRate;                       /* ChipRate */
static int hf_ilp_refSECTORID;                    /* BIT_STRING_SIZE_128 */
static int hf_ilp_cellGlobalIdEUTRA;              /* CellGlobalIdEUTRA */
static int hf_ilp_physCellId;                     /* PhysCellId */
static int hf_ilp_trackingAreaCode;               /* TrackingAreaCode */
static int hf_ilp_rsrpResult;                     /* RSRP_Range */
static int hf_ilp_rsrqResult;                     /* RSRQ_Range */
static int hf_ilp_ta_02;                          /* INTEGER_0_1282 */
static int hf_ilp_measResultListEUTRA;            /* MeasResultListEUTRA */
static int hf_ilp_earfcn;                         /* INTEGER_0_65535 */
static int hf_ilp_earfcn_ext;                     /* INTEGER_65536_262143 */
static int hf_ilp_rsrpResult_ext;                 /* RSRP_Range_Ext */
static int hf_ilp_rsrqResult_ext;                 /* RSRQ_Range_Ext */
static int hf_ilp_rs_sinrResult;                  /* RS_SINR_Range */
static int hf_ilp_servingInformation5G;           /* ServingInformation5G */
static int hf_ilp_MeasResultListEUTRA_item;       /* MeasResultEUTRA */
static int hf_ilp_cgi_Info;                       /* T_cgi_Info */
static int hf_ilp_cellGlobalId;                   /* CellGlobalIdEUTRA */
static int hf_ilp_measResult;                     /* T_measResult */
static int hf_ilp_neighbourInformation5G;         /* NeighbourInformation5G */
static int hf_ilp_plmn_Identity;                  /* PLMN_Identity */
static int hf_ilp_eutra_cellIdentity;             /* CellIdentity */
static int hf_ilp_mcc;                            /* MCC */
static int hf_ilp_mnc;                            /* MNC */
static int hf_ilp_MCC_item;                       /* MCC_MNC_Digit */
static int hf_ilp_MNC_item;                       /* MCC_MNC_Digit */
static int hf_ilp_trackingAreaCode_01;            /* TrackingAreaCodeNR */
static int hf_ilp_apMACAddress;                   /* BIT_STRING_SIZE_48 */
static int hf_ilp_apTransmitPower;                /* INTEGER_M127_128 */
static int hf_ilp_apAntennaGain;                  /* INTEGER_M127_128 */
static int hf_ilp_apSignaltoNoise;                /* INTEGER_M127_128 */
static int hf_ilp_apDeviceType;                   /* T_apDeviceType */
static int hf_ilp_apSignalStrength;               /* INTEGER_M127_128 */
static int hf_ilp_apChannelFrequency;             /* INTEGER_0_256 */
static int hf_ilp_apRoundTripDelay;               /* RTD */
static int hf_ilp_setTransmitPower;               /* INTEGER_M127_128 */
static int hf_ilp_setAntennaGain;                 /* INTEGER_M127_128 */
static int hf_ilp_setSignaltoNoise;               /* INTEGER_M127_128 */
static int hf_ilp_setSignalStrength;              /* INTEGER_M127_128 */
static int hf_ilp_apReportedLocation;             /* ReportedLocation */
static int hf_ilp_apRepLocation;                  /* RepLocation */
static int hf_ilp_apSignalStrengthDelta;          /* INTEGER_0_1 */
static int hf_ilp_apSignaltoNoiseDelta;           /* INTEGER_0_1 */
static int hf_ilp_setSignalStrengthDelta;         /* INTEGER_0_1 */
static int hf_ilp_setSignaltoNoiseDelta;          /* INTEGER_0_1 */
static int hf_ilp_operatingClass;                 /* INTEGER_0_255 */
static int hf_ilp_apSSID;                         /* OCTET_STRING_SIZE_1_32 */
static int hf_ilp_apPHYType;                      /* T_apPHYType */
static int hf_ilp_setMACAddress;                  /* BIT_STRING_SIZE_48 */
static int hf_ilp_rTDValue;                       /* INTEGER_0_16777216 */
static int hf_ilp_rTDUnits;                       /* RTDUnits */
static int hf_ilp_rTDAccuracy;                    /* INTEGER_0_255 */
static int hf_ilp_locationEncodingDescriptor;     /* LocationEncodingDescriptor */
static int hf_ilp_locationData;                   /* LocationData */
static int hf_ilp_locationAccuracy;               /* INTEGER_0_4294967295 */
static int hf_ilp_locationValue;                  /* OCTET_STRING_SIZE_1_128 */
static int hf_ilp_lciLocData;                     /* LciLocData */
static int hf_ilp_locationDataLCI;                /* LocationDataLCI */
static int hf_ilp_latitudeResolution;             /* BIT_STRING_SIZE_6 */
static int hf_ilp_LocationDataLCI_latitude;       /* BIT_STRING_SIZE_34 */
static int hf_ilp_longitudeResolution;            /* BIT_STRING_SIZE_6 */
static int hf_ilp_LocationDataLCI_longitude;      /* BIT_STRING_SIZE_34 */
static int hf_ilp_altitudeType;                   /* BIT_STRING_SIZE_4 */
static int hf_ilp_altitudeResolution;             /* BIT_STRING_SIZE_6 */
static int hf_ilp_LocationDataLCI_altitude;       /* BIT_STRING_SIZE_30 */
static int hf_ilp_datum;                          /* BIT_STRING_SIZE_8 */
static int hf_ilp_wimaxBsID;                      /* WimaxBsID */
static int hf_ilp_wimaxRTD;                       /* WimaxRTD */
static int hf_ilp_wimaxNMRList;                   /* WimaxNMRList */
static int hf_ilp_bsID_MSB;                       /* BIT_STRING_SIZE_24 */
static int hf_ilp_bsID_LSB;                       /* BIT_STRING_SIZE_24 */
static int hf_ilp_rtd;                            /* INTEGER_0_65535 */
static int hf_ilp_rTDstd;                         /* INTEGER_0_1023 */
static int hf_ilp_WimaxNMRList_item;              /* WimaxNMR */
static int hf_ilp_relDelay;                       /* INTEGER_M32768_32767 */
static int hf_ilp_relDelaystd;                    /* INTEGER_0_1023 */
static int hf_ilp_rssi;                           /* INTEGER_0_255 */
static int hf_ilp_rSSIstd;                        /* INTEGER_0_63 */
static int hf_ilp_bSTxPower;                      /* INTEGER_0_255 */
static int hf_ilp_cinr;                           /* INTEGER_0_255 */
static int hf_ilp_cINRstd;                        /* INTEGER_0_63 */
static int hf_ilp_bSLocation;                     /* ReportedLocation */
static int hf_ilp_servingCellInformation;         /* ServingCellInformationNR */
static int hf_ilp_measuredResultsListNR;          /* MeasResultListNR */
static int hf_ilp_ServingCellInformationNR_item;  /* ServCellNR */
static int hf_ilp_physCellId_01;                  /* PhysCellIdNR */
static int hf_ilp_arfcn_NR;                       /* ARFCN_NR */
static int hf_ilp_cellGlobalId_01;                /* CellGlobalIdNR */
static int hf_ilp_ssb_Measurements;               /* NR_Measurements */
static int hf_ilp_csi_rs_Measurements;            /* NR_Measurements */
static int hf_ilp_ta_03;                          /* INTEGER_0_3846 */
static int hf_ilp_MeasResultListNR_item;          /* MeasResultNR */
static int hf_ilp_cellIdentityNR;                 /* CellIdentityNR */
static int hf_ilp_rsrp_Range;                     /* INTEGER_0_127 */
static int hf_ilp_rsrq_Range;                     /* INTEGER_0_127 */
static int hf_ilp_sinr_Range;                     /* INTEGER_0_127 */
static int hf_ilp_modeSpecificFrequencyInfo;      /* FrequencySpecificInfo */
static int hf_ilp_fdd_fr;                         /* FrequencyInfoFDD */
static int hf_ilp_tdd_fr;                         /* FrequencyInfoTDD */
static int hf_ilp_uarfcn_UL;                      /* UARFCN */
static int hf_ilp_uarfcn_DL;                      /* UARFCN */
static int hf_ilp_uarfcn_Nt;                      /* UARFCN */
static int hf_ilp_NMR_item;                       /* NMRelement */
static int hf_ilp_arfcn;                          /* INTEGER_0_1023 */
static int hf_ilp_bsic;                           /* INTEGER_0_63 */
static int hf_ilp_rxLev;                          /* INTEGER_0_63 */
static int hf_ilp_MeasuredResultsList_item;       /* MeasuredResults */
static int hf_ilp_utra_CarrierRSSI;               /* UTRA_CarrierRSSI */
static int hf_ilp_cellMeasuredResultsList;        /* CellMeasuredResultsList */
static int hf_ilp_CellMeasuredResultsList_item;   /* CellMeasuredResults */
static int hf_ilp_cellIdentity;                   /* INTEGER_0_268435455 */
static int hf_ilp_modeSpecificInfo_02;            /* T_modeSpecificInfo_02 */
static int hf_ilp_fdd_02;                         /* T_fdd_02 */
static int hf_ilp_primaryCPICH_Info;              /* PrimaryCPICH_Info */
static int hf_ilp_cpich_Ec_N0;                    /* CPICH_Ec_N0 */
static int hf_ilp_cpich_RSCP;                     /* CPICH_RSCP */
static int hf_ilp_pathloss;                       /* Pathloss */
static int hf_ilp_tdd_02;                         /* T_tdd_02 */
static int hf_ilp_cellParametersID;               /* CellParametersID */
static int hf_ilp_proposedTGSN;                   /* TGSN */
static int hf_ilp_primaryCCPCH_RSCP;              /* PrimaryCCPCH_RSCP */
static int hf_ilp_timeslotISCP_List;              /* TimeslotISCP_List */
static int hf_ilp_TimeslotISCP_List_item;         /* TimeslotISCP */
static int hf_ilp_utran_GPSReferenceTime;         /* UTRAN_GPSReferenceTime */
static int hf_ilp_utranGPSDriftRate;              /* UTRANGPSDriftRate */
static int hf_ilp_utran_GPSTimingOfCell;          /* T_utran_GPSTimingOfCell */
static int hf_ilp_ms_part_02;                     /* INTEGER_0_1023 */
static int hf_ilp_modeSpecificInfo_03;            /* T_modeSpecificInfo_03 */
static int hf_ilp_fdd_03;                         /* T_fdd_03 */
static int hf_ilp_tdd_03;                         /* T_tdd_03 */
static int hf_ilp_utran_GANSSReferenceTime;       /* UTRAN_GANSSReferenceTime */
static int hf_ilp_ganssDay;                       /* INTEGER_0_8191 */
static int hf_ilp_utranGANSSDriftRate;            /* UTRANGANSSDriftRate */
static int hf_ilp_ganssTOD;                       /* INTEGER_0_86399 */
static int hf_ilp_utran_GANSSTimingOfCell;        /* INTEGER_0_3999999 */
static int hf_ilp_modeSpecificInfo_04;            /* T_modeSpecificInfo_04 */
static int hf_ilp_fdd_04;                         /* T_fdd_04 */
static int hf_ilp_tdd_04;                         /* T_tdd_04 */
static int hf_ilp_horacc;                         /* INTEGER_0_127 */
static int hf_ilp_veracc;                         /* INTEGER_0_127 */
static int hf_ilp_maxLocAge;                      /* INTEGER_0_65535 */
static int hf_ilp_delay;                          /* INTEGER_0_7 */
static int hf_ilp_ver2_responseTime;              /* INTEGER_1_128 */
static int hf_ilp_horvel;                         /* Horvel */
static int hf_ilp_horandvervel;                   /* Horandvervel */
static int hf_ilp_horveluncert;                   /* Horveluncert */
static int hf_ilp_horandveruncert;                /* Horandveruncert */
static int hf_ilp_bearing;                        /* BIT_STRING_SIZE_9 */
static int hf_ilp_horspeed;                       /* BIT_STRING_SIZE_16 */
static int hf_ilp_verdirect;                      /* BIT_STRING_SIZE_1 */
static int hf_ilp_verspeed;                       /* BIT_STRING_SIZE_8 */
static int hf_ilp_uncertspeed;                    /* BIT_STRING_SIZE_8 */
static int hf_ilp_horuncertspeed;                 /* BIT_STRING_SIZE_8 */
static int hf_ilp_veruncertspeed;                 /* BIT_STRING_SIZE_8 */
static int hf_ilp_rand;                           /* BIT_STRING_SIZE_128 */
static int hf_ilp_slpFQDN;                        /* FQDN */
static int hf_ilp_rrcPayload;                     /* OCTET_STRING_SIZE_1_8192 */
static int hf_ilp_rrlpPayload;                    /* T_rrlpPayload */
static int hf_ilp_multiPosPayload;                /* MultiPosPayLoad */
static int hf_ilp_lPPPayload;                     /* T_lPPPayload */
static int hf_ilp_lPPPayload_item;                /* T_lPPPayload_item */
static int hf_ilp_tia801Payload;                  /* T_tia801Payload */
static int hf_ilp_tia801Payload_item;             /* OCTET_STRING_SIZE_1_60000 */
/* named bits */
static int hf_ilp_GANSSSignals_signal1;
static int hf_ilp_GANSSSignals_signal2;
static int hf_ilp_GANSSSignals_signal3;
static int hf_ilp_GANSSSignals_signal4;
static int hf_ilp_GANSSSignals_signal5;
static int hf_ilp_GANSSSignals_signal6;
static int hf_ilp_GANSSSignals_signal7;
static int hf_ilp_GANSSSignals_signal8;
static int hf_ilp_T_addPosMode_standalone;
static int hf_ilp_T_addPosMode_setBased;
static int hf_ilp_T_addPosMode_setAssisted;
static int hf_ilp_mobile_directory_number;

/* Initialize the subtree pointers */
static int ett_ilp;
static int ett_ilp_setid;
static int ett_ilp_ILP_PDU;
static int ett_ilp_IlpMessage;
static int ett_ilp_PREQ;
static int ett_ilp_TriggerParams;
static int ett_ilp_PeriodicTriggerParams;
static int ett_ilp_PRES;
static int ett_ilp_PRPT;
static int ett_ilp_PLREQ;
static int ett_ilp_PLRES;
static int ett_ilp_PositionResults;
static int ett_ilp_PositionResult;
static int ett_ilp_PINIT;
static int ett_ilp_RequestedAssistData;
static int ett_ilp_ExtendedEphemeris;
static int ett_ilp_ExtendedEphCheck;
static int ett_ilp_GPSTime;
static int ett_ilp_GanssRequestedCommonAssistanceDataList;
static int ett_ilp_GanssRequestedGenericAssistanceDataList;
static int ett_ilp_GanssReqGenericData;
static int ett_ilp_GanssNavigationModelData;
static int ett_ilp_SatellitesListRelatedDataList;
static int ett_ilp_SatellitesListRelatedData;
static int ett_ilp_GanssDataBits;
static int ett_ilp_ReqDataBitAssistanceList;
static int ett_ilp_T_ganssDataBitSatList;
static int ett_ilp_GanssAdditionalDataChoices;
static int ett_ilp_GanssExtendedEphCheck;
static int ett_ilp_GANSSextEphTime;
static int ett_ilp_NavigationModel;
static int ett_ilp_SatelliteInfo;
static int ett_ilp_SatelliteInfoElement;
static int ett_ilp_PAUTH;
static int ett_ilp_PALIVE;
static int ett_ilp_PEND;
static int ett_ilp_PMESS;
static int ett_ilp_Version;
static int ett_ilp_SessionID2;
static int ett_ilp_SetSessionID;
static int ett_ilp_SETId;
static int ett_ilp_SlcSessionID;
static int ett_ilp_SpcSessionID;
static int ett_ilp_IPAddress;
static int ett_ilp_NodeAddress;
static int ett_ilp_LocationId;
static int ett_ilp_MultipleLocationIds;
static int ett_ilp_LocationIdData;
static int ett_ilp_SETCapabilities;
static int ett_ilp_PosTechnology;
static int ett_ilp_GANSSPositionMethods;
static int ett_ilp_GANSSPositionMethod;
static int ett_ilp_GANSSPositioningMethodTypes;
static int ett_ilp_GANSSSignals;
static int ett_ilp_AdditionalPositioningMethods;
static int ett_ilp_AddPosSupport_Element;
static int ett_ilp_T_addPosMode;
static int ett_ilp_PosProtocol;
static int ett_ilp_PosProtocolVersion3GPP;
static int ett_ilp_PosProtocolVersion3GPP2;
static int ett_ilp_Supported3GPP2PosProtocolVersion;
static int ett_ilp_PosProtocolVersionOMA;
static int ett_ilp_SupportedBearers;
static int ett_ilp_CellInfo;
static int ett_ilp_UTRAN_GPSReferenceTimeResult;
static int ett_ilp_T_set_GPSTimingOfCell;
static int ett_ilp_T_modeSpecificInfo;
static int ett_ilp_T_fdd;
static int ett_ilp_T_tdd;
static int ett_ilp_UTRAN_GANSSReferenceTimeResult;
static int ett_ilp_SET_GANSSReferenceTime;
static int ett_ilp_T_set_GANSSTimingOfCell;
static int ett_ilp_T_modeSpecificInfo_01;
static int ett_ilp_T_fdd_01;
static int ett_ilp_T_tdd_01;
static int ett_ilp_GNSSPosTechnology;
static int ett_ilp_Position;
static int ett_ilp_PositionEstimate;
static int ett_ilp_T_uncertainty;
static int ett_ilp_AltitudeInfo;
static int ett_ilp_CdmaCellInformation;
static int ett_ilp_GsmCellInformation;
static int ett_ilp_WcdmaCellInformation;
static int ett_ilp_TimingAdvance;
static int ett_ilp_HrpdCellInformation;
static int ett_ilp_UmbCellInformation;
static int ett_ilp_LteCellInformation;
static int ett_ilp_MeasResultListEUTRA;
static int ett_ilp_MeasResultEUTRA;
static int ett_ilp_T_cgi_Info;
static int ett_ilp_T_measResult;
static int ett_ilp_CellGlobalIdEUTRA;
static int ett_ilp_PLMN_Identity;
static int ett_ilp_MCC;
static int ett_ilp_MNC;
static int ett_ilp_ServingInformation5G;
static int ett_ilp_NeighbourInformation5G;
static int ett_ilp_WlanAPInformation;
static int ett_ilp_RTD;
static int ett_ilp_ReportedLocation;
static int ett_ilp_LocationData;
static int ett_ilp_RepLocation;
static int ett_ilp_LciLocData;
static int ett_ilp_LocationDataLCI;
static int ett_ilp_WimaxBSInformation;
static int ett_ilp_WimaxBsID;
static int ett_ilp_WimaxRTD;
static int ett_ilp_WimaxNMRList;
static int ett_ilp_WimaxNMR;
static int ett_ilp_NRCellInformation;
static int ett_ilp_ServingCellInformationNR;
static int ett_ilp_ServCellNR;
static int ett_ilp_MeasResultListNR;
static int ett_ilp_MeasResultNR;
static int ett_ilp_CellGlobalIdNR;
static int ett_ilp_NR_Measurements;
static int ett_ilp_FrequencyInfo;
static int ett_ilp_FrequencySpecificInfo;
static int ett_ilp_FrequencyInfoFDD;
static int ett_ilp_FrequencyInfoTDD;
static int ett_ilp_NMR;
static int ett_ilp_NMRelement;
static int ett_ilp_MeasuredResultsList;
static int ett_ilp_MeasuredResults;
static int ett_ilp_CellMeasuredResultsList;
static int ett_ilp_CellMeasuredResults;
static int ett_ilp_T_modeSpecificInfo_02;
static int ett_ilp_T_fdd_02;
static int ett_ilp_T_tdd_02;
static int ett_ilp_TimeslotISCP_List;
static int ett_ilp_PrimaryCPICH_Info;
static int ett_ilp_UTRAN_GPSReferenceTimeAssistance;
static int ett_ilp_UTRAN_GPSReferenceTime;
static int ett_ilp_T_utran_GPSTimingOfCell;
static int ett_ilp_T_modeSpecificInfo_03;
static int ett_ilp_T_fdd_03;
static int ett_ilp_T_tdd_03;
static int ett_ilp_UTRAN_GANSSReferenceTimeAssistance;
static int ett_ilp_UTRAN_GANSSReferenceTime;
static int ett_ilp_T_modeSpecificInfo_04;
static int ett_ilp_T_fdd_04;
static int ett_ilp_T_tdd_04;
static int ett_ilp_QoP;
static int ett_ilp_Velocity;
static int ett_ilp_Horvel;
static int ett_ilp_Horandvervel;
static int ett_ilp_Horveluncert;
static int ett_ilp_Horandveruncert;
static int ett_ilp_SPCTID;
static int ett_ilp_PosPayLoad;
static int ett_ilp_MultiPosPayLoad;
static int ett_ilp_T_lPPPayload;
static int ett_ilp_T_tia801Payload;

/* Include constants */
#define maxGANSS                       16
#define maxGANSSSat                    32
#define maxLidSize                     64
#define maxCellReport                  8
#define maxWimaxBSMeas                 32
#define maxNRServingCell               32
#define maxCellReportNR                32
#define maxCellMeas                    32
#define maxFreq                        8
#define maxTS                          14
#define maxPosSize                     1024




static int
dissect_ilp_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t Version_sequence[] = {
  { &hf_ilp_maj             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_255 },
  { &hf_ilp_min             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_255 },
  { &hf_ilp_servind         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_Version(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_Version, Version_sequence);

  return offset;
}



static int
dissect_ilp_OCTET_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, false, NULL);

  return offset;
}



static int
dissect_ilp_OCTET_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, false, NULL);

  return offset;
}


static const value_string ilp_IPAddress_vals[] = {
  {   0, "ipv4Address" },
  {   1, "ipv6Address" },
  { 0, NULL }
};

static const per_choice_t IPAddress_choice[] = {
  {   0, &hf_ilp_ipv4Address     , ASN1_NO_EXTENSIONS     , dissect_ilp_OCTET_STRING_SIZE_4 },
  {   1, &hf_ilp_ipv6Address     , ASN1_NO_EXTENSIONS     , dissect_ilp_OCTET_STRING_SIZE_16 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_IPAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_IPAddress, IPAddress_choice,
                                 NULL);

  return offset;
}



static int
dissect_ilp_FQDN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_restricted_character_string(tvb, offset, actx, tree, hf_index,
                                                      1, 255, false, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-", 64,
                                                      NULL);

  return offset;
}


static const value_string ilp_NodeAddress_vals[] = {
  {   0, "iPAddress" },
  {   1, "fqdn" },
  { 0, NULL }
};

static const per_choice_t NodeAddress_choice[] = {
  {   0, &hf_ilp_iPAddress       , ASN1_EXTENSION_ROOT    , dissect_ilp_IPAddress },
  {   1, &hf_ilp_fqdn            , ASN1_EXTENSION_ROOT    , dissect_ilp_FQDN },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_NodeAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_NodeAddress, NodeAddress_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SlcSessionID_sequence[] = {
  { &hf_ilp_sessionID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_OCTET_STRING_SIZE_4 },
  { &hf_ilp_slcId           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_NodeAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_SlcSessionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_SlcSessionID, SlcSessionID_sequence);

  return offset;
}



static int
dissect_ilp_T_msisdn(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *msisdn_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, &msisdn_tvb);

  if (msisdn_tvb) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_ilp_setid);
    dissect_e164_msisdn(msisdn_tvb, subtree, 0, 8, E164_ENC_BCD);
  }


  return offset;
}



static int
dissect_ilp_T_mdn(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *mdn_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, &mdn_tvb);

  if (mdn_tvb) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_ilp_setid);
    proto_tree_add_item(subtree, hf_ilp_mobile_directory_number, mdn_tvb, 0, 8, ENC_BCD_DIGITS_0_9|ENC_LITTLE_ENDIAN);
  }


  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_34(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     34, 34, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ilp_T_imsi(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *imsi_tvb;
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, &imsi_tvb);

  if (imsi_tvb) {
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_ilp_setid);
    dissect_e212_imsi(imsi_tvb, actx->pinfo, subtree, 0, 8, false);
  }


  return offset;
}



static int
dissect_ilp_IA5String_SIZE_1_1000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 1000, false,
                                          NULL);

  return offset;
}



static int
dissect_ilp_OCTET_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, false, NULL);

  return offset;
}


static const value_string ilp_SETId_vals[] = {
  {   0, "msisdn" },
  {   1, "mdn" },
  {   2, "min" },
  {   3, "imsi" },
  {   4, "nai" },
  {   5, "iPAddress" },
  {   6, "imei" },
  { 0, NULL }
};

static const per_choice_t SETId_choice[] = {
  {   0, &hf_ilp_msisdn          , ASN1_EXTENSION_ROOT    , dissect_ilp_T_msisdn },
  {   1, &hf_ilp_mdn             , ASN1_EXTENSION_ROOT    , dissect_ilp_T_mdn },
  {   2, &hf_ilp_minsi           , ASN1_EXTENSION_ROOT    , dissect_ilp_BIT_STRING_SIZE_34 },
  {   3, &hf_ilp_imsi            , ASN1_EXTENSION_ROOT    , dissect_ilp_T_imsi },
  {   4, &hf_ilp_nai             , ASN1_EXTENSION_ROOT    , dissect_ilp_IA5String_SIZE_1_1000 },
  {   5, &hf_ilp_iPAddress       , ASN1_EXTENSION_ROOT    , dissect_ilp_IPAddress },
  {   6, &hf_ilp_imei            , ASN1_NOT_EXTENSION_ROOT, dissect_ilp_OCTET_STRING_SIZE_8 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_SETId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_SETId, SETId_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SetSessionID_sequence[] = {
  { &hf_ilp_sessionId       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_setId           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_SETId },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_SetSessionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_SetSessionID, SetSessionID_sequence);

  return offset;
}


static const per_sequence_t SpcSessionID_sequence[] = {
  { &hf_ilp_sessionID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_OCTET_STRING_SIZE_4 },
  { &hf_ilp_spcId           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_NodeAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_SpcSessionID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_SpcSessionID, SpcSessionID_sequence);

  return offset;
}


static const per_sequence_t SessionID2_sequence[] = {
  { &hf_ilp_slcSessionID    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_SlcSessionID },
  { &hf_ilp_setSessionID    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_SetSessionID },
  { &hf_ilp_spcSessionID    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_SpcSessionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_SessionID2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_SessionID2, SessionID2_sequence);

  return offset;
}


static const value_string ilp_SLPMode_vals[] = {
  {   0, "proxy" },
  {   1, "nonProxy" },
  { 0, NULL }
};


static int
dissect_ilp_SLPMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_ilp_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     3, 3, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GANSSPositioningMethodTypes_sequence[] = {
  { &hf_ilp_setAssisted     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_setBased        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_autonomous      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_GANSSPositioningMethodTypes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_GANSSPositioningMethodTypes, GANSSPositioningMethodTypes_sequence);

  return offset;
}


static int * const GANSSSignals_bits[] = {
  &hf_ilp_GANSSSignals_signal1,
  &hf_ilp_GANSSSignals_signal2,
  &hf_ilp_GANSSSignals_signal3,
  &hf_ilp_GANSSSignals_signal4,
  &hf_ilp_GANSSSignals_signal5,
  &hf_ilp_GANSSSignals_signal6,
  &hf_ilp_GANSSSignals_signal7,
  &hf_ilp_GANSSSignals_signal8,
  NULL
};

static int
dissect_ilp_GANSSSignals(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 8, false, GANSSSignals_bits, 8, NULL, NULL);

  return offset;
}


static const per_sequence_t GANSSPositionMethod_sequence[] = {
  { &hf_ilp_ganssId         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_15 },
  { &hf_ilp_ganssSBASid     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_BIT_STRING_SIZE_3 },
  { &hf_ilp_gANSSPositioningMethodTypes, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_GANSSPositioningMethodTypes },
  { &hf_ilp_gANSSSignals    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_GANSSSignals },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_GANSSPositionMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_GANSSPositionMethod, GANSSPositionMethod_sequence);

  return offset;
}


static const per_sequence_t GANSSPositionMethods_sequence_of[1] = {
  { &hf_ilp_GANSSPositionMethods_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_GANSSPositionMethod },
};

static int
dissect_ilp_GANSSPositionMethods(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_GANSSPositionMethods, GANSSPositionMethods_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const value_string ilp_T_addPosID_vals[] = {
  {   0, "mBS" },
  { 0, NULL }
};


static int
dissect_ilp_T_addPosID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     1, NULL, true, 0, NULL);

  return offset;
}


static int * const T_addPosMode_bits[] = {
  &hf_ilp_T_addPosMode_standalone,
  &hf_ilp_T_addPosMode_setBased,
  &hf_ilp_T_addPosMode_setAssisted,
  NULL
};

static int
dissect_ilp_T_addPosMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 8, false, T_addPosMode_bits, 3, NULL, NULL);

  return offset;
}


static const per_sequence_t AddPosSupport_Element_sequence[] = {
  { &hf_ilp_addPosID        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_T_addPosID },
  { &hf_ilp_addPosMode      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_T_addPosMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_AddPosSupport_Element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_AddPosSupport_Element, AddPosSupport_Element_sequence);

  return offset;
}


static const per_sequence_t AdditionalPositioningMethods_sequence_of[1] = {
  { &hf_ilp_AdditionalPositioningMethods_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_AddPosSupport_Element },
};

static int
dissect_ilp_AdditionalPositioningMethods(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_AdditionalPositioningMethods, AdditionalPositioningMethods_sequence_of,
                                                  1, 8, false);

  return offset;
}


static const per_sequence_t PosTechnology_sequence[] = {
  { &hf_ilp_agpsSETassisted , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_agpsSETBased    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_autonomousGPS   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_aflt            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_ecid            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_eotd            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_otdoa           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_gANSSPositionMethods, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_GANSSPositionMethods },
  { &hf_ilp_additionalPositioningMethods, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_AdditionalPositioningMethods },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PosTechnology(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PosTechnology, PosTechnology_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_0_999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 999U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}


static const per_sequence_t NMRelement_sequence[] = {
  { &hf_ilp_arfcn           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_1023 },
  { &hf_ilp_bsic            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_63 },
  { &hf_ilp_rxLev           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_63 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_NMRelement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_NMRelement, NMRelement_sequence);

  return offset;
}


static const per_sequence_t NMR_sequence_of[1] = {
  { &hf_ilp_NMR_item        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_NMRelement },
};

static int
dissect_ilp_NMR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_NMR, NMR_sequence_of,
                                                  1, 15, false);

  return offset;
}


static const per_sequence_t GsmCellInformation_sequence[] = {
  { &hf_ilp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_999 },
  { &hf_ilp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_999 },
  { &hf_ilp_refLAC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_refCI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_nmr             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_NMR },
  { &hf_ilp_ta              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_GsmCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_GsmCellInformation, GsmCellInformation_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_0_268435455(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 268435455U, NULL, false);

  return offset;
}



static int
dissect_ilp_UARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, false);

  return offset;
}


static const per_sequence_t FrequencyInfoFDD_sequence[] = {
  { &hf_ilp_uarfcn_UL       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_UARFCN },
  { &hf_ilp_uarfcn_DL       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_UARFCN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_FrequencyInfoFDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_FrequencyInfoFDD, FrequencyInfoFDD_sequence);

  return offset;
}


static const per_sequence_t FrequencyInfoTDD_sequence[] = {
  { &hf_ilp_uarfcn_Nt       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_UARFCN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_FrequencyInfoTDD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_FrequencyInfoTDD, FrequencyInfoTDD_sequence);

  return offset;
}


static const value_string ilp_FrequencySpecificInfo_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t FrequencySpecificInfo_choice[] = {
  {   0, &hf_ilp_fdd_fr          , ASN1_EXTENSION_ROOT    , dissect_ilp_FrequencyInfoFDD },
  {   1, &hf_ilp_tdd_fr          , ASN1_EXTENSION_ROOT    , dissect_ilp_FrequencyInfoTDD },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_FrequencySpecificInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_FrequencySpecificInfo, FrequencySpecificInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t FrequencyInfo_sequence[] = {
  { &hf_ilp_modeSpecificFrequencyInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_FrequencySpecificInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_FrequencyInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_FrequencyInfo, FrequencyInfo_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_0_511(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, false);

  return offset;
}



static int
dissect_ilp_UTRA_CarrierRSSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t PrimaryCPICH_Info_sequence[] = {
  { &hf_ilp_primaryScramblingCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_511 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PrimaryCPICH_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PrimaryCPICH_Info, PrimaryCPICH_Info_sequence);

  return offset;
}



static int
dissect_ilp_CPICH_Ec_N0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}



static int
dissect_ilp_CPICH_RSCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_ilp_Pathloss(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            46U, 173U, NULL, false);

  return offset;
}


static const per_sequence_t T_fdd_02_sequence[] = {
  { &hf_ilp_primaryCPICH_Info, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_PrimaryCPICH_Info },
  { &hf_ilp_cpich_Ec_N0     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_CPICH_Ec_N0 },
  { &hf_ilp_cpich_RSCP      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_CPICH_RSCP },
  { &hf_ilp_pathloss        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_Pathloss },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_fdd_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_fdd_02, T_fdd_02_sequence);

  return offset;
}



static int
dissect_ilp_CellParametersID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_ilp_TGSN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 14U, NULL, false);

  return offset;
}



static int
dissect_ilp_PrimaryCCPCH_RSCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_ilp_TimeslotISCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t TimeslotISCP_List_sequence_of[1] = {
  { &hf_ilp_TimeslotISCP_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_TimeslotISCP },
};

static int
dissect_ilp_TimeslotISCP_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_TimeslotISCP_List, TimeslotISCP_List_sequence_of,
                                                  1, maxTS, false);

  return offset;
}


static const per_sequence_t T_tdd_02_sequence[] = {
  { &hf_ilp_cellParametersID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_CellParametersID },
  { &hf_ilp_proposedTGSN    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_TGSN },
  { &hf_ilp_primaryCCPCH_RSCP, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_PrimaryCCPCH_RSCP },
  { &hf_ilp_pathloss        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_Pathloss },
  { &hf_ilp_timeslotISCP_List, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_TimeslotISCP_List },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_tdd_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_tdd_02, T_tdd_02_sequence);

  return offset;
}


static const value_string ilp_T_modeSpecificInfo_02_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_02_choice[] = {
  {   0, &hf_ilp_fdd_02          , ASN1_NO_EXTENSIONS     , dissect_ilp_T_fdd_02 },
  {   1, &hf_ilp_tdd_02          , ASN1_NO_EXTENSIONS     , dissect_ilp_T_tdd_02 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_T_modeSpecificInfo_02(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_T_modeSpecificInfo_02, T_modeSpecificInfo_02_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CellMeasuredResults_sequence[] = {
  { &hf_ilp_cellIdentity    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_268435455 },
  { &hf_ilp_modeSpecificInfo_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_T_modeSpecificInfo_02 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_CellMeasuredResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_CellMeasuredResults, CellMeasuredResults_sequence);

  return offset;
}


static const per_sequence_t CellMeasuredResultsList_sequence_of[1] = {
  { &hf_ilp_CellMeasuredResultsList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_CellMeasuredResults },
};

static int
dissect_ilp_CellMeasuredResultsList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_CellMeasuredResultsList, CellMeasuredResultsList_sequence_of,
                                                  1, maxCellMeas, false);

  return offset;
}


static const per_sequence_t MeasuredResults_sequence[] = {
  { &hf_ilp_frequencyInfo   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_FrequencyInfo },
  { &hf_ilp_utra_CarrierRSSI, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_UTRA_CarrierRSSI },
  { &hf_ilp_cellMeasuredResultsList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_CellMeasuredResultsList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_MeasuredResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_MeasuredResults, MeasuredResults_sequence);

  return offset;
}


static const per_sequence_t MeasuredResultsList_sequence_of[1] = {
  { &hf_ilp_MeasuredResultsList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_MeasuredResults },
};

static int
dissect_ilp_MeasuredResultsList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_MeasuredResultsList, MeasuredResultsList_sequence_of,
                                                  1, maxFreq, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_8191(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8191U, NULL, false);

  return offset;
}


static const value_string ilp_TAResolution_vals[] = {
  {   0, "res10chip" },
  {   1, "res05chip" },
  {   2, "res0125chip" },
  { 0, NULL }
};


static int
dissect_ilp_TAResolution(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const value_string ilp_ChipRate_vals[] = {
  {   0, "tdd128" },
  {   1, "tdd384" },
  {   2, "tdd768" },
  { 0, NULL }
};


static int
dissect_ilp_ChipRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t TimingAdvance_sequence[] = {
  { &hf_ilp_ta_01           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_8191 },
  { &hf_ilp_tAResolution    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_TAResolution },
  { &hf_ilp_chipRate        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_ChipRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_TimingAdvance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_TimingAdvance, TimingAdvance_sequence);

  return offset;
}


static const per_sequence_t WcdmaCellInformation_sequence[] = {
  { &hf_ilp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_999 },
  { &hf_ilp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_999 },
  { &hf_ilp_refUC           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_268435455 },
  { &hf_ilp_frequencyInfo   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_FrequencyInfo },
  { &hf_ilp_primaryScramblingCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_511 },
  { &hf_ilp_measuredResultsList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_MeasuredResultsList },
  { &hf_ilp_cellParametersId, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_127 },
  { &hf_ilp_timingAdvance   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_TimingAdvance },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_WcdmaCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_WcdmaCellInformation, WcdmaCellInformation_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_0_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_4194303(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4194303U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, NULL, false);

  return offset;
}


static const per_sequence_t CdmaCellInformation_sequence[] = {
  { &hf_ilp_refNID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_refSID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_32767 },
  { &hf_ilp_refBASEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_refBASELAT      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4194303 },
  { &hf_ilp_reBASELONG      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_8388607 },
  { &hf_ilp_refREFPN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_511 },
  { &hf_ilp_refWeekNumber   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_refSeconds      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4194303 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_CdmaCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_CdmaCellInformation, CdmaCellInformation_sequence);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t HrpdCellInformation_sequence[] = {
  { &hf_ilp_refSECTORID     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_BIT_STRING_SIZE_128 },
  { &hf_ilp_refBASELAT      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4194303 },
  { &hf_ilp_reBASELONG      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_8388607 },
  { &hf_ilp_refWeekNumber   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_refSeconds      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4194303 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_HrpdCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_HrpdCellInformation, HrpdCellInformation_sequence);

  return offset;
}


static const per_sequence_t UmbCellInformation_sequence[] = {
  { &hf_ilp_refSECTORID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_128 },
  { &hf_ilp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_999 },
  { &hf_ilp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_999 },
  { &hf_ilp_refBASELAT      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4194303 },
  { &hf_ilp_reBASELONG      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_8388607 },
  { &hf_ilp_refWeekNumber   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_refSeconds      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4194303 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_UmbCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_UmbCellInformation, UmbCellInformation_sequence);

  return offset;
}



static int
dissect_ilp_MCC_MNC_Digit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9U, NULL, false);

  return offset;
}


static const per_sequence_t MCC_sequence_of[1] = {
  { &hf_ilp_MCC_item        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_MCC_MNC_Digit },
};

static int
dissect_ilp_MCC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_MCC, MCC_sequence_of,
                                                  3, 3, false);

  return offset;
}


static const per_sequence_t MNC_sequence_of[1] = {
  { &hf_ilp_MNC_item        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_MCC_MNC_Digit },
};

static int
dissect_ilp_MNC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_MNC, MNC_sequence_of,
                                                  2, 3, false);

  return offset;
}


static const per_sequence_t PLMN_Identity_sequence[] = {
  { &hf_ilp_mcc             , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_MCC },
  { &hf_ilp_mnc             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_MNC },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PLMN_Identity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PLMN_Identity, PLMN_Identity_sequence);

  return offset;
}



static int
dissect_ilp_CellIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     28, 28, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t CellGlobalIdEUTRA_sequence[] = {
  { &hf_ilp_plmn_Identity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_PLMN_Identity },
  { &hf_ilp_eutra_cellIdentity, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_CellIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_CellGlobalIdEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_CellGlobalIdEUTRA, CellGlobalIdEUTRA_sequence);

  return offset;
}



static int
dissect_ilp_PhysCellId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 503U, NULL, false);

  return offset;
}



static int
dissect_ilp_TrackingAreaCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ilp_RSRP_Range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 97U, NULL, false);

  return offset;
}



static int
dissect_ilp_RSRQ_Range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 34U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_1282(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1282U, NULL, false);

  return offset;
}


static const per_sequence_t T_cgi_Info_sequence[] = {
  { &hf_ilp_cellGlobalId    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_CellGlobalIdEUTRA },
  { &hf_ilp_trackingAreaCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_TrackingAreaCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_cgi_Info(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_cgi_Info, T_cgi_Info_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_65536_262143(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            65536U, 262143U, NULL, false);

  return offset;
}



static int
dissect_ilp_RSRP_Range_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -17, -1, NULL, false);

  return offset;
}



static int
dissect_ilp_RSRQ_Range_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -30, 46U, NULL, false);

  return offset;
}



static int
dissect_ilp_RS_SINR_Range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}



static int
dissect_ilp_TrackingAreaCodeNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t NeighbourInformation5G_sequence[] = {
  { &hf_ilp_trackingAreaCode_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_TrackingAreaCodeNR },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_NeighbourInformation5G(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_NeighbourInformation5G, NeighbourInformation5G_sequence);

  return offset;
}


static const per_sequence_t T_measResult_sequence[] = {
  { &hf_ilp_rsrpResult      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_RSRP_Range },
  { &hf_ilp_rsrqResult      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_RSRQ_Range },
  { &hf_ilp_earfcn          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_earfcn_ext      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_INTEGER_65536_262143 },
  { &hf_ilp_rsrpResult_ext  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_RSRP_Range_Ext },
  { &hf_ilp_rsrqResult_ext  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_RSRQ_Range_Ext },
  { &hf_ilp_rs_sinrResult   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_RS_SINR_Range },
  { &hf_ilp_neighbourInformation5G, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_NeighbourInformation5G },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_measResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_measResult, T_measResult_sequence);

  return offset;
}


static const per_sequence_t MeasResultEUTRA_sequence[] = {
  { &hf_ilp_physCellId      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_PhysCellId },
  { &hf_ilp_cgi_Info        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_T_cgi_Info },
  { &hf_ilp_measResult      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_T_measResult },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_MeasResultEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_MeasResultEUTRA, MeasResultEUTRA_sequence);

  return offset;
}


static const per_sequence_t MeasResultListEUTRA_sequence_of[1] = {
  { &hf_ilp_MeasResultListEUTRA_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_MeasResultEUTRA },
};

static int
dissect_ilp_MeasResultListEUTRA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_MeasResultListEUTRA, MeasResultListEUTRA_sequence_of,
                                                  1, maxCellReport, false);

  return offset;
}


static const per_sequence_t ServingInformation5G_sequence[] = {
  { &hf_ilp_trackingAreaCode_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_TrackingAreaCodeNR },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_ServingInformation5G(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_ServingInformation5G, ServingInformation5G_sequence);

  return offset;
}


static const per_sequence_t LteCellInformation_sequence[] = {
  { &hf_ilp_cellGlobalIdEUTRA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_CellGlobalIdEUTRA },
  { &hf_ilp_physCellId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_PhysCellId },
  { &hf_ilp_trackingAreaCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_TrackingAreaCode },
  { &hf_ilp_rsrpResult      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_RSRP_Range },
  { &hf_ilp_rsrqResult      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_RSRQ_Range },
  { &hf_ilp_ta_02           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_1282 },
  { &hf_ilp_measResultListEUTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_MeasResultListEUTRA },
  { &hf_ilp_earfcn          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_earfcn_ext      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_INTEGER_65536_262143 },
  { &hf_ilp_rsrpResult_ext  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_RSRP_Range_Ext },
  { &hf_ilp_rsrqResult_ext  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_RSRQ_Range_Ext },
  { &hf_ilp_rs_sinrResult   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_RS_SINR_Range },
  { &hf_ilp_servingInformation5G, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_ServingInformation5G },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_LteCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_LteCellInformation, LteCellInformation_sequence);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_48(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     48, 48, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_M127_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 128U, NULL, false);

  return offset;
}


static const value_string ilp_T_apDeviceType_vals[] = {
  {   0, "wlan802-11a" },
  {   1, "wlan802-11b" },
  {   2, "wlan802-11g" },
  {   3, "wlan802-11n" },
  {   4, "wlan802-11ac" },
  {   5, "wlan802-11ad" },
  { 0, NULL }
};


static int
dissect_ilp_T_apDeviceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 3, NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_0_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 256U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_16777216(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777216U, NULL, false);

  return offset;
}


static const value_string ilp_RTDUnits_vals[] = {
  {   0, "microseconds" },
  {   1, "hundredsofnanoseconds" },
  {   2, "tensofnanoseconds" },
  {   3, "nanoseconds" },
  {   4, "tenthsofnanoseconds" },
  { 0, NULL }
};


static int
dissect_ilp_RTDUnits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t RTD_sequence[] = {
  { &hf_ilp_rTDValue        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_16777216 },
  { &hf_ilp_rTDUnits        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_RTDUnits },
  { &hf_ilp_rTDAccuracy     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_RTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_RTD, RTD_sequence);

  return offset;
}


static const value_string ilp_LocationEncodingDescriptor_vals[] = {
  {   0, "lci" },
  {   1, "asn1" },
  { 0, NULL }
};


static int
dissect_ilp_LocationEncodingDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_ilp_OCTET_STRING_SIZE_1_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 128, false, NULL);

  return offset;
}


static const per_sequence_t LocationData_sequence[] = {
  { &hf_ilp_locationAccuracy, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_4294967295 },
  { &hf_ilp_locationValue   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_OCTET_STRING_SIZE_1_128 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_LocationData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_LocationData, LocationData_sequence);

  return offset;
}


static const per_sequence_t ReportedLocation_sequence[] = {
  { &hf_ilp_locationEncodingDescriptor, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_LocationEncodingDescriptor },
  { &hf_ilp_locationData    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_LocationData },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_ReportedLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_ReportedLocation, ReportedLocation_sequence);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_30(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     30, 30, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t LocationDataLCI_sequence[] = {
  { &hf_ilp_latitudeResolution, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_6 },
  { &hf_ilp_LocationDataLCI_latitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_34 },
  { &hf_ilp_longitudeResolution, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_6 },
  { &hf_ilp_LocationDataLCI_longitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_34 },
  { &hf_ilp_altitudeType    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_4 },
  { &hf_ilp_altitudeResolution, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_6 },
  { &hf_ilp_LocationDataLCI_altitude, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_30 },
  { &hf_ilp_datum           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_LocationDataLCI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_LocationDataLCI, LocationDataLCI_sequence);

  return offset;
}


static const per_sequence_t LciLocData_sequence[] = {
  { &hf_ilp_locationDataLCI , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_LocationDataLCI },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_LciLocData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_LciLocData, LciLocData_sequence);

  return offset;
}


static const value_string ilp_RepLocation_vals[] = {
  {   0, "lciLocData" },
  { 0, NULL }
};

static const per_choice_t RepLocation_choice[] = {
  {   0, &hf_ilp_lciLocData      , ASN1_EXTENSION_ROOT    , dissect_ilp_LciLocData },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_RepLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_RepLocation, RepLocation_choice,
                                 NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_0_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, false);

  return offset;
}



static int
dissect_ilp_OCTET_STRING_SIZE_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 32, false, NULL);

  return offset;
}


static const value_string ilp_T_apPHYType_vals[] = {
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
dissect_ilp_T_apPHYType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     10, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t WlanAPInformation_sequence[] = {
  { &hf_ilp_apMACAddress    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_48 },
  { &hf_ilp_apTransmitPower , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_M127_128 },
  { &hf_ilp_apAntennaGain   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_M127_128 },
  { &hf_ilp_apSignaltoNoise , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_M127_128 },
  { &hf_ilp_apDeviceType    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_T_apDeviceType },
  { &hf_ilp_apSignalStrength, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_M127_128 },
  { &hf_ilp_apChannelFrequency, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_256 },
  { &hf_ilp_apRoundTripDelay, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_RTD },
  { &hf_ilp_setTransmitPower, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_M127_128 },
  { &hf_ilp_setAntennaGain  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_M127_128 },
  { &hf_ilp_setSignaltoNoise, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_M127_128 },
  { &hf_ilp_setSignalStrength, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_M127_128 },
  { &hf_ilp_apReportedLocation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_ReportedLocation },
  { &hf_ilp_apRepLocation   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_RepLocation },
  { &hf_ilp_apSignalStrengthDelta, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_1 },
  { &hf_ilp_apSignaltoNoiseDelta, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_1 },
  { &hf_ilp_setSignalStrengthDelta, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_1 },
  { &hf_ilp_setSignaltoNoiseDelta, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_1 },
  { &hf_ilp_operatingClass  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_255 },
  { &hf_ilp_apSSID          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_OCTET_STRING_SIZE_1_32 },
  { &hf_ilp_apPHYType       , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_T_apPHYType },
  { &hf_ilp_setMACAddress   , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_BIT_STRING_SIZE_48 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_WlanAPInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_WlanAPInformation, WlanAPInformation_sequence);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     24, 24, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t WimaxBsID_sequence[] = {
  { &hf_ilp_bsID_MSB        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_BIT_STRING_SIZE_24 },
  { &hf_ilp_bsID_LSB        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_24 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_WimaxBsID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_WimaxBsID, WimaxBsID_sequence);

  return offset;
}


static const per_sequence_t WimaxRTD_sequence[] = {
  { &hf_ilp_rtd             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_rTDstd          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_1023 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_WimaxRTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_WimaxRTD, WimaxRTD_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_M32768_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32768, 32767U, NULL, false);

  return offset;
}


static const per_sequence_t WimaxNMR_sequence[] = {
  { &hf_ilp_wimaxBsID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_WimaxBsID },
  { &hf_ilp_relDelay        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_M32768_32767 },
  { &hf_ilp_relDelaystd     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_1023 },
  { &hf_ilp_rssi            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_255 },
  { &hf_ilp_rSSIstd         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_63 },
  { &hf_ilp_bSTxPower       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_255 },
  { &hf_ilp_cinr            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_255 },
  { &hf_ilp_cINRstd         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_63 },
  { &hf_ilp_bSLocation      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_ReportedLocation },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_WimaxNMR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_WimaxNMR, WimaxNMR_sequence);

  return offset;
}


static const per_sequence_t WimaxNMRList_sequence_of[1] = {
  { &hf_ilp_WimaxNMRList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_WimaxNMR },
};

static int
dissect_ilp_WimaxNMRList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_WimaxNMRList, WimaxNMRList_sequence_of,
                                                  1, maxWimaxBSMeas, false);

  return offset;
}


static const per_sequence_t WimaxBSInformation_sequence[] = {
  { &hf_ilp_wimaxBsID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_WimaxBsID },
  { &hf_ilp_wimaxRTD        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_WimaxRTD },
  { &hf_ilp_wimaxNMRList    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_WimaxNMRList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_WimaxBSInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_WimaxBSInformation, WimaxBSInformation_sequence);

  return offset;
}



static int
dissect_ilp_PhysCellIdNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1007U, NULL, false);

  return offset;
}



static int
dissect_ilp_ARFCN_NR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3279165U, NULL, false);

  return offset;
}



static int
dissect_ilp_CellIdentityNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     36, 36, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t CellGlobalIdNR_sequence[] = {
  { &hf_ilp_plmn_Identity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_PLMN_Identity },
  { &hf_ilp_cellIdentityNR  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_CellIdentityNR },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_CellGlobalIdNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_CellGlobalIdNR, CellGlobalIdNR_sequence);

  return offset;
}


static const per_sequence_t NR_Measurements_sequence[] = {
  { &hf_ilp_rsrp_Range      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_127 },
  { &hf_ilp_rsrq_Range      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_127 },
  { &hf_ilp_sinr_Range      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_NR_Measurements(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_NR_Measurements, NR_Measurements_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_0_3846(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3846U, NULL, false);

  return offset;
}


static const per_sequence_t ServCellNR_sequence[] = {
  { &hf_ilp_physCellId_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_PhysCellIdNR },
  { &hf_ilp_arfcn_NR        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_ARFCN_NR },
  { &hf_ilp_cellGlobalId_01 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_CellGlobalIdNR },
  { &hf_ilp_trackingAreaCode_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_TrackingAreaCodeNR },
  { &hf_ilp_ssb_Measurements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_NR_Measurements },
  { &hf_ilp_csi_rs_Measurements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_NR_Measurements },
  { &hf_ilp_ta_03           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_3846 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_ServCellNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_ServCellNR, ServCellNR_sequence);

  return offset;
}


static const per_sequence_t ServingCellInformationNR_sequence_of[1] = {
  { &hf_ilp_ServingCellInformationNR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_ServCellNR },
};

static int
dissect_ilp_ServingCellInformationNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_ServingCellInformationNR, ServingCellInformationNR_sequence_of,
                                                  1, maxNRServingCell, false);

  return offset;
}


static const per_sequence_t MeasResultNR_sequence[] = {
  { &hf_ilp_physCellId_01   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_PhysCellIdNR },
  { &hf_ilp_arfcn_NR        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_ARFCN_NR },
  { &hf_ilp_cellGlobalId_01 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_CellGlobalIdNR },
  { &hf_ilp_trackingAreaCode_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_TrackingAreaCodeNR },
  { &hf_ilp_ssb_Measurements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_NR_Measurements },
  { &hf_ilp_csi_rs_Measurements, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_NR_Measurements },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_MeasResultNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_MeasResultNR, MeasResultNR_sequence);

  return offset;
}


static const per_sequence_t MeasResultListNR_sequence_of[1] = {
  { &hf_ilp_MeasResultListNR_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_MeasResultNR },
};

static int
dissect_ilp_MeasResultListNR(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_MeasResultListNR, MeasResultListNR_sequence_of,
                                                  1, maxCellReportNR, false);

  return offset;
}


static const per_sequence_t NRCellInformation_sequence[] = {
  { &hf_ilp_servingCellInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_ServingCellInformationNR },
  { &hf_ilp_measuredResultsListNR, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_MeasResultListNR },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_NRCellInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_NRCellInformation, NRCellInformation_sequence);

  return offset;
}


static const value_string ilp_CellInfo_vals[] = {
  {   0, "gsmCell" },
  {   1, "wcdmaCell" },
  {   2, "cdmaCell" },
  {   3, "hrpdCell" },
  {   4, "umbCell" },
  {   5, "lteCell" },
  {   6, "wlanAP" },
  {   7, "wimaxBS" },
  {   8, "nrCell" },
  { 0, NULL }
};

static const per_choice_t CellInfo_choice[] = {
  {   0, &hf_ilp_gsmCell         , ASN1_EXTENSION_ROOT    , dissect_ilp_GsmCellInformation },
  {   1, &hf_ilp_wcdmaCell       , ASN1_EXTENSION_ROOT    , dissect_ilp_WcdmaCellInformation },
  {   2, &hf_ilp_cdmaCell        , ASN1_EXTENSION_ROOT    , dissect_ilp_CdmaCellInformation },
  {   3, &hf_ilp_hrpdCell        , ASN1_EXTENSION_ROOT    , dissect_ilp_HrpdCellInformation },
  {   4, &hf_ilp_umbCell         , ASN1_EXTENSION_ROOT    , dissect_ilp_UmbCellInformation },
  {   5, &hf_ilp_lteCell         , ASN1_EXTENSION_ROOT    , dissect_ilp_LteCellInformation },
  {   6, &hf_ilp_wlanAP          , ASN1_EXTENSION_ROOT    , dissect_ilp_WlanAPInformation },
  {   7, &hf_ilp_wimaxBS         , ASN1_EXTENSION_ROOT    , dissect_ilp_WimaxBSInformation },
  {   8, &hf_ilp_nrCell          , ASN1_NOT_EXTENSION_ROOT, dissect_ilp_NRCellInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_CellInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_CellInfo, CellInfo_choice,
                                 NULL);

  return offset;
}


static const value_string ilp_Status_vals[] = {
  {   0, "stale" },
  {   1, "current" },
  {   2, "unknown" },
  { 0, NULL }
};


static int
dissect_ilp_Status(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t LocationId_sequence[] = {
  { &hf_ilp_cellInfo        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_CellInfo },
  { &hf_ilp_status          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_Status },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_LocationId(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_LocationId, LocationId_sequence);

  return offset;
}



static int
dissect_ilp_RelativeTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const per_sequence_t LocationIdData_sequence[] = {
  { &hf_ilp_locationId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_LocationId },
  { &hf_ilp_relativetimestamp, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_RelativeTime },
  { &hf_ilp_servingFlag     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_LocationIdData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_LocationIdData, LocationIdData_sequence);

  return offset;
}


static const per_sequence_t MultipleLocationIds_sequence_of[1] = {
  { &hf_ilp_MultipleLocationIds_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_LocationIdData },
};

static int
dissect_ilp_MultipleLocationIds(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_MultipleLocationIds, MultipleLocationIds_sequence_of,
                                                  1, maxLidSize, false);

  return offset;
}



static int
dissect_ilp_UTCTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_VisibleString(tvb, offset, actx, tree, hf_index,
                                        NO_BOUND, NO_BOUND, false,
                                        NULL);

  return offset;
}


static const value_string ilp_T_latitudeSign_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_ilp_T_latitudeSign(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_M8388608_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_180(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 180U, NULL, false);

  return offset;
}


static const per_sequence_t T_uncertainty_sequence[] = {
  { &hf_ilp_uncertaintySemiMajor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_127 },
  { &hf_ilp_uncertaintySemiMinor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_127 },
  { &hf_ilp_orientationMajorAxis, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_180 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_uncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_uncertainty, T_uncertainty_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_0_100(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 100U, NULL, false);

  return offset;
}


static const value_string ilp_T_altitudeDirection_vals[] = {
  {   0, "height" },
  {   1, "depth" },
  { 0, NULL }
};


static int
dissect_ilp_T_altitudeDirection(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t AltitudeInfo_sequence[] = {
  { &hf_ilp_altitudeDirection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_T_altitudeDirection },
  { &hf_ilp_altitude        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_32767 },
  { &hf_ilp_altUncertainty  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_AltitudeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_AltitudeInfo, AltitudeInfo_sequence);

  return offset;
}


static const per_sequence_t PositionEstimate_sequence[] = {
  { &hf_ilp_latitudeSign    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_T_latitudeSign },
  { &hf_ilp_latitude        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_8388607 },
  { &hf_ilp_longitude       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_M8388608_8388607 },
  { &hf_ilp_uncertainty     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_T_uncertainty },
  { &hf_ilp_confidence      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_100 },
  { &hf_ilp_altitudeInfo    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_AltitudeInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PositionEstimate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PositionEstimate, PositionEstimate_sequence);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_9(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     9, 9, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t Horvel_sequence[] = {
  { &hf_ilp_bearing         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_9 },
  { &hf_ilp_horspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_Horvel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_Horvel, Horvel_sequence);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 1, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t Horandvervel_sequence[] = {
  { &hf_ilp_verdirect       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_1 },
  { &hf_ilp_bearing         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_9 },
  { &hf_ilp_horspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_16 },
  { &hf_ilp_verspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_Horandvervel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_Horandvervel, Horandvervel_sequence);

  return offset;
}


static const per_sequence_t Horveluncert_sequence[] = {
  { &hf_ilp_bearing         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_9 },
  { &hf_ilp_horspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_16 },
  { &hf_ilp_uncertspeed     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_Horveluncert(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_Horveluncert, Horveluncert_sequence);

  return offset;
}


static const per_sequence_t Horandveruncert_sequence[] = {
  { &hf_ilp_verdirect       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_1 },
  { &hf_ilp_bearing         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_9 },
  { &hf_ilp_horspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_16 },
  { &hf_ilp_verspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_8 },
  { &hf_ilp_horuncertspeed  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_8 },
  { &hf_ilp_veruncertspeed  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_Horandveruncert(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_Horandveruncert, Horandveruncert_sequence);

  return offset;
}


static const value_string ilp_Velocity_vals[] = {
  {   0, "horvel" },
  {   1, "horandvervel" },
  {   2, "horveluncert" },
  {   3, "horandveruncert" },
  { 0, NULL }
};

static const per_choice_t Velocity_choice[] = {
  {   0, &hf_ilp_horvel          , ASN1_EXTENSION_ROOT    , dissect_ilp_Horvel },
  {   1, &hf_ilp_horandvervel    , ASN1_EXTENSION_ROOT    , dissect_ilp_Horandvervel },
  {   2, &hf_ilp_horveluncert    , ASN1_EXTENSION_ROOT    , dissect_ilp_Horveluncert },
  {   3, &hf_ilp_horandveruncert , ASN1_EXTENSION_ROOT    , dissect_ilp_Horandveruncert },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_Velocity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_Velocity, Velocity_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Position_sequence[] = {
  { &hf_ilp_timestamp       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_UTCTime },
  { &hf_ilp_positionEstimate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_PositionEstimate },
  { &hf_ilp_velocity        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_Velocity },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_Position(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_Position, Position_sequence);

  return offset;
}


static const value_string ilp_TriggerType_vals[] = {
  {   0, "periodic" },
  {   1, "areaEvent" },
  { 0, NULL }
};


static int
dissect_ilp_TriggerType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_1_8639999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8639999U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_2678400(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2678400U, NULL, false);

  return offset;
}


static const per_sequence_t PeriodicTriggerParams_sequence[] = {
  { &hf_ilp_numberOfFixes   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_1_8639999 },
  { &hf_ilp_intervalBetweenFixes, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_1_8639999 },
  { &hf_ilp_startTime       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_2678400 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PeriodicTriggerParams(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PeriodicTriggerParams, PeriodicTriggerParams_sequence);

  return offset;
}


static const per_sequence_t TriggerParams_sequence[] = {
  { &hf_ilp_triggerType     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_TriggerType },
  { &hf_ilp_periodicTriggerParams, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_PeriodicTriggerParams },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_TriggerParams(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_TriggerParams, TriggerParams_sequence);

  return offset;
}



static int
dissect_ilp_SPCSETKey(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t SPCTID_sequence[] = {
  { &hf_ilp_rand            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_128 },
  { &hf_ilp_slpFQDN         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_FQDN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_SPCTID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_SPCTID, SPCTID_sequence);

  return offset;
}



static int
dissect_ilp_SPCSETKeylifetime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 24U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_1_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 128U, NULL, false);

  return offset;
}


static const per_sequence_t QoP_sequence[] = {
  { &hf_ilp_horacc          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_127 },
  { &hf_ilp_veracc          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_127 },
  { &hf_ilp_maxLocAge       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_delay           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_7 },
  { &hf_ilp_ver2_responseTime, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_INTEGER_1_128 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_QoP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_QoP, QoP_sequence);

  return offset;
}


static const value_string ilp_PrefMethod_vals[] = {
  {   0, "agnssSETAssistedPreferred" },
  {   1, "agnssSETBasedPreferred" },
  {   2, "noPreference" },
  { 0, NULL }
};


static int
dissect_ilp_PrefMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PosProtocolVersion3GPP_sequence[] = {
  { &hf_ilp_majorVersionField, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_255 },
  { &hf_ilp_technicalVersionField, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_255 },
  { &hf_ilp_editorialVersionField, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PosProtocolVersion3GPP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PosProtocolVersion3GPP, PosProtocolVersion3GPP_sequence);

  return offset;
}


static const per_sequence_t Supported3GPP2PosProtocolVersion_sequence[] = {
  { &hf_ilp_revisionNumber  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_6 },
  { &hf_ilp_pointReleaseNumber, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_255 },
  { &hf_ilp_internalEditLevel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_Supported3GPP2PosProtocolVersion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_Supported3GPP2PosProtocolVersion, Supported3GPP2PosProtocolVersion_sequence);

  return offset;
}


static const per_sequence_t PosProtocolVersion3GPP2_sequence_of[1] = {
  { &hf_ilp_PosProtocolVersion3GPP2_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_Supported3GPP2PosProtocolVersion },
};

static int
dissect_ilp_PosProtocolVersion3GPP2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_PosProtocolVersion3GPP2, PosProtocolVersion3GPP2_sequence_of,
                                                  1, 8, false);

  return offset;
}


static const per_sequence_t PosProtocolVersionOMA_sequence[] = {
  { &hf_ilp_majorVersionField, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_255 },
  { &hf_ilp_minorVersionField, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PosProtocolVersionOMA(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PosProtocolVersionOMA, PosProtocolVersionOMA_sequence);

  return offset;
}


static const per_sequence_t PosProtocol_sequence[] = {
  { &hf_ilp_tia801          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_rrlp            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_rrc             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_lpp             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_posProtocolVersionRRLP, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_PosProtocolVersion3GPP },
  { &hf_ilp_posProtocolVersionRRC, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_PosProtocolVersion3GPP },
  { &hf_ilp_posProtocolVersionTIA801, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_PosProtocolVersion3GPP2 },
  { &hf_ilp_posProtocolVersionLPP, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_PosProtocolVersion3GPP },
  { &hf_ilp_lppe            , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_BOOLEAN },
  { &hf_ilp_posProtocolVersionLPPe, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_PosProtocolVersionOMA },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PosProtocol(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PosProtocol, PosProtocol_sequence);

  return offset;
}


static const per_sequence_t SupportedBearers_sequence[] = {
  { &hf_ilp_gsm             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_wcdma           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_lte             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_cdma            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_hprd            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_umb             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_wlan            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_wiMAX           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_nr              , ASN1_NOT_EXTENSION_ROOT, ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_SupportedBearers(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_SupportedBearers, SupportedBearers_sequence);

  return offset;
}


static const per_sequence_t SETCapabilities_sequence[] = {
  { &hf_ilp_posTechnology   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_PosTechnology },
  { &hf_ilp_prefMethod      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_PrefMethod },
  { &hf_ilp_posProtocol     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_PosProtocol },
  { &hf_ilp_supportedBearers, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_SupportedBearers },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_SETCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_SETCapabilities, SETCapabilities_sequence);

  return offset;
}


static const value_string ilp_NotificationMode_vals[] = {
  {   0, "normal" },
  {   1, "basedOnLocation" },
  { 0, NULL }
};


static int
dissect_ilp_NotificationMode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PREQ_sequence[] = {
  { &hf_ilp_sLPMode         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_SLPMode },
  { &hf_ilp_approvedPosMethods, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_PosTechnology },
  { &hf_ilp_locationId      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_LocationId },
  { &hf_ilp_multipleLocationIds, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_MultipleLocationIds },
  { &hf_ilp_position        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_Position },
  { &hf_ilp_triggerParams   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_TriggerParams },
  { &hf_ilp_sPCSETKey       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_SPCSETKey },
  { &hf_ilp_spctid          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_SPCTID },
  { &hf_ilp_sPCSETKeylifetime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_SPCSETKeylifetime },
  { &hf_ilp_qoP             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_QoP },
  { &hf_ilp_sETCapabilities , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_SETCapabilities },
  { &hf_ilp_notificationMode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_NotificationMode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PREQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PREQ, PREQ_sequence);

  return offset;
}


static const value_string ilp_PosMethod_vals[] = {
  {   0, "agpsSETassisted" },
  {   1, "agpsSETbased" },
  {   2, "agpsSETassistedpref" },
  {   3, "agpsSETbasedpref" },
  {   4, "autonomousGPS" },
  {   5, "aflt" },
  {   6, "ecid" },
  {   7, "eotd" },
  {   8, "otdoa" },
  {   9, "agnssSETassisted" },
  {  10, "agnssSETbased" },
  {  11, "agnssSETassistedpref" },
  {  12, "agnssSETbasedpref" },
  {  13, "autonomousGNSS" },
  {  14, "ver2-mbs" },
  { 0, NULL }
};


static int
dissect_ilp_PosMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, true, 1, NULL);

  return offset;
}


static const per_sequence_t GNSSPosTechnology_sequence[] = {
  { &hf_ilp_gps             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_galileo         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_sbas            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_modernized_gps  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_qzss            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_glonass         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_bds             , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_GNSSPosTechnology(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_GNSSPosTechnology, GNSSPosTechnology_sequence);

  return offset;
}


static const value_string ilp_SPCStatusCode_vals[] = {
  {   0, "operational" },
  {   1, "notOperational" },
  {   2, "reducedAvailability" },
  { 0, NULL }
};


static int
dissect_ilp_SPCStatusCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PRES_sequence[] = {
  { &hf_ilp_preferredPosMethod, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_PosMethod },
  { &hf_ilp_gnssPosTechnology, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_GNSSPosTechnology },
  { &hf_ilp_supportedPosMethods, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_PosTechnology },
  { &hf_ilp_position        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_Position },
  { &hf_ilp_sPCstatusCode   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_SPCStatusCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PRES(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PRES, PRES_sequence);

  return offset;
}


static const value_string ilp_StatusCode_vals[] = {
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
  {  16, "iLPTimeout" },
  { 0, NULL }
};


static int
dissect_ilp_StatusCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     17, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PRPT_sequence[] = {
  { &hf_ilp_position        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_Position },
  { &hf_ilp_fixNumber       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_1_8639999 },
  { &hf_ilp_statusCode      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_StatusCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PRPT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PRPT, PRPT_sequence);

  return offset;
}


static const per_sequence_t PLREQ_sequence[] = {
  { &hf_ilp_locationId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_LocationId },
  { &hf_ilp_multipleLocationIds, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_MultipleLocationIds },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PLREQ(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PLREQ, PLREQ_sequence);

  return offset;
}


static const value_string ilp_PositionResult_vals[] = {
  {   0, "position" },
  {   1, "statusCode" },
  { 0, NULL }
};

static const per_choice_t PositionResult_choice[] = {
  {   0, &hf_ilp_position        , ASN1_EXTENSION_ROOT    , dissect_ilp_Position },
  {   1, &hf_ilp_statusCode      , ASN1_EXTENSION_ROOT    , dissect_ilp_StatusCode },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_PositionResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_PositionResult, PositionResult_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PositionResults_sequence_of[1] = {
  { &hf_ilp_PositionResults_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_PositionResult },
};

static int
dissect_ilp_PositionResults(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_PositionResults, PositionResults_sequence_of,
                                                  1, maxPosSize, false);

  return offset;
}


static const per_sequence_t PLRES_sequence[] = {
  { &hf_ilp_positionResults , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_PositionResults },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PLRES(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PLRES, PLRES_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_0_167(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 167U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 10U, NULL, false);

  return offset;
}


static const per_sequence_t SatelliteInfoElement_sequence[] = {
  { &hf_ilp_satId           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_63 },
  { &hf_ilp_iode            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_SatelliteInfoElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_SatelliteInfoElement, SatelliteInfoElement_sequence);

  return offset;
}


static const per_sequence_t SatelliteInfo_sequence_of[1] = {
  { &hf_ilp_SatelliteInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_SatelliteInfoElement },
};

static int
dissect_ilp_SatelliteInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_SatelliteInfo, SatelliteInfo_sequence_of,
                                                  1, 31, false);

  return offset;
}


static const per_sequence_t NavigationModel_sequence[] = {
  { &hf_ilp_gpsWeek         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_1023 },
  { &hf_ilp_gpsToe          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_167 },
  { &hf_ilp_nsat            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_31 },
  { &hf_ilp_toeLimit        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_10 },
  { &hf_ilp_satInfo         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_SatelliteInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_NavigationModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_NavigationModel, NavigationModel_sequence);

  return offset;
}


static const per_sequence_t GanssRequestedCommonAssistanceDataList_sequence[] = {
  { &hf_ilp_ganssReferenceTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_ganssIonosphericModel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_ganssAdditionalIonosphericModelForDataID00, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_ganssAdditionalIonosphericModelForDataID11, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_ganssEarthOrientationParameters, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_ganssAdditionalIonosphericModelForDataID01, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_GanssRequestedCommonAssistanceDataList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_GanssRequestedCommonAssistanceDataList, GanssRequestedCommonAssistanceDataList_sequence);

  return offset;
}



static int
dissect_ilp_DGANSS_Sig_Id_Req(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_0_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}


static const per_sequence_t SatellitesListRelatedData_sequence[] = {
  { &hf_ilp_satId           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_63 },
  { &hf_ilp_iod             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_1023 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_SatellitesListRelatedData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_SatellitesListRelatedData, SatellitesListRelatedData_sequence);

  return offset;
}


static const per_sequence_t SatellitesListRelatedDataList_sequence_of[1] = {
  { &hf_ilp_SatellitesListRelatedDataList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_SatellitesListRelatedData },
};

static int
dissect_ilp_SatellitesListRelatedDataList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_SatellitesListRelatedDataList, SatellitesListRelatedDataList_sequence_of,
                                                  0, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t GanssNavigationModelData_sequence[] = {
  { &hf_ilp_ganssWeek       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4095 },
  { &hf_ilp_ganssToe        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_167 },
  { &hf_ilp_t_toeLimit      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_10 },
  { &hf_ilp_satellitesListRelatedDataList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_SatellitesListRelatedDataList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_GanssNavigationModelData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_GanssNavigationModelData, GanssNavigationModelData_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_0_59(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, false);

  return offset;
}


static const per_sequence_t T_ganssDataBitSatList_sequence_of[1] = {
  { &hf_ilp_ganssDataBitSatList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_63 },
};

static int
dissect_ilp_T_ganssDataBitSatList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_T_ganssDataBitSatList, T_ganssDataBitSatList_sequence_of,
                                                  1, maxGANSSSat, false);

  return offset;
}


static const per_sequence_t ReqDataBitAssistanceList_sequence[] = {
  { &hf_ilp_gnssSignals     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_GANSSSignals },
  { &hf_ilp_ganssDataBitInterval, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_15 },
  { &hf_ilp_ganssDataBitSatList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_T_ganssDataBitSatList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_ReqDataBitAssistanceList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_ReqDataBitAssistanceList, ReqDataBitAssistanceList_sequence);

  return offset;
}


static const per_sequence_t GanssDataBits_sequence[] = {
  { &hf_ilp_ganssTODmin     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_59 },
  { &hf_ilp_reqDataBitAssistanceList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_ReqDataBitAssistanceList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_GanssDataBits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_GanssDataBits, GanssDataBits_sequence);

  return offset;
}


static const per_sequence_t GanssAdditionalDataChoices_sequence[] = {
  { &hf_ilp_orbitModelID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_7 },
  { &hf_ilp_clockModelID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_7 },
  { &hf_ilp_utcModelID      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_7 },
  { &hf_ilp_almanacModelID  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_GanssAdditionalDataChoices(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_GanssAdditionalDataChoices, GanssAdditionalDataChoices_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_1_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 256U, NULL, false);

  return offset;
}


static const per_sequence_t ExtendedEphemeris_sequence[] = {
  { &hf_ilp_validity        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_1_256 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_ExtendedEphemeris(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_ExtendedEphemeris, ExtendedEphemeris_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_0_23(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 23U, NULL, false);

  return offset;
}


static const per_sequence_t GANSSextEphTime_sequence[] = {
  { &hf_ilp_gANSSday        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_8191 },
  { &hf_ilp_gANSSTODhour    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_23 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_GANSSextEphTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_GANSSextEphTime, GANSSextEphTime_sequence);

  return offset;
}


static const per_sequence_t GanssExtendedEphCheck_sequence[] = {
  { &hf_ilp_beginTime_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_GANSSextEphTime },
  { &hf_ilp_endTime_01      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_GANSSextEphTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_GanssExtendedEphCheck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_GanssExtendedEphCheck, GanssExtendedEphCheck_sequence);

  return offset;
}



static int
dissect_ilp_BDS_Sig_Id_Req(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GanssReqGenericData_sequence[] = {
  { &hf_ilp_ganssId         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_15 },
  { &hf_ilp_ganssSBASid     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_BIT_STRING_SIZE_3 },
  { &hf_ilp_ganssRealTimeIntegrity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_BOOLEAN },
  { &hf_ilp_ganssDifferentialCorrection, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_DGANSS_Sig_Id_Req },
  { &hf_ilp_ganssAlmanac    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_ganssNavigationModelData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_GanssNavigationModelData },
  { &hf_ilp_ganssTimeModels , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_BIT_STRING_SIZE_16 },
  { &hf_ilp_ganssReferenceMeasurementInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_ganssDataBits   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_GanssDataBits },
  { &hf_ilp_ganssUTCModel   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_ganssAdditionalDataChoices, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_GanssAdditionalDataChoices },
  { &hf_ilp_ganssAuxiliaryInformation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_ganssExtendedEphemeris, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_ExtendedEphemeris },
  { &hf_ilp_ganssExtendedEphemerisCheck, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_GanssExtendedEphCheck },
  { &hf_ilp_bds_DifferentialCorrection, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_BDS_Sig_Id_Req },
  { &hf_ilp_bds_GridModelReq, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_GanssReqGenericData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_GanssReqGenericData, GanssReqGenericData_sequence);

  return offset;
}


static const per_sequence_t GanssRequestedGenericAssistanceDataList_sequence_of[1] = {
  { &hf_ilp_GanssRequestedGenericAssistanceDataList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_GanssReqGenericData },
};

static int
dissect_ilp_GanssRequestedGenericAssistanceDataList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_GanssRequestedGenericAssistanceDataList, GanssRequestedGenericAssistanceDataList_sequence_of,
                                                  1, maxGANSS, false);

  return offset;
}


static const per_sequence_t GPSTime_sequence[] = {
  { &hf_ilp_gPSWeek         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_1023 },
  { &hf_ilp_gPSTOWhour      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_167 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_GPSTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_GPSTime, GPSTime_sequence);

  return offset;
}


static const per_sequence_t ExtendedEphCheck_sequence[] = {
  { &hf_ilp_beginTime       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_GPSTime },
  { &hf_ilp_endTime         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_GPSTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_ExtendedEphCheck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_ExtendedEphCheck, ExtendedEphCheck_sequence);

  return offset;
}


static const per_sequence_t RequestedAssistData_sequence[] = {
  { &hf_ilp_almanacRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_utcModelRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_ionosphericModelRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_dgpsCorrectionsRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_referenceLocationRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_referenceTimeRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_acquisitionAssistanceRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_realTimeIntegrityRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_navigationModelRequested, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_navigationModelData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_NavigationModel },
  { &hf_ilp_ganssRequestedCommonAssistanceDataList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_GanssRequestedCommonAssistanceDataList },
  { &hf_ilp_ganssRequestedGenericAssistanceDataList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_GanssRequestedGenericAssistanceDataList },
  { &hf_ilp_extendedEphemeris, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_ExtendedEphemeris },
  { &hf_ilp_extendedEphemerisCheck, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_ExtendedEphCheck },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_RequestedAssistData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_RequestedAssistData, RequestedAssistData_sequence);

  return offset;
}



static int
dissect_ilp_OCTET_STRING_SIZE_1_8192(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 8192, false, NULL);

  return offset;
}



static int
dissect_ilp_T_rrlpPayload(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *rrlp_tvb;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 8192, false, &rrlp_tvb);


  if (rrlp_tvb && rrlp_handle) {
    call_dissector(rrlp_handle, rrlp_tvb, actx->pinfo, tree);
  }


  return offset;
}



static int
dissect_ilp_T_lPPPayload_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *lpp_tvb;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 60000, false, &lpp_tvb);


  if (lpp_tvb && lpp_handle) {
    call_dissector(lpp_handle, lpp_tvb, actx->pinfo, tree);
  }


  return offset;
}


static const per_sequence_t T_lPPPayload_sequence_of[1] = {
  { &hf_ilp_lPPPayload_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_T_lPPPayload_item },
};

static int
dissect_ilp_T_lPPPayload(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_T_lPPPayload, T_lPPPayload_sequence_of,
                                                  1, 3, false);

  return offset;
}



static int
dissect_ilp_OCTET_STRING_SIZE_1_60000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 60000, false, NULL);

  return offset;
}


static const per_sequence_t T_tia801Payload_sequence_of[1] = {
  { &hf_ilp_tia801Payload_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_OCTET_STRING_SIZE_1_60000 },
};

static int
dissect_ilp_T_tia801Payload(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_T_tia801Payload, T_tia801Payload_sequence_of,
                                                  1, 3, false);

  return offset;
}


static const per_sequence_t MultiPosPayLoad_sequence[] = {
  { &hf_ilp_lPPPayload      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_T_lPPPayload },
  { &hf_ilp_tia801Payload   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_T_tia801Payload },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_MultiPosPayLoad(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_MultiPosPayLoad, MultiPosPayLoad_sequence);

  return offset;
}


static const value_string ilp_PosPayLoad_vals[] = {
  {   0, "rrcPayload" },
  {   1, "rrlpPayload" },
  {   2, "multiPosPayload" },
  { 0, NULL }
};

static const per_choice_t PosPayLoad_choice[] = {
  {   0, &hf_ilp_rrcPayload      , ASN1_EXTENSION_ROOT    , dissect_ilp_OCTET_STRING_SIZE_1_8192 },
  {   1, &hf_ilp_rrlpPayload     , ASN1_EXTENSION_ROOT    , dissect_ilp_T_rrlpPayload },
  {   2, &hf_ilp_multiPosPayload , ASN1_EXTENSION_ROOT    , dissect_ilp_MultiPosPayLoad },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_PosPayLoad(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_PosPayLoad, PosPayLoad_choice,
                                 NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_0_16383(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, false);

  return offset;
}


static const per_sequence_t T_set_GPSTimingOfCell_sequence[] = {
  { &hf_ilp_ms_part         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_16383 },
  { &hf_ilp_ls_part         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_set_GPSTimingOfCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_set_GPSTimingOfCell, T_set_GPSTimingOfCell_sequence);

  return offset;
}


static const per_sequence_t T_fdd_sequence[] = {
  { &hf_ilp_referenceIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_PrimaryCPICH_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_fdd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_fdd, T_fdd_sequence);

  return offset;
}


static const per_sequence_t T_tdd_sequence[] = {
  { &hf_ilp_referenceIdentity_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_CellParametersID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_tdd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_tdd, T_tdd_sequence);

  return offset;
}


static const value_string ilp_T_modeSpecificInfo_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_choice[] = {
  {   0, &hf_ilp_fdd             , ASN1_NO_EXTENSIONS     , dissect_ilp_T_fdd },
  {   1, &hf_ilp_tdd             , ASN1_NO_EXTENSIONS     , dissect_ilp_T_tdd },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_T_modeSpecificInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_T_modeSpecificInfo, T_modeSpecificInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UTRAN_GPSReferenceTimeResult_sequence[] = {
  { &hf_ilp_set_GPSTimingOfCell, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_T_set_GPSTimingOfCell },
  { &hf_ilp_modeSpecificInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_T_modeSpecificInfo },
  { &hf_ilp_sfn             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4095 },
  { &hf_ilp_gpsReferenceTimeUncertainty, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_UTRAN_GPSReferenceTimeResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_UTRAN_GPSReferenceTimeResult, UTRAN_GPSReferenceTimeResult_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_0_80(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 80U, NULL, false);

  return offset;
}


static const per_sequence_t T_set_GANSSTimingOfCell_sequence[] = {
  { &hf_ilp_ms_part_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_80 },
  { &hf_ilp_ls_part         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_set_GANSSTimingOfCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_set_GANSSTimingOfCell, T_set_GANSSTimingOfCell_sequence);

  return offset;
}


static const per_sequence_t T_fdd_01_sequence[] = {
  { &hf_ilp_referenceIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_PrimaryCPICH_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_fdd_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_fdd_01, T_fdd_01_sequence);

  return offset;
}


static const per_sequence_t T_tdd_01_sequence[] = {
  { &hf_ilp_referenceIdentity_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_CellParametersID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_tdd_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_tdd_01, T_tdd_01_sequence);

  return offset;
}


static const value_string ilp_T_modeSpecificInfo_01_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_01_choice[] = {
  {   0, &hf_ilp_fdd_01          , ASN1_NO_EXTENSIONS     , dissect_ilp_T_fdd_01 },
  {   1, &hf_ilp_tdd_01          , ASN1_NO_EXTENSIONS     , dissect_ilp_T_tdd_01 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_T_modeSpecificInfo_01(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_T_modeSpecificInfo_01, T_modeSpecificInfo_01_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SET_GANSSReferenceTime_sequence[] = {
  { &hf_ilp_set_GANSSTimingOfCell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_T_set_GANSSTimingOfCell },
  { &hf_ilp_modeSpecificInfo_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_T_modeSpecificInfo_01 },
  { &hf_ilp_sfn             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4095 },
  { &hf_ilp_ganss_TODUncertainty, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_SET_GANSSReferenceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_SET_GANSSReferenceTime, SET_GANSSReferenceTime_sequence);

  return offset;
}


static const per_sequence_t UTRAN_GANSSReferenceTimeResult_sequence[] = {
  { &hf_ilp_ganssTimeID     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_15 },
  { &hf_ilp_set_GANSSReferenceTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_SET_GANSSReferenceTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_UTRAN_GANSSReferenceTimeResult(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_UTRAN_GANSSReferenceTimeResult, UTRAN_GANSSReferenceTimeResult_sequence);

  return offset;
}


static const per_sequence_t PINIT_sequence[] = {
  { &hf_ilp_sETCapabilities , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_SETCapabilities },
  { &hf_ilp_locationId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_LocationId },
  { &hf_ilp_posMethod       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_PosMethod },
  { &hf_ilp_requestedAssistData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_RequestedAssistData },
  { &hf_ilp_position        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_Position },
  { &hf_ilp_posPayLoad      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_PosPayLoad },
  { &hf_ilp_multipleLocationIds, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_MultipleLocationIds },
  { &hf_ilp_utran_GPSReferenceTimeResult, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_UTRAN_GPSReferenceTimeResult },
  { &hf_ilp_utran_GANSSReferenceTimeResult, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_UTRAN_GANSSReferenceTimeResult },
  { &hf_ilp_gnssPosTechnology, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_GNSSPosTechnology },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PINIT(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PINIT, PINIT_sequence);

  return offset;
}


static const per_sequence_t PAUTH_sequence[] = {
  { &hf_ilp_sPCSETKey       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_SPCSETKey },
  { &hf_ilp_spctid          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_SPCTID },
  { &hf_ilp_sPCSETKeylifetime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_SPCSETKeylifetime },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PAUTH(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PAUTH, PAUTH_sequence);

  return offset;
}


static const per_sequence_t PALIVE_sequence[] = {
  { &hf_ilp_sPCStatusCode   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_SPCStatusCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PALIVE(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PALIVE, PALIVE_sequence);

  return offset;
}


static const per_sequence_t PEND_sequence[] = {
  { &hf_ilp_position        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_Position },
  { &hf_ilp_statusCode      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_StatusCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PEND(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PEND, PEND_sequence);

  return offset;
}


static const per_sequence_t T_utran_GPSTimingOfCell_sequence[] = {
  { &hf_ilp_ms_part_02      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_1023 },
  { &hf_ilp_ls_part         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4294967295 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_utran_GPSTimingOfCell(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_utran_GPSTimingOfCell, T_utran_GPSTimingOfCell_sequence);

  return offset;
}


static const per_sequence_t T_fdd_03_sequence[] = {
  { &hf_ilp_referenceIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_PrimaryCPICH_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_fdd_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_fdd_03, T_fdd_03_sequence);

  return offset;
}


static const per_sequence_t T_tdd_03_sequence[] = {
  { &hf_ilp_referenceIdentity_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_CellParametersID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_tdd_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_tdd_03, T_tdd_03_sequence);

  return offset;
}


static const value_string ilp_T_modeSpecificInfo_03_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_03_choice[] = {
  {   0, &hf_ilp_fdd_03          , ASN1_NO_EXTENSIONS     , dissect_ilp_T_fdd_03 },
  {   1, &hf_ilp_tdd_03          , ASN1_NO_EXTENSIONS     , dissect_ilp_T_tdd_03 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_T_modeSpecificInfo_03(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_T_modeSpecificInfo_03, T_modeSpecificInfo_03_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UTRAN_GPSReferenceTime_sequence[] = {
  { &hf_ilp_utran_GPSTimingOfCell, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_T_utran_GPSTimingOfCell },
  { &hf_ilp_modeSpecificInfo_03, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_T_modeSpecificInfo_03 },
  { &hf_ilp_sfn             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4095 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_UTRAN_GPSReferenceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_UTRAN_GPSReferenceTime, UTRAN_GPSReferenceTime_sequence);

  return offset;
}


static const value_string ilp_UTRANGPSDriftRate_vals[] = {
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
dissect_ilp_UTRANGPSDriftRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     15, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t UTRAN_GPSReferenceTimeAssistance_sequence[] = {
  { &hf_ilp_utran_GPSReferenceTime, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_UTRAN_GPSReferenceTime },
  { &hf_ilp_gpsReferenceTimeUncertainty, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_127 },
  { &hf_ilp_utranGPSDriftRate, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_UTRANGPSDriftRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_UTRAN_GPSReferenceTimeAssistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_UTRAN_GPSReferenceTimeAssistance, UTRAN_GPSReferenceTimeAssistance_sequence);

  return offset;
}



static int
dissect_ilp_INTEGER_0_86399(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 86399U, NULL, false);

  return offset;
}



static int
dissect_ilp_INTEGER_0_3999999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3999999U, NULL, false);

  return offset;
}


static const per_sequence_t T_fdd_04_sequence[] = {
  { &hf_ilp_referenceIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_PrimaryCPICH_Info },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_fdd_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_fdd_04, T_fdd_04_sequence);

  return offset;
}


static const per_sequence_t T_tdd_04_sequence[] = {
  { &hf_ilp_referenceIdentity_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_CellParametersID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_T_tdd_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_T_tdd_04, T_tdd_04_sequence);

  return offset;
}


static const value_string ilp_T_modeSpecificInfo_04_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_04_choice[] = {
  {   0, &hf_ilp_fdd_04          , ASN1_NO_EXTENSIONS     , dissect_ilp_T_fdd_04 },
  {   1, &hf_ilp_tdd_04          , ASN1_NO_EXTENSIONS     , dissect_ilp_T_tdd_04 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_T_modeSpecificInfo_04(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_T_modeSpecificInfo_04, T_modeSpecificInfo_04_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t UTRAN_GANSSReferenceTime_sequence[] = {
  { &hf_ilp_ganssTOD        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_86399 },
  { &hf_ilp_utran_GANSSTimingOfCell, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_3999999 },
  { &hf_ilp_modeSpecificInfo_04, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_T_modeSpecificInfo_04 },
  { &hf_ilp_sfn             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_4095 },
  { &hf_ilp_ganss_TODUncertainty, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_UTRAN_GANSSReferenceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_UTRAN_GANSSReferenceTime, UTRAN_GANSSReferenceTime_sequence);

  return offset;
}


static const value_string ilp_UTRANGANSSDriftRate_vals[] = {
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
dissect_ilp_UTRANGANSSDriftRate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     15, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t UTRAN_GANSSReferenceTimeAssistance_sequence[] = {
  { &hf_ilp_ganssTimeID     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_15 },
  { &hf_ilp_utran_GANSSReferenceTime, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_UTRAN_GANSSReferenceTime },
  { &hf_ilp_ganssDay        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_8191 },
  { &hf_ilp_utranGANSSDriftRate, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_UTRANGANSSDriftRate },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_UTRAN_GANSSReferenceTimeAssistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_UTRAN_GANSSReferenceTimeAssistance, UTRAN_GANSSReferenceTimeAssistance_sequence);

  return offset;
}


static const per_sequence_t PMESS_sequence[] = {
  { &hf_ilp_posPayLoad      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_PosPayLoad },
  { &hf_ilp_velocity        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_Velocity },
  { &hf_ilp_utran_GPSReferenceTimeAssistance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_UTRAN_GPSReferenceTimeAssistance },
  { &hf_ilp_utran_GPSReferenceTimeResult, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_UTRAN_GPSReferenceTimeResult },
  { &hf_ilp_utran_GANSSReferenceTimeAssistance, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_UTRAN_GANSSReferenceTimeAssistance },
  { &hf_ilp_utran_GANSSReferenceTimeResult, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_UTRAN_GANSSReferenceTimeResult },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_PMESS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ilp_PMESS, PMESS_sequence);

  return offset;
}


static const value_string ilp_IlpMessage_vals[] = {
  {   0, "msPREQ" },
  {   1, "msPRES" },
  {   2, "msPRPT" },
  {   3, "msPLREQ" },
  {   4, "msPLRES" },
  {   5, "msPINIT" },
  {   6, "msPAUTH" },
  {   7, "msPALIVE" },
  {   8, "msPEND" },
  {   9, "msPMESS" },
  { 0, NULL }
};

static const per_choice_t IlpMessage_choice[] = {
  {   0, &hf_ilp_msPREQ          , ASN1_EXTENSION_ROOT    , dissect_ilp_PREQ },
  {   1, &hf_ilp_msPRES          , ASN1_EXTENSION_ROOT    , dissect_ilp_PRES },
  {   2, &hf_ilp_msPRPT          , ASN1_EXTENSION_ROOT    , dissect_ilp_PRPT },
  {   3, &hf_ilp_msPLREQ         , ASN1_EXTENSION_ROOT    , dissect_ilp_PLREQ },
  {   4, &hf_ilp_msPLRES         , ASN1_EXTENSION_ROOT    , dissect_ilp_PLRES },
  {   5, &hf_ilp_msPINIT         , ASN1_EXTENSION_ROOT    , dissect_ilp_PINIT },
  {   6, &hf_ilp_msPAUTH         , ASN1_EXTENSION_ROOT    , dissect_ilp_PAUTH },
  {   7, &hf_ilp_msPALIVE        , ASN1_EXTENSION_ROOT    , dissect_ilp_PALIVE },
  {   8, &hf_ilp_msPEND          , ASN1_EXTENSION_ROOT    , dissect_ilp_PEND },
  {   9, &hf_ilp_msPMESS         , ASN1_EXTENSION_ROOT    , dissect_ilp_PMESS },
  { 0, NULL, 0, NULL }
};

static int
dissect_ilp_IlpMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

uint32_t IlpMessage;

    offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_IlpMessage, IlpMessage_choice,
                                 &IlpMessage);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s ", val_to_str_const(IlpMessage,ilp_IlpMessage_vals,"Unknown"));


  return offset;
}


static const per_sequence_t ILP_PDU_sequence[] = {
  { &hf_ilp_length          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_version         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_Version },
  { &hf_ilp_sessionID2      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_SessionID2 },
  { &hf_ilp_message         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_IlpMessage },
  { NULL, 0, 0, NULL }
};

static int
dissect_ilp_ILP_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  proto_item *it;
  proto_tree *ilp_tree;

  it = proto_tree_add_item(tree, proto_ilp, tvb, 0, -1, ENC_NA);
  ilp_tree = proto_item_add_subtree(it, ett_ilp);

  col_set_str(actx->pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear(actx->pinfo->cinfo, COL_INFO);
  offset = dissect_per_sequence(tvb, offset, actx, ilp_tree, hf_index,
                                   ett_ilp_ILP_PDU, ILP_PDU_sequence);


  return offset;
}

/*--- PDUs ---*/

static int dissect_ILP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, false, pinfo);
  offset = dissect_ilp_ILP_PDU(tvb, offset, &asn1_ctx, tree, hf_ilp_ILP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}



static unsigned
get_ilp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_)
{
  /* PDU length = Message length */
  return tvb_get_ntohs(tvb,offset);
}

static int
dissect_ilp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
  tcp_dissect_pdus(tvb, pinfo, tree, ilp_desegment, ILP_HEADER_SIZE,
                   get_ilp_pdu_len, dissect_ILP_PDU_PDU, data);
  return tvb_captured_length(tvb);
}

void proto_reg_handoff_ilp(void);

/*--- proto_register_ilp -------------------------------------------*/
void proto_register_ilp(void) {

  /* List of fields */
  static hf_register_info hf[] = {

    { &hf_ilp_ILP_PDU_PDU,
      { "ILP-PDU", "ilp.ILP_PDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_length,
      { "length", "ilp.length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ilp_version,
      { "version", "ilp.version_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_sessionID2,
      { "sessionID2", "ilp.sessionID2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_message,
      { "message", "ilp.message",
        FT_UINT32, BASE_DEC, VALS(ilp_IlpMessage_vals), 0,
        "IlpMessage", HFILL }},
    { &hf_ilp_msPREQ,
      { "msPREQ", "ilp.msPREQ_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PREQ", HFILL }},
    { &hf_ilp_msPRES,
      { "msPRES", "ilp.msPRES_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PRES", HFILL }},
    { &hf_ilp_msPRPT,
      { "msPRPT", "ilp.msPRPT_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PRPT", HFILL }},
    { &hf_ilp_msPLREQ,
      { "msPLREQ", "ilp.msPLREQ_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PLREQ", HFILL }},
    { &hf_ilp_msPLRES,
      { "msPLRES", "ilp.msPLRES_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PLRES", HFILL }},
    { &hf_ilp_msPINIT,
      { "msPINIT", "ilp.msPINIT_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PINIT", HFILL }},
    { &hf_ilp_msPAUTH,
      { "msPAUTH", "ilp.msPAUTH_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PAUTH", HFILL }},
    { &hf_ilp_msPALIVE,
      { "msPALIVE", "ilp.msPALIVE_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PALIVE", HFILL }},
    { &hf_ilp_msPEND,
      { "msPEND", "ilp.msPEND_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PEND", HFILL }},
    { &hf_ilp_msPMESS,
      { "msPMESS", "ilp.msPMESS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PMESS", HFILL }},
    { &hf_ilp_sLPMode,
      { "sLPMode", "ilp.sLPMode",
        FT_UINT32, BASE_DEC, VALS(ilp_SLPMode_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_approvedPosMethods,
      { "approvedPosMethods", "ilp.approvedPosMethods_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosTechnology", HFILL }},
    { &hf_ilp_locationId,
      { "locationId", "ilp.locationId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_multipleLocationIds,
      { "multipleLocationIds", "ilp.multipleLocationIds",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_position,
      { "position", "ilp.position_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_triggerParams,
      { "triggerParams", "ilp.triggerParams_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_sPCSETKey,
      { "sPCSETKey", "ilp.sPCSETKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_spctid,
      { "spctid", "ilp.spctid_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_sPCSETKeylifetime,
      { "sPCSETKeylifetime", "ilp.sPCSETKeylifetime",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_qoP,
      { "qoP", "ilp.qoP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_sETCapabilities,
      { "sETCapabilities", "ilp.sETCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_notificationMode,
      { "notificationMode", "ilp.notificationMode",
        FT_UINT32, BASE_DEC, VALS(ilp_NotificationMode_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_triggerType,
      { "triggerType", "ilp.triggerType",
        FT_UINT32, BASE_DEC, VALS(ilp_TriggerType_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_periodicTriggerParams,
      { "periodicTriggerParams", "ilp.periodicTriggerParams_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_numberOfFixes,
      { "numberOfFixes", "ilp.numberOfFixes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8639999", HFILL }},
    { &hf_ilp_intervalBetweenFixes,
      { "intervalBetweenFixes", "ilp.intervalBetweenFixes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8639999", HFILL }},
    { &hf_ilp_startTime,
      { "startTime", "ilp.startTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2678400", HFILL }},
    { &hf_ilp_preferredPosMethod,
      { "preferredPosMethod", "ilp.preferredPosMethod",
        FT_UINT32, BASE_DEC, VALS(ilp_PosMethod_vals), 0,
        "PosMethod", HFILL }},
    { &hf_ilp_gnssPosTechnology,
      { "gnssPosTechnology", "ilp.gnssPosTechnology_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_supportedPosMethods,
      { "supportedPosMethods", "ilp.supportedPosMethods_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosTechnology", HFILL }},
    { &hf_ilp_sPCstatusCode,
      { "sPCstatusCode", "ilp.sPCstatusCode",
        FT_UINT32, BASE_DEC, VALS(ilp_SPCStatusCode_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_fixNumber,
      { "fixNumber", "ilp.fixNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8639999", HFILL }},
    { &hf_ilp_statusCode,
      { "statusCode", "ilp.statusCode",
        FT_UINT32, BASE_DEC, VALS(ilp_StatusCode_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_positionResults,
      { "positionResults", "ilp.positionResults",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_PositionResults_item,
      { "PositionResult", "ilp.PositionResult",
        FT_UINT32, BASE_DEC, VALS(ilp_PositionResult_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_posMethod,
      { "posMethod", "ilp.posMethod",
        FT_UINT32, BASE_DEC, VALS(ilp_PosMethod_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_requestedAssistData,
      { "requestedAssistData", "ilp.requestedAssistData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_posPayLoad,
      { "posPayLoad", "ilp.posPayLoad",
        FT_UINT32, BASE_DEC, VALS(ilp_PosPayLoad_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_utran_GPSReferenceTimeResult,
      { "utran-GPSReferenceTimeResult", "ilp.utran_GPSReferenceTimeResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_utran_GANSSReferenceTimeResult,
      { "utran-GANSSReferenceTimeResult", "ilp.utran_GANSSReferenceTimeResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_almanacRequested,
      { "almanacRequested", "ilp.almanacRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_utcModelRequested,
      { "utcModelRequested", "ilp.utcModelRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_ionosphericModelRequested,
      { "ionosphericModelRequested", "ilp.ionosphericModelRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_dgpsCorrectionsRequested,
      { "dgpsCorrectionsRequested", "ilp.dgpsCorrectionsRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_referenceLocationRequested,
      { "referenceLocationRequested", "ilp.referenceLocationRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_referenceTimeRequested,
      { "referenceTimeRequested", "ilp.referenceTimeRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_acquisitionAssistanceRequested,
      { "acquisitionAssistanceRequested", "ilp.acquisitionAssistanceRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_realTimeIntegrityRequested,
      { "realTimeIntegrityRequested", "ilp.realTimeIntegrityRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_navigationModelRequested,
      { "navigationModelRequested", "ilp.navigationModelRequested",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_navigationModelData,
      { "navigationModelData", "ilp.navigationModelData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavigationModel", HFILL }},
    { &hf_ilp_ganssRequestedCommonAssistanceDataList,
      { "ganssRequestedCommonAssistanceDataList", "ilp.ganssRequestedCommonAssistanceDataList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_ganssRequestedGenericAssistanceDataList,
      { "ganssRequestedGenericAssistanceDataList", "ilp.ganssRequestedGenericAssistanceDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_extendedEphemeris,
      { "extendedEphemeris", "ilp.extendedEphemeris_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_extendedEphemerisCheck,
      { "extendedEphemerisCheck", "ilp.extendedEphemerisCheck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedEphCheck", HFILL }},
    { &hf_ilp_validity,
      { "validity", "ilp.validity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_256", HFILL }},
    { &hf_ilp_beginTime,
      { "beginTime", "ilp.beginTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPSTime", HFILL }},
    { &hf_ilp_endTime,
      { "endTime", "ilp.endTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPSTime", HFILL }},
    { &hf_ilp_gPSWeek,
      { "gPSWeek", "ilp.gPSWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ilp_gPSTOWhour,
      { "gPSTOWhour", "ilp.gPSTOWhour",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_167", HFILL }},
    { &hf_ilp_ganssReferenceTime,
      { "ganssReferenceTime", "ilp.ganssReferenceTime",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_ganssIonosphericModel,
      { "ganssIonosphericModel", "ilp.ganssIonosphericModel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_ganssAdditionalIonosphericModelForDataID00,
      { "ganssAdditionalIonosphericModelForDataID00", "ilp.ganssAdditionalIonosphericModelForDataID00",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_ganssAdditionalIonosphericModelForDataID11,
      { "ganssAdditionalIonosphericModelForDataID11", "ilp.ganssAdditionalIonosphericModelForDataID11",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_ganssEarthOrientationParameters,
      { "ganssEarthOrientationParameters", "ilp.ganssEarthOrientationParameters",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_ganssAdditionalIonosphericModelForDataID01,
      { "ganssAdditionalIonosphericModelForDataID01", "ilp.ganssAdditionalIonosphericModelForDataID01",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_GanssRequestedGenericAssistanceDataList_item,
      { "GanssReqGenericData", "ilp.GanssReqGenericData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_ganssId,
      { "ganssId", "ilp.ganssId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_ilp_ganssSBASid,
      { "ganssSBASid", "ilp.ganssSBASid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_3", HFILL }},
    { &hf_ilp_ganssRealTimeIntegrity,
      { "ganssRealTimeIntegrity", "ilp.ganssRealTimeIntegrity",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_ganssDifferentialCorrection,
      { "ganssDifferentialCorrection", "ilp.ganssDifferentialCorrection",
        FT_BYTES, BASE_NONE, NULL, 0,
        "DGANSS_Sig_Id_Req", HFILL }},
    { &hf_ilp_ganssAlmanac,
      { "ganssAlmanac", "ilp.ganssAlmanac",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_ganssNavigationModelData,
      { "ganssNavigationModelData", "ilp.ganssNavigationModelData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_ganssTimeModels,
      { "ganssTimeModels", "ilp.ganssTimeModels",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_ilp_ganssReferenceMeasurementInfo,
      { "ganssReferenceMeasurementInfo", "ilp.ganssReferenceMeasurementInfo",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_ganssDataBits,
      { "ganssDataBits", "ilp.ganssDataBits_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_ganssUTCModel,
      { "ganssUTCModel", "ilp.ganssUTCModel",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_ganssAdditionalDataChoices,
      { "ganssAdditionalDataChoices", "ilp.ganssAdditionalDataChoices_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_ganssAuxiliaryInformation,
      { "ganssAuxiliaryInformation", "ilp.ganssAuxiliaryInformation",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_ganssExtendedEphemeris,
      { "ganssExtendedEphemeris", "ilp.ganssExtendedEphemeris_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ExtendedEphemeris", HFILL }},
    { &hf_ilp_ganssExtendedEphemerisCheck,
      { "ganssExtendedEphemerisCheck", "ilp.ganssExtendedEphemerisCheck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GanssExtendedEphCheck", HFILL }},
    { &hf_ilp_bds_DifferentialCorrection,
      { "bds-DifferentialCorrection", "ilp.bds_DifferentialCorrection",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BDS_Sig_Id_Req", HFILL }},
    { &hf_ilp_bds_GridModelReq,
      { "bds-GridModelReq", "ilp.bds_GridModelReq",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_ganssWeek,
      { "ganssWeek", "ilp.ganssWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_ilp_ganssToe,
      { "ganssToe", "ilp.ganssToe",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_167", HFILL }},
    { &hf_ilp_t_toeLimit,
      { "t-toeLimit", "ilp.t_toeLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_10", HFILL }},
    { &hf_ilp_satellitesListRelatedDataList,
      { "satellitesListRelatedDataList", "ilp.satellitesListRelatedDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_SatellitesListRelatedDataList_item,
      { "SatellitesListRelatedData", "ilp.SatellitesListRelatedData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_satId,
      { "satId", "ilp.satId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_ilp_iod,
      { "iod", "ilp.iod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ilp_ganssTODmin,
      { "ganssTODmin", "ilp.ganssTODmin",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_59", HFILL }},
    { &hf_ilp_reqDataBitAssistanceList,
      { "reqDataBitAssistanceList", "ilp.reqDataBitAssistanceList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_gnssSignals,
      { "gnssSignals", "ilp.gnssSignals",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GANSSSignals", HFILL }},
    { &hf_ilp_ganssDataBitInterval,
      { "ganssDataBitInterval", "ilp.ganssDataBitInterval",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_ilp_ganssDataBitSatList,
      { "ganssDataBitSatList", "ilp.ganssDataBitSatList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_ganssDataBitSatList_item,
      { "ganssDataBitSatList item", "ilp.ganssDataBitSatList_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_ilp_orbitModelID,
      { "orbitModelID", "ilp.orbitModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_ilp_clockModelID,
      { "clockModelID", "ilp.clockModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_ilp_utcModelID,
      { "utcModelID", "ilp.utcModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_ilp_almanacModelID,
      { "almanacModelID", "ilp.almanacModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_ilp_beginTime_01,
      { "beginTime", "ilp.beginTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSextEphTime", HFILL }},
    { &hf_ilp_endTime_01,
      { "endTime", "ilp.endTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSextEphTime", HFILL }},
    { &hf_ilp_gANSSday,
      { "gANSSday", "ilp.gANSSday",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_ilp_gANSSTODhour,
      { "gANSSTODhour", "ilp.gANSSTODhour",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_23", HFILL }},
    { &hf_ilp_gpsWeek,
      { "gpsWeek", "ilp.gpsWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ilp_gpsToe,
      { "gpsToe", "ilp.gpsToe",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_167", HFILL }},
    { &hf_ilp_nsat,
      { "nsat", "ilp.nsat",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_ilp_toeLimit,
      { "toeLimit", "ilp.toeLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_10", HFILL }},
    { &hf_ilp_satInfo,
      { "satInfo", "ilp.satInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SatelliteInfo", HFILL }},
    { &hf_ilp_SatelliteInfo_item,
      { "SatelliteInfoElement", "ilp.SatelliteInfoElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_iode,
      { "iode", "ilp.iode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_sPCStatusCode,
      { "sPCStatusCode", "ilp.sPCStatusCode",
        FT_UINT32, BASE_DEC, VALS(ilp_SPCStatusCode_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_velocity,
      { "velocity", "ilp.velocity",
        FT_UINT32, BASE_DEC, VALS(ilp_Velocity_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_utran_GPSReferenceTimeAssistance,
      { "utran-GPSReferenceTimeAssistance", "ilp.utran_GPSReferenceTimeAssistance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_utran_GANSSReferenceTimeAssistance,
      { "utran-GANSSReferenceTimeAssistance", "ilp.utran_GANSSReferenceTimeAssistance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_maj,
      { "maj", "ilp.maj",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_min,
      { "min", "ilp.min",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_servind,
      { "servind", "ilp.servind",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_slcSessionID,
      { "slcSessionID", "ilp.slcSessionID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_setSessionID,
      { "setSessionID", "ilp.setSessionID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_spcSessionID,
      { "spcSessionID", "ilp.spcSessionID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_sessionId,
      { "sessionId", "ilp.sessionId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ilp_setId,
      { "setId", "ilp.setId",
        FT_UINT32, BASE_DEC, VALS(ilp_SETId_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_msisdn,
      { "msisdn", "ilp.msisdn",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_mdn,
      { "mdn", "ilp.mdn",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_minsi,
      { "min", "ilp.minsi",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_34", HFILL }},
    { &hf_ilp_imsi,
      { "imsi", "ilp.imsi",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_nai,
      { "nai", "ilp.nai",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_1000", HFILL }},
    { &hf_ilp_iPAddress,
      { "iPAddress", "ilp.iPAddress",
        FT_UINT32, BASE_DEC, VALS(ilp_IPAddress_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_imei,
      { "imei", "ilp.imei",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_8", HFILL }},
    { &hf_ilp_sessionID,
      { "sessionID", "ilp.sessionID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_ilp_slcId,
      { "slcId", "ilp.slcId",
        FT_UINT32, BASE_DEC, VALS(ilp_NodeAddress_vals), 0,
        "NodeAddress", HFILL }},
    { &hf_ilp_spcId,
      { "spcId", "ilp.spcId",
        FT_UINT32, BASE_DEC, VALS(ilp_NodeAddress_vals), 0,
        "NodeAddress", HFILL }},
    { &hf_ilp_ipv4Address,
      { "ipv4Address", "ilp.ipv4Address",
        FT_IPv4, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_4", HFILL }},
    { &hf_ilp_ipv6Address,
      { "ipv6Address", "ilp.ipv6Address",
        FT_IPv6, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_16", HFILL }},
    { &hf_ilp_fqdn,
      { "fqdn", "ilp.fqdn",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_cellInfo,
      { "cellInfo", "ilp.cellInfo",
        FT_UINT32, BASE_DEC, VALS(ilp_CellInfo_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_status,
      { "status", "ilp.status",
        FT_UINT32, BASE_DEC, VALS(ilp_Status_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_MultipleLocationIds_item,
      { "LocationIdData", "ilp.LocationIdData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_relativetimestamp,
      { "relativetimestamp", "ilp.relativetimestamp",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RelativeTime", HFILL }},
    { &hf_ilp_servingFlag,
      { "servingFlag", "ilp.servingFlag",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_posTechnology,
      { "posTechnology", "ilp.posTechnology_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_prefMethod,
      { "prefMethod", "ilp.prefMethod",
        FT_UINT32, BASE_DEC, VALS(ilp_PrefMethod_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_posProtocol,
      { "posProtocol", "ilp.posProtocol_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_supportedBearers,
      { "supportedBearers", "ilp.supportedBearers_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_agpsSETassisted,
      { "agpsSETassisted", "ilp.agpsSETassisted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_agpsSETBased,
      { "agpsSETBased", "ilp.agpsSETBased",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_autonomousGPS,
      { "autonomousGPS", "ilp.autonomousGPS",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_aflt,
      { "aflt", "ilp.aflt",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_ecid,
      { "ecid", "ilp.ecid",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_eotd,
      { "eotd", "ilp.eotd",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_otdoa,
      { "otdoa", "ilp.otdoa",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_gANSSPositionMethods,
      { "gANSSPositionMethods", "ilp.gANSSPositionMethods",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_additionalPositioningMethods,
      { "additionalPositioningMethods", "ilp.additionalPositioningMethods",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_GANSSPositionMethods_item,
      { "GANSSPositionMethod", "ilp.GANSSPositionMethod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_gANSSPositioningMethodTypes,
      { "gANSSPositioningMethodTypes", "ilp.gANSSPositioningMethodTypes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_gANSSSignals,
      { "gANSSSignals", "ilp.gANSSSignals",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_setAssisted,
      { "setAssisted", "ilp.setAssisted",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_setBased,
      { "setBased", "ilp.setBased",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_autonomous,
      { "autonomous", "ilp.autonomous",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_AdditionalPositioningMethods_item,
      { "AddPosSupport-Element", "ilp.AddPosSupport_Element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_addPosID,
      { "addPosID", "ilp.addPosID",
        FT_UINT32, BASE_DEC, VALS(ilp_T_addPosID_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_addPosMode,
      { "addPosMode", "ilp.addPosMode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_tia801,
      { "tia801", "ilp.tia801",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_rrlp,
      { "rrlp", "ilp.rrlp",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_rrc,
      { "rrc", "ilp.rrc",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_lpp,
      { "lpp", "ilp.lpp",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_posProtocolVersionRRLP,
      { "posProtocolVersionRRLP", "ilp.posProtocolVersionRRLP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosProtocolVersion3GPP", HFILL }},
    { &hf_ilp_posProtocolVersionRRC,
      { "posProtocolVersionRRC", "ilp.posProtocolVersionRRC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosProtocolVersion3GPP", HFILL }},
    { &hf_ilp_posProtocolVersionTIA801,
      { "posProtocolVersionTIA801", "ilp.posProtocolVersionTIA801",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PosProtocolVersion3GPP2", HFILL }},
    { &hf_ilp_posProtocolVersionLPP,
      { "posProtocolVersionLPP", "ilp.posProtocolVersionLPP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosProtocolVersion3GPP", HFILL }},
    { &hf_ilp_lppe,
      { "lppe", "ilp.lppe",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_posProtocolVersionLPPe,
      { "posProtocolVersionLPPe", "ilp.posProtocolVersionLPPe_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosProtocolVersionOMA", HFILL }},
    { &hf_ilp_majorVersionField,
      { "majorVersionField", "ilp.majorVersionField",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_technicalVersionField,
      { "technicalVersionField", "ilp.technicalVersionField",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_editorialVersionField,
      { "editorialVersionField", "ilp.editorialVersionField",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_PosProtocolVersion3GPP2_item,
      { "Supported3GPP2PosProtocolVersion", "ilp.Supported3GPP2PosProtocolVersion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_revisionNumber,
      { "revisionNumber", "ilp.revisionNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_ilp_pointReleaseNumber,
      { "pointReleaseNumber", "ilp.pointReleaseNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_internalEditLevel,
      { "internalEditLevel", "ilp.internalEditLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_minorVersionField,
      { "minorVersionField", "ilp.minorVersionField",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_gsm,
      { "gsm", "ilp.gsm",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_wcdma,
      { "wcdma", "ilp.wcdma",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_lte,
      { "lte", "ilp.lte",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_cdma,
      { "cdma", "ilp.cdma",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_hprd,
      { "hprd", "ilp.hprd",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_umb,
      { "umb", "ilp.umb",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_wlan,
      { "wlan", "ilp.wlan",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_wiMAX,
      { "wiMAX", "ilp.wiMAX",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_nr,
      { "nr", "ilp.nr",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_gsmCell,
      { "gsmCell", "ilp.gsmCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GsmCellInformation", HFILL }},
    { &hf_ilp_wcdmaCell,
      { "wcdmaCell", "ilp.wcdmaCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WcdmaCellInformation", HFILL }},
    { &hf_ilp_cdmaCell,
      { "cdmaCell", "ilp.cdmaCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CdmaCellInformation", HFILL }},
    { &hf_ilp_hrpdCell,
      { "hrpdCell", "ilp.hrpdCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "HrpdCellInformation", HFILL }},
    { &hf_ilp_umbCell,
      { "umbCell", "ilp.umbCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UmbCellInformation", HFILL }},
    { &hf_ilp_lteCell,
      { "lteCell", "ilp.lteCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LteCellInformation", HFILL }},
    { &hf_ilp_wlanAP,
      { "wlanAP", "ilp.wlanAP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WlanAPInformation", HFILL }},
    { &hf_ilp_wimaxBS,
      { "wimaxBS", "ilp.wimaxBS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "WimaxBSInformation", HFILL }},
    { &hf_ilp_nrCell,
      { "nrCell", "ilp.nrCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NRCellInformation", HFILL }},
    { &hf_ilp_set_GPSTimingOfCell,
      { "set-GPSTimingOfCell", "ilp.set_GPSTimingOfCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_set_GPSTimingOfCell", HFILL }},
    { &hf_ilp_ms_part,
      { "ms-part", "ilp.ms_part",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_ilp_ls_part,
      { "ls-part", "ilp.ls_part",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_ilp_modeSpecificInfo,
      { "modeSpecificInfo", "ilp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ilp_T_modeSpecificInfo_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_fdd,
      { "fdd", "ilp.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_referenceIdentity,
      { "referenceIdentity", "ilp.referenceIdentity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PrimaryCPICH_Info", HFILL }},
    { &hf_ilp_tdd,
      { "tdd", "ilp.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_referenceIdentity_01,
      { "referenceIdentity", "ilp.referenceIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellParametersID", HFILL }},
    { &hf_ilp_sfn,
      { "sfn", "ilp.sfn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_ilp_gpsReferenceTimeUncertainty,
      { "gpsReferenceTimeUncertainty", "ilp.gpsReferenceTimeUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ilp_ganssTimeID,
      { "ganssTimeID", "ilp.ganssTimeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_ilp_set_GANSSReferenceTime,
      { "set-GANSSReferenceTime", "ilp.set_GANSSReferenceTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_set_GANSSTimingOfCell,
      { "set-GANSSTimingOfCell", "ilp.set_GANSSTimingOfCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_set_GANSSTimingOfCell", HFILL }},
    { &hf_ilp_ms_part_01,
      { "ms-part", "ilp.ms_part",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_80", HFILL }},
    { &hf_ilp_modeSpecificInfo_01,
      { "modeSpecificInfo", "ilp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ilp_T_modeSpecificInfo_01_vals), 0,
        "T_modeSpecificInfo_01", HFILL }},
    { &hf_ilp_fdd_01,
      { "fdd", "ilp.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_fdd_01", HFILL }},
    { &hf_ilp_tdd_01,
      { "tdd", "ilp.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tdd_01", HFILL }},
    { &hf_ilp_ganss_TODUncertainty,
      { "ganss-TODUncertainty", "ilp.ganss_TODUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ilp_gps,
      { "gps", "ilp.gps",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_galileo,
      { "galileo", "ilp.galileo",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_sbas,
      { "sbas", "ilp.sbas",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_modernized_gps,
      { "modernized-gps", "ilp.modernized_gps",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_qzss,
      { "qzss", "ilp.qzss",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_glonass,
      { "glonass", "ilp.glonass",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_bds,
      { "bds", "ilp.bds",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_timestamp,
      { "timestamp", "ilp.timestamp",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTCTime", HFILL }},
    { &hf_ilp_positionEstimate,
      { "positionEstimate", "ilp.positionEstimate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_latitudeSign,
      { "latitudeSign", "ilp.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(ilp_T_latitudeSign_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_latitude,
      { "latitude", "ilp.latitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_ilp_longitude,
      { "longitude", "ilp.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_ilp_uncertainty,
      { "uncertainty", "ilp.uncertainty_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_uncertaintySemiMajor,
      { "uncertaintySemiMajor", "ilp.uncertaintySemiMajor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ilp_uncertaintySemiMinor,
      { "uncertaintySemiMinor", "ilp.uncertaintySemiMinor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ilp_orientationMajorAxis,
      { "orientationMajorAxis", "ilp.orientationMajorAxis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_180", HFILL }},
    { &hf_ilp_confidence,
      { "confidence", "ilp.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_ilp_altitudeInfo,
      { "altitudeInfo", "ilp.altitudeInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_altitudeDirection,
      { "altitudeDirection", "ilp.altitudeDirection",
        FT_UINT32, BASE_DEC, VALS(ilp_T_altitudeDirection_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_altitude,
      { "altitude", "ilp.altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_ilp_altUncertainty,
      { "altUncertainty", "ilp.altUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ilp_refNID,
      { "refNID", "ilp.refNID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ilp_refSID,
      { "refSID", "ilp.refSID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_ilp_refBASEID,
      { "refBASEID", "ilp.refBASEID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ilp_refBASELAT,
      { "refBASELAT", "ilp.refBASELAT",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4194303", HFILL }},
    { &hf_ilp_reBASELONG,
      { "reBASELONG", "ilp.reBASELONG",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_ilp_refREFPN,
      { "refREFPN", "ilp.refREFPN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_511", HFILL }},
    { &hf_ilp_refWeekNumber,
      { "refWeekNumber", "ilp.refWeekNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ilp_refSeconds,
      { "refSeconds", "ilp.refSeconds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4194303", HFILL }},
    { &hf_ilp_refMCC,
      { "refMCC", "ilp.refMCC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_999", HFILL }},
    { &hf_ilp_refMNC,
      { "refMNC", "ilp.refMNC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_999", HFILL }},
    { &hf_ilp_refLAC,
      { "refLAC", "ilp.refLAC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ilp_refCI,
      { "refCI", "ilp.refCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ilp_nmr,
      { "nmr", "ilp.nmr",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_ta,
      { "ta", "ilp.ta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_refUC,
      { "refUC", "ilp.refUC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_268435455", HFILL }},
    { &hf_ilp_frequencyInfo,
      { "frequencyInfo", "ilp.frequencyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_primaryScramblingCode,
      { "primaryScramblingCode", "ilp.primaryScramblingCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_511", HFILL }},
    { &hf_ilp_measuredResultsList,
      { "measuredResultsList", "ilp.measuredResultsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_cellParametersId,
      { "cellParametersId", "ilp.cellParametersId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ilp_timingAdvance,
      { "timingAdvance", "ilp.timingAdvance_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_ta_01,
      { "ta", "ilp.ta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_ilp_tAResolution,
      { "tAResolution", "ilp.tAResolution",
        FT_UINT32, BASE_DEC, VALS(ilp_TAResolution_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_chipRate,
      { "chipRate", "ilp.chipRate",
        FT_UINT32, BASE_DEC, VALS(ilp_ChipRate_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_refSECTORID,
      { "refSECTORID", "ilp.refSECTORID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_128", HFILL }},
    { &hf_ilp_cellGlobalIdEUTRA,
      { "cellGlobalIdEUTRA", "ilp.cellGlobalIdEUTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_physCellId,
      { "physCellId", "ilp.physCellId",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_trackingAreaCode,
      { "trackingAreaCode", "ilp.trackingAreaCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_rsrpResult,
      { "rsrpResult", "ilp.rsrpResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRP_Range", HFILL }},
    { &hf_ilp_rsrqResult,
      { "rsrqResult", "ilp.rsrqResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RSRQ_Range", HFILL }},
    { &hf_ilp_ta_02,
      { "ta", "ilp.ta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1282", HFILL }},
    { &hf_ilp_measResultListEUTRA,
      { "measResultListEUTRA", "ilp.measResultListEUTRA",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_earfcn,
      { "earfcn", "ilp.earfcn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ilp_earfcn_ext,
      { "earfcn-ext", "ilp.earfcn_ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_65536_262143", HFILL }},
    { &hf_ilp_rsrpResult_ext,
      { "rsrpResult-ext", "ilp.rsrpResult_ext",
        FT_INT32, BASE_DEC, NULL, 0,
        "RSRP_Range_Ext", HFILL }},
    { &hf_ilp_rsrqResult_ext,
      { "rsrqResult-ext", "ilp.rsrqResult_ext",
        FT_INT32, BASE_DEC, NULL, 0,
        "RSRQ_Range_Ext", HFILL }},
    { &hf_ilp_rs_sinrResult,
      { "rs-sinrResult", "ilp.rs_sinrResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RS_SINR_Range", HFILL }},
    { &hf_ilp_servingInformation5G,
      { "servingInformation5G", "ilp.servingInformation5G_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_MeasResultListEUTRA_item,
      { "MeasResultEUTRA", "ilp.MeasResultEUTRA_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_cgi_Info,
      { "cgi-Info", "ilp.cgi_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_cellGlobalId,
      { "cellGlobalId", "ilp.cellGlobalId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellGlobalIdEUTRA", HFILL }},
    { &hf_ilp_measResult,
      { "measResult", "ilp.measResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_neighbourInformation5G,
      { "neighbourInformation5G", "ilp.neighbourInformation5G_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_plmn_Identity,
      { "plmn-Identity", "ilp.plmn_Identity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_eutra_cellIdentity,
      { "cellIdentity", "ilp.cellglobalideutra.cellIdentity",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_mcc,
      { "mcc", "ilp.mcc",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_mnc,
      { "mnc", "ilp.mnc",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_MCC_item,
      { "MCC-MNC-Digit", "ilp.MCC_MNC_Digit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_MNC_item,
      { "MCC-MNC-Digit", "ilp.MCC_MNC_Digit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_trackingAreaCode_01,
      { "trackingAreaCode", "ilp.trackingAreaCode",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TrackingAreaCodeNR", HFILL }},
    { &hf_ilp_apMACAddress,
      { "apMACAddress", "ilp.apMACAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_48", HFILL }},
    { &hf_ilp_apTransmitPower,
      { "apTransmitPower", "ilp.apTransmitPower",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ilp_apAntennaGain,
      { "apAntennaGain", "ilp.apAntennaGain",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ilp_apSignaltoNoise,
      { "apSignaltoNoise", "ilp.apSignaltoNoise",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ilp_apDeviceType,
      { "apDeviceType", "ilp.apDeviceType",
        FT_UINT32, BASE_DEC, VALS(ilp_T_apDeviceType_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_apSignalStrength,
      { "apSignalStrength", "ilp.apSignalStrength",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ilp_apChannelFrequency,
      { "apChannelFrequency", "ilp.apChannelFrequency",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_256", HFILL }},
    { &hf_ilp_apRoundTripDelay,
      { "apRoundTripDelay", "ilp.apRoundTripDelay_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTD", HFILL }},
    { &hf_ilp_setTransmitPower,
      { "setTransmitPower", "ilp.setTransmitPower",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ilp_setAntennaGain,
      { "setAntennaGain", "ilp.setAntennaGain",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ilp_setSignaltoNoise,
      { "setSignaltoNoise", "ilp.setSignaltoNoise",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ilp_setSignalStrength,
      { "setSignalStrength", "ilp.setSignalStrength",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_128", HFILL }},
    { &hf_ilp_apReportedLocation,
      { "apReportedLocation", "ilp.apReportedLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportedLocation", HFILL }},
    { &hf_ilp_apRepLocation,
      { "apRepLocation", "ilp.apRepLocation",
        FT_UINT32, BASE_DEC, VALS(ilp_RepLocation_vals), 0,
        "RepLocation", HFILL }},
    { &hf_ilp_apSignalStrengthDelta,
      { "apSignalStrengthDelta", "ilp.apSignalStrengthDelta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_ilp_apSignaltoNoiseDelta,
      { "apSignaltoNoiseDelta", "ilp.apSignaltoNoiseDelta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_ilp_setSignalStrengthDelta,
      { "setSignalStrengthDelta", "ilp.setSignalStrengthDelta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_ilp_setSignaltoNoiseDelta,
      { "setSignaltoNoiseDelta", "ilp.setSignaltoNoiseDelta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_ilp_operatingClass,
      { "operatingClass", "ilp.operatingClass",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_apSSID,
      { "apSSID", "ilp.apSSID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_32", HFILL }},
    { &hf_ilp_apPHYType,
      { "apPHYType", "ilp.apPHYType",
        FT_UINT32, BASE_DEC, VALS(ilp_T_apPHYType_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_setMACAddress,
      { "setMACAddress", "ilp.setMACAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_48", HFILL }},
    { &hf_ilp_rTDValue,
      { "rTDValue", "ilp.rTDValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777216", HFILL }},
    { &hf_ilp_rTDUnits,
      { "rTDUnits", "ilp.rTDUnits",
        FT_UINT32, BASE_DEC, VALS(ilp_RTDUnits_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_rTDAccuracy,
      { "rTDAccuracy", "ilp.rTDAccuracy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_locationEncodingDescriptor,
      { "locationEncodingDescriptor", "ilp.locationEncodingDescriptor",
        FT_UINT32, BASE_DEC, VALS(ilp_LocationEncodingDescriptor_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_locationData,
      { "locationData", "ilp.locationData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_locationAccuracy,
      { "locationAccuracy", "ilp.locationAccuracy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_ilp_locationValue,
      { "locationValue", "ilp.locationValue",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_128", HFILL }},
    { &hf_ilp_lciLocData,
      { "lciLocData", "ilp.lciLocData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_locationDataLCI,
      { "locationDataLCI", "ilp.locationDataLCI_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_latitudeResolution,
      { "latitudeResolution", "ilp.latitudeResolution",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_ilp_LocationDataLCI_latitude,
      { "latitude", "ilp.locationdatalci.latitude",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_34", HFILL }},
    { &hf_ilp_longitudeResolution,
      { "longitudeResolution", "ilp.longitudeResolution",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_ilp_LocationDataLCI_longitude,
      { "longitude", "ilp.longitude",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_34", HFILL }},
    { &hf_ilp_altitudeType,
      { "altitudeType", "ilp.altitudeType",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_ilp_altitudeResolution,
      { "altitudeResolution", "ilp.altitudeResolution",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_6", HFILL }},
    { &hf_ilp_LocationDataLCI_altitude,
      { "altitude", "ilp.locationdatalci.altitude",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_30", HFILL }},
    { &hf_ilp_datum,
      { "datum", "ilp.datum",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_ilp_wimaxBsID,
      { "wimaxBsID", "ilp.wimaxBsID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_wimaxRTD,
      { "wimaxRTD", "ilp.wimaxRTD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_wimaxNMRList,
      { "wimaxNMRList", "ilp.wimaxNMRList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_bsID_MSB,
      { "bsID-MSB", "ilp.bsID_MSB",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_ilp_bsID_LSB,
      { "bsID-LSB", "ilp.bsID_LSB",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_24", HFILL }},
    { &hf_ilp_rtd,
      { "rtd", "ilp.rtd",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ilp_rTDstd,
      { "rTDstd", "ilp.rTDstd",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ilp_WimaxNMRList_item,
      { "WimaxNMR", "ilp.WimaxNMR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_relDelay,
      { "relDelay", "ilp.relDelay",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_ilp_relDelaystd,
      { "relDelaystd", "ilp.relDelaystd",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ilp_rssi,
      { "rssi", "ilp.rssi",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_rSSIstd,
      { "rSSIstd", "ilp.rSSIstd",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_ilp_bSTxPower,
      { "bSTxPower", "ilp.bSTxPower",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_cinr,
      { "cinr", "ilp.cinr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_ilp_cINRstd,
      { "cINRstd", "ilp.cINRstd",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_ilp_bSLocation,
      { "bSLocation", "ilp.bSLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReportedLocation", HFILL }},
    { &hf_ilp_servingCellInformation,
      { "servingCellInformation", "ilp.servingCellInformation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServingCellInformationNR", HFILL }},
    { &hf_ilp_measuredResultsListNR,
      { "measuredResultsListNR", "ilp.measuredResultsListNR",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasResultListNR", HFILL }},
    { &hf_ilp_ServingCellInformationNR_item,
      { "ServCellNR", "ilp.ServCellNR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_physCellId_01,
      { "physCellId", "ilp.physCellId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PhysCellIdNR", HFILL }},
    { &hf_ilp_arfcn_NR,
      { "arfcn-NR", "ilp.arfcn_NR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_cellGlobalId_01,
      { "cellGlobalId", "ilp.cellGlobalId_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellGlobalIdNR", HFILL }},
    { &hf_ilp_ssb_Measurements,
      { "ssb-Measurements", "ilp.ssb_Measurements_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_Measurements", HFILL }},
    { &hf_ilp_csi_rs_Measurements,
      { "csi-rs-Measurements", "ilp.csi_rs_Measurements_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NR_Measurements", HFILL }},
    { &hf_ilp_ta_03,
      { "ta", "ilp.ta",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3846", HFILL }},
    { &hf_ilp_MeasResultListNR_item,
      { "MeasResultNR", "ilp.MeasResultNR_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_cellIdentityNR,
      { "cellIdentityNR", "ilp.cellIdentityNR",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_rsrp_Range,
      { "rsrp-Range", "ilp.rsrp_Range",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ilp_rsrq_Range,
      { "rsrq-Range", "ilp.rsrq_Range",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ilp_sinr_Range,
      { "sinr-Range", "ilp.sinr_Range",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ilp_modeSpecificFrequencyInfo,
      { "modeSpecificInfo", "ilp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ilp_FrequencySpecificInfo_vals), 0,
        "FrequencySpecificInfo", HFILL }},
    { &hf_ilp_fdd_fr,
      { "fdd", "ilp.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FrequencyInfoFDD", HFILL }},
    { &hf_ilp_tdd_fr,
      { "tdd", "ilp.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "FrequencyInfoTDD", HFILL }},
    { &hf_ilp_uarfcn_UL,
      { "uarfcn-UL", "ilp.uarfcn_UL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UARFCN", HFILL }},
    { &hf_ilp_uarfcn_DL,
      { "uarfcn-DL", "ilp.uarfcn_DL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UARFCN", HFILL }},
    { &hf_ilp_uarfcn_Nt,
      { "uarfcn-Nt", "ilp.uarfcn_Nt",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UARFCN", HFILL }},
    { &hf_ilp_NMR_item,
      { "NMRelement", "ilp.NMRelement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_arfcn,
      { "arfcn", "ilp.arfcn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ilp_bsic,
      { "bsic", "ilp.bsic",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_ilp_rxLev,
      { "rxLev", "ilp.rxLev",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_ilp_MeasuredResultsList_item,
      { "MeasuredResults", "ilp.MeasuredResults_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_utra_CarrierRSSI,
      { "utra-CarrierRSSI", "ilp.utra_CarrierRSSI",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_cellMeasuredResultsList,
      { "cellMeasuredResultsList", "ilp.cellMeasuredResultsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_CellMeasuredResultsList_item,
      { "CellMeasuredResults", "ilp.CellMeasuredResults_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_cellIdentity,
      { "cellIdentity", "ilp.cellIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_268435455", HFILL }},
    { &hf_ilp_modeSpecificInfo_02,
      { "modeSpecificInfo", "ilp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ilp_T_modeSpecificInfo_02_vals), 0,
        "T_modeSpecificInfo_02", HFILL }},
    { &hf_ilp_fdd_02,
      { "fdd", "ilp.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_fdd_02", HFILL }},
    { &hf_ilp_primaryCPICH_Info,
      { "primaryCPICH-Info", "ilp.primaryCPICH_Info_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_cpich_Ec_N0,
      { "cpich-Ec-N0", "ilp.cpich_Ec_N0",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_cpich_RSCP,
      { "cpich-RSCP", "ilp.cpich_RSCP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_pathloss,
      { "pathloss", "ilp.pathloss",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_tdd_02,
      { "tdd", "ilp.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tdd_02", HFILL }},
    { &hf_ilp_cellParametersID,
      { "cellParametersID", "ilp.cellParametersID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_proposedTGSN,
      { "proposedTGSN", "ilp.proposedTGSN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TGSN", HFILL }},
    { &hf_ilp_primaryCCPCH_RSCP,
      { "primaryCCPCH-RSCP", "ilp.primaryCCPCH_RSCP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_timeslotISCP_List,
      { "timeslotISCP-List", "ilp.timeslotISCP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_TimeslotISCP_List_item,
      { "TimeslotISCP", "ilp.TimeslotISCP",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_utran_GPSReferenceTime,
      { "utran-GPSReferenceTime", "ilp.utran_GPSReferenceTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_utranGPSDriftRate,
      { "utranGPSDriftRate", "ilp.utranGPSDriftRate",
        FT_UINT32, BASE_DEC, VALS(ilp_UTRANGPSDriftRate_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_utran_GPSTimingOfCell,
      { "utran-GPSTimingOfCell", "ilp.utran_GPSTimingOfCell_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_ms_part_02,
      { "ms-part", "ilp.ms_part",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ilp_modeSpecificInfo_03,
      { "modeSpecificInfo", "ilp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ilp_T_modeSpecificInfo_03_vals), 0,
        "T_modeSpecificInfo_03", HFILL }},
    { &hf_ilp_fdd_03,
      { "fdd", "ilp.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_fdd_03", HFILL }},
    { &hf_ilp_tdd_03,
      { "tdd", "ilp.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tdd_03", HFILL }},
    { &hf_ilp_utran_GANSSReferenceTime,
      { "utran-GANSSReferenceTime", "ilp.utran_GANSSReferenceTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_ganssDay,
      { "ganssDay", "ilp.ganssDay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_ilp_utranGANSSDriftRate,
      { "utranGANSSDriftRate", "ilp.utranGANSSDriftRate",
        FT_UINT32, BASE_DEC, VALS(ilp_UTRANGANSSDriftRate_vals), 0,
        NULL, HFILL }},
    { &hf_ilp_ganssTOD,
      { "ganssTOD", "ilp.ganssTOD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_86399", HFILL }},
    { &hf_ilp_utran_GANSSTimingOfCell,
      { "utran-GANSSTimingOfCell", "ilp.utran_GANSSTimingOfCell",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3999999", HFILL }},
    { &hf_ilp_modeSpecificInfo_04,
      { "modeSpecificInfo", "ilp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ilp_T_modeSpecificInfo_04_vals), 0,
        "T_modeSpecificInfo_04", HFILL }},
    { &hf_ilp_fdd_04,
      { "fdd", "ilp.fdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_fdd_04", HFILL }},
    { &hf_ilp_tdd_04,
      { "tdd", "ilp.tdd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_tdd_04", HFILL }},
    { &hf_ilp_horacc,
      { "horacc", "ilp.horacc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ilp_veracc,
      { "veracc", "ilp.veracc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_ilp_maxLocAge,
      { "maxLocAge", "ilp.maxLocAge",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_ilp_delay,
      { "delay", "ilp.delay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_ilp_ver2_responseTime,
      { "ver2-responseTime", "ilp.ver2_responseTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_128", HFILL }},
    { &hf_ilp_horvel,
      { "horvel", "ilp.horvel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_horandvervel,
      { "horandvervel", "ilp.horandvervel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_horveluncert,
      { "horveluncert", "ilp.horveluncert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_horandveruncert,
      { "horandveruncert", "ilp.horandveruncert_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_bearing,
      { "bearing", "ilp.bearing",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_9", HFILL }},
    { &hf_ilp_horspeed,
      { "horspeed", "ilp.horspeed",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_16", HFILL }},
    { &hf_ilp_verdirect,
      { "verdirect", "ilp.verdirect",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_ilp_verspeed,
      { "verspeed", "ilp.verspeed",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_ilp_uncertspeed,
      { "uncertspeed", "ilp.uncertspeed",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_ilp_horuncertspeed,
      { "horuncertspeed", "ilp.horuncertspeed",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_ilp_veruncertspeed,
      { "veruncertspeed", "ilp.veruncertspeed",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_ilp_rand,
      { "rand", "ilp.rand",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_128", HFILL }},
    { &hf_ilp_slpFQDN,
      { "slpFQDN", "ilp.slpFQDN",
        FT_STRING, BASE_NONE, NULL, 0,
        "FQDN", HFILL }},
    { &hf_ilp_rrcPayload,
      { "rrcPayload", "ilp.rrcPayload",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_8192", HFILL }},
    { &hf_ilp_rrlpPayload,
      { "rrlpPayload", "ilp.rrlpPayload",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_multiPosPayload,
      { "multiPosPayload", "ilp.multiPosPayload_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_lPPPayload,
      { "lPPPayload", "ilp.lPPPayload",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_lPPPayload_item,
      { "lPPPayload item", "ilp.lPPPayload_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_tia801Payload,
      { "tia801Payload", "ilp.tia801Payload",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_tia801Payload_item,
      { "tia801Payload item", "ilp.tia801Payload_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_60000", HFILL }},
    { &hf_ilp_GANSSSignals_signal1,
      { "signal1", "ilp.GANSSSignals.signal1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal2,
      { "signal2", "ilp.GANSSSignals.signal2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal3,
      { "signal3", "ilp.GANSSSignals.signal3",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal4,
      { "signal4", "ilp.GANSSSignals.signal4",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal5,
      { "signal5", "ilp.GANSSSignals.signal5",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal6,
      { "signal6", "ilp.GANSSSignals.signal6",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal7,
      { "signal7", "ilp.GANSSSignals.signal7",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal8,
      { "signal8", "ilp.GANSSSignals.signal8",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_ilp_T_addPosMode_standalone,
      { "standalone", "ilp.T.addPosMode.standalone",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ilp_T_addPosMode_setBased,
      { "setBased", "ilp.T.addPosMode.setBased",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ilp_T_addPosMode_setAssisted,
      { "setAssisted", "ilp.T.addPosMode.setAssisted",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ilp_mobile_directory_number,
      { "Mobile Directory Number", "ilp.mobile_directory_number",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_ilp,
    &ett_ilp_setid,
    &ett_ilp_ILP_PDU,
    &ett_ilp_IlpMessage,
    &ett_ilp_PREQ,
    &ett_ilp_TriggerParams,
    &ett_ilp_PeriodicTriggerParams,
    &ett_ilp_PRES,
    &ett_ilp_PRPT,
    &ett_ilp_PLREQ,
    &ett_ilp_PLRES,
    &ett_ilp_PositionResults,
    &ett_ilp_PositionResult,
    &ett_ilp_PINIT,
    &ett_ilp_RequestedAssistData,
    &ett_ilp_ExtendedEphemeris,
    &ett_ilp_ExtendedEphCheck,
    &ett_ilp_GPSTime,
    &ett_ilp_GanssRequestedCommonAssistanceDataList,
    &ett_ilp_GanssRequestedGenericAssistanceDataList,
    &ett_ilp_GanssReqGenericData,
    &ett_ilp_GanssNavigationModelData,
    &ett_ilp_SatellitesListRelatedDataList,
    &ett_ilp_SatellitesListRelatedData,
    &ett_ilp_GanssDataBits,
    &ett_ilp_ReqDataBitAssistanceList,
    &ett_ilp_T_ganssDataBitSatList,
    &ett_ilp_GanssAdditionalDataChoices,
    &ett_ilp_GanssExtendedEphCheck,
    &ett_ilp_GANSSextEphTime,
    &ett_ilp_NavigationModel,
    &ett_ilp_SatelliteInfo,
    &ett_ilp_SatelliteInfoElement,
    &ett_ilp_PAUTH,
    &ett_ilp_PALIVE,
    &ett_ilp_PEND,
    &ett_ilp_PMESS,
    &ett_ilp_Version,
    &ett_ilp_SessionID2,
    &ett_ilp_SetSessionID,
    &ett_ilp_SETId,
    &ett_ilp_SlcSessionID,
    &ett_ilp_SpcSessionID,
    &ett_ilp_IPAddress,
    &ett_ilp_NodeAddress,
    &ett_ilp_LocationId,
    &ett_ilp_MultipleLocationIds,
    &ett_ilp_LocationIdData,
    &ett_ilp_SETCapabilities,
    &ett_ilp_PosTechnology,
    &ett_ilp_GANSSPositionMethods,
    &ett_ilp_GANSSPositionMethod,
    &ett_ilp_GANSSPositioningMethodTypes,
    &ett_ilp_GANSSSignals,
    &ett_ilp_AdditionalPositioningMethods,
    &ett_ilp_AddPosSupport_Element,
    &ett_ilp_T_addPosMode,
    &ett_ilp_PosProtocol,
    &ett_ilp_PosProtocolVersion3GPP,
    &ett_ilp_PosProtocolVersion3GPP2,
    &ett_ilp_Supported3GPP2PosProtocolVersion,
    &ett_ilp_PosProtocolVersionOMA,
    &ett_ilp_SupportedBearers,
    &ett_ilp_CellInfo,
    &ett_ilp_UTRAN_GPSReferenceTimeResult,
    &ett_ilp_T_set_GPSTimingOfCell,
    &ett_ilp_T_modeSpecificInfo,
    &ett_ilp_T_fdd,
    &ett_ilp_T_tdd,
    &ett_ilp_UTRAN_GANSSReferenceTimeResult,
    &ett_ilp_SET_GANSSReferenceTime,
    &ett_ilp_T_set_GANSSTimingOfCell,
    &ett_ilp_T_modeSpecificInfo_01,
    &ett_ilp_T_fdd_01,
    &ett_ilp_T_tdd_01,
    &ett_ilp_GNSSPosTechnology,
    &ett_ilp_Position,
    &ett_ilp_PositionEstimate,
    &ett_ilp_T_uncertainty,
    &ett_ilp_AltitudeInfo,
    &ett_ilp_CdmaCellInformation,
    &ett_ilp_GsmCellInformation,
    &ett_ilp_WcdmaCellInformation,
    &ett_ilp_TimingAdvance,
    &ett_ilp_HrpdCellInformation,
    &ett_ilp_UmbCellInformation,
    &ett_ilp_LteCellInformation,
    &ett_ilp_MeasResultListEUTRA,
    &ett_ilp_MeasResultEUTRA,
    &ett_ilp_T_cgi_Info,
    &ett_ilp_T_measResult,
    &ett_ilp_CellGlobalIdEUTRA,
    &ett_ilp_PLMN_Identity,
    &ett_ilp_MCC,
    &ett_ilp_MNC,
    &ett_ilp_ServingInformation5G,
    &ett_ilp_NeighbourInformation5G,
    &ett_ilp_WlanAPInformation,
    &ett_ilp_RTD,
    &ett_ilp_ReportedLocation,
    &ett_ilp_LocationData,
    &ett_ilp_RepLocation,
    &ett_ilp_LciLocData,
    &ett_ilp_LocationDataLCI,
    &ett_ilp_WimaxBSInformation,
    &ett_ilp_WimaxBsID,
    &ett_ilp_WimaxRTD,
    &ett_ilp_WimaxNMRList,
    &ett_ilp_WimaxNMR,
    &ett_ilp_NRCellInformation,
    &ett_ilp_ServingCellInformationNR,
    &ett_ilp_ServCellNR,
    &ett_ilp_MeasResultListNR,
    &ett_ilp_MeasResultNR,
    &ett_ilp_CellGlobalIdNR,
    &ett_ilp_NR_Measurements,
    &ett_ilp_FrequencyInfo,
    &ett_ilp_FrequencySpecificInfo,
    &ett_ilp_FrequencyInfoFDD,
    &ett_ilp_FrequencyInfoTDD,
    &ett_ilp_NMR,
    &ett_ilp_NMRelement,
    &ett_ilp_MeasuredResultsList,
    &ett_ilp_MeasuredResults,
    &ett_ilp_CellMeasuredResultsList,
    &ett_ilp_CellMeasuredResults,
    &ett_ilp_T_modeSpecificInfo_02,
    &ett_ilp_T_fdd_02,
    &ett_ilp_T_tdd_02,
    &ett_ilp_TimeslotISCP_List,
    &ett_ilp_PrimaryCPICH_Info,
    &ett_ilp_UTRAN_GPSReferenceTimeAssistance,
    &ett_ilp_UTRAN_GPSReferenceTime,
    &ett_ilp_T_utran_GPSTimingOfCell,
    &ett_ilp_T_modeSpecificInfo_03,
    &ett_ilp_T_fdd_03,
    &ett_ilp_T_tdd_03,
    &ett_ilp_UTRAN_GANSSReferenceTimeAssistance,
    &ett_ilp_UTRAN_GANSSReferenceTime,
    &ett_ilp_T_modeSpecificInfo_04,
    &ett_ilp_T_fdd_04,
    &ett_ilp_T_tdd_04,
    &ett_ilp_QoP,
    &ett_ilp_Velocity,
    &ett_ilp_Horvel,
    &ett_ilp_Horandvervel,
    &ett_ilp_Horveluncert,
    &ett_ilp_Horandveruncert,
    &ett_ilp_SPCTID,
    &ett_ilp_PosPayLoad,
    &ett_ilp_MultiPosPayLoad,
    &ett_ilp_T_lPPPayload,
    &ett_ilp_T_tia801Payload,
  };

  module_t *ilp_module;


  /* Register protocol */
  proto_ilp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  ilp_tcp_handle = register_dissector("ilp", dissect_ilp_tcp, proto_ilp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ilp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ilp_module = prefs_register_protocol(proto_ilp, NULL);

  prefs_register_bool_preference(ilp_module, "desegment_ilp_messages",
        "Reassemble ILP messages spanning multiple TCP segments",
        "Whether the ILP dissector should reassemble messages spanning multiple TCP segments."
        " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
        &ilp_desegment);
}


/*--- proto_reg_handoff_ilp ---------------------------------------*/
void
proto_reg_handoff_ilp(void)
{
  dissector_handle_t ilp_pdu_handle;

  ilp_pdu_handle = create_dissector_handle(dissect_ILP_PDU_PDU, proto_ilp);
  rrlp_handle = find_dissector_add_dependency("rrlp", proto_ilp);
  lpp_handle = find_dissector_add_dependency("lpp", proto_ilp);

  dissector_add_string("media_type","application/oma-supl-ilp", ilp_pdu_handle);
  dissector_add_uint_with_preference("tcp.port", ILP_TCP_PORT, ilp_tcp_handle);
}
