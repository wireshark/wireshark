/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-rrlp.c                                                              */
/* asn2wrs.py -q -L -p rrlp -c ./rrlp.cnf -s ./packet-rrlp-template -D . -O ../.. ../gsm_map/MAP-ExtensionDataTypes.asn ../gsm_map/MAP-LCS-DataTypes.asn RRLP-Messages.asn RRLP-Components.asn */

/* packet-rrlp.c
 * Routines for 3GPP Radio Resource LCS Protocol (RRLP) packet dissection
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref 3GPP TS 44.031 version 11.0.0 Release 11
 * http://www.3gpp.org
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-gsm_a_common.h"

#define PNAME  "Radio Resource LCS Protocol (RRLP)"
#define PSNAME "RRLP"
#define PFNAME "rrlp"



#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

void proto_register_rrlp(void);
void proto_reg_handoff_rrlp(void);

/* Initialize the protocol and registered fields */
static int proto_rrlp;


static int hf_rrlp_PDU_PDU;                       /* PDU */
static int hf_rrlp_privateExtensionList;          /* PrivateExtensionList */
static int hf_rrlp_pcs_Extensions;                /* PCS_Extensions */
static int hf_rrlp_PrivateExtensionList_item;     /* PrivateExtension */
static int hf_rrlp_extId;                         /* OBJECT_IDENTIFIER */
static int hf_rrlp_extType;                       /* T_extType */
static int hf_rrlp_referenceNumber;               /* INTEGER_0_7 */
static int hf_rrlp_component;                     /* RRLP_Component */
static int hf_rrlp_msrPositionReq;                /* MsrPosition_Req */
static int hf_rrlp_msrPositionRsp;                /* MsrPosition_Rsp */
static int hf_rrlp_assistanceData;                /* AssistanceData */
static int hf_rrlp_assistanceDataAck;             /* NULL */
static int hf_rrlp_protocolError;                 /* ProtocolError */
static int hf_rrlp_posCapabilityReq;              /* PosCapability_Req */
static int hf_rrlp_posCapabilityRsp;              /* PosCapability_Rsp */
static int hf_rrlp_positionInstruct;              /* PositionInstruct */
static int hf_rrlp_referenceAssistData;           /* ReferenceAssistData */
static int hf_rrlp_msrAssistData;                 /* MsrAssistData */
static int hf_rrlp_systemInfoAssistData;          /* SystemInfoAssistData */
static int hf_rrlp_gps_AssistData;                /* GPS_AssistData */
static int hf_rrlp_extensionContainer;            /* ExtensionContainer */
static int hf_rrlp_rel98_MsrPosition_Req_extension;  /* Rel98_MsrPosition_Req_Extension */
static int hf_rrlp_rel5_MsrPosition_Req_extension;  /* Rel5_MsrPosition_Req_Extension */
static int hf_rrlp_rel7_MsrPosition_Req_extension;  /* Rel7_MsrPosition_Req_Extension */
static int hf_rrlp_multipleSets;                  /* MultipleSets */
static int hf_rrlp_referenceIdentity;             /* ReferenceIdentity */
static int hf_rrlp_otd_MeasureInfo;               /* OTD_MeasureInfo */
static int hf_rrlp_locationInfo;                  /* LocationInfo */
static int hf_rrlp_gps_MeasureInfo;               /* GPS_MeasureInfo */
static int hf_rrlp_locationError;                 /* LocationError */
static int hf_rrlp_rel_98_MsrPosition_Rsp_Extension;  /* Rel_98_MsrPosition_Rsp_Extension */
static int hf_rrlp_rel_5_MsrPosition_Rsp_Extension;  /* Rel_5_MsrPosition_Rsp_Extension */
static int hf_rrlp_rel_7_MsrPosition_Rsp_Extension;  /* Rel_7_MsrPosition_Rsp_Extension */
static int hf_rrlp_moreAssDataToBeSent;           /* MoreAssDataToBeSent */
static int hf_rrlp_rel98_AssistanceData_Extension;  /* Rel98_AssistanceData_Extension */
static int hf_rrlp_rel5_AssistanceData_Extension;  /* Rel5_AssistanceData_Extension */
static int hf_rrlp_rel7_AssistanceData_Extension;  /* Rel7_AssistanceData_Extension */
static int hf_rrlp_errorCause;                    /* ErrorCodes */
static int hf_rrlp_rel_5_ProtocolError_Extension;  /* Rel_5_ProtocolError_Extension */
static int hf_rrlp_extended_reference;            /* Extended_reference */
static int hf_rrlp_gANSSPositionMethods;          /* GANSSPositionMethods */
static int hf_rrlp_posCapabilities;               /* PosCapabilities */
static int hf_rrlp_assistanceSupported;           /* AssistanceSupported */
static int hf_rrlp_assistanceNeeded;              /* AssistanceNeeded */
static int hf_rrlp_methodType;                    /* MethodType */
static int hf_rrlp_positionMethod;                /* PositionMethod */
static int hf_rrlp_measureResponseTime;           /* MeasureResponseTime */
static int hf_rrlp_useMultipleSets;               /* UseMultipleSets */
static int hf_rrlp_environmentCharacter;          /* EnvironmentCharacter */
static int hf_rrlp_msAssisted;                    /* AccuracyOpt */
static int hf_rrlp_msBased;                       /* Accuracy */
static int hf_rrlp_msBasedPref;                   /* Accuracy */
static int hf_rrlp_msAssistedPref;                /* Accuracy */
static int hf_rrlp_accuracy;                      /* Accuracy */
static int hf_rrlp_bcchCarrier;                   /* BCCHCarrier */
static int hf_rrlp_bsic;                          /* BSIC */
static int hf_rrlp_timeSlotScheme;                /* TimeSlotScheme */
static int hf_rrlp_btsPosition;                   /* BTSPosition */
static int hf_rrlp_msrAssistList;                 /* SeqOfMsrAssistBTS */
static int hf_rrlp_SeqOfMsrAssistBTS_item;        /* MsrAssistBTS */
static int hf_rrlp_multiFrameOffset;              /* MultiFrameOffset */
static int hf_rrlp_roughRTD;                      /* RoughRTD */
static int hf_rrlp_calcAssistanceBTS;             /* CalcAssistanceBTS */
static int hf_rrlp_systemInfoAssistList;          /* SeqOfSystemInfoAssistBTS */
static int hf_rrlp_SeqOfSystemInfoAssistBTS_item;  /* SystemInfoAssistBTS */
static int hf_rrlp_notPresent;                    /* NULL */
static int hf_rrlp_present;                       /* AssistBTSData */
static int hf_rrlp_fineRTD;                       /* FineRTD */
static int hf_rrlp_referenceWGS84;                /* ReferenceWGS84 */
static int hf_rrlp_relativeNorth;                 /* RelDistance */
static int hf_rrlp_relativeEast;                  /* RelDistance */
static int hf_rrlp_relativeAlt;                   /* RelativeAlt */
static int hf_rrlp_nbrOfSets;                     /* INTEGER_2_3 */
static int hf_rrlp_nbrOfReferenceBTSs;            /* INTEGER_1_3 */
static int hf_rrlp_referenceRelation;             /* ReferenceRelation */
static int hf_rrlp_refBTSList;                    /* SeqOfReferenceIdentityType */
static int hf_rrlp_SeqOfReferenceIdentityType_item;  /* ReferenceIdentityType */
static int hf_rrlp_bsicAndCarrier;                /* BSICAndCarrier */
static int hf_rrlp_ci;                            /* CellID */
static int hf_rrlp_requestIndex;                  /* RequestIndex */
static int hf_rrlp_systemInfoIndex;               /* SystemInfoIndex */
static int hf_rrlp_ciAndLAC;                      /* CellIDAndLAC */
static int hf_rrlp_carrier;                       /* BCCHCarrier */
static int hf_rrlp_referenceLAC;                  /* LAC */
static int hf_rrlp_referenceCI;                   /* CellID */
static int hf_rrlp_otdMsrFirstSets;               /* OTD_MsrElementFirst */
static int hf_rrlp_otdMsrRestSets;                /* SeqOfOTD_MsrElementRest */
static int hf_rrlp_SeqOfOTD_MsrElementRest_item;  /* OTD_MsrElementRest */
static int hf_rrlp_refFrameNumber;                /* INTEGER_0_42431 */
static int hf_rrlp_referenceTimeSlot;             /* ModuloTimeSlot */
static int hf_rrlp_toaMeasurementsOfRef;          /* TOA_MeasurementsOfRef */
static int hf_rrlp_stdResolution;                 /* StdResolution */
static int hf_rrlp_taCorrection;                  /* INTEGER_0_960 */
static int hf_rrlp_otd_FirstSetMsrs;              /* SeqOfOTD_FirstSetMsrs */
static int hf_rrlp_SeqOfOTD_FirstSetMsrs_item;    /* OTD_FirstSetMsrs */
static int hf_rrlp_otd_MsrsOfOtherSets;           /* SeqOfOTD_MsrsOfOtherSets */
static int hf_rrlp_SeqOfOTD_MsrsOfOtherSets_item;  /* OTD_MsrsOfOtherSets */
static int hf_rrlp_refQuality;                    /* RefQuality */
static int hf_rrlp_numOfMeasurements;             /* NumOfMeasurements */
static int hf_rrlp_identityNotPresent;            /* OTD_Measurement */
static int hf_rrlp_identityPresent;               /* OTD_MeasurementWithID */
static int hf_rrlp_nborTimeSlot;                  /* ModuloTimeSlot */
static int hf_rrlp_eotdQuality;                   /* EOTDQuality */
static int hf_rrlp_otdValue;                      /* OTDValue */
static int hf_rrlp_neighborIdentity;              /* NeighborIdentity */
static int hf_rrlp_nbrOfMeasurements;             /* INTEGER_0_7 */
static int hf_rrlp_stdOfEOTD;                     /* INTEGER_0_31 */
static int hf_rrlp_multiFrameCarrier;             /* MultiFrameCarrier */
static int hf_rrlp_refFrame;                      /* INTEGER_0_65535 */
static int hf_rrlp_gpsTOW;                        /* INTEGER_0_14399999 */
static int hf_rrlp_fixType;                       /* FixType */
static int hf_rrlp_posEstimate;                   /* Ext_GeographicalInformation */
static int hf_rrlp_gpsMsrSetList;                 /* SeqOfGPS_MsrSetElement */
static int hf_rrlp_SeqOfGPS_MsrSetElement_item;   /* GPS_MsrSetElement */
static int hf_rrlp_gpsTOW_01;                     /* GPSTOW24b */
static int hf_rrlp_gps_msrList;                   /* SeqOfGPS_MsrElement */
static int hf_rrlp_SeqOfGPS_MsrElement_item;      /* GPS_MsrElement */
static int hf_rrlp_satelliteID;                   /* SatelliteID */
static int hf_rrlp_cNo;                           /* INTEGER_0_63 */
static int hf_rrlp_doppler;                       /* INTEGER_M32768_32767 */
static int hf_rrlp_wholeChips;                    /* INTEGER_0_1022 */
static int hf_rrlp_fracChips;                     /* INTEGER_0_1024 */
static int hf_rrlp_mpathIndic;                    /* MpathIndic */
static int hf_rrlp_pseuRangeRMSErr;               /* INTEGER_0_63 */
static int hf_rrlp_locErrorReason;                /* LocErrorReason */
static int hf_rrlp_additionalAssistanceData;      /* AdditionalAssistanceData */
static int hf_rrlp_gpsAssistanceData;             /* GPSAssistanceData */
static int hf_rrlp_ganssAssistanceData;           /* GANSSAssistanceData */
static int hf_rrlp_controlHeader;                 /* ControlHeader */
static int hf_rrlp_referenceTime;                 /* ReferenceTime */
static int hf_rrlp_refLocation;                   /* RefLocation */
static int hf_rrlp_dgpsCorrections;               /* DGPSCorrections */
static int hf_rrlp_navigationModel;               /* NavigationModel */
static int hf_rrlp_ionosphericModel;              /* IonosphericModel */
static int hf_rrlp_utcModel;                      /* UTCModel */
static int hf_rrlp_almanac;                       /* Almanac */
static int hf_rrlp_acquisAssist;                  /* AcquisAssist */
static int hf_rrlp_realTimeIntegrity;             /* SeqOf_BadSatelliteSet */
static int hf_rrlp_gpsTime;                       /* GPSTime */
static int hf_rrlp_gsmTime;                       /* GSMTime */
static int hf_rrlp_gpsTowAssist;                  /* GPSTOWAssist */
static int hf_rrlp_gpsTOW23b;                     /* GPSTOW23b */
static int hf_rrlp_gpsWeek;                       /* GPSWeek */
static int hf_rrlp_GPSTOWAssist_item;             /* GPSTOWAssistElement */
static int hf_rrlp_tlmWord;                       /* TLMWord */
static int hf_rrlp_antiSpoof;                     /* AntiSpoofFlag */
static int hf_rrlp_alert;                         /* AlertFlag */
static int hf_rrlp_tlmRsvdBits;                   /* TLMReservedBits */
static int hf_rrlp_frameNumber;                   /* FrameNumber */
static int hf_rrlp_timeSlot;                      /* TimeSlot */
static int hf_rrlp_bitNumber;                     /* BitNumber */
static int hf_rrlp_threeDLocation;                /* Ext_GeographicalInformation */
static int hf_rrlp_gpsTOW_02;                     /* INTEGER_0_604799 */
static int hf_rrlp_status;                        /* INTEGER_0_7 */
static int hf_rrlp_satList;                       /* SeqOfSatElement */
static int hf_rrlp_SeqOfSatElement_item;          /* SatElement */
static int hf_rrlp_iode;                          /* INTEGER_0_239 */
static int hf_rrlp_udre;                          /* INTEGER_0_3 */
static int hf_rrlp_pseudoRangeCor;                /* INTEGER_M2047_2047 */
static int hf_rrlp_rangeRateCor;                  /* INTEGER_M127_127 */
static int hf_rrlp_deltaPseudoRangeCor2;          /* INTEGER_M127_127 */
static int hf_rrlp_deltaRangeRateCor2;            /* INTEGER_M7_7 */
static int hf_rrlp_deltaPseudoRangeCor3;          /* INTEGER_M127_127 */
static int hf_rrlp_deltaRangeRateCor3;            /* INTEGER_M7_7 */
static int hf_rrlp_navModelList;                  /* SeqOfNavModelElement */
static int hf_rrlp_SeqOfNavModelElement_item;     /* NavModelElement */
static int hf_rrlp_satStatus;                     /* SatStatus */
static int hf_rrlp_newSatelliteAndModelUC;        /* UncompressedEphemeris */
static int hf_rrlp_oldSatelliteAndModel;          /* NULL */
static int hf_rrlp_newNaviModelUC;                /* UncompressedEphemeris */
static int hf_rrlp_ephemCodeOnL2;                 /* INTEGER_0_3 */
static int hf_rrlp_ephemURA;                      /* INTEGER_0_15 */
static int hf_rrlp_ephemSVhealth;                 /* INTEGER_0_63 */
static int hf_rrlp_ephemIODC;                     /* INTEGER_0_1023 */
static int hf_rrlp_ephemL2Pflag;                  /* INTEGER_0_1 */
static int hf_rrlp_ephemSF1Rsvd;                  /* EphemerisSubframe1Reserved */
static int hf_rrlp_ephemTgd;                      /* INTEGER_M128_127 */
static int hf_rrlp_ephemToc;                      /* INTEGER_0_37799 */
static int hf_rrlp_ephemAF2;                      /* INTEGER_M128_127 */
static int hf_rrlp_ephemAF1;                      /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemAF0;                      /* INTEGER_M2097152_2097151 */
static int hf_rrlp_ephemCrs;                      /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemDeltaN;                   /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemM0;                       /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_ephemCuc;                      /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemE;                        /* INTEGER_0_4294967295 */
static int hf_rrlp_ephemCus;                      /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemAPowerHalf;               /* INTEGER_0_4294967295 */
static int hf_rrlp_ephemToe;                      /* INTEGER_0_37799 */
static int hf_rrlp_ephemFitFlag;                  /* INTEGER_0_1 */
static int hf_rrlp_ephemAODA;                     /* INTEGER_0_31 */
static int hf_rrlp_ephemCic;                      /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemOmegaA0;                  /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_ephemCis;                      /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemI0;                       /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_ephemCrc;                      /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemW;                        /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_ephemOmegaADot;                /* INTEGER_M8388608_8388607 */
static int hf_rrlp_ephemIDot;                     /* INTEGER_M8192_8191 */
static int hf_rrlp_reserved1;                     /* INTEGER_0_8388607 */
static int hf_rrlp_reserved2;                     /* INTEGER_0_16777215 */
static int hf_rrlp_reserved3;                     /* INTEGER_0_16777215 */
static int hf_rrlp_reserved4;                     /* INTEGER_0_65535 */
static int hf_rrlp_alfa0;                         /* INTEGER_M128_127 */
static int hf_rrlp_alfa1;                         /* INTEGER_M128_127 */
static int hf_rrlp_alfa2;                         /* INTEGER_M128_127 */
static int hf_rrlp_alfa3;                         /* INTEGER_M128_127 */
static int hf_rrlp_beta0;                         /* INTEGER_M128_127 */
static int hf_rrlp_beta1;                         /* INTEGER_M128_127 */
static int hf_rrlp_beta2;                         /* INTEGER_M128_127 */
static int hf_rrlp_beta3;                         /* INTEGER_M128_127 */
static int hf_rrlp_utcA1;                         /* INTEGER_M8388608_8388607 */
static int hf_rrlp_utcA0;                         /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_utcTot;                        /* INTEGER_0_255 */
static int hf_rrlp_utcWNt;                        /* INTEGER_0_255 */
static int hf_rrlp_utcDeltaTls;                   /* INTEGER_M128_127 */
static int hf_rrlp_utcWNlsf;                      /* INTEGER_0_255 */
static int hf_rrlp_utcDN;                         /* INTEGER_M128_127 */
static int hf_rrlp_utcDeltaTlsf;                  /* INTEGER_M128_127 */
static int hf_rrlp_alamanacWNa;                   /* INTEGER_0_255 */
static int hf_rrlp_almanacList;                   /* SeqOfAlmanacElement */
static int hf_rrlp_SeqOfAlmanacElement_item;      /* AlmanacElement */
static int hf_rrlp_almanacE;                      /* INTEGER_0_65535 */
static int hf_rrlp_alamanacToa;                   /* INTEGER_0_255 */
static int hf_rrlp_almanacKsii;                   /* INTEGER_M32768_32767 */
static int hf_rrlp_almanacOmegaDot;               /* INTEGER_M32768_32767 */
static int hf_rrlp_almanacSVhealth;               /* INTEGER_0_255 */
static int hf_rrlp_almanacAPowerHalf;             /* INTEGER_0_16777215 */
static int hf_rrlp_almanacOmega0;                 /* INTEGER_M8388608_8388607 */
static int hf_rrlp_almanacW;                      /* INTEGER_M8388608_8388607 */
static int hf_rrlp_almanacM0;                     /* INTEGER_M8388608_8388607 */
static int hf_rrlp_almanacAF0;                    /* INTEGER_M1024_1023 */
static int hf_rrlp_almanacAF1;                    /* INTEGER_M1024_1023 */
static int hf_rrlp_timeRelation;                  /* TimeRelation */
static int hf_rrlp_acquisList;                    /* SeqOfAcquisElement */
static int hf_rrlp_SeqOfAcquisElement_item;       /* AcquisElement */
static int hf_rrlp_gpsTOW_03;                     /* GPSTOW23b */
static int hf_rrlp_svid;                          /* SatelliteID */
static int hf_rrlp_doppler0;                      /* INTEGER_M2048_2047 */
static int hf_rrlp_addionalDoppler;               /* AddionalDopplerFields */
static int hf_rrlp_codePhase;                     /* INTEGER_0_1022 */
static int hf_rrlp_intCodePhase;                  /* INTEGER_0_19 */
static int hf_rrlp_gpsBitNumber;                  /* INTEGER_0_3 */
static int hf_rrlp_codePhaseSearchWindow;         /* INTEGER_0_15 */
static int hf_rrlp_addionalAngle;                 /* AddionalAngleFields */
static int hf_rrlp_doppler1;                      /* INTEGER_0_63 */
static int hf_rrlp_dopplerUncertainty;            /* INTEGER_0_7 */
static int hf_rrlp_azimuth;                       /* INTEGER_0_31 */
static int hf_rrlp_elevation;                     /* INTEGER_0_7 */
static int hf_rrlp_SeqOf_BadSatelliteSet_item;    /* SatelliteID */
static int hf_rrlp_rel98_Ext_ExpOTD;              /* Rel98_Ext_ExpOTD */
static int hf_rrlp_gpsTimeAssistanceMeasurementRequest;  /* NULL */
static int hf_rrlp_gpsReferenceTimeUncertainty;   /* GPSReferenceTimeUncertainty */
static int hf_rrlp_msrAssistData_R98_ExpOTD;      /* MsrAssistData_R98_ExpOTD */
static int hf_rrlp_systemInfoAssistData_R98_ExpOTD;  /* SystemInfoAssistData_R98_ExpOTD */
static int hf_rrlp_msrAssistList_R98_ExpOTD;      /* SeqOfMsrAssistBTS_R98_ExpOTD */
static int hf_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD_item;  /* MsrAssistBTS_R98_ExpOTD */
static int hf_rrlp_expectedOTD;                   /* ExpectedOTD */
static int hf_rrlp_expOTDUncertainty;             /* ExpOTDUncertainty */
static int hf_rrlp_systemInfoAssistListR98_ExpOTD;  /* SeqOfSystemInfoAssistBTS_R98_ExpOTD */
static int hf_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD_item;  /* SystemInfoAssistBTS_R98_ExpOTD */
static int hf_rrlp_present_01;                    /* AssistBTSData_R98_ExpOTD */
static int hf_rrlp_expOTDuncertainty;             /* ExpOTDUncertainty */
static int hf_rrlp_referenceFrameMSB;             /* INTEGER_0_63 */
static int hf_rrlp_gpsTowSubms;                   /* INTEGER_0_9999 */
static int hf_rrlp_deltaTow;                      /* INTEGER_0_127 */
static int hf_rrlp_rel_98_Ext_MeasureInfo;        /* T_rel_98_Ext_MeasureInfo */
static int hf_rrlp_otd_MeasureInfo_R98_Ext;       /* OTD_MeasureInfo_R98_Ext */
static int hf_rrlp_timeAssistanceMeasurements;    /* GPSTimeAssistanceMeasurements */
static int hf_rrlp_otdMsrFirstSets_R98_Ext;       /* OTD_MsrElementFirst_R98_Ext */
static int hf_rrlp_otd_FirstSetMsrs_R98_Ext;      /* SeqOfOTD_FirstSetMsrs_R98_Ext */
static int hf_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext_item;  /* OTD_FirstSetMsrs */
static int hf_rrlp_otd_MeasureInfo_5_Ext;         /* OTD_MeasureInfo_5_Ext */
static int hf_rrlp_ulPseudoSegInd;                /* UlPseudoSegInd */
static int hf_rrlp_smlc_code;                     /* INTEGER_0_63 */
static int hf_rrlp_transaction_ID;                /* INTEGER_0_262143 */
static int hf_rrlp_velocityRequested;             /* NULL */
static int hf_rrlp_ganssPositionMethod;           /* GANSSPositioningMethod */
static int hf_rrlp_ganss_AssistData;              /* GANSS_AssistData */
static int hf_rrlp_ganssCarrierPhaseMeasurementRequest;  /* NULL */
static int hf_rrlp_ganssTODGSMTimeAssociationMeasurementRequest;  /* NULL */
static int hf_rrlp_requiredResponseTime;          /* RequiredResponseTime */
static int hf_rrlp_add_GPS_AssistData;            /* Add_GPS_AssistData */
static int hf_rrlp_ganssMultiFreqMeasurementRequest;  /* NULL */
static int hf_rrlp_ganss_controlHeader;           /* GANSS_ControlHeader */
static int hf_rrlp_ganssCommonAssistData;         /* GANSSCommonAssistData */
static int hf_rrlp_ganssGenericAssistDataList;    /* SeqOfGANSSGenericAssistDataElement */
static int hf_rrlp_ganssReferenceTime;            /* GANSSReferenceTime */
static int hf_rrlp_ganssRefLocation;              /* GANSSRefLocation */
static int hf_rrlp_ganssIonosphericModel;         /* GANSSIonosphericModel */
static int hf_rrlp_ganssAddIonosphericModel;      /* GANSSAddIonosphericModel */
static int hf_rrlp_ganssEarthOrientParam;         /* GANSSEarthOrientParam */
static int hf_rrlp_ganssReferenceTime_R10_Ext;    /* GANSSReferenceTime_R10_Ext */
static int hf_rrlp_SeqOfGANSSGenericAssistDataElement_item;  /* GANSSGenericAssistDataElement */
static int hf_rrlp_ganssID;                       /* INTEGER_0_7 */
static int hf_rrlp_ganssTimeModel;                /* SeqOfGANSSTimeModel */
static int hf_rrlp_ganssDiffCorrections;          /* GANSSDiffCorrections */
static int hf_rrlp_ganssNavigationModel;          /* GANSSNavModel */
static int hf_rrlp_ganssRealTimeIntegrity;        /* GANSSRealTimeIntegrity */
static int hf_rrlp_ganssDataBitAssist;            /* GANSSDataBitAssist */
static int hf_rrlp_ganssRefMeasurementAssist;     /* GANSSRefMeasurementAssist */
static int hf_rrlp_ganssAlmanacModel;             /* GANSSAlmanacModel */
static int hf_rrlp_ganssUTCModel;                 /* GANSSUTCModel */
static int hf_rrlp_ganssEphemerisExtension;       /* GANSSEphemerisExtension */
static int hf_rrlp_ganssEphemerisExtCheck;        /* GANSSEphemerisExtensionCheck */
static int hf_rrlp_sbasID;                        /* INTEGER_0_7 */
static int hf_rrlp_ganssAddUTCModel;              /* GANSSAddUTCModel */
static int hf_rrlp_ganssAuxiliaryInfo;            /* GANSSAuxiliaryInformation */
static int hf_rrlp_ganssDiffCorrectionsValidityPeriod;  /* GANSSDiffCorrectionsValidityPeriod */
static int hf_rrlp_ganssTimeModel_R10_Ext;        /* SeqOfGANSSTimeModel_R10_Ext */
static int hf_rrlp_ganssRefMeasurementAssist_R10_Ext;  /* GANSSRefMeasurementAssist_R10_Ext */
static int hf_rrlp_ganssAlmanacModel_R10_Ext;     /* GANSSAlmanacModel_R10_Ext */
static int hf_rrlp_ganssRefTimeInfo;              /* GANSSRefTimeInfo */
static int hf_rrlp_ganssTOD_GSMTimeAssociation;   /* GANSSTOD_GSMTimeAssociation */
static int hf_rrlp_ganssDay;                      /* INTEGER_0_8191 */
static int hf_rrlp_ganssTOD;                      /* GANSSTOD */
static int hf_rrlp_ganssTODUncertainty;           /* GANSSTODUncertainty */
static int hf_rrlp_ganssTimeID;                   /* INTEGER_0_7 */
static int hf_rrlp_ganssDayCycleNumber;           /* INTEGER_0_7 */
static int hf_rrlp_frameDrift;                    /* FrameDrift */
static int hf_rrlp_ganssIonoModel;                /* GANSSIonosphereModel */
static int hf_rrlp_ganssIonoStormFlags;           /* GANSSIonoStormFlags */
static int hf_rrlp_ai0;                           /* INTEGER_0_4095 */
static int hf_rrlp_ai1;                           /* INTEGER_0_4095 */
static int hf_rrlp_ai2;                           /* INTEGER_0_4095 */
static int hf_rrlp_ionoStormFlag1;                /* INTEGER_0_1 */
static int hf_rrlp_ionoStormFlag2;                /* INTEGER_0_1 */
static int hf_rrlp_ionoStormFlag3;                /* INTEGER_0_1 */
static int hf_rrlp_ionoStormFlag4;                /* INTEGER_0_1 */
static int hf_rrlp_ionoStormFlag5;                /* INTEGER_0_1 */
static int hf_rrlp_dataID;                        /* BIT_STRING_SIZE_2 */
static int hf_rrlp_ionoModel;                     /* IonosphericModel */
static int hf_rrlp_teop;                          /* INTEGER_0_65535 */
static int hf_rrlp_pmX;                           /* INTEGER_M1048576_1048575 */
static int hf_rrlp_pmXdot;                        /* INTEGER_M16384_16383 */
static int hf_rrlp_pmY;                           /* INTEGER_M1048576_1048575 */
static int hf_rrlp_pmYdot;                        /* INTEGER_M16384_16383 */
static int hf_rrlp_deltaUT1;                      /* INTEGER_M1073741824_1073741823 */
static int hf_rrlp_deltaUT1dot;                   /* INTEGER_M262144_262143 */
static int hf_rrlp_SeqOfGANSSTimeModel_item;      /* GANSSTimeModelElement */
static int hf_rrlp_ganssTimeModelRefTime;         /* INTEGER_0_65535 */
static int hf_rrlp_tA0;                           /* TA0 */
static int hf_rrlp_tA1;                           /* TA1 */
static int hf_rrlp_tA2;                           /* TA2 */
static int hf_rrlp_gnssTOID;                      /* INTEGER_0_7 */
static int hf_rrlp_weekNumber;                    /* INTEGER_0_8191 */
static int hf_rrlp_SeqOfGANSSTimeModel_R10_Ext_item;  /* GANSSTimeModelElement_R10_Ext */
static int hf_rrlp_deltaT;                        /* INTEGER_M128_127 */
static int hf_rrlp_dganssRefTime;                 /* INTEGER_0_119 */
static int hf_rrlp_sgnTypeList;                   /* SeqOfSgnTypeElement */
static int hf_rrlp_SeqOfSgnTypeElement_item;      /* SgnTypeElement */
static int hf_rrlp_ganssSignalID;                 /* GANSSSignalID */
static int hf_rrlp_ganssStatusHealth;             /* INTEGER_0_7 */
static int hf_rrlp_dganssSgnList;                 /* SeqOfDGANSSSgnElement */
static int hf_rrlp_SeqOfDGANSSSgnElement_item;    /* DGANSSSgnElement */
static int hf_rrlp_svID;                          /* SVID */
static int hf_rrlp_iod;                           /* INTEGER_0_1023 */
static int hf_rrlp_nonBroadcastIndFlag;           /* INTEGER_0_1 */
static int hf_rrlp_ganssSatelliteList;            /* SeqOfGANSSSatelliteElement */
static int hf_rrlp_SeqOfGANSSSatelliteElement_item;  /* GANSSSatelliteElement */
static int hf_rrlp_svHealth;                      /* BIT_STRING_SIZE_5 */
static int hf_rrlp_ganssClockModel;               /* GANSSClockModel */
static int hf_rrlp_ganssOrbitModel;               /* GANSSOrbitModel */
static int hf_rrlp_svHealthMSB;                   /* BIT_STRING_SIZE_1 */
static int hf_rrlp_iodMSB;                        /* INTEGER_0_1 */
static int hf_rrlp_keplerianSet;                  /* NavModel_KeplerianSet */
static int hf_rrlp_navKeplerianSet;               /* NavModel_NAVKeplerianSet */
static int hf_rrlp_cnavKeplerianSet;              /* NavModel_CNAVKeplerianSet */
static int hf_rrlp_glonassECEF;                   /* NavModel_GLONASSecef */
static int hf_rrlp_sbasECEF;                      /* NavModel_SBASecef */
static int hf_rrlp_keplerToe;                     /* INTEGER_0_16383 */
static int hf_rrlp_keplerW;                       /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_keplerDeltaN;                  /* INTEGER_M32768_32767 */
static int hf_rrlp_keplerM0;                      /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_keplerOmegaDot;                /* INTEGER_M8388608_8388607 */
static int hf_rrlp_keplerE;                       /* INTEGER_0_4294967295 */
static int hf_rrlp_keplerIDot;                    /* INTEGER_M8192_8191 */
static int hf_rrlp_keplerAPowerHalf;              /* INTEGER_0_4294967295 */
static int hf_rrlp_keplerI0;                      /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_keplerOmega0;                  /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_keplerCrs;                     /* INTEGER_M32768_32767 */
static int hf_rrlp_keplerCis;                     /* INTEGER_M32768_32767 */
static int hf_rrlp_keplerCus;                     /* INTEGER_M32768_32767 */
static int hf_rrlp_keplerCrc;                     /* INTEGER_M32768_32767 */
static int hf_rrlp_keplerCic;                     /* INTEGER_M32768_32767 */
static int hf_rrlp_keplerCuc;                     /* INTEGER_M32768_32767 */
static int hf_rrlp_navURA;                        /* INTEGER_0_15 */
static int hf_rrlp_navFitFlag;                    /* INTEGER_0_1 */
static int hf_rrlp_navToe;                        /* INTEGER_0_37799 */
static int hf_rrlp_navOmega;                      /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_navDeltaN;                     /* INTEGER_M32768_32767 */
static int hf_rrlp_navM0;                         /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_navOmegaADot;                  /* INTEGER_M8388608_8388607 */
static int hf_rrlp_navE;                          /* INTEGER_0_4294967295 */
static int hf_rrlp_navIDot;                       /* INTEGER_M8192_8191 */
static int hf_rrlp_navAPowerHalf;                 /* INTEGER_0_4294967295 */
static int hf_rrlp_navI0;                         /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_navOmegaA0;                    /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_navCrs;                        /* INTEGER_M32768_32767 */
static int hf_rrlp_navCis;                        /* INTEGER_M32768_32767 */
static int hf_rrlp_navCus;                        /* INTEGER_M32768_32767 */
static int hf_rrlp_navCrc;                        /* INTEGER_M32768_32767 */
static int hf_rrlp_navCic;                        /* INTEGER_M32768_32767 */
static int hf_rrlp_navCuc;                        /* INTEGER_M32768_32767 */
static int hf_rrlp_cnavTop;                       /* INTEGER_0_2015 */
static int hf_rrlp_cnavURAindex;                  /* INTEGER_M16_15 */
static int hf_rrlp_cnavDeltaA;                    /* INTEGER_M33554432_33554431 */
static int hf_rrlp_cnavAdot;                      /* INTEGER_M16777216_16777215 */
static int hf_rrlp_cnavDeltaNo;                   /* INTEGER_M65536_65535 */
static int hf_rrlp_cnavDeltaNoDot;                /* INTEGER_M4194304_4194303 */
static int hf_rrlp_cnavMo;                        /* INTEGER_M4294967296_4294967295 */
static int hf_rrlp_cnavE;                         /* INTEGER_0_8589934591 */
static int hf_rrlp_cnavOmega;                     /* INTEGER_M4294967296_4294967295 */
static int hf_rrlp_cnavOMEGA0;                    /* INTEGER_M4294967296_4294967295 */
static int hf_rrlp_cnavDeltaOmegaDot;             /* INTEGER_M65536_65535 */
static int hf_rrlp_cnavIo;                        /* INTEGER_M4294967296_4294967295 */
static int hf_rrlp_cnavIoDot;                     /* INTEGER_M16384_16383 */
static int hf_rrlp_cnavCis;                       /* INTEGER_M32768_32767 */
static int hf_rrlp_cnavCic;                       /* INTEGER_M32768_32767 */
static int hf_rrlp_cnavCrs;                       /* INTEGER_M8388608_8388607 */
static int hf_rrlp_cnavCrc;                       /* INTEGER_M8388608_8388607 */
static int hf_rrlp_cnavCus;                       /* INTEGER_M1048576_1048575 */
static int hf_rrlp_cnavCuc;                       /* INTEGER_M1048576_1048575 */
static int hf_rrlp_gloEn;                         /* INTEGER_0_31 */
static int hf_rrlp_gloP1;                         /* BIT_STRING_SIZE_2 */
static int hf_rrlp_gloP2;                         /* BOOLEAN */
static int hf_rrlp_gloM;                          /* INTEGER_0_3 */
static int hf_rrlp_gloX;                          /* INTEGER_M67108864_67108863 */
static int hf_rrlp_gloXdot;                       /* INTEGER_M8388608_8388607 */
static int hf_rrlp_gloXdotdot;                    /* INTEGER_M16_15 */
static int hf_rrlp_gloY;                          /* INTEGER_M67108864_67108863 */
static int hf_rrlp_gloYdot;                       /* INTEGER_M8388608_8388607 */
static int hf_rrlp_gloYdotdot;                    /* INTEGER_M16_15 */
static int hf_rrlp_gloZ;                          /* INTEGER_M67108864_67108863 */
static int hf_rrlp_gloZdot;                       /* INTEGER_M8388608_8388607 */
static int hf_rrlp_gloZdotdot;                    /* INTEGER_M16_15 */
static int hf_rrlp_sbasTo;                        /* INTEGER_0_5399 */
static int hf_rrlp_sbasAccuracy;                  /* BIT_STRING_SIZE_4 */
static int hf_rrlp_sbasXg;                        /* INTEGER_M536870912_536870911 */
static int hf_rrlp_sbasYg;                        /* INTEGER_M536870912_536870911 */
static int hf_rrlp_sbasZg;                        /* INTEGER_M16777216_16777215 */
static int hf_rrlp_sbasXgDot;                     /* INTEGER_M65536_65535 */
static int hf_rrlp_sbasYgDot;                     /* INTEGER_M65536_65535 */
static int hf_rrlp_sbasZgDot;                     /* INTEGER_M131072_131071 */
static int hf_rrlp_sbasXgDotDot;                  /* INTEGER_M512_511 */
static int hf_rrlp_sbagYgDotDot;                  /* INTEGER_M512_511 */
static int hf_rrlp_sbasZgDotDot;                  /* INTEGER_M512_511 */
static int hf_rrlp_standardClockModelList;        /* SeqOfStandardClockModelElement */
static int hf_rrlp_navClockModel;                 /* NAVclockModel */
static int hf_rrlp_cnavClockModel;                /* CNAVclockModel */
static int hf_rrlp_glonassClockModel;             /* GLONASSclockModel */
static int hf_rrlp_sbasClockModel;                /* SBASclockModel */
static int hf_rrlp_SeqOfStandardClockModelElement_item;  /* StandardClockModelElement */
static int hf_rrlp_stanClockToc;                  /* INTEGER_0_16383 */
static int hf_rrlp_stanClockAF2;                  /* INTEGER_M2048_2047 */
static int hf_rrlp_stanClockAF1;                  /* INTEGER_M131072_131071 */
static int hf_rrlp_stanClockAF0;                  /* INTEGER_M134217728_134217727 */
static int hf_rrlp_stanClockTgd;                  /* INTEGER_M512_511 */
static int hf_rrlp_stanModelID;                   /* INTEGER_0_1 */
static int hf_rrlp_navToc;                        /* INTEGER_0_37799 */
static int hf_rrlp_navaf2;                        /* INTEGER_M128_127 */
static int hf_rrlp_navaf1;                        /* INTEGER_M32768_32767 */
static int hf_rrlp_navaf0;                        /* INTEGER_M2097152_2097151 */
static int hf_rrlp_navTgd;                        /* INTEGER_M128_127 */
static int hf_rrlp_cnavToc;                       /* INTEGER_0_2015 */
static int hf_rrlp_cnavURA0;                      /* INTEGER_M16_15 */
static int hf_rrlp_cnavURA1;                      /* INTEGER_0_7 */
static int hf_rrlp_cnavURA2;                      /* INTEGER_0_7 */
static int hf_rrlp_cnavAf2;                       /* INTEGER_M512_511 */
static int hf_rrlp_cnavAf1;                       /* INTEGER_M524288_524287 */
static int hf_rrlp_cnavAf0;                       /* INTEGER_M33554432_33554431 */
static int hf_rrlp_cnavTgd;                       /* INTEGER_M4096_4095 */
static int hf_rrlp_cnavISCl1cp;                   /* INTEGER_M4096_4095 */
static int hf_rrlp_cnavISCl1cd;                   /* INTEGER_M4096_4095 */
static int hf_rrlp_cnavISCl1ca;                   /* INTEGER_M4096_4095 */
static int hf_rrlp_cnavISCl2c;                    /* INTEGER_M4096_4095 */
static int hf_rrlp_cnavISCl5i5;                   /* INTEGER_M4096_4095 */
static int hf_rrlp_cnavISCl5q5;                   /* INTEGER_M4096_4095 */
static int hf_rrlp_gloTau;                        /* INTEGER_M2097152_2097151 */
static int hf_rrlp_gloGamma;                      /* INTEGER_M1024_1023 */
static int hf_rrlp_gloDeltaTau;                   /* INTEGER_M16_15 */
static int hf_rrlp_sbasAgfo;                      /* INTEGER_M2048_2047 */
static int hf_rrlp_sbasAgf1;                      /* INTEGER_M128_127 */
static int hf_rrlp_ganssBadSignalList;            /* SeqOfBadSignalElement */
static int hf_rrlp_SeqOfBadSignalElement_item;    /* BadSignalElement */
static int hf_rrlp_badSVID;                       /* SVID */
static int hf_rrlp_badSignalID;                   /* GANSSSignals */
static int hf_rrlp_ganssTOD_01;                   /* INTEGER_0_59 */
static int hf_rrlp_ganssDataBitsSatList;          /* SeqOfGanssDataBitsElement */
static int hf_rrlp_SeqOfGanssDataBitsElement_item;  /* GanssDataBitsElement */
static int hf_rrlp_ganssDataBitsSgnList;          /* Seq_OfGANSSDataBitsSgn */
static int hf_rrlp_Seq_OfGANSSDataBitsSgn_item;   /* GANSSDataBitsSgnElement */
static int hf_rrlp_ganssSignalType;               /* GANSSSignalID */
static int hf_rrlp_ganssDataBits;                 /* SeqOf_GANSSDataBits */
static int hf_rrlp_SeqOf_GANSSDataBits_item;      /* GANSSDataBit */
static int hf_rrlp_ganssRefMeasAssistList;        /* SeqOfGANSSRefMeasurementElement */
static int hf_rrlp_SeqOfGANSSRefMeasurementElement_item;  /* GANSSRefMeasurementElement */
static int hf_rrlp_additionalDoppler;             /* AdditionalDopplerFields */
static int hf_rrlp_intCodePhase_01;               /* INTEGER_0_127 */
static int hf_rrlp_codePhaseSearchWindow_01;      /* INTEGER_0_31 */
static int hf_rrlp_additionalAngle;               /* AddionalAngleFields */
static int hf_rrlp_dopplerUncertainty_01;         /* INTEGER_0_4 */
static int hf_rrlp_GANSSRefMeasurementAssist_R10_Ext_item;  /* GANSSRefMeasurement_R10_Ext_Element */
static int hf_rrlp_azimuthLSB;                    /* INTEGER_0_15 */
static int hf_rrlp_elevationLSB;                  /* INTEGER_0_15 */
static int hf_rrlp_weekNumber_01;                 /* INTEGER_0_255 */
static int hf_rrlp_toa;                           /* INTEGER_0_255 */
static int hf_rrlp_ioda;                          /* INTEGER_0_3 */
static int hf_rrlp_ganssAlmanacList;              /* SeqOfGANSSAlmanacElement */
static int hf_rrlp_SeqOfGANSSAlmanacElement_item;  /* GANSSAlmanacElement */
static int hf_rrlp_keplerianAlmanacSet;           /* Almanac_KeplerianSet */
static int hf_rrlp_keplerianNAVAlmanac;           /* Almanac_NAVKeplerianSet */
static int hf_rrlp_keplerianReducedAlmanac;       /* Almanac_ReducedKeplerianSet */
static int hf_rrlp_keplerianMidiAlmanac;          /* Almanac_MidiAlmanacSet */
static int hf_rrlp_keplerianGLONASS;              /* Almanac_GlonassAlmanacSet */
static int hf_rrlp_ecefSBASAlmanac;               /* Almanac_ECEFsbasAlmanacSet */
static int hf_rrlp_kepAlmanacE;                   /* INTEGER_0_2047 */
static int hf_rrlp_kepAlmanacDeltaI;              /* INTEGER_M1024_1023 */
static int hf_rrlp_kepAlmanacOmegaDot;            /* INTEGER_M1024_1023 */
static int hf_rrlp_kepSVHealth;                   /* INTEGER_0_15 */
static int hf_rrlp_kepAlmanacAPowerHalf;          /* INTEGER_M65536_65535 */
static int hf_rrlp_kepAlmanacOmega0;              /* INTEGER_M32768_32767 */
static int hf_rrlp_kepAlmanacW;                   /* INTEGER_M32768_32767 */
static int hf_rrlp_kepAlmanacM0;                  /* INTEGER_M32768_32767 */
static int hf_rrlp_kepAlmanacAF0;                 /* INTEGER_M8192_8191 */
static int hf_rrlp_kepAlmanacAF1;                 /* INTEGER_M1024_1023 */
static int hf_rrlp_navAlmE;                       /* INTEGER_0_65535 */
static int hf_rrlp_navAlmDeltaI;                  /* INTEGER_M32768_32767 */
static int hf_rrlp_navAlmOMEGADOT;                /* INTEGER_M32768_32767 */
static int hf_rrlp_navAlmSVHealth;                /* INTEGER_0_255 */
static int hf_rrlp_navAlmSqrtA;                   /* INTEGER_0_16777215 */
static int hf_rrlp_navAlmOMEGAo;                  /* INTEGER_M8388608_8388607 */
static int hf_rrlp_navAlmOmega;                   /* INTEGER_M8388608_8388607 */
static int hf_rrlp_navAlmMo;                      /* INTEGER_M8388608_8388607 */
static int hf_rrlp_navAlmaf0;                     /* INTEGER_M1024_1023 */
static int hf_rrlp_navAlmaf1;                     /* INTEGER_M1024_1023 */
static int hf_rrlp_redAlmDeltaA;                  /* INTEGER_M128_127 */
static int hf_rrlp_redAlmOmega0;                  /* INTEGER_M64_63 */
static int hf_rrlp_redAlmPhi0;                    /* INTEGER_M64_63 */
static int hf_rrlp_redAlmL1Health;                /* BOOLEAN */
static int hf_rrlp_redAlmL2Health;                /* BOOLEAN */
static int hf_rrlp_redAlmL5Health;                /* BOOLEAN */
static int hf_rrlp_midiAlmE;                      /* INTEGER_0_2047 */
static int hf_rrlp_midiAlmDeltaI;                 /* INTEGER_M1024_1023 */
static int hf_rrlp_midiAlmOmegaDot;               /* INTEGER_M1024_1023 */
static int hf_rrlp_midiAlmSqrtA;                  /* INTEGER_0_131071 */
static int hf_rrlp_midiAlmOmega0;                 /* INTEGER_M32768_32767 */
static int hf_rrlp_midiAlmOmega;                  /* INTEGER_M32768_32767 */
static int hf_rrlp_midiAlmMo;                     /* INTEGER_M32768_32767 */
static int hf_rrlp_midiAlmaf0;                    /* INTEGER_M1024_1023 */
static int hf_rrlp_midiAlmaf1;                    /* INTEGER_M512_511 */
static int hf_rrlp_midiAlmL1Health;               /* BOOLEAN */
static int hf_rrlp_midiAlmL2Health;               /* BOOLEAN */
static int hf_rrlp_midiAlmL5Health;               /* BOOLEAN */
static int hf_rrlp_gloAlmNA;                      /* INTEGER_1_1461 */
static int hf_rrlp_gloAlmnA;                      /* INTEGER_1_24 */
static int hf_rrlp_gloAlmHA;                      /* INTEGER_0_31 */
static int hf_rrlp_gloAlmLambdaA;                 /* INTEGER_M1048576_1048575 */
static int hf_rrlp_gloAlmtlambdaA;                /* INTEGER_0_2097151 */
static int hf_rrlp_gloAlmDeltaIa;                 /* INTEGER_M131072_131071 */
static int hf_rrlp_gloAlmDeltaTA;                 /* INTEGER_M2097152_2097151 */
static int hf_rrlp_gloAlmDeltaTdotA;              /* INTEGER_M64_63 */
static int hf_rrlp_gloAlmEpsilonA;                /* INTEGER_0_32767 */
static int hf_rrlp_gloAlmOmegaA;                  /* INTEGER_M32768_32767 */
static int hf_rrlp_gloAlmTauA;                    /* INTEGER_M512_511 */
static int hf_rrlp_gloAlmCA;                      /* INTEGER_0_1 */
static int hf_rrlp_gloAlmMA;                      /* BIT_STRING_SIZE_2 */
static int hf_rrlp_sbasAlmDataID;                 /* INTEGER_0_3 */
static int hf_rrlp_sbasAlmHealth;                 /* BIT_STRING_SIZE_8 */
static int hf_rrlp_sbasAlmXg;                     /* INTEGER_M16384_16383 */
static int hf_rrlp_sbasAlmYg;                     /* INTEGER_M16384_16383 */
static int hf_rrlp_sbasAlmZg;                     /* INTEGER_M256_255 */
static int hf_rrlp_sbasAlmXgdot;                  /* INTEGER_M4_3 */
static int hf_rrlp_sbasAlmYgDot;                  /* INTEGER_M4_3 */
static int hf_rrlp_sbasAlmZgDot;                  /* INTEGER_M8_7 */
static int hf_rrlp_sbasAlmTo;                     /* INTEGER_0_2047 */
static int hf_rrlp_completeAlmanacProvided;       /* BOOLEAN */
static int hf_rrlp_ganssUtcA1;                    /* INTEGER_M8388608_8388607 */
static int hf_rrlp_ganssUtcA0;                    /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_ganssUtcTot;                   /* INTEGER_0_255 */
static int hf_rrlp_ganssUtcWNt;                   /* INTEGER_0_255 */
static int hf_rrlp_ganssUtcDeltaTls;              /* INTEGER_M128_127 */
static int hf_rrlp_ganssUtcWNlsf;                 /* INTEGER_0_255 */
static int hf_rrlp_ganssUtcDN;                    /* INTEGER_M128_127 */
static int hf_rrlp_ganssUtcDeltaTlsf;             /* INTEGER_M128_127 */
static int hf_rrlp_ganssEphemerisHeader;          /* GANSSEphemerisExtensionHeader */
static int hf_rrlp_ganssReferenceSet;             /* SeqOfGANSSRefOrbit */
static int hf_rrlp_ganssephemerisDeltasMatrix;    /* GANSSEphemerisDeltaMatrix */
static int hf_rrlp_timeAtEstimation;              /* GANSSEphemerisExtensionTime */
static int hf_rrlp_validityPeriod;                /* INTEGER_1_8 */
static int hf_rrlp_ephemerisExtensionDuration;    /* INTEGER_1_512 */
static int hf_rrlp_ganssEphExtDay;                /* INTEGER_0_8191 */
static int hf_rrlp_ganssEphExtTOD;                /* GANSSTOD */
static int hf_rrlp_keplerToe_01;                  /* INTEGER_0_37799 */
static int hf_rrlp_SeqOfGANSSRefOrbit_item;       /* GANSSReferenceOrbit */
static int hf_rrlp_ganssOrbitModel_01;            /* ReferenceNavModel */
static int hf_rrlp_GANSSEphemerisDeltaMatrix_item;  /* GANSSEphemerisDeltaEpoch */
static int hf_rrlp_ganssDeltaEpochHeader;         /* GANSSDeltaEpochHeader */
static int hf_rrlp_ganssDeltaElementList;         /* GANSSDeltaElementList */
static int hf_rrlp_ephemerisDeltaSizes;           /* GANSSEphemerisDeltaBitSizes */
static int hf_rrlp_ephemerisDeltaScales;          /* GANSSEphemerisDeltaScales */
static int hf_rrlp_GANSSDeltaElementList_item;    /* OCTET_STRING_SIZE_1_49 */
static int hf_rrlp_bitsize_delta_omega;           /* INTEGER_1_32 */
static int hf_rrlp_bitsize_delta_deltaN;          /* INTEGER_1_16 */
static int hf_rrlp_bitsize_delta_m0;              /* INTEGER_1_32 */
static int hf_rrlp_bitsize_delta_omegadot;        /* INTEGER_1_24 */
static int hf_rrlp_bitsize_delta_e;               /* INTEGER_1_32 */
static int hf_rrlp_bitsize_delta_idot;            /* INTEGER_1_14 */
static int hf_rrlp_bitsize_delta_sqrtA;           /* INTEGER_1_32 */
static int hf_rrlp_bitsize_delta_i0;              /* INTEGER_1_32 */
static int hf_rrlp_bitsize_delta_omega0;          /* INTEGER_1_32 */
static int hf_rrlp_bitsize_delta_crs;             /* INTEGER_1_16 */
static int hf_rrlp_bitsize_delta_cis;             /* INTEGER_1_16 */
static int hf_rrlp_bitsize_delta_cus;             /* INTEGER_1_16 */
static int hf_rrlp_bitsize_delta_crc;             /* INTEGER_1_16 */
static int hf_rrlp_bitsize_delta_cic;             /* INTEGER_1_16 */
static int hf_rrlp_bitsize_delta_cuc;             /* INTEGER_1_16 */
static int hf_rrlp_bitsize_delta_tgd1;            /* INTEGER_1_10 */
static int hf_rrlp_bitsize_delta_tgd2;            /* INTEGER_1_10 */
static int hf_rrlp_scale_delta_omega;             /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_deltaN;            /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_m0;                /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_omegadot;          /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_e;                 /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_idot;              /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_sqrtA;             /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_i0;                /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_omega0;            /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_crs;               /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_cis;               /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_cus;               /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_crc;               /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_cic;               /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_cuc;               /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_tgd1;              /* INTEGER_M16_15 */
static int hf_rrlp_scale_delta_tgd2;              /* INTEGER_M16_15 */
static int hf_rrlp_ganssBeginTime;                /* GANSSEphemerisExtensionTime */
static int hf_rrlp_ganssEndTime;                  /* GANSSEphemerisExtensionTime */
static int hf_rrlp_ganssSatEventsInfo;            /* GANSSSatEventsInfo */
static int hf_rrlp_eventOccured;                  /* BIT_STRING_SIZE_64 */
static int hf_rrlp_futureEventNoted;              /* BIT_STRING_SIZE_64 */
static int hf_rrlp_utcModel2;                     /* UTCmodelSet2 */
static int hf_rrlp_utcModel3;                     /* UTCmodelSet3 */
static int hf_rrlp_utcModel4;                     /* UTCmodelSet4 */
static int hf_rrlp_utcA0_01;                      /* INTEGER_M32768_32767 */
static int hf_rrlp_utcA1_01;                      /* INTEGER_M4096_4095 */
static int hf_rrlp_utcA2;                         /* INTEGER_M64_63 */
static int hf_rrlp_utcTot_01;                     /* INTEGER_0_65535 */
static int hf_rrlp_utcWNot;                       /* INTEGER_0_8191 */
static int hf_rrlp_utcDN_01;                      /* BIT_STRING_SIZE_4 */
static int hf_rrlp_nA;                            /* INTEGER_1_1461 */
static int hf_rrlp_tauC;                          /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_b1;                            /* INTEGER_M1024_1023 */
static int hf_rrlp_b2;                            /* INTEGER_M512_511 */
static int hf_rrlp_kp;                            /* BIT_STRING_SIZE_2 */
static int hf_rrlp_utcA1wnt;                      /* INTEGER_M8388608_8388607 */
static int hf_rrlp_utcA0wnt;                      /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_utcStandardID;                 /* INTEGER_0_7 */
static int hf_rrlp_ganssID1;                      /* GANSS_ID1 */
static int hf_rrlp_ganssID3;                      /* GANSS_ID3 */
static int hf_rrlp_GANSS_ID1_item;                /* GANSS_ID1_element */
static int hf_rrlp_signalsAvailable;              /* GANSSSignals */
static int hf_rrlp_GANSS_ID3_item;                /* GANSS_ID3_element */
static int hf_rrlp_channelNumber;                 /* INTEGER_M7_13 */
static int hf_rrlp_GANSSDiffCorrectionsValidityPeriod_item;  /* DGANSSExtensionSgnTypeElement */
static int hf_rrlp_dganssExtensionSgnList;        /* SeqOfDGANSSExtensionSgnElement */
static int hf_rrlp_SeqOfDGANSSExtensionSgnElement_item;  /* DGANSSExtensionSgnElement */
static int hf_rrlp_udreGrowthRate;                /* INTEGER_0_7 */
static int hf_rrlp_udreValidityTime;              /* INTEGER_0_7 */
static int hf_rrlp_add_GPS_controlHeader;         /* Add_GPS_ControlHeader */
static int hf_rrlp_gpsEphemerisExtension;         /* GPSEphemerisExtension */
static int hf_rrlp_gpsEphemerisExtensionCheck;    /* GPSEphemerisExtensionCheck */
static int hf_rrlp_dgpsCorrectionsValidityPeriod;  /* DGPSCorrectionsValidityPeriod */
static int hf_rrlp_gpsReferenceTime_R10_Ext;      /* GPSReferenceTime_R10_Ext */
static int hf_rrlp_gpsAcquisAssist_R10_Ext;       /* GPSAcquisAssist_R10_Ext */
static int hf_rrlp_gpsAlmanac_R10_Ext;            /* GPSAlmanac_R10_Ext */
static int hf_rrlp_af2;                           /* INTEGER_M128_127 */
static int hf_rrlp_af1;                           /* INTEGER_M32768_32767 */
static int hf_rrlp_af0;                           /* INTEGER_M2097152_2097151 */
static int hf_rrlp_tgd;                           /* INTEGER_M128_127 */
static int hf_rrlp_gpsEphemerisHeader;            /* GPSEphemerisExtensionHeader */
static int hf_rrlp_gpsReferenceSet;               /* SeqOfGPSRefOrbit */
static int hf_rrlp_gpsephemerisDeltaMatrix;       /* GPSEphemerisDeltaMatrix */
static int hf_rrlp_timeofEstimation;              /* GPSEphemerisExtensionTime */
static int hf_rrlp_SeqOfGPSRefOrbit_item;         /* GPSReferenceOrbit */
static int hf_rrlp_gpsOrbitModel;                 /* ReferenceNavModel */
static int hf_rrlp_gpsClockModel;                 /* GPSClockModel */
static int hf_rrlp_GPSEphemerisDeltaMatrix_item;  /* GPSEphemerisDeltaEpoch */
static int hf_rrlp_gpsDeltaEpochHeader;           /* GPSDeltaEpochHeader */
static int hf_rrlp_gpsDeltaElementList;           /* GPSDeltaElementList */
static int hf_rrlp_ephemerisDeltaSizes_01;        /* GPSEphemerisDeltaBitSizes */
static int hf_rrlp_ephemerisDeltaScales_01;       /* GPSEphemerisDeltaScales */
static int hf_rrlp_GPSDeltaElementList_item;      /* OCTET_STRING_SIZE_1_47 */
static int hf_rrlp_bitsize_delta_tgd;             /* INTEGER_1_10 */
static int hf_rrlp_scale_delta_tgd;               /* INTEGER_M16_15 */
static int hf_rrlp_gpsBeginTime;                  /* GPSEphemerisExtensionTime */
static int hf_rrlp_gpsEndTime;                    /* GPSEphemerisExtensionTime */
static int hf_rrlp_gpsSatEventsInfo;              /* GPSSatEventsInfo */
static int hf_rrlp_eventOccured_01;               /* BIT_STRING_SIZE_32 */
static int hf_rrlp_futureEventNoted_01;           /* BIT_STRING_SIZE_32 */
static int hf_rrlp_DGPSCorrectionsValidityPeriod_item;  /* DGPSExtensionSatElement */
static int hf_rrlp_gpsWeekCycleNumber;            /* INTEGER_0_7 */
static int hf_rrlp_GPSAcquisAssist_R10_Ext_item;  /* GPSAcquisAssist_R10_Ext_Element */
static int hf_rrlp_velEstimate;                   /* VelocityEstimate */
static int hf_rrlp_ganssLocationInfo;             /* GANSSLocationInfo */
static int hf_rrlp_ganssMeasureInfo;              /* GANSSMeasureInfo */
static int hf_rrlp_referenceFrame;                /* ReferenceFrame */
static int hf_rrlp_ganssTODm;                     /* GANSSTODm */
static int hf_rrlp_ganssTODFrac;                  /* INTEGER_0_16384 */
static int hf_rrlp_posData;                       /* PositionData */
static int hf_rrlp_stationaryIndication;          /* INTEGER_0_1 */
static int hf_rrlp_referenceFN;                   /* INTEGER_0_65535 */
static int hf_rrlp_referenceFNMSB;                /* INTEGER_0_63 */
static int hf_rrlp_ganssMsrSetList;               /* SeqOfGANSS_MsrSetElement */
static int hf_rrlp_SeqOfGANSS_MsrSetElement_item;  /* GANSS_MsrSetElement */
static int hf_rrlp_deltaGANSSTOD;                 /* INTEGER_0_127 */
static int hf_rrlp_ganss_MsrElementList;          /* SeqOfGANSS_MsrElement */
static int hf_rrlp_SeqOfGANSS_MsrElement_item;    /* GANSS_MsrElement */
static int hf_rrlp_ganss_SgnTypeList;             /* SeqOfGANSS_SgnTypeElement */
static int hf_rrlp_SeqOfGANSS_SgnTypeElement_item;  /* GANSS_SgnTypeElement */
static int hf_rrlp_ganssCodePhaseAmbiguity;       /* INTEGER_0_127 */
static int hf_rrlp_ganss_SgnList;                 /* SeqOfGANSS_SgnElement */
static int hf_rrlp_SeqOfGANSS_SgnElement_item;    /* GANSS_SgnElement */
static int hf_rrlp_mpathDet;                      /* MpathIndic */
static int hf_rrlp_carrierQualityInd;             /* INTEGER_0_3 */
static int hf_rrlp_codePhase_01;                  /* INTEGER_0_2097151 */
static int hf_rrlp_integerCodePhase;              /* INTEGER_0_127 */
static int hf_rrlp_codePhaseRMSError;             /* INTEGER_0_63 */
static int hf_rrlp_adr;                           /* INTEGER_0_33554431 */
static int hf_rrlp_nonGANSSpositionMethods;       /* NonGANSSPositionMethods */
static int hf_rrlp_multipleMeasurementSets;       /* MultipleMeasurementSets */
static int hf_rrlp_GANSSPositionMethods_item;     /* GANSSPositionMethod */
static int hf_rrlp_gANSSPositioningMethodTypes;   /* GANSSPositioningMethodTypes */
static int hf_rrlp_gANSSSignals;                  /* GANSSSignals */
static int hf_rrlp_sbasID_01;                     /* SBASID */
static int hf_rrlp_gpsAssistance;                 /* GPSAssistance */
static int hf_rrlp_gANSSAssistanceSet;            /* GANSSAssistanceSet */
static int hf_rrlp_gANSSAdditionalAssistanceChoices;  /* GANSSAdditionalAssistanceChoices */
static int hf_rrlp_commonGANSSAssistance;         /* CommonGANSSAssistance */
static int hf_rrlp_specificGANSSAssistance;       /* SpecificGANSSAssistance */
static int hf_rrlp_SpecificGANSSAssistance_item;  /* GANSSAssistanceForOneGANSS */
static int hf_rrlp_gANSSAssistance;               /* GANSSAssistance */
static int hf_rrlp_GANSSAdditionalAssistanceChoices_item;  /* GANSSAdditionalAssistanceChoicesForOneGANSS */
static int hf_rrlp_ganssClockModelChoice;         /* GANSSModelID */
static int hf_rrlp_gannsOrbitModelChoice;         /* GANSSModelID */
static int hf_rrlp_ganssAlmanacModelChoice;       /* GANSSModelID */
static int hf_rrlp_ganssAdditionalUTCModelChoice;  /* GANSSModelID */
/* named bits */
static int hf_rrlp_GANSSPositioningMethod_gps;
static int hf_rrlp_GANSSPositioningMethod_galileo;
static int hf_rrlp_GANSSPositioningMethod_sbas;
static int hf_rrlp_GANSSPositioningMethod_modernizedGPS;
static int hf_rrlp_GANSSPositioningMethod_qzss;
static int hf_rrlp_GANSSPositioningMethod_glonass;
static int hf_rrlp_PositionData_e_otd;
static int hf_rrlp_PositionData_gps;
static int hf_rrlp_PositionData_galileo;
static int hf_rrlp_PositionData_sbas;
static int hf_rrlp_PositionData_modernizedGPS;
static int hf_rrlp_PositionData_qzss;
static int hf_rrlp_PositionData_glonass;
static int hf_rrlp_NonGANSSPositionMethods_msAssistedEOTD;
static int hf_rrlp_NonGANSSPositionMethods_msBasedEOTD;
static int hf_rrlp_NonGANSSPositionMethods_msAssistedGPS;
static int hf_rrlp_NonGANSSPositionMethods_msBasedGPS;
static int hf_rrlp_NonGANSSPositionMethods_standaloneGPS;
static int hf_rrlp_GANSSPositioningMethodTypes_msAssisted;
static int hf_rrlp_GANSSPositioningMethodTypes_msBased;
static int hf_rrlp_GANSSPositioningMethodTypes_standalone;
static int hf_rrlp_GANSSSignals_signal1;
static int hf_rrlp_GANSSSignals_signal2;
static int hf_rrlp_GANSSSignals_signal3;
static int hf_rrlp_GANSSSignals_signal4;
static int hf_rrlp_GANSSSignals_signal5;
static int hf_rrlp_GANSSSignals_signal6;
static int hf_rrlp_GANSSSignals_signal7;
static int hf_rrlp_GANSSSignals_signal8;
static int hf_rrlp_SBASID_waas;
static int hf_rrlp_SBASID_egnos;
static int hf_rrlp_SBASID_masas;
static int hf_rrlp_SBASID_gagan;
static int hf_rrlp_MultipleMeasurementSets_eotd;
static int hf_rrlp_MultipleMeasurementSets_gps;
static int hf_rrlp_MultipleMeasurementSets_ganss;
static int hf_rrlp_GPSAssistance_almanac;
static int hf_rrlp_GPSAssistance_uTCmodel;
static int hf_rrlp_GPSAssistance_ionosphericModel;
static int hf_rrlp_GPSAssistance_navigationmodel;
static int hf_rrlp_GPSAssistance_dGPScorrections;
static int hf_rrlp_GPSAssistance_referenceLocation;
static int hf_rrlp_GPSAssistance_referenceTime;
static int hf_rrlp_GPSAssistance_acquisitionAssistance;
static int hf_rrlp_GPSAssistance_realTimeIntegrity;
static int hf_rrlp_GPSAssistance_ephemerisExtension;
static int hf_rrlp_GPSAssistance_ephemerisExtensionCheck;
static int hf_rrlp_CommonGANSSAssistance_referenceTime;
static int hf_rrlp_CommonGANSSAssistance_referenceLocation;
static int hf_rrlp_CommonGANSSAssistance_spare_bit2;
static int hf_rrlp_CommonGANSSAssistance_ionosphericModel;
static int hf_rrlp_CommonGANSSAssistance_addIonosphericModel;
static int hf_rrlp_CommonGANSSAssistance_earthOrientationParam;
static int hf_rrlp_GANSSAssistance_realTimeIntegrity;
static int hf_rrlp_GANSSAssistance_differentialCorrections;
static int hf_rrlp_GANSSAssistance_almanac;
static int hf_rrlp_GANSSAssistance_referenceMeasurementInformation;
static int hf_rrlp_GANSSAssistance_navigationModel;
static int hf_rrlp_GANSSAssistance_timeModelGNSS_UTC;
static int hf_rrlp_GANSSAssistance_timeModelGNSS_GNSS;
static int hf_rrlp_GANSSAssistance_databitassistance;
static int hf_rrlp_GANSSAssistance_ephemerisExtension;
static int hf_rrlp_GANSSAssistance_ephemerisExtensionCheck;
static int hf_rrlp_GANSSAssistance_addUTCmodel;
static int hf_rrlp_GANSSAssistance_auxiliaryInformation;
static int hf_rrlp_GANSSModelID_model1;
static int hf_rrlp_GANSSModelID_model2;
static int hf_rrlp_GANSSModelID_model3;
static int hf_rrlp_GANSSModelID_model4;
static int hf_rrlp_GANSSModelID_model5;
static int hf_rrlp_GANSSModelID_model6;
static int hf_rrlp_GANSSModelID_model7;
static int hf_rrlp_GANSSModelID_model8;

/* Initialize the subtree pointers */
static int ett_rrlp;
static int ett_rrlp_ExtensionContainer;
static int ett_rrlp_PrivateExtensionList;
static int ett_rrlp_PrivateExtension;
static int ett_rrlp_PCS_Extensions;
static int ett_rrlp_PDU;
static int ett_rrlp_RRLP_Component;
static int ett_rrlp_MsrPosition_Req;
static int ett_rrlp_MsrPosition_Rsp;
static int ett_rrlp_AssistanceData;
static int ett_rrlp_ProtocolError;
static int ett_rrlp_PosCapability_Req;
static int ett_rrlp_PosCapability_Rsp;
static int ett_rrlp_PositionInstruct;
static int ett_rrlp_MethodType;
static int ett_rrlp_AccuracyOpt;
static int ett_rrlp_ReferenceAssistData;
static int ett_rrlp_MsrAssistData;
static int ett_rrlp_SeqOfMsrAssistBTS;
static int ett_rrlp_MsrAssistBTS;
static int ett_rrlp_SystemInfoAssistData;
static int ett_rrlp_SeqOfSystemInfoAssistBTS;
static int ett_rrlp_SystemInfoAssistBTS;
static int ett_rrlp_AssistBTSData;
static int ett_rrlp_CalcAssistanceBTS;
static int ett_rrlp_ReferenceWGS84;
static int ett_rrlp_MultipleSets;
static int ett_rrlp_ReferenceIdentity;
static int ett_rrlp_SeqOfReferenceIdentityType;
static int ett_rrlp_ReferenceIdentityType;
static int ett_rrlp_BSICAndCarrier;
static int ett_rrlp_CellIDAndLAC;
static int ett_rrlp_OTD_MeasureInfo;
static int ett_rrlp_SeqOfOTD_MsrElementRest;
static int ett_rrlp_OTD_MsrElementFirst;
static int ett_rrlp_SeqOfOTD_FirstSetMsrs;
static int ett_rrlp_OTD_MsrElementRest;
static int ett_rrlp_SeqOfOTD_MsrsOfOtherSets;
static int ett_rrlp_TOA_MeasurementsOfRef;
static int ett_rrlp_OTD_MsrsOfOtherSets;
static int ett_rrlp_OTD_Measurement;
static int ett_rrlp_OTD_MeasurementWithID;
static int ett_rrlp_EOTDQuality;
static int ett_rrlp_NeighborIdentity;
static int ett_rrlp_MultiFrameCarrier;
static int ett_rrlp_LocationInfo;
static int ett_rrlp_GPS_MeasureInfo;
static int ett_rrlp_SeqOfGPS_MsrSetElement;
static int ett_rrlp_GPS_MsrSetElement;
static int ett_rrlp_SeqOfGPS_MsrElement;
static int ett_rrlp_GPS_MsrElement;
static int ett_rrlp_LocationError;
static int ett_rrlp_AdditionalAssistanceData;
static int ett_rrlp_GPS_AssistData;
static int ett_rrlp_ControlHeader;
static int ett_rrlp_ReferenceTime;
static int ett_rrlp_GPSTime;
static int ett_rrlp_GPSTOWAssist;
static int ett_rrlp_GPSTOWAssistElement;
static int ett_rrlp_GSMTime;
static int ett_rrlp_RefLocation;
static int ett_rrlp_DGPSCorrections;
static int ett_rrlp_SeqOfSatElement;
static int ett_rrlp_SatElement;
static int ett_rrlp_NavigationModel;
static int ett_rrlp_SeqOfNavModelElement;
static int ett_rrlp_NavModelElement;
static int ett_rrlp_SatStatus;
static int ett_rrlp_UncompressedEphemeris;
static int ett_rrlp_EphemerisSubframe1Reserved;
static int ett_rrlp_IonosphericModel;
static int ett_rrlp_UTCModel;
static int ett_rrlp_Almanac;
static int ett_rrlp_SeqOfAlmanacElement;
static int ett_rrlp_AlmanacElement;
static int ett_rrlp_AcquisAssist;
static int ett_rrlp_SeqOfAcquisElement;
static int ett_rrlp_TimeRelation;
static int ett_rrlp_AcquisElement;
static int ett_rrlp_AddionalDopplerFields;
static int ett_rrlp_AddionalAngleFields;
static int ett_rrlp_SeqOf_BadSatelliteSet;
static int ett_rrlp_Rel98_MsrPosition_Req_Extension;
static int ett_rrlp_Rel98_AssistanceData_Extension;
static int ett_rrlp_Rel98_Ext_ExpOTD;
static int ett_rrlp_MsrAssistData_R98_ExpOTD;
static int ett_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD;
static int ett_rrlp_MsrAssistBTS_R98_ExpOTD;
static int ett_rrlp_SystemInfoAssistData_R98_ExpOTD;
static int ett_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD;
static int ett_rrlp_SystemInfoAssistBTS_R98_ExpOTD;
static int ett_rrlp_AssistBTSData_R98_ExpOTD;
static int ett_rrlp_GPSTimeAssistanceMeasurements;
static int ett_rrlp_Rel_98_MsrPosition_Rsp_Extension;
static int ett_rrlp_T_rel_98_Ext_MeasureInfo;
static int ett_rrlp_OTD_MeasureInfo_R98_Ext;
static int ett_rrlp_OTD_MsrElementFirst_R98_Ext;
static int ett_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext;
static int ett_rrlp_Rel_5_MsrPosition_Rsp_Extension;
static int ett_rrlp_Extended_reference;
static int ett_rrlp_Rel5_MsrPosition_Req_Extension;
static int ett_rrlp_Rel5_AssistanceData_Extension;
static int ett_rrlp_Rel_5_ProtocolError_Extension;
static int ett_rrlp_Rel7_MsrPosition_Req_Extension;
static int ett_rrlp_GANSSPositioningMethod;
static int ett_rrlp_GANSS_AssistData;
static int ett_rrlp_GANSS_ControlHeader;
static int ett_rrlp_GANSSCommonAssistData;
static int ett_rrlp_SeqOfGANSSGenericAssistDataElement;
static int ett_rrlp_GANSSGenericAssistDataElement;
static int ett_rrlp_GANSSReferenceTime;
static int ett_rrlp_GANSSRefTimeInfo;
static int ett_rrlp_GANSSReferenceTime_R10_Ext;
static int ett_rrlp_GANSSTOD_GSMTimeAssociation;
static int ett_rrlp_GANSSRefLocation;
static int ett_rrlp_GANSSIonosphericModel;
static int ett_rrlp_GANSSIonosphereModel;
static int ett_rrlp_GANSSIonoStormFlags;
static int ett_rrlp_GANSSAddIonosphericModel;
static int ett_rrlp_GANSSEarthOrientParam;
static int ett_rrlp_SeqOfGANSSTimeModel;
static int ett_rrlp_GANSSTimeModelElement;
static int ett_rrlp_SeqOfGANSSTimeModel_R10_Ext;
static int ett_rrlp_GANSSTimeModelElement_R10_Ext;
static int ett_rrlp_GANSSDiffCorrections;
static int ett_rrlp_SeqOfSgnTypeElement;
static int ett_rrlp_SgnTypeElement;
static int ett_rrlp_SeqOfDGANSSSgnElement;
static int ett_rrlp_DGANSSSgnElement;
static int ett_rrlp_GANSSNavModel;
static int ett_rrlp_SeqOfGANSSSatelliteElement;
static int ett_rrlp_GANSSSatelliteElement;
static int ett_rrlp_GANSSOrbitModel;
static int ett_rrlp_NavModel_KeplerianSet;
static int ett_rrlp_NavModel_NAVKeplerianSet;
static int ett_rrlp_NavModel_CNAVKeplerianSet;
static int ett_rrlp_NavModel_GLONASSecef;
static int ett_rrlp_NavModel_SBASecef;
static int ett_rrlp_GANSSClockModel;
static int ett_rrlp_SeqOfStandardClockModelElement;
static int ett_rrlp_StandardClockModelElement;
static int ett_rrlp_NAVclockModel;
static int ett_rrlp_CNAVclockModel;
static int ett_rrlp_GLONASSclockModel;
static int ett_rrlp_SBASclockModel;
static int ett_rrlp_GANSSRealTimeIntegrity;
static int ett_rrlp_SeqOfBadSignalElement;
static int ett_rrlp_BadSignalElement;
static int ett_rrlp_GANSSDataBitAssist;
static int ett_rrlp_SeqOfGanssDataBitsElement;
static int ett_rrlp_GanssDataBitsElement;
static int ett_rrlp_Seq_OfGANSSDataBitsSgn;
static int ett_rrlp_GANSSDataBitsSgnElement;
static int ett_rrlp_SeqOf_GANSSDataBits;
static int ett_rrlp_GANSSRefMeasurementAssist;
static int ett_rrlp_SeqOfGANSSRefMeasurementElement;
static int ett_rrlp_GANSSRefMeasurementElement;
static int ett_rrlp_AdditionalDopplerFields;
static int ett_rrlp_GANSSRefMeasurementAssist_R10_Ext;
static int ett_rrlp_GANSSRefMeasurement_R10_Ext_Element;
static int ett_rrlp_GANSSAlmanacModel;
static int ett_rrlp_SeqOfGANSSAlmanacElement;
static int ett_rrlp_GANSSAlmanacElement;
static int ett_rrlp_Almanac_KeplerianSet;
static int ett_rrlp_Almanac_NAVKeplerianSet;
static int ett_rrlp_Almanac_ReducedKeplerianSet;
static int ett_rrlp_Almanac_MidiAlmanacSet;
static int ett_rrlp_Almanac_GlonassAlmanacSet;
static int ett_rrlp_Almanac_ECEFsbasAlmanacSet;
static int ett_rrlp_GANSSAlmanacModel_R10_Ext;
static int ett_rrlp_GANSSUTCModel;
static int ett_rrlp_GANSSEphemerisExtension;
static int ett_rrlp_GANSSEphemerisExtensionHeader;
static int ett_rrlp_GANSSEphemerisExtensionTime;
static int ett_rrlp_ReferenceNavModel;
static int ett_rrlp_SeqOfGANSSRefOrbit;
static int ett_rrlp_GANSSReferenceOrbit;
static int ett_rrlp_GANSSEphemerisDeltaMatrix;
static int ett_rrlp_GANSSEphemerisDeltaEpoch;
static int ett_rrlp_GANSSDeltaEpochHeader;
static int ett_rrlp_GANSSDeltaElementList;
static int ett_rrlp_GANSSEphemerisDeltaBitSizes;
static int ett_rrlp_GANSSEphemerisDeltaScales;
static int ett_rrlp_GANSSEphemerisExtensionCheck;
static int ett_rrlp_GANSSSatEventsInfo;
static int ett_rrlp_GANSSAddUTCModel;
static int ett_rrlp_UTCmodelSet2;
static int ett_rrlp_UTCmodelSet3;
static int ett_rrlp_UTCmodelSet4;
static int ett_rrlp_GANSSAuxiliaryInformation;
static int ett_rrlp_GANSS_ID1;
static int ett_rrlp_GANSS_ID1_element;
static int ett_rrlp_GANSS_ID3;
static int ett_rrlp_GANSS_ID3_element;
static int ett_rrlp_GANSSDiffCorrectionsValidityPeriod;
static int ett_rrlp_DGANSSExtensionSgnTypeElement;
static int ett_rrlp_SeqOfDGANSSExtensionSgnElement;
static int ett_rrlp_DGANSSExtensionSgnElement;
static int ett_rrlp_Add_GPS_AssistData;
static int ett_rrlp_Add_GPS_ControlHeader;
static int ett_rrlp_GPSClockModel;
static int ett_rrlp_GPSEphemerisExtension;
static int ett_rrlp_GPSEphemerisExtensionHeader;
static int ett_rrlp_GPSEphemerisExtensionTime;
static int ett_rrlp_SeqOfGPSRefOrbit;
static int ett_rrlp_GPSReferenceOrbit;
static int ett_rrlp_GPSEphemerisDeltaMatrix;
static int ett_rrlp_GPSEphemerisDeltaEpoch;
static int ett_rrlp_GPSDeltaEpochHeader;
static int ett_rrlp_GPSDeltaElementList;
static int ett_rrlp_GPSEphemerisDeltaBitSizes;
static int ett_rrlp_GPSEphemerisDeltaScales;
static int ett_rrlp_GPSEphemerisExtensionCheck;
static int ett_rrlp_GPSSatEventsInfo;
static int ett_rrlp_DGPSCorrectionsValidityPeriod;
static int ett_rrlp_DGPSExtensionSatElement;
static int ett_rrlp_GPSReferenceTime_R10_Ext;
static int ett_rrlp_GPSAcquisAssist_R10_Ext;
static int ett_rrlp_GPSAcquisAssist_R10_Ext_Element;
static int ett_rrlp_GPSAlmanac_R10_Ext;
static int ett_rrlp_Rel_7_MsrPosition_Rsp_Extension;
static int ett_rrlp_GANSSLocationInfo;
static int ett_rrlp_PositionData;
static int ett_rrlp_ReferenceFrame;
static int ett_rrlp_GANSSMeasureInfo;
static int ett_rrlp_SeqOfGANSS_MsrSetElement;
static int ett_rrlp_GANSS_MsrSetElement;
static int ett_rrlp_SeqOfGANSS_MsrElement;
static int ett_rrlp_GANSS_MsrElement;
static int ett_rrlp_SeqOfGANSS_SgnTypeElement;
static int ett_rrlp_GANSS_SgnTypeElement;
static int ett_rrlp_SeqOfGANSS_SgnElement;
static int ett_rrlp_GANSS_SgnElement;
static int ett_rrlp_Rel7_AssistanceData_Extension;
static int ett_rrlp_PosCapabilities;
static int ett_rrlp_NonGANSSPositionMethods;
static int ett_rrlp_GANSSPositionMethods;
static int ett_rrlp_GANSSPositionMethod;
static int ett_rrlp_GANSSPositioningMethodTypes;
static int ett_rrlp_GANSSSignals;
static int ett_rrlp_SBASID;
static int ett_rrlp_MultipleMeasurementSets;
static int ett_rrlp_AssistanceSupported;
static int ett_rrlp_GPSAssistance;
static int ett_rrlp_GANSSAssistanceSet;
static int ett_rrlp_CommonGANSSAssistance;
static int ett_rrlp_SpecificGANSSAssistance;
static int ett_rrlp_GANSSAssistanceForOneGANSS;
static int ett_rrlp_GANSSAssistance;
static int ett_rrlp_GANSSAdditionalAssistanceChoices;
static int ett_rrlp_GANSSAdditionalAssistanceChoicesForOneGANSS;
static int ett_rrlp_GANSSModelID;
static int ett_rrlp_AssistanceNeeded;

/* Include constants */
#define maxNumOfPrivateExtensions      10
#define maxExt_GeographicalInformation 20
#define maxGPSAssistanceData           40
#define maxGANSSAssistanceData         40




static int
dissect_rrlp_OBJECT_IDENTIFIER(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_object_identifier(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_rrlp_T_extType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_open_type(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PrivateExtension_sequence[] = {
  { &hf_rrlp_extId          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_OBJECT_IDENTIFIER },
  { &hf_rrlp_extType        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_T_extType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_PrivateExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_PrivateExtension, PrivateExtension_sequence);

  return offset;
}


static const per_sequence_t PrivateExtensionList_sequence_of[1] = {
  { &hf_rrlp_PrivateExtensionList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_PrivateExtension },
};

static int
dissect_rrlp_PrivateExtensionList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_PrivateExtensionList, PrivateExtensionList_sequence_of,
                                                  1, maxNumOfPrivateExtensions, false);

  return offset;
}


static const per_sequence_t PCS_Extensions_sequence[] = {
  { NULL, ASN1_EXTENSION_ROOT, 0, NULL }
};

static int
dissect_rrlp_PCS_Extensions(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_PCS_Extensions, PCS_Extensions_sequence);

  return offset;
}


static const per_sequence_t ExtensionContainer_sequence[] = {
  { &hf_rrlp_privateExtensionList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_PrivateExtensionList },
  { &hf_rrlp_pcs_Extensions , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_PCS_Extensions },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ExtensionContainer(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_ExtensionContainer, ExtensionContainer_sequence);

  return offset;
}



static int
dissect_rrlp_Ext_GeographicalInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

tvbuff_t *parameter_tvb = NULL;

    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, maxExt_GeographicalInformation, false, &parameter_tvb);


  if(parameter_tvb)
	dissect_geographical_description(parameter_tvb, actx->pinfo, tree);

  return offset;
}



static int
dissect_rrlp_VelocityEstimate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 7, false, NULL);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}



static int
dissect_rrlp_Accuracy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t AccuracyOpt_sequence[] = {
  { &hf_rrlp_accuracy       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_Accuracy },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AccuracyOpt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_AccuracyOpt, AccuracyOpt_sequence);

  return offset;
}


static const value_string rrlp_MethodType_vals[] = {
  {   0, "msAssisted" },
  {   1, "msBased" },
  {   2, "msBasedPref" },
  {   3, "msAssistedPref" },
  { 0, NULL }
};

static const per_choice_t MethodType_choice[] = {
  {   0, &hf_rrlp_msAssisted     , ASN1_NO_EXTENSIONS     , dissect_rrlp_AccuracyOpt },
  {   1, &hf_rrlp_msBased        , ASN1_NO_EXTENSIONS     , dissect_rrlp_Accuracy },
  {   2, &hf_rrlp_msBasedPref    , ASN1_NO_EXTENSIONS     , dissect_rrlp_Accuracy },
  {   3, &hf_rrlp_msAssistedPref , ASN1_NO_EXTENSIONS     , dissect_rrlp_Accuracy },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_MethodType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_MethodType, MethodType_choice,
                                 NULL);

  return offset;
}


static const value_string rrlp_PositionMethod_vals[] = {
  {   0, "eotd" },
  {   1, "gps" },
  {   2, "gpsOrEOTD" },
  { 0, NULL }
};


static int
dissect_rrlp_PositionMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_rrlp_MeasureResponseTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}


static const value_string rrlp_UseMultipleSets_vals[] = {
  {   0, "multipleSets" },
  {   1, "oneSet" },
  { 0, NULL }
};


static int
dissect_rrlp_UseMultipleSets(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const value_string rrlp_EnvironmentCharacter_vals[] = {
  {   0, "badArea" },
  {   1, "notBadArea" },
  {   2, "mixedArea" },
  { 0, NULL }
};


static int
dissect_rrlp_EnvironmentCharacter(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t PositionInstruct_sequence[] = {
  { &hf_rrlp_methodType     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_MethodType },
  { &hf_rrlp_positionMethod , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_PositionMethod },
  { &hf_rrlp_measureResponseTime, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_MeasureResponseTime },
  { &hf_rrlp_useMultipleSets, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_UseMultipleSets },
  { &hf_rrlp_environmentCharacter, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_EnvironmentCharacter },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_PositionInstruct(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_PositionInstruct, PositionInstruct_sequence);

  return offset;
}



static int
dissect_rrlp_BCCHCarrier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, false);

  return offset;
}



static int
dissect_rrlp_BSIC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}


static const value_string rrlp_TimeSlotScheme_vals[] = {
  {   0, "equalLength" },
  {   1, "variousLength" },
  { 0, NULL }
};


static int
dissect_rrlp_TimeSlotScheme(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}



static int
dissect_rrlp_BTSPosition(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_rrlp_Ext_GeographicalInformation(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t ReferenceAssistData_sequence[] = {
  { &hf_rrlp_bcchCarrier    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BCCHCarrier },
  { &hf_rrlp_bsic           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BSIC },
  { &hf_rrlp_timeSlotScheme , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_TimeSlotScheme },
  { &hf_rrlp_btsPosition    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_BTSPosition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ReferenceAssistData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_ReferenceAssistData, ReferenceAssistData_sequence);

  return offset;
}



static int
dissect_rrlp_MultiFrameOffset(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 51U, NULL, false);

  return offset;
}



static int
dissect_rrlp_RoughRTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1250U, NULL, false);

  return offset;
}



static int
dissect_rrlp_FineRTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}



static int
dissect_rrlp_RelDistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -200000, 200000U, NULL, false);

  return offset;
}



static int
dissect_rrlp_RelativeAlt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -4000, 4000U, NULL, false);

  return offset;
}


static const per_sequence_t ReferenceWGS84_sequence[] = {
  { &hf_rrlp_relativeNorth  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_RelDistance },
  { &hf_rrlp_relativeEast   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_RelDistance },
  { &hf_rrlp_relativeAlt    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_RelativeAlt },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ReferenceWGS84(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_ReferenceWGS84, ReferenceWGS84_sequence);

  return offset;
}


static const per_sequence_t CalcAssistanceBTS_sequence[] = {
  { &hf_rrlp_fineRTD        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_FineRTD },
  { &hf_rrlp_referenceWGS84 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_ReferenceWGS84 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_CalcAssistanceBTS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_CalcAssistanceBTS, CalcAssistanceBTS_sequence);

  return offset;
}


static const per_sequence_t MsrAssistBTS_sequence[] = {
  { &hf_rrlp_bcchCarrier    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BCCHCarrier },
  { &hf_rrlp_bsic           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BSIC },
  { &hf_rrlp_multiFrameOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_MultiFrameOffset },
  { &hf_rrlp_timeSlotScheme , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_TimeSlotScheme },
  { &hf_rrlp_roughRTD       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_RoughRTD },
  { &hf_rrlp_calcAssistanceBTS, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_CalcAssistanceBTS },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MsrAssistBTS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_MsrAssistBTS, MsrAssistBTS_sequence);

  return offset;
}


static const per_sequence_t SeqOfMsrAssistBTS_sequence_of[1] = {
  { &hf_rrlp_SeqOfMsrAssistBTS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_MsrAssistBTS },
};

static int
dissect_rrlp_SeqOfMsrAssistBTS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfMsrAssistBTS, SeqOfMsrAssistBTS_sequence_of,
                                                  1, 15, false);

  return offset;
}


static const per_sequence_t MsrAssistData_sequence[] = {
  { &hf_rrlp_msrAssistList  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfMsrAssistBTS },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MsrAssistData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_MsrAssistData, MsrAssistData_sequence);

  return offset;
}



static int
dissect_rrlp_NULL(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_null(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t AssistBTSData_sequence[] = {
  { &hf_rrlp_bsic           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BSIC },
  { &hf_rrlp_multiFrameOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_MultiFrameOffset },
  { &hf_rrlp_timeSlotScheme , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_TimeSlotScheme },
  { &hf_rrlp_roughRTD       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_RoughRTD },
  { &hf_rrlp_calcAssistanceBTS, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_CalcAssistanceBTS },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AssistBTSData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_AssistBTSData, AssistBTSData_sequence);

  return offset;
}


static const value_string rrlp_SystemInfoAssistBTS_vals[] = {
  {   0, "notPresent" },
  {   1, "present" },
  { 0, NULL }
};

static const per_choice_t SystemInfoAssistBTS_choice[] = {
  {   0, &hf_rrlp_notPresent     , ASN1_NO_EXTENSIONS     , dissect_rrlp_NULL },
  {   1, &hf_rrlp_present        , ASN1_NO_EXTENSIONS     , dissect_rrlp_AssistBTSData },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_SystemInfoAssistBTS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_SystemInfoAssistBTS, SystemInfoAssistBTS_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SeqOfSystemInfoAssistBTS_sequence_of[1] = {
  { &hf_rrlp_SeqOfSystemInfoAssistBTS_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SystemInfoAssistBTS },
};

static int
dissect_rrlp_SeqOfSystemInfoAssistBTS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfSystemInfoAssistBTS, SeqOfSystemInfoAssistBTS_sequence_of,
                                                  1, 32, false);

  return offset;
}


static const per_sequence_t SystemInfoAssistData_sequence[] = {
  { &hf_rrlp_systemInfoAssistList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfSystemInfoAssistBTS },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_SystemInfoAssistData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_SystemInfoAssistData, SystemInfoAssistData_sequence);

  return offset;
}



static int
dissect_rrlp_GPSTOW23b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7559999U, NULL, false);

  return offset;
}



static int
dissect_rrlp_GPSWeek(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, false);

  return offset;
}


static const per_sequence_t GPSTime_sequence[] = {
  { &hf_rrlp_gpsTOW23b      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSTOW23b },
  { &hf_rrlp_gpsWeek        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSWeek },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSTime, GPSTime_sequence);

  return offset;
}



static int
dissect_rrlp_FrameNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2097151U, NULL, false);

  return offset;
}



static int
dissect_rrlp_TimeSlot(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}



static int
dissect_rrlp_BitNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 156U, NULL, false);

  return offset;
}


static const per_sequence_t GSMTime_sequence[] = {
  { &hf_rrlp_bcchCarrier    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BCCHCarrier },
  { &hf_rrlp_bsic           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BSIC },
  { &hf_rrlp_frameNumber    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_FrameNumber },
  { &hf_rrlp_timeSlot       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_TimeSlot },
  { &hf_rrlp_bitNumber      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BitNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GSMTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GSMTime, GSMTime_sequence);

  return offset;
}



static int
dissect_rrlp_SatelliteID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}



static int
dissect_rrlp_TLMWord(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, false);

  return offset;
}



static int
dissect_rrlp_AntiSpoofFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, false);

  return offset;
}



static int
dissect_rrlp_AlertFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, false);

  return offset;
}



static int
dissect_rrlp_TLMReservedBits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, false);

  return offset;
}


static const per_sequence_t GPSTOWAssistElement_sequence[] = {
  { &hf_rrlp_satelliteID    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SatelliteID },
  { &hf_rrlp_tlmWord        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_TLMWord },
  { &hf_rrlp_antiSpoof      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_AntiSpoofFlag },
  { &hf_rrlp_alert          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_AlertFlag },
  { &hf_rrlp_tlmRsvdBits    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_TLMReservedBits },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSTOWAssistElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSTOWAssistElement, GPSTOWAssistElement_sequence);

  return offset;
}


static const per_sequence_t GPSTOWAssist_sequence_of[1] = {
  { &hf_rrlp_GPSTOWAssist_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSTOWAssistElement },
};

static int
dissect_rrlp_GPSTOWAssist(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_GPSTOWAssist, GPSTOWAssist_sequence_of,
                                                  1, 12, false);

  return offset;
}


static const per_sequence_t ReferenceTime_sequence[] = {
  { &hf_rrlp_gpsTime        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSTime },
  { &hf_rrlp_gsmTime        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_GSMTime },
  { &hf_rrlp_gpsTowAssist   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_GPSTOWAssist },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ReferenceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_ReferenceTime, ReferenceTime_sequence);

  return offset;
}


static const per_sequence_t RefLocation_sequence[] = {
  { &hf_rrlp_threeDLocation , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_Ext_GeographicalInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_RefLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_RefLocation, RefLocation_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_604799(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 604799U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_239(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 239U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M2047_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2047, 2047U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M127_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 127U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M7_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -7, 7U, NULL, false);

  return offset;
}


static const per_sequence_t SatElement_sequence[] = {
  { &hf_rrlp_satelliteID    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SatelliteID },
  { &hf_rrlp_iode           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_239 },
  { &hf_rrlp_udre           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_3 },
  { &hf_rrlp_pseudoRangeCor , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2047_2047 },
  { &hf_rrlp_rangeRateCor   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M127_127 },
  { &hf_rrlp_deltaPseudoRangeCor2, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M127_127 },
  { &hf_rrlp_deltaRangeRateCor2, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M7_7 },
  { &hf_rrlp_deltaPseudoRangeCor3, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M127_127 },
  { &hf_rrlp_deltaRangeRateCor3, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M7_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_SatElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_SatElement, SatElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfSatElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfSatElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SatElement },
};

static int
dissect_rrlp_SeqOfSatElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfSatElement, SeqOfSatElement_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t DGPSCorrections_sequence[] = {
  { &hf_rrlp_gpsTOW_02      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_604799 },
  { &hf_rrlp_status         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_satList        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfSatElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_DGPSCorrections(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_DGPSCorrections, DGPSCorrections_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 15U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_16777215(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777215U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const per_sequence_t EphemerisSubframe1Reserved_sequence[] = {
  { &hf_rrlp_reserved1      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_8388607 },
  { &hf_rrlp_reserved2      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_16777215 },
  { &hf_rrlp_reserved3      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_16777215 },
  { &hf_rrlp_reserved4      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_65535 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_EphemerisSubframe1Reserved(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_EphemerisSubframe1Reserved, EphemerisSubframe1Reserved_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_M128_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -128, 127U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_37799(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 37799U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M32768_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32768, 32767U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M2097152_2097151(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2097152, 2097151U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M2147483648_2147483647(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            INT32_MIN, 2147483647U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M8388608_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M8192_8191(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8192, 8191U, NULL, false);

  return offset;
}


static const per_sequence_t UncompressedEphemeris_sequence[] = {
  { &hf_rrlp_ephemCodeOnL2  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_3 },
  { &hf_rrlp_ephemURA       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_15 },
  { &hf_rrlp_ephemSVhealth  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_63 },
  { &hf_rrlp_ephemIODC      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1023 },
  { &hf_rrlp_ephemL2Pflag   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1 },
  { &hf_rrlp_ephemSF1Rsvd   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_EphemerisSubframe1Reserved },
  { &hf_rrlp_ephemTgd       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_ephemToc       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_37799 },
  { &hf_rrlp_ephemAF2       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_ephemAF1       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_ephemAF0       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2097152_2097151 },
  { &hf_rrlp_ephemCrs       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_ephemDeltaN    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_ephemM0        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_ephemCuc       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_ephemE         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_4294967295 },
  { &hf_rrlp_ephemCus       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_ephemAPowerHalf, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_4294967295 },
  { &hf_rrlp_ephemToe       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_37799 },
  { &hf_rrlp_ephemFitFlag   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1 },
  { &hf_rrlp_ephemAODA      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_31 },
  { &hf_rrlp_ephemCic       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_ephemOmegaA0   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_ephemCis       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_ephemI0        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_ephemCrc       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_ephemW         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_ephemOmegaADot , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_ephemIDot      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8192_8191 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_UncompressedEphemeris(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_UncompressedEphemeris, UncompressedEphemeris_sequence);

  return offset;
}


static const value_string rrlp_SatStatus_vals[] = {
  {   0, "newSatelliteAndModelUC" },
  {   1, "oldSatelliteAndModel" },
  {   2, "newNaviModelUC" },
  { 0, NULL }
};

static const per_choice_t SatStatus_choice[] = {
  {   0, &hf_rrlp_newSatelliteAndModelUC, ASN1_EXTENSION_ROOT    , dissect_rrlp_UncompressedEphemeris },
  {   1, &hf_rrlp_oldSatelliteAndModel, ASN1_EXTENSION_ROOT    , dissect_rrlp_NULL },
  {   2, &hf_rrlp_newNaviModelUC , ASN1_EXTENSION_ROOT    , dissect_rrlp_UncompressedEphemeris },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_SatStatus(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_SatStatus, SatStatus_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NavModelElement_sequence[] = {
  { &hf_rrlp_satelliteID    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SatelliteID },
  { &hf_rrlp_satStatus      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SatStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_NavModelElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_NavModelElement, NavModelElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfNavModelElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfNavModelElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_NavModelElement },
};

static int
dissect_rrlp_SeqOfNavModelElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfNavModelElement, SeqOfNavModelElement_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t NavigationModel_sequence[] = {
  { &hf_rrlp_navModelList   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfNavModelElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_NavigationModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_NavigationModel, NavigationModel_sequence);

  return offset;
}


static const per_sequence_t IonosphericModel_sequence[] = {
  { &hf_rrlp_alfa0          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_alfa1          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_alfa2          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_alfa3          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_beta0          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_beta1          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_beta2          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_beta3          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_IonosphericModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_IonosphericModel, IonosphericModel_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, false);

  return offset;
}


static const per_sequence_t UTCModel_sequence[] = {
  { &hf_rrlp_utcA1          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_utcA0          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_utcTot         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_utcWNt         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_utcDeltaTls    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_utcWNlsf       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_utcDN          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_utcDeltaTlsf   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_UTCModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_UTCModel, UTCModel_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_M1024_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1024, 1023U, NULL, false);

  return offset;
}


static const per_sequence_t AlmanacElement_sequence[] = {
  { &hf_rrlp_satelliteID    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SatelliteID },
  { &hf_rrlp_almanacE       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_65535 },
  { &hf_rrlp_alamanacToa    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_almanacKsii    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_almanacOmegaDot, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_almanacSVhealth, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_almanacAPowerHalf, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_16777215 },
  { &hf_rrlp_almanacOmega0  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_almanacW       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_almanacM0      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_almanacAF0     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1024_1023 },
  { &hf_rrlp_almanacAF1     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1024_1023 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AlmanacElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_AlmanacElement, AlmanacElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfAlmanacElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfAlmanacElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_AlmanacElement },
};

static int
dissect_rrlp_SeqOfAlmanacElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfAlmanacElement, SeqOfAlmanacElement_sequence_of,
                                                  1, 64, false);

  return offset;
}


static const per_sequence_t Almanac_sequence[] = {
  { &hf_rrlp_alamanacWNa    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_almanacList    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfAlmanacElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Almanac(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Almanac, Almanac_sequence);

  return offset;
}


static const per_sequence_t TimeRelation_sequence[] = {
  { &hf_rrlp_gpsTOW_03      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSTOW23b },
  { &hf_rrlp_gsmTime        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_GSMTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_TimeRelation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_TimeRelation, TimeRelation_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_M2048_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2048, 2047U, NULL, false);

  return offset;
}


static const per_sequence_t AddionalDopplerFields_sequence[] = {
  { &hf_rrlp_doppler1       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_63 },
  { &hf_rrlp_dopplerUncertainty, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AddionalDopplerFields(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_AddionalDopplerFields, AddionalDopplerFields_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_1022(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1022U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 19U, NULL, false);

  return offset;
}


static const per_sequence_t AddionalAngleFields_sequence[] = {
  { &hf_rrlp_azimuth        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_31 },
  { &hf_rrlp_elevation      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AddionalAngleFields(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_AddionalAngleFields, AddionalAngleFields_sequence);

  return offset;
}


static const per_sequence_t AcquisElement_sequence[] = {
  { &hf_rrlp_svid           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SatelliteID },
  { &hf_rrlp_doppler0       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2048_2047 },
  { &hf_rrlp_addionalDoppler, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_AddionalDopplerFields },
  { &hf_rrlp_codePhase      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1022 },
  { &hf_rrlp_intCodePhase   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_19 },
  { &hf_rrlp_gpsBitNumber   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_3 },
  { &hf_rrlp_codePhaseSearchWindow, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_15 },
  { &hf_rrlp_addionalAngle  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_AddionalAngleFields },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AcquisElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_AcquisElement, AcquisElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfAcquisElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfAcquisElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_AcquisElement },
};

static int
dissect_rrlp_SeqOfAcquisElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfAcquisElement, SeqOfAcquisElement_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t AcquisAssist_sequence[] = {
  { &hf_rrlp_timeRelation   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_TimeRelation },
  { &hf_rrlp_acquisList     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfAcquisElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AcquisAssist(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_AcquisAssist, AcquisAssist_sequence);

  return offset;
}


static const per_sequence_t SeqOf_BadSatelliteSet_sequence_of[1] = {
  { &hf_rrlp_SeqOf_BadSatelliteSet_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SatelliteID },
};

static int
dissect_rrlp_SeqOf_BadSatelliteSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOf_BadSatelliteSet, SeqOf_BadSatelliteSet_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t ControlHeader_sequence[] = {
  { &hf_rrlp_referenceTime  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_ReferenceTime },
  { &hf_rrlp_refLocation    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_RefLocation },
  { &hf_rrlp_dgpsCorrections, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_DGPSCorrections },
  { &hf_rrlp_navigationModel, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_NavigationModel },
  { &hf_rrlp_ionosphericModel, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_IonosphericModel },
  { &hf_rrlp_utcModel       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_UTCModel },
  { &hf_rrlp_almanac        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_Almanac },
  { &hf_rrlp_acquisAssist   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_AcquisAssist },
  { &hf_rrlp_realTimeIntegrity, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_SeqOf_BadSatelliteSet },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ControlHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_ControlHeader, ControlHeader_sequence);

  return offset;
}


static const per_sequence_t GPS_AssistData_sequence[] = {
  { &hf_rrlp_controlHeader  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_ControlHeader },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPS_AssistData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPS_AssistData, GPS_AssistData_sequence);

  return offset;
}



static int
dissect_rrlp_ExpectedOTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1250U, NULL, false);

  return offset;
}



static int
dissect_rrlp_ExpOTDUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}


static const per_sequence_t MsrAssistBTS_R98_ExpOTD_sequence[] = {
  { &hf_rrlp_expectedOTD    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_ExpectedOTD },
  { &hf_rrlp_expOTDUncertainty, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_ExpOTDUncertainty },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MsrAssistBTS_R98_ExpOTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_MsrAssistBTS_R98_ExpOTD, MsrAssistBTS_R98_ExpOTD_sequence);

  return offset;
}


static const per_sequence_t SeqOfMsrAssistBTS_R98_ExpOTD_sequence_of[1] = {
  { &hf_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_MsrAssistBTS_R98_ExpOTD },
};

static int
dissect_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD, SeqOfMsrAssistBTS_R98_ExpOTD_sequence_of,
                                                  1, 15, false);

  return offset;
}


static const per_sequence_t MsrAssistData_R98_ExpOTD_sequence[] = {
  { &hf_rrlp_msrAssistList_R98_ExpOTD, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MsrAssistData_R98_ExpOTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_MsrAssistData_R98_ExpOTD, MsrAssistData_R98_ExpOTD_sequence);

  return offset;
}


static const per_sequence_t AssistBTSData_R98_ExpOTD_sequence[] = {
  { &hf_rrlp_expectedOTD    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_ExpectedOTD },
  { &hf_rrlp_expOTDuncertainty, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_ExpOTDUncertainty },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AssistBTSData_R98_ExpOTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_AssistBTSData_R98_ExpOTD, AssistBTSData_R98_ExpOTD_sequence);

  return offset;
}


static const value_string rrlp_SystemInfoAssistBTS_R98_ExpOTD_vals[] = {
  {   0, "notPresent" },
  {   1, "present" },
  { 0, NULL }
};

static const per_choice_t SystemInfoAssistBTS_R98_ExpOTD_choice[] = {
  {   0, &hf_rrlp_notPresent     , ASN1_NO_EXTENSIONS     , dissect_rrlp_NULL },
  {   1, &hf_rrlp_present_01     , ASN1_NO_EXTENSIONS     , dissect_rrlp_AssistBTSData_R98_ExpOTD },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_SystemInfoAssistBTS_R98_ExpOTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_SystemInfoAssistBTS_R98_ExpOTD, SystemInfoAssistBTS_R98_ExpOTD_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SeqOfSystemInfoAssistBTS_R98_ExpOTD_sequence_of[1] = {
  { &hf_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SystemInfoAssistBTS_R98_ExpOTD },
};

static int
dissect_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD, SeqOfSystemInfoAssistBTS_R98_ExpOTD_sequence_of,
                                                  1, 32, false);

  return offset;
}


static const per_sequence_t SystemInfoAssistData_R98_ExpOTD_sequence[] = {
  { &hf_rrlp_systemInfoAssistListR98_ExpOTD, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_SystemInfoAssistData_R98_ExpOTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_SystemInfoAssistData_R98_ExpOTD, SystemInfoAssistData_R98_ExpOTD_sequence);

  return offset;
}


static const per_sequence_t Rel98_Ext_ExpOTD_sequence[] = {
  { &hf_rrlp_msrAssistData_R98_ExpOTD, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_MsrAssistData_R98_ExpOTD },
  { &hf_rrlp_systemInfoAssistData_R98_ExpOTD, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_SystemInfoAssistData_R98_ExpOTD },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel98_Ext_ExpOTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Rel98_Ext_ExpOTD, Rel98_Ext_ExpOTD_sequence);

  return offset;
}



static int
dissect_rrlp_GPSReferenceTimeUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t Rel98_MsrPosition_Req_Extension_sequence[] = {
  { &hf_rrlp_rel98_Ext_ExpOTD, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_Rel98_Ext_ExpOTD },
  { &hf_rrlp_gpsTimeAssistanceMeasurementRequest, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_NULL },
  { &hf_rrlp_gpsReferenceTimeUncertainty, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GPSReferenceTimeUncertainty },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel98_MsrPosition_Req_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Rel98_MsrPosition_Req_Extension, Rel98_MsrPosition_Req_Extension_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_262143(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 262143U, NULL, false);

  return offset;
}


static const per_sequence_t Extended_reference_sequence[] = {
  { &hf_rrlp_smlc_code      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_63 },
  { &hf_rrlp_transaction_ID , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_262143 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Extended_reference(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Extended_reference, Extended_reference_sequence);

  return offset;
}


static const per_sequence_t Rel5_MsrPosition_Req_Extension_sequence[] = {
  { &hf_rrlp_extended_reference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_Extended_reference },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel5_MsrPosition_Req_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Rel5_MsrPosition_Req_Extension, Rel5_MsrPosition_Req_Extension_sequence);

  return offset;
}


static int * const GANSSPositioningMethod_bits[] = {
  &hf_rrlp_GANSSPositioningMethod_gps,
  &hf_rrlp_GANSSPositioningMethod_galileo,
  &hf_rrlp_GANSSPositioningMethod_sbas,
  &hf_rrlp_GANSSPositioningMethod_modernizedGPS,
  &hf_rrlp_GANSSPositioningMethod_qzss,
  &hf_rrlp_GANSSPositioningMethod_glonass,
  NULL
};

static int
dissect_rrlp_GANSSPositioningMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 16, false, GANSSPositioningMethod_bits, 6, NULL, NULL);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_8191(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8191U, NULL, false);

  return offset;
}



static int
dissect_rrlp_GANSSTOD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 86399U, NULL, false);

  return offset;
}



static int
dissect_rrlp_GANSSTODUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t GANSSRefTimeInfo_sequence[] = {
  { &hf_rrlp_ganssDay       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_8191 },
  { &hf_rrlp_ganssTOD       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSTOD },
  { &hf_rrlp_ganssTODUncertainty, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_GANSSTODUncertainty },
  { &hf_rrlp_ganssTimeID    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSRefTimeInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSRefTimeInfo, GANSSRefTimeInfo_sequence);

  return offset;
}



static int
dissect_rrlp_FrameDrift(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -64, 63U, NULL, false);

  return offset;
}


static const per_sequence_t GANSSTOD_GSMTimeAssociation_sequence[] = {
  { &hf_rrlp_bcchCarrier    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BCCHCarrier },
  { &hf_rrlp_bsic           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BSIC },
  { &hf_rrlp_frameNumber    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_FrameNumber },
  { &hf_rrlp_timeSlot       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_TimeSlot },
  { &hf_rrlp_bitNumber      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BitNumber },
  { &hf_rrlp_frameDrift     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_FrameDrift },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSTOD_GSMTimeAssociation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSTOD_GSMTimeAssociation, GANSSTOD_GSMTimeAssociation_sequence);

  return offset;
}


static const per_sequence_t GANSSReferenceTime_sequence[] = {
  { &hf_rrlp_ganssRefTimeInfo, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSRefTimeInfo },
  { &hf_rrlp_ganssTOD_GSMTimeAssociation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_GANSSTOD_GSMTimeAssociation },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSReferenceTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSReferenceTime, GANSSReferenceTime_sequence);

  return offset;
}


static const per_sequence_t GANSSRefLocation_sequence[] = {
  { &hf_rrlp_threeDLocation , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_Ext_GeographicalInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSRefLocation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSRefLocation, GANSSRefLocation_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, false);

  return offset;
}


static const per_sequence_t GANSSIonosphereModel_sequence[] = {
  { &hf_rrlp_ai0            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_4095 },
  { &hf_rrlp_ai1            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_4095 },
  { &hf_rrlp_ai2            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_4095 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSIonosphereModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSIonosphereModel, GANSSIonosphereModel_sequence);

  return offset;
}


static const per_sequence_t GANSSIonoStormFlags_sequence[] = {
  { &hf_rrlp_ionoStormFlag1 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1 },
  { &hf_rrlp_ionoStormFlag2 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1 },
  { &hf_rrlp_ionoStormFlag3 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1 },
  { &hf_rrlp_ionoStormFlag4 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1 },
  { &hf_rrlp_ionoStormFlag5 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSIonoStormFlags(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSIonoStormFlags, GANSSIonoStormFlags_sequence);

  return offset;
}


static const per_sequence_t GANSSIonosphericModel_sequence[] = {
  { &hf_rrlp_ganssIonoModel , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSIonosphereModel },
  { &hf_rrlp_ganssIonoStormFlags, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSIonoStormFlags },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSIonosphericModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSIonosphericModel, GANSSIonosphericModel_sequence);

  return offset;
}



static int
dissect_rrlp_BIT_STRING_SIZE_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 2, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GANSSAddIonosphericModel_sequence[] = {
  { &hf_rrlp_dataID         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BIT_STRING_SIZE_2 },
  { &hf_rrlp_ionoModel      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_IonosphericModel },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSAddIonosphericModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSAddIonosphericModel, GANSSAddIonosphericModel_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_M1048576_1048575(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1048576, 1048575U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M16384_16383(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -16384, 16383U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M1073741824_1073741823(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -1073741824, 1073741823U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M262144_262143(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -262144, 262143U, NULL, false);

  return offset;
}


static const per_sequence_t GANSSEarthOrientParam_sequence[] = {
  { &hf_rrlp_teop           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_65535 },
  { &hf_rrlp_pmX            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1048576_1048575 },
  { &hf_rrlp_pmXdot         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16384_16383 },
  { &hf_rrlp_pmY            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1048576_1048575 },
  { &hf_rrlp_pmYdot         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16384_16383 },
  { &hf_rrlp_deltaUT1       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1073741824_1073741823 },
  { &hf_rrlp_deltaUT1dot    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M262144_262143 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSEarthOrientParam(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSEarthOrientParam, GANSSEarthOrientParam_sequence);

  return offset;
}


static const per_sequence_t GANSSReferenceTime_R10_Ext_sequence[] = {
  { &hf_rrlp_ganssDayCycleNumber, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSReferenceTime_R10_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSReferenceTime_R10_Ext, GANSSReferenceTime_R10_Ext_sequence);

  return offset;
}


static const per_sequence_t GANSSCommonAssistData_sequence[] = {
  { &hf_rrlp_ganssReferenceTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSReferenceTime },
  { &hf_rrlp_ganssRefLocation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSRefLocation },
  { &hf_rrlp_ganssIonosphericModel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSIonosphericModel },
  { &hf_rrlp_ganssAddIonosphericModel, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GANSSAddIonosphericModel },
  { &hf_rrlp_ganssEarthOrientParam, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GANSSEarthOrientParam },
  { &hf_rrlp_ganssReferenceTime_R10_Ext, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GANSSReferenceTime_R10_Ext },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSCommonAssistData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSCommonAssistData, GANSSCommonAssistData_sequence);

  return offset;
}



static int
dissect_rrlp_TA0(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            INT32_MIN, 2147483647U, NULL, false);

  return offset;
}



static int
dissect_rrlp_TA1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, false);

  return offset;
}



static int
dissect_rrlp_TA2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -64, 63U, NULL, false);

  return offset;
}


static const per_sequence_t GANSSTimeModelElement_sequence[] = {
  { &hf_rrlp_ganssTimeModelRefTime, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_65535 },
  { &hf_rrlp_tA0            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_TA0 },
  { &hf_rrlp_tA1            , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_TA1 },
  { &hf_rrlp_tA2            , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_TA2 },
  { &hf_rrlp_gnssTOID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_weekNumber     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_8191 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSTimeModelElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSTimeModelElement, GANSSTimeModelElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfGANSSTimeModel_sequence_of[1] = {
  { &hf_rrlp_SeqOfGANSSTimeModel_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSTimeModelElement },
};

static int
dissect_rrlp_SeqOfGANSSTimeModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGANSSTimeModel, SeqOfGANSSTimeModel_sequence_of,
                                                  1, 7, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_119(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 119U, NULL, false);

  return offset;
}



static int
dissect_rrlp_GANSSSignalID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}



static int
dissect_rrlp_SVID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, false);

  return offset;
}


static const per_sequence_t DGANSSSgnElement_sequence[] = {
  { &hf_rrlp_svID           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_iod            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1023 },
  { &hf_rrlp_udre           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_3 },
  { &hf_rrlp_pseudoRangeCor , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2047_2047 },
  { &hf_rrlp_rangeRateCor   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M127_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_DGANSSSgnElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_DGANSSSgnElement, DGANSSSgnElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfDGANSSSgnElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfDGANSSSgnElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_DGANSSSgnElement },
};

static int
dissect_rrlp_SeqOfDGANSSSgnElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfDGANSSSgnElement, SeqOfDGANSSSgnElement_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t SgnTypeElement_sequence[] = {
  { &hf_rrlp_ganssSignalID  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSSignalID },
  { &hf_rrlp_ganssStatusHealth, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_dganssSgnList  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfDGANSSSgnElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_SgnTypeElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_SgnTypeElement, SgnTypeElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfSgnTypeElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfSgnTypeElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SgnTypeElement },
};

static int
dissect_rrlp_SeqOfSgnTypeElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfSgnTypeElement, SeqOfSgnTypeElement_sequence_of,
                                                  1, 3, false);

  return offset;
}


static const per_sequence_t GANSSDiffCorrections_sequence[] = {
  { &hf_rrlp_dganssRefTime  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_119 },
  { &hf_rrlp_sgnTypeList    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfSgnTypeElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSDiffCorrections(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSDiffCorrections, GANSSDiffCorrections_sequence);

  return offset;
}



static int
dissect_rrlp_BIT_STRING_SIZE_5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     5, 5, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_16383(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M131072_131071(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -131072, 131071U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M134217728_134217727(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -134217728, 134217727U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M512_511(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -512, 511U, NULL, false);

  return offset;
}


static const per_sequence_t StandardClockModelElement_sequence[] = {
  { &hf_rrlp_stanClockToc   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_16383 },
  { &hf_rrlp_stanClockAF2   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2048_2047 },
  { &hf_rrlp_stanClockAF1   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M131072_131071 },
  { &hf_rrlp_stanClockAF0   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M134217728_134217727 },
  { &hf_rrlp_stanClockTgd   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_M512_511 },
  { &hf_rrlp_stanModelID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_StandardClockModelElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_StandardClockModelElement, StandardClockModelElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfStandardClockModelElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfStandardClockModelElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_StandardClockModelElement },
};

static int
dissect_rrlp_SeqOfStandardClockModelElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfStandardClockModelElement, SeqOfStandardClockModelElement_sequence_of,
                                                  1, 2, false);

  return offset;
}


static const per_sequence_t NAVclockModel_sequence[] = {
  { &hf_rrlp_navToc         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_37799 },
  { &hf_rrlp_navaf2         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_navaf1         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_navaf0         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2097152_2097151 },
  { &hf_rrlp_navTgd         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_NAVclockModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_NAVclockModel, NAVclockModel_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_2015(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2015U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M16_15(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -16, 15U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M524288_524287(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -524288, 524287U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M33554432_33554431(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -33554432, 33554431U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M4096_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -4096, 4095U, NULL, false);

  return offset;
}


static const per_sequence_t CNAVclockModel_sequence[] = {
  { &hf_rrlp_cnavToc        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_2015 },
  { &hf_rrlp_cnavTop        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_2015 },
  { &hf_rrlp_cnavURA0       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_cnavURA1       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_cnavURA2       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_cnavAf2        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M512_511 },
  { &hf_rrlp_cnavAf1        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M524288_524287 },
  { &hf_rrlp_cnavAf0        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M33554432_33554431 },
  { &hf_rrlp_cnavTgd        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M4096_4095 },
  { &hf_rrlp_cnavISCl1cp    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_M4096_4095 },
  { &hf_rrlp_cnavISCl1cd    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_M4096_4095 },
  { &hf_rrlp_cnavISCl1ca    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_M4096_4095 },
  { &hf_rrlp_cnavISCl2c     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_M4096_4095 },
  { &hf_rrlp_cnavISCl5i5    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_M4096_4095 },
  { &hf_rrlp_cnavISCl5q5    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_M4096_4095 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_CNAVclockModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_CNAVclockModel, CNAVclockModel_sequence);

  return offset;
}


static const per_sequence_t GLONASSclockModel_sequence[] = {
  { &hf_rrlp_gloTau         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2097152_2097151 },
  { &hf_rrlp_gloGamma       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1024_1023 },
  { &hf_rrlp_gloDeltaTau    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_M16_15 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GLONASSclockModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GLONASSclockModel, GLONASSclockModel_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_5399(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 5399U, NULL, false);

  return offset;
}


static const per_sequence_t SBASclockModel_sequence[] = {
  { &hf_rrlp_sbasTo         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_5399 },
  { &hf_rrlp_sbasAgfo       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2048_2047 },
  { &hf_rrlp_sbasAgf1       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_SBASclockModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_SBASclockModel, SBASclockModel_sequence);

  return offset;
}


static const value_string rrlp_GANSSClockModel_vals[] = {
  {   0, "standardClockModelList" },
  {   1, "navClockModel" },
  {   2, "cnavClockModel" },
  {   3, "glonassClockModel" },
  {   4, "sbasClockModel" },
  { 0, NULL }
};

static const per_choice_t GANSSClockModel_choice[] = {
  {   0, &hf_rrlp_standardClockModelList, ASN1_EXTENSION_ROOT    , dissect_rrlp_SeqOfStandardClockModelElement },
  {   1, &hf_rrlp_navClockModel  , ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_NAVclockModel },
  {   2, &hf_rrlp_cnavClockModel , ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_CNAVclockModel },
  {   3, &hf_rrlp_glonassClockModel, ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_GLONASSclockModel },
  {   4, &hf_rrlp_sbasClockModel , ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_SBASclockModel },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_GANSSClockModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_GANSSClockModel, GANSSClockModel_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t NavModel_KeplerianSet_sequence[] = {
  { &hf_rrlp_keplerToe      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_16383 },
  { &hf_rrlp_keplerW        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_keplerDeltaN   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_keplerM0       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_keplerOmegaDot , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_keplerE        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_4294967295 },
  { &hf_rrlp_keplerIDot     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8192_8191 },
  { &hf_rrlp_keplerAPowerHalf, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_4294967295 },
  { &hf_rrlp_keplerI0       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_keplerOmega0   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_keplerCrs      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_keplerCis      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_keplerCus      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_keplerCrc      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_keplerCic      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_keplerCuc      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_NavModel_KeplerianSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_NavModel_KeplerianSet, NavModel_KeplerianSet_sequence);

  return offset;
}


static const per_sequence_t NavModel_NAVKeplerianSet_sequence[] = {
  { &hf_rrlp_navURA         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_15 },
  { &hf_rrlp_navFitFlag     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1 },
  { &hf_rrlp_navToe         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_37799 },
  { &hf_rrlp_navOmega       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_navDeltaN      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_navM0          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_navOmegaADot   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_navE           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_4294967295 },
  { &hf_rrlp_navIDot        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8192_8191 },
  { &hf_rrlp_navAPowerHalf  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_4294967295 },
  { &hf_rrlp_navI0          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_navOmegaA0     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_navCrs         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_navCis         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_navCus         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_navCrc         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_navCic         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_navCuc         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_NavModel_NAVKeplerianSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_NavModel_NAVKeplerianSet, NavModel_NAVKeplerianSet_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_M16777216_16777215(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -16777216, 16777215U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M65536_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -65536, 65535U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M4194304_4194303(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -4194304, 4194303U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M4294967296_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            INT64_C(-4294967296), 4294967295U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_8589934591(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer_64b(tvb, offset, actx, tree, hf_index,
                                                            0U, UINT64_C(8589934591), NULL, false);

  return offset;
}


static const per_sequence_t NavModel_CNAVKeplerianSet_sequence[] = {
  { &hf_rrlp_cnavTop        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_2015 },
  { &hf_rrlp_cnavURAindex   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_cnavDeltaA     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M33554432_33554431 },
  { &hf_rrlp_cnavAdot       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16777216_16777215 },
  { &hf_rrlp_cnavDeltaNo    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M65536_65535 },
  { &hf_rrlp_cnavDeltaNoDot , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M4194304_4194303 },
  { &hf_rrlp_cnavMo         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M4294967296_4294967295 },
  { &hf_rrlp_cnavE          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_8589934591 },
  { &hf_rrlp_cnavOmega      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M4294967296_4294967295 },
  { &hf_rrlp_cnavOMEGA0     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M4294967296_4294967295 },
  { &hf_rrlp_cnavDeltaOmegaDot, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M65536_65535 },
  { &hf_rrlp_cnavIo         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M4294967296_4294967295 },
  { &hf_rrlp_cnavIoDot      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16384_16383 },
  { &hf_rrlp_cnavCis        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_cnavCic        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_cnavCrs        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_cnavCrc        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_cnavCus        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1048576_1048575 },
  { &hf_rrlp_cnavCuc        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1048576_1048575 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_NavModel_CNAVKeplerianSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_NavModel_CNAVKeplerianSet, NavModel_CNAVKeplerianSet_sequence);

  return offset;
}



static int
dissect_rrlp_BOOLEAN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}



static int
dissect_rrlp_INTEGER_M67108864_67108863(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -67108864, 67108863U, NULL, false);

  return offset;
}


static const per_sequence_t NavModel_GLONASSecef_sequence[] = {
  { &hf_rrlp_gloEn          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_31 },
  { &hf_rrlp_gloP1          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BIT_STRING_SIZE_2 },
  { &hf_rrlp_gloP2          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BOOLEAN },
  { &hf_rrlp_gloM           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_3 },
  { &hf_rrlp_gloX           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M67108864_67108863 },
  { &hf_rrlp_gloXdot        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_gloXdotdot     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_gloY           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M67108864_67108863 },
  { &hf_rrlp_gloYdot        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_gloYdotdot     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_gloZ           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M67108864_67108863 },
  { &hf_rrlp_gloZdot        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_gloZdotdot     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_NavModel_GLONASSecef(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_NavModel_GLONASSecef, NavModel_GLONASSecef_sequence);

  return offset;
}



static int
dissect_rrlp_BIT_STRING_SIZE_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     4, 4, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_rrlp_INTEGER_M536870912_536870911(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -536870912, 536870911U, NULL, false);

  return offset;
}


static const per_sequence_t NavModel_SBASecef_sequence[] = {
  { &hf_rrlp_sbasTo         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_5399 },
  { &hf_rrlp_sbasAccuracy   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BIT_STRING_SIZE_4 },
  { &hf_rrlp_sbasXg         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M536870912_536870911 },
  { &hf_rrlp_sbasYg         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M536870912_536870911 },
  { &hf_rrlp_sbasZg         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16777216_16777215 },
  { &hf_rrlp_sbasXgDot      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M65536_65535 },
  { &hf_rrlp_sbasYgDot      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M65536_65535 },
  { &hf_rrlp_sbasZgDot      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M131072_131071 },
  { &hf_rrlp_sbasXgDotDot   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M512_511 },
  { &hf_rrlp_sbagYgDotDot   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M512_511 },
  { &hf_rrlp_sbasZgDotDot   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M512_511 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_NavModel_SBASecef(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_NavModel_SBASecef, NavModel_SBASecef_sequence);

  return offset;
}


static const value_string rrlp_GANSSOrbitModel_vals[] = {
  {   0, "keplerianSet" },
  {   1, "navKeplerianSet" },
  {   2, "cnavKeplerianSet" },
  {   3, "glonassECEF" },
  {   4, "sbasECEF" },
  { 0, NULL }
};

static const per_choice_t GANSSOrbitModel_choice[] = {
  {   0, &hf_rrlp_keplerianSet   , ASN1_EXTENSION_ROOT    , dissect_rrlp_NavModel_KeplerianSet },
  {   1, &hf_rrlp_navKeplerianSet, ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_NavModel_NAVKeplerianSet },
  {   2, &hf_rrlp_cnavKeplerianSet, ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_NavModel_CNAVKeplerianSet },
  {   3, &hf_rrlp_glonassECEF    , ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_NavModel_GLONASSecef },
  {   4, &hf_rrlp_sbasECEF       , ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_NavModel_SBASecef },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_GANSSOrbitModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_GANSSOrbitModel, GANSSOrbitModel_choice,
                                 NULL);

  return offset;
}



static int
dissect_rrlp_BIT_STRING_SIZE_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 1, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GANSSSatelliteElement_sequence[] = {
  { &hf_rrlp_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_svHealth       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_BIT_STRING_SIZE_5 },
  { &hf_rrlp_iod            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1023 },
  { &hf_rrlp_ganssClockModel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSClockModel },
  { &hf_rrlp_ganssOrbitModel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSOrbitModel },
  { &hf_rrlp_svHealthMSB    , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_BIT_STRING_SIZE_1 },
  { &hf_rrlp_iodMSB         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSSatelliteElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSSatelliteElement, GANSSSatelliteElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfGANSSSatelliteElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfGANSSSatelliteElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSSatelliteElement },
};

static int
dissect_rrlp_SeqOfGANSSSatelliteElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGANSSSatelliteElement, SeqOfGANSSSatelliteElement_sequence_of,
                                                  1, 32, false);

  return offset;
}


static const per_sequence_t GANSSNavModel_sequence[] = {
  { &hf_rrlp_nonBroadcastIndFlag, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1 },
  { &hf_rrlp_ganssSatelliteList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGANSSSatelliteElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSNavModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSNavModel, GANSSNavModel_sequence);

  return offset;
}


static int * const GANSSSignals_bits[] = {
  &hf_rrlp_GANSSSignals_signal1,
  &hf_rrlp_GANSSSignals_signal2,
  &hf_rrlp_GANSSSignals_signal3,
  &hf_rrlp_GANSSSignals_signal4,
  &hf_rrlp_GANSSSignals_signal5,
  &hf_rrlp_GANSSSignals_signal6,
  &hf_rrlp_GANSSSignals_signal7,
  &hf_rrlp_GANSSSignals_signal8,
  NULL
};

static int
dissect_rrlp_GANSSSignals(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 8, false, GANSSSignals_bits, 8, NULL, NULL);

  return offset;
}


static const per_sequence_t BadSignalElement_sequence[] = {
  { &hf_rrlp_badSVID        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_badSignalID    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_GANSSSignals },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_BadSignalElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_BadSignalElement, BadSignalElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfBadSignalElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfBadSignalElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BadSignalElement },
};

static int
dissect_rrlp_SeqOfBadSignalElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfBadSignalElement, SeqOfBadSignalElement_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t GANSSRealTimeIntegrity_sequence[] = {
  { &hf_rrlp_ganssBadSignalList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfBadSignalElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSRealTimeIntegrity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSRealTimeIntegrity, GANSSRealTimeIntegrity_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_59(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, false);

  return offset;
}



static int
dissect_rrlp_GANSSDataBit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, false);

  return offset;
}


static const per_sequence_t SeqOf_GANSSDataBits_sequence_of[1] = {
  { &hf_rrlp_SeqOf_GANSSDataBits_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSDataBit },
};

static int
dissect_rrlp_SeqOf_GANSSDataBits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOf_GANSSDataBits, SeqOf_GANSSDataBits_sequence_of,
                                                  1, 1024, false);

  return offset;
}


static const per_sequence_t GANSSDataBitsSgnElement_sequence[] = {
  { &hf_rrlp_ganssSignalType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSSignalID },
  { &hf_rrlp_ganssDataBits  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOf_GANSSDataBits },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSDataBitsSgnElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSDataBitsSgnElement, GANSSDataBitsSgnElement_sequence);

  return offset;
}


static const per_sequence_t Seq_OfGANSSDataBitsSgn_sequence_of[1] = {
  { &hf_rrlp_Seq_OfGANSSDataBitsSgn_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSDataBitsSgnElement },
};

static int
dissect_rrlp_Seq_OfGANSSDataBitsSgn(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_Seq_OfGANSSDataBitsSgn, Seq_OfGANSSDataBitsSgn_sequence_of,
                                                  1, 8, false);

  return offset;
}


static const per_sequence_t GanssDataBitsElement_sequence[] = {
  { &hf_rrlp_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_ganssDataBitsSgnList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_Seq_OfGANSSDataBitsSgn },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GanssDataBitsElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GanssDataBitsElement, GanssDataBitsElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfGanssDataBitsElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfGanssDataBitsElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GanssDataBitsElement },
};

static int
dissect_rrlp_SeqOfGanssDataBitsElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGanssDataBitsElement, SeqOfGanssDataBitsElement_sequence_of,
                                                  1, 32, false);

  return offset;
}


static const per_sequence_t GANSSDataBitAssist_sequence[] = {
  { &hf_rrlp_ganssTOD_01    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_59 },
  { &hf_rrlp_ganssDataBitsSatList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGanssDataBitsElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSDataBitAssist(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSDataBitAssist, GANSSDataBitAssist_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4U, NULL, false);

  return offset;
}


static const per_sequence_t AdditionalDopplerFields_sequence[] = {
  { &hf_rrlp_doppler1       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_63 },
  { &hf_rrlp_dopplerUncertainty_01, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AdditionalDopplerFields(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_AdditionalDopplerFields, AdditionalDopplerFields_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, false);

  return offset;
}


static const per_sequence_t GANSSRefMeasurementElement_sequence[] = {
  { &hf_rrlp_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_doppler0       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2048_2047 },
  { &hf_rrlp_additionalDoppler, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_AdditionalDopplerFields },
  { &hf_rrlp_codePhase      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1022 },
  { &hf_rrlp_intCodePhase_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_127 },
  { &hf_rrlp_codePhaseSearchWindow_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_31 },
  { &hf_rrlp_additionalAngle, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_AddionalAngleFields },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSRefMeasurementElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSRefMeasurementElement, GANSSRefMeasurementElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfGANSSRefMeasurementElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfGANSSRefMeasurementElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSRefMeasurementElement },
};

static int
dissect_rrlp_SeqOfGANSSRefMeasurementElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGANSSRefMeasurementElement, SeqOfGANSSRefMeasurementElement_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t GANSSRefMeasurementAssist_sequence[] = {
  { &hf_rrlp_ganssSignalID  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSSignalID },
  { &hf_rrlp_ganssRefMeasAssistList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGANSSRefMeasurementElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSRefMeasurementAssist(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSRefMeasurementAssist, GANSSRefMeasurementAssist_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2047U, NULL, false);

  return offset;
}


static const per_sequence_t Almanac_KeplerianSet_sequence[] = {
  { &hf_rrlp_svID           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_kepAlmanacE    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_2047 },
  { &hf_rrlp_kepAlmanacDeltaI, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1024_1023 },
  { &hf_rrlp_kepAlmanacOmegaDot, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1024_1023 },
  { &hf_rrlp_kepSVHealth    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_15 },
  { &hf_rrlp_kepAlmanacAPowerHalf, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M65536_65535 },
  { &hf_rrlp_kepAlmanacOmega0, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_kepAlmanacW    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_kepAlmanacM0   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_kepAlmanacAF0  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8192_8191 },
  { &hf_rrlp_kepAlmanacAF1  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1024_1023 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Almanac_KeplerianSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Almanac_KeplerianSet, Almanac_KeplerianSet_sequence);

  return offset;
}


static const per_sequence_t Almanac_NAVKeplerianSet_sequence[] = {
  { &hf_rrlp_svID           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_navAlmE        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_65535 },
  { &hf_rrlp_navAlmDeltaI   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_navAlmOMEGADOT , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_navAlmSVHealth , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_navAlmSqrtA    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_16777215 },
  { &hf_rrlp_navAlmOMEGAo   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_navAlmOmega    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_navAlmMo       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_navAlmaf0      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1024_1023 },
  { &hf_rrlp_navAlmaf1      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1024_1023 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Almanac_NAVKeplerianSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Almanac_NAVKeplerianSet, Almanac_NAVKeplerianSet_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_M64_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -64, 63U, NULL, false);

  return offset;
}


static const per_sequence_t Almanac_ReducedKeplerianSet_sequence[] = {
  { &hf_rrlp_svID           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_redAlmDeltaA   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_redAlmOmega0   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M64_63 },
  { &hf_rrlp_redAlmPhi0     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M64_63 },
  { &hf_rrlp_redAlmL1Health , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BOOLEAN },
  { &hf_rrlp_redAlmL2Health , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BOOLEAN },
  { &hf_rrlp_redAlmL5Health , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Almanac_ReducedKeplerianSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Almanac_ReducedKeplerianSet, Almanac_ReducedKeplerianSet_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_131071(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 131071U, NULL, false);

  return offset;
}


static const per_sequence_t Almanac_MidiAlmanacSet_sequence[] = {
  { &hf_rrlp_svID           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_midiAlmE       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_2047 },
  { &hf_rrlp_midiAlmDeltaI  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1024_1023 },
  { &hf_rrlp_midiAlmOmegaDot, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1024_1023 },
  { &hf_rrlp_midiAlmSqrtA   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_131071 },
  { &hf_rrlp_midiAlmOmega0  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_midiAlmOmega   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_midiAlmMo      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_midiAlmaf0     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1024_1023 },
  { &hf_rrlp_midiAlmaf1     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M512_511 },
  { &hf_rrlp_midiAlmL1Health, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BOOLEAN },
  { &hf_rrlp_midiAlmL2Health, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BOOLEAN },
  { &hf_rrlp_midiAlmL5Health, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Almanac_MidiAlmanacSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Almanac_MidiAlmanacSet, Almanac_MidiAlmanacSet_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_1_1461(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 1461U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_1_24(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 24U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_2097151(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2097151U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 32767U, NULL, false);

  return offset;
}


static const per_sequence_t Almanac_GlonassAlmanacSet_sequence[] = {
  { &hf_rrlp_gloAlmNA       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_1461 },
  { &hf_rrlp_gloAlmnA       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_24 },
  { &hf_rrlp_gloAlmHA       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_31 },
  { &hf_rrlp_gloAlmLambdaA  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M1048576_1048575 },
  { &hf_rrlp_gloAlmtlambdaA , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_2097151 },
  { &hf_rrlp_gloAlmDeltaIa  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M131072_131071 },
  { &hf_rrlp_gloAlmDeltaTA  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2097152_2097151 },
  { &hf_rrlp_gloAlmDeltaTdotA, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M64_63 },
  { &hf_rrlp_gloAlmEpsilonA , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_32767 },
  { &hf_rrlp_gloAlmOmegaA   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_gloAlmTauA     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M512_511 },
  { &hf_rrlp_gloAlmCA       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1 },
  { &hf_rrlp_gloAlmMA       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_BIT_STRING_SIZE_2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Almanac_GlonassAlmanacSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Almanac_GlonassAlmanacSet, Almanac_GlonassAlmanacSet_sequence);

  return offset;
}



static int
dissect_rrlp_BIT_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, false, NULL, 0, NULL, NULL);

  return offset;
}



static int
dissect_rrlp_INTEGER_M256_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -256, 255U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M4_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -4, 3U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M8_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8, 7U, NULL, false);

  return offset;
}


static const per_sequence_t Almanac_ECEFsbasAlmanacSet_sequence[] = {
  { &hf_rrlp_sbasAlmDataID  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_3 },
  { &hf_rrlp_svID           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_sbasAlmHealth  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BIT_STRING_SIZE_8 },
  { &hf_rrlp_sbasAlmXg      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16384_16383 },
  { &hf_rrlp_sbasAlmYg      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16384_16383 },
  { &hf_rrlp_sbasAlmZg      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M256_255 },
  { &hf_rrlp_sbasAlmXgdot   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M4_3 },
  { &hf_rrlp_sbasAlmYgDot   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M4_3 },
  { &hf_rrlp_sbasAlmZgDot   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8_7 },
  { &hf_rrlp_sbasAlmTo      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_2047 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Almanac_ECEFsbasAlmanacSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Almanac_ECEFsbasAlmanacSet, Almanac_ECEFsbasAlmanacSet_sequence);

  return offset;
}


static const value_string rrlp_GANSSAlmanacElement_vals[] = {
  {   0, "keplerianAlmanacSet" },
  {   1, "keplerianNAVAlmanac" },
  {   2, "keplerianReducedAlmanac" },
  {   3, "keplerianMidiAlmanac" },
  {   4, "keplerianGLONASS" },
  {   5, "ecefSBASAlmanac" },
  { 0, NULL }
};

static const per_choice_t GANSSAlmanacElement_choice[] = {
  {   0, &hf_rrlp_keplerianAlmanacSet, ASN1_EXTENSION_ROOT    , dissect_rrlp_Almanac_KeplerianSet },
  {   1, &hf_rrlp_keplerianNAVAlmanac, ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_Almanac_NAVKeplerianSet },
  {   2, &hf_rrlp_keplerianReducedAlmanac, ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_Almanac_ReducedKeplerianSet },
  {   3, &hf_rrlp_keplerianMidiAlmanac, ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_Almanac_MidiAlmanacSet },
  {   4, &hf_rrlp_keplerianGLONASS, ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_Almanac_GlonassAlmanacSet },
  {   5, &hf_rrlp_ecefSBASAlmanac, ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_Almanac_ECEFsbasAlmanacSet },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_GANSSAlmanacElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_GANSSAlmanacElement, GANSSAlmanacElement_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SeqOfGANSSAlmanacElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfGANSSAlmanacElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSAlmanacElement },
};

static int
dissect_rrlp_SeqOfGANSSAlmanacElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGANSSAlmanacElement, SeqOfGANSSAlmanacElement_sequence_of,
                                                  1, 36, false);

  return offset;
}


static const per_sequence_t GANSSAlmanacModel_sequence[] = {
  { &hf_rrlp_weekNumber_01  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_toa            , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_ioda           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_3 },
  { &hf_rrlp_ganssAlmanacList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGANSSAlmanacElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSAlmanacModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSAlmanacModel, GANSSAlmanacModel_sequence);

  return offset;
}


static const per_sequence_t GANSSUTCModel_sequence[] = {
  { &hf_rrlp_ganssUtcA1     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_ganssUtcA0     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_ganssUtcTot    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_ganssUtcWNt    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_ganssUtcDeltaTls, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_ganssUtcWNlsf  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_ganssUtcDN     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_ganssUtcDeltaTlsf, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSUTCModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSUTCModel, GANSSUTCModel_sequence);

  return offset;
}


static const per_sequence_t GANSSEphemerisExtensionTime_sequence[] = {
  { &hf_rrlp_ganssEphExtDay , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_8191 },
  { &hf_rrlp_ganssEphExtTOD , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSTOD },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSEphemerisExtensionTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSEphemerisExtensionTime, GANSSEphemerisExtensionTime_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_1_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_1_512(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 512U, NULL, false);

  return offset;
}


static const per_sequence_t GANSSEphemerisExtensionHeader_sequence[] = {
  { &hf_rrlp_timeAtEstimation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSEphemerisExtensionTime },
  { &hf_rrlp_validityPeriod , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_8 },
  { &hf_rrlp_ephemerisExtensionDuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_512 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSEphemerisExtensionHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSEphemerisExtensionHeader, GANSSEphemerisExtensionHeader_sequence);

  return offset;
}


static const per_sequence_t ReferenceNavModel_sequence[] = {
  { &hf_rrlp_keplerToe_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_37799 },
  { &hf_rrlp_keplerW        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_keplerDeltaN   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_keplerM0       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_keplerOmegaDot , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_keplerE        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_4294967295 },
  { &hf_rrlp_keplerIDot     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8192_8191 },
  { &hf_rrlp_keplerAPowerHalf, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_4294967295 },
  { &hf_rrlp_keplerI0       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_keplerOmega0   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_keplerCrs      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_keplerCis      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_keplerCus      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_keplerCrc      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_keplerCic      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_keplerCuc      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ReferenceNavModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_ReferenceNavModel, ReferenceNavModel_sequence);

  return offset;
}


static const per_sequence_t GANSSReferenceOrbit_sequence[] = {
  { &hf_rrlp_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_ganssOrbitModel_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_ReferenceNavModel },
  { &hf_rrlp_ganssClockModel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSClockModel },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSReferenceOrbit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSReferenceOrbit, GANSSReferenceOrbit_sequence);

  return offset;
}


static const per_sequence_t SeqOfGANSSRefOrbit_sequence_of[1] = {
  { &hf_rrlp_SeqOfGANSSRefOrbit_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSReferenceOrbit },
};

static int
dissect_rrlp_SeqOfGANSSRefOrbit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGANSSRefOrbit, SeqOfGANSSRefOrbit_sequence_of,
                                                  1, 32, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_1_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_1_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_1_14(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 14U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_1_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 10U, NULL, false);

  return offset;
}


static const per_sequence_t GANSSEphemerisDeltaBitSizes_sequence[] = {
  { &hf_rrlp_bitsize_delta_omega, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_32 },
  { &hf_rrlp_bitsize_delta_deltaN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_m0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_32 },
  { &hf_rrlp_bitsize_delta_omegadot, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_24 },
  { &hf_rrlp_bitsize_delta_e, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_32 },
  { &hf_rrlp_bitsize_delta_idot, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_14 },
  { &hf_rrlp_bitsize_delta_sqrtA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_32 },
  { &hf_rrlp_bitsize_delta_i0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_32 },
  { &hf_rrlp_bitsize_delta_omega0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_32 },
  { &hf_rrlp_bitsize_delta_crs, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_cis, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_cus, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_crc, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_cic, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_cuc, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_tgd1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_10 },
  { &hf_rrlp_bitsize_delta_tgd2, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_10 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSEphemerisDeltaBitSizes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSEphemerisDeltaBitSizes, GANSSEphemerisDeltaBitSizes_sequence);

  return offset;
}


static const per_sequence_t GANSSEphemerisDeltaScales_sequence[] = {
  { &hf_rrlp_scale_delta_omega, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_deltaN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_m0 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_omegadot, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_e  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_idot, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_sqrtA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_i0 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_omega0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_crs, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_cis, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_cus, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_crc, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_cic, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_cuc, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_tgd1, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_tgd2, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSEphemerisDeltaScales(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSEphemerisDeltaScales, GANSSEphemerisDeltaScales_sequence);

  return offset;
}


static const per_sequence_t GANSSDeltaEpochHeader_sequence[] = {
  { &hf_rrlp_validityPeriod , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_1_8 },
  { &hf_rrlp_ephemerisDeltaSizes, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSEphemerisDeltaBitSizes },
  { &hf_rrlp_ephemerisDeltaScales, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSEphemerisDeltaScales },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSDeltaEpochHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSDeltaEpochHeader, GANSSDeltaEpochHeader_sequence);

  return offset;
}



static int
dissect_rrlp_OCTET_STRING_SIZE_1_49(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 49, false, NULL);

  return offset;
}


static const per_sequence_t GANSSDeltaElementList_sequence_of[1] = {
  { &hf_rrlp_GANSSDeltaElementList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_OCTET_STRING_SIZE_1_49 },
};

static int
dissect_rrlp_GANSSDeltaElementList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_GANSSDeltaElementList, GANSSDeltaElementList_sequence_of,
                                                  1, 32, false);

  return offset;
}


static const per_sequence_t GANSSEphemerisDeltaEpoch_sequence[] = {
  { &hf_rrlp_ganssDeltaEpochHeader, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSDeltaEpochHeader },
  { &hf_rrlp_ganssDeltaElementList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSDeltaElementList },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSEphemerisDeltaEpoch(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSEphemerisDeltaEpoch, GANSSEphemerisDeltaEpoch_sequence);

  return offset;
}


static const per_sequence_t GANSSEphemerisDeltaMatrix_sequence_of[1] = {
  { &hf_rrlp_GANSSEphemerisDeltaMatrix_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSEphemerisDeltaEpoch },
};

static int
dissect_rrlp_GANSSEphemerisDeltaMatrix(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_GANSSEphemerisDeltaMatrix, GANSSEphemerisDeltaMatrix_sequence_of,
                                                  1, 128, false);

  return offset;
}


static const per_sequence_t GANSSEphemerisExtension_sequence[] = {
  { &hf_rrlp_ganssEphemerisHeader, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSEphemerisExtensionHeader },
  { &hf_rrlp_ganssReferenceSet, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_SeqOfGANSSRefOrbit },
  { &hf_rrlp_ganssephemerisDeltasMatrix, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSEphemerisDeltaMatrix },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSEphemerisExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSEphemerisExtension, GANSSEphemerisExtension_sequence);

  return offset;
}



static int
dissect_rrlp_BIT_STRING_SIZE_64(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GANSSSatEventsInfo_sequence[] = {
  { &hf_rrlp_eventOccured   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_BIT_STRING_SIZE_64 },
  { &hf_rrlp_futureEventNoted, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_BIT_STRING_SIZE_64 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSSatEventsInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSSatEventsInfo, GANSSSatEventsInfo_sequence);

  return offset;
}


static const per_sequence_t GANSSEphemerisExtensionCheck_sequence[] = {
  { &hf_rrlp_ganssBeginTime , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSEphemerisExtensionTime },
  { &hf_rrlp_ganssEndTime   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSEphemerisExtensionTime },
  { &hf_rrlp_ganssSatEventsInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSSatEventsInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSEphemerisExtensionCheck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSEphemerisExtensionCheck, GANSSEphemerisExtensionCheck_sequence);

  return offset;
}


static const per_sequence_t UTCmodelSet2_sequence[] = {
  { &hf_rrlp_utcA0_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_utcA1_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M4096_4095 },
  { &hf_rrlp_utcA2          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M64_63 },
  { &hf_rrlp_utcDeltaTls    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_utcTot_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_65535 },
  { &hf_rrlp_utcWNot        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_8191 },
  { &hf_rrlp_utcWNlsf       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_utcDN_01       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BIT_STRING_SIZE_4 },
  { &hf_rrlp_utcDeltaTlsf   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_UTCmodelSet2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_UTCmodelSet2, UTCmodelSet2_sequence);

  return offset;
}


static const per_sequence_t UTCmodelSet3_sequence[] = {
  { &hf_rrlp_nA             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_1461 },
  { &hf_rrlp_tauC           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_b1             , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_M1024_1023 },
  { &hf_rrlp_b2             , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_M512_511 },
  { &hf_rrlp_kp             , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_BIT_STRING_SIZE_2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_UTCmodelSet3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_UTCmodelSet3, UTCmodelSet3_sequence);

  return offset;
}


static const per_sequence_t UTCmodelSet4_sequence[] = {
  { &hf_rrlp_utcA1wnt       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_utcA0wnt       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_utcTot         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_utcWNt         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_utcDeltaTls    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_utcWNlsf       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_utcDN          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_utcDeltaTlsf   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_utcStandardID  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_UTCmodelSet4(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_UTCmodelSet4, UTCmodelSet4_sequence);

  return offset;
}


static const value_string rrlp_GANSSAddUTCModel_vals[] = {
  {   0, "utcModel2" },
  {   1, "utcModel3" },
  {   2, "utcModel4" },
  { 0, NULL }
};

static const per_choice_t GANSSAddUTCModel_choice[] = {
  {   0, &hf_rrlp_utcModel2      , ASN1_EXTENSION_ROOT    , dissect_rrlp_UTCmodelSet2 },
  {   1, &hf_rrlp_utcModel3      , ASN1_EXTENSION_ROOT    , dissect_rrlp_UTCmodelSet3 },
  {   2, &hf_rrlp_utcModel4      , ASN1_EXTENSION_ROOT    , dissect_rrlp_UTCmodelSet4 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_GANSSAddUTCModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_GANSSAddUTCModel, GANSSAddUTCModel_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GANSS_ID1_element_sequence[] = {
  { &hf_rrlp_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_signalsAvailable, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSSignals },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSS_ID1_element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSS_ID1_element, GANSS_ID1_element_sequence);

  return offset;
}


static const per_sequence_t GANSS_ID1_sequence_of[1] = {
  { &hf_rrlp_GANSS_ID1_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSS_ID1_element },
};

static int
dissect_rrlp_GANSS_ID1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_GANSS_ID1, GANSS_ID1_sequence_of,
                                                  1, 64, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_M7_13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -7, 13U, NULL, false);

  return offset;
}


static const per_sequence_t GANSS_ID3_element_sequence[] = {
  { &hf_rrlp_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_signalsAvailable, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSSignals },
  { &hf_rrlp_channelNumber  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M7_13 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSS_ID3_element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSS_ID3_element, GANSS_ID3_element_sequence);

  return offset;
}


static const per_sequence_t GANSS_ID3_sequence_of[1] = {
  { &hf_rrlp_GANSS_ID3_item , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSS_ID3_element },
};

static int
dissect_rrlp_GANSS_ID3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_GANSS_ID3, GANSS_ID3_sequence_of,
                                                  1, 64, false);

  return offset;
}


static const value_string rrlp_GANSSAuxiliaryInformation_vals[] = {
  {   0, "ganssID1" },
  {   1, "ganssID3" },
  { 0, NULL }
};

static const per_choice_t GANSSAuxiliaryInformation_choice[] = {
  {   0, &hf_rrlp_ganssID1       , ASN1_EXTENSION_ROOT    , dissect_rrlp_GANSS_ID1 },
  {   1, &hf_rrlp_ganssID3       , ASN1_EXTENSION_ROOT    , dissect_rrlp_GANSS_ID3 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_GANSSAuxiliaryInformation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_GANSSAuxiliaryInformation, GANSSAuxiliaryInformation_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t DGANSSExtensionSgnElement_sequence[] = {
  { &hf_rrlp_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_udreGrowthRate , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_udreValidityTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_DGANSSExtensionSgnElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_DGANSSExtensionSgnElement, DGANSSExtensionSgnElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfDGANSSExtensionSgnElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfDGANSSExtensionSgnElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_DGANSSExtensionSgnElement },
};

static int
dissect_rrlp_SeqOfDGANSSExtensionSgnElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfDGANSSExtensionSgnElement, SeqOfDGANSSExtensionSgnElement_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t DGANSSExtensionSgnTypeElement_sequence[] = {
  { &hf_rrlp_ganssSignalID  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSSignalID },
  { &hf_rrlp_dganssExtensionSgnList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfDGANSSExtensionSgnElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_DGANSSExtensionSgnTypeElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_DGANSSExtensionSgnTypeElement, DGANSSExtensionSgnTypeElement_sequence);

  return offset;
}


static const per_sequence_t GANSSDiffCorrectionsValidityPeriod_sequence_of[1] = {
  { &hf_rrlp_GANSSDiffCorrectionsValidityPeriod_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_DGANSSExtensionSgnTypeElement },
};

static int
dissect_rrlp_GANSSDiffCorrectionsValidityPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_GANSSDiffCorrectionsValidityPeriod, GANSSDiffCorrectionsValidityPeriod_sequence_of,
                                                  1, 3, false);

  return offset;
}


static const per_sequence_t GANSSTimeModelElement_R10_Ext_sequence[] = {
  { &hf_rrlp_gnssTOID       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_deltaT         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSTimeModelElement_R10_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSTimeModelElement_R10_Ext, GANSSTimeModelElement_R10_Ext_sequence);

  return offset;
}


static const per_sequence_t SeqOfGANSSTimeModel_R10_Ext_sequence_of[1] = {
  { &hf_rrlp_SeqOfGANSSTimeModel_R10_Ext_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSTimeModelElement_R10_Ext },
};

static int
dissect_rrlp_SeqOfGANSSTimeModel_R10_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGANSSTimeModel_R10_Ext, SeqOfGANSSTimeModel_R10_Ext_sequence_of,
                                                  1, 7, false);

  return offset;
}


static const per_sequence_t GANSSRefMeasurement_R10_Ext_Element_sequence[] = {
  { &hf_rrlp_svID           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_azimuthLSB     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_15 },
  { &hf_rrlp_elevationLSB   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_15 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSRefMeasurement_R10_Ext_Element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSRefMeasurement_R10_Ext_Element, GANSSRefMeasurement_R10_Ext_Element_sequence);

  return offset;
}


static const per_sequence_t GANSSRefMeasurementAssist_R10_Ext_sequence_of[1] = {
  { &hf_rrlp_GANSSRefMeasurementAssist_R10_Ext_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSRefMeasurement_R10_Ext_Element },
};

static int
dissect_rrlp_GANSSRefMeasurementAssist_R10_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_GANSSRefMeasurementAssist_R10_Ext, GANSSRefMeasurementAssist_R10_Ext_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t GANSSAlmanacModel_R10_Ext_sequence[] = {
  { &hf_rrlp_completeAlmanacProvided, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSAlmanacModel_R10_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSAlmanacModel_R10_Ext, GANSSAlmanacModel_R10_Ext_sequence);

  return offset;
}


static const per_sequence_t GANSSGenericAssistDataElement_sequence[] = {
  { &hf_rrlp_ganssID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_ganssTimeModel , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_SeqOfGANSSTimeModel },
  { &hf_rrlp_ganssDiffCorrections, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSDiffCorrections },
  { &hf_rrlp_ganssNavigationModel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSNavModel },
  { &hf_rrlp_ganssRealTimeIntegrity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSRealTimeIntegrity },
  { &hf_rrlp_ganssDataBitAssist, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSDataBitAssist },
  { &hf_rrlp_ganssRefMeasurementAssist, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSRefMeasurementAssist },
  { &hf_rrlp_ganssAlmanacModel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSAlmanacModel },
  { &hf_rrlp_ganssUTCModel  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSUTCModel },
  { &hf_rrlp_ganssEphemerisExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSEphemerisExtension },
  { &hf_rrlp_ganssEphemerisExtCheck, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSEphemerisExtensionCheck },
  { &hf_rrlp_sbasID         , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_ganssAddUTCModel, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GANSSAddUTCModel },
  { &hf_rrlp_ganssAuxiliaryInfo, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GANSSAuxiliaryInformation },
  { &hf_rrlp_ganssDiffCorrectionsValidityPeriod, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GANSSDiffCorrectionsValidityPeriod },
  { &hf_rrlp_ganssTimeModel_R10_Ext, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_SeqOfGANSSTimeModel_R10_Ext },
  { &hf_rrlp_ganssRefMeasurementAssist_R10_Ext, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GANSSRefMeasurementAssist_R10_Ext },
  { &hf_rrlp_ganssAlmanacModel_R10_Ext, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GANSSAlmanacModel_R10_Ext },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSGenericAssistDataElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSGenericAssistDataElement, GANSSGenericAssistDataElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfGANSSGenericAssistDataElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfGANSSGenericAssistDataElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSGenericAssistDataElement },
};

static int
dissect_rrlp_SeqOfGANSSGenericAssistDataElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGANSSGenericAssistDataElement, SeqOfGANSSGenericAssistDataElement_sequence_of,
                                                  1, 8, false);

  return offset;
}


static const per_sequence_t GANSS_ControlHeader_sequence[] = {
  { &hf_rrlp_ganssCommonAssistData, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_GANSSCommonAssistData },
  { &hf_rrlp_ganssGenericAssistDataList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_SeqOfGANSSGenericAssistDataElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSS_ControlHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSS_ControlHeader, GANSS_ControlHeader_sequence);

  return offset;
}


static const per_sequence_t GANSS_AssistData_sequence[] = {
  { &hf_rrlp_ganss_controlHeader, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSS_ControlHeader },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSS_AssistData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSS_AssistData, GANSS_AssistData_sequence);

  return offset;
}



static int
dissect_rrlp_RequiredResponseTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 128U, NULL, false);

  return offset;
}


static const per_sequence_t GPSEphemerisExtensionTime_sequence[] = {
  { &hf_rrlp_gpsWeek        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSWeek },
  { &hf_rrlp_gpsTOW_02      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_604799 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSEphemerisExtensionTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSEphemerisExtensionTime, GPSEphemerisExtensionTime_sequence);

  return offset;
}


static const per_sequence_t GPSEphemerisExtensionHeader_sequence[] = {
  { &hf_rrlp_timeofEstimation, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSEphemerisExtensionTime },
  { &hf_rrlp_validityPeriod , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_8 },
  { &hf_rrlp_ephemerisExtensionDuration, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_512 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSEphemerisExtensionHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSEphemerisExtensionHeader, GPSEphemerisExtensionHeader_sequence);

  return offset;
}


static const per_sequence_t GPSClockModel_sequence[] = {
  { &hf_rrlp_af2            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { &hf_rrlp_af1            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_af0            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2097152_2097151 },
  { &hf_rrlp_tgd            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M128_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSClockModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSClockModel, GPSClockModel_sequence);

  return offset;
}


static const per_sequence_t GPSReferenceOrbit_sequence[] = {
  { &hf_rrlp_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_gpsOrbitModel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_ReferenceNavModel },
  { &hf_rrlp_gpsClockModel  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSClockModel },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSReferenceOrbit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSReferenceOrbit, GPSReferenceOrbit_sequence);

  return offset;
}


static const per_sequence_t SeqOfGPSRefOrbit_sequence_of[1] = {
  { &hf_rrlp_SeqOfGPSRefOrbit_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSReferenceOrbit },
};

static int
dissect_rrlp_SeqOfGPSRefOrbit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGPSRefOrbit, SeqOfGPSRefOrbit_sequence_of,
                                                  1, 32, false);

  return offset;
}


static const per_sequence_t GPSEphemerisDeltaBitSizes_sequence[] = {
  { &hf_rrlp_bitsize_delta_omega, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_32 },
  { &hf_rrlp_bitsize_delta_deltaN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_m0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_32 },
  { &hf_rrlp_bitsize_delta_omegadot, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_24 },
  { &hf_rrlp_bitsize_delta_e, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_32 },
  { &hf_rrlp_bitsize_delta_idot, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_14 },
  { &hf_rrlp_bitsize_delta_sqrtA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_32 },
  { &hf_rrlp_bitsize_delta_i0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_32 },
  { &hf_rrlp_bitsize_delta_omega0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_32 },
  { &hf_rrlp_bitsize_delta_crs, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_cis, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_cus, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_crc, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_cic, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_cuc, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_16 },
  { &hf_rrlp_bitsize_delta_tgd, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_10 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSEphemerisDeltaBitSizes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSEphemerisDeltaBitSizes, GPSEphemerisDeltaBitSizes_sequence);

  return offset;
}


static const per_sequence_t GPSEphemerisDeltaScales_sequence[] = {
  { &hf_rrlp_scale_delta_omega, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_deltaN, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_m0 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_omegadot, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_e  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_idot, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_sqrtA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_i0 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_omega0, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_crs, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_cis, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_cus, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_crc, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_cic, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_cuc, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { &hf_rrlp_scale_delta_tgd, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M16_15 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSEphemerisDeltaScales(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSEphemerisDeltaScales, GPSEphemerisDeltaScales_sequence);

  return offset;
}


static const per_sequence_t GPSDeltaEpochHeader_sequence[] = {
  { &hf_rrlp_validityPeriod , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_1_8 },
  { &hf_rrlp_ephemerisDeltaSizes_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GPSEphemerisDeltaBitSizes },
  { &hf_rrlp_ephemerisDeltaScales_01, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GPSEphemerisDeltaScales },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSDeltaEpochHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSDeltaEpochHeader, GPSDeltaEpochHeader_sequence);

  return offset;
}



static int
dissect_rrlp_OCTET_STRING_SIZE_1_47(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 47, false, NULL);

  return offset;
}


static const per_sequence_t GPSDeltaElementList_sequence_of[1] = {
  { &hf_rrlp_GPSDeltaElementList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_OCTET_STRING_SIZE_1_47 },
};

static int
dissect_rrlp_GPSDeltaElementList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_GPSDeltaElementList, GPSDeltaElementList_sequence_of,
                                                  1, 32, false);

  return offset;
}


static const per_sequence_t GPSEphemerisDeltaEpoch_sequence[] = {
  { &hf_rrlp_gpsDeltaEpochHeader, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GPSDeltaEpochHeader },
  { &hf_rrlp_gpsDeltaElementList, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSDeltaElementList },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSEphemerisDeltaEpoch(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSEphemerisDeltaEpoch, GPSEphemerisDeltaEpoch_sequence);

  return offset;
}


static const per_sequence_t GPSEphemerisDeltaMatrix_sequence_of[1] = {
  { &hf_rrlp_GPSEphemerisDeltaMatrix_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSEphemerisDeltaEpoch },
};

static int
dissect_rrlp_GPSEphemerisDeltaMatrix(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_GPSEphemerisDeltaMatrix, GPSEphemerisDeltaMatrix_sequence_of,
                                                  1, 128, false);

  return offset;
}


static const per_sequence_t GPSEphemerisExtension_sequence[] = {
  { &hf_rrlp_gpsEphemerisHeader, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GPSEphemerisExtensionHeader },
  { &hf_rrlp_gpsReferenceSet, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_SeqOfGPSRefOrbit },
  { &hf_rrlp_gpsephemerisDeltaMatrix, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GPSEphemerisDeltaMatrix },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSEphemerisExtension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSEphemerisExtension, GPSEphemerisExtension_sequence);

  return offset;
}



static int
dissect_rrlp_BIT_STRING_SIZE_32(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     32, 32, false, NULL, 0, NULL, NULL);

  return offset;
}


static const per_sequence_t GPSSatEventsInfo_sequence[] = {
  { &hf_rrlp_eventOccured_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_BIT_STRING_SIZE_32 },
  { &hf_rrlp_futureEventNoted_01, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_BIT_STRING_SIZE_32 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSSatEventsInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSSatEventsInfo, GPSSatEventsInfo_sequence);

  return offset;
}


static const per_sequence_t GPSEphemerisExtensionCheck_sequence[] = {
  { &hf_rrlp_gpsBeginTime   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSEphemerisExtensionTime },
  { &hf_rrlp_gpsEndTime     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSEphemerisExtensionTime },
  { &hf_rrlp_gpsSatEventsInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSSatEventsInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSEphemerisExtensionCheck(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSEphemerisExtensionCheck, GPSEphemerisExtensionCheck_sequence);

  return offset;
}


static const per_sequence_t DGPSExtensionSatElement_sequence[] = {
  { &hf_rrlp_satelliteID    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SatelliteID },
  { &hf_rrlp_udreGrowthRate , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_udreValidityTime, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_DGPSExtensionSatElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_DGPSExtensionSatElement, DGPSExtensionSatElement_sequence);

  return offset;
}


static const per_sequence_t DGPSCorrectionsValidityPeriod_sequence_of[1] = {
  { &hf_rrlp_DGPSCorrectionsValidityPeriod_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_DGPSExtensionSatElement },
};

static int
dissect_rrlp_DGPSCorrectionsValidityPeriod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_DGPSCorrectionsValidityPeriod, DGPSCorrectionsValidityPeriod_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t GPSReferenceTime_R10_Ext_sequence[] = {
  { &hf_rrlp_gpsWeekCycleNumber, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSReferenceTime_R10_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSReferenceTime_R10_Ext, GPSReferenceTime_R10_Ext_sequence);

  return offset;
}


static const per_sequence_t GPSAcquisAssist_R10_Ext_Element_sequence[] = {
  { &hf_rrlp_satelliteID    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SatelliteID },
  { &hf_rrlp_azimuthLSB     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_15 },
  { &hf_rrlp_elevationLSB   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_15 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSAcquisAssist_R10_Ext_Element(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSAcquisAssist_R10_Ext_Element, GPSAcquisAssist_R10_Ext_Element_sequence);

  return offset;
}


static const per_sequence_t GPSAcquisAssist_R10_Ext_sequence_of[1] = {
  { &hf_rrlp_GPSAcquisAssist_R10_Ext_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSAcquisAssist_R10_Ext_Element },
};

static int
dissect_rrlp_GPSAcquisAssist_R10_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_GPSAcquisAssist_R10_Ext, GPSAcquisAssist_R10_Ext_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t GPSAlmanac_R10_Ext_sequence[] = {
  { &hf_rrlp_completeAlmanacProvided, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSAlmanac_R10_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSAlmanac_R10_Ext, GPSAlmanac_R10_Ext_sequence);

  return offset;
}


static const per_sequence_t Add_GPS_ControlHeader_sequence[] = {
  { &hf_rrlp_gpsEphemerisExtension, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GPSEphemerisExtension },
  { &hf_rrlp_gpsEphemerisExtensionCheck, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GPSEphemerisExtensionCheck },
  { &hf_rrlp_dgpsCorrectionsValidityPeriod, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_DGPSCorrectionsValidityPeriod },
  { &hf_rrlp_gpsReferenceTime_R10_Ext, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GPSReferenceTime_R10_Ext },
  { &hf_rrlp_gpsAcquisAssist_R10_Ext, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GPSAcquisAssist_R10_Ext },
  { &hf_rrlp_gpsAlmanac_R10_Ext, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GPSAlmanac_R10_Ext },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Add_GPS_ControlHeader(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Add_GPS_ControlHeader, Add_GPS_ControlHeader_sequence);

  return offset;
}


static const per_sequence_t Add_GPS_AssistData_sequence[] = {
  { &hf_rrlp_add_GPS_controlHeader, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_Add_GPS_ControlHeader },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Add_GPS_AssistData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Add_GPS_AssistData, Add_GPS_AssistData_sequence);

  return offset;
}


static const per_sequence_t Rel7_MsrPosition_Req_Extension_sequence[] = {
  { &hf_rrlp_velocityRequested, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_NULL },
  { &hf_rrlp_ganssPositionMethod, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSPositioningMethod },
  { &hf_rrlp_ganss_AssistData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSS_AssistData },
  { &hf_rrlp_ganssCarrierPhaseMeasurementRequest, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_NULL },
  { &hf_rrlp_ganssTODGSMTimeAssociationMeasurementRequest, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_NULL },
  { &hf_rrlp_requiredResponseTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_RequiredResponseTime },
  { &hf_rrlp_add_GPS_AssistData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_Add_GPS_AssistData },
  { &hf_rrlp_ganssMultiFreqMeasurementRequest, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_NULL },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel7_MsrPosition_Req_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Rel7_MsrPosition_Req_Extension, Rel7_MsrPosition_Req_Extension_sequence);

  return offset;
}


static const per_sequence_t MsrPosition_Req_sequence[] = {
  { &hf_rrlp_positionInstruct, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_PositionInstruct },
  { &hf_rrlp_referenceAssistData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_ReferenceAssistData },
  { &hf_rrlp_msrAssistData  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_MsrAssistData },
  { &hf_rrlp_systemInfoAssistData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_SystemInfoAssistData },
  { &hf_rrlp_gps_AssistData , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GPS_AssistData },
  { &hf_rrlp_extensionContainer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_ExtensionContainer },
  { &hf_rrlp_rel98_MsrPosition_Req_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_Rel98_MsrPosition_Req_Extension },
  { &hf_rrlp_rel5_MsrPosition_Req_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_Rel5_MsrPosition_Req_Extension },
  { &hf_rrlp_rel7_MsrPosition_Req_extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_Rel7_MsrPosition_Req_Extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MsrPosition_Req(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_MsrPosition_Req, MsrPosition_Req_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_2_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            2U, 3U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_1_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 3U, NULL, false);

  return offset;
}


static const value_string rrlp_ReferenceRelation_vals[] = {
  {   0, "secondBTSThirdSet" },
  {   1, "secondBTSSecondSet" },
  {   2, "firstBTSFirstSet" },
  { 0, NULL }
};


static int
dissect_rrlp_ReferenceRelation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t MultipleSets_sequence[] = {
  { &hf_rrlp_nbrOfSets      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_2_3 },
  { &hf_rrlp_nbrOfReferenceBTSs, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_1_3 },
  { &hf_rrlp_referenceRelation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_ReferenceRelation },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MultipleSets(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_MultipleSets, MultipleSets_sequence);

  return offset;
}


static const per_sequence_t BSICAndCarrier_sequence[] = {
  { &hf_rrlp_carrier        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BCCHCarrier },
  { &hf_rrlp_bsic           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BSIC },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_BSICAndCarrier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_BSICAndCarrier, BSICAndCarrier_sequence);

  return offset;
}



static int
dissect_rrlp_CellID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}



static int
dissect_rrlp_RequestIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, false);

  return offset;
}



static int
dissect_rrlp_SystemInfoIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, false);

  return offset;
}



static int
dissect_rrlp_LAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, false);

  return offset;
}


static const per_sequence_t CellIDAndLAC_sequence[] = {
  { &hf_rrlp_referenceLAC   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_LAC },
  { &hf_rrlp_referenceCI    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_CellID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_CellIDAndLAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_CellIDAndLAC, CellIDAndLAC_sequence);

  return offset;
}


static const value_string rrlp_ReferenceIdentityType_vals[] = {
  {   0, "bsicAndCarrier" },
  {   1, "ci" },
  {   2, "requestIndex" },
  {   3, "systemInfoIndex" },
  {   4, "ciAndLAC" },
  { 0, NULL }
};

static const per_choice_t ReferenceIdentityType_choice[] = {
  {   0, &hf_rrlp_bsicAndCarrier , ASN1_NO_EXTENSIONS     , dissect_rrlp_BSICAndCarrier },
  {   1, &hf_rrlp_ci             , ASN1_NO_EXTENSIONS     , dissect_rrlp_CellID },
  {   2, &hf_rrlp_requestIndex   , ASN1_NO_EXTENSIONS     , dissect_rrlp_RequestIndex },
  {   3, &hf_rrlp_systemInfoIndex, ASN1_NO_EXTENSIONS     , dissect_rrlp_SystemInfoIndex },
  {   4, &hf_rrlp_ciAndLAC       , ASN1_NO_EXTENSIONS     , dissect_rrlp_CellIDAndLAC },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_ReferenceIdentityType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_ReferenceIdentityType, ReferenceIdentityType_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SeqOfReferenceIdentityType_sequence_of[1] = {
  { &hf_rrlp_SeqOfReferenceIdentityType_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_ReferenceIdentityType },
};

static int
dissect_rrlp_SeqOfReferenceIdentityType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfReferenceIdentityType, SeqOfReferenceIdentityType_sequence_of,
                                                  1, 3, false);

  return offset;
}


static const per_sequence_t ReferenceIdentity_sequence[] = {
  { &hf_rrlp_refBTSList     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfReferenceIdentityType },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ReferenceIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_ReferenceIdentity, ReferenceIdentity_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_42431(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 42431U, NULL, false);

  return offset;
}



static int
dissect_rrlp_ModuloTimeSlot(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, false);

  return offset;
}



static int
dissect_rrlp_RefQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, false);

  return offset;
}



static int
dissect_rrlp_NumOfMeasurements(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, false);

  return offset;
}


static const per_sequence_t TOA_MeasurementsOfRef_sequence[] = {
  { &hf_rrlp_refQuality     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_RefQuality },
  { &hf_rrlp_numOfMeasurements, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_NumOfMeasurements },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_TOA_MeasurementsOfRef(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_TOA_MeasurementsOfRef, TOA_MeasurementsOfRef_sequence);

  return offset;
}



static int
dissect_rrlp_StdResolution(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_960(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 960U, NULL, false);

  return offset;
}


static const per_sequence_t MultiFrameCarrier_sequence[] = {
  { &hf_rrlp_bcchCarrier    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_BCCHCarrier },
  { &hf_rrlp_multiFrameOffset, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_MultiFrameOffset },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MultiFrameCarrier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_MultiFrameCarrier, MultiFrameCarrier_sequence);

  return offset;
}


static const value_string rrlp_NeighborIdentity_vals[] = {
  {   0, "bsicAndCarrier" },
  {   1, "ci" },
  {   2, "multiFrameCarrier" },
  {   3, "requestIndex" },
  {   4, "systemInfoIndex" },
  {   5, "ciAndLAC" },
  { 0, NULL }
};

static const per_choice_t NeighborIdentity_choice[] = {
  {   0, &hf_rrlp_bsicAndCarrier , ASN1_NO_EXTENSIONS     , dissect_rrlp_BSICAndCarrier },
  {   1, &hf_rrlp_ci             , ASN1_NO_EXTENSIONS     , dissect_rrlp_CellID },
  {   2, &hf_rrlp_multiFrameCarrier, ASN1_NO_EXTENSIONS     , dissect_rrlp_MultiFrameCarrier },
  {   3, &hf_rrlp_requestIndex   , ASN1_NO_EXTENSIONS     , dissect_rrlp_RequestIndex },
  {   4, &hf_rrlp_systemInfoIndex, ASN1_NO_EXTENSIONS     , dissect_rrlp_SystemInfoIndex },
  {   5, &hf_rrlp_ciAndLAC       , ASN1_NO_EXTENSIONS     , dissect_rrlp_CellIDAndLAC },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_NeighborIdentity(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_NeighborIdentity, NeighborIdentity_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t EOTDQuality_sequence[] = {
  { &hf_rrlp_nbrOfMeasurements, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_stdOfEOTD      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_31 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_EOTDQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_EOTDQuality, EOTDQuality_sequence);

  return offset;
}



static int
dissect_rrlp_OTDValue(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 39999U, NULL, false);

  return offset;
}


static const per_sequence_t OTD_MeasurementWithID_sequence[] = {
  { &hf_rrlp_neighborIdentity, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_NeighborIdentity },
  { &hf_rrlp_nborTimeSlot   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_ModuloTimeSlot },
  { &hf_rrlp_eotdQuality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_EOTDQuality },
  { &hf_rrlp_otdValue       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_OTDValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_MeasurementWithID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_OTD_MeasurementWithID, OTD_MeasurementWithID_sequence);

  return offset;
}



static int
dissect_rrlp_OTD_FirstSetMsrs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_rrlp_OTD_MeasurementWithID(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t SeqOfOTD_FirstSetMsrs_sequence_of[1] = {
  { &hf_rrlp_SeqOfOTD_FirstSetMsrs_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_OTD_FirstSetMsrs },
};

static int
dissect_rrlp_SeqOfOTD_FirstSetMsrs(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfOTD_FirstSetMsrs, SeqOfOTD_FirstSetMsrs_sequence_of,
                                                  1, 10, false);

  return offset;
}


static const per_sequence_t OTD_MsrElementFirst_sequence[] = {
  { &hf_rrlp_refFrameNumber , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_42431 },
  { &hf_rrlp_referenceTimeSlot, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_ModuloTimeSlot },
  { &hf_rrlp_toaMeasurementsOfRef, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_TOA_MeasurementsOfRef },
  { &hf_rrlp_stdResolution  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_StdResolution },
  { &hf_rrlp_taCorrection   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_960 },
  { &hf_rrlp_otd_FirstSetMsrs, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_SeqOfOTD_FirstSetMsrs },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_MsrElementFirst(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_OTD_MsrElementFirst, OTD_MsrElementFirst_sequence);

  return offset;
}


static const per_sequence_t OTD_Measurement_sequence[] = {
  { &hf_rrlp_nborTimeSlot   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_ModuloTimeSlot },
  { &hf_rrlp_eotdQuality    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_EOTDQuality },
  { &hf_rrlp_otdValue       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_OTDValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_Measurement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_OTD_Measurement, OTD_Measurement_sequence);

  return offset;
}


static const value_string rrlp_OTD_MsrsOfOtherSets_vals[] = {
  {   0, "identityNotPresent" },
  {   1, "identityPresent" },
  { 0, NULL }
};

static const per_choice_t OTD_MsrsOfOtherSets_choice[] = {
  {   0, &hf_rrlp_identityNotPresent, ASN1_NO_EXTENSIONS     , dissect_rrlp_OTD_Measurement },
  {   1, &hf_rrlp_identityPresent, ASN1_NO_EXTENSIONS     , dissect_rrlp_OTD_MeasurementWithID },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_OTD_MsrsOfOtherSets(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_OTD_MsrsOfOtherSets, OTD_MsrsOfOtherSets_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SeqOfOTD_MsrsOfOtherSets_sequence_of[1] = {
  { &hf_rrlp_SeqOfOTD_MsrsOfOtherSets_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_OTD_MsrsOfOtherSets },
};

static int
dissect_rrlp_SeqOfOTD_MsrsOfOtherSets(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfOTD_MsrsOfOtherSets, SeqOfOTD_MsrsOfOtherSets_sequence_of,
                                                  1, 10, false);

  return offset;
}


static const per_sequence_t OTD_MsrElementRest_sequence[] = {
  { &hf_rrlp_refFrameNumber , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_42431 },
  { &hf_rrlp_referenceTimeSlot, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_ModuloTimeSlot },
  { &hf_rrlp_toaMeasurementsOfRef, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_TOA_MeasurementsOfRef },
  { &hf_rrlp_stdResolution  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_StdResolution },
  { &hf_rrlp_taCorrection   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_960 },
  { &hf_rrlp_otd_MsrsOfOtherSets, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_SeqOfOTD_MsrsOfOtherSets },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_MsrElementRest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_OTD_MsrElementRest, OTD_MsrElementRest_sequence);

  return offset;
}


static const per_sequence_t SeqOfOTD_MsrElementRest_sequence_of[1] = {
  { &hf_rrlp_SeqOfOTD_MsrElementRest_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_OTD_MsrElementRest },
};

static int
dissect_rrlp_SeqOfOTD_MsrElementRest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfOTD_MsrElementRest, SeqOfOTD_MsrElementRest_sequence_of,
                                                  1, 2, false);

  return offset;
}


static const per_sequence_t OTD_MeasureInfo_sequence[] = {
  { &hf_rrlp_otdMsrFirstSets, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_OTD_MsrElementFirst },
  { &hf_rrlp_otdMsrRestSets , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_SeqOfOTD_MsrElementRest },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_MeasureInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_OTD_MeasureInfo, OTD_MeasureInfo_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_14399999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 14399999U, NULL, false);

  return offset;
}


static const value_string rrlp_FixType_vals[] = {
  {   0, "twoDFix" },
  {   1, "threeDFix" },
  { 0, NULL }
};


static int
dissect_rrlp_FixType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, false);

  return offset;
}


static const per_sequence_t LocationInfo_sequence[] = {
  { &hf_rrlp_refFrame       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_65535 },
  { &hf_rrlp_gpsTOW         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_14399999 },
  { &hf_rrlp_fixType        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_FixType },
  { &hf_rrlp_posEstimate    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_Ext_GeographicalInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_LocationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_LocationInfo, LocationInfo_sequence);

  return offset;
}



static int
dissect_rrlp_GPSTOW24b(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 14399999U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_1024(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1024U, NULL, false);

  return offset;
}


static const value_string rrlp_MpathIndic_vals[] = {
  {   0, "notMeasured" },
  {   1, "low" },
  {   2, "medium" },
  {   3, "high" },
  { 0, NULL }
};


static int
dissect_rrlp_MpathIndic(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     4, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t GPS_MsrElement_sequence[] = {
  { &hf_rrlp_satelliteID    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SatelliteID },
  { &hf_rrlp_cNo            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_63 },
  { &hf_rrlp_doppler        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_wholeChips     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1022 },
  { &hf_rrlp_fracChips      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1024 },
  { &hf_rrlp_mpathIndic     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_MpathIndic },
  { &hf_rrlp_pseuRangeRMSErr, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_63 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPS_MsrElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPS_MsrElement, GPS_MsrElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfGPS_MsrElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfGPS_MsrElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GPS_MsrElement },
};

static int
dissect_rrlp_SeqOfGPS_MsrElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGPS_MsrElement, SeqOfGPS_MsrElement_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t GPS_MsrSetElement_sequence[] = {
  { &hf_rrlp_refFrame       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_65535 },
  { &hf_rrlp_gpsTOW_01      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GPSTOW24b },
  { &hf_rrlp_gps_msrList    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGPS_MsrElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPS_MsrSetElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPS_MsrSetElement, GPS_MsrSetElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfGPS_MsrSetElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfGPS_MsrSetElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GPS_MsrSetElement },
};

static int
dissect_rrlp_SeqOfGPS_MsrSetElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGPS_MsrSetElement, SeqOfGPS_MsrSetElement_sequence_of,
                                                  1, 3, false);

  return offset;
}


static const per_sequence_t GPS_MeasureInfo_sequence[] = {
  { &hf_rrlp_gpsMsrSetList  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGPS_MsrSetElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPS_MeasureInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPS_MeasureInfo, GPS_MeasureInfo_sequence);

  return offset;
}


static const value_string rrlp_LocErrorReason_vals[] = {
  {   0, "unDefined" },
  {   1, "notEnoughBTSs" },
  {   2, "notEnoughSats" },
  {   3, "eotdLocCalAssDataMissing" },
  {   4, "eotdAssDataMissing" },
  {   5, "gpsLocCalAssDataMissing" },
  {   6, "gpsAssDataMissing" },
  {   7, "methodNotSupported" },
  {   8, "notProcessed" },
  {   9, "refBTSForGPSNotServingBTS" },
  {  10, "refBTSForEOTDNotServingBTS" },
  {  11, "notEnoughGANSSSats" },
  {  12, "ganssAssDataMissing" },
  {  13, "refBTSForGANSSNotServingBTS" },
  { 0, NULL }
};


static int
dissect_rrlp_LocErrorReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     11, NULL, true, 3, NULL);

  return offset;
}



static int
dissect_rrlp_GPSAssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, maxGPSAssistanceData, false, NULL);

  return offset;
}



static int
dissect_rrlp_GANSSAssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, maxGANSSAssistanceData, false, NULL);

  return offset;
}


static const per_sequence_t AdditionalAssistanceData_sequence[] = {
  { &hf_rrlp_gpsAssistanceData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GPSAssistanceData },
  { &hf_rrlp_extensionContainer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_ExtensionContainer },
  { &hf_rrlp_ganssAssistanceData, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GANSSAssistanceData },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AdditionalAssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_AdditionalAssistanceData, AdditionalAssistanceData_sequence);

  return offset;
}


static const per_sequence_t LocationError_sequence[] = {
  { &hf_rrlp_locErrorReason , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_LocErrorReason },
  { &hf_rrlp_additionalAssistanceData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_AdditionalAssistanceData },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_LocationError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_LocationError, LocationError_sequence);

  return offset;
}


static const per_sequence_t SeqOfOTD_FirstSetMsrs_R98_Ext_sequence_of[1] = {
  { &hf_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_OTD_FirstSetMsrs },
};

static int
dissect_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext, SeqOfOTD_FirstSetMsrs_R98_Ext_sequence_of,
                                                  1, 5, false);

  return offset;
}


static const per_sequence_t OTD_MsrElementFirst_R98_Ext_sequence[] = {
  { &hf_rrlp_otd_FirstSetMsrs_R98_Ext, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_MsrElementFirst_R98_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_OTD_MsrElementFirst_R98_Ext, OTD_MsrElementFirst_R98_Ext_sequence);

  return offset;
}


static const per_sequence_t OTD_MeasureInfo_R98_Ext_sequence[] = {
  { &hf_rrlp_otdMsrFirstSets_R98_Ext, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_OTD_MsrElementFirst_R98_Ext },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_MeasureInfo_R98_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_OTD_MeasureInfo_R98_Ext, OTD_MeasureInfo_R98_Ext_sequence);

  return offset;
}


static const per_sequence_t T_rel_98_Ext_MeasureInfo_sequence[] = {
  { &hf_rrlp_otd_MeasureInfo_R98_Ext, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_OTD_MeasureInfo_R98_Ext },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_T_rel_98_Ext_MeasureInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_T_rel_98_Ext_MeasureInfo, T_rel_98_Ext_MeasureInfo_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_9999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 9999U, NULL, false);

  return offset;
}


static const per_sequence_t GPSTimeAssistanceMeasurements_sequence[] = {
  { &hf_rrlp_referenceFrameMSB, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_63 },
  { &hf_rrlp_gpsTowSubms    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_9999 },
  { &hf_rrlp_deltaTow       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_127 },
  { &hf_rrlp_gpsReferenceTimeUncertainty, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_GPSReferenceTimeUncertainty },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSTimeAssistanceMeasurements(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GPSTimeAssistanceMeasurements, GPSTimeAssistanceMeasurements_sequence);

  return offset;
}


static const per_sequence_t Rel_98_MsrPosition_Rsp_Extension_sequence[] = {
  { &hf_rrlp_rel_98_Ext_MeasureInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_T_rel_98_Ext_MeasureInfo },
  { &hf_rrlp_timeAssistanceMeasurements, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GPSTimeAssistanceMeasurements },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel_98_MsrPosition_Rsp_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Rel_98_MsrPosition_Rsp_Extension, Rel_98_MsrPosition_Rsp_Extension_sequence);

  return offset;
}



static int
dissect_rrlp_OTD_MeasureInfo_5_Ext(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_rrlp_SeqOfOTD_MsrElementRest(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string rrlp_UlPseudoSegInd_vals[] = {
  {   0, "firstOfMany" },
  {   1, "secondOfMany" },
  { 0, NULL }
};


static int
dissect_rrlp_UlPseudoSegInd(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t Rel_5_MsrPosition_Rsp_Extension_sequence[] = {
  { &hf_rrlp_extended_reference, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_Extended_reference },
  { &hf_rrlp_otd_MeasureInfo_5_Ext, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_OTD_MeasureInfo_5_Ext },
  { &hf_rrlp_ulPseudoSegInd , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_UlPseudoSegInd },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel_5_MsrPosition_Rsp_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Rel_5_MsrPosition_Rsp_Extension, Rel_5_MsrPosition_Rsp_Extension_sequence);

  return offset;
}


static const per_sequence_t ReferenceFrame_sequence[] = {
  { &hf_rrlp_referenceFN    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_65535 },
  { &hf_rrlp_referenceFNMSB , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_63 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ReferenceFrame(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_ReferenceFrame, ReferenceFrame_sequence);

  return offset;
}



static int
dissect_rrlp_GANSSTODm(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3599999U, NULL, false);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_16384(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16384U, NULL, false);

  return offset;
}


static int * const PositionData_bits[] = {
  &hf_rrlp_PositionData_e_otd,
  &hf_rrlp_PositionData_gps,
  &hf_rrlp_PositionData_galileo,
  &hf_rrlp_PositionData_sbas,
  &hf_rrlp_PositionData_modernizedGPS,
  &hf_rrlp_PositionData_qzss,
  &hf_rrlp_PositionData_glonass,
  NULL
};

static int
dissect_rrlp_PositionData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     3, 16, false, PositionData_bits, 7, NULL, NULL);

  return offset;
}


static const per_sequence_t GANSSLocationInfo_sequence[] = {
  { &hf_rrlp_referenceFrame , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_ReferenceFrame },
  { &hf_rrlp_ganssTODm      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSTODm },
  { &hf_rrlp_ganssTODFrac   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_16384 },
  { &hf_rrlp_ganssTODUncertainty, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSTODUncertainty },
  { &hf_rrlp_ganssTimeID    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_fixType        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_FixType },
  { &hf_rrlp_posData        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_PositionData },
  { &hf_rrlp_stationaryIndication, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_1 },
  { &hf_rrlp_posEstimate    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_Ext_GeographicalInformation },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSLocationInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSLocationInfo, GANSSLocationInfo_sequence);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_33554431(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 33554431U, NULL, false);

  return offset;
}


static const per_sequence_t GANSS_SgnElement_sequence[] = {
  { &hf_rrlp_svID           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_cNo            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_63 },
  { &hf_rrlp_mpathDet       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_MpathIndic },
  { &hf_rrlp_carrierQualityInd, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_3 },
  { &hf_rrlp_codePhase_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_2097151 },
  { &hf_rrlp_integerCodePhase, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_127 },
  { &hf_rrlp_codePhaseRMSError, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_63 },
  { &hf_rrlp_doppler        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_adr            , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_33554431 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSS_SgnElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSS_SgnElement, GANSS_SgnElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfGANSS_SgnElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfGANSS_SgnElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSS_SgnElement },
};

static int
dissect_rrlp_SeqOfGANSS_SgnElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGANSS_SgnElement, SeqOfGANSS_SgnElement_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t GANSS_SgnTypeElement_sequence[] = {
  { &hf_rrlp_ganssSignalID  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSSignalID },
  { &hf_rrlp_ganssCodePhaseAmbiguity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_127 },
  { &hf_rrlp_ganss_SgnList  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGANSS_SgnElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSS_SgnTypeElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSS_SgnTypeElement, GANSS_SgnTypeElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfGANSS_SgnTypeElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfGANSS_SgnTypeElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSS_SgnTypeElement },
};

static int
dissect_rrlp_SeqOfGANSS_SgnTypeElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGANSS_SgnTypeElement, SeqOfGANSS_SgnTypeElement_sequence_of,
                                                  1, 8, false);

  return offset;
}


static const per_sequence_t GANSS_MsrElement_sequence[] = {
  { &hf_rrlp_ganssID        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_ganss_SgnTypeList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGANSS_SgnTypeElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSS_MsrElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSS_MsrElement, GANSS_MsrElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfGANSS_MsrElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfGANSS_MsrElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSS_MsrElement },
};

static int
dissect_rrlp_SeqOfGANSS_MsrElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGANSS_MsrElement, SeqOfGANSS_MsrElement_sequence_of,
                                                  1, 8, false);

  return offset;
}


static const per_sequence_t GANSS_MsrSetElement_sequence[] = {
  { &hf_rrlp_referenceFrame , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_ReferenceFrame },
  { &hf_rrlp_ganssTODm      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_GANSSTODm },
  { &hf_rrlp_deltaGANSSTOD  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_127 },
  { &hf_rrlp_ganssTODUncertainty, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_GANSSTODUncertainty },
  { &hf_rrlp_ganss_MsrElementList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGANSS_MsrElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSS_MsrSetElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSS_MsrSetElement, GANSS_MsrSetElement_sequence);

  return offset;
}


static const per_sequence_t SeqOfGANSS_MsrSetElement_sequence_of[1] = {
  { &hf_rrlp_SeqOfGANSS_MsrSetElement_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSS_MsrSetElement },
};

static int
dissect_rrlp_SeqOfGANSS_MsrSetElement(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOfGANSS_MsrSetElement, SeqOfGANSS_MsrSetElement_sequence_of,
                                                  1, 3, false);

  return offset;
}


static const per_sequence_t GANSSMeasureInfo_sequence[] = {
  { &hf_rrlp_ganssMsrSetList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGANSS_MsrSetElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSMeasureInfo(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSMeasureInfo, GANSSMeasureInfo_sequence);

  return offset;
}


static const per_sequence_t Rel_7_MsrPosition_Rsp_Extension_sequence[] = {
  { &hf_rrlp_velEstimate    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_VelocityEstimate },
  { &hf_rrlp_ganssLocationInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSLocationInfo },
  { &hf_rrlp_ganssMeasureInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSMeasureInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel_7_MsrPosition_Rsp_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Rel_7_MsrPosition_Rsp_Extension, Rel_7_MsrPosition_Rsp_Extension_sequence);

  return offset;
}


static const per_sequence_t MsrPosition_Rsp_sequence[] = {
  { &hf_rrlp_multipleSets   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_MultipleSets },
  { &hf_rrlp_referenceIdentity, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_ReferenceIdentity },
  { &hf_rrlp_otd_MeasureInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_OTD_MeasureInfo },
  { &hf_rrlp_locationInfo   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_LocationInfo },
  { &hf_rrlp_gps_MeasureInfo, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GPS_MeasureInfo },
  { &hf_rrlp_locationError  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_LocationError },
  { &hf_rrlp_extensionContainer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_ExtensionContainer },
  { &hf_rrlp_rel_98_MsrPosition_Rsp_Extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_Rel_98_MsrPosition_Rsp_Extension },
  { &hf_rrlp_rel_5_MsrPosition_Rsp_Extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_Rel_5_MsrPosition_Rsp_Extension },
  { &hf_rrlp_rel_7_MsrPosition_Rsp_Extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_Rel_7_MsrPosition_Rsp_Extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MsrPosition_Rsp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_MsrPosition_Rsp, MsrPosition_Rsp_sequence);

  return offset;
}


static const value_string rrlp_MoreAssDataToBeSent_vals[] = {
  {   0, "noMoreMessages" },
  {   1, "moreMessagesOnTheWay" },
  { 0, NULL }
};


static int
dissect_rrlp_MoreAssDataToBeSent(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, false, 0, NULL);

  return offset;
}


static const per_sequence_t Rel98_AssistanceData_Extension_sequence[] = {
  { &hf_rrlp_rel98_Ext_ExpOTD, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_Rel98_Ext_ExpOTD },
  { &hf_rrlp_gpsTimeAssistanceMeasurementRequest, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_NULL },
  { &hf_rrlp_gpsReferenceTimeUncertainty, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GPSReferenceTimeUncertainty },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel98_AssistanceData_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Rel98_AssistanceData_Extension, Rel98_AssistanceData_Extension_sequence);

  return offset;
}


static const per_sequence_t Rel5_AssistanceData_Extension_sequence[] = {
  { &hf_rrlp_extended_reference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_Extended_reference },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel5_AssistanceData_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Rel5_AssistanceData_Extension, Rel5_AssistanceData_Extension_sequence);

  return offset;
}


static const per_sequence_t Rel7_AssistanceData_Extension_sequence[] = {
  { &hf_rrlp_ganss_AssistData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSS_AssistData },
  { &hf_rrlp_ganssCarrierPhaseMeasurementRequest, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_NULL },
  { &hf_rrlp_ganssTODGSMTimeAssociationMeasurementRequest, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_NULL },
  { &hf_rrlp_add_GPS_AssistData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_Add_GPS_AssistData },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel7_AssistanceData_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Rel7_AssistanceData_Extension, Rel7_AssistanceData_Extension_sequence);

  return offset;
}


static const per_sequence_t AssistanceData_sequence[] = {
  { &hf_rrlp_referenceAssistData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_ReferenceAssistData },
  { &hf_rrlp_msrAssistData  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_MsrAssistData },
  { &hf_rrlp_systemInfoAssistData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_SystemInfoAssistData },
  { &hf_rrlp_gps_AssistData , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GPS_AssistData },
  { &hf_rrlp_moreAssDataToBeSent, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_MoreAssDataToBeSent },
  { &hf_rrlp_extensionContainer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_ExtensionContainer },
  { &hf_rrlp_rel98_AssistanceData_Extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_Rel98_AssistanceData_Extension },
  { &hf_rrlp_rel5_AssistanceData_Extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_Rel5_AssistanceData_Extension },
  { &hf_rrlp_rel7_AssistanceData_Extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_Rel7_AssistanceData_Extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_AssistanceData, AssistanceData_sequence);

  return offset;
}


static const value_string rrlp_ErrorCodes_vals[] = {
  {   0, "unDefined" },
  {   1, "missingComponet" },
  {   2, "incorrectData" },
  {   3, "missingIEorComponentElement" },
  {   4, "messageTooShort" },
  {   5, "unknowReferenceNumber" },
  { 0, NULL }
};


static int
dissect_rrlp_ErrorCodes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     6, NULL, true, 0, NULL);

  return offset;
}


static const per_sequence_t Rel_5_ProtocolError_Extension_sequence[] = {
  { &hf_rrlp_extended_reference, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_Extended_reference },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel_5_ProtocolError_Extension(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_Rel_5_ProtocolError_Extension, Rel_5_ProtocolError_Extension_sequence);

  return offset;
}


static const per_sequence_t ProtocolError_sequence[] = {
  { &hf_rrlp_errorCause     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_ErrorCodes },
  { &hf_rrlp_extensionContainer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_ExtensionContainer },
  { &hf_rrlp_rel_5_ProtocolError_Extension, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_Rel_5_ProtocolError_Extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ProtocolError(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_ProtocolError, ProtocolError_sequence);

  return offset;
}


static int * const GANSSPositioningMethodTypes_bits[] = {
  &hf_rrlp_GANSSPositioningMethodTypes_msAssisted,
  &hf_rrlp_GANSSPositioningMethodTypes_msBased,
  &hf_rrlp_GANSSPositioningMethodTypes_standalone,
  NULL
};

static int
dissect_rrlp_GANSSPositioningMethodTypes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 8, false, GANSSPositioningMethodTypes_bits, 3, NULL, NULL);

  return offset;
}


static int * const SBASID_bits[] = {
  &hf_rrlp_SBASID_waas,
  &hf_rrlp_SBASID_egnos,
  &hf_rrlp_SBASID_masas,
  &hf_rrlp_SBASID_gagan,
  NULL
};

static int
dissect_rrlp_SBASID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 8, false, SBASID_bits, 4, NULL, NULL);

  return offset;
}


static const per_sequence_t GANSSPositionMethod_sequence[] = {
  { &hf_rrlp_ganssID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_gANSSPositioningMethodTypes, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSPositioningMethodTypes },
  { &hf_rrlp_gANSSSignals   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSSignals },
  { &hf_rrlp_sbasID_01      , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_SBASID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSPositionMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSPositionMethod, GANSSPositionMethod_sequence);

  return offset;
}


static const per_sequence_t GANSSPositionMethods_sequence_of[1] = {
  { &hf_rrlp_GANSSPositionMethods_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSPositionMethod },
};

static int
dissect_rrlp_GANSSPositionMethods(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_GANSSPositionMethods, GANSSPositionMethods_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t PosCapability_Req_sequence[] = {
  { &hf_rrlp_extended_reference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_Extended_reference },
  { &hf_rrlp_gANSSPositionMethods, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSPositionMethods },
  { &hf_rrlp_extensionContainer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_ExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_PosCapability_Req(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_PosCapability_Req, PosCapability_Req_sequence);

  return offset;
}


static int * const NonGANSSPositionMethods_bits[] = {
  &hf_rrlp_NonGANSSPositionMethods_msAssistedEOTD,
  &hf_rrlp_NonGANSSPositionMethods_msBasedEOTD,
  &hf_rrlp_NonGANSSPositionMethods_msAssistedGPS,
  &hf_rrlp_NonGANSSPositionMethods_msBasedGPS,
  &hf_rrlp_NonGANSSPositionMethods_standaloneGPS,
  NULL
};

static int
dissect_rrlp_NonGANSSPositionMethods(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 16, false, NonGANSSPositionMethods_bits, 5, NULL, NULL);

  return offset;
}


static int * const MultipleMeasurementSets_bits[] = {
  &hf_rrlp_MultipleMeasurementSets_eotd,
  &hf_rrlp_MultipleMeasurementSets_gps,
  &hf_rrlp_MultipleMeasurementSets_ganss,
  NULL
};

static int
dissect_rrlp_MultipleMeasurementSets(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 8, false, MultipleMeasurementSets_bits, 3, NULL, NULL);

  return offset;
}


static const per_sequence_t PosCapabilities_sequence[] = {
  { &hf_rrlp_nonGANSSpositionMethods, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_NonGANSSPositionMethods },
  { &hf_rrlp_gANSSPositionMethods, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSPositionMethods },
  { &hf_rrlp_multipleMeasurementSets, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_MultipleMeasurementSets },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_PosCapabilities(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_PosCapabilities, PosCapabilities_sequence);

  return offset;
}


static int * const GPSAssistance_bits[] = {
  &hf_rrlp_GPSAssistance_almanac,
  &hf_rrlp_GPSAssistance_uTCmodel,
  &hf_rrlp_GPSAssistance_ionosphericModel,
  &hf_rrlp_GPSAssistance_navigationmodel,
  &hf_rrlp_GPSAssistance_dGPScorrections,
  &hf_rrlp_GPSAssistance_referenceLocation,
  &hf_rrlp_GPSAssistance_referenceTime,
  &hf_rrlp_GPSAssistance_acquisitionAssistance,
  &hf_rrlp_GPSAssistance_realTimeIntegrity,
  &hf_rrlp_GPSAssistance_ephemerisExtension,
  &hf_rrlp_GPSAssistance_ephemerisExtensionCheck,
  NULL
};

static int
dissect_rrlp_GPSAssistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 16, false, GPSAssistance_bits, 11, NULL, NULL);

  return offset;
}


static int * const CommonGANSSAssistance_bits[] = {
  &hf_rrlp_CommonGANSSAssistance_referenceTime,
  &hf_rrlp_CommonGANSSAssistance_referenceLocation,
  &hf_rrlp_CommonGANSSAssistance_spare_bit2,
  &hf_rrlp_CommonGANSSAssistance_ionosphericModel,
  &hf_rrlp_CommonGANSSAssistance_addIonosphericModel,
  &hf_rrlp_CommonGANSSAssistance_earthOrientationParam,
  NULL
};

static int
dissect_rrlp_CommonGANSSAssistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 8, false, CommonGANSSAssistance_bits, 6, NULL, NULL);

  return offset;
}


static int * const GANSSAssistance_bits[] = {
  &hf_rrlp_GANSSAssistance_realTimeIntegrity,
  &hf_rrlp_GANSSAssistance_differentialCorrections,
  &hf_rrlp_GANSSAssistance_almanac,
  &hf_rrlp_GANSSAssistance_referenceMeasurementInformation,
  &hf_rrlp_GANSSAssistance_navigationModel,
  &hf_rrlp_GANSSAssistance_timeModelGNSS_UTC,
  &hf_rrlp_GANSSAssistance_timeModelGNSS_GNSS,
  &hf_rrlp_GANSSAssistance_databitassistance,
  &hf_rrlp_GANSSAssistance_ephemerisExtension,
  &hf_rrlp_GANSSAssistance_ephemerisExtensionCheck,
  &hf_rrlp_GANSSAssistance_addUTCmodel,
  &hf_rrlp_GANSSAssistance_auxiliaryInformation,
  NULL
};

static int
dissect_rrlp_GANSSAssistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 16, false, GANSSAssistance_bits, 12, NULL, NULL);

  return offset;
}


static const per_sequence_t GANSSAssistanceForOneGANSS_sequence[] = {
  { &hf_rrlp_ganssID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_gANSSAssistance, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSAssistance },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSAssistanceForOneGANSS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSAssistanceForOneGANSS, GANSSAssistanceForOneGANSS_sequence);

  return offset;
}


static const per_sequence_t SpecificGANSSAssistance_sequence_of[1] = {
  { &hf_rrlp_SpecificGANSSAssistance_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSAssistanceForOneGANSS },
};

static int
dissect_rrlp_SpecificGANSSAssistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SpecificGANSSAssistance, SpecificGANSSAssistance_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t GANSSAssistanceSet_sequence[] = {
  { &hf_rrlp_commonGANSSAssistance, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_CommonGANSSAssistance },
  { &hf_rrlp_specificGANSSAssistance, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SpecificGANSSAssistance },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSAssistanceSet(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSAssistanceSet, GANSSAssistanceSet_sequence);

  return offset;
}


static int * const GANSSModelID_bits[] = {
  &hf_rrlp_GANSSModelID_model1,
  &hf_rrlp_GANSSModelID_model2,
  &hf_rrlp_GANSSModelID_model3,
  &hf_rrlp_GANSSModelID_model4,
  &hf_rrlp_GANSSModelID_model5,
  &hf_rrlp_GANSSModelID_model6,
  &hf_rrlp_GANSSModelID_model7,
  &hf_rrlp_GANSSModelID_model8,
  NULL
};

static int
dissect_rrlp_GANSSModelID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 8, false, GANSSModelID_bits, 8, NULL, NULL);

  return offset;
}


static const per_sequence_t GANSSAdditionalAssistanceChoicesForOneGANSS_sequence[] = {
  { &hf_rrlp_ganssID        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_ganssClockModelChoice, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSModelID },
  { &hf_rrlp_gannsOrbitModelChoice, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSModelID },
  { &hf_rrlp_ganssAlmanacModelChoice, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSModelID },
  { &hf_rrlp_ganssAdditionalUTCModelChoice, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSModelID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSAdditionalAssistanceChoicesForOneGANSS(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSAdditionalAssistanceChoicesForOneGANSS, GANSSAdditionalAssistanceChoicesForOneGANSS_sequence);

  return offset;
}


static const per_sequence_t GANSSAdditionalAssistanceChoices_sequence_of[1] = {
  { &hf_rrlp_GANSSAdditionalAssistanceChoices_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSAdditionalAssistanceChoicesForOneGANSS },
};

static int
dissect_rrlp_GANSSAdditionalAssistanceChoices(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_GANSSAdditionalAssistanceChoices, GANSSAdditionalAssistanceChoices_sequence_of,
                                                  1, 16, false);

  return offset;
}


static const per_sequence_t AssistanceSupported_sequence[] = {
  { &hf_rrlp_gpsAssistance  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GPSAssistance },
  { &hf_rrlp_gANSSAssistanceSet, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSAssistanceSet },
  { &hf_rrlp_gANSSAdditionalAssistanceChoices, ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rrlp_GANSSAdditionalAssistanceChoices },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AssistanceSupported(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_AssistanceSupported, AssistanceSupported_sequence);

  return offset;
}


static const per_sequence_t AssistanceNeeded_sequence[] = {
  { &hf_rrlp_gpsAssistanceData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GPSAssistanceData },
  { &hf_rrlp_ganssAssistanceData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSAssistanceData },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AssistanceNeeded(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_AssistanceNeeded, AssistanceNeeded_sequence);

  return offset;
}


static const per_sequence_t PosCapability_Rsp_sequence[] = {
  { &hf_rrlp_extended_reference, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_Extended_reference },
  { &hf_rrlp_posCapabilities, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_PosCapabilities },
  { &hf_rrlp_assistanceSupported, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_AssistanceSupported },
  { &hf_rrlp_assistanceNeeded, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_AssistanceNeeded },
  { &hf_rrlp_extensionContainer, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_ExtensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_PosCapability_Rsp(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_PosCapability_Rsp, PosCapability_Rsp_sequence);

  return offset;
}


static const value_string rrlp_RRLP_Component_vals[] = {
  {   0, "msrPositionReq" },
  {   1, "msrPositionRsp" },
  {   2, "assistanceData" },
  {   3, "assistanceDataAck" },
  {   4, "protocolError" },
  {   5, "posCapabilityReq" },
  {   6, "posCapabilityRsp" },
  { 0, NULL }
};

static const per_choice_t RRLP_Component_choice[] = {
  {   0, &hf_rrlp_msrPositionReq , ASN1_EXTENSION_ROOT    , dissect_rrlp_MsrPosition_Req },
  {   1, &hf_rrlp_msrPositionRsp , ASN1_EXTENSION_ROOT    , dissect_rrlp_MsrPosition_Rsp },
  {   2, &hf_rrlp_assistanceData , ASN1_EXTENSION_ROOT    , dissect_rrlp_AssistanceData },
  {   3, &hf_rrlp_assistanceDataAck, ASN1_EXTENSION_ROOT    , dissect_rrlp_NULL },
  {   4, &hf_rrlp_protocolError  , ASN1_EXTENSION_ROOT    , dissect_rrlp_ProtocolError },
  {   5, &hf_rrlp_posCapabilityReq, ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_PosCapability_Req },
  {   6, &hf_rrlp_posCapabilityRsp, ASN1_NOT_EXTENSION_ROOT, dissect_rrlp_PosCapability_Rsp },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_RRLP_Component(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_RRLP_Component, RRLP_Component_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t PDU_sequence[] = {
  { &hf_rrlp_referenceNumber, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_7 },
  { &hf_rrlp_component      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_RRLP_Component },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_PDU(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

	proto_tree_add_item(tree, proto_rrlp, tvb, 0, -1, ENC_NA);

	col_append_sep_str(actx->pinfo->cinfo, COL_PROTOCOL, "/", "RRLP");
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_PDU, PDU_sequence);

  return offset;
}

/*--- PDUs ---*/

static int dissect_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, false, pinfo);
  offset = dissect_rrlp_PDU(tvb, offset, &asn1_ctx, tree, hf_rrlp_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}



/*--- proto_register_rrlp -------------------------------------------*/
void proto_register_rrlp(void) {

  /* List of fields */
  static hf_register_info hf[] = {

    { &hf_rrlp_PDU_PDU,
      { "PDU", "rrlp.PDU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_privateExtensionList,
      { "privateExtensionList", "rrlp.privateExtensionList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_pcs_Extensions,
      { "pcs-Extensions", "rrlp.pcs_Extensions_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_PrivateExtensionList_item,
      { "PrivateExtension", "rrlp.PrivateExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_extId,
      { "extId", "rrlp.extId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_rrlp_extType,
      { "extType", "rrlp.extType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_referenceNumber,
      { "referenceNumber", "rrlp.referenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_component,
      { "component", "rrlp.component",
        FT_UINT32, BASE_DEC, VALS(rrlp_RRLP_Component_vals), 0,
        "RRLP_Component", HFILL }},
    { &hf_rrlp_msrPositionReq,
      { "msrPositionReq", "rrlp.msrPositionReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsrPosition_Req", HFILL }},
    { &hf_rrlp_msrPositionRsp,
      { "msrPositionRsp", "rrlp.msrPositionRsp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsrPosition_Rsp", HFILL }},
    { &hf_rrlp_assistanceData,
      { "assistanceData", "rrlp.assistanceData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_assistanceDataAck,
      { "assistanceDataAck", "rrlp.assistanceDataAck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_protocolError,
      { "protocolError", "rrlp.protocolError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_posCapabilityReq,
      { "posCapabilityReq", "rrlp.posCapabilityReq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosCapability_Req", HFILL }},
    { &hf_rrlp_posCapabilityRsp,
      { "posCapabilityRsp", "rrlp.posCapabilityRsp_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "PosCapability_Rsp", HFILL }},
    { &hf_rrlp_positionInstruct,
      { "positionInstruct", "rrlp.positionInstruct_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_referenceAssistData,
      { "referenceAssistData", "rrlp.referenceAssistData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_msrAssistData,
      { "msrAssistData", "rrlp.msrAssistData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_systemInfoAssistData,
      { "systemInfoAssistData", "rrlp.systemInfoAssistData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gps_AssistData,
      { "gps-AssistData", "rrlp.gps_AssistData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_extensionContainer,
      { "extensionContainer", "rrlp.extensionContainer_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_rel98_MsrPosition_Req_extension,
      { "rel98-MsrPosition-Req-extension", "rrlp.rel98_MsrPosition_Req_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_rel5_MsrPosition_Req_extension,
      { "rel5-MsrPosition-Req-extension", "rrlp.rel5_MsrPosition_Req_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_rel7_MsrPosition_Req_extension,
      { "rel7-MsrPosition-Req-extension", "rrlp.rel7_MsrPosition_Req_extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_multipleSets,
      { "multipleSets", "rrlp.multipleSets_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_referenceIdentity,
      { "referenceIdentity", "rrlp.referenceIdentity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_otd_MeasureInfo,
      { "otd-MeasureInfo", "rrlp.otd_MeasureInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_locationInfo,
      { "locationInfo", "rrlp.locationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gps_MeasureInfo,
      { "gps-MeasureInfo", "rrlp.gps_MeasureInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_locationError,
      { "locationError", "rrlp.locationError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_rel_98_MsrPosition_Rsp_Extension,
      { "rel-98-MsrPosition-Rsp-Extension", "rrlp.rel_98_MsrPosition_Rsp_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_rel_5_MsrPosition_Rsp_Extension,
      { "rel-5-MsrPosition-Rsp-Extension", "rrlp.rel_5_MsrPosition_Rsp_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_rel_7_MsrPosition_Rsp_Extension,
      { "rel-7-MsrPosition-Rsp-Extension", "rrlp.rel_7_MsrPosition_Rsp_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_moreAssDataToBeSent,
      { "moreAssDataToBeSent", "rrlp.moreAssDataToBeSent",
        FT_UINT32, BASE_DEC, VALS(rrlp_MoreAssDataToBeSent_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_rel98_AssistanceData_Extension,
      { "rel98-AssistanceData-Extension", "rrlp.rel98_AssistanceData_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_rel5_AssistanceData_Extension,
      { "rel5-AssistanceData-Extension", "rrlp.rel5_AssistanceData_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_rel7_AssistanceData_Extension,
      { "rel7-AssistanceData-Extension", "rrlp.rel7_AssistanceData_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_errorCause,
      { "errorCause", "rrlp.errorCause",
        FT_UINT32, BASE_DEC, VALS(rrlp_ErrorCodes_vals), 0,
        "ErrorCodes", HFILL }},
    { &hf_rrlp_rel_5_ProtocolError_Extension,
      { "rel-5-ProtocolError-Extension", "rrlp.rel_5_ProtocolError_Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_extended_reference,
      { "extended-reference", "rrlp.extended_reference_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gANSSPositionMethods,
      { "gANSSPositionMethods", "rrlp.gANSSPositionMethods",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_posCapabilities,
      { "posCapabilities", "rrlp.posCapabilities_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_assistanceSupported,
      { "assistanceSupported", "rrlp.assistanceSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_assistanceNeeded,
      { "assistanceNeeded", "rrlp.assistanceNeeded_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_methodType,
      { "methodType", "rrlp.methodType",
        FT_UINT32, BASE_DEC, VALS(rrlp_MethodType_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_positionMethod,
      { "positionMethod", "rrlp.positionMethod",
        FT_UINT32, BASE_DEC, VALS(rrlp_PositionMethod_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_measureResponseTime,
      { "measureResponseTime", "rrlp.measureResponseTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_useMultipleSets,
      { "useMultipleSets", "rrlp.useMultipleSets",
        FT_UINT32, BASE_DEC, VALS(rrlp_UseMultipleSets_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_environmentCharacter,
      { "environmentCharacter", "rrlp.environmentCharacter",
        FT_UINT32, BASE_DEC, VALS(rrlp_EnvironmentCharacter_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_msAssisted,
      { "msAssisted", "rrlp.msAssisted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AccuracyOpt", HFILL }},
    { &hf_rrlp_msBased,
      { "msBased", "rrlp.msBased",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Accuracy", HFILL }},
    { &hf_rrlp_msBasedPref,
      { "msBasedPref", "rrlp.msBasedPref",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Accuracy", HFILL }},
    { &hf_rrlp_msAssistedPref,
      { "msAssistedPref", "rrlp.msAssistedPref",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Accuracy", HFILL }},
    { &hf_rrlp_accuracy,
      { "accuracy", "rrlp.accuracy",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_bcchCarrier,
      { "bcchCarrier", "rrlp.bcchCarrier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_bsic,
      { "bsic", "rrlp.bsic",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_timeSlotScheme,
      { "timeSlotScheme", "rrlp.timeSlotScheme",
        FT_UINT32, BASE_DEC, VALS(rrlp_TimeSlotScheme_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_btsPosition,
      { "btsPosition", "rrlp.btsPosition",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_msrAssistList,
      { "msrAssistList", "rrlp.msrAssistList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfMsrAssistBTS", HFILL }},
    { &hf_rrlp_SeqOfMsrAssistBTS_item,
      { "MsrAssistBTS", "rrlp.MsrAssistBTS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_multiFrameOffset,
      { "multiFrameOffset", "rrlp.multiFrameOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_roughRTD,
      { "roughRTD", "rrlp.roughRTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_calcAssistanceBTS,
      { "calcAssistanceBTS", "rrlp.calcAssistanceBTS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_systemInfoAssistList,
      { "systemInfoAssistList", "rrlp.systemInfoAssistList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfSystemInfoAssistBTS", HFILL }},
    { &hf_rrlp_SeqOfSystemInfoAssistBTS_item,
      { "SystemInfoAssistBTS", "rrlp.SystemInfoAssistBTS",
        FT_UINT32, BASE_DEC, VALS(rrlp_SystemInfoAssistBTS_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_notPresent,
      { "notPresent", "rrlp.notPresent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_present,
      { "present", "rrlp.present_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AssistBTSData", HFILL }},
    { &hf_rrlp_fineRTD,
      { "fineRTD", "rrlp.fineRTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_referenceWGS84,
      { "referenceWGS84", "rrlp.referenceWGS84_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_relativeNorth,
      { "relativeNorth", "rrlp.relativeNorth",
        FT_INT32, BASE_DEC, NULL, 0,
        "RelDistance", HFILL }},
    { &hf_rrlp_relativeEast,
      { "relativeEast", "rrlp.relativeEast",
        FT_INT32, BASE_DEC, NULL, 0,
        "RelDistance", HFILL }},
    { &hf_rrlp_relativeAlt,
      { "relativeAlt", "rrlp.relativeAlt",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_nbrOfSets,
      { "nbrOfSets", "rrlp.nbrOfSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_2_3", HFILL }},
    { &hf_rrlp_nbrOfReferenceBTSs,
      { "nbrOfReferenceBTSs", "rrlp.nbrOfReferenceBTSs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_3", HFILL }},
    { &hf_rrlp_referenceRelation,
      { "referenceRelation", "rrlp.referenceRelation",
        FT_UINT32, BASE_DEC, VALS(rrlp_ReferenceRelation_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_refBTSList,
      { "refBTSList", "rrlp.refBTSList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfReferenceIdentityType", HFILL }},
    { &hf_rrlp_SeqOfReferenceIdentityType_item,
      { "ReferenceIdentityType", "rrlp.ReferenceIdentityType",
        FT_UINT32, BASE_DEC, VALS(rrlp_ReferenceIdentityType_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_bsicAndCarrier,
      { "bsicAndCarrier", "rrlp.bsicAndCarrier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ci,
      { "ci", "rrlp.ci",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellID", HFILL }},
    { &hf_rrlp_requestIndex,
      { "requestIndex", "rrlp.requestIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_systemInfoIndex,
      { "systemInfoIndex", "rrlp.systemInfoIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ciAndLAC,
      { "ciAndLAC", "rrlp.ciAndLAC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellIDAndLAC", HFILL }},
    { &hf_rrlp_carrier,
      { "carrier", "rrlp.carrier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BCCHCarrier", HFILL }},
    { &hf_rrlp_referenceLAC,
      { "referenceLAC", "rrlp.referenceLAC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LAC", HFILL }},
    { &hf_rrlp_referenceCI,
      { "referenceCI", "rrlp.referenceCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellID", HFILL }},
    { &hf_rrlp_otdMsrFirstSets,
      { "otdMsrFirstSets", "rrlp.otdMsrFirstSets_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OTD_MsrElementFirst", HFILL }},
    { &hf_rrlp_otdMsrRestSets,
      { "otdMsrRestSets", "rrlp.otdMsrRestSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfOTD_MsrElementRest", HFILL }},
    { &hf_rrlp_SeqOfOTD_MsrElementRest_item,
      { "OTD-MsrElementRest", "rrlp.OTD_MsrElementRest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_refFrameNumber,
      { "refFrameNumber", "rrlp.refFrameNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_42431", HFILL }},
    { &hf_rrlp_referenceTimeSlot,
      { "referenceTimeSlot", "rrlp.referenceTimeSlot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ModuloTimeSlot", HFILL }},
    { &hf_rrlp_toaMeasurementsOfRef,
      { "toaMeasurementsOfRef", "rrlp.toaMeasurementsOfRef_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "TOA_MeasurementsOfRef", HFILL }},
    { &hf_rrlp_stdResolution,
      { "stdResolution", "rrlp.stdResolution",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_taCorrection,
      { "taCorrection", "rrlp.taCorrection",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_960", HFILL }},
    { &hf_rrlp_otd_FirstSetMsrs,
      { "otd-FirstSetMsrs", "rrlp.otd_FirstSetMsrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfOTD_FirstSetMsrs", HFILL }},
    { &hf_rrlp_SeqOfOTD_FirstSetMsrs_item,
      { "OTD-FirstSetMsrs", "rrlp.OTD_FirstSetMsrs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_otd_MsrsOfOtherSets,
      { "otd-MsrsOfOtherSets", "rrlp.otd_MsrsOfOtherSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfOTD_MsrsOfOtherSets", HFILL }},
    { &hf_rrlp_SeqOfOTD_MsrsOfOtherSets_item,
      { "OTD-MsrsOfOtherSets", "rrlp.OTD_MsrsOfOtherSets",
        FT_UINT32, BASE_DEC, VALS(rrlp_OTD_MsrsOfOtherSets_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_refQuality,
      { "refQuality", "rrlp.refQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_numOfMeasurements,
      { "numOfMeasurements", "rrlp.numOfMeasurements",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_identityNotPresent,
      { "identityNotPresent", "rrlp.identityNotPresent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OTD_Measurement", HFILL }},
    { &hf_rrlp_identityPresent,
      { "identityPresent", "rrlp.identityPresent_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OTD_MeasurementWithID", HFILL }},
    { &hf_rrlp_nborTimeSlot,
      { "nborTimeSlot", "rrlp.nborTimeSlot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ModuloTimeSlot", HFILL }},
    { &hf_rrlp_eotdQuality,
      { "eotdQuality", "rrlp.eotdQuality_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_otdValue,
      { "otdValue", "rrlp.otdValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_neighborIdentity,
      { "neighborIdentity", "rrlp.neighborIdentity",
        FT_UINT32, BASE_DEC, VALS(rrlp_NeighborIdentity_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_nbrOfMeasurements,
      { "nbrOfMeasurements", "rrlp.nbrOfMeasurements",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_stdOfEOTD,
      { "stdOfEOTD", "rrlp.stdOfEOTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_rrlp_multiFrameCarrier,
      { "multiFrameCarrier", "rrlp.multiFrameCarrier_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_refFrame,
      { "refFrame", "rrlp.refFrame",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_rrlp_gpsTOW,
      { "gpsTOW", "rrlp.gpsTOW",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_14399999", HFILL }},
    { &hf_rrlp_fixType,
      { "fixType", "rrlp.fixType",
        FT_UINT32, BASE_DEC, VALS(rrlp_FixType_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_posEstimate,
      { "posEstimate", "rrlp.posEstimate",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Ext_GeographicalInformation", HFILL }},
    { &hf_rrlp_gpsMsrSetList,
      { "gpsMsrSetList", "rrlp.gpsMsrSetList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGPS_MsrSetElement", HFILL }},
    { &hf_rrlp_SeqOfGPS_MsrSetElement_item,
      { "GPS-MsrSetElement", "rrlp.GPS_MsrSetElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsTOW_01,
      { "gpsTOW", "rrlp.gpsTOW",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPSTOW24b", HFILL }},
    { &hf_rrlp_gps_msrList,
      { "gps-msrList", "rrlp.gps_msrList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGPS_MsrElement", HFILL }},
    { &hf_rrlp_SeqOfGPS_MsrElement_item,
      { "GPS-MsrElement", "rrlp.GPS_MsrElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_satelliteID,
      { "satelliteID", "rrlp.satelliteID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_cNo,
      { "cNo", "rrlp.cNo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_rrlp_doppler,
      { "doppler", "rrlp.doppler",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_wholeChips,
      { "wholeChips", "rrlp.wholeChips",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1022", HFILL }},
    { &hf_rrlp_fracChips,
      { "fracChips", "rrlp.fracChips",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1024", HFILL }},
    { &hf_rrlp_mpathIndic,
      { "mpathIndic", "rrlp.mpathIndic",
        FT_UINT32, BASE_DEC, VALS(rrlp_MpathIndic_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_pseuRangeRMSErr,
      { "pseuRangeRMSErr", "rrlp.pseuRangeRMSErr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_rrlp_locErrorReason,
      { "locErrorReason", "rrlp.locErrorReason",
        FT_UINT32, BASE_DEC, VALS(rrlp_LocErrorReason_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_additionalAssistanceData,
      { "additionalAssistanceData", "rrlp.additionalAssistanceData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsAssistanceData,
      { "gpsAssistanceData", "rrlp.gpsAssistanceData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssAssistanceData,
      { "ganssAssistanceData", "rrlp.ganssAssistanceData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_controlHeader,
      { "controlHeader", "rrlp.controlHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_referenceTime,
      { "referenceTime", "rrlp.referenceTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_refLocation,
      { "refLocation", "rrlp.refLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_dgpsCorrections,
      { "dgpsCorrections", "rrlp.dgpsCorrections_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_navigationModel,
      { "navigationModel", "rrlp.navigationModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ionosphericModel,
      { "ionosphericModel", "rrlp.ionosphericModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_utcModel,
      { "utcModel", "rrlp.utcModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_almanac,
      { "almanac", "rrlp.almanac_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_acquisAssist,
      { "acquisAssist", "rrlp.acquisAssist_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_realTimeIntegrity,
      { "realTimeIntegrity", "rrlp.realTimeIntegrity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOf_BadSatelliteSet", HFILL }},
    { &hf_rrlp_gpsTime,
      { "gpsTime", "rrlp.gpsTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gsmTime,
      { "gsmTime", "rrlp.gsmTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsTowAssist,
      { "gpsTowAssist", "rrlp.gpsTowAssist",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsTOW23b,
      { "gpsTOW23b", "rrlp.gpsTOW23b",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsWeek,
      { "gpsWeek", "rrlp.gpsWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_GPSTOWAssist_item,
      { "GPSTOWAssistElement", "rrlp.GPSTOWAssistElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_tlmWord,
      { "tlmWord", "rrlp.tlmWord",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_antiSpoof,
      { "antiSpoof", "rrlp.antiSpoof",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AntiSpoofFlag", HFILL }},
    { &hf_rrlp_alert,
      { "alert", "rrlp.alert",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AlertFlag", HFILL }},
    { &hf_rrlp_tlmRsvdBits,
      { "tlmRsvdBits", "rrlp.tlmRsvdBits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TLMReservedBits", HFILL }},
    { &hf_rrlp_frameNumber,
      { "frameNumber", "rrlp.frameNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_timeSlot,
      { "timeSlot", "rrlp.timeSlot",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_bitNumber,
      { "bitNumber", "rrlp.bitNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_threeDLocation,
      { "threeDLocation", "rrlp.threeDLocation",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Ext_GeographicalInformation", HFILL }},
    { &hf_rrlp_gpsTOW_02,
      { "gpsTOW", "rrlp.gpsTOW",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_604799", HFILL }},
    { &hf_rrlp_status,
      { "status", "rrlp.status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_satList,
      { "satList", "rrlp.satList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfSatElement", HFILL }},
    { &hf_rrlp_SeqOfSatElement_item,
      { "SatElement", "rrlp.SatElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_iode,
      { "iode", "rrlp.iode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_239", HFILL }},
    { &hf_rrlp_udre,
      { "udre", "rrlp.udre",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_rrlp_pseudoRangeCor,
      { "pseudoRangeCor", "rrlp.pseudoRangeCor",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2047_2047", HFILL }},
    { &hf_rrlp_rangeRateCor,
      { "rangeRateCor", "rrlp.rangeRateCor",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_127", HFILL }},
    { &hf_rrlp_deltaPseudoRangeCor2,
      { "deltaPseudoRangeCor2", "rrlp.deltaPseudoRangeCor2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_127", HFILL }},
    { &hf_rrlp_deltaRangeRateCor2,
      { "deltaRangeRateCor2", "rrlp.deltaRangeRateCor2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M7_7", HFILL }},
    { &hf_rrlp_deltaPseudoRangeCor3,
      { "deltaPseudoRangeCor3", "rrlp.deltaPseudoRangeCor3",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M127_127", HFILL }},
    { &hf_rrlp_deltaRangeRateCor3,
      { "deltaRangeRateCor3", "rrlp.deltaRangeRateCor3",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M7_7", HFILL }},
    { &hf_rrlp_navModelList,
      { "navModelList", "rrlp.navModelList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfNavModelElement", HFILL }},
    { &hf_rrlp_SeqOfNavModelElement_item,
      { "NavModelElement", "rrlp.NavModelElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_satStatus,
      { "satStatus", "rrlp.satStatus",
        FT_UINT32, BASE_DEC, VALS(rrlp_SatStatus_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_newSatelliteAndModelUC,
      { "newSatelliteAndModelUC", "rrlp.newSatelliteAndModelUC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UncompressedEphemeris", HFILL }},
    { &hf_rrlp_oldSatelliteAndModel,
      { "oldSatelliteAndModel", "rrlp.oldSatelliteAndModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_newNaviModelUC,
      { "newNaviModelUC", "rrlp.newNaviModelUC_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UncompressedEphemeris", HFILL }},
    { &hf_rrlp_ephemCodeOnL2,
      { "ephemCodeOnL2", "rrlp.ephemCodeOnL2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_rrlp_ephemURA,
      { "ephemURA", "rrlp.ephemURA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_rrlp_ephemSVhealth,
      { "ephemSVhealth", "rrlp.ephemSVhealth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_rrlp_ephemIODC,
      { "ephemIODC", "rrlp.ephemIODC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_rrlp_ephemL2Pflag,
      { "ephemL2Pflag", "rrlp.ephemL2Pflag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_rrlp_ephemSF1Rsvd,
      { "ephemSF1Rsvd", "rrlp.ephemSF1Rsvd_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EphemerisSubframe1Reserved", HFILL }},
    { &hf_rrlp_ephemTgd,
      { "ephemTgd", "rrlp.ephemTgd",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_ephemToc,
      { "ephemToc", "rrlp.ephemToc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_37799", HFILL }},
    { &hf_rrlp_ephemAF2,
      { "ephemAF2", "rrlp.ephemAF2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_ephemAF1,
      { "ephemAF1", "rrlp.ephemAF1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemAF0,
      { "ephemAF0", "rrlp.ephemAF0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2097152_2097151", HFILL }},
    { &hf_rrlp_ephemCrs,
      { "ephemCrs", "rrlp.ephemCrs",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemDeltaN,
      { "ephemDeltaN", "rrlp.ephemDeltaN",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemM0,
      { "ephemM0", "rrlp.ephemM0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_ephemCuc,
      { "ephemCuc", "rrlp.ephemCuc",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemE,
      { "ephemE", "rrlp.ephemE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_rrlp_ephemCus,
      { "ephemCus", "rrlp.ephemCus",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemAPowerHalf,
      { "ephemAPowerHalf", "rrlp.ephemAPowerHalf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_rrlp_ephemToe,
      { "ephemToe", "rrlp.ephemToe",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_37799", HFILL }},
    { &hf_rrlp_ephemFitFlag,
      { "ephemFitFlag", "rrlp.ephemFitFlag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_rrlp_ephemAODA,
      { "ephemAODA", "rrlp.ephemAODA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_rrlp_ephemCic,
      { "ephemCic", "rrlp.ephemCic",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemOmegaA0,
      { "ephemOmegaA0", "rrlp.ephemOmegaA0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_ephemCis,
      { "ephemCis", "rrlp.ephemCis",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemI0,
      { "ephemI0", "rrlp.ephemI0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_ephemCrc,
      { "ephemCrc", "rrlp.ephemCrc",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemW,
      { "ephemW", "rrlp.ephemW",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_ephemOmegaADot,
      { "ephemOmegaADot", "rrlp.ephemOmegaADot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_ephemIDot,
      { "ephemIDot", "rrlp.ephemIDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8192_8191", HFILL }},
    { &hf_rrlp_reserved1,
      { "reserved1", "rrlp.reserved1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8388607", HFILL }},
    { &hf_rrlp_reserved2,
      { "reserved2", "rrlp.reserved2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_rrlp_reserved3,
      { "reserved3", "rrlp.reserved3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_rrlp_reserved4,
      { "reserved4", "rrlp.reserved4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_rrlp_alfa0,
      { "alfa0", "rrlp.alfa0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_alfa1,
      { "alfa1", "rrlp.alfa1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_alfa2,
      { "alfa2", "rrlp.alfa2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_alfa3,
      { "alfa3", "rrlp.alfa3",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_beta0,
      { "beta0", "rrlp.beta0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_beta1,
      { "beta1", "rrlp.beta1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_beta2,
      { "beta2", "rrlp.beta2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_beta3,
      { "beta3", "rrlp.beta3",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_utcA1,
      { "utcA1", "rrlp.utcA1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_utcA0,
      { "utcA0", "rrlp.utcA0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_utcTot,
      { "utcTot", "rrlp.utcTot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_rrlp_utcWNt,
      { "utcWNt", "rrlp.utcWNt",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_rrlp_utcDeltaTls,
      { "utcDeltaTls", "rrlp.utcDeltaTls",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_utcWNlsf,
      { "utcWNlsf", "rrlp.utcWNlsf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_rrlp_utcDN,
      { "utcDN", "rrlp.utcDN",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_utcDeltaTlsf,
      { "utcDeltaTlsf", "rrlp.utcDeltaTlsf",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_alamanacWNa,
      { "alamanacWNa", "rrlp.alamanacWNa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_rrlp_almanacList,
      { "almanacList", "rrlp.almanacList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfAlmanacElement", HFILL }},
    { &hf_rrlp_SeqOfAlmanacElement_item,
      { "AlmanacElement", "rrlp.AlmanacElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_almanacE,
      { "almanacE", "rrlp.almanacE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_rrlp_alamanacToa,
      { "alamanacToa", "rrlp.alamanacToa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_rrlp_almanacKsii,
      { "almanacKsii", "rrlp.almanacKsii",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_almanacOmegaDot,
      { "almanacOmegaDot", "rrlp.almanacOmegaDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_almanacSVhealth,
      { "almanacSVhealth", "rrlp.almanacSVhealth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_rrlp_almanacAPowerHalf,
      { "almanacAPowerHalf", "rrlp.almanacAPowerHalf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_rrlp_almanacOmega0,
      { "almanacOmega0", "rrlp.almanacOmega0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_almanacW,
      { "almanacW", "rrlp.almanacW",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_almanacM0,
      { "almanacM0", "rrlp.almanacM0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_almanacAF0,
      { "almanacAF0", "rrlp.almanacAF0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_almanacAF1,
      { "almanacAF1", "rrlp.almanacAF1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_timeRelation,
      { "timeRelation", "rrlp.timeRelation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_acquisList,
      { "acquisList", "rrlp.acquisList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfAcquisElement", HFILL }},
    { &hf_rrlp_SeqOfAcquisElement_item,
      { "AcquisElement", "rrlp.AcquisElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsTOW_03,
      { "gpsTOW", "rrlp.gpsTOW",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPSTOW23b", HFILL }},
    { &hf_rrlp_svid,
      { "svid", "rrlp.svid",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SatelliteID", HFILL }},
    { &hf_rrlp_doppler0,
      { "doppler0", "rrlp.doppler0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2048_2047", HFILL }},
    { &hf_rrlp_addionalDoppler,
      { "addionalDoppler", "rrlp.addionalDoppler_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddionalDopplerFields", HFILL }},
    { &hf_rrlp_codePhase,
      { "codePhase", "rrlp.codePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1022", HFILL }},
    { &hf_rrlp_intCodePhase,
      { "intCodePhase", "rrlp.intCodePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_19", HFILL }},
    { &hf_rrlp_gpsBitNumber,
      { "gpsBitNumber", "rrlp.gpsBitNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_rrlp_codePhaseSearchWindow,
      { "codePhaseSearchWindow", "rrlp.codePhaseSearchWindow",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_rrlp_addionalAngle,
      { "addionalAngle", "rrlp.addionalAngle_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddionalAngleFields", HFILL }},
    { &hf_rrlp_doppler1,
      { "doppler1", "rrlp.doppler1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_rrlp_dopplerUncertainty,
      { "dopplerUncertainty", "rrlp.dopplerUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_azimuth,
      { "azimuth", "rrlp.azimuth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_rrlp_elevation,
      { "elevation", "rrlp.elevation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_SeqOf_BadSatelliteSet_item,
      { "SatelliteID", "rrlp.SatelliteID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_rel98_Ext_ExpOTD,
      { "rel98-Ext-ExpOTD", "rrlp.rel98_Ext_ExpOTD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsTimeAssistanceMeasurementRequest,
      { "gpsTimeAssistanceMeasurementRequest", "rrlp.gpsTimeAssistanceMeasurementRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsReferenceTimeUncertainty,
      { "gpsReferenceTimeUncertainty", "rrlp.gpsReferenceTimeUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_msrAssistData_R98_ExpOTD,
      { "msrAssistData-R98-ExpOTD", "rrlp.msrAssistData_R98_ExpOTD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_systemInfoAssistData_R98_ExpOTD,
      { "systemInfoAssistData-R98-ExpOTD", "rrlp.systemInfoAssistData_R98_ExpOTD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_msrAssistList_R98_ExpOTD,
      { "msrAssistList-R98-ExpOTD", "rrlp.msrAssistList_R98_ExpOTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfMsrAssistBTS_R98_ExpOTD", HFILL }},
    { &hf_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD_item,
      { "MsrAssistBTS-R98-ExpOTD", "rrlp.MsrAssistBTS_R98_ExpOTD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_expectedOTD,
      { "expectedOTD", "rrlp.expectedOTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_expOTDUncertainty,
      { "expOTDUncertainty", "rrlp.expOTDUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_systemInfoAssistListR98_ExpOTD,
      { "systemInfoAssistListR98-ExpOTD", "rrlp.systemInfoAssistListR98_ExpOTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfSystemInfoAssistBTS_R98_ExpOTD", HFILL }},
    { &hf_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD_item,
      { "SystemInfoAssistBTS-R98-ExpOTD", "rrlp.SystemInfoAssistBTS_R98_ExpOTD",
        FT_UINT32, BASE_DEC, VALS(rrlp_SystemInfoAssistBTS_R98_ExpOTD_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_present_01,
      { "present", "rrlp.present_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AssistBTSData_R98_ExpOTD", HFILL }},
    { &hf_rrlp_expOTDuncertainty,
      { "expOTDuncertainty", "rrlp.expOTDuncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_referenceFrameMSB,
      { "referenceFrameMSB", "rrlp.referenceFrameMSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_rrlp_gpsTowSubms,
      { "gpsTowSubms", "rrlp.gpsTowSubms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9999", HFILL }},
    { &hf_rrlp_deltaTow,
      { "deltaTow", "rrlp.deltaTow",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_rrlp_rel_98_Ext_MeasureInfo,
      { "rel-98-Ext-MeasureInfo", "rrlp.rel_98_Ext_MeasureInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_rel_98_Ext_MeasureInfo", HFILL }},
    { &hf_rrlp_otd_MeasureInfo_R98_Ext,
      { "otd-MeasureInfo-R98-Ext", "rrlp.otd_MeasureInfo_R98_Ext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_timeAssistanceMeasurements,
      { "timeAssistanceMeasurements", "rrlp.timeAssistanceMeasurements_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPSTimeAssistanceMeasurements", HFILL }},
    { &hf_rrlp_otdMsrFirstSets_R98_Ext,
      { "otdMsrFirstSets-R98-Ext", "rrlp.otdMsrFirstSets_R98_Ext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "OTD_MsrElementFirst_R98_Ext", HFILL }},
    { &hf_rrlp_otd_FirstSetMsrs_R98_Ext,
      { "otd-FirstSetMsrs-R98-Ext", "rrlp.otd_FirstSetMsrs_R98_Ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfOTD_FirstSetMsrs_R98_Ext", HFILL }},
    { &hf_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext_item,
      { "OTD-FirstSetMsrs", "rrlp.OTD_FirstSetMsrs_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_otd_MeasureInfo_5_Ext,
      { "otd-MeasureInfo-5-Ext", "rrlp.otd_MeasureInfo_5_Ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ulPseudoSegInd,
      { "ulPseudoSegInd", "rrlp.ulPseudoSegInd",
        FT_UINT32, BASE_DEC, VALS(rrlp_UlPseudoSegInd_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_smlc_code,
      { "smlc-code", "rrlp.smlc_code",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_rrlp_transaction_ID,
      { "transaction-ID", "rrlp.transaction_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_262143", HFILL }},
    { &hf_rrlp_velocityRequested,
      { "velocityRequested", "rrlp.velocityRequested_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssPositionMethod,
      { "ganssPositionMethod", "rrlp.ganssPositionMethod",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GANSSPositioningMethod", HFILL }},
    { &hf_rrlp_ganss_AssistData,
      { "ganss-AssistData", "rrlp.ganss_AssistData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssCarrierPhaseMeasurementRequest,
      { "ganssCarrierPhaseMeasurementRequest", "rrlp.ganssCarrierPhaseMeasurementRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssTODGSMTimeAssociationMeasurementRequest,
      { "ganssTODGSMTimeAssociationMeasurementRequest", "rrlp.ganssTODGSMTimeAssociationMeasurementRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_requiredResponseTime,
      { "requiredResponseTime", "rrlp.requiredResponseTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_add_GPS_AssistData,
      { "add-GPS-AssistData", "rrlp.add_GPS_AssistData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssMultiFreqMeasurementRequest,
      { "ganssMultiFreqMeasurementRequest", "rrlp.ganssMultiFreqMeasurementRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganss_controlHeader,
      { "ganss-controlHeader", "rrlp.ganss_controlHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssCommonAssistData,
      { "ganssCommonAssistData", "rrlp.ganssCommonAssistData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssGenericAssistDataList,
      { "ganssGenericAssistDataList", "rrlp.ganssGenericAssistDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGANSSGenericAssistDataElement", HFILL }},
    { &hf_rrlp_ganssReferenceTime,
      { "ganssReferenceTime", "rrlp.ganssReferenceTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssRefLocation,
      { "ganssRefLocation", "rrlp.ganssRefLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssIonosphericModel,
      { "ganssIonosphericModel", "rrlp.ganssIonosphericModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssAddIonosphericModel,
      { "ganssAddIonosphericModel", "rrlp.ganssAddIonosphericModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssEarthOrientParam,
      { "ganssEarthOrientParam", "rrlp.ganssEarthOrientParam_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssReferenceTime_R10_Ext,
      { "ganssReferenceTime-R10-Ext", "rrlp.ganssReferenceTime_R10_Ext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_SeqOfGANSSGenericAssistDataElement_item,
      { "GANSSGenericAssistDataElement", "rrlp.GANSSGenericAssistDataElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssID,
      { "ganssID", "rrlp.ganssID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_ganssTimeModel,
      { "ganssTimeModel", "rrlp.ganssTimeModel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGANSSTimeModel", HFILL }},
    { &hf_rrlp_ganssDiffCorrections,
      { "ganssDiffCorrections", "rrlp.ganssDiffCorrections_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssNavigationModel,
      { "ganssNavigationModel", "rrlp.ganssNavigationModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSNavModel", HFILL }},
    { &hf_rrlp_ganssRealTimeIntegrity,
      { "ganssRealTimeIntegrity", "rrlp.ganssRealTimeIntegrity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssDataBitAssist,
      { "ganssDataBitAssist", "rrlp.ganssDataBitAssist_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssRefMeasurementAssist,
      { "ganssRefMeasurementAssist", "rrlp.ganssRefMeasurementAssist_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssAlmanacModel,
      { "ganssAlmanacModel", "rrlp.ganssAlmanacModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssUTCModel,
      { "ganssUTCModel", "rrlp.ganssUTCModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssEphemerisExtension,
      { "ganssEphemerisExtension", "rrlp.ganssEphemerisExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssEphemerisExtCheck,
      { "ganssEphemerisExtCheck", "rrlp.ganssEphemerisExtCheck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSEphemerisExtensionCheck", HFILL }},
    { &hf_rrlp_sbasID,
      { "sbasID", "rrlp.sbasID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_ganssAddUTCModel,
      { "ganssAddUTCModel", "rrlp.ganssAddUTCModel",
        FT_UINT32, BASE_DEC, VALS(rrlp_GANSSAddUTCModel_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssAuxiliaryInfo,
      { "ganssAuxiliaryInfo", "rrlp.ganssAuxiliaryInfo",
        FT_UINT32, BASE_DEC, VALS(rrlp_GANSSAuxiliaryInformation_vals), 0,
        "GANSSAuxiliaryInformation", HFILL }},
    { &hf_rrlp_ganssDiffCorrectionsValidityPeriod,
      { "ganssDiffCorrectionsValidityPeriod", "rrlp.ganssDiffCorrectionsValidityPeriod",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssTimeModel_R10_Ext,
      { "ganssTimeModel-R10-Ext", "rrlp.ganssTimeModel_R10_Ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGANSSTimeModel_R10_Ext", HFILL }},
    { &hf_rrlp_ganssRefMeasurementAssist_R10_Ext,
      { "ganssRefMeasurementAssist-R10-Ext", "rrlp.ganssRefMeasurementAssist_R10_Ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssAlmanacModel_R10_Ext,
      { "ganssAlmanacModel-R10-Ext", "rrlp.ganssAlmanacModel_R10_Ext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssRefTimeInfo,
      { "ganssRefTimeInfo", "rrlp.ganssRefTimeInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssTOD_GSMTimeAssociation,
      { "ganssTOD-GSMTimeAssociation", "rrlp.ganssTOD_GSMTimeAssociation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssDay,
      { "ganssDay", "rrlp.ganssDay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_rrlp_ganssTOD,
      { "ganssTOD", "rrlp.ganssTOD",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssTODUncertainty,
      { "ganssTODUncertainty", "rrlp.ganssTODUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssTimeID,
      { "ganssTimeID", "rrlp.ganssTimeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_ganssDayCycleNumber,
      { "ganssDayCycleNumber", "rrlp.ganssDayCycleNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_frameDrift,
      { "frameDrift", "rrlp.frameDrift",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssIonoModel,
      { "ganssIonoModel", "rrlp.ganssIonoModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSIonosphereModel", HFILL }},
    { &hf_rrlp_ganssIonoStormFlags,
      { "ganssIonoStormFlags", "rrlp.ganssIonoStormFlags_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ai0,
      { "ai0", "rrlp.ai0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_rrlp_ai1,
      { "ai1", "rrlp.ai1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_rrlp_ai2,
      { "ai2", "rrlp.ai2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4095", HFILL }},
    { &hf_rrlp_ionoStormFlag1,
      { "ionoStormFlag1", "rrlp.ionoStormFlag1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_rrlp_ionoStormFlag2,
      { "ionoStormFlag2", "rrlp.ionoStormFlag2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_rrlp_ionoStormFlag3,
      { "ionoStormFlag3", "rrlp.ionoStormFlag3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_rrlp_ionoStormFlag4,
      { "ionoStormFlag4", "rrlp.ionoStormFlag4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_rrlp_ionoStormFlag5,
      { "ionoStormFlag5", "rrlp.ionoStormFlag5",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_rrlp_dataID,
      { "dataID", "rrlp.dataID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_rrlp_ionoModel,
      { "ionoModel", "rrlp.ionoModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IonosphericModel", HFILL }},
    { &hf_rrlp_teop,
      { "teop", "rrlp.teop",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_rrlp_pmX,
      { "pmX", "rrlp.pmX",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1048576_1048575", HFILL }},
    { &hf_rrlp_pmXdot,
      { "pmXdot", "rrlp.pmXdot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16384_16383", HFILL }},
    { &hf_rrlp_pmY,
      { "pmY", "rrlp.pmY",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1048576_1048575", HFILL }},
    { &hf_rrlp_pmYdot,
      { "pmYdot", "rrlp.pmYdot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16384_16383", HFILL }},
    { &hf_rrlp_deltaUT1,
      { "deltaUT1", "rrlp.deltaUT1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1073741824_1073741823", HFILL }},
    { &hf_rrlp_deltaUT1dot,
      { "deltaUT1dot", "rrlp.deltaUT1dot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M262144_262143", HFILL }},
    { &hf_rrlp_SeqOfGANSSTimeModel_item,
      { "GANSSTimeModelElement", "rrlp.GANSSTimeModelElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssTimeModelRefTime,
      { "ganssTimeModelRefTime", "rrlp.ganssTimeModelRefTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_rrlp_tA0,
      { "tA0", "rrlp.tA0",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_tA1,
      { "tA1", "rrlp.tA1",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_tA2,
      { "tA2", "rrlp.tA2",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gnssTOID,
      { "gnssTOID", "rrlp.gnssTOID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_weekNumber,
      { "weekNumber", "rrlp.weekNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_rrlp_SeqOfGANSSTimeModel_R10_Ext_item,
      { "GANSSTimeModelElement-R10-Ext", "rrlp.GANSSTimeModelElement_R10_Ext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_deltaT,
      { "deltaT", "rrlp.deltaT",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_dganssRefTime,
      { "dganssRefTime", "rrlp.dganssRefTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_119", HFILL }},
    { &hf_rrlp_sgnTypeList,
      { "sgnTypeList", "rrlp.sgnTypeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfSgnTypeElement", HFILL }},
    { &hf_rrlp_SeqOfSgnTypeElement_item,
      { "SgnTypeElement", "rrlp.SgnTypeElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssSignalID,
      { "ganssSignalID", "rrlp.ganssSignalID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssStatusHealth,
      { "ganssStatusHealth", "rrlp.ganssStatusHealth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_dganssSgnList,
      { "dganssSgnList", "rrlp.dganssSgnList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfDGANSSSgnElement", HFILL }},
    { &hf_rrlp_SeqOfDGANSSSgnElement_item,
      { "DGANSSSgnElement", "rrlp.DGANSSSgnElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_svID,
      { "svID", "rrlp.svID",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_iod,
      { "iod", "rrlp.iod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_rrlp_nonBroadcastIndFlag,
      { "nonBroadcastIndFlag", "rrlp.nonBroadcastIndFlag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_rrlp_ganssSatelliteList,
      { "ganssSatelliteList", "rrlp.ganssSatelliteList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGANSSSatelliteElement", HFILL }},
    { &hf_rrlp_SeqOfGANSSSatelliteElement_item,
      { "GANSSSatelliteElement", "rrlp.GANSSSatelliteElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_svHealth,
      { "svHealth", "rrlp.svHealth",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_5", HFILL }},
    { &hf_rrlp_ganssClockModel,
      { "ganssClockModel", "rrlp.ganssClockModel",
        FT_UINT32, BASE_DEC, VALS(rrlp_GANSSClockModel_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssOrbitModel,
      { "ganssOrbitModel", "rrlp.ganssOrbitModel",
        FT_UINT32, BASE_DEC, VALS(rrlp_GANSSOrbitModel_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_svHealthMSB,
      { "svHealthMSB", "rrlp.svHealthMSB",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_1", HFILL }},
    { &hf_rrlp_iodMSB,
      { "iodMSB", "rrlp.iodMSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_rrlp_keplerianSet,
      { "keplerianSet", "rrlp.keplerianSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavModel_KeplerianSet", HFILL }},
    { &hf_rrlp_navKeplerianSet,
      { "navKeplerianSet", "rrlp.navKeplerianSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavModel_NAVKeplerianSet", HFILL }},
    { &hf_rrlp_cnavKeplerianSet,
      { "cnavKeplerianSet", "rrlp.cnavKeplerianSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavModel_CNAVKeplerianSet", HFILL }},
    { &hf_rrlp_glonassECEF,
      { "glonassECEF", "rrlp.glonassECEF_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavModel_GLONASSecef", HFILL }},
    { &hf_rrlp_sbasECEF,
      { "sbasECEF", "rrlp.sbasECEF_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NavModel_SBASecef", HFILL }},
    { &hf_rrlp_keplerToe,
      { "keplerToe", "rrlp.keplerToe",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_rrlp_keplerW,
      { "keplerW", "rrlp.keplerW",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_keplerDeltaN,
      { "keplerDeltaN", "rrlp.keplerDeltaN",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_keplerM0,
      { "keplerM0", "rrlp.keplerM0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_keplerOmegaDot,
      { "keplerOmegaDot", "rrlp.keplerOmegaDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_keplerE,
      { "keplerE", "rrlp.keplerE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_rrlp_keplerIDot,
      { "keplerIDot", "rrlp.keplerIDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8192_8191", HFILL }},
    { &hf_rrlp_keplerAPowerHalf,
      { "keplerAPowerHalf", "rrlp.keplerAPowerHalf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_rrlp_keplerI0,
      { "keplerI0", "rrlp.keplerI0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_keplerOmega0,
      { "keplerOmega0", "rrlp.keplerOmega0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_keplerCrs,
      { "keplerCrs", "rrlp.keplerCrs",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_keplerCis,
      { "keplerCis", "rrlp.keplerCis",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_keplerCus,
      { "keplerCus", "rrlp.keplerCus",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_keplerCrc,
      { "keplerCrc", "rrlp.keplerCrc",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_keplerCic,
      { "keplerCic", "rrlp.keplerCic",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_keplerCuc,
      { "keplerCuc", "rrlp.keplerCuc",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_navURA,
      { "navURA", "rrlp.navURA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_rrlp_navFitFlag,
      { "navFitFlag", "rrlp.navFitFlag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_rrlp_navToe,
      { "navToe", "rrlp.navToe",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_37799", HFILL }},
    { &hf_rrlp_navOmega,
      { "navOmega", "rrlp.navOmega",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_navDeltaN,
      { "navDeltaN", "rrlp.navDeltaN",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_navM0,
      { "navM0", "rrlp.navM0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_navOmegaADot,
      { "navOmegaADot", "rrlp.navOmegaADot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_navE,
      { "navE", "rrlp.navE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_rrlp_navIDot,
      { "navIDot", "rrlp.navIDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8192_8191", HFILL }},
    { &hf_rrlp_navAPowerHalf,
      { "navAPowerHalf", "rrlp.navAPowerHalf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4294967295", HFILL }},
    { &hf_rrlp_navI0,
      { "navI0", "rrlp.navI0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_navOmegaA0,
      { "navOmegaA0", "rrlp.navOmegaA0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_navCrs,
      { "navCrs", "rrlp.navCrs",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_navCis,
      { "navCis", "rrlp.navCis",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_navCus,
      { "navCus", "rrlp.navCus",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_navCrc,
      { "navCrc", "rrlp.navCrc",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_navCic,
      { "navCic", "rrlp.navCic",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_navCuc,
      { "navCuc", "rrlp.navCuc",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_cnavTop,
      { "cnavTop", "rrlp.cnavTop",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2015", HFILL }},
    { &hf_rrlp_cnavURAindex,
      { "cnavURAindex", "rrlp.cnavURAindex",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_cnavDeltaA,
      { "cnavDeltaA", "rrlp.cnavDeltaA",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M33554432_33554431", HFILL }},
    { &hf_rrlp_cnavAdot,
      { "cnavAdot", "rrlp.cnavAdot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16777216_16777215", HFILL }},
    { &hf_rrlp_cnavDeltaNo,
      { "cnavDeltaNo", "rrlp.cnavDeltaNo",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M65536_65535", HFILL }},
    { &hf_rrlp_cnavDeltaNoDot,
      { "cnavDeltaNoDot", "rrlp.cnavDeltaNoDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M4194304_4194303", HFILL }},
    { &hf_rrlp_cnavMo,
      { "cnavMo", "rrlp.cnavMo",
        FT_INT64, BASE_DEC, NULL, 0,
        "INTEGER_M4294967296_4294967295", HFILL }},
    { &hf_rrlp_cnavE,
      { "cnavE", "rrlp.cnavE",
        FT_UINT64, BASE_DEC, NULL, 0,
        "INTEGER_0_8589934591", HFILL }},
    { &hf_rrlp_cnavOmega,
      { "cnavOmega", "rrlp.cnavOmega",
        FT_INT64, BASE_DEC, NULL, 0,
        "INTEGER_M4294967296_4294967295", HFILL }},
    { &hf_rrlp_cnavOMEGA0,
      { "cnavOMEGA0", "rrlp.cnavOMEGA0",
        FT_INT64, BASE_DEC, NULL, 0,
        "INTEGER_M4294967296_4294967295", HFILL }},
    { &hf_rrlp_cnavDeltaOmegaDot,
      { "cnavDeltaOmegaDot", "rrlp.cnavDeltaOmegaDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M65536_65535", HFILL }},
    { &hf_rrlp_cnavIo,
      { "cnavIo", "rrlp.cnavIo",
        FT_INT64, BASE_DEC, NULL, 0,
        "INTEGER_M4294967296_4294967295", HFILL }},
    { &hf_rrlp_cnavIoDot,
      { "cnavIoDot", "rrlp.cnavIoDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16384_16383", HFILL }},
    { &hf_rrlp_cnavCis,
      { "cnavCis", "rrlp.cnavCis",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_cnavCic,
      { "cnavCic", "rrlp.cnavCic",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_cnavCrs,
      { "cnavCrs", "rrlp.cnavCrs",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_cnavCrc,
      { "cnavCrc", "rrlp.cnavCrc",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_cnavCus,
      { "cnavCus", "rrlp.cnavCus",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1048576_1048575", HFILL }},
    { &hf_rrlp_cnavCuc,
      { "cnavCuc", "rrlp.cnavCuc",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1048576_1048575", HFILL }},
    { &hf_rrlp_gloEn,
      { "gloEn", "rrlp.gloEn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_rrlp_gloP1,
      { "gloP1", "rrlp.gloP1",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_rrlp_gloP2,
      { "gloP2", "rrlp.gloP2",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_rrlp_gloM,
      { "gloM", "rrlp.gloM",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_rrlp_gloX,
      { "gloX", "rrlp.gloX",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M67108864_67108863", HFILL }},
    { &hf_rrlp_gloXdot,
      { "gloXdot", "rrlp.gloXdot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_gloXdotdot,
      { "gloXdotdot", "rrlp.gloXdotdot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_gloY,
      { "gloY", "rrlp.gloY",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M67108864_67108863", HFILL }},
    { &hf_rrlp_gloYdot,
      { "gloYdot", "rrlp.gloYdot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_gloYdotdot,
      { "gloYdotdot", "rrlp.gloYdotdot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_gloZ,
      { "gloZ", "rrlp.gloZ",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M67108864_67108863", HFILL }},
    { &hf_rrlp_gloZdot,
      { "gloZdot", "rrlp.gloZdot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_gloZdotdot,
      { "gloZdotdot", "rrlp.gloZdotdot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_sbasTo,
      { "sbasTo", "rrlp.sbasTo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_5399", HFILL }},
    { &hf_rrlp_sbasAccuracy,
      { "sbasAccuracy", "rrlp.sbasAccuracy",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_rrlp_sbasXg,
      { "sbasXg", "rrlp.sbasXg",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M536870912_536870911", HFILL }},
    { &hf_rrlp_sbasYg,
      { "sbasYg", "rrlp.sbasYg",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M536870912_536870911", HFILL }},
    { &hf_rrlp_sbasZg,
      { "sbasZg", "rrlp.sbasZg",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16777216_16777215", HFILL }},
    { &hf_rrlp_sbasXgDot,
      { "sbasXgDot", "rrlp.sbasXgDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M65536_65535", HFILL }},
    { &hf_rrlp_sbasYgDot,
      { "sbasYgDot", "rrlp.sbasYgDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M65536_65535", HFILL }},
    { &hf_rrlp_sbasZgDot,
      { "sbasZgDot", "rrlp.sbasZgDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M131072_131071", HFILL }},
    { &hf_rrlp_sbasXgDotDot,
      { "sbasXgDotDot", "rrlp.sbasXgDotDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M512_511", HFILL }},
    { &hf_rrlp_sbagYgDotDot,
      { "sbagYgDotDot", "rrlp.sbagYgDotDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M512_511", HFILL }},
    { &hf_rrlp_sbasZgDotDot,
      { "sbasZgDotDot", "rrlp.sbasZgDotDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M512_511", HFILL }},
    { &hf_rrlp_standardClockModelList,
      { "standardClockModelList", "rrlp.standardClockModelList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfStandardClockModelElement", HFILL }},
    { &hf_rrlp_navClockModel,
      { "navClockModel", "rrlp.navClockModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_cnavClockModel,
      { "cnavClockModel", "rrlp.cnavClockModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_glonassClockModel,
      { "glonassClockModel", "rrlp.glonassClockModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_sbasClockModel,
      { "sbasClockModel", "rrlp.sbasClockModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_SeqOfStandardClockModelElement_item,
      { "StandardClockModelElement", "rrlp.StandardClockModelElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_stanClockToc,
      { "stanClockToc", "rrlp.stanClockToc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16383", HFILL }},
    { &hf_rrlp_stanClockAF2,
      { "stanClockAF2", "rrlp.stanClockAF2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2048_2047", HFILL }},
    { &hf_rrlp_stanClockAF1,
      { "stanClockAF1", "rrlp.stanClockAF1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M131072_131071", HFILL }},
    { &hf_rrlp_stanClockAF0,
      { "stanClockAF0", "rrlp.stanClockAF0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M134217728_134217727", HFILL }},
    { &hf_rrlp_stanClockTgd,
      { "stanClockTgd", "rrlp.stanClockTgd",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M512_511", HFILL }},
    { &hf_rrlp_stanModelID,
      { "stanModelID", "rrlp.stanModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_rrlp_navToc,
      { "navToc", "rrlp.navToc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_37799", HFILL }},
    { &hf_rrlp_navaf2,
      { "navaf2", "rrlp.navaf2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_navaf1,
      { "navaf1", "rrlp.navaf1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_navaf0,
      { "navaf0", "rrlp.navaf0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2097152_2097151", HFILL }},
    { &hf_rrlp_navTgd,
      { "navTgd", "rrlp.navTgd",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_cnavToc,
      { "cnavToc", "rrlp.cnavToc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2015", HFILL }},
    { &hf_rrlp_cnavURA0,
      { "cnavURA0", "rrlp.cnavURA0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_cnavURA1,
      { "cnavURA1", "rrlp.cnavURA1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_cnavURA2,
      { "cnavURA2", "rrlp.cnavURA2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_cnavAf2,
      { "cnavAf2", "rrlp.cnavAf2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M512_511", HFILL }},
    { &hf_rrlp_cnavAf1,
      { "cnavAf1", "rrlp.cnavAf1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M524288_524287", HFILL }},
    { &hf_rrlp_cnavAf0,
      { "cnavAf0", "rrlp.cnavAf0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M33554432_33554431", HFILL }},
    { &hf_rrlp_cnavTgd,
      { "cnavTgd", "rrlp.cnavTgd",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M4096_4095", HFILL }},
    { &hf_rrlp_cnavISCl1cp,
      { "cnavISCl1cp", "rrlp.cnavISCl1cp",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M4096_4095", HFILL }},
    { &hf_rrlp_cnavISCl1cd,
      { "cnavISCl1cd", "rrlp.cnavISCl1cd",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M4096_4095", HFILL }},
    { &hf_rrlp_cnavISCl1ca,
      { "cnavISCl1ca", "rrlp.cnavISCl1ca",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M4096_4095", HFILL }},
    { &hf_rrlp_cnavISCl2c,
      { "cnavISCl2c", "rrlp.cnavISCl2c",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M4096_4095", HFILL }},
    { &hf_rrlp_cnavISCl5i5,
      { "cnavISCl5i5", "rrlp.cnavISCl5i5",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M4096_4095", HFILL }},
    { &hf_rrlp_cnavISCl5q5,
      { "cnavISCl5q5", "rrlp.cnavISCl5q5",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M4096_4095", HFILL }},
    { &hf_rrlp_gloTau,
      { "gloTau", "rrlp.gloTau",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2097152_2097151", HFILL }},
    { &hf_rrlp_gloGamma,
      { "gloGamma", "rrlp.gloGamma",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_gloDeltaTau,
      { "gloDeltaTau", "rrlp.gloDeltaTau",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_sbasAgfo,
      { "sbasAgfo", "rrlp.sbasAgfo",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2048_2047", HFILL }},
    { &hf_rrlp_sbasAgf1,
      { "sbasAgf1", "rrlp.sbasAgf1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_ganssBadSignalList,
      { "ganssBadSignalList", "rrlp.ganssBadSignalList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfBadSignalElement", HFILL }},
    { &hf_rrlp_SeqOfBadSignalElement_item,
      { "BadSignalElement", "rrlp.BadSignalElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_badSVID,
      { "badSVID", "rrlp.badSVID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SVID", HFILL }},
    { &hf_rrlp_badSignalID,
      { "badSignalID", "rrlp.badSignalID",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GANSSSignals", HFILL }},
    { &hf_rrlp_ganssTOD_01,
      { "ganssTOD", "rrlp.ganssTOD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_59", HFILL }},
    { &hf_rrlp_ganssDataBitsSatList,
      { "ganssDataBitsSatList", "rrlp.ganssDataBitsSatList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGanssDataBitsElement", HFILL }},
    { &hf_rrlp_SeqOfGanssDataBitsElement_item,
      { "GanssDataBitsElement", "rrlp.GanssDataBitsElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssDataBitsSgnList,
      { "ganssDataBitsSgnList", "rrlp.ganssDataBitsSgnList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Seq_OfGANSSDataBitsSgn", HFILL }},
    { &hf_rrlp_Seq_OfGANSSDataBitsSgn_item,
      { "GANSSDataBitsSgnElement", "rrlp.GANSSDataBitsSgnElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssSignalType,
      { "ganssSignalType", "rrlp.ganssSignalType",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSSSignalID", HFILL }},
    { &hf_rrlp_ganssDataBits,
      { "ganssDataBits", "rrlp.ganssDataBits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOf_GANSSDataBits", HFILL }},
    { &hf_rrlp_SeqOf_GANSSDataBits_item,
      { "GANSSDataBit", "rrlp.GANSSDataBit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssRefMeasAssistList,
      { "ganssRefMeasAssistList", "rrlp.ganssRefMeasAssistList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGANSSRefMeasurementElement", HFILL }},
    { &hf_rrlp_SeqOfGANSSRefMeasurementElement_item,
      { "GANSSRefMeasurementElement", "rrlp.GANSSRefMeasurementElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_additionalDoppler,
      { "additionalDoppler", "rrlp.additionalDoppler_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AdditionalDopplerFields", HFILL }},
    { &hf_rrlp_intCodePhase_01,
      { "intCodePhase", "rrlp.intCodePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_rrlp_codePhaseSearchWindow_01,
      { "codePhaseSearchWindow", "rrlp.codePhaseSearchWindow",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_rrlp_additionalAngle,
      { "additionalAngle", "rrlp.additionalAngle_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddionalAngleFields", HFILL }},
    { &hf_rrlp_dopplerUncertainty_01,
      { "dopplerUncertainty", "rrlp.dopplerUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_4", HFILL }},
    { &hf_rrlp_GANSSRefMeasurementAssist_R10_Ext_item,
      { "GANSSRefMeasurement-R10-Ext-Element", "rrlp.GANSSRefMeasurement_R10_Ext_Element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_azimuthLSB,
      { "azimuthLSB", "rrlp.azimuthLSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_rrlp_elevationLSB,
      { "elevationLSB", "rrlp.elevationLSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_rrlp_weekNumber_01,
      { "weekNumber", "rrlp.weekNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_rrlp_toa,
      { "toa", "rrlp.toa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_rrlp_ioda,
      { "ioda", "rrlp.ioda",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_rrlp_ganssAlmanacList,
      { "ganssAlmanacList", "rrlp.ganssAlmanacList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGANSSAlmanacElement", HFILL }},
    { &hf_rrlp_SeqOfGANSSAlmanacElement_item,
      { "GANSSAlmanacElement", "rrlp.GANSSAlmanacElement",
        FT_UINT32, BASE_DEC, VALS(rrlp_GANSSAlmanacElement_vals), 0,
        NULL, HFILL }},
    { &hf_rrlp_keplerianAlmanacSet,
      { "keplerianAlmanacSet", "rrlp.keplerianAlmanacSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Almanac_KeplerianSet", HFILL }},
    { &hf_rrlp_keplerianNAVAlmanac,
      { "keplerianNAVAlmanac", "rrlp.keplerianNAVAlmanac_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Almanac_NAVKeplerianSet", HFILL }},
    { &hf_rrlp_keplerianReducedAlmanac,
      { "keplerianReducedAlmanac", "rrlp.keplerianReducedAlmanac_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Almanac_ReducedKeplerianSet", HFILL }},
    { &hf_rrlp_keplerianMidiAlmanac,
      { "keplerianMidiAlmanac", "rrlp.keplerianMidiAlmanac_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Almanac_MidiAlmanacSet", HFILL }},
    { &hf_rrlp_keplerianGLONASS,
      { "keplerianGLONASS", "rrlp.keplerianGLONASS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Almanac_GlonassAlmanacSet", HFILL }},
    { &hf_rrlp_ecefSBASAlmanac,
      { "ecefSBASAlmanac", "rrlp.ecefSBASAlmanac_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Almanac_ECEFsbasAlmanacSet", HFILL }},
    { &hf_rrlp_kepAlmanacE,
      { "kepAlmanacE", "rrlp.kepAlmanacE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2047", HFILL }},
    { &hf_rrlp_kepAlmanacDeltaI,
      { "kepAlmanacDeltaI", "rrlp.kepAlmanacDeltaI",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_kepAlmanacOmegaDot,
      { "kepAlmanacOmegaDot", "rrlp.kepAlmanacOmegaDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_kepSVHealth,
      { "kepSVHealth", "rrlp.kepSVHealth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_15", HFILL }},
    { &hf_rrlp_kepAlmanacAPowerHalf,
      { "kepAlmanacAPowerHalf", "rrlp.kepAlmanacAPowerHalf",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M65536_65535", HFILL }},
    { &hf_rrlp_kepAlmanacOmega0,
      { "kepAlmanacOmega0", "rrlp.kepAlmanacOmega0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_kepAlmanacW,
      { "kepAlmanacW", "rrlp.kepAlmanacW",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_kepAlmanacM0,
      { "kepAlmanacM0", "rrlp.kepAlmanacM0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_kepAlmanacAF0,
      { "kepAlmanacAF0", "rrlp.kepAlmanacAF0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8192_8191", HFILL }},
    { &hf_rrlp_kepAlmanacAF1,
      { "kepAlmanacAF1", "rrlp.kepAlmanacAF1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_navAlmE,
      { "navAlmE", "rrlp.navAlmE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_rrlp_navAlmDeltaI,
      { "navAlmDeltaI", "rrlp.navAlmDeltaI",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_navAlmOMEGADOT,
      { "navAlmOMEGADOT", "rrlp.navAlmOMEGADOT",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_navAlmSVHealth,
      { "navAlmSVHealth", "rrlp.navAlmSVHealth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_rrlp_navAlmSqrtA,
      { "navAlmSqrtA", "rrlp.navAlmSqrtA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16777215", HFILL }},
    { &hf_rrlp_navAlmOMEGAo,
      { "navAlmOMEGAo", "rrlp.navAlmOMEGAo",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_navAlmOmega,
      { "navAlmOmega", "rrlp.navAlmOmega",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_navAlmMo,
      { "navAlmMo", "rrlp.navAlmMo",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_navAlmaf0,
      { "navAlmaf0", "rrlp.navAlmaf0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_navAlmaf1,
      { "navAlmaf1", "rrlp.navAlmaf1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_redAlmDeltaA,
      { "redAlmDeltaA", "rrlp.redAlmDeltaA",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_redAlmOmega0,
      { "redAlmOmega0", "rrlp.redAlmOmega0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M64_63", HFILL }},
    { &hf_rrlp_redAlmPhi0,
      { "redAlmPhi0", "rrlp.redAlmPhi0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M64_63", HFILL }},
    { &hf_rrlp_redAlmL1Health,
      { "redAlmL1Health", "rrlp.redAlmL1Health",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_rrlp_redAlmL2Health,
      { "redAlmL2Health", "rrlp.redAlmL2Health",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_rrlp_redAlmL5Health,
      { "redAlmL5Health", "rrlp.redAlmL5Health",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_rrlp_midiAlmE,
      { "midiAlmE", "rrlp.midiAlmE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2047", HFILL }},
    { &hf_rrlp_midiAlmDeltaI,
      { "midiAlmDeltaI", "rrlp.midiAlmDeltaI",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_midiAlmOmegaDot,
      { "midiAlmOmegaDot", "rrlp.midiAlmOmegaDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_midiAlmSqrtA,
      { "midiAlmSqrtA", "rrlp.midiAlmSqrtA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_131071", HFILL }},
    { &hf_rrlp_midiAlmOmega0,
      { "midiAlmOmega0", "rrlp.midiAlmOmega0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_midiAlmOmega,
      { "midiAlmOmega", "rrlp.midiAlmOmega",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_midiAlmMo,
      { "midiAlmMo", "rrlp.midiAlmMo",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_midiAlmaf0,
      { "midiAlmaf0", "rrlp.midiAlmaf0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_midiAlmaf1,
      { "midiAlmaf1", "rrlp.midiAlmaf1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M512_511", HFILL }},
    { &hf_rrlp_midiAlmL1Health,
      { "midiAlmL1Health", "rrlp.midiAlmL1Health",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_rrlp_midiAlmL2Health,
      { "midiAlmL2Health", "rrlp.midiAlmL2Health",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_rrlp_midiAlmL5Health,
      { "midiAlmL5Health", "rrlp.midiAlmL5Health",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_rrlp_gloAlmNA,
      { "gloAlmNA", "rrlp.gloAlmNA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1461", HFILL }},
    { &hf_rrlp_gloAlmnA,
      { "gloAlmnA", "rrlp.gloAlmnA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_24", HFILL }},
    { &hf_rrlp_gloAlmHA,
      { "gloAlmHA", "rrlp.gloAlmHA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_31", HFILL }},
    { &hf_rrlp_gloAlmLambdaA,
      { "gloAlmLambdaA", "rrlp.gloAlmLambdaA",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1048576_1048575", HFILL }},
    { &hf_rrlp_gloAlmtlambdaA,
      { "gloAlmtlambdaA", "rrlp.gloAlmtlambdaA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2097151", HFILL }},
    { &hf_rrlp_gloAlmDeltaIa,
      { "gloAlmDeltaIa", "rrlp.gloAlmDeltaIa",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M131072_131071", HFILL }},
    { &hf_rrlp_gloAlmDeltaTA,
      { "gloAlmDeltaTA", "rrlp.gloAlmDeltaTA",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2097152_2097151", HFILL }},
    { &hf_rrlp_gloAlmDeltaTdotA,
      { "gloAlmDeltaTdotA", "rrlp.gloAlmDeltaTdotA",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M64_63", HFILL }},
    { &hf_rrlp_gloAlmEpsilonA,
      { "gloAlmEpsilonA", "rrlp.gloAlmEpsilonA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_32767", HFILL }},
    { &hf_rrlp_gloAlmOmegaA,
      { "gloAlmOmegaA", "rrlp.gloAlmOmegaA",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_gloAlmTauA,
      { "gloAlmTauA", "rrlp.gloAlmTauA",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M512_511", HFILL }},
    { &hf_rrlp_gloAlmCA,
      { "gloAlmCA", "rrlp.gloAlmCA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_rrlp_gloAlmMA,
      { "gloAlmMA", "rrlp.gloAlmMA",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_rrlp_sbasAlmDataID,
      { "sbasAlmDataID", "rrlp.sbasAlmDataID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_rrlp_sbasAlmHealth,
      { "sbasAlmHealth", "rrlp.sbasAlmHealth",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_8", HFILL }},
    { &hf_rrlp_sbasAlmXg,
      { "sbasAlmXg", "rrlp.sbasAlmXg",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16384_16383", HFILL }},
    { &hf_rrlp_sbasAlmYg,
      { "sbasAlmYg", "rrlp.sbasAlmYg",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16384_16383", HFILL }},
    { &hf_rrlp_sbasAlmZg,
      { "sbasAlmZg", "rrlp.sbasAlmZg",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M256_255", HFILL }},
    { &hf_rrlp_sbasAlmXgdot,
      { "sbasAlmXgdot", "rrlp.sbasAlmXgdot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M4_3", HFILL }},
    { &hf_rrlp_sbasAlmYgDot,
      { "sbasAlmYgDot", "rrlp.sbasAlmYgDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M4_3", HFILL }},
    { &hf_rrlp_sbasAlmZgDot,
      { "sbasAlmZgDot", "rrlp.sbasAlmZgDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8_7", HFILL }},
    { &hf_rrlp_sbasAlmTo,
      { "sbasAlmTo", "rrlp.sbasAlmTo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2047", HFILL }},
    { &hf_rrlp_completeAlmanacProvided,
      { "completeAlmanacProvided", "rrlp.completeAlmanacProvided",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_rrlp_ganssUtcA1,
      { "ganssUtcA1", "rrlp.ganssUtcA1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_ganssUtcA0,
      { "ganssUtcA0", "rrlp.ganssUtcA0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_ganssUtcTot,
      { "ganssUtcTot", "rrlp.ganssUtcTot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_rrlp_ganssUtcWNt,
      { "ganssUtcWNt", "rrlp.ganssUtcWNt",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_rrlp_ganssUtcDeltaTls,
      { "ganssUtcDeltaTls", "rrlp.ganssUtcDeltaTls",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_ganssUtcWNlsf,
      { "ganssUtcWNlsf", "rrlp.ganssUtcWNlsf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_rrlp_ganssUtcDN,
      { "ganssUtcDN", "rrlp.ganssUtcDN",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_ganssUtcDeltaTlsf,
      { "ganssUtcDeltaTlsf", "rrlp.ganssUtcDeltaTlsf",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_ganssEphemerisHeader,
      { "ganssEphemerisHeader", "rrlp.ganssEphemerisHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSEphemerisExtensionHeader", HFILL }},
    { &hf_rrlp_ganssReferenceSet,
      { "ganssReferenceSet", "rrlp.ganssReferenceSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGANSSRefOrbit", HFILL }},
    { &hf_rrlp_ganssephemerisDeltasMatrix,
      { "ganssephemerisDeltasMatrix", "rrlp.ganssephemerisDeltasMatrix",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSSEphemerisDeltaMatrix", HFILL }},
    { &hf_rrlp_timeAtEstimation,
      { "timeAtEstimation", "rrlp.timeAtEstimation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSEphemerisExtensionTime", HFILL }},
    { &hf_rrlp_validityPeriod,
      { "validityPeriod", "rrlp.validityPeriod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8", HFILL }},
    { &hf_rrlp_ephemerisExtensionDuration,
      { "ephemerisExtensionDuration", "rrlp.ephemerisExtensionDuration",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_512", HFILL }},
    { &hf_rrlp_ganssEphExtDay,
      { "ganssEphExtDay", "rrlp.ganssEphExtDay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_rrlp_ganssEphExtTOD,
      { "ganssEphExtTOD", "rrlp.ganssEphExtTOD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSSTOD", HFILL }},
    { &hf_rrlp_keplerToe_01,
      { "keplerToe", "rrlp.keplerToe",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_37799", HFILL }},
    { &hf_rrlp_SeqOfGANSSRefOrbit_item,
      { "GANSSReferenceOrbit", "rrlp.GANSSReferenceOrbit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssOrbitModel_01,
      { "ganssOrbitModel", "rrlp.ganssOrbitModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReferenceNavModel", HFILL }},
    { &hf_rrlp_GANSSEphemerisDeltaMatrix_item,
      { "GANSSEphemerisDeltaEpoch", "rrlp.GANSSEphemerisDeltaEpoch_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssDeltaEpochHeader,
      { "ganssDeltaEpochHeader", "rrlp.ganssDeltaEpochHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssDeltaElementList,
      { "ganssDeltaElementList", "rrlp.ganssDeltaElementList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ephemerisDeltaSizes,
      { "ephemerisDeltaSizes", "rrlp.ephemerisDeltaSizes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSEphemerisDeltaBitSizes", HFILL }},
    { &hf_rrlp_ephemerisDeltaScales,
      { "ephemerisDeltaScales", "rrlp.ephemerisDeltaScales_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSEphemerisDeltaScales", HFILL }},
    { &hf_rrlp_GANSSDeltaElementList_item,
      { "GANSSDeltaElementList item", "rrlp.GANSSDeltaElementList_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_49", HFILL }},
    { &hf_rrlp_bitsize_delta_omega,
      { "bitsize-delta-omega", "rrlp.bitsize_delta_omega",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_rrlp_bitsize_delta_deltaN,
      { "bitsize-delta-deltaN", "rrlp.bitsize_delta_deltaN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16", HFILL }},
    { &hf_rrlp_bitsize_delta_m0,
      { "bitsize-delta-m0", "rrlp.bitsize_delta_m0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_rrlp_bitsize_delta_omegadot,
      { "bitsize-delta-omegadot", "rrlp.bitsize_delta_omegadot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_24", HFILL }},
    { &hf_rrlp_bitsize_delta_e,
      { "bitsize-delta-e", "rrlp.bitsize_delta_e",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_rrlp_bitsize_delta_idot,
      { "bitsize-delta-idot", "rrlp.bitsize_delta_idot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_14", HFILL }},
    { &hf_rrlp_bitsize_delta_sqrtA,
      { "bitsize-delta-sqrtA", "rrlp.bitsize_delta_sqrtA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_rrlp_bitsize_delta_i0,
      { "bitsize-delta-i0", "rrlp.bitsize_delta_i0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_rrlp_bitsize_delta_omega0,
      { "bitsize-delta-omega0", "rrlp.bitsize_delta_omega0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_32", HFILL }},
    { &hf_rrlp_bitsize_delta_crs,
      { "bitsize-delta-crs", "rrlp.bitsize_delta_crs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16", HFILL }},
    { &hf_rrlp_bitsize_delta_cis,
      { "bitsize-delta-cis", "rrlp.bitsize_delta_cis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16", HFILL }},
    { &hf_rrlp_bitsize_delta_cus,
      { "bitsize-delta-cus", "rrlp.bitsize_delta_cus",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16", HFILL }},
    { &hf_rrlp_bitsize_delta_crc,
      { "bitsize-delta-crc", "rrlp.bitsize_delta_crc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16", HFILL }},
    { &hf_rrlp_bitsize_delta_cic,
      { "bitsize-delta-cic", "rrlp.bitsize_delta_cic",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16", HFILL }},
    { &hf_rrlp_bitsize_delta_cuc,
      { "bitsize-delta-cuc", "rrlp.bitsize_delta_cuc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_16", HFILL }},
    { &hf_rrlp_bitsize_delta_tgd1,
      { "bitsize-delta-tgd1", "rrlp.bitsize_delta_tgd1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_10", HFILL }},
    { &hf_rrlp_bitsize_delta_tgd2,
      { "bitsize-delta-tgd2", "rrlp.bitsize_delta_tgd2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_10", HFILL }},
    { &hf_rrlp_scale_delta_omega,
      { "scale-delta-omega", "rrlp.scale_delta_omega",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_deltaN,
      { "scale-delta-deltaN", "rrlp.scale_delta_deltaN",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_m0,
      { "scale-delta-m0", "rrlp.scale_delta_m0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_omegadot,
      { "scale-delta-omegadot", "rrlp.scale_delta_omegadot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_e,
      { "scale-delta-e", "rrlp.scale_delta_e",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_idot,
      { "scale-delta-idot", "rrlp.scale_delta_idot",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_sqrtA,
      { "scale-delta-sqrtA", "rrlp.scale_delta_sqrtA",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_i0,
      { "scale-delta-i0", "rrlp.scale_delta_i0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_omega0,
      { "scale-delta-omega0", "rrlp.scale_delta_omega0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_crs,
      { "scale-delta-crs", "rrlp.scale_delta_crs",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_cis,
      { "scale-delta-cis", "rrlp.scale_delta_cis",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_cus,
      { "scale-delta-cus", "rrlp.scale_delta_cus",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_crc,
      { "scale-delta-crc", "rrlp.scale_delta_crc",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_cic,
      { "scale-delta-cic", "rrlp.scale_delta_cic",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_cuc,
      { "scale-delta-cuc", "rrlp.scale_delta_cuc",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_tgd1,
      { "scale-delta-tgd1", "rrlp.scale_delta_tgd1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_scale_delta_tgd2,
      { "scale-delta-tgd2", "rrlp.scale_delta_tgd2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_ganssBeginTime,
      { "ganssBeginTime", "rrlp.ganssBeginTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSEphemerisExtensionTime", HFILL }},
    { &hf_rrlp_ganssEndTime,
      { "ganssEndTime", "rrlp.ganssEndTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GANSSEphemerisExtensionTime", HFILL }},
    { &hf_rrlp_ganssSatEventsInfo,
      { "ganssSatEventsInfo", "rrlp.ganssSatEventsInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_eventOccured,
      { "eventOccured", "rrlp.eventOccured",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_64", HFILL }},
    { &hf_rrlp_futureEventNoted,
      { "futureEventNoted", "rrlp.futureEventNoted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_64", HFILL }},
    { &hf_rrlp_utcModel2,
      { "utcModel2", "rrlp.utcModel2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UTCmodelSet2", HFILL }},
    { &hf_rrlp_utcModel3,
      { "utcModel3", "rrlp.utcModel3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UTCmodelSet3", HFILL }},
    { &hf_rrlp_utcModel4,
      { "utcModel4", "rrlp.utcModel4_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "UTCmodelSet4", HFILL }},
    { &hf_rrlp_utcA0_01,
      { "utcA0", "rrlp.utcA0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_utcA1_01,
      { "utcA1", "rrlp.utcA1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M4096_4095", HFILL }},
    { &hf_rrlp_utcA2,
      { "utcA2", "rrlp.utcA2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M64_63", HFILL }},
    { &hf_rrlp_utcTot_01,
      { "utcTot", "rrlp.utcTot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_rrlp_utcWNot,
      { "utcWNot", "rrlp.utcWNot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_8191", HFILL }},
    { &hf_rrlp_utcDN_01,
      { "utcDN", "rrlp.utcDN",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_4", HFILL }},
    { &hf_rrlp_nA,
      { "nA", "rrlp.nA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_1461", HFILL }},
    { &hf_rrlp_tauC,
      { "tauC", "rrlp.tauC",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_b1,
      { "b1", "rrlp.b1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_b2,
      { "b2", "rrlp.b2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M512_511", HFILL }},
    { &hf_rrlp_kp,
      { "kp", "rrlp.kp",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_2", HFILL }},
    { &hf_rrlp_utcA1wnt,
      { "utcA1wnt", "rrlp.utcA1wnt",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_utcA0wnt,
      { "utcA0wnt", "rrlp.utcA0wnt",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_utcStandardID,
      { "utcStandardID", "rrlp.utcStandardID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_ganssID1,
      { "ganssID1", "rrlp.ganssID1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_ID1", HFILL }},
    { &hf_rrlp_ganssID3,
      { "ganssID3", "rrlp.ganssID3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GANSS_ID3", HFILL }},
    { &hf_rrlp_GANSS_ID1_item,
      { "GANSS-ID1-element", "rrlp.GANSS_ID1_element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_signalsAvailable,
      { "signalsAvailable", "rrlp.signalsAvailable",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GANSSSignals", HFILL }},
    { &hf_rrlp_GANSS_ID3_item,
      { "GANSS-ID3-element", "rrlp.GANSS_ID3_element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_channelNumber,
      { "channelNumber", "rrlp.channelNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M7_13", HFILL }},
    { &hf_rrlp_GANSSDiffCorrectionsValidityPeriod_item,
      { "DGANSSExtensionSgnTypeElement", "rrlp.DGANSSExtensionSgnTypeElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_dganssExtensionSgnList,
      { "dganssExtensionSgnList", "rrlp.dganssExtensionSgnList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfDGANSSExtensionSgnElement", HFILL }},
    { &hf_rrlp_SeqOfDGANSSExtensionSgnElement_item,
      { "DGANSSExtensionSgnElement", "rrlp.DGANSSExtensionSgnElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_udreGrowthRate,
      { "udreGrowthRate", "rrlp.udreGrowthRate",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_udreValidityTime,
      { "udreValidityTime", "rrlp.udreValidityTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_add_GPS_controlHeader,
      { "add-GPS-controlHeader", "rrlp.add_GPS_controlHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsEphemerisExtension,
      { "gpsEphemerisExtension", "rrlp.gpsEphemerisExtension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsEphemerisExtensionCheck,
      { "gpsEphemerisExtensionCheck", "rrlp.gpsEphemerisExtensionCheck_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_dgpsCorrectionsValidityPeriod,
      { "dgpsCorrectionsValidityPeriod", "rrlp.dgpsCorrectionsValidityPeriod",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsReferenceTime_R10_Ext,
      { "gpsReferenceTime-R10-Ext", "rrlp.gpsReferenceTime_R10_Ext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsAcquisAssist_R10_Ext,
      { "gpsAcquisAssist-R10-Ext", "rrlp.gpsAcquisAssist_R10_Ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsAlmanac_R10_Ext,
      { "gpsAlmanac-R10-Ext", "rrlp.gpsAlmanac_R10_Ext_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_af2,
      { "af2", "rrlp.af2",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_af1,
      { "af1", "rrlp.af1",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_af0,
      { "af0", "rrlp.af0",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M2097152_2097151", HFILL }},
    { &hf_rrlp_tgd,
      { "tgd", "rrlp.tgd",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M128_127", HFILL }},
    { &hf_rrlp_gpsEphemerisHeader,
      { "gpsEphemerisHeader", "rrlp.gpsEphemerisHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPSEphemerisExtensionHeader", HFILL }},
    { &hf_rrlp_gpsReferenceSet,
      { "gpsReferenceSet", "rrlp.gpsReferenceSet",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGPSRefOrbit", HFILL }},
    { &hf_rrlp_gpsephemerisDeltaMatrix,
      { "gpsephemerisDeltaMatrix", "rrlp.gpsephemerisDeltaMatrix",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_timeofEstimation,
      { "timeofEstimation", "rrlp.timeofEstimation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPSEphemerisExtensionTime", HFILL }},
    { &hf_rrlp_SeqOfGPSRefOrbit_item,
      { "GPSReferenceOrbit", "rrlp.GPSReferenceOrbit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsOrbitModel,
      { "gpsOrbitModel", "rrlp.gpsOrbitModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReferenceNavModel", HFILL }},
    { &hf_rrlp_gpsClockModel,
      { "gpsClockModel", "rrlp.gpsClockModel_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_GPSEphemerisDeltaMatrix_item,
      { "GPSEphemerisDeltaEpoch", "rrlp.GPSEphemerisDeltaEpoch_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsDeltaEpochHeader,
      { "gpsDeltaEpochHeader", "rrlp.gpsDeltaEpochHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsDeltaElementList,
      { "gpsDeltaElementList", "rrlp.gpsDeltaElementList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ephemerisDeltaSizes_01,
      { "ephemerisDeltaSizes", "rrlp.ephemerisDeltaSizes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPSEphemerisDeltaBitSizes", HFILL }},
    { &hf_rrlp_ephemerisDeltaScales_01,
      { "ephemerisDeltaScales", "rrlp.ephemerisDeltaScales_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPSEphemerisDeltaScales", HFILL }},
    { &hf_rrlp_GPSDeltaElementList_item,
      { "GPSDeltaElementList item", "rrlp.GPSDeltaElementList_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_1_47", HFILL }},
    { &hf_rrlp_bitsize_delta_tgd,
      { "bitsize-delta-tgd", "rrlp.bitsize_delta_tgd",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_10", HFILL }},
    { &hf_rrlp_scale_delta_tgd,
      { "scale-delta-tgd", "rrlp.scale_delta_tgd",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER_M16_15", HFILL }},
    { &hf_rrlp_gpsBeginTime,
      { "gpsBeginTime", "rrlp.gpsBeginTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPSEphemerisExtensionTime", HFILL }},
    { &hf_rrlp_gpsEndTime,
      { "gpsEndTime", "rrlp.gpsEndTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPSEphemerisExtensionTime", HFILL }},
    { &hf_rrlp_gpsSatEventsInfo,
      { "gpsSatEventsInfo", "rrlp.gpsSatEventsInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_eventOccured_01,
      { "eventOccured", "rrlp.eventOccured",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_rrlp_futureEventNoted_01,
      { "futureEventNoted", "rrlp.futureEventNoted",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_32", HFILL }},
    { &hf_rrlp_DGPSCorrectionsValidityPeriod_item,
      { "DGPSExtensionSatElement", "rrlp.DGPSExtensionSatElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsWeekCycleNumber,
      { "gpsWeekCycleNumber", "rrlp.gpsWeekCycleNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_7", HFILL }},
    { &hf_rrlp_GPSAcquisAssist_R10_Ext_item,
      { "GPSAcquisAssist-R10-Ext-Element", "rrlp.GPSAcquisAssist_R10_Ext_Element_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_velEstimate,
      { "velEstimate", "rrlp.velEstimate",
        FT_BYTES, BASE_NONE, NULL, 0,
        "VelocityEstimate", HFILL }},
    { &hf_rrlp_ganssLocationInfo,
      { "ganssLocationInfo", "rrlp.ganssLocationInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssMeasureInfo,
      { "ganssMeasureInfo", "rrlp.ganssMeasureInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_referenceFrame,
      { "referenceFrame", "rrlp.referenceFrame_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssTODm,
      { "ganssTODm", "rrlp.ganssTODm",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssTODFrac,
      { "ganssTODFrac", "rrlp.ganssTODFrac",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_16384", HFILL }},
    { &hf_rrlp_posData,
      { "posData", "rrlp.posData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PositionData", HFILL }},
    { &hf_rrlp_stationaryIndication,
      { "stationaryIndication", "rrlp.stationaryIndication",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1", HFILL }},
    { &hf_rrlp_referenceFN,
      { "referenceFN", "rrlp.referenceFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_rrlp_referenceFNMSB,
      { "referenceFNMSB", "rrlp.referenceFNMSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_rrlp_ganssMsrSetList,
      { "ganssMsrSetList", "rrlp.ganssMsrSetList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGANSS_MsrSetElement", HFILL }},
    { &hf_rrlp_SeqOfGANSS_MsrSetElement_item,
      { "GANSS-MsrSetElement", "rrlp.GANSS_MsrSetElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_deltaGANSSTOD,
      { "deltaGANSSTOD", "rrlp.deltaGANSSTOD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_rrlp_ganss_MsrElementList,
      { "ganss-MsrElementList", "rrlp.ganss_MsrElementList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGANSS_MsrElement", HFILL }},
    { &hf_rrlp_SeqOfGANSS_MsrElement_item,
      { "GANSS-MsrElement", "rrlp.GANSS_MsrElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganss_SgnTypeList,
      { "ganss-SgnTypeList", "rrlp.ganss_SgnTypeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGANSS_SgnTypeElement", HFILL }},
    { &hf_rrlp_SeqOfGANSS_SgnTypeElement_item,
      { "GANSS-SgnTypeElement", "rrlp.GANSS_SgnTypeElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssCodePhaseAmbiguity,
      { "ganssCodePhaseAmbiguity", "rrlp.ganssCodePhaseAmbiguity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_rrlp_ganss_SgnList,
      { "ganss-SgnList", "rrlp.ganss_SgnList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOfGANSS_SgnElement", HFILL }},
    { &hf_rrlp_SeqOfGANSS_SgnElement_item,
      { "GANSS-SgnElement", "rrlp.GANSS_SgnElement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_mpathDet,
      { "mpathDet", "rrlp.mpathDet",
        FT_UINT32, BASE_DEC, VALS(rrlp_MpathIndic_vals), 0,
        "MpathIndic", HFILL }},
    { &hf_rrlp_carrierQualityInd,
      { "carrierQualityInd", "rrlp.carrierQualityInd",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_rrlp_codePhase_01,
      { "codePhase", "rrlp.codePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_2097151", HFILL }},
    { &hf_rrlp_integerCodePhase,
      { "integerCodePhase", "rrlp.integerCodePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_127", HFILL }},
    { &hf_rrlp_codePhaseRMSError,
      { "codePhaseRMSError", "rrlp.codePhaseRMSError",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_63", HFILL }},
    { &hf_rrlp_adr,
      { "adr", "rrlp.adr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_33554431", HFILL }},
    { &hf_rrlp_nonGANSSpositionMethods,
      { "nonGANSSpositionMethods", "rrlp.nonGANSSpositionMethods",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_multipleMeasurementSets,
      { "multipleMeasurementSets", "rrlp.multipleMeasurementSets",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_GANSSPositionMethods_item,
      { "GANSSPositionMethod", "rrlp.GANSSPositionMethod_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gANSSPositioningMethodTypes,
      { "gANSSPositioningMethodTypes", "rrlp.gANSSPositioningMethodTypes",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gANSSSignals,
      { "gANSSSignals", "rrlp.gANSSSignals",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_sbasID_01,
      { "sbasID", "rrlp.sbasID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gpsAssistance,
      { "gpsAssistance", "rrlp.gpsAssistance",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gANSSAssistanceSet,
      { "gANSSAssistanceSet", "rrlp.gANSSAssistanceSet_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gANSSAdditionalAssistanceChoices,
      { "gANSSAdditionalAssistanceChoices", "rrlp.gANSSAdditionalAssistanceChoices",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_commonGANSSAssistance,
      { "commonGANSSAssistance", "rrlp.commonGANSSAssistance",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_specificGANSSAssistance,
      { "specificGANSSAssistance", "rrlp.specificGANSSAssistance",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_SpecificGANSSAssistance_item,
      { "GANSSAssistanceForOneGANSS", "rrlp.GANSSAssistanceForOneGANSS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_gANSSAssistance,
      { "gANSSAssistance", "rrlp.gANSSAssistance",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_GANSSAdditionalAssistanceChoices_item,
      { "GANSSAdditionalAssistanceChoicesForOneGANSS", "rrlp.GANSSAdditionalAssistanceChoicesForOneGANSS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rrlp_ganssClockModelChoice,
      { "ganssClockModelChoice", "rrlp.ganssClockModelChoice",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GANSSModelID", HFILL }},
    { &hf_rrlp_gannsOrbitModelChoice,
      { "gannsOrbitModelChoice", "rrlp.gannsOrbitModelChoice",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GANSSModelID", HFILL }},
    { &hf_rrlp_ganssAlmanacModelChoice,
      { "ganssAlmanacModelChoice", "rrlp.ganssAlmanacModelChoice",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GANSSModelID", HFILL }},
    { &hf_rrlp_ganssAdditionalUTCModelChoice,
      { "ganssAdditionalUTCModelChoice", "rrlp.ganssAdditionalUTCModelChoice",
        FT_BYTES, BASE_NONE, NULL, 0,
        "GANSSModelID", HFILL }},
    { &hf_rrlp_GANSSPositioningMethod_gps,
      { "gps", "rrlp.GANSSPositioningMethod.gps",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_rrlp_GANSSPositioningMethod_galileo,
      { "galileo", "rrlp.GANSSPositioningMethod.galileo",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_rrlp_GANSSPositioningMethod_sbas,
      { "sbas", "rrlp.GANSSPositioningMethod.sbas",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_rrlp_GANSSPositioningMethod_modernizedGPS,
      { "modernizedGPS", "rrlp.GANSSPositioningMethod.modernizedGPS",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_rrlp_GANSSPositioningMethod_qzss,
      { "qzss", "rrlp.GANSSPositioningMethod.qzss",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_rrlp_GANSSPositioningMethod_glonass,
      { "glonass", "rrlp.GANSSPositioningMethod.glonass",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_rrlp_PositionData_e_otd,
      { "e-otd", "rrlp.PositionData.e.otd",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_rrlp_PositionData_gps,
      { "gps", "rrlp.PositionData.gps",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_rrlp_PositionData_galileo,
      { "galileo", "rrlp.PositionData.galileo",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_rrlp_PositionData_sbas,
      { "sbas", "rrlp.PositionData.sbas",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_rrlp_PositionData_modernizedGPS,
      { "modernizedGPS", "rrlp.PositionData.modernizedGPS",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_rrlp_PositionData_qzss,
      { "qzss", "rrlp.PositionData.qzss",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_rrlp_PositionData_glonass,
      { "glonass", "rrlp.PositionData.glonass",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_rrlp_NonGANSSPositionMethods_msAssistedEOTD,
      { "msAssistedEOTD", "rrlp.NonGANSSPositionMethods.msAssistedEOTD",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_rrlp_NonGANSSPositionMethods_msBasedEOTD,
      { "msBasedEOTD", "rrlp.NonGANSSPositionMethods.msBasedEOTD",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_rrlp_NonGANSSPositionMethods_msAssistedGPS,
      { "msAssistedGPS", "rrlp.NonGANSSPositionMethods.msAssistedGPS",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_rrlp_NonGANSSPositionMethods_msBasedGPS,
      { "msBasedGPS", "rrlp.NonGANSSPositionMethods.msBasedGPS",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_rrlp_NonGANSSPositionMethods_standaloneGPS,
      { "standaloneGPS", "rrlp.NonGANSSPositionMethods.standaloneGPS",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_rrlp_GANSSPositioningMethodTypes_msAssisted,
      { "msAssisted", "rrlp.GANSSPositioningMethodTypes.msAssisted",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_rrlp_GANSSPositioningMethodTypes_msBased,
      { "msBased", "rrlp.GANSSPositioningMethodTypes.msBased",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_rrlp_GANSSPositioningMethodTypes_standalone,
      { "standalone", "rrlp.GANSSPositioningMethodTypes.standalone",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_rrlp_GANSSSignals_signal1,
      { "signal1", "rrlp.GANSSSignals.signal1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_rrlp_GANSSSignals_signal2,
      { "signal2", "rrlp.GANSSSignals.signal2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_rrlp_GANSSSignals_signal3,
      { "signal3", "rrlp.GANSSSignals.signal3",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_rrlp_GANSSSignals_signal4,
      { "signal4", "rrlp.GANSSSignals.signal4",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_rrlp_GANSSSignals_signal5,
      { "signal5", "rrlp.GANSSSignals.signal5",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_rrlp_GANSSSignals_signal6,
      { "signal6", "rrlp.GANSSSignals.signal6",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_rrlp_GANSSSignals_signal7,
      { "signal7", "rrlp.GANSSSignals.signal7",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_rrlp_GANSSSignals_signal8,
      { "signal8", "rrlp.GANSSSignals.signal8",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_rrlp_SBASID_waas,
      { "waas", "rrlp.SBASID.waas",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_rrlp_SBASID_egnos,
      { "egnos", "rrlp.SBASID.egnos",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_rrlp_SBASID_masas,
      { "masas", "rrlp.SBASID.masas",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_rrlp_SBASID_gagan,
      { "gagan", "rrlp.SBASID.gagan",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_rrlp_MultipleMeasurementSets_eotd,
      { "eotd", "rrlp.MultipleMeasurementSets.eotd",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_rrlp_MultipleMeasurementSets_gps,
      { "gps", "rrlp.MultipleMeasurementSets.gps",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_rrlp_MultipleMeasurementSets_ganss,
      { "ganss", "rrlp.MultipleMeasurementSets.ganss",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_rrlp_GPSAssistance_almanac,
      { "almanac", "rrlp.GPSAssistance.almanac",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_rrlp_GPSAssistance_uTCmodel,
      { "uTCmodel", "rrlp.GPSAssistance.uTCmodel",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_rrlp_GPSAssistance_ionosphericModel,
      { "ionosphericModel", "rrlp.GPSAssistance.ionosphericModel",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_rrlp_GPSAssistance_navigationmodel,
      { "navigationmodel", "rrlp.GPSAssistance.navigationmodel",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_rrlp_GPSAssistance_dGPScorrections,
      { "dGPScorrections", "rrlp.GPSAssistance.dGPScorrections",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_rrlp_GPSAssistance_referenceLocation,
      { "referenceLocation", "rrlp.GPSAssistance.referenceLocation",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_rrlp_GPSAssistance_referenceTime,
      { "referenceTime", "rrlp.GPSAssistance.referenceTime",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_rrlp_GPSAssistance_acquisitionAssistance,
      { "acquisitionAssistance", "rrlp.GPSAssistance.acquisitionAssistance",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_rrlp_GPSAssistance_realTimeIntegrity,
      { "realTimeIntegrity", "rrlp.GPSAssistance.realTimeIntegrity",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_rrlp_GPSAssistance_ephemerisExtension,
      { "ephemerisExtension", "rrlp.GPSAssistance.ephemerisExtension",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_rrlp_GPSAssistance_ephemerisExtensionCheck,
      { "ephemerisExtensionCheck", "rrlp.GPSAssistance.ephemerisExtensionCheck",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_rrlp_CommonGANSSAssistance_referenceTime,
      { "referenceTime", "rrlp.CommonGANSSAssistance.referenceTime",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_rrlp_CommonGANSSAssistance_referenceLocation,
      { "referenceLocation", "rrlp.CommonGANSSAssistance.referenceLocation",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_rrlp_CommonGANSSAssistance_spare_bit2,
      { "spare_bit2", "rrlp.CommonGANSSAssistance.spare.bit2",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_rrlp_CommonGANSSAssistance_ionosphericModel,
      { "ionosphericModel", "rrlp.CommonGANSSAssistance.ionosphericModel",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_rrlp_CommonGANSSAssistance_addIonosphericModel,
      { "addIonosphericModel", "rrlp.CommonGANSSAssistance.addIonosphericModel",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_rrlp_CommonGANSSAssistance_earthOrientationParam,
      { "earthOrientationParam", "rrlp.CommonGANSSAssistance.earthOrientationParam",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_rrlp_GANSSAssistance_realTimeIntegrity,
      { "realTimeIntegrity", "rrlp.GANSSAssistance.realTimeIntegrity",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_rrlp_GANSSAssistance_differentialCorrections,
      { "differentialCorrections", "rrlp.GANSSAssistance.differentialCorrections",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_rrlp_GANSSAssistance_almanac,
      { "almanac", "rrlp.GANSSAssistance.almanac",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_rrlp_GANSSAssistance_referenceMeasurementInformation,
      { "referenceMeasurementInformation", "rrlp.GANSSAssistance.referenceMeasurementInformation",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_rrlp_GANSSAssistance_navigationModel,
      { "navigationModel", "rrlp.GANSSAssistance.navigationModel",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_rrlp_GANSSAssistance_timeModelGNSS_UTC,
      { "timeModelGNSS-UTC", "rrlp.GANSSAssistance.timeModelGNSS.UTC",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_rrlp_GANSSAssistance_timeModelGNSS_GNSS,
      { "timeModelGNSS-GNSS", "rrlp.GANSSAssistance.timeModelGNSS.GNSS",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_rrlp_GANSSAssistance_databitassistance,
      { "databitassistance", "rrlp.GANSSAssistance.databitassistance",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_rrlp_GANSSAssistance_ephemerisExtension,
      { "ephemerisExtension", "rrlp.GANSSAssistance.ephemerisExtension",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_rrlp_GANSSAssistance_ephemerisExtensionCheck,
      { "ephemerisExtensionCheck", "rrlp.GANSSAssistance.ephemerisExtensionCheck",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_rrlp_GANSSAssistance_addUTCmodel,
      { "addUTCmodel", "rrlp.GANSSAssistance.addUTCmodel",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_rrlp_GANSSAssistance_auxiliaryInformation,
      { "auxiliaryInformation", "rrlp.GANSSAssistance.auxiliaryInformation",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_rrlp_GANSSModelID_model1,
      { "model1", "rrlp.GANSSModelID.model1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_rrlp_GANSSModelID_model2,
      { "model2", "rrlp.GANSSModelID.model2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_rrlp_GANSSModelID_model3,
      { "model3", "rrlp.GANSSModelID.model3",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_rrlp_GANSSModelID_model4,
      { "model4", "rrlp.GANSSModelID.model4",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_rrlp_GANSSModelID_model5,
      { "model5", "rrlp.GANSSModelID.model5",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_rrlp_GANSSModelID_model6,
      { "model6", "rrlp.GANSSModelID.model6",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_rrlp_GANSSModelID_model7,
      { "model7", "rrlp.GANSSModelID.model7",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_rrlp_GANSSModelID_model8,
      { "model8", "rrlp.GANSSModelID.model8",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
	  &ett_rrlp,
    &ett_rrlp_ExtensionContainer,
    &ett_rrlp_PrivateExtensionList,
    &ett_rrlp_PrivateExtension,
    &ett_rrlp_PCS_Extensions,
    &ett_rrlp_PDU,
    &ett_rrlp_RRLP_Component,
    &ett_rrlp_MsrPosition_Req,
    &ett_rrlp_MsrPosition_Rsp,
    &ett_rrlp_AssistanceData,
    &ett_rrlp_ProtocolError,
    &ett_rrlp_PosCapability_Req,
    &ett_rrlp_PosCapability_Rsp,
    &ett_rrlp_PositionInstruct,
    &ett_rrlp_MethodType,
    &ett_rrlp_AccuracyOpt,
    &ett_rrlp_ReferenceAssistData,
    &ett_rrlp_MsrAssistData,
    &ett_rrlp_SeqOfMsrAssistBTS,
    &ett_rrlp_MsrAssistBTS,
    &ett_rrlp_SystemInfoAssistData,
    &ett_rrlp_SeqOfSystemInfoAssistBTS,
    &ett_rrlp_SystemInfoAssistBTS,
    &ett_rrlp_AssistBTSData,
    &ett_rrlp_CalcAssistanceBTS,
    &ett_rrlp_ReferenceWGS84,
    &ett_rrlp_MultipleSets,
    &ett_rrlp_ReferenceIdentity,
    &ett_rrlp_SeqOfReferenceIdentityType,
    &ett_rrlp_ReferenceIdentityType,
    &ett_rrlp_BSICAndCarrier,
    &ett_rrlp_CellIDAndLAC,
    &ett_rrlp_OTD_MeasureInfo,
    &ett_rrlp_SeqOfOTD_MsrElementRest,
    &ett_rrlp_OTD_MsrElementFirst,
    &ett_rrlp_SeqOfOTD_FirstSetMsrs,
    &ett_rrlp_OTD_MsrElementRest,
    &ett_rrlp_SeqOfOTD_MsrsOfOtherSets,
    &ett_rrlp_TOA_MeasurementsOfRef,
    &ett_rrlp_OTD_MsrsOfOtherSets,
    &ett_rrlp_OTD_Measurement,
    &ett_rrlp_OTD_MeasurementWithID,
    &ett_rrlp_EOTDQuality,
    &ett_rrlp_NeighborIdentity,
    &ett_rrlp_MultiFrameCarrier,
    &ett_rrlp_LocationInfo,
    &ett_rrlp_GPS_MeasureInfo,
    &ett_rrlp_SeqOfGPS_MsrSetElement,
    &ett_rrlp_GPS_MsrSetElement,
    &ett_rrlp_SeqOfGPS_MsrElement,
    &ett_rrlp_GPS_MsrElement,
    &ett_rrlp_LocationError,
    &ett_rrlp_AdditionalAssistanceData,
    &ett_rrlp_GPS_AssistData,
    &ett_rrlp_ControlHeader,
    &ett_rrlp_ReferenceTime,
    &ett_rrlp_GPSTime,
    &ett_rrlp_GPSTOWAssist,
    &ett_rrlp_GPSTOWAssistElement,
    &ett_rrlp_GSMTime,
    &ett_rrlp_RefLocation,
    &ett_rrlp_DGPSCorrections,
    &ett_rrlp_SeqOfSatElement,
    &ett_rrlp_SatElement,
    &ett_rrlp_NavigationModel,
    &ett_rrlp_SeqOfNavModelElement,
    &ett_rrlp_NavModelElement,
    &ett_rrlp_SatStatus,
    &ett_rrlp_UncompressedEphemeris,
    &ett_rrlp_EphemerisSubframe1Reserved,
    &ett_rrlp_IonosphericModel,
    &ett_rrlp_UTCModel,
    &ett_rrlp_Almanac,
    &ett_rrlp_SeqOfAlmanacElement,
    &ett_rrlp_AlmanacElement,
    &ett_rrlp_AcquisAssist,
    &ett_rrlp_SeqOfAcquisElement,
    &ett_rrlp_TimeRelation,
    &ett_rrlp_AcquisElement,
    &ett_rrlp_AddionalDopplerFields,
    &ett_rrlp_AddionalAngleFields,
    &ett_rrlp_SeqOf_BadSatelliteSet,
    &ett_rrlp_Rel98_MsrPosition_Req_Extension,
    &ett_rrlp_Rel98_AssistanceData_Extension,
    &ett_rrlp_Rel98_Ext_ExpOTD,
    &ett_rrlp_MsrAssistData_R98_ExpOTD,
    &ett_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD,
    &ett_rrlp_MsrAssistBTS_R98_ExpOTD,
    &ett_rrlp_SystemInfoAssistData_R98_ExpOTD,
    &ett_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD,
    &ett_rrlp_SystemInfoAssistBTS_R98_ExpOTD,
    &ett_rrlp_AssistBTSData_R98_ExpOTD,
    &ett_rrlp_GPSTimeAssistanceMeasurements,
    &ett_rrlp_Rel_98_MsrPosition_Rsp_Extension,
    &ett_rrlp_T_rel_98_Ext_MeasureInfo,
    &ett_rrlp_OTD_MeasureInfo_R98_Ext,
    &ett_rrlp_OTD_MsrElementFirst_R98_Ext,
    &ett_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext,
    &ett_rrlp_Rel_5_MsrPosition_Rsp_Extension,
    &ett_rrlp_Extended_reference,
    &ett_rrlp_Rel5_MsrPosition_Req_Extension,
    &ett_rrlp_Rel5_AssistanceData_Extension,
    &ett_rrlp_Rel_5_ProtocolError_Extension,
    &ett_rrlp_Rel7_MsrPosition_Req_Extension,
    &ett_rrlp_GANSSPositioningMethod,
    &ett_rrlp_GANSS_AssistData,
    &ett_rrlp_GANSS_ControlHeader,
    &ett_rrlp_GANSSCommonAssistData,
    &ett_rrlp_SeqOfGANSSGenericAssistDataElement,
    &ett_rrlp_GANSSGenericAssistDataElement,
    &ett_rrlp_GANSSReferenceTime,
    &ett_rrlp_GANSSRefTimeInfo,
    &ett_rrlp_GANSSReferenceTime_R10_Ext,
    &ett_rrlp_GANSSTOD_GSMTimeAssociation,
    &ett_rrlp_GANSSRefLocation,
    &ett_rrlp_GANSSIonosphericModel,
    &ett_rrlp_GANSSIonosphereModel,
    &ett_rrlp_GANSSIonoStormFlags,
    &ett_rrlp_GANSSAddIonosphericModel,
    &ett_rrlp_GANSSEarthOrientParam,
    &ett_rrlp_SeqOfGANSSTimeModel,
    &ett_rrlp_GANSSTimeModelElement,
    &ett_rrlp_SeqOfGANSSTimeModel_R10_Ext,
    &ett_rrlp_GANSSTimeModelElement_R10_Ext,
    &ett_rrlp_GANSSDiffCorrections,
    &ett_rrlp_SeqOfSgnTypeElement,
    &ett_rrlp_SgnTypeElement,
    &ett_rrlp_SeqOfDGANSSSgnElement,
    &ett_rrlp_DGANSSSgnElement,
    &ett_rrlp_GANSSNavModel,
    &ett_rrlp_SeqOfGANSSSatelliteElement,
    &ett_rrlp_GANSSSatelliteElement,
    &ett_rrlp_GANSSOrbitModel,
    &ett_rrlp_NavModel_KeplerianSet,
    &ett_rrlp_NavModel_NAVKeplerianSet,
    &ett_rrlp_NavModel_CNAVKeplerianSet,
    &ett_rrlp_NavModel_GLONASSecef,
    &ett_rrlp_NavModel_SBASecef,
    &ett_rrlp_GANSSClockModel,
    &ett_rrlp_SeqOfStandardClockModelElement,
    &ett_rrlp_StandardClockModelElement,
    &ett_rrlp_NAVclockModel,
    &ett_rrlp_CNAVclockModel,
    &ett_rrlp_GLONASSclockModel,
    &ett_rrlp_SBASclockModel,
    &ett_rrlp_GANSSRealTimeIntegrity,
    &ett_rrlp_SeqOfBadSignalElement,
    &ett_rrlp_BadSignalElement,
    &ett_rrlp_GANSSDataBitAssist,
    &ett_rrlp_SeqOfGanssDataBitsElement,
    &ett_rrlp_GanssDataBitsElement,
    &ett_rrlp_Seq_OfGANSSDataBitsSgn,
    &ett_rrlp_GANSSDataBitsSgnElement,
    &ett_rrlp_SeqOf_GANSSDataBits,
    &ett_rrlp_GANSSRefMeasurementAssist,
    &ett_rrlp_SeqOfGANSSRefMeasurementElement,
    &ett_rrlp_GANSSRefMeasurementElement,
    &ett_rrlp_AdditionalDopplerFields,
    &ett_rrlp_GANSSRefMeasurementAssist_R10_Ext,
    &ett_rrlp_GANSSRefMeasurement_R10_Ext_Element,
    &ett_rrlp_GANSSAlmanacModel,
    &ett_rrlp_SeqOfGANSSAlmanacElement,
    &ett_rrlp_GANSSAlmanacElement,
    &ett_rrlp_Almanac_KeplerianSet,
    &ett_rrlp_Almanac_NAVKeplerianSet,
    &ett_rrlp_Almanac_ReducedKeplerianSet,
    &ett_rrlp_Almanac_MidiAlmanacSet,
    &ett_rrlp_Almanac_GlonassAlmanacSet,
    &ett_rrlp_Almanac_ECEFsbasAlmanacSet,
    &ett_rrlp_GANSSAlmanacModel_R10_Ext,
    &ett_rrlp_GANSSUTCModel,
    &ett_rrlp_GANSSEphemerisExtension,
    &ett_rrlp_GANSSEphemerisExtensionHeader,
    &ett_rrlp_GANSSEphemerisExtensionTime,
    &ett_rrlp_ReferenceNavModel,
    &ett_rrlp_SeqOfGANSSRefOrbit,
    &ett_rrlp_GANSSReferenceOrbit,
    &ett_rrlp_GANSSEphemerisDeltaMatrix,
    &ett_rrlp_GANSSEphemerisDeltaEpoch,
    &ett_rrlp_GANSSDeltaEpochHeader,
    &ett_rrlp_GANSSDeltaElementList,
    &ett_rrlp_GANSSEphemerisDeltaBitSizes,
    &ett_rrlp_GANSSEphemerisDeltaScales,
    &ett_rrlp_GANSSEphemerisExtensionCheck,
    &ett_rrlp_GANSSSatEventsInfo,
    &ett_rrlp_GANSSAddUTCModel,
    &ett_rrlp_UTCmodelSet2,
    &ett_rrlp_UTCmodelSet3,
    &ett_rrlp_UTCmodelSet4,
    &ett_rrlp_GANSSAuxiliaryInformation,
    &ett_rrlp_GANSS_ID1,
    &ett_rrlp_GANSS_ID1_element,
    &ett_rrlp_GANSS_ID3,
    &ett_rrlp_GANSS_ID3_element,
    &ett_rrlp_GANSSDiffCorrectionsValidityPeriod,
    &ett_rrlp_DGANSSExtensionSgnTypeElement,
    &ett_rrlp_SeqOfDGANSSExtensionSgnElement,
    &ett_rrlp_DGANSSExtensionSgnElement,
    &ett_rrlp_Add_GPS_AssistData,
    &ett_rrlp_Add_GPS_ControlHeader,
    &ett_rrlp_GPSClockModel,
    &ett_rrlp_GPSEphemerisExtension,
    &ett_rrlp_GPSEphemerisExtensionHeader,
    &ett_rrlp_GPSEphemerisExtensionTime,
    &ett_rrlp_SeqOfGPSRefOrbit,
    &ett_rrlp_GPSReferenceOrbit,
    &ett_rrlp_GPSEphemerisDeltaMatrix,
    &ett_rrlp_GPSEphemerisDeltaEpoch,
    &ett_rrlp_GPSDeltaEpochHeader,
    &ett_rrlp_GPSDeltaElementList,
    &ett_rrlp_GPSEphemerisDeltaBitSizes,
    &ett_rrlp_GPSEphemerisDeltaScales,
    &ett_rrlp_GPSEphemerisExtensionCheck,
    &ett_rrlp_GPSSatEventsInfo,
    &ett_rrlp_DGPSCorrectionsValidityPeriod,
    &ett_rrlp_DGPSExtensionSatElement,
    &ett_rrlp_GPSReferenceTime_R10_Ext,
    &ett_rrlp_GPSAcquisAssist_R10_Ext,
    &ett_rrlp_GPSAcquisAssist_R10_Ext_Element,
    &ett_rrlp_GPSAlmanac_R10_Ext,
    &ett_rrlp_Rel_7_MsrPosition_Rsp_Extension,
    &ett_rrlp_GANSSLocationInfo,
    &ett_rrlp_PositionData,
    &ett_rrlp_ReferenceFrame,
    &ett_rrlp_GANSSMeasureInfo,
    &ett_rrlp_SeqOfGANSS_MsrSetElement,
    &ett_rrlp_GANSS_MsrSetElement,
    &ett_rrlp_SeqOfGANSS_MsrElement,
    &ett_rrlp_GANSS_MsrElement,
    &ett_rrlp_SeqOfGANSS_SgnTypeElement,
    &ett_rrlp_GANSS_SgnTypeElement,
    &ett_rrlp_SeqOfGANSS_SgnElement,
    &ett_rrlp_GANSS_SgnElement,
    &ett_rrlp_Rel7_AssistanceData_Extension,
    &ett_rrlp_PosCapabilities,
    &ett_rrlp_NonGANSSPositionMethods,
    &ett_rrlp_GANSSPositionMethods,
    &ett_rrlp_GANSSPositionMethod,
    &ett_rrlp_GANSSPositioningMethodTypes,
    &ett_rrlp_GANSSSignals,
    &ett_rrlp_SBASID,
    &ett_rrlp_MultipleMeasurementSets,
    &ett_rrlp_AssistanceSupported,
    &ett_rrlp_GPSAssistance,
    &ett_rrlp_GANSSAssistanceSet,
    &ett_rrlp_CommonGANSSAssistance,
    &ett_rrlp_SpecificGANSSAssistance,
    &ett_rrlp_GANSSAssistanceForOneGANSS,
    &ett_rrlp_GANSSAssistance,
    &ett_rrlp_GANSSAdditionalAssistanceChoices,
    &ett_rrlp_GANSSAdditionalAssistanceChoicesForOneGANSS,
    &ett_rrlp_GANSSModelID,
    &ett_rrlp_AssistanceNeeded,
  };


  /* Register protocol */
  proto_rrlp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("rrlp", dissect_PDU_PDU, proto_rrlp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_rrlp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


}


/*--- proto_reg_handoff_rrlp ---------------------------------------*/
void
proto_reg_handoff_rrlp(void)
{

}


