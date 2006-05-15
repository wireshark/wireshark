/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-rrlp.c                                                            */
/* ../../tools/asn2eth.py -u -e -p rrlp -c rrlp.cnf -s packet-rrlp-template rrlp.asn */

/* Input file: packet-rrlp-template.c */

#line 1 "packet-rrlp-template.c"
/* packet-rrlp.c
 * Routines for 3GPP Radio Resource LCS Protocol (RRLP) packet dissection
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
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
 *
 * Ref 3GPP TS 44.031 version 6.8.0 Release 6
 * http://www.3gpp.org
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-rrlp.h"

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-gsm_map.h"

#define PNAME  "Radio Resource LCS Protocol (RRLP)"
#define PSNAME "RRLP"
#define PFNAME "rrlp"

static dissector_handle_t rrlp_handle=NULL;


/* Initialize the protocol and registered fields */
static int proto_rrlp = -1;



/*--- Included file: packet-rrlp-hf.c ---*/
#line 1 "packet-rrlp-hf.c"
static int hf_rrlp_PDU_PDU = -1;                  /* PDU */
static int hf_rrlp_referenceNumber = -1;          /* INTEGER_0_7 */
static int hf_rrlp_component = -1;                /* RRLP_Component */
static int hf_rrlp_msrPositionReq = -1;           /* MsrPosition_Req */
static int hf_rrlp_msrPositionRsp = -1;           /* MsrPosition_Rsp */
static int hf_rrlp_assistanceData = -1;           /* AssistanceData */
static int hf_rrlp_assistanceDataAck = -1;        /* NULL */
static int hf_rrlp_protocolError = -1;            /* ProtocolError */
static int hf_rrlp_positionInstruct = -1;         /* PositionInstruct */
static int hf_rrlp_referenceAssistData = -1;      /* ReferenceAssistData */
static int hf_rrlp_msrAssistData = -1;            /* MsrAssistData */
static int hf_rrlp_systemInfoAssistData = -1;     /* SystemInfoAssistData */
static int hf_rrlp_gps_AssistData = -1;           /* GPS_AssistData */
static int hf_rrlp_extensionContainer = -1;       /* ExtensionContainer */
static int hf_rrlp_rel98_MsrPosition_Req_extension = -1;  /* Rel98_MsrPosition_Req_Extension */
static int hf_rrlp_rel5_MsrPosition_Req_extension = -1;  /* Rel5_MsrPosition_Req_Extension */
static int hf_rrlp_multipleSets = -1;             /* MultipleSets */
static int hf_rrlp_referenceIdentity = -1;        /* ReferenceIdentity */
static int hf_rrlp_otd_MeasureInfo = -1;          /* OTD_MeasureInfo */
static int hf_rrlp_locationInfo = -1;             /* LocationInfo */
static int hf_rrlp_gps_MeasureInfo = -1;          /* GPS_MeasureInfo */
static int hf_rrlp_locationError = -1;            /* LocationError */
static int hf_rrlp_rel_98_MsrPosition_Rsp_Extension = -1;  /* Rel_98_MsrPosition_Rsp_Extension */
static int hf_rrlp_rel_5_MsrPosition_Rsp_Extension = -1;  /* Rel_5_MsrPosition_Rsp_Extension */
static int hf_rrlp_moreAssDataToBeSent = -1;      /* MoreAssDataToBeSent */
static int hf_rrlp_rel98_AssistanceData_Extension = -1;  /* Rel98_AssistanceData_Extension */
static int hf_rrlp_rel5_AssistanceData_Extension = -1;  /* Rel5_AssistanceData_Extension */
static int hf_rrlp_errorCause = -1;               /* ErrorCodes */
static int hf_rrlp_rel_5_ProtocolError_Extension = -1;  /* Rel_5_ProtocolError_Extension */
static int hf_rrlp_methodType = -1;               /* MethodType */
static int hf_rrlp_positionMethod = -1;           /* PositionMethod */
static int hf_rrlp_measureResponseTime = -1;      /* MeasureResponseTime */
static int hf_rrlp_useMultipleSets = -1;          /* UseMultipleSets */
static int hf_rrlp_environmentCharacter = -1;     /* EnvironmentCharacter */
static int hf_rrlp_msAssisted = -1;               /* AccuracyOpt */
static int hf_rrlp_msBased = -1;                  /* Accuracy */
static int hf_rrlp_msBasedPref = -1;              /* Accuracy */
static int hf_rrlp_msAssistedPref = -1;           /* Accuracy */
static int hf_rrlp_accuracy = -1;                 /* Accuracy */
static int hf_rrlp_bcchCarrier = -1;              /* BCCHCarrier */
static int hf_rrlp_bsic = -1;                     /* BSIC */
static int hf_rrlp_timeSlotScheme = -1;           /* TimeSlotScheme */
static int hf_rrlp_btsPosition = -1;              /* BTSPosition */
static int hf_rrlp_msrAssistList = -1;            /* SeqOfMsrAssistBTS */
static int hf_rrlp_SeqOfMsrAssistBTS_item = -1;   /* MsrAssistBTS */
static int hf_rrlp_multiFrameOffset = -1;         /* MultiFrameOffset */
static int hf_rrlp_roughRTD = -1;                 /* RoughRTD */
static int hf_rrlp_calcAssistanceBTS = -1;        /* CalcAssistanceBTS */
static int hf_rrlp_systemInfoAssistList = -1;     /* SeqOfSystemInfoAssistBTS */
static int hf_rrlp_SeqOfSystemInfoAssistBTS_item = -1;  /* SystemInfoAssistBTS */
static int hf_rrlp_notPresent = -1;               /* NULL */
static int hf_rrlp_present = -1;                  /* AssistBTSData */
static int hf_rrlp_fineRTD = -1;                  /* FineRTD */
static int hf_rrlp_referenceWGS84 = -1;           /* ReferenceWGS84 */
static int hf_rrlp_relativeNorth = -1;            /* RelDistance */
static int hf_rrlp_relativeEast = -1;             /* RelDistance */
static int hf_rrlp_relativeAlt = -1;              /* RelativeAlt */
static int hf_rrlp_nbrOfSets = -1;                /* INTEGER_2_3 */
static int hf_rrlp_nbrOfReferenceBTSs = -1;       /* INTEGER_1_3 */
static int hf_rrlp_referenceRelation = -1;        /* ReferenceRelation */
static int hf_rrlp_refBTSList = -1;               /* SeqOfReferenceIdentityType */
static int hf_rrlp_SeqOfReferenceIdentityType_item = -1;  /* ReferenceIdentityType */
static int hf_rrlp_bsicAndCarrier = -1;           /* BSICAndCarrier */
static int hf_rrlp_ci = -1;                       /* CellID */
static int hf_rrlp_requestIndex = -1;             /* RequestIndex */
static int hf_rrlp_systemInfoIndex = -1;          /* SystemInfoIndex */
static int hf_rrlp_ciAndLAC = -1;                 /* CellIDAndLAC */
static int hf_rrlp_carrier = -1;                  /* BCCHCarrier */
static int hf_rrlp_referenceLAC = -1;             /* LAC */
static int hf_rrlp_referenceCI = -1;              /* CellID */
static int hf_rrlp_otdMsrFirstSets = -1;          /* OTD_MsrElementFirst */
static int hf_rrlp_otdMsrRestSets = -1;           /* SeqOfOTD_MsrElementRest */
static int hf_rrlp_SeqOfOTD_MsrElementRest_item = -1;  /* OTD_MsrElementRest */
static int hf_rrlp_refFrameNumber = -1;           /* INTEGER_0_42431 */
static int hf_rrlp_referenceTimeSlot = -1;        /* ModuloTimeSlot */
static int hf_rrlp_toaMeasurementsOfRef = -1;     /* TOA_MeasurementsOfRef */
static int hf_rrlp_stdResolution = -1;            /* StdResolution */
static int hf_rrlp_taCorrection = -1;             /* INTEGER_0_960 */
static int hf_rrlp_otd_FirstSetMsrs = -1;         /* SeqOfOTD_FirstSetMsrs */
static int hf_rrlp_SeqOfOTD_FirstSetMsrs_item = -1;  /* OTD_FirstSetMsrs */
static int hf_rrlp_otd_MsrsOfOtherSets = -1;      /* SeqOfOTD_MsrsOfOtherSets */
static int hf_rrlp_SeqOfOTD_MsrsOfOtherSets_item = -1;  /* OTD_MsrsOfOtherSets */
static int hf_rrlp_refQuality = -1;               /* RefQuality */
static int hf_rrlp_numOfMeasurements = -1;        /* NumOfMeasurements */
static int hf_rrlp_identityNotPresent = -1;       /* OTD_Measurement */
static int hf_rrlp_identityPresent = -1;          /* OTD_MeasurementWithID */
static int hf_rrlp_nborTimeSlot = -1;             /* ModuloTimeSlot */
static int hf_rrlp_eotdQuality = -1;              /* EOTDQuality */
static int hf_rrlp_otdValue = -1;                 /* OTDValue */
static int hf_rrlp_neighborIdentity = -1;         /* NeighborIdentity */
static int hf_rrlp_nbrOfMeasurements = -1;        /* INTEGER_0_7 */
static int hf_rrlp_stdOfEOTD = -1;                /* INTEGER_0_31 */
static int hf_rrlp_multiFrameCarrier = -1;        /* MultiFrameCarrier */
static int hf_rrlp_refFrame = -1;                 /* INTEGER_0_65535 */
static int hf_rrlp_gpsTOW = -1;                   /* INTEGER_0_14399999 */
static int hf_rrlp_fixType = -1;                  /* FixType */
static int hf_rrlp_posEstimate = -1;              /* Ext_GeographicalInformation */
static int hf_rrlp_gpsMsrSetList = -1;            /* SeqOfGPS_MsrSetElement */
static int hf_rrlp_SeqOfGPS_MsrSetElement_item = -1;  /* GPS_MsrSetElement */
static int hf_rrlp_gpsTOW1 = -1;                  /* GPSTOW24b */
static int hf_rrlp_gps_msrList = -1;              /* SeqOfGPS_MsrElement */
static int hf_rrlp_SeqOfGPS_MsrElement_item = -1;  /* GPS_MsrElement */
static int hf_rrlp_satelliteID = -1;              /* SatelliteID */
static int hf_rrlp_cNo = -1;                      /* INTEGER_0_63 */
static int hf_rrlp_doppler = -1;                  /* INTEGER_M32768_32767 */
static int hf_rrlp_wholeChips = -1;               /* INTEGER_0_1022 */
static int hf_rrlp_fracChips = -1;                /* INTEGER_0_1024 */
static int hf_rrlp_mpathIndic = -1;               /* MpathIndic */
static int hf_rrlp_pseuRangeRMSErr = -1;          /* INTEGER_0_63 */
static int hf_rrlp_locErrorReason = -1;           /* LocErrorReason */
static int hf_rrlp_additionalAssistanceData = -1;  /* AdditionalAssistanceData */
static int hf_rrlp_gpsAssistanceData = -1;        /* GPSAssistanceData */
static int hf_rrlp_controlHeader = -1;            /* ControlHeader */
static int hf_rrlp_referenceTime = -1;            /* ReferenceTime */
static int hf_rrlp_refLocation = -1;              /* RefLocation */
static int hf_rrlp_dgpsCorrections = -1;          /* DGPSCorrections */
static int hf_rrlp_navigationModel = -1;          /* NavigationModel */
static int hf_rrlp_ionosphericModel = -1;         /* IonosphericModel */
static int hf_rrlp_utcModel = -1;                 /* UTCModel */
static int hf_rrlp_almanac = -1;                  /* Almanac */
static int hf_rrlp_acquisAssist = -1;             /* AcquisAssist */
static int hf_rrlp_realTimeIntegrity = -1;        /* SeqOf_BadSatelliteSet */
static int hf_rrlp_gpsTime = -1;                  /* GPSTime */
static int hf_rrlp_gsmTime = -1;                  /* GSMTime */
static int hf_rrlp_gpsTowAssist = -1;             /* GPSTOWAssist */
static int hf_rrlp_gpsTOW23b = -1;                /* GPSTOW23b */
static int hf_rrlp_gpsWeek = -1;                  /* GPSWeek */
static int hf_rrlp_GPSTOWAssist_item = -1;        /* GPSTOWAssistElement */
static int hf_rrlp_tlmWord = -1;                  /* TLMWord */
static int hf_rrlp_antiSpoof = -1;                /* AntiSpoofFlag */
static int hf_rrlp_alert = -1;                    /* AlertFlag */
static int hf_rrlp_tlmRsvdBits = -1;              /* TLMReservedBits */
static int hf_rrlp_frameNumber = -1;              /* FrameNumber */
static int hf_rrlp_timeSlot = -1;                 /* TimeSlot */
static int hf_rrlp_bitNumber = -1;                /* BitNumber */
static int hf_rrlp_threeDLocation = -1;           /* Ext_GeographicalInformation */
static int hf_rrlp_gpsTOW2 = -1;                  /* INTEGER_0_604799 */
static int hf_rrlp_status = -1;                   /* INTEGER_0_7 */
static int hf_rrlp_satList = -1;                  /* SeqOfSatElement */
static int hf_rrlp_SeqOfSatElement_item = -1;     /* SatElement */
static int hf_rrlp_iode = -1;                     /* INTEGER_0_239 */
static int hf_rrlp_udre = -1;                     /* INTEGER_0_3 */
static int hf_rrlp_pseudoRangeCor = -1;           /* INTEGER_M2047_2047 */
static int hf_rrlp_rangeRateCor = -1;             /* INTEGER_M127_127 */
static int hf_rrlp_deltaPseudoRangeCor2 = -1;     /* INTEGER_M127_127 */
static int hf_rrlp_deltaRangeRateCor2 = -1;       /* INTEGER_M7_7 */
static int hf_rrlp_deltaPseudoRangeCor3 = -1;     /* INTEGER_M127_127 */
static int hf_rrlp_deltaRangeRateCor3 = -1;       /* INTEGER_M7_7 */
static int hf_rrlp_navModelList = -1;             /* SeqOfNavModelElement */
static int hf_rrlp_SeqOfNavModelElement_item = -1;  /* NavModelElement */
static int hf_rrlp_satStatus = -1;                /* SatStatus */
static int hf_rrlp_newSatelliteAndModelUC = -1;   /* UncompressedEphemeris */
static int hf_rrlp_oldSatelliteAndModel = -1;     /* NULL */
static int hf_rrlp_newNaviModelUC = -1;           /* UncompressedEphemeris */
static int hf_rrlp_ephemCodeOnL2 = -1;            /* INTEGER_0_3 */
static int hf_rrlp_ephemURA = -1;                 /* INTEGER_0_15 */
static int hf_rrlp_ephemSVhealth = -1;            /* INTEGER_0_63 */
static int hf_rrlp_ephemIODC = -1;                /* INTEGER_0_1023 */
static int hf_rrlp_ephemL2Pflag = -1;             /* INTEGER_0_1 */
static int hf_rrlp_ephemSF1Rsvd = -1;             /* EphemerisSubframe1Reserved */
static int hf_rrlp_ephemTgd = -1;                 /* INTEGER_M128_127 */
static int hf_rrlp_ephemToc = -1;                 /* INTEGER_0_37799 */
static int hf_rrlp_ephemAF2 = -1;                 /* INTEGER_M128_127 */
static int hf_rrlp_ephemAF1 = -1;                 /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemAF0 = -1;                 /* INTEGER_M2097152_2097151 */
static int hf_rrlp_ephemCrs = -1;                 /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemDeltaN = -1;              /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemM0 = -1;                  /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_ephemCuc = -1;                 /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemE = -1;                   /* INTEGER_0_4294967295 */
static int hf_rrlp_ephemCus = -1;                 /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemAPowerHalf = -1;          /* INTEGER_0_4294967295 */
static int hf_rrlp_ephemToe = -1;                 /* INTEGER_0_37799 */
static int hf_rrlp_ephemFitFlag = -1;             /* INTEGER_0_1 */
static int hf_rrlp_ephemAODA = -1;                /* INTEGER_0_31 */
static int hf_rrlp_ephemCic = -1;                 /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemOmegaA0 = -1;             /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_ephemCis = -1;                 /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemI0 = -1;                  /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_ephemCrc = -1;                 /* INTEGER_M32768_32767 */
static int hf_rrlp_ephemW = -1;                   /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_ephemOmegaADot = -1;           /* INTEGER_M8388608_8388607 */
static int hf_rrlp_ephemIDot = -1;                /* INTEGER_M8192_8191 */
static int hf_rrlp_reserved1 = -1;                /* INTEGER_0_8388607 */
static int hf_rrlp_reserved2 = -1;                /* INTEGER_0_16777215 */
static int hf_rrlp_reserved3 = -1;                /* INTEGER_0_16777215 */
static int hf_rrlp_reserved4 = -1;                /* INTEGER_0_65535 */
static int hf_rrlp_alfa0 = -1;                    /* INTEGER_M128_127 */
static int hf_rrlp_alfa1 = -1;                    /* INTEGER_M128_127 */
static int hf_rrlp_alfa2 = -1;                    /* INTEGER_M128_127 */
static int hf_rrlp_alfa3 = -1;                    /* INTEGER_M128_127 */
static int hf_rrlp_beta0 = -1;                    /* INTEGER_M128_127 */
static int hf_rrlp_beta1 = -1;                    /* INTEGER_M128_127 */
static int hf_rrlp_beta2 = -1;                    /* INTEGER_M128_127 */
static int hf_rrlp_beta3 = -1;                    /* INTEGER_M128_127 */
static int hf_rrlp_utcA1 = -1;                    /* INTEGER_M8388608_8388607 */
static int hf_rrlp_utcA0 = -1;                    /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_utcTot = -1;                   /* INTEGER_0_255 */
static int hf_rrlp_utcWNt = -1;                   /* INTEGER_0_255 */
static int hf_rrlp_utcDeltaTls = -1;              /* INTEGER_M128_127 */
static int hf_rrlp_utcWNlsf = -1;                 /* INTEGER_0_255 */
static int hf_rrlp_utcDN = -1;                    /* INTEGER_M128_127 */
static int hf_rrlp_utcDeltaTlsf = -1;             /* INTEGER_M128_127 */
static int hf_rrlp_alamanacWNa = -1;              /* INTEGER_0_255 */
static int hf_rrlp_almanacList = -1;              /* SeqOfAlmanacElement */
static int hf_rrlp_SeqOfAlmanacElement_item = -1;  /* AlmanacElement */
static int hf_rrlp_almanacE = -1;                 /* INTEGER_0_65535 */
static int hf_rrlp_alamanacToa = -1;              /* INTEGER_0_255 */
static int hf_rrlp_almanacKsii = -1;              /* INTEGER_M32768_32767 */
static int hf_rrlp_almanacOmegaDot = -1;          /* INTEGER_M32768_32767 */
static int hf_rrlp_almanacSVhealth = -1;          /* INTEGER_0_255 */
static int hf_rrlp_almanacAPowerHalf = -1;        /* INTEGER_0_16777215 */
static int hf_rrlp_almanacOmega0 = -1;            /* INTEGER_M8388608_8388607 */
static int hf_rrlp_almanacW = -1;                 /* INTEGER_M8388608_8388607 */
static int hf_rrlp_almanacM0 = -1;                /* INTEGER_M8388608_8388607 */
static int hf_rrlp_almanacAF0 = -1;               /* INTEGER_M1024_1023 */
static int hf_rrlp_almanacAF1 = -1;               /* INTEGER_M1024_1023 */
static int hf_rrlp_timeRelation = -1;             /* TimeRelation */
static int hf_rrlp_acquisList = -1;               /* SeqOfAcquisElement */
static int hf_rrlp_SeqOfAcquisElement_item = -1;  /* AcquisElement */
static int hf_rrlp_gpsTOW3 = -1;                  /* GPSTOW23b */
static int hf_rrlp_svid = -1;                     /* SatelliteID */
static int hf_rrlp_doppler0 = -1;                 /* INTEGER_M2048_2047 */
static int hf_rrlp_addionalDoppler = -1;          /* AddionalDopplerFields */
static int hf_rrlp_codePhase = -1;                /* INTEGER_0_1022 */
static int hf_rrlp_intCodePhase = -1;             /* INTEGER_0_19 */
static int hf_rrlp_gpsBitNumber = -1;             /* INTEGER_0_3 */
static int hf_rrlp_codePhaseSearchWindow = -1;    /* INTEGER_0_15 */
static int hf_rrlp_addionalAngle = -1;            /* AddionalAngleFields */
static int hf_rrlp_doppler1 = -1;                 /* INTEGER_0_63 */
static int hf_rrlp_dopplerUncertainty = -1;       /* INTEGER_0_7 */
static int hf_rrlp_azimuth = -1;                  /* INTEGER_0_31 */
static int hf_rrlp_elevation = -1;                /* INTEGER_0_7 */
static int hf_rrlp_SeqOf_BadSatelliteSet_item = -1;  /* SatelliteID */
static int hf_rrlp_rel98_Ext_ExpOTD = -1;         /* Rel98_Ext_ExpOTD */
static int hf_rrlp_gpsTimeAssistanceMeasurementRequest = -1;  /* NULL */
static int hf_rrlp_gpsReferenceTimeUncertainty = -1;  /* GPSReferenceTimeUncertainty */
static int hf_rrlp_msrAssistData_R98_ExpOTD = -1;  /* MsrAssistData_R98_ExpOTD */
static int hf_rrlp_systemInfoAssistData_R98_ExpOTD = -1;  /* SystemInfoAssistData_R98_ExpOTD */
static int hf_rrlp_msrAssistList_R98_ExpOTD = -1;  /* SeqOfMsrAssistBTS_R98_ExpOTD */
static int hf_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD_item = -1;  /* MsrAssistBTS_R98_ExpOTD */
static int hf_rrlp_expectedOTD = -1;              /* ExpectedOTD */
static int hf_rrlp_expOTDUncertainty = -1;        /* ExpOTDUncertainty */
static int hf_rrlp_systemInfoAssistListR98_ExpOTD = -1;  /* SeqOfSystemInfoAssistBTS_R98_ExpOTD */
static int hf_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD_item = -1;  /* SystemInfoAssistBTS_R98_ExpOTD */
static int hf_rrlp_present1 = -1;                 /* AssistBTSData_R98_ExpOTD */
static int hf_rrlp_expOTDuncertainty = -1;        /* ExpOTDUncertainty */
static int hf_rrlp_referenceFrameMSB = -1;        /* INTEGER_0_63 */
static int hf_rrlp_gpsTowSubms = -1;              /* INTEGER_0_9999 */
static int hf_rrlp_deltaTow = -1;                 /* INTEGER_0_127 */
static int hf_rrlp_rel_98_Ext_MeasureInfo = -1;   /* T_rel_98_Ext_MeasureInfo */
static int hf_rrlp_otd_MeasureInfo_R98_Ext = -1;  /* OTD_MeasureInfo_R98_Ext */
static int hf_rrlp_timeAssistanceMeasurements = -1;  /* GPSTimeAssistanceMeasurements */
static int hf_rrlp_otdMsrFirstSets_R98_Ext = -1;  /* OTD_MsrElementFirst_R98_Ext */
static int hf_rrlp_otd_FirstSetMsrs_R98_Ext = -1;  /* SeqOfOTD_FirstSetMsrs_R98_Ext */
static int hf_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext_item = -1;  /* OTD_FirstSetMsrs */
static int hf_rrlp_extended_reference = -1;       /* Extended_reference */
static int hf_rrlp_otd_MeasureInfo_5_Ext = -1;    /* OTD_MeasureInfo_5_Ext */
static int hf_rrlp_ulPseudoSegInd = -1;           /* UlPseudoSegInd */
static int hf_rrlp_smlc_code = -1;                /* INTEGER_0_63 */
static int hf_rrlp_transaction_ID = -1;           /* INTEGER_0_262143 */

/*--- End of included file: packet-rrlp-hf.c ---*/
#line 58 "packet-rrlp-template.c"

/* Initialize the subtree pointers */
static gint ett_rrlp = -1;

/*--- Included file: packet-rrlp-ett.c ---*/
#line 1 "packet-rrlp-ett.c"
static gint ett_rrlp_PDU = -1;
static gint ett_rrlp_RRLP_Component = -1;
static gint ett_rrlp_MsrPosition_Req = -1;
static gint ett_rrlp_MsrPosition_Rsp = -1;
static gint ett_rrlp_AssistanceData = -1;
static gint ett_rrlp_ProtocolError = -1;
static gint ett_rrlp_PositionInstruct = -1;
static gint ett_rrlp_MethodType = -1;
static gint ett_rrlp_AccuracyOpt = -1;
static gint ett_rrlp_ReferenceAssistData = -1;
static gint ett_rrlp_MsrAssistData = -1;
static gint ett_rrlp_SeqOfMsrAssistBTS = -1;
static gint ett_rrlp_MsrAssistBTS = -1;
static gint ett_rrlp_SystemInfoAssistData = -1;
static gint ett_rrlp_SeqOfSystemInfoAssistBTS = -1;
static gint ett_rrlp_SystemInfoAssistBTS = -1;
static gint ett_rrlp_AssistBTSData = -1;
static gint ett_rrlp_CalcAssistanceBTS = -1;
static gint ett_rrlp_ReferenceWGS84 = -1;
static gint ett_rrlp_MultipleSets = -1;
static gint ett_rrlp_ReferenceIdentity = -1;
static gint ett_rrlp_SeqOfReferenceIdentityType = -1;
static gint ett_rrlp_ReferenceIdentityType = -1;
static gint ett_rrlp_BSICAndCarrier = -1;
static gint ett_rrlp_CellIDAndLAC = -1;
static gint ett_rrlp_OTD_MeasureInfo = -1;
static gint ett_rrlp_SeqOfOTD_MsrElementRest = -1;
static gint ett_rrlp_OTD_MsrElementFirst = -1;
static gint ett_rrlp_SeqOfOTD_FirstSetMsrs = -1;
static gint ett_rrlp_OTD_MsrElementRest = -1;
static gint ett_rrlp_SeqOfOTD_MsrsOfOtherSets = -1;
static gint ett_rrlp_TOA_MeasurementsOfRef = -1;
static gint ett_rrlp_OTD_MsrsOfOtherSets = -1;
static gint ett_rrlp_OTD_Measurement = -1;
static gint ett_rrlp_OTD_MeasurementWithID = -1;
static gint ett_rrlp_EOTDQuality = -1;
static gint ett_rrlp_NeighborIdentity = -1;
static gint ett_rrlp_MultiFrameCarrier = -1;
static gint ett_rrlp_LocationInfo = -1;
static gint ett_rrlp_GPS_MeasureInfo = -1;
static gint ett_rrlp_SeqOfGPS_MsrSetElement = -1;
static gint ett_rrlp_GPS_MsrSetElement = -1;
static gint ett_rrlp_SeqOfGPS_MsrElement = -1;
static gint ett_rrlp_GPS_MsrElement = -1;
static gint ett_rrlp_LocationError = -1;
static gint ett_rrlp_AdditionalAssistanceData = -1;
static gint ett_rrlp_GPS_AssistData = -1;
static gint ett_rrlp_ControlHeader = -1;
static gint ett_rrlp_ReferenceTime = -1;
static gint ett_rrlp_GPSTime = -1;
static gint ett_rrlp_GPSTOWAssist = -1;
static gint ett_rrlp_GPSTOWAssistElement = -1;
static gint ett_rrlp_GSMTime = -1;
static gint ett_rrlp_RefLocation = -1;
static gint ett_rrlp_DGPSCorrections = -1;
static gint ett_rrlp_SeqOfSatElement = -1;
static gint ett_rrlp_SatElement = -1;
static gint ett_rrlp_NavigationModel = -1;
static gint ett_rrlp_SeqOfNavModelElement = -1;
static gint ett_rrlp_NavModelElement = -1;
static gint ett_rrlp_SatStatus = -1;
static gint ett_rrlp_UncompressedEphemeris = -1;
static gint ett_rrlp_EphemerisSubframe1Reserved = -1;
static gint ett_rrlp_IonosphericModel = -1;
static gint ett_rrlp_UTCModel = -1;
static gint ett_rrlp_Almanac = -1;
static gint ett_rrlp_SeqOfAlmanacElement = -1;
static gint ett_rrlp_AlmanacElement = -1;
static gint ett_rrlp_AcquisAssist = -1;
static gint ett_rrlp_SeqOfAcquisElement = -1;
static gint ett_rrlp_TimeRelation = -1;
static gint ett_rrlp_AcquisElement = -1;
static gint ett_rrlp_AddionalDopplerFields = -1;
static gint ett_rrlp_AddionalAngleFields = -1;
static gint ett_rrlp_SeqOf_BadSatelliteSet = -1;
static gint ett_rrlp_Rel98_MsrPosition_Req_Extension = -1;
static gint ett_rrlp_Rel98_AssistanceData_Extension = -1;
static gint ett_rrlp_Rel98_Ext_ExpOTD = -1;
static gint ett_rrlp_MsrAssistData_R98_ExpOTD = -1;
static gint ett_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD = -1;
static gint ett_rrlp_MsrAssistBTS_R98_ExpOTD = -1;
static gint ett_rrlp_SystemInfoAssistData_R98_ExpOTD = -1;
static gint ett_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD = -1;
static gint ett_rrlp_SystemInfoAssistBTS_R98_ExpOTD = -1;
static gint ett_rrlp_AssistBTSData_R98_ExpOTD = -1;
static gint ett_rrlp_GPSTimeAssistanceMeasurements = -1;
static gint ett_rrlp_Rel_98_MsrPosition_Rsp_Extension = -1;
static gint ett_rrlp_T_rel_98_Ext_MeasureInfo = -1;
static gint ett_rrlp_OTD_MeasureInfo_R98_Ext = -1;
static gint ett_rrlp_OTD_MsrElementFirst_R98_Ext = -1;
static gint ett_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext = -1;
static gint ett_rrlp_Rel_5_MsrPosition_Rsp_Extension = -1;
static gint ett_rrlp_Extended_reference = -1;
static gint ett_rrlp_Rel5_MsrPosition_Req_Extension = -1;
static gint ett_rrlp_Rel5_AssistanceData_Extension = -1;
static gint ett_rrlp_Rel_5_ProtocolError_Extension = -1;

/*--- End of included file: packet-rrlp-ett.c ---*/
#line 62 "packet-rrlp-template.c"

/* Include constants */

/*--- Included file: packet-rrlp-val.h ---*/
#line 1 "packet-rrlp-val.h"
#define maxGPSAssistanceData           40

/*--- End of included file: packet-rrlp-val.h ---*/
#line 65 "packet-rrlp-template.c"

/* If trying to use module import the "dissect_gsm_map_ExtensionContainer" will be wrongly constructed
 * presumably because it assumes it will be PER encoded
 */
static int
dissect_MAP_ExtensionDataTypes_ExtensionContainer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index){

	return dissect_gsm_map_ExtensionContainer(TRUE, tvb, offset, pinfo, tree, hf_index);
}

static int
dissect_MAP_LCS_DataTypes_Ext_GeographicalInformation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index){

	return dissect_gsm_map_Ext_GeographicalInformation(TRUE, tvb, offset, pinfo, tree, hf_index);
}


/*--- Included file: packet-rrlp-fn.c ---*/
#line 1 "packet-rrlp-fn.c"
/*--- Fields for imported types ---*/

static int dissect_extensionContainer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_MAP_ExtensionDataTypes_ExtensionContainer(tvb, offset, pinfo, tree, hf_rrlp_extensionContainer);
}
static int dissect_posEstimate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_MAP_LCS_DataTypes_Ext_GeographicalInformation(tvb, offset, pinfo, tree, hf_rrlp_posEstimate);
}
static int dissect_threeDLocation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_MAP_LCS_DataTypes_Ext_GeographicalInformation(tvb, offset, pinfo, tree, hf_rrlp_threeDLocation);
}



static int
dissect_rrlp_INTEGER_0_7(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 7U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_referenceNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_7(tvb, offset, pinfo, tree, hf_rrlp_referenceNumber);
}
static int dissect_nbrOfMeasurements(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_7(tvb, offset, pinfo, tree, hf_rrlp_nbrOfMeasurements);
}
static int dissect_status(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_7(tvb, offset, pinfo, tree, hf_rrlp_status);
}
static int dissect_dopplerUncertainty(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_7(tvb, offset, pinfo, tree, hf_rrlp_dopplerUncertainty);
}
static int dissect_elevation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_7(tvb, offset, pinfo, tree, hf_rrlp_elevation);
}



static int
dissect_rrlp_Accuracy(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 127U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_msBased(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Accuracy(tvb, offset, pinfo, tree, hf_rrlp_msBased);
}
static int dissect_msBasedPref(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Accuracy(tvb, offset, pinfo, tree, hf_rrlp_msBasedPref);
}
static int dissect_msAssistedPref(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Accuracy(tvb, offset, pinfo, tree, hf_rrlp_msAssistedPref);
}
static int dissect_accuracy(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Accuracy(tvb, offset, pinfo, tree, hf_rrlp_accuracy);
}


static const per_sequence_t AccuracyOpt_sequence[] = {
  { "accuracy"                    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_accuracy },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AccuracyOpt(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_AccuracyOpt, AccuracyOpt_sequence);

  return offset;
}
static int dissect_msAssisted(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_AccuracyOpt(tvb, offset, pinfo, tree, hf_rrlp_msAssisted);
}


static const value_string rrlp_MethodType_vals[] = {
  {   0, "msAssisted" },
  {   1, "msBased" },
  {   2, "msBasedPref" },
  {   3, "msAssistedPref" },
  { 0, NULL }
};

static const per_choice_t MethodType_choice[] = {
  {   0, "msAssisted"                  , ASN1_NO_EXTENSIONS     , dissect_msAssisted },
  {   1, "msBased"                     , ASN1_NO_EXTENSIONS     , dissect_msBased },
  {   2, "msBasedPref"                 , ASN1_NO_EXTENSIONS     , dissect_msBasedPref },
  {   3, "msAssistedPref"              , ASN1_NO_EXTENSIONS     , dissect_msAssistedPref },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_MethodType(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_rrlp_MethodType, MethodType_choice,
                                 NULL);

  return offset;
}
static int dissect_methodType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_MethodType(tvb, offset, pinfo, tree, hf_rrlp_methodType);
}


static const value_string rrlp_PositionMethod_vals[] = {
  {   0, "eotd" },
  {   1, "gps" },
  {   2, "gpsOrEOTD" },
  { 0, NULL }
};


static int
dissect_rrlp_PositionMethod(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     3, NULL, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_positionMethod(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_PositionMethod(tvb, offset, pinfo, tree, hf_rrlp_positionMethod);
}



static int
dissect_rrlp_MeasureResponseTime(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 7U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_measureResponseTime(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_MeasureResponseTime(tvb, offset, pinfo, tree, hf_rrlp_measureResponseTime);
}


static const value_string rrlp_UseMultipleSets_vals[] = {
  {   0, "multipleSets" },
  {   1, "oneSet" },
  { 0, NULL }
};


static int
dissect_rrlp_UseMultipleSets(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     2, NULL, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_useMultipleSets(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_UseMultipleSets(tvb, offset, pinfo, tree, hf_rrlp_useMultipleSets);
}


static const value_string rrlp_EnvironmentCharacter_vals[] = {
  {   0, "badArea" },
  {   1, "notBadArea" },
  {   2, "mixedArea" },
  { 0, NULL }
};


static int
dissect_rrlp_EnvironmentCharacter(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     3, NULL, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_environmentCharacter(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_EnvironmentCharacter(tvb, offset, pinfo, tree, hf_rrlp_environmentCharacter);
}


static const per_sequence_t PositionInstruct_sequence[] = {
  { "methodType"                  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_methodType },
  { "positionMethod"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_positionMethod },
  { "measureResponseTime"         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_measureResponseTime },
  { "useMultipleSets"             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_useMultipleSets },
  { "environmentCharacter"        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_environmentCharacter },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_PositionInstruct(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_PositionInstruct, PositionInstruct_sequence);

  return offset;
}
static int dissect_positionInstruct(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_PositionInstruct(tvb, offset, pinfo, tree, hf_rrlp_positionInstruct);
}



static int
dissect_rrlp_BCCHCarrier(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 1023U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_bcchCarrier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_BCCHCarrier(tvb, offset, pinfo, tree, hf_rrlp_bcchCarrier);
}
static int dissect_carrier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_BCCHCarrier(tvb, offset, pinfo, tree, hf_rrlp_carrier);
}



static int
dissect_rrlp_BSIC(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 63U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_bsic(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_BSIC(tvb, offset, pinfo, tree, hf_rrlp_bsic);
}


static const value_string rrlp_TimeSlotScheme_vals[] = {
  {   0, "equalLength" },
  {   1, "variousLength" },
  { 0, NULL }
};


static int
dissect_rrlp_TimeSlotScheme(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     2, NULL, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_timeSlotScheme(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_TimeSlotScheme(tvb, offset, pinfo, tree, hf_rrlp_timeSlotScheme);
}



static int
dissect_rrlp_BTSPosition(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_MAP_LCS_DataTypes_Ext_GeographicalInformation(tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_btsPosition(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_BTSPosition(tvb, offset, pinfo, tree, hf_rrlp_btsPosition);
}


static const per_sequence_t ReferenceAssistData_sequence[] = {
  { "bcchCarrier"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_bcchCarrier },
  { "bsic"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_bsic },
  { "timeSlotScheme"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_timeSlotScheme },
  { "btsPosition"                 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_btsPosition },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ReferenceAssistData(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_ReferenceAssistData, ReferenceAssistData_sequence);

  return offset;
}
static int dissect_referenceAssistData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ReferenceAssistData(tvb, offset, pinfo, tree, hf_rrlp_referenceAssistData);
}



static int
dissect_rrlp_MultiFrameOffset(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 51U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_multiFrameOffset(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_MultiFrameOffset(tvb, offset, pinfo, tree, hf_rrlp_multiFrameOffset);
}



static int
dissect_rrlp_RoughRTD(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 1250U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_roughRTD(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_RoughRTD(tvb, offset, pinfo, tree, hf_rrlp_roughRTD);
}



static int
dissect_rrlp_FineRTD(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 255U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_fineRTD(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_FineRTD(tvb, offset, pinfo, tree, hf_rrlp_fineRTD);
}



static int
dissect_rrlp_RelDistance(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -200000, 200000U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_relativeNorth(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_RelDistance(tvb, offset, pinfo, tree, hf_rrlp_relativeNorth);
}
static int dissect_relativeEast(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_RelDistance(tvb, offset, pinfo, tree, hf_rrlp_relativeEast);
}



static int
dissect_rrlp_RelativeAlt(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -4000, 4000U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_relativeAlt(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_RelativeAlt(tvb, offset, pinfo, tree, hf_rrlp_relativeAlt);
}


static const per_sequence_t ReferenceWGS84_sequence[] = {
  { "relativeNorth"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_relativeNorth },
  { "relativeEast"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_relativeEast },
  { "relativeAlt"                 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_relativeAlt },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ReferenceWGS84(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_ReferenceWGS84, ReferenceWGS84_sequence);

  return offset;
}
static int dissect_referenceWGS84(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ReferenceWGS84(tvb, offset, pinfo, tree, hf_rrlp_referenceWGS84);
}


static const per_sequence_t CalcAssistanceBTS_sequence[] = {
  { "fineRTD"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_fineRTD },
  { "referenceWGS84"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_referenceWGS84 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_CalcAssistanceBTS(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_CalcAssistanceBTS, CalcAssistanceBTS_sequence);

  return offset;
}
static int dissect_calcAssistanceBTS(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_CalcAssistanceBTS(tvb, offset, pinfo, tree, hf_rrlp_calcAssistanceBTS);
}


static const per_sequence_t MsrAssistBTS_sequence[] = {
  { "bcchCarrier"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_bcchCarrier },
  { "bsic"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_bsic },
  { "multiFrameOffset"            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_multiFrameOffset },
  { "timeSlotScheme"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_timeSlotScheme },
  { "roughRTD"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_roughRTD },
  { "calcAssistanceBTS"           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_calcAssistanceBTS },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MsrAssistBTS(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_MsrAssistBTS, MsrAssistBTS_sequence);

  return offset;
}
static int dissect_SeqOfMsrAssistBTS_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_MsrAssistBTS(tvb, offset, pinfo, tree, hf_rrlp_SeqOfMsrAssistBTS_item);
}


static const per_sequence_t SeqOfMsrAssistBTS_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfMsrAssistBTS_item },
};

static int
dissect_rrlp_SeqOfMsrAssistBTS(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfMsrAssistBTS, SeqOfMsrAssistBTS_sequence_of,
                                                  1, 15);

  return offset;
}
static int dissect_msrAssistList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfMsrAssistBTS(tvb, offset, pinfo, tree, hf_rrlp_msrAssistList);
}


static const per_sequence_t MsrAssistData_sequence[] = {
  { "msrAssistList"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_msrAssistList },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MsrAssistData(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_MsrAssistData, MsrAssistData_sequence);

  return offset;
}
static int dissect_msrAssistData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_MsrAssistData(tvb, offset, pinfo, tree, hf_rrlp_msrAssistData);
}



static int
dissect_rrlp_NULL(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_null(tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_assistanceDataAck(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_NULL(tvb, offset, pinfo, tree, hf_rrlp_assistanceDataAck);
}
static int dissect_notPresent(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_NULL(tvb, offset, pinfo, tree, hf_rrlp_notPresent);
}
static int dissect_oldSatelliteAndModel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_NULL(tvb, offset, pinfo, tree, hf_rrlp_oldSatelliteAndModel);
}
static int dissect_gpsTimeAssistanceMeasurementRequest(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_NULL(tvb, offset, pinfo, tree, hf_rrlp_gpsTimeAssistanceMeasurementRequest);
}


static const per_sequence_t AssistBTSData_sequence[] = {
  { "bsic"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_bsic },
  { "multiFrameOffset"            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_multiFrameOffset },
  { "timeSlotScheme"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_timeSlotScheme },
  { "roughRTD"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_roughRTD },
  { "calcAssistanceBTS"           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_calcAssistanceBTS },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AssistBTSData(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_AssistBTSData, AssistBTSData_sequence);

  return offset;
}
static int dissect_present(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_AssistBTSData(tvb, offset, pinfo, tree, hf_rrlp_present);
}


static const value_string rrlp_SystemInfoAssistBTS_vals[] = {
  {   0, "notPresent" },
  {   1, "present" },
  { 0, NULL }
};

static const per_choice_t SystemInfoAssistBTS_choice[] = {
  {   0, "notPresent"                  , ASN1_NO_EXTENSIONS     , dissect_notPresent },
  {   1, "present"                     , ASN1_NO_EXTENSIONS     , dissect_present },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_SystemInfoAssistBTS(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_rrlp_SystemInfoAssistBTS, SystemInfoAssistBTS_choice,
                                 NULL);

  return offset;
}
static int dissect_SeqOfSystemInfoAssistBTS_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SystemInfoAssistBTS(tvb, offset, pinfo, tree, hf_rrlp_SeqOfSystemInfoAssistBTS_item);
}


static const per_sequence_t SeqOfSystemInfoAssistBTS_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfSystemInfoAssistBTS_item },
};

static int
dissect_rrlp_SeqOfSystemInfoAssistBTS(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfSystemInfoAssistBTS, SeqOfSystemInfoAssistBTS_sequence_of,
                                                  1, 32);

  return offset;
}
static int dissect_systemInfoAssistList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfSystemInfoAssistBTS(tvb, offset, pinfo, tree, hf_rrlp_systemInfoAssistList);
}


static const per_sequence_t SystemInfoAssistData_sequence[] = {
  { "systemInfoAssistList"        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_systemInfoAssistList },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_SystemInfoAssistData(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_SystemInfoAssistData, SystemInfoAssistData_sequence);

  return offset;
}
static int dissect_systemInfoAssistData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SystemInfoAssistData(tvb, offset, pinfo, tree, hf_rrlp_systemInfoAssistData);
}



static int
dissect_rrlp_GPSTOW23b(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 7559999U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_gpsTOW23b(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPSTOW23b(tvb, offset, pinfo, tree, hf_rrlp_gpsTOW23b);
}
static int dissect_gpsTOW3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPSTOW23b(tvb, offset, pinfo, tree, hf_rrlp_gpsTOW3);
}



static int
dissect_rrlp_GPSWeek(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 1023U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_gpsWeek(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPSWeek(tvb, offset, pinfo, tree, hf_rrlp_gpsWeek);
}


static const per_sequence_t GPSTime_sequence[] = {
  { "gpsTOW23b"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_gpsTOW23b },
  { "gpsWeek"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_gpsWeek },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSTime(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_GPSTime, GPSTime_sequence);

  return offset;
}
static int dissect_gpsTime(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPSTime(tvb, offset, pinfo, tree, hf_rrlp_gpsTime);
}



static int
dissect_rrlp_FrameNumber(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 2097151U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_frameNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_FrameNumber(tvb, offset, pinfo, tree, hf_rrlp_frameNumber);
}



static int
dissect_rrlp_TimeSlot(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 7U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_timeSlot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_TimeSlot(tvb, offset, pinfo, tree, hf_rrlp_timeSlot);
}



static int
dissect_rrlp_BitNumber(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 156U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_bitNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_BitNumber(tvb, offset, pinfo, tree, hf_rrlp_bitNumber);
}


static const per_sequence_t GSMTime_sequence[] = {
  { "bcchCarrier"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_bcchCarrier },
  { "bsic"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_bsic },
  { "frameNumber"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_frameNumber },
  { "timeSlot"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_timeSlot },
  { "bitNumber"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_bitNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GSMTime(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_GSMTime, GSMTime_sequence);

  return offset;
}
static int dissect_gsmTime(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GSMTime(tvb, offset, pinfo, tree, hf_rrlp_gsmTime);
}



static int
dissect_rrlp_SatelliteID(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 63U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_satelliteID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SatelliteID(tvb, offset, pinfo, tree, hf_rrlp_satelliteID);
}
static int dissect_svid(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SatelliteID(tvb, offset, pinfo, tree, hf_rrlp_svid);
}
static int dissect_SeqOf_BadSatelliteSet_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SatelliteID(tvb, offset, pinfo, tree, hf_rrlp_SeqOf_BadSatelliteSet_item);
}



static int
dissect_rrlp_TLMWord(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 16383U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_tlmWord(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_TLMWord(tvb, offset, pinfo, tree, hf_rrlp_tlmWord);
}



static int
dissect_rrlp_AntiSpoofFlag(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 1U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_antiSpoof(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_AntiSpoofFlag(tvb, offset, pinfo, tree, hf_rrlp_antiSpoof);
}



static int
dissect_rrlp_AlertFlag(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 1U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_alert(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_AlertFlag(tvb, offset, pinfo, tree, hf_rrlp_alert);
}



static int
dissect_rrlp_TLMReservedBits(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 3U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_tlmRsvdBits(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_TLMReservedBits(tvb, offset, pinfo, tree, hf_rrlp_tlmRsvdBits);
}


static const per_sequence_t GPSTOWAssistElement_sequence[] = {
  { "satelliteID"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_satelliteID },
  { "tlmWord"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tlmWord },
  { "antiSpoof"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_antiSpoof },
  { "alert"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_alert },
  { "tlmRsvdBits"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_tlmRsvdBits },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSTOWAssistElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_GPSTOWAssistElement, GPSTOWAssistElement_sequence);

  return offset;
}
static int dissect_GPSTOWAssist_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPSTOWAssistElement(tvb, offset, pinfo, tree, hf_rrlp_GPSTOWAssist_item);
}


static const per_sequence_t GPSTOWAssist_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_GPSTOWAssist_item },
};

static int
dissect_rrlp_GPSTOWAssist(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_GPSTOWAssist, GPSTOWAssist_sequence_of,
                                                  1, 12);

  return offset;
}
static int dissect_gpsTowAssist(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPSTOWAssist(tvb, offset, pinfo, tree, hf_rrlp_gpsTowAssist);
}


static const per_sequence_t ReferenceTime_sequence[] = {
  { "gpsTime"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_gpsTime },
  { "gsmTime"                     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_gsmTime },
  { "gpsTowAssist"                , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_gpsTowAssist },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ReferenceTime(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_ReferenceTime, ReferenceTime_sequence);

  return offset;
}
static int dissect_referenceTime(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ReferenceTime(tvb, offset, pinfo, tree, hf_rrlp_referenceTime);
}


static const per_sequence_t RefLocation_sequence[] = {
  { "threeDLocation"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_threeDLocation },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_RefLocation(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_RefLocation, RefLocation_sequence);

  return offset;
}
static int dissect_refLocation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_RefLocation(tvb, offset, pinfo, tree, hf_rrlp_refLocation);
}



static int
dissect_rrlp_INTEGER_0_604799(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 604799U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_gpsTOW2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_604799(tvb, offset, pinfo, tree, hf_rrlp_gpsTOW2);
}



static int
dissect_rrlp_INTEGER_0_239(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 239U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_iode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_239(tvb, offset, pinfo, tree, hf_rrlp_iode);
}



static int
dissect_rrlp_INTEGER_0_3(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 3U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_udre(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_3(tvb, offset, pinfo, tree, hf_rrlp_udre);
}
static int dissect_ephemCodeOnL2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_3(tvb, offset, pinfo, tree, hf_rrlp_ephemCodeOnL2);
}
static int dissect_gpsBitNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_3(tvb, offset, pinfo, tree, hf_rrlp_gpsBitNumber);
}



static int
dissect_rrlp_INTEGER_M2047_2047(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -2047, 2047U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_pseudoRangeCor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M2047_2047(tvb, offset, pinfo, tree, hf_rrlp_pseudoRangeCor);
}



static int
dissect_rrlp_INTEGER_M127_127(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -127, 127U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_rangeRateCor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M127_127(tvb, offset, pinfo, tree, hf_rrlp_rangeRateCor);
}
static int dissect_deltaPseudoRangeCor2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M127_127(tvb, offset, pinfo, tree, hf_rrlp_deltaPseudoRangeCor2);
}
static int dissect_deltaPseudoRangeCor3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M127_127(tvb, offset, pinfo, tree, hf_rrlp_deltaPseudoRangeCor3);
}



static int
dissect_rrlp_INTEGER_M7_7(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -7, 7U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_deltaRangeRateCor2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M7_7(tvb, offset, pinfo, tree, hf_rrlp_deltaRangeRateCor2);
}
static int dissect_deltaRangeRateCor3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M7_7(tvb, offset, pinfo, tree, hf_rrlp_deltaRangeRateCor3);
}


static const per_sequence_t SatElement_sequence[] = {
  { "satelliteID"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_satelliteID },
  { "iode"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_iode },
  { "udre"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_udre },
  { "pseudoRangeCor"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pseudoRangeCor },
  { "rangeRateCor"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rangeRateCor },
  { "deltaPseudoRangeCor2"        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_deltaPseudoRangeCor2 },
  { "deltaRangeRateCor2"          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_deltaRangeRateCor2 },
  { "deltaPseudoRangeCor3"        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_deltaPseudoRangeCor3 },
  { "deltaRangeRateCor3"          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_deltaRangeRateCor3 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_SatElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_SatElement, SatElement_sequence);

  return offset;
}
static int dissect_SeqOfSatElement_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SatElement(tvb, offset, pinfo, tree, hf_rrlp_SeqOfSatElement_item);
}


static const per_sequence_t SeqOfSatElement_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfSatElement_item },
};

static int
dissect_rrlp_SeqOfSatElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfSatElement, SeqOfSatElement_sequence_of,
                                                  1, 16);

  return offset;
}
static int dissect_satList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfSatElement(tvb, offset, pinfo, tree, hf_rrlp_satList);
}


static const per_sequence_t DGPSCorrections_sequence[] = {
  { "gpsTOW"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_gpsTOW2 },
  { "status"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_status },
  { "satList"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_satList },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_DGPSCorrections(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_DGPSCorrections, DGPSCorrections_sequence);

  return offset;
}
static int dissect_dgpsCorrections(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_DGPSCorrections(tvb, offset, pinfo, tree, hf_rrlp_dgpsCorrections);
}



static int
dissect_rrlp_INTEGER_0_15(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 15U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_ephemURA(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_15(tvb, offset, pinfo, tree, hf_rrlp_ephemURA);
}
static int dissect_codePhaseSearchWindow(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_15(tvb, offset, pinfo, tree, hf_rrlp_codePhaseSearchWindow);
}



static int
dissect_rrlp_INTEGER_0_63(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 63U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_cNo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_63(tvb, offset, pinfo, tree, hf_rrlp_cNo);
}
static int dissect_pseuRangeRMSErr(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_63(tvb, offset, pinfo, tree, hf_rrlp_pseuRangeRMSErr);
}
static int dissect_ephemSVhealth(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_63(tvb, offset, pinfo, tree, hf_rrlp_ephemSVhealth);
}
static int dissect_doppler1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_63(tvb, offset, pinfo, tree, hf_rrlp_doppler1);
}
static int dissect_referenceFrameMSB(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_63(tvb, offset, pinfo, tree, hf_rrlp_referenceFrameMSB);
}
static int dissect_smlc_code(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_63(tvb, offset, pinfo, tree, hf_rrlp_smlc_code);
}



static int
dissect_rrlp_INTEGER_0_1023(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 1023U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_ephemIODC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_1023(tvb, offset, pinfo, tree, hf_rrlp_ephemIODC);
}



static int
dissect_rrlp_INTEGER_0_1(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 1U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_ephemL2Pflag(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_1(tvb, offset, pinfo, tree, hf_rrlp_ephemL2Pflag);
}
static int dissect_ephemFitFlag(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_1(tvb, offset, pinfo, tree, hf_rrlp_ephemFitFlag);
}



static int
dissect_rrlp_INTEGER_0_8388607(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 8388607U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_reserved1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_8388607(tvb, offset, pinfo, tree, hf_rrlp_reserved1);
}



static int
dissect_rrlp_INTEGER_0_16777215(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 16777215U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_reserved2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_16777215(tvb, offset, pinfo, tree, hf_rrlp_reserved2);
}
static int dissect_reserved3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_16777215(tvb, offset, pinfo, tree, hf_rrlp_reserved3);
}
static int dissect_almanacAPowerHalf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_16777215(tvb, offset, pinfo, tree, hf_rrlp_almanacAPowerHalf);
}



static int
dissect_rrlp_INTEGER_0_65535(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 65535U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_refFrame(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_65535(tvb, offset, pinfo, tree, hf_rrlp_refFrame);
}
static int dissect_reserved4(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_65535(tvb, offset, pinfo, tree, hf_rrlp_reserved4);
}
static int dissect_almanacE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_65535(tvb, offset, pinfo, tree, hf_rrlp_almanacE);
}


static const per_sequence_t EphemerisSubframe1Reserved_sequence[] = {
  { "reserved1"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_reserved1 },
  { "reserved2"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_reserved2 },
  { "reserved3"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_reserved3 },
  { "reserved4"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_reserved4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_EphemerisSubframe1Reserved(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_EphemerisSubframe1Reserved, EphemerisSubframe1Reserved_sequence);

  return offset;
}
static int dissect_ephemSF1Rsvd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_EphemerisSubframe1Reserved(tvb, offset, pinfo, tree, hf_rrlp_ephemSF1Rsvd);
}



static int
dissect_rrlp_INTEGER_M128_127(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -128, 127U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_ephemTgd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M128_127(tvb, offset, pinfo, tree, hf_rrlp_ephemTgd);
}
static int dissect_ephemAF2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M128_127(tvb, offset, pinfo, tree, hf_rrlp_ephemAF2);
}
static int dissect_alfa0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M128_127(tvb, offset, pinfo, tree, hf_rrlp_alfa0);
}
static int dissect_alfa1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M128_127(tvb, offset, pinfo, tree, hf_rrlp_alfa1);
}
static int dissect_alfa2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M128_127(tvb, offset, pinfo, tree, hf_rrlp_alfa2);
}
static int dissect_alfa3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M128_127(tvb, offset, pinfo, tree, hf_rrlp_alfa3);
}
static int dissect_beta0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M128_127(tvb, offset, pinfo, tree, hf_rrlp_beta0);
}
static int dissect_beta1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M128_127(tvb, offset, pinfo, tree, hf_rrlp_beta1);
}
static int dissect_beta2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M128_127(tvb, offset, pinfo, tree, hf_rrlp_beta2);
}
static int dissect_beta3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M128_127(tvb, offset, pinfo, tree, hf_rrlp_beta3);
}
static int dissect_utcDeltaTls(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M128_127(tvb, offset, pinfo, tree, hf_rrlp_utcDeltaTls);
}
static int dissect_utcDN(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M128_127(tvb, offset, pinfo, tree, hf_rrlp_utcDN);
}
static int dissect_utcDeltaTlsf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M128_127(tvb, offset, pinfo, tree, hf_rrlp_utcDeltaTlsf);
}



static int
dissect_rrlp_INTEGER_0_37799(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 37799U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_ephemToc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_37799(tvb, offset, pinfo, tree, hf_rrlp_ephemToc);
}
static int dissect_ephemToe(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_37799(tvb, offset, pinfo, tree, hf_rrlp_ephemToe);
}



static int
dissect_rrlp_INTEGER_M32768_32767(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -32768, 32767U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_doppler(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M32768_32767(tvb, offset, pinfo, tree, hf_rrlp_doppler);
}
static int dissect_ephemAF1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M32768_32767(tvb, offset, pinfo, tree, hf_rrlp_ephemAF1);
}
static int dissect_ephemCrs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M32768_32767(tvb, offset, pinfo, tree, hf_rrlp_ephemCrs);
}
static int dissect_ephemDeltaN(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M32768_32767(tvb, offset, pinfo, tree, hf_rrlp_ephemDeltaN);
}
static int dissect_ephemCuc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M32768_32767(tvb, offset, pinfo, tree, hf_rrlp_ephemCuc);
}
static int dissect_ephemCus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M32768_32767(tvb, offset, pinfo, tree, hf_rrlp_ephemCus);
}
static int dissect_ephemCic(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M32768_32767(tvb, offset, pinfo, tree, hf_rrlp_ephemCic);
}
static int dissect_ephemCis(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M32768_32767(tvb, offset, pinfo, tree, hf_rrlp_ephemCis);
}
static int dissect_ephemCrc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M32768_32767(tvb, offset, pinfo, tree, hf_rrlp_ephemCrc);
}
static int dissect_almanacKsii(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M32768_32767(tvb, offset, pinfo, tree, hf_rrlp_almanacKsii);
}
static int dissect_almanacOmegaDot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M32768_32767(tvb, offset, pinfo, tree, hf_rrlp_almanacOmegaDot);
}



static int
dissect_rrlp_INTEGER_M2097152_2097151(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -2097152, 2097151U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_ephemAF0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M2097152_2097151(tvb, offset, pinfo, tree, hf_rrlp_ephemAF0);
}



static int
dissect_rrlp_INTEGER_M2147483648_2147483647(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -2147483648, 2147483647U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_ephemM0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M2147483648_2147483647(tvb, offset, pinfo, tree, hf_rrlp_ephemM0);
}
static int dissect_ephemOmegaA0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M2147483648_2147483647(tvb, offset, pinfo, tree, hf_rrlp_ephemOmegaA0);
}
static int dissect_ephemI0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M2147483648_2147483647(tvb, offset, pinfo, tree, hf_rrlp_ephemI0);
}
static int dissect_ephemW(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M2147483648_2147483647(tvb, offset, pinfo, tree, hf_rrlp_ephemW);
}
static int dissect_utcA0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M2147483648_2147483647(tvb, offset, pinfo, tree, hf_rrlp_utcA0);
}



static int
dissect_rrlp_INTEGER_0_4294967295(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 4294967295U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_ephemE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_4294967295(tvb, offset, pinfo, tree, hf_rrlp_ephemE);
}
static int dissect_ephemAPowerHalf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_4294967295(tvb, offset, pinfo, tree, hf_rrlp_ephemAPowerHalf);
}



static int
dissect_rrlp_INTEGER_0_31(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 31U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_stdOfEOTD(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_31(tvb, offset, pinfo, tree, hf_rrlp_stdOfEOTD);
}
static int dissect_ephemAODA(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_31(tvb, offset, pinfo, tree, hf_rrlp_ephemAODA);
}
static int dissect_azimuth(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_31(tvb, offset, pinfo, tree, hf_rrlp_azimuth);
}



static int
dissect_rrlp_INTEGER_M8388608_8388607(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -8388608, 8388607U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_ephemOmegaADot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M8388608_8388607(tvb, offset, pinfo, tree, hf_rrlp_ephemOmegaADot);
}
static int dissect_utcA1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M8388608_8388607(tvb, offset, pinfo, tree, hf_rrlp_utcA1);
}
static int dissect_almanacOmega0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M8388608_8388607(tvb, offset, pinfo, tree, hf_rrlp_almanacOmega0);
}
static int dissect_almanacW(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M8388608_8388607(tvb, offset, pinfo, tree, hf_rrlp_almanacW);
}
static int dissect_almanacM0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M8388608_8388607(tvb, offset, pinfo, tree, hf_rrlp_almanacM0);
}



static int
dissect_rrlp_INTEGER_M8192_8191(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -8192, 8191U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_ephemIDot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M8192_8191(tvb, offset, pinfo, tree, hf_rrlp_ephemIDot);
}


static const per_sequence_t UncompressedEphemeris_sequence[] = {
  { "ephemCodeOnL2"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemCodeOnL2 },
  { "ephemURA"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemURA },
  { "ephemSVhealth"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemSVhealth },
  { "ephemIODC"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemIODC },
  { "ephemL2Pflag"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemL2Pflag },
  { "ephemSF1Rsvd"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemSF1Rsvd },
  { "ephemTgd"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemTgd },
  { "ephemToc"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemToc },
  { "ephemAF2"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemAF2 },
  { "ephemAF1"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemAF1 },
  { "ephemAF0"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemAF0 },
  { "ephemCrs"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemCrs },
  { "ephemDeltaN"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemDeltaN },
  { "ephemM0"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemM0 },
  { "ephemCuc"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemCuc },
  { "ephemE"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemE },
  { "ephemCus"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemCus },
  { "ephemAPowerHalf"             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemAPowerHalf },
  { "ephemToe"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemToe },
  { "ephemFitFlag"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemFitFlag },
  { "ephemAODA"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemAODA },
  { "ephemCic"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemCic },
  { "ephemOmegaA0"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemOmegaA0 },
  { "ephemCis"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemCis },
  { "ephemI0"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemI0 },
  { "ephemCrc"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemCrc },
  { "ephemW"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemW },
  { "ephemOmegaADot"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemOmegaADot },
  { "ephemIDot"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ephemIDot },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_UncompressedEphemeris(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_UncompressedEphemeris, UncompressedEphemeris_sequence);

  return offset;
}
static int dissect_newSatelliteAndModelUC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_UncompressedEphemeris(tvb, offset, pinfo, tree, hf_rrlp_newSatelliteAndModelUC);
}
static int dissect_newNaviModelUC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_UncompressedEphemeris(tvb, offset, pinfo, tree, hf_rrlp_newNaviModelUC);
}


static const value_string rrlp_SatStatus_vals[] = {
  {   0, "newSatelliteAndModelUC" },
  {   1, "oldSatelliteAndModel" },
  {   2, "newNaviModelUC" },
  { 0, NULL }
};

static const per_choice_t SatStatus_choice[] = {
  {   0, "newSatelliteAndModelUC"      , ASN1_EXTENSION_ROOT    , dissect_newSatelliteAndModelUC },
  {   1, "oldSatelliteAndModel"        , ASN1_EXTENSION_ROOT    , dissect_oldSatelliteAndModel },
  {   2, "newNaviModelUC"              , ASN1_EXTENSION_ROOT    , dissect_newNaviModelUC },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_SatStatus(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_rrlp_SatStatus, SatStatus_choice,
                                 NULL);

  return offset;
}
static int dissect_satStatus(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SatStatus(tvb, offset, pinfo, tree, hf_rrlp_satStatus);
}


static const per_sequence_t NavModelElement_sequence[] = {
  { "satelliteID"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_satelliteID },
  { "satStatus"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_satStatus },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_NavModelElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_NavModelElement, NavModelElement_sequence);

  return offset;
}
static int dissect_SeqOfNavModelElement_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_NavModelElement(tvb, offset, pinfo, tree, hf_rrlp_SeqOfNavModelElement_item);
}


static const per_sequence_t SeqOfNavModelElement_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfNavModelElement_item },
};

static int
dissect_rrlp_SeqOfNavModelElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfNavModelElement, SeqOfNavModelElement_sequence_of,
                                                  1, 16);

  return offset;
}
static int dissect_navModelList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfNavModelElement(tvb, offset, pinfo, tree, hf_rrlp_navModelList);
}


static const per_sequence_t NavigationModel_sequence[] = {
  { "navModelList"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_navModelList },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_NavigationModel(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_NavigationModel, NavigationModel_sequence);

  return offset;
}
static int dissect_navigationModel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_NavigationModel(tvb, offset, pinfo, tree, hf_rrlp_navigationModel);
}


static const per_sequence_t IonosphericModel_sequence[] = {
  { "alfa0"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_alfa0 },
  { "alfa1"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_alfa1 },
  { "alfa2"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_alfa2 },
  { "alfa3"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_alfa3 },
  { "beta0"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_beta0 },
  { "beta1"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_beta1 },
  { "beta2"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_beta2 },
  { "beta3"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_beta3 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_IonosphericModel(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_IonosphericModel, IonosphericModel_sequence);

  return offset;
}
static int dissect_ionosphericModel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_IonosphericModel(tvb, offset, pinfo, tree, hf_rrlp_ionosphericModel);
}



static int
dissect_rrlp_INTEGER_0_255(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 255U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_utcTot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_255(tvb, offset, pinfo, tree, hf_rrlp_utcTot);
}
static int dissect_utcWNt(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_255(tvb, offset, pinfo, tree, hf_rrlp_utcWNt);
}
static int dissect_utcWNlsf(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_255(tvb, offset, pinfo, tree, hf_rrlp_utcWNlsf);
}
static int dissect_alamanacWNa(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_255(tvb, offset, pinfo, tree, hf_rrlp_alamanacWNa);
}
static int dissect_alamanacToa(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_255(tvb, offset, pinfo, tree, hf_rrlp_alamanacToa);
}
static int dissect_almanacSVhealth(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_255(tvb, offset, pinfo, tree, hf_rrlp_almanacSVhealth);
}


static const per_sequence_t UTCModel_sequence[] = {
  { "utcA1"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_utcA1 },
  { "utcA0"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_utcA0 },
  { "utcTot"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_utcTot },
  { "utcWNt"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_utcWNt },
  { "utcDeltaTls"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_utcDeltaTls },
  { "utcWNlsf"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_utcWNlsf },
  { "utcDN"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_utcDN },
  { "utcDeltaTlsf"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_utcDeltaTlsf },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_UTCModel(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_UTCModel, UTCModel_sequence);

  return offset;
}
static int dissect_utcModel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_UTCModel(tvb, offset, pinfo, tree, hf_rrlp_utcModel);
}



static int
dissect_rrlp_INTEGER_M1024_1023(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -1024, 1023U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_almanacAF0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M1024_1023(tvb, offset, pinfo, tree, hf_rrlp_almanacAF0);
}
static int dissect_almanacAF1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M1024_1023(tvb, offset, pinfo, tree, hf_rrlp_almanacAF1);
}


static const per_sequence_t AlmanacElement_sequence[] = {
  { "satelliteID"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_satelliteID },
  { "almanacE"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_almanacE },
  { "alamanacToa"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_alamanacToa },
  { "almanacKsii"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_almanacKsii },
  { "almanacOmegaDot"             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_almanacOmegaDot },
  { "almanacSVhealth"             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_almanacSVhealth },
  { "almanacAPowerHalf"           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_almanacAPowerHalf },
  { "almanacOmega0"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_almanacOmega0 },
  { "almanacW"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_almanacW },
  { "almanacM0"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_almanacM0 },
  { "almanacAF0"                  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_almanacAF0 },
  { "almanacAF1"                  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_almanacAF1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AlmanacElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_AlmanacElement, AlmanacElement_sequence);

  return offset;
}
static int dissect_SeqOfAlmanacElement_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_AlmanacElement(tvb, offset, pinfo, tree, hf_rrlp_SeqOfAlmanacElement_item);
}


static const per_sequence_t SeqOfAlmanacElement_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfAlmanacElement_item },
};

static int
dissect_rrlp_SeqOfAlmanacElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfAlmanacElement, SeqOfAlmanacElement_sequence_of,
                                                  1, 64);

  return offset;
}
static int dissect_almanacList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfAlmanacElement(tvb, offset, pinfo, tree, hf_rrlp_almanacList);
}


static const per_sequence_t Almanac_sequence[] = {
  { "alamanacWNa"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_alamanacWNa },
  { "almanacList"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_almanacList },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Almanac(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_Almanac, Almanac_sequence);

  return offset;
}
static int dissect_almanac(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Almanac(tvb, offset, pinfo, tree, hf_rrlp_almanac);
}


static const per_sequence_t TimeRelation_sequence[] = {
  { "gpsTOW"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_gpsTOW3 },
  { "gsmTime"                     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_gsmTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_TimeRelation(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_TimeRelation, TimeRelation_sequence);

  return offset;
}
static int dissect_timeRelation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_TimeRelation(tvb, offset, pinfo, tree, hf_rrlp_timeRelation);
}



static int
dissect_rrlp_INTEGER_M2048_2047(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -2048, 2047U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_doppler0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_M2048_2047(tvb, offset, pinfo, tree, hf_rrlp_doppler0);
}


static const per_sequence_t AddionalDopplerFields_sequence[] = {
  { "doppler1"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_doppler1 },
  { "dopplerUncertainty"          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_dopplerUncertainty },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AddionalDopplerFields(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_AddionalDopplerFields, AddionalDopplerFields_sequence);

  return offset;
}
static int dissect_addionalDoppler(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_AddionalDopplerFields(tvb, offset, pinfo, tree, hf_rrlp_addionalDoppler);
}



static int
dissect_rrlp_INTEGER_0_1022(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 1022U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_wholeChips(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_1022(tvb, offset, pinfo, tree, hf_rrlp_wholeChips);
}
static int dissect_codePhase(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_1022(tvb, offset, pinfo, tree, hf_rrlp_codePhase);
}



static int
dissect_rrlp_INTEGER_0_19(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 19U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_intCodePhase(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_19(tvb, offset, pinfo, tree, hf_rrlp_intCodePhase);
}


static const per_sequence_t AddionalAngleFields_sequence[] = {
  { "azimuth"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_azimuth },
  { "elevation"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_elevation },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AddionalAngleFields(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_AddionalAngleFields, AddionalAngleFields_sequence);

  return offset;
}
static int dissect_addionalAngle(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_AddionalAngleFields(tvb, offset, pinfo, tree, hf_rrlp_addionalAngle);
}


static const per_sequence_t AcquisElement_sequence[] = {
  { "svid"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_svid },
  { "doppler0"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_doppler0 },
  { "addionalDoppler"             , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_addionalDoppler },
  { "codePhase"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_codePhase },
  { "intCodePhase"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_intCodePhase },
  { "gpsBitNumber"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_gpsBitNumber },
  { "codePhaseSearchWindow"       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_codePhaseSearchWindow },
  { "addionalAngle"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_addionalAngle },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AcquisElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_AcquisElement, AcquisElement_sequence);

  return offset;
}
static int dissect_SeqOfAcquisElement_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_AcquisElement(tvb, offset, pinfo, tree, hf_rrlp_SeqOfAcquisElement_item);
}


static const per_sequence_t SeqOfAcquisElement_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfAcquisElement_item },
};

static int
dissect_rrlp_SeqOfAcquisElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfAcquisElement, SeqOfAcquisElement_sequence_of,
                                                  1, 16);

  return offset;
}
static int dissect_acquisList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfAcquisElement(tvb, offset, pinfo, tree, hf_rrlp_acquisList);
}


static const per_sequence_t AcquisAssist_sequence[] = {
  { "timeRelation"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_timeRelation },
  { "acquisList"                  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_acquisList },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AcquisAssist(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_AcquisAssist, AcquisAssist_sequence);

  return offset;
}
static int dissect_acquisAssist(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_AcquisAssist(tvb, offset, pinfo, tree, hf_rrlp_acquisAssist);
}


static const per_sequence_t SeqOf_BadSatelliteSet_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOf_BadSatelliteSet_item },
};

static int
dissect_rrlp_SeqOf_BadSatelliteSet(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOf_BadSatelliteSet, SeqOf_BadSatelliteSet_sequence_of,
                                                  1, 16);

  return offset;
}
static int dissect_realTimeIntegrity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOf_BadSatelliteSet(tvb, offset, pinfo, tree, hf_rrlp_realTimeIntegrity);
}


static const per_sequence_t ControlHeader_sequence[] = {
  { "referenceTime"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_referenceTime },
  { "refLocation"                 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_refLocation },
  { "dgpsCorrections"             , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_dgpsCorrections },
  { "navigationModel"             , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_navigationModel },
  { "ionosphericModel"            , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ionosphericModel },
  { "utcModel"                    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_utcModel },
  { "almanac"                     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_almanac },
  { "acquisAssist"                , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_acquisAssist },
  { "realTimeIntegrity"           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_realTimeIntegrity },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ControlHeader(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_ControlHeader, ControlHeader_sequence);

  return offset;
}
static int dissect_controlHeader(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ControlHeader(tvb, offset, pinfo, tree, hf_rrlp_controlHeader);
}


static const per_sequence_t GPS_AssistData_sequence[] = {
  { "controlHeader"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_controlHeader },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPS_AssistData(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_GPS_AssistData, GPS_AssistData_sequence);

  return offset;
}
static int dissect_gps_AssistData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPS_AssistData(tvb, offset, pinfo, tree, hf_rrlp_gps_AssistData);
}



static int
dissect_rrlp_ExpectedOTD(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 1250U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_expectedOTD(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ExpectedOTD(tvb, offset, pinfo, tree, hf_rrlp_expectedOTD);
}



static int
dissect_rrlp_ExpOTDUncertainty(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 7U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_expOTDUncertainty(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ExpOTDUncertainty(tvb, offset, pinfo, tree, hf_rrlp_expOTDUncertainty);
}
static int dissect_expOTDuncertainty(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ExpOTDUncertainty(tvb, offset, pinfo, tree, hf_rrlp_expOTDuncertainty);
}


static const per_sequence_t MsrAssistBTS_R98_ExpOTD_sequence[] = {
  { "expectedOTD"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_expectedOTD },
  { "expOTDUncertainty"           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_expOTDUncertainty },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MsrAssistBTS_R98_ExpOTD(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_MsrAssistBTS_R98_ExpOTD, MsrAssistBTS_R98_ExpOTD_sequence);

  return offset;
}
static int dissect_SeqOfMsrAssistBTS_R98_ExpOTD_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_MsrAssistBTS_R98_ExpOTD(tvb, offset, pinfo, tree, hf_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD_item);
}


static const per_sequence_t SeqOfMsrAssistBTS_R98_ExpOTD_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfMsrAssistBTS_R98_ExpOTD_item },
};

static int
dissect_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD, SeqOfMsrAssistBTS_R98_ExpOTD_sequence_of,
                                                  1, 15);

  return offset;
}
static int dissect_msrAssistList_R98_ExpOTD(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD(tvb, offset, pinfo, tree, hf_rrlp_msrAssistList_R98_ExpOTD);
}


static const per_sequence_t MsrAssistData_R98_ExpOTD_sequence[] = {
  { "msrAssistList-R98-ExpOTD"    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_msrAssistList_R98_ExpOTD },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MsrAssistData_R98_ExpOTD(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_MsrAssistData_R98_ExpOTD, MsrAssistData_R98_ExpOTD_sequence);

  return offset;
}
static int dissect_msrAssistData_R98_ExpOTD(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_MsrAssistData_R98_ExpOTD(tvb, offset, pinfo, tree, hf_rrlp_msrAssistData_R98_ExpOTD);
}


static const per_sequence_t AssistBTSData_R98_ExpOTD_sequence[] = {
  { "expectedOTD"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_expectedOTD },
  { "expOTDuncertainty"           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_expOTDuncertainty },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AssistBTSData_R98_ExpOTD(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_AssistBTSData_R98_ExpOTD, AssistBTSData_R98_ExpOTD_sequence);

  return offset;
}
static int dissect_present1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_AssistBTSData_R98_ExpOTD(tvb, offset, pinfo, tree, hf_rrlp_present1);
}


static const value_string rrlp_SystemInfoAssistBTS_R98_ExpOTD_vals[] = {
  {   0, "notPresent" },
  {   1, "present" },
  { 0, NULL }
};

static const per_choice_t SystemInfoAssistBTS_R98_ExpOTD_choice[] = {
  {   0, "notPresent"                  , ASN1_NO_EXTENSIONS     , dissect_notPresent },
  {   1, "present"                     , ASN1_NO_EXTENSIONS     , dissect_present1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_SystemInfoAssistBTS_R98_ExpOTD(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_rrlp_SystemInfoAssistBTS_R98_ExpOTD, SystemInfoAssistBTS_R98_ExpOTD_choice,
                                 NULL);

  return offset;
}
static int dissect_SeqOfSystemInfoAssistBTS_R98_ExpOTD_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SystemInfoAssistBTS_R98_ExpOTD(tvb, offset, pinfo, tree, hf_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD_item);
}


static const per_sequence_t SeqOfSystemInfoAssistBTS_R98_ExpOTD_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfSystemInfoAssistBTS_R98_ExpOTD_item },
};

static int
dissect_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD, SeqOfSystemInfoAssistBTS_R98_ExpOTD_sequence_of,
                                                  1, 32);

  return offset;
}
static int dissect_systemInfoAssistListR98_ExpOTD(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD(tvb, offset, pinfo, tree, hf_rrlp_systemInfoAssistListR98_ExpOTD);
}


static const per_sequence_t SystemInfoAssistData_R98_ExpOTD_sequence[] = {
  { "systemInfoAssistListR98-ExpOTD", ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_systemInfoAssistListR98_ExpOTD },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_SystemInfoAssistData_R98_ExpOTD(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_SystemInfoAssistData_R98_ExpOTD, SystemInfoAssistData_R98_ExpOTD_sequence);

  return offset;
}
static int dissect_systemInfoAssistData_R98_ExpOTD(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SystemInfoAssistData_R98_ExpOTD(tvb, offset, pinfo, tree, hf_rrlp_systemInfoAssistData_R98_ExpOTD);
}


static const per_sequence_t Rel98_Ext_ExpOTD_sequence[] = {
  { "msrAssistData-R98-ExpOTD"    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_msrAssistData_R98_ExpOTD },
  { "systemInfoAssistData-R98-ExpOTD", ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_systemInfoAssistData_R98_ExpOTD },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel98_Ext_ExpOTD(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_Rel98_Ext_ExpOTD, Rel98_Ext_ExpOTD_sequence);

  return offset;
}
static int dissect_rel98_Ext_ExpOTD(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Rel98_Ext_ExpOTD(tvb, offset, pinfo, tree, hf_rrlp_rel98_Ext_ExpOTD);
}



static int
dissect_rrlp_GPSReferenceTimeUncertainty(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 127U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_gpsReferenceTimeUncertainty(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPSReferenceTimeUncertainty(tvb, offset, pinfo, tree, hf_rrlp_gpsReferenceTimeUncertainty);
}


static const per_sequence_t Rel98_MsrPosition_Req_Extension_sequence[] = {
  { "rel98-Ext-ExpOTD"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rel98_Ext_ExpOTD },
  { "gpsTimeAssistanceMeasurementRequest", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_gpsTimeAssistanceMeasurementRequest },
  { "gpsReferenceTimeUncertainty" , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_gpsReferenceTimeUncertainty },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel98_MsrPosition_Req_Extension(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_Rel98_MsrPosition_Req_Extension, Rel98_MsrPosition_Req_Extension_sequence);

  return offset;
}
static int dissect_rel98_MsrPosition_Req_extension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Rel98_MsrPosition_Req_Extension(tvb, offset, pinfo, tree, hf_rrlp_rel98_MsrPosition_Req_extension);
}



static int
dissect_rrlp_INTEGER_0_262143(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 262143U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_transaction_ID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_262143(tvb, offset, pinfo, tree, hf_rrlp_transaction_ID);
}


static const per_sequence_t Extended_reference_sequence[] = {
  { "smlc-code"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_smlc_code },
  { "transaction-ID"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_transaction_ID },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Extended_reference(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_Extended_reference, Extended_reference_sequence);

  return offset;
}
static int dissect_extended_reference(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Extended_reference(tvb, offset, pinfo, tree, hf_rrlp_extended_reference);
}


static const per_sequence_t Rel5_MsrPosition_Req_Extension_sequence[] = {
  { "extended-reference"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_extended_reference },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel5_MsrPosition_Req_Extension(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_Rel5_MsrPosition_Req_Extension, Rel5_MsrPosition_Req_Extension_sequence);

  return offset;
}
static int dissect_rel5_MsrPosition_Req_extension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Rel5_MsrPosition_Req_Extension(tvb, offset, pinfo, tree, hf_rrlp_rel5_MsrPosition_Req_extension);
}


static const per_sequence_t MsrPosition_Req_sequence[] = {
  { "positionInstruct"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_positionInstruct },
  { "referenceAssistData"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_referenceAssistData },
  { "msrAssistData"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_msrAssistData },
  { "systemInfoAssistData"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_systemInfoAssistData },
  { "gps-AssistData"              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gps_AssistData },
  { "extensionContainer"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionContainer },
  { "rel98-MsrPosition-Req-extension", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rel98_MsrPosition_Req_extension },
  { "rel5-MsrPosition-Req-extension", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rel5_MsrPosition_Req_extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MsrPosition_Req(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_MsrPosition_Req, MsrPosition_Req_sequence);

  return offset;
}
static int dissect_msrPositionReq(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_MsrPosition_Req(tvb, offset, pinfo, tree, hf_rrlp_msrPositionReq);
}



static int
dissect_rrlp_INTEGER_2_3(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              2U, 3U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_nbrOfSets(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_2_3(tvb, offset, pinfo, tree, hf_rrlp_nbrOfSets);
}



static int
dissect_rrlp_INTEGER_1_3(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              1U, 3U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_nbrOfReferenceBTSs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_1_3(tvb, offset, pinfo, tree, hf_rrlp_nbrOfReferenceBTSs);
}


static const value_string rrlp_ReferenceRelation_vals[] = {
  {   0, "secondBTSThirdSet" },
  {   1, "secondBTSSecondSet" },
  {   2, "firstBTSFirstSet" },
  { 0, NULL }
};


static int
dissect_rrlp_ReferenceRelation(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     3, NULL, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_referenceRelation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ReferenceRelation(tvb, offset, pinfo, tree, hf_rrlp_referenceRelation);
}


static const per_sequence_t MultipleSets_sequence[] = {
  { "nbrOfSets"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nbrOfSets },
  { "nbrOfReferenceBTSs"          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nbrOfReferenceBTSs },
  { "referenceRelation"           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_referenceRelation },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MultipleSets(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_MultipleSets, MultipleSets_sequence);

  return offset;
}
static int dissect_multipleSets(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_MultipleSets(tvb, offset, pinfo, tree, hf_rrlp_multipleSets);
}


static const per_sequence_t BSICAndCarrier_sequence[] = {
  { "carrier"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_carrier },
  { "bsic"                        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_bsic },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_BSICAndCarrier(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_BSICAndCarrier, BSICAndCarrier_sequence);

  return offset;
}
static int dissect_bsicAndCarrier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_BSICAndCarrier(tvb, offset, pinfo, tree, hf_rrlp_bsicAndCarrier);
}



static int
dissect_rrlp_CellID(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 65535U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_ci(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_CellID(tvb, offset, pinfo, tree, hf_rrlp_ci);
}
static int dissect_referenceCI(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_CellID(tvb, offset, pinfo, tree, hf_rrlp_referenceCI);
}



static int
dissect_rrlp_RequestIndex(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              1U, 16U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_requestIndex(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_RequestIndex(tvb, offset, pinfo, tree, hf_rrlp_requestIndex);
}



static int
dissect_rrlp_SystemInfoIndex(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              1U, 32U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_systemInfoIndex(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SystemInfoIndex(tvb, offset, pinfo, tree, hf_rrlp_systemInfoIndex);
}



static int
dissect_rrlp_LAC(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 65535U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_referenceLAC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_LAC(tvb, offset, pinfo, tree, hf_rrlp_referenceLAC);
}


static const per_sequence_t CellIDAndLAC_sequence[] = {
  { "referenceLAC"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_referenceLAC },
  { "referenceCI"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_referenceCI },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_CellIDAndLAC(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_CellIDAndLAC, CellIDAndLAC_sequence);

  return offset;
}
static int dissect_ciAndLAC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_CellIDAndLAC(tvb, offset, pinfo, tree, hf_rrlp_ciAndLAC);
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
  {   0, "bsicAndCarrier"              , ASN1_NO_EXTENSIONS     , dissect_bsicAndCarrier },
  {   1, "ci"                          , ASN1_NO_EXTENSIONS     , dissect_ci },
  {   2, "requestIndex"                , ASN1_NO_EXTENSIONS     , dissect_requestIndex },
  {   3, "systemInfoIndex"             , ASN1_NO_EXTENSIONS     , dissect_systemInfoIndex },
  {   4, "ciAndLAC"                    , ASN1_NO_EXTENSIONS     , dissect_ciAndLAC },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_ReferenceIdentityType(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_rrlp_ReferenceIdentityType, ReferenceIdentityType_choice,
                                 NULL);

  return offset;
}
static int dissect_SeqOfReferenceIdentityType_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ReferenceIdentityType(tvb, offset, pinfo, tree, hf_rrlp_SeqOfReferenceIdentityType_item);
}


static const per_sequence_t SeqOfReferenceIdentityType_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfReferenceIdentityType_item },
};

static int
dissect_rrlp_SeqOfReferenceIdentityType(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfReferenceIdentityType, SeqOfReferenceIdentityType_sequence_of,
                                                  1, 3);

  return offset;
}
static int dissect_refBTSList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfReferenceIdentityType(tvb, offset, pinfo, tree, hf_rrlp_refBTSList);
}


static const per_sequence_t ReferenceIdentity_sequence[] = {
  { "refBTSList"                  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_refBTSList },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ReferenceIdentity(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_ReferenceIdentity, ReferenceIdentity_sequence);

  return offset;
}
static int dissect_referenceIdentity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ReferenceIdentity(tvb, offset, pinfo, tree, hf_rrlp_referenceIdentity);
}



static int
dissect_rrlp_INTEGER_0_42431(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 42431U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_refFrameNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_42431(tvb, offset, pinfo, tree, hf_rrlp_refFrameNumber);
}



static int
dissect_rrlp_ModuloTimeSlot(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 3U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_referenceTimeSlot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ModuloTimeSlot(tvb, offset, pinfo, tree, hf_rrlp_referenceTimeSlot);
}
static int dissect_nborTimeSlot(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ModuloTimeSlot(tvb, offset, pinfo, tree, hf_rrlp_nborTimeSlot);
}



static int
dissect_rrlp_RefQuality(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 31U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_refQuality(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_RefQuality(tvb, offset, pinfo, tree, hf_rrlp_refQuality);
}



static int
dissect_rrlp_NumOfMeasurements(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 7U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_numOfMeasurements(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_NumOfMeasurements(tvb, offset, pinfo, tree, hf_rrlp_numOfMeasurements);
}


static const per_sequence_t TOA_MeasurementsOfRef_sequence[] = {
  { "refQuality"                  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_refQuality },
  { "numOfMeasurements"           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_numOfMeasurements },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_TOA_MeasurementsOfRef(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_TOA_MeasurementsOfRef, TOA_MeasurementsOfRef_sequence);

  return offset;
}
static int dissect_toaMeasurementsOfRef(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_TOA_MeasurementsOfRef(tvb, offset, pinfo, tree, hf_rrlp_toaMeasurementsOfRef);
}



static int
dissect_rrlp_StdResolution(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 3U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_stdResolution(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_StdResolution(tvb, offset, pinfo, tree, hf_rrlp_stdResolution);
}



static int
dissect_rrlp_INTEGER_0_960(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 960U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_taCorrection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_960(tvb, offset, pinfo, tree, hf_rrlp_taCorrection);
}


static const per_sequence_t MultiFrameCarrier_sequence[] = {
  { "bcchCarrier"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_bcchCarrier },
  { "multiFrameOffset"            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_multiFrameOffset },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MultiFrameCarrier(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_MultiFrameCarrier, MultiFrameCarrier_sequence);

  return offset;
}
static int dissect_multiFrameCarrier(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_MultiFrameCarrier(tvb, offset, pinfo, tree, hf_rrlp_multiFrameCarrier);
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
  {   0, "bsicAndCarrier"              , ASN1_NO_EXTENSIONS     , dissect_bsicAndCarrier },
  {   1, "ci"                          , ASN1_NO_EXTENSIONS     , dissect_ci },
  {   2, "multiFrameCarrier"           , ASN1_NO_EXTENSIONS     , dissect_multiFrameCarrier },
  {   3, "requestIndex"                , ASN1_NO_EXTENSIONS     , dissect_requestIndex },
  {   4, "systemInfoIndex"             , ASN1_NO_EXTENSIONS     , dissect_systemInfoIndex },
  {   5, "ciAndLAC"                    , ASN1_NO_EXTENSIONS     , dissect_ciAndLAC },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_NeighborIdentity(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_rrlp_NeighborIdentity, NeighborIdentity_choice,
                                 NULL);

  return offset;
}
static int dissect_neighborIdentity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_NeighborIdentity(tvb, offset, pinfo, tree, hf_rrlp_neighborIdentity);
}


static const per_sequence_t EOTDQuality_sequence[] = {
  { "nbrOfMeasurements"           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nbrOfMeasurements },
  { "stdOfEOTD"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_stdOfEOTD },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_EOTDQuality(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_EOTDQuality, EOTDQuality_sequence);

  return offset;
}
static int dissect_eotdQuality(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_EOTDQuality(tvb, offset, pinfo, tree, hf_rrlp_eotdQuality);
}



static int
dissect_rrlp_OTDValue(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 39999U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_otdValue(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_OTDValue(tvb, offset, pinfo, tree, hf_rrlp_otdValue);
}


static const per_sequence_t OTD_MeasurementWithID_sequence[] = {
  { "neighborIdentity"            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_neighborIdentity },
  { "nborTimeSlot"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nborTimeSlot },
  { "eotdQuality"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_eotdQuality },
  { "otdValue"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_otdValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_MeasurementWithID(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_OTD_MeasurementWithID, OTD_MeasurementWithID_sequence);

  return offset;
}
static int dissect_identityPresent(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_OTD_MeasurementWithID(tvb, offset, pinfo, tree, hf_rrlp_identityPresent);
}



static int
dissect_rrlp_OTD_FirstSetMsrs(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_rrlp_OTD_MeasurementWithID(tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_SeqOfOTD_FirstSetMsrs_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_OTD_FirstSetMsrs(tvb, offset, pinfo, tree, hf_rrlp_SeqOfOTD_FirstSetMsrs_item);
}
static int dissect_SeqOfOTD_FirstSetMsrs_R98_Ext_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_OTD_FirstSetMsrs(tvb, offset, pinfo, tree, hf_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext_item);
}


static const per_sequence_t SeqOfOTD_FirstSetMsrs_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfOTD_FirstSetMsrs_item },
};

static int
dissect_rrlp_SeqOfOTD_FirstSetMsrs(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfOTD_FirstSetMsrs, SeqOfOTD_FirstSetMsrs_sequence_of,
                                                  1, 10);

  return offset;
}
static int dissect_otd_FirstSetMsrs(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfOTD_FirstSetMsrs(tvb, offset, pinfo, tree, hf_rrlp_otd_FirstSetMsrs);
}


static const per_sequence_t OTD_MsrElementFirst_sequence[] = {
  { "refFrameNumber"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_refFrameNumber },
  { "referenceTimeSlot"           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_referenceTimeSlot },
  { "toaMeasurementsOfRef"        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_toaMeasurementsOfRef },
  { "stdResolution"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_stdResolution },
  { "taCorrection"                , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_taCorrection },
  { "otd-FirstSetMsrs"            , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_otd_FirstSetMsrs },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_MsrElementFirst(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_OTD_MsrElementFirst, OTD_MsrElementFirst_sequence);

  return offset;
}
static int dissect_otdMsrFirstSets(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_OTD_MsrElementFirst(tvb, offset, pinfo, tree, hf_rrlp_otdMsrFirstSets);
}


static const per_sequence_t OTD_Measurement_sequence[] = {
  { "nborTimeSlot"                , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_nborTimeSlot },
  { "eotdQuality"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_eotdQuality },
  { "otdValue"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_otdValue },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_Measurement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_OTD_Measurement, OTD_Measurement_sequence);

  return offset;
}
static int dissect_identityNotPresent(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_OTD_Measurement(tvb, offset, pinfo, tree, hf_rrlp_identityNotPresent);
}


static const value_string rrlp_OTD_MsrsOfOtherSets_vals[] = {
  {   0, "identityNotPresent" },
  {   1, "identityPresent" },
  { 0, NULL }
};

static const per_choice_t OTD_MsrsOfOtherSets_choice[] = {
  {   0, "identityNotPresent"          , ASN1_NO_EXTENSIONS     , dissect_identityNotPresent },
  {   1, "identityPresent"             , ASN1_NO_EXTENSIONS     , dissect_identityPresent },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_OTD_MsrsOfOtherSets(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_rrlp_OTD_MsrsOfOtherSets, OTD_MsrsOfOtherSets_choice,
                                 NULL);

  return offset;
}
static int dissect_SeqOfOTD_MsrsOfOtherSets_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_OTD_MsrsOfOtherSets(tvb, offset, pinfo, tree, hf_rrlp_SeqOfOTD_MsrsOfOtherSets_item);
}


static const per_sequence_t SeqOfOTD_MsrsOfOtherSets_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfOTD_MsrsOfOtherSets_item },
};

static int
dissect_rrlp_SeqOfOTD_MsrsOfOtherSets(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfOTD_MsrsOfOtherSets, SeqOfOTD_MsrsOfOtherSets_sequence_of,
                                                  1, 10);

  return offset;
}
static int dissect_otd_MsrsOfOtherSets(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfOTD_MsrsOfOtherSets(tvb, offset, pinfo, tree, hf_rrlp_otd_MsrsOfOtherSets);
}


static const per_sequence_t OTD_MsrElementRest_sequence[] = {
  { "refFrameNumber"              , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_refFrameNumber },
  { "referenceTimeSlot"           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_referenceTimeSlot },
  { "toaMeasurementsOfRef"        , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_toaMeasurementsOfRef },
  { "stdResolution"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_stdResolution },
  { "taCorrection"                , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_taCorrection },
  { "otd-MsrsOfOtherSets"         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_otd_MsrsOfOtherSets },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_MsrElementRest(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_OTD_MsrElementRest, OTD_MsrElementRest_sequence);

  return offset;
}
static int dissect_SeqOfOTD_MsrElementRest_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_OTD_MsrElementRest(tvb, offset, pinfo, tree, hf_rrlp_SeqOfOTD_MsrElementRest_item);
}


static const per_sequence_t SeqOfOTD_MsrElementRest_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfOTD_MsrElementRest_item },
};

static int
dissect_rrlp_SeqOfOTD_MsrElementRest(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfOTD_MsrElementRest, SeqOfOTD_MsrElementRest_sequence_of,
                                                  1, 2);

  return offset;
}
static int dissect_otdMsrRestSets(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfOTD_MsrElementRest(tvb, offset, pinfo, tree, hf_rrlp_otdMsrRestSets);
}


static const per_sequence_t OTD_MeasureInfo_sequence[] = {
  { "otdMsrFirstSets"             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_otdMsrFirstSets },
  { "otdMsrRestSets"              , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_otdMsrRestSets },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_MeasureInfo(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_OTD_MeasureInfo, OTD_MeasureInfo_sequence);

  return offset;
}
static int dissect_otd_MeasureInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_OTD_MeasureInfo(tvb, offset, pinfo, tree, hf_rrlp_otd_MeasureInfo);
}



static int
dissect_rrlp_INTEGER_0_14399999(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 14399999U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_gpsTOW(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_14399999(tvb, offset, pinfo, tree, hf_rrlp_gpsTOW);
}


static const value_string rrlp_FixType_vals[] = {
  {   0, "twoDFix" },
  {   1, "threeDFix" },
  { 0, NULL }
};


static int
dissect_rrlp_FixType(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 1U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_fixType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_FixType(tvb, offset, pinfo, tree, hf_rrlp_fixType);
}


static const per_sequence_t LocationInfo_sequence[] = {
  { "refFrame"                    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_refFrame },
  { "gpsTOW"                      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_gpsTOW },
  { "fixType"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_fixType },
  { "posEstimate"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_posEstimate },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_LocationInfo(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_LocationInfo, LocationInfo_sequence);

  return offset;
}
static int dissect_locationInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_LocationInfo(tvb, offset, pinfo, tree, hf_rrlp_locationInfo);
}



static int
dissect_rrlp_GPSTOW24b(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 14399999U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_gpsTOW1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPSTOW24b(tvb, offset, pinfo, tree, hf_rrlp_gpsTOW1);
}



static int
dissect_rrlp_INTEGER_0_1024(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 1024U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_fracChips(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_1024(tvb, offset, pinfo, tree, hf_rrlp_fracChips);
}


static const value_string rrlp_MpathIndic_vals[] = {
  {   0, "notMeasured" },
  {   1, "low" },
  {   2, "medium" },
  {   3, "high" },
  { 0, NULL }
};


static int
dissect_rrlp_MpathIndic(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     4, NULL, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_mpathIndic(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_MpathIndic(tvb, offset, pinfo, tree, hf_rrlp_mpathIndic);
}


static const per_sequence_t GPS_MsrElement_sequence[] = {
  { "satelliteID"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_satelliteID },
  { "cNo"                         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cNo },
  { "doppler"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_doppler },
  { "wholeChips"                  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_wholeChips },
  { "fracChips"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_fracChips },
  { "mpathIndic"                  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_mpathIndic },
  { "pseuRangeRMSErr"             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_pseuRangeRMSErr },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPS_MsrElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_GPS_MsrElement, GPS_MsrElement_sequence);

  return offset;
}
static int dissect_SeqOfGPS_MsrElement_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPS_MsrElement(tvb, offset, pinfo, tree, hf_rrlp_SeqOfGPS_MsrElement_item);
}


static const per_sequence_t SeqOfGPS_MsrElement_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfGPS_MsrElement_item },
};

static int
dissect_rrlp_SeqOfGPS_MsrElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfGPS_MsrElement, SeqOfGPS_MsrElement_sequence_of,
                                                  1, 16);

  return offset;
}
static int dissect_gps_msrList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfGPS_MsrElement(tvb, offset, pinfo, tree, hf_rrlp_gps_msrList);
}


static const per_sequence_t GPS_MsrSetElement_sequence[] = {
  { "refFrame"                    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_refFrame },
  { "gpsTOW"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_gpsTOW1 },
  { "gps-msrList"                 , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_gps_msrList },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPS_MsrSetElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_GPS_MsrSetElement, GPS_MsrSetElement_sequence);

  return offset;
}
static int dissect_SeqOfGPS_MsrSetElement_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPS_MsrSetElement(tvb, offset, pinfo, tree, hf_rrlp_SeqOfGPS_MsrSetElement_item);
}


static const per_sequence_t SeqOfGPS_MsrSetElement_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfGPS_MsrSetElement_item },
};

static int
dissect_rrlp_SeqOfGPS_MsrSetElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfGPS_MsrSetElement, SeqOfGPS_MsrSetElement_sequence_of,
                                                  1, 3);

  return offset;
}
static int dissect_gpsMsrSetList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfGPS_MsrSetElement(tvb, offset, pinfo, tree, hf_rrlp_gpsMsrSetList);
}


static const per_sequence_t GPS_MeasureInfo_sequence[] = {
  { "gpsMsrSetList"               , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_gpsMsrSetList },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPS_MeasureInfo(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_GPS_MeasureInfo, GPS_MeasureInfo_sequence);

  return offset;
}
static int dissect_gps_MeasureInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPS_MeasureInfo(tvb, offset, pinfo, tree, hf_rrlp_gps_MeasureInfo);
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
  { 0, NULL }
};


static int
dissect_rrlp_LocErrorReason(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     11, NULL, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_locErrorReason(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_LocErrorReason(tvb, offset, pinfo, tree, hf_rrlp_locErrorReason);
}



static int
dissect_rrlp_GPSAssistanceData(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index,
                                       1, maxGPSAssistanceData, NULL);

  return offset;
}
static int dissect_gpsAssistanceData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPSAssistanceData(tvb, offset, pinfo, tree, hf_rrlp_gpsAssistanceData);
}


static const per_sequence_t AdditionalAssistanceData_sequence[] = {
  { "gpsAssistanceData"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gpsAssistanceData },
  { "extensionContainer"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionContainer },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AdditionalAssistanceData(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_AdditionalAssistanceData, AdditionalAssistanceData_sequence);

  return offset;
}
static int dissect_additionalAssistanceData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_AdditionalAssistanceData(tvb, offset, pinfo, tree, hf_rrlp_additionalAssistanceData);
}


static const per_sequence_t LocationError_sequence[] = {
  { "locErrorReason"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_locErrorReason },
  { "additionalAssistanceData"    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_additionalAssistanceData },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_LocationError(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_LocationError, LocationError_sequence);

  return offset;
}
static int dissect_locationError(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_LocationError(tvb, offset, pinfo, tree, hf_rrlp_locationError);
}


static const per_sequence_t SeqOfOTD_FirstSetMsrs_R98_Ext_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SeqOfOTD_FirstSetMsrs_R98_Ext_item },
};

static int
dissect_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext, SeqOfOTD_FirstSetMsrs_R98_Ext_sequence_of,
                                                  1, 5);

  return offset;
}
static int dissect_otd_FirstSetMsrs_R98_Ext(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext(tvb, offset, pinfo, tree, hf_rrlp_otd_FirstSetMsrs_R98_Ext);
}


static const per_sequence_t OTD_MsrElementFirst_R98_Ext_sequence[] = {
  { "otd-FirstSetMsrs-R98-Ext"    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_otd_FirstSetMsrs_R98_Ext },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_MsrElementFirst_R98_Ext(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_OTD_MsrElementFirst_R98_Ext, OTD_MsrElementFirst_R98_Ext_sequence);

  return offset;
}
static int dissect_otdMsrFirstSets_R98_Ext(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_OTD_MsrElementFirst_R98_Ext(tvb, offset, pinfo, tree, hf_rrlp_otdMsrFirstSets_R98_Ext);
}


static const per_sequence_t OTD_MeasureInfo_R98_Ext_sequence[] = {
  { "otdMsrFirstSets-R98-Ext"     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_otdMsrFirstSets_R98_Ext },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_OTD_MeasureInfo_R98_Ext(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_OTD_MeasureInfo_R98_Ext, OTD_MeasureInfo_R98_Ext_sequence);

  return offset;
}
static int dissect_otd_MeasureInfo_R98_Ext(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_OTD_MeasureInfo_R98_Ext(tvb, offset, pinfo, tree, hf_rrlp_otd_MeasureInfo_R98_Ext);
}


static const per_sequence_t T_rel_98_Ext_MeasureInfo_sequence[] = {
  { "otd-MeasureInfo-R98-Ext"     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_otd_MeasureInfo_R98_Ext },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_T_rel_98_Ext_MeasureInfo(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_T_rel_98_Ext_MeasureInfo, T_rel_98_Ext_MeasureInfo_sequence);

  return offset;
}
static int dissect_rel_98_Ext_MeasureInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_T_rel_98_Ext_MeasureInfo(tvb, offset, pinfo, tree, hf_rrlp_rel_98_Ext_MeasureInfo);
}



static int
dissect_rrlp_INTEGER_0_9999(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 9999U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_gpsTowSubms(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_9999(tvb, offset, pinfo, tree, hf_rrlp_gpsTowSubms);
}



static int
dissect_rrlp_INTEGER_0_127(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 127U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_deltaTow(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_INTEGER_0_127(tvb, offset, pinfo, tree, hf_rrlp_deltaTow);
}


static const per_sequence_t GPSTimeAssistanceMeasurements_sequence[] = {
  { "referenceFrameMSB"           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_referenceFrameMSB },
  { "gpsTowSubms"                 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_gpsTowSubms },
  { "deltaTow"                    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_deltaTow },
  { "gpsReferenceTimeUncertainty" , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_gpsReferenceTimeUncertainty },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GPSTimeAssistanceMeasurements(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_GPSTimeAssistanceMeasurements, GPSTimeAssistanceMeasurements_sequence);

  return offset;
}
static int dissect_timeAssistanceMeasurements(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_GPSTimeAssistanceMeasurements(tvb, offset, pinfo, tree, hf_rrlp_timeAssistanceMeasurements);
}


static const per_sequence_t Rel_98_MsrPosition_Rsp_Extension_sequence[] = {
  { "rel-98-Ext-MeasureInfo"      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rel_98_Ext_MeasureInfo },
  { "timeAssistanceMeasurements"  , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_timeAssistanceMeasurements },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel_98_MsrPosition_Rsp_Extension(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_Rel_98_MsrPosition_Rsp_Extension, Rel_98_MsrPosition_Rsp_Extension_sequence);

  return offset;
}
static int dissect_rel_98_MsrPosition_Rsp_Extension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Rel_98_MsrPosition_Rsp_Extension(tvb, offset, pinfo, tree, hf_rrlp_rel_98_MsrPosition_Rsp_Extension);
}



static int
dissect_rrlp_OTD_MeasureInfo_5_Ext(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_rrlp_SeqOfOTD_MsrElementRest(tvb, offset, pinfo, tree, hf_index);

  return offset;
}
static int dissect_otd_MeasureInfo_5_Ext(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_OTD_MeasureInfo_5_Ext(tvb, offset, pinfo, tree, hf_rrlp_otd_MeasureInfo_5_Ext);
}


static const value_string rrlp_UlPseudoSegInd_vals[] = {
  {   0, "firstOfMany" },
  {   1, "secondOfMany" },
  { 0, NULL }
};


static int
dissect_rrlp_UlPseudoSegInd(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     2, NULL, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_ulPseudoSegInd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_UlPseudoSegInd(tvb, offset, pinfo, tree, hf_rrlp_ulPseudoSegInd);
}


static const per_sequence_t Rel_5_MsrPosition_Rsp_Extension_sequence[] = {
  { "extended-reference"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extended_reference },
  { "otd-MeasureInfo-5-Ext"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_otd_MeasureInfo_5_Ext },
  { "ulPseudoSegInd"              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulPseudoSegInd },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel_5_MsrPosition_Rsp_Extension(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_Rel_5_MsrPosition_Rsp_Extension, Rel_5_MsrPosition_Rsp_Extension_sequence);

  return offset;
}
static int dissect_rel_5_MsrPosition_Rsp_Extension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Rel_5_MsrPosition_Rsp_Extension(tvb, offset, pinfo, tree, hf_rrlp_rel_5_MsrPosition_Rsp_Extension);
}


static const per_sequence_t MsrPosition_Rsp_sequence[] = {
  { "multipleSets"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_multipleSets },
  { "referenceIdentity"           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_referenceIdentity },
  { "otd-MeasureInfo"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_otd_MeasureInfo },
  { "locationInfo"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_locationInfo },
  { "gps-MeasureInfo"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gps_MeasureInfo },
  { "locationError"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_locationError },
  { "extensionContainer"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionContainer },
  { "rel-98-MsrPosition-Rsp-Extension", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rel_98_MsrPosition_Rsp_Extension },
  { "rel-5-MsrPosition-Rsp-Extension", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rel_5_MsrPosition_Rsp_Extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_MsrPosition_Rsp(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_MsrPosition_Rsp, MsrPosition_Rsp_sequence);

  return offset;
}
static int dissect_msrPositionRsp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_MsrPosition_Rsp(tvb, offset, pinfo, tree, hf_rrlp_msrPositionRsp);
}


static const value_string rrlp_MoreAssDataToBeSent_vals[] = {
  {   0, "noMoreMessages" },
  {   1, "moreMessagesOnTheWay" },
  { 0, NULL }
};


static int
dissect_rrlp_MoreAssDataToBeSent(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     2, NULL, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_moreAssDataToBeSent(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_MoreAssDataToBeSent(tvb, offset, pinfo, tree, hf_rrlp_moreAssDataToBeSent);
}


static const per_sequence_t Rel98_AssistanceData_Extension_sequence[] = {
  { "rel98-Ext-ExpOTD"            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rel98_Ext_ExpOTD },
  { "gpsTimeAssistanceMeasurementRequest", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_gpsTimeAssistanceMeasurementRequest },
  { "gpsReferenceTimeUncertainty" , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_gpsReferenceTimeUncertainty },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel98_AssistanceData_Extension(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_Rel98_AssistanceData_Extension, Rel98_AssistanceData_Extension_sequence);

  return offset;
}
static int dissect_rel98_AssistanceData_Extension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Rel98_AssistanceData_Extension(tvb, offset, pinfo, tree, hf_rrlp_rel98_AssistanceData_Extension);
}


static const per_sequence_t Rel5_AssistanceData_Extension_sequence[] = {
  { "extended-reference"          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_extended_reference },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel5_AssistanceData_Extension(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_Rel5_AssistanceData_Extension, Rel5_AssistanceData_Extension_sequence);

  return offset;
}
static int dissect_rel5_AssistanceData_Extension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Rel5_AssistanceData_Extension(tvb, offset, pinfo, tree, hf_rrlp_rel5_AssistanceData_Extension);
}


static const per_sequence_t AssistanceData_sequence[] = {
  { "referenceAssistData"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_referenceAssistData },
  { "msrAssistData"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_msrAssistData },
  { "systemInfoAssistData"        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_systemInfoAssistData },
  { "gps-AssistData"              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_gps_AssistData },
  { "moreAssDataToBeSent"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_moreAssDataToBeSent },
  { "extensionContainer"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionContainer },
  { "rel98-AssistanceData-Extension", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rel98_AssistanceData_Extension },
  { "rel5-AssistanceData-Extension", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rel5_AssistanceData_Extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_AssistanceData(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_AssistanceData, AssistanceData_sequence);

  return offset;
}
static int dissect_assistanceData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_AssistanceData(tvb, offset, pinfo, tree, hf_rrlp_assistanceData);
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
dissect_rrlp_ErrorCodes(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     6, NULL, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_errorCause(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ErrorCodes(tvb, offset, pinfo, tree, hf_rrlp_errorCause);
}


static const per_sequence_t Rel_5_ProtocolError_Extension_sequence[] = {
  { "extended-reference"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extended_reference },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_Rel_5_ProtocolError_Extension(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_Rel_5_ProtocolError_Extension, Rel_5_ProtocolError_Extension_sequence);

  return offset;
}
static int dissect_rel_5_ProtocolError_Extension(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_Rel_5_ProtocolError_Extension(tvb, offset, pinfo, tree, hf_rrlp_rel_5_ProtocolError_Extension);
}


static const per_sequence_t ProtocolError_sequence[] = {
  { "errorCause"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_errorCause },
  { "extensionContainer"          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_extensionContainer },
  { "rel-5-ProtocolError-Extension", ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_rel_5_ProtocolError_Extension },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_ProtocolError(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_ProtocolError, ProtocolError_sequence);

  return offset;
}
static int dissect_protocolError(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_ProtocolError(tvb, offset, pinfo, tree, hf_rrlp_protocolError);
}


static const value_string rrlp_RRLP_Component_vals[] = {
  {   0, "msrPositionReq" },
  {   1, "msrPositionRsp" },
  {   2, "assistanceData" },
  {   3, "assistanceDataAck" },
  {   4, "protocolError" },
  { 0, NULL }
};

static const per_choice_t RRLP_Component_choice[] = {
  {   0, "msrPositionReq"              , ASN1_EXTENSION_ROOT    , dissect_msrPositionReq },
  {   1, "msrPositionRsp"              , ASN1_EXTENSION_ROOT    , dissect_msrPositionRsp },
  {   2, "assistanceData"              , ASN1_EXTENSION_ROOT    , dissect_assistanceData },
  {   3, "assistanceDataAck"           , ASN1_EXTENSION_ROOT    , dissect_assistanceDataAck },
  {   4, "protocolError"               , ASN1_EXTENSION_ROOT    , dissect_protocolError },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_RRLP_Component(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_rrlp_RRLP_Component, RRLP_Component_choice,
                                 NULL);

  return offset;
}
static int dissect_component(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_rrlp_RRLP_Component(tvb, offset, pinfo, tree, hf_rrlp_component);
}


static const per_sequence_t PDU_sequence[] = {
  { "referenceNumber"             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_referenceNumber },
  { "component"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_component },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_PDU(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
#line 10 "rrlp.cnf"

	proto_tree_add_item(tree, proto_rrlp, tvb, 0, -1, FALSE);

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

    offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_rrlp_PDU, PDU_sequence);



  return offset;
}

/*--- PDUs ---*/

static void dissect_PDU_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  per_aligment_type_callback(FALSE);
  dissect_rrlp_PDU(tvb, 0, pinfo, tree, hf_rrlp_PDU_PDU);
}


/*--- End of included file: packet-rrlp-fn.c ---*/
#line 82 "packet-rrlp-template.c"


/*--- proto_register_rrlp -------------------------------------------*/
void proto_register_rrlp(void) {

  /* List of fields */
  static hf_register_info hf[] = {


/*--- Included file: packet-rrlp-hfarr.c ---*/
#line 1 "packet-rrlp-hfarr.c"
    { &hf_rrlp_PDU_PDU,
      { "PDU", "rrlp.PDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "PDU", HFILL }},
    { &hf_rrlp_referenceNumber,
      { "referenceNumber", "rrlp.referenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PDU/referenceNumber", HFILL }},
    { &hf_rrlp_component,
      { "component", "rrlp.component",
        FT_UINT32, BASE_DEC, VALS(rrlp_RRLP_Component_vals), 0,
        "PDU/component", HFILL }},
    { &hf_rrlp_msrPositionReq,
      { "msrPositionReq", "rrlp.msrPositionReq",
        FT_NONE, BASE_NONE, NULL, 0,
        "RRLP-Component/msrPositionReq", HFILL }},
    { &hf_rrlp_msrPositionRsp,
      { "msrPositionRsp", "rrlp.msrPositionRsp",
        FT_NONE, BASE_NONE, NULL, 0,
        "RRLP-Component/msrPositionRsp", HFILL }},
    { &hf_rrlp_assistanceData,
      { "assistanceData", "rrlp.assistanceData",
        FT_NONE, BASE_NONE, NULL, 0,
        "RRLP-Component/assistanceData", HFILL }},
    { &hf_rrlp_assistanceDataAck,
      { "assistanceDataAck", "rrlp.assistanceDataAck",
        FT_NONE, BASE_NONE, NULL, 0,
        "RRLP-Component/assistanceDataAck", HFILL }},
    { &hf_rrlp_protocolError,
      { "protocolError", "rrlp.protocolError",
        FT_NONE, BASE_NONE, NULL, 0,
        "RRLP-Component/protocolError", HFILL }},
    { &hf_rrlp_positionInstruct,
      { "positionInstruct", "rrlp.positionInstruct",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsrPosition-Req/positionInstruct", HFILL }},
    { &hf_rrlp_referenceAssistData,
      { "referenceAssistData", "rrlp.referenceAssistData",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_msrAssistData,
      { "msrAssistData", "rrlp.msrAssistData",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_systemInfoAssistData,
      { "systemInfoAssistData", "rrlp.systemInfoAssistData",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_gps_AssistData,
      { "gps-AssistData", "rrlp.gps_AssistData",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_extensionContainer,
      { "extensionContainer", "rrlp.extensionContainer",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_rel98_MsrPosition_Req_extension,
      { "rel98-MsrPosition-Req-extension", "rrlp.rel98_MsrPosition_Req_extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsrPosition-Req/rel98-MsrPosition-Req-extension", HFILL }},
    { &hf_rrlp_rel5_MsrPosition_Req_extension,
      { "rel5-MsrPosition-Req-extension", "rrlp.rel5_MsrPosition_Req_extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsrPosition-Req/rel5-MsrPosition-Req-extension", HFILL }},
    { &hf_rrlp_multipleSets,
      { "multipleSets", "rrlp.multipleSets",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsrPosition-Rsp/multipleSets", HFILL }},
    { &hf_rrlp_referenceIdentity,
      { "referenceIdentity", "rrlp.referenceIdentity",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsrPosition-Rsp/referenceIdentity", HFILL }},
    { &hf_rrlp_otd_MeasureInfo,
      { "otd-MeasureInfo", "rrlp.otd_MeasureInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsrPosition-Rsp/otd-MeasureInfo", HFILL }},
    { &hf_rrlp_locationInfo,
      { "locationInfo", "rrlp.locationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsrPosition-Rsp/locationInfo", HFILL }},
    { &hf_rrlp_gps_MeasureInfo,
      { "gps-MeasureInfo", "rrlp.gps_MeasureInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsrPosition-Rsp/gps-MeasureInfo", HFILL }},
    { &hf_rrlp_locationError,
      { "locationError", "rrlp.locationError",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsrPosition-Rsp/locationError", HFILL }},
    { &hf_rrlp_rel_98_MsrPosition_Rsp_Extension,
      { "rel-98-MsrPosition-Rsp-Extension", "rrlp.rel_98_MsrPosition_Rsp_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsrPosition-Rsp/rel-98-MsrPosition-Rsp-Extension", HFILL }},
    { &hf_rrlp_rel_5_MsrPosition_Rsp_Extension,
      { "rel-5-MsrPosition-Rsp-Extension", "rrlp.rel_5_MsrPosition_Rsp_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "MsrPosition-Rsp/rel-5-MsrPosition-Rsp-Extension", HFILL }},
    { &hf_rrlp_moreAssDataToBeSent,
      { "moreAssDataToBeSent", "rrlp.moreAssDataToBeSent",
        FT_UINT32, BASE_DEC, VALS(rrlp_MoreAssDataToBeSent_vals), 0,
        "AssistanceData/moreAssDataToBeSent", HFILL }},
    { &hf_rrlp_rel98_AssistanceData_Extension,
      { "rel98-AssistanceData-Extension", "rrlp.rel98_AssistanceData_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "AssistanceData/rel98-AssistanceData-Extension", HFILL }},
    { &hf_rrlp_rel5_AssistanceData_Extension,
      { "rel5-AssistanceData-Extension", "rrlp.rel5_AssistanceData_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "AssistanceData/rel5-AssistanceData-Extension", HFILL }},
    { &hf_rrlp_errorCause,
      { "errorCause", "rrlp.errorCause",
        FT_UINT32, BASE_DEC, VALS(rrlp_ErrorCodes_vals), 0,
        "ProtocolError/errorCause", HFILL }},
    { &hf_rrlp_rel_5_ProtocolError_Extension,
      { "rel-5-ProtocolError-Extension", "rrlp.rel_5_ProtocolError_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProtocolError/rel-5-ProtocolError-Extension", HFILL }},
    { &hf_rrlp_methodType,
      { "methodType", "rrlp.methodType",
        FT_UINT32, BASE_DEC, VALS(rrlp_MethodType_vals), 0,
        "PositionInstruct/methodType", HFILL }},
    { &hf_rrlp_positionMethod,
      { "positionMethod", "rrlp.positionMethod",
        FT_UINT32, BASE_DEC, VALS(rrlp_PositionMethod_vals), 0,
        "PositionInstruct/positionMethod", HFILL }},
    { &hf_rrlp_measureResponseTime,
      { "measureResponseTime", "rrlp.measureResponseTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PositionInstruct/measureResponseTime", HFILL }},
    { &hf_rrlp_useMultipleSets,
      { "useMultipleSets", "rrlp.useMultipleSets",
        FT_UINT32, BASE_DEC, VALS(rrlp_UseMultipleSets_vals), 0,
        "PositionInstruct/useMultipleSets", HFILL }},
    { &hf_rrlp_environmentCharacter,
      { "environmentCharacter", "rrlp.environmentCharacter",
        FT_UINT32, BASE_DEC, VALS(rrlp_EnvironmentCharacter_vals), 0,
        "PositionInstruct/environmentCharacter", HFILL }},
    { &hf_rrlp_msAssisted,
      { "msAssisted", "rrlp.msAssisted",
        FT_NONE, BASE_NONE, NULL, 0,
        "MethodType/msAssisted", HFILL }},
    { &hf_rrlp_msBased,
      { "msBased", "rrlp.msBased",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MethodType/msBased", HFILL }},
    { &hf_rrlp_msBasedPref,
      { "msBasedPref", "rrlp.msBasedPref",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MethodType/msBasedPref", HFILL }},
    { &hf_rrlp_msAssistedPref,
      { "msAssistedPref", "rrlp.msAssistedPref",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MethodType/msAssistedPref", HFILL }},
    { &hf_rrlp_accuracy,
      { "accuracy", "rrlp.accuracy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AccuracyOpt/accuracy", HFILL }},
    { &hf_rrlp_bcchCarrier,
      { "bcchCarrier", "rrlp.bcchCarrier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_bsic,
      { "bsic", "rrlp.bsic",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_timeSlotScheme,
      { "timeSlotScheme", "rrlp.timeSlotScheme",
        FT_UINT32, BASE_DEC, VALS(rrlp_TimeSlotScheme_vals), 0,
        "", HFILL }},
    { &hf_rrlp_btsPosition,
      { "btsPosition", "rrlp.btsPosition",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReferenceAssistData/btsPosition", HFILL }},
    { &hf_rrlp_msrAssistList,
      { "msrAssistList", "rrlp.msrAssistList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MsrAssistData/msrAssistList", HFILL }},
    { &hf_rrlp_SeqOfMsrAssistBTS_item,
      { "Item", "rrlp.SeqOfMsrAssistBTS_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SeqOfMsrAssistBTS/_item", HFILL }},
    { &hf_rrlp_multiFrameOffset,
      { "multiFrameOffset", "rrlp.multiFrameOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_roughRTD,
      { "roughRTD", "rrlp.roughRTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_calcAssistanceBTS,
      { "calcAssistanceBTS", "rrlp.calcAssistanceBTS",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_systemInfoAssistList,
      { "systemInfoAssistList", "rrlp.systemInfoAssistList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SystemInfoAssistData/systemInfoAssistList", HFILL }},
    { &hf_rrlp_SeqOfSystemInfoAssistBTS_item,
      { "Item", "rrlp.SeqOfSystemInfoAssistBTS_item",
        FT_UINT32, BASE_DEC, VALS(rrlp_SystemInfoAssistBTS_vals), 0,
        "SeqOfSystemInfoAssistBTS/_item", HFILL }},
    { &hf_rrlp_notPresent,
      { "notPresent", "rrlp.notPresent",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_present,
      { "present", "rrlp.present",
        FT_NONE, BASE_NONE, NULL, 0,
        "SystemInfoAssistBTS/present", HFILL }},
    { &hf_rrlp_fineRTD,
      { "fineRTD", "rrlp.fineRTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CalcAssistanceBTS/fineRTD", HFILL }},
    { &hf_rrlp_referenceWGS84,
      { "referenceWGS84", "rrlp.referenceWGS84",
        FT_NONE, BASE_NONE, NULL, 0,
        "CalcAssistanceBTS/referenceWGS84", HFILL }},
    { &hf_rrlp_relativeNorth,
      { "relativeNorth", "rrlp.relativeNorth",
        FT_INT32, BASE_DEC, NULL, 0,
        "ReferenceWGS84/relativeNorth", HFILL }},
    { &hf_rrlp_relativeEast,
      { "relativeEast", "rrlp.relativeEast",
        FT_INT32, BASE_DEC, NULL, 0,
        "ReferenceWGS84/relativeEast", HFILL }},
    { &hf_rrlp_relativeAlt,
      { "relativeAlt", "rrlp.relativeAlt",
        FT_INT32, BASE_DEC, NULL, 0,
        "ReferenceWGS84/relativeAlt", HFILL }},
    { &hf_rrlp_nbrOfSets,
      { "nbrOfSets", "rrlp.nbrOfSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MultipleSets/nbrOfSets", HFILL }},
    { &hf_rrlp_nbrOfReferenceBTSs,
      { "nbrOfReferenceBTSs", "rrlp.nbrOfReferenceBTSs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MultipleSets/nbrOfReferenceBTSs", HFILL }},
    { &hf_rrlp_referenceRelation,
      { "referenceRelation", "rrlp.referenceRelation",
        FT_UINT32, BASE_DEC, VALS(rrlp_ReferenceRelation_vals), 0,
        "MultipleSets/referenceRelation", HFILL }},
    { &hf_rrlp_refBTSList,
      { "refBTSList", "rrlp.refBTSList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ReferenceIdentity/refBTSList", HFILL }},
    { &hf_rrlp_SeqOfReferenceIdentityType_item,
      { "Item", "rrlp.SeqOfReferenceIdentityType_item",
        FT_UINT32, BASE_DEC, VALS(rrlp_ReferenceIdentityType_vals), 0,
        "SeqOfReferenceIdentityType/_item", HFILL }},
    { &hf_rrlp_bsicAndCarrier,
      { "bsicAndCarrier", "rrlp.bsicAndCarrier",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_ci,
      { "ci", "rrlp.ci",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_requestIndex,
      { "requestIndex", "rrlp.requestIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_systemInfoIndex,
      { "systemInfoIndex", "rrlp.systemInfoIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_ciAndLAC,
      { "ciAndLAC", "rrlp.ciAndLAC",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_carrier,
      { "carrier", "rrlp.carrier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "BSICAndCarrier/carrier", HFILL }},
    { &hf_rrlp_referenceLAC,
      { "referenceLAC", "rrlp.referenceLAC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellIDAndLAC/referenceLAC", HFILL }},
    { &hf_rrlp_referenceCI,
      { "referenceCI", "rrlp.referenceCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellIDAndLAC/referenceCI", HFILL }},
    { &hf_rrlp_otdMsrFirstSets,
      { "otdMsrFirstSets", "rrlp.otdMsrFirstSets",
        FT_NONE, BASE_NONE, NULL, 0,
        "OTD-MeasureInfo/otdMsrFirstSets", HFILL }},
    { &hf_rrlp_otdMsrRestSets,
      { "otdMsrRestSets", "rrlp.otdMsrRestSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OTD-MeasureInfo/otdMsrRestSets", HFILL }},
    { &hf_rrlp_SeqOfOTD_MsrElementRest_item,
      { "Item", "rrlp.SeqOfOTD_MsrElementRest_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SeqOfOTD-MsrElementRest/_item", HFILL }},
    { &hf_rrlp_refFrameNumber,
      { "refFrameNumber", "rrlp.refFrameNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_referenceTimeSlot,
      { "referenceTimeSlot", "rrlp.referenceTimeSlot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_toaMeasurementsOfRef,
      { "toaMeasurementsOfRef", "rrlp.toaMeasurementsOfRef",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_stdResolution,
      { "stdResolution", "rrlp.stdResolution",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_taCorrection,
      { "taCorrection", "rrlp.taCorrection",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_otd_FirstSetMsrs,
      { "otd-FirstSetMsrs", "rrlp.otd_FirstSetMsrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OTD-MsrElementFirst/otd-FirstSetMsrs", HFILL }},
    { &hf_rrlp_SeqOfOTD_FirstSetMsrs_item,
      { "Item", "rrlp.SeqOfOTD_FirstSetMsrs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SeqOfOTD-FirstSetMsrs/_item", HFILL }},
    { &hf_rrlp_otd_MsrsOfOtherSets,
      { "otd-MsrsOfOtherSets", "rrlp.otd_MsrsOfOtherSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OTD-MsrElementRest/otd-MsrsOfOtherSets", HFILL }},
    { &hf_rrlp_SeqOfOTD_MsrsOfOtherSets_item,
      { "Item", "rrlp.SeqOfOTD_MsrsOfOtherSets_item",
        FT_UINT32, BASE_DEC, VALS(rrlp_OTD_MsrsOfOtherSets_vals), 0,
        "SeqOfOTD-MsrsOfOtherSets/_item", HFILL }},
    { &hf_rrlp_refQuality,
      { "refQuality", "rrlp.refQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TOA-MeasurementsOfRef/refQuality", HFILL }},
    { &hf_rrlp_numOfMeasurements,
      { "numOfMeasurements", "rrlp.numOfMeasurements",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TOA-MeasurementsOfRef/numOfMeasurements", HFILL }},
    { &hf_rrlp_identityNotPresent,
      { "identityNotPresent", "rrlp.identityNotPresent",
        FT_NONE, BASE_NONE, NULL, 0,
        "OTD-MsrsOfOtherSets/identityNotPresent", HFILL }},
    { &hf_rrlp_identityPresent,
      { "identityPresent", "rrlp.identityPresent",
        FT_NONE, BASE_NONE, NULL, 0,
        "OTD-MsrsOfOtherSets/identityPresent", HFILL }},
    { &hf_rrlp_nborTimeSlot,
      { "nborTimeSlot", "rrlp.nborTimeSlot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_eotdQuality,
      { "eotdQuality", "rrlp.eotdQuality",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_otdValue,
      { "otdValue", "rrlp.otdValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_neighborIdentity,
      { "neighborIdentity", "rrlp.neighborIdentity",
        FT_UINT32, BASE_DEC, VALS(rrlp_NeighborIdentity_vals), 0,
        "OTD-MeasurementWithID/neighborIdentity", HFILL }},
    { &hf_rrlp_nbrOfMeasurements,
      { "nbrOfMeasurements", "rrlp.nbrOfMeasurements",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EOTDQuality/nbrOfMeasurements", HFILL }},
    { &hf_rrlp_stdOfEOTD,
      { "stdOfEOTD", "rrlp.stdOfEOTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EOTDQuality/stdOfEOTD", HFILL }},
    { &hf_rrlp_multiFrameCarrier,
      { "multiFrameCarrier", "rrlp.multiFrameCarrier",
        FT_NONE, BASE_NONE, NULL, 0,
        "NeighborIdentity/multiFrameCarrier", HFILL }},
    { &hf_rrlp_refFrame,
      { "refFrame", "rrlp.refFrame",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_gpsTOW,
      { "gpsTOW", "rrlp.gpsTOW",
        FT_UINT32, BASE_DEC, NULL, 0,
        "LocationInfo/gpsTOW", HFILL }},
    { &hf_rrlp_fixType,
      { "fixType", "rrlp.fixType",
        FT_UINT32, BASE_DEC, VALS(rrlp_FixType_vals), 0,
        "LocationInfo/fixType", HFILL }},
    { &hf_rrlp_posEstimate,
      { "posEstimate", "rrlp.posEstimate",
        FT_NONE, BASE_NONE, NULL, 0,
        "LocationInfo/posEstimate", HFILL }},
    { &hf_rrlp_gpsMsrSetList,
      { "gpsMsrSetList", "rrlp.gpsMsrSetList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPS-MeasureInfo/gpsMsrSetList", HFILL }},
    { &hf_rrlp_SeqOfGPS_MsrSetElement_item,
      { "Item", "rrlp.SeqOfGPS_MsrSetElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SeqOfGPS-MsrSetElement/_item", HFILL }},
    { &hf_rrlp_gpsTOW1,
      { "gpsTOW", "rrlp.gpsTOW",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPS-MsrSetElement/gpsTOW", HFILL }},
    { &hf_rrlp_gps_msrList,
      { "gps-msrList", "rrlp.gps_msrList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPS-MsrSetElement/gps-msrList", HFILL }},
    { &hf_rrlp_SeqOfGPS_MsrElement_item,
      { "Item", "rrlp.SeqOfGPS_MsrElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SeqOfGPS-MsrElement/_item", HFILL }},
    { &hf_rrlp_satelliteID,
      { "satelliteID", "rrlp.satelliteID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_cNo,
      { "cNo", "rrlp.cNo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPS-MsrElement/cNo", HFILL }},
    { &hf_rrlp_doppler,
      { "doppler", "rrlp.doppler",
        FT_INT32, BASE_DEC, NULL, 0,
        "GPS-MsrElement/doppler", HFILL }},
    { &hf_rrlp_wholeChips,
      { "wholeChips", "rrlp.wholeChips",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPS-MsrElement/wholeChips", HFILL }},
    { &hf_rrlp_fracChips,
      { "fracChips", "rrlp.fracChips",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPS-MsrElement/fracChips", HFILL }},
    { &hf_rrlp_mpathIndic,
      { "mpathIndic", "rrlp.mpathIndic",
        FT_UINT32, BASE_DEC, VALS(rrlp_MpathIndic_vals), 0,
        "GPS-MsrElement/mpathIndic", HFILL }},
    { &hf_rrlp_pseuRangeRMSErr,
      { "pseuRangeRMSErr", "rrlp.pseuRangeRMSErr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPS-MsrElement/pseuRangeRMSErr", HFILL }},
    { &hf_rrlp_locErrorReason,
      { "locErrorReason", "rrlp.locErrorReason",
        FT_UINT32, BASE_DEC, VALS(rrlp_LocErrorReason_vals), 0,
        "LocationError/locErrorReason", HFILL }},
    { &hf_rrlp_additionalAssistanceData,
      { "additionalAssistanceData", "rrlp.additionalAssistanceData",
        FT_NONE, BASE_NONE, NULL, 0,
        "LocationError/additionalAssistanceData", HFILL }},
    { &hf_rrlp_gpsAssistanceData,
      { "gpsAssistanceData", "rrlp.gpsAssistanceData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "AdditionalAssistanceData/gpsAssistanceData", HFILL }},
    { &hf_rrlp_controlHeader,
      { "controlHeader", "rrlp.controlHeader",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPS-AssistData/controlHeader", HFILL }},
    { &hf_rrlp_referenceTime,
      { "referenceTime", "rrlp.referenceTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlHeader/referenceTime", HFILL }},
    { &hf_rrlp_refLocation,
      { "refLocation", "rrlp.refLocation",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlHeader/refLocation", HFILL }},
    { &hf_rrlp_dgpsCorrections,
      { "dgpsCorrections", "rrlp.dgpsCorrections",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlHeader/dgpsCorrections", HFILL }},
    { &hf_rrlp_navigationModel,
      { "navigationModel", "rrlp.navigationModel",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlHeader/navigationModel", HFILL }},
    { &hf_rrlp_ionosphericModel,
      { "ionosphericModel", "rrlp.ionosphericModel",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlHeader/ionosphericModel", HFILL }},
    { &hf_rrlp_utcModel,
      { "utcModel", "rrlp.utcModel",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlHeader/utcModel", HFILL }},
    { &hf_rrlp_almanac,
      { "almanac", "rrlp.almanac",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlHeader/almanac", HFILL }},
    { &hf_rrlp_acquisAssist,
      { "acquisAssist", "rrlp.acquisAssist",
        FT_NONE, BASE_NONE, NULL, 0,
        "ControlHeader/acquisAssist", HFILL }},
    { &hf_rrlp_realTimeIntegrity,
      { "realTimeIntegrity", "rrlp.realTimeIntegrity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ControlHeader/realTimeIntegrity", HFILL }},
    { &hf_rrlp_gpsTime,
      { "gpsTime", "rrlp.gpsTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "ReferenceTime/gpsTime", HFILL }},
    { &hf_rrlp_gsmTime,
      { "gsmTime", "rrlp.gsmTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_gpsTowAssist,
      { "gpsTowAssist", "rrlp.gpsTowAssist",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ReferenceTime/gpsTowAssist", HFILL }},
    { &hf_rrlp_gpsTOW23b,
      { "gpsTOW23b", "rrlp.gpsTOW23b",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPSTime/gpsTOW23b", HFILL }},
    { &hf_rrlp_gpsWeek,
      { "gpsWeek", "rrlp.gpsWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPSTime/gpsWeek", HFILL }},
    { &hf_rrlp_GPSTOWAssist_item,
      { "Item", "rrlp.GPSTOWAssist_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "GPSTOWAssist/_item", HFILL }},
    { &hf_rrlp_tlmWord,
      { "tlmWord", "rrlp.tlmWord",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPSTOWAssistElement/tlmWord", HFILL }},
    { &hf_rrlp_antiSpoof,
      { "antiSpoof", "rrlp.antiSpoof",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPSTOWAssistElement/antiSpoof", HFILL }},
    { &hf_rrlp_alert,
      { "alert", "rrlp.alert",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPSTOWAssistElement/alert", HFILL }},
    { &hf_rrlp_tlmRsvdBits,
      { "tlmRsvdBits", "rrlp.tlmRsvdBits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPSTOWAssistElement/tlmRsvdBits", HFILL }},
    { &hf_rrlp_frameNumber,
      { "frameNumber", "rrlp.frameNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GSMTime/frameNumber", HFILL }},
    { &hf_rrlp_timeSlot,
      { "timeSlot", "rrlp.timeSlot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GSMTime/timeSlot", HFILL }},
    { &hf_rrlp_bitNumber,
      { "bitNumber", "rrlp.bitNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GSMTime/bitNumber", HFILL }},
    { &hf_rrlp_threeDLocation,
      { "threeDLocation", "rrlp.threeDLocation",
        FT_NONE, BASE_NONE, NULL, 0,
        "RefLocation/threeDLocation", HFILL }},
    { &hf_rrlp_gpsTOW2,
      { "gpsTOW", "rrlp.gpsTOW",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DGPSCorrections/gpsTOW", HFILL }},
    { &hf_rrlp_status,
      { "status", "rrlp.status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DGPSCorrections/status", HFILL }},
    { &hf_rrlp_satList,
      { "satList", "rrlp.satList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DGPSCorrections/satList", HFILL }},
    { &hf_rrlp_SeqOfSatElement_item,
      { "Item", "rrlp.SeqOfSatElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SeqOfSatElement/_item", HFILL }},
    { &hf_rrlp_iode,
      { "iode", "rrlp.iode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SatElement/iode", HFILL }},
    { &hf_rrlp_udre,
      { "udre", "rrlp.udre",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SatElement/udre", HFILL }},
    { &hf_rrlp_pseudoRangeCor,
      { "pseudoRangeCor", "rrlp.pseudoRangeCor",
        FT_INT32, BASE_DEC, NULL, 0,
        "SatElement/pseudoRangeCor", HFILL }},
    { &hf_rrlp_rangeRateCor,
      { "rangeRateCor", "rrlp.rangeRateCor",
        FT_INT32, BASE_DEC, NULL, 0,
        "SatElement/rangeRateCor", HFILL }},
    { &hf_rrlp_deltaPseudoRangeCor2,
      { "deltaPseudoRangeCor2", "rrlp.deltaPseudoRangeCor2",
        FT_INT32, BASE_DEC, NULL, 0,
        "SatElement/deltaPseudoRangeCor2", HFILL }},
    { &hf_rrlp_deltaRangeRateCor2,
      { "deltaRangeRateCor2", "rrlp.deltaRangeRateCor2",
        FT_INT32, BASE_DEC, NULL, 0,
        "SatElement/deltaRangeRateCor2", HFILL }},
    { &hf_rrlp_deltaPseudoRangeCor3,
      { "deltaPseudoRangeCor3", "rrlp.deltaPseudoRangeCor3",
        FT_INT32, BASE_DEC, NULL, 0,
        "SatElement/deltaPseudoRangeCor3", HFILL }},
    { &hf_rrlp_deltaRangeRateCor3,
      { "deltaRangeRateCor3", "rrlp.deltaRangeRateCor3",
        FT_INT32, BASE_DEC, NULL, 0,
        "SatElement/deltaRangeRateCor3", HFILL }},
    { &hf_rrlp_navModelList,
      { "navModelList", "rrlp.navModelList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NavigationModel/navModelList", HFILL }},
    { &hf_rrlp_SeqOfNavModelElement_item,
      { "Item", "rrlp.SeqOfNavModelElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SeqOfNavModelElement/_item", HFILL }},
    { &hf_rrlp_satStatus,
      { "satStatus", "rrlp.satStatus",
        FT_UINT32, BASE_DEC, VALS(rrlp_SatStatus_vals), 0,
        "NavModelElement/satStatus", HFILL }},
    { &hf_rrlp_newSatelliteAndModelUC,
      { "newSatelliteAndModelUC", "rrlp.newSatelliteAndModelUC",
        FT_NONE, BASE_NONE, NULL, 0,
        "SatStatus/newSatelliteAndModelUC", HFILL }},
    { &hf_rrlp_oldSatelliteAndModel,
      { "oldSatelliteAndModel", "rrlp.oldSatelliteAndModel",
        FT_NONE, BASE_NONE, NULL, 0,
        "SatStatus/oldSatelliteAndModel", HFILL }},
    { &hf_rrlp_newNaviModelUC,
      { "newNaviModelUC", "rrlp.newNaviModelUC",
        FT_NONE, BASE_NONE, NULL, 0,
        "SatStatus/newNaviModelUC", HFILL }},
    { &hf_rrlp_ephemCodeOnL2,
      { "ephemCodeOnL2", "rrlp.ephemCodeOnL2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemCodeOnL2", HFILL }},
    { &hf_rrlp_ephemURA,
      { "ephemURA", "rrlp.ephemURA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemURA", HFILL }},
    { &hf_rrlp_ephemSVhealth,
      { "ephemSVhealth", "rrlp.ephemSVhealth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemSVhealth", HFILL }},
    { &hf_rrlp_ephemIODC,
      { "ephemIODC", "rrlp.ephemIODC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemIODC", HFILL }},
    { &hf_rrlp_ephemL2Pflag,
      { "ephemL2Pflag", "rrlp.ephemL2Pflag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemL2Pflag", HFILL }},
    { &hf_rrlp_ephemSF1Rsvd,
      { "ephemSF1Rsvd", "rrlp.ephemSF1Rsvd",
        FT_NONE, BASE_NONE, NULL, 0,
        "UncompressedEphemeris/ephemSF1Rsvd", HFILL }},
    { &hf_rrlp_ephemTgd,
      { "ephemTgd", "rrlp.ephemTgd",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemTgd", HFILL }},
    { &hf_rrlp_ephemToc,
      { "ephemToc", "rrlp.ephemToc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemToc", HFILL }},
    { &hf_rrlp_ephemAF2,
      { "ephemAF2", "rrlp.ephemAF2",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemAF2", HFILL }},
    { &hf_rrlp_ephemAF1,
      { "ephemAF1", "rrlp.ephemAF1",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemAF1", HFILL }},
    { &hf_rrlp_ephemAF0,
      { "ephemAF0", "rrlp.ephemAF0",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemAF0", HFILL }},
    { &hf_rrlp_ephemCrs,
      { "ephemCrs", "rrlp.ephemCrs",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemCrs", HFILL }},
    { &hf_rrlp_ephemDeltaN,
      { "ephemDeltaN", "rrlp.ephemDeltaN",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemDeltaN", HFILL }},
    { &hf_rrlp_ephemM0,
      { "ephemM0", "rrlp.ephemM0",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemM0", HFILL }},
    { &hf_rrlp_ephemCuc,
      { "ephemCuc", "rrlp.ephemCuc",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemCuc", HFILL }},
    { &hf_rrlp_ephemE,
      { "ephemE", "rrlp.ephemE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemE", HFILL }},
    { &hf_rrlp_ephemCus,
      { "ephemCus", "rrlp.ephemCus",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemCus", HFILL }},
    { &hf_rrlp_ephemAPowerHalf,
      { "ephemAPowerHalf", "rrlp.ephemAPowerHalf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemAPowerHalf", HFILL }},
    { &hf_rrlp_ephemToe,
      { "ephemToe", "rrlp.ephemToe",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemToe", HFILL }},
    { &hf_rrlp_ephemFitFlag,
      { "ephemFitFlag", "rrlp.ephemFitFlag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemFitFlag", HFILL }},
    { &hf_rrlp_ephemAODA,
      { "ephemAODA", "rrlp.ephemAODA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemAODA", HFILL }},
    { &hf_rrlp_ephemCic,
      { "ephemCic", "rrlp.ephemCic",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemCic", HFILL }},
    { &hf_rrlp_ephemOmegaA0,
      { "ephemOmegaA0", "rrlp.ephemOmegaA0",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemOmegaA0", HFILL }},
    { &hf_rrlp_ephemCis,
      { "ephemCis", "rrlp.ephemCis",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemCis", HFILL }},
    { &hf_rrlp_ephemI0,
      { "ephemI0", "rrlp.ephemI0",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemI0", HFILL }},
    { &hf_rrlp_ephemCrc,
      { "ephemCrc", "rrlp.ephemCrc",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemCrc", HFILL }},
    { &hf_rrlp_ephemW,
      { "ephemW", "rrlp.ephemW",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemW", HFILL }},
    { &hf_rrlp_ephemOmegaADot,
      { "ephemOmegaADot", "rrlp.ephemOmegaADot",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemOmegaADot", HFILL }},
    { &hf_rrlp_ephemIDot,
      { "ephemIDot", "rrlp.ephemIDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "UncompressedEphemeris/ephemIDot", HFILL }},
    { &hf_rrlp_reserved1,
      { "reserved1", "rrlp.reserved1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EphemerisSubframe1Reserved/reserved1", HFILL }},
    { &hf_rrlp_reserved2,
      { "reserved2", "rrlp.reserved2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EphemerisSubframe1Reserved/reserved2", HFILL }},
    { &hf_rrlp_reserved3,
      { "reserved3", "rrlp.reserved3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EphemerisSubframe1Reserved/reserved3", HFILL }},
    { &hf_rrlp_reserved4,
      { "reserved4", "rrlp.reserved4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "EphemerisSubframe1Reserved/reserved4", HFILL }},
    { &hf_rrlp_alfa0,
      { "alfa0", "rrlp.alfa0",
        FT_INT32, BASE_DEC, NULL, 0,
        "IonosphericModel/alfa0", HFILL }},
    { &hf_rrlp_alfa1,
      { "alfa1", "rrlp.alfa1",
        FT_INT32, BASE_DEC, NULL, 0,
        "IonosphericModel/alfa1", HFILL }},
    { &hf_rrlp_alfa2,
      { "alfa2", "rrlp.alfa2",
        FT_INT32, BASE_DEC, NULL, 0,
        "IonosphericModel/alfa2", HFILL }},
    { &hf_rrlp_alfa3,
      { "alfa3", "rrlp.alfa3",
        FT_INT32, BASE_DEC, NULL, 0,
        "IonosphericModel/alfa3", HFILL }},
    { &hf_rrlp_beta0,
      { "beta0", "rrlp.beta0",
        FT_INT32, BASE_DEC, NULL, 0,
        "IonosphericModel/beta0", HFILL }},
    { &hf_rrlp_beta1,
      { "beta1", "rrlp.beta1",
        FT_INT32, BASE_DEC, NULL, 0,
        "IonosphericModel/beta1", HFILL }},
    { &hf_rrlp_beta2,
      { "beta2", "rrlp.beta2",
        FT_INT32, BASE_DEC, NULL, 0,
        "IonosphericModel/beta2", HFILL }},
    { &hf_rrlp_beta3,
      { "beta3", "rrlp.beta3",
        FT_INT32, BASE_DEC, NULL, 0,
        "IonosphericModel/beta3", HFILL }},
    { &hf_rrlp_utcA1,
      { "utcA1", "rrlp.utcA1",
        FT_INT32, BASE_DEC, NULL, 0,
        "UTCModel/utcA1", HFILL }},
    { &hf_rrlp_utcA0,
      { "utcA0", "rrlp.utcA0",
        FT_INT32, BASE_DEC, NULL, 0,
        "UTCModel/utcA0", HFILL }},
    { &hf_rrlp_utcTot,
      { "utcTot", "rrlp.utcTot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UTCModel/utcTot", HFILL }},
    { &hf_rrlp_utcWNt,
      { "utcWNt", "rrlp.utcWNt",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UTCModel/utcWNt", HFILL }},
    { &hf_rrlp_utcDeltaTls,
      { "utcDeltaTls", "rrlp.utcDeltaTls",
        FT_INT32, BASE_DEC, NULL, 0,
        "UTCModel/utcDeltaTls", HFILL }},
    { &hf_rrlp_utcWNlsf,
      { "utcWNlsf", "rrlp.utcWNlsf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "UTCModel/utcWNlsf", HFILL }},
    { &hf_rrlp_utcDN,
      { "utcDN", "rrlp.utcDN",
        FT_INT32, BASE_DEC, NULL, 0,
        "UTCModel/utcDN", HFILL }},
    { &hf_rrlp_utcDeltaTlsf,
      { "utcDeltaTlsf", "rrlp.utcDeltaTlsf",
        FT_INT32, BASE_DEC, NULL, 0,
        "UTCModel/utcDeltaTlsf", HFILL }},
    { &hf_rrlp_alamanacWNa,
      { "alamanacWNa", "rrlp.alamanacWNa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Almanac/alamanacWNa", HFILL }},
    { &hf_rrlp_almanacList,
      { "almanacList", "rrlp.almanacList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Almanac/almanacList", HFILL }},
    { &hf_rrlp_SeqOfAlmanacElement_item,
      { "Item", "rrlp.SeqOfAlmanacElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SeqOfAlmanacElement/_item", HFILL }},
    { &hf_rrlp_almanacE,
      { "almanacE", "rrlp.almanacE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AlmanacElement/almanacE", HFILL }},
    { &hf_rrlp_alamanacToa,
      { "alamanacToa", "rrlp.alamanacToa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AlmanacElement/alamanacToa", HFILL }},
    { &hf_rrlp_almanacKsii,
      { "almanacKsii", "rrlp.almanacKsii",
        FT_INT32, BASE_DEC, NULL, 0,
        "AlmanacElement/almanacKsii", HFILL }},
    { &hf_rrlp_almanacOmegaDot,
      { "almanacOmegaDot", "rrlp.almanacOmegaDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "AlmanacElement/almanacOmegaDot", HFILL }},
    { &hf_rrlp_almanacSVhealth,
      { "almanacSVhealth", "rrlp.almanacSVhealth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AlmanacElement/almanacSVhealth", HFILL }},
    { &hf_rrlp_almanacAPowerHalf,
      { "almanacAPowerHalf", "rrlp.almanacAPowerHalf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AlmanacElement/almanacAPowerHalf", HFILL }},
    { &hf_rrlp_almanacOmega0,
      { "almanacOmega0", "rrlp.almanacOmega0",
        FT_INT32, BASE_DEC, NULL, 0,
        "AlmanacElement/almanacOmega0", HFILL }},
    { &hf_rrlp_almanacW,
      { "almanacW", "rrlp.almanacW",
        FT_INT32, BASE_DEC, NULL, 0,
        "AlmanacElement/almanacW", HFILL }},
    { &hf_rrlp_almanacM0,
      { "almanacM0", "rrlp.almanacM0",
        FT_INT32, BASE_DEC, NULL, 0,
        "AlmanacElement/almanacM0", HFILL }},
    { &hf_rrlp_almanacAF0,
      { "almanacAF0", "rrlp.almanacAF0",
        FT_INT32, BASE_DEC, NULL, 0,
        "AlmanacElement/almanacAF0", HFILL }},
    { &hf_rrlp_almanacAF1,
      { "almanacAF1", "rrlp.almanacAF1",
        FT_INT32, BASE_DEC, NULL, 0,
        "AlmanacElement/almanacAF1", HFILL }},
    { &hf_rrlp_timeRelation,
      { "timeRelation", "rrlp.timeRelation",
        FT_NONE, BASE_NONE, NULL, 0,
        "AcquisAssist/timeRelation", HFILL }},
    { &hf_rrlp_acquisList,
      { "acquisList", "rrlp.acquisList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AcquisAssist/acquisList", HFILL }},
    { &hf_rrlp_SeqOfAcquisElement_item,
      { "Item", "rrlp.SeqOfAcquisElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SeqOfAcquisElement/_item", HFILL }},
    { &hf_rrlp_gpsTOW3,
      { "gpsTOW", "rrlp.gpsTOW",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeRelation/gpsTOW", HFILL }},
    { &hf_rrlp_svid,
      { "svid", "rrlp.svid",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AcquisElement/svid", HFILL }},
    { &hf_rrlp_doppler0,
      { "doppler0", "rrlp.doppler0",
        FT_INT32, BASE_DEC, NULL, 0,
        "AcquisElement/doppler0", HFILL }},
    { &hf_rrlp_addionalDoppler,
      { "addionalDoppler", "rrlp.addionalDoppler",
        FT_NONE, BASE_NONE, NULL, 0,
        "AcquisElement/addionalDoppler", HFILL }},
    { &hf_rrlp_codePhase,
      { "codePhase", "rrlp.codePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AcquisElement/codePhase", HFILL }},
    { &hf_rrlp_intCodePhase,
      { "intCodePhase", "rrlp.intCodePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AcquisElement/intCodePhase", HFILL }},
    { &hf_rrlp_gpsBitNumber,
      { "gpsBitNumber", "rrlp.gpsBitNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AcquisElement/gpsBitNumber", HFILL }},
    { &hf_rrlp_codePhaseSearchWindow,
      { "codePhaseSearchWindow", "rrlp.codePhaseSearchWindow",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AcquisElement/codePhaseSearchWindow", HFILL }},
    { &hf_rrlp_addionalAngle,
      { "addionalAngle", "rrlp.addionalAngle",
        FT_NONE, BASE_NONE, NULL, 0,
        "AcquisElement/addionalAngle", HFILL }},
    { &hf_rrlp_doppler1,
      { "doppler1", "rrlp.doppler1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AddionalDopplerFields/doppler1", HFILL }},
    { &hf_rrlp_dopplerUncertainty,
      { "dopplerUncertainty", "rrlp.dopplerUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AddionalDopplerFields/dopplerUncertainty", HFILL }},
    { &hf_rrlp_azimuth,
      { "azimuth", "rrlp.azimuth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AddionalAngleFields/azimuth", HFILL }},
    { &hf_rrlp_elevation,
      { "elevation", "rrlp.elevation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AddionalAngleFields/elevation", HFILL }},
    { &hf_rrlp_SeqOf_BadSatelliteSet_item,
      { "Item", "rrlp.SeqOf_BadSatelliteSet_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SeqOf-BadSatelliteSet/_item", HFILL }},
    { &hf_rrlp_rel98_Ext_ExpOTD,
      { "rel98-Ext-ExpOTD", "rrlp.rel98_Ext_ExpOTD",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_gpsTimeAssistanceMeasurementRequest,
      { "gpsTimeAssistanceMeasurementRequest", "rrlp.gpsTimeAssistanceMeasurementRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_gpsReferenceTimeUncertainty,
      { "gpsReferenceTimeUncertainty", "rrlp.gpsReferenceTimeUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_msrAssistData_R98_ExpOTD,
      { "msrAssistData-R98-ExpOTD", "rrlp.msrAssistData_R98_ExpOTD",
        FT_NONE, BASE_NONE, NULL, 0,
        "Rel98-Ext-ExpOTD/msrAssistData-R98-ExpOTD", HFILL }},
    { &hf_rrlp_systemInfoAssistData_R98_ExpOTD,
      { "systemInfoAssistData-R98-ExpOTD", "rrlp.systemInfoAssistData_R98_ExpOTD",
        FT_NONE, BASE_NONE, NULL, 0,
        "Rel98-Ext-ExpOTD/systemInfoAssistData-R98-ExpOTD", HFILL }},
    { &hf_rrlp_msrAssistList_R98_ExpOTD,
      { "msrAssistList-R98-ExpOTD", "rrlp.msrAssistList_R98_ExpOTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MsrAssistData-R98-ExpOTD/msrAssistList-R98-ExpOTD", HFILL }},
    { &hf_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD_item,
      { "Item", "rrlp.SeqOfMsrAssistBTS_R98_ExpOTD_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SeqOfMsrAssistBTS-R98-ExpOTD/_item", HFILL }},
    { &hf_rrlp_expectedOTD,
      { "expectedOTD", "rrlp.expectedOTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_expOTDUncertainty,
      { "expOTDUncertainty", "rrlp.expOTDUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MsrAssistBTS-R98-ExpOTD/expOTDUncertainty", HFILL }},
    { &hf_rrlp_systemInfoAssistListR98_ExpOTD,
      { "systemInfoAssistListR98-ExpOTD", "rrlp.systemInfoAssistListR98_ExpOTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SystemInfoAssistData-R98-ExpOTD/systemInfoAssistListR98-ExpOTD", HFILL }},
    { &hf_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD_item,
      { "Item", "rrlp.SeqOfSystemInfoAssistBTS_R98_ExpOTD_item",
        FT_UINT32, BASE_DEC, VALS(rrlp_SystemInfoAssistBTS_R98_ExpOTD_vals), 0,
        "SeqOfSystemInfoAssistBTS-R98-ExpOTD/_item", HFILL }},
    { &hf_rrlp_present1,
      { "present", "rrlp.present",
        FT_NONE, BASE_NONE, NULL, 0,
        "SystemInfoAssistBTS-R98-ExpOTD/present", HFILL }},
    { &hf_rrlp_expOTDuncertainty,
      { "expOTDuncertainty", "rrlp.expOTDuncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AssistBTSData-R98-ExpOTD/expOTDuncertainty", HFILL }},
    { &hf_rrlp_referenceFrameMSB,
      { "referenceFrameMSB", "rrlp.referenceFrameMSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPSTimeAssistanceMeasurements/referenceFrameMSB", HFILL }},
    { &hf_rrlp_gpsTowSubms,
      { "gpsTowSubms", "rrlp.gpsTowSubms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPSTimeAssistanceMeasurements/gpsTowSubms", HFILL }},
    { &hf_rrlp_deltaTow,
      { "deltaTow", "rrlp.deltaTow",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GPSTimeAssistanceMeasurements/deltaTow", HFILL }},
    { &hf_rrlp_rel_98_Ext_MeasureInfo,
      { "rel-98-Ext-MeasureInfo", "rrlp.rel_98_Ext_MeasureInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "Rel-98-MsrPosition-Rsp-Extension/rel-98-Ext-MeasureInfo", HFILL }},
    { &hf_rrlp_otd_MeasureInfo_R98_Ext,
      { "otd-MeasureInfo-R98-Ext", "rrlp.otd_MeasureInfo_R98_Ext",
        FT_NONE, BASE_NONE, NULL, 0,
        "Rel-98-MsrPosition-Rsp-Extension/rel-98-Ext-MeasureInfo/otd-MeasureInfo-R98-Ext", HFILL }},
    { &hf_rrlp_timeAssistanceMeasurements,
      { "timeAssistanceMeasurements", "rrlp.timeAssistanceMeasurements",
        FT_NONE, BASE_NONE, NULL, 0,
        "Rel-98-MsrPosition-Rsp-Extension/timeAssistanceMeasurements", HFILL }},
    { &hf_rrlp_otdMsrFirstSets_R98_Ext,
      { "otdMsrFirstSets-R98-Ext", "rrlp.otdMsrFirstSets_R98_Ext",
        FT_NONE, BASE_NONE, NULL, 0,
        "OTD-MeasureInfo-R98-Ext/otdMsrFirstSets-R98-Ext", HFILL }},
    { &hf_rrlp_otd_FirstSetMsrs_R98_Ext,
      { "otd-FirstSetMsrs-R98-Ext", "rrlp.otd_FirstSetMsrs_R98_Ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "OTD-MsrElementFirst-R98-Ext/otd-FirstSetMsrs-R98-Ext", HFILL }},
    { &hf_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext_item,
      { "Item", "rrlp.SeqOfOTD_FirstSetMsrs_R98_Ext_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SeqOfOTD-FirstSetMsrs-R98-Ext/_item", HFILL }},
    { &hf_rrlp_extended_reference,
      { "extended-reference", "rrlp.extended_reference",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_rrlp_otd_MeasureInfo_5_Ext,
      { "otd-MeasureInfo-5-Ext", "rrlp.otd_MeasureInfo_5_Ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Rel-5-MsrPosition-Rsp-Extension/otd-MeasureInfo-5-Ext", HFILL }},
    { &hf_rrlp_ulPseudoSegInd,
      { "ulPseudoSegInd", "rrlp.ulPseudoSegInd",
        FT_UINT32, BASE_DEC, VALS(rrlp_UlPseudoSegInd_vals), 0,
        "Rel-5-MsrPosition-Rsp-Extension/ulPseudoSegInd", HFILL }},
    { &hf_rrlp_smlc_code,
      { "smlc-code", "rrlp.smlc_code",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extended-reference/smlc-code", HFILL }},
    { &hf_rrlp_transaction_ID,
      { "transaction-ID", "rrlp.transaction_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extended-reference/transaction-ID", HFILL }},

/*--- End of included file: packet-rrlp-hfarr.c ---*/
#line 91 "packet-rrlp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_rrlp,

/*--- Included file: packet-rrlp-ettarr.c ---*/
#line 1 "packet-rrlp-ettarr.c"
    &ett_rrlp_PDU,
    &ett_rrlp_RRLP_Component,
    &ett_rrlp_MsrPosition_Req,
    &ett_rrlp_MsrPosition_Rsp,
    &ett_rrlp_AssistanceData,
    &ett_rrlp_ProtocolError,
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

/*--- End of included file: packet-rrlp-ettarr.c ---*/
#line 97 "packet-rrlp-template.c"
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

	rrlp_handle = create_dissector_handle(dissect_PDU_PDU, proto_rrlp);


}


