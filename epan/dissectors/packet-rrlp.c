/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-rrlp.c                                                              */
/* ../../tools/asn2wrs.py -p rrlp -c rrlp.cnf -s packet-rrlp-template ../gsmmap/MAP-ExtensionDataTypes.asn ../gsmmap/MAP-LCS-DataTypes.asn RRLP-Messages.asn RRLP-Components.asn */

/* Input file: packet-rrlp-template.c */

#line 1 "packet-rrlp-template.c"
/* packet-rrlp.c
 * Routines for 3GPP Radio Resource LCS Protocol (RRLP) packet dissection
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
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
#include <epan/asn1.h>

#include <stdio.h>
#include <string.h>

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

static dissector_handle_t rrlp_handle=NULL;


/* Initialize the protocol and registered fields */
static int proto_rrlp = -1;



/*--- Included file: packet-rrlp-hf.c ---*/
#line 1 "packet-rrlp-hf.c"
static int hf_rrlp_PDU_PDU = -1;                  /* PDU */
static int hf_rrlp_privateExtensionList = -1;     /* PrivateExtensionList */
static int hf_rrlp_pcs_Extensions = -1;           /* PCS_Extensions */
static int hf_rrlp_PrivateExtensionList_item = -1;  /* PrivateExtension */
static int hf_rrlp_extId = -1;                    /* OBJECT_IDENTIFIER */
static int hf_rrlp_extType = -1;                  /* T_extType */
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
static int hf_rrlp_rel7_MsrPosition_Req_extension = -1;  /* Rel7_MsrPosition_Req_Extension */
static int hf_rrlp_multipleSets = -1;             /* MultipleSets */
static int hf_rrlp_referenceIdentity = -1;        /* ReferenceIdentity */
static int hf_rrlp_otd_MeasureInfo = -1;          /* OTD_MeasureInfo */
static int hf_rrlp_locationInfo = -1;             /* LocationInfo */
static int hf_rrlp_gps_MeasureInfo = -1;          /* GPS_MeasureInfo */
static int hf_rrlp_locationError = -1;            /* LocationError */
static int hf_rrlp_rel_98_MsrPosition_Rsp_Extension = -1;  /* Rel_98_MsrPosition_Rsp_Extension */
static int hf_rrlp_rel_5_MsrPosition_Rsp_Extension = -1;  /* Rel_5_MsrPosition_Rsp_Extension */
static int hf_rrlp_rel_7_MsrPosition_Rsp_Extension = -1;  /* Rel_7_MsrPosition_Rsp_Extension */
static int hf_rrlp_moreAssDataToBeSent = -1;      /* MoreAssDataToBeSent */
static int hf_rrlp_rel98_AssistanceData_Extension = -1;  /* Rel98_AssistanceData_Extension */
static int hf_rrlp_rel5_AssistanceData_Extension = -1;  /* Rel5_AssistanceData_Extension */
static int hf_rrlp_rel7_AssistanceData_Extension = -1;  /* Rel7_AssistanceData_Extension */
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
static int hf_rrlp_gpsTOW_01 = -1;                /* GPSTOW24b */
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
static int hf_rrlp_ganssAssistanceData = -1;      /* GANSSAssistanceData */
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
static int hf_rrlp_gpsTOW_02 = -1;                /* INTEGER_0_604799 */
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
static int hf_rrlp_gpsTOW_03 = -1;                /* GPSTOW23b */
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
static int hf_rrlp_present_01 = -1;               /* AssistBTSData_R98_ExpOTD */
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
static int hf_rrlp_velocityRequested = -1;        /* NULL */
static int hf_rrlp_ganssPositionMethod = -1;      /* GANSSPositioningMethod */
static int hf_rrlp_ganss_AssistData = -1;         /* GANSS_AssistData */
static int hf_rrlp_ganssCarrierPhaseMeasurementRequest = -1;  /* NULL */
static int hf_rrlp_ganssTODGSMTimeAssociationMeasurementRequest = -1;  /* NULL */
static int hf_rrlp_requiredResponseTime = -1;     /* RequiredResponseTime */
static int hf_rrlp_ganss_controlHeader = -1;      /* GANSS_ControlHeader */
static int hf_rrlp_ganssCommonAssistData = -1;    /* GANSSCommonAssistData */
static int hf_rrlp_ganssGenericAssistDataList = -1;  /* SeqOfGANSSGenericAssistDataElement */
static int hf_rrlp_ganssReferenceTime = -1;       /* GANSSReferenceTime */
static int hf_rrlp_ganssRefLocation = -1;         /* GANSSRefLocation */
static int hf_rrlp_ganssIonosphericModel = -1;    /* GANSSIonosphericModel */
static int hf_rrlp_SeqOfGANSSGenericAssistDataElement_item = -1;  /* GANSSGenericAssistDataElement */
static int hf_rrlp_ganssID = -1;                  /* INTEGER_0_7 */
static int hf_rrlp_ganssTimeModel = -1;           /* SeqOfGANSSTimeModel */
static int hf_rrlp_ganssDiffCorrections = -1;     /* GANSSDiffCorrections */
static int hf_rrlp_ganssNavigationModel = -1;     /* GANSSNavModel */
static int hf_rrlp_ganssRealTimeIntegrity = -1;   /* GANSSRealTimeIntegrity */
static int hf_rrlp_ganssDataBitAssist = -1;       /* GANSSDataBitAssist */
static int hf_rrlp_ganssRefMeasurementAssist = -1;  /* GANSSRefMeasurementAssist */
static int hf_rrlp_ganssAlmanacModel = -1;        /* GANSSAlmanacModel */
static int hf_rrlp_ganssUTCModel = -1;            /* GANSSUTCModel */
static int hf_rrlp_ganssRefTimeInfo = -1;         /* GANSSRefTimeInfo */
static int hf_rrlp_ganssTOD_GSMTimeAssociation = -1;  /* GANSSTOD_GSMTimeAssociation */
static int hf_rrlp_ganssDay = -1;                 /* INTEGER_0_8191 */
static int hf_rrlp_ganssTOD = -1;                 /* GANSSTOD */
static int hf_rrlp_ganssTODUncertainty = -1;      /* GANSSTODUncertainty */
static int hf_rrlp_ganssTimeID = -1;              /* INTEGER_0_7 */
static int hf_rrlp_frameDrift = -1;               /* FrameDrift */
static int hf_rrlp_ganssIonoModel = -1;           /* GANSSIonosphereModel */
static int hf_rrlp_ganssIonoStormFlags = -1;      /* GANSSIonoStormFlags */
static int hf_rrlp_ai0 = -1;                      /* INTEGER_0_4095 */
static int hf_rrlp_ai1 = -1;                      /* INTEGER_0_4095 */
static int hf_rrlp_ai2 = -1;                      /* INTEGER_0_4095 */
static int hf_rrlp_ionoStormFlag1 = -1;           /* INTEGER_0_1 */
static int hf_rrlp_ionoStormFlag2 = -1;           /* INTEGER_0_1 */
static int hf_rrlp_ionoStormFlag3 = -1;           /* INTEGER_0_1 */
static int hf_rrlp_ionoStormFlag4 = -1;           /* INTEGER_0_1 */
static int hf_rrlp_ionoStormFlag5 = -1;           /* INTEGER_0_1 */
static int hf_rrlp_SeqOfGANSSTimeModel_item = -1;  /* GANSSTimeModelElement */
static int hf_rrlp_ganssTimeModelRefTime = -1;    /* INTEGER_0_65535 */
static int hf_rrlp_tA0 = -1;                      /* TA0 */
static int hf_rrlp_tA1 = -1;                      /* TA1 */
static int hf_rrlp_tA2 = -1;                      /* TA2 */
static int hf_rrlp_gnssTOID = -1;                 /* INTEGER_0_7 */
static int hf_rrlp_weekNumber = -1;               /* INTEGER_0_8191 */
static int hf_rrlp_dganssRefTime = -1;            /* INTEGER_0_119 */
static int hf_rrlp_sgnTypeList = -1;              /* SeqOfSgnTypeElement */
static int hf_rrlp_SeqOfSgnTypeElement_item = -1;  /* SgnTypeElement */
static int hf_rrlp_ganssSignalID = -1;            /* GANSSSignalID */
static int hf_rrlp_ganssStatusHealth = -1;        /* INTEGER_0_7 */
static int hf_rrlp_dganssSgnList = -1;            /* SeqOfDGANSSSgnElement */
static int hf_rrlp_SeqOfDGANSSSgnElement_item = -1;  /* DGANSSSgnElement */
static int hf_rrlp_svID = -1;                     /* SVID */
static int hf_rrlp_iod = -1;                      /* INTEGER_0_1023 */
static int hf_rrlp_nonBroadcastIndFlag = -1;      /* INTEGER_0_1 */
static int hf_rrlp_toeMSB = -1;                   /* INTEGER_0_31 */
static int hf_rrlp_eMSB = -1;                     /* INTEGER_0_127 */
static int hf_rrlp_sqrtAMBS = -1;                 /* INTEGER_0_63 */
static int hf_rrlp_ganssSatelliteList = -1;       /* SeqOfGANSSSatelliteElement */
static int hf_rrlp_SeqOfGANSSSatelliteElement_item = -1;  /* GANSSSatelliteElement */
static int hf_rrlp_svHealth = -1;                 /* INTEGER_M7_13 */
static int hf_rrlp_ganssClockModel = -1;          /* GANSSClockModel */
static int hf_rrlp_ganssOrbitModel = -1;          /* GANSSOrbitModel */
static int hf_rrlp_keplerianSet = -1;             /* NavModel_KeplerianSet */
static int hf_rrlp_keplerToeLSB = -1;             /* INTEGER_0_511 */
static int hf_rrlp_keplerW = -1;                  /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_keplerDeltaN = -1;             /* INTEGER_M32768_32767 */
static int hf_rrlp_keplerM0 = -1;                 /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_keplerOmegaDot = -1;           /* INTEGER_M8388608_8388607 */
static int hf_rrlp_keplerELSB = -1;               /* INTEGER_0_33554431 */
static int hf_rrlp_keplerIDot = -1;               /* INTEGER_M8192_8191 */
static int hf_rrlp_keplerAPowerHalfLSB = -1;      /* INTEGER_0_67108863 */
static int hf_rrlp_keplerI0 = -1;                 /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_keplerOmega0 = -1;             /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_keplerCrs = -1;                /* INTEGER_M32768_32767 */
static int hf_rrlp_keplerCis = -1;                /* INTEGER_M32768_32767 */
static int hf_rrlp_keplerCus = -1;                /* INTEGER_M32768_32767 */
static int hf_rrlp_keplerCrc = -1;                /* INTEGER_M32768_32767 */
static int hf_rrlp_keplerCic = -1;                /* INTEGER_M32768_32767 */
static int hf_rrlp_keplerCuc = -1;                /* INTEGER_M32768_32767 */
static int hf_rrlp_standardClockModelList = -1;   /* SeqOfStandardClockModelElement */
static int hf_rrlp_SeqOfStandardClockModelElement_item = -1;  /* StandardClockModelElement */
static int hf_rrlp_stanClockTocLSB = -1;          /* INTEGER_0_511 */
static int hf_rrlp_stanClockAF2 = -1;             /* INTEGER_M2048_2047 */
static int hf_rrlp_stanClockAF1 = -1;             /* INTEGER_M131072_131071 */
static int hf_rrlp_stanClockAF0 = -1;             /* INTEGER_M134217728_134217727 */
static int hf_rrlp_stanClockTgd = -1;             /* INTEGER_M512_511 */
static int hf_rrlp_stanModelID = -1;              /* INTEGER_0_1 */
static int hf_rrlp_ganssBadSignalList = -1;       /* SeqOfBadSignalElement */
static int hf_rrlp_SeqOfBadSignalElement_item = -1;  /* BadSignalElement */
static int hf_rrlp_badSVID = -1;                  /* SVID */
static int hf_rrlp_badSignalID = -1;              /* INTEGER_0_3 */
static int hf_rrlp_ganssTOD_01 = -1;              /* INTEGER_0_59 */
static int hf_rrlp_ganssDataTypeID = -1;          /* INTEGER_0_2 */
static int hf_rrlp_ganssDataBits = -1;            /* SeqOf_GANSSDataBits */
static int hf_rrlp_SeqOf_GANSSDataBits_item = -1;  /* GANSSDataBit */
static int hf_rrlp_ganssSignalID_01 = -1;         /* INTEGER_0_3 */
static int hf_rrlp_ganssRefMeasAssitList = -1;    /* SeqOfGANSSRefMeasurementElement */
static int hf_rrlp_SeqOfGANSSRefMeasurementElement_item = -1;  /* GANSSRefMeasurementElement */
static int hf_rrlp_additionalDoppler = -1;        /* AdditionalDopplerFields */
static int hf_rrlp_intCodePhase_01 = -1;          /* INTEGER_0_127 */
static int hf_rrlp_codePhaseSearchWindow_01 = -1;  /* INTEGER_0_31 */
static int hf_rrlp_additionalAngle = -1;          /* AddionalAngleFields */
static int hf_rrlp_dopplerUncertainty_01 = -1;    /* INTEGER_0_4 */
static int hf_rrlp_weekNumber_01 = -1;            /* INTEGER_0_255 */
static int hf_rrlp_svIDMask = -1;                 /* SVIDMASK */
static int hf_rrlp_toa = -1;                      /* INTEGER_0_255 */
static int hf_rrlp_ioda = -1;                     /* INTEGER_0_3 */
static int hf_rrlp_ganssAlmanacList = -1;         /* SeqOfGANSSAlmanacElement */
static int hf_rrlp_SeqOfGANSSAlmanacElement_item = -1;  /* GANSSAlmanacElement */
static int hf_rrlp_keplerianAlmanacSet = -1;      /* Almanac_KeplerianSet */
static int hf_rrlp_kepAlmanacE = -1;              /* INTEGER_0_2047 */
static int hf_rrlp_kepAlmanacDeltaI = -1;         /* INTEGER_M1024_1023 */
static int hf_rrlp_kepAlmanacOmegaDot = -1;       /* INTEGER_M1024_1023 */
static int hf_rrlp_kepSVHealth = -1;              /* INTEGER_0_15 */
static int hf_rrlp_kepAlmanacAPowerHalf = -1;     /* INTEGER_M65536_65535 */
static int hf_rrlp_kepAlmanacOmega0 = -1;         /* INTEGER_M32768_32767 */
static int hf_rrlp_kepAlmanacW = -1;              /* INTEGER_M32768_32767 */
static int hf_rrlp_kepAlmanacM0 = -1;             /* INTEGER_M32768_32767 */
static int hf_rrlp_kepAlmanacAF0 = -1;            /* INTEGER_M8192_8191 */
static int hf_rrlp_kepAlmanacAF1 = -1;            /* INTEGER_M1024_1023 */
static int hf_rrlp_ganssUtcA1 = -1;               /* INTEGER_M8388608_8388607 */
static int hf_rrlp_ganssUtcA0 = -1;               /* INTEGER_M2147483648_2147483647 */
static int hf_rrlp_ganssUtcTot = -1;              /* INTEGER_0_255 */
static int hf_rrlp_ganssUtcWNt = -1;              /* INTEGER_0_255 */
static int hf_rrlp_ganssUtcDeltaTls = -1;         /* INTEGER_M128_127 */
static int hf_rrlp_ganssUtcWNlsf = -1;            /* INTEGER_0_255 */
static int hf_rrlp_ganssUtcDN = -1;               /* INTEGER_M128_127 */
static int hf_rrlp_ganssUtcDeltaTlsf = -1;        /* INTEGER_M128_127 */
static int hf_rrlp_velEstimate = -1;              /* VelocityEstimate */
static int hf_rrlp_ganssLocationInfo = -1;        /* GANSSLocationInfo */
static int hf_rrlp_ganssMeasureInfo = -1;         /* GANSSMeasureInfo */
static int hf_rrlp_referenceFrame = -1;           /* ReferenceFrame */
static int hf_rrlp_ganssTODm = -1;                /* GANSSTODm */
static int hf_rrlp_ganssTODFrac = -1;             /* INTEGER_0_16384 */
static int hf_rrlp_ganssTimeID_01 = -1;           /* INTEGER_0_3 */
static int hf_rrlp_posData = -1;                  /* PositionData */
static int hf_rrlp_stationaryIndication = -1;     /* INTEGER_0_1 */
static int hf_rrlp_referenceFN = -1;              /* INTEGER_0_65535 */
static int hf_rrlp_referenceFNMSB = -1;           /* INTEGER_0_63 */
static int hf_rrlp_ganssMsrSetList = -1;          /* SeqOfGANSS_MsrSetElement */
static int hf_rrlp_SeqOfGANSS_MsrSetElement_item = -1;  /* GANSS_MsrSetElement */
static int hf_rrlp_deltaGNASSTOD = -1;            /* INTEGER_0_127 */
static int hf_rrlp_ganss_SgnTypeList = -1;        /* SeqOfGANSS_SgnTypeElement */
static int hf_rrlp_SeqOfGANSS_SgnTypeElement_item = -1;  /* GANSS_SgnTypeElement */
static int hf_rrlp_ganssSignalID_02 = -1;         /* INTEGER_0_15 */
static int hf_rrlp_ganss_SgnList = -1;            /* SeqOfGANSS_SgnElement */
static int hf_rrlp_SeqOfGANSS_SgnElement_item = -1;  /* GANSS_SgnElement */
static int hf_rrlp_mpathDet = -1;                 /* MpathIndic */
static int hf_rrlp_carrierQualityInd = -1;        /* INTEGER_0_3 */
static int hf_rrlp_codePhase_01 = -1;             /* INTEGER_0_2097151 */
static int hf_rrlp_integerCodePhase = -1;         /* INTEGER_0_63 */
static int hf_rrlp_codePhaseRMSError = -1;        /* INTEGER_0_63 */
static int hf_rrlp_adr = -1;                      /* INTEGER_0_33554431 */
/* named bits */
static int hf_rrlp_GANSSPositioningMethod_gps = -1;
static int hf_rrlp_GANSSPositioningMethod_galileo = -1;
static int hf_rrlp_PositionData_e_otd = -1;
static int hf_rrlp_PositionData_gps = -1;
static int hf_rrlp_PositionData_galileo = -1;

/*--- End of included file: packet-rrlp-hf.c ---*/
#line 64 "packet-rrlp-template.c"

/* Initialize the subtree pointers */
static gint ett_rrlp = -1;

/*--- Included file: packet-rrlp-ett.c ---*/
#line 1 "packet-rrlp-ett.c"
static gint ett_rrlp_ExtensionContainer = -1;
static gint ett_rrlp_PrivateExtensionList = -1;
static gint ett_rrlp_PrivateExtension = -1;
static gint ett_rrlp_PCS_Extensions = -1;
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
static gint ett_rrlp_Rel7_MsrPosition_Req_Extension = -1;
static gint ett_rrlp_GANSSPositioningMethod = -1;
static gint ett_rrlp_GANSS_AssistData = -1;
static gint ett_rrlp_GANSS_ControlHeader = -1;
static gint ett_rrlp_GANSSCommonAssistData = -1;
static gint ett_rrlp_SeqOfGANSSGenericAssistDataElement = -1;
static gint ett_rrlp_GANSSGenericAssistDataElement = -1;
static gint ett_rrlp_GANSSReferenceTime = -1;
static gint ett_rrlp_GANSSRefTimeInfo = -1;
static gint ett_rrlp_GANSSTOD_GSMTimeAssociation = -1;
static gint ett_rrlp_GANSSRefLocation = -1;
static gint ett_rrlp_GANSSIonosphericModel = -1;
static gint ett_rrlp_GANSSIonosphereModel = -1;
static gint ett_rrlp_GANSSIonoStormFlags = -1;
static gint ett_rrlp_SeqOfGANSSTimeModel = -1;
static gint ett_rrlp_GANSSTimeModelElement = -1;
static gint ett_rrlp_GANSSDiffCorrections = -1;
static gint ett_rrlp_SeqOfSgnTypeElement = -1;
static gint ett_rrlp_SgnTypeElement = -1;
static gint ett_rrlp_SeqOfDGANSSSgnElement = -1;
static gint ett_rrlp_DGANSSSgnElement = -1;
static gint ett_rrlp_GANSSNavModel = -1;
static gint ett_rrlp_SeqOfGANSSSatelliteElement = -1;
static gint ett_rrlp_GANSSSatelliteElement = -1;
static gint ett_rrlp_GANSSOrbitModel = -1;
static gint ett_rrlp_NavModel_KeplerianSet = -1;
static gint ett_rrlp_GANSSClockModel = -1;
static gint ett_rrlp_SeqOfStandardClockModelElement = -1;
static gint ett_rrlp_StandardClockModelElement = -1;
static gint ett_rrlp_GANSSRealTimeIntegrity = -1;
static gint ett_rrlp_SeqOfBadSignalElement = -1;
static gint ett_rrlp_BadSignalElement = -1;
static gint ett_rrlp_GANSSDataBitAssist = -1;
static gint ett_rrlp_SeqOf_GANSSDataBits = -1;
static gint ett_rrlp_GANSSRefMeasurementAssist = -1;
static gint ett_rrlp_SeqOfGANSSRefMeasurementElement = -1;
static gint ett_rrlp_GANSSRefMeasurementElement = -1;
static gint ett_rrlp_AdditionalDopplerFields = -1;
static gint ett_rrlp_GANSSAlmanacModel = -1;
static gint ett_rrlp_SeqOfGANSSAlmanacElement = -1;
static gint ett_rrlp_GANSSAlmanacElement = -1;
static gint ett_rrlp_Almanac_KeplerianSet = -1;
static gint ett_rrlp_GANSSUTCModel = -1;
static gint ett_rrlp_Rel_7_MsrPosition_Rsp_Extension = -1;
static gint ett_rrlp_GANSSLocationInfo = -1;
static gint ett_rrlp_PositionData = -1;
static gint ett_rrlp_ReferenceFrame = -1;
static gint ett_rrlp_GANSSMeasureInfo = -1;
static gint ett_rrlp_SeqOfGANSS_MsrSetElement = -1;
static gint ett_rrlp_GANSS_MsrSetElement = -1;
static gint ett_rrlp_SeqOfGANSS_SgnTypeElement = -1;
static gint ett_rrlp_GANSS_SgnTypeElement = -1;
static gint ett_rrlp_SeqOfGANSS_SgnElement = -1;
static gint ett_rrlp_GANSS_SgnElement = -1;
static gint ett_rrlp_Rel7_AssistanceData_Extension = -1;

/*--- End of included file: packet-rrlp-ett.c ---*/
#line 68 "packet-rrlp-template.c"

/* Include constants */

/*--- Included file: packet-rrlp-val.h ---*/
#line 1 "packet-rrlp-val.h"
#define maxNumOfPrivateExtensions      10
#define maxExt_GeographicalInformation 20
#define maxGPSAssistanceData           40
#define maxGANSSAssistanceData         40

/*--- End of included file: packet-rrlp-val.h ---*/
#line 71 "packet-rrlp-template.c"



/*--- Included file: packet-rrlp-fn.c ---*/
#line 1 "packet-rrlp-fn.c"


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
                                                  1, maxNumOfPrivateExtensions);

  return offset;
}


static const per_sequence_t PCS_Extensions_sequence[] = {
  { NULL, 0, 0, NULL }
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
#line 35 "rrlp.cnf"

tvbuff_t *parameter_tvb = NULL;

    offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, maxExt_GeographicalInformation, FALSE, &parameter_tvb);


  if(parameter_tvb)
	dissect_geographical_description(parameter_tvb, actx->pinfo, tree);


  return offset;
}



static int
dissect_rrlp_VelocityEstimate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 7, FALSE, NULL);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_Accuracy(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

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
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_rrlp_MeasureResponseTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

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
                                     2, NULL, FALSE, 0, NULL);

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
                                     3, NULL, TRUE, 0, NULL);

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
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_BSIC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

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
                                     2, NULL, FALSE, 0, NULL);

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
                                                            0U, 51U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_RoughRTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1250U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_FineRTD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_RelDistance(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -200000, 200000U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_RelativeAlt(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -4000, 4000U, NULL, FALSE);

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
                                                  1, 15);

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
                                                  1, 32);

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
                                                            0U, 7559999U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_GPSWeek(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

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
                                                            0U, 2097151U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_TimeSlot(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_BitNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 156U, NULL, FALSE);

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
                                                            0U, 63U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_TLMWord(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_AntiSpoofFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_AlertFlag(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_TLMReservedBits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

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
                                                  1, 12);

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
                                                            0U, 604799U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_239(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 239U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_M2047_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2047, 2047U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_M127_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_M7_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -7, 7U, NULL, FALSE);

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
                                                  1, 16);

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
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_16777215(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777215U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

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
                                                            -128, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_37799(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 37799U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_M32768_32767(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -32768, 32767U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_M2097152_2097151(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2097152, 2097151U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_M2147483648_2147483647(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -2147483648, 2147483647U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_M8388608_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_M8192_8191(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8192, 8191U, NULL, FALSE);

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
                                                  1, 16);

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
                                                            0U, 255U, NULL, FALSE);

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
                                                            -1024, 1023U, NULL, FALSE);

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
                                                  1, 64);

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
                                                            -2048, 2047U, NULL, FALSE);

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
                                                            0U, 1022U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_19(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 19U, NULL, FALSE);

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
                                                  1, 16);

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
                                                  1, 16);

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
                                                            0U, 1250U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_ExpOTDUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

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
                                                  1, 15);

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
                                                  1, 32);

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
                                                            0U, 127U, NULL, FALSE);

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
                                                            0U, 262143U, NULL, FALSE);

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



static int
dissect_rrlp_GANSSPositioningMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     2, 16, FALSE, NULL);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_8191(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8191U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_GANSSTOD(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 86399U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_GANSSTODUncertainty(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

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
                                                            -64, 63U, NULL, FALSE);

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
                                                            0U, 4095U, NULL, FALSE);

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


static const per_sequence_t GANSSCommonAssistData_sequence[] = {
  { &hf_rrlp_ganssReferenceTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSReferenceTime },
  { &hf_rrlp_ganssRefLocation, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSRefLocation },
  { &hf_rrlp_ganssIonosphericModel, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSIonosphericModel },
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
                                                            -2147483648, 2147483647U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_TA1(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_TA2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -64, 63U, NULL, FALSE);

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
                                                  1, 7);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_119(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 119U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_GANSSSignalID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_SVID(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

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
                                                  1, 16);

  return offset;
}


static const per_sequence_t SgnTypeElement_sequence[] = {
  { &hf_rrlp_ganssSignalID  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_GANSSSignalID },
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
                                                  1, 3);

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
dissect_rrlp_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_M7_13(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -7, 13U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_511(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 511U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_M131072_131071(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -131072, 131071U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_M134217728_134217727(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -134217728, 134217727U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_M512_511(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -512, 511U, NULL, FALSE);

  return offset;
}


static const per_sequence_t StandardClockModelElement_sequence[] = {
  { &hf_rrlp_stanClockTocLSB, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_511 },
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
                                                  1, 2);

  return offset;
}


static const value_string rrlp_GANSSClockModel_vals[] = {
  {   0, "standardClockModelList" },
  { 0, NULL }
};

static const per_choice_t GANSSClockModel_choice[] = {
  {   0, &hf_rrlp_standardClockModelList, ASN1_EXTENSION_ROOT    , dissect_rrlp_SeqOfStandardClockModelElement },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_GANSSClockModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_GANSSClockModel, GANSSClockModel_choice,
                                 NULL);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_33554431(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 33554431U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_67108863(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 67108863U, NULL, FALSE);

  return offset;
}


static const per_sequence_t NavModel_KeplerianSet_sequence[] = {
  { &hf_rrlp_keplerToeLSB   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_511 },
  { &hf_rrlp_keplerW        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_keplerDeltaN   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M32768_32767 },
  { &hf_rrlp_keplerM0       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M2147483648_2147483647 },
  { &hf_rrlp_keplerOmegaDot , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8388608_8388607 },
  { &hf_rrlp_keplerELSB     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_33554431 },
  { &hf_rrlp_keplerIDot     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M8192_8191 },
  { &hf_rrlp_keplerAPowerHalfLSB, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_67108863 },
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


static const value_string rrlp_GANSSOrbitModel_vals[] = {
  {   0, "keplerianSet" },
  { 0, NULL }
};

static const per_choice_t GANSSOrbitModel_choice[] = {
  {   0, &hf_rrlp_keplerianSet   , ASN1_EXTENSION_ROOT    , dissect_rrlp_NavModel_KeplerianSet },
  { 0, NULL, 0, NULL }
};

static int
dissect_rrlp_GANSSOrbitModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_rrlp_GANSSOrbitModel, GANSSOrbitModel_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t GANSSSatelliteElement_sequence[] = {
  { &hf_rrlp_svID           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_svHealth       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_M7_13 },
  { &hf_rrlp_iod            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1023 },
  { &hf_rrlp_ganssClockModel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSClockModel },
  { &hf_rrlp_ganssOrbitModel, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSOrbitModel },
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
                                                  1, 32);

  return offset;
}


static const per_sequence_t GANSSNavModel_sequence[] = {
  { &hf_rrlp_nonBroadcastIndFlag, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_1 },
  { &hf_rrlp_toeMSB         , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_31 },
  { &hf_rrlp_eMSB           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_127 },
  { &hf_rrlp_sqrtAMBS       , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_63 },
  { &hf_rrlp_ganssSatelliteList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGANSSSatelliteElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSNavModel(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSNavModel, GANSSNavModel_sequence);

  return offset;
}


static const per_sequence_t BadSignalElement_sequence[] = {
  { &hf_rrlp_badSVID        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_badSignalID    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_3 },
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
                                                  1, 16);

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
                                                            0U, 59U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_2(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_GANSSDataBit(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SeqOf_GANSSDataBits_sequence_of[1] = {
  { &hf_rrlp_SeqOf_GANSSDataBits_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_GANSSDataBit },
};

static int
dissect_rrlp_SeqOf_GANSSDataBits(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_rrlp_SeqOf_GANSSDataBits, SeqOf_GANSSDataBits_sequence_of,
                                                  1, 1024);

  return offset;
}


static const per_sequence_t GANSSDataBitAssist_sequence[] = {
  { &hf_rrlp_ganssTOD_01    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_59 },
  { &hf_rrlp_svID           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_ganssDataTypeID, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_2 },
  { &hf_rrlp_ganssDataBits  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOf_GANSSDataBits },
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
                                                            0U, 4U, NULL, FALSE);

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
                                                  1, 16);

  return offset;
}


static const per_sequence_t GANSSRefMeasurementAssist_sequence[] = {
  { &hf_rrlp_ganssSignalID_01, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_3 },
  { &hf_rrlp_ganssRefMeasAssitList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGANSSRefMeasurementElement },
  { NULL, 0, 0, NULL }
};

static int
dissect_rrlp_GANSSRefMeasurementAssist(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_GANSSRefMeasurementAssist, GANSSRefMeasurementAssist_sequence);

  return offset;
}



static int
dissect_rrlp_SVIDMASK(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 36, FALSE, NULL);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_2047(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2047U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_M65536_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -65536, 65535U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Almanac_KeplerianSet_sequence[] = {
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


static const value_string rrlp_GANSSAlmanacElement_vals[] = {
  {   0, "keplerianAlmanacSet" },
  { 0, NULL }
};

static const per_choice_t GANSSAlmanacElement_choice[] = {
  {   0, &hf_rrlp_keplerianAlmanacSet, ASN1_EXTENSION_ROOT    , dissect_rrlp_Almanac_KeplerianSet },
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
                                                  1, 36);

  return offset;
}


static const per_sequence_t GANSSAlmanacModel_sequence[] = {
  { &hf_rrlp_weekNumber_01  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_255 },
  { &hf_rrlp_svIDMask       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SVIDMASK },
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
                                                  1, 8);

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
                                                            1U, 128U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Rel7_MsrPosition_Req_Extension_sequence[] = {
  { &hf_rrlp_velocityRequested, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_NULL },
  { &hf_rrlp_ganssPositionMethod, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSPositioningMethod },
  { &hf_rrlp_ganss_AssistData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSS_AssistData },
  { &hf_rrlp_ganssCarrierPhaseMeasurementRequest, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_NULL },
  { &hf_rrlp_ganssTODGSMTimeAssociationMeasurementRequest, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_NULL },
  { &hf_rrlp_requiredResponseTime, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_RequiredResponseTime },
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
                                                            2U, 3U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_1_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 3U, NULL, FALSE);

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
                                     3, NULL, FALSE, 0, NULL);

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
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_RequestIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 16U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_SystemInfoIndex(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 32U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_LAC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

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
                                                  1, 3);

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
                                                            0U, 42431U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_ModuloTimeSlot(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_RefQuality(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_NumOfMeasurements(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

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
                                                            0U, 3U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_960(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 960U, NULL, FALSE);

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
                                                            0U, 39999U, NULL, FALSE);

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
                                                  1, 10);

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
                                                  1, 10);

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
                                                  1, 2);

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
                                                            0U, 14399999U, NULL, FALSE);

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
                                                            0U, 1U, NULL, FALSE);

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
                                                            0U, 14399999U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_1024(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1024U, NULL, FALSE);

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
                                     4, NULL, FALSE, 0, NULL);

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
                                                  1, 16);

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
                                                  1, 3);

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
                                     11, NULL, TRUE, 3, NULL);

  return offset;
}



static int
dissect_rrlp_GPSAssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, maxGPSAssistanceData, FALSE, NULL);

  return offset;
}



static int
dissect_rrlp_GANSSAssistanceData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, maxGANSSAssistanceData, FALSE, NULL);

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
                                                  1, 5);

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
                                                            0U, 9999U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GPSTimeAssistanceMeasurements_sequence[] = {
  { &hf_rrlp_referenceFrameMSB, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_63 },
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
                                     2, NULL, FALSE, 0, NULL);

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
                                                            0U, 3599999U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_INTEGER_0_16384(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16384U, NULL, FALSE);

  return offset;
}



static int
dissect_rrlp_PositionData(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     3, 16, FALSE, NULL);

  return offset;
}


static const per_sequence_t GANSSLocationInfo_sequence[] = {
  { &hf_rrlp_referenceFrame , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_ReferenceFrame },
  { &hf_rrlp_ganssTODm      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSTODm },
  { &hf_rrlp_ganssTODFrac   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_16384 },
  { &hf_rrlp_ganssTODUncertainty, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_GANSSTODUncertainty },
  { &hf_rrlp_ganssTimeID_01 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_3 },
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
dissect_rrlp_INTEGER_0_2097151(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2097151U, NULL, FALSE);

  return offset;
}


static const per_sequence_t GANSS_SgnElement_sequence[] = {
  { &hf_rrlp_svID           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SVID },
  { &hf_rrlp_cNo            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_63 },
  { &hf_rrlp_mpathDet       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_MpathIndic },
  { &hf_rrlp_carrierQualityInd, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_3 },
  { &hf_rrlp_codePhase_01   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_2097151 },
  { &hf_rrlp_integerCodePhase, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_63 },
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
                                                  1, 16);

  return offset;
}


static const per_sequence_t GANSS_SgnTypeElement_sequence[] = {
  { &hf_rrlp_ganssSignalID_02, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_INTEGER_0_15 },
  { &hf_rrlp_ganss_SgnList  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGANSS_SgnElement },
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
                                                  1, 6);

  return offset;
}


static const per_sequence_t GANSS_MsrSetElement_sequence[] = {
  { &hf_rrlp_referenceFrame , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_ReferenceFrame },
  { &hf_rrlp_ganssTODm      , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_GANSSTODm },
  { &hf_rrlp_deltaGNASSTOD  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_INTEGER_0_127 },
  { &hf_rrlp_ganssTODUncertainty, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_rrlp_GANSSTODUncertainty },
  { &hf_rrlp_ganss_SgnTypeList, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_rrlp_SeqOfGANSS_SgnTypeElement },
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
                                                  1, 3);

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
                                     2, NULL, FALSE, 0, NULL);

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
                                     6, NULL, TRUE, 0, NULL);

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


static const value_string rrlp_RRLP_Component_vals[] = {
  {   0, "msrPositionReq" },
  {   1, "msrPositionRsp" },
  {   2, "assistanceData" },
  {   3, "assistanceDataAck" },
  {   4, "protocolError" },
  { 0, NULL }
};

static const per_choice_t RRLP_Component_choice[] = {
  {   0, &hf_rrlp_msrPositionReq , ASN1_EXTENSION_ROOT    , dissect_rrlp_MsrPosition_Req },
  {   1, &hf_rrlp_msrPositionRsp , ASN1_EXTENSION_ROOT    , dissect_rrlp_MsrPosition_Rsp },
  {   2, &hf_rrlp_assistanceData , ASN1_EXTENSION_ROOT    , dissect_rrlp_AssistanceData },
  {   3, &hf_rrlp_assistanceDataAck, ASN1_EXTENSION_ROOT    , dissect_rrlp_NULL },
  {   4, &hf_rrlp_protocolError  , ASN1_EXTENSION_ROOT    , dissect_rrlp_ProtocolError },
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
#line 26 "rrlp.cnf"
	
	proto_tree_add_item(tree, proto_rrlp, tvb, 0, -1, FALSE);

	if (check_col(actx->pinfo->cinfo, COL_PROTOCOL)) 
		col_append_str(actx->pinfo->cinfo, COL_PROTOCOL, "/RRLP");

  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_rrlp_PDU, PDU_sequence);

  return offset;
}

/*--- PDUs ---*/

static void dissect_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  dissect_rrlp_PDU(tvb, 0, &asn1_ctx, tree, hf_rrlp_PDU_PDU);
}


/*--- End of included file: packet-rrlp-fn.c ---*/
#line 74 "packet-rrlp-template.c"


/*--- proto_register_rrlp -------------------------------------------*/
void proto_register_rrlp(void) {

  /* List of fields */
  static hf_register_info hf[] = {


/*--- Included file: packet-rrlp-hfarr.c ---*/
#line 1 "packet-rrlp-hfarr.c"
    { &hf_rrlp_PDU_PDU,
      { "PDU", "rrlp.PDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.PDU", HFILL }},
    { &hf_rrlp_privateExtensionList,
      { "privateExtensionList", "rrlp.privateExtensionList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.PrivateExtensionList", HFILL }},
    { &hf_rrlp_pcs_Extensions,
      { "pcs-Extensions", "rrlp.pcs_Extensions",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.PCS_Extensions", HFILL }},
    { &hf_rrlp_PrivateExtensionList_item,
      { "Item", "rrlp.PrivateExtensionList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.PrivateExtension", HFILL }},
    { &hf_rrlp_extId,
      { "extId", "rrlp.extId",
        FT_OID, BASE_NONE, NULL, 0,
        "rrlp.OBJECT_IDENTIFIER", HFILL }},
    { &hf_rrlp_extType,
      { "extType", "rrlp.extType",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.T_extType", HFILL }},
    { &hf_rrlp_referenceNumber,
      { "referenceNumber", "rrlp.referenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_7", HFILL }},
    { &hf_rrlp_component,
      { "component", "rrlp.component",
        FT_UINT32, BASE_DEC, VALS(rrlp_RRLP_Component_vals), 0,
        "rrlp.RRLP_Component", HFILL }},
    { &hf_rrlp_msrPositionReq,
      { "msrPositionReq", "rrlp.msrPositionReq",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.MsrPosition_Req", HFILL }},
    { &hf_rrlp_msrPositionRsp,
      { "msrPositionRsp", "rrlp.msrPositionRsp",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.MsrPosition_Rsp", HFILL }},
    { &hf_rrlp_assistanceData,
      { "assistanceData", "rrlp.assistanceData",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.AssistanceData", HFILL }},
    { &hf_rrlp_assistanceDataAck,
      { "assistanceDataAck", "rrlp.assistanceDataAck",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.NULL", HFILL }},
    { &hf_rrlp_protocolError,
      { "protocolError", "rrlp.protocolError",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.ProtocolError", HFILL }},
    { &hf_rrlp_positionInstruct,
      { "positionInstruct", "rrlp.positionInstruct",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.PositionInstruct", HFILL }},
    { &hf_rrlp_referenceAssistData,
      { "referenceAssistData", "rrlp.referenceAssistData",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.ReferenceAssistData", HFILL }},
    { &hf_rrlp_msrAssistData,
      { "msrAssistData", "rrlp.msrAssistData",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.MsrAssistData", HFILL }},
    { &hf_rrlp_systemInfoAssistData,
      { "systemInfoAssistData", "rrlp.systemInfoAssistData",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.SystemInfoAssistData", HFILL }},
    { &hf_rrlp_gps_AssistData,
      { "gps-AssistData", "rrlp.gps_AssistData",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GPS_AssistData", HFILL }},
    { &hf_rrlp_extensionContainer,
      { "extensionContainer", "rrlp.extensionContainer",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.ExtensionContainer", HFILL }},
    { &hf_rrlp_rel98_MsrPosition_Req_extension,
      { "rel98-MsrPosition-Req-extension", "rrlp.rel98_MsrPosition_Req_extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Rel98_MsrPosition_Req_Extension", HFILL }},
    { &hf_rrlp_rel5_MsrPosition_Req_extension,
      { "rel5-MsrPosition-Req-extension", "rrlp.rel5_MsrPosition_Req_extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Rel5_MsrPosition_Req_Extension", HFILL }},
    { &hf_rrlp_rel7_MsrPosition_Req_extension,
      { "rel7-MsrPosition-Req-extension", "rrlp.rel7_MsrPosition_Req_extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Rel7_MsrPosition_Req_Extension", HFILL }},
    { &hf_rrlp_multipleSets,
      { "multipleSets", "rrlp.multipleSets",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.MultipleSets", HFILL }},
    { &hf_rrlp_referenceIdentity,
      { "referenceIdentity", "rrlp.referenceIdentity",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.ReferenceIdentity", HFILL }},
    { &hf_rrlp_otd_MeasureInfo,
      { "otd-MeasureInfo", "rrlp.otd_MeasureInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.OTD_MeasureInfo", HFILL }},
    { &hf_rrlp_locationInfo,
      { "locationInfo", "rrlp.locationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.LocationInfo", HFILL }},
    { &hf_rrlp_gps_MeasureInfo,
      { "gps-MeasureInfo", "rrlp.gps_MeasureInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GPS_MeasureInfo", HFILL }},
    { &hf_rrlp_locationError,
      { "locationError", "rrlp.locationError",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.LocationError", HFILL }},
    { &hf_rrlp_rel_98_MsrPosition_Rsp_Extension,
      { "rel-98-MsrPosition-Rsp-Extension", "rrlp.rel_98_MsrPosition_Rsp_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Rel_98_MsrPosition_Rsp_Extension", HFILL }},
    { &hf_rrlp_rel_5_MsrPosition_Rsp_Extension,
      { "rel-5-MsrPosition-Rsp-Extension", "rrlp.rel_5_MsrPosition_Rsp_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Rel_5_MsrPosition_Rsp_Extension", HFILL }},
    { &hf_rrlp_rel_7_MsrPosition_Rsp_Extension,
      { "rel-7-MsrPosition-Rsp-Extension", "rrlp.rel_7_MsrPosition_Rsp_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Rel_7_MsrPosition_Rsp_Extension", HFILL }},
    { &hf_rrlp_moreAssDataToBeSent,
      { "moreAssDataToBeSent", "rrlp.moreAssDataToBeSent",
        FT_UINT32, BASE_DEC, VALS(rrlp_MoreAssDataToBeSent_vals), 0,
        "rrlp.MoreAssDataToBeSent", HFILL }},
    { &hf_rrlp_rel98_AssistanceData_Extension,
      { "rel98-AssistanceData-Extension", "rrlp.rel98_AssistanceData_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Rel98_AssistanceData_Extension", HFILL }},
    { &hf_rrlp_rel5_AssistanceData_Extension,
      { "rel5-AssistanceData-Extension", "rrlp.rel5_AssistanceData_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Rel5_AssistanceData_Extension", HFILL }},
    { &hf_rrlp_rel7_AssistanceData_Extension,
      { "rel7-AssistanceData-Extension", "rrlp.rel7_AssistanceData_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Rel7_AssistanceData_Extension", HFILL }},
    { &hf_rrlp_errorCause,
      { "errorCause", "rrlp.errorCause",
        FT_UINT32, BASE_DEC, VALS(rrlp_ErrorCodes_vals), 0,
        "rrlp.ErrorCodes", HFILL }},
    { &hf_rrlp_rel_5_ProtocolError_Extension,
      { "rel-5-ProtocolError-Extension", "rrlp.rel_5_ProtocolError_Extension",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Rel_5_ProtocolError_Extension", HFILL }},
    { &hf_rrlp_methodType,
      { "methodType", "rrlp.methodType",
        FT_UINT32, BASE_DEC, VALS(rrlp_MethodType_vals), 0,
        "rrlp.MethodType", HFILL }},
    { &hf_rrlp_positionMethod,
      { "positionMethod", "rrlp.positionMethod",
        FT_UINT32, BASE_DEC, VALS(rrlp_PositionMethod_vals), 0,
        "rrlp.PositionMethod", HFILL }},
    { &hf_rrlp_measureResponseTime,
      { "measureResponseTime", "rrlp.measureResponseTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.MeasureResponseTime", HFILL }},
    { &hf_rrlp_useMultipleSets,
      { "useMultipleSets", "rrlp.useMultipleSets",
        FT_UINT32, BASE_DEC, VALS(rrlp_UseMultipleSets_vals), 0,
        "rrlp.UseMultipleSets", HFILL }},
    { &hf_rrlp_environmentCharacter,
      { "environmentCharacter", "rrlp.environmentCharacter",
        FT_UINT32, BASE_DEC, VALS(rrlp_EnvironmentCharacter_vals), 0,
        "rrlp.EnvironmentCharacter", HFILL }},
    { &hf_rrlp_msAssisted,
      { "msAssisted", "rrlp.msAssisted",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.AccuracyOpt", HFILL }},
    { &hf_rrlp_msBased,
      { "msBased", "rrlp.msBased",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.Accuracy", HFILL }},
    { &hf_rrlp_msBasedPref,
      { "msBasedPref", "rrlp.msBasedPref",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.Accuracy", HFILL }},
    { &hf_rrlp_msAssistedPref,
      { "msAssistedPref", "rrlp.msAssistedPref",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.Accuracy", HFILL }},
    { &hf_rrlp_accuracy,
      { "accuracy", "rrlp.accuracy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.Accuracy", HFILL }},
    { &hf_rrlp_bcchCarrier,
      { "bcchCarrier", "rrlp.bcchCarrier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.BCCHCarrier", HFILL }},
    { &hf_rrlp_bsic,
      { "bsic", "rrlp.bsic",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.BSIC", HFILL }},
    { &hf_rrlp_timeSlotScheme,
      { "timeSlotScheme", "rrlp.timeSlotScheme",
        FT_UINT32, BASE_DEC, VALS(rrlp_TimeSlotScheme_vals), 0,
        "rrlp.TimeSlotScheme", HFILL }},
    { &hf_rrlp_btsPosition,
      { "btsPosition", "rrlp.btsPosition",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rrlp.BTSPosition", HFILL }},
    { &hf_rrlp_msrAssistList,
      { "msrAssistList", "rrlp.msrAssistList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfMsrAssistBTS", HFILL }},
    { &hf_rrlp_SeqOfMsrAssistBTS_item,
      { "Item", "rrlp.SeqOfMsrAssistBTS_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.MsrAssistBTS", HFILL }},
    { &hf_rrlp_multiFrameOffset,
      { "multiFrameOffset", "rrlp.multiFrameOffset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.MultiFrameOffset", HFILL }},
    { &hf_rrlp_roughRTD,
      { "roughRTD", "rrlp.roughRTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.RoughRTD", HFILL }},
    { &hf_rrlp_calcAssistanceBTS,
      { "calcAssistanceBTS", "rrlp.calcAssistanceBTS",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.CalcAssistanceBTS", HFILL }},
    { &hf_rrlp_systemInfoAssistList,
      { "systemInfoAssistList", "rrlp.systemInfoAssistList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfSystemInfoAssistBTS", HFILL }},
    { &hf_rrlp_SeqOfSystemInfoAssistBTS_item,
      { "Item", "rrlp.SeqOfSystemInfoAssistBTS_item",
        FT_UINT32, BASE_DEC, VALS(rrlp_SystemInfoAssistBTS_vals), 0,
        "rrlp.SystemInfoAssistBTS", HFILL }},
    { &hf_rrlp_notPresent,
      { "notPresent", "rrlp.notPresent",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.NULL", HFILL }},
    { &hf_rrlp_present,
      { "present", "rrlp.present",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.AssistBTSData", HFILL }},
    { &hf_rrlp_fineRTD,
      { "fineRTD", "rrlp.fineRTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.FineRTD", HFILL }},
    { &hf_rrlp_referenceWGS84,
      { "referenceWGS84", "rrlp.referenceWGS84",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.ReferenceWGS84", HFILL }},
    { &hf_rrlp_relativeNorth,
      { "relativeNorth", "rrlp.relativeNorth",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.RelDistance", HFILL }},
    { &hf_rrlp_relativeEast,
      { "relativeEast", "rrlp.relativeEast",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.RelDistance", HFILL }},
    { &hf_rrlp_relativeAlt,
      { "relativeAlt", "rrlp.relativeAlt",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.RelativeAlt", HFILL }},
    { &hf_rrlp_nbrOfSets,
      { "nbrOfSets", "rrlp.nbrOfSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_2_3", HFILL }},
    { &hf_rrlp_nbrOfReferenceBTSs,
      { "nbrOfReferenceBTSs", "rrlp.nbrOfReferenceBTSs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_1_3", HFILL }},
    { &hf_rrlp_referenceRelation,
      { "referenceRelation", "rrlp.referenceRelation",
        FT_UINT32, BASE_DEC, VALS(rrlp_ReferenceRelation_vals), 0,
        "rrlp.ReferenceRelation", HFILL }},
    { &hf_rrlp_refBTSList,
      { "refBTSList", "rrlp.refBTSList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfReferenceIdentityType", HFILL }},
    { &hf_rrlp_SeqOfReferenceIdentityType_item,
      { "Item", "rrlp.SeqOfReferenceIdentityType_item",
        FT_UINT32, BASE_DEC, VALS(rrlp_ReferenceIdentityType_vals), 0,
        "rrlp.ReferenceIdentityType", HFILL }},
    { &hf_rrlp_bsicAndCarrier,
      { "bsicAndCarrier", "rrlp.bsicAndCarrier",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.BSICAndCarrier", HFILL }},
    { &hf_rrlp_ci,
      { "ci", "rrlp.ci",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.CellID", HFILL }},
    { &hf_rrlp_requestIndex,
      { "requestIndex", "rrlp.requestIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.RequestIndex", HFILL }},
    { &hf_rrlp_systemInfoIndex,
      { "systemInfoIndex", "rrlp.systemInfoIndex",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SystemInfoIndex", HFILL }},
    { &hf_rrlp_ciAndLAC,
      { "ciAndLAC", "rrlp.ciAndLAC",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.CellIDAndLAC", HFILL }},
    { &hf_rrlp_carrier,
      { "carrier", "rrlp.carrier",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.BCCHCarrier", HFILL }},
    { &hf_rrlp_referenceLAC,
      { "referenceLAC", "rrlp.referenceLAC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.LAC", HFILL }},
    { &hf_rrlp_referenceCI,
      { "referenceCI", "rrlp.referenceCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.CellID", HFILL }},
    { &hf_rrlp_otdMsrFirstSets,
      { "otdMsrFirstSets", "rrlp.otdMsrFirstSets",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.OTD_MsrElementFirst", HFILL }},
    { &hf_rrlp_otdMsrRestSets,
      { "otdMsrRestSets", "rrlp.otdMsrRestSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfOTD_MsrElementRest", HFILL }},
    { &hf_rrlp_SeqOfOTD_MsrElementRest_item,
      { "Item", "rrlp.SeqOfOTD_MsrElementRest_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.OTD_MsrElementRest", HFILL }},
    { &hf_rrlp_refFrameNumber,
      { "refFrameNumber", "rrlp.refFrameNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_42431", HFILL }},
    { &hf_rrlp_referenceTimeSlot,
      { "referenceTimeSlot", "rrlp.referenceTimeSlot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.ModuloTimeSlot", HFILL }},
    { &hf_rrlp_toaMeasurementsOfRef,
      { "toaMeasurementsOfRef", "rrlp.toaMeasurementsOfRef",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.TOA_MeasurementsOfRef", HFILL }},
    { &hf_rrlp_stdResolution,
      { "stdResolution", "rrlp.stdResolution",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.StdResolution", HFILL }},
    { &hf_rrlp_taCorrection,
      { "taCorrection", "rrlp.taCorrection",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_960", HFILL }},
    { &hf_rrlp_otd_FirstSetMsrs,
      { "otd-FirstSetMsrs", "rrlp.otd_FirstSetMsrs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfOTD_FirstSetMsrs", HFILL }},
    { &hf_rrlp_SeqOfOTD_FirstSetMsrs_item,
      { "Item", "rrlp.SeqOfOTD_FirstSetMsrs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.OTD_FirstSetMsrs", HFILL }},
    { &hf_rrlp_otd_MsrsOfOtherSets,
      { "otd-MsrsOfOtherSets", "rrlp.otd_MsrsOfOtherSets",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfOTD_MsrsOfOtherSets", HFILL }},
    { &hf_rrlp_SeqOfOTD_MsrsOfOtherSets_item,
      { "Item", "rrlp.SeqOfOTD_MsrsOfOtherSets_item",
        FT_UINT32, BASE_DEC, VALS(rrlp_OTD_MsrsOfOtherSets_vals), 0,
        "rrlp.OTD_MsrsOfOtherSets", HFILL }},
    { &hf_rrlp_refQuality,
      { "refQuality", "rrlp.refQuality",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.RefQuality", HFILL }},
    { &hf_rrlp_numOfMeasurements,
      { "numOfMeasurements", "rrlp.numOfMeasurements",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.NumOfMeasurements", HFILL }},
    { &hf_rrlp_identityNotPresent,
      { "identityNotPresent", "rrlp.identityNotPresent",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.OTD_Measurement", HFILL }},
    { &hf_rrlp_identityPresent,
      { "identityPresent", "rrlp.identityPresent",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.OTD_MeasurementWithID", HFILL }},
    { &hf_rrlp_nborTimeSlot,
      { "nborTimeSlot", "rrlp.nborTimeSlot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.ModuloTimeSlot", HFILL }},
    { &hf_rrlp_eotdQuality,
      { "eotdQuality", "rrlp.eotdQuality",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.EOTDQuality", HFILL }},
    { &hf_rrlp_otdValue,
      { "otdValue", "rrlp.otdValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.OTDValue", HFILL }},
    { &hf_rrlp_neighborIdentity,
      { "neighborIdentity", "rrlp.neighborIdentity",
        FT_UINT32, BASE_DEC, VALS(rrlp_NeighborIdentity_vals), 0,
        "rrlp.NeighborIdentity", HFILL }},
    { &hf_rrlp_nbrOfMeasurements,
      { "nbrOfMeasurements", "rrlp.nbrOfMeasurements",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_7", HFILL }},
    { &hf_rrlp_stdOfEOTD,
      { "stdOfEOTD", "rrlp.stdOfEOTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_31", HFILL }},
    { &hf_rrlp_multiFrameCarrier,
      { "multiFrameCarrier", "rrlp.multiFrameCarrier",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.MultiFrameCarrier", HFILL }},
    { &hf_rrlp_refFrame,
      { "refFrame", "rrlp.refFrame",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_65535", HFILL }},
    { &hf_rrlp_gpsTOW,
      { "gpsTOW", "rrlp.gpsTOW",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_14399999", HFILL }},
    { &hf_rrlp_fixType,
      { "fixType", "rrlp.fixType",
        FT_UINT32, BASE_DEC, VALS(rrlp_FixType_vals), 0,
        "rrlp.FixType", HFILL }},
    { &hf_rrlp_posEstimate,
      { "posEstimate", "rrlp.posEstimate",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rrlp.Ext_GeographicalInformation", HFILL }},
    { &hf_rrlp_gpsMsrSetList,
      { "gpsMsrSetList", "rrlp.gpsMsrSetList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfGPS_MsrSetElement", HFILL }},
    { &hf_rrlp_SeqOfGPS_MsrSetElement_item,
      { "Item", "rrlp.SeqOfGPS_MsrSetElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GPS_MsrSetElement", HFILL }},
    { &hf_rrlp_gpsTOW_01,
      { "gpsTOW", "rrlp.gpsTOW",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.GPSTOW24b", HFILL }},
    { &hf_rrlp_gps_msrList,
      { "gps-msrList", "rrlp.gps_msrList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfGPS_MsrElement", HFILL }},
    { &hf_rrlp_SeqOfGPS_MsrElement_item,
      { "Item", "rrlp.SeqOfGPS_MsrElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GPS_MsrElement", HFILL }},
    { &hf_rrlp_satelliteID,
      { "satelliteID", "rrlp.satelliteID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SatelliteID", HFILL }},
    { &hf_rrlp_cNo,
      { "cNo", "rrlp.cNo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_63", HFILL }},
    { &hf_rrlp_doppler,
      { "doppler", "rrlp.doppler",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_wholeChips,
      { "wholeChips", "rrlp.wholeChips",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1022", HFILL }},
    { &hf_rrlp_fracChips,
      { "fracChips", "rrlp.fracChips",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1024", HFILL }},
    { &hf_rrlp_mpathIndic,
      { "mpathIndic", "rrlp.mpathIndic",
        FT_UINT32, BASE_DEC, VALS(rrlp_MpathIndic_vals), 0,
        "rrlp.MpathIndic", HFILL }},
    { &hf_rrlp_pseuRangeRMSErr,
      { "pseuRangeRMSErr", "rrlp.pseuRangeRMSErr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_63", HFILL }},
    { &hf_rrlp_locErrorReason,
      { "locErrorReason", "rrlp.locErrorReason",
        FT_UINT32, BASE_DEC, VALS(rrlp_LocErrorReason_vals), 0,
        "rrlp.LocErrorReason", HFILL }},
    { &hf_rrlp_additionalAssistanceData,
      { "additionalAssistanceData", "rrlp.additionalAssistanceData",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.AdditionalAssistanceData", HFILL }},
    { &hf_rrlp_gpsAssistanceData,
      { "gpsAssistanceData", "rrlp.gpsAssistanceData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rrlp.GPSAssistanceData", HFILL }},
    { &hf_rrlp_ganssAssistanceData,
      { "ganssAssistanceData", "rrlp.ganssAssistanceData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rrlp.GANSSAssistanceData", HFILL }},
    { &hf_rrlp_controlHeader,
      { "controlHeader", "rrlp.controlHeader",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.ControlHeader", HFILL }},
    { &hf_rrlp_referenceTime,
      { "referenceTime", "rrlp.referenceTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.ReferenceTime", HFILL }},
    { &hf_rrlp_refLocation,
      { "refLocation", "rrlp.refLocation",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.RefLocation", HFILL }},
    { &hf_rrlp_dgpsCorrections,
      { "dgpsCorrections", "rrlp.dgpsCorrections",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.DGPSCorrections", HFILL }},
    { &hf_rrlp_navigationModel,
      { "navigationModel", "rrlp.navigationModel",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.NavigationModel", HFILL }},
    { &hf_rrlp_ionosphericModel,
      { "ionosphericModel", "rrlp.ionosphericModel",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.IonosphericModel", HFILL }},
    { &hf_rrlp_utcModel,
      { "utcModel", "rrlp.utcModel",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.UTCModel", HFILL }},
    { &hf_rrlp_almanac,
      { "almanac", "rrlp.almanac",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Almanac", HFILL }},
    { &hf_rrlp_acquisAssist,
      { "acquisAssist", "rrlp.acquisAssist",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.AcquisAssist", HFILL }},
    { &hf_rrlp_realTimeIntegrity,
      { "realTimeIntegrity", "rrlp.realTimeIntegrity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOf_BadSatelliteSet", HFILL }},
    { &hf_rrlp_gpsTime,
      { "gpsTime", "rrlp.gpsTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GPSTime", HFILL }},
    { &hf_rrlp_gsmTime,
      { "gsmTime", "rrlp.gsmTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GSMTime", HFILL }},
    { &hf_rrlp_gpsTowAssist,
      { "gpsTowAssist", "rrlp.gpsTowAssist",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.GPSTOWAssist", HFILL }},
    { &hf_rrlp_gpsTOW23b,
      { "gpsTOW23b", "rrlp.gpsTOW23b",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.GPSTOW23b", HFILL }},
    { &hf_rrlp_gpsWeek,
      { "gpsWeek", "rrlp.gpsWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.GPSWeek", HFILL }},
    { &hf_rrlp_GPSTOWAssist_item,
      { "Item", "rrlp.GPSTOWAssist_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GPSTOWAssistElement", HFILL }},
    { &hf_rrlp_tlmWord,
      { "tlmWord", "rrlp.tlmWord",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.TLMWord", HFILL }},
    { &hf_rrlp_antiSpoof,
      { "antiSpoof", "rrlp.antiSpoof",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.AntiSpoofFlag", HFILL }},
    { &hf_rrlp_alert,
      { "alert", "rrlp.alert",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.AlertFlag", HFILL }},
    { &hf_rrlp_tlmRsvdBits,
      { "tlmRsvdBits", "rrlp.tlmRsvdBits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.TLMReservedBits", HFILL }},
    { &hf_rrlp_frameNumber,
      { "frameNumber", "rrlp.frameNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.FrameNumber", HFILL }},
    { &hf_rrlp_timeSlot,
      { "timeSlot", "rrlp.timeSlot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.TimeSlot", HFILL }},
    { &hf_rrlp_bitNumber,
      { "bitNumber", "rrlp.bitNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.BitNumber", HFILL }},
    { &hf_rrlp_threeDLocation,
      { "threeDLocation", "rrlp.threeDLocation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rrlp.Ext_GeographicalInformation", HFILL }},
    { &hf_rrlp_gpsTOW_02,
      { "gpsTOW", "rrlp.gpsTOW",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_604799", HFILL }},
    { &hf_rrlp_status,
      { "status", "rrlp.status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_7", HFILL }},
    { &hf_rrlp_satList,
      { "satList", "rrlp.satList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfSatElement", HFILL }},
    { &hf_rrlp_SeqOfSatElement_item,
      { "Item", "rrlp.SeqOfSatElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.SatElement", HFILL }},
    { &hf_rrlp_iode,
      { "iode", "rrlp.iode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_239", HFILL }},
    { &hf_rrlp_udre,
      { "udre", "rrlp.udre",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_3", HFILL }},
    { &hf_rrlp_pseudoRangeCor,
      { "pseudoRangeCor", "rrlp.pseudoRangeCor",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2047_2047", HFILL }},
    { &hf_rrlp_rangeRateCor,
      { "rangeRateCor", "rrlp.rangeRateCor",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M127_127", HFILL }},
    { &hf_rrlp_deltaPseudoRangeCor2,
      { "deltaPseudoRangeCor2", "rrlp.deltaPseudoRangeCor2",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M127_127", HFILL }},
    { &hf_rrlp_deltaRangeRateCor2,
      { "deltaRangeRateCor2", "rrlp.deltaRangeRateCor2",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M7_7", HFILL }},
    { &hf_rrlp_deltaPseudoRangeCor3,
      { "deltaPseudoRangeCor3", "rrlp.deltaPseudoRangeCor3",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M127_127", HFILL }},
    { &hf_rrlp_deltaRangeRateCor3,
      { "deltaRangeRateCor3", "rrlp.deltaRangeRateCor3",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M7_7", HFILL }},
    { &hf_rrlp_navModelList,
      { "navModelList", "rrlp.navModelList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfNavModelElement", HFILL }},
    { &hf_rrlp_SeqOfNavModelElement_item,
      { "Item", "rrlp.SeqOfNavModelElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.NavModelElement", HFILL }},
    { &hf_rrlp_satStatus,
      { "satStatus", "rrlp.satStatus",
        FT_UINT32, BASE_DEC, VALS(rrlp_SatStatus_vals), 0,
        "rrlp.SatStatus", HFILL }},
    { &hf_rrlp_newSatelliteAndModelUC,
      { "newSatelliteAndModelUC", "rrlp.newSatelliteAndModelUC",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.UncompressedEphemeris", HFILL }},
    { &hf_rrlp_oldSatelliteAndModel,
      { "oldSatelliteAndModel", "rrlp.oldSatelliteAndModel",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.NULL", HFILL }},
    { &hf_rrlp_newNaviModelUC,
      { "newNaviModelUC", "rrlp.newNaviModelUC",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.UncompressedEphemeris", HFILL }},
    { &hf_rrlp_ephemCodeOnL2,
      { "ephemCodeOnL2", "rrlp.ephemCodeOnL2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_3", HFILL }},
    { &hf_rrlp_ephemURA,
      { "ephemURA", "rrlp.ephemURA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_15", HFILL }},
    { &hf_rrlp_ephemSVhealth,
      { "ephemSVhealth", "rrlp.ephemSVhealth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_63", HFILL }},
    { &hf_rrlp_ephemIODC,
      { "ephemIODC", "rrlp.ephemIODC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1023", HFILL }},
    { &hf_rrlp_ephemL2Pflag,
      { "ephemL2Pflag", "rrlp.ephemL2Pflag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1", HFILL }},
    { &hf_rrlp_ephemSF1Rsvd,
      { "ephemSF1Rsvd", "rrlp.ephemSF1Rsvd",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.EphemerisSubframe1Reserved", HFILL }},
    { &hf_rrlp_ephemTgd,
      { "ephemTgd", "rrlp.ephemTgd",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_ephemToc,
      { "ephemToc", "rrlp.ephemToc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_37799", HFILL }},
    { &hf_rrlp_ephemAF2,
      { "ephemAF2", "rrlp.ephemAF2",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_ephemAF1,
      { "ephemAF1", "rrlp.ephemAF1",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemAF0,
      { "ephemAF0", "rrlp.ephemAF0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2097152_2097151", HFILL }},
    { &hf_rrlp_ephemCrs,
      { "ephemCrs", "rrlp.ephemCrs",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemDeltaN,
      { "ephemDeltaN", "rrlp.ephemDeltaN",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemM0,
      { "ephemM0", "rrlp.ephemM0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_ephemCuc,
      { "ephemCuc", "rrlp.ephemCuc",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemE,
      { "ephemE", "rrlp.ephemE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_4294967295", HFILL }},
    { &hf_rrlp_ephemCus,
      { "ephemCus", "rrlp.ephemCus",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemAPowerHalf,
      { "ephemAPowerHalf", "rrlp.ephemAPowerHalf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_4294967295", HFILL }},
    { &hf_rrlp_ephemToe,
      { "ephemToe", "rrlp.ephemToe",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_37799", HFILL }},
    { &hf_rrlp_ephemFitFlag,
      { "ephemFitFlag", "rrlp.ephemFitFlag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1", HFILL }},
    { &hf_rrlp_ephemAODA,
      { "ephemAODA", "rrlp.ephemAODA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_31", HFILL }},
    { &hf_rrlp_ephemCic,
      { "ephemCic", "rrlp.ephemCic",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemOmegaA0,
      { "ephemOmegaA0", "rrlp.ephemOmegaA0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_ephemCis,
      { "ephemCis", "rrlp.ephemCis",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemI0,
      { "ephemI0", "rrlp.ephemI0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_ephemCrc,
      { "ephemCrc", "rrlp.ephemCrc",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_ephemW,
      { "ephemW", "rrlp.ephemW",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_ephemOmegaADot,
      { "ephemOmegaADot", "rrlp.ephemOmegaADot",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_ephemIDot,
      { "ephemIDot", "rrlp.ephemIDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M8192_8191", HFILL }},
    { &hf_rrlp_reserved1,
      { "reserved1", "rrlp.reserved1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_8388607", HFILL }},
    { &hf_rrlp_reserved2,
      { "reserved2", "rrlp.reserved2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_16777215", HFILL }},
    { &hf_rrlp_reserved3,
      { "reserved3", "rrlp.reserved3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_16777215", HFILL }},
    { &hf_rrlp_reserved4,
      { "reserved4", "rrlp.reserved4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_65535", HFILL }},
    { &hf_rrlp_alfa0,
      { "alfa0", "rrlp.alfa0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_alfa1,
      { "alfa1", "rrlp.alfa1",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_alfa2,
      { "alfa2", "rrlp.alfa2",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_alfa3,
      { "alfa3", "rrlp.alfa3",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_beta0,
      { "beta0", "rrlp.beta0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_beta1,
      { "beta1", "rrlp.beta1",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_beta2,
      { "beta2", "rrlp.beta2",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_beta3,
      { "beta3", "rrlp.beta3",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_utcA1,
      { "utcA1", "rrlp.utcA1",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_utcA0,
      { "utcA0", "rrlp.utcA0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_utcTot,
      { "utcTot", "rrlp.utcTot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_255", HFILL }},
    { &hf_rrlp_utcWNt,
      { "utcWNt", "rrlp.utcWNt",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_255", HFILL }},
    { &hf_rrlp_utcDeltaTls,
      { "utcDeltaTls", "rrlp.utcDeltaTls",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_utcWNlsf,
      { "utcWNlsf", "rrlp.utcWNlsf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_255", HFILL }},
    { &hf_rrlp_utcDN,
      { "utcDN", "rrlp.utcDN",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_utcDeltaTlsf,
      { "utcDeltaTlsf", "rrlp.utcDeltaTlsf",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_alamanacWNa,
      { "alamanacWNa", "rrlp.alamanacWNa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_255", HFILL }},
    { &hf_rrlp_almanacList,
      { "almanacList", "rrlp.almanacList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfAlmanacElement", HFILL }},
    { &hf_rrlp_SeqOfAlmanacElement_item,
      { "Item", "rrlp.SeqOfAlmanacElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.AlmanacElement", HFILL }},
    { &hf_rrlp_almanacE,
      { "almanacE", "rrlp.almanacE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_65535", HFILL }},
    { &hf_rrlp_alamanacToa,
      { "alamanacToa", "rrlp.alamanacToa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_255", HFILL }},
    { &hf_rrlp_almanacKsii,
      { "almanacKsii", "rrlp.almanacKsii",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_almanacOmegaDot,
      { "almanacOmegaDot", "rrlp.almanacOmegaDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_almanacSVhealth,
      { "almanacSVhealth", "rrlp.almanacSVhealth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_255", HFILL }},
    { &hf_rrlp_almanacAPowerHalf,
      { "almanacAPowerHalf", "rrlp.almanacAPowerHalf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_16777215", HFILL }},
    { &hf_rrlp_almanacOmega0,
      { "almanacOmega0", "rrlp.almanacOmega0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_almanacW,
      { "almanacW", "rrlp.almanacW",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_almanacM0,
      { "almanacM0", "rrlp.almanacM0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_almanacAF0,
      { "almanacAF0", "rrlp.almanacAF0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_almanacAF1,
      { "almanacAF1", "rrlp.almanacAF1",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_timeRelation,
      { "timeRelation", "rrlp.timeRelation",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.TimeRelation", HFILL }},
    { &hf_rrlp_acquisList,
      { "acquisList", "rrlp.acquisList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfAcquisElement", HFILL }},
    { &hf_rrlp_SeqOfAcquisElement_item,
      { "Item", "rrlp.SeqOfAcquisElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.AcquisElement", HFILL }},
    { &hf_rrlp_gpsTOW_03,
      { "gpsTOW", "rrlp.gpsTOW",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.GPSTOW23b", HFILL }},
    { &hf_rrlp_svid,
      { "svid", "rrlp.svid",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SatelliteID", HFILL }},
    { &hf_rrlp_doppler0,
      { "doppler0", "rrlp.doppler0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2048_2047", HFILL }},
    { &hf_rrlp_addionalDoppler,
      { "addionalDoppler", "rrlp.addionalDoppler",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.AddionalDopplerFields", HFILL }},
    { &hf_rrlp_codePhase,
      { "codePhase", "rrlp.codePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1022", HFILL }},
    { &hf_rrlp_intCodePhase,
      { "intCodePhase", "rrlp.intCodePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_19", HFILL }},
    { &hf_rrlp_gpsBitNumber,
      { "gpsBitNumber", "rrlp.gpsBitNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_3", HFILL }},
    { &hf_rrlp_codePhaseSearchWindow,
      { "codePhaseSearchWindow", "rrlp.codePhaseSearchWindow",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_15", HFILL }},
    { &hf_rrlp_addionalAngle,
      { "addionalAngle", "rrlp.addionalAngle",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.AddionalAngleFields", HFILL }},
    { &hf_rrlp_doppler1,
      { "doppler1", "rrlp.doppler1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_63", HFILL }},
    { &hf_rrlp_dopplerUncertainty,
      { "dopplerUncertainty", "rrlp.dopplerUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_7", HFILL }},
    { &hf_rrlp_azimuth,
      { "azimuth", "rrlp.azimuth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_31", HFILL }},
    { &hf_rrlp_elevation,
      { "elevation", "rrlp.elevation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_7", HFILL }},
    { &hf_rrlp_SeqOf_BadSatelliteSet_item,
      { "Item", "rrlp.SeqOf_BadSatelliteSet_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SatelliteID", HFILL }},
    { &hf_rrlp_rel98_Ext_ExpOTD,
      { "rel98-Ext-ExpOTD", "rrlp.rel98_Ext_ExpOTD",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Rel98_Ext_ExpOTD", HFILL }},
    { &hf_rrlp_gpsTimeAssistanceMeasurementRequest,
      { "gpsTimeAssistanceMeasurementRequest", "rrlp.gpsTimeAssistanceMeasurementRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.NULL", HFILL }},
    { &hf_rrlp_gpsReferenceTimeUncertainty,
      { "gpsReferenceTimeUncertainty", "rrlp.gpsReferenceTimeUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.GPSReferenceTimeUncertainty", HFILL }},
    { &hf_rrlp_msrAssistData_R98_ExpOTD,
      { "msrAssistData-R98-ExpOTD", "rrlp.msrAssistData_R98_ExpOTD",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.MsrAssistData_R98_ExpOTD", HFILL }},
    { &hf_rrlp_systemInfoAssistData_R98_ExpOTD,
      { "systemInfoAssistData-R98-ExpOTD", "rrlp.systemInfoAssistData_R98_ExpOTD",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.SystemInfoAssistData_R98_ExpOTD", HFILL }},
    { &hf_rrlp_msrAssistList_R98_ExpOTD,
      { "msrAssistList-R98-ExpOTD", "rrlp.msrAssistList_R98_ExpOTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfMsrAssistBTS_R98_ExpOTD", HFILL }},
    { &hf_rrlp_SeqOfMsrAssistBTS_R98_ExpOTD_item,
      { "Item", "rrlp.SeqOfMsrAssistBTS_R98_ExpOTD_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.MsrAssistBTS_R98_ExpOTD", HFILL }},
    { &hf_rrlp_expectedOTD,
      { "expectedOTD", "rrlp.expectedOTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.ExpectedOTD", HFILL }},
    { &hf_rrlp_expOTDUncertainty,
      { "expOTDUncertainty", "rrlp.expOTDUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.ExpOTDUncertainty", HFILL }},
    { &hf_rrlp_systemInfoAssistListR98_ExpOTD,
      { "systemInfoAssistListR98-ExpOTD", "rrlp.systemInfoAssistListR98_ExpOTD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfSystemInfoAssistBTS_R98_ExpOTD", HFILL }},
    { &hf_rrlp_SeqOfSystemInfoAssistBTS_R98_ExpOTD_item,
      { "Item", "rrlp.SeqOfSystemInfoAssistBTS_R98_ExpOTD_item",
        FT_UINT32, BASE_DEC, VALS(rrlp_SystemInfoAssistBTS_R98_ExpOTD_vals), 0,
        "rrlp.SystemInfoAssistBTS_R98_ExpOTD", HFILL }},
    { &hf_rrlp_present_01,
      { "present", "rrlp.present",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.AssistBTSData_R98_ExpOTD", HFILL }},
    { &hf_rrlp_expOTDuncertainty,
      { "expOTDuncertainty", "rrlp.expOTDuncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.ExpOTDUncertainty", HFILL }},
    { &hf_rrlp_referenceFrameMSB,
      { "referenceFrameMSB", "rrlp.referenceFrameMSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_63", HFILL }},
    { &hf_rrlp_gpsTowSubms,
      { "gpsTowSubms", "rrlp.gpsTowSubms",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_9999", HFILL }},
    { &hf_rrlp_deltaTow,
      { "deltaTow", "rrlp.deltaTow",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_127", HFILL }},
    { &hf_rrlp_rel_98_Ext_MeasureInfo,
      { "rel-98-Ext-MeasureInfo", "rrlp.rel_98_Ext_MeasureInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.T_rel_98_Ext_MeasureInfo", HFILL }},
    { &hf_rrlp_otd_MeasureInfo_R98_Ext,
      { "otd-MeasureInfo-R98-Ext", "rrlp.otd_MeasureInfo_R98_Ext",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.OTD_MeasureInfo_R98_Ext", HFILL }},
    { &hf_rrlp_timeAssistanceMeasurements,
      { "timeAssistanceMeasurements", "rrlp.timeAssistanceMeasurements",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GPSTimeAssistanceMeasurements", HFILL }},
    { &hf_rrlp_otdMsrFirstSets_R98_Ext,
      { "otdMsrFirstSets-R98-Ext", "rrlp.otdMsrFirstSets_R98_Ext",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.OTD_MsrElementFirst_R98_Ext", HFILL }},
    { &hf_rrlp_otd_FirstSetMsrs_R98_Ext,
      { "otd-FirstSetMsrs-R98-Ext", "rrlp.otd_FirstSetMsrs_R98_Ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfOTD_FirstSetMsrs_R98_Ext", HFILL }},
    { &hf_rrlp_SeqOfOTD_FirstSetMsrs_R98_Ext_item,
      { "Item", "rrlp.SeqOfOTD_FirstSetMsrs_R98_Ext_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.OTD_FirstSetMsrs", HFILL }},
    { &hf_rrlp_extended_reference,
      { "extended-reference", "rrlp.extended_reference",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Extended_reference", HFILL }},
    { &hf_rrlp_otd_MeasureInfo_5_Ext,
      { "otd-MeasureInfo-5-Ext", "rrlp.otd_MeasureInfo_5_Ext",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.OTD_MeasureInfo_5_Ext", HFILL }},
    { &hf_rrlp_ulPseudoSegInd,
      { "ulPseudoSegInd", "rrlp.ulPseudoSegInd",
        FT_UINT32, BASE_DEC, VALS(rrlp_UlPseudoSegInd_vals), 0,
        "rrlp.UlPseudoSegInd", HFILL }},
    { &hf_rrlp_smlc_code,
      { "smlc-code", "rrlp.smlc_code",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_63", HFILL }},
    { &hf_rrlp_transaction_ID,
      { "transaction-ID", "rrlp.transaction_ID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_262143", HFILL }},
    { &hf_rrlp_velocityRequested,
      { "velocityRequested", "rrlp.velocityRequested",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.NULL", HFILL }},
    { &hf_rrlp_ganssPositionMethod,
      { "ganssPositionMethod", "rrlp.ganssPositionMethod",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rrlp.GANSSPositioningMethod", HFILL }},
    { &hf_rrlp_ganss_AssistData,
      { "ganss-AssistData", "rrlp.ganss_AssistData",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSS_AssistData", HFILL }},
    { &hf_rrlp_ganssCarrierPhaseMeasurementRequest,
      { "ganssCarrierPhaseMeasurementRequest", "rrlp.ganssCarrierPhaseMeasurementRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.NULL", HFILL }},
    { &hf_rrlp_ganssTODGSMTimeAssociationMeasurementRequest,
      { "ganssTODGSMTimeAssociationMeasurementRequest", "rrlp.ganssTODGSMTimeAssociationMeasurementRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.NULL", HFILL }},
    { &hf_rrlp_requiredResponseTime,
      { "requiredResponseTime", "rrlp.requiredResponseTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.RequiredResponseTime", HFILL }},
    { &hf_rrlp_ganss_controlHeader,
      { "ganss-controlHeader", "rrlp.ganss_controlHeader",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSS_ControlHeader", HFILL }},
    { &hf_rrlp_ganssCommonAssistData,
      { "ganssCommonAssistData", "rrlp.ganssCommonAssistData",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSCommonAssistData", HFILL }},
    { &hf_rrlp_ganssGenericAssistDataList,
      { "ganssGenericAssistDataList", "rrlp.ganssGenericAssistDataList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfGANSSGenericAssistDataElement", HFILL }},
    { &hf_rrlp_ganssReferenceTime,
      { "ganssReferenceTime", "rrlp.ganssReferenceTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSReferenceTime", HFILL }},
    { &hf_rrlp_ganssRefLocation,
      { "ganssRefLocation", "rrlp.ganssRefLocation",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSRefLocation", HFILL }},
    { &hf_rrlp_ganssIonosphericModel,
      { "ganssIonosphericModel", "rrlp.ganssIonosphericModel",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSIonosphericModel", HFILL }},
    { &hf_rrlp_SeqOfGANSSGenericAssistDataElement_item,
      { "Item", "rrlp.SeqOfGANSSGenericAssistDataElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSGenericAssistDataElement", HFILL }},
    { &hf_rrlp_ganssID,
      { "ganssID", "rrlp.ganssID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_7", HFILL }},
    { &hf_rrlp_ganssTimeModel,
      { "ganssTimeModel", "rrlp.ganssTimeModel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfGANSSTimeModel", HFILL }},
    { &hf_rrlp_ganssDiffCorrections,
      { "ganssDiffCorrections", "rrlp.ganssDiffCorrections",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSDiffCorrections", HFILL }},
    { &hf_rrlp_ganssNavigationModel,
      { "ganssNavigationModel", "rrlp.ganssNavigationModel",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSNavModel", HFILL }},
    { &hf_rrlp_ganssRealTimeIntegrity,
      { "ganssRealTimeIntegrity", "rrlp.ganssRealTimeIntegrity",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSRealTimeIntegrity", HFILL }},
    { &hf_rrlp_ganssDataBitAssist,
      { "ganssDataBitAssist", "rrlp.ganssDataBitAssist",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSDataBitAssist", HFILL }},
    { &hf_rrlp_ganssRefMeasurementAssist,
      { "ganssRefMeasurementAssist", "rrlp.ganssRefMeasurementAssist",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSRefMeasurementAssist", HFILL }},
    { &hf_rrlp_ganssAlmanacModel,
      { "ganssAlmanacModel", "rrlp.ganssAlmanacModel",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSAlmanacModel", HFILL }},
    { &hf_rrlp_ganssUTCModel,
      { "ganssUTCModel", "rrlp.ganssUTCModel",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSUTCModel", HFILL }},
    { &hf_rrlp_ganssRefTimeInfo,
      { "ganssRefTimeInfo", "rrlp.ganssRefTimeInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSRefTimeInfo", HFILL }},
    { &hf_rrlp_ganssTOD_GSMTimeAssociation,
      { "ganssTOD-GSMTimeAssociation", "rrlp.ganssTOD_GSMTimeAssociation",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSTOD_GSMTimeAssociation", HFILL }},
    { &hf_rrlp_ganssDay,
      { "ganssDay", "rrlp.ganssDay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_8191", HFILL }},
    { &hf_rrlp_ganssTOD,
      { "ganssTOD", "rrlp.ganssTOD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.GANSSTOD", HFILL }},
    { &hf_rrlp_ganssTODUncertainty,
      { "ganssTODUncertainty", "rrlp.ganssTODUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.GANSSTODUncertainty", HFILL }},
    { &hf_rrlp_ganssTimeID,
      { "ganssTimeID", "rrlp.ganssTimeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_7", HFILL }},
    { &hf_rrlp_frameDrift,
      { "frameDrift", "rrlp.frameDrift",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.FrameDrift", HFILL }},
    { &hf_rrlp_ganssIonoModel,
      { "ganssIonoModel", "rrlp.ganssIonoModel",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSIonosphereModel", HFILL }},
    { &hf_rrlp_ganssIonoStormFlags,
      { "ganssIonoStormFlags", "rrlp.ganssIonoStormFlags",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSIonoStormFlags", HFILL }},
    { &hf_rrlp_ai0,
      { "ai0", "rrlp.ai0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_4095", HFILL }},
    { &hf_rrlp_ai1,
      { "ai1", "rrlp.ai1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_4095", HFILL }},
    { &hf_rrlp_ai2,
      { "ai2", "rrlp.ai2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_4095", HFILL }},
    { &hf_rrlp_ionoStormFlag1,
      { "ionoStormFlag1", "rrlp.ionoStormFlag1",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1", HFILL }},
    { &hf_rrlp_ionoStormFlag2,
      { "ionoStormFlag2", "rrlp.ionoStormFlag2",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1", HFILL }},
    { &hf_rrlp_ionoStormFlag3,
      { "ionoStormFlag3", "rrlp.ionoStormFlag3",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1", HFILL }},
    { &hf_rrlp_ionoStormFlag4,
      { "ionoStormFlag4", "rrlp.ionoStormFlag4",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1", HFILL }},
    { &hf_rrlp_ionoStormFlag5,
      { "ionoStormFlag5", "rrlp.ionoStormFlag5",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1", HFILL }},
    { &hf_rrlp_SeqOfGANSSTimeModel_item,
      { "Item", "rrlp.SeqOfGANSSTimeModel_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSTimeModelElement", HFILL }},
    { &hf_rrlp_ganssTimeModelRefTime,
      { "ganssTimeModelRefTime", "rrlp.ganssTimeModelRefTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_65535", HFILL }},
    { &hf_rrlp_tA0,
      { "tA0", "rrlp.tA0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.TA0", HFILL }},
    { &hf_rrlp_tA1,
      { "tA1", "rrlp.tA1",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.TA1", HFILL }},
    { &hf_rrlp_tA2,
      { "tA2", "rrlp.tA2",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.TA2", HFILL }},
    { &hf_rrlp_gnssTOID,
      { "gnssTOID", "rrlp.gnssTOID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_7", HFILL }},
    { &hf_rrlp_weekNumber,
      { "weekNumber", "rrlp.weekNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_8191", HFILL }},
    { &hf_rrlp_dganssRefTime,
      { "dganssRefTime", "rrlp.dganssRefTime",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_119", HFILL }},
    { &hf_rrlp_sgnTypeList,
      { "sgnTypeList", "rrlp.sgnTypeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfSgnTypeElement", HFILL }},
    { &hf_rrlp_SeqOfSgnTypeElement_item,
      { "Item", "rrlp.SeqOfSgnTypeElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.SgnTypeElement", HFILL }},
    { &hf_rrlp_ganssSignalID,
      { "ganssSignalID", "rrlp.ganssSignalID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.GANSSSignalID", HFILL }},
    { &hf_rrlp_ganssStatusHealth,
      { "ganssStatusHealth", "rrlp.ganssStatusHealth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_7", HFILL }},
    { &hf_rrlp_dganssSgnList,
      { "dganssSgnList", "rrlp.dganssSgnList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfDGANSSSgnElement", HFILL }},
    { &hf_rrlp_SeqOfDGANSSSgnElement_item,
      { "Item", "rrlp.SeqOfDGANSSSgnElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.DGANSSSgnElement", HFILL }},
    { &hf_rrlp_svID,
      { "svID", "rrlp.svID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SVID", HFILL }},
    { &hf_rrlp_iod,
      { "iod", "rrlp.iod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1023", HFILL }},
    { &hf_rrlp_nonBroadcastIndFlag,
      { "nonBroadcastIndFlag", "rrlp.nonBroadcastIndFlag",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1", HFILL }},
    { &hf_rrlp_toeMSB,
      { "toeMSB", "rrlp.toeMSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_31", HFILL }},
    { &hf_rrlp_eMSB,
      { "eMSB", "rrlp.eMSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_127", HFILL }},
    { &hf_rrlp_sqrtAMBS,
      { "sqrtAMBS", "rrlp.sqrtAMBS",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_63", HFILL }},
    { &hf_rrlp_ganssSatelliteList,
      { "ganssSatelliteList", "rrlp.ganssSatelliteList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfGANSSSatelliteElement", HFILL }},
    { &hf_rrlp_SeqOfGANSSSatelliteElement_item,
      { "Item", "rrlp.SeqOfGANSSSatelliteElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSSatelliteElement", HFILL }},
    { &hf_rrlp_svHealth,
      { "svHealth", "rrlp.svHealth",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M7_13", HFILL }},
    { &hf_rrlp_ganssClockModel,
      { "ganssClockModel", "rrlp.ganssClockModel",
        FT_UINT32, BASE_DEC, VALS(rrlp_GANSSClockModel_vals), 0,
        "rrlp.GANSSClockModel", HFILL }},
    { &hf_rrlp_ganssOrbitModel,
      { "ganssOrbitModel", "rrlp.ganssOrbitModel",
        FT_UINT32, BASE_DEC, VALS(rrlp_GANSSOrbitModel_vals), 0,
        "rrlp.GANSSOrbitModel", HFILL }},
    { &hf_rrlp_keplerianSet,
      { "keplerianSet", "rrlp.keplerianSet",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.NavModel_KeplerianSet", HFILL }},
    { &hf_rrlp_keplerToeLSB,
      { "keplerToeLSB", "rrlp.keplerToeLSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_511", HFILL }},
    { &hf_rrlp_keplerW,
      { "keplerW", "rrlp.keplerW",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_keplerDeltaN,
      { "keplerDeltaN", "rrlp.keplerDeltaN",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_keplerM0,
      { "keplerM0", "rrlp.keplerM0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_keplerOmegaDot,
      { "keplerOmegaDot", "rrlp.keplerOmegaDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_keplerELSB,
      { "keplerELSB", "rrlp.keplerELSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_33554431", HFILL }},
    { &hf_rrlp_keplerIDot,
      { "keplerIDot", "rrlp.keplerIDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M8192_8191", HFILL }},
    { &hf_rrlp_keplerAPowerHalfLSB,
      { "keplerAPowerHalfLSB", "rrlp.keplerAPowerHalfLSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_67108863", HFILL }},
    { &hf_rrlp_keplerI0,
      { "keplerI0", "rrlp.keplerI0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_keplerOmega0,
      { "keplerOmega0", "rrlp.keplerOmega0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_keplerCrs,
      { "keplerCrs", "rrlp.keplerCrs",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_keplerCis,
      { "keplerCis", "rrlp.keplerCis",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_keplerCus,
      { "keplerCus", "rrlp.keplerCus",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_keplerCrc,
      { "keplerCrc", "rrlp.keplerCrc",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_keplerCic,
      { "keplerCic", "rrlp.keplerCic",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_keplerCuc,
      { "keplerCuc", "rrlp.keplerCuc",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_standardClockModelList,
      { "standardClockModelList", "rrlp.standardClockModelList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfStandardClockModelElement", HFILL }},
    { &hf_rrlp_SeqOfStandardClockModelElement_item,
      { "Item", "rrlp.SeqOfStandardClockModelElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.StandardClockModelElement", HFILL }},
    { &hf_rrlp_stanClockTocLSB,
      { "stanClockTocLSB", "rrlp.stanClockTocLSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_511", HFILL }},
    { &hf_rrlp_stanClockAF2,
      { "stanClockAF2", "rrlp.stanClockAF2",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2048_2047", HFILL }},
    { &hf_rrlp_stanClockAF1,
      { "stanClockAF1", "rrlp.stanClockAF1",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M131072_131071", HFILL }},
    { &hf_rrlp_stanClockAF0,
      { "stanClockAF0", "rrlp.stanClockAF0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M134217728_134217727", HFILL }},
    { &hf_rrlp_stanClockTgd,
      { "stanClockTgd", "rrlp.stanClockTgd",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M512_511", HFILL }},
    { &hf_rrlp_stanModelID,
      { "stanModelID", "rrlp.stanModelID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1", HFILL }},
    { &hf_rrlp_ganssBadSignalList,
      { "ganssBadSignalList", "rrlp.ganssBadSignalList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfBadSignalElement", HFILL }},
    { &hf_rrlp_SeqOfBadSignalElement_item,
      { "Item", "rrlp.SeqOfBadSignalElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.BadSignalElement", HFILL }},
    { &hf_rrlp_badSVID,
      { "badSVID", "rrlp.badSVID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SVID", HFILL }},
    { &hf_rrlp_badSignalID,
      { "badSignalID", "rrlp.badSignalID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_3", HFILL }},
    { &hf_rrlp_ganssTOD_01,
      { "ganssTOD", "rrlp.ganssTOD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_59", HFILL }},
    { &hf_rrlp_ganssDataTypeID,
      { "ganssDataTypeID", "rrlp.ganssDataTypeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_2", HFILL }},
    { &hf_rrlp_ganssDataBits,
      { "ganssDataBits", "rrlp.ganssDataBits",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOf_GANSSDataBits", HFILL }},
    { &hf_rrlp_SeqOf_GANSSDataBits_item,
      { "Item", "rrlp.SeqOf_GANSSDataBits_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.GANSSDataBit", HFILL }},
    { &hf_rrlp_ganssSignalID_01,
      { "ganssSignalID", "rrlp.ganssSignalID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_3", HFILL }},
    { &hf_rrlp_ganssRefMeasAssitList,
      { "ganssRefMeasAssitList", "rrlp.ganssRefMeasAssitList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfGANSSRefMeasurementElement", HFILL }},
    { &hf_rrlp_SeqOfGANSSRefMeasurementElement_item,
      { "Item", "rrlp.SeqOfGANSSRefMeasurementElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSRefMeasurementElement", HFILL }},
    { &hf_rrlp_additionalDoppler,
      { "additionalDoppler", "rrlp.additionalDoppler",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.AdditionalDopplerFields", HFILL }},
    { &hf_rrlp_intCodePhase_01,
      { "intCodePhase", "rrlp.intCodePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_127", HFILL }},
    { &hf_rrlp_codePhaseSearchWindow_01,
      { "codePhaseSearchWindow", "rrlp.codePhaseSearchWindow",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_31", HFILL }},
    { &hf_rrlp_additionalAngle,
      { "additionalAngle", "rrlp.additionalAngle",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.AddionalAngleFields", HFILL }},
    { &hf_rrlp_dopplerUncertainty_01,
      { "dopplerUncertainty", "rrlp.dopplerUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_4", HFILL }},
    { &hf_rrlp_weekNumber_01,
      { "weekNumber", "rrlp.weekNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_255", HFILL }},
    { &hf_rrlp_svIDMask,
      { "svIDMask", "rrlp.svIDMask",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rrlp.SVIDMASK", HFILL }},
    { &hf_rrlp_toa,
      { "toa", "rrlp.toa",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_255", HFILL }},
    { &hf_rrlp_ioda,
      { "ioda", "rrlp.ioda",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_3", HFILL }},
    { &hf_rrlp_ganssAlmanacList,
      { "ganssAlmanacList", "rrlp.ganssAlmanacList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfGANSSAlmanacElement", HFILL }},
    { &hf_rrlp_SeqOfGANSSAlmanacElement_item,
      { "Item", "rrlp.SeqOfGANSSAlmanacElement_item",
        FT_UINT32, BASE_DEC, VALS(rrlp_GANSSAlmanacElement_vals), 0,
        "rrlp.GANSSAlmanacElement", HFILL }},
    { &hf_rrlp_keplerianAlmanacSet,
      { "keplerianAlmanacSet", "rrlp.keplerianAlmanacSet",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.Almanac_KeplerianSet", HFILL }},
    { &hf_rrlp_kepAlmanacE,
      { "kepAlmanacE", "rrlp.kepAlmanacE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_2047", HFILL }},
    { &hf_rrlp_kepAlmanacDeltaI,
      { "kepAlmanacDeltaI", "rrlp.kepAlmanacDeltaI",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_kepAlmanacOmegaDot,
      { "kepAlmanacOmegaDot", "rrlp.kepAlmanacOmegaDot",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_kepSVHealth,
      { "kepSVHealth", "rrlp.kepSVHealth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_15", HFILL }},
    { &hf_rrlp_kepAlmanacAPowerHalf,
      { "kepAlmanacAPowerHalf", "rrlp.kepAlmanacAPowerHalf",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M65536_65535", HFILL }},
    { &hf_rrlp_kepAlmanacOmega0,
      { "kepAlmanacOmega0", "rrlp.kepAlmanacOmega0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_kepAlmanacW,
      { "kepAlmanacW", "rrlp.kepAlmanacW",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_kepAlmanacM0,
      { "kepAlmanacM0", "rrlp.kepAlmanacM0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M32768_32767", HFILL }},
    { &hf_rrlp_kepAlmanacAF0,
      { "kepAlmanacAF0", "rrlp.kepAlmanacAF0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M8192_8191", HFILL }},
    { &hf_rrlp_kepAlmanacAF1,
      { "kepAlmanacAF1", "rrlp.kepAlmanacAF1",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M1024_1023", HFILL }},
    { &hf_rrlp_ganssUtcA1,
      { "ganssUtcA1", "rrlp.ganssUtcA1",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M8388608_8388607", HFILL }},
    { &hf_rrlp_ganssUtcA0,
      { "ganssUtcA0", "rrlp.ganssUtcA0",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M2147483648_2147483647", HFILL }},
    { &hf_rrlp_ganssUtcTot,
      { "ganssUtcTot", "rrlp.ganssUtcTot",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_255", HFILL }},
    { &hf_rrlp_ganssUtcWNt,
      { "ganssUtcWNt", "rrlp.ganssUtcWNt",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_255", HFILL }},
    { &hf_rrlp_ganssUtcDeltaTls,
      { "ganssUtcDeltaTls", "rrlp.ganssUtcDeltaTls",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_ganssUtcWNlsf,
      { "ganssUtcWNlsf", "rrlp.ganssUtcWNlsf",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_255", HFILL }},
    { &hf_rrlp_ganssUtcDN,
      { "ganssUtcDN", "rrlp.ganssUtcDN",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_ganssUtcDeltaTlsf,
      { "ganssUtcDeltaTlsf", "rrlp.ganssUtcDeltaTlsf",
        FT_INT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_M128_127", HFILL }},
    { &hf_rrlp_velEstimate,
      { "velEstimate", "rrlp.velEstimate",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rrlp.VelocityEstimate", HFILL }},
    { &hf_rrlp_ganssLocationInfo,
      { "ganssLocationInfo", "rrlp.ganssLocationInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSLocationInfo", HFILL }},
    { &hf_rrlp_ganssMeasureInfo,
      { "ganssMeasureInfo", "rrlp.ganssMeasureInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSSMeasureInfo", HFILL }},
    { &hf_rrlp_referenceFrame,
      { "referenceFrame", "rrlp.referenceFrame",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.ReferenceFrame", HFILL }},
    { &hf_rrlp_ganssTODm,
      { "ganssTODm", "rrlp.ganssTODm",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.GANSSTODm", HFILL }},
    { &hf_rrlp_ganssTODFrac,
      { "ganssTODFrac", "rrlp.ganssTODFrac",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_16384", HFILL }},
    { &hf_rrlp_ganssTimeID_01,
      { "ganssTimeID", "rrlp.ganssTimeID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_3", HFILL }},
    { &hf_rrlp_posData,
      { "posData", "rrlp.posData",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rrlp.PositionData", HFILL }},
    { &hf_rrlp_stationaryIndication,
      { "stationaryIndication", "rrlp.stationaryIndication",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_1", HFILL }},
    { &hf_rrlp_referenceFN,
      { "referenceFN", "rrlp.referenceFN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_65535", HFILL }},
    { &hf_rrlp_referenceFNMSB,
      { "referenceFNMSB", "rrlp.referenceFNMSB",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_63", HFILL }},
    { &hf_rrlp_ganssMsrSetList,
      { "ganssMsrSetList", "rrlp.ganssMsrSetList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfGANSS_MsrSetElement", HFILL }},
    { &hf_rrlp_SeqOfGANSS_MsrSetElement_item,
      { "Item", "rrlp.SeqOfGANSS_MsrSetElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSS_MsrSetElement", HFILL }},
    { &hf_rrlp_deltaGNASSTOD,
      { "deltaGNASSTOD", "rrlp.deltaGNASSTOD",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_127", HFILL }},
    { &hf_rrlp_ganss_SgnTypeList,
      { "ganss-SgnTypeList", "rrlp.ganss_SgnTypeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfGANSS_SgnTypeElement", HFILL }},
    { &hf_rrlp_SeqOfGANSS_SgnTypeElement_item,
      { "Item", "rrlp.SeqOfGANSS_SgnTypeElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSS_SgnTypeElement", HFILL }},
    { &hf_rrlp_ganssSignalID_02,
      { "ganssSignalID", "rrlp.ganssSignalID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_15", HFILL }},
    { &hf_rrlp_ganss_SgnList,
      { "ganss-SgnList", "rrlp.ganss_SgnList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.SeqOfGANSS_SgnElement", HFILL }},
    { &hf_rrlp_SeqOfGANSS_SgnElement_item,
      { "Item", "rrlp.SeqOfGANSS_SgnElement_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "rrlp.GANSS_SgnElement", HFILL }},
    { &hf_rrlp_mpathDet,
      { "mpathDet", "rrlp.mpathDet",
        FT_UINT32, BASE_DEC, VALS(rrlp_MpathIndic_vals), 0,
        "rrlp.MpathIndic", HFILL }},
    { &hf_rrlp_carrierQualityInd,
      { "carrierQualityInd", "rrlp.carrierQualityInd",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_3", HFILL }},
    { &hf_rrlp_codePhase_01,
      { "codePhase", "rrlp.codePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_2097151", HFILL }},
    { &hf_rrlp_integerCodePhase,
      { "integerCodePhase", "rrlp.integerCodePhase",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_63", HFILL }},
    { &hf_rrlp_codePhaseRMSError,
      { "codePhaseRMSError", "rrlp.codePhaseRMSError",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_63", HFILL }},
    { &hf_rrlp_adr,
      { "adr", "rrlp.adr",
        FT_UINT32, BASE_DEC, NULL, 0,
        "rrlp.INTEGER_0_33554431", HFILL }},
    { &hf_rrlp_GANSSPositioningMethod_gps,
      { "gps", "rrlp.gps",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_rrlp_GANSSPositioningMethod_galileo,
      { "galileo", "rrlp.galileo",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_rrlp_PositionData_e_otd,
      { "e-otd", "rrlp.e-otd",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_rrlp_PositionData_gps,
      { "gps", "rrlp.gps",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_rrlp_PositionData_galileo,
      { "galileo", "rrlp.galileo",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},

/*--- End of included file: packet-rrlp-hfarr.c ---*/
#line 83 "packet-rrlp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_rrlp,

/*--- Included file: packet-rrlp-ettarr.c ---*/
#line 1 "packet-rrlp-ettarr.c"
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
    &ett_rrlp_GANSSTOD_GSMTimeAssociation,
    &ett_rrlp_GANSSRefLocation,
    &ett_rrlp_GANSSIonosphericModel,
    &ett_rrlp_GANSSIonosphereModel,
    &ett_rrlp_GANSSIonoStormFlags,
    &ett_rrlp_SeqOfGANSSTimeModel,
    &ett_rrlp_GANSSTimeModelElement,
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
    &ett_rrlp_GANSSClockModel,
    &ett_rrlp_SeqOfStandardClockModelElement,
    &ett_rrlp_StandardClockModelElement,
    &ett_rrlp_GANSSRealTimeIntegrity,
    &ett_rrlp_SeqOfBadSignalElement,
    &ett_rrlp_BadSignalElement,
    &ett_rrlp_GANSSDataBitAssist,
    &ett_rrlp_SeqOf_GANSSDataBits,
    &ett_rrlp_GANSSRefMeasurementAssist,
    &ett_rrlp_SeqOfGANSSRefMeasurementElement,
    &ett_rrlp_GANSSRefMeasurementElement,
    &ett_rrlp_AdditionalDopplerFields,
    &ett_rrlp_GANSSAlmanacModel,
    &ett_rrlp_SeqOfGANSSAlmanacElement,
    &ett_rrlp_GANSSAlmanacElement,
    &ett_rrlp_Almanac_KeplerianSet,
    &ett_rrlp_GANSSUTCModel,
    &ett_rrlp_Rel_7_MsrPosition_Rsp_Extension,
    &ett_rrlp_GANSSLocationInfo,
    &ett_rrlp_PositionData,
    &ett_rrlp_ReferenceFrame,
    &ett_rrlp_GANSSMeasureInfo,
    &ett_rrlp_SeqOfGANSS_MsrSetElement,
    &ett_rrlp_GANSS_MsrSetElement,
    &ett_rrlp_SeqOfGANSS_SgnTypeElement,
    &ett_rrlp_GANSS_SgnTypeElement,
    &ett_rrlp_SeqOfGANSS_SgnElement,
    &ett_rrlp_GANSS_SgnElement,
    &ett_rrlp_Rel7_AssistanceData_Extension,

/*--- End of included file: packet-rrlp-ettarr.c ---*/
#line 89 "packet-rrlp-template.c"
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


