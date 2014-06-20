/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ilp.c                                                               */
/* ../../tools/asn2wrs.py -p ilp -c ./ilp.cnf -s ./packet-ilp-template -D . -O ../../epan/dissectors ILP.asn ILP-Components.asn */

/* Input file: packet-ilp-template.c */

#line 1 "../../asn1/ilp/packet-ilp-template.c"
/* packet-ilp.c
 * Routines for OMA Internal Location Protocol packet dissection
 * Copyright 2006, e.yimjia <jy.m12.0@gmail.com>
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
 *
 * ref OMA-TS-ILP-V2_0_1-20121205-A
 * http://www.openmobilealliance.org
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-tcp.h"
#include "packet-gsm_map.h"

#define PNAME  "OMA Internal Location Protocol"
#define PSNAME "ILP"
#define PFNAME "ilp"

void proto_register_ilp(void);

static dissector_handle_t rrlp_handle;
static dissector_handle_t lpp_handle;

/* IANA Registered Ports
 * oma-ilp         7276/tcp    OMA Internal Location
 */
static guint gbl_ilp_port = 7276;

/* Initialize the protocol and registered fields */
static int proto_ilp = -1;


#define ILP_HEADER_SIZE 2

static gboolean ilp_desegment = TRUE;


/*--- Included file: packet-ilp-hf.c ---*/
#line 1 "../../asn1/ilp/packet-ilp-hf.c"
static int hf_ilp_ILP_PDU_PDU = -1;               /* ILP_PDU */
static int hf_ilp_length = -1;                    /* INTEGER_0_65535 */
static int hf_ilp_version = -1;                   /* Version */
static int hf_ilp_sessionID2 = -1;                /* SessionID2 */
static int hf_ilp_message = -1;                   /* IlpMessage */
static int hf_ilp_msPREQ = -1;                    /* PREQ */
static int hf_ilp_msPRES = -1;                    /* PRES */
static int hf_ilp_msPRPT = -1;                    /* PRPT */
static int hf_ilp_msPLREQ = -1;                   /* PLREQ */
static int hf_ilp_msPLRES = -1;                   /* PLRES */
static int hf_ilp_msPINIT = -1;                   /* PINIT */
static int hf_ilp_msPAUTH = -1;                   /* PAUTH */
static int hf_ilp_msPALIVE = -1;                  /* PALIVE */
static int hf_ilp_msPEND = -1;                    /* PEND */
static int hf_ilp_msPMESS = -1;                   /* PMESS */
static int hf_ilp_sLPMode = -1;                   /* SLPMode */
static int hf_ilp_approvedPosMethods = -1;        /* PosTechnology */
static int hf_ilp_locationId = -1;                /* LocationId */
static int hf_ilp_multipleLocationIds = -1;       /* MultipleLocationIds */
static int hf_ilp_position = -1;                  /* Position */
static int hf_ilp_triggerParams = -1;             /* TriggerParams */
static int hf_ilp_sPCSETKey = -1;                 /* SPCSETKey */
static int hf_ilp_sPCTID = -1;                    /* SPCTID */
static int hf_ilp_sPCSETKeylifetime = -1;         /* SPCSETKeylifetime */
static int hf_ilp_qoP = -1;                       /* QoP */
static int hf_ilp_sETCapabilities = -1;           /* SETCapabilities */
static int hf_ilp_notificationMode = -1;          /* NotificationMode */
static int hf_ilp_triggerType = -1;               /* TriggerType */
static int hf_ilp_periodicTriggerParams = -1;     /* PeriodicTriggerParams */
static int hf_ilp_numberOfFixes = -1;             /* INTEGER_1_8639999 */
static int hf_ilp_intervalBetweenFixes = -1;      /* INTEGER_1_8639999 */
static int hf_ilp_startTime = -1;                 /* INTEGER_0_2678400 */
static int hf_ilp_preferredPosMethod = -1;        /* PosMethod */
static int hf_ilp_gnssPosTechnology = -1;         /* GNSSPosTechnology */
static int hf_ilp_supportedPosMethods = -1;       /* PosTechnology */
static int hf_ilp_sPCstatusCode = -1;             /* SPCStatusCode */
static int hf_ilp_fixNumber = -1;                 /* INTEGER_1_8639999 */
static int hf_ilp_statusCode = -1;                /* StatusCode */
static int hf_ilp_positionResults = -1;           /* PositionResults */
static int hf_ilp_PositionResults_item = -1;      /* PositionResult */
static int hf_ilp_posMethod = -1;                 /* PosMethod */
static int hf_ilp_requestedAssistData = -1;       /* RequestedAssistData */
static int hf_ilp_posPayLoad = -1;                /* PosPayLoad */
static int hf_ilp_utran_GPSReferenceTimeResult = -1;  /* UTRAN_GPSReferenceTimeResult */
static int hf_ilp_utran_GANSSReferenceTimeResult = -1;  /* UTRAN_GANSSReferenceTimeResult */
static int hf_ilp_almanacRequested = -1;          /* BOOLEAN */
static int hf_ilp_utcModelRequested = -1;         /* BOOLEAN */
static int hf_ilp_ionosphericModelRequested = -1;  /* BOOLEAN */
static int hf_ilp_dgpsCorrectionsRequested = -1;  /* BOOLEAN */
static int hf_ilp_referenceLocationRequested = -1;  /* BOOLEAN */
static int hf_ilp_referenceTimeRequested = -1;    /* BOOLEAN */
static int hf_ilp_acquisitionAssistanceRequested = -1;  /* BOOLEAN */
static int hf_ilp_realTimeIntegrityRequested = -1;  /* BOOLEAN */
static int hf_ilp_navigationModelRequested = -1;  /* BOOLEAN */
static int hf_ilp_navigationModelData = -1;       /* NavigationModel */
static int hf_ilp_ganssRequestedCommonAssistanceDataList = -1;  /* GanssRequestedCommonAssistanceDataList */
static int hf_ilp_ganssRequestedGenericAssistanceDataList = -1;  /* GanssRequestedGenericAssistanceDataList */
static int hf_ilp_extendedEphemeris = -1;         /* ExtendedEphemeris */
static int hf_ilp_extendedEphemerisCheck = -1;    /* ExtendedEphCheck */
static int hf_ilp_validity = -1;                  /* INTEGER_1_256 */
static int hf_ilp_beginTime = -1;                 /* GPSTime */
static int hf_ilp_endTime = -1;                   /* GPSTime */
static int hf_ilp_gPSWeek = -1;                   /* INTEGER_0_1023 */
static int hf_ilp_gPSTOWhour = -1;                /* INTEGER_0_167 */
static int hf_ilp_ganssReferenceTime = -1;        /* BOOLEAN */
static int hf_ilp_ganssIonosphericModel = -1;     /* BOOLEAN */
static int hf_ilp_ganssAdditionalIonosphericModelForDataID00 = -1;  /* BOOLEAN */
static int hf_ilp_ganssAdditionalIonosphericModelForDataID11 = -1;  /* BOOLEAN */
static int hf_ilp_ganssEarthOrientationParameters = -1;  /* BOOLEAN */
static int hf_ilp_GanssRequestedGenericAssistanceDataList_item = -1;  /* GanssReqGenericData */
static int hf_ilp_ganssId = -1;                   /* INTEGER_0_15 */
static int hf_ilp_ganssSBASid = -1;               /* BIT_STRING_SIZE_3 */
static int hf_ilp_ganssRealTimeIntegrity = -1;    /* BOOLEAN */
static int hf_ilp_ganssDifferentialCorrection = -1;  /* DGANSS_Sig_Id_Req */
static int hf_ilp_ganssAlmanac = -1;              /* BOOLEAN */
static int hf_ilp_ganssNavigationModelData = -1;  /* GanssNavigationModelData */
static int hf_ilp_ganssTimeModels = -1;           /* BIT_STRING_SIZE_16 */
static int hf_ilp_ganssReferenceMeasurementInfo = -1;  /* BOOLEAN */
static int hf_ilp_ganssDataBits = -1;             /* GanssDataBits */
static int hf_ilp_ganssUTCModel = -1;             /* BOOLEAN */
static int hf_ilp_ganssAdditionalDataChoices = -1;  /* GanssAdditionalDataChoices */
static int hf_ilp_ganssAuxiliaryInformation = -1;  /* BOOLEAN */
static int hf_ilp_ganssExtendedEphemeris = -1;    /* ExtendedEphemeris */
static int hf_ilp_ganssExtendedEphemerisCheck = -1;  /* GanssExtendedEphCheck */
static int hf_ilp_ganssWeek = -1;                 /* INTEGER_0_4095 */
static int hf_ilp_ganssToe = -1;                  /* INTEGER_0_167 */
static int hf_ilp_t_toeLimit = -1;                /* INTEGER_0_10 */
static int hf_ilp_satellitesListRelatedDataList = -1;  /* SatellitesListRelatedDataList */
static int hf_ilp_SatellitesListRelatedDataList_item = -1;  /* SatellitesListRelatedData */
static int hf_ilp_satId = -1;                     /* INTEGER_0_63 */
static int hf_ilp_iod = -1;                       /* INTEGER_0_1023 */
static int hf_ilp_ganssTODmin = -1;               /* INTEGER_0_59 */
static int hf_ilp_reqDataBitAssistanceList = -1;  /* ReqDataBitAssistanceList */
static int hf_ilp_gnssSignals = -1;               /* GANSSSignals */
static int hf_ilp_ganssDataBitInterval = -1;      /* INTEGER_0_15 */
static int hf_ilp_ganssDataBitSatList = -1;       /* T_ganssDataBitSatList */
static int hf_ilp_ganssDataBitSatList_item = -1;  /* INTEGER_0_63 */
static int hf_ilp_orbitModelID = -1;              /* INTEGER_0_7 */
static int hf_ilp_clockModelID = -1;              /* INTEGER_0_7 */
static int hf_ilp_utcModelID = -1;                /* INTEGER_0_7 */
static int hf_ilp_almanacModelID = -1;            /* INTEGER_0_7 */
static int hf_ilp_beginTime_01 = -1;              /* GANSSextEphTime */
static int hf_ilp_endTime_01 = -1;                /* GANSSextEphTime */
static int hf_ilp_gANSSday = -1;                  /* INTEGER_0_8191 */
static int hf_ilp_gANSSTODhour = -1;              /* INTEGER_0_23 */
static int hf_ilp_gpsWeek = -1;                   /* INTEGER_0_1023 */
static int hf_ilp_gpsToe = -1;                    /* INTEGER_0_167 */
static int hf_ilp_nSAT = -1;                      /* INTEGER_0_31 */
static int hf_ilp_toeLimit = -1;                  /* INTEGER_0_10 */
static int hf_ilp_satInfo = -1;                   /* SatelliteInfo */
static int hf_ilp_SatelliteInfo_item = -1;        /* SatelliteInfoElement */
static int hf_ilp_iODE = -1;                      /* INTEGER_0_255 */
static int hf_ilp_sPCStatusCode = -1;             /* SPCStatusCode */
static int hf_ilp_velocity = -1;                  /* Velocity */
static int hf_ilp_utran_GPSReferenceTimeAssistance = -1;  /* UTRAN_GPSReferenceTimeAssistance */
static int hf_ilp_utran_GANSSReferenceTimeAssistance = -1;  /* UTRAN_GANSSReferenceTimeAssistance */
static int hf_ilp_maj = -1;                       /* INTEGER_0_255 */
static int hf_ilp_min = -1;                       /* INTEGER_0_255 */
static int hf_ilp_servind = -1;                   /* INTEGER_0_255 */
static int hf_ilp_slcSessionID = -1;              /* SlcSessionID */
static int hf_ilp_setSessionID = -1;              /* SetSessionID */
static int hf_ilp_spcSessionID = -1;              /* SpcSessionID */
static int hf_ilp_sessionId = -1;                 /* INTEGER_0_65535 */
static int hf_ilp_setId = -1;                     /* SETId */
static int hf_ilp_msisdn = -1;                    /* OCTET_STRING_SIZE_8 */
static int hf_ilp_mdn = -1;                       /* OCTET_STRING_SIZE_8 */
static int hf_ilp_minsi = -1;                     /* BIT_STRING_SIZE_34 */
static int hf_ilp_imsi = -1;                      /* OCTET_STRING_SIZE_8 */
static int hf_ilp_nai = -1;                       /* IA5String_SIZE_1_1000 */
static int hf_ilp_iPAddress = -1;                 /* IPAddress */
static int hf_ilp_sessionID = -1;                 /* OCTET_STRING_SIZE_4 */
static int hf_ilp_slcId = -1;                     /* NodeAddress */
static int hf_ilp_spcId = -1;                     /* NodeAddress */
static int hf_ilp_ipv4Address = -1;               /* OCTET_STRING_SIZE_4 */
static int hf_ilp_ipv6Address = -1;               /* OCTET_STRING_SIZE_16 */
static int hf_ilp_fqdn = -1;                      /* FQDN */
static int hf_ilp_cellInfo = -1;                  /* CellInfo */
static int hf_ilp_status = -1;                    /* Status */
static int hf_ilp_MultipleLocationIds_item = -1;  /* LocationIdData */
static int hf_ilp_relativetimestamp = -1;         /* RelativeTime */
static int hf_ilp_servingFlag = -1;               /* BOOLEAN */
static int hf_ilp_posTechnology = -1;             /* PosTechnology */
static int hf_ilp_prefMethod = -1;                /* PrefMethod */
static int hf_ilp_posProtocol = -1;               /* PosProtocol */
static int hf_ilp_supportedBearers = -1;          /* SupportedBearers */
static int hf_ilp_agpsSETassisted = -1;           /* BOOLEAN */
static int hf_ilp_agpsSETBased = -1;              /* BOOLEAN */
static int hf_ilp_autonomousGPS = -1;             /* BOOLEAN */
static int hf_ilp_aFLT = -1;                      /* BOOLEAN */
static int hf_ilp_eCID = -1;                      /* BOOLEAN */
static int hf_ilp_eOTD = -1;                      /* BOOLEAN */
static int hf_ilp_oTDOA = -1;                     /* BOOLEAN */
static int hf_ilp_gANSSPositionMethods = -1;      /* GANSSPositionMethods */
static int hf_ilp_GANSSPositionMethods_item = -1;  /* GANSSPositionMethod */
static int hf_ilp_gANSSPositioningMethodTypes = -1;  /* GANSSPositioningMethodTypes */
static int hf_ilp_gANSSSignals = -1;              /* GANSSSignals */
static int hf_ilp_setAssisted = -1;               /* BOOLEAN */
static int hf_ilp_setBased = -1;                  /* BOOLEAN */
static int hf_ilp_autonomous = -1;                /* BOOLEAN */
static int hf_ilp_tia801 = -1;                    /* BOOLEAN */
static int hf_ilp_rrlp = -1;                      /* BOOLEAN */
static int hf_ilp_rrc = -1;                       /* BOOLEAN */
static int hf_ilp_lpp = -1;                       /* BOOLEAN */
static int hf_ilp_posProtocolVersionRRLP = -1;    /* PosProtocolVersion3GPP */
static int hf_ilp_posProtocolVersionRRC = -1;     /* PosProtocolVersion3GPP */
static int hf_ilp_posProtocolVersionTIA801 = -1;  /* PosProtocolVersion3GPP2 */
static int hf_ilp_posProtocolVersionLPP = -1;     /* PosProtocolVersion3GPP */
static int hf_ilp_majorVersionField = -1;         /* INTEGER_0_255 */
static int hf_ilp_technicalVersionField = -1;     /* INTEGER_0_255 */
static int hf_ilp_editorialVersionField = -1;     /* INTEGER_0_255 */
static int hf_ilp_PosProtocolVersion3GPP2_item = -1;  /* Supported3GPP2PosProtocolVersion */
static int hf_ilp_revisionNumber = -1;            /* BIT_STRING_SIZE_6 */
static int hf_ilp_pointReleaseNumber = -1;        /* INTEGER_0_255 */
static int hf_ilp_internalEditLevel = -1;         /* INTEGER_0_255 */
static int hf_ilp_gsm = -1;                       /* BOOLEAN */
static int hf_ilp_wcdma = -1;                     /* BOOLEAN */
static int hf_ilp_lte = -1;                       /* BOOLEAN */
static int hf_ilp_cdma = -1;                      /* BOOLEAN */
static int hf_ilp_hprd = -1;                      /* BOOLEAN */
static int hf_ilp_umb = -1;                       /* BOOLEAN */
static int hf_ilp_wlan = -1;                      /* BOOLEAN */
static int hf_ilp_wiMAX = -1;                     /* BOOLEAN */
static int hf_ilp_gsmCell = -1;                   /* GsmCellInformation */
static int hf_ilp_wcdmaCell = -1;                 /* WcdmaCellInformation */
static int hf_ilp_cdmaCell = -1;                  /* CdmaCellInformation */
static int hf_ilp_hrpdCell = -1;                  /* HrpdCellInformation */
static int hf_ilp_umbCell = -1;                   /* UmbCellInformation */
static int hf_ilp_lteCell = -1;                   /* LteCellInformation */
static int hf_ilp_wlanAP = -1;                    /* WlanAPInformation */
static int hf_ilp_wimaxBS = -1;                   /* WimaxBSInformation */
static int hf_ilp_set_GPSTimingOfCell = -1;       /* T_set_GPSTimingOfCell */
static int hf_ilp_ms_part = -1;                   /* INTEGER_0_16383 */
static int hf_ilp_ls_part = -1;                   /* INTEGER_0_4294967295 */
static int hf_ilp_modeSpecificInfo = -1;          /* T_modeSpecificInfo */
static int hf_ilp_fdd = -1;                       /* T_fdd */
static int hf_ilp_referenceIdentity = -1;         /* PrimaryCPICH_Info */
static int hf_ilp_tdd = -1;                       /* T_tdd */
static int hf_ilp_referenceIdentity_01 = -1;      /* CellParametersID */
static int hf_ilp_sfn = -1;                       /* INTEGER_0_4095 */
static int hf_ilp_gpsReferenceTimeUncertainty = -1;  /* INTEGER_0_127 */
static int hf_ilp_ganssTimeID = -1;               /* INTEGER_0_15 */
static int hf_ilp_set_GANSSReferenceTime = -1;    /* SET_GANSSReferenceTime */
static int hf_ilp_set_GANSSTimingOfCell = -1;     /* T_set_GANSSTimingOfCell */
static int hf_ilp_ms_part_01 = -1;                /* INTEGER_0_80 */
static int hf_ilp_modeSpecificInfo_01 = -1;       /* T_modeSpecificInfo_01 */
static int hf_ilp_fdd_01 = -1;                    /* T_fdd_01 */
static int hf_ilp_tdd_01 = -1;                    /* T_tdd_01 */
static int hf_ilp_ganss_TODUncertainty = -1;      /* INTEGER_0_127 */
static int hf_ilp_gps = -1;                       /* BOOLEAN */
static int hf_ilp_galileo = -1;                   /* BOOLEAN */
static int hf_ilp_sbas = -1;                      /* BOOLEAN */
static int hf_ilp_modernized_gps = -1;            /* BOOLEAN */
static int hf_ilp_qzss = -1;                      /* BOOLEAN */
static int hf_ilp_glonass = -1;                   /* BOOLEAN */
static int hf_ilp_timestamp = -1;                 /* UTCTime */
static int hf_ilp_positionEstimate = -1;          /* PositionEstimate */
static int hf_ilp_latitudeSign = -1;              /* T_latitudeSign */
static int hf_ilp_latitude = -1;                  /* INTEGER_0_8388607 */
static int hf_ilp_longitude = -1;                 /* INTEGER_M8388608_8388607 */
static int hf_ilp_uncertainty = -1;               /* T_uncertainty */
static int hf_ilp_uncertaintySemiMajor = -1;      /* INTEGER_0_127 */
static int hf_ilp_uncertaintySemiMinor = -1;      /* INTEGER_0_127 */
static int hf_ilp_orientationMajorAxis = -1;      /* INTEGER_0_180 */
static int hf_ilp_confidence = -1;                /* INTEGER_0_100 */
static int hf_ilp_altitudeInfo = -1;              /* AltitudeInfo */
static int hf_ilp_altitudeDirection = -1;         /* T_altitudeDirection */
static int hf_ilp_altitude = -1;                  /* INTEGER_0_32767 */
static int hf_ilp_altUncertainty = -1;            /* INTEGER_0_127 */
static int hf_ilp_refNID = -1;                    /* INTEGER_0_65535 */
static int hf_ilp_refSID = -1;                    /* INTEGER_0_32767 */
static int hf_ilp_refBASEID = -1;                 /* INTEGER_0_65535 */
static int hf_ilp_refBASELAT = -1;                /* INTEGER_0_4194303 */
static int hf_ilp_reBASELONG = -1;                /* INTEGER_0_8388607 */
static int hf_ilp_refREFPN = -1;                  /* INTEGER_0_511 */
static int hf_ilp_refWeekNumber = -1;             /* INTEGER_0_65535 */
static int hf_ilp_refSeconds = -1;                /* INTEGER_0_4194303 */
static int hf_ilp_refMCC = -1;                    /* INTEGER_0_999 */
static int hf_ilp_refMNC = -1;                    /* INTEGER_0_999 */
static int hf_ilp_refLAC = -1;                    /* INTEGER_0_65535 */
static int hf_ilp_refCI = -1;                     /* INTEGER_0_65535 */
static int hf_ilp_nMR = -1;                       /* NMR */
static int hf_ilp_tA = -1;                        /* INTEGER_0_255 */
static int hf_ilp_refUC = -1;                     /* INTEGER_0_268435455 */
static int hf_ilp_frequencyInfo = -1;             /* FrequencyInfo */
static int hf_ilp_primaryScramblingCode = -1;     /* INTEGER_0_511 */
static int hf_ilp_measuredResultsList = -1;       /* MeasuredResultsList */
static int hf_ilp_cellParametersId = -1;          /* INTEGER_0_127 */
static int hf_ilp_timingAdvance = -1;             /* TimingAdvance */
static int hf_ilp_tA_01 = -1;                     /* INTEGER_0_8191 */
static int hf_ilp_tAResolution = -1;              /* TAResolution */
static int hf_ilp_chipRate = -1;                  /* ChipRate */
static int hf_ilp_refSECTORID = -1;               /* BIT_STRING_SIZE_128 */
static int hf_ilp_cellGlobalIdEUTRA = -1;         /* CellGlobalIdEUTRA */
static int hf_ilp_physCellId = -1;                /* PhysCellId */
static int hf_ilp_trackingAreaCode = -1;          /* TrackingAreaCode */
static int hf_ilp_rsrpResult = -1;                /* RSRP_Range */
static int hf_ilp_rsrqResult = -1;                /* RSRQ_Range */
static int hf_ilp_tA_02 = -1;                     /* INTEGER_0_1282 */
static int hf_ilp_measResultListEUTRA = -1;       /* MeasResultListEUTRA */
static int hf_ilp_earfcn = -1;                    /* INTEGER_0_65535 */
static int hf_ilp_MeasResultListEUTRA_item = -1;  /* MeasResultEUTRA */
static int hf_ilp_cgi_Info = -1;                  /* T_cgi_Info */
static int hf_ilp_cellGlobalId = -1;              /* CellGlobalIdEUTRA */
static int hf_ilp_measResult = -1;                /* T_measResult */
static int hf_ilp_plmn_Identity = -1;             /* PLMN_Identity */
static int hf_ilp_cellIdentity = -1;              /* CellIdentity */
static int hf_ilp_mcc = -1;                       /* MCC */
static int hf_ilp_mnc = -1;                       /* MNC */
static int hf_ilp_MCC_item = -1;                  /* MCC_MNC_Digit */
static int hf_ilp_MNC_item = -1;                  /* MCC_MNC_Digit */
static int hf_ilp_apMACAddress = -1;              /* BIT_STRING_SIZE_48 */
static int hf_ilp_apTransmitPower = -1;           /* INTEGER_M127_128 */
static int hf_ilp_apAntennaGain = -1;             /* INTEGER_M127_128 */
static int hf_ilp_apSignaltoNoise = -1;           /* INTEGER_M127_128 */
static int hf_ilp_apDeviceType = -1;              /* T_apDeviceType */
static int hf_ilp_apSignalStrength = -1;          /* INTEGER_M127_128 */
static int hf_ilp_apChannelFrequency = -1;        /* INTEGER_0_256 */
static int hf_ilp_apRoundTripDelay = -1;          /* RTD */
static int hf_ilp_setTransmitPower = -1;          /* INTEGER_M127_128 */
static int hf_ilp_setAntennaGain = -1;            /* INTEGER_M127_128 */
static int hf_ilp_setSignaltoNoise = -1;          /* INTEGER_M127_128 */
static int hf_ilp_setSignalStrength = -1;         /* INTEGER_M127_128 */
static int hf_ilp_apReportedLocation = -1;        /* ReportedLocation */
static int hf_ilp_rTDValue = -1;                  /* INTEGER_0_16777216 */
static int hf_ilp_rTDUnits = -1;                  /* RTDUnits */
static int hf_ilp_rTDAccuracy = -1;               /* INTEGER_0_255 */
static int hf_ilp_locationEncodingDescriptor = -1;  /* LocationEncodingDescriptor */
static int hf_ilp_locationData = -1;              /* LocationData */
static int hf_ilp_locationAccuracy = -1;          /* INTEGER_0_4294967295 */
static int hf_ilp_locationValue = -1;             /* OCTET_STRING_SIZE_1_128 */
static int hf_ilp_wimaxBsID = -1;                 /* WimaxBsID */
static int hf_ilp_wimaxRTD = -1;                  /* WimaxRTD */
static int hf_ilp_wimaxNMRList = -1;              /* WimaxNMRList */
static int hf_ilp_bsID_MSB = -1;                  /* BIT_STRING_SIZE_24 */
static int hf_ilp_bsID_LSB = -1;                  /* BIT_STRING_SIZE_24 */
static int hf_ilp_rTD = -1;                       /* INTEGER_0_65535 */
static int hf_ilp_rTDstd = -1;                    /* INTEGER_0_1023 */
static int hf_ilp_WimaxNMRList_item = -1;         /* WimaxNMR */
static int hf_ilp_relDelay = -1;                  /* INTEGER_M32768_32767 */
static int hf_ilp_relDelaystd = -1;               /* INTEGER_0_1023 */
static int hf_ilp_rSSI = -1;                      /* INTEGER_0_255 */
static int hf_ilp_rSSIstd = -1;                   /* INTEGER_0_63 */
static int hf_ilp_bSTxPower = -1;                 /* INTEGER_0_255 */
static int hf_ilp_cINR = -1;                      /* INTEGER_0_255 */
static int hf_ilp_cINRstd = -1;                   /* INTEGER_0_63 */
static int hf_ilp_bSLocation = -1;                /* ReportedLocation */
static int hf_ilp_modeSpecificFrequencyInfo = -1;  /* FrequencySpecificInfo */
static int hf_ilp_fdd_fr = -1;                    /* FrequencyInfoFDD */
static int hf_ilp_tdd_fr = -1;                    /* FrequencyInfoTDD */
static int hf_ilp_uarfcn_UL = -1;                 /* UARFCN */
static int hf_ilp_uarfcn_DL = -1;                 /* UARFCN */
static int hf_ilp_uarfcn_Nt = -1;                 /* UARFCN */
static int hf_ilp_NMR_item = -1;                  /* NMRelement */
static int hf_ilp_aRFCN = -1;                     /* INTEGER_0_1023 */
static int hf_ilp_bSIC = -1;                      /* INTEGER_0_63 */
static int hf_ilp_rxLev = -1;                     /* INTEGER_0_63 */
static int hf_ilp_MeasuredResultsList_item = -1;  /* MeasuredResults */
static int hf_ilp_utra_CarrierRSSI = -1;          /* UTRA_CarrierRSSI */
static int hf_ilp_cellMeasuredResultsList = -1;   /* CellMeasuredResultsList */
static int hf_ilp_CellMeasuredResultsList_item = -1;  /* CellMeasuredResults */
static int hf_ilp_cellIdentity_01 = -1;           /* INTEGER_0_268435455 */
static int hf_ilp_modeSpecificInfo_02 = -1;       /* T_modeSpecificInfo_02 */
static int hf_ilp_fdd_02 = -1;                    /* T_fdd_02 */
static int hf_ilp_primaryCPICH_Info = -1;         /* PrimaryCPICH_Info */
static int hf_ilp_cpich_Ec_N0 = -1;               /* CPICH_Ec_N0 */
static int hf_ilp_cpich_RSCP = -1;                /* CPICH_RSCP */
static int hf_ilp_pathloss = -1;                  /* Pathloss */
static int hf_ilp_tdd_02 = -1;                    /* T_tdd_02 */
static int hf_ilp_cellParametersID = -1;          /* CellParametersID */
static int hf_ilp_proposedTGSN = -1;              /* TGSN */
static int hf_ilp_primaryCCPCH_RSCP = -1;         /* PrimaryCCPCH_RSCP */
static int hf_ilp_timeslotISCP_List = -1;         /* TimeslotISCP_List */
static int hf_ilp_TimeslotISCP_List_item = -1;    /* TimeslotISCP */
static int hf_ilp_utran_GPSReferenceTime = -1;    /* UTRAN_GPSReferenceTime */
static int hf_ilp_utranGPSDriftRate = -1;         /* UTRANGPSDriftRate */
static int hf_ilp_utran_GPSTimingOfCell = -1;     /* T_utran_GPSTimingOfCell */
static int hf_ilp_ms_part_02 = -1;                /* INTEGER_0_1023 */
static int hf_ilp_modeSpecificInfo_03 = -1;       /* T_modeSpecificInfo_03 */
static int hf_ilp_fdd_03 = -1;                    /* T_fdd_03 */
static int hf_ilp_tdd_03 = -1;                    /* T_tdd_03 */
static int hf_ilp_utran_GANSSReferenceTime = -1;  /* UTRAN_GANSSReferenceTime */
static int hf_ilp_ganssDay = -1;                  /* INTEGER_0_8191 */
static int hf_ilp_utranGANSSDriftRate = -1;       /* UTRANGANSSDriftRate */
static int hf_ilp_ganssTOD = -1;                  /* INTEGER_0_86399 */
static int hf_ilp_utran_GANSSTimingOfCell = -1;   /* INTEGER_0_3999999 */
static int hf_ilp_modeSpecificInfo_04 = -1;       /* T_modeSpecificInfo_04 */
static int hf_ilp_fdd_04 = -1;                    /* T_fdd_04 */
static int hf_ilp_tdd_04 = -1;                    /* T_tdd_04 */
static int hf_ilp_horacc = -1;                    /* INTEGER_0_127 */
static int hf_ilp_veracc = -1;                    /* INTEGER_0_127 */
static int hf_ilp_maxLocAge = -1;                 /* INTEGER_0_65535 */
static int hf_ilp_delay = -1;                     /* INTEGER_0_7 */
static int hf_ilp_horvel = -1;                    /* Horvel */
static int hf_ilp_horandvervel = -1;              /* Horandvervel */
static int hf_ilp_horveluncert = -1;              /* Horveluncert */
static int hf_ilp_horandveruncert = -1;           /* Horandveruncert */
static int hf_ilp_bearing = -1;                   /* BIT_STRING_SIZE_9 */
static int hf_ilp_horspeed = -1;                  /* BIT_STRING_SIZE_16 */
static int hf_ilp_verdirect = -1;                 /* BIT_STRING_SIZE_1 */
static int hf_ilp_verspeed = -1;                  /* BIT_STRING_SIZE_8 */
static int hf_ilp_uncertspeed = -1;               /* BIT_STRING_SIZE_8 */
static int hf_ilp_horuncertspeed = -1;            /* BIT_STRING_SIZE_8 */
static int hf_ilp_veruncertspeed = -1;            /* BIT_STRING_SIZE_8 */
static int hf_ilp_rAND = -1;                      /* BIT_STRING_SIZE_128 */
static int hf_ilp_slpFQDN = -1;                   /* FQDN */
static int hf_ilp_rrcPayload = -1;                /* OCTET_STRING_SIZE_1_8192 */
static int hf_ilp_rrlpPayload = -1;               /* T_rrlpPayload */
static int hf_ilp_multiPosPayload = -1;           /* MultiPosPayLoad */
static int hf_ilp_lPPPayload = -1;                /* T_lPPPayload */
static int hf_ilp_lPPPayload_item = -1;           /* T_lPPPayload_item */
static int hf_ilp_tia801Payload = -1;             /* T_tia801Payload */
static int hf_ilp_tia801Payload_item = -1;        /* OCTET_STRING_SIZE_1_60000 */
/* named bits */
static int hf_ilp_GANSSSignals_signal1 = -1;
static int hf_ilp_GANSSSignals_signal2 = -1;
static int hf_ilp_GANSSSignals_signal3 = -1;
static int hf_ilp_GANSSSignals_signal4 = -1;
static int hf_ilp_GANSSSignals_signal5 = -1;
static int hf_ilp_GANSSSignals_signal6 = -1;
static int hf_ilp_GANSSSignals_signal7 = -1;
static int hf_ilp_GANSSSignals_signal8 = -1;

/*--- End of included file: packet-ilp-hf.c ---*/
#line 61 "../../asn1/ilp/packet-ilp-template.c"

/* Initialize the subtree pointers */
static gint ett_ilp = -1;

/*--- Included file: packet-ilp-ett.c ---*/
#line 1 "../../asn1/ilp/packet-ilp-ett.c"
static gint ett_ilp_ILP_PDU = -1;
static gint ett_ilp_IlpMessage = -1;
static gint ett_ilp_PREQ = -1;
static gint ett_ilp_TriggerParams = -1;
static gint ett_ilp_PeriodicTriggerParams = -1;
static gint ett_ilp_PRES = -1;
static gint ett_ilp_PRPT = -1;
static gint ett_ilp_PLREQ = -1;
static gint ett_ilp_PLRES = -1;
static gint ett_ilp_PositionResults = -1;
static gint ett_ilp_PositionResult = -1;
static gint ett_ilp_PINIT = -1;
static gint ett_ilp_RequestedAssistData = -1;
static gint ett_ilp_ExtendedEphemeris = -1;
static gint ett_ilp_ExtendedEphCheck = -1;
static gint ett_ilp_GPSTime = -1;
static gint ett_ilp_GanssRequestedCommonAssistanceDataList = -1;
static gint ett_ilp_GanssRequestedGenericAssistanceDataList = -1;
static gint ett_ilp_GanssReqGenericData = -1;
static gint ett_ilp_GanssNavigationModelData = -1;
static gint ett_ilp_SatellitesListRelatedDataList = -1;
static gint ett_ilp_SatellitesListRelatedData = -1;
static gint ett_ilp_GanssDataBits = -1;
static gint ett_ilp_ReqDataBitAssistanceList = -1;
static gint ett_ilp_T_ganssDataBitSatList = -1;
static gint ett_ilp_GanssAdditionalDataChoices = -1;
static gint ett_ilp_GanssExtendedEphCheck = -1;
static gint ett_ilp_GANSSextEphTime = -1;
static gint ett_ilp_NavigationModel = -1;
static gint ett_ilp_SatelliteInfo = -1;
static gint ett_ilp_SatelliteInfoElement = -1;
static gint ett_ilp_PAUTH = -1;
static gint ett_ilp_PALIVE = -1;
static gint ett_ilp_PEND = -1;
static gint ett_ilp_PMESS = -1;
static gint ett_ilp_Version = -1;
static gint ett_ilp_SessionID2 = -1;
static gint ett_ilp_SetSessionID = -1;
static gint ett_ilp_SETId = -1;
static gint ett_ilp_SlcSessionID = -1;
static gint ett_ilp_SpcSessionID = -1;
static gint ett_ilp_IPAddress = -1;
static gint ett_ilp_NodeAddress = -1;
static gint ett_ilp_LocationId = -1;
static gint ett_ilp_MultipleLocationIds = -1;
static gint ett_ilp_LocationIdData = -1;
static gint ett_ilp_SETCapabilities = -1;
static gint ett_ilp_PosTechnology = -1;
static gint ett_ilp_GANSSPositionMethods = -1;
static gint ett_ilp_GANSSPositionMethod = -1;
static gint ett_ilp_GANSSPositioningMethodTypes = -1;
static gint ett_ilp_GANSSSignals = -1;
static gint ett_ilp_PosProtocol = -1;
static gint ett_ilp_PosProtocolVersion3GPP = -1;
static gint ett_ilp_PosProtocolVersion3GPP2 = -1;
static gint ett_ilp_Supported3GPP2PosProtocolVersion = -1;
static gint ett_ilp_SupportedBearers = -1;
static gint ett_ilp_CellInfo = -1;
static gint ett_ilp_UTRAN_GPSReferenceTimeResult = -1;
static gint ett_ilp_T_set_GPSTimingOfCell = -1;
static gint ett_ilp_T_modeSpecificInfo = -1;
static gint ett_ilp_T_fdd = -1;
static gint ett_ilp_T_tdd = -1;
static gint ett_ilp_UTRAN_GANSSReferenceTimeResult = -1;
static gint ett_ilp_SET_GANSSReferenceTime = -1;
static gint ett_ilp_T_set_GANSSTimingOfCell = -1;
static gint ett_ilp_T_modeSpecificInfo_01 = -1;
static gint ett_ilp_T_fdd_01 = -1;
static gint ett_ilp_T_tdd_01 = -1;
static gint ett_ilp_GNSSPosTechnology = -1;
static gint ett_ilp_Position = -1;
static gint ett_ilp_PositionEstimate = -1;
static gint ett_ilp_T_uncertainty = -1;
static gint ett_ilp_AltitudeInfo = -1;
static gint ett_ilp_CdmaCellInformation = -1;
static gint ett_ilp_GsmCellInformation = -1;
static gint ett_ilp_WcdmaCellInformation = -1;
static gint ett_ilp_TimingAdvance = -1;
static gint ett_ilp_HrpdCellInformation = -1;
static gint ett_ilp_UmbCellInformation = -1;
static gint ett_ilp_LteCellInformation = -1;
static gint ett_ilp_MeasResultListEUTRA = -1;
static gint ett_ilp_MeasResultEUTRA = -1;
static gint ett_ilp_T_cgi_Info = -1;
static gint ett_ilp_T_measResult = -1;
static gint ett_ilp_CellGlobalIdEUTRA = -1;
static gint ett_ilp_PLMN_Identity = -1;
static gint ett_ilp_MCC = -1;
static gint ett_ilp_MNC = -1;
static gint ett_ilp_WlanAPInformation = -1;
static gint ett_ilp_RTD = -1;
static gint ett_ilp_ReportedLocation = -1;
static gint ett_ilp_LocationData = -1;
static gint ett_ilp_WimaxBSInformation = -1;
static gint ett_ilp_WimaxBsID = -1;
static gint ett_ilp_WimaxRTD = -1;
static gint ett_ilp_WimaxNMRList = -1;
static gint ett_ilp_WimaxNMR = -1;
static gint ett_ilp_FrequencyInfo = -1;
static gint ett_ilp_FrequencySpecificInfo = -1;
static gint ett_ilp_FrequencyInfoFDD = -1;
static gint ett_ilp_FrequencyInfoTDD = -1;
static gint ett_ilp_NMR = -1;
static gint ett_ilp_NMRelement = -1;
static gint ett_ilp_MeasuredResultsList = -1;
static gint ett_ilp_MeasuredResults = -1;
static gint ett_ilp_CellMeasuredResultsList = -1;
static gint ett_ilp_CellMeasuredResults = -1;
static gint ett_ilp_T_modeSpecificInfo_02 = -1;
static gint ett_ilp_T_fdd_02 = -1;
static gint ett_ilp_T_tdd_02 = -1;
static gint ett_ilp_TimeslotISCP_List = -1;
static gint ett_ilp_PrimaryCPICH_Info = -1;
static gint ett_ilp_UTRAN_GPSReferenceTimeAssistance = -1;
static gint ett_ilp_UTRAN_GPSReferenceTime = -1;
static gint ett_ilp_T_utran_GPSTimingOfCell = -1;
static gint ett_ilp_T_modeSpecificInfo_03 = -1;
static gint ett_ilp_T_fdd_03 = -1;
static gint ett_ilp_T_tdd_03 = -1;
static gint ett_ilp_UTRAN_GANSSReferenceTimeAssistance = -1;
static gint ett_ilp_UTRAN_GANSSReferenceTime = -1;
static gint ett_ilp_T_modeSpecificInfo_04 = -1;
static gint ett_ilp_T_fdd_04 = -1;
static gint ett_ilp_T_tdd_04 = -1;
static gint ett_ilp_QoP = -1;
static gint ett_ilp_Velocity = -1;
static gint ett_ilp_Horvel = -1;
static gint ett_ilp_Horandvervel = -1;
static gint ett_ilp_Horveluncert = -1;
static gint ett_ilp_Horandveruncert = -1;
static gint ett_ilp_SPCTID = -1;
static gint ett_ilp_PosPayLoad = -1;
static gint ett_ilp_MultiPosPayLoad = -1;
static gint ett_ilp_T_lPPPayload = -1;
static gint ett_ilp_T_tia801Payload = -1;

/*--- End of included file: packet-ilp-ett.c ---*/
#line 65 "../../asn1/ilp/packet-ilp-template.c"

/* Include constants */

/*--- Included file: packet-ilp-val.h ---*/
#line 1 "../../asn1/ilp/packet-ilp-val.h"
#define maxGANSS                       16
#define maxGANSSSat                    32
#define maxLidSize                     64
#define maxCellReport                  8
#define maxWimaxBSMeas                 32
#define maxCellMeas                    32
#define maxFreq                        8
#define maxTS                          14
#define maxPosSize                     1024

/*--- End of included file: packet-ilp-val.h ---*/
#line 68 "../../asn1/ilp/packet-ilp-template.c"



/*--- Included file: packet-ilp-fn.c ---*/
#line 1 "../../asn1/ilp/packet-ilp-fn.c"


static int
dissect_ilp_INTEGER_0_65535(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_255(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

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
                                       4, 4, FALSE, NULL);

  return offset;
}



static int
dissect_ilp_OCTET_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, FALSE, NULL);

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
                                                      1, 255, FALSE, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-", 64,
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
dissect_ilp_OCTET_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, FALSE, NULL);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_34(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     34, 34, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_ilp_IA5String_SIZE_1_1000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 1000, FALSE);

  return offset;
}


static const value_string ilp_SETId_vals[] = {
  {   0, "msisdn" },
  {   1, "mdn" },
  {   2, "min" },
  {   3, "imsi" },
  {   4, "nai" },
  {   5, "iPAddress" },
  { 0, NULL }
};

static const per_choice_t SETId_choice[] = {
  {   0, &hf_ilp_msisdn          , ASN1_EXTENSION_ROOT    , dissect_ilp_OCTET_STRING_SIZE_8 },
  {   1, &hf_ilp_mdn             , ASN1_EXTENSION_ROOT    , dissect_ilp_OCTET_STRING_SIZE_8 },
  {   2, &hf_ilp_minsi           , ASN1_EXTENSION_ROOT    , dissect_ilp_BIT_STRING_SIZE_34 },
  {   3, &hf_ilp_imsi            , ASN1_EXTENSION_ROOT    , dissect_ilp_OCTET_STRING_SIZE_8 },
  {   4, &hf_ilp_nai             , ASN1_EXTENSION_ROOT    , dissect_ilp_IA5String_SIZE_1_1000 },
  {   5, &hf_ilp_iPAddress       , ASN1_EXTENSION_ROOT    , dissect_ilp_IPAddress },
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
                                     2, NULL, FALSE, 0, NULL);

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
                                                            0U, 15U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     3, 3, FALSE, NULL, NULL);

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



static int
dissect_ilp_GANSSSignals(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 8, FALSE, NULL, NULL);

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
                                                  1, 16, FALSE);

  return offset;
}


static const per_sequence_t PosTechnology_sequence[] = {
  { &hf_ilp_agpsSETassisted , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_agpsSETBased    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_autonomousGPS   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_aFLT            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_eCID            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_eOTD            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_oTDOA           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_gANSSPositionMethods, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_GANSSPositionMethods },
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
                                                            0U, 999U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_1023(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_63(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 63U, NULL, FALSE);

  return offset;
}


static const per_sequence_t NMRelement_sequence[] = {
  { &hf_ilp_aRFCN           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_1023 },
  { &hf_ilp_bSIC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_63 },
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
                                                  1, 15, FALSE);

  return offset;
}


static const per_sequence_t GsmCellInformation_sequence[] = {
  { &hf_ilp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_999 },
  { &hf_ilp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_999 },
  { &hf_ilp_refLAC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_refCI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_nMR             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_NMR },
  { &hf_ilp_tA              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_255 },
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
                                                            0U, 268435455U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_UARFCN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16383U, NULL, FALSE);

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
                                                            0U, 511U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_UTRA_CarrierRSSI(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

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
                                                            0U, 63U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_CPICH_RSCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_Pathloss(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            46U, 173U, NULL, FALSE);

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
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_TGSN(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 14U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_PrimaryCCPCH_RSCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_TimeslotISCP(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TimeslotISCP_List_sequence_of[1] = {
  { &hf_ilp_TimeslotISCP_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_TimeslotISCP },
};

static int
dissect_ilp_TimeslotISCP_List(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_TimeslotISCP_List, TimeslotISCP_List_sequence_of,
                                                  1, maxTS, FALSE);

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
  { &hf_ilp_cellIdentity_01 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_268435455 },
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
                                                  1, maxCellMeas, FALSE);

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
                                                  1, maxFreq, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_127(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_8191(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8191U, NULL, FALSE);

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
                                     3, NULL, TRUE, 0, NULL);

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
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t TimingAdvance_sequence[] = {
  { &hf_ilp_tA_01           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_8191 },
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
                                                            0U, 32767U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_4194303(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4194303U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 8388607U, NULL, FALSE);

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
                                     128, 128, FALSE, NULL, NULL);

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
                                                            0U, 9U, NULL, FALSE);

  return offset;
}


static const per_sequence_t MCC_sequence_of[1] = {
  { &hf_ilp_MCC_item        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_MCC_MNC_Digit },
};

static int
dissect_ilp_MCC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_MCC, MCC_sequence_of,
                                                  3, 3, FALSE);

  return offset;
}


static const per_sequence_t MNC_sequence_of[1] = {
  { &hf_ilp_MNC_item        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_MCC_MNC_Digit },
};

static int
dissect_ilp_MNC(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_MNC, MNC_sequence_of,
                                                  2, 3, FALSE);

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
                                     28, 28, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t CellGlobalIdEUTRA_sequence[] = {
  { &hf_ilp_plmn_Identity   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_PLMN_Identity },
  { &hf_ilp_cellIdentity    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_CellIdentity },
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
                                                            0U, 503U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_TrackingAreaCode(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_ilp_RSRP_Range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 97U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_RSRQ_Range(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 34U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_1282(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 1282U, NULL, FALSE);

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


static const per_sequence_t T_measResult_sequence[] = {
  { &hf_ilp_rsrpResult      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_RSRP_Range },
  { &hf_ilp_rsrqResult      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_RSRQ_Range },
  { &hf_ilp_earfcn          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_65535 },
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
                                                  1, maxCellReport, FALSE);

  return offset;
}


static const per_sequence_t LteCellInformation_sequence[] = {
  { &hf_ilp_cellGlobalIdEUTRA, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_CellGlobalIdEUTRA },
  { &hf_ilp_physCellId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_PhysCellId },
  { &hf_ilp_trackingAreaCode, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_TrackingAreaCode },
  { &hf_ilp_rsrpResult      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_RSRP_Range },
  { &hf_ilp_rsrqResult      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_RSRQ_Range },
  { &hf_ilp_tA_02           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_1282 },
  { &hf_ilp_measResultListEUTRA, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_MeasResultListEUTRA },
  { &hf_ilp_earfcn          , ASN1_NOT_EXTENSION_ROOT, ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_65535 },
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
                                     48, 48, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_M127_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -127, 128U, NULL, FALSE);

  return offset;
}


static const value_string ilp_T_apDeviceType_vals[] = {
  {   0, "wlan802-11a" },
  {   1, "wlan802-11b" },
  {   2, "wlan802-11g" },
  { 0, NULL }
};


static int
dissect_ilp_T_apDeviceType(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_0_256(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 256U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_16777216(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 16777216U, NULL, FALSE);

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
                                     5, NULL, TRUE, 0, NULL);

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
  {   0, "lCI" },
  {   1, "aSN1" },
  { 0, NULL }
};


static int
dissect_ilp_LocationEncodingDescriptor(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_0_4294967295(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4294967295U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_OCTET_STRING_SIZE_1_128(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 128, FALSE, NULL);

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
                                     24, 24, FALSE, NULL, NULL);

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
  { &hf_ilp_rTD             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_65535 },
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
                                                            -32768, 32767U, NULL, FALSE);

  return offset;
}


static const per_sequence_t WimaxNMR_sequence[] = {
  { &hf_ilp_wimaxBsID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_WimaxBsID },
  { &hf_ilp_relDelay        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_M32768_32767 },
  { &hf_ilp_relDelaystd     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_1023 },
  { &hf_ilp_rSSI            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_255 },
  { &hf_ilp_rSSIstd         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_63 },
  { &hf_ilp_bSTxPower       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_255 },
  { &hf_ilp_cINR            , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_255 },
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
                                                  1, maxWimaxBSMeas, FALSE);

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


static const value_string ilp_CellInfo_vals[] = {
  {   0, "gsmCell" },
  {   1, "wcdmaCell" },
  {   2, "cdmaCell" },
  {   3, "hrpdCell" },
  {   4, "umbCell" },
  {   5, "lteCell" },
  {   6, "wlanAP" },
  {   7, "wimaxBS" },
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
                                     3, NULL, TRUE, 0, NULL);

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
                                                            0U, 65535U, NULL, FALSE);

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
                                                  1, maxLidSize, FALSE);

  return offset;
}



static int
dissect_ilp_UTCTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_VisibleString(tvb, offset, actx, tree, hf_index,
                                        NO_BOUND, NO_BOUND, FALSE);

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
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_M8388608_8388607(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            -8388608, 8388607U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_180(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 180U, NULL, FALSE);

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
                                                            0U, 100U, NULL, FALSE);

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
                                     2, NULL, FALSE, 0, NULL);

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
                                     9, 9, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_16(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL, NULL);

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
                                     1, 1, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_ilp_BIT_STRING_SIZE_8(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL, NULL);

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
                                     2, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_1_8639999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 8639999U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_2678400(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 2678400U, NULL, FALSE);

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
                                     128, 128, FALSE, NULL, NULL);

  return offset;
}


static const per_sequence_t SPCTID_sequence[] = {
  { &hf_ilp_rAND            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BIT_STRING_SIZE_128 },
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
                                                            1U, 24U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_7(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t QoP_sequence[] = {
  { &hf_ilp_horacc          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_127 },
  { &hf_ilp_veracc          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_127 },
  { &hf_ilp_maxLocAge       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_65535 },
  { &hf_ilp_delay           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_INTEGER_0_7 },
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
                                     3, NULL, TRUE, 0, NULL);

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



static int
dissect_ilp_BIT_STRING_SIZE_6(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     6, 6, FALSE, NULL, NULL);

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
                                                  1, 8, FALSE);

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
                                     2, NULL, TRUE, 0, NULL);

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
  { &hf_ilp_sPCTID          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ilp_SPCTID },
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
  {   5, "aFLT" },
  {   6, "eCID" },
  {   7, "eOTD" },
  {   8, "oTDOA" },
  {   9, "agnssSETassisted" },
  {  10, "agnssSETbased" },
  {  11, "agnssSETassistedpref" },
  {  12, "agnssSETbasedpref" },
  {  13, "autonomousGNSS" },
  { 0, NULL }
};


static int
dissect_ilp_PosMethod(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     14, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t GNSSPosTechnology_sequence[] = {
  { &hf_ilp_gps             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_galileo         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_sbas            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_modernized_gps  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_qzss            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
  { &hf_ilp_glonass         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_BOOLEAN },
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
                                     3, NULL, TRUE, 0, NULL);

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
                                     17, NULL, TRUE, 0, NULL);

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
                                                  1, maxPosSize, FALSE);

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
                                                            0U, 167U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_31(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 31U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_10(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 10U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SatelliteInfoElement_sequence[] = {
  { &hf_ilp_satId           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_63 },
  { &hf_ilp_iODE            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_255 },
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
                                                  1, 31, FALSE);

  return offset;
}


static const per_sequence_t NavigationModel_sequence[] = {
  { &hf_ilp_gpsWeek         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_1023 },
  { &hf_ilp_gpsToe          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_167 },
  { &hf_ilp_nSAT            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_31 },
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
                                     8, 8, FALSE, NULL, NULL);

  return offset;
}



static int
dissect_ilp_INTEGER_0_4095(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 4095U, NULL, FALSE);

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
                                                  0, maxGANSSSat, FALSE);

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
                                                            0U, 59U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_ganssDataBitSatList_sequence_of[1] = {
  { &hf_ilp_ganssDataBitSatList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_INTEGER_0_63 },
};

static int
dissect_ilp_T_ganssDataBitSatList(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_T_ganssDataBitSatList, T_ganssDataBitSatList_sequence_of,
                                                  1, maxGANSSSat, FALSE);

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
                                                            1U, 256U, NULL, FALSE);

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
                                                            0U, 23U, NULL, FALSE);

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
                                                  1, maxGANSS, FALSE);

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
                                       1, 8192, FALSE, NULL);

  return offset;
}



static int
dissect_ilp_T_rrlpPayload(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 52 "../../asn1/ilp/ilp.cnf"
  tvbuff_t *rrlp_tvb;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 8192, FALSE, &rrlp_tvb);


  if (rrlp_tvb && rrlp_handle) {
    call_dissector(rrlp_handle, rrlp_tvb, actx->pinfo, tree);
  }



  return offset;
}



static int
dissect_ilp_T_lPPPayload_item(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 61 "../../asn1/ilp/ilp.cnf"
  tvbuff_t *lpp_tvb;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 60000, FALSE, &lpp_tvb);


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
                                                  1, 3, FALSE);

  return offset;
}



static int
dissect_ilp_OCTET_STRING_SIZE_1_60000(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 60000, FALSE, NULL);

  return offset;
}


static const per_sequence_t T_tia801Payload_sequence_of[1] = {
  { &hf_ilp_tia801Payload_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ilp_OCTET_STRING_SIZE_1_60000 },
};

static int
dissect_ilp_T_tia801Payload(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ilp_T_tia801Payload, T_tia801Payload_sequence_of,
                                                  1, 3, FALSE);

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
                                                            0U, 16383U, NULL, FALSE);

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
                                                            0U, 80U, NULL, FALSE);

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
  { &hf_ilp_sPCTID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ilp_SPCTID },
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
                                     15, NULL, FALSE, 0, NULL);

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
                                                            0U, 86399U, NULL, FALSE);

  return offset;
}



static int
dissect_ilp_INTEGER_0_3999999(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 3999999U, NULL, FALSE);

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
                                     15, NULL, FALSE, 0, NULL);

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
#line 42 "../../asn1/ilp/ilp.cnf"

guint32 IlpMessage;

    offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ilp_IlpMessage, IlpMessage_choice,
                                 &IlpMessage);


  col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s ", val_to_str(IlpMessage,ilp_IlpMessage_vals,"Unknown"));



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
#line 27 "../../asn1/ilp/ilp.cnf"
  proto_item *it;
  proto_tree *ilp_tree;

  it = proto_tree_add_item(tree, proto_ilp, tvb, 0, -1, ENC_NA);
  ilp_tree = proto_item_add_subtree(it, ett_ilp);

  col_set_str(actx->pinfo->cinfo, COL_PROTOCOL, PSNAME);
  col_clear(actx->pinfo->cinfo, COL_INFO);

#line 38 "../../asn1/ilp/ilp.cnf"
  offset = dissect_per_sequence(tvb, offset, actx, ilp_tree, hf_index,
                                   ett_ilp_ILP_PDU, ILP_PDU_sequence);



  return offset;
}

/*--- PDUs ---*/

static int dissect_ILP_PDU_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_ilp_ILP_PDU(tvb, offset, &asn1_ctx, tree, hf_ilp_ILP_PDU_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-ilp-fn.c ---*/
#line 71 "../../asn1/ilp/packet-ilp-template.c"


static guint
get_ilp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
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


/*--- Included file: packet-ilp-hfarr.c ---*/
#line 1 "../../asn1/ilp/packet-ilp-hfarr.c"
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
    { &hf_ilp_sPCTID,
      { "sPCTID", "ilp.sPCTID_element",
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
    { &hf_ilp_nSAT,
      { "nSAT", "ilp.nSAT",
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
    { &hf_ilp_iODE,
      { "iODE", "ilp.iODE",
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
        "OCTET_STRING_SIZE_8", HFILL }},
    { &hf_ilp_mdn,
      { "mdn", "ilp.mdn",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_8", HFILL }},
    { &hf_ilp_minsi,
      { "min", "ilp.min",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING_SIZE_34", HFILL }},
    { &hf_ilp_imsi,
      { "imsi", "ilp.imsi",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_8", HFILL }},
    { &hf_ilp_nai,
      { "nai", "ilp.nai",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_1000", HFILL }},
    { &hf_ilp_iPAddress,
      { "iPAddress", "ilp.iPAddress",
        FT_UINT32, BASE_DEC, VALS(ilp_IPAddress_vals), 0,
        NULL, HFILL }},
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
    { &hf_ilp_aFLT,
      { "aFLT", "ilp.aFLT",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_eCID,
      { "eCID", "ilp.eCID",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_eOTD,
      { "eOTD", "ilp.eOTD",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_oTDOA,
      { "oTDOA", "ilp.oTDOA",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_ilp_gANSSPositionMethods,
      { "gANSSPositionMethods", "ilp.gANSSPositionMethods",
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
    { &hf_ilp_nMR,
      { "nMR", "ilp.nMR",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_tA,
      { "tA", "ilp.tA",
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
    { &hf_ilp_tA_01,
      { "tA", "ilp.tA",
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
    { &hf_ilp_tA_02,
      { "tA", "ilp.tA",
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
    { &hf_ilp_plmn_Identity,
      { "plmn-Identity", "ilp.plmn_Identity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ilp_cellIdentity,
      { "cellIdentity", "ilp.cellIdentity",
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
    { &hf_ilp_rTD,
      { "rTD", "ilp.rTD",
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
    { &hf_ilp_rSSI,
      { "rSSI", "ilp.rSSI",
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
    { &hf_ilp_cINR,
      { "cINR", "ilp.cINR",
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
    { &hf_ilp_aRFCN,
      { "aRFCN", "ilp.aRFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_1023", HFILL }},
    { &hf_ilp_bSIC,
      { "bSIC", "ilp.bSIC",
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
    { &hf_ilp_cellIdentity_01,
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
    { &hf_ilp_rAND,
      { "rAND", "ilp.rAND",
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
      { "signal1", "ilp.signal1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal2,
      { "signal2", "ilp.signal2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal3,
      { "signal3", "ilp.signal3",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal4,
      { "signal4", "ilp.signal4",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal5,
      { "signal5", "ilp.signal5",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal6,
      { "signal6", "ilp.signal6",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal7,
      { "signal7", "ilp.signal7",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ilp_GANSSSignals_signal8,
      { "signal8", "ilp.signal8",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},

/*--- End of included file: packet-ilp-hfarr.c ---*/
#line 97 "../../asn1/ilp/packet-ilp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ilp,

/*--- Included file: packet-ilp-ettarr.c ---*/
#line 1 "../../asn1/ilp/packet-ilp-ettarr.c"
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
    &ett_ilp_PosProtocol,
    &ett_ilp_PosProtocolVersion3GPP,
    &ett_ilp_PosProtocolVersion3GPP2,
    &ett_ilp_Supported3GPP2PosProtocolVersion,
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
    &ett_ilp_WlanAPInformation,
    &ett_ilp_RTD,
    &ett_ilp_ReportedLocation,
    &ett_ilp_LocationData,
    &ett_ilp_WimaxBSInformation,
    &ett_ilp_WimaxBsID,
    &ett_ilp_WimaxRTD,
    &ett_ilp_WimaxNMRList,
    &ett_ilp_WimaxNMR,
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

/*--- End of included file: packet-ilp-ettarr.c ---*/
#line 103 "../../asn1/ilp/packet-ilp-template.c"
  };

  module_t *ilp_module;


  /* Register protocol */
  proto_ilp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  new_register_dissector("ilp", dissect_ilp_tcp, proto_ilp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ilp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ilp_module = prefs_register_protocol(proto_ilp,proto_reg_handoff_ilp);

  prefs_register_bool_preference(ilp_module, "desegment_ilp_messages",
        "Reassemble ILP messages spanning multiple TCP segments",
        "Whether the ILP dissector should reassemble messages spanning multiple TCP segments."
        " To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
        &ilp_desegment);

  /* Register a configuration option for port */
  prefs_register_uint_preference(ilp_module, "tcp.port",
                                 "ILP TCP Port",
                                 "Set the TCP port for ILP messages(IANA registered port is 7276)",
                                 10,
                                 &gbl_ilp_port);

}


/*--- proto_reg_handoff_ilp ---------------------------------------*/
void
proto_reg_handoff_ilp(void)
{
  static gboolean initialized = FALSE;
  static dissector_handle_t ilp_handle;
  static guint local_ilp_port;

  if (!initialized) {
    ilp_handle = find_dissector("ilp");
    dissector_add_string("media_type","application/oma-supl-ilp", ilp_handle);
    rrlp_handle = find_dissector("rrlp");
    lpp_handle = find_dissector("lpp");
    initialized = TRUE;
  } else {
    dissector_delete_uint("tcp.port", local_ilp_port, ilp_handle);
  }

  local_ilp_port = gbl_ilp_port;
  dissector_add_uint("tcp.port", gbl_ilp_port, ilp_handle);
}
