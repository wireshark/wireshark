/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-ulp.c                                                             */
/* ../../tools/asn2eth.py -u -e -p ulp -c ulp.cnf -s packet-ulp-template ULP.asn */

/* Input file: packet-ulp-template.c */

#line 1 "packet-ulp-template.c"
/* packet-ulp.c
 * Routines for OMA UserPlane Location Protocol packet dissection
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
 * ref OMA-TS-ULP-V1_0-20060127-C
 * http://www.openmobilealliance.org
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>

#include <stdio.h>
#include <string.h>

#include "packet-ulp.h"

#include "packet-ber.h"
#include "packet-per.h"

#define PNAME  "OMA UserPlane Location Protocol"
#define PSNAME "ULP"
#define PFNAME "ulp"

static dissector_handle_t ulp_handle=NULL;

/* IANA Registered Ports  
 * oma-ulp         7275/tcp    OMA UserPlane Location
 * oma-ulp         7275/udp    OMA UserPlane Location
 */
guint gbl_ulp_port = 7275;

/* Initialize the protocol and registered fields */
static int proto_ulp = -1;



/*--- Included file: packet-ulp-hf.c ---*/
#line 1 "packet-ulp-hf.c"
static int hf_ulp_ULP_PDU_PDU = -1;               /* ULP_PDU */
static int hf_ulp_length = -1;                    /* INTEGER_0_65535 */
static int hf_ulp_version = -1;                   /* Version */
static int hf_ulp_sessionID = -1;                 /* SessionID */
static int hf_ulp_message = -1;                   /* UlpMessage */
static int hf_ulp_msSUPLINIT = -1;                /* SUPLINIT */
static int hf_ulp_msSUPLSTART = -1;               /* SUPLSTART */
static int hf_ulp_msSUPLRESPONSE = -1;            /* SUPLRESPONSE */
static int hf_ulp_msSUPLPOSINIT = -1;             /* SUPLPOSINIT */
static int hf_ulp_msSUPLPOS = -1;                 /* SUPLPOS */
static int hf_ulp_msSUPLEND = -1;                 /* SUPLEND */
static int hf_ulp_msSUPLAUTHREQ = -1;             /* SUPLAUTHREQ */
static int hf_ulp_msSUPLAUTHRESP = -1;            /* SUPLAUTHRESP */
static int hf_ulp_maj = -1;                       /* INTEGER_0_255 */
static int hf_ulp_min = -1;                       /* INTEGER_0_255 */
static int hf_ulp_servind = -1;                   /* INTEGER_0_255 */
static int hf_ulp_setSessionID = -1;              /* SetSessionID */
static int hf_ulp_slpSessionID = -1;              /* SlpSessionID */
static int hf_ulp_sessionId = -1;                 /* INTEGER_0_65535 */
static int hf_ulp_setId = -1;                     /* SETId */
static int hf_ulp_msisdn = -1;                    /* OCTET_STRING_SIZE_8 */
static int hf_ulp_mdn = -1;                       /* OCTET_STRING_SIZE_8 */
static int hf_ulp_min1 = -1;                      /* BIT_STRING_SIZE_34 */
static int hf_ulp_imsi = -1;                      /* OCTET_STRING_SIZE_8 */
static int hf_ulp_nai = -1;                       /* IA5String_SIZE_1_1000 */
static int hf_ulp_iPAddress = -1;                 /* IPAddress */
static int hf_ulp_sessionID1 = -1;                /* OCTET_STRING_SIZE_4 */
static int hf_ulp_slpId = -1;                     /* SLPAddress */
static int hf_ulp_ipv4Address = -1;               /* IPv4Address */
static int hf_ulp_ipv6Address = -1;               /* IPv6Address */
static int hf_ulp_fQDN = -1;                      /* FQDN */
static int hf_ulp_cellInfo = -1;                  /* CellInfo */
static int hf_ulp_status = -1;                    /* Status */
static int hf_ulp_gsmCell = -1;                   /* GsmCellInformation */
static int hf_ulp_wcdmaCell = -1;                 /* WcdmaCellInformation */
static int hf_ulp_cdmaCell = -1;                  /* CdmaCellInformation */
static int hf_ulp_timestamp = -1;                 /* UTCTime */
static int hf_ulp_positionEstimate = -1;          /* PositionEstimate */
static int hf_ulp_velocity = -1;                  /* Velocity */
static int hf_ulp_latitudeSign = -1;              /* T_latitudeSign */
static int hf_ulp_latitude = -1;                  /* INTEGER_0_8388607 */
static int hf_ulp_longitude = -1;                 /* INTEGER_M8388608_8388607 */
static int hf_ulp_uncertainty = -1;               /* T_uncertainty */
static int hf_ulp_uncertaintySemiMajor = -1;      /* INTEGER_0_127 */
static int hf_ulp_uncertaintySemiMinor = -1;      /* INTEGER_0_127 */
static int hf_ulp_orientationMajorAxis = -1;      /* INTEGER_0_180 */
static int hf_ulp_confidence = -1;                /* INTEGER_0_100 */
static int hf_ulp_altitudeInfo = -1;              /* AltitudeInfo */
static int hf_ulp_altitudeDirection = -1;         /* T_altitudeDirection */
static int hf_ulp_altitude = -1;                  /* INTEGER_0_32767 */
static int hf_ulp_altUncertainty = -1;            /* INTEGER_0_127 */
static int hf_ulp_refNID = -1;                    /* INTEGER_0_65535 */
static int hf_ulp_refSID = -1;                    /* INTEGER_0_32767 */
static int hf_ulp_refBASEID = -1;                 /* INTEGER_0_65535 */
static int hf_ulp_refBASELAT = -1;                /* INTEGER_0_4194303 */
static int hf_ulp_reBASELONG = -1;                /* INTEGER_0_8388607 */
static int hf_ulp_refREFPN = -1;                  /* INTEGER_0_511 */
static int hf_ulp_refWeekNumber = -1;             /* INTEGER_0_65535 */
static int hf_ulp_refSeconds = -1;                /* INTEGER_0_4194303 */
static int hf_ulp_refMCC = -1;                    /* INTEGER_0_999 */
static int hf_ulp_refMNC = -1;                    /* INTEGER_0_999 */
static int hf_ulp_refLAC = -1;                    /* INTEGER_0_65535 */
static int hf_ulp_refCI = -1;                     /* INTEGER_0_65535 */
static int hf_ulp_nMR = -1;                       /* NMR */
static int hf_ulp_tA = -1;                        /* INTEGER_0_255 */
static int hf_ulp_refUC = -1;                     /* INTEGER_0_268435455 */
static int hf_ulp_frequencyInfo = -1;             /* FrequencyInfo */
static int hf_ulp_primaryScramblingCode = -1;     /* INTEGER_0_511 */
static int hf_ulp_measuredResultsList = -1;       /* MeasuredResultsList */
static int hf_ulp_modeSpecificInfo = -1;          /* T_modeSpecificInfo */
static int hf_ulp_fdd = -1;                       /* FrequencyInfoFDD */
static int hf_ulp_tdd = -1;                       /* FrequencyInfoTDD */
static int hf_ulp_uarfcn_UL = -1;                 /* UARFCN */
static int hf_ulp_uarfcn_DL = -1;                 /* UARFCN */
static int hf_ulp_uarfcn_Nt = -1;                 /* UARFCN */
static int hf_ulp_NMR_item = -1;                  /* NMRelement */
static int hf_ulp_aRFCN = -1;                     /* INTEGER_0_1023 */
static int hf_ulp_bSIC = -1;                      /* INTEGER_0_63 */
static int hf_ulp_rxLev = -1;                     /* INTEGER_0_63 */
static int hf_ulp_MeasuredResultsList_item = -1;  /* MeasuredResults */
static int hf_ulp_utra_CarrierRSSI = -1;          /* UTRA_CarrierRSSI */
static int hf_ulp_cellMeasuredResultsList = -1;   /* CellMeasuredResultsList */
static int hf_ulp_CellMeasuredResultsList_item = -1;  /* CellMeasuredResults */
static int hf_ulp_cellIdentity = -1;              /* INTEGER_0_268435455 */
static int hf_ulp_modeSpecificInfo1 = -1;         /* T_modeSpecificInfo1 */
static int hf_ulp_fdd1 = -1;                      /* T_fdd */
static int hf_ulp_primaryCPICH_Info = -1;         /* PrimaryCPICH_Info */
static int hf_ulp_cpich_Ec_N0 = -1;               /* CPICH_Ec_N0 */
static int hf_ulp_cpich_RSCP = -1;                /* CPICH_RSCP */
static int hf_ulp_pathloss = -1;                  /* Pathloss */
static int hf_ulp_tdd1 = -1;                      /* T_tdd */
static int hf_ulp_cellParametersID = -1;          /* CellParametersID */
static int hf_ulp_proposedTGSN = -1;              /* TGSN */
static int hf_ulp_primaryCCPCH_RSCP = -1;         /* PrimaryCCPCH_RSCP */
static int hf_ulp_timeslotISCP_List = -1;         /* TimeslotISCP_List */
static int hf_ulp_TimeslotISCP_List_item = -1;    /* TimeslotISCP */
static int hf_ulp_horacc = -1;                    /* INTEGER_0_127 */
static int hf_ulp_veracc = -1;                    /* INTEGER_0_127 */
static int hf_ulp_maxLocAge = -1;                 /* INTEGER_0_65535 */
static int hf_ulp_delay = -1;                     /* INTEGER_0_7 */
static int hf_ulp_horvel = -1;                    /* Horvel */
static int hf_ulp_horandvervel = -1;              /* Horandvervel */
static int hf_ulp_horveluncert = -1;              /* Horveluncert */
static int hf_ulp_horandveruncert = -1;           /* Horandveruncert */
static int hf_ulp_bearing = -1;                   /* BIT_STRING_SIZE_9 */
static int hf_ulp_horspeed = -1;                  /* BIT_STRING_SIZE_16 */
static int hf_ulp_verdirect = -1;                 /* BIT_STRING_SIZE_1 */
static int hf_ulp_verspeed = -1;                  /* BIT_STRING_SIZE_8 */
static int hf_ulp_uncertspeed = -1;               /* BIT_STRING_SIZE_8 */
static int hf_ulp_horuncertspeed = -1;            /* BIT_STRING_SIZE_8 */
static int hf_ulp_veruncertspeed = -1;            /* BIT_STRING_SIZE_8 */
static int hf_ulp_sETNonce = -1;                  /* SETNonce */
static int hf_ulp_keyIdentity2 = -1;              /* KeyIdentity2 */
static int hf_ulp_sPCAuthKey = -1;                /* SPCAuthKey */
static int hf_ulp_keyIdentity3 = -1;              /* KeyIdentity3 */
static int hf_ulp_statusCode = -1;                /* StatusCode */
static int hf_ulp_shortKey = -1;                  /* BIT_STRING_SIZE_128 */
static int hf_ulp_longKey = -1;                   /* BIT_STRING_SIZE_256 */
static int hf_ulp_position = -1;                  /* Position */
static int hf_ulp_ver = -1;                       /* Ver */
static int hf_ulp_posMethod = -1;                 /* PosMethod */
static int hf_ulp_notification = -1;              /* Notification */
static int hf_ulp_sLPAddress = -1;                /* SLPAddress */
static int hf_ulp_qoP = -1;                       /* QoP */
static int hf_ulp_sLPMode = -1;                   /* SLPMode */
static int hf_ulp_mAC = -1;                       /* MAC */
static int hf_ulp_keyIdentity = -1;               /* KeyIdentity */
static int hf_ulp_notificationType = -1;          /* NotificationType */
static int hf_ulp_encodingType = -1;              /* EncodingType */
static int hf_ulp_requestorId = -1;               /* OCTET_STRING_SIZE_1_maxReqLength */
static int hf_ulp_requestorIdType = -1;           /* FormatIndicator */
static int hf_ulp_clientName = -1;                /* OCTET_STRING_SIZE_1_maxClientLength */
static int hf_ulp_clientNameType = -1;            /* FormatIndicator */
static int hf_ulp_posPayLoad = -1;                /* PosPayLoad */
static int hf_ulp_tia801payload = -1;             /* OCTET_STRING_SIZE_1_8192 */
static int hf_ulp_rrcPayload = -1;                /* OCTET_STRING_SIZE_1_8192 */
static int hf_ulp_rrlpPayload = -1;               /* OCTET_STRING_SIZE_1_8192 */
static int hf_ulp_sETCapabilities = -1;           /* SETCapabilities */
static int hf_ulp_requestedAssistData = -1;       /* RequestedAssistData */
static int hf_ulp_locationId = -1;                /* LocationId */
static int hf_ulp_sUPLPOS = -1;                   /* SUPLPOS */
static int hf_ulp_almanacRequested = -1;          /* BOOLEAN */
static int hf_ulp_utcModelRequested = -1;         /* BOOLEAN */
static int hf_ulp_ionosphericModelRequested = -1;  /* BOOLEAN */
static int hf_ulp_dgpsCorrectionsRequested = -1;  /* BOOLEAN */
static int hf_ulp_referenceLocationRequested = -1;  /* BOOLEAN */
static int hf_ulp_referenceTimeRequested = -1;    /* BOOLEAN */
static int hf_ulp_acquisitionAssistanceRequested = -1;  /* BOOLEAN */
static int hf_ulp_realTimeIntegrityRequested = -1;  /* BOOLEAN */
static int hf_ulp_navigationModelRequested = -1;  /* BOOLEAN */
static int hf_ulp_navigationModelData = -1;       /* NavigationModel */
static int hf_ulp_gpsWeek = -1;                   /* INTEGER_0_1023 */
static int hf_ulp_gpsToe = -1;                    /* INTEGER_0_167 */
static int hf_ulp_nSAT = -1;                      /* INTEGER_0_31 */
static int hf_ulp_toeLimit = -1;                  /* INTEGER_0_10 */
static int hf_ulp_satInfo = -1;                   /* SatelliteInfo */
static int hf_ulp_SatelliteInfo_item = -1;        /* SatelliteInfoElement */
static int hf_ulp_satId = -1;                     /* INTEGER_0_63 */
static int hf_ulp_iODE = -1;                      /* INTEGER_0_255 */
static int hf_ulp_sETAuthKey = -1;                /* SETAuthKey */
static int hf_ulp_keyIdentity4 = -1;              /* KeyIdentity4 */
static int hf_ulp_posTechnology = -1;             /* PosTechnology */
static int hf_ulp_prefMethod = -1;                /* PrefMethod */
static int hf_ulp_posProtocol = -1;               /* PosProtocol */
static int hf_ulp_agpsSETassisted = -1;           /* BOOLEAN */
static int hf_ulp_agpsSETBased = -1;              /* BOOLEAN */
static int hf_ulp_autonomousGPS = -1;             /* BOOLEAN */
static int hf_ulp_aFLT = -1;                      /* BOOLEAN */
static int hf_ulp_eCID = -1;                      /* BOOLEAN */
static int hf_ulp_eOTD = -1;                      /* BOOLEAN */
static int hf_ulp_oTDOA = -1;                     /* BOOLEAN */
static int hf_ulp_tia801 = -1;                    /* BOOLEAN */
static int hf_ulp_rrlp = -1;                      /* BOOLEAN */
static int hf_ulp_rrc = -1;                       /* BOOLEAN */

/*--- End of included file: packet-ulp-hf.c ---*/
#line 63 "packet-ulp-template.c"

/* Initialize the subtree pointers */
static gint ett_ulp = -1;

/*--- Included file: packet-ulp-ett.c ---*/
#line 1 "packet-ulp-ett.c"
static gint ett_ulp_ULP_PDU = -1;
static gint ett_ulp_UlpMessage = -1;
static gint ett_ulp_Version = -1;
static gint ett_ulp_SessionID = -1;
static gint ett_ulp_SetSessionID = -1;
static gint ett_ulp_SETId = -1;
static gint ett_ulp_SlpSessionID = -1;
static gint ett_ulp_IPAddress = -1;
static gint ett_ulp_SLPAddress = -1;
static gint ett_ulp_LocationId = -1;
static gint ett_ulp_CellInfo = -1;
static gint ett_ulp_Position = -1;
static gint ett_ulp_PositionEstimate = -1;
static gint ett_ulp_T_uncertainty = -1;
static gint ett_ulp_AltitudeInfo = -1;
static gint ett_ulp_CdmaCellInformation = -1;
static gint ett_ulp_GsmCellInformation = -1;
static gint ett_ulp_WcdmaCellInformation = -1;
static gint ett_ulp_FrequencyInfo = -1;
static gint ett_ulp_T_modeSpecificInfo = -1;
static gint ett_ulp_FrequencyInfoFDD = -1;
static gint ett_ulp_FrequencyInfoTDD = -1;
static gint ett_ulp_NMR = -1;
static gint ett_ulp_NMRelement = -1;
static gint ett_ulp_MeasuredResultsList = -1;
static gint ett_ulp_MeasuredResults = -1;
static gint ett_ulp_CellMeasuredResultsList = -1;
static gint ett_ulp_CellMeasuredResults = -1;
static gint ett_ulp_T_modeSpecificInfo1 = -1;
static gint ett_ulp_T_fdd = -1;
static gint ett_ulp_T_tdd = -1;
static gint ett_ulp_TimeslotISCP_List = -1;
static gint ett_ulp_PrimaryCPICH_Info = -1;
static gint ett_ulp_QoP = -1;
static gint ett_ulp_Velocity = -1;
static gint ett_ulp_Horvel = -1;
static gint ett_ulp_Horandvervel = -1;
static gint ett_ulp_Horveluncert = -1;
static gint ett_ulp_Horandveruncert = -1;
static gint ett_ulp_SUPLAUTHREQ = -1;
static gint ett_ulp_SUPLAUTHRESP = -1;
static gint ett_ulp_SPCAuthKey = -1;
static gint ett_ulp_SUPLEND = -1;
static gint ett_ulp_SUPLINIT = -1;
static gint ett_ulp_Notification = -1;
static gint ett_ulp_SUPLPOS = -1;
static gint ett_ulp_PosPayLoad = -1;
static gint ett_ulp_SUPLPOSINIT = -1;
static gint ett_ulp_RequestedAssistData = -1;
static gint ett_ulp_NavigationModel = -1;
static gint ett_ulp_SatelliteInfo = -1;
static gint ett_ulp_SatelliteInfoElement = -1;
static gint ett_ulp_SUPLRESPONSE = -1;
static gint ett_ulp_SETAuthKey = -1;
static gint ett_ulp_SUPLSTART = -1;
static gint ett_ulp_SETCapabilities = -1;
static gint ett_ulp_PosTechnology = -1;
static gint ett_ulp_PosProtocol = -1;

/*--- End of included file: packet-ulp-ett.c ---*/
#line 67 "packet-ulp-template.c"

/* Include constants */

/*--- Included file: packet-ulp-val.h ---*/
#line 1 "packet-ulp-val.h"
#define maxCellMeas                    32
#define maxFreq                        8
#define maxTS                          14
#define maxReqLength                   50
#define maxClientLength                50

/*--- End of included file: packet-ulp-val.h ---*/
#line 70 "packet-ulp-template.c"


/*--- Included file: packet-ulp-fn.c ---*/
#line 1 "packet-ulp-fn.c"
/*--- Fields for imported types ---*/




static int
dissect_ulp_INTEGER_0_65535(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 65535U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_length(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_65535(tvb, offset, pinfo, tree, hf_ulp_length);
}
static int dissect_sessionId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_65535(tvb, offset, pinfo, tree, hf_ulp_sessionId);
}
static int dissect_refNID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_65535(tvb, offset, pinfo, tree, hf_ulp_refNID);
}
static int dissect_refBASEID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_65535(tvb, offset, pinfo, tree, hf_ulp_refBASEID);
}
static int dissect_refWeekNumber(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_65535(tvb, offset, pinfo, tree, hf_ulp_refWeekNumber);
}
static int dissect_refLAC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_65535(tvb, offset, pinfo, tree, hf_ulp_refLAC);
}
static int dissect_refCI(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_65535(tvb, offset, pinfo, tree, hf_ulp_refCI);
}
static int dissect_maxLocAge(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_65535(tvb, offset, pinfo, tree, hf_ulp_maxLocAge);
}



static int
dissect_ulp_INTEGER_0_255(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 255U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_maj(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_255(tvb, offset, pinfo, tree, hf_ulp_maj);
}
static int dissect_min(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_255(tvb, offset, pinfo, tree, hf_ulp_min);
}
static int dissect_servind(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_255(tvb, offset, pinfo, tree, hf_ulp_servind);
}
static int dissect_tA(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_255(tvb, offset, pinfo, tree, hf_ulp_tA);
}
static int dissect_iODE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_255(tvb, offset, pinfo, tree, hf_ulp_iODE);
}


static const per_sequence_t Version_sequence[] = {
  { "maj"                         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_maj },
  { "min"                         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_min },
  { "servind"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_servind },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Version(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_Version, Version_sequence);

  return offset;
}
static int dissect_version(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_Version(tvb, offset, pinfo, tree, hf_ulp_version);
}



static int
dissect_ulp_OCTET_STRING_SIZE_8(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index,
                                       8, 8, NULL);

  return offset;
}
static int dissect_msisdn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_OCTET_STRING_SIZE_8(tvb, offset, pinfo, tree, hf_ulp_msisdn);
}
static int dissect_mdn(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_OCTET_STRING_SIZE_8(tvb, offset, pinfo, tree, hf_ulp_mdn);
}
static int dissect_imsi(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_OCTET_STRING_SIZE_8(tvb, offset, pinfo, tree, hf_ulp_imsi);
}



static int
dissect_ulp_BIT_STRING_SIZE_34(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     34, 34, FALSE);

  return offset;
}
static int dissect_min1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BIT_STRING_SIZE_34(tvb, offset, pinfo, tree, hf_ulp_min1);
}



static int
dissect_ulp_IA5String_SIZE_1_1000(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_IA5String(tvb, offset, pinfo, tree, hf_index,
                                          1, 1000);

  return offset;
}
static int dissect_nai(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_IA5String_SIZE_1_1000(tvb, offset, pinfo, tree, hf_ulp_nai);
}



static int
dissect_ulp_IPv4Address(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index,
                                       4, 4, NULL);

  return offset;
}
static int dissect_ipv4Address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_IPv4Address(tvb, offset, pinfo, tree, hf_ulp_ipv4Address);
}



static int
dissect_ulp_IPv6Address(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index,
                                       16, 16, NULL);

  return offset;
}
static int dissect_ipv6Address(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_IPv6Address(tvb, offset, pinfo, tree, hf_ulp_ipv6Address);
}


static const value_string ulp_IPAddress_vals[] = {
  {   0, "ipv4Address" },
  {   1, "ipv6Address" },
  { 0, NULL }
};

static const per_choice_t IPAddress_choice[] = {
  {   0, "ipv4Address"                 , ASN1_NO_EXTENSIONS     , dissect_ipv4Address },
  {   1, "ipv6Address"                 , ASN1_NO_EXTENSIONS     , dissect_ipv6Address },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_IPAddress(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_ulp_IPAddress, IPAddress_choice,
                                 NULL);

  return offset;
}
static int dissect_iPAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_IPAddress(tvb, offset, pinfo, tree, hf_ulp_iPAddress);
}


static const value_string ulp_SETId_vals[] = {
  {   0, "msisdn" },
  {   1, "mdn" },
  {   2, "min" },
  {   3, "imsi" },
  {   4, "nai" },
  {   5, "iPAddress" },
  { 0, NULL }
};

static const per_choice_t SETId_choice[] = {
  {   0, "msisdn"                      , ASN1_EXTENSION_ROOT    , dissect_msisdn },
  {   1, "mdn"                         , ASN1_EXTENSION_ROOT    , dissect_mdn },
  {   2, "min"                         , ASN1_EXTENSION_ROOT    , dissect_min1 },
  {   3, "imsi"                        , ASN1_EXTENSION_ROOT    , dissect_imsi },
  {   4, "nai"                         , ASN1_EXTENSION_ROOT    , dissect_nai },
  {   5, "iPAddress"                   , ASN1_EXTENSION_ROOT    , dissect_iPAddress },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_SETId(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_ulp_SETId, SETId_choice,
                                 NULL);

  return offset;
}
static int dissect_setId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SETId(tvb, offset, pinfo, tree, hf_ulp_setId);
}


static const per_sequence_t SetSessionID_sequence[] = {
  { "sessionId"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sessionId },
  { "setId"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_setId },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SetSessionID(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_SetSessionID, SetSessionID_sequence);

  return offset;
}
static int dissect_setSessionID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SetSessionID(tvb, offset, pinfo, tree, hf_ulp_setSessionID);
}



static int
dissect_ulp_OCTET_STRING_SIZE_4(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index,
                                       4, 4, NULL);

  return offset;
}
static int dissect_sessionID1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_OCTET_STRING_SIZE_4(tvb, offset, pinfo, tree, hf_ulp_sessionID1);
}



static int
dissect_ulp_FQDN(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_VisibleString(tvb, offset, pinfo, tree, hf_index,
                                          1, 255);

  return offset;
}
static int dissect_fQDN(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_FQDN(tvb, offset, pinfo, tree, hf_ulp_fQDN);
}


static const value_string ulp_SLPAddress_vals[] = {
  {   0, "iPAddress" },
  {   1, "fQDN" },
  { 0, NULL }
};

static const per_choice_t SLPAddress_choice[] = {
  {   0, "iPAddress"                   , ASN1_EXTENSION_ROOT    , dissect_iPAddress },
  {   1, "fQDN"                        , ASN1_EXTENSION_ROOT    , dissect_fQDN },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_SLPAddress(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_ulp_SLPAddress, SLPAddress_choice,
                                 NULL);

  return offset;
}
static int dissect_slpId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SLPAddress(tvb, offset, pinfo, tree, hf_ulp_slpId);
}
static int dissect_sLPAddress(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SLPAddress(tvb, offset, pinfo, tree, hf_ulp_sLPAddress);
}


static const per_sequence_t SlpSessionID_sequence[] = {
  { "sessionID"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sessionID1 },
  { "slpId"                       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_slpId },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SlpSessionID(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_SlpSessionID, SlpSessionID_sequence);

  return offset;
}
static int dissect_slpSessionID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SlpSessionID(tvb, offset, pinfo, tree, hf_ulp_slpSessionID);
}


static const per_sequence_t SessionID_sequence[] = {
  { "setSessionID"                , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_setSessionID },
  { "slpSessionID"                , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_slpSessionID },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SessionID(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_SessionID, SessionID_sequence);

  return offset;
}
static int dissect_sessionID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SessionID(tvb, offset, pinfo, tree, hf_ulp_sessionID);
}


static const value_string ulp_PosMethod_vals[] = {
  {   0, "agpsSETassisted" },
  {   1, "agpsSETbased" },
  {   2, "agpsSETassistedpref" },
  {   3, "agpsSETbasedpref" },
  {   4, "autonomousGPS" },
  {   5, "aFLT" },
  {   6, "eCID" },
  {   7, "eOTD" },
  {   8, "oTDOA" },
  {   9, "noPosition" },
  { 0, NULL }
};


static int
dissect_ulp_PosMethod(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     10, NULL, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_posMethod(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_PosMethod(tvb, offset, pinfo, tree, hf_ulp_posMethod);
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
dissect_ulp_NotificationType(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     5, NULL, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_notificationType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_NotificationType(tvb, offset, pinfo, tree, hf_ulp_notificationType);
}


static const value_string ulp_EncodingType_vals[] = {
  {   0, "ucs2" },
  {   1, "gsmDefault" },
  {   2, "utf8" },
  { 0, NULL }
};


static int
dissect_ulp_EncodingType(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     3, NULL, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_encodingType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_EncodingType(tvb, offset, pinfo, tree, hf_ulp_encodingType);
}



static int
dissect_ulp_OCTET_STRING_SIZE_1_maxReqLength(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index,
                                       1, maxReqLength, NULL);

  return offset;
}
static int dissect_requestorId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_OCTET_STRING_SIZE_1_maxReqLength(tvb, offset, pinfo, tree, hf_ulp_requestorId);
}


static const value_string ulp_FormatIndicator_vals[] = {
  {   0, "logicalName" },
  {   1, "e-mailAddress" },
  {   2, "msisdn" },
  {   3, "url" },
  {   4, "sipUrl" },
  {   5, "min" },
  {   6, "mdn" },
  { 0, NULL }
};


static int
dissect_ulp_FormatIndicator(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     7, NULL, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_requestorIdType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_FormatIndicator(tvb, offset, pinfo, tree, hf_ulp_requestorIdType);
}
static int dissect_clientNameType(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_FormatIndicator(tvb, offset, pinfo, tree, hf_ulp_clientNameType);
}



static int
dissect_ulp_OCTET_STRING_SIZE_1_maxClientLength(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index,
                                       1, maxClientLength, NULL);

  return offset;
}
static int dissect_clientName(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_OCTET_STRING_SIZE_1_maxClientLength(tvb, offset, pinfo, tree, hf_ulp_clientName);
}


static const per_sequence_t Notification_sequence[] = {
  { "notificationType"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_notificationType },
  { "encodingType"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_encodingType },
  { "requestorId"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_requestorId },
  { "requestorIdType"             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_requestorIdType },
  { "clientName"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_clientName },
  { "clientNameType"              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_clientNameType },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Notification(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_Notification, Notification_sequence);

  return offset;
}
static int dissect_notification(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_Notification(tvb, offset, pinfo, tree, hf_ulp_notification);
}



static int
dissect_ulp_INTEGER_0_127(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 127U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_uncertaintySemiMajor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_127(tvb, offset, pinfo, tree, hf_ulp_uncertaintySemiMajor);
}
static int dissect_uncertaintySemiMinor(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_127(tvb, offset, pinfo, tree, hf_ulp_uncertaintySemiMinor);
}
static int dissect_altUncertainty(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_127(tvb, offset, pinfo, tree, hf_ulp_altUncertainty);
}
static int dissect_horacc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_127(tvb, offset, pinfo, tree, hf_ulp_horacc);
}
static int dissect_veracc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_127(tvb, offset, pinfo, tree, hf_ulp_veracc);
}



static int
dissect_ulp_INTEGER_0_7(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 7U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_delay(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_7(tvb, offset, pinfo, tree, hf_ulp_delay);
}


static const per_sequence_t QoP_sequence[] = {
  { "horacc"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_horacc },
  { "veracc"                      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_veracc },
  { "maxLocAge"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_maxLocAge },
  { "delay"                       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_delay },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_QoP(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_QoP, QoP_sequence);

  return offset;
}
static int dissect_qoP(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_QoP(tvb, offset, pinfo, tree, hf_ulp_qoP);
}


static const value_string ulp_SLPMode_vals[] = {
  {   0, "proxy" },
  {   1, "nonProxy" },
  { 0, NULL }
};


static int
dissect_ulp_SLPMode(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     2, NULL, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_sLPMode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SLPMode(tvb, offset, pinfo, tree, hf_ulp_sLPMode);
}



static int
dissect_ulp_MAC(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     64, 64, FALSE);

  return offset;
}
static int dissect_mAC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_MAC(tvb, offset, pinfo, tree, hf_ulp_mAC);
}



static int
dissect_ulp_KeyIdentity(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     128, 128, FALSE);

  return offset;
}
static int dissect_keyIdentity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_KeyIdentity(tvb, offset, pinfo, tree, hf_ulp_keyIdentity);
}


static const per_sequence_t SUPLINIT_sequence[] = {
  { "posMethod"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_posMethod },
  { "notification"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_notification },
  { "sLPAddress"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sLPAddress },
  { "qoP"                         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_qoP },
  { "sLPMode"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sLPMode },
  { "mAC"                         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_mAC },
  { "keyIdentity"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_keyIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLINIT(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_SUPLINIT, SUPLINIT_sequence);

  return offset;
}
static int dissect_msSUPLINIT(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SUPLINIT(tvb, offset, pinfo, tree, hf_ulp_msSUPLINIT);
}



static int
dissect_ulp_BOOLEAN(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_boolean(tvb, offset, pinfo, tree, hf_index,
                                  NULL, NULL);

  return offset;
}
static int dissect_almanacRequested(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_almanacRequested);
}
static int dissect_utcModelRequested(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_utcModelRequested);
}
static int dissect_ionosphericModelRequested(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_ionosphericModelRequested);
}
static int dissect_dgpsCorrectionsRequested(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_dgpsCorrectionsRequested);
}
static int dissect_referenceLocationRequested(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_referenceLocationRequested);
}
static int dissect_referenceTimeRequested(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_referenceTimeRequested);
}
static int dissect_acquisitionAssistanceRequested(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_acquisitionAssistanceRequested);
}
static int dissect_realTimeIntegrityRequested(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_realTimeIntegrityRequested);
}
static int dissect_navigationModelRequested(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_navigationModelRequested);
}
static int dissect_agpsSETassisted(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_agpsSETassisted);
}
static int dissect_agpsSETBased(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_agpsSETBased);
}
static int dissect_autonomousGPS(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_autonomousGPS);
}
static int dissect_aFLT(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_aFLT);
}
static int dissect_eCID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_eCID);
}
static int dissect_eOTD(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_eOTD);
}
static int dissect_oTDOA(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_oTDOA);
}
static int dissect_tia801(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_tia801);
}
static int dissect_rrlp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_rrlp);
}
static int dissect_rrc(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BOOLEAN(tvb, offset, pinfo, tree, hf_ulp_rrc);
}


static const per_sequence_t PosTechnology_sequence[] = {
  { "agpsSETassisted"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_agpsSETassisted },
  { "agpsSETBased"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_agpsSETBased },
  { "autonomousGPS"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_autonomousGPS },
  { "aFLT"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_aFLT },
  { "eCID"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_eCID },
  { "eOTD"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_eOTD },
  { "oTDOA"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_oTDOA },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PosTechnology(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_PosTechnology, PosTechnology_sequence);

  return offset;
}
static int dissect_posTechnology(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_PosTechnology(tvb, offset, pinfo, tree, hf_ulp_posTechnology);
}


static const value_string ulp_PrefMethod_vals[] = {
  {   0, "agpsSETassistedPreferred" },
  {   1, "agpsSETBasedPreferred" },
  {   2, "noPreference" },
  { 0, NULL }
};


static int
dissect_ulp_PrefMethod(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     3, NULL, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_prefMethod(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_PrefMethod(tvb, offset, pinfo, tree, hf_ulp_prefMethod);
}


static const per_sequence_t PosProtocol_sequence[] = {
  { "tia801"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_tia801 },
  { "rrlp"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrlp },
  { "rrc"                         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rrc },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PosProtocol(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_PosProtocol, PosProtocol_sequence);

  return offset;
}
static int dissect_posProtocol(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_PosProtocol(tvb, offset, pinfo, tree, hf_ulp_posProtocol);
}


static const per_sequence_t SETCapabilities_sequence[] = {
  { "posTechnology"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_posTechnology },
  { "prefMethod"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_prefMethod },
  { "posProtocol"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_posProtocol },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SETCapabilities(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_SETCapabilities, SETCapabilities_sequence);

  return offset;
}
static int dissect_sETCapabilities(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SETCapabilities(tvb, offset, pinfo, tree, hf_ulp_sETCapabilities);
}



static int
dissect_ulp_INTEGER_0_999(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 999U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_refMCC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_999(tvb, offset, pinfo, tree, hf_ulp_refMCC);
}
static int dissect_refMNC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_999(tvb, offset, pinfo, tree, hf_ulp_refMNC);
}



static int
dissect_ulp_INTEGER_0_1023(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 1023U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_aRFCN(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_1023(tvb, offset, pinfo, tree, hf_ulp_aRFCN);
}
static int dissect_gpsWeek(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_1023(tvb, offset, pinfo, tree, hf_ulp_gpsWeek);
}



static int
dissect_ulp_INTEGER_0_63(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 63U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_bSIC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_63(tvb, offset, pinfo, tree, hf_ulp_bSIC);
}
static int dissect_rxLev(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_63(tvb, offset, pinfo, tree, hf_ulp_rxLev);
}
static int dissect_satId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_63(tvb, offset, pinfo, tree, hf_ulp_satId);
}


static const per_sequence_t NMRelement_sequence[] = {
  { "aRFCN"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_aRFCN },
  { "bSIC"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_bSIC },
  { "rxLev"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_rxLev },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_NMRelement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_NMRelement, NMRelement_sequence);

  return offset;
}
static int dissect_NMR_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_NMRelement(tvb, offset, pinfo, tree, hf_ulp_NMR_item);
}


static const per_sequence_t NMR_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_NMR_item },
};

static int
dissect_ulp_NMR(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_ulp_NMR, NMR_sequence_of,
                                                  1, 15);

  return offset;
}
static int dissect_nMR(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_NMR(tvb, offset, pinfo, tree, hf_ulp_nMR);
}


static const per_sequence_t GsmCellInformation_sequence[] = {
  { "refMCC"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refMCC },
  { "refMNC"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refMNC },
  { "refLAC"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refLAC },
  { "refCI"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refCI },
  { "nMR"                         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_nMR },
  { "tA"                          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_tA },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GsmCellInformation(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_GsmCellInformation, GsmCellInformation_sequence);

  return offset;
}
static int dissect_gsmCell(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_GsmCellInformation(tvb, offset, pinfo, tree, hf_ulp_gsmCell);
}



static int
dissect_ulp_INTEGER_0_268435455(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 268435455U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_refUC(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_268435455(tvb, offset, pinfo, tree, hf_ulp_refUC);
}
static int dissect_cellIdentity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_268435455(tvb, offset, pinfo, tree, hf_ulp_cellIdentity);
}



static int
dissect_ulp_UARFCN(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 16383U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_uarfcn_UL(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_UARFCN(tvb, offset, pinfo, tree, hf_ulp_uarfcn_UL);
}
static int dissect_uarfcn_DL(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_UARFCN(tvb, offset, pinfo, tree, hf_ulp_uarfcn_DL);
}
static int dissect_uarfcn_Nt(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_UARFCN(tvb, offset, pinfo, tree, hf_ulp_uarfcn_Nt);
}


static const per_sequence_t FrequencyInfoFDD_sequence[] = {
  { "uarfcn-UL"                   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_uarfcn_UL },
  { "uarfcn-DL"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uarfcn_DL },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_FrequencyInfoFDD(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_FrequencyInfoFDD, FrequencyInfoFDD_sequence);

  return offset;
}
static int dissect_fdd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_FrequencyInfoFDD(tvb, offset, pinfo, tree, hf_ulp_fdd);
}


static const per_sequence_t FrequencyInfoTDD_sequence[] = {
  { "uarfcn-Nt"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uarfcn_Nt },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_FrequencyInfoTDD(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_FrequencyInfoTDD, FrequencyInfoTDD_sequence);

  return offset;
}
static int dissect_tdd(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_FrequencyInfoTDD(tvb, offset, pinfo, tree, hf_ulp_tdd);
}


static const value_string ulp_T_modeSpecificInfo_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_choice[] = {
  {   0, "fdd"                         , ASN1_EXTENSION_ROOT    , dissect_fdd },
  {   1, "tdd"                         , ASN1_EXTENSION_ROOT    , dissect_tdd },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_T_modeSpecificInfo(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_ulp_T_modeSpecificInfo, T_modeSpecificInfo_choice,
                                 NULL);

  return offset;
}
static int dissect_modeSpecificInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_T_modeSpecificInfo(tvb, offset, pinfo, tree, hf_ulp_modeSpecificInfo);
}


static const per_sequence_t FrequencyInfo_sequence[] = {
  { "modeSpecificInfo"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_modeSpecificInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_FrequencyInfo(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_FrequencyInfo, FrequencyInfo_sequence);

  return offset;
}
static int dissect_frequencyInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_FrequencyInfo(tvb, offset, pinfo, tree, hf_ulp_frequencyInfo);
}



static int
dissect_ulp_INTEGER_0_511(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 511U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_refREFPN(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_511(tvb, offset, pinfo, tree, hf_ulp_refREFPN);
}
static int dissect_primaryScramblingCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_511(tvb, offset, pinfo, tree, hf_ulp_primaryScramblingCode);
}



static int
dissect_ulp_UTRA_CarrierRSSI(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 127U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_utra_CarrierRSSI(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_UTRA_CarrierRSSI(tvb, offset, pinfo, tree, hf_ulp_utra_CarrierRSSI);
}


static const per_sequence_t PrimaryCPICH_Info_sequence[] = {
  { "primaryScramblingCode"       , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_primaryScramblingCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PrimaryCPICH_Info(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_PrimaryCPICH_Info, PrimaryCPICH_Info_sequence);

  return offset;
}
static int dissect_primaryCPICH_Info(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_PrimaryCPICH_Info(tvb, offset, pinfo, tree, hf_ulp_primaryCPICH_Info);
}



static int
dissect_ulp_CPICH_Ec_N0(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 63U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_cpich_Ec_N0(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_CPICH_Ec_N0(tvb, offset, pinfo, tree, hf_ulp_cpich_Ec_N0);
}



static int
dissect_ulp_CPICH_RSCP(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 127U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_cpich_RSCP(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_CPICH_RSCP(tvb, offset, pinfo, tree, hf_ulp_cpich_RSCP);
}



static int
dissect_ulp_Pathloss(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              46U, 173U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_pathloss(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_Pathloss(tvb, offset, pinfo, tree, hf_ulp_pathloss);
}


static const per_sequence_t T_fdd_sequence[] = {
  { "primaryCPICH-Info"           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_primaryCPICH_Info },
  { "cpich-Ec-N0"                 , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cpich_Ec_N0 },
  { "cpich-RSCP"                  , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cpich_RSCP },
  { "pathloss"                    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_pathloss },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_fdd(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_T_fdd, T_fdd_sequence);

  return offset;
}
static int dissect_fdd1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_T_fdd(tvb, offset, pinfo, tree, hf_ulp_fdd1);
}



static int
dissect_ulp_CellParametersID(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 127U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_cellParametersID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_CellParametersID(tvb, offset, pinfo, tree, hf_ulp_cellParametersID);
}



static int
dissect_ulp_TGSN(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 14U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_proposedTGSN(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_TGSN(tvb, offset, pinfo, tree, hf_ulp_proposedTGSN);
}



static int
dissect_ulp_PrimaryCCPCH_RSCP(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 127U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_primaryCCPCH_RSCP(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_PrimaryCCPCH_RSCP(tvb, offset, pinfo, tree, hf_ulp_primaryCCPCH_RSCP);
}



static int
dissect_ulp_TimeslotISCP(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 127U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_TimeslotISCP_List_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_TimeslotISCP(tvb, offset, pinfo, tree, hf_ulp_TimeslotISCP_List_item);
}


static const per_sequence_t TimeslotISCP_List_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_TimeslotISCP_List_item },
};

static int
dissect_ulp_TimeslotISCP_List(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_ulp_TimeslotISCP_List, TimeslotISCP_List_sequence_of,
                                                  1, maxTS);

  return offset;
}
static int dissect_timeslotISCP_List(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_TimeslotISCP_List(tvb, offset, pinfo, tree, hf_ulp_timeslotISCP_List);
}


static const per_sequence_t T_tdd_sequence[] = {
  { "cellParametersID"            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_cellParametersID },
  { "proposedTGSN"                , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_proposedTGSN },
  { "primaryCCPCH-RSCP"           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_primaryCCPCH_RSCP },
  { "pathloss"                    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_pathloss },
  { "timeslotISCP-List"           , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_timeslotISCP_List },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_tdd(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_T_tdd, T_tdd_sequence);

  return offset;
}
static int dissect_tdd1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_T_tdd(tvb, offset, pinfo, tree, hf_ulp_tdd1);
}


static const value_string ulp_T_modeSpecificInfo1_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo1_choice[] = {
  {   0, "fdd"                         , ASN1_NO_EXTENSIONS     , dissect_fdd1 },
  {   1, "tdd"                         , ASN1_NO_EXTENSIONS     , dissect_tdd1 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_T_modeSpecificInfo1(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_ulp_T_modeSpecificInfo1, T_modeSpecificInfo1_choice,
                                 NULL);

  return offset;
}
static int dissect_modeSpecificInfo1(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_T_modeSpecificInfo1(tvb, offset, pinfo, tree, hf_ulp_modeSpecificInfo1);
}


static const per_sequence_t CellMeasuredResults_sequence[] = {
  { "cellIdentity"                , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cellIdentity },
  { "modeSpecificInfo"            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_modeSpecificInfo1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_CellMeasuredResults(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_CellMeasuredResults, CellMeasuredResults_sequence);

  return offset;
}
static int dissect_CellMeasuredResultsList_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_CellMeasuredResults(tvb, offset, pinfo, tree, hf_ulp_CellMeasuredResultsList_item);
}


static const per_sequence_t CellMeasuredResultsList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_CellMeasuredResultsList_item },
};

static int
dissect_ulp_CellMeasuredResultsList(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_ulp_CellMeasuredResultsList, CellMeasuredResultsList_sequence_of,
                                                  1, maxCellMeas);

  return offset;
}
static int dissect_cellMeasuredResultsList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_CellMeasuredResultsList(tvb, offset, pinfo, tree, hf_ulp_cellMeasuredResultsList);
}


static const per_sequence_t MeasuredResults_sequence[] = {
  { "frequencyInfo"               , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_frequencyInfo },
  { "utra-CarrierRSSI"            , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_utra_CarrierRSSI },
  { "cellMeasuredResultsList"     , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_cellMeasuredResultsList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_MeasuredResults(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_MeasuredResults, MeasuredResults_sequence);

  return offset;
}
static int dissect_MeasuredResultsList_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_MeasuredResults(tvb, offset, pinfo, tree, hf_ulp_MeasuredResultsList_item);
}


static const per_sequence_t MeasuredResultsList_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_MeasuredResultsList_item },
};

static int
dissect_ulp_MeasuredResultsList(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_ulp_MeasuredResultsList, MeasuredResultsList_sequence_of,
                                                  1, maxFreq);

  return offset;
}
static int dissect_measuredResultsList(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_MeasuredResultsList(tvb, offset, pinfo, tree, hf_ulp_measuredResultsList);
}


static const per_sequence_t WcdmaCellInformation_sequence[] = {
  { "refMCC"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refMCC },
  { "refMNC"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refMNC },
  { "refUC"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refUC },
  { "frequencyInfo"               , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_frequencyInfo },
  { "primaryScramblingCode"       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_primaryScramblingCode },
  { "measuredResultsList"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_measuredResultsList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_WcdmaCellInformation(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_WcdmaCellInformation, WcdmaCellInformation_sequence);

  return offset;
}
static int dissect_wcdmaCell(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_WcdmaCellInformation(tvb, offset, pinfo, tree, hf_ulp_wcdmaCell);
}



static int
dissect_ulp_INTEGER_0_32767(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 32767U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_altitude(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_32767(tvb, offset, pinfo, tree, hf_ulp_altitude);
}
static int dissect_refSID(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_32767(tvb, offset, pinfo, tree, hf_ulp_refSID);
}



static int
dissect_ulp_INTEGER_0_4194303(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 4194303U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_refBASELAT(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_4194303(tvb, offset, pinfo, tree, hf_ulp_refBASELAT);
}
static int dissect_refSeconds(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_4194303(tvb, offset, pinfo, tree, hf_ulp_refSeconds);
}



static int
dissect_ulp_INTEGER_0_8388607(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 8388607U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_latitude(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_8388607(tvb, offset, pinfo, tree, hf_ulp_latitude);
}
static int dissect_reBASELONG(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_8388607(tvb, offset, pinfo, tree, hf_ulp_reBASELONG);
}


static const per_sequence_t CdmaCellInformation_sequence[] = {
  { "refNID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refNID },
  { "refSID"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refSID },
  { "refBASEID"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refBASEID },
  { "refBASELAT"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refBASELAT },
  { "reBASELONG"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_reBASELONG },
  { "refREFPN"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refREFPN },
  { "refWeekNumber"               , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refWeekNumber },
  { "refSeconds"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_refSeconds },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_CdmaCellInformation(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_CdmaCellInformation, CdmaCellInformation_sequence);

  return offset;
}
static int dissect_cdmaCell(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_CdmaCellInformation(tvb, offset, pinfo, tree, hf_ulp_cdmaCell);
}


static const value_string ulp_CellInfo_vals[] = {
  {   0, "gsmCell" },
  {   1, "wcdmaCell" },
  {   2, "cdmaCell" },
  { 0, NULL }
};

static const per_choice_t CellInfo_choice[] = {
  {   0, "gsmCell"                     , ASN1_EXTENSION_ROOT    , dissect_gsmCell },
  {   1, "wcdmaCell"                   , ASN1_EXTENSION_ROOT    , dissect_wcdmaCell },
  {   2, "cdmaCell"                    , ASN1_EXTENSION_ROOT    , dissect_cdmaCell },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_CellInfo(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_ulp_CellInfo, CellInfo_choice,
                                 NULL);

  return offset;
}
static int dissect_cellInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_CellInfo(tvb, offset, pinfo, tree, hf_ulp_cellInfo);
}


static const value_string ulp_Status_vals[] = {
  {   0, "stale" },
  {   1, "current" },
  {   2, "unknown" },
  { 0, NULL }
};


static int
dissect_ulp_Status(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     3, NULL, NULL, TRUE, 0, NULL);

  return offset;
}
static int dissect_status(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_Status(tvb, offset, pinfo, tree, hf_ulp_status);
}


static const per_sequence_t LocationId_sequence[] = {
  { "cellInfo"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_cellInfo },
  { "status"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_status },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_LocationId(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_LocationId, LocationId_sequence);

  return offset;
}
static int dissect_locationId(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_LocationId(tvb, offset, pinfo, tree, hf_ulp_locationId);
}


static const per_sequence_t SUPLSTART_sequence[] = {
  { "sETCapabilities"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sETCapabilities },
  { "locationId"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_locationId },
  { "qoP"                         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_qoP },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLSTART(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_SUPLSTART, SUPLSTART_sequence);

  return offset;
}
static int dissect_msSUPLSTART(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SUPLSTART(tvb, offset, pinfo, tree, hf_ulp_msSUPLSTART);
}



static int
dissect_ulp_BIT_STRING_SIZE_128(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     128, 128, FALSE);

  return offset;
}
static int dissect_shortKey(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BIT_STRING_SIZE_128(tvb, offset, pinfo, tree, hf_ulp_shortKey);
}



static int
dissect_ulp_BIT_STRING_SIZE_256(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     256, 256, FALSE);

  return offset;
}
static int dissect_longKey(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BIT_STRING_SIZE_256(tvb, offset, pinfo, tree, hf_ulp_longKey);
}


static const value_string ulp_SETAuthKey_vals[] = {
  {   0, "shortKey" },
  {   1, "longKey" },
  { 0, NULL }
};

static const per_choice_t SETAuthKey_choice[] = {
  {   0, "shortKey"                    , ASN1_EXTENSION_ROOT    , dissect_shortKey },
  {   1, "longKey"                     , ASN1_EXTENSION_ROOT    , dissect_longKey },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_SETAuthKey(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_ulp_SETAuthKey, SETAuthKey_choice,
                                 NULL);

  return offset;
}
static int dissect_sETAuthKey(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SETAuthKey(tvb, offset, pinfo, tree, hf_ulp_sETAuthKey);
}



static int
dissect_ulp_KeyIdentity4(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     128, 128, FALSE);

  return offset;
}
static int dissect_keyIdentity4(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_KeyIdentity4(tvb, offset, pinfo, tree, hf_ulp_keyIdentity4);
}


static const per_sequence_t SUPLRESPONSE_sequence[] = {
  { "posMethod"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_posMethod },
  { "sLPAddress"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sLPAddress },
  { "sETAuthKey"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sETAuthKey },
  { "keyIdentity4"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_keyIdentity4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLRESPONSE(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_SUPLRESPONSE, SUPLRESPONSE_sequence);

  return offset;
}
static int dissect_msSUPLRESPONSE(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SUPLRESPONSE(tvb, offset, pinfo, tree, hf_ulp_msSUPLRESPONSE);
}



static int
dissect_ulp_INTEGER_0_167(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 167U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_gpsToe(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_167(tvb, offset, pinfo, tree, hf_ulp_gpsToe);
}



static int
dissect_ulp_INTEGER_0_31(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 31U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_nSAT(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_31(tvb, offset, pinfo, tree, hf_ulp_nSAT);
}



static int
dissect_ulp_INTEGER_0_10(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 10U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_toeLimit(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_10(tvb, offset, pinfo, tree, hf_ulp_toeLimit);
}


static const per_sequence_t SatelliteInfoElement_sequence[] = {
  { "satId"                       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_satId },
  { "iODE"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_iODE },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SatelliteInfoElement(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_SatelliteInfoElement, SatelliteInfoElement_sequence);

  return offset;
}
static int dissect_SatelliteInfo_item(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SatelliteInfoElement(tvb, offset, pinfo, tree, hf_ulp_SatelliteInfo_item);
}


static const per_sequence_t SatelliteInfo_sequence_of[1] = {
  { ""                            , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_SatelliteInfo_item },
};

static int
dissect_ulp_SatelliteInfo(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, pinfo, tree, hf_index,
                                                  ett_ulp_SatelliteInfo, SatelliteInfo_sequence_of,
                                                  1, 31);

  return offset;
}
static int dissect_satInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SatelliteInfo(tvb, offset, pinfo, tree, hf_ulp_satInfo);
}


static const per_sequence_t NavigationModel_sequence[] = {
  { "gpsWeek"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_gpsWeek },
  { "gpsToe"                      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_gpsToe },
  { "nSAT"                        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_nSAT },
  { "toeLimit"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_toeLimit },
  { "satInfo"                     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_satInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_NavigationModel(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_NavigationModel, NavigationModel_sequence);

  return offset;
}
static int dissect_navigationModelData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_NavigationModel(tvb, offset, pinfo, tree, hf_ulp_navigationModelData);
}


static const per_sequence_t RequestedAssistData_sequence[] = {
  { "almanacRequested"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_almanacRequested },
  { "utcModelRequested"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_utcModelRequested },
  { "ionosphericModelRequested"   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ionosphericModelRequested },
  { "dgpsCorrectionsRequested"    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_dgpsCorrectionsRequested },
  { "referenceLocationRequested"  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_referenceLocationRequested },
  { "referenceTimeRequested"      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_referenceTimeRequested },
  { "acquisitionAssistanceRequested", ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_acquisitionAssistanceRequested },
  { "realTimeIntegrityRequested"  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_realTimeIntegrityRequested },
  { "navigationModelRequested"    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_navigationModelRequested },
  { "navigationModelData"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_navigationModelData },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_RequestedAssistData(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_RequestedAssistData, RequestedAssistData_sequence);

  return offset;
}
static int dissect_requestedAssistData(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_RequestedAssistData(tvb, offset, pinfo, tree, hf_ulp_requestedAssistData);
}



static int
dissect_ulp_UTCTime(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_VisibleString(tvb, offset, pinfo, tree, hf_index,
                                        NO_BOUND, NO_BOUND);

  return offset;
}
static int dissect_timestamp(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_UTCTime(tvb, offset, pinfo, tree, hf_ulp_timestamp);
}


static const value_string ulp_T_latitudeSign_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_ulp_T_latitudeSign(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     2, NULL, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_latitudeSign(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_T_latitudeSign(tvb, offset, pinfo, tree, hf_ulp_latitudeSign);
}



static int
dissect_ulp_INTEGER_M8388608_8388607(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              -8388608, 8388607U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_longitude(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_M8388608_8388607(tvb, offset, pinfo, tree, hf_ulp_longitude);
}



static int
dissect_ulp_INTEGER_0_180(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 180U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_orientationMajorAxis(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_180(tvb, offset, pinfo, tree, hf_ulp_orientationMajorAxis);
}


static const per_sequence_t T_uncertainty_sequence[] = {
  { "uncertaintySemiMajor"        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_uncertaintySemiMajor },
  { "uncertaintySemiMinor"        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_uncertaintySemiMinor },
  { "orientationMajorAxis"        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_orientationMajorAxis },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_uncertainty(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_T_uncertainty, T_uncertainty_sequence);

  return offset;
}
static int dissect_uncertainty(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_T_uncertainty(tvb, offset, pinfo, tree, hf_ulp_uncertainty);
}



static int
dissect_ulp_INTEGER_0_100(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, pinfo, tree, hf_index,
                                              0U, 100U, NULL, NULL, FALSE);

  return offset;
}
static int dissect_confidence(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_INTEGER_0_100(tvb, offset, pinfo, tree, hf_ulp_confidence);
}


static const value_string ulp_T_altitudeDirection_vals[] = {
  {   0, "height" },
  {   1, "depth" },
  { 0, NULL }
};


static int
dissect_ulp_T_altitudeDirection(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     2, NULL, NULL, FALSE, 0, NULL);

  return offset;
}
static int dissect_altitudeDirection(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_T_altitudeDirection(tvb, offset, pinfo, tree, hf_ulp_altitudeDirection);
}


static const per_sequence_t AltitudeInfo_sequence[] = {
  { "altitudeDirection"           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_altitudeDirection },
  { "altitude"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_altitude },
  { "altUncertainty"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_altUncertainty },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_AltitudeInfo(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_AltitudeInfo, AltitudeInfo_sequence);

  return offset;
}
static int dissect_altitudeInfo(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_AltitudeInfo(tvb, offset, pinfo, tree, hf_ulp_altitudeInfo);
}


static const per_sequence_t PositionEstimate_sequence[] = {
  { "latitudeSign"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_latitudeSign },
  { "latitude"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_latitude },
  { "longitude"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_longitude },
  { "uncertainty"                 , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_uncertainty },
  { "confidence"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_confidence },
  { "altitudeInfo"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_altitudeInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PositionEstimate(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_PositionEstimate, PositionEstimate_sequence);

  return offset;
}
static int dissect_positionEstimate(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_PositionEstimate(tvb, offset, pinfo, tree, hf_ulp_positionEstimate);
}



static int
dissect_ulp_BIT_STRING_SIZE_9(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     9, 9, FALSE);

  return offset;
}
static int dissect_bearing(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BIT_STRING_SIZE_9(tvb, offset, pinfo, tree, hf_ulp_bearing);
}



static int
dissect_ulp_BIT_STRING_SIZE_16(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     16, 16, FALSE);

  return offset;
}
static int dissect_horspeed(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BIT_STRING_SIZE_16(tvb, offset, pinfo, tree, hf_ulp_horspeed);
}


static const per_sequence_t Horvel_sequence[] = {
  { "bearing"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_bearing },
  { "horspeed"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_horspeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Horvel(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_Horvel, Horvel_sequence);

  return offset;
}
static int dissect_horvel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_Horvel(tvb, offset, pinfo, tree, hf_ulp_horvel);
}



static int
dissect_ulp_BIT_STRING_SIZE_1(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     1, 1, FALSE);

  return offset;
}
static int dissect_verdirect(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BIT_STRING_SIZE_1(tvb, offset, pinfo, tree, hf_ulp_verdirect);
}



static int
dissect_ulp_BIT_STRING_SIZE_8(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     8, 8, FALSE);

  return offset;
}
static int dissect_verspeed(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BIT_STRING_SIZE_8(tvb, offset, pinfo, tree, hf_ulp_verspeed);
}
static int dissect_uncertspeed(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BIT_STRING_SIZE_8(tvb, offset, pinfo, tree, hf_ulp_uncertspeed);
}
static int dissect_horuncertspeed(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BIT_STRING_SIZE_8(tvb, offset, pinfo, tree, hf_ulp_horuncertspeed);
}
static int dissect_veruncertspeed(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_BIT_STRING_SIZE_8(tvb, offset, pinfo, tree, hf_ulp_veruncertspeed);
}


static const per_sequence_t Horandvervel_sequence[] = {
  { "verdirect"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_verdirect },
  { "bearing"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_bearing },
  { "horspeed"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_horspeed },
  { "verspeed"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_verspeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Horandvervel(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_Horandvervel, Horandvervel_sequence);

  return offset;
}
static int dissect_horandvervel(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_Horandvervel(tvb, offset, pinfo, tree, hf_ulp_horandvervel);
}


static const per_sequence_t Horveluncert_sequence[] = {
  { "bearing"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_bearing },
  { "horspeed"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_horspeed },
  { "uncertspeed"                 , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_uncertspeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Horveluncert(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_Horveluncert, Horveluncert_sequence);

  return offset;
}
static int dissect_horveluncert(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_Horveluncert(tvb, offset, pinfo, tree, hf_ulp_horveluncert);
}


static const per_sequence_t Horandveruncert_sequence[] = {
  { "verdirect"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_verdirect },
  { "bearing"                     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_bearing },
  { "horspeed"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_horspeed },
  { "verspeed"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_verspeed },
  { "horuncertspeed"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_horuncertspeed },
  { "veruncertspeed"              , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_veruncertspeed },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Horandveruncert(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_Horandveruncert, Horandveruncert_sequence);

  return offset;
}
static int dissect_horandveruncert(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_Horandveruncert(tvb, offset, pinfo, tree, hf_ulp_horandveruncert);
}


static const value_string ulp_Velocity_vals[] = {
  {   0, "horvel" },
  {   1, "horandvervel" },
  {   2, "horveluncert" },
  {   3, "horandveruncert" },
  { 0, NULL }
};

static const per_choice_t Velocity_choice[] = {
  {   0, "horvel"                      , ASN1_EXTENSION_ROOT    , dissect_horvel },
  {   1, "horandvervel"                , ASN1_EXTENSION_ROOT    , dissect_horandvervel },
  {   2, "horveluncert"                , ASN1_EXTENSION_ROOT    , dissect_horveluncert },
  {   3, "horandveruncert"             , ASN1_EXTENSION_ROOT    , dissect_horandveruncert },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_Velocity(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_ulp_Velocity, Velocity_choice,
                                 NULL);

  return offset;
}
static int dissect_velocity(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_Velocity(tvb, offset, pinfo, tree, hf_ulp_velocity);
}


static const per_sequence_t Position_sequence[] = {
  { "timestamp"                   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_timestamp },
  { "positionEstimate"            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_positionEstimate },
  { "velocity"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_velocity },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Position(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_Position, Position_sequence);

  return offset;
}
static int dissect_position(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_Position(tvb, offset, pinfo, tree, hf_ulp_position);
}



static int
dissect_ulp_OCTET_STRING_SIZE_1_8192(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, pinfo, tree, hf_index,
                                       1, 8192, NULL);

  return offset;
}
static int dissect_tia801payload(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_OCTET_STRING_SIZE_1_8192(tvb, offset, pinfo, tree, hf_ulp_tia801payload);
}
static int dissect_rrcPayload(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_OCTET_STRING_SIZE_1_8192(tvb, offset, pinfo, tree, hf_ulp_rrcPayload);
}
static int dissect_rrlpPayload(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_OCTET_STRING_SIZE_1_8192(tvb, offset, pinfo, tree, hf_ulp_rrlpPayload);
}


static const value_string ulp_PosPayLoad_vals[] = {
  {   0, "tia801payload" },
  {   1, "rrcPayload" },
  {   2, "rrlpPayload" },
  { 0, NULL }
};

static const per_choice_t PosPayLoad_choice[] = {
  {   0, "tia801payload"               , ASN1_EXTENSION_ROOT    , dissect_tia801payload },
  {   1, "rrcPayload"                  , ASN1_EXTENSION_ROOT    , dissect_rrcPayload },
  {   2, "rrlpPayload"                 , ASN1_EXTENSION_ROOT    , dissect_rrlpPayload },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_PosPayLoad(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_ulp_PosPayLoad, PosPayLoad_choice,
                                 NULL);

  return offset;
}
static int dissect_posPayLoad(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_PosPayLoad(tvb, offset, pinfo, tree, hf_ulp_posPayLoad);
}


static const per_sequence_t SUPLPOS_sequence[] = {
  { "posPayLoad"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_posPayLoad },
  { "velocity"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_velocity },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLPOS(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_SUPLPOS, SUPLPOS_sequence);

  return offset;
}
static int dissect_msSUPLPOS(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SUPLPOS(tvb, offset, pinfo, tree, hf_ulp_msSUPLPOS);
}
static int dissect_sUPLPOS(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SUPLPOS(tvb, offset, pinfo, tree, hf_ulp_sUPLPOS);
}



static int
dissect_ulp_Ver(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     64, 64, FALSE);

  return offset;
}
static int dissect_ver(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_Ver(tvb, offset, pinfo, tree, hf_ulp_ver);
}


static const per_sequence_t SUPLPOSINIT_sequence[] = {
  { "sETCapabilities"             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sETCapabilities },
  { "requestedAssistData"         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_requestedAssistData },
  { "locationId"                  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_locationId },
  { "position"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_position },
  { "sUPLPOS"                     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sUPLPOS },
  { "ver"                         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ver },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLPOSINIT(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_SUPLPOSINIT, SUPLPOSINIT_sequence);

  return offset;
}
static int dissect_msSUPLPOSINIT(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SUPLPOSINIT(tvb, offset, pinfo, tree, hf_ulp_msSUPLPOSINIT);
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
  { 0, NULL }
};

static guint32 StatusCode_value_map[20+0] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 100, 101};

static int
dissect_ulp_StatusCode(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, pinfo, tree, hf_index,
                                     20, NULL, NULL, TRUE, 0, StatusCode_value_map);

  return offset;
}
static int dissect_statusCode(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_StatusCode(tvb, offset, pinfo, tree, hf_ulp_statusCode);
}


static const per_sequence_t SUPLEND_sequence[] = {
  { "position"                    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_position },
  { "statusCode"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_statusCode },
  { "ver"                         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ver },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLEND(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_SUPLEND, SUPLEND_sequence);

  return offset;
}
static int dissect_msSUPLEND(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SUPLEND(tvb, offset, pinfo, tree, hf_ulp_msSUPLEND);
}



static int
dissect_ulp_SETNonce(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     128, 128, FALSE);

  return offset;
}
static int dissect_sETNonce(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SETNonce(tvb, offset, pinfo, tree, hf_ulp_sETNonce);
}



static int
dissect_ulp_KeyIdentity2(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     128, 128, FALSE);

  return offset;
}
static int dissect_keyIdentity2(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_KeyIdentity2(tvb, offset, pinfo, tree, hf_ulp_keyIdentity2);
}


static const per_sequence_t SUPLAUTHREQ_sequence[] = {
  { "sETNonce"                    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_sETNonce },
  { "keyIdentity2"                , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_keyIdentity2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLAUTHREQ(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_SUPLAUTHREQ, SUPLAUTHREQ_sequence);

  return offset;
}
static int dissect_msSUPLAUTHREQ(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SUPLAUTHREQ(tvb, offset, pinfo, tree, hf_ulp_msSUPLAUTHREQ);
}


static const value_string ulp_SPCAuthKey_vals[] = {
  {   0, "shortKey" },
  {   1, "longKey" },
  { 0, NULL }
};

static const per_choice_t SPCAuthKey_choice[] = {
  {   0, "shortKey"                    , ASN1_EXTENSION_ROOT    , dissect_shortKey },
  {   1, "longKey"                     , ASN1_EXTENSION_ROOT    , dissect_longKey },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_SPCAuthKey(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_ulp_SPCAuthKey, SPCAuthKey_choice,
                                 NULL);

  return offset;
}
static int dissect_sPCAuthKey(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SPCAuthKey(tvb, offset, pinfo, tree, hf_ulp_sPCAuthKey);
}



static int
dissect_ulp_KeyIdentity3(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, pinfo, tree, hf_index,
                                     128, 128, FALSE);

  return offset;
}
static int dissect_keyIdentity3(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_KeyIdentity3(tvb, offset, pinfo, tree, hf_ulp_keyIdentity3);
}


static const per_sequence_t SUPLAUTHRESP_sequence[] = {
  { "sPCAuthKey"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_sPCAuthKey },
  { "keyIdentity3"                , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_keyIdentity3 },
  { "statusCode"                  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_statusCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLAUTHRESP(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_SUPLAUTHRESP, SUPLAUTHRESP_sequence);

  return offset;
}
static int dissect_msSUPLAUTHRESP(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_SUPLAUTHRESP(tvb, offset, pinfo, tree, hf_ulp_msSUPLAUTHRESP);
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
  { 0, NULL }
};

static const per_choice_t UlpMessage_choice[] = {
  {   0, "msSUPLINIT"                  , ASN1_EXTENSION_ROOT    , dissect_msSUPLINIT },
  {   1, "msSUPLSTART"                 , ASN1_EXTENSION_ROOT    , dissect_msSUPLSTART },
  {   2, "msSUPLRESPONSE"              , ASN1_EXTENSION_ROOT    , dissect_msSUPLRESPONSE },
  {   3, "msSUPLPOSINIT"               , ASN1_EXTENSION_ROOT    , dissect_msSUPLPOSINIT },
  {   4, "msSUPLPOS"                   , ASN1_EXTENSION_ROOT    , dissect_msSUPLPOS },
  {   5, "msSUPLEND"                   , ASN1_EXTENSION_ROOT    , dissect_msSUPLEND },
  {   6, "msSUPLAUTHREQ"               , ASN1_EXTENSION_ROOT    , dissect_msSUPLAUTHREQ },
  {   7, "msSUPLAUTHRESP"              , ASN1_EXTENSION_ROOT    , dissect_msSUPLAUTHRESP },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_UlpMessage(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
#line 21 "ulp.cnf"

guint32 UlpMessage;

    offset = dissect_per_choice(tvb, offset, pinfo, tree, hf_index,
                                 ett_ulp_UlpMessage, UlpMessage_choice,
                                 &UlpMessage);


	if (check_col(pinfo->cinfo, COL_INFO))
	{
	    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", val_to_str(UlpMessage,ulp_UlpMessage_vals,"Unknown"));
	}


  return offset;
}
static int dissect_message(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree) {
  return dissect_ulp_UlpMessage(tvb, offset, pinfo, tree, hf_ulp_message);
}


static const per_sequence_t ULP_PDU_sequence[] = {
  { "length"                      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_length },
  { "version"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_version },
  { "sessionID"                   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_sessionID },
  { "message"                     , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_message },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_ULP_PDU(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
#line 10 "ulp.cnf"

	proto_tree_add_item(tree, proto_ulp, tvb, 0, -1, FALSE);

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

    offset = dissect_per_sequence(tvb, offset, pinfo, tree, hf_index,
                                   ett_ulp_ULP_PDU, ULP_PDU_sequence);




  return offset;
}

/*--- PDUs ---*/

static void dissect_ULP_PDU_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  per_aligment_type_callback(FALSE);
  dissect_ulp_ULP_PDU(tvb, 0, pinfo, tree, hf_ulp_ULP_PDU_PDU);
}


/*--- End of included file: packet-ulp-fn.c ---*/
#line 72 "packet-ulp-template.c"

/*--- proto_reg_handoff_ulp ---------------------------------------*/
void
proto_reg_handoff_ulp(void)
{

	ulp_handle = create_dissector_handle(dissect_ULP_PDU_PDU, proto_ulp);

	dissector_add("tcp.port", gbl_ulp_port, ulp_handle);

	/* application/oma-supl-ulp */
	dissector_add_string("media_type","application/oma-supl-ulp", ulp_handle);

}


/*--- proto_register_ulp -------------------------------------------*/
void proto_register_ulp(void) {

  /* List of fields */
  static hf_register_info hf[] = {


/*--- Included file: packet-ulp-hfarr.c ---*/
#line 1 "packet-ulp-hfarr.c"
    { &hf_ulp_ULP_PDU_PDU,
      { "ULP-PDU", "ulp.ULP_PDU",
        FT_NONE, BASE_NONE, NULL, 0,
        "ULP-PDU", HFILL }},
    { &hf_ulp_length,
      { "length", "ulp.length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ULP-PDU/length", HFILL }},
    { &hf_ulp_version,
      { "version", "ulp.version",
        FT_NONE, BASE_NONE, NULL, 0,
        "ULP-PDU/version", HFILL }},
    { &hf_ulp_sessionID,
      { "sessionID", "ulp.sessionID",
        FT_NONE, BASE_NONE, NULL, 0,
        "ULP-PDU/sessionID", HFILL }},
    { &hf_ulp_message,
      { "message", "ulp.message",
        FT_UINT32, BASE_DEC, VALS(ulp_UlpMessage_vals), 0,
        "ULP-PDU/message", HFILL }},
    { &hf_ulp_msSUPLINIT,
      { "msSUPLINIT", "ulp.msSUPLINIT",
        FT_NONE, BASE_NONE, NULL, 0,
        "UlpMessage/msSUPLINIT", HFILL }},
    { &hf_ulp_msSUPLSTART,
      { "msSUPLSTART", "ulp.msSUPLSTART",
        FT_NONE, BASE_NONE, NULL, 0,
        "UlpMessage/msSUPLSTART", HFILL }},
    { &hf_ulp_msSUPLRESPONSE,
      { "msSUPLRESPONSE", "ulp.msSUPLRESPONSE",
        FT_NONE, BASE_NONE, NULL, 0,
        "UlpMessage/msSUPLRESPONSE", HFILL }},
    { &hf_ulp_msSUPLPOSINIT,
      { "msSUPLPOSINIT", "ulp.msSUPLPOSINIT",
        FT_NONE, BASE_NONE, NULL, 0,
        "UlpMessage/msSUPLPOSINIT", HFILL }},
    { &hf_ulp_msSUPLPOS,
      { "msSUPLPOS", "ulp.msSUPLPOS",
        FT_NONE, BASE_NONE, NULL, 0,
        "UlpMessage/msSUPLPOS", HFILL }},
    { &hf_ulp_msSUPLEND,
      { "msSUPLEND", "ulp.msSUPLEND",
        FT_NONE, BASE_NONE, NULL, 0,
        "UlpMessage/msSUPLEND", HFILL }},
    { &hf_ulp_msSUPLAUTHREQ,
      { "msSUPLAUTHREQ", "ulp.msSUPLAUTHREQ",
        FT_NONE, BASE_NONE, NULL, 0,
        "UlpMessage/msSUPLAUTHREQ", HFILL }},
    { &hf_ulp_msSUPLAUTHRESP,
      { "msSUPLAUTHRESP", "ulp.msSUPLAUTHRESP",
        FT_NONE, BASE_NONE, NULL, 0,
        "UlpMessage/msSUPLAUTHRESP", HFILL }},
    { &hf_ulp_maj,
      { "maj", "ulp.maj",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Version/maj", HFILL }},
    { &hf_ulp_min,
      { "min", "ulp.min",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Version/min", HFILL }},
    { &hf_ulp_servind,
      { "servind", "ulp.servind",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Version/servind", HFILL }},
    { &hf_ulp_setSessionID,
      { "setSessionID", "ulp.setSessionID",
        FT_NONE, BASE_NONE, NULL, 0,
        "SessionID/setSessionID", HFILL }},
    { &hf_ulp_slpSessionID,
      { "slpSessionID", "ulp.slpSessionID",
        FT_NONE, BASE_NONE, NULL, 0,
        "SessionID/slpSessionID", HFILL }},
    { &hf_ulp_sessionId,
      { "sessionId", "ulp.sessionId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SetSessionID/sessionId", HFILL }},
    { &hf_ulp_setId,
      { "setId", "ulp.setId",
        FT_UINT32, BASE_DEC, VALS(ulp_SETId_vals), 0,
        "SetSessionID/setId", HFILL }},
    { &hf_ulp_msisdn,
      { "msisdn", "ulp.msisdn",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SETId/msisdn", HFILL }},
    { &hf_ulp_mdn,
      { "mdn", "ulp.mdn",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SETId/mdn", HFILL }},
    { &hf_ulp_min1,
      { "min", "ulp.min",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SETId/min", HFILL }},
    { &hf_ulp_imsi,
      { "imsi", "ulp.imsi",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SETId/imsi", HFILL }},
    { &hf_ulp_nai,
      { "nai", "ulp.nai",
        FT_STRING, BASE_NONE, NULL, 0,
        "SETId/nai", HFILL }},
    { &hf_ulp_iPAddress,
      { "iPAddress", "ulp.iPAddress",
        FT_UINT32, BASE_DEC, VALS(ulp_IPAddress_vals), 0,
        "", HFILL }},
    { &hf_ulp_sessionID1,
      { "sessionID", "ulp.sessionID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SlpSessionID/sessionID", HFILL }},
    { &hf_ulp_slpId,
      { "slpId", "ulp.slpId",
        FT_UINT32, BASE_DEC, VALS(ulp_SLPAddress_vals), 0,
        "SlpSessionID/slpId", HFILL }},
    { &hf_ulp_ipv4Address,
      { "ipv4Address", "ulp.ipv4Address",
        FT_IPv4, BASE_NONE, NULL, 0,
        "IPAddress/ipv4Address", HFILL }},
    { &hf_ulp_ipv6Address,
      { "ipv6Address", "ulp.ipv6Address",
        FT_IPv6, BASE_NONE, NULL, 0,
        "IPAddress/ipv6Address", HFILL }},
    { &hf_ulp_fQDN,
      { "fQDN", "ulp.fQDN",
        FT_STRING, BASE_NONE, NULL, 0,
        "SLPAddress/fQDN", HFILL }},
    { &hf_ulp_cellInfo,
      { "cellInfo", "ulp.cellInfo",
        FT_UINT32, BASE_DEC, VALS(ulp_CellInfo_vals), 0,
        "LocationId/cellInfo", HFILL }},
    { &hf_ulp_status,
      { "status", "ulp.status",
        FT_UINT32, BASE_DEC, VALS(ulp_Status_vals), 0,
        "LocationId/status", HFILL }},
    { &hf_ulp_gsmCell,
      { "gsmCell", "ulp.gsmCell",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellInfo/gsmCell", HFILL }},
    { &hf_ulp_wcdmaCell,
      { "wcdmaCell", "ulp.wcdmaCell",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellInfo/wcdmaCell", HFILL }},
    { &hf_ulp_cdmaCell,
      { "cdmaCell", "ulp.cdmaCell",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellInfo/cdmaCell", HFILL }},
    { &hf_ulp_timestamp,
      { "timestamp", "ulp.timestamp",
        FT_STRING, BASE_NONE, NULL, 0,
        "Position/timestamp", HFILL }},
    { &hf_ulp_positionEstimate,
      { "positionEstimate", "ulp.positionEstimate",
        FT_NONE, BASE_NONE, NULL, 0,
        "Position/positionEstimate", HFILL }},
    { &hf_ulp_velocity,
      { "velocity", "ulp.velocity",
        FT_UINT32, BASE_DEC, VALS(ulp_Velocity_vals), 0,
        "", HFILL }},
    { &hf_ulp_latitudeSign,
      { "latitudeSign", "ulp.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(ulp_T_latitudeSign_vals), 0,
        "PositionEstimate/latitudeSign", HFILL }},
    { &hf_ulp_latitude,
      { "latitude", "ulp.latitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PositionEstimate/latitude", HFILL }},
    { &hf_ulp_longitude,
      { "longitude", "ulp.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "PositionEstimate/longitude", HFILL }},
    { &hf_ulp_uncertainty,
      { "uncertainty", "ulp.uncertainty",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionEstimate/uncertainty", HFILL }},
    { &hf_ulp_uncertaintySemiMajor,
      { "uncertaintySemiMajor", "ulp.uncertaintySemiMajor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PositionEstimate/uncertainty/uncertaintySemiMajor", HFILL }},
    { &hf_ulp_uncertaintySemiMinor,
      { "uncertaintySemiMinor", "ulp.uncertaintySemiMinor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PositionEstimate/uncertainty/uncertaintySemiMinor", HFILL }},
    { &hf_ulp_orientationMajorAxis,
      { "orientationMajorAxis", "ulp.orientationMajorAxis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PositionEstimate/uncertainty/orientationMajorAxis", HFILL }},
    { &hf_ulp_confidence,
      { "confidence", "ulp.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PositionEstimate/confidence", HFILL }},
    { &hf_ulp_altitudeInfo,
      { "altitudeInfo", "ulp.altitudeInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "PositionEstimate/altitudeInfo", HFILL }},
    { &hf_ulp_altitudeDirection,
      { "altitudeDirection", "ulp.altitudeDirection",
        FT_UINT32, BASE_DEC, VALS(ulp_T_altitudeDirection_vals), 0,
        "AltitudeInfo/altitudeDirection", HFILL }},
    { &hf_ulp_altitude,
      { "altitude", "ulp.altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AltitudeInfo/altitude", HFILL }},
    { &hf_ulp_altUncertainty,
      { "altUncertainty", "ulp.altUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AltitudeInfo/altUncertainty", HFILL }},
    { &hf_ulp_refNID,
      { "refNID", "ulp.refNID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CdmaCellInformation/refNID", HFILL }},
    { &hf_ulp_refSID,
      { "refSID", "ulp.refSID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CdmaCellInformation/refSID", HFILL }},
    { &hf_ulp_refBASEID,
      { "refBASEID", "ulp.refBASEID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CdmaCellInformation/refBASEID", HFILL }},
    { &hf_ulp_refBASELAT,
      { "refBASELAT", "ulp.refBASELAT",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CdmaCellInformation/refBASELAT", HFILL }},
    { &hf_ulp_reBASELONG,
      { "reBASELONG", "ulp.reBASELONG",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CdmaCellInformation/reBASELONG", HFILL }},
    { &hf_ulp_refREFPN,
      { "refREFPN", "ulp.refREFPN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CdmaCellInformation/refREFPN", HFILL }},
    { &hf_ulp_refWeekNumber,
      { "refWeekNumber", "ulp.refWeekNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CdmaCellInformation/refWeekNumber", HFILL }},
    { &hf_ulp_refSeconds,
      { "refSeconds", "ulp.refSeconds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CdmaCellInformation/refSeconds", HFILL }},
    { &hf_ulp_refMCC,
      { "refMCC", "ulp.refMCC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ulp_refMNC,
      { "refMNC", "ulp.refMNC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ulp_refLAC,
      { "refLAC", "ulp.refLAC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GsmCellInformation/refLAC", HFILL }},
    { &hf_ulp_refCI,
      { "refCI", "ulp.refCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GsmCellInformation/refCI", HFILL }},
    { &hf_ulp_nMR,
      { "nMR", "ulp.nMR",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GsmCellInformation/nMR", HFILL }},
    { &hf_ulp_tA,
      { "tA", "ulp.tA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GsmCellInformation/tA", HFILL }},
    { &hf_ulp_refUC,
      { "refUC", "ulp.refUC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "WcdmaCellInformation/refUC", HFILL }},
    { &hf_ulp_frequencyInfo,
      { "frequencyInfo", "ulp.frequencyInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ulp_primaryScramblingCode,
      { "primaryScramblingCode", "ulp.primaryScramblingCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ulp_measuredResultsList,
      { "measuredResultsList", "ulp.measuredResultsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "WcdmaCellInformation/measuredResultsList", HFILL }},
    { &hf_ulp_modeSpecificInfo,
      { "modeSpecificInfo", "ulp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ulp_T_modeSpecificInfo_vals), 0,
        "FrequencyInfo/modeSpecificInfo", HFILL }},
    { &hf_ulp_fdd,
      { "fdd", "ulp.fdd",
        FT_NONE, BASE_NONE, NULL, 0,
        "FrequencyInfo/modeSpecificInfo/fdd", HFILL }},
    { &hf_ulp_tdd,
      { "tdd", "ulp.tdd",
        FT_NONE, BASE_NONE, NULL, 0,
        "FrequencyInfo/modeSpecificInfo/tdd", HFILL }},
    { &hf_ulp_uarfcn_UL,
      { "uarfcn-UL", "ulp.uarfcn_UL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FrequencyInfoFDD/uarfcn-UL", HFILL }},
    { &hf_ulp_uarfcn_DL,
      { "uarfcn-DL", "ulp.uarfcn_DL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FrequencyInfoFDD/uarfcn-DL", HFILL }},
    { &hf_ulp_uarfcn_Nt,
      { "uarfcn-Nt", "ulp.uarfcn_Nt",
        FT_UINT32, BASE_DEC, NULL, 0,
        "FrequencyInfoTDD/uarfcn-Nt", HFILL }},
    { &hf_ulp_NMR_item,
      { "Item", "ulp.NMR_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "NMR/_item", HFILL }},
    { &hf_ulp_aRFCN,
      { "aRFCN", "ulp.aRFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NMRelement/aRFCN", HFILL }},
    { &hf_ulp_bSIC,
      { "bSIC", "ulp.bSIC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NMRelement/bSIC", HFILL }},
    { &hf_ulp_rxLev,
      { "rxLev", "ulp.rxLev",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NMRelement/rxLev", HFILL }},
    { &hf_ulp_MeasuredResultsList_item,
      { "Item", "ulp.MeasuredResultsList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MeasuredResultsList/_item", HFILL }},
    { &hf_ulp_utra_CarrierRSSI,
      { "utra-CarrierRSSI", "ulp.utra_CarrierRSSI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasuredResults/utra-CarrierRSSI", HFILL }},
    { &hf_ulp_cellMeasuredResultsList,
      { "cellMeasuredResultsList", "ulp.cellMeasuredResultsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MeasuredResults/cellMeasuredResultsList", HFILL }},
    { &hf_ulp_CellMeasuredResultsList_item,
      { "Item", "ulp.CellMeasuredResultsList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellMeasuredResultsList/_item", HFILL }},
    { &hf_ulp_cellIdentity,
      { "cellIdentity", "ulp.cellIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellMeasuredResults/cellIdentity", HFILL }},
    { &hf_ulp_modeSpecificInfo1,
      { "modeSpecificInfo", "ulp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ulp_T_modeSpecificInfo1_vals), 0,
        "CellMeasuredResults/modeSpecificInfo", HFILL }},
    { &hf_ulp_fdd1,
      { "fdd", "ulp.fdd",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellMeasuredResults/modeSpecificInfo/fdd", HFILL }},
    { &hf_ulp_primaryCPICH_Info,
      { "primaryCPICH-Info", "ulp.primaryCPICH_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellMeasuredResults/modeSpecificInfo/fdd/primaryCPICH-Info", HFILL }},
    { &hf_ulp_cpich_Ec_N0,
      { "cpich-Ec-N0", "ulp.cpich_Ec_N0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellMeasuredResults/modeSpecificInfo/fdd/cpich-Ec-N0", HFILL }},
    { &hf_ulp_cpich_RSCP,
      { "cpich-RSCP", "ulp.cpich_RSCP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellMeasuredResults/modeSpecificInfo/fdd/cpich-RSCP", HFILL }},
    { &hf_ulp_pathloss,
      { "pathloss", "ulp.pathloss",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ulp_tdd1,
      { "tdd", "ulp.tdd",
        FT_NONE, BASE_NONE, NULL, 0,
        "CellMeasuredResults/modeSpecificInfo/tdd", HFILL }},
    { &hf_ulp_cellParametersID,
      { "cellParametersID", "ulp.cellParametersID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellMeasuredResults/modeSpecificInfo/tdd/cellParametersID", HFILL }},
    { &hf_ulp_proposedTGSN,
      { "proposedTGSN", "ulp.proposedTGSN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellMeasuredResults/modeSpecificInfo/tdd/proposedTGSN", HFILL }},
    { &hf_ulp_primaryCCPCH_RSCP,
      { "primaryCCPCH-RSCP", "ulp.primaryCCPCH_RSCP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellMeasuredResults/modeSpecificInfo/tdd/primaryCCPCH-RSCP", HFILL }},
    { &hf_ulp_timeslotISCP_List,
      { "timeslotISCP-List", "ulp.timeslotISCP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CellMeasuredResults/modeSpecificInfo/tdd/timeslotISCP-List", HFILL }},
    { &hf_ulp_TimeslotISCP_List_item,
      { "Item", "ulp.TimeslotISCP_List_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeslotISCP-List/_item", HFILL }},
    { &hf_ulp_horacc,
      { "horacc", "ulp.horacc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoP/horacc", HFILL }},
    { &hf_ulp_veracc,
      { "veracc", "ulp.veracc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoP/veracc", HFILL }},
    { &hf_ulp_maxLocAge,
      { "maxLocAge", "ulp.maxLocAge",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoP/maxLocAge", HFILL }},
    { &hf_ulp_delay,
      { "delay", "ulp.delay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "QoP/delay", HFILL }},
    { &hf_ulp_horvel,
      { "horvel", "ulp.horvel",
        FT_NONE, BASE_NONE, NULL, 0,
        "Velocity/horvel", HFILL }},
    { &hf_ulp_horandvervel,
      { "horandvervel", "ulp.horandvervel",
        FT_NONE, BASE_NONE, NULL, 0,
        "Velocity/horandvervel", HFILL }},
    { &hf_ulp_horveluncert,
      { "horveluncert", "ulp.horveluncert",
        FT_NONE, BASE_NONE, NULL, 0,
        "Velocity/horveluncert", HFILL }},
    { &hf_ulp_horandveruncert,
      { "horandveruncert", "ulp.horandveruncert",
        FT_NONE, BASE_NONE, NULL, 0,
        "Velocity/horandveruncert", HFILL }},
    { &hf_ulp_bearing,
      { "bearing", "ulp.bearing",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ulp_horspeed,
      { "horspeed", "ulp.horspeed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ulp_verdirect,
      { "verdirect", "ulp.verdirect",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ulp_verspeed,
      { "verspeed", "ulp.verspeed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ulp_uncertspeed,
      { "uncertspeed", "ulp.uncertspeed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Horveluncert/uncertspeed", HFILL }},
    { &hf_ulp_horuncertspeed,
      { "horuncertspeed", "ulp.horuncertspeed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Horandveruncert/horuncertspeed", HFILL }},
    { &hf_ulp_veruncertspeed,
      { "veruncertspeed", "ulp.veruncertspeed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Horandveruncert/veruncertspeed", HFILL }},
    { &hf_ulp_sETNonce,
      { "sETNonce", "ulp.sETNonce",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SUPLAUTHREQ/sETNonce", HFILL }},
    { &hf_ulp_keyIdentity2,
      { "keyIdentity2", "ulp.keyIdentity2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SUPLAUTHREQ/keyIdentity2", HFILL }},
    { &hf_ulp_sPCAuthKey,
      { "sPCAuthKey", "ulp.sPCAuthKey",
        FT_UINT32, BASE_DEC, VALS(ulp_SPCAuthKey_vals), 0,
        "SUPLAUTHRESP/sPCAuthKey", HFILL }},
    { &hf_ulp_keyIdentity3,
      { "keyIdentity3", "ulp.keyIdentity3",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SUPLAUTHRESP/keyIdentity3", HFILL }},
    { &hf_ulp_statusCode,
      { "statusCode", "ulp.statusCode",
        FT_UINT32, BASE_DEC, VALS(ulp_StatusCode_vals), 0,
        "", HFILL }},
    { &hf_ulp_shortKey,
      { "shortKey", "ulp.shortKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ulp_longKey,
      { "longKey", "ulp.longKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ulp_position,
      { "position", "ulp.position",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ulp_ver,
      { "ver", "ulp.ver",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ulp_posMethod,
      { "posMethod", "ulp.posMethod",
        FT_UINT32, BASE_DEC, VALS(ulp_PosMethod_vals), 0,
        "", HFILL }},
    { &hf_ulp_notification,
      { "notification", "ulp.notification",
        FT_NONE, BASE_NONE, NULL, 0,
        "SUPLINIT/notification", HFILL }},
    { &hf_ulp_sLPAddress,
      { "sLPAddress", "ulp.sLPAddress",
        FT_UINT32, BASE_DEC, VALS(ulp_SLPAddress_vals), 0,
        "", HFILL }},
    { &hf_ulp_qoP,
      { "qoP", "ulp.qoP",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ulp_sLPMode,
      { "sLPMode", "ulp.sLPMode",
        FT_UINT32, BASE_DEC, VALS(ulp_SLPMode_vals), 0,
        "SUPLINIT/sLPMode", HFILL }},
    { &hf_ulp_mAC,
      { "mAC", "ulp.mAC",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SUPLINIT/mAC", HFILL }},
    { &hf_ulp_keyIdentity,
      { "keyIdentity", "ulp.keyIdentity",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SUPLINIT/keyIdentity", HFILL }},
    { &hf_ulp_notificationType,
      { "notificationType", "ulp.notificationType",
        FT_UINT32, BASE_DEC, VALS(ulp_NotificationType_vals), 0,
        "Notification/notificationType", HFILL }},
    { &hf_ulp_encodingType,
      { "encodingType", "ulp.encodingType",
        FT_UINT32, BASE_DEC, VALS(ulp_EncodingType_vals), 0,
        "Notification/encodingType", HFILL }},
    { &hf_ulp_requestorId,
      { "requestorId", "ulp.requestorId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Notification/requestorId", HFILL }},
    { &hf_ulp_requestorIdType,
      { "requestorIdType", "ulp.requestorIdType",
        FT_UINT32, BASE_DEC, VALS(ulp_FormatIndicator_vals), 0,
        "Notification/requestorIdType", HFILL }},
    { &hf_ulp_clientName,
      { "clientName", "ulp.clientName",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Notification/clientName", HFILL }},
    { &hf_ulp_clientNameType,
      { "clientNameType", "ulp.clientNameType",
        FT_UINT32, BASE_DEC, VALS(ulp_FormatIndicator_vals), 0,
        "Notification/clientNameType", HFILL }},
    { &hf_ulp_posPayLoad,
      { "posPayLoad", "ulp.posPayLoad",
        FT_UINT32, BASE_DEC, VALS(ulp_PosPayLoad_vals), 0,
        "SUPLPOS/posPayLoad", HFILL }},
    { &hf_ulp_tia801payload,
      { "tia801payload", "ulp.tia801payload",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PosPayLoad/tia801payload", HFILL }},
    { &hf_ulp_rrcPayload,
      { "rrcPayload", "ulp.rrcPayload",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PosPayLoad/rrcPayload", HFILL }},
    { &hf_ulp_rrlpPayload,
      { "rrlpPayload", "ulp.rrlpPayload",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PosPayLoad/rrlpPayload", HFILL }},
    { &hf_ulp_sETCapabilities,
      { "sETCapabilities", "ulp.sETCapabilities",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ulp_requestedAssistData,
      { "requestedAssistData", "ulp.requestedAssistData",
        FT_NONE, BASE_NONE, NULL, 0,
        "SUPLPOSINIT/requestedAssistData", HFILL }},
    { &hf_ulp_locationId,
      { "locationId", "ulp.locationId",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ulp_sUPLPOS,
      { "sUPLPOS", "ulp.sUPLPOS",
        FT_NONE, BASE_NONE, NULL, 0,
        "SUPLPOSINIT/sUPLPOS", HFILL }},
    { &hf_ulp_almanacRequested,
      { "almanacRequested", "ulp.almanacRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "RequestedAssistData/almanacRequested", HFILL }},
    { &hf_ulp_utcModelRequested,
      { "utcModelRequested", "ulp.utcModelRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "RequestedAssistData/utcModelRequested", HFILL }},
    { &hf_ulp_ionosphericModelRequested,
      { "ionosphericModelRequested", "ulp.ionosphericModelRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "RequestedAssistData/ionosphericModelRequested", HFILL }},
    { &hf_ulp_dgpsCorrectionsRequested,
      { "dgpsCorrectionsRequested", "ulp.dgpsCorrectionsRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "RequestedAssistData/dgpsCorrectionsRequested", HFILL }},
    { &hf_ulp_referenceLocationRequested,
      { "referenceLocationRequested", "ulp.referenceLocationRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "RequestedAssistData/referenceLocationRequested", HFILL }},
    { &hf_ulp_referenceTimeRequested,
      { "referenceTimeRequested", "ulp.referenceTimeRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "RequestedAssistData/referenceTimeRequested", HFILL }},
    { &hf_ulp_acquisitionAssistanceRequested,
      { "acquisitionAssistanceRequested", "ulp.acquisitionAssistanceRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "RequestedAssistData/acquisitionAssistanceRequested", HFILL }},
    { &hf_ulp_realTimeIntegrityRequested,
      { "realTimeIntegrityRequested", "ulp.realTimeIntegrityRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "RequestedAssistData/realTimeIntegrityRequested", HFILL }},
    { &hf_ulp_navigationModelRequested,
      { "navigationModelRequested", "ulp.navigationModelRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "RequestedAssistData/navigationModelRequested", HFILL }},
    { &hf_ulp_navigationModelData,
      { "navigationModelData", "ulp.navigationModelData",
        FT_NONE, BASE_NONE, NULL, 0,
        "RequestedAssistData/navigationModelData", HFILL }},
    { &hf_ulp_gpsWeek,
      { "gpsWeek", "ulp.gpsWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NavigationModel/gpsWeek", HFILL }},
    { &hf_ulp_gpsToe,
      { "gpsToe", "ulp.gpsToe",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NavigationModel/gpsToe", HFILL }},
    { &hf_ulp_nSAT,
      { "nSAT", "ulp.nSAT",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NavigationModel/nSAT", HFILL }},
    { &hf_ulp_toeLimit,
      { "toeLimit", "ulp.toeLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NavigationModel/toeLimit", HFILL }},
    { &hf_ulp_satInfo,
      { "satInfo", "ulp.satInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NavigationModel/satInfo", HFILL }},
    { &hf_ulp_SatelliteInfo_item,
      { "Item", "ulp.SatelliteInfo_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "SatelliteInfo/_item", HFILL }},
    { &hf_ulp_satId,
      { "satId", "ulp.satId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SatelliteInfoElement/satId", HFILL }},
    { &hf_ulp_iODE,
      { "iODE", "ulp.iODE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SatelliteInfoElement/iODE", HFILL }},
    { &hf_ulp_sETAuthKey,
      { "sETAuthKey", "ulp.sETAuthKey",
        FT_UINT32, BASE_DEC, VALS(ulp_SETAuthKey_vals), 0,
        "SUPLRESPONSE/sETAuthKey", HFILL }},
    { &hf_ulp_keyIdentity4,
      { "keyIdentity4", "ulp.keyIdentity4",
        FT_BYTES, BASE_HEX, NULL, 0,
        "SUPLRESPONSE/keyIdentity4", HFILL }},
    { &hf_ulp_posTechnology,
      { "posTechnology", "ulp.posTechnology",
        FT_NONE, BASE_NONE, NULL, 0,
        "SETCapabilities/posTechnology", HFILL }},
    { &hf_ulp_prefMethod,
      { "prefMethod", "ulp.prefMethod",
        FT_UINT32, BASE_DEC, VALS(ulp_PrefMethod_vals), 0,
        "SETCapabilities/prefMethod", HFILL }},
    { &hf_ulp_posProtocol,
      { "posProtocol", "ulp.posProtocol",
        FT_NONE, BASE_NONE, NULL, 0,
        "SETCapabilities/posProtocol", HFILL }},
    { &hf_ulp_agpsSETassisted,
      { "agpsSETassisted", "ulp.agpsSETassisted",
        FT_BOOLEAN, 8, NULL, 0,
        "PosTechnology/agpsSETassisted", HFILL }},
    { &hf_ulp_agpsSETBased,
      { "agpsSETBased", "ulp.agpsSETBased",
        FT_BOOLEAN, 8, NULL, 0,
        "PosTechnology/agpsSETBased", HFILL }},
    { &hf_ulp_autonomousGPS,
      { "autonomousGPS", "ulp.autonomousGPS",
        FT_BOOLEAN, 8, NULL, 0,
        "PosTechnology/autonomousGPS", HFILL }},
    { &hf_ulp_aFLT,
      { "aFLT", "ulp.aFLT",
        FT_BOOLEAN, 8, NULL, 0,
        "PosTechnology/aFLT", HFILL }},
    { &hf_ulp_eCID,
      { "eCID", "ulp.eCID",
        FT_BOOLEAN, 8, NULL, 0,
        "PosTechnology/eCID", HFILL }},
    { &hf_ulp_eOTD,
      { "eOTD", "ulp.eOTD",
        FT_BOOLEAN, 8, NULL, 0,
        "PosTechnology/eOTD", HFILL }},
    { &hf_ulp_oTDOA,
      { "oTDOA", "ulp.oTDOA",
        FT_BOOLEAN, 8, NULL, 0,
        "PosTechnology/oTDOA", HFILL }},
    { &hf_ulp_tia801,
      { "tia801", "ulp.tia801",
        FT_BOOLEAN, 8, NULL, 0,
        "PosProtocol/tia801", HFILL }},
    { &hf_ulp_rrlp,
      { "rrlp", "ulp.rrlp",
        FT_BOOLEAN, 8, NULL, 0,
        "PosProtocol/rrlp", HFILL }},
    { &hf_ulp_rrc,
      { "rrc", "ulp.rrc",
        FT_BOOLEAN, 8, NULL, 0,
        "PosProtocol/rrc", HFILL }},

/*--- End of included file: packet-ulp-hfarr.c ---*/
#line 95 "packet-ulp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_ulp,

/*--- Included file: packet-ulp-ettarr.c ---*/
#line 1 "packet-ulp-ettarr.c"
    &ett_ulp_ULP_PDU,
    &ett_ulp_UlpMessage,
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
    &ett_ulp_FrequencyInfo,
    &ett_ulp_T_modeSpecificInfo,
    &ett_ulp_FrequencyInfoFDD,
    &ett_ulp_FrequencyInfoTDD,
    &ett_ulp_NMR,
    &ett_ulp_NMRelement,
    &ett_ulp_MeasuredResultsList,
    &ett_ulp_MeasuredResults,
    &ett_ulp_CellMeasuredResultsList,
    &ett_ulp_CellMeasuredResults,
    &ett_ulp_T_modeSpecificInfo1,
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
    &ett_ulp_SUPLAUTHREQ,
    &ett_ulp_SUPLAUTHRESP,
    &ett_ulp_SPCAuthKey,
    &ett_ulp_SUPLEND,
    &ett_ulp_SUPLINIT,
    &ett_ulp_Notification,
    &ett_ulp_SUPLPOS,
    &ett_ulp_PosPayLoad,
    &ett_ulp_SUPLPOSINIT,
    &ett_ulp_RequestedAssistData,
    &ett_ulp_NavigationModel,
    &ett_ulp_SatelliteInfo,
    &ett_ulp_SatelliteInfoElement,
    &ett_ulp_SUPLRESPONSE,
    &ett_ulp_SETAuthKey,
    &ett_ulp_SUPLSTART,
    &ett_ulp_SETCapabilities,
    &ett_ulp_PosTechnology,
    &ett_ulp_PosProtocol,

/*--- End of included file: packet-ulp-ettarr.c ---*/
#line 101 "packet-ulp-template.c"
  };

  module_t *ulp_module;


  /* Register protocol */
  proto_ulp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ulp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


  /* Register a configuration option for port */
  ulp_module = prefs_register_protocol(proto_ulp,proto_reg_handoff_ulp);
  prefs_register_uint_preference(ulp_module, "tcp.port",
								   "ULP TCP Port",
								   "Set the TCP port for Ulp messages(IANA registerd port is 7275)",
								   10,
								   &gbl_ulp_port);
 
}




