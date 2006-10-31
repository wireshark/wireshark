/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* ./packet-ulp.c                                                             */
/* ../../tools/asn2wrs.py -e -p ulp -c ulp.cnf -s packet-ulp-template ULP.asn */

/* Input file: packet-ulp-template.c */

#line 1 "packet-ulp-template.c"
/* packet-ulp.c
 * Routines for OMA UserPlane Location Protocol packet dissection
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
#include <epan/emem.h>
#include "packet-tcp.h"

#define PNAME  "OMA UserPlane Location Protocol"
#define PSNAME "ULP"
#define PFNAME "ulp"

static dissector_handle_t ulp_handle=NULL;
static dissector_handle_t rrlp_handle;

/* IANA Registered Ports  
 * oma-ulp         7275/tcp    OMA UserPlane Location
 * oma-ulp         7275/udp    OMA UserPlane Location
 */
guint gbl_ulp_port = 7275;

/* Initialize the protocol and registered fields */
static int proto_ulp = -1;


#define ULP_HEADER_SIZE 2

gboolean ulp_desegment = TRUE;


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
static int hf_ulp_rrlpPayload = -1;               /* RRLPPayload */
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
#line 70 "packet-ulp-template.c"

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
#line 74 "packet-ulp-template.c"

/* Include constants */

/*--- Included file: packet-ulp-val.h ---*/
#line 1 "packet-ulp-val.h"
#define maxCellMeas                    32
#define maxFreq                        8
#define maxTS                          14
#define maxReqLength                   50
#define maxClientLength                50

/*--- End of included file: packet-ulp-val.h ---*/
#line 77 "packet-ulp-template.c"



/*--- Included file: packet-ulp-fn.c ---*/
#line 1 "packet-ulp-fn.c"


static int
dissect_ulp_INTEGER_0_65535(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 65535U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_INTEGER_0_255(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 255U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Version_sequence[] = {
  { &hf_ulp_maj             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_min             , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { &hf_ulp_servind         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Version(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Version, Version_sequence);

  return offset;
}



static int
dissect_ulp_OCTET_STRING_SIZE_8(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       8, 8, NULL);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_34(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     34, 34, FALSE, NULL);

  return offset;
}



static int
dissect_ulp_IA5String_SIZE_1_1000(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          1, 1000);

  return offset;
}



static int
dissect_ulp_IPv4Address(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, NULL);

  return offset;
}



static int
dissect_ulp_IPv6Address(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       16, 16, NULL);

  return offset;
}


static const value_string ulp_IPAddress_vals[] = {
  {   0, "ipv4Address" },
  {   1, "ipv6Address" },
  { 0, NULL }
};

static const per_choice_t IPAddress_choice[] = {
  {   0, &hf_ulp_ipv4Address     , ASN1_NO_EXTENSIONS     , dissect_ulp_IPv4Address },
  {   1, &hf_ulp_ipv6Address     , ASN1_NO_EXTENSIONS     , dissect_ulp_IPv6Address },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_IPAddress(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_IPAddress, IPAddress_choice,
                                 NULL);

  return offset;
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
  {   0, &hf_ulp_msisdn          , ASN1_EXTENSION_ROOT    , dissect_ulp_OCTET_STRING_SIZE_8 },
  {   1, &hf_ulp_mdn             , ASN1_EXTENSION_ROOT    , dissect_ulp_OCTET_STRING_SIZE_8 },
  {   2, &hf_ulp_min1            , ASN1_EXTENSION_ROOT    , dissect_ulp_BIT_STRING_SIZE_34 },
  {   3, &hf_ulp_imsi            , ASN1_EXTENSION_ROOT    , dissect_ulp_OCTET_STRING_SIZE_8 },
  {   4, &hf_ulp_nai             , ASN1_EXTENSION_ROOT    , dissect_ulp_IA5String_SIZE_1_1000 },
  {   5, &hf_ulp_iPAddress       , ASN1_EXTENSION_ROOT    , dissect_ulp_IPAddress },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_SETId(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
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
dissect_ulp_SetSessionID(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SetSessionID, SetSessionID_sequence);

  return offset;
}



static int
dissect_ulp_OCTET_STRING_SIZE_4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       4, 4, NULL);

  return offset;
}



static int
dissect_ulp_FQDN(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_VisibleString(tvb, offset, actx, tree, hf_index,
                                          1, 255);

  return offset;
}


static const value_string ulp_SLPAddress_vals[] = {
  {   0, "iPAddress" },
  {   1, "fQDN" },
  { 0, NULL }
};

static const per_choice_t SLPAddress_choice[] = {
  {   0, &hf_ulp_iPAddress       , ASN1_EXTENSION_ROOT    , dissect_ulp_IPAddress },
  {   1, &hf_ulp_fQDN            , ASN1_EXTENSION_ROOT    , dissect_ulp_FQDN },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_SLPAddress(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_SLPAddress, SLPAddress_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SlpSessionID_sequence[] = {
  { &hf_ulp_sessionID1      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_OCTET_STRING_SIZE_4 },
  { &hf_ulp_slpId           , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_SLPAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SlpSessionID(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
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
dissect_ulp_SessionID(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
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
  {   5, "aFLT" },
  {   6, "eCID" },
  {   7, "eOTD" },
  {   8, "oTDOA" },
  {   9, "noPosition" },
  { 0, NULL }
};


static int
dissect_ulp_PosMethod(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     10, NULL, TRUE, 0, NULL);

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
dissect_ulp_NotificationType(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     5, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string ulp_EncodingType_vals[] = {
  {   0, "ucs2" },
  {   1, "gsmDefault" },
  {   2, "utf8" },
  { 0, NULL }
};


static int
dissect_ulp_EncodingType(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ulp_OCTET_STRING_SIZE_1_maxReqLength(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, maxReqLength, NULL);

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
  { 0, NULL }
};


static int
dissect_ulp_FormatIndicator(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     7, NULL, TRUE, 0, NULL);

  return offset;
}



static int
dissect_ulp_OCTET_STRING_SIZE_1_maxClientLength(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, maxClientLength, NULL);

  return offset;
}


static const per_sequence_t Notification_sequence[] = {
  { &hf_ulp_notificationType, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_NotificationType },
  { &hf_ulp_encodingType    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_EncodingType },
  { &hf_ulp_requestorId     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_OCTET_STRING_SIZE_1_maxReqLength },
  { &hf_ulp_requestorIdType , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_FormatIndicator },
  { &hf_ulp_clientName      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_OCTET_STRING_SIZE_1_maxClientLength },
  { &hf_ulp_clientNameType  , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_FormatIndicator },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Notification(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Notification, Notification_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_127(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_INTEGER_0_7(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 7U, NULL, FALSE);

  return offset;
}


static const per_sequence_t QoP_sequence[] = {
  { &hf_ulp_horacc          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_127 },
  { &hf_ulp_veracc          , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_127 },
  { &hf_ulp_maxLocAge       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_delay           , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_7 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_QoP(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
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
dissect_ulp_SLPMode(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ulp_MAC(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL);

  return offset;
}



static int
dissect_ulp_KeyIdentity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE, NULL);

  return offset;
}


static const per_sequence_t SUPLINIT_sequence[] = {
  { &hf_ulp_posMethod       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PosMethod },
  { &hf_ulp_notification    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Notification },
  { &hf_ulp_sLPAddress      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SLPAddress },
  { &hf_ulp_qoP             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_QoP },
  { &hf_ulp_sLPMode         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SLPMode },
  { &hf_ulp_mAC             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_MAC },
  { &hf_ulp_keyIdentity     , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_KeyIdentity },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLINIT(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLINIT, SUPLINIT_sequence);

  return offset;
}



static int
dissect_ulp_BOOLEAN(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_boolean(tvb, offset, actx, tree, hf_index, NULL);

  return offset;
}


static const per_sequence_t PosTechnology_sequence[] = {
  { &hf_ulp_agpsSETassisted , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_agpsSETBased    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_autonomousGPS   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_aFLT            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_eCID            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_eOTD            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_oTDOA           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PosTechnology(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
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
dissect_ulp_PrefMethod(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t PosProtocol_sequence[] = {
  { &hf_ulp_tia801          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_rrlp            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { &hf_ulp_rrc             , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BOOLEAN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PosProtocol(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_PosProtocol, PosProtocol_sequence);

  return offset;
}


static const per_sequence_t SETCapabilities_sequence[] = {
  { &hf_ulp_posTechnology   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PosTechnology },
  { &hf_ulp_prefMethod      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PrefMethod },
  { &hf_ulp_posProtocol     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PosProtocol },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SETCapabilities(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SETCapabilities, SETCapabilities_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_999(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 999U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_INTEGER_0_1023(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 1023U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_INTEGER_0_63(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 63U, NULL, FALSE);

  return offset;
}


static const per_sequence_t NMRelement_sequence[] = {
  { &hf_ulp_aRFCN           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_1023 },
  { &hf_ulp_bSIC            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_63 },
  { &hf_ulp_rxLev           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_63 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_NMRelement(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_NMRelement, NMRelement_sequence);

  return offset;
}


static const per_sequence_t NMR_sequence_of[1] = {
  { &hf_ulp_NMR_item        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_NMRelement },
};

static int
dissect_ulp_NMR(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_NMR, NMR_sequence_of,
                                                  1, 15);

  return offset;
}


static const per_sequence_t GsmCellInformation_sequence[] = {
  { &hf_ulp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refLAC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_refCI           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_nMR             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_NMR },
  { &hf_ulp_tA              , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_GsmCellInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_GsmCellInformation, GsmCellInformation_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_268435455(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 268435455U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_UARFCN(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 16383U, NULL, FALSE);

  return offset;
}


static const per_sequence_t FrequencyInfoFDD_sequence[] = {
  { &hf_ulp_uarfcn_UL       , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_UARFCN },
  { &hf_ulp_uarfcn_DL       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_UARFCN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_FrequencyInfoFDD(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_FrequencyInfoFDD, FrequencyInfoFDD_sequence);

  return offset;
}


static const per_sequence_t FrequencyInfoTDD_sequence[] = {
  { &hf_ulp_uarfcn_Nt       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_UARFCN },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_FrequencyInfoTDD(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_FrequencyInfoTDD, FrequencyInfoTDD_sequence);

  return offset;
}


static const value_string ulp_T_modeSpecificInfo_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo_choice[] = {
  {   0, &hf_ulp_fdd             , ASN1_EXTENSION_ROOT    , dissect_ulp_FrequencyInfoFDD },
  {   1, &hf_ulp_tdd             , ASN1_EXTENSION_ROOT    , dissect_ulp_FrequencyInfoTDD },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_T_modeSpecificInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_T_modeSpecificInfo, T_modeSpecificInfo_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t FrequencyInfo_sequence[] = {
  { &hf_ulp_modeSpecificInfo, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_modeSpecificInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_FrequencyInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_FrequencyInfo, FrequencyInfo_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_511(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 511U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_UTRA_CarrierRSSI(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t PrimaryCPICH_Info_sequence[] = {
  { &hf_ulp_primaryScramblingCode, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_511 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_PrimaryCPICH_Info(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_PrimaryCPICH_Info, PrimaryCPICH_Info_sequence);

  return offset;
}



static int
dissect_ulp_CPICH_Ec_N0(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 63U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_CPICH_RSCP(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_Pathloss(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              46U, 173U, NULL, FALSE);

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
dissect_ulp_T_fdd(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_fdd, T_fdd_sequence);

  return offset;
}



static int
dissect_ulp_CellParametersID(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_TGSN(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 14U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_PrimaryCCPCH_RSCP(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 127U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_TimeslotISCP(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 127U, NULL, FALSE);

  return offset;
}


static const per_sequence_t TimeslotISCP_List_sequence_of[1] = {
  { &hf_ulp_TimeslotISCP_List_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_TimeslotISCP },
};

static int
dissect_ulp_TimeslotISCP_List(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_TimeslotISCP_List, TimeslotISCP_List_sequence_of,
                                                  1, maxTS);

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
dissect_ulp_T_tdd(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_tdd, T_tdd_sequence);

  return offset;
}


static const value_string ulp_T_modeSpecificInfo1_vals[] = {
  {   0, "fdd" },
  {   1, "tdd" },
  { 0, NULL }
};

static const per_choice_t T_modeSpecificInfo1_choice[] = {
  {   0, &hf_ulp_fdd1            , ASN1_NO_EXTENSIONS     , dissect_ulp_T_fdd },
  {   1, &hf_ulp_tdd1            , ASN1_NO_EXTENSIONS     , dissect_ulp_T_tdd },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_T_modeSpecificInfo1(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_T_modeSpecificInfo1, T_modeSpecificInfo1_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CellMeasuredResults_sequence[] = {
  { &hf_ulp_cellIdentity    , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_268435455 },
  { &hf_ulp_modeSpecificInfo1, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_T_modeSpecificInfo1 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_CellMeasuredResults(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_CellMeasuredResults, CellMeasuredResults_sequence);

  return offset;
}


static const per_sequence_t CellMeasuredResultsList_sequence_of[1] = {
  { &hf_ulp_CellMeasuredResultsList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_CellMeasuredResults },
};

static int
dissect_ulp_CellMeasuredResultsList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_CellMeasuredResultsList, CellMeasuredResultsList_sequence_of,
                                                  1, maxCellMeas);

  return offset;
}


static const per_sequence_t MeasuredResults_sequence[] = {
  { &hf_ulp_frequencyInfo   , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_FrequencyInfo },
  { &hf_ulp_utra_CarrierRSSI, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_UTRA_CarrierRSSI },
  { &hf_ulp_cellMeasuredResultsList, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_ulp_CellMeasuredResultsList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_MeasuredResults(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_MeasuredResults, MeasuredResults_sequence);

  return offset;
}


static const per_sequence_t MeasuredResultsList_sequence_of[1] = {
  { &hf_ulp_MeasuredResultsList_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_MeasuredResults },
};

static int
dissect_ulp_MeasuredResultsList(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_MeasuredResultsList, MeasuredResultsList_sequence_of,
                                                  1, maxFreq);

  return offset;
}


static const per_sequence_t WcdmaCellInformation_sequence[] = {
  { &hf_ulp_refMCC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refMNC          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_999 },
  { &hf_ulp_refUC           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_268435455 },
  { &hf_ulp_frequencyInfo   , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_FrequencyInfo },
  { &hf_ulp_primaryScramblingCode, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_INTEGER_0_511 },
  { &hf_ulp_measuredResultsList, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_MeasuredResultsList },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_WcdmaCellInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_WcdmaCellInformation, WcdmaCellInformation_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_32767(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 32767U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_INTEGER_0_4194303(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 4194303U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_INTEGER_0_8388607(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 8388607U, NULL, FALSE);

  return offset;
}


static const per_sequence_t CdmaCellInformation_sequence[] = {
  { &hf_ulp_refNID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_refSID          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_32767 },
  { &hf_ulp_refBASEID       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_refBASELAT      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4194303 },
  { &hf_ulp_reBASELONG      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_8388607 },
  { &hf_ulp_refREFPN        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_511 },
  { &hf_ulp_refWeekNumber   , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_65535 },
  { &hf_ulp_refSeconds      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_4194303 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_CdmaCellInformation(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_CdmaCellInformation, CdmaCellInformation_sequence);

  return offset;
}


static const value_string ulp_CellInfo_vals[] = {
  {   0, "gsmCell" },
  {   1, "wcdmaCell" },
  {   2, "cdmaCell" },
  { 0, NULL }
};

static const per_choice_t CellInfo_choice[] = {
  {   0, &hf_ulp_gsmCell         , ASN1_EXTENSION_ROOT    , dissect_ulp_GsmCellInformation },
  {   1, &hf_ulp_wcdmaCell       , ASN1_EXTENSION_ROOT    , dissect_ulp_WcdmaCellInformation },
  {   2, &hf_ulp_cdmaCell        , ASN1_EXTENSION_ROOT    , dissect_ulp_CdmaCellInformation },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_CellInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
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
dissect_ulp_Status(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, TRUE, 0, NULL);

  return offset;
}


static const per_sequence_t LocationId_sequence[] = {
  { &hf_ulp_cellInfo        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_CellInfo },
  { &hf_ulp_status          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_Status },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_LocationId(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_LocationId, LocationId_sequence);

  return offset;
}


static const per_sequence_t SUPLSTART_sequence[] = {
  { &hf_ulp_sETCapabilities , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SETCapabilities },
  { &hf_ulp_locationId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_LocationId },
  { &hf_ulp_qoP             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_QoP },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLSTART(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLSTART, SUPLSTART_sequence);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_128(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE, NULL);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_256(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     256, 256, FALSE, NULL);

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
dissect_ulp_SETAuthKey(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_SETAuthKey, SETAuthKey_choice,
                                 NULL);

  return offset;
}



static int
dissect_ulp_KeyIdentity4(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE, NULL);

  return offset;
}


static const per_sequence_t SUPLRESPONSE_sequence[] = {
  { &hf_ulp_posMethod       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PosMethod },
  { &hf_ulp_sLPAddress      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SLPAddress },
  { &hf_ulp_sETAuthKey      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SETAuthKey },
  { &hf_ulp_keyIdentity4    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_KeyIdentity4 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLRESPONSE(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLRESPONSE, SUPLRESPONSE_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_167(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 167U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_INTEGER_0_31(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 31U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_INTEGER_0_10(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 10U, NULL, FALSE);

  return offset;
}


static const per_sequence_t SatelliteInfoElement_sequence[] = {
  { &hf_ulp_satId           , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_63 },
  { &hf_ulp_iODE            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_255 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SatelliteInfoElement(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SatelliteInfoElement, SatelliteInfoElement_sequence);

  return offset;
}


static const per_sequence_t SatelliteInfo_sequence_of[1] = {
  { &hf_ulp_SatelliteInfo_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_SatelliteInfoElement },
};

static int
dissect_ulp_SatelliteInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_ulp_SatelliteInfo, SatelliteInfo_sequence_of,
                                                  1, 31);

  return offset;
}


static const per_sequence_t NavigationModel_sequence[] = {
  { &hf_ulp_gpsWeek         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_1023 },
  { &hf_ulp_gpsToe          , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_167 },
  { &hf_ulp_nSAT            , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_31 },
  { &hf_ulp_toeLimit        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_10 },
  { &hf_ulp_satInfo         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SatelliteInfo },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_NavigationModel(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_NavigationModel, NavigationModel_sequence);

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
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_RequestedAssistData(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_RequestedAssistData, RequestedAssistData_sequence);

  return offset;
}



static int
dissect_ulp_UTCTime(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_VisibleString(tvb, offset, actx, tree, hf_index,
                                        NO_BOUND, NO_BOUND);

  return offset;
}


static const value_string ulp_T_latitudeSign_vals[] = {
  {   0, "north" },
  {   1, "south" },
  { 0, NULL }
};


static int
dissect_ulp_T_latitudeSign(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_ulp_INTEGER_M8388608_8388607(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              -8388608, 8388607U, NULL, FALSE);

  return offset;
}



static int
dissect_ulp_INTEGER_0_180(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 180U, NULL, FALSE);

  return offset;
}


static const per_sequence_t T_uncertainty_sequence[] = {
  { &hf_ulp_uncertaintySemiMajor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_127 },
  { &hf_ulp_uncertaintySemiMinor, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_127 },
  { &hf_ulp_orientationMajorAxis, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_180 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_T_uncertainty(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_T_uncertainty, T_uncertainty_sequence);

  return offset;
}



static int
dissect_ulp_INTEGER_0_100(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                              0U, 100U, NULL, FALSE);

  return offset;
}


static const value_string ulp_T_altitudeDirection_vals[] = {
  {   0, "height" },
  {   1, "depth" },
  { 0, NULL }
};


static int
dissect_ulp_T_altitudeDirection(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}


static const per_sequence_t AltitudeInfo_sequence[] = {
  { &hf_ulp_altitudeDirection, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_T_altitudeDirection },
  { &hf_ulp_altitude        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_32767 },
  { &hf_ulp_altUncertainty  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_INTEGER_0_127 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_AltitudeInfo(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
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
dissect_ulp_PositionEstimate(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_PositionEstimate, PositionEstimate_sequence);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_9(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     9, 9, FALSE, NULL);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_16(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     16, 16, FALSE, NULL);

  return offset;
}


static const per_sequence_t Horvel_sequence[] = {
  { &hf_ulp_bearing         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_9 },
  { &hf_ulp_horspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_16 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Horvel(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Horvel, Horvel_sequence);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_1(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     1, 1, FALSE, NULL);

  return offset;
}



static int
dissect_ulp_BIT_STRING_SIZE_8(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     8, 8, FALSE, NULL);

  return offset;
}


static const per_sequence_t Horandvervel_sequence[] = {
  { &hf_ulp_verdirect       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_1 },
  { &hf_ulp_bearing         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_9 },
  { &hf_ulp_horspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_16 },
  { &hf_ulp_verspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Horandvervel(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Horandvervel, Horandvervel_sequence);

  return offset;
}


static const per_sequence_t Horveluncert_sequence[] = {
  { &hf_ulp_bearing         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_9 },
  { &hf_ulp_horspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_16 },
  { &hf_ulp_uncertspeed     , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Horveluncert(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Horveluncert, Horveluncert_sequence);

  return offset;
}


static const per_sequence_t Horandveruncert_sequence[] = {
  { &hf_ulp_verdirect       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_1 },
  { &hf_ulp_bearing         , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_9 },
  { &hf_ulp_horspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_16 },
  { &hf_ulp_verspeed        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_8 },
  { &hf_ulp_horuncertspeed  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_8 },
  { &hf_ulp_veruncertspeed  , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_BIT_STRING_SIZE_8 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Horandveruncert(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
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
dissect_ulp_Velocity(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_Velocity, Velocity_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t Position_sequence[] = {
  { &hf_ulp_timestamp       , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_UTCTime },
  { &hf_ulp_positionEstimate, ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PositionEstimate },
  { &hf_ulp_velocity        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Velocity },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_Position(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_Position, Position_sequence);

  return offset;
}



static int
dissect_ulp_OCTET_STRING_SIZE_1_8192(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 8192, NULL);

  return offset;
}



static int
dissect_ulp_RRLPPayload(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 33 "ulp.cnf"
 tvbuff_t *rrlp_tvb;

  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       1, 8192, &rrlp_tvb);


  if (rrlp_tvb){
	call_dissector(rrlp_handle, rrlp_tvb, actx->pinfo, tree);

  }

  return offset;
}


static const value_string ulp_PosPayLoad_vals[] = {
  {   0, "tia801payload" },
  {   1, "rrcPayload" },
  {   2, "rrlpPayload" },
  { 0, NULL }
};

static const per_choice_t PosPayLoad_choice[] = {
  {   0, &hf_ulp_tia801payload   , ASN1_EXTENSION_ROOT    , dissect_ulp_OCTET_STRING_SIZE_1_8192 },
  {   1, &hf_ulp_rrcPayload      , ASN1_EXTENSION_ROOT    , dissect_ulp_OCTET_STRING_SIZE_1_8192 },
  {   2, &hf_ulp_rrlpPayload     , ASN1_EXTENSION_ROOT    , dissect_ulp_RRLPPayload },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_PosPayLoad(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_PosPayLoad, PosPayLoad_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t SUPLPOS_sequence[] = {
  { &hf_ulp_posPayLoad      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_PosPayLoad },
  { &hf_ulp_velocity        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Velocity },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLPOS(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLPOS, SUPLPOS_sequence);

  return offset;
}



static int
dissect_ulp_Ver(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     64, 64, FALSE, NULL);

  return offset;
}


static const per_sequence_t SUPLPOSINIT_sequence[] = {
  { &hf_ulp_sETCapabilities , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SETCapabilities },
  { &hf_ulp_requestedAssistData, ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_RequestedAssistData },
  { &hf_ulp_locationId      , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_LocationId },
  { &hf_ulp_position        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Position },
  { &hf_ulp_sUPLPOS         , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SUPLPOS },
  { &hf_ulp_ver             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Ver },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLPOSINIT(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
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
  { 0, NULL }
};

static guint32 StatusCode_value_map[20+0] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 100, 101};

static int
dissect_ulp_StatusCode(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     20, NULL, TRUE, 0, StatusCode_value_map);

  return offset;
}


static const per_sequence_t SUPLEND_sequence[] = {
  { &hf_ulp_position        , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Position },
  { &hf_ulp_statusCode      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_StatusCode },
  { &hf_ulp_ver             , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_Ver },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLEND(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLEND, SUPLEND_sequence);

  return offset;
}



static int
dissect_ulp_SETNonce(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE, NULL);

  return offset;
}



static int
dissect_ulp_KeyIdentity2(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE, NULL);

  return offset;
}


static const per_sequence_t SUPLAUTHREQ_sequence[] = {
  { &hf_ulp_sETNonce        , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_SETNonce },
  { &hf_ulp_keyIdentity2    , ASN1_EXTENSION_ROOT    , ASN1_NOT_OPTIONAL, dissect_ulp_KeyIdentity2 },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLAUTHREQ(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLAUTHREQ, SUPLAUTHREQ_sequence);

  return offset;
}


static const value_string ulp_SPCAuthKey_vals[] = {
  {   0, "shortKey" },
  {   1, "longKey" },
  { 0, NULL }
};

static const per_choice_t SPCAuthKey_choice[] = {
  {   0, &hf_ulp_shortKey        , ASN1_EXTENSION_ROOT    , dissect_ulp_BIT_STRING_SIZE_128 },
  {   1, &hf_ulp_longKey         , ASN1_EXTENSION_ROOT    , dissect_ulp_BIT_STRING_SIZE_256 },
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_SPCAuthKey(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_SPCAuthKey, SPCAuthKey_choice,
                                 NULL);

  return offset;
}



static int
dissect_ulp_KeyIdentity3(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_bit_string(tvb, offset, actx, tree, hf_index,
                                     128, 128, FALSE, NULL);

  return offset;
}


static const per_sequence_t SUPLAUTHRESP_sequence[] = {
  { &hf_ulp_sPCAuthKey      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_SPCAuthKey },
  { &hf_ulp_keyIdentity3    , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_KeyIdentity3 },
  { &hf_ulp_statusCode      , ASN1_EXTENSION_ROOT    , ASN1_OPTIONAL    , dissect_ulp_StatusCode },
  { NULL, 0, 0, NULL }
};

static int
dissect_ulp_SUPLAUTHRESP(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_SUPLAUTHRESP, SUPLAUTHRESP_sequence);

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
  { 0, NULL, 0, NULL }
};

static int
dissect_ulp_UlpMessage(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 21 "ulp.cnf"

guint32 UlpMessage;

    offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_ulp_UlpMessage, UlpMessage_choice,
                                 &UlpMessage);


	if (check_col(actx->pinfo->cinfo, COL_INFO))
	{
	    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "%s ", val_to_str(UlpMessage,ulp_UlpMessage_vals,"Unknown"));
	}


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
dissect_ulp_ULP_PDU(tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_, proto_tree *tree, int hf_index) {
#line 10 "ulp.cnf"

	proto_tree_add_item(tree, proto_ulp, tvb, 0, -1, FALSE);

	if (check_col(actx->pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(actx->pinfo->cinfo, COL_PROTOCOL, PSNAME);
	if (check_col(actx->pinfo->cinfo, COL_INFO))
		col_clear(actx->pinfo->cinfo, COL_INFO);

    offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_ulp_ULP_PDU, ULP_PDU_sequence);




  return offset;
}

/*--- PDUs ---*/

static void dissect_ULP_PDU_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, TRUE, pinfo);
  dissect_ulp_ULP_PDU(tvb, 0, &asn1_ctx, tree, hf_ulp_ULP_PDU_PDU);
}


/*--- End of included file: packet-ulp-fn.c ---*/
#line 80 "packet-ulp-template.c"


static guint
get_ulp_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	/* PDU length = Message length */
	return tvb_get_ntohs(tvb,offset);
}

static void
dissect_ulp_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tcp_dissect_pdus(tvb, pinfo, tree, ulp_desegment, ULP_HEADER_SIZE,
	    get_ulp_pdu_len, dissect_ULP_PDU_PDU);
}
/*--- proto_reg_handoff_ulp ---------------------------------------*/
void
proto_reg_handoff_ulp(void)
{

	ulp_handle = create_dissector_handle(dissect_ulp_tcp, proto_ulp);

	dissector_add("tcp.port", gbl_ulp_port, ulp_handle);

	/* application/oma-supl-ulp */
	dissector_add_string("media_type","application/oma-supl-ulp", ulp_handle);

	rrlp_handle = find_dissector("rrlp");

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
        "ulp.ULP_PDU", HFILL }},
    { &hf_ulp_length,
      { "length", "ulp.length",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_65535", HFILL }},
    { &hf_ulp_version,
      { "version", "ulp.version",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.Version", HFILL }},
    { &hf_ulp_sessionID,
      { "sessionID", "ulp.sessionID",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SessionID", HFILL }},
    { &hf_ulp_message,
      { "message", "ulp.message",
        FT_UINT32, BASE_DEC, VALS(ulp_UlpMessage_vals), 0,
        "ulp.UlpMessage", HFILL }},
    { &hf_ulp_msSUPLINIT,
      { "msSUPLINIT", "ulp.msSUPLINIT",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SUPLINIT", HFILL }},
    { &hf_ulp_msSUPLSTART,
      { "msSUPLSTART", "ulp.msSUPLSTART",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SUPLSTART", HFILL }},
    { &hf_ulp_msSUPLRESPONSE,
      { "msSUPLRESPONSE", "ulp.msSUPLRESPONSE",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SUPLRESPONSE", HFILL }},
    { &hf_ulp_msSUPLPOSINIT,
      { "msSUPLPOSINIT", "ulp.msSUPLPOSINIT",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SUPLPOSINIT", HFILL }},
    { &hf_ulp_msSUPLPOS,
      { "msSUPLPOS", "ulp.msSUPLPOS",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SUPLPOS", HFILL }},
    { &hf_ulp_msSUPLEND,
      { "msSUPLEND", "ulp.msSUPLEND",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SUPLEND", HFILL }},
    { &hf_ulp_msSUPLAUTHREQ,
      { "msSUPLAUTHREQ", "ulp.msSUPLAUTHREQ",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SUPLAUTHREQ", HFILL }},
    { &hf_ulp_msSUPLAUTHRESP,
      { "msSUPLAUTHRESP", "ulp.msSUPLAUTHRESP",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SUPLAUTHRESP", HFILL }},
    { &hf_ulp_maj,
      { "maj", "ulp.maj",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_255", HFILL }},
    { &hf_ulp_min,
      { "min", "ulp.min",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_255", HFILL }},
    { &hf_ulp_servind,
      { "servind", "ulp.servind",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_255", HFILL }},
    { &hf_ulp_setSessionID,
      { "setSessionID", "ulp.setSessionID",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SetSessionID", HFILL }},
    { &hf_ulp_slpSessionID,
      { "slpSessionID", "ulp.slpSessionID",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SlpSessionID", HFILL }},
    { &hf_ulp_sessionId,
      { "sessionId", "ulp.sessionId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_65535", HFILL }},
    { &hf_ulp_setId,
      { "setId", "ulp.setId",
        FT_UINT32, BASE_DEC, VALS(ulp_SETId_vals), 0,
        "ulp.SETId", HFILL }},
    { &hf_ulp_msisdn,
      { "msisdn", "ulp.msisdn",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.OCTET_STRING_SIZE_8", HFILL }},
    { &hf_ulp_mdn,
      { "mdn", "ulp.mdn",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.OCTET_STRING_SIZE_8", HFILL }},
    { &hf_ulp_min1,
      { "min", "ulp.min",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.BIT_STRING_SIZE_34", HFILL }},
    { &hf_ulp_imsi,
      { "imsi", "ulp.imsi",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.OCTET_STRING_SIZE_8", HFILL }},
    { &hf_ulp_nai,
      { "nai", "ulp.nai",
        FT_STRING, BASE_NONE, NULL, 0,
        "ulp.IA5String_SIZE_1_1000", HFILL }},
    { &hf_ulp_iPAddress,
      { "iPAddress", "ulp.iPAddress",
        FT_UINT32, BASE_DEC, VALS(ulp_IPAddress_vals), 0,
        "ulp.IPAddress", HFILL }},
    { &hf_ulp_sessionID1,
      { "sessionID", "ulp.sessionID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.OCTET_STRING_SIZE_4", HFILL }},
    { &hf_ulp_slpId,
      { "slpId", "ulp.slpId",
        FT_UINT32, BASE_DEC, VALS(ulp_SLPAddress_vals), 0,
        "ulp.SLPAddress", HFILL }},
    { &hf_ulp_ipv4Address,
      { "ipv4Address", "ulp.ipv4Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.IPv4Address", HFILL }},
    { &hf_ulp_ipv6Address,
      { "ipv6Address", "ulp.ipv6Address",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.IPv6Address", HFILL }},
    { &hf_ulp_fQDN,
      { "fQDN", "ulp.fQDN",
        FT_STRING, BASE_NONE, NULL, 0,
        "ulp.FQDN", HFILL }},
    { &hf_ulp_cellInfo,
      { "cellInfo", "ulp.cellInfo",
        FT_UINT32, BASE_DEC, VALS(ulp_CellInfo_vals), 0,
        "ulp.CellInfo", HFILL }},
    { &hf_ulp_status,
      { "status", "ulp.status",
        FT_UINT32, BASE_DEC, VALS(ulp_Status_vals), 0,
        "ulp.Status", HFILL }},
    { &hf_ulp_gsmCell,
      { "gsmCell", "ulp.gsmCell",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.GsmCellInformation", HFILL }},
    { &hf_ulp_wcdmaCell,
      { "wcdmaCell", "ulp.wcdmaCell",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.WcdmaCellInformation", HFILL }},
    { &hf_ulp_cdmaCell,
      { "cdmaCell", "ulp.cdmaCell",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.CdmaCellInformation", HFILL }},
    { &hf_ulp_timestamp,
      { "timestamp", "ulp.timestamp",
        FT_STRING, BASE_NONE, NULL, 0,
        "ulp.UTCTime", HFILL }},
    { &hf_ulp_positionEstimate,
      { "positionEstimate", "ulp.positionEstimate",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.PositionEstimate", HFILL }},
    { &hf_ulp_velocity,
      { "velocity", "ulp.velocity",
        FT_UINT32, BASE_DEC, VALS(ulp_Velocity_vals), 0,
        "ulp.Velocity", HFILL }},
    { &hf_ulp_latitudeSign,
      { "latitudeSign", "ulp.latitudeSign",
        FT_UINT32, BASE_DEC, VALS(ulp_T_latitudeSign_vals), 0,
        "ulp.T_latitudeSign", HFILL }},
    { &hf_ulp_latitude,
      { "latitude", "ulp.latitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_8388607", HFILL }},
    { &hf_ulp_longitude,
      { "longitude", "ulp.longitude",
        FT_INT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_M8388608_8388607", HFILL }},
    { &hf_ulp_uncertainty,
      { "uncertainty", "ulp.uncertainty",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.T_uncertainty", HFILL }},
    { &hf_ulp_uncertaintySemiMajor,
      { "uncertaintySemiMajor", "ulp.uncertaintySemiMajor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_127", HFILL }},
    { &hf_ulp_uncertaintySemiMinor,
      { "uncertaintySemiMinor", "ulp.uncertaintySemiMinor",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_127", HFILL }},
    { &hf_ulp_orientationMajorAxis,
      { "orientationMajorAxis", "ulp.orientationMajorAxis",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_180", HFILL }},
    { &hf_ulp_confidence,
      { "confidence", "ulp.confidence",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_100", HFILL }},
    { &hf_ulp_altitudeInfo,
      { "altitudeInfo", "ulp.altitudeInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.AltitudeInfo", HFILL }},
    { &hf_ulp_altitudeDirection,
      { "altitudeDirection", "ulp.altitudeDirection",
        FT_UINT32, BASE_DEC, VALS(ulp_T_altitudeDirection_vals), 0,
        "ulp.T_altitudeDirection", HFILL }},
    { &hf_ulp_altitude,
      { "altitude", "ulp.altitude",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_32767", HFILL }},
    { &hf_ulp_altUncertainty,
      { "altUncertainty", "ulp.altUncertainty",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_127", HFILL }},
    { &hf_ulp_refNID,
      { "refNID", "ulp.refNID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_65535", HFILL }},
    { &hf_ulp_refSID,
      { "refSID", "ulp.refSID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_32767", HFILL }},
    { &hf_ulp_refBASEID,
      { "refBASEID", "ulp.refBASEID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_65535", HFILL }},
    { &hf_ulp_refBASELAT,
      { "refBASELAT", "ulp.refBASELAT",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_4194303", HFILL }},
    { &hf_ulp_reBASELONG,
      { "reBASELONG", "ulp.reBASELONG",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_8388607", HFILL }},
    { &hf_ulp_refREFPN,
      { "refREFPN", "ulp.refREFPN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_511", HFILL }},
    { &hf_ulp_refWeekNumber,
      { "refWeekNumber", "ulp.refWeekNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_65535", HFILL }},
    { &hf_ulp_refSeconds,
      { "refSeconds", "ulp.refSeconds",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_4194303", HFILL }},
    { &hf_ulp_refMCC,
      { "refMCC", "ulp.refMCC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_999", HFILL }},
    { &hf_ulp_refMNC,
      { "refMNC", "ulp.refMNC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_999", HFILL }},
    { &hf_ulp_refLAC,
      { "refLAC", "ulp.refLAC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_65535", HFILL }},
    { &hf_ulp_refCI,
      { "refCI", "ulp.refCI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_65535", HFILL }},
    { &hf_ulp_nMR,
      { "nMR", "ulp.nMR",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.NMR", HFILL }},
    { &hf_ulp_tA,
      { "tA", "ulp.tA",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_255", HFILL }},
    { &hf_ulp_refUC,
      { "refUC", "ulp.refUC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_268435455", HFILL }},
    { &hf_ulp_frequencyInfo,
      { "frequencyInfo", "ulp.frequencyInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.FrequencyInfo", HFILL }},
    { &hf_ulp_primaryScramblingCode,
      { "primaryScramblingCode", "ulp.primaryScramblingCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_511", HFILL }},
    { &hf_ulp_measuredResultsList,
      { "measuredResultsList", "ulp.measuredResultsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.MeasuredResultsList", HFILL }},
    { &hf_ulp_modeSpecificInfo,
      { "modeSpecificInfo", "ulp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ulp_T_modeSpecificInfo_vals), 0,
        "ulp.T_modeSpecificInfo", HFILL }},
    { &hf_ulp_fdd,
      { "fdd", "ulp.fdd",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.FrequencyInfoFDD", HFILL }},
    { &hf_ulp_tdd,
      { "tdd", "ulp.tdd",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.FrequencyInfoTDD", HFILL }},
    { &hf_ulp_uarfcn_UL,
      { "uarfcn-UL", "ulp.uarfcn_UL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.UARFCN", HFILL }},
    { &hf_ulp_uarfcn_DL,
      { "uarfcn-DL", "ulp.uarfcn_DL",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.UARFCN", HFILL }},
    { &hf_ulp_uarfcn_Nt,
      { "uarfcn-Nt", "ulp.uarfcn_Nt",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.UARFCN", HFILL }},
    { &hf_ulp_NMR_item,
      { "Item", "ulp.NMR_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.NMRelement", HFILL }},
    { &hf_ulp_aRFCN,
      { "aRFCN", "ulp.aRFCN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_1023", HFILL }},
    { &hf_ulp_bSIC,
      { "bSIC", "ulp.bSIC",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_63", HFILL }},
    { &hf_ulp_rxLev,
      { "rxLev", "ulp.rxLev",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_63", HFILL }},
    { &hf_ulp_MeasuredResultsList_item,
      { "Item", "ulp.MeasuredResultsList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.MeasuredResults", HFILL }},
    { &hf_ulp_utra_CarrierRSSI,
      { "utra-CarrierRSSI", "ulp.utra_CarrierRSSI",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.UTRA_CarrierRSSI", HFILL }},
    { &hf_ulp_cellMeasuredResultsList,
      { "cellMeasuredResultsList", "ulp.cellMeasuredResultsList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.CellMeasuredResultsList", HFILL }},
    { &hf_ulp_CellMeasuredResultsList_item,
      { "Item", "ulp.CellMeasuredResultsList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.CellMeasuredResults", HFILL }},
    { &hf_ulp_cellIdentity,
      { "cellIdentity", "ulp.cellIdentity",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_268435455", HFILL }},
    { &hf_ulp_modeSpecificInfo1,
      { "modeSpecificInfo", "ulp.modeSpecificInfo",
        FT_UINT32, BASE_DEC, VALS(ulp_T_modeSpecificInfo1_vals), 0,
        "ulp.T_modeSpecificInfo1", HFILL }},
    { &hf_ulp_fdd1,
      { "fdd", "ulp.fdd",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.T_fdd", HFILL }},
    { &hf_ulp_primaryCPICH_Info,
      { "primaryCPICH-Info", "ulp.primaryCPICH_Info",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.PrimaryCPICH_Info", HFILL }},
    { &hf_ulp_cpich_Ec_N0,
      { "cpich-Ec-N0", "ulp.cpich_Ec_N0",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.CPICH_Ec_N0", HFILL }},
    { &hf_ulp_cpich_RSCP,
      { "cpich-RSCP", "ulp.cpich_RSCP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.CPICH_RSCP", HFILL }},
    { &hf_ulp_pathloss,
      { "pathloss", "ulp.pathloss",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.Pathloss", HFILL }},
    { &hf_ulp_tdd1,
      { "tdd", "ulp.tdd",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.T_tdd", HFILL }},
    { &hf_ulp_cellParametersID,
      { "cellParametersID", "ulp.cellParametersID",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.CellParametersID", HFILL }},
    { &hf_ulp_proposedTGSN,
      { "proposedTGSN", "ulp.proposedTGSN",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.TGSN", HFILL }},
    { &hf_ulp_primaryCCPCH_RSCP,
      { "primaryCCPCH-RSCP", "ulp.primaryCCPCH_RSCP",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.PrimaryCCPCH_RSCP", HFILL }},
    { &hf_ulp_timeslotISCP_List,
      { "timeslotISCP-List", "ulp.timeslotISCP_List",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.TimeslotISCP_List", HFILL }},
    { &hf_ulp_TimeslotISCP_List_item,
      { "Item", "ulp.TimeslotISCP_List_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.TimeslotISCP", HFILL }},
    { &hf_ulp_horacc,
      { "horacc", "ulp.horacc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_127", HFILL }},
    { &hf_ulp_veracc,
      { "veracc", "ulp.veracc",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_127", HFILL }},
    { &hf_ulp_maxLocAge,
      { "maxLocAge", "ulp.maxLocAge",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_65535", HFILL }},
    { &hf_ulp_delay,
      { "delay", "ulp.delay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_7", HFILL }},
    { &hf_ulp_horvel,
      { "horvel", "ulp.horvel",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.Horvel", HFILL }},
    { &hf_ulp_horandvervel,
      { "horandvervel", "ulp.horandvervel",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.Horandvervel", HFILL }},
    { &hf_ulp_horveluncert,
      { "horveluncert", "ulp.horveluncert",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.Horveluncert", HFILL }},
    { &hf_ulp_horandveruncert,
      { "horandveruncert", "ulp.horandveruncert",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.Horandveruncert", HFILL }},
    { &hf_ulp_bearing,
      { "bearing", "ulp.bearing",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.BIT_STRING_SIZE_9", HFILL }},
    { &hf_ulp_horspeed,
      { "horspeed", "ulp.horspeed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.BIT_STRING_SIZE_16", HFILL }},
    { &hf_ulp_verdirect,
      { "verdirect", "ulp.verdirect",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.BIT_STRING_SIZE_1", HFILL }},
    { &hf_ulp_verspeed,
      { "verspeed", "ulp.verspeed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.BIT_STRING_SIZE_8", HFILL }},
    { &hf_ulp_uncertspeed,
      { "uncertspeed", "ulp.uncertspeed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.BIT_STRING_SIZE_8", HFILL }},
    { &hf_ulp_horuncertspeed,
      { "horuncertspeed", "ulp.horuncertspeed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.BIT_STRING_SIZE_8", HFILL }},
    { &hf_ulp_veruncertspeed,
      { "veruncertspeed", "ulp.veruncertspeed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.BIT_STRING_SIZE_8", HFILL }},
    { &hf_ulp_sETNonce,
      { "sETNonce", "ulp.sETNonce",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.SETNonce", HFILL }},
    { &hf_ulp_keyIdentity2,
      { "keyIdentity2", "ulp.keyIdentity2",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.KeyIdentity2", HFILL }},
    { &hf_ulp_sPCAuthKey,
      { "sPCAuthKey", "ulp.sPCAuthKey",
        FT_UINT32, BASE_DEC, VALS(ulp_SPCAuthKey_vals), 0,
        "ulp.SPCAuthKey", HFILL }},
    { &hf_ulp_keyIdentity3,
      { "keyIdentity3", "ulp.keyIdentity3",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.KeyIdentity3", HFILL }},
    { &hf_ulp_statusCode,
      { "statusCode", "ulp.statusCode",
        FT_UINT32, BASE_DEC, VALS(ulp_StatusCode_vals), 0,
        "ulp.StatusCode", HFILL }},
    { &hf_ulp_shortKey,
      { "shortKey", "ulp.shortKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.BIT_STRING_SIZE_128", HFILL }},
    { &hf_ulp_longKey,
      { "longKey", "ulp.longKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.BIT_STRING_SIZE_256", HFILL }},
    { &hf_ulp_position,
      { "position", "ulp.position",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.Position", HFILL }},
    { &hf_ulp_ver,
      { "ver", "ulp.ver",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.Ver", HFILL }},
    { &hf_ulp_posMethod,
      { "posMethod", "ulp.posMethod",
        FT_UINT32, BASE_DEC, VALS(ulp_PosMethod_vals), 0,
        "ulp.PosMethod", HFILL }},
    { &hf_ulp_notification,
      { "notification", "ulp.notification",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.Notification", HFILL }},
    { &hf_ulp_sLPAddress,
      { "sLPAddress", "ulp.sLPAddress",
        FT_UINT32, BASE_DEC, VALS(ulp_SLPAddress_vals), 0,
        "ulp.SLPAddress", HFILL }},
    { &hf_ulp_qoP,
      { "qoP", "ulp.qoP",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.QoP", HFILL }},
    { &hf_ulp_sLPMode,
      { "sLPMode", "ulp.sLPMode",
        FT_UINT32, BASE_DEC, VALS(ulp_SLPMode_vals), 0,
        "ulp.SLPMode", HFILL }},
    { &hf_ulp_mAC,
      { "mAC", "ulp.mAC",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.MAC", HFILL }},
    { &hf_ulp_keyIdentity,
      { "keyIdentity", "ulp.keyIdentity",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.KeyIdentity", HFILL }},
    { &hf_ulp_notificationType,
      { "notificationType", "ulp.notificationType",
        FT_UINT32, BASE_DEC, VALS(ulp_NotificationType_vals), 0,
        "ulp.NotificationType", HFILL }},
    { &hf_ulp_encodingType,
      { "encodingType", "ulp.encodingType",
        FT_UINT32, BASE_DEC, VALS(ulp_EncodingType_vals), 0,
        "ulp.EncodingType", HFILL }},
    { &hf_ulp_requestorId,
      { "requestorId", "ulp.requestorId",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.OCTET_STRING_SIZE_1_maxReqLength", HFILL }},
    { &hf_ulp_requestorIdType,
      { "requestorIdType", "ulp.requestorIdType",
        FT_UINT32, BASE_DEC, VALS(ulp_FormatIndicator_vals), 0,
        "ulp.FormatIndicator", HFILL }},
    { &hf_ulp_clientName,
      { "clientName", "ulp.clientName",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.OCTET_STRING_SIZE_1_maxClientLength", HFILL }},
    { &hf_ulp_clientNameType,
      { "clientNameType", "ulp.clientNameType",
        FT_UINT32, BASE_DEC, VALS(ulp_FormatIndicator_vals), 0,
        "ulp.FormatIndicator", HFILL }},
    { &hf_ulp_posPayLoad,
      { "posPayLoad", "ulp.posPayLoad",
        FT_UINT32, BASE_DEC, VALS(ulp_PosPayLoad_vals), 0,
        "ulp.PosPayLoad", HFILL }},
    { &hf_ulp_tia801payload,
      { "tia801payload", "ulp.tia801payload",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.OCTET_STRING_SIZE_1_8192", HFILL }},
    { &hf_ulp_rrcPayload,
      { "rrcPayload", "ulp.rrcPayload",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.OCTET_STRING_SIZE_1_8192", HFILL }},
    { &hf_ulp_rrlpPayload,
      { "rrlpPayload", "ulp.rrlpPayload",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.RRLPPayload", HFILL }},
    { &hf_ulp_sETCapabilities,
      { "sETCapabilities", "ulp.sETCapabilities",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SETCapabilities", HFILL }},
    { &hf_ulp_requestedAssistData,
      { "requestedAssistData", "ulp.requestedAssistData",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.RequestedAssistData", HFILL }},
    { &hf_ulp_locationId,
      { "locationId", "ulp.locationId",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.LocationId", HFILL }},
    { &hf_ulp_sUPLPOS,
      { "sUPLPOS", "ulp.sUPLPOS",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SUPLPOS", HFILL }},
    { &hf_ulp_almanacRequested,
      { "almanacRequested", "ulp.almanacRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_utcModelRequested,
      { "utcModelRequested", "ulp.utcModelRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_ionosphericModelRequested,
      { "ionosphericModelRequested", "ulp.ionosphericModelRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_dgpsCorrectionsRequested,
      { "dgpsCorrectionsRequested", "ulp.dgpsCorrectionsRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_referenceLocationRequested,
      { "referenceLocationRequested", "ulp.referenceLocationRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_referenceTimeRequested,
      { "referenceTimeRequested", "ulp.referenceTimeRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_acquisitionAssistanceRequested,
      { "acquisitionAssistanceRequested", "ulp.acquisitionAssistanceRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_realTimeIntegrityRequested,
      { "realTimeIntegrityRequested", "ulp.realTimeIntegrityRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_navigationModelRequested,
      { "navigationModelRequested", "ulp.navigationModelRequested",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_navigationModelData,
      { "navigationModelData", "ulp.navigationModelData",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.NavigationModel", HFILL }},
    { &hf_ulp_gpsWeek,
      { "gpsWeek", "ulp.gpsWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_1023", HFILL }},
    { &hf_ulp_gpsToe,
      { "gpsToe", "ulp.gpsToe",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_167", HFILL }},
    { &hf_ulp_nSAT,
      { "nSAT", "ulp.nSAT",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_31", HFILL }},
    { &hf_ulp_toeLimit,
      { "toeLimit", "ulp.toeLimit",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_10", HFILL }},
    { &hf_ulp_satInfo,
      { "satInfo", "ulp.satInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.SatelliteInfo", HFILL }},
    { &hf_ulp_SatelliteInfo_item,
      { "Item", "ulp.SatelliteInfo_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.SatelliteInfoElement", HFILL }},
    { &hf_ulp_satId,
      { "satId", "ulp.satId",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_63", HFILL }},
    { &hf_ulp_iODE,
      { "iODE", "ulp.iODE",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ulp.INTEGER_0_255", HFILL }},
    { &hf_ulp_sETAuthKey,
      { "sETAuthKey", "ulp.sETAuthKey",
        FT_UINT32, BASE_DEC, VALS(ulp_SETAuthKey_vals), 0,
        "ulp.SETAuthKey", HFILL }},
    { &hf_ulp_keyIdentity4,
      { "keyIdentity4", "ulp.keyIdentity4",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ulp.KeyIdentity4", HFILL }},
    { &hf_ulp_posTechnology,
      { "posTechnology", "ulp.posTechnology",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.PosTechnology", HFILL }},
    { &hf_ulp_prefMethod,
      { "prefMethod", "ulp.prefMethod",
        FT_UINT32, BASE_DEC, VALS(ulp_PrefMethod_vals), 0,
        "ulp.PrefMethod", HFILL }},
    { &hf_ulp_posProtocol,
      { "posProtocol", "ulp.posProtocol",
        FT_NONE, BASE_NONE, NULL, 0,
        "ulp.PosProtocol", HFILL }},
    { &hf_ulp_agpsSETassisted,
      { "agpsSETassisted", "ulp.agpsSETassisted",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_agpsSETBased,
      { "agpsSETBased", "ulp.agpsSETBased",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_autonomousGPS,
      { "autonomousGPS", "ulp.autonomousGPS",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_aFLT,
      { "aFLT", "ulp.aFLT",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_eCID,
      { "eCID", "ulp.eCID",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_eOTD,
      { "eOTD", "ulp.eOTD",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_oTDOA,
      { "oTDOA", "ulp.oTDOA",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_tia801,
      { "tia801", "ulp.tia801",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_rrlp,
      { "rrlp", "ulp.rrlp",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},
    { &hf_ulp_rrc,
      { "rrc", "ulp.rrc",
        FT_BOOLEAN, 8, NULL, 0,
        "ulp.BOOLEAN", HFILL }},

/*--- End of included file: packet-ulp-hfarr.c ---*/
#line 119 "packet-ulp-template.c"
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
#line 125 "packet-ulp-template.c"
  };

  module_t *ulp_module;


  /* Register protocol */
  proto_ulp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_ulp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  ulp_module = prefs_register_protocol(proto_ulp,proto_reg_handoff_ulp);

  prefs_register_bool_preference(ulp_module, "desegment_ulp_messages",
		"Reassemble ULP messages spanning multiple TCP segments",
		"Whether the ULP dissector should reassemble messages spanning multiple TCP segments."
		" To use this option, you must also enable \"Allow subdissectors to reassemble TCP streams\" in the TCP protocol settings.",
		&ulp_desegment);

	/* Register a configuration option for port */
	prefs_register_uint_preference(ulp_module, "tcp.port",
								   "ULP TCP Port",
								   "Set the TCP port for Ulp messages(IANA registerd port is 7275)",
								   10,
								   &gbl_ulp_port);
 
}




