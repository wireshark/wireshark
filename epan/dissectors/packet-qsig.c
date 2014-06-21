/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-qsig.c                                                              */
/* ../../tools/asn2wrs.py -c ./qsig.cnf -s ./packet-qsig-template -D . -O ../../epan/dissectors General-Error-List.asn qsig-gf-ext.asn qsig-gf-gp.asn qsig-gf-ade.asn QSIG-NA.asn QSIG-CF.asn QSIG-PR.asn QSIG-CT.asn QSIG-CC.asn QSIG-CO.asn QSIG-DND.asn QSIG-CI.asn QSIG-AOC.asn QSIG-RE.asn SYNC-SIG.asn QSIG-CINT.asn QSIG-CMN.asn QSIG-CPI.asn QSIG-PUMR.asn QSIG-PUMCH.asn QSIG-SSCT.asn QSIG-WTMLR.asn QSIG-WTMCH.asn QSIG-WTMAU.asn QSIG-SD.asn QSIG-CIDL.asn QSIG-SMS.asn QSIG-MCR.asn QSIG-MCM.asn QSIG-MID.asn */

/* Input file: packet-qsig-template.c */

#line 1 "../../asn1/qsig/packet-qsig-template.c"
/* packet-qsig.c
 * Routines for QSIG packet dissection
 * 2007  Tomas Kukosa
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
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-qsig.h"

#define PNAME  "QSIG"
#define PSNAME "QSIG"
#define PFNAME "qsig"

/* Shifted codeset values */
#define CS0 0x000
#define CS1 0x100
#define CS2 0x200
#define CS3 0x300
#define CS4 0x400
#define CS5 0x500
#define CS6 0x600
#define CS7 0x700

#define	QSIG_IE_TRANSIT_COUNTER 0x31
#define	QSIG_IE_PARTY_CATEGORY  0x32

void proto_register_qsig(void);
void proto_reg_handoff_qsig(void);

static const value_string qsig_str_ie_type_cs4[] = {
  { QSIG_IE_TRANSIT_COUNTER , "Transit counter" },
  { 0, NULL}
};
static const value_string qsig_str_ie_type_cs5[] = {
  { QSIG_IE_PARTY_CATEGORY  , "Party category" },
  { 0, NULL}
};
/* Codeset array */
static const value_string *qsig_str_ie_type[] = {
  NULL,
  NULL,
  NULL,
  NULL,
  qsig_str_ie_type_cs4,
  qsig_str_ie_type_cs5,
  NULL,
  NULL,
};


static const value_string qsig_str_pc[] = {
  { 0x00 , "unknown" },
  { 0x01 , "extension" },
  { 0x02 , "operator" },
  { 0x03 , "emergency extension" },
  { 0, NULL}
};

static const value_string qsig_str_service[] = {
  { 13868, "QSIG-NA" },
  { 13873, "QSIG-CF" },
  { 13874, "QSIG-PR" },
  { 13869, "QSIG-CT" },
  { 13870, "QSIG-CC" },
  { 14843, "QSIG-CO" },
  { 14844, "QSIG-DND(O)" },
  { 14846, "QSIG-CI" },
  { 15050, "QSIG-AOC" },
  { 15052, "QSIG-RE" },
  { 15054, "QSIG-CINT" },
  { 15506, "QSIG-MWI" },
  { 15507, "SYNC-SIG" },
  { 15772, "QSIG-CMN" },
  { 15992, "QSIG-CPI(P)" },
  { 17876, "QSIG-PUMR" },
  { 17878, "QSIG-PUMCH" },
  { 19460, "QSIG-SSCT" },
  { 15429, "QSIG-WTMLR" },
  { 15431, "QSIG-WTMCH" },
  { 15433, "QSIG-WTMAU" },
  { 21407, "QSIG-SD" },
  { 21889, "QSIG-CIDL" },
  {   325, "QSIG-SMS" },
  {   344, "QSIG-MCR" },
  {  3471, "QSIG-MCM" },
  {  3472, "QSIG-MID" },
  {   0, NULL}
};

static const value_string qsig_str_service_name[] = {
  { 13868, "Name-Operations" },
  { 13873, "Call-Diversion-Operations" },
  { 13874, "Path-Replacement-Operations" },
  { 13869, "Call-Transfer-Operations" },
  { 13870, "SS-CC-Operations" },
  { 14843, "Call-Offer-Operations" },
  { 14844, "Do-Not-Disturb-Operations" },
  { 14846, "Call-Intrusion-Operations" },
  { 15050, "SS-AOC-Operation" },
  { 15052, "Recall-Operation" },
  { 15054, "Call-Interception-Operations" },
  { 15506, "SS-MWI-Operations" },
  { 15507, "Synchronization-Operations" },
  { 15772, "Common-Information-Operations" },
  { 15992, "Call-Interruption-Operation" },
  { 17876, "PUM-Registration-Operation" },
  { 17878, "Private-User-Mobility-Call-Handling-Operations" },
  { 19460, "Single-Step-Call-Transfer-Operations" },
  { 15429, "WTM-Location-Registration-Operations" },
  { 15431, "Wireless-Terminal-Call-Handling-Operations" },
  { 15433, "WTM-Authentication-Operations" },
  { 21407, "SS-SD-Operations" },
  { 21889, "Call-Identification-and-Call-Linkage-Operations" },
  {   325, "Short-Message-Service-Operations" },
  {   344, "SS-MCR-Operations" },
  {  3471, "SS-MCM-Operations" },
  {  3472, "SS-MID-Operations" },
  {   0, NULL}
};

#define NO_SRV (-1)
static const gint32 op2srv_tab[] = {
  /*   0 */ 13868,
  /*   1 */ 13868,
  /*   2 */ 13868,
  /*   3 */ 13868,
  /*   4 */ 13874,
  /*   5 */ 13874,
  /*   6 */ 13874,
  /*   7 */ 13869,
  /*   8 */ 13869,
  /*   9 */ 13869,
  /*  10 */ 13869,
  /*  11 */ 13869,
  /*  12 */ 13869,
  /*  13 */ 13869,
  /*  14 */ 13869,
  /*  15 */ 13873,
  /*  16 */ 13873,
  /*  17 */ 13873,
  /*  18 */ 13873,
  /*  19 */ 13873,
  /*  20 */ 13873,
  /*  21 */ 13873,
  /*  22 */ 13873,
  /*  23 */ 13873,
  /*  24 */ NO_SRV,
  /*  25 */ NO_SRV,
  /*  26 */ NO_SRV,
  /*  27 */ 13870,
  /*  28 */ 13870,
  /*  29 */ 13870,
  /*  30 */ 13870,
  /*  31 */ 13870,
  /*  32 */ 13870,
  /*  33 */ 13870,
  /*  34 */ 14843,
  /*  35 */ 14844,
  /*  36 */ 14844,
  /*  37 */ 14844,
  /*  38 */ 14844,
  /*  39 */ 14844,
  /*  40 */ 13870,
  /*  41 */ 90001,
  /*  42 */ 90001,
  /*  43 */ 14846,
  /*  44 */ 14846,
  /*  45 */ 14846,
  /*  46 */ 14846,
  /*  47 */ 14846,
  /*  48 */ 14846,
  /*  49 */ 90001,
  /*  50 */ 15429,
  /*  51 */ 15429,
  /*  52 */ 15429,
  /*  53 */ 15429,
  /*  54 */ 15431,
  /*  55 */ 15431,
  /*  56 */ 15431,
  /*  57 */ 15052,
  /*  58 */ 15052,
  /*  59 */ 15050,
  /*  60 */ 15050,
  /*  61 */ 15050,
  /*  62 */ 15050,
  /*  63 */ 15050,
  /*  64 */ 15050,
  /*  65 */ 15050,
  /*  66 */ 15054,
  /*  67 */ 15054,
  /*  68 */ 15054,
  /*  69 */ 15054,
  /*  70 */ 15054,
  /*  71 */ 15431,
  /*  72 */ 15433,
  /*  73 */ 15433,
  /*  74 */ 15433,
  /*  75 */ 15433,
  /*  76 */ 15433,
  /*  77 */ 15433,
  /*  78 */ 15507,
  /*  79 */ 15507,
  /*  80 */  3471,
  /*  81 */  3471,
  /*  82 */  3471,
  /*  83 */ NO_SRV,
  /*  84 */ 15772,
  /*  85 */ 15772,
  /*  86 */ 13874,
  /*  87 */ 15992,
  /*  88 */ 15992,
  /*  89 */ 17876,
  /*  90 */ 17876,
  /*  91 */ 17876,
  /*  92 */ 17876,
  /*  93 */ 17878,
  /*  94 */ 17878,
  /*  95 */ 17878,
  /*  96 */ 17878,
  /*  97 */ 15429,
  /*  98 */ 15429,
  /*  99 */ 19460,
  /* 100 */ 19460,
  /* 101 */ 19460,
  /* 102 */ 19460,
  /* 103 */ 21407,
  /* 104 */ 21407,
  /* 105 */ 21889,
  /* 106 */ 21889,
  /* 107 */   325,
  /* 108 */   325,
  /* 109 */   325,
  /* 110 */   325,
  /* 111 */   325,
  /* 112 */   344,
  /* 113 */   344,
  /* 114 */   344,
  /* 115 */  3471,
  /* 116 */  3471,
  /* 117 */  3471,
  /* 118 */  3471,
  /* 119 */  3472,
  /* 120 */  3472,
};

static const value_string qsig_str_operation[] = {

/*--- Included file: packet-qsig-table10.c ---*/
#line 1 "../../asn1/qsig/packet-qsig-table10.c"

/* --- Module General-Error-List --- --- ---                                  */

/* Unknown or empty loop list OPERATION */

/* --- Modules Manufacturer-specific-service-extension-class-asn1-97 PSS1-generic-parameters-definition-asn1-97 Addressing-Data-Elements-asn1-97 --- --- --- */

/* Unknown or empty loop list OPERATION */

/* --- Module Name-Operations-asn1-97 --- --- ---                             */

  {   0, "callingName" },
  {   1, "calledName" },
  {   2, "connectedName" },
  {   3, "busyName" },

/* --- Module Call-Diversion-Operations-asn1-97 --- --- ---                   */

  {  15, "activateDiversionQ" },
  {  16, "deactivateDiversionQ" },
  {  17, "interrogateDiversionQ" },
  {  18, "checkRestriction" },
  {  19, "callRerouteing" },
  {  20, "divertingLegInformation1" },
  {  21, "divertingLegInformation2" },
  {  22, "divertingLegInformation3" },
  {  23, "cfnrDivertedLegFailed" },

/* --- Module Path-Replacement-Operations-asn1-97 --- --- ---                 */

  {  86, "pathReplaceInvite" },
  {   4, "pathReplacePropose" },
  {   5, "pathReplaceSetup" },
  {   6, "pathReplaceRetain" },

/* --- Module Call-Transfer-Operations-asn1-97 --- --- ---                    */

  {   7, "callTransferIdentify" },
  {   8, "callTransferAbandon" },
  {   9, "callTransferInitiate" },
  {  10, "callTransferSetup" },
  {  11, "callTransferActive" },
  {  12, "callTransferComplete" },
  {  13, "callTransferUpdate" },
  {  14, "subaddressTransfer" },

/* --- Module SS-CC-Operations-asn1-97 --- --- ---                            */

  {  40, "ccbsRequest" },
  {  27, "ccnrRequest" },
  {  28, "ccCancel" },
  {  29, "ccExecPossible" },
  {  30, "ccPathReserve" },
  {  31, "ccRingout" },
  {  32, "ccSuspend" },
  {  33, "ccResume" },

/* --- Module Call-Offer-Operations-asn1-97 --- --- ---                       */

  {  41, "pathRetain" },
  {  42, "serviceAvailable" },
  {  34, "callOfferRequest" },
  {  49, "cfbOverride" },

/* --- Module Do-Not-Disturb-Operations-asn1-97 --- --- ---                   */

  {  35, "doNotDisturbActivateQ" },
  {  36, "doNotDisturbDeactivateQ" },
  {  37, "doNotDisturbInterrogateQ" },
  {  38, "doNotDisturbOverrideQ" },
  {  41, "pathRetain" },
  {  42, "serviceAvailable" },
  {  39, "doNotDisturbOvrExecuteQ" },

/* --- Module Call-Intrusion-Operations-asn1-97 --- --- ---                   */

  {  41, "pathRetain" },
  {  42, "serviceAvailable" },
  {  43, "callIntrusionRequest" },
  {  44, "callIntrusionGetCIPL" },
  {  46, "callIntrusionForcedRelease" },
  {  45, "callIntrusionIsolate" },
  {  47, "callIntrusionWOBRequest" },
  {  48, "callIntrusionCompleted" },
  {  49, "cfbOverride" },

/* --- Module SS-AOC-Operations-asn1-97 --- --- ---                           */

  {  63, "aocRate" },
  {  62, "aocInterim" },
  {  61, "aocFinal" },
  {  59, "chargeRequest" },
  {  60, "getFinalCharge" },
  {  64, "aocComplete" },
  {  65, "aocDivChargeReq" },

/* --- Module Recall-Operations-asn1-97 --- --- ---                           */

  {  57, "recallAlerting" },
  {  58, "recallAnswered" },

/* --- Module Synchronization-Operations-asn1-97 --- --- ---                  */

  {  78, "synchronizationRequest" },
  {  79, "synchronizationInfo" },

/* --- Module Call-Interception-Operations-asn1-97 --- --- ---                */

  {  66, "cintLegInformation1" },
  {  67, "cintLegInformation2" },
  {  68, "cintCondition" },
  {  69, "cintDisable" },
  {  70, "cintEnable" },

/* --- Module Common-Information-Operations-asn1-97 --- --- ---               */

  {  84, "cmnRequest" },
  {  85, "cmnInform" },

/* --- Module Call-Interruption-Operations-asn1-97 --- --- ---                */

  {  87, "callInterruptionRequest" },
  {  88, "callProtectionRequest" },

/* --- Module PUM-Registration-Operations-asn1-97 --- --- ---                 */

  {  89, "pumRegistr" },
  {  90, "pumDelReg" },
  {  91, "pumDe-reg" },
  {  92, "pumInterrog" },

/* --- Module Private-User-Mobility-Call-Handling-Operations-asn1-97 --- --- --- */

  {  93, "pumiEnquiry" },
  {  94, "pumiDivert" },
  {  95, "pumiInform" },
  {  96, "pumoCall" },

/* --- Module Single-Step-Call-Transfer-Operations-asn1-97 --- --- ---        */

  {  99, "ssctInitiate" },
  { 100, "ssctSetup" },
  { 101, "ssctPostDial" },
  { 102, "ssctDigitInfo" },

/* --- Module WTM-Location-Registration-Operations-asn1-97 --- --- ---        */

  {  50, "locUpdate" },
  {  51, "locDelete" },
  {  52, "locDeReg" },
  {  53, "pisnEnquiry" },
  {  97, "getRRCInf" },
  {  98, "locInfoCheck" },

/* --- Module Wireless-Terminal-Call-Handling-Operations-asn1-97 --- --- ---  */

  {  54, "wtmiEnquiry" },
  {  55, "wtmiDivert" },
  {  56, "wtmiInform" },
  {  71, "wtmoCall" },

/* --- Module WTM-Authentication-Operations-asn1-97 --- --- ---               */

  {  72, "authWtmUser" },
  {  73, "getWtatParam" },
  {  74, "wtatParamEnq" },
  {  75, "getWtanParam" },
  {  76, "wtanParamEnq" },
  {  77, "transferAuthParam" },

/* --- Module SS-SD-Operations-asn1-97 --- --- ---                            */

  { 103, "display" },
  { 104, "keypad" },

/* --- Module Call-Identification-and-Call-Linkage-Operations-asn1-97 --- --- --- */

  { 105, "callIdentificationAssign" },
  { 106, "callIdentificationUpdate" },

/* --- Module Short-Message-Service-Operations-asn1-97 --- --- ---            */

  { 107, "smsSubmit" },
  { 108, "smsDeliver" },
  { 109, "smsStatusReport" },
  { 110, "smsCommand" },
  { 111, "scAlert" },

/* --- Module SS-MCR-Operations-asn97 --- --- ---                             */

  { 112, "mCRequest" },
  { 113, "mCInform" },
  { 114, "mCAlerting" },

/* --- Module SS-MCM-Operations-asn1-97 --- --- ---                           */

  {  80, "mCMNewMsg" },
  {  81, "mCMNoNewMsg" },
  { 115, "mCMUpdate" },
  {  82, "mCMUpdateReq" },
  { 116, "mCMService" },
  { 117, "mCMInterrogate" },
  { 118, "mCMailboxFull" },

/* --- Module SS-MID-Operations-asn1-97 --- --- ---                           */

  { 119, "mIDMailboxAuth" },
  { 120, "mIDMailboxID" },

/*--- End of included file: packet-qsig-table10.c ---*/
#line 271 "../../asn1/qsig/packet-qsig-template.c"
  {   0, NULL}
};

static const value_string qsig_str_error[] = {

/*--- Included file: packet-qsig-table20.c ---*/
#line 1 "../../asn1/qsig/packet-qsig-table20.c"

/* --- Module General-Error-List --- --- ---                                  */

  {    0, "userNotSubscribed" },
  {    1, "rejectedByNetwork" },
  {    2, "rejectedByUser" },
  {    3, "notAvailable" },
  {    5, "insufficientInformation" },
  {    6, "invalidServedUserNr" },
  {    7, "invalidCallState" },
  {    8, "basicServiceNotProvided" },
  {    9, "notIncomingCall" },
  {   10, "supplementaryServiceInteractionNotAllowed" },
  {   11, "resourceUnavailable" },
  {   25, "callFailure" },
  {   43, "proceduralError" },

/* --- Modules Manufacturer-specific-service-extension-class-asn1-97 PSS1-generic-parameters-definition-asn1-97 Addressing-Data-Elements-asn1-97 --- --- --- */

/* Unknown or empty loop list ERROR */

/* --- Module Name-Operations-asn1-97 --- --- ---                             */

/* Unknown or empty loop list ERROR */

/* --- Module Call-Diversion-Operations-asn1-97 --- --- ---                   */

  {   12, "invalidDivertedToNr" },
  {   14, "specialServiceNr" },
  {   15, "diversionToServedUserNr" },
  {   24, "numberOfDiversionsExceeded" },
  { 1000, "temporarilyUnavailable" },
  { 1007, "notAuthorized" },
  { 1008, "unspecified" },

/* --- Module Path-Replacement-Operations-asn1-97 --- --- ---                 */

  { 1000, "temporarilyUnavailable" },
  { 1001, "collision" },
  { 1002, "criteriaPermanentlyUnachievable" },
  { 1003, "criteriaTemporarilyUnachievable" },
  { 1004, "invalidRerouteingNumber" },
  { 1005, "unrecognizedCallIdentity" },
  { 1006, "establishmentFailure" },
  { 1008, "unspecified" },

/* --- Module Call-Transfer-Operations-asn1-97 --- --- ---                    */

  { 1008, "unspecified" },
  { 1004, "invalidRerouteingNumber" },
  { 1005, "unrecognizedCallIdentity" },
  { 1006, "establishmentFailure" },

/* --- Module SS-CC-Operations-asn1-97 --- --- ---                            */

  { 1008, "unspecified" },
  { 1010, "shortTermRejection" },
  { 1011, "longTermRejection" },
  { 1012, "remoteUserBusyAgain" },
  { 1013, "failureToMatch" },
  { 1014, "failedDueToInterworking" },

/* --- Module Call-Offer-Operations-asn1-97 --- --- ---                       */

  { 1009, "notBusy" },
  { 1000, "temporarilyUnavailable" },
  { 1008, "unspecified" },

/* --- Module Do-Not-Disturb-Operations-asn1-97 --- --- ---                   */

  { 1000, "temporarilyUnavailable" },
  {   43, "notActivated" },
  { 1008, "unspecified" },

/* --- Module Call-Intrusion-Operations-asn1-97 --- --- ---                   */

  { 1009, "notBusy" },
  { 1000, "temporarilyUnavailable" },
  { 1007, "notAuthorized" },
  { 1008, "unspecified" },

/* --- Module SS-AOC-Operations-asn1-97 --- --- ---                           */

  { 1008, "unspecified" },
  { 1016, "freeOfCharge" },

/* --- Module Recall-Operations-asn1-97 --- --- ---                           */

/* Unknown or empty loop list ERROR */

/* --- Module Synchronization-Operations-asn1-97 --- --- ---                  */

  { 1008, "unspecified" },

/* --- Module Call-Interception-Operations-asn1-97 --- --- ---                */

/* Unknown or empty loop list ERROR */

/* --- Module Common-Information-Operations-asn1-97 --- --- ---               */

/* Unknown or empty loop list ERROR */

/* --- Module Call-Interruption-Operations-asn1-97 --- --- ---                */

/* Unknown or empty loop list ERROR */

/* --- Module PUM-Registration-Operations-asn1-97 --- --- ---                 */

  { 1008, "unspecified" },
  { 1007, "notAuthorized" },
  { 1000, "temporarilyUnavailable" },
  { 1019, "pumUserNotSubscribedToThisServiceOpt" },
  { 1020, "pumUserFailedAuthentication" },
  { 1021, "hostingAddrInvalid" },
  { 1022, "pumUserNotRegistered" },

/* --- Module Private-User-Mobility-Call-Handling-Operations-asn1-97 --- --- --- */

  { 1015, "locationNotKnown" },
  { 1008, "unspecified" },

/* --- Module Single-Step-Call-Transfer-Operations-asn1-97 --- --- ---        */

  { 1008, "unspecified" },

/* --- Module WTM-Location-Registration-Operations-asn1-97 --- --- ---        */

  { 1007, "notAuthorized" },
  { 1000, "temporarilyUnavailable" },
  { 1008, "unspecified" },

/* --- Module Wireless-Terminal-Call-Handling-Operations-asn1-97 --- --- ---  */

  { 1008, "unspecified" },
  { 1015, "locationNotKnown" },

/* --- Module WTM-Authentication-Operations-asn1-97 --- --- ---               */

  { 1007, "notAuthorized" },
  { 1017, "paramNotAvailable" },
  { 1000, "temporarilyUnavailable" },
  { 1008, "unspecified" },

/* --- Module SS-SD-Operations-asn1-97 --- --- ---                            */

  { 1008, "unspecified" },
  { 1023, "noDisplayAvailable" },
  { 1024, "displayTemporarilyNotAvailable" },
  { 1025, "notPresentable" },

/* --- Module Call-Identification-and-Call-Linkage-Operations-asn1-97 --- --- --- */

/* Unknown or empty loop list ERROR */

/* --- Module Short-Message-Service-Operations-asn1-97 --- --- ---            */

  { 1026, "smsDeliverError" },
  { 1027, "smsSubmitError" },
  { 1028, "smsStatusReportError" },
  { 1029, "smsCommandError" },
  { 1008, "unspecified" },

/* --- Module SS-MCR-Operations-asn97 --- --- ---                             */

  { 1030, "invalidDestinationNumber" },
  { 1031, "invalidCooperationNumber" },
  { 1032, "mCRequestNotAllowed" },
  { 1033, "mCExecutionNotAllowed" },
  { 1034, "mCDestUserBusy" },
  { 1035, "mCCoopUserBusy" },
  { 1036, "mCCoopUserRejected" },
  { 1008, "unspecified" },

/* --- Module SS-MCM-Operations-asn1-97 --- --- ---                           */

  { 1037, "mCMModeNotProvided" },
  { 1008, "unspecified" },

/* --- Module SS-MID-Operations-asn1-97 --- --- ---                           */

  { 1039, "invalidMailbox" },
  { 1040, "authorizationFailed" },
  { 1008, "unspecified" },

/*--- End of included file: packet-qsig-table20.c ---*/
#line 276 "../../asn1/qsig/packet-qsig-template.c"
  {   0, NULL}
};

/* Initialize the protocol and registered fields */
static int proto_qsig = -1;
static int hf_qsig_operation = -1;
static int hf_qsig_service = -1;
static int hf_qsig_error = -1;
static int hf_qsig_ie_type = -1;
static int hf_qsig_ie_type_cs4 = -1;
static int hf_qsig_ie_type_cs5 = -1;
static int hf_qsig_ie_len = -1;
static int hf_qsig_ie_data = -1;
static int hf_qsig_tc = -1;
static int hf_qsig_pc = -1;

/*--- Included file: packet-qsig-hf.c ---*/
#line 1 "../../asn1/qsig/packet-qsig-hf.c"

/* --- Modules Manufacturer-specific-service-extension-class-asn1-97 PSS1-generic-parameters-definition-asn1-97 Addressing-Data-Elements-asn1-97 --- --- --- */

static int hf_qsig_extensionId = -1;              /* T_extensionId */
static int hf_qsig_extensionArgument = -1;        /* T_extensionArgument */
static int hf_qsig_presentationAllowedAddressS = -1;  /* AddressScreened */
static int hf_qsig_presentationRestricted = -1;   /* NULL */
static int hf_qsig_numberNotAvailableDueToInterworking = -1;  /* NULL */
static int hf_qsig_presentationRestrictedAddressS = -1;  /* AddressScreened */
static int hf_qsig_presentationAllowedAddressU = -1;  /* Address */
static int hf_qsig_presentationRestrictedAddressU = -1;  /* Address */
static int hf_qsig_presentationAllowedAddressNS = -1;  /* NumberScreened */
static int hf_qsig_presentationRestrictedAddressNS = -1;  /* NumberScreened */
static int hf_qsig_presentationAllowedAddressNU = -1;  /* PartyNumber */
static int hf_qsig_presentationRestrictedAddressNU = -1;  /* PartyNumber */
static int hf_qsig_partyNumber = -1;              /* PartyNumber */
static int hf_qsig_screeningIndicator = -1;       /* ScreeningIndicator */
static int hf_qsig_partySubaddress = -1;          /* PartySubaddress */
static int hf_qsig_unknownPartyNumber = -1;       /* NumberDigits */
static int hf_qsig_publicPartyNumber = -1;        /* PublicPartyNumber */
static int hf_qsig_dataPartyNumber = -1;          /* NumberDigits */
static int hf_qsig_telexPartyNumber = -1;         /* NumberDigits */
static int hf_qsig_privatePartyNumber = -1;       /* PrivatePartyNumber */
static int hf_qsig_nationalStandardPartyNumber = -1;  /* NumberDigits */
static int hf_qsig_publicTypeOfNumber = -1;       /* PublicTypeOfNumber */
static int hf_qsig_publicNumberDigits = -1;       /* NumberDigits */
static int hf_qsig_privateTypeOfNumber = -1;      /* PrivateTypeOfNumber */
static int hf_qsig_privateNumberDigits = -1;      /* NumberDigits */
static int hf_qsig_userSpecifiedSubaddress = -1;  /* UserSpecifiedSubaddress */
static int hf_qsig_nSAPSubaddress = -1;           /* NSAPSubaddress */
static int hf_qsig_subaddressInformation = -1;    /* SubaddressInformation */
static int hf_qsig_oddCountIndicator = -1;        /* BOOLEAN */

/* --- Module Name-Operations-asn1-97 --- --- ---                             */

static int hf_qsig_na_qsig_na_NameArg_PDU = -1;   /* NameArg */
static int hf_qsig_na_name = -1;                  /* Name */
static int hf_qsig_na_nameSequence = -1;          /* T_nameSequence */
static int hf_qsig_na_extensionNA = -1;           /* NameExtension */
static int hf_qsig_na_single = -1;                /* Extension */
static int hf_qsig_na_multiple = -1;              /* SEQUENCE_OF_Extension */
static int hf_qsig_na_multiple_item = -1;         /* Extension */
static int hf_qsig_na_namePresentationAllowed = -1;  /* NamePresentationAllowed */
static int hf_qsig_na_namePresentationRestricted = -1;  /* NamePresentationRestricted */
static int hf_qsig_na_nameNotAvailable = -1;      /* NameNotAvailable */
static int hf_qsig_na_namePresentationAllowedSimple = -1;  /* NameData */
static int hf_qsig_na_namePresentationAllowedExtended = -1;  /* NameSet */
static int hf_qsig_na_namePresentationRestrictedSimple = -1;  /* NameData */
static int hf_qsig_na_namePresentationRestrictedExtended = -1;  /* NameSet */
static int hf_qsig_na_namePresentationRestrictedNull = -1;  /* NULL */
static int hf_qsig_na_nameData = -1;              /* NameData */
static int hf_qsig_na_characterSet = -1;          /* CharacterSet */

/* --- Module Call-Diversion-Operations-asn1-97 --- --- ---                   */

static int hf_qsig_cf_qsig_cf_ARG_activateDiversionQ_PDU = -1;  /* ARG_activateDiversionQ */
static int hf_qsig_cf_qsig_cf_RES_activateDiversionQ_PDU = -1;  /* RES_activateDiversionQ */
static int hf_qsig_cf_qsig_cf_ARG_deactivateDiversionQ_PDU = -1;  /* ARG_deactivateDiversionQ */
static int hf_qsig_cf_qsig_cf_RES_deactivateDiversionQ_PDU = -1;  /* RES_deactivateDiversionQ */
static int hf_qsig_cf_qsig_cf_ARG_interrogateDiversionQ_PDU = -1;  /* ARG_interrogateDiversionQ */
static int hf_qsig_cf_qsig_cf_IntResultList_PDU = -1;  /* IntResultList */
static int hf_qsig_cf_qsig_cf_ARG_checkRestriction_PDU = -1;  /* ARG_checkRestriction */
static int hf_qsig_cf_qsig_cf_RES_checkRestriction_PDU = -1;  /* RES_checkRestriction */
static int hf_qsig_cf_qsig_cf_ARG_callRerouteing_PDU = -1;  /* ARG_callRerouteing */
static int hf_qsig_cf_qsig_cf_RES_callRerouteing_PDU = -1;  /* RES_callRerouteing */
static int hf_qsig_cf_qsig_cf_ARG_divertingLegInformation1_PDU = -1;  /* ARG_divertingLegInformation1 */
static int hf_qsig_cf_qsig_cf_ARG_divertingLegInformation2_PDU = -1;  /* ARG_divertingLegInformation2 */
static int hf_qsig_cf_qsig_cf_ARG_divertingLegInformation3_PDU = -1;  /* ARG_divertingLegInformation3 */
static int hf_qsig_cf_qsig_cf_ARG_cfnrDivertedLegFailed_PDU = -1;  /* ARG_cfnrDivertedLegFailed */
static int hf_qsig_cf_qsig_cf_Extension_PDU = -1;  /* Extension */
static int hf_qsig_cf_procedure = -1;             /* Procedure */
static int hf_qsig_cf_basicService = -1;          /* BasicService */
static int hf_qsig_cf_divertedToAddress = -1;     /* Address */
static int hf_qsig_cf_servedUserNr = -1;          /* PartyNumber */
static int hf_qsig_cf_activatingUserNr = -1;      /* PartyNumber */
static int hf_qsig_cf_extensionAD = -1;           /* ADExtension */
static int hf_qsig_cf_single = -1;                /* Extension */
static int hf_qsig_cf_multiple = -1;              /* SEQUENCE_OF_Extension */
static int hf_qsig_cf_multiple_item = -1;         /* Extension */
static int hf_qsig_cf_null = -1;                  /* NULL */
static int hf_qsig_cf_deactivatingUserNr = -1;    /* PartyNumber */
static int hf_qsig_cf_extensionDD = -1;           /* DDExtension */
static int hf_qsig_cf_interrogatingUserNr = -1;   /* PartyNumber */
static int hf_qsig_cf_extensionID = -1;           /* IDExtension */
static int hf_qsig_cf_divertedToNr = -1;          /* PartyNumber */
static int hf_qsig_cf_extensionCHR = -1;          /* CHRExtension */
static int hf_qsig_cf_rerouteingReason = -1;      /* DiversionReason */
static int hf_qsig_cf_originalRerouteingReason = -1;  /* DiversionReason */
static int hf_qsig_cf_calledAddress = -1;         /* Address */
static int hf_qsig_cf_diversionCounter = -1;      /* INTEGER_1_15 */
static int hf_qsig_cf_pSS1InfoElement = -1;       /* PSS1InformationElement */
static int hf_qsig_cf_lastRerouteingNr = -1;      /* PresentedNumberUnscreened */
static int hf_qsig_cf_subscriptionOption = -1;    /* SubscriptionOption */
static int hf_qsig_cf_callingPartySubaddress = -1;  /* PartySubaddress */
static int hf_qsig_cf_callingNumber = -1;         /* PresentedNumberScreened */
static int hf_qsig_cf_callingName = -1;           /* Name */
static int hf_qsig_cf_originalCalledNr = -1;      /* PresentedNumberUnscreened */
static int hf_qsig_cf_redirectingName = -1;       /* Name */
static int hf_qsig_cf_originalCalledName = -1;    /* Name */
static int hf_qsig_cf_extensionCRR = -1;          /* CRRExtension */
static int hf_qsig_cf_diversionReason = -1;       /* DiversionReason */
static int hf_qsig_cf_nominatedNr = -1;           /* PartyNumber */
static int hf_qsig_cf_extensionDLI1 = -1;         /* DLI1Extension */
static int hf_qsig_cf_originalDiversionReason = -1;  /* DiversionReason */
static int hf_qsig_cf_divertingNr = -1;           /* PresentedNumberUnscreened */
static int hf_qsig_cf_extensionDLI2 = -1;         /* DLI2Extension */
static int hf_qsig_cf_presentationAllowedIndicator = -1;  /* PresentationAllowedIndicator */
static int hf_qsig_cf_redirectionName = -1;       /* Name */
static int hf_qsig_cf_extensionDLI3 = -1;         /* DLI3Extension */
static int hf_qsig_cf_IntResultList_item = -1;    /* IntResult */
static int hf_qsig_cf_remoteEnabled = -1;         /* BOOLEAN */
static int hf_qsig_cf_extensionIR = -1;           /* IRExtension */

/* --- Module Path-Replacement-Operations-asn1-97 --- --- ---                 */

static int hf_qsig_pr_qsig_pr_DummyArg_PDU = -1;  /* DummyArg */
static int hf_qsig_pr_qsig_pr_PRProposeArg_PDU = -1;  /* PRProposeArg */
static int hf_qsig_pr_qsig_pr_PRSetupArg_PDU = -1;  /* PRSetupArg */
static int hf_qsig_pr_qsig_pr_DummyResult_PDU = -1;  /* DummyResult */
static int hf_qsig_pr_qsig_pr_PRRetainArg_PDU = -1;  /* PRRetainArg */
static int hf_qsig_pr_qsig_pr_Extension_PDU = -1;  /* Extension */
static int hf_qsig_pr_callIdentity = -1;          /* CallIdentity */
static int hf_qsig_pr_rerouteingNumber = -1;      /* PartyNumber */
static int hf_qsig_pr_extensionPRP = -1;          /* PRPExtension */
static int hf_qsig_pr_single = -1;                /* Extension */
static int hf_qsig_pr_multiple = -1;              /* SEQUENCE_OF_Extension */
static int hf_qsig_pr_multiple_item = -1;         /* Extension */
static int hf_qsig_pr_extensionPRS = -1;          /* PRSExtension */
static int hf_qsig_pr_extensionPRR = -1;          /* PRRExtension */
static int hf_qsig_pr_null = -1;                  /* NULL */

/* --- Module Call-Transfer-Operations-asn1-97 --- --- ---                    */

static int hf_qsig_ct_qsig_ct_DummyArg_PDU = -1;  /* DummyArg */
static int hf_qsig_ct_qsig_ct_CTIdentifyRes_PDU = -1;  /* CTIdentifyRes */
static int hf_qsig_ct_qsig_ct_CTInitiateArg_PDU = -1;  /* CTInitiateArg */
static int hf_qsig_ct_qsig_ct_DummyRes_PDU = -1;  /* DummyRes */
static int hf_qsig_ct_qsig_ct_CTSetupArg_PDU = -1;  /* CTSetupArg */
static int hf_qsig_ct_qsig_ct_CTActiveArg_PDU = -1;  /* CTActiveArg */
static int hf_qsig_ct_qsig_ct_CTCompleteArg_PDU = -1;  /* CTCompleteArg */
static int hf_qsig_ct_qsig_ct_CTUpdateArg_PDU = -1;  /* CTUpdateArg */
static int hf_qsig_ct_qsig_ct_SubaddressTransferArg_PDU = -1;  /* SubaddressTransferArg */
static int hf_qsig_ct_qsig_ct_Extension_PDU = -1;  /* Extension */
static int hf_qsig_ct_null = -1;                  /* NULL */
static int hf_qsig_ct_single = -1;                /* Extension */
static int hf_qsig_ct_multiple = -1;              /* SEQUENCE_OF_Extension */
static int hf_qsig_ct_multiple_item = -1;         /* Extension */
static int hf_qsig_ct_callIdentity = -1;          /* CallIdentity */
static int hf_qsig_ct_rerouteingNumber = -1;      /* PartyNumber */
static int hf_qsig_ct_resultExtension = -1;       /* T_resultExtension */
static int hf_qsig_ct_argumentExtensionCTI = -1;  /* CTIargumentExtension */
static int hf_qsig_ct_argumentExtensionCTS = -1;  /* CTSargumentExtension */
static int hf_qsig_ct_connectedAddress = -1;      /* PresentedAddressScreened */
static int hf_qsig_ct_basicCallInfoElements = -1;  /* PSS1InformationElement */
static int hf_qsig_ct_connectedName = -1;         /* Name */
static int hf_qsig_ct_argumentExtensionCTA = -1;  /* CTAargumentExtension */
static int hf_qsig_ct_endDesignation = -1;        /* EndDesignation */
static int hf_qsig_ct_redirectionNumber = -1;     /* PresentedNumberScreened */
static int hf_qsig_ct_redirectionName = -1;       /* Name */
static int hf_qsig_ct_callStatus = -1;            /* CallStatus */
static int hf_qsig_ct_argumentExtensionCTC = -1;  /* CTCargumentExtension */
static int hf_qsig_ct_argumentExtensionCTU = -1;  /* CTUargumentExtension */
static int hf_qsig_ct_redirectionSubaddress = -1;  /* PartySubaddress */
static int hf_qsig_ct_argumentExtensionST = -1;   /* STargumentExtension */

/* --- Module SS-CC-Operations-asn1-97 --- --- ---                            */

static int hf_qsig_cc_qsig_cc_CcRequestArg_PDU = -1;  /* CcRequestArg */
static int hf_qsig_cc_qsig_cc_CcRequestRes_PDU = -1;  /* CcRequestRes */
static int hf_qsig_cc_qsig_cc_CcOptionalArg_PDU = -1;  /* CcOptionalArg */
static int hf_qsig_cc_qsig_cc_CcExtension_PDU = -1;  /* CcExtension */
static int hf_qsig_cc_qsig_cc_Extension_PDU = -1;  /* Extension */
static int hf_qsig_cc_numberA = -1;               /* PresentedNumberUnscreened */
static int hf_qsig_cc_numberB = -1;               /* PartyNumber */
static int hf_qsig_cc_service = -1;               /* PSS1InformationElement */
static int hf_qsig_cc_subaddrA = -1;              /* PartySubaddress */
static int hf_qsig_cc_subaddrB = -1;              /* PartySubaddress */
static int hf_qsig_cc_can_retain_service = -1;    /* BOOLEAN */
static int hf_qsig_cc_retain_sig_connection = -1;  /* BOOLEAN */
static int hf_qsig_cc_extension = -1;             /* CcExtension */
static int hf_qsig_cc_no_path_reservation = -1;   /* BOOLEAN */
static int hf_qsig_cc_retain_service = -1;        /* BOOLEAN */
static int hf_qsig_cc_fullArg = -1;               /* T_fullArg */
static int hf_qsig_cc_numberA_01 = -1;            /* PartyNumber */
static int hf_qsig_cc_extArg = -1;                /* CcExtension */
static int hf_qsig_cc_none = -1;                  /* NULL */
static int hf_qsig_cc_single = -1;                /* Extension */
static int hf_qsig_cc_multiple = -1;              /* SEQUENCE_OF_Extension */
static int hf_qsig_cc_multiple_item = -1;         /* Extension */

/* --- Module Call-Offer-Operations-asn1-97 --- --- ---                       */

static int hf_qsig_co_qsig_co_PathRetainArg_PDU = -1;  /* PathRetainArg */
static int hf_qsig_co_qsig_co_ServiceAvailableArg_PDU = -1;  /* ServiceAvailableArg */
static int hf_qsig_co_qsig_co_DummyArg_PDU = -1;  /* DummyArg */
static int hf_qsig_co_qsig_co_DummyRes_PDU = -1;  /* DummyRes */
static int hf_qsig_co_qsig_co_Extension_PDU = -1;  /* Extension */
static int hf_qsig_co_serviceList = -1;           /* ServiceList */
static int hf_qsig_co_extendedServiceList = -1;   /* T_extendedServiceList */
static int hf_qsig_co_extension = -1;             /* Extension */
static int hf_qsig_co_extendedServiceList_01 = -1;  /* T_extendedServiceList_01 */
static int hf_qsig_co_null = -1;                  /* NULL */
static int hf_qsig_co_sequenceOfExtn = -1;        /* SEQUENCE_OF_Extension */
static int hf_qsig_co_sequenceOfExtn_item = -1;   /* Extension */
/* named bits */
static int hf_qsig_co_ServiceList_callOffer = -1;

/* --- Module Do-Not-Disturb-Operations-asn1-97 --- --- ---                   */

static int hf_qsig_dnd_qsig_dnd_DNDActivateArg_PDU = -1;  /* DNDActivateArg */
static int hf_qsig_dnd_qsig_dnd_DNDActivateRes_PDU = -1;  /* DNDActivateRes */
static int hf_qsig_dnd_qsig_dnd_DNDDeactivateArg_PDU = -1;  /* DNDDeactivateArg */
static int hf_qsig_dnd_qsig_dnd_DummyRes_PDU = -1;  /* DummyRes */
static int hf_qsig_dnd_qsig_dnd_DNDInterrogateArg_PDU = -1;  /* DNDInterrogateArg */
static int hf_qsig_dnd_qsig_dnd_DNDInterrogateRes_PDU = -1;  /* DNDInterrogateRes */
static int hf_qsig_dnd_qsig_dnd_DNDOverrideArg_PDU = -1;  /* DNDOverrideArg */
static int hf_qsig_dnd_qsig_dnd_PathRetainArg_PDU = -1;  /* PathRetainArg */
static int hf_qsig_dnd_qsig_dnd_ServiceAvailableArg_PDU = -1;  /* ServiceAvailableArg */
static int hf_qsig_dnd_qsig_dnd_DummyArg_PDU = -1;  /* DummyArg */
static int hf_qsig_dnd_qsig_dnd_Extension_PDU = -1;  /* Extension */
static int hf_qsig_dnd_null = -1;                 /* NULL */
static int hf_qsig_dnd_extension = -1;            /* Extension */
static int hf_qsig_dnd_sequenceOfExtn = -1;       /* SEQUENCE_OF_Extension */
static int hf_qsig_dnd_sequenceOfExtn_item = -1;  /* Extension */
static int hf_qsig_dnd_basicService = -1;         /* BasicService */
static int hf_qsig_dnd_servedUserNr = -1;         /* PartyNumber */
static int hf_qsig_dnd_argumentExtensionDNDA = -1;  /* DNDAargumentExtension */
static int hf_qsig_dnd_status = -1;               /* T_status */
static int hf_qsig_dnd_status_item = -1;          /* T_status_item */
static int hf_qsig_dnd_dndProtectionLevel = -1;   /* DNDProtectionLevel */
static int hf_qsig_dnd_resultExtension = -1;      /* T_resultExtension */
static int hf_qsig_dnd_argumentExtensionDNDD = -1;  /* DNDDargumentExtension */
static int hf_qsig_dnd_argumentExtensionDNDI = -1;  /* DNDIargumentExtension */
static int hf_qsig_dnd_status_01 = -1;            /* T_status_01 */
static int hf_qsig_dnd_status_item_01 = -1;       /* T_status_item_01 */
static int hf_qsig_dnd_resultExtension_01 = -1;   /* T_resultExtension_01 */
static int hf_qsig_dnd_dndoCapabilityLevel = -1;  /* DNDOCapabilityLevel */
static int hf_qsig_dnd_argumentExtensionDNDO = -1;  /* DNDOargumentExtension */
static int hf_qsig_dnd_serviceList = -1;          /* ServiceList */
static int hf_qsig_dnd_extendedServiceList = -1;  /* T_extendedServiceList */
static int hf_qsig_dnd_extendedServiceList_01 = -1;  /* T_extendedServiceList_01 */
/* named bits */
static int hf_qsig_dnd_ServiceList_dndo_low = -1;
static int hf_qsig_dnd_ServiceList_dndo_medium = -1;
static int hf_qsig_dnd_ServiceList_dndo_high = -1;

/* --- Module Call-Intrusion-Operations-asn1-97 --- --- ---                   */

static int hf_qsig_ci_qsig_ci_PathRetainArg_PDU = -1;  /* PathRetainArg */
static int hf_qsig_ci_qsig_ci_ServiceAvailableArg_PDU = -1;  /* ServiceAvailableArg */
static int hf_qsig_ci_qsig_ci_CIRequestArg_PDU = -1;  /* CIRequestArg */
static int hf_qsig_ci_qsig_ci_CIRequestRes_PDU = -1;  /* CIRequestRes */
static int hf_qsig_ci_qsig_ci_DummyArg_PDU = -1;  /* DummyArg */
static int hf_qsig_ci_qsig_ci_CIGetCIPLRes_PDU = -1;  /* CIGetCIPLRes */
static int hf_qsig_ci_qsig_ci_DummyRes_PDU = -1;  /* DummyRes */
static int hf_qsig_ci_qsig_ci_Extension_PDU = -1;  /* Extension */
static int hf_qsig_ci_serviceList = -1;           /* ServiceList */
static int hf_qsig_ci_extendedServiceList = -1;   /* T_extendedServiceList */
static int hf_qsig_ci_extension = -1;             /* Extension */
static int hf_qsig_ci_extendedServiceList_01 = -1;  /* T_extendedServiceList_01 */
static int hf_qsig_ci_null = -1;                  /* NULL */
static int hf_qsig_ci_sequenceOfExtn = -1;        /* SEQUENCE_OF_Extension */
static int hf_qsig_ci_sequenceOfExtn_item = -1;   /* Extension */
static int hf_qsig_ci_ciCapabilityLevel = -1;     /* CICapabilityLevel */
static int hf_qsig_ci_argumentExtension = -1;     /* T_argumentExtension */
static int hf_qsig_ci_ciUnwantedUserStatus = -1;  /* CIUnwantedUserStatus */
static int hf_qsig_ci_resultExtension = -1;       /* T_resultExtension */
static int hf_qsig_ci_ciProtectionLevel = -1;     /* CIProtectionLevel */
static int hf_qsig_ci_resultExtension_01 = -1;    /* T_resultExtension_01 */
/* named bits */
static int hf_qsig_ci_ServiceList_ci_low = -1;
static int hf_qsig_ci_ServiceList_ci_medium = -1;
static int hf_qsig_ci_ServiceList_ci_high = -1;

/* --- Module SS-AOC-Operations-asn1-97 --- --- ---                           */

static int hf_qsig_aoc_qsig_aoc_AocRateArg_PDU = -1;  /* AocRateArg */
static int hf_qsig_aoc_qsig_aoc_AocInterimArg_PDU = -1;  /* AocInterimArg */
static int hf_qsig_aoc_qsig_aoc_AocFinalArg_PDU = -1;  /* AocFinalArg */
static int hf_qsig_aoc_qsig_aoc_ChargeRequestArg_PDU = -1;  /* ChargeRequestArg */
static int hf_qsig_aoc_qsig_aoc_ChargeRequestRes_PDU = -1;  /* ChargeRequestRes */
static int hf_qsig_aoc_qsig_aoc_DummyArg_PDU = -1;  /* DummyArg */
static int hf_qsig_aoc_qsig_aoc_AocCompleteArg_PDU = -1;  /* AocCompleteArg */
static int hf_qsig_aoc_qsig_aoc_AocCompleteRes_PDU = -1;  /* AocCompleteRes */
static int hf_qsig_aoc_qsig_aoc_AocDivChargeReqArg_PDU = -1;  /* AocDivChargeReqArg */
static int hf_qsig_aoc_qsig_aoc_Extension_PDU = -1;  /* Extension */
static int hf_qsig_aoc_aocRate = -1;              /* T_aocRate */
static int hf_qsig_aoc_chargeNotAvailable = -1;   /* NULL */
static int hf_qsig_aoc_aocSCurrencyInfoList = -1;  /* AOCSCurrencyInfoList */
static int hf_qsig_aoc_rateArgExtension = -1;     /* T_rateArgExtension */
static int hf_qsig_aoc_extension = -1;            /* Extension */
static int hf_qsig_aoc_multipleExtension = -1;    /* SEQUENCE_OF_Extension */
static int hf_qsig_aoc_multipleExtension_item = -1;  /* Extension */
static int hf_qsig_aoc_interimCharge = -1;        /* T_interimCharge */
static int hf_qsig_aoc_freeOfCharge = -1;         /* NULL */
static int hf_qsig_aoc_specificCurrency = -1;     /* T_specificCurrency */
static int hf_qsig_aoc_recordedCurrency = -1;     /* RecordedCurrency */
static int hf_qsig_aoc_interimBillingId = -1;     /* InterimBillingId */
static int hf_qsig_aoc_interimArgExtension = -1;  /* T_interimArgExtension */
static int hf_qsig_aoc_finalCharge = -1;          /* T_finalCharge */
static int hf_qsig_aoc_specificCurrency_01 = -1;  /* T_specificCurrency_01 */
static int hf_qsig_aoc_finalBillingId = -1;       /* FinalBillingId */
static int hf_qsig_aoc_chargingAssociation = -1;  /* ChargingAssociation */
static int hf_qsig_aoc_finalArgExtension = -1;    /* T_finalArgExtension */
static int hf_qsig_aoc_AOCSCurrencyInfoList_item = -1;  /* AOCSCurrencyInfo */
static int hf_qsig_aoc_chargedItem = -1;          /* ChargedItem */
static int hf_qsig_aoc_rateType = -1;             /* T_rateType */
static int hf_qsig_aoc_durationCurrency = -1;     /* DurationCurrency */
static int hf_qsig_aoc_flatRateCurrency = -1;     /* FlatRateCurrency */
static int hf_qsig_aoc_volumeRateCurrency = -1;   /* VolumeRateCurrency */
static int hf_qsig_aoc_specialChargingCode = -1;  /* SpecialChargingCode */
static int hf_qsig_aoc_currencyInfoNotAvailable = -1;  /* NULL */
static int hf_qsig_aoc_freeOfChargefromBeginning = -1;  /* NULL */
static int hf_qsig_aoc_dCurrency = -1;            /* Currency */
static int hf_qsig_aoc_dAmount = -1;              /* Amount */
static int hf_qsig_aoc_dChargingType = -1;        /* ChargingType */
static int hf_qsig_aoc_dTime = -1;                /* Time */
static int hf_qsig_aoc_dGranularity = -1;         /* Time */
static int hf_qsig_aoc_fRCurrency = -1;           /* Currency */
static int hf_qsig_aoc_fRAmount = -1;             /* Amount */
static int hf_qsig_aoc_vRCurrency = -1;           /* Currency */
static int hf_qsig_aoc_vRAmount = -1;             /* Amount */
static int hf_qsig_aoc_vRVolumeUnit = -1;         /* VolumeUnit */
static int hf_qsig_aoc_rCurrency = -1;            /* Currency */
static int hf_qsig_aoc_rAmount = -1;              /* Amount */
static int hf_qsig_aoc_currencyAmount = -1;       /* CurrencyAmount */
static int hf_qsig_aoc_multiplier = -1;           /* Multiplier */
static int hf_qsig_aoc_lengthOfTimeUnit = -1;     /* LengthOfTimeUnit */
static int hf_qsig_aoc_scale = -1;                /* Scale */
static int hf_qsig_aoc_chargeNumber = -1;         /* PartyNumber */
static int hf_qsig_aoc_chargeIdentifier = -1;     /* ChargeIdentifier */
static int hf_qsig_aoc_adviceModeCombinations = -1;  /* SEQUENCE_SIZE_0_7_OF_AdviceModeCombination */
static int hf_qsig_aoc_adviceModeCombinations_item = -1;  /* AdviceModeCombination */
static int hf_qsig_aoc_chargeReqArgExtension = -1;  /* T_chargeReqArgExtension */
static int hf_qsig_aoc_adviceModeCombination = -1;  /* AdviceModeCombination */
static int hf_qsig_aoc_chargeReqResExtension = -1;  /* T_chargeReqResExtension */
static int hf_qsig_aoc_none = -1;                 /* NULL */
static int hf_qsig_aoc_chargedUser = -1;          /* PartyNumber */
static int hf_qsig_aoc_completeArgExtension = -1;  /* T_completeArgExtension */
static int hf_qsig_aoc_chargingOption = -1;       /* ChargingOption */
static int hf_qsig_aoc_completeResExtension = -1;  /* T_completeResExtension */
static int hf_qsig_aoc_divertingUser = -1;        /* PartyNumber */
static int hf_qsig_aoc_diversionType = -1;        /* DiversionType */
static int hf_qsig_aoc_aocDivChargeReqArgExt = -1;  /* T_aocDivChargeReqArgExt */

/* --- Module Recall-Operations-asn1-97 --- --- ---                           */

static int hf_qsig_re_qsig_re_ReAlertingArg_PDU = -1;  /* ReAlertingArg */
static int hf_qsig_re_qsig_re_ReAnswerArg_PDU = -1;  /* ReAnswerArg */
static int hf_qsig_re_alertedNumber = -1;         /* PresentedNumberScreened */
static int hf_qsig_re_alertedName = -1;           /* Name */
static int hf_qsig_re_argumentExtension = -1;     /* T_argumentExtension */
static int hf_qsig_re_extension = -1;             /* Extension */
static int hf_qsig_re_multipleExtension = -1;     /* SEQUENCE_OF_Extension */
static int hf_qsig_re_multipleExtension_item = -1;  /* Extension */
static int hf_qsig_re_connectedNumber = -1;       /* PresentedNumberScreened */
static int hf_qsig_re_connectedSubaddress = -1;   /* PartySubaddress */
static int hf_qsig_re_connectedName = -1;         /* Name */
static int hf_qsig_re_argumentExtension_01 = -1;  /* T_argumentExtension_01 */

/* --- Module Synchronization-Operations-asn1-97 --- --- ---                  */

static int hf_qsig_sync_qsig_sync_SynchronizationReqArg_PDU = -1;  /* SynchronizationReqArg */
static int hf_qsig_sync_qsig_sync_SynchronizationReqRes_PDU = -1;  /* SynchronizationReqRes */
static int hf_qsig_sync_qsig_sync_SynchronizationInfoArg_PDU = -1;  /* SynchronizationInfoArg */
static int hf_qsig_sync_qsig_sync_Extension_PDU = -1;  /* Extension */
static int hf_qsig_sync_action = -1;              /* Action */
static int hf_qsig_sync_argExtension = -1;        /* ArgExtension */
static int hf_qsig_sync_response = -1;            /* BOOLEAN */
static int hf_qsig_sync_stateinfo = -1;           /* T_stateinfo */
static int hf_qsig_sync_extension = -1;           /* Extension */
static int hf_qsig_sync_sequOfExtn = -1;          /* SEQUENCE_OF_Extension */
static int hf_qsig_sync_sequOfExtn_item = -1;     /* Extension */

/* --- Module Call-Interception-Operations-asn1-97 --- --- ---                */

static int hf_qsig_cint_qsig_cint_CintInformation1Arg_PDU = -1;  /* CintInformation1Arg */
static int hf_qsig_cint_qsig_cint_CintInformation2Arg_PDU = -1;  /* CintInformation2Arg */
static int hf_qsig_cint_qsig_cint_CintCondArg_PDU = -1;  /* CintCondArg */
static int hf_qsig_cint_qsig_cint_CintExtension_PDU = -1;  /* CintExtension */
static int hf_qsig_cint_interceptionCause = -1;   /* CintCause */
static int hf_qsig_cint_interceptedToNumber = -1;  /* PartyNumber */
static int hf_qsig_cint_extension = -1;           /* CintExtension */
static int hf_qsig_cint_calledNumber = -1;        /* PresentedNumberUnscreened */
static int hf_qsig_cint_originalCalledNumber = -1;  /* PresentedNumberUnscreened */
static int hf_qsig_cint_calledName = -1;          /* Name */
static int hf_qsig_cint_originalCalledName = -1;  /* Name */
static int hf_qsig_cint_interceptionCause_01 = -1;  /* Condition */
static int hf_qsig_cint_none = -1;                /* NULL */
static int hf_qsig_cint_single = -1;              /* Extension */
static int hf_qsig_cint_multiple = -1;            /* SEQUENCE_OF_Extension */
static int hf_qsig_cint_multiple_item = -1;       /* Extension */

/* --- Module Common-Information-Operations-asn1-97 --- --- ---               */

static int hf_qsig_cmn_qsig_cmn_DummyArg_PDU = -1;  /* DummyArg */
static int hf_qsig_cmn_qsig_cmn_CmnArg_PDU = -1;  /* CmnArg */
static int hf_qsig_cmn_featureIdentifier = -1;    /* FeatureIdList */
static int hf_qsig_cmn_ssDNDOprotectionLevel = -1;  /* INTEGER_0_3 */
static int hf_qsig_cmn_ssCIprotectionLevel = -1;  /* INTEGER_0_3 */
static int hf_qsig_cmn_equipmentIdentity = -1;    /* EquipmentId */
static int hf_qsig_cmn_partyCategory = -1;        /* PartyCategory */
static int hf_qsig_cmn_extension = -1;            /* T_extension */
static int hf_qsig_cmn_single = -1;               /* Extension */
static int hf_qsig_cmn_multiple = -1;             /* SEQUENCE_OF_Extension */
static int hf_qsig_cmn_multiple_item = -1;        /* Extension */
static int hf_qsig_cmn_null = -1;                 /* NULL */
static int hf_qsig_cmn_nodeId = -1;               /* IA5String_SIZE_1_10 */
static int hf_qsig_cmn_groupId = -1;              /* IA5String_SIZE_1_10 */
static int hf_qsig_cmn_unitId = -1;               /* IA5String_SIZE_1_10 */
/* named bits */
static int hf_qsig_cmn_FeatureIdList_reserved = -1;
static int hf_qsig_cmn_FeatureIdList_ssCFreRoutingSupported = -1;
static int hf_qsig_cmn_FeatureIdList_ssCTreRoutingSupported = -1;
static int hf_qsig_cmn_FeatureIdList_ssCCBSpossible = -1;
static int hf_qsig_cmn_FeatureIdList_ssCCNRpossible = -1;
static int hf_qsig_cmn_FeatureIdList_ssCOsupported = -1;
static int hf_qsig_cmn_FeatureIdList_ssCIforcedRelease = -1;
static int hf_qsig_cmn_FeatureIdList_ssCIisolation = -1;
static int hf_qsig_cmn_FeatureIdList_ssCIwaitOnBusy = -1;
static int hf_qsig_cmn_FeatureIdList_ssAOCsupportChargeRateProvAtGatewPinx = -1;
static int hf_qsig_cmn_FeatureIdList_ssAOCsupportInterimChargeProvAtGatewPinx = -1;
static int hf_qsig_cmn_FeatureIdList_ssAOCsupportFinalChargeProvAtGatewPinx = -1;
static int hf_qsig_cmn_FeatureIdList_anfPRsupportedAtCooperatingPinx = -1;
static int hf_qsig_cmn_FeatureIdList_anfCINTcanInterceptImmediate = -1;
static int hf_qsig_cmn_FeatureIdList_anfCINTcanInterceptDelayed = -1;
static int hf_qsig_cmn_FeatureIdList_anfWTMIreRoutingSupported = -1;
static int hf_qsig_cmn_FeatureIdList_anfPUMIreRoutingSupported = -1;
static int hf_qsig_cmn_FeatureIdList_ssSSCTreRoutingSupported = -1;

/* --- Module Call-Interruption-Operations-asn1-97 --- --- ---                */

static int hf_qsig_cpi_qsig_cpi_CPIRequestArg_PDU = -1;  /* CPIRequestArg */
static int hf_qsig_cpi_qsig_cpi_CPIPRequestArg_PDU = -1;  /* CPIPRequestArg */
static int hf_qsig_cpi_cpiCapabilityLevel = -1;   /* CPICapabilityLevel */
static int hf_qsig_cpi_argumentExtension = -1;    /* T_argumentExtension */
static int hf_qsig_cpi_extension = -1;            /* Extension */
static int hf_qsig_cpi_sequenceOfExtn = -1;       /* SEQUENCE_OF_Extension */
static int hf_qsig_cpi_sequenceOfExtn_item = -1;  /* Extension */
static int hf_qsig_cpi_cpiProtectionLevel = -1;   /* CPIProtectionLevel */
static int hf_qsig_cpi_argumentExtension_01 = -1;  /* T_argumentExtension_01 */

/* --- Module PUM-Registration-Operations-asn1-97 --- --- ---                 */

static int hf_qsig_pumr_qsig_pumr_PumRegistrArg_PDU = -1;  /* PumRegistrArg */
static int hf_qsig_pumr_qsig_pumr_PumRegistrRes_PDU = -1;  /* PumRegistrRes */
static int hf_qsig_pumr_qsig_pumr_PumDelRegArg_PDU = -1;  /* PumDelRegArg */
static int hf_qsig_pumr_qsig_pumr_DummyRes_PDU = -1;  /* DummyRes */
static int hf_qsig_pumr_qsig_pumr_PumDe_regArg_PDU = -1;  /* PumDe_regArg */
static int hf_qsig_pumr_qsig_pumr_PumInterrogArg_PDU = -1;  /* PumInterrogArg */
static int hf_qsig_pumr_qsig_pumr_PumInterrogRes_PDU = -1;  /* PumInterrogRes */
static int hf_qsig_pumr_qsig_pumr_Extension_PDU = -1;  /* Extension */
static int hf_qsig_pumr_pumRUserId = -1;          /* RpumUserId */
static int hf_qsig_pumr_pumNumber = -1;           /* PartyNumber */
static int hf_qsig_pumr_alternativeId = -1;       /* AlternativeId */
static int hf_qsig_pumr_basicService = -1;        /* BasicService */
static int hf_qsig_pumr_hostingAddr = -1;         /* PartyNumber */
static int hf_qsig_pumr_activatingUserAddr = -1;  /* PartyNumber */
static int hf_qsig_pumr_serviceOption = -1;       /* ServiceOption */
static int hf_qsig_pumr_sessionParams = -1;       /* SessionParams */
static int hf_qsig_pumr_userPin = -1;             /* T_userPin */
static int hf_qsig_pumr_pumUserPin = -1;          /* UserPin */
static int hf_qsig_pumr_activatingUserPin = -1;   /* UserPin */
static int hf_qsig_pumr_argExtension = -1;        /* PumrExtension */
static int hf_qsig_pumr_null = -1;                /* NULL */
static int hf_qsig_pumr_extension = -1;           /* Extension */
static int hf_qsig_pumr_sequOfExtn = -1;          /* SEQUENCE_OF_Extension */
static int hf_qsig_pumr_sequOfExtn_item = -1;     /* Extension */
static int hf_qsig_pumr_pumXUserId = -1;          /* XpumUserId */
static int hf_qsig_pumr_pumDUserId = -1;          /* DpumUserId */
static int hf_qsig_pumr_userPin_01 = -1;          /* T_userPin_01 */
static int hf_qsig_pumr_pumIUserId = -1;          /* IpumUserId */
static int hf_qsig_pumr_homeInfoOnly = -1;        /* BOOLEAN */
static int hf_qsig_pumr_userPin_02 = -1;          /* T_userPin_02 */
static int hf_qsig_pumr_PumInterrogRes_item = -1;  /* PumInterrogRes_item */
static int hf_qsig_pumr_interrogParams = -1;      /* SessionParams */
static int hf_qsig_pumr_durationOfSession = -1;   /* INTEGER */
static int hf_qsig_pumr_numberOfOutgCalls = -1;   /* INTEGER */

/* --- Module Private-User-Mobility-Call-Handling-Operations-asn1-97 --- --- --- */

static int hf_qsig_pumch_qsig_pumch_EnquiryArg_PDU = -1;  /* EnquiryArg */
static int hf_qsig_pumch_qsig_pumch_EnquiryRes_PDU = -1;  /* EnquiryRes */
static int hf_qsig_pumch_qsig_pumch_DivertArg_PDU = -1;  /* DivertArg */
static int hf_qsig_pumch_qsig_pumch_DummyRes_PDU = -1;  /* DummyRes */
static int hf_qsig_pumch_qsig_pumch_InformArg_PDU = -1;  /* InformArg */
static int hf_qsig_pumch_qsig_pumch_PumoArg_PDU = -1;  /* PumoArg */
static int hf_qsig_pumch_qsig_pumch_Extension_PDU = -1;  /* Extension */
static int hf_qsig_pumch_pisnNumber = -1;         /* PartyNumber */
static int hf_qsig_pumch_qSIGInfoElement = -1;    /* PSS1InformationElement */
static int hf_qsig_pumch_argExtension = -1;       /* PumiExtension */
static int hf_qsig_pumch_hostingAddr = -1;        /* PartyNumber */
static int hf_qsig_pumch_callingNumber = -1;      /* PresentedNumberScreened */
static int hf_qsig_pumch_pumIdentity = -1;        /* PumIdentity */
static int hf_qsig_pumch_callingUserSub = -1;     /* PartySubaddress */
static int hf_qsig_pumch_callingUserName = -1;    /* Name */
static int hf_qsig_pumch_pumUserSub = -1;         /* PartySubaddress */
static int hf_qsig_pumch_currLocation = -1;       /* CurrLocation */
static int hf_qsig_pumch_cfuActivated = -1;       /* CfuActivated */
static int hf_qsig_pumch_divToAddress = -1;       /* Address */
static int hf_qsig_pumch_divOptions = -1;         /* SubscriptionOption */
static int hf_qsig_pumch_pumName = -1;            /* Name */
static int hf_qsig_pumch_null = -1;               /* NULL */
static int hf_qsig_pumch_extension = -1;          /* Extension */
static int hf_qsig_pumch_sequOfExtn = -1;         /* SEQUENCE_OF_Extension */
static int hf_qsig_pumch_sequOfExtn_item = -1;    /* Extension */
static int hf_qsig_pumch_alternativeId = -1;      /* AlternativeId */
static int hf_qsig_pumch_both = -1;               /* T_both */
static int hf_qsig_pumch_destinationNumber = -1;  /* PartyNumber */
static int hf_qsig_pumch_sendingComplete = -1;    /* NULL */
static int hf_qsig_pumch_pumoaextension = -1;     /* T_pumoaextension */
static int hf_qsig_pumch_single = -1;             /* Extension */
static int hf_qsig_pumch_multiple = -1;           /* SEQUENCE_OF_Extension */
static int hf_qsig_pumch_multiple_item = -1;      /* Extension */

/* --- Module Single-Step-Call-Transfer-Operations-asn1-97 --- --- ---        */

static int hf_qsig_ssct_qsig_ssct_SSCTInitiateArg_PDU = -1;  /* SSCTInitiateArg */
static int hf_qsig_ssct_qsig_ssct_DummyRes_PDU = -1;  /* DummyRes */
static int hf_qsig_ssct_qsig_ssct_SSCTSetupArg_PDU = -1;  /* SSCTSetupArg */
static int hf_qsig_ssct_qsig_ssct_DummyArg_PDU = -1;  /* DummyArg */
static int hf_qsig_ssct_qsig_ssct_SSCTDigitInfoArg_PDU = -1;  /* SSCTDigitInfoArg */
static int hf_qsig_ssct_qsig_ssct_Extension_PDU = -1;  /* Extension */
static int hf_qsig_ssct_null = -1;                /* NULL */
static int hf_qsig_ssct_single = -1;              /* Extension */
static int hf_qsig_ssct_multiple = -1;            /* SEQUENCE_OF_Extension */
static int hf_qsig_ssct_multiple_item = -1;       /* Extension */
static int hf_qsig_ssct_rerouteingNumber = -1;    /* PartyNumber */
static int hf_qsig_ssct_transferredAddress = -1;  /* PresentedAddressScreened */
static int hf_qsig_ssct_awaitConnect = -1;        /* AwaitConnect */
static int hf_qsig_ssct_transferredName = -1;     /* Name */
static int hf_qsig_ssct_transferringAddress = -1;  /* PresentedAddressScreened */
static int hf_qsig_ssct_transferringName = -1;    /* Name */
static int hf_qsig_ssct_argumentExtensionSSCTI = -1;  /* SSCTIargumentExtension */
static int hf_qsig_ssct_argumentExtensionSSCTS = -1;  /* SSCTSargumentExtension */
static int hf_qsig_ssct_reroutingNumber = -1;     /* PartyNumber */
static int hf_qsig_ssct_sendingComplete = -1;     /* NULL */
static int hf_qsig_ssct_argumentExtensionSSCTD = -1;  /* SSCTDargumentExtension */

/* --- Module WTM-Location-Registration-Operations-asn1-97 --- --- ---        */

static int hf_qsig_wtmlr_qsig_wtmlr_LocUpdArg_PDU = -1;  /* LocUpdArg */
static int hf_qsig_wtmlr_qsig_wtmlr_DummyRes_PDU = -1;  /* DummyRes */
static int hf_qsig_wtmlr_qsig_wtmlr_LocDelArg_PDU = -1;  /* LocDelArg */
static int hf_qsig_wtmlr_qsig_wtmlr_LocDeRegArg_PDU = -1;  /* LocDeRegArg */
static int hf_qsig_wtmlr_qsig_wtmlr_PisnEnqArg_PDU = -1;  /* PisnEnqArg */
static int hf_qsig_wtmlr_qsig_wtmlr_PisnEnqRes_PDU = -1;  /* PisnEnqRes */
static int hf_qsig_wtmlr_qsig_wtmlr_GetRRCInfArg_PDU = -1;  /* GetRRCInfArg */
static int hf_qsig_wtmlr_qsig_wtmlr_GetRRCInfRes_PDU = -1;  /* GetRRCInfRes */
static int hf_qsig_wtmlr_qsig_wtmlr_LocInfoCheckArg_PDU = -1;  /* LocInfoCheckArg */
static int hf_qsig_wtmlr_qsig_wtmlr_LocInfoCheckRes_PDU = -1;  /* LocInfoCheckRes */
static int hf_qsig_wtmlr_qsig_wtmlr_Extension_PDU = -1;  /* Extension */
static int hf_qsig_wtmlr_wtmUserId = -1;          /* WtmUserId */
static int hf_qsig_wtmlr_basicService = -1;       /* BasicService */
static int hf_qsig_wtmlr_visitPINX = -1;          /* PartyNumber */
static int hf_qsig_wtmlr_argExtension = -1;       /* LrExtension */
static int hf_qsig_wtmlr_null = -1;               /* NULL */
static int hf_qsig_wtmlr_extension = -1;          /* Extension */
static int hf_qsig_wtmlr_sequOfExtn = -1;         /* SEQUENCE_OF_Extension */
static int hf_qsig_wtmlr_sequOfExtn_item = -1;    /* Extension */
static int hf_qsig_wtmlr_alternativeId = -1;      /* AlternativeId */
static int hf_qsig_wtmlr_resExtension = -1;       /* LrExtension */
static int hf_qsig_wtmlr_rrClass = -1;            /* RRClass */
static int hf_qsig_wtmlr_checkResult = -1;        /* CheckResult */
static int hf_qsig_wtmlr_pisnNumber = -1;         /* PartyNumber */

/* --- Module Wireless-Terminal-Call-Handling-Operations-asn1-97 --- --- ---  */

static int hf_qsig_wtmch_qsig_wtmch_EnquiryArg_PDU = -1;  /* EnquiryArg */
static int hf_qsig_wtmch_qsig_wtmch_EnquiryRes_PDU = -1;  /* EnquiryRes */
static int hf_qsig_wtmch_qsig_wtmch_DivertArg_PDU = -1;  /* DivertArg */
static int hf_qsig_wtmch_qsig_wtmch_DummyRes_PDU = -1;  /* DummyRes */
static int hf_qsig_wtmch_qsig_wtmch_InformArg_PDU = -1;  /* InformArg */
static int hf_qsig_wtmch_qsig_wtmch_WtmoArg_PDU = -1;  /* WtmoArg */
static int hf_qsig_wtmch_qsig_wtmch_Extension_PDU = -1;  /* Extension */
static int hf_qsig_wtmch_pisnNumber = -1;         /* PartyNumber */
static int hf_qsig_wtmch_qSIGInfoElement = -1;    /* PSS1InformationElement */
static int hf_qsig_wtmch_argExtension = -1;       /* WtmiExtension */
static int hf_qsig_wtmch_visitPINX = -1;          /* PartyNumber */
static int hf_qsig_wtmch_callingNumber = -1;      /* PresentedNumberScreened */
static int hf_qsig_wtmch_wtmIdentity = -1;        /* WtmIdentity */
static int hf_qsig_wtmch_callingUserSub = -1;     /* PartySubaddress */
static int hf_qsig_wtmch_callingName = -1;        /* Name */
static int hf_qsig_wtmch_wtmUserSub = -1;         /* PartySubaddress */
static int hf_qsig_wtmch_currLocation = -1;       /* CurrLocation */
static int hf_qsig_wtmch_cfuActivated = -1;       /* CfuActivated */
static int hf_qsig_wtmch_divToAddress = -1;       /* Address */
static int hf_qsig_wtmch_divOptions = -1;         /* SubscriptionOption */
static int hf_qsig_wtmch_wtmName = -1;            /* Name */
static int hf_qsig_wtmch_null = -1;               /* NULL */
static int hf_qsig_wtmch_extension = -1;          /* Extension */
static int hf_qsig_wtmch_sequOfExtn = -1;         /* SEQUENCE_OF_Extension */
static int hf_qsig_wtmch_sequOfExtn_item = -1;    /* Extension */
static int hf_qsig_wtmch_alternativeId = -1;      /* AlternativeId */
static int hf_qsig_wtmch_both = -1;               /* T_both */
static int hf_qsig_wtmch_destinationNumber = -1;  /* PartyNumber */
static int hf_qsig_wtmch_sendingComplete = -1;    /* NULL */
static int hf_qsig_wtmch_wtmoaextension = -1;     /* T_wtmoaextension */
static int hf_qsig_wtmch_single = -1;             /* Extension */
static int hf_qsig_wtmch_multiple = -1;           /* SEQUENCE_OF_Extension */
static int hf_qsig_wtmch_multiple_item = -1;      /* Extension */

/* --- Module WTM-Authentication-Operations-asn1-97 --- --- ---               */

static int hf_qsig_wtmau_qsig_wtmau_AuthWtmArg_PDU = -1;  /* AuthWtmArg */
static int hf_qsig_wtmau_qsig_wtmau_AuthWtmRes_PDU = -1;  /* AuthWtmRes */
static int hf_qsig_wtmau_qsig_wtmau_WtatParamArg_PDU = -1;  /* WtatParamArg */
static int hf_qsig_wtmau_qsig_wtmau_WtatParamRes_PDU = -1;  /* WtatParamRes */
static int hf_qsig_wtmau_qsig_wtmau_WtanParamArg_PDU = -1;  /* WtanParamArg */
static int hf_qsig_wtmau_qsig_wtmau_WtanParamRes_PDU = -1;  /* WtanParamRes */
static int hf_qsig_wtmau_qsig_wtmau_ARG_transferAuthParam_PDU = -1;  /* ARG_transferAuthParam */
static int hf_qsig_wtmau_qsig_wtmau_Extension_PDU = -1;  /* Extension */
static int hf_qsig_wtmau_wtmUserId = -1;          /* WtmUserId */
static int hf_qsig_wtmau_calcWtatInfo = -1;       /* CalcWtatInfo */
static int hf_qsig_wtmau_dummyExtension = -1;     /* DummyExtension */
static int hf_qsig_wtmau_autWtmResValue = -1;     /* T_autWtmResValue */
static int hf_qsig_wtmau_canCompute = -1;         /* CanCompute */
static int hf_qsig_wtmau_authChallenge = -1;      /* AuthChallenge */
static int hf_qsig_wtmau_wtatParamInfo = -1;      /* WtatParamInfo */
static int hf_qsig_wtmau_authAlgorithm = -1;      /* AuthAlgorithm */
static int hf_qsig_wtmau_pisnNumber = -1;         /* PartyNumber */
static int hf_qsig_wtmau_alternativeId = -1;      /* AlternativeId */
static int hf_qsig_wtmau_wtanParamInfo = -1;      /* WtanParamInfo */
static int hf_qsig_wtmau_wtatParamInfoChoice = -1;  /* T_wtatParamInfoChoice */
static int hf_qsig_wtmau_authSessionKeyInfo = -1;  /* AuthSessionKeyInfo */
static int hf_qsig_wtmau_authKey = -1;            /* AuthKey */
static int hf_qsig_wtmau_challLen = -1;           /* INTEGER_1_8 */
static int hf_qsig_wtmau_calcWtanInfo = -1;       /* CalcWtanInfo */
static int hf_qsig_wtmau_authSessionKey = -1;     /* AuthSessionKey */
static int hf_qsig_wtmau_calculationParam = -1;   /* CalculationParam */
static int hf_qsig_wtmau_CalcWtatInfo_item = -1;  /* CalcWtatInfoUnit */
static int hf_qsig_wtmau_authResponse = -1;       /* AuthResponse */
static int hf_qsig_wtmau_derivedCipherKey = -1;   /* DerivedCipherKey */
static int hf_qsig_wtmau_extension = -1;          /* Extension */
static int hf_qsig_wtmau_sequOfExtn = -1;         /* SEQUENCE_OF_Extension */
static int hf_qsig_wtmau_sequOfExtn_item = -1;    /* Extension */
static int hf_qsig_wtmau_authAlg = -1;            /* DefinedIDs */
static int hf_qsig_wtmau_param = -1;              /* T_param */

/* --- Module SS-SD-Operations-asn1-97 --- --- ---                            */

static int hf_qsig_sd_qsig_sd_DisplayArg_PDU = -1;  /* DisplayArg */
static int hf_qsig_sd_qsig_sd_KeypadArg_PDU = -1;  /* KeypadArg */
static int hf_qsig_sd_qsig_sd_Extension_PDU = -1;  /* Extension */
static int hf_qsig_sd_displayString = -1;         /* DisplayString */
static int hf_qsig_sd_sdextension = -1;           /* SDExtension */
static int hf_qsig_sd_displayStringNormal = -1;   /* BMPStringNormal */
static int hf_qsig_sd_displayStringExtended = -1;  /* BMPStringExtended */
static int hf_qsig_sd_keypadString = -1;          /* BMPStringNormal */
static int hf_qsig_sd_extension = -1;             /* Extension */
static int hf_qsig_sd_multipleExtension = -1;     /* SEQUENCE_OF_Extension */
static int hf_qsig_sd_multipleExtension_item = -1;  /* Extension */

/* --- Module Call-Identification-and-Call-Linkage-Operations-asn1-97 --- --- --- */

static int hf_qsig_cidl_qsig_cidl_CallIdentificationAssignArg_PDU = -1;  /* CallIdentificationAssignArg */
static int hf_qsig_cidl_qsig_cidl_CallIdentificationUpdateArg_PDU = -1;  /* CallIdentificationUpdateArg */
static int hf_qsig_cidl_globalCallID = -1;        /* CallIdentificationData */
static int hf_qsig_cidl_threadID = -1;            /* CallIdentificationData */
static int hf_qsig_cidl_legID = -1;               /* CallIdentificationData */
static int hf_qsig_cidl_extensiont = -1;          /* ExtensionType */
static int hf_qsig_cidl_switchingSubDomainName = -1;  /* SwitchingSubDomainName */
static int hf_qsig_cidl_linkageID = -1;           /* T_linkageID */
static int hf_qsig_cidl_subDomainID = -1;         /* SubDomainID */
static int hf_qsig_cidl_globallyUniqueID = -1;    /* GloballyUniqueID */
static int hf_qsig_cidl_timeStamp = -1;           /* TimeStamp */
static int hf_qsig_cidl_extension = -1;           /* Extension */
static int hf_qsig_cidl_sequenceOfExt = -1;       /* SEQUENCE_OF_Extension */
static int hf_qsig_cidl_sequenceOfExt_item = -1;  /* Extension */

/* --- Module Short-Message-Service-Operations-asn1-97 --- --- ---            */

static int hf_qsig_sms_qsig_sms_SmsSubmitArg_PDU = -1;  /* SmsSubmitArg */
static int hf_qsig_sms_qsig_sms_SmsSubmitRes_PDU = -1;  /* SmsSubmitRes */
static int hf_qsig_sms_qsig_sms_SmsDeliverArg_PDU = -1;  /* SmsDeliverArg */
static int hf_qsig_sms_qsig_sms_SmsDeliverRes_PDU = -1;  /* SmsDeliverRes */
static int hf_qsig_sms_qsig_sms_SmsStatusReportArg_PDU = -1;  /* SmsStatusReportArg */
static int hf_qsig_sms_qsig_sms_SmsStatusReportRes_PDU = -1;  /* SmsStatusReportRes */
static int hf_qsig_sms_qsig_sms_SmsCommandArg_PDU = -1;  /* SmsCommandArg */
static int hf_qsig_sms_qsig_sms_SmsCommandRes_PDU = -1;  /* SmsCommandRes */
static int hf_qsig_sms_qsig_sms_ScAlertArg_PDU = -1;  /* ScAlertArg */
static int hf_qsig_sms_qsig_sms_DummyRes_PDU = -1;  /* DummyRes */
static int hf_qsig_sms_qsig_sms_PAR_smsDeliverError_PDU = -1;  /* PAR_smsDeliverError */
static int hf_qsig_sms_qsig_sms_PAR_smsSubmitError_PDU = -1;  /* PAR_smsSubmitError */
static int hf_qsig_sms_qsig_sms_PAR_smsStatusReportError_PDU = -1;  /* PAR_smsStatusReportError */
static int hf_qsig_sms_qsig_sms_PAR_smsCommandError_PDU = -1;  /* PAR_smsCommandError */
static int hf_qsig_sms_qsig_sms_SmsExtension_PDU = -1;  /* SmsExtension */
static int hf_qsig_sms_destinationAddress = -1;   /* PartyNumber */
static int hf_qsig_sms_originatingAddress = -1;   /* PartyNumber */
static int hf_qsig_sms_messageReference = -1;     /* MessageReference */
static int hf_qsig_sms_smSubmitParameter = -1;    /* SmSubmitParameter */
static int hf_qsig_sms_userData = -1;             /* UserData */
static int hf_qsig_sms_smsExtension = -1;         /* SmsExtension */
static int hf_qsig_sms_serviceCentreTimeStamp = -1;  /* ServiceCentreTimeStamp */
static int hf_qsig_sms_protocolIdentifier = -1;   /* ProtocolIdentifier */
static int hf_qsig_sms_originatingName = -1;      /* Name */
static int hf_qsig_sms_smDeliverParameter = -1;   /* SmDeliverParameter */
static int hf_qsig_sms_smsDeliverResponseChoice = -1;  /* SmsDeliverResChoice */
static int hf_qsig_sms_dischargeTime = -1;        /* DischargeTime */
static int hf_qsig_sms_recipientAddress = -1;     /* PartyNumber */
static int hf_qsig_sms_recipientName = -1;        /* Name */
static int hf_qsig_sms_status = -1;               /* Status */
static int hf_qsig_sms_priority = -1;             /* BOOLEAN */
static int hf_qsig_sms_moreMessagesToSend = -1;   /* BOOLEAN */
static int hf_qsig_sms_statusReportQualifier = -1;  /* BOOLEAN */
static int hf_qsig_sms_smsStatusReportResponseChoice = -1;  /* SmsStatusReportResponseChoice */
static int hf_qsig_sms_messageNumber = -1;        /* MessageReference */
static int hf_qsig_sms_commandType = -1;          /* CommandType */
static int hf_qsig_sms_commandData = -1;          /* CommandData */
static int hf_qsig_sms_statusReportRequest = -1;  /* BOOLEAN */
static int hf_qsig_sms_null = -1;                 /* NULL */
static int hf_qsig_sms_validityPeriod = -1;       /* ValidityPeriod */
static int hf_qsig_sms_replyPath = -1;            /* BOOLEAN */
static int hf_qsig_sms_rejectDuplicates = -1;     /* BOOLEAN */
static int hf_qsig_sms_statusReportIndication = -1;  /* BOOLEAN */
static int hf_qsig_sms_resChoiceSeq = -1;         /* ResChoiceSeq */
static int hf_qsig_sms_single = -1;               /* Extension */
static int hf_qsig_sms_multiple = -1;             /* SEQUENCE_OF_Extension */
static int hf_qsig_sms_multiple_item = -1;        /* Extension */
static int hf_qsig_sms_validityPeriodRel = -1;    /* ValidityPeriodRel */
static int hf_qsig_sms_validityPeriodAbs = -1;    /* ValidityPeriodAbs */
static int hf_qsig_sms_validityPeriodEnh = -1;    /* ValidityPeriodEnh */
static int hf_qsig_sms_singleShotSM = -1;         /* BOOLEAN */
static int hf_qsig_sms_enhancedVP = -1;           /* EnhancedVP */
static int hf_qsig_sms_validityPeriodSec = -1;    /* INTEGER_0_255 */
static int hf_qsig_sms_validityPeriodSemi = -1;   /* ValidityPeriodSemi */
static int hf_qsig_sms_userDataHeader = -1;       /* UserDataHeader */
static int hf_qsig_sms_class = -1;                /* INTEGER_0_3 */
static int hf_qsig_sms_compressed = -1;           /* BOOLEAN */
static int hf_qsig_sms_shortMessageText = -1;     /* ShortMessageText */
static int hf_qsig_sms_shortMessageTextType = -1;  /* ShortMessageTextType */
static int hf_qsig_sms_shortMessageTextData = -1;  /* ShortMessageTextData */
static int hf_qsig_sms_UserDataHeader_item = -1;  /* UserDataHeaderChoice */
static int hf_qsig_sms_smscControlParameterHeader = -1;  /* SmscControlParameterHeader */
static int hf_qsig_sms_concatenated8BitSMHeader = -1;  /* Concatenated8BitSMHeader */
static int hf_qsig_sms_concatenated16BitSMHeader = -1;  /* Concatenated16BitSMHeader */
static int hf_qsig_sms_applicationPort8BitHeader = -1;  /* ApplicationPort8BitHeader */
static int hf_qsig_sms_applicationPort16BitHeader = -1;  /* ApplicationPort16BitHeader */
static int hf_qsig_sms_dataHeaderSourceIndicator = -1;  /* DataHeaderSourceIndicator */
static int hf_qsig_sms_wirelessControlHeader = -1;  /* WirelessControlHeader */
static int hf_qsig_sms_genericUserValue = -1;     /* GenericUserValue */
static int hf_qsig_sms_concatenated8BitSMReferenceNumber = -1;  /* INTEGER_0_255 */
static int hf_qsig_sms_maximumNumberOf8BitSMInConcatenatedSM = -1;  /* INTEGER_0_255 */
static int hf_qsig_sms_sequenceNumberOf8BitSM = -1;  /* INTEGER_0_255 */
static int hf_qsig_sms_concatenated16BitSMReferenceNumber = -1;  /* INTEGER_0_65536 */
static int hf_qsig_sms_maximumNumberOf16BitSMInConcatenatedSM = -1;  /* INTEGER_0_255 */
static int hf_qsig_sms_sequenceNumberOf16BitSM = -1;  /* INTEGER_0_255 */
static int hf_qsig_sms_destination8BitPort = -1;  /* INTEGER_0_255 */
static int hf_qsig_sms_originator8BitPort = -1;   /* INTEGER_0_255 */
static int hf_qsig_sms_destination16BitPort = -1;  /* INTEGER_0_65536 */
static int hf_qsig_sms_originator16BitPort = -1;  /* INTEGER_0_65536 */
static int hf_qsig_sms_parameterValue = -1;       /* INTEGER_0_255 */
static int hf_qsig_sms_genericUserData = -1;      /* OCTET_STRING */
static int hf_qsig_sms_failureCause = -1;         /* FailureCause */
static int hf_qsig_sms_scAddressSaved = -1;       /* BOOLEAN */
/* named bits */
static int hf_qsig_sms_SmscControlParameterHeader_sRforTransactionCompleted = -1;
static int hf_qsig_sms_SmscControlParameterHeader_sRforPermanentError = -1;
static int hf_qsig_sms_SmscControlParameterHeader_sRforTempErrorSCnotTrying = -1;
static int hf_qsig_sms_SmscControlParameterHeader_sRforTempErrorSCstillTrying = -1;
static int hf_qsig_sms_SmscControlParameterHeader_cancelSRRforConcatenatedSM = -1;
static int hf_qsig_sms_SmscControlParameterHeader_includeOrigUDHintoSR = -1;

/* --- Module SS-MCR-Operations-asn97 --- --- ---                             */

static int hf_qsig_mcr_qsig_mcr_MCRequestArg_PDU = -1;  /* MCRequestArg */
static int hf_qsig_mcr_qsig_mcr_MCRequestResult_PDU = -1;  /* MCRequestResult */
static int hf_qsig_mcr_qsig_mcr_MCInformArg_PDU = -1;  /* MCInformArg */
static int hf_qsig_mcr_qsig_mcr_MCAlertingArg_PDU = -1;  /* MCAlertingArg */
static int hf_qsig_mcr_qsig_mcr_Extension_PDU = -1;  /* Extension */
static int hf_qsig_mcr_callType = -1;             /* CallType */
static int hf_qsig_mcr_retainOrigCall = -1;       /* BOOLEAN */
static int hf_qsig_mcr_destinationAddress = -1;   /* PresentedAddressUnscreened */
static int hf_qsig_mcr_requestingAddress = -1;    /* PresentedAddressUnscreened */
static int hf_qsig_mcr_cooperatingAddress = -1;   /* PresentedAddressUnscreened */
static int hf_qsig_mcr_correlation = -1;          /* Correlation */
static int hf_qsig_mcr_extensions = -1;           /* MCRExtensions */
static int hf_qsig_mcr_basicService = -1;         /* BasicService */
static int hf_qsig_mcr_cisc = -1;                 /* NULL */
static int hf_qsig_mcr_correlationData = -1;      /* CallIdentity */
static int hf_qsig_mcr_correlationReason = -1;    /* CorrelationReason */
static int hf_qsig_mcr_none = -1;                 /* NULL */
static int hf_qsig_mcr_single = -1;               /* Extension */
static int hf_qsig_mcr_multiple = -1;             /* SEQUENCE_OF_Extension */
static int hf_qsig_mcr_multiple_item = -1;        /* Extension */

/* --- Module SS-MCM-Operations-asn1-97 --- --- ---                           */

static int hf_qsig_mcm_qsig_mcm_MCMNewMsgArg_PDU = -1;  /* MCMNewMsgArg */
static int hf_qsig_mcm_qsig_mcm_MCMDummyRes_PDU = -1;  /* MCMDummyRes */
static int hf_qsig_mcm_qsig_mcm_MCMNoNewMsgArg_PDU = -1;  /* MCMNoNewMsgArg */
static int hf_qsig_mcm_qsig_mcm_MCMUpdateArg_PDU = -1;  /* MCMUpdateArg */
static int hf_qsig_mcm_qsig_mcm_MCMUpdateReqArg_PDU = -1;  /* MCMUpdateReqArg */
static int hf_qsig_mcm_qsig_mcm_MCMUpdateReqRes_PDU = -1;  /* MCMUpdateReqRes */
static int hf_qsig_mcm_qsig_mcm_MCMServiceArg_PDU = -1;  /* MCMServiceArg */
static int hf_qsig_mcm_qsig_mcm_MCMInterrogateArg_PDU = -1;  /* MCMInterrogateArg */
static int hf_qsig_mcm_qsig_mcm_MCMInterrogateRes_PDU = -1;  /* MCMInterrogateRes */
static int hf_qsig_mcm_qsig_mcm_MCMailboxFullArg_PDU = -1;  /* MCMailboxFullArg */
static int hf_qsig_mcm_qsig_mcm_Extension_PDU = -1;  /* Extension */
static int hf_qsig_mcm_partyInfo = -1;            /* PartyInfo */
static int hf_qsig_mcm_mailboxFullFor = -1;       /* MailboxFullFor */
static int hf_qsig_mcm_extensions = -1;           /* MCMExtensions */
static int hf_qsig_mcm_MailboxFullFor_item = -1;  /* MailboxFullPar */
static int hf_qsig_mcm_messageType = -1;          /* MessageType */
static int hf_qsig_mcm_capacityReached = -1;      /* INTEGER_0_100 */
static int hf_qsig_mcm_mCMChange = -1;            /* MCMChange */
static int hf_qsig_mcm_activateMCM = -1;          /* SEQUENCE_OF_MCMServiceInfo */
static int hf_qsig_mcm_activateMCM_item = -1;     /* MCMServiceInfo */
static int hf_qsig_mcm_deactivateMCM = -1;        /* SEQUENCE_OF_MessageType */
static int hf_qsig_mcm_deactivateMCM_item = -1;   /* MessageType */
static int hf_qsig_mcm_setToDefaultValues = -1;   /* NULL */
static int hf_qsig_mcm_mCMModeNew = -1;           /* MCMMode */
static int hf_qsig_mcm_mCMModeRetrieved = -1;     /* MCMMode */
static int hf_qsig_mcm_interrogateInfo = -1;      /* SEQUENCE_OF_MessageType */
static int hf_qsig_mcm_interrogateInfo_item = -1;  /* MessageType */
static int hf_qsig_mcm_interrogateResult = -1;    /* SEQUENCE_OF_MCMServiceInfo */
static int hf_qsig_mcm_interrogateResult_item = -1;  /* MCMServiceInfo */
static int hf_qsig_mcm_servedUserNr = -1;         /* PartyNumber */
static int hf_qsig_mcm_specificMessageType = -1;  /* MessageType */
static int hf_qsig_mcm_msgCentreId = -1;          /* MsgCentreId */
static int hf_qsig_mcm_nrOfMessages = -1;         /* NrOfMessages */
static int hf_qsig_mcm_originatingNr = -1;        /* PartyNumber */
static int hf_qsig_mcm_timestamp = -1;            /* TimeStamp */
static int hf_qsig_mcm_priority = -1;             /* INTEGER_0_9 */
static int hf_qsig_mcm_argumentExtMCMNew = -1;    /* MCMNewArgumentExt */
static int hf_qsig_mcm_extension = -1;            /* Extension */
static int hf_qsig_mcm_multipleExtension = -1;    /* SEQUENCE_OF_Extension */
static int hf_qsig_mcm_multipleExtension_item = -1;  /* Extension */
static int hf_qsig_mcm_argumentExtMCMNoNew = -1;  /* MCMNoNewArgumentExt */
static int hf_qsig_mcm_updateInfo = -1;           /* UpdateInfo */
static int hf_qsig_mcm_moreInfoFollows = -1;      /* BOOLEAN */
static int hf_qsig_mcm_argumentExtMCMUpdArg = -1;  /* MCMUpdArgArgumentExt */
static int hf_qsig_mcm_MCMUpdateReqRes_item = -1;  /* MCMUpdateReqResElt */
static int hf_qsig_mcm_argumentExtMCMUpdRes = -1;  /* MCMUpdResArgumentExt */
static int hf_qsig_mcm_messageCentreID = -1;      /* MsgCentreId */
static int hf_qsig_mcm_newMsgInfoOnly = -1;       /* MessageInfo */
static int hf_qsig_mcm_retrievedMsgInfoOnly = -1;  /* MessageInfo */
static int hf_qsig_mcm_allMsgInfo = -1;           /* AllMsgInfo */
static int hf_qsig_mcm_newMsgInfo = -1;           /* MessageInfo */
static int hf_qsig_mcm_retrievedMsgInfo = -1;     /* MessageInfo */
static int hf_qsig_mcm_completeInfo = -1;         /* CompleteInfo */
static int hf_qsig_mcm_compressedInfo = -1;       /* CompressedInfo */
static int hf_qsig_mcm_noMsgsOfMsgType = -1;      /* NULL */
static int hf_qsig_mcm_CompleteInfo_item = -1;    /* AddressHeader */
static int hf_qsig_mcm_originatorNr = -1;         /* PartyNumber */
static int hf_qsig_mcm_timeStamp = -1;            /* TimeStamp */
static int hf_qsig_mcm_ahpriority = -1;           /* Priority */
static int hf_qsig_mcm_lastTimeStamp = -1;        /* TimeStamp */
static int hf_qsig_mcm_highestPriority = -1;      /* Priority */
static int hf_qsig_mcm_integer = -1;              /* INTEGER_0_65535 */
static int hf_qsig_mcm_partyNumber = -1;          /* PartyNumber */
static int hf_qsig_mcm_numericString = -1;        /* NumericString_SIZE_1_10 */
static int hf_qsig_mcm_none = -1;                 /* NULL */

/* --- Module SS-MID-Operations-asn1-97 --- --- ---                           */

static int hf_qsig_mid_qsig_mid_MIDMailboxAuthArg_PDU = -1;  /* MIDMailboxAuthArg */
static int hf_qsig_mid_qsig_mid_MIDDummyRes_PDU = -1;  /* MIDDummyRes */
static int hf_qsig_mid_qsig_mid_MIDMailboxIDArg_PDU = -1;  /* MIDMailboxIDArg */
static int hf_qsig_mid_qsig_mid_Extension_PDU = -1;  /* Extension */
static int hf_qsig_mid_partyInfo = -1;            /* PartyInfo */
static int hf_qsig_mid_servedUserName = -1;       /* Name */
static int hf_qsig_mid_mailBox = -1;              /* String */
static int hf_qsig_mid_password = -1;             /* String */
static int hf_qsig_mid_extensions = -1;           /* MIDExtensions */
static int hf_qsig_mid_servedUserNr = -1;         /* PresentedAddressUnscreened */
static int hf_qsig_mid_messageType = -1;          /* MessageType */
static int hf_qsig_mid_messageCentreID = -1;      /* MsgCentreId */
static int hf_qsig_mid_stringBmp = -1;            /* BMPString */
static int hf_qsig_mid_stringUtf8 = -1;           /* UTF8String */
static int hf_qsig_mid_none = -1;                 /* NULL */
static int hf_qsig_mid_extension = -1;            /* Extension */
static int hf_qsig_mid_multipleExtension = -1;    /* SEQUENCE_OF_Extension */
static int hf_qsig_mid_multipleExtension_item = -1;  /* Extension */

/*--- End of included file: packet-qsig-hf.c ---*/
#line 292 "../../asn1/qsig/packet-qsig-template.c"

static int *hf_qsig_ie_type_arr[] = {
  NULL,
  NULL,
  NULL,
  NULL,
  &hf_qsig_ie_type_cs4,
  &hf_qsig_ie_type_cs5,
  NULL,
  NULL,
};

/* Initialize the subtree pointers */
static gint ett_qsig = -1;
static gint ett_qsig_ie = -1;
static gint ett_qsig_unknown_extension = -1;

/*--- Included file: packet-qsig-ett.c ---*/
#line 1 "../../asn1/qsig/packet-qsig-ett.c"

/* --- Modules Manufacturer-specific-service-extension-class-asn1-97 PSS1-generic-parameters-definition-asn1-97 Addressing-Data-Elements-asn1-97 --- --- --- */

static gint ett_qsig_Extension = -1;
static gint ett_qsig_PresentedAddressScreened = -1;
static gint ett_qsig_PresentedAddressUnscreened = -1;
static gint ett_qsig_PresentedNumberScreened = -1;
static gint ett_qsig_PresentedNumberUnscreened = -1;
static gint ett_qsig_AddressScreened = -1;
static gint ett_qsig_NumberScreened = -1;
static gint ett_qsig_Address = -1;
static gint ett_qsig_PartyNumber = -1;
static gint ett_qsig_PublicPartyNumber = -1;
static gint ett_qsig_PrivatePartyNumber = -1;
static gint ett_qsig_PartySubaddress = -1;
static gint ett_qsig_UserSpecifiedSubaddress = -1;

/* --- Module Name-Operations-asn1-97 --- --- ---                             */

static gint ett_qsig_na_NameArg = -1;
static gint ett_qsig_na_T_nameSequence = -1;
static gint ett_qsig_na_NameExtension = -1;
static gint ett_qsig_na_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_na_Name = -1;
static gint ett_qsig_na_NamePresentationAllowed = -1;
static gint ett_qsig_na_NamePresentationRestricted = -1;
static gint ett_qsig_na_NameSet = -1;

/* --- Module Call-Diversion-Operations-asn1-97 --- --- ---                   */

static gint ett_qsig_cf_ARG_activateDiversionQ = -1;
static gint ett_qsig_cf_ADExtension = -1;
static gint ett_qsig_cf_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_cf_RES_activateDiversionQ = -1;
static gint ett_qsig_cf_ARG_deactivateDiversionQ = -1;
static gint ett_qsig_cf_DDExtension = -1;
static gint ett_qsig_cf_RES_deactivateDiversionQ = -1;
static gint ett_qsig_cf_ARG_interrogateDiversionQ = -1;
static gint ett_qsig_cf_IDExtension = -1;
static gint ett_qsig_cf_ARG_checkRestriction = -1;
static gint ett_qsig_cf_CHRExtension = -1;
static gint ett_qsig_cf_RES_checkRestriction = -1;
static gint ett_qsig_cf_ARG_callRerouteing = -1;
static gint ett_qsig_cf_CRRExtension = -1;
static gint ett_qsig_cf_RES_callRerouteing = -1;
static gint ett_qsig_cf_ARG_divertingLegInformation1 = -1;
static gint ett_qsig_cf_DLI1Extension = -1;
static gint ett_qsig_cf_ARG_divertingLegInformation2 = -1;
static gint ett_qsig_cf_DLI2Extension = -1;
static gint ett_qsig_cf_ARG_divertingLegInformation3 = -1;
static gint ett_qsig_cf_DLI3Extension = -1;
static gint ett_qsig_cf_ARG_cfnrDivertedLegFailed = -1;
static gint ett_qsig_cf_IntResultList = -1;
static gint ett_qsig_cf_IntResult = -1;
static gint ett_qsig_cf_IRExtension = -1;

/* --- Module Path-Replacement-Operations-asn1-97 --- --- ---                 */

static gint ett_qsig_pr_PRProposeArg = -1;
static gint ett_qsig_pr_PRPExtension = -1;
static gint ett_qsig_pr_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_pr_PRSetupArg = -1;
static gint ett_qsig_pr_PRSExtension = -1;
static gint ett_qsig_pr_PRRetainArg = -1;
static gint ett_qsig_pr_PRRExtension = -1;
static gint ett_qsig_pr_DummyResult = -1;
static gint ett_qsig_pr_DummyArg = -1;

/* --- Module Call-Transfer-Operations-asn1-97 --- --- ---                    */

static gint ett_qsig_ct_DummyArg = -1;
static gint ett_qsig_ct_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_ct_DummyRes = -1;
static gint ett_qsig_ct_CTIdentifyRes = -1;
static gint ett_qsig_ct_T_resultExtension = -1;
static gint ett_qsig_ct_CTInitiateArg = -1;
static gint ett_qsig_ct_CTIargumentExtension = -1;
static gint ett_qsig_ct_CTSetupArg = -1;
static gint ett_qsig_ct_CTSargumentExtension = -1;
static gint ett_qsig_ct_CTActiveArg = -1;
static gint ett_qsig_ct_CTAargumentExtension = -1;
static gint ett_qsig_ct_CTCompleteArg = -1;
static gint ett_qsig_ct_CTCargumentExtension = -1;
static gint ett_qsig_ct_CTUpdateArg = -1;
static gint ett_qsig_ct_CTUargumentExtension = -1;
static gint ett_qsig_ct_SubaddressTransferArg = -1;
static gint ett_qsig_ct_STargumentExtension = -1;

/* --- Module SS-CC-Operations-asn1-97 --- --- ---                            */

static gint ett_qsig_cc_CcRequestArg = -1;
static gint ett_qsig_cc_CcRequestRes = -1;
static gint ett_qsig_cc_CcOptionalArg = -1;
static gint ett_qsig_cc_T_fullArg = -1;
static gint ett_qsig_cc_CcExtension = -1;
static gint ett_qsig_cc_SEQUENCE_OF_Extension = -1;

/* --- Module Call-Offer-Operations-asn1-97 --- --- ---                       */

static gint ett_qsig_co_PathRetainArg = -1;
static gint ett_qsig_co_T_extendedServiceList = -1;
static gint ett_qsig_co_ServiceAvailableArg = -1;
static gint ett_qsig_co_T_extendedServiceList_01 = -1;
static gint ett_qsig_co_ServiceList = -1;
static gint ett_qsig_co_DummyArg = -1;
static gint ett_qsig_co_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_co_DummyRes = -1;

/* --- Module Do-Not-Disturb-Operations-asn1-97 --- --- ---                   */

static gint ett_qsig_dnd_DummyArg = -1;
static gint ett_qsig_dnd_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_dnd_DummyRes = -1;
static gint ett_qsig_dnd_DNDActivateArg = -1;
static gint ett_qsig_dnd_DNDAargumentExtension = -1;
static gint ett_qsig_dnd_DNDActivateRes = -1;
static gint ett_qsig_dnd_T_status = -1;
static gint ett_qsig_dnd_T_status_item = -1;
static gint ett_qsig_dnd_T_resultExtension = -1;
static gint ett_qsig_dnd_DNDDeactivateArg = -1;
static gint ett_qsig_dnd_DNDDargumentExtension = -1;
static gint ett_qsig_dnd_DNDInterrogateArg = -1;
static gint ett_qsig_dnd_DNDIargumentExtension = -1;
static gint ett_qsig_dnd_DNDInterrogateRes = -1;
static gint ett_qsig_dnd_T_status_01 = -1;
static gint ett_qsig_dnd_T_status_item_01 = -1;
static gint ett_qsig_dnd_T_resultExtension_01 = -1;
static gint ett_qsig_dnd_DNDOverrideArg = -1;
static gint ett_qsig_dnd_DNDOargumentExtension = -1;
static gint ett_qsig_dnd_PathRetainArg = -1;
static gint ett_qsig_dnd_T_extendedServiceList = -1;
static gint ett_qsig_dnd_ServiceAvailableArg = -1;
static gint ett_qsig_dnd_T_extendedServiceList_01 = -1;
static gint ett_qsig_dnd_ServiceList = -1;

/* --- Module Call-Intrusion-Operations-asn1-97 --- --- ---                   */

static gint ett_qsig_ci_PathRetainArg = -1;
static gint ett_qsig_ci_T_extendedServiceList = -1;
static gint ett_qsig_ci_ServiceAvailableArg = -1;
static gint ett_qsig_ci_T_extendedServiceList_01 = -1;
static gint ett_qsig_ci_ServiceList = -1;
static gint ett_qsig_ci_DummyArg = -1;
static gint ett_qsig_ci_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_ci_DummyRes = -1;
static gint ett_qsig_ci_CIRequestArg = -1;
static gint ett_qsig_ci_T_argumentExtension = -1;
static gint ett_qsig_ci_CIRequestRes = -1;
static gint ett_qsig_ci_T_resultExtension = -1;
static gint ett_qsig_ci_CIGetCIPLRes = -1;
static gint ett_qsig_ci_T_resultExtension_01 = -1;

/* --- Module SS-AOC-Operations-asn1-97 --- --- ---                           */

static gint ett_qsig_aoc_AocRateArg = -1;
static gint ett_qsig_aoc_T_aocRate = -1;
static gint ett_qsig_aoc_T_rateArgExtension = -1;
static gint ett_qsig_aoc_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_aoc_AocInterimArg = -1;
static gint ett_qsig_aoc_T_interimCharge = -1;
static gint ett_qsig_aoc_T_specificCurrency = -1;
static gint ett_qsig_aoc_T_interimArgExtension = -1;
static gint ett_qsig_aoc_AocFinalArg = -1;
static gint ett_qsig_aoc_T_finalCharge = -1;
static gint ett_qsig_aoc_T_specificCurrency_01 = -1;
static gint ett_qsig_aoc_T_finalArgExtension = -1;
static gint ett_qsig_aoc_AOCSCurrencyInfoList = -1;
static gint ett_qsig_aoc_AOCSCurrencyInfo = -1;
static gint ett_qsig_aoc_T_rateType = -1;
static gint ett_qsig_aoc_DurationCurrency = -1;
static gint ett_qsig_aoc_FlatRateCurrency = -1;
static gint ett_qsig_aoc_VolumeRateCurrency = -1;
static gint ett_qsig_aoc_RecordedCurrency = -1;
static gint ett_qsig_aoc_Amount = -1;
static gint ett_qsig_aoc_Time = -1;
static gint ett_qsig_aoc_ChargingAssociation = -1;
static gint ett_qsig_aoc_ChargeRequestArg = -1;
static gint ett_qsig_aoc_SEQUENCE_SIZE_0_7_OF_AdviceModeCombination = -1;
static gint ett_qsig_aoc_T_chargeReqArgExtension = -1;
static gint ett_qsig_aoc_ChargeRequestRes = -1;
static gint ett_qsig_aoc_T_chargeReqResExtension = -1;
static gint ett_qsig_aoc_DummyArg = -1;
static gint ett_qsig_aoc_AocCompleteArg = -1;
static gint ett_qsig_aoc_T_completeArgExtension = -1;
static gint ett_qsig_aoc_AocCompleteRes = -1;
static gint ett_qsig_aoc_T_completeResExtension = -1;
static gint ett_qsig_aoc_AocDivChargeReqArg = -1;
static gint ett_qsig_aoc_T_aocDivChargeReqArgExt = -1;

/* --- Module Recall-Operations-asn1-97 --- --- ---                           */

static gint ett_qsig_re_ReAlertingArg = -1;
static gint ett_qsig_re_T_argumentExtension = -1;
static gint ett_qsig_re_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_re_ReAnswerArg = -1;
static gint ett_qsig_re_T_argumentExtension_01 = -1;

/* --- Module Synchronization-Operations-asn1-97 --- --- ---                  */

static gint ett_qsig_sync_SynchronizationReqArg = -1;
static gint ett_qsig_sync_SynchronizationReqRes = -1;
static gint ett_qsig_sync_SynchronizationInfoArg = -1;
static gint ett_qsig_sync_ArgExtension = -1;
static gint ett_qsig_sync_SEQUENCE_OF_Extension = -1;

/* --- Module Call-Interception-Operations-asn1-97 --- --- ---                */

static gint ett_qsig_cint_CintInformation1Arg = -1;
static gint ett_qsig_cint_CintInformation2Arg = -1;
static gint ett_qsig_cint_CintCondArg = -1;
static gint ett_qsig_cint_CintExtension = -1;
static gint ett_qsig_cint_SEQUENCE_OF_Extension = -1;

/* --- Module Common-Information-Operations-asn1-97 --- --- ---               */

static gint ett_qsig_cmn_CmnArg = -1;
static gint ett_qsig_cmn_T_extension = -1;
static gint ett_qsig_cmn_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_cmn_DummyArg = -1;
static gint ett_qsig_cmn_FeatureIdList = -1;
static gint ett_qsig_cmn_EquipmentId = -1;

/* --- Module Call-Interruption-Operations-asn1-97 --- --- ---                */

static gint ett_qsig_cpi_CPIRequestArg = -1;
static gint ett_qsig_cpi_T_argumentExtension = -1;
static gint ett_qsig_cpi_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_cpi_CPIPRequestArg = -1;
static gint ett_qsig_cpi_T_argumentExtension_01 = -1;

/* --- Module PUM-Registration-Operations-asn1-97 --- --- ---                 */

static gint ett_qsig_pumr_PumRegistrArg = -1;
static gint ett_qsig_pumr_RpumUserId = -1;
static gint ett_qsig_pumr_T_userPin = -1;
static gint ett_qsig_pumr_PumRegistrRes = -1;
static gint ett_qsig_pumr_DummyRes = -1;
static gint ett_qsig_pumr_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_pumr_PumDelRegArg = -1;
static gint ett_qsig_pumr_XpumUserId = -1;
static gint ett_qsig_pumr_PumDe_regArg = -1;
static gint ett_qsig_pumr_DpumUserId = -1;
static gint ett_qsig_pumr_T_userPin_01 = -1;
static gint ett_qsig_pumr_PumInterrogArg = -1;
static gint ett_qsig_pumr_IpumUserId = -1;
static gint ett_qsig_pumr_T_userPin_02 = -1;
static gint ett_qsig_pumr_PumInterrogRes = -1;
static gint ett_qsig_pumr_PumInterrogRes_item = -1;
static gint ett_qsig_pumr_SessionParams = -1;
static gint ett_qsig_pumr_PumrExtension = -1;

/* --- Module Private-User-Mobility-Call-Handling-Operations-asn1-97 --- --- --- */

static gint ett_qsig_pumch_EnquiryArg = -1;
static gint ett_qsig_pumch_DivertArg = -1;
static gint ett_qsig_pumch_InformArg = -1;
static gint ett_qsig_pumch_EnquiryRes = -1;
static gint ett_qsig_pumch_CurrLocation = -1;
static gint ett_qsig_pumch_CfuActivated = -1;
static gint ett_qsig_pumch_DummyRes = -1;
static gint ett_qsig_pumch_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_pumch_PumiExtension = -1;
static gint ett_qsig_pumch_PumIdentity = -1;
static gint ett_qsig_pumch_T_both = -1;
static gint ett_qsig_pumch_PumoArg = -1;
static gint ett_qsig_pumch_T_pumoaextension = -1;

/* --- Module Single-Step-Call-Transfer-Operations-asn1-97 --- --- ---        */

static gint ett_qsig_ssct_DummyArg = -1;
static gint ett_qsig_ssct_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_ssct_DummyRes = -1;
static gint ett_qsig_ssct_SSCTInitiateArg = -1;
static gint ett_qsig_ssct_SSCTIargumentExtension = -1;
static gint ett_qsig_ssct_SSCTSetupArg = -1;
static gint ett_qsig_ssct_SSCTSargumentExtension = -1;
static gint ett_qsig_ssct_SSCTDigitInfoArg = -1;
static gint ett_qsig_ssct_SSCTDargumentExtension = -1;

/* --- Module WTM-Location-Registration-Operations-asn1-97 --- --- ---        */

static gint ett_qsig_wtmlr_LocUpdArg = -1;
static gint ett_qsig_wtmlr_DummyRes = -1;
static gint ett_qsig_wtmlr_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_wtmlr_LocDelArg = -1;
static gint ett_qsig_wtmlr_LocDeRegArg = -1;
static gint ett_qsig_wtmlr_PisnEnqArg = -1;
static gint ett_qsig_wtmlr_PisnEnqRes = -1;
static gint ett_qsig_wtmlr_GetRRCInfArg = -1;
static gint ett_qsig_wtmlr_GetRRCInfRes = -1;
static gint ett_qsig_wtmlr_LocInfoCheckArg = -1;
static gint ett_qsig_wtmlr_LocInfoCheckRes = -1;
static gint ett_qsig_wtmlr_WtmUserId = -1;
static gint ett_qsig_wtmlr_LrExtension = -1;

/* --- Module Wireless-Terminal-Call-Handling-Operations-asn1-97 --- --- ---  */

static gint ett_qsig_wtmch_EnquiryArg = -1;
static gint ett_qsig_wtmch_DivertArg = -1;
static gint ett_qsig_wtmch_InformArg = -1;
static gint ett_qsig_wtmch_EnquiryRes = -1;
static gint ett_qsig_wtmch_CurrLocation = -1;
static gint ett_qsig_wtmch_CfuActivated = -1;
static gint ett_qsig_wtmch_DummyRes = -1;
static gint ett_qsig_wtmch_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_wtmch_WtmiExtension = -1;
static gint ett_qsig_wtmch_WtmIdentity = -1;
static gint ett_qsig_wtmch_T_both = -1;
static gint ett_qsig_wtmch_WtmoArg = -1;
static gint ett_qsig_wtmch_T_wtmoaextension = -1;

/* --- Module WTM-Authentication-Operations-asn1-97 --- --- ---               */

static gint ett_qsig_wtmau_AuthWtmArg = -1;
static gint ett_qsig_wtmau_AuthWtmRes = -1;
static gint ett_qsig_wtmau_WtatParamArg = -1;
static gint ett_qsig_wtmau_WtatParamRes = -1;
static gint ett_qsig_wtmau_WtanParamArg = -1;
static gint ett_qsig_wtmau_WtmUserId = -1;
static gint ett_qsig_wtmau_WtanParamRes = -1;
static gint ett_qsig_wtmau_ARG_transferAuthParam = -1;
static gint ett_qsig_wtmau_WtatParamInfo = -1;
static gint ett_qsig_wtmau_T_wtatParamInfoChoice = -1;
static gint ett_qsig_wtmau_WtanParamInfo = -1;
static gint ett_qsig_wtmau_AuthSessionKeyInfo = -1;
static gint ett_qsig_wtmau_CalcWtatInfo = -1;
static gint ett_qsig_wtmau_CalcWtatInfoUnit = -1;
static gint ett_qsig_wtmau_CalcWtanInfo = -1;
static gint ett_qsig_wtmau_DummyExtension = -1;
static gint ett_qsig_wtmau_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_wtmau_AuthAlgorithm = -1;

/* --- Module SS-SD-Operations-asn1-97 --- --- ---                            */

static gint ett_qsig_sd_DisplayArg = -1;
static gint ett_qsig_sd_DisplayString = -1;
static gint ett_qsig_sd_KeypadArg = -1;
static gint ett_qsig_sd_SDExtension = -1;
static gint ett_qsig_sd_SEQUENCE_OF_Extension = -1;

/* --- Module Call-Identification-and-Call-Linkage-Operations-asn1-97 --- --- --- */

static gint ett_qsig_cidl_CallIdentificationAssignArg = -1;
static gint ett_qsig_cidl_CallIdentificationUpdateArg = -1;
static gint ett_qsig_cidl_CallIdentificationData = -1;
static gint ett_qsig_cidl_T_linkageID = -1;
static gint ett_qsig_cidl_ExtensionType = -1;
static gint ett_qsig_cidl_SEQUENCE_OF_Extension = -1;

/* --- Module Short-Message-Service-Operations-asn1-97 --- --- ---            */

static gint ett_qsig_sms_SmsSubmitArg = -1;
static gint ett_qsig_sms_SmsSubmitRes = -1;
static gint ett_qsig_sms_SmsDeliverArg = -1;
static gint ett_qsig_sms_SmsDeliverRes = -1;
static gint ett_qsig_sms_SmsStatusReportArg = -1;
static gint ett_qsig_sms_SmsStatusReportRes = -1;
static gint ett_qsig_sms_SmsCommandArg = -1;
static gint ett_qsig_sms_SmsCommandRes = -1;
static gint ett_qsig_sms_ScAlertArg = -1;
static gint ett_qsig_sms_DummyRes = -1;
static gint ett_qsig_sms_SmSubmitParameter = -1;
static gint ett_qsig_sms_SmDeliverParameter = -1;
static gint ett_qsig_sms_SmsDeliverResChoice = -1;
static gint ett_qsig_sms_ResChoiceSeq = -1;
static gint ett_qsig_sms_SmsStatusReportResponseChoice = -1;
static gint ett_qsig_sms_SmsExtension = -1;
static gint ett_qsig_sms_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_sms_ValidityPeriod = -1;
static gint ett_qsig_sms_ValidityPeriodEnh = -1;
static gint ett_qsig_sms_EnhancedVP = -1;
static gint ett_qsig_sms_UserData = -1;
static gint ett_qsig_sms_ShortMessageText = -1;
static gint ett_qsig_sms_UserDataHeader = -1;
static gint ett_qsig_sms_UserDataHeaderChoice = -1;
static gint ett_qsig_sms_SmscControlParameterHeader = -1;
static gint ett_qsig_sms_Concatenated8BitSMHeader = -1;
static gint ett_qsig_sms_Concatenated16BitSMHeader = -1;
static gint ett_qsig_sms_ApplicationPort8BitHeader = -1;
static gint ett_qsig_sms_ApplicationPort16BitHeader = -1;
static gint ett_qsig_sms_GenericUserValue = -1;
static gint ett_qsig_sms_PAR_smsDeliverError = -1;
static gint ett_qsig_sms_PAR_smsSubmitError = -1;
static gint ett_qsig_sms_PAR_smsStatusReportError = -1;
static gint ett_qsig_sms_PAR_smsCommandError = -1;

/* --- Module SS-MCR-Operations-asn97 --- --- ---                             */

static gint ett_qsig_mcr_MCRequestArg = -1;
static gint ett_qsig_mcr_MCRequestResult = -1;
static gint ett_qsig_mcr_MCInformArg = -1;
static gint ett_qsig_mcr_MCAlertingArg = -1;
static gint ett_qsig_mcr_CallType = -1;
static gint ett_qsig_mcr_Correlation = -1;
static gint ett_qsig_mcr_MCRExtensions = -1;
static gint ett_qsig_mcr_SEQUENCE_OF_Extension = -1;

/* --- Module SS-MCM-Operations-asn1-97 --- --- ---                           */

static gint ett_qsig_mcm_MCMailboxFullArg = -1;
static gint ett_qsig_mcm_MailboxFullFor = -1;
static gint ett_qsig_mcm_MailboxFullPar = -1;
static gint ett_qsig_mcm_MCMServiceArg = -1;
static gint ett_qsig_mcm_MCMChange = -1;
static gint ett_qsig_mcm_SEQUENCE_OF_MCMServiceInfo = -1;
static gint ett_qsig_mcm_SEQUENCE_OF_MessageType = -1;
static gint ett_qsig_mcm_MCMServiceInfo = -1;
static gint ett_qsig_mcm_MCMInterrogateArg = -1;
static gint ett_qsig_mcm_MCMInterrogateRes = -1;
static gint ett_qsig_mcm_MCMNewMsgArg = -1;
static gint ett_qsig_mcm_MCMNewArgumentExt = -1;
static gint ett_qsig_mcm_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_mcm_MCMNoNewMsgArg = -1;
static gint ett_qsig_mcm_MCMNoNewArgumentExt = -1;
static gint ett_qsig_mcm_MCMUpdateArg = -1;
static gint ett_qsig_mcm_MCMUpdateReqArg = -1;
static gint ett_qsig_mcm_MCMUpdArgArgumentExt = -1;
static gint ett_qsig_mcm_MCMUpdateReqRes = -1;
static gint ett_qsig_mcm_MCMUpdateReqResElt = -1;
static gint ett_qsig_mcm_MCMUpdResArgumentExt = -1;
static gint ett_qsig_mcm_PartyInfo = -1;
static gint ett_qsig_mcm_UpdateInfo = -1;
static gint ett_qsig_mcm_AllMsgInfo = -1;
static gint ett_qsig_mcm_MessageInfo = -1;
static gint ett_qsig_mcm_CompleteInfo = -1;
static gint ett_qsig_mcm_AddressHeader = -1;
static gint ett_qsig_mcm_CompressedInfo = -1;
static gint ett_qsig_mcm_MsgCentreId = -1;
static gint ett_qsig_mcm_MCMExtensions = -1;

/* --- Module SS-MID-Operations-asn1-97 --- --- ---                           */

static gint ett_qsig_mid_MIDMailboxAuthArg = -1;
static gint ett_qsig_mid_MIDMailboxIDArg = -1;
static gint ett_qsig_mid_PartyInfo = -1;
static gint ett_qsig_mid_String = -1;
static gint ett_qsig_mid_MIDExtensions = -1;
static gint ett_qsig_mid_SEQUENCE_OF_Extension = -1;

/*--- End of included file: packet-qsig-ett.c ---*/
#line 309 "../../asn1/qsig/packet-qsig-template.c"
static gint ett_cnq_PSS1InformationElement = -1;

/* Preferences */

/* Subdissectors */
static dissector_handle_t q931_ie_handle = NULL;

/* Global variables */
static const char *extension_oid = NULL;
static GHashTable *qsig_opcode2oid_hashtable = NULL;
static GHashTable *qsig_oid2op_hashtable = NULL;

/* Dissector tables */
static dissector_table_t extension_dissector_table;


/*--- Included file: packet-qsig-fn.c ---*/
#line 1 "../../asn1/qsig/packet-qsig-fn.c"

/* --- Modules Manufacturer-specific-service-extension-class-asn1-97 PSS1-generic-parameters-definition-asn1-97 Addressing-Data-Elements-asn1-97 --- --- --- */



static int
dissect_qsig_T_extensionId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &extension_oid);

  return offset;
}



static int
dissect_qsig_T_extensionArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 144 "../../asn1/qsig/qsig.cnf"
    tvbuff_t *next_tvb;

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (!dissector_try_string(extension_dissector_table, extension_oid, next_tvb, actx->pinfo, tree, NULL)) {
        proto_tree *next_tree;

        next_tree=proto_tree_add_subtree_format(tree, next_tvb, 0, -1, ett_qsig_unknown_extension, NULL,
                               "QSIG: Dissector for extension with OID:%s not implemented.", extension_oid);

        dissect_unknown_ber(actx->pinfo, next_tvb, offset, next_tree);
    }

    offset+=tvb_length_remaining(tvb, offset);


  return offset;
}


static const ber_sequence_t qsig_Extension_sequence[] = {
  { &hf_qsig_extensionId    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_qsig_T_extensionId },
  { &hf_qsig_extensionArgument, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_qsig_T_extensionArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 141 "../../asn1/qsig/qsig.cnf"
  extension_oid = NULL;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_Extension_sequence, hf_index, ett_qsig_Extension);

  return offset;
}



static int
dissect_qsig_PSS1InformationElement_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 164 "../../asn1/qsig/qsig.cnf"
  tvbuff_t *out_tvb = NULL;
  proto_tree *data_tree;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &out_tvb);

  data_tree = proto_item_add_subtree(actx->created_item, ett_cnq_PSS1InformationElement);
  if (out_tvb && (tvb_length(out_tvb) > 0) && q931_ie_handle)
    call_dissector(q931_ie_handle, out_tvb, actx->pinfo, data_tree);


  return offset;
}



static int
dissect_qsig_PSS1InformationElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, TRUE, dissect_qsig_PSS1InformationElement_U);

  return offset;
}



static int
dissect_qsig_NumberDigits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string qsig_PublicTypeOfNumber_vals[] = {
  {   0, "unknown" },
  {   1, "internationalNumber" },
  {   2, "nationalNumber" },
  {   3, "networkSpecificNumber" },
  {   4, "subscriberNumber" },
  {   6, "abbreviatedNumber" },
  { 0, NULL }
};


static int
dissect_qsig_PublicTypeOfNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_PublicPartyNumber_sequence[] = {
  { &hf_qsig_publicTypeOfNumber, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_PublicTypeOfNumber },
  { &hf_qsig_publicNumberDigits, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_qsig_NumberDigits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PublicPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_PublicPartyNumber_sequence, hf_index, ett_qsig_PublicPartyNumber);

  return offset;
}


static const value_string qsig_PrivateTypeOfNumber_vals[] = {
  {   0, "unknown" },
  {   1, "level2RegionalNumber" },
  {   2, "level1RegionalNumber" },
  {   3, "pISNSpecificNumber" },
  {   4, "localNumber" },
  {   6, "abbreviatedNumber" },
  { 0, NULL }
};


static int
dissect_qsig_PrivateTypeOfNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_PrivatePartyNumber_sequence[] = {
  { &hf_qsig_privateTypeOfNumber, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_PrivateTypeOfNumber },
  { &hf_qsig_privateNumberDigits, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_qsig_NumberDigits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PrivatePartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_PrivatePartyNumber_sequence, hf_index, ett_qsig_PrivatePartyNumber);

  return offset;
}


static const value_string qsig_PartyNumber_vals[] = {
  {   0, "unknownPartyNumber" },
  {   1, "publicPartyNumber" },
  {   3, "dataPartyNumber" },
  {   4, "telexPartyNumber" },
  {   5, "privatePartyNumber" },
  {   8, "nationalStandardPartyNumber" },
  { 0, NULL }
};

static const ber_choice_t qsig_PartyNumber_choice[] = {
  {   0, &hf_qsig_unknownPartyNumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_NumberDigits },
  {   1, &hf_qsig_publicPartyNumber, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_PublicPartyNumber },
  {   3, &hf_qsig_dataPartyNumber, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_NumberDigits },
  {   4, &hf_qsig_telexPartyNumber, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_NumberDigits },
  {   5, &hf_qsig_privatePartyNumber, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_qsig_PrivatePartyNumber },
  {   8, &hf_qsig_nationalStandardPartyNumber, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_qsig_NumberDigits },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_PartyNumber_choice, hf_index, ett_qsig_PartyNumber,
                                 NULL);

  return offset;
}


static const value_string qsig_ScreeningIndicator_vals[] = {
  {   0, "userProvidedNotScreened" },
  {   1, "userProvidedVerifiedAndPassed" },
  {   2, "userProvidedVerifiedAndFailed" },
  {   3, "networkProvided" },
  { 0, NULL }
};


static int
dissect_qsig_ScreeningIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_qsig_SubaddressInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t qsig_UserSpecifiedSubaddress_sequence[] = {
  { &hf_qsig_subaddressInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_SubaddressInformation },
  { &hf_qsig_oddCountIndicator, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_UserSpecifiedSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_UserSpecifiedSubaddress_sequence, hf_index, ett_qsig_UserSpecifiedSubaddress);

  return offset;
}



static int
dissect_qsig_NSAPSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string qsig_PartySubaddress_vals[] = {
  {   0, "userSpecifiedSubaddress" },
  {   1, "nSAPSubaddress" },
  { 0, NULL }
};

static const ber_choice_t qsig_PartySubaddress_choice[] = {
  {   0, &hf_qsig_userSpecifiedSubaddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_UserSpecifiedSubaddress },
  {   1, &hf_qsig_nSAPSubaddress , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_NSAPSubaddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PartySubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_PartySubaddress_choice, hf_index, ett_qsig_PartySubaddress,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_AddressScreened_sequence[] = {
  { &hf_qsig_partyNumber    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_screeningIndicator, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_ScreeningIndicator },
  { &hf_qsig_partySubaddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartySubaddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_AddressScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_AddressScreened_sequence, hf_index, ett_qsig_AddressScreened);

  return offset;
}



static int
dissect_qsig_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string qsig_PresentedAddressScreened_vals[] = {
  {   0, "presentationAllowedAddressS" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddressS" },
  { 0, NULL }
};

static const ber_choice_t qsig_PresentedAddressScreened_choice[] = {
  {   0, &hf_qsig_presentationAllowedAddressS, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_AddressScreened },
  {   1, &hf_qsig_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   2, &hf_qsig_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   3, &hf_qsig_presentationRestrictedAddressS, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_AddressScreened },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PresentedAddressScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_PresentedAddressScreened_choice, hf_index, ett_qsig_PresentedAddressScreened,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_Address_sequence[] = {
  { &hf_qsig_partyNumber    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_partySubaddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartySubaddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_Address_sequence, hf_index, ett_qsig_Address);

  return offset;
}


static const value_string qsig_PresentedAddressUnscreened_vals[] = {
  {   0, "presentationAllowedAddressU" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddressU" },
  { 0, NULL }
};

static const ber_choice_t qsig_PresentedAddressUnscreened_choice[] = {
  {   0, &hf_qsig_presentationAllowedAddressU, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_Address },
  {   1, &hf_qsig_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   2, &hf_qsig_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   3, &hf_qsig_presentationRestrictedAddressU, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_Address },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PresentedAddressUnscreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_PresentedAddressUnscreened_choice, hf_index, ett_qsig_PresentedAddressUnscreened,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_NumberScreened_sequence[] = {
  { &hf_qsig_partyNumber    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_screeningIndicator, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_ScreeningIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_NumberScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_NumberScreened_sequence, hf_index, ett_qsig_NumberScreened);

  return offset;
}


static const value_string qsig_PresentedNumberScreened_vals[] = {
  {   0, "presentationAllowedAddressNS" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddressNS" },
  { 0, NULL }
};

static const ber_choice_t qsig_PresentedNumberScreened_choice[] = {
  {   0, &hf_qsig_presentationAllowedAddressNS, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_NumberScreened },
  {   1, &hf_qsig_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   2, &hf_qsig_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   3, &hf_qsig_presentationRestrictedAddressNS, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_NumberScreened },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PresentedNumberScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_PresentedNumberScreened_choice, hf_index, ett_qsig_PresentedNumberScreened,
                                 NULL);

  return offset;
}


static const value_string qsig_PresentedNumberUnscreened_vals[] = {
  {   0, "presentationAllowedAddressNU" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddressNU" },
  { 0, NULL }
};

static const ber_choice_t qsig_PresentedNumberUnscreened_choice[] = {
  {   0, &hf_qsig_presentationAllowedAddressNU, BER_CLASS_CON, 0, 0, dissect_qsig_PartyNumber },
  {   1, &hf_qsig_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   2, &hf_qsig_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   3, &hf_qsig_presentationRestrictedAddressNU, BER_CLASS_CON, 3, 0, dissect_qsig_PartyNumber },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PresentedNumberUnscreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_PresentedNumberUnscreened_choice, hf_index, ett_qsig_PresentedNumberUnscreened,
                                 NULL);

  return offset;
}



static int
dissect_qsig_PresentationAllowedIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


/* --- Module Name-Operations-asn1-97 --- --- ---                             */



static int
dissect_qsig_na_NameData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string qsig_na_CharacterSet_vals[] = {
  {   0, "unknown" },
  {   1, "iso8859-1" },
  {   3, "iso8859-2" },
  {   4, "iso8859-3" },
  {   5, "iso8859-4" },
  {   6, "iso8859-5" },
  {   7, "iso8859-7" },
  {   8, "iso10646-BmpString" },
  {   9, "iso10646-utf-8String" },
  { 0, NULL }
};


static int
dissect_qsig_na_CharacterSet(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_na_NameSet_sequence[] = {
  { &hf_qsig_na_nameData    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_na_NameData },
  { &hf_qsig_na_characterSet, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_na_CharacterSet },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_na_NameSet(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_na_NameSet_sequence, hf_index, ett_qsig_na_NameSet);

  return offset;
}


static const value_string qsig_na_NamePresentationAllowed_vals[] = {
  {   0, "namePresentationAllowedSimple" },
  {   1, "namePresentationAllowedExtended" },
  { 0, NULL }
};

static const ber_choice_t qsig_na_NamePresentationAllowed_choice[] = {
  {   0, &hf_qsig_na_namePresentationAllowedSimple, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_na_NameData },
  {   1, &hf_qsig_na_namePresentationAllowedExtended, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_na_NameSet },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_na_NamePresentationAllowed(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_na_NamePresentationAllowed_choice, hf_index, ett_qsig_na_NamePresentationAllowed,
                                 NULL);

  return offset;
}



static int
dissect_qsig_na_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string qsig_na_NamePresentationRestricted_vals[] = {
  {   2, "namePresentationRestrictedSimple" },
  {   3, "namePresentationRestrictedExtended" },
  {   7, "namePresentationRestrictedNull" },
  { 0, NULL }
};

static const ber_choice_t qsig_na_NamePresentationRestricted_choice[] = {
  {   2, &hf_qsig_na_namePresentationRestrictedSimple, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_na_NameData },
  {   3, &hf_qsig_na_namePresentationRestrictedExtended, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_na_NameSet },
  {   7, &hf_qsig_na_namePresentationRestrictedNull, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_qsig_na_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_na_NamePresentationRestricted(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_na_NamePresentationRestricted_choice, hf_index, ett_qsig_na_NamePresentationRestricted,
                                 NULL);

  return offset;
}



static int
dissect_qsig_na_NameNotAvailable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 4, TRUE, dissect_qsig_na_NULL);

  return offset;
}


static const ber_choice_t qsig_na_Name_choice[] = {
  {   0, &hf_qsig_na_namePresentationAllowed, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_na_NamePresentationAllowed },
  {   1, &hf_qsig_na_namePresentationRestricted, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_na_NamePresentationRestricted },
  {   2, &hf_qsig_na_nameNotAvailable, BER_CLASS_CON, 4, BER_FLAGS_NOOWNTAG, dissect_qsig_na_NameNotAvailable },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_qsig_na_Name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_na_Name_choice, hf_index, ett_qsig_na_Name,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_na_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_na_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_na_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_na_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_na_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_na_NameExtension_vals[] = {
  {   5, "single" },
  {   6, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_na_NameExtension_choice[] = {
  {   5, &hf_qsig_na_single      , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   6, &hf_qsig_na_multiple    , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_na_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_na_NameExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_na_NameExtension_choice, hf_index, ett_qsig_na_NameExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_na_T_nameSequence_sequence[] = {
  { &hf_qsig_na_name        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_na_Name },
  { &hf_qsig_na_extensionNA , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_na_NameExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_na_T_nameSequence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_na_T_nameSequence_sequence, hf_index, ett_qsig_na_T_nameSequence);

  return offset;
}


static const value_string qsig_na_NameArg_vals[] = {
  {   0, "name" },
  {   1, "nameSequence" },
  { 0, NULL }
};

static const ber_choice_t qsig_na_NameArg_choice[] = {
  {   0, &hf_qsig_na_name        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_na_Name },
  {   1, &hf_qsig_na_nameSequence, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_na_T_nameSequence },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_na_NameArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_na_NameArg_choice, hf_index, ett_qsig_na_NameArg,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_na_NameArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_na_NameArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_na_qsig_na_NameArg_PDU);
  return offset;
}


/* --- Module Call-Diversion-Operations-asn1-97 --- --- ---                   */


static const value_string qsig_cf_Procedure_vals[] = {
  {   0, "cfu" },
  {   1, "cfb" },
  {   2, "cfnr" },
  { 0, NULL }
};


static int
dissect_qsig_cf_Procedure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_cf_BasicService_vals[] = {
  {   0, "allServices" },
  {   1, "speech" },
  {   2, "unrestrictedDigitalInformation" },
  {   3, "audio3100Hz" },
  {  32, "telephony" },
  {  33, "teletex" },
  {  34, "telefaxGroup4Class1" },
  {  35, "videotexSyntaxBased" },
  {  36, "videotelephony" },
  { 0, NULL }
};


static int
dissect_qsig_cf_BasicService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_cf_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_cf_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_cf_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_cf_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_cf_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_cf_ADExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_ADExtension_choice[] = {
  {   1, &hf_qsig_cf_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cf_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_ADExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_ADExtension_choice, hf_index, ett_qsig_cf_ADExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cf_ARG_activateDiversionQ_sequence[] = {
  { &hf_qsig_cf_procedure   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_Procedure },
  { &hf_qsig_cf_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_cf_divertedToAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Address },
  { &hf_qsig_cf_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cf_activatingUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cf_extensionAD , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cf_ADExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_ARG_activateDiversionQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cf_ARG_activateDiversionQ_sequence, hf_index, ett_qsig_cf_ARG_activateDiversionQ);

  return offset;
}



static int
dissect_qsig_cf_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string qsig_cf_RES_activateDiversionQ_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_RES_activateDiversionQ_choice[] = {
  {   0, &hf_qsig_cf_null        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_NULL },
  {   1, &hf_qsig_cf_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cf_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_RES_activateDiversionQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_RES_activateDiversionQ_choice, hf_index, ett_qsig_cf_RES_activateDiversionQ,
                                 NULL);

  return offset;
}


static const value_string qsig_cf_DDExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_DDExtension_choice[] = {
  {   1, &hf_qsig_cf_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cf_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_DDExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_DDExtension_choice, hf_index, ett_qsig_cf_DDExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cf_ARG_deactivateDiversionQ_sequence[] = {
  { &hf_qsig_cf_procedure   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_Procedure },
  { &hf_qsig_cf_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_cf_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cf_deactivatingUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cf_extensionDD , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cf_DDExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_ARG_deactivateDiversionQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cf_ARG_deactivateDiversionQ_sequence, hf_index, ett_qsig_cf_ARG_deactivateDiversionQ);

  return offset;
}


static const value_string qsig_cf_RES_deactivateDiversionQ_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_RES_deactivateDiversionQ_choice[] = {
  {   0, &hf_qsig_cf_null        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_NULL },
  {   1, &hf_qsig_cf_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cf_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_RES_deactivateDiversionQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_RES_deactivateDiversionQ_choice, hf_index, ett_qsig_cf_RES_deactivateDiversionQ,
                                 NULL);

  return offset;
}


static const value_string qsig_cf_IDExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_IDExtension_choice[] = {
  {   1, &hf_qsig_cf_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cf_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_IDExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_IDExtension_choice, hf_index, ett_qsig_cf_IDExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cf_ARG_interrogateDiversionQ_sequence[] = {
  { &hf_qsig_cf_procedure   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_Procedure },
  { &hf_qsig_cf_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_cf_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cf_interrogatingUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cf_extensionID , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cf_IDExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_ARG_interrogateDiversionQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cf_ARG_interrogateDiversionQ_sequence, hf_index, ett_qsig_cf_ARG_interrogateDiversionQ);

  return offset;
}


static const value_string qsig_cf_CHRExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_CHRExtension_choice[] = {
  {   1, &hf_qsig_cf_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cf_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_CHRExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_CHRExtension_choice, hf_index, ett_qsig_cf_CHRExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cf_ARG_checkRestriction_sequence[] = {
  { &hf_qsig_cf_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cf_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_cf_divertedToNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cf_extensionCHR, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cf_CHRExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_ARG_checkRestriction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cf_ARG_checkRestriction_sequence, hf_index, ett_qsig_cf_ARG_checkRestriction);

  return offset;
}


static const value_string qsig_cf_RES_checkRestriction_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_RES_checkRestriction_choice[] = {
  {   0, &hf_qsig_cf_null        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_NULL },
  {   1, &hf_qsig_cf_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cf_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_RES_checkRestriction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_RES_checkRestriction_choice, hf_index, ett_qsig_cf_RES_checkRestriction,
                                 NULL);

  return offset;
}


static const value_string qsig_cf_DiversionReason_vals[] = {
  {   0, "unknown" },
  {   1, "cfu" },
  {   2, "cfb" },
  {   3, "cfnr" },
  { 0, NULL }
};


static int
dissect_qsig_cf_DiversionReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_qsig_cf_INTEGER_1_15(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string qsig_cf_SubscriptionOption_vals[] = {
  {   0, "noNotification" },
  {   1, "notificationWithoutDivertedToNr" },
  {   2, "notificationWithDivertedToNr" },
  { 0, NULL }
};


static int
dissect_qsig_cf_SubscriptionOption(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_cf_CRRExtension_vals[] = {
  {   9, "single" },
  {  10, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_CRRExtension_choice[] = {
  {   9, &hf_qsig_cf_single      , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {  10, &hf_qsig_cf_multiple    , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_CRRExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_CRRExtension_choice, hf_index, ett_qsig_cf_CRRExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cf_ARG_callRerouteing_sequence[] = {
  { &hf_qsig_cf_rerouteingReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_DiversionReason },
  { &hf_qsig_cf_originalRerouteingReason, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cf_DiversionReason },
  { &hf_qsig_cf_calledAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Address },
  { &hf_qsig_cf_diversionCounter, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_INTEGER_1_15 },
  { &hf_qsig_cf_pSS1InfoElement, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_qsig_PSS1InformationElement },
  { &hf_qsig_cf_lastRerouteingNr, BER_CLASS_CON, 1, 0, dissect_qsig_PresentedNumberUnscreened },
  { &hf_qsig_cf_subscriptionOption, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SubscriptionOption },
  { &hf_qsig_cf_callingPartySubaddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_qsig_PartySubaddress },
  { &hf_qsig_cf_callingNumber, BER_CLASS_CON, 4, 0, dissect_qsig_PresentedNumberScreened },
  { &hf_qsig_cf_callingName , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_cf_originalCalledNr, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL, dissect_qsig_PresentedNumberUnscreened },
  { &hf_qsig_cf_redirectingName, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_cf_originalCalledName, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_cf_extensionCRR, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cf_CRRExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_ARG_callRerouteing(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cf_ARG_callRerouteing_sequence, hf_index, ett_qsig_cf_ARG_callRerouteing);

  return offset;
}


static const value_string qsig_cf_RES_callRerouteing_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_RES_callRerouteing_choice[] = {
  {   0, &hf_qsig_cf_null        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_NULL },
  {   1, &hf_qsig_cf_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cf_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_RES_callRerouteing(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_RES_callRerouteing_choice, hf_index, ett_qsig_cf_RES_callRerouteing,
                                 NULL);

  return offset;
}


static const value_string qsig_cf_DLI1Extension_vals[] = {
  {   9, "single" },
  {  10, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_DLI1Extension_choice[] = {
  {   9, &hf_qsig_cf_single      , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {  10, &hf_qsig_cf_multiple    , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_DLI1Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_DLI1Extension_choice, hf_index, ett_qsig_cf_DLI1Extension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cf_ARG_divertingLegInformation1_sequence[] = {
  { &hf_qsig_cf_diversionReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_DiversionReason },
  { &hf_qsig_cf_subscriptionOption, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_SubscriptionOption },
  { &hf_qsig_cf_nominatedNr , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cf_extensionDLI1, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cf_DLI1Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_ARG_divertingLegInformation1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cf_ARG_divertingLegInformation1_sequence, hf_index, ett_qsig_cf_ARG_divertingLegInformation1);

  return offset;
}


static const value_string qsig_cf_DLI2Extension_vals[] = {
  {   5, "single" },
  {   6, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_DLI2Extension_choice[] = {
  {   5, &hf_qsig_cf_single      , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   6, &hf_qsig_cf_multiple    , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_DLI2Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_DLI2Extension_choice, hf_index, ett_qsig_cf_DLI2Extension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cf_ARG_divertingLegInformation2_sequence[] = {
  { &hf_qsig_cf_diversionCounter, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_INTEGER_1_15 },
  { &hf_qsig_cf_diversionReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_DiversionReason },
  { &hf_qsig_cf_originalDiversionReason, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cf_DiversionReason },
  { &hf_qsig_cf_divertingNr , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_PresentedNumberUnscreened },
  { &hf_qsig_cf_originalCalledNr, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_qsig_PresentedNumberUnscreened },
  { &hf_qsig_cf_redirectingName, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_cf_originalCalledName, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_cf_extensionDLI2, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cf_DLI2Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_ARG_divertingLegInformation2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cf_ARG_divertingLegInformation2_sequence, hf_index, ett_qsig_cf_ARG_divertingLegInformation2);

  return offset;
}


static const value_string qsig_cf_DLI3Extension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_DLI3Extension_choice[] = {
  {   1, &hf_qsig_cf_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cf_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_DLI3Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_DLI3Extension_choice, hf_index, ett_qsig_cf_DLI3Extension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cf_ARG_divertingLegInformation3_sequence[] = {
  { &hf_qsig_cf_presentationAllowedIndicator, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_qsig_PresentationAllowedIndicator },
  { &hf_qsig_cf_redirectionName, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_cf_extensionDLI3, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cf_DLI3Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_ARG_divertingLegInformation3(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cf_ARG_divertingLegInformation3_sequence, hf_index, ett_qsig_cf_ARG_divertingLegInformation3);

  return offset;
}


static const value_string qsig_cf_ARG_cfnrDivertedLegFailed_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_ARG_cfnrDivertedLegFailed_choice[] = {
  {   0, &hf_qsig_cf_null        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_NULL },
  {   1, &hf_qsig_cf_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cf_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_ARG_cfnrDivertedLegFailed(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_ARG_cfnrDivertedLegFailed_choice, hf_index, ett_qsig_cf_ARG_cfnrDivertedLegFailed,
                                 NULL);

  return offset;
}



static int
dissect_qsig_cf_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string qsig_cf_IRExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cf_IRExtension_choice[] = {
  {   1, &hf_qsig_cf_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cf_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cf_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_IRExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_IRExtension_choice, hf_index, ett_qsig_cf_IRExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cf_IntResult_sequence[] = {
  { &hf_qsig_cf_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cf_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_cf_procedure   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_Procedure },
  { &hf_qsig_cf_divertedToAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Address },
  { &hf_qsig_cf_remoteEnabled, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BOOLEAN },
  { &hf_qsig_cf_extensionIR , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cf_IRExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cf_IntResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cf_IntResult_sequence, hf_index, ett_qsig_cf_IntResult);

  return offset;
}


static const ber_sequence_t qsig_cf_IntResultList_set_of[1] = {
  { &hf_qsig_cf_IntResultList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_IntResult },
};

static int
dissect_qsig_cf_IntResultList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 qsig_cf_IntResultList_set_of, hf_index, ett_qsig_cf_IntResultList);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_cf_ARG_activateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_ARG_activateDiversionQ(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_activateDiversionQ_PDU);
  return offset;
}
static int dissect_qsig_cf_RES_activateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_RES_activateDiversionQ(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_RES_activateDiversionQ_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_deactivateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_ARG_deactivateDiversionQ(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_deactivateDiversionQ_PDU);
  return offset;
}
static int dissect_qsig_cf_RES_deactivateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_RES_deactivateDiversionQ(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_RES_deactivateDiversionQ_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_interrogateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_ARG_interrogateDiversionQ(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_interrogateDiversionQ_PDU);
  return offset;
}
static int dissect_qsig_cf_IntResultList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_IntResultList(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_IntResultList_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_checkRestriction_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_ARG_checkRestriction(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_checkRestriction_PDU);
  return offset;
}
static int dissect_qsig_cf_RES_checkRestriction_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_RES_checkRestriction(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_RES_checkRestriction_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_callRerouteing_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_ARG_callRerouteing(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_callRerouteing_PDU);
  return offset;
}
static int dissect_qsig_cf_RES_callRerouteing_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_RES_callRerouteing(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_RES_callRerouteing_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_divertingLegInformation1_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_ARG_divertingLegInformation1(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_divertingLegInformation1_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_divertingLegInformation2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_ARG_divertingLegInformation2(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_divertingLegInformation2_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_divertingLegInformation3_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_ARG_divertingLegInformation3(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_divertingLegInformation3_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_cfnrDivertedLegFailed_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cf_ARG_cfnrDivertedLegFailed(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_cfnrDivertedLegFailed_PDU);
  return offset;
}
static int dissect_qsig_cf_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_Extension_PDU);
  return offset;
}


/* --- Module Path-Replacement-Operations-asn1-97 --- --- ---                 */



static int
dissect_qsig_pr_CallIdentity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t qsig_pr_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_pr_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_pr_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_pr_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_pr_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_pr_PRPExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_pr_PRPExtension_choice[] = {
  {   1, &hf_qsig_pr_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_pr_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_pr_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pr_PRPExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pr_PRPExtension_choice, hf_index, ett_qsig_pr_PRPExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_pr_PRProposeArg_sequence[] = {
  { &hf_qsig_pr_callIdentity, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_qsig_pr_CallIdentity },
  { &hf_qsig_pr_rerouteingNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_pr_extensionPRP, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pr_PRPExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pr_PRProposeArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pr_PRProposeArg_sequence, hf_index, ett_qsig_pr_PRProposeArg);

  return offset;
}


static const value_string qsig_pr_PRSExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_pr_PRSExtension_choice[] = {
  {   1, &hf_qsig_pr_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_pr_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_pr_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pr_PRSExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pr_PRSExtension_choice, hf_index, ett_qsig_pr_PRSExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_pr_PRSetupArg_sequence[] = {
  { &hf_qsig_pr_callIdentity, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_qsig_pr_CallIdentity },
  { &hf_qsig_pr_extensionPRS, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pr_PRSExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pr_PRSetupArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pr_PRSetupArg_sequence, hf_index, ett_qsig_pr_PRSetupArg);

  return offset;
}


static const value_string qsig_pr_PRRExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_pr_PRRExtension_choice[] = {
  {   1, &hf_qsig_pr_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_pr_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_pr_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pr_PRRExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pr_PRRExtension_choice, hf_index, ett_qsig_pr_PRRExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_pr_PRRetainArg_sequence[] = {
  { &hf_qsig_pr_callIdentity, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_qsig_pr_CallIdentity },
  { &hf_qsig_pr_rerouteingNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_pr_extensionPRR, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pr_PRRExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pr_PRRetainArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pr_PRRetainArg_sequence, hf_index, ett_qsig_pr_PRRetainArg);

  return offset;
}



static int
dissect_qsig_pr_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string qsig_pr_DummyResult_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_pr_DummyResult_choice[] = {
  {   0, &hf_qsig_pr_null        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_pr_NULL },
  {   1, &hf_qsig_pr_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_pr_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_pr_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pr_DummyResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pr_DummyResult_choice, hf_index, ett_qsig_pr_DummyResult,
                                 NULL);

  return offset;
}


static const value_string qsig_pr_DummyArg_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_pr_DummyArg_choice[] = {
  {   0, &hf_qsig_pr_null        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_pr_NULL },
  {   1, &hf_qsig_pr_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_pr_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_pr_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pr_DummyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pr_DummyArg_choice, hf_index, ett_qsig_pr_DummyArg,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_pr_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pr_DummyArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pr_qsig_pr_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_pr_PRProposeArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pr_PRProposeArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pr_qsig_pr_PRProposeArg_PDU);
  return offset;
}
static int dissect_qsig_pr_PRSetupArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pr_PRSetupArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pr_qsig_pr_PRSetupArg_PDU);
  return offset;
}
static int dissect_qsig_pr_DummyResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pr_DummyResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pr_qsig_pr_DummyResult_PDU);
  return offset;
}
static int dissect_qsig_pr_PRRetainArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pr_PRRetainArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pr_qsig_pr_PRRetainArg_PDU);
  return offset;
}
static int dissect_qsig_pr_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pr_qsig_pr_Extension_PDU);
  return offset;
}


/* --- Module Call-Transfer-Operations-asn1-97 --- --- ---                    */



static int
dissect_qsig_ct_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_ct_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_ct_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_ct_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_ct_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_ct_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_ct_DummyArg_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ct_DummyArg_choice[] = {
  {   0, &hf_qsig_ct_null        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_ct_NULL },
  {   1, &hf_qsig_ct_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_ct_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_ct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_DummyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ct_DummyArg_choice, hf_index, ett_qsig_ct_DummyArg,
                                 NULL);

  return offset;
}


static const value_string qsig_ct_DummyRes_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ct_DummyRes_choice[] = {
  {   0, &hf_qsig_ct_null        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_ct_NULL },
  {   1, &hf_qsig_ct_single      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_ct_multiple    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_ct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_DummyRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ct_DummyRes_choice, hf_index, ett_qsig_ct_DummyRes,
                                 NULL);

  return offset;
}



static int
dissect_qsig_ct_CallIdentity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string qsig_ct_T_resultExtension_vals[] = {
  {   6, "single" },
  {   7, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ct_T_resultExtension_choice[] = {
  {   6, &hf_qsig_ct_single      , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   7, &hf_qsig_ct_multiple    , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_qsig_ct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_T_resultExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ct_T_resultExtension_choice, hf_index, ett_qsig_ct_T_resultExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ct_CTIdentifyRes_sequence[] = {
  { &hf_qsig_ct_callIdentity, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_qsig_ct_CallIdentity },
  { &hf_qsig_ct_rerouteingNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_ct_resultExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ct_T_resultExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_CTIdentifyRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ct_CTIdentifyRes_sequence, hf_index, ett_qsig_ct_CTIdentifyRes);

  return offset;
}


static const value_string qsig_ct_CTIargumentExtension_vals[] = {
  {   6, "single" },
  {   7, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ct_CTIargumentExtension_choice[] = {
  {   6, &hf_qsig_ct_single      , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   7, &hf_qsig_ct_multiple    , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_qsig_ct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_CTIargumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ct_CTIargumentExtension_choice, hf_index, ett_qsig_ct_CTIargumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ct_CTInitiateArg_sequence[] = {
  { &hf_qsig_ct_callIdentity, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_qsig_ct_CallIdentity },
  { &hf_qsig_ct_rerouteingNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_ct_argumentExtensionCTI, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ct_CTIargumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_CTInitiateArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ct_CTInitiateArg_sequence, hf_index, ett_qsig_ct_CTInitiateArg);

  return offset;
}


static const value_string qsig_ct_CTSargumentExtension_vals[] = {
  {   0, "single" },
  {   1, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ct_CTSargumentExtension_choice[] = {
  {   0, &hf_qsig_ct_single      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   1, &hf_qsig_ct_multiple    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_ct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_CTSargumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ct_CTSargumentExtension_choice, hf_index, ett_qsig_ct_CTSargumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ct_CTSetupArg_sequence[] = {
  { &hf_qsig_ct_callIdentity, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_qsig_ct_CallIdentity },
  { &hf_qsig_ct_argumentExtensionCTS, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ct_CTSargumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_CTSetupArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ct_CTSetupArg_sequence, hf_index, ett_qsig_ct_CTSetupArg);

  return offset;
}


static const value_string qsig_ct_CTAargumentExtension_vals[] = {
  {   9, "single" },
  {  10, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ct_CTAargumentExtension_choice[] = {
  {   9, &hf_qsig_ct_single      , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {  10, &hf_qsig_ct_multiple    , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_qsig_ct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_CTAargumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ct_CTAargumentExtension_choice, hf_index, ett_qsig_ct_CTAargumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ct_CTActiveArg_sequence[] = {
  { &hf_qsig_ct_connectedAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PresentedAddressScreened },
  { &hf_qsig_ct_basicCallInfoElements, BER_CLASS_APP, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_PSS1InformationElement },
  { &hf_qsig_ct_connectedName, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_na_Name },
  { &hf_qsig_ct_argumentExtensionCTA, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ct_CTAargumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_CTActiveArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ct_CTActiveArg_sequence, hf_index, ett_qsig_ct_CTActiveArg);

  return offset;
}


static const value_string qsig_ct_EndDesignation_vals[] = {
  {   0, "primaryEnd" },
  {   1, "secondaryEnd" },
  { 0, NULL }
};


static int
dissect_qsig_ct_EndDesignation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_ct_CallStatus_vals[] = {
  {   0, "answered" },
  {   1, "alerting" },
  { 0, NULL }
};


static int
dissect_qsig_ct_CallStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_ct_CTCargumentExtension_vals[] = {
  {   9, "single" },
  {  10, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ct_CTCargumentExtension_choice[] = {
  {   9, &hf_qsig_ct_single      , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {  10, &hf_qsig_ct_multiple    , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_qsig_ct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_CTCargumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ct_CTCargumentExtension_choice, hf_index, ett_qsig_ct_CTCargumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ct_CTCompleteArg_sequence[] = {
  { &hf_qsig_ct_endDesignation, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_ct_EndDesignation },
  { &hf_qsig_ct_redirectionNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PresentedNumberScreened },
  { &hf_qsig_ct_basicCallInfoElements, BER_CLASS_APP, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_PSS1InformationElement },
  { &hf_qsig_ct_redirectionName, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_na_Name },
  { &hf_qsig_ct_callStatus  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_ct_CallStatus },
  { &hf_qsig_ct_argumentExtensionCTC, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ct_CTCargumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_CTCompleteArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ct_CTCompleteArg_sequence, hf_index, ett_qsig_ct_CTCompleteArg);

  return offset;
}


static const value_string qsig_ct_CTUargumentExtension_vals[] = {
  {   9, "single" },
  {  10, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ct_CTUargumentExtension_choice[] = {
  {   9, &hf_qsig_ct_single      , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {  10, &hf_qsig_ct_multiple    , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_qsig_ct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_CTUargumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ct_CTUargumentExtension_choice, hf_index, ett_qsig_ct_CTUargumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ct_CTUpdateArg_sequence[] = {
  { &hf_qsig_ct_redirectionNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PresentedNumberScreened },
  { &hf_qsig_ct_redirectionName, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_na_Name },
  { &hf_qsig_ct_basicCallInfoElements, BER_CLASS_APP, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_PSS1InformationElement },
  { &hf_qsig_ct_argumentExtensionCTU, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ct_CTUargumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_CTUpdateArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ct_CTUpdateArg_sequence, hf_index, ett_qsig_ct_CTUpdateArg);

  return offset;
}


static const value_string qsig_ct_STargumentExtension_vals[] = {
  {   0, "single" },
  {   1, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ct_STargumentExtension_choice[] = {
  {   0, &hf_qsig_ct_single      , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   1, &hf_qsig_ct_multiple    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_ct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_STargumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ct_STargumentExtension_choice, hf_index, ett_qsig_ct_STargumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ct_SubaddressTransferArg_sequence[] = {
  { &hf_qsig_ct_redirectionSubaddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartySubaddress },
  { &hf_qsig_ct_argumentExtensionST, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ct_STargumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ct_SubaddressTransferArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ct_SubaddressTransferArg_sequence, hf_index, ett_qsig_ct_SubaddressTransferArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_ct_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ct_DummyArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_ct_CTIdentifyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ct_CTIdentifyRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_CTIdentifyRes_PDU);
  return offset;
}
static int dissect_qsig_ct_CTInitiateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ct_CTInitiateArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_CTInitiateArg_PDU);
  return offset;
}
static int dissect_qsig_ct_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ct_DummyRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_ct_CTSetupArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ct_CTSetupArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_CTSetupArg_PDU);
  return offset;
}
static int dissect_qsig_ct_CTActiveArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ct_CTActiveArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_CTActiveArg_PDU);
  return offset;
}
static int dissect_qsig_ct_CTCompleteArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ct_CTCompleteArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_CTCompleteArg_PDU);
  return offset;
}
static int dissect_qsig_ct_CTUpdateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ct_CTUpdateArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_CTUpdateArg_PDU);
  return offset;
}
static int dissect_qsig_ct_SubaddressTransferArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ct_SubaddressTransferArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_SubaddressTransferArg_PDU);
  return offset;
}
static int dissect_qsig_ct_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_Extension_PDU);
  return offset;
}


/* --- Module SS-CC-Operations-asn1-97 --- --- ---                            */



static int
dissect_qsig_cc_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_qsig_cc_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_cc_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_cc_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_cc_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_cc_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_cc_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_cc_CcExtension_vals[] = {
  {   0, "none" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cc_CcExtension_choice[] = {
  {   0, &hf_qsig_cc_none        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_cc_NULL },
  {   1, &hf_qsig_cc_single      , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cc_multiple    , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_qsig_cc_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cc_CcExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cc_CcExtension_choice, hf_index, ett_qsig_cc_CcExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cc_CcRequestArg_sequence[] = {
  { &hf_qsig_cc_numberA     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PresentedNumberUnscreened },
  { &hf_qsig_cc_numberB     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cc_service     , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_qsig_PSS1InformationElement },
  { &hf_qsig_cc_subaddrA    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_qsig_PartySubaddress },
  { &hf_qsig_cc_subaddrB    , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_qsig_PartySubaddress },
  { &hf_qsig_cc_can_retain_service, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cc_BOOLEAN },
  { &hf_qsig_cc_retain_sig_connection, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cc_BOOLEAN },
  { &hf_qsig_cc_extension   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cc_CcExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cc_CcRequestArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cc_CcRequestArg_sequence, hf_index, ett_qsig_cc_CcRequestArg);

  return offset;
}


static const ber_sequence_t qsig_cc_CcRequestRes_sequence[] = {
  { &hf_qsig_cc_no_path_reservation, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cc_BOOLEAN },
  { &hf_qsig_cc_retain_service, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cc_BOOLEAN },
  { &hf_qsig_cc_extension   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cc_CcExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cc_CcRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cc_CcRequestRes_sequence, hf_index, ett_qsig_cc_CcRequestRes);

  return offset;
}


static const ber_sequence_t qsig_cc_T_fullArg_sequence[] = {
  { &hf_qsig_cc_numberA_01  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cc_numberB     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cc_service     , BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_qsig_PSS1InformationElement },
  { &hf_qsig_cc_subaddrA    , BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_qsig_PartySubaddress },
  { &hf_qsig_cc_subaddrB    , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL, dissect_qsig_PartySubaddress },
  { &hf_qsig_cc_extension   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cc_CcExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cc_T_fullArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cc_T_fullArg_sequence, hf_index, ett_qsig_cc_T_fullArg);

  return offset;
}


static const value_string qsig_cc_CcOptionalArg_vals[] = {
  {   0, "fullArg" },
  {   1, "extArg" },
  { 0, NULL }
};

static const ber_choice_t qsig_cc_CcOptionalArg_choice[] = {
  {   0, &hf_qsig_cc_fullArg     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_cc_T_fullArg },
  {   1, &hf_qsig_cc_extArg      , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_cc_CcExtension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cc_CcOptionalArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cc_CcOptionalArg_choice, hf_index, ett_qsig_cc_CcOptionalArg,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_cc_CcRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cc_CcRequestArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cc_qsig_cc_CcRequestArg_PDU);
  return offset;
}
static int dissect_qsig_cc_CcRequestRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cc_CcRequestRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cc_qsig_cc_CcRequestRes_PDU);
  return offset;
}
static int dissect_qsig_cc_CcOptionalArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cc_CcOptionalArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cc_qsig_cc_CcOptionalArg_PDU);
  return offset;
}
static int dissect_qsig_cc_CcExtension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cc_CcExtension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cc_qsig_cc_CcExtension_PDU);
  return offset;
}
static int dissect_qsig_cc_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cc_qsig_cc_Extension_PDU);
  return offset;
}


/* --- Module Call-Offer-Operations-asn1-97 --- --- ---                       */


static const asn_namedbit qsig_co_ServiceList_bits[] = {
  {  0, &hf_qsig_co_ServiceList_callOffer, -1, -1, "callOffer", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_qsig_co_ServiceList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    qsig_co_ServiceList_bits, hf_index, ett_qsig_co_ServiceList,
                                    NULL);

  return offset;
}


static const ber_sequence_t qsig_co_T_extendedServiceList_sequence[] = {
  { &hf_qsig_co_serviceList , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_co_ServiceList },
  { &hf_qsig_co_extension   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_co_T_extendedServiceList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_co_T_extendedServiceList_sequence, hf_index, ett_qsig_co_T_extendedServiceList);

  return offset;
}


static const value_string qsig_co_PathRetainArg_vals[] = {
  {   0, "serviceList" },
  {   1, "extendedServiceList" },
  { 0, NULL }
};

static const ber_choice_t qsig_co_PathRetainArg_choice[] = {
  {   0, &hf_qsig_co_serviceList , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_co_ServiceList },
  {   1, &hf_qsig_co_extendedServiceList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_co_T_extendedServiceList },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_co_PathRetainArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_co_PathRetainArg_choice, hf_index, ett_qsig_co_PathRetainArg,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_co_T_extendedServiceList_01_sequence[] = {
  { &hf_qsig_co_serviceList , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_co_ServiceList },
  { &hf_qsig_co_extension   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_co_T_extendedServiceList_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_co_T_extendedServiceList_01_sequence, hf_index, ett_qsig_co_T_extendedServiceList_01);

  return offset;
}


static const value_string qsig_co_ServiceAvailableArg_vals[] = {
  {   0, "serviceList" },
  {   1, "extendedServiceList" },
  { 0, NULL }
};

static const ber_choice_t qsig_co_ServiceAvailableArg_choice[] = {
  {   0, &hf_qsig_co_serviceList , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_co_ServiceList },
  {   1, &hf_qsig_co_extendedServiceList_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_co_T_extendedServiceList_01 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_co_ServiceAvailableArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_co_ServiceAvailableArg_choice, hf_index, ett_qsig_co_ServiceAvailableArg,
                                 NULL);

  return offset;
}



static int
dissect_qsig_co_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_co_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_co_sequenceOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_co_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_co_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_co_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_co_DummyArg_vals[] = {
  {   0, "null" },
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_co_DummyArg_choice[] = {
  {   0, &hf_qsig_co_null        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_co_NULL },
  {   1, &hf_qsig_co_extension   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_co_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_co_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_co_DummyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_co_DummyArg_choice, hf_index, ett_qsig_co_DummyArg,
                                 NULL);

  return offset;
}


static const value_string qsig_co_DummyRes_vals[] = {
  {   0, "null" },
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_co_DummyRes_choice[] = {
  {   0, &hf_qsig_co_null        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_co_NULL },
  {   1, &hf_qsig_co_extension   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_co_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_co_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_co_DummyRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_co_DummyRes_choice, hf_index, ett_qsig_co_DummyRes,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_co_PathRetainArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_co_PathRetainArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_co_qsig_co_PathRetainArg_PDU);
  return offset;
}
static int dissect_qsig_co_ServiceAvailableArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_co_ServiceAvailableArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_co_qsig_co_ServiceAvailableArg_PDU);
  return offset;
}
static int dissect_qsig_co_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_co_DummyArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_co_qsig_co_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_co_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_co_DummyRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_co_qsig_co_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_co_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_co_qsig_co_Extension_PDU);
  return offset;
}


/* --- Module Do-Not-Disturb-Operations-asn1-97 --- --- ---                   */



static int
dissect_qsig_dnd_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_dnd_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_dnd_sequenceOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_dnd_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_dnd_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_dnd_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_dnd_DummyArg_vals[] = {
  {   0, "null" },
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_dnd_DummyArg_choice[] = {
  {   0, &hf_qsig_dnd_null       , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_NULL },
  {   1, &hf_qsig_dnd_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_dnd_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_dnd_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_DummyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_dnd_DummyArg_choice, hf_index, ett_qsig_dnd_DummyArg,
                                 NULL);

  return offset;
}


static const value_string qsig_dnd_DummyRes_vals[] = {
  {   0, "null" },
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_dnd_DummyRes_choice[] = {
  {   0, &hf_qsig_dnd_null       , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_NULL },
  {   1, &hf_qsig_dnd_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_dnd_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_dnd_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_DummyRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_dnd_DummyRes_choice, hf_index, ett_qsig_dnd_DummyRes,
                                 NULL);

  return offset;
}


static const value_string qsig_dnd_DNDAargumentExtension_vals[] = {
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_dnd_DNDAargumentExtension_choice[] = {
  {   1, &hf_qsig_dnd_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_dnd_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_dnd_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_DNDAargumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_dnd_DNDAargumentExtension_choice, hf_index, ett_qsig_dnd_DNDAargumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_dnd_DNDActivateArg_sequence[] = {
  { &hf_qsig_dnd_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_dnd_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_dnd_argumentExtensionDNDA, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_dnd_DNDAargumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_DNDActivateArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_dnd_DNDActivateArg_sequence, hf_index, ett_qsig_dnd_DNDActivateArg);

  return offset;
}


static const value_string qsig_dnd_DNDProtectionLevel_vals[] = {
  {   0, "lowProtection" },
  {   1, "mediumProtection" },
  {   2, "highProtection" },
  {   3, "fullProtection" },
  { 0, NULL }
};


static int
dissect_qsig_dnd_DNDProtectionLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_dnd_T_status_item_sequence[] = {
  { &hf_qsig_dnd_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_dnd_dndProtectionLevel, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_DNDProtectionLevel },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_T_status_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_dnd_T_status_item_sequence, hf_index, ett_qsig_dnd_T_status_item);

  return offset;
}


static const ber_sequence_t qsig_dnd_T_status_set_of[1] = {
  { &hf_qsig_dnd_status_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_T_status_item },
};

static int
dissect_qsig_dnd_T_status(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 qsig_dnd_T_status_set_of, hf_index, ett_qsig_dnd_T_status);

  return offset;
}


static const value_string qsig_dnd_T_resultExtension_vals[] = {
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_dnd_T_resultExtension_choice[] = {
  {   1, &hf_qsig_dnd_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_dnd_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_dnd_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_T_resultExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_dnd_T_resultExtension_choice, hf_index, ett_qsig_dnd_T_resultExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_dnd_DNDActivateRes_sequence[] = {
  { &hf_qsig_dnd_status     , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_T_status },
  { &hf_qsig_dnd_resultExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_dnd_T_resultExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_DNDActivateRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_dnd_DNDActivateRes_sequence, hf_index, ett_qsig_dnd_DNDActivateRes);

  return offset;
}


static const value_string qsig_dnd_DNDDargumentExtension_vals[] = {
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_dnd_DNDDargumentExtension_choice[] = {
  {   1, &hf_qsig_dnd_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_dnd_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_dnd_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_DNDDargumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_dnd_DNDDargumentExtension_choice, hf_index, ett_qsig_dnd_DNDDargumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_dnd_DNDDeactivateArg_sequence[] = {
  { &hf_qsig_dnd_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_dnd_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_dnd_argumentExtensionDNDD, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_dnd_DNDDargumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_DNDDeactivateArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_dnd_DNDDeactivateArg_sequence, hf_index, ett_qsig_dnd_DNDDeactivateArg);

  return offset;
}


static const value_string qsig_dnd_DNDIargumentExtension_vals[] = {
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_dnd_DNDIargumentExtension_choice[] = {
  {   1, &hf_qsig_dnd_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_dnd_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_dnd_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_DNDIargumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_dnd_DNDIargumentExtension_choice, hf_index, ett_qsig_dnd_DNDIargumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_dnd_DNDInterrogateArg_sequence[] = {
  { &hf_qsig_dnd_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_dnd_argumentExtensionDNDI, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_dnd_DNDIargumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_DNDInterrogateArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_dnd_DNDInterrogateArg_sequence, hf_index, ett_qsig_dnd_DNDInterrogateArg);

  return offset;
}


static const ber_sequence_t qsig_dnd_T_status_item_01_sequence[] = {
  { &hf_qsig_dnd_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_dnd_dndProtectionLevel, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_DNDProtectionLevel },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_T_status_item_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_dnd_T_status_item_01_sequence, hf_index, ett_qsig_dnd_T_status_item_01);

  return offset;
}


static const ber_sequence_t qsig_dnd_T_status_01_set_of[1] = {
  { &hf_qsig_dnd_status_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_T_status_item_01 },
};

static int
dissect_qsig_dnd_T_status_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 qsig_dnd_T_status_01_set_of, hf_index, ett_qsig_dnd_T_status_01);

  return offset;
}


static const value_string qsig_dnd_T_resultExtension_01_vals[] = {
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_dnd_T_resultExtension_01_choice[] = {
  {   1, &hf_qsig_dnd_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_dnd_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_dnd_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_T_resultExtension_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_dnd_T_resultExtension_01_choice, hf_index, ett_qsig_dnd_T_resultExtension_01,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_dnd_DNDInterrogateRes_sequence[] = {
  { &hf_qsig_dnd_status_01  , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_T_status_01 },
  { &hf_qsig_dnd_resultExtension_01, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_dnd_T_resultExtension_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_DNDInterrogateRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_dnd_DNDInterrogateRes_sequence, hf_index, ett_qsig_dnd_DNDInterrogateRes);

  return offset;
}


static const value_string qsig_dnd_DNDOCapabilityLevel_vals[] = {
  {   1, "overrideLowProt" },
  {   2, "overrideMediumProt" },
  {   3, "overrideHighProt" },
  { 0, NULL }
};


static int
dissect_qsig_dnd_DNDOCapabilityLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_dnd_DNDOargumentExtension_vals[] = {
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_dnd_DNDOargumentExtension_choice[] = {
  {   1, &hf_qsig_dnd_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_dnd_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_dnd_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_DNDOargumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_dnd_DNDOargumentExtension_choice, hf_index, ett_qsig_dnd_DNDOargumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_dnd_DNDOverrideArg_sequence[] = {
  { &hf_qsig_dnd_dndoCapabilityLevel, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_DNDOCapabilityLevel },
  { &hf_qsig_dnd_argumentExtensionDNDO, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_dnd_DNDOargumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_DNDOverrideArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_dnd_DNDOverrideArg_sequence, hf_index, ett_qsig_dnd_DNDOverrideArg);

  return offset;
}


static const asn_namedbit qsig_dnd_ServiceList_bits[] = {
  {  1, &hf_qsig_dnd_ServiceList_dndo_low, -1, -1, "dndo-low", NULL },
  {  2, &hf_qsig_dnd_ServiceList_dndo_medium, -1, -1, "dndo-medium", NULL },
  {  3, &hf_qsig_dnd_ServiceList_dndo_high, -1, -1, "dndo-high", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_qsig_dnd_ServiceList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    qsig_dnd_ServiceList_bits, hf_index, ett_qsig_dnd_ServiceList,
                                    NULL);

  return offset;
}


static const ber_sequence_t qsig_dnd_T_extendedServiceList_sequence[] = {
  { &hf_qsig_dnd_serviceList, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_ServiceList },
  { &hf_qsig_dnd_extension  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_T_extendedServiceList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_dnd_T_extendedServiceList_sequence, hf_index, ett_qsig_dnd_T_extendedServiceList);

  return offset;
}


static const value_string qsig_dnd_PathRetainArg_vals[] = {
  {   0, "serviceList" },
  {   1, "extendedServiceList" },
  { 0, NULL }
};

static const ber_choice_t qsig_dnd_PathRetainArg_choice[] = {
  {   0, &hf_qsig_dnd_serviceList, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_ServiceList },
  {   1, &hf_qsig_dnd_extendedServiceList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_T_extendedServiceList },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_PathRetainArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_dnd_PathRetainArg_choice, hf_index, ett_qsig_dnd_PathRetainArg,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_dnd_T_extendedServiceList_01_sequence[] = {
  { &hf_qsig_dnd_serviceList, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_ServiceList },
  { &hf_qsig_dnd_extension  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_T_extendedServiceList_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_dnd_T_extendedServiceList_01_sequence, hf_index, ett_qsig_dnd_T_extendedServiceList_01);

  return offset;
}


static const value_string qsig_dnd_ServiceAvailableArg_vals[] = {
  {   0, "serviceList" },
  {   1, "extendedServiceList" },
  { 0, NULL }
};

static const ber_choice_t qsig_dnd_ServiceAvailableArg_choice[] = {
  {   0, &hf_qsig_dnd_serviceList, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_ServiceList },
  {   1, &hf_qsig_dnd_extendedServiceList_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_T_extendedServiceList_01 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_ServiceAvailableArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_dnd_ServiceAvailableArg_choice, hf_index, ett_qsig_dnd_ServiceAvailableArg,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_dnd_DNDActivateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_dnd_DNDActivateArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DNDActivateArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_DNDActivateRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_dnd_DNDActivateRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DNDActivateRes_PDU);
  return offset;
}
static int dissect_qsig_dnd_DNDDeactivateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_dnd_DNDDeactivateArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DNDDeactivateArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_dnd_DummyRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_dnd_DNDInterrogateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_dnd_DNDInterrogateArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DNDInterrogateArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_DNDInterrogateRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_dnd_DNDInterrogateRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DNDInterrogateRes_PDU);
  return offset;
}
static int dissect_qsig_dnd_DNDOverrideArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_dnd_DNDOverrideArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DNDOverrideArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_PathRetainArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_dnd_PathRetainArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_PathRetainArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_ServiceAvailableArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_dnd_ServiceAvailableArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_ServiceAvailableArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_dnd_DummyArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_Extension_PDU);
  return offset;
}


/* --- Module Call-Intrusion-Operations-asn1-97 --- --- ---                   */


static const asn_namedbit qsig_ci_ServiceList_bits[] = {
  {  4, &hf_qsig_ci_ServiceList_ci_low, -1, -1, "ci-low", NULL },
  {  5, &hf_qsig_ci_ServiceList_ci_medium, -1, -1, "ci-medium", NULL },
  {  6, &hf_qsig_ci_ServiceList_ci_high, -1, -1, "ci-high", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_qsig_ci_ServiceList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    qsig_ci_ServiceList_bits, hf_index, ett_qsig_ci_ServiceList,
                                    NULL);

  return offset;
}


static const ber_sequence_t qsig_ci_T_extendedServiceList_sequence[] = {
  { &hf_qsig_ci_serviceList , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_ci_ServiceList },
  { &hf_qsig_ci_extension   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ci_T_extendedServiceList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ci_T_extendedServiceList_sequence, hf_index, ett_qsig_ci_T_extendedServiceList);

  return offset;
}


static const value_string qsig_ci_PathRetainArg_vals[] = {
  {   0, "serviceList" },
  {   1, "extendedServiceList" },
  { 0, NULL }
};

static const ber_choice_t qsig_ci_PathRetainArg_choice[] = {
  {   0, &hf_qsig_ci_serviceList , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_ci_ServiceList },
  {   1, &hf_qsig_ci_extendedServiceList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_ci_T_extendedServiceList },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ci_PathRetainArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ci_PathRetainArg_choice, hf_index, ett_qsig_ci_PathRetainArg,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ci_T_extendedServiceList_01_sequence[] = {
  { &hf_qsig_ci_serviceList , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_ci_ServiceList },
  { &hf_qsig_ci_extension   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ci_T_extendedServiceList_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ci_T_extendedServiceList_01_sequence, hf_index, ett_qsig_ci_T_extendedServiceList_01);

  return offset;
}


static const value_string qsig_ci_ServiceAvailableArg_vals[] = {
  {   0, "serviceList" },
  {   1, "extendedServiceList" },
  { 0, NULL }
};

static const ber_choice_t qsig_ci_ServiceAvailableArg_choice[] = {
  {   0, &hf_qsig_ci_serviceList , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_ci_ServiceList },
  {   1, &hf_qsig_ci_extendedServiceList_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_ci_T_extendedServiceList_01 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ci_ServiceAvailableArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ci_ServiceAvailableArg_choice, hf_index, ett_qsig_ci_ServiceAvailableArg,
                                 NULL);

  return offset;
}



static int
dissect_qsig_ci_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_ci_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_ci_sequenceOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_ci_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_ci_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_ci_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_ci_DummyArg_vals[] = {
  {   0, "null" },
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_ci_DummyArg_choice[] = {
  {   0, &hf_qsig_ci_null        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_ci_NULL },
  {   1, &hf_qsig_ci_extension   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_ci_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_ci_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ci_DummyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ci_DummyArg_choice, hf_index, ett_qsig_ci_DummyArg,
                                 NULL);

  return offset;
}


static const value_string qsig_ci_DummyRes_vals[] = {
  {   0, "null" },
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_ci_DummyRes_choice[] = {
  {   0, &hf_qsig_ci_null        , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_ci_NULL },
  {   1, &hf_qsig_ci_extension   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_ci_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_ci_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ci_DummyRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ci_DummyRes_choice, hf_index, ett_qsig_ci_DummyRes,
                                 NULL);

  return offset;
}


static const value_string qsig_ci_CICapabilityLevel_vals[] = {
  {   1, "intrusionLowProt" },
  {   2, "intrusionMediumProt" },
  {   3, "intrusionHighProt" },
  { 0, NULL }
};


static int
dissect_qsig_ci_CICapabilityLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_ci_T_argumentExtension_vals[] = {
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_ci_T_argumentExtension_choice[] = {
  {   1, &hf_qsig_ci_extension   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_ci_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_ci_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ci_T_argumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ci_T_argumentExtension_choice, hf_index, ett_qsig_ci_T_argumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ci_CIRequestArg_sequence[] = {
  { &hf_qsig_ci_ciCapabilityLevel, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_ci_CICapabilityLevel },
  { &hf_qsig_ci_argumentExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ci_T_argumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ci_CIRequestArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ci_CIRequestArg_sequence, hf_index, ett_qsig_ci_CIRequestArg);

  return offset;
}


static const value_string qsig_ci_CIUnwantedUserStatus_vals[] = {
  {   0, "unwantedUserIntruded" },
  {   1, "unwantedUserIsolated" },
  { 0, NULL }
};


static int
dissect_qsig_ci_CIUnwantedUserStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_ci_T_resultExtension_vals[] = {
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_ci_T_resultExtension_choice[] = {
  {   1, &hf_qsig_ci_extension   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_ci_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_ci_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ci_T_resultExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ci_T_resultExtension_choice, hf_index, ett_qsig_ci_T_resultExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ci_CIRequestRes_sequence[] = {
  { &hf_qsig_ci_ciUnwantedUserStatus, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_ci_CIUnwantedUserStatus },
  { &hf_qsig_ci_resultExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ci_T_resultExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ci_CIRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ci_CIRequestRes_sequence, hf_index, ett_qsig_ci_CIRequestRes);

  return offset;
}


static const value_string qsig_ci_CIProtectionLevel_vals[] = {
  {   0, "lowProtection" },
  {   1, "mediumProtection" },
  {   2, "highProtection" },
  {   3, "fullProtection" },
  { 0, NULL }
};


static int
dissect_qsig_ci_CIProtectionLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_ci_T_resultExtension_01_vals[] = {
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_ci_T_resultExtension_01_choice[] = {
  {   1, &hf_qsig_ci_extension   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_ci_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_ci_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ci_T_resultExtension_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ci_T_resultExtension_01_choice, hf_index, ett_qsig_ci_T_resultExtension_01,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ci_CIGetCIPLRes_sequence[] = {
  { &hf_qsig_ci_ciProtectionLevel, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_ci_CIProtectionLevel },
  { &hf_qsig_ci_resultExtension_01, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ci_T_resultExtension_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ci_CIGetCIPLRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ci_CIGetCIPLRes_sequence, hf_index, ett_qsig_ci_CIGetCIPLRes);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_ci_PathRetainArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ci_PathRetainArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_PathRetainArg_PDU);
  return offset;
}
static int dissect_qsig_ci_ServiceAvailableArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ci_ServiceAvailableArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_ServiceAvailableArg_PDU);
  return offset;
}
static int dissect_qsig_ci_CIRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ci_CIRequestArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_CIRequestArg_PDU);
  return offset;
}
static int dissect_qsig_ci_CIRequestRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ci_CIRequestRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_CIRequestRes_PDU);
  return offset;
}
static int dissect_qsig_ci_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ci_DummyArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_ci_CIGetCIPLRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ci_CIGetCIPLRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_CIGetCIPLRes_PDU);
  return offset;
}
static int dissect_qsig_ci_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ci_DummyRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_ci_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_Extension_PDU);
  return offset;
}


/* --- Module SS-AOC-Operations-asn1-97 --- --- ---                           */



static int
dissect_qsig_aoc_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string qsig_aoc_ChargedItem_vals[] = {
  {   0, "basicCommunication" },
  {   1, "callAttempt" },
  {   2, "callSetup" },
  {   3, "userToUserInfo" },
  {   4, "operationOfSupplementaryServ" },
  { 0, NULL }
};


static int
dissect_qsig_aoc_ChargedItem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_qsig_aoc_Currency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_qsig_aoc_CurrencyAmount(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string qsig_aoc_Multiplier_vals[] = {
  {   0, "oneThousandth" },
  {   1, "oneHundredth" },
  {   2, "oneTenth" },
  {   3, "one" },
  {   4, "ten" },
  {   5, "hundred" },
  {   6, "thousand" },
  { 0, NULL }
};


static int
dissect_qsig_aoc_Multiplier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_Amount_sequence[] = {
  { &hf_qsig_aoc_currencyAmount, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_CurrencyAmount },
  { &hf_qsig_aoc_multiplier , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_Multiplier },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_Amount(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_Amount_sequence, hf_index, ett_qsig_aoc_Amount);

  return offset;
}


static const value_string qsig_aoc_ChargingType_vals[] = {
  {   0, "continuousCharging" },
  {   1, "stepFunction" },
  { 0, NULL }
};


static int
dissect_qsig_aoc_ChargingType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_qsig_aoc_LengthOfTimeUnit(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string qsig_aoc_Scale_vals[] = {
  {   0, "oneHundredthSecond" },
  {   1, "oneTenthSecond" },
  {   2, "oneSecond" },
  {   3, "tenSeconds" },
  {   4, "oneMinute" },
  {   5, "oneHour" },
  {   6, "twentyFourHours" },
  { 0, NULL }
};


static int
dissect_qsig_aoc_Scale(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_Time_sequence[] = {
  { &hf_qsig_aoc_lengthOfTimeUnit, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_LengthOfTimeUnit },
  { &hf_qsig_aoc_scale      , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_Scale },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_Time(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_Time_sequence, hf_index, ett_qsig_aoc_Time);

  return offset;
}


static const ber_sequence_t qsig_aoc_DurationCurrency_sequence[] = {
  { &hf_qsig_aoc_dCurrency  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_Currency },
  { &hf_qsig_aoc_dAmount    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_Amount },
  { &hf_qsig_aoc_dChargingType, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_ChargingType },
  { &hf_qsig_aoc_dTime      , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_Time },
  { &hf_qsig_aoc_dGranularity, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_aoc_Time },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_DurationCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_DurationCurrency_sequence, hf_index, ett_qsig_aoc_DurationCurrency);

  return offset;
}


static const ber_sequence_t qsig_aoc_FlatRateCurrency_sequence[] = {
  { &hf_qsig_aoc_fRCurrency , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_Currency },
  { &hf_qsig_aoc_fRAmount   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_Amount },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_FlatRateCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_FlatRateCurrency_sequence, hf_index, ett_qsig_aoc_FlatRateCurrency);

  return offset;
}


static const value_string qsig_aoc_VolumeUnit_vals[] = {
  {   0, "octet" },
  {   1, "segment" },
  {   2, "message" },
  { 0, NULL }
};


static int
dissect_qsig_aoc_VolumeUnit(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_VolumeRateCurrency_sequence[] = {
  { &hf_qsig_aoc_vRCurrency , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_Currency },
  { &hf_qsig_aoc_vRAmount   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_Amount },
  { &hf_qsig_aoc_vRVolumeUnit, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_VolumeUnit },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_VolumeRateCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_VolumeRateCurrency_sequence, hf_index, ett_qsig_aoc_VolumeRateCurrency);

  return offset;
}



static int
dissect_qsig_aoc_SpecialChargingCode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string qsig_aoc_T_rateType_vals[] = {
  {   0, "durationCurrency" },
  {   1, "flatRateCurrency" },
  {   2, "volumeRateCurrency" },
  {   3, "specialChargingCode" },
  {   4, "freeOfCharge" },
  {   5, "currencyInfoNotAvailable" },
  {   6, "freeOfChargefromBeginning" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_T_rateType_choice[] = {
  {   0, &hf_qsig_aoc_durationCurrency, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_DurationCurrency },
  {   1, &hf_qsig_aoc_flatRateCurrency, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_FlatRateCurrency },
  {   2, &hf_qsig_aoc_volumeRateCurrency, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_VolumeRateCurrency },
  {   3, &hf_qsig_aoc_specialChargingCode, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_SpecialChargingCode },
  {   4, &hf_qsig_aoc_freeOfCharge, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_NULL },
  {   5, &hf_qsig_aoc_currencyInfoNotAvailable, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_NULL },
  {   6, &hf_qsig_aoc_freeOfChargefromBeginning, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_rateType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_rateType_choice, hf_index, ett_qsig_aoc_T_rateType,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_AOCSCurrencyInfo_sequence[] = {
  { &hf_qsig_aoc_chargedItem, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_ChargedItem },
  { &hf_qsig_aoc_rateType   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_T_rateType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_AOCSCurrencyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_AOCSCurrencyInfo_sequence, hf_index, ett_qsig_aoc_AOCSCurrencyInfo);

  return offset;
}


static const ber_sequence_t qsig_aoc_AOCSCurrencyInfoList_sequence_of[1] = {
  { &hf_qsig_aoc_AOCSCurrencyInfoList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_AOCSCurrencyInfo },
};

static int
dissect_qsig_aoc_AOCSCurrencyInfoList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_aoc_AOCSCurrencyInfoList_sequence_of, hf_index, ett_qsig_aoc_AOCSCurrencyInfoList);

  return offset;
}


static const value_string qsig_aoc_T_aocRate_vals[] = {
  {   0, "chargeNotAvailable" },
  {   1, "aocSCurrencyInfoList" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_T_aocRate_choice[] = {
  {   0, &hf_qsig_aoc_chargeNotAvailable, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_NULL },
  {   1, &hf_qsig_aoc_aocSCurrencyInfoList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_AOCSCurrencyInfoList },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_aocRate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_aocRate_choice, hf_index, ett_qsig_aoc_T_aocRate,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_aoc_multipleExtension_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_aoc_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_aoc_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_aoc_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_aoc_T_rateArgExtension_vals[] = {
  {   1, "extension" },
  {   2, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_T_rateArgExtension_choice[] = {
  {   1, &hf_qsig_aoc_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_aoc_multipleExtension, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_rateArgExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_rateArgExtension_choice, hf_index, ett_qsig_aoc_T_rateArgExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_AocRateArg_sequence[] = {
  { &hf_qsig_aoc_aocRate    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_T_aocRate },
  { &hf_qsig_aoc_rateArgExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_T_rateArgExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_AocRateArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_AocRateArg_sequence, hf_index, ett_qsig_aoc_AocRateArg);

  return offset;
}


static const ber_sequence_t qsig_aoc_RecordedCurrency_sequence[] = {
  { &hf_qsig_aoc_rCurrency  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_Currency },
  { &hf_qsig_aoc_rAmount    , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_Amount },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_RecordedCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_RecordedCurrency_sequence, hf_index, ett_qsig_aoc_RecordedCurrency);

  return offset;
}


static const value_string qsig_aoc_InterimBillingId_vals[] = {
  {   0, "normalCharging" },
  {   2, "creditCardCharging" },
  { 0, NULL }
};


static int
dissect_qsig_aoc_InterimBillingId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_T_specificCurrency_sequence[] = {
  { &hf_qsig_aoc_recordedCurrency, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_RecordedCurrency },
  { &hf_qsig_aoc_interimBillingId, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_aoc_InterimBillingId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_specificCurrency(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_T_specificCurrency_sequence, hf_index, ett_qsig_aoc_T_specificCurrency);

  return offset;
}


static const value_string qsig_aoc_T_interimCharge_vals[] = {
  {   0, "chargeNotAvailable" },
  {   1, "freeOfCharge" },
  {   2, "specificCurrency" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_T_interimCharge_choice[] = {
  {   0, &hf_qsig_aoc_chargeNotAvailable, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_NULL },
  {   1, &hf_qsig_aoc_freeOfCharge, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_NULL },
  {   2, &hf_qsig_aoc_specificCurrency, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_T_specificCurrency },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_interimCharge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_interimCharge_choice, hf_index, ett_qsig_aoc_T_interimCharge,
                                 NULL);

  return offset;
}


static const value_string qsig_aoc_T_interimArgExtension_vals[] = {
  {   1, "extension" },
  {   2, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_T_interimArgExtension_choice[] = {
  {   1, &hf_qsig_aoc_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_aoc_multipleExtension, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_interimArgExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_interimArgExtension_choice, hf_index, ett_qsig_aoc_T_interimArgExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_AocInterimArg_sequence[] = {
  { &hf_qsig_aoc_interimCharge, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_T_interimCharge },
  { &hf_qsig_aoc_interimArgExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_T_interimArgExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_AocInterimArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_AocInterimArg_sequence, hf_index, ett_qsig_aoc_AocInterimArg);

  return offset;
}


static const value_string qsig_aoc_FinalBillingId_vals[] = {
  {   0, "normalCharging" },
  {   2, "creditCardCharging" },
  {   3, "callForwardingUnconditional" },
  {   4, "callForwardingBusy" },
  {   5, "callForwardingNoReply" },
  {   6, "callDeflection" },
  {   7, "callTransfer" },
  { 0, NULL }
};


static int
dissect_qsig_aoc_FinalBillingId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_T_specificCurrency_01_sequence[] = {
  { &hf_qsig_aoc_recordedCurrency, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_RecordedCurrency },
  { &hf_qsig_aoc_finalBillingId, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_aoc_FinalBillingId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_specificCurrency_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_T_specificCurrency_01_sequence, hf_index, ett_qsig_aoc_T_specificCurrency_01);

  return offset;
}


static const value_string qsig_aoc_T_finalCharge_vals[] = {
  {   0, "chargeNotAvailable" },
  {   1, "freeOfCharge" },
  {   2, "specificCurrency" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_T_finalCharge_choice[] = {
  {   0, &hf_qsig_aoc_chargeNotAvailable, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_NULL },
  {   1, &hf_qsig_aoc_freeOfCharge, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_NULL },
  {   2, &hf_qsig_aoc_specificCurrency_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_T_specificCurrency_01 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_finalCharge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_finalCharge_choice, hf_index, ett_qsig_aoc_T_finalCharge,
                                 NULL);

  return offset;
}



static int
dissect_qsig_aoc_ChargeIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string qsig_aoc_ChargingAssociation_vals[] = {
  {   0, "chargeNumber" },
  {   1, "chargeIdentifier" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_ChargingAssociation_choice[] = {
  {   0, &hf_qsig_aoc_chargeNumber, BER_CLASS_CON, 0, 0, dissect_qsig_PartyNumber },
  {   1, &hf_qsig_aoc_chargeIdentifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_ChargeIdentifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_ChargingAssociation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_ChargingAssociation_choice, hf_index, ett_qsig_aoc_ChargingAssociation,
                                 NULL);

  return offset;
}


static const value_string qsig_aoc_T_finalArgExtension_vals[] = {
  {   1, "extension" },
  {   2, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_T_finalArgExtension_choice[] = {
  {   1, &hf_qsig_aoc_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_aoc_multipleExtension, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_finalArgExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_finalArgExtension_choice, hf_index, ett_qsig_aoc_T_finalArgExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_AocFinalArg_sequence[] = {
  { &hf_qsig_aoc_finalCharge, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_T_finalCharge },
  { &hf_qsig_aoc_chargingAssociation, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_ChargingAssociation },
  { &hf_qsig_aoc_finalArgExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_T_finalArgExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_AocFinalArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_AocFinalArg_sequence, hf_index, ett_qsig_aoc_AocFinalArg);

  return offset;
}


static const value_string qsig_aoc_AdviceModeCombination_vals[] = {
  {   0, "rate" },
  {   1, "rateInterim" },
  {   2, "rateFinal" },
  {   3, "interim" },
  {   4, "final" },
  {   5, "interimFinal" },
  {   6, "rateInterimFinal" },
  { 0, NULL }
};


static int
dissect_qsig_aoc_AdviceModeCombination(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_SEQUENCE_SIZE_0_7_OF_AdviceModeCombination_sequence_of[1] = {
  { &hf_qsig_aoc_adviceModeCombinations_item, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_AdviceModeCombination },
};

static int
dissect_qsig_aoc_SEQUENCE_SIZE_0_7_OF_AdviceModeCombination(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_aoc_SEQUENCE_SIZE_0_7_OF_AdviceModeCombination_sequence_of, hf_index, ett_qsig_aoc_SEQUENCE_SIZE_0_7_OF_AdviceModeCombination);

  return offset;
}


static const value_string qsig_aoc_T_chargeReqArgExtension_vals[] = {
  {   1, "extension" },
  {   2, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_T_chargeReqArgExtension_choice[] = {
  {   1, &hf_qsig_aoc_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_aoc_multipleExtension, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_chargeReqArgExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_chargeReqArgExtension_choice, hf_index, ett_qsig_aoc_T_chargeReqArgExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_ChargeRequestArg_sequence[] = {
  { &hf_qsig_aoc_adviceModeCombinations, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_SEQUENCE_SIZE_0_7_OF_AdviceModeCombination },
  { &hf_qsig_aoc_chargeReqArgExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_T_chargeReqArgExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_ChargeRequestArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_ChargeRequestArg_sequence, hf_index, ett_qsig_aoc_ChargeRequestArg);

  return offset;
}


static const value_string qsig_aoc_T_chargeReqResExtension_vals[] = {
  {   1, "extension" },
  {   2, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_T_chargeReqResExtension_choice[] = {
  {   1, &hf_qsig_aoc_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_aoc_multipleExtension, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_chargeReqResExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_chargeReqResExtension_choice, hf_index, ett_qsig_aoc_T_chargeReqResExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_ChargeRequestRes_sequence[] = {
  { &hf_qsig_aoc_adviceModeCombination, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_AdviceModeCombination },
  { &hf_qsig_aoc_chargeReqResExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_T_chargeReqResExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_ChargeRequestRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_ChargeRequestRes_sequence, hf_index, ett_qsig_aoc_ChargeRequestRes);

  return offset;
}


static const value_string qsig_aoc_DummyArg_vals[] = {
  {   0, "none" },
  {   1, "extension" },
  {   2, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_DummyArg_choice[] = {
  {   0, &hf_qsig_aoc_none       , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_NULL },
  {   1, &hf_qsig_aoc_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_aoc_multipleExtension, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_DummyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_DummyArg_choice, hf_index, ett_qsig_aoc_DummyArg,
                                 NULL);

  return offset;
}


static const value_string qsig_aoc_T_completeArgExtension_vals[] = {
  {   1, "extension" },
  {   2, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_T_completeArgExtension_choice[] = {
  {   1, &hf_qsig_aoc_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_aoc_multipleExtension, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_completeArgExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_completeArgExtension_choice, hf_index, ett_qsig_aoc_T_completeArgExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_AocCompleteArg_sequence[] = {
  { &hf_qsig_aoc_chargedUser, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_aoc_chargingAssociation, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_ChargingAssociation },
  { &hf_qsig_aoc_completeArgExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_T_completeArgExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_AocCompleteArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_AocCompleteArg_sequence, hf_index, ett_qsig_aoc_AocCompleteArg);

  return offset;
}


static const value_string qsig_aoc_ChargingOption_vals[] = {
  {   0, "aocFreeOfCharge" },
  {   1, "aocContinueCharging" },
  {   2, "aocStopCharging" },
  { 0, NULL }
};


static int
dissect_qsig_aoc_ChargingOption(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_aoc_T_completeResExtension_vals[] = {
  {   1, "extension" },
  {   2, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_T_completeResExtension_choice[] = {
  {   1, &hf_qsig_aoc_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_aoc_multipleExtension, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_completeResExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_completeResExtension_choice, hf_index, ett_qsig_aoc_T_completeResExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_AocCompleteRes_sequence[] = {
  { &hf_qsig_aoc_chargingOption, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_ChargingOption },
  { &hf_qsig_aoc_completeResExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_T_completeResExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_AocCompleteRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_AocCompleteRes_sequence, hf_index, ett_qsig_aoc_AocCompleteRes);

  return offset;
}


static const value_string qsig_aoc_DiversionType_vals[] = {
  {   0, "callForwardingUnconditional" },
  {   1, "callForwardingBusy" },
  {   2, "callForwardingNoReply" },
  {   3, "callDeflection" },
  { 0, NULL }
};


static int
dissect_qsig_aoc_DiversionType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_aoc_T_aocDivChargeReqArgExt_vals[] = {
  {   1, "extension" },
  {   2, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_aoc_T_aocDivChargeReqArgExt_choice[] = {
  {   1, &hf_qsig_aoc_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_aoc_multipleExtension, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_aoc_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_T_aocDivChargeReqArgExt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_aocDivChargeReqArgExt_choice, hf_index, ett_qsig_aoc_T_aocDivChargeReqArgExt,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_AocDivChargeReqArg_sequence[] = {
  { &hf_qsig_aoc_divertingUser, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_aoc_chargingAssociation, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_ChargingAssociation },
  { &hf_qsig_aoc_diversionType, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_DiversionType },
  { &hf_qsig_aoc_aocDivChargeReqArgExt, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_aoc_T_aocDivChargeReqArgExt },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_aoc_AocDivChargeReqArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_AocDivChargeReqArg_sequence, hf_index, ett_qsig_aoc_AocDivChargeReqArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_aoc_AocRateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_aoc_AocRateArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_AocRateArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_AocInterimArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_aoc_AocInterimArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_AocInterimArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_AocFinalArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_aoc_AocFinalArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_AocFinalArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_ChargeRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_aoc_ChargeRequestArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_ChargeRequestArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_ChargeRequestRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_aoc_ChargeRequestRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_ChargeRequestRes_PDU);
  return offset;
}
static int dissect_qsig_aoc_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_aoc_DummyArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_AocCompleteArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_aoc_AocCompleteArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_AocCompleteArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_AocCompleteRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_aoc_AocCompleteRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_AocCompleteRes_PDU);
  return offset;
}
static int dissect_qsig_aoc_AocDivChargeReqArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_aoc_AocDivChargeReqArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_AocDivChargeReqArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_Extension_PDU);
  return offset;
}


/* --- Module Recall-Operations-asn1-97 --- --- ---                           */


static const ber_sequence_t qsig_re_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_re_multipleExtension_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_re_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_re_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_re_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_re_T_argumentExtension_vals[] = {
  {   6, "extension" },
  {   7, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_re_T_argumentExtension_choice[] = {
  {   6, &hf_qsig_re_extension   , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   7, &hf_qsig_re_multipleExtension, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_qsig_re_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_re_T_argumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_re_T_argumentExtension_choice, hf_index, ett_qsig_re_T_argumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_re_ReAlertingArg_sequence[] = {
  { &hf_qsig_re_alertedNumber, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_PresentedNumberScreened },
  { &hf_qsig_re_alertedName , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_re_argumentExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_re_T_argumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_re_ReAlertingArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_re_ReAlertingArg_sequence, hf_index, ett_qsig_re_ReAlertingArg);

  return offset;
}


static const value_string qsig_re_T_argumentExtension_01_vals[] = {
  {   6, "extension" },
  {   7, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_re_T_argumentExtension_01_choice[] = {
  {   6, &hf_qsig_re_extension   , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   7, &hf_qsig_re_multipleExtension, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_qsig_re_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_re_T_argumentExtension_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_re_T_argumentExtension_01_choice, hf_index, ett_qsig_re_T_argumentExtension_01,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_re_ReAnswerArg_sequence[] = {
  { &hf_qsig_re_connectedNumber, BER_CLASS_CON, 1, 0, dissect_qsig_PresentedNumberScreened },
  { &hf_qsig_re_connectedSubaddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_qsig_PartySubaddress },
  { &hf_qsig_re_connectedName, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_re_argumentExtension_01, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_re_T_argumentExtension_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_re_ReAnswerArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_re_ReAnswerArg_sequence, hf_index, ett_qsig_re_ReAnswerArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_re_ReAlertingArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_re_ReAlertingArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_re_qsig_re_ReAlertingArg_PDU);
  return offset;
}
static int dissect_qsig_re_ReAnswerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_re_ReAnswerArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_re_qsig_re_ReAnswerArg_PDU);
  return offset;
}


/* --- Module Synchronization-Operations-asn1-97 --- --- ---                  */


static const value_string qsig_sync_Action_vals[] = {
  {   0, "enslavement" },
  {   1, "holdon" },
  { 0, NULL }
};


static int
dissect_qsig_sync_Action(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_sync_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_sync_sequOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_sync_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_sync_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_sync_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_sync_ArgExtension_vals[] = {
  {   1, "extension" },
  {   2, "sequOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_sync_ArgExtension_choice[] = {
  {   1, &hf_qsig_sync_extension , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_sync_sequOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_sync_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sync_ArgExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_sync_ArgExtension_choice, hf_index, ett_qsig_sync_ArgExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_sync_SynchronizationReqArg_sequence[] = {
  { &hf_qsig_sync_action    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sync_Action },
  { &hf_qsig_sync_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sync_ArgExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sync_SynchronizationReqArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sync_SynchronizationReqArg_sequence, hf_index, ett_qsig_sync_SynchronizationReqArg);

  return offset;
}



static int
dissect_qsig_sync_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t qsig_sync_SynchronizationReqRes_sequence[] = {
  { &hf_qsig_sync_action    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sync_Action },
  { &hf_qsig_sync_response  , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_qsig_sync_BOOLEAN },
  { &hf_qsig_sync_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sync_ArgExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sync_SynchronizationReqRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sync_SynchronizationReqRes_sequence, hf_index, ett_qsig_sync_SynchronizationReqRes);

  return offset;
}


static const value_string qsig_sync_T_stateinfo_vals[] = {
  {   0, "freerunning" },
  {   1, "idle" },
  { 0, NULL }
};


static int
dissect_qsig_sync_T_stateinfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_sync_SynchronizationInfoArg_sequence[] = {
  { &hf_qsig_sync_stateinfo , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sync_T_stateinfo },
  { &hf_qsig_sync_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sync_ArgExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sync_SynchronizationInfoArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sync_SynchronizationInfoArg_sequence, hf_index, ett_qsig_sync_SynchronizationInfoArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_sync_SynchronizationReqArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sync_SynchronizationReqArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sync_qsig_sync_SynchronizationReqArg_PDU);
  return offset;
}
static int dissect_qsig_sync_SynchronizationReqRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sync_SynchronizationReqRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sync_qsig_sync_SynchronizationReqRes_PDU);
  return offset;
}
static int dissect_qsig_sync_SynchronizationInfoArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sync_SynchronizationInfoArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sync_qsig_sync_SynchronizationInfoArg_PDU);
  return offset;
}
static int dissect_qsig_sync_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sync_qsig_sync_Extension_PDU);
  return offset;
}


/* --- Module Call-Interception-Operations-asn1-97 --- --- ---                */


static const value_string qsig_cint_CintCause_vals[] = {
  {   0, "unknown" },
  {   1, "cintBnan" },
  {   2, "cintBus" },
  {   3, "cintCug" },
  {   4, "cintDnd" },
  {   5, "cintIbd" },
  {   6, "cintInn" },
  {   7, "cintMob1" },
  {   8, "cintMob2" },
  {   9, "cintMob3" },
  {  10, "cintNcmp" },
  {  11, "cintNcong" },
  {  12, "cintNre" },
  {  13, "cintOos" },
  {  14, "cintRrs" },
  {  15, "cintTbnan" },
  {  16, "cintTnre" },
  {  17, "cintTrans" },
  {  18, "cintUpl" },
  {  19, "cintInvDiv" },
  {  20, "cintHold" },
  { 0, NULL }
};


static int
dissect_qsig_cint_CintCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_cint_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_cint_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_cint_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_cint_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_cint_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_cint_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_cint_CintExtension_vals[] = {
  {   0, "none" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cint_CintExtension_choice[] = {
  {   0, &hf_qsig_cint_none      , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_cint_NULL },
  {   1, &hf_qsig_cint_single    , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cint_multiple  , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_cint_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cint_CintExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cint_CintExtension_choice, hf_index, ett_qsig_cint_CintExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cint_CintInformation1Arg_sequence[] = {
  { &hf_qsig_cint_interceptionCause, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_cint_CintCause },
  { &hf_qsig_cint_interceptedToNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_cint_extension , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cint_CintExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cint_CintInformation1Arg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cint_CintInformation1Arg_sequence, hf_index, ett_qsig_cint_CintInformation1Arg);

  return offset;
}


static const ber_sequence_t qsig_cint_CintInformation2Arg_sequence[] = {
  { &hf_qsig_cint_interceptionCause, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_cint_CintCause },
  { &hf_qsig_cint_calledNumber, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_PresentedNumberUnscreened },
  { &hf_qsig_cint_originalCalledNumber, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_qsig_PresentedNumberUnscreened },
  { &hf_qsig_cint_calledName, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_cint_originalCalledName, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_cint_extension , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cint_CintExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cint_CintInformation2Arg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cint_CintInformation2Arg_sequence, hf_index, ett_qsig_cint_CintInformation2Arg);

  return offset;
}


static const value_string qsig_cint_Condition_vals[] = {
  {   0, "unknown" },
  {   2, "cintBus" },
  {   3, "cintCug" },
  {   4, "cintDnd" },
  {   5, "cintIbd" },
  {   6, "cintInn" },
  {   7, "cintMob1" },
  {   8, "cintMob2" },
  {   9, "cintMob3" },
  {  10, "cintNcmp" },
  {  11, "cintNcong" },
  {  13, "cintOos" },
  {  14, "cintRrs" },
  {  17, "cintTrans" },
  {  18, "cintUpl" },
  {  19, "cintInvDiv" },
  { 0, NULL }
};


static int
dissect_qsig_cint_Condition(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_cint_CintCondArg_sequence[] = {
  { &hf_qsig_cint_interceptionCause_01, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_cint_Condition },
  { &hf_qsig_cint_originalCalledNumber, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_PresentedNumberUnscreened },
  { &hf_qsig_cint_calledName, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_cint_originalCalledName, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_cint_extension , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cint_CintExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cint_CintCondArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cint_CintCondArg_sequence, hf_index, ett_qsig_cint_CintCondArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_cint_CintInformation1Arg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cint_CintInformation1Arg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cint_qsig_cint_CintInformation1Arg_PDU);
  return offset;
}
static int dissect_qsig_cint_CintInformation2Arg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cint_CintInformation2Arg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cint_qsig_cint_CintInformation2Arg_PDU);
  return offset;
}
static int dissect_qsig_cint_CintCondArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cint_CintCondArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cint_qsig_cint_CintCondArg_PDU);
  return offset;
}
static int dissect_qsig_cint_CintExtension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cint_CintExtension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cint_qsig_cint_CintExtension_PDU);
  return offset;
}


/* --- Module Common-Information-Operations-asn1-97 --- --- ---               */


static const asn_namedbit qsig_cmn_FeatureIdList_bits[] = {
  {  0, &hf_qsig_cmn_FeatureIdList_reserved, -1, -1, "reserved", NULL },
  {  1, &hf_qsig_cmn_FeatureIdList_ssCFreRoutingSupported, -1, -1, "ssCFreRoutingSupported", NULL },
  {  2, &hf_qsig_cmn_FeatureIdList_ssCTreRoutingSupported, -1, -1, "ssCTreRoutingSupported", NULL },
  {  3, &hf_qsig_cmn_FeatureIdList_ssCCBSpossible, -1, -1, "ssCCBSpossible", NULL },
  {  4, &hf_qsig_cmn_FeatureIdList_ssCCNRpossible, -1, -1, "ssCCNRpossible", NULL },
  {  5, &hf_qsig_cmn_FeatureIdList_ssCOsupported, -1, -1, "ssCOsupported", NULL },
  {  6, &hf_qsig_cmn_FeatureIdList_ssCIforcedRelease, -1, -1, "ssCIforcedRelease", NULL },
  {  7, &hf_qsig_cmn_FeatureIdList_ssCIisolation, -1, -1, "ssCIisolation", NULL },
  {  8, &hf_qsig_cmn_FeatureIdList_ssCIwaitOnBusy, -1, -1, "ssCIwaitOnBusy", NULL },
  {  9, &hf_qsig_cmn_FeatureIdList_ssAOCsupportChargeRateProvAtGatewPinx, -1, -1, "ssAOCsupportChargeRateProvAtGatewPinx", NULL },
  { 10, &hf_qsig_cmn_FeatureIdList_ssAOCsupportInterimChargeProvAtGatewPinx, -1, -1, "ssAOCsupportInterimChargeProvAtGatewPinx", NULL },
  { 11, &hf_qsig_cmn_FeatureIdList_ssAOCsupportFinalChargeProvAtGatewPinx, -1, -1, "ssAOCsupportFinalChargeProvAtGatewPinx", NULL },
  { 12, &hf_qsig_cmn_FeatureIdList_anfPRsupportedAtCooperatingPinx, -1, -1, "anfPRsupportedAtCooperatingPinx", NULL },
  { 13, &hf_qsig_cmn_FeatureIdList_anfCINTcanInterceptImmediate, -1, -1, "anfCINTcanInterceptImmediate", NULL },
  { 14, &hf_qsig_cmn_FeatureIdList_anfCINTcanInterceptDelayed, -1, -1, "anfCINTcanInterceptDelayed", NULL },
  { 15, &hf_qsig_cmn_FeatureIdList_anfWTMIreRoutingSupported, -1, -1, "anfWTMIreRoutingSupported", NULL },
  { 16, &hf_qsig_cmn_FeatureIdList_anfPUMIreRoutingSupported, -1, -1, "anfPUMIreRoutingSupported", NULL },
  { 17, &hf_qsig_cmn_FeatureIdList_ssSSCTreRoutingSupported, -1, -1, "ssSSCTreRoutingSupported", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_qsig_cmn_FeatureIdList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    qsig_cmn_FeatureIdList_bits, hf_index, ett_qsig_cmn_FeatureIdList,
                                    NULL);

  return offset;
}



static int
dissect_qsig_cmn_INTEGER_0_3(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_cmn_IA5String_SIZE_1_10(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t qsig_cmn_EquipmentId_sequence[] = {
  { &hf_qsig_cmn_nodeId     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cmn_IA5String_SIZE_1_10 },
  { &hf_qsig_cmn_groupId    , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cmn_IA5String_SIZE_1_10 },
  { &hf_qsig_cmn_unitId     , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cmn_IA5String_SIZE_1_10 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cmn_EquipmentId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cmn_EquipmentId_sequence, hf_index, ett_qsig_cmn_EquipmentId);

  return offset;
}


static const value_string qsig_cmn_PartyCategory_vals[] = {
  {   0, "unknown" },
  {   1, "extension" },
  {   2, "pisnAttendant" },
  {   3, "emergExt" },
  { 0, NULL }
};


static int
dissect_qsig_cmn_PartyCategory(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_cmn_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_cmn_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_cmn_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_cmn_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_cmn_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_cmn_T_extension_vals[] = {
  {   7, "single" },
  {   8, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cmn_T_extension_choice[] = {
  {   7, &hf_qsig_cmn_single     , BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   8, &hf_qsig_cmn_multiple   , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_qsig_cmn_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cmn_T_extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cmn_T_extension_choice, hf_index, ett_qsig_cmn_T_extension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cmn_CmnArg_sequence[] = {
  { &hf_qsig_cmn_featureIdentifier, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cmn_FeatureIdList },
  { &hf_qsig_cmn_ssDNDOprotectionLevel, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cmn_INTEGER_0_3 },
  { &hf_qsig_cmn_ssCIprotectionLevel, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cmn_INTEGER_0_3 },
  { &hf_qsig_cmn_equipmentIdentity, BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cmn_EquipmentId },
  { &hf_qsig_cmn_partyCategory, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cmn_PartyCategory },
  { &hf_qsig_cmn_extension  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cmn_T_extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cmn_CmnArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cmn_CmnArg_sequence, hf_index, ett_qsig_cmn_CmnArg);

  return offset;
}



static int
dissect_qsig_cmn_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string qsig_cmn_DummyArg_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_cmn_DummyArg_choice[] = {
  {   0, &hf_qsig_cmn_null       , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_cmn_NULL },
  {   1, &hf_qsig_cmn_single     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cmn_multiple   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cmn_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cmn_DummyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cmn_DummyArg_choice, hf_index, ett_qsig_cmn_DummyArg,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_cmn_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cmn_DummyArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cmn_qsig_cmn_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_cmn_CmnArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cmn_CmnArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cmn_qsig_cmn_CmnArg_PDU);
  return offset;
}


/* --- Module Call-Interruption-Operations-asn1-97 --- --- ---                */


static const value_string qsig_cpi_CPICapabilityLevel_vals[] = {
  {   1, "interruptionLowPriority" },
  {   2, "interruptionMediumPriority" },
  {   3, "interruptionHighPriority" },
  { 0, NULL }
};


static int
dissect_qsig_cpi_CPICapabilityLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_cpi_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_cpi_sequenceOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_cpi_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_cpi_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_cpi_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_cpi_T_argumentExtension_vals[] = {
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_cpi_T_argumentExtension_choice[] = {
  {   1, &hf_qsig_cpi_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cpi_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cpi_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cpi_T_argumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cpi_T_argumentExtension_choice, hf_index, ett_qsig_cpi_T_argumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cpi_CPIRequestArg_sequence[] = {
  { &hf_qsig_cpi_cpiCapabilityLevel, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cpi_CPICapabilityLevel },
  { &hf_qsig_cpi_argumentExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cpi_T_argumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cpi_CPIRequestArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cpi_CPIRequestArg_sequence, hf_index, ett_qsig_cpi_CPIRequestArg);

  return offset;
}


static const value_string qsig_cpi_CPIProtectionLevel_vals[] = {
  {   0, "noProtection" },
  {   1, "lowProtection" },
  {   2, "mediumProtection" },
  {   3, "totalProtection" },
  { 0, NULL }
};


static int
dissect_qsig_cpi_CPIProtectionLevel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_cpi_T_argumentExtension_01_vals[] = {
  {   1, "extension" },
  {   2, "sequenceOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_cpi_T_argumentExtension_01_choice[] = {
  {   1, &hf_qsig_cpi_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_cpi_sequenceOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cpi_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cpi_T_argumentExtension_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cpi_T_argumentExtension_01_choice, hf_index, ett_qsig_cpi_T_argumentExtension_01,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cpi_CPIPRequestArg_sequence[] = {
  { &hf_qsig_cpi_cpiProtectionLevel, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cpi_CPIProtectionLevel },
  { &hf_qsig_cpi_argumentExtension_01, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cpi_T_argumentExtension_01 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cpi_CPIPRequestArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cpi_CPIPRequestArg_sequence, hf_index, ett_qsig_cpi_CPIPRequestArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_cpi_CPIRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cpi_CPIRequestArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cpi_qsig_cpi_CPIRequestArg_PDU);
  return offset;
}
static int dissect_qsig_cpi_CPIPRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cpi_CPIPRequestArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cpi_qsig_cpi_CPIPRequestArg_PDU);
  return offset;
}


/* --- Module PUM-Registration-Operations-asn1-97 --- --- ---                 */



static int
dissect_qsig_pumr_AlternativeId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string qsig_pumr_RpumUserId_vals[] = {
  {   0, "pumNumber" },
  {   1, "alternativeId" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumr_RpumUserId_choice[] = {
  {   0, &hf_qsig_pumr_pumNumber , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  {   1, &hf_qsig_pumr_alternativeId, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_AlternativeId },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_RpumUserId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumr_RpumUserId_choice, hf_index, ett_qsig_pumr_RpumUserId,
                                 NULL);

  return offset;
}


static const value_string qsig_pumr_ServiceOption_vals[] = {
  {   0, "inCallRegistration" },
  {   1, "outCallRegistration" },
  {   2, "allCallRegistration" },
  { 0, NULL }
};


static int
dissect_qsig_pumr_ServiceOption(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_qsig_pumr_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_pumr_SessionParams_sequence[] = {
  { &hf_qsig_pumr_durationOfSession, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_pumr_INTEGER },
  { &hf_qsig_pumr_numberOfOutgCalls, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_pumr_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_SessionParams(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumr_SessionParams_sequence, hf_index, ett_qsig_pumr_SessionParams);

  return offset;
}



static int
dissect_qsig_pumr_UserPin(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string qsig_pumr_T_userPin_vals[] = {
  {   6, "pumUserPin" },
  {   7, "activatingUserPin" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumr_T_userPin_choice[] = {
  {   6, &hf_qsig_pumr_pumUserPin, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_pumr_UserPin },
  {   7, &hf_qsig_pumr_activatingUserPin, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_qsig_pumr_UserPin },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_T_userPin(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumr_T_userPin_choice, hf_index, ett_qsig_pumr_T_userPin,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_pumr_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_pumr_sequOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_pumr_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_pumr_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_pumr_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_pumr_PumrExtension_vals[] = {
  {   4, "extension" },
  {   5, "sequOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumr_PumrExtension_choice[] = {
  {   4, &hf_qsig_pumr_extension , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   5, &hf_qsig_pumr_sequOfExtn, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_qsig_pumr_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_PumrExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumr_PumrExtension_choice, hf_index, ett_qsig_pumr_PumrExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_pumr_PumRegistrArg_sequence[] = {
  { &hf_qsig_pumr_pumRUserId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumr_RpumUserId },
  { &hf_qsig_pumr_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_pumr_hostingAddr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_pumr_activatingUserAddr, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_qsig_PartyNumber },
  { &hf_qsig_pumr_serviceOption, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_ServiceOption },
  { &hf_qsig_pumr_sessionParams, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_SessionParams },
  { &hf_qsig_pumr_userPin   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumr_T_userPin },
  { &hf_qsig_pumr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumr_PumrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_PumRegistrArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumr_PumRegistrArg_sequence, hf_index, ett_qsig_pumr_PumRegistrArg);

  return offset;
}


static const ber_sequence_t qsig_pumr_PumRegistrRes_sequence[] = {
  { &hf_qsig_pumr_pumNumber , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_pumr_serviceOption, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_ServiceOption },
  { &hf_qsig_pumr_sessionParams, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_SessionParams },
  { &hf_qsig_pumr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumr_PumrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_PumRegistrRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumr_PumRegistrRes_sequence, hf_index, ett_qsig_pumr_PumRegistrRes);

  return offset;
}



static int
dissect_qsig_pumr_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string qsig_pumr_DummyRes_vals[] = {
  {   0, "null" },
  {   1, "extension" },
  {   2, "sequOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumr_DummyRes_choice[] = {
  {   0, &hf_qsig_pumr_null      , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_NULL },
  {   1, &hf_qsig_pumr_extension , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_pumr_sequOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_pumr_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_DummyRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumr_DummyRes_choice, hf_index, ett_qsig_pumr_DummyRes,
                                 NULL);

  return offset;
}


static const value_string qsig_pumr_XpumUserId_vals[] = {
  {   0, "pumNumber" },
  {   1, "alternativeId" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumr_XpumUserId_choice[] = {
  {   0, &hf_qsig_pumr_pumNumber , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  {   1, &hf_qsig_pumr_alternativeId, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_AlternativeId },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_XpumUserId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumr_XpumUserId_choice, hf_index, ett_qsig_pumr_XpumUserId,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_pumr_PumDelRegArg_sequence[] = {
  { &hf_qsig_pumr_pumXUserId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumr_XpumUserId },
  { &hf_qsig_pumr_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_pumr_hostingAddr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_pumr_serviceOption, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_ServiceOption },
  { &hf_qsig_pumr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumr_PumrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_PumDelRegArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumr_PumDelRegArg_sequence, hf_index, ett_qsig_pumr_PumDelRegArg);

  return offset;
}


static const value_string qsig_pumr_DpumUserId_vals[] = {
  {   0, "pumNumber" },
  {   1, "alternativeId" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumr_DpumUserId_choice[] = {
  {   0, &hf_qsig_pumr_pumNumber , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  {   1, &hf_qsig_pumr_alternativeId, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_AlternativeId },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_DpumUserId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumr_DpumUserId_choice, hf_index, ett_qsig_pumr_DpumUserId,
                                 NULL);

  return offset;
}


static const value_string qsig_pumr_T_userPin_01_vals[] = {
  {   6, "pumUserPin" },
  {   7, "activatingUserPin" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumr_T_userPin_01_choice[] = {
  {   6, &hf_qsig_pumr_pumUserPin, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_pumr_UserPin },
  {   7, &hf_qsig_pumr_activatingUserPin, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_qsig_pumr_UserPin },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_T_userPin_01(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumr_T_userPin_01_choice, hf_index, ett_qsig_pumr_T_userPin_01,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_pumr_PumDe_regArg_sequence[] = {
  { &hf_qsig_pumr_pumDUserId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumr_DpumUserId },
  { &hf_qsig_pumr_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_pumr_hostingAddr, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_qsig_PartyNumber },
  { &hf_qsig_pumr_activatingUserAddr, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_PartyNumber },
  { &hf_qsig_pumr_serviceOption, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_ServiceOption },
  { &hf_qsig_pumr_userPin_01, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumr_T_userPin_01 },
  { &hf_qsig_pumr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumr_PumrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_PumDe_regArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumr_PumDe_regArg_sequence, hf_index, ett_qsig_pumr_PumDe_regArg);

  return offset;
}


static const value_string qsig_pumr_IpumUserId_vals[] = {
  {   0, "pumNumber" },
  {   1, "alternativeId" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumr_IpumUserId_choice[] = {
  {   0, &hf_qsig_pumr_pumNumber , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  {   1, &hf_qsig_pumr_alternativeId, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_AlternativeId },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_IpumUserId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumr_IpumUserId_choice, hf_index, ett_qsig_pumr_IpumUserId,
                                 NULL);

  return offset;
}



static int
dissect_qsig_pumr_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string qsig_pumr_T_userPin_02_vals[] = {
  {   6, "pumUserPin" },
  {   7, "activatingUserPin" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumr_T_userPin_02_choice[] = {
  {   6, &hf_qsig_pumr_pumUserPin, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_pumr_UserPin },
  {   7, &hf_qsig_pumr_activatingUserPin, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_qsig_pumr_UserPin },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_T_userPin_02(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumr_T_userPin_02_choice, hf_index, ett_qsig_pumr_T_userPin_02,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_pumr_PumInterrogArg_sequence[] = {
  { &hf_qsig_pumr_pumIUserId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumr_IpumUserId },
  { &hf_qsig_pumr_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_pumr_hostingAddr, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_qsig_PartyNumber },
  { &hf_qsig_pumr_activatingUserAddr, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_PartyNumber },
  { &hf_qsig_pumr_serviceOption, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_qsig_pumr_ServiceOption },
  { &hf_qsig_pumr_homeInfoOnly, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_BOOLEAN },
  { &hf_qsig_pumr_userPin_02, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumr_T_userPin_02 },
  { &hf_qsig_pumr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumr_PumrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_PumInterrogArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumr_PumInterrogArg_sequence, hf_index, ett_qsig_pumr_PumInterrogArg);

  return offset;
}


static const ber_sequence_t qsig_pumr_PumInterrogRes_item_sequence[] = {
  { &hf_qsig_pumr_basicService, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_pumr_hostingAddr, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_PartyNumber },
  { &hf_qsig_pumr_serviceOption, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_pumr_ServiceOption },
  { &hf_qsig_pumr_interrogParams, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_SessionParams },
  { &hf_qsig_pumr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumr_PumrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumr_PumInterrogRes_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumr_PumInterrogRes_item_sequence, hf_index, ett_qsig_pumr_PumInterrogRes_item);

  return offset;
}


static const ber_sequence_t qsig_pumr_PumInterrogRes_set_of[1] = {
  { &hf_qsig_pumr_PumInterrogRes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_PumInterrogRes_item },
};

static int
dissect_qsig_pumr_PumInterrogRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 qsig_pumr_PumInterrogRes_set_of, hf_index, ett_qsig_pumr_PumInterrogRes);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_pumr_PumRegistrArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pumr_PumRegistrArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_PumRegistrArg_PDU);
  return offset;
}
static int dissect_qsig_pumr_PumRegistrRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pumr_PumRegistrRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_PumRegistrRes_PDU);
  return offset;
}
static int dissect_qsig_pumr_PumDelRegArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pumr_PumDelRegArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_PumDelRegArg_PDU);
  return offset;
}
static int dissect_qsig_pumr_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pumr_DummyRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_pumr_PumDe_regArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pumr_PumDe_regArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_PumDe_regArg_PDU);
  return offset;
}
static int dissect_qsig_pumr_PumInterrogArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pumr_PumInterrogArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_PumInterrogArg_PDU);
  return offset;
}
static int dissect_qsig_pumr_PumInterrogRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pumr_PumInterrogRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_PumInterrogRes_PDU);
  return offset;
}
static int dissect_qsig_pumr_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_Extension_PDU);
  return offset;
}


/* --- Module Private-User-Mobility-Call-Handling-Operations-asn1-97 --- --- --- */


static const ber_sequence_t qsig_pumch_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_pumch_sequOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_pumch_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_pumch_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_pumch_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_pumch_PumiExtension_vals[] = {
  {   4, "extension" },
  {   5, "sequOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumch_PumiExtension_choice[] = {
  {   4, &hf_qsig_pumch_extension, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   5, &hf_qsig_pumch_sequOfExtn, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_qsig_pumch_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumch_PumiExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumch_PumiExtension_choice, hf_index, ett_qsig_pumch_PumiExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_pumch_EnquiryArg_sequence[] = {
  { &hf_qsig_pumch_pisnNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_pumch_qSIGInfoElement, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_qsig_PSS1InformationElement },
  { &hf_qsig_pumch_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumch_PumiExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumch_EnquiryArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumch_EnquiryArg_sequence, hf_index, ett_qsig_pumch_EnquiryArg);

  return offset;
}



static int
dissect_qsig_pumch_AlternativeId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t qsig_pumch_T_both_sequence[] = {
  { &hf_qsig_pumch_pisnNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_pumch_alternativeId, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_pumch_AlternativeId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumch_T_both(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumch_T_both_sequence, hf_index, ett_qsig_pumch_T_both);

  return offset;
}


static const value_string qsig_pumch_PumIdentity_vals[] = {
  {   0, "pisnNumber" },
  {   1, "alternativeId" },
  {   2, "both" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumch_PumIdentity_choice[] = {
  {   0, &hf_qsig_pumch_pisnNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  {   1, &hf_qsig_pumch_alternativeId, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_qsig_pumch_AlternativeId },
  {   2, &hf_qsig_pumch_both     , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_qsig_pumch_T_both },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumch_PumIdentity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumch_PumIdentity_choice, hf_index, ett_qsig_pumch_PumIdentity,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_pumch_DivertArg_sequence[] = {
  { &hf_qsig_pumch_hostingAddr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_pumch_callingNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PresentedNumberScreened },
  { &hf_qsig_pumch_pumIdentity, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumch_PumIdentity },
  { &hf_qsig_pumch_qSIGInfoElement, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_qsig_PSS1InformationElement },
  { &hf_qsig_pumch_callingUserSub, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_PartySubaddress },
  { &hf_qsig_pumch_callingUserName, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_pumch_pumUserSub, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_qsig_PartySubaddress },
  { &hf_qsig_pumch_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumch_PumiExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumch_DivertArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumch_DivertArg_sequence, hf_index, ett_qsig_pumch_DivertArg);

  return offset;
}


static const ber_sequence_t qsig_pumch_InformArg_sequence[] = {
  { &hf_qsig_pumch_pumIdentity, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumch_PumIdentity },
  { &hf_qsig_pumch_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumch_PumiExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumch_InformArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumch_InformArg_sequence, hf_index, ett_qsig_pumch_InformArg);

  return offset;
}


static const ber_sequence_t qsig_pumch_CurrLocation_sequence[] = {
  { &hf_qsig_pumch_hostingAddr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_pumch_pumIdentity, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumch_PumIdentity },
  { &hf_qsig_pumch_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumch_PumiExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumch_CurrLocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumch_CurrLocation_sequence, hf_index, ett_qsig_pumch_CurrLocation);

  return offset;
}


static const value_string qsig_pumch_SubscriptionOption_vals[] = {
  {   0, "noNotification" },
  {   1, "notificationWithoutDivertedToNr" },
  {   2, "notificationWithDivertedToNr" },
  { 0, NULL }
};


static int
dissect_qsig_pumch_SubscriptionOption(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_pumch_CfuActivated_sequence[] = {
  { &hf_qsig_pumch_divToAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Address },
  { &hf_qsig_pumch_divOptions, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_pumch_SubscriptionOption },
  { &hf_qsig_pumch_pumName  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_pumch_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumch_PumiExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumch_CfuActivated(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumch_CfuActivated_sequence, hf_index, ett_qsig_pumch_CfuActivated);

  return offset;
}


static const value_string qsig_pumch_EnquiryRes_vals[] = {
  {   1, "currLocation" },
  {   2, "cfuActivated" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumch_EnquiryRes_choice[] = {
  {   1, &hf_qsig_pumch_currLocation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_pumch_CurrLocation },
  {   2, &hf_qsig_pumch_cfuActivated, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_pumch_CfuActivated },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumch_EnquiryRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumch_EnquiryRes_choice, hf_index, ett_qsig_pumch_EnquiryRes,
                                 NULL);

  return offset;
}



static int
dissect_qsig_pumch_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string qsig_pumch_DummyRes_vals[] = {
  {   0, "null" },
  {   1, "extension" },
  {   2, "sequOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumch_DummyRes_choice[] = {
  {   0, &hf_qsig_pumch_null     , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_pumch_NULL },
  {   1, &hf_qsig_pumch_extension, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_pumch_sequOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_pumch_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumch_DummyRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumch_DummyRes_choice, hf_index, ett_qsig_pumch_DummyRes,
                                 NULL);

  return offset;
}


static const value_string qsig_pumch_T_pumoaextension_vals[] = {
  {   3, "single" },
  {   4, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_pumch_T_pumoaextension_choice[] = {
  {   3, &hf_qsig_pumch_single   , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   4, &hf_qsig_pumch_multiple , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_pumch_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumch_T_pumoaextension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumch_T_pumoaextension_choice, hf_index, ett_qsig_pumch_T_pumoaextension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_pumch_PumoArg_sequence[] = {
  { &hf_qsig_pumch_destinationNumber, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_qsig_PartyNumber },
  { &hf_qsig_pumch_pumIdentity, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumch_PumIdentity },
  { &hf_qsig_pumch_sendingComplete, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_pumch_NULL },
  { &hf_qsig_pumch_pumoaextension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_pumch_T_pumoaextension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_pumch_PumoArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumch_PumoArg_sequence, hf_index, ett_qsig_pumch_PumoArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_pumch_EnquiryArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pumch_EnquiryArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_EnquiryArg_PDU);
  return offset;
}
static int dissect_qsig_pumch_EnquiryRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pumch_EnquiryRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_EnquiryRes_PDU);
  return offset;
}
static int dissect_qsig_pumch_DivertArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pumch_DivertArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_DivertArg_PDU);
  return offset;
}
static int dissect_qsig_pumch_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pumch_DummyRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_pumch_InformArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pumch_InformArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_InformArg_PDU);
  return offset;
}
static int dissect_qsig_pumch_PumoArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_pumch_PumoArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_PumoArg_PDU);
  return offset;
}
static int dissect_qsig_pumch_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_Extension_PDU);
  return offset;
}


/* --- Module Single-Step-Call-Transfer-Operations-asn1-97 --- --- ---        */



static int
dissect_qsig_ssct_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_ssct_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_ssct_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_ssct_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_ssct_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_ssct_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_ssct_DummyArg_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ssct_DummyArg_choice[] = {
  {   0, &hf_qsig_ssct_null      , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_ssct_NULL },
  {   1, &hf_qsig_ssct_single    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_ssct_multiple  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_ssct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ssct_DummyArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ssct_DummyArg_choice, hf_index, ett_qsig_ssct_DummyArg,
                                 NULL);

  return offset;
}


static const value_string qsig_ssct_DummyRes_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ssct_DummyRes_choice[] = {
  {   0, &hf_qsig_ssct_null      , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_ssct_NULL },
  {   1, &hf_qsig_ssct_single    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_ssct_multiple  , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_ssct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ssct_DummyRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ssct_DummyRes_choice, hf_index, ett_qsig_ssct_DummyRes,
                                 NULL);

  return offset;
}



static int
dissect_qsig_ssct_AwaitConnect(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string qsig_ssct_SSCTIargumentExtension_vals[] = {
  {   4, "single" },
  {   5, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ssct_SSCTIargumentExtension_choice[] = {
  {   4, &hf_qsig_ssct_single    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   5, &hf_qsig_ssct_multiple  , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_qsig_ssct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ssct_SSCTIargumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ssct_SSCTIargumentExtension_choice, hf_index, ett_qsig_ssct_SSCTIargumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ssct_SSCTInitiateArg_sequence[] = {
  { &hf_qsig_ssct_rerouteingNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_ssct_transferredAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PresentedAddressScreened },
  { &hf_qsig_ssct_awaitConnect, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_qsig_ssct_AwaitConnect },
  { &hf_qsig_ssct_transferredName, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_ssct_transferringAddress, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_qsig_PresentedAddressScreened },
  { &hf_qsig_ssct_transferringName, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_ssct_argumentExtensionSSCTI, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ssct_SSCTIargumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ssct_SSCTInitiateArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ssct_SSCTInitiateArg_sequence, hf_index, ett_qsig_ssct_SSCTInitiateArg);

  return offset;
}


static const value_string qsig_ssct_SSCTSargumentExtension_vals[] = {
  {   3, "single" },
  {   4, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ssct_SSCTSargumentExtension_choice[] = {
  {   3, &hf_qsig_ssct_single    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   4, &hf_qsig_ssct_multiple  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_ssct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ssct_SSCTSargumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ssct_SSCTSargumentExtension_choice, hf_index, ett_qsig_ssct_SSCTSargumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ssct_SSCTSetupArg_sequence[] = {
  { &hf_qsig_ssct_transferringAddress, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_PresentedAddressScreened },
  { &hf_qsig_ssct_transferringName, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_ssct_argumentExtensionSSCTS, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ssct_SSCTSargumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ssct_SSCTSetupArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ssct_SSCTSetupArg_sequence, hf_index, ett_qsig_ssct_SSCTSetupArg);

  return offset;
}


static const value_string qsig_ssct_SSCTDargumentExtension_vals[] = {
  {   3, "single" },
  {   4, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_ssct_SSCTDargumentExtension_choice[] = {
  {   3, &hf_qsig_ssct_single    , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   4, &hf_qsig_ssct_multiple  , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_ssct_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ssct_SSCTDargumentExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ssct_SSCTDargumentExtension_choice, hf_index, ett_qsig_ssct_SSCTDargumentExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_ssct_SSCTDigitInfoArg_sequence[] = {
  { &hf_qsig_ssct_reroutingNumber, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_PartyNumber },
  { &hf_qsig_ssct_sendingComplete, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_ssct_NULL },
  { &hf_qsig_ssct_argumentExtensionSSCTD, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ssct_SSCTDargumentExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ssct_SSCTDigitInfoArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ssct_SSCTDigitInfoArg_sequence, hf_index, ett_qsig_ssct_SSCTDigitInfoArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_ssct_SSCTInitiateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ssct_SSCTInitiateArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ssct_qsig_ssct_SSCTInitiateArg_PDU);
  return offset;
}
static int dissect_qsig_ssct_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ssct_DummyRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ssct_qsig_ssct_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_ssct_SSCTSetupArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ssct_SSCTSetupArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ssct_qsig_ssct_SSCTSetupArg_PDU);
  return offset;
}
static int dissect_qsig_ssct_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ssct_DummyArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ssct_qsig_ssct_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_ssct_SSCTDigitInfoArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ssct_SSCTDigitInfoArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ssct_qsig_ssct_SSCTDigitInfoArg_PDU);
  return offset;
}
static int dissect_qsig_ssct_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ssct_qsig_ssct_Extension_PDU);
  return offset;
}


/* --- Module WTM-Location-Registration-Operations-asn1-97 --- --- ---        */



static int
dissect_qsig_wtmlr_AlternativeId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string qsig_wtmlr_WtmUserId_vals[] = {
  {   0, "pisnNumber" },
  {   1, "alternativeId" },
  { 0, NULL }
};

static const ber_choice_t qsig_wtmlr_WtmUserId_choice[] = {
  {   0, &hf_qsig_wtmlr_pisnNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  {   1, &hf_qsig_wtmlr_alternativeId, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmlr_AlternativeId },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmlr_WtmUserId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmlr_WtmUserId_choice, hf_index, ett_qsig_wtmlr_WtmUserId,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmlr_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_wtmlr_sequOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_wtmlr_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_wtmlr_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_wtmlr_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_wtmlr_LrExtension_vals[] = {
  {   1, "extension" },
  {   2, "sequOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_wtmlr_LrExtension_choice[] = {
  {   1, &hf_qsig_wtmlr_extension, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_wtmlr_sequOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_wtmlr_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmlr_LrExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmlr_LrExtension_choice, hf_index, ett_qsig_wtmlr_LrExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmlr_LocUpdArg_sequence[] = {
  { &hf_qsig_wtmlr_wtmUserId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_WtmUserId },
  { &hf_qsig_wtmlr_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_wtmlr_visitPINX, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_wtmlr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_LrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmlr_LocUpdArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmlr_LocUpdArg_sequence, hf_index, ett_qsig_wtmlr_LocUpdArg);

  return offset;
}



static int
dissect_qsig_wtmlr_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string qsig_wtmlr_DummyRes_vals[] = {
  {   0, "null" },
  {   1, "extension" },
  {   2, "sequOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_wtmlr_DummyRes_choice[] = {
  {   0, &hf_qsig_wtmlr_null     , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmlr_NULL },
  {   1, &hf_qsig_wtmlr_extension, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_wtmlr_sequOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_wtmlr_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmlr_DummyRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmlr_DummyRes_choice, hf_index, ett_qsig_wtmlr_DummyRes,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmlr_LocDelArg_sequence[] = {
  { &hf_qsig_wtmlr_wtmUserId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_WtmUserId },
  { &hf_qsig_wtmlr_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_wtmlr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_LrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmlr_LocDelArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmlr_LocDelArg_sequence, hf_index, ett_qsig_wtmlr_LocDelArg);

  return offset;
}


static const ber_sequence_t qsig_wtmlr_LocDeRegArg_sequence[] = {
  { &hf_qsig_wtmlr_wtmUserId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_WtmUserId },
  { &hf_qsig_wtmlr_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_wtmlr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_LrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmlr_LocDeRegArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmlr_LocDeRegArg_sequence, hf_index, ett_qsig_wtmlr_LocDeRegArg);

  return offset;
}


static const ber_sequence_t qsig_wtmlr_PisnEnqArg_sequence[] = {
  { &hf_qsig_wtmlr_alternativeId, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmlr_AlternativeId },
  { &hf_qsig_wtmlr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_LrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmlr_PisnEnqArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmlr_PisnEnqArg_sequence, hf_index, ett_qsig_wtmlr_PisnEnqArg);

  return offset;
}


static const ber_sequence_t qsig_wtmlr_PisnEnqRes_sequence[] = {
  { &hf_qsig_wtmlr_wtmUserId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_WtmUserId },
  { &hf_qsig_wtmlr_resExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_LrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmlr_PisnEnqRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmlr_PisnEnqRes_sequence, hf_index, ett_qsig_wtmlr_PisnEnqRes);

  return offset;
}


static const ber_sequence_t qsig_wtmlr_GetRRCInfArg_sequence[] = {
  { &hf_qsig_wtmlr_wtmUserId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_WtmUserId },
  { &hf_qsig_wtmlr_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_wtmlr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_LrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmlr_GetRRCInfArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmlr_GetRRCInfArg_sequence, hf_index, ett_qsig_wtmlr_GetRRCInfArg);

  return offset;
}



static int
dissect_qsig_wtmlr_RRClass(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmlr_GetRRCInfRes_sequence[] = {
  { &hf_qsig_wtmlr_alternativeId, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_wtmlr_AlternativeId },
  { &hf_qsig_wtmlr_rrClass  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_wtmlr_RRClass },
  { &hf_qsig_wtmlr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_LrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmlr_GetRRCInfRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmlr_GetRRCInfRes_sequence, hf_index, ett_qsig_wtmlr_GetRRCInfRes);

  return offset;
}


static const ber_sequence_t qsig_wtmlr_LocInfoCheckArg_sequence[] = {
  { &hf_qsig_wtmlr_wtmUserId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_WtmUserId },
  { &hf_qsig_wtmlr_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  { &hf_qsig_wtmlr_visitPINX, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_wtmlr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_LrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmlr_LocInfoCheckArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmlr_LocInfoCheckArg_sequence, hf_index, ett_qsig_wtmlr_LocInfoCheckArg);

  return offset;
}


static const value_string qsig_wtmlr_CheckResult_vals[] = {
  {   0, "locInfChk-correct" },
  {   1, "locInfChk-incorrect" },
  { 0, NULL }
};


static int
dissect_qsig_wtmlr_CheckResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmlr_LocInfoCheckRes_sequence[] = {
  { &hf_qsig_wtmlr_checkResult, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmlr_CheckResult },
  { &hf_qsig_wtmlr_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmlr_LrExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmlr_LocInfoCheckRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmlr_LocInfoCheckRes_sequence, hf_index, ett_qsig_wtmlr_LocInfoCheckRes);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_wtmlr_LocUpdArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmlr_LocUpdArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_LocUpdArg_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmlr_DummyRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_LocDelArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmlr_LocDelArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_LocDelArg_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_LocDeRegArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmlr_LocDeRegArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_LocDeRegArg_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_PisnEnqArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmlr_PisnEnqArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_PisnEnqArg_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_PisnEnqRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmlr_PisnEnqRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_PisnEnqRes_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_GetRRCInfArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmlr_GetRRCInfArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_GetRRCInfArg_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_GetRRCInfRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmlr_GetRRCInfRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_GetRRCInfRes_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_LocInfoCheckArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmlr_LocInfoCheckArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_LocInfoCheckArg_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_LocInfoCheckRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmlr_LocInfoCheckRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_LocInfoCheckRes_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_Extension_PDU);
  return offset;
}


/* --- Module Wireless-Terminal-Call-Handling-Operations-asn1-97 --- --- ---  */


static const ber_sequence_t qsig_wtmch_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_wtmch_sequOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_wtmch_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_wtmch_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_wtmch_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_wtmch_WtmiExtension_vals[] = {
  {   4, "extension" },
  {   5, "sequOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_wtmch_WtmiExtension_choice[] = {
  {   4, &hf_qsig_wtmch_extension, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   5, &hf_qsig_wtmch_sequOfExtn, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_qsig_wtmch_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmch_WtmiExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmch_WtmiExtension_choice, hf_index, ett_qsig_wtmch_WtmiExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmch_EnquiryArg_sequence[] = {
  { &hf_qsig_wtmch_pisnNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_wtmch_qSIGInfoElement, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_qsig_PSS1InformationElement },
  { &hf_qsig_wtmch_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmch_WtmiExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmch_EnquiryArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmch_EnquiryArg_sequence, hf_index, ett_qsig_wtmch_EnquiryArg);

  return offset;
}



static int
dissect_qsig_wtmch_AlternativeId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmch_T_both_sequence[] = {
  { &hf_qsig_wtmch_pisnNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_wtmch_alternativeId, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmch_AlternativeId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmch_T_both(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmch_T_both_sequence, hf_index, ett_qsig_wtmch_T_both);

  return offset;
}


static const value_string qsig_wtmch_WtmIdentity_vals[] = {
  {   0, "pisnNumber" },
  {   1, "alternativeId" },
  {   2, "both" },
  { 0, NULL }
};

static const ber_choice_t qsig_wtmch_WtmIdentity_choice[] = {
  {   0, &hf_qsig_wtmch_pisnNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  {   1, &hf_qsig_wtmch_alternativeId, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_qsig_wtmch_AlternativeId },
  {   2, &hf_qsig_wtmch_both     , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_qsig_wtmch_T_both },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmch_WtmIdentity(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmch_WtmIdentity_choice, hf_index, ett_qsig_wtmch_WtmIdentity,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmch_DivertArg_sequence[] = {
  { &hf_qsig_wtmch_visitPINX, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_wtmch_callingNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PresentedNumberScreened },
  { &hf_qsig_wtmch_wtmIdentity, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmch_WtmIdentity },
  { &hf_qsig_wtmch_qSIGInfoElement, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_qsig_PSS1InformationElement },
  { &hf_qsig_wtmch_callingUserSub, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_PartySubaddress },
  { &hf_qsig_wtmch_callingName, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_wtmch_wtmUserSub, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_qsig_PartySubaddress },
  { &hf_qsig_wtmch_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmch_WtmiExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmch_DivertArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmch_DivertArg_sequence, hf_index, ett_qsig_wtmch_DivertArg);

  return offset;
}


static const ber_sequence_t qsig_wtmch_InformArg_sequence[] = {
  { &hf_qsig_wtmch_wtmIdentity, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmch_WtmIdentity },
  { &hf_qsig_wtmch_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmch_WtmiExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmch_InformArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmch_InformArg_sequence, hf_index, ett_qsig_wtmch_InformArg);

  return offset;
}


static const ber_sequence_t qsig_wtmch_CurrLocation_sequence[] = {
  { &hf_qsig_wtmch_visitPINX, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_wtmch_wtmIdentity, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmch_WtmIdentity },
  { &hf_qsig_wtmch_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmch_WtmiExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmch_CurrLocation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmch_CurrLocation_sequence, hf_index, ett_qsig_wtmch_CurrLocation);

  return offset;
}


static const value_string qsig_wtmch_SubscriptionOption_vals[] = {
  {   0, "noNotification" },
  {   1, "notificationWithoutDivertedToNr" },
  {   2, "notificationWithDivertedToNr" },
  { 0, NULL }
};


static int
dissect_qsig_wtmch_SubscriptionOption(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmch_CfuActivated_sequence[] = {
  { &hf_qsig_wtmch_divToAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Address },
  { &hf_qsig_wtmch_divOptions, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmch_SubscriptionOption },
  { &hf_qsig_wtmch_wtmName  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_wtmch_argExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmch_WtmiExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmch_CfuActivated(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmch_CfuActivated_sequence, hf_index, ett_qsig_wtmch_CfuActivated);

  return offset;
}


static const value_string qsig_wtmch_EnquiryRes_vals[] = {
  {   1, "currLocation" },
  {   2, "cfuActivated" },
  { 0, NULL }
};

static const ber_choice_t qsig_wtmch_EnquiryRes_choice[] = {
  {   1, &hf_qsig_wtmch_currLocation, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_wtmch_CurrLocation },
  {   2, &hf_qsig_wtmch_cfuActivated, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_wtmch_CfuActivated },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmch_EnquiryRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmch_EnquiryRes_choice, hf_index, ett_qsig_wtmch_EnquiryRes,
                                 NULL);

  return offset;
}



static int
dissect_qsig_wtmch_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string qsig_wtmch_DummyRes_vals[] = {
  {   0, "null" },
  {   1, "extension" },
  {   2, "sequOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_wtmch_DummyRes_choice[] = {
  {   0, &hf_qsig_wtmch_null     , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmch_NULL },
  {   1, &hf_qsig_wtmch_extension, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_wtmch_sequOfExtn, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_wtmch_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmch_DummyRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmch_DummyRes_choice, hf_index, ett_qsig_wtmch_DummyRes,
                                 NULL);

  return offset;
}


static const value_string qsig_wtmch_T_wtmoaextension_vals[] = {
  {   2, "single" },
  {   3, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_wtmch_T_wtmoaextension_choice[] = {
  {   2, &hf_qsig_wtmch_single   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   3, &hf_qsig_wtmch_multiple , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_wtmch_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmch_T_wtmoaextension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmch_T_wtmoaextension_choice, hf_index, ett_qsig_wtmch_T_wtmoaextension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmch_WtmoArg_sequence[] = {
  { &hf_qsig_wtmch_destinationNumber, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_qsig_PartyNumber },
  { &hf_qsig_wtmch_sendingComplete, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_wtmch_NULL },
  { &hf_qsig_wtmch_wtmoaextension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmch_T_wtmoaextension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmch_WtmoArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmch_WtmoArg_sequence, hf_index, ett_qsig_wtmch_WtmoArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_wtmch_EnquiryArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmch_EnquiryArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_EnquiryArg_PDU);
  return offset;
}
static int dissect_qsig_wtmch_EnquiryRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmch_EnquiryRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_EnquiryRes_PDU);
  return offset;
}
static int dissect_qsig_wtmch_DivertArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmch_DivertArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_DivertArg_PDU);
  return offset;
}
static int dissect_qsig_wtmch_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmch_DummyRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_wtmch_InformArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmch_InformArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_InformArg_PDU);
  return offset;
}
static int dissect_qsig_wtmch_WtmoArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmch_WtmoArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_WtmoArg_PDU);
  return offset;
}
static int dissect_qsig_wtmch_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_Extension_PDU);
  return offset;
}


/* --- Module WTM-Authentication-Operations-asn1-97 --- --- ---               */



static int
dissect_qsig_wtmau_AlternativeId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string qsig_wtmau_WtmUserId_vals[] = {
  {   0, "pisnNumber" },
  {   1, "alternativeId" },
  { 0, NULL }
};

static const ber_choice_t qsig_wtmau_WtmUserId_choice[] = {
  {   0, &hf_qsig_wtmau_pisnNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  {   1, &hf_qsig_wtmau_alternativeId, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_AlternativeId },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_WtmUserId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmau_WtmUserId_choice, hf_index, ett_qsig_wtmau_WtmUserId,
                                 NULL);

  return offset;
}



static int
dissect_qsig_wtmau_AuthChallenge(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_wtmau_AuthResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_wtmau_DerivedCipherKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_wtmau_CalculationParam(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmau_CalcWtatInfoUnit_sequence[] = {
  { &hf_qsig_wtmau_authChallenge, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_AuthChallenge },
  { &hf_qsig_wtmau_authResponse, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_AuthResponse },
  { &hf_qsig_wtmau_derivedCipherKey, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_wtmau_DerivedCipherKey },
  { &hf_qsig_wtmau_calculationParam, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_wtmau_CalculationParam },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_CalcWtatInfoUnit(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_CalcWtatInfoUnit_sequence, hf_index, ett_qsig_wtmau_CalcWtatInfoUnit);

  return offset;
}


static const ber_sequence_t qsig_wtmau_CalcWtatInfo_sequence_of[1] = {
  { &hf_qsig_wtmau_CalcWtatInfo_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_CalcWtatInfoUnit },
};

static int
dissect_qsig_wtmau_CalcWtatInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_wtmau_CalcWtatInfo_sequence_of, hf_index, ett_qsig_wtmau_CalcWtatInfo);

  return offset;
}


static const ber_sequence_t qsig_wtmau_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_wtmau_sequOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_wtmau_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_wtmau_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_wtmau_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_wtmau_DummyExtension_vals[] = {
  {   5, "extension" },
  {   6, "sequOfExtn" },
  { 0, NULL }
};

static const ber_choice_t qsig_wtmau_DummyExtension_choice[] = {
  {   5, &hf_qsig_wtmau_extension, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   6, &hf_qsig_wtmau_sequOfExtn, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_wtmau_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_DummyExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmau_DummyExtension_choice, hf_index, ett_qsig_wtmau_DummyExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmau_AuthWtmArg_sequence[] = {
  { &hf_qsig_wtmau_wtmUserId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmau_WtmUserId },
  { &hf_qsig_wtmau_calcWtatInfo, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_wtmau_CalcWtatInfo },
  { &hf_qsig_wtmau_dummyExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmau_DummyExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_AuthWtmArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_AuthWtmArg_sequence, hf_index, ett_qsig_wtmau_AuthWtmArg);

  return offset;
}


static const value_string qsig_wtmau_T_autWtmResValue_vals[] = {
  {   0, "auth-res-correct" },
  {   1, "auth-res-incorrect" },
  { 0, NULL }
};


static int
dissect_qsig_wtmau_T_autWtmResValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmau_AuthWtmRes_sequence[] = {
  { &hf_qsig_wtmau_autWtmResValue, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_T_autWtmResValue },
  { &hf_qsig_wtmau_dummyExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmau_DummyExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_AuthWtmRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_AuthWtmRes_sequence, hf_index, ett_qsig_wtmau_AuthWtmRes);

  return offset;
}



static int
dissect_qsig_wtmau_CanCompute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_wtmau_WtatParamArg_sequence[] = {
  { &hf_qsig_wtmau_wtmUserId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmau_WtmUserId },
  { &hf_qsig_wtmau_canCompute, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_CanCompute },
  { &hf_qsig_wtmau_authChallenge, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_AuthChallenge },
  { &hf_qsig_wtmau_dummyExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmau_DummyExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_WtatParamArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_WtatParamArg_sequence, hf_index, ett_qsig_wtmau_WtatParamArg);

  return offset;
}


static const value_string qsig_wtmau_DefinedIDs_vals[] = {
  {   0, "ct2" },
  {   1, "dect" },
  {   2, "gsm" },
  {   3, "pci" },
  {   4, "pwt" },
  {   5, "us-gsm" },
  {   6, "phs" },
  {   7, "tetra" },
  { 0, NULL }
};


static int
dissect_qsig_wtmau_DefinedIDs(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_wtmau_T_param(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 160 "../../asn1/qsig/qsig.cnf"



  return offset;
}


static const ber_sequence_t qsig_wtmau_AuthAlgorithm_sequence[] = {
  { &hf_qsig_wtmau_authAlg  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_DefinedIDs },
  { &hf_qsig_wtmau_param    , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_T_param },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_AuthAlgorithm(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_AuthAlgorithm_sequence, hf_index, ett_qsig_wtmau_AuthAlgorithm);

  return offset;
}



static int
dissect_qsig_wtmau_AuthSessionKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmau_AuthSessionKeyInfo_sequence[] = {
  { &hf_qsig_wtmau_authSessionKey, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_AuthSessionKey },
  { &hf_qsig_wtmau_calculationParam, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_CalculationParam },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_AuthSessionKeyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_AuthSessionKeyInfo_sequence, hf_index, ett_qsig_wtmau_AuthSessionKeyInfo);

  return offset;
}



static int
dissect_qsig_wtmau_AuthKey(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_wtmau_INTEGER_1_8(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string qsig_wtmau_T_wtatParamInfoChoice_vals[] = {
  {   1, "authSessionKeyInfo" },
  {   2, "calcWtatInfo" },
  {   3, "authKey" },
  {   4, "challLen" },
  { 0, NULL }
};

static const ber_choice_t qsig_wtmau_T_wtatParamInfoChoice_choice[] = {
  {   1, &hf_qsig_wtmau_authSessionKeyInfo, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_wtmau_AuthSessionKeyInfo },
  {   2, &hf_qsig_wtmau_calcWtatInfo, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_wtmau_CalcWtatInfo },
  {   3, &hf_qsig_wtmau_authKey  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_wtmau_AuthKey },
  {   4, &hf_qsig_wtmau_challLen , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_wtmau_INTEGER_1_8 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_T_wtatParamInfoChoice(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmau_T_wtatParamInfoChoice_choice, hf_index, ett_qsig_wtmau_T_wtatParamInfoChoice,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmau_WtatParamInfo_sequence[] = {
  { &hf_qsig_wtmau_authAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_AuthAlgorithm },
  { &hf_qsig_wtmau_wtatParamInfoChoice, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmau_T_wtatParamInfoChoice },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_WtatParamInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_WtatParamInfo_sequence, hf_index, ett_qsig_wtmau_WtatParamInfo);

  return offset;
}


static const ber_sequence_t qsig_wtmau_WtatParamRes_sequence[] = {
  { &hf_qsig_wtmau_wtatParamInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_WtatParamInfo },
  { &hf_qsig_wtmau_dummyExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmau_DummyExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_WtatParamRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_WtatParamRes_sequence, hf_index, ett_qsig_wtmau_WtatParamRes);

  return offset;
}


static const ber_sequence_t qsig_wtmau_WtanParamArg_sequence[] = {
  { &hf_qsig_wtmau_wtmUserId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmau_WtmUserId },
  { &hf_qsig_wtmau_authChallenge, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_AuthChallenge },
  { &hf_qsig_wtmau_authAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_AuthAlgorithm },
  { &hf_qsig_wtmau_canCompute, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_CanCompute },
  { &hf_qsig_wtmau_dummyExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmau_DummyExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_WtanParamArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_WtanParamArg_sequence, hf_index, ett_qsig_wtmau_WtanParamArg);

  return offset;
}


static const ber_sequence_t qsig_wtmau_CalcWtanInfo_sequence[] = {
  { &hf_qsig_wtmau_authResponse, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_AuthResponse },
  { &hf_qsig_wtmau_calculationParam, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_CalculationParam },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_CalcWtanInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_CalcWtanInfo_sequence, hf_index, ett_qsig_wtmau_CalcWtanInfo);

  return offset;
}


static const value_string qsig_wtmau_WtanParamInfo_vals[] = {
  {   1, "authSessionKeyInfo" },
  {   2, "calcWtanInfo" },
  { 0, NULL }
};

static const ber_choice_t qsig_wtmau_WtanParamInfo_choice[] = {
  {   1, &hf_qsig_wtmau_authSessionKeyInfo, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_wtmau_AuthSessionKeyInfo },
  {   2, &hf_qsig_wtmau_calcWtanInfo, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_wtmau_CalcWtanInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_WtanParamInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmau_WtanParamInfo_choice, hf_index, ett_qsig_wtmau_WtanParamInfo,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmau_WtanParamRes_sequence[] = {
  { &hf_qsig_wtmau_wtanParamInfo, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmau_WtanParamInfo },
  { &hf_qsig_wtmau_dummyExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmau_DummyExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_WtanParamRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_WtanParamRes_sequence, hf_index, ett_qsig_wtmau_WtanParamRes);

  return offset;
}


static const ber_sequence_t qsig_wtmau_ARG_transferAuthParam_sequence[] = {
  { &hf_qsig_wtmau_wtatParamInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_WtatParamInfo },
  { &hf_qsig_wtmau_dummyExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_wtmau_DummyExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_ARG_transferAuthParam(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_ARG_transferAuthParam_sequence, hf_index, ett_qsig_wtmau_ARG_transferAuthParam);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_wtmau_AuthWtmArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmau_AuthWtmArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_AuthWtmArg_PDU);
  return offset;
}
static int dissect_qsig_wtmau_AuthWtmRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmau_AuthWtmRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_AuthWtmRes_PDU);
  return offset;
}
static int dissect_qsig_wtmau_WtatParamArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmau_WtatParamArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_WtatParamArg_PDU);
  return offset;
}
static int dissect_qsig_wtmau_WtatParamRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmau_WtatParamRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_WtatParamRes_PDU);
  return offset;
}
static int dissect_qsig_wtmau_WtanParamArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmau_WtanParamArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_WtanParamArg_PDU);
  return offset;
}
static int dissect_qsig_wtmau_WtanParamRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmau_WtanParamRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_WtanParamRes_PDU);
  return offset;
}
static int dissect_qsig_wtmau_ARG_transferAuthParam_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_wtmau_ARG_transferAuthParam(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_ARG_transferAuthParam_PDU);
  return offset;
}
static int dissect_qsig_wtmau_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_Extension_PDU);
  return offset;
}


/* --- Module SS-SD-Operations-asn1-97 --- --- ---                            */



static int
dissect_qsig_sd_BMPStringNormal(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_sd_BMPStringExtended(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string qsig_sd_DisplayString_vals[] = {
  {   0, "displayStringNormal" },
  {   1, "displayStringExtended" },
  { 0, NULL }
};

static const ber_choice_t qsig_sd_DisplayString_choice[] = {
  {   0, &hf_qsig_sd_displayStringNormal, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_sd_BMPStringNormal },
  {   1, &hf_qsig_sd_displayStringExtended, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_sd_BMPStringExtended },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sd_DisplayString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_sd_DisplayString_choice, hf_index, ett_qsig_sd_DisplayString,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_sd_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_sd_multipleExtension_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_sd_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_sd_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_sd_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_sd_SDExtension_vals[] = {
  {   2, "extension" },
  {   3, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_sd_SDExtension_choice[] = {
  {   2, &hf_qsig_sd_extension   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   3, &hf_qsig_sd_multipleExtension, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_sd_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sd_SDExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_sd_SDExtension_choice, hf_index, ett_qsig_sd_SDExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_sd_DisplayArg_sequence[] = {
  { &hf_qsig_sd_displayString, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sd_DisplayString },
  { &hf_qsig_sd_sdextension , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sd_SDExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sd_DisplayArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sd_DisplayArg_sequence, hf_index, ett_qsig_sd_DisplayArg);

  return offset;
}


static const ber_sequence_t qsig_sd_KeypadArg_sequence[] = {
  { &hf_qsig_sd_keypadString, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_sd_BMPStringNormal },
  { &hf_qsig_sd_sdextension , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sd_SDExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sd_KeypadArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sd_KeypadArg_sequence, hf_index, ett_qsig_sd_KeypadArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_sd_DisplayArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sd_DisplayArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sd_qsig_sd_DisplayArg_PDU);
  return offset;
}
static int dissect_qsig_sd_KeypadArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sd_KeypadArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sd_qsig_sd_KeypadArg_PDU);
  return offset;
}
static int dissect_qsig_sd_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sd_qsig_sd_Extension_PDU);
  return offset;
}


/* --- Module Call-Identification-and-Call-Linkage-Operations-asn1-97 --- --- --- */



static int
dissect_qsig_cidl_SwitchingSubDomainName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_qsig_cidl_SubDomainID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_cidl_GloballyUniqueID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string qsig_cidl_T_linkageID_vals[] = {
  {   1, "subDomainID" },
  {   2, "globallyUniqueID" },
  { 0, NULL }
};

static const ber_choice_t qsig_cidl_T_linkageID_choice[] = {
  {   1, &hf_qsig_cidl_subDomainID, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_cidl_SubDomainID },
  {   2, &hf_qsig_cidl_globallyUniqueID, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_cidl_GloballyUniqueID },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cidl_T_linkageID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cidl_T_linkageID_choice, hf_index, ett_qsig_cidl_T_linkageID,
                                 NULL);

  return offset;
}



static int
dissect_qsig_cidl_TimeStamp(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_cidl_CallIdentificationData_sequence[] = {
  { &hf_qsig_cidl_switchingSubDomainName, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cidl_SwitchingSubDomainName },
  { &hf_qsig_cidl_linkageID , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cidl_T_linkageID },
  { &hf_qsig_cidl_timeStamp , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_cidl_TimeStamp },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cidl_CallIdentificationData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cidl_CallIdentificationData_sequence, hf_index, ett_qsig_cidl_CallIdentificationData);

  return offset;
}


static const ber_sequence_t qsig_cidl_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_cidl_sequenceOfExt_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_cidl_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_cidl_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_cidl_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_cidl_ExtensionType_vals[] = {
  {   3, "extension" },
  {   4, "sequenceOfExt" },
  { 0, NULL }
};

static const ber_choice_t qsig_cidl_ExtensionType_choice[] = {
  {   3, &hf_qsig_cidl_extension , BER_CLASS_CON, 3, 0, dissect_qsig_Extension },
  {   4, &hf_qsig_cidl_sequenceOfExt, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_cidl_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cidl_ExtensionType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cidl_ExtensionType_choice, hf_index, ett_qsig_cidl_ExtensionType,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_cidl_CallIdentificationAssignArg_sequence[] = {
  { &hf_qsig_cidl_globalCallID, BER_CLASS_CON, 0, 0, dissect_qsig_cidl_CallIdentificationData },
  { &hf_qsig_cidl_threadID  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_cidl_CallIdentificationData },
  { &hf_qsig_cidl_legID     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_qsig_cidl_CallIdentificationData },
  { &hf_qsig_cidl_extensiont, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cidl_ExtensionType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cidl_CallIdentificationAssignArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cidl_CallIdentificationAssignArg_sequence, hf_index, ett_qsig_cidl_CallIdentificationAssignArg);

  return offset;
}


static const ber_sequence_t qsig_cidl_CallIdentificationUpdateArg_sequence[] = {
  { &hf_qsig_cidl_globalCallID, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_qsig_cidl_CallIdentificationData },
  { &hf_qsig_cidl_threadID  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_cidl_CallIdentificationData },
  { &hf_qsig_cidl_legID     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_qsig_cidl_CallIdentificationData },
  { &hf_qsig_cidl_extensiont, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_cidl_ExtensionType },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_cidl_CallIdentificationUpdateArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cidl_CallIdentificationUpdateArg_sequence, hf_index, ett_qsig_cidl_CallIdentificationUpdateArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_cidl_CallIdentificationAssignArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cidl_CallIdentificationAssignArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cidl_qsig_cidl_CallIdentificationAssignArg_PDU);
  return offset;
}
static int dissect_qsig_cidl_CallIdentificationUpdateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_cidl_CallIdentificationUpdateArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_cidl_qsig_cidl_CallIdentificationUpdateArg_PDU);
  return offset;
}


/* --- Module Short-Message-Service-Operations-asn1-97 --- --- ---            */



static int
dissect_qsig_sms_MessageReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_ProtocolIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_ValidityPeriodRel(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_ValidityPeriodAbs(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_qsig_sms_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_qsig_sms_INTEGER_0_255(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_ValidityPeriodSemi(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string qsig_sms_EnhancedVP_vals[] = {
  {   0, "validityPeriodRel" },
  {   1, "validityPeriodSec" },
  {   2, "validityPeriodSemi" },
  { 0, NULL }
};

static const ber_choice_t qsig_sms_EnhancedVP_choice[] = {
  {   0, &hf_qsig_sms_validityPeriodRel, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_sms_ValidityPeriodRel },
  {   1, &hf_qsig_sms_validityPeriodSec, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_sms_INTEGER_0_255 },
  {   2, &hf_qsig_sms_validityPeriodSemi, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_sms_ValidityPeriodSemi },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_EnhancedVP(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_sms_EnhancedVP_choice, hf_index, ett_qsig_sms_EnhancedVP,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_ValidityPeriodEnh_sequence[] = {
  { &hf_qsig_sms_singleShotSM, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_sms_BOOLEAN },
  { &hf_qsig_sms_enhancedVP , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_EnhancedVP },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_ValidityPeriodEnh(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_ValidityPeriodEnh_sequence, hf_index, ett_qsig_sms_ValidityPeriodEnh);

  return offset;
}


static const value_string qsig_sms_ValidityPeriod_vals[] = {
  {   0, "validityPeriodRel" },
  {   1, "validityPeriodAbs" },
  {   2, "validityPeriodEnh" },
  { 0, NULL }
};

static const ber_choice_t qsig_sms_ValidityPeriod_choice[] = {
  {   0, &hf_qsig_sms_validityPeriodRel, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_sms_ValidityPeriodRel },
  {   1, &hf_qsig_sms_validityPeriodAbs, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_sms_ValidityPeriodAbs },
  {   2, &hf_qsig_sms_validityPeriodEnh, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_sms_ValidityPeriodEnh },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_ValidityPeriod(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_sms_ValidityPeriod_choice, hf_index, ett_qsig_sms_ValidityPeriod,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_SmSubmitParameter_sequence[] = {
  { &hf_qsig_sms_protocolIdentifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ProtocolIdentifier },
  { &hf_qsig_sms_validityPeriod, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_ValidityPeriod },
  { &hf_qsig_sms_statusReportRequest, BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_BOOLEAN },
  { &hf_qsig_sms_replyPath  , BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_BOOLEAN },
  { &hf_qsig_sms_rejectDuplicates, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_SmSubmitParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmSubmitParameter_sequence, hf_index, ett_qsig_sms_SmSubmitParameter);

  return offset;
}


static const asn_namedbit qsig_sms_SmscControlParameterHeader_bits[] = {
  {  0, &hf_qsig_sms_SmscControlParameterHeader_sRforTransactionCompleted, -1, -1, "sRforTransactionCompleted", NULL },
  {  1, &hf_qsig_sms_SmscControlParameterHeader_sRforPermanentError, -1, -1, "sRforPermanentError", NULL },
  {  2, &hf_qsig_sms_SmscControlParameterHeader_sRforTempErrorSCnotTrying, -1, -1, "sRforTempErrorSCnotTrying", NULL },
  {  3, &hf_qsig_sms_SmscControlParameterHeader_sRforTempErrorSCstillTrying, -1, -1, "sRforTempErrorSCstillTrying", NULL },
  {  6, &hf_qsig_sms_SmscControlParameterHeader_cancelSRRforConcatenatedSM, -1, -1, "cancelSRRforConcatenatedSM", NULL },
  {  7, &hf_qsig_sms_SmscControlParameterHeader_includeOrigUDHintoSR, -1, -1, "includeOrigUDHintoSR", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_qsig_sms_SmscControlParameterHeader(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    qsig_sms_SmscControlParameterHeader_bits, hf_index, ett_qsig_sms_SmscControlParameterHeader,
                                    NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_Concatenated8BitSMHeader_sequence[] = {
  { &hf_qsig_sms_concatenated8BitSMReferenceNumber, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_INTEGER_0_255 },
  { &hf_qsig_sms_maximumNumberOf8BitSMInConcatenatedSM, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_INTEGER_0_255 },
  { &hf_qsig_sms_sequenceNumberOf8BitSM, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_INTEGER_0_255 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_Concatenated8BitSMHeader(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_Concatenated8BitSMHeader_sequence, hf_index, ett_qsig_sms_Concatenated8BitSMHeader);

  return offset;
}



static int
dissect_qsig_sms_INTEGER_0_65536(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_Concatenated16BitSMHeader_sequence[] = {
  { &hf_qsig_sms_concatenated16BitSMReferenceNumber, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_INTEGER_0_65536 },
  { &hf_qsig_sms_maximumNumberOf16BitSMInConcatenatedSM, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_INTEGER_0_255 },
  { &hf_qsig_sms_sequenceNumberOf16BitSM, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_INTEGER_0_255 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_Concatenated16BitSMHeader(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_Concatenated16BitSMHeader_sequence, hf_index, ett_qsig_sms_Concatenated16BitSMHeader);

  return offset;
}


static const ber_sequence_t qsig_sms_ApplicationPort8BitHeader_sequence[] = {
  { &hf_qsig_sms_destination8BitPort, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_INTEGER_0_255 },
  { &hf_qsig_sms_originator8BitPort, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_INTEGER_0_255 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_ApplicationPort8BitHeader(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_ApplicationPort8BitHeader_sequence, hf_index, ett_qsig_sms_ApplicationPort8BitHeader);

  return offset;
}


static const ber_sequence_t qsig_sms_ApplicationPort16BitHeader_sequence[] = {
  { &hf_qsig_sms_destination16BitPort, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_INTEGER_0_65536 },
  { &hf_qsig_sms_originator16BitPort, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_INTEGER_0_65536 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_ApplicationPort16BitHeader(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_ApplicationPort16BitHeader_sequence, hf_index, ett_qsig_sms_ApplicationPort16BitHeader);

  return offset;
}


static const value_string qsig_sms_DataHeaderSourceIndicator_vals[] = {
  {   1, "originalSender" },
  {   2, "originalReceiver" },
  {   3, "sMSC" },
  { 0, NULL }
};


static int
dissect_qsig_sms_DataHeaderSourceIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_WirelessControlHeader(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_sms_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_GenericUserValue_sequence[] = {
  { &hf_qsig_sms_parameterValue, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_INTEGER_0_255 },
  { &hf_qsig_sms_genericUserData, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_OCTET_STRING },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_GenericUserValue(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_GenericUserValue_sequence, hf_index, ett_qsig_sms_GenericUserValue);

  return offset;
}


static const value_string qsig_sms_UserDataHeaderChoice_vals[] = {
  {   0, "smscControlParameterHeader" },
  {   1, "concatenated8BitSMHeader" },
  {   2, "concatenated16BitSMHeader" },
  {   3, "applicationPort8BitHeader" },
  {   4, "applicationPort16BitHeader" },
  {   5, "dataHeaderSourceIndicator" },
  {   6, "wirelessControlHeader" },
  {  99, "genericUserValue" },
  { 0, NULL }
};

static const ber_choice_t qsig_sms_UserDataHeaderChoice_choice[] = {
  {   0, &hf_qsig_sms_smscControlParameterHeader, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_sms_SmscControlParameterHeader },
  {   1, &hf_qsig_sms_concatenated8BitSMHeader, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_sms_Concatenated8BitSMHeader },
  {   2, &hf_qsig_sms_concatenated16BitSMHeader, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_sms_Concatenated16BitSMHeader },
  {   3, &hf_qsig_sms_applicationPort8BitHeader, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_sms_ApplicationPort8BitHeader },
  {   4, &hf_qsig_sms_applicationPort16BitHeader, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_sms_ApplicationPort16BitHeader },
  {   5, &hf_qsig_sms_dataHeaderSourceIndicator, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_qsig_sms_DataHeaderSourceIndicator },
  {   6, &hf_qsig_sms_wirelessControlHeader, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_sms_WirelessControlHeader },
  {  99, &hf_qsig_sms_genericUserValue, BER_CLASS_CON, 99, BER_FLAGS_IMPLTAG, dissect_qsig_sms_GenericUserValue },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_UserDataHeaderChoice(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_sms_UserDataHeaderChoice_choice, hf_index, ett_qsig_sms_UserDataHeaderChoice,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_UserDataHeader_sequence_of[1] = {
  { &hf_qsig_sms_UserDataHeader_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_UserDataHeaderChoice },
};

static int
dissect_qsig_sms_UserDataHeader(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_sms_UserDataHeader_sequence_of, hf_index, ett_qsig_sms_UserDataHeader);

  return offset;
}



static int
dissect_qsig_sms_INTEGER_0_3(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string qsig_sms_ShortMessageTextType_vals[] = {
  {   0, "iA5Coded" },
  {   1, "octetCoded" },
  {   2, "uniCoded" },
  {   3, "compressedCoded" },
  { 0, NULL }
};


static int
dissect_qsig_sms_ShortMessageTextType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_ShortMessageTextData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_ShortMessageText_sequence[] = {
  { &hf_qsig_sms_shortMessageTextType, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ShortMessageTextType },
  { &hf_qsig_sms_shortMessageTextData, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ShortMessageTextData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_ShortMessageText(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_ShortMessageText_sequence, hf_index, ett_qsig_sms_ShortMessageText);

  return offset;
}


static const ber_sequence_t qsig_sms_UserData_sequence[] = {
  { &hf_qsig_sms_userDataHeader, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_UserDataHeader },
  { &hf_qsig_sms_class      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_INTEGER_0_3 },
  { &hf_qsig_sms_compressed , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_BOOLEAN },
  { &hf_qsig_sms_shortMessageText, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ShortMessageText },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_UserData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_UserData_sequence, hf_index, ett_qsig_sms_UserData);

  return offset;
}


static const ber_sequence_t qsig_sms_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_sms_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_sms_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_sms_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_sms_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_sms_SmsExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_sms_SmsExtension_choice[] = {
  {   1, &hf_qsig_sms_single     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_sms_multiple   , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_sms_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_SmsExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_sms_SmsExtension_choice, hf_index, ett_qsig_sms_SmsExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_SmsSubmitArg_sequence[] = {
  { &hf_qsig_sms_destinationAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_sms_originatingAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_sms_messageReference, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_MessageReference },
  { &hf_qsig_sms_smSubmitParameter, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_SmSubmitParameter },
  { &hf_qsig_sms_userData   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_UserData },
  { &hf_qsig_sms_smsExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_SmsExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_SmsSubmitArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmsSubmitArg_sequence, hf_index, ett_qsig_sms_SmsSubmitArg);

  return offset;
}



static int
dissect_qsig_sms_ServiceCentreTimeStamp(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_sms_SmsSubmitRes_sequence[] = {
  { &hf_qsig_sms_serviceCentreTimeStamp, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ServiceCentreTimeStamp },
  { &hf_qsig_sms_protocolIdentifier, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_ProtocolIdentifier },
  { &hf_qsig_sms_userData   , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_UserData },
  { &hf_qsig_sms_smsExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_SmsExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_SmsSubmitRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmsSubmitRes_sequence, hf_index, ett_qsig_sms_SmsSubmitRes);

  return offset;
}


static const ber_sequence_t qsig_sms_SmDeliverParameter_sequence[] = {
  { &hf_qsig_sms_protocolIdentifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ProtocolIdentifier },
  { &hf_qsig_sms_serviceCentreTimeStamp, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ServiceCentreTimeStamp },
  { &hf_qsig_sms_priority   , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_BOOLEAN },
  { &hf_qsig_sms_moreMessagesToSend, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_BOOLEAN },
  { &hf_qsig_sms_statusReportIndication, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_BOOLEAN },
  { &hf_qsig_sms_replyPath  , BER_CLASS_CON, 14, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_SmDeliverParameter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmDeliverParameter_sequence, hf_index, ett_qsig_sms_SmDeliverParameter);

  return offset;
}


static const ber_sequence_t qsig_sms_SmsDeliverArg_sequence[] = {
  { &hf_qsig_sms_originatingAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_sms_destinationAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_sms_originatingName, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_na_Name },
  { &hf_qsig_sms_smDeliverParameter, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_SmDeliverParameter },
  { &hf_qsig_sms_userData   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_UserData },
  { &hf_qsig_sms_smsExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_SmsExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_SmsDeliverArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmsDeliverArg_sequence, hf_index, ett_qsig_sms_SmsDeliverArg);

  return offset;
}



static int
dissect_qsig_sms_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_sms_ResChoiceSeq_sequence[] = {
  { &hf_qsig_sms_protocolIdentifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ProtocolIdentifier },
  { &hf_qsig_sms_userData   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_UserData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_ResChoiceSeq(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_ResChoiceSeq_sequence, hf_index, ett_qsig_sms_ResChoiceSeq);

  return offset;
}


static const value_string qsig_sms_SmsDeliverResChoice_vals[] = {
  {   0, "null" },
  {   1, "protocolIdentifier" },
  {   2, "userData" },
  {   3, "resChoiceSeq" },
  { 0, NULL }
};

static const ber_choice_t qsig_sms_SmsDeliverResChoice_choice[] = {
  {   0, &hf_qsig_sms_null       , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_NULL },
  {   1, &hf_qsig_sms_protocolIdentifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ProtocolIdentifier },
  {   2, &hf_qsig_sms_userData   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_sms_UserData },
  {   3, &hf_qsig_sms_resChoiceSeq, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_sms_ResChoiceSeq },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_SmsDeliverResChoice(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_sms_SmsDeliverResChoice_choice, hf_index, ett_qsig_sms_SmsDeliverResChoice,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_SmsDeliverRes_sequence[] = {
  { &hf_qsig_sms_smsDeliverResponseChoice, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_SmsDeliverResChoice },
  { &hf_qsig_sms_smsExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_SmsExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_SmsDeliverRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmsDeliverRes_sequence, hf_index, ett_qsig_sms_SmsDeliverRes);

  return offset;
}



static int
dissect_qsig_sms_DischargeTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_qsig_sms_Status(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_SmsStatusReportArg_sequence[] = {
  { &hf_qsig_sms_messageReference, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_MessageReference },
  { &hf_qsig_sms_serviceCentreTimeStamp, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ServiceCentreTimeStamp },
  { &hf_qsig_sms_dischargeTime, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_DischargeTime },
  { &hf_qsig_sms_recipientAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_sms_recipientName, BER_CLASS_CON, 10, BER_FLAGS_OPTIONAL, dissect_qsig_na_Name },
  { &hf_qsig_sms_destinationAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_sms_status     , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_Status },
  { &hf_qsig_sms_priority   , BER_CLASS_CON, 11, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_BOOLEAN },
  { &hf_qsig_sms_moreMessagesToSend, BER_CLASS_CON, 12, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_BOOLEAN },
  { &hf_qsig_sms_statusReportQualifier, BER_CLASS_CON, 13, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_BOOLEAN },
  { &hf_qsig_sms_protocolIdentifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ProtocolIdentifier },
  { &hf_qsig_sms_userData   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_sms_UserData },
  { &hf_qsig_sms_smsExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_SmsExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_SmsStatusReportArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmsStatusReportArg_sequence, hf_index, ett_qsig_sms_SmsStatusReportArg);

  return offset;
}


static const value_string qsig_sms_SmsStatusReportResponseChoice_vals[] = {
  {   0, "null" },
  {   1, "protocolIdentifier" },
  {   2, "userData" },
  {   3, "resChoiceSeq" },
  { 0, NULL }
};

static const ber_choice_t qsig_sms_SmsStatusReportResponseChoice_choice[] = {
  {   0, &hf_qsig_sms_null       , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_NULL },
  {   1, &hf_qsig_sms_protocolIdentifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ProtocolIdentifier },
  {   2, &hf_qsig_sms_userData   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_sms_UserData },
  {   3, &hf_qsig_sms_resChoiceSeq, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_sms_ResChoiceSeq },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_SmsStatusReportResponseChoice(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_sms_SmsStatusReportResponseChoice_choice, hf_index, ett_qsig_sms_SmsStatusReportResponseChoice,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_SmsStatusReportRes_sequence[] = {
  { &hf_qsig_sms_smsStatusReportResponseChoice, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_SmsStatusReportResponseChoice },
  { &hf_qsig_sms_smsExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_SmsExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_SmsStatusReportRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmsStatusReportRes_sequence, hf_index, ett_qsig_sms_SmsStatusReportRes);

  return offset;
}


static const value_string qsig_sms_CommandType_vals[] = {
  {   0, "enquiry" },
  {   1, "cancelSRR" },
  {   2, "deletePreviouslySubmittedSM" },
  {   3, "enableSRRrelatingToPreviouslySubmittedSM" },
  { 0, NULL }
};


static int
dissect_qsig_sms_CommandType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_CommandData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_SmsCommandArg_sequence[] = {
  { &hf_qsig_sms_destinationAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_sms_messageReference, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_MessageReference },
  { &hf_qsig_sms_messageNumber, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_MessageReference },
  { &hf_qsig_sms_protocolIdentifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ProtocolIdentifier },
  { &hf_qsig_sms_commandType, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_CommandType },
  { &hf_qsig_sms_commandData, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_sms_CommandData },
  { &hf_qsig_sms_statusReportRequest, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_sms_BOOLEAN },
  { &hf_qsig_sms_smsExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_SmsExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_SmsCommandArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmsCommandArg_sequence, hf_index, ett_qsig_sms_SmsCommandArg);

  return offset;
}


static const ber_sequence_t qsig_sms_SmsCommandRes_sequence[] = {
  { &hf_qsig_sms_serviceCentreTimeStamp, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ServiceCentreTimeStamp },
  { &hf_qsig_sms_protocolIdentifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ProtocolIdentifier },
  { &hf_qsig_sms_userData   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_sms_UserData },
  { &hf_qsig_sms_smsExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_SmsExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_SmsCommandRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmsCommandRes_sequence, hf_index, ett_qsig_sms_SmsCommandRes);

  return offset;
}


static const ber_sequence_t qsig_sms_ScAlertArg_sequence[] = {
  { &hf_qsig_sms_originatingAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_sms_smsExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_SmsExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_ScAlertArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_ScAlertArg_sequence, hf_index, ett_qsig_sms_ScAlertArg);

  return offset;
}


static const value_string qsig_sms_DummyRes_vals[] = {
  {   0, "null" },
  {   1, "smsExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_sms_DummyRes_choice[] = {
  {   0, &hf_qsig_sms_null       , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_NULL },
  {   1, &hf_qsig_sms_smsExtension, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_SmsExtension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_DummyRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_sms_DummyRes_choice, hf_index, ett_qsig_sms_DummyRes,
                                 NULL);

  return offset;
}



static int
dissect_qsig_sms_FailureCause(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_PAR_smsDeliverError_sequence[] = {
  { &hf_qsig_sms_failureCause, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_FailureCause },
  { &hf_qsig_sms_protocolIdentifier, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_ProtocolIdentifier },
  { &hf_qsig_sms_userData   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_UserData },
  { &hf_qsig_sms_scAddressSaved, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_PAR_smsDeliverError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_PAR_smsDeliverError_sequence, hf_index, ett_qsig_sms_PAR_smsDeliverError);

  return offset;
}


static const ber_sequence_t qsig_sms_PAR_smsSubmitError_sequence[] = {
  { &hf_qsig_sms_failureCause, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_FailureCause },
  { &hf_qsig_sms_serviceCentreTimeStamp, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ServiceCentreTimeStamp },
  { &hf_qsig_sms_protocolIdentifier, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_ProtocolIdentifier },
  { &hf_qsig_sms_userData   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_UserData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_PAR_smsSubmitError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_PAR_smsSubmitError_sequence, hf_index, ett_qsig_sms_PAR_smsSubmitError);

  return offset;
}


static const ber_sequence_t qsig_sms_PAR_smsStatusReportError_sequence[] = {
  { &hf_qsig_sms_failureCause, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_FailureCause },
  { &hf_qsig_sms_protocolIdentifier, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_ProtocolIdentifier },
  { &hf_qsig_sms_userData   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_UserData },
  { &hf_qsig_sms_scAddressSaved, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_PAR_smsStatusReportError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_PAR_smsStatusReportError_sequence, hf_index, ett_qsig_sms_PAR_smsStatusReportError);

  return offset;
}


static const ber_sequence_t qsig_sms_PAR_smsCommandError_sequence[] = {
  { &hf_qsig_sms_failureCause, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_FailureCause },
  { &hf_qsig_sms_serviceCentreTimeStamp, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ServiceCentreTimeStamp },
  { &hf_qsig_sms_protocolIdentifier, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_ProtocolIdentifier },
  { &hf_qsig_sms_userData   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_sms_UserData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_PAR_smsCommandError(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_PAR_smsCommandError_sequence, hf_index, ett_qsig_sms_PAR_smsCommandError);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_sms_SmsSubmitArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_SmsSubmitArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsSubmitArg_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsSubmitRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_SmsSubmitRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsSubmitRes_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsDeliverArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_SmsDeliverArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsDeliverArg_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsDeliverRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_SmsDeliverRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsDeliverRes_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsStatusReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_SmsStatusReportArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsStatusReportArg_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsStatusReportRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_SmsStatusReportRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsStatusReportRes_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsCommandArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_SmsCommandArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsCommandArg_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsCommandRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_SmsCommandRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsCommandRes_PDU);
  return offset;
}
static int dissect_qsig_sms_ScAlertArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_ScAlertArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_ScAlertArg_PDU);
  return offset;
}
static int dissect_qsig_sms_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_DummyRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_sms_PAR_smsDeliverError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_PAR_smsDeliverError(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_PAR_smsDeliverError_PDU);
  return offset;
}
static int dissect_qsig_sms_PAR_smsSubmitError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_PAR_smsSubmitError(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_PAR_smsSubmitError_PDU);
  return offset;
}
static int dissect_qsig_sms_PAR_smsStatusReportError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_PAR_smsStatusReportError(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_PAR_smsStatusReportError_PDU);
  return offset;
}
static int dissect_qsig_sms_PAR_smsCommandError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_PAR_smsCommandError(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_PAR_smsCommandError_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsExtension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_sms_SmsExtension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsExtension_PDU);
  return offset;
}


/* --- Module SS-MCR-Operations-asn97 --- --- ---                             */



static int
dissect_qsig_mcr_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string qsig_mcr_CallType_vals[] = {
  {   0, "basicService" },
  {   1, "cisc" },
  { 0, NULL }
};

static const ber_choice_t qsig_mcr_CallType_choice[] = {
  {   0, &hf_qsig_mcr_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_BasicService },
  {   1, &hf_qsig_mcr_cisc       , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_mcr_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcr_CallType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mcr_CallType_choice, hf_index, ett_qsig_mcr_CallType,
                                 NULL);

  return offset;
}



static int
dissect_qsig_mcr_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string qsig_mcr_CorrelationReason_vals[] = {
  {   0, "unknown" },
  {   1, "mCACommunication" },
  {   2, "cTIApplication" },
  { 0, NULL }
};


static int
dissect_qsig_mcr_CorrelationReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_mcr_Correlation_sequence[] = {
  { &hf_qsig_mcr_correlationData, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_qsig_pr_CallIdentity },
  { &hf_qsig_mcr_correlationReason, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_mcr_CorrelationReason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcr_Correlation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcr_Correlation_sequence, hf_index, ett_qsig_mcr_Correlation);

  return offset;
}


static const ber_sequence_t qsig_mcr_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_mcr_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_mcr_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_mcr_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_mcr_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_mcr_MCRExtensions_vals[] = {
  {   0, "none" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t qsig_mcr_MCRExtensions_choice[] = {
  {   0, &hf_qsig_mcr_none       , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_mcr_NULL },
  {   1, &hf_qsig_mcr_single     , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_mcr_multiple   , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_mcr_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcr_MCRExtensions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mcr_MCRExtensions_choice, hf_index, ett_qsig_mcr_MCRExtensions,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_mcr_MCRequestArg_sequence[] = {
  { &hf_qsig_mcr_callType   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcr_CallType },
  { &hf_qsig_mcr_retainOrigCall, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_mcr_BOOLEAN },
  { &hf_qsig_mcr_destinationAddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PresentedAddressUnscreened },
  { &hf_qsig_mcr_requestingAddress, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_qsig_PresentedAddressUnscreened },
  { &hf_qsig_mcr_cooperatingAddress, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_PresentedAddressUnscreened },
  { &hf_qsig_mcr_correlation, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcr_Correlation },
  { &hf_qsig_mcr_extensions , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcr_MCRExtensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcr_MCRequestArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcr_MCRequestArg_sequence, hf_index, ett_qsig_mcr_MCRequestArg);

  return offset;
}


static const ber_sequence_t qsig_mcr_MCRequestResult_sequence[] = {
  { &hf_qsig_mcr_extensions , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcr_MCRExtensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcr_MCRequestResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcr_MCRequestResult_sequence, hf_index, ett_qsig_mcr_MCRequestResult);

  return offset;
}


static const ber_sequence_t qsig_mcr_MCInformArg_sequence[] = {
  { &hf_qsig_mcr_requestingAddress, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_qsig_PresentedAddressUnscreened },
  { &hf_qsig_mcr_cooperatingAddress, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_qsig_PresentedAddressUnscreened },
  { &hf_qsig_mcr_correlation, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcr_Correlation },
  { &hf_qsig_mcr_extensions , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcr_MCRExtensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcr_MCInformArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcr_MCInformArg_sequence, hf_index, ett_qsig_mcr_MCInformArg);

  return offset;
}


static const ber_sequence_t qsig_mcr_MCAlertingArg_sequence[] = {
  { &hf_qsig_mcr_correlation, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcr_Correlation },
  { &hf_qsig_mcr_extensions , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcr_MCRExtensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcr_MCAlertingArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcr_MCAlertingArg_sequence, hf_index, ett_qsig_mcr_MCAlertingArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_mcr_MCRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcr_MCRequestArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcr_qsig_mcr_MCRequestArg_PDU);
  return offset;
}
static int dissect_qsig_mcr_MCRequestResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcr_MCRequestResult(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcr_qsig_mcr_MCRequestResult_PDU);
  return offset;
}
static int dissect_qsig_mcr_MCInformArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcr_MCInformArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcr_qsig_mcr_MCInformArg_PDU);
  return offset;
}
static int dissect_qsig_mcr_MCAlertingArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcr_MCAlertingArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcr_qsig_mcr_MCAlertingArg_PDU);
  return offset;
}
static int dissect_qsig_mcr_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcr_qsig_mcr_Extension_PDU);
  return offset;
}


/* --- Module SS-MCM-Operations-asn1-97 --- --- ---                           */



static int
dissect_qsig_mcm_INTEGER_0_65535(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_mcm_NumericString_SIZE_1_10(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string qsig_mcm_MsgCentreId_vals[] = {
  {   0, "integer" },
  {   1, "partyNumber" },
  {   2, "numericString" },
  { 0, NULL }
};

static const ber_choice_t qsig_mcm_MsgCentreId_choice[] = {
  {   0, &hf_qsig_mcm_integer    , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_mcm_INTEGER_0_65535 },
  {   1, &hf_qsig_mcm_partyNumber, BER_CLASS_CON, 1, 0, dissect_qsig_PartyNumber },
  {   2, &hf_qsig_mcm_numericString, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_mcm_NumericString_SIZE_1_10 },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MsgCentreId(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mcm_MsgCentreId_choice, hf_index, ett_qsig_mcm_MsgCentreId,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_mcm_PartyInfo_sequence[] = {
  { &hf_qsig_mcm_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_mcm_messageCentreID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MsgCentreId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_PartyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_PartyInfo_sequence, hf_index, ett_qsig_mcm_PartyInfo);

  return offset;
}


static const value_string qsig_mcm_MessageType_vals[] = {
  {   0, "allServices" },
  {   1, "speech" },
  {   2, "unrestrictedDigitalInformation" },
  {   3, "audio3100Hz" },
  {  32, "telephony" },
  {  33, "teletex" },
  {  34, "telefaxGroup4Class1" },
  {  35, "videotextSyntaxBased" },
  {  36, "videotelephony" },
  {  37, "telefaxGroup2-3" },
  {  38, "reservedNotUsed1" },
  {  39, "reservedNotUsed2" },
  {  40, "reservedNotUsed3" },
  {  41, "reservedNotUsed4" },
  {  42, "reservedNotUsed5" },
  {  51, "email" },
  {  52, "video" },
  {  53, "fileTransfer" },
  {  54, "shortMessageService" },
  {  55, "speechAndVideo" },
  {  56, "speechAndFax" },
  {  57, "speechAndEmail" },
  {  58, "videoAndFax" },
  {  59, "videoAndEmail" },
  {  60, "faxAndEmail" },
  {  61, "speechVideoAndFax" },
  {  62, "speechVideoAndEmail" },
  {  63, "speechFaxAndEmail" },
  {  64, "videoFaxAndEmail" },
  {  65, "speechVideoFaxAndEmail" },
  {  66, "multimediaUnknown" },
  {  67, "serviceUnknown" },
  {  68, "futureReserve1" },
  {  69, "futureReserve2" },
  {  70, "futureReserve3" },
  {  71, "futureReserve4" },
  {  72, "futureReserve5" },
  {  73, "futureReserve6" },
  {  74, "futureReserve7" },
  {  75, "futureReserve8" },
  { 0, NULL }
};


static int
dissect_qsig_mcm_MessageType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_qsig_mcm_INTEGER_0_100(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_mcm_MailboxFullPar_sequence[] = {
  { &hf_qsig_mcm_messageType, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MessageType },
  { &hf_qsig_mcm_capacityReached, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_INTEGER_0_100 },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MailboxFullPar(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MailboxFullPar_sequence, hf_index, ett_qsig_mcm_MailboxFullPar);

  return offset;
}


static const ber_sequence_t qsig_mcm_MailboxFullFor_sequence_of[1] = {
  { &hf_qsig_mcm_MailboxFullFor_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MailboxFullPar },
};

static int
dissect_qsig_mcm_MailboxFullFor(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_mcm_MailboxFullFor_sequence_of, hf_index, ett_qsig_mcm_MailboxFullFor);

  return offset;
}



static int
dissect_qsig_mcm_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_mcm_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_mcm_multipleExtension_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_mcm_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_mcm_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_mcm_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_mcm_MCMExtensions_vals[] = {
  {   0, "none" },
  {   1, "extension" },
  {   2, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_mcm_MCMExtensions_choice[] = {
  {   0, &hf_qsig_mcm_none       , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_NULL },
  {   1, &hf_qsig_mcm_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_mcm_multipleExtension, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_mcm_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMExtensions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mcm_MCMExtensions_choice, hf_index, ett_qsig_mcm_MCMExtensions,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_mcm_MCMailboxFullArg_sequence[] = {
  { &hf_qsig_mcm_partyInfo  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_PartyInfo },
  { &hf_qsig_mcm_mailboxFullFor, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MailboxFullFor },
  { &hf_qsig_mcm_extensions , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MCMExtensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMailboxFullArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMailboxFullArg_sequence, hf_index, ett_qsig_mcm_MCMailboxFullArg);

  return offset;
}


static const value_string qsig_mcm_MCMMode_vals[] = {
  {   0, "compressed" },
  {   1, "complete" },
  { 0, NULL }
};


static int
dissect_qsig_mcm_MCMMode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_mcm_MCMServiceInfo_sequence[] = {
  { &hf_qsig_mcm_messageType, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MessageType },
  { &hf_qsig_mcm_mCMModeNew , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_mcm_MCMMode },
  { &hf_qsig_mcm_mCMModeRetrieved, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_mcm_MCMMode },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMServiceInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMServiceInfo_sequence, hf_index, ett_qsig_mcm_MCMServiceInfo);

  return offset;
}


static const ber_sequence_t qsig_mcm_SEQUENCE_OF_MCMServiceInfo_sequence_of[1] = {
  { &hf_qsig_mcm_activateMCM_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MCMServiceInfo },
};

static int
dissect_qsig_mcm_SEQUENCE_OF_MCMServiceInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_mcm_SEQUENCE_OF_MCMServiceInfo_sequence_of, hf_index, ett_qsig_mcm_SEQUENCE_OF_MCMServiceInfo);

  return offset;
}


static const ber_sequence_t qsig_mcm_SEQUENCE_OF_MessageType_sequence_of[1] = {
  { &hf_qsig_mcm_deactivateMCM_item, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MessageType },
};

static int
dissect_qsig_mcm_SEQUENCE_OF_MessageType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_mcm_SEQUENCE_OF_MessageType_sequence_of, hf_index, ett_qsig_mcm_SEQUENCE_OF_MessageType);

  return offset;
}


static const value_string qsig_mcm_MCMChange_vals[] = {
  {   0, "activateMCM" },
  {   1, "deactivateMCM" },
  {   2, "setToDefaultValues" },
  { 0, NULL }
};

static const ber_choice_t qsig_mcm_MCMChange_choice[] = {
  {   0, &hf_qsig_mcm_activateMCM, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_mcm_SEQUENCE_OF_MCMServiceInfo },
  {   1, &hf_qsig_mcm_deactivateMCM, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_mcm_SEQUENCE_OF_MessageType },
  {   2, &hf_qsig_mcm_setToDefaultValues, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMChange(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mcm_MCMChange_choice, hf_index, ett_qsig_mcm_MCMChange,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_mcm_MCMServiceArg_sequence[] = {
  { &hf_qsig_mcm_partyInfo  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_PartyInfo },
  { &hf_qsig_mcm_mCMChange  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MCMChange },
  { &hf_qsig_mcm_extensions , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MCMExtensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMServiceArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMServiceArg_sequence, hf_index, ett_qsig_mcm_MCMServiceArg);

  return offset;
}


static const ber_sequence_t qsig_mcm_MCMInterrogateArg_sequence[] = {
  { &hf_qsig_mcm_partyInfo  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_PartyInfo },
  { &hf_qsig_mcm_interrogateInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_SEQUENCE_OF_MessageType },
  { &hf_qsig_mcm_extensions , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MCMExtensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMInterrogateArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMInterrogateArg_sequence, hf_index, ett_qsig_mcm_MCMInterrogateArg);

  return offset;
}


static const ber_sequence_t qsig_mcm_MCMInterrogateRes_sequence[] = {
  { &hf_qsig_mcm_interrogateResult, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_SEQUENCE_OF_MCMServiceInfo },
  { &hf_qsig_mcm_extensions , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MCMExtensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMInterrogateRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMInterrogateRes_sequence, hf_index, ett_qsig_mcm_MCMInterrogateRes);

  return offset;
}



static int
dissect_qsig_mcm_NrOfMessages(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_mcm_TimeStamp(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_qsig_mcm_INTEGER_0_9(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string qsig_mcm_MCMNewArgumentExt_vals[] = {
  {   6, "extension" },
  {   7, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_mcm_MCMNewArgumentExt_choice[] = {
  {   6, &hf_qsig_mcm_extension  , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   7, &hf_qsig_mcm_multipleExtension, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_qsig_mcm_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMNewArgumentExt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mcm_MCMNewArgumentExt_choice, hf_index, ett_qsig_mcm_MCMNewArgumentExt,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_mcm_MCMNewMsgArg_sequence[] = {
  { &hf_qsig_mcm_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_mcm_specificMessageType, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MessageType },
  { &hf_qsig_mcm_msgCentreId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MsgCentreId },
  { &hf_qsig_mcm_nrOfMessages, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_mcm_NrOfMessages },
  { &hf_qsig_mcm_originatingNr, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_qsig_PartyNumber },
  { &hf_qsig_mcm_timestamp  , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_TimeStamp },
  { &hf_qsig_mcm_priority   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_mcm_INTEGER_0_9 },
  { &hf_qsig_mcm_argumentExtMCMNew, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MCMNewArgumentExt },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMNewMsgArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMNewMsgArg_sequence, hf_index, ett_qsig_mcm_MCMNewMsgArg);

  return offset;
}


static const value_string qsig_mcm_MCMNoNewArgumentExt_vals[] = {
  {   3, "extension" },
  {   4, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_mcm_MCMNoNewArgumentExt_choice[] = {
  {   3, &hf_qsig_mcm_extension  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   4, &hf_qsig_mcm_multipleExtension, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_mcm_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMNoNewArgumentExt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mcm_MCMNoNewArgumentExt_choice, hf_index, ett_qsig_mcm_MCMNoNewArgumentExt,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_mcm_MCMNoNewMsgArg_sequence[] = {
  { &hf_qsig_mcm_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_mcm_specificMessageType, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MessageType },
  { &hf_qsig_mcm_msgCentreId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MsgCentreId },
  { &hf_qsig_mcm_argumentExtMCMNoNew, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MCMNoNewArgumentExt },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMNoNewMsgArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMNoNewMsgArg_sequence, hf_index, ett_qsig_mcm_MCMNoNewMsgArg);

  return offset;
}



static int
dissect_qsig_mcm_Priority(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_mcm_AddressHeader_sequence[] = {
  { &hf_qsig_mcm_originatorNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_mcm_timeStamp  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_mcm_TimeStamp },
  { &hf_qsig_mcm_ahpriority , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_mcm_Priority },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_AddressHeader(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_AddressHeader_sequence, hf_index, ett_qsig_mcm_AddressHeader);

  return offset;
}


static const ber_sequence_t qsig_mcm_CompleteInfo_sequence_of[1] = {
  { &hf_qsig_mcm_CompleteInfo_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_AddressHeader },
};

static int
dissect_qsig_mcm_CompleteInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_mcm_CompleteInfo_sequence_of, hf_index, ett_qsig_mcm_CompleteInfo);

  return offset;
}


static const ber_sequence_t qsig_mcm_CompressedInfo_sequence[] = {
  { &hf_qsig_mcm_nrOfMessages, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_NrOfMessages },
  { &hf_qsig_mcm_lastTimeStamp, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_TimeStamp },
  { &hf_qsig_mcm_highestPriority, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_Priority },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_CompressedInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_CompressedInfo_sequence, hf_index, ett_qsig_mcm_CompressedInfo);

  return offset;
}


static const value_string qsig_mcm_MessageInfo_vals[] = {
  {   0, "completeInfo" },
  {   1, "compressedInfo" },
  {   2, "noMsgsOfMsgType" },
  { 0, NULL }
};

static const ber_choice_t qsig_mcm_MessageInfo_choice[] = {
  {   0, &hf_qsig_mcm_completeInfo, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_mcm_CompleteInfo },
  {   1, &hf_qsig_mcm_compressedInfo, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_mcm_CompressedInfo },
  {   2, &hf_qsig_mcm_noMsgsOfMsgType, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MessageInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mcm_MessageInfo_choice, hf_index, ett_qsig_mcm_MessageInfo,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_mcm_AllMsgInfo_sequence[] = {
  { &hf_qsig_mcm_newMsgInfo , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MessageInfo },
  { &hf_qsig_mcm_retrievedMsgInfo, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MessageInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_AllMsgInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_AllMsgInfo_sequence, hf_index, ett_qsig_mcm_AllMsgInfo);

  return offset;
}


static const value_string qsig_mcm_UpdateInfo_vals[] = {
  {   0, "newMsgInfoOnly" },
  {   1, "retrievedMsgInfoOnly" },
  {   2, "allMsgInfo" },
  { 0, NULL }
};

static const ber_choice_t qsig_mcm_UpdateInfo_choice[] = {
  {   0, &hf_qsig_mcm_newMsgInfoOnly, BER_CLASS_CON, 1, 0, dissect_qsig_mcm_MessageInfo },
  {   1, &hf_qsig_mcm_retrievedMsgInfoOnly, BER_CLASS_CON, 2, 0, dissect_qsig_mcm_MessageInfo },
  {   2, &hf_qsig_mcm_allMsgInfo , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_AllMsgInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_UpdateInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mcm_UpdateInfo_choice, hf_index, ett_qsig_mcm_UpdateInfo,
                                 NULL);

  return offset;
}



static int
dissect_qsig_mcm_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t qsig_mcm_MCMUpdateArg_sequence[] = {
  { &hf_qsig_mcm_partyInfo  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_PartyInfo },
  { &hf_qsig_mcm_messageType, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MessageType },
  { &hf_qsig_mcm_updateInfo , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_UpdateInfo },
  { &hf_qsig_mcm_moreInfoFollows, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_BOOLEAN },
  { &hf_qsig_mcm_extensions , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MCMExtensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMUpdateArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMUpdateArg_sequence, hf_index, ett_qsig_mcm_MCMUpdateArg);

  return offset;
}


static const value_string qsig_mcm_MCMUpdArgArgumentExt_vals[] = {
  {   3, "extension" },
  {   4, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_mcm_MCMUpdArgArgumentExt_choice[] = {
  {   3, &hf_qsig_mcm_extension  , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   4, &hf_qsig_mcm_multipleExtension, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_qsig_mcm_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMUpdArgArgumentExt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mcm_MCMUpdArgArgumentExt_choice, hf_index, ett_qsig_mcm_MCMUpdArgArgumentExt,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_mcm_MCMUpdateReqArg_sequence[] = {
  { &hf_qsig_mcm_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_mcm_specificMessageType, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MessageType },
  { &hf_qsig_mcm_msgCentreId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MsgCentreId },
  { &hf_qsig_mcm_argumentExtMCMUpdArg, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MCMUpdArgArgumentExt },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMUpdateReqArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMUpdateReqArg_sequence, hf_index, ett_qsig_mcm_MCMUpdateReqArg);

  return offset;
}


static const value_string qsig_mcm_MCMUpdResArgumentExt_vals[] = {
  {   6, "extension" },
  {   7, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_mcm_MCMUpdResArgumentExt_choice[] = {
  {   6, &hf_qsig_mcm_extension  , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   7, &hf_qsig_mcm_multipleExtension, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_qsig_mcm_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMUpdResArgumentExt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mcm_MCMUpdResArgumentExt_choice, hf_index, ett_qsig_mcm_MCMUpdResArgumentExt,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_mcm_MCMUpdateReqResElt_sequence[] = {
  { &hf_qsig_mcm_specificMessageType, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MessageType },
  { &hf_qsig_mcm_msgCentreId, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MsgCentreId },
  { &hf_qsig_mcm_nrOfMessages, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_mcm_NrOfMessages },
  { &hf_qsig_mcm_originatingNr, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_qsig_PartyNumber },
  { &hf_qsig_mcm_timestamp  , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_TimeStamp },
  { &hf_qsig_mcm_priority   , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_mcm_INTEGER_0_9 },
  { &hf_qsig_mcm_argumentExtMCMUpdRes, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcm_MCMUpdResArgumentExt },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcm_MCMUpdateReqResElt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMUpdateReqResElt_sequence, hf_index, ett_qsig_mcm_MCMUpdateReqResElt);

  return offset;
}


static const ber_sequence_t qsig_mcm_MCMUpdateReqRes_sequence_of[1] = {
  { &hf_qsig_mcm_MCMUpdateReqRes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MCMUpdateReqResElt },
};

static int
dissect_qsig_mcm_MCMUpdateReqRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_mcm_MCMUpdateReqRes_sequence_of, hf_index, ett_qsig_mcm_MCMUpdateReqRes);

  return offset;
}



static int
dissect_qsig_mcm_MCMDummyRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_qsig_mcm_MCMExtensions(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_mcm_MCMNewMsgArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcm_MCMNewMsgArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMNewMsgArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMDummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcm_MCMDummyRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMDummyRes_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMNoNewMsgArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcm_MCMNoNewMsgArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMNoNewMsgArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMUpdateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcm_MCMUpdateArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMUpdateArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMUpdateReqArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcm_MCMUpdateReqArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMUpdateReqArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMUpdateReqRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcm_MCMUpdateReqRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMUpdateReqRes_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMServiceArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcm_MCMServiceArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMServiceArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMInterrogateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcm_MCMInterrogateArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMInterrogateArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMInterrogateRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcm_MCMInterrogateRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMInterrogateRes_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMailboxFullArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mcm_MCMailboxFullArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMailboxFullArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_Extension_PDU);
  return offset;
}


/* --- Module SS-MID-Operations-asn1-97 --- --- ---                           */


static const ber_sequence_t qsig_mid_PartyInfo_sequence[] = {
  { &hf_qsig_mid_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_PresentedAddressUnscreened },
  { &hf_qsig_mid_messageType, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MessageType },
  { &hf_qsig_mid_messageCentreID, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MsgCentreId },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mid_PartyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mid_PartyInfo_sequence, hf_index, ett_qsig_mid_PartyInfo);

  return offset;
}



static int
dissect_qsig_mid_BMPString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_BMPString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_qsig_mid_UTF8String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string qsig_mid_String_vals[] = {
  {   0, "stringBmp" },
  {   1, "stringUtf8" },
  { 0, NULL }
};

static const ber_choice_t qsig_mid_String_choice[] = {
  {   0, &hf_qsig_mid_stringBmp  , BER_CLASS_UNI, BER_UNI_TAG_BMPString, BER_FLAGS_NOOWNTAG, dissect_qsig_mid_BMPString },
  {   1, &hf_qsig_mid_stringUtf8 , BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_qsig_mid_UTF8String },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mid_String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mid_String_choice, hf_index, ett_qsig_mid_String,
                                 NULL);

  return offset;
}



static int
dissect_qsig_mid_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_mid_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_mid_multipleExtension_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_mid_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_mid_SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_mid_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_mid_MIDExtensions_vals[] = {
  {   0, "none" },
  {   1, "extension" },
  {   2, "multipleExtension" },
  { 0, NULL }
};

static const ber_choice_t qsig_mid_MIDExtensions_choice[] = {
  {   0, &hf_qsig_mid_none       , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_mid_NULL },
  {   1, &hf_qsig_mid_extension  , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_mid_multipleExtension, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_mid_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mid_MIDExtensions(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mid_MIDExtensions_choice, hf_index, ett_qsig_mid_MIDExtensions,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_mid_MIDMailboxAuthArg_sequence[] = {
  { &hf_qsig_mid_partyInfo  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mid_PartyInfo },
  { &hf_qsig_mid_servedUserName, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_na_Name },
  { &hf_qsig_mid_mailBox    , BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_qsig_mid_String },
  { &hf_qsig_mid_password   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mid_String },
  { &hf_qsig_mid_extensions , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mid_MIDExtensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mid_MIDMailboxAuthArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mid_MIDMailboxAuthArg_sequence, hf_index, ett_qsig_mid_MIDMailboxAuthArg);

  return offset;
}


static const ber_sequence_t qsig_mid_MIDMailboxIDArg_sequence[] = {
  { &hf_qsig_mid_partyInfo  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mid_PartyInfo },
  { &hf_qsig_mid_servedUserName, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_na_Name },
  { &hf_qsig_mid_mailBox    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mid_String },
  { &hf_qsig_mid_extensions , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mid_MIDExtensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mid_MIDMailboxIDArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mid_MIDMailboxIDArg_sequence, hf_index, ett_qsig_mid_MIDMailboxIDArg);

  return offset;
}



static int
dissect_qsig_mid_MIDDummyRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_qsig_mid_MIDExtensions(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_mid_MIDMailboxAuthArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mid_MIDMailboxAuthArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mid_qsig_mid_MIDMailboxAuthArg_PDU);
  return offset;
}
static int dissect_qsig_mid_MIDDummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mid_MIDDummyRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mid_qsig_mid_MIDDummyRes_PDU);
  return offset;
}
static int dissect_qsig_mid_MIDMailboxIDArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_mid_MIDMailboxIDArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mid_qsig_mid_MIDMailboxIDArg_PDU);
  return offset;
}
static int dissect_qsig_mid_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_Extension(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_mid_qsig_mid_Extension_PDU);
  return offset;
}


/*--- End of included file: packet-qsig-fn.c ---*/
#line 325 "../../asn1/qsig/packet-qsig-template.c"

typedef struct _qsig_op_t {
  gint32 opcode;
  new_dissector_t arg_pdu;
  new_dissector_t res_pdu;
} qsig_op_t;

static const qsig_op_t qsig_op_tab[] = {

/*--- Included file: packet-qsig-table11.c ---*/
#line 1 "../../asn1/qsig/packet-qsig-table11.c"

/* --- Module General-Error-List --- --- ---                                  */

/* Unknown or empty loop list OPERATION */

/* --- Modules Manufacturer-specific-service-extension-class-asn1-97 PSS1-generic-parameters-definition-asn1-97 Addressing-Data-Elements-asn1-97 --- --- --- */

/* Unknown or empty loop list OPERATION */

/* --- Module Name-Operations-asn1-97 --- --- ---                             */

  /* callingName              */ {   0, dissect_qsig_na_NameArg_PDU, NULL },
  /* calledName               */ {   1, dissect_qsig_na_NameArg_PDU, NULL },
  /* connectedName            */ {   2, dissect_qsig_na_NameArg_PDU, NULL },
  /* busyName                 */ {   3, dissect_qsig_na_NameArg_PDU, NULL },

/* --- Module Call-Diversion-Operations-asn1-97 --- --- ---                   */

  /* activateDiversionQ       */ {  15, dissect_qsig_cf_ARG_activateDiversionQ_PDU, dissect_qsig_cf_RES_activateDiversionQ_PDU },
  /* deactivateDiversionQ     */ {  16, dissect_qsig_cf_ARG_deactivateDiversionQ_PDU, dissect_qsig_cf_RES_deactivateDiversionQ_PDU },
  /* interrogateDiversionQ    */ {  17, dissect_qsig_cf_ARG_interrogateDiversionQ_PDU, dissect_qsig_cf_IntResultList_PDU },
  /* checkRestriction         */ {  18, dissect_qsig_cf_ARG_checkRestriction_PDU, dissect_qsig_cf_RES_checkRestriction_PDU },
  /* callRerouteing           */ {  19, dissect_qsig_cf_ARG_callRerouteing_PDU, dissect_qsig_cf_RES_callRerouteing_PDU },
  /* divertingLegInformation1 */ {  20, dissect_qsig_cf_ARG_divertingLegInformation1_PDU, NULL },
  /* divertingLegInformation2 */ {  21, dissect_qsig_cf_ARG_divertingLegInformation2_PDU, NULL },
  /* divertingLegInformation3 */ {  22, dissect_qsig_cf_ARG_divertingLegInformation3_PDU, NULL },
  /* cfnrDivertedLegFailed    */ {  23, dissect_qsig_cf_ARG_cfnrDivertedLegFailed_PDU, NULL },

/* --- Module Path-Replacement-Operations-asn1-97 --- --- ---                 */

  /* pathReplaceInvite        */ {  86, dissect_qsig_pr_DummyArg_PDU, NULL },
  /* pathReplacePropose       */ {   4, dissect_qsig_pr_PRProposeArg_PDU, NULL },
  /* pathReplaceSetup         */ {   5, dissect_qsig_pr_PRSetupArg_PDU, dissect_qsig_pr_DummyResult_PDU },
  /* pathReplaceRetain        */ {   6, dissect_qsig_pr_PRRetainArg_PDU, dissect_qsig_pr_DummyResult_PDU },

/* --- Module Call-Transfer-Operations-asn1-97 --- --- ---                    */

  /* callTransferIdentify     */ {   7, dissect_qsig_ct_DummyArg_PDU, dissect_qsig_ct_CTIdentifyRes_PDU },
  /* callTransferAbandon      */ {   8, dissect_qsig_ct_DummyArg_PDU, NULL },
  /* callTransferInitiate     */ {   9, dissect_qsig_ct_CTInitiateArg_PDU, dissect_qsig_ct_DummyRes_PDU },
  /* callTransferSetup        */ {  10, dissect_qsig_ct_CTSetupArg_PDU, dissect_qsig_ct_DummyRes_PDU },
  /* callTransferActive       */ {  11, dissect_qsig_ct_CTActiveArg_PDU, NULL },
  /* callTransferComplete     */ {  12, dissect_qsig_ct_CTCompleteArg_PDU, NULL },
  /* callTransferUpdate       */ {  13, dissect_qsig_ct_CTUpdateArg_PDU, NULL },
  /* subaddressTransfer       */ {  14, dissect_qsig_ct_SubaddressTransferArg_PDU, NULL },

/* --- Module SS-CC-Operations-asn1-97 --- --- ---                            */

  /* ccbsRequest              */ {  40, dissect_qsig_cc_CcRequestArg_PDU, dissect_qsig_cc_CcRequestRes_PDU },
  /* ccnrRequest              */ {  27, dissect_qsig_cc_CcRequestArg_PDU, dissect_qsig_cc_CcRequestRes_PDU },
  /* ccCancel                 */ {  28, dissect_qsig_cc_CcOptionalArg_PDU, NULL },
  /* ccExecPossible           */ {  29, dissect_qsig_cc_CcOptionalArg_PDU, NULL },
  /* ccPathReserve            */ {  30, dissect_qsig_cc_CcExtension_PDU, dissect_qsig_cc_CcExtension_PDU },
  /* ccRingout                */ {  31, dissect_qsig_cc_CcExtension_PDU, NULL },
  /* ccSuspend                */ {  32, dissect_qsig_cc_CcExtension_PDU, NULL },
  /* ccResume                 */ {  33, dissect_qsig_cc_CcExtension_PDU, NULL },

/* --- Module Call-Offer-Operations-asn1-97 --- --- ---                       */

  /* pathRetain               */ {  41, dissect_qsig_co_PathRetainArg_PDU, NULL },
  /* serviceAvailable         */ {  42, dissect_qsig_co_ServiceAvailableArg_PDU, NULL },
  /* callOfferRequest         */ {  34, dissect_qsig_co_DummyArg_PDU, dissect_qsig_co_DummyRes_PDU },
  /* cfbOverride              */ {  49, dissect_qsig_co_DummyArg_PDU, NULL },

/* --- Module Do-Not-Disturb-Operations-asn1-97 --- --- ---                   */

  /* doNotDisturbActivateQ    */ {  35, dissect_qsig_dnd_DNDActivateArg_PDU, dissect_qsig_dnd_DNDActivateRes_PDU },
  /* doNotDisturbDeactivateQ  */ {  36, dissect_qsig_dnd_DNDDeactivateArg_PDU, dissect_qsig_dnd_DummyRes_PDU },
  /* doNotDisturbInterrogateQ */ {  37, dissect_qsig_dnd_DNDInterrogateArg_PDU, dissect_qsig_dnd_DNDInterrogateRes_PDU },
  /* doNotDisturbOverrideQ    */ {  38, dissect_qsig_dnd_DNDOverrideArg_PDU, NULL },
  /* pathRetain               */ {  41, dissect_qsig_dnd_PathRetainArg_PDU, NULL },
  /* serviceAvailable         */ {  42, dissect_qsig_dnd_ServiceAvailableArg_PDU, NULL },
  /* doNotDisturbOvrExecuteQ  */ {  39, dissect_qsig_dnd_DummyArg_PDU, dissect_qsig_dnd_DummyRes_PDU },

/* --- Module Call-Intrusion-Operations-asn1-97 --- --- ---                   */

  /* pathRetain               */ {  41, dissect_qsig_ci_PathRetainArg_PDU, NULL },
  /* serviceAvailable         */ {  42, dissect_qsig_ci_ServiceAvailableArg_PDU, NULL },
  /* callIntrusionRequest     */ {  43, dissect_qsig_ci_CIRequestArg_PDU, dissect_qsig_ci_CIRequestRes_PDU },
  /* callIntrusionGetCIPL     */ {  44, dissect_qsig_ci_DummyArg_PDU, dissect_qsig_ci_CIGetCIPLRes_PDU },
  /* callIntrusionForcedRelease */ {  46, dissect_qsig_ci_DummyArg_PDU, dissect_qsig_ci_DummyRes_PDU },
  /* callIntrusionIsolate     */ {  45, dissect_qsig_ci_DummyArg_PDU, dissect_qsig_ci_DummyRes_PDU },
  /* callIntrusionWOBRequest  */ {  47, dissect_qsig_ci_DummyArg_PDU, dissect_qsig_ci_DummyRes_PDU },
  /* callIntrusionCompleted   */ {  48, dissect_qsig_ci_DummyArg_PDU, NULL },
  /* cfbOverride              */ {  49, dissect_qsig_ci_DummyArg_PDU, NULL },

/* --- Module SS-AOC-Operations-asn1-97 --- --- ---                           */

  /* aocRate                  */ {  63, dissect_qsig_aoc_AocRateArg_PDU, NULL },
  /* aocInterim               */ {  62, dissect_qsig_aoc_AocInterimArg_PDU, NULL },
  /* aocFinal                 */ {  61, dissect_qsig_aoc_AocFinalArg_PDU, NULL },
  /* chargeRequest            */ {  59, dissect_qsig_aoc_ChargeRequestArg_PDU, dissect_qsig_aoc_ChargeRequestRes_PDU },
  /* getFinalCharge           */ {  60, dissect_qsig_aoc_DummyArg_PDU, NULL },
  /* aocComplete              */ {  64, dissect_qsig_aoc_AocCompleteArg_PDU, dissect_qsig_aoc_AocCompleteRes_PDU },
  /* aocDivChargeReq          */ {  65, dissect_qsig_aoc_AocDivChargeReqArg_PDU, NULL },

/* --- Module Recall-Operations-asn1-97 --- --- ---                           */

  /* recallAlerting           */ {  57, dissect_qsig_re_ReAlertingArg_PDU, NULL },
  /* recallAnswered           */ {  58, dissect_qsig_re_ReAnswerArg_PDU, NULL },

/* --- Module Synchronization-Operations-asn1-97 --- --- ---                  */

  /* synchronizationRequest   */ {  78, dissect_qsig_sync_SynchronizationReqArg_PDU, dissect_qsig_sync_SynchronizationReqRes_PDU },
  /* synchronizationInfo      */ {  79, dissect_qsig_sync_SynchronizationInfoArg_PDU, NULL },

/* --- Module Call-Interception-Operations-asn1-97 --- --- ---                */

  /* cintLegInformation1      */ {  66, dissect_qsig_cint_CintInformation1Arg_PDU, NULL },
  /* cintLegInformation2      */ {  67, dissect_qsig_cint_CintInformation2Arg_PDU, NULL },
  /* cintCondition            */ {  68, dissect_qsig_cint_CintCondArg_PDU, NULL },
  /* cintDisable              */ {  69, dissect_qsig_cint_CintExtension_PDU, NULL },
  /* cintEnable               */ {  70, dissect_qsig_cint_CintExtension_PDU, NULL },

/* --- Module Common-Information-Operations-asn1-97 --- --- ---               */

  /* cmnRequest               */ {  84, dissect_qsig_cmn_DummyArg_PDU, dissect_qsig_cmn_CmnArg_PDU },
  /* cmnInform                */ {  85, dissect_qsig_cmn_CmnArg_PDU, NULL },

/* --- Module Call-Interruption-Operations-asn1-97 --- --- ---                */

  /* callInterruptionRequest  */ {  87, dissect_qsig_cpi_CPIRequestArg_PDU, NULL },
  /* callProtectionRequest    */ {  88, dissect_qsig_cpi_CPIPRequestArg_PDU, NULL },

/* --- Module PUM-Registration-Operations-asn1-97 --- --- ---                 */

  /* pumRegistr               */ {  89, dissect_qsig_pumr_PumRegistrArg_PDU, dissect_qsig_pumr_PumRegistrRes_PDU },
  /* pumDelReg                */ {  90, dissect_qsig_pumr_PumDelRegArg_PDU, dissect_qsig_pumr_DummyRes_PDU },
  /* pumDe-reg                */ {  91, dissect_qsig_pumr_PumDe_regArg_PDU, dissect_qsig_pumr_DummyRes_PDU },
  /* pumInterrog              */ {  92, dissect_qsig_pumr_PumInterrogArg_PDU, dissect_qsig_pumr_PumInterrogRes_PDU },

/* --- Module Private-User-Mobility-Call-Handling-Operations-asn1-97 --- --- --- */

  /* pumiEnquiry              */ {  93, dissect_qsig_pumch_EnquiryArg_PDU, dissect_qsig_pumch_EnquiryRes_PDU },
  /* pumiDivert               */ {  94, dissect_qsig_pumch_DivertArg_PDU, dissect_qsig_pumch_DummyRes_PDU },
  /* pumiInform               */ {  95, dissect_qsig_pumch_InformArg_PDU, NULL },
  /* pumoCall                 */ {  96, dissect_qsig_pumch_PumoArg_PDU, NULL },

/* --- Module Single-Step-Call-Transfer-Operations-asn1-97 --- --- ---        */

  /* ssctInitiate             */ {  99, dissect_qsig_ssct_SSCTInitiateArg_PDU, dissect_qsig_ssct_DummyRes_PDU },
  /* ssctSetup                */ { 100, dissect_qsig_ssct_SSCTSetupArg_PDU, NULL },
  /* ssctPostDial             */ { 101, dissect_qsig_ssct_DummyArg_PDU, NULL },
  /* ssctDigitInfo            */ { 102, dissect_qsig_ssct_SSCTDigitInfoArg_PDU, NULL },

/* --- Module WTM-Location-Registration-Operations-asn1-97 --- --- ---        */

  /* locUpdate                */ {  50, dissect_qsig_wtmlr_LocUpdArg_PDU, dissect_qsig_wtmlr_DummyRes_PDU },
  /* locDelete                */ {  51, dissect_qsig_wtmlr_LocDelArg_PDU, dissect_qsig_wtmlr_DummyRes_PDU },
  /* locDeReg                 */ {  52, dissect_qsig_wtmlr_LocDeRegArg_PDU, dissect_qsig_wtmlr_DummyRes_PDU },
  /* pisnEnquiry              */ {  53, dissect_qsig_wtmlr_PisnEnqArg_PDU, dissect_qsig_wtmlr_PisnEnqRes_PDU },
  /* getRRCInf                */ {  97, dissect_qsig_wtmlr_GetRRCInfArg_PDU, dissect_qsig_wtmlr_GetRRCInfRes_PDU },
  /* locInfoCheck             */ {  98, dissect_qsig_wtmlr_LocInfoCheckArg_PDU, dissect_qsig_wtmlr_LocInfoCheckRes_PDU },

/* --- Module Wireless-Terminal-Call-Handling-Operations-asn1-97 --- --- ---  */

  /* wtmiEnquiry              */ {  54, dissect_qsig_wtmch_EnquiryArg_PDU, dissect_qsig_wtmch_EnquiryRes_PDU },
  /* wtmiDivert               */ {  55, dissect_qsig_wtmch_DivertArg_PDU, dissect_qsig_wtmch_DummyRes_PDU },
  /* wtmiInform               */ {  56, dissect_qsig_wtmch_InformArg_PDU, NULL },
  /* wtmoCall                 */ {  71, dissect_qsig_wtmch_WtmoArg_PDU, NULL },

/* --- Module WTM-Authentication-Operations-asn1-97 --- --- ---               */

  /* authWtmUser              */ {  72, dissect_qsig_wtmau_AuthWtmArg_PDU, dissect_qsig_wtmau_AuthWtmRes_PDU },
  /* getWtatParam             */ {  73, dissect_qsig_wtmau_WtatParamArg_PDU, dissect_qsig_wtmau_WtatParamRes_PDU },
  /* wtatParamEnq             */ {  74, dissect_qsig_wtmau_WtatParamArg_PDU, dissect_qsig_wtmau_WtatParamRes_PDU },
  /* getWtanParam             */ {  75, dissect_qsig_wtmau_WtanParamArg_PDU, dissect_qsig_wtmau_WtanParamRes_PDU },
  /* wtanParamEnq             */ {  76, dissect_qsig_wtmau_WtanParamArg_PDU, dissect_qsig_wtmau_WtanParamRes_PDU },
  /* transferAuthParam        */ {  77, dissect_qsig_wtmau_ARG_transferAuthParam_PDU, NULL },

/* --- Module SS-SD-Operations-asn1-97 --- --- ---                            */

  /* display                  */ { 103, dissect_qsig_sd_DisplayArg_PDU, NULL },
  /* keypad                   */ { 104, dissect_qsig_sd_KeypadArg_PDU, NULL },

/* --- Module Call-Identification-and-Call-Linkage-Operations-asn1-97 --- --- --- */

  /* callIdentificationAssign */ { 105, dissect_qsig_cidl_CallIdentificationAssignArg_PDU, NULL },
  /* callIdentificationUpdate */ { 106, dissect_qsig_cidl_CallIdentificationUpdateArg_PDU, NULL },

/* --- Module Short-Message-Service-Operations-asn1-97 --- --- ---            */

  /* smsSubmit                */ { 107, dissect_qsig_sms_SmsSubmitArg_PDU, dissect_qsig_sms_SmsSubmitRes_PDU },
  /* smsDeliver               */ { 108, dissect_qsig_sms_SmsDeliverArg_PDU, dissect_qsig_sms_SmsDeliverRes_PDU },
  /* smsStatusReport          */ { 109, dissect_qsig_sms_SmsStatusReportArg_PDU, dissect_qsig_sms_SmsStatusReportRes_PDU },
  /* smsCommand               */ { 110, dissect_qsig_sms_SmsCommandArg_PDU, dissect_qsig_sms_SmsCommandRes_PDU },
  /* scAlert                  */ { 111, dissect_qsig_sms_ScAlertArg_PDU, dissect_qsig_sms_DummyRes_PDU },

/* --- Module SS-MCR-Operations-asn97 --- --- ---                             */

  /* mCRequest                */ { 112, dissect_qsig_mcr_MCRequestArg_PDU, dissect_qsig_mcr_MCRequestResult_PDU },
  /* mCInform                 */ { 113, dissect_qsig_mcr_MCInformArg_PDU, NULL },
  /* mCAlerting               */ { 114, dissect_qsig_mcr_MCAlertingArg_PDU, NULL },

/* --- Module SS-MCM-Operations-asn1-97 --- --- ---                           */

  /* mCMNewMsg                */ {  80, dissect_qsig_mcm_MCMNewMsgArg_PDU, dissect_qsig_mcm_MCMDummyRes_PDU },
  /* mCMNoNewMsg              */ {  81, dissect_qsig_mcm_MCMNoNewMsgArg_PDU, dissect_qsig_mcm_MCMDummyRes_PDU },
  /* mCMUpdate                */ { 115, dissect_qsig_mcm_MCMUpdateArg_PDU, dissect_qsig_mcm_MCMDummyRes_PDU },
  /* mCMUpdateReq             */ {  82, dissect_qsig_mcm_MCMUpdateReqArg_PDU, dissect_qsig_mcm_MCMUpdateReqRes_PDU },
  /* mCMService               */ { 116, dissect_qsig_mcm_MCMServiceArg_PDU, dissect_qsig_mcm_MCMDummyRes_PDU },
  /* mCMInterrogate           */ { 117, dissect_qsig_mcm_MCMInterrogateArg_PDU, dissect_qsig_mcm_MCMInterrogateRes_PDU },
  /* mCMailboxFull            */ { 118, dissect_qsig_mcm_MCMailboxFullArg_PDU, NULL },

/* --- Module SS-MID-Operations-asn1-97 --- --- ---                           */

  /* mIDMailboxAuth           */ { 119, dissect_qsig_mid_MIDMailboxAuthArg_PDU, dissect_qsig_mid_MIDDummyRes_PDU },
  /* mIDMailboxID             */ { 120, dissect_qsig_mid_MIDMailboxIDArg_PDU, dissect_qsig_mid_MIDDummyRes_PDU },

/*--- End of included file: packet-qsig-table11.c ---*/
#line 334 "../../asn1/qsig/packet-qsig-template.c"
};

typedef struct _qsig_err_t {
  gint32 errcode;
  new_dissector_t err_pdu;
} qsig_err_t;

static const qsig_err_t qsig_err_tab[] = {

/*--- Included file: packet-qsig-table21.c ---*/
#line 1 "../../asn1/qsig/packet-qsig-table21.c"

/* --- Module General-Error-List --- --- ---                                  */

  /* userNotSubscribed        */ {    0, NULL },
  /* rejectedByNetwork        */ {    1, NULL },
  /* rejectedByUser           */ {    2, NULL },
  /* notAvailable             */ {    3, NULL },
  /* insufficientInformation  */ {    5, NULL },
  /* invalidServedUserNr      */ {    6, NULL },
  /* invalidCallState         */ {    7, NULL },
  /* basicServiceNotProvided  */ {    8, NULL },
  /* notIncomingCall          */ {    9, NULL },
  /* supplementaryServiceInteractionNotAllowed */ {   10, NULL },
  /* resourceUnavailable      */ {   11, NULL },
  /* callFailure              */ {   25, NULL },
  /* proceduralError          */ {   43, NULL },

/* --- Modules Manufacturer-specific-service-extension-class-asn1-97 PSS1-generic-parameters-definition-asn1-97 Addressing-Data-Elements-asn1-97 --- --- --- */

/* Unknown or empty loop list ERROR */

/* --- Module Name-Operations-asn1-97 --- --- ---                             */

/* Unknown or empty loop list ERROR */

/* --- Module Call-Diversion-Operations-asn1-97 --- --- ---                   */

  /* invalidDivertedToNr      */ {   12, NULL },
  /* specialServiceNr         */ {   14, NULL },
  /* diversionToServedUserNr  */ {   15, NULL },
  /* numberOfDiversionsExceeded */ {   24, NULL },
  /* temporarilyUnavailable   */ { 1000, NULL },
  /* notAuthorized            */ { 1007, NULL },
  /* unspecified              */ { 1008, dissect_qsig_cf_Extension_PDU },

/* --- Module Path-Replacement-Operations-asn1-97 --- --- ---                 */

  /* temporarilyUnavailable   */ { 1000, NULL },
  /* collision                */ { 1001, NULL },
  /* criteriaPermanentlyUnachievable */ { 1002, NULL },
  /* criteriaTemporarilyUnachievable */ { 1003, NULL },
  /* invalidRerouteingNumber  */ { 1004, NULL },
  /* unrecognizedCallIdentity */ { 1005, NULL },
  /* establishmentFailure     */ { 1006, NULL },
  /* unspecified              */ { 1008, dissect_qsig_pr_Extension_PDU },

/* --- Module Call-Transfer-Operations-asn1-97 --- --- ---                    */

  /* unspecified              */ { 1008, dissect_qsig_ct_Extension_PDU },
  /* invalidRerouteingNumber  */ { 1004, NULL },
  /* unrecognizedCallIdentity */ { 1005, NULL },
  /* establishmentFailure     */ { 1006, NULL },

/* --- Module SS-CC-Operations-asn1-97 --- --- ---                            */

  /* unspecified              */ { 1008, dissect_qsig_cc_Extension_PDU },
  /* shortTermRejection       */ { 1010, NULL },
  /* longTermRejection        */ { 1011, NULL },
  /* remoteUserBusyAgain      */ { 1012, NULL },
  /* failureToMatch           */ { 1013, NULL },
  /* failedDueToInterworking  */ { 1014, NULL },

/* --- Module Call-Offer-Operations-asn1-97 --- --- ---                       */

  /* notBusy                  */ { 1009, NULL },
  /* temporarilyUnavailable   */ { 1000, NULL },
  /* unspecified              */ { 1008, dissect_qsig_co_Extension_PDU },

/* --- Module Do-Not-Disturb-Operations-asn1-97 --- --- ---                   */

  /* temporarilyUnavailable   */ { 1000, NULL },
  /* notActivated             */ {   43, NULL },
  /* unspecified              */ { 1008, dissect_qsig_dnd_Extension_PDU },

/* --- Module Call-Intrusion-Operations-asn1-97 --- --- ---                   */

  /* notBusy                  */ { 1009, NULL },
  /* temporarilyUnavailable   */ { 1000, NULL },
  /* notAuthorized            */ { 1007, NULL },
  /* unspecified              */ { 1008, dissect_qsig_ci_Extension_PDU },

/* --- Module SS-AOC-Operations-asn1-97 --- --- ---                           */

  /* unspecified              */ { 1008, dissect_qsig_aoc_Extension_PDU },
  /* freeOfCharge             */ { 1016, NULL },

/* --- Module Recall-Operations-asn1-97 --- --- ---                           */

/* Unknown or empty loop list ERROR */

/* --- Module Synchronization-Operations-asn1-97 --- --- ---                  */

  /* unspecified              */ { 1008, dissect_qsig_sync_Extension_PDU },

/* --- Module Call-Interception-Operations-asn1-97 --- --- ---                */

/* Unknown or empty loop list ERROR */

/* --- Module Common-Information-Operations-asn1-97 --- --- ---               */

/* Unknown or empty loop list ERROR */

/* --- Module Call-Interruption-Operations-asn1-97 --- --- ---                */

/* Unknown or empty loop list ERROR */

/* --- Module PUM-Registration-Operations-asn1-97 --- --- ---                 */

  /* unspecified              */ { 1008, dissect_qsig_pumr_Extension_PDU },
  /* notAuthorized            */ { 1007, NULL },
  /* temporarilyUnavailable   */ { 1000, NULL },
  /* pumUserNotSubscribedToThisServiceOpt */ { 1019, NULL },
  /* pumUserFailedAuthentication */ { 1020, NULL },
  /* hostingAddrInvalid       */ { 1021, NULL },
  /* pumUserNotRegistered     */ { 1022, NULL },

/* --- Module Private-User-Mobility-Call-Handling-Operations-asn1-97 --- --- --- */

  /* locationNotKnown         */ { 1015, NULL },
  /* unspecified              */ { 1008, dissect_qsig_pumch_Extension_PDU },

/* --- Module Single-Step-Call-Transfer-Operations-asn1-97 --- --- ---        */

  /* unspecified              */ { 1008, dissect_qsig_ssct_Extension_PDU },

/* --- Module WTM-Location-Registration-Operations-asn1-97 --- --- ---        */

  /* notAuthorized            */ { 1007, NULL },
  /* temporarilyUnavailable   */ { 1000, NULL },
  /* unspecified              */ { 1008, dissect_qsig_wtmlr_Extension_PDU },

/* --- Module Wireless-Terminal-Call-Handling-Operations-asn1-97 --- --- ---  */

  /* unspecified              */ { 1008, dissect_qsig_wtmch_Extension_PDU },
  /* locationNotKnown         */ { 1015, NULL },

/* --- Module WTM-Authentication-Operations-asn1-97 --- --- ---               */

  /* notAuthorized            */ { 1007, NULL },
  /* paramNotAvailable        */ { 1017, NULL },
  /* temporarilyUnavailable   */ { 1000, NULL },
  /* unspecified              */ { 1008, dissect_qsig_wtmau_Extension_PDU },

/* --- Module SS-SD-Operations-asn1-97 --- --- ---                            */

  /* unspecified              */ { 1008, dissect_qsig_sd_Extension_PDU },
  /* noDisplayAvailable       */ { 1023, NULL },
  /* displayTemporarilyNotAvailable */ { 1024, NULL },
  /* notPresentable           */ { 1025, NULL },

/* --- Module Call-Identification-and-Call-Linkage-Operations-asn1-97 --- --- --- */

/* Unknown or empty loop list ERROR */

/* --- Module Short-Message-Service-Operations-asn1-97 --- --- ---            */

  /* smsDeliverError          */ { 1026, dissect_qsig_sms_PAR_smsDeliverError_PDU },
  /* smsSubmitError           */ { 1027, dissect_qsig_sms_PAR_smsSubmitError_PDU },
  /* smsStatusReportError     */ { 1028, dissect_qsig_sms_PAR_smsStatusReportError_PDU },
  /* smsCommandError          */ { 1029, dissect_qsig_sms_PAR_smsCommandError_PDU },
  /* unspecified              */ { 1008, dissect_qsig_sms_SmsExtension_PDU },

/* --- Module SS-MCR-Operations-asn97 --- --- ---                             */

  /* invalidDestinationNumber */ { 1030, NULL },
  /* invalidCooperationNumber */ { 1031, NULL },
  /* mCRequestNotAllowed      */ { 1032, NULL },
  /* mCExecutionNotAllowed    */ { 1033, NULL },
  /* mCDestUserBusy           */ { 1034, NULL },
  /* mCCoopUserBusy           */ { 1035, NULL },
  /* mCCoopUserRejected       */ { 1036, NULL },
  /* unspecified              */ { 1008, dissect_qsig_mcr_Extension_PDU },

/* --- Module SS-MCM-Operations-asn1-97 --- --- ---                           */

  /* mCMModeNotProvided       */ { 1037, NULL },
  /* unspecified              */ { 1008, dissect_qsig_mcm_Extension_PDU },

/* --- Module SS-MID-Operations-asn1-97 --- --- ---                           */

  /* invalidMailbox           */ { 1039, NULL },
  /* authorizationFailed      */ { 1040, NULL },
  /* unspecified              */ { 1008, dissect_qsig_mid_Extension_PDU },

/*--- End of included file: packet-qsig-table21.c ---*/
#line 343 "../../asn1/qsig/packet-qsig-template.c"
};

static const qsig_op_t *get_op(gint32 opcode) {
  int i;

  /* search from the end to get the last occurrence if the operation is redefined in some newer specification */
  for (i = array_length(qsig_op_tab) - 1; i >= 0; i--)
    if (qsig_op_tab[i].opcode == opcode)
      return &qsig_op_tab[i];
  return NULL;
}

static gint32 get_service(gint32 opcode) {
  if ((opcode < 0) || (opcode >= (int)array_length(op2srv_tab)))
    return NO_SRV;
  return op2srv_tab[opcode];
}

static const qsig_err_t *get_err(gint32 errcode) {
  int i;

  /* search from the end to get the last occurrence if the operation is redefined in some newer specification */
  for (i = array_length(qsig_err_tab) - 1; i >= 0; i--)
    if (qsig_err_tab[i].errcode == errcode)
      return &qsig_err_tab[i];
  return NULL;
}

/*--- dissect_qsig_arg ------------------------------------------------------*/
static int
dissect_qsig_arg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  int offset = 0;
  rose_ctx_t *rctx;
  gint32 opcode = 0, service;
  const qsig_op_t *op_ptr;
  const gchar *p;
  proto_item *ti, *ti_tmp;
  proto_tree *qsig_tree;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
  DISSECTOR_ASSERT(rctx);

  if (rctx->d.pdu != 1)  /* invoke */
    return offset;
  if (rctx->d.code == 0) {  /* local */
    opcode = rctx->d.code_local;
    op_ptr = get_op(opcode);
  } else if (rctx->d.code == 1) {  /* global */
    op_ptr = (qsig_op_t *)g_hash_table_lookup(qsig_oid2op_hashtable, rctx->d.code_global);
    if (op_ptr) opcode = op_ptr->opcode;
  } else {
    return offset;
  }
  if (!op_ptr)
    return offset;
  service = get_service(opcode);

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, tvb_captured_length(tvb), ENC_NA);
  qsig_tree = proto_item_add_subtree(ti, ett_qsig);

  proto_tree_add_uint(qsig_tree, hf_qsig_operation, tvb, 0, 0, opcode);
  p = try_val_to_str(opcode, VALS(qsig_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  ti_tmp = proto_tree_add_uint(qsig_tree, hf_qsig_service, tvb, 0, 0, service);
  p = try_val_to_str(service, VALS(qsig_str_service_name));
  if (p) proto_item_append_text(ti_tmp, " - %s", p);

  if (op_ptr->arg_pdu)
    offset = op_ptr->arg_pdu(tvb, pinfo, qsig_tree, NULL);
  else
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(qsig_tree, tvb, offset, -1, "UNSUPPORTED ARGUMENT TYPE (QSIG)");
      offset += tvb_captured_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_qsig_res -------------------------------------------------------*/
static int
dissect_qsig_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  gint offset = 0;
  rose_ctx_t *rctx;
  gint32 opcode, service;
  const qsig_op_t *op_ptr;
  const gchar *p;
  proto_item *ti, *ti_tmp;
  proto_tree *qsig_tree;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
  DISSECTOR_ASSERT(rctx);

  if (rctx->d.pdu != 2)  /* returnResult */
    return offset;
  if (rctx->d.code != 0)  /* local */
    return offset;
  opcode = rctx->d.code_local;
  op_ptr = get_op(opcode);
  if (!op_ptr)
    return offset;
  service = get_service(opcode);

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, tvb_captured_length(tvb), ENC_NA);
  qsig_tree = proto_item_add_subtree(ti, ett_qsig);

  proto_tree_add_uint(qsig_tree, hf_qsig_operation, tvb, 0, 0, opcode);
  p = try_val_to_str(opcode, VALS(qsig_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  ti_tmp = proto_tree_add_uint(qsig_tree, hf_qsig_service, tvb, 0, 0, service);
  p = try_val_to_str(service, VALS(qsig_str_service_name));
  if (p) proto_item_append_text(ti_tmp, " - %s", p);

  if (op_ptr->res_pdu)
    offset = op_ptr->res_pdu(tvb, pinfo, qsig_tree, NULL);
  else
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(qsig_tree, tvb, offset, -1, "UNSUPPORTED RESULT TYPE (QSIG)");
      offset += tvb_captured_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_qsig_err ------------------------------------------------------*/
static int
dissect_qsig_err(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  int offset = 0;
  rose_ctx_t *rctx;
  gint32 errcode;
  const qsig_err_t *err_ptr;
  const gchar *p;
  proto_item *ti;
  proto_tree *qsig_tree;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
  DISSECTOR_ASSERT(rctx);

  if (rctx->d.pdu != 3)  /* returnError */
    return offset;
  if (rctx->d.code != 0)  /* local */
    return offset;
  errcode = rctx->d.code_local;
  err_ptr = get_err(errcode);
  if (!err_ptr)
    return offset;

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, tvb_captured_length(tvb), ENC_NA);
  qsig_tree = proto_item_add_subtree(ti, ett_qsig);

  proto_tree_add_uint(qsig_tree, hf_qsig_error, tvb, 0, 0, errcode);
  p = try_val_to_str(errcode, VALS(qsig_str_error));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (err_ptr->err_pdu)
    offset = err_ptr->err_pdu(tvb, pinfo, qsig_tree, NULL);
  else
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(qsig_tree, tvb, offset, -1, "UNSUPPORTED ERROR TYPE (QSIG)");
      offset += tvb_captured_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_qsig_transit_counter_ie ---------------------------------------*/
static int
dissect_qsig_transit_counter_ie(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int length  _U_) {
  proto_tree_add_item(tree, hf_qsig_tc, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  return offset;
}
/*--- dissect_qsig_party_category_ie ----------------------------------------*/
static int
dissect_qsig_party_category_ie(tvbuff_t *tvb, int offset, packet_info *pinfo  _U_, proto_tree *tree, int length  _U_) {
  proto_tree_add_item(tree, hf_qsig_pc, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  return offset;
}

/*--- dissect_qsig_ie -------------------------------------------------------*/
static void
dissect_qsig_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int codeset) {
  gint offset;
  proto_item *ti, *hidden_item;
  proto_tree *ie_tree;
  guint8 ie_type, ie_len;

  offset = 0;

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, -1, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(ti);

  ie_type = tvb_get_guint8(tvb, offset);
  ie_len = tvb_get_guint8(tvb, offset + 1);

  ie_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_qsig_ie, NULL,
            val_to_str(ie_type, VALS(qsig_str_ie_type[codeset]), "unknown (0x%02X)"));

  proto_tree_add_item(ie_tree, *hf_qsig_ie_type_arr[codeset], tvb, offset, 1, ENC_BIG_ENDIAN);
  hidden_item = proto_tree_add_item(ie_tree, hf_qsig_ie_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  PROTO_ITEM_SET_HIDDEN(hidden_item);
  proto_tree_add_item(ie_tree, hf_qsig_ie_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
  offset += 2;
  if (tvb_reported_length_remaining(tvb, offset) <= 0)
    return;
  switch ((codeset << 8) | ie_type) {
    case CS4 | QSIG_IE_TRANSIT_COUNTER :
      dissect_qsig_transit_counter_ie(tvb, offset, pinfo, ie_tree, ie_len);
      break;
    case CS5 | QSIG_IE_PARTY_CATEGORY :
      dissect_qsig_party_category_ie(tvb, offset, pinfo, ie_tree, ie_len);
      break;
    default:
      if (ie_len > 0) {
        if (tree) proto_tree_add_item(ie_tree, hf_qsig_ie_data, tvb, offset, ie_len, ENC_NA);
      }
  }
}
/*--- dissect_qsig_ie_cs4 ---------------------------------------------------*/
static void
dissect_qsig_ie_cs4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_qsig_ie(tvb, pinfo, tree, 4);
}
/*--- dissect_qsig_ie_cs5 ---------------------------------------------------*/
static void
dissect_qsig_ie_cs5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_qsig_ie(tvb, pinfo, tree, 5);
}

/*--- qsig_init_tables ---------------------------------------------------------*/
static void qsig_init_tables(void) {
  guint i;
  gint opcode, *key;
  gchar *oid;

  if (qsig_opcode2oid_hashtable)
    g_hash_table_destroy(qsig_opcode2oid_hashtable);
  qsig_opcode2oid_hashtable = g_hash_table_new_full(g_int_hash, g_int_equal, g_free, g_free);

  if (qsig_oid2op_hashtable)
    g_hash_table_destroy(qsig_oid2op_hashtable);
  qsig_oid2op_hashtable = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);

  /* fill-in global OIDs */
  for (i=0; i<array_length(qsig_op_tab); i++) {
    opcode = qsig_op_tab[i].opcode;
    oid = g_strdup_printf("1.3.12.9.%d", opcode);
    key = (gint *)g_malloc(sizeof(gint));
    *key = opcode;
    g_hash_table_insert(qsig_opcode2oid_hashtable, key, oid);
    g_hash_table_insert(qsig_oid2op_hashtable, g_strdup(oid), (gpointer)&qsig_op_tab[i]);
  }

}

/*--- proto_register_qsig ---------------------------------------------------*/
void proto_register_qsig(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_qsig_operation, { "Operation", "qsig.operation",
                           FT_UINT8, BASE_DEC, VALS(qsig_str_operation), 0x0,
                           NULL, HFILL }},
    { &hf_qsig_service,   { "Service", "qsig.service",
                           FT_UINT8, BASE_DEC, VALS(qsig_str_service), 0x0,
                           "Supplementary Service", HFILL }},
    { &hf_qsig_error,     { "Error", "qsig.error",
                           FT_UINT8, BASE_DEC, VALS(qsig_str_error), 0x0,
                           NULL, HFILL }},
    { &hf_qsig_ie_type, { "Type", "qsig.ie.type",
                          FT_UINT8, BASE_HEX, NULL, 0x0,
                          "Information Element Type", HFILL }},
    { &hf_qsig_ie_type_cs4, { "Type", "qsig.ie.type.cs4",
                          FT_UINT8, BASE_HEX, VALS(qsig_str_ie_type_cs4), 0x0,
                          "Information Element Type (Codeset 4)", HFILL }},
    { &hf_qsig_ie_type_cs5, { "Type", "qsig.ie.type.cs5",
                          FT_UINT8, BASE_HEX, VALS(qsig_str_ie_type_cs5), 0x0,
                          "Information Element Type (Codeset 5)", HFILL }},
    { &hf_qsig_ie_len,  { "Length", "qsig.ie.len",
                          FT_UINT8, BASE_DEC, NULL, 0x0,
                          "Information Element Length", HFILL }},
    { &hf_qsig_ie_data, { "Data", "qsig.ie.data",
                          FT_BYTES, BASE_NONE, NULL, 0x0,
                          NULL, HFILL }},
    { &hf_qsig_tc,      { "Transit count", "qsig.tc",
                          FT_UINT8, BASE_DEC, NULL, 0x1F,
                          NULL, HFILL }},
    { &hf_qsig_pc,      { "Party category", "qsig.pc",
                          FT_UINT8, BASE_HEX, VALS(qsig_str_pc), 0x07,
                          NULL, HFILL }},

/*--- Included file: packet-qsig-hfarr.c ---*/
#line 1 "../../asn1/qsig/packet-qsig-hfarr.c"

/* --- Modules Manufacturer-specific-service-extension-class-asn1-97 PSS1-generic-parameters-definition-asn1-97 Addressing-Data-Elements-asn1-97 --- --- --- */

    { &hf_qsig_extensionId,
      { "extensionId", "qsig.extensionId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_extensionArgument,
      { "extensionArgument", "qsig.extensionArgument_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_presentationAllowedAddressS,
      { "presentationAllowedAddressS", "qsig.presentationAllowedAddressS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressScreened", HFILL }},
    { &hf_qsig_presentationRestricted,
      { "presentationRestricted", "qsig.presentationRestricted_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_numberNotAvailableDueToInterworking,
      { "numberNotAvailableDueToInterworking", "qsig.numberNotAvailableDueToInterworking_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_presentationRestrictedAddressS,
      { "presentationRestrictedAddressS", "qsig.presentationRestrictedAddressS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressScreened", HFILL }},
    { &hf_qsig_presentationAllowedAddressU,
      { "presentationAllowedAddressU", "qsig.presentationAllowedAddressU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_qsig_presentationRestrictedAddressU,
      { "presentationRestrictedAddressU", "qsig.presentationRestrictedAddressU_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_qsig_presentationAllowedAddressNS,
      { "presentationAllowedAddressNS", "qsig.presentationAllowedAddressNS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NumberScreened", HFILL }},
    { &hf_qsig_presentationRestrictedAddressNS,
      { "presentationRestrictedAddressNS", "qsig.presentationRestrictedAddressNS_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NumberScreened", HFILL }},
    { &hf_qsig_presentationAllowedAddressNU,
      { "presentationAllowedAddressNU", "qsig.presentationAllowedAddressNU",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_presentationRestrictedAddressNU,
      { "presentationRestrictedAddressNU", "qsig.presentationRestrictedAddressNU",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_partyNumber,
      { "partyNumber", "qsig.partyNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_screeningIndicator,
      { "screeningIndicator", "qsig.screeningIndicator",
        FT_UINT32, BASE_DEC, VALS(qsig_ScreeningIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_partySubaddress,
      { "partySubaddress", "qsig.partySubaddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PartySubaddress_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_unknownPartyNumber,
      { "unknownPartyNumber", "qsig.unknownPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_qsig_publicPartyNumber,
      { "publicPartyNumber", "qsig.publicPartyNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dataPartyNumber,
      { "dataPartyNumber", "qsig.dataPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_qsig_telexPartyNumber,
      { "telexPartyNumber", "qsig.telexPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_qsig_privatePartyNumber,
      { "privatePartyNumber", "qsig.privatePartyNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_nationalStandardPartyNumber,
      { "nationalStandardPartyNumber", "qsig.nationalStandardPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_qsig_publicTypeOfNumber,
      { "publicTypeOfNumber", "qsig.publicTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PublicTypeOfNumber_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_publicNumberDigits,
      { "publicNumberDigits", "qsig.publicNumberDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_qsig_privateTypeOfNumber,
      { "privateTypeOfNumber", "qsig.privateTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PrivateTypeOfNumber_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_privateNumberDigits,
      { "privateNumberDigits", "qsig.privateNumberDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_qsig_userSpecifiedSubaddress,
      { "userSpecifiedSubaddress", "qsig.userSpecifiedSubaddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_nSAPSubaddress,
      { "nSAPSubaddress", "qsig.nSAPSubaddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_subaddressInformation,
      { "subaddressInformation", "qsig.subaddressInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_oddCountIndicator,
      { "oddCountIndicator", "qsig.oddCountIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},

/* --- Module Name-Operations-asn1-97 --- --- ---                             */

    { &hf_qsig_na_qsig_na_NameArg_PDU,
      { "NameArg", "qsig.na.NameArg",
        FT_UINT32, BASE_DEC, VALS(qsig_na_NameArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_na_name,
      { "name", "qsig.na.name",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_na_nameSequence,
      { "nameSequence", "qsig.na.nameSequence_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_na_extensionNA,
      { "extension", "qsig.na.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_na_NameExtension_vals), 0,
        "NameExtension", HFILL }},
    { &hf_qsig_na_single,
      { "single", "qsig.na.single_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extension", HFILL }},
    { &hf_qsig_na_multiple,
      { "multiple", "qsig.na.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_na_multiple_item,
      { "Extension", "qsig.na.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_na_namePresentationAllowed,
      { "namePresentationAllowed", "qsig.na.namePresentationAllowed",
        FT_UINT32, BASE_DEC, VALS(qsig_na_NamePresentationAllowed_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_na_namePresentationRestricted,
      { "namePresentationRestricted", "qsig.na.namePresentationRestricted",
        FT_UINT32, BASE_DEC, VALS(qsig_na_NamePresentationRestricted_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_na_nameNotAvailable,
      { "nameNotAvailable", "qsig.na.nameNotAvailable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_na_namePresentationAllowedSimple,
      { "namePresentationAllowedSimple", "qsig.na.namePresentationAllowedSimple",
        FT_STRING, BASE_NONE, NULL, 0,
        "NameData", HFILL }},
    { &hf_qsig_na_namePresentationAllowedExtended,
      { "namePresentationAllowedExtended", "qsig.na.namePresentationAllowedExtended_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NameSet", HFILL }},
    { &hf_qsig_na_namePresentationRestrictedSimple,
      { "namePresentationRestrictedSimple", "qsig.na.namePresentationRestrictedSimple",
        FT_STRING, BASE_NONE, NULL, 0,
        "NameData", HFILL }},
    { &hf_qsig_na_namePresentationRestrictedExtended,
      { "namePresentationRestrictedExtended", "qsig.na.namePresentationRestrictedExtended_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NameSet", HFILL }},
    { &hf_qsig_na_namePresentationRestrictedNull,
      { "namePresentationRestrictedNull", "qsig.na.namePresentationRestrictedNull_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_na_nameData,
      { "nameData", "qsig.na.nameData",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_na_characterSet,
      { "characterSet", "qsig.na.characterSet",
        FT_UINT32, BASE_DEC, VALS(qsig_na_CharacterSet_vals), 0,
        NULL, HFILL }},

/* --- Module Call-Diversion-Operations-asn1-97 --- --- ---                   */

    { &hf_qsig_cf_qsig_cf_ARG_activateDiversionQ_PDU,
      { "ARG-activateDiversionQ", "qsig.cf.ARG_activateDiversionQ_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_RES_activateDiversionQ_PDU,
      { "RES-activateDiversionQ", "qsig.cf.RES_activateDiversionQ",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_RES_activateDiversionQ_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_ARG_deactivateDiversionQ_PDU,
      { "ARG-deactivateDiversionQ", "qsig.cf.ARG_deactivateDiversionQ_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_RES_deactivateDiversionQ_PDU,
      { "RES-deactivateDiversionQ", "qsig.cf.RES_deactivateDiversionQ",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_RES_deactivateDiversionQ_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_ARG_interrogateDiversionQ_PDU,
      { "ARG-interrogateDiversionQ", "qsig.cf.ARG_interrogateDiversionQ_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_IntResultList_PDU,
      { "IntResultList", "qsig.cf.IntResultList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_ARG_checkRestriction_PDU,
      { "ARG-checkRestriction", "qsig.cf.ARG_checkRestriction_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_RES_checkRestriction_PDU,
      { "RES-checkRestriction", "qsig.cf.RES_checkRestriction",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_RES_checkRestriction_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_ARG_callRerouteing_PDU,
      { "ARG-callRerouteing", "qsig.cf.ARG_callRerouteing_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_RES_callRerouteing_PDU,
      { "RES-callRerouteing", "qsig.cf.RES_callRerouteing",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_RES_callRerouteing_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_ARG_divertingLegInformation1_PDU,
      { "ARG-divertingLegInformation1", "qsig.cf.ARG_divertingLegInformation1_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_ARG_divertingLegInformation2_PDU,
      { "ARG-divertingLegInformation2", "qsig.cf.ARG_divertingLegInformation2_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_ARG_divertingLegInformation3_PDU,
      { "ARG-divertingLegInformation3", "qsig.cf.ARG_divertingLegInformation3_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_ARG_cfnrDivertedLegFailed_PDU,
      { "ARG-cfnrDivertedLegFailed", "qsig.cf.ARG_cfnrDivertedLegFailed",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_ARG_cfnrDivertedLegFailed_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cf_qsig_cf_Extension_PDU,
      { "Extension", "qsig.cf.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_procedure,
      { "procedure", "qsig.cf.procedure",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_Procedure_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cf_basicService,
      { "basicService", "qsig.cf.basicService",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_BasicService_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cf_divertedToAddress,
      { "divertedToAddress", "qsig.cf.divertedToAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_qsig_cf_servedUserNr,
      { "servedUserNr", "qsig.cf.servedUserNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_cf_activatingUserNr,
      { "activatingUserNr", "qsig.cf.activatingUserNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_cf_extensionAD,
      { "extension", "qsig.cf.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_ADExtension_vals), 0,
        "ADExtension", HFILL }},
    { &hf_qsig_cf_single,
      { "single", "qsig.cf.single_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extension", HFILL }},
    { &hf_qsig_cf_multiple,
      { "multiple", "qsig.cf.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_cf_multiple_item,
      { "Extension", "qsig.cf.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_null,
      { "null", "qsig.cf.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_deactivatingUserNr,
      { "deactivatingUserNr", "qsig.cf.deactivatingUserNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_cf_extensionDD,
      { "extension", "qsig.cf.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_DDExtension_vals), 0,
        "DDExtension", HFILL }},
    { &hf_qsig_cf_interrogatingUserNr,
      { "interrogatingUserNr", "qsig.cf.interrogatingUserNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_cf_extensionID,
      { "extension", "qsig.cf.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_IDExtension_vals), 0,
        "IDExtension", HFILL }},
    { &hf_qsig_cf_divertedToNr,
      { "divertedToNr", "qsig.cf.divertedToNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_cf_extensionCHR,
      { "extension", "qsig.cf.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_CHRExtension_vals), 0,
        "CHRExtension", HFILL }},
    { &hf_qsig_cf_rerouteingReason,
      { "rerouteingReason", "qsig.cf.rerouteingReason",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_DiversionReason_vals), 0,
        "DiversionReason", HFILL }},
    { &hf_qsig_cf_originalRerouteingReason,
      { "originalRerouteingReason", "qsig.cf.originalRerouteingReason",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_DiversionReason_vals), 0,
        "DiversionReason", HFILL }},
    { &hf_qsig_cf_calledAddress,
      { "calledAddress", "qsig.cf.calledAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_qsig_cf_diversionCounter,
      { "diversionCounter", "qsig.cf.diversionCounter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_15", HFILL }},
    { &hf_qsig_cf_pSS1InfoElement,
      { "pSS1InfoElement", "qsig.cf.pSS1InfoElement",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PSS1InformationElement", HFILL }},
    { &hf_qsig_cf_lastRerouteingNr,
      { "lastRerouteingNr", "qsig.cf.lastRerouteingNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_qsig_cf_subscriptionOption,
      { "subscriptionOption", "qsig.cf.subscriptionOption",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_SubscriptionOption_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cf_callingPartySubaddress,
      { "callingPartySubaddress", "qsig.cf.callingPartySubaddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_qsig_cf_callingNumber,
      { "callingNumber", "qsig.cf.callingNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberScreened_vals), 0,
        "PresentedNumberScreened", HFILL }},
    { &hf_qsig_cf_callingName,
      { "callingName", "qsig.cf.callingName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_cf_originalCalledNr,
      { "originalCalledNr", "qsig.cf.originalCalledNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_qsig_cf_redirectingName,
      { "redirectingName", "qsig.cf.redirectingName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_cf_originalCalledName,
      { "originalCalledName", "qsig.cf.originalCalledName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_cf_extensionCRR,
      { "extension", "qsig.cf.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_CRRExtension_vals), 0,
        "CRRExtension", HFILL }},
    { &hf_qsig_cf_diversionReason,
      { "diversionReason", "qsig.cf.diversionReason",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_DiversionReason_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cf_nominatedNr,
      { "nominatedNr", "qsig.cf.nominatedNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_cf_extensionDLI1,
      { "extension", "qsig.cf.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_DLI1Extension_vals), 0,
        "DLI1Extension", HFILL }},
    { &hf_qsig_cf_originalDiversionReason,
      { "originalDiversionReason", "qsig.cf.originalDiversionReason",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_DiversionReason_vals), 0,
        "DiversionReason", HFILL }},
    { &hf_qsig_cf_divertingNr,
      { "divertingNr", "qsig.cf.divertingNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_qsig_cf_extensionDLI2,
      { "extension", "qsig.cf.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_DLI2Extension_vals), 0,
        "DLI2Extension", HFILL }},
    { &hf_qsig_cf_presentationAllowedIndicator,
      { "presentationAllowedIndicator", "qsig.cf.presentationAllowedIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_redirectionName,
      { "redirectionName", "qsig.cf.redirectionName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_cf_extensionDLI3,
      { "extension", "qsig.cf.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_DLI3Extension_vals), 0,
        "DLI3Extension", HFILL }},
    { &hf_qsig_cf_IntResultList_item,
      { "IntResult", "qsig.cf.IntResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cf_remoteEnabled,
      { "remoteEnabled", "qsig.cf.remoteEnabled",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_cf_extensionIR,
      { "extension", "qsig.cf.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_IRExtension_vals), 0,
        "IRExtension", HFILL }},

/* --- Module Path-Replacement-Operations-asn1-97 --- --- ---                 */

    { &hf_qsig_pr_qsig_pr_DummyArg_PDU,
      { "DummyArg", "qsig.pr.DummyArg",
        FT_UINT32, BASE_DEC, VALS(qsig_pr_DummyArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_pr_qsig_pr_PRProposeArg_PDU,
      { "PRProposeArg", "qsig.pr.PRProposeArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pr_qsig_pr_PRSetupArg_PDU,
      { "PRSetupArg", "qsig.pr.PRSetupArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pr_qsig_pr_DummyResult_PDU,
      { "DummyResult", "qsig.pr.DummyResult",
        FT_UINT32, BASE_DEC, VALS(qsig_pr_DummyResult_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_pr_qsig_pr_PRRetainArg_PDU,
      { "PRRetainArg", "qsig.pr.PRRetainArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pr_qsig_pr_Extension_PDU,
      { "Extension", "qsig.pr.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pr_callIdentity,
      { "callIdentity", "qsig.pr.callIdentity",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pr_rerouteingNumber,
      { "rerouteingNumber", "qsig.pr.rerouteingNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_pr_extensionPRP,
      { "extension", "qsig.pr.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_pr_PRPExtension_vals), 0,
        "PRPExtension", HFILL }},
    { &hf_qsig_pr_single,
      { "single", "qsig.pr.single_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extension", HFILL }},
    { &hf_qsig_pr_multiple,
      { "multiple", "qsig.pr.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_pr_multiple_item,
      { "Extension", "qsig.pr.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pr_extensionPRS,
      { "extension", "qsig.pr.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_pr_PRSExtension_vals), 0,
        "PRSExtension", HFILL }},
    { &hf_qsig_pr_extensionPRR,
      { "extension", "qsig.pr.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_pr_PRRExtension_vals), 0,
        "PRRExtension", HFILL }},
    { &hf_qsig_pr_null,
      { "null", "qsig.pr.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module Call-Transfer-Operations-asn1-97 --- --- ---                    */

    { &hf_qsig_ct_qsig_ct_DummyArg_PDU,
      { "DummyArg", "qsig.ct.DummyArg",
        FT_UINT32, BASE_DEC, VALS(qsig_ct_DummyArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ct_qsig_ct_CTIdentifyRes_PDU,
      { "CTIdentifyRes", "qsig.ct.CTIdentifyRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ct_qsig_ct_CTInitiateArg_PDU,
      { "CTInitiateArg", "qsig.ct.CTInitiateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ct_qsig_ct_DummyRes_PDU,
      { "DummyRes", "qsig.ct.DummyRes",
        FT_UINT32, BASE_DEC, VALS(qsig_ct_DummyRes_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ct_qsig_ct_CTSetupArg_PDU,
      { "CTSetupArg", "qsig.ct.CTSetupArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ct_qsig_ct_CTActiveArg_PDU,
      { "CTActiveArg", "qsig.ct.CTActiveArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ct_qsig_ct_CTCompleteArg_PDU,
      { "CTCompleteArg", "qsig.ct.CTCompleteArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ct_qsig_ct_CTUpdateArg_PDU,
      { "CTUpdateArg", "qsig.ct.CTUpdateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ct_qsig_ct_SubaddressTransferArg_PDU,
      { "SubaddressTransferArg", "qsig.ct.SubaddressTransferArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ct_qsig_ct_Extension_PDU,
      { "Extension", "qsig.ct.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ct_null,
      { "null", "qsig.ct.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ct_single,
      { "single", "qsig.ct.single_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extension", HFILL }},
    { &hf_qsig_ct_multiple,
      { "multiple", "qsig.ct.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_ct_multiple_item,
      { "Extension", "qsig.ct.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ct_callIdentity,
      { "callIdentity", "qsig.ct.callIdentity",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ct_rerouteingNumber,
      { "rerouteingNumber", "qsig.ct.rerouteingNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_ct_resultExtension,
      { "resultExtension", "qsig.ct.resultExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_ct_T_resultExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ct_argumentExtensionCTI,
      { "argumentExtension", "qsig.ct.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_ct_CTIargumentExtension_vals), 0,
        "CTIargumentExtension", HFILL }},
    { &hf_qsig_ct_argumentExtensionCTS,
      { "argumentExtension", "qsig.ct.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_ct_CTSargumentExtension_vals), 0,
        "CTSargumentExtension", HFILL }},
    { &hf_qsig_ct_connectedAddress,
      { "connectedAddress", "qsig.ct.connectedAddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedAddressScreened_vals), 0,
        "PresentedAddressScreened", HFILL }},
    { &hf_qsig_ct_basicCallInfoElements,
      { "basicCallInfoElements", "qsig.ct.basicCallInfoElements",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PSS1InformationElement", HFILL }},
    { &hf_qsig_ct_connectedName,
      { "connectedName", "qsig.ct.connectedName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_ct_argumentExtensionCTA,
      { "argumentExtension", "qsig.ct.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_ct_CTAargumentExtension_vals), 0,
        "CTAargumentExtension", HFILL }},
    { &hf_qsig_ct_endDesignation,
      { "endDesignation", "qsig.ct.endDesignation",
        FT_UINT32, BASE_DEC, VALS(qsig_ct_EndDesignation_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ct_redirectionNumber,
      { "redirectionNumber", "qsig.ct.redirectionNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberScreened_vals), 0,
        "PresentedNumberScreened", HFILL }},
    { &hf_qsig_ct_redirectionName,
      { "redirectionName", "qsig.ct.redirectionName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_ct_callStatus,
      { "callStatus", "qsig.ct.callStatus",
        FT_UINT32, BASE_DEC, VALS(qsig_ct_CallStatus_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ct_argumentExtensionCTC,
      { "argumentExtension", "qsig.ct.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_ct_CTCargumentExtension_vals), 0,
        "CTCargumentExtension", HFILL }},
    { &hf_qsig_ct_argumentExtensionCTU,
      { "argumentExtension", "qsig.ct.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_ct_CTUargumentExtension_vals), 0,
        "CTUargumentExtension", HFILL }},
    { &hf_qsig_ct_redirectionSubaddress,
      { "redirectionSubaddress", "qsig.ct.redirectionSubaddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_qsig_ct_argumentExtensionST,
      { "argumentExtension", "qsig.ct.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_ct_STargumentExtension_vals), 0,
        "STargumentExtension", HFILL }},

/* --- Module SS-CC-Operations-asn1-97 --- --- ---                            */

    { &hf_qsig_cc_qsig_cc_CcRequestArg_PDU,
      { "CcRequestArg", "qsig.cc.CcRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cc_qsig_cc_CcRequestRes_PDU,
      { "CcRequestRes", "qsig.cc.CcRequestRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cc_qsig_cc_CcOptionalArg_PDU,
      { "CcOptionalArg", "qsig.cc.CcOptionalArg",
        FT_UINT32, BASE_DEC, VALS(qsig_cc_CcOptionalArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cc_qsig_cc_CcExtension_PDU,
      { "CcExtension", "qsig.cc.CcExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_cc_CcExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cc_qsig_cc_Extension_PDU,
      { "Extension", "qsig.cc.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cc_numberA,
      { "numberA", "qsig.cc.numberA",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_qsig_cc_numberB,
      { "numberB", "qsig.cc.numberB",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_cc_service,
      { "service", "qsig.cc.service",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PSS1InformationElement", HFILL }},
    { &hf_qsig_cc_subaddrA,
      { "subaddrA", "qsig.cc.subaddrA",
        FT_UINT32, BASE_DEC, VALS(qsig_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_qsig_cc_subaddrB,
      { "subaddrB", "qsig.cc.subaddrB",
        FT_UINT32, BASE_DEC, VALS(qsig_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_qsig_cc_can_retain_service,
      { "can-retain-service", "qsig.cc.can_retain_service",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_cc_retain_sig_connection,
      { "retain-sig-connection", "qsig.cc.retain_sig_connection",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_cc_extension,
      { "extension", "qsig.cc.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_cc_CcExtension_vals), 0,
        "CcExtension", HFILL }},
    { &hf_qsig_cc_no_path_reservation,
      { "no-path-reservation", "qsig.cc.no_path_reservation",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_cc_retain_service,
      { "retain-service", "qsig.cc.retain_service",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_cc_fullArg,
      { "fullArg", "qsig.cc.fullArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cc_numberA_01,
      { "numberA", "qsig.cc.numberA",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_cc_extArg,
      { "extArg", "qsig.cc.extArg",
        FT_UINT32, BASE_DEC, VALS(qsig_cc_CcExtension_vals), 0,
        "CcExtension", HFILL }},
    { &hf_qsig_cc_none,
      { "none", "qsig.cc.none_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cc_single,
      { "single", "qsig.cc.single_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extension", HFILL }},
    { &hf_qsig_cc_multiple,
      { "multiple", "qsig.cc.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_cc_multiple_item,
      { "Extension", "qsig.cc.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module Call-Offer-Operations-asn1-97 --- --- ---                       */

    { &hf_qsig_co_qsig_co_PathRetainArg_PDU,
      { "PathRetainArg", "qsig.co.PathRetainArg",
        FT_UINT32, BASE_DEC, VALS(qsig_co_PathRetainArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_co_qsig_co_ServiceAvailableArg_PDU,
      { "ServiceAvailableArg", "qsig.co.ServiceAvailableArg",
        FT_UINT32, BASE_DEC, VALS(qsig_co_ServiceAvailableArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_co_qsig_co_DummyArg_PDU,
      { "DummyArg", "qsig.co.DummyArg",
        FT_UINT32, BASE_DEC, VALS(qsig_co_DummyArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_co_qsig_co_DummyRes_PDU,
      { "DummyRes", "qsig.co.DummyRes",
        FT_UINT32, BASE_DEC, VALS(qsig_co_DummyRes_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_co_qsig_co_Extension_PDU,
      { "Extension", "qsig.co.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_co_serviceList,
      { "serviceList", "qsig.co.serviceList",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_co_extendedServiceList,
      { "extendedServiceList", "qsig.co.extendedServiceList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_co_extension,
      { "extension", "qsig.co.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_co_extendedServiceList_01,
      { "extendedServiceList", "qsig.co.extendedServiceList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_extendedServiceList_01", HFILL }},
    { &hf_qsig_co_null,
      { "null", "qsig.co.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_co_sequenceOfExtn,
      { "sequenceOfExtn", "qsig.co.sequenceOfExtn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_co_sequenceOfExtn_item,
      { "Extension", "qsig.co.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_co_ServiceList_callOffer,
      { "callOffer", "qsig.co.callOffer",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},

/* --- Module Do-Not-Disturb-Operations-asn1-97 --- --- ---                   */

    { &hf_qsig_dnd_qsig_dnd_DNDActivateArg_PDU,
      { "DNDActivateArg", "qsig.dnd.DNDActivateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_qsig_dnd_DNDActivateRes_PDU,
      { "DNDActivateRes", "qsig.dnd.DNDActivateRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_qsig_dnd_DNDDeactivateArg_PDU,
      { "DNDDeactivateArg", "qsig.dnd.DNDDeactivateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_qsig_dnd_DummyRes_PDU,
      { "DummyRes", "qsig.dnd.DummyRes",
        FT_UINT32, BASE_DEC, VALS(qsig_dnd_DummyRes_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_qsig_dnd_DNDInterrogateArg_PDU,
      { "DNDInterrogateArg", "qsig.dnd.DNDInterrogateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_qsig_dnd_DNDInterrogateRes_PDU,
      { "DNDInterrogateRes", "qsig.dnd.DNDInterrogateRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_qsig_dnd_DNDOverrideArg_PDU,
      { "DNDOverrideArg", "qsig.dnd.DNDOverrideArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_qsig_dnd_PathRetainArg_PDU,
      { "PathRetainArg", "qsig.dnd.PathRetainArg",
        FT_UINT32, BASE_DEC, VALS(qsig_dnd_PathRetainArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_qsig_dnd_ServiceAvailableArg_PDU,
      { "ServiceAvailableArg", "qsig.dnd.ServiceAvailableArg",
        FT_UINT32, BASE_DEC, VALS(qsig_dnd_ServiceAvailableArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_qsig_dnd_DummyArg_PDU,
      { "DummyArg", "qsig.dnd.DummyArg",
        FT_UINT32, BASE_DEC, VALS(qsig_dnd_DummyArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_qsig_dnd_Extension_PDU,
      { "Extension", "qsig.dnd.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_null,
      { "null", "qsig.dnd.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_extension,
      { "extension", "qsig.dnd.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_sequenceOfExtn,
      { "sequenceOfExtn", "qsig.dnd.sequenceOfExtn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_dnd_sequenceOfExtn_item,
      { "Extension", "qsig.dnd.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_basicService,
      { "basicService", "qsig.dnd.basicService",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_BasicService_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_servedUserNr,
      { "servedUserNr", "qsig.dnd.servedUserNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_dnd_argumentExtensionDNDA,
      { "argumentExtension", "qsig.dnd.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_dnd_DNDAargumentExtension_vals), 0,
        "DNDAargumentExtension", HFILL }},
    { &hf_qsig_dnd_status,
      { "status", "qsig.dnd.status",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_status_item,
      { "status item", "qsig.dnd.status_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_dndProtectionLevel,
      { "dndProtectionLevel", "qsig.dnd.dndProtectionLevel",
        FT_UINT32, BASE_DEC, VALS(qsig_dnd_DNDProtectionLevel_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_resultExtension,
      { "resultExtension", "qsig.dnd.resultExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_dnd_T_resultExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_argumentExtensionDNDD,
      { "argumentExtension", "qsig.dnd.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_dnd_DNDDargumentExtension_vals), 0,
        "DNDDargumentExtension", HFILL }},
    { &hf_qsig_dnd_argumentExtensionDNDI,
      { "argumentExtension", "qsig.dnd.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_dnd_DNDIargumentExtension_vals), 0,
        "DNDIargumentExtension", HFILL }},
    { &hf_qsig_dnd_status_01,
      { "status", "qsig.dnd.status",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_status_01", HFILL }},
    { &hf_qsig_dnd_status_item_01,
      { "status item", "qsig.dnd.status_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_status_item_01", HFILL }},
    { &hf_qsig_dnd_resultExtension_01,
      { "resultExtension", "qsig.dnd.resultExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_dnd_T_resultExtension_01_vals), 0,
        "T_resultExtension_01", HFILL }},
    { &hf_qsig_dnd_dndoCapabilityLevel,
      { "dndoCapabilityLevel", "qsig.dnd.dndoCapabilityLevel",
        FT_UINT32, BASE_DEC, VALS(qsig_dnd_DNDOCapabilityLevel_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_argumentExtensionDNDO,
      { "argumentExtension", "qsig.dnd.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_dnd_DNDOargumentExtension_vals), 0,
        "DNDOargumentExtension", HFILL }},
    { &hf_qsig_dnd_serviceList,
      { "serviceList", "qsig.dnd.serviceList",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_extendedServiceList,
      { "extendedServiceList", "qsig.dnd.extendedServiceList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_dnd_extendedServiceList_01,
      { "extendedServiceList", "qsig.dnd.extendedServiceList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_extendedServiceList_01", HFILL }},
    { &hf_qsig_dnd_ServiceList_dndo_low,
      { "dndo-low", "qsig.dnd.dndo-low",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_qsig_dnd_ServiceList_dndo_medium,
      { "dndo-medium", "qsig.dnd.dndo-medium",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_qsig_dnd_ServiceList_dndo_high,
      { "dndo-high", "qsig.dnd.dndo-high",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},

/* --- Module Call-Intrusion-Operations-asn1-97 --- --- ---                   */

    { &hf_qsig_ci_qsig_ci_PathRetainArg_PDU,
      { "PathRetainArg", "qsig.ci.PathRetainArg",
        FT_UINT32, BASE_DEC, VALS(qsig_ci_PathRetainArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ci_qsig_ci_ServiceAvailableArg_PDU,
      { "ServiceAvailableArg", "qsig.ci.ServiceAvailableArg",
        FT_UINT32, BASE_DEC, VALS(qsig_ci_ServiceAvailableArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ci_qsig_ci_CIRequestArg_PDU,
      { "CIRequestArg", "qsig.ci.CIRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ci_qsig_ci_CIRequestRes_PDU,
      { "CIRequestRes", "qsig.ci.CIRequestRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ci_qsig_ci_DummyArg_PDU,
      { "DummyArg", "qsig.ci.DummyArg",
        FT_UINT32, BASE_DEC, VALS(qsig_ci_DummyArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ci_qsig_ci_CIGetCIPLRes_PDU,
      { "CIGetCIPLRes", "qsig.ci.CIGetCIPLRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ci_qsig_ci_DummyRes_PDU,
      { "DummyRes", "qsig.ci.DummyRes",
        FT_UINT32, BASE_DEC, VALS(qsig_ci_DummyRes_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ci_qsig_ci_Extension_PDU,
      { "Extension", "qsig.ci.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ci_serviceList,
      { "serviceList", "qsig.ci.serviceList",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ci_extendedServiceList,
      { "extendedServiceList", "qsig.ci.extendedServiceList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ci_extension,
      { "extension", "qsig.ci.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ci_extendedServiceList_01,
      { "extendedServiceList", "qsig.ci.extendedServiceList_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_extendedServiceList_01", HFILL }},
    { &hf_qsig_ci_null,
      { "null", "qsig.ci.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ci_sequenceOfExtn,
      { "sequenceOfExtn", "qsig.ci.sequenceOfExtn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_ci_sequenceOfExtn_item,
      { "Extension", "qsig.ci.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ci_ciCapabilityLevel,
      { "ciCapabilityLevel", "qsig.ci.ciCapabilityLevel",
        FT_UINT32, BASE_DEC, VALS(qsig_ci_CICapabilityLevel_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ci_argumentExtension,
      { "argumentExtension", "qsig.ci.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_ci_T_argumentExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ci_ciUnwantedUserStatus,
      { "ciUnwantedUserStatus", "qsig.ci.ciUnwantedUserStatus",
        FT_UINT32, BASE_DEC, VALS(qsig_ci_CIUnwantedUserStatus_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ci_resultExtension,
      { "resultExtension", "qsig.ci.resultExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_ci_T_resultExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ci_ciProtectionLevel,
      { "ciProtectionLevel", "qsig.ci.ciProtectionLevel",
        FT_UINT32, BASE_DEC, VALS(qsig_ci_CIProtectionLevel_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ci_resultExtension_01,
      { "resultExtension", "qsig.ci.resultExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_ci_T_resultExtension_01_vals), 0,
        "T_resultExtension_01", HFILL }},
    { &hf_qsig_ci_ServiceList_ci_low,
      { "ci-low", "qsig.ci.ci-low",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_qsig_ci_ServiceList_ci_medium,
      { "ci-medium", "qsig.ci.ci-medium",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_qsig_ci_ServiceList_ci_high,
      { "ci-high", "qsig.ci.ci-high",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},

/* --- Module SS-AOC-Operations-asn1-97 --- --- ---                           */

    { &hf_qsig_aoc_qsig_aoc_AocRateArg_PDU,
      { "AocRateArg", "qsig.aoc.AocRateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_qsig_aoc_AocInterimArg_PDU,
      { "AocInterimArg", "qsig.aoc.AocInterimArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_qsig_aoc_AocFinalArg_PDU,
      { "AocFinalArg", "qsig.aoc.AocFinalArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_qsig_aoc_ChargeRequestArg_PDU,
      { "ChargeRequestArg", "qsig.aoc.ChargeRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_qsig_aoc_ChargeRequestRes_PDU,
      { "ChargeRequestRes", "qsig.aoc.ChargeRequestRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_qsig_aoc_DummyArg_PDU,
      { "DummyArg", "qsig.aoc.DummyArg",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_DummyArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_qsig_aoc_AocCompleteArg_PDU,
      { "AocCompleteArg", "qsig.aoc.AocCompleteArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_qsig_aoc_AocCompleteRes_PDU,
      { "AocCompleteRes", "qsig.aoc.AocCompleteRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_qsig_aoc_AocDivChargeReqArg_PDU,
      { "AocDivChargeReqArg", "qsig.aoc.AocDivChargeReqArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_qsig_aoc_Extension_PDU,
      { "Extension", "qsig.aoc.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_aocRate,
      { "aocRate", "qsig.aoc.aocRate",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_T_aocRate_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_chargeNotAvailable,
      { "chargeNotAvailable", "qsig.aoc.chargeNotAvailable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_aocSCurrencyInfoList,
      { "aocSCurrencyInfoList", "qsig.aoc.aocSCurrencyInfoList",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_rateArgExtension,
      { "rateArgExtension", "qsig.aoc.rateArgExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_T_rateArgExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_extension,
      { "extension", "qsig.aoc.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_multipleExtension,
      { "multipleExtension", "qsig.aoc.multipleExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_aoc_multipleExtension_item,
      { "Extension", "qsig.aoc.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_interimCharge,
      { "interimCharge", "qsig.aoc.interimCharge",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_T_interimCharge_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_freeOfCharge,
      { "freeOfCharge", "qsig.aoc.freeOfCharge_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_specificCurrency,
      { "specificCurrency", "qsig.aoc.specificCurrency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_recordedCurrency,
      { "recordedCurrency", "qsig.aoc.recordedCurrency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_interimBillingId,
      { "interimBillingId", "qsig.aoc.interimBillingId",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_InterimBillingId_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_interimArgExtension,
      { "interimArgExtension", "qsig.aoc.interimArgExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_T_interimArgExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_finalCharge,
      { "finalCharge", "qsig.aoc.finalCharge",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_T_finalCharge_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_specificCurrency_01,
      { "specificCurrency", "qsig.aoc.specificCurrency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "T_specificCurrency_01", HFILL }},
    { &hf_qsig_aoc_finalBillingId,
      { "finalBillingId", "qsig.aoc.finalBillingId",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_FinalBillingId_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_chargingAssociation,
      { "chargingAssociation", "qsig.aoc.chargingAssociation",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_ChargingAssociation_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_finalArgExtension,
      { "finalArgExtension", "qsig.aoc.finalArgExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_T_finalArgExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_AOCSCurrencyInfoList_item,
      { "AOCSCurrencyInfo", "qsig.aoc.AOCSCurrencyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_chargedItem,
      { "chargedItem", "qsig.aoc.chargedItem",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_ChargedItem_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_rateType,
      { "rateType", "qsig.aoc.rateType",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_T_rateType_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_durationCurrency,
      { "durationCurrency", "qsig.aoc.durationCurrency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_flatRateCurrency,
      { "flatRateCurrency", "qsig.aoc.flatRateCurrency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_volumeRateCurrency,
      { "volumeRateCurrency", "qsig.aoc.volumeRateCurrency_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_specialChargingCode,
      { "specialChargingCode", "qsig.aoc.specialChargingCode",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_currencyInfoNotAvailable,
      { "currencyInfoNotAvailable", "qsig.aoc.currencyInfoNotAvailable_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_freeOfChargefromBeginning,
      { "freeOfChargefromBeginning", "qsig.aoc.freeOfChargefromBeginning_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_dCurrency,
      { "dCurrency", "qsig.aoc.dCurrency",
        FT_STRING, BASE_NONE, NULL, 0,
        "Currency", HFILL }},
    { &hf_qsig_aoc_dAmount,
      { "dAmount", "qsig.aoc.dAmount_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Amount", HFILL }},
    { &hf_qsig_aoc_dChargingType,
      { "dChargingType", "qsig.aoc.dChargingType",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_ChargingType_vals), 0,
        "ChargingType", HFILL }},
    { &hf_qsig_aoc_dTime,
      { "dTime", "qsig.aoc.dTime_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_qsig_aoc_dGranularity,
      { "dGranularity", "qsig.aoc.dGranularity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Time", HFILL }},
    { &hf_qsig_aoc_fRCurrency,
      { "fRCurrency", "qsig.aoc.fRCurrency",
        FT_STRING, BASE_NONE, NULL, 0,
        "Currency", HFILL }},
    { &hf_qsig_aoc_fRAmount,
      { "fRAmount", "qsig.aoc.fRAmount_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Amount", HFILL }},
    { &hf_qsig_aoc_vRCurrency,
      { "vRCurrency", "qsig.aoc.vRCurrency",
        FT_STRING, BASE_NONE, NULL, 0,
        "Currency", HFILL }},
    { &hf_qsig_aoc_vRAmount,
      { "vRAmount", "qsig.aoc.vRAmount_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Amount", HFILL }},
    { &hf_qsig_aoc_vRVolumeUnit,
      { "vRVolumeUnit", "qsig.aoc.vRVolumeUnit",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_VolumeUnit_vals), 0,
        "VolumeUnit", HFILL }},
    { &hf_qsig_aoc_rCurrency,
      { "rCurrency", "qsig.aoc.rCurrency",
        FT_STRING, BASE_NONE, NULL, 0,
        "Currency", HFILL }},
    { &hf_qsig_aoc_rAmount,
      { "rAmount", "qsig.aoc.rAmount_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Amount", HFILL }},
    { &hf_qsig_aoc_currencyAmount,
      { "currencyAmount", "qsig.aoc.currencyAmount",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_multiplier,
      { "multiplier", "qsig.aoc.multiplier",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_Multiplier_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_lengthOfTimeUnit,
      { "lengthOfTimeUnit", "qsig.aoc.lengthOfTimeUnit",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_scale,
      { "scale", "qsig.aoc.scale",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_Scale_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_chargeNumber,
      { "chargeNumber", "qsig.aoc.chargeNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_aoc_chargeIdentifier,
      { "chargeIdentifier", "qsig.aoc.chargeIdentifier",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_adviceModeCombinations,
      { "adviceModeCombinations", "qsig.aoc.adviceModeCombinations",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_0_7_OF_AdviceModeCombination", HFILL }},
    { &hf_qsig_aoc_adviceModeCombinations_item,
      { "AdviceModeCombination", "qsig.aoc.AdviceModeCombination",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_AdviceModeCombination_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_chargeReqArgExtension,
      { "chargeReqArgExtension", "qsig.aoc.chargeReqArgExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_T_chargeReqArgExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_adviceModeCombination,
      { "adviceModeCombination", "qsig.aoc.adviceModeCombination",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_AdviceModeCombination_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_chargeReqResExtension,
      { "chargeReqResExtension", "qsig.aoc.chargeReqResExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_T_chargeReqResExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_none,
      { "none", "qsig.aoc.none_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_chargedUser,
      { "chargedUser", "qsig.aoc.chargedUser",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_aoc_completeArgExtension,
      { "completeArgExtension", "qsig.aoc.completeArgExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_T_completeArgExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_chargingOption,
      { "chargingOption", "qsig.aoc.chargingOption",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_ChargingOption_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_completeResExtension,
      { "completeResExtension", "qsig.aoc.completeResExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_T_completeResExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_divertingUser,
      { "divertingUser", "qsig.aoc.divertingUser",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_aoc_diversionType,
      { "diversionType", "qsig.aoc.diversionType",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_DiversionType_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_aoc_aocDivChargeReqArgExt,
      { "aocDivChargeReqArgExt", "qsig.aoc.aocDivChargeReqArgExt",
        FT_UINT32, BASE_DEC, VALS(qsig_aoc_T_aocDivChargeReqArgExt_vals), 0,
        NULL, HFILL }},

/* --- Module Recall-Operations-asn1-97 --- --- ---                           */

    { &hf_qsig_re_qsig_re_ReAlertingArg_PDU,
      { "ReAlertingArg", "qsig.re.ReAlertingArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_re_qsig_re_ReAnswerArg_PDU,
      { "ReAnswerArg", "qsig.re.ReAnswerArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_re_alertedNumber,
      { "alertedNumber", "qsig.re.alertedNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberScreened_vals), 0,
        "PresentedNumberScreened", HFILL }},
    { &hf_qsig_re_alertedName,
      { "alertedName", "qsig.re.alertedName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_re_argumentExtension,
      { "argumentExtension", "qsig.re.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_re_T_argumentExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_re_extension,
      { "extension", "qsig.re.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_re_multipleExtension,
      { "multipleExtension", "qsig.re.multipleExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_re_multipleExtension_item,
      { "Extension", "qsig.re.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_re_connectedNumber,
      { "connectedNumber", "qsig.re.connectedNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberScreened_vals), 0,
        "PresentedNumberScreened", HFILL }},
    { &hf_qsig_re_connectedSubaddress,
      { "connectedSubaddress", "qsig.re.connectedSubaddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_qsig_re_connectedName,
      { "connectedName", "qsig.re.connectedName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_re_argumentExtension_01,
      { "argumentExtension", "qsig.re.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_re_T_argumentExtension_01_vals), 0,
        "T_argumentExtension_01", HFILL }},

/* --- Module Synchronization-Operations-asn1-97 --- --- ---                  */

    { &hf_qsig_sync_qsig_sync_SynchronizationReqArg_PDU,
      { "SynchronizationReqArg", "qsig.sync.SynchronizationReqArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sync_qsig_sync_SynchronizationReqRes_PDU,
      { "SynchronizationReqRes", "qsig.sync.SynchronizationReqRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sync_qsig_sync_SynchronizationInfoArg_PDU,
      { "SynchronizationInfoArg", "qsig.sync.SynchronizationInfoArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sync_qsig_sync_Extension_PDU,
      { "Extension", "qsig.sync.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sync_action,
      { "action", "qsig.sync.action",
        FT_INT32, BASE_DEC, VALS(qsig_sync_Action_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sync_argExtension,
      { "argExtension", "qsig.sync.argExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_sync_ArgExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sync_response,
      { "response", "qsig.sync.response",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_sync_stateinfo,
      { "stateinfo", "qsig.sync.stateinfo",
        FT_INT32, BASE_DEC, VALS(qsig_sync_T_stateinfo_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sync_extension,
      { "extension", "qsig.sync.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sync_sequOfExtn,
      { "sequOfExtn", "qsig.sync.sequOfExtn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_sync_sequOfExtn_item,
      { "Extension", "qsig.sync.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module Call-Interception-Operations-asn1-97 --- --- ---                */

    { &hf_qsig_cint_qsig_cint_CintInformation1Arg_PDU,
      { "CintInformation1Arg", "qsig.cint.CintInformation1Arg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cint_qsig_cint_CintInformation2Arg_PDU,
      { "CintInformation2Arg", "qsig.cint.CintInformation2Arg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cint_qsig_cint_CintCondArg_PDU,
      { "CintCondArg", "qsig.cint.CintCondArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cint_qsig_cint_CintExtension_PDU,
      { "CintExtension", "qsig.cint.CintExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_cint_CintExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cint_interceptionCause,
      { "interceptionCause", "qsig.cint.interceptionCause",
        FT_UINT32, BASE_DEC, VALS(qsig_cint_CintCause_vals), 0,
        "CintCause", HFILL }},
    { &hf_qsig_cint_interceptedToNumber,
      { "interceptedToNumber", "qsig.cint.interceptedToNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_cint_extension,
      { "extension", "qsig.cint.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_cint_CintExtension_vals), 0,
        "CintExtension", HFILL }},
    { &hf_qsig_cint_calledNumber,
      { "calledNumber", "qsig.cint.calledNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_qsig_cint_originalCalledNumber,
      { "originalCalledNumber", "qsig.cint.originalCalledNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_qsig_cint_calledName,
      { "calledName", "qsig.cint.calledName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_cint_originalCalledName,
      { "originalCalledName", "qsig.cint.originalCalledName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_cint_interceptionCause_01,
      { "interceptionCause", "qsig.cint.interceptionCause",
        FT_UINT32, BASE_DEC, VALS(qsig_cint_Condition_vals), 0,
        "Condition", HFILL }},
    { &hf_qsig_cint_none,
      { "none", "qsig.cint.none_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cint_single,
      { "single", "qsig.cint.single_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extension", HFILL }},
    { &hf_qsig_cint_multiple,
      { "multiple", "qsig.cint.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_cint_multiple_item,
      { "Extension", "qsig.cint.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module Common-Information-Operations-asn1-97 --- --- ---               */

    { &hf_qsig_cmn_qsig_cmn_DummyArg_PDU,
      { "DummyArg", "qsig.cmn.DummyArg",
        FT_UINT32, BASE_DEC, VALS(qsig_cmn_DummyArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cmn_qsig_cmn_CmnArg_PDU,
      { "CmnArg", "qsig.cmn.CmnArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cmn_featureIdentifier,
      { "featureIdentifier", "qsig.cmn.featureIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        "FeatureIdList", HFILL }},
    { &hf_qsig_cmn_ssDNDOprotectionLevel,
      { "ssDNDOprotectionLevel", "qsig.cmn.ssDNDOprotectionLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_qsig_cmn_ssCIprotectionLevel,
      { "ssCIprotectionLevel", "qsig.cmn.ssCIprotectionLevel",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_qsig_cmn_equipmentIdentity,
      { "equipmentIdentity", "qsig.cmn.equipmentIdentity_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "EquipmentId", HFILL }},
    { &hf_qsig_cmn_partyCategory,
      { "partyCategory", "qsig.cmn.partyCategory",
        FT_UINT32, BASE_DEC, VALS(qsig_cmn_PartyCategory_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cmn_extension,
      { "extension", "qsig.cmn.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_cmn_T_extension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cmn_single,
      { "single", "qsig.cmn.single_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extension", HFILL }},
    { &hf_qsig_cmn_multiple,
      { "multiple", "qsig.cmn.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_cmn_multiple_item,
      { "Extension", "qsig.cmn.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cmn_null,
      { "null", "qsig.cmn.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cmn_nodeId,
      { "nodeId", "qsig.cmn.nodeId",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_10", HFILL }},
    { &hf_qsig_cmn_groupId,
      { "groupId", "qsig.cmn.groupId",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_10", HFILL }},
    { &hf_qsig_cmn_unitId,
      { "unitId", "qsig.cmn.unitId",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String_SIZE_1_10", HFILL }},
    { &hf_qsig_cmn_FeatureIdList_reserved,
      { "reserved", "qsig.cmn.reserved",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCFreRoutingSupported,
      { "ssCFreRoutingSupported", "qsig.cmn.ssCFreRoutingSupported",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCTreRoutingSupported,
      { "ssCTreRoutingSupported", "qsig.cmn.ssCTreRoutingSupported",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCCBSpossible,
      { "ssCCBSpossible", "qsig.cmn.ssCCBSpossible",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCCNRpossible,
      { "ssCCNRpossible", "qsig.cmn.ssCCNRpossible",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCOsupported,
      { "ssCOsupported", "qsig.cmn.ssCOsupported",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCIforcedRelease,
      { "ssCIforcedRelease", "qsig.cmn.ssCIforcedRelease",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCIisolation,
      { "ssCIisolation", "qsig.cmn.ssCIisolation",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCIwaitOnBusy,
      { "ssCIwaitOnBusy", "qsig.cmn.ssCIwaitOnBusy",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssAOCsupportChargeRateProvAtGatewPinx,
      { "ssAOCsupportChargeRateProvAtGatewPinx", "qsig.cmn.ssAOCsupportChargeRateProvAtGatewPinx",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssAOCsupportInterimChargeProvAtGatewPinx,
      { "ssAOCsupportInterimChargeProvAtGatewPinx", "qsig.cmn.ssAOCsupportInterimChargeProvAtGatewPinx",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssAOCsupportFinalChargeProvAtGatewPinx,
      { "ssAOCsupportFinalChargeProvAtGatewPinx", "qsig.cmn.ssAOCsupportFinalChargeProvAtGatewPinx",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_anfPRsupportedAtCooperatingPinx,
      { "anfPRsupportedAtCooperatingPinx", "qsig.cmn.anfPRsupportedAtCooperatingPinx",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_anfCINTcanInterceptImmediate,
      { "anfCINTcanInterceptImmediate", "qsig.cmn.anfCINTcanInterceptImmediate",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_anfCINTcanInterceptDelayed,
      { "anfCINTcanInterceptDelayed", "qsig.cmn.anfCINTcanInterceptDelayed",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_anfWTMIreRoutingSupported,
      { "anfWTMIreRoutingSupported", "qsig.cmn.anfWTMIreRoutingSupported",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_anfPUMIreRoutingSupported,
      { "anfPUMIreRoutingSupported", "qsig.cmn.anfPUMIreRoutingSupported",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssSSCTreRoutingSupported,
      { "ssSSCTreRoutingSupported", "qsig.cmn.ssSSCTreRoutingSupported",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},

/* --- Module Call-Interruption-Operations-asn1-97 --- --- ---                */

    { &hf_qsig_cpi_qsig_cpi_CPIRequestArg_PDU,
      { "CPIRequestArg", "qsig.cpi.CPIRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cpi_qsig_cpi_CPIPRequestArg_PDU,
      { "CPIPRequestArg", "qsig.cpi.CPIPRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cpi_cpiCapabilityLevel,
      { "cpiCapabilityLevel", "qsig.cpi.cpiCapabilityLevel",
        FT_UINT32, BASE_DEC, VALS(qsig_cpi_CPICapabilityLevel_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cpi_argumentExtension,
      { "argumentExtension", "qsig.cpi.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_cpi_T_argumentExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cpi_extension,
      { "extension", "qsig.cpi.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cpi_sequenceOfExtn,
      { "sequenceOfExtn", "qsig.cpi.sequenceOfExtn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_cpi_sequenceOfExtn_item,
      { "Extension", "qsig.cpi.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cpi_cpiProtectionLevel,
      { "cpiProtectionLevel", "qsig.cpi.cpiProtectionLevel",
        FT_UINT32, BASE_DEC, VALS(qsig_cpi_CPIProtectionLevel_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cpi_argumentExtension_01,
      { "argumentExtension", "qsig.cpi.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_cpi_T_argumentExtension_01_vals), 0,
        "T_argumentExtension_01", HFILL }},

/* --- Module PUM-Registration-Operations-asn1-97 --- --- ---                 */

    { &hf_qsig_pumr_qsig_pumr_PumRegistrArg_PDU,
      { "PumRegistrArg", "qsig.pumr.PumRegistrArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_qsig_pumr_PumRegistrRes_PDU,
      { "PumRegistrRes", "qsig.pumr.PumRegistrRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_qsig_pumr_PumDelRegArg_PDU,
      { "PumDelRegArg", "qsig.pumr.PumDelRegArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_qsig_pumr_DummyRes_PDU,
      { "DummyRes", "qsig.pumr.DummyRes",
        FT_UINT32, BASE_DEC, VALS(qsig_pumr_DummyRes_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_qsig_pumr_PumDe_regArg_PDU,
      { "PumDe-regArg", "qsig.pumr.PumDe_regArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_qsig_pumr_PumInterrogArg_PDU,
      { "PumInterrogArg", "qsig.pumr.PumInterrogArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_qsig_pumr_PumInterrogRes_PDU,
      { "PumInterrogRes", "qsig.pumr.PumInterrogRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_qsig_pumr_Extension_PDU,
      { "Extension", "qsig.pumr.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_pumRUserId,
      { "pumUserId", "qsig.pumr.pumUserId",
        FT_UINT32, BASE_DEC, VALS(qsig_pumr_RpumUserId_vals), 0,
        "RpumUserId", HFILL }},
    { &hf_qsig_pumr_pumNumber,
      { "pumNumber", "qsig.pumr.pumNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_pumr_alternativeId,
      { "alternativeId", "qsig.pumr.alternativeId",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_basicService,
      { "basicService", "qsig.pumr.basicService",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_BasicService_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_hostingAddr,
      { "hostingAddr", "qsig.pumr.hostingAddr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_pumr_activatingUserAddr,
      { "activatingUserAddr", "qsig.pumr.activatingUserAddr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_pumr_serviceOption,
      { "serviceOption", "qsig.pumr.serviceOption",
        FT_UINT32, BASE_DEC, VALS(qsig_pumr_ServiceOption_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_sessionParams,
      { "sessionParams", "qsig.pumr.sessionParams_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_userPin,
      { "userPin", "qsig.pumr.userPin",
        FT_UINT32, BASE_DEC, VALS(qsig_pumr_T_userPin_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_pumUserPin,
      { "pumUserPin", "qsig.pumr.pumUserPin",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UserPin", HFILL }},
    { &hf_qsig_pumr_activatingUserPin,
      { "activatingUserPin", "qsig.pumr.activatingUserPin",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UserPin", HFILL }},
    { &hf_qsig_pumr_argExtension,
      { "argExtension", "qsig.pumr.argExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_pumr_PumrExtension_vals), 0,
        "PumrExtension", HFILL }},
    { &hf_qsig_pumr_null,
      { "null", "qsig.pumr.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_extension,
      { "extension", "qsig.pumr.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_sequOfExtn,
      { "sequOfExtn", "qsig.pumr.sequOfExtn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_pumr_sequOfExtn_item,
      { "Extension", "qsig.pumr.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_pumXUserId,
      { "pumUserId", "qsig.pumr.pumUserId",
        FT_UINT32, BASE_DEC, VALS(qsig_pumr_XpumUserId_vals), 0,
        "XpumUserId", HFILL }},
    { &hf_qsig_pumr_pumDUserId,
      { "pumUserId", "qsig.pumr.pumUserId",
        FT_UINT32, BASE_DEC, VALS(qsig_pumr_DpumUserId_vals), 0,
        "DpumUserId", HFILL }},
    { &hf_qsig_pumr_userPin_01,
      { "userPin", "qsig.pumr.userPin",
        FT_UINT32, BASE_DEC, VALS(qsig_pumr_T_userPin_01_vals), 0,
        "T_userPin_01", HFILL }},
    { &hf_qsig_pumr_pumIUserId,
      { "pumUserId", "qsig.pumr.pumUserId",
        FT_UINT32, BASE_DEC, VALS(qsig_pumr_IpumUserId_vals), 0,
        "IpumUserId", HFILL }},
    { &hf_qsig_pumr_homeInfoOnly,
      { "homeInfoOnly", "qsig.pumr.homeInfoOnly",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_pumr_userPin_02,
      { "userPin", "qsig.pumr.userPin",
        FT_UINT32, BASE_DEC, VALS(qsig_pumr_T_userPin_02_vals), 0,
        "T_userPin_02", HFILL }},
    { &hf_qsig_pumr_PumInterrogRes_item,
      { "PumInterrogRes item", "qsig.pumr.PumInterrogRes_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumr_interrogParams,
      { "interrogParams", "qsig.pumr.interrogParams_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SessionParams", HFILL }},
    { &hf_qsig_pumr_durationOfSession,
      { "durationOfSession", "qsig.pumr.durationOfSession",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_qsig_pumr_numberOfOutgCalls,
      { "numberOfOutgCalls", "qsig.pumr.numberOfOutgCalls",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},

/* --- Module Private-User-Mobility-Call-Handling-Operations-asn1-97 --- --- --- */

    { &hf_qsig_pumch_qsig_pumch_EnquiryArg_PDU,
      { "EnquiryArg", "qsig.pumch.EnquiryArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_qsig_pumch_EnquiryRes_PDU,
      { "EnquiryRes", "qsig.pumch.EnquiryRes",
        FT_UINT32, BASE_DEC, VALS(qsig_pumch_EnquiryRes_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_qsig_pumch_DivertArg_PDU,
      { "DivertArg", "qsig.pumch.DivertArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_qsig_pumch_DummyRes_PDU,
      { "DummyRes", "qsig.pumch.DummyRes",
        FT_UINT32, BASE_DEC, VALS(qsig_pumch_DummyRes_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_qsig_pumch_InformArg_PDU,
      { "InformArg", "qsig.pumch.InformArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_qsig_pumch_PumoArg_PDU,
      { "PumoArg", "qsig.pumch.PumoArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_qsig_pumch_Extension_PDU,
      { "Extension", "qsig.pumch.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_pisnNumber,
      { "pisnNumber", "qsig.pumch.pisnNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_pumch_qSIGInfoElement,
      { "qSIGInfoElement", "qsig.pumch.qSIGInfoElement",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PSS1InformationElement", HFILL }},
    { &hf_qsig_pumch_argExtension,
      { "argExtension", "qsig.pumch.argExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_pumch_PumiExtension_vals), 0,
        "PumiExtension", HFILL }},
    { &hf_qsig_pumch_hostingAddr,
      { "hostingAddr", "qsig.pumch.hostingAddr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_pumch_callingNumber,
      { "callingNumber", "qsig.pumch.callingNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberScreened_vals), 0,
        "PresentedNumberScreened", HFILL }},
    { &hf_qsig_pumch_pumIdentity,
      { "pumIdentity", "qsig.pumch.pumIdentity",
        FT_UINT32, BASE_DEC, VALS(qsig_pumch_PumIdentity_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_callingUserSub,
      { "callingUserSub", "qsig.pumch.callingUserSub",
        FT_UINT32, BASE_DEC, VALS(qsig_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_qsig_pumch_callingUserName,
      { "callingUserName", "qsig.pumch.callingUserName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_pumch_pumUserSub,
      { "pumUserSub", "qsig.pumch.pumUserSub",
        FT_UINT32, BASE_DEC, VALS(qsig_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_qsig_pumch_currLocation,
      { "currLocation", "qsig.pumch.currLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_cfuActivated,
      { "cfuActivated", "qsig.pumch.cfuActivated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_divToAddress,
      { "divToAddress", "qsig.pumch.divToAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_qsig_pumch_divOptions,
      { "divOptions", "qsig.pumch.divOptions",
        FT_UINT32, BASE_DEC, VALS(qsig_pumch_SubscriptionOption_vals), 0,
        "SubscriptionOption", HFILL }},
    { &hf_qsig_pumch_pumName,
      { "pumName", "qsig.pumch.pumName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_pumch_null,
      { "null", "qsig.pumch.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_extension,
      { "extension", "qsig.pumch.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_sequOfExtn,
      { "sequOfExtn", "qsig.pumch.sequOfExtn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_pumch_sequOfExtn_item,
      { "Extension", "qsig.pumch.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_alternativeId,
      { "alternativeId", "qsig.pumch.alternativeId",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_both,
      { "both", "qsig.pumch.both_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_destinationNumber,
      { "destinationNumber", "qsig.pumch.destinationNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_pumch_sendingComplete,
      { "sendingComplete", "qsig.pumch.sendingComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_pumch_pumoaextension,
      { "extension", "qsig.pumch.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_pumch_T_pumoaextension_vals), 0,
        "T_pumoaextension", HFILL }},
    { &hf_qsig_pumch_single,
      { "single", "qsig.pumch.single_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extension", HFILL }},
    { &hf_qsig_pumch_multiple,
      { "multiple", "qsig.pumch.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_pumch_multiple_item,
      { "Extension", "qsig.pumch.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module Single-Step-Call-Transfer-Operations-asn1-97 --- --- ---        */

    { &hf_qsig_ssct_qsig_ssct_SSCTInitiateArg_PDU,
      { "SSCTInitiateArg", "qsig.ssct.SSCTInitiateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ssct_qsig_ssct_DummyRes_PDU,
      { "DummyRes", "qsig.ssct.DummyRes",
        FT_UINT32, BASE_DEC, VALS(qsig_ssct_DummyRes_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ssct_qsig_ssct_SSCTSetupArg_PDU,
      { "SSCTSetupArg", "qsig.ssct.SSCTSetupArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ssct_qsig_ssct_DummyArg_PDU,
      { "DummyArg", "qsig.ssct.DummyArg",
        FT_UINT32, BASE_DEC, VALS(qsig_ssct_DummyArg_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_ssct_qsig_ssct_SSCTDigitInfoArg_PDU,
      { "SSCTDigitInfoArg", "qsig.ssct.SSCTDigitInfoArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ssct_qsig_ssct_Extension_PDU,
      { "Extension", "qsig.ssct.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ssct_null,
      { "null", "qsig.ssct.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ssct_single,
      { "single", "qsig.ssct.single_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extension", HFILL }},
    { &hf_qsig_ssct_multiple,
      { "multiple", "qsig.ssct.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_ssct_multiple_item,
      { "Extension", "qsig.ssct.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ssct_rerouteingNumber,
      { "rerouteingNumber", "qsig.ssct.rerouteingNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_ssct_transferredAddress,
      { "transferredAddress", "qsig.ssct.transferredAddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedAddressScreened_vals), 0,
        "PresentedAddressScreened", HFILL }},
    { &hf_qsig_ssct_awaitConnect,
      { "awaitConnect", "qsig.ssct.awaitConnect",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ssct_transferredName,
      { "transferredName", "qsig.ssct.transferredName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_ssct_transferringAddress,
      { "transferringAddress", "qsig.ssct.transferringAddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedAddressScreened_vals), 0,
        "PresentedAddressScreened", HFILL }},
    { &hf_qsig_ssct_transferringName,
      { "transferringName", "qsig.ssct.transferringName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_ssct_argumentExtensionSSCTI,
      { "argumentExtension", "qsig.ssct.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_ssct_SSCTIargumentExtension_vals), 0,
        "SSCTIargumentExtension", HFILL }},
    { &hf_qsig_ssct_argumentExtensionSSCTS,
      { "argumentExtension", "qsig.ssct.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_ssct_SSCTSargumentExtension_vals), 0,
        "SSCTSargumentExtension", HFILL }},
    { &hf_qsig_ssct_reroutingNumber,
      { "reroutingNumber", "qsig.ssct.reroutingNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_ssct_sendingComplete,
      { "sendingComplete", "qsig.ssct.sendingComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_ssct_argumentExtensionSSCTD,
      { "argumentExtension", "qsig.ssct.argumentExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_ssct_SSCTDargumentExtension_vals), 0,
        "SSCTDargumentExtension", HFILL }},

/* --- Module WTM-Location-Registration-Operations-asn1-97 --- --- ---        */

    { &hf_qsig_wtmlr_qsig_wtmlr_LocUpdArg_PDU,
      { "LocUpdArg", "qsig.wtmlr.LocUpdArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_qsig_wtmlr_DummyRes_PDU,
      { "DummyRes", "qsig.wtmlr.DummyRes",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmlr_DummyRes_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_qsig_wtmlr_LocDelArg_PDU,
      { "LocDelArg", "qsig.wtmlr.LocDelArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_qsig_wtmlr_LocDeRegArg_PDU,
      { "LocDeRegArg", "qsig.wtmlr.LocDeRegArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_qsig_wtmlr_PisnEnqArg_PDU,
      { "PisnEnqArg", "qsig.wtmlr.PisnEnqArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_qsig_wtmlr_PisnEnqRes_PDU,
      { "PisnEnqRes", "qsig.wtmlr.PisnEnqRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_qsig_wtmlr_GetRRCInfArg_PDU,
      { "GetRRCInfArg", "qsig.wtmlr.GetRRCInfArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_qsig_wtmlr_GetRRCInfRes_PDU,
      { "GetRRCInfRes", "qsig.wtmlr.GetRRCInfRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_qsig_wtmlr_LocInfoCheckArg_PDU,
      { "LocInfoCheckArg", "qsig.wtmlr.LocInfoCheckArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_qsig_wtmlr_LocInfoCheckRes_PDU,
      { "LocInfoCheckRes", "qsig.wtmlr.LocInfoCheckRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_qsig_wtmlr_Extension_PDU,
      { "Extension", "qsig.wtmlr.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_wtmUserId,
      { "wtmUserId", "qsig.wtmlr.wtmUserId",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmlr_WtmUserId_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_basicService,
      { "basicService", "qsig.wtmlr.basicService",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_BasicService_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_visitPINX,
      { "visitPINX", "qsig.wtmlr.visitPINX",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_wtmlr_argExtension,
      { "argExtension", "qsig.wtmlr.argExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmlr_LrExtension_vals), 0,
        "LrExtension", HFILL }},
    { &hf_qsig_wtmlr_null,
      { "null", "qsig.wtmlr.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_extension,
      { "extension", "qsig.wtmlr.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_sequOfExtn,
      { "sequOfExtn", "qsig.wtmlr.sequOfExtn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_wtmlr_sequOfExtn_item,
      { "Extension", "qsig.wtmlr.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_alternativeId,
      { "alternativeId", "qsig.wtmlr.alternativeId",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_resExtension,
      { "resExtension", "qsig.wtmlr.resExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmlr_LrExtension_vals), 0,
        "LrExtension", HFILL }},
    { &hf_qsig_wtmlr_rrClass,
      { "rrClass", "qsig.wtmlr.rrClass",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_checkResult,
      { "checkResult", "qsig.wtmlr.checkResult",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmlr_CheckResult_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_wtmlr_pisnNumber,
      { "pisnNumber", "qsig.wtmlr.pisnNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},

/* --- Module Wireless-Terminal-Call-Handling-Operations-asn1-97 --- --- ---  */

    { &hf_qsig_wtmch_qsig_wtmch_EnquiryArg_PDU,
      { "EnquiryArg", "qsig.wtmch.EnquiryArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_qsig_wtmch_EnquiryRes_PDU,
      { "EnquiryRes", "qsig.wtmch.EnquiryRes",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmch_EnquiryRes_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_qsig_wtmch_DivertArg_PDU,
      { "DivertArg", "qsig.wtmch.DivertArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_qsig_wtmch_DummyRes_PDU,
      { "DummyRes", "qsig.wtmch.DummyRes",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmch_DummyRes_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_qsig_wtmch_InformArg_PDU,
      { "InformArg", "qsig.wtmch.InformArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_qsig_wtmch_WtmoArg_PDU,
      { "WtmoArg", "qsig.wtmch.WtmoArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_qsig_wtmch_Extension_PDU,
      { "Extension", "qsig.wtmch.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_pisnNumber,
      { "pisnNumber", "qsig.wtmch.pisnNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_wtmch_qSIGInfoElement,
      { "qSIGInfoElement", "qsig.wtmch.qSIGInfoElement",
        FT_BYTES, BASE_NONE, NULL, 0,
        "PSS1InformationElement", HFILL }},
    { &hf_qsig_wtmch_argExtension,
      { "argExtension", "qsig.wtmch.argExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmch_WtmiExtension_vals), 0,
        "WtmiExtension", HFILL }},
    { &hf_qsig_wtmch_visitPINX,
      { "visitPINX", "qsig.wtmch.visitPINX",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_wtmch_callingNumber,
      { "callingNumber", "qsig.wtmch.callingNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberScreened_vals), 0,
        "PresentedNumberScreened", HFILL }},
    { &hf_qsig_wtmch_wtmIdentity,
      { "wtmIdentity", "qsig.wtmch.wtmIdentity",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmch_WtmIdentity_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_callingUserSub,
      { "callingUserSub", "qsig.wtmch.callingUserSub",
        FT_UINT32, BASE_DEC, VALS(qsig_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_qsig_wtmch_callingName,
      { "callingName", "qsig.wtmch.callingName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_wtmch_wtmUserSub,
      { "wtmUserSub", "qsig.wtmch.wtmUserSub",
        FT_UINT32, BASE_DEC, VALS(qsig_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_qsig_wtmch_currLocation,
      { "currLocation", "qsig.wtmch.currLocation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_cfuActivated,
      { "cfuActivated", "qsig.wtmch.cfuActivated_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_divToAddress,
      { "divToAddress", "qsig.wtmch.divToAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_qsig_wtmch_divOptions,
      { "divOptions", "qsig.wtmch.divOptions",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmch_SubscriptionOption_vals), 0,
        "SubscriptionOption", HFILL }},
    { &hf_qsig_wtmch_wtmName,
      { "wtmName", "qsig.wtmch.wtmName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_wtmch_null,
      { "null", "qsig.wtmch.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_extension,
      { "extension", "qsig.wtmch.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_sequOfExtn,
      { "sequOfExtn", "qsig.wtmch.sequOfExtn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_wtmch_sequOfExtn_item,
      { "Extension", "qsig.wtmch.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_alternativeId,
      { "alternativeId", "qsig.wtmch.alternativeId",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_both,
      { "both", "qsig.wtmch.both_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_destinationNumber,
      { "destinationNumber", "qsig.wtmch.destinationNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_wtmch_sendingComplete,
      { "sendingComplete", "qsig.wtmch.sendingComplete_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmch_wtmoaextension,
      { "extension", "qsig.wtmch.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmch_T_wtmoaextension_vals), 0,
        "T_wtmoaextension", HFILL }},
    { &hf_qsig_wtmch_single,
      { "single", "qsig.wtmch.single_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extension", HFILL }},
    { &hf_qsig_wtmch_multiple,
      { "multiple", "qsig.wtmch.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_wtmch_multiple_item,
      { "Extension", "qsig.wtmch.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module WTM-Authentication-Operations-asn1-97 --- --- ---               */

    { &hf_qsig_wtmau_qsig_wtmau_AuthWtmArg_PDU,
      { "AuthWtmArg", "qsig.wtmau.AuthWtmArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_qsig_wtmau_AuthWtmRes_PDU,
      { "AuthWtmRes", "qsig.wtmau.AuthWtmRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_qsig_wtmau_WtatParamArg_PDU,
      { "WtatParamArg", "qsig.wtmau.WtatParamArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_qsig_wtmau_WtatParamRes_PDU,
      { "WtatParamRes", "qsig.wtmau.WtatParamRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_qsig_wtmau_WtanParamArg_PDU,
      { "WtanParamArg", "qsig.wtmau.WtanParamArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_qsig_wtmau_WtanParamRes_PDU,
      { "WtanParamRes", "qsig.wtmau.WtanParamRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_qsig_wtmau_ARG_transferAuthParam_PDU,
      { "ARG-transferAuthParam", "qsig.wtmau.ARG_transferAuthParam_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_qsig_wtmau_Extension_PDU,
      { "Extension", "qsig.wtmau.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_wtmUserId,
      { "wtmUserId", "qsig.wtmau.wtmUserId",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmau_WtmUserId_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_calcWtatInfo,
      { "calcWtatInfo", "qsig.wtmau.calcWtatInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_dummyExtension,
      { "dummyExtension", "qsig.wtmau.dummyExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmau_DummyExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_autWtmResValue,
      { "autWtmResValue", "qsig.wtmau.autWtmResValue",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmau_T_autWtmResValue_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_canCompute,
      { "canCompute", "qsig.wtmau.canCompute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_authChallenge,
      { "authChallenge", "qsig.wtmau.authChallenge",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_wtatParamInfo,
      { "wtatParamInfo", "qsig.wtmau.wtatParamInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_authAlgorithm,
      { "authAlgorithm", "qsig.wtmau.authAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_pisnNumber,
      { "pisnNumber", "qsig.wtmau.pisnNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_wtmau_alternativeId,
      { "alternativeId", "qsig.wtmau.alternativeId",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_wtanParamInfo,
      { "wtanParamInfo", "qsig.wtmau.wtanParamInfo",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmau_WtanParamInfo_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_wtatParamInfoChoice,
      { "wtatParamInfoChoice", "qsig.wtmau.wtatParamInfoChoice",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmau_T_wtatParamInfoChoice_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_authSessionKeyInfo,
      { "authSessionKeyInfo", "qsig.wtmau.authSessionKeyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_authKey,
      { "authKey", "qsig.wtmau.authKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_challLen,
      { "challLen", "qsig.wtmau.challLen",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_1_8", HFILL }},
    { &hf_qsig_wtmau_calcWtanInfo,
      { "calcWtanInfo", "qsig.wtmau.calcWtanInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_authSessionKey,
      { "authSessionKey", "qsig.wtmau.authSessionKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_calculationParam,
      { "calculationParam", "qsig.wtmau.calculationParam",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_CalcWtatInfo_item,
      { "CalcWtatInfoUnit", "qsig.wtmau.CalcWtatInfoUnit_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_authResponse,
      { "authResponse", "qsig.wtmau.authResponse",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_derivedCipherKey,
      { "derivedCipherKey", "qsig.wtmau.derivedCipherKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_extension,
      { "extension", "qsig.wtmau.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_sequOfExtn,
      { "sequOfExtn", "qsig.wtmau.sequOfExtn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_wtmau_sequOfExtn_item,
      { "Extension", "qsig.wtmau.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_wtmau_authAlg,
      { "authAlg", "qsig.wtmau.authAlg",
        FT_UINT32, BASE_DEC, VALS(qsig_wtmau_DefinedIDs_vals), 0,
        "DefinedIDs", HFILL }},
    { &hf_qsig_wtmau_param,
      { "param", "qsig.wtmau.param_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module SS-SD-Operations-asn1-97 --- --- ---                            */

    { &hf_qsig_sd_qsig_sd_DisplayArg_PDU,
      { "DisplayArg", "qsig.sd.DisplayArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sd_qsig_sd_KeypadArg_PDU,
      { "KeypadArg", "qsig.sd.KeypadArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sd_qsig_sd_Extension_PDU,
      { "Extension", "qsig.sd.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sd_displayString,
      { "displayString", "qsig.sd.displayString",
        FT_UINT32, BASE_DEC, VALS(qsig_sd_DisplayString_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sd_sdextension,
      { "extension", "qsig.sd.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_sd_SDExtension_vals), 0,
        "SDExtension", HFILL }},
    { &hf_qsig_sd_displayStringNormal,
      { "displayStringNormal", "qsig.sd.displayStringNormal",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BMPStringNormal", HFILL }},
    { &hf_qsig_sd_displayStringExtended,
      { "displayStringExtended", "qsig.sd.displayStringExtended",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BMPStringExtended", HFILL }},
    { &hf_qsig_sd_keypadString,
      { "keypadString", "qsig.sd.keypadString",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BMPStringNormal", HFILL }},
    { &hf_qsig_sd_extension,
      { "extension", "qsig.sd.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sd_multipleExtension,
      { "multipleExtension", "qsig.sd.multipleExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_sd_multipleExtension_item,
      { "Extension", "qsig.sd.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module Call-Identification-and-Call-Linkage-Operations-asn1-97 --- --- --- */

    { &hf_qsig_cidl_qsig_cidl_CallIdentificationAssignArg_PDU,
      { "CallIdentificationAssignArg", "qsig.cidl.CallIdentificationAssignArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cidl_qsig_cidl_CallIdentificationUpdateArg_PDU,
      { "CallIdentificationUpdateArg", "qsig.cidl.CallIdentificationUpdateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cidl_globalCallID,
      { "globalCallID", "qsig.cidl.globalCallID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallIdentificationData", HFILL }},
    { &hf_qsig_cidl_threadID,
      { "threadID", "qsig.cidl.threadID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallIdentificationData", HFILL }},
    { &hf_qsig_cidl_legID,
      { "legID", "qsig.cidl.legID_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "CallIdentificationData", HFILL }},
    { &hf_qsig_cidl_extensiont,
      { "extension", "qsig.cidl.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_cidl_ExtensionType_vals), 0,
        "ExtensionType", HFILL }},
    { &hf_qsig_cidl_switchingSubDomainName,
      { "switchingSubDomainName", "qsig.cidl.switchingSubDomainName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cidl_linkageID,
      { "linkageID", "qsig.cidl.linkageID",
        FT_UINT32, BASE_DEC, VALS(qsig_cidl_T_linkageID_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_cidl_subDomainID,
      { "subDomainID", "qsig.cidl.subDomainID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cidl_globallyUniqueID,
      { "globallyUniqueID", "qsig.cidl.globallyUniqueID",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cidl_timeStamp,
      { "timeStamp", "qsig.cidl.timeStamp",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cidl_extension,
      { "extension", "qsig.cidl.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_cidl_sequenceOfExt,
      { "sequenceOfExt", "qsig.cidl.sequenceOfExt",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_cidl_sequenceOfExt_item,
      { "Extension", "qsig.cidl.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module Short-Message-Service-Operations-asn1-97 --- --- ---            */

    { &hf_qsig_sms_qsig_sms_SmsSubmitArg_PDU,
      { "SmsSubmitArg", "qsig.sms.SmsSubmitArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_SmsSubmitRes_PDU,
      { "SmsSubmitRes", "qsig.sms.SmsSubmitRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_SmsDeliverArg_PDU,
      { "SmsDeliverArg", "qsig.sms.SmsDeliverArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_SmsDeliverRes_PDU,
      { "SmsDeliverRes", "qsig.sms.SmsDeliverRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_SmsStatusReportArg_PDU,
      { "SmsStatusReportArg", "qsig.sms.SmsStatusReportArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_SmsStatusReportRes_PDU,
      { "SmsStatusReportRes", "qsig.sms.SmsStatusReportRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_SmsCommandArg_PDU,
      { "SmsCommandArg", "qsig.sms.SmsCommandArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_SmsCommandRes_PDU,
      { "SmsCommandRes", "qsig.sms.SmsCommandRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_ScAlertArg_PDU,
      { "ScAlertArg", "qsig.sms.ScAlertArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_DummyRes_PDU,
      { "DummyRes", "qsig.sms.DummyRes",
        FT_UINT32, BASE_DEC, VALS(qsig_sms_DummyRes_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_PAR_smsDeliverError_PDU,
      { "PAR-smsDeliverError", "qsig.sms.PAR_smsDeliverError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_PAR_smsSubmitError_PDU,
      { "PAR-smsSubmitError", "qsig.sms.PAR_smsSubmitError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_PAR_smsStatusReportError_PDU,
      { "PAR-smsStatusReportError", "qsig.sms.PAR_smsStatusReportError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_PAR_smsCommandError_PDU,
      { "PAR-smsCommandError", "qsig.sms.PAR_smsCommandError_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_qsig_sms_SmsExtension_PDU,
      { "SmsExtension", "qsig.sms.SmsExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_sms_SmsExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sms_destinationAddress,
      { "destinationAddress", "qsig.sms.destinationAddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_sms_originatingAddress,
      { "originatingAddress", "qsig.sms.originatingAddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_sms_messageReference,
      { "messageReference", "qsig.sms.messageReference",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_smSubmitParameter,
      { "smSubmitParameter", "qsig.sms.smSubmitParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_userData,
      { "userData", "qsig.sms.userData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_smsExtension,
      { "smsExtension", "qsig.sms.smsExtension",
        FT_UINT32, BASE_DEC, VALS(qsig_sms_SmsExtension_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sms_serviceCentreTimeStamp,
      { "serviceCentreTimeStamp", "qsig.sms.serviceCentreTimeStamp",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_protocolIdentifier,
      { "protocolIdentifier", "qsig.sms.protocolIdentifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_originatingName,
      { "originatingName", "qsig.sms.originatingName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_sms_smDeliverParameter,
      { "smDeliverParameter", "qsig.sms.smDeliverParameter_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_smsDeliverResponseChoice,
      { "smsDeliverResponseChoice", "qsig.sms.smsDeliverResponseChoice",
        FT_UINT32, BASE_DEC, VALS(qsig_sms_SmsDeliverResChoice_vals), 0,
        "SmsDeliverResChoice", HFILL }},
    { &hf_qsig_sms_dischargeTime,
      { "dischargeTime", "qsig.sms.dischargeTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_recipientAddress,
      { "recipientAddress", "qsig.sms.recipientAddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_sms_recipientName,
      { "recipientName", "qsig.sms.recipientName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_sms_status,
      { "status", "qsig.sms.status",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_priority,
      { "priority", "qsig.sms.priority",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_sms_moreMessagesToSend,
      { "moreMessagesToSend", "qsig.sms.moreMessagesToSend",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_sms_statusReportQualifier,
      { "statusReportQualifier", "qsig.sms.statusReportQualifier",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_sms_smsStatusReportResponseChoice,
      { "smsStatusReportResponseChoice", "qsig.sms.smsStatusReportResponseChoice",
        FT_UINT32, BASE_DEC, VALS(qsig_sms_SmsStatusReportResponseChoice_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sms_messageNumber,
      { "messageNumber", "qsig.sms.messageNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MessageReference", HFILL }},
    { &hf_qsig_sms_commandType,
      { "commandType", "qsig.sms.commandType",
        FT_UINT32, BASE_DEC, VALS(qsig_sms_CommandType_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sms_commandData,
      { "commandData", "qsig.sms.commandData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_statusReportRequest,
      { "statusReportRequest", "qsig.sms.statusReportRequest",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_sms_null,
      { "null", "qsig.sms.null_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_validityPeriod,
      { "validityPeriod", "qsig.sms.validityPeriod",
        FT_UINT32, BASE_DEC, VALS(qsig_sms_ValidityPeriod_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sms_replyPath,
      { "replyPath", "qsig.sms.replyPath",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_sms_rejectDuplicates,
      { "rejectDuplicates", "qsig.sms.rejectDuplicates",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_sms_statusReportIndication,
      { "statusReportIndication", "qsig.sms.statusReportIndication",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_sms_resChoiceSeq,
      { "resChoiceSeq", "qsig.sms.resChoiceSeq_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_single,
      { "single", "qsig.sms.single_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extension", HFILL }},
    { &hf_qsig_sms_multiple,
      { "multiple", "qsig.sms.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_sms_multiple_item,
      { "Extension", "qsig.sms.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_validityPeriodRel,
      { "validityPeriodRel", "qsig.sms.validityPeriodRel",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_validityPeriodAbs,
      { "validityPeriodAbs", "qsig.sms.validityPeriodAbs",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_validityPeriodEnh,
      { "validityPeriodEnh", "qsig.sms.validityPeriodEnh_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_singleShotSM,
      { "singleShotSM", "qsig.sms.singleShotSM",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_sms_enhancedVP,
      { "enhancedVP", "qsig.sms.enhancedVP",
        FT_UINT32, BASE_DEC, VALS(qsig_sms_EnhancedVP_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sms_validityPeriodSec,
      { "validityPeriodSec", "qsig.sms.validityPeriodSec",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_qsig_sms_validityPeriodSemi,
      { "validityPeriodSemi", "qsig.sms.validityPeriodSemi",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_userDataHeader,
      { "userDataHeader", "qsig.sms.userDataHeader",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_class,
      { "class", "qsig.sms.class",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_3", HFILL }},
    { &hf_qsig_sms_compressed,
      { "compressed", "qsig.sms.compressed",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_sms_shortMessageText,
      { "shortMessageText", "qsig.sms.shortMessageText_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_shortMessageTextType,
      { "shortMessageTextType", "qsig.sms.shortMessageTextType",
        FT_UINT32, BASE_DEC, VALS(qsig_sms_ShortMessageTextType_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sms_shortMessageTextData,
      { "shortMessageTextData", "qsig.sms.shortMessageTextData",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_UserDataHeader_item,
      { "UserDataHeaderChoice", "qsig.sms.UserDataHeaderChoice",
        FT_UINT32, BASE_DEC, VALS(qsig_sms_UserDataHeaderChoice_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sms_smscControlParameterHeader,
      { "smscControlParameterHeader", "qsig.sms.smscControlParameterHeader",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_concatenated8BitSMHeader,
      { "concatenated8BitSMHeader", "qsig.sms.concatenated8BitSMHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_concatenated16BitSMHeader,
      { "concatenated16BitSMHeader", "qsig.sms.concatenated16BitSMHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_applicationPort8BitHeader,
      { "applicationPort8BitHeader", "qsig.sms.applicationPort8BitHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_applicationPort16BitHeader,
      { "applicationPort16BitHeader", "qsig.sms.applicationPort16BitHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_dataHeaderSourceIndicator,
      { "dataHeaderSourceIndicator", "qsig.sms.dataHeaderSourceIndicator",
        FT_UINT32, BASE_DEC, VALS(qsig_sms_DataHeaderSourceIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_sms_wirelessControlHeader,
      { "wirelessControlHeader", "qsig.sms.wirelessControlHeader",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_genericUserValue,
      { "genericUserValue", "qsig.sms.genericUserValue_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_concatenated8BitSMReferenceNumber,
      { "concatenated8BitSMReferenceNumber", "qsig.sms.concatenated8BitSMReferenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_qsig_sms_maximumNumberOf8BitSMInConcatenatedSM,
      { "maximumNumberOf8BitSMInConcatenatedSM", "qsig.sms.maximumNumberOf8BitSMInConcatenatedSM",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_qsig_sms_sequenceNumberOf8BitSM,
      { "sequenceNumberOf8BitSM", "qsig.sms.sequenceNumberOf8BitSM",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_qsig_sms_concatenated16BitSMReferenceNumber,
      { "concatenated16BitSMReferenceNumber", "qsig.sms.concatenated16BitSMReferenceNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65536", HFILL }},
    { &hf_qsig_sms_maximumNumberOf16BitSMInConcatenatedSM,
      { "maximumNumberOf16BitSMInConcatenatedSM", "qsig.sms.maximumNumberOf16BitSMInConcatenatedSM",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_qsig_sms_sequenceNumberOf16BitSM,
      { "sequenceNumberOf16BitSM", "qsig.sms.sequenceNumberOf16BitSM",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_qsig_sms_destination8BitPort,
      { "destination8BitPort", "qsig.sms.destination8BitPort",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_qsig_sms_originator8BitPort,
      { "originator8BitPort", "qsig.sms.originator8BitPort",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_qsig_sms_destination16BitPort,
      { "destination16BitPort", "qsig.sms.destination16BitPort",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65536", HFILL }},
    { &hf_qsig_sms_originator16BitPort,
      { "originator16BitPort", "qsig.sms.originator16BitPort",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65536", HFILL }},
    { &hf_qsig_sms_parameterValue,
      { "parameterValue", "qsig.sms.parameterValue",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_255", HFILL }},
    { &hf_qsig_sms_genericUserData,
      { "genericUserData", "qsig.sms.genericUserData",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_qsig_sms_failureCause,
      { "failureCause", "qsig.sms.failureCause",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_sms_scAddressSaved,
      { "scAddressSaved", "qsig.sms.scAddressSaved",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_sms_SmscControlParameterHeader_sRforTransactionCompleted,
      { "sRforTransactionCompleted", "qsig.sms.sRforTransactionCompleted",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_qsig_sms_SmscControlParameterHeader_sRforPermanentError,
      { "sRforPermanentError", "qsig.sms.sRforPermanentError",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_qsig_sms_SmscControlParameterHeader_sRforTempErrorSCnotTrying,
      { "sRforTempErrorSCnotTrying", "qsig.sms.sRforTempErrorSCnotTrying",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_qsig_sms_SmscControlParameterHeader_sRforTempErrorSCstillTrying,
      { "sRforTempErrorSCstillTrying", "qsig.sms.sRforTempErrorSCstillTrying",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_qsig_sms_SmscControlParameterHeader_cancelSRRforConcatenatedSM,
      { "cancelSRRforConcatenatedSM", "qsig.sms.cancelSRRforConcatenatedSM",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_qsig_sms_SmscControlParameterHeader_includeOrigUDHintoSR,
      { "includeOrigUDHintoSR", "qsig.sms.includeOrigUDHintoSR",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},

/* --- Module SS-MCR-Operations-asn97 --- --- ---                             */

    { &hf_qsig_mcr_qsig_mcr_MCRequestArg_PDU,
      { "MCRequestArg", "qsig.mcr.MCRequestArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcr_qsig_mcr_MCRequestResult_PDU,
      { "MCRequestResult", "qsig.mcr.MCRequestResult_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcr_qsig_mcr_MCInformArg_PDU,
      { "MCInformArg", "qsig.mcr.MCInformArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcr_qsig_mcr_MCAlertingArg_PDU,
      { "MCAlertingArg", "qsig.mcr.MCAlertingArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcr_qsig_mcr_Extension_PDU,
      { "Extension", "qsig.mcr.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcr_callType,
      { "callType", "qsig.mcr.callType",
        FT_UINT32, BASE_DEC, VALS(qsig_mcr_CallType_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_mcr_retainOrigCall,
      { "retainOrigCall", "qsig.mcr.retainOrigCall",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_mcr_destinationAddress,
      { "destinationAddress", "qsig.mcr.destinationAddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedAddressUnscreened_vals), 0,
        "PresentedAddressUnscreened", HFILL }},
    { &hf_qsig_mcr_requestingAddress,
      { "requestingAddress", "qsig.mcr.requestingAddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedAddressUnscreened_vals), 0,
        "PresentedAddressUnscreened", HFILL }},
    { &hf_qsig_mcr_cooperatingAddress,
      { "cooperatingAddress", "qsig.mcr.cooperatingAddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedAddressUnscreened_vals), 0,
        "PresentedAddressUnscreened", HFILL }},
    { &hf_qsig_mcr_correlation,
      { "correlation", "qsig.mcr.correlation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcr_extensions,
      { "extensions", "qsig.mcr.extensions",
        FT_UINT32, BASE_DEC, VALS(qsig_mcr_MCRExtensions_vals), 0,
        "MCRExtensions", HFILL }},
    { &hf_qsig_mcr_basicService,
      { "basicService", "qsig.mcr.basicService",
        FT_UINT32, BASE_DEC, VALS(qsig_cf_BasicService_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_mcr_cisc,
      { "cisc", "qsig.mcr.cisc_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcr_correlationData,
      { "correlationData", "qsig.mcr.correlationData",
        FT_STRING, BASE_NONE, NULL, 0,
        "CallIdentity", HFILL }},
    { &hf_qsig_mcr_correlationReason,
      { "correlationReason", "qsig.mcr.correlationReason",
        FT_UINT32, BASE_DEC, VALS(qsig_mcr_CorrelationReason_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_mcr_none,
      { "none", "qsig.mcr.none_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcr_single,
      { "single", "qsig.mcr.single_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extension", HFILL }},
    { &hf_qsig_mcr_multiple,
      { "multiple", "qsig.mcr.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_mcr_multiple_item,
      { "Extension", "qsig.mcr.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module SS-MCM-Operations-asn1-97 --- --- ---                           */

    { &hf_qsig_mcm_qsig_mcm_MCMNewMsgArg_PDU,
      { "MCMNewMsgArg", "qsig.mcm.MCMNewMsgArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_qsig_mcm_MCMDummyRes_PDU,
      { "MCMDummyRes", "qsig.mcm.MCMDummyRes",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MCMExtensions_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_qsig_mcm_MCMNoNewMsgArg_PDU,
      { "MCMNoNewMsgArg", "qsig.mcm.MCMNoNewMsgArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_qsig_mcm_MCMUpdateArg_PDU,
      { "MCMUpdateArg", "qsig.mcm.MCMUpdateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_qsig_mcm_MCMUpdateReqArg_PDU,
      { "MCMUpdateReqArg", "qsig.mcm.MCMUpdateReqArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_qsig_mcm_MCMUpdateReqRes_PDU,
      { "MCMUpdateReqRes", "qsig.mcm.MCMUpdateReqRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_qsig_mcm_MCMServiceArg_PDU,
      { "MCMServiceArg", "qsig.mcm.MCMServiceArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_qsig_mcm_MCMInterrogateArg_PDU,
      { "MCMInterrogateArg", "qsig.mcm.MCMInterrogateArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_qsig_mcm_MCMInterrogateRes_PDU,
      { "MCMInterrogateRes", "qsig.mcm.MCMInterrogateRes_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_qsig_mcm_MCMailboxFullArg_PDU,
      { "MCMailboxFullArg", "qsig.mcm.MCMailboxFullArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_qsig_mcm_Extension_PDU,
      { "Extension", "qsig.mcm.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_partyInfo,
      { "partyInfo", "qsig.mcm.partyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_mailboxFullFor,
      { "mailboxFullFor", "qsig.mcm.mailboxFullFor",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_extensions,
      { "extensions", "qsig.mcm.extensions",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MCMExtensions_vals), 0,
        "MCMExtensions", HFILL }},
    { &hf_qsig_mcm_MailboxFullFor_item,
      { "MailboxFullPar", "qsig.mcm.MailboxFullPar_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_messageType,
      { "messageType", "qsig.mcm.messageType",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MessageType_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_capacityReached,
      { "capacityReached", "qsig.mcm.capacityReached",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_100", HFILL }},
    { &hf_qsig_mcm_mCMChange,
      { "mCMChange", "qsig.mcm.mCMChange",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MCMChange_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_activateMCM,
      { "activateMCM", "qsig.mcm.activateMCM",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MCMServiceInfo", HFILL }},
    { &hf_qsig_mcm_activateMCM_item,
      { "MCMServiceInfo", "qsig.mcm.MCMServiceInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_deactivateMCM,
      { "deactivateMCM", "qsig.mcm.deactivateMCM",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MessageType", HFILL }},
    { &hf_qsig_mcm_deactivateMCM_item,
      { "MessageType", "qsig.mcm.MessageType",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MessageType_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_setToDefaultValues,
      { "setToDefaultValues", "qsig.mcm.setToDefaultValues_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_mCMModeNew,
      { "mCMModeNew", "qsig.mcm.mCMModeNew",
        FT_INT32, BASE_DEC, VALS(qsig_mcm_MCMMode_vals), 0,
        "MCMMode", HFILL }},
    { &hf_qsig_mcm_mCMModeRetrieved,
      { "mCMModeRetrieved", "qsig.mcm.mCMModeRetrieved",
        FT_INT32, BASE_DEC, VALS(qsig_mcm_MCMMode_vals), 0,
        "MCMMode", HFILL }},
    { &hf_qsig_mcm_interrogateInfo,
      { "interrogateInfo", "qsig.mcm.interrogateInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MessageType", HFILL }},
    { &hf_qsig_mcm_interrogateInfo_item,
      { "MessageType", "qsig.mcm.MessageType",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MessageType_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_interrogateResult,
      { "interrogateResult", "qsig.mcm.interrogateResult",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_MCMServiceInfo", HFILL }},
    { &hf_qsig_mcm_interrogateResult_item,
      { "MCMServiceInfo", "qsig.mcm.MCMServiceInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_servedUserNr,
      { "servedUserNr", "qsig.mcm.servedUserNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_mcm_specificMessageType,
      { "specificMessageType", "qsig.mcm.specificMessageType",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MessageType_vals), 0,
        "MessageType", HFILL }},
    { &hf_qsig_mcm_msgCentreId,
      { "msgCentreId", "qsig.mcm.msgCentreId",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MsgCentreId_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_nrOfMessages,
      { "nrOfMessages", "qsig.mcm.nrOfMessages",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_originatingNr,
      { "originatingNr", "qsig.mcm.originatingNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_mcm_timestamp,
      { "timestamp", "qsig.mcm.timestamp",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_priority,
      { "priority", "qsig.mcm.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_9", HFILL }},
    { &hf_qsig_mcm_argumentExtMCMNew,
      { "argumentExt", "qsig.mcm.argumentExt",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MCMNewArgumentExt_vals), 0,
        "MCMNewArgumentExt", HFILL }},
    { &hf_qsig_mcm_extension,
      { "extension", "qsig.mcm.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_multipleExtension,
      { "multipleExtension", "qsig.mcm.multipleExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_mcm_multipleExtension_item,
      { "Extension", "qsig.mcm.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_argumentExtMCMNoNew,
      { "argumentExt", "qsig.mcm.argumentExt",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MCMNoNewArgumentExt_vals), 0,
        "MCMNoNewArgumentExt", HFILL }},
    { &hf_qsig_mcm_updateInfo,
      { "updateInfo", "qsig.mcm.updateInfo",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_UpdateInfo_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_moreInfoFollows,
      { "moreInfoFollows", "qsig.mcm.moreInfoFollows",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_qsig_mcm_argumentExtMCMUpdArg,
      { "argumentExt", "qsig.mcm.argumentExt",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MCMUpdArgArgumentExt_vals), 0,
        "MCMUpdArgArgumentExt", HFILL }},
    { &hf_qsig_mcm_MCMUpdateReqRes_item,
      { "MCMUpdateReqResElt", "qsig.mcm.MCMUpdateReqResElt_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_argumentExtMCMUpdRes,
      { "argumentExt", "qsig.mcm.argumentExt",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MCMUpdResArgumentExt_vals), 0,
        "MCMUpdResArgumentExt", HFILL }},
    { &hf_qsig_mcm_messageCentreID,
      { "messageCentreID", "qsig.mcm.messageCentreID",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MsgCentreId_vals), 0,
        "MsgCentreId", HFILL }},
    { &hf_qsig_mcm_newMsgInfoOnly,
      { "newMsgInfoOnly", "qsig.mcm.newMsgInfoOnly",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MessageInfo_vals), 0,
        "MessageInfo", HFILL }},
    { &hf_qsig_mcm_retrievedMsgInfoOnly,
      { "retrievedMsgInfoOnly", "qsig.mcm.retrievedMsgInfoOnly",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MessageInfo_vals), 0,
        "MessageInfo", HFILL }},
    { &hf_qsig_mcm_allMsgInfo,
      { "allMsgInfo", "qsig.mcm.allMsgInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_newMsgInfo,
      { "newMsgInfo", "qsig.mcm.newMsgInfo",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MessageInfo_vals), 0,
        "MessageInfo", HFILL }},
    { &hf_qsig_mcm_retrievedMsgInfo,
      { "retrievedMsgInfo", "qsig.mcm.retrievedMsgInfo",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MessageInfo_vals), 0,
        "MessageInfo", HFILL }},
    { &hf_qsig_mcm_completeInfo,
      { "completeInfo", "qsig.mcm.completeInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_compressedInfo,
      { "compressedInfo", "qsig.mcm.compressedInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_noMsgsOfMsgType,
      { "noMsgsOfMsgType", "qsig.mcm.noMsgsOfMsgType_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_CompleteInfo_item,
      { "AddressHeader", "qsig.mcm.AddressHeader_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_originatorNr,
      { "originatorNr", "qsig.mcm.originatorNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_qsig_mcm_timeStamp,
      { "timeStamp", "qsig.mcm.timeStamp",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_ahpriority,
      { "priority", "qsig.mcm.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_lastTimeStamp,
      { "lastTimeStamp", "qsig.mcm.lastTimeStamp",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeStamp", HFILL }},
    { &hf_qsig_mcm_highestPriority,
      { "highestPriority", "qsig.mcm.highestPriority",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Priority", HFILL }},
    { &hf_qsig_mcm_integer,
      { "integer", "qsig.mcm.integer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER_0_65535", HFILL }},
    { &hf_qsig_mcm_partyNumber,
      { "partyNumber", "qsig.mcm.partyNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_numericString,
      { "numericString", "qsig.mcm.numericString",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumericString_SIZE_1_10", HFILL }},
    { &hf_qsig_mcm_none,
      { "none", "qsig.mcm.none_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/* --- Module SS-MID-Operations-asn1-97 --- --- ---                           */

    { &hf_qsig_mid_qsig_mid_MIDMailboxAuthArg_PDU,
      { "MIDMailboxAuthArg", "qsig.mid.MIDMailboxAuthArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mid_qsig_mid_MIDDummyRes_PDU,
      { "MIDDummyRes", "qsig.mid.MIDDummyRes",
        FT_UINT32, BASE_DEC, VALS(qsig_mid_MIDExtensions_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_mid_qsig_mid_MIDMailboxIDArg_PDU,
      { "MIDMailboxIDArg", "qsig.mid.MIDMailboxIDArg_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mid_qsig_mid_Extension_PDU,
      { "Extension", "qsig.mid.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mid_partyInfo,
      { "partyInfo", "qsig.mid.partyInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mid_servedUserName,
      { "servedUserName", "qsig.mid.servedUserName",
        FT_UINT32, BASE_DEC, VALS(qsig_na_Name_vals), 0,
        "Name", HFILL }},
    { &hf_qsig_mid_mailBox,
      { "mailBox", "qsig.mid.mailBox",
        FT_UINT32, BASE_DEC, VALS(qsig_mid_String_vals), 0,
        "String", HFILL }},
    { &hf_qsig_mid_password,
      { "password", "qsig.mid.password",
        FT_UINT32, BASE_DEC, VALS(qsig_mid_String_vals), 0,
        "String", HFILL }},
    { &hf_qsig_mid_extensions,
      { "extensions", "qsig.mid.extensions",
        FT_UINT32, BASE_DEC, VALS(qsig_mid_MIDExtensions_vals), 0,
        "MIDExtensions", HFILL }},
    { &hf_qsig_mid_servedUserNr,
      { "servedUserNr", "qsig.mid.servedUserNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedAddressUnscreened_vals), 0,
        "PresentedAddressUnscreened", HFILL }},
    { &hf_qsig_mid_messageType,
      { "messageType", "qsig.mid.messageType",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MessageType_vals), 0,
        NULL, HFILL }},
    { &hf_qsig_mid_messageCentreID,
      { "messageCentreID", "qsig.mid.messageCentreID",
        FT_UINT32, BASE_DEC, VALS(qsig_mcm_MsgCentreId_vals), 0,
        "MsgCentreId", HFILL }},
    { &hf_qsig_mid_stringBmp,
      { "stringBmp", "qsig.mid.stringBmp",
        FT_STRING, BASE_NONE, NULL, 0,
        "BMPString", HFILL }},
    { &hf_qsig_mid_stringUtf8,
      { "stringUtf8", "qsig.mid.stringUtf8",
        FT_STRING, BASE_NONE, NULL, 0,
        "UTF8String", HFILL }},
    { &hf_qsig_mid_none,
      { "none", "qsig.mid.none_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mid_extension,
      { "extension", "qsig.mid.extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mid_multipleExtension,
      { "multipleExtension", "qsig.mid.multipleExtension",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_mid_multipleExtension_item,
      { "Extension", "qsig.mid.Extension_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-qsig-hfarr.c ---*/
#line 660 "../../asn1/qsig/packet-qsig-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_qsig,
    &ett_qsig_ie,
    &ett_qsig_unknown_extension,

/*--- Included file: packet-qsig-ettarr.c ---*/
#line 1 "../../asn1/qsig/packet-qsig-ettarr.c"

/* --- Modules Manufacturer-specific-service-extension-class-asn1-97 PSS1-generic-parameters-definition-asn1-97 Addressing-Data-Elements-asn1-97 --- --- --- */

    &ett_qsig_Extension,
    &ett_qsig_PresentedAddressScreened,
    &ett_qsig_PresentedAddressUnscreened,
    &ett_qsig_PresentedNumberScreened,
    &ett_qsig_PresentedNumberUnscreened,
    &ett_qsig_AddressScreened,
    &ett_qsig_NumberScreened,
    &ett_qsig_Address,
    &ett_qsig_PartyNumber,
    &ett_qsig_PublicPartyNumber,
    &ett_qsig_PrivatePartyNumber,
    &ett_qsig_PartySubaddress,
    &ett_qsig_UserSpecifiedSubaddress,

/* --- Module Name-Operations-asn1-97 --- --- ---                             */

    &ett_qsig_na_NameArg,
    &ett_qsig_na_T_nameSequence,
    &ett_qsig_na_NameExtension,
    &ett_qsig_na_SEQUENCE_OF_Extension,
    &ett_qsig_na_Name,
    &ett_qsig_na_NamePresentationAllowed,
    &ett_qsig_na_NamePresentationRestricted,
    &ett_qsig_na_NameSet,

/* --- Module Call-Diversion-Operations-asn1-97 --- --- ---                   */

    &ett_qsig_cf_ARG_activateDiversionQ,
    &ett_qsig_cf_ADExtension,
    &ett_qsig_cf_SEQUENCE_OF_Extension,
    &ett_qsig_cf_RES_activateDiversionQ,
    &ett_qsig_cf_ARG_deactivateDiversionQ,
    &ett_qsig_cf_DDExtension,
    &ett_qsig_cf_RES_deactivateDiversionQ,
    &ett_qsig_cf_ARG_interrogateDiversionQ,
    &ett_qsig_cf_IDExtension,
    &ett_qsig_cf_ARG_checkRestriction,
    &ett_qsig_cf_CHRExtension,
    &ett_qsig_cf_RES_checkRestriction,
    &ett_qsig_cf_ARG_callRerouteing,
    &ett_qsig_cf_CRRExtension,
    &ett_qsig_cf_RES_callRerouteing,
    &ett_qsig_cf_ARG_divertingLegInformation1,
    &ett_qsig_cf_DLI1Extension,
    &ett_qsig_cf_ARG_divertingLegInformation2,
    &ett_qsig_cf_DLI2Extension,
    &ett_qsig_cf_ARG_divertingLegInformation3,
    &ett_qsig_cf_DLI3Extension,
    &ett_qsig_cf_ARG_cfnrDivertedLegFailed,
    &ett_qsig_cf_IntResultList,
    &ett_qsig_cf_IntResult,
    &ett_qsig_cf_IRExtension,

/* --- Module Path-Replacement-Operations-asn1-97 --- --- ---                 */

    &ett_qsig_pr_PRProposeArg,
    &ett_qsig_pr_PRPExtension,
    &ett_qsig_pr_SEQUENCE_OF_Extension,
    &ett_qsig_pr_PRSetupArg,
    &ett_qsig_pr_PRSExtension,
    &ett_qsig_pr_PRRetainArg,
    &ett_qsig_pr_PRRExtension,
    &ett_qsig_pr_DummyResult,
    &ett_qsig_pr_DummyArg,

/* --- Module Call-Transfer-Operations-asn1-97 --- --- ---                    */

    &ett_qsig_ct_DummyArg,
    &ett_qsig_ct_SEQUENCE_OF_Extension,
    &ett_qsig_ct_DummyRes,
    &ett_qsig_ct_CTIdentifyRes,
    &ett_qsig_ct_T_resultExtension,
    &ett_qsig_ct_CTInitiateArg,
    &ett_qsig_ct_CTIargumentExtension,
    &ett_qsig_ct_CTSetupArg,
    &ett_qsig_ct_CTSargumentExtension,
    &ett_qsig_ct_CTActiveArg,
    &ett_qsig_ct_CTAargumentExtension,
    &ett_qsig_ct_CTCompleteArg,
    &ett_qsig_ct_CTCargumentExtension,
    &ett_qsig_ct_CTUpdateArg,
    &ett_qsig_ct_CTUargumentExtension,
    &ett_qsig_ct_SubaddressTransferArg,
    &ett_qsig_ct_STargumentExtension,

/* --- Module SS-CC-Operations-asn1-97 --- --- ---                            */

    &ett_qsig_cc_CcRequestArg,
    &ett_qsig_cc_CcRequestRes,
    &ett_qsig_cc_CcOptionalArg,
    &ett_qsig_cc_T_fullArg,
    &ett_qsig_cc_CcExtension,
    &ett_qsig_cc_SEQUENCE_OF_Extension,

/* --- Module Call-Offer-Operations-asn1-97 --- --- ---                       */

    &ett_qsig_co_PathRetainArg,
    &ett_qsig_co_T_extendedServiceList,
    &ett_qsig_co_ServiceAvailableArg,
    &ett_qsig_co_T_extendedServiceList_01,
    &ett_qsig_co_ServiceList,
    &ett_qsig_co_DummyArg,
    &ett_qsig_co_SEQUENCE_OF_Extension,
    &ett_qsig_co_DummyRes,

/* --- Module Do-Not-Disturb-Operations-asn1-97 --- --- ---                   */

    &ett_qsig_dnd_DummyArg,
    &ett_qsig_dnd_SEQUENCE_OF_Extension,
    &ett_qsig_dnd_DummyRes,
    &ett_qsig_dnd_DNDActivateArg,
    &ett_qsig_dnd_DNDAargumentExtension,
    &ett_qsig_dnd_DNDActivateRes,
    &ett_qsig_dnd_T_status,
    &ett_qsig_dnd_T_status_item,
    &ett_qsig_dnd_T_resultExtension,
    &ett_qsig_dnd_DNDDeactivateArg,
    &ett_qsig_dnd_DNDDargumentExtension,
    &ett_qsig_dnd_DNDInterrogateArg,
    &ett_qsig_dnd_DNDIargumentExtension,
    &ett_qsig_dnd_DNDInterrogateRes,
    &ett_qsig_dnd_T_status_01,
    &ett_qsig_dnd_T_status_item_01,
    &ett_qsig_dnd_T_resultExtension_01,
    &ett_qsig_dnd_DNDOverrideArg,
    &ett_qsig_dnd_DNDOargumentExtension,
    &ett_qsig_dnd_PathRetainArg,
    &ett_qsig_dnd_T_extendedServiceList,
    &ett_qsig_dnd_ServiceAvailableArg,
    &ett_qsig_dnd_T_extendedServiceList_01,
    &ett_qsig_dnd_ServiceList,

/* --- Module Call-Intrusion-Operations-asn1-97 --- --- ---                   */

    &ett_qsig_ci_PathRetainArg,
    &ett_qsig_ci_T_extendedServiceList,
    &ett_qsig_ci_ServiceAvailableArg,
    &ett_qsig_ci_T_extendedServiceList_01,
    &ett_qsig_ci_ServiceList,
    &ett_qsig_ci_DummyArg,
    &ett_qsig_ci_SEQUENCE_OF_Extension,
    &ett_qsig_ci_DummyRes,
    &ett_qsig_ci_CIRequestArg,
    &ett_qsig_ci_T_argumentExtension,
    &ett_qsig_ci_CIRequestRes,
    &ett_qsig_ci_T_resultExtension,
    &ett_qsig_ci_CIGetCIPLRes,
    &ett_qsig_ci_T_resultExtension_01,

/* --- Module SS-AOC-Operations-asn1-97 --- --- ---                           */

    &ett_qsig_aoc_AocRateArg,
    &ett_qsig_aoc_T_aocRate,
    &ett_qsig_aoc_T_rateArgExtension,
    &ett_qsig_aoc_SEQUENCE_OF_Extension,
    &ett_qsig_aoc_AocInterimArg,
    &ett_qsig_aoc_T_interimCharge,
    &ett_qsig_aoc_T_specificCurrency,
    &ett_qsig_aoc_T_interimArgExtension,
    &ett_qsig_aoc_AocFinalArg,
    &ett_qsig_aoc_T_finalCharge,
    &ett_qsig_aoc_T_specificCurrency_01,
    &ett_qsig_aoc_T_finalArgExtension,
    &ett_qsig_aoc_AOCSCurrencyInfoList,
    &ett_qsig_aoc_AOCSCurrencyInfo,
    &ett_qsig_aoc_T_rateType,
    &ett_qsig_aoc_DurationCurrency,
    &ett_qsig_aoc_FlatRateCurrency,
    &ett_qsig_aoc_VolumeRateCurrency,
    &ett_qsig_aoc_RecordedCurrency,
    &ett_qsig_aoc_Amount,
    &ett_qsig_aoc_Time,
    &ett_qsig_aoc_ChargingAssociation,
    &ett_qsig_aoc_ChargeRequestArg,
    &ett_qsig_aoc_SEQUENCE_SIZE_0_7_OF_AdviceModeCombination,
    &ett_qsig_aoc_T_chargeReqArgExtension,
    &ett_qsig_aoc_ChargeRequestRes,
    &ett_qsig_aoc_T_chargeReqResExtension,
    &ett_qsig_aoc_DummyArg,
    &ett_qsig_aoc_AocCompleteArg,
    &ett_qsig_aoc_T_completeArgExtension,
    &ett_qsig_aoc_AocCompleteRes,
    &ett_qsig_aoc_T_completeResExtension,
    &ett_qsig_aoc_AocDivChargeReqArg,
    &ett_qsig_aoc_T_aocDivChargeReqArgExt,

/* --- Module Recall-Operations-asn1-97 --- --- ---                           */

    &ett_qsig_re_ReAlertingArg,
    &ett_qsig_re_T_argumentExtension,
    &ett_qsig_re_SEQUENCE_OF_Extension,
    &ett_qsig_re_ReAnswerArg,
    &ett_qsig_re_T_argumentExtension_01,

/* --- Module Synchronization-Operations-asn1-97 --- --- ---                  */

    &ett_qsig_sync_SynchronizationReqArg,
    &ett_qsig_sync_SynchronizationReqRes,
    &ett_qsig_sync_SynchronizationInfoArg,
    &ett_qsig_sync_ArgExtension,
    &ett_qsig_sync_SEQUENCE_OF_Extension,

/* --- Module Call-Interception-Operations-asn1-97 --- --- ---                */

    &ett_qsig_cint_CintInformation1Arg,
    &ett_qsig_cint_CintInformation2Arg,
    &ett_qsig_cint_CintCondArg,
    &ett_qsig_cint_CintExtension,
    &ett_qsig_cint_SEQUENCE_OF_Extension,

/* --- Module Common-Information-Operations-asn1-97 --- --- ---               */

    &ett_qsig_cmn_CmnArg,
    &ett_qsig_cmn_T_extension,
    &ett_qsig_cmn_SEQUENCE_OF_Extension,
    &ett_qsig_cmn_DummyArg,
    &ett_qsig_cmn_FeatureIdList,
    &ett_qsig_cmn_EquipmentId,

/* --- Module Call-Interruption-Operations-asn1-97 --- --- ---                */

    &ett_qsig_cpi_CPIRequestArg,
    &ett_qsig_cpi_T_argumentExtension,
    &ett_qsig_cpi_SEQUENCE_OF_Extension,
    &ett_qsig_cpi_CPIPRequestArg,
    &ett_qsig_cpi_T_argumentExtension_01,

/* --- Module PUM-Registration-Operations-asn1-97 --- --- ---                 */

    &ett_qsig_pumr_PumRegistrArg,
    &ett_qsig_pumr_RpumUserId,
    &ett_qsig_pumr_T_userPin,
    &ett_qsig_pumr_PumRegistrRes,
    &ett_qsig_pumr_DummyRes,
    &ett_qsig_pumr_SEQUENCE_OF_Extension,
    &ett_qsig_pumr_PumDelRegArg,
    &ett_qsig_pumr_XpumUserId,
    &ett_qsig_pumr_PumDe_regArg,
    &ett_qsig_pumr_DpumUserId,
    &ett_qsig_pumr_T_userPin_01,
    &ett_qsig_pumr_PumInterrogArg,
    &ett_qsig_pumr_IpumUserId,
    &ett_qsig_pumr_T_userPin_02,
    &ett_qsig_pumr_PumInterrogRes,
    &ett_qsig_pumr_PumInterrogRes_item,
    &ett_qsig_pumr_SessionParams,
    &ett_qsig_pumr_PumrExtension,

/* --- Module Private-User-Mobility-Call-Handling-Operations-asn1-97 --- --- --- */

    &ett_qsig_pumch_EnquiryArg,
    &ett_qsig_pumch_DivertArg,
    &ett_qsig_pumch_InformArg,
    &ett_qsig_pumch_EnquiryRes,
    &ett_qsig_pumch_CurrLocation,
    &ett_qsig_pumch_CfuActivated,
    &ett_qsig_pumch_DummyRes,
    &ett_qsig_pumch_SEQUENCE_OF_Extension,
    &ett_qsig_pumch_PumiExtension,
    &ett_qsig_pumch_PumIdentity,
    &ett_qsig_pumch_T_both,
    &ett_qsig_pumch_PumoArg,
    &ett_qsig_pumch_T_pumoaextension,

/* --- Module Single-Step-Call-Transfer-Operations-asn1-97 --- --- ---        */

    &ett_qsig_ssct_DummyArg,
    &ett_qsig_ssct_SEQUENCE_OF_Extension,
    &ett_qsig_ssct_DummyRes,
    &ett_qsig_ssct_SSCTInitiateArg,
    &ett_qsig_ssct_SSCTIargumentExtension,
    &ett_qsig_ssct_SSCTSetupArg,
    &ett_qsig_ssct_SSCTSargumentExtension,
    &ett_qsig_ssct_SSCTDigitInfoArg,
    &ett_qsig_ssct_SSCTDargumentExtension,

/* --- Module WTM-Location-Registration-Operations-asn1-97 --- --- ---        */

    &ett_qsig_wtmlr_LocUpdArg,
    &ett_qsig_wtmlr_DummyRes,
    &ett_qsig_wtmlr_SEQUENCE_OF_Extension,
    &ett_qsig_wtmlr_LocDelArg,
    &ett_qsig_wtmlr_LocDeRegArg,
    &ett_qsig_wtmlr_PisnEnqArg,
    &ett_qsig_wtmlr_PisnEnqRes,
    &ett_qsig_wtmlr_GetRRCInfArg,
    &ett_qsig_wtmlr_GetRRCInfRes,
    &ett_qsig_wtmlr_LocInfoCheckArg,
    &ett_qsig_wtmlr_LocInfoCheckRes,
    &ett_qsig_wtmlr_WtmUserId,
    &ett_qsig_wtmlr_LrExtension,

/* --- Module Wireless-Terminal-Call-Handling-Operations-asn1-97 --- --- ---  */

    &ett_qsig_wtmch_EnquiryArg,
    &ett_qsig_wtmch_DivertArg,
    &ett_qsig_wtmch_InformArg,
    &ett_qsig_wtmch_EnquiryRes,
    &ett_qsig_wtmch_CurrLocation,
    &ett_qsig_wtmch_CfuActivated,
    &ett_qsig_wtmch_DummyRes,
    &ett_qsig_wtmch_SEQUENCE_OF_Extension,
    &ett_qsig_wtmch_WtmiExtension,
    &ett_qsig_wtmch_WtmIdentity,
    &ett_qsig_wtmch_T_both,
    &ett_qsig_wtmch_WtmoArg,
    &ett_qsig_wtmch_T_wtmoaextension,

/* --- Module WTM-Authentication-Operations-asn1-97 --- --- ---               */

    &ett_qsig_wtmau_AuthWtmArg,
    &ett_qsig_wtmau_AuthWtmRes,
    &ett_qsig_wtmau_WtatParamArg,
    &ett_qsig_wtmau_WtatParamRes,
    &ett_qsig_wtmau_WtanParamArg,
    &ett_qsig_wtmau_WtmUserId,
    &ett_qsig_wtmau_WtanParamRes,
    &ett_qsig_wtmau_ARG_transferAuthParam,
    &ett_qsig_wtmau_WtatParamInfo,
    &ett_qsig_wtmau_T_wtatParamInfoChoice,
    &ett_qsig_wtmau_WtanParamInfo,
    &ett_qsig_wtmau_AuthSessionKeyInfo,
    &ett_qsig_wtmau_CalcWtatInfo,
    &ett_qsig_wtmau_CalcWtatInfoUnit,
    &ett_qsig_wtmau_CalcWtanInfo,
    &ett_qsig_wtmau_DummyExtension,
    &ett_qsig_wtmau_SEQUENCE_OF_Extension,
    &ett_qsig_wtmau_AuthAlgorithm,

/* --- Module SS-SD-Operations-asn1-97 --- --- ---                            */

    &ett_qsig_sd_DisplayArg,
    &ett_qsig_sd_DisplayString,
    &ett_qsig_sd_KeypadArg,
    &ett_qsig_sd_SDExtension,
    &ett_qsig_sd_SEQUENCE_OF_Extension,

/* --- Module Call-Identification-and-Call-Linkage-Operations-asn1-97 --- --- --- */

    &ett_qsig_cidl_CallIdentificationAssignArg,
    &ett_qsig_cidl_CallIdentificationUpdateArg,
    &ett_qsig_cidl_CallIdentificationData,
    &ett_qsig_cidl_T_linkageID,
    &ett_qsig_cidl_ExtensionType,
    &ett_qsig_cidl_SEQUENCE_OF_Extension,

/* --- Module Short-Message-Service-Operations-asn1-97 --- --- ---            */

    &ett_qsig_sms_SmsSubmitArg,
    &ett_qsig_sms_SmsSubmitRes,
    &ett_qsig_sms_SmsDeliverArg,
    &ett_qsig_sms_SmsDeliverRes,
    &ett_qsig_sms_SmsStatusReportArg,
    &ett_qsig_sms_SmsStatusReportRes,
    &ett_qsig_sms_SmsCommandArg,
    &ett_qsig_sms_SmsCommandRes,
    &ett_qsig_sms_ScAlertArg,
    &ett_qsig_sms_DummyRes,
    &ett_qsig_sms_SmSubmitParameter,
    &ett_qsig_sms_SmDeliverParameter,
    &ett_qsig_sms_SmsDeliverResChoice,
    &ett_qsig_sms_ResChoiceSeq,
    &ett_qsig_sms_SmsStatusReportResponseChoice,
    &ett_qsig_sms_SmsExtension,
    &ett_qsig_sms_SEQUENCE_OF_Extension,
    &ett_qsig_sms_ValidityPeriod,
    &ett_qsig_sms_ValidityPeriodEnh,
    &ett_qsig_sms_EnhancedVP,
    &ett_qsig_sms_UserData,
    &ett_qsig_sms_ShortMessageText,
    &ett_qsig_sms_UserDataHeader,
    &ett_qsig_sms_UserDataHeaderChoice,
    &ett_qsig_sms_SmscControlParameterHeader,
    &ett_qsig_sms_Concatenated8BitSMHeader,
    &ett_qsig_sms_Concatenated16BitSMHeader,
    &ett_qsig_sms_ApplicationPort8BitHeader,
    &ett_qsig_sms_ApplicationPort16BitHeader,
    &ett_qsig_sms_GenericUserValue,
    &ett_qsig_sms_PAR_smsDeliverError,
    &ett_qsig_sms_PAR_smsSubmitError,
    &ett_qsig_sms_PAR_smsStatusReportError,
    &ett_qsig_sms_PAR_smsCommandError,

/* --- Module SS-MCR-Operations-asn97 --- --- ---                             */

    &ett_qsig_mcr_MCRequestArg,
    &ett_qsig_mcr_MCRequestResult,
    &ett_qsig_mcr_MCInformArg,
    &ett_qsig_mcr_MCAlertingArg,
    &ett_qsig_mcr_CallType,
    &ett_qsig_mcr_Correlation,
    &ett_qsig_mcr_MCRExtensions,
    &ett_qsig_mcr_SEQUENCE_OF_Extension,

/* --- Module SS-MCM-Operations-asn1-97 --- --- ---                           */

    &ett_qsig_mcm_MCMailboxFullArg,
    &ett_qsig_mcm_MailboxFullFor,
    &ett_qsig_mcm_MailboxFullPar,
    &ett_qsig_mcm_MCMServiceArg,
    &ett_qsig_mcm_MCMChange,
    &ett_qsig_mcm_SEQUENCE_OF_MCMServiceInfo,
    &ett_qsig_mcm_SEQUENCE_OF_MessageType,
    &ett_qsig_mcm_MCMServiceInfo,
    &ett_qsig_mcm_MCMInterrogateArg,
    &ett_qsig_mcm_MCMInterrogateRes,
    &ett_qsig_mcm_MCMNewMsgArg,
    &ett_qsig_mcm_MCMNewArgumentExt,
    &ett_qsig_mcm_SEQUENCE_OF_Extension,
    &ett_qsig_mcm_MCMNoNewMsgArg,
    &ett_qsig_mcm_MCMNoNewArgumentExt,
    &ett_qsig_mcm_MCMUpdateArg,
    &ett_qsig_mcm_MCMUpdateReqArg,
    &ett_qsig_mcm_MCMUpdArgArgumentExt,
    &ett_qsig_mcm_MCMUpdateReqRes,
    &ett_qsig_mcm_MCMUpdateReqResElt,
    &ett_qsig_mcm_MCMUpdResArgumentExt,
    &ett_qsig_mcm_PartyInfo,
    &ett_qsig_mcm_UpdateInfo,
    &ett_qsig_mcm_AllMsgInfo,
    &ett_qsig_mcm_MessageInfo,
    &ett_qsig_mcm_CompleteInfo,
    &ett_qsig_mcm_AddressHeader,
    &ett_qsig_mcm_CompressedInfo,
    &ett_qsig_mcm_MsgCentreId,
    &ett_qsig_mcm_MCMExtensions,

/* --- Module SS-MID-Operations-asn1-97 --- --- ---                           */

    &ett_qsig_mid_MIDMailboxAuthArg,
    &ett_qsig_mid_MIDMailboxIDArg,
    &ett_qsig_mid_PartyInfo,
    &ett_qsig_mid_String,
    &ett_qsig_mid_MIDExtensions,
    &ett_qsig_mid_SEQUENCE_OF_Extension,

/*--- End of included file: packet-qsig-ettarr.c ---*/
#line 668 "../../asn1/qsig/packet-qsig-template.c"
    &ett_cnq_PSS1InformationElement,
  };

  /* Register protocol and dissector */
  proto_qsig = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_qsig, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register dissector tables */
  extension_dissector_table = register_dissector_table("qsig.ext", "QSIG Extension", FT_STRING, BASE_NONE);

  qsig_init_tables();
}


/*--- proto_reg_handoff_qsig ------------------------------------------------*/
void proto_reg_handoff_qsig(void) {
  int i;
  gint key;
  const gchar *oid;
  dissector_handle_t q931_handle;
  dissector_handle_t qsig_arg_handle;
  dissector_handle_t qsig_res_handle;
  dissector_handle_t qsig_err_handle;
  dissector_handle_t qsig_ie_handle;

  q931_handle = find_dissector("q931");
  q931_ie_handle = find_dissector("q931.ie");

  qsig_arg_handle = new_create_dissector_handle(dissect_qsig_arg, proto_qsig);
  qsig_res_handle = new_create_dissector_handle(dissect_qsig_res, proto_qsig);
  for (i=0; i<(int)array_length(qsig_op_tab); i++) {
    dissector_add_uint("q932.ros.local.arg", qsig_op_tab[i].opcode, qsig_arg_handle);
    dissector_add_uint("q932.ros.local.res", qsig_op_tab[i].opcode, qsig_res_handle);
    key = qsig_op_tab[i].opcode;
    oid = (const gchar *)g_hash_table_lookup(qsig_opcode2oid_hashtable, &key);
    if (oid) {
      dissector_add_string("q932.ros.global.arg", oid, qsig_arg_handle);
      dissector_add_string("q932.ros.global.res", oid, qsig_res_handle);
    }
  }
  qsig_err_handle = new_create_dissector_handle(dissect_qsig_err, proto_qsig);
  for (i=0; i<(int)array_length(qsig_err_tab); i++) {
    dissector_add_uint("q932.ros.local.err", qsig_err_tab[i].errcode, qsig_err_handle);
  }

  qsig_ie_handle = create_dissector_handle(dissect_qsig_ie_cs4, proto_qsig);
  /* QSIG-TC - Transit counter */
  dissector_add_uint("q931.ie", CS4 | QSIG_IE_TRANSIT_COUNTER, qsig_ie_handle);

  qsig_ie_handle = create_dissector_handle(dissect_qsig_ie_cs5, proto_qsig);
  /* SSIG-BC - Party category */
  dissector_add_uint("q931.ie", CS5 | QSIG_IE_PARTY_CATEGORY, qsig_ie_handle);

  /* RFC 3204, 3.2 QSIG Media Type */
  dissector_add_string("media_type", "application/qsig", q931_handle);

}

/*---------------------------------------------------------------------------*/
