/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-qsig.c                                                              */
/* asn2wrs.py -q -L -c ./qsig.cnf -s ./packet-qsig-template -D . -O ../.. General-Error-List.asn qsig-gf-ext.asn qsig-gf-gp.asn qsig-gf-ade.asn QSIG-NA.asn QSIG-CF.asn QSIG-PR.asn QSIG-CT.asn QSIG-CC.asn QSIG-CO.asn QSIG-DND.asn QSIG-CI.asn QSIG-AOC.asn QSIG-RE.asn SYNC-SIG.asn QSIG-CINT.asn QSIG-CMN.asn QSIG-CPI.asn QSIG-PUMR.asn QSIG-PUMCH.asn QSIG-SSCT.asn QSIG-WTMLR.asn QSIG-WTMCH.asn QSIG-WTMAU.asn QSIG-SD.asn QSIG-CIDL.asn QSIG-SMS.asn QSIG-MCR.asn QSIG-MCM.asn QSIG-MID.asn */

/* packet-qsig.c
 * Routines for QSIG packet dissection
 * 2007  Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include <epan/asn1.h>
#include <wsutil/strtoi.h>

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

static dissector_handle_t qsig_arg_handle;
static dissector_handle_t qsig_res_handle;
static dissector_handle_t qsig_err_handle;
static dissector_handle_t qsig_ie4_handle;
static dissector_handle_t qsig_ie5_handle;

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
static const int32_t op2srv_tab[] = {
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
  {   0, NULL}
};

static const value_string qsig_str_error[] = {

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
  {   0, NULL}
};

/* Initialize the protocol and registered fields */
static int proto_qsig;
static int hf_qsig_operation;
static int hf_qsig_service;
static int hf_qsig_error;
static int hf_qsig_ie_type;
static int hf_qsig_ie_type_cs4;
static int hf_qsig_ie_type_cs5;
static int hf_qsig_ie_len;
static int hf_qsig_ie_data;
static int hf_qsig_tc;
static int hf_qsig_pc;

/* --- Modules Manufacturer-specific-service-extension-class-asn1-97 PSS1-generic-parameters-definition-asn1-97 Addressing-Data-Elements-asn1-97 --- --- --- */

static int hf_qsig_extensionId;                   /* T_extensionId */
static int hf_qsig_extensionArgument;             /* T_extensionArgument */
static int hf_qsig_presentationAllowedAddressS;   /* AddressScreened */
static int hf_qsig_presentationRestricted;        /* NULL */
static int hf_qsig_numberNotAvailableDueToInterworking;  /* NULL */
static int hf_qsig_presentationRestrictedAddressS;  /* AddressScreened */
static int hf_qsig_presentationAllowedAddressU;   /* Address */
static int hf_qsig_presentationRestrictedAddressU;  /* Address */
static int hf_qsig_presentationAllowedAddressNS;  /* NumberScreened */
static int hf_qsig_presentationRestrictedAddressNS;  /* NumberScreened */
static int hf_qsig_presentationAllowedAddressNU;  /* PartyNumber */
static int hf_qsig_presentationRestrictedAddressNU;  /* PartyNumber */
static int hf_qsig_partyNumber;                   /* PartyNumber */
static int hf_qsig_screeningIndicator;            /* ScreeningIndicator */
static int hf_qsig_partySubaddress;               /* PartySubaddress */
static int hf_qsig_unknownPartyNumber;            /* NumberDigits */
static int hf_qsig_publicPartyNumber;             /* PublicPartyNumber */
static int hf_qsig_dataPartyNumber;               /* NumberDigits */
static int hf_qsig_telexPartyNumber;              /* NumberDigits */
static int hf_qsig_privatePartyNumber;            /* PrivatePartyNumber */
static int hf_qsig_nationalStandardPartyNumber;   /* NumberDigits */
static int hf_qsig_publicTypeOfNumber;            /* PublicTypeOfNumber */
static int hf_qsig_publicNumberDigits;            /* NumberDigits */
static int hf_qsig_privateTypeOfNumber;           /* PrivateTypeOfNumber */
static int hf_qsig_privateNumberDigits;           /* NumberDigits */
static int hf_qsig_userSpecifiedSubaddress;       /* UserSpecifiedSubaddress */
static int hf_qsig_nSAPSubaddress;                /* NSAPSubaddress */
static int hf_qsig_subaddressInformation;         /* SubaddressInformation */
static int hf_qsig_oddCountIndicator;             /* BOOLEAN */

/* --- Module Name-Operations-asn1-97 --- --- ---                             */

static int hf_qsig_na_qsig_na_NameArg_PDU;        /* NameArg */
static int hf_qsig_na_name;                       /* Name */
static int hf_qsig_na_nameSequence;               /* T_nameSequence */
static int hf_qsig_na_extensionNA;                /* NameExtension */
static int hf_qsig_na_single;                     /* Extension */
static int hf_qsig_na_multiple;                   /* SEQUENCE_OF_Extension */
static int hf_qsig_na_multiple_item;              /* Extension */
static int hf_qsig_na_namePresentationAllowed;    /* NamePresentationAllowed */
static int hf_qsig_na_namePresentationRestricted;  /* NamePresentationRestricted */
static int hf_qsig_na_nameNotAvailable;           /* NameNotAvailable */
static int hf_qsig_na_namePresentationAllowedSimple;  /* NameData */
static int hf_qsig_na_namePresentationAllowedExtended;  /* NameSet */
static int hf_qsig_na_namePresentationRestrictedSimple;  /* NameData */
static int hf_qsig_na_namePresentationRestrictedExtended;  /* NameSet */
static int hf_qsig_na_namePresentationRestrictedNull;  /* NULL */
static int hf_qsig_na_nameData;                   /* NameData */
static int hf_qsig_na_characterSet;               /* CharacterSet */

/* --- Module Call-Diversion-Operations-asn1-97 --- --- ---                   */

static int hf_qsig_cf_qsig_cf_ARG_activateDiversionQ_PDU;  /* ARG_activateDiversionQ */
static int hf_qsig_cf_qsig_cf_RES_activateDiversionQ_PDU;  /* RES_activateDiversionQ */
static int hf_qsig_cf_qsig_cf_ARG_deactivateDiversionQ_PDU;  /* ARG_deactivateDiversionQ */
static int hf_qsig_cf_qsig_cf_RES_deactivateDiversionQ_PDU;  /* RES_deactivateDiversionQ */
static int hf_qsig_cf_qsig_cf_ARG_interrogateDiversionQ_PDU;  /* ARG_interrogateDiversionQ */
static int hf_qsig_cf_qsig_cf_IntResultList_PDU;  /* IntResultList */
static int hf_qsig_cf_qsig_cf_ARG_checkRestriction_PDU;  /* ARG_checkRestriction */
static int hf_qsig_cf_qsig_cf_RES_checkRestriction_PDU;  /* RES_checkRestriction */
static int hf_qsig_cf_qsig_cf_ARG_callRerouteing_PDU;  /* ARG_callRerouteing */
static int hf_qsig_cf_qsig_cf_RES_callRerouteing_PDU;  /* RES_callRerouteing */
static int hf_qsig_cf_qsig_cf_ARG_divertingLegInformation1_PDU;  /* ARG_divertingLegInformation1 */
static int hf_qsig_cf_qsig_cf_ARG_divertingLegInformation2_PDU;  /* ARG_divertingLegInformation2 */
static int hf_qsig_cf_qsig_cf_ARG_divertingLegInformation3_PDU;  /* ARG_divertingLegInformation3 */
static int hf_qsig_cf_qsig_cf_ARG_cfnrDivertedLegFailed_PDU;  /* ARG_cfnrDivertedLegFailed */
static int hf_qsig_cf_qsig_cf_Extension_PDU;      /* Extension */
static int hf_qsig_cf_procedure;                  /* Procedure */
static int hf_qsig_cf_basicService;               /* BasicService */
static int hf_qsig_cf_divertedToAddress;          /* Address */
static int hf_qsig_cf_servedUserNr;               /* PartyNumber */
static int hf_qsig_cf_activatingUserNr;           /* PartyNumber */
static int hf_qsig_cf_extensionAD;                /* ADExtension */
static int hf_qsig_cf_single;                     /* Extension */
static int hf_qsig_cf_multiple;                   /* SEQUENCE_OF_Extension */
static int hf_qsig_cf_multiple_item;              /* Extension */
static int hf_qsig_cf_null;                       /* NULL */
static int hf_qsig_cf_deactivatingUserNr;         /* PartyNumber */
static int hf_qsig_cf_extensionDD;                /* DDExtension */
static int hf_qsig_cf_interrogatingUserNr;        /* PartyNumber */
static int hf_qsig_cf_extensionID;                /* IDExtension */
static int hf_qsig_cf_divertedToNr;               /* PartyNumber */
static int hf_qsig_cf_extensionCHR;               /* CHRExtension */
static int hf_qsig_cf_rerouteingReason;           /* DiversionReason */
static int hf_qsig_cf_originalRerouteingReason;   /* DiversionReason */
static int hf_qsig_cf_calledAddress;              /* Address */
static int hf_qsig_cf_diversionCounter;           /* INTEGER_1_15 */
static int hf_qsig_cf_pSS1InfoElement;            /* PSS1InformationElement */
static int hf_qsig_cf_lastRerouteingNr;           /* PresentedNumberUnscreened */
static int hf_qsig_cf_subscriptionOption;         /* SubscriptionOption */
static int hf_qsig_cf_callingPartySubaddress;     /* PartySubaddress */
static int hf_qsig_cf_callingNumber;              /* PresentedNumberScreened */
static int hf_qsig_cf_callingName;                /* Name */
static int hf_qsig_cf_originalCalledNr;           /* PresentedNumberUnscreened */
static int hf_qsig_cf_redirectingName;            /* Name */
static int hf_qsig_cf_originalCalledName;         /* Name */
static int hf_qsig_cf_extensionCRR;               /* CRRExtension */
static int hf_qsig_cf_diversionReason;            /* DiversionReason */
static int hf_qsig_cf_nominatedNr;                /* PartyNumber */
static int hf_qsig_cf_extensionDLI1;              /* DLI1Extension */
static int hf_qsig_cf_originalDiversionReason;    /* DiversionReason */
static int hf_qsig_cf_divertingNr;                /* PresentedNumberUnscreened */
static int hf_qsig_cf_extensionDLI2;              /* DLI2Extension */
static int hf_qsig_cf_presentationAllowedIndicator;  /* PresentationAllowedIndicator */
static int hf_qsig_cf_redirectionName;            /* Name */
static int hf_qsig_cf_extensionDLI3;              /* DLI3Extension */
static int hf_qsig_cf_IntResultList_item;         /* IntResult */
static int hf_qsig_cf_remoteEnabled;              /* BOOLEAN */
static int hf_qsig_cf_extensionIR;                /* IRExtension */

/* --- Module Path-Replacement-Operations-asn1-97 --- --- ---                 */

static int hf_qsig_pr_qsig_pr_DummyArg_PDU;       /* DummyArg */
static int hf_qsig_pr_qsig_pr_PRProposeArg_PDU;   /* PRProposeArg */
static int hf_qsig_pr_qsig_pr_PRSetupArg_PDU;     /* PRSetupArg */
static int hf_qsig_pr_qsig_pr_DummyResult_PDU;    /* DummyResult */
static int hf_qsig_pr_qsig_pr_PRRetainArg_PDU;    /* PRRetainArg */
static int hf_qsig_pr_qsig_pr_Extension_PDU;      /* Extension */
static int hf_qsig_pr_callIdentity;               /* CallIdentity */
static int hf_qsig_pr_rerouteingNumber;           /* PartyNumber */
static int hf_qsig_pr_extensionPRP;               /* PRPExtension */
static int hf_qsig_pr_single;                     /* Extension */
static int hf_qsig_pr_multiple;                   /* SEQUENCE_OF_Extension */
static int hf_qsig_pr_multiple_item;              /* Extension */
static int hf_qsig_pr_extensionPRS;               /* PRSExtension */
static int hf_qsig_pr_extensionPRR;               /* PRRExtension */
static int hf_qsig_pr_null;                       /* NULL */

/* --- Module Call-Transfer-Operations-asn1-97 --- --- ---                    */

static int hf_qsig_ct_qsig_ct_DummyArg_PDU;       /* DummyArg */
static int hf_qsig_ct_qsig_ct_CTIdentifyRes_PDU;  /* CTIdentifyRes */
static int hf_qsig_ct_qsig_ct_CTInitiateArg_PDU;  /* CTInitiateArg */
static int hf_qsig_ct_qsig_ct_DummyRes_PDU;       /* DummyRes */
static int hf_qsig_ct_qsig_ct_CTSetupArg_PDU;     /* CTSetupArg */
static int hf_qsig_ct_qsig_ct_CTActiveArg_PDU;    /* CTActiveArg */
static int hf_qsig_ct_qsig_ct_CTCompleteArg_PDU;  /* CTCompleteArg */
static int hf_qsig_ct_qsig_ct_CTUpdateArg_PDU;    /* CTUpdateArg */
static int hf_qsig_ct_qsig_ct_SubaddressTransferArg_PDU;  /* SubaddressTransferArg */
static int hf_qsig_ct_qsig_ct_Extension_PDU;      /* Extension */
static int hf_qsig_ct_null;                       /* NULL */
static int hf_qsig_ct_single;                     /* Extension */
static int hf_qsig_ct_multiple;                   /* SEQUENCE_OF_Extension */
static int hf_qsig_ct_multiple_item;              /* Extension */
static int hf_qsig_ct_callIdentity;               /* CallIdentity */
static int hf_qsig_ct_rerouteingNumber;           /* PartyNumber */
static int hf_qsig_ct_resultExtension;            /* T_resultExtension */
static int hf_qsig_ct_argumentExtensionCTI;       /* CTIargumentExtension */
static int hf_qsig_ct_argumentExtensionCTS;       /* CTSargumentExtension */
static int hf_qsig_ct_connectedAddress;           /* PresentedAddressScreened */
static int hf_qsig_ct_basicCallInfoElements;      /* PSS1InformationElement */
static int hf_qsig_ct_connectedName;              /* Name */
static int hf_qsig_ct_argumentExtensionCTA;       /* CTAargumentExtension */
static int hf_qsig_ct_endDesignation;             /* EndDesignation */
static int hf_qsig_ct_redirectionNumber;          /* PresentedNumberScreened */
static int hf_qsig_ct_redirectionName;            /* Name */
static int hf_qsig_ct_callStatus;                 /* CallStatus */
static int hf_qsig_ct_argumentExtensionCTC;       /* CTCargumentExtension */
static int hf_qsig_ct_argumentExtensionCTU;       /* CTUargumentExtension */
static int hf_qsig_ct_redirectionSubaddress;      /* PartySubaddress */
static int hf_qsig_ct_argumentExtensionST;        /* STargumentExtension */

/* --- Module SS-CC-Operations-asn1-97 --- --- ---                            */

static int hf_qsig_cc_qsig_cc_CcRequestArg_PDU;   /* CcRequestArg */
static int hf_qsig_cc_qsig_cc_CcRequestRes_PDU;   /* CcRequestRes */
static int hf_qsig_cc_qsig_cc_CcOptionalArg_PDU;  /* CcOptionalArg */
static int hf_qsig_cc_qsig_cc_CcExtension_PDU;    /* CcExtension */
static int hf_qsig_cc_qsig_cc_Extension_PDU;      /* Extension */
static int hf_qsig_cc_numberA;                    /* PresentedNumberUnscreened */
static int hf_qsig_cc_numberB;                    /* PartyNumber */
static int hf_qsig_cc_service;                    /* PSS1InformationElement */
static int hf_qsig_cc_subaddrA;                   /* PartySubaddress */
static int hf_qsig_cc_subaddrB;                   /* PartySubaddress */
static int hf_qsig_cc_can_retain_service;         /* BOOLEAN */
static int hf_qsig_cc_retain_sig_connection;      /* BOOLEAN */
static int hf_qsig_cc_extension;                  /* CcExtension */
static int hf_qsig_cc_no_path_reservation;        /* BOOLEAN */
static int hf_qsig_cc_retain_service;             /* BOOLEAN */
static int hf_qsig_cc_fullArg;                    /* T_fullArg */
static int hf_qsig_cc_numberA_01;                 /* PartyNumber */
static int hf_qsig_cc_extArg;                     /* CcExtension */
static int hf_qsig_cc_none;                       /* NULL */
static int hf_qsig_cc_single;                     /* Extension */
static int hf_qsig_cc_multiple;                   /* SEQUENCE_OF_Extension */
static int hf_qsig_cc_multiple_item;              /* Extension */

/* --- Module Call-Offer-Operations-asn1-97 --- --- ---                       */

static int hf_qsig_co_qsig_co_PathRetainArg_PDU;  /* PathRetainArg */
static int hf_qsig_co_qsig_co_ServiceAvailableArg_PDU;  /* ServiceAvailableArg */
static int hf_qsig_co_qsig_co_DummyArg_PDU;       /* DummyArg */
static int hf_qsig_co_qsig_co_DummyRes_PDU;       /* DummyRes */
static int hf_qsig_co_qsig_co_Extension_PDU;      /* Extension */
static int hf_qsig_co_serviceList;                /* ServiceList */
static int hf_qsig_co_extendedServiceList;        /* T_extendedServiceList */
static int hf_qsig_co_extension;                  /* Extension */
static int hf_qsig_co_extendedServiceList_01;     /* T_extendedServiceList_01 */
static int hf_qsig_co_null;                       /* NULL */
static int hf_qsig_co_sequenceOfExtn;             /* SEQUENCE_OF_Extension */
static int hf_qsig_co_sequenceOfExtn_item;        /* Extension */
/* named bits */
static int hf_qsig_co_ServiceList_callOffer;

/* --- Module Do-Not-Disturb-Operations-asn1-97 --- --- ---                   */

static int hf_qsig_dnd_qsig_dnd_DNDActivateArg_PDU;  /* DNDActivateArg */
static int hf_qsig_dnd_qsig_dnd_DNDActivateRes_PDU;  /* DNDActivateRes */
static int hf_qsig_dnd_qsig_dnd_DNDDeactivateArg_PDU;  /* DNDDeactivateArg */
static int hf_qsig_dnd_qsig_dnd_DummyRes_PDU;     /* DummyRes */
static int hf_qsig_dnd_qsig_dnd_DNDInterrogateArg_PDU;  /* DNDInterrogateArg */
static int hf_qsig_dnd_qsig_dnd_DNDInterrogateRes_PDU;  /* DNDInterrogateRes */
static int hf_qsig_dnd_qsig_dnd_DNDOverrideArg_PDU;  /* DNDOverrideArg */
static int hf_qsig_dnd_qsig_dnd_PathRetainArg_PDU;  /* PathRetainArg */
static int hf_qsig_dnd_qsig_dnd_ServiceAvailableArg_PDU;  /* ServiceAvailableArg */
static int hf_qsig_dnd_qsig_dnd_DummyArg_PDU;     /* DummyArg */
static int hf_qsig_dnd_qsig_dnd_Extension_PDU;    /* Extension */
static int hf_qsig_dnd_null;                      /* NULL */
static int hf_qsig_dnd_extension;                 /* Extension */
static int hf_qsig_dnd_sequenceOfExtn;            /* SEQUENCE_OF_Extension */
static int hf_qsig_dnd_sequenceOfExtn_item;       /* Extension */
static int hf_qsig_dnd_basicService;              /* BasicService */
static int hf_qsig_dnd_servedUserNr;              /* PartyNumber */
static int hf_qsig_dnd_argumentExtensionDNDA;     /* DNDAargumentExtension */
static int hf_qsig_dnd_status;                    /* T_status */
static int hf_qsig_dnd_status_item;               /* T_status_item */
static int hf_qsig_dnd_dndProtectionLevel;        /* DNDProtectionLevel */
static int hf_qsig_dnd_resultExtension;           /* T_resultExtension */
static int hf_qsig_dnd_argumentExtensionDNDD;     /* DNDDargumentExtension */
static int hf_qsig_dnd_argumentExtensionDNDI;     /* DNDIargumentExtension */
static int hf_qsig_dnd_status_01;                 /* T_status_01 */
static int hf_qsig_dnd_status_item_01;            /* T_status_item_01 */
static int hf_qsig_dnd_resultExtension_01;        /* T_resultExtension_01 */
static int hf_qsig_dnd_dndoCapabilityLevel;       /* DNDOCapabilityLevel */
static int hf_qsig_dnd_argumentExtensionDNDO;     /* DNDOargumentExtension */
static int hf_qsig_dnd_serviceList;               /* ServiceList */
static int hf_qsig_dnd_extendedServiceList;       /* T_extendedServiceList */
static int hf_qsig_dnd_extendedServiceList_01;    /* T_extendedServiceList_01 */
/* named bits */
static int hf_qsig_dnd_ServiceList_spare_bit0;
static int hf_qsig_dnd_ServiceList_dndo_low;
static int hf_qsig_dnd_ServiceList_dndo_medium;
static int hf_qsig_dnd_ServiceList_dndo_high;

/* --- Module Call-Intrusion-Operations-asn1-97 --- --- ---                   */

static int hf_qsig_ci_qsig_ci_PathRetainArg_PDU;  /* PathRetainArg */
static int hf_qsig_ci_qsig_ci_ServiceAvailableArg_PDU;  /* ServiceAvailableArg */
static int hf_qsig_ci_qsig_ci_CIRequestArg_PDU;   /* CIRequestArg */
static int hf_qsig_ci_qsig_ci_CIRequestRes_PDU;   /* CIRequestRes */
static int hf_qsig_ci_qsig_ci_DummyArg_PDU;       /* DummyArg */
static int hf_qsig_ci_qsig_ci_CIGetCIPLRes_PDU;   /* CIGetCIPLRes */
static int hf_qsig_ci_qsig_ci_DummyRes_PDU;       /* DummyRes */
static int hf_qsig_ci_qsig_ci_Extension_PDU;      /* Extension */
static int hf_qsig_ci_serviceList;                /* ServiceList */
static int hf_qsig_ci_extendedServiceList;        /* T_extendedServiceList */
static int hf_qsig_ci_extension;                  /* Extension */
static int hf_qsig_ci_extendedServiceList_01;     /* T_extendedServiceList_01 */
static int hf_qsig_ci_null;                       /* NULL */
static int hf_qsig_ci_sequenceOfExtn;             /* SEQUENCE_OF_Extension */
static int hf_qsig_ci_sequenceOfExtn_item;        /* Extension */
static int hf_qsig_ci_ciCapabilityLevel;          /* CICapabilityLevel */
static int hf_qsig_ci_argumentExtension;          /* T_argumentExtension */
static int hf_qsig_ci_ciUnwantedUserStatus;       /* CIUnwantedUserStatus */
static int hf_qsig_ci_resultExtension;            /* T_resultExtension */
static int hf_qsig_ci_ciProtectionLevel;          /* CIProtectionLevel */
static int hf_qsig_ci_resultExtension_01;         /* T_resultExtension_01 */
/* named bits */
static int hf_qsig_ci_ServiceList_spare_bit0;
static int hf_qsig_ci_ServiceList_spare_bit1;
static int hf_qsig_ci_ServiceList_spare_bit2;
static int hf_qsig_ci_ServiceList_spare_bit3;
static int hf_qsig_ci_ServiceList_ci_low;
static int hf_qsig_ci_ServiceList_ci_medium;
static int hf_qsig_ci_ServiceList_ci_high;

/* --- Module SS-AOC-Operations-asn1-97 --- --- ---                           */

static int hf_qsig_aoc_qsig_aoc_AocRateArg_PDU;   /* AocRateArg */
static int hf_qsig_aoc_qsig_aoc_AocInterimArg_PDU;  /* AocInterimArg */
static int hf_qsig_aoc_qsig_aoc_AocFinalArg_PDU;  /* AocFinalArg */
static int hf_qsig_aoc_qsig_aoc_ChargeRequestArg_PDU;  /* ChargeRequestArg */
static int hf_qsig_aoc_qsig_aoc_ChargeRequestRes_PDU;  /* ChargeRequestRes */
static int hf_qsig_aoc_qsig_aoc_DummyArg_PDU;     /* DummyArg */
static int hf_qsig_aoc_qsig_aoc_AocCompleteArg_PDU;  /* AocCompleteArg */
static int hf_qsig_aoc_qsig_aoc_AocCompleteRes_PDU;  /* AocCompleteRes */
static int hf_qsig_aoc_qsig_aoc_AocDivChargeReqArg_PDU;  /* AocDivChargeReqArg */
static int hf_qsig_aoc_qsig_aoc_Extension_PDU;    /* Extension */
static int hf_qsig_aoc_aocRate;                   /* T_aocRate */
static int hf_qsig_aoc_chargeNotAvailable;        /* NULL */
static int hf_qsig_aoc_aocSCurrencyInfoList;      /* AOCSCurrencyInfoList */
static int hf_qsig_aoc_rateArgExtension;          /* T_rateArgExtension */
static int hf_qsig_aoc_extension;                 /* Extension */
static int hf_qsig_aoc_multipleExtension;         /* SEQUENCE_OF_Extension */
static int hf_qsig_aoc_multipleExtension_item;    /* Extension */
static int hf_qsig_aoc_interimCharge;             /* T_interimCharge */
static int hf_qsig_aoc_freeOfCharge;              /* NULL */
static int hf_qsig_aoc_specificCurrency;          /* T_specificCurrency */
static int hf_qsig_aoc_recordedCurrency;          /* RecordedCurrency */
static int hf_qsig_aoc_interimBillingId;          /* InterimBillingId */
static int hf_qsig_aoc_interimArgExtension;       /* T_interimArgExtension */
static int hf_qsig_aoc_finalCharge;               /* T_finalCharge */
static int hf_qsig_aoc_specificCurrency_01;       /* T_specificCurrency_01 */
static int hf_qsig_aoc_finalBillingId;            /* FinalBillingId */
static int hf_qsig_aoc_chargingAssociation;       /* ChargingAssociation */
static int hf_qsig_aoc_finalArgExtension;         /* T_finalArgExtension */
static int hf_qsig_aoc_AOCSCurrencyInfoList_item;  /* AOCSCurrencyInfo */
static int hf_qsig_aoc_chargedItem;               /* ChargedItem */
static int hf_qsig_aoc_rateType;                  /* T_rateType */
static int hf_qsig_aoc_durationCurrency;          /* DurationCurrency */
static int hf_qsig_aoc_flatRateCurrency;          /* FlatRateCurrency */
static int hf_qsig_aoc_volumeRateCurrency;        /* VolumeRateCurrency */
static int hf_qsig_aoc_specialChargingCode;       /* SpecialChargingCode */
static int hf_qsig_aoc_currencyInfoNotAvailable;  /* NULL */
static int hf_qsig_aoc_freeOfChargefromBeginning;  /* NULL */
static int hf_qsig_aoc_dCurrency;                 /* Currency */
static int hf_qsig_aoc_dAmount;                   /* Amount */
static int hf_qsig_aoc_dChargingType;             /* ChargingType */
static int hf_qsig_aoc_dTime;                     /* Time */
static int hf_qsig_aoc_dGranularity;              /* Time */
static int hf_qsig_aoc_fRCurrency;                /* Currency */
static int hf_qsig_aoc_fRAmount;                  /* Amount */
static int hf_qsig_aoc_vRCurrency;                /* Currency */
static int hf_qsig_aoc_vRAmount;                  /* Amount */
static int hf_qsig_aoc_vRVolumeUnit;              /* VolumeUnit */
static int hf_qsig_aoc_rCurrency;                 /* Currency */
static int hf_qsig_aoc_rAmount;                   /* Amount */
static int hf_qsig_aoc_currencyAmount;            /* CurrencyAmount */
static int hf_qsig_aoc_multiplier;                /* Multiplier */
static int hf_qsig_aoc_lengthOfTimeUnit;          /* LengthOfTimeUnit */
static int hf_qsig_aoc_scale;                     /* Scale */
static int hf_qsig_aoc_chargeNumber;              /* PartyNumber */
static int hf_qsig_aoc_chargeIdentifier;          /* ChargeIdentifier */
static int hf_qsig_aoc_adviceModeCombinations;    /* SEQUENCE_SIZE_0_7_OF_AdviceModeCombination */
static int hf_qsig_aoc_adviceModeCombinations_item;  /* AdviceModeCombination */
static int hf_qsig_aoc_chargeReqArgExtension;     /* T_chargeReqArgExtension */
static int hf_qsig_aoc_adviceModeCombination;     /* AdviceModeCombination */
static int hf_qsig_aoc_chargeReqResExtension;     /* T_chargeReqResExtension */
static int hf_qsig_aoc_none;                      /* NULL */
static int hf_qsig_aoc_chargedUser;               /* PartyNumber */
static int hf_qsig_aoc_completeArgExtension;      /* T_completeArgExtension */
static int hf_qsig_aoc_chargingOption;            /* ChargingOption */
static int hf_qsig_aoc_completeResExtension;      /* T_completeResExtension */
static int hf_qsig_aoc_divertingUser;             /* PartyNumber */
static int hf_qsig_aoc_diversionType;             /* DiversionType */
static int hf_qsig_aoc_aocDivChargeReqArgExt;     /* T_aocDivChargeReqArgExt */

/* --- Module Recall-Operations-asn1-97 --- --- ---                           */

static int hf_qsig_re_qsig_re_ReAlertingArg_PDU;  /* ReAlertingArg */
static int hf_qsig_re_qsig_re_ReAnswerArg_PDU;    /* ReAnswerArg */
static int hf_qsig_re_alertedNumber;              /* PresentedNumberScreened */
static int hf_qsig_re_alertedName;                /* Name */
static int hf_qsig_re_argumentExtension;          /* T_argumentExtension */
static int hf_qsig_re_extension;                  /* Extension */
static int hf_qsig_re_multipleExtension;          /* SEQUENCE_OF_Extension */
static int hf_qsig_re_multipleExtension_item;     /* Extension */
static int hf_qsig_re_connectedNumber;            /* PresentedNumberScreened */
static int hf_qsig_re_connectedSubaddress;        /* PartySubaddress */
static int hf_qsig_re_connectedName;              /* Name */
static int hf_qsig_re_argumentExtension_01;       /* T_argumentExtension_01 */

/* --- Module Synchronization-Operations-asn1-97 --- --- ---                  */

static int hf_qsig_sync_qsig_sync_SynchronizationReqArg_PDU;  /* SynchronizationReqArg */
static int hf_qsig_sync_qsig_sync_SynchronizationReqRes_PDU;  /* SynchronizationReqRes */
static int hf_qsig_sync_qsig_sync_SynchronizationInfoArg_PDU;  /* SynchronizationInfoArg */
static int hf_qsig_sync_qsig_sync_Extension_PDU;  /* Extension */
static int hf_qsig_sync_action;                   /* Action */
static int hf_qsig_sync_argExtension;             /* ArgExtension */
static int hf_qsig_sync_response;                 /* BOOLEAN */
static int hf_qsig_sync_stateinfo;                /* T_stateinfo */
static int hf_qsig_sync_extension;                /* Extension */
static int hf_qsig_sync_sequOfExtn;               /* SEQUENCE_OF_Extension */
static int hf_qsig_sync_sequOfExtn_item;          /* Extension */

/* --- Module Call-Interception-Operations-asn1-97 --- --- ---                */

static int hf_qsig_cint_qsig_cint_CintInformation1Arg_PDU;  /* CintInformation1Arg */
static int hf_qsig_cint_qsig_cint_CintInformation2Arg_PDU;  /* CintInformation2Arg */
static int hf_qsig_cint_qsig_cint_CintCondArg_PDU;  /* CintCondArg */
static int hf_qsig_cint_qsig_cint_CintExtension_PDU;  /* CintExtension */
static int hf_qsig_cint_interceptionCause;        /* CintCause */
static int hf_qsig_cint_interceptedToNumber;      /* PartyNumber */
static int hf_qsig_cint_extension;                /* CintExtension */
static int hf_qsig_cint_calledNumber;             /* PresentedNumberUnscreened */
static int hf_qsig_cint_originalCalledNumber;     /* PresentedNumberUnscreened */
static int hf_qsig_cint_calledName;               /* Name */
static int hf_qsig_cint_originalCalledName;       /* Name */
static int hf_qsig_cint_interceptionCause_01;     /* Condition */
static int hf_qsig_cint_none;                     /* NULL */
static int hf_qsig_cint_single;                   /* Extension */
static int hf_qsig_cint_multiple;                 /* SEQUENCE_OF_Extension */
static int hf_qsig_cint_multiple_item;            /* Extension */

/* --- Module Common-Information-Operations-asn1-97 --- --- ---               */

static int hf_qsig_cmn_qsig_cmn_DummyArg_PDU;     /* DummyArg */
static int hf_qsig_cmn_qsig_cmn_CmnArg_PDU;       /* CmnArg */
static int hf_qsig_cmn_featureIdentifier;         /* FeatureIdList */
static int hf_qsig_cmn_ssDNDOprotectionLevel;     /* INTEGER_0_3 */
static int hf_qsig_cmn_ssCIprotectionLevel;       /* INTEGER_0_3 */
static int hf_qsig_cmn_equipmentIdentity;         /* EquipmentId */
static int hf_qsig_cmn_partyCategory;             /* PartyCategory */
static int hf_qsig_cmn_extension;                 /* T_extension */
static int hf_qsig_cmn_single;                    /* Extension */
static int hf_qsig_cmn_multiple;                  /* SEQUENCE_OF_Extension */
static int hf_qsig_cmn_multiple_item;             /* Extension */
static int hf_qsig_cmn_null;                      /* NULL */
static int hf_qsig_cmn_nodeId;                    /* IA5String_SIZE_1_10 */
static int hf_qsig_cmn_groupId;                   /* IA5String_SIZE_1_10 */
static int hf_qsig_cmn_unitId;                    /* IA5String_SIZE_1_10 */
/* named bits */
static int hf_qsig_cmn_FeatureIdList_reserved;
static int hf_qsig_cmn_FeatureIdList_ssCFreRoutingSupported;
static int hf_qsig_cmn_FeatureIdList_ssCTreRoutingSupported;
static int hf_qsig_cmn_FeatureIdList_ssCCBSpossible;
static int hf_qsig_cmn_FeatureIdList_ssCCNRpossible;
static int hf_qsig_cmn_FeatureIdList_ssCOsupported;
static int hf_qsig_cmn_FeatureIdList_ssCIforcedRelease;
static int hf_qsig_cmn_FeatureIdList_ssCIisolation;
static int hf_qsig_cmn_FeatureIdList_ssCIwaitOnBusy;
static int hf_qsig_cmn_FeatureIdList_ssAOCsupportChargeRateProvAtGatewPinx;
static int hf_qsig_cmn_FeatureIdList_ssAOCsupportInterimChargeProvAtGatewPinx;
static int hf_qsig_cmn_FeatureIdList_ssAOCsupportFinalChargeProvAtGatewPinx;
static int hf_qsig_cmn_FeatureIdList_anfPRsupportedAtCooperatingPinx;
static int hf_qsig_cmn_FeatureIdList_anfCINTcanInterceptImmediate;
static int hf_qsig_cmn_FeatureIdList_anfCINTcanInterceptDelayed;
static int hf_qsig_cmn_FeatureIdList_anfWTMIreRoutingSupported;
static int hf_qsig_cmn_FeatureIdList_anfPUMIreRoutingSupported;
static int hf_qsig_cmn_FeatureIdList_ssSSCTreRoutingSupported;

/* --- Module Call-Interruption-Operations-asn1-97 --- --- ---                */

static int hf_qsig_cpi_qsig_cpi_CPIRequestArg_PDU;  /* CPIRequestArg */
static int hf_qsig_cpi_qsig_cpi_CPIPRequestArg_PDU;  /* CPIPRequestArg */
static int hf_qsig_cpi_cpiCapabilityLevel;        /* CPICapabilityLevel */
static int hf_qsig_cpi_argumentExtension;         /* T_argumentExtension */
static int hf_qsig_cpi_extension;                 /* Extension */
static int hf_qsig_cpi_sequenceOfExtn;            /* SEQUENCE_OF_Extension */
static int hf_qsig_cpi_sequenceOfExtn_item;       /* Extension */
static int hf_qsig_cpi_cpiProtectionLevel;        /* CPIProtectionLevel */
static int hf_qsig_cpi_argumentExtension_01;      /* T_argumentExtension_01 */

/* --- Module PUM-Registration-Operations-asn1-97 --- --- ---                 */

static int hf_qsig_pumr_qsig_pumr_PumRegistrArg_PDU;  /* PumRegistrArg */
static int hf_qsig_pumr_qsig_pumr_PumRegistrRes_PDU;  /* PumRegistrRes */
static int hf_qsig_pumr_qsig_pumr_PumDelRegArg_PDU;  /* PumDelRegArg */
static int hf_qsig_pumr_qsig_pumr_DummyRes_PDU;   /* DummyRes */
static int hf_qsig_pumr_qsig_pumr_PumDe_regArg_PDU;  /* PumDe_regArg */
static int hf_qsig_pumr_qsig_pumr_PumInterrogArg_PDU;  /* PumInterrogArg */
static int hf_qsig_pumr_qsig_pumr_PumInterrogRes_PDU;  /* PumInterrogRes */
static int hf_qsig_pumr_qsig_pumr_Extension_PDU;  /* Extension */
static int hf_qsig_pumr_pumRUserId;               /* RpumUserId */
static int hf_qsig_pumr_pumNumber;                /* PartyNumber */
static int hf_qsig_pumr_alternativeId;            /* AlternativeId */
static int hf_qsig_pumr_basicService;             /* BasicService */
static int hf_qsig_pumr_hostingAddr;              /* PartyNumber */
static int hf_qsig_pumr_activatingUserAddr;       /* PartyNumber */
static int hf_qsig_pumr_serviceOption;            /* ServiceOption */
static int hf_qsig_pumr_sessionParams;            /* SessionParams */
static int hf_qsig_pumr_userPin;                  /* T_userPin */
static int hf_qsig_pumr_pumUserPin;               /* UserPin */
static int hf_qsig_pumr_activatingUserPin;        /* UserPin */
static int hf_qsig_pumr_argExtension;             /* PumrExtension */
static int hf_qsig_pumr_null;                     /* NULL */
static int hf_qsig_pumr_extension;                /* Extension */
static int hf_qsig_pumr_sequOfExtn;               /* SEQUENCE_OF_Extension */
static int hf_qsig_pumr_sequOfExtn_item;          /* Extension */
static int hf_qsig_pumr_pumXUserId;               /* XpumUserId */
static int hf_qsig_pumr_pumDUserId;               /* DpumUserId */
static int hf_qsig_pumr_userPin_01;               /* T_userPin_01 */
static int hf_qsig_pumr_pumIUserId;               /* IpumUserId */
static int hf_qsig_pumr_homeInfoOnly;             /* BOOLEAN */
static int hf_qsig_pumr_userPin_02;               /* T_userPin_02 */
static int hf_qsig_pumr_PumInterrogRes_item;      /* PumInterrogRes_item */
static int hf_qsig_pumr_interrogParams;           /* SessionParams */
static int hf_qsig_pumr_durationOfSession;        /* INTEGER */
static int hf_qsig_pumr_numberOfOutgCalls;        /* INTEGER */

/* --- Module Private-User-Mobility-Call-Handling-Operations-asn1-97 --- --- --- */

static int hf_qsig_pumch_qsig_pumch_EnquiryArg_PDU;  /* EnquiryArg */
static int hf_qsig_pumch_qsig_pumch_EnquiryRes_PDU;  /* EnquiryRes */
static int hf_qsig_pumch_qsig_pumch_DivertArg_PDU;  /* DivertArg */
static int hf_qsig_pumch_qsig_pumch_DummyRes_PDU;  /* DummyRes */
static int hf_qsig_pumch_qsig_pumch_InformArg_PDU;  /* InformArg */
static int hf_qsig_pumch_qsig_pumch_PumoArg_PDU;  /* PumoArg */
static int hf_qsig_pumch_qsig_pumch_Extension_PDU;  /* Extension */
static int hf_qsig_pumch_pisnNumber;              /* PartyNumber */
static int hf_qsig_pumch_qSIGInfoElement;         /* PSS1InformationElement */
static int hf_qsig_pumch_argExtension;            /* PumiExtension */
static int hf_qsig_pumch_hostingAddr;             /* PartyNumber */
static int hf_qsig_pumch_callingNumber;           /* PresentedNumberScreened */
static int hf_qsig_pumch_pumIdentity;             /* PumIdentity */
static int hf_qsig_pumch_callingUserSub;          /* PartySubaddress */
static int hf_qsig_pumch_callingUserName;         /* Name */
static int hf_qsig_pumch_pumUserSub;              /* PartySubaddress */
static int hf_qsig_pumch_currLocation;            /* CurrLocation */
static int hf_qsig_pumch_cfuActivated;            /* CfuActivated */
static int hf_qsig_pumch_divToAddress;            /* Address */
static int hf_qsig_pumch_divOptions;              /* SubscriptionOption */
static int hf_qsig_pumch_pumName;                 /* Name */
static int hf_qsig_pumch_null;                    /* NULL */
static int hf_qsig_pumch_extension;               /* Extension */
static int hf_qsig_pumch_sequOfExtn;              /* SEQUENCE_OF_Extension */
static int hf_qsig_pumch_sequOfExtn_item;         /* Extension */
static int hf_qsig_pumch_alternativeId;           /* AlternativeId */
static int hf_qsig_pumch_both;                    /* T_both */
static int hf_qsig_pumch_destinationNumber;       /* PartyNumber */
static int hf_qsig_pumch_sendingComplete;         /* NULL */
static int hf_qsig_pumch_pumoaextension;          /* T_pumoaextension */
static int hf_qsig_pumch_single;                  /* Extension */
static int hf_qsig_pumch_multiple;                /* SEQUENCE_OF_Extension */
static int hf_qsig_pumch_multiple_item;           /* Extension */

/* --- Module Single-Step-Call-Transfer-Operations-asn1-97 --- --- ---        */

static int hf_qsig_ssct_qsig_ssct_SSCTInitiateArg_PDU;  /* SSCTInitiateArg */
static int hf_qsig_ssct_qsig_ssct_DummyRes_PDU;   /* DummyRes */
static int hf_qsig_ssct_qsig_ssct_SSCTSetupArg_PDU;  /* SSCTSetupArg */
static int hf_qsig_ssct_qsig_ssct_DummyArg_PDU;   /* DummyArg */
static int hf_qsig_ssct_qsig_ssct_SSCTDigitInfoArg_PDU;  /* SSCTDigitInfoArg */
static int hf_qsig_ssct_qsig_ssct_Extension_PDU;  /* Extension */
static int hf_qsig_ssct_null;                     /* NULL */
static int hf_qsig_ssct_single;                   /* Extension */
static int hf_qsig_ssct_multiple;                 /* SEQUENCE_OF_Extension */
static int hf_qsig_ssct_multiple_item;            /* Extension */
static int hf_qsig_ssct_rerouteingNumber;         /* PartyNumber */
static int hf_qsig_ssct_transferredAddress;       /* PresentedAddressScreened */
static int hf_qsig_ssct_awaitConnect;             /* AwaitConnect */
static int hf_qsig_ssct_transferredName;          /* Name */
static int hf_qsig_ssct_transferringAddress;      /* PresentedAddressScreened */
static int hf_qsig_ssct_transferringName;         /* Name */
static int hf_qsig_ssct_argumentExtensionSSCTI;   /* SSCTIargumentExtension */
static int hf_qsig_ssct_argumentExtensionSSCTS;   /* SSCTSargumentExtension */
static int hf_qsig_ssct_reroutingNumber;          /* PartyNumber */
static int hf_qsig_ssct_sendingComplete;          /* NULL */
static int hf_qsig_ssct_argumentExtensionSSCTD;   /* SSCTDargumentExtension */

/* --- Module WTM-Location-Registration-Operations-asn1-97 --- --- ---        */

static int hf_qsig_wtmlr_qsig_wtmlr_LocUpdArg_PDU;  /* LocUpdArg */
static int hf_qsig_wtmlr_qsig_wtmlr_DummyRes_PDU;  /* DummyRes */
static int hf_qsig_wtmlr_qsig_wtmlr_LocDelArg_PDU;  /* LocDelArg */
static int hf_qsig_wtmlr_qsig_wtmlr_LocDeRegArg_PDU;  /* LocDeRegArg */
static int hf_qsig_wtmlr_qsig_wtmlr_PisnEnqArg_PDU;  /* PisnEnqArg */
static int hf_qsig_wtmlr_qsig_wtmlr_PisnEnqRes_PDU;  /* PisnEnqRes */
static int hf_qsig_wtmlr_qsig_wtmlr_GetRRCInfArg_PDU;  /* GetRRCInfArg */
static int hf_qsig_wtmlr_qsig_wtmlr_GetRRCInfRes_PDU;  /* GetRRCInfRes */
static int hf_qsig_wtmlr_qsig_wtmlr_LocInfoCheckArg_PDU;  /* LocInfoCheckArg */
static int hf_qsig_wtmlr_qsig_wtmlr_LocInfoCheckRes_PDU;  /* LocInfoCheckRes */
static int hf_qsig_wtmlr_qsig_wtmlr_Extension_PDU;  /* Extension */
static int hf_qsig_wtmlr_wtmUserId;               /* WtmUserId */
static int hf_qsig_wtmlr_basicService;            /* BasicService */
static int hf_qsig_wtmlr_visitPINX;               /* PartyNumber */
static int hf_qsig_wtmlr_argExtension;            /* LrExtension */
static int hf_qsig_wtmlr_null;                    /* NULL */
static int hf_qsig_wtmlr_extension;               /* Extension */
static int hf_qsig_wtmlr_sequOfExtn;              /* SEQUENCE_OF_Extension */
static int hf_qsig_wtmlr_sequOfExtn_item;         /* Extension */
static int hf_qsig_wtmlr_alternativeId;           /* AlternativeId */
static int hf_qsig_wtmlr_resExtension;            /* LrExtension */
static int hf_qsig_wtmlr_rrClass;                 /* RRClass */
static int hf_qsig_wtmlr_checkResult;             /* CheckResult */
static int hf_qsig_wtmlr_pisnNumber;              /* PartyNumber */

/* --- Module Wireless-Terminal-Call-Handling-Operations-asn1-97 --- --- ---  */

static int hf_qsig_wtmch_qsig_wtmch_EnquiryArg_PDU;  /* EnquiryArg */
static int hf_qsig_wtmch_qsig_wtmch_EnquiryRes_PDU;  /* EnquiryRes */
static int hf_qsig_wtmch_qsig_wtmch_DivertArg_PDU;  /* DivertArg */
static int hf_qsig_wtmch_qsig_wtmch_DummyRes_PDU;  /* DummyRes */
static int hf_qsig_wtmch_qsig_wtmch_InformArg_PDU;  /* InformArg */
static int hf_qsig_wtmch_qsig_wtmch_WtmoArg_PDU;  /* WtmoArg */
static int hf_qsig_wtmch_qsig_wtmch_Extension_PDU;  /* Extension */
static int hf_qsig_wtmch_pisnNumber;              /* PartyNumber */
static int hf_qsig_wtmch_qSIGInfoElement;         /* PSS1InformationElement */
static int hf_qsig_wtmch_argExtension;            /* WtmiExtension */
static int hf_qsig_wtmch_visitPINX;               /* PartyNumber */
static int hf_qsig_wtmch_callingNumber;           /* PresentedNumberScreened */
static int hf_qsig_wtmch_wtmIdentity;             /* WtmIdentity */
static int hf_qsig_wtmch_callingUserSub;          /* PartySubaddress */
static int hf_qsig_wtmch_callingName;             /* Name */
static int hf_qsig_wtmch_wtmUserSub;              /* PartySubaddress */
static int hf_qsig_wtmch_currLocation;            /* CurrLocation */
static int hf_qsig_wtmch_cfuActivated;            /* CfuActivated */
static int hf_qsig_wtmch_divToAddress;            /* Address */
static int hf_qsig_wtmch_divOptions;              /* SubscriptionOption */
static int hf_qsig_wtmch_wtmName;                 /* Name */
static int hf_qsig_wtmch_null;                    /* NULL */
static int hf_qsig_wtmch_extension;               /* Extension */
static int hf_qsig_wtmch_sequOfExtn;              /* SEQUENCE_OF_Extension */
static int hf_qsig_wtmch_sequOfExtn_item;         /* Extension */
static int hf_qsig_wtmch_alternativeId;           /* AlternativeId */
static int hf_qsig_wtmch_both;                    /* T_both */
static int hf_qsig_wtmch_destinationNumber;       /* PartyNumber */
static int hf_qsig_wtmch_sendingComplete;         /* NULL */
static int hf_qsig_wtmch_wtmoaextension;          /* T_wtmoaextension */
static int hf_qsig_wtmch_single;                  /* Extension */
static int hf_qsig_wtmch_multiple;                /* SEQUENCE_OF_Extension */
static int hf_qsig_wtmch_multiple_item;           /* Extension */

/* --- Module WTM-Authentication-Operations-asn1-97 --- --- ---               */

static int hf_qsig_wtmau_qsig_wtmau_AuthWtmArg_PDU;  /* AuthWtmArg */
static int hf_qsig_wtmau_qsig_wtmau_AuthWtmRes_PDU;  /* AuthWtmRes */
static int hf_qsig_wtmau_qsig_wtmau_WtatParamArg_PDU;  /* WtatParamArg */
static int hf_qsig_wtmau_qsig_wtmau_WtatParamRes_PDU;  /* WtatParamRes */
static int hf_qsig_wtmau_qsig_wtmau_WtanParamArg_PDU;  /* WtanParamArg */
static int hf_qsig_wtmau_qsig_wtmau_WtanParamRes_PDU;  /* WtanParamRes */
static int hf_qsig_wtmau_qsig_wtmau_ARG_transferAuthParam_PDU;  /* ARG_transferAuthParam */
static int hf_qsig_wtmau_qsig_wtmau_Extension_PDU;  /* Extension */
static int hf_qsig_wtmau_wtmUserId;               /* WtmUserId */
static int hf_qsig_wtmau_calcWtatInfo;            /* CalcWtatInfo */
static int hf_qsig_wtmau_dummyExtension;          /* DummyExtension */
static int hf_qsig_wtmau_autWtmResValue;          /* T_autWtmResValue */
static int hf_qsig_wtmau_canCompute;              /* CanCompute */
static int hf_qsig_wtmau_authChallenge;           /* AuthChallenge */
static int hf_qsig_wtmau_wtatParamInfo;           /* WtatParamInfo */
static int hf_qsig_wtmau_authAlgorithm;           /* AuthAlgorithm */
static int hf_qsig_wtmau_pisnNumber;              /* PartyNumber */
static int hf_qsig_wtmau_alternativeId;           /* AlternativeId */
static int hf_qsig_wtmau_wtanParamInfo;           /* WtanParamInfo */
static int hf_qsig_wtmau_wtatParamInfoChoice;     /* T_wtatParamInfoChoice */
static int hf_qsig_wtmau_authSessionKeyInfo;      /* AuthSessionKeyInfo */
static int hf_qsig_wtmau_authKey;                 /* AuthKey */
static int hf_qsig_wtmau_challLen;                /* INTEGER_1_8 */
static int hf_qsig_wtmau_calcWtanInfo;            /* CalcWtanInfo */
static int hf_qsig_wtmau_authSessionKey;          /* AuthSessionKey */
static int hf_qsig_wtmau_calculationParam;        /* CalculationParam */
static int hf_qsig_wtmau_CalcWtatInfo_item;       /* CalcWtatInfoUnit */
static int hf_qsig_wtmau_authResponse;            /* AuthResponse */
static int hf_qsig_wtmau_derivedCipherKey;        /* DerivedCipherKey */
static int hf_qsig_wtmau_extension;               /* Extension */
static int hf_qsig_wtmau_sequOfExtn;              /* SEQUENCE_OF_Extension */
static int hf_qsig_wtmau_sequOfExtn_item;         /* Extension */
static int hf_qsig_wtmau_authAlg;                 /* DefinedIDs */
static int hf_qsig_wtmau_param;                   /* T_param */

/* --- Module SS-SD-Operations-asn1-97 --- --- ---                            */

static int hf_qsig_sd_qsig_sd_DisplayArg_PDU;     /* DisplayArg */
static int hf_qsig_sd_qsig_sd_KeypadArg_PDU;      /* KeypadArg */
static int hf_qsig_sd_qsig_sd_Extension_PDU;      /* Extension */
static int hf_qsig_sd_displayString;              /* DisplayString */
static int hf_qsig_sd_sdextension;                /* SDExtension */
static int hf_qsig_sd_displayStringNormal;        /* BMPStringNormal */
static int hf_qsig_sd_displayStringExtended;      /* BMPStringExtended */
static int hf_qsig_sd_keypadString;               /* BMPStringNormal */
static int hf_qsig_sd_extension;                  /* Extension */
static int hf_qsig_sd_multipleExtension;          /* SEQUENCE_OF_Extension */
static int hf_qsig_sd_multipleExtension_item;     /* Extension */

/* --- Module Call-Identification-and-Call-Linkage-Operations-asn1-97 --- --- --- */

static int hf_qsig_cidl_qsig_cidl_CallIdentificationAssignArg_PDU;  /* CallIdentificationAssignArg */
static int hf_qsig_cidl_qsig_cidl_CallIdentificationUpdateArg_PDU;  /* CallIdentificationUpdateArg */
static int hf_qsig_cidl_globalCallID;             /* CallIdentificationData */
static int hf_qsig_cidl_threadID;                 /* CallIdentificationData */
static int hf_qsig_cidl_legID;                    /* CallIdentificationData */
static int hf_qsig_cidl_extensiont;               /* ExtensionType */
static int hf_qsig_cidl_switchingSubDomainName;   /* SwitchingSubDomainName */
static int hf_qsig_cidl_linkageID;                /* T_linkageID */
static int hf_qsig_cidl_subDomainID;              /* SubDomainID */
static int hf_qsig_cidl_globallyUniqueID;         /* GloballyUniqueID */
static int hf_qsig_cidl_timeStamp;                /* TimeStamp */
static int hf_qsig_cidl_extension;                /* Extension */
static int hf_qsig_cidl_sequenceOfExt;            /* SEQUENCE_OF_Extension */
static int hf_qsig_cidl_sequenceOfExt_item;       /* Extension */

/* --- Module Short-Message-Service-Operations-asn1-97 --- --- ---            */

static int hf_qsig_sms_qsig_sms_SmsSubmitArg_PDU;  /* SmsSubmitArg */
static int hf_qsig_sms_qsig_sms_SmsSubmitRes_PDU;  /* SmsSubmitRes */
static int hf_qsig_sms_qsig_sms_SmsDeliverArg_PDU;  /* SmsDeliverArg */
static int hf_qsig_sms_qsig_sms_SmsDeliverRes_PDU;  /* SmsDeliverRes */
static int hf_qsig_sms_qsig_sms_SmsStatusReportArg_PDU;  /* SmsStatusReportArg */
static int hf_qsig_sms_qsig_sms_SmsStatusReportRes_PDU;  /* SmsStatusReportRes */
static int hf_qsig_sms_qsig_sms_SmsCommandArg_PDU;  /* SmsCommandArg */
static int hf_qsig_sms_qsig_sms_SmsCommandRes_PDU;  /* SmsCommandRes */
static int hf_qsig_sms_qsig_sms_ScAlertArg_PDU;   /* ScAlertArg */
static int hf_qsig_sms_qsig_sms_DummyRes_PDU;     /* DummyRes */
static int hf_qsig_sms_qsig_sms_PAR_smsDeliverError_PDU;  /* PAR_smsDeliverError */
static int hf_qsig_sms_qsig_sms_PAR_smsSubmitError_PDU;  /* PAR_smsSubmitError */
static int hf_qsig_sms_qsig_sms_PAR_smsStatusReportError_PDU;  /* PAR_smsStatusReportError */
static int hf_qsig_sms_qsig_sms_PAR_smsCommandError_PDU;  /* PAR_smsCommandError */
static int hf_qsig_sms_qsig_sms_SmsExtension_PDU;  /* SmsExtension */
static int hf_qsig_sms_destinationAddress;        /* PartyNumber */
static int hf_qsig_sms_originatingAddress;        /* PartyNumber */
static int hf_qsig_sms_messageReference;          /* MessageReference */
static int hf_qsig_sms_smSubmitParameter;         /* SmSubmitParameter */
static int hf_qsig_sms_userData;                  /* UserData */
static int hf_qsig_sms_smsExtension;              /* SmsExtension */
static int hf_qsig_sms_serviceCentreTimeStamp;    /* ServiceCentreTimeStamp */
static int hf_qsig_sms_protocolIdentifier;        /* ProtocolIdentifier */
static int hf_qsig_sms_originatingName;           /* Name */
static int hf_qsig_sms_smDeliverParameter;        /* SmDeliverParameter */
static int hf_qsig_sms_smsDeliverResponseChoice;  /* SmsDeliverResChoice */
static int hf_qsig_sms_dischargeTime;             /* DischargeTime */
static int hf_qsig_sms_recipientAddress;          /* PartyNumber */
static int hf_qsig_sms_recipientName;             /* Name */
static int hf_qsig_sms_status;                    /* Status */
static int hf_qsig_sms_priority;                  /* BOOLEAN */
static int hf_qsig_sms_moreMessagesToSend;        /* BOOLEAN */
static int hf_qsig_sms_statusReportQualifier;     /* BOOLEAN */
static int hf_qsig_sms_smsStatusReportResponseChoice;  /* SmsStatusReportResponseChoice */
static int hf_qsig_sms_messageNumber;             /* MessageReference */
static int hf_qsig_sms_commandType;               /* CommandType */
static int hf_qsig_sms_commandData;               /* CommandData */
static int hf_qsig_sms_statusReportRequest;       /* BOOLEAN */
static int hf_qsig_sms_null;                      /* NULL */
static int hf_qsig_sms_validityPeriod;            /* ValidityPeriod */
static int hf_qsig_sms_replyPath;                 /* BOOLEAN */
static int hf_qsig_sms_rejectDuplicates;          /* BOOLEAN */
static int hf_qsig_sms_statusReportIndication;    /* BOOLEAN */
static int hf_qsig_sms_resChoiceSeq;              /* ResChoiceSeq */
static int hf_qsig_sms_single;                    /* Extension */
static int hf_qsig_sms_multiple;                  /* SEQUENCE_OF_Extension */
static int hf_qsig_sms_multiple_item;             /* Extension */
static int hf_qsig_sms_validityPeriodRel;         /* ValidityPeriodRel */
static int hf_qsig_sms_validityPeriodAbs;         /* ValidityPeriodAbs */
static int hf_qsig_sms_validityPeriodEnh;         /* ValidityPeriodEnh */
static int hf_qsig_sms_singleShotSM;              /* BOOLEAN */
static int hf_qsig_sms_enhancedVP;                /* EnhancedVP */
static int hf_qsig_sms_validityPeriodSec;         /* INTEGER_0_255 */
static int hf_qsig_sms_validityPeriodSemi;        /* ValidityPeriodSemi */
static int hf_qsig_sms_userDataHeader;            /* UserDataHeader */
static int hf_qsig_sms_class;                     /* INTEGER_0_3 */
static int hf_qsig_sms_compressed;                /* BOOLEAN */
static int hf_qsig_sms_shortMessageText;          /* ShortMessageText */
static int hf_qsig_sms_shortMessageTextType;      /* ShortMessageTextType */
static int hf_qsig_sms_shortMessageTextData;      /* ShortMessageTextData */
static int hf_qsig_sms_UserDataHeader_item;       /* UserDataHeaderChoice */
static int hf_qsig_sms_smscControlParameterHeader;  /* SmscControlParameterHeader */
static int hf_qsig_sms_concatenated8BitSMHeader;  /* Concatenated8BitSMHeader */
static int hf_qsig_sms_concatenated16BitSMHeader;  /* Concatenated16BitSMHeader */
static int hf_qsig_sms_applicationPort8BitHeader;  /* ApplicationPort8BitHeader */
static int hf_qsig_sms_applicationPort16BitHeader;  /* ApplicationPort16BitHeader */
static int hf_qsig_sms_dataHeaderSourceIndicator;  /* DataHeaderSourceIndicator */
static int hf_qsig_sms_wirelessControlHeader;     /* WirelessControlHeader */
static int hf_qsig_sms_genericUserValue;          /* GenericUserValue */
static int hf_qsig_sms_concatenated8BitSMReferenceNumber;  /* INTEGER_0_255 */
static int hf_qsig_sms_maximumNumberOf8BitSMInConcatenatedSM;  /* INTEGER_0_255 */
static int hf_qsig_sms_sequenceNumberOf8BitSM;    /* INTEGER_0_255 */
static int hf_qsig_sms_concatenated16BitSMReferenceNumber;  /* INTEGER_0_65536 */
static int hf_qsig_sms_maximumNumberOf16BitSMInConcatenatedSM;  /* INTEGER_0_255 */
static int hf_qsig_sms_sequenceNumberOf16BitSM;   /* INTEGER_0_255 */
static int hf_qsig_sms_destination8BitPort;       /* INTEGER_0_255 */
static int hf_qsig_sms_originator8BitPort;        /* INTEGER_0_255 */
static int hf_qsig_sms_destination16BitPort;      /* INTEGER_0_65536 */
static int hf_qsig_sms_originator16BitPort;       /* INTEGER_0_65536 */
static int hf_qsig_sms_parameterValue;            /* INTEGER_0_255 */
static int hf_qsig_sms_genericUserData;           /* OCTET_STRING */
static int hf_qsig_sms_failureCause;              /* FailureCause */
static int hf_qsig_sms_scAddressSaved;            /* BOOLEAN */
/* named bits */
static int hf_qsig_sms_SmscControlParameterHeader_sRforTransactionCompleted;
static int hf_qsig_sms_SmscControlParameterHeader_sRforPermanentError;
static int hf_qsig_sms_SmscControlParameterHeader_sRforTempErrorSCnotTrying;
static int hf_qsig_sms_SmscControlParameterHeader_sRforTempErrorSCstillTrying;
static int hf_qsig_sms_SmscControlParameterHeader_spare_bit4;
static int hf_qsig_sms_SmscControlParameterHeader_spare_bit5;
static int hf_qsig_sms_SmscControlParameterHeader_cancelSRRforConcatenatedSM;
static int hf_qsig_sms_SmscControlParameterHeader_includeOrigUDHintoSR;

/* --- Module SS-MCR-Operations-asn97 --- --- ---                             */

static int hf_qsig_mcr_qsig_mcr_MCRequestArg_PDU;  /* MCRequestArg */
static int hf_qsig_mcr_qsig_mcr_MCRequestResult_PDU;  /* MCRequestResult */
static int hf_qsig_mcr_qsig_mcr_MCInformArg_PDU;  /* MCInformArg */
static int hf_qsig_mcr_qsig_mcr_MCAlertingArg_PDU;  /* MCAlertingArg */
static int hf_qsig_mcr_qsig_mcr_Extension_PDU;    /* Extension */
static int hf_qsig_mcr_callType;                  /* CallType */
static int hf_qsig_mcr_retainOrigCall;            /* BOOLEAN */
static int hf_qsig_mcr_destinationAddress;        /* PresentedAddressUnscreened */
static int hf_qsig_mcr_requestingAddress;         /* PresentedAddressUnscreened */
static int hf_qsig_mcr_cooperatingAddress;        /* PresentedAddressUnscreened */
static int hf_qsig_mcr_correlation;               /* Correlation */
static int hf_qsig_mcr_extensions;                /* MCRExtensions */
static int hf_qsig_mcr_basicService;              /* BasicService */
static int hf_qsig_mcr_cisc;                      /* NULL */
static int hf_qsig_mcr_correlationData;           /* CallIdentity */
static int hf_qsig_mcr_correlationReason;         /* CorrelationReason */
static int hf_qsig_mcr_none;                      /* NULL */
static int hf_qsig_mcr_single;                    /* Extension */
static int hf_qsig_mcr_multiple;                  /* SEQUENCE_OF_Extension */
static int hf_qsig_mcr_multiple_item;             /* Extension */

/* --- Module SS-MCM-Operations-asn1-97 --- --- ---                           */

static int hf_qsig_mcm_qsig_mcm_MCMNewMsgArg_PDU;  /* MCMNewMsgArg */
static int hf_qsig_mcm_qsig_mcm_MCMDummyRes_PDU;  /* MCMDummyRes */
static int hf_qsig_mcm_qsig_mcm_MCMNoNewMsgArg_PDU;  /* MCMNoNewMsgArg */
static int hf_qsig_mcm_qsig_mcm_MCMUpdateArg_PDU;  /* MCMUpdateArg */
static int hf_qsig_mcm_qsig_mcm_MCMUpdateReqArg_PDU;  /* MCMUpdateReqArg */
static int hf_qsig_mcm_qsig_mcm_MCMUpdateReqRes_PDU;  /* MCMUpdateReqRes */
static int hf_qsig_mcm_qsig_mcm_MCMServiceArg_PDU;  /* MCMServiceArg */
static int hf_qsig_mcm_qsig_mcm_MCMInterrogateArg_PDU;  /* MCMInterrogateArg */
static int hf_qsig_mcm_qsig_mcm_MCMInterrogateRes_PDU;  /* MCMInterrogateRes */
static int hf_qsig_mcm_qsig_mcm_MCMailboxFullArg_PDU;  /* MCMailboxFullArg */
static int hf_qsig_mcm_qsig_mcm_Extension_PDU;    /* Extension */
static int hf_qsig_mcm_partyInfo;                 /* PartyInfo */
static int hf_qsig_mcm_mailboxFullFor;            /* MailboxFullFor */
static int hf_qsig_mcm_extensions;                /* MCMExtensions */
static int hf_qsig_mcm_MailboxFullFor_item;       /* MailboxFullPar */
static int hf_qsig_mcm_messageType;               /* MessageType */
static int hf_qsig_mcm_capacityReached;           /* INTEGER_0_100 */
static int hf_qsig_mcm_mCMChange;                 /* MCMChange */
static int hf_qsig_mcm_activateMCM;               /* SEQUENCE_OF_MCMServiceInfo */
static int hf_qsig_mcm_activateMCM_item;          /* MCMServiceInfo */
static int hf_qsig_mcm_deactivateMCM;             /* SEQUENCE_OF_MessageType */
static int hf_qsig_mcm_deactivateMCM_item;        /* MessageType */
static int hf_qsig_mcm_setToDefaultValues;        /* NULL */
static int hf_qsig_mcm_mCMModeNew;                /* MCMMode */
static int hf_qsig_mcm_mCMModeRetrieved;          /* MCMMode */
static int hf_qsig_mcm_interrogateInfo;           /* SEQUENCE_OF_MessageType */
static int hf_qsig_mcm_interrogateInfo_item;      /* MessageType */
static int hf_qsig_mcm_interrogateResult;         /* SEQUENCE_OF_MCMServiceInfo */
static int hf_qsig_mcm_interrogateResult_item;    /* MCMServiceInfo */
static int hf_qsig_mcm_servedUserNr;              /* PartyNumber */
static int hf_qsig_mcm_specificMessageType;       /* MessageType */
static int hf_qsig_mcm_msgCentreId;               /* MsgCentreId */
static int hf_qsig_mcm_nrOfMessages;              /* NrOfMessages */
static int hf_qsig_mcm_originatingNr;             /* PartyNumber */
static int hf_qsig_mcm_timestamp;                 /* TimeStamp */
static int hf_qsig_mcm_priority;                  /* INTEGER_0_9 */
static int hf_qsig_mcm_argumentExtMCMNew;         /* MCMNewArgumentExt */
static int hf_qsig_mcm_extension;                 /* Extension */
static int hf_qsig_mcm_multipleExtension;         /* SEQUENCE_OF_Extension */
static int hf_qsig_mcm_multipleExtension_item;    /* Extension */
static int hf_qsig_mcm_argumentExtMCMNoNew;       /* MCMNoNewArgumentExt */
static int hf_qsig_mcm_updateInfo;                /* UpdateInfo */
static int hf_qsig_mcm_moreInfoFollows;           /* BOOLEAN */
static int hf_qsig_mcm_argumentExtMCMUpdArg;      /* MCMUpdArgArgumentExt */
static int hf_qsig_mcm_MCMUpdateReqRes_item;      /* MCMUpdateReqResElt */
static int hf_qsig_mcm_argumentExtMCMUpdRes;      /* MCMUpdResArgumentExt */
static int hf_qsig_mcm_messageCentreID;           /* MsgCentreId */
static int hf_qsig_mcm_newMsgInfoOnly;            /* MessageInfo */
static int hf_qsig_mcm_retrievedMsgInfoOnly;      /* MessageInfo */
static int hf_qsig_mcm_allMsgInfo;                /* AllMsgInfo */
static int hf_qsig_mcm_newMsgInfo;                /* MessageInfo */
static int hf_qsig_mcm_retrievedMsgInfo;          /* MessageInfo */
static int hf_qsig_mcm_completeInfo;              /* CompleteInfo */
static int hf_qsig_mcm_compressedInfo;            /* CompressedInfo */
static int hf_qsig_mcm_noMsgsOfMsgType;           /* NULL */
static int hf_qsig_mcm_CompleteInfo_item;         /* AddressHeader */
static int hf_qsig_mcm_originatorNr;              /* PartyNumber */
static int hf_qsig_mcm_timeStamp;                 /* TimeStamp */
static int hf_qsig_mcm_ahpriority;                /* Priority */
static int hf_qsig_mcm_lastTimeStamp;             /* TimeStamp */
static int hf_qsig_mcm_highestPriority;           /* Priority */
static int hf_qsig_mcm_integer;                   /* INTEGER_0_65535 */
static int hf_qsig_mcm_partyNumber;               /* PartyNumber */
static int hf_qsig_mcm_numericString;             /* NumericString_SIZE_1_10 */
static int hf_qsig_mcm_none;                      /* NULL */

/* --- Module SS-MID-Operations-asn1-97 --- --- ---                           */

static int hf_qsig_mid_qsig_mid_MIDMailboxAuthArg_PDU;  /* MIDMailboxAuthArg */
static int hf_qsig_mid_qsig_mid_MIDDummyRes_PDU;  /* MIDDummyRes */
static int hf_qsig_mid_qsig_mid_MIDMailboxIDArg_PDU;  /* MIDMailboxIDArg */
static int hf_qsig_mid_qsig_mid_Extension_PDU;    /* Extension */
static int hf_qsig_mid_partyInfo;                 /* PartyInfo */
static int hf_qsig_mid_servedUserName;            /* Name */
static int hf_qsig_mid_mailBox;                   /* String */
static int hf_qsig_mid_password;                  /* String */
static int hf_qsig_mid_extensions;                /* MIDExtensions */
static int hf_qsig_mid_servedUserNr;              /* PresentedAddressUnscreened */
static int hf_qsig_mid_messageType;               /* MessageType */
static int hf_qsig_mid_messageCentreID;           /* MsgCentreId */
static int hf_qsig_mid_stringBmp;                 /* BMPString */
static int hf_qsig_mid_stringUtf8;                /* UTF8String */
static int hf_qsig_mid_none;                      /* NULL */
static int hf_qsig_mid_extension;                 /* Extension */
static int hf_qsig_mid_multipleExtension;         /* SEQUENCE_OF_Extension */
static int hf_qsig_mid_multipleExtension_item;    /* Extension */

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
static int ett_qsig;
static int ett_qsig_ie;
static int ett_qsig_unknown_extension;

/* --- Modules Manufacturer-specific-service-extension-class-asn1-97 PSS1-generic-parameters-definition-asn1-97 Addressing-Data-Elements-asn1-97 --- --- --- */

static int ett_qsig_Extension;
static int ett_qsig_PresentedAddressScreened;
static int ett_qsig_PresentedAddressUnscreened;
static int ett_qsig_PresentedNumberScreened;
static int ett_qsig_PresentedNumberUnscreened;
static int ett_qsig_AddressScreened;
static int ett_qsig_NumberScreened;
static int ett_qsig_Address;
static int ett_qsig_PartyNumber;
static int ett_qsig_PublicPartyNumber;
static int ett_qsig_PrivatePartyNumber;
static int ett_qsig_PartySubaddress;
static int ett_qsig_UserSpecifiedSubaddress;

/* --- Module Name-Operations-asn1-97 --- --- ---                             */

static int ett_qsig_na_NameArg;
static int ett_qsig_na_T_nameSequence;
static int ett_qsig_na_NameExtension;
static int ett_qsig_na_SEQUENCE_OF_Extension;
static int ett_qsig_na_Name;
static int ett_qsig_na_NamePresentationAllowed;
static int ett_qsig_na_NamePresentationRestricted;
static int ett_qsig_na_NameSet;

/* --- Module Call-Diversion-Operations-asn1-97 --- --- ---                   */

static int ett_qsig_cf_ARG_activateDiversionQ;
static int ett_qsig_cf_ADExtension;
static int ett_qsig_cf_SEQUENCE_OF_Extension;
static int ett_qsig_cf_RES_activateDiversionQ;
static int ett_qsig_cf_ARG_deactivateDiversionQ;
static int ett_qsig_cf_DDExtension;
static int ett_qsig_cf_RES_deactivateDiversionQ;
static int ett_qsig_cf_ARG_interrogateDiversionQ;
static int ett_qsig_cf_IDExtension;
static int ett_qsig_cf_ARG_checkRestriction;
static int ett_qsig_cf_CHRExtension;
static int ett_qsig_cf_RES_checkRestriction;
static int ett_qsig_cf_ARG_callRerouteing;
static int ett_qsig_cf_CRRExtension;
static int ett_qsig_cf_RES_callRerouteing;
static int ett_qsig_cf_ARG_divertingLegInformation1;
static int ett_qsig_cf_DLI1Extension;
static int ett_qsig_cf_ARG_divertingLegInformation2;
static int ett_qsig_cf_DLI2Extension;
static int ett_qsig_cf_ARG_divertingLegInformation3;
static int ett_qsig_cf_DLI3Extension;
static int ett_qsig_cf_ARG_cfnrDivertedLegFailed;
static int ett_qsig_cf_IntResultList;
static int ett_qsig_cf_IntResult;
static int ett_qsig_cf_IRExtension;

/* --- Module Path-Replacement-Operations-asn1-97 --- --- ---                 */

static int ett_qsig_pr_PRProposeArg;
static int ett_qsig_pr_PRPExtension;
static int ett_qsig_pr_SEQUENCE_OF_Extension;
static int ett_qsig_pr_PRSetupArg;
static int ett_qsig_pr_PRSExtension;
static int ett_qsig_pr_PRRetainArg;
static int ett_qsig_pr_PRRExtension;
static int ett_qsig_pr_DummyResult;
static int ett_qsig_pr_DummyArg;

/* --- Module Call-Transfer-Operations-asn1-97 --- --- ---                    */

static int ett_qsig_ct_DummyArg;
static int ett_qsig_ct_SEQUENCE_OF_Extension;
static int ett_qsig_ct_DummyRes;
static int ett_qsig_ct_CTIdentifyRes;
static int ett_qsig_ct_T_resultExtension;
static int ett_qsig_ct_CTInitiateArg;
static int ett_qsig_ct_CTIargumentExtension;
static int ett_qsig_ct_CTSetupArg;
static int ett_qsig_ct_CTSargumentExtension;
static int ett_qsig_ct_CTActiveArg;
static int ett_qsig_ct_CTAargumentExtension;
static int ett_qsig_ct_CTCompleteArg;
static int ett_qsig_ct_CTCargumentExtension;
static int ett_qsig_ct_CTUpdateArg;
static int ett_qsig_ct_CTUargumentExtension;
static int ett_qsig_ct_SubaddressTransferArg;
static int ett_qsig_ct_STargumentExtension;

/* --- Module SS-CC-Operations-asn1-97 --- --- ---                            */

static int ett_qsig_cc_CcRequestArg;
static int ett_qsig_cc_CcRequestRes;
static int ett_qsig_cc_CcOptionalArg;
static int ett_qsig_cc_T_fullArg;
static int ett_qsig_cc_CcExtension;
static int ett_qsig_cc_SEQUENCE_OF_Extension;

/* --- Module Call-Offer-Operations-asn1-97 --- --- ---                       */

static int ett_qsig_co_PathRetainArg;
static int ett_qsig_co_T_extendedServiceList;
static int ett_qsig_co_ServiceAvailableArg;
static int ett_qsig_co_T_extendedServiceList_01;
static int ett_qsig_co_ServiceList;
static int ett_qsig_co_DummyArg;
static int ett_qsig_co_SEQUENCE_OF_Extension;
static int ett_qsig_co_DummyRes;

/* --- Module Do-Not-Disturb-Operations-asn1-97 --- --- ---                   */

static int ett_qsig_dnd_DummyArg;
static int ett_qsig_dnd_SEQUENCE_OF_Extension;
static int ett_qsig_dnd_DummyRes;
static int ett_qsig_dnd_DNDActivateArg;
static int ett_qsig_dnd_DNDAargumentExtension;
static int ett_qsig_dnd_DNDActivateRes;
static int ett_qsig_dnd_T_status;
static int ett_qsig_dnd_T_status_item;
static int ett_qsig_dnd_T_resultExtension;
static int ett_qsig_dnd_DNDDeactivateArg;
static int ett_qsig_dnd_DNDDargumentExtension;
static int ett_qsig_dnd_DNDInterrogateArg;
static int ett_qsig_dnd_DNDIargumentExtension;
static int ett_qsig_dnd_DNDInterrogateRes;
static int ett_qsig_dnd_T_status_01;
static int ett_qsig_dnd_T_status_item_01;
static int ett_qsig_dnd_T_resultExtension_01;
static int ett_qsig_dnd_DNDOverrideArg;
static int ett_qsig_dnd_DNDOargumentExtension;
static int ett_qsig_dnd_PathRetainArg;
static int ett_qsig_dnd_T_extendedServiceList;
static int ett_qsig_dnd_ServiceAvailableArg;
static int ett_qsig_dnd_T_extendedServiceList_01;
static int ett_qsig_dnd_ServiceList;

/* --- Module Call-Intrusion-Operations-asn1-97 --- --- ---                   */

static int ett_qsig_ci_PathRetainArg;
static int ett_qsig_ci_T_extendedServiceList;
static int ett_qsig_ci_ServiceAvailableArg;
static int ett_qsig_ci_T_extendedServiceList_01;
static int ett_qsig_ci_ServiceList;
static int ett_qsig_ci_DummyArg;
static int ett_qsig_ci_SEQUENCE_OF_Extension;
static int ett_qsig_ci_DummyRes;
static int ett_qsig_ci_CIRequestArg;
static int ett_qsig_ci_T_argumentExtension;
static int ett_qsig_ci_CIRequestRes;
static int ett_qsig_ci_T_resultExtension;
static int ett_qsig_ci_CIGetCIPLRes;
static int ett_qsig_ci_T_resultExtension_01;

/* --- Module SS-AOC-Operations-asn1-97 --- --- ---                           */

static int ett_qsig_aoc_AocRateArg;
static int ett_qsig_aoc_T_aocRate;
static int ett_qsig_aoc_T_rateArgExtension;
static int ett_qsig_aoc_SEQUENCE_OF_Extension;
static int ett_qsig_aoc_AocInterimArg;
static int ett_qsig_aoc_T_interimCharge;
static int ett_qsig_aoc_T_specificCurrency;
static int ett_qsig_aoc_T_interimArgExtension;
static int ett_qsig_aoc_AocFinalArg;
static int ett_qsig_aoc_T_finalCharge;
static int ett_qsig_aoc_T_specificCurrency_01;
static int ett_qsig_aoc_T_finalArgExtension;
static int ett_qsig_aoc_AOCSCurrencyInfoList;
static int ett_qsig_aoc_AOCSCurrencyInfo;
static int ett_qsig_aoc_T_rateType;
static int ett_qsig_aoc_DurationCurrency;
static int ett_qsig_aoc_FlatRateCurrency;
static int ett_qsig_aoc_VolumeRateCurrency;
static int ett_qsig_aoc_RecordedCurrency;
static int ett_qsig_aoc_Amount;
static int ett_qsig_aoc_Time;
static int ett_qsig_aoc_ChargingAssociation;
static int ett_qsig_aoc_ChargeRequestArg;
static int ett_qsig_aoc_SEQUENCE_SIZE_0_7_OF_AdviceModeCombination;
static int ett_qsig_aoc_T_chargeReqArgExtension;
static int ett_qsig_aoc_ChargeRequestRes;
static int ett_qsig_aoc_T_chargeReqResExtension;
static int ett_qsig_aoc_DummyArg;
static int ett_qsig_aoc_AocCompleteArg;
static int ett_qsig_aoc_T_completeArgExtension;
static int ett_qsig_aoc_AocCompleteRes;
static int ett_qsig_aoc_T_completeResExtension;
static int ett_qsig_aoc_AocDivChargeReqArg;
static int ett_qsig_aoc_T_aocDivChargeReqArgExt;

/* --- Module Recall-Operations-asn1-97 --- --- ---                           */

static int ett_qsig_re_ReAlertingArg;
static int ett_qsig_re_T_argumentExtension;
static int ett_qsig_re_SEQUENCE_OF_Extension;
static int ett_qsig_re_ReAnswerArg;
static int ett_qsig_re_T_argumentExtension_01;

/* --- Module Synchronization-Operations-asn1-97 --- --- ---                  */

static int ett_qsig_sync_SynchronizationReqArg;
static int ett_qsig_sync_SynchronizationReqRes;
static int ett_qsig_sync_SynchronizationInfoArg;
static int ett_qsig_sync_ArgExtension;
static int ett_qsig_sync_SEQUENCE_OF_Extension;

/* --- Module Call-Interception-Operations-asn1-97 --- --- ---                */

static int ett_qsig_cint_CintInformation1Arg;
static int ett_qsig_cint_CintInformation2Arg;
static int ett_qsig_cint_CintCondArg;
static int ett_qsig_cint_CintExtension;
static int ett_qsig_cint_SEQUENCE_OF_Extension;

/* --- Module Common-Information-Operations-asn1-97 --- --- ---               */

static int ett_qsig_cmn_CmnArg;
static int ett_qsig_cmn_T_extension;
static int ett_qsig_cmn_SEQUENCE_OF_Extension;
static int ett_qsig_cmn_DummyArg;
static int ett_qsig_cmn_FeatureIdList;
static int ett_qsig_cmn_EquipmentId;

/* --- Module Call-Interruption-Operations-asn1-97 --- --- ---                */

static int ett_qsig_cpi_CPIRequestArg;
static int ett_qsig_cpi_T_argumentExtension;
static int ett_qsig_cpi_SEQUENCE_OF_Extension;
static int ett_qsig_cpi_CPIPRequestArg;
static int ett_qsig_cpi_T_argumentExtension_01;

/* --- Module PUM-Registration-Operations-asn1-97 --- --- ---                 */

static int ett_qsig_pumr_PumRegistrArg;
static int ett_qsig_pumr_RpumUserId;
static int ett_qsig_pumr_T_userPin;
static int ett_qsig_pumr_PumRegistrRes;
static int ett_qsig_pumr_DummyRes;
static int ett_qsig_pumr_SEQUENCE_OF_Extension;
static int ett_qsig_pumr_PumDelRegArg;
static int ett_qsig_pumr_XpumUserId;
static int ett_qsig_pumr_PumDe_regArg;
static int ett_qsig_pumr_DpumUserId;
static int ett_qsig_pumr_T_userPin_01;
static int ett_qsig_pumr_PumInterrogArg;
static int ett_qsig_pumr_IpumUserId;
static int ett_qsig_pumr_T_userPin_02;
static int ett_qsig_pumr_PumInterrogRes;
static int ett_qsig_pumr_PumInterrogRes_item;
static int ett_qsig_pumr_SessionParams;
static int ett_qsig_pumr_PumrExtension;

/* --- Module Private-User-Mobility-Call-Handling-Operations-asn1-97 --- --- --- */

static int ett_qsig_pumch_EnquiryArg;
static int ett_qsig_pumch_DivertArg;
static int ett_qsig_pumch_InformArg;
static int ett_qsig_pumch_EnquiryRes;
static int ett_qsig_pumch_CurrLocation;
static int ett_qsig_pumch_CfuActivated;
static int ett_qsig_pumch_DummyRes;
static int ett_qsig_pumch_SEQUENCE_OF_Extension;
static int ett_qsig_pumch_PumiExtension;
static int ett_qsig_pumch_PumIdentity;
static int ett_qsig_pumch_T_both;
static int ett_qsig_pumch_PumoArg;
static int ett_qsig_pumch_T_pumoaextension;

/* --- Module Single-Step-Call-Transfer-Operations-asn1-97 --- --- ---        */

static int ett_qsig_ssct_DummyArg;
static int ett_qsig_ssct_SEQUENCE_OF_Extension;
static int ett_qsig_ssct_DummyRes;
static int ett_qsig_ssct_SSCTInitiateArg;
static int ett_qsig_ssct_SSCTIargumentExtension;
static int ett_qsig_ssct_SSCTSetupArg;
static int ett_qsig_ssct_SSCTSargumentExtension;
static int ett_qsig_ssct_SSCTDigitInfoArg;
static int ett_qsig_ssct_SSCTDargumentExtension;

/* --- Module WTM-Location-Registration-Operations-asn1-97 --- --- ---        */

static int ett_qsig_wtmlr_LocUpdArg;
static int ett_qsig_wtmlr_DummyRes;
static int ett_qsig_wtmlr_SEQUENCE_OF_Extension;
static int ett_qsig_wtmlr_LocDelArg;
static int ett_qsig_wtmlr_LocDeRegArg;
static int ett_qsig_wtmlr_PisnEnqArg;
static int ett_qsig_wtmlr_PisnEnqRes;
static int ett_qsig_wtmlr_GetRRCInfArg;
static int ett_qsig_wtmlr_GetRRCInfRes;
static int ett_qsig_wtmlr_LocInfoCheckArg;
static int ett_qsig_wtmlr_LocInfoCheckRes;
static int ett_qsig_wtmlr_WtmUserId;
static int ett_qsig_wtmlr_LrExtension;

/* --- Module Wireless-Terminal-Call-Handling-Operations-asn1-97 --- --- ---  */

static int ett_qsig_wtmch_EnquiryArg;
static int ett_qsig_wtmch_DivertArg;
static int ett_qsig_wtmch_InformArg;
static int ett_qsig_wtmch_EnquiryRes;
static int ett_qsig_wtmch_CurrLocation;
static int ett_qsig_wtmch_CfuActivated;
static int ett_qsig_wtmch_DummyRes;
static int ett_qsig_wtmch_SEQUENCE_OF_Extension;
static int ett_qsig_wtmch_WtmiExtension;
static int ett_qsig_wtmch_WtmIdentity;
static int ett_qsig_wtmch_T_both;
static int ett_qsig_wtmch_WtmoArg;
static int ett_qsig_wtmch_T_wtmoaextension;

/* --- Module WTM-Authentication-Operations-asn1-97 --- --- ---               */

static int ett_qsig_wtmau_AuthWtmArg;
static int ett_qsig_wtmau_AuthWtmRes;
static int ett_qsig_wtmau_WtatParamArg;
static int ett_qsig_wtmau_WtatParamRes;
static int ett_qsig_wtmau_WtanParamArg;
static int ett_qsig_wtmau_WtmUserId;
static int ett_qsig_wtmau_WtanParamRes;
static int ett_qsig_wtmau_ARG_transferAuthParam;
static int ett_qsig_wtmau_WtatParamInfo;
static int ett_qsig_wtmau_T_wtatParamInfoChoice;
static int ett_qsig_wtmau_WtanParamInfo;
static int ett_qsig_wtmau_AuthSessionKeyInfo;
static int ett_qsig_wtmau_CalcWtatInfo;
static int ett_qsig_wtmau_CalcWtatInfoUnit;
static int ett_qsig_wtmau_CalcWtanInfo;
static int ett_qsig_wtmau_DummyExtension;
static int ett_qsig_wtmau_SEQUENCE_OF_Extension;
static int ett_qsig_wtmau_AuthAlgorithm;

/* --- Module SS-SD-Operations-asn1-97 --- --- ---                            */

static int ett_qsig_sd_DisplayArg;
static int ett_qsig_sd_DisplayString;
static int ett_qsig_sd_KeypadArg;
static int ett_qsig_sd_SDExtension;
static int ett_qsig_sd_SEQUENCE_OF_Extension;

/* --- Module Call-Identification-and-Call-Linkage-Operations-asn1-97 --- --- --- */

static int ett_qsig_cidl_CallIdentificationAssignArg;
static int ett_qsig_cidl_CallIdentificationUpdateArg;
static int ett_qsig_cidl_CallIdentificationData;
static int ett_qsig_cidl_T_linkageID;
static int ett_qsig_cidl_ExtensionType;
static int ett_qsig_cidl_SEQUENCE_OF_Extension;

/* --- Module Short-Message-Service-Operations-asn1-97 --- --- ---            */

static int ett_qsig_sms_SmsSubmitArg;
static int ett_qsig_sms_SmsSubmitRes;
static int ett_qsig_sms_SmsDeliverArg;
static int ett_qsig_sms_SmsDeliverRes;
static int ett_qsig_sms_SmsStatusReportArg;
static int ett_qsig_sms_SmsStatusReportRes;
static int ett_qsig_sms_SmsCommandArg;
static int ett_qsig_sms_SmsCommandRes;
static int ett_qsig_sms_ScAlertArg;
static int ett_qsig_sms_DummyRes;
static int ett_qsig_sms_SmSubmitParameter;
static int ett_qsig_sms_SmDeliverParameter;
static int ett_qsig_sms_SmsDeliverResChoice;
static int ett_qsig_sms_ResChoiceSeq;
static int ett_qsig_sms_SmsStatusReportResponseChoice;
static int ett_qsig_sms_SmsExtension;
static int ett_qsig_sms_SEQUENCE_OF_Extension;
static int ett_qsig_sms_ValidityPeriod;
static int ett_qsig_sms_ValidityPeriodEnh;
static int ett_qsig_sms_EnhancedVP;
static int ett_qsig_sms_UserData;
static int ett_qsig_sms_ShortMessageText;
static int ett_qsig_sms_UserDataHeader;
static int ett_qsig_sms_UserDataHeaderChoice;
static int ett_qsig_sms_SmscControlParameterHeader;
static int ett_qsig_sms_Concatenated8BitSMHeader;
static int ett_qsig_sms_Concatenated16BitSMHeader;
static int ett_qsig_sms_ApplicationPort8BitHeader;
static int ett_qsig_sms_ApplicationPort16BitHeader;
static int ett_qsig_sms_GenericUserValue;
static int ett_qsig_sms_PAR_smsDeliverError;
static int ett_qsig_sms_PAR_smsSubmitError;
static int ett_qsig_sms_PAR_smsStatusReportError;
static int ett_qsig_sms_PAR_smsCommandError;

/* --- Module SS-MCR-Operations-asn97 --- --- ---                             */

static int ett_qsig_mcr_MCRequestArg;
static int ett_qsig_mcr_MCRequestResult;
static int ett_qsig_mcr_MCInformArg;
static int ett_qsig_mcr_MCAlertingArg;
static int ett_qsig_mcr_CallType;
static int ett_qsig_mcr_Correlation;
static int ett_qsig_mcr_MCRExtensions;
static int ett_qsig_mcr_SEQUENCE_OF_Extension;

/* --- Module SS-MCM-Operations-asn1-97 --- --- ---                           */

static int ett_qsig_mcm_MCMailboxFullArg;
static int ett_qsig_mcm_MailboxFullFor;
static int ett_qsig_mcm_MailboxFullPar;
static int ett_qsig_mcm_MCMServiceArg;
static int ett_qsig_mcm_MCMChange;
static int ett_qsig_mcm_SEQUENCE_OF_MCMServiceInfo;
static int ett_qsig_mcm_SEQUENCE_OF_MessageType;
static int ett_qsig_mcm_MCMServiceInfo;
static int ett_qsig_mcm_MCMInterrogateArg;
static int ett_qsig_mcm_MCMInterrogateRes;
static int ett_qsig_mcm_MCMNewMsgArg;
static int ett_qsig_mcm_MCMNewArgumentExt;
static int ett_qsig_mcm_SEQUENCE_OF_Extension;
static int ett_qsig_mcm_MCMNoNewMsgArg;
static int ett_qsig_mcm_MCMNoNewArgumentExt;
static int ett_qsig_mcm_MCMUpdateArg;
static int ett_qsig_mcm_MCMUpdateReqArg;
static int ett_qsig_mcm_MCMUpdArgArgumentExt;
static int ett_qsig_mcm_MCMUpdateReqRes;
static int ett_qsig_mcm_MCMUpdateReqResElt;
static int ett_qsig_mcm_MCMUpdResArgumentExt;
static int ett_qsig_mcm_PartyInfo;
static int ett_qsig_mcm_UpdateInfo;
static int ett_qsig_mcm_AllMsgInfo;
static int ett_qsig_mcm_MessageInfo;
static int ett_qsig_mcm_CompleteInfo;
static int ett_qsig_mcm_AddressHeader;
static int ett_qsig_mcm_CompressedInfo;
static int ett_qsig_mcm_MsgCentreId;
static int ett_qsig_mcm_MCMExtensions;

/* --- Module SS-MID-Operations-asn1-97 --- --- ---                           */

static int ett_qsig_mid_MIDMailboxAuthArg;
static int ett_qsig_mid_MIDMailboxIDArg;
static int ett_qsig_mid_PartyInfo;
static int ett_qsig_mid_String;
static int ett_qsig_mid_MIDExtensions;
static int ett_qsig_mid_SEQUENCE_OF_Extension;
static int ett_cnq_PSS1InformationElement;

/* static expert_field ei_qsig_unsupported_arg_type; */
static expert_field ei_qsig_unsupported_result_type;
static expert_field ei_qsig_unsupported_error_type;

/* Preferences */

/* Subdissectors */
static dissector_handle_t q931_ie_handle;

/* Global variables */
static const char *extension_oid;

/* Dissector tables */
static dissector_table_t extension_dissector_table;


/* --- Modules Manufacturer-specific-service-extension-class-asn1-97 PSS1-generic-parameters-definition-asn1-97 Addressing-Data-Elements-asn1-97 --- --- --- */



static int
dissect_qsig_T_extensionId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_index, &extension_oid);

  return offset;
}



static int
dissect_qsig_T_extensionArgument(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
    tvbuff_t *next_tvb;

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    if (!dissector_try_string_new(extension_dissector_table, extension_oid, next_tvb, actx->pinfo, tree, false, NULL)) {
        proto_tree *next_tree;

        next_tree=proto_tree_add_subtree_format(tree, next_tvb, 0, -1, ett_qsig_unknown_extension, NULL,
                               "QSIG: Dissector for extension with OID:%s not implemented.", extension_oid);

        dissect_unknown_ber(actx->pinfo, next_tvb, offset, next_tree);
    }

    offset+=tvb_reported_length_remaining(tvb, offset);

  return offset;
}


static const ber_sequence_t qsig_Extension_sequence[] = {
  { &hf_qsig_extensionId    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_qsig_T_extensionId },
  { &hf_qsig_extensionArgument, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_qsig_T_extensionArgument },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_qsig_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  extension_oid = NULL;
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_Extension_sequence, hf_index, ett_qsig_Extension);

  return offset;
}



static int
dissect_qsig_PSS1InformationElement_U(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  tvbuff_t *out_tvb = NULL;
  proto_tree *data_tree;

  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &out_tvb);

  data_tree = proto_item_add_subtree(actx->created_item, ett_cnq_PSS1InformationElement);
  if (out_tvb && (tvb_reported_length(out_tvb) > 0) && q931_ie_handle)
    call_dissector(q931_ie_handle, out_tvb, actx->pinfo, data_tree);

  return offset;
}



int
dissect_qsig_PSS1InformationElement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, true, dissect_qsig_PSS1InformationElement_U);

  return offset;
}



static int
dissect_qsig_NumberDigits(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_PublicTypeOfNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_PublicPartyNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_PrivateTypeOfNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_PrivatePartyNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_PartyNumber(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ScreeningIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_qsig_SubaddressInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t qsig_UserSpecifiedSubaddress_sequence[] = {
  { &hf_qsig_subaddressInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_SubaddressInformation },
  { &hf_qsig_oddCountIndicator, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_UserSpecifiedSubaddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_UserSpecifiedSubaddress_sequence, hf_index, ett_qsig_UserSpecifiedSubaddress);

  return offset;
}



static int
dissect_qsig_NSAPSubaddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_PartySubaddress(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_AddressScreened(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_AddressScreened_sequence, hf_index, ett_qsig_AddressScreened);

  return offset;
}



static int
dissect_qsig_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_PresentedAddressScreened(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_Address(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_PresentedAddressUnscreened(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_NumberScreened(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_PresentedNumberScreened(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_PresentedNumberUnscreened(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_PresentedNumberUnscreened_choice, hf_index, ett_qsig_PresentedNumberUnscreened,
                                 NULL);

  return offset;
}



static int
dissect_qsig_PresentationAllowedIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


/* --- Module Name-Operations-asn1-97 --- --- ---                             */



static int
dissect_qsig_na_NameData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_na_CharacterSet(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_na_NameSet(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_na_NamePresentationAllowed(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_na_NamePresentationAllowed_choice, hf_index, ett_qsig_na_NamePresentationAllowed,
                                 NULL);

  return offset;
}



static int
dissect_qsig_na_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_na_NamePresentationRestricted(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_na_NamePresentationRestricted_choice, hf_index, ett_qsig_na_NamePresentationRestricted,
                                 NULL);

  return offset;
}



static int
dissect_qsig_na_NameNotAvailable(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 4, true, dissect_qsig_na_NULL);

  return offset;
}


static const ber_choice_t qsig_na_Name_choice[] = {
  {   0, &hf_qsig_na_namePresentationAllowed, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_na_NamePresentationAllowed },
  {   1, &hf_qsig_na_namePresentationRestricted, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_na_NamePresentationRestricted },
  {   2, &hf_qsig_na_nameNotAvailable, BER_CLASS_CON, 4, BER_FLAGS_NOOWNTAG, dissect_qsig_na_NameNotAvailable },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_qsig_na_Name(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_na_Name_choice, hf_index, ett_qsig_na_Name,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_na_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_na_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_na_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_na_NameExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_na_T_nameSequence(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_na_NameArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_na_NameArg_choice, hf_index, ett_qsig_na_NameArg,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_na_NameArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_na_NameArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_na_qsig_na_NameArg_PDU);
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
dissect_qsig_cf_Procedure(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_BasicService(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_cf_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_cf_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_cf_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_ADExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_ARG_activateDiversionQ(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cf_ARG_activateDiversionQ_sequence, hf_index, ett_qsig_cf_ARG_activateDiversionQ);

  return offset;
}



static int
dissect_qsig_cf_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_RES_activateDiversionQ(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_DDExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_ARG_deactivateDiversionQ(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_RES_deactivateDiversionQ(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_IDExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_ARG_interrogateDiversionQ(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_CHRExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_ARG_checkRestriction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_RES_checkRestriction(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_DiversionReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_qsig_cf_INTEGER_1_15(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_SubscriptionOption(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_CRRExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_ARG_callRerouteing(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_RES_callRerouteing(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_DLI1Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_ARG_divertingLegInformation1(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_DLI2Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_ARG_divertingLegInformation2(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_DLI3Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_ARG_divertingLegInformation3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_ARG_cfnrDivertedLegFailed(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cf_ARG_cfnrDivertedLegFailed_choice, hf_index, ett_qsig_cf_ARG_cfnrDivertedLegFailed,
                                 NULL);

  return offset;
}



static int
dissect_qsig_cf_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_IRExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cf_IntResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cf_IntResult_sequence, hf_index, ett_qsig_cf_IntResult);

  return offset;
}


static const ber_sequence_t qsig_cf_IntResultList_set_of[1] = {
  { &hf_qsig_cf_IntResultList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_cf_IntResult },
};

static int
dissect_qsig_cf_IntResultList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 qsig_cf_IntResultList_set_of, hf_index, ett_qsig_cf_IntResultList);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_cf_ARG_activateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_ARG_activateDiversionQ(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_activateDiversionQ_PDU);
  return offset;
}
static int dissect_qsig_cf_RES_activateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_RES_activateDiversionQ(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_RES_activateDiversionQ_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_deactivateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_ARG_deactivateDiversionQ(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_deactivateDiversionQ_PDU);
  return offset;
}
static int dissect_qsig_cf_RES_deactivateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_RES_deactivateDiversionQ(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_RES_deactivateDiversionQ_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_interrogateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_ARG_interrogateDiversionQ(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_interrogateDiversionQ_PDU);
  return offset;
}
static int dissect_qsig_cf_IntResultList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_IntResultList(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_IntResultList_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_checkRestriction_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_ARG_checkRestriction(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_checkRestriction_PDU);
  return offset;
}
static int dissect_qsig_cf_RES_checkRestriction_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_RES_checkRestriction(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_RES_checkRestriction_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_callRerouteing_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_ARG_callRerouteing(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_callRerouteing_PDU);
  return offset;
}
static int dissect_qsig_cf_RES_callRerouteing_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_RES_callRerouteing(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_RES_callRerouteing_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_divertingLegInformation1_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_ARG_divertingLegInformation1(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_divertingLegInformation1_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_divertingLegInformation2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_ARG_divertingLegInformation2(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_divertingLegInformation2_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_divertingLegInformation3_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_ARG_divertingLegInformation3(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_divertingLegInformation3_PDU);
  return offset;
}
static int dissect_qsig_cf_ARG_cfnrDivertedLegFailed_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cf_ARG_cfnrDivertedLegFailed(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_ARG_cfnrDivertedLegFailed_PDU);
  return offset;
}
static int dissect_qsig_cf_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cf_qsig_cf_Extension_PDU);
  return offset;
}


/* --- Module Path-Replacement-Operations-asn1-97 --- --- ---                 */



static int
dissect_qsig_pr_CallIdentity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t qsig_pr_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_pr_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_pr_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pr_PRPExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pr_PRProposeArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pr_PRSExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pr_PRSetupArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pr_PRRExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pr_PRRetainArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pr_PRRetainArg_sequence, hf_index, ett_qsig_pr_PRRetainArg);

  return offset;
}



static int
dissect_qsig_pr_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pr_DummyResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pr_DummyArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pr_DummyArg_choice, hf_index, ett_qsig_pr_DummyArg,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_pr_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pr_DummyArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pr_qsig_pr_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_pr_PRProposeArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pr_PRProposeArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pr_qsig_pr_PRProposeArg_PDU);
  return offset;
}
static int dissect_qsig_pr_PRSetupArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pr_PRSetupArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pr_qsig_pr_PRSetupArg_PDU);
  return offset;
}
static int dissect_qsig_pr_DummyResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pr_DummyResult(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pr_qsig_pr_DummyResult_PDU);
  return offset;
}
static int dissect_qsig_pr_PRRetainArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pr_PRRetainArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pr_qsig_pr_PRRetainArg_PDU);
  return offset;
}
static int dissect_qsig_pr_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pr_qsig_pr_Extension_PDU);
  return offset;
}


/* --- Module Call-Transfer-Operations-asn1-97 --- --- ---                    */



static int
dissect_qsig_ct_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_ct_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_ct_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_ct_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_DummyArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_DummyRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ct_DummyRes_choice, hf_index, ett_qsig_ct_DummyRes,
                                 NULL);

  return offset;
}



static int
dissect_qsig_ct_CallIdentity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_T_resultExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_CTIdentifyRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_CTIargumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_CTInitiateArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_CTSargumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_CTSetupArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_CTAargumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_CTActiveArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_EndDesignation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_CallStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_CTCargumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_CTCompleteArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_CTUargumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_CTUpdateArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_STargumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ct_SubaddressTransferArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ct_SubaddressTransferArg_sequence, hf_index, ett_qsig_ct_SubaddressTransferArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_ct_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ct_DummyArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_ct_CTIdentifyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ct_CTIdentifyRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_CTIdentifyRes_PDU);
  return offset;
}
static int dissect_qsig_ct_CTInitiateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ct_CTInitiateArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_CTInitiateArg_PDU);
  return offset;
}
static int dissect_qsig_ct_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ct_DummyRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_ct_CTSetupArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ct_CTSetupArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_CTSetupArg_PDU);
  return offset;
}
static int dissect_qsig_ct_CTActiveArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ct_CTActiveArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_CTActiveArg_PDU);
  return offset;
}
static int dissect_qsig_ct_CTCompleteArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ct_CTCompleteArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_CTCompleteArg_PDU);
  return offset;
}
static int dissect_qsig_ct_CTUpdateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ct_CTUpdateArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_CTUpdateArg_PDU);
  return offset;
}
static int dissect_qsig_ct_SubaddressTransferArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ct_SubaddressTransferArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_SubaddressTransferArg_PDU);
  return offset;
}
static int dissect_qsig_ct_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ct_qsig_ct_Extension_PDU);
  return offset;
}


/* --- Module SS-CC-Operations-asn1-97 --- --- ---                            */



static int
dissect_qsig_cc_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_qsig_cc_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_cc_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_cc_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_cc_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cc_CcExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cc_CcRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cc_CcRequestRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cc_T_fullArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cc_CcOptionalArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cc_CcOptionalArg_choice, hf_index, ett_qsig_cc_CcOptionalArg,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_cc_CcRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cc_CcRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cc_qsig_cc_CcRequestArg_PDU);
  return offset;
}
static int dissect_qsig_cc_CcRequestRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cc_CcRequestRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cc_qsig_cc_CcRequestRes_PDU);
  return offset;
}
static int dissect_qsig_cc_CcOptionalArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cc_CcOptionalArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cc_qsig_cc_CcOptionalArg_PDU);
  return offset;
}
static int dissect_qsig_cc_CcExtension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cc_CcExtension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cc_qsig_cc_CcExtension_PDU);
  return offset;
}
static int dissect_qsig_cc_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cc_qsig_cc_Extension_PDU);
  return offset;
}


/* --- Module Call-Offer-Operations-asn1-97 --- --- ---                       */


static int * const qsig_co_ServiceList_bits[] = {
  &hf_qsig_co_ServiceList_callOffer,
  NULL
};

static int
dissect_qsig_co_ServiceList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    qsig_co_ServiceList_bits, 1, hf_index, ett_qsig_co_ServiceList,
                                    NULL);

  return offset;
}


static const ber_sequence_t qsig_co_T_extendedServiceList_sequence[] = {
  { &hf_qsig_co_serviceList , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_co_ServiceList },
  { &hf_qsig_co_extension   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_co_T_extendedServiceList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_co_PathRetainArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_co_T_extendedServiceList_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_co_ServiceAvailableArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_co_ServiceAvailableArg_choice, hf_index, ett_qsig_co_ServiceAvailableArg,
                                 NULL);

  return offset;
}



static int
dissect_qsig_co_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_co_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_co_sequenceOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_co_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_co_DummyArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_co_DummyRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_co_DummyRes_choice, hf_index, ett_qsig_co_DummyRes,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_co_PathRetainArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_co_PathRetainArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_co_qsig_co_PathRetainArg_PDU);
  return offset;
}
static int dissect_qsig_co_ServiceAvailableArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_co_ServiceAvailableArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_co_qsig_co_ServiceAvailableArg_PDU);
  return offset;
}
static int dissect_qsig_co_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_co_DummyArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_co_qsig_co_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_co_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_co_DummyRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_co_qsig_co_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_co_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_co_qsig_co_Extension_PDU);
  return offset;
}


/* --- Module Do-Not-Disturb-Operations-asn1-97 --- --- ---                   */



static int
dissect_qsig_dnd_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_dnd_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_dnd_sequenceOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_dnd_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DummyArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DummyRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DNDAargumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DNDActivateArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DNDProtectionLevel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_T_status_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_dnd_T_status_item_sequence, hf_index, ett_qsig_dnd_T_status_item);

  return offset;
}


static const ber_sequence_t qsig_dnd_T_status_set_of[1] = {
  { &hf_qsig_dnd_status_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_T_status_item },
};

static int
dissect_qsig_dnd_T_status(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_T_resultExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DNDActivateRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DNDDargumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DNDDeactivateArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DNDIargumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DNDInterrogateArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_T_status_item_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_dnd_T_status_item_01_sequence, hf_index, ett_qsig_dnd_T_status_item_01);

  return offset;
}


static const ber_sequence_t qsig_dnd_T_status_01_set_of[1] = {
  { &hf_qsig_dnd_status_item_01, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_T_status_item_01 },
};

static int
dissect_qsig_dnd_T_status_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_T_resultExtension_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DNDInterrogateRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DNDOCapabilityLevel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DNDOargumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_DNDOverrideArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_dnd_DNDOverrideArg_sequence, hf_index, ett_qsig_dnd_DNDOverrideArg);

  return offset;
}


static int * const qsig_dnd_ServiceList_bits[] = {
  &hf_qsig_dnd_ServiceList_spare_bit0,
  &hf_qsig_dnd_ServiceList_dndo_low,
  &hf_qsig_dnd_ServiceList_dndo_medium,
  &hf_qsig_dnd_ServiceList_dndo_high,
  NULL
};

static int
dissect_qsig_dnd_ServiceList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    qsig_dnd_ServiceList_bits, 4, hf_index, ett_qsig_dnd_ServiceList,
                                    NULL);

  return offset;
}


static const ber_sequence_t qsig_dnd_T_extendedServiceList_sequence[] = {
  { &hf_qsig_dnd_serviceList, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_dnd_ServiceList },
  { &hf_qsig_dnd_extension  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_dnd_T_extendedServiceList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_PathRetainArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_T_extendedServiceList_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_dnd_ServiceAvailableArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_dnd_ServiceAvailableArg_choice, hf_index, ett_qsig_dnd_ServiceAvailableArg,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_dnd_DNDActivateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_dnd_DNDActivateArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DNDActivateArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_DNDActivateRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_dnd_DNDActivateRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DNDActivateRes_PDU);
  return offset;
}
static int dissect_qsig_dnd_DNDDeactivateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_dnd_DNDDeactivateArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DNDDeactivateArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_dnd_DummyRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_dnd_DNDInterrogateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_dnd_DNDInterrogateArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DNDInterrogateArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_DNDInterrogateRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_dnd_DNDInterrogateRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DNDInterrogateRes_PDU);
  return offset;
}
static int dissect_qsig_dnd_DNDOverrideArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_dnd_DNDOverrideArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DNDOverrideArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_PathRetainArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_dnd_PathRetainArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_PathRetainArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_ServiceAvailableArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_dnd_ServiceAvailableArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_ServiceAvailableArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_dnd_DummyArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_dnd_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_dnd_qsig_dnd_Extension_PDU);
  return offset;
}


/* --- Module Call-Intrusion-Operations-asn1-97 --- --- ---                   */


static int * const qsig_ci_ServiceList_bits[] = {
  &hf_qsig_ci_ServiceList_spare_bit0,
  &hf_qsig_ci_ServiceList_spare_bit1,
  &hf_qsig_ci_ServiceList_spare_bit2,
  &hf_qsig_ci_ServiceList_spare_bit3,
  &hf_qsig_ci_ServiceList_ci_low,
  &hf_qsig_ci_ServiceList_ci_medium,
  &hf_qsig_ci_ServiceList_ci_high,
  NULL
};

static int
dissect_qsig_ci_ServiceList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    qsig_ci_ServiceList_bits, 7, hf_index, ett_qsig_ci_ServiceList,
                                    NULL);

  return offset;
}


static const ber_sequence_t qsig_ci_T_extendedServiceList_sequence[] = {
  { &hf_qsig_ci_serviceList , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_ci_ServiceList },
  { &hf_qsig_ci_extension   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ci_T_extendedServiceList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_PathRetainArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_T_extendedServiceList_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_ServiceAvailableArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ci_ServiceAvailableArg_choice, hf_index, ett_qsig_ci_ServiceAvailableArg,
                                 NULL);

  return offset;
}



static int
dissect_qsig_ci_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_ci_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_ci_sequenceOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_ci_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_DummyArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_DummyRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_CICapabilityLevel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_T_argumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_CIRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_CIUnwantedUserStatus(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_T_resultExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_CIRequestRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_CIProtectionLevel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_T_resultExtension_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ci_CIGetCIPLRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ci_CIGetCIPLRes_sequence, hf_index, ett_qsig_ci_CIGetCIPLRes);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_ci_PathRetainArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ci_PathRetainArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_PathRetainArg_PDU);
  return offset;
}
static int dissect_qsig_ci_ServiceAvailableArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ci_ServiceAvailableArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_ServiceAvailableArg_PDU);
  return offset;
}
static int dissect_qsig_ci_CIRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ci_CIRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_CIRequestArg_PDU);
  return offset;
}
static int dissect_qsig_ci_CIRequestRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ci_CIRequestRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_CIRequestRes_PDU);
  return offset;
}
static int dissect_qsig_ci_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ci_DummyArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_ci_CIGetCIPLRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ci_CIGetCIPLRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_CIGetCIPLRes_PDU);
  return offset;
}
static int dissect_qsig_ci_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ci_DummyRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_ci_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ci_qsig_ci_Extension_PDU);
  return offset;
}


/* --- Module SS-AOC-Operations-asn1-97 --- --- ---                           */



static int
dissect_qsig_aoc_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_ChargedItem(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_qsig_aoc_Currency(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_qsig_aoc_CurrencyAmount(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_Multiplier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_Amount(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_ChargingType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_qsig_aoc_LengthOfTimeUnit(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_Scale(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_Time(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_DurationCurrency(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_FlatRateCurrency(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_VolumeUnit(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_VolumeRateCurrency(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_VolumeRateCurrency_sequence, hf_index, ett_qsig_aoc_VolumeRateCurrency);

  return offset;
}



static int
dissect_qsig_aoc_SpecialChargingCode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_rateType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_AOCSCurrencyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_AOCSCurrencyInfo_sequence, hf_index, ett_qsig_aoc_AOCSCurrencyInfo);

  return offset;
}


static const ber_sequence_t qsig_aoc_AOCSCurrencyInfoList_sequence_of[1] = {
  { &hf_qsig_aoc_AOCSCurrencyInfoList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_AOCSCurrencyInfo },
};

static int
dissect_qsig_aoc_AOCSCurrencyInfoList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_aocRate(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_aocRate_choice, hf_index, ett_qsig_aoc_T_aocRate,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_aoc_multipleExtension_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_aoc_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_rateArgExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_AocRateArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_RecordedCurrency(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_InterimBillingId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_specificCurrency(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_interimCharge(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_interimArgExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_AocInterimArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_FinalBillingId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_specificCurrency_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_finalCharge(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_aoc_T_finalCharge_choice, hf_index, ett_qsig_aoc_T_finalCharge,
                                 NULL);

  return offset;
}



static int
dissect_qsig_aoc_ChargeIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_ChargingAssociation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_finalArgExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_AocFinalArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_AdviceModeCombination(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_aoc_SEQUENCE_SIZE_0_7_OF_AdviceModeCombination_sequence_of[1] = {
  { &hf_qsig_aoc_adviceModeCombinations_item, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_aoc_AdviceModeCombination },
};

static int
dissect_qsig_aoc_SEQUENCE_SIZE_0_7_OF_AdviceModeCombination(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_chargeReqArgExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_ChargeRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_chargeReqResExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_ChargeRequestRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_DummyArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_completeArgExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_AocCompleteArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_ChargingOption(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_completeResExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_AocCompleteRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_DiversionType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_T_aocDivChargeReqArgExt(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_aoc_AocDivChargeReqArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_aoc_AocDivChargeReqArg_sequence, hf_index, ett_qsig_aoc_AocDivChargeReqArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_aoc_AocRateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_aoc_AocRateArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_AocRateArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_AocInterimArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_aoc_AocInterimArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_AocInterimArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_AocFinalArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_aoc_AocFinalArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_AocFinalArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_ChargeRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_aoc_ChargeRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_ChargeRequestArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_ChargeRequestRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_aoc_ChargeRequestRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_ChargeRequestRes_PDU);
  return offset;
}
static int dissect_qsig_aoc_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_aoc_DummyArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_AocCompleteArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_aoc_AocCompleteArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_AocCompleteArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_AocCompleteRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_aoc_AocCompleteRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_AocCompleteRes_PDU);
  return offset;
}
static int dissect_qsig_aoc_AocDivChargeReqArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_aoc_AocDivChargeReqArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_AocDivChargeReqArg_PDU);
  return offset;
}
static int dissect_qsig_aoc_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_aoc_qsig_aoc_Extension_PDU);
  return offset;
}


/* --- Module Recall-Operations-asn1-97 --- --- ---                           */


static const ber_sequence_t qsig_re_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_re_multipleExtension_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_re_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_re_T_argumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_re_ReAlertingArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_re_T_argumentExtension_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_re_ReAnswerArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_re_ReAnswerArg_sequence, hf_index, ett_qsig_re_ReAnswerArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_re_ReAlertingArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_re_ReAlertingArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_re_qsig_re_ReAlertingArg_PDU);
  return offset;
}
static int dissect_qsig_re_ReAnswerArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_re_ReAnswerArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_re_qsig_re_ReAnswerArg_PDU);
  return offset;
}


/* --- Module Synchronization-Operations-asn1-97 --- --- ---                  */


static const value_string qsig_sync_Action_vals[] = {
  {   0, "enslavement" },
  {   1, "holdon" },
  { 0, NULL }
};


static int
dissect_qsig_sync_Action(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t qsig_sync_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_sync_sequOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_sync_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sync_ArgExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sync_SynchronizationReqArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sync_SynchronizationReqArg_sequence, hf_index, ett_qsig_sync_SynchronizationReqArg);

  return offset;
}



static int
dissect_qsig_sync_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sync_SynchronizationReqRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sync_T_stateinfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sync_SynchronizationInfoArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sync_SynchronizationInfoArg_sequence, hf_index, ett_qsig_sync_SynchronizationInfoArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_sync_SynchronizationReqArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sync_SynchronizationReqArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sync_qsig_sync_SynchronizationReqArg_PDU);
  return offset;
}
static int dissect_qsig_sync_SynchronizationReqRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sync_SynchronizationReqRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sync_qsig_sync_SynchronizationReqRes_PDU);
  return offset;
}
static int dissect_qsig_sync_SynchronizationInfoArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sync_SynchronizationInfoArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sync_qsig_sync_SynchronizationInfoArg_PDU);
  return offset;
}
static int dissect_qsig_sync_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sync_qsig_sync_Extension_PDU);
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
dissect_qsig_cint_CintCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_cint_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_cint_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_cint_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_cint_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cint_CintExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cint_CintInformation1Arg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cint_CintInformation2Arg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cint_Condition(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cint_CintCondArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cint_CintCondArg_sequence, hf_index, ett_qsig_cint_CintCondArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_cint_CintInformation1Arg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cint_CintInformation1Arg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cint_qsig_cint_CintInformation1Arg_PDU);
  return offset;
}
static int dissect_qsig_cint_CintInformation2Arg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cint_CintInformation2Arg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cint_qsig_cint_CintInformation2Arg_PDU);
  return offset;
}
static int dissect_qsig_cint_CintCondArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cint_CintCondArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cint_qsig_cint_CintCondArg_PDU);
  return offset;
}
static int dissect_qsig_cint_CintExtension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cint_CintExtension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cint_qsig_cint_CintExtension_PDU);
  return offset;
}


/* --- Module Common-Information-Operations-asn1-97 --- --- ---               */


static int * const qsig_cmn_FeatureIdList_bits[] = {
  &hf_qsig_cmn_FeatureIdList_reserved,
  &hf_qsig_cmn_FeatureIdList_ssCFreRoutingSupported,
  &hf_qsig_cmn_FeatureIdList_ssCTreRoutingSupported,
  &hf_qsig_cmn_FeatureIdList_ssCCBSpossible,
  &hf_qsig_cmn_FeatureIdList_ssCCNRpossible,
  &hf_qsig_cmn_FeatureIdList_ssCOsupported,
  &hf_qsig_cmn_FeatureIdList_ssCIforcedRelease,
  &hf_qsig_cmn_FeatureIdList_ssCIisolation,
  &hf_qsig_cmn_FeatureIdList_ssCIwaitOnBusy,
  &hf_qsig_cmn_FeatureIdList_ssAOCsupportChargeRateProvAtGatewPinx,
  &hf_qsig_cmn_FeatureIdList_ssAOCsupportInterimChargeProvAtGatewPinx,
  &hf_qsig_cmn_FeatureIdList_ssAOCsupportFinalChargeProvAtGatewPinx,
  &hf_qsig_cmn_FeatureIdList_anfPRsupportedAtCooperatingPinx,
  &hf_qsig_cmn_FeatureIdList_anfCINTcanInterceptImmediate,
  &hf_qsig_cmn_FeatureIdList_anfCINTcanInterceptDelayed,
  &hf_qsig_cmn_FeatureIdList_anfWTMIreRoutingSupported,
  &hf_qsig_cmn_FeatureIdList_anfPUMIreRoutingSupported,
  &hf_qsig_cmn_FeatureIdList_ssSSCTreRoutingSupported,
  NULL
};

static int
dissect_qsig_cmn_FeatureIdList(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    qsig_cmn_FeatureIdList_bits, 18, hf_index, ett_qsig_cmn_FeatureIdList,
                                    NULL);

  return offset;
}



static int
dissect_qsig_cmn_INTEGER_0_3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_cmn_IA5String_SIZE_1_10(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cmn_EquipmentId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cmn_PartyCategory(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_cmn_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_cmn_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_cmn_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cmn_T_extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cmn_CmnArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cmn_CmnArg_sequence, hf_index, ett_qsig_cmn_CmnArg);

  return offset;
}



static int
dissect_qsig_cmn_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cmn_DummyArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cmn_DummyArg_choice, hf_index, ett_qsig_cmn_DummyArg,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_cmn_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cmn_DummyArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cmn_qsig_cmn_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_cmn_CmnArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cmn_CmnArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cmn_qsig_cmn_CmnArg_PDU);
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
dissect_qsig_cpi_CPICapabilityLevel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t qsig_cpi_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_cpi_sequenceOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_cpi_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cpi_T_argumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cpi_CPIRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cpi_CPIProtectionLevel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cpi_T_argumentExtension_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cpi_CPIPRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cpi_CPIPRequestArg_sequence, hf_index, ett_qsig_cpi_CPIPRequestArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_cpi_CPIRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cpi_CPIRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cpi_qsig_cpi_CPIRequestArg_PDU);
  return offset;
}
static int dissect_qsig_cpi_CPIPRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cpi_CPIPRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cpi_qsig_cpi_CPIPRequestArg_PDU);
  return offset;
}


/* --- Module PUM-Registration-Operations-asn1-97 --- --- ---                 */



static int
dissect_qsig_pumr_AlternativeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_RpumUserId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_ServiceOption(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_qsig_pumr_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_SessionParams(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumr_SessionParams_sequence, hf_index, ett_qsig_pumr_SessionParams);

  return offset;
}



static int
dissect_qsig_pumr_UserPin(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_T_userPin(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumr_T_userPin_choice, hf_index, ett_qsig_pumr_T_userPin,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_pumr_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_pumr_sequOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_pumr_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_PumrExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_PumRegistrArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_PumRegistrRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumr_PumRegistrRes_sequence, hf_index, ett_qsig_pumr_PumRegistrRes);

  return offset;
}



static int
dissect_qsig_pumr_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_DummyRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_XpumUserId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_PumDelRegArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_DpumUserId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_T_userPin_01(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_PumDe_regArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_IpumUserId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumr_IpumUserId_choice, hf_index, ett_qsig_pumr_IpumUserId,
                                 NULL);

  return offset;
}



static int
dissect_qsig_pumr_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_T_userPin_02(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_PumInterrogArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumr_PumInterrogRes_item(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumr_PumInterrogRes_item_sequence, hf_index, ett_qsig_pumr_PumInterrogRes_item);

  return offset;
}


static const ber_sequence_t qsig_pumr_PumInterrogRes_set_of[1] = {
  { &hf_qsig_pumr_PumInterrogRes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_pumr_PumInterrogRes_item },
};

static int
dissect_qsig_pumr_PumInterrogRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 qsig_pumr_PumInterrogRes_set_of, hf_index, ett_qsig_pumr_PumInterrogRes);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_pumr_PumRegistrArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pumr_PumRegistrArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_PumRegistrArg_PDU);
  return offset;
}
static int dissect_qsig_pumr_PumRegistrRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pumr_PumRegistrRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_PumRegistrRes_PDU);
  return offset;
}
static int dissect_qsig_pumr_PumDelRegArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pumr_PumDelRegArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_PumDelRegArg_PDU);
  return offset;
}
static int dissect_qsig_pumr_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pumr_DummyRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_pumr_PumDe_regArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pumr_PumDe_regArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_PumDe_regArg_PDU);
  return offset;
}
static int dissect_qsig_pumr_PumInterrogArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pumr_PumInterrogArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_PumInterrogArg_PDU);
  return offset;
}
static int dissect_qsig_pumr_PumInterrogRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pumr_PumInterrogRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_PumInterrogRes_PDU);
  return offset;
}
static int dissect_qsig_pumr_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumr_qsig_pumr_Extension_PDU);
  return offset;
}


/* --- Module Private-User-Mobility-Call-Handling-Operations-asn1-97 --- --- --- */


static const ber_sequence_t qsig_pumch_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_pumch_sequOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_pumch_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumch_PumiExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumch_EnquiryArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumch_EnquiryArg_sequence, hf_index, ett_qsig_pumch_EnquiryArg);

  return offset;
}



static int
dissect_qsig_pumch_AlternativeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumch_T_both(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumch_PumIdentity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumch_DivertArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumch_InformArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumch_CurrLocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumch_SubscriptionOption(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumch_CfuActivated(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumch_EnquiryRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_pumch_EnquiryRes_choice, hf_index, ett_qsig_pumch_EnquiryRes,
                                 NULL);

  return offset;
}



static int
dissect_qsig_pumch_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumch_DummyRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumch_T_pumoaextension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_pumch_PumoArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_pumch_PumoArg_sequence, hf_index, ett_qsig_pumch_PumoArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_pumch_EnquiryArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pumch_EnquiryArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_EnquiryArg_PDU);
  return offset;
}
static int dissect_qsig_pumch_EnquiryRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pumch_EnquiryRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_EnquiryRes_PDU);
  return offset;
}
static int dissect_qsig_pumch_DivertArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pumch_DivertArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_DivertArg_PDU);
  return offset;
}
static int dissect_qsig_pumch_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pumch_DummyRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_pumch_InformArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pumch_InformArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_InformArg_PDU);
  return offset;
}
static int dissect_qsig_pumch_PumoArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_pumch_PumoArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_PumoArg_PDU);
  return offset;
}
static int dissect_qsig_pumch_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_pumch_qsig_pumch_Extension_PDU);
  return offset;
}


/* --- Module Single-Step-Call-Transfer-Operations-asn1-97 --- --- ---        */



static int
dissect_qsig_ssct_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_ssct_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_ssct_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_ssct_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ssct_DummyArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ssct_DummyRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_ssct_DummyRes_choice, hf_index, ett_qsig_ssct_DummyRes,
                                 NULL);

  return offset;
}



static int
dissect_qsig_ssct_AwaitConnect(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ssct_SSCTIargumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ssct_SSCTInitiateArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ssct_SSCTSargumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ssct_SSCTSetupArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ssct_SSCTDargumentExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_ssct_SSCTDigitInfoArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_ssct_SSCTDigitInfoArg_sequence, hf_index, ett_qsig_ssct_SSCTDigitInfoArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_ssct_SSCTInitiateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ssct_SSCTInitiateArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ssct_qsig_ssct_SSCTInitiateArg_PDU);
  return offset;
}
static int dissect_qsig_ssct_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ssct_DummyRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ssct_qsig_ssct_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_ssct_SSCTSetupArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ssct_SSCTSetupArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ssct_qsig_ssct_SSCTSetupArg_PDU);
  return offset;
}
static int dissect_qsig_ssct_DummyArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ssct_DummyArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ssct_qsig_ssct_DummyArg_PDU);
  return offset;
}
static int dissect_qsig_ssct_SSCTDigitInfoArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_ssct_SSCTDigitInfoArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ssct_qsig_ssct_SSCTDigitInfoArg_PDU);
  return offset;
}
static int dissect_qsig_ssct_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_ssct_qsig_ssct_Extension_PDU);
  return offset;
}


/* --- Module WTM-Location-Registration-Operations-asn1-97 --- --- ---        */



static int
dissect_qsig_wtmlr_AlternativeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmlr_WtmUserId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmlr_WtmUserId_choice, hf_index, ett_qsig_wtmlr_WtmUserId,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_wtmlr_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_wtmlr_sequOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_wtmlr_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmlr_LrExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmlr_LocUpdArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmlr_LocUpdArg_sequence, hf_index, ett_qsig_wtmlr_LocUpdArg);

  return offset;
}



static int
dissect_qsig_wtmlr_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmlr_DummyRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmlr_LocDelArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmlr_LocDeRegArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmlr_PisnEnqArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmlr_PisnEnqRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmlr_GetRRCInfArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmlr_GetRRCInfArg_sequence, hf_index, ett_qsig_wtmlr_GetRRCInfArg);

  return offset;
}



static int
dissect_qsig_wtmlr_RRClass(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmlr_GetRRCInfRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmlr_LocInfoCheckArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmlr_CheckResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmlr_LocInfoCheckRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmlr_LocInfoCheckRes_sequence, hf_index, ett_qsig_wtmlr_LocInfoCheckRes);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_wtmlr_LocUpdArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmlr_LocUpdArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_LocUpdArg_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmlr_DummyRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_LocDelArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmlr_LocDelArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_LocDelArg_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_LocDeRegArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmlr_LocDeRegArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_LocDeRegArg_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_PisnEnqArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmlr_PisnEnqArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_PisnEnqArg_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_PisnEnqRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmlr_PisnEnqRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_PisnEnqRes_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_GetRRCInfArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmlr_GetRRCInfArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_GetRRCInfArg_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_GetRRCInfRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmlr_GetRRCInfRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_GetRRCInfRes_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_LocInfoCheckArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmlr_LocInfoCheckArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_LocInfoCheckArg_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_LocInfoCheckRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmlr_LocInfoCheckRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_LocInfoCheckRes_PDU);
  return offset;
}
static int dissect_qsig_wtmlr_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmlr_qsig_wtmlr_Extension_PDU);
  return offset;
}


/* --- Module Wireless-Terminal-Call-Handling-Operations-asn1-97 --- --- ---  */


static const ber_sequence_t qsig_wtmch_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_wtmch_sequOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_wtmch_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmch_WtmiExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmch_EnquiryArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmch_EnquiryArg_sequence, hf_index, ett_qsig_wtmch_EnquiryArg);

  return offset;
}



static int
dissect_qsig_wtmch_AlternativeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmch_T_both(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmch_WtmIdentity(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmch_DivertArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmch_InformArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmch_CurrLocation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmch_SubscriptionOption(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmch_CfuActivated(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmch_EnquiryRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmch_EnquiryRes_choice, hf_index, ett_qsig_wtmch_EnquiryRes,
                                 NULL);

  return offset;
}



static int
dissect_qsig_wtmch_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmch_DummyRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmch_T_wtmoaextension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmch_WtmoArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmch_WtmoArg_sequence, hf_index, ett_qsig_wtmch_WtmoArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_wtmch_EnquiryArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmch_EnquiryArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_EnquiryArg_PDU);
  return offset;
}
static int dissect_qsig_wtmch_EnquiryRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmch_EnquiryRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_EnquiryRes_PDU);
  return offset;
}
static int dissect_qsig_wtmch_DivertArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmch_DivertArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_DivertArg_PDU);
  return offset;
}
static int dissect_qsig_wtmch_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmch_DummyRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_wtmch_InformArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmch_InformArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_InformArg_PDU);
  return offset;
}
static int dissect_qsig_wtmch_WtmoArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmch_WtmoArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_WtmoArg_PDU);
  return offset;
}
static int dissect_qsig_wtmch_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmch_qsig_wtmch_Extension_PDU);
  return offset;
}


/* --- Module WTM-Authentication-Operations-asn1-97 --- --- ---               */



static int
dissect_qsig_wtmau_AlternativeId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_WtmUserId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_wtmau_WtmUserId_choice, hf_index, ett_qsig_wtmau_WtmUserId,
                                 NULL);

  return offset;
}



static int
dissect_qsig_wtmau_AuthChallenge(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_wtmau_AuthResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_wtmau_DerivedCipherKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_wtmau_CalculationParam(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_CalcWtatInfoUnit(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_CalcWtatInfoUnit_sequence, hf_index, ett_qsig_wtmau_CalcWtatInfoUnit);

  return offset;
}


static const ber_sequence_t qsig_wtmau_CalcWtatInfo_sequence_of[1] = {
  { &hf_qsig_wtmau_CalcWtatInfo_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_CalcWtatInfoUnit },
};

static int
dissect_qsig_wtmau_CalcWtatInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_wtmau_CalcWtatInfo_sequence_of, hf_index, ett_qsig_wtmau_CalcWtatInfo);

  return offset;
}


static const ber_sequence_t qsig_wtmau_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_wtmau_sequOfExtn_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_wtmau_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_DummyExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_AuthWtmArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_T_autWtmResValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_AuthWtmRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_AuthWtmRes_sequence, hf_index, ett_qsig_wtmau_AuthWtmRes);

  return offset;
}



static int
dissect_qsig_wtmau_CanCompute(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_WtatParamArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_DefinedIDs(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_wtmau_T_param(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {


  return offset;
}


static const ber_sequence_t qsig_wtmau_AuthAlgorithm_sequence[] = {
  { &hf_qsig_wtmau_authAlg  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_DefinedIDs },
  { &hf_qsig_wtmau_param    , BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_wtmau_T_param },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_wtmau_AuthAlgorithm(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_AuthAlgorithm_sequence, hf_index, ett_qsig_wtmau_AuthAlgorithm);

  return offset;
}



static int
dissect_qsig_wtmau_AuthSessionKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_AuthSessionKeyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_AuthSessionKeyInfo_sequence, hf_index, ett_qsig_wtmau_AuthSessionKeyInfo);

  return offset;
}



static int
dissect_qsig_wtmau_AuthKey(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_wtmau_INTEGER_1_8(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_T_wtatParamInfoChoice(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_WtatParamInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_WtatParamRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_WtanParamArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_CalcWtanInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_WtanParamInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_WtanParamRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_wtmau_ARG_transferAuthParam(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_wtmau_ARG_transferAuthParam_sequence, hf_index, ett_qsig_wtmau_ARG_transferAuthParam);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_wtmau_AuthWtmArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmau_AuthWtmArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_AuthWtmArg_PDU);
  return offset;
}
static int dissect_qsig_wtmau_AuthWtmRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmau_AuthWtmRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_AuthWtmRes_PDU);
  return offset;
}
static int dissect_qsig_wtmau_WtatParamArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmau_WtatParamArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_WtatParamArg_PDU);
  return offset;
}
static int dissect_qsig_wtmau_WtatParamRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmau_WtatParamRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_WtatParamRes_PDU);
  return offset;
}
static int dissect_qsig_wtmau_WtanParamArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmau_WtanParamArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_WtanParamArg_PDU);
  return offset;
}
static int dissect_qsig_wtmau_WtanParamRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmau_WtanParamRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_WtanParamRes_PDU);
  return offset;
}
static int dissect_qsig_wtmau_ARG_transferAuthParam_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_wtmau_ARG_transferAuthParam(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_ARG_transferAuthParam_PDU);
  return offset;
}
static int dissect_qsig_wtmau_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_wtmau_qsig_wtmau_Extension_PDU);
  return offset;
}


/* --- Module SS-SD-Operations-asn1-97 --- --- ---                            */



static int
dissect_qsig_sd_BMPStringNormal(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_sd_BMPStringExtended(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sd_DisplayString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_sd_DisplayString_choice, hf_index, ett_qsig_sd_DisplayString,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_sd_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_sd_multipleExtension_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_sd_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sd_SDExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sd_DisplayArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sd_KeypadArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sd_KeypadArg_sequence, hf_index, ett_qsig_sd_KeypadArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_sd_DisplayArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sd_DisplayArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sd_qsig_sd_DisplayArg_PDU);
  return offset;
}
static int dissect_qsig_sd_KeypadArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sd_KeypadArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sd_qsig_sd_KeypadArg_PDU);
  return offset;
}
static int dissect_qsig_sd_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sd_qsig_sd_Extension_PDU);
  return offset;
}


/* --- Module Call-Identification-and-Call-Linkage-Operations-asn1-97 --- --- --- */



static int
dissect_qsig_cidl_SwitchingSubDomainName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_qsig_cidl_SubDomainID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_cidl_GloballyUniqueID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cidl_T_linkageID(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_cidl_T_linkageID_choice, hf_index, ett_qsig_cidl_T_linkageID,
                                 NULL);

  return offset;
}



static int
dissect_qsig_cidl_TimeStamp(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cidl_CallIdentificationData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cidl_CallIdentificationData_sequence, hf_index, ett_qsig_cidl_CallIdentificationData);

  return offset;
}


static const ber_sequence_t qsig_cidl_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_cidl_sequenceOfExt_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_cidl_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cidl_ExtensionType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cidl_CallIdentificationAssignArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_cidl_CallIdentificationUpdateArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_cidl_CallIdentificationUpdateArg_sequence, hf_index, ett_qsig_cidl_CallIdentificationUpdateArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_cidl_CallIdentificationAssignArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cidl_CallIdentificationAssignArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cidl_qsig_cidl_CallIdentificationAssignArg_PDU);
  return offset;
}
static int dissect_qsig_cidl_CallIdentificationUpdateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_cidl_CallIdentificationUpdateArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_cidl_qsig_cidl_CallIdentificationUpdateArg_PDU);
  return offset;
}


/* --- Module Short-Message-Service-Operations-asn1-97 --- --- ---            */



static int
dissect_qsig_sms_MessageReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_ProtocolIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_ValidityPeriodRel(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_ValidityPeriodAbs(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_qsig_sms_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_qsig_sms_INTEGER_0_255(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_ValidityPeriodSemi(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_EnhancedVP(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_ValidityPeriodEnh(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_ValidityPeriod(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_SmSubmitParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmSubmitParameter_sequence, hf_index, ett_qsig_sms_SmSubmitParameter);

  return offset;
}


static int * const qsig_sms_SmscControlParameterHeader_bits[] = {
  &hf_qsig_sms_SmscControlParameterHeader_sRforTransactionCompleted,
  &hf_qsig_sms_SmscControlParameterHeader_sRforPermanentError,
  &hf_qsig_sms_SmscControlParameterHeader_sRforTempErrorSCnotTrying,
  &hf_qsig_sms_SmscControlParameterHeader_sRforTempErrorSCstillTrying,
  &hf_qsig_sms_SmscControlParameterHeader_spare_bit4,
  &hf_qsig_sms_SmscControlParameterHeader_spare_bit5,
  &hf_qsig_sms_SmscControlParameterHeader_cancelSRRforConcatenatedSM,
  &hf_qsig_sms_SmscControlParameterHeader_includeOrigUDHintoSR,
  NULL
};

static int
dissect_qsig_sms_SmscControlParameterHeader(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    qsig_sms_SmscControlParameterHeader_bits, 8, hf_index, ett_qsig_sms_SmscControlParameterHeader,
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
dissect_qsig_sms_Concatenated8BitSMHeader(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_Concatenated8BitSMHeader_sequence, hf_index, ett_qsig_sms_Concatenated8BitSMHeader);

  return offset;
}



static int
dissect_qsig_sms_INTEGER_0_65536(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_Concatenated16BitSMHeader(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_ApplicationPort8BitHeader(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_ApplicationPort16BitHeader(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_DataHeaderSourceIndicator(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_WirelessControlHeader(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_sms_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_GenericUserValue(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_UserDataHeaderChoice(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_sms_UserDataHeaderChoice_choice, hf_index, ett_qsig_sms_UserDataHeaderChoice,
                                 NULL);

  return offset;
}


static const ber_sequence_t qsig_sms_UserDataHeader_sequence_of[1] = {
  { &hf_qsig_sms_UserDataHeader_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_sms_UserDataHeaderChoice },
};

static int
dissect_qsig_sms_UserDataHeader(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_sms_UserDataHeader_sequence_of, hf_index, ett_qsig_sms_UserDataHeader);

  return offset;
}



static int
dissect_qsig_sms_INTEGER_0_3(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_ShortMessageTextType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_ShortMessageTextData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_ShortMessageText(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_UserData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_UserData_sequence, hf_index, ett_qsig_sms_UserData);

  return offset;
}


static const ber_sequence_t qsig_sms_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_sms_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_sms_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_SmsExtension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_SmsSubmitArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmsSubmitArg_sequence, hf_index, ett_qsig_sms_SmsSubmitArg);

  return offset;
}



static int
dissect_qsig_sms_ServiceCentreTimeStamp(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_SmsSubmitRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_SmDeliverParameter(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_SmsDeliverArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmsDeliverArg_sequence, hf_index, ett_qsig_sms_SmsDeliverArg);

  return offset;
}



static int
dissect_qsig_sms_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_sms_ResChoiceSeq_sequence[] = {
  { &hf_qsig_sms_protocolIdentifier, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_ProtocolIdentifier },
  { &hf_qsig_sms_userData   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_sms_UserData },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_sms_ResChoiceSeq(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_SmsDeliverResChoice(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_SmsDeliverRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_SmsDeliverRes_sequence, hf_index, ett_qsig_sms_SmsDeliverRes);

  return offset;
}



static int
dissect_qsig_sms_DischargeTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_qsig_sms_Status(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_SmsStatusReportArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_SmsStatusReportResponseChoice(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_SmsStatusReportRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_CommandType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_sms_CommandData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_SmsCommandArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_SmsCommandRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_ScAlertArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_DummyRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_sms_DummyRes_choice, hf_index, ett_qsig_sms_DummyRes,
                                 NULL);

  return offset;
}



static int
dissect_qsig_sms_FailureCause(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_PAR_smsDeliverError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_PAR_smsSubmitError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_PAR_smsStatusReportError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_sms_PAR_smsCommandError(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_sms_PAR_smsCommandError_sequence, hf_index, ett_qsig_sms_PAR_smsCommandError);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_sms_SmsSubmitArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_SmsSubmitArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsSubmitArg_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsSubmitRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_SmsSubmitRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsSubmitRes_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsDeliverArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_SmsDeliverArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsDeliverArg_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsDeliverRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_SmsDeliverRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsDeliverRes_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsStatusReportArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_SmsStatusReportArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsStatusReportArg_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsStatusReportRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_SmsStatusReportRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsStatusReportRes_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsCommandArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_SmsCommandArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsCommandArg_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsCommandRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_SmsCommandRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsCommandRes_PDU);
  return offset;
}
static int dissect_qsig_sms_ScAlertArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_ScAlertArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_ScAlertArg_PDU);
  return offset;
}
static int dissect_qsig_sms_DummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_DummyRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_DummyRes_PDU);
  return offset;
}
static int dissect_qsig_sms_PAR_smsDeliverError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_PAR_smsDeliverError(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_PAR_smsDeliverError_PDU);
  return offset;
}
static int dissect_qsig_sms_PAR_smsSubmitError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_PAR_smsSubmitError(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_PAR_smsSubmitError_PDU);
  return offset;
}
static int dissect_qsig_sms_PAR_smsStatusReportError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_PAR_smsStatusReportError(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_PAR_smsStatusReportError_PDU);
  return offset;
}
static int dissect_qsig_sms_PAR_smsCommandError_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_PAR_smsCommandError(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_PAR_smsCommandError_PDU);
  return offset;
}
static int dissect_qsig_sms_SmsExtension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_sms_SmsExtension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_sms_qsig_sms_SmsExtension_PDU);
  return offset;
}


/* --- Module SS-MCR-Operations-asn97 --- --- ---                             */



static int
dissect_qsig_mcr_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcr_CallType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mcr_CallType_choice, hf_index, ett_qsig_mcr_CallType,
                                 NULL);

  return offset;
}



static int
dissect_qsig_mcr_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcr_CorrelationReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcr_Correlation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcr_Correlation_sequence, hf_index, ett_qsig_mcr_Correlation);

  return offset;
}


static const ber_sequence_t qsig_mcr_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_mcr_multiple_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_mcr_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcr_MCRExtensions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcr_MCRequestArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcr_MCRequestArg_sequence, hf_index, ett_qsig_mcr_MCRequestArg);

  return offset;
}


static const ber_sequence_t qsig_mcr_MCRequestResult_sequence[] = {
  { &hf_qsig_mcr_extensions , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_mcr_MCRExtensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_mcr_MCRequestResult(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcr_MCInformArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcr_MCAlertingArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcr_MCAlertingArg_sequence, hf_index, ett_qsig_mcr_MCAlertingArg);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_mcr_MCRequestArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcr_MCRequestArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcr_qsig_mcr_MCRequestArg_PDU);
  return offset;
}
static int dissect_qsig_mcr_MCRequestResult_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcr_MCRequestResult(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcr_qsig_mcr_MCRequestResult_PDU);
  return offset;
}
static int dissect_qsig_mcr_MCInformArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcr_MCInformArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcr_qsig_mcr_MCInformArg_PDU);
  return offset;
}
static int dissect_qsig_mcr_MCAlertingArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcr_MCAlertingArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcr_qsig_mcr_MCAlertingArg_PDU);
  return offset;
}
static int dissect_qsig_mcr_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcr_qsig_mcr_Extension_PDU);
  return offset;
}


/* --- Module SS-MCM-Operations-asn1-97 --- --- ---                           */



static int
dissect_qsig_mcm_INTEGER_0_65535(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_mcm_NumericString_SIZE_1_10(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MsgCentreId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_PartyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MessageType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_qsig_mcm_INTEGER_0_100(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MailboxFullPar(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MailboxFullPar_sequence, hf_index, ett_qsig_mcm_MailboxFullPar);

  return offset;
}


static const ber_sequence_t qsig_mcm_MailboxFullFor_sequence_of[1] = {
  { &hf_qsig_mcm_MailboxFullFor_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MailboxFullPar },
};

static int
dissect_qsig_mcm_MailboxFullFor(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_mcm_MailboxFullFor_sequence_of, hf_index, ett_qsig_mcm_MailboxFullFor);

  return offset;
}



static int
dissect_qsig_mcm_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_mcm_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_mcm_multipleExtension_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_mcm_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMExtensions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMailboxFullArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMMode(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMServiceInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMServiceInfo_sequence, hf_index, ett_qsig_mcm_MCMServiceInfo);

  return offset;
}


static const ber_sequence_t qsig_mcm_SEQUENCE_OF_MCMServiceInfo_sequence_of[1] = {
  { &hf_qsig_mcm_activateMCM_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MCMServiceInfo },
};

static int
dissect_qsig_mcm_SEQUENCE_OF_MCMServiceInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_mcm_SEQUENCE_OF_MCMServiceInfo_sequence_of, hf_index, ett_qsig_mcm_SEQUENCE_OF_MCMServiceInfo);

  return offset;
}


static const ber_sequence_t qsig_mcm_SEQUENCE_OF_MessageType_sequence_of[1] = {
  { &hf_qsig_mcm_deactivateMCM_item, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MessageType },
};

static int
dissect_qsig_mcm_SEQUENCE_OF_MessageType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMChange(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMServiceArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMInterrogateArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMInterrogateRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMInterrogateRes_sequence, hf_index, ett_qsig_mcm_MCMInterrogateRes);

  return offset;
}



static int
dissect_qsig_mcm_NrOfMessages(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_qsig_mcm_TimeStamp(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_qsig_mcm_INTEGER_0_9(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMNewArgumentExt(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMNewMsgArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMNoNewArgumentExt(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMNoNewMsgArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMNoNewMsgArg_sequence, hf_index, ett_qsig_mcm_MCMNoNewMsgArg);

  return offset;
}



static int
dissect_qsig_mcm_Priority(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_AddressHeader(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_AddressHeader_sequence, hf_index, ett_qsig_mcm_AddressHeader);

  return offset;
}


static const ber_sequence_t qsig_mcm_CompleteInfo_sequence_of[1] = {
  { &hf_qsig_mcm_CompleteInfo_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_AddressHeader },
};

static int
dissect_qsig_mcm_CompleteInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_CompressedInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MessageInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_AllMsgInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_UpdateInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mcm_UpdateInfo_choice, hf_index, ett_qsig_mcm_UpdateInfo,
                                 NULL);

  return offset;
}



static int
dissect_qsig_mcm_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMUpdateArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMUpdArgArgumentExt(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMUpdateReqArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMUpdResArgumentExt(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mcm_MCMUpdateReqResElt(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mcm_MCMUpdateReqResElt_sequence, hf_index, ett_qsig_mcm_MCMUpdateReqResElt);

  return offset;
}


static const ber_sequence_t qsig_mcm_MCMUpdateReqRes_sequence_of[1] = {
  { &hf_qsig_mcm_MCMUpdateReqRes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_mcm_MCMUpdateReqResElt },
};

static int
dissect_qsig_mcm_MCMUpdateReqRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      qsig_mcm_MCMUpdateReqRes_sequence_of, hf_index, ett_qsig_mcm_MCMUpdateReqRes);

  return offset;
}



static int
dissect_qsig_mcm_MCMDummyRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_qsig_mcm_MCMExtensions(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_mcm_MCMNewMsgArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcm_MCMNewMsgArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMNewMsgArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMDummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcm_MCMDummyRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMDummyRes_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMNoNewMsgArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcm_MCMNoNewMsgArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMNoNewMsgArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMUpdateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcm_MCMUpdateArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMUpdateArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMUpdateReqArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcm_MCMUpdateReqArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMUpdateReqArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMUpdateReqRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcm_MCMUpdateReqRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMUpdateReqRes_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMServiceArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcm_MCMServiceArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMServiceArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMInterrogateArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcm_MCMInterrogateArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMInterrogateArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMInterrogateRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcm_MCMInterrogateRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMInterrogateRes_PDU);
  return offset;
}
static int dissect_qsig_mcm_MCMailboxFullArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mcm_MCMailboxFullArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_MCMailboxFullArg_PDU);
  return offset;
}
static int dissect_qsig_mcm_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mcm_qsig_mcm_Extension_PDU);
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
dissect_qsig_mid_PartyInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mid_PartyInfo_sequence, hf_index, ett_qsig_mid_PartyInfo);

  return offset;
}



static int
dissect_qsig_mid_BMPString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_BMPString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_qsig_mid_UTF8String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mid_String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 qsig_mid_String_choice, hf_index, ett_qsig_mid_String,
                                 NULL);

  return offset;
}



static int
dissect_qsig_mid_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t qsig_mid_SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_mid_multipleExtension_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_mid_SEQUENCE_OF_Extension(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mid_MIDExtensions(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mid_MIDMailboxAuthArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_qsig_mid_MIDMailboxIDArg(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   qsig_mid_MIDMailboxIDArg_sequence, hf_index, ett_qsig_mid_MIDMailboxIDArg);

  return offset;
}



static int
dissect_qsig_mid_MIDDummyRes(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_qsig_mid_MIDExtensions(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}

/*--- PDUs ---*/

static int dissect_qsig_mid_MIDMailboxAuthArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mid_MIDMailboxAuthArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mid_qsig_mid_MIDMailboxAuthArg_PDU);
  return offset;
}
static int dissect_qsig_mid_MIDDummyRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mid_MIDDummyRes(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mid_qsig_mid_MIDDummyRes_PDU);
  return offset;
}
static int dissect_qsig_mid_MIDMailboxIDArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_mid_MIDMailboxIDArg(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mid_qsig_mid_MIDMailboxIDArg_PDU);
  return offset;
}
static int dissect_qsig_mid_Extension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_qsig_Extension(false, tvb, offset, &asn1_ctx, tree, hf_qsig_mid_qsig_mid_Extension_PDU);
  return offset;
}


typedef struct _qsig_op_t {
  int32_t opcode;
  dissector_t arg_pdu;
  dissector_t res_pdu;
} qsig_op_t;

static const qsig_op_t qsig_op_tab[] = {

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
};

typedef struct _qsig_err_t {
  int32_t errcode;
  dissector_t err_pdu;
} qsig_err_t;

static const qsig_err_t qsig_err_tab[] = {

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
};

static const qsig_op_t *get_op(int32_t opcode) {
  int i;

  /* search from the end to get the last occurrence if the operation is redefined in some newer specification */
  for (i = array_length(qsig_op_tab) - 1; i >= 0; i--)
    if (qsig_op_tab[i].opcode == opcode)
      return &qsig_op_tab[i];
  return NULL;
}

static int32_t get_service(int32_t opcode) {
  if ((opcode < 0) || (opcode >= (int)array_length(op2srv_tab)))
    return NO_SRV;
  return op2srv_tab[opcode];
}

static const qsig_err_t *get_err(int32_t errcode) {
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
  int32_t opcode = 0, service, oid_num;
  const qsig_op_t *op_ptr = NULL;
  const char *p, *oid;
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
    oid = g_strrstr(rctx->d.code_global, ".");
    if (oid != NULL) {
     if (ws_strtou32(oid+1, NULL, &oid_num))
        op_ptr = get_op(oid_num);
    }
    if (op_ptr)
        opcode = op_ptr->opcode;
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
      proto_tree_add_expert(tree, pinfo, &ei_qsig_unsupported_error_type, tvb, offset, -1);
      offset += tvb_captured_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_qsig_res -------------------------------------------------------*/
static int
dissect_qsig_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  int offset = 0;
  rose_ctx_t *rctx;
  int32_t opcode, service;
  const qsig_op_t *op_ptr;
  const char *p;
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
      proto_tree_add_expert(tree, pinfo, &ei_qsig_unsupported_result_type, tvb, offset, -1);
      offset += tvb_captured_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_qsig_err ------------------------------------------------------*/
static int
dissect_qsig_err(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  int offset = 0;
  rose_ctx_t *rctx;
  int32_t errcode;
  const qsig_err_t *err_ptr;
  const char *p;
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
      proto_tree_add_expert(tree, pinfo, &ei_qsig_unsupported_error_type, tvb, offset, -1);
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
  int offset;
  proto_item *ti, *hidden_item;
  proto_tree *ie_tree;
  uint8_t ie_type, ie_len;

  offset = 0;

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, -1, ENC_NA);
  proto_item_set_hidden(ti);

  ie_type = tvb_get_uint8(tvb, offset);
  ie_len = tvb_get_uint8(tvb, offset + 1);

  ie_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_qsig_ie, NULL,
            val_to_str(ie_type, VALS(qsig_str_ie_type[codeset]), "unknown (0x%02X)"));

  proto_tree_add_item(ie_tree, *hf_qsig_ie_type_arr[codeset], tvb, offset, 1, ENC_BIG_ENDIAN);
  hidden_item = proto_tree_add_item(ie_tree, hf_qsig_ie_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_item_set_hidden(hidden_item);
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
static int
dissect_qsig_ie_cs4(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
  dissect_qsig_ie(tvb, pinfo, tree, 4);
  return tvb_captured_length(tvb);
}
/*--- dissect_qsig_ie_cs5 ---------------------------------------------------*/
static int
dissect_qsig_ie_cs5(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
  dissect_qsig_ie(tvb, pinfo, tree, 5);
  return tvb_captured_length(tvb);
}

/*--- proto_register_qsig ---------------------------------------------------*/
void proto_register_qsig(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_qsig_operation, { "Operation", "qsig.operation",
                           FT_UINT8, BASE_DEC, VALS(qsig_str_operation), 0x0,
                           NULL, HFILL }},
    { &hf_qsig_service,   { "Service", "qsig.service",
                           FT_UINT16, BASE_DEC, VALS(qsig_str_service), 0x0,
                           "Supplementary Service", HFILL }},
    { &hf_qsig_error,     { "Error", "qsig.error",
                           FT_UINT16, BASE_DEC, VALS(qsig_str_error), 0x0,
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
      { "callOffer", "qsig.co.ServiceList.callOffer",
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
    { &hf_qsig_dnd_ServiceList_spare_bit0,
      { "spare_bit0", "qsig.dnd.ServiceList.spare.bit0",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_qsig_dnd_ServiceList_dndo_low,
      { "dndo-low", "qsig.dnd.ServiceList.dndo.low",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_qsig_dnd_ServiceList_dndo_medium,
      { "dndo-medium", "qsig.dnd.ServiceList.dndo.medium",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_qsig_dnd_ServiceList_dndo_high,
      { "dndo-high", "qsig.dnd.ServiceList.dndo.high",
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
    { &hf_qsig_ci_ServiceList_spare_bit0,
      { "spare_bit0", "qsig.ci.ServiceList.spare.bit0",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_qsig_ci_ServiceList_spare_bit1,
      { "spare_bit1", "qsig.ci.ServiceList.spare.bit1",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_qsig_ci_ServiceList_spare_bit2,
      { "spare_bit2", "qsig.ci.ServiceList.spare.bit2",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_qsig_ci_ServiceList_spare_bit3,
      { "spare_bit3", "qsig.ci.ServiceList.spare.bit3",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_qsig_ci_ServiceList_ci_low,
      { "ci-low", "qsig.ci.ServiceList.ci.low",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_qsig_ci_ServiceList_ci_medium,
      { "ci-medium", "qsig.ci.ServiceList.ci.medium",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_qsig_ci_ServiceList_ci_high,
      { "ci-high", "qsig.ci.ServiceList.ci.high",
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
      { "reserved", "qsig.cmn.FeatureIdList.reserved",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCFreRoutingSupported,
      { "ssCFreRoutingSupported", "qsig.cmn.FeatureIdList.ssCFreRoutingSupported",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCTreRoutingSupported,
      { "ssCTreRoutingSupported", "qsig.cmn.FeatureIdList.ssCTreRoutingSupported",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCCBSpossible,
      { "ssCCBSpossible", "qsig.cmn.FeatureIdList.ssCCBSpossible",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCCNRpossible,
      { "ssCCNRpossible", "qsig.cmn.FeatureIdList.ssCCNRpossible",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCOsupported,
      { "ssCOsupported", "qsig.cmn.FeatureIdList.ssCOsupported",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCIforcedRelease,
      { "ssCIforcedRelease", "qsig.cmn.FeatureIdList.ssCIforcedRelease",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCIisolation,
      { "ssCIisolation", "qsig.cmn.FeatureIdList.ssCIisolation",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssCIwaitOnBusy,
      { "ssCIwaitOnBusy", "qsig.cmn.FeatureIdList.ssCIwaitOnBusy",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssAOCsupportChargeRateProvAtGatewPinx,
      { "ssAOCsupportChargeRateProvAtGatewPinx", "qsig.cmn.FeatureIdList.ssAOCsupportChargeRateProvAtGatewPinx",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssAOCsupportInterimChargeProvAtGatewPinx,
      { "ssAOCsupportInterimChargeProvAtGatewPinx", "qsig.cmn.FeatureIdList.ssAOCsupportInterimChargeProvAtGatewPinx",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssAOCsupportFinalChargeProvAtGatewPinx,
      { "ssAOCsupportFinalChargeProvAtGatewPinx", "qsig.cmn.FeatureIdList.ssAOCsupportFinalChargeProvAtGatewPinx",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_anfPRsupportedAtCooperatingPinx,
      { "anfPRsupportedAtCooperatingPinx", "qsig.cmn.FeatureIdList.anfPRsupportedAtCooperatingPinx",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_anfCINTcanInterceptImmediate,
      { "anfCINTcanInterceptImmediate", "qsig.cmn.FeatureIdList.anfCINTcanInterceptImmediate",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_anfCINTcanInterceptDelayed,
      { "anfCINTcanInterceptDelayed", "qsig.cmn.FeatureIdList.anfCINTcanInterceptDelayed",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_anfWTMIreRoutingSupported,
      { "anfWTMIreRoutingSupported", "qsig.cmn.FeatureIdList.anfWTMIreRoutingSupported",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_anfPUMIreRoutingSupported,
      { "anfPUMIreRoutingSupported", "qsig.cmn.FeatureIdList.anfPUMIreRoutingSupported",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_qsig_cmn_FeatureIdList_ssSSCTreRoutingSupported,
      { "ssSSCTreRoutingSupported", "qsig.cmn.FeatureIdList.ssSSCTreRoutingSupported",
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
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
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
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
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
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
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
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
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
      { "sRforTransactionCompleted", "qsig.sms.SmscControlParameterHeader.sRforTransactionCompleted",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_qsig_sms_SmscControlParameterHeader_sRforPermanentError,
      { "sRforPermanentError", "qsig.sms.SmscControlParameterHeader.sRforPermanentError",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_qsig_sms_SmscControlParameterHeader_sRforTempErrorSCnotTrying,
      { "sRforTempErrorSCnotTrying", "qsig.sms.SmscControlParameterHeader.sRforTempErrorSCnotTrying",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_qsig_sms_SmscControlParameterHeader_sRforTempErrorSCstillTrying,
      { "sRforTempErrorSCstillTrying", "qsig.sms.SmscControlParameterHeader.sRforTempErrorSCstillTrying",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_qsig_sms_SmscControlParameterHeader_spare_bit4,
      { "spare_bit4", "qsig.sms.SmscControlParameterHeader.spare.bit4",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_qsig_sms_SmscControlParameterHeader_spare_bit5,
      { "spare_bit5", "qsig.sms.SmscControlParameterHeader.spare.bit5",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_qsig_sms_SmscControlParameterHeader_cancelSRRforConcatenatedSM,
      { "cancelSRRforConcatenatedSM", "qsig.sms.SmscControlParameterHeader.cancelSRRforConcatenatedSM",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_qsig_sms_SmscControlParameterHeader_includeOrigUDHintoSR,
      { "includeOrigUDHintoSR", "qsig.sms.SmscControlParameterHeader.includeOrigUDHintoSR",
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
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
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
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_ahpriority,
      { "priority", "qsig.mcm.priority",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_qsig_mcm_lastTimeStamp,
      { "lastTimeStamp", "qsig.mcm.lastTimeStamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
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
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_qsig,
    &ett_qsig_ie,
    &ett_qsig_unknown_extension,

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
    &ett_cnq_PSS1InformationElement,
  };

  static ei_register_info ei[] = {
#if 0
    { &ei_qsig_unsupported_arg_type, { "qsig.unsupported.arg_type", PI_UNDECODED, PI_WARN, "UNSUPPORTED ARGUMENT TYPE (QSIG)", EXPFILL }},
#endif
    { &ei_qsig_unsupported_result_type, { "qsig.unsupported.result_type", PI_UNDECODED, PI_WARN, "UNSUPPORTED RESULT TYPE (QSIG)", EXPFILL }},
    { &ei_qsig_unsupported_error_type, { "qsig.unsupported.error_type", PI_UNDECODED, PI_WARN, "UNSUPPORTED ERROR TYPE (QSIG)", EXPFILL }},
  };

  expert_module_t* expert_qsig;

  /* Register protocol and dissector */
  proto_qsig = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_qsig, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_qsig = expert_register_protocol(proto_qsig);
  expert_register_field_array(expert_qsig, ei, array_length(ei));

  /* Register dissectors */
  qsig_arg_handle = register_dissector(PFNAME "_arg", dissect_qsig_arg, proto_qsig);
  qsig_res_handle = register_dissector(PFNAME "_res", dissect_qsig_res, proto_qsig);
  qsig_err_handle = register_dissector(PFNAME "_err", dissect_qsig_err, proto_qsig);
  qsig_ie4_handle = register_dissector(PFNAME "_ie_cs4", dissect_qsig_ie_cs4, proto_qsig);
  qsig_ie5_handle = register_dissector(PFNAME "_ie_cs5", dissect_qsig_ie_cs5, proto_qsig);

  /* Register dissector tables */
  extension_dissector_table = register_dissector_table("qsig.ext", "QSIG Extension", proto_qsig, FT_STRING, STRING_CASE_SENSITIVE);
}


/*--- proto_reg_handoff_qsig ------------------------------------------------*/
void proto_reg_handoff_qsig(void) {
  int i;
  char *oid;
  dissector_handle_t q931_handle;

  q931_handle = find_dissector_add_dependency("q931", proto_qsig);
  q931_ie_handle = find_dissector_add_dependency("q931.ie", proto_qsig);

  for (i=0; i<(int)array_length(qsig_op_tab); i++) {
    dissector_add_uint("q932.ros.local.arg", qsig_op_tab[i].opcode, qsig_arg_handle);
    dissector_add_uint("q932.ros.local.res", qsig_op_tab[i].opcode, qsig_res_handle);

    oid = wmem_strdup_printf(NULL, "1.3.12.9.%d", qsig_op_tab[i].opcode);
    dissector_add_string("q932.ros.global.arg", oid, qsig_arg_handle);
    dissector_add_string("q932.ros.global.res", oid, qsig_res_handle);
    wmem_free(NULL, oid);
  }
  for (i=0; i<(int)array_length(qsig_err_tab); i++) {
    dissector_add_uint("q932.ros.local.err", qsig_err_tab[i].errcode, qsig_err_handle);
  }

  /* QSIG-TC - Transit counter */
  dissector_add_uint("q931.ie", CS4 | QSIG_IE_TRANSIT_COUNTER, qsig_ie4_handle);

  /* SSIG-BC - Party category */
  dissector_add_uint("q931.ie", CS5 | QSIG_IE_PARTY_CATEGORY, qsig_ie5_handle);

  /* RFC 3204, 3.2 QSIG Media Type */
  dissector_add_string("media_type", "application/qsig", q931_handle);

}

/*---------------------------------------------------------------------------*/
