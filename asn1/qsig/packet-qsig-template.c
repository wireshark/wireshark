/* packet-qsig.c
 * Routines for QSIG packet dissection
 * 2007  Tomas Kukosa
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/strutil.h>
#include <epan/emem.h>

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

const value_string qsig_str_service[] = {
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

const value_string qsig_str_service_name[] = {
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

const value_string qsig_str_operation[] = {
  {   0, "callingName" },
  {   1, "calledName" },
  {   2, "connectedName" },
  {   3, "busyName" },
  {   4, "pathReplacePropose" },
  {   5, "pathReplaceSetup" },
  {   6, "pathReplaceRetain" },
  {   7, "callTransferIdentify" },
  {   8, "callTransferAbandon" },
  {   9, "callTransferInitiate" },
  {  10, "callTransferSetup" },
  {  11, "callTransferActive" },
  {  12, "callTransferComplete" },
  {  13, "callTransferUpdate" },
  {  14, "subaddressTransfer" },
  {  15, "activateDiversionQ" },
  {  16, "deactivateDiversionQ" },
  {  17, "interrogateDiversionQ" },
  {  18, "checkRestriction" },
  {  19, "callRerouteing" },
  {  20, "divertingLegInformation1" },
  {  21, "divertingLegInformation2" },
  {  22, "divertingLegInformation3" },
  {  23, "cfnrDivertedLegFailed" },
/*   24	Reserved (corresponding integer value used by ISO for MLPP) */	 
/*   25	Reserved (corresponding integer value used by ISO for MLPP) */	 
/*   26	Reserved (corresponding integer value used by ISO for MLPP) */	 
  {  27, "ccnrRequest" },
  {  28, "ccCancel" },
  {  29, "ccExecPossible" },
  {  30, "ccPathReserve" },
  {  31, "ccRingout" },
  {  32, "ccSuspend" },
  {  33, "ccResume" },
  {  34, "callOfferRequest" },
  {  35, "doNotDisturbActivateQ" },
  {  36, "doNotDisturbDeactivateQ" },
  {  37, "doNotDisturbInterrogateQ" },
  {  38, "doNotDisturbOverrideQ" },
  {  39, "doNotDisturbOvrExecuteQ" },
  {  40, "ccbsRequest" },
  {  41, "pathRetain" },        /* common for QSIG-CO, QSIG-DND(O), QSIG-CI */
  {  42, "serviceAvailable" },  /* common for QSIG-CO, QSIG-DND(O), QSIG-CI */
  {  43, "callIntrusionRequest" },
  {  44, "callIntrusionGetCIPL" },
  {  45, "callIntrusionIsolate" },
  {  46, "callIntrusionForcedRelease" },
  {  47, "callIntrusionWOBRequest" },
  {  48, "callIntrusionCompleted" },
  {  49, "cfbOverride" },       /* common for QSIG-CO, QSIG-CI */
  {  50, "locUpdate" },
  {  51, "locDelete" },
  {  52, "locDeReg" },
  {  53, "pisnEnquiry" },
  {  54, "wtmiEnquiry" },
  {  55, "wtmiDivert" },
  {  56, "wtmiInform" },
  {  57, "recallAlerting" },
  {  58, "recallAnswered" },
  {  59, "chargeRequest" },
  {  60, "getFinalCharge" },
  {  61, "aocFinal" },
  {  62, "aocInterim" },
  {  63, "aocRate" },
  {  64, "aocComplete" },
  {  65, "aocDivChargeReq" },
  {  66, "cintLegInformation1" },
  {  67, "cintLegInformation2" },
  {  68, "cintCondition" },
  {  69, "cintDisable" },
  {  70, "cintEnable" },
  {  71, "wtmoCall" },
  {  72, "authWtmUser" },
  {  73, "getWtatParam" },
  {  74, "wtatParamEnq" },
  {  75, "getWtanParam" },
  {  76, "wtanParamEnq" },
  {  77, "transferAuthParam" },
  {  78, "synchronizationRequest" },
  {  79, "synchronizationInfo" },
  {  80, "mwiActivate/mCMNewMsg" },        /* common for QSIG-MWI, QSIG-MCM */
  {  81, "mwiDeactivate/mCMNoNewMsg" },    /* common for QSIG-MWI, QSIG-MCM */
  {  82, "mwiInterrogate/mCMUpdateReq" },  /* common for QSIG-MWI, QSIG-MCM */
/*   83	Reserved (corresponding integer value used by ISO for RRC) 	ISO/IEC 13241 */
  {  84, "cmnRequest" },
  {  85, "cmnInform" },
  {  86, "pathReplaceInvite" },
  {  87, "callInterruptionRequest" },
  {  88, "callProtectionRequest" },
  {  89, "pumRegistr" },
  {  90, "pumDelReg" },
  {  91, "pumDe-reg" },
  {  92, "pumInterrog" },
  {  93, "pumiEnquiry" },
  {  94, "pumiDivert" },
  {  95, "pumiInform" },
  {  96, "pumoCall" },
  {  97, "getRRCInf" },
  {  98, "locInfoCheck" },
  {  99, "ssctInitiate" },
  { 100, "ssctSetup" },
  { 101, "ssctPostDial" },
  { 102, "ssctDigitInfo" },
  { 103, "display" },
  { 104, "keypad" },
  { 105, "callIdentificationAssign" },
  { 106, "callIdentificationUpdate" },
  { 107, "smsSubmit" },
  { 108, "smsDeliver" },
  { 109, "smsStatusReport" },
  { 110, "smsCommand" },
  { 111, "scAlert" },
  { 112, "mCRequest" },
  { 113, "mCAlerting" },
  { 114, "mCInform" },
  { 115, "mCMUpdate" },
  { 116, "mCMService" },
  { 117, "mCMInterrogate" },
  { 118, "mCMailboxFull" },
  { 119, "mIDMailboxAuth" },
  { 120, "mIDMailboxID" },
  {   0, NULL}
};


void dissect_qsig_arg(tvbuff_t*, packet_info*, proto_tree*, guint32);
#define FNABODY(x) static void dissect_qsig_arg##x(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) \
  { dissect_qsig_arg(tvb, pinfo, tree, (x)); }

void dissect_qsig_res(tvbuff_t*, packet_info*, proto_tree*, guint32);
#define FNRBODY(x) static void dissect_qsig_res##x(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) \
  { dissect_qsig_res(tvb, pinfo, tree, (x)); }

/* QSIG-NA */
FNABODY(0)  FNRBODY(0)
FNABODY(1)  FNRBODY(1)
FNABODY(2)  FNRBODY(2)
FNABODY(3)  FNRBODY(3)
/* QSIG-CF */
FNABODY(15)  FNRBODY(15)
FNABODY(16)  FNRBODY(16)
FNABODY(17)  FNRBODY(17)
FNABODY(18)  FNRBODY(18)
FNABODY(19)  FNRBODY(19)
FNABODY(20)  FNRBODY(20)
FNABODY(21)  FNRBODY(21)
FNABODY(22)  FNRBODY(22)
FNABODY(23)  FNRBODY(23)
/* QSIG-PR */
FNABODY(4)   FNRBODY(4)
FNABODY(5)   FNRBODY(5)
FNABODY(6)   FNRBODY(6)
FNABODY(86)  FNRBODY(86)
/* QSIG-CT */
FNABODY(7)   FNRBODY(7)
FNABODY(8)   FNRBODY(8)
FNABODY(9)   FNRBODY(9)
FNABODY(10)  FNRBODY(10)
FNABODY(11)  FNRBODY(11)
FNABODY(12)  FNRBODY(12)
FNABODY(13)  FNRBODY(13)
FNABODY(14)  FNRBODY(14)
/* QSIG-CC */
FNABODY(40)  FNRBODY(40)
FNABODY(27)  FNRBODY(27)
FNABODY(28)  FNRBODY(28)
FNABODY(29)  FNRBODY(29)
FNABODY(30)  FNRBODY(30)
FNABODY(31)  FNRBODY(31)
FNABODY(32)  FNRBODY(32)
FNABODY(33)  FNRBODY(33)
/* QSIG-CO */
FNABODY(34)  FNRBODY(34)
/* see common for QSIG-CO, QSIG-DND(O), QSIG-CI */                     
/* QSIG-DND(O) */
FNABODY(35)  FNRBODY(35)
FNABODY(36)  FNRBODY(36)
FNABODY(37)  FNRBODY(37)
FNABODY(38)  FNRBODY(38)
FNABODY(39)  FNRBODY(39)
/* see common for QSIG-CO, QSIG-DND(O), QSIG-CI */                     
/* QSIG-CI */
FNABODY(43)  FNRBODY(43)
FNABODY(44)  FNRBODY(44)
FNABODY(45)  FNRBODY(45)
FNABODY(46)  FNRBODY(46)
FNABODY(47)  FNRBODY(47)
FNABODY(48)  FNRBODY(48)
/* QSIG-AOC */
FNABODY(59)  FNRBODY(59)
FNABODY(60)  FNRBODY(60)
FNABODY(61)  FNRBODY(61)
FNABODY(62)  FNRBODY(62)
FNABODY(63)  FNRBODY(63)
FNABODY(64)  FNRBODY(64)
FNABODY(65)  FNRBODY(65)
/* QSIG-RE */
FNABODY(57)  FNRBODY(57)
FNABODY(58)  FNRBODY(58)
/* QSIG-CINT */
FNABODY(66)  FNRBODY(66)
FNABODY(67)  FNRBODY(67)
FNABODY(68)  FNRBODY(68)
FNABODY(69)  FNRBODY(69)
FNABODY(70)  FNRBODY(70)
/* QSIG-MWI */
/* see common for QSIG-MWI, QSIG-MCM */                     
/* SYNC-SIG */                     
FNABODY(78)  FNRBODY(78)
FNABODY(79)  FNRBODY(79)
/* QSIG-CMN */
FNABODY(84) FNRBODY(84)
FNABODY(85) FNRBODY(85)
/* QSIG-CPI(P) */
FNABODY(87)  FNRBODY(87)
FNABODY(88)  FNRBODY(88)
/* QSIG-PUMR */
FNABODY(89)  FNRBODY(89)
FNABODY(90)  FNRBODY(90)
FNABODY(91)  FNRBODY(91)
FNABODY(92)  FNRBODY(92)
/* QSIG-PUMCH */
FNABODY(93)  FNRBODY(93)
FNABODY(94)  FNRBODY(94)
FNABODY(95)  FNRBODY(95)
FNABODY(96)  FNRBODY(96)
/* QSIG-SSCT */
FNABODY(99)  FNRBODY(99)
FNABODY(100) FNRBODY(100)
FNABODY(101) FNRBODY(101)
FNABODY(102) FNRBODY(102)
/* QSIG-WTMLR */
FNABODY(50)  FNRBODY(50)
FNABODY(51)  FNRBODY(51)
FNABODY(52)  FNRBODY(52)
FNABODY(53)  FNRBODY(53)
FNABODY(97)  FNRBODY(97)
FNABODY(98)  FNRBODY(98)
/* QSIG-WTMCH */                      
FNABODY(54)  FNRBODY(54)
FNABODY(55)  FNRBODY(55)
FNABODY(56)  FNRBODY(56)
FNABODY(71)  FNRBODY(71)
/* QSIG-WTMAU */               
FNABODY(72)  FNRBODY(72)
FNABODY(73)  FNRBODY(73)
FNABODY(74)  FNRBODY(74)
FNABODY(75)  FNRBODY(75)
FNABODY(76)  FNRBODY(76)
FNABODY(77)  FNRBODY(77)
/* QSIG-SD */                     
FNABODY(103) FNRBODY(103)
FNABODY(104) FNRBODY(104)
/* QSIG-CIDL */
FNABODY(105) FNRBODY(105)
FNABODY(106) FNRBODY(106)
/* QSIG-SMS */
FNABODY(107) FNRBODY(107)
FNABODY(108) FNRBODY(108)
FNABODY(109) FNRBODY(109)
FNABODY(110) FNRBODY(110)
FNABODY(111) FNRBODY(111)
/* QSIG-MCR */
FNABODY(112)  FNRBODY(112)
FNABODY(113)  FNRBODY(113)
FNABODY(114)  FNRBODY(114)
/* QSIG-MCM */                      
FNABODY(115) FNRBODY(115)
FNABODY(116) FNRBODY(116)
FNABODY(117) FNRBODY(117)
FNABODY(118) FNRBODY(118)
/* QSIG-MID */                      
FNABODY(119) FNRBODY(119)
FNABODY(120) FNRBODY(120)
/* common for QSIG-CO, QSIG-DND(O), QSIG-CI */                     
FNABODY(41)  FNRBODY(41)
FNABODY(42)  FNRBODY(42)
FNABODY(49)  FNRBODY(49)
/* common for QSIG-MWI, QSIG-MCM */                     
FNABODY(80)  FNRBODY(80)
FNABODY(81)  FNRBODY(81)
FNABODY(82)  FNRBODY(82)
                     

typedef guint32 (*pdu_fn)(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset);

typedef struct _qsig_op {
  guint32 service;
  dissector_t arg_dissector;
  dissector_t res_dissector;
  dissector_t arg_pdu;
  dissector_t res_pdu;
} qsig_op;
#define FNA(x) dissect_qsig_arg##x
#define FNR(x) dissect_qsig_res##x

/* Initialize the protocol and registered fields */
int proto_qsig = -1;
static int hf_qsig_operation = -1;
static int hf_qsig_service = -1;
static int hf_qsig_ie_type = -1;
static int hf_qsig_ie_type_cs4 = -1;
static int hf_qsig_ie_type_cs5 = -1;
static int hf_qsig_ie_len = -1;
static int hf_qsig_ie_data = -1;
static int hf_qsig_tc = -1;
static int hf_qsig_pc = -1;
#include "packet-qsig-hf.c"

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
#include "packet-qsig-ett.c"

/* Preferences */

/* Subdissectors */
static dissector_handle_t data_handle = NULL; 

/* Gloabl variables */


#include "packet-qsig-fn.c"


static qsig_op qsig_tab[] = {
  /*   0 */ { 13868, FNA(  0), FNR(  0), dissect_NameArg_PDU, NULL },
  /*   1 */ { 13868, FNA(  1), FNR(  1), dissect_NameArg_PDU, NULL },
  /*   2 */ { 13868, FNA(  2), FNR(  2), dissect_NameArg_PDU, NULL },
  /*   3 */ { 13868, FNA(  3), FNR(  3), dissect_NameArg_PDU, NULL },
  /*   4 */ { 13874, FNA(  4), FNR(  4), NULL, NULL },
  /*   5 */ { 13874, FNA(  5), FNR(  5), NULL, NULL },
  /*   6 */ { 13874, FNA(  6), FNR(  6), NULL, NULL },
  /*   7 */ { 13869, FNA(  7), FNR(  7), NULL, NULL },
  /*   8 */ { 13869, FNA(  8), FNR(  8), NULL, NULL },
  /*   9 */ { 13869, FNA(  9), FNR(  9), NULL, NULL },
  /*  10 */ { 13869, FNA( 10), FNR( 10), NULL, NULL },
  /*  11 */ { 13869, FNA( 11), FNR( 11), NULL, NULL },
  /*  12 */ { 13869, FNA( 12), FNR( 12), NULL, NULL },
  /*  13 */ { 13869, FNA( 13), FNR( 13), NULL, NULL },
  /*  14 */ { 13869, FNA( 14), FNR( 14), NULL, NULL },
  /*  15 */ { 13873, FNA( 15), FNR( 15), dissect_ActivateDivArg_PDU, dissect_ActivateDivRes_PDU },
  /*  16 */ { 13873, FNA( 16), FNR( 16), dissect_DeactivateDivArg_PDU, dissect_DeactivateDivRes_PDU },
  /*  17 */ { 13873, FNA( 17), FNR( 17), dissect_InterrDivArg_PDU, dissect_IntResultList_PDU },
  /*  18 */ { 13873, FNA( 18), FNR( 18), dissect_ChkResArg_PDU, dissect_ChkResRes_PDU },
  /*  19 */ { 13873, FNA( 19), FNR( 19), dissect_CallRrArg_PDU, dissect_CallRrArg_PDU },
  /*  20 */ { 13873, FNA( 20), FNR( 20), dissect_DivLegInf1Arg_PDU, NULL },
  /*  21 */ { 13873, FNA( 21), FNR( 21), dissect_DivLegInf2Arg_PDU, NULL },
  /*  22 */ { 13873, FNA( 22), FNR( 22), dissect_DivLegInf3Arg_PDU, NULL },
  /*  23 */ { 13873, FNA( 23), FNR( 23), dissect_DivLegFailArg_PDU, NULL },
  /*  24 */ {    -1,     NULL,     NULL, NULL, NULL },
  /*  25 */ {    -1,     NULL,     NULL, NULL, NULL },
  /*  26 */ {    -1,     NULL,     NULL, NULL, NULL },
  /*  27 */ { 13870, FNA( 27), FNR( 27), NULL, NULL },
  /*  28 */ { 13870, FNA( 28), FNR( 28), NULL, NULL },
  /*  29 */ { 13870, FNA( 29), FNR( 29), NULL, NULL },
  /*  30 */ { 13870, FNA( 30), FNR( 30), NULL, NULL },
  /*  31 */ { 13870, FNA( 31), FNR( 31), NULL, NULL },
  /*  32 */ { 13870, FNA( 32), FNR( 32), NULL, NULL },
  /*  33 */ { 13870, FNA( 33), FNR( 33), NULL, NULL },
  /*  34 */ { 14843, FNA( 34), FNR( 34), NULL, NULL },
  /*  35 */ { 14844, FNA( 35), FNR( 35), NULL, NULL },
  /*  36 */ { 14844, FNA( 36), FNR( 36), NULL, NULL },
  /*  37 */ { 14844, FNA( 37), FNR( 37), NULL, NULL },
  /*  38 */ { 14844, FNA( 38), FNR( 38), NULL, NULL },
  /*  39 */ { 14844, FNA( 39), FNR( 39), NULL, NULL },
  /*  40 */ { 13870, FNA( 40), FNR( 40), NULL, NULL },
  /*  41 */ { 90001, FNA( 41), FNR( 41), NULL, NULL },
  /*  42 */ { 90001, FNA( 42), FNR( 42), NULL, NULL },
  /*  43 */ { 14846, FNA( 43), FNR( 43), NULL, NULL },
  /*  44 */ { 14846, FNA( 44), FNR( 44), NULL, NULL },
  /*  45 */ { 14846, FNA( 45), FNR( 45), NULL, NULL },
  /*  46 */ { 14846, FNA( 46), FNR( 46), NULL, NULL },
  /*  47 */ { 14846, FNA( 47), FNR( 47), NULL, NULL },
  /*  48 */ { 14846, FNA( 48), FNR( 48), NULL, NULL },
  /*  49 */ { 90001, FNA( 49), FNR( 49), NULL, NULL },
  /*  50 */ { 15429, FNA( 50), FNR( 50), NULL, NULL },
  /*  51 */ { 15429, FNA( 51), FNR( 51), NULL, NULL },
  /*  52 */ { 15429, FNA( 52), FNR( 52), NULL, NULL },
  /*  53 */ { 15429, FNA( 53), FNR( 53), NULL, NULL },
  /*  54 */ { 15431, FNA( 54), FNR( 54), NULL, NULL },
  /*  55 */ { 15431, FNA( 55), FNR( 55), NULL, NULL },
  /*  56 */ { 15431, FNA( 56), FNR( 56), NULL, NULL },
  /*  57 */ { 15052, FNA( 57), FNR( 57), NULL, NULL },
  /*  58 */ { 15052, FNA( 58), FNR( 58), NULL, NULL },
  /*  59 */ { 15050, FNA( 59), FNR( 59), NULL, NULL },
  /*  60 */ { 15050, FNA( 60), FNR( 60), NULL, NULL },
  /*  61 */ { 15050, FNA( 61), FNR( 61), NULL, NULL },
  /*  62 */ { 15050, FNA( 62), FNR( 62), NULL, NULL },
  /*  63 */ { 15050, FNA( 63), FNR( 63), NULL, NULL },
  /*  64 */ { 15050, FNA( 64), FNR( 64), NULL, NULL },
  /*  65 */ { 15050, FNA( 65), FNR( 65), NULL, NULL },
  /*  66 */ { 15054, FNA( 66), FNR( 66), NULL, NULL },
  /*  67 */ { 15054, FNA( 67), FNR( 67), NULL, NULL },
  /*  68 */ { 15054, FNA( 68), FNR( 68), NULL, NULL },
  /*  69 */ { 15054, FNA( 69), FNR( 69), NULL, NULL },
  /*  70 */ { 15054, FNA( 70), FNR( 70), NULL, NULL },
  /*  71 */ { 15431, FNA( 71), FNR( 71), NULL, NULL },
  /*  72 */ { 15433, FNA( 72), FNR( 72), NULL, NULL },
  /*  73 */ { 15433, FNA( 73), FNR( 73), NULL, NULL },
  /*  74 */ { 15433, FNA( 74), FNR( 74), NULL, NULL },
  /*  75 */ { 15433, FNA( 75), FNR( 75), NULL, NULL },
  /*  76 */ { 15433, FNA( 76), FNR( 76), NULL, NULL },
  /*  77 */ { 15433, FNA( 77), FNR( 77), NULL, NULL },
  /*  78 */ { 15507, FNA( 78), FNR( 78), NULL, NULL },
  /*  79 */ { 15507, FNA( 79), FNR( 79), NULL, NULL },
  /*  80 */ { 90002, FNA( 80), FNR( 80), NULL, NULL },
  /*  81 */ { 90002, FNA( 81), FNR( 81), NULL, NULL },
  /*  82 */ { 90002, FNA( 82), FNR( 82), NULL, NULL },
  /*  83 */ {    -1,     NULL,     NULL, NULL, NULL },
  /*  84 */ { 15772, FNA( 84), FNR( 84), NULL, NULL },
  /*  85 */ { 15772, FNA( 85), FNR( 85), NULL, NULL },
  /*  86 */ { 13874, FNA( 86), FNR( 86), NULL, NULL },
  /*  87 */ { 15992, FNA( 87), FNR( 87), NULL, NULL },
  /*  88 */ { 15992, FNA( 88), FNR( 88), NULL, NULL },
  /*  89 */ { 17876, FNA( 89), FNR( 89), NULL, NULL },
  /*  90 */ { 17876, FNA( 90), FNR( 90), NULL, NULL },
  /*  91 */ { 17876, FNA( 91), FNR( 91), NULL, NULL },
  /*  92 */ { 17876, FNA( 92), FNR( 92), NULL, NULL },
  /*  93 */ { 17878, FNA( 93), FNR( 93), NULL, NULL },
  /*  94 */ { 17878, FNA( 94), FNR( 94), NULL, NULL },
  /*  95 */ { 17878, FNA( 95), FNR( 95), NULL, NULL },
  /*  96 */ { 17878, FNA( 96), FNR( 96), NULL, NULL },
  /*  97 */ { 15429, FNA( 97), FNR( 97), NULL, NULL },
  /*  98 */ { 15429, FNA( 98), FNR( 98), NULL, NULL },
  /*  99 */ { 19460, FNA( 99), FNR( 99), NULL, NULL },
  /* 100 */ { 19460, FNA(100), FNR(100), NULL, NULL },
  /* 101 */ { 19460, FNA(101), FNR(101), NULL, NULL },
  /* 102 */ { 19460, FNA(102), FNR(102), NULL, NULL },
  /* 103 */ { 21407, FNA(103), FNR(103), NULL, NULL },
  /* 104 */ { 21407, FNA(104), FNR(104), NULL, NULL },
  /* 105 */ { 21889, FNA(105), FNR(105), NULL, NULL },
  /* 106 */ { 21889, FNA(106), FNR(106), NULL, NULL },
  /* 107 */ {   325, FNA(107), FNR(107), NULL, NULL },
  /* 108 */ {   325, FNA(108), FNR(108), NULL, NULL },
  /* 109 */ {   325, FNA(109), FNR(109), NULL, NULL },
  /* 110 */ {   325, FNA(110), FNR(110), NULL, NULL },
  /* 111 */ {   325, FNA(111), FNR(111), NULL, NULL },
  /* 112 */ {   344, FNA(112), FNR(112), NULL, NULL },
  /* 113 */ {   344, FNA(113), FNR(113), NULL, NULL },
  /* 114 */ {   344, FNA(114), FNR(114), NULL, NULL },
  /* 115 */ {  3471, FNA(115), FNR(115), NULL, NULL },
  /* 116 */ {  3471, FNA(116), FNR(116), NULL, NULL },
  /* 117 */ {  3471, FNA(117), FNR(117), NULL, NULL },
  /* 118 */ {  3471, FNA(118), FNR(118), NULL, NULL },
  /* 119 */ {  3472, FNA(119), FNR(119), NULL, NULL },
  /* 120 */ {  3472, FNA(120), FNR(120), NULL, NULL },
};                                 
                  
/*--- dissect_qsig_arg ------------------------------------------------------*/
/*static*/ void   
dissect_qsig_arg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 operation) {
  gint offset;
  const gchar *p;
  proto_item *ti, *ti_tmp;
  proto_tree *qsig_tree;

  offset = 0;
  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, tvb_length(tvb), FALSE);
  qsig_tree = proto_item_add_subtree(ti, ett_qsig); 

  proto_tree_add_uint(qsig_tree, hf_qsig_operation, tvb, 0, 0, operation);
  p = match_strval(operation, VALS(qsig_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(proto_item_get_parent(proto_tree_get_parent(tree)), " %s", p);
  }
  if (operation >= array_length(qsig_tab)) return;
  if (qsig_tab[operation].service != -1) {
    ti_tmp = proto_tree_add_uint(qsig_tree, hf_qsig_service, tvb, 0, 0, qsig_tab[operation].service);
    p = match_strval(qsig_tab[operation].service, VALS(qsig_str_service_name));
    if (p) proto_item_append_text(ti_tmp, " - %s", p);
  }
  if (qsig_tab[operation].arg_pdu)
    qsig_tab[operation].arg_pdu(tvb, pinfo, qsig_tree);
  else 
    if (tvb_length_remaining(tvb, offset) > 0)
      proto_tree_add_text(qsig_tree, tvb, offset, tvb_length_remaining(tvb, offset), "UNSUPPORTED ARGUMENT TYPE (QSIG)");
}

/*--- dissect_qsig_res -------------------------------------------------------*/
/*static*/ void
dissect_qsig_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 operation) {
  gint offset;
  const gchar *p;
  proto_item *ti, *ti_tmp;
  proto_tree *qsig_tree;

  offset = 0;
  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, tvb_length(tvb), FALSE);
  qsig_tree = proto_item_add_subtree(ti, ett_qsig); 

  proto_tree_add_uint(qsig_tree, hf_qsig_operation, tvb, 0, 0, operation);
  p = match_strval(operation, VALS(qsig_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(proto_item_get_parent(proto_tree_get_parent(tree)), " %s", p);
  }
  if (operation >= array_length(qsig_tab)) return;
  if (qsig_tab[operation].service != -1) {
    ti_tmp = proto_tree_add_uint(qsig_tree, hf_qsig_service, tvb, 0, 0, qsig_tab[operation].service);
    p = match_strval(qsig_tab[operation].service, VALS(qsig_str_service_name));
    if (p) proto_item_append_text(ti_tmp, " - %s", p);
  }
  if (qsig_tab[operation].res_pdu)
    qsig_tab[operation].res_pdu(tvb, pinfo, qsig_tree);
  else 
    if (tvb_length_remaining(tvb, offset) > 0)
      proto_tree_add_text(qsig_tree, tvb, offset, tvb_length_remaining(tvb, offset), "UNSUPPORTED RESULT TYPE (QSIG)");
}

/*--- dissect_qsig_transit_counter_ie ---------------------------------------*/
static int
dissect_qsig_transit_counter_ie(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int length) {
  proto_tree_add_item(tree, hf_qsig_tc, tvb, offset, 1, FALSE);
  offset++;
  return offset;
}
/*--- dissect_qsig_party_category_ie ----------------------------------------*/
static int 
dissect_qsig_party_category_ie(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int length) {
  proto_tree_add_item(tree, hf_qsig_pc, tvb, offset, 1, FALSE);
  offset++;
  return offset;
}

/*--- dissect_qsig_ie -------------------------------------------------------*/
static void
dissect_qsig_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int codeset) {
  gint offset;
  proto_item *ti, *ti_ie;
  proto_tree *ie_tree;
  guint8 ie_type, ie_len;

  offset = 0;

  ti = proto_tree_add_item_hidden(tree, proto_qsig, tvb, offset, -1, FALSE);

  ie_type = tvb_get_guint8(tvb, offset);
  ie_len = tvb_get_guint8(tvb, offset + 1);

  ti_ie = proto_tree_add_text(tree, tvb, offset, -1, "%s",
            val_to_str(ie_type, VALS(qsig_str_ie_type[codeset]), "unknown (0x%02X)"));
  ie_tree = proto_item_add_subtree(ti_ie, ett_qsig_ie); 
  proto_tree_add_item(ie_tree, *hf_qsig_ie_type_arr[codeset], tvb, offset, 1, FALSE);
  proto_tree_add_item_hidden(ie_tree, hf_qsig_ie_type, tvb, offset, 1, FALSE);
  proto_tree_add_item(ie_tree, hf_qsig_ie_len, tvb, offset + 1, 1, FALSE);
  offset += 2;
  if (tvb_length_remaining(tvb, offset) <= 0)
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
        if (tree) proto_tree_add_item(ie_tree, hf_qsig_ie_data, tvb, offset, ie_len, FALSE);
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

/*--- proto_register_qsig ---------------------------------------------------*/
void proto_register_qsig(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_qsig_operation, { "Operation", "qsig.operation",
                           FT_UINT8, BASE_DEC, VALS(qsig_str_operation), 0x0,
                           "Operation", HFILL }},
    { &hf_qsig_service,   { "Service", "qsig.service",
                           FT_UINT8, BASE_DEC, VALS(qsig_str_service), 0x0,
                           "Supplementary Service", HFILL }},
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
                          FT_BYTES, BASE_HEX, NULL, 0x0,
                          "Data", HFILL }},
    { &hf_qsig_tc,      { "Transit count", "qsig.tc",
                          FT_UINT8, BASE_DEC, NULL, 0x1F,
                          "Transit count", HFILL }},
    { &hf_qsig_pc,      { "Party category", "qsig.pc",
                          FT_UINT8, BASE_HEX, VALS(qsig_str_pc), 0x07,
                          "Party category", HFILL }},
#include "packet-qsig-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_qsig,
    &ett_qsig_ie,
#include "packet-qsig-ettarr.c"
  };

  /* Register protocol and dissector */
  proto_qsig = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_qsig, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_qsig ------------------------------------------------*/
void proto_reg_handoff_qsig(void) {
  guint32 op;
  dissector_handle_t qsig_op_handle;
  dissector_handle_t qsig_ie_handle;

  data_handle = find_dissector("data");

  if (find_dissector_table("q932.ros.local.arg")) {
    for (op=0; op<array_length(qsig_tab); op++) {
      if (qsig_tab[op].arg_dissector) {
        qsig_op_handle = create_dissector_handle(qsig_tab[op].arg_dissector, proto_qsig);
        dissector_add("q932.ros.local.arg", op, qsig_op_handle);
      }
      if (qsig_tab[op].res_dissector) {
        qsig_op_handle = create_dissector_handle(qsig_tab[op].res_dissector, proto_qsig);
        dissector_add("q932.ros.local.res", op, qsig_op_handle);
      }
    }
  }

  qsig_ie_handle = create_dissector_handle(dissect_qsig_ie_cs4, proto_qsig);
  /* QSIG-TC - Transit counter */
  dissector_add("q931.ie", CS4 | QSIG_IE_TRANSIT_COUNTER, qsig_ie_handle);

  qsig_ie_handle = create_dissector_handle(dissect_qsig_ie_cs5, proto_qsig);
  /* SSIG-BC - Party category */
  dissector_add("q931.ie", CS5 | QSIG_IE_PARTY_CATEGORY, qsig_ie_handle);

}

/*---------------------------------------------------------------------------*/