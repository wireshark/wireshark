/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-qsig.c                                                            */
/* ../../tools/asn2wrs.py -b -T -e -p qsig -c qsig.cnf -s packet-qsig-template qsig-gf-ext.asn qsig-gf-gp.asn qsig-gf-ade.asn qsig-na.asn qsig-cf.asn */

/* Input file: packet-qsig-template.c */

#line 1 "packet-qsig-template.c"
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
#define NO_SRV ((guint32)-1)
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

/*--- Included file: packet-qsig-hf.c ---*/
#line 1 "packet-qsig-hf.c"
static int hf_qsig_NameArg_PDU = -1;              /* NameArg */
static int hf_qsig_ActivateDivArg_PDU = -1;       /* ActivateDivArg */
static int hf_qsig_ActivateDivRes_PDU = -1;       /* ActivateDivRes */
static int hf_qsig_DeactivateDivArg_PDU = -1;     /* DeactivateDivArg */
static int hf_qsig_DeactivateDivRes_PDU = -1;     /* DeactivateDivRes */
static int hf_qsig_InterrDivArg_PDU = -1;         /* InterrDivArg */
static int hf_qsig_ChkResArg_PDU = -1;            /* ChkResArg */
static int hf_qsig_ChkResRes_PDU = -1;            /* ChkResRes */
static int hf_qsig_CallRrArg_PDU = -1;            /* CallRrArg */
static int hf_qsig_CallRrRes_PDU = -1;            /* CallRrRes */
static int hf_qsig_DivLegInf1Arg_PDU = -1;        /* DivLegInf1Arg */
static int hf_qsig_DivLegInf2Arg_PDU = -1;        /* DivLegInf2Arg */
static int hf_qsig_DivLegInf3Arg_PDU = -1;        /* DivLegInf3Arg */
static int hf_qsig_DivLegFailArg_PDU = -1;        /* DivLegFailArg */
static int hf_qsig_IntResultList_PDU = -1;        /* IntResultList */
static int hf_qsig_extensionId = -1;              /* OBJECT_IDENTIFIER */
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
static int hf_qsig_name = -1;                     /* Name */
static int hf_qsig_nameSequence = -1;             /* T_nameSequence */
static int hf_qsig_extensionNA = -1;              /* NameExtension */
static int hf_qsig_single = -1;                   /* Extension */
static int hf_qsig_multiple = -1;                 /* SEQUENCE_OF_Extension */
static int hf_qsig_multiple_item = -1;            /* Extension */
static int hf_qsig_namePresentationAllowed = -1;  /* NamePresentationAllowed */
static int hf_qsig_namePresentationRestricted = -1;  /* NamePresentationRestricted */
static int hf_qsig_nameNotAvailable = -1;         /* NameNotAvailable */
static int hf_qsig_namePresentationAllowedSimple = -1;  /* NameData */
static int hf_qsig_namePresentationAllowedExtended = -1;  /* NameSet */
static int hf_qsig_namePresentationRestrictedSimple = -1;  /* NameData */
static int hf_qsig_namePresentationRestrictedExtended = -1;  /* NameSet */
static int hf_qsig_namePresentationRestrictedNull = -1;  /* NULL */
static int hf_qsig_nameData = -1;                 /* NameData */
static int hf_qsig_characterSet = -1;             /* CharacterSet */
static int hf_qsig_procedure = -1;                /* Procedure */
static int hf_qsig_basicService = -1;             /* BasicService */
static int hf_qsig_divertedToAddress = -1;        /* Address */
static int hf_qsig_servedUserNr = -1;             /* PartyNumber */
static int hf_qsig_activatingUserNr = -1;         /* PartyNumber */
static int hf_qsig_extensionAD = -1;              /* ADExtension */
static int hf_qsig_null = -1;                     /* NULL */
static int hf_qsig_deactivatingUserNr = -1;       /* PartyNumber */
static int hf_qsig_extensionDD = -1;              /* DDExtension */
static int hf_qsig_interrogatingUserNr = -1;      /* PartyNumber */
static int hf_qsig_extensionID = -1;              /* IDExtension */
static int hf_qsig_divertedToNr = -1;             /* PartyNumber */
static int hf_qsig_extensionCHR = -1;             /* CHRExtension */
static int hf_qsig_rerouteingReason = -1;         /* DiversionReason */
static int hf_qsig_originalRerouteingReason = -1;  /* DiversionReason */
static int hf_qsig_calledAddress = -1;            /* Address */
static int hf_qsig_diversionCounter = -1;         /* INTEGER_1_15 */
static int hf_qsig_pSS1InfoElement = -1;          /* PSS1InformationElement */
static int hf_qsig_lastRerouteingNr = -1;         /* PresentedNumberUnscreened */
static int hf_qsig_subscriptionOption = -1;       /* SubscriptionOption */
static int hf_qsig_callingPartySubaddress = -1;   /* PartySubaddress */
static int hf_qsig_callingNumber = -1;            /* PresentedNumberScreened */
static int hf_qsig_callingName = -1;              /* Name */
static int hf_qsig_originalCalledNr = -1;         /* PresentedNumberUnscreened */
static int hf_qsig_redirectingName = -1;          /* Name */
static int hf_qsig_originalCalledName = -1;       /* Name */
static int hf_qsig_extensionCRR = -1;             /* CRRExtension */
static int hf_qsig_diversionReason = -1;          /* DiversionReason */
static int hf_qsig_nominatedNr = -1;              /* PartyNumber */
static int hf_qsig_extensionDLI1 = -1;            /* DLI1Extension */
static int hf_qsig_originalDiversionReason = -1;  /* DiversionReason */
static int hf_qsig_divertingNr = -1;              /* PresentedNumberUnscreened */
static int hf_qsig_extensionDLI2 = -1;            /* DLI2Extension */
static int hf_qsig_presentationAllowedIndicator = -1;  /* PresentationAllowedIndicator */
static int hf_qsig_redirectionName = -1;          /* Name */
static int hf_qsig_extensionDLI3 = -1;            /* DLI3Extension */
static int hf_qsig_IntResultList_item = -1;       /* IntResult */
static int hf_qsig_remoteEnabled = -1;            /* BOOLEAN */
static int hf_qsig_extensionIR = -1;              /* IRExtension */

/*--- End of included file: packet-qsig-hf.c ---*/
#line 456 "packet-qsig-template.c"

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

/*--- Included file: packet-qsig-ett.c ---*/
#line 1 "packet-qsig-ett.c"
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
static gint ett_qsig_NameArg = -1;
static gint ett_qsig_T_nameSequence = -1;
static gint ett_qsig_NameExtension = -1;
static gint ett_qsig_SEQUENCE_OF_Extension = -1;
static gint ett_qsig_Name = -1;
static gint ett_qsig_NamePresentationAllowed = -1;
static gint ett_qsig_NamePresentationRestricted = -1;
static gint ett_qsig_NameSet = -1;
static gint ett_qsig_ActivateDivArg = -1;
static gint ett_qsig_ADExtension = -1;
static gint ett_qsig_ActivateDivRes = -1;
static gint ett_qsig_DeactivateDivArg = -1;
static gint ett_qsig_DDExtension = -1;
static gint ett_qsig_DeactivateDivRes = -1;
static gint ett_qsig_InterrDivArg = -1;
static gint ett_qsig_IDExtension = -1;
static gint ett_qsig_ChkResArg = -1;
static gint ett_qsig_CHRExtension = -1;
static gint ett_qsig_ChkResRes = -1;
static gint ett_qsig_CallRrArg = -1;
static gint ett_qsig_CRRExtension = -1;
static gint ett_qsig_CallRrRes = -1;
static gint ett_qsig_DivLegInf1Arg = -1;
static gint ett_qsig_DLI1Extension = -1;
static gint ett_qsig_DivLegInf2Arg = -1;
static gint ett_qsig_DLI2Extension = -1;
static gint ett_qsig_DivLegInf3Arg = -1;
static gint ett_qsig_DLI3Extension = -1;
static gint ett_qsig_DivLegFailArg = -1;
static gint ett_qsig_IntResultList = -1;
static gint ett_qsig_IntResult = -1;
static gint ett_qsig_IRExtension = -1;

/*--- End of included file: packet-qsig-ett.c ---*/
#line 472 "packet-qsig-template.c"

/* Preferences */

/* Subdissectors */
static dissector_handle_t data_handle = NULL; 

/* Gloabl variables */



/*--- Included file: packet-qsig-fn.c ---*/
#line 1 "packet-qsig-fn.c"
/*--- Fields for imported types ---*/




static int
dissect_qsig_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_extensionId(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_qsig_extensionId);
}



static int
dissect_qsig_T_extensionArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 65 "qsig.cnf"



  return offset;
}
static int dissect_extensionArgument(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_T_extensionArgument(FALSE, tvb, offset, pinfo, tree, hf_qsig_extensionArgument);
}


static const ber_sequence_t Extension_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_extensionId },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_extensionArgument },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Extension_sequence, hf_index, ett_qsig_Extension);

  return offset;
}
static int dissect_single_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_Extension(TRUE, tvb, offset, pinfo, tree, hf_qsig_single);
}
static int dissect_multiple_item(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_Extension(FALSE, tvb, offset, pinfo, tree, hf_qsig_multiple_item);
}



static int
dissect_qsig_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_PSS1InformationElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, pinfo, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, TRUE, dissect_qsig_OCTET_STRING);

  return offset;
}
static int dissect_pSS1InfoElement(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PSS1InformationElement(FALSE, tvb, offset, pinfo, tree, hf_qsig_pSS1InfoElement);
}



static int
dissect_qsig_NumberDigits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_unknownPartyNumber_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NumberDigits(TRUE, tvb, offset, pinfo, tree, hf_qsig_unknownPartyNumber);
}
static int dissect_dataPartyNumber_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NumberDigits(TRUE, tvb, offset, pinfo, tree, hf_qsig_dataPartyNumber);
}
static int dissect_telexPartyNumber_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NumberDigits(TRUE, tvb, offset, pinfo, tree, hf_qsig_telexPartyNumber);
}
static int dissect_nationalStandardPartyNumber_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NumberDigits(TRUE, tvb, offset, pinfo, tree, hf_qsig_nationalStandardPartyNumber);
}
static int dissect_publicNumberDigits(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NumberDigits(FALSE, tvb, offset, pinfo, tree, hf_qsig_publicNumberDigits);
}
static int dissect_privateNumberDigits(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NumberDigits(FALSE, tvb, offset, pinfo, tree, hf_qsig_privateNumberDigits);
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
dissect_qsig_PublicTypeOfNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_publicTypeOfNumber(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PublicTypeOfNumber(FALSE, tvb, offset, pinfo, tree, hf_qsig_publicTypeOfNumber);
}


static const ber_sequence_t PublicPartyNumber_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_publicTypeOfNumber },
  { BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_publicNumberDigits },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_PublicPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PublicPartyNumber_sequence, hf_index, ett_qsig_PublicPartyNumber);

  return offset;
}
static int dissect_publicPartyNumber_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PublicPartyNumber(TRUE, tvb, offset, pinfo, tree, hf_qsig_publicPartyNumber);
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
dissect_qsig_PrivateTypeOfNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_privateTypeOfNumber(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PrivateTypeOfNumber(FALSE, tvb, offset, pinfo, tree, hf_qsig_privateTypeOfNumber);
}


static const ber_sequence_t PrivatePartyNumber_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_privateTypeOfNumber },
  { BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_privateNumberDigits },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_PrivatePartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PrivatePartyNumber_sequence, hf_index, ett_qsig_PrivatePartyNumber);

  return offset;
}
static int dissect_privatePartyNumber_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PrivatePartyNumber(TRUE, tvb, offset, pinfo, tree, hf_qsig_privatePartyNumber);
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

static const ber_choice_t PartyNumber_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_unknownPartyNumber_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_publicPartyNumber_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_dataPartyNumber_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_telexPartyNumber_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_privatePartyNumber_impl },
  {   8, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_nationalStandardPartyNumber_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_PartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PartyNumber_choice, hf_index, ett_qsig_PartyNumber,
                                 NULL);

  return offset;
}
static int dissect_presentationAllowedAddressNU(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PartyNumber(FALSE, tvb, offset, pinfo, tree, hf_qsig_presentationAllowedAddressNU);
}
static int dissect_presentationRestrictedAddressNU(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PartyNumber(FALSE, tvb, offset, pinfo, tree, hf_qsig_presentationRestrictedAddressNU);
}
static int dissect_partyNumber(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PartyNumber(FALSE, tvb, offset, pinfo, tree, hf_qsig_partyNumber);
}
static int dissect_servedUserNr(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PartyNumber(FALSE, tvb, offset, pinfo, tree, hf_qsig_servedUserNr);
}
static int dissect_activatingUserNr(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PartyNumber(FALSE, tvb, offset, pinfo, tree, hf_qsig_activatingUserNr);
}
static int dissect_deactivatingUserNr(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PartyNumber(FALSE, tvb, offset, pinfo, tree, hf_qsig_deactivatingUserNr);
}
static int dissect_interrogatingUserNr(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PartyNumber(FALSE, tvb, offset, pinfo, tree, hf_qsig_interrogatingUserNr);
}
static int dissect_divertedToNr(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PartyNumber(FALSE, tvb, offset, pinfo, tree, hf_qsig_divertedToNr);
}
static int dissect_nominatedNr(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PartyNumber(FALSE, tvb, offset, pinfo, tree, hf_qsig_nominatedNr);
}


static const value_string qsig_ScreeningIndicator_vals[] = {
  {   0, "userProvidedNotScreened" },
  {   1, "userProvidedVerifiedAndPassed" },
  {   2, "userProvidedVerifiedAndFailed" },
  {   3, "networkProvided" },
  { 0, NULL }
};


static int
dissect_qsig_ScreeningIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_screeningIndicator(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_ScreeningIndicator(FALSE, tvb, offset, pinfo, tree, hf_qsig_screeningIndicator);
}



static int
dissect_qsig_SubaddressInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_subaddressInformation(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_SubaddressInformation(FALSE, tvb, offset, pinfo, tree, hf_qsig_subaddressInformation);
}



static int
dissect_qsig_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_oddCountIndicator(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_qsig_oddCountIndicator);
}
static int dissect_remoteEnabled(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_qsig_remoteEnabled);
}


static const ber_sequence_t UserSpecifiedSubaddress_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_subaddressInformation },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_oddCountIndicator },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_UserSpecifiedSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   UserSpecifiedSubaddress_sequence, hf_index, ett_qsig_UserSpecifiedSubaddress);

  return offset;
}
static int dissect_userSpecifiedSubaddress(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_UserSpecifiedSubaddress(FALSE, tvb, offset, pinfo, tree, hf_qsig_userSpecifiedSubaddress);
}



static int
dissect_qsig_NSAPSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_nSAPSubaddress(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NSAPSubaddress(FALSE, tvb, offset, pinfo, tree, hf_qsig_nSAPSubaddress);
}


static const value_string qsig_PartySubaddress_vals[] = {
  {   0, "userSpecifiedSubaddress" },
  {   1, "nSAPSubaddress" },
  { 0, NULL }
};

static const ber_choice_t PartySubaddress_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_userSpecifiedSubaddress },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_nSAPSubaddress },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_PartySubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PartySubaddress_choice, hf_index, ett_qsig_PartySubaddress,
                                 NULL);

  return offset;
}
static int dissect_partySubaddress(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PartySubaddress(FALSE, tvb, offset, pinfo, tree, hf_qsig_partySubaddress);
}
static int dissect_callingPartySubaddress(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PartySubaddress(FALSE, tvb, offset, pinfo, tree, hf_qsig_callingPartySubaddress);
}


static const ber_sequence_t AddressScreened_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_partyNumber },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_screeningIndicator },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_partySubaddress },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_AddressScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AddressScreened_sequence, hf_index, ett_qsig_AddressScreened);

  return offset;
}
static int dissect_presentationAllowedAddressS_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_AddressScreened(TRUE, tvb, offset, pinfo, tree, hf_qsig_presentationAllowedAddressS);
}
static int dissect_presentationRestrictedAddressS_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_AddressScreened(TRUE, tvb, offset, pinfo, tree, hf_qsig_presentationRestrictedAddressS);
}



static int
dissect_qsig_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_presentationRestricted_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NULL(TRUE, tvb, offset, pinfo, tree, hf_qsig_presentationRestricted);
}
static int dissect_numberNotAvailableDueToInterworking_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NULL(TRUE, tvb, offset, pinfo, tree, hf_qsig_numberNotAvailableDueToInterworking);
}
static int dissect_namePresentationRestrictedNull_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NULL(TRUE, tvb, offset, pinfo, tree, hf_qsig_namePresentationRestrictedNull);
}
static int dissect_null(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NULL(FALSE, tvb, offset, pinfo, tree, hf_qsig_null);
}


static const value_string qsig_PresentedAddressScreened_vals[] = {
  {   0, "presentationAllowedAddressS" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddressS" },
  { 0, NULL }
};

static const ber_choice_t PresentedAddressScreened_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_presentationAllowedAddressS_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_presentationRestricted_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_numberNotAvailableDueToInterworking_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_presentationRestrictedAddressS_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_PresentedAddressScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PresentedAddressScreened_choice, hf_index, ett_qsig_PresentedAddressScreened,
                                 NULL);

  return offset;
}


static const ber_sequence_t Address_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_partyNumber },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_partySubaddress },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Address_sequence, hf_index, ett_qsig_Address);

  return offset;
}
static int dissect_presentationAllowedAddressU_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_Address(TRUE, tvb, offset, pinfo, tree, hf_qsig_presentationAllowedAddressU);
}
static int dissect_presentationRestrictedAddressU_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_Address(TRUE, tvb, offset, pinfo, tree, hf_qsig_presentationRestrictedAddressU);
}
static int dissect_divertedToAddress(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_Address(FALSE, tvb, offset, pinfo, tree, hf_qsig_divertedToAddress);
}
static int dissect_calledAddress(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_Address(FALSE, tvb, offset, pinfo, tree, hf_qsig_calledAddress);
}


static const value_string qsig_PresentedAddressUnscreened_vals[] = {
  {   0, "presentationAllowedAddressU" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddressU" },
  { 0, NULL }
};

static const ber_choice_t PresentedAddressUnscreened_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_presentationAllowedAddressU_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_presentationRestricted_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_numberNotAvailableDueToInterworking_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_presentationRestrictedAddressU_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_PresentedAddressUnscreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PresentedAddressUnscreened_choice, hf_index, ett_qsig_PresentedAddressUnscreened,
                                 NULL);

  return offset;
}


static const ber_sequence_t NumberScreened_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_partyNumber },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_screeningIndicator },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_NumberScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NumberScreened_sequence, hf_index, ett_qsig_NumberScreened);

  return offset;
}
static int dissect_presentationAllowedAddressNS_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NumberScreened(TRUE, tvb, offset, pinfo, tree, hf_qsig_presentationAllowedAddressNS);
}
static int dissect_presentationRestrictedAddressNS_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NumberScreened(TRUE, tvb, offset, pinfo, tree, hf_qsig_presentationRestrictedAddressNS);
}


static const value_string qsig_PresentedNumberScreened_vals[] = {
  {   0, "presentationAllowedAddressNS" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddressNS" },
  { 0, NULL }
};

static const ber_choice_t PresentedNumberScreened_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_presentationAllowedAddressNS_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_presentationRestricted_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_numberNotAvailableDueToInterworking_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_presentationRestrictedAddressNS_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_PresentedNumberScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PresentedNumberScreened_choice, hf_index, ett_qsig_PresentedNumberScreened,
                                 NULL);

  return offset;
}
static int dissect_callingNumber(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PresentedNumberScreened(FALSE, tvb, offset, pinfo, tree, hf_qsig_callingNumber);
}


static const value_string qsig_PresentedNumberUnscreened_vals[] = {
  {   0, "presentationAllowedAddressNU" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddressNU" },
  { 0, NULL }
};

static const ber_choice_t PresentedNumberUnscreened_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_presentationAllowedAddressNU },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_presentationRestricted_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_numberNotAvailableDueToInterworking_impl },
  {   3, BER_CLASS_CON, 3, 0, dissect_presentationRestrictedAddressNU },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_PresentedNumberUnscreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PresentedNumberUnscreened_choice, hf_index, ett_qsig_PresentedNumberUnscreened,
                                 NULL);

  return offset;
}
static int dissect_lastRerouteingNr(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PresentedNumberUnscreened(FALSE, tvb, offset, pinfo, tree, hf_qsig_lastRerouteingNr);
}
static int dissect_originalCalledNr(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PresentedNumberUnscreened(FALSE, tvb, offset, pinfo, tree, hf_qsig_originalCalledNr);
}
static int dissect_divertingNr(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PresentedNumberUnscreened(FALSE, tvb, offset, pinfo, tree, hf_qsig_divertingNr);
}



static int
dissect_qsig_PresentationAllowedIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_presentationAllowedIndicator(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_PresentationAllowedIndicator(FALSE, tvb, offset, pinfo, tree, hf_qsig_presentationAllowedIndicator);
}



static int
dissect_qsig_NameData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_namePresentationAllowedSimple_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NameData(TRUE, tvb, offset, pinfo, tree, hf_qsig_namePresentationAllowedSimple);
}
static int dissect_namePresentationRestrictedSimple_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NameData(TRUE, tvb, offset, pinfo, tree, hf_qsig_namePresentationRestrictedSimple);
}
static int dissect_nameData(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NameData(FALSE, tvb, offset, pinfo, tree, hf_qsig_nameData);
}


static const value_string qsig_CharacterSet_vals[] = {
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
dissect_qsig_CharacterSet(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_characterSet(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_CharacterSet(FALSE, tvb, offset, pinfo, tree, hf_qsig_characterSet);
}


static const ber_sequence_t NameSet_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_nameData },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_characterSet },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_NameSet(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NameSet_sequence, hf_index, ett_qsig_NameSet);

  return offset;
}
static int dissect_namePresentationAllowedExtended_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NameSet(TRUE, tvb, offset, pinfo, tree, hf_qsig_namePresentationAllowedExtended);
}
static int dissect_namePresentationRestrictedExtended_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NameSet(TRUE, tvb, offset, pinfo, tree, hf_qsig_namePresentationRestrictedExtended);
}


static const value_string qsig_NamePresentationAllowed_vals[] = {
  {   0, "namePresentationAllowedSimple" },
  {   1, "namePresentationAllowedExtended" },
  { 0, NULL }
};

static const ber_choice_t NamePresentationAllowed_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_namePresentationAllowedSimple_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_namePresentationAllowedExtended_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_NamePresentationAllowed(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 NamePresentationAllowed_choice, hf_index, ett_qsig_NamePresentationAllowed,
                                 NULL);

  return offset;
}
static int dissect_namePresentationAllowed(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NamePresentationAllowed(FALSE, tvb, offset, pinfo, tree, hf_qsig_namePresentationAllowed);
}


static const value_string qsig_NamePresentationRestricted_vals[] = {
  {   2, "namePresentationRestrictedSimple" },
  {   3, "namePresentationRestrictedExtended" },
  {   7, "namePresentationRestrictedNull" },
  { 0, NULL }
};

static const ber_choice_t NamePresentationRestricted_choice[] = {
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_namePresentationRestrictedSimple_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_namePresentationRestrictedExtended_impl },
  {   7, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_namePresentationRestrictedNull_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_NamePresentationRestricted(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 NamePresentationRestricted_choice, hf_index, ett_qsig_NamePresentationRestricted,
                                 NULL);

  return offset;
}
static int dissect_namePresentationRestricted(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NamePresentationRestricted(FALSE, tvb, offset, pinfo, tree, hf_qsig_namePresentationRestricted);
}



static int
dissect_qsig_NameNotAvailable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, pinfo, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 4, TRUE, dissect_qsig_NULL);

  return offset;
}
static int dissect_nameNotAvailable(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NameNotAvailable(FALSE, tvb, offset, pinfo, tree, hf_qsig_nameNotAvailable);
}


static const ber_choice_t Name_choice[] = {
  {   0, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_namePresentationAllowed },
  {   1, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_namePresentationRestricted },
  {   2, BER_CLASS_CON, 4, BER_FLAGS_NOOWNTAG, dissect_nameNotAvailable },
  { 0, 0, 0, 0, NULL }
};

int
dissect_qsig_Name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Name_choice, hf_index, ett_qsig_Name,
                                 NULL);

  return offset;
}
static int dissect_name(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_Name(FALSE, tvb, offset, pinfo, tree, hf_qsig_name);
}
static int dissect_callingName(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_Name(FALSE, tvb, offset, pinfo, tree, hf_qsig_callingName);
}
static int dissect_redirectingName(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_Name(FALSE, tvb, offset, pinfo, tree, hf_qsig_redirectingName);
}
static int dissect_originalCalledName(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_Name(FALSE, tvb, offset, pinfo, tree, hf_qsig_originalCalledName);
}
static int dissect_redirectionName(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_Name(FALSE, tvb, offset, pinfo, tree, hf_qsig_redirectionName);
}


static const ber_sequence_t SEQUENCE_OF_Extension_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_multiple_item },
};

static int
dissect_qsig_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_SEQUENCE_OF_Extension);

  return offset;
}
static int dissect_multiple_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_SEQUENCE_OF_Extension(TRUE, tvb, offset, pinfo, tree, hf_qsig_multiple);
}


static const value_string qsig_NameExtension_vals[] = {
  {   5, "single" },
  {   6, "multiple" },
  { 0, NULL }
};

static const ber_choice_t NameExtension_choice[] = {
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_NameExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 NameExtension_choice, hf_index, ett_qsig_NameExtension,
                                 NULL);

  return offset;
}
static int dissect_extensionNA(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_NameExtension(FALSE, tvb, offset, pinfo, tree, hf_qsig_extensionNA);
}


static const ber_sequence_t T_nameSequence_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_name },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extensionNA },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_T_nameSequence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_nameSequence_sequence, hf_index, ett_qsig_T_nameSequence);

  return offset;
}
static int dissect_nameSequence(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_T_nameSequence(FALSE, tvb, offset, pinfo, tree, hf_qsig_nameSequence);
}


static const value_string qsig_NameArg_vals[] = {
  {   0, "name" },
  {   1, "nameSequence" },
  { 0, NULL }
};

static const ber_choice_t NameArg_choice[] = {
  {   0, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_name },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_nameSequence },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_NameArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 NameArg_choice, hf_index, ett_qsig_NameArg,
                                 NULL);

  return offset;
}


static const value_string qsig_Procedure_vals[] = {
  {   0, "cfu" },
  {   1, "cfb" },
  {   2, "cfnr" },
  { 0, NULL }
};


static int
dissect_qsig_Procedure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_procedure(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_Procedure(FALSE, tvb, offset, pinfo, tree, hf_qsig_procedure);
}


static const value_string qsig_BasicService_vals[] = {
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
dissect_qsig_BasicService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_basicService(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_BasicService(FALSE, tvb, offset, pinfo, tree, hf_qsig_basicService);
}


static const value_string qsig_ADExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t ADExtension_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_ADExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ADExtension_choice, hf_index, ett_qsig_ADExtension,
                                 NULL);

  return offset;
}
static int dissect_extensionAD(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_ADExtension(FALSE, tvb, offset, pinfo, tree, hf_qsig_extensionAD);
}


static const ber_sequence_t ActivateDivArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_procedure },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_basicService },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_divertedToAddress },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_servedUserNr },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_activatingUserNr },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extensionAD },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_ActivateDivArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ActivateDivArg_sequence, hf_index, ett_qsig_ActivateDivArg);

  return offset;
}


static const value_string qsig_ActivateDivRes_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t ActivateDivRes_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_null },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_ActivateDivRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ActivateDivRes_choice, hf_index, ett_qsig_ActivateDivRes,
                                 NULL);

  return offset;
}


static const value_string qsig_DDExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t DDExtension_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_DDExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DDExtension_choice, hf_index, ett_qsig_DDExtension,
                                 NULL);

  return offset;
}
static int dissect_extensionDD(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_DDExtension(FALSE, tvb, offset, pinfo, tree, hf_qsig_extensionDD);
}


static const ber_sequence_t DeactivateDivArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_procedure },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_basicService },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_servedUserNr },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_deactivatingUserNr },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extensionDD },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_DeactivateDivArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DeactivateDivArg_sequence, hf_index, ett_qsig_DeactivateDivArg);

  return offset;
}


static const value_string qsig_DeactivateDivRes_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t DeactivateDivRes_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_null },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_DeactivateDivRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DeactivateDivRes_choice, hf_index, ett_qsig_DeactivateDivRes,
                                 NULL);

  return offset;
}


static const value_string qsig_IDExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t IDExtension_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_IDExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 IDExtension_choice, hf_index, ett_qsig_IDExtension,
                                 NULL);

  return offset;
}
static int dissect_extensionID(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_IDExtension(FALSE, tvb, offset, pinfo, tree, hf_qsig_extensionID);
}


static const ber_sequence_t InterrDivArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_procedure },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_basicService },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_servedUserNr },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_interrogatingUserNr },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extensionID },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_InterrDivArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   InterrDivArg_sequence, hf_index, ett_qsig_InterrDivArg);

  return offset;
}


static const value_string qsig_CHRExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t CHRExtension_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_CHRExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CHRExtension_choice, hf_index, ett_qsig_CHRExtension,
                                 NULL);

  return offset;
}
static int dissect_extensionCHR(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_CHRExtension(FALSE, tvb, offset, pinfo, tree, hf_qsig_extensionCHR);
}


static const ber_sequence_t ChkResArg_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_servedUserNr },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_basicService },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_divertedToNr },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extensionCHR },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_ChkResArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ChkResArg_sequence, hf_index, ett_qsig_ChkResArg);

  return offset;
}


static const value_string qsig_ChkResRes_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t ChkResRes_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_null },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_ChkResRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ChkResRes_choice, hf_index, ett_qsig_ChkResRes,
                                 NULL);

  return offset;
}


static const value_string qsig_DiversionReason_vals[] = {
  {   0, "unknown" },
  {   1, "cfu" },
  {   2, "cfb" },
  {   3, "cfnr" },
  { 0, NULL }
};


static int
dissect_qsig_DiversionReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_rerouteingReason(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_DiversionReason(FALSE, tvb, offset, pinfo, tree, hf_qsig_rerouteingReason);
}
static int dissect_originalRerouteingReason_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_DiversionReason(TRUE, tvb, offset, pinfo, tree, hf_qsig_originalRerouteingReason);
}
static int dissect_diversionReason(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_DiversionReason(FALSE, tvb, offset, pinfo, tree, hf_qsig_diversionReason);
}
static int dissect_originalDiversionReason_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_DiversionReason(TRUE, tvb, offset, pinfo, tree, hf_qsig_originalDiversionReason);
}



static int
dissect_qsig_INTEGER_1_15(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_diversionCounter(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_INTEGER_1_15(FALSE, tvb, offset, pinfo, tree, hf_qsig_diversionCounter);
}


static const value_string qsig_SubscriptionOption_vals[] = {
  {   0, "noNotification" },
  {   1, "notificationWithoutDivertedToNr" },
  {   2, "notificationWithDivertedToNr" },
  { 0, NULL }
};


static int
dissect_qsig_SubscriptionOption(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_subscriptionOption(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_SubscriptionOption(FALSE, tvb, offset, pinfo, tree, hf_qsig_subscriptionOption);
}
static int dissect_subscriptionOption_impl(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_SubscriptionOption(TRUE, tvb, offset, pinfo, tree, hf_qsig_subscriptionOption);
}


static const value_string qsig_CRRExtension_vals[] = {
  {   9, "single" },
  {  10, "multiple" },
  { 0, NULL }
};

static const ber_choice_t CRRExtension_choice[] = {
  {   9, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {  10, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_CRRExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CRRExtension_choice, hf_index, ett_qsig_CRRExtension,
                                 NULL);

  return offset;
}
static int dissect_extensionCRR(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_CRRExtension(FALSE, tvb, offset, pinfo, tree, hf_qsig_extensionCRR);
}


static const ber_sequence_t CallRrArg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_rerouteingReason },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalRerouteingReason_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_calledAddress },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_diversionCounter },
  { BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_pSS1InfoElement },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_lastRerouteingNr },
  { BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_subscriptionOption_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_callingPartySubaddress },
  { BER_CLASS_CON, 4, BER_FLAGS_NOTCHKTAG, dissect_callingNumber },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_callingName },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_originalCalledNr },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_redirectingName },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_originalCalledName },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extensionCRR },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_CallRrArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CallRrArg_sequence, hf_index, ett_qsig_CallRrArg);

  return offset;
}


static const value_string qsig_CallRrRes_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t CallRrRes_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_null },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_CallRrRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CallRrRes_choice, hf_index, ett_qsig_CallRrRes,
                                 NULL);

  return offset;
}


static const value_string qsig_DLI1Extension_vals[] = {
  {   9, "single" },
  {  10, "multiple" },
  { 0, NULL }
};

static const ber_choice_t DLI1Extension_choice[] = {
  {   9, BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {  10, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_DLI1Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DLI1Extension_choice, hf_index, ett_qsig_DLI1Extension,
                                 NULL);

  return offset;
}
static int dissect_extensionDLI1(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_DLI1Extension(FALSE, tvb, offset, pinfo, tree, hf_qsig_extensionDLI1);
}


static const ber_sequence_t DivLegInf1Arg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_diversionReason },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_subscriptionOption },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_nominatedNr },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extensionDLI1 },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_DivLegInf1Arg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DivLegInf1Arg_sequence, hf_index, ett_qsig_DivLegInf1Arg);

  return offset;
}


static const value_string qsig_DLI2Extension_vals[] = {
  {   5, "single" },
  {   6, "multiple" },
  { 0, NULL }
};

static const ber_choice_t DLI2Extension_choice[] = {
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {   6, BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_DLI2Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DLI2Extension_choice, hf_index, ett_qsig_DLI2Extension,
                                 NULL);

  return offset;
}
static int dissect_extensionDLI2(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_DLI2Extension(FALSE, tvb, offset, pinfo, tree, hf_qsig_extensionDLI2);
}


static const ber_sequence_t DivLegInf2Arg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_diversionCounter },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_diversionReason },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originalDiversionReason_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_divertingNr },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_originalCalledNr },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_redirectingName },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_originalCalledName },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extensionDLI2 },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_DivLegInf2Arg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DivLegInf2Arg_sequence, hf_index, ett_qsig_DivLegInf2Arg);

  return offset;
}


static const value_string qsig_DLI3Extension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t DLI3Extension_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_DLI3Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DLI3Extension_choice, hf_index, ett_qsig_DLI3Extension,
                                 NULL);

  return offset;
}
static int dissect_extensionDLI3(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_DLI3Extension(FALSE, tvb, offset, pinfo, tree, hf_qsig_extensionDLI3);
}


static const ber_sequence_t DivLegInf3Arg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_presentationAllowedIndicator },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_redirectionName },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extensionDLI3 },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_DivLegInf3Arg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DivLegInf3Arg_sequence, hf_index, ett_qsig_DivLegInf3Arg);

  return offset;
}


static const value_string qsig_DivLegFailArg_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t DivLegFailArg_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_null },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_DivLegFailArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 DivLegFailArg_choice, hf_index, ett_qsig_DivLegFailArg,
                                 NULL);

  return offset;
}


static const value_string qsig_IRExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t IRExtension_choice[] = {
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_single_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_multiple_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_qsig_IRExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 IRExtension_choice, hf_index, ett_qsig_IRExtension,
                                 NULL);

  return offset;
}
static int dissect_extensionIR(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_IRExtension(FALSE, tvb, offset, pinfo, tree, hf_qsig_extensionIR);
}


static const ber_sequence_t IntResult_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_servedUserNr },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_basicService },
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_procedure },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_divertedToAddress },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_remoteEnabled },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_extensionIR },
  { 0, 0, 0, NULL }
};

static int
dissect_qsig_IntResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   IntResult_sequence, hf_index, ett_qsig_IntResult);

  return offset;
}
static int dissect_IntResultList_item(packet_info *pinfo _U_, proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_) {
  return dissect_qsig_IntResult(FALSE, tvb, offset, pinfo, tree, hf_qsig_IntResultList_item);
}


static const ber_sequence_t IntResultList_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_IntResultList_item },
};

static int
dissect_qsig_IntResultList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, packet_info *pinfo _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 IntResultList_set_of, hf_index, ett_qsig_IntResultList);

  return offset;
}

/*--- PDUs ---*/

static void dissect_NameArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_NameArg(FALSE, tvb, offset, pinfo, tree, hf_qsig_NameArg_PDU);
}
static void dissect_ActivateDivArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_ActivateDivArg(FALSE, tvb, offset, pinfo, tree, hf_qsig_ActivateDivArg_PDU);
}
static void dissect_ActivateDivRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_ActivateDivRes(FALSE, tvb, offset, pinfo, tree, hf_qsig_ActivateDivRes_PDU);
}
static void dissect_DeactivateDivArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_DeactivateDivArg(FALSE, tvb, offset, pinfo, tree, hf_qsig_DeactivateDivArg_PDU);
}
static void dissect_DeactivateDivRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_DeactivateDivRes(FALSE, tvb, offset, pinfo, tree, hf_qsig_DeactivateDivRes_PDU);
}
static void dissect_InterrDivArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_InterrDivArg(FALSE, tvb, offset, pinfo, tree, hf_qsig_InterrDivArg_PDU);
}
static void dissect_ChkResArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_ChkResArg(FALSE, tvb, offset, pinfo, tree, hf_qsig_ChkResArg_PDU);
}
static void dissect_ChkResRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_ChkResRes(FALSE, tvb, offset, pinfo, tree, hf_qsig_ChkResRes_PDU);
}
static void dissect_CallRrArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_CallRrArg(FALSE, tvb, offset, pinfo, tree, hf_qsig_CallRrArg_PDU);
}
static void dissect_CallRrRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_CallRrRes(FALSE, tvb, offset, pinfo, tree, hf_qsig_CallRrRes_PDU);
}
static void dissect_DivLegInf1Arg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_DivLegInf1Arg(FALSE, tvb, offset, pinfo, tree, hf_qsig_DivLegInf1Arg_PDU);
}
static void dissect_DivLegInf2Arg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_DivLegInf2Arg(FALSE, tvb, offset, pinfo, tree, hf_qsig_DivLegInf2Arg_PDU);
}
static void dissect_DivLegInf3Arg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_DivLegInf3Arg(FALSE, tvb, offset, pinfo, tree, hf_qsig_DivLegInf3Arg_PDU);
}
static void dissect_DivLegFailArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_DivLegFailArg(FALSE, tvb, offset, pinfo, tree, hf_qsig_DivLegFailArg_PDU);
}
static void dissect_IntResultList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  offset = dissect_qsig_IntResultList(FALSE, tvb, offset, pinfo, tree, hf_qsig_IntResultList_PDU);
}


/*--- End of included file: packet-qsig-fn.c ---*/
#line 482 "packet-qsig-template.c"


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
  /*  24 */ { NO_SRV,     NULL,     NULL, NULL, NULL },
  /*  25 */ { NO_SRV,     NULL,     NULL, NULL, NULL },
  /*  26 */ { NO_SRV,     NULL,     NULL, NULL, NULL },
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
  /*  83 */ { NO_SRV,     NULL,     NULL, NULL, NULL },
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
  if (qsig_tab[operation].service != NO_SRV) {
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
  if (qsig_tab[operation].service != NO_SRV) {
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
dissect_qsig_transit_counter_ie(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int length  _U_) {
  proto_tree_add_item(tree, hf_qsig_tc, tvb, offset, 1, FALSE);
  offset++;
  return offset;
}
/*--- dissect_qsig_party_category_ie ----------------------------------------*/
static int 
dissect_qsig_party_category_ie(tvbuff_t *tvb, int offset, packet_info *pinfo  _U_, proto_tree *tree, int length  _U_) {
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

/*--- Included file: packet-qsig-hfarr.c ---*/
#line 1 "packet-qsig-hfarr.c"
    { &hf_qsig_NameArg_PDU,
      { "NameArg", "qsig.NameArg",
        FT_UINT32, BASE_DEC, VALS(qsig_NameArg_vals), 0,
        "qsig.NameArg", HFILL }},
    { &hf_qsig_ActivateDivArg_PDU,
      { "ActivateDivArg", "qsig.ActivateDivArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.ActivateDivArg", HFILL }},
    { &hf_qsig_ActivateDivRes_PDU,
      { "ActivateDivRes", "qsig.ActivateDivRes",
        FT_UINT32, BASE_DEC, VALS(qsig_ActivateDivRes_vals), 0,
        "qsig.ActivateDivRes", HFILL }},
    { &hf_qsig_DeactivateDivArg_PDU,
      { "DeactivateDivArg", "qsig.DeactivateDivArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.DeactivateDivArg", HFILL }},
    { &hf_qsig_DeactivateDivRes_PDU,
      { "DeactivateDivRes", "qsig.DeactivateDivRes",
        FT_UINT32, BASE_DEC, VALS(qsig_DeactivateDivRes_vals), 0,
        "qsig.DeactivateDivRes", HFILL }},
    { &hf_qsig_InterrDivArg_PDU,
      { "InterrDivArg", "qsig.InterrDivArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.InterrDivArg", HFILL }},
    { &hf_qsig_ChkResArg_PDU,
      { "ChkResArg", "qsig.ChkResArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.ChkResArg", HFILL }},
    { &hf_qsig_ChkResRes_PDU,
      { "ChkResRes", "qsig.ChkResRes",
        FT_UINT32, BASE_DEC, VALS(qsig_ChkResRes_vals), 0,
        "qsig.ChkResRes", HFILL }},
    { &hf_qsig_CallRrArg_PDU,
      { "CallRrArg", "qsig.CallRrArg",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.CallRrArg", HFILL }},
    { &hf_qsig_CallRrRes_PDU,
      { "CallRrRes", "qsig.CallRrRes",
        FT_UINT32, BASE_DEC, VALS(qsig_CallRrRes_vals), 0,
        "qsig.CallRrRes", HFILL }},
    { &hf_qsig_DivLegInf1Arg_PDU,
      { "DivLegInf1Arg", "qsig.DivLegInf1Arg",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.DivLegInf1Arg", HFILL }},
    { &hf_qsig_DivLegInf2Arg_PDU,
      { "DivLegInf2Arg", "qsig.DivLegInf2Arg",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.DivLegInf2Arg", HFILL }},
    { &hf_qsig_DivLegInf3Arg_PDU,
      { "DivLegInf3Arg", "qsig.DivLegInf3Arg",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.DivLegInf3Arg", HFILL }},
    { &hf_qsig_DivLegFailArg_PDU,
      { "DivLegFailArg", "qsig.DivLegFailArg",
        FT_UINT32, BASE_DEC, VALS(qsig_DivLegFailArg_vals), 0,
        "qsig.DivLegFailArg", HFILL }},
    { &hf_qsig_IntResultList_PDU,
      { "IntResultList", "qsig.IntResultList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "qsig.IntResultList", HFILL }},
    { &hf_qsig_extensionId,
      { "extensionId", "qsig.extensionId",
        FT_OID, BASE_NONE, NULL, 0,
        "qsig.OBJECT_IDENTIFIER", HFILL }},
    { &hf_qsig_extensionArgument,
      { "extensionArgument", "qsig.extensionArgument",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.T_extensionArgument", HFILL }},
    { &hf_qsig_presentationAllowedAddressS,
      { "presentationAllowedAddressS", "qsig.presentationAllowedAddressS",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.AddressScreened", HFILL }},
    { &hf_qsig_presentationRestricted,
      { "presentationRestricted", "qsig.presentationRestricted",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.NULL", HFILL }},
    { &hf_qsig_numberNotAvailableDueToInterworking,
      { "numberNotAvailableDueToInterworking", "qsig.numberNotAvailableDueToInterworking",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.NULL", HFILL }},
    { &hf_qsig_presentationRestrictedAddressS,
      { "presentationRestrictedAddressS", "qsig.presentationRestrictedAddressS",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.AddressScreened", HFILL }},
    { &hf_qsig_presentationAllowedAddressU,
      { "presentationAllowedAddressU", "qsig.presentationAllowedAddressU",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.Address", HFILL }},
    { &hf_qsig_presentationRestrictedAddressU,
      { "presentationRestrictedAddressU", "qsig.presentationRestrictedAddressU",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.Address", HFILL }},
    { &hf_qsig_presentationAllowedAddressNS,
      { "presentationAllowedAddressNS", "qsig.presentationAllowedAddressNS",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.NumberScreened", HFILL }},
    { &hf_qsig_presentationRestrictedAddressNS,
      { "presentationRestrictedAddressNS", "qsig.presentationRestrictedAddressNS",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.NumberScreened", HFILL }},
    { &hf_qsig_presentationAllowedAddressNU,
      { "presentationAllowedAddressNU", "qsig.presentationAllowedAddressNU",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "qsig.PartyNumber", HFILL }},
    { &hf_qsig_presentationRestrictedAddressNU,
      { "presentationRestrictedAddressNU", "qsig.presentationRestrictedAddressNU",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "qsig.PartyNumber", HFILL }},
    { &hf_qsig_partyNumber,
      { "partyNumber", "qsig.partyNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "qsig.PartyNumber", HFILL }},
    { &hf_qsig_screeningIndicator,
      { "screeningIndicator", "qsig.screeningIndicator",
        FT_UINT32, BASE_DEC, VALS(qsig_ScreeningIndicator_vals), 0,
        "qsig.ScreeningIndicator", HFILL }},
    { &hf_qsig_partySubaddress,
      { "partySubaddress", "qsig.partySubaddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PartySubaddress_vals), 0,
        "qsig.PartySubaddress", HFILL }},
    { &hf_qsig_unknownPartyNumber,
      { "unknownPartyNumber", "qsig.unknownPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "qsig.NumberDigits", HFILL }},
    { &hf_qsig_publicPartyNumber,
      { "publicPartyNumber", "qsig.publicPartyNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.PublicPartyNumber", HFILL }},
    { &hf_qsig_dataPartyNumber,
      { "dataPartyNumber", "qsig.dataPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "qsig.NumberDigits", HFILL }},
    { &hf_qsig_telexPartyNumber,
      { "telexPartyNumber", "qsig.telexPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "qsig.NumberDigits", HFILL }},
    { &hf_qsig_privatePartyNumber,
      { "privatePartyNumber", "qsig.privatePartyNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.PrivatePartyNumber", HFILL }},
    { &hf_qsig_nationalStandardPartyNumber,
      { "nationalStandardPartyNumber", "qsig.nationalStandardPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "qsig.NumberDigits", HFILL }},
    { &hf_qsig_publicTypeOfNumber,
      { "publicTypeOfNumber", "qsig.publicTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PublicTypeOfNumber_vals), 0,
        "qsig.PublicTypeOfNumber", HFILL }},
    { &hf_qsig_publicNumberDigits,
      { "publicNumberDigits", "qsig.publicNumberDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "qsig.NumberDigits", HFILL }},
    { &hf_qsig_privateTypeOfNumber,
      { "privateTypeOfNumber", "qsig.privateTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PrivateTypeOfNumber_vals), 0,
        "qsig.PrivateTypeOfNumber", HFILL }},
    { &hf_qsig_privateNumberDigits,
      { "privateNumberDigits", "qsig.privateNumberDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "qsig.NumberDigits", HFILL }},
    { &hf_qsig_userSpecifiedSubaddress,
      { "userSpecifiedSubaddress", "qsig.userSpecifiedSubaddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.UserSpecifiedSubaddress", HFILL }},
    { &hf_qsig_nSAPSubaddress,
      { "nSAPSubaddress", "qsig.nSAPSubaddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "qsig.NSAPSubaddress", HFILL }},
    { &hf_qsig_subaddressInformation,
      { "subaddressInformation", "qsig.subaddressInformation",
        FT_BYTES, BASE_HEX, NULL, 0,
        "qsig.SubaddressInformation", HFILL }},
    { &hf_qsig_oddCountIndicator,
      { "oddCountIndicator", "qsig.oddCountIndicator",
        FT_BOOLEAN, 8, NULL, 0,
        "qsig.BOOLEAN", HFILL }},
    { &hf_qsig_name,
      { "name", "qsig.name",
        FT_UINT32, BASE_DEC, VALS(qsig_Name_vals), 0,
        "qsig.Name", HFILL }},
    { &hf_qsig_nameSequence,
      { "nameSequence", "qsig.nameSequence",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.T_nameSequence", HFILL }},
    { &hf_qsig_extensionNA,
      { "extension", "qsig.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_NameExtension_vals), 0,
        "qsig.NameExtension", HFILL }},
    { &hf_qsig_single,
      { "single", "qsig.single",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.Extension", HFILL }},
    { &hf_qsig_multiple,
      { "multiple", "qsig.multiple",
        FT_UINT32, BASE_DEC, NULL, 0,
        "qsig.SEQUENCE_OF_Extension", HFILL }},
    { &hf_qsig_multiple_item,
      { "Item", "qsig.multiple_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.Extension", HFILL }},
    { &hf_qsig_namePresentationAllowed,
      { "namePresentationAllowed", "qsig.namePresentationAllowed",
        FT_UINT32, BASE_DEC, VALS(qsig_NamePresentationAllowed_vals), 0,
        "qsig.NamePresentationAllowed", HFILL }},
    { &hf_qsig_namePresentationRestricted,
      { "namePresentationRestricted", "qsig.namePresentationRestricted",
        FT_UINT32, BASE_DEC, VALS(qsig_NamePresentationRestricted_vals), 0,
        "qsig.NamePresentationRestricted", HFILL }},
    { &hf_qsig_nameNotAvailable,
      { "nameNotAvailable", "qsig.nameNotAvailable",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.NameNotAvailable", HFILL }},
    { &hf_qsig_namePresentationAllowedSimple,
      { "namePresentationAllowedSimple", "qsig.namePresentationAllowedSimple",
        FT_STRING, BASE_NONE, NULL, 0,
        "qsig.NameData", HFILL }},
    { &hf_qsig_namePresentationAllowedExtended,
      { "namePresentationAllowedExtended", "qsig.namePresentationAllowedExtended",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.NameSet", HFILL }},
    { &hf_qsig_namePresentationRestrictedSimple,
      { "namePresentationRestrictedSimple", "qsig.namePresentationRestrictedSimple",
        FT_STRING, BASE_NONE, NULL, 0,
        "qsig.NameData", HFILL }},
    { &hf_qsig_namePresentationRestrictedExtended,
      { "namePresentationRestrictedExtended", "qsig.namePresentationRestrictedExtended",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.NameSet", HFILL }},
    { &hf_qsig_namePresentationRestrictedNull,
      { "namePresentationRestrictedNull", "qsig.namePresentationRestrictedNull",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.NULL", HFILL }},
    { &hf_qsig_nameData,
      { "nameData", "qsig.nameData",
        FT_STRING, BASE_NONE, NULL, 0,
        "qsig.NameData", HFILL }},
    { &hf_qsig_characterSet,
      { "characterSet", "qsig.characterSet",
        FT_UINT32, BASE_DEC, VALS(qsig_CharacterSet_vals), 0,
        "qsig.CharacterSet", HFILL }},
    { &hf_qsig_procedure,
      { "procedure", "qsig.procedure",
        FT_UINT32, BASE_DEC, VALS(qsig_Procedure_vals), 0,
        "qsig.Procedure", HFILL }},
    { &hf_qsig_basicService,
      { "basicService", "qsig.basicService",
        FT_UINT32, BASE_DEC, VALS(qsig_BasicService_vals), 0,
        "qsig.BasicService", HFILL }},
    { &hf_qsig_divertedToAddress,
      { "divertedToAddress", "qsig.divertedToAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.Address", HFILL }},
    { &hf_qsig_servedUserNr,
      { "servedUserNr", "qsig.servedUserNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "qsig.PartyNumber", HFILL }},
    { &hf_qsig_activatingUserNr,
      { "activatingUserNr", "qsig.activatingUserNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "qsig.PartyNumber", HFILL }},
    { &hf_qsig_extensionAD,
      { "extension", "qsig.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_ADExtension_vals), 0,
        "qsig.ADExtension", HFILL }},
    { &hf_qsig_null,
      { "null", "qsig.null",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.NULL", HFILL }},
    { &hf_qsig_deactivatingUserNr,
      { "deactivatingUserNr", "qsig.deactivatingUserNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "qsig.PartyNumber", HFILL }},
    { &hf_qsig_extensionDD,
      { "extension", "qsig.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_DDExtension_vals), 0,
        "qsig.DDExtension", HFILL }},
    { &hf_qsig_interrogatingUserNr,
      { "interrogatingUserNr", "qsig.interrogatingUserNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "qsig.PartyNumber", HFILL }},
    { &hf_qsig_extensionID,
      { "extension", "qsig.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_IDExtension_vals), 0,
        "qsig.IDExtension", HFILL }},
    { &hf_qsig_divertedToNr,
      { "divertedToNr", "qsig.divertedToNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "qsig.PartyNumber", HFILL }},
    { &hf_qsig_extensionCHR,
      { "extension", "qsig.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_CHRExtension_vals), 0,
        "qsig.CHRExtension", HFILL }},
    { &hf_qsig_rerouteingReason,
      { "rerouteingReason", "qsig.rerouteingReason",
        FT_UINT32, BASE_DEC, VALS(qsig_DiversionReason_vals), 0,
        "qsig.DiversionReason", HFILL }},
    { &hf_qsig_originalRerouteingReason,
      { "originalRerouteingReason", "qsig.originalRerouteingReason",
        FT_UINT32, BASE_DEC, VALS(qsig_DiversionReason_vals), 0,
        "qsig.DiversionReason", HFILL }},
    { &hf_qsig_calledAddress,
      { "calledAddress", "qsig.calledAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.Address", HFILL }},
    { &hf_qsig_diversionCounter,
      { "diversionCounter", "qsig.diversionCounter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "qsig.INTEGER_1_15", HFILL }},
    { &hf_qsig_pSS1InfoElement,
      { "pSS1InfoElement", "qsig.pSS1InfoElement",
        FT_BYTES, BASE_HEX, NULL, 0,
        "qsig.PSS1InformationElement", HFILL }},
    { &hf_qsig_lastRerouteingNr,
      { "lastRerouteingNr", "qsig.lastRerouteingNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberUnscreened_vals), 0,
        "qsig.PresentedNumberUnscreened", HFILL }},
    { &hf_qsig_subscriptionOption,
      { "subscriptionOption", "qsig.subscriptionOption",
        FT_UINT32, BASE_DEC, VALS(qsig_SubscriptionOption_vals), 0,
        "qsig.SubscriptionOption", HFILL }},
    { &hf_qsig_callingPartySubaddress,
      { "callingPartySubaddress", "qsig.callingPartySubaddress",
        FT_UINT32, BASE_DEC, VALS(qsig_PartySubaddress_vals), 0,
        "qsig.PartySubaddress", HFILL }},
    { &hf_qsig_callingNumber,
      { "callingNumber", "qsig.callingNumber",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberScreened_vals), 0,
        "qsig.PresentedNumberScreened", HFILL }},
    { &hf_qsig_callingName,
      { "callingName", "qsig.callingName",
        FT_UINT32, BASE_DEC, VALS(qsig_Name_vals), 0,
        "qsig.Name", HFILL }},
    { &hf_qsig_originalCalledNr,
      { "originalCalledNr", "qsig.originalCalledNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberUnscreened_vals), 0,
        "qsig.PresentedNumberUnscreened", HFILL }},
    { &hf_qsig_redirectingName,
      { "redirectingName", "qsig.redirectingName",
        FT_UINT32, BASE_DEC, VALS(qsig_Name_vals), 0,
        "qsig.Name", HFILL }},
    { &hf_qsig_originalCalledName,
      { "originalCalledName", "qsig.originalCalledName",
        FT_UINT32, BASE_DEC, VALS(qsig_Name_vals), 0,
        "qsig.Name", HFILL }},
    { &hf_qsig_extensionCRR,
      { "extension", "qsig.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_CRRExtension_vals), 0,
        "qsig.CRRExtension", HFILL }},
    { &hf_qsig_diversionReason,
      { "diversionReason", "qsig.diversionReason",
        FT_UINT32, BASE_DEC, VALS(qsig_DiversionReason_vals), 0,
        "qsig.DiversionReason", HFILL }},
    { &hf_qsig_nominatedNr,
      { "nominatedNr", "qsig.nominatedNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PartyNumber_vals), 0,
        "qsig.PartyNumber", HFILL }},
    { &hf_qsig_extensionDLI1,
      { "extension", "qsig.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_DLI1Extension_vals), 0,
        "qsig.DLI1Extension", HFILL }},
    { &hf_qsig_originalDiversionReason,
      { "originalDiversionReason", "qsig.originalDiversionReason",
        FT_UINT32, BASE_DEC, VALS(qsig_DiversionReason_vals), 0,
        "qsig.DiversionReason", HFILL }},
    { &hf_qsig_divertingNr,
      { "divertingNr", "qsig.divertingNr",
        FT_UINT32, BASE_DEC, VALS(qsig_PresentedNumberUnscreened_vals), 0,
        "qsig.PresentedNumberUnscreened", HFILL }},
    { &hf_qsig_extensionDLI2,
      { "extension", "qsig.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_DLI2Extension_vals), 0,
        "qsig.DLI2Extension", HFILL }},
    { &hf_qsig_presentationAllowedIndicator,
      { "presentationAllowedIndicator", "qsig.presentationAllowedIndicator",
        FT_BOOLEAN, 8, NULL, 0,
        "qsig.PresentationAllowedIndicator", HFILL }},
    { &hf_qsig_redirectionName,
      { "redirectionName", "qsig.redirectionName",
        FT_UINT32, BASE_DEC, VALS(qsig_Name_vals), 0,
        "qsig.Name", HFILL }},
    { &hf_qsig_extensionDLI3,
      { "extension", "qsig.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_DLI3Extension_vals), 0,
        "qsig.DLI3Extension", HFILL }},
    { &hf_qsig_IntResultList_item,
      { "Item", "qsig.IntResultList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.IntResult", HFILL }},
    { &hf_qsig_remoteEnabled,
      { "remoteEnabled", "qsig.remoteEnabled",
        FT_BOOLEAN, 8, NULL, 0,
        "qsig.BOOLEAN", HFILL }},
    { &hf_qsig_extensionIR,
      { "extension", "qsig.extension",
        FT_UINT32, BASE_DEC, VALS(qsig_IRExtension_vals), 0,
        "qsig.IRExtension", HFILL }},

/*--- End of included file: packet-qsig-hfarr.c ---*/
#line 766 "packet-qsig-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_qsig,
    &ett_qsig_ie,

/*--- Included file: packet-qsig-ettarr.c ---*/
#line 1 "packet-qsig-ettarr.c"
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
    &ett_qsig_NameArg,
    &ett_qsig_T_nameSequence,
    &ett_qsig_NameExtension,
    &ett_qsig_SEQUENCE_OF_Extension,
    &ett_qsig_Name,
    &ett_qsig_NamePresentationAllowed,
    &ett_qsig_NamePresentationRestricted,
    &ett_qsig_NameSet,
    &ett_qsig_ActivateDivArg,
    &ett_qsig_ADExtension,
    &ett_qsig_ActivateDivRes,
    &ett_qsig_DeactivateDivArg,
    &ett_qsig_DDExtension,
    &ett_qsig_DeactivateDivRes,
    &ett_qsig_InterrDivArg,
    &ett_qsig_IDExtension,
    &ett_qsig_ChkResArg,
    &ett_qsig_CHRExtension,
    &ett_qsig_ChkResRes,
    &ett_qsig_CallRrArg,
    &ett_qsig_CRRExtension,
    &ett_qsig_CallRrRes,
    &ett_qsig_DivLegInf1Arg,
    &ett_qsig_DLI1Extension,
    &ett_qsig_DivLegInf2Arg,
    &ett_qsig_DLI2Extension,
    &ett_qsig_DivLegInf3Arg,
    &ett_qsig_DLI3Extension,
    &ett_qsig_DivLegFailArg,
    &ett_qsig_IntResultList,
    &ett_qsig_IntResult,
    &ett_qsig_IRExtension,

/*--- End of included file: packet-qsig-ettarr.c ---*/
#line 773 "packet-qsig-template.c"
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
