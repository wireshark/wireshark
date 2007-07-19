/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-qsig.c                                                            */
/* ../../tools/asn2wrs.py -b -T -X -e -p qsig -c qsig.cnf -s packet-qsig-template qsig-gf-ext.asn qsig-gf-gp.asn qsig-gf-ade.asn qsig-na.asn qsig-cf.asn */

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
                     
typedef struct _qsig_op_t {
  gint32 opcode;
  new_dissector_t arg_pdu;
  new_dissector_t res_pdu;
} qsig_op_t;

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
static int hf_qsig_ARG_activateDiversionQ_PDU = -1;  /* ARG_activateDiversionQ */
static int hf_qsig_RES_activateDiversionQ_PDU = -1;  /* RES_activateDiversionQ */
static int hf_qsig_ARG_deactivateDiversionQ_PDU = -1;  /* ARG_deactivateDiversionQ */
static int hf_qsig_RES_deactivateDiversionQ_PDU = -1;  /* RES_deactivateDiversionQ */
static int hf_qsig_ARG_interrogateDiversionQ_PDU = -1;  /* ARG_interrogateDiversionQ */
static int hf_qsig_IntResultList_PDU = -1;        /* IntResultList */
static int hf_qsig_ARG_checkRestriction_PDU = -1;  /* ARG_checkRestriction */
static int hf_qsig_RES_checkRestriction_PDU = -1;  /* RES_checkRestriction */
static int hf_qsig_ARG_callRerouteing_PDU = -1;   /* ARG_callRerouteing */
static int hf_qsig_RES_callRerouteing_PDU = -1;   /* RES_callRerouteing */
static int hf_qsig_ARG_divertingLegInformation1_PDU = -1;  /* ARG_divertingLegInformation1 */
static int hf_qsig_ARG_divertingLegInformation2_PDU = -1;  /* ARG_divertingLegInformation2 */
static int hf_qsig_ARG_divertingLegInformation3_PDU = -1;  /* ARG_divertingLegInformation3 */
static int hf_qsig_ARG_cfnrDivertedLegFailed_PDU = -1;  /* ARG_cfnrDivertedLegFailed */
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
#line 415 "packet-qsig-template.c"

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
static gint ett_qsig_ARG_activateDiversionQ = -1;
static gint ett_qsig_ADExtension = -1;
static gint ett_qsig_RES_activateDiversionQ = -1;
static gint ett_qsig_ARG_deactivateDiversionQ = -1;
static gint ett_qsig_DDExtension = -1;
static gint ett_qsig_RES_deactivateDiversionQ = -1;
static gint ett_qsig_ARG_interrogateDiversionQ = -1;
static gint ett_qsig_IDExtension = -1;
static gint ett_qsig_ARG_checkRestriction = -1;
static gint ett_qsig_CHRExtension = -1;
static gint ett_qsig_RES_checkRestriction = -1;
static gint ett_qsig_ARG_callRerouteing = -1;
static gint ett_qsig_CRRExtension = -1;
static gint ett_qsig_RES_callRerouteing = -1;
static gint ett_qsig_ARG_divertingLegInformation1 = -1;
static gint ett_qsig_DLI1Extension = -1;
static gint ett_qsig_ARG_divertingLegInformation2 = -1;
static gint ett_qsig_DLI2Extension = -1;
static gint ett_qsig_ARG_divertingLegInformation3 = -1;
static gint ett_qsig_DLI3Extension = -1;
static gint ett_qsig_ARG_cfnrDivertedLegFailed = -1;
static gint ett_qsig_IntResultList = -1;
static gint ett_qsig_IntResult = -1;
static gint ett_qsig_IRExtension = -1;

/*--- End of included file: packet-qsig-ett.c ---*/
#line 431 "packet-qsig-template.c"

/* Preferences */

/* Subdissectors */
static dissector_handle_t data_handle = NULL; 

/* Gloabl variables */



/*--- Included file: packet-qsig-fn.c ---*/
#line 1 "packet-qsig-fn.c"


static int
dissect_qsig_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_qsig_T_extensionArgument(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 50 "qsig.cnf"



  return offset;
}


static const ber_sequence_t Extension_sequence[] = {
  { &hf_qsig_extensionId    , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_qsig_OBJECT_IDENTIFIER },
  { &hf_qsig_extensionArgument, BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_qsig_T_extensionArgument },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Extension_sequence, hf_index, ett_qsig_Extension);

  return offset;
}



static int
dissect_qsig_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_qsig_PSS1InformationElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, TRUE, dissect_qsig_OCTET_STRING);

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


static const ber_sequence_t PublicPartyNumber_sequence[] = {
  { &hf_qsig_publicTypeOfNumber, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_PublicTypeOfNumber },
  { &hf_qsig_publicNumberDigits, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_qsig_NumberDigits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PublicPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PublicPartyNumber_sequence, hf_index, ett_qsig_PublicPartyNumber);

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


static const ber_sequence_t PrivatePartyNumber_sequence[] = {
  { &hf_qsig_privateTypeOfNumber, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_PrivateTypeOfNumber },
  { &hf_qsig_privateNumberDigits, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_qsig_NumberDigits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PrivatePartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrivatePartyNumber_sequence, hf_index, ett_qsig_PrivatePartyNumber);

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

static const ber_choice_t PartyNumber_choice[] = {
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
                                 PartyNumber_choice, hf_index, ett_qsig_PartyNumber,
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
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t UserSpecifiedSubaddress_sequence[] = {
  { &hf_qsig_subaddressInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_SubaddressInformation },
  { &hf_qsig_oddCountIndicator, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_UserSpecifiedSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UserSpecifiedSubaddress_sequence, hf_index, ett_qsig_UserSpecifiedSubaddress);

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

static const ber_choice_t PartySubaddress_choice[] = {
  {   0, &hf_qsig_userSpecifiedSubaddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_UserSpecifiedSubaddress },
  {   1, &hf_qsig_nSAPSubaddress , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_NSAPSubaddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PartySubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PartySubaddress_choice, hf_index, ett_qsig_PartySubaddress,
                                 NULL);

  return offset;
}


static const ber_sequence_t AddressScreened_sequence[] = {
  { &hf_qsig_partyNumber    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_screeningIndicator, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_ScreeningIndicator },
  { &hf_qsig_partySubaddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartySubaddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_AddressScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AddressScreened_sequence, hf_index, ett_qsig_AddressScreened);

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

static const ber_choice_t PresentedAddressScreened_choice[] = {
  {   0, &hf_qsig_presentationAllowedAddressS, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_AddressScreened },
  {   1, &hf_qsig_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   2, &hf_qsig_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   3, &hf_qsig_presentationRestrictedAddressS, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_AddressScreened },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PresentedAddressScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PresentedAddressScreened_choice, hf_index, ett_qsig_PresentedAddressScreened,
                                 NULL);

  return offset;
}


static const ber_sequence_t Address_sequence[] = {
  { &hf_qsig_partyNumber    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_partySubaddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartySubaddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Address_sequence, hf_index, ett_qsig_Address);

  return offset;
}


static const value_string qsig_PresentedAddressUnscreened_vals[] = {
  {   0, "presentationAllowedAddressU" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddressU" },
  { 0, NULL }
};

static const ber_choice_t PresentedAddressUnscreened_choice[] = {
  {   0, &hf_qsig_presentationAllowedAddressU, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_Address },
  {   1, &hf_qsig_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   2, &hf_qsig_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   3, &hf_qsig_presentationRestrictedAddressU, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_Address },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PresentedAddressUnscreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PresentedAddressUnscreened_choice, hf_index, ett_qsig_PresentedAddressUnscreened,
                                 NULL);

  return offset;
}


static const ber_sequence_t NumberScreened_sequence[] = {
  { &hf_qsig_partyNumber    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_screeningIndicator, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_ScreeningIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_NumberScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NumberScreened_sequence, hf_index, ett_qsig_NumberScreened);

  return offset;
}


static const value_string qsig_PresentedNumberScreened_vals[] = {
  {   0, "presentationAllowedAddressNS" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddressNS" },
  { 0, NULL }
};

static const ber_choice_t PresentedNumberScreened_choice[] = {
  {   0, &hf_qsig_presentationAllowedAddressNS, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_NumberScreened },
  {   1, &hf_qsig_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   2, &hf_qsig_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   3, &hf_qsig_presentationRestrictedAddressNS, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_NumberScreened },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PresentedNumberScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PresentedNumberScreened_choice, hf_index, ett_qsig_PresentedNumberScreened,
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

static const ber_choice_t PresentedNumberUnscreened_choice[] = {
  {   0, &hf_qsig_presentationAllowedAddressNU, BER_CLASS_CON, 0, 0, dissect_qsig_PartyNumber },
  {   1, &hf_qsig_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   2, &hf_qsig_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  {   3, &hf_qsig_presentationRestrictedAddressNU, BER_CLASS_CON, 3, 0, dissect_qsig_PartyNumber },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_PresentedNumberUnscreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PresentedNumberUnscreened_choice, hf_index, ett_qsig_PresentedNumberUnscreened,
                                 NULL);

  return offset;
}



static int
dissect_qsig_PresentationAllowedIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_qsig_NameData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
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
dissect_qsig_CharacterSet(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t NameSet_sequence[] = {
  { &hf_qsig_nameData       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_qsig_NameData },
  { &hf_qsig_characterSet   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_CharacterSet },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_NameSet(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NameSet_sequence, hf_index, ett_qsig_NameSet);

  return offset;
}


static const value_string qsig_NamePresentationAllowed_vals[] = {
  {   0, "namePresentationAllowedSimple" },
  {   1, "namePresentationAllowedExtended" },
  { 0, NULL }
};

static const ber_choice_t NamePresentationAllowed_choice[] = {
  {   0, &hf_qsig_namePresentationAllowedSimple, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_qsig_NameData },
  {   1, &hf_qsig_namePresentationAllowedExtended, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_NameSet },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_NamePresentationAllowed(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 NamePresentationAllowed_choice, hf_index, ett_qsig_NamePresentationAllowed,
                                 NULL);

  return offset;
}


static const value_string qsig_NamePresentationRestricted_vals[] = {
  {   2, "namePresentationRestrictedSimple" },
  {   3, "namePresentationRestrictedExtended" },
  {   7, "namePresentationRestrictedNull" },
  { 0, NULL }
};

static const ber_choice_t NamePresentationRestricted_choice[] = {
  {   2, &hf_qsig_namePresentationRestrictedSimple, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_NameData },
  {   3, &hf_qsig_namePresentationRestrictedExtended, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_qsig_NameSet },
  {   7, &hf_qsig_namePresentationRestrictedNull, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_qsig_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_NamePresentationRestricted(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 NamePresentationRestricted_choice, hf_index, ett_qsig_NamePresentationRestricted,
                                 NULL);

  return offset;
}



static int
dissect_qsig_NameNotAvailable(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 4, TRUE, dissect_qsig_NULL);

  return offset;
}


static const ber_choice_t Name_choice[] = {
  {   0, &hf_qsig_namePresentationAllowed, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_NamePresentationAllowed },
  {   1, &hf_qsig_namePresentationRestricted, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_NamePresentationRestricted },
  {   2, &hf_qsig_nameNotAvailable, BER_CLASS_CON, 4, BER_FLAGS_NOOWNTAG, dissect_qsig_NameNotAvailable },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_qsig_Name(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Name_choice, hf_index, ett_qsig_Name,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Extension_sequence_of[1] = {
  { &hf_qsig_multiple_item  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Extension },
};

static int
dissect_qsig_SEQUENCE_OF_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Extension_sequence_of, hf_index, ett_qsig_SEQUENCE_OF_Extension);

  return offset;
}


static const value_string qsig_NameExtension_vals[] = {
  {   5, "single" },
  {   6, "multiple" },
  { 0, NULL }
};

static const ber_choice_t NameExtension_choice[] = {
  {   5, &hf_qsig_single         , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   6, &hf_qsig_multiple       , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_NameExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 NameExtension_choice, hf_index, ett_qsig_NameExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_nameSequence_sequence[] = {
  { &hf_qsig_name           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_Name },
  { &hf_qsig_extensionNA    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_NameExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_T_nameSequence(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_nameSequence_sequence, hf_index, ett_qsig_T_nameSequence);

  return offset;
}


static const value_string qsig_NameArg_vals[] = {
  {   0, "name" },
  {   1, "nameSequence" },
  { 0, NULL }
};

static const ber_choice_t NameArg_choice[] = {
  {   0, &hf_qsig_name           , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_qsig_Name },
  {   1, &hf_qsig_nameSequence   , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_T_nameSequence },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_NameArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
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
dissect_qsig_Procedure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
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
dissect_qsig_BasicService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_ADExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t ADExtension_choice[] = {
  {   1, &hf_qsig_single         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_multiple       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ADExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ADExtension_choice, hf_index, ett_qsig_ADExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t ARG_activateDiversionQ_sequence[] = {
  { &hf_qsig_procedure      , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_Procedure },
  { &hf_qsig_basicService   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_BasicService },
  { &hf_qsig_divertedToAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Address },
  { &hf_qsig_servedUserNr   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_activatingUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_extensionAD    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_ADExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ARG_activateDiversionQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ARG_activateDiversionQ_sequence, hf_index, ett_qsig_ARG_activateDiversionQ);

  return offset;
}


static const value_string qsig_RES_activateDiversionQ_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t RES_activateDiversionQ_choice[] = {
  {   0, &hf_qsig_null           , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_NULL },
  {   1, &hf_qsig_single         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_multiple       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_RES_activateDiversionQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RES_activateDiversionQ_choice, hf_index, ett_qsig_RES_activateDiversionQ,
                                 NULL);

  return offset;
}


static const value_string qsig_DDExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t DDExtension_choice[] = {
  {   1, &hf_qsig_single         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_multiple       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_DDExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DDExtension_choice, hf_index, ett_qsig_DDExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t ARG_deactivateDiversionQ_sequence[] = {
  { &hf_qsig_procedure      , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_Procedure },
  { &hf_qsig_basicService   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_BasicService },
  { &hf_qsig_servedUserNr   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_deactivatingUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_extensionDD    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_DDExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ARG_deactivateDiversionQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ARG_deactivateDiversionQ_sequence, hf_index, ett_qsig_ARG_deactivateDiversionQ);

  return offset;
}


static const value_string qsig_RES_deactivateDiversionQ_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t RES_deactivateDiversionQ_choice[] = {
  {   0, &hf_qsig_null           , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_NULL },
  {   1, &hf_qsig_single         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_multiple       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_RES_deactivateDiversionQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RES_deactivateDiversionQ_choice, hf_index, ett_qsig_RES_deactivateDiversionQ,
                                 NULL);

  return offset;
}


static const value_string qsig_IDExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t IDExtension_choice[] = {
  {   1, &hf_qsig_single         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_multiple       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_IDExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IDExtension_choice, hf_index, ett_qsig_IDExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t ARG_interrogateDiversionQ_sequence[] = {
  { &hf_qsig_procedure      , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_Procedure },
  { &hf_qsig_basicService   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_BasicService },
  { &hf_qsig_servedUserNr   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_interrogatingUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_extensionID    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_IDExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ARG_interrogateDiversionQ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ARG_interrogateDiversionQ_sequence, hf_index, ett_qsig_ARG_interrogateDiversionQ);

  return offset;
}


static const value_string qsig_CHRExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t CHRExtension_choice[] = {
  {   1, &hf_qsig_single         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_multiple       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_CHRExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CHRExtension_choice, hf_index, ett_qsig_CHRExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t ARG_checkRestriction_sequence[] = {
  { &hf_qsig_servedUserNr   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_basicService   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_BasicService },
  { &hf_qsig_divertedToNr   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_extensionCHR   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_CHRExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ARG_checkRestriction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ARG_checkRestriction_sequence, hf_index, ett_qsig_ARG_checkRestriction);

  return offset;
}


static const value_string qsig_RES_checkRestriction_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t RES_checkRestriction_choice[] = {
  {   0, &hf_qsig_null           , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_NULL },
  {   1, &hf_qsig_single         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_multiple       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_RES_checkRestriction(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RES_checkRestriction_choice, hf_index, ett_qsig_RES_checkRestriction,
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
dissect_qsig_DiversionReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_qsig_INTEGER_1_15(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_SubscriptionOption_vals[] = {
  {   0, "noNotification" },
  {   1, "notificationWithoutDivertedToNr" },
  {   2, "notificationWithDivertedToNr" },
  { 0, NULL }
};


static int
dissect_qsig_SubscriptionOption(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string qsig_CRRExtension_vals[] = {
  {   9, "single" },
  {  10, "multiple" },
  { 0, NULL }
};

static const ber_choice_t CRRExtension_choice[] = {
  {   9, &hf_qsig_single         , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {  10, &hf_qsig_multiple       , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_CRRExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CRRExtension_choice, hf_index, ett_qsig_CRRExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t ARG_callRerouteing_sequence[] = {
  { &hf_qsig_rerouteingReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_DiversionReason },
  { &hf_qsig_originalRerouteingReason, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_DiversionReason },
  { &hf_qsig_calledAddress  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Address },
  { &hf_qsig_diversionCounter, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_INTEGER_1_15 },
  { &hf_qsig_pSS1InfoElement, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_qsig_PSS1InformationElement },
  { &hf_qsig_lastRerouteingNr, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_qsig_PresentedNumberUnscreened },
  { &hf_qsig_subscriptionOption, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_SubscriptionOption },
  { &hf_qsig_callingPartySubaddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartySubaddress },
  { &hf_qsig_callingNumber  , BER_CLASS_CON, 4, BER_FLAGS_NOTCHKTAG, dissect_qsig_PresentedNumberScreened },
  { &hf_qsig_callingName    , BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_qsig_Name },
  { &hf_qsig_originalCalledNr, BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_qsig_PresentedNumberUnscreened },
  { &hf_qsig_redirectingName, BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_qsig_Name },
  { &hf_qsig_originalCalledName, BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_qsig_Name },
  { &hf_qsig_extensionCRR   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_CRRExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ARG_callRerouteing(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ARG_callRerouteing_sequence, hf_index, ett_qsig_ARG_callRerouteing);

  return offset;
}


static const value_string qsig_RES_callRerouteing_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t RES_callRerouteing_choice[] = {
  {   0, &hf_qsig_null           , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_NULL },
  {   1, &hf_qsig_single         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_multiple       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_RES_callRerouteing(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RES_callRerouteing_choice, hf_index, ett_qsig_RES_callRerouteing,
                                 NULL);

  return offset;
}


static const value_string qsig_DLI1Extension_vals[] = {
  {   9, "single" },
  {  10, "multiple" },
  { 0, NULL }
};

static const ber_choice_t DLI1Extension_choice[] = {
  {   9, &hf_qsig_single         , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {  10, &hf_qsig_multiple       , BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_DLI1Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DLI1Extension_choice, hf_index, ett_qsig_DLI1Extension,
                                 NULL);

  return offset;
}


static const ber_sequence_t ARG_divertingLegInformation1_sequence[] = {
  { &hf_qsig_diversionReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_DiversionReason },
  { &hf_qsig_subscriptionOption, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_SubscriptionOption },
  { &hf_qsig_nominatedNr    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_extensionDLI1  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_DLI1Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ARG_divertingLegInformation1(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ARG_divertingLegInformation1_sequence, hf_index, ett_qsig_ARG_divertingLegInformation1);

  return offset;
}


static const value_string qsig_DLI2Extension_vals[] = {
  {   5, "single" },
  {   6, "multiple" },
  { 0, NULL }
};

static const ber_choice_t DLI2Extension_choice[] = {
  {   5, &hf_qsig_single         , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   6, &hf_qsig_multiple       , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_DLI2Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DLI2Extension_choice, hf_index, ett_qsig_DLI2Extension,
                                 NULL);

  return offset;
}


static const ber_sequence_t ARG_divertingLegInformation2_sequence[] = {
  { &hf_qsig_diversionCounter, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_qsig_INTEGER_1_15 },
  { &hf_qsig_diversionReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_DiversionReason },
  { &hf_qsig_originalDiversionReason, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_qsig_DiversionReason },
  { &hf_qsig_divertingNr    , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_qsig_PresentedNumberUnscreened },
  { &hf_qsig_originalCalledNr, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_qsig_PresentedNumberUnscreened },
  { &hf_qsig_redirectingName, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_qsig_Name },
  { &hf_qsig_originalCalledName, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_qsig_Name },
  { &hf_qsig_extensionDLI2  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_DLI2Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ARG_divertingLegInformation2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ARG_divertingLegInformation2_sequence, hf_index, ett_qsig_ARG_divertingLegInformation2);

  return offset;
}


static const value_string qsig_DLI3Extension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t DLI3Extension_choice[] = {
  {   1, &hf_qsig_single         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_multiple       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_DLI3Extension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DLI3Extension_choice, hf_index, ett_qsig_DLI3Extension,
                                 NULL);

  return offset;
}


static const ber_sequence_t ARG_divertingLegInformation3_sequence[] = {
  { &hf_qsig_presentationAllowedIndicator, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_NOOWNTAG, dissect_qsig_PresentationAllowedIndicator },
  { &hf_qsig_redirectionName, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_qsig_Name },
  { &hf_qsig_extensionDLI3  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_DLI3Extension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ARG_divertingLegInformation3(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ARG_divertingLegInformation3_sequence, hf_index, ett_qsig_ARG_divertingLegInformation3);

  return offset;
}


static const value_string qsig_ARG_cfnrDivertedLegFailed_vals[] = {
  {   0, "null" },
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t ARG_cfnrDivertedLegFailed_choice[] = {
  {   0, &hf_qsig_null           , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_qsig_NULL },
  {   1, &hf_qsig_single         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_multiple       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_ARG_cfnrDivertedLegFailed(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ARG_cfnrDivertedLegFailed_choice, hf_index, ett_qsig_ARG_cfnrDivertedLegFailed,
                                 NULL);

  return offset;
}


static const value_string qsig_IRExtension_vals[] = {
  {   1, "single" },
  {   2, "multiple" },
  { 0, NULL }
};

static const ber_choice_t IRExtension_choice[] = {
  {   1, &hf_qsig_single         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_qsig_Extension },
  {   2, &hf_qsig_multiple       , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_qsig_SEQUENCE_OF_Extension },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_IRExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 IRExtension_choice, hf_index, ett_qsig_IRExtension,
                                 NULL);

  return offset;
}


static const ber_sequence_t IntResult_sequence[] = {
  { &hf_qsig_servedUserNr   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_PartyNumber },
  { &hf_qsig_basicService   , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_BasicService },
  { &hf_qsig_procedure      , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_qsig_Procedure },
  { &hf_qsig_divertedToAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_Address },
  { &hf_qsig_remoteEnabled  , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_qsig_BOOLEAN },
  { &hf_qsig_extensionIR    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_qsig_IRExtension },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_qsig_IntResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IntResult_sequence, hf_index, ett_qsig_IntResult);

  return offset;
}


static const ber_sequence_t IntResultList_set_of[1] = {
  { &hf_qsig_IntResultList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_qsig_IntResult },
};

static int
dissect_qsig_IntResultList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 IntResultList_set_of, hf_index, ett_qsig_IntResultList);

  return offset;
}

/*--- PDUs ---*/

static int dissect_NameArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_NameArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_NameArg_PDU);
  return offset;
}
static int dissect_ARG_activateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ARG_activateDiversionQ(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ARG_activateDiversionQ_PDU);
  return offset;
}
static int dissect_RES_activateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_RES_activateDiversionQ(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_RES_activateDiversionQ_PDU);
  return offset;
}
static int dissect_ARG_deactivateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ARG_deactivateDiversionQ(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ARG_deactivateDiversionQ_PDU);
  return offset;
}
static int dissect_RES_deactivateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_RES_deactivateDiversionQ(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_RES_deactivateDiversionQ_PDU);
  return offset;
}
static int dissect_ARG_interrogateDiversionQ_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ARG_interrogateDiversionQ(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ARG_interrogateDiversionQ_PDU);
  return offset;
}
static int dissect_IntResultList_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_IntResultList(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_IntResultList_PDU);
  return offset;
}
static int dissect_ARG_checkRestriction_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ARG_checkRestriction(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ARG_checkRestriction_PDU);
  return offset;
}
static int dissect_RES_checkRestriction_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_RES_checkRestriction(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_RES_checkRestriction_PDU);
  return offset;
}
static int dissect_ARG_callRerouteing_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ARG_callRerouteing(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ARG_callRerouteing_PDU);
  return offset;
}
static int dissect_RES_callRerouteing_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_RES_callRerouteing(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_RES_callRerouteing_PDU);
  return offset;
}
static int dissect_ARG_divertingLegInformation1_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ARG_divertingLegInformation1(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ARG_divertingLegInformation1_PDU);
  return offset;
}
static int dissect_ARG_divertingLegInformation2_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ARG_divertingLegInformation2(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ARG_divertingLegInformation2_PDU);
  return offset;
}
static int dissect_ARG_divertingLegInformation3_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ARG_divertingLegInformation3(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ARG_divertingLegInformation3_PDU);
  return offset;
}
static int dissect_ARG_cfnrDivertedLegFailed_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_qsig_ARG_cfnrDivertedLegFailed(FALSE, tvb, offset, &asn1_ctx, tree, hf_qsig_ARG_cfnrDivertedLegFailed_PDU);
  return offset;
}


/*--- End of included file: packet-qsig-fn.c ---*/
#line 441 "packet-qsig-template.c"

static const qsig_op_t qsig_tab[] = {
  /*   0 */ {   0, dissect_NameArg_PDU, NULL },
  /*   1 */ {   1, dissect_NameArg_PDU, NULL },
  /*   2 */ {   2, dissect_NameArg_PDU, NULL },
  /*   3 */ {   3, dissect_NameArg_PDU, NULL },
  /*   4 */ {   4, NULL, NULL },
  /*   5 */ {   5, NULL, NULL },
  /*   6 */ {   6, NULL, NULL },
  /*   7 */ {   7, NULL, NULL },
  /*   8 */ {   8, NULL, NULL },
  /*   9 */ {   9, NULL, NULL },
  /*  10 */ {  10, NULL, NULL },
  /*  11 */ {  11, NULL, NULL },
  /*  12 */ {  12, NULL, NULL },
  /*  13 */ {  13, NULL, NULL },
  /*  14 */ {  14, NULL, NULL },
  /*  15 */ {  15, dissect_ARG_activateDiversionQ_PDU, dissect_RES_activateDiversionQ_PDU },
  /*  16 */ {  16, dissect_ARG_deactivateDiversionQ_PDU, dissect_RES_deactivateDiversionQ_PDU },
  /*  17 */ {  17, dissect_ARG_interrogateDiversionQ_PDU, dissect_IntResultList_PDU },
  /*  18 */ {  18, dissect_ARG_checkRestriction_PDU, dissect_RES_checkRestriction_PDU },
  /*  19 */ {  19, dissect_ARG_callRerouteing_PDU, dissect_RES_callRerouteing_PDU },
  /*  20 */ {  20, dissect_ARG_divertingLegInformation1_PDU, NULL },
  /*  21 */ {  21, dissect_ARG_divertingLegInformation2_PDU, NULL },
  /*  22 */ {  22, dissect_ARG_divertingLegInformation3_PDU, NULL },
  /*  23 */ {  23, dissect_ARG_cfnrDivertedLegFailed_PDU, NULL },
  /*  27 */ {  27, NULL, NULL },
  /*  28 */ {  28, NULL, NULL },
  /*  29 */ {  29, NULL, NULL },
  /*  30 */ {  30, NULL, NULL },
  /*  31 */ {  31, NULL, NULL },
  /*  32 */ {  32, NULL, NULL },
  /*  33 */ {  33, NULL, NULL },
  /*  34 */ {  34, NULL, NULL },
  /*  35 */ {  35, NULL, NULL },
  /*  36 */ {  36, NULL, NULL },
  /*  37 */ {  37, NULL, NULL },
  /*  38 */ {  38, NULL, NULL },
  /*  39 */ {  39, NULL, NULL },
  /*  40 */ {  40, NULL, NULL },
  /*  41 */ {  41, NULL, NULL },
  /*  42 */ {  42, NULL, NULL },
  /*  43 */ {  43, NULL, NULL },
  /*  44 */ {  44, NULL, NULL },
  /*  45 */ {  45, NULL, NULL },
  /*  46 */ {  46, NULL, NULL },
  /*  47 */ {  47, NULL, NULL },
  /*  48 */ {  48, NULL, NULL },
  /*  49 */ {  49, NULL, NULL },
  /*  50 */ {  50, NULL, NULL },
  /*  51 */ {  51, NULL, NULL },
  /*  52 */ {  52, NULL, NULL },
  /*  53 */ {  53, NULL, NULL },
  /*  54 */ {  54, NULL, NULL },
  /*  55 */ {  55, NULL, NULL },
  /*  56 */ {  56, NULL, NULL },
  /*  57 */ {  57, NULL, NULL },
  /*  58 */ {  58, NULL, NULL },
  /*  59 */ {  59, NULL, NULL },
  /*  60 */ {  60, NULL, NULL },
  /*  61 */ {  61, NULL, NULL },
  /*  62 */ {  62, NULL, NULL },
  /*  63 */ {  63, NULL, NULL },
  /*  64 */ {  64, NULL, NULL },
  /*  65 */ {  65, NULL, NULL },
  /*  66 */ {  66, NULL, NULL },
  /*  67 */ {  67, NULL, NULL },
  /*  68 */ {  68, NULL, NULL },
  /*  69 */ {  69, NULL, NULL },
  /*  70 */ {  70, NULL, NULL },
  /*  71 */ {  71, NULL, NULL },
  /*  72 */ {  72, NULL, NULL },
  /*  73 */ {  73, NULL, NULL },
  /*  74 */ {  74, NULL, NULL },
  /*  75 */ {  75, NULL, NULL },
  /*  76 */ {  76, NULL, NULL },
  /*  77 */ {  77, NULL, NULL },
  /*  78 */ {  78, NULL, NULL },
  /*  79 */ {  79, NULL, NULL },
  /*  80 */ {  80, NULL, NULL },
  /*  81 */ {  81, NULL, NULL },
  /*  82 */ {  82, NULL, NULL },
  /*  84 */ {  84, NULL, NULL },
  /*  85 */ {  85, NULL, NULL },
  /*  86 */ {  86, NULL, NULL },
  /*  87 */ {  87, NULL, NULL },
  /*  88 */ {  88, NULL, NULL },
  /*  89 */ {  89, NULL, NULL },
  /*  90 */ {  90, NULL, NULL },
  /*  91 */ {  91, NULL, NULL },
  /*  92 */ {  92, NULL, NULL },
  /*  93 */ {  93, NULL, NULL },
  /*  94 */ {  94, NULL, NULL },
  /*  95 */ {  95, NULL, NULL },
  /*  96 */ {  96, NULL, NULL },
  /*  97 */ {  97, NULL, NULL },
  /*  98 */ {  98, NULL, NULL },
  /*  99 */ {  99, NULL, NULL },
  /* 100 */ { 100, NULL, NULL },
  /* 101 */ { 101, NULL, NULL },
  /* 102 */ { 102, NULL, NULL },
  /* 103 */ { 103, NULL, NULL },
  /* 104 */ { 104, NULL, NULL },
  /* 105 */ { 105, NULL, NULL },
  /* 106 */ { 106, NULL, NULL },
  /* 107 */ { 107, NULL, NULL },
  /* 108 */ { 108, NULL, NULL },
  /* 109 */ { 109, NULL, NULL },
  /* 110 */ { 110, NULL, NULL },
  /* 111 */ { 111, NULL, NULL },
  /* 112 */ { 112, NULL, NULL },
  /* 113 */ { 113, NULL, NULL },
  /* 114 */ { 114, NULL, NULL },
  /* 115 */ { 115, NULL, NULL },
  /* 116 */ { 116, NULL, NULL },
  /* 117 */ { 117, NULL, NULL },
  /* 118 */ { 118, NULL, NULL },
  /* 119 */ { 119, NULL, NULL },
  /* 120 */ { 120, NULL, NULL },
};                                 

static const qsig_op_t *get_op(gint32 opcode) {
  int i;

  /* search from the end to get the last occurence if the operation is redefined in some newer specification */
  for (i = array_length(qsig_tab) - 1; i >= 0; i--)
    if (qsig_tab[i].opcode == opcode)
      return &qsig_tab[i];
  return NULL;
}

static gint32 get_service(gint32 opcode) {
  if ((opcode < 0) || (opcode >= (int)array_length(op2srv_tab)))
    return NO_SRV;
  return op2srv_tab[opcode];
}
                  
/*--- dissect_qsig_arg ------------------------------------------------------*/
static int   
dissect_qsig_arg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  int offset;
  rose_ctx_t *rctx;
  gint32 opcode, service;
  const qsig_op_t *op_ptr;
  const gchar *p;
  proto_item *ti, *ti_tmp;
  proto_tree *qsig_tree;

  offset = 0;
  rctx = get_rose_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(rctx);
  if (rctx->d.pdu != 1)  /* invoke */
    return offset; 
  if (rctx->d.code != 0)  /* local */
    return offset; 
  opcode = rctx->d.code_local;
  op_ptr = get_op(opcode);
  if (!op_ptr)
    return offset; 
  service = get_service(opcode);

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, tvb_length(tvb), FALSE);
  qsig_tree = proto_item_add_subtree(ti, ett_qsig); 

  proto_tree_add_uint(qsig_tree, hf_qsig_operation, tvb, 0, 0, opcode);
  p = match_strval(opcode, VALS(qsig_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  ti_tmp = proto_tree_add_uint(qsig_tree, hf_qsig_service, tvb, 0, 0, service);
  p = match_strval(service, VALS(qsig_str_service_name));
  if (p) proto_item_append_text(ti_tmp, " - %s", p);

  if (op_ptr->arg_pdu)
    offset = op_ptr->arg_pdu(tvb, pinfo, qsig_tree);
  else 
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(qsig_tree, tvb, offset, -1, "UNSUPPORTED ARGUMENT TYPE (QSIG)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_qsig_res -------------------------------------------------------*/
static int
dissect_qsig_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset;
  rose_ctx_t *rctx;
  gint32 opcode, service;
  const qsig_op_t *op_ptr;
  const gchar *p;
  proto_item *ti, *ti_tmp;
  proto_tree *qsig_tree;

  offset = 0;
  rctx = get_rose_ctx(pinfo->private_data);
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

  ti = proto_tree_add_item(tree, proto_qsig, tvb, offset, tvb_length(tvb), FALSE);
  qsig_tree = proto_item_add_subtree(ti, ett_qsig); 

  proto_tree_add_uint(qsig_tree, hf_qsig_operation, tvb, 0, 0, opcode);
  p = match_strval(opcode, VALS(qsig_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  ti_tmp = proto_tree_add_uint(qsig_tree, hf_qsig_service, tvb, 0, 0, service);
  p = match_strval(service, VALS(qsig_str_service_name));
  if (p) proto_item_append_text(ti_tmp, " - %s", p);

  if (op_ptr->res_pdu)
    offset = op_ptr->res_pdu(tvb, pinfo, qsig_tree);
  else 
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(qsig_tree, tvb, offset, -1, "UNSUPPORTED RESULT TYPE (QSIG)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
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
    { &hf_qsig_ARG_activateDiversionQ_PDU,
      { "ARG-activateDiversionQ", "qsig.ARG_activateDiversionQ",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.ARG_activateDiversionQ", HFILL }},
    { &hf_qsig_RES_activateDiversionQ_PDU,
      { "RES-activateDiversionQ", "qsig.RES_activateDiversionQ",
        FT_UINT32, BASE_DEC, VALS(qsig_RES_activateDiversionQ_vals), 0,
        "qsig.RES_activateDiversionQ", HFILL }},
    { &hf_qsig_ARG_deactivateDiversionQ_PDU,
      { "ARG-deactivateDiversionQ", "qsig.ARG_deactivateDiversionQ",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.ARG_deactivateDiversionQ", HFILL }},
    { &hf_qsig_RES_deactivateDiversionQ_PDU,
      { "RES-deactivateDiversionQ", "qsig.RES_deactivateDiversionQ",
        FT_UINT32, BASE_DEC, VALS(qsig_RES_deactivateDiversionQ_vals), 0,
        "qsig.RES_deactivateDiversionQ", HFILL }},
    { &hf_qsig_ARG_interrogateDiversionQ_PDU,
      { "ARG-interrogateDiversionQ", "qsig.ARG_interrogateDiversionQ",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.ARG_interrogateDiversionQ", HFILL }},
    { &hf_qsig_IntResultList_PDU,
      { "IntResultList", "qsig.IntResultList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "qsig.IntResultList", HFILL }},
    { &hf_qsig_ARG_checkRestriction_PDU,
      { "ARG-checkRestriction", "qsig.ARG_checkRestriction",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.ARG_checkRestriction", HFILL }},
    { &hf_qsig_RES_checkRestriction_PDU,
      { "RES-checkRestriction", "qsig.RES_checkRestriction",
        FT_UINT32, BASE_DEC, VALS(qsig_RES_checkRestriction_vals), 0,
        "qsig.RES_checkRestriction", HFILL }},
    { &hf_qsig_ARG_callRerouteing_PDU,
      { "ARG-callRerouteing", "qsig.ARG_callRerouteing",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.ARG_callRerouteing", HFILL }},
    { &hf_qsig_RES_callRerouteing_PDU,
      { "RES-callRerouteing", "qsig.RES_callRerouteing",
        FT_UINT32, BASE_DEC, VALS(qsig_RES_callRerouteing_vals), 0,
        "qsig.RES_callRerouteing", HFILL }},
    { &hf_qsig_ARG_divertingLegInformation1_PDU,
      { "ARG-divertingLegInformation1", "qsig.ARG_divertingLegInformation1",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.ARG_divertingLegInformation1", HFILL }},
    { &hf_qsig_ARG_divertingLegInformation2_PDU,
      { "ARG-divertingLegInformation2", "qsig.ARG_divertingLegInformation2",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.ARG_divertingLegInformation2", HFILL }},
    { &hf_qsig_ARG_divertingLegInformation3_PDU,
      { "ARG-divertingLegInformation3", "qsig.ARG_divertingLegInformation3",
        FT_NONE, BASE_NONE, NULL, 0,
        "qsig.ARG_divertingLegInformation3", HFILL }},
    { &hf_qsig_ARG_cfnrDivertedLegFailed_PDU,
      { "ARG-cfnrDivertedLegFailed", "qsig.ARG_cfnrDivertedLegFailed",
        FT_UINT32, BASE_DEC, VALS(qsig_ARG_cfnrDivertedLegFailed_vals), 0,
        "qsig.ARG_cfnrDivertedLegFailed", HFILL }},
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
#line 776 "packet-qsig-template.c"
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
    &ett_qsig_ARG_activateDiversionQ,
    &ett_qsig_ADExtension,
    &ett_qsig_RES_activateDiversionQ,
    &ett_qsig_ARG_deactivateDiversionQ,
    &ett_qsig_DDExtension,
    &ett_qsig_RES_deactivateDiversionQ,
    &ett_qsig_ARG_interrogateDiversionQ,
    &ett_qsig_IDExtension,
    &ett_qsig_ARG_checkRestriction,
    &ett_qsig_CHRExtension,
    &ett_qsig_RES_checkRestriction,
    &ett_qsig_ARG_callRerouteing,
    &ett_qsig_CRRExtension,
    &ett_qsig_RES_callRerouteing,
    &ett_qsig_ARG_divertingLegInformation1,
    &ett_qsig_DLI1Extension,
    &ett_qsig_ARG_divertingLegInformation2,
    &ett_qsig_DLI2Extension,
    &ett_qsig_ARG_divertingLegInformation3,
    &ett_qsig_DLI3Extension,
    &ett_qsig_ARG_cfnrDivertedLegFailed,
    &ett_qsig_IntResultList,
    &ett_qsig_IntResult,
    &ett_qsig_IRExtension,

/*--- End of included file: packet-qsig-ettarr.c ---*/
#line 783 "packet-qsig-template.c"
  };

  /* Register protocol and dissector */
  proto_qsig = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_qsig, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_qsig ------------------------------------------------*/
void proto_reg_handoff_qsig(void) {
  int i;
  dissector_handle_t qsig_arg_handle;
  dissector_handle_t qsig_res_handle;
  dissector_handle_t qsig_ie_handle;

  data_handle = find_dissector("data");

  if (find_dissector_table("q932.ros.local.arg")) {
    qsig_arg_handle = new_create_dissector_handle(dissect_qsig_arg, proto_qsig);
    qsig_res_handle = new_create_dissector_handle(dissect_qsig_res, proto_qsig);
    for (i=0; i<(int)array_length(qsig_tab); i++) {
      dissector_add("q932.ros.local.arg", qsig_tab[i].opcode, qsig_arg_handle);
      dissector_add("q932.ros.local.res", qsig_tab[i].opcode, qsig_res_handle);
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
