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
  if ((opcode <0) || (opcode >= array_length(op2srv_tab)))
    return NULL;
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
  int i;
  dissector_handle_t qsig_arg_handle;
  dissector_handle_t qsig_res_handle;
  dissector_handle_t qsig_ie_handle;

  data_handle = find_dissector("data");

  if (find_dissector_table("q932.ros.local.arg")) {
    qsig_arg_handle = new_create_dissector_handle(dissect_qsig_arg, proto_qsig);
    qsig_res_handle = new_create_dissector_handle(dissect_qsig_res, proto_qsig);
    for (i=0; i<array_length(qsig_tab); i++) {
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
