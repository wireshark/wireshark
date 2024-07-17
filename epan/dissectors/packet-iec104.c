/* packet-iec104.c
 * Routines for IEC-60870-5-101 & 104 Protocol disassembly
 *
 * Copyright (c) 2008 by Joan Ramio <joan@ramio.cat>
 * Joan is a masculine catalan name. Search the Internet for Joan Pujol (alias Garbo).
 *
 * Copyright (c) 2009 by Kjell Hultman <kjell.hultman@gmail.com>
 * Added dissection of signal (ASDU) information.
 * Kjell is also a masculine name, but a Scandinavian one.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <math.h> /* floor */

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/reassemble.h>
#include <wsutil/str_util.h>
#include "packet-tcp.h"

void proto_register_iec60870_104(void);
void proto_reg_handoff_iec60870_104(void);

void proto_register_iec60870_101(void);
void proto_reg_handoff_iec60870_101(void);

void proto_register_iec60870_5_103(void);
void proto_reg_handoff_iec60870_5_103(void);

void proto_register_iec60870_asdu(void);

static int dissect_iec60870_asdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data);

static dissector_handle_t iec60870_asdu_handle;
static dissector_handle_t iec60870_104_handle;
static dissector_handle_t iec60870_101_handle;
static dissector_handle_t iec60870_5_103_handle;

static reassembly_table iec60870_reassemble_table;

/* the asdu header structure */
struct asduheader {
	uint32_t Addr;
	uint8_t OA;
	uint8_t TypeId;
	uint8_t TNCause;
	uint32_t IOA;
	uint8_t NumIx;
	uint8_t SQ;
	uint8_t DataLength;
};

struct asdu_parms {
	unsigned cot_len;
	unsigned asdu_addr_len;
	unsigned ioa_len;
};

/* ASDU command value/status structure */
typedef struct {
	bool OFF;
	bool ON;

	bool UP;
	bool DOWN;

	/* QOC qualifier-bits */
	uint16_t QU;      /* qualifier-value */
	bool ZeroP;   /* No pulse */
	bool ShortP;  /* Short Pulse */
	bool LongP;   /* Long Pulse */
	bool Persist; /* Persistent output */
	bool SE;      /* Select (1) / Execute (0) */
} td_CmdInfo;

#define IEC104_PORT     2404

/* Define the iec101/103/104 protos */
static int proto_iec60870_101;
static int proto_iec60870_5_103;
static int proto_iec60870_104;
static int proto_iec60870_asdu;

/* Protocol constants */
#define APCI_START	0x68
#define APCI_LEN	6
#define APCI_START_LEN	2
#define APCI_DATA_LEN	(APCI_LEN - APCI_START_LEN)
#define APDU_MIN_LEN	4
#define APDU_MAX_LEN	253

/* ASDU_HEAD_LEN: Includes Asdu head and first IOA */
#define ASDU_HEAD_LEN	9
#define F_TEST  0x80
#define F_NEGA  0x40
#define F_CAUSE 0x3F
#define F_SQ    0x80

/* APCI types */

/* Type I is only lowest bit set to 0 */
#define I_TYPE		0
#define S_TYPE		1
#define U_TYPE		3
#define APCI_TYPE_UNKNOWN 4

static const value_string apci_types [] = {
	{ I_TYPE,		"I" },
	{ S_TYPE,		"S" },
	{ U_TYPE,		"U" },
	{ 0, NULL }
};

/* Constants relative to the field, independent of the field position in the byte */
/* U (Unnumbered) constants */
#define U_STARTDT_ACT 		0x01
#define U_STARTDT_CON	 	0x02
#define U_STOPDT_ACT 		0x04
#define U_STOPDT_CON	 	0x08
#define U_TESTFR_ACT 		0x10
#define U_TESTFR_CON	 	0x20
static const value_string u_types[] = {
	{ U_STARTDT_ACT,		"STARTDT act" },
	{ U_STARTDT_CON, 		"STARTDT con" },
	{ U_STOPDT_ACT,			"STOPDT act" },
	{ U_STOPDT_CON, 		"STOPDT con" },
	{ U_TESTFR_ACT, 		"TESTFR act" },
	{ U_TESTFR_CON, 		"TESTFR con" },
	{ 0, NULL }
};

/* ASDU types (TypeId) */
#define M_SP_NA_1  1    /* single-point information 								*/
#define M_SP_TA_1  2    /* single-point information with time tag 	 					*/
#define M_DP_NA_1  3    /* double-point information 								*/
#define M_DP_TA_1  4    /* double-point information with time tag 						*/
#define M_ST_NA_1  5    /* step position information 								*/
#define M_ST_TA_1  6    /* step position information with time tag 						*/
#define M_BO_NA_1  7    /* bitstring of 32 bits 								*/
#define M_BO_TA_1  8    /* bitstring of 32 bits with time tag 							*/
#define M_ME_NA_1  9    /* measured value, normalized value 							*/
#define M_ME_TA_1  10    /* measured value, normalized value with time tag 					*/
#define M_ME_NB_1  11    /* measured value, scaled value 							*/
#define M_ME_TB_1  12    /* measured value, scaled value with time tag 						*/
#define M_ME_NC_1  13    /* measured value, short floating point number 					*/
#define M_ME_TC_1  14    /* measured value, short floating point number with time tag 				*/
#define M_IT_NA_1  15    /* integrated totals 									*/
#define M_IT_TA_1  16    /* integrated totals with time tag 							*/
#define M_PS_NA_1  20    /* packed single-point information with status change detection 			*/
#define M_ME_ND_1  21    /* measured value, normalized value without quality descriptor 			*/
#define M_SP_TB_1  30    /* single-point information with time tag CP56Time2a 					*/
#define M_DP_TB_1  31    /* double-point information with time tag CP56Time2a 					*/
#define M_ST_TB_1  32    /* step position information with time tag CP56Time2a 					*/
#define M_BO_TB_1  33    /* bitstring of 32 bit with time tag CP56Time2a 					*/
#define M_ME_TD_1  34    /* measured value, normalized value with time tag CP56Time2a 				*/
#define M_ME_TE_1  35    /* measured value, scaled value with time tag CP56Time2a 				*/
#define M_ME_TF_1  36    /* measured value, short floating point number with time tag CP56Time2a 		*/
#define M_IT_TB_1  37    /* integrated totals with time tag CP56Time2a 						*/
#define M_EP_TD_1  38    /* event of protection equipment with time tag CP56Time2a 				*/
#define M_EP_TE_1  39    /* packed start events of protection equipment with time tag CP56Time2a 		*/
#define M_EP_TF_1  40    /* packed output circuit information of protection equipment with time tag CP56Time2a 	*/
#define S_IT_TC_1  41    /* integrated totals containing time tagged security statistics			*/
#define C_SC_NA_1  45    /* single command 									*/
#define C_DC_NA_1  46    /* double command 									*/
#define C_RC_NA_1  47    /* regulating step command 								*/
#define C_SE_NA_1  48    /* set point command, normalized value 						*/
#define C_SE_NB_1  49    /* set point command, scaled value 							*/
#define C_SE_NC_1  50    /* set point command, short floating point number 					*/
#define C_BO_NA_1  51    /* bitstring of 32 bits 								*/
#define C_SC_TA_1  58    /* single command with time tag CP56Time2a 						*/
#define C_DC_TA_1  59    /* double command with time tag CP56Time2a 						*/
#define C_RC_TA_1  60    /* regulating step command with time tag CP56Time2a 					*/
#define C_SE_TA_1  61    /* set point command, normalized value with time tag CP56Time2a 			*/
#define C_SE_TB_1  62    /* set point command, scaled value with time tag CP56Time2a 				*/
#define C_SE_TC_1  63    /* set point command, short floating-point number with time tag CP56Time2a 		*/
#define C_BO_TA_1  64    /* bitstring of 32 bits with time tag CP56Time2a 					*/
#define M_EI_NA_1  70    /* end of initialization 								*/
#define S_CH_NA_1  81    /* authentication challenge								*/
#define S_RP_NA_1  82    /* authentication reply								*/
#define S_AR_NA_1  83    /* aggressive mode authentication request session key status request			*/
#define S_KR_NA_1  84    /* session key status request								*/
#define S_KS_NA_1  85    /* session key status									*/
#define S_KC_NA_1  86    /* session key change									*/
#define S_ER_NA_1  87    /* authentication error								*/
#define S_US_NA_1  90    /* user status change									*/
#define S_UQ_NA_1  91    /* update key change request								*/
#define S_UR_NA_1  92    /* update key change reply								*/
#define S_UK_NA_1  93    /* update key change symmetric								*/
#define S_UA_NA_1  94    /* update key change asymmetric							*/
#define S_UC_NA_1  95    /* update key change confirmation							*/
#define C_IC_NA_1  100    /* interrogation command 								*/
#define C_CI_NA_1  101    /* counter interrogation command 							*/
#define C_RD_NA_1  102    /* read command 									*/
#define C_CS_NA_1  103    /* clock synchronization command 							*/
#define C_RP_NA_1  105    /* reset process command 								*/
#define C_TS_TA_1  107    /* test command with time tag CP56Time2a 						*/
#define P_ME_NA_1  110    /* parameter of measured value, normalized value 					*/
#define P_ME_NB_1  111    /* parameter of measured value, scaled value 						*/
#define P_ME_NC_1  112    /* parameter of measured value, short floating-point number 				*/
#define P_AC_NA_1  113    /* parameter activation 								*/
#define F_FR_NA_1  120    /* file ready 									*/
#define F_SR_NA_1  121    /* section ready 									*/
#define F_SC_NA_1  122    /* call directory, select file, call file, call section 				*/
#define F_LS_NA_1  123    /* last section, last segment 							*/
#define F_AF_NA_1  124    /* ack file, ack section 								*/
#define F_SG_NA_1  125    /* segment 										*/
#define F_DR_TA_1  126    /* directory 										*/
#define F_SC_NB_1  127    /* Query Log - Request archive file 							*/
static const value_string asdu_types [] = {
	{  M_SP_NA_1,		"M_SP_NA_1" },
	{  M_SP_TA_1,		"M_SP_TA_1" },
	{  M_DP_NA_1,		"M_DP_NA_1" },
	{  M_DP_TA_1,		"M_DP_TA_1" },
	{  M_ST_NA_1,		"M_ST_NA_1" },
	{  M_ST_TA_1,		"M_ST_TA_1" },
	{  M_BO_NA_1,		"M_BO_NA_1" },
	{  M_BO_TA_1,		"M_BO_TA_1" },
	{  M_ME_NA_1,		"M_ME_NA_1" },
	{  M_ME_TA_1,		"M_ME_TA_1" },
	{  M_ME_NB_1,		"M_ME_NB_1" },
	{  M_ME_TB_1,		"M_ME_TB_1" },
	{  M_ME_NC_1,		"M_ME_NC_1" },
	{  M_ME_TC_1,		"M_ME_TC_1" },
	{  M_IT_NA_1,		"M_IT_NA_1" },
	{  M_IT_TA_1,		"M_IT_TA_1" },
	{  M_PS_NA_1,		"M_PS_NA_1" },
	{  M_ME_ND_1,		"M_ME_ND_1" },
	{  M_SP_TB_1,		"M_SP_TB_1" },
	{  M_DP_TB_1,		"M_DP_TB_1" },
	{  M_ST_TB_1,		"M_ST_TB_1" },
	{  M_BO_TB_1,		"M_BO_TB_1" },
	{  M_ME_TD_1,		"M_ME_TD_1" },
	{  M_ME_TE_1,		"M_ME_TE_1" },
	{  M_ME_TF_1,		"M_ME_TF_1" },
	{  M_IT_TB_1,		"M_IT_TB_1" },
	{  M_EP_TD_1,		"M_EP_TD_1" },
	{  M_EP_TE_1,		"M_EP_TE_1" },
	{  M_EP_TF_1,		"M_EP_TF_1" },
	{  S_IT_TC_1,		"S_IT_TC_1" },
	{  C_SC_NA_1,		"C_SC_NA_1" },
	{  C_DC_NA_1,		"C_DC_NA_1" },
	{  C_RC_NA_1,		"C_RC_NA_1" },
	{  C_SE_NA_1,		"C_SE_NA_1" },
	{  C_SE_NB_1,		"C_SE_NB_1" },
	{  C_SE_NC_1,		"C_SE_NC_1" },
	{  C_BO_NA_1,		"C_BO_NA_1" },
	{  C_SC_TA_1,		"C_SC_TA_1" },
	{  C_DC_TA_1,		"C_DC_TA_1" },
	{  C_RC_TA_1,		"C_RC_TA_1" },
	{  C_SE_TA_1,		"C_SE_TA_1" },
	{  C_SE_TB_1,		"C_SE_TB_1" },
	{  C_SE_TC_1,		"C_SE_TC_1" },
	{  C_BO_TA_1,		"C_BO_TA_1" },
	{  M_EI_NA_1,		"M_EI_NA_1" },
	{  S_CH_NA_1,		"S_CH_NA_1" },
	{  S_RP_NA_1,		"S_RP_NA_1" },
	{  S_AR_NA_1,		"S_AR_NA_1" },
	{  S_KR_NA_1,		"S_KR_NA_1" },
	{  S_KS_NA_1,		"S_KS_NA_1" },
	{  S_KC_NA_1,		"S_KC_NA_1" },
	{  S_ER_NA_1,		"S_ER_NA_1" },
	{  S_US_NA_1,		"S_US_NA_1" },
	{  S_UQ_NA_1,		"S_UQ_NA_1" },
	{  S_UR_NA_1,		"S_UR_NA_1" },
	{  S_UK_NA_1,		"S_UK_NA_1" },
	{  S_UA_NA_1,		"S_UA_NA_1" },
	{  S_UC_NA_1,		"S_UC_NA_1" },
	{  C_IC_NA_1,		"C_IC_NA_1" },
	{  C_CI_NA_1,		"C_CI_NA_1" },
	{  C_RD_NA_1,		"C_RD_NA_1" },
	{  C_CS_NA_1,		"C_CS_NA_1" },
	{  C_RP_NA_1,		"C_RP_NA_1" },
	{  C_TS_TA_1,		"C_TS_TA_1" },
	{  P_ME_NA_1,		"P_ME_NA_1" },
	{  P_ME_NB_1,		"P_ME_NB_1" },
	{  P_ME_NC_1,		"P_ME_NC_1" },
	{  P_AC_NA_1,		"P_AC_NA_1" },
	{  F_FR_NA_1,		"F_FR_NA_1" },
	{  F_SR_NA_1,		"F_SR_NA_1" },
	{  F_SC_NA_1,		"F_SC_NA_1" },
	{  F_LS_NA_1,		"F_LS_NA_1" },
	{  F_AF_NA_1,		"F_AF_NA_1" },
	{  F_SG_NA_1,		"F_SG_NA_1" },
	{  F_DR_TA_1,		"F_DR_TA_1" },
	{  F_SC_NB_1,		"F_SC_NB_1" },
	{ 0, NULL }
};

static const value_string asdu_lngtypes [] = {
	{  M_SP_NA_1,		"single-point information" },
	{  M_SP_TA_1,		"single-point information with time tag" },
	{  M_DP_NA_1,		"double-point information" },
	{  M_DP_TA_1,		"double-point information with time tag" },
	{  M_ST_NA_1,		"step position information" },
	{  M_ST_TA_1,		"step position information with time tag" },
	{  M_BO_NA_1,		"bitstring of 32 bits" },
	{  M_BO_TA_1,		"bitstring of 32 bits with time tag" },
	{  M_ME_NA_1,		"measured value, normalized value" },
	{  M_ME_TA_1,		"measured value, normalized value with time tag" },
	{  M_ME_NB_1,		"measured value, scaled value" },
	{  M_ME_TB_1,		"measured value, scaled value with time tag" },
	{  M_ME_NC_1,		"measured value, short floating point number" },
	{  M_ME_TC_1,		"measured value, short floating point number with time tag" },
	{  M_IT_NA_1,		"integrated totals" },
	{  M_IT_TA_1,		"integrated totals with time tag" },
	{  M_PS_NA_1,		"packed single-point information with status change detection" },
	{  M_ME_ND_1,		"measured value, normalized value without quality descriptor" },
	{  M_SP_TB_1,		"single-point information with time tag CP56Time2a" },
	{  M_DP_TB_1,		"double-point information with time tag CP56Time2a" },
	{  M_ST_TB_1,		"step position information with time tag CP56Time2a" },
	{  M_BO_TB_1,		"bitstring of 32 bit with time tag CP56Time2a" },
	{  M_ME_TD_1,		"measured value, normalized value with time tag CP56Time2a" },
	{  M_ME_TE_1,		"measured value, scaled value with time tag CP56Time2a" },
	{  M_ME_TF_1,		"measured value, short floating point number with time tag CP56Time2a" },
	{  M_IT_TB_1,		"integrated totals with time tag CP56Time2a" },
	{  M_EP_TD_1,		"event of protection equipment with time tag CP56Time2a" },
	{  M_EP_TE_1,		"packed start events of protection equipment with time tag CP56Time2a" },
	{  M_EP_TF_1,		"packed output circuit information of protection equipment with time tag CP56Time2a" },
	{  S_IT_TC_1,		"integrated totals containing time tagged security statistics" },
	{  C_SC_NA_1,		"single command" },
	{  C_DC_NA_1,		"double command" },
	{  C_RC_NA_1,		"regulating step command" },
	{  C_SE_NA_1,		"set point command, normalized value" },
	{  C_SE_NB_1,		"set point command, scaled value" },
	{  C_SE_NC_1,		"set point command, short floating point number" },
	{  C_BO_NA_1,		"bitstring of 32 bits" },
	{  C_SC_TA_1,		"single command with time tag CP56Time2a" },
	{  C_DC_TA_1,		"double command with time tag CP56Time2a" },
	{  C_RC_TA_1,		"regulating step command with time tag CP56Time2a" },
	{  C_SE_TA_1,		"set point command, normalized value with time tag CP56Time2a" },
	{  C_SE_TB_1,		"set point command, scaled value with time tag CP56Time2a" },
	{  C_SE_TC_1,		"set point command, short floating-point number with time tag CP56Time2a" },
	{  C_BO_TA_1,		"bitstring of 32 bits with time tag CP56Time2a" },
	{  M_EI_NA_1,		"end of initialization" },
	{  S_CH_NA_1,		"authentication challenge" },
	{  S_RP_NA_1,		"authentication reply" },
	{  S_AR_NA_1,		"aggressive mode authentication request session key status request" },
	{  S_KR_NA_1,		"session key status request" },
	{  S_KS_NA_1,		"session key status" },
	{  S_KC_NA_1,		"session key change" },
	{  S_ER_NA_1,		"authentication error" },
	{  S_US_NA_1,		"user status change" },
	{  S_UQ_NA_1,		"update key change request" },
	{  S_UR_NA_1,		"update key change reply" },
	{  S_UK_NA_1,		"update key change symmetric" },
	{  S_UA_NA_1,		"update key change asymmetric" },
	{  S_UC_NA_1,		"update key change confirmation" },
	{  C_IC_NA_1,		"interrogation command" },
	{  C_CI_NA_1,		"counter interrogation command" },
	{  C_RD_NA_1,		"read command" },
	{  C_CS_NA_1,		"clock synchronization command" },
	{  C_RP_NA_1,		"reset process command" },
	{  C_TS_TA_1,		"test command with time tag CP56Time2a" },
	{  P_ME_NA_1,		"parameter of measured value, normalized value" },
	{  P_ME_NB_1,		"parameter of measured value, scaled value" },
	{  P_ME_NC_1,		"parameter of measured value, short floating-point number" },
	{  P_AC_NA_1,		"parameter activation" },
	{  F_FR_NA_1,		"file ready" },
	{  F_SR_NA_1,		"section ready" },
	{  F_SC_NA_1,		"call directory, select file, call file, call section" },
	{  F_LS_NA_1,		"last section, last segment" },
	{  F_AF_NA_1,		"ack file, ack section" },
	{  F_SG_NA_1,		"segment" },
	{  F_DR_TA_1,		"directory" },
	{  F_SC_NB_1,		"Query Log - Request archive file" },
	{ 0, NULL }
};

typedef struct {
	uint8_t value;
	uint8_t length;
} td_asdu_length;

static const td_asdu_length asdu_length [] = {
	{  M_SP_NA_1,	 1 },
	{  M_SP_TA_1,	 4 },
	{  M_DP_NA_1,	 1 },
	{  M_DP_TA_1,	 4 },
	{  M_ST_NA_1,	 2 },
	{  M_ST_TA_1,	 5 },
	{  M_BO_NA_1,	 5 },
	{  M_BO_TA_1,	 8 },
	{  M_ME_NA_1,	 3 },
	{  M_ME_TA_1,	 6 },
	{  M_ME_NB_1,	 3 },
	{  M_ME_TB_1,	 6 },
	{  M_ME_NC_1,	 5 },
	{  M_ME_TC_1,	 8 },
	{  M_IT_NA_1,	 5 },
	{  M_IT_TA_1,	 8 },
	{  M_PS_NA_1,	 5 },
	{  M_ME_ND_1,	 2 },
	{  M_SP_TB_1,	 8 },
	{  M_DP_TB_1,	 8 },
	{  M_ST_TB_1,	 9 },
	{  M_BO_TB_1,	12 },
	{  M_ME_TD_1,	10 },
	{  M_ME_TE_1,	10 },
	{  M_ME_TF_1,	12 },
	{  M_IT_TB_1,	12 },
	{  M_EP_TD_1,	10 },
	{  M_EP_TE_1,	11 },
	{  M_EP_TF_1,	11 },
	{  S_IT_TC_1,   14 },
	{  C_SC_NA_1,	 1 },
	{  C_DC_NA_1,	 1 },
	{  C_RC_NA_1,	 1 },
	{  C_SE_NA_1,	 3 },
	{  C_SE_NB_1,	 3 },
	{  C_SE_NC_1,	 5 },
	{  C_BO_NA_1,	 4 },
	{  C_SC_TA_1,	 8 },
	{  C_DC_TA_1,	 8 },
	{  C_RC_TA_1,	 8 },
	{  C_SE_TA_1,	10 },
	{  C_SE_TB_1,	10 },
	{  C_SE_TC_1,	12 },
	{  C_BO_TA_1,	11 },
	{  M_EI_NA_1,	 1 },
	{  S_CH_NA_1,    0 },
	{  S_RP_NA_1,    0 },
	{  S_AR_NA_1,    0 },
	{  S_KR_NA_1,    0 },
	{  S_KS_NA_1,    0 },
	{  S_KC_NA_1,    0 },
	{  S_ER_NA_1,    0 },
	{  S_US_NA_1,    0 },
	{  S_UQ_NA_1,    0 },
	{  S_UR_NA_1,    0 },
	{  S_UK_NA_1,    0 },
	{  S_UA_NA_1,    0 },
	{  S_UC_NA_1,    0 },
	{  C_IC_NA_1,	 1 },
	{  C_CI_NA_1,	 1 },
	{  C_RD_NA_1,	 0 },
	{  C_CS_NA_1,	 7 },
	{  C_RP_NA_1,	 1 },
	{  C_TS_TA_1,	 9 },
	{  P_ME_NA_1,	 3 },
	{  P_ME_NB_1,	 3 },
	{  P_ME_NC_1,	 5 },
	{  P_AC_NA_1,	 1 },
	{  F_FR_NA_1,	 6 },
	{  F_SR_NA_1,	 7 },
	{  F_SC_NA_1,	 4 },
	{  F_LS_NA_1,	 5 },
	{  F_AF_NA_1,	 4 },
	{  F_SG_NA_1,	 0 },
	{  F_DR_TA_1,	13 },
	{  F_SC_NB_1,	16 },
	{ 0, 0 }
};

/* Cause of Transmission (CauseTx) */
#define Per_Cyc         1
#define Back            2
#define Spont           3
#define Init            4
#define Req             5
#define Act             6
#define ActCon          7
#define Deact           8
#define DeactCon        9
#define ActTerm         10
#define Retrem          11
#define Retloc          12
#define File            13
#define Auth            14
#define Seskey          15
#define Usrkey          16
#define Inrogen         20
#define Inro1           21
#define Inro2           22
#define Inro3           23
#define Inro4           24
#define Inro5           25
#define Inro6           26
#define Inro7           27
#define Inro8           28
#define Inro9           29
#define Inro10          30
#define Inro11          31
#define Inro12          32
#define Inro13          33
#define Inro14          34
#define Inro15          35
#define Inro16          36
#define Reqcogen        37
#define Reqco1          38
#define Reqco2          39
#define Reqco3          40
#define Reqco4          41
#define UkTypeId        44
#define UkCauseTx       45
#define UkComAdrASDU    46
#define UkIOA           47

static const value_string causetx_types [] = {
	{ Per_Cyc         ,"Per/Cyc" },
	{ Back            ,"Back" },
	{ Spont           ,"Spont" },
	{ Init            ,"Init" },
	{ Req             ,"Req" },
	{ Act             ,"Act" },
	{ ActCon          ,"ActCon" },
	{ Deact           ,"Deact" },
	{ DeactCon        ,"DeactCon" },
	{ ActTerm         ,"ActTerm" },
	{ Retrem          ,"Retrem" },
	{ Retloc          ,"Retloc" },
	{ File            ,"File" },
	{ Auth            ,"Auth" },
	{ Seskey          ,"Seskey" },
	{ Usrkey          ,"Usrkey" },
	{ Inrogen         ,"Inrogen" },
	{ Inro1           ,"Inro1" },
	{ Inro2           ,"Inro2" },
	{ Inro3           ,"Inro3" },
	{ Inro4           ,"Inro4" },
	{ Inro5           ,"Inro5" },
	{ Inro6           ,"Inro6" },
	{ Inro7           ,"Inro7" },
	{ Inro8           ,"Inro8" },
	{ Inro9           ,"Inro9" },
	{ Inro10          ,"Inro10" },
	{ Inro11          ,"Inro11" },
	{ Inro12          ,"Inro12" },
	{ Inro13          ,"Inro13" },
	{ Inro14          ,"Inro14" },
	{ Inro15          ,"Inro15" },
	{ Inro16          ,"Inro16" },
	{ Reqcogen        ,"Reqcogen" },
	{ Reqco1          ,"Reqco1" },
	{ Reqco2          ,"Reqco2" },
	{ Reqco3          ,"Reqco3" },
	{ Reqco4          ,"Reqco4" },
	{ UkTypeId        ,"UkTypeId" },
	{ UkCauseTx       ,"UkCauseTx" },
	{ UkComAdrASDU    ,"UkComAdrASDU" },
	{ UkIOA           ,"UkIOA" },
	{ 0, NULL }
};

static const value_string diq_types[] = {
	{ 0,		"Indeterminate or Intermediate" },
	{ 1,		"OFF" },
	{ 2,		"ON" },
	{ 3,		"Indeterminate" },
	{ 0, NULL }
};

static const value_string qos_qu_types[] = {
	{ 0,		"No pulse defined" },
	{ 1,		"Short Pulse" },
	{ 2,		"Long Pulse" },
	{ 3,		"Persistent Output" },
	{ 0, NULL }
};

static const value_string dco_on_types[] = {
	{ 0,		"(None)" },
	{ 1,		"OFF" },
	{ 2,		"ON" },
	{ 3,		"Error: On/Off not defined" },
	{ 0, NULL }
};

static const value_string rco_up_types[] = {
	{ 0,		"(None)" },
	{ 1,		"DOWN" },
	{ 2,		"UP" },
	{ 3,		"Error: Up/Down not defined" },
	{ 0, NULL }
};

static const value_string qpm_kpa_types[] = {
	{ 0,		"Not used" },
	{ 1,		"Threshold value" },
	{ 2,		"Smoothing factor (filter time constant)" },
	{ 0, NULL }
};

static const value_string qpm_lpc_types[] = {
	{ 0,		"No change" },
	{ 1,		"Change" },
	{ 0, NULL }
};

static const value_string qpm_pop_types[] = {
	{ 0,		"Operation" },
	{ 1,		"Not in operation" },
	{ 0, NULL }
};

static const value_string coi_r_types[] = {
	{ 0,		"Local power switch on" },
	{ 1,		"Local manual reset" },
	{ 2,		"Remote reset" },
	{ 0, NULL }
};

static const value_string qoi_r_types[] = {
	{ 0,		"Not specified" },
	{ 20,		"Station interrogation (global)" },
	{ 21,		"Group 1 interrogation" },
	{ 22,		"Group 2 interrogation" },
	{ 23,		"Group 3 interrogation" },
	{ 24,		"Group 4 interrogation" },
	{ 25,		"Group 5 interrogation" },
	{ 26,		"Group 6 interrogation" },
	{ 27,		"Group 7 interrogation" },
	{ 28,		"Group 8 interrogation" },
	{ 29,		"Group 9 interrogation" },
	{ 30,		"Group 10 interrogation" },
	{ 31,		"Group 11 interrogation" },
	{ 32,		"Group 12 interrogation" },
	{ 33,		"Group 13 interrogation" },
	{ 34,		"Group 14 interrogation" },
	{ 35,		"Group 15 interrogation" },
	{ 36,		"Group 16 interrogation" },
	{ 0, NULL }
};

static const value_string rqt_r_types[] = {
	{ 0,		"Not specified" },
	{ 1,		"Group 1 counter interrogation" },
	{ 2,		"Group 2 counter interrogation" },
	{ 3,		"Group 3 counter interrogation" },
	{ 4,		"Group 4 counter interrogation" },
	{ 5,		"General counter interrogation" },
	{ 0, NULL }
};

static const value_string frz_r_types[] = {
	{ 0,		"Read only (no freeze or reset)" },
	{ 1,		"Counter freeze without reset (value frozen represents integrated total)" },
	{ 2,		"Counter freeze with reset (value frozen represents incremental information)" },
	{ 3,		"Counter reset" },
	{ 0, NULL }
};

static const value_string qrp_r_types[] = {
	{ 0,		"Not used" },
	{ 1,		"General reset of process" },
	{ 2,		"Reset of pending information with time tag of the event buffer" },
	{ 0, NULL }
};

static const range_string usr_types[] = {
	{ 0,	0,	"(Unknown)" },
	{ 1,	1,	"Default" },
	{ 2,	65535,	"Chosen by the controlling station" },
	{ 0, 0, NULL }
};

static const range_string mal_types[] = {
	{ 0,	0,	"(not used)" },
	{ 1,	1,	"HMAC SHA-1 truncated to 4 octets (serial)" },
	{ 2,	2,	"HMAC SHA-1 truncated to 10 octets (networked)" },
	{ 3,	3,	"HMAC-SHA-256 truncated to 8 octets (serial)" },
	{ 4,	4,	"HMAC-SHA-256 truncated to 16 octets (networked)" },
	{ 128,	255,	"(vendor-specific choice)" },
	{ 0, 0, NULL }
};

static const value_string rsc_types[] = {
	{ 0,		"(not used)" },
	{ 1,		"CRITICAL" },
	{ 0, NULL }
};

static const range_string kwa_types[] = {
	{ 0,	0,	"(not used)" },
	{ 1,	1,	"AES-128 Key Wrap Algorithm" },
	{ 2,	2,	"AES-256 Key Wrap Algorithm" },
	{ 128,	255,	"(vendor-specific choice)" },
	{ 0, 0, NULL }
};

static const value_string kst_types[] = {
	{ 0,		"(not used)" },
	{ 1,		"OK" },
	{ 2,		"NOT INIT" },
	{ 3,		"COMM FAIL" },
	{ 4,		"AUTH FAIL" },
	{ 0, NULL }
};

static const range_string hal_types[] = {
	{ 0,	0,	"No MAC value in this message" },
	{ 1,	1,	"HMAC SHA-1 truncated to 4 octets (serial)" },
	{ 2,	2,	"HMAC SHA-1 truncated to 10 octets (networked)" },
	{ 3,	3,	"HMAC-SHA-256 truncated to 8 octets (serial)" },
	{ 4,	4,	"HMAC-SHA-256 truncated to 16 octets (networked)" },
	{ 128,	255,	"(vendor-specific choice)" },
	{ 0, 0, NULL }
};

static const range_string error_codes[] = {
	{ 0,	0,	"(not used)" },
	{ 1,	1,	"Authentication failed" },
	{ 2,	2,	"Unexpected reply" },
	{ 3,	3,	"No reply" },
	{ 4,	4,	"Aggressive Mode not permitted" },
	{ 5,	5,	"MAC algorithm not permitted" },
	{ 6,	6,	"Key Wrap algorithm not permitted" },
	{ 7,	7,	"Authorization failed" },
	{ 8,	8,	"Update Key Change Method not permitted" },
	{ 9,	9,	"Invalid Signature" },
	{ 10,	10,	"Invalid Certification Data" },
	{ 11,	11,	"Unknown User" },
	{ 128, 255,	"(vendor-specific choice)"},
	{ 0, 0, NULL }
};

static const true_false_string tfs_blocked_not_blocked = { "Blocked", "Not blocked" };
static const true_false_string tfs_substituted_not_substituted = { "Substituted", "Not Substituted" };
static const true_false_string tfs_not_topical_topical = { "Not Topical", "Topical" };
static const true_false_string tfs_transient_not_transient = { "Transient", "Not Transient" };
static const true_false_string tfs_overflow_no_overflow = { "Overflow", "No overflow" };
static const true_false_string tfs_select_execute = { "Select", "Execute" };
static const true_false_string tfs_local_dst = { "DST", "Local" };
static const true_false_string tfs_coi_i = { "Initialisation after change of local parameters", "Initialisation with unchanged local parameters" };
static const true_false_string tfs_adjusted_not_adjusted = { "Adjusted", "Not Adjusted" };

static unsigned global_iec60870_link_addr_len = 1;
static unsigned global_iec60870_cot_len = 1;
static unsigned global_iec60870_asdu_addr_len = 1;
static unsigned global_iec60870_ioa_len = 2;

/* Protocol fields to be filtered */
static int hf_apdulen;
static int hf_apcitype_i;
static int hf_apcitype_s_u;
static int hf_apciutype;
static int hf_apcitx;
static int hf_apcirx;
static int hf_apcidata;

static int hf_addr;
static int hf_oa;
static int hf_typeid;
static int hf_causetx;
static int hf_nega;
static int hf_test;
static int hf_ioa;
static int hf_numix;
static int hf_sq;
static int hf_cp24time;
static int hf_cp24time_ms;
static int hf_cp24time_min;
static int hf_cp24time_iv;
static int hf_cp56time;
static int hf_cp56time_ms;
static int hf_cp56time_min;
static int hf_cp56time_gen;
static int hf_cp56time_iv;
static int hf_cp56time_hour;
static int hf_cp56time_su;
static int hf_cp56time_day;
static int hf_cp56time_dow;
static int hf_cp56time_month;
static int hf_cp56time_year;
static int hf_siq;
static int hf_siq_spi;
static int hf_siq_bl;
static int hf_siq_sb;
static int hf_siq_nt;
static int hf_siq_iv;
static int hf_diq;
static int hf_diq_dpi;
static int hf_diq_bl;
static int hf_diq_sb;
static int hf_diq_nt;
static int hf_diq_iv;
static int hf_qds;
static int hf_qds_ov;
static int hf_qds_bl;
static int hf_qds_sb;
static int hf_qds_nt;
static int hf_qds_iv;
static int hf_vti;
static int hf_vti_v;
static int hf_vti_t;
static int hf_qos;
static int hf_qos_ql;
static int hf_qos_se;
static int hf_sco;
static int hf_sco_on;
static int hf_sco_qu;
static int hf_sco_se;
static int hf_dco;
static int hf_dco_on;
static int hf_dco_qu;
static int hf_dco_se;
static int hf_rco;
static int hf_rco_up;
static int hf_rco_qu;
static int hf_rco_se;
static int hf_qpm;
static int hf_qpm_kpa;
static int hf_qpm_lpc;
static int hf_qpm_pop;
static int hf_asn;
static int hf_usr;
static int hf_iec60870_segment_data;
static int hf_mal;
static int hf_rsc;
static int hf_asn_fin;
static int hf_asn_fir;
static int hf_csq;
static int hf_ksq;
static int hf_kwa;
static int hf_kst;
static int hf_hln;
static int hf_hal;
static int hf_cln;
static int hf_wkl;
static int hf_prcd_raw_data;
static int hf_hmac_raw_data;
static int hf_wkd_raw_data;
static int hf_aid;
static int hf_err;
static int hf_etm;
static int hf_etm_ms;
static int hf_etm_min;
static int hf_etm_iv;
static int hf_etm_hour;
static int hf_etm_su;
static int hf_etm_day;
static int hf_etm_dow;
static int hf_etm_month;
static int hf_etm_year;
static int hf_eln;
static int hf_error_text;
static int hf_coi;
static int hf_coi_r;
static int hf_coi_i;
static int hf_qoi;
static int hf_qcc;
static int hf_qcc_rqt;
static int hf_qcc_frz;
static int hf_qrp;
static int hf_bcr;
static int hf_bcr_count;
static int hf_bcr_sq;
static int hf_bcr_cy;
static int hf_bcr_ca;
static int hf_bcr_iv;
static int hf_start;

static int hf_asdu_bitstring;
static int hf_asdu_float;
static int hf_asdu_normval;
static int hf_asdu_scalval;
static int hf_asdu_tsc;
static int hf_asdu_raw_data;

static int ett_apci;
static int ett_asdu;
static int ett_asdu_objects;
static int ett_siq;
static int ett_diq;
static int ett_vti;
static int ett_qds;
static int ett_qos;
static int ett_sco;
static int ett_dco;
static int ett_rco;
static int ett_qpm;
static int ett_coi;
static int ett_qcc;
static int ett_cp24time;
static int ett_cp56time;
static int ett_etm;

static int ett_iec60870_segment;
static int ett_iec60870_segments;

static expert_field ei_iec104_short_asdu;
static expert_field ei_iec104_apdu_min_len;
static expert_field ei_iec104_apdu_invalid_len;

/* IEC 101 stuff */
/* Initialize the protocol and registered fields */
static int hf_iec60870_101_frame;
static int hf_iec60870_101_length;
static int hf_iec60870_101_num_user_octets;
static int hf_iec60870_101_ctrlfield;
static int hf_iec60870_101_ctrl_prm;
static int hf_iec60870_101_ctrl_fcb;
static int hf_iec60870_101_ctrl_fcv;
static int hf_iec60870_101_ctrl_dfc;
static int hf_iec60870_101_ctrl_func_pri_to_sec;
static int hf_iec60870_101_ctrl_func_sec_to_pri;
static int hf_iec60870_101_linkaddr;
static int hf_iec60870_101_checksum;
static int hf_iec60870_101_stopchar;

static int hf_iec60870_segments;
static int hf_iec60870_segment;
static int hf_iec60870_segment_overlap;
static int hf_iec60870_segment_overlap_conflict;
static int hf_iec60870_segment_multiple_tails;
static int hf_iec60870_segment_too_long_segment;
static int hf_iec60870_segment_error;
static int hf_iec60870_segment_count;
static int hf_iec60870_reassembled_in;
static int hf_iec60870_reassembled_length;

static const fragment_items iec60870_frag_items = {
  &ett_iec60870_segment,
  &ett_iec60870_segments,
  &hf_iec60870_segments,
  &hf_iec60870_segment,
  &hf_iec60870_segment_overlap,
  &hf_iec60870_segment_overlap_conflict,
  &hf_iec60870_segment_multiple_tails,
  &hf_iec60870_segment_too_long_segment,
  &hf_iec60870_segment_error,
  &hf_iec60870_segment_count,
  &hf_iec60870_reassembled_in,
  &hf_iec60870_reassembled_length,
  /* Reassembled data field */
  NULL,
  "segments"
};

/* Initialize the subtree pointers */
static int ett_iec60870_101;
static int ett_iec60870_101_ctrlfield;

static expert_field ei_iec101_frame_mismatch;
static expert_field ei_iec101_length_mismatch;
static expert_field ei_iec101_stopchar_invalid;

/* Frame Format */
#define IEC101_VAR_LEN        0x68
#define IEC101_FIXED_LEN      0x10
#define IEC101_SINGLE_CHAR    0xE5
#define IEC101_STOP_CHAR      0x16

static const value_string iec60870_101_frame_vals[] = {
	{ IEC101_VAR_LEN,         "Variable Length" },
	{ IEC101_FIXED_LEN,       "Fixed Length" },
	{ IEC101_SINGLE_CHAR,     "Single Character" },
	{ 0,                         NULL }
};

static const value_string iec60870_101_ctrl_prm_values[] = {
	{ 0,      "Message from Secondary (Responding) Station" },
	{ 1,      "Message from Primary (Initiating) Station" },
	{ 0,      NULL }
};

static const value_string iec60870_101_ctrl_func_pri_to_sec_values[] = {
	{ 0,      "Reset of Remote Link" },
	{ 1,      "Reset of User Process" },
	{ 2,      "Reserved for Balanced Mode" },
	{ 3,      "User Data" },
	{ 4,      "User Data" },
	{ 5,      "Reserved" },
	{ 6,      "Reserved" },
	{ 7,      "Reserved" },
	{ 8,      "Expected Response Specifies Access Demand" },
	{ 9,      "Request Status of Link" },
	{ 10,     "Request User Data Class 1" },
	{ 11,     "Request User Data Class 2" },
	{ 12,     "Reserved" },
	{ 13,     "Reserved" },
	{ 14,     "Reserved" },
	{ 15,     "Reserved" },
	{ 0,      NULL }
};

static const value_string iec60870_101_ctrl_func_sec_to_pri_values[] = {
	{ 0,      "ACK: Positive Acknowledgement" },
	{ 1,      "NACK: Message Not Accepted, Link Busy" },
	{ 2,      "Reserved" },
	{ 3,      "Reserved" },
	{ 4,      "Reserved" },
	{ 5,      "Reserved" },
	{ 6,      "Reserved" },
	{ 7,      "Reserved" },
	{ 8,      "User Data" },
	{ 9,      "NACK: Requested Data not Available" },
	{ 10,     "Reserved" },
	{ 11,     "Status of Link" },
	{ 12,     "Reserved" },
	{ 13,     "Reserved" },
	{ 14,     "Link Service not Functioning" },
	{ 15,     "Link Service not Implemented" },
	{ 0,      NULL }
};

/* IEC 60870-5-103 Variables */
/* Initialize the protocol and registered fields */
static int hf_iec60870_5_103_areva_cmd;
static int hf_iec60870_5_103_asdu_address;
static int hf_iec60870_5_103_asdu_typeid_mon;
static int hf_iec60870_5_103_asdu_typeid_ctrl;
static int hf_iec60870_5_103_asdu205_ms;
static int hf_iec60870_5_103_asdu205_min;
static int hf_iec60870_5_103_asdu205_h;
static int hf_iec60870_5_103_asdu205_value;
static int hf_iec60870_5_103_checksum;
static int hf_iec60870_5_103_col;
static int hf_iec60870_5_103_cot_mon;
static int hf_iec60870_5_103_cot_ctrl;
static int hf_iec60870_5_103_cp32time2a;
static int hf_iec60870_5_103_cp32time2a_ms;
static int hf_iec60870_5_103_cp32time2a_min;
static int hf_iec60870_5_103_cp32time2a_res1;
static int hf_iec60870_5_103_cp32time2a_iv;
static int hf_iec60870_5_103_cp32time2a_hr;
static int hf_iec60870_5_103_cp32time2a_res2;
static int hf_iec60870_5_103_cp32time2a_sum;
static int hf_iec60870_5_103_ctrlfield;
static int hf_iec60870_5_103_ctrl_prm;
static int hf_iec60870_5_103_ctrl_fcb;
static int hf_iec60870_5_103_ctrl_fcv;
static int hf_iec60870_5_103_ctrl_dfc;
static int hf_iec60870_5_103_ctrl_func_pri_to_sec;
static int hf_iec60870_5_103_ctrl_func_sec_to_pri;
static int hf_iec60870_5_103_dco;
static int hf_iec60870_5_103_dpi;
static int hf_iec60870_5_103_frame;
static int hf_iec60870_5_103_func_type;
static int hf_iec60870_5_103_info_num;
static int hf_iec60870_5_103_length;
static int hf_iec60870_5_103_linkaddr;
static int hf_iec60870_5_103_mfg;
static int hf_iec60870_5_103_mfg_sw;
static int hf_iec60870_5_103_num_user_octets;
static int hf_iec60870_5_103_rii;
static int hf_iec60870_5_103_scn;
static int hf_iec60870_5_103_sin;
static int hf_iec60870_5_103_sq;
static int hf_iec60870_5_103_stopchar;

/* Initialize the subtree pointers */
static int ett_iec60870_5_103;
static int ett_iec60870_5_103_ctrlfield;
static int ett_iec60870_5_103_cp32time2a;

/* Frame Format */
#define IEC103_VAR_LEN        0x68
#define IEC103_FIXED_LEN      0x10
#define IEC103_SINGLE_CHAR    0xE5

/* Frame Format */
static const value_string iec60870_5_103_frame_vals[] = {
	{ IEC103_VAR_LEN,         "Variable Length" },
	{ IEC103_FIXED_LEN,       "Fixed Length" },
	{ IEC103_SINGLE_CHAR,     "Single Character" },
	{ 0,                         NULL }
};

static const value_string iec60870_5_103_ctrl_prm_values[] = {
	{ 0,      "Message from Secondary (Responding) Station" },
	{ 1,      "Message from Primary (Initiating) Station" },
	{ 0,      NULL }
};

static const value_string iec60870_5_103_ctrl_func_pri_to_sec_values[] = {
	{ 0,     "Reset of Communications Unit" },
	{ 1,     "Reserved" },
	{ 2,     "Reserved" },
	{ 3,     "Send / Confirm Expected" },
	{ 4,     "Send / No Confirm Expected" },
	{ 5,     "Reserved" },
	{ 6,     "Reserved" },
	{ 7,     "Reset Frame Count Bit" },
	{ 8,     "Reserved" },
	{ 9,     "Request Status of Link" },
	{ 10,    "Request User Data Class 1" },
	{ 11,    "Request User Data Class 2" },
	{ 12,    "Reserved" },
	{ 13,    "Reserved" },
	{ 14,    "Reserved" },
	{ 15,    "Reserved" },
	{ 0,     NULL }
};

static const value_string iec60870_5_103_ctrl_func_sec_to_pri_values[] = {
	{ 0,     "ACK: Positive Acknowledgement" },
	{ 1,     "NACK: Message Not Accepted, Link Busy" },
	{ 2,     "Reserved" },
	{ 3,     "Reserved" },
	{ 4,     "Reserved" },
	{ 5,     "Reserved" },
	{ 6,     "Reserved" },
	{ 7,     "Reserved" },
	{ 8,     "ACK: User Data" },
	{ 9,     "NACK: Requested Data not Available" },
	{ 10,    "Reserved" },
	{ 11,    "Status of Link" },
	{ 12,    "Reserved" },
	{ 13,    "Reserved" },
	{ 14,    "Link Service not Functioning" },
	{ 15,    "Link Service not Implemented" },
	{ 0,     NULL }
};

/* IEC 60870-5-103 ASDU types (TypeId); monitor direction */
static const value_string iec103_asdu_types_monitor_dir [] = {
	{  1,		"Time tagged message" },    /* dissection implemented */
	{  2,		"Time tagged message with relative time" },
	{  3,		"Measurands I" },
	{  4,		"Time tagged measurands with relative time" },
	{  5,		"Identification" },    /* dissection implemented */
	{  6,		"Time synchronization" },    /* dissection implemented */
	{  8,		"General interrogation termination" },    /* dissection implemented */
	{  9,		"Measurands II" },    /* dissection implemented */
	{  10,		"Generic data" },
	{  11,		"Generic identification" },
	{  12,		"reserved" },
	{  13,		"reserved" },
	{  14,		"reserved" },
	{  15,		"reserved" },
	{  16,		"reserved" },
	{  17,		"reserved" },
	{  18,		"reserved" },
	{  19,		"reserved" },
	{  20,		"reserved" },
	{  21,		"reserved" },
	{  22,		"reserved" },
	{  23,		"List of recorded disturbances" },
	{  24,		"reserved" },
	{  25,		"reserved" },
	{  26,		"Ready for transmission of disturbance data" },
	{  27,		"Ready for transmission of a channel" },
	{  28,		"Ready for transmission of tags" },
	{  29,		"Transmission of tags" },
	{  30,		"Transmission of disturbance values" },
	{  31,		"End of transmission" },
	{  205,     "Private, Siemens energy counters"},    /* dissection implemented */
	{  0,		NULL }
};

/* IEC 60870-5-103 ASDU types (TypeId); control direction */
static const value_string iec103_asdu_types_control_dir [] = {
	{  1,		"reserved" },
	{  2,		"reserved" },
	{  3,		"reserved" },
	{  4,		"reserved" },
	{  5,		"reserved" },
	{  6,		"Time synchronization" },    /* dissection implemented */
	{  7,		"General interrogation" },    /* dissection implemented */
	{  8,		"reserved" },
	{  9,		"reserved" },
	{  10,		"Generic data" },
	{  11,		"reserved" },
	{  12,		"reserved" },
	{  13,		"reserved" },
	{  14,		"reserved" },
	{  15,		"reserved" },
	{  16,		"reserved" },
	{  17,		"reserved" },
	{  18,		"reserved" },
	{  19,		"reserved" },
	{  20,		"General command" },    /* dissection implemented */
	{  21,		"Generic command" },
	{  22,		"reserved" },
	{  23,		"reserved" },
	{  24,		"Order for disturbance data transmission" },
	{  25,		"Acknowledgement for disturbance data transmission" },
	{  26,		"reserved" },
	{  27,		"reserved" },
	{  28,		"reserved" },
	{  29,		"reserved" },
	{  30,		"reserved" },
	{  31,		"reserved" },
	{  45,		"Private, Areva Single Command" },    /* dissection implemented */
	{  46,		"Private, Areva Double Command" },    /* dissection implemented */
	{  0,		NULL }
};

static const value_string iec60870_5_103_cot_monitor_dir [] = {
	{ 1,     "Spontaneous" },
	{ 2,     "Cyclic" },
	{ 3,     "Reset frame count bit (FCB)" },
	{ 4,     "Reset communication unit (CU)" },
	{ 5,     "Start / restart" },
	{ 6,     "Power on" },
	{ 7,     "Test mode" },
	{ 8,     "Time synchronization" },
	{ 9,     "General interrogation" },
	{ 10,    "Termination of general interrogation" },
	{ 11,    "Local operation" },
	{ 12,    "Remote operation" },
	{ 20,    "Positive acknowledgement of command" },
	{ 21,    "Negative acknowledgement of command" },
	{ 31,    "Transmission of disturbance data" },
	{ 40,    "Positive acknowledgement of generic write command" },
	{ 41,    "Negative acknowledgement of generic write command" },
	{ 42,    "Valid data response to generic read command" },
	{ 43,    "Invalid data response to generic read command" },
	{ 44,    "Generic write confirmation" },
	{ 0,     NULL }
};

static const value_string iec60870_5_103_cot_ctrl_dir [] = {
	{ 8,     "Time synchronization" },
	{ 9,     "Initiation of general interrogation" },
	{ 20,    "General command" },
	{ 31,    "Transmission of disturbance data" },
	{ 40,    "Generic write command" },
	{ 42,    "Generic read command" },
	{ 0,     NULL }
};


static const value_string iec103_quadstate_types[] = {
	{ 0,      "Not used" },
	{ 1,      "OFF" },
	{ 2,      "ON" },
	{ 3,      "Not used" },
	{ 0,      NULL }
};

/* Misc. functions for dissection of signal values */

/* ====================================================================
   Dissects the CP24Time2a time (Three octet binary time)
   that starts 'offset' bytes in 'tvb'.
   ==================================================================== */
static void get_CP24Time(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	uint16_t ms;
	uint8_t min;
	nstime_t nstime;
	proto_item* ti;
	proto_tree* cp24time_tree;

	ms = tvb_get_letohs(tvb, *offset);
	nstime.nsecs = (ms % 1000) * 1000000;
	nstime.secs = ms / 1000;
	(*offset) += 2;

	min = tvb_get_uint8(tvb, *offset);
	nstime.secs += (min & 0x3F) * 60;
	(*offset)++;

	(*offset) -= 3;

	ti = proto_tree_add_time(iec104_header_tree, hf_cp24time, tvb, *offset, 3, &nstime);
	cp24time_tree = proto_item_add_subtree(ti, ett_cp24time);

	proto_tree_add_item(cp24time_tree, hf_cp24time_ms, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	(*offset) += 2;

	proto_tree_add_item(cp24time_tree, hf_cp24time_min, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cp24time_tree, hf_cp24time_iv, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset) ++;
}

/* ====================================================================
   Dissect a CP32Time2a (four octet binary time), add to proto tree
   ==================================================================== */
static void get_CP32TimeA(tvbuff_t *tvb, uint8_t *offset, proto_tree *tree)
{
	uint16_t ms;
	uint8_t value;
	nstime_t  datetime;
	struct tm tm = {0};
	proto_item* ti;
	proto_tree* cp32time2a_tree;

	ms = tvb_get_letohs(tvb, *offset);
	tm.tm_sec = ms / 1000;
	datetime.nsecs = (ms % 1000) * 1000000;

	value = tvb_get_uint8(tvb, *offset+2);
	tm.tm_min = value & 0x3F;

	value = tvb_get_uint8(tvb, *offset+3);
	tm.tm_hour = value & 0x1F;

	/* The CP32Time2a structure does not contain any mm/dd/yyyy information.  Set these as default to 1/1/2000 */
	tm.tm_mday = 1;
	tm.tm_mon = 0;
	tm.tm_year = 100;

	datetime.secs = mktime(&tm);

	ti = proto_tree_add_time(tree, hf_iec60870_5_103_cp32time2a, tvb, *offset, 4, &datetime);
	cp32time2a_tree = proto_item_add_subtree(ti, ett_iec60870_5_103_cp32time2a);

	proto_tree_add_item(cp32time2a_tree, hf_iec60870_5_103_cp32time2a_ms, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cp32time2a_tree, hf_iec60870_5_103_cp32time2a_min, tvb, *offset+2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cp32time2a_tree, hf_iec60870_5_103_cp32time2a_res1, tvb, *offset+2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cp32time2a_tree, hf_iec60870_5_103_cp32time2a_iv, tvb, *offset+2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cp32time2a_tree, hf_iec60870_5_103_cp32time2a_hr, tvb, *offset+3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cp32time2a_tree, hf_iec60870_5_103_cp32time2a_res2, tvb, *offset+3, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cp32time2a_tree, hf_iec60870_5_103_cp32time2a_sum, tvb, *offset+3, 1, ENC_LITTLE_ENDIAN);

	(*offset) += 4;
}

/* ====================================================================
   Dissects the CP56Time2a time (Seven octet binary time)
   that starts 'offset' bytes in 'tvb'.
   ==================================================================== */
static void get_CP56Time(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	uint16_t ms;
	uint8_t value;
	uint8_t su;
	struct tm tm;
	nstime_t  datetime;
	proto_item* ti;
	proto_tree* cp56time_tree;

	ms = tvb_get_letohs(tvb, *offset);
	tm.tm_sec = ms / 1000;
	datetime.nsecs = (ms % 1000) * 1000000;
	(*offset) += 2;

	value = tvb_get_uint8(tvb, *offset);
	tm.tm_min = value & 0x3F;
	(*offset)++;

	value = tvb_get_uint8(tvb, *offset);
	tm.tm_hour = value & 0x1F;
	su = value & 0x80;
	(*offset)++;

	value = tvb_get_uint8(tvb, *offset);
	tm.tm_mday = value & 0x1F;
	(*offset)++;

	value = tvb_get_uint8(tvb, *offset);
	tm.tm_mon = (value & 0x0F) - 1;
	(*offset)++;

	value = tvb_get_uint8(tvb, *offset);
	tm.tm_year = value & 0x7F;
	if (tm.tm_year < 70)
		tm.tm_year += 100;

	(*offset)++;

	if (su)
		tm.tm_isdst = 1;
	else
		tm.tm_isdst = -1; /* there's no info on whether DST was in force; assume it's
				   * the same as currently */

	datetime.secs = mktime(&tm);

	(*offset) -= 7;

	ti = proto_tree_add_time(iec104_header_tree, hf_cp56time, tvb, *offset, 7, &datetime);
	cp56time_tree = proto_item_add_subtree(ti, ett_cp56time);

	proto_tree_add_item(cp56time_tree, hf_cp56time_ms, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	(*offset) += 2;

	proto_tree_add_item(cp56time_tree, hf_cp56time_min, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cp56time_tree, hf_cp56time_gen, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cp56time_tree, hf_cp56time_iv, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset) ++;

	proto_tree_add_item(cp56time_tree, hf_cp56time_hour, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cp56time_tree, hf_cp56time_su, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset) ++;

	proto_tree_add_item(cp56time_tree, hf_cp56time_day, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(cp56time_tree, hf_cp56time_dow, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset) ++;

	proto_tree_add_item(cp56time_tree, hf_cp56time_month, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset) ++;

	proto_tree_add_item(cp56time_tree, hf_cp56time_year, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset) ++;
}

/* ====================================================================
   Information object address (Identifier)
   ASDU -> Inform Object #1 -> Information object address
   ==================================================================== */
static proto_item* get_InfoObjectAddress(uint32_t *asdu_info_obj_addr, tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree, unsigned ioa_len)
{
	proto_item* ti = NULL;

	/* Information object address */
	/* Support both 16 and 24-bit IOA addresses */
	ti = proto_tree_add_item_ret_uint(iec104_header_tree, hf_ioa, tvb, *offset, ioa_len, ENC_LITTLE_ENDIAN, asdu_info_obj_addr);
	(*offset) += ioa_len;

	return ti;
}

/* ====================================================================
   TypeId length
   ==================================================================== */
static uint8_t get_TypeIdLength(uint8_t TypeId)
{
	uint8_t ret = 0;
	const td_asdu_length *item;

	item = asdu_length;
	while (item->value)
	{
		if (item->value == TypeId)
		{
			ret = item->length;
			break;
		}
		item++;
	}

	return ret;
}

/* ====================================================================
   SIQ: Single-point information (IEV 371-02-07) w quality descriptor
   ==================================================================== */
static void get_SIQ(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_item* ti;
	proto_tree* siq_tree;

	ti = proto_tree_add_item(iec104_header_tree, hf_siq, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	siq_tree = proto_item_add_subtree(ti, ett_siq);

	proto_tree_add_item(siq_tree, hf_siq_spi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(siq_tree, hf_siq_bl, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(siq_tree, hf_siq_sb, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(siq_tree, hf_siq_nt, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(siq_tree, hf_siq_iv, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
   DIQ: Double-point information (IEV 371-02-08) w quality descriptor
   ==================================================================== */
static void get_DIQ(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_item* ti;
	proto_tree* diq_tree;

	ti = proto_tree_add_item(iec104_header_tree, hf_diq, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	diq_tree = proto_item_add_subtree(ti, ett_diq);

	proto_tree_add_item(diq_tree, hf_diq_dpi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(diq_tree, hf_diq_bl, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(diq_tree, hf_diq_sb, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(diq_tree, hf_diq_nt, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(diq_tree, hf_diq_iv, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
   QDS: Quality descriptor (separate octet)
   ==================================================================== */
static void get_QDS(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_item* ti;
	proto_tree* qds_tree;

	ti = proto_tree_add_item(iec104_header_tree, hf_qds, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	qds_tree = proto_item_add_subtree(ti, ett_qds);

	proto_tree_add_item(qds_tree, hf_qds_ov, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qds_tree, hf_qds_bl, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qds_tree, hf_qds_sb, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qds_tree, hf_qds_nt, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qds_tree, hf_qds_iv, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
   QDP: Quality descriptor for events of protection equipment
   (separate octet)
   ==================================================================== */
#if 0
static void get_QDP(tvbuff_t *tvb _U_, uint8_t *offset _U_, proto_tree *iec104_header_tree _U_)
{
	/* todo */

}
#endif

/* ====================================================================
   VTI: Value with transient state indication
   ==================================================================== */
static void get_VTI(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_item* ti;
	proto_tree* vti_tree;

	ti = proto_tree_add_item(iec104_header_tree, hf_vti, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	vti_tree = proto_item_add_subtree(ti, ett_vti);

	proto_tree_add_item(vti_tree, hf_vti_v, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(vti_tree, hf_vti_t, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
   NVA: Normalized value
   ==================================================================== */
static void get_NVA(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	int16_t value;
	float fvalue;

	value = tvb_get_letohis(tvb, *offset);
	fvalue = (float)value / 32768;

	/* Normalized value F16[1..16]<-1..+1-2^-15> */
	proto_tree_add_float_format_value(iec104_header_tree, hf_asdu_normval, tvb, *offset, 2, fvalue, "%." G_STRINGIFY(FLT_DIG) "g (%d)", fvalue, value);

	(*offset) += 2;
}

static void get_NVAspt(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	int16_t value;
	float fvalue;

	value = tvb_get_letohis(tvb, *offset);
	fvalue = (float)value / 32768;

	/* Normalized value F16[1..16]<-1..+1-2^-15> */
	proto_tree_add_float_format_value(iec104_header_tree, hf_asdu_normval, tvb, *offset, 2, fvalue, "%." G_STRINGIFY(FLT_DIG) "g (%d)", fvalue, value);

	(*offset) += 2;
}

/* ====================================================================
   SVA: Scaled value
   ==================================================================== */
static void get_SVA(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	/* Scaled value I16[1..16]<-2^15..+2^15-1> */
	proto_tree_add_item(iec104_header_tree, hf_asdu_scalval, tvb, *offset, 2, ENC_LITTLE_ENDIAN);

	(*offset) += 2;
}

static void get_SVAspt(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	/* Scaled value I16[1..16]<-2^15..+2^15-1> */
	proto_tree_add_item(iec104_header_tree, hf_asdu_scalval, tvb, *offset, 2, ENC_LITTLE_ENDIAN);

	(*offset) += 2;
}

/* ====================================================================
   TSC: Test sequence counter
   ==================================================================== */
static void get_TSC(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_tree_add_item(iec104_header_tree, hf_asdu_tsc, tvb, *offset, 2, ENC_LITTLE_ENDIAN);

	(*offset) += 2;
}

/* ====================================================================
   "FLT": Short floating point number
   ==================================================================== */
static void get_FLT(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	/* --------  IEEE 754 float value */
	proto_tree_add_item(iec104_header_tree, hf_asdu_float, tvb, *offset, 4, ENC_LITTLE_ENDIAN);

	(*offset) += 4;
}

static void get_FLTspt(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	/* --------  IEEE 754 float value */
	proto_tree_add_item(iec104_header_tree, hf_asdu_float, tvb, *offset, 4, ENC_LITTLE_ENDIAN);

	(*offset) += 4;
}

/* ====================================================================
   "BSI": Binary state information, 32 bit
   ==================================================================== */
static void get_BSI(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_tree_add_bits_item(iec104_header_tree, hf_asdu_bitstring, tvb, *offset*8, 32, ENC_BIG_ENDIAN);

	(*offset) += 4;
}

static void get_BSIspt(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_tree_add_bits_item(iec104_header_tree, hf_asdu_bitstring, tvb, *offset*8, 32, ENC_BIG_ENDIAN);

	(*offset) += 4;
}

/* ====================================================================
    BCR: Binary counter reading
   ==================================================================== */
static void get_BCR(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_item* ti;
	proto_tree* bcr_tree;

	ti = proto_tree_add_item(iec104_header_tree, hf_bcr, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
	bcr_tree = proto_item_add_subtree(ti, ett_vti);

	proto_tree_add_item(bcr_tree, hf_bcr_count, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
	(*offset) += 4;

	proto_tree_add_item(bcr_tree, hf_bcr_sq, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(bcr_tree, hf_bcr_cy, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(bcr_tree, hf_bcr_ca, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(bcr_tree, hf_bcr_iv, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
}

/* ====================================================================
    todo -- SEP: Single event of protection equipment
   ==================================================================== */
#if 0
static void get_SEP(tvbuff_t *tvb _U_, uint8_t *offset _U_, proto_tree *iec104_header_tree _U_)
{
	/* todo */

}
#endif

/* ====================================================================
    QOS: Qualifier Of Set-point command
   ==================================================================== */
static void get_QOS(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_item* ti;
	proto_tree* qos_tree;

	ti = proto_tree_add_item(iec104_header_tree, hf_qos, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	qos_tree = proto_item_add_subtree(ti, ett_qos);

	proto_tree_add_item(qos_tree, hf_qos_ql, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qos_tree, hf_qos_se, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
    SCO: Single Command (IEV 371-03-02)
   ==================================================================== */
static void get_SCO(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_item* ti;
	proto_tree* sco_tree;

	ti = proto_tree_add_item(iec104_header_tree, hf_sco, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	sco_tree = proto_item_add_subtree(ti, ett_sco);

	proto_tree_add_item(sco_tree, hf_sco_on, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sco_tree, hf_sco_qu, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(sco_tree, hf_sco_se, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
    DCO: Double Command (IEV 371-03-03)
   ==================================================================== */
static void get_DCO(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_item* ti;
	proto_tree* dco_tree;

	ti = proto_tree_add_item(iec104_header_tree, hf_dco, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	dco_tree = proto_item_add_subtree(ti, ett_dco);

	proto_tree_add_item(dco_tree, hf_dco_on, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(dco_tree, hf_dco_qu, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(dco_tree, hf_dco_se, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
    RCO: Regulating step command (IEV 371-03-13)
   ==================================================================== */
static void get_RCO(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_item* ti;
	proto_tree* rco_tree;

	ti = proto_tree_add_item(iec104_header_tree, hf_rco, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	rco_tree = proto_item_add_subtree(ti, ett_rco);

	proto_tree_add_item(rco_tree, hf_rco_up, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(rco_tree, hf_rco_qu, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(rco_tree, hf_rco_se, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
    QPM: Qualifier of parameter of measured value
   ==================================================================== */
static void get_QPM(tvbuff_t* tvb, uint8_t* offset, proto_tree* iec104_header_tree)
{
	proto_item* ti;
	proto_tree* qpm_tree;

	ti = proto_tree_add_item(iec104_header_tree, hf_qpm, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	qpm_tree = proto_item_add_subtree(ti, ett_qpm);

	proto_tree_add_item(qpm_tree, hf_qpm_kpa, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qpm_tree, hf_qpm_lpc, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qpm_tree, hf_qpm_pop, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
    USR: User Number
   ==================================================================== */
static void get_USR(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_tree_add_item(iec104_header_tree, hf_usr, tvb, *offset, 2, ENC_LITTLE_ENDIAN);

	(*offset) += 2;
}

/* ====================================================================
    MAL: MAC algorithm
   ==================================================================== */
static void get_MAL(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_tree_add_item(iec104_header_tree, hf_mal, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
    RSC: Reason for challenge
   ==================================================================== */
static void get_RSC(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_tree_add_item(iec104_header_tree, hf_rsc, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
    CSQ: Challenge sequence number
   ==================================================================== */
static void get_CSQ(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_tree_add_item(iec104_header_tree, hf_csq, tvb, *offset, 4, ENC_LITTLE_ENDIAN);

	(*offset) += 4;
}

/* ====================================================================
    KSQ: Key change sequence number
   ==================================================================== */
static void get_KSQ(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_tree_add_item(iec104_header_tree, hf_ksq, tvb, *offset, 4, ENC_LITTLE_ENDIAN);

	(*offset) += 4;
}

/* ====================================================================
    KWA: Key wrap algorithm
   ==================================================================== */
static void get_KWA(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_tree_add_item(iec104_header_tree, hf_kwa, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
    KST: Key status
   ==================================================================== */
static void get_KST(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_tree_add_item(iec104_header_tree, hf_kst, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
    HLN: MAC length
   ==================================================================== */
static uint16_t get_HLN(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	uint16_t value = tvb_get_letohs(tvb, *offset);

	proto_tree_add_item(iec104_header_tree, hf_hln, tvb, *offset, 2, ENC_LITTLE_ENDIAN);

	(*offset) += 2;
	return value;
}

/* ====================================================================
    HAL: MAC algorithm
   ==================================================================== */
static uint8_t get_HAL(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	uint8_t hal = tvb_get_uint8(tvb, *offset);
	proto_tree_add_item(iec104_header_tree, hf_hal, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
	switch (hal)
	{
		case 3: /* HMAC-SHA-256 truncated to 8 octets (serial) */
			return 8;
		case 4: /* HMAC-SHA-256 truncated to 16 octets (networked) */
			return 16;
		case 6: /* AES-GMAC (output is 12 octets) */
			return 12;
	}
	return 0;
}

/* ====================================================================
    CLN: Challenge data length
   ==================================================================== */
static uint16_t get_CLN(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	uint16_t value = tvb_get_letohs(tvb, *offset);

	proto_tree_add_item(iec104_header_tree, hf_cln, tvb, *offset, 2, ENC_LITTLE_ENDIAN);

	(*offset) += 2;
	return value;
}

/* ====================================================================
    WKL: Wrapped key data length
   ==================================================================== */
static uint16_t get_WKL(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	uint16_t value = tvb_get_letohs(tvb, *offset);

	proto_tree_add_item(iec104_header_tree, hf_wkl, tvb, *offset, 2, ENC_LITTLE_ENDIAN);

	(*offset) += 2;
	return value;
}

/* ====================================================================
    Pseudo-random challenge data
   ==================================================================== */
static void get_PRCD(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree, int length)
{
	proto_tree_add_item(iec104_header_tree, hf_prcd_raw_data, tvb, *offset, length, ENC_NA);
	(*offset) += length;
}

/* ====================================================================
    MAC value
   ==================================================================== */
static void get_HMAC(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree, int length)
{
	if (length)
	{
		proto_tree_add_item(iec104_header_tree, hf_hmac_raw_data, tvb, *offset, length, ENC_NA);
		(*offset) += length;
	}
}

/* ====================================================================
    Wrapped key data
   ==================================================================== */
static void get_WKD(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree, int length)
{
	proto_tree_add_item(iec104_header_tree, hf_wkd_raw_data, tvb, *offset, length, ENC_NA);
	(*offset) += length;
}

/* ====================================================================
    AID: Association ID
   ==================================================================== */
static void get_AID(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_tree_add_item(iec104_header_tree, hf_aid, tvb, *offset, 2, ENC_LITTLE_ENDIAN);

	(*offset) += 2;
}

/* ====================================================================
    ERR: Error code
   ==================================================================== */
static void get_ERR(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_tree_add_item(iec104_header_tree, hf_err, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
    ETM: Error time stamp (7-octet binary time)
   ==================================================================== */
static void get_ETM(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	uint16_t ms;
	uint8_t value;
	uint8_t su;
	struct tm tm;
	nstime_t  datetime;
	proto_item* ti;
	proto_tree* etm_tree;

	ms = tvb_get_letohs(tvb, *offset);
	tm.tm_sec = ms / 1000;
	datetime.nsecs = (ms % 1000) * 1000000;
	(*offset) += 2;

	value = tvb_get_uint8(tvb, *offset);
	tm.tm_min = value & 0x3F;
	(*offset)++;

	value = tvb_get_uint8(tvb, *offset);
	tm.tm_hour = value & 0x1F;
	su = value & 0x80;
	(*offset)++;

	value = tvb_get_uint8(tvb, *offset);
	tm.tm_mday = value & 0x1F;
	(*offset)++;

	value = tvb_get_uint8(tvb, *offset);
	tm.tm_mon = (value & 0x0F) - 1;
	(*offset)++;

	value = tvb_get_uint8(tvb, *offset);
	tm.tm_year = value & 0x7F;
	if (tm.tm_year < 70)
		tm.tm_year += 100;

	(*offset)++;

	if (su)
		tm.tm_isdst = 1;
	else
		tm.tm_isdst = -1; /* there's no info on whether DST was in force; assume it's
				   * the same as currently */

	datetime.secs = mktime(&tm);

	(*offset) -= 7;

	ti = proto_tree_add_time(iec104_header_tree, hf_etm, tvb, *offset, 7, &datetime);
	etm_tree = proto_item_add_subtree(ti, ett_etm);

	proto_tree_add_item(etm_tree, hf_etm_ms, tvb, *offset, 2, ENC_LITTLE_ENDIAN);
	(*offset) += 2;

	proto_tree_add_item(etm_tree, hf_etm_min, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(etm_tree, hf_etm_iv, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;

	proto_tree_add_item(etm_tree, hf_etm_hour, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(etm_tree, hf_etm_su, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;

	proto_tree_add_item(etm_tree, hf_etm_day, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(etm_tree, hf_etm_dow, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;

	proto_tree_add_item(etm_tree, hf_etm_month, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;

	proto_tree_add_item(etm_tree, hf_etm_year, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	(*offset)++;
}

/* ====================================================================
    ELN: Error length
   ==================================================================== */
static uint16_t get_ELN(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	uint16_t value = tvb_get_letohs(tvb, *offset);
	proto_tree_add_item(iec104_header_tree, hf_eln, tvb, *offset, 2, ENC_LITTLE_ENDIAN);

	(*offset) += 2;
	return value;
}

/* ====================================================================
    Error text
   ==================================================================== */
static void get_ErrorText(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree, int length)
{
	if (length)
	{
		proto_tree_add_item(iec104_header_tree, hf_error_text, tvb, *offset, length, ENC_UTF_8 | ENC_NA);
		(*offset) += length;
	}
}

/* ====================================================================
    COI: Cause of initialisation
   ==================================================================== */
static void get_COI(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_item* ti;
	proto_tree* coi_tree;

	ti = proto_tree_add_item(iec104_header_tree, hf_coi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	coi_tree = proto_item_add_subtree(ti, ett_coi);

	proto_tree_add_item(coi_tree, hf_coi_r, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(coi_tree, hf_coi_i, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
    QOI: Qualifier of interrogation
   ==================================================================== */
static void get_QOI(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_tree_add_item(iec104_header_tree, hf_qoi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
    QCC: Qualifier of counter interrogation
   ==================================================================== */
static void get_QCC(tvbuff_t *tvb, uint8_t *offset, proto_tree *iec104_header_tree)
{
	proto_item* ti;
	proto_tree* qcc_tree;

	ti = proto_tree_add_item(iec104_header_tree, hf_qcc, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	qcc_tree = proto_item_add_subtree(ti, ett_qcc);

	proto_tree_add_item(qcc_tree, hf_qcc_rqt, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(qcc_tree, hf_qcc_frz, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}

/* ====================================================================
    QRP: Qualifier of reset process command
   ==================================================================== */
static void get_QRP(tvbuff_t* tvb, uint8_t* offset, proto_tree* iec104_header_tree)
{
	proto_tree_add_item(iec104_header_tree, hf_qrp, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;
}
/* .... end Misc. functions for dissection of signal values */


/* Find the IEC60870-5-104 APDU (APDU=APCI+ASDU) length.
Includes possible tvb_length-1 bytes that don't form an APDU */
static unsigned get_iec104apdu_len(packet_info *pinfo _U_, tvbuff_t *tvb,
                                int offset, void *data _U_)
{
	uint8_t Val;
	uint32_t Off;

	for (Off = 0; Off <= tvb_reported_length(tvb) - 2; Off++) {
		Val = tvb_get_uint8(tvb, offset + Off);
		if (Val == APCI_START) {
			return (unsigned)(Off + tvb_get_uint8(tvb, offset + Off + 1) + 2);
		}
	}

	return (unsigned)(tvb_reported_length(tvb));
}

/* Dissect reassembled extended IEC60870-5-7 secure authentication ASDUs */
// NOLINTNEXTLINE(misc-no-recursion)
static int dissect_iec60870_asdu_segment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *it_segment_tree, uint8_t type_id, struct asdu_parms* parms)
{
	unsigned Len = tvb_reported_length(tvb);
	uint8_t offset = 0;
	uint8_t i, encapsulated_type, encapsulated_length;
	uint16_t j;
	tvbuff_t *encapsulated_tvb = NULL;

	switch (type_id) {
		case S_CH_NA_1: /* 81    authentication challenge */
			get_CSQ(tvb, &offset, it_segment_tree);
			get_USR(tvb, &offset, it_segment_tree);
			get_MAL(tvb, &offset, it_segment_tree);
			get_RSC(tvb, &offset, it_segment_tree);
			j = get_CLN(tvb, &offset, it_segment_tree);
			get_PRCD(tvb, &offset, it_segment_tree, j);
			break;
		case S_RP_NA_1: /* 82    authentication reply */
			get_CSQ(tvb, &offset, it_segment_tree);
			get_USR(tvb, &offset, it_segment_tree);
			j = get_HLN(tvb, &offset, it_segment_tree);
			get_HMAC(tvb, &offset, it_segment_tree, j);
			break;
		case S_AR_NA_1: /* 83    Aggressive mode authentication request */
			encapsulated_type = tvb_get_uint8(tvb, offset);
			encapsulated_length = 1 + 1 + parms->cot_len + parms->asdu_addr_len + parms->ioa_len + get_TypeIdLength(encapsulated_type);
			encapsulated_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, encapsulated_length);
			dissect_iec60870_asdu(encapsulated_tvb, pinfo, it_segment_tree, parms);
			offset = tvb_reported_length(encapsulated_tvb);
			get_CSQ(tvb, &offset, it_segment_tree);
			get_USR(tvb, &offset, it_segment_tree);
			get_HMAC(tvb, &offset, it_segment_tree, tvb_reported_length_remaining(tvb, offset));
			break;
		case S_KS_NA_1: /* 85    session key status */
			get_KSQ(tvb, &offset, it_segment_tree);
			get_USR(tvb, &offset, it_segment_tree);
			get_KWA(tvb, &offset, it_segment_tree);
			get_KST(tvb, &offset, it_segment_tree);
			i = get_HAL(tvb, &offset, it_segment_tree);
			j = get_CLN(tvb, &offset, it_segment_tree);
			get_PRCD(tvb, &offset, it_segment_tree, j);
			get_HMAC(tvb, &offset, it_segment_tree, i);
			break;
		case S_KC_NA_1: /* 86    session key change */
			get_KSQ(tvb, &offset, it_segment_tree);
			get_USR(tvb, &offset, it_segment_tree);
			j = get_WKL(tvb, &offset, it_segment_tree);
			get_WKD(tvb, &offset, it_segment_tree, j);
			break;
		case S_ER_NA_1: /* 87    Authentication error */
			get_CSQ(tvb, &offset, it_segment_tree);
			get_USR(tvb, &offset, it_segment_tree);
			get_AID(tvb, &offset, it_segment_tree);
			get_ERR(tvb, &offset, it_segment_tree);
			get_ETM(tvb, &offset, it_segment_tree);
			j = get_ELN(tvb, &offset, it_segment_tree);
			get_ErrorText(tvb, &offset, it_segment_tree, j);
			break;
		default:
			proto_tree_add_item(it_segment_tree, hf_ioa, tvb, offset, 3, ENC_LITTLE_ENDIAN);
			offset += 3;

			if (Len - offset > 0)
				proto_tree_add_item(it_segment_tree, hf_asdu_raw_data, tvb, offset, Len - offset, ENC_NA);
			offset = Len;

			break;
	}
	/* check correct apdu length */
	if (Len != offset) {
		expert_add_info(pinfo, it_segment_tree, &ei_iec104_apdu_invalid_len);
		return offset;
	}

	return Len;
}

/* Handle segmentation of IEC60870-5-7 secure authentication APDUs */
// NOLINTNEXTLINE(misc-no-recursion)
static void dissect_iec60870_segment(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint8_t *offset, uint8_t typeId, struct asdu_parms* parms)
{
	uint32_t msg_seqid = 0;

	bool final_segment = tvb_get_bits(tvb, (*offset << 3) + 0, 1, ENC_LITTLE_ENDIAN) == 1;

	proto_tree_add_item(tree, hf_asn_fin, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_asn_fir, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(tree, hf_asn, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

	(*offset)++;

	tvbuff_t *next_tvb = tvb_new_subset_remaining(tvb, *offset);
	uint32_t fragment_length = tvb_captured_length(next_tvb);
	if (!final_segment) {
		col_append_fstr(pinfo->cinfo, COL_INFO, " [ASDU fragment, %u byte%s]",
				fragment_length, plurality(fragment_length, "", "s"));
	} else {
		col_append_fstr(pinfo->cinfo, COL_INFO, " EOA");
	}

	fragment_head *fd_head = fragment_add_seq_next(&iec60870_reassemble_table, next_tvb, 0, pinfo,msg_seqid, NULL,
						       fragment_length, !final_segment);

	if (fd_head && fd_head->next) {
		/* don't use -1 if fragment length is zero (throws Exception) */
		proto_tree_add_bytes_format(tree, hf_iec60870_segment_data, tvb, *offset, (fragment_length) ? -1 : 0,
					    NULL, "ASDU segment data (%u byte%s)", fragment_length,
					    plurality(fragment_length, "", "s"));

		if (final_segment) {
			next_tvb = process_reassembled_data(next_tvb, *offset, pinfo,
							    "Reassembled ASDU", fd_head,
							    &iec60870_frag_items, NULL, tree);
		} else if (pinfo->num != fd_head->reassembled_in) {
			/* Add a "Reassembled in" link if not reassembled in this frame */
			proto_tree_add_uint(tree, *(iec60870_frag_items.hf_reassembled_in),
					    next_tvb, 0, 0, fd_head->reassembled_in);
		}
		pinfo->fragmented = !final_segment;
	}

	if (final_segment) {
		dissect_iec60870_asdu_segment(next_tvb, pinfo, tree, typeId, parms);
	}

	*offset += tvb_captured_length_remaining(tvb, *offset);
}

/* Is is called twice: For 'Packet List' and for 'Packet Details' */
/* This dissection is shared by the IEC '101 and '104 dissectors */
// NOLINTNEXTLINE(misc-no-recursion)
static int dissect_iec60870_asdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	unsigned Len = tvb_reported_length(tvb);
	uint8_t Bytex;
	const char *cause_str;
	size_t Ind;
	struct asduheader asduh = { .OA = 0, .Addr = 0, .IOA = 0};
	struct asdu_parms* parms = (struct asdu_parms*)data;
	proto_item *it104;
	proto_tree *it104tree;
	wmem_strbuf_t * res;

	uint8_t offset = 0;  /* byte offset, signal dissection */
	uint8_t i;
	uint32_t asdu_info_obj_addr = 0;
	proto_item * itSignal = NULL;
	proto_tree * trSignal;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEC 60870-5 ASDU");

	it104 = proto_tree_add_item(tree, proto_iec60870_asdu, tvb, offset, -1, ENC_NA);
	it104tree = proto_item_add_subtree(it104, ett_asdu);

	res = wmem_strbuf_create(pinfo->pool);

	/* Type identification */
	asduh.TypeId = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(it104tree, hf_typeid, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	asduh.DataLength = get_TypeIdLength(asduh.TypeId);
	offset += 1;

	/* Variable structure qualifier */
	Bytex = tvb_get_uint8(tvb, 1);
	asduh.SQ = Bytex & F_SQ;
	asduh.NumIx = Bytex & 0x7F;
	proto_tree_add_item(it104tree, hf_sq, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(it104tree, hf_numix, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* Cause of transmission */
	asduh.TNCause = tvb_get_uint8(tvb, offset);
	proto_tree_add_item(it104tree, hf_causetx, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(it104tree, hf_nega, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(it104tree, hf_test, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	offset += 1;

	/* Originator address */
	/* This is only present if the Cause of Tx field is 2 octets */
	if (parms->cot_len == 2) {
		asduh.OA = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(it104tree, hf_oa, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		offset += 1;
	}

	/* Common address of ASDU */
	proto_tree_add_item_ret_uint(it104tree, hf_addr, tvb, offset, parms->asdu_addr_len, ENC_LITTLE_ENDIAN, &asduh.Addr);
	offset += parms->asdu_addr_len;

	/* Information object address */
	/* Support both 16 and 24-bit IOA addresses */
	/* Don't increment offset, as we'll want to be at this position later */
	if (asduh.TypeId < S_CH_NA_1 || asduh.TypeId > S_UC_NA_1) {
		if (parms->ioa_len == 3) {
			asduh.IOA = tvb_get_letoh24(tvb, offset);
		}
		else if (parms->ioa_len == 2) {
			asduh.IOA = tvb_get_letohs(tvb, offset);
		}
	}

	cause_str = val_to_str(asduh.TNCause & F_CAUSE, causetx_types, " <CauseTx=%u>");

	wmem_strbuf_append_printf(res, "ASDU=%u %s %s", asduh.Addr, val_to_str(asduh.TypeId, asdu_types, "<TypeId=%u>"), cause_str);

	if (asduh.TNCause & F_NEGA)
		wmem_strbuf_append(res, "_NEGA");
	if (asduh.TNCause & F_TEST)
		wmem_strbuf_append(res, "_TEST");

	if ((asduh.TNCause & (F_TEST | F_NEGA)) == 0) {
		for (Ind=strlen(cause_str); Ind< 7; Ind++)
			wmem_strbuf_append(res, " ");
	}

	if (asduh.NumIx > 1) {
		wmem_strbuf_append_printf(res, " IOA[%d]=%d", asduh.NumIx, asduh.IOA);
		if (asduh.SQ == F_SQ)
			wmem_strbuf_append_printf(res, "-%d", asduh.IOA + asduh.NumIx - 1);
		else
			wmem_strbuf_append(res, ",...");
	} else {
		wmem_strbuf_append_printf(res, " IOA=%d", asduh.IOA);
	}

	col_append_str(pinfo->cinfo, COL_INFO, wmem_strbuf_get_str(res));
	col_set_fence(pinfo->cinfo, COL_INFO);

	/* 'ASDU Details': ROOT ITEM */
	proto_item_append_text(it104, ": %s '%s'", wmem_strbuf_get_str(res),
		Len >= offset + parms->ioa_len ? val_to_str_const(asduh.TypeId, asdu_lngtypes, "<Unknown TypeId>") : "");

	/* 'Signal Details': TREE */
	/* -------- get signal value and status based on ASDU type id */

	switch (asduh.TypeId) {
		case M_SP_NA_1:
		case M_SP_TA_1:
		case M_DP_NA_1:
		case M_DP_TA_1:
		case M_ST_NA_1:
		case M_ST_TA_1:
		case M_BO_NA_1:
		case M_BO_TA_1:
		case M_SP_TB_1:
		case M_DP_TB_1:
		case M_ST_TB_1:
		case M_BO_TB_1:
		case M_ME_NA_1:
		case M_ME_TA_1:
		case M_ME_NB_1:
		case M_ME_TB_1:
		case M_ME_NC_1:
		case M_ME_TC_1:
		case M_ME_ND_1:
		case M_ME_TD_1:
		case M_ME_TE_1:
		case M_ME_TF_1:
		case M_IT_NA_1:
		case M_IT_TA_1:
		case M_IT_TB_1:
		case S_IT_TC_1:
		case C_SC_NA_1:
		case C_DC_NA_1:
		case C_RC_NA_1:
		case C_SE_NA_1:
		case C_SE_NB_1:
		case C_SE_NC_1:
		case C_BO_NA_1:
		case C_SC_TA_1:
		case C_DC_TA_1:
		case C_RC_TA_1:
		case C_SE_TA_1:
		case C_SE_TB_1:
		case C_SE_TC_1:
		case C_BO_TA_1:
		case M_EI_NA_1:
		case C_IC_NA_1:
		case C_CI_NA_1:
		case C_CS_NA_1:
		case C_RP_NA_1:
		case C_TS_TA_1:
		case P_ME_NA_1:
		case P_ME_NB_1:
		case P_ME_NC_1:

			/* -- object values */
			for(i = 0; i < asduh.NumIx; i++)
			{
				/* create subtree for the signal values ... */
				if (i == 0 || !asduh.SQ)
					trSignal = proto_tree_add_subtree(it104tree, tvb, offset, asduh.DataLength + parms->ioa_len,
														ett_asdu_objects, &itSignal, "IOA:s");
				else
					trSignal = proto_tree_add_subtree(it104tree, tvb, offset, asduh.DataLength,
														ett_asdu_objects, &itSignal, "IOA:s");

				/* --------  First Information object address */
				if (i == 0)
				{
					/* --------  Information object address */
					/* check length */
					if(Len < (unsigned)(offset + 3)) {
						expert_add_info(pinfo, itSignal, &ei_iec104_short_asdu);
						return offset;
					}
					get_InfoObjectAddress(&asdu_info_obj_addr, tvb, &offset, trSignal, parms->ioa_len);
				} else {
					/* -------- following Information object address depending on SQ */
					if (asduh.SQ) /* <=> SQ=1, info obj addr = startaddr++ */
					{
						proto_item *ti;
						asdu_info_obj_addr++;
						ti = proto_tree_add_uint(trSignal, hf_ioa, tvb, 0, 0, asdu_info_obj_addr);
						proto_item_set_generated(ti);
					} else { /* SQ=0, info obj addr given */
						/* --------  Information object address */
						/* check length */
						if(Len < (unsigned)(offset + 3)) {
							expert_add_info(pinfo, itSignal, &ei_iec104_short_asdu);
							return offset;
						}
						get_InfoObjectAddress(&asdu_info_obj_addr, tvb, &offset, trSignal, parms->ioa_len);
					}
				}

				proto_item_set_text(itSignal, "IOA: %d", asdu_info_obj_addr);

				/* check length */
				if(Len < (unsigned)(offset + asduh.DataLength)) {
					expert_add_info(pinfo, itSignal, &ei_iec104_short_asdu);
					return offset;
				}

				switch (asduh.TypeId) {
				case M_SP_NA_1: /* 1	Single-point information */
					get_SIQ(tvb, &offset, trSignal);
					break;
				case M_SP_TA_1: /* 2	Single-point information with time tag */
					get_SIQ(tvb, &offset, trSignal);
					get_CP24Time(tvb, &offset, trSignal);
					break;
				case M_DP_NA_1: /* 3	Double-point information */
					get_DIQ(tvb, &offset, trSignal);
					break;
				case M_DP_TA_1: /* 4	Double-point information with time tag */
					get_DIQ(tvb, &offset, trSignal);
					get_CP24Time(tvb, &offset, trSignal);
					break;
				case M_ST_NA_1: /* 5	Step position information */
					get_VTI(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					break;
				case M_ST_TA_1: /* 6	Step position information with time tag */
					get_VTI(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					get_CP24Time(tvb, &offset, trSignal);
					break;
				case M_BO_NA_1: /* 7	Bitstring of 32 bits */
					get_BSI(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					break;
				case M_BO_TA_1: /* 8	Bitstring of 32 bits with time tag */
					get_BSI(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					get_CP24Time(tvb, &offset, trSignal);
					break;
				case M_ME_NA_1: /* 9	Measured value, normalized value */
					get_NVA(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					break;
				case M_ME_TA_1: /* 10	Measured value, normalized value with time tag */
					get_NVA(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					get_CP24Time(tvb, &offset, trSignal);
					break;
				case M_ME_NB_1: /* 11     Measured value, scaled value */
					get_SVA(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					break;
				case M_ME_TB_1: /* 12     Measured value, scaled value with time tag */
					get_SVA(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					get_CP24Time(tvb, &offset, trSignal);
					break;
				case M_ME_NC_1: /* 13	Measured value, short floating point value */
					get_FLT(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					break;
				case M_ME_TC_1: /* 14	Measured value, short floating point value with time tag */
					get_FLT(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					get_CP24Time(tvb, &offset, trSignal);
					break;
				case M_IT_NA_1: /* 15	Integrated totals */
					get_BCR(tvb, &offset, trSignal);
					break;
				case M_IT_TA_1: /* 16	Integrated totals with time tag */
					get_BCR(tvb, &offset, trSignal);
					get_CP24Time(tvb, &offset, trSignal);
					break;
				case M_ME_ND_1: /* 21    Measured value, normalized value without quality descriptor */
					get_NVA(tvb, &offset, trSignal);
					break;
				case M_SP_TB_1: /* 30	Single-point information with time tag CP56Time2a */
					get_SIQ(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case M_DP_TB_1: /* 31	Double-point information with time tag CP56Time2a */
					get_DIQ(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case M_ST_TB_1: /* 32	Step position information with time tag CP56Time2a */
					get_VTI(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case M_BO_TB_1: /* 33	Bitstring of 32 bit with time tag CP56Time2a */
					get_BSI(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case M_ME_TD_1: /* 34    Measured value, normalized value with time tag CP56Time2a */
					get_NVA(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case M_ME_TE_1: /* 35    Measured value, scaled value with time tag CP56Time2a */
					get_SVA(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case M_ME_TF_1: /* 36    Measured value, short floating point value with time tag CP56Time2a */
					get_FLT(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case M_IT_TB_1: /* 37	Integrated totals with time tag CP56Time2a */
					get_BCR(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case S_IT_TC_1: /* 41   Integrated totals containing time tagged security statistics */
					get_AID(tvb, &offset, trSignal);
					get_BCR(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case C_SC_NA_1: /* 45	Single command */
					get_SCO(tvb, &offset, trSignal);
					break;
				case C_DC_NA_1: /* 46	Double command */
					get_DCO(tvb, &offset, trSignal);
					break;
				case C_RC_NA_1: /* 47	Regulating step command */
					get_RCO(tvb, &offset, trSignal);
					break;
				case C_SE_NA_1: /* 48    Set point command, normalized value */
					get_NVAspt(tvb, &offset, trSignal);
					get_QOS(tvb, &offset, trSignal);
					break;
				case C_SE_NB_1: /* 49    Set point command, scaled value */
					get_SVAspt(tvb, &offset, trSignal);
					get_QOS(tvb, &offset, trSignal);
					break;
				case C_SE_NC_1: /* 50    Set point command, short floating point value */
					get_FLTspt(tvb, &offset, trSignal);
					get_QOS(tvb, &offset, trSignal);
					break;
				case C_BO_NA_1: /* 51    Bitstring of 32 bits */
					get_BSIspt(tvb, &offset, trSignal);
					break;
				case C_SC_TA_1: /* 58    Single command with time tag CP56Time2a */
					get_SCO(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case C_DC_TA_1: /* 59    Double command with time tag CP56Time2a */
					get_DCO(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case C_RC_TA_1: /* 60    Regulating step command with time tag CP56Time2a */
					get_RCO(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case C_SE_TA_1: /* 61    Set point command, normalized value with time tag CP56Time2a */
					get_NVAspt(tvb, &offset, trSignal);
					get_QOS(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case C_SE_TB_1: /* 62    Set point command, scaled value with time tag CP56Time2a */
					get_SVAspt(tvb, &offset, trSignal);
					get_QOS(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case C_SE_TC_1: /* 63    Set point command, short floating point value with time tag CP56Time2a */
					get_FLTspt(tvb, &offset, trSignal);
					get_QOS(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case C_BO_TA_1: /* 64    Bitstring of 32 bits with time tag CP56Time2a */
					get_BSIspt(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case M_EI_NA_1: /* 70    End of initialization  */
					get_COI(tvb, &offset, trSignal);
					break;
				case C_IC_NA_1: /* 100   Interrogation command  */
					get_QOI(tvb, &offset, trSignal);
					break;
				case C_CI_NA_1: /* 101   Counter interrogation command  */
					get_QCC(tvb, &offset, trSignal);
					break;
				case C_CS_NA_1: /* 103   Clock synchronization command  */
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case C_RP_NA_1: /* 105   reset process command  */
					get_QRP(tvb, &offset, trSignal);
					break;
				case C_TS_TA_1: /* 107   test command with time tag CP56Time2a */
					get_TSC(tvb, &offset, trSignal);
					get_CP56Time(tvb, &offset, trSignal);
					break;
				case P_ME_NA_1: /* 110   Parameter of measured value, normalized value */
					get_NVA(tvb, &offset, trSignal);
					get_QPM(tvb, &offset, trSignal);
					break;
				case P_ME_NB_1: /* 111   Parameter of measured value, scaled value */
					get_SVA(tvb, &offset, trSignal);
					get_QPM(tvb, &offset, trSignal);
					break;
				case P_ME_NC_1: /* 112   Parameter of measured value, short floating-point number */
					get_FLT(tvb, &offset, trSignal);
					get_QPM(tvb, &offset, trSignal);
					break;
				default:
					break;
				} /* end 'switch (asduh.TypeId)' */
			} /* end 'for(i = 0; i < dui.asdu_vsq_no_of_obj; i++)' */
			break;
		case S_CH_NA_1: /* 81    authentication challenge */
		case S_RP_NA_1: /* 82    authentication reply */
		case S_AR_NA_1: /* 83    Aggressive mode authentication request */
		case S_KS_NA_1: /* 85    session key status */
		case S_KC_NA_1: /* 86    session key change */
		case S_ER_NA_1: /* 87    Authentication error */
			dissect_iec60870_segment(tvb, pinfo, it104tree, &offset, asduh.TypeId, parms);
			break;
		case S_KR_NA_1: /* 84    Session key status request */
			proto_tree_add_item(it104tree, hf_usr, tvb, offset, 2, ENC_LITTLE_ENDIAN);
			offset += 2;
			break;
		default:
			proto_tree_add_item(it104tree, hf_ioa, tvb, offset, 3, ENC_LITTLE_ENDIAN);
			offset += 3;

			if (Len - offset > 0)
				proto_tree_add_item(it104tree, hf_asdu_raw_data, tvb, offset, Len - offset, ENC_NA);
			offset = Len;

			break;
	} /* end 'switch (asdu_typeid)' */

	/* check correct apdu length */
	if (Len != offset) {
		expert_add_info_format(pinfo, it104tree, &ei_iec104_apdu_invalid_len, "Invalid Apdulen (%d != %d)", Len, offset);
		return offset;
	}

	return tvb_captured_length(tvb);
}



/* Is is called twice: For 'Packet List' and for 'Packet Details' */
static int dissect_iec60870_104(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	unsigned TcpLen = tvb_reported_length(tvb);
	uint8_t Start, len, type, temp8;
	uint32_t apci_txid, apci_rxid, apci_u_type;
	unsigned Off;
	proto_item *it104, *ti;
	proto_tree *it104tree;
	wmem_strbuf_t * res;
	struct asdu_parms parms;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEC 60870-5-104");

	it104 = proto_tree_add_item(tree, proto_iec60870_104, tvb, 0, -1, ENC_NA);
	it104tree = proto_item_add_subtree(it104, ett_apci);

	res = wmem_strbuf_create(pinfo->pool);

	Start = 0;
	for (Off = 0; Off <= TcpLen - 2; Off++) {
		Start = tvb_get_uint8(tvb, Off);

		if (Start == APCI_START) {
			if (Off > 0)
			{
				proto_tree_add_item(it104tree, hf_apcidata, tvb, 0, Off, ENC_NA);
				wmem_strbuf_append_printf(res, "<ERR prefix %u bytes> ", Off);
			}

			proto_item_set_len(it104, Off + APCI_LEN);

			proto_tree_add_uint_format(it104tree, hf_start, tvb, Off, 1, Start, "START");
			ti = proto_tree_add_item(it104tree, hf_apdulen, tvb, Off + 1, 1, ENC_LITTLE_ENDIAN);

			len = tvb_get_uint8(tvb, Off + 1);
			if (len < APDU_MIN_LEN) {
				expert_add_info_format(pinfo, ti, &ei_iec104_apdu_min_len, "APDU less than %d bytes", APDU_MIN_LEN);
				wmem_strbuf_append_printf(res, "<ERR ApduLen=%u bytes> ", len);
				return tvb_captured_length(tvb);
			}

			temp8 = tvb_get_uint8(tvb, Off + 2);
			if ((temp8 & 0x01) == 0)
				type = 0;
			else
				type = temp8 & 0x03;

			if (type == I_TYPE)
				proto_tree_add_item(it104tree, hf_apcitype_i, tvb, Off + 2, 4, ENC_LITTLE_ENDIAN);
			else
				proto_tree_add_item(it104tree, hf_apcitype_s_u, tvb, Off + 2, 4, ENC_LITTLE_ENDIAN);

			if (len <= APDU_MAX_LEN) {
				wmem_strbuf_append_printf(res, "%s %s ",
					(pinfo->srcport == pinfo->match_uint ? "->" : "<-"),
					val_to_str_const(type, apci_types, "<ERR>"));
			}
			else {
				wmem_strbuf_append_printf(res, "<ERR ApduLen=%u bytes> ", len);
			}

			switch(type) {
			case I_TYPE:
				proto_tree_add_item_ret_uint(it104tree, hf_apcitx, tvb, Off + 2, 4, ENC_LITTLE_ENDIAN, &apci_txid);
				proto_tree_add_item_ret_uint(it104tree, hf_apcirx, tvb, Off + 2, 4, ENC_LITTLE_ENDIAN, &apci_rxid);
				wmem_strbuf_append_printf(res, "(%d,%d) ", apci_txid, apci_rxid);
				break;
			case S_TYPE:
				proto_tree_add_item_ret_uint(it104tree, hf_apcirx, tvb, Off + 2, 4, ENC_LITTLE_ENDIAN, &apci_rxid);
				wmem_strbuf_append_printf(res, "(%d) ", apci_rxid);
				break;
			case U_TYPE:
				proto_tree_add_item_ret_uint(it104tree, hf_apciutype, tvb, Off + 2, 4, ENC_LITTLE_ENDIAN, &apci_u_type);
				wmem_strbuf_append_printf(res, "(%s) ", val_to_str_const(apci_u_type, u_types, "<ERR>"));
				break;
			}

			col_clear(pinfo->cinfo, COL_INFO);
			col_append_sep_str(pinfo->cinfo, COL_INFO, " | ", wmem_strbuf_get_str(res));
			col_set_fence(pinfo->cinfo, COL_INFO);

			proto_item_append_text(it104, ": %s", wmem_strbuf_get_str(res));

			if (type == I_TYPE) {
				/* Set the field lengths to the '104 fixed values before calling the ASDU dissection */
				parms.cot_len = 2;
				parms.asdu_addr_len = 2;
				parms.ioa_len = 3;

				call_dissector_with_data(iec60870_asdu_handle, tvb_new_subset_length_caplen(tvb, Off + APCI_LEN, -1, len - APCI_DATA_LEN), pinfo, tree, &parms);
			}
			/* Don't search more the APCI_START */
			break;
		}
	}

	if (Start != APCI_START) {
		/* Everything is bad (no APCI found) */
		proto_tree_add_item(it104tree, hf_apcidata, tvb, 0, Off, ENC_NA);
	}

	return tvb_captured_length(tvb);
}

/******************************************************************************************************/
/* Code to dissect IEC 101 Protocol packets */
/******************************************************************************************************/
static int
dissect_iec60870_101(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
/* Set up structures needed to add the protocol subtree and manage it */
	proto_item	*iec101_item, *ctrlfield_item, *expert_item;
	proto_tree	*iec101_tree, *ctrlfield_tree;
	uint8_t		ctrlfield_prm;
	uint32_t	frametype, linkaddr, data_len, stopchar;
	int		offset = 0;
	struct      asdu_parms parms;

	/* Make entries in Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEC 60870-5-101");
	col_clear(pinfo->cinfo, COL_INFO);

	iec101_item = proto_tree_add_item(tree, proto_iec60870_101, tvb, 0, -1, ENC_NA);
	iec101_tree = proto_item_add_subtree(iec101_item, ett_iec60870_101);

	/* Add Frame Format to Protocol Tree */
	proto_tree_add_item_ret_uint(iec101_tree, hf_iec60870_101_frame, tvb, offset, 1, ENC_LITTLE_ENDIAN, &frametype);
	offset += 1;

	/* If this is a single character frame, there is nothing left to do... */
	if (frametype == IEC101_SINGLE_CHAR) {
		return offset;
	}

	if (frametype == IEC101_VAR_LEN) {
		proto_tree_add_item(iec101_tree, hf_iec60870_101_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		expert_item = proto_tree_add_item_ret_uint(iec101_tree, hf_iec60870_101_num_user_octets, tvb, offset+1, 1, ENC_LITTLE_ENDIAN, &data_len);
		if (data_len != tvb_get_uint8(tvb, offset)) {
			expert_add_info(pinfo, expert_item, &ei_iec101_length_mismatch);
			col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
			return tvb_captured_length(tvb);
		}
		/* do not include the ctrl field and link address bytes in the length passed to the asdu dissector */
		data_len -= 1 + global_iec60870_link_addr_len;
		expert_item = proto_tree_add_item_ret_uint(iec101_tree, hf_iec60870_101_frame, tvb, offset+2, 1, ENC_LITTLE_ENDIAN, &frametype);
		if (frametype != IEC101_VAR_LEN) {
			expert_add_info(pinfo, expert_item, &ei_iec101_frame_mismatch);
			col_set_str(pinfo->cinfo, COL_INFO, "Continuation");
			return tvb_captured_length(tvb);
		}
		offset += 3;
	}

	/* Fields common to both variable and fixed length frames */
	ctrlfield_item = proto_tree_add_item(iec101_tree, hf_iec60870_101_ctrlfield, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	ctrlfield_tree = proto_item_add_subtree(ctrlfield_item, ett_iec60870_101_ctrlfield);

	ctrlfield_prm = tvb_get_uint8(tvb, offset) & 0x40;
	if (ctrlfield_prm) {
		col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Pri->Sec");
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_101_ctrl_prm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_101_ctrl_fcb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_101_ctrl_fcv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_101_ctrl_func_pri_to_sec, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
	else {
		col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Sec->Pri");
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_101_ctrl_prm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_101_ctrl_dfc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_101_ctrl_func_sec_to_pri, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
	offset += 1;

	if (global_iec60870_link_addr_len) {
		proto_tree_add_item_ret_uint(iec101_tree, hf_iec60870_101_linkaddr, tvb, offset, global_iec60870_link_addr_len, ENC_LITTLE_ENDIAN, &linkaddr);
		col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Link Address: %d ", linkaddr);
		offset += global_iec60870_link_addr_len;
	}

	/* If this is a variable length frame, we need to call the ASDU dissector */
	if (frametype == IEC101_VAR_LEN) {

		/* Retrieve the user preferences */
		parms.cot_len = global_iec60870_cot_len;
		parms.asdu_addr_len = global_iec60870_asdu_addr_len;
		parms.ioa_len = global_iec60870_ioa_len;

		call_dissector_with_data(iec60870_asdu_handle, tvb_new_subset_length_caplen(tvb, offset, -1, data_len), pinfo, tree, &parms);
		offset += data_len;
	}

	proto_tree_add_item(iec101_tree, hf_iec60870_101_checksum, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	expert_item = proto_tree_add_item_ret_uint(iec101_tree, hf_iec60870_101_stopchar, tvb, offset+1, 1, ENC_LITTLE_ENDIAN, &stopchar);
	if (stopchar != IEC101_STOP_CHAR) {
		expert_add_info(pinfo, expert_item, &ei_iec101_stopchar_invalid);
	}
	offset += 2;

	return offset;

}

static int dissect_iec60870_104_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	/* 5th parameter = 6 = minimum bytes received to calculate the length.
	 * (Not 2 in order to find more APCIs in case of 'noisy' bytes between the APCIs)
	 */
	tcp_dissect_pdus(tvb, pinfo, tree, true, APCI_LEN,
			get_iec104apdu_len, dissect_iec60870_104, data);
	return tvb_captured_length(tvb);
}

/* The protocol has two subprotocols: Register APCI */
void
proto_register_iec60870_104(void)
{
	static hf_register_info hf_ap[] = {

		{ &hf_apdulen,
		  { "ApduLen", "iec60870_104.apdulen", FT_UINT8, BASE_DEC, NULL, 0x0,
		    "APDU Len", HFILL }},

		{ &hf_apcitype_i,
		  { "Type", "iec60870_104.type", FT_UINT32, BASE_HEX, VALS(apci_types), 0x00000001,
		    "APCI type", HFILL }},

		{ &hf_apcitype_s_u,
		  { "Type", "iec60870_104.type", FT_UINT32, BASE_HEX, VALS(apci_types), 0x00000003,
		    "APCI type", HFILL }},

		{ &hf_apciutype,
		  { "UType", "iec60870_104.utype", FT_UINT32, BASE_HEX, VALS(u_types), 0x000000FC,
		    "Apci U type", HFILL }},

		{ &hf_apcitx,
		  { "Tx", "iec60870_104.tx", FT_UINT32, BASE_DEC, NULL, 0x0000FFFE,
		    NULL, HFILL }},

		{ &hf_apcirx,
		  { "Rx", "iec60870_104.rx", FT_UINT32, BASE_DEC, NULL, 0xFFFE0000,
		    NULL, HFILL }},

		{ &hf_apcidata,
		  { "Data", "iec60870_104.data", FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
	};

	static int *ett_ap[] = {
		&ett_apci,
	};

	proto_iec60870_104 = proto_register_protocol("IEC 60870-5-104", "IEC 60870-5-104", "iec60870_104");

	/* Provide an alias to the previous name of this dissector */
	proto_register_alias(proto_iec60870_104, "104apci");

	proto_register_field_array(proto_iec60870_104, hf_ap, array_length(hf_ap));
	proto_register_subtree_array(ett_ap, array_length(ett_ap));

	prefs_register_protocol(proto_iec60870_104, NULL);

	iec60870_104_handle = register_dissector("iec60870_104", dissect_iec60870_104_tcp, proto_iec60870_104);

}

/* Register ASDU dissection, shared by the '101 and '104 dissectors */
void
proto_register_iec60870_asdu(void)
{
	static hf_register_info hf_as[] = {

		{ &hf_addr,
		  { "Addr", "iec60870_asdu.addr", FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Common Address of Asdu", HFILL }},

		{ &hf_oa,
		  { "OA", "iec60870_asdu.oa", FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Originator Address", HFILL }},

		{ &hf_typeid,
		  { "TypeId", "iec60870_asdu.typeid", FT_UINT8, BASE_DEC, VALS(asdu_types), 0x0,
		    "Asdu Type Id", HFILL }},

		{ &hf_causetx,
		  { "CauseTx", "iec60870_asdu.causetx", FT_UINT8, BASE_DEC, VALS(causetx_types), F_CAUSE,
		    "Cause of Transmission", HFILL }},

		{ &hf_nega,
		  { "Negative", "iec60870_asdu.nega", FT_BOOLEAN, 8, NULL, F_NEGA,
		    NULL, HFILL }},

		{ &hf_test,
		  { "Test", "iec60870_asdu.test", FT_BOOLEAN, 8, NULL, F_TEST,
		    NULL, HFILL }},

		{ &hf_ioa,
		  { "IOA", "iec60870_asdu.ioa", FT_UINT24, BASE_DEC, NULL, 0x0,
		    "Information Object Address", HFILL }},

		{ &hf_numix,
		  { "NumIx", "iec60870_asdu.numix", FT_UINT8, BASE_DEC, NULL, 0x7F,
		    "Number of Information Objects/Elements", HFILL }},

		{ &hf_sq,
		  { "SQ", "iec60870_asdu.sq", FT_BOOLEAN, 8, NULL, F_SQ,
		    "Sequence", HFILL }},

		{ &hf_cp24time,
		  { "CP24Time", "iec60870_asdu.cp24time", FT_RELATIVE_TIME, BASE_NONE, NULL, 0,
		    NULL, HFILL }},

		{ &hf_cp24time_ms,
		  { "MS", "iec60870_asdu.cp24time.ms", FT_UINT16, BASE_DEC, NULL, 0,
		    "CP24Time milliseconds", HFILL }},

		{ &hf_cp24time_min,
		  { "Min", "iec60870_asdu.cp24time.min", FT_UINT8, BASE_DEC, NULL, 0x3F,
		    "CP24Time minutes", HFILL }},

		{ &hf_cp24time_iv,
		  { "IV", "iec60870_asdu.cp24time.iv", FT_BOOLEAN, 8, TFS(&tfs_invalid_valid), 0x80,
		    "CP24Time invalid", HFILL }},

		{ &hf_cp56time,
		  { "CP56Time", "iec60870_asdu.cp56time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
		    NULL, HFILL }},

		{ &hf_cp56time_ms,
		  { "MS", "iec60870_asdu.cp56time.ms", FT_UINT16, BASE_DEC, NULL, 0,
		    "CP56Time milliseconds", HFILL }},

		{ &hf_cp56time_min,
		  { "Min", "iec60870_asdu.cp56time.min", FT_UINT8, BASE_DEC, NULL, 0x3F,
		    "CP56Time minutes", HFILL }},

		{ &hf_cp56time_gen,
		  { "GEN", "iec60870_asdu.cp56time.gen", FT_BOOLEAN, 8, TFS(&tfs_substituted_not_substituted), 0x40,
		    "CP56Time substituted", HFILL }},

		{ &hf_cp56time_iv,
		  { "IV", "iec60870_asdu.cp56time.iv", FT_BOOLEAN, 8, TFS(&tfs_invalid_valid), 0x80,
		    "CP56Time invalid", HFILL }},

		{ &hf_cp56time_hour,
		  { "Hour", "iec60870_asdu.cp56time.hour", FT_UINT8, BASE_DEC, NULL, 0x1F,
		    "CP56Time hours", HFILL }},

		{ &hf_cp56time_su,
		  { "SU", "iec60870_asdu.cp56time.su", FT_BOOLEAN, 8, TFS(&tfs_local_dst), 0x80,
		    "CP56Time summer time", HFILL }},

		{ &hf_cp56time_day,
		  { "Day", "iec60870_asdu.cp56time.day", FT_UINT8, BASE_DEC, NULL, 0x1F,
		    "CP56Time day", HFILL }},

		{ &hf_cp56time_dow,
		  { "DOW", "iec60870_asdu.cp56time.dow", FT_UINT8, BASE_DEC, NULL, 0xE0,
		    "CP56Time day of week", HFILL }},

		{ &hf_cp56time_month,
		  { "Month", "iec60870_asdu.cp56time.month", FT_UINT8, BASE_DEC, NULL, 0x0F,
		    "CP56Time month", HFILL }},

		{ &hf_cp56time_year,
		  { "Year", "iec60870_asdu.cp56time.year", FT_UINT8, BASE_DEC, NULL, 0x7F,
		    "CP56Time year", HFILL }},

		{ &hf_siq,
		  { "SIQ", "iec60870_asdu.siq", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_siq_spi,
		  { "SPI", "iec60870_asdu.siq.spi", FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x01,
		    "SIQ SPI", HFILL }},

		{ &hf_siq_bl,
		  { "BL", "iec60870_asdu.siq.bl", FT_BOOLEAN, 8, TFS(&tfs_blocked_not_blocked), 0x10,
		    "SIQ BL", HFILL }},

		{ &hf_siq_sb,
		  { "SB", "iec60870_asdu.siq.sb", FT_BOOLEAN, 8, TFS(&tfs_substituted_not_substituted), 0x20,
		    "SIQ SB", HFILL }},

		{ &hf_siq_nt,
		  { "NT", "iec60870_asdu.siq.nt", FT_BOOLEAN, 8, TFS(&tfs_not_topical_topical), 0x40,
		    "SIQ NT", HFILL }},

		{ &hf_siq_iv,
		  { "IV", "iec60870_asdu.siq.iv", FT_BOOLEAN, 8, TFS(&tfs_invalid_valid), 0x80,
		    "SIQ IV", HFILL }},

		{ &hf_diq,
		  { "DIQ", "iec60870_asdu.diq", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_diq_dpi,
		  { "DPI", "iec60870_asdu.diq.dpi", FT_UINT8, BASE_DEC, VALS(diq_types), 0x03,
		    "DIQ DPI", HFILL }},

		{ &hf_diq_bl,
		  { "BL", "iec60870_asdu.diq.bl", FT_BOOLEAN, 8, TFS(&tfs_blocked_not_blocked), 0x10,
		    "DIQ BL", HFILL }},

		{ &hf_diq_sb,
		  { "SB", "iec60870_asdu.diq.sb", FT_BOOLEAN, 8, TFS(&tfs_substituted_not_substituted), 0x20,
		    "DIQ SB", HFILL }},

		{ &hf_diq_nt,
		  { "NT", "iec60870_asdu.diq.nt", FT_BOOLEAN, 8, TFS(&tfs_not_topical_topical), 0x40,
		    "DIQ NT", HFILL }},

		{ &hf_diq_iv,
		  { "IV", "iec60870_asdu.diq.iv", FT_BOOLEAN, 8, TFS(&tfs_invalid_valid), 0x80,
		    "DIQ IV", HFILL }},

		{ &hf_qds,
		  { "QDS", "iec60870_asdu.qds", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_qds_ov,
		  { "OV", "iec60870_asdu.qds.ov", FT_BOOLEAN, 8, TFS(&tfs_overflow_no_overflow), 0x01,
		    "QDS OV", HFILL }},

		{ &hf_qds_bl,
		  { "BL", "iec60870_asdu.qds.bl", FT_BOOLEAN, 8, TFS(&tfs_blocked_not_blocked), 0x10,
		    "QDS BL", HFILL }},

		{ &hf_qds_sb,
		  { "SB", "iec60870_asdu.qds.sb", FT_BOOLEAN, 8, TFS(&tfs_substituted_not_substituted), 0x20,
		    "QDS SB", HFILL }},

		{ &hf_qds_nt,
		  { "NT", "iec60870_asdu.qds.nt", FT_BOOLEAN, 8, TFS(&tfs_not_topical_topical), 0x40,
		    "QDS NT", HFILL }},

		{ &hf_qds_iv,
		  { "IV", "iec60870_asdu.qds.iv", FT_BOOLEAN, 8, TFS(&tfs_invalid_valid), 0x80,
		    "QDS IV", HFILL }},

		{ &hf_vti,
		  { "VTI", "iec60870_asdu.vti", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_vti_v,
		  { "Value", "iec60870_asdu.vti.v", FT_INT8, BASE_DEC, NULL, 0x7F,
		    "VTI Value", HFILL }},

		{ &hf_vti_t,
		  { "T", "iec60870_asdu.vti.t", FT_BOOLEAN, 8, TFS(&tfs_transient_not_transient), 0x80,
		    "VTI T", HFILL }},

		{ &hf_qos,
		  { "QOS", "iec60870_asdu.qos", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_qos_ql,
		  { "QL", "iec60870_asdu.qos.ql", FT_UINT8, BASE_DEC, NULL, 0x7F,
		    "QOS QL", HFILL }},

		{ &hf_qos_se,
		  { "S/E", "iec60870_asdu.qos.se", FT_BOOLEAN, 8, TFS(&tfs_select_execute), 0x80,
		    "QOS S/E", HFILL }},

		{ &hf_sco,
		  { "SCO", "iec60870_asdu.sco", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_sco_on,
		  { "ON/OFF", "iec60870_asdu.sco.on", FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x01,
		    "SCO SCS", HFILL }},

		{ &hf_sco_qu,
		  { "QU", "iec60870_asdu.sco.qu", FT_UINT8, BASE_DEC, VALS(qos_qu_types), 0x7C,
		    "SCO QU", HFILL }},

		{ &hf_sco_se,
		  { "S/E", "iec60870_asdu.sco.se", FT_BOOLEAN, 8, TFS(&tfs_select_execute), 0x80,
		    "SCO S/E", HFILL }},

		{ &hf_dco,
		  { "DCO", "iec60870_asdu.dco", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_dco_on,
		  { "ON/OFF", "iec60870_asdu.dco.on", FT_UINT8, BASE_DEC, VALS(dco_on_types), 0x03,
		    "DCO DCS", HFILL }},

		{ &hf_dco_qu,
		  { "QU", "iec60870_asdu.dco.qu", FT_UINT8, BASE_DEC, VALS(qos_qu_types), 0x7C,
		    "DCO QU", HFILL }},

		{ &hf_dco_se,
		  { "S/E", "iec60870_asdu.dco.se", FT_BOOLEAN, 8, TFS(&tfs_select_execute), 0x80,
		    "DCO S/E", HFILL }},

		{ &hf_rco,
		  { "RCO", "iec60870_asdu.rco", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_rco_up,
		  { "UP/DOWN", "iec60870_asdu.rco.up", FT_UINT8, BASE_DEC, VALS(rco_up_types), 0x03,
		    "RCO RCS", HFILL }},

		{ &hf_rco_qu,
		  { "QU", "iec60870_asdu.rco.qu", FT_UINT8, BASE_DEC, VALS(qos_qu_types), 0x7C,
		    "RCO QU", HFILL }},

		{ &hf_rco_se,
		  { "S/E", "iec60870_asdu.rco.se", FT_BOOLEAN, 8, TFS(&tfs_select_execute), 0x80,
		    "RCO S/E", HFILL }},

		{ &hf_qpm,
		  { "QPM", "iec60870_asdu.qpm", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL } },

		{ &hf_qpm_kpa,
		  { "KPA", "iec60870_asdu.qpm.kpa", FT_UINT8, BASE_DEC, VALS(qpm_kpa_types), 0x3F,
		    "QPM KPA", HFILL } },

		{ &hf_qpm_lpc,
		  { "LPC", "iec60870_asdu.qpm.lpc", FT_UINT8, BASE_DEC, VALS(qpm_lpc_types), 0x40,
		    "QPM LPC", HFILL } },

		{ &hf_qpm_pop,
		  { "POP", "iec60870_asdu.qpm.pop", FT_UINT8, BASE_DEC, VALS(qpm_pop_types), 0x80,
		    "QPM POP", HFILL } },

		{ &hf_asn,
		  { "ASDU Segment Sequence Number (ASN)", "iec60870_asdu.asn", FT_UINT8, BASE_DEC, NULL, 0x3F,
		    NULL, HFILL }},

		{ &hf_asn_fin,
		  { "Final segment (FIN)", "iec60870_asdu.asn.fin", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x80,
		    NULL, HFILL }},

		{ &hf_asn_fir,
		  { "First segment (FIR)", "iec60870_asdu.asn.fir", FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
		    NULL, HFILL }},

		{ &hf_iec60870_segment_data,
		   { "ASDU segment data", "iec60870_asdu.segment_data", FT_BYTES, BASE_NONE, NULL, 0x0,
		     NULL, HFILL }},

		{ &hf_usr,
		  { "User number (USR)", "iec60870_asdu.usr", FT_UINT16, BASE_DEC | BASE_RANGE_STRING, RVALS(usr_types), 0,
		    NULL, HFILL }},

		{ &hf_mal,
		  { "MAC algorithm (MAL)", "iec60870_asdu.mal", FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(mal_types), 0,
		    NULL, HFILL }},

		{ &hf_rsc,
		  { "Reason for challenge (RSC)", "iec60870_asdu.rsc", FT_UINT8, BASE_DEC, VALS(rsc_types), 0,
		    NULL, HFILL }},

		{ &hf_csq,
		  { "Challenge sequence number (CSQ)", "iec60870_asdu.csq", FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},

		{ &hf_ksq,
		  { "Key change sequence number (KSQ)", "iec60870_asdu.ksq", FT_UINT32, BASE_DEC, NULL, 0,
		    NULL, HFILL }},

		{ &hf_kwa,
		  { "Key wrap algorithm (KWA)", "iec60870_asdu.kwa", FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(kwa_types), 0,
		    NULL, HFILL }},

		{ &hf_kst,
		  { "Key status (KST)", "iec60870_asdu.kst", FT_UINT8, BASE_DEC, VALS(kst_types), 0,
		    NULL, HFILL }},

		{ &hf_hln,
		  { "MAC length (HLN)", "iec60870_asdu.hln", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},

		{ &hf_hal,
		  { "MAC algorithm (HAL)", "iec60870_asdu.hal", FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(hal_types), 0,
		    NULL, HFILL }},

		{ &hf_cln,
		  { "Challenge data length (CLN)", "iec60870_asdu.cln", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},

		{ &hf_wkl,
		  { "Wrapped key data length (CLN)", "iec60870_asdu.wkl", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},

		{ &hf_prcd_raw_data,
		  { "Pseudo-random challenge data", "iec60870_asdu.challenge_data", FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_hmac_raw_data,
		  { "HMAC value", "iec60870_asdu.hmac", FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_wkd_raw_data,
		  { "Wrapped key data", "iec60870_asdu.wkd", FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_aid,
		  { "Association ID (AID)", "iec60870_asdu.aid", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},

		{ &hf_err,
		  { "Error code (ERR)", "iec60870_asdu.err", FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(error_codes), 0,
		    NULL, HFILL }},

		{ &hf_etm,
		  { "Error time stamp (ETM)", "iec60870_asdu.etm", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
		    NULL, HFILL }},

		{ &hf_etm_ms,
		  { "MS", "iec60870_asdu.etm.ms", FT_UINT16, BASE_DEC, NULL, 0,
		    "Error time stamp milliseconds", HFILL }},

		{ &hf_etm_min,
		  { "Min", "iec60870_asdu.etm.min", FT_UINT8, BASE_DEC, NULL, 0x3F,
		    "Error time stamp minutes", HFILL }},

		{ &hf_etm_iv,
		  { "IV", "iec60870_asdu.etm.iv", FT_BOOLEAN, 8, TFS(&tfs_invalid_valid), 0x80,
		    "Error time stamp invalid", HFILL }},

		{ &hf_etm_hour,
		  { "Hour", "iec60870_asdu.etm.hour", FT_UINT8, BASE_DEC, NULL, 0x1F,
		    "Error time stamp hours", HFILL }},

		{ &hf_etm_su,
		  { "SU", "iec60870_asdu.etm.su", FT_BOOLEAN, 8, TFS(&tfs_local_dst), 0x80,
		    "Error time stamp summer time", HFILL }},

		{ &hf_etm_day,
		  { "Day", "iec60870_asdu.etm.day", FT_UINT8, BASE_DEC, NULL, 0x1F,
		    "Error time stamp day", HFILL }},

		{ &hf_etm_dow,
		  { "DOW", "iec60870_asdu.etm.dow", FT_UINT8, BASE_DEC, NULL, 0xE0,
		    "Error time stamp day of week", HFILL }},

		{ &hf_etm_month,
		  { "Month", "iec60870_asdu.etm.month", FT_UINT8, BASE_DEC, NULL, 0x0F,
		    "Error time stamp month", HFILL }},

		{ &hf_etm_year,
		  { "Year", "iec60870_asdu.etm.year", FT_UINT8, BASE_DEC, NULL, 0x7F,
		    "Error time stamp year", HFILL }},

		{ &hf_eln,
		  { "Error length (ELN)", "iec60870_asdu.eln", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},

		{ &hf_error_text,
		  { "Error text", "iec60870_asdu.error_text", FT_STRING, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_coi,
		  { "COI", "iec60870_asdu.coi", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_coi_r,
		  { "R", "iec60870_asdu.coi.r", FT_UINT8, BASE_DEC, VALS(coi_r_types), 0x7F,
		    "COI R", HFILL }},

		{ &hf_coi_i,
		  { "I", "iec60870_asdu.coi.i", FT_BOOLEAN, 8, TFS(&tfs_coi_i), 0x80,
		    "COI I", HFILL }},

		{ &hf_qoi,
		  { "QOI", "iec60870_asdu.qoi", FT_UINT8, BASE_DEC, VALS(qoi_r_types), 0,
		    NULL, HFILL }},

		{ &hf_qcc,
		  { "QCC", "iec60870_asdu.qcc", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL } },

		{ &hf_qcc_rqt,
		  { "RQT", "iec60870_asdu.qcc.rqt", FT_UINT8, BASE_DEC, VALS(rqt_r_types), 0x3F,
		    NULL, HFILL } },

		{ &hf_qcc_frz,
		  { "FRZ", "iec60870_asdu.qcc.frz", FT_UINT8, BASE_DEC, VALS(frz_r_types), 0xC0,
		    NULL, HFILL } },

		{ &hf_qrp,
		  { "QRP", "iec60870_asdu.qrp", FT_UINT8, BASE_DEC, VALS(qrp_r_types), 0,
		    NULL, HFILL }},

		{ &hf_bcr,
		  { "BCR", "iec60870_asdu.bcr", FT_INT32, BASE_DEC, NULL, 0x0,
		    "Binary Counter", HFILL }},

		{ &hf_bcr_count,
		  { "Value", "iec60870_asdu.bcr.count", FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bcr_sq,
		  { "SQ", "iec60870_asdu.bcr.sq", FT_UINT8, BASE_DEC, NULL, 0x1F,
		    "Sequence Number", HFILL }},

		{ &hf_bcr_cy,
		  { "CY", "iec60870_asdu.bcr.cy", FT_BOOLEAN, 8, TFS(&tfs_overflow_no_overflow), 0x20,
		    "Counter Overflow", HFILL }},

		{ &hf_bcr_ca,
		  { "CA", "iec60870_asdu.bcr.ca", FT_BOOLEAN, 8, TFS(&tfs_adjusted_not_adjusted), 0x40,
		    "Counter Adjusted", HFILL }},

		{ &hf_bcr_iv,
		  { "IV", "iec60870_asdu.bcr.iv", FT_BOOLEAN, 8, TFS(&tfs_invalid_valid), 0x80,
		    "Counter Validity", HFILL }},

		{ &hf_start,
		  { "START", "iec60870_asdu.start", FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_asdu_bitstring,
		  { "Value", "iec60870_asdu.bitstring", FT_UINT32, BASE_HEX, NULL, 0x0,
		    "BSI value", HFILL }},

		{ &hf_asdu_float,
		  { "Value", "iec60870_asdu.float", FT_FLOAT, BASE_NONE, NULL, 0x0,
		    "Float value", HFILL }},

		{ &hf_asdu_normval,
		  { "Value", "iec60870_asdu.normval", FT_FLOAT, BASE_NONE, NULL, 0x0,
		    "Normalised value", HFILL }},

		{ &hf_asdu_scalval,
		  { "Value", "iec60870_asdu.scalval", FT_INT16, BASE_DEC, NULL, 0x0,
		    "Scaled value", HFILL }},

		{ &hf_asdu_tsc,
		  { "TSC", "iec60870_asdu.tsc", FT_UINT16, BASE_DEC, NULL, 0x0,
	            "Test sequence counter", HFILL }},

		{ &hf_asdu_raw_data,
		  { "Raw Data", "iec60870_asdu.rawdata", FT_BYTES, BASE_NONE, NULL, 0x0,
		    "Information object raw data", HFILL }},

		{ &hf_iec60870_segments,
		  { "ASDU Segments", "iec60870_asdu.segments", FT_NONE, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_iec60870_segment,
		  { "ASDU Segment", "iec60870_asdu.segment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_iec60870_segment_overlap,
		  { "Segment overlap", "iec60870_asdu.segment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Segment overlaps with other segments", HFILL }},

		{ &hf_iec60870_segment_overlap_conflict,
		  { "Conflicting data in segment overlap", "iec60870_asdu.segment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Overlapping segments contained conflicting data", HFILL }},

		{ &hf_iec60870_segment_multiple_tails,
		  { "Multiple tail segments found", "iec60870_asdu.segment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Several tails were found when reassembling the packet", HFILL }},

		{ &hf_iec60870_segment_too_long_segment,
		  { "Segment too long", "iec60870_asdu.segment.toolongsegment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		    "Segment contained data past end of packet", HFILL }},

		{ &hf_iec60870_segment_error,
		  { "Reassembly error", "iec60870_asdu.segment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		    "Reassembly error due to illegal segments", HFILL }},

		{ &hf_iec60870_segment_count,
		  { "Segment count", "iec60870_asdu.segment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_iec60870_reassembled_in,
		   { "Reassembled ASDU in frame", "iec60870_asdu.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		     "This ASDU packet is reassembled in this frame", HFILL }},

		{ &hf_iec60870_reassembled_length,
		  { "Reassembled ASDU length", "iec60870_asdu.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
		    "The total length of the reassembled payload", HFILL }},

	};

	static int *ett_as[] = {
		&ett_asdu,
		&ett_asdu_objects,
		&ett_siq,
		&ett_diq,
		&ett_qds,
		&ett_qos,
		&ett_vti,
		&ett_sco,
		&ett_dco,
		&ett_rco,
		&ett_qpm,
		&ett_coi,
		&ett_qcc,
		&ett_cp24time,
		&ett_cp56time,
		&ett_etm,
		&ett_iec60870_segment,
		&ett_iec60870_segments
	};

	static ei_register_info ei[] = {
		{ &ei_iec104_short_asdu, { "iec104.short_asdu", PI_MALFORMED, PI_ERROR, "<ERR Short Asdu>", EXPFILL }},
		{ &ei_iec104_apdu_min_len, { "iec104.apdu_min_len", PI_MALFORMED, PI_ERROR, "APDU less than bytes", EXPFILL }},
		{ &ei_iec104_apdu_invalid_len, { "iec104.apdu_invalid_len", PI_MALFORMED, PI_ERROR, "Invalid ApduLen", EXPFILL }},
	};

	expert_module_t* expert_iec60870;

	proto_iec60870_asdu = proto_register_protocol("IEC 60870-5-101/104 ASDU", "IEC 60870-5-101/104 ASDU", "iec60870_asdu");
	iec60870_asdu_handle = register_dissector("iec60870_asdu", dissect_iec60870_asdu, proto_iec60870_asdu);

	/* Provide an alias to the previous name of this dissector */
	proto_register_alias(proto_iec60870_asdu, "104asdu");

	proto_register_field_array(proto_iec60870_asdu, hf_as, array_length(hf_as));
	proto_register_subtree_array(ett_as, array_length(ett_as));
	expert_iec60870 = expert_register_protocol(proto_iec60870_asdu);
	expert_register_field_array(expert_iec60870, ei, array_length(ei));

	reassembly_table_register(&iec60870_reassemble_table, &addresses_ports_reassembly_table_functions);
}

/* The registration hand-off routine */
void
proto_reg_handoff_iec60870_104(void)
{
	dissector_add_uint_with_preference("tcp.port", IEC104_PORT, iec60870_104_handle);
}

/******************************************************************************************************/
/* Return length of IEC 101 Protocol over TCP message (used for re-assembly)						 */
/******************************************************************************************************/
static unsigned
get_iec101_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{

	unsigned len=0, type;
	type = tvb_get_uint8(tvb, offset);

	switch (type) {
		case IEC101_SINGLE_CHAR:
			len = 1;
			break;
		case IEC101_FIXED_LEN:
			len = global_iec60870_link_addr_len + 4;
			break;
		case IEC101_VAR_LEN:
			if (tvb_captured_length_remaining(tvb, offset) < 3) {
				/* We need another segment. */
				return 0;
			}
			len = tvb_get_uint8(tvb, offset + 1) + 6;
			/* If the copy of the length or start byte is wrong,
			 * we have errors. Take the entire remaining length
			 * and the dissector will show the error. We'll try
			 * to start a new PDU in a later packet. We can't
			 * really reject the packet at this point.
			 */
			if (len != (unsigned)tvb_get_uint8(tvb, offset + 2) + 6) {
				len = tvb_reported_length_remaining(tvb, offset);
			}
			if (tvb_get_uint8(tvb, offset+3) != IEC101_VAR_LEN) {
				len = tvb_reported_length_remaining(tvb, offset);
			}
			break;
	}

	return len;
}

/******************************************************************************************************/
/* Dissect (and possibly Re-assemble) IEC 101 protocol payload data */
/******************************************************************************************************/
static int
dissect_iec60870_101_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

	unsigned type = tvb_get_uint8(tvb, 0);

	/* Check that this is actually a IEC 60870-5-101 packet. */
	/* Note we are guaranteed to get one byte here, not necessarily more. */
	switch (type) {
		case IEC101_SINGLE_CHAR:
		case IEC101_FIXED_LEN:
		case IEC101_VAR_LEN:
			tcp_dissect_pdus(tvb, pinfo, tree, true, 1, get_iec101_len, dissect_iec60870_101, data);
			break;
		default:
			return 0;
	}

	return tvb_captured_length(tvb);
}

/* The registration hand-off routine */
void
proto_register_iec60870_101(void)
{
	/* IEC 101 Protocol header fields */
	static hf_register_info iec60870_101_hf[] = {
		{ &hf_iec60870_101_frame,
		{ "Frame Format", "iec60870_101.header", FT_UINT8, BASE_HEX, VALS(iec60870_101_frame_vals), 0x0, NULL, HFILL }},
		{ &hf_iec60870_101_length,
		{ "Length", "iec60870_101.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_101_num_user_octets,
		{ "Number of User Octets", "iec60870_101.num_user_octets", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_101_ctrlfield,
		{ "Control Field", "iec60870_101.ctrlfield", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_101_ctrl_prm,
		{ "PRM", "iec60870_101.ctrl_prm", FT_UINT8, BASE_DEC, VALS(iec60870_101_ctrl_prm_values), 0x40, "Primary Message", HFILL }},
		{ &hf_iec60870_101_ctrl_fcb,
		{ "FCB", "iec60870_101.ctrl_fcb", FT_UINT8, BASE_DEC, NULL, 0x20, "Frame Count Bit", HFILL }},
		{ &hf_iec60870_101_ctrl_fcv,
		{ "FCV", "iec60870_101.ctrl_fcv", FT_UINT8, BASE_DEC, NULL, 0x10, "Frame Count Bit Valid", HFILL }},
		{ &hf_iec60870_101_ctrl_dfc,
		{ "DFC", "iec60870_101.ctrl_dfc", FT_UINT8, BASE_DEC, NULL, 0x10, "Data Flow Control", HFILL }},
		{ &hf_iec60870_101_ctrl_func_pri_to_sec,
		{ "CF Func Code", "iec60870_101.ctrl_func_pri_to_sec", FT_UINT8, BASE_DEC, VALS(iec60870_101_ctrl_func_pri_to_sec_values), 0x0F, "Control Field Function Code, Pri to Sec", HFILL }},
		{ &hf_iec60870_101_ctrl_func_sec_to_pri,
		{ "CF Func Code", "iec60870_101.ctrl_func_sec_to_pri", FT_UINT8, BASE_DEC, VALS(iec60870_101_ctrl_func_sec_to_pri_values), 0x0F, "Control Field Function Code, Sec to Pri", HFILL }},
		{ &hf_iec60870_101_linkaddr,
		{ "Data Link Address", "iec60870_101.linkaddr", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_101_checksum,
		{ "Checksum", "iec60870_101.checksum", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_101_stopchar,
		{ "Stop Character", "iec60870_101.stopchar", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

	};

	/* Setup protocol subtree array */
	static int *ett_serial[] = {
		&ett_iec60870_101,
		&ett_iec60870_101_ctrlfield,
	};

	static ei_register_info ei_101[] = {
		{ &ei_iec101_frame_mismatch, { "iec60870_101.header.mismatch", PI_MALFORMED, PI_ERROR, "Variable Length frames must have two matching start bytes (0x68)", EXPFILL }},
		{ &ei_iec101_length_mismatch, { "iec60870_101.length.mismatch", PI_MALFORMED, PI_ERROR, "Variable Length frames must have two matching length bytes", EXPFILL }},
		{ &ei_iec101_stopchar_invalid, { "iec60870_101.stopchar.invalid", PI_PROTOCOL, PI_WARN, "Stop character must be 0x16", EXPFILL }},
	};

	module_t *iec60870_101_module;
	expert_module_t* expert_iec60870_101;

	/* Register the protocol name and description */
	proto_iec60870_101 = proto_register_protocol("IEC 60870-5-101", "IEC 60870-5-101", "iec60870_101");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_iec60870_101, iec60870_101_hf, array_length(iec60870_101_hf));
	proto_register_subtree_array(ett_serial, array_length(ett_serial));

	expert_iec60870_101 = expert_register_protocol(proto_iec60870_101);
	expert_register_field_array(expert_iec60870_101, ei_101, array_length(ei_101));

	iec60870_101_handle = register_dissector("iec60870_101", dissect_iec60870_101_tcp, proto_iec60870_101);

	/* Register required preferences for IEC 101 configurable field lengths */
	iec60870_101_module = prefs_register_protocol(proto_iec60870_101, NULL);

	static const enum_val_t link_addr_len[] = {
		{"0", "0 octet", 0},
		{"1", "1 octet", 1},
		{"2", "2 octet", 2},
		{NULL, NULL, -1}
	};

	static const enum_val_t cot_len[] = {
		{"1", "1 octet", 1},
		{"2", "2 octet", 2},
		{NULL, NULL, -1}
	};

	static const enum_val_t asdu_addr_len[] = {
		{"1", "1 octet", 1},
		{"2", "2 octet", 2},
		{NULL, NULL, -1}
	};

	static const enum_val_t asdu_ioa_len[] = {
		{"1", "1 octet", 1},
		{"2", "2 octet", 2},
		{"3", "3 octet", 3},
		{NULL, NULL, -1}
	};

	prefs_register_enum_preference(iec60870_101_module, "linkaddr_len",
		"Length of the Link Address Field",
		"Length of the Link Address Field, configurable in '101 and absent in '104",
		&global_iec60870_link_addr_len, link_addr_len, false);

	prefs_register_enum_preference(iec60870_101_module, "cot_len",
		"Length of the Cause of Transmission Field",
		"Length of the Cause of Transmission Field, configurable in '101 and fixed at 2 octets with '104",
		&global_iec60870_cot_len, cot_len, false);

	prefs_register_enum_preference(iec60870_101_module, "asdu_addr_len",
		"Length of the Common ASDU Address Field",
		"Length of the Common ASDU Address Field, configurable in '101 and fixed at 2 octets with '104",
		&global_iec60870_asdu_addr_len, asdu_addr_len, false);

	prefs_register_enum_preference(iec60870_101_module, "asdu_ioa_len",
		"Length of the Information Object Address Field",
		"Length of the Information Object Address Field, configurable in '101 and fixed at 3 octets with '104",
		&global_iec60870_ioa_len, asdu_ioa_len, false);

}

void
proto_reg_handoff_iec60870_101(void)
{
	/* Add decode-as connection to determine user-customized TCP port */
	dissector_add_for_decode_as_with_preference("tcp.port", iec60870_101_handle);
	/* Add dissection for serial pcap files generated by the RTAC */
	dissector_add_for_decode_as("rtacser.data", iec60870_101_handle);
}

/******************************************************************************************************/
/* Code to dissect IEC 60870-5-103 Protocol packets */
/******************************************************************************************************/
static int
dissect_iec60870_5_103(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
/* Set up structures needed to add the protocol subtree and manage it */
	proto_item	*iec103_item, *ctrlfield_item;
	proto_tree	*iec103_tree, *ctrlfield_tree;
	uint8_t		frametype, ctrlfield_prm, linkaddr, asdu_type, sq_num_obj;
	uint8_t		offset = 0;
	int         i;

	/* Make entries in Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "IEC 60870-5-103");
	col_clear(pinfo->cinfo, COL_INFO);

	iec103_item = proto_tree_add_item(tree, proto_iec60870_5_103, tvb, 0, -1, ENC_NA);
	iec103_tree = proto_item_add_subtree(iec103_item, ett_iec60870_5_103);

	/* Add Frame Format to Protocol Tree */
	proto_tree_add_item(iec103_tree, hf_iec60870_5_103_frame, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	frametype = tvb_get_uint8(tvb, 0);
	offset += 1;

	/* If this is a single character frame, there is nothing left to do... */
	if (frametype == IEC103_SINGLE_CHAR) {
		return offset;
	}

	if (frametype == IEC103_VAR_LEN) {
		proto_tree_add_item(iec103_tree, hf_iec60870_5_103_length, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(iec103_tree, hf_iec60870_5_103_num_user_octets, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(iec103_tree, hf_iec60870_5_103_frame, tvb, offset+2, 1, ENC_LITTLE_ENDIAN);
		offset += 3;
	}

	/* Fields common to both variable and fixed length frames */
	ctrlfield_item = proto_tree_add_item(iec103_tree, hf_iec60870_5_103_ctrlfield, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	ctrlfield_tree = proto_item_add_subtree(ctrlfield_item, ett_iec60870_5_103_ctrlfield);

	ctrlfield_prm = tvb_get_uint8(tvb, offset) & 0x40;
	if (ctrlfield_prm) {
		col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Pri->Sec");
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_5_103_ctrl_prm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_5_103_ctrl_fcb, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_5_103_ctrl_fcv, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_5_103_ctrl_func_pri_to_sec, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
	else {
		col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Sec->Pri");
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_5_103_ctrl_prm, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_5_103_ctrl_dfc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(ctrlfield_tree, hf_iec60870_5_103_ctrl_func_sec_to_pri, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	}
	offset += 1;

	proto_tree_add_item(iec103_tree, hf_iec60870_5_103_linkaddr, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	linkaddr = tvb_get_uint8(tvb, offset);
	col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL, "Link Address: %d ", linkaddr);
	offset += 1;

	/* If this is a variable length frame, we need to perform additional dissection */
	if (frametype == IEC103_VAR_LEN) {

		if (ctrlfield_prm) {
			proto_tree_add_item(iec103_tree, hf_iec60870_5_103_asdu_typeid_ctrl, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			asdu_type = tvb_get_uint8(tvb, offset);
		}
		else {
			proto_tree_add_item(iec103_tree, hf_iec60870_5_103_asdu_typeid_mon, tvb, offset, 1, ENC_LITTLE_ENDIAN);
			asdu_type = tvb_get_uint8(tvb, offset);
		}
		proto_tree_add_item(iec103_tree, hf_iec60870_5_103_sq, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
		sq_num_obj = tvb_get_uint8(tvb, offset+1) & 0x1F;

		if (ctrlfield_prm) {
			proto_tree_add_item(iec103_tree, hf_iec60870_5_103_cot_ctrl, tvb, offset+2, 1, ENC_LITTLE_ENDIAN);
		}
		else {
			proto_tree_add_item(iec103_tree, hf_iec60870_5_103_cot_mon, tvb, offset+2, 1, ENC_LITTLE_ENDIAN);
		}

		proto_tree_add_item(iec103_tree, hf_iec60870_5_103_asdu_address, tvb, offset+3, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(iec103_tree, hf_iec60870_5_103_func_type, tvb, offset+4, 1, ENC_LITTLE_ENDIAN);
		proto_tree_add_item(iec103_tree, hf_iec60870_5_103_info_num, tvb, offset+5, 1, ENC_LITTLE_ENDIAN);
		offset += 6;

		for(i = 0; i < sq_num_obj; i++) {
			/* Control Direction */
			if (ctrlfield_prm) {
				switch (asdu_type) {
					case 0x06:   /* ASDU 6 - Time synchronization */
						get_CP56Time(tvb, &offset, iec103_tree);
						break;
					case 0x07:   /* ASDU 7 - General interrogation */
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_scn, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						offset += 1;
						break;
					case 0x14:   /* ASDU 20 - general command */
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_dco, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_rii, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
						offset += 2;
						break;
					case 0x2d:   /* ASDU 45 - Private, Areva Single command */
					case 0x2e:   /* ASDU 46 - Private, Areva Double command */
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_areva_cmd, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						offset += 1;
						break;
				}
			}
			/* Monitor Direction */
			else {
				switch (asdu_type) {
					case 0x01:     /* ASDU 1 - Time Tagged Message */
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_dpi, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						offset += 1;
						get_CP32TimeA(tvb, &offset, iec103_tree);
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_sin, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						offset += 1;
						break;
					case 0x05:    /* ASDU 5 - Identification */
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_col, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						offset += 1;
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_mfg, tvb, offset, 8, ENC_ASCII);
						offset += 8;
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_mfg_sw, tvb, offset, 4, ENC_LITTLE_ENDIAN);
						offset += 4;
						break;
					case 0x06:    /* ASDU 6 - Time synchronization */
						get_CP56Time(tvb, &offset, iec103_tree);
						break;
					case 0x08:    /* ASDU 8 - Termination of general interrogation */
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_scn, tvb, offset, 1, ENC_LITTLE_ENDIAN);
						offset += 1;
						break;
					case 0x09:    /* ASDU 9 - Measurements II */
						get_NVA(tvb, &offset, iec103_tree);
						break;
					case 0xcd:    /* ASDU 205 - private, siemens energy counters */
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_asdu205_value, tvb, offset, 4, ENC_LITTLE_ENDIAN);
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_asdu205_ms, tvb, offset+4, 2, ENC_LITTLE_ENDIAN);
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_asdu205_min, tvb, offset+6, 1, ENC_LITTLE_ENDIAN);
						proto_tree_add_item(iec103_tree, hf_iec60870_5_103_asdu205_h, tvb, offset+7, 1, ENC_LITTLE_ENDIAN);
						offset += 8;
						break;
				}

			}
		}
	}

	proto_tree_add_item(iec103_tree, hf_iec60870_5_103_checksum, tvb, offset, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(iec103_tree, hf_iec60870_5_103_stopchar, tvb, offset+1, 1, ENC_LITTLE_ENDIAN);
	offset += 2;

	return offset;

}

/******************************************************************************************************/
/* Return length of IEC 103 Protocol over TCP message (used for re-assembly)						 */
/******************************************************************************************************/
static unsigned
get_iec103_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_)
{

	unsigned len=0, type;
	type = tvb_get_uint8(tvb, offset);

	switch (type) {
		case IEC103_SINGLE_CHAR:
			len = 1;
			break;
		case IEC103_FIXED_LEN:
			len = 5;
			break;
		case IEC103_VAR_LEN:
			len = tvb_get_uint8(tvb, offset+1) + 6;
			break;
	}

	return len;
}

/******************************************************************************************************/
/* Dissect (and possibly Re-assemble) IEC 103 protocol payload data */
/******************************************************************************************************/
static int
dissect_iec60870_5_103_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{

	unsigned type = tvb_get_uint8(tvb, 0);

	/* Check that this is actually a IEC 60870-5-103 packet. */
	switch (type) {
		case IEC103_SINGLE_CHAR:
		case IEC103_FIXED_LEN:
		case IEC103_VAR_LEN:
			tcp_dissect_pdus(tvb, pinfo, tree, true, 1, get_iec103_len, dissect_iec60870_5_103, data);
			break;
		default:
			return 0;
	}

	return tvb_captured_length(tvb);
}

/* IEC 60870-5-103 Protocol registration hand-off routine */
void
proto_register_iec60870_5_103(void)
{
	/* IEC 103 Protocol header fields */
	static hf_register_info iec60870_5_103_hf[] = {
		{ &hf_iec60870_5_103_areva_cmd,
		{ "Areva Command Code", "iec60870_5_103.areva_cmd", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_asdu_address,
		{ "ASDU Common Address", "iec60870_5_103.asdu_address", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_asdu_typeid_ctrl,
		{ "ASDU Type ID (Ctrl Direction)", "iec60870_5_103.asdu_typeid_ctrl", FT_UINT8, BASE_HEX, VALS(iec103_asdu_types_control_dir), 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_asdu_typeid_mon,
		{ "ASDU Type ID (Monitor Direction)", "iec60870_5_103.asdu_typeid_mon", FT_UINT8, BASE_HEX, VALS(iec103_asdu_types_monitor_dir), 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_asdu205_ms,
		{ "Timestamp: Milliseconds", "iec60870_5_103.asdu205_ms", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_asdu205_min,
		{ "Timestamp: Minutes", "iec60870_5_103.asdu205_min", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_asdu205_h,
		{ "Timestamp: Hours", "iec60870_5_103.asdu205_h", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_asdu205_value,
		{ "Counter Value", "iec60870_5_103.asdu205_value", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_checksum,
		{ "Checksum", "iec60870_5_103.checksum", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_col,
		{ "Compatibility Level", "iec60870_5_103.col", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_cot_ctrl,
		{ "Cause of Transmission (Ctrl Direction)", "iec60870_5_103.cot_ctrl", FT_UINT8, BASE_HEX, VALS(iec60870_5_103_cot_ctrl_dir), 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_cot_mon,
		{ "Cause of Transmission (Monitored Direction)", "iec60870_5_103.cot_mon", FT_UINT8, BASE_HEX, VALS(iec60870_5_103_cot_monitor_dir), 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_cp32time2a,
		{ "CP32Time2a", "iec60870_5_103.cp32time2a", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0, NULL, HFILL }},
		{ &hf_iec60870_5_103_cp32time2a_ms,
		{ "Milliseconds", "iec60870_5_103.cp32time2a_ms", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_cp32time2a_min,
		{ "Minutes", "iec60870_5_103.cp32time2a_min", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL }},
		{ &hf_iec60870_5_103_cp32time2a_res1,
		{ "Res1", "iec60870_5_103.cp32time2a_res1", FT_UINT8, BASE_DEC, NULL, 0x40, NULL, HFILL }},
		{ &hf_iec60870_5_103_cp32time2a_iv,
		{ "Invalid", "iec60870_5_103.cp32time2a_iv", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_iec60870_5_103_cp32time2a_hr,
		{ "Hours", "iec60870_5_103.cp32time2a_hr", FT_UINT8, BASE_DEC, NULL, 0x1f, NULL, HFILL }},
		{ &hf_iec60870_5_103_cp32time2a_res2,
		{ "Res2", "iec60870_5_103.cp32time2a_res2", FT_UINT8, BASE_DEC, NULL, 0x60, NULL, HFILL }},
		{ &hf_iec60870_5_103_cp32time2a_sum,
		{ "Summer Time", "iec60870_5_103.cp32time2a_sum", FT_UINT8, BASE_DEC, NULL, 0x80, NULL, HFILL }},
		{ &hf_iec60870_5_103_ctrlfield,
		{ "Control Field", "iec60870_5_103.ctrlfield", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_ctrl_prm,
		{ "PRM", "iec60870_5_103.ctrl_prm", FT_UINT8, BASE_DEC, VALS(iec60870_5_103_ctrl_prm_values), 0x40, "Primary Message", HFILL }},
		{ &hf_iec60870_5_103_ctrl_fcb,
		{ "FCB", "iec60870_5_103.ctrl_fcb", FT_UINT8, BASE_DEC, NULL, 0x20, "Frame Count Bit", HFILL }},
		{ &hf_iec60870_5_103_ctrl_fcv,
		{ "FCV", "iec60870_5_103.ctrl_fcv", FT_UINT8, BASE_DEC, NULL, 0x10, "Frame Count Bit Valid", HFILL }},
		{ &hf_iec60870_5_103_ctrl_dfc,
		{ "DFC", "iec60870_5_103.ctrl_dfc", FT_UINT8, BASE_DEC, NULL, 0x10, "Data Flow Control", HFILL }},
		{ &hf_iec60870_5_103_ctrl_func_pri_to_sec,
		{ "CF Func Code", "iec60870_5_103.ctrl_func_pri_to_sec", FT_UINT8, BASE_DEC, VALS(iec60870_5_103_ctrl_func_pri_to_sec_values), 0x0F, "Control Field Function Code, Pri to Sec", HFILL }},
		{ &hf_iec60870_5_103_ctrl_func_sec_to_pri,
		{ "CF Func Code", "iec60870_5_103.ctrl_func_sec_to_pri", FT_UINT8, BASE_DEC, VALS(iec60870_5_103_ctrl_func_sec_to_pri_values), 0x0F, "Control Field Function Code, Sec to Pri", HFILL }},
		{ &hf_iec60870_5_103_dco,
		{ "Double Command Type", "iec60870_5_103.dco", FT_UINT8, BASE_DEC, VALS(iec103_quadstate_types), 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_dpi,
		{ "Double Point Information", "iec60870_5_103.dpi", FT_UINT8, BASE_DEC, VALS(iec103_quadstate_types), 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_frame,
		{ "Frame Format", "iec60870_5_103.header", FT_UINT8, BASE_HEX, VALS(iec60870_5_103_frame_vals), 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_func_type,
		{ "Function Type", "iec60870_5_103.func_type", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_info_num,
		{ "Information Number", "iec60870_5_103.info_num", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_length,
		{ "Length", "iec60870_5_103.length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_linkaddr,
		{ "Data Link Address", "iec60870_5_103.linkaddr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_mfg,
		{ "Manufacturer Identity", "iec60870_5_103.mfg", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_mfg_sw,
		{ "Manufacturer's Software Identification", "iec60870_5_103.mfg_sw", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_num_user_octets,
		{ "Number of User Octets", "iec60870_5_103.num_user_octets", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_rii,
		{ "Return Information Identifier", "iec60870_5_103.rii", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_scn,
		{ "Scan Number", "iec60870_5_103.scn", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_sin,
		{ "Supplementary Information", "iec60870_5_103.sin", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_sq,
		{ "Structured Qualifier", "iec60870_5_103.sq", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
		{ &hf_iec60870_5_103_stopchar,
		{ "Stop Character", "iec60870_5_103.stopchar", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
	};

	/* Setup protocol subtree array */
	static int *ett_serial[] = {
		&ett_iec60870_5_103,
		&ett_iec60870_5_103_ctrlfield,
		&ett_iec60870_5_103_cp32time2a,
	};

	/* Register the protocol name and description */
	proto_iec60870_5_103 = proto_register_protocol("IEC 60870-5-103", "IEC 60870-5-103", "iec60870_5_103");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_iec60870_5_103, iec60870_5_103_hf, array_length(iec60870_5_103_hf));
	proto_register_subtree_array(ett_serial, array_length(ett_serial));

	iec60870_5_103_handle = register_dissector("iec60870_5_103", dissect_iec60870_5_103_tcp, proto_iec60870_5_103);
}

void
proto_reg_handoff_iec60870_5_103(void)
{
	/* Add decode-as connection to determine user-customized TCP port */
	dissector_add_for_decode_as_with_preference("tcp.port", iec60870_5_103_handle);
	/* Add dissection for serial pcap files generated by the RTAC */
	dissector_add_for_decode_as("rtacser.data", iec60870_5_103_handle);
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
