/* packet-iec104.c
 * Routines for IEC-60870-5-104 (iec104) Protocol disassembly
 *
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

#include <string.h>
#include <glib.h>
#include <math.h> /* floor */

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/wmem/wmem.h>

void proto_register_iec104apci(void);
void proto_register_iec104asdu(void);
void proto_reg_handoff_iec104(void);

/* IEC-104 comment: Fields are little endian. */

#define MAXS 256

static dissector_handle_t iec104asdu_handle;

/* the asdu header structure */
struct asduheader {
	guint16 Addr;
	guint8 OA;
	guint8 TypeId;
	guint8 TNCause;
	guint32 IOA;
	guint8 NumIx;
	guint8 SQ;
	guint8 DataLength;
};

/* ASDU command value/status structure */
typedef struct {
	gboolean OFF;
	gboolean ON;

	gboolean UP;
	gboolean DOWN;

	/* QOC qualifier-bits */
	guint16  QU;      /* qualifier-value */
	gboolean ZeroP;   /* No pulse */
	gboolean ShortP;  /* Short Pulse */
	gboolean LongP;   /* Long Pulse */
	gboolean Persist; /* Persistent output */
	gboolean SE;      /* Select (1) / Execute (0) */
} td_CmdInfo;

#define IEC104_PORT     2404

/* Define the iec104 proto */
static int proto_iec104apci = -1;
static int proto_iec104asdu = -1;

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

/* Constants relative to the filed, independent of the field position in the byte */
/* U (Unnombered) constants */
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
#define M_DP_NA_1  3    /* double-point information 								*/
#define M_ST_NA_1  5    /* step position information 								*/
#define M_BO_NA_1  7    /* bitstring of 32 bits 								*/
#define M_ME_NA_1  9    /* measured value, normalized value 							*/
#define M_ME_NB_1  11    /* measured value, scaled value 							*/
#define M_ME_NC_1  13    /* measured value, short floating point number 					*/
#define M_IT_NA_1  15    /* integrated totals 									*/
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
	{  M_DP_NA_1,		"M_DP_NA_1" },
	{  M_ST_NA_1,		"M_ST_NA_1" },
	{  M_BO_NA_1,		"M_BO_NA_1" },
	{  M_ME_NA_1,		"M_ME_NA_1" },
	{  M_ME_NB_1,		"M_ME_NB_1" },
	{  M_ME_NC_1,		"M_ME_NC_1" },
	{  M_IT_NA_1,		"M_IT_NA_1" },
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
	{  M_DP_NA_1,		"double-point information" },
	{  M_ST_NA_1,		"step position information" },
	{  M_BO_NA_1,		"bitstring of 32 bits" },
	{  M_ME_NA_1,		"measured value, normalized value" },
	{  M_ME_NB_1,		"measured value, scaled value" },
	{  M_ME_NC_1,		"measured value, short floating point number" },
	{  M_IT_NA_1,		"integrated totals" },
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
	guint8  value;
	guint8  length;
} td_asdu_length;

static const td_asdu_length asdu_length [] = {
	{  M_SP_NA_1,	 1 },
	{  M_DP_NA_1,	 1 },
	{  M_ST_NA_1,	 2 },
	{  M_BO_NA_1,	 5 },
	{  M_ME_NA_1,	 3 },
	{  M_ME_NB_1,	 3 },
	{  M_ME_NC_1,	 5 },
	{  M_IT_NA_1,	 5 },
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

/* Cause of Transmision (CauseTx) */
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

static const value_string coi_r_types[] = {
	{ 0,		"Local power switch on" },
	{ 1,		"Local manual reset" },
	{ 2,		"Remote reset" },
	{ 0, NULL }
};

static const value_string qoi_r_types[] = {
	{ 0,		"Not specified" },
	{ 20,		"Station interrogation (global)" },
	{ 21,		"Group 1 interrotagion" },
	{ 22,		"Group 2 interrotagion" },
	{ 23,		"Group 3 interrotagion" },
	{ 24,		"Group 4 interrotagion" },
	{ 25,		"Group 5 interrotagion" },
	{ 26,		"Group 6 interrotagion" },
	{ 27,		"Group 7 interrotagion" },
	{ 28,		"Group 8 interrotagion" },
	{ 29,		"Group 9 interrotagion" },
	{ 30,		"Group 10 interrotagion" },
	{ 31,		"Group 11 interrotagion" },
	{ 32,		"Group 12 interrotagion" },
	{ 33,		"Group 13 interrotagion" },
	{ 34,		"Group 14 interrotagion" },
	{ 35,		"Group 15 interrotagion" },
	{ 36,		"Group 16 interrotagion" },
	{ 0, NULL }
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

/* Protocol fields to be filtered */
static int hf_apdulen = -1;
static int hf_apcitype = -1;
static int hf_apciutype = -1;
static int hf_apcitx = -1;
static int hf_apcirx = -1;
static int hf_apcidata = -1;

static int hf_addr  = -1;
static int hf_oa  = -1;
static int hf_typeid   = -1;
static int hf_causetx  = -1;
static int hf_nega  = -1;
static int hf_test  = -1;
static int hf_ioa  = -1;
static int hf_numix  = -1;
static int hf_sq  = -1;
static int hf_cp56time  = -1;
static int hf_cp56time_ms  = -1;
static int hf_cp56time_min  = -1;
static int hf_cp56time_iv  = -1;
static int hf_cp56time_hour  = -1;
static int hf_cp56time_su  = -1;
static int hf_cp56time_day  = -1;
static int hf_cp56time_dow  = -1;
static int hf_cp56time_month  = -1;
static int hf_cp56time_year  = -1;
static int hf_siq  = -1;
static int hf_siq_spi  = -1;
static int hf_siq_bl  = -1;
static int hf_siq_sb  = -1;
static int hf_siq_nt  = -1;
static int hf_siq_iv  = -1;
static int hf_diq  = -1;
static int hf_diq_dpi  = -1;
static int hf_diq_bl  = -1;
static int hf_diq_sb  = -1;
static int hf_diq_nt  = -1;
static int hf_diq_iv  = -1;
static int hf_qds  = -1;
static int hf_qds_ov  = -1;
static int hf_qds_bl  = -1;
static int hf_qds_sb  = -1;
static int hf_qds_nt  = -1;
static int hf_qds_iv  = -1;
static int hf_vti  = -1;
static int hf_vti_v  = -1;
static int hf_vti_t  = -1;
static int hf_qos  = -1;
static int hf_qos_ql  = -1;
static int hf_qos_se  = -1;
static int hf_sco  = -1;
static int hf_sco_on  = -1;
static int hf_sco_qu  = -1;
static int hf_sco_se  = -1;
static int hf_dco  = -1;
static int hf_dco_on  = -1;
static int hf_dco_qu  = -1;
static int hf_dco_se  = -1;
static int hf_rco  = -1;
static int hf_rco_up  = -1;
static int hf_rco_qu  = -1;
static int hf_rco_se  = -1;
static int hf_coi  = -1;
static int hf_coi_r  = -1;
static int hf_coi_i  = -1;
static int hf_qoi  = -1;
static int hf_bcr_count = -1;
static int hf_bcr_sq = -1;
static int hf_bcr_cy = -1;
static int hf_bcr_ca = -1;
static int hf_bcr_iv = -1;

static int hf_asdu_bitstring = -1;
static int hf_asdu_float = -1;
static int hf_asdu_normval = -1;
static int hf_asdu_scalval = -1;

static gint ett_apci = -1;
static gint ett_asdu = -1;
static gint ett_asdu_objects = -1;
static gint ett_siq = -1;
static gint ett_diq = -1;
static gint ett_vti = -1;
static gint ett_qds = -1;
static gint ett_qos = -1;
static gint ett_sco = -1;
static gint ett_dco = -1;
static gint ett_rco = -1;
static gint ett_cp56time = -1;

static expert_field ei_iec104_short_asdu = EI_INIT;
static expert_field ei_iec104_apdu_min_len = EI_INIT;

/* Misc. functions for dissection of signal values */

/* ====================================================================
    void get_CP56Time(td_CP56Time *cp56t, tvbuff_t *tvb, guint8 offset)

    Dissects the CP56Time2a time (Seven octet binary time)
    that starts 'offset' bytes in 'tvb'.
   ==================================================================== */
static void get_CP56Time(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
{
  guint16 ms;
  guint8 value;
  guint8 su;
  struct tm tm;
  nstime_t  datetime;
  proto_item* ti;
  proto_tree* cp56time_tree;

  ms = tvb_get_letohs(tvb, *offset);
  tm.tm_sec = ms / 1000;
  datetime.nsecs = (ms % 1000) * 1000000;
  (*offset) += 2;

  value = tvb_get_guint8(tvb, *offset);
  tm.tm_min = value & 0x3F;
  (*offset)++;

  value = tvb_get_guint8(tvb, *offset);
  tm.tm_hour = value & 0x1F;
  su = value & 0x80;
  (*offset)++;

  value = tvb_get_guint8(tvb, *offset);
  tm.tm_mday = value & 0x1F;
  (*offset)++;

  value = tvb_get_guint8(tvb, *offset);
  tm.tm_mon = (value & 0x0F) - 1;
  (*offset)++;

  value = tvb_get_guint8(tvb, *offset);
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
static proto_item* get_InfoObjectAddress(guint32 *asdu_info_obj_addr, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
{
  proto_item* ti;

  /* --------  Information object address */
  *asdu_info_obj_addr = tvb_get_letoh24(tvb, *offset);
  ti = proto_tree_add_item(iec104_header_tree, hf_ioa, tvb, *offset, 3, ENC_LITTLE_ENDIAN);
  (*offset) += 3;

  return ti;
}

/* ====================================================================
    TypeId length
   ==================================================================== */
static guint8 get_TypeIdLength(guint8 TypeId)
{
  guint8 ret = 0;
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
static void get_SIQ(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
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
static void get_DIQ(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
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
static void get_QDS(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
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
static void get_QDP(tvbuff_t *tvb _U_, guint8 *offset _U_, proto_tree *iec104_header_tree _U_)
{
	/* todo */

}
#endif

/* ====================================================================
    VTI: Value with transient state indication
   ==================================================================== */
static void get_VTI(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
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
static void get_NVA(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
{
  gint16 value;
  float fvalue;

  value = (gint16)tvb_get_letohs(tvb, *offset);
  fvalue = (float)value / 32768;

  /* Normalized value F16[1..16]<-1..+1-2^-15> */
  proto_tree_add_float_format_value(iec104_header_tree, hf_asdu_normval, tvb, *offset, 2, fvalue, "%." G_STRINGIFY(FLT_DIG) "g (%d)", fvalue, value);

  (*offset) += 2;
}

static void get_NVAspt(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
{
  gint16 value;
  float fvalue;

  value = (gint16)tvb_get_letohs(tvb, *offset);
  fvalue = (float)value / 32768;

  /* Normalized value F16[1..16]<-1..+1-2^-15> */
  proto_tree_add_float_format_value(iec104_header_tree, hf_asdu_normval, tvb, *offset, 2, fvalue, "%." G_STRINGIFY(FLT_DIG) "g (%d)", fvalue, value);

  (*offset) += 2;
}

/* ====================================================================
    SVA: Scaled value
   ==================================================================== */
static void get_SVA(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
{
  /* Scaled value I16[1..16]<-2^15..+2^15-1> */
  proto_tree_add_item(iec104_header_tree, hf_asdu_scalval, tvb, *offset, 2, ENC_LITTLE_ENDIAN);

  (*offset) += 2;
}

static void get_SVAspt(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
{
  /* Scaled value I16[1..16]<-2^15..+2^15-1> */
  proto_tree_add_item(iec104_header_tree, hf_asdu_scalval, tvb, *offset, 2, ENC_LITTLE_ENDIAN);

  (*offset) += 2;
}

/* ====================================================================
    "FLT": Short floating point number
   ==================================================================== */
static void get_FLT(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
{
  /* --------  IEEE 754 float value */
  proto_tree_add_item(iec104_header_tree, hf_asdu_float, tvb, *offset, 4, ENC_LITTLE_ENDIAN);

  (*offset) += 4;
}

static void get_FLTspt(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
{
  /* --------  IEEE 754 float value */
  proto_tree_add_item(iec104_header_tree, hf_asdu_float, tvb, *offset, 4, ENC_LITTLE_ENDIAN);

  (*offset) += 4;
}

/* ====================================================================
    "BSI": Binary state information, 32 bit
   ==================================================================== */
static void get_BSI(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
{
  proto_tree_add_bits_item(iec104_header_tree, hf_asdu_bitstring, tvb, *offset*8, 32, ENC_BIG_ENDIAN);

  (*offset) += 4;
}

static void get_BSIspt(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
{
  proto_tree_add_bits_item(iec104_header_tree, hf_asdu_bitstring, tvb, *offset*8, 32, ENC_BIG_ENDIAN);

  (*offset) += 4;
}

/* ====================================================================
    BCR: Binary counter reading
   ==================================================================== */
static void get_BCR(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
{
  proto_tree_add_item(iec104_header_tree, hf_bcr_count, tvb, *offset, 4, ENC_LITTLE_ENDIAN);
  *offset += 4;

  proto_tree_add_item(iec104_header_tree, hf_bcr_sq, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(iec104_header_tree, hf_bcr_cy, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(iec104_header_tree, hf_bcr_ca, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(iec104_header_tree, hf_bcr_iv, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
  *offset += 1;
}

/* ====================================================================
    todo -- SEP: Single event of protection equipment
   ==================================================================== */
#if 0
static void get_SEP(tvbuff_t *tvb _U_, guint8 *offset _U_, proto_tree *iec104_header_tree _U_)
{
  /* todo */

}
#endif

/* ====================================================================
    QOS: Qualifier Of Set-point command
   ==================================================================== */
static void get_QOS(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
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
static void get_SCO(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
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
static void get_DCO(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
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
static void get_RCO(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
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
    COI: Cause of initialisation
   ==================================================================== */
static void get_COI(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
{
  proto_item* ti;
  proto_tree* coi_tree;

  ti = proto_tree_add_item(iec104_header_tree, hf_coi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
  coi_tree = proto_item_add_subtree(ti, ett_rco);

  proto_tree_add_item(coi_tree, hf_coi_r, tvb, *offset, 1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(coi_tree, hf_coi_i, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

  (*offset)++;
}

/* ====================================================================
    QOI: Qualifier of interrogation
   ==================================================================== */
static void get_QOI(tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree)
{
  proto_tree_add_item(iec104_header_tree, hf_qoi, tvb, *offset, 1, ENC_LITTLE_ENDIAN);

  (*offset)++;
}
/* .... end Misc. functions for dissection of signal values */


/* Find the APDU 104 (APDU=APCI+ASDU) length.
Includes possible tvb_length-1 bytes that don't form an APDU */
static guint get_iec104apdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint8 Val;
	guint32 Off;

	for (Off = 0; Off <= tvb_reported_length(tvb) - 2; Off++) {
		Val = tvb_get_guint8(tvb, offset + Off);
		if (Val == APCI_START) {
			return (guint)(Off + tvb_get_guint8(tvb, offset + Off + 1) + 2);
		}
	}

	return (guint)(tvb_reported_length(tvb));
}


/* Is is called twice: For 'Packet List' and for 'Packet Details' */
static void dissect_iec104asdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint Len = tvb_reported_length(tvb);
	guint8 Bytex;
	const char *cause_str;
	size_t Ind;
	struct asduheader asduh;
	proto_item *it104;
	proto_tree *it104tree;
	wmem_strbuf_t * res;

	guint8 offset = 0;  /* byte offset, signal dissection */
	guint8 offset_start_ioa = 0; /* position first ioa */
	guint8 i;
	guint32 asdu_info_obj_addr = 0;
	proto_item * itSignal = NULL;
	proto_tree * trSignal;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "104asdu");

	it104 = proto_tree_add_item(tree, proto_iec104asdu, tvb, 0, -1, ENC_NA);
	it104tree = proto_item_add_subtree(it104, ett_asdu);

	res = wmem_strbuf_new_label(wmem_packet_scope());

	/* Type identification */
	asduh.TypeId = tvb_get_guint8(tvb, 0);
	proto_tree_add_item(it104tree, hf_typeid, tvb, 0, 1, ENC_LITTLE_ENDIAN);
	asduh.DataLength = get_TypeIdLength(asduh.TypeId);

	/* Variable structure qualifier */
	Bytex = tvb_get_guint8(tvb, 1);
	asduh.SQ = Bytex & F_SQ;
	asduh.NumIx = Bytex & 0x7F;
	proto_tree_add_item(it104tree, hf_sq, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(it104tree, hf_numix, tvb, 1, 1, ENC_LITTLE_ENDIAN);

	/* Cause of transmission */
	asduh.TNCause = tvb_get_guint8(tvb, 2);
	proto_tree_add_item(it104tree, hf_causetx, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(it104tree, hf_nega, tvb, 2, 1, ENC_LITTLE_ENDIAN);
	proto_tree_add_item(it104tree, hf_test, tvb, 2, 1, ENC_LITTLE_ENDIAN);

	/* Originator address */
	asduh.OA = tvb_get_guint8(tvb, 3);
	proto_tree_add_item(it104tree, hf_oa, tvb, 3, 1, ENC_LITTLE_ENDIAN);

	/* Common address of ASDU */
	asduh.Addr = tvb_get_letohs(tvb, 4);
	proto_tree_add_item(it104tree, hf_addr, tvb, 4, 2, ENC_LITTLE_ENDIAN);

	/* Information object address */
	asduh.IOA = tvb_get_letoh24(tvb, 6);

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
		Len >= ASDU_HEAD_LEN ? val_to_str_const(asduh.TypeId, asdu_lngtypes, "<Unknown TypeId>") : "");

	/* 'Signal Details': TREE */
	offset = 6;  /* offset position after DUI, already stored in asduh struct */
	/* -------- get signal value and status based on ASDU type id */

	switch (asduh.TypeId) {
		case M_SP_NA_1:
		case M_DP_NA_1:
		case M_ST_NA_1:
		case M_BO_NA_1:
		case M_SP_TB_1:
		case M_DP_TB_1:
		case M_ST_TB_1:
		case M_BO_TB_1:
		case M_ME_NA_1:
		case M_ME_NB_1:
		case M_ME_NC_1:
		case M_ME_ND_1:
		case M_ME_TD_1:
		case M_ME_TE_1:
		case M_ME_TF_1:
		case M_IT_NA_1:
		case M_IT_TB_1:
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
		case C_CS_NA_1:

			/* -- object values */
			for(i = 0; i < asduh.NumIx; i++)
			{
				/* create subtree for the signal values ... */
				itSignal = proto_tree_add_text(it104tree, tvb, offset, asduh.DataLength + 3, "IOA:s");
				trSignal = proto_item_add_subtree(itSignal, ett_asdu_objects);

				/* --------  First Information object address */
				if (!i)
				{
					offset_start_ioa = offset;
					/* --------  Information object address */
					/* check length */
					if(Len < (guint)(offset + 3)) {
						expert_add_info(pinfo, itSignal, &ei_iec104_short_asdu);
						return;
					}
					get_InfoObjectAddress(&asdu_info_obj_addr, tvb, &offset, trSignal);
				} else {
					/* -------- following Information object address depending on SQ */
					if (asduh.SQ) /* <=> SQ=1, info obj addr = startaddr++ */
					{
						asdu_info_obj_addr++;
						proto_tree_add_uint(trSignal, hf_ioa, tvb, offset_start_ioa, 3, asdu_info_obj_addr);
					} else { /* SQ=0, info obj addr given */
						/* --------  Information object address */
						/* check length */
						if(Len < (guint)(offset + 3)) {
							expert_add_info(pinfo, itSignal, &ei_iec104_short_asdu);
							return;
						}
						get_InfoObjectAddress(&asdu_info_obj_addr, tvb, &offset, trSignal);
					}
				}

				proto_item_set_text(itSignal, "IOA: %d", asdu_info_obj_addr);

				/* check length */
				if(Len < (guint)(offset + asduh.DataLength)) {
					expert_add_info(pinfo, itSignal, &ei_iec104_short_asdu);
					return;
				}

				switch (asduh.TypeId) {
				case M_SP_NA_1: /* 1	Single-point information */
					get_SIQ(tvb, &offset, trSignal);
					break;
				case M_DP_NA_1: /* 3	Double-point information */
					get_DIQ(tvb, &offset, trSignal);
					break;
				case M_ST_NA_1: /* 5	Step position information */
					get_VTI(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					break;
				case M_BO_NA_1: /* 7	Bitstring of 32 bits */
					get_BSI(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					break;
				case M_ME_NA_1: /* 9	Measured value, normalized value */
					get_NVA(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					break;
				case M_ME_NB_1: /* 11     Measured value, scaled value */
					get_SVA(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					break;
				case M_ME_NC_1: /* 13	Measured value, short floating point value */
					get_FLT(tvb, &offset, trSignal);
					get_QDS(tvb, &offset, trSignal);
					break;
				case M_IT_NA_1: /* 15	Integrated totals */
					get_BCR(tvb, &offset, trSignal);
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
				case M_BO_TB_1: /* 33	bitstring of 32 bit with time tag CP56Time2a */
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
				case C_CS_NA_1: /* 103   Clock synchronization command  */
					get_CP56Time(tvb, &offset, trSignal);
					break;

				default:
    				break;
				} /* end 'switch (asduh.TypeId)' */
			} /* end 'for(i = 0; i < dui.asdu_vsq_no_of_obj; i++)' */
			break;
		default:
			proto_tree_add_item(it104tree, hf_ioa, tvb, offset, 3, ENC_LITTLE_ENDIAN);
			break;
	} /* end 'switch (asdu_typeid)' */

}



/* Is is called twice: For 'Packet List' and for 'Packet Details' */
static int dissect_iec104apci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint TcpLen = tvb_reported_length(tvb);
	guint8 Start, len, type, temp8;
	guint16 temp16;
	guint Off;
	proto_item *it104, *ti;
	proto_tree *it104tree;
	wmem_strbuf_t * res;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "104apci");

	it104 = proto_tree_add_item(tree, proto_iec104apci, tvb, 0, -1, ENC_NA);
	it104tree = proto_item_add_subtree(it104, ett_apci);

	res = wmem_strbuf_new_label(wmem_packet_scope());

	for (Off = 0; Off <= TcpLen - 2; Off++) {
		Start = tvb_get_guint8(tvb, Off);
		if (Start == APCI_START) {
			if (Off > 0)
			{
				proto_tree_add_item(it104tree, hf_apcidata, tvb, 0, Off, ENC_NA);
				wmem_strbuf_append_printf(res, "<ERR prefix %u bytes> ", Off);
			}

			proto_item_set_len(it104, Off + APCI_LEN);

			proto_tree_add_text(it104tree, tvb, Off, 1, "START");
			ti = proto_tree_add_item(it104tree, hf_apdulen, tvb, Off + 1, 1, ENC_LITTLE_ENDIAN);

			len = tvb_get_guint8(tvb, Off + 1);
			if (len < APDU_MIN_LEN) {
				expert_add_info_format(pinfo, ti, &ei_iec104_apdu_min_len, "APDU less than %d bytes", APDU_MIN_LEN);
				wmem_strbuf_append_printf(res, "<ERR ApduLen=%u bytes> ", len);
				return tvb_length(tvb);
			}

			temp8 = tvb_get_guint8(tvb, Off + 2);
			if ((temp8 & 0x01) == 0)
				type = 0;
			else
				type = temp8 & 0x03;

			if (type == I_TYPE)
				proto_tree_add_bits_item(it104tree, hf_apcitype, tvb, (Off + 2) * 8 + 7, 1, ENC_LITTLE_ENDIAN);
			else
				proto_tree_add_bits_item(it104tree, hf_apcitype, tvb, (Off + 2) * 8 + 6, 2, ENC_LITTLE_ENDIAN);

			if (len <= APDU_MAX_LEN) {
				wmem_strbuf_append_printf(res, "%s %s (",
					(pinfo->srcport == IEC104_PORT ? "->" : "<-"),
					val_to_str_const(type, apci_types, "<ERR>"));
			}
			else {
				wmem_strbuf_append_printf(res, "<ERR ApduLen=%u bytes> ", len);
			}

			switch(type) {
			case I_TYPE:
				temp16 = tvb_get_letohs(tvb, Off + 2) >> 1;
				wmem_strbuf_append_printf(res, "%d,", temp16);
				proto_tree_add_uint(it104tree, hf_apcitx, tvb, Off+2, 2, temp16);
			case S_TYPE:
				temp16 = tvb_get_letohs(tvb, Off + 4) >> 1;
				wmem_strbuf_append_printf(res, "%d) ", temp16);
				proto_tree_add_uint(it104tree, hf_apcirx, tvb, Off+4, 2, temp16);
				break;
			case U_TYPE:
				wmem_strbuf_append_printf(res, "%s) ", val_to_str_const((temp8 >> 2) & 0x3F, u_types, "<ERR>"));
				proto_tree_add_item(it104tree, hf_apciutype, tvb, Off + 2, 1, ENC_LITTLE_ENDIAN);
				break;
			}

			col_clear(pinfo->cinfo, COL_INFO);
			col_append_sep_str(pinfo->cinfo, COL_INFO, " | ", wmem_strbuf_get_str(res));
			col_set_fence(pinfo->cinfo, COL_INFO);

			proto_item_append_text(it104, ": %s", wmem_strbuf_get_str(res));

			if (type == I_TYPE)
				call_dissector(iec104asdu_handle, tvb_new_subset(tvb, Off + APCI_LEN, -1, len - APCI_DATA_LEN), pinfo, tree);

			/* Don't search more the APCI_START */
			break;
		}
	}

	if (Start != APCI_START) {
		/* Everything is bad (no APCI found) */
		proto_tree_add_item(it104tree, hf_apcidata, tvb, 0, Off, ENC_NA);
	}

	return tvb_length(tvb);
}

static int dissect_iec104reas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	/* 5th parameter = 6 = minimum bytes received to calculate the length.
	 * (Not 2 in order to find more APCIs in case of 'noisy' bytes between the APCIs)
	 */
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, APCI_LEN,
			get_iec104apdu_len, dissect_iec104apci, data);
	return tvb_length(tvb);
}

/* The protocol has two subprotocols: Register APCI */
void
proto_register_iec104apci(void)
{
	static hf_register_info hf_ap[] = {

		{ &hf_apdulen,
		  { "ApduLen", "104apci.apdulen", FT_UINT8, BASE_DEC, NULL, 0x0,
		    "APDU Len", HFILL }},

		{ &hf_apcitype,
		  { "Type", "104apci.type", FT_UINT8, BASE_HEX, VALS(apci_types), 0x00,
		    "APCI type", HFILL }},

		{ &hf_apciutype,
		  { "UType", "104apci.utype", FT_UINT8, BASE_HEX, VALS(u_types), 0xFC,
		    "Apci U type", HFILL }},

		{ &hf_apcitx,
		  { "Tx", "104apci.tx", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},

		{ &hf_apcirx,
		  { "Rx", "104apci.rx", FT_UINT16, BASE_DEC, NULL, 0,
		    NULL, HFILL }},

		{ &hf_apcidata,
		  { "Data", "104apci.data", FT_BYTES, BASE_NONE, NULL, 0,
		    NULL, HFILL }},
	};

	static gint *ett_ap[] = {
		&ett_apci,
	};

	proto_iec104apci = proto_register_protocol(
		"IEC 60870-5-104-Apci",
		"104apci",
		"104apci"
		);
	proto_register_field_array(proto_iec104apci, hf_ap, array_length(hf_ap));
	proto_register_subtree_array(ett_ap, array_length(ett_ap));
}


/* The protocol has two subprotocols: Register ASDU */
void
proto_register_iec104asdu(void)
{
	static hf_register_info hf_as[] = {

		{ &hf_addr,
		  { "Addr", "104asdu.addr", FT_UINT16, BASE_DEC, NULL, 0x0,
		    "Common Address of Asdu", HFILL }},

		{ &hf_oa,
		  { "OA", "104asdu.oa", FT_UINT8, BASE_DEC, NULL, 0x0,
		    "Originator Address", HFILL }},

		{ &hf_typeid,
		  { "TypeId", "104asdu.typeid", FT_UINT8, BASE_DEC, VALS(asdu_types), 0x0,
		    "Asdu Type Id", HFILL }},

		{ &hf_causetx,
		  { "CauseTx", "104asdu.causetx", FT_UINT8, BASE_DEC, VALS(causetx_types), F_CAUSE,
		    "Cause of Transmision", HFILL }},

		{ &hf_nega,
		  { "Negative", "104asdu.nega", FT_BOOLEAN, 8, NULL, F_NEGA,
		    NULL, HFILL }},

		{ &hf_test,
		  { "Test", "104asdu.test", FT_BOOLEAN, 8, NULL, F_TEST,
		    NULL, HFILL }},

		{ &hf_ioa,
		  { "IOA", "104asdu.ioa", FT_UINT24, BASE_DEC, NULL, 0x0,
		    "Information Object Address", HFILL }},

		{ &hf_numix,
		  { "NumIx", "104asdu.numix", FT_UINT8, BASE_DEC, NULL, 0x7F,
		    "Number of Information Objects/Elements", HFILL }},

		{ &hf_sq,
		  { "SQ", "104asdu.sq", FT_BOOLEAN, 8, NULL, F_SQ,
		    "Sequence", HFILL }},

		{ &hf_cp56time,
		  { "CP56Time", "104asdu.cp56time", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
		    NULL, HFILL }},

		{ &hf_cp56time_ms,
		  { "MS", "104asdu.cp56time.ms", FT_UINT16, BASE_DEC, NULL, 0xFFFF,
		    "CP56Time milliseconds", HFILL }},

		{ &hf_cp56time_min,
		  { "Min", "104asdu.cp56time.min", FT_UINT8, BASE_DEC, NULL, 0x3F,
		    "CP56Time minutes", HFILL }},

		{ &hf_cp56time_iv,
		  { "IV", "104asdu.cp56time.iv", FT_BOOLEAN, 8, TFS(&tfs_invalid_valid), 0x80,
		    "CP56Time invalid", HFILL }},

		{ &hf_cp56time_hour,
		  { "Hour", "104asdu.cp56time.hour", FT_UINT8, BASE_DEC, NULL, 0x1F,
		    "CP56Time hours", HFILL }},

		{ &hf_cp56time_su,
		  { "SU", "104asdu.cp56time.su", FT_BOOLEAN, 8, TFS(&tfs_local_dst), 0x80,
		    "CP56Time summer time", HFILL }},

		{ &hf_cp56time_day,
		  { "Day", "104asdu.cp56time.day", FT_UINT8, BASE_DEC, NULL, 0x1F,
		    "CP56Time day", HFILL }},

		{ &hf_cp56time_dow,
		  { "DOW", "104asdu.cp56time.dow", FT_UINT8, BASE_DEC, NULL, 0xE0,
		    "CP56Time day of week", HFILL }},

		{ &hf_cp56time_month,
		  { "Month", "104asdu.cp56time.month", FT_UINT8, BASE_DEC, NULL, 0x0F,
		    "CP56Time month", HFILL }},

		{ &hf_cp56time_year,
		  { "Year", "104asdu.cp56time.year", FT_UINT8, BASE_DEC, NULL, 0x7F,
		    "CP56Time year", HFILL }},

		{ &hf_siq,
		  { "SIQ", "104asdu.siq", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_siq_spi,
		  { "SPI", "104asdu.siq.spi", FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x01,
		    "SIQ SPI", HFILL }},

		{ &hf_siq_bl,
		  { "BL", "104asdu.siq.bl", FT_BOOLEAN, 8, TFS(&tfs_blocked_not_blocked), 0x10,
		    "SIQ BL", HFILL }},

		{ &hf_siq_sb,
		  { "SB", "104asdu.siq.sb", FT_BOOLEAN, 8, TFS(&tfs_substituted_not_substituted), 0x20,
		    "SIQ SB", HFILL }},

		{ &hf_siq_nt,
		  { "NT", "104asdu.siq.nt", FT_BOOLEAN, 8, TFS(&tfs_not_topical_topical), 0x40,
		    "SIQ NT", HFILL }},

		{ &hf_siq_iv,
		  { "IV", "104asdu.siq.iv", FT_BOOLEAN, 8, TFS(&tfs_invalid_valid), 0x80,
		    "SIQ IV", HFILL }},

		{ &hf_diq,
		  { "DIQ", "104asdu.diq", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_diq_dpi,
		  { "DPI", "104asdu.diq.dpi", FT_UINT8, BASE_DEC, VALS(diq_types), 0x03,
		    "DIQ DPI", HFILL }},

		{ &hf_diq_bl,
		  { "BL", "104asdu.diq.bl", FT_BOOLEAN, 8, TFS(&tfs_blocked_not_blocked), 0x10,
		    "DIQ BL", HFILL }},

		{ &hf_diq_sb,
		  { "SB", "104asdu.diq.sb", FT_BOOLEAN, 8, TFS(&tfs_substituted_not_substituted), 0x20,
		    "DIQ SB", HFILL }},

		{ &hf_diq_nt,
		  { "NT", "104asdu.diq.nt", FT_BOOLEAN, 8, TFS(&tfs_not_topical_topical), 0x40,
		    "DIQ NT", HFILL }},

		{ &hf_diq_iv,
		  { "IV", "104asdu.diq.iv", FT_BOOLEAN, 8, TFS(&tfs_invalid_valid), 0x80,
		    "DIQ IV", HFILL }},

		{ &hf_qds,
		  { "QDS", "104asdu.qds", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_qds_ov,
		  { "OV", "104asdu.qds.ov", FT_BOOLEAN, 8, TFS(&tfs_overflow_no_overflow), 0x01,
		    "QDS OV", HFILL }},

		{ &hf_qds_bl,
		  { "BL", "104asdu.qds.bl", FT_BOOLEAN, 8, TFS(&tfs_blocked_not_blocked), 0x10,
		    "QDS BL", HFILL }},

		{ &hf_qds_sb,
		  { "SB", "104asdu.qds.sb", FT_BOOLEAN, 8, TFS(&tfs_substituted_not_substituted), 0x20,
		    "QDS SB", HFILL }},

		{ &hf_qds_nt,
		  { "NT", "104asdu.qds.nt", FT_BOOLEAN, 8, TFS(&tfs_not_topical_topical), 0x40,
		    "QDS NT", HFILL }},

		{ &hf_qds_iv,
		  { "IV", "104asdu.qds.iv", FT_BOOLEAN, 8, TFS(&tfs_invalid_valid), 0x80,
		    "QDS IV", HFILL }},

		{ &hf_vti,
		  { "VTI", "104asdu.vti", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_vti_v,
		  { "Value", "104asdu.vti.v", FT_INT8, BASE_DEC, NULL, 0x7F,
		    "VTI Value", HFILL }},

		{ &hf_vti_t,
		  { "T", "104asdu.vti.t", FT_BOOLEAN, 8, TFS(&tfs_transient_not_transient), 0x80,
		    "VTI T", HFILL }},

		{ &hf_qos,
		  { "QOS", "104asdu.qos", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_qos_ql,
		  { "QL", "104asdu.qos.ql", FT_UINT8, BASE_DEC, NULL, 0x7F,
		    "QOS QL", HFILL }},

		{ &hf_qos_se,
		  { "S/E", "104asdu.qos.se", FT_BOOLEAN, 8, TFS(&tfs_select_execute), 0x80,
		    "QOS S/E", HFILL }},

		{ &hf_sco,
		  { "SCO", "104asdu.sco", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_sco_on,
		  { "ON/OFF", "104asdu.sco.on", FT_BOOLEAN, 8, TFS(&tfs_on_off), 0x01,
		    "SCO SCS", HFILL }},

		{ &hf_sco_qu,
		  { "QU", "104asdu.sco.qu", FT_UINT8, BASE_DEC, VALS(qos_qu_types), 0x7C,
		    "SCO QU", HFILL }},

		{ &hf_sco_se,
		  { "S/E", "104asdu.sco.se", FT_BOOLEAN, 8, TFS(&tfs_select_execute), 0x80,
		    "SCO S/E", HFILL }},

		{ &hf_dco,
		  { "DCO", "104asdu.dco", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_dco_on,
		  { "ON/OFF", "104asdu.dco.on", FT_UINT8, BASE_DEC, VALS(dco_on_types), 0x03,
		    "DCO DCS", HFILL }},

		{ &hf_dco_qu,
		  { "QU", "104asdu.dco.qu", FT_UINT8, BASE_DEC, VALS(qos_qu_types), 0x7C,
		    "DCO QU", HFILL }},

		{ &hf_dco_se,
		  { "S/E", "104asdu.dco.se", FT_BOOLEAN, 8, TFS(&tfs_select_execute), 0x80,
		    "DCO S/E", HFILL }},

		{ &hf_rco,
		  { "RCO", "104asdu.rco", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_rco_up,
		  { "UP/DOWN", "104asdu.rco.up", FT_UINT8, BASE_DEC, VALS(rco_up_types), 0x03,
		    "RCO RCS", HFILL }},

		{ &hf_rco_qu,
		  { "QU", "104asdu.rco.qu", FT_UINT8, BASE_DEC, VALS(qos_qu_types), 0x7C,
		    "RCO QU", HFILL }},

		{ &hf_rco_se,
		  { "S/E", "104asdu.rco.se", FT_BOOLEAN, 8, TFS(&tfs_select_execute), 0x80,
		    "RCO S/E", HFILL }},

		{ &hf_coi,
		  { "COI", "104asdu.coi", FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }},

		{ &hf_coi_r,
		  { "R", "104asdu.coi_r", FT_UINT8, BASE_DEC, VALS(coi_r_types), 0x7F,
		    "COI R", HFILL }},

		{ &hf_coi_i,
		  { "I", "104asdu.coi_i", FT_BOOLEAN, 8, TFS(&tfs_coi_i), 0x80,
		    "COI I", HFILL }},

		{ &hf_qoi,
		  { "QOI", "104asdu.qoi", FT_UINT8, BASE_DEC, VALS(qoi_r_types), 0,
		    NULL, HFILL }},

		{ &hf_bcr_count,
		  { "Binary Counter", "104asdu.bcr.count", FT_INT32, BASE_DEC, NULL, 0x0,
		    NULL, HFILL }},

		{ &hf_bcr_sq,
		  { "SQ", "104asdu.bcr.sq", FT_UINT8, BASE_DEC, NULL, 0x1F,
		    "Sequence Number", HFILL }},

		{ &hf_bcr_cy,
		  { "CY", "104asdu.bcr.cy", FT_BOOLEAN, 8, TFS(&tfs_overflow_no_overflow), 0x20,
		    "Counter Overflow", HFILL }},

		{ &hf_bcr_ca,
		  { "CA", "104asdu.bcr.ca", FT_BOOLEAN, 8, TFS(&tfs_adjusted_not_adjusted), 0x40,
		    "Counter Adjusted", HFILL }},

		{ &hf_bcr_iv,
		  { "IV", "104asdu.bcr.iv", FT_BOOLEAN, 8, TFS(&tfs_invalid_valid), 0x80,
		    "Counter Validity", HFILL }},

		{ &hf_asdu_bitstring,
		  { "Value", "104asdu.bitstring", FT_UINT32, BASE_HEX, NULL, 0x0,
		    "BSI value", HFILL }},

		{ &hf_asdu_float,
		  { "Value", "104asdu.float", FT_FLOAT, BASE_NONE, NULL, 0x0,
		    "Float value", HFILL }},

		{ &hf_asdu_normval,
		  { "Value", "104asdu.normval", FT_FLOAT, BASE_NONE, NULL, 0x0,
		    "Normalised value", HFILL }},

		{ &hf_asdu_scalval,
		  { "Value", "104asdu.scalval", FT_INT16, BASE_DEC, NULL, 0x0,
		    "Scaled value", HFILL }},
	};

	static gint *ett_as[] = {
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
		&ett_cp56time
	};

	static ei_register_info ei[] = {
		{ &ei_iec104_short_asdu, { "iec104.short_asdu", PI_MALFORMED, PI_ERROR, "<ERR Short Asdu>", EXPFILL }},
		{ &ei_iec104_apdu_min_len, { "iec104.apdu_min_len", PI_MALFORMED, PI_ERROR, "APDU less than bytes", EXPFILL }},
	};

	expert_module_t* expert_iec104;

	proto_iec104asdu = proto_register_protocol(
		"IEC 60870-5-104-Asdu",
		"104asdu",
		"104asdu"
		);

	proto_register_field_array(proto_iec104asdu, hf_as, array_length(hf_as));
	proto_register_subtree_array(ett_as, array_length(ett_as));
	expert_iec104 = expert_register_protocol(proto_iec104asdu);
	expert_register_field_array(expert_iec104, ei, array_length(ei));
}



/* The registration hand-off routine */
void
proto_reg_handoff_iec104(void)
{
	dissector_handle_t iec104apci_handle;

	iec104apci_handle = new_create_dissector_handle(dissect_iec104reas, proto_iec104apci);
	iec104asdu_handle = create_dissector_handle(dissect_iec104asdu, proto_iec104asdu);

	dissector_add_uint("tcp.port", IEC104_PORT, iec104apci_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
