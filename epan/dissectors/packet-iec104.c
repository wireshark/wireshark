/* packet-iec104.c
 * Routines for IEC-60870-5-104 (iec104) Protocol disassembly
 *
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <math.h> /* floor */

#include <epan/packet.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/emem.h>

/* IEC-104 comment: Fields are little endian. */

#define MAXS 256

static dissector_handle_t iec104asdu_handle;

/* the asdu header structure */
struct asduheader {
	guint8 AddrLow;
	guint8 AddrHigh;
	guint8 OA;
	guint8 TypeId;
	guint8 TNCause;
	guint32 IOA;
	guint8 NumIx;
	guint8 SQ;
};

/* the apci header structure */
struct apciheader {
	guint8 ApduLen;
	guint8 Type;
	guint8 UType;
	guint16 Tx;
	guint16 Rx;
};

/* asdu value time stamp structure */
typedef struct
{
  guint16 cp56t_ms;
  guint8 cp56t_s;
  guint8 cp56t_min;
  guint8 cp56t_h;
  guint8 cp56t_dom;    /* day of month */
  guint8 cp56t_dow;    /* day of week */
  guint8 cp56t_month;
  guint8 cp56t_year;

  gboolean IV;  /* Invalid (1) */


} td_CP56Time;

/* asdu value/status structure */
typedef struct {
	union {
		guint8  VTI; /* Value w transient state indication, */
					 /* CP8: value I7[1..7]<-64..+63>,  */
					 /* Transient BS1[8]<0..1>0: eq. not in transient state, 1: in trans ... */
		gint16 NVA;  /* Normalized value F16[1..16]<-1..+1-2^-15> */
		gint16 SVA;  /* Scaled value I16[1..16]<-2^15..+2^15-1> */
		gfloat  FLT; /* IEEE 754 float value  R32.23{Fraction,Exponent,Sign} */
		/* ToDo -- BCR Binary counter reading */
	} MV;	/* Measured Value */

	/* together with VTI */
	gboolean TRANSIENT; /* equipment is in transient state */

	/* boolean values */
	gboolean IPOS0;	/* double-point: indeterminate or intermediate state  */
	gboolean OFF;
	gboolean ON;
	gboolean IPOS3; /* double-point: indeterminate state  (fault?) */

	/* quality descriptor-bits  */
	gboolean BL;  /* Blocked (1) */
	gboolean SB;  /* Substituted (1) */
	gboolean NT;  /* Topical (0) / Not topical (1) [Topical <=> if most recent update was succesful] */
	gboolean IV;  /* Invalid (1) */
	/* from separat quality descriptor  */
	gboolean OV;  /* Overflow (1) */
	/* from separate quality descriptor  */
	gboolean EI;  /* Elapsed time valid (0) / Elapsed time invalid (1) */

} td_ValueInfo;

/* asdu command value/status structure */
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

/* asdu setpoint value/status structure */
typedef struct {
	union {
		gint16 NVA; /* Normalized value F16[1..16]<-1..+1-2^-15>            */
		gint16 SVA; /* Scaled value I16[1..16]<-2^15..+2^15-1>              */
		gfloat  FLT; /* IEEE 754 float value  R32.23{Fraction,Exponent,Sign} */
	} SP;	/* Measured Value */

	/* QOS qualifier-bits  */
	guint8 QL;    /* UI7[1..7]<0..127>; 0-default, 1..63-reserved for strd def.,     */
				  /*				64..127-reserved for special use (private range) */
	gboolean SE;  /* Select (1) / Execute (0)                                        */

} td_SpInfo;



static guint iec104port = 2404;

/* Define the iec104 proto */
static int proto_iec104apci = -1;
static int proto_iec104asdu = -1;

/* Protocol constants */
#define APCI_START	0x68
#define APCI_LEN	6
#define APCI_START_LEN	2
#define APCI_DATA_LEN	(APCI_LEN- APCI_START_LEN)
#define APDU_MIN_LEN	4
#define APDU_MAX_LEN	253

/* ASDU_HEAD_LEN: Includes Asdu head and first IOA */
#define ASDU_HEAD_LEN	9
#define F_TEST  0x80
#define F_NEGA  0x40
#define F_CAUSE 0x3F
#define F_SQ    0x80

/* APCI types */
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
#define  P_ME_NA_1  110    /* parameter of measured value, normalized value 					*/
#define  P_ME_NB_1  111    /* parameter of measured value, scaled value 					*/
#define  P_ME_NC_1  112    /* parameter of measured value, short floating-point number 				*/
#define  P_AC_NA_1  113    /* parameter activation 								*/
#define  F_FR_NA_1  120    /* file ready 									*/
#define  F_SR_NA_1  121    /* section ready 									*/
#define  F_SC_NA_1  122    /* call directory, select file, call file, call section 				*/
#define  F_LS_NA_1  123    /* last section, last segment 							*/
#define  F_AF_NA_1  124    /* ack file, ack section 								*/
#define  F_SG_NA_1  125    /* segment 										*/
#define  F_DR_TA_1  126    /* directory 									*/
#define  F_SC_NB_1  127    /* Query Log - Request archive file 							*/
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


/* Protocol fields to be filtered */
static int hf_apdulen = -1;
static int hf_apcitype = -1;
static int hf_apciutype    = -1;

static int hf_addr  = -1;
static int hf_oa  = -1;
static int hf_typeid   = -1;
static int hf_causetx  = -1;
static int hf_nega  = -1;
static int hf_test  = -1;
static int hf_ioa  = -1;
static int hf_numix  = -1;
static int hf_sq  = -1;

static gint hf_asdu_bitstring = -1;
static gint hf_asdu_float = -1;
static gint hf_asdu_normval = -1;

static gint ett_apci = -1;
static gint ett_asdu = -1;

/* Misc. functions for dissection of signal values */

/* ====================================================================
    void get_CP56Time( td_CP56Time *cp56t, tvbuff_t *tvb, guint8 offset)

    Dissects the CP56Time2a time (Seven octet binary time)
    that starts 'offset' bytes in 'tvb'.
    The time and date is put in struct 'cp56t'
   ==================================================================== */
static void get_CP56Time( td_CP56Time *cp56t, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
  guint16 ms;
  ms = tvb_get_letohs( tvb , *offset );
  (*offset) += 2;
  cp56t->cp56t_s = ms / 1000;
  cp56t->cp56t_ms = ms % 1000;

  cp56t->cp56t_min = tvb_get_guint8(tvb, *offset);
  /* "Invalid" -- Todo: test */
  cp56t->IV = cp56t->cp56t_min & 0x80;

  cp56t->cp56t_min = cp56t->cp56t_min & 0x3F;
  (*offset)++;
  cp56t->cp56t_h = 0x1F & tvb_get_guint8(tvb, *offset);
  (*offset)++;
  cp56t->cp56t_dom = tvb_get_guint8(tvb, *offset);
  cp56t->cp56t_dow = 0xE0 & cp56t->cp56t_dom;
  cp56t->cp56t_dow >>= 5;
  cp56t->cp56t_dom = cp56t->cp56t_dom & 0x1F;
  (*offset)++;
  cp56t->cp56t_month = 0x0F & tvb_get_guint8(tvb, *offset);
  (*offset)++;
  cp56t->cp56t_year = 0x7F & tvb_get_guint8(tvb, *offset);
  (*offset)++;


  if( iec104_header_tree != NULL )
  {
    /* ---- format yy-mm-dd (dow) hh:mm:ss.ms  */
    proto_tree_add_text(iec104_header_tree, tvb, (*offset)-7, 7,
          "%.2d-%.2d-%.2d (%d) %.2d:%.2d:%.2d.%.3d (%s)",
		  cp56t->cp56t_year,cp56t->cp56t_month,cp56t->cp56t_dom,
		  cp56t->cp56t_dow,cp56t->cp56t_h,cp56t->cp56t_min,
		  cp56t->cp56t_s,cp56t->cp56t_ms,cp56t->IV?"Invalid":"Valid");
  }


}


/* ====================================================================
    Information object address (Identifier)
    ASDU -> Inform Object #1 -> Information object address
   ==================================================================== */
static void get_InfoObjectAddress( guint32 *asdu_info_obj_addr, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
  /* --------  Information object address */
  *asdu_info_obj_addr = tvb_get_letoh24(tvb, *offset);
  if( iec104_header_tree != NULL )
  {
    proto_tree_add_uint(iec104_header_tree, hf_ioa,
    		tvb, *offset, 3, *asdu_info_obj_addr);

  }
  (*offset) += 3;
}




/* ====================================================================
    SIQ: Single-point information (IEV 371-02-07) w quality descriptor
   ==================================================================== */
static void get_SIQ( td_ValueInfo *value, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
  guint8 siq;
  siq = tvb_get_guint8(tvb, *offset);

  value->ON = siq & 0x01;
  value->OFF = !(value->ON);
  value->BL = siq & 0x10;  /* Blocked (1)                                       */
  value->SB = siq & 0x20;  /* Substituted (1)                                   */
  value->NT = siq & 0x40;  /* Topical (0) / Not topical (1)                     */
                           /* [Topical <=> if most recent update was succesful] */
  value->IV = siq & 0x80;  /* Invalid (1)                                       */
  if( iec104_header_tree != NULL )
  {
    proto_tree_add_text( iec104_header_tree, tvb, *offset, 1, "Value: %s - Status: %s, %s, %s, %s",
		value->ON?"ON":"OFF", value->BL?"Blocked":"Not blocked",
		value->SB?"Substituted":"Not Substituted", value->NT?"Not Topical":"Topical",
		value->IV?"Invalid":"Valid" );
  }

  (*offset)++;

}


/* ====================================================================
    DIQ: Double-point information (IEV 371-02-08) w quality descriptor
   ==================================================================== */
static void get_DIQ( td_ValueInfo *value, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{

  guint8 diq;
  diq = tvb_get_guint8(tvb, *offset);
  value->IPOS0 = FALSE;
  value->OFF = FALSE;
  value->ON = FALSE;
  value->IPOS3 = FALSE;
  switch ( diq & 0x03 )
  {
  case 0:
    value->IPOS0 = TRUE;
    break;
  case 1:
    value->OFF = TRUE;
    break;
  case 2:
    value->ON = TRUE;
    break;
  case 3:
    value->IPOS3 = TRUE;
    break;
  default:
    break;
  }
  value->BL = diq & 0x10;  /* Blocked (1)                                       */
  value->SB = diq & 0x20;  /* Substituted (1)                                   */
  value->NT = diq & 0x40;  /* Topical (0) / Not topical (1)                     */
                           /* [Topical <=> if most recent update was succesful] */
  value->IV = diq & 0x80;  /* Invalid (1)                                       */

  if( iec104_header_tree != NULL )
  {
    proto_tree_add_text( iec104_header_tree, tvb, *offset, 1, "Value: %s%s%s%s - Status: %s, %s, %s, %s",
		value->ON?"ON":"", value->OFF?"OFF":"", value->IPOS0?"IPOS0":"", value->IPOS3?"IPOS3":"",
		value->BL?"Blocked":"Not blocked", value->SB?"Substituted":"Not Substituted",
		value->NT?"Not Topical":"Topical", value->IV?"Invalid":"Valid" );
  }

  (*offset)++;

}

/* ====================================================================
    QDS: Quality descriptor (separate octet)
   ==================================================================== */
static void get_QDS( td_ValueInfo *value, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
  guint8 qds;
  /* --------  QDS quality description */
  qds = tvb_get_guint8(tvb, *offset);

  value->OV = qds & 0x01;  /* Overflow (1)                                      */
  value->BL = qds & 0x10;  /* Blocked (1)                                       */
  value->SB = qds & 0x20;  /* Substituted (1)                                   */
  value->NT = qds & 0x40;  /* Topical (0) / Not topical (1)                     */
                           /* [Topical <=> if most recent update was succesful] */
  value->IV = qds & 0x80;  /* Invalid (1)                                       */
  if( iec104_header_tree != NULL )
  {
    proto_tree_add_text( iec104_header_tree, tvb, *offset, 1, "Status: %s, %s, %s, %s, %s",
		value->OV?"Overflow!":"No Overflow", value->BL?"Blocked!":"Not Blocked",
		value->SB?"Substituted!":"Not Substituted", value->NT?"Not Topical!":"Topical",
		value->IV?"Invalid!":"Valid" );
  }

  (*offset)++;

}

/* ====================================================================
    QDP: Quality descriptor for events of protection equipment
	(separate octet)
   ==================================================================== */
#if 0
static void get_QDP( td_ValueInfo *value _U_, tvbuff_t *tvb _U_, guint8 *offset _U_, proto_tree *iec104_header_tree _U_ )
{
	/* todo */

}
#endif

/* ====================================================================
    VTI: Value with transient state indication
   ==================================================================== */
static void get_VTI( td_ValueInfo *value _U_, tvbuff_t *tvb _U_, guint8 *offset _U_, proto_tree *iec104_header_tree _U_ )
{
  guint8 vti;
  vti = tvb_get_guint8(tvb, *offset);

  value->MV.VTI= vti & 0x7F;
  value->TRANSIENT = (vti & 0x80) != 0;

  if( iec104_header_tree != NULL )
  {
    proto_tree_add_text( iec104_header_tree, tvb, *offset, 1, "Value: %d - Status: %s",
		value->MV.VTI, value->TRANSIENT?"Transient":"Not transient" );
  }

  (*offset)++;
}

/* ====================================================================
    NVA: Normalized value
   ==================================================================== */
static void get_NVA( td_ValueInfo *value, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
  /* Normalized value F16[1..16]<-1..+1-2^-15> */
	value->MV.NVA = tvb_get_letohs(tvb, *offset);

	if ( iec104_header_tree != NULL )
	{
  		proto_tree_add_int(iec104_header_tree, hf_asdu_normval,
  								tvb, *offset, 2, value->MV.NVA);
			/* todo ... presentation as float +/- 1 (val/32767) ... */
	}
	(*offset) += 2;

}

static void get_NVAspt( td_SpInfo *spt, tvbuff_t *tvb, guint8 *offset,
            proto_tree *iec104_header_tree )
{
  /* Normalized value F16[1..16]<-1..+1-2^-15> */
	spt->SP.NVA = tvb_get_letohs(tvb, *offset);

	if ( iec104_header_tree != NULL )
	{
  		proto_tree_add_int(iec104_header_tree, hf_asdu_normval,
  								tvb, *offset, 2, spt->SP.NVA);
			/* todo ... presentation as float +/- 1 */
	}
	(*offset) += 2;

}

/* ====================================================================
    SVA: Scaled value
   ==================================================================== */
static void get_SVA( td_ValueInfo *value, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
  /* Scaled value I16[1..16]<-2^15..+2^15-1> */
	value->MV.SVA = tvb_get_letohs(tvb, *offset);
	if ( iec104_header_tree != NULL )
	{
  		proto_tree_add_int(iec104_header_tree, hf_asdu_normval,
  								tvb, *offset, 2, value->MV.SVA);
	}
	(*offset) += 2;

}

static void get_SVAspt( td_SpInfo *spt, tvbuff_t *tvb, guint8 *offset,
            proto_tree *iec104_header_tree )
{
  /* Scaled value I16[1..16]<-2^15..+2^15-1> */
	spt->SP.SVA = tvb_get_letohs(tvb, *offset);
	if ( iec104_header_tree != NULL )
	{
  		proto_tree_add_int(iec104_header_tree, hf_asdu_normval,
  								tvb, *offset, 2, spt->SP.SVA);
	}
	(*offset) += 2;

}

/* ====================================================================
    "FLT": Short floating point number
   ==================================================================== */
static void get_FLT( td_ValueInfo *value, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
  	/* --------  IEEE 754 float value */
	value->MV.FLT = tvb_get_letohieee_float(tvb, *offset);

	if ( iec104_header_tree != NULL )
	{
  		proto_tree_add_float(iec104_header_tree, hf_asdu_float,
  				tvb, *offset, 4, value->MV.FLT);
	}
	(*offset) += 4;


}

static void get_FLTspt( td_SpInfo *spt, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
  	/* --------  IEEE 754 float value */
	spt->SP.FLT = tvb_get_letohieee_float(tvb, *offset);

	if ( iec104_header_tree != NULL )
	{
  		proto_tree_add_float(iec104_header_tree, hf_asdu_float,
  				tvb, *offset, 4, spt->SP.FLT);
	}
	(*offset) += 4;


}

/* ====================================================================
    "BSI": Binary state information, 32 bit
   ==================================================================== */
static void get_BSI( td_ValueInfo *value _U_, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
	if ( iec104_header_tree != NULL )
	{
		proto_tree_add_bits_item(iec104_header_tree, hf_asdu_bitstring,
				tvb, *offset*8, 32, ENC_BIG_ENDIAN);
	}
	(*offset) += 4;

}

static void get_BSIspt( td_ValueInfo *value _U_, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
	if ( iec104_header_tree != NULL )
	{
		proto_tree_add_bits_item(iec104_header_tree, hf_asdu_bitstring,
				tvb, *offset*8, 32, ENC_BIG_ENDIAN);
	}
	(*offset) += 4;

}

/* ====================================================================
    todo  -- BCR: Binary counter reading
   ==================================================================== */
/* void get_BCR( td_ValueInfo *value, tvbuff_t *tvb, guint8 *offset,
           proto_tree *iec104_header_tree );  */

/* ====================================================================
    todo -- SEP: Single event of protection equipment
   ==================================================================== */
#if 0
static void get_SEP( td_ValueInfo *value _U_, tvbuff_t *tvb _U_, guint8 *offset _U_, proto_tree *iec104_header_tree _U_ )
{
	/* todo */

}
#endif

/* ====================================================================
    QOC: Qualifier Of Command
   ==================================================================== */
static void get_QOC( td_CmdInfo *value, guint8 data )
{
	value->ZeroP   = FALSE;  /* No pulse                        */
	value->ShortP  = FALSE;  /* Short Pulse                     */
	value->LongP   = FALSE;  /* Long Pulse                      */
	value->Persist = FALSE;  /* Persistent output               */

	value->QU = data & 0x7c;
	value->QU >>= 2;

	switch( value->QU )
	{
		case 0x00:
			value->ZeroP = TRUE;
			break; /* No additional definition */
		case 0x01:
			value->ShortP = TRUE;
			break;
		case 0x02:
			value->LongP = TRUE;
			break;
		case 0x03:
			value->Persist = TRUE;
			break;
		default:
		/* case 4..31 --> reserved .. */
			;
    		break;
	}
	value->SE = data & 0x80;  /* Select (1) / Execute (0) */

}


/* ====================================================================
    QOS: Qualifier Of Set-point command
   ==================================================================== */
static void get_QOS( td_SpInfo *spt, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
	guint8 qos;
  /* --------  QOS quality description */
  qos = tvb_get_guint8(tvb, *offset);

	spt->QL = qos & 0x7F;  /* UI7[1..7]<0..127>        */
	spt->SE = qos & 0x80;  /* Select (1) / Execute (0) */

  if( iec104_header_tree != NULL )
  {
	  proto_tree_add_text( iec104_header_tree, tvb, *offset, 1, "Qualifier - QL: %d, S/E: %s",
		spt->QL, spt->SE?"Select":"Execute" );
  }

  (*offset)++;

}


/* ====================================================================
    SCO: Single Command (IEV 371-03-02)
   ==================================================================== */
static void get_SCO( td_CmdInfo *value, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
  guint8 data;
  /* On/Off */
  data = tvb_get_guint8(tvb, *offset);
  value->ON  = data & 0x01;
  value->OFF = !(value->ON);

  /* QOC */
  get_QOC( value, data );


  if( iec104_header_tree != NULL )
  {
	  if ( value->QU < 4 )
	  {
  		  proto_tree_add_text( iec104_header_tree, tvb, *offset, 1, "Command: %s%s, Qualifier: %s%s%s%s, %s",
			value->ON?"ON":"", value->OFF?"OFF":"",
			value->ZeroP?"No pulse defined":"", value->ShortP?"Short Pulse":"",
			value->LongP?"Long Pulse":"", value->Persist?"Persistent Output":"",
			value->SE?"Select":"Execute");
	  } else {
  		  proto_tree_add_text( iec104_header_tree, tvb, *offset, 1, "Command: %s%s, Qualifier: QU=%d, %s",
			value->ON?"ON":"", value->OFF?"OFF":"",
			value->QU,
			value->SE?"Select":"Execute");
  	  }
  }

  (*offset)++;

}

/* ====================================================================
    DCO: Double Command (IEV 371-03-03)
   ==================================================================== */
static void get_DCO( td_CmdInfo *value, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
  guint8 data;
  /* On/Off */
  data = tvb_get_guint8(tvb, *offset);
  value->OFF = FALSE;
  value->ON = FALSE;
  switch ( data & 0x03 )
  {
  case 1:
    value->OFF = TRUE;
    break;
  case 2:
    value->ON = TRUE;
    break;
  default:
    ;
    break;
  }

  /* QOC */
  get_QOC( value, data );


  if( iec104_header_tree != NULL )
  {
	  if ( value->QU < 4 )
	  {
  		  proto_tree_add_text( iec104_header_tree, tvb, *offset, 1, "Command: %s%s%s, Qualifier: %s%s%s%s, %s",
			value->ON?"ON":"", value->OFF?"OFF":"", (value->ON | value->OFF)?"":"Error: On/Off not defined",
			value->ZeroP?"No pulse defined":"", value->ShortP?"Short Pulse":"",
			value->LongP?"Long Pulse":"", value->Persist?"Persistent Output":"",
			value->SE?"Select":"Execute");
	  } else {
  		  proto_tree_add_text( iec104_header_tree, tvb, *offset, 1, "Command: %s%s%s, Qualifier: QU=%d, %s",
			value->ON?"ON":"", value->OFF?"OFF":"", (value->ON | value->OFF)?"":"Error: On/Off not defined",
			value->QU,
			value->SE?"Select":"Execute");
  	  }
  }

  (*offset)++;

}

/* ====================================================================
    RCO: Regulating step command (IEV 371-03-13)
   ==================================================================== */
static void get_RCO( td_CmdInfo *value, tvbuff_t *tvb, guint8 *offset, proto_tree *iec104_header_tree )
{
  guint8 data;
  /* Up/Down */
  data = tvb_get_guint8(tvb, *offset);
  value->UP = FALSE;
  value->DOWN = FALSE;
  switch ( data & 0x03 )
  {
  case 1:
    value->DOWN = TRUE;
    break;
  case 2:
    value->UP = TRUE;
    break;
  default:
    ;
    break;
  }

  /* QOC */
  get_QOC( value, data );


  if( iec104_header_tree != NULL )
  {
	  if ( value->QU < 4 )
	  {
		  proto_tree_add_text( iec104_header_tree, tvb, *offset, 1, "Command: %s%s%s, Qualifier: %s%s%s%s, %s",
			value->UP?"UP":"", value->DOWN?"DOWN":"", (value->UP | value->DOWN)?"":"Error: On/Off not defined",
			value->ZeroP?"No pulse defined":"", value->ShortP?"Short Pulse":"",
			value->LongP?"Long Pulse":"", value->Persist?"Persistent Output":"",
			value->SE?"Select":"Execute");
	  } else {
		  proto_tree_add_text( iec104_header_tree, tvb, *offset, 1, "Command: %s%s%s, Qualifier: QU=%d, %s",
			value->UP?"UP":"", value->DOWN?"DOWN":"", (value->UP | value->DOWN)?"":"Error: On/Off not defined",
			value->QU,
			value->SE?"Select":"Execute");
  	  }
  }

  (*offset)++;

}
/* .... end Misc. functions for dissection of signal values */


/* Find the APDU 104 (APDU=APCI+ASDU) length.
Includes possible tvb_length-1 bytes that don't form an APDU */
static guint get_iec104apdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset)
{
	guint8 Val;
	guint32 Off;

	for (Off= 0; Off <= tvb_length(tvb)- 2; Off++)  {
		Val = tvb_get_guint8(tvb, offset+ Off);
		if (Val == APCI_START)  {
			return (guint)(Off+ tvb_get_guint8(tvb, offset+ Off+ 1)+ 2);
		}
	}

	return (guint)(tvb_length(tvb));
}


/* Is is called twice: For 'Packet List' and for 'Packet Details' */
static void dissect_iec104asdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint Len = tvb_reported_length(tvb);
	guint8 Bytex = 0;
	const char *cause_str;
	size_t Ind = 0;
	struct asduheader * asduh;
	emem_strbuf_t * res;
	proto_item * it104 = NULL;
	proto_tree * trHead;


	guint8 offset = 0;  /* byte offset, signal dissection */
	guint8 offset_start_ioa = 0; /* position first ioa */
	guint8 i;
	guint32 asdu_info_obj_addr = 0;
	proto_item * itSignal = NULL;
	proto_tree * trSignal;
	td_ValueInfo value;  /* signal value struct */
	td_CmdInfo cmd;      /* command value struct */
	td_SpInfo  spt;	     /* setpoint value struct */
	td_CP56Time cp56t;   /* time value struct */

	if (!(check_col(pinfo->cinfo, COL_INFO) || tree))   return; /* Be sure that the function is only called twice */

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "104asdu");
	col_clear(pinfo->cinfo, COL_INFO);

	asduh = ep_alloc(sizeof(struct asduheader));
	res = ep_strbuf_new_label(NULL);

	/*** *** START: Common to 'Packet List' and 'Packet Details' *** ***/
	if (Len >= ASDU_HEAD_LEN)  {
		/* Get fields */
		asduh->AddrLow = tvb_get_guint8(tvb, 4);
		asduh->AddrHigh = tvb_get_guint8(tvb, 5);
		asduh->OA = tvb_get_guint8(tvb, 3);
		asduh->TypeId = tvb_get_guint8(tvb, 0);
		asduh->TNCause = tvb_get_guint8(tvb, 2);
		asduh->IOA = tvb_get_letoh24(tvb, 6);
		Bytex = tvb_get_guint8(tvb, 1);
		asduh->NumIx = Bytex & 0x7F;
		asduh->SQ = Bytex & F_SQ;
		/* Build common string for 'Packet List' and 'Packet Details' */
		ep_strbuf_printf(res, "%u,%u%s%u ", asduh->AddrLow, asduh->AddrHigh,  pinfo->srcport == iec104port ? "->" : "<-", asduh->OA);
		ep_strbuf_append(res, val_to_str(asduh->TypeId, asdu_types, "<TypeId=%u>"));
		ep_strbuf_append_c(res, ' ');
		cause_str = val_to_str(asduh->TNCause & F_CAUSE, causetx_types, " <CauseTx=%u>");
		ep_strbuf_append(res, cause_str);
		if (asduh->TNCause & F_NEGA)   ep_strbuf_append(res, "_NEGA");
		if (asduh->TNCause & F_TEST)   ep_strbuf_append(res, "_TEST");
		if (asduh->TNCause & (F_TEST | F_NEGA))  {
			for (Ind=strlen(cause_str); Ind< 7; Ind++)   ep_strbuf_append_c(res, ' ');
		}
		ep_strbuf_append_printf(res, " IOA=%d", asduh->IOA);
		if (asduh->NumIx > 1)   {
			if (asduh->SQ == F_SQ)   ep_strbuf_append_printf(res, "-%d", asduh->IOA + asduh->NumIx - 1);
			else      ep_strbuf_append(res, ",...");
			ep_strbuf_append_printf(res, " (%u)", asduh->NumIx);
		}
	}
	else   {
		ep_strbuf_printf(res, "<ERR Short Asdu, Len=%u>", Len);
	}
	ep_strbuf_append_c(res, ' '); /* We add a space to separate possible APCIs/ASDUs in the same packet */
	/*** *** END: Common to 'Packet List' and 'Packet Details' *** ***/

	/*** *** DISSECT 'Packet List' *** ***/
	if (check_col(pinfo->cinfo, COL_INFO))  {
		col_add_str(pinfo->cinfo, COL_INFO, res->str);
		col_set_fence(pinfo->cinfo, COL_INFO);
	}

	if(!tree)   return;

	/*** *** DISSECT 'Packet Details' *** ***/

	it104 = proto_tree_add_item(tree, proto_iec104asdu, tvb, 0, -1, FALSE);

	/* 'Packet Details': ROOT ITEM */
	proto_item_append_text(it104, ": %s'%s'", res->str, Len >= ASDU_HEAD_LEN ? val_to_str(asduh->TypeId, asdu_lngtypes, "<Unknown TypeId>") : "");

	/* 'Packet Details': TREE */
	if (Len < ASDU_HEAD_LEN)   return;
	trHead = proto_item_add_subtree(it104, ett_asdu);

	/* Remember: 	add_uint, add_boolean, _add_text: value from last parameter.
			add_item: value from tvb. */
	proto_tree_add_uint(trHead, hf_typeid, tvb, 0, 1, asduh->TypeId);
	proto_tree_add_uint(trHead, hf_numix, tvb, 1, 1, asduh->NumIx);
	proto_tree_add_uint(trHead, hf_causetx, tvb, 2, 1, asduh->TNCause & F_CAUSE);
	proto_tree_add_boolean(trHead, hf_nega, tvb, 2, 1, asduh->TNCause);
	proto_tree_add_boolean(trHead, hf_test, tvb, 2, 1, asduh->TNCause);
	proto_tree_add_uint(trHead, hf_oa, tvb, 3, 1, asduh->OA);
	proto_tree_add_uint(trHead, hf_addr, tvb, 4, 2, asduh->AddrLow+ 256* asduh->AddrHigh);
	proto_tree_add_uint(trHead, hf_ioa, tvb, 6, 3, asduh->IOA);
	if (asduh->NumIx > 1)   proto_tree_add_boolean(trHead, hf_sq, tvb, 1, 1, asduh->SQ);

	/* 'Signal Details': TREE */
	offset = 6;  /* offset position after DUI, already stored in asduh struct */
	/* -------- get signal value and status based on ASDU type id */

	switch (asduh->TypeId) {
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
		case C_CS_NA_1:

			/* create subtree for the signal values ... */
			itSignal = proto_tree_add_item( trHead, proto_iec104asdu, tvb, offset, -1, FALSE );
			proto_item_append_text(itSignal, ": Value");

			trSignal = proto_item_add_subtree( itSignal, ett_asdu );

			/* -- object values */
			for(i = 0; i < asduh->NumIx; i++)
			{
				/* --------  First Information object address */
				if (!i)
				{
					offset_start_ioa = offset;
					/* --------  Information object address */
					asdu_info_obj_addr = asduh->IOA;
					proto_tree_add_uint(trSignal, hf_ioa,
							tvb, offset_start_ioa, 3, asdu_info_obj_addr);
					/* check length */
					if( Len < (guint)(offset+3) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					offset += 3;  /* step over IOA bytes */
				} else {
					/* -------- following Information object address depending on SQ */
					if (asduh->SQ) /* <=> SQ=1, info obj addr = startaddr++ */
					{
						asdu_info_obj_addr++;
						proto_tree_add_uint(trSignal, hf_ioa,
								tvb, offset_start_ioa, 3, asdu_info_obj_addr);


					} else { /* SQ=0, info obj addr given */
						/* --------  Information object address */
						/* check length */
						if( Len < (guint)(offset+3) ) {
							proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
							return;
						}
						get_InfoObjectAddress( &asdu_info_obj_addr, tvb, &offset,
							trSignal);

					}
				}

				switch (asduh->TypeId) {
				case M_SP_NA_1: /* 1	Single-point information */
					/* check length */
					if( Len < (guint)(offset+1) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_SIQ( &value, tvb, &offset, trSignal );
					break;
				case M_DP_NA_1: /* 3	Double-point information */
					/* check length */
					if( Len < (guint)(offset+1) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_DIQ( &value, tvb, &offset, trSignal );
					break;
				case M_ST_NA_1: /* 5	Step position information */
					/* check length */
					if( Len < (guint)(offset+2) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_VTI( &value, tvb, &offset, trSignal );
					get_QDS( &value, tvb, &offset, trSignal );
					break;
				case M_BO_NA_1: /* 7	Bitstring of 32 bits */
					/* check length */
					if( Len < (guint)(offset+5) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_BSI( &value, tvb, &offset, trSignal );
					get_QDS( &value, tvb, &offset, trSignal );
					break;
				case M_ME_NA_1: /* 9	Measured value, normalized value */
					/* check length */
					if( Len < (guint)(offset+3) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_NVA( &value, tvb, &offset, trSignal );
					get_QDS( &value, tvb, &offset, trSignal );
					break;
				case M_ME_NB_1: /* 11     Measured value, scaled value */
					/* check length */
					if( Len < (guint)(offset+3) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_SVA( &value, tvb, &offset, trSignal );
					get_QDS( &value, tvb, &offset, trSignal );
					break;
				case M_ME_NC_1: /* 13	Measured value, short floating point value */
					/* check length */
					if( Len < (guint)(offset+5) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_FLT( &value, tvb, &offset, trSignal );
					get_QDS( &value, tvb, &offset, trSignal );
					break;
				case M_ME_ND_1: /* 21    Measured value, normalized value without quality descriptor */
					/* check length */
					if( Len < (guint)(offset+2) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_NVA( &value, tvb, &offset, trSignal );
					break;
				case M_SP_TB_1: /* 30	Single-point information with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+8) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_SIQ( &value, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case M_DP_TB_1: /* 31	Double-point information with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+8) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_DIQ( &value, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case M_ST_TB_1: /* 32	Step position information with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+9) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_VTI( &value, tvb, &offset, trSignal );
					get_QDS( &value, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case M_BO_TB_1: /* 33	bitstring of 32 bit with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+12) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_BSI( &value, tvb, &offset, trSignal );
					get_QDS( &value, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case M_ME_TD_1: /* 34    Measured value, normalized value with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+10) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_NVA( &value, tvb, &offset, trSignal );
					get_QDS( &value, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case M_ME_TE_1: /* 35    Measured value, scaled value with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+10) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_SVA( &value, tvb, &offset, trSignal );
					get_QDS( &value, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case M_ME_TF_1: /* 36    Measured value, short floating point value with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+12) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_FLT( &value, tvb, &offset, trSignal );
					get_QDS( &value, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case C_SC_NA_1: /* 45	Single command */
					/* check length */
					if( Len < (guint)(offset+1) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_SCO( &cmd, tvb, &offset, trSignal );
					break;
				case C_DC_NA_1: /* 46	Double command */
					/* check length */
					if( Len < (guint)(offset+1) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_DCO( &cmd, tvb, &offset, trSignal );
					break;
				case C_RC_NA_1: /* 47	Regulating step command */
					/* check length */
					if( Len < (guint)(offset+1) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_RCO( &cmd, tvb, &offset, trSignal );
					break;
				case C_SE_NA_1: /*  48    Set point command, normalized value */
					/* check length */
					if( Len < (guint)(offset+3) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_NVAspt( &spt, tvb, &offset, trSignal );
					get_QOS( &spt, tvb, &offset, trSignal );
					break;
				case C_SE_NB_1: /* 49    Set point command, scaled value */
					/* check length */
					if( Len < (guint)(offset+3) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_SVAspt( &spt, tvb, &offset, trSignal );
					get_QOS( &spt, tvb, &offset, trSignal );
					break;
				case C_SE_NC_1: /* 50    Set point command, short floating point value */
					/* check length */
					if( Len < (guint)(offset+5) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_FLTspt( &spt, tvb, &offset, trSignal );
					get_QOS( &spt, tvb, &offset, trSignal );
					break;
				case C_BO_NA_1: /* 51    Bitstring of 32 bits */
					/* check length */
					if( Len < (guint)(offset+4) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_BSIspt( &value, tvb, &offset, trSignal );
				    break;
				case C_SC_TA_1: /* 58    Single command with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+8) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_SCO( &cmd, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case C_DC_TA_1: /* 59    Double command with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+8) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_DCO( &cmd, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case C_RC_TA_1: /* 60    Regulating step command with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+8) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_RCO( &cmd, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case C_SE_TA_1: /* 61    Set point command, normalized value with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+10) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_NVAspt( &spt, tvb, &offset, trSignal );
					get_QOS( &spt, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case C_SE_TB_1: /* 62    Set point command, scaled value with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+10) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_SVAspt( &spt, tvb, &offset, trSignal );
					get_QOS( &spt, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case C_SE_TC_1: /* 63    Set point command, short floating point value with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+12) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_FLTspt( &spt, tvb, &offset, trSignal );
					get_QOS( &spt, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case C_BO_TA_1: /* 64    Bitstring of 32 bits with time tag CP56Time2a */
					/* check length */
					if( Len < (guint)(offset+11) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_BSIspt( &value, tvb, &offset, trSignal );
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;
				case C_CS_NA_1: /* 103    clock synchronization command  */
					/* check length */
					if( Len < (guint)(offset+7) ) {
						proto_tree_add_text( trSignal, tvb, offset, 1, "<ERR Short Asdu>" );
						return;
					}
					get_CP56Time( &cp56t, tvb, &offset, trSignal );
					break;

				default:
    				break;
				} /* end 'switch (asduh->TypeId)' */
			} /* end 'for(i = 0; i < dui.asdu_vsq_no_of_obj; i++)' */
			break;
		default:
			break;
	} /* end 'switch (asdu_typeid)' */

}



/* Is is called twice: For 'Packet List' and for 'Packet Details' */
static void dissect_iec104apci(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint TcpLen = tvb_length(tvb);
	guint Brossa = 0;
	guint8 Start;
	guint Off;
	guint8 Byte1 = 0;
	struct apciheader * apcih;
	emem_strbuf_t * res;
	proto_item * it104 = NULL;
	proto_tree * trHead;

	if (!(check_col(pinfo->cinfo, COL_INFO) || tree))   return; /* Be sure that the function is only called twice */

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "104apci");
	col_clear(pinfo->cinfo, COL_INFO);

	apcih = ep_alloc(sizeof(struct apciheader));

	/*** *** START: Common to 'Packet List' and 'Packet Details' *** ***/
	Start = 0;
	for (Off= 0; Off <= TcpLen- 2; Off++)  {
		Start = tvb_get_guint8(tvb, Off);
		if (Start == APCI_START)  {
			Brossa = Off;
			apcih->ApduLen = tvb_get_guint8(tvb, Off+ 1);
			if (apcih->ApduLen >= APDU_MIN_LEN)  {
				Byte1 = tvb_get_guint8(tvb, Off+ 2);
				apcih->Type = Byte1 & 0x03;
				/* Type I is only lowest bit set to 0 */
				if (apcih->Type == 2)   apcih->Type = 0;
				switch(apcih->Type)  {
				case I_TYPE:
					apcih->Tx = tvb_get_letohs(tvb, Off+ 2) >> 1;
				case S_TYPE:
					apcih->Rx = tvb_get_letohs(tvb, Off+ 4) >> 1;
					break;
				case U_TYPE:
					apcih->UType = (Byte1 & 0xFC); /* Don't shift */
					break;
				}
			}
			else   {
				/* WireShark can crash if we process packets with length less than expected (6). We consider that everything is bad */
				Brossa = TcpLen;
			}
			/* Don't search more the APCI_START */
			break;
		}
	}
	if (Start != APCI_START)  {
		/* Everything is bad (no APCI found) */
		Brossa = TcpLen;
	}
	/* Construir string comu a List i Details */
	res = ep_strbuf_new_label(NULL);
	if (Brossa > 0)
		ep_strbuf_append_printf(res, "<ERR %u bytes> ", Brossa);
	if (Brossa != TcpLen)  {
		if (apcih->ApduLen <= APDU_MAX_LEN)  {
			/* APCI in 'Paquet List' */
			ep_strbuf_append_printf(res, "%s%s(", pinfo->srcport == iec104port ? "->" : "<-", val_to_str(apcih->Type, apci_types, "<ERR>"));
			switch(apcih->Type) {  /* APCI in 'Packet List' */
			case I_TYPE:
				ep_strbuf_append_printf(res, "%d,", apcih->Tx);
			case S_TYPE:
				ep_strbuf_append_printf(res, "%d)", apcih->Rx);
				/* Align first packets */
				if (apcih->Tx < 10)
					ep_strbuf_append_c(res, ' ');
				if (apcih->Rx < 10)
					ep_strbuf_append_c(res, ' ');
				break;
			case U_TYPE:
				ep_strbuf_append_printf(res, "%s)", val_to_str(apcih->UType >> 2, u_types, "<ERR>"));
				break;
			}
			if (apcih->Type != I_TYPE  &&  apcih->ApduLen > APDU_MIN_LEN)   ep_strbuf_append_printf(res, "<ERR %u bytes> ", apcih->ApduLen- APDU_MIN_LEN);
		}
		else  {
			ep_strbuf_append_printf(res, "<ERR ApduLen=%u bytes> ", apcih->ApduLen);
		}
	}
	ep_strbuf_append_c(res, ' '); /* We add a space to separate possible APCIs/ASDUs in the same packet */
	/*** *** END: Common to 'Packet List' and 'Packet Details' *** ***/

	/*** *** Dissect 'Packet List' *** ***/
	if (check_col(pinfo->cinfo, COL_INFO))  {
		col_add_str(pinfo->cinfo, COL_INFO, res->str);
		if(apcih->Type == I_TYPE  &&  Brossa != TcpLen)   {
			call_dissector(iec104asdu_handle, tvb_new_subset(tvb, Off+ APCI_LEN, -1, apcih->ApduLen- APCI_DATA_LEN), pinfo, tree);
		} else {
			col_set_fence(pinfo->cinfo, COL_INFO);
		}
	}

	if(!tree)   return;

	/*** *** DISSECT 'Packet Details' *** ***/

	it104 = proto_tree_add_item(tree, proto_iec104apci, tvb, 0, Off+ APCI_LEN, FALSE);

	/* 'Packet Details': ROOT ITEM */
	proto_item_append_text(it104, ": %s", res->str);

	if(Brossa == TcpLen)   return;

	/* Don't call ASDU dissector if it was called before */
	if(apcih->Type == I_TYPE  &&  (!check_col(pinfo->cinfo, COL_INFO))){
		call_dissector(iec104asdu_handle, tvb_new_subset(tvb, Off+ APCI_LEN, -1, apcih->ApduLen- APCI_DATA_LEN), pinfo, tree);
	}

	/* 'Packet Details': TREE */
	trHead = proto_item_add_subtree(it104, ett_apci);
	/* Remember: 	add_uint, add_boolean, _add_text: value from last parameter.
			add_item: value from tvb. */
	proto_tree_add_uint(trHead, hf_apdulen, tvb, Off+ 1, 1, apcih->ApduLen);
	proto_tree_add_uint(trHead, hf_apcitype, tvb, Off+ 2, 1, apcih->Type);
	switch(apcih->Type){
	case U_TYPE:
		proto_tree_add_uint(trHead, hf_apciutype, tvb, Off+ 2, 1, apcih->UType); /* Don't shift the value */
		break;
	}

}




static void dissect_iec104reas(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* 5th parameter = 6 = minimum bytes received to calculate the length.
	 * (Not 2 in order to find more APCIs in case of 'noisy' bytes between the APCIs)
	 */
	tcp_dissect_pdus(tvb, pinfo, tree, TRUE, APCI_LEN,
			get_iec104apdu_len, dissect_iec104apci);
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
		  { "ApciType", "104apci.type", FT_UINT8, BASE_HEX, VALS(apci_types), 0x03,
		    "APCI type", HFILL }},

		{ &hf_apciutype,
		  { "ApciUType", "104apci.utype", FT_UINT8, BASE_HEX, VALS(u_types), 0xFC,
		    "Apci U type", HFILL }},

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
		  { "CauseTx", "104asdu.causetx", FT_UINT8, BASE_DEC, VALS(causetx_types), 0x3F,
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

		{ &hf_asdu_bitstring,
		{ "Object value", "104asdu.bitstring", FT_UINT32, BASE_HEX, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_asdu_float,
		{ "Object value", "104asdu.float", FT_FLOAT, BASE_NONE, NULL, 0x0,
		 NULL, HFILL }},

		{ &hf_asdu_normval,
		{ "Object value", "104asdu.normval", FT_INT16, BASE_DEC, NULL, 0x0,
		 NULL, HFILL }},

	};

	static gint *ett_as[] = {
		&ett_asdu,
	};

	proto_iec104asdu = proto_register_protocol(
		"IEC 60870-5-104-Asdu",
		"104asdu",
		"104asdu"
		);
	proto_register_field_array(proto_iec104asdu, hf_as, array_length(hf_as));
	proto_register_subtree_array(ett_as, array_length(ett_as));

}



/* The registration hand-off routine */
void
proto_reg_handoff_iec104(void)
{
	dissector_handle_t iec104apci_handle;

	iec104apci_handle = create_dissector_handle(dissect_iec104reas, proto_iec104apci);
	iec104asdu_handle = create_dissector_handle(dissect_iec104asdu, proto_iec104asdu);

	dissector_add_uint("tcp.port", iec104port, iec104apci_handle);
}

