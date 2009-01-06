/* packet-nas_eps.c
 * Routines for Non-Access-Stratum (NAS) protocol for Evolved Packet System (EPS) dissection
 *
 * Copyright 2008 - 2009, Anders Broman <anders.broman@ericsson.com>
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
 * References: 3GPP TS 24.301 V8.0.0 (2008-12)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include "packet-gsm_a_common.h"

#define PNAME  "Non-Access-Stratum (NAS)PDU"
#define PSNAME "NAS-EPS"
#define PFNAME "nas-eps"

/* Initialize the protocol and registered fields */
static int proto_nas_eps = -1;

static int hf_nas_eps_msg_emm_type = -1;
int hf_nas_eps_common_elem_id = -1;
int hf_nas_emm_elem_id = -1;
static int hf_nas_eps_spare_bits = -1;
static int hf_nas_eps_security_header_type = -1;
static int hf_nas_eps_emm_eps_att_type = -1;
static int hf_nas_eps_emm_nas_key_set_id = -1;
static int hf_nas_eps_emm_odd_even = -1;
static int hf_nas_eps_emm_type_of_id = -1;
static int hf_nas_eps_emm_EPS_attach_result = -1;
static int hf_nas_eps_emm_spare_half_octet = -1;
static int hf_nas_eps_emm_res = -1;
static int hf_nas_eps_emm_cause = -1;
static int hf_nas_eps_emm_short_mac = -1;
static int hf_nas_eps_active_flg = -1;
static int hf_nas_eps_eps_update_result_value = -1;
static int hf_nas_eps_eps_update_type_value = -1;

/* Initialize the subtree pointers */
static int ett_nas_eps = -1;

/* Table 9.8.1: Message types for EPS mobility management
 *	0	1	-	-	-	-	-	-		EPS mobility management messages
 */
static const value_string nas_msg_emm_strings[] = {									
	{ 0x41,	"Attach request"},
	{ 0x42,	"Attach accept"},
	{ 0x43,	"Attach complete"},
	{ 0x44,	"Attach reject"},
	{ 0x45,	"Detach request"},
	{ 0x46,	"Detach accept"},
							
	{ 0x48,	"Tracking area update request"},
	{ 0x49,	"Tracking area update accept"},
	{ 0x4a,	"Tracking area update complete"},
	{ 0x4b,	"Tracking area update reject"},
							
	{ 0x4c,	"Extended service request"},
	{ 0x4e,	"Service reject"},
									
	{ 0x50,	"GUTI reallocation command"},
	{ 0x51,	"GUTI reallocation complete"},
	{ 0x52,	"Authentication request"},
	{ 0x53,	"Authentication response"},
	{ 0x54,	"Authentication reject"},
	{ 0x5a,	"Authentication failure"},
	{ 0x55,	"Identity request"},
	{ 0x56,	"Identity response"},
	{ 0x5d,	"Security mode command"},
	{ 0x5e,	"Security mode complete"},
	{ 0x5f,	"Security mode reject"},
									
	{ 0x60,	"EMM status"},
	{ 0x61,	"EMM information"},
	{ 0x62,	"Downlink NAS transport"},
	{ 0x63,	"Uplink NAS transport"},
	{ 0,	NULL }
};

static const value_string security_header_type_vals[] = {
	{ 0,	"Not security protected, plain NAS message"},
	{ 1,	"Security protected NAS message"},
	{ 2,	"Reserved"},
	{ 3,	"Reserved"},
	{ 4,	"Reserved"},
	{ 5,	"Reserved"},
	{ 6,	"Reserved"},
	{ 7,	"Reserved"},
	{ 8,	"Reserved"},
	{ 9,	"Reserved"},
	{ 10,	"Reserved"},
	{ 11,	"Reserved"},
	{ 12,	"Security header for the SERVICE REQUEST message "},
	{ 13,	"These values are not used in this version of the protocol. If received they shall be interpreted as \"1100\". (NOTE)"},
	{ 14,	"These values are not used in this version of the protocol. If received they shall be interpreted as \"1100\". (NOTE)"},
	{ 15,	"These values are not used in this version of the protocol. If received they shall be interpreted as \"1100\". (NOTE)"},
	{ 0,	NULL }
};

const value_string nas_eps_common_elem_strings[] = {
	{ 0x00,	"EPS bearer context status" },		/* 9.9.2.1	EPS bearer context status */
	{ 0x00,	"Location area identification" },	/* 9.9.2.2	Location area identification */
	{ 0x00,	"Mobile identity" },				/* 9.9.2.3	Mobile identity */
	{ 0x00, "Mobile station classmark 2" },		/* 9.9.2.4	Mobile station classmark 2 */
	{ 0x00, "Mobile station classmark 3" },		/* 9.9.2.5	Mobile station classmark 3 */
	{ 0x00,	"PLMN list" },						/* 9.9.2.5	PLMN list */
	{ 0x00, "Supported codec list" },			/* 9.9.2.8	Supported codec list */
	{ 0, NULL }
};
#define	NUM_NAS_EPS_COMMON_ELEM (sizeof(nas_eps_common_elem_strings)/sizeof(value_string))
gint ett_nas_eps_common_elem[NUM_NAS_EPS_COMMON_ELEM];

typedef enum
{
	DE_EPS_CMN_EPS_BE_CTX_STATUS,				/* 9.9.2.1	EPS bearer context status */
	DE_EPS_CMN_LOC_AREA_ID,						/* 9.9.2.2	Location area identification */
	DE_EPS_CMN_MOB_ID,							/* 9.9.2.3	Mobile identity */
	DE_EPS_MS_CM_2,								/* 9.9.2.4	Mobile station classmark 2 */
	DE_EPS_MS_CM_3,								/* 9.9.2.5	Mobile station classmark 3 */
	DE_EPS_CMN_PLM_LST,							/* 9.9.2.6	PLMN list */
	DE_EPS_CMN_SUP_CODEC_LST,					/* 9.9.2.6	9.9.2.8	Supported codec list */
	DE_EPS_COMMON_NONE							/* NONE */
}
nas_eps_common_elem_idx_t;
/* 
 * 9.9.2	Common information elements
 */

/*
 * 9.9.2.1	EPS bearer context status
 */
static guint16
de_eps_cmn_eps_be_ctx_status(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_text(tree, tvb, curr_offset, len , "Not decoded yet");

	return len;
}
/*
 * 9.9.2.2	Location area identification
 * See subclause 10.5.1.3 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.2.3	Mobile identity
 * See subclause 10.5.1.4 in 3GPP TS 24.008 [6].
 * exported from gsm_a_common
 */

/*
 * 9.9.2.4	Mobile station classmark 2
 * See subclause 10.5.1.6 in 3GPP TS 24.008 [13].
 */
/*
 * 9.9.2.5	Mobile station classmark 3
 * See subclause 10.5.1.7 in 3GPP TS 24.008 [13].
 */
/*
 * 9.9.2.6	PLMN list
 * See subclause 10.5.1.13 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.2.7	Spare half octet
 * This element is used in the description of EMM and ESM messages when an odd number of 
 * half octet type 1 information elements are used. This element is filled with spare bits 
 * set to zero and is placed in bits 5 to 8 of the octet unless otherwise specified.
 *
 */
/*
 * 9.9.2.8	Supported codec list
 * See subclause 10.5.4.32 in 3GPP TS 24.008 [13].
 * Dissectecd in packet-gsm_a_dtap.c
 */

guint16 (*nas_eps_common_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len) = {
	/* 9.9.2	Common information elements */
	de_eps_cmn_eps_be_ctx_status,	/* 9.9.2.1	EPS bearer context status */
	de_lai,							/* 9.9.2.2	Location area identification */
	de_mid,							/* 9.9.2.3	Mobile identity */
	de_ms_cm_2,						/* 9.9.2.4	Mobile station classmark 2 */
	de_ms_cm_3,						/* 9.9.2.5	Mobile station classmark 3 */
	de_plmn_list,					/* 9.9.2.6	PLMN list */
	NULL,							/* 9.9.2.8	Supported codec list (packet-gsm_a_dtap.c) */
	NULL,	/* NONE */
};

const value_string nas_emm_elem_strings[] = {
	/* 9.9.3	EPS Mobility Management (EMM) information elements */
	{ 0x00,	"Authentication failure parameter" },	/* 9.9.3.1	Authentication failure parameter */
	{ 0x00,	"Authentication parameter AUTN" },		/* 9.9.3.2	Authentication parameter AUTN */
	{ 0x00,	"Authentication parameter RAND" },		/* 9.9.3.3	Authentication parameter RAND */
	{ 0x00,	"Authentication response parameter" },	/* 9.9.3.4	Authentication response parameter */
	{ 0x00,	"Daylight saving time" },				/* 9.9.3.6	Daylight saving time */
	{ 0x00,	"Detach type" },						/* 9.9.3.7	Detach type */
	{ 0x00,	"DRX parameter" },						/* 9.9.3.8	DRX parameter */
	{ 0x00,	"EMM cause" },							/* 9.9.3.9	EMM cause */
	{ 0x00,	"EPS attach result" },					/* 9.9.3.10	EPS attach result */
	{ 0x00,	"EPS attach type" },					/* 9.9.3.11	EPS attach type */
	{ 0x00,	"EPS mobile identity" },				/* 9.9.3.12	EPS mobile identity */
	{ 0x00,	"EPS update resul" },					/* 9.9.3.13	EPS update result */
	{ 0x00,	"EPS update type" },					/* 9.9.3.14	EPS update type */
	{ 0x00,	"ESM message container" },				/* 9.9.3.15	ESM message conta */
	{ 0x00,	"GPRS timer" },							/* 9.9.3.16	GPRS timer ,See subclause 10.5.7.3 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"Identity type 2" },					/* 9.9.3.17	Identity type 2 ,See subclause 10.5.5.9 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"IMEISV request" },						/* 9.9.3.18	IMEISV request ,See subclause 10.5.5.10 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"KSI and sequence number" },			/* 9.9.3.19	KSI and sequence number */
	{ 0x00,	"MS network capability" },				/* 9.9.3.20	MS network capability ,See subclause 10.5.5.12 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"NAS key set identifier" },				/* 9.9.3.21	NAS key set identifier */
	{ 0x00, "NAS message container" },				/* 9.9.3.22	NAS message container */
	{ 0x00,	"NAS security algorithms" },			/* 9.9.3.23	NAS security algorithms */
	{ 0x00,	"Network name" },						/* 9.9.3.24	Network name, See subclause 10.5.3.5a in 3GPP TS 24.008 [6]. */
	{ 0x00,	"Nonce" },								/* 9.9.3.25	Nonce */
	{ 0x00,	"P-TMSI signature" },					/* 9.9.3.26	P-TMSI signature, See subclause 10.5.5.8 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"Routing area identification" },		/* 9.9.3.27	Service type ,See subclause 10.5.5.15 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"Short MAC" },							/* 9.9.3.28	Short MAC */
	{ 0x00,	"Time zone" },							/* 9.9.3.29	Time zone, See subclause 10.5.3.8 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"Time zone and time" },					/* 9.9.3.30	Time zone and time, See subclause 10.5.3.9 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"TMSI status" },						/* 9.9.3.31	TMSI status, See subclause 10.5.5.4 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"Tracking area identity" },				/* 9.9.3.32	Tracking area identity */
	{ 0x00,	"Tracking area identity list" },		/* 9.9.3.33	Tracking area identity list */
	{ 0x00,	"UE network capability" },				/* 9.9.3.34	UE network capability */
	{ 0x00,	"UE radio capability information update needed" },	/* 9.9.3.35	UE radio capability information update needed */
	{ 0x00,	"UE security capability" },				/* 9.9.3.36	UE security capability */
	{ 0, NULL }
};
#define	NUM_NAS_EMM_ELEM (sizeof(nas_emm_elem_strings)/sizeof(value_string))
gint ett_nas_emm_elem[NUM_NAS_EMM_ELEM];

typedef enum
{
	/* 9.9.3	EPS Mobility Management (EMM) information elements */
	DE_EMM_AUTH_FAIL_PAR,		/* 9.9.3.1	Authentication failure parameter (dissected in packet-gsm_a_dtap.c)*/
	DE_EMM_AUTN,				/* 9.9.3.2	Authentication parameter AUTN */
	DE_EMM_AUTH_PAR_RAND,		/* 9.9.3.3	Authentication parameter RAND */
	DE_EMM_AUTH_RESP_PAR,		/* 9.9.3.4	Authentication response parameter */
	DE_EMM_CSFB_RESP,			/* 9.9.3.5	CSFB response */
	DE_EMM_DAYL_SAV_T,			/* 9.9.3.6	Daylight saving time */
	DE_EMM_DET_TYPE,			/* 9.9.3.7	Detach type */
	DE_EMM_DRX_PAR,				/* 9.9.3.8	DRX parameter (dissected in packet-gsm_a_gm.c)*/
	DE_EMM_CAUSE,				/* 9.9.3.9	EMM cause */
	DE_EMM_ATT_RES,				/* 9.9.3.10	EPS attach result (Coded inline */
	DE_EMM_ATT_TYPE,			/* 9.9.3.11	EPS attach type (Coded Inline)*/
	DE_EMM_EPS_MID,				/* 9.9.3.12	EPS mobile identity */
	DE_EMM_EPS_UPD_RES,			/* 9.9.3.13	EPS update result ( Coded inline)*/
	DE_EMM_EPS_UPD_TYPE,		/* 9.9.3.14	EPS update type */
	DE_EMM_ESM_MSG_CONT,		/* 9.9.3.15	ESM message conta */
	DE_EMM_GPRS_TIMER,			/* 9.9.3.16	GPRS timer ,See subclause 10.5.7.3 in 3GPP TS 24.008 [6]. */
	DE_EMM_ID_TYPE_2,			/* 9.9.3.17	Identity type 2 ,See subclause 10.5.5.9 in 3GPP TS 24.008 [6]. */
	DE_EMM_IMEISV_REQ,			/* 9.9.3.18	IMEISV request ,See subclause 10.5.5.10 in 3GPP TS 24.008 [6]. */
	DE_EMM_KSI_AND_SEQ_NO,		/* 9.9.3.19	KSI and sequence number */
	DE_EMM_MS_NET_CAP,			/* 9.9.3.20	MS network capability ,See subclause 10.5.5.12 in 3GPP TS 24.008 [6]. */
	DE_EMM_NAS_KEY_SET_ID,		/* 9.9.3.21	NAS key set identifier (coded inline)*/
	DE_EMM_NAS_MSG_CONT,		/* 9.9.3.22	NAS message container */
	DE_EMM_NAS_SEC_ALGS,		/* 9.9.3.23	NAS security algorithms */
	DE_EMM_NET_NAME,			/* 9.9.3.24	Network name, See subclause 10.5.3.5a in 3GPP TS 24.008 [6]. */
	DE_EMM_NONCE,				/* 9.9.3.25	Nonce */
	DE_EMM_P_TMSI,				/* 9.9.3.22	P-TMSI, See subclause 10.5.1.4 in 3GPP TS 24.008 [6]. */
	DE_EMM_P_TMSI_SIGN,			/* 9.9.3.26	P-TMSI signature, See subclause 10.5.5.8 in 3GPP TS 24.008 [6]. */
	DE_EMM_SERV_TYPE,			/* 9.9.3.27	Service type */
	DE_EMM_SHORT_MAC,			/* 9.9.3.28	Short MAC */
	DE_EMM_TZ,					/* 9.9.3.29	Time zone, See subclause 10.5.3.8 in 3GPP TS 24.008 [6]. */
	DE_EMM_TZ_AND_T,			/* 9.9.3.30	Time zone and time, See subclause 10.5.3.9 in 3GPP TS 24.008 [6]. */
	DE_EMM_TMSI_STAT,			/* 9.9.3.31	TMSI status, See subclause 10.5.5.4 in 3GPP TS 24.008 [6]. */
	DE_EMM_TRAC_AREA_ID,		/* 9.9.3.32	Tracking area identity */
	DE_EMM_TRAC_AREA_ID_LST,	/* 9.9.3.33	Tracking area identity list */
	DE_EMM_UE_NET_CAP,			/* 9.9.3.34	UE network capability */
	DE_EMM_UE_RA_CAP_INF_UPD_NEED,	/* 9.9.3.35	UE radio capability information update needed */
	DE_EMM_UE_SEC_CAP,			/* 9.9.3.36	UE security capability */
	DE_EMM_NONE					/* NONE */
}
nas_emm_elem_idx_t;

/* TODO: Update to latest spec */
/* 9.9.3	EPS Mobility Management (EMM) information elements
 * 9.9.3.1	Authentication failure parameter
 * See subclause 10.5.3.2.2 in 3GPP TS 24.008 [6].
 * (dissected in packet-gsm_a_dtap.c)
 */
/*
 * 9.9.3.2	Authentication parameter AUTN
 * See subclause 10.5.3.1.1 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.3	Authentication parameter RAND
 * See subclause 10.5.3.1 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.4	Authentication response parameter
 */
static guint16
de_emm_auth_resp_par(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_nas_eps_emm_res, tvb, curr_offset, len, FALSE);

	return len;
}
/*
 * 9.9.3.5	CSFB response
 */
/*
 * 9.9.3.6	Daylight saving time
 * See subclause 10.5.3.12 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.7	Detach type
 */
/*
Type of detach (octet 1)

In the UE to network direction:
Bits
3	2	1		
0	0	1		EPS detach
0	1	0		IMSI detach
0	1	1		combined EPS/IMSI detach

All other values are interpreted as "combined EPS/IMSI detach" in this version of the protocol.

In the network to UE direction:
Bits
3	2	1		
0	0	1		re-attach required
0	1	0		re-attach not required
0	1	1		IMSI detach

All other values are interpreted as "re-attach not required" in this version of the protocol.

Switch off (octet 1)

In the UE to network direction:
Bit
4				
0				normal detach
1				switch off

In the network to UE direction bit 4 is spare. The network shall set this bit to zero.
*/
/*
 * 9.9.3.8	DRX parameter
 * See subclause 10.5.5.6 in 3GPP TS 24.008 [13].
 */
/*
 * 9.9.3.9	EMM cause
 */
static const value_string nas_eps_emm_cause_values[] = {
	{ 0x2,	"IMSI unknown in HLR"},
	{ 0x3,	"Illegal MS"},
	{ 0x6,	"Illegal ME"},
	{ 0x7,	"EPS services not allowed"},
	{ 0x8,	"EPS services and non-EPS services not allowed"},
	{ 0x9,	"UE identity cannot be derived by the network"},
	{ 0xa,	"Implicitly detached"},
	{ 0xb,	"PLMN not allowed"},
	{ 0xc,	"Tracking Area not allowed"},
	{ 0xd,	"Roaming not allowed in this tracking area"},
	{ 0xe,	"EPS services not allowed in this PLMN"},
	{ 0xf,	"No Suitable Cells In tracking area"},
	{ 0x10,	"MSC temporarily not reachable"},
	{ 0x11,	"Network failure"},
	{ 0x12,	"CS domain not available"},
	{ 0x13,	"ESM failure"},
	{ 0x14,	"MAC failure"},
	{ 0x15,	"Synch failure"},
	{ 0x16,	"Congestion"},
	{ 0x17,	"UE security capabilities mismatch"},
	{ 0x18,	"Security mode rejected, unspecified"},
	{ 0x19,	"Not authorized for this CSG"},
	{ 0x26,	"CS fallback call establishment not allowed"},
	{ 0x27,	"CS domain temporarily not available"},
	{ 0x28,	"No EPS bearer context activated"},
	{ 0x5f,	"Semantically incorrect message"},
	{ 0x60,	"Invalid mandatory information"},
	{ 0x61,	"Message type non-existent or not implemented"},
	{ 0x62,	"Message type not compatible with the protocol state"},
	{ 0x63,	"Information element non-existent or not implemented"},
	{ 0x64,	"Conditional IE error"},
	{ 0x65,	"Message not compatible with the protocol state"},
	{ 0x6f,	"Protocol error, unspecified"},
	{ 0, NULL }
};

static guint16
de_emm_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_nas_eps_emm_cause, tvb, curr_offset, len, FALSE);
	curr_offset++;

	return curr_offset-offset;}
/*
 * 9.9.3.10	EPS attach result
 */

static const value_string nas_eps_emm_EPS_attach_result_values[] = {
	{ 0,	"reserved"},
	{ 1,	"EPS only"},
	{ 2,	"Combined EPS/IMSI attach"},
	{ 3,	"reserved"},
	{ 4,	"reserved"},
	{ 5,	"reserved"},
	{ 6,	"reserved"},
	{ 7,	"reserved"},
	{ 0, NULL }
};
/* Coded inline */

/*
 * 9.9.3.11	EPS attach type
 */

static const value_string nas_eps_emm_eps_att_type_vals[] = {
	{ 0,	"EPS attach(unused)"},
	{ 1,	"EPS attach"},
	{ 2,	"EPS attach(unused)"},
	{ 3,	"EPS attach(unused)"},
	{ 4,	"Combined handover EPS/IMSI attach"},
	{ 5,	"EPS attach(unused)"},
	{ 6,	"EPS attach(unused)"},
	{ 7,	"EPS attach(unused)"},
	{ 0, NULL }
};
/* Coded inline */

/*
 * 9.9.3.12	EPS mobile identity
 */

static const value_string nas_eps_emm_type_of_id_vals[] = {
	{ 0,	"IMSI"},
	{ 1,	"reserved"},
	{ 2,	"reserved"},
	{ 3,	"reserved"},
	{ 4,	"reserved"},
	{ 5,	"reserved"},
	{ 6,	"GUTI"},
	{ 7,	"reserved"},
	{ 0, NULL }
};
static guint16
de_emm_eps_mid(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 octet;

	curr_offset = offset;

	octet = tvb_get_guint8(tvb,offset);
	if ((octet&0x7) == 1){
		/* IMSI */
		proto_tree_add_item(tree, hf_nas_eps_emm_odd_even, tvb, curr_offset, 1, FALSE);
	}
	/* Type of identity (octet 3) */
	proto_tree_add_item(tree, hf_nas_eps_emm_type_of_id, tvb, curr_offset, 1, FALSE);
	curr_offset++;

	proto_tree_add_text(tree, tvb, curr_offset, len - 1, "Not decoded yet");
	return(len);
}
/*
 * 9.9.3.13	EPS update result
 */
static const value_string nas_eps_emm_eps_update_result_vals[] = {
	{ 0,	"TA updated"},
	{ 1,	"Combined TA/LA updated"},
	{ 2,	"TA updated and ISR activated"},
	{ 3,	"Combined TA/LA updated and ISR activated"},
	{ 0, NULL }
};

/*
 * 9.9.3.14	EPS update type
 */
static const true_false_string  nas_eps_emm_active_flg_value = {
	"Bearer establishment requested",
	"No bearer establishment requested"
};

static const value_string nas_eps_emm_eps_update_type_vals[] = {
	{ 0,	"TA updating"},
	{ 1,	"Combined TA/LA updating"},
	{ 2,	"Combined TA/LA updating with IMSI attach"},
	{ 3,	"Periodic updating"},
	{ 0, NULL }
};

/*
 * 9.9.3.15	ESM message conta
 */
static guint16
de_emm_esm_msg_cont(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;


	proto_tree_add_text(tree, tvb, curr_offset, len, "Not decoded yet");
	/* This IE can contain any ESM PDU as defined in subclause 8.3. */

	return(len);
}
/*
 * 9.9.3.16	GPRS timer
 * See subclause 10.5.7.3 in 3GPP TS 24.008 [6].
 * packet-gsm_a_gm.c
 */
/*
 * 9.9.3.17	Identity type 2
 * See subclause 10.5.5.9 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.18	IMEISV request
 * See subclause 10.5.5.10 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.19	KSI and sequence number
 */

/*
 * 9.9.3.20	MS network capability
 * See subclause 10.5.5.12 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.21	NAS key set identifier
 */
/*
Bit
4			
0			cached security context
1			mapped security context
*/

static const value_string nas_eps_emm_NAS_key_set_identifier_vals[] = {
	{ 0,	""},
	{ 1,	""},
	{ 2,	""},
	{ 3,	""},
	{ 4,	""},
	{ 5,	""},
	{ 6,	""},
	{ 7,	"No key is available"},
	{ 0, NULL }
};
/* Coded Inline */

/*
 * 9.9.3.22	NAS message container
 */
static guint16
de_emm_nas_msg_cont(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;


	proto_tree_add_text(tree, tvb, curr_offset, len , "Not decoded yet");
	

	return(len);
}
/*
 * 9.9.3.23	NAS security algorithms
 */
static guint16
de_emm_nas_sec_alsgs(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;


	proto_tree_add_text(tree, tvb, curr_offset, 1 , "Not decoded yet");
	curr_offset++;

	return(curr_offset-offset);
}
/*
 * 9.9.3.24	Network name
 * See subclause 10.5.3.5a in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.25	Nonce
 * Editor's note: The coding of this information element is FFS.
 */
static guint16
de_emm_nonce(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;


	proto_tree_add_text(tree, tvb, curr_offset, 5 , "Not decoded yet");
	curr_offset+=5;

	return(len);
}
/*
 * 9.9.3.26	P-TMSI signature
 * See subclause 10.5.5.8 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.27	Service type
 */
/*
Service type value
Bits
4	3	2	1	
0	0	0	0	mobile originating CS fallback
0	0	0	1	mobile terminating CS fallback
0	0	1	0	mobile originating CS fallback emergency call

*/
/*
 * 9.9.3.28	Short MAC
 */
static guint16
de_emm_nas_short_mac(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;


	proto_tree_add_item(tree, hf_nas_eps_emm_short_mac, tvb, curr_offset, 2, FALSE);
	curr_offset+=2;

	return(curr_offset-offset);
}
/*
 * 9.9.3.29	Time zone
 * See subclause 10.5.3.8 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.30	Time zone and time
 * See subclause 10.5.3.9 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.31	TMSI status
 * See subclause 10.5.5.4 in 3GPP TS 24.008 [6].
 */
/*
 * 9.9.3.32	Tracking area identity
 */
static guint16
de_emm_trac_area_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;


	proto_tree_add_text(tree, tvb, curr_offset, 6 , "Not decoded yet");
	curr_offset+=6;

	return(curr_offset-offset);
}
/*
 * 9.9.3.33	Tracking area identity list
 */
static guint16
de_emm_trac_area_id_lst(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;


	proto_tree_add_text(tree, tvb, curr_offset, len , "Not decoded yet");

	return(len);
}
/*
 * 9.9.3.34	UE network capability 
 */
static guint16
de_emm_ue_net_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;


	proto_tree_add_text(tree, tvb, curr_offset, len , "Not decoded yet");

	return(len);
}
/*
 * 9.9.3.35	UE radio capability information update needed
 */
/*
 * 9.9.3.36	UE security capability
 */

static guint16
de_emm_ue_sec_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;


	proto_tree_add_text(tree, tvb, curr_offset, len , "Not decoded yet");

	return(len);
}
/*
 * 9.9.4	EPS Session Management (ESM) information elements
 *
 * 9.9.4.1	Access point name
 * See subclause 10.5.6.1 in 3GPP TS 24.008 [6].
 * 9.9.4.2	ESM cause
 * 9.9.4.2a	ESM information transfer flag
 * Editor's note: The coding of this information element is FFS.
 * 9.9.4.3	Linked EPS bearer identity
 * 9.9.4.4	LLC service access point identifier
 * See subclause 10.5.6.9 in 3GPP TS 24.008 [6].
 * 9.9.4.5	Packet flow identifier
 * See subclause 10.5.6.11 in 3GPP TS 24.008 [6].
 * 9.9.4.6	PDN address
 * 9.9.4.7	PDN type
 * 9.9.4.8	Protocol configuration options
 * See subclause 10.5.6.3 in 3GPP TS 24.008 [6].
 * 9.9.4.9	Quality of service
 * See subclause 10.5.6.5 in 3GPP TS 24.008 [6].
 * 9.9.4.10	Radio priority
 * See subclause 10.5.7.2 in 3GPP TS 24.008 [6].
 * 9.9.4.11	Request type
 * 9.9.4.12	SDF quality of service
 * 9.9.4.13	Traffic flow template
 * See subclause 10.5.6.12 in 3GPP TS 24.008 [6].
 * 9.9.4.14	Transaction identifier
 */

guint16 (*emm_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len) = {
	/* 9.9.3	EPS Mobility Management (EMM) information elements */
	NULL,						/* 9.9.3.1	Authentication failure parameter(dissected in packet-gsm_a_dtap.c) */
	NULL,						/* 9.9.3.2	Authentication parameter AUTN(packet-gsm_a_dtap.c) */
	NULL,						/* 9.9.3.3	Authentication parameter RAND */
	de_emm_auth_resp_par,		/* 9.9.3.4	Authentication response parameter */
	NULL,						/* 9.9.3.5	CSFB response */
	NULL,						/* 9.9.3.6	Daylight saving time (packet-gsm_a_dtap.c)*/
	NULL,						/* 9.9.3.7	Detach type */
	NULL,						/* 9.9.3.8	DRX parameter */
	de_emm_cause,				/* 9.9.3.9	EMM cause */
	NULL,						/* 9.9.3.10	EPS attach result (coded inline) */
	NULL,						/* 9.9.3.11	EPS attach type(Coded Inline) */
	de_emm_eps_mid,				/* 9.9.3.12	EPS mobile identity */
	NULL,						/* 9.9.3.13	EPS update result (Coded Inline)*/
	NULL,						/* 9.9.3.14	EPS update type (Inline)*/
	de_emm_esm_msg_cont,		/* 9.9.3.15	ESM message conta */
	NULL,						/* 9.9.3.16	GPRS timer ,See subclause 10.5.7.3 in 3GPP TS 24.008 [6]. (packet-gsm_a_gm.c)*/
	NULL,						/* 9.9.3.17	Identity type 2 ,See subclause 10.5.5.9 in 3GPP TS 24.008 [6]. */
	NULL,						/* 9.9.3.18	IMEISV request ,See subclause 10.5.5.10 in 3GPP TS 24.008 [6]. */
	NULL,						/* 9.9.3.19	KSI and sequence number */
	NULL,						/* 9.9.3.20	MS network capability ,See subclause 10.5.5.12 in 3GPP TS 24.008 [6].(packet-gsm_a_gm.c) */
	NULL,						/* 9.9.3.21	NAS key set identifier (Coded Inline) */
	de_emm_nas_msg_cont,		/* 9.9.3.22	NAS message container */
	de_emm_nas_sec_alsgs,		/* 9.9.3.23	NAS security algorithms */
	NULL,						/* 9.9.3.24	Network name, See subclause 10.5.3.5a in 3GPP TS 24.008 [6]. (packet-gsm_a_dtap.c)*/
	de_emm_nonce,				/* 9.9.3.25	Nonce */
	NULL,						/* 9.9.3.26	P-TMSI signature, See subclause 10.5.5.8 in 3GPP TS 24.008 [6]. (packet-gsm_a_gm.c)*/
	NULL,						/* 9.9.3.27	Service type  */
	de_emm_nas_short_mac,		/* 9.9.3.28	Short MAC */
	NULL,						/* 9.9.3.29	Time zone, See subclause 10.5.3.8 in 3GPP TS 24.008 [6]. (packet-gsm_a_dtap.c)*/
	NULL,						/* 9.9.3.30	Time zone and time, See subclause 10.5.3.9 in 3GPP TS 24.008 [6]. (packet-gsm_a_dtap.c)*/
	NULL,						/* 9.9.3.31	TMSI status, See subclause 10.5.5.4 in 3GPP TS 24.008 [6]. (packet-gsm_a_gm.c)*/
	de_emm_trac_area_id,		/* 9.9.3.32	Tracking area identity */
	de_emm_trac_area_id_lst,	/* 9.9.3.33	Tracking area identity list */
	de_emm_ue_net_cap,			/* 9.9.3.34	UE network capability */
	NULL,						/* 9.9.3.35	UE radio capability information update needed */
	de_emm_ue_sec_cap,			/* 9.9.3.36	UE security capability */
	NULL,	/* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * 8.2.1	Attach accept
 */

static void
nas_emm_attach_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset, bit_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* 	EPS attach result	EPS attach result 9.9.3.10	M	V	1/2 */
	bit_offset = curr_offset<<3;
	proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_nas_eps_emm_EPS_attach_result, tvb, bit_offset, 3, FALSE);
	bit_offset+=3;
	/* 	Spare half octet	Spare half octet 9.9.2.7	M	V	1/2 */
	proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, FALSE);
	bit_offset+=4;
	/* Fix up the lengths */
	consumed = 1;/*Remove later */
	curr_len--;
	curr_offset++;
	/* 	T3412 value	GPRS timer 9.9.3.16	M	V	1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER);
	/* 	Tracking area identity list 9.9.3.33	M	LV	7-97 */
	ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID_LST, " - TAI list");
	/* 	ESM message container 9.9.3.15	M	LV-E	2-n */
	ELEM_MAND_LV_E(NAS_PDU_TYPE_EMM, DE_EMM_ESM_MSG_CONT, "");
	/* 50	GUTI	EPS mobile identity 9.9.3.12	O	TLV	13 */
	ELEM_OPT_TLV(0x50, NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, "GUTI");
	/* 13	Location area identification	Location area identification 9.9.2.2	O	TV	6 */
	ELEM_OPT_TV(0x13, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_LOC_AREA_ID, "Location area identification");
	/* 23	MS identity 	Mobile identity 9.9.2.3	O	TLV	7-10 */
	ELEM_OPT_TLV(0x23, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_MOB_ID, "MS identity");
	/* 53	EMM cause	EMM cause 9.9.3.9	O	TV	2 */
	ELEM_OPT_TV(0x53, NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, "");
	/* 17	T3402 value	GPRS timer 9.9.3.16	O	TV	2 */
	ELEM_OPT_TV(0x17, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, "T3402 value");
	/* 59	T3423 value	GPRS timer 9.9.3.16	O	TV	2 */
	ELEM_OPT_TV(0x59, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, "T3423 value");
	/* 4A	Equivalent PLMNs	PLMN list 9.9.2.6	O	TLV	5-47 */
	ELEM_OPT_TLV(0x4a, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_PLM_LST, "Equivalent PLMNs");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}
/*
 * 8.2.2	Attach complete
 */
static void
nas_emm_attach_comp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* ESM message container	ESM message container 9.9.3.15	M	LV-E	2-n */
	ELEM_MAND_LV_E(NAS_PDU_TYPE_EMM, DE_EMM_ESM_MSG_CONT, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 8.2.3	Attach reject
 */
static void
nas_emm_attach_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* * EMM cause	EMM cause 9.9.3.9	M	V	1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_EMM_CAUSE);
	/* 78 ESM message container	ESM message container 9.9.3.15	O	TLV-E	4-n */
	ELEM_OPT_TLV(0x78, NAS_PDU_TYPE_EMM, DE_EMM_ESM_MSG_CONT, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}
/*
 * 8.2.4	Attach request
 */
static void
nas_emm_attach_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset, bit_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* EPS attach type	EPS attach type 9.9.3.11	M	V	1/2  
	 * Inline:
	 */
	bit_offset = curr_offset<<3;
	
	proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_nas_eps_emm_eps_att_type, tvb, bit_offset, 3, FALSE);
	bit_offset+=3;
	/* NAS key set identifier	NAS key set identifier 9.9.3.21	M	V	1/2 */
	proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_nas_eps_emm_nas_key_set_id, tvb, bit_offset, 3, FALSE);
	bit_offset+=3;
	/* Fix up the lengths */
	curr_len--;
	curr_offset++;
	/* Old GUTI or IMSI	EPS mobile identity 9.9.3.12	M	LV	5-12 */
	ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - Old GUTI or IMSI");
	/* UE network capability	UE network capability 9.9.3.34	M	LV	3-14 */
	ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_UE_NET_CAP, "");
	/* ESM message container	ESM message container 9.9.3.15	M	LV-E	2-n */
	ELEM_MAND_LV_E(NAS_PDU_TYPE_EMM, DE_EMM_ESM_MSG_CONT, "");
	/* 52 Last visited registered TAI	Tracking area identity 9.9.3.32	O	TV	6 */
	ELEM_OPT_TV(0x52, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID, "Last visited registered TAI");
	/* 5c DRX parameter	DRX parameter 9.9.3.8	O	TV	3 */
	ELEM_OPT_TV(0x5c, GSM_A_PDU_TYPE_GM, DE_DRX_PARAM, "" );
	/* 31 MS network capability	MS network capability 9.9.3.20	M	LV	3-9 */
	ELEM_OPT_TLV( 0x31, GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP , "" );
	/* 13 Old location area identification	Location area identification 9.9.2.2	O	TV	6 */
	ELEM_OPT_TV(0x13, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_LOC_AREA_ID, "Old location area identification");
	/* 9- TMSI status	TMSI status 9.9.3.31	O	TV	1 */
	ELEM_OPT_TV_SHORT( 0x90 , GSM_A_PDU_TYPE_GM, DE_TMSI_STAT , "" );
	/* 11	Mobile station classmark 2	Mobile station classmark 2 9.9.2.5	O	TLV	5 */
	ELEM_OPT_TLV( 0x11, NAS_PDU_TYPE_COMMON, DE_EPS_MS_CM_2 , "" );
	/* 20	Mobile station classmark 3	Mobile station classmark 3 9.9.2.5	O	TLV	2-34 */
	ELEM_OPT_TLV( 0x20, NAS_PDU_TYPE_COMMON, DE_EPS_MS_CM_3 , "" );
	/* 40	Supported Codecs	Supported Codec List 9.9.2.8	O	TLV	5-n */
	ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, " - Supported Codecs");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.5	Authentication failure 
 */
static void
nas_emm_attach_fail(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	 /* EMM cause	EMM cause 9.9.3.9	M	V	1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_EMM_CAUSE);
	/* 30 Authentication failure parameter	Authentication failure parameter 9.9.3.1	O	TLV	1 */
	ELEM_OPT_TLV(0x30, GSM_A_PDU_TYPE_DTAP, DE_AUTH_FAIL_PARAM, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.6	Authentication reject
 * No IE:s
 */
/*
 * 8.2.7	Authentication request
 */

static void
nas_emm_auth_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset, bit_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* 
	 * NAS key set identifierASME 	NAS key set identifier 9.9.3.21	M	V	1/2  
	 */
	bit_offset = curr_offset<<3;
	proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_nas_eps_emm_nas_key_set_id, tvb, bit_offset, 3, FALSE);
	bit_offset+=3;
	
	/* 	Spare half octet	Spare half octet 9.9.2.7	M	V	1/2 */
	proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, FALSE);
	bit_offset+=4;
	/* Fix up the lengths */
	curr_len--;
	curr_offset++;

	/*
	 * Authentication parameter RAND (EPS challenge) 9.9.3.3	M	V	16
	 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_DTAP, DE_AUTH_PARAM_RAND);
	/*
	 * Authentication parameter AUTN (EPS challenge) 9.9.3.2	M	LV	17
	 */
	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_AUTH_PARAM_AUTN, " - EPS challenge");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}
/*
 * 8.2.8	Authentication response
 */
static void
nas_emm_auth_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	consumed = len;
	/*
	 * Authentication response parameter 9.9.3.4	M	LV	5-17
	 */
	ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_AUTH_RESP_PAR, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.9	Detach accept
 * 8.2.9.1	Detach accept (UE originating detach)
 * No further IE's
 * 8.2.9.2	Detach accept (UE terminated detach)
 * No further IE's
 */
/*
 * 8.2.10	Detach request
 * 8.2.10.1	Detach request (UE originating detach)
 * Detach type	Detach type 9.9.3.6	M	V	1/2
 * Spare half octet	Spare half octet 9.9.2.7	M	V	1/2
 * GUTI or IMSI	EPS mobile identity 9.9.3.12	M	LV	5-12
 *ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - GUTI or IMSI");
 */
/*
 * 8.2.10.2	Detach request (UE terminated detach)
 * Detach type	Detach type 9.9.3.6	M	V	1/2
 * Spare half octet	Spare half octet 9.9.2.7	M	V	1/2
 * EMM cause	EMM cause 9.9.3.9	O	TV	2
 * ELEM_OPT_TV(0x53, NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, "");
 */


/*
 * 8.2.11	Downlink NAS Transport
 */
static void
nas_emm_dl_nas_trans(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	consumed = len;
	/* NAS message container	NAS message container 9.9.3.22	M	LV	3-252 */
	ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_NAS_MSG_CONT, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.12	EMM information
 */
static void
nas_emm_emm_inf(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	consumed = len;

	/* 43	Full name for network	Network name 9.9.3.24	O	TLV	3-? */
	ELEM_OPT_TLV(0x43, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Full name for network");
	/* 45	Short name for network	Network name 9.9.3.24	O	TLV	3-? */
	ELEM_OPT_TLV(0x45, GSM_A_PDU_TYPE_DTAP, DE_NETWORK_NAME, " - Short Name");
	/* 46	Local time zone	Time zone 9.9.3.29	O	TV	2 */
	ELEM_OPT_TV(0x46, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE, " - Local");
	/* 47	Universal time and local time zone	Time zone and time 9.9.3.30	O	TV	8 */
	ELEM_OPT_TV(0x47, GSM_A_PDU_TYPE_DTAP, DE_TIME_ZONE_TIME, " - Universal Time and Local Time Zone");
	/* 49	Network daylight saving time	Daylight saving time 9.9.3.6	O	TLV	3 */
	ELEM_OPT_TLV(0x49, GSM_A_PDU_TYPE_DTAP, DE_DAY_SAVING_TIME, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}


/*
 * 8.2.13	EMM status
 */
static void
nas_emm_emm_status(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	consumed = len;

	/* EMM cause	EMM cause 9.9.3.9	M	V	1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_EMM_CAUSE);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.2.14	Extended service request
 */
static void
nas_emm_ext_serv_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	consumed = len;


	/* Service type	Service type 9.9.3.27	M	V	1/2 */
	/* NAS key set identifier	NAS key set identifier 9.9.3.21	M	V	1/2 */
	/* M-TMSI	Mobile identity 9.9.2.3	M	LV	6 */
	/* B-	CSFB response	CSFB response 9.9.3.5	C	TV	1 */

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.15	GUTI reallocation command
 */
static void
nas_emm_guti_realloc_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	consumed = len;

	/* GUTI	EPS mobile identity 9.9.3.12	M	LV	12 */
	ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - GUTI");
	
	/* 54	TAI list	Tracking area identity list 9.9.3.33	O	TLV	8-98 */
	ELEM_OPT_TLV(0x54, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID_LST, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.2.16	GUTI reallocation complete
 * No more IE's
 */
/*
 * 8.2.17	Identity request
 */

static void
nas_emm_id_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	consumed = 1;

	/* Identity type	Identity type 2 9.9.3.17	M	V	1/2 */
	/* Spare half octet	Spare half octet 9.9.2.7	M	V	1/2 */

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.18	Identity response
 */
static void
nas_emm_id_res(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Mobile identity	Mobile identity 9.9.2.3	M	LV	4-10 */
	ELEM_OPT_TLV(0x23, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_MOB_ID, "");
	
	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.2.19	NAS CS service notification
 */

/*
 * 8.2.20	Security mode command
 */
static void
nas_emm_sec_mode_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	proto_item *item;
	guint32	curr_offset, bit_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* 	Selected NAS security algorithms	NAS security algorithms 9.9.3.23	M	V	1  */
	ELEM_MAND_V(NAS_PDU_TYPE_EMM, DE_EMM_NAS_SEC_ALGS);
	/* 	NAS key set identifierASME	NAS key set identifier 9.9.3.21	M	V	1/2 */
	bit_offset = curr_offset<<3;
	proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	item = proto_tree_add_bits_item(tree, hf_nas_eps_emm_nas_key_set_id, tvb, bit_offset, 3, FALSE);
	proto_item_append_text(item," - ASME");
	bit_offset+=3;
	/* 	NAS key set identifierSGSN	NAS key set identifier 9.9.3.21	M	V	1/2 */
	bit_offset = curr_offset<<3;
	proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	item = proto_tree_add_bits_item(tree, hf_nas_eps_emm_nas_key_set_id, tvb, bit_offset, 3, FALSE);
	proto_item_append_text(item," - SGSN");
	bit_offset+=3;

	/* Fix up the lengths */
	curr_len--;
	curr_offset++;

	/* 	Replayed UE security capabilities	UE security capability 9.9.3.36	M	LV	3-6 */
	ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_UE_SEC_CAP, " - Replayed UE security capabilities");
	/* C-	IMEISV request	IMEISV request 9.9.3.18	O	TV	1 */

	/* 55	Replayed NonceUE	Nonce 9.9.3.25	O	TV	5 */
	ELEM_OPT_TV(0x55, GSM_A_PDU_TYPE_GM, DE_EMM_NONCE, " - Replayed NonceUE");
	/* 56	NonceMME	Nonce 9.9.3.25	O	TV	5 */
	ELEM_OPT_TV(0x55, GSM_A_PDU_TYPE_GM, DE_EMM_NONCE, " - NonceMME");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.21	Security mode complete
 */
static void
nas_emm_sec_mode_comp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* 23	IMEISV	Mobile identity 9.9.2.3	O	TLV	11 DE_EPS_CMN_MOB_ID*/
	ELEM_OPT_TLV(0x23, NAS_PDU_TYPE_EMM, DE_EPS_CMN_MOB_ID, "IMEISV");
 
	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.22	Security mode reject
 */
static void
nas_emm_sec_mode_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* EMM cause	EMM cause 9.9.3.9	M	V	1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_EMM_CAUSE);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.23	Security protected NAS message
 */
#if 0

static void
nas_emm_sec_prot_msg(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	proto_item *item;
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Message authentication code	Message authentication code 9.5	M	V	4 */
	/* Sequence number	Sequence number 9.6	M	V	1 */
	/* NAS message	NAS message 9.7	M	V	1-n  */
	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
#endif
/*
 * 8.2.24	Service reject
 */
static void
nas_emm_serv_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* EMM cause	EMM cause 9.9.3.9	M	V	1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_EMM_CAUSE);

	/* 5B	T3442 value	GPRS timer 9.9.3.16	C	TV	2 */

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.25	Service request
 * This message is sent by the UE to the network to request the establishment
 * of a NAS signalling connection and of the radio and S1 bearers. 
 * Its structure does not follow the structure of a standard layer 3 message. See table 8.2.22.1.
 * Protocol discriminator	Protocol discriminator 9.2	M	V	1/2
 * Security header type	Security header type 9.3.1	M	V	1/2
 * KSI and sequence number	KSI and sequence number 9.9.3.17	M	V	1
 * Message authentication code (short)	Short MAC 9.9.3.25	M	V	2
 */
/*
 * 8.2.26	Tracking area update accept
 */
static void
nas_emm_trac_area_upd_acc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset, bit_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* 	EPS update result	EPS update result 9.9.3.13	M	V	1/2 */
	bit_offset = curr_offset<<3;
	proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_nas_eps_eps_update_result_value, tvb, bit_offset, 3, FALSE);
	bit_offset+=3;
	/* 	Spare half octet	Spare half octet 9.9.2.7	M	V	1/2 */
	proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, FALSE);
	bit_offset+=4;
	/* Fix up the lengths */
	curr_len--;
	curr_offset++;
	/* 5A	T3412 value	GPRS timer 9.9.3.16	O	TV	2 */
	ELEM_OPT_TV(0x5a, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, "T3412 value");
	/* 50	GUTI	EPS mobile identity 9.9.3.12	O	TLV	13 */
	ELEM_OPT_TLV(0x50, NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, "GUTI"); 
	/* 54	TAI list	Tracking area identity list 9.9.3.33	O	TLV	8-98 */
	ELEM_OPT_TLV(0x54, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID_LST, ""); 
	/* 57	EPS bearer context status	EPS bearer context status 9.9.2.1	O	TLV	4 */
	ELEM_OPT_TLV(0x57, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_EPS_BE_CTX_STATUS, "");
	/* 13	Location area identification	Location area identification 9.9.2.2	O	TV	6 */
	ELEM_OPT_TLV(0x13, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_LOC_AREA_ID, "");
	/* 23	MS identity	Mobile identity 9.9.2.3	O	TLV	7-10  */
	ELEM_OPT_TLV(0x23, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_MOB_ID, "MS identity");
	/* 53	EMM cause	EMM cause 9.9.3.9	O	TV	2  */
	ELEM_OPT_TV(0x53, NAS_PDU_TYPE_EMM, DE_EMM_CAUSE, "");
	/* 17	T3402 value	GPRS timer 9.9.3.16	O	TV	2  */
	ELEM_OPT_TV(0x17, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, "T3402 value");
	/* 59	T3423 value	GPRS timer 9.9.3.16	O	TV	2 */
	ELEM_OPT_TV(0x59, GSM_A_PDU_TYPE_GM, DE_GPRS_TIMER, "T3423 value");
	/* 4A	Equivalent PLMNs	PLMN list 9.9.2.6	O	TLV	5-47 */
	ELEM_OPT_TLV(0x4a, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_PLM_LST, "Equivalent PLMNs");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.27	Tracking area update complete
 * No more IE's
 */
/*
 * 8.2.28	Tracking area update reject
 */
static void
nas_emm_trac_area_upd_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* EMM cause	EMM cause 9.9.3.9	M	V	1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_EMM_CAUSE);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.2.29	Tracking area update request
 */
static void
nas_emm_trac_area_upd_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	proto_item *item;
	guint32	curr_offset, bit_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* 	EPS update type	EPS update type 9.9.3.14	M	V	1/2 */
	bit_offset = curr_offset<<3;
	proto_tree_add_bits_item(tree, hf_nas_eps_active_flg, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	proto_tree_add_bits_item(tree, hf_nas_eps_eps_update_type_value, tvb, bit_offset, 3, FALSE);
	bit_offset+=3;

	/* 	Spare half octet	Spare half octet 9.9.2.7	M	V	1/2 */
	proto_tree_add_bits_item(tree, hf_nas_eps_emm_spare_half_octet, tvb, bit_offset, 4, FALSE);
	bit_offset+=4;
	/* Fix up the lengths */
	curr_len--;
	curr_offset++;
	/* 	Old GUTI 	EPS mobile identity 9.9.3.12	M	LV	12 */
	ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - Old GUTI");
	/* 	NAS key set identifierASME	NAS key set identifier 9.9.3.21	M	V	1/2 */
	bit_offset = curr_offset<<3;
	proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	item = proto_tree_add_bits_item(tree, hf_nas_eps_emm_nas_key_set_id, tvb, bit_offset, 3, FALSE);
	proto_item_append_text(item," - ASME");
	bit_offset+=3;
	/* 	NAS key set identifierSGSN	NAS key set identifier 9.9.3.21	M	V	1/2 */
	bit_offset = curr_offset<<3;
	proto_tree_add_bits_item(tree, hf_nas_eps_spare_bits, tvb, bit_offset, 1, FALSE);
	bit_offset++;
	item = proto_tree_add_bits_item(tree, hf_nas_eps_emm_nas_key_set_id, tvb, bit_offset, 3, FALSE);
	proto_item_append_text(item," - SGSN");
	bit_offset+=3;
	/* Fix up the lengths */
	curr_len--;
	curr_offset++;
	/* 19	Old P-TMSI signature	P-TMSI signature 9.9.3.26	O	TV	4 */
	ELEM_OPT_TV( 0x19 , GSM_A_PDU_TYPE_GM, DE_P_TMSI_SIG, " - Old P-TMSI Signature");
	/* 50	Additional GUTI	EPS mobile identity 9.9.3.12	O	TLV	13 */
	ELEM_OPT_TLV(0x50, NAS_PDU_TYPE_EMM, DE_EMM_EPS_MID, " - Additional GUTI");
	/* 55	NonceUE	Nonce 9.9.3.25	O	TV	5 */
	ELEM_OPT_TV(0x55, GSM_A_PDU_TYPE_GM, DE_EMM_NONCE, " - NonceUE");
	/* 58	UE network capability	UE network capability 9.9.3.34	O	TLV	4-15 */
	ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_UE_NET_CAP, "");
	/* 52	Last visited registered TAI	Tracking area identity 9.9.3.32	O	TV	6 */
	ELEM_OPT_TV(0x52, NAS_PDU_TYPE_EMM, DE_EMM_TRAC_AREA_ID, "Last visited registered TAI");
	/* 5C	DRX parameter	DRX parameter 9.9.3.8	O	TV	3 */
	ELEM_OPT_TV(0x5c, GSM_A_PDU_TYPE_GM, DE_DRX_PARAM, "" );
	/* A-	UE radio capability information update needed	UE radio capability information update needed 9.9.3.35	O	TV	1 */

	/* 57	EPS bearer context status	EPS bearer context status 9.9.2.1	O	TLV	4 */
	ELEM_OPT_TLV(0x57, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_EPS_BE_CTX_STATUS, "");
	/* 31	MS network capability	MS network capability 9.9.3.20	O	TLV	4-10 */
	ELEM_OPT_TLV( 0x31 , GSM_A_PDU_TYPE_GM, DE_MS_NET_CAP , "" );
	/* 13	Old location area identification	Location area identification 9.9.2.2	O	TV	6 */
	ELEM_OPT_TV(0x13, NAS_PDU_TYPE_COMMON, DE_EPS_CMN_LOC_AREA_ID, "Old location area identification");
 	/* 9-	TMSI status	TMSI status 9.9.3.31	O	TV	1  */
	ELEM_OPT_TV_SHORT( 0x90 , GSM_A_PDU_TYPE_GM, DE_TMSI_STAT , "" );
	/* 11	Mobile station classmark 2	Mobile station classmark 2 9.9.2.5	O	TLV	5 */
	ELEM_OPT_TLV( 0x11, NAS_PDU_TYPE_COMMON, DE_EPS_MS_CM_2 , "" );
	/* 20	Mobile station classmark 3	Mobile station classmark 3 9.9.2.5	O	TLV	2-34 */
	ELEM_OPT_TLV( 0x20, NAS_PDU_TYPE_COMMON, DE_EPS_MS_CM_3 , "" );
	/* 40	Supported Codecs	Supported Codec List 9.9.2.8	O	TLV	5-n */
	ELEM_OPT_TLV(0x40, GSM_A_PDU_TYPE_DTAP, DE_SUP_CODEC_LIST, " - Supported Codecs");
 
	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 8.2.30	Uplink NAS Transport
 */
static void
nas_emm_ul_nas_trans(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* NAS message container	NAS message container 9.9.3.22	M	LV	3-252*/
	ELEM_MAND_LV(NAS_PDU_TYPE_EMM, DE_EMM_NAS_MSG_CONT, "");
 
	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}
/*
 * 8.3	EPS session management messages
 */
/*
 * 8.3.1	Activate dedicated EPS bearer context accept
 * 27	Protocol configuration options	Protocol configuration options 9.9.4.8	O	TLV	3-253
 */
/*
 * 8.3.2	Activate dedicated EPS bearer context reject
 * 	ESM cause	ESM cause 9.9.4.2	M	V	1
 * 27	Protocol configuration options	Protocol configuration options 9.9.4.8	O	TLV	3-253
 */
/*
 * 8.3.3	Activate dedicated EPS bearer context request
 	Linked EPS bearer identity	Linked EPS bearer identity
9.9.4.6	M	V	1/2
	Spare half octet	Spare half octet
9.9.2.7	M	V	1/2
	EPS QoS	EPS quality of service
9.9.4.3	M	LV	2-10
	TFT	Traffic flow template
9.9.4.16	M	LV	2-256
5D	Transaction identifier	Transaction identifier
9.9.4.17	O	TLV	3-4
30	Negotiated QoS	Quality of service
9.9.4.12	O	TLV	14-18
32	Negotiated LLC SAPI	LLC service access point identifier
9.9.4.7	O	TV	2
8-	Radio priority	Radio priority
9.9.4.13	O	TV	1
34	Packet flow Identifier	Packet flow Identifier
9.9.4.8	O	TLV	3
27	Protocol configuration options	Protocol configuration options
9.9.4.11	O	TLV	3-253

 */
/*
 * 8.3.3	Activate dedicated EPS bearer context requ
 *
 */

/*
 * 8.3.4	Activate default EPS bearer context accept
 */








#define	NUM_NAS_MSG_EMM (sizeof(nas_msg_emm_strings)/sizeof(value_string))
static gint ett_nas_msg_emm[NUM_NAS_MSG_EMM];
static void (*nas_msg_emm_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
	nas_emm_attach_req,			/* Attach request */
	nas_emm_attach_acc,			/* Attach accept */
	nas_emm_attach_comp,		/* Attach complete */
	nas_emm_attach_rej,			/* Attach reject */
	NULL,	/* Detach request */
	NULL,	/* Detach accept */
							
	nas_emm_trac_area_upd_req,	/* Tracking area update request */
	nas_emm_trac_area_upd_acc,	/* Tracking area update accept */
	NULL,						/* Tracking area update complete (No IE's)*/
	nas_emm_trac_area_upd_rej,	/* Tracking area update reject */
			
	nas_emm_ext_serv_req,		/* Extended service request */
	nas_emm_serv_rej,			/* Service reject */
									
	nas_emm_guti_realloc_cmd,	/* GUTI reallocation command */
	NULL,						/* GUTI reallocation complete (No IE's) */
	nas_emm_auth_req,			/* Authentication request */
	nas_emm_auth_resp,			/* Authentication response */
	NULL,						/* Authentication reject (No IE:s)*/
	nas_emm_attach_fail,		/* Authentication failure */
	nas_emm_id_req,				/* Identity request */
	nas_emm_id_res,				/* Identity response */
/* 	NULL,						8.2.19	NAS CS service notification */
	nas_emm_sec_mode_cmd,		/* Security mode command */
	nas_emm_sec_mode_comp,		/* Security mode complete */
	nas_emm_sec_mode_rej,		/* Security mode reject */
									
	nas_emm_emm_status,			/* EMM status */
	nas_emm_emm_inf,			/* EMM information */
	nas_emm_dl_nas_trans,		/* Downlink NAS transport */
	nas_emm_ul_nas_trans,		/* Uplink NAS transport */
	NULL,	/* NONE */

};

void get_nas_emm_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn)
{
	gint			idx;

	*msg_str = match_strval_idx((guint32) (oct & 0xff), nas_msg_emm_strings, &idx);
	*ett_tree = ett_nas_msg_emm[idx];
	*hf_idx = hf_nas_eps_msg_emm_type;
	*msg_fcn = nas_msg_emm_fcn[idx];

	return;
}

static void
dissect_nas_eps(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *item;
	proto_tree *nas_eps_tree;
	const gchar		*msg_str;
	guint32			len;
	gint			ett_tree;
	int				hf_idx;
	void			(*msg_fcn)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len);
	guint8 security_header_type, pd, oct;
	int offset = 0;

	/* make entry in the Protocol column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "NAS-EPS");

	len = tvb_length(tvb);

	item = proto_tree_add_item(tree, proto_nas_eps, tvb, 0, -1, FALSE);
	nas_eps_tree = proto_item_add_subtree(item, ett_nas_eps);
	/* 9.3.1	Security header type */
	security_header_type = tvb_get_guint8(tvb,offset)>>4;
	proto_tree_add_item(nas_eps_tree, hf_nas_eps_security_header_type, tvb, 0, 1, FALSE);
	if (security_header_type !=0)
		/* XXX Add further decoding here? */
		return;
	pd = tvb_get_guint8(tvb,offset)&0x0f;
	proto_tree_add_item(nas_eps_tree, hf_gsm_a_L3_protocol_discriminator, tvb, 0, 1, FALSE);
	offset++;
	/*messge type IE*/
	oct = tvb_get_guint8(tvb,offset);
	msg_fcn = NULL;
	ett_tree = -1;
	hf_idx = -1;
	msg_str = NULL;

	/* Debug
	 * 	proto_tree_add_text(nas_eps_tree, tvb, offset, 1,"Pd %u MSG %u", pd,oct);
	 */

	switch (pd){
		case 8:
			get_nas_emm_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn);
			break;
		default:
			proto_tree_add_text(nas_eps_tree, tvb, offset, len - offset, "PD not decoded yet");
			return;
			break;
	}

	if(msg_str){
		if (check_col(pinfo->cinfo, COL_INFO)){
			col_append_fstr(pinfo->cinfo, COL_INFO, " %s ", msg_str);
		}
	}

	/*
	 * Add NAS message name
	 */
	proto_tree_add_item(nas_eps_tree, hf_idx, tvb, offset, 1, FALSE);
	offset++;


	/*
	 * decode elements
	 */
	if (msg_fcn == NULL)
	{
		proto_tree_add_text(nas_eps_tree, tvb, offset, len - offset,
			"Message Elements");
	}
	else
	{
		(*msg_fcn)(tvb, nas_eps_tree, offset, len - offset);
	}
	
}

void proto_register_nas_eps(void) {
	guint		i;
	guint		last_offset;

	/* List of fields */

  static hf_register_info hf[] = {
	{ &hf_nas_eps_msg_emm_type,
		{ "NAS EPS Mobility Management Message Type",	"nas_eps.nas_msg_epsmm_type",
		FT_UINT8, BASE_HEX, VALS(nas_msg_emm_strings), 0x0,
		"", HFILL }
	},
	{ &hf_nas_eps_common_elem_id,
		{ "Element ID",	"nas_eps.common.elem_id",
		FT_UINT8, BASE_DEC, NULL, 0,
		"", HFILL }
	},
	{ &hf_nas_emm_elem_id,
		{ "Element ID",	"nas_eps.emm.elem_id",
		FT_UINT8, BASE_DEC, NULL, 0,
		"", HFILL }
	},
	{ &hf_nas_eps_spare_bits,
		{ "Spare bit(s)", "nas_eps.spare_bits",
		FT_UINT8, BASE_HEX, NULL, 0x0,
		"Spare bit(s)", HFILL }
	},
	{ &hf_nas_eps_security_header_type,
		{ "Security header type","nas_eps.security_header_type",
		FT_UINT8,BASE_DEC, VALS(security_header_type_vals), 0xf0,
		"Security_header_type", HFILL }
	},
	{ &hf_nas_eps_emm_eps_att_type,
		{ "EPS attach type","nas_eps.emm.eps_att_type",
		FT_UINT8,BASE_DEC, VALS(nas_eps_emm_eps_att_type_vals), 0x0,
		"EPS attach type", HFILL }
	},
	{ &hf_nas_eps_emm_nas_key_set_id,
		{ "NAS key set identifier","nas_eps.emm.nas_key_set_id",
		FT_UINT8,BASE_DEC, VALS(nas_eps_emm_NAS_key_set_identifier_vals), 0x0,
		"NAS key set identifier", HFILL }
	},
	{ &hf_nas_eps_emm_odd_even,
		{ "odd/even indic","nas_eps.emm.odd_even",
		FT_UINT8,BASE_DEC, NULL, 0x8,
		"odd/even indic", HFILL }
	},
	{ &hf_nas_eps_emm_type_of_id,
		{ "Type of identity","nas_eps.emm.type_of_id",
		FT_UINT8,BASE_DEC, VALS(nas_eps_emm_type_of_id_vals), 0x07,
		"Type of identity", HFILL }
	},
	{ &hf_nas_eps_emm_EPS_attach_result,
		{ "Type of identity","nas_eps.emm.EPS_attach_result",
		FT_UINT8,BASE_DEC, VALS(nas_eps_emm_EPS_attach_result_values), 0x0,
		"Type of identity", HFILL }
	},
	{ &hf_nas_eps_emm_spare_half_octet,
		{ "Spare half octet","nas_eps.emm.EPS_attach_result",
		FT_UINT8,BASE_DEC, NULL, 0x0,
		"Spare half octet", HFILL }
	},
	{ &hf_nas_eps_emm_res,
		{ "RES","nas_eps.emm.res",
		FT_BYTES, BASE_HEX, NULL, 0x0,
		"RES", HFILL }
	},
	{ &hf_nas_eps_emm_cause,
		{ "Cause","nas_eps.emm.cause",
		FT_UINT8,BASE_DEC, VALS(nas_eps_emm_cause_values), 0x0,
		"Cause", HFILL }
	},
	{ &hf_nas_eps_emm_short_mac,
		{ "Short MAC value","nas_eps.emm.short_mac",
		FT_BYTES, BASE_HEX, NULL, 0x0,
		"Short MAC value", HFILL }
	},
	{ &hf_nas_eps_active_flg,
		{ "Active flag", "nas_eps.emm.active_flg",
		FT_BOOLEAN, 8, TFS(&nas_eps_emm_active_flg_value), 0x0,
		"Active flag", HFILL }
	},
	{ &hf_nas_eps_eps_update_result_value,
		{ "EPS update result value","nas_eps.emm.eps_update_result_value",
		FT_UINT8,BASE_DEC, VALS(nas_eps_emm_eps_update_result_vals), 0x0,
		"EPS update result value", HFILL }
	},
	{ &hf_nas_eps_eps_update_type_value,
		{ "EPS update type value","nas_eps.emm.update_type_value",
		FT_UINT8,BASE_DEC, VALS(nas_eps_emm_eps_update_type_vals), 0x0,
		"EPS update type value", HFILL }
	},
  };

	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	1
	static gint *ett[NUM_INDIVIDUAL_ELEMS +
		NUM_NAS_EPS_COMMON_ELEM +
		NUM_NAS_MSG_EMM + NUM_NAS_EMM_ELEM];

	ett[0] = &ett_nas_eps;

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i < NUM_NAS_EPS_COMMON_ELEM; i++, last_offset++)
	{
		ett_nas_eps_common_elem[i] = -1;
		ett[last_offset] = &ett_nas_eps_common_elem[i];
	}

	for (i=0; i < NUM_NAS_MSG_EMM; i++, last_offset++)
	{
		ett_nas_msg_emm[i] = -1;
		ett[last_offset] = &ett_nas_msg_emm[i];
	}

	for (i=0; i < NUM_NAS_EMM_ELEM; i++, last_offset++)
	{
		ett_gsm_gm_elem[i] = -1;
		ett[last_offset] = &ett_gsm_gm_elem[i];
	}

  /* Register protocol */
  proto_nas_eps = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_nas_eps, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
 
  /* Register dissector */
  register_dissector(PFNAME, dissect_nas_eps, proto_nas_eps);
}
