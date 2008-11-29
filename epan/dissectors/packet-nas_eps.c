/* packet-nas_eps.c
 * Routines for Non-Access-Stratum (NAS) protocol for Evolved Packet System (EPS) dissection
 *
 * Copyright 2008, Anders Broman <anders.broman@ericsson.com>
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
 * References: 3GPP TS 24.301 V1.1.1 (2008-10)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include "packet-gsm_a_common.h"

#define PNAME  "Non-Access-Stratum (NAS)PDU"
#define PSNAME "NAS_EPS"
#define PFNAME "nas_eps"

/* Initialize the protocol and registered fields */
static int proto_nas_eps = -1;

static int hf_nas_eps_msg_emm_type = -1;
int hf_nas_emm_elem_id = -1;
static int hf_nas_eps_security_header_type = -1;
static int hf_nas_eps_emm_eps_att_type = -1;

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
	{ 13,	"These values are not used in this version of the protocol. If received they shall be interpreted as ‘1100’. (NOTE)"},
	{ 14,	"These values are not used in this version of the protocol. If received they shall be interpreted as ‘1100’. (NOTE)"},
	{ 15,	"These values are not used in this version of the protocol. If received they shall be interpreted as ‘1100’. (NOTE)"},
	{ 0,	NULL }
};

/* 9.9.2	Common information elements
 * 9.9.2.1	EPS bearer context status
 * 9.9.2.2	Location area identification
 * See subclause 10.5.1.3 in 3GPP TS 24.008 [6].
 * 9.9.2.3	Mobile identity
 * See subclause 10.5.1.4 in 3GPP TS 24.008 [6].
 * 9.9.2.4	PLMN list
 * See subclause 10.5.1.13 in 3GPP TS 24.008 [6].
 * 9.9.2.5	Spare half octet
 * This element is used in the description of EMM and ESM messages when an odd number of 
 * half octet type 1 information elements are used. This element is filled with spare bits 
 * set to zero and is placed in bits 5 to 8 of the octet unless otherwise specified.
 *
 */

const value_string nas_emm_elem_strings[] = {
	/* 9.9.3	EPS Mobility Management (EMM) information elements */
	{ 0x00,	"Authentication failure parameter" },	/* 9.9.3.1	Authentication failure parameter */
	{ 0x00,	"Authentication parameter AUTN" },		/* 9.9.3.2	Authentication parameter AUTN */
	{ 0x00,	"Authentication parameter RAND" },		/* 9.9.3.3	Authentication parameter RAND */
	{ 0x00,	"Authentication response parameter" },	/* 9.9.3.4	Authentication response parameter */
	{ 0x00,	"Daylight saving time" },				/* 9.9.3.5	Daylight saving time */
	{ 0x00,	"Detach type" },						/* 9.9.3.6	Detach type */
	{ 0x00,	"DRX parameter" },						/* 9.9.3.6a	DRX parameter */
	{ 0x00,	"EMM cause" },							/* 9.9.3.7	EMM cause */
	{ 0x00,	"EPS attach result" },					/* 9.9.3.8	EPS attach result */
	{ 0x00,	"EPS attach type" },					/* 9.9.3.9	EPS attach type */
	{ 0x00,	"EPS mobile identity" },				/* 9.9.3.10	EPS mobile identity */
	{ 0x00,	"EPS update resul" },					/* 9.9.3.11	EPS update result */
	{ 0x00,	"EPS update type" },					/* 9.9.3.12	EPS update type */
	{ 0x00,	"ESM message container" },				/* 9.9.3.13	ESM message container */
	{ 0x00,	"GPRS timer" },							/* 9.9.3.14	GPRS timer ,See subclause 10.5.7.3 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"Identity type 2" },					/* 9.9.3.15	Identity type 2 ,See subclause 10.5.5.9 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"IMEISV request" },						/* 9.9.3.16	IMEISV request ,See subclause 10.5.5.10 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"KSI and sequence number" },			/* 9.9.3.17	KSI and sequence number */
	{ 0x00,	"MS network capability" },				/* 9.9.3.18	MS network capability ,See subclause 10.5.5.12 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"NAS key set identifier" },				/* 9.9.3.19	NAS key set identifier */
	{ 0x00,	"NAS security algorithms" },			/* 9.9.3.20	NAS security algorithms */
	{ 0x00,	"Network name" },						/* 9.9.3.21	Network name, See subclause 10.5.3.5a in 3GPP TS 24.008 [6]. */
	{ 0x00,	"Nonce" },								/* 9.9.3.21a	Nonce */
	{ 0x00,	"P-TMSI" },								/* 9.9.3.22	P-TMSI, See subclause 10.5.1.4 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"P-TMSI signature" },					/* 9.9.3.23	P-TMSI signature, See subclause 10.5.5.8 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"Routing area identification" },		/* 9.9.3.24	Routing area identification ,See subclause 10.5.5.15 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"Short MAC" },							/* 9.9.3.25	Short MAC */
	{ 0x00,	"Time zone" },							/* 9.9.3.26	Time zone, See subclause 10.5.3.8 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"Time zone and time" },					/* 9.9.3.27	Time zone and time, See subclause 10.5.3.9 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"TMSI status" },						/* 9.9.3.27a	TMSI status, See subclause 10.5.5.4 in 3GPP TS 24.008 [6]. */
	{ 0x00,	"Tracking area identity" },				/* 9.9.3.28	Tracking area identity */
	{ 0x00,	"Tracking area identity list" },		/* 9.9.3.29	Tracking area identity list */
	{ 0x00,	"UE security capability" },				/* 9.9.3.30	UE security capability */
	{ 0, NULL }
};
#define	NUM_NAS_EMM_ELEM (sizeof(nas_emm_elem_strings)/sizeof(value_string))
gint ett_nas_emm_elem[NUM_NAS_EMM_ELEM];

typedef enum
{
	/* 9.9.3	EPS Mobility Management (EMM) information elements */
	DE_EMM_AUTH_FAIL_PAR,		/* 9.9.3.1	Authentication failure parameter */
	DE_EMM_AUTN,				/* 9.9.3.2	Authentication parameter AUTN */
	DE_EMM_AUTH_PAR_RAND,		/* 9.9.3.3	Authentication parameter RAND */
	DE_EMM_AUTH_RESP_PAR,		/* 9.9.3.4	Authentication response parameter */
	DE_EMM_DAYL_SAV_T,			/* 9.9.3.5	Daylight saving time */
	DE_EMM_DET_TYPE,			/* 9.9.3.6	Detach type */
	DE_EMM_DRX_PAR,				/* 9.9.3.6a	DRX parameter */
	DE_EMM_CAUSE,				/* 9.9.3.7	EMM cause */
	DE_EMM_ATT_RES,				/* 9.9.3.8	EPS attach result */
	DE_EMM_ATT_TYPE,			/* 9.9.3.9	EPS attach type */
	DE_EMM_EPS_MID,				/* 9.9.3.10	EPS mobile identity */
	DE_EMM_EPS_UPD_RES,			/* 9.9.3.11	EPS update result */
	DE_EMM_EPS_UPD_TYPE,		/* 9.9.3.12	EPS update type */
	DE_EMM_ESM_MSG_CONT,		/* 9.9.3.13	ESM message container */
	DE_EMM_GPRS_TIMER,			/* 9.9.3.14	GPRS timer ,See subclause 10.5.7.3 in 3GPP TS 24.008 [6]. */
	DE_EMM_GPRS_ID_TYPE_2,		/* 9.9.3.15	Identity type 2 ,See subclause 10.5.5.9 in 3GPP TS 24.008 [6]. */
	DE_EMM_GPRS_IMEISV_REQ,		/* 9.9.3.16	IMEISV request ,See subclause 10.5.5.10 in 3GPP TS 24.008 [6]. */
	DE_EMM_GPRS_KSI_AND_SEQ_NO,	/* 9.9.3.17	KSI and sequence number */
	DE_EMM_GPRS_MS_NET_CAP,		/* 9.9.3.18	MS network capability ,See subclause 10.5.5.12 in 3GPP TS 24.008 [6]. */
	DE_EMM_GPRS_NAS_KEY_SET_ID,	/* 9.9.3.19	NAS key set identifier */
	DE_EMM_GPRS_NAS_SEC_ALGS,	/* 9.9.3.20	NAS security algorithms */
	DE_EMM_GPRS_NET_NAME,		/* 9.9.3.21	Network name, See subclause 10.5.3.5a in 3GPP TS 24.008 [6]. */
	DE_EMM_GPRS_NONCE,			/* 9.9.3.21a	Nonce */
	DE_EMM_GPRS_P_TMSI,			/* 9.9.3.22	P-TMSI, See subclause 10.5.1.4 in 3GPP TS 24.008 [6]. */
	DE_EMM_GPRS_P_TMSI_SIGN,	/* 9.9.3.23	P-TMSI signature, See subclause 10.5.5.8 in 3GPP TS 24.008 [6]. */
	DE_EMM_GPRS_RAI,			/* 9.9.3.24	Routing area identification ,See subclause 10.5.5.15 in 3GPP TS 24.008 [6]. */
	DE_EMM_GPRS_S_MAC,			/* 9.9.3.25	Short MAC */
	DE_EMM_GPRS_TZ,				/* 9.9.3.26	Time zone, See subclause 10.5.3.8 in 3GPP TS 24.008 [6]. */
	DE_EMM_GPRS_TZ_AND_T,		/* 9.9.3.27	Time zone and time, See subclause 10.5.3.9 in 3GPP TS 24.008 [6]. */
	DE_EMM_GPRS_TMSI_STAT,		/* 9.9.3.27a	TMSI status, See subclause 10.5.5.4 in 3GPP TS 24.008 [6]. */
	DE_EMM_GPRS_TRAC_AREA_ID,	/* 9.9.3.28	Tracking area identity */
	DE_EMM_GPRS_TRAC_AREA_ID_LST, /* 9.9.3.29	Tracking area identity list */
	DE_EMM_GPRS_UE_SEC_CAP,		/* 9.9.3.30	UE security capability */
	DE_EMM_NONE							/* NONE */
}
nas_emm_elem_idx_t;

/* 9.9.3	EPS Mobility Management (EMM) information elements
 * 9.9.3.1	Authentication failure parameter
 * See subclause 10.5.3.2.2 in 3GPP TS 24.008 [6].
 * 9.9.3.2	Authentication parameter AUTN
 * See subclause 10.5.3.1.1 in 3GPP TS 24.008 [6].
 * 9.9.3.3	Authentication parameter RAND
 * See subclause 10.5.3.1 in 3GPP TS 24.008 [6].
 * 9.9.3.4	Authentication response parameter
 * 9.9.3.5	Daylight saving time
 * See subclause 10.5.3.12 in 3GPP TS 24.008 [6].
 * 9.9.3.6	Detach type
 * 9.9.3.6a	DRX parameter
 * 9.9.3.7	EMM cause
 * 9.9.3.8	EPS attach result
 */
/*
 * 9.9.3.9	EPS attach type
 */

static const value_string nas_eps_emm_eps_att_type_vals[] = {
	{ 0,	"EPS attach"},
	{ 1,	"EPS attach"},
	{ 2,	"EPS attach"},
	{ 3,	"EPS attach"},
	{ 4,	"Combined handover EPS/IMSI attach"},
	{ 5,	"EPS attach"},
	{ 6,	"EPS attach"},
	{ 7,	"EPS attach"},
	{ 0, NULL }
};

static guint8
de_emm_att_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/* 8	7	6	5		4	3	2	1
	 *EPS attach type IEI	0   EPS attach type value
	 *                     Spare	
	 */
	proto_tree_add_item(tree, hf_nas_eps_emm_eps_att_type, tvb, 1, 1, FALSE);
	curr_offset++;

	return(curr_offset - offset);
}
/*
 * 9.9.3.10	EPS mobile identity
 * 9.9.3.11	EPS update result
 * 9.9.3.12	EPS update type
 * 9.9.3.13	ESM message container
 * 9.9.3.14	GPRS timer
 * See subclause 10.5.7.3 in 3GPP TS 24.008 [6].
 * 9.9.3.15	Identity type 2
 * See subclause 10.5.5.9 in 3GPP TS 24.008 [6].
 * 9.9.3.16	IMEISV request
 * See subclause 10.5.5.10 in 3GPP TS 24.008 [6].
 * 9.9.3.17	KSI and sequence number
 * 9.9.3.18	MS network capability
 * See subclause 10.5.5.12 in 3GPP TS 24.008 [6].
 * 9.9.3.19	NAS key set identifier
 * 9.9.3.20	NAS security algorithms
 * 9.9.3.21	Network name
 * See subclause 10.5.3.5a in 3GPP TS 24.008 [6].
 * 9.9.3.21a	Nonce
 * Editor's note: The coding of this information element is FFS.
 * 9.9.3.22	P-TMSI
 * See subclause 10.5.1.4 in 3GPP TS 24.008 [6].
 * 9.9.3.23	P-TMSI signature
 * See subclause 10.5.5.8 in 3GPP TS 24.008 [6].
 * 9.9.3.24	Routing area identification
 * See subclause 10.5.5.15 in 3GPP TS 24.008 [6].
 * 9.9.3.25	Short MAC
 * 9.9.3.26	Time zone
 * See subclause 10.5.3.8 in 3GPP TS 24.008 [6].
 * 9.9.3.27	Time zone and time
 * See subclause 10.5.3.9 in 3GPP TS 24.008 [6].
 * 9.9.3.27a	TMSI status
 * See subclause 10.5.5.4 in 3GPP TS 24.008 [6].
 * 9.9.3.28	Tracking area identity
 * 9.9.3.29	Tracking area identity list
 * 9.9.3.30	UE security capability
 * 
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

guint8 (*emm_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len) = {
	/* 9.9.3	EPS Mobility Management (EMM) information elements */
	NULL,						/* 9.9.3.1	Authentication failure parameter */
	NULL,						/* 9.9.3.2	Authentication parameter AUTN */
	NULL,						/* 9.9.3.3	Authentication parameter RAND */
	NULL,						/* 9.9.3.4	Authentication response parameter */
	NULL,						/* 9.9.3.5	Daylight saving time */
	NULL,						/* 9.9.3.6	Detach type */
	NULL,						/* 9.9.3.6a	DRX parameter */
	NULL,						/* 9.9.3.7	EMM cause */
	NULL,						/* 9.9.3.8	EPS attach result */
	de_emm_att_type,			/* 9.9.3.9	EPS attach type */
	NULL,						/* 9.9.3.10	EPS mobile identity */
	NULL,						/* 9.9.3.11	EPS update result */
	NULL,						/* 9.9.3.12	EPS update type */
	NULL,						/* 9.9.3.13	ESM message container */
	NULL,						/* 9.9.3.14	GPRS timer ,See subclause 10.5.7.3 in 3GPP TS 24.008 [6]. */
	NULL,						/* 9.9.3.15	Identity type 2 ,See subclause 10.5.5.9 in 3GPP TS 24.008 [6]. */
	NULL,						/* 9.9.3.16	IMEISV request ,See subclause 10.5.5.10 in 3GPP TS 24.008 [6]. */
	NULL,						/* 9.9.3.17	KSI and sequence number */
	NULL,						/* 9.9.3.18	MS network capability ,See subclause 10.5.5.12 in 3GPP TS 24.008 [6]. */
	NULL,						/* 9.9.3.19	NAS key set identifier */
	NULL,						/* 9.9.3.20	NAS security algorithms */
	NULL,						/* 9.9.3.21	Network name, See subclause 10.5.3.5a in 3GPP TS 24.008 [6]. */
	NULL,						/* 9.9.3.21a	Nonce */
	NULL,						/* 9.9.3.22	P-TMSI, See subclause 10.5.1.4 in 3GPP TS 24.008 [6]. */
	NULL,						/* 9.9.3.23	P-TMSI signature, See subclause 10.5.5.8 in 3GPP TS 24.008 [6]. */
	NULL,						/* 9.9.3.24	Routing area identification ,See subclause 10.5.5.15 in 3GPP TS 24.008 [6]. */
	NULL,						/* 9.9.3.25	Short MAC */
	NULL,						/* 9.9.3.26	Time zone, See subclause 10.5.3.8 in 3GPP TS 24.008 [6]. */
	NULL,						/* 9.9.3.27	Time zone and time, See subclause 10.5.3.9 in 3GPP TS 24.008 [6]. */
	NULL,						/* 9.9.3.27a	TMSI status, See subclause 10.5.5.4 in 3GPP TS 24.008 [6]. */
	NULL,						/* 9.9.3.28	Tracking area identity */
	NULL,						/* 9.9.3.29	Tracking area identity list */
	NULL,						/* 9.9.3.30	UE security capability */
	NULL,	/* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * 8.2.4	Attach request
 */
static void
nas_emm_attach_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;
	/* Delete when dissection completed */
	consumed = 0;
	/* EPS attach type	EPS attach type 9.9.3.9	M	V	1/2  */
	ELEM_MAND_V_SHORT(NAS_PDU_TYPE_EMM, DE_EMM_ATT_TYPE);
	/* NAS key set identifier	NAS key set identifier 9.9.3.19	M	V	1/2 */
	/* Old GUTI or IMSI	EPS mobile identity 9.9.3.10	M	LV	5-12 */
	/* MS network capability	MS network capability 9.9.3.18	M	LV	3-9 */
	/* ESM message container	ESM message container 9.9.3.13	M	LV-E	2-n */
	/* Last visited registered TAI	Tracking area identity 9.9.3.28	O	TV	6 */
	/* DRX parameter	DRX parameter 9.9.3.6a	O	FFS	FFS */
	/* Old location area identification	Location area identification 9.9.2.2	O	TV	6 */
	/* TMSI status	TMSI status 9.9.3.27a	O	TV	1 */

}
#define	NUM_NAS_MSG_EMM (sizeof(nas_msg_emm_strings)/sizeof(value_string))
static gint ett_nas_msg_emm[NUM_NAS_MSG_EMM];
static void (*nas_msg_emm_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
	nas_emm_attach_req,		/* Attach request */
	NULL,	/* Attach accept */
	NULL,	/* Attach complete */
	NULL,	/* Attach reject */
	NULL,	/* Detach request */
	NULL,	/* Detach accept */
							
	NULL,	/* Tracking area update request */
	NULL,	/* Tracking area update accept */
	NULL,	/* Tracking area update complete */
	NULL,	/* Tracking area update reject */
									
	NULL,	/* Service reject */
									
	NULL,	/* GUTI reallocation command */
	NULL,	/* GUTI reallocation complete */
	NULL,	/* Authentication request */
	NULL,	/* Authentication response */
	NULL,	/* Authentication reject */
	NULL,	/* Authentication failure */
	NULL,	/* Identity request */
	NULL,	/* Identity response */
	NULL,	/* Security mode command */
	NULL,	/* Security mode complete */
	NULL,	/* Security mode reject */
									
	NULL,	/* EMM status */
	NULL,	/* EMM information */
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
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "nas_eps");

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
	{ &hf_nas_emm_elem_id,
		{ "Element ID",	"nas_eps.emm.elem_id",
		FT_UINT8, BASE_DEC, NULL, 0,
		"", HFILL }
	},
	{ &hf_nas_eps_security_header_type,
		{ "Security header type","nas_eps.security_header_type",
		FT_UINT8,BASE_DEC, VALS(security_header_type_vals), 0xf0,
		"Security_header_type", HFILL }
	},
	{ &hf_nas_eps_emm_eps_att_type,
		{ "EPS attach type","nas_eps.emm.eps_att_type",
		FT_UINT8,BASE_DEC, VALS(nas_eps_emm_eps_att_type_vals), 0x0f,
		"EPS attach type", HFILL }
	},
  };

	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	1
	static gint *ett[NUM_INDIVIDUAL_ELEMS +
			NUM_NAS_MSG_EMM + NUM_NAS_EMM_ELEM];

	ett[0] = &ett_nas_eps;

	last_offset = NUM_INDIVIDUAL_ELEMS;

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
