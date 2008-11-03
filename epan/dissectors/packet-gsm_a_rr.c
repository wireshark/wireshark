/* packet-gsm_a_rr.c
 * Routines for GSM A Interface (actually A-bis really) RR dissection - A.K.A. GSM layer 3 Radio Resource Protocol
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Added Dissection of Radio Resource Management Information Elements
 * and othere enhancements and fixes.
 * Copyright 2005 - 2006, Anders Broman [AT] ericsson.com
 *
 * Title		3GPP			Other
 *
 *   Reference [3]
 *   Mobile radio interface Layer 3 specification;
 *   Core network protocols;
 *   Stage 3
 *   (3GPP TS 24.008 version 4.7.0 Release 4)
 *   (ETSI TS 124 008 V6.8.0 (2005-03))
 *
 *   Reference [4]
 *   Mobile radio interface layer 3 specification;
 *   Radio Resource Control Protocol
 *   (GSM 04.18 version 8.4.1 Release 1999)
 *   (3GPP TS 04.18 version 8.26.0 Release 1999)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>

#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/asn1.h>

#include "packet-bssap.h"
#include "packet-sccp.h"
#include "packet-ber.h"
#include "packet-q931.h"
#include "packet-gsm_a_common.h"
#include "packet-ipv6.h"
#include "packet-e212.h"
#include "packet-ppp.h"

#define PADDING_BYTE 0x2B

gboolean gsm_a_rr_is_bit_high(tvbuff_t *tvb, gint bit_offset)
{
   guint8 bit_mask = 0x80 >> (bit_offset & 0x07);
   if ((tvb_get_guint8(tvb,bit_offset >> 3) & bit_mask) != (PADDING_BYTE & bit_mask))
      return TRUE;
   return FALSE;
}

/* PROTOTYPES/FORWARDS */

const value_string gsm_a_dtap_msg_rr_strings[] = {
	{ 0x3c,	"RR Initialisation Request" },
	{ 0x3b,	"Additional Assignment" },
	{ 0x3f,	"Immediate Assignment" },
	{ 0x39,	"Immediate Assignment Extended" },
	{ 0x3a,	"Immediate Assignment Reject" },

	{ 0x48,	"DTM Assignment Failure" },
	{ 0x49,	"DTM Reject" },
	{ 0x4a,	"DTM Request" },
	{ 0x4b,	"Main DCCH Assignment Command" },
	{ 0x4c,	"Packet Assignment Command" },

	{ 0x35,	"Ciphering Mode Command" },
	{ 0x32,	"Ciphering Mode Complete" },

	{ 0x30,	"Configuration Change Command" },
	{ 0x31,	"Configuration Change Ack." },
	{ 0x33,	"Configuration Change Reject" },

	{ 0x2e,	"Assignment Command" },
	{ 0x29,	"Assignment Complete" },
	{ 0x2f,	"Assignment Failure" },
	{ 0x2b,	"Handover Command" },
	{ 0x2c,	"Handover Complete" },
	{ 0x28,	"Handover Failure" },
	{ 0x2d,	"Physical Information" },
	{ 0x4d,	"DTM Assignment Command" },

	{ 0x08,	"RR-cell Change Order" },
	{ 0x23,	"PDCH Assignment Command" },

	{ 0x0d,	"Channel Release" },
	{ 0x0a,	"Partial Release" },
	{ 0x0f,	"Partial Release Complete" },

	{ 0x21,	"Paging Request Type 1" },
	{ 0x22,	"Paging Request Type 2" },
	{ 0x24,	"Paging Request Type 3" },
	{ 0x27,	"Paging Response" },
	{ 0x20,	"Notification/NCH" },
	{ 0x25,	"Reserved" },
	{ 0x26,	"Notification/Response" },

	{ 0x0b,	"Reserved" },

/*	ETSI TS 101 503 V8.5.0 Seems to give Other def for this Messages???
	{ 0xc0,	"Utran Classmark Change" }, CONFLICTS WITH Handover To UTRAN Command
	{ 0xc1,	"UE RAB Preconfiguration" },
	{ 0xc2,	"cdma2000 Classmark Change" },*/

	/* ETSI TS 101 503 V8.5.0 */
	{ 0x60,	"Utran Classmark Change" },
	{ 0x61,	"UE RAB Preconfiguration" },
	{ 0x62,	"cdma2000 Classmark Change" },
	{ 0x63,	"Inter System to UTRAN Handover Command" },
	{ 0x64,	"Inter System to cdma2000 Handover Command" },
	{ 0x18,	"System Information Type 8" },
	{ 0x19,	"System Information Type 1" },
	{ 0x1a,	"System Information Type 2" },
	{ 0x1b,	"System Information Type 3" },
	{ 0x1c,	"System Information Type 4" },
	{ 0x1d,	"System Information Type 5" },
	{ 0x1e,	"System Information Type 6" },
	{ 0x1f,	"System Information Type 7" },

	{ 0x02,	"System Information Type 2bis" },
	{ 0x03,	"System Information Type 2ter" },
	{ 0x07,	"System Information Type 2quater" },
	{ 0x05,	"System Information Type 5bis" },
	{ 0x06,	"System Information Type 5ter" },
	{ 0x04,	"System Information Type 9" },
	{ 0x00,	"System Information Type 13" },

	{ 0x3d,	"System Information Type 16" },
	{ 0x3e,	"System Information Type 17" },

	{ 0x40,	"System Information Type 18" },
	{ 0x41,	"System Information Type 19" },
	{ 0x42,	"System Information Type 20" },

	{ 0x10,	"Channel Mode Modify" },
	{ 0x12,	"RR Status" },
	{ 0x17,	"Channel Mode Modify Acknowledge" },
	{ 0x14,	"Frequency Redefinition" },
	{ 0x15,	"Measurement Report" },
	{ 0x16,	"Classmark Change" },
	{ 0x13,	"Classmark Enquiry" },
	{ 0x36,	"Extended Measurement Report" },
	{ 0x37,	"Extended Measurement Order" },
	{ 0x34,	"GPRS Suspension Request" },

	{ 0x09,	"VGCS Uplink Grant" },
	{ 0x0e,	"Uplink Release" },
	{ 0x0c,	"Reserved" },
	{ 0x2a,	"Uplink Busy" },
	{ 0x11,	"Talker Indication" },

	{ 0xc0,	"UTRAN Classmark Change/Handover To UTRAN Command" },	/* spec conflict */

	{ 0x38,	"Application Information" },

	{ 0, NULL }
};

const value_string gsm_rr_elem_strings[] = {
	/* Radio Resource Management Information Elements 10.5.2, most are from 10.5.1 */
/*
 * [3]  10.5.2.1a	BA Range
 */
	{ 0x00,	"Cell Channel Description" },		/* [3]  10.5.2.1b	*/
/* [3]  10.5.2.1c	BA List Pref
 * [3]  10.5.2.1d	UTRAN Frequency List
 * [3]  10.5.2.1e	Cell selection indicator after release of all TCH and SDCCH IE
 */
	{ 0x00, "Cell Description" },				/* 10.5.2.2  */
	{ 0x00, "Cell Options (BCCH)" },			/* [3]  10.5.2.3	Cell Options (BCCH)			*/
	{ 0x00, "Cell Options (SACCH)" },			/* [3]  10.5.2.3a	Cell Options (SACCH)		*/
	{ 0x00, "Cell Selection Parameters" },			/* [3]  10.5.2.4	Cell Selection Parameters	*/
/* [3]  10.5.2.4a	(void) */
	{ 0x00, "Channel Description" },			/* 10.5.2.5	 */
	{ 0x00, "Channel Description 2" },			/* 10.5.2.5a */

	{ 0x00, "Channel Mode" },					/* [3]  10.5.2.6 */
	{ 0x00, "Channel Mode 2" },					/* [3]  10.5.2.7 */
/* [3]  10.5.2.7a	UTRAN predefined configuration status information / START-CS / UE CapabilityUTRAN Classmark information element	218
 * [3]  10.5.2.7b	(void) */
	{ 0x00, "Classmark Enquiry Mask" },			/* [3]  10.5.2.7c */
/* [3]  10.5.2.7d	GERAN Iu Mode Classmark information element */
	{ 0x00, "Channel Needed"},					/* [3]  10.5.2.8	*/
 /* [3]  10.5.2.8a	(void) */
 /* [3]  10.5.2.8b	Channel Request Description 2 */
		/* Pos 20 */
 	{ 0x00, "Cipher Mode Setting" },				/* [3]  10.5.2.9	*/
	{ 0x00, "Cipher Mode Response" },			   /* [3]  10.5.2.10	*/
	{ 0x00, "Control Channel Description" },	/* [3]  10.5.2.11	Control Channel Description		*/
/* [3]  10.5.2.11a	DTM Information Details */
	{ 0x00, "Dynamic ARFCN Mapping" },			/* [3]  10.5.2.11b	*/
	{ 0x00, "Frequency Channel Sequence" },		/* [3]  10.5.2.12	*/
	{ 0x00,	"Frequency List" },					/* 10.5.2.13		*/
	{ 0x00,	"Frequency Short List" },			/* 10.5.2.14		*/
	{ 0x00,	"Frequency Short List2" },			/* 10.5.2.14a		*/
/* [3]  10.5.2.14b	Group Channel Description */
	{ 0x00,	"GPRS Resumption" },			 /* [3]  10.5.2.14c	GPRS Resumption */
	{ 0x00,	"GPRS Broadcast Information" },			 /* [3]  10.5.2.14d	GPRS broadcast information */
/* [3]  10.5.2.14e	Enhanced DTM CS Release Indication */
	{ 0x00, "Handover Reference" },				/* 10.5.2.15		*/
	{ 0x00, "IA Rest Octets" },					/* [3] 10.5.2.16	*/
	{ 0x00, "IAR Rest Octets" },					/* [3] 10.5.2.17 IAR Rest Octets */
	{ 0x00, "IAX Rest Octets" },					/* [3] 10.5.2.18 IAX Rest Octets */
	{ 0x00, "L2 Pseudo Length" },				/* [3] 10.5.2.19	*/
	{ 0x00, "Measurement Results" },			/* [3] 10.5.2.20 Measurement Results */
/*
 * [3] 10.5.2.20a GPRS Measurement Results
 */
 	{ 0x00, "Mobile Allocation" },				/* [3] 10.5.2.21	*/
 	{ 0x00, "Mobile Time Difference" },			/* [3] 10.5.2.21a	*/
 	{ 0x00, "MultiRate configuration" },		/* [3] 10.5.2.21aa	*/
	/* Pos 30 */
	{ 0x00, "Multislot Allocation" },			/* [3] 10.5.2.21b	*/
 /*
 * [3] 10.5.2.21c NC mode
 */
	{ 0x00, "Neighbour Cell Description" },		/* [3] 10.5.2.22 Neighbour Cell Description */
	{ 0x00, "Neighbour Cell Description 2" },	/* [3] 10.5.2.22a Neighbour Cell Description 2 */
/*
 * [3] 10.5.2.22b (void)
 * [3] 10.5.2.22c NT/N Rest Octets
 * [3] 10.5.2.23 P1 Rest Octets
 * [3] 10.5.2.24 P2 Rest Octets
 * [3] 10.5.2.25 P3 Rest Octets */
	{ 0x00, "Packet Channel Description" },		/* [3] 10.5.2.25a	*/
	{ 0x00, "Dedicated mode or TBF" },			/* [3] 10.5.2.25b */
 /* [3] 10.5.2.25c RR Packet Uplink Assignment
 * [3] 10.5.2.25d RR Packet Downlink Assignment */
	{ 0x00, "Page Mode" },						/* [3] 10.5.2.26  */
/*
 * [3] 10.5.2.26a (void)
 * [3] 10.5.2.26b (void)
 * [3] 10.5.2.26c (void)
 * [3] 10.5.2.26d (void)
 */
	{ 0x00, "NCC Permitted" },			/* [3] 10.5.2.27 NCC Permitted */
	{ 0x00, "Power Command" },					/* 10.5.2.28 */
	{ 0x00, "Power Command and access type" },	/* 10.5.2.28a */
	{ 0x00, "RACH Control Parameters" },		/* [3] 10.5.2.29 RACH Control Parameters */
	{ 0x00, "Request Reference" },				/* [3] 10.5.2.30 Request Reference				*/
	{ 0x00,	"RR Cause" },						/* 10.5.2.31 */
	{ 0x00,	"Synchronization Indication" },		/* 10.5.2.39 */
	{ 0x00, "SI 1 Rest Octets" },			/* [3] 10.5.2.32 */
/* [3] 10.5.2.33 SI 2bis Rest Octets */
	{ 0x00, "SI 2ter Rest Octets" },		/* [3] 10.5.2.33a */
	{ 0x00, "SI 2quater Rest Octets" },		/* [3] 10.5.2.33b */
	{ 0x00, "SI 3 Rest Octets" },			/* [3] 10.5.2.34 */
	{ 0x00, "SI 4 Rest Octets" },			/* [3] 10.5.2.35 */
	{ 0x00, "SI 6 Rest Octets" },			/* [3] 10.5.2.35a */
/* [3] 10.5.2.36 SI 7 Rest Octets
 * [3] 10.5.2.37 SI 8 Rest Octets
 * [3] 10.5.2.37a SI 9 Rest Octets
 */
	{ 0x00, "SI 13 Rest Octets" },			/* [3] 10.5.2.37b */
/* [3] 10.5.2.37c (void)
 * [3] 10.5.2.37d (void)
 * [3] 10.5.2.37e SI 16 Rest Octets
 * [3] 10.5.2.37f SI 17 Rest Octets
 * [3] 10.5.2.37g SI 19 Rest Octets
 * [3] 10.5.2.37h SI 18 Rest Octets
 * [3] 10.5.2.37i SI 20 Rest Octets */
	{ 0x00,	"Starting Time" },					/* [3] 10.5.2.38 Starting Time	*/
	{ 0x00,	"Timing Advance" },					/* [3] 10.5.2.40 Timing Advance */
	{ 0x00,	"Time Difference" },				/* [3] 10.5.2.41 Time Difference				*/
	{ 0x00,	"TLLI" },							/* [3] 10.5.2.41a TLLI							*/
/*
 * [3] 10.5.2.42 TMSI/P-TMSI */
	{ 0x00,	"VGCS target mode Indication" },	/* [3] 10.5.2.42a								*/
	/* Pos 40 */
	{ 0x00,	"VGCS Ciphering Parameters" },		/* [3] 10.5.2.42b								*/
	{ 0x00,	"Wait Indication" },			/* [3] 10.5.2.43 Wait Indication */
/* [3] 10.5.2.44 SI10 rest octets $(ASCI)$
 * [3] 10.5.2.45 EXTENDED MEASUREMENT RESULTS
 * [3] 10.5.2.46 Extended Measurement Frequency List */
	{ 0x00,	"Suspension Cause" },				/* [3] 10.5.2.47								*/
/* [3] 10.5.2.48 APDU ID
 * [3] 10.5.2.49 APDU Flags
 * [3] 10.5.2.50 APDU Data
 * [3] 10.5.2.51 Handover To UTRAN Command
 * [3] 10.5.2.52 Handover To cdma2000 Command
 * [3] 10.5.2.53 (void)
 * [3] 10.5.2.54 (void)
 * [3] 10.5.2.55 (void)
 * [3] 10.5.2.56 3G Target Cell */
 { 0x00,	"Service Support" },					/* [3] 10.5.2.57	*/
 /* 10.5.2.58 MBMS p-t-m Channel Description */
	{ 0x00,	"Dedicated Service Information" },		/* [3] 10.5.2.59	*/
/*
 * 10.5.2.60 MPRACH Description
 * 10.5.2.61 Restriction Timer
 * 10.5.2.62 MBMS Session Identity
 * 10.5.2.63 Reduced group or broadcast call reference
 * 10.5.2.64 Talker Priority status
 * 10.5.2.65 Talker Identity
 * 10.5.2.66 Token
 * 10.5.2.67 PS Cause
 * 10.5.2.68 VGCS AMR Configuration
 * 10.5.2.69 Carrier Indication
 */
	{ 0, NULL }
};

const value_string gsm_rr_rest_octets_elem_strings[] = {
   /* RR Rest Octets information elements */
   { 0, "UTRAN FDD Description" },
   { 0, "UTRAN TDD Description" }, 
   { 0, "3G Measurement Parameters Description" },
   { 0, "3G Additional Measurement Parameters Description" },
   { 0, "Measurement Parameters Description" },
   { 0, "GPRS Real Time Difference Description" },
   { 0, "GPRS BSIC Description" },
   { 0, "GPRS Report Priority Description" },
   { 0, "GPRS Measurement Parameters Description" },
   { 0, "NC Measurement Parameters" },
   { 0, "SI2q Extension Information" },
   { 0, "CCN Support Description" },
   { 0, "3G Neighbour Cell Description" },
   { 0, "FDD Cell Information Field" },
   { 0, "TDD Cell Information Field" },
   { 0, "GPRS 3G Measurement Parameters Description" },
   { 0, "3G Additional Measurement Parameters Description 2" },
   { 0, "Optional Selection Parameters" },
   { 0, "GPRS Indicator" },
   { 0, "SI4 Rest Octets_O" },
   { 0, "SI4 Rest Octets_S" },
   { 0, "LSA Parameters" },
   { 0, "LSA ID Information" },
   { 0, "PCH and NCH Info" },
   { 0, "VBS/VGCS Options" },
   { 0, "GPRS Mobile Allocation" },
   { 0, "GPRS Cell Options" },
   { 0, "GPRS Cell Options Extension Information" },
   { 0, "GPRS Power Control Parameters" },
   { 0, "PBCCH Description" },
   { 0, NULL }
};


/* RR cause value (octet 2) TS 44.018 6.11.0*/
static const value_string gsm_a_rr_RR_cause_vals[] = {
	{ 0,	"Normal event"},
	{ 1,	"Abnormal release, unspecified"},
	{ 2,	"Abnormal release, channel unacceptable"},
	{ 3,	"Abnormal release, timer expired"},
	{ 4,	"Abnormal release, no activity on the radio path"},
	{ 5,	"Preemptive release"},
	{ 6,	"UTRAN configuration unknown"},
	{ 8,	"Handover impossible, timing advance out of range"},
	{ 9,	"Channel mode unacceptable"},
	{ 10,	"Frequency not implemented"},
	{ 13,	"Originator or talker leaving group call area"},
	{ 12,	"Lower layer failure"},
	{ 0x41,	"Call already cleared"},
	{ 0x5f,	"Semantically incorrect message"},
	{ 0x60,	"Invalid mandatory information"},
	{ 0x61,	"Message type non-existent or not implemented"},
	{ 0x62,	"Message type not compatible with protocol state"},
	{ 0x64,	"Conditional IE error"},
	{ 0x65,	"No cell allocation available"},
	{ 0x6f,	"Protocol error unspecified"},
	{ 0,	NULL }
};

static const value_string gsm_a_algorithm_identifier_vals[] = {
	{ 0,	"Cipher with algorithm A5/1"},
	{ 1,	"Cipher with algorithm A5/2"},
	{ 2,	"Cipher with algorithm A5/3"},
	{ 3,	"Cipher with algorithm A5/4"},
	{ 4,	"Cipher with algorithm A5/5"},
	{ 5,	"Cipher with algorithm A5/6"},
	{ 6,	"Cipher with algorithm A5/7"},
	{ 7,	"Reserved"},
	{ 0,	NULL }
};


#define	DTAP_PD_MASK		0x0f
#define	DTAP_SKIP_MASK		0xf0
#define	DTAP_TI_MASK		DTAP_SKIP_MASK
#define	DTAP_TIE_PRES_MASK	0x07			/* after TI shifted to right */
#define	DTAP_TIE_MASK		0x7f

#define	DTAP_RR_IEI_MASK	0xff

/* Initialize the protocol and registered fields */
static int proto_a_ccch = -1;

static int hf_gsm_a_dtap_msg_rr_type = -1;
int hf_gsm_a_rr_elem_id = -1;

static int hf_gsm_a_bcc				= -1;
static int hf_gsm_a_ncc				= -1;
static int hf_gsm_a_bcch_arfcn		= -1;
static int hf_gsm_a_rr_ho_ref_val	= -1;
static int hf_gsm_a_rr_L2_pseudo_len = -1;
static int hf_gsm_a_rr_ba_used = -1;
static int hf_gsm_a_rr_dtx_used = -1;
static int hf_gsm_a_rr_3g_ba_used = -1;
static int hf_gsm_a_rr_meas_valid = -1;
static int hf_gsm_a_rr_rxlev_full_serv_cell = -1;
static int hf_gsm_a_rr_rxlev_sub_serv_cell = -1;
static int hf_gsm_a_rr_rxqual_full_serv_cell = -1;
static int hf_gsm_a_rr_rxqual_sub_serv_cell = -1;
static int hf_gsm_a_rr_no_ncell_m = -1;
static int hf_gsm_a_rr_rxlev_ncell = -1;
static int hf_gsm_a_rr_bcch_freq_ncell = -1;
static int hf_gsm_a_rr_bsic_ncell = -1;
static int hf_gsm_a_rr_mobile_time_difference = -1;
static int hf_gsm_a_rr_pow_cmd_atc = -1;
static int hf_gsm_a_rr_pow_cmd_epc = -1;
static int hf_gsm_a_rr_page_mode = -1;
static int hf_gsm_a_rr_dedicated_mode_or_tbf = -1;
static int hf_gsm_a_rr_pow_cmd_fpcepc = -1;
static int hf_gsm_a_rr_pow_cmd_powlev = -1;
static int hf_gsm_a_rr_sync_ind_nci = -1;
static int hf_gsm_a_rr_sync_ind_rot = -1;
static int hf_gsm_a_rr_sync_ind_si = -1;
static int hf_gsm_a_rr_format_id = -1;
static int hf_gsm_a_rr_channel_mode = -1;
static int hf_gsm_a_rr_channel_mode2 = -1;
static int hf_gsm_a_rr_sc = -1;
static int hf_gsm_a_algorithm_id = -1;
static int hf_gsm_a_rr_cr = -1;
static int hf_gsm_a_rr_multirate_speech_ver = -1;
static int hf_gsm_a_rr_NCSB				= -1;
static int hf_gsm_a_rr_ICMI				= -1;
static int hf_gsm_a_rr_start_mode		= -1;
static int hf_gsm_a_rr_timing_adv = -1;
static int hf_gsm_a_rr_time_diff = -1;
static int hf_gsm_a_rr_tlli = -1;
static int hf_gsm_a_rr_target_mode = -1;
static int hf_gsm_a_rr_wait_indication = -1;
static int hf_gsm_a_rr_group_cipher_key_number = -1;
static int hf_gsm_a_rr_MBMS_multicast = -1;
static int hf_gsm_a_rr_MBMS_broadcast = -1;
static int hf_gsm_a_rr_last_segment = -1;
static int hf_gsm_a_rr_ra		= -1;
static int hf_gsm_a_rr_T1prim	= -1;
static int hf_gsm_a_rr_T3		= -1;
static int hf_gsm_a_rr_T2		= -1;
static int hf_gsm_a_rr_rfn	= -1;
static int hf_gsm_a_rr_RR_cause = -1;
static int hf_gsm_a_rr_cm_cng_msg_req = -1;
static int hf_gsm_a_rr_utran_cm_cng_msg_req = -1;
static int hf_gsm_a_rr_cdma200_cm_cng_msg_req = -1;
static int hf_gsm_a_rr_geran_iu_cm_cng_msg_req = -1;
int hf_gsm_a_rr_chnl_needed_ch1 = -1;
static int hf_gsm_a_rr_chnl_needed_ch2 = -1;
static int hf_gsm_a_rr_suspension_cause = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b8 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b7 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b6 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b5 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b4 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b3 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b2 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v1_b1 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v2_b5 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v2_b4 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v2_b3 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v2_b2 = -1;
static int hf_gsm_a_rr_set_of_amr_codec_modes_v2_b1 = -1;
static int hf_gsm_a_rr_amr_threshold = -1;
static int hf_gsm_a_rr_amr_hysteresis = -1;
static int hf_gsm_a_rr_pwrc = -1;
static int hf_gsm_a_rr_dtx_bcch = -1;
static int hf_gsm_a_rr_dtx_sacch = -1;
static int hf_gsm_a_rr_radio_link_timeout = -1;
static int hf_gsm_a_rr_cell_reselect_hyst = -1;
static int hf_gsm_a_rr_ms_txpwr_max_cch = -1;
static int hf_gsm_a_rr_acs = -1;
static int hf_gsm_a_rr_neci = -1;
static int hf_gsm_a_rr_rxlev_access_min = -1;
static int hf_gsm_a_rr_mscr = -1;
static int hf_gsm_a_rr_att = -1;
static int hf_gsm_a_rr_ccch_conf = -1;
static int hf_gsm_a_rr_cbq3 = -1;
static int hf_gsm_a_rr_bs_pa_mfrms = -1;
static int hf_gsm_a_rr_bs_ag_blks_res = -1;
static int hf_gsm_a_rr_t3212 = -1;
static int hf_gsm_a_rr_dyn_arfcn_length = -1;
static int hf_gsm_a_rr_gsm_band = -1;
static int hf_gsm_a_rr_arfcn_first = -1;
static int hf_gsm_a_rr_band_offset = -1;
static int hf_gsm_a_rr_arfcn_range = -1;
static int hf_gsm_a_rr_lowest_arfcn = -1;
static int hf_gsm_a_rr_inc_skip_arfcn = -1;
static int hf_gsm_a_rr_gprs_resumption_ack = -1;
static int hf_gsm_a_rr_ext_ind = -1;
static int hf_gsm_a_rr_ba_ind = -1;
static int hf_gsm_a_rr_multiband_reporting = -1;
static int hf_gsm_a_rr_ncc_permitted = -1;
static int hf_gsm_a_rr_max_retrans = -1;
static int hf_gsm_a_rr_tx_integer = -1;
static int hf_gsm_a_rr_cell_barr_access = -1;
static int hf_gsm_a_rr_re = -1;
static int hf_gsm_a_rr_acc = -1;
static int hf_gsm_a_rr_nch_position = -1;
static int hf_gsm_a_rr_qsearch_i = -1;
static int hf_gsm_a_rr_fdd_qoffset = -1;
static int hf_gsm_a_rr_fdd_qmin = -1;
static int hf_gsm_a_rr_tdd_qoffset = -1;
static int hf_gsm_a_rr_fdd_qmin_offset = -1;
static int hf_gsm_a_rr_fdd_rscpmin = -1;
static int hf_gsm_a_rr_gsm_report_type = -1;
static int hf_gsm_a_rr_serving_band_reporting = -1;
static int hf_gsm_a_rr_frequency_scrolling = -1;
static int hf_gsm_a_rr_rep_priority = -1;
static int hf_gsm_a_rr_report_type = -1;
static int hf_gsm_a_rr_reporting_rate = -1;
static int hf_gsm_a_rr_invalid_bsic_reporting = -1;
static int hf_gsm_a_rr_scale_ord = -1;
static int hf_gsm_a_rr_900_reporting_offset = -1;
static int hf_gsm_a_rr_900_reporting_threshold = -1;
static int hf_gsm_a_rr_1800_reporting_offset = -1;
static int hf_gsm_a_rr_1800_reporting_threshold = -1;
static int hf_gsm_a_rr_400_reporting_offset = -1;
static int hf_gsm_a_rr_400_reporting_threshold = -1;
static int hf_gsm_a_rr_1900_reporting_offset = -1;
static int hf_gsm_a_rr_1900_reporting_threshold = -1;
static int hf_gsm_a_rr_850_reporting_offset = -1;
static int hf_gsm_a_rr_850_reporting_threshold = -1;
static int hf_gsm_a_rr_network_control_order = -1;
static int hf_gsm_a_rr_nc_non_drx_period = -1;
static int hf_gsm_a_rr_nc_reporting_period_i = -1;
static int hf_gsm_a_rr_nc_reporting_period_t = -1;
static int hf_gsm_a_rr_qsearch_c_initial = -1;
static int hf_gsm_a_rr_fdd_rep_quant = -1;
static int hf_gsm_a_rr_fdd_multirat_reporting = -1;
static int hf_gsm_a_rr_tdd_multirat_reporting = -1;
static int hf_gsm_a_rr_qsearch_p = -1;
static int hf_gsm_a_rr_3g_search_prio = -1;
static int hf_gsm_a_rr_fdd_reporting_offset = -1;
static int hf_gsm_a_rr_fdd_reporting_threshold = -1;
static int hf_gsm_a_rr_tdd_reporting_offset = -1;
static int hf_gsm_a_rr_tdd_reporting_threshold = -1;
static int hf_gsm_a_rr_fdd_reporting_threshold_2 = -1;
static int hf_gsm_a_rr_3g_ccn_active = -1;
static int hf_gsm_a_rr_700_reporting_offset = -1;
static int hf_gsm_a_rr_700_reporting_threshold = -1;
static int hf_gsm_a_rr_810_reporting_offset = -1;
static int hf_gsm_a_rr_810_reporting_threshold = -1;
static int hf_gsm_a_rr_cbq = -1;
static int hf_gsm_a_rr_cell_reselect_offset = -1;
static int hf_gsm_a_rr_temporary_offset = -1;
static int hf_gsm_a_rr_penalty_time = -1;
static int hf_gsm_a_rr_si13_position = -1;
static int hf_gsm_a_rr_power_offset = -1;
static int hf_gsm_a_rr_si2quater_position = -1;
static int hf_gsm_a_rr_si13alt_position = -1;
static int hf_gsm_a_rr_prio_thr = -1;
static int hf_gsm_a_rr_lsa_offset = -1;
static int hf_gsm_a_rr_paging_channel_restructuring = -1;
static int hf_gsm_a_rr_nln_sacch = -1;
static int hf_gsm_a_rr_nln_status_sacch = -1;
static int hf_gsm_a_rr_vbs_vgcs_inband_notifications = -1;
static int hf_gsm_a_rr_vbs_vgcs_inband_pagings = -1;
static int hf_gsm_a_rr_rac = -1;
static int hf_gsm_a_rr_max_lapdm = -1;
static int hf_gsm_a_rr_gprs_ms_txpwr_max_ccch = -1;
static int hf_gsm_a_rr_dedicated_mode_mbms_notification_support = -1;
static int hf_gsm_a_rr_mnci_support = -1;
static int hf_gsm_a_rr_amr_config = -1;
static int hf_gsm_a_rr_bcch_change_mark = -1;
static int hf_gsm_a_rr_si_change_field = -1;
static int hf_gsm_a_rr_si13_change_mark = -1;
static int hf_gsm_a_rr_hsn = -1;
static int hf_gsm_a_rr_rfl_number = -1;
static int hf_gsm_a_rr_arfcn_index = -1;
static int hf_gsm_a_rr_ma_length = -1;
static int hf_gsm_a_rr_psi1_repeat_period = -1;
static int hf_gsm_a_rr_pbcch_pb = -1;
static int hf_gsm_a_rr_pbcch_tsc = -1;
static int hf_gsm_a_rr_pbcch_tn = -1;
static int hf_gsm_a_rr_spgc_ccch_sup = -1;
static int hf_gsm_a_rr_priority_access_thr = -1;
static int hf_gsm_a_rr_nmo = -1;
static int hf_gsm_a_rr_t3168 = -1;
static int hf_gsm_a_rr_t3192 = -1;
static int hf_gsm_a_rr_drx_timer_max = -1;
static int hf_gsm_a_rr_access_burst_type = -1;
static int hf_gsm_a_rr_control_ack_type = -1;
static int hf_gsm_a_rr_bs_cv_max = -1;
static int hf_gsm_a_rr_pan_dec = -1;
static int hf_gsm_a_rr_pan_inc = -1;
static int hf_gsm_a_rr_pan_max = -1;
static int hf_gsm_a_rr_egprs_packet_channel_request = -1;
static int hf_gsm_a_rr_bep_period = -1;
static int hf_gsm_a_rr_pfc_feature_mode = -1;
static int hf_gsm_a_rr_dtm_support = -1;
static int hf_gsm_a_rr_bss_paging_coordination = -1;
static int hf_gsm_a_rr_ccn_active = -1;
static int hf_gsm_a_rr_nw_ext_utbf = -1;
static int hf_gsm_a_rr_multiple_tbf_capability = -1;
static int hf_gsm_a_rr_ext_utbf_no_data = -1;
static int hf_gsm_a_rr_dtm_enhancements_capability = -1;
static int hf_gsm_a_rr_reduced_latency_access = -1;
static int hf_gsm_a_rr_alpha = -1;
static int hf_gsm_a_rr_t_avg_w = -1;
static int hf_gsm_a_rr_t_avg_t = -1;
static int hf_gsm_a_rr_pc_meas_chan = -1;
static int hf_gsm_a_rr_n_avg_i = -1;
static int hf_gsm_a_rr_sgsnr = -1;
static int hf_gsm_a_rr_si_status_ind = -1;
static int hf_gsm_a_rr_lb_ms_txpwr_max_cch = -1;
static int hf_gsm_a_rr_si2n_support = -1;
static int hf_gsm_a_rr_t1prime = -1;
static int hf_gsm_a_rr_t3 = -1;
static int hf_gsm_a_rr_t2 = -1;

/* Initialize the subtree pointers */
static gint ett_ccch_msg = -1;
static gint ett_ccch_oct_1 = -1;

static char a_bigbuf[1024];

static dissector_handle_t data_handle;



#define	NUM_GSM_RR_ELEM (sizeof(gsm_rr_elem_strings)/sizeof(value_string))
gint ett_gsm_rr_elem[NUM_GSM_RR_ELEM];

typedef enum
{
   /* RR Rest Octets information elements */
   DE_RR_REST_OCTETS_UTRAN_FDD_DESC,
   DE_RR_REST_OCTETS_UTRAN_TDD_DESC,
   DE_RR_REST_OCTETS_3G_MEAS_PARAM_DESC,
   DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC,
   DE_RR_REST_OCTETS_MEAS_PARAM_DESC,
   DE_RR_REST_OCTETS_GPRS_RTD_DESC,
   DE_RR_REST_OCTETS_GPRS_BSIC_DESC,
   DE_RR_REST_OCTETS_GPRS_REPORT_PRIO_DESC,
   DE_RR_REST_OCTETS_GPRS_MEAS_PARAM_DESC,
   DE_RR_REST_OCTETS_NC_MEAS_PARAM,
   DE_RR_REST_OCTETS_SI2Q_EXT_INFO,
   DE_RR_REST_OCTETS_CCN_SUPPORT_DESC,
   DE_RR_REST_OCTETS_3G_NEIGH_CELL_DESC,
   DE_RR_REST_OCTETS_FDD_CELL_INFORMATION_FIELD,
   DE_RR_REST_OCTETS_TDD_CELL_INFORMATION_FIELD,
   DE_RR_REST_OCTETS_GPRS_3G_MEAS_PARAM_DESC,
   DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC2,
   DE_RR_REST_OCTETS_OPTIONAL_SEL_PARAM,
   DE_RR_REST_OCTETS_GPRS_INDICATOR,
   DE_RR_REST_OCTETS_SI4_REST_OCTETS_O,
   DE_RR_REST_OCTETS_SI4_REST_OCTETS_S,
   DE_RR_REST_OCTETS_LSA_PARAMETERS,
   DE_RR_REST_OCTETS_LSA_ID_INFO,
   DE_RR_REST_OCTETS_PCH_AND_NCH_INFO,
   DE_RR_REST_OCTETS_VBS_VGCS_OPTIONS,
   DE_RR_REST_OCTETS_GPRS_MOBILE_ALLOC,
   DE_RR_REST_OCTETS_GPRS_CELL_OPTIONS,
   DE_RR_REST_OCTETS_GPRS_CELL_OPTIONS_EXT_INFO,
   DE_RR_REST_OCTETS_GPRS_POWER_CONTROL_PARAMS,
   DE_RR_REST_OCTETS_PBCCH_DESC,
   DE_RR_REST_OCTETS_NONE
}
rr_rest_octets_elem_idx_t;

#define NUM_GSM_RR_REST_OCTETS_ELEM (sizeof(gsm_rr_rest_octets_elem_strings)/sizeof(value_string))
gint ett_gsm_rr_rest_octets_elem[NUM_GSM_RR_REST_OCTETS_ELEM];

/*
10.5.2 Radio Resource management information elements
 * [3] 10.5.2.1a BA Range
 */
/*
 * [3] 10.5.2.1b Cell Channel Description
 */

#define ARFCN_MAX 1024 /* total number of ARFCNs defined */

static void display_channel_list(guint8 *list, tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
	int arfcn;
	proto_item *ti=NULL;

	ti = proto_tree_add_text(tree, tvb, 0, offset, "List of ARFCNs =");
	for (arfcn=0; arfcn<ARFCN_MAX; arfcn++) {
		if (list[arfcn])
			proto_item_append_text(ti, " %d", arfcn);
	}

	return;
}

static gint greatest_power_of_2_lesser_or_equal_to(gint index)
{
   gint j = 1;
   do {
      j<<=1;
   } while (j<=index);
   j >>= 1;
   return j;
}

static gint f_k(gint k, gint *w, gint range)
{
   gint index, n, j;

   index = k;
   range -= 1;
   range = range/greatest_power_of_2_lesser_or_equal_to(index);
   n = w[index]-1;

   while (index>1) {
      j = greatest_power_of_2_lesser_or_equal_to(index);
      range = 2*range+1;
      if ((2*index) < 3*j){ /* left child */
         index -= j/2;
         n = (n+w[index]-1+((range-1)/2)+1)%range;
      }
      else { /* right child */
         index -= j;
         n = (n+w[index]-1+1)%range;
      }
   }

   return (n+1)%1024;
}

static void dissect_channel_list_n_range(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gint range)
{
	gint curr_offset=offset, f0, arfcn_orig, bits, w[64], wsize, i, wi;
	gint octet, nwi=1, jwi=0, wbits, imax, iused, arfcn;
	guint8 list[1024];

	memset((void*)list,0,sizeof(list));

	octet = tvb_get_guint8(tvb, curr_offset++);
	if (range==1024) {
		f0 = (octet>>2)&1;
		if (f0)
			list[0] = 1;
		bits = 2;
		arfcn_orig = 0;
		wsize = 10;
		imax = 16;
	}
	else {
		arfcn_orig = (octet&1);
		arfcn_orig = (arfcn_orig << 8) + tvb_get_guint8(tvb, curr_offset++);
		octet = tvb_get_guint8(tvb, curr_offset++);
		arfcn_orig = (arfcn_orig << 1) + (octet>>7);
		list[arfcn_orig] = 1;
		bits = 7;
		switch (range) {
		case 512:
			wsize=9;
			imax = 17;
			break;
		case 256:
			wsize=8;
			imax = 21;
			break;
		case 128:
			wsize=7;
			imax = 28;
			break;
		default:
			wsize=0;
			imax = 0;
			DISSECTOR_ASSERT_NOT_REACHED();
		}
	}
	iused = imax;   /* in case the list is actually full */

	/* extract the variable size w[] elements */
	for (i=1; i<=imax; i++) {
		wi = octet & ~(0xff<<bits);	 /* mask "bits" low bits to start wi from existing octet */
		wbits = bits;
		if (wsize>wbits) {			  /* need to extract more bits from the next octet */
			octet = tvb_get_guint8(tvb, curr_offset++);
			wi = (wi << 8) + octet;
			bits = 8;
			wbits += 8;
		}

		if (wbits>wsize)	{		   /* now we have too many bits - save some */
			bits = wbits - wsize;
			wi >>= bits;
		}
		else							/* just right number of bits */
			bits = 0;

		w[i] = wi;
		if ((w[i]==0) || ((curr_offset-offset)>len)) {
			iused = i - 1;
			break;	  /* all remaining elements must also be zero */
		}

		if (++jwi==nwi) {	   /* check if the number of wi at this wsize has been extracted */
			jwi = 0;			/* reset the count of wi at this size */
			nwi <<= 1;		  /* get twice as many of the next size */
			wsize--;			/* make the next size 1 bit smaller */
		}
	}

	for (i=1; i<=iused; i++) {
		arfcn = (f_k(i, w, range) + arfcn_orig)%1024;
		list[arfcn] = 1;
	}

	display_channel_list(list, tvb, tree, offset);

	return;
}

static guint8
dissect_arfcn_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8  oct,bit,byte;
	guint16 arfcn;
	proto_item	*item;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* FORMAT-ID, Format Identifier (part of octet 3)*/
	proto_tree_add_item(tree, hf_gsm_a_rr_format_id, tvb, curr_offset, 1, FALSE);

	if ((oct & 0xc0) == 0x00)
	{
		/* bit map 0 */
		item = proto_tree_add_text(tree,tvb, curr_offset, len, "List of ARFCNs =");
		bit = 4;
		arfcn = 125;
		for (byte = 0;byte <= len-1;byte++)
		{
			oct = tvb_get_guint8(tvb, curr_offset);
			while (bit-- != 0)
			{
				arfcn--;
				if (((oct >> bit) & 1) == 1)
				{
					proto_item_append_text(item," %d",arfcn);
				}
			}
			bit = 8;
			curr_offset++;
		}
	}
	else if ((oct & 0xc8) == 0x80)
	{
		/* 1024 range */
		dissect_channel_list_n_range(tvb, tree, curr_offset, len, 1024);
		curr_offset = curr_offset + len;
	}
	else if ((oct & 0xce) == 0x88)
	{
		/* 512 range */
		dissect_channel_list_n_range(tvb, tree, curr_offset, len, 512);
		curr_offset = curr_offset + len;
	}
	else if ((oct & 0xce) == 0x8a)
	{
		/* 256 range */
		dissect_channel_list_n_range(tvb, tree, curr_offset, len, 256);
		curr_offset = curr_offset + len;
	}
	else if ((oct & 0xce) == 0x8c)
	{
		/* 128 range */
		dissect_channel_list_n_range(tvb, tree, curr_offset, len, 128);
		curr_offset = curr_offset + len;
	}
	else if ((oct & 0xce) == 0x8e)
	{
		/* variable bit map */
		arfcn = ((oct & 0x01) << 9) | (tvb_get_guint8(tvb, curr_offset+1) << 1) | ((tvb_get_guint8(tvb, curr_offset + 2) & 0x80) >> 7);
		item = proto_tree_add_text(tree,tvb,curr_offset,len,"List of ARFCNs = %d",arfcn);
		curr_offset = curr_offset + 2;
		bit = 7;
		for (byte = 0;byte <= len-3;byte++)
		{
			oct = tvb_get_guint8(tvb, curr_offset);
			while (bit-- != 0)
			{
				arfcn++;
				if (((oct >> bit) & 1) == 1)
				{
					proto_item_append_text(item," %d",arfcn);
				}
			}
			bit = 8;
			curr_offset++;
		}
	}

	return(curr_offset - offset);
}

guint8
de_rr_cell_ch_dsc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	return dissect_arfcn_list(tvb, tree, offset, 16, add_string, string_len);
}
/*
 * [3] 10.5.2.1c BA List Pref
 * [3] 10.5.2.1d UTRAN Frequency List
 */
/*
 * [3] 10.5.2.2 Cell Description
 */
guint8
de_rr_cell_dsc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint8	oct;
	guint32	curr_offset;
	guint16 bcch_arfcn;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	item =
		proto_tree_add_text(tree,
			tvb, curr_offset, 2, "%s",
			gsm_rr_elem_strings[DE_RR_CELL_DSC].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_CELL_DSC]);

	proto_tree_add_item(subtree, hf_gsm_a_ncc, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_bcc, tvb, curr_offset, 1, FALSE);
	bcch_arfcn = (tvb_get_guint8(tvb,curr_offset) & 0xc0) << 2;
	bcch_arfcn = bcch_arfcn | tvb_get_guint8(tvb,curr_offset+1);
	proto_tree_add_uint(subtree, hf_gsm_a_bcch_arfcn , tvb, curr_offset, 2, bcch_arfcn );

	curr_offset = curr_offset + 2;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.3 Cell Options (BCCH)
 */
static const value_string gsm_a_rr_dtx_bcch_vals[] = {
	{ 0x00,	"The MSs may use uplink discontinuous transmission" },
	{ 0x01,	"The MSs shall use uplink discontinuous transmission" },
	{ 0x02,	"The MSs shall not use uplink discontinuous transmission" },
	{ 0x03,	"Reserved" },
	{ 0,	NULL } };

static const value_string gsm_a_rr_radio_link_timeout_vals[] = {
	{ 0x00,	"4" },
	{ 0x01,	"8" },
	{ 0x02,	"12" },
	{ 0x03,	"16" },
	{ 0x04,	"20" },
	{ 0x05,	"24" },
	{ 0x06,	"28" },
	{ 0x07,	"32" },
	{ 0x08,	"36" },
	{ 0x09,	"40" },
	{ 0x0A,	"44" },
	{ 0x0B,	"48" },
	{ 0x0C,	"52" },
	{ 0x0D,	"56" },
	{ 0x0E,	"60" },
	{ 0x0F,	"64" },
	{ 0,	NULL } };

static guint8
de_rr_cell_opt_bcch(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	curr_offset = offset;

	item = proto_tree_add_text(tree, tvb, curr_offset, 1, "%s",
		gsm_rr_elem_strings[DE_RR_CELL_OPT_BCCH].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_CELL_OPT_BCCH]);

	proto_tree_add_item(subtree, hf_gsm_a_rr_pwrc, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_dtx_bcch, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_radio_link_timeout, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.3a Cell Options (SACCH)
 */
static const value_string gsm_a_rr_dtx_sacch_vals[] = {
	{ 0x00,	"The MS may use uplink discontinuous transmission on a TCH-F. The MS shall not use uplink discontinuous transmission on TCH-H" },
	{ 0x01,	"The MS shall use uplink discontinuous transmission on a TCH-F. The MS shall not use uplink discontinuous transmission on TCH-H" },
	{ 0x02,	"The MS shall not use uplink discontinuous transmission on a TCH-F. The MS shall not use uplink discontinuous transmission on TCH-H" },
	{ 0x03,	"The MS shall use uplink discontinuous transmission on a TCH-F. The MS may use uplink discontinuous transmission on TCH-H" },
	{ 0x04,	"The MS may use uplink discontinuous transmission on a TCH-F. The MS may use uplink discontinuous transmission on TCH-H" },
	{ 0x05,	"The MS shall use uplink discontinuous transmission on a TCH-F. The MS shall use uplink discontinuous transmission on TCH-H" },
	{ 0x06,	"The MS shall not use uplink discontinuous transmission on a TCH-F. The MS shall use uplink discontinuous transmission on TCH-H" },
	{ 0x07,	"The MS may use uplink discontinuous transmission on a TCH-F. The MS shall use uplink discontinuous transmission on TCH-H" },
	{ 0,	NULL } };

static guint8
de_rr_cell_opt_sacch(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint8	oct;
	guint8	dtx;
	guint32	curr_offset;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	dtx = ((oct&0x80)>>5)|((oct&0x30)>>4); /* DTX is a split filed in bits 8, 6 and 5 */
	item = proto_tree_add_text(tree, tvb, curr_offset, 1, "%s",
		gsm_rr_elem_strings[DE_RR_CELL_OPT_SACCH].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_CELL_OPT_SACCH]);

	proto_tree_add_item(subtree, hf_gsm_a_rr_pwrc, tvb, curr_offset, 1, FALSE);
	proto_tree_add_uint(subtree, hf_gsm_a_rr_dtx_sacch, tvb, curr_offset, 1, dtx);
	proto_tree_add_item(subtree, hf_gsm_a_rr_radio_link_timeout, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.4 Cell Selection Parameters
 */
static guint8
de_rr_cell_sel_param(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint8	oct;
	guint32	curr_offset;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	item = proto_tree_add_text(tree, tvb, curr_offset, 2, "%s",
		gsm_rr_elem_strings[DE_RR_CELL_SEL_PARAM].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_CELL_SEL_PARAM]);

	proto_tree_add_item(subtree, hf_gsm_a_rr_cell_reselect_hyst, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_ms_txpwr_max_cch, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	proto_tree_add_item(subtree, hf_gsm_a_rr_acs, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_neci, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_rxlev_access_min, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.4a MAC Mode and Channel Coding Requested
 * [3] 10.5.2.5 Channel Description
 */
guint8
de_rr_ch_dsc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8	oct8,subchannel;
	guint16 arfcn, hsn, maio;
	proto_tree	*subtree;
	proto_item	*item;
	const gchar *str;

	curr_offset = offset;

	item = proto_tree_add_text(tree,tvb, curr_offset, 3, "%s", gsm_rr_elem_strings[DE_RR_CH_DSC].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_CH_DSC]);

	/* Octet 2 */
	oct8 = tvb_get_guint8(tvb, curr_offset);

	if ((oct8 & 0xf8) == 0x08)
	{
		str = "TCH/F + ACCHs";
		other_decode_bitfield_value(a_bigbuf, oct8, 0xf8, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = %s",a_bigbuf,str);
	}
	else
	{
		if ((oct8 & 0xf0) == 0x10)
		{
			str = "TCH/H + ACCHs, Subchannel";
			subchannel = ((oct8 & 0x08)>>3);
		}
		else if ((oct8 & 0xe0) == 0x20)
		{
			str = "SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4), Subchannel";
			subchannel = ((oct8 & 0x18)>>3);
		}
		else if ((oct8 & 0xc0) == 0x40)
		{
			str = "SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8), Subchannel";
			subchannel = ((oct8 % 0x38)>>3);
   	 	} else {
			str = "";
			subchannel = 0;
			DISSECTOR_ASSERT_NOT_REACHED();
		}
	
		other_decode_bitfield_value(a_bigbuf, oct8, 0xf8, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = %s %d",a_bigbuf,str,subchannel);
	}

	other_decode_bitfield_value(a_bigbuf, oct8, 0x07, 8);
	proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Timeslot: %d",a_bigbuf,(oct8 & 0x07));

	curr_offset +=1;
	
	/* Octet 3 */
	oct8 = tvb_get_guint8(tvb, curr_offset);
	other_decode_bitfield_value(a_bigbuf, oct8, 0xe0, 8);
	proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Training Sequence: %d",a_bigbuf,((oct8 & 0xe0)>>5));
	

	if ((oct8 & 0x10) == 0x10)
	{
		/* Hopping sequence */
		maio = ((oct8 & 0x0f)<<2) | ((tvb_get_guint8(tvb,curr_offset+1) & 0xc0) >> 6);
		hsn = (tvb_get_guint8(tvb,curr_offset+1) & 0x3f);
		str = "Yes";

		other_decode_bitfield_value(a_bigbuf, oct8, 0x10, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Hopping channel: %s",a_bigbuf,str);
		proto_tree_add_text(subtree,tvb, curr_offset, 2,"Hopping channel: MAIO %d",maio);
		proto_tree_add_text(subtree,tvb, curr_offset, 2,"Hopping channel: HSN %d",hsn);
	}
	else
	{
		/* sinlge ARFCN */
		arfcn = ((oct8 & 0x03) << 8) | tvb_get_guint8(tvb,curr_offset+1);
		str = "No";

		other_decode_bitfield_value(a_bigbuf, oct8, 0x10, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Hopping channel: %s",a_bigbuf,str);
		other_decode_bitfield_value(a_bigbuf, oct8, 0x0c, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Spare",a_bigbuf);
		proto_tree_add_text(subtree,tvb, curr_offset, 2,"Single channel : ARFCN %d",arfcn);
	}
	
	curr_offset = curr_offset + 2;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.5a Channel Description 2
 */
static guint8
de_rr_ch_dsc2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8	oct8,subchannel;
	guint16 arfcn, hsn, maio;
	proto_tree	*subtree;
	proto_item	*item;
	const gchar *str;

	curr_offset = offset;

	item = proto_tree_add_text(tree,tvb, curr_offset, 3, "%s", gsm_rr_elem_strings[DE_RR_CH_DSC2].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_CH_DSC2]);

	/* Octet 2 */
	oct8 = tvb_get_guint8(tvb, curr_offset);

	if ((oct8 & 0xf8) == 0x0)
	{
		str = "TCH/F + FACCH/F and SACCH/M";
		other_decode_bitfield_value(a_bigbuf, oct8, 0xf8, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = %s",a_bigbuf,str);
	}
	else if ((oct8 & 0xf8) == 0x08)
	{
		str = "TCH/F + FACCH/F and SACCH/F";
		other_decode_bitfield_value(a_bigbuf, oct8, 0xf8, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = %s",a_bigbuf,str);
	}
	else if ((oct8 & 0xf8) == 0xf0)
	{
		str = "TCH/F + FACCH/F and SACCH/M + bi- and unidirectional channels";
		other_decode_bitfield_value(a_bigbuf, oct8, 0xf8, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = %s",a_bigbuf,str);
	}
	else
	{
		if ((oct8 & 0xf0) == 0x10)
		{
			str = "TCH/H + ACCHs, Subchannel";
			subchannel = ((oct8 & 0x08)>>3);
		}
		else if ((oct8 & 0xe0) == 0x20)
		{
			str = "SDCCH/4 + SACCH/C4 or CBCH (SDCCH/4), Subchannel";
			subchannel = ((oct8 & 0x18)>>3);
		}
		else if ((oct8 & 0xc0) == 0x40)
		{
			str = "SDCCH/8 + SACCH/C8 or CBCH (SDCCH/8), Subchannel";
			subchannel = ((oct8 % 0x38)>>3);
   	 	}
		else if ((oct8 & 0xc0) == 0x80)
		{
			str = "TCH/F + FACCH/F and SACCH/M + bidirectional channels at timeslot";
			subchannel = ((oct8 % 0x38)>>3);
		}
		else if ((oct8 & 0xe0) == 0xc0)
		{
			str = "TCH/F + FACCH/F and SACCH/M + unidirectional channels at timeslot";
			subchannel = ((oct8 % 0x38)>>3);
		} else {
			str = "";
			subchannel = 0;
			DISSECTOR_ASSERT_NOT_REACHED();
		}
		other_decode_bitfield_value(a_bigbuf, oct8, 0xf8, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = %s %d",a_bigbuf,str,subchannel);
	}

	other_decode_bitfield_value(a_bigbuf, oct8, 0x07, 8);
	proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Timeslot: %d",a_bigbuf,(oct8 & 0x07));

	curr_offset +=1;
	
	/* Octet 3 */
	oct8 = tvb_get_guint8(tvb, curr_offset);
	other_decode_bitfield_value(a_bigbuf, oct8, 0xe0, 8);
	proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Training Sequence: %d",a_bigbuf,((oct8 & 0xe0)>>5));

	if ((oct8 & 0x10) == 0x10)
	{
		/* Hopping sequence */
		maio = ((oct8 & 0x0f)<<2) | ((tvb_get_guint8(tvb,curr_offset+1) & 0xc0) >> 6);
		hsn = (tvb_get_guint8(tvb,curr_offset+1) & 0x3f);
		str = "Yes";

		other_decode_bitfield_value(a_bigbuf, oct8, 0x10, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Hopping channel: %s",a_bigbuf,str);
		proto_tree_add_text(subtree,tvb, curr_offset, 2,"Hopping channel: MAIO %d",maio);
		proto_tree_add_text(subtree,tvb, curr_offset, 2,"Hopping channel: HSN %d",hsn);
	}
	else
	{
		/* sinlge ARFCN */
		arfcn = ((oct8 & 0x03) << 8) | tvb_get_guint8(tvb,curr_offset+1);
		str = "No";

		other_decode_bitfield_value(a_bigbuf, oct8, 0x10, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Hopping channel: %s",a_bigbuf,str);
		other_decode_bitfield_value(a_bigbuf, oct8, 0x0c, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Spare",a_bigbuf);
		proto_tree_add_text(subtree,tvb, curr_offset, 2,"Single channel : ARFCN %d",arfcn);
	}
	
	curr_offset = curr_offset + 2;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.6 Channel Mode
 */
/* Channel Mode  */
static const value_string gsm_a_rr_channel_mode_vals[] = {
	{ 0x00,	"signalling only"},
	{ 0x01,	"speech full rate or half rate version 1(GSM FR or GSM HR)"},
	{ 0x21,	"speech full rate or half rate version 2(GSM EFR)"},
	{ 0x41,	"speech full rate or half rate version 3(FR AMR or HR AMR)"},
	{ 0x81,	"speech full rate or half rate version 4(OFR AMR-WB or OHR AMR-WB)"},
	{ 0x82,	"speech full rate or half rate version 5(FR AMR-WB )"},
	{ 0x83,	"speech full rate or half rate version 6(OHR AMR )"},
	{ 0x61,	"data, 43.5 kbit/s (downlink)+14.5 kbps (uplink)"},
	{ 0x62,	"data, 29.0 kbit/s (downlink)+14.5 kbps (uplink)"},
	{ 0x64,	"data, 43.5 kbit/s (downlink)+29.0 kbps (uplink)"},
	{ 0x67,	"data, 14.5 kbit/s (downlink)+43.5 kbps (uplink)"},
	{ 0x65,	"data, 14.5 kbit/s (downlink)+29.0 kbps (uplink)"},
	{ 0x66,	"data, 29.0 kbit/s (downlink)+43.5 kbps (uplink)"},
	{ 0x27,	"data, 43.5 kbit/s radio interface rate"},
	{ 0x63,	"data, 32.0 kbit/s radio interface rate"},
	{ 0x43,	"data, 29.0 kbit/s radio interface rate"},
	{ 0x0f,	"data, 14.5 kbit/s radio interface rate"},
	{ 0x03,	"data, 12.0 kbit/s radio interface rate"},
	{ 0x0b,	"data, 6.0 kbit/s radio interface rate"},
	{ 0x13,	"data, 3.6 kbit/s radio interface rate"},
	{ 0,	NULL }
};

guint8
de_rr_ch_mode(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_channel_mode, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.7 Channel Mode 2
 */

static const value_string gsm_a_rr_channel_mode2_vals[] = {
	{ 0x00,	"signalling only"},
	{ 0x05,	"speech half rate version 1(GSM HR)"},
	{ 0x25,	"speech half rate version 2(GSM EFR)"},
	{ 0x45,	"speech half rate version 3(HR AMR)"},
	{ 0x85,	"speech half rate version 4(OHR AMR-WB)"},
	{ 0x06,	"speech half rate version 6(OHR AMR )"},
	{ 0x0f,	"data, 6.0 kbit/s radio interface rate"},
	{ 0x17,	"data, 3.6 kbit/s radio interface rate"},
	{ 0,	NULL }
};

static guint8
de_rr_ch_mode2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_channel_mode2, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.7a UTRAN Classmark information element
 * [3] 10.5.2.7b (void)
 */
/*
 * [3] 10.5.2.7c Classmark Enquiry Mask
 * Bit 8:
 * 0	CLASSMARK CHANGE message is requested
 * 1	CLASSMARK CHANGE message is not requested
 * Bits 7-5 . 5
 * 000	UTRAN CLASSMARK CHANGE message including status on predefined configurations (i.e. Sequence Description) is requested
 * 111	UTRAN CLASSMARK CHANGE message including status on predefined configurations (i.e. Sequence Description) is not requested.
 * All other values shall not be sent. If received, they shall be interpreted as '000'.
 * Bit 4:
 * 0	CDMA2000 CLASSMARK CHANGE message requested
 * 1	CDMA2000 CLASSMARK CHANGE message not requested.
 * Bit 3:
 * 0	GERAN IU MODE CLASSMARK CHANGE message requested
 * 1	GERAN IU MODE CLASSMARK CHANGE message not requested.
 * Bits 2 - 1: spare(0).
 */
static const true_false_string gsm_a_msg_req_value  = {
	"message is not requested",
	"message is requested"
};

static const value_string gsm_a_rr_utran_cm_cng_msg_req_vals[] = {
	{ 0x0,	"message including status on predefined configurations (i.e. Sequence Description) is requested"},
	{ 0x1,	"message including status on predefined configurations (i.e. Sequence Description) is requested"},
	{ 0x2,	"message including status on predefined configurations (i.e. Sequence Description) is requested"},
	{ 0x3,	"message including status on predefined configurations (i.e. Sequence Description) is requested"},
	{ 0x4,	"message including status on predefined configurations (i.e. Sequence Description) is requested"},
	{ 0x5,	"message including status on predefined configurations (i.e. Sequence Description) is requested"},
	{ 0x6,	"message including status on predefined configurations (i.e. Sequence Description) is requested"},
	{ 0x7,	"message including status on predefined configurations (i.e. Sequence Description) is not requested."},
	{ 0,	NULL }
};
guint8
de_rr_cm_enq_mask(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_cm_cng_msg_req, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_utran_cm_cng_msg_req, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_cdma200_cm_cng_msg_req, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_geran_iu_cm_cng_msg_req, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.8 Channel Needed
 */
static const value_string gsm_a_rr_channel_needed_vals[] = {
	{ 0x00,	"Any channel"},
	{ 0x01,	"SDCCH"},
	{ 0x02,	"TCH/F (Full rate)"},
	{ 0x03,	"TCH/H or TCH/F (Dual rate)"},
	{ 0,	NULL }
};
guint8
de_rr_chnl_needed(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_chnl_needed_ch1, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_chnl_needed_ch2, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.8a Channel Request Description
 * [3] 10.5.2.8b Channel Request Description 2
 */
/*
 * [3] 10.5.2.9 Cipher Mode Setting
 */
/* SC (octet 1) */
static const value_string gsm_a_rr_sc_vals[] = {
	{ 0,	"No ciphering"},
	{ 1,	"Start ciphering"},
	{ 0,	NULL }
};
/* algorithm identifier
 * If SC=1 then:
 * bits
 * 4 3 2
 */
guint8
de_rr_cip_mode_set(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 oct;

	curr_offset = offset;

	/* Cipher Mode Setting
	 * Note: The coding of fields SC and algorithm identifier is defined in [44.018]
	 * as part of the Cipher Mode Setting IE.
	 */
	oct = tvb_get_guint8(tvb,curr_offset);
	if (UPPER_NIBBLE==len)
		oct>>=4;

	proto_tree_add_uint(tree, hf_gsm_a_rr_sc, tvb, curr_offset, 1, oct);
	if ( (oct & 1) == 1){ /* Start ciphering */
		/* algorithm identifier */
		proto_tree_add_uint(tree, hf_gsm_a_algorithm_id, tvb, curr_offset, 1, oct);
	}
	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.10 Cipher Response
 */
/* CR (octet 1) */
static const value_string gsm_a_rr_cr_vals[] = {
	{ 0,		"IMEISV shall not be included"},
	{ 1,		"IMEISV shall be included"},
	{ 0,	NULL }
};

static guint8
de_rr_cip_mode_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 oct;

	curr_offset = offset;
	oct = tvb_get_guint8(tvb,curr_offset);
	if (UPPER_NIBBLE==len)
		oct>>=4;

	/* Cipher Mode Response
		 * Note: The coding of field CR is defined in [44.018]
		 * as part of the Cipher Mode Response IE.
		 */
	proto_tree_add_uint(tree, hf_gsm_a_rr_cr, tvb, curr_offset, 1, oct);
	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}
/* [3] 10.5.2.11 Control Channel Description */

static const value_string gsm_a_rr_mscr_vals[] = {
	{ 0,	"MSC is Release '98 or older"},
	{ 1,	"MSC is Release '99 onwards"},
	{ 0,	NULL }
};

static const value_string gsm_a_rr_att_vals[] = {
	{ 0,	"MSs in the cell are not allowed to apply IMSI attach and detach procedure"},
	{ 1,	"MSs in the cell shall apply IMSI attach and detach procedure"},
	{ 0,	NULL }
};

static const value_string gsm_a_rr_ccch_conf_vals[] = {
	{ 0,	"1 basic physical channel used for CCCH, not combined with SDCCHs"},
	{ 1,	"1 basic physical channel used for CCCH, combined with SDCCHs"},
	{ 2,	"2 basic physical channels used for CCCH, not combined with SDCCHs"},
	{ 3,	"Reserved"},
	{ 4,	"3 basic physical channels used for CCCH, not combined with SDCCHs"},
	{ 5,	"Reserved"},
	{ 6,	"4 basic physical channels used for CCCH, not combined with SDCCHs"},
	{ 7,	"Reserved"},
	{ 0,	NULL }
};

static const value_string gsm_a_rr_cbq3_vals[] = {
	{ 0,	"Iu mode not supported"},
	{ 1,	"Iu mode capable MSs barred"},
	{ 2,	"Iu mode supported, cell not barred"},
	{ 3,	"Iu mode supported, cell not barred"},
	{ 0,	NULL }
};

static guint8
de_rr_ctrl_ch_desc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint8	oct;
	guint32	curr_offset;

	curr_offset = offset;

	item = proto_tree_add_text(tree, tvb, curr_offset, 3, "%s",
		gsm_rr_elem_strings[DE_RR_CTRL_CH_DESC].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_CTRL_CH_DESC]);

	proto_tree_add_item(subtree, hf_gsm_a_rr_mscr, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_att, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_bs_ag_blks_res, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_ccch_conf, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;
	oct = tvb_get_guint8(tvb, curr_offset);

   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_cbq3, tvb, (curr_offset<<3)+1, 2, FALSE);
	proto_tree_add_uint(subtree, hf_gsm_a_rr_bs_pa_mfrms, tvb, curr_offset, 1, (oct&0x07)+2);

	curr_offset = curr_offset + 1;

	proto_tree_add_item(subtree, hf_gsm_a_rr_t3212, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}

/* [3] 10.5.2.11a DTM Information Details
 */
/*
 * [3]  10.5.2.11b	Dynamic ARFCN Mapping	
 */
static const value_string gsm_a_rr_gsm_band_vals[] = {
	{ 0,	"GSM 750"},
	{ 1,	"DCS 1800"},
	{ 2,	"PCS 1900"},
	{ 3,	"GSM T 380"},
	{ 4,	"GSM T 410"},
	{ 5,	"GSM T 900"},
	{ 6,	"GSM 710"},
	{ 7,	"GSM T 810"},
	{ 8,	"Reserved"},
	{ 9,	"Reserved"},
	{ 10,	"Reserved"},
	{ 11,	"Reserved"},
	{ 12,	"Reserved"},
	{ 13,	"Reserved"},
	{ 14,	"Reserved"},
	{ 15,	"Reserved"},
	{ 0,	NULL }
};


static guint8
de_rr_dyn_arfcn_map(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
   gint bit_offset;
   guint64 length;
   guint value;

	curr_offset = offset;
   bit_offset = curr_offset << 3;

   proto_tree_add_bits_ret_val(tree, hf_gsm_a_rr_dyn_arfcn_length, tvb, bit_offset, 8, &length, FALSE);
   value = tvb_get_bits8(tvb,bit_offset,1);
   bit_offset += 1;
   while (value && length)
   {
      proto_tree_add_bits_item(tree, hf_gsm_a_rr_gsm_band, tvb, bit_offset, 4, FALSE);
      bit_offset += 4;
      proto_tree_add_bits_item(tree, hf_gsm_a_rr_arfcn_first, tvb, bit_offset, 10, FALSE);
      bit_offset += 10;
      proto_tree_add_bits_item(tree, hf_gsm_a_rr_band_offset, tvb, bit_offset, 10, FALSE);
      bit_offset += 10;
      proto_tree_add_bits_item(tree, hf_gsm_a_rr_arfcn_range, tvb, bit_offset, 7, FALSE);
      bit_offset += 7;
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      length -= 4;
   }

	curr_offset = curr_offset + len;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.12 Frequency Channel Sequence
 */
static guint8
de_rr_freq_ch_seq(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
   gint bit_offset, i;

	curr_offset = offset;

   proto_tree_add_item(tree, hf_gsm_a_rr_lowest_arfcn, tvb, curr_offset, 1, FALSE);
   curr_offset += 1;
   bit_offset = curr_offset << 3;
   for (i=0; i<16; i++)
   {
      proto_tree_add_bits_item(tree, hf_gsm_a_rr_inc_skip_arfcn, tvb, bit_offset, 4, FALSE);
      bit_offset += 4;
   }

	curr_offset = curr_offset + 8;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.13 Frequency List
 */
/*
 * [3] 10.5.2.13 Frequency List
 * 
 * Bit Bit Bit Bit Bit format notation
 * 8 7  4 3 2
 * 0 0  X X X bit map 0
 * 1 0  0 X X 1024 range
 * 1 0  1 0 0 512 range
 * 1 0  1 0 1 256 range
 * 1 0  1 1 0 128 range
 * 1 0  1 1 1 variable bit map
 */
/* The mask 0xce (1100 1110) will produce the result 0110 0111*/ 
static const value_string gsm_a_rr_freq_list_format_id_vals[] = {
	{ 0x00,	"bit map 0"},
	{ 0x02,	"bit map 0"},
	{ 0x04,	"bit map 0"},
	{ 0x06,	"bit map 0"},
	{ 0x08,	"bit map 0"},
	{ 0x0a,	"bit map 0"},
	{ 0x0c,	"bit map 0"},
	{ 0x0e,	"bit map 0"},
	{ 0x40,	"1024 range"},
	{ 0x41,	"1024 range"},
	{ 0x42,	"1024 range"},
	{ 0x43,	"1024 range"},
	{ 0x44,	"512 range"},
	{ 0x45,	"256 range"},
	{ 0x46,	"128 range"},
	{ 0x47,	"variable bit map"},
	{ 0x00,	NULL }
};
static guint8
de_rr_freq_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	return dissect_arfcn_list(tvb, tree, offset, len, add_string, string_len);
}
/*
 * [3] 10.5.2.14 Frequency Short List
 *
 *The Frequency Short List information element is a type 3 information element of 10 octet length.
 *
 * This element is encoded exactly as the Frequency List information element,
 * except that it has a fixed length instead of a variable length and does
 * not contain a length indicator and that it shall not be encoded in bitmap 0 format.
 */

 static guint8
de_rr_freq_short_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	return dissect_arfcn_list(tvb, tree, offset, 9, add_string, string_len);
}

/*
 * [3] 10.5.2.14a Frequency Short List 2
 *
 * The Frequency Short List information element is a type 3 information element of 8 octet length.
 *
 * This element is encoded exactly as the Frequency List information element,
 * except that it has a fixed length instead of a variable length and does
 * not contain a length indicator and that it shall not be encoded in bitmap 0 format.
 */
static guint8
de_rr_freq_short_list2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	return dissect_arfcn_list(tvb, tree, offset, 8, add_string, string_len);
}
/*
 * [3] 10.5.2.14b Group Channel Description
 */

/*
 * [3] 10.5.2.14c GPRS Resumption
 */
static const true_false_string gsm_a_rr_gprs_resumption_ack_value  = {
	"Resumption of GPRS services successfully acknowledged",
	"Resumption of GPRS services not successfully acknowledged"
};

static guint8
de_rr_gprs_resumption(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
   guint32 curr_offset;

   curr_offset = offset;

   proto_tree_add_item(tree, hf_gsm_a_rr_gprs_resumption_ack, tvb, curr_offset, 1, FALSE);
   curr_offset += 1;

   return (curr_offset - offset);
}

/*
 * [3] 10.5.2.14d GPRS broadcast information
 */

static gint
de_rr_rest_oct_gprs_cell_options(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
   proto_tree *subtree, *subtree2;
   proto_item *item, *item2;
   gint curr_bit_offset, curr_bit_offset_sav;
   guint8 value;

   curr_bit_offset = bit_offset;

   item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_CELL_OPTIONS].strptr);
	subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_CELL_OPTIONS]);
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_nmo, tvb, curr_bit_offset, 2, FALSE);
   curr_bit_offset += 2;
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_t3168, tvb, curr_bit_offset, 3, FALSE);
   curr_bit_offset += 3;
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_t3192, tvb, curr_bit_offset, 3, FALSE);
   curr_bit_offset += 3;
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_drx_timer_max, tvb, curr_bit_offset, 3, FALSE);
   curr_bit_offset += 3;
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_access_burst_type, tvb, curr_bit_offset, 1, FALSE);
   curr_bit_offset += 1;
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_control_ack_type, tvb, curr_bit_offset, 1, FALSE);
   curr_bit_offset += 1;
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bs_cv_max, tvb, curr_bit_offset, 4, FALSE);
   curr_bit_offset += 4;
   if (tvb_get_bits8(tvb,curr_bit_offset,1))
   {
      curr_bit_offset += 1;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pan_dec, tvb, curr_bit_offset, 3, FALSE);
      curr_bit_offset += 3;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pan_inc, tvb, curr_bit_offset, 3, FALSE);
      curr_bit_offset += 3;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pan_max, tvb, curr_bit_offset, 3, FALSE);
      curr_bit_offset += 3;
   }
   else
      curr_bit_offset += 1;
   if (tvb_get_bits8(tvb,curr_bit_offset,1))
   { /* Optional extension information */
      curr_bit_offset += 1;
      curr_bit_offset_sav = curr_bit_offset;
      item2 = proto_tree_add_text(subtree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_CELL_OPTIONS_EXT_INFO].strptr);
	   subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_CELL_OPTIONS_EXT_INFO]);
      value = tvb_get_bits8(tvb,curr_bit_offset,6);
      proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, 1, "Extension Length: %d", value);
      curr_bit_offset += 6;
      value += 1;
      proto_item_set_len(item2,((curr_bit_offset+value-curr_bit_offset_sav)>>3)+1);
      if (tvb_get_bits8(tvb,curr_bit_offset,1))
      {
         curr_bit_offset += 1;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_egprs_packet_channel_request, tvb, curr_bit_offset, 1, FALSE);
         curr_bit_offset += 1;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_bep_period, tvb, curr_bit_offset, 4, FALSE);
         curr_bit_offset += 4;
         value -= 5;
      }
      else
         curr_bit_offset += 1;
      value -= 1;
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_pfc_feature_mode, tvb, curr_bit_offset, 1, FALSE);
      curr_bit_offset += 1;
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_dtm_support, tvb, curr_bit_offset, 1, FALSE);
      curr_bit_offset += 1;
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_bss_paging_coordination, tvb, curr_bit_offset, 1, FALSE);
      curr_bit_offset += 1;
      value -= 3;
      if (value > 0)
      { /* Rel 4 extension */
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_ccn_active, tvb, curr_bit_offset, 1, FALSE);
         curr_bit_offset += 1;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_nw_ext_utbf, tvb, curr_bit_offset, 1, FALSE);
         curr_bit_offset += 1;
         value -= 2;
         if (value > 0)
         { /* Rel 6 extension */
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_multiple_tbf_capability, tvb, curr_bit_offset, 1, FALSE);
            curr_bit_offset += 1;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_ext_utbf_no_data, tvb, curr_bit_offset, 1, FALSE);
            curr_bit_offset += 1;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_dtm_enhancements_capability, tvb, curr_bit_offset, 1, FALSE);
            curr_bit_offset += 1;
            value -= 3;
            if (tvb_get_bits8(tvb,curr_bit_offset,1))
            {
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_dedicated_mode_mbms_notification_support, tvb, bit_offset, 1, FALSE);
               bit_offset += 1;
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_mnci_support, tvb, bit_offset, 1, FALSE);
               bit_offset += 1;
               value -= 2;
            }
            else
               bit_offset += 1;
            value -= 1;
            if (value > 0)
            { /* Rel 7 extension */
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_reduced_latency_access, tvb, bit_offset, 1, FALSE);
               bit_offset += 1;
               value -= 1;
            }
         }
      }
      curr_bit_offset += value;
   }
   else
      curr_bit_offset += 1;
   proto_item_set_len(item,((curr_bit_offset-bit_offset)>>3)+1);

   return (curr_bit_offset - bit_offset);
}

static gint
de_rr_rest_oct_gprs_power_control_parameters(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
   proto_tree *subtree;
   proto_item *item;
   gint curr_bit_offset;

   curr_bit_offset = bit_offset;

   item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_POWER_CONTROL_PARAMS].strptr);
	subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_POWER_CONTROL_PARAMS]);
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_alpha, tvb, curr_bit_offset, 4, FALSE);
   curr_bit_offset += 4;
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_t_avg_w, tvb, curr_bit_offset, 5, FALSE);
   curr_bit_offset += 5;
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_t_avg_t, tvb, curr_bit_offset, 5, FALSE);
   curr_bit_offset += 5;
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pc_meas_chan, tvb, curr_bit_offset, 1, FALSE);
   curr_bit_offset += 1;
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_n_avg_i, tvb, curr_bit_offset, 4, FALSE);
   curr_bit_offset += 4;
   proto_item_set_len(item,((curr_bit_offset-bit_offset)>>3)+1);

   return (curr_bit_offset - bit_offset);
}

static guint8
de_rr_gprs_broadcast_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len , gchar *add_string _U_, int string_len _U_)
{
   guint32 curr_offset;
   gint bit_offset;

   curr_offset = offset;
   bit_offset = curr_offset << 3;

   bit_offset += de_rr_rest_oct_gprs_cell_options(tvb, tree, bit_offset);
   bit_offset += de_rr_rest_oct_gprs_power_control_parameters(tvb, tree, bit_offset);  
   curr_offset += len;

   return (curr_offset - offset);
}

/*
 * [3] 10.5.2.15 Handover Reference
 */
static guint8
de_rr_ho_ref(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	curr_offset = offset;

	item =
		proto_tree_add_text(tree,
			tvb, curr_offset, 1, "%s",
			gsm_rr_elem_strings[DE_RR_HO_REF].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_HO_REF]);

	/* Handover reference value */
	proto_tree_add_item(subtree, hf_gsm_a_rr_ho_ref_val, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.16 IA Rest Octets
 */

static guint8
de_rr_ia_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	len = tvb_length_remaining(tvb,offset);
	if (len==0)
		return 0;

	curr_offset = offset;

	item =
		proto_tree_add_text(tree,
			tvb, curr_offset, len, "%s",
			gsm_rr_elem_strings[DE_RR_IA_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_IA_REST_OCT]);

	proto_tree_add_text(subtree,tvb, curr_offset, len ,"Data(Not decoded)");

	curr_offset = curr_offset + len;

	return curr_offset-offset;
}

/*
 * [3] 10.5.2.17 IAR Rest Octets
 */

static guint8
de_rr_iar_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	len = 3;
	curr_offset = offset;

	item =
	proto_tree_add_text(tree,
		tvb, curr_offset, 3, "%s",
		gsm_rr_elem_strings[DE_RR_IAR_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_IAR_REST_OCT]);

	proto_tree_add_text(subtree,tvb, curr_offset, len ,"Data(Not decoded)");

	curr_offset = curr_offset + len;

	return curr_offset-offset;
}

/*
 * [3] 10.5.2.18 IAX Rest Octets
 */
static guint8
de_rr_iax_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	len = tvb_length_remaining(tvb,offset);
	if (len==0)
		return 0;

	curr_offset = offset;

	item =
	proto_tree_add_text(tree,
		tvb, curr_offset, len, "%s",
		gsm_rr_elem_strings[DE_RR_IAX_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_IAX_REST_OCT]);

	proto_tree_add_text(subtree,tvb, curr_offset, len ,"Data(Not decoded)");

	curr_offset = curr_offset + len;

	return curr_offset-offset;
}

/*
 * [3] 10.5.2.19 L2 Pseudo Length
 */
static guint8
de_rr_l2_pseudo_len(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	curr_offset = offset;

	item = proto_tree_add_text(tree,tvb, curr_offset, 1, "%s", gsm_rr_elem_strings[DE_RR_L2_PSEUDO_LEN].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_L2_PSEUDO_LEN]);

	/* L2 Pseudo Length value */
	proto_tree_add_item(subtree, hf_gsm_a_rr_L2_pseudo_len, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.20 Measurement Results
 */
static const true_false_string gsm_a_rr_dtx_vals  = {
	"DTX was not used",
	"DTX was used"
};

static const value_string gsm_a_rr_rxlev_vals [] = {
	{0, "< -110 dBm"},
	{1, "-110 <= x < -109 dBm"},
	{2, "-109 <= x < -108 dBm"},
	{3, "-108 <= x < -107 dBm"},
	{4, "-107 <= x < -106 dBm"},
	{5, "-106 <= x < -105 dBm"},
	{6, "-105 <= x < -104 dBm"},
	{7, "-104 <= x < -103 dBm"},
	{8, "-103 <= x < -102 dBm"},
	{9, "-102 <= x < -101 dBm"},
	{10, "-101 <= x < -100 dBm"},
	{11, "-100 <= x < -99 dBm"},
	{12, "-99 <= x < -98 dBm"},
	{13, "-98 <= x < -97 dBm"},
	{14, "-97 <= x < -96 dBm"},
	{15, "-96 <= x < -95 dBm"},
	{16, "-95 <= x < -94 dBm"},
	{17, "-94 <= x < -93 dBm"},
	{18, "-93 <= x < -92 dBm"},
	{19, "-92 <= x < -91 dBm"},
	{20, "-91 <= x < -90 dBm"},
	{21, "-90 <= x < -89 dBm"},
	{22, "-89 <= x < -88 dBm"},
	{23, "-88 <= x < -87 dBm"},
	{24, "-87 <= x < -86 dBm"},
	{25, "-86 <= x < -85 dBm"},
	{26, "-85 <= x < -84 dBm"},
	{27, "-84 <= x < -83 dBm"},
	{28, "-83 <= x < -82 dBm"},
	{29, "-82 <= x < -81 dBm"},
	{30, "-81 <= x < -80 dBm"},
	{31, "-80 <= x < -79 dBm"},
	{32, "-79 <= x < -78 dBm"},
	{33, "-78 <= x < -77 dBm"},
	{34, "-77 <= x < -76 dBm"},
	{35, "-76 <= x < -75 dBm"},
	{36, "-75 <= x < -74 dBm"},
	{37, "-74 <= x < -73 dBm"},
	{38, "-73 <= x < -72 dBm"},
	{39, "-72 <= x < -71 dBm"},
	{40, "-71 <= x < -70 dBm"},
	{41, "-70 <= x < -69 dBm"},
	{42, "-69 <= x < -68 dBm"},
	{43, "-68 <= x < -67 dBm"},
	{44, "-67 <= x < -66 dBm"},
	{45, "-66 <= x < -65 dBm"},
	{46, "-65 <= x < -64 dBm"},
	{47, "-64 <= x < -63 dBm"},
	{48, "-63 <= x < -62 dBm"},
	{49, "-62 <= x < -61 dBm"},
	{50, "-61 <= x < -60 dBm"},
	{51, "-60 <= x < -59 dBm"},
	{52, "-59 <= x < -58 dBm"},
	{53, "-58 <= x < -57 dBm"},
	{54, "-57 <= x < -56 dBm"},
	{55, "-56 <= x < -55 dBm"},
	{56, "-55 <= x < -54 dBm"},
	{57, "-54 <= x < -53 dBm"},
	{58, "-53 <= x < -52 dBm"},
	{59, "-52 <= x < -51 dBm"},
	{60, "-51 <= x < -50 dBm"},
	{61, "-50 <= x < -49 dBm"},
	{62, "-49 <= x < -48 dBm"},
	{63, ">= -48 dBm"},
	{ 0, NULL}
};

static const true_false_string gsm_a_rr_mv_vals  = {
	"The measurement results are valid",
	"The measurement results are not valid"
};

static const value_string gsm_a_rr_rxqual_vals [] = {
	{0, "BER < 0.2%, Mean value 0.14%"},
	{1, "0.2% <= BER < 0.4%, Mean value 0.28%"},
	{2, "0.4% <= BER < 0.8%, Mean value 0.57%"},
	{3, "0.8% <= BER < 1.6%, Mean value 1.13%"},
	{4, "1.6% <= BER < 3.2%, Mean value 2.26%"},
	{5, "3.2% <= BER < 6.4%, Mean value 4.53%"},
	{6, "6.4% <= BER < 12.8%, Mean value 9.05%"},
	{7, "BER > 12.8%, Mean value 18.10%"},
	{0, NULL}
};
static const value_string gsm_a_rr_ncell_vals [] = {
	{0, "No neighbour cell measurement result"},
	{1, "1 neighbour cell measurement result"},
	{2, "2 neighbour cell measurement result"},
	{3, "3 neighbour cell measurement result"},
	{4, "4 neighbour cell measurement result"},
	{5, "5 neighbour cell measurement result"},
	{6, "6 neighbour cell measurement result"},
	{7, "Neighbour cell information not available for serving cell"},
	{0, NULL}
};
guint8
de_rr_meas_res(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;
	gint bit_offset;
	guint64 no_ncell_m;

	curr_offset = offset;

	item =
		proto_tree_add_text(tree,
			tvb, curr_offset, 16, "%s",
			gsm_rr_elem_strings[DE_RR_MEAS_RES].strptr);
	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_MEAS_RES]);

	/* 2nd octet */
	/* BA-USED */
	proto_tree_add_item(subtree, hf_gsm_a_rr_ba_used, tvb, curr_offset, 1, FALSE);
	/* DTX USED */
	proto_tree_add_item(subtree, hf_gsm_a_rr_dtx_used, tvb, curr_offset, 1, FALSE);
	/* RXLEV-FULL-SERVING-CELL */
	proto_tree_add_item(subtree, hf_gsm_a_rr_rxlev_full_serv_cell, tvb, curr_offset, 1, FALSE);
	curr_offset++;

	/* 3rd octet */
	/* 3G-BA-USED */ 
	proto_tree_add_item(subtree, hf_gsm_a_rr_3g_ba_used, tvb, curr_offset, 1, FALSE);
	/* MEAS-VALID */
	proto_tree_add_item(subtree, hf_gsm_a_rr_meas_valid, tvb, curr_offset, 1, FALSE);	
	/* RXLEV-SUB-SERVING-CELL */
	proto_tree_add_item(subtree, hf_gsm_a_rr_rxlev_sub_serv_cell, tvb, curr_offset, 1, FALSE);

	curr_offset++;

	/* 4th octet */
	/* RXQUAL-FULL-SERVING-CELL */
	proto_tree_add_item(subtree, hf_gsm_a_rr_rxqual_full_serv_cell, tvb, curr_offset, 1, FALSE);

	/* RXQUAL-SUB-SERVING-CELL */
	proto_tree_add_item(subtree, hf_gsm_a_rr_rxqual_sub_serv_cell, tvb, curr_offset, 1, FALSE);
	/* NO-NCELL-M */
	bit_offset = (curr_offset << 3) + 7;
	proto_tree_add_bits_ret_val(subtree, hf_gsm_a_rr_no_ncell_m, tvb, bit_offset, 3, &no_ncell_m, FALSE);
	bit_offset += 3;
	if (no_ncell_m == 7) /* No neighbour cell information available) */
		no_ncell_m = 0;
	while (no_ncell_m)
	{
		proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rxlev_ncell, tvb, bit_offset, 6, FALSE);
		bit_offset += 6;
		proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bcch_freq_ncell, tvb, bit_offset, 5, FALSE);
		bit_offset += 5;
		proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bsic_ncell, tvb, bit_offset, 6, FALSE);
		bit_offset += 6;
		no_ncell_m -= 1;
	}

	return(len);
}

/*
 * [3] 10.5.2.20a GPRS Measurement Results
 */
/*
 * [3] 10.5.2.21 Mobile Allocation
 */
static guint8
de_rr_mob_all(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
   proto_item *item;
   gint i, j;
   guint8 value;

	curr_offset = offset;

   item = proto_tree_add_text(tree, tvb, curr_offset, len, "Bitmap of increasing ARFCNs included in the Mobile Allocation: ");
   for(i=len; i>0; i--)
   {
      value = tvb_get_guint8(tvb,curr_offset+i-1);
      for (j=0; j<8; j++)
      {
         proto_item_append_text(item,"%d",(value>>j)&0x01);
      }
   }

	curr_offset = curr_offset + len;
	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.21a Mobile Time Difference
 */
static guint8
de_rr_mob_time_diff(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_mobile_time_difference, tvb, curr_offset, len, FALSE);

	curr_offset = curr_offset + len;
	return(curr_offset - offset);

}
/*
 * [3] 10.5.2.21aa MultiRate configuration
 */
/*	Multirate speech version Octet 3 Bits 8 7 6 */
static const value_string multirate_speech_ver_vals[] = {
	{ 1,	"Adaptive Multirate speech version 1"},
	{ 2,	"Adaptive Multirate speech version 2"},
	{ 0,	NULL }
};
/* Bit	5 	NSCB: Noise Suppression Control Bit */
static const value_string NSCB_vals[] = {
	{ 0,	"Noise Suppression can be used (default)"},
	{ 1,	"Noise Suppression shall be turned off"},
	{ 0,	NULL }
};
/* Bit	4	ICMI: Initial Codec Mode Indicator */
static const value_string ICMI_vals[] = {
	{ 0,	"The initial codec mode is defined by the implicit rule provided in 3GPP TS 05.09"},
	{ 1,	"The initial codec mode is defined by the Start Mode field"},
	{ 0,	NULL }
};
/*
Table 10.5.2.21aa.2: Set of adaptive multirate codec modes field (octet 4)
for the Multirate speech version 1
*/
static const true_false_string gsm_a_rr_set_of_amr_codec_modes  = {
	"is part of the subset",
	"is not part of the subset"
};

static const value_string gsm_a_rr_amr_threshold_vals[] = {
	{ 0,	"0.0 dB"},
	{ 1,	"0.5 dB"},
	{ 2,	"1.0 dB"},
	{ 3,	"1.5 dB"},
	{ 4,	"2.0 dB"},
	{ 5,	"2.5 dB"},
	{ 6,	"3.0 dB"},
	{ 7,	"3.5 dB"},
	{ 8,	"4.0 dB"},
	{ 9,	"4.5 dB"},
	{ 10,	"5.0 dB"},
	{ 11,	"5.5 dB"},
	{ 12,	"6.0 dB"},
	{ 13,	"6.5 dB"},
	{ 14,	"7.0 dB"},
	{ 15,	"7.5 dB"},
	{ 16,	"8.0 dB"},
	{ 17,	"8.5 dB"},
	{ 18,	"9.0 dB"},
	{ 19,	"9.5 dB"},
	{ 20,	"10.0 dB"},
	{ 21,	"10.5 dB"},
	{ 22,	"11.0 dB"},
	{ 23,	"11.5 dB"},
	{ 24,	"12.0 dB"},
	{ 25,	"12.5 dB"},
	{ 26,	"13.0 dB"},
	{ 27,	"13.5 dB"},
	{ 28,	"14.0 dB"},
	{ 29,	"14.5 dB"},
	{ 30,	"15.0 dB"},
	{ 31,	"15.5 dB"},
	{ 32,	"16.0 dB"},
	{ 33,	"16.5 dB"},
	{ 34,	"17.0 dB"},
	{ 35,	"17.5 dB"},
	{ 36,	"18.0 dB"},
	{ 37,	"18.5 dB"},
	{ 38,	"19.0 dB"},
	{ 39,	"19.5 dB"},
	{ 40,	"20.0 dB"},
	{ 41,	"20.5 dB"},
	{ 42,	"21.0 dB"},
	{ 43,	"21.5 dB"},
	{ 44,	"22.0 dB"},
	{ 45,	"22.5 dB"},
	{ 46,	"23.0 dB"},
	{ 47,	"23.5 dB"},
	{ 48,	"24.0 dB"},
	{ 49,	"24.5 dB"},
	{ 50,	"25.0 dB"},
	{ 51,	"25.5 dB"},
	{ 52,	"26.0 dB"},
	{ 53,	"26.5 dB"},
	{ 54,	"27.0 dB"},
	{ 55,	"27.5 dB"},
	{ 56,	"28.0 dB"},
	{ 57,	"28.5 dB"},
	{ 58,	"29.0 dB"},
	{ 59,	"29.5 dB"},
	{ 60,	"30.0 dB"},
	{ 61,	"30.5 dB"},
	{ 62,	"31.0 dB"},
	{ 63,	"31.5 dB"},
	{ 0,	NULL }
};

static const value_string gsm_a_rr_amr_hysteresis_vals[] = {
	{ 0,	"0.0 dB"},
	{ 1,	"0.5 dB"},
	{ 2,	"1.0 dB"},
	{ 3,	"1.5 dB"},
	{ 4,	"2.0 dB"},
	{ 5,	"2.5 dB"},
	{ 6,	"3.0 dB"},
	{ 7,	"3.5 dB"},
	{ 8,	"4.0 dB"},
	{ 9,	"4.5 dB"},
	{ 10,	"5.0 dB"},
	{ 11,	"5.5 dB"},
	{ 12,	"6.0 dB"},
	{ 13,	"6.5 dB"},
	{ 14,	"7.0 dB"},
	{ 15,	"7.5 dB"},
	{ 0,	NULL }
};

guint8
de_rr_multirate_conf(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 oct;
   gint bit_offset, remaining_length, nb_of_params;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_multirate_speech_ver, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_NCSB, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_ICMI, tvb, curr_offset, 1, FALSE);
	/* The initial codec mode is coded as in 3GPP TS 45.009 */
	proto_tree_add_item(tree, hf_gsm_a_rr_start_mode, tvb, curr_offset, 1, FALSE);
	oct = ( tvb_get_guint8(tvb,curr_offset) &0xe0 ) >> 5;
	curr_offset++;
	switch ( oct){
	case 1:
		/* Adaptive Multirate speech version 1 */
		/* Set of AMR codec modes */
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b8, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b7, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b6, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b5, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b4, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b3, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b2, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b1, tvb, curr_offset, 1, FALSE);
		curr_offset++;

		remaining_length = len-2;
		break;
	case 2:
		/* Adaptive Multirate speech version 2 */
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b5, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b4, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b3, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b2, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b1, tvb, curr_offset, 1, FALSE);
		curr_offset++;

		remaining_length = len-2;
		break;
	default:
		proto_tree_add_text(tree,tvb,offset,1,"Unknown version");
		proto_tree_add_text(tree,tvb, curr_offset, len-1 ,"Data(Not decoded)");
		remaining_length = 0;
		break;
	}

   if (remaining_length)
   {
	   bit_offset = (curr_offset<<3) + 2;
      nb_of_params = remaining_length - 1;
      while (nb_of_params)
      {
         proto_tree_add_bits_item(tree, hf_gsm_a_rr_amr_threshold, tvb, bit_offset, 6, FALSE);
         bit_offset += 6;
         proto_tree_add_bits_item(tree, hf_gsm_a_rr_amr_hysteresis, tvb, bit_offset, 4, FALSE);
         bit_offset += 4;
         nb_of_params -= 1;
      }
   }

	curr_offset = offset + len;
	return(curr_offset - offset);

}
/*
 * [3] 10.5.2.21b Multislot Allocation
 */
static guint8
de_rr_mult_all(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, len ,"Data(Not decoded)");

	curr_offset = curr_offset + len;
	return(curr_offset - offset);

}
/*
 * [3] 10.5.2.21c NC mode
 */

 /*
 * [3] 10.5.2.22 Neighbour Cell Description
 */
static const value_string gsm_a_rr_ext_ind_vals[] = {
	{ 0,	"The information element carries the complete BA"},
	{ 1,	"The information element carries only a part of the BA"},
	{ 0,	NULL }
};
static guint8
de_rr_neigh_cell_desc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_ext_ind, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_ba_ind, tvb, curr_offset, 1, FALSE);

	return dissect_arfcn_list(tvb, tree, offset, 16, add_string, string_len);
}

 /*
 * [3] 10.5.2.22a Neighbour Cell Description 2
 */
static guint8
de_rr_neigh_cell_desc2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

   proto_tree_add_bits_item(tree, hf_gsm_a_rr_multiband_reporting, tvb, (curr_offset<<3)+1, 2, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_ba_ind, tvb, curr_offset, 1, FALSE);

	return dissect_arfcn_list(tvb, tree, offset, 16, add_string, string_len);
}

/*
 * [3] 10.5.2.22b (void)
 * [3] 10.5.2.22c NT/N Rest Octets
 * [3] 10.5.2.23 P1 Rest Octets
 * [3] 10.5.2.24 P2 Rest Octets
 * [3] 10.5.2.25 P3 Rest Octets
 */
/*
 * [3] 10.5.2.25a Packet Channel Description C V 3
 */
static guint8
de_rr_packet_ch_desc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8	oct8;
	guint16	arfcn, hsn, maio;
	proto_tree	*subtree;
	proto_item	*item;
	const gchar *str;

	curr_offset = offset;

	item = proto_tree_add_text(tree,tvb,curr_offset,3, "%s", gsm_rr_elem_strings[DE_RR_PACKET_CH_DESC].strptr);
	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_PACKET_CH_DESC]);

	/* Octet 2 */
	oct8 = tvb_get_guint8(tvb, curr_offset);
	/* Channel Type */
	str = "Spare bits (ignored by receiver)";
	other_decode_bitfield_value(a_bigbuf, oct8, 0xf8, 8);
	proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = %s",a_bigbuf,str);
	/* TN */
	other_decode_bitfield_value(a_bigbuf, oct8, 0x07, 8);
	proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Timeslot: %d",a_bigbuf,(oct8 & 0x07));

	curr_offset +=1;
	
	/* Octet 3 */
	oct8 = tvb_get_guint8(tvb, curr_offset);
	other_decode_bitfield_value(a_bigbuf, oct8, 0xe0, 8);
	proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Training Sequence: %d",a_bigbuf,((oct8 & 0xe0)>>5));
	
	if ((oct8 & 0x10) == 0x10)
	{
		/* Hopping sequence */
		maio = ((oct8 & 0x0f)<<2) | ((tvb_get_guint8(tvb,curr_offset+1) & 0xc0) >> 6);
		hsn = (tvb_get_guint8(tvb,curr_offset+1) & 0x3f);
		str = "Yes";

		other_decode_bitfield_value(a_bigbuf, oct8, 0x10, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Hopping channel: %s",a_bigbuf,str);
		proto_tree_add_text(subtree,tvb, curr_offset, 2,"Hopping channel: MAIO %d",maio);
		proto_tree_add_text(subtree,tvb, curr_offset, 2,"Hopping channel: HSN %d",hsn);
	}
	else
	{
		/* single ARFCN */
		arfcn = ((oct8 & 0x03) << 8) | tvb_get_guint8(tvb,curr_offset+1);
		str = "No";
		other_decode_bitfield_value(a_bigbuf, oct8, 0x10, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Hopping channel: %s",a_bigbuf,str);
		other_decode_bitfield_value(a_bigbuf, oct8, 0x0c, 8);
		proto_tree_add_text(subtree,tvb, curr_offset, 1,"%s = Spare",a_bigbuf);
		proto_tree_add_text(subtree,tvb, curr_offset, 2,"Single channel : ARFCN %d",arfcn);
	}

	curr_offset = curr_offset + 2;
	return(curr_offset - offset);

}
/*
 * [3] 10.5.2.25b Dedicated mode or TBF
 */

static const value_string gsm_a_rr_dedicated_mode_or_tbf_vals[] = {
	{ 0,	"This message assigns a dedicated mode resource"},
	{ 1,	"This message assigns an uplink TBF or is the second message of two in a two-message assignment of an uplink or downlink TBF"},
	{ 2,	"Not used"},
	{ 3,	"This message assigns a downlink TBF to the mobile station identified in the IA Rest Octets IE"},
	{ 4,	"Not used"},
	{ 5,	"This message is the first message of two in a two-message assignment of an uplink TBF"},
	{ 6,	"Not used"},
	{ 7,	"This message is the first message of two in a two-message assignment of a downlink TBF to the mobile station identified in the IA Rest Octets IE"},
	{ 0,	NULL }
};
static guint8
de_rr_ded_mod_or_tbf(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	curr_offset = offset;

	item =
		proto_tree_add_text(tree,
			tvb, curr_offset, 1, "%s",
			gsm_rr_elem_strings[DE_RR_DED_MOD_OR_TBF].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_DED_MOD_OR_TBF]);

	proto_tree_add_item(subtree, hf_gsm_a_rr_dedicated_mode_or_tbf, tvb, curr_offset, 1, FALSE);

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.25c RR Packet Uplink Assignment
 * [3] 10.5.2.25d RR Packet Downlink Assignment
 */
/*
 * [3] 10.5.2.26 Page Mode
 */

static const value_string gsm_a_rr_page_mode_vals[] = {
	{ 0,	"Normal paging"},
	{ 1,	"Extended paging"},
	{ 2,	"Paging reorganization"},
	{ 3,	"Same as before"},
	{ 0,	NULL }
};
static guint8
de_rr_page_mode(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	curr_offset = offset;

	item =
		proto_tree_add_text(tree,
			tvb, curr_offset, 1, "%s",
			gsm_rr_elem_strings[DE_RR_PAGE_MODE].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_PAGE_MODE]);

	proto_tree_add_item(subtree, hf_gsm_a_rr_page_mode, tvb, curr_offset, 1, FALSE);

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.26a (void)
 * [3] 10.5.2.26b (void)
 * [3] 10.5.2.26c (void)
 * [3] 10.5.2.26d (void)
 */
/*
 * [3] 10.5.2.27 NCC Permitted
 */
static guint8
de_rr_ncc_perm(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	curr_offset = offset;

	item = proto_tree_add_text(tree, tvb, curr_offset, 1, "%s",
		gsm_rr_elem_strings[DE_RR_NCC_PERM].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_NCC_PERM]);

	proto_tree_add_item(subtree, hf_gsm_a_rr_ncc_permitted, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.28 Power Command
 *
 *
 * ATC (Access Type Control) (octet 2)Bit 8
 * 0	Sending of Handover access is mandatory
 * 1	Sending of Handover access is optional
 */
static const true_false_string gsm_a_rr_pow_cmd_atc_value  = {
	"Sending of Handover access is optional",
	"Sending of Handover access is mandatory"
};
/*
 *  The EPC mode field (octet 2) indicates whether the assigned channel(s)
 *  shall be in enhanced power control (EPC) mode. It is only valid for channels
 *  on which EPC may be used. It is coded as follows:
*/
static const true_false_string gsm_a_rr_pow_cmd_epc_value  = {
	"Channel(s) in EPC mode",
	"Channel(s) not in EPC mode"
};
/*
 * FPC_EPC (octet 2)
 * The FPC_EPC field (octet 2) has different interpretation depending
 *		on the channel mode	of the assigned channel (s) and the value
 *		of the EPC mode field.
 * If the channel mode is such that fast power control (FPC) may be
 *		used, the FPC_EPC field indicates whether Fast Measurement
 *		Reporting and Power Control mechanism is used.
 *		It is coded as follows:
 * Value 0	FPC not in use
 *	   1	FPC in use
 * If the channel mode is such that EPC may be used and the EPC mode
 *		field indicates that the channel is in EPC mode, the FPC_EPC
 *		field indicates whether EPC shall be used for uplink power control.
 * It is coded as follows:
 * Value 0	EPC not in use for uplink power control
 *		 1	EPC in use for uplink power control
 *
 */
static const true_false_string gsm_a_rr_pow_cmd_fpcepc_value  = {
	"FPC in use/EPC in use for uplink power control",
	"FPC not in use/C not in use for uplink power control"
};

/*
 * Power level (octet 2)The power level field is coded as the binaryRepresentation
 * of the "power control level", see 3GPP TS 3GPP TS 45.005. This value shall be used
 * by the mobile station According to 3GPP TS 45.008.Range: 0 to 31.
 */

static guint8
de_rr_pow_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	curr_offset = offset;

	item =
		proto_tree_add_text(tree,
			tvb, curr_offset, 1, "%s",
			gsm_rr_elem_strings[DE_RR_POW_CMD].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_POW_CMD]);

	proto_tree_add_item(subtree, hf_gsm_a_b8spare, tvb, curr_offset, 1, FALSE);
	/*EPC mode */
	proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_epc, tvb, curr_offset, 1, FALSE);
	/*FPC_EPC*/
	proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_fpcepc, tvb, curr_offset, 1, FALSE);
	/*POWER LEVEL*/
	proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_powlev, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.28a Power Command and access type
 */
static guint8
de_rr_pow_cmd_and_acc_type(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	curr_offset = offset;

	item =
		proto_tree_add_text(tree,
			tvb, curr_offset, 1, "%s",
			gsm_rr_elem_strings[DE_RR_POW_CMD_AND_ACC_TYPE].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_POW_CMD_AND_ACC_TYPE]);

	/*ATC */
	proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_atc, tvb, curr_offset, 1, FALSE);
	/*EPC mode */
	proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_epc, tvb, curr_offset, 1, FALSE);
	/*FPC_EPC*/
	proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_fpcepc, tvb, curr_offset, 1, FALSE);
	/*POWER LEVEL*/
	proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_powlev, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.29 RACH Control Parameters
 */

static const value_string gsm_a_rr_max_retrans_vals[] = {
	{ 0,	"Maximum 1 retransmission"},
	{ 1,	"Maximum 2 retransmissions"},
	{ 2,	"Maximum 4 retransmissions"},
	{ 3,	"Maximum 7 retransmissions"},
	{ 0,	NULL }
};

static const value_string gsm_a_rr_tx_integer_vals[] = {
	{ 0,	"3 slots used to spread transmission"},
	{ 1,	"4 slots used to spread transmission"},
	{ 2,	"5 slots used to spread transmission"},
	{ 3,	"6 slots used to spread transmission"},
	{ 4,	"7 slots used to spread transmission"},
	{ 5,	"8 slots used to spread transmission"},
	{ 6,	"9 slots used to spread transmission"},
	{ 7,	"10 slots used to spread transmission"},
	{ 8,	"11 slots used to spread transmission"},
	{ 9,	"12 slots used to spread transmission"},
	{ 10,	"14 slots used to spread transmission"},
	{ 11,	"16 slots used to spread transmission"},
	{ 12,	"20 slots used to spread transmission"},
	{ 13,	"25 slots used to spread transmission"},
	{ 14,	"32 slots used to spread transmission"},
	{ 15,	"50 slots used to spread transmission"},
	{ 0,	NULL }
};
static const value_string gsm_a_rr_cell_barr_access_vals[] = {
	{ 0,	"The cell is not barred"},
	{ 1,	"The cell is barred"},
	{ 0,	NULL }
};
static const value_string gsm_a_rr_re_vals[] = {
	{ 0,	"Call Reestablishment allowed in the cell"},
	{ 1,	"Call Reestablishment not allowed in the cell"},
	{ 0,	NULL }
};

static guint8
de_rr_rach_ctrl_param(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	curr_offset = offset;

	item = proto_tree_add_text(tree, tvb, curr_offset, 3, "%s",
		gsm_rr_elem_strings[DE_RR_RACH_CTRL_PARAM].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_RACH_CTRL_PARAM]);

	proto_tree_add_item(subtree, hf_gsm_a_rr_max_retrans, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_tx_integer, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_cell_barr_access, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_re, tvb, curr_offset, 1, FALSE);
	curr_offset = curr_offset + 1;

	proto_tree_add_item(subtree, hf_gsm_a_rr_acc, tvb, curr_offset, 2, FALSE);

	curr_offset = curr_offset + 2;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.30 Request Reference M V 3
 */
static guint16 reduced_frame_number(guint16 fn)
{
	/* great care needed with signed/unsigned - -1 in unsigned is 0xffff, which mod(26) is not what you think !!! */
	gint16	t2, t3, t;
	guint16	frame, t1;

	t1 = (fn >> 11) & 0x1f;
	t2 = (fn >> 0) & 0x1f;
	t3 = (fn >> 5) & 0x3f;

	t = (t3-t2)%26;
	if (t<0)
		t += 26;

	frame = 51*(unsigned)t+(unsigned)t3+51*26*t1;

	return frame;
}

static guint8
de_rr_req_ref(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;
	guint16	rfn;
	guint16	fn;

	curr_offset = offset;

	item =
		proto_tree_add_text(tree,
			tvb, curr_offset, 3, "%s",
			gsm_rr_elem_strings[DE_RR_REQ_REF].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_REQ_REF]);

	proto_tree_add_item(subtree, hf_gsm_a_rr_ra, tvb, curr_offset, 1, FALSE);
	curr_offset++;
	fn = tvb_get_ntohs(tvb,curr_offset);
	rfn = reduced_frame_number(fn);
	proto_tree_add_item(subtree, hf_gsm_a_rr_T1prim, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_T3, tvb, curr_offset, 2, FALSE);
	curr_offset++;
	proto_tree_add_item(subtree, hf_gsm_a_rr_T2, tvb, curr_offset, 1, FALSE);
	curr_offset++;
	proto_tree_add_uint(subtree, hf_gsm_a_rr_rfn, tvb, curr_offset-2, 2, rfn);

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.31
 */
guint8
de_rr_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_RR_cause, tvb, curr_offset, 1, FALSE);

	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.32 SI 1 Rest Octets
 */
static const value_string gsm_a_rr_nch_position_vals[] = {
	{ 0,	"No of blocks = 1 and Number of first block = 0"},
	{ 1,	"No of blocks = 1 and Number of first block = 1"},
	{ 2,	"No of blocks = 1 and Number of first block = 2"},
	{ 3,	"No of blocks = 1 and Number of first block = 3"},
	{ 4,	"No of blocks = 1 and Number of first block = 4"},
	{ 5,	"No of blocks = 1 and Number of first block = 5"},
	{ 6,	"No of blocks = 1 and Number of first block = 6"},
	{ 7,	"No of blocks = 1 and Number of first block = 0"},
	{ 8,	"No of blocks = 2 and Number of first block = 1"},
	{ 9,	"No of blocks = 2 and Number of first block = 2"},
	{10,	"No of blocks = 2 and Number of first block = 3"},
	{11,	"No of blocks = 2 and Number of first block = 4"},
	{12,	"No of blocks = 2 and Number of first block = 5"},
	{13,	"No of blocks = 3 and Number of first block = 0"},
	{14,	"No of blocks = 3 and Number of first block = 1"},
	{15,	"No of blocks = 3 and Number of first block = 2"},
	{16,	"No of blocks = 3 and Number of first block = 3"},
	{17,	"No of blocks = 3 and Number of first block = 4"},
	{18,	"No of blocks = 4 and Number of first block = 0"},
	{19,	"No of blocks = 4 and Number of first block = 1"},
	{20,	"No of blocks = 4 and Number of first block = 2"},
	{21,	"No of blocks = 4 and Number of first block = 3"},
	{22,	"No of blocks = 5 and Number of first block = 0"},
	{23,	"No of blocks = 5 and Number of first block = 1"},
	{24,	"No of blocks = 5 and Number of first block = 2"},
	{25,	"No of blocks = 6 and Number of first block = 0"},
	{26,	"No of blocks = 6 and Number of first block = 1"},
	{27,	"No of blocks = 7 and Number of first block = 0"},
	{28,	"Reserved"},
	{29,	"Reserved"},
	{30,	"Reserved"},
	{31,	"Reserved"},
	{ 0,	NULL }
};

static guint8
de_rr_si1_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;
   gint bit_offset;

	len = 1;
	curr_offset = offset;
   bit_offset = curr_offset << 3;

	item = proto_tree_add_text(tree, tvb, curr_offset, len, "%s",
		gsm_rr_elem_strings[DE_RR_SI1_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_SI1_REST_OCT]);

   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   {
      bit_offset += 1;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_nch_position, tvb, bit_offset, 5, FALSE);
      bit_offset += 5;
   }
   else
   {
      proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "NCH position: not present");
      bit_offset += 1;
   }
   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
      proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "Band Indicator: 1900");
   else
      proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "Band Indicator: 1800");
   bit_offset += 1;

	curr_offset = curr_offset + len;

	return curr_offset-offset;
}

/*
 * [3] 10.5.2.33 SI 2bis Rest Octets
 */

/*
 * [3] 10.5.2.33a SI 2ter Rest Octets
 */
static const value_string gsm_a_rr_qsearch_x_vals[] = {
	{ 0,	"-98 dBm"},
	{ 1,	"-94 dBm"},
	{ 2,	"-90 dBm"},
	{ 3,	"-86 dBm"},
	{ 4,	"-82 dBm"},
	{ 5,	"-78 dBm"},
	{ 6,	"-74 dBm"},
	{ 7,	"Always"},
	{ 8,	"-78 dBm"},
	{ 9,	"-74 dBm"},
	{10,	"-70 dBm"},
	{11,	"-66 dBm"},
	{12,	"-62 dBm"},
	{13,	"-58 dBm"},
	{14,	"-54 dBm"},
	{15,	"Never"},
	{ 0,	NULL }
};

static const value_string gsm_a_rr_xdd_qoffset_vals[] = {
	{ 0,	"always select a cell if acceptable"},
	{ 1,	"-28 dB"},
	{ 2,	"-24 dB"},
	{ 3,	"-20 dB"},
	{ 4,	"-16 dB"},
	{ 5,	"-12 dB"},
	{ 6,	"-8 dB"},
	{ 7,	"-4 dB"},
	{ 8,	"0 dB"},
	{ 9,	"4 dB"},
	{10,	"8 dB"},
	{11,	"12 dB"},
	{12,	"16 dB"},
	{13,	"20 dB"},
	{14,	"24 dB"},
	{15,	"28 dB"},
	{ 0,	NULL }
};

static const value_string gsm_a_rr_fdd_qmin_vals[] = {
	{ 0,	"-20 dB"},
	{ 1,	"-6 dB"},
	{ 2,	"-18 dB"},
	{ 3,	"-8 dB"},
	{ 4,	"-16 dB"},
	{ 5,	"-10 dB"},
	{ 6,	"-14 dB"},
	{ 7,	"-12 dB"},
	{ 0,	NULL }
};

static const value_string gsm_a_rr_fdd_qmin_offset_vals[] = {
	{ 0,	"0 dB"},
	{ 1,	"2 dB"},
	{ 2,	"4 dB"},
	{ 3,	"6 dB"},
	{ 4,	"8 dB"},
	{ 5,	"10 dB"},
	{ 6,	"12 dB"},
	{ 7,	"14 dB"},
	{ 0,	NULL }
};

static const value_string gsm_a_rr_fdd_rscpmin_vals[] = {
	{ 0,	"-114 dBm"},
	{ 1,	"-112 dBm"},
	{ 2,	"-110 dBm"},
	{ 3,	"-108 dBm"},
	{ 4,	"-106 dBm"},
	{ 5,	"-104 dBm"},
	{ 6,	"-102 dBm"},
	{ 7,	"-100 dBm"},
	{ 8,	"-98 dBm"},
	{ 9,	"-96 dBm"},
	{10,	"-94 dBm"},
	{11,	"-92 dBm"},
	{12,	"-90 dBm"},
	{13,	"-88 dBm"},
	{14,	"-86 dBm"},
	{15,	"-84 dBm"},
	{ 0,	NULL }
};

static guint8
de_rr_si2ter_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree, *subtree2;
	proto_item	*item, *item2;
	guint32	curr_offset;
   gint bit_offset, bit_offset_sav;
   guint8 value;

	len = 4;
	curr_offset = offset;
   bit_offset = curr_offset<<3;

	item = proto_tree_add_text(tree, tvb, curr_offset, len, "%s",
		gsm_rr_elem_strings[DE_RR_SI2TER_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_SI2TER_REST_OCT]);

   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   {
      bit_offset += 1;
	   proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "SI2ter Rest Octet Measurement Parameter Change Mark: %d", tvb_get_bits8(tvb,bit_offset,1));
      bit_offset += 1;
	   proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "SI2ter Rest Octet 3G Change Mark: %d", tvb_get_bits8(tvb,bit_offset,1));
      bit_offset += 1;
      proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "SI2ter Index: %d", tvb_get_bits8(tvb,bit_offset,3));
      bit_offset += 3;
      proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "SI2ter Count: %d", tvb_get_bits8(tvb,bit_offset,3));
      bit_offset += 3;
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      { /* UTRAN FDD Description */
         bit_offset_sav = bit_offset;
         item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_FDD_DESC].strptr);
         subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_UTRAN_FDD_DESC]);
         bit_offset += 2; /* skip '01' bits */
         proto_tree_add_text(subtree2,tvb, bit_offset>>3, 2, "FDD UARFCN: %d", tvb_get_bits16(tvb,bit_offset,14,FALSE));
         bit_offset += 14;
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         if (value)
         {
            proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "Bandwidth FDD: %d", tvb_get_bits8(tvb,bit_offset,3));
            bit_offset += 3;
         }
         proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      { /* UTRAN TDD Description */
         bit_offset_sav = bit_offset;
         item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_TDD_DESC].strptr);
         subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_UTRAN_TDD_DESC]);
         bit_offset += 2; /* skip '01' bits */
         proto_tree_add_text(subtree2,tvb, bit_offset>>3, 2, "TDD UARFCN: %d", tvb_get_bits16(tvb,bit_offset,14,FALSE));
         bit_offset += 14;
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         if (value)
         {
            proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "Bandwidth TDD: %d", tvb_get_bits8(tvb,bit_offset,3));
            bit_offset += 3;
         }
         proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      { /* 3G Measurement Parameters Description */
         bit_offset_sav = bit_offset;
         item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_MEAS_PARAM_DESC].strptr);
         subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_MEAS_PARAM_DESC]);
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_qsearch_i, tvb, bit_offset, 4, FALSE);
         bit_offset += 4;
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         if (value)
         {
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_qoffset, tvb, bit_offset, 4, FALSE);
            bit_offset += 4;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_qmin, tvb, bit_offset, 3, FALSE);
            bit_offset += 3;
         }
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         if (value)
         {
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_qoffset, tvb, bit_offset, 4, FALSE);
            bit_offset += 4;
         }
         proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
      }
      if (((curr_offset + len)<<3) - bit_offset > 0)
      {
         /* There is still room left in the Rest Octets IE */
         if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
         { /* Additions in release R5 */
            bit_offset += 1;
            value = tvb_get_bits8(tvb,bit_offset,1);
            bit_offset += 1;
            if (value)
            { /* 3G Additional Measurement Parameters Description */
               bit_offset_sav = bit_offset;
               item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC].strptr);
               subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC]);
               proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_qmin_offset, tvb, bit_offset, 3, FALSE);
               bit_offset += 3;
               proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_rscpmin, tvb, bit_offset, 4, FALSE);
               bit_offset += 4;
               proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
            }
         }
         else
            bit_offset += 1;
      }
   }
   else
   {
      bit_offset += 1;
      proto_tree_add_text(subtree,tvb, curr_offset, len ,"Empty");
   }

	curr_offset = curr_offset + len;

	return curr_offset-offset;
}

/*
 * [3] 10.5.2.33b SI 2quater Rest Octets
 */
static const true_false_string gsm_a_rr_gsm_report_type_value = {
	"The MS shall use the Measurement Report message for reporting",
	"The MS shall use the Enhanced Measurement Report message for reporting if at least one BSIC is allocated to each BA (list) frequency. Otherwise, the Measurement Report message shall be used"
};

static const true_false_string gsm_a_rr_frequency_scrolling_value = {
	"Next BSIC in the structure relates to the subsequent frequency in the BA(list)",
	"Next BSIC in the structure relates to the same frequency in the BA(list)"
};

static const true_false_string gsm_a_rr_rep_priority_value = {
	"High reporting priority",
	"Normal reporting priority"
};

static const true_false_string gsm_a_rr_report_type_value = {
	"The MS shall use the PACKET MEASUREMENT REPORT message for reporting",
	"The MS shall use the PACKET ENHANCED MEASUREMENT REPORT message for reporting"
};

static const true_false_string gsm_a_rr_reporting_rate_value = {
	"Reduced reporting rate allowed",
	"Normal reporting rate"
};

static const true_false_string gsm_a_rr_invalid_bsic_reporting_value = {
	"High reporting priority",
	"Normal reporting priority"
};

static const value_string gsm_a_rr_scale_ord_vals[] = {
	{ 0, "An offset of 0 dB shall be used for the reported RXLEV values"},
	{ 1, "An offset of 10 dB shall be used for the reported RXLEV values"},
	{ 2, "An automatic offset shall be used for the reported RXLEV values"},
	{ 0, NULL }
};

static const value_string gsm_a_rr_xxx_reporting_offset_vals[] = {
	{ 0, "Apply an offset of 0 dB to the reported value when prioritising the cells for reporting"},
	{ 1, "Apply an offset of 6 dB to the reported value when prioritising the cells for reporting"},
	{ 2, "Apply an offset of 12 dB to the reported value when prioritising the cells for reporting"},
	{ 3, "Apply an offset of 18 dB to the reported value when prioritising the cells for reporting"},
	{ 4, "Apply an offset of 24 dB to the reported value when prioritising the cells for reporting"},
	{ 5, "Apply an offset of 30 dB to the reported value when prioritising the cells for reporting"},
	{ 6, "Apply an offset of 36 dB to the reported value when prioritising the cells for reporting"},
	{ 7, "Apply an offset of 42 dB to the reported value when prioritising the cells for reporting"},
	{ 0, NULL }
};

static const value_string gsm_a_rr_xxx_reporting_threshold_vals[] = {
	{ 0, "Apply priority reporting if the reported value is above 0 dB"},
	{ 1, "Apply priority reporting if the reported value is above 6 dB"},
	{ 2, "Apply priority reporting if the reported value is above 12 dB"},
	{ 3, "Apply priority reporting if the reported value is above 18 dB"},
	{ 4, "Apply priority reporting if the reported value is above 24 dB"},
	{ 5, "Apply priority reporting if the reported value is above 30 dB"},
	{ 6, "Apply priority reporting if the reported value is above 36 dB"},
	{ 7, "Never apply priority reporting"},
	{ 0, NULL }
};

static const value_string gsm_a_rr_network_control_order_vals[] = {
   { 0, "NC0"},
   { 1, "NC1"},
   { 2, "NC2"},
   { 3, "NC0"},
   { 0, NULL }
};

static const value_string gsm_a_rr_nc_non_drx_period_vals[] = {
   { 0, "No non-DRX mode after a measurement report has been sent"},
   { 1, "0,24 s"},
   { 2, "0,48 s"},
   { 3, "0.72 s"},
   { 4, "0.96 s"},
   { 5, "1.20 s"},
   { 6, "1.44 s"},
   { 7, "1.92 s"},
   { 0, NULL }
};

static const value_string gsm_a_rr_nc_reporting_period_x_vals[] = {
   { 0, "0.48 s"},
   { 1, "0.96 s"},
   { 2, "1.92 s"},
   { 3, "3.84 s"},
   { 4, "7.68 s"},
   { 5, "15.36 s"},
   { 6, "30.72 s"},
   { 7, "61.44 s"},
   { 0, NULL }
};

static const true_false_string gsm_a_rr_qsearch_c_initial_value = {
	"Always",
	"use Qsearch I"
};

static const true_false_string gsm_a_rr_fdd_rep_quant_value = {
	"Ec/No",
	"RSCP"
};

static const true_false_string gsm_a_rr_3g_search_prio_value = {
	"3G cells may be searched when BSIC decoding is required",
	"3G cells may not be searched when BSIC decoding is required"
};

static const true_false_string gsm_a_rr_3g_ccn_active_value = {
	"CCN towards 3G cells is enabled in the cell",
	"CCN towards 3G cells is disabled in the cell"
};

static const guint8
convert_n_to_p[32] = {   0, 10, 19, 28, 26, 44, 52, 60, 67, 74, 81, 88, 95, 102, 109, 116,
                       122,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,   0,   0,   0};

static const guint8
convert_n_to_q[32] = {   0,   9,  17,  25,  32, 39, 46, 53, 59, 65, 71, 77, 83, 89, 95, 101,
                       106, 111, 116, 121, 126,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,   0};

static guint8
de_rr_si2quater_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree, *subtree2, *subtree3, *subtree4;
	proto_item	*item, *item2, *item3, *item4;
	guint32	curr_offset;
   gint bit_offset, bit_offset_sav, bit_offset_sav2, idx;
   guint8 value;
   gint xdd_cell_info, wsize, nwi, jwi, w[64], i, iused, xdd_indic0;

	len = 20;
	curr_offset = offset;
   bit_offset = curr_offset<<3;

	item = proto_tree_add_text(tree, tvb, curr_offset, len, "%s",
		gsm_rr_elem_strings[DE_RR_SI2QUATER_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_SI2QUATER_REST_OCT]);

   proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "BA Ind: %d", tvb_get_bits8(tvb,bit_offset,1));
   bit_offset += 1;
   proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "3G BA Ind: %d", tvb_get_bits8(tvb,bit_offset,1));
   bit_offset += 1;
   proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "MP Change Mark: %d", tvb_get_bits8(tvb,bit_offset,1));
   bit_offset += 1;
   proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "SI2quater Index: %d", tvb_get_bits8(tvb,bit_offset,4));
   bit_offset += 4;
   proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "SI2quater Count: %d", tvb_get_bits8(tvb,bit_offset,4));
   bit_offset += 4;
   value = tvb_get_bits8(tvb,bit_offset,1);
   bit_offset += 1;
   if (value)
   { /* Measurement Parameters Description */
      bit_offset_sav = bit_offset;
      item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_MEAS_PARAM_DESC].strptr);
      subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_MEAS_PARAM_DESC]);
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_gsm_report_type, tvb, bit_offset, 1, FALSE);
      bit_offset += 1;
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_serving_band_reporting, tvb, bit_offset, 2, FALSE);
      bit_offset += 2;
      proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
   }
   value  = tvb_get_bits8(tvb,bit_offset,1);
   bit_offset += 1;
   if (value)
   { /* GPRS Real Time Difference Description */
      bit_offset_sav = bit_offset;
      item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_RTD_DESC].strptr);
      subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_RTD_DESC]);
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         if (value)
         {
            idx = tvb_get_bits8(tvb,bit_offset,5);
            proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "BA Index Start RTD: %d", idx);
            bit_offset += 5;
         }
         else
            idx = 0;
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         while (value == 0)
         {
            proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "RTD index %d: %d TDMA frame(s) modulo 51 TDMA frames", idx, tvb_get_bits8(tvb,bit_offset,6));
            bit_offset += 6;
            value = tvb_get_bits8(tvb,bit_offset,1);
            bit_offset += 1;
         }
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         while (value == 0)
         {
            idx += 1;
            value = tvb_get_bits8(tvb,bit_offset,1);
            bit_offset += 1;
            while (value == 0)
            {
               proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "RTD index %d: %d TDMA frame(s) modulo 51 TDMA frames", idx, tvb_get_bits8(tvb,bit_offset,6));
               bit_offset += 6;
               value = tvb_get_bits8(tvb,bit_offset,1);
               bit_offset += 1;
            }
         }
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         if (value)
         {
            idx = tvb_get_bits8(tvb,bit_offset,5);
            proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "BA Index Start RTD: %d", idx);
            bit_offset += 5;
         }
         else
            idx = 0;
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         while (value == 0)
         {
            proto_tree_add_text(subtree2,tvb, bit_offset>>3, 2, "RTD index %d: %d/64 TDMA frame(s) modulo 51 TDMA frames", idx, tvb_get_bits16(tvb,bit_offset,12,FALSE));
            bit_offset += 12;
            value = tvb_get_bits8(tvb,bit_offset,1);
            bit_offset += 1;
         }
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         while (value == 0)
         {
            idx += 1;
            value = tvb_get_bits8(tvb,bit_offset,1);
            bit_offset += 1;
            while (value == 0)
            {
               proto_tree_add_text(subtree2,tvb, bit_offset>>3, 2, "RTD index %d: %d/64 TDMA frame(s) modulo 51 TDMA frames", idx, tvb_get_bits16(tvb,bit_offset,12,FALSE));
               bit_offset += 12;
               value = tvb_get_bits8(tvb,bit_offset,1);
               bit_offset += 1;
            }
         }
      }
      proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
   }
   value  = tvb_get_bits8(tvb,bit_offset,1);
   bit_offset += 1;
   if (value)
   { /* GPRS BSIC Description */
      bit_offset_sav = bit_offset;
      item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_BSIC_DESC].strptr);
      subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_BSIC_DESC]);
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "BA Index Start BSIC: %d", tvb_get_bits8(tvb,bit_offset,5));
         bit_offset += 5;
      }
      proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "BSIC: %d", tvb_get_bits8(tvb,bit_offset,6));
      bit_offset += 6;
      idx = tvb_get_bits8(tvb,bit_offset,7);
      proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "Number Remaining BSIC: %d", idx);
      bit_offset += 7;
      while (idx)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_frequency_scrolling, tvb, bit_offset, 1, FALSE);
         bit_offset += 1;
         proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "BSIC: %d", tvb_get_bits8(tvb,bit_offset,6));
         bit_offset += 6;
         idx -= 1;
      }
      proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
   }
   value  = tvb_get_bits8(tvb,bit_offset,1);
   bit_offset += 1;
   if (value)
   { /* GPRS Report Priority Description */
      bit_offset_sav = bit_offset;
      item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_REPORT_PRIO_DESC].strptr);
      subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_REPORT_PRIO_DESC]);
      idx = tvb_get_bits8(tvb,bit_offset,7);
      proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "Number Cells: %d", idx);
      bit_offset += 7;
      while (idx)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_rep_priority, tvb, bit_offset, 1, FALSE);
         bit_offset += 1;
         idx -= 1;
      }
      proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
   }
   value  = tvb_get_bits8(tvb,bit_offset,1);
   bit_offset += 1;
   if (value)
   { /* GPRS Measurement Parameters Description */
      bit_offset_sav = bit_offset;
      item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_MEAS_PARAM_DESC].strptr);
      subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_MEAS_PARAM_DESC]);
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_report_type, tvb, bit_offset, 1, FALSE);
      bit_offset += 1;
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_reporting_rate, tvb, bit_offset, 1, FALSE);
      bit_offset +=1;
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_invalid_bsic_reporting, tvb, bit_offset, 1, FALSE);
      bit_offset +=1;
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_multiband_reporting, tvb, bit_offset, 2, FALSE);
         bit_offset += 2;
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_serving_band_reporting, tvb, bit_offset, 2, FALSE);
         bit_offset += 2;
      }
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_scale_ord, tvb, bit_offset, 2, FALSE);
      bit_offset += 2;
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_900_reporting_offset, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_900_reporting_threshold, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_1800_reporting_offset, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_1800_reporting_threshold, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_400_reporting_offset, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_400_reporting_threshold, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_1900_reporting_offset, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_1900_reporting_threshold, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_850_reporting_offset, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_850_reporting_threshold, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
      }
      proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
   }
   value = tvb_get_bits8(tvb,bit_offset,1);
   bit_offset += 1;
   if (value)
   { /* NC Measurement Parameters */
      bit_offset_sav = bit_offset;
      item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_NC_MEAS_PARAM].strptr);
      subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_NC_MEAS_PARAM]);
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_network_control_order, tvb, bit_offset, 2, FALSE);
      bit_offset += 2;
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_nc_non_drx_period, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_nc_reporting_period_i, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_nc_reporting_period_t, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
      }
      proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
   }
   value = tvb_get_bits8(tvb,bit_offset,1);
   bit_offset += 1;
   if (value)
   { /* SI 2quater Extension Information */
      bit_offset_sav = bit_offset;
      item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_SI2Q_EXT_INFO].strptr);
      subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_SI2Q_EXT_INFO]);
      idx = tvb_get_bits8(tvb,bit_offset,8);
      proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "Extension Length: %d", idx);
      bit_offset += 8;
      proto_item_set_len(item2,((bit_offset+idx+1-bit_offset_sav)>>3)+1);
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      { /* CCN Support Description */
         bit_offset_sav = bit_offset;
         item3 = proto_tree_add_text(subtree2, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_CCN_SUPPORT_DESC].strptr);
         subtree3 = proto_item_add_subtree(item3, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_CCN_SUPPORT_DESC]);
         value = tvb_get_bits8(tvb,bit_offset,7);
         proto_tree_add_text(subtree3,tvb, bit_offset>>3, 1, "Number Cells: %d", value);
         bit_offset += 7;
         idx -= 7;
         item2 = proto_tree_add_text(subtree3,tvb, bit_offset>>3, (value>>3)+1, "CCN Supported: ");
         while (value)
         {
            proto_item_append_text(item2,"%d",tvb_get_bits8(tvb,bit_offset,1));
            bit_offset += 1;
            value -= 1;
            idx -= 1;
         }
         proto_item_set_len(item3,((bit_offset+-bit_offset_sav)>>3)+1);
      }
      bit_offset += idx;
   }
   value = tvb_get_bits8(tvb,bit_offset,1);
   bit_offset += 1;
   if (value)
   { /* 3G Neighbour Cell Description */
      bit_offset_sav = bit_offset;
      item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_NEIGH_CELL_DESC].strptr);
      subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_NEIGH_CELL_DESC]);
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "Index Start 3G: %d", tvb_get_bits8(tvb,bit_offset,7));
         bit_offset += 7;
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "Absolute Index Start EMR: %d", tvb_get_bits8(tvb,bit_offset,7));
         bit_offset += 7;
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      { /* UTRAN FDD Description */
         bit_offset_sav2 = bit_offset;
         item3 = proto_tree_add_text(subtree2, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_FDD_DESC].strptr);
         subtree3 = proto_item_add_subtree(item3, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_UTRAN_FDD_DESC]);
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         if (value)
         {
            proto_tree_add_text(subtree3,tvb, bit_offset>>3, 1, "Bandwidth FDD: %d", tvb_get_bits8(tvb,bit_offset,3));
            bit_offset += 3;
         }
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         while (value)
         {
            bit_offset += 1; /* skip a 0 bit */
            proto_tree_add_text(subtree3,tvb, bit_offset>>3, 2, "FDD UARFCN: %d", tvb_get_bits16(tvb,bit_offset,14,FALSE));
            bit_offset += 14;
            xdd_indic0 = tvb_get_bits8(tvb,bit_offset,1);
            proto_tree_add_text(subtree3,tvb, bit_offset>>3, 1, "FDD Indic0: %d", xdd_indic0);
            bit_offset += 1;
            idx = tvb_get_bits8(tvb,bit_offset,5);
            proto_tree_add_text(subtree3,tvb, bit_offset>>3, 1, "Nr of FDD Cells : %d", idx);
            bit_offset += 5;
            idx = convert_n_to_p[idx];
            item4 = proto_tree_add_text(subtree3,tvb, bit_offset>>3, (idx>>3)+1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_FDD_DESC].strptr);
            subtree4 = proto_item_add_subtree(item4, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_FDD_CELL_INFORMATION_FIELD]);
            proto_tree_add_text(subtree4,tvb, bit_offset>>3, (idx>>3)+1, "Field is %d bits long", idx);
            if (xdd_indic0)
            {
               proto_tree_add_text(subtree4,tvb, bit_offset>>3, 0, "Scrambling Code: %d", 0);
               proto_tree_add_text(subtree4,tvb, bit_offset>>3, 0, "Diversity: %d", 0);
            }
            if (idx)
            {
               wsize = 10;
               nwi = 1;
               jwi = 0;
               i = 1;

               while (idx > 0)
               {
                  w[i] = tvb_get_bits16(tvb, bit_offset, wsize, FALSE);
                  bit_offset += wsize;
                  idx -= wsize;
                  if (w[i] == 0)
                  {
                     idx = 0;
                     break;
                  }
                  if (++jwi==nwi)
                  {
                     jwi = 0;
                     nwi <<= 1;
                     wsize--;
                  }
                  i++;
               }
               if (idx < 0)
               {
                  bit_offset += idx;
               }
               iused = i-1;

               for (i=1; i <= iused; i++)
               {
                  xdd_cell_info = f_k(i, w, 1024);
                  proto_tree_add_text(subtree4,tvb, bit_offset>>3, 0, "Scrambling Code: %d", xdd_cell_info & 0x01FF);
                  proto_tree_add_text(subtree4,tvb, bit_offset>>3, 0, "Diversity: %d", (xdd_cell_info >> 9) & 0x01);
               }
            }
            value = tvb_get_bits8(tvb,bit_offset,1);
            bit_offset += 1;
         }
         proto_item_set_len(item3,((bit_offset-bit_offset_sav2)>>3)+1);
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      { /* UTRAN TDD Description */
         bit_offset_sav2 = bit_offset;
         item3 = proto_tree_add_text(subtree2, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_TDD_DESC].strptr);
         subtree3 = proto_item_add_subtree(item3, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_UTRAN_TDD_DESC]);
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         if (value)
         {
            proto_tree_add_text(subtree3,tvb, bit_offset>>3, 1, "Bandwidth TDD: %d", tvb_get_bits8(tvb,bit_offset,3));
            bit_offset += 3;
         }
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         while (value)
         {
            bit_offset += 1; /* skip a 0 bit */
            proto_tree_add_text(subtree3,tvb, bit_offset>>3, 2, "TDD UARFCN: %d", tvb_get_bits16(tvb,bit_offset,14,FALSE));
            bit_offset += 14;
            xdd_indic0 = tvb_get_bits8(tvb,bit_offset,1);
            proto_tree_add_text(subtree3,tvb, bit_offset>>3, 1, "TDD Indic0: %d", xdd_indic0);
            bit_offset += 1;
            idx = tvb_get_bits8(tvb,bit_offset,5);
            proto_tree_add_text(subtree3,tvb, bit_offset>>3, 1, "Nr of TDD Cells : %d", idx);
            bit_offset += 5;
            idx = convert_n_to_q[idx];
            item4 = proto_tree_add_text(subtree3,tvb, bit_offset>>3, (idx>>3)+1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_TDD_DESC].strptr);
            subtree4 = proto_item_add_subtree(item4, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_TDD_CELL_INFORMATION_FIELD]);
            proto_tree_add_text(subtree4,tvb, bit_offset>>3, (idx>>3)+1, "Field is %d bits long", idx);
            if (xdd_indic0)
            {
               proto_tree_add_text(subtree4,tvb, bit_offset>>3, 0, "Cell Parameter: %d", 0);
               proto_tree_add_text(subtree4,tvb, bit_offset>>3, 0, "Sync Case TSTD: %d", 0);
               proto_tree_add_text(subtree4,tvb, bit_offset>>3, 0, "Diversity TDD: %d", 0);
            }
            if (idx)
            {
               wsize = 9;
               nwi = 1;
               jwi = 0;
               i = 1;

               while (idx > 0)
               {
                  w[i] = tvb_get_bits16(tvb, bit_offset, wsize, FALSE);
                  bit_offset += wsize;
                  idx -= wsize;
                  if (w[i] == 0)
                  {
                     idx = 0;
                     break;
                  }
                  if (++jwi==nwi)
                  {
                     jwi = 0;
                     nwi <<= 1;
                     wsize--;
                  }
                  i++;
               }
               if (idx < 0)
               {
                  bit_offset += idx;
               }
               iused = i-1;

               for (i=1; i <= iused; i++)
               {
                  xdd_cell_info = f_k(i, w, 512);
                  proto_tree_add_text(subtree4,tvb, bit_offset>>3, 0, "Cell Parameter: %d", xdd_cell_info & 0x07F);
                  proto_tree_add_text(subtree4,tvb, bit_offset>>3, 0, "Sync Case TSTD: %d", (xdd_cell_info >> 7) & 0x01);
                  proto_tree_add_text(subtree4,tvb, bit_offset>>3, 0, "Diversity TDD: %d", (xdd_cell_info >> 8) & 0x01);
               }
            }
            value = tvb_get_bits8(tvb,bit_offset,1);
            bit_offset += 1;
         }
         proto_item_set_len(item3,((bit_offset-bit_offset_sav2)>>3)+1);
      }
      proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
   }
   value = tvb_get_bits8(tvb,bit_offset,1);
   bit_offset += 1;
   if (value)
   { /* 3G Measurement Parameters Description */
      bit_offset_sav = bit_offset;
      item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_MEAS_PARAM_DESC].strptr);
      subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_MEAS_PARAM_DESC]);
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_qsearch_i, tvb, bit_offset, 4, FALSE);
      bit_offset += 4;
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_qsearch_c_initial, tvb, bit_offset, 1, FALSE);
      bit_offset += 1;
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_qoffset, tvb, bit_offset, 4, FALSE);
         bit_offset += 4;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_rep_quant, tvb, bit_offset, 1, FALSE);
         bit_offset += 1;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_multirat_reporting, tvb, bit_offset, 2, FALSE);
         bit_offset += 2;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_qmin, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_qoffset, tvb, bit_offset, 4, FALSE);
         bit_offset += 4;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_multirat_reporting, tvb, bit_offset, 2, FALSE);
         bit_offset += 2;
      }
      proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
   }
   value = tvb_get_bits8(tvb,bit_offset,1);
   bit_offset += 1;
   if (value)
   { /* GPRS 3G Measurement Parameters Description */
      bit_offset_sav = bit_offset;
      item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_3G_MEAS_PARAM_DESC].strptr);
      subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_3G_MEAS_PARAM_DESC]);
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_qsearch_p, tvb, bit_offset, 4, FALSE);
      bit_offset += 4;
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_3g_search_prio, tvb, bit_offset, 1, FALSE);
      bit_offset += 1;
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_rep_quant, tvb, bit_offset, 1, FALSE);
         bit_offset += 1;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_multirat_reporting, tvb, bit_offset, 2, FALSE);
         bit_offset += 2;
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_reporting_offset, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_reporting_threshold, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_multirat_reporting, tvb, bit_offset, 2, FALSE);
         bit_offset += 2;
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_reporting_offset, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_reporting_threshold, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
      }
      proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
   }
   if (((curr_offset + len)<<3) - bit_offset > 0)
   {
      /* There is still room left in the Rest Octets IE */
      if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
      { /* Additions in Rel-5 */
         bit_offset += 1;
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         if (value)
         { /* 3G Additional Measurement Parameters Description */
            bit_offset_sav = bit_offset;
            item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC].strptr);
            subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC]);
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_qmin_offset, tvb, bit_offset, 3, FALSE);
            bit_offset += 3;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_rscpmin, tvb, bit_offset, 4, FALSE);
            bit_offset += 4;
            proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
         }
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         if (value)
         { /* 3G Additional Measurement Parameters Description 2 */
            bit_offset_sav = bit_offset;
            item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC2].strptr);
            subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC2]);
            value = tvb_get_bits8(tvb,bit_offset,1);
            bit_offset += 1;
            if (value)
            {
               proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_reporting_threshold_2, tvb, bit_offset, 6, FALSE);
               bit_offset += 6;
            }
            proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
         }
         if (((curr_offset + len)<<3) - bit_offset > 0)
         {
            /* There is still room left in the Rest Octets IE */
            if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
            { /* Additions in Rel-6 */
               bit_offset += 1;
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_ccn_active, tvb, bit_offset, 1, FALSE);
               bit_offset += 1;
               if (((curr_offset + len)<<3) - bit_offset > 0)
               {
                  /* There is still room left in the Rest Octets IE */
                  if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
                  { /* Additions in Rel-7 */
                     bit_offset += 1;
                     value = tvb_get_bits8(tvb,bit_offset,1);
                     bit_offset += 1;
                     if (value)
                     {
                        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_700_reporting_offset, tvb, bit_offset, 3, FALSE);
                        bit_offset += 3;
                        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_700_reporting_threshold, tvb, bit_offset, 3, FALSE);
                        bit_offset += 3;
                     }
                     value = tvb_get_bits8(tvb,bit_offset,1);
                     bit_offset += 1;
                     if (value)
                     {
                        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_810_reporting_offset, tvb, bit_offset, 3, FALSE);
                        bit_offset += 3;
                        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_810_reporting_threshold, tvb, bit_offset, 3, FALSE);
                        bit_offset += 3;
                     }
                  }
                  else
                     bit_offset += 1;
               }
            }
            else
               bit_offset += 1;
         }
      }
      else bit_offset += 1;
   }

 	curr_offset = curr_offset + len;

	return curr_offset-offset;
}

/*
 * [3] 10.5.2.34 SI 3 Rest Octets
 */
static const value_string gsm_a_rr_temporary_offset_vals[] = {
   { 0, "0 dB"},
   { 1, "10 dB"},
   { 2, "20 dB"},
   { 3, "30 dB"},
   { 4, "40 dB"},
   { 5, "50 dB"},
   { 6, "60 dB"},
   { 7, "infinity"},
   { 0, NULL }
};

static const value_string gsm_a_rr_cell_reselect_offset_vals[] = {
   { 0, "0 dB"},
   { 1, "2 dB"},
   { 2, "4 dB"},
   { 3, "6 dB"},
   { 4, "8 dB"},
   { 5, "10 dB"},
   { 6, "12 dB"},
   { 7, "14 dB"},
   { 8, "16 dB"},
   { 9, "18 dB"},
   {10, "20 dB"},
   {11, "22 dB"},
   {12, "24 dB"},
   {13, "26 dB"},
   {14, "28 dB"},
   {15, "30 dB"},
   {16, "32 dB"},
   {17, "34 dB"},
   {18, "36 dB"},
   {19, "38 dB"},
   {20, "40 dB"},
   {21, "42 dB"},
   {22, "44 dB"},
   {23, "46 dB"},
   {24, "48 dB"},
   {25, "50 dB"},
   {26, "52 dB"},
   {27, "54 dB"},
   {28, "56 dB"},
   {29, "58 dB"},
   {30, "60 dB"},
   {31, "62 dB"},
   {32, "64 dB"},
   {33, "66 dB"},
   {34, "68 dB"},
   {35, "70 dB"},
   {36, "72 dB"},
   {37, "74 dB"},
   {38, "76 dB"},
   {39, "78 dB"},
   {40, "80 dB"},
   {41, "82 dB"},
   {42, "84 dB"},
   {43, "86 dB"},
   {44, "88 dB"},
   {45, "90 dB"},
   {46, "92 dB"},
   {47, "94 dB"},
   {48, "96 dB"},
   {49, "98 dB"},
   {50, "100 dB"},
   {51, "102 dB"},
   {52, "104 dB"},
   {53, "106 dB"},
   {54, "108 dB"},
   {55, "110 dB"},
   {56, "112 dB"},
   {57, "114 dB"},
   {58, "116 dB"},
   {59, "118 dB"},
   {60, "120 dB"},
   {61, "122 dB"},
   {62, "124 dB"},
   {63, "126 dB"},
   { 0, NULL }
};

static const value_string gsm_a_rr_penalty_time_vals[] = {
   { 0, "20 s"},
   { 1, "40 s"},
   { 2, "60 s"},
   { 3, "80 s"},
   { 4, "100 s"},
   { 5, "120 s"},
   { 6, "140 s"},
   { 7, "160 s"},
   { 8, "180 s"},
   { 9, "200 s"},
   {10, "220 s"},
   {11, "240 s"},
   {12, "260 s"},
   {13, "280 s"},
   {14, "300 s"},
   {15, "320 s"},
   {16, "340 s"},
   {17, "360 s"},
   {18, "380 s"},
   {19, "400 s"},
   {20, "420 s"},
   {21, "440 s"},
   {22, "460 s"},
   {23, "480 s"},
   {24, "500 s"},
   {25, "520 s"},
   {26, "540 s"},
   {27, "560 s"},
   {28, "580 s"},
   {29, "600 s"},
   {30, "620 s"},
   {31, "Cell Reselect Offset is subtracted from C2 and Temporary Offset is ignored"},
   { 0, NULL }
};

static gint
de_rr_rest_oct_opt_sel_param(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
   proto_tree *subtree;
   proto_item *item;
   gint curr_bit_offset;

   curr_bit_offset = bit_offset;

   if (gsm_a_rr_is_bit_high(tvb,curr_bit_offset) == TRUE)
   { /* Selection Parameters */
      curr_bit_offset += 1;
      item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_OPTIONAL_SEL_PARAM].strptr);
      subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_OPTIONAL_SEL_PARAM]);
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_cbq, tvb, curr_bit_offset, 1, FALSE);
      curr_bit_offset += 1;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_cell_reselect_offset, tvb, curr_bit_offset, 6, FALSE);
      curr_bit_offset += 6;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_temporary_offset, tvb, curr_bit_offset, 3, FALSE);
      curr_bit_offset += 3;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_penalty_time, tvb, curr_bit_offset, 5, FALSE);
      curr_bit_offset += 5;
      proto_item_set_len(item,((curr_bit_offset-bit_offset)>>3)+1);
   }
   else
      curr_bit_offset += 1;

   return (curr_bit_offset - bit_offset);
}

static const value_string gsm_a_rr_si13_position_vals[] = {
   { 0, "SYSTEM INFORMATION TYPE 13 message is sent on BCCH Norm"},
   { 1, "SYSTEM INFORMATION TYPE 13 message is sent on BCCH Ext"},
   { 0, NULL }
};

static gint
de_rr_rest_oct_gprs_indicator(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
   proto_tree *subtree;
   proto_item *item;
   gint curr_bit_offset;

   curr_bit_offset = bit_offset;

   item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, 1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_INDICATOR].strptr);
   subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_INDICATOR]);
   proto_tree_add_text(subtree, tvb, curr_bit_offset>>3, 1, "RA Colour: %d",tvb_get_bits8(tvb,curr_bit_offset,3));
   curr_bit_offset += 3;
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si13_position, tvb, curr_bit_offset, 1, FALSE);
   curr_bit_offset += 1;

   return (curr_bit_offset - bit_offset);
}

static const value_string gsm_a_rr_power_offset_vals[] = {
	{ 0, "0 dB"},
	{ 1, "2 dB"},
	{ 2, "4 dB"},
   { 3, "8 dB"},
	{ 0, NULL }
};

static const true_false_string gsm_a_rr_si2quater_position_value = {
   "SYSTEM INFORMATION TYPE 2 quater message is sent on BCCH Ext",
   "SYSTEM INFORMATION TYPE 2 quater message is sent on BCCH Norm"
};

static const true_false_string gsm_a_rr_si13alt_position_value = {
   "If Iu mode is supported in the cell, SYSTEM INFORMATION TYPE 13alt message is sent on BCCH Ext",
   "If Iu mode is supported in the cell, SYSTEM INFORMATION TYPE 13alt message is sent on BCCH Norm"
};

static guint8
de_rr_si3_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;
   gint bit_offset;
   gboolean gprs_indicator;

	len = 4;
	curr_offset = offset;
   bit_offset = curr_offset << 3;

	item = proto_tree_add_text(tree, tvb, curr_offset, len, "%s",
		gsm_rr_elem_strings[DE_RR_SI3_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_SI3_REST_OCT]);

   bit_offset += de_rr_rest_oct_opt_sel_param(tvb, subtree, bit_offset);

   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   { /* Optional Power Offset */
      bit_offset += 1;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_power_offset, tvb, bit_offset, 2, FALSE);
      bit_offset += 2;
   }
   else
      bit_offset += 1;
   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
      proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "SYSTEM INFORMATION TYPE 2ter message is available");
   else
      proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "SYSTEM INFORMATION TYPE 2ter message is not available");
   bit_offset += 1;
   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
      proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "Early Classmark Sending is allowed");
   else
      proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "Early Classmark Sending is forbidden");
   bit_offset += 1;
   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   { /* Scheduling if and where */
      bit_offset += 1;
      proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "Where: %d",tvb_get_bits8(tvb,bit_offset,3));
      bit_offset += 3;
   }
   else
      bit_offset += 1;
   gprs_indicator = gsm_a_rr_is_bit_high(tvb,bit_offset);
   if (gprs_indicator == TRUE)
   { /* GPRS indicator */
      bit_offset += 1;
      bit_offset += de_rr_rest_oct_gprs_indicator(tvb, subtree, bit_offset);
   }
   else
      bit_offset += 1;
   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
      proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "3G Early Classmark Sending Restriction: The sending of UTRAN,CDMA2000 and GERAN IU MODE CLASSMARK CHANGE messages are controlled by the Early Classmark Sending Control parameter");
   else
      proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "3G Early Classmark Sending Restriction: Neither UTRAN, CDMA2000 nor GERAN IU MODE CLASSMARK CHANGE message shall be sent with the Early classmark sending");
   bit_offset += 1;
   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   { /* SI2quater Indicator */
      bit_offset += 1;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si2quater_position, tvb, bit_offset, 1, FALSE);
      bit_offset += 1;
   }
   else
      bit_offset += 1;
   if (gprs_indicator == FALSE)
   {
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si13alt_position, tvb, bit_offset, 1, FALSE);
      bit_offset += 1;
   }
   
	curr_offset = curr_offset + len;

	return curr_offset-offset;
}

/*
 * [3] 10.5.2.32 SI 4 Rest Octets
 */
static const value_string gsm_a_rr_prio_thr_vals[] = {
   { 0, "0 dB"},
   { 1, "6 dB"},
   { 2, "12 dB"},
   { 3, "18 dB"},
   { 4, "24 dB"},
   { 5, "30 dB"},
   { 6, "36 dB"},
   { 7, "Infinite"},
   { 0, NULL }
};

static const value_string gsm_a_rr_lsa_offset_vals[] = {
   { 0, "0 dB"},
   { 1, "4 dB"},
   { 2, "8 dB"},
   { 3, "16 dB"},
   { 4, "24 dB"},
   { 5, "32 dB"},
   { 6, "48 dB"},
   { 7, "64 dB"},
   { 0, NULL }
};

static guint8
de_rr_si4_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree, *subtree2, *subtree3;
	proto_item	*item, *item2, *item3;
	guint32	curr_offset;
   gint bit_offset, bit_offset_sav, bit_offset_sav2;
   guint value;

	len = tvb_length_remaining(tvb,offset);
	if (len==0)
		return 0;

	curr_offset = offset;
   bit_offset = curr_offset << 3;

	item = proto_tree_add_text(tree, tvb, curr_offset, len, "%s",
		gsm_rr_elem_strings[DE_RR_SI4_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_SI4_REST_OCT]);

   item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_SI4_REST_OCTETS_O].strptr);

	subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_SI4_REST_OCTETS_O]);

   bit_offset += de_rr_rest_oct_opt_sel_param(tvb, subtree2, bit_offset);

   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   { /* Optional Power Offset */
      bit_offset += 1;
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_power_offset, tvb, bit_offset, 2, FALSE);
      bit_offset += 2;
   }
   else
      bit_offset += 1;
   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   {
      bit_offset += 1;
      bit_offset += de_rr_rest_oct_gprs_indicator(tvb, subtree2, bit_offset);
   }
   else
      bit_offset += 1;
   proto_item_set_len(item2,(bit_offset>>3)+1-curr_offset);
   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   { /* SI4 Rest Octets_S */
      bit_offset += 1;
      bit_offset_sav = bit_offset;
      item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_SI4_REST_OCTETS_S].strptr);
      subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_SI4_REST_OCTETS_S]);
      if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
      { /* LSA Parameters */
         bit_offset += 1;
         bit_offset_sav2 = bit_offset;
         item3 = proto_tree_add_text(subtree2, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_LSA_PARAMETERS].strptr);
         subtree3 = proto_item_add_subtree(item3, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_LSA_PARAMETERS]);
         proto_tree_add_bits_item(subtree3, hf_gsm_a_rr_prio_thr, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         proto_tree_add_bits_item(subtree3, hf_gsm_a_rr_lsa_offset, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         if (value)
         {
            proto_tree_add_text(subtree3, tvb, bit_offset>>3, 2, "MCC: %d", tvb_get_bits16(tvb,bit_offset,12,FALSE));
            bit_offset += 12;
            proto_tree_add_text(subtree3, tvb, bit_offset>>3, 2, "MNC: %d", tvb_get_bits16(tvb,bit_offset,12,FALSE));
            bit_offset += 12;
         }
         proto_item_set_len(item2,((bit_offset-bit_offset_sav2)>>3)+1);
      }
      else
         bit_offset += 1;
      if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
      { /* Cell Identity */
         bit_offset += 1;
         value = tvb_get_bits16(tvb, bit_offset, 16, FALSE);
		   proto_tree_add_uint(subtree2, hf_gsm_a_bssmap_cell_ci, tvb, bit_offset>>3, 2, value);
         bit_offset += 16;
      }
      else
         bit_offset += 1;
      if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
      { /* LSA ID information */
         bit_offset += 1;
         bit_offset_sav2 = bit_offset;
         item3 = proto_tree_add_text(subtree2, tvb, bit_offset>>3, len, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_LSA_ID_INFO].strptr);
         subtree3 = proto_item_add_subtree(item3, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_LSA_ID_INFO]);
         do
         {
            value = tvb_get_bits8(tvb,bit_offset,1);
            bit_offset += 1;
            if (value)
            {
               proto_tree_add_text(subtree3, tvb, bit_offset>>3, 3, "Short LSA ID: %d",tvb_get_bits16(tvb,bit_offset,10,FALSE));
               bit_offset += 10;
            }
            else
            {
               proto_tree_add_text(subtree3, tvb, bit_offset>>3, 3, "LSA ID: %d",tvb_get_bits32(tvb,bit_offset,24,FALSE));
               bit_offset += 24;
            }
            value = tvb_get_bits8(tvb,bit_offset,1);
            bit_offset += 1;
         } while (value);
      }
      else
         bit_offset += 1;
      if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
      {
         bit_offset += 1;
         proto_tree_add_bits_item(subtree, hf_gsm_a_rr_cbq3, tvb, (curr_offset<<3)+1, 2, FALSE);
         bit_offset += 3;
      }
      else
         bit_offset += 1;
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si13alt_position, tvb, bit_offset, 1, FALSE);
         bit_offset += 1;
      }
      proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
   }
   else
   { /* Break indicator */
      bit_offset += 1;
      if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
         proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "Break Indicator: Additional parameters \"SI4 Rest Octets_S\" are sent in SYSTEM INFORMATION TYPE 7 and 8");
      else
         proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "Break Indicator: Additional parameters \"SI4 Rest Octets_S\" are not sent in SYSTEM INFORMATION TYPE 7 and 8");
      bit_offset += 1;
   }

	curr_offset = curr_offset + len;

	return curr_offset-offset;
}

/*
 * [3] 10.5.2.35a SI 6 Rest Octets
 */
static const true_false_string gsm_a_rr_paging_channel_restructuring_value = {
   "Paging channel is restructured",
   "Paging channel is not restructured"
};

static const true_false_string gsm_a_rr_vbs_vgcs_inband_notifications_value = {
   "The mobile shall be notified on incoming high priority VBS/VGCS calls through NOTIFICATION/FACCH, the mobile need not to inspect the NCH",
   "The network does not provide notification on FACCH so that the mobile should inspect the NCH for notifications"
};

static const true_false_string gsm_a_rr_vbs_vgcs_inband_pagings_value = {
   "The mobile shall be notified on incoming high priority point-to-point calls through NOTIFICATION/FACCH, the mobile need not to inspect the PCH",
   "The network does not provide paging information on FACCH so that the mobile should inspect the PCH for pagings"
};

static const value_string gsm_a_rr_max_lapdm_vals[] = {
   { 0, "Any message segmented in up to 5 LAPDm frames"},
   { 1, "Any message segmented in up to 6 LAPDm frames"},
   { 2, "Any message segmented in up to 7 LAPDm frames"},
   { 3, "Any message segmented in up to 8 LAPDm frames"},
   { 4, "Any message segmented in up to 9 LAPDm frames"},
   { 5, "Any message segmented in up to 10 LAPDm frames"},
   { 6, "Any message segmented in up to 11 LAPDm frames"},
   { 7, "Any message segmented in up to 12 LAPDm frames"},
   { 0, NULL }
};

static const true_false_string gsm_a_rr_dedicated_mode_mbms_notification_support_value = {
   "The cell supports the Dedicated Mode MBMS Notification procedures",
   "The cell does not support the Dedicated Mode MBMS Notification procedures"
};

static const true_false_string gsm_a_rr_mnci_support_value = {
   "The cell supports the distribution of MBMS NEIGHBOURING CELL INFORMATION messages",
   "The cell does not support the distribution of MBMS NEIGHBOURING CELL INFORMATION messages"
};

static guint8
de_rr_si6_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree, *subtree2;
	proto_item	*item, *item2;
	guint32	curr_offset;
   gint bit_offset, bit_offset_sav;
   guint8 value;

	len = 7;
	curr_offset = offset;
   bit_offset = curr_offset << 3;

	item = proto_tree_add_text(tree, tvb, curr_offset, len, "%s",
		gsm_rr_elem_strings[DE_RR_SI6_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_SI6_REST_OCT]);

   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   { /* PCH and NCH Info */
      bit_offset += 1;
      bit_offset_sav = bit_offset;
      item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_PCH_AND_NCH_INFO].strptr);
	   subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_PCH_AND_NCH_INFO]);
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_paging_channel_restructuring, tvb, bit_offset, 1, FALSE);
      bit_offset += 1;
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_nln_sacch, tvb, bit_offset, 2, FALSE);
      bit_offset += 2;
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree2, hf_gsm_a_call_prio, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
      }
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_nln_status_sacch, tvb, bit_offset, 1, FALSE);
      bit_offset += 1;
      proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
   }
   else
      bit_offset += 1;
   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   { /* VBS/VGCS options */
      bit_offset += 1;
      bit_offset_sav = bit_offset;
      item2 = proto_tree_add_text(subtree, tvb,bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_VBS_VGCS_OPTIONS].strptr);
	   subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_VBS_VGCS_OPTIONS]);
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_vbs_vgcs_inband_notifications, tvb, bit_offset, 1, FALSE);
      bit_offset += 1;
      proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_vbs_vgcs_inband_pagings, tvb, bit_offset, 1, FALSE);
      bit_offset += 1;
      proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
   }
   else
      bit_offset += 1;
   value = gsm_a_rr_is_bit_high(tvb,bit_offset);
   if (value == TRUE)
   {
      proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "DTM is supported in the serving cell");
      bit_offset += 1;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rac, tvb, bit_offset, 8, FALSE);
      bit_offset += 8;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_max_lapdm, tvb, bit_offset, 3, FALSE);
      bit_offset += 3;
   }
   else
   {
      proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "DTM is not supported in the serving cell");
      bit_offset += 1;
   }
   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
      proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "Band Indicator: 1900");
   else
      proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "Band Indicator: 1800");
   bit_offset += 1;
   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   {
      bit_offset += 1;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_gprs_ms_txpwr_max_ccch, tvb, bit_offset, 5, FALSE);
      bit_offset += 5;
   }
   else
      bit_offset += 1;
   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   { /* MBMS Procedures */
      bit_offset += 1;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_dedicated_mode_mbms_notification_support, tvb, bit_offset, 1, FALSE);
      bit_offset += 1;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_mnci_support, tvb, bit_offset, 1, FALSE);
      bit_offset += 1;
   }
   else
      bit_offset += 1;
   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   { /* Additions in Release 7 */
      bit_offset += 1;
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree, hf_gsm_a_rr_amr_config, tvb, bit_offset, 4, FALSE);
         bit_offset += 4;
      }
   }
   else
      bit_offset += 1;

	curr_offset = curr_offset + len;

	return curr_offset-offset;
}

/* [3] 10.5.2.36 SI 7 Rest Octets
 * [3] 10.5.2.37 SI 8 Rest Octets
 * [3] 10.5.2.37a SI 9 Rest Octets
 */

/*
 * [3] 10.5.2.37b SI 13 Rest Octets
 */
static const value_string gsm_a_rr_si_change_field_vals[] = {
   { 0, "Update of unspecified SI message or SI messages"},
   { 1, "Update of SI1 message"},
   { 2, "Update of SI2, SI2 bis or SI2 ter message or any instance of SI2quater messages"},
   { 3, "Update of SI3, SI4, SI7, SI8, SI16 or SI17 message"},
   { 4, "Update of SI9 message"},
   { 5, "Update of SI18 or SI20 message"},
   { 6, "Update of SI19 message"},
   { 7, "Update of SI15 message"},
   { 8, "Update of SI2n message"},
   { 9, "Update of unknown SI message type"},
   { 10, "Update of unknown SI message type"},
   { 11, "Update of unknown SI message type"},
   { 12, "Update of unknown SI message type"},
   { 13, "Update of unknown SI message type"},
   { 14, "Update of unknown SI message type"},
   { 15, "Update of unknown SI message type"},
   { 0, NULL }
};

static const value_string gsm_a_rr_psi1_repeat_period_vals[] = {
   { 0, "1 multiframe"},
   { 1, "2 multiframes"},
   { 2, "3 multiframes"},
   { 3, "4 multiframes"},
   { 4, "5 multiframes"},
   { 5, "6 multiframes"},
   { 6, "7 multiframes"},
   { 7, "8 multiframes"},
   { 8, "9 multiframes"},
   { 9, "10 multiframes"},
   { 10, "11 multiframes"},
   { 11, "12 multiframes"},
   { 12, "13 multiframes"},
   { 13, "14 multiframes"},
   { 14, "15 multiframes"},
   { 15, "16 multiframes"},
   { 0, NULL }
};

static const value_string gsm_a_rr_pbcch_pb_vals[] = {
   { 0, "0 dB"},
   { 1, "-2 dB"},
   { 2, "-4 dB"},
   { 3, "-6 dB"},
   { 4, "-8 dB"},
   { 5, "-10 dB"},
   { 6, "-12 dB"},
   { 7, "-14 dB"},
   { 8, "-16 dB"},
   { 9, "-18 dB"},
   { 10, "-20 dB"},
   { 11, "-22 dB"},
   { 12, "-24 dB"},
   { 13, "-26 dB"},
   { 14, "-28 dB"},
   { 15, "-30 dB"},
   { 0, NULL }
};

static const true_false_string gsm_a_rr_spgc_ccch_sup_value = {
   "SPLIT_PG_CYCLE is supported on CCCH in this cell",
   "SPLIT_PG_CYCLE is not supported on CCCH in this cell"
};

static const value_string gsm_a_rr_priority_access_thr_vals[] = {
   { 0, "Packet access is not allowed in the cell"},
   { 1, "Packet access is not allowed in the cell"},
   { 2, "Packet access is not allowed in the cell"},
   { 3, "Packet access is allowed for priority level 1"},
   { 4, "Packet access is allowed for priority level 1 to 2"},
   { 5, "Packet access is allowed for priority level 1 to 3"},
   { 6, "Packet access is allowed for priority level 1 to 4"},
   { 7, "Packet access is allowed for priority level 1 to 4"},
   { 0, NULL }
};

static gint
de_rr_rest_oct_gprs_mobile_allocation(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
   proto_tree *subtree;
   proto_item *item;
   gint curr_bit_offset;
   guint8 value;
   guint64 ma_length;

   curr_bit_offset = bit_offset;

   item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_MOBILE_ALLOC].strptr);
	subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_MOBILE_ALLOC]);
   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_hsn, tvb, curr_bit_offset, 6, FALSE);
   curr_bit_offset += 6;
   while (tvb_get_bits8(tvb,curr_bit_offset,1))
   {
      curr_bit_offset += 1;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rfl_number, tvb, curr_bit_offset, 4, FALSE);
      curr_bit_offset += 4;
   }
   curr_bit_offset += 1;
   if (tvb_get_bits8(tvb,curr_bit_offset,1))
   {
      curr_bit_offset += 1;
      while (tvb_get_bits8(tvb,curr_bit_offset,1))
      {
         curr_bit_offset += 1;
         proto_tree_add_bits_item(subtree, hf_gsm_a_rr_arfcn_index, tvb, curr_bit_offset, 6, FALSE);
         curr_bit_offset += 6;
      }
      curr_bit_offset += 1;
   }
   else
   {
      curr_bit_offset += 1;
      proto_tree_add_bits_ret_val(subtree, hf_gsm_a_rr_ma_length, tvb, curr_bit_offset, 6, &ma_length, FALSE);
      curr_bit_offset += 6;
      value = (gint)ma_length + 1;
      item = proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, (value>>3)+1, "MA Bitmap: ");
      while (value)
      {
         proto_item_append_text(item,"%d",tvb_get_bits8(tvb,curr_bit_offset,1));
         curr_bit_offset += 1;
         value -= 1;
      }
   }
   proto_item_set_len(item,((curr_bit_offset-bit_offset)>>3)+1);

   return (curr_bit_offset - bit_offset);
}

static const value_string gsm_a_rr_nmo_vals[] = {
   { 0, "Network Mode of Operation I"},
   { 1, "Network Mode of Operation II"},
   { 2, "Network Mode of Operation III"},
   { 3, "Reserved"},
   { 0, NULL }
};

static const value_string gsm_a_rr_t3168_vals[] = {
   { 0, "500 ms"},
   { 1, "1000 ms"},
   { 2, "1500 ms"},
   { 3, "2000 ms"},
   { 4, "2500 ms"},
   { 5, "3000 ms"},
   { 6, "3500 ms"},
   { 7, "4000 ms"},
   { 0, NULL }
};

static const value_string gsm_a_rr_t3192_vals[] = {
   { 0, "500 ms"},
   { 1, "1000 ms"},
   { 2, "1500 ms"},
   { 3, "0 ms"},
   { 4, "80 ms"},
   { 5, "120 ms"},
   { 6, "160 ms"},
   { 7, "200 ms"},
   { 0, NULL }
};

static const value_string gsm_a_rr_drx_timer_max_vals[] = {
   { 0, "0 s"},
   { 1, "1 s"},
   { 2, "2 s"},
   { 3, "4 s"},
   { 4, "8 s"},
   { 5, "16 s"},
   { 6, "32 s"},
   { 7, "64 s"},
   { 0, NULL }
};

static const true_false_string gsm_a_rr_access_burst_type_value = {
   "11-bit format shall be used",
   "8-bit format shall be used"
};

static const true_false_string gsm_a_rr_control_ack_type_value = {
   "Default format is RLC/MAC control block",
   "Default format is four access bursts"
};

static const value_string gsm_a_rr_pan_max_vals[] = {
   { 0, "maximum value allowed for counter N3102 is 4"},
   { 1, "maximum value allowed for counter N3102 is 8"},
   { 2, "maximum value allowed for counter N3102 is 12"},
   { 3, "maximum value allowed for counter N3102 is 16"},
   { 4, "maximum value allowed for counter N3102 is 20"},
   { 5, "maximum value allowed for counter N3102 is 24"},
   { 6, "maximum value allowed for counter N3102 is 28"},
   { 7, "maximum value allowed for counter N3102 is 32"},
   { 0, NULL }
};

static const true_false_string gsm_a_rr_egprs_packet_channel_request_value = {
   "Use two phase packet access with PACKET CHANNEL REQUEST message for uplink TBF establishment on the PRACH",
   "Use EGPRS PACKET CHANNEL REQUEST message for uplink TBF	establishment on the PRACH"
};

static const value_string gsm_a_rr_bep_period_vals[] = {
   { 0, "1"},
   { 1, "2"},
   { 2, "3"},
   { 3, "4"},
   { 4, "5"},
   { 5, "7"},
   { 6, "10"},
   { 7, "12"},
   { 8, "15"},
   { 9, "20"},
   { 10, "25"},
   { 11, "Reserved"},
   { 12, "Reserved"},
   { 13, "Reserved"},
   { 14, "Reserved"},
   { 15, "Reserved"},
   { 0, NULL }
};

static const true_false_string gsm_a_rr_pfc_feature_mode_value = {
   "The network supports packet flow context procedures",
   "The network does not support packet flow context procedures"
};

static const true_false_string gsm_a_rr_dtm_support_value = {
   "The cell supports DTM procedures",
   "The cell does not support DTM procedures"
};

static const true_false_string gsm_a_rr_bss_paging_coordination_value = {
   "The cell supports Circuit-Switched paging coordination",
   "The cell does not support Circuit-Switched paging coordination"
};

static const true_false_string gsm_a_rr_ccn_active_value = {
   "CCN is enabled in the cell",
   "CCN is disabled in the cell"
};

static const true_false_string gsm_a_rr_nw_ext_utbf_value = {
   "The extended uplink TBF mode is supported by the network",
   "The extended uplink TBF mode is not supported by the network"
};

static const true_false_string gsm_a_rr_multiple_tbf_capability_value = {
   "The cell supports multiple TBF procedures",
   "The cell does not support multiple TBF procedures"
};

static const true_false_string gsm_a_rr_ext_utbf_no_data_value = {
   "The mobile station may refrain from sending a PACKET UPLINK DUMMY CONTROL BLOCK message when there is no other RLC/MAC block ready to send in an uplink radio block allocated by the network",
   "The mobile station shall send a PACKET UPLINK DUMMY CONTROL BLOCK message when there is no other RLC/MAC block ready to send in an uplink radio block allocated by the network"
};

static const true_false_string gsm_a_rr_dtm_enhancements_capability_value = {
   "The cell supports enhanced DTM CS establishment and enhanced DTM CS release procedures",
   "The cell does not support enhanced DTM CS establishment and enhanced DTM CS release procedures"
};

static const true_false_string gsm_a_rr_reduced_latency_access_value = {
   "The cell supports \"One Phase Access Request by Reduced Latency MS\"",
   "The cell does not support \"One Phase Access Request by Reduced Latency MS\""
};

static const value_string gsm_a_rr_alpha_vals[] = {
   { 0, "0.0"},
   { 1, "0.1"},
   { 2, "0.2"},
   { 3, "0.3"},
   { 4, "0.4"},
   { 5, "0.5"},
   { 6, "0.6"},
   { 7, "0.7"},
   { 8, "0.8"},
   { 9, "0.9"},
   { 10, "1.0"},
   { 11, "1.0"},
   { 12, "1.0"},
   { 13, "1.0"},
   { 14, "1.0"},
   { 15, "1.0"},
   { 0, NULL }
};

static const value_string gsm_a_rr_t_avg_x_vals[] = {
   { 0, "2^(0/2) / 6 multiframes"},
   { 1, "2^(1/2) / 6 multiframes"},
   { 2, "2^(2/2) / 6 multiframes"},
   { 3, "2^(3/2) / 6 multiframes"},
   { 4, "2^(4/2) / 6 multiframes"},
   { 5, "2^(5/2) / 6 multiframes"},
   { 6, "2^(6/2) / 6 multiframes"},
   { 7, "2^(7/2) / 6 multiframes"},
   { 8, "2^(8/2) / 6 multiframes"},
   { 9, "2^(9/2) / 6 multiframes"},
   { 10, "2^(10/2) / 6 multiframes"},
   { 11, "2^(11/2) / 6 multiframes"},
   { 12, "2^(12/2) / 6 multiframes"},
   { 13, "2^(13/2) / 6 multiframes"},
   { 14, "2^(14/2) / 6 multiframes"},
   { 15, "2^(15/2) / 6 multiframes"},
   { 16, "2^(16/2) / 6 multiframes"},
   { 17, "2^(17/2) / 6 multiframes"},
   { 18, "2^(18/2) / 6 multiframes"},
   { 19, "2^(19/2) / 6 multiframes"},
   { 20, "2^(20/2) / 6 multiframes"},
   { 21, "2^(21/2) / 6 multiframes"},
   { 22, "2^(22/2) / 6 multiframes"},
   { 23, "2^(23/2) / 6 multiframes"},
   { 24, "2^(24/2) / 6 multiframes"},
   { 25, "2^(25/2) / 6 multiframes"},
   { 26, "2^(25/2) / 6 multiframes"},
   { 27, "2^(25/2) / 6 multiframes"},
   { 28, "2^(25/2) / 6 multiframes"},
   { 29, "2^(25/2) / 6 multiframes"},
   { 30, "2^(25/2) / 6 multiframes"},
   { 31, "2^(25/2) / 6 multiframes"},
   { 0, NULL }
};

static const true_false_string gsm_a_rr_pc_meas_chan_value = {
   "Downlink measurements for power control shall be made on PDCH",
   "Downlink measurements for power control shall be made on BCCH"
};

static const value_string gsm_a_rr_n_avg_i_vals[] = {
   { 0, "2^(0/2)"},
   { 1, "2^(1/2)"},
   { 2, "2^(2/2)"},
   { 3, "2^(3/2)"},
   { 4, "2^(4/2)"},
   { 5, "2^(5/2)"},
   { 6, "2^(6/2)"},
   { 7, "2^(7/2)"},
   { 8, "2^(8/2)"},
   { 9, "2^(9/2)"},
   { 10, "2^(10/2)"},
   { 11, "2^(11/2)"},
   { 12, "2^(12/2)"},
   { 13, "2^(13/2)"},
   { 14, "2^(14/2)"},
   { 15, "2^(15/2)"},
   { 0, NULL }
};

static const true_false_string gsm_a_rr_sgsnr_value = {
   "SGSN is Release '99 onwards",
   "SGSN is Release '98 or older"
};

static const true_false_string gsm_a_rr_si_status_ind_value = {
   "The network does not support the PACKET SI STATUS message",
   "The network supports the PACKET SI STATUS message"
};

static const value_string gsm_a_rr_lb_ms_txpwr_max_cch_vals[] = {
   { 0, "43 dBm"},
   { 1, "41 dBm"},
   { 2, "39 dBm"},
   { 3, "37 dBm"},
   { 4, "35 dBm"},
   { 5, "33 dBm"},
   { 6, "31 dBm"},
   { 7, "29 dBm"},
   { 8, "27 dBm"},
   { 9, "25 dBm"},
   { 10, "23 dBm"},
   { 11, "21 dBm"},
   { 12, "19 dBm"},
   { 13, "17 dBm"},
   { 14, "15 dBm"},
   { 15, "13 dBm"},
   { 16, "11 dBm"},
   { 17, "9 dBm"},
   { 18, "7 dBm"},
   { 19, "5 dBm"},
   { 20, "5 dBm"},
   { 21, "5 dBm"},
   { 22, "5 dBm"},
   { 23, "5 dBm"},
   { 24, "5 dBm"},
   { 25, "5 dBm"},
   { 26, "5 dBm"},
   { 27, "5 dBm"},
   { 28, "5 dBm"},
   { 29, "5 dBm"},
   { 30, "5 dBm"},
   { 31, "5 dBm"},
   { 0, NULL }
};

static const value_string gsm_a_rr_si2n_support_vals[] = {
   { 0, "SI2n is not supported"},
   { 1, "SI2n is supported on PACCH"},
   { 2, "SI2n is supported on PACCH and broadcast on BCCH"},
   { 3, "SI2n is supported on PACCH and broadcast on BCCH Ext"},
   { 0, NULL }
};

static guint8
de_rr_si13_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree, *subtree2;
	proto_item	*item, *item2;
	guint32	curr_offset;
   gint bit_offset, bit_offset_sav;
   guint8 value;

	len = 20;
	curr_offset = offset;
   bit_offset = curr_offset << 3;

	item = proto_tree_add_text(tree, tvb, curr_offset, len, "%s",
		gsm_rr_elem_strings[DE_RR_SI13_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_SI13_REST_OCT]);

   if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
   {
      bit_offset += 1;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bcch_change_mark, tvb, bit_offset, 3, FALSE);
      bit_offset += 3;
      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si_change_field, tvb, bit_offset, 4, FALSE);
      bit_offset += 4;
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      {
         proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si13_change_mark, tvb, bit_offset, 2, FALSE);
         bit_offset += 2;
         bit_offset += de_rr_rest_oct_gprs_mobile_allocation(tvb, subtree, bit_offset);
      }
      value = tvb_get_bits8(tvb,bit_offset,1);
      bit_offset += 1;
      if (value)
      { /* PBCCH present in the cell */
         proto_tree_add_bits_item(subtree, hf_gsm_a_rr_psi1_repeat_period, tvb, bit_offset, 4, FALSE);
         bit_offset += 4;
         bit_offset_sav = bit_offset;
         item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_PBCCH_DESC].strptr);
	      subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_PBCCH_DESC]);
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_pbcch_pb, tvb, bit_offset, 4, FALSE);
         bit_offset += 4;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_pbcch_tsc, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_pbcch_tn, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         value = tvb_get_bits8(tvb,bit_offset,1);
         bit_offset += 1;
         if (value)
         {
            proto_tree_add_text(subtree2, tvb, bit_offset>>3, 1, "MAIO: %d", tvb_get_bits8(tvb,bit_offset,6));
            bit_offset += 6;
         }
         else
         {
            value = tvb_get_bits8(tvb,bit_offset,1);
            bit_offset += 1;
            if (value)
            {
               proto_tree_add_text(subtree2, tvb, bit_offset>>3, 1, "ARFCN: %d", tvb_get_bits16(tvb,bit_offset,10,FALSE));
               bit_offset += 10;
            }
            else
               proto_tree_add_text(subtree2, tvb, bit_offset>>3, 1, "PBCCH shall use the BCCH carrier");
         }
         proto_item_set_len(item2,((bit_offset-bit_offset_sav)>>3)+1);
      }
      else
      { /* PBCCH not present in the cell */
         proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rac, tvb, bit_offset, 8, FALSE);
         bit_offset += 8;
         proto_tree_add_bits_item(subtree, hf_gsm_a_rr_spgc_ccch_sup, tvb, bit_offset, 1, FALSE);
         bit_offset += 1;
         proto_tree_add_bits_item(subtree, hf_gsm_a_rr_priority_access_thr, tvb, bit_offset, 3, FALSE);
         bit_offset += 3;
         proto_tree_add_bits_item(subtree, hf_gsm_a_rr_network_control_order, tvb, bit_offset, 2, FALSE);
         bit_offset += 2;
         bit_offset += de_rr_rest_oct_gprs_cell_options(tvb, subtree, bit_offset);
         bit_offset += de_rr_rest_oct_gprs_power_control_parameters(tvb, subtree, bit_offset);  
      }
      if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
      { /* Additions in release 99 */
         bit_offset += 1;
         proto_tree_add_bits_item(subtree, hf_gsm_a_rr_sgsnr, tvb, bit_offset, 1, FALSE);
         bit_offset += 1;
         if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
         { /* Additions in release Rel-4 */
            bit_offset += 1;
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si_status_ind, tvb, bit_offset, 1, FALSE);
            bit_offset += 1;
            if (gsm_a_rr_is_bit_high(tvb,bit_offset) == TRUE)
            { /* Additions in release Rel-6 */
               bit_offset += 1;
               value = tvb_get_bits8(tvb,bit_offset,1);
               bit_offset += 1;
               if (value)
               {
                  proto_tree_add_bits_item(subtree, hf_gsm_a_rr_lb_ms_txpwr_max_cch, tvb, bit_offset, 5, FALSE);
                  bit_offset += 5;
               }
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si2n_support, tvb, bit_offset, 2, FALSE);
               bit_offset += 2;
            }
            else
               bit_offset += 1;
         }
         else
            bit_offset += 1;
      }
      else
         bit_offset += 1;
   }
   else
   {
      bit_offset += 1;
      proto_tree_add_text(subtree,tvb, curr_offset, len ,"Empty");
   }

	curr_offset = curr_offset + len;

	return curr_offset-offset;
}

/* [3] 10.5.2.37c (void)
 * [3] 10.5.2.37d (void)
 * [3] 10.5.2.37e SI 16 Rest Octets
 * [3] 10.5.2.37f SI 17 Rest Octets
 * [3] 10.5.2.37g SI 19 Rest Octets
 * [3] 10.5.2.37h SI 18 Rest Octets
 * [3] 10.5.2.37i SI 20 Rest Octets
 */
/*
 * [3] 10.5.2.38 Starting Time
 */
static guint8
de_rr_starting_time(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	gint bit_offset;
	guint64 t1prime, t2, t3;

	curr_offset = offset;
	bit_offset = curr_offset << 3;

	proto_tree_add_bits_ret_val(tree, hf_gsm_a_rr_t1prime, tvb, bit_offset, 5, &t1prime, FALSE);
	bit_offset += 5;
	proto_tree_add_bits_ret_val(tree, hf_gsm_a_rr_t3, tvb, bit_offset, 6, &t3, FALSE);
	bit_offset += 6;
	proto_tree_add_bits_ret_val(tree, hf_gsm_a_rr_t2, tvb, bit_offset, 5, &t2, FALSE);
	bit_offset += 5;
	proto_tree_add_text(tree,tvb, curr_offset, 2, "FN mod 42432: %" G_GINT64_MODIFIER "u",51*((t3-t2)%26)+t3+51*26*t1prime);
	curr_offset = curr_offset + 2;
	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.39 Synchronization Indication
 */
/*
 * ROT: Report Observed Time Difference (Octet1 bit 3) */

static const true_false_string sm_a_rr_sync_ind_rot_value  = {
	"Mobile Time Difference IE shall be included in the HANDOVER COMPLETE message",
	"Mobile Time Difference IE shall not be included in the HANDOVER COMPLETE message"
};

/* SI: Synchronization indication (octet 1)Bit2 1 */

static const value_string gsm_a_rr_sync_ind_si_vals[] = {
	{ 0,	"Non-synchronized"},
	{ 1,	"Synchronized"},
	{ 2,	"Pre-synchronised"},
	{ 3,	"Pseudo-synchronised"},
	{ 0,	NULL }
};
/* NCI: Normal cell indication (octet 1, bit 4) */

static const true_false_string gsm_a_rr_sync_ind_nci_value  = {
	"Out of range timing advance shall trigger a handover failure procedure",
	"Out of range timing advance is ignored"
};
static guint8
de_rr_sync_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	/*NCI */
	proto_tree_add_item(tree, hf_gsm_a_rr_sync_ind_nci, tvb, curr_offset, 1, FALSE);
	/*ROT */
	proto_tree_add_item(tree, hf_gsm_a_rr_sync_ind_rot, tvb, curr_offset, 1, FALSE);
	/*SI*/
	proto_tree_add_item(tree, hf_gsm_a_rr_sync_ind_si, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.40 Timing Advance
 */
static guint8
de_rr_timing_adv(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_timing_adv, tvb, curr_offset, 1, FALSE);
	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.41 Time Difference
 */
static guint8
de_rr_time_diff(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_time_diff, tvb, curr_offset, 1, FALSE);
	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.41a TLLI
 * The TLLI is encoded as a binary number with a length of 4 octets. TLLI is defined in 3GPP TS 23.003
 */
guint8
de_rr_tlli(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_tlli, tvb, curr_offset, 4, FALSE);
	curr_offset = curr_offset + 4;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.42 TMSI/P-TMSI
 */
/*
 * [3] 10.5.2.42a VGCS target mode Indication
 */
/*
Target mode (octet 3)
Bit	8 7
	0 0	dedicated mode
	0 1	group transmit mode
	Other values are reserved for future use.
*/
static const value_string gsm_a_rr_target_mode_vals[] _U_ = {
	{ 0,	"Dedicated mode"},
	{ 1,	"Group transmit mode"},
	{ 0,	NULL }
};
static guint8
de_rr_vgcs_tar_mode_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_target_mode, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_group_cipher_key_number, tvb, curr_offset, 1, FALSE);
	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.42b	VGCS Ciphering Parameters
 */
static guint8
de_rr_vgcs_cip_par(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, len ,"Data(Not decoded)");

	curr_offset = curr_offset + 2;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.43 Wait Indication
 */
static guint8
de_rr_wait_ind(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_wait_indication, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}

/* [3] 10.5.2.44 SI10 rest octets $(ASCI)$
 * [3] 10.5.2.45 EXTENDED MEASUREMENT RESULTS
 * [3] 10.5.2.46 Extended Measurement Frequency List
 */
/*
 * [3] 10.5.2.47 Suspension Cause
 */
/*Suspension cause value (octet 2)*/
static const value_string gsm_a_rr_suspension_cause_vals[] = {
	{ 0,	"Emergency call, mobile originating call or call re-establishment"},
	{ 1,	"Location Area Update"},
	{ 2,	"MO Short message service"},
	{ 3,	"Other procedure which can be completed with an SDCCH"},
	{ 4,	"MO Voice broadcast or group call"},
	{ 5,	"Mobile terminating CS connection"},
	{ 6,	"DTM not supported in the cell"},
	{ 0,	NULL }
};
guint8
de_rr_sus_cau(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_suspension_cause, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}
/*
 * [3] 10.5.2.48 APDU ID
 * [3] 10.5.2.49 APDU Flags
 * [3] 10.5.2.50 APDU Data
 * [3] 10.5.2.51 Handover To UTRAN Command
 * [3] 10.5.2.52 Handover To cdma2000 Command
 * [3] 10.5.2.53 (void)
 * [3] 10.5.2.54 (void)
 * [3] 10.5.2.55 (void)
 * [3] 10.5.2.56 3G Target Cell
 */
/*
 * 10.5.2.57 Service Support
 */
static const true_false_string gsm_a_rr_MBMS_multicast_value  = {
	"mobile station requires notification of multicast MBMS services",
	"mobile station does not require notification of multicast MBMS services"
};
static const true_false_string gsm_a_rr_MBMS_broadcast_value  = {
	"mobile station requires notification of broadcast MBMS services",
	"mobile station does not require notification of broadcast MBMS services"
};
static guint8
de_rr_serv_sup(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;
	/* bit 1
	 * 0 mobile station does not require notification of broadcast MBMS services
	 * 1 mobile station requires notification of broadcast MBMS services
	 * bit 2
	 * 0 mobile station does not require notification of multicast MBMS services
	 * 1 mobile station requires notification of multicast MBMS services
	 */
	/* MBMS Multicast */
	proto_tree_add_item(tree, hf_gsm_a_rr_MBMS_multicast, tvb, curr_offset, 1, FALSE);

	/* MBMS Broadcast */
	proto_tree_add_item(tree, hf_gsm_a_rr_MBMS_broadcast, tvb, curr_offset, 1, FALSE);
	curr_offset++;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.59	Dedicated Service Information
 */
/*
Last Segment (octet 2)
bit 1
0	mobile station shall not perform Service Information Sending procedure on new cell.
1	mobile station shall perform Service Information Sending procedure on new cell.
*/
static const true_false_string gsm_a_rr_last_segment_value  = {
	"Mobile station shall perform Service Information Sending procedure on new cell.",
	"mobile station shall not perform Service Information Sending procedure on new cell."
};
static guint8
de_rr_ded_serv_inf(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_a_rr_last_segment, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 3;

	return(curr_offset - offset);
}

guint8 (*rr_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len) = {
	/* Radio Resource Management  Information Elements 10.5.2, most are from 10.5.1 */
/*
 * [3]  10.5.2.1a	BA Range
 */
	de_rr_cell_ch_dsc,				/* [3]  10.5.2.1b	Cell Channel Description	*/
/* [3]  10.5.2.1c	BA List Pref
 * [3]  10.5.2.1d	UTRAN Frequency List
 * [3]  10.5.2.1e	Cell selection indicator after release of all TCH and SDCCH IE
 */
	de_rr_cell_dsc,					/* 10.5.2.2   RR Cell Description				*/
	de_rr_cell_opt_bcch,				/* [3]  10.5.2.3	Cell Options (BCCH)	*/
	de_rr_cell_opt_sacch,			/* [3]  10.5.2.3a	Cell Options (SACCH)	*/
	de_rr_cell_sel_param,			/* [3]  10.5.2.4	Cell Selection Parameters		*/
/*
 * [3]  10.5.2.4a	(void)
 */
	de_rr_ch_dsc,					/* [3]  10.5.2.5	Channel Description			*/
	de_rr_ch_dsc2,					/* [3]  10.5.2.5a   RR Channel Description 2 	*/
	de_rr_ch_mode,					/* [3]  10.5.2.6	Channel Mode				*/
	de_rr_ch_mode2,					/* [3]  10.5.2.7	Channel Mode 2				*/
/*
 * [3]  10.5.2.7a	UTRAN predefined configuration status information / START-CS / UE CapabilityUTRAN Classmark information element	218
 * [3]  10.5.2.7b	(void) */

	de_rr_cm_enq_mask,				/* [3]  10.5.2.7c	Classmark Enquiry Mask		*/
/* [3]  10.5.2.7d	GERAN Iu Mode Classmark information element						*/
	de_rr_chnl_needed,				/* [3]  10.5.2.8	Channel Needed
 * [3]  10.5.2.8a	(void)
 * [3]  10.5.2.8b	Channel Request Description 2 */
	/* Pos 20 */
	de_rr_cip_mode_set,					/* [3]  10.5.2.9	Cipher Mode Setting		*/
	de_rr_cip_mode_resp,				/* [3]  10.5.2.10	Cipher Response */
	de_rr_ctrl_ch_desc,			/* [3]  10.5.2.11	Control Channel Description	*/
/* [3]  10.5.2.11a	DTM Information Details */
	de_rr_dyn_arfcn_map,				/* [3]  10.5.2.11b	Dynamic ARFCN Mapping		*/
	de_rr_freq_ch_seq,					/* [3]  10.5.2.12	Frequency Channel Sequence	*/
	de_rr_freq_list,					/* [3]  10.5.2.13	Frequency List				*/
	de_rr_freq_short_list,				/* [3]  10.5.2.14	Frequency Short List		*/
	de_rr_freq_short_list2,				/* [3]  10.5.2.14a	Frequency Short List 2		*/
/* [3]  10.5.2.14b	Group Channel Description */
	de_rr_gprs_resumption,				/* [3]  10.5.2.14c	GPRS Resumption */
	de_rr_gprs_broadcast_info,			/* [3]  10.5.2.14d	GPRS broadcast information */
/* [3]  10.5.2.14e	Enhanced DTM CS Release Indication */
	de_rr_ho_ref,						/* 10.5.2.15  Handover Reference			*/
	de_rr_ia_rest_oct,					/* [3] 10.5.2.16 IA Rest Octets				*/
	de_rr_iar_rest_oct,					/* [3] 10.5.2.17 IAR Rest Octets			*/
	de_rr_iax_rest_oct,					/* [3] 10.5.2.18 IAX Rest Octets			*/
	de_rr_l2_pseudo_len,				/*[3] 10.5.2.19 L2 Pseudo Length			*/
	de_rr_meas_res,						/* [3] 10.5.2.20 Measurement Results		*/
/*
 * [3] 10.5.2.20a GPRS Measurement Results
 */
	de_rr_mob_all,					/* [3] 10.5.2.21 Mobile Allocation				*/
	de_rr_mob_time_diff,			/* [3] 10.5.2.21a Mobile Time Difference		*/
	de_rr_multirate_conf,			/* [3] 10.5.2.21aa MultiRate configuration		*/
	/* Pos 30 */
	de_rr_mult_all,					/* [3] 10.5.2.21b Multislot Allocation			*/
/*
 * [3] 10.5.2.21c NC mode
 */
	de_rr_neigh_cell_desc,				/* [3] 10.5.2.22 Neighbour Cell Description	*/
	de_rr_neigh_cell_desc2,				/* [3] 10.5.2.22a Neighbour Cell Description 2	*/
/*
 * [3] 10.5.2.22b (void)
 * [3] 10.5.2.22c NT/N Rest Octets
 * [3] 10.5.2.23 P1 Rest Octets
 * [3] 10.5.2.24 P2 Rest Octets
 * [3] 10.5.2.25 P3 Rest Octets */
	de_rr_packet_ch_desc,			/* [3] 10.5.2.25a Packet Channel Description	*/
	de_rr_ded_mod_or_tbf,			/* [3] 10.5.2.25b Dedicated mode or TBF			*/
/* [3] 10.5.2.25c RR Packet Uplink Assignment
 * [3] 10.5.2.25d RR Packet Downlink Assignment
 */
	de_rr_page_mode,				/* [3] 10.5.2.26 Page Mode						*/
/*
 * [3] 10.5.2.26a (void)
 * [3] 10.5.2.26b (void)
 * [3] 10.5.2.26c (void)
 * [3] 10.5.2.26d (void)
 */
	de_rr_ncc_perm,					/* [3] 10.5.2.27 NCC Permitted					*/
	de_rr_pow_cmd,					/* 10.5.2.28  Power Command						*/
	de_rr_pow_cmd_and_acc_type,		/* 10.5.2.28a Power Command and access type		*/
	de_rr_rach_ctrl_param,			/* [3] 10.5.2.29 RACH Control Parameters 		*/
	de_rr_req_ref,					/* [3] 10.5.2.30 Request Reference				*/
	de_rr_cause,					/* 10.5.2.31  RR Cause							*/
	de_rr_sync_ind,					/* 10.5.2.39  Synchronization Indication		*/
	de_rr_si1_rest_oct,					/* [3] 10.5.2.32 SI1 Rest Octets	*/
/* [3] 10.5.2.33 SI 2bis Rest Octets */
	de_rr_si2ter_rest_oct,				/* [3] 10.5.2.33a SI 2ter Rest Octets */
	de_rr_si2quater_rest_oct,			/* [3] 10.5.2.33b SI 2quater Rest Octets */
	de_rr_si3_rest_oct,					/* [3] 10.5.2.34 SI3 Rest Octets	*/
	de_rr_si4_rest_oct,					/* [3] 10.5.2.35 SI4 Rest Octets	*/
	de_rr_si6_rest_oct,					/* [3] 10.5.2.35b SI6 Rest Octets	*/
/* [3] 10.5.2.36 SI 7 Rest Octets
 * [3] 10.5.2.37 SI 8 Rest Octets
 * [3] 10.5.2.37a SI 9 Rest Octets
 */
	de_rr_si13_rest_oct,					/* [3] 10.5.2.37a SI13 Rest Octets	*/
/* [3] 10.5.2.37c (void)
 * [3] 10.5.2.37d (void)
 * [3] 10.5.2.37e SI 16 Rest Octets
 * [3] 10.5.2.37f SI 17 Rest Octets
 * [3] 10.5.2.37g SI 19 Rest Octets
 * [3] 10.5.2.37h SI 18 Rest Octets
 * [3] 10.5.2.37i SI 20 Rest Octets */
	de_rr_starting_time,				/* [3] 10.5.2.38 Starting Time					*/
	de_rr_timing_adv,					/* [3] 10.5.2.40 Timing Advance					*/
	de_rr_time_diff,					/* [3] 10.5.2.41 Time Difference				*/
	de_rr_tlli,							/* [3] 10.5.2.41a TLLI							*/
/*
 * [3] 10.5.2.42 TMSI/P-TMSI */
	de_rr_vgcs_tar_mode_ind,			/* [3] 10.5.2.42a VGCS target mode Indication	*/
	/* Pos 40 */
	de_rr_vgcs_cip_par,					/* [3] 10.5.2.42b	VGCS Ciphering Parameters	*/
	de_rr_wait_ind,					/* [3] 10.5.2.43 Wait Indication */
/* [3] 10.5.2.44 SI10 rest octets $(ASCI)$
 * [3] 10.5.2.45 EXTENDED MEASUREMENT RESULTS
 * [3] 10.5.2.46 Extended Measurement Frequency List */
	de_rr_sus_cau,						/* [3] 10.5.2.47 Suspension Cause				*/
/* [3] 10.5.2.48 APDU ID
 * [3] 10.5.2.49 APDU Flags
 * [3] 10.5.2.50 APDU Data
 * [3] 10.5.2.51 Handover To UTRAN Command
 * [3] 10.5.2.52 Handover To cdma2000 Command
 * [3] 10.5.2.53 (void)
 * [3] 10.5.2.54 (void)
 * [3] 10.5.2.55 (void)
 * [3] 10.5.2.56 3G Target Cell
 * 10.5.2.57 Service Support */
	de_rr_serv_sup,						/* 10.5.2.57		Service Support				*/
/*
 * 10.5.2.58 MBMS p-t-m Channel Description
 */
	de_rr_ded_serv_inf,					/* [3] 10.5.2.59	Dedicated Service Information */
/*
 * 10.5.2.60 MPRACH Description
 * 10.5.2.61 Restriction Timer
 * 10.5.2.62 MBMS Session Identity
 * 10.5.2.63 Reduced group or broadcast call reference
 * 10.5.2.64 Talker Priority status
 * 10.5.2.65 Talker Identity
 * 10.5.2.66 Token
 * 10.5.2.67 PS Cause
 * 10.5.2.68 VGCS AMR Configuration
 * 10.5.2.69 Carrier Indication
 */
	NULL,	/* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * 9.1.2 Assignment command
 */
static void
dtap_rr_ass_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Channel Description 2	10.5.2.5a	M V 3 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC2);

	/* Power Command			10.5.2.28	M V 1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_POW_CMD);

	/* 05 Frequency List		10.5.2.13	C TLV 4-132 */
	ELEM_OPT_TLV(0x05, GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, " - Frequency List, after time");

	/* 62 Cell Channel Description	10.5.2.1b	O TV 17 */
	ELEM_OPT_TV(0x62, GSM_A_PDU_TYPE_RR, DE_RR_CELL_CH_DSC, "");

	/* 10 Multislot Allocation		10.5.2.21b	C TLV 3-12 */
	ELEM_OPT_TLV(0x10,GSM_A_PDU_TYPE_RR, DE_RR_MULT_ALL, " - Description of the multislot configuration");

	/* 63 Channel Mode				10.5.2.6	O TV 2 */
	ELEM_OPT_TV(0x63,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of the First Channel(Channel Set 1)");

	/* 11 Channel Mode				10.5.2.6	O TV 2 */
	ELEM_OPT_TV(0x11,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 2");

	/* 13 Channel Mode				10.5.2.6	O TV 2 */
	ELEM_OPT_TV(0x13,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 3");

	/* 14 Channel Mode				10.5.2.6	O TV 2 */
	ELEM_OPT_TV(0x14,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 4");

	/* 15 Channel Mode				10.5.2.6	O TV 2 */
	ELEM_OPT_TV(0x15,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 5");

	/* 16 Channel Mode				10.5.2.6	O TV 2 */
	ELEM_OPT_TV(0x16,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 6");

	/* 17 Channel Mode				10.5.2.6	O TV 2 */
	ELEM_OPT_TV(0x17,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 7");

	/* 18 Channel Mode				10.5.2.6	O TV 2 */
	ELEM_OPT_TV(0x18,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 8");

	/* 64 Channel Description		10.5.2.5	O TV 4 */
	ELEM_OPT_TV(0x64,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, "Description of the Second Channel, after time");

	/* 66  Channel Mode 2			10.5.2.7	O TV 2 */
	ELEM_OPT_TV(0x66,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE2, " - Mode of the Second Channel");

	/* 72 Mobile Allocation			10.5.2.21	C TLV 3-10 */
	ELEM_OPT_TLV(0x72,GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, " - Mobile Allocation, after time");

	/* 7C Starting Time				10.5.2.38	O TV 3 */
	ELEM_OPT_TV(0x7C,GSM_A_PDU_TYPE_RR, DE_RR_STARTING_TIME, "");

	/* 19 Frequency List			10.5.2.13	C TLV 4-132 */
	ELEM_OPT_TLV(0x19, GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, " - Frequency List, before time");

	/* 1C Channel Description 2		10.5.2.5a	O TV 4 */
	ELEM_OPT_TV(0x1c,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC2, " - Description of the First Channel, before time");

	/* 1D Channel Description		10.5.2.5	O TV 4 */
	ELEM_OPT_TV(0x1d,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, " - Description of the Second Channel, before time");

	/* 1E Frequency channel sequence 10.5.2.12	C TV 10 */
	ELEM_OPT_TV(0x1e,GSM_A_PDU_TYPE_RR, DE_RR_FREQ_CH_SEQ, " - Frequency channel sequence before time");

	/* 21 Mobile Allocation			10.5.2.21	C TLV 3-10 */
	ELEM_OPT_TLV(0x21,GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, " - Mobile Allocation, before time");

	/* 9- Cipher Mode Setting		10.5.2.9	O TV 1 */
	ELEM_OPT_TV_SHORT(0x90,GSM_A_PDU_TYPE_RR, DE_RR_CIP_MODE_SET, "");
	/* 01 VGCS target mode Indication VGCS target mode Indication 10.5.2.42a O TLV 3 */
	ELEM_OPT_TLV(0x01,GSM_A_PDU_TYPE_RR, DE_RR_VGCS_TAR_MODE_IND, "");

	/* 03 Multi-Rate configuration,	MultiRate configuration 10.5.2.21aa	O TLV 4-8 */
	ELEM_OPT_TLV(0x03,GSM_A_PDU_TYPE_RR, DE_RR_MULTIRATE_CONF, "");

	/* 04 VGCS Ciphering Parameters VGCS Ciphering Parameters 10.5.2.42b O TLV 3-15	*/
	ELEM_OPT_TLV(0x04,GSM_A_PDU_TYPE_RR, DE_RR_VGCS_CIP_PAR, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.3 Assignment complete
 */
static void
dtap_rr_ass_comp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* RR Cause RR Cause 10.5.2.31 M V 1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.4 Assignment failure
 */
static void
dtap_rr_ass_fail(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* RR Cause RR Cause 10.5.2.31 M V 1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.5 Channel Mode Modify
 */
static void
dtap_rr_ch_mode_mod(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Channel Description 2	10.5.2.5a	M V 3 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC2);

	/* Channel Mode				10.5.2.6	M V 1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE);

	/* 01 VGCS target mode Indication VGCS target mode Indication 10.5.2.42a O TLV 3 */
	ELEM_OPT_TLV(0x01,GSM_A_PDU_TYPE_RR, DE_RR_VGCS_TAR_MODE_IND, "");

	/* 03 Multi-Rate configuration,	MultiRate configuration 10.5.2.21aa	O TLV 4-8 */
	ELEM_OPT_TLV(0x03,GSM_A_PDU_TYPE_RR, DE_RR_MULTIRATE_CONF, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.6 Channel Mode Modify Acknowledge
 */
static void
dtap_rr_ch_mode_mod_ack(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Channel Description 2	10.5.2.5a	M V 3 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC2);

	/* Channel Mode				10.5.2.6	M V 1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.7 Channel Release
 */
static void
dtap_rr_ch_rel(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* RR Cause RR Cause 10.5.2.31 M V 1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE);

	/* 73 BA Range BA Range 10.5.2.1a O TLV 6-7 */
	/* ELEM_OPT_TLV(0x73, GSM_A_PDU_TYPE_RR, DE_BA_RANGE, ""); */

	/* 74 Group Channel Description Group Channel Description 10.5.2.14b O TLV 5-13 */
	/* ELEM_OPT_TLV(0x74, GSM_A_PDU_TYPE_RR, DE_GRP_CH_DESC, ""); */

	/* 8x Group Cipher Key Number Group Cipher Key Number 10.5.1.10 C TV 1 */
	/* ELEM_OPT_TV_SHORT(0x80, GSM_A_PDU_TYPE_RR, DE_GRP_CIP_KEY_NUM, ""); */

	/* Cx GPRS Resumption GPRS Resumption 10.5.2.14c O TV 1 */
	ELEM_OPT_TV_SHORT(0xC0, GSM_A_PDU_TYPE_RR, DE_RR_GPRS_RESUMPTION, "");

	/* 75 BA List Pref BA List Pref 10.5.2.1c O TLV 3-? */
	/* ELEM_OPT_TLV(0x75, GSM_A_PDU_TYPE_RR, DE_BA_LIST_PREF, ""); */

	/* 76 UTRAN Freq List 10.5.2.1d O TLV 3-? */
	/* ELEM_OPT_TLV(0x75, GSM_A_PDU_TYPE_RR, DE_UTRAN_FREQ_LIST, ""); */

	/* 62 Cell Channel Description Cell Channel Description 10.5.2.1b O TV 17 */
	ELEM_OPT_TV(0x62, GSM_A_PDU_TYPE_RR, DE_RR_CELL_CH_DSC, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.8 Channel Request
 */
/* This message is NOT follow the basic format, and is only found on RACH - ignored here */

/*
 * 9.1.9 Ciphering Mode Command
 */
static void
dtap_rr_cip_mode_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;
	lower_nibble = FALSE;

	/* Ciphering Mode Setting		10.5.2.9	M V 0.5 */
	ELEM_MAND_V_SHORT(GSM_A_PDU_TYPE_RR, DE_RR_CIP_MODE_SET);
	/* Cipher Response	10.5.2.10	M V 0.5 */
	ELEM_MAND_V_SHORT(GSM_A_PDU_TYPE_RR, DE_RR_CIP_MODE_RESP);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}
/*
 * 9.1.10 Ciphering Mode Complete
 */
static void
dtap_rr_cip_mode_cpte(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;
	lower_nibble = FALSE;

	/* Mobile Equipment Identity		10.5.1.4	O TLV */
	ELEM_OPT_TLV(0x17, GSM_A_PDU_TYPE_COMMON, DE_MID, "Mobile Equipment Identity");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.11 Classmark change
 */
static void
dtap_rr_mm_cm_change(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Mobile Station Classmark 2		10.5.1.6	M LV 4 */
	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, "");
	/* 20 Mobile Station Classmark 3	10.5.1.7	C TLV 3-34 */
	ELEM_OPT_TLV(0x20, GSM_A_PDU_TYPE_COMMON, DE_MS_CM_3, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.12 Classmark enquiry
 */
static void
dtap_rr_cm_enq(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* 10 Classmark Enquiry Mask 	10.5.2.7c	O TLV 3 */
	ELEM_OPT_TLV(0x10, GSM_A_PDU_TYPE_RR, DE_RR_CM_ENQ_MASK, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.13b GPRS suspension request
 */
static void
dtap_rr_gprs_sus_req(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	curr_offset = offset;
	curr_len = len;

	/* TLLI								10.5.2.41a	M V 4 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TLLI);

	/* Routeing Area Identification		10.5.5.15	M V 6 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAI);
	/* Suspension cause					10.5.2.47	M V 1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SUS_CAU);

	/* 01 Service Support					10.5.2.57	O TV 2 */
	ELEM_OPT_TV_SHORT(0x01,GSM_A_PDU_TYPE_RR, DE_RR_SERV_SUP,"");

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

}

/*
 * 9.1.14 Handover Access
 */
/* This message is NOT follow the basic format, and is only found on DCH during initial handover access */

/* 3GPP TS 24.008 version 4.7.0 Release 4
 * [3] 9.1.15
 */
void
dtap_rr_ho_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	curr_offset = offset;
	curr_len = len;

	/* Mandatory Elemets
	 * Cell description 10.5.2.2
	 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CELL_DSC);

	/* Description of the first channel,after time
	 * Channel Description 2 10.5.2.5a
	 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC2);

	/* Handover Reference 10.5.2.15 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_HO_REF);

	/* Power Command and Access type 10.5.2.28a */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_POW_CMD_AND_ACC_TYPE);

	/* optional elements */

	/* Synchronization Indication 10.5.2.39 */
	ELEM_OPT_TV_SHORT(0xD0,GSM_A_PDU_TYPE_RR, DE_RR_SYNC_IND,"");

	/* Frequency Short List 10.5.2.14 */
	ELEM_OPT_TV(0x02,GSM_A_PDU_TYPE_RR, DE_RR_FREQ_SHORT_LIST," - Frequency Short List, after time");

	/* Frequency List 10.5.2.13 */
	ELEM_OPT_TLV(0x05, GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, " - Frequency List, after time");

	/* Cell Channel Description 10.5.2.1b */
	ELEM_OPT_TV(0x62,GSM_A_PDU_TYPE_RR, DE_RR_CELL_CH_DSC, "");

	/* Multislot Allocation 10.5.2.21b */
	ELEM_OPT_TLV(0x10,GSM_A_PDU_TYPE_RR, DE_RR_MULT_ALL, "");

	/* Mode of the First Channel(Channel Set 1)) Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x63,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of the First Channel(Channel Set 1))");

	/* Mode of Channel Set 2 Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x11,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 2");

	/* Mode of Channel Set 3 Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x13,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 3");

	/* Mode of Channel Set 4 Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x14,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 4");

	/* Mode of Channel Set 5 Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x15,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 5");

	/* Mode of Channel Set 6 Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x16,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 6");

	/* Mode of Channel Set 7 Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x17,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 7");

	/* Mode of Channel Set 8 Channel Mode 10.5.2.6*/
	ELEM_OPT_TV(0x18,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 8");

	/* Description of the Second Channel, after time, Channel Description 10.5.2.5 */
	ELEM_OPT_TV(0x64,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, " - Description of the Second Channel, after time");

	/* Mode of the Second Channel, Channel Mode 2 10.5.2.7 */
	ELEM_OPT_TV(0x66,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE2, " - Mode of the Second Channel");

	/* Frequency Channel Sequence, after time, Frequency Channel Sequence 10.5.2.12 */
	ELEM_OPT_TV(0x69,GSM_A_PDU_TYPE_RR, DE_RR_FREQ_CH_SEQ, " - Frequency Channel Sequence, after time");

	/* Mobile Allocation, after time, Mobile Allocation 10.5.2.21 */
	ELEM_OPT_TLV(0x72,GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, " - Mobile Allocation, after time");

	/* Starting Time 10.5.2.38 */
	ELEM_OPT_TV(0x7C,GSM_A_PDU_TYPE_RR, DE_RR_STARTING_TIME, "");

	/* Real Time Difference, Time Difference 10.5.2.41 */
	ELEM_OPT_TV(0x7B,GSM_A_PDU_TYPE_RR, DE_RR_TIME_DIFF, " - Real Time Difference");

	/* Timing Advance, Timing Advance 10.5.2.40 */
	ELEM_OPT_TV(0x7D,GSM_A_PDU_TYPE_RR, DE_RR_TIMING_ADV, "");

	/* Frequency Short List, before time, Frequency Short List 10.5.2.14 */
	ELEM_OPT_TV(0x12,GSM_A_PDU_TYPE_RR, DE_RR_FREQ_SHORT_LIST, " - Frequency Short List, before time");

	/* Frequency List, before time,	Frequency List 10.5.2.13 */
	ELEM_OPT_TLV(0x19,GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, " - Frequency List, before time");

	/* Description of the First Channel, before time,	Channel Description 2 10.5.2.5a*/
	ELEM_OPT_TV(0x1c,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC2, " - Description of the First Channel, before time");

	/* Description of the Second Channel, before time,	Channel Description 10.5.2.5*/
	ELEM_OPT_TV(0x1d,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, " - Description of the Second Channel, before time");

	/* Frequency channel sequence before time,	Frequency channel sequence 10.5.2.12*/
	ELEM_OPT_TV(0x1e,GSM_A_PDU_TYPE_RR, DE_RR_FREQ_CH_SEQ, " - Frequency channel sequence before time");

	/* Mobile Allocation, before time,	Mobile Allocation 10.5.2.21 */
	ELEM_OPT_TLV(0x21,GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, " - Mobile Allocation, before time");

	/* Cipher Mode Setting,	Cipher Mode Setting 10.5.2.9 */
	ELEM_OPT_TV_SHORT(0x90,GSM_A_PDU_TYPE_RR, DE_RR_CIP_MODE_SET, "");

	/* VGCS target mode Indication,	VGCS target mode Indication 10.5.2.42a */
	ELEM_OPT_TLV(0x01,GSM_A_PDU_TYPE_RR, DE_RR_VGCS_TAR_MODE_IND, "");

	/* Multi-Rate configuration,	MultiRate configuration 10.5.2.21a */
	ELEM_OPT_TLV(0x03,GSM_A_PDU_TYPE_RR, DE_RR_MULTIRATE_CONF, "");

	/* Dynamic ARFCN Mapping,	Dynamic ARFCN Mapping 10.5.2.11b */
	ELEM_OPT_TLV(0x76,GSM_A_PDU_TYPE_RR, DE_RR_DYN_ARFCN_MAP, "");

	/* VGCS Ciphering Parameters,	VGCS Ciphering Parameters 10.5.2.42b */
	ELEM_OPT_TLV(0x04,GSM_A_PDU_TYPE_RR, DE_RR_VGCS_CIP_PAR, "");

	/* Dedicated Service Information,	Dedicated Service Information 10.5.2.59 */
	ELEM_OPT_TV(0x51,GSM_A_PDU_TYPE_RR, DE_RR_DED_SERV_INF, "");

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

}
/* 3GPP TS 24.008 version 4.7.0 Release 4
 * [3] 9.1.16
 */
static void
dtap_rr_ho_cpte(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	curr_offset = offset;
	curr_len = len;

	/* RR Cause RR Cause 10.5.2.31 M V 1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE);

	/* 77 Mobile Observed Time Difference	Mobile Time Difference 10.5.2.21a */
	ELEM_OPT_TLV(0x77,GSM_A_PDU_TYPE_RR, DE_RR_MOB_TIME_DIFF, " - Mobile Observed Time Difference");

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

}

/*
 * 9.1.17 Handover failure
 */
static void
dtap_rr_ho_fail(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* RR Cause RR Cause 10.5.2.31 M V 1 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.18 Immediate assignment
 */
static void
dtap_rr_imm_ass(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	guint8 oct;
	curr_offset = offset;
	curr_len = len;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* NOTE: The order of the mandatory information elements should be chosen so that
	 * information elements with 1/2 octet of content (type 1) go together in succession.
	 * The first type 1 information element occupies bits 1 to 4 of octet N,
	 * the second bits 5 to 8 of octet N, the third bits 1 to 4 of octet N+1 etc.
	 * If the number of type 1 information elements is odd then bits 5 to 8 of the last octet
	 *  occupied by these information elements should be treated as spare bits,
	 * i.e. coded with a "0" in each.
	 */

	/* Page Mode					10.5.2.26	M V 1/2 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_PAGE_MODE);

	/* Dedicated mode or TBF		10.5.2.25b	M V 1/2 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_DED_MOD_OR_TBF);
	curr_offset++;
	if((oct&0x10) == 0){
	/* Channel Description			10.5.2.5	C V 3m */
		ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC);
	}else{
	/* Packet Channel Description	10.5.2.25a	C V 3
	 * If the Dedicated mode or TBF IE indicates that the message assigns a Temporary Block Flow (TBF),
	 * the mobile station shall consider this information element present in the message.
	 * If the Dedicated mode or TBF IE indicates that this message is the first of two in a two-message
	 * assignment of an uplink or downlink TBF, the mobile station shall ignore the contents
	 * of this information element and regard it as an unnecessary IE.
	 */
		if((oct&0x04) == 0){
			ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_PACKET_CH_DESC);
		}
	}
	/* Request Reference			10.5.2.30	M V 3	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF);

	/* Timing Advance				10.5.2.40	M V 1	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TIMING_ADV);
	/* Mobile Allocation			10.5.2.21	M LV 1-9 */
	ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, "");
	/* 7C Starting Time				10.5.2.38	O TV 3	*/
	ELEM_OPT_TV(0x7C,GSM_A_PDU_TYPE_RR, DE_RR_STARTING_TIME, "");
	/* IA Rest Octets				10.5.2.16	M V 0-11 */
	if(tvb_length_remaining(tvb,curr_offset) > 0)
		ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_IA_REST_OCT);

}

/*
 * 9.1.19 Immediate assignment extended
 */
static void
dtap_rr_imm_ass_ext(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	guint8 oct;
	curr_offset = offset;
	curr_len = len;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* Page Mode					10.5.2.26	M V 1/2 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_PAGE_MODE);
	/* Spare Half Octet		10.5.1.8	M V 1/2 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE);
	curr_offset++;
	/* Channel Description 1	Channel Description		10.5.2.5	M V 3 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC);
	/* Request Reference 1	Request Reference		10.5.2.30	M V 3	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF);
	/* Timing Advance 1	Timing Advance			10.5.2.40	M V 1	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TIMING_ADV);
	/* Channel Description 2	Channel Description		10.5.2.5	M V 3 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC);
	/* Request Reference 2	Request Reference		10.5.2.30	M V 3	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF);
	/* Timing Advance 2	Timing Advance			10.5.2.40	M V 1	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TIMING_ADV);
	/* Mobile Allocation			10.5.2.21	M LV 1-9 */
	ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, "");
	/* 7C Starting Time				10.5.2.38	O TV 3	*/
	ELEM_OPT_TV(0x7C,GSM_A_PDU_TYPE_RR, DE_RR_STARTING_TIME, "");
	/* IAX Rest Octets				10.5.2.18	M V 0-4 */
	if(tvb_length_remaining(tvb,curr_offset) > 0)
		ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_IAX_REST_OCT);

}

/*
 * 9.1.20 Immediate assignment reject
 */
static void
dtap_rr_imm_ass_rej(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	guint8 oct;
	curr_offset = offset;
	curr_len = len;

	oct = tvb_get_guint8(tvb, curr_offset);

	/* Page Mode					10.5.2.26	M V 1/2 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_PAGE_MODE);
	/* Spare Half Octet		10.5.1.8	M V 1/2 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE);
	curr_offset++;
	/* Request Reference 1	Request Reference		10.5.2.30	M V 3	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF);
	/* Wait Indication 1	Wait Indication			10.5.2.43	M V 1	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_WAIT_IND);
	/* Request Reference 2	Request Reference		10.5.2.30	M V 3	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF);
	/* Wait Indication 2	Wait Indication			10.5.2.43	M V 1	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_WAIT_IND);
	/* Request Reference 3	Request Reference		10.5.2.30	M V 3	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF);
	/* Wait Indication 3	Wait Indication			10.5.2.43	M V 1	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_WAIT_IND);
	/* Request Reference 4	Request Reference		10.5.2.30	M V 3	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF);
	/* Wait Indication 4	Wait Indication			10.5.2.43	M V 1	*/
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_WAIT_IND);
	/* IAR Rest Octets				10.5.2.19	M V 3 */
	if(tvb_length_remaining(tvb,curr_offset) > 0)
		ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_IAR_REST_OCT);

}

/*
 * 9.1.21 Measurement report
 */
static void
dtap_rr_meas_rep(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Measurement Results 10.5.2.20 M V 16 */
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_MEAS_RES);
}

/*
 * [4] 9.1.25
 */
static void
dtap_rr_paging_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;
	guint8	oct;
	proto_tree	*subtree;
	proto_item	*item;

	curr_offset = offset;
	curr_len = len;

	/*
	 * special dissection for Cipher Key Sequence Number
	 */
	oct = tvb_get_guint8(tvb, curr_offset);

	other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree,
	tvb, curr_offset, 1,
	"%s :  Spare",
	a_bigbuf);

	item =
	proto_tree_add_text(tree,
		tvb, curr_offset, 1, "%s",
		gsm_common_elem_strings[DE_CIPH_KEY_SEQ_NUM].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_CIPH_KEY_SEQ_NUM]);

	other_decode_bitfield_value(a_bigbuf, oct, 0x08, 8);
	proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"%s :  Spare",
		a_bigbuf);

	other_decode_bitfield_value(a_bigbuf, oct, 0x07, 8);

	switch (oct & 0x07)
	{
	case 0x07:
		proto_tree_add_text(subtree,
			tvb, curr_offset, 1,
			"%s :  Ciphering Key Sequence Number: No key is available",
			a_bigbuf);
		break;

	default:
		proto_tree_add_text(subtree,
			tvb, curr_offset, 1,
			"%s :  Ciphering Key Sequence Number: %u",
			a_bigbuf,
			oct & 0x07);
		break;
	}

	curr_offset++;
	curr_len--;

	if (curr_len <= 0) return;

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, "");

	ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.1.29 Physical Information
 */
static void
dtap_rr_phy_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TIMING_ADV);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.1.29
 */
static void
dtap_rr_rr_status(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.1.31
 */
static void
dtap_rr_sys_info_1(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CELL_CH_DSC);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_RACH_CTRL_PARAM);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI1_REST_OCT);
}

/*
 * [4] 9.1.32
 */
static void
dtap_rr_sys_info_2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

   proto_tree_add_text(tree, tvb, curr_offset, 16, "BCCH Frequency List");
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NCC_PERM);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_RACH_CTRL_PARAM);
}

/*
 * [4] 9.1.33
 */
static void
dtap_rr_sys_info_2bis(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

   proto_tree_add_text(tree, tvb, curr_offset, 16, "Extended BCCH Frequency List");
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_RACH_CTRL_PARAM);
}

/*
 * [4] 9.1.34
 */
static void
dtap_rr_sys_info_2ter(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

   proto_tree_add_text(tree, tvb, curr_offset, 16, "Extended BCCH Frequency List");
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC2);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI2TER_REST_OCT);
}

/*
 * [4] 9.1.34a
 */
static void
dtap_rr_sys_info_2quater(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI2QUATER_REST_OCT);
}

/*
 * [4] 9.1.35
 */
static void
dtap_rr_sys_info_3(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_CELL_ID);

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_LAI);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CTRL_CH_DESC);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CELL_OPT_BCCH);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CELL_SEL_PARAM);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_RACH_CTRL_PARAM);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI3_REST_OCT);
}

/*
 * [4] 9.1.36
 */
static void
dtap_rr_sys_info_4(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_LAI);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CELL_SEL_PARAM);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_RACH_CTRL_PARAM);

	ELEM_OPT_TV(0x64, GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, "CBCH Channel Description");

	ELEM_OPT_TV(0x72, GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, "CBCH Mobile Allocation");

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI4_REST_OCT);
}

/*
 * [4] 9.1.37
 */
static void
dtap_rr_sys_info_5(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

   proto_tree_add_text(tree, tvb, curr_offset, 16, "BCCH Frequency List");
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC);
}

/*
 * [4] 9.1.38
 */
static void
dtap_rr_sys_info_5bis(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

   proto_tree_add_text(tree, tvb, curr_offset, 16, "Extended BCCH Frequency List");
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC);
}

/*
 * [4] 9.1.39
 */
static void
dtap_rr_sys_info_5ter(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

   proto_tree_add_text(tree, tvb, curr_offset, 16, "Extended BCCH Frequency List");
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC2);
}

/*
 * [4] 9.1.40
 */
static void
dtap_rr_sys_info_6(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_CELL_ID);

	ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_LAI);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CELL_OPT_SACCH);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NCC_PERM);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI6_REST_OCT);
}

/*
 * [4] 9.1.43a
 */
static void
dtap_rr_sys_info_13(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI13_REST_OCT);
}

#define	NUM_GSM_DTAP_MSG_RR (sizeof(gsm_a_dtap_msg_rr_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_rr[NUM_GSM_DTAP_MSG_RR];
static void (*dtap_msg_rr_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
	NULL,	/* RR Initialisation Request */
	NULL,	/* Additional Assignment */
	dtap_rr_imm_ass,	/* 9.1.18 Immediate assignment  */
	dtap_rr_imm_ass_ext,	/* Immediate Assignment Extended */
	dtap_rr_imm_ass_rej,	/* Immediate Assignment Reject */

	NULL,	/* DTM Assignment Failure */
	NULL,	/* DTM Reject */
	NULL,	/* DTM Request */
	NULL,	/* Main DCCH Assignment Command */
	NULL,	/* Packet Assignment Command */

	dtap_rr_cip_mode_cmd,	/* Ciphering Mode Command */
	dtap_rr_cip_mode_cpte,	/* Ciphering Mode Complete */

	NULL,	/* Configuration Change Command */
	NULL,	/* Configuration Change Ack. */
	NULL,	/* Configuration Change Reject */

	dtap_rr_ass_cmd,	/* 9.1.2 Assignment Command */
	dtap_rr_ass_comp,	/* Assignment Complete */
	dtap_rr_ass_fail,	/* Assignment Failure */
	dtap_rr_ho_cmd,	/* Handover Command */
	dtap_rr_ho_cpte,	/* Handover Complete */
	dtap_rr_ho_fail,	/* Handover Failure */
	dtap_rr_phy_info,	/* Physical Information */
	NULL,	/* DTM Assignment Command */

	NULL,	/* RR-cell Change Order */
	NULL,	/* PDCH Assignment Command */

	dtap_rr_ch_rel,	/* Channel Release */
	NULL,	/* Partial Release */
	NULL,	/* Partial Release Complete */

	NULL,	/* Paging Request Type 1 */
	NULL,	/* Paging Request Type 2 */
	NULL,	/* Paging Request Type 3 */
	dtap_rr_paging_resp,	/* Paging Response */
	NULL,	/* Notification/NCH */
	NULL,	/* Reserved */
	NULL,	/* Notification/Response */

	NULL,	/* Reserved */

	NULL,	/* Utran Classmark Change  */
	NULL,	/* UE RAB Preconfiguration */
	NULL,	/* cdma2000 Classmark Change */
	NULL,	/* Inter System to UTRAN Handover Command */
	NULL,	/* Inter System to cdma2000 Handover Command */

	NULL,	/* System Information Type 8 */
	dtap_rr_sys_info_1,	/* System Information Type 1 */
	dtap_rr_sys_info_2,	/* System Information Type 2 */
	dtap_rr_sys_info_3,	/* System Information Type 3 */
	dtap_rr_sys_info_4,	/* System Information Type 4 */
	dtap_rr_sys_info_5,	/* System Information Type 5 */
	dtap_rr_sys_info_6,	/* System Information Type 6 */
	NULL,	/* System Information Type 7 */

	dtap_rr_sys_info_2bis,	/* System Information Type 2bis */
	dtap_rr_sys_info_2ter,	/* System Information Type 2ter */
	dtap_rr_sys_info_2quater,	/* System Information Type 2quater */
	dtap_rr_sys_info_5bis,	/* System Information Type 5bis */
	dtap_rr_sys_info_5ter,	/* System Information Type 5ter */
	NULL,	/* System Information Type 9 */
	dtap_rr_sys_info_13,	/* System Information Type 13 */

	NULL,	/* System Information Type 16 */
	NULL,	/* System Information Type 17 */

	NULL,	/* System Information Type 18 */
	NULL,	/* System Information Type 19 */
	NULL,	/* System Information Type 20 */

	dtap_rr_ch_mode_mod,	/* Channel Mode Modify */
	dtap_rr_rr_status,	/* RR Status */
	dtap_rr_ch_mode_mod_ack,	/* Channel Mode Modify Acknowledge */
	NULL,	/* Frequency Redefinition */
	dtap_rr_meas_rep,		/* 9.1.21 Measurement report */
	dtap_rr_mm_cm_change,	/* 9.1.11 Classmark Change */
	dtap_rr_cm_enq,	/* Classmark Enquiry */
	NULL,	/* Extended Measurement Report */
	NULL,	/* Extended Measurement Order */
	dtap_rr_gprs_sus_req,	/* 9.1.13b GPRS Suspension Request */

	NULL,	/* VGCS Uplink Grant */
	NULL,	/* Uplink Release */
	NULL,	/* Reserved */
	NULL,	/* Uplink Busy */
	NULL,	/* Talker Indication */

	NULL,	/* UTRAN Classmark Change/Handover To UTRAN Command */	/* spec conflict */

	NULL,	/* Application Information */

	NULL,	/* NONE */
};

void get_rr_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn)
{
	gint			idx;

	*msg_str = match_strval_idx((guint32) (oct & DTAP_RR_IEI_MASK), gsm_a_dtap_msg_rr_strings, &idx);
	*ett_tree = ett_gsm_dtap_msg_rr[idx];
	*hf_idx = hf_gsm_a_dtap_msg_rr_type;
	*msg_fcn = dtap_msg_rr_fcn[idx];

	return;
}
/* This is more or less a copy of the dissect_dtap() code just adding
 * L2 Pseudo Length decoding first
 * The code should probably be cleaned up.
 * The name CCCH might not be correct!
 */
static void
dissect_ccch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

	static gsm_a_tap_rec_t	tap_rec[4];
	static gsm_a_tap_rec_t	*tap_p;
	static guint			tap_current=0;

	void			(*msg_fcn)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len);
	guint8			oct;
	guint8			pd;
	guint32			offset, saved_offset;
	guint32			len;
	guint32			oct_1, oct_2;
	proto_item		*ccch_item = NULL;
	proto_tree		*ccch_tree = NULL;
	proto_item		*oct_1_item = NULL;
	proto_tree		*pd_tree = NULL;
	proto_tree		*saved_tree = NULL;
	const gchar		*msg_str;
	gint			ett_tree;
	gint			ti;
	int				hf_idx;
	gboolean		nsd;
	guint8			pseudo_len;
	guint32			curr_offset;
	guint32			consumed;
	guint			curr_len;

	len = tvb_length(tvb);

	if (len < 2){
		/*
		 * too short to be CCCH
		 */
		call_dissector(data_handle, tvb, pinfo, tree);
		return;
	}

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_str(pinfo->cinfo, COL_INFO, "(CCCH) ");
	}
	/*
	 * set tap record pointer
	 */
	tap_current++;
	if (tap_current >= 4)
	{
		tap_current = 0;
	}
	tap_p = &tap_rec[tap_current];

	offset = 0;
	oct_2 = 0;

	/* Skip pseeudo hdr here */
	offset = 1;

	/*
	 * get protocol discriminator
	 */
	oct_1 = tvb_get_guint8(tvb, offset++);

	if ((((oct_1 & DTAP_TI_MASK) >> 4) & DTAP_TIE_PRES_MASK) == DTAP_TIE_PRES_MASK){
		/*
		 * eventhough we don't know if a TI should be in the message yet
		 * we rely on the TI/SKIP indicator to be 0 to avoid taking this
		 * octet
		 */
		oct_2 = tvb_get_guint8(tvb, offset++);
	}

	oct = tvb_get_guint8(tvb, offset);

	pd = oct_1 & DTAP_PD_MASK;
	ti = -1;
	msg_str = NULL;
	ett_tree = -1;
	hf_idx = -1;
	msg_fcn = NULL;
	nsd = FALSE;
	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ",val_to_str(pd,gsm_a_pd_short_str_vals,"Unknown (%u)"));
	}

	/*
	 * octet 1
	 */
	switch (pd){
	case 6:
		get_rr_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn);
		break;

	default:
		/* XXX - hf_idx is still -1! this is a bug in the implementation, and I don't know how to fix it so simple return here */
		return;
	}

	/*
	 * create the protocol tree
	 */
	if (msg_str == NULL){
		ccch_item = proto_tree_add_protocol_format(tree, proto_a_ccch, tvb, 0, len,
			"GSM CCCH - Message Type (0x%02x)",
			oct);

		ccch_tree = proto_item_add_subtree(ccch_item, ett_ccch_msg);
	}else{
		ccch_item = proto_tree_add_protocol_format(tree, proto_a_ccch, tvb, 0, -1,
			"GSM CCCH - %s", msg_str);

		ccch_tree = proto_item_add_subtree(ccch_item, ett_tree);
	}

	if (check_col(pinfo->cinfo, COL_INFO)){
		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", msg_str);
	}

	/* back to the begining */
	saved_offset = offset;
	offset = 0;

	curr_offset = offset;
	curr_len = len;
	len = 1;

	/*	L2 Pseudo Length 10.5.2.19 */
	pseudo_len = tvb_get_guint8(tvb,offset)>>2;

	saved_tree = tree;
	tree = ccch_tree;
	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_L2_PSEUDO_LEN);
	tree = saved_tree;
	offset = saved_offset;

	oct_1_item =
	proto_tree_add_text(ccch_tree,
		tvb, 1, 1,
		"Protocol Discriminator: %s",
		val_to_str(pd, protocol_discriminator_vals, "Unknown (%u)"));

	pd_tree = proto_item_add_subtree(oct_1_item, ett_ccch_oct_1);

	if (ti == -1){
		proto_tree_add_item(pd_tree, hf_gsm_a_skip_ind, tvb, 1, 1, FALSE);
	}else{
		other_decode_bitfield_value(a_bigbuf, oct_1, 0x80, 8);
		proto_tree_add_text(pd_tree,tvb, 1, 1,
			"%s :  TI flag: %s",
			a_bigbuf,
			((oct_1 & 0x80) ?  "allocated by receiver" : "allocated by sender"));

		if ((ti & DTAP_TIE_PRES_MASK) == DTAP_TIE_PRES_MASK){
			/* ti is extended to next octet */
			other_decode_bitfield_value(a_bigbuf, oct_1, 0x70, 8);
			proto_tree_add_text(pd_tree, tvb, 1, 1,
				"%s :  TIO: The TI value is given by the TIE in octet 2",
				a_bigbuf);
		}else{
			other_decode_bitfield_value(a_bigbuf, oct_1, 0x70, 8);
			proto_tree_add_text(pd_tree,tvb, 1, 1,
				"%s :  TIO: %u",a_bigbuf,ti & DTAP_TIE_PRES_MASK);
		}
	}

	proto_tree_add_item(pd_tree, hf_gsm_a_L3_protocol_discriminator, tvb, 1, 1, FALSE);

	if ((ti != -1) && (ti & DTAP_TIE_PRES_MASK) == DTAP_TIE_PRES_MASK){
		proto_tree_add_item(tree, hf_gsm_a_extension, tvb, 2, 1, FALSE);
		other_decode_bitfield_value(a_bigbuf, oct_2, DTAP_TIE_MASK, 8);
		proto_tree_add_text(pd_tree, tvb, 2, 1,
			"%s :  TIE: %u", a_bigbuf, oct_2 & DTAP_TIE_MASK);
	}

	/*
	 * N(SD)
	 */
	if ((pinfo->p2p_dir == P2P_DIR_RECV) &&
		nsd)
	{
		/* XXX */
	}

	/*
	 * add DTAP message name
	 */
	proto_tree_add_uint_format(ccch_tree, hf_idx, tvb, offset, 1, oct,
		"Message Type: %s",msg_str ? msg_str : "(Unknown)");

	offset++;

	tap_p->pdu_type = GSM_A_PDU_TYPE_DTAP;
	tap_p->message_type = (nsd ? (oct & 0x3f) : oct);
	tap_p->protocol_disc = pd;

	tap_queue_packet(gsm_a_tap, pinfo, tap_p);

	if (msg_str == NULL)
		return;

	if ((len - offset) <= 0)
		return;

	/*
	 * decode elements
	 */
	if (msg_fcn == NULL){
		proto_tree_add_text(ccch_tree, tvb, offset, len - offset,
			"Message Elements");
	}else{
		(*msg_fcn)(tvb, ccch_tree, offset, len - offset);
	}
}

/* Register the protocol with Wireshark */
void
proto_register_gsm_a_rr(void)
{
	guint		i;
	guint		last_offset;

	/* Setup list of header fields */

	static hf_register_info hf[] =
	{
	{ &hf_gsm_a_dtap_msg_rr_type,
		{ "DTAP Radio Resources Management Message Type",	"gsm_a.dtap_msg_rr_type",
		FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_rr_strings), 0x0,
		"", HFILL }
	},
	{ &hf_gsm_a_rr_elem_id,
		{ "Element ID",	"gsm_a_rr.elem_id",
		FT_UINT8, BASE_DEC, NULL, 0,
		"", HFILL }
	},
	{ &hf_gsm_a_bcc,
		{ "BCC","gsm_a.bcc",
		FT_UINT8,BASE_DEC,  NULL, 0x07,
		"BCC", HFILL }
	},
	{ &hf_gsm_a_ncc,
		{ "NCC","gsm_a.ncc",
		FT_UINT8,BASE_DEC,  NULL, 0x38,
		"NCC", HFILL }
	},
	{ &hf_gsm_a_bcch_arfcn,
		{ "BCCH ARFCN(RF channel number)","gsm_a.bcch_arfcn",
		FT_UINT16,BASE_DEC,  NULL, 0x0,
		"BCCH ARFCN", HFILL }
	},
	{ &hf_gsm_a_rr_ho_ref_val,
		{ "Handover reference value","gsm_a.rr.ho_ref_val",
		FT_UINT8,BASE_DEC,  NULL, 0x0,
		"Handover reference value", HFILL }
	},
	{ &hf_gsm_a_rr_L2_pseudo_len,
		{ "L2 Pseudo Length value","gsm_a.rr.rr_2_pseudo_len",
		FT_UINT8, BASE_DEC, NULL, 0xfc,
		"L2 Pseudo Length value", HFILL }
	},
	{ &hf_gsm_a_rr_ba_used,
		{ "BA-USED","gsm_a.rr.ba_used",
		FT_UINT8,BASE_DEC,  NULL, 0x80,
		"BA-USED", HFILL }
	},
	{ &hf_gsm_a_rr_dtx_used,
		{ "DTX-USED","gsm_a.rr.dtx_used",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_dtx_vals), 0x40,
		"DTX-USED", HFILL }
	},
	{ &hf_gsm_a_rr_3g_ba_used,
	{ "3G-BA-USED","gsm_a.rr.3g_ba_used",
		FT_UINT8, BASE_DEC, NULL, 0x80,
		"3G-BA-USED", HFILL }
	},
	{ &hf_gsm_a_rr_meas_valid,
		{ "MEAS-VALID","gsm_a.rr.meas_valid",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_mv_vals), 0x40,
		"MEAS-VALID", HFILL }
	},
	{ &hf_gsm_a_rr_rxlev_full_serv_cell,
		{ "RXLEV-FULL-SERVING-CELL","gsm_a.rr.rxlev_full_serv_cell",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_rxlev_vals), 0x3f,
		"RXLEV-FULL-SERVING-CELL", HFILL }
	},
	{ &hf_gsm_a_rr_rxlev_sub_serv_cell,
		{ "RXLEV-SUB-SERVING-CELL","gsm_a.rr.rxlev_sub_serv_cell",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_rxlev_vals), 0x3f,
		"RXLEV-SUB-SERVING-CELL", HFILL }
	},
	{ &hf_gsm_a_rr_rxqual_full_serv_cell,
		{ "RXQUAL-FULL-SERVING-CELL","gsm_a.rr.rxqual_full_serv_cell",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_rxqual_vals), 0x70,
		"RXQUAL-FULL-SERVING-CELL", HFILL }
	},
	{ &hf_gsm_a_rr_rxqual_sub_serv_cell,
		{ "RXQUAL-SUB-SERVING-CELL","gsm_a.rr.rxqual_sub_serv_cell",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_rxqual_vals), 0x0e,
		"RXQUAL-SUB-SERVING-CELL", HFILL }
	},
	{ &hf_gsm_a_rr_no_ncell_m,
		{ "NO-NCELL-M","gsm_a.rr.no_ncell_m",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_ncell_vals), 0x00,
		"NO-NCELL-M", HFILL }
	},
	{ &hf_gsm_a_rr_rxlev_ncell,
		{ "RXLEV-NCELL","gsm_a.rr.rxlev_ncell",
		FT_UINT8,BASE_DEC, NULL, 0x00,
		"RXLEV-NCELL", HFILL }
	},
	{ &hf_gsm_a_rr_bcch_freq_ncell,
		{ "BCCH-FREQ-NCELL","gsm_a.rr.bcch_freq_ncell",
		FT_UINT8,BASE_DEC, NULL, 0x00,
		"BCCH-FREQ-NCELL", HFILL }
	},
	{ &hf_gsm_a_rr_bsic_ncell,
		{ "BSIC-NCELL","gsm_a.rr.bsic_ncell",
		FT_UINT8,BASE_DEC, NULL, 0x00,
		"BSIC-NCELL", HFILL }
	},
	{ &hf_gsm_a_rr_mobile_time_difference,
		{ "Mobile Timing Difference value (in half bit periods)","gsm_a.rr.mobile_time_difference",
		FT_UINT32,BASE_DEC, NULL, 0xFFFFF8,
		"Mobile Timing Difference value (in half bit periods)", HFILL }
	},
	{ &hf_gsm_a_rr_pow_cmd_atc,
		{ "ATC","gsm_a.rr.pow_cmd_atc",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_pow_cmd_atc_value), 0x80,
		"ATC", HFILL }
	},
	{ &hf_gsm_a_rr_page_mode,
		{ "Page Mode","gsm_a.rr.page_mode",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_page_mode_vals), 0x03,
		"Page Mode", HFILL }
	},
	{ &hf_gsm_a_rr_dedicated_mode_or_tbf,
		{ "Dedicated mode or TBF","gsm_a.rr.dedicated_mode_or_tbf",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_dedicated_mode_or_tbf_vals), 0x70,
		"Dedicated mode or TBF", HFILL }
	},
	{ &hf_gsm_a_rr_pow_cmd_epc,
		{ "EPC_mode","gsm_a.rr.pow_cmd_epc",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_pow_cmd_epc_value), 0x40,
		"EPC_mode", HFILL }
	},
	{ &hf_gsm_a_rr_pow_cmd_fpcepc,
		{ "FPC_EPC","gsm_a.rr.pow_cmd_fpcepc",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_pow_cmd_fpcepc_value), 0x20,
		"FPC_EPC", HFILL }
	},
	{ &hf_gsm_a_rr_pow_cmd_powlev,
		{ "POWER LEVEL","gsm_a.rr.pow_cmd_pow",
		FT_UINT8,BASE_DEC,  NULL, 0x1f,
		"POWER LEVEL", HFILL }
	},
	{ &hf_gsm_a_rr_sync_ind_nci,
		{ "Normal cell indication(NCI)","gsm_a.rr.sync_ind_nci",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_sync_ind_nci_value), 0x08,
		"Normal cell indication(NCI)", HFILL }
	},
	{ &hf_gsm_a_rr_sync_ind_rot,
		{ "Report Observed Time Difference(ROT)","gsm_a.rr.sync_ind_rot",
		FT_BOOLEAN,8,  TFS(&sm_a_rr_sync_ind_rot_value), 0x04,
		"Report Observed Time Difference(ROT)", HFILL }
	},
	{ &hf_gsm_a_rr_sync_ind_si,
		{ "Synchronization indication(SI)","gsm_a.rr_sync_ind_si",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_sync_ind_si_vals), 0x03,
		"Synchronization indication(SI)", HFILL }
	},
	{ &hf_gsm_a_rr_format_id,
		{ "Format Identifier","gsm_a.rr_format_id",
		FT_UINT8,BASE_HEX,  VALS(gsm_a_rr_freq_list_format_id_vals), 0xce,
		"Format Identifier", HFILL }
	},
	{ &hf_gsm_a_rr_channel_mode,
		{ "Channel Mode","gsm_a.rr.channel_mode",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_channel_mode_vals), 0x0,
		"Channel Mode", HFILL }
	},
	{ &hf_gsm_a_rr_channel_mode2,
		{ "Channel Mode 2","gsm_a.rr.channel_mode2",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_channel_mode2_vals), 0x0,
		"Channel Mode 2", HFILL }
	},
	{ &hf_gsm_a_rr_sc,
		{ "SC","gsm_a.rr.SC",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_sc_vals), 0x1,
		"SC", HFILL }
	},
	{ &hf_gsm_a_algorithm_id,
		{ "Algorithm identifier","gsm_a.algorithm_identifier",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_algorithm_identifier_vals), 0xe,
		"Algorithm_identifier", HFILL }
	},
	{ &hf_gsm_a_rr_cr,
		{ "CR","gsm_a.rr.CR",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_cr_vals), 0x1,
		"CR", HFILL }
	},
	{ &hf_gsm_a_rr_multirate_speech_ver,
		{ "Multirate speech version","gsm_a.rr.multirate_speech_ver",
		FT_UINT8,BASE_DEC,  VALS(multirate_speech_ver_vals), 0xe0,
		"Multirate speech version", HFILL }
	},
	{ &hf_gsm_a_rr_NCSB,
		{ "NSCB: Noise Suppression Control Bit","gsm_a.rr.NCSB",
		FT_UINT8,BASE_DEC,  VALS(NSCB_vals), 0x10,
		"NSCB: Noise Suppression Control Bit", HFILL }
	},
	{ &hf_gsm_a_rr_ICMI,
		{ "ICMI: Initial Codec Mode Indicator","gsm_a.rr.ICMI",
		FT_UINT8,BASE_DEC,  VALS(ICMI_vals), 0x8,
		"ICMI: Initial Codec Mode Indicator", HFILL }
	},
	{ &hf_gsm_a_rr_start_mode,
		{ "Start Mode","gsm_a.rr.start_mode",
		FT_UINT8,BASE_DEC,  NULL, 0x3,
		"Start Mode", HFILL }
	},
	{ &hf_gsm_a_rr_timing_adv,
		{ "Timing advance value","gsm_a.rr.timing_adv",
		FT_UINT8,BASE_DEC,  NULL, 0x0,
		"Timing advance value", HFILL }
	},
	{ &hf_gsm_a_rr_time_diff,
		{ "Time difference value","gsm_a.rr.time_diff",
		FT_UINT8,BASE_DEC,  NULL, 0x0,
		"Time difference value", HFILL }
	},
	{ &hf_gsm_a_rr_tlli,
		{ "TLLI","gsm_a.rr.tlli",
		FT_UINT32,BASE_HEX,  NULL, 0x0,
		"TLLI", HFILL }
	},
	{ &hf_gsm_a_rr_target_mode,
		{ "Target mode","gsm_a.rr.target_mode",
		FT_UINT8,BASE_DEC,  NULL, 0xc0,
		"Target mode", HFILL }
	},
	{ &hf_gsm_a_rr_wait_indication,
		{ "Wait Indication","gsm_a.rr.wait_indication",
		FT_UINT8,BASE_DEC,  NULL, 0x00,
		"Wait Indication (T3122/T3142)", HFILL }
	},
	{ &hf_gsm_a_rr_group_cipher_key_number,
		{ "Group cipher key number","gsm_a.rr.Group_cipher_key_number",
		FT_UINT8,BASE_DEC,  NULL, 0x3c,
		"Group cipher key number", HFILL }
	},
	{ &hf_gsm_a_rr_MBMS_broadcast,
		{ "MBMS Broadcast","gsm_a.rr.MBMS_broadcast",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_MBMS_broadcast_value), 0x01,
		"MBMS Broadcast", HFILL }
	},
	{ &hf_gsm_a_rr_MBMS_multicast,
		{ "MBMS Multicast","gsm_a.rr.MBMS_multicast",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_MBMS_multicast_value), 0x02,
		"MBMS Multicast", HFILL }
	},
	{ &hf_gsm_a_rr_last_segment,
		{ "Last Segment","gsm_a.rr.last_segment",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_last_segment_value), 0x01,
		"Last Segment", HFILL }
	},
	{ &hf_gsm_a_rr_ra,
		{ "Random Access Information (RA)", "gsm_a_rr_ra",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Random Access Information (RA)", HFILL }
	},
	{ &hf_gsm_a_rr_T1prim,
		{ "T1'",		   "gsm_a.rr.T1prim",
		FT_UINT8, BASE_DEC, NULL, 0xf8,
		"T1'", HFILL }
	},
	{ &hf_gsm_a_rr_T3,
		{ "T3",		   "gsm_a.rr.T3",
		FT_UINT16, BASE_DEC, NULL, 0x07e0,
		"T3", HFILL }
	},
	{ &hf_gsm_a_rr_T2,
		{ "T2",		   "gsm_a.rr.T2",
		FT_UINT8, BASE_DEC, NULL, 0x1f,
		"T2", HFILL }
	},
	{ &hf_gsm_a_rr_rfn,
		{ "RFN",		   "gsm_a.rr.rfn",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"Reduced Frame Number", HFILL }
	},
	{ &hf_gsm_a_rr_RR_cause,
		{ "RR cause value","gsm_a.rr.RRcause",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_RR_cause_vals), 0x0,
		"RR cause value", HFILL }
		},
	{ &hf_gsm_a_rr_cm_cng_msg_req,
		{ "CLASSMARK CHANGE","gsm_a.rr_cm_cng_msg_req",
		FT_BOOLEAN,8,  TFS(&gsm_a_msg_req_value), 0x80,
		"CLASSMARK CHANGE ", HFILL }
	},
	{ &hf_gsm_a_rr_utran_cm_cng_msg_req,
		{ "UTRAN CLASSMARK CHANGE","gsm_a.rr_utran_cm_cng_msg_req",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_utran_cm_cng_msg_req_vals), 0x70,
		"UTRAN CLASSMARK CHANGE", HFILL }
	},
	{ &hf_gsm_a_rr_cdma200_cm_cng_msg_req,
		{ "CDMA2000 CLASSMARK CHANGE ","gsm_a.rr_cdma200_cm_cng_msg_req",
		FT_BOOLEAN,8,  TFS(&gsm_a_msg_req_value), 0x08,
		"CDMA2000 CLASSMARK CHANGE ", HFILL }
	},
	{ &hf_gsm_a_rr_geran_iu_cm_cng_msg_req,
		{ "GERAN IU MODE CLASSMARK CHANGE","gsm_a.rr_geran_iu_cm_cng_msg_req",
		FT_BOOLEAN,8,  TFS(&gsm_a_msg_req_value), 0x04,
		"GERAN IU MODE CLASSMARK CHANGE", HFILL }
	},
	{ &hf_gsm_a_rr_chnl_needed_ch1,
		{ "Channel 1","gsm_a.rr_chnl_needed_ch1",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_channel_needed_vals), 0x03,
		"Channel 1", HFILL }
	},
	{ &hf_gsm_a_rr_chnl_needed_ch2,
		{ "Channel 2","gsm_a.rr_chnl_needed_ch1",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_channel_needed_vals), 0x0c,
		"Channel 2", HFILL }
	},
	{ &hf_gsm_a_rr_suspension_cause,
		{ "Suspension cause value","gsm_a.rr.suspension_cause",
		FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_suspension_cause_vals), 0x0,
		"Suspension cause value", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b8,
	  { "12,2 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b8",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x80,
		"12,2 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b7,
	  { "10,2 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b7",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x40,
		"10,2 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b6,
	  { "7,95 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b6",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x20,
		"7,95 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b5,
	  { "7,40 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b5",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x10,
		"7,40 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b4,
	  { "6,70 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b4",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x08,
		"6,70 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b3,
	  { "5,90 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b3",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x04,
		"5,90 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b2,
	  { "5,15 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b2",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x02,
		"5,15 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b1,
	  { "4,75 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b1",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x01,
		"4,75 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b5,
	  { "23,85 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b5",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x10,
		"23,85 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b4,
	  { "15,85 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b4",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x08,
		"15,85 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b3,
	  { "12,65 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b3",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x04,
		"12,65 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b2,
	  { "8,85 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b2",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x02,
		"8,85 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b1,
	  { "6,60 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b1",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x01,
		"6,60 kbit/s codec rate", HFILL }
	},
	{ &hf_gsm_a_rr_amr_threshold,
	  { "AMR Threshold", "gsm_a.rr.amr_threshold",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_amr_threshold_vals), 0x00,
		"AMR Threshold", HFILL }
	},
	{ &hf_gsm_a_rr_amr_hysteresis,
	  { "AMR Hysteresis", "gsm_a.rr.amr_hysteresis",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_amr_hysteresis_vals), 0x00,
		"AMR Hysteresis", HFILL }
	},
	{ &hf_gsm_a_rr_pwrc,
	  { "PWRC", "gsm_a.rr.pwrc",
		FT_BOOLEAN, 8,  NULL, 0x40,
		"Power Control Indicator (PWRC)", HFILL }
	},
	{ &hf_gsm_a_rr_dtx_bcch,
	  { "DTX (BCCH)", "gsm_a.rr.dtx_bcch",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_dtx_bcch_vals), 0x30,
		"Discontinuous Tranmission (DTX-BCCH)", HFILL }
	},
	{ &hf_gsm_a_rr_dtx_sacch,
	  { "DTX (SACCH)", "gsm_a.rr.dtx_sacch",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_dtx_sacch_vals), 0xb0,
		"Discontinuous Tranmission (DTX-SACCH)", HFILL }
	},
	{ &hf_gsm_a_rr_radio_link_timeout,
	  { "Radio Link Timeout", "gsm_a.rr.radio_link_timeout",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_radio_link_timeout_vals), 0x0f,
		"Radio Link Timeout (s)", HFILL }
	},
	{ &hf_gsm_a_rr_cell_reselect_hyst,
	  { "Cell Reselection Hysteresis", "gsm_a.rr.cell_reselect_hyst",
		FT_UINT8, BASE_DEC,  NULL, 0xe0,
		"Cell Reslection Hysteresis (dB)", HFILL }
	},
	{ &hf_gsm_a_rr_ms_txpwr_max_cch,
	  { "MS TXPWR MAX CCH", "gsm_a.rr.ms_txpwr_max_cch",
		FT_UINT8, BASE_DEC,  NULL, 0x1f,
		"MS TXPWR MAX CCH", HFILL }
	},
	{ &hf_gsm_a_rr_acs,
	  { "ACS", "gsm_a.rr.acs",
		FT_BOOLEAN, 8,  NULL, 0x80,
		"Additional Reselect Param Indicator (ACS)", HFILL }
	},
	{ &hf_gsm_a_rr_neci,
	  { "NECI", "gsm_a.rr.neci",
		FT_UINT8, BASE_DEC,  NULL, 0x40,
		"New Establishment Cause Indicator (NECI)", HFILL }
	},
	{ &hf_gsm_a_rr_rxlev_access_min,
	  { "RXLEV-ACCESS-MIN", "gsm_a.rr.rxlev_access_min",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_rxlev_vals), 0x3f,
		"RXLEV-ACCESS-MIN", HFILL }
	},
	{ &hf_gsm_a_rr_mscr,
	  { "MSCR", "gsm_a.rr.mscr",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_mscr_vals), 0x80,
		"MSC Release Indicator (MSCR)", HFILL }
	},
	{ &hf_gsm_a_rr_att,
	  { "ATT", "gsm_a.rr.att",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_att_vals), 0x40,
		"Attach Indicator (ATT)", HFILL }
	},
	{ &hf_gsm_a_rr_bs_ag_blks_res,
	  { "BS_AG_BLKS_RES", "gsm_a.rr.bs_ag_blks_res",
		FT_UINT8, BASE_DEC,  NULL, 0x38,
		"Access Grant Reserved Blocks (BS_AG_BLKS_RES)", HFILL }
	},
	{ &hf_gsm_a_rr_ccch_conf,
	  { "CCCH-CONF", "gsm_a.rr.ccch_conf",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_ccch_conf_vals), 0x07,
		"CCCH-CONF", HFILL }
	},
	{ &hf_gsm_a_rr_cbq3,
	  { "CBQ3", "gsm_a.rr.cbq3",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_cbq3_vals), 0x00,
		"Cell Bar Qualify 3", HFILL }
	},
	{ &hf_gsm_a_rr_bs_pa_mfrms,
	  { "BS-PA-MFRMS", "gsm_a.rr.bs_pa_mfrms",
		FT_UINT8, BASE_DEC,  NULL, 0x07,
		"BS-PA-MFRMS", HFILL }
	},
	{ &hf_gsm_a_rr_t3212,
	  { "T3212", "gsm_a.rr.t3212",
		FT_UINT8, BASE_DEC,  NULL, 0x00,
		"Periodic Update period (T3212) (deci-hours)", HFILL }
	},
	{ &hf_gsm_a_rr_dyn_arfcn_length,
	  { "Length of Dynamic Mapping", "gsm_a.rr.dyn_arfcn_length",
		FT_UINT8, BASE_DEC,  NULL, 0x00,
		"Length of Dynamic Mapping", HFILL }
	},
	{ &hf_gsm_a_rr_gsm_band,
	  { "GSM Band", "gsm_a.rr.gsm_band",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_gsm_band_vals), 0x00,
		"GSM Band", HFILL }
	},
	{ &hf_gsm_a_rr_arfcn_first,
	  { "ARFCN First", "gsm_a.rr.arfcn_first",
		FT_UINT16, BASE_DEC,  NULL, 0x00,
		"ARFCN First", HFILL }
	},
	{ &hf_gsm_a_rr_band_offset,
	  { "Band Offset", "gsm_a.rr.band_offset",
		FT_UINT16, BASE_DEC,  NULL, 0x00,
		"Band Offset", HFILL }
	},
	{ &hf_gsm_a_rr_arfcn_range,
	  { "ARFCN Range", "gsm_a.rr.arfcn_range",
		FT_UINT8, BASE_DEC,  NULL, 0x00,
		"ARFCN Range", HFILL }
	},
	{ &hf_gsm_a_rr_lowest_arfcn,
	  { "Lowest ARFCN", "gsm_a.rr.lowest_arfcn",
		FT_UINT8, BASE_DEC,  NULL, 0x7f,
		"Lowest ARFCN", HFILL }
	},
	{ &hf_gsm_a_rr_inc_skip_arfcn,
	  { "Increment skip ARFCN", "gsm_a.rr.inc_skip_arfcn",
		FT_UINT8, BASE_DEC,  NULL, 0x00,
		"Increment skip ARFCN", HFILL }
	},
	{ &hf_gsm_a_rr_gprs_resumption_ack,
	  { "Ack", "gsm_a.rr.gprs_resumption_ack",
		FT_BOOLEAN, BASE_DEC,  TFS(&gsm_a_rr_gprs_resumption_ack_value), 0x01,
		"GPRS Resumption Ack bit", HFILL }
	},
	{ &hf_gsm_a_rr_ext_ind,
	  { "EXT-IND", "gsm_a.rr.ext_ind",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_ext_ind_vals), 0x20,
		"Extension Indication (EXT-IND)", HFILL }
	},
	{ &hf_gsm_a_rr_ba_ind,
	  { "BA-IND", "gsm_a.rr.ba_ind",
		FT_UINT8, BASE_DEC,  NULL, 0x10,
		"BCCH Allocation Indication (BA-IND)", HFILL }
	},
	{ &hf_gsm_a_rr_multiband_reporting,
	  { "Multiband Reporting", "gsm_a.rr.multiband_reporting",
		FT_UINT8, BASE_DEC,  NULL, 0x00,
		"Number of cells to be reported in each band if Multiband Reporting", HFILL }
	},
	{ &hf_gsm_a_rr_ncc_permitted,
	  { "NCC Permitted", "gsm_a.rr.ncc_permitted",
		FT_UINT8, BASE_HEX,  NULL, 0xff,
		"NCC Permitted", HFILL }
	},
	{ &hf_gsm_a_rr_max_retrans,
	  { "Max retrans", "gsm_a.rr.max_retrans",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_max_retrans_vals), 0xc0,
		"Maximum number of retransmissions", HFILL }
	},
	{ &hf_gsm_a_rr_tx_integer,
	  { "Tx-integer", "gsm_a.rr.tx_integer",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_tx_integer_vals), 0x3c,
		"Number of Slots to spread Transmission (Tx-integer)", HFILL }
	},
	{ &hf_gsm_a_rr_cell_barr_access,
	  { "CELL_BARR_ACCESS", "gsm_a.rr.cell_barr_access",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_cell_barr_access_vals), 0x02,
		"Cell Barred for Access (CELL_BARR_ACCESS)", HFILL }
	},
	{ &hf_gsm_a_rr_re,
	  { "RE", "gsm_a.rr.re",
		FT_BOOLEAN, 8,  NULL, 0x01,
		"Call re-establishment allowed (RE)", HFILL }
	},
	{ &hf_gsm_a_rr_acc,
	  { "ACC", "gsm_a.rr.acc",
		FT_UINT16, BASE_HEX,  NULL, 0xffff,
		"Access Control Class N barred (ACC)", HFILL }
	},
	{ &hf_gsm_a_rr_nch_position,
	  { "NCH Position", "gsm_a.rr.nch_position",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_nch_position_vals), 0x00,
		"NCH Position", HFILL }
	},
	{ &hf_gsm_a_rr_qsearch_i,
	  { "Qsearch I", "gsm_a.rr.qsearch_i",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_qsearch_x_vals), 0x00,
		"Search for 3G cells if signal level is below (0 7) or above (8 15) threshold (Qsearch I)", HFILL }
	},
	{ &hf_gsm_a_rr_fdd_qoffset,
	  { "FDD Qoffset", "gsm_a.rr.fdd_qoffset",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_xdd_qoffset_vals), 0x00,
		"Offset to RLA_C for cell re selection to FDD access technology (FDD Qoffset)", HFILL }
	},
	{ &hf_gsm_a_rr_fdd_qmin,
	  { "FDD Qmin", "gsm_a.rr.fdd_qmin",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_fdd_qmin_vals), 0x00,
		"Minimum threshold for Ec/No for UTRAN FDD cell re-selection (FDD Qmin)", HFILL }
	},
	{ &hf_gsm_a_rr_tdd_qoffset,
	  { "TDD Qoffset", "gsm_a.rr.tdd_qoffset",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_xdd_qoffset_vals), 0x00,
		"Offset to RLA_C for cell re selection to TDD access technology (TDD Qoffset)", HFILL }
	},
	{ &hf_gsm_a_rr_fdd_qmin_offset,
	  { "FDD Qmin Offset", "gsm_a.rr.fdd_qmin_offset",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_fdd_qmin_offset_vals), 0x00,
		"Offset to FDD Qmin value (FDD Qmin Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_fdd_rscpmin,
	  { "FDD RSCPmin", "gsm_a.rr.fdd_rscpmin",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_fdd_rscpmin_vals), 0x00,
		"Minimum threshold of RSCP for UTRAN FDD cell re-selection (FDD RSCPmin)", HFILL }
	},
	{ &hf_gsm_a_rr_gsm_report_type,
	  { "Report Type", "gsm_a.rr.gsm_report_type",
		FT_BOOLEAN, BASE_DEC,  TFS(&gsm_a_rr_gsm_report_type_value), 0x00,
		"Report type the MS shall use (Report Type)", HFILL }
	},
	{ &hf_gsm_a_rr_serving_band_reporting,
	  { "Serving Band Reporting", "gsm_a.rr.serving_band_reporting",
		FT_UINT8, BASE_DEC, NULL, 0x00,
		"Number of cells reported from the GSM serving frequency band (Serving Band Reporting)", HFILL }
	},
	{ &hf_gsm_a_rr_frequency_scrolling,
	  { "Frequency Scrolling", "gsm_a.rr.frequency_scrolling",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_frequency_scrolling_value), 0x00,
		"Frequency Scrolling", HFILL }
	},
	{ &hf_gsm_a_rr_rep_priority,
	  { "Rep Priority", "gsm_a.rr.rep_priority",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_rep_priority_value), 0x00,
		"Reporting Priority", HFILL }
	},
	{ &hf_gsm_a_rr_report_type,
	  { "Report Type", "gsm_a.rr.report_type",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_report_type_value), 0x00,
		"Report Type", HFILL }
	},
	{ &hf_gsm_a_rr_reporting_rate,
	  { "Reporting Rate", "gsm_a.rr.reporting_rate",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_reporting_rate_value), 0x00,
		"Reporting Rate", HFILL }
	},
	{ &hf_gsm_a_rr_invalid_bsic_reporting,
	  { "Invalid BSCI Reporting", "gsm_a.rr.invalid_bsic_reporting",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_invalid_bsic_reporting_value), 0x00,
		"Invalid BSCI Reporting", HFILL }
	},
	{ &hf_gsm_a_rr_scale_ord,
	  { "Scale Ord", "gsm_a.rr.scale_ord",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_scale_ord_vals), 0x00,
		"Offset used for the reported RXLEV values (Scale Ord)", HFILL }
	},
	{ &hf_gsm_a_rr_900_reporting_offset,
	  { "900 Reporting Offset", "gsm_a.rr.900_reporting_offset",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
		"Offset to the reported value when prioritising the cells for reporting for GSM frequency band 900 (900 Reporting Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_900_reporting_threshold,
	  { "900 Reporting Threshold", "gsm_a.rr.900_reporting_threshold",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_threshold_vals), 0x00,
		"Apply priority reporting if the reported value is above threshold for GSM frequency band 900 (900 Reporting Threshold)", HFILL }
	},
	{ &hf_gsm_a_rr_1800_reporting_offset,
	  { "1800 Reporting Offset", "gsm_a.rr.1800_reporting_offset",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
		"Offset to the reported value when prioritising the cells for reporting for GSM frequency band 1800 (1800 Reporting Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_1800_reporting_threshold,
	  { "1800 Reporting Threshold", "gsm_a.rr.1800_reporting_threshold",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_threshold_vals), 0x00,
		"Apply priority reporting if the reported value is above threshold for GSM frequency band 1800 (1800 Reporting Threshold)", HFILL }
	},
	{ &hf_gsm_a_rr_400_reporting_offset,
	  { "400 Reporting Offset", "gsm_a.rr.400_reporting_offset",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
		"Offset to the reported value when prioritising the cells for reporting for GSM frequency band 400 (400 Reporting Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_400_reporting_threshold,
	  { "400 Reporting Threshold", "gsm_a.rr.400_reporting_threshold",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_threshold_vals), 0x00,
		"Apply priority reporting if the reported value is above threshold for GSM frequency band 400 (400 Reporting Threshold)", HFILL }
	},
	{ &hf_gsm_a_rr_1900_reporting_offset,
	  { "1900 Reporting Offset", "gsm_a.rr.1900_reporting_offset",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
		"Offset to the reported value when prioritising the cells for reporting for GSM frequency band 1900 (1900 Reporting Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_1900_reporting_threshold,
	  { "1900 Reporting Threshold", "gsm_a.rr.1900_reporting_threshold",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_threshold_vals), 0x00,
		"Apply priority reporting if the reported value is above threshold for GSM frequency band 1900 (1900 Reporting Threshold)", HFILL }
	},
	{ &hf_gsm_a_rr_850_reporting_offset,
	  { "850 Reporting Offset", "gsm_a.rr.850_reporting_offset",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
		"Offset to the reported value when prioritising the cells for reporting for GSM frequency band 850 (850 Reporting Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_850_reporting_threshold,
	  { "850 Reporting Threshold", "gsm_a.rr.900_reporting_threshold",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_threshold_vals), 0x00,
		"Apply priority reporting if the reported value is above threshold for GSM frequency band 850 (850 Reporting Threshold)", HFILL }
	},
	{ &hf_gsm_a_rr_network_control_order,
	  { "Network Control Order", "gsm_a.rr.network_control_order",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_network_control_order_vals), 0x00,
		"Network Control Order", HFILL }
	},
	{ &hf_gsm_a_rr_nc_non_drx_period,
	  { "NC Non DRX Period", "gsm_a.rr.nc_non_drx_period",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_nc_non_drx_period_vals), 0x00,
		"NC Non DRX Period", HFILL }
	},
	{ &hf_gsm_a_rr_nc_reporting_period_i,
	  { "NC Reporting Period I", "gsm_a.rr.nc_reporting_period_i",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_nc_reporting_period_x_vals), 0x00,
		"NC Reporting Period in Packet Idle mode (NC Reporting Period I)", HFILL }
	},
	{ &hf_gsm_a_rr_nc_reporting_period_t,
	  { "NC Reporting Period T", "gsm_a.rr.nc_reporting_period_t",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_nc_reporting_period_x_vals), 0x00,
		"NC Reporting Period in Packet Transfer mode (NC Reporting Period T)", HFILL }
	},
	{ &hf_gsm_a_rr_qsearch_c_initial,
	  { "QSearch C Initial", "gsm_a.rr.qsearch_c_initial",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_qsearch_c_initial_value), 0x00,
		"Qsearch value to be used in connected mode before Qsearch C is received (QSearch C Initial)", HFILL }
	},
	{ &hf_gsm_a_rr_fdd_rep_quant,
	  { "FDD Rep Quant", "gsm_a.rr.fdd_rep_quant",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_fdd_rep_quant_value), 0x00,
		"FDD Reporting Quantity (FDD Rep Quant)", HFILL }
	},
	{ &hf_gsm_a_rr_fdd_multirat_reporting,
	  { "FDD Multirat Reporting", "gsm_a.rr.fdd_multirat_reporting",
		FT_UINT8, BASE_DEC, NULL, 0x00,
		"Number of cells from the FDD access technology that shall be included in the list of strongest cells or in the measurement report (FDD Multirat Reporting)", HFILL }
	},
	{ &hf_gsm_a_rr_tdd_multirat_reporting,
	  { "TDD Multirat Reporting", "gsm_a.rr.tdd_multirat_reporting",
		FT_UINT8, BASE_DEC, NULL, 0x00,
		"Number of cells from the TDD access technology that shall be included in the list of strongest cells or in the measurement report (TDD Multirat Reporting)", HFILL }
	},
	{ &hf_gsm_a_rr_qsearch_p,
	  { "Qsearch P", "gsm_a.rr.qsearch_p",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_qsearch_x_vals), 0x00,
		"Search for 3G cells if signal level below threshold (Qsearch P)", HFILL }
	},
	{ &hf_gsm_a_rr_3g_search_prio,
	  { "3G Search Prio", "gsm_a.rr.3g_search_prio",
		FT_BOOLEAN, BASE_DEC,  TFS(&gsm_a_rr_3g_search_prio_value), 0x00,
		"3G Search Priority", HFILL }
	},
	{ &hf_gsm_a_rr_fdd_reporting_offset,
	  { "FDD Reporting Offset", "gsm_a.rr.fdd_reporting_offset",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
		"Offset to the reported value when prioritising the cells for reporting for FDD access technology (FDD Reporting Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_fdd_reporting_threshold,
	  { "FDD Reporting Threshold", "gsm_a.rr.fdd_reporting_threshold",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_xxx_reporting_threshold_vals), 0x00,
		"Apply priority reporting if the reported value is above threshold for FDD access technology (FDD Reporting Threshold)", HFILL }
	},
	{ &hf_gsm_a_rr_tdd_reporting_offset,
	  { "TDD Reporting Offset", "gsm_a.rr.tdd_reporting_offset",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
		"Offset to the reported value when prioritising the cells for reporting for TDD access technology (TDD Reporting Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_tdd_reporting_threshold,
	  { "TDD Reporting Threshold", "gsm_a.rr.tdd_reporting_threshold",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_xxx_reporting_threshold_vals), 0x00,
		"Apply priority reporting if the reported value is above threshold for TDD access technology (TDD Reporting Threshold)", HFILL }
	},
	{ &hf_gsm_a_rr_fdd_reporting_threshold_2,
	  { "FDD Reporting Threshold 2", "gsm_a.rr.fdd_reporting_threshold_2",
		FT_UINT8, BASE_DEC,  NULL, 0x00,
		"Reporting threshold for the CPICH parameter (Ec/No or RSCP) that is not reported according to FDD_REP_QUANT (FDD Reporting Threshold 2)", HFILL }
	},
	{ &hf_gsm_a_rr_3g_ccn_active,
	  { "3G CCN Active", "gsm_a.rr.3g_ccn_active",
		FT_BOOLEAN, BASE_DEC,  TFS(&gsm_a_rr_3g_ccn_active_value), 0x00,
		"3G CCN Active", HFILL }
	},
	{ &hf_gsm_a_rr_700_reporting_offset,
	  { "700 Reporting Offset", "gsm_a.rr.700_reporting_offset",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
		"Offset to the reported value when prioritising the cells for reporting for GSM frequency band 700 (700 Reporting Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_700_reporting_threshold,
	  { "700 Reporting Threshold", "gsm_a.rr.700_reporting_threshold",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_threshold_vals), 0x00,
		"Apply priority reporting if the reported value is above threshold for GSM frequency band 700 (700 Reporting Threshold)", HFILL }
	},
	{ &hf_gsm_a_rr_810_reporting_offset,
	  { "810 Reporting Offset", "gsm_a.rr.810_reporting_offset",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
		"Offset to the reported value when prioritising the cells for reporting for GSM frequency band 810 (810 Reporting Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_810_reporting_threshold,
	  { "810 Reporting Threshold", "gsm_a.rr.810_reporting_threshold",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_threshold_vals), 0x00,
		"Apply priority reporting if the reported value is above threshold for GSM frequency band 810 (810 Reporting Threshold)", HFILL }
	},
	{ &hf_gsm_a_rr_cbq,
	  { "CBQ", "gsm_a.rr.cbq",
		FT_UINT8, BASE_DEC,  NULL, 0x00,
		"Cell Bar Qualify", HFILL }
	},
	{ &hf_gsm_a_rr_cell_reselect_offset,
	  { "Cell Reselect Offset", "gsm_a.rr.cell_reselect_offset",
		FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_cell_reselect_offset_vals), 0x00,
		"Offset to the C2 reselection criterion (Cell Reselect Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_temporary_offset,
		{ "Temporary Offset", "gsm_a.rr.temporary_offset",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_temporary_offset_vals), 0x0,
		"Negative offset to C2 for the duration of Penalty Time (Temporary Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_penalty_time,
		{ "Penalty Time", "gsm_a.rr.penalty_time",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_penalty_time_vals), 0x0,
		"Duration for which the temporary offset is applied (Penalty Time)", HFILL }
	},
	{ &hf_gsm_a_rr_si13_position,
		{ "SI13 Position", "gsm_a.rr.si13_position",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_si13_position_vals), 0x0,
		"SI13 Position", HFILL }
	},
	{ &hf_gsm_a_rr_power_offset,
		{ "Power Offset", "gsm_a.rr.power_offset",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_power_offset_vals), 0x0,
		"Power offset used in conjunction with the MS TXPWR MAX CCH parameter by the class 3 DCS 1800 MS (Power Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_si2quater_position,
		{ "SI2quater Position", "gsm_a.rr.si2quater_position",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_si2quater_position_value), 0x0,
		"SI2quater Position", HFILL }
	},
	{ &hf_gsm_a_rr_si13alt_position,
		{ "SI13alt Position", "gsm_a.rr.si13alt_position",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_si13alt_position_value), 0x0,
		"SI13alt Position", HFILL }
	},
	{ &hf_gsm_a_rr_prio_thr,
		{ "Prio Thr", "gsm_a.rr.prio_thr",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_prio_thr_vals), 0x0,
		"Prio signal strength threshold is related to RXLEV ACCESS_MIN (Prio Thr)", HFILL }
	},
	{ &hf_gsm_a_rr_lsa_offset,
		{ "LSA Offset", "gsm_a.rr.lsa_offset",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_lsa_offset_vals), 0x0,
		"Offset to be used for LSA cell re selection between cells with the same LSA priorities (LSA Offset)", HFILL }
	},
	{ &hf_gsm_a_rr_paging_channel_restructuring,
		{ "Paging Channel Restructuring", "gsm_a.rr.paging_channel_restructuring",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_paging_channel_restructuring_value), 0x0,
		"Paging Channel Restructuring", HFILL }
	},
	{ &hf_gsm_a_rr_nln_sacch,
		{ "NLN (SACCH)", "gsm_a.rr.nln_sacch",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"NLN (SACCH)", HFILL }
	},
	{ &hf_gsm_a_rr_nln_status_sacch,
		{ "NLN Status (SACCH)", "gsm_a.rr.nln_status_sacch",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"NLN Status (SACCH)", HFILL }
	},
	{ &hf_gsm_a_rr_vbs_vgcs_inband_notifications,
		{ "Inband Notifications", "gsm_a.rr.vbs_vgcs_inband_notifications",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_vbs_vgcs_inband_notifications_value), 0x0,
		"Inband Notifications", HFILL }
	},
	{ &hf_gsm_a_rr_vbs_vgcs_inband_pagings,
		{ "Inband Pagings", "gsm_a.rr.vbs_vgcs_inband_pagings",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_vbs_vgcs_inband_pagings_value), 0x0,
		"Inband Pagings", HFILL }
	},
	{ &hf_gsm_a_rr_rac,
		{ "RAC", "gsm_a.rr.rac",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Routeing Area Code", HFILL }
	},
	{ &hf_gsm_a_rr_max_lapdm,
		{ "Max LAPDm", "gsm_a.rr.max_lapdm",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_max_lapdm_vals), 0x0,
		"Maximum number of LAPDm frames on which a layer 3 can be segmented into and be sent on the main DCCH (Max LAPDm)", HFILL }
	},
	{ &hf_gsm_a_rr_gprs_ms_txpwr_max_ccch,
	  { "GPRS MS TxPwr Max CCH", "gsm_a.rr.gprs_ms_txpwr_max_cch",
		FT_UINT8, BASE_DEC,  NULL, 0x00,
		"GPRS MS TxPwr Max CCH", HFILL }
	},
	{ &hf_gsm_a_rr_dedicated_mode_mbms_notification_support,
		{ "Dedicated Mode MBMS Notification Support", "gsm_a.rr.dedicated_mode_mbms_notification_support",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_dedicated_mode_mbms_notification_support_value), 0x0,
		"Dedicated Mode MBMS Notification Support", HFILL }
	},
	{ &hf_gsm_a_rr_mnci_support,
		{ "MNCI Support", "gsm_a.rr.mnci_support",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_mnci_support_value), 0x0,
		"MBMS Neighbouring Cell Information Support (MNCI Support)", HFILL }
	},
	{ &hf_gsm_a_rr_amr_config,
		{ "AMR Configuration", "gsm_a.rr.amr_config",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"AMR Configuration", HFILL }
	},
	{ &hf_gsm_a_rr_bcch_change_mark,
		{ "BCCH Change Mark", "gsm_a.rr.bcch_change_mark",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"BCCH Change Mark", HFILL }
	},
	{ &hf_gsm_a_rr_si_change_field,
		{ "SI Change Field", "gsm_a.rr.si_change_field",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_si_change_field_vals), 0x0,
		"SI Change Field", HFILL }
	},
	{ &hf_gsm_a_rr_si13_change_mark,
		{ "SI13 Change Mark", "gsm_a.rr.si13_change_mark",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"SI13 Change Mark", HFILL }
	},
	{ &hf_gsm_a_rr_hsn,
		{ "HSN", "gsm_a.rr.hsn",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Hopping Sequence Number (HSN)", HFILL }
	},
	{ &hf_gsm_a_rr_rfl_number,
		{ "RFL Number", "gsm_a.rr.rfl_number",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Radio Frequency List Number (RFL Number)", HFILL }
	},
	{ &hf_gsm_a_rr_arfcn_index,
		{ "ARFCN Index", "gsm_a.rr.arfcn_index",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"ARFCN Index", HFILL }
	},
	{ &hf_gsm_a_rr_ma_length,
		{ "MA Length", "gsm_a.rr.ma_length",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Mobile Allocation Length (MA Length)", HFILL }
	},
	{ &hf_gsm_a_rr_psi1_repeat_period,
		{ "PSI1 Repeat Period", "gsm_a.rr.psi1_repeat_period",
		FT_UINT8, BASE_DEC, VALS(&gsm_a_rr_psi1_repeat_period_vals), 0x0,
		"PSI1 Repeat Period", HFILL }
	},
	{ &hf_gsm_a_rr_pbcch_pb,
		{ "Pb", "gsm_a.rr.pbcch_pb",
		FT_UINT8, BASE_DEC, VALS(&gsm_a_rr_pbcch_pb_vals), 0x0,
		"Power reduction on PBCCH/PCCCH (Pb)", HFILL }
	},
	{ &hf_gsm_a_rr_pbcch_tsc,
		{ "TSC", "gsm_a.rr.pbcch_tsc",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Training Sequence Code for PBCCH (TSC)", HFILL }
	},
	{ &hf_gsm_a_rr_pbcch_tn,
		{ "TN", "gsm_a.rr.pbcch_tn",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Timeslot Number for PCCH (TN)", HFILL }
	},
	{ &hf_gsm_a_rr_spgc_ccch_sup,
		{ "SPGC CCCH Sup", "gsm_a.rr.spgc_ccch_sup",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_spgc_ccch_sup_value), 0x0,
		"Split PG Cycle Code on CCCH Support (SPGC CCCH Sup)", HFILL }
	},
	{ &hf_gsm_a_rr_priority_access_thr,
		{ "Priority Access Thr", "gsm_a.rr.priority_access_thr",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_priority_access_thr_vals), 0x0,
		"Priority Access Threshold for packet access (Priority Access Thr)", HFILL }
	},
	{ &hf_gsm_a_rr_nmo,
		{ "NMO", "gsm_a.rr.nmo",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_nmo_vals), 0x0,
		"Network mode of Operation (NMO)", HFILL }
	},
	{ &hf_gsm_a_rr_t3168,
		{ "T3168", "gsm_a.rr.t3168",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_t3168_vals), 0x0,
		"T3168", HFILL }
	},
	{ &hf_gsm_a_rr_t3192,
		{ "T3192", "gsm_a.rr.t3192",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_t3192_vals), 0x0,
		"T3192", HFILL }
	},
	{ &hf_gsm_a_rr_drx_timer_max,
		{ "DRX Timer Max", "gsm_a.rr.drx_timer_max",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_drx_timer_max_vals), 0x0,
		"Discontinous Reception Timer Max (DRX Timer Max)", HFILL }
	},
	{ &hf_gsm_a_rr_access_burst_type,
		{ "Access Burst Type", "gsm_a.rr.access_burst_type",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_access_burst_type_value), 0x0,
		"Format used in the PACKET CHANNEL REQUEST message, the PS HANDOVER ACCESS message, the PTCCH uplink block and in the PACKET CONTROL ACKNOWLEDGMENT message (Access Burst Type)", HFILL }
	},
	{ &hf_gsm_a_rr_control_ack_type,
		{ "Control Ack Type", "gsm_a.rr.control_ack_type",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_control_ack_type_value), 0x0,
		"Default format of the PACKET CONTROL ACKNOWLEDGMENT message (Control Ack Type)", HFILL }
	},
	{ &hf_gsm_a_rr_bs_cv_max,
		{ "BS CV Max", "gsm_a.rr.bs_cv_max",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Base Station Countdown Value Maximum (BS CV Max)", HFILL }
	},
	{ &hf_gsm_a_rr_pan_dec,
		{ "PAN Dec", "gsm_a.rr.pan_dec",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"PAN Dec", HFILL }
	},
	{ &hf_gsm_a_rr_pan_inc,
		{ "PAN Inc", "gsm_a.rr.pan_inc",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"PAN Inc", HFILL }
	},
	{ &hf_gsm_a_rr_pan_max,
		{ "PAN Max", "gsm_a.rr.pan_max",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_pan_max_vals), 0x0,
		"PAN Max", HFILL }
	},
	{ &hf_gsm_a_rr_egprs_packet_channel_request,
		{ "EGPRS Packet Channel Request", "gsm_a.rr.egprs_packet_channel_request",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_egprs_packet_channel_request_value), 0x0,
		"EGPRS Packet Channel Request", HFILL }
	},
	{ &hf_gsm_a_rr_bep_period,
		{ "BEP Period", "gsm_a.rr.bep_period",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_bep_period_vals), 0x0,
		"BEP Period", HFILL }
	},
	{ &hf_gsm_a_rr_pfc_feature_mode,
		{ "PFC Feature Mode", "gsm_a.rr.pfc_feature_mode",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_pfc_feature_mode_value), 0x0,
		"Packet Flow Context Feature Mode (PFC Feature Mode)", HFILL }
	},
	{ &hf_gsm_a_rr_dtm_support,
		{ "DTM Support", "gsm_a.rr.dtm_support",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_dtm_support_value), 0x0,
		"Dual Transfer Mode Support (DTM Support)", HFILL }
	},
	{ &hf_gsm_a_rr_bss_paging_coordination,
		{ "BSS Paging Coordination", "gsm_a.rr.bss_paging_coordination",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_bss_paging_coordination_value), 0x0,
		"BSS Paging Coordination", HFILL }
	},
	{ &hf_gsm_a_rr_ccn_active,
		{ "CCN Active", "gsm_a.rr.ccn_active",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_ccn_active_value), 0x0,
		"CCN Active", HFILL }
	},
	{ &hf_gsm_a_rr_nw_ext_utbf,
		{ "NW Ext UTBF", "gsm_a.rr.nw_ext_utbf",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_nw_ext_utbf_value), 0x0,
		"Network Extended Uplink TBF (NW Ext UTBF)", HFILL }
	},
	{ &hf_gsm_a_rr_multiple_tbf_capability,
		{ "Multiple TBF Capability", "gsm_a.rr.multiple_tbf_capability",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_multiple_tbf_capability_value), 0x0,
		"Multiple TBF Capability", HFILL }
	},
	{ &hf_gsm_a_rr_ext_utbf_no_data,
		{ "Ext UTBF No Data", "gsm_a.rr.ext_utbf_no_data",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_ext_utbf_no_data_value), 0x0,
		"Ext UTBF No Data", HFILL }
	},
	{ &hf_gsm_a_rr_dtm_enhancements_capability,
		{ "DTM Enhancements Capability", "gsm_a.rr.dtm_enhancements_capability",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_dtm_enhancements_capability_value), 0x0,
		"DTM Enhancements Capability", HFILL }
	},
	{ &hf_gsm_a_rr_reduced_latency_access,
		{ "Reduced Latency Access", "gsm_a.rr.reduced_latency_access",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_reduced_latency_access_value), 0x0,
		"Reduced Latency Access", HFILL }
	},
	{ &hf_gsm_a_rr_alpha,
		{ "Alpha", "gsm_a.rr.alpha",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_alpha_vals), 0x0,
		"Alpha parameter for GPR MS output power control (Alpha)", HFILL }
	},
	{ &hf_gsm_a_rr_t_avg_w,
		{ "T Avg W", "gsm_a.rr.t_avg_w",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_t_avg_x_vals), 0x0,
		"Signal strength filter period for power control in packet idle mode ", HFILL }
	},
	{ &hf_gsm_a_rr_t_avg_t,
		{ "T Avg T", "gsm_a.rr.t_avg_t",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_t_avg_x_vals), 0x0,
		"Signal strength filter period for power control in packet transfer mode ", HFILL }
	},
	{ &hf_gsm_a_rr_pc_meas_chan,
		{ "PC Meas Chan", "gsm_a.rr.pc_meas_chan",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_pc_meas_chan_value), 0x0,
		"Channel used to measure the received power level on the downlink for the purpose of the uplink power control (PC Meas Chan)", HFILL }
	},
	{ &hf_gsm_a_rr_n_avg_i,
		{ "N Avg I", "gsm_a.rr.n_avg_i",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_n_avg_i_vals), 0x0,
		"Interfering signal strength filter constant for power control (N Avg I)", HFILL }
	},
	{ &hf_gsm_a_rr_sgsnr,
		{ "SGSNR", "gsm_a.rr.sgsnr",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_sgsnr_value), 0x0,
		"SGSN Release (SGSNR)", HFILL }
	},
	{ &hf_gsm_a_rr_si_status_ind,
		{ "SI Status Ind", "gsm_a.rr.si_status_ind",
		FT_BOOLEAN, BASE_DEC, TFS(&gsm_a_rr_si_status_ind_value), 0x0,
		"SI Status Ind", HFILL }
	},
	{ &hf_gsm_a_rr_lb_ms_txpwr_max_cch,
		{ "LB MS TxPwr Max CCCH", "gsm_a.rr.n_avg_i",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_n_avg_i_vals), 0x0,
		"Maximum TX power level an MS is allowed to use on all other than DCS 1800 and PCS 1900 frequency bands when accessing the system until otherwise commanded (LB MS TxPwr Max CCCH)", HFILL }
	},
	{ &hf_gsm_a_rr_si2n_support,
		{ "SI2n Support", "gsm_a.rr.si2n_support",
		FT_UINT8, BASE_DEC, VALS(gsm_a_rr_si2n_support_vals), 0x0,
		"SI2n Support", HFILL }
	},
	{ &hf_gsm_a_rr_t1prime,
		{ "T1'", "gsm_a.rr.t1prime",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"T1'", HFILL }
	},
	{ &hf_gsm_a_rr_t3,
		{ "T3", "gsm_a.rr.t3",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"T3", HFILL }
	},
	{ &hf_gsm_a_rr_t2,
		{ "T2", "gsm_a.rr.t2",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"T2", HFILL }
	}
	};

	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	2
	static gint *ett[NUM_INDIVIDUAL_ELEMS +
			NUM_GSM_DTAP_MSG_RR +
			NUM_GSM_RR_ELEM +
			NUM_GSM_RR_REST_OCTETS_ELEM];

	ett[0] = &ett_ccch_msg;
	ett[1] = &ett_ccch_oct_1;

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i < NUM_GSM_DTAP_MSG_RR; i++, last_offset++)
	{
		ett_gsm_dtap_msg_rr[i] = -1;
		ett[last_offset] = &ett_gsm_dtap_msg_rr[i];
	}

	for (i=0; i < NUM_GSM_RR_ELEM; i++, last_offset++)
	{
		ett_gsm_rr_elem[i] = -1;
		ett[last_offset] = &ett_gsm_rr_elem[i];
	}

	for (i=0; i < NUM_GSM_RR_REST_OCTETS_ELEM; i++, last_offset++)
	{
		ett_gsm_rr_rest_octets_elem[i] = -1;
		ett[last_offset] = &ett_gsm_rr_rest_octets_elem[i];
	}

	/* Register the protocol name and description */
	proto_a_ccch =
		proto_register_protocol("GSM CCCH", "GSM CCCH", "gsm_a_ccch");

	proto_register_field_array(proto_a_ccch, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	register_dissector("gsm_a_ccch", dissect_ccch, proto_a_ccch);
}

void
proto_reg_handoff_gsm_a_rr(void)
{
}
