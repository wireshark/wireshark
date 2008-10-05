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
/* [3]  10.5.2.14b	Group Channel Description
 * [3]  10.5.2.14c	GPRS Resumption
 * [3]  10.5.2.14d	GPRS broadcast information
 * [3]  10.5.2.14e	Enhanced DTM CS Release Indication
 */
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
/* [3] 10.5.2.33 SI 2bis Rest Octets
 * [3] 10.5.2.33a SI 2ter Rest Octets
 * [3] 10.5.2.33b SI 2quater Rest Octets
 */
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
static int hf_gsm_a_rr_bs_pa_mfrms = -1;
static int hf_gsm_a_rr_bs_ag_blks_res = -1;
static int hf_gsm_a_rr_t3212 = -1;
static int hf_gsm_a_rr_ext_ind = -1;
static int hf_gsm_a_rr_ba_ind = -1;
static int hf_gsm_a_rr_multiband_reporting = -1;
static int hf_gsm_a_rr_ncc_permitted = -1;
static int hf_gsm_a_rr_max_retrans = -1;
static int hf_gsm_a_rr_tx_integer = -1;
static int hf_gsm_a_rr_cell_barr_access = -1;
static int hf_gsm_a_rr_re = -1;
static int hf_gsm_a_rr_acc = -1;

/* Initialize the subtree pointers */
static gint ett_ccch_msg = -1;
static gint ett_ccch_oct_1 = -1;

static char a_bigbuf[1024];

static dissector_handle_t data_handle;

typedef enum
{
	/* Radio Resource Management Information Elements 10.5.2, most are from 10.5.1	*/
/*
 * [3]  10.5.2.1a	BA Range
 */
	DE_RR_CELL_CH_DSC,				/* [3]  10.5.2.1b	Cell Channel Description	*/

/* [3]  10.5.2.1c	BA List Pref
 * [3]  10.5.2.1d	UTRAN Frequency List
 * [3]  10.5.2.1e	Cell selection indicator after release of all TCH and SDCCH IE
 */
	DE_RR_CELL_DSC,					/* 10.5.2.2   RR Cell Description				*/
	DE_RR_CELL_OPT_BCCH,				/* [3]  10.5.2.3	Cell Options (BCCH)		*/
	DE_RR_CELL_OPT_SACCH,				/* [3]  10.5.2.3a	Cell Options (SACCH)		*/
	DE_RR_CELL_SEL_PARAM,				/* [3]  10.5.2.4	Cell Selection Parameters		*/
/*
 * [3]  10.5.2.4a	(void)
 */
	DE_RR_CH_DSC,					/* [3]  10.5.2.5	Channel Description			*/
	DE_RR_CH_DSC2,					/* [3]  10.5.2.5a   Channel Description 2 		*/
	DE_RR_CH_MODE,					/* [3]  10.5.2.6	Channel Mode				*/
	DE_RR_CH_MODE2,					/* [3]  10.5.2.7	Channel Mode 2				*/
/* [3]  10.5.2.7a	UTRAN predefined configuration status information / START-CS / UE CapabilityUTRAN Classmark information element	218
 * [3]  10.5.2.7b	(void) */
	DE_RR_CM_ENQ_MASK,				/* [3]  10.5.2.7c	Classmark Enquiry Mask		*/
/* [3]  10.5.2.7d	GERAN Iu Mode Classmark information element						*/
	DE_RR_CHNL_NEEDED,				/* [3]  10.5.2.8	Channel Needed
 * [3]  10.5.2.8a	(void)
 * [3]  10.5.2.8b	Channel Request Description 2 */
	DE_RR_CIP_MODE_SET,				/* [3]  10.5.2.9	Cipher Mode Setting			*/
	DE_RR_CIP_MODE_RESP,			/* [3]  10.5.2.10	Cipher Response			 */
	DE_RR_CTRL_CH_DESC,		/* [3]  10.5.2.11	Control Channel Description	*/
/* [3]  10.5.2.11a	DTM Information Details */
	DE_RR_DYN_ARFCN_MAP,			/* [3]  10.5.2.11b	Dynamic ARFCN Mapping		*/
	DE_RR_FREQ_CH_SEQ,				/* [3]  10.5.2.12	Frequency Channel Sequence	*/
	DE_RR_FREQ_LIST,				/* [3]  10.5.2.13	Frequency List				*/
	DE_RR_FREQ_SHORT_LIST,			/* [3]  10.5.2.14	Frequency Short List		*/
	DE_RR_FREQ_SHORT_LIST2,			/* [3]  10.5.2.14a	Frequency Short List 2		*/
/* [3]  10.5.2.14b	Group Channel Description
 * [3]  10.5.2.14c	GPRS Resumption
 * [3]  10.5.2.14d	GPRS broadcast information
 * [3]  10.5.2.14e	Enhanced DTM CS Release Indication
 */

	DE_RR_HO_REF,					/* 10.5.2.15  Handover Reference				*/

	DE_RR_IA_REST_OCT,					/* [3] 10.5.2.16 IA Rest Octets				*/
	DE_RR_IAR_REST_OCT,					/* [3] 10.5.2.17 IAR Rest Octets				*/
	DE_RR_IAX_REST_OCT,					/* [3] 10.5.2.18 IAX Rest Octets				*/
	DE_RR_L2_PSEUDO_LEN,			/*	[3] 10.5.2.19 L2 Pseudo Length				*/
	DE_RR_MEAS_RES,					/* [3] 10.5.2.20 Measurement Results		*/
 /* [3] 10.5.2.20a GPRS Measurement Results */
	DE_RR_MOB_ALL,					/* [3] 10.5.2.21 Mobile Allocation				*/
	DE_RR_MOB_TIME_DIFF,			/* [3] 10.5.2.21a Mobile Time Difference		*/
	DE_RR_MULTIRATE_CONF,			/* [3] 10.5.2.21aa MultiRate configuration		*/
	DE_RR_MULT_ALL,					/* [3] 10.5.2.21b Multislot Allocation			*/
/*
 * [3] 10.5.2.21c NC mode
 */
	DE_RR_NEIGH_CELL_DESC,				/* [3] 10.5.2.22 Neighbour Cell Description	*/
	DE_RR_NEIGH_CELL_DESC2,				/* [3] 10.5.2.22a Neighbour Cell Description 2	*/
/*
 * [3] 10.5.2.22b (void)
 * [3] 10.5.2.22c NT/N Rest Octets
 * [3] 10.5.2.23 P1 Rest Octets
 * [3] 10.5.2.24 P2 Rest Octets
 * [3] 10.5.2.25 P3 Rest Octets */
	DE_RR_PACKET_CH_DESC,				/* [3] 10.5.2.25a Packet Channel Description	*/
	DE_RR_DED_MOD_OR_TBF,			/* [3] 10.5.2.25b Dedicated mode or TBF			*/
/* [3] 10.5.2.25c RR Packet Uplink Assignment
 * [3] 10.5.2.25d RR Packet Downlink Assignment */
	DE_RR_PAGE_MODE,				/* [3] 10.5.2.26 Page Mode						*/
/* [3] 10.5.2.26a (void)
 * [3] 10.5.2.26b (void)
 * [3] 10.5.2.26c (void)
 * [3] 10.5.2.26d (void)
 */
	DE_RR_NCC_PERM,					/* [3] 10.5.2.27 NCC Permitted */
	DE_RR_POW_CMD,					/* 10.5.2.28  Power Command						*/
	DE_RR_POW_CMD_AND_ACC_TYPE,		/* 10.5.2.28a Power Command and access type		*/
	DE_RR_RACH_CTRL_PARAM,			/* [3] 10.5.2.29 RACH Control Parameters */
	DE_RR_REQ_REF,					/* [3] 10.5.2.30 Request Reference				*/
	DE_RR_CAUSE,					/* 10.5.2.31  RR Cause							*/
	DE_RR_SYNC_IND,					/* 10.5.2.39  Synchronization Indication		*/
	DE_RR_SI1_REST_OCT,				/* [3] 10.5.2.32 SI1 Rest Octets */
/* [3] 10.5.2.33 SI 2bis Rest Octets
 * [3] 10.5.2.33a SI 2ter Rest Octets
 * [3] 10.5.2.33b SI 2quater Rest Octets
 */
	DE_RR_SI3_REST_OCT,				/* [3] 10.5.2.34 SI3 Rest Octets */
	DE_RR_SI4_REST_OCT,				/* [3] 10.5.2.35 SI4 Rest Octets */
	DE_RR_SI6_REST_OCT,				/* [3] 10.5.2.35a SI6 Rest Octets */
/* [3] 10.5.2.36 SI 7 Rest Octets
 * [3] 10.5.2.37 SI 8 Rest Octets
 * [3] 10.5.2.37a SI 9 Rest Octets
 */
	DE_RR_SI13_REST_OCT,				/* [3] 10.5.2.37b SI13 Rest Octets */
/* [3] 10.5.2.37c (void)
 * [3] 10.5.2.37d (void)
 * [3] 10.5.2.37e SI 16 Rest Octets
 * [3] 10.5.2.37f SI 17 Rest Octets
 * [3] 10.5.2.37g SI 19 Rest Octets
 * [3] 10.5.2.37h SI 18 Rest Octets
 * [3] 10.5.2.37i SI 20 Rest Octets */
	DE_RR_STARTING_TIME,			/* [3] 10.5.2.38 Starting Time					*/
	DE_RR_TIMING_ADV,				/* [3] 10.5.2.40 Timing Advance					*/
	DE_RR_TIME_DIFF,				/* [3] 10.5.2.41 Time Difference				*/
	DE_RR_TLLI,						/* [3] 10.5.2.41a TLLI							*/
/*
 * [3] 10.5.2.42 TMSI/P-TMSI */
	DE_RR_VGCS_TAR_MODE_IND,		/* [3] 10.5.2.42a VGCS target mode Indication	*/
	DE_RR_VGCS_CIP_PAR,				/* [3] 10.5.2.42b	VGCS Ciphering Parameters	*/

	DE_RR_WAIT_IND,					/* [3] 10.5.2.43 Wait Indication */
/* [3] 10.5.2.44 SI10 rest octets $(ASCI)$
 * [3] 10.5.2.45 EXTENDED MEASUREMENT RESULTS
 * [3] 10.5.2.46 Extended Measurement Frequency List */
	DE_RR_SUS_CAU,					/* [3] 10.5.2.47 Suspension Cause				*/
/* [3] 10.5.2.48 APDU ID
 * [3] 10.5.2.49 APDU Flags
 * [3] 10.5.2.50 APDU Data
 * [3] 10.5.2.51 Handover To UTRAN Command
 * [3] 10.5.2.52 Handover To cdma2000 Command
 * [3] 10.5.2.53 (void)
 * [3] 10.5.2.54 (void)
 * [3] 10.5.2.55 (void)
 * [3] 10.5.2.56 3G Target Cell */
	DE_RR_SERV_SUP,					/* 10.5.2.57 Service Support						*/
/* 10.5.2.58 MBMS p-t-m Channel Description
 */

	DE_RR_DED_SERV_INF,				/* [3] 10.5.2.59	Dedicated Service Information */

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
	DE_RR_NONE							/* NONE */
}
rr_elem_idx_t;

#define	NUM_GSM_RR_ELEM (sizeof(gsm_rr_elem_strings)/sizeof(value_string))
gint ett_gsm_rr_elem[NUM_GSM_RR_ELEM];

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

static int f_k(int k, int *w, int range)
{
	int index=k, j=1, n;

	/* J := GREATEST_POWER_OF_2_LESSER_OR_EQUAL_TO(INDEX); */
	if (index>1) {
		do {
			j<<=1;
		} while (j<=index);
		j >>= 1;
	}

   n = w[index];

   while (index>1) {
	   if (2*index < 3*j) {			 /* left child */
			index -= j>>1;
			n = (n + w[index] - range/j - 1)%((2*range/j) - 1) + 1;
	   }
	   else {						   /* right child */
			index -= j;
			n = (n + w[index] - 1)%((2*range)/j - 1) + 1;
		}
		j >>= 1;
	}

	return n%1024;
}

static void dissect_channel_list_n_range(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, int range)
{
	int curr_offset=offset, f0, arfcn_orig, bits, w[64], wsize, i, wi;
	int octet, nwi=1, jwi=0, wbits, imax, iused, arfcn;
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
			tvb, curr_offset, 2,
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

static guint8
de_rr_cell_opt_bcch(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint8	oct;
	guint8	rlt;
	guint32	curr_offset;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	rlt = ((1+(oct&0x0f))<<2); /* Radio Link Timeout is in units of 4 frames, starting at 4 */
	item = proto_tree_add_text(tree, tvb, curr_offset, 1,
		gsm_rr_elem_strings[DE_RR_CELL_OPT_BCCH].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_CELL_OPT_BCCH]);

	proto_tree_add_item(subtree, hf_gsm_a_rr_pwrc, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_dtx_bcch, tvb, curr_offset, 1, FALSE);
	proto_tree_add_uint(subtree, hf_gsm_a_rr_radio_link_timeout, tvb, curr_offset, 1, rlt);

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
	guint8	rlt;
	guint32	curr_offset;

	curr_offset = offset;

	oct = tvb_get_guint8(tvb, curr_offset);
	dtx = ((oct&0x80)>>5)|((oct&0x30)>>4); /* DTX is a split filed in bits 8, 6 and 5 */
	rlt = ((1+(oct&0x0f))<<2); /* Radio Link Timeout is in units of 4 frames, starting at 4 */
	item = proto_tree_add_text(tree, tvb, curr_offset, 1,
		gsm_rr_elem_strings[DE_RR_CELL_OPT_SACCH].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_CELL_OPT_SACCH]);

	proto_tree_add_item(subtree, hf_gsm_a_rr_pwrc, tvb, curr_offset, 1, FALSE);
	proto_tree_add_uint(subtree, hf_gsm_a_rr_dtx_sacch, tvb, curr_offset, 1, dtx);
	proto_tree_add_uint(subtree, hf_gsm_a_rr_radio_link_timeout, tvb, curr_offset, 1, rlt);

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
	item = proto_tree_add_text(tree, tvb, curr_offset, 2,
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

	item = proto_tree_add_text(tree,tvb, curr_offset, 3,gsm_rr_elem_strings[DE_RR_CH_DSC].strptr);

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

	item = proto_tree_add_text(tree,tvb, curr_offset, 3,gsm_rr_elem_strings[DE_RR_CH_DSC2].strptr);

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

static guint8
de_rr_ctrl_ch_desc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint8	oct;
	guint32	curr_offset;

	curr_offset = offset;

	item = proto_tree_add_text(tree, tvb, curr_offset, 3,
		gsm_rr_elem_strings[DE_RR_CTRL_CH_DESC].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_CTRL_CH_DESC]);

	proto_tree_add_item(subtree, hf_gsm_a_rr_mscr, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_att, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_bs_ag_blks_res, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(subtree, hf_gsm_a_rr_ccch_conf, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;
	oct = tvb_get_guint8(tvb, curr_offset);

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
static guint8
de_rr_dyn_arfcn_map(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

	curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, len,"Dynamic ARFCN Mapping content(Not decoded)");

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

	curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, 9,"Frequency Channel Sequence(Not decoded)");

	curr_offset = curr_offset + 9;

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
	guint32	curr_offset;

	curr_offset = offset;

	/* FORMAT-ID, Format Identifier (part of octet 3)*/
	proto_tree_add_item(tree, hf_gsm_a_rr_format_id, tvb, curr_offset, 1, FALSE);
	/* Frequency list */
	proto_tree_add_text(tree,tvb, curr_offset, 9,"Frequency Data(Not decoded)");

	curr_offset = curr_offset + 9;
	return(curr_offset - offset);

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
	guint32	curr_offset;

	curr_offset = offset;

	/* FORMAT-ID, Format Identifier (part of octet 3)*/
	proto_tree_add_item(tree, hf_gsm_a_rr_format_id, tvb, curr_offset, 1, FALSE);

	/* Frequency list */
	proto_tree_add_text(tree,tvb, curr_offset, 7,"Frequency Data(Not decoded)");

	curr_offset = curr_offset + 8;
	return(curr_offset - offset);

}
/*
 * [3] 10.5.2.14b Group Channel Description
 * [3] 10.5.2.14c GPRS Resumption
 * [3] 10.5.2.14d GPRS broadcast information
 */
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
			tvb, curr_offset, 1,
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
			tvb, curr_offset, len,
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
		tvb, curr_offset, 3,
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
		tvb, curr_offset, len,
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

	item = proto_tree_add_text(tree,tvb, curr_offset, 1, gsm_rr_elem_strings[DE_RR_L2_PSEUDO_LEN].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_L2_PSEUDO_LEN]);

	/* L2 Pseudo Length value */
	proto_tree_add_item(subtree, hf_gsm_a_rr_L2_pseudo_len, tvb, curr_offset, 1, FALSE);

	curr_offset = curr_offset + 1;

	return(curr_offset - offset);
}

/*
 * [3] 10.5.2.20 Measurement Results
 */
static const value_string gsm_a_rr_dtx_vals[] = {
	{ 0,	"DTX was not used"},
	{ 1,	"DTX was used"},
	{ 0,	NULL}
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
static const value_string gsm_a_rr_mv_vals[] = {
	{ 0,	"The measurement results are valid"},
	{ 1,	"The measurement results are not valid"},
	{ 0,	NULL}
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
	guint8	oct, nextoct, val;

	curr_offset = offset;

	item =
		proto_tree_add_text(tree,
			tvb, curr_offset, 16,
			gsm_rr_elem_strings[DE_RR_MEAS_RES].strptr);
	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_MEAS_RES]);

	/* 2nd octet */
	oct = tvb_get_guint8(tvb,curr_offset);
	/* BA-USED */
	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,tvb,curr_offset,1,"%s = BA-USED: %d",a_bigbuf,(oct & 0x80)>>7);
	/* DTX USED */
	other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
	proto_tree_add_text(subtree,tvb,curr_offset,1,"%s = DTX USED: %s",a_bigbuf,\
		val_to_str((oct & 0x40)>>6, gsm_a_rr_dtx_vals, "Reserved (0x%02x)"));
	/* RXLEV-FULL-SERVING-CELL */
	other_decode_bitfield_value(a_bigbuf, oct, 0x3F, 8);
	proto_tree_add_text(subtree,tvb,curr_offset,1,"%s = RXLEV-FULL-SERVING-CELL: %s (%d)",a_bigbuf,\
		val_to_str((oct & 0x3F), gsm_a_rr_rxlev_vals, "Reserved (0x%02x)"),(oct & 0x3F));

	curr_offset++;

	/* 3rd octet */
	oct = tvb_get_guint8(tvb,curr_offset);
	/* 3G-BA-USED */
	other_decode_bitfield_value(a_bigbuf, oct, 0x80, 8);
	proto_tree_add_text(subtree,tvb,curr_offset,1,"%s = 3G-BA-USED: %d",a_bigbuf,(oct & 0x80)>>7);
	/* MEAS-VALID */
	other_decode_bitfield_value(a_bigbuf, oct, 0x40, 8);
	proto_tree_add_text(subtree,tvb,curr_offset,1,"%s = MEAS-VALID: %s",a_bigbuf,\
		val_to_str((oct & 0x40)>>6, gsm_a_rr_mv_vals, "Reserved (0x%02x)"));
	/* RXLEV-SUB-SERVING-CELL */
	other_decode_bitfield_value(a_bigbuf, oct, 0x3F, 8);
	proto_tree_add_text(subtree,tvb,curr_offset,1,"%s = RXLEV-SUB-SERVING-CELL: %s (%d)",\
		a_bigbuf,val_to_str((oct & 0x3F), gsm_a_rr_rxlev_vals, "Reserved (0x%02x)"),(oct & 0x3F));

	curr_offset++;

	/* 4th octet */
	oct = tvb_get_guint8(tvb,curr_offset);
	/* RXQUAL-FULL-SERVING-CELL */
	other_decode_bitfield_value(a_bigbuf, oct, 0x70, 8);
	proto_tree_add_text(subtree,tvb,curr_offset,1,"%s = RXQUAL-FULL-SERVING-CELL: %s (%d)",a_bigbuf,\
		val_to_str((oct & 0x7)>>4, gsm_a_rr_rxqual_vals, "Reserved (0x%02x)"),(oct & 0x70)>>4);
	/* RXQUAL-SUB-SERVING-CELL */
	other_decode_bitfield_value(a_bigbuf, oct, 0x0e, 8);
	proto_tree_add_text(subtree,tvb,curr_offset,1,"%s = RXQUAL-SUB-SERVING-CELL: %s (%d)",a_bigbuf,\
		val_to_str((oct & 0x0e)>>1, gsm_a_rr_rxqual_vals, "Reserved (0x%02x)"),(oct & 0x0e)>>1);
	/* NO-NCELL-M */
	nextoct = tvb_get_guint8(tvb,curr_offset+1);
	val = ((oct & 0x01) << 2) + ((nextoct & 0xc0) >> 6);
	other_decode_bitfield_value(a_bigbuf, oct, 0x01, 8);
	proto_tree_add_text(subtree,tvb,curr_offset,1,"%s",a_bigbuf);
	other_decode_bitfield_value(a_bigbuf, nextoct, 0xc0, 8);
	proto_tree_add_text(subtree,tvb,curr_offset+1,1,"%s = NO-NCELL-M: %s (%d)",a_bigbuf,\
		val_to_str(val, gsm_a_rr_ncell_vals, "Reserved (0x%02x)"),val);

	curr_offset = curr_offset + len;
	return(curr_offset - offset);
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

	curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, len ,"Data(Not decoded)");

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

	proto_tree_add_text(tree,tvb, curr_offset, len ,"Data(Not decoded)");

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

guint8
de_rr_multirate_conf(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 oct;

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

		proto_tree_add_text(tree,tvb, curr_offset, len-2 ,"Parameters for multirate speech field(Not decoded)");
		break;
	case 2:
		/* Adaptive Multirate speech version 2 */
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b5, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b4, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b3, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b2, tvb, curr_offset, 1, FALSE);
		proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b1, tvb, curr_offset, 1, FALSE);
		curr_offset++;

		proto_tree_add_text(tree,tvb, curr_offset, len-2 ,"Parameters for multirate speech field(Not decoded)");
		break;
	default:
		proto_tree_add_text(tree,tvb,offset,1,"Unknown version");
		proto_tree_add_text(tree,tvb, curr_offset, len-1 ,"Data(Not decoded)");
		break;
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

	proto_tree_add_item(tree, hf_gsm_a_rr_multiband_reporting, tvb, curr_offset, 1, FALSE);
	proto_tree_add_item(tree, hf_gsm_a_rr_ext_ind, tvb, curr_offset, 1, FALSE);
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

	item = proto_tree_add_text(tree,tvb,curr_offset,3,gsm_rr_elem_strings[DE_RR_PACKET_CH_DESC].strptr);
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
			tvb, curr_offset, 1,
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
			tvb, curr_offset, 1,
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

	item = proto_tree_add_text(tree, tvb, curr_offset, 1,
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
			tvb, curr_offset, 1,
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
			tvb, curr_offset, 1,
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

	item = proto_tree_add_text(tree, tvb, curr_offset, 3,
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
			tvb, curr_offset, 3,
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
static guint8
de_rr_si1_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	len = 1;
	curr_offset = offset;

	item = proto_tree_add_text(tree, tvb, curr_offset, len,
		gsm_rr_elem_strings[DE_RR_SI1_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_SI1_REST_OCT]);

	proto_tree_add_text(subtree,tvb, curr_offset, len ,"Data(Not decoded)");

	curr_offset = curr_offset + len;

	return curr_offset-offset;
}
/*
 * [3] 10.5.2.33 SI 2bis Rest Octets
 * [3] 10.5.2.33a SI 2ter Rest Octets
 * [3] 10.5.2.33b SI 2quater Rest Octets
 */

/*
 * [3] 10.5.2.34 SI 3 Rest Octets
 */
static guint8
de_rr_si3_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	len = 4;
	curr_offset = offset;

	item = proto_tree_add_text(tree, tvb, curr_offset, len,
		gsm_rr_elem_strings[DE_RR_SI3_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_SI3_REST_OCT]);

	proto_tree_add_text(subtree,tvb, curr_offset, len ,"Data(Not decoded)");

	curr_offset = curr_offset + len;

	return curr_offset-offset;
}

/*
 * [3] 10.5.2.32 SI 4 Rest Octets
 */
static guint8
de_rr_si4_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	len = tvb_length_remaining(tvb,offset);
	if (len==0)
		return 0;

	curr_offset = offset;

	item = proto_tree_add_text(tree, tvb, curr_offset, len,
		gsm_rr_elem_strings[DE_RR_SI4_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_SI4_REST_OCT]);

	proto_tree_add_text(subtree,tvb, curr_offset, len ,"Data(Not decoded)");

	curr_offset = curr_offset + len;

	return curr_offset-offset;
}

/*
 * [3] 10.5.2.35a SI 6 Rest Octets
 */
static guint8
de_rr_si6_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	len = 7;
	curr_offset = offset;

	item = proto_tree_add_text(tree, tvb, curr_offset, len,
		gsm_rr_elem_strings[DE_RR_SI6_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_SI6_REST_OCT]);

	proto_tree_add_text(subtree,tvb, curr_offset, len ,"Data(Not decoded)");

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
static guint8
de_rr_si13_rest_oct(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	proto_tree	*subtree;
	proto_item	*item;
	guint32	curr_offset;

	len = 20;
	curr_offset = offset;

	item = proto_tree_add_text(tree, tvb, curr_offset, len,
		gsm_rr_elem_strings[DE_RR_SI13_REST_OCT].strptr);

	subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_SI13_REST_OCT]);

	proto_tree_add_text(subtree,tvb, curr_offset, len ,"Data(Not decoded)");

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

	curr_offset = offset;

	proto_tree_add_text(tree,tvb, curr_offset, 2 ,"Data(Not decoded)");

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
/* [3]  10.5.2.14b	Group Channel Description
 * [3]  10.5.2.14c	GPRS Resumption
 * [3]  10.5.2.14d	GPRS broadcast information
 * [3]  10.5.2.14e	Enhanced DTM CS Release Indication
 */
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
/* [3] 10.5.2.33 SI 2bis Rest Octets
 * [3] 10.5.2.33a SI 2ter Rest Octets
 * [3] 10.5.2.33b SI 2quater Rest Octets
 */
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

	/* 66  Channe l Mode 2			10.5.2.7	O TV 2 */
	/* Mode of the Second Channel */

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
	ELEM_OPT_TLV(0x72,GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, " - Mobile Allocation, before time");

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
	/* ELEM_OPT_TV_SHORT(0xC0, GSM_A_PDU_TYPE_RR, DE_GPRS_RES, ""); */

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
	ELEM_OPT_TLV(0x19,GSM_A_PDU_TYPE_RR, DE_RR_FREQ_SHORT_LIST, " - Frequency Short List, before time");

	/* Frequency List, before time,	Frequency List 10.5.2.13 */
	ELEM_OPT_TV(0x12,GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, " - Frequency List, before time");

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
	ELEM_OPT_TLV(0x77,GSM_A_PDU_TYPE_RR, DE_RR_MOB_TIME_DIFF, "Mobile Observed Time Difference");

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
		tvb, curr_offset, 1,
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

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NCC_PERM);

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_RACH_CTRL_PARAM);
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

	ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC);
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
	NULL,	/* Physical Information */
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

	NULL,	/* System Information Type 2bis */
	NULL,	/* System Information Type 2ter */
	NULL,	/* System Information Type 2quater */
	NULL,	/* System Information Type 5bis */
	NULL,	/* System Information Type 5ter */
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
		FT_UINT8,BASE_DEC,  NULL, 0xfc,
		"L2 Pseudo Length value", HFILL }
	},
	{ &hf_gsm_a_rr_pow_cmd_atc,
		{ "Spare","gsm_a.rr.pow_cmd_atc",
		FT_BOOLEAN,8,  TFS(&gsm_a_rr_pow_cmd_atc_value), 0x80,
		"Spare", HFILL }
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
		FT_UINT8, BASE_DEC,  NULL, 0x0f,
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
		FT_UINT8, BASE_DEC,  NULL, 0x30,
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
	};

	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	2
	static gint *ett[NUM_INDIVIDUAL_ELEMS +
			NUM_GSM_DTAP_MSG_RR +
			NUM_GSM_RR_ELEM];

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
