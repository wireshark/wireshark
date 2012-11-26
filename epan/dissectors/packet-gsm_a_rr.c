 /* packet-gsm_a_rr.c
 * Routines for GSM A Interface (actually A-bis really) RR dissection - A.K.A. GSM layer 3 Radio Resource Protocol
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Added Dissection of Radio Resource Management Information Elements
 * and other enhancements and fixes.
 * Copyright 2005 - 2006, Anders Broman [AT] ericsson.com
 *
 * Title        3GPP            Other
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/tap.h>
#include <epan/asn1.h>
#include <epan/expert.h>
#include "packet-bssap.h"
#include "packet-sccp.h"
#include "packet-ber.h"
#include "packet-q931.h"
#include "packet-gsm_a_common.h"
#include "packet-e212.h"
#include "packet-ppp.h"

static dissector_handle_t rrc_irat_ho_info_handle;
static dissector_handle_t rrc_irat_ho_to_utran_cmd_handle;

#define PADDING_BYTE 0x2B

/* 3GPP TS 44.018 version 11.2.0 Release 11 */
const value_string gsm_a_dtap_msg_rr_strings[] = {
    { 0x3c, "Reserved" },
    { 0x3b, "Additional Assignment" },
    { 0x3f, "Immediate Assignment" },
    { 0x39, "Immediate Assignment Extended" },
    { 0x3a, "Immediate Assignment Reject" },

    { 0x48, "DTM Assignment Failure" },
    { 0x49, "DTM Reject" },
    { 0x4a, "DTM Request" },
    { 0x4b, "Packet Assignment" },
    { 0x4c, "DTM Assignment Command" },
    { 0x4d, "DTM Information" },
    { 0x4e, "Packet Notification" },

    { 0x35, "Ciphering Mode Command" },
    { 0x32, "Ciphering Mode Complete" },

    { 0x30, "Configuration Change Command" },
    { 0x31, "Configuration Change Ack." },
    { 0x33, "Configuration Change Reject" },

    { 0x2e, "Assignment Command" },
    { 0x29, "Assignment Complete" },
    { 0x2f, "Assignment Failure" },
    { 0x2b, "Handover Command" },
    { 0x2c, "Handover Complete" },
    { 0x28, "Handover Failure" },
    { 0x2d, "Physical Information" },

    { 0x08, "RR-cell Change Order" },
    { 0x23, "PDCH Assignment Command" },

    { 0x0d, "Channel Release" },
    { 0x0a, "Partial Release" },
    { 0x0f, "Partial Release Complete" },

    { 0x21, "Paging Request Type 1" },
    { 0x22, "Paging Request Type 2" },
    { 0x24, "Paging Request Type 3" },
    { 0x27, "Paging Response" },
    { 0x20, "Notification/NCH" },
    { 0x25, "Reserved" },
    { 0x26, "Notification/Response" },

    { 0x0b, "Reserved" },

#if 0
/* ETSI TS 101 503 V8.5.0 Seems to give Other def for this Messages??? */
    { 0xc0, "Utran Classmark Change" }, CONFLICTS WITH Handover To UTRAN Command
    { 0xc1, "UE RAB Preconfiguration" },
    { 0xc2, "cdma2000 Classmark Change" },
#endif

    /* ETSI TS 101 503 V8.5.0 */
    { 0x60, "Utran Classmark Change" },
    { 0x62, "cdma2000 Classmark Change" },
    { 0x63, "Inter System to UTRAN Handover Command" },
    { 0x64, "Inter System to cdma2000 Handover Command" },
    { 0x18, "System Information Type 8" },
    { 0x19, "System Information Type 1" },
    { 0x1a, "System Information Type 2" },
    { 0x1b, "System Information Type 3" },
    { 0x1c, "System Information Type 4" },
    { 0x1d, "System Information Type 5" },
    { 0x1e, "System Information Type 6" },
    { 0x1f, "System Information Type 7" },

    { 0x02, "System Information Type 2bis" },
    { 0x03, "System Information Type 2ter" },
    { 0x07, "System Information Type 2quater" },
    { 0x05, "System Information Type 5bis" },
    { 0x06, "System Information Type 5ter" },
    { 0x04, "System Information Type 9" },
    { 0x00, "System Information Type 13" },

    { 0x3d, "System Information Type 16" },
    { 0x3e, "System Information Type 17" },

    { 0x40, "System Information Type 18" },
    { 0x41, "System Information Type 19" },
    { 0x42, "System Information Type 20" },

    { 0x10, "Channel Mode Modify" },
    { 0x12, "RR Status" },
    { 0x17, "Channel Mode Modify Acknowledge" },
    { 0x14, "Frequency Redefinition" },
    { 0x15, "Measurement Report" },
    { 0x16, "Classmark Change" },
    { 0x13, "Classmark Enquiry" },
    { 0x36, "Extended Measurement Report" },
    { 0x37, "Extended Measurement Order" },
    { 0x34, "GPRS Suspension Request" },

    { 0x09, "VGCS Uplink Grant" },
    { 0x0e, "Uplink Release" },
    { 0x0c, "Reserved" },
    { 0x2a, "Uplink Busy" },
    { 0x11, "Talker Indication" },

    { 0xc0, "UTRAN Classmark Change/Handover To UTRAN Command" }, /* spec conflict */

    { 0x38, "Application Information" },

    {    0, NULL }
};

const value_string gsm_rr_elem_strings[] = {
    /* Radio Resource Management Information Elements 10.5.2, most are from 10.5.1 */
    { 0x00, "BA Range" },                               /* [3]  10.5.2.1a BA Range */
    { 0x00, "Cell Channel Description" },               /* [3]  10.5.2.1b */
    { 0x00, "BA List Pref" },                           /* [3]  10.5.2.1c BA List Pref */
    { 0x00, "UTRAN Frequency List" },                   /* [3]  10.5.2.1d UTRAN Frequency List */
    { 0x00, "Cell Selection Indicator after Release of all TCH and SDCCH" },    /* [3]  10.5.2.1e   Cell selection indicator after release of all TCH and SDCCH IE */
    { 0x00, "Cell Description" },                       /* 10.5.2.2  */
    { 0x00, "Cell Options (BCCH)" },                    /* [3]  10.5.2.3    Cell Options (BCCH) */
    { 0x00, "Cell Options (SACCH)" },                   /* [3]  10.5.2.3a   Cell Options (SACCH) */
    { 0x00, "Cell Selection Parameters" },              /* [3]  10.5.2.4    Cell Selection Parameters */
/* [3]  10.5.2.4a   (void) */
    { 0x00, "Channel Description" },                    /* 10.5.2.5  */
    { 0x00, "Channel Description 2" },                  /* 10.5.2.5a */
    { 0x00, "Channel Description 3" },                  /* 10.5.2.5c */
    { 0x00, "Channel Mode" },                           /* [3]  10.5.2.6 */
    { 0x00, "Channel Mode 2" },                         /* [3]  10.5.2.7 */
    { 0x00, "UTRAN Classmark" },                        /* [3]  10.5.2.7a   */
/* [3]  10.5.2.7b   (void) */
    { 0x00, "Classmark Enquiry Mask" },                 /* [3]  10.5.2.7c */
/* [3]  10.5.2.7d   GERAN Iu Mode Classmark information element */
    { 0x00, "Channel Needed"},                          /* [3]  10.5.2.8    */
    /* [3]  10.5.2.8a   (void) */
    { 0x00, "Channel Request Description 2"},           /* [3]  10.5.2.8b   Channel Request Description 2 */
    /* Pos 20 */
    { 0x00, "Cipher Mode Setting" },                    /* [3]  10.5.2.9    */
    { 0x00, "Cipher Mode Response" },                   /* [3]  10.5.2.10   */
    { 0x00, "Control Channel Description" },            /* [3]  10.5.2.11   Control Channel Description */
    { 0x00, "DTM Information Details" },                /* [3]  10.5.2.11a  DTM Information Details */
    { 0x00, "Dynamic ARFCN Mapping" },                  /* [3]  10.5.2.11b  */
    { 0x00, "Frequency Channel Sequence" },             /* [3]  10.5.2.12   */
    { 0x00, "Frequency List" },                         /* 10.5.2.13        */
    { 0x00, "Frequency Short List" },                   /* 10.5.2.14        */
    { 0x00, "Frequency Short List2" },                  /* 10.5.2.14a       */
/* [3]  10.5.2.14b  Group Channel Description */
    { 0x00, "GPRS Resumption" },                        /* [3]  10.5.2.14c  GPRS Resumption */
    { 0x00, "GPRS Broadcast Information" },             /* [3]  10.5.2.14d  GPRS broadcast information */
/* [3]  10.5.2.14e  Enhanced DTM CS Release Indication */
    { 0x00, "Handover Reference" },                     /* 10.5.2.15        */
    { 0x00, "IA Rest Octets" },                         /* [3] 10.5.2.16    */
    { 0x00, "IAR Rest Octets" },                        /* [3] 10.5.2.17 IAR Rest Octets */
    { 0x00, "IAX Rest Octets" },                        /* [3] 10.5.2.18 IAX Rest Octets */
    { 0x00, "L2 Pseudo Length" },                       /* [3] 10.5.2.19    */
    { 0x00, "Measurement Results" },                    /* [3] 10.5.2.20 Measurement Results */
/*
 * [3] 10.5.2.20a GPRS Measurement Results
 */
    { 0x00, "Mobile Allocation" },                      /* [3] 10.5.2.21    */
    { 0x00, "Mobile Time Difference" },                 /* [3] 10.5.2.21a   */
    { 0x00, "MultiRate configuration" },                /* [3] 10.5.2.21aa  */
    /* Pos 30 */
    { 0x00, "Multislot Allocation" },                   /* [3] 10.5.2.21b   */
    /*
     * [3] 10.5.2.21c NC mode
     */
    { 0x00, "Neighbour Cell Description" },             /* [3] 10.5.2.22 Neighbour Cell Description */
    { 0x00, "Neighbour Cell Description 2" },           /* [3] 10.5.2.22a Neighbour Cell Description 2 */
/*
 * [3] 10.5.2.22b (void)
 * [3] 10.5.2.22c NT/N Rest Octets */
    { 0x00, "P1 Rest Octets" },                         /* [3] 10.5.2.23 P1 Rest Octets */
    { 0x00, "P2 Rest Octets" },                         /* [3] 10.5.2.24 P2 Rest Octets */
    { 0x00, "P3 Rest Octets" },                         /* [3] 10.5.2.25 P3 Rest Octets */
    { 0x00, "Packet Channel Description" },             /* [3] 10.5.2.25a   */
    { 0x00, "Dedicated mode or TBF" },                  /* [3] 10.5.2.25b */
    { 0x00, "Packet Uplink Assignment" },               /* [3] 10.5.2.25c RR Packet Uplink Assignment */
    { 0x00, "Packet Downlink Assignment" },             /* [3] 10.5.2.25d RR Packet Downlink Assignment */
    { 0x00, "Packet Downlink Assignment Type 2" },      /* [3] 110.5.2.25e RR Packet Downlink Assignment Type 2 */
    { 0x00, "Page Mode" },                              /* [3] 10.5.2.26  */
    { 0x00, "NCC Permitted" },                          /* [3] 10.5.2.27 NCC Permitted */
    { 0x00, "Power Command" },                          /* 10.5.2.28 */
    { 0x00, "Power Command and access type" },          /* 10.5.2.28a */
    { 0x00, "RACH Control Parameters" },                /* [3] 10.5.2.29 RACH Control Parameters */
    { 0x00, "Request Reference" },                      /* [3] 10.5.2.30 Request Reference */
    { 0x00, "RR Cause" },                               /* 10.5.2.31 */
    { 0x00, "Synchronization Indication" },             /* 10.5.2.39 */
    { 0x00, "SI 1 Rest Octets" },                       /* [3] 10.5.2.32 */
/* [3] 10.5.2.33 SI 2bis Rest Octets */
    { 0x00, "SI 2ter Rest Octets" },                    /* [3] 10.5.2.33a */
    { 0x00, "SI 2quater Rest Octets" },                 /* [3] 10.5.2.33b */
    { 0x00, "SI 3 Rest Octets" },                       /* [3] 10.5.2.34 */
    { 0x00, "SI 4 Rest Octets" },                       /* [3] 10.5.2.35 */
    { 0x00, "SI 6 Rest Octets" },                       /* [3] 10.5.2.35a */
/* [3] 10.5.2.36 SI 7 Rest Octets
 * [3] 10.5.2.37 SI 8 Rest Octets
 * [3] 10.5.2.37a SI 9 Rest Octets
 */
    { 0x00, "SI 13 Rest Octets" },                      /* [3] 10.5.2.37b */
/* [3] 10.5.2.37c (void)
 * [3] 10.5.2.37d (void)
 * [3] 10.5.2.37e SI 16 Rest Octets
 * [3] 10.5.2.37f SI 17 Rest Octets
 * [3] 10.5.2.37g SI 19 Rest Octets
 * [3] 10.5.2.37h SI 18 Rest Octets
 * [3] 10.5.2.37i SI 20 Rest Octets */
    { 0x00, "Starting Time" },                          /* [3] 10.5.2.38 Starting Time  */
    { 0x00, "Timing Advance" },                         /* [3] 10.5.2.40 Timing Advance */
    { 0x00, "Time Difference" },                        /* [3] 10.5.2.41 Time Difference */
    { 0x00, "TLLI" },                                   /* [3] 10.5.2.41a TLLI  */
    { 0x00, "TMSI/P-TMSI" },                            /* [3] 10.5.2.42 TMSI/P-TMSI */
    { 0x00, "VGCS target mode Indication" },            /* [3] 10.5.2.42a */
    /* Pos 40 */
    { 0x00, "VGCS Ciphering Parameters" },              /* [3] 10.5.2.42b */
    { 0x00, "Wait Indication" },                        /* [3] 10.5.2.43 Wait Indication */
/* [3] 10.5.2.44 SI10 rest octets $(ASCI)$ */
    { 0x00, "Extended Measurement Results" },           /* [3] 10.5.2.45 Extended Measurement Results */
    { 0x00, "Extended Measurement Frequency List" },    /* [3] 10.5.2.46 Extended Measurement Frequency List */
    { 0x00, "Suspension Cause" },                       /* [3] 10.5.2.47                                */
    { 0x00, "APDU ID" },                                /* [3] 10.5.2.48 APDU ID */
    { 0x00, "APDU Flags" },                             /* [3] 10.5.2.49 APDU Flags */
    { 0x00, "APDU Data" },                              /* [3] 10.5.2.50 APDU Data */
    { 0x00, "Handover to UTRAN Command" },              /* [3] 10.5.2.51 Handover To UTRAN Command */
/* [3] 10.5.2.52 Handover To cdma2000 Command
 * [3] 10.5.2.53 (void)
 * [3] 10.5.2.54 (void)
 * [3] 10.5.2.55 (void)
 * [3] 10.5.2.56 3G Target Cell */
    { 0x00, "Service Support" },                        /* [3] 10.5.2.57    */
    /* 10.5.2.58 MBMS p-t-m Channel Description */
    { 0x00, "Dedicated Service Information" },          /* [3] 10.5.2.59    */
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
 */
    { 0x00, "Carrier Indication" },                     /* 10.5.2.69 Carrier Indication */
    {    0, NULL }
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
    { 0, "Priority and E-UTRAN Parameters Description" },
    { 0, "Serving Cell Priority Parameters Description" },
    { 0, "3G Priority Parameters Description" },
    { 0, "UTRAN Priority Parameters" },
    { 0, "E-UTRAN Parameters Description" },
    { 0, "E-UTRAN Neighbour Cells" },
    { 0, "E-UTRAN Not Allowed Cells" },
    { 0, "E-UTRAN PCID to TA mapping" },
    { 0, "3G CSG Description" },
    { 0, "E-UTRAN CSG Description" },
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
    { 0, "GSM Description" },
    { 0, "Real Time Difference Description" },
    { 0, "BSIC Description" },
    { 0, "Report Priority Description" },
    { 0, "CDMA2000 Description" },
    { 0, "Serving cell data" },
    { 0, "Repeated Invalid BSIC Information" },
    { 0, "Bitmap Type Reporting" },
    { 0, "3G Supplementary Parameters Description" },
    { 0, "UTRAN Measurement Control Parameters" },
    { 0, "EGPRS Packet Uplink Assignment" },
    { 0, "Multiple Blocks Packet Downlink Assignment" },
    { 0, "Temporary Mobile Group Identity (TMGI)" },
    { 0, "Packet Timing Advance" },
    { 0, "Packet Uplink Assignment" },
    { 0, "Packet Downlink Assignment" },
    { 0, "Second Part Packet Assignment" },
    { 0, "REPORTING QUANTITY" },
    { 0, "E-UTRAN Measurement Report" },
    { 0, NULL }
};


/* RR cause value (octet 2) TS 44.018 6.11.0*/
static const value_string gsm_a_rr_RR_cause_vals[] = {
    {    0, "Normal event"},
    {    1, "Abnormal release, unspecified"},
    {    2, "Abnormal release, channel unacceptable"},
    {    3, "Abnormal release, timer expired"},
    {    4, "Abnormal release, no activity on the radio path"},
    {    5, "Preemptive release"},
    {    6, "UTRAN configuration unknown"},
    {    8, "Handover impossible, timing advance out of range"},
    {    9, "Channel mode unacceptable"},
    {   10, "Frequency not implemented"},
    {   13, "Originator or talker leaving group call area"},
    {   12, "Lower layer failure"},
    { 0x41, "Call already cleared"},
    { 0x5f, "Semantically incorrect message"},
    { 0x60, "Invalid mandatory information"},
    { 0x61, "Message type non-existent or not implemented"},
    { 0x62, "Message type not compatible with protocol state"},
    { 0x64, "Conditional IE error"},
    { 0x65, "No cell allocation available"},
    { 0x6f, "Protocol error unspecified"},
    { 0, NULL }
};

static const value_string gsm_a_rr_algorithm_identifier_vals[] = {
    { 0, "Cipher with algorithm A5/1"},
    { 1, "Cipher with algorithm A5/2"},
    { 2, "Cipher with algorithm A5/3"},
    { 3, "Cipher with algorithm A5/4"},
    { 4, "Cipher with algorithm A5/5"},
    { 5, "Cipher with algorithm A5/6"},
    { 6, "Cipher with algorithm A5/7"},
    { 7, "Reserved"},
    { 0, NULL }
};


#define DTAP_PD_MASK            0x0f
#define DTAP_SKIP_MASK          0xf0
#define DTAP_TI_MASK            DTAP_SKIP_MASK
#define DTAP_TIE_PRES_MASK      0x07                    /* after TI shifted to right */
#define DTAP_TIE_MASK           0x7f

#define DTAP_RR_IEI_MASK        0xff

/* Initialize the protocol and registered fields */
static int proto_a_rr = -1;
static int proto_a_ccch = -1;
static int proto_a_sacch = -1;

static int hf_gsm_a_dtap_msg_rr_type = -1;
int hf_gsm_a_rr_elem_id = -1;

static int hf_gsm_a_rr_short_pd_msg_type = -1;
static int hf_gsm_a_rr_short_pd = -1;
static int hf_gsm_a_rr_short_l2_header = -1;


static int hf_gsm_a_rr_bcc = -1;
static int hf_gsm_a_rr_ncc = -1;
static int hf_gsm_a_rr_bcch_arfcn = -1;
static int hf_gsm_a_rr_range_nb = -1;
static int hf_gsm_a_rr_range_lower = -1;
static int hf_gsm_a_rr_range_higher = -1;
static int hf_gsm_a_rr_ba_freq = -1;
static int hf_gsm_a_rr_ho_ref_val = -1;
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
static int hf_gsm_a_rr_format_id2 = -1;
static int hf_gsm_a_rr_channel_mode = -1;
static int hf_gsm_a_rr_channel_mode2 = -1;
static int hf_gsm_a_rr_sc = -1;
static int hf_gsm_a_rr_algorithm_id = -1;
static int hf_gsm_a_rr_cr = -1;
static int hf_gsm_a_rr_multirate_speech_ver = -1;
static int hf_gsm_a_rr_NCSB = -1;
static int hf_gsm_a_rr_ICMI = -1;
static int hf_gsm_a_rr_start_mode = -1;
static int hf_gsm_a_rr_timing_adv = -1;
static int hf_gsm_a_rr_time_diff = -1;
static int hf_gsm_a_rr_tlli = -1;
static int hf_gsm_a_rr_tmsi_ptmsi = -1;
static int hf_gsm_a_rr_target_mode = -1;
static int hf_gsm_a_rr_wait_indication = -1;
static int hf_gsm_a_rr_seq_code = -1;
static int hf_gsm_a_rr_group_cipher_key_number = -1;
static int hf_gsm_a_rr_MBMS_multicast = -1;
static int hf_gsm_a_rr_MBMS_broadcast = -1;
static int hf_gsm_a_rr_last_segment = -1;
static int hf_gsm_a_rr_carrier_ind = -1;
static int hf_gsm_a_rr_ra = -1;
static int hf_gsm_a_rr_T1prim = -1;
static int hf_gsm_a_rr_T3 = -1;
static int hf_gsm_a_rr_T2 = -1;
static int hf_gsm_a_rr_tbf_T1prim = -1;
static int hf_gsm_a_rr_tbf_T3 = -1;
static int hf_gsm_a_rr_tbf_T2 = -1;
static int hf_gsm_a_rr_rfn = -1;
static int hf_gsm_a_rr_RR_cause = -1;
static int hf_gsm_a_rr_cm_cng_msg_req = -1;
static int hf_gsm_a_rr_utran_cm_cng_msg_req = -1;
static int hf_gsm_a_rr_cdma200_cm_cng_msg_req = -1;
static int hf_gsm_a_rr_geran_iu_cm_cng_msg_req = -1;
int hf_gsm_a_rr_chnl_needed_ch1 = -1;
static int hf_gsm_a_rr_chnl_needed_ch2 = -1;
static int hf_gsm_a_rr_chnl_needed_ch3 = -1;
static int hf_gsm_a_rr_chnl_needed_ch4 = -1;
static int hf_gsm_a_rr_pkt_estab_cause = -1;
static int hf_gsm_a_rr_peak_throughput_class = -1;
static int hf_gsm_a_rr_radio_priority = -1;
static int hf_gsm_a_rr_llc_pdu_type = -1;
static int hf_gsm_a_rr_rlc_octet_count = -1;
static int hf_gsm_a_rr_rlc_non_pers_mode_cap = -1;
static int hf_gsm_a_rr_reduced_latency_cap = -1;
static int hf_gsm_a_rr_ul_egprs2 = -1;
static int hf_gsm_a_rr_dl_egprs2 = -1;
static int hf_gsm_a_rr_emst_ms_cap = -1;
static int hf_gsm_a_rr_suspension_cause = -1;
static int hf_gsm_a_rr_apdu_id = -1;
static int hf_gsm_a_rr_apdu_flags = -1;
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
int hf_gsm_a_rr_t3212 = -1;
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
static int hf_gsm_a_rr_si2ter_mp_change_mark = -1;
static int hf_gsm_a_rr_si2ter_3g_change_mark = -1;
static int hf_gsm_a_rr_si2ter_index = -1;
static int hf_gsm_a_rr_si2ter_count = -1;
static int hf_gsm_a_rr_fdd_uarfcn = -1;
static int hf_gsm_a_rr_bandwidth_fdd = -1;
static int hf_gsm_a_rr_tdd_uarfcn = -1;
static int hf_gsm_a_rr_bandwidth_tdd = -1;
static int hf_gsm_a_rr_arfcn = -1;
static int hf_gsm_a_rr_bsic = -1;
static int hf_gsm_a_rr_qsearch_i = -1;
static int hf_gsm_a_rr_fdd_qoffset = -1;
static int hf_gsm_a_rr_fdd_qmin = -1;
static int hf_gsm_a_rr_tdd_qoffset = -1;
static int hf_gsm_a_rr_fdd_qmin_offset = -1;
static int hf_gsm_a_rr_fdd_rscpmin = -1;
static int hf_gsm_a_rr_3g_ba_ind = -1;
static int hf_gsm_a_rr_mp_change_mark = -1;
static int hf_gsm_a_rr_si2quater_index = -1;
static int hf_gsm_a_rr_si2quater_count = -1;
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
static int hf_gsm_a_rr_index_start_3g = -1;
static int hf_gsm_a_rr_absolute_index_start_emr = -1;
static int hf_gsm_a_rr_qsearch_c_initial = -1;
static int hf_gsm_a_rr_fdd_rep_quant = -1;
static int hf_gsm_a_rr_fdd_multirat_reporting = -1;
static int hf_gsm_a_rr_tdd_multirat_reporting = -1;
static int hf_gsm_a_rr_qsearch_p = -1;
static int hf_gsm_a_rr_3g_search_prio = -1;
static int hf_gsm_a_rr_fdd_reporting_offset = -1;
static int hf_gsm_a_rr_fdd_reporting_threshold_rscp = -1;
static int hf_gsm_a_rr_fdd_reporting_threshold_ecn0 = -1;
static int hf_gsm_a_rr_tdd_reporting_offset = -1;
static int hf_gsm_a_rr_tdd_reporting_threshold_rscp = -1;
static int hf_gsm_a_rr_tdd_reporting_threshold_ecn0 = -1;
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
static int hf_gsm_a_rr_gprs_ra_colour = -1;
static int hf_gsm_a_rr_si13_position = -1;
static int hf_gsm_a_rr_power_offset = -1;
static int hf_gsm_a_rr_si2quater_position = -1;
static int hf_gsm_a_rr_si13alt_position = -1;
static int hf_gsm_a_rr_prio_thr = -1;
static int hf_gsm_a_rr_lsa_offset = -1;
static int hf_gsm_a_rr_cell_id = -1;
static int hf_gsm_a_rr_paging_channel_restructuring = -1;
static int hf_gsm_a_rr_nln_sacch = -1;
static int hf_gsm_a_rr_nln_status_sacch = -1;
static int hf_gsm_a_rr_nln_pch = -1;
static int hf_gsm_a_rr_nln_status_pch = -1;
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
static int hf_gsm_a_rr_mi_index = -1;
static int hf_gsm_a_rr_mi_count = -1;
static int hf_gsm_a_rr_3g_wait = -1;
static int hf_gsm_a_rr_qsearch_c = -1;
static int hf_gsm_a_rr_bsic_seen = -1;
static int hf_gsm_a_rr_scale = -1;
static int hf_gsm_a_rr_mean_bep_gmsk = -1;
static int hf_gsm_a_rr_mean_cv_bep = -1;
static int hf_gsm_a_rr_nbr_rcvd_blocks = -1;
static int hf_gsm_a_rr_reporting_quantity = -1;
static int hf_gsm_a_rr_extended_ra = -1;
static int hf_gsm_a_rr_access_tech_type = -1;
static int hf_gsm_a_rr_tfi_assignment = -1;
static int hf_gsm_a_rr_polling = -1;
static int hf_gsm_a_rr_usf = -1;
static int hf_gsm_a_rr_usf_granularity = -1;
static int hf_gsm_a_rr_p0 = -1;
static int hf_gsm_a_rr_pr_mode = -1;
static int hf_gsm_a_rr_egprs_mcs = -1;
static int hf_gsm_a_rr_tlli_block_channel_coding = -1;
static int hf_gsm_a_rr_bep_period2 = -1;
static int hf_gsm_a_rr_resegment = -1;
static int hf_gsm_a_rr_egprs_window_size = -1;
static int hf_gsm_a_rr_gamma = -1;
static int hf_gsm_a_rr_timing_adv_index = -1;
static int hf_gsm_a_rr_timing_adv_timeslot_num = -1;
static int hf_gsm_a_rr_tbf_starting_time = -1;
static int hf_gsm_a_rr_num_of_radio_block_allocated = -1;
static int hf_gsm_a_rr_pfi = -1;
static int hf_gsm_a_rr_mbms_service_id = -1;
static int hf_gsm_a_rr_ms_id = -1;
static int hf_gsm_a_rr_gprs_cs = -1;
static int hf_gsm_a_rr_rlc_mode = -1;
static int hf_gsm_a_rr_ta_valid = -1;
static int hf_gsm_a_rr_link_quality_meas_mode = -1;
static int hf_gsm_a_rr_emr_bitmap_length = -1;
static int hf_gsm_a_rr_eutran_mr_n_eutran = -1;
static int hf_gsm_a_rr_eutran_mr_freq_idx = -1;
static int hf_gsm_a_rr_eutran_mr_cell_id = -1;
static int hf_gsm_a_rr_eutran_mr_rpt_quantity = -1;
static int hf_gsm_a_rr_ma_channel_set = -1;
static int hf_n_range_orig_arfcn = -1;



/* Additions in Rel-8 */
static int hf_gsm_a_rr_3g_priority_param_desc_utran_start = -1;
static int hf_gsm_a_rr_3g_priority_param_desc_utran_stop = -1;
static int hf_gsm_a_rr_3g_priority_param_desc_default_utran_prio = -1;
static int hf_gsm_a_rr_3g_priority_param_desc_default_threshold_utran = -1;
static int hf_gsm_a_rr_3g_priority_param_desc_default_utran_qrxlevmin = -1;
static int hf_gsm_a_rr_utran_frequency_index = -1;
static int hf_gsm_a_rr_utran_priority = -1;
static int hf_gsm_a_rr_thresh_utran_high = -1;
static int hf_gsm_a_rr_thresh_utran_low = -1;
static int hf_gsm_a_rr_utran_qrxlevmin = -1;
static int hf_gsm_a_rr_eutran_ccn_active = -1;
static int hf_gsm_a_rr_eutran_start = -1;
static int hf_gsm_a_rr_eutran_stop = -1;
static int hf_gsm_a_rr_qsearch_c_eutran_initial = -1;
static int hf_gsm_a_rr_eutran_multirat_reporting = -1;
static int hf_gsm_a_rr_eutran_fdd_reporting_threshold_rsrp = -1;
static int hf_gsm_a_rr_eutran_fdd_reporting_threshold_rsrq = -1;
static int hf_gsm_a_rr_eutran_fdd_reporting_threshold_2 = -1;
static int hf_gsm_a_rr_eutran_fdd_reporting_offset = -1;
static int hf_gsm_a_rr_eutran_tdd_reporting_threshold_rsrp = -1;
static int hf_gsm_a_rr_eutran_tdd_reporting_threshold_rsrq = -1;
static int hf_gsm_a_rr_eutran_tdd_reporting_threshold_2 = -1;
static int hf_gsm_a_rr_eutran_tdd_reporting_offset = -1;
static int hf_gsm_a_rr_eutran_fdd_measurement_report_offset = -1;
static int hf_gsm_a_rr_eutran_tdd_measurement_report_offset = -1;
static int hf_gsm_a_rr_reporting_granularity = -1;
static int hf_gsm_a_rr_eutran_default_measurement_control_eutran = -1;
static int hf_gsm_a_rr_eutran_measurement_control_eutran = -1;
static int hf_gsm_a_rr_qsearch_p_eutran = -1;
static int hf_gsm_a_rr_serving_cell_priority_param_geran_priority = -1;
static int hf_gsm_a_rr_serving_cell_priority_param_thresh_prio_search = -1;
static int hf_gsm_a_rr_serving_cell_priority_param_thresh_gsm_low = -1;
static int hf_gsm_a_rr_serving_cell_priority_param_h_prio = -1;
static int hf_gsm_a_rr_serving_cell_priority_param_t_reselection = -1;
static int hf_gsm_a_rr_eutran_earfcn = -1;
static int hf_gsm_a_rr_eutran_measurement_bandwidth = -1;
static int hf_gsm_a_rr_eutran_priority = -1;
static int hf_gsm_a_rr_thresh_eutran_high = -1;
static int hf_gsm_a_rr_thresh_eutran_low = -1;
static int hf_gsm_a_rr_eutran_qrxlevmin = -1;
static int hf_gsm_a_rr_eutran_pcid = -1;
static int hf_gsm_a_rr_eutran_pcid_bitmap_group = -1;
static int hf_gsm_a_rr_eutran_pcid_pattern_length = -1;
static int hf_gsm_a_rr_eutran_pcid_pattern = -1;
static int hf_gsm_a_rr_eutran_pcid_pattern_sense = -1;
static int hf_gsm_a_rr_eutran_frequency_index = -1;
static int hf_gsm_a_rr_psc = -1;
static int hf_gsm_a_rr_utran_psc_pattern_length = -1;
static int hf_gsm_a_rr_utran_psc_pattern_sense = -1;
static int hf_gsm_a_rr_utran_csg_fdd_uarfcn = -1;
static int hf_gsm_a_rr_utran_csg_tdd_uarfcn = -1;
static int hf_gsm_a_rr_csg_earfcn = -1;
static int hf_gsm_a_rr_3g_control_param_desc_meas_ctrl_utran = -1;

/* Initialize the subtree pointers */
static gint ett_ccch_msg = -1;
static gint ett_ccch_oct_1 = -1;
static gint ett_sacch_msg = -1;

static char a_bigbuf[1024];

static dissector_handle_t data_handle;
static dissector_handle_t rrlp_dissector;


#define NUM_GSM_RR_ELEM (sizeof(gsm_rr_elem_strings)/sizeof(value_string))
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
    DE_RR_REST_OCTETS_PRIORITY_AND_EUTRAN_PARAM_DESC,
    DE_RR_REST_OCTETS_SERVING_CELL_PRIORITY_PARAM_DESC,
    DE_RR_REST_OCTETS_3G_PRIORITY_PARAM_DESC,
    DE_RR_REST_OCTETS_UTRAN_PRIO_PARAM,
    DE_RR_REST_OCTETS_EUTRAN_PARAM_DESC,
    DE_RR_REST_OCTETS_EUTRAN_NEIGHBOUR_CELLS,
    DE_RR_REST_OCTETS_EUTRAN_NOT_ALLOWED_CELLS,
    DE_RR_REST_OCTETS_EUTRAN_PCID_TO_TA_MAPPING,
    DE_RR_REST_OCTETS_3G_CSG_DESC,
    DE_RR_REST_OCTETS_EUTRAN_CSG_DESC,
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
    DE_RR_REST_OCTETS_GSM_DESC,
    DE_RR_REST_OCTETS_RTD_DESC,
    DE_RR_REST_OCTETS_BSIC_DESC,
    DE_RR_REST_OCTETS_REPORT_PRIO_DESC,
    DE_RR_REST_OCTETS_CDMA2000_DESC,
    DE_RR_REST_OCTETS_SERVING_CELL_DATA,
    DE_RR_REST_OCTETS_REPEAT_INV_BSIC_INFO,
    DE_RR_REST_OCTETS_BITMAP_TYPE_REPORTING,
    DE_RR_REST_OCTETS_3G_SUPPLEMENTARY_PARAM_DESC,
    DE_RR_REST_OCTETS_UTRAN_MEASUREMENT_CONTROL_PARAM_DESC,
    DE_RR_REST_OCTETS_EGPRS_PACKET_UPLINK_ASSIGNMENT,
    DE_RR_REST_OCTETS_MULTIPLE_BLOCKS_PACKET_DOWNLINK_ASSIGNMENT,
    DE_RR_REST_OCTETS_TMGI,
    DE_RR_REST_OCTETS_PACKET_TIMING_ADVANCE,
    DE_RR_REST_OCTETS_PACKET_UPLINK_ASSIGNMENT,
    DE_RR_REST_OCTETS_PACKET_DOWNLINK_ASSIGNMENT,
    DE_RR_REST_OCTETS_SECOND_PART_PACKET_ASSIGNMENT,
    DE_RR_REST_OCTETS_REPORTING_QUANTITY,
    DE_RR_REST_OCTETS_EUTRAN_MEASUREMENT_REPORT,
    DE_RR_REST_OCTETS_NONE
}
rr_rest_octets_elem_idx_t;

#define NUM_GSM_RR_REST_OCTETS_ELEM (sizeof(gsm_rr_rest_octets_elem_strings)/sizeof(value_string))
gint ett_gsm_rr_rest_octets_elem[NUM_GSM_RR_REST_OCTETS_ELEM];

/*
 * Generates a string representing the bits in a bitfield at "bit_offset" from an 8 bit boundary
 * with the length in bits of no_of_bits based on value.
 * Ex: ..xx x...
 */

/* this function is used for dissecting the 0/1 presence flags in CSN.1 coded IEs */
static gboolean gsm_rr_csn_flag(tvbuff_t *tvb, proto_tree *tree, gint bit_offset, const char *description, const char *true_string, const char * false_string)
{
    guint8 bit_mask        = 0x80 >> (bit_offset % 8);
    guint8 value           = tvb_get_guint8(tvb, bit_offset >> 3);
    guint8 offset_in_octet = bit_offset % 8;
    char   bits_str[]      = {".... ...."};

    if (value & bit_mask)
    {
        bits_str[offset_in_octet + (offset_in_octet / 4)] = '1';
        proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s: %s: %s", bits_str, description, true_string);
        return TRUE;
    }
    bits_str[offset_in_octet + (offset_in_octet / 4)] = '0';
    proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s: %s: %s", bits_str, description, false_string);
    return FALSE;
}

/* this function is used for dissecting the H/L presence flags in CSN.1 coded IEs"
   If truncation ( 44.018 section 8.9) is allowed, truncation_length is set to the actual bit length of the CSN.1 string,
   otherwise it is set to 0 */
static gboolean gsm_rr_csn_HL_flag(tvbuff_t *tvb, proto_tree *tree, guint truncation_length, guint bit_offset, const char *description, const char *true_string, const char * false_string)
{
    guint8 bit_mask        = 0x80 >> (bit_offset % 8);
    guint8 value           = PADDING_BYTE;
    char   bits_str[]      = {".... ...."};
    guint8 offset_in_octet = bit_offset % 8;

    if (truncation_length)
    {
       if (bit_offset < truncation_length)
       {
          /* there should be some real data to fetch */
          value = tvb_get_guint8(tvb, bit_offset >> 3)^PADDING_BYTE;
       }
       else
       {
          /* implicit L bit */
          proto_tree_add_text(tree, tvb, truncation_length>>3, 1, "(implicit L bit): %s: %s", description, false_string);
          return FALSE;
       }
    }
    else
    {
       /* if truncation_length == 0, then don't check for truncation*/
       value = tvb_get_guint8(tvb, bit_offset >> 3)^PADDING_BYTE;
    }

    if (value & bit_mask)
    {
        bits_str[offset_in_octet + (offset_in_octet / 4)] = 'H';
        proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s: %s: %s", bits_str, description, true_string);
        return TRUE;
    }
    bits_str[offset_in_octet + (offset_in_octet / 4)] = 'L';
    proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "%s: %s: %s", bits_str, description, false_string);
    return FALSE;
}

/*
10.5.2 Radio Resource management information elements
 * [3] 10.5.2.1a BA Range
 */
static guint16
de_rr_ba_range(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    gint    bit_offset;
    guint8  value;

    curr_offset = offset;
    proto_tree_add_item(tree, hf_gsm_a_rr_range_nb, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    value = tvb_get_guint8(tvb, curr_offset);
    curr_offset += 1;
    bit_offset = curr_offset << 3;
    while (value)
    {
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_range_lower, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_range_higher, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;
        value -= 1;
    }

    curr_offset += len - 1;
    return (curr_offset - offset);
}

/*
 * [3] 10.5.2.1b Cell Channel Description
 */

#define ARFCN_MAX 1024 /* total number of ARFCNs defined */

static void display_channel_list(guint8 *list, tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
    int         arfcn;
    proto_item *ti = NULL;

    ti = proto_tree_add_text(tree, tvb, offset, len, "List of ARFCNs =");
    for (arfcn=0; arfcn<ARFCN_MAX; arfcn++) {
        if (list[arfcn])
            proto_item_append_text(ti, " %d", arfcn);
    }

    return;
}

/**
 * Checks that the remaining "rest octets" all contain the default padding value.
 * If not, it can be assumed that there is a protocol extension
 * that we don't handle,
 * or a malformed PDU.
 *
 * len:        total length of buffer
 * bit_offset: bit offset in TVB of first bit to be examined
 */
static void gsm_rr_csn_padding_bits(proto_tree* tree, tvbuff_t* tvb, guint16 bit_offset, guint8 octet_len)
{
    guint    i;
    gboolean non_padding_found = FALSE;
    guint8   octet_offset      = bit_offset >> 3;

    if ((octet_len << 3) > bit_offset)
    {
        /* there is spare room, check the first padding octet */
        guint8 bit_mask = 0xFF >> (bit_offset & 0x07);
        if ((tvb_get_guint8(tvb, octet_offset) & bit_mask) != (PADDING_BYTE & bit_mask))
        {
               non_padding_found = TRUE;
        }
        else
        {
           for (i=octet_offset+1; (i<octet_len) && !non_padding_found; i++)
           {
               if (tvb_get_guint8(tvb, i) != PADDING_BYTE)
                   non_padding_found = TRUE;
           }
        }

        if (non_padding_found)
        {
            /* there is something here we don't understand */
            proto_tree_add_text(tree, tvb, octet_offset, -1,"Padding Bits: Unknown extension detected or malformed PDU (Not decoded)");
        }
        else
        {
            proto_tree_add_text(tree, tvb, octet_offset, -1,"Padding Bits: default padding");
        }
    }
    else
    {
       proto_tree_add_text(tree, tvb, 0, 0,"No space for padding bits");
    }
}

static gint greatest_power_of_2_lesser_or_equal_to(gint idx)
{
    gint j = 1;
    do {
        j <<= 1;
    } while (j <= idx);
    j >>= 1;
    return j;
}

gint f_k(gint k, gint *w, gint range)
{
    gint idx, n, j;

    idx    = k;
    range -= 1;
    range  = range/greatest_power_of_2_lesser_or_equal_to(idx);
    n      = w[idx]-1;

    while (idx>1) {
        j = greatest_power_of_2_lesser_or_equal_to(idx);
        range = 2*range+1;
        if ((2*idx) < 3*j){ /* left child */
            idx -= j/2;
            n = (n+w[idx]-1+((range-1)/2)+1)%range;
        }
        else { /* right child */
            idx -= j;
            n = (n+w[idx]-1+1)%range;
        }
    }

    return (n+1)%1024;
}

static void dissect_channel_list_n_range(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gint range)
{
  gint        curr_offset = offset, bit_offset, f0, arfcn_orig, w[64], wsize, i;
  gint        octet, nwi  = 1, jwi=0, imax, iused, arfcn;
  guint8      list[1024];
  proto_item *item;
  proto_tree *subtree;

  memset((void*)list,0,sizeof(list));

  item = proto_tree_add_text(tree,tvb, curr_offset, len, "Range %d format", range);
  subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_NEIGH_CELL_DESC]);

  octet = tvb_get_guint8(tvb, curr_offset);
  if (range == 1024) {
    f0 = (octet>>2)&1;
    if (f0)
      list[0] = 1;
    arfcn_orig = 0;
    wsize = 10;
    imax = 16;
    bit_offset = curr_offset*8 + 6;
  }
  else {
    bit_offset = curr_offset*8 + 7;
    arfcn_orig = (gint) tvb_get_bits(tvb, bit_offset, 10, FALSE);
    proto_tree_add_bits_item(subtree, hf_n_range_orig_arfcn, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
    bit_offset+=10;

    list[arfcn_orig] = 1;

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
      DISSECTOR_ASSERT_NOT_REACHED();
    }
  }
  iused = imax;   /* in case the list is actually full */

  /* extract the variable size w[] elements */
  for (i=1; i<=imax; i++) {
    w[i] = (gint) tvb_get_bits(tvb, bit_offset, wsize, FALSE);
    proto_tree_add_text(subtree, tvb, bit_offset>>3, ((bit_offset+wsize-1)>>3) - (bit_offset>>3) + 1 , "%s %s(%d): %d",
                        decode_bits_in_field(bit_offset, wsize, w[i]),
                        "W",
                        i,
                        w[i]);
    bit_offset += wsize;
    curr_offset = bit_offset>>3;

    if ((iused == imax) && (w[i] == 0) ) {
      iused = i - 1;
    }
    if ((curr_offset-offset)>len) {
      iused = i - 1;
      break;
    }
    if (++jwi == nwi) {       /* check if the number of wi at this wsize has been extracted */
      jwi = 0;            /* reset the count of wi at this size */
      nwi <<= 1;          /* get twice as many of the next size */
      wsize--;            /* make the next size 1 bit smaller */
    }
  }

  for (i=1; i<=iused; i++) {
    arfcn = (f_k(i, w, range) + arfcn_orig)%1024;
    list[arfcn] = 1;
  }

  display_channel_list(list, tvb, tree, offset, curr_offset-offset);

  return;
}

static guint16
dissect_arfcn_list_core(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_, guint8 format)
{
    guint32     curr_offset, byte;
    guint8      oct,bit;
    guint16     arfcn;
    proto_item *item;

    curr_offset = offset;

    if ((format & 0xc0) == 0x00)
    {
        /* bit map 0 */
        item = proto_tree_add_text(tree,tvb, curr_offset, len, "List of ARFCNs =");
        bit = 4;
        arfcn = 125;
        for (byte = 0; byte <= len-1; byte++)
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
    else if ((format & 0xc8) == 0x80)
    {
        /* 1024 range */
        dissect_channel_list_n_range(tvb, tree, pinfo, curr_offset, len, 1024);
        curr_offset = curr_offset + len;
    }
    else if ((format & 0xce) == 0x88)
    {
        /* 512 range */
        dissect_channel_list_n_range(tvb, tree, pinfo, curr_offset, len, 512);
        curr_offset = curr_offset + len;
    }
    else if ((format & 0xce) == 0x8a)
    {
        /* 256 range */
        dissect_channel_list_n_range(tvb, tree, pinfo, curr_offset, len, 256);
        curr_offset = curr_offset + len;
    }
    else if ((format & 0xce) == 0x8c)
    {
        /* 128 range */
        dissect_channel_list_n_range(tvb, tree, pinfo, curr_offset, len, 128);
        curr_offset = curr_offset + len;
    }
    else if ((format & 0xce) == 0x8e)
    {
        /* variable bit map */
        arfcn = ((format & 0x01) << 9) | (tvb_get_guint8(tvb, curr_offset+1) << 1) | ((tvb_get_guint8(tvb, curr_offset + 2) & 0x80) >> 7);
        item = proto_tree_add_text(tree,tvb,curr_offset,len,"List of ARFCNs = %d",arfcn);
        curr_offset = curr_offset + 2;
        bit = 7;
        for (byte = 0; byte <= len-3; byte++)
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

/*
 * Format ID is in bits:
 * 128 127 124 123 122 (hf_gsm_a_rr_format_id)
 */
static guint16
dissect_arfcn_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint8  oct;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    /* FORMAT-ID, Format Identifier (part of octet 3)*/
    proto_tree_add_item(tree, hf_gsm_a_rr_format_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset += dissect_arfcn_list_core(tvb, tree, pinfo, offset, len, add_string, string_len, oct);

    return(curr_offset - offset);
}

/*
 * Format ID is in bits:
 * 128 124 123 122 (hf_gsm_a_rr_format_id2)
 */
static guint16
dissect_arfcn_list2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint8  oct;

    curr_offset = offset;

    /* Turn bit 127 off, in order to reuse the ARFCN dissection code */
    oct = tvb_get_guint8(tvb, curr_offset) & 0xbf;

    /* FORMAT-ID, Format Identifier (part of octet 3)*/
    proto_tree_add_item(tree, hf_gsm_a_rr_format_id2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset += dissect_arfcn_list_core(tvb, tree, pinfo, offset, len, add_string, string_len, oct);

    return(curr_offset - offset);
}

static guint16
de_rr_cell_ch_dsc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    return dissect_arfcn_list(tvb, tree, pinfo, offset, 16, add_string, string_len);
}
/*
 * [3] 10.5.2.1c BA List Pref
 */
static guint16
de_rr_ba_list_pref(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint bit_offset;

    bit_offset = offset << 3;
    while (gsm_rr_csn_flag(tvb, tree, bit_offset++, "Repeating Range Limits", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_range_lower, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_range_higher, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;
    }
    while (gsm_rr_csn_flag(tvb, tree, bit_offset++, "Repeating BA Frequency", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_ba_freq, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;
    }

    if (((bit_offset + 7) >> 3) > (offset + len))
    {
       expert_add_info_format(pinfo, proto_tree_get_parent(tree), PI_MALFORMED, PI_ERROR, "IE over-runs stated length");
    }
    else if ((bit_offset >> 3) < (offset + len))
    {
       expert_add_info_format(pinfo, proto_tree_get_parent(tree), PI_COMMENTS_GROUP, PI_NOTE, "IE under-runs stated length");
    }
    return len;
}

/*
 * [3] 10.5.2.1d UTRAN Frequency List
 */
static guint16
de_rr_utran_freq_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint bit_offset;

    /* < UTRAN Freq List >::=
     * < LENGTH OF UTRAN FREQ LIST : bit (8) > -- length following in octets
     * { 1 < FDD_ARFCN > : bit (14) } ** 0 -- FDD frequencies
     * { 1 < TDD_ARFCN > : bit (14) } ** 0 -- TDD frequencies
     * <spare bit>**;
     * Spare bits in the end of the field are used to fill the last octet.
     */
    bit_offset = offset << 3;
    while (gsm_rr_csn_flag(tvb, tree, bit_offset++, "Repeating FDD Frequency", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_fdd_uarfcn, tvb, bit_offset, 14, ENC_BIG_ENDIAN);
        bit_offset += 14;
    }
    while (gsm_rr_csn_flag(tvb, tree, bit_offset++, "Repeating TDD Frequency", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_tdd_uarfcn, tvb, bit_offset, 14, ENC_BIG_ENDIAN);
        bit_offset += 14;
    }

    if (((bit_offset + 7) >> 3) > (offset + len))
    {
       expert_add_info_format(pinfo, proto_tree_get_parent(tree), PI_MALFORMED, PI_ERROR, "IE over-runs stated length");
    }
    else if ((bit_offset >> 3) < (offset + len))
    {
       expert_add_info_format(pinfo, proto_tree_get_parent(tree), PI_COMMENTS_GROUP, PI_NOTE, "IE under-runs stated length");
    }
    return (len);
}

/*
 * [3] 10.5.2.1e Cell selection indicator after release of all TCH and SDCCH
 */
static const guint8
convert_n_to_p[32] = {   0, 10, 19, 28, 36, 44, 52, 60, 67, 74, 81, 88, 95, 102, 109, 116,
                       122,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,   0,   0,   0};

static const guint8
convert_n_to_q[32] = {   0,   9,  17,  25,  32, 39, 46, 53, 59, 65, 71, 77, 83, 89, 95, 101,
                       106, 111, 116, 121, 126,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,   0};

static guint16
de_rr_cell_select_indic(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_tree *subtree, *subtree2;
    proto_item *item, *item2;
    guint32     curr_offset;
    gint        bit_offset, bit_offset_sav, idx, xdd_cell_info, wsize, nwi, jwi, w[64], i, iused, xdd_indic0;
    guint8      value;

    curr_offset = offset;
    bit_offset  = curr_offset << 3;
    value = tvb_get_bits8(tvb,bit_offset,3);
    bit_offset += 3;
    switch (value)
    {
    case 0: /* GSM Description */
        bit_offset_sav = bit_offset;
        item = proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "%s",
                                   gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GSM_DESC].strptr);
        subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GSM_DESC]);
        while (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Repeating GSM Description struct", "Present", "Not Present"))
        {
            gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Band Indicator", "1900", "1800");
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_arfcn, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
            bit_offset += 10;
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bsic, tvb, bit_offset, 6, ENC_BIG_ENDIAN);
            bit_offset += 6;
        }
        proto_item_set_len(item,((bit_offset>>3) - (bit_offset_sav>>3) + 1));
        break;
    case 1: /* UTRAN FDD Description */
        bit_offset_sav = bit_offset;
        item = proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "%s",
                                   gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_FDD_DESC].strptr);
        subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_UTRAN_FDD_DESC]);
        while (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Repeating UTRAN FDD Description struct", "Present", "Not Present"))
        {
            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Bandwidth FDD", "Present", "Not Present"))
            {
                proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bandwidth_fdd, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                bit_offset += 3;
            }
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_fdd_uarfcn, tvb, bit_offset, 14, ENC_BIG_ENDIAN);
            bit_offset += 14;
            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "FDD Cell Information", "Present", "Not Present"))
            {
                xdd_indic0 = gsm_rr_csn_flag(tvb, subtree, bit_offset++, "FDD Indic0", "1", "0");
                idx = tvb_get_bits8(tvb,bit_offset,5);
                proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "Nr of FDD Cells : %d", idx);
                bit_offset += 5;
                idx = convert_n_to_p[idx];
                item2 = proto_tree_add_text(subtree,tvb, bit_offset>>3, (idx>>3)+1, "%s",
                                            gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_FDD_DESC].strptr);
                subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_FDD_CELL_INFORMATION_FIELD]);
                proto_tree_add_text(subtree2,tvb, bit_offset>>3, (idx>>3)+1, "Field is %d bits long", idx);
                if (xdd_indic0)
                {
                    proto_tree_add_text(subtree2,tvb, bit_offset>>3, 0, "Scrambling Code: %d", 0);
                    proto_tree_add_text(subtree2,tvb, bit_offset>>3, 0, "Diversity: %d", 0);
                }
                if (idx)
                {
                    wsize = 10;
                    nwi = 1;
                    jwi = 0;
                    i = 1;

                    while (idx > 0)
                    {
                        w[i] = tvb_get_bits(tvb, bit_offset, wsize, ENC_BIG_ENDIAN);
                        bit_offset += wsize;
                        idx -= wsize;
                        if (w[i] == 0)
                        {
                            idx = 0;
                            break;
                        }
                        if (++jwi == nwi)
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
                        proto_tree_add_text(subtree2,tvb, bit_offset>>3, 0,
                                            "Scrambling Code: %d", xdd_cell_info & 0x01FF);
                        proto_tree_add_text(subtree2,tvb, bit_offset>>3, 0,
                                            "Diversity: %d", (xdd_cell_info >> 9) & 0x01);
                    }
                }
            }
        }
        proto_item_set_len(item,((bit_offset>>3) - (bit_offset_sav>>3) + 1));
        break;
    case 2: /* UTRAN TDD Description */
        bit_offset_sav = bit_offset;
        item = proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_TDD_DESC].strptr);
        subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_UTRAN_TDD_DESC]);
        while (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Repeating UTRAN TDD Description struct", "Present", "Not Present"))
        {
            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Bandwidth TDD", "Present", "Not Present"))
            {
                proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bandwidth_tdd, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                bit_offset += 3;
            }
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_tdd_uarfcn, tvb, bit_offset, 14, ENC_BIG_ENDIAN);
            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "TDD Cell Information", "Present", "Not Present"))
            {
                xdd_indic0 = gsm_rr_csn_flag(tvb, subtree, bit_offset++, "TDD Indic0", "1", "0");
                idx = tvb_get_bits8(tvb,bit_offset,5);
                proto_tree_add_text(subtree,tvb, bit_offset>>3, 1, "Nr of TDD Cells : %d", idx);
                bit_offset += 5;
                idx = convert_n_to_q[idx];
                item2 = proto_tree_add_text(subtree,tvb, bit_offset>>3, (idx>>3)+1, "%s",
                                            gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_TDD_DESC].strptr);
                subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_TDD_CELL_INFORMATION_FIELD]);
                proto_tree_add_text(subtree2,tvb, bit_offset>>3, (idx>>3)+1, "Field is %d bits long", idx);
                if (xdd_indic0)
                {
                    proto_tree_add_text(subtree2,tvb, bit_offset>>3, 0, "Cell Parameter: %d", 0);
                    proto_tree_add_text(subtree2,tvb, bit_offset>>3, 0, "Sync Case TSTD: %d", 0);
                    proto_tree_add_text(subtree2,tvb, bit_offset>>3, 0, "Diversity TDD: %d", 0);
                }
                if (idx)
                {
                    wsize = 9;
                    nwi = 1;
                    jwi = 0;
                    i = 1;

                    while (idx > 0)
                    {
                        w[i] = tvb_get_bits(tvb, bit_offset, wsize, ENC_BIG_ENDIAN);
                        bit_offset += wsize;
                        idx -= wsize;
                        if (w[i]  ==  0)
                        {
                            idx = 0;
                            break;
                        }
                        if (++jwi == nwi)
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
                        proto_tree_add_text(subtree2,tvb, bit_offset>>3, 0,
                                            "Cell Parameter: %d", xdd_cell_info & 0x07F);
                        proto_tree_add_text(subtree2,tvb, bit_offset>>3, 0,
                                            "Sync Case TSTD: %d", (xdd_cell_info >> 7) & 0x01);
                        proto_tree_add_text(subtree2,tvb, bit_offset>>3, 0,
                                            "Diversity TDD: %d", (xdd_cell_info >> 8) & 0x01);
                    }
                }
            }
        }
        proto_item_set_len(item,((bit_offset>>3) - (bit_offset_sav>>3) + 1));
        break;
    default:
        break;
    }

    curr_offset += len;
    return (curr_offset - offset);
}

/*
 * [3] 10.5.2.2 Cell Description
 */
guint16
de_rr_cell_dsc(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint16 bcch_arfcn;

    curr_offset = offset;

    proto_tree_add_item(subtree, hf_gsm_a_rr_ncc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_rr_bcc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    bcch_arfcn = (tvb_get_guint8(tvb,curr_offset) & 0xc0) << 2;
    bcch_arfcn = bcch_arfcn | tvb_get_guint8(tvb,curr_offset+1);
    proto_tree_add_uint(subtree, hf_gsm_a_rr_bcch_arfcn , tvb, curr_offset, 2, bcch_arfcn );

    curr_offset = curr_offset + 2;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.3 Cell Options (BCCH)
 */
static const value_string gsm_a_rr_dtx_bcch_vals[] = {
    { 0x00, "The MSs may use uplink discontinuous transmission" },
    { 0x01, "The MSs shall use uplink discontinuous transmission" },
    { 0x02, "The MSs shall not use uplink discontinuous transmission" },
    { 0x03, "Reserved" },
    {    0, NULL } };

static const value_string gsm_a_rr_radio_link_timeout_vals[] = {
    { 0x00, "4" },
    { 0x01, "8" },
    { 0x02, "12" },
    { 0x03, "16" },
    { 0x04, "20" },
    { 0x05, "24" },
    { 0x06, "28" },
    { 0x07, "32" },
    { 0x08, "36" },
    { 0x09, "40" },
    { 0x0A, "44" },
    { 0x0B, "48" },
    { 0x0C, "52" },
    { 0x0D, "56" },
    { 0x0E, "60" },
    { 0x0F, "64" },
    {    0, NULL } };

static guint16
de_rr_cell_opt_bcch(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pwrc, tvb, (curr_offset<<3)+1, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_rr_dtx_bcch, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_rr_radio_link_timeout, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.3a Cell Options (SACCH)
 */
static const value_string gsm_a_rr_dtx_sacch_vals[] = {
    { 0x00, "The MS may use uplink discontinuous transmission on a TCH-F. The MS shall not use uplink discontinuous transmission on TCH-H" },
    { 0x01, "The MS shall use uplink discontinuous transmission on a TCH-F. The MS shall not use uplink discontinuous transmission on TCH-H" },
    { 0x02, "The MS shall not use uplink discontinuous transmission on a TCH-F. The MS shall not use uplink discontinuous transmission on TCH-H" },
    { 0x03, "The MS shall use uplink discontinuous transmission on a TCH-F. The MS may use uplink discontinuous transmission on TCH-H" },
    { 0x04, "The MS may use uplink discontinuous transmission on a TCH-F. The MS may use uplink discontinuous transmission on TCH-H" },
    { 0x05, "The MS shall use uplink discontinuous transmission on a TCH-F. The MS shall use uplink discontinuous transmission on TCH-H" },
    { 0x06, "The MS shall not use uplink discontinuous transmission on a TCH-F. The MS shall use uplink discontinuous transmission on TCH-H" },
    { 0x07, "The MS may use uplink discontinuous transmission on a TCH-F. The MS shall use uplink discontinuous transmission on TCH-H" },
    {    0, NULL } };

static const crumb_spec_t gsm_a_rr_dtx_sacch_crumbs[] = {
    { 0, 1}, /* B8 */
    { 2, 2}, /* B6 - B5 */
    { 0, 0}
};

static guint16
de_rr_cell_opt_sacch(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;


    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pwrc, tvb, (curr_offset<<3)+1, 1, ENC_BIG_ENDIAN);
    /* DTX is a split field in bits 8, 6 and 5 */
    proto_tree_add_split_bits_item_ret_val(subtree, hf_gsm_a_rr_dtx_sacch, tvb, (curr_offset<<3), gsm_a_rr_dtx_sacch_crumbs, NULL);
    proto_tree_add_item(subtree, hf_gsm_a_rr_radio_link_timeout, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.4 Cell Selection Parameters
 */
static guint16
de_rr_cell_sel_param(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(subtree, hf_gsm_a_rr_cell_reselect_hyst, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_rr_ms_txpwr_max_cch, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    proto_tree_add_item(subtree, hf_gsm_a_rr_acs, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_rr_neci, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_rr_rxlev_access_min, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.4a MAC Mode and Channel Coding Requested
 * [3] 10.5.2.5 Channel Description
 */
guint16
de_rr_ch_dsc(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32      curr_offset;
    guint8       oct8,subchannel;
    guint16      arfcn, hsn, maio;
    const gchar *str;

    curr_offset = offset;

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
            subchannel = ((oct8 & 0x38)>>3);
        } else {
            str = "Unknown channel information";
            subchannel = oct8;
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
 * [3] 10.5.2.5a Channel Description 2
 */
static guint16
de_rr_ch_dsc2(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32      curr_offset;
    guint8       oct8,subchannel;
    guint16      arfcn, hsn, maio;
    const gchar *str;

    curr_offset = offset;

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
            str = "Unknown channel information";
            subchannel = oct8;
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
 * [3] 10.5.2.5c Channel Description 3
 */
static guint16
de_rr_ch_dsc3(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32      curr_offset;
    guint8       oct8;
    guint16      arfcn, hsn, maio;
    const gchar *str;

    curr_offset = offset;

    /* Octet 2 */
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
 * [3] 10.5.2.6 Channel Mode
 */
/* Channel Mode  */
static const value_string gsm_a_rr_channel_mode_vals[] = {
    { 0x00, "signalling only"},
    { 0x01, "speech full rate or half rate version 1(GSM FR or GSM HR)"},
    { 0x21, "speech full rate or half rate version 2(GSM EFR)"},
    { 0x41, "speech full rate or half rate version 3(FR AMR or HR AMR)"},
    { 0x81, "speech full rate or half rate version 4(OFR AMR-WB or OHR AMR-WB)"},
    { 0x82, "speech full rate or half rate version 5(FR AMR-WB )"},
    { 0x83, "speech full rate or half rate version 6(OHR AMR )"},
    { 0x61, "data, 43.5 kbit/s (downlink)+14.5 kbps (uplink)"},
    { 0x62, "data, 29.0 kbit/s (downlink)+14.5 kbps (uplink)"},
    { 0x64, "data, 43.5 kbit/s (downlink)+29.0 kbps (uplink)"},
    { 0x67, "data, 14.5 kbit/s (downlink)+43.5 kbps (uplink)"},
    { 0x65, "data, 14.5 kbit/s (downlink)+29.0 kbps (uplink)"},
    { 0x66, "data, 29.0 kbit/s (downlink)+43.5 kbps (uplink)"},
    { 0x27, "data, 43.5 kbit/s radio interface rate"},
    { 0x63, "data, 32.0 kbit/s radio interface rate"},
    { 0x43, "data, 29.0 kbit/s radio interface rate"},
    { 0x0f, "data, 14.5 kbit/s radio interface rate"},
    { 0x03, "data, 12.0 kbit/s radio interface rate"},
    { 0x0b, "data, 6.0 kbit/s radio interface rate"},
    { 0x13, "data, 3.6 kbit/s radio interface rate"},
    {    0, NULL }
};

guint16
de_rr_ch_mode(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_channel_mode, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.7 Channel Mode 2
 */

static const value_string gsm_a_rr_channel_mode2_vals[] = {
    { 0x00, "signalling only"},
    { 0x05, "speech half rate version 1(GSM HR)"},
    { 0x25, "speech half rate version 2(GSM EFR)"},
    { 0x45, "speech half rate version 3(HR AMR)"},
    { 0x85, "speech half rate version 4(OHR AMR-WB)"},
    { 0x06, "speech half rate version 6(OHR AMR )"},
    { 0x0f, "data, 6.0 kbit/s radio interface rate"},
    { 0x17, "data, 3.6 kbit/s radio interface rate"},
    {    0, NULL }
};

static guint16
de_rr_ch_mode2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_channel_mode2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.7a UTRAN Classmark information element
 */
static guint16
de_rr_utran_cm(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32   curr_offset;
    tvbuff_t *rrc_irat_ho_info_tvb;

    curr_offset = offset;
    if (len)
    {
        rrc_irat_ho_info_tvb = tvb_new_subset(tvb, curr_offset, len, len);
        if (rrc_irat_ho_info_handle)
            call_dissector(rrc_irat_ho_info_handle, rrc_irat_ho_info_tvb, pinfo, tree);
    }

    curr_offset += len;
    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.7b (void)
 */

/*
 * [3] 10.5.2.7c Classmark Enquiry Mask
 * Bit 8:
 * 0    CLASSMARK CHANGE message is requested
 * 1    CLASSMARK CHANGE message is not requested
 * Bits 7-5 . 5
 * 000  UTRAN CLASSMARK CHANGE message including status on predefined configurations (i.e. Sequence Description) is requested
 * 111  UTRAN CLASSMARK CHANGE message including status on predefined configurations (i.e. Sequence Description) is not requested.
 * All other values shall not be sent. If received, they shall be interpreted as '000'.
 * Bit 4:
 * 0    CDMA2000 CLASSMARK CHANGE message requested
 * 1    CDMA2000 CLASSMARK CHANGE message not requested.
 * Bit 3:
 * 0    GERAN IU MODE CLASSMARK CHANGE message requested
 * 1    GERAN IU MODE CLASSMARK CHANGE message not requested.
 * Bits 2 - 1: spare(0).
 */
static const true_false_string gsm_a_msg_req_value  = {
    "message is not requested",
    "message is requested"
};

static const value_string gsm_a_rr_utran_cm_cng_msg_req_vals[] = {
    { 0x0, "message including status on predefined configurations (i.e. Sequence Description) is requested"},
    { 0x1, "message including status on predefined configurations (i.e. Sequence Description) is requested"},
    { 0x2, "message including status on predefined configurations (i.e. Sequence Description) is requested"},
    { 0x3, "message including status on predefined configurations (i.e. Sequence Description) is requested"},
    { 0x4, "message including status on predefined configurations (i.e. Sequence Description) is requested"},
    { 0x5, "message including status on predefined configurations (i.e. Sequence Description) is requested"},
    { 0x6, "message including status on predefined configurations (i.e. Sequence Description) is requested"},
    { 0x7, "message including status on predefined configurations (i.e. Sequence Description) is not requested."},
    {   0, NULL }
};
guint16
de_rr_cm_enq_mask(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_cm_cng_msg_req, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_rr_utran_cm_cng_msg_req, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_rr_cdma200_cm_cng_msg_req, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_rr_geran_iu_cm_cng_msg_req, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.8 Channel Needed
 */
static const value_string gsm_a_rr_channel_needed_vals[] = {
    { 0x00, "Any channel"},
    { 0x01, "SDCCH"},
    { 0x02, "TCH/F (Full rate)"},
    { 0x03, "TCH/H or TCH/F (Dual rate)"},
    {    0, NULL }
};
guint16
de_rr_chnl_needed(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    gint    bit_offset;

    curr_offset = offset;
    if (RIGHT_NIBBLE == len)
        bit_offset = 4;
    else
        bit_offset = 0;

    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_chnl_needed_ch1, tvb, (curr_offset<<3)+bit_offset+2, 2, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_chnl_needed_ch2, tvb, (curr_offset<<3)+bit_offset, 2, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.8a Channel Request Description
 */

 /*
 * [3] 10.5.2.8b Channel Request Description 2
 */
static const value_string gsm_a_rr_pkt_estab_cause_vals[] = {
    { 0x00, "User Data"},
    { 0x01, "Page Response"},
    { 0x02, "Cell Update"},
    { 0x03, "Mobility Management procedure"},
    {    0, NULL }
};
static const value_string gsm_a_rr_radio_priority_vals[] = {
    { 0x00, "1"},
    { 0x01, "2"},
    { 0x02, "3"},
    { 0x03, "4"},
    {    0, NULL }
};
static const true_false_string gsm_a_rr_llc_pdu_type_value = {
    "LLC PDU is not SACK or ACK",
    "LLC PDU is SACK or ACK"
};
static const true_false_string gsm_a_rr_reduced_latency_cap_value = {
    "The mobile station supports Reduced TTI configurations and Fast Ack/Nack Reporting",
    "The mobile station does not support Reduced TTI configurations and Fast Ack/Nack Reporting"
};
static const value_string gsm_a_rr_egprs2_vals[] = {
    { 0x00, "The mobile station does not support either EGPRS2-A or EGPRS2-B"},
    { 0x01, "The mobile station supports EGPRS2-A"},
    { 0x02, "The mobile station supports both EGPRS2-A and EGPRS2-B"},
    {    0, NULL }
};
guint16
de_rr_chnl_req_desc2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 bit_offset = offset << 3;

    proto_tree_add_bits_item(tree, hf_gsm_a_rr_pkt_estab_cause, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    bit_offset += 2;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_peak_throughput_class, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset += 4;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_radio_priority, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    bit_offset += 2;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_rlc_mode, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_llc_pdu_type, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_rlc_octet_count, tvb, bit_offset, 16, ENC_BIG_ENDIAN);
    bit_offset += 16;
    if (gsm_rr_csn_flag(tvb, tree, bit_offset++, "PFI", "Present", "Not Present")) {
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_pfi, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
        bit_offset += 7;
    }
    gsm_rr_csn_HL_flag(tvb, tree, 0, bit_offset++, "Multiple TBF Capability",
                             "Multiple TBF procedures in A/Gb mode supported",
                             "Multiple TBF procedures in A/Gb mode not supported");
    bit_offset += 1;
    if (gsm_rr_csn_HL_flag(tvb, tree, (offset+len)<<3, bit_offset++, "Additions in Rel-7", "Present", "Not present")) {
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_rlc_non_pers_mode_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_reduced_latency_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_ul_egprs2, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset += 2;
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_dl_egprs2, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset += 2;
        if (gsm_rr_csn_HL_flag(tvb, tree, (offset+len)<<3, bit_offset++, "Additions in Rel-9", "Present", "Not present")) {
            proto_tree_add_bits_item(tree, hf_gsm_a_rr_emst_ms_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset += 1;
        }
    }

    return len;
}

/*
 * [3] 10.5.2.9 Cipher Mode Setting
 */
/* SC (octet 1) */
static const value_string gsm_a_rr_sc_vals[] = {
    { 0, "No ciphering"},
    { 1, "Start ciphering"},
    { 0, NULL }
};
/* algorithm identifier
 * If SC=1 then:
 * bits
 * 4 3 2
 */
guint16
de_rr_cip_mode_set(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    gint    bit_offset;
    guint64 value;

    curr_offset = offset;

    /* Cipher Mode Setting
     * Note: The coding of fields SC and algorithm identifier is defined in [44.018]
     * as part of the Cipher Mode Setting IE.
     */
    if (RIGHT_NIBBLE == len)
        bit_offset = 4;
    else
        bit_offset = 0;

    proto_tree_add_bits_ret_val(tree, hf_gsm_a_rr_sc, tvb, (curr_offset<<3)+bit_offset+3, 1, &value, ENC_BIG_ENDIAN);
    if (value == 1){ /* Start ciphering */
        /* algorithm identifier */
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_algorithm_id, tvb, (curr_offset<<3)+bit_offset, 3, ENC_BIG_ENDIAN);
    }
    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.10 Cipher Response
 */
/* CR (octet 1) */
static const value_string gsm_a_rr_cr_vals[] = {
    { 0, "IMEISV shall not be included"},
    { 1, "IMEISV shall be included"},
    { 0, NULL }
};

static guint16
de_rr_cip_mode_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    gint    bit_offset;

    curr_offset = offset;
    if (RIGHT_NIBBLE == len)
        bit_offset = 4;
    else
        bit_offset = 0;

    /* Cipher Mode Response
     * Note: The coding of field CR is defined in [44.018]
     * as part of the Cipher Mode Response IE.
     */
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_cr, tvb, (curr_offset<<3)+bit_offset+3, 1, ENC_BIG_ENDIAN);
    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/* [3] 10.5.2.11 Control Channel Description */

static const value_string gsm_a_rr_mscr_vals[] = {
    { 0, "MSC is Release '98 or older"},
    { 1, "MSC is Release '99 onwards"},
    { 0, NULL }
};

static const value_string gsm_a_rr_att_vals[] = {
    { 0, "MSs in the cell are not allowed to apply IMSI attach and detach procedure"},
    { 1, "MSs in the cell shall apply IMSI attach and detach procedure"},
    { 0, NULL }
};

static const value_string gsm_a_rr_ccch_conf_vals[] = {
    { 0, "1 basic physical channel used for CCCH, not combined with SDCCHs"},
    { 1, "1 basic physical channel used for CCCH, combined with SDCCHs"},
    { 2, "2 basic physical channels used for CCCH, not combined with SDCCHs"},
    { 3, "Reserved"},
    { 4, "3 basic physical channels used for CCCH, not combined with SDCCHs"},
    { 5, "Reserved"},
    { 6, "4 basic physical channels used for CCCH, not combined with SDCCHs"},
    { 7, "Reserved"},
    { 0, NULL }
};

static const value_string gsm_a_rr_cbq3_vals[] = {
    { 0, "Iu mode not supported"},
    { 1, "Iu mode capable MSs barred"},
    { 2, "Iu mode supported, cell not barred"},
    { 3, "Iu mode supported, cell not barred"},
    { 0, NULL }
};

static guint16
de_rr_ctrl_ch_desc(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8  oct;
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(subtree, hf_gsm_a_rr_mscr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_rr_att, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_rr_bs_ag_blks_res, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_rr_ccch_conf, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;
    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_cbq3, tvb, (curr_offset<<3)+1, 2, ENC_BIG_ENDIAN);
    proto_tree_add_uint(subtree, hf_gsm_a_rr_bs_pa_mfrms, tvb, curr_offset, 1, (oct&0x07)+2);

    curr_offset = curr_offset + 1;

    proto_tree_add_item(subtree, hf_gsm_a_rr_t3212, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/* [3] 10.5.2.11a  DTM Information Details
 */
static guint16
de_rr_dtm_info_details(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 bit_offset = offset << 3;

    proto_tree_add_bits_item(tree, hf_gsm_a_rr_max_lapdm, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset += 3;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_gprs_ms_txpwr_max_ccch, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
    bit_offset += 5;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_cell_id, tvb, bit_offset, 16, ENC_BIG_ENDIAN);
    bit_offset += 16;
    if (gsm_rr_csn_HL_flag(tvb, tree, (offset+len)<<3, bit_offset++, "Additions in Rel-6", "Present", "Not present")) {
        if (gsm_rr_csn_flag(tvb, tree, bit_offset++, "MBMS procedures", "Supported by cell", "Not supported by cell")) {
            proto_tree_add_bits_item(tree, hf_gsm_a_rr_dedicated_mode_mbms_notification_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset += 1;
            proto_tree_add_bits_item(tree, hf_gsm_a_rr_mnci_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset += 1;
        }
    }

    return len;
}

/*
 * [3] 10.5.2.11b  Dynamic ARFCN Mapping
 */
static const value_string gsm_a_rr_gsm_band_vals[] = {
    {  0, "GSM 750"},
    {  1, "DCS 1800"},
    {  2, "PCS 1900"},
    {  3, "GSM T 380"},
    {  4, "GSM T 410"},
    {  5, "GSM T 900"},
    {  6, "GSM 710"},
    {  7, "GSM T 810"},
    {  8, "Reserved"},
    {  9, "Reserved"},
    { 10, "Reserved"},
    { 11, "Reserved"},
    { 12, "Reserved"},
    { 13, "Reserved"},
    { 14, "Reserved"},
    { 15, "Reserved"},
    {  0, NULL }
};


static guint16
de_rr_dyn_arfcn_map(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint bit_offset;

    bit_offset = offset << 3;

    while (gsm_rr_csn_flag(tvb, tree, bit_offset++, "Repeating Dynamic ARFCN Mapping", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_gsm_band, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset += 4;
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_arfcn_first, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_band_offset, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
        bit_offset += 10;
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_arfcn_range, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
        bit_offset += 7;
    }

    if (((bit_offset + 7) >> 3) > (offset + len))
    {
       expert_add_info_format(pinfo, proto_tree_get_parent(tree), PI_MALFORMED, PI_ERROR, "IE over-runs stated length");
    }
    else if ((bit_offset >> 3) < (offset + len))
    {
       expert_add_info_format(pinfo, proto_tree_get_parent(tree), PI_COMMENTS_GROUP, PI_NOTE, "IE under-runs stated length");
    }
    return(len);
}
/*
 * [3] 10.5.2.12 Frequency Channel Sequence
 */
static guint16
de_rr_freq_ch_seq(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    gint    bit_offset, i;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_lowest_arfcn, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset += 1;
    bit_offset = curr_offset << 3;
    for (i=0; i<16; i++)
    {
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_inc_skip_arfcn, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
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
    { 0x00, "bit map 0"},
    { 0x02, "bit map 0"},
    { 0x04, "bit map 0"},
    { 0x06, "bit map 0"},
    { 0x08, "bit map 0"},
    { 0x0a, "bit map 0"},
    { 0x0c, "bit map 0"},
    { 0x0e, "bit map 0"},
    { 0x40, "1024 range"},
    { 0x41, "1024 range"},
    { 0x42, "1024 range"},
    { 0x43, "1024 range"},
    { 0x44, "512 range"},
    { 0x45, "256 range"},
    { 0x46, "128 range"},
    { 0x47, "variable bit map"},
    { 0x00, NULL }
};

static guint16
de_rr_freq_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    return dissect_arfcn_list(tvb, tree, pinfo, offset, len, add_string, string_len);
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

 static guint16
de_rr_freq_short_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
 {
     return dissect_arfcn_list(tvb, tree, pinfo, offset, 9, add_string, string_len);
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
static guint16
de_rr_freq_short_list2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    return dissect_arfcn_list(tvb, tree, pinfo, offset, 8, add_string, string_len);
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

static guint16
de_rr_gprs_resumption(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_gprs_resumption_ack, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
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
    gint        curr_bit_offset, curr_bit_offset_sav;
    guint8      value;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_CELL_OPTIONS].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_CELL_OPTIONS]);
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_nmo, tvb, curr_bit_offset, 2, ENC_BIG_ENDIAN);
    curr_bit_offset += 2;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_t3168, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
    curr_bit_offset += 3;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_t3192, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
    curr_bit_offset += 3;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_drx_timer_max, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
    curr_bit_offset += 3;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_access_burst_type, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
    curr_bit_offset += 1;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_control_ack_type, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
    curr_bit_offset += 1;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bs_cv_max, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
    curr_bit_offset += 4;
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "PAN bits", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pan_dec, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pan_inc, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pan_max, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
    }
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Optional Extensions", "Present", "Not Present"))
    { /* Optional extension information */
        curr_bit_offset_sav = curr_bit_offset;
        item2 = proto_tree_add_text(subtree, tvb, curr_bit_offset>>3, -1, "%s",
                                    gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_CELL_OPTIONS_EXT_INFO].strptr);
        subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_CELL_OPTIONS_EXT_INFO]);
        value = tvb_get_bits8(tvb,curr_bit_offset,6);
        proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, 1, "Extension Length: %d", value);
        curr_bit_offset += 6;
        value += 1;
        proto_item_set_len(item2,((curr_bit_offset+value)>>3) - (curr_bit_offset_sav>>3)+1);
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "EGPRS", "Supported by cell", "Not supported by cell"))
        {
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_egprs_packet_channel_request, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
            curr_bit_offset += 1;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_bep_period, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
            curr_bit_offset += 4;
            value -= 5;
        }
        value -= 1;
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_pfc_feature_mode, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_dtm_support, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_bss_paging_coordination, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        value -= 3;
        if (value > 0)
        { /* Rel 4 extension */
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_ccn_active, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
            curr_bit_offset += 1;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_nw_ext_utbf, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
            curr_bit_offset += 1;
            value -= 2;
            if (value > 0)
            { /* Rel 6 extension */
                proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_multiple_tbf_capability, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
                curr_bit_offset += 1;
                proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_ext_utbf_no_data, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
                curr_bit_offset += 1;
                proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_dtm_enhancements_capability, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
                curr_bit_offset += 1;
                value -= 3;
                if (gsm_rr_csn_flag(tvb, subtree2, curr_bit_offset++, "MBMS procedures", "Supported by cell", "Not supported by cell"))
                {
                    proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_dedicated_mode_mbms_notification_support, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
                    curr_bit_offset += 1;
                    proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_mnci_support, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
                    curr_bit_offset += 1;
                    value -= 2;
                }
                value -= 1;
                if (value > 0)
                { /* Rel 7 extension */
                    proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_reduced_latency_access, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
                    curr_bit_offset += 1;
                    value -= 1;
                }
            }
        }
        curr_bit_offset += value;
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return (curr_bit_offset - bit_offset);
}

static gint
de_rr_rest_oct_gprs_power_control_parameters(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_POWER_CONTROL_PARAMS].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_POWER_CONTROL_PARAMS]);
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_alpha, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
    curr_bit_offset += 4;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_t_avg_w, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
    curr_bit_offset += 5;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_t_avg_t, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
    curr_bit_offset += 5;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pc_meas_chan, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
    curr_bit_offset += 1;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_n_avg_i, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
    curr_bit_offset += 4;
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return (curr_bit_offset - bit_offset);
}

static guint16
de_rr_gprs_broadcast_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len , gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    gint    bit_offset;

    curr_offset = offset;
    bit_offset = curr_offset << 3;

    bit_offset += de_rr_rest_oct_gprs_cell_options(tvb, tree, bit_offset);
    /*bit_offset += */de_rr_rest_oct_gprs_power_control_parameters(tvb, tree, bit_offset);
    curr_offset += len;

    return (curr_offset - offset);
}

/*
 * [3] 10.5.2.15 Handover Reference
 */
static guint16
de_rr_ho_ref(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    /* Handover reference value */
    proto_tree_add_item(subtree, hf_gsm_a_rr_ho_ref_val, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

static const value_string gsm_a_access_tech_type_vals[] = {
    { 0, "GSM P"},
    { 1, "GSM E --note that GSM E covers GSM P"},
    { 2, "GSM R --note that GSM R covers GSM E and GSM P"},
    { 3, "GSM 1800"},
    { 4, "GSM 1900"},
    { 5, "GSM 450"},
    { 6, "GSM 480"},
    { 7, "GSM 850"},
    { 8, "GSM 750"},
    { 9, "GSM T 380"},
    { 10, "GSM T 410"},
    { 11, "GSM T 900"},
    { 12, "GSM 710"},
    { 13, "GSM T 810"},
    { 14, "reserved"},
    { 15, "Indicates the presence of a list of Additional access technologies"},
    { 0, NULL }
};


static const value_string gsm_a_egprs_mcs_vals[] = {
    { 0, "MCS-1"},
    { 1, "MCS-2"},
    { 2, "MCS-3"},
    { 3, "MCS-4"},
    { 4, "MCS-5"},
    { 5, "MCS-6"},
    { 6, "MCS-7"},
    { 7, "MCS-8"},
    { 8, "MCS-9"},
    { 9, "MCS-5-7"},
    { 10, "MCS-6-9"},
    { 11, "reserved"},
    { 0, NULL }
};

static const value_string gsm_a_gprs_cs_vals[] = {
    { 0, "CS-1"},
    { 1, "CS-2"},
    { 2, "CS-3"},
    { 3, "CS-4"},
    { 0, NULL }
};


static const true_false_string gsm_a_tlli_block_channel_coding_vals = {
    "mobile station shall use coding scheme as specified by the corresponding CHANNEL CODING COMMAND or EGPRS CHANNEL CODING COMMAND field",
    "mobile station shall use CS-1 in GPRS TBF mode or MCS-1 in EGPRS TBF mode"
};

static const true_false_string gsm_a_resegment_vals = {
    "Retransmitted RLC data blocks shall be re-segmented according to commanded MCS",
    "Retransmitted RLC data blocks shall not be re-segmented"
};

static const true_false_string gsm_a_polling_vals = {
    "MS shall send a PACKET CONTROL ACKNOWLEDGEMENT message in the uplink block specified by TBF Starting Time, on the assigned PDCH",
    "no action is required from MS"
};

static const true_false_string gsm_a_usf_granularity_vals = {
    "the mobile station shall transmit four consecutive RLC/MAC blocks",
    "the mobile station shall transmit one RLC/MAC block"
};

static const true_false_string gsm_a_rlc_mode_vals = {
    "RLC unacknowledged mode",
    "RLC acknowledged mode"
};

static const true_false_string gsm_a_ta_valid_vals = {
    "the timing advance value is valid",
    "the timing advance value is not valid"
};



static const value_string gsm_a_egprs_windows_size_vals[] = {
    { 0, "64"},
    { 1, "96"},
    { 2, "128"},
    { 3, "160"},
    { 4, "192"},
    { 5, "224"},
    { 6, "256"},
    { 7, "288"},
    { 8, "320"},
    { 9, "352"},
    { 10, "384"},
    { 11, "416"},
    { 12, "448"},
    { 13, "480"},
    { 14, "512"},
    { 15, "544"},
    { 16, "576"},
    { 17, "608"},
    { 18, "640"},
    { 19, "672"},
    { 20, "704"},
    { 21, "736"},
    { 22, "768"},
    { 23, "800"},
    { 24, "832"},
    { 25, "864"},
    { 26, "896"},
    { 27, "928"},
    { 28, "960"},
    { 29, "992"},
    { 30, "1024"},
    { 31, "reserved"},
    { 0, NULL }
};

static const value_string gsm_a_rr_gamma_vals[] = {
    {  0, "0 dB"},
    {  1, "2 dB"},
    {  2, "4 dB"},
    {  3, "6 dB"},
    {  4, "8 dB"},
    {  5, "10 dB"},
    {  6, "12 dB"},
    {  7, "14 dB"},
    {  8, "16 dB"},
    {  9, "18 dB"},
    { 10, "20 dB"},
    { 11, "22 dB"},
    { 12, "24 dB"},
    { 13, "26 dB"},
    { 14, "28 dB"},
    { 15, "30 dB"},
    { 16, "32 dB"},
    { 17, "34 dB"},
    { 18, "36 dB"},
    { 19, "38 dB"},
    { 20, "40 dB"},
    { 21, "42 dB"},
    { 22, "44 dB"},
    { 23, "46 dB"},
    { 24, "48 dB"},
    { 25, "50 dB"},
    { 26, "52 dB"},
    { 27, "54 dB"},
    { 28, "56 dB"},
    { 29, "58 dB"},
    { 30, "60 dB"},
    { 31, "62 dB"},
    {  0, NULL }
};



static const value_string gsm_a_link_quality_meas_mode_vals[] = {
    {  0, "The MS shall not report either interference measurements or per slot BEP measurements"},
    {  1, "The MS shall report available interference measurements for timeslots 0 through 7"},
    {  2, "The MS shall report mean BEP on each assigned time slot ... No interference measurements shall be reported..."},
    {  3, "The MS shall report mean BEP on each assigned time slot ... In addition to mean BEP, the MS shall report interference measurements for no more than four time slots..."},
    {  0, NULL }
};


static guint16
de_tbf_starting_time(tvbuff_t *tvb, proto_tree *tree, guint32 bit_offset)
{
    proto_item *item;
    guint32     curr_bit_offset;
    guint16     rfn, t;
    guint64     t1, t2, t3;

    curr_bit_offset = bit_offset;

    proto_tree_add_bits_ret_val(tree, hf_gsm_a_rr_tbf_T1prim, tvb, curr_bit_offset, 5, &t1, ENC_BIG_ENDIAN);
    curr_bit_offset += 5;
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_rr_tbf_T3, tvb, curr_bit_offset, 6, &t3, ENC_BIG_ENDIAN);
    curr_bit_offset += 6;
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_rr_tbf_T2, tvb, curr_bit_offset, 5, &t2, ENC_BIG_ENDIAN);
    curr_bit_offset += 5;


    /* great care needed with signed/unsigned - -1 in unsigned is 0xffff, which mod(26) is not what you think !!! */
    t = (26 + t3 - t2) % 26;
    rfn = (guint16)((51 * t) + t3 + (51 * 26 * t1));

    item = proto_tree_add_uint(tree, hf_gsm_a_rr_tbf_starting_time, tvb, bit_offset >> 3, ((curr_bit_offset - bit_offset) >> 3) + 1, rfn);
    PROTO_ITEM_SET_GENERATED(item);
    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_ia_rest_oct_egprs_packet_uplink_assignment(tvbuff_t *tvb, proto_tree *tree, gint bit_offset, guint bit_len)
{
    proto_tree *subtree;
    proto_item *item;
    guint       curr_bit_offset;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_EGPRS_PACKET_UPLINK_ASSIGNMENT].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_EGPRS_PACKET_UPLINK_ASSIGNMENT]);
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_extended_ra, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
    curr_bit_offset += 5;
    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Access Technologies Request", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_access_tech_type, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
        curr_bit_offset += 4;
    }

    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "", "TFI Assignment Present", "Multi Block Allocation   Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_tfi_assignment, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_polling, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Allocation Type", "Fixed Allocation (not to be used after Rel-4)", "Dynamic Allocation (mandatory after Rel-4)"))
        {
           gint8 bitmap_len = tvb_get_bits8(tvb, curr_bit_offset, 5);
           gint32 bitmap;
           proto_tree_add_text(tree, tvb, curr_bit_offset>>3, 1+((curr_bit_offset+5)>>3) - (curr_bit_offset>>3), "Bitmap length %d", bitmap_len);
           curr_bit_offset += 5;
           bitmap = tvb_get_bits32(tvb, curr_bit_offset, bitmap_len, ENC_BIG_ENDIAN);
           proto_tree_add_text(tree, tvb, curr_bit_offset>>3, 1+((curr_bit_offset+bitmap_len)>>3) - (curr_bit_offset>>3), "Bitmap %d", bitmap);
           curr_bit_offset += bitmap_len;
           if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "P0 bits", "Present", "Not Present"))
           {
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_p0, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
               curr_bit_offset += 4;
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pr_mode, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
               curr_bit_offset += 1;
           }
        }
        else
        {
           proto_tree_add_bits_item(subtree, hf_gsm_a_rr_usf, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
           curr_bit_offset += 3;
           proto_tree_add_bits_item(subtree, hf_gsm_a_rr_usf_granularity, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
           curr_bit_offset += 1;
           if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "P0 bits", "Present", "Not Present"))
           {
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_p0, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
               curr_bit_offset += 4;
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pr_mode, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
               curr_bit_offset += 1;
           }
        }

        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_egprs_mcs, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
        curr_bit_offset += 4;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_tlli_block_channel_coding, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "BEP_PERIOD2", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bep_period2, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
            curr_bit_offset += 4;
        }
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_resegment, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_egprs_window_size, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Alpha", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_alpha, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
            curr_bit_offset += 4;
        }
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_gamma, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Timing Advance Index", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_timing_adv_index, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
            curr_bit_offset += 4;
        }
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "TBF Starting Time", "Present", "Not Present"))
        {
            curr_bit_offset += de_tbf_starting_time(tvb, subtree, curr_bit_offset);
        }
        /* Null breakpoint */
    }
    else  /*  Multi Block Allocation */
    {
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Alpha", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_alpha, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
            curr_bit_offset += 4;
        }
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_gamma, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
        curr_bit_offset += de_tbf_starting_time(tvb, subtree, curr_bit_offset);
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_num_of_radio_block_allocated, tvb, curr_bit_offset, 2, ENC_BIG_ENDIAN);
        curr_bit_offset += 2;
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "P0 bits", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_p0, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
            curr_bit_offset += 4;
            gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "BTS Power Control Mode", "Mode B (not to be used after Rel-4)", "Mode A (mandatory after Rel-4)");
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pr_mode, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
            curr_bit_offset += 1;
        }

        /* Null breakpoint */
        if (curr_bit_offset < bit_len)
        {
           if (gsm_rr_csn_HL_flag(tvb,subtree, 0,curr_bit_offset++,"Additions in Rel-7", "Present", "Not present"))
           {
               if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "PFI", "Present", "Not Present"))
               {
                   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pfi, tvb, curr_bit_offset, 7, ENC_BIG_ENDIAN);
                   curr_bit_offset += 7;
               }
           }
        }
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return (curr_bit_offset - bit_offset);
}


static gint
de_rr_ia_rest_oct_tmgi(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;
    guint16     value16;
    gchar       mcc[4];
    gchar       mnc[4];

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_TMGI].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_TMGI]);

    if (0 == gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "MCC and MNC Parameters", "Present", "Not Present"))   /*  without MCC and MNC parameters */
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_mbms_service_id, tvb, curr_bit_offset, 24, ENC_BIG_ENDIAN);
        curr_bit_offset += 24;
    }
    else   /* with MCC and MNC parameters */
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_mbms_service_id, tvb, curr_bit_offset, 24, ENC_BIG_ENDIAN);
        curr_bit_offset += 24;

        value16 = tvb_get_bits16(tvb,curr_bit_offset,12,ENC_BIG_ENDIAN);
        mcc[0] = '0' + ((value16>>8)&0xf);
        mcc[1] = '0' + ((value16>>4)&0xf);
        mcc[2] = '0' + ((value16   )&0xf);
        mcc[3] = '\0';
        proto_tree_add_text(tree,
            tvb, curr_bit_offset>>3, 12,
            "Mobile Country Code (MCC): %s",
            mcc);
        curr_bit_offset += 12;

        value16 = tvb_get_bits16(tvb,curr_bit_offset,12,ENC_BIG_ENDIAN);
        mnc[0] = '0' + ((value16>>8)&0xf);
        mnc[1] = '0' + ((value16>>4)&0xf);
        mnc[2] = '0' + ((value16   )&0xf);
        mnc[3] = '\0';
        proto_tree_add_text(tree,
            tvb, curr_bit_offset>>3, 12,
            "Mobile Network Code (MNC): %s",
            mnc);
        curr_bit_offset += 12;
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return (curr_bit_offset - bit_offset);
}



static gint
de_rr_ia_rest_oct_packet_timing_advance(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;


    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_PACKET_TIMING_ADVANCE].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_PACKET_TIMING_ADVANCE]);

    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Timing Advance Value", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_timing_adv, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
        curr_bit_offset += 6;
    }

    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Timing Advance Index and Timeslot", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_timing_adv_index, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
        curr_bit_offset += 4;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_timing_adv_timeslot_num, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return (curr_bit_offset - bit_offset);
}



static gint
de_rr_ia_rest_oct_multiple_blocks_packet_downlink_assignment(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;
    guint8      value;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_MULTIPLE_BLOCKS_PACKET_DOWNLINK_ASSIGNMENT].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_MULTIPLE_BLOCKS_PACKET_DOWNLINK_ASSIGNMENT]);

    curr_bit_offset += de_tbf_starting_time(tvb, subtree, curr_bit_offset);
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_num_of_radio_block_allocated, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
    curr_bit_offset += 4;

    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "", "default 0 bit", "Reserved Value"))
    {
        if (0 == gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "MBMS Assignment", "(Non-distribution)", "(Distribution)"))
        {/* MBMS Assignment (Distribution) */
            curr_bit_offset += de_rr_ia_rest_oct_tmgi(tvb, tree, curr_bit_offset);
        }
        else   /* MBMS Assignment (Non-distribution) */
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_tlli, tvb, curr_bit_offset, 32, ENC_BIG_ENDIAN);
            curr_bit_offset += 32;
            if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "MS Parameters", "Present", "Not Present"))
            {
                value = tvb_get_bits8(tvb,curr_bit_offset,2);
                proto_tree_add_text(tree,
                    tvb, curr_bit_offset>>3, 2,
                    "Length Indicator of MS ID: %d",
                    value);
                curr_bit_offset += 2;

                proto_tree_add_bits_item(subtree, hf_gsm_a_rr_ms_id, tvb, curr_bit_offset, value+1, ENC_BIG_ENDIAN);
                curr_bit_offset += value+1;
                curr_bit_offset += de_rr_ia_rest_oct_packet_timing_advance(tvb, tree, curr_bit_offset);
                if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Alpha", "Present", "Not Present"))
                {
                    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_alpha, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
                    curr_bit_offset += 4;
                    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Gamma", "Present", "Not Present"))
                    {
                        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_gamma, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
                        curr_bit_offset += 5;
                    }
                }
            }
        }
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return (curr_bit_offset - bit_offset);
}




static gint
de_rr_ia_rest_oct_packet_uplink_assignment(tvbuff_t *tvb, proto_tree *tree, gint bit_offset, guint bit_len)
{
    proto_tree *subtree;
    proto_item *item;
    guint       curr_bit_offset;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_PACKET_UPLINK_ASSIGNMENT].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_PACKET_UPLINK_ASSIGNMENT]);

    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Packet Uplink Assignment", "Normal", "Single Block"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_tfi_assignment, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_polling, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Allocation Type", "Fixed Allocation (not to be used after Rel-4))", "Dynamic Allocation (mandatory after Rel-4)"))
        {
           gint8 bitmap_len = tvb_get_bits8(tvb, curr_bit_offset, 5);
           gint32 bitmap;
           proto_tree_add_text(tree, tvb, curr_bit_offset>>3, 1+((curr_bit_offset+5)>>3) - (curr_bit_offset>>3), "Bitmap length %d", bitmap_len);
           curr_bit_offset += 5;
           bitmap = tvb_get_bits32(tvb, curr_bit_offset, bitmap_len, ENC_BIG_ENDIAN);
           proto_tree_add_text(tree, tvb, curr_bit_offset>>3, 1+((curr_bit_offset+bitmap_len)>>3) - (curr_bit_offset>>3), "Bitmap %d", bitmap);
           curr_bit_offset += bitmap_len;
           if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "P0 bits", "Present", "Not Present"))
           {
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_p0, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
               curr_bit_offset += 4;
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pr_mode, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
               curr_bit_offset += 1;
           }
        }
        else
        {
           proto_tree_add_bits_item(subtree, hf_gsm_a_rr_usf, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
           curr_bit_offset += 3;
           proto_tree_add_bits_item(subtree, hf_gsm_a_rr_usf_granularity, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
           curr_bit_offset += 1;
           if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "P0", "Present", "Not Present"))
           {
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_p0, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
               curr_bit_offset += 4;
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pr_mode, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
               curr_bit_offset += 1;
           }
        }
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_gprs_cs, tvb, curr_bit_offset, 2, ENC_BIG_ENDIAN);
        curr_bit_offset += 2;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_tlli_block_channel_coding, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Alpha", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_alpha, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
            curr_bit_offset += 4;
        }
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_gamma, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Timing Advance Index", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_timing_adv_index, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
            curr_bit_offset += 4;
        }
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "TBF Starting Time", "Present", "Not Present"))
        {
           curr_bit_offset += de_tbf_starting_time(tvb, subtree, curr_bit_offset);
        }
    }
    else  /* Single Block Allocation */
    {
       if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Alpha", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_alpha, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
            curr_bit_offset += 4;
        }
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_gamma, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
        /* fixed bits '01' */
        gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Bit reserved for earlier version of protocol", "Early R97 version", "Later than R97 version");
        gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Bit reserved for earlier version of protocol", "Later than R97 version",  "Early R97 version");
        curr_bit_offset += de_tbf_starting_time(tvb, subtree, curr_bit_offset);
        if (gsm_rr_csn_HL_flag(tvb,subtree, 0,curr_bit_offset++,"P0", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_p0, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
            curr_bit_offset += 4;
            /* The value '1' was allocated in an earlier version of the protocol and shall not be used */
            gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Bit reserved for earlier version of protocol", "Earlier version", "Current version");
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pr_mode, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
            curr_bit_offset += 1;
        }
    }

    /* Null breakpoint */
    if (curr_bit_offset < bit_len)
    {
       if (gsm_rr_csn_HL_flag(tvb,subtree, 0,curr_bit_offset++,"Additions in R99", "Present", "Not Present"))
       {
           if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Extended RA", "Present", "Not Present"))
           {
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_extended_ra, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
               curr_bit_offset += 5;
           }
       }
    }

    /* Null breakpoint */
    if (curr_bit_offset < bit_len)
    {
       if (gsm_rr_csn_HL_flag(tvb,subtree, 0,curr_bit_offset++,"Additions in Rel-6", "Present", "Not Present"))
       {
           if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "PFI", "Present", "Not Present"))
           {
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pfi, tvb, curr_bit_offset, 7, ENC_BIG_ENDIAN);
               curr_bit_offset += 7;
           }
       }
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return (curr_bit_offset - bit_offset);
}


static gint
de_rr_ia_rest_oct_packet_downlink_assignment(tvbuff_t *tvb, proto_tree *tree, guint bit_offset, guint bit_len)
{
    proto_tree *subtree;
    proto_item *item;
    guint       curr_bit_offset;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_PACKET_DOWNLINK_ASSIGNMENT].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_PACKET_DOWNLINK_ASSIGNMENT]);

    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_tlli, tvb, curr_bit_offset, 32, ENC_BIG_ENDIAN);
    curr_bit_offset += 32;

    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "TFI Assignment (etc)", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_tfi_assignment, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rlc_mode, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Alpha", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_alpha, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
            curr_bit_offset += 4;
        }
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_gamma, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_polling, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_ta_valid, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
    }
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Timing Advance Index", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_timing_adv_index, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
        curr_bit_offset += 4;
    }
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "TBF Starting Time", "Present", "Not Present"))
    {
       curr_bit_offset += de_tbf_starting_time(tvb, subtree, curr_bit_offset);
    }
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "P0", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_p0, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
        curr_bit_offset += 4;
        gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "BTS Power Control Mode", "Mode B (not to be used after Rel-4)", "Mode A (mandatory after Rel-4)");
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pr_mode, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
    }

    /* Null breakpoint */
    if (curr_bit_offset < bit_len)
    {
       if (gsm_rr_csn_HL_flag(tvb,subtree, 0,curr_bit_offset++,"Additions in R99", "Present", "Not Present"))
       {
           proto_tree_add_bits_item(subtree, hf_gsm_a_rr_egprs_window_size, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
           curr_bit_offset += 5;
           proto_tree_add_bits_item(subtree, hf_gsm_a_rr_link_quality_meas_mode, tvb, curr_bit_offset, 2, ENC_BIG_ENDIAN);
           curr_bit_offset += 2;
           if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "BEP_PERIOD2", "Present", "Not Present"))
           {
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bep_period2, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
               curr_bit_offset += 4;
           }
       }
    }

    /* Null breakpoint */
    if (curr_bit_offset < bit_len)
    {
       if (gsm_rr_csn_HL_flag(tvb,subtree, 0, curr_bit_offset++, "Additions in Rel-6", "Present", "Not Present"))
       {
           if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "PFI", "Present", "Not Present"))
           {
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_pfi, tvb, curr_bit_offset, 7, ENC_BIG_ENDIAN);
               curr_bit_offset += 7;
           }
       }
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return (curr_bit_offset - bit_offset);
}

static gint
de_rr_ia_rest_oct_second_part_packet_assignment(tvbuff_t *tvb, proto_tree *tree, guint bit_offset, guint bit_len)
{
    proto_tree *subtree;
    proto_item *item;
    guint       curr_bit_offset;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_SECOND_PART_PACKET_ASSIGNMENT].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_SECOND_PART_PACKET_ASSIGNMENT]);

    /* Null breakpoint */
    if (curr_bit_offset < bit_len)
    {
       if (gsm_rr_csn_HL_flag(tvb,subtree, 0,curr_bit_offset++,"Additions in R99", "Present", "Not Present"))
       {
           if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Extended RA", "Present", "Not Present"))
           {
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_extended_ra, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
               curr_bit_offset += 5;
           }
       }
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return (curr_bit_offset - bit_offset);
}


/*
 * [3] 10.5.2.16 IA Rest Octets
 */

static guint16
de_rr_ia_rest_oct(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    guint32     curr_offset;
    gint        bit_offset;
    gint        length;
    guint64     ma_length;
    guint8      tvb_len = tvb_length(tvb);
    guint16     bit_len = tvb_len << 3;

    curr_offset = offset;

    bit_offset = curr_offset << 3;
    if (0 == gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "First Discriminator Bit", "High", "Low"))
    {
        if (0 == gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Second Discriminator Bit", "High", "Low"))
        {
           /* LL */
           gsm_rr_csn_HL_flag(tvb, subtree, 0,bit_offset++, "A compressed version of the INTER RAT HANDOVER INFO message ", "shall be used", "shall not be used");
        }
        else   /* LH */
        {
            if (0 == gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Discriminator bit", "reserved for future use", "EGPRS Packet Uplink Assignment or Multiple blocks Packet Downlink Assignment"))
            {
                if (0 == gsm_rr_csn_flag(tvb, subtree, bit_offset++, "", "Multiple blocks Packet Downlink Assignment", "EGPRS Packet Uplink Assignment"))
                {
                    bit_offset += de_rr_ia_rest_oct_egprs_packet_uplink_assignment(tvb, subtree, bit_offset, bit_len);
                }
                else
                {
                    bit_offset += de_rr_ia_rest_oct_multiple_blocks_packet_downlink_assignment(tvb, subtree, bit_offset);
                }
            }
            else
            {
                proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "reserved for future use (however the value 7C for the first octet shall not be used)");
            }
        }
    }
    else
    {
        if (0 == gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Second Discriminator Bit", "High", "Low"))
        {
           /* HL */
            proto_tree_add_bits_ret_val(subtree, hf_gsm_a_rr_ma_length, tvb, bit_offset, 6, &ma_length, ENC_BIG_ENDIAN);
            bit_offset += 6;
            /* Frequency Parameters, before time */
            if (ma_length>0)
            {
                /* two '0' bits */
                bit_offset += 2;
                proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "MAIO: %d", tvb_get_bits8(tvb,bit_offset,6));
                bit_offset += 6;
                length = (gint)ma_length;
                item = proto_tree_add_text(subtree,tvb, bit_offset>>3, (length>>3)-1, "MA Bitmap: ");
                length = (length-1)*8;
                while (length)
                {
                    proto_item_append_text(item,"%d",tvb_get_bits8(tvb,bit_offset,1));
                    bit_offset += 1;
                    length -= 1;
                }
            }
            gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "A compressed version of the INTER RAT HANDOVER INFO message", "shall be used", "shall not be used");
        }
        else   /* HH */
        {
            if (0 == gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Discriminator Bit", "Second Part Packet Assignment", "Packet Assignment"))
            {
                if (0 == gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Discriminator Bit", "Packet Downlink Assignment", "Packet Uplink Assignment"))
                {
                      /* 00  < Packet Uplink Assignment > */
                    bit_offset += de_rr_ia_rest_oct_packet_uplink_assignment(tvb, subtree, bit_offset, bit_len);
                }
                else  /*  01     < Packet Downlink Assignment >  */
                {
                    bit_offset += de_rr_ia_rest_oct_packet_downlink_assignment(tvb, subtree, bit_offset, bit_len);
                }
            }
            else  /*  1       < Second Part Packet Assignment >   */
            {
                bit_offset += de_rr_ia_rest_oct_second_part_packet_assignment(tvb, subtree, bit_offset, bit_len);
            }
        }
    }
    gsm_rr_csn_padding_bits(subtree, tvb, bit_offset, tvb_len);
    return tvb_len - offset;
}

/*
 * [3] 10.5.2.17 IAR Rest Octets
 */

static guint16
de_rr_iar_rest_oct(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_bit_offset;
    guint8  i;
    guint8  tvb_len = tvb_length(tvb);

    curr_bit_offset = offset<<3;

    for( i=0; i<4; i++ )
    {
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Extended RA", "Present", "Not Present"))
        {
            proto_tree_add_text(subtree, tvb, curr_bit_offset>>3, 1, "Extended RA %d present", i);
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_extended_ra, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
            curr_bit_offset += 5;
        }
        else
        {
            proto_tree_add_text(subtree, tvb, curr_bit_offset>>3, 1, "Extended RA %d not present", i);
        }
    }
    gsm_rr_csn_padding_bits(subtree, tvb, curr_bit_offset, tvb_len);
    return tvb_len - offset;
}

/*
 * [3] 10.5.2.18 IAX Rest Octets
 */
static guint16
de_rr_iax_rest_oct(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_bit_offset;
    guint8  tvb_len = tvb_length(tvb);

    curr_bit_offset = offset<<3;

    gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "A compressed version of the INTER RAT HANDOVER INFO message", "shall be used", "shall not be used");

    gsm_rr_csn_padding_bits(subtree, tvb, curr_bit_offset, tvb_len);
    return tvb_len - offset;
}

/*
 * [3] 10.5.2.19 L2 Pseudo Length
 */
static guint16
de_rr_l2_pseudo_len(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    /* L2 Pseudo Length value */
    proto_tree_add_item(subtree, hf_gsm_a_rr_L2_pseudo_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.20 Measurement Results
 */
static const true_false_string gsm_a_rr_dtx_vals  = {
    "DTX was used",
    "DTX was not used"
};


static const true_false_string gsm_a_rr_mv_vals  = {
    "The measurement results are not valid",
    "The measurement results are valid"
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

guint16
de_rr_meas_res(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    gint    bit_offset;
    guint64 no_ncell_m;

    curr_offset = offset;

    /* 2nd octet */
    /* BA-USED */
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_ba_used, tvb, curr_offset<<3, 1, ENC_BIG_ENDIAN);
    /* DTX USED */
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_dtx_used, tvb, (curr_offset<<3)+1, 1, ENC_BIG_ENDIAN);
    /* RXLEV-FULL-SERVING-CELL */
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rxlev_full_serv_cell, tvb, (curr_offset<<3)+2, 6, ENC_BIG_ENDIAN);
    curr_offset++;

    /* 3rd octet */
    /* 3G-BA-USED */
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_ba_used, tvb, curr_offset<<3, 1, ENC_BIG_ENDIAN);
    /* MEAS-VALID */
    proto_tree_add_item(subtree, hf_gsm_a_rr_meas_valid, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* RXLEV-SUB-SERVING-CELL */
    proto_tree_add_item(subtree, hf_gsm_a_rr_rxlev_sub_serv_cell, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    /* 4th octet */
    /* RXQUAL-FULL-SERVING-CELL */
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rxqual_full_serv_cell, tvb, (curr_offset<<3)+1, 3, ENC_BIG_ENDIAN);

    /* RXQUAL-SUB-SERVING-CELL */
    proto_tree_add_item(subtree, hf_gsm_a_rr_rxqual_sub_serv_cell, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* NO-NCELL-M */
    bit_offset = (curr_offset << 3) + 7;
    proto_tree_add_bits_ret_val(subtree, hf_gsm_a_rr_no_ncell_m, tvb, bit_offset, 3, &no_ncell_m, ENC_BIG_ENDIAN);
    bit_offset += 3;
    if (no_ncell_m == 7) /* No neighbour cell information available) */
        no_ncell_m = 0;
    while (no_ncell_m)
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rxlev_ncell, tvb, bit_offset, 6, ENC_BIG_ENDIAN);
        bit_offset += 6;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bcch_freq_ncell, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
        bit_offset += 5;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bsic_ncell, tvb, bit_offset, 6, ENC_BIG_ENDIAN);
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
static guint16
de_rr_mob_all(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;
    proto_item *item;
    gint        i, j;
    guint8      value;

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
static guint16
de_rr_mob_time_diff(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_mobile_time_difference, tvb, curr_offset, len, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + len;
    return(curr_offset - offset);

}
/*
 * [3] 10.5.2.21aa MultiRate configuration
 */
/*    Multirate speech version Octet 3 Bits 8 7 6 */
static const value_string multirate_speech_ver_vals[] = {
    { 1, "Adaptive Multirate speech version 1"},
    { 2, "Adaptive Multirate speech version 2"},
    { 0, NULL }
};
/* Bit 5  NSCB: Noise Suppression Control Bit */
static const value_string NSCB_vals[] = {
    { 0, "Noise Suppression can be used (default)"},
    { 1, "Noise Suppression shall be turned off"},
    { 0, NULL }
};
/* Bit 4 ICMI: Initial Codec Mode Indicator */
static const value_string ICMI_vals[] = {
    { 0, "The initial codec mode is defined by the implicit rule provided in 3GPP TS 05.09"},
    { 1, "The initial codec mode is defined by the Start Mode field"},
    { 0, NULL }
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
    {  0, "0.0 dB"},
    {  1, "0.5 dB"},
    {  2, "1.0 dB"},
    {  3, "1.5 dB"},
    {  4, "2.0 dB"},
    {  5, "2.5 dB"},
    {  6, "3.0 dB"},
    {  7, "3.5 dB"},
    {  8, "4.0 dB"},
    {  9, "4.5 dB"},
    { 10, "5.0 dB"},
    { 11, "5.5 dB"},
    { 12, "6.0 dB"},
    { 13, "6.5 dB"},
    { 14, "7.0 dB"},
    { 15, "7.5 dB"},
    { 16, "8.0 dB"},
    { 17, "8.5 dB"},
    { 18, "9.0 dB"},
    { 19, "9.5 dB"},
    { 20, "10.0 dB"},
    { 21, "10.5 dB"},
    { 22, "11.0 dB"},
    { 23, "11.5 dB"},
    { 24, "12.0 dB"},
    { 25, "12.5 dB"},
    { 26, "13.0 dB"},
    { 27, "13.5 dB"},
    { 28, "14.0 dB"},
    { 29, "14.5 dB"},
    { 30, "15.0 dB"},
    { 31, "15.5 dB"},
    { 32, "16.0 dB"},
    { 33, "16.5 dB"},
    { 34, "17.0 dB"},
    { 35, "17.5 dB"},
    { 36, "18.0 dB"},
    { 37, "18.5 dB"},
    { 38, "19.0 dB"},
    { 39, "19.5 dB"},
    { 40, "20.0 dB"},
    { 41, "20.5 dB"},
    { 42, "21.0 dB"},
    { 43, "21.5 dB"},
    { 44, "22.0 dB"},
    { 45, "22.5 dB"},
    { 46, "23.0 dB"},
    { 47, "23.5 dB"},
    { 48, "24.0 dB"},
    { 49, "24.5 dB"},
    { 50, "25.0 dB"},
    { 51, "25.5 dB"},
    { 52, "26.0 dB"},
    { 53, "26.5 dB"},
    { 54, "27.0 dB"},
    { 55, "27.5 dB"},
    { 56, "28.0 dB"},
    { 57, "28.5 dB"},
    { 58, "29.0 dB"},
    { 59, "29.5 dB"},
    { 60, "30.0 dB"},
    { 61, "30.5 dB"},
    { 62, "31.0 dB"},
    { 63, "31.5 dB"},
    { 0, NULL }
};

static value_string_ext gsm_a_rr_amr_threshold_vals_ext = VALUE_STRING_EXT_INIT(gsm_a_rr_amr_threshold_vals);

static const value_string gsm_a_rr_amr_hysteresis_vals[] = {
    {  0, "0.0 dB"},
    {  1, "0.5 dB"},
    {  2, "1.0 dB"},
    {  3, "1.5 dB"},
    {  4, "2.0 dB"},
    {  5, "2.5 dB"},
    {  6, "3.0 dB"},
    {  7, "3.5 dB"},
    {  8, "4.0 dB"},
    {  9, "4.5 dB"},
    { 10, "5.0 dB"},
    { 11, "5.5 dB"},
    { 12, "6.0 dB"},
    { 13, "6.5 dB"},
    { 14, "7.0 dB"},
    { 15, "7.5 dB"},
    { 0, NULL }
};

guint16
de_rr_multirate_conf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    guint8  oct;
    gint    bit_offset, remaining_length, nb_of_params;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_multirate_speech_ver, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_rr_NCSB, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_rr_ICMI, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* The initial codec mode is coded as in 3GPP TS 45.009 */
    proto_tree_add_item(tree, hf_gsm_a_rr_start_mode, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    oct = ( tvb_get_guint8(tvb,curr_offset) &0xe0 ) >> 5;
    curr_offset++;
    switch ( oct){
    case 1:
        /* Adaptive Multirate speech version 1 */
        /* Set of AMR codec modes */
        proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b8, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b7, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b6, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v1_b1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;

        remaining_length = len-2;
        break;
    case 2:
        /* Adaptive Multirate speech version 2 */
        proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b5, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b4, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_rr_set_of_amr_codec_modes_v2_b1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
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
            proto_tree_add_bits_item(tree, hf_gsm_a_rr_amr_threshold, tvb, bit_offset, 6, ENC_BIG_ENDIAN);
            bit_offset += 6;
            proto_tree_add_bits_item(tree, hf_gsm_a_rr_amr_hysteresis, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
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
static guint16
de_rr_mult_all(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    guint32     curr_offset;
    guint8      oct;
    guint8      i;

    curr_offset = offset;

    item = proto_tree_add_text(tree,tvb, curr_offset, 1 ,"List of DA:");

    oct = tvb_get_guint8(tvb, curr_offset);
    curr_offset++;
    for( i=0;i<7;i++ )
    {
        if( (oct>>i) & 1 )
        {
            proto_item_append_text(item," DA%d",i+1);
        }
    }

    if( oct & 0x80 )  /* octet 3a present */
    {
        item = proto_tree_add_text(tree,tvb, curr_offset, 1 ,"List of UA:");
        oct = tvb_get_guint8(tvb, curr_offset);
        curr_offset++;
        for( i=0;i<7;i++ )
        {
            if( (oct>>i) & 1 )
            {
                proto_item_append_text(item," UA%d",i+1);
            }
        }
    }

    while ( curr_offset < offset + len )
    {
        proto_tree_add_item(tree, hf_gsm_a_rr_ma_channel_set, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
    }

    return(curr_offset - offset);

}
/*
 * [3] 10.5.2.21c NC mode
 */

 /*
 * [3] 10.5.2.22 Neighbour Cell Description
 */
static const value_string gsm_a_rr_ext_ind_vals[] = {
    { 0, "The information element carries the complete BA"},
    { 1, "The information element carries only a part of the BA"},
    { 0, NULL }
};
static guint16
de_rr_neigh_cell_desc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_ext_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_ba_ind, tvb, (curr_offset<<3)+3, 1, ENC_BIG_ENDIAN);

    return dissect_arfcn_list(tvb, tree, pinfo, offset, 16, add_string, string_len);
}

 /*
 * [3] 10.5.2.22a Neighbour Cell Description 2
 */
static guint16
de_rr_neigh_cell_desc2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_rr_multiband_reporting, tvb, (curr_offset<<3)+1, 2, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_ba_ind, tvb, (curr_offset<<3)+3, 1, ENC_BIG_ENDIAN);

    return dissect_arfcn_list2(tvb, tree, pinfo, offset, 16, add_string, string_len);
}

/*
 * [3] 10.5.2.22b (void)
 * [3] 10.5.2.22c NT/N Rest Octets
 */

/*
 * [3] 10.5.2.23 P1 Rest Octets
 */
static guint16
de_rr_p1_rest_oct(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_item *item2;
    guint32     curr_offset, value;
    gint        bit_offset, bit_offset_sav;
    guint8      tvb_len = tvb_length(tvb);
    guint16     bit_len = tvb_len << 3;

    curr_offset = offset;
    bit_offset = curr_offset << 3;

    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "NLN(PCH)", "Present", "Not present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_nln_pch, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset += 2;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_nln_status_pch, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Priority 1", "Present", "Not present"))
    {
        item2 = proto_tree_add_bits_item(subtree, hf_gsm_a_call_prio, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
        proto_item_append_text(item2, " for Mobile Identity 1");
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Priority 2", "Present", "Not present"))
    {
        item2 = proto_tree_add_bits_item(subtree, hf_gsm_a_call_prio, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
        proto_item_append_text(item2, " for Mobile Identity 2");
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Group Call Information", "Present", "Not present"))
    { /* Group Call Information */
        bit_offset_sav = bit_offset;
        bit_offset += 36;
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Group Channel Description", "Present", "Not Present"))
        { /* Group Channel Description */
            bit_offset += 24;
            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Hopping case", "Present", "Not Present"))
            { /* Hopping case */
                if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "????", "Present", "Not Present"))
                {
                    bit_offset += 64;
                }
                else
                {
                    value = tvb_get_bits8(tvb,bit_offset,8);
                    bit_offset += 8 + (value<<3);
                }
            }
        }
        proto_tree_add_text(subtree,tvb, bit_offset_sav>>3, (bit_offset-bit_offset_sav)>>3,"Group Call Information: Data(Not decoded)");
    }
    gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Packet Page Indication 1", "For GPRS", "For RR connection establishment");
    gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Packet Page Indication 2", "For GPRS", "For RR connection establishment");

    /* Truncation allowed (see 44.018 section 8.9) */

    gsm_rr_csn_padding_bits(subtree, tvb, bit_offset, tvb_len);
    return tvb_len - offset;
}

/*
 * [3] 10.5.2.24 P2 Rest Octets
 */
static guint16
de_rr_p2_rest_oct(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)

{
    proto_item *item2;
    guint32     curr_offset;
    gint        bit_offset;
    guint8      tvb_len = tvb_length(tvb);
    guint16     bit_len = tvb_len << 3;

    curr_offset = offset;
    bit_offset = curr_offset << 3;

    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Channel Needed 3", "Present", "Not present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_chnl_needed_ch3, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset += 2;
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len ,bit_offset++, "NLN (PCH)", "Present", "Not present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_nln_pch, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset += 2;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_nln_status_pch, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Priority 1", "Present", "Not present"))
    {
       item2 = proto_tree_add_bits_item(subtree, hf_gsm_a_call_prio, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
       bit_offset += 3;
       proto_item_append_text(item2, " for Mobile Identity 1");
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Priority 2", "Present", "Not present"))
    {
        item2 = proto_tree_add_bits_item(subtree, hf_gsm_a_call_prio, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
        proto_item_append_text(item2, " for Mobile Identity 2");
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Priority 3", "Present", "Not present"))
    {
        item2 = proto_tree_add_bits_item(subtree, hf_gsm_a_call_prio, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
        proto_item_append_text(item2, " for Mobile Identity 3");
    }
    gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Packet Paging Procedure 1", "For GPRS", "For RR connection establishment");
    gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Packet Paging Procedure 2", "For GPRS", "For RR connection establishment");
    gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Packet Paging Procedure 3", "For GPRS", "For RR connection establishment");


    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Additions in release 6", "Present", "Not present"))
    { /* Additions in release 6 */
        bit_offset += 1;
        proto_tree_add_text(subtree, tvb, bit_offset>>3, -1,"Additions in Release 6: Data(Not decoded)");
    }

    /* Truncation allowed (see 44.018 section 8.9 */
    gsm_rr_csn_padding_bits(subtree, tvb, bit_offset, tvb_len);
    return tvb_len - offset;
}

/*
 * [3] 10.5.2.25 P3 Rest Octets
 */
static guint16
de_rr_p3_rest_oct(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_item *item2;
    guint32     curr_offset;
    gint        bit_offset;
    guint8      tvb_len = tvb_length(tvb);
    guint16     bit_len = tvb_len << 3;

    curr_offset = offset;
    bit_offset = curr_offset << 3;

    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Channel Needed 3 & 4", "Present", "Not present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_chnl_needed_ch3, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset += 2;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_chnl_needed_ch4, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset += 2;
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "NLN (PCH)", "Present", "Not present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_nln_pch, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset += 2;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_nln_status_pch, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Priority 1", "Present", "Not present"))
    {
        item2 = proto_tree_add_bits_item(subtree, hf_gsm_a_call_prio, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
        proto_item_append_text(item2, " for Mobile Identity 1");
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Priority 2", "Present", "Not present"))
    {
        item2 = proto_tree_add_bits_item(subtree, hf_gsm_a_call_prio, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
        proto_item_append_text(item2, " for Mobile Identity 2");
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Priority 3", "Present", "Not present"))
    {
        item2 = proto_tree_add_bits_item(subtree, hf_gsm_a_call_prio, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
        proto_item_append_text(item2, " for Mobile Identity 3");
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Priority 4", "Present", "Not present"))
    {
        item2 = proto_tree_add_bits_item(subtree, hf_gsm_a_call_prio, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
        proto_item_append_text(item2, " for Mobile Identity 4");
    }

    /* Truncation allowed (see 44.018 section 8.9 */
    gsm_rr_csn_padding_bits(subtree, tvb, bit_offset, tvb_len);
    return tvb_len - offset;
}

/*
 * [3] 10.5.2.25a Packet Channel Description C V 3
 */
static guint16
de_rr_packet_ch_desc(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32      curr_offset;
    guint8       oct8;
    guint16      arfcn, hsn, maio;
    const gchar *str;

    curr_offset = offset;

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
    { 0, "This message assigns a dedicated mode resource"},
    { 1, "This message assigns an uplink TBF or is the second message of two in a two-message assignment of an uplink or downlink TBF"},
    { 2, "Not used"},
    { 3, "This message assigns a downlink TBF to the mobile station identified in the IA Rest Octets IE"},
    { 4, "Not used"},
    { 5, "This message is the first message of two in a two-message assignment of an uplink TBF"},
    { 6, "Not used"},
    { 7, "This message is the first message of two in a two-message assignment of a downlink TBF to the mobile station identified in the IA Rest Octets IE"},
    { 0, NULL }
};
static guint16
de_rr_ded_mod_or_tbf(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(subtree, hf_gsm_a_rr_dedicated_mode_or_tbf, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset += 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.25c RR Packet Uplink Assignment
 */
static guint16
de_rr_pkt_ul_ass(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_text(subtree, tvb, curr_offset, len, "Not dissected yet");

    return len;
}

/*
 * [3] 10.5.2.25d RR Packet Downlink Assignment
 */
static guint16
de_rr_pkt_dl_ass(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_text(subtree, tvb, curr_offset, len, "Not dissected yet");

    return len;
}

/*
 * [3] 10.5.2.25e RR Packet Downlink Assignment Type 2
 */
static guint16
de_rr_pkt_dl_ass_type2(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_text(subtree, tvb, curr_offset, len, "Not dissected yet");

    return len;
}

/*
 * [3] 10.5.2.26 Page Mode
 */

static const value_string gsm_a_rr_page_mode_vals[] = {
    { 0, "Normal paging"},
    { 1, "Extended paging"},
    { 2, "Paging reorganization"},
    { 3, "Same as before"},
    { 0, NULL }
};
static guint16
de_rr_page_mode(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(subtree, hf_gsm_a_rr_page_mode, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset += 1;

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
static guint16
de_rr_ncc_perm(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(subtree, hf_gsm_a_rr_ncc_permitted, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.28 Power Command
 *
 *
 * ATC (Access Type Control) (octet 2)Bit 8
 * 0    Sending of Handover access is mandatory
 * 1    Sending of Handover access is optional
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
 *              on the channel mode     of the assigned channel (s) and the value
 *              of the EPC mode field.
 * If the channel mode is such that fast power control (FPC) may be
 *              used, the FPC_EPC field indicates whether Fast Measurement
 *              Reporting and Power Control mechanism is used.
 *              It is coded as follows:
 * Value 0      FPC not in use
 *       1      FPC in use
 * If the channel mode is such that EPC may be used and the EPC mode
 *              field indicates that the channel is in EPC mode, the FPC_EPC
 *              field indicates whether EPC shall be used for uplink power control.
 * It is coded as follows:
 * Value 0      EPC not in use for uplink power control
 *       1      EPC in use for uplink power control
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

static guint16
de_rr_pow_cmd(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(subtree, hf_gsm_a_b8spare, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /*EPC mode */
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_epc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /*FPC_EPC*/
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_fpcepc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /*POWER LEVEL*/
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_powlev, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.28a Power Command and access type
 */
static guint16
de_rr_pow_cmd_and_acc_type(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    /*ATC */
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_atc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /*EPC mode */
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_epc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /*FPC_EPC*/
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_fpcepc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /*POWER LEVEL*/
    proto_tree_add_item(subtree, hf_gsm_a_rr_pow_cmd_powlev, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.29 RACH Control Parameters
 */

static const value_string gsm_a_rr_max_retrans_vals[] = {
    {  0, "Maximum 1 retransmission"},
    {  1, "Maximum 2 retransmissions"},
    {  2, "Maximum 4 retransmissions"},
    {  3, "Maximum 7 retransmissions"},
    {  0, NULL }
};

static const value_string gsm_a_rr_tx_integer_vals[] = {
    {  0, "3 slots used to spread transmission"},
    {  1, "4 slots used to spread transmission"},
    {  2, "5 slots used to spread transmission"},
    {  3, "6 slots used to spread transmission"},
    {  4, "7 slots used to spread transmission"},
    {  5, "8 slots used to spread transmission"},
    {  6, "9 slots used to spread transmission"},
    {  7, "10 slots used to spread transmission"},
    {  8, "11 slots used to spread transmission"},
    {  9, "12 slots used to spread transmission"},
    { 10, "14 slots used to spread transmission"},
    { 11, "16 slots used to spread transmission"},
    { 12, "20 slots used to spread transmission"},
    { 13, "25 slots used to spread transmission"},
    { 14, "32 slots used to spread transmission"},
    { 15, "50 slots used to spread transmission"},
    {  0, NULL }
};
static const value_string gsm_a_rr_cell_barr_access_vals[] = {
    {  0, "The cell is not barred"},
    {  1, "The cell is barred"},
    {  0, NULL }
};
static const value_string gsm_a_rr_re_vals[] = {
    {  0, "Call Reestablishment allowed in the cell"},
    {  1, "Call Reestablishment not allowed in the cell"},
    {  0, NULL }
};

static guint16
de_rr_rach_ctrl_param(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(subtree, hf_gsm_a_rr_max_retrans, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_rr_tx_integer, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_rr_cell_barr_access, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_rr_re, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset = curr_offset + 1;

    proto_tree_add_item(subtree, hf_gsm_a_rr_acc, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 2;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.30 Request Reference M V 3
 */
static guint16 reduced_frame_number(guint16 fn)
{
    /* great care needed with signed/unsigned - -1 in unsigned is 0xffff, which mod(26) is not what you think !!! */
    gint16  t2, t3, t;
    guint16 frame, t1;

    t1 = (fn >> 11) & 0x1f;
    t2 = (fn >> 0) & 0x1f;
    t3 = (fn >> 5) & 0x3f;

    t = (t3-t2)%26;
    if (t<0)
        t += 26;

    frame = 51*(unsigned)t+(unsigned)t3+51*26*t1;

    return frame;
}

static guint16
de_rr_req_ref(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    guint32     curr_offset;
    guint16     rfn;
    guint16     fn;

    curr_offset = offset;

    proto_tree_add_item(subtree, hf_gsm_a_rr_ra, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;
    fn = tvb_get_ntohs(tvb,curr_offset);
    rfn = reduced_frame_number(fn);
    proto_tree_add_item(subtree, hf_gsm_a_rr_T1prim, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_a_rr_T3, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    curr_offset++;
    proto_tree_add_item(subtree, hf_gsm_a_rr_T2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;
    item = proto_tree_add_uint(subtree, hf_gsm_a_rr_rfn, tvb, curr_offset-2, 2, rfn);
    PROTO_ITEM_SET_GENERATED(item);

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.31
 */
guint16
de_rr_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_RR_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.32 SI 1 Rest Octets
 */
static const value_string gsm_a_rr_nch_position_vals[] = {
    { 0, "No of blocks = 1 and Number of first block = 0"},
    { 1, "No of blocks = 1 and Number of first block = 1"},
    { 2, "No of blocks = 1 and Number of first block = 2"},
    { 3, "No of blocks = 1 and Number of first block = 3"},
    { 4, "No of blocks = 1 and Number of first block = 4"},
    { 5, "No of blocks = 1 and Number of first block = 5"},
    { 6, "No of blocks = 1 and Number of first block = 6"},
    { 7, "No of blocks = 1 and Number of first block = 0"},
    { 8, "No of blocks = 2 and Number of first block = 1"},
    { 9, "No of blocks = 2 and Number of first block = 2"},
    {10, "No of blocks = 2 and Number of first block = 3"},
    {11, "No of blocks = 2 and Number of first block = 4"},
    {12, "No of blocks = 2 and Number of first block = 5"},
    {13, "No of blocks = 3 and Number of first block = 0"},
    {14, "No of blocks = 3 and Number of first block = 1"},
    {15, "No of blocks = 3 and Number of first block = 2"},
    {16, "No of blocks = 3 and Number of first block = 3"},
    {17, "No of blocks = 3 and Number of first block = 4"},
    {18, "No of blocks = 4 and Number of first block = 0"},
    {19, "No of blocks = 4 and Number of first block = 1"},
    {20, "No of blocks = 4 and Number of first block = 2"},
    {21, "No of blocks = 4 and Number of first block = 3"},
    {22, "No of blocks = 5 and Number of first block = 0"},
    {23, "No of blocks = 5 and Number of first block = 1"},
    {24, "No of blocks = 5 and Number of first block = 2"},
    {25, "No of blocks = 6 and Number of first block = 0"},
    {26, "No of blocks = 6 and Number of first block = 1"},
    {27, "No of blocks = 7 and Number of first block = 0"},
    {28, "Reserved"},
    {29, "Reserved"},
    {30, "Reserved"},
    {31, "Reserved"},
    { 0, NULL }
};

static guint16
de_rr_si1_rest_oct(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    gint    bit_offset;
    guint8  tvb_len = tvb_length(tvb);

    curr_offset = offset;
    bit_offset = curr_offset << 3;

    if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "NCH position", "Present", "Not present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_nch_position, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
        bit_offset += 5;
    }
    gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Band Indicator", "1900", "1800");

    gsm_rr_csn_padding_bits(subtree, tvb, bit_offset, tvb_len);
    return tvb_len - offset;
}

/*
 * [3] 10.5.2.33 SI 2bis Rest Octets
 */

/*
 * [3] 10.5.2.33a SI 2ter Rest Octets
 */
static const value_string gsm_a_rr_qsearch_x_vals[] = {
    { 0, "-98 dBm"},
    { 1, "-94 dBm"},
    { 2, "-90 dBm"},
    { 3, "-86 dBm"},
    { 4, "-82 dBm"},
    { 5, "-78 dBm"},
    { 6, "-74 dBm"},
    { 7, "Always"},
    { 8, "-78 dBm"},
    { 9, "-74 dBm"},
    {10, "-70 dBm"},
    {11, "-66 dBm"},
    {12, "-62 dBm"},
    {13, "-58 dBm"},
    {14, "-54 dBm"},
    {15, "Never"},
    { 0, NULL }
};

static const value_string gsm_a_rr_xdd_qoffset_vals[] = {
    { 0, "always select a cell if acceptable"},
    { 1, "-28 dB"},
    { 2, "-24 dB"},
    { 3, "-20 dB"},
    { 4, "-16 dB"},
    { 5, "-12 dB"},
    { 6, "-8 dB"},
    { 7, "-4 dB"},
    { 8, "0 dB"},
    { 9, "4 dB"},
    {10, "8 dB"},
    {11, "12 dB"},
    {12, "16 dB"},
    {13, "20 dB"},
    {14, "24 dB"},
    {15, "28 dB"},
    { 0, NULL }
};

static const value_string gsm_a_rr_fdd_qmin_vals[] = {
    { 0, "-20 dB"},
    { 1, "-6 dB"},
    { 2, "-18 dB"},
    { 3, "-8 dB"},
    { 4, "-16 dB"},
    { 5, "-10 dB"},
    { 6, "-14 dB"},
    { 7, "-12 dB"},
    { 0, NULL }
};

static const value_string gsm_a_rr_fdd_qmin_offset_vals[] = {
    { 0, "0 dB"},
    { 1, "2 dB"},
    { 2, "4 dB"},
    { 3, "6 dB"},
    { 4, "8 dB"},
    { 5, "10 dB"},
    { 6, "12 dB"},
    { 7, "14 dB"},
    { 0, NULL }
};

static const value_string gsm_a_rr_fdd_rscpmin_vals[] = {
    { 0, "-114 dBm"},
    { 1, "-112 dBm"},
    { 2, "-110 dBm"},
    { 3, "-108 dBm"},
    { 4, "-106 dBm"},
    { 5, "-104 dBm"},
    { 6, "-102 dBm"},
    { 7, "-100 dBm"},
    { 8, "-98 dBm"},
    { 9, "-96 dBm"},
    {10, "-94 dBm"},
    {11, "-92 dBm"},
    {12, "-90 dBm"},
    {13, "-88 dBm"},
    {14, "-86 dBm"},
    {15, "-84 dBm"},
    { 0, NULL }
};

static guint16
de_rr_si2ter_rest_oct(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree *subtree2;
    proto_item *item2;
    guint32     curr_offset;
    gint        bit_offset, bit_offset_sav;
    guint8      tvb_len = tvb_length(tvb);
    guint16     bit_len = tvb_len << 3;

    curr_offset = offset;
    bit_offset = curr_offset<<3;

    if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "MP Changemark", "Present", "Not present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si2ter_mp_change_mark, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si2ter_3g_change_mark, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si2ter_index, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si2ter_count, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "UTRAN FDD Description", "Present", "Not Present"))
        { /* UTRAN FDD Description */
            bit_offset_sav = bit_offset;
            item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_FDD_DESC].strptr);
            subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_UTRAN_FDD_DESC]);
            gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "Bit reserved for earlier version of protocol", "Earlier version", "Current version");
            gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "Bit reserved for earlier version of protocol", "Current version", "Earlier version");
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_uarfcn, tvb, bit_offset, 14, ENC_BIG_ENDIAN);
            bit_offset += 14;
            if (gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "Bandwidth FDD", "Present", "Not Present"))
            {
                proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_bandwidth_fdd, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                bit_offset += 3;
            }
            proto_item_set_len(item2,(bit_offset>>3) - (bit_offset_sav>>3)+1);
        }
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "UTRAN TDD Description", "Present", "Not Present"))
        { /* UTRAN TDD Description */
            bit_offset_sav = bit_offset;
            item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_TDD_DESC].strptr);
            subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_UTRAN_TDD_DESC]);
            gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "Bit reserved for earlier version of protocol", "Earlier version", "Current version");
            gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "Bit reserved for earlier version of protocol", "Current version", "Earlier version");
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_uarfcn, tvb, bit_offset, 14, ENC_BIG_ENDIAN);
            bit_offset += 14;
            if (gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "Bandwidth TDD", "Present", "Not Present"))
            {
                proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_bandwidth_tdd, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                bit_offset += 3;
            }
            proto_item_set_len(item2,(bit_offset>>3) - (bit_offset_sav>>3)+1);
        }
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "3G Measurement Parameters Description", "Present", "Not Present"))
        { /* 3G Measurement Parameters Description */
            bit_offset_sav = bit_offset;
            item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_MEAS_PARAM_DESC].strptr);
            subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_MEAS_PARAM_DESC]);
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_qsearch_i, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
            bit_offset += 4;
            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "FDD Parameters", "Present", "Not Present"))
            {
                proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_qoffset, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
                bit_offset += 4;
                proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_qmin, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                bit_offset += 3;
            }
            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "TDD Parameters", "Present", "Not Present"))
            {
                proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_qoffset, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
                bit_offset += 4;
            }
            proto_item_set_len(item2,(bit_offset>>3) - (bit_offset_sav>>3)+1);
        }
        /* Null breakpoint */
        if (bit_len - bit_offset > 0)
        {
            /* There is still room left in the Rest Octets IE */
            if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Additions in Rel-5", "Present", "Not present"))
            { /* Additions in release R5 */
                if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "3G Additional Measurement Parameters Description", "Present", "Not Present"))
                { /* 3G Additional Measurement Parameters Description */
                    bit_offset_sav = bit_offset;
                    item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC].strptr);
                    subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC]);
                    proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_qmin_offset, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                    bit_offset += 3;
                    proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_rscpmin, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
                    bit_offset += 4;
                    proto_item_set_len(item2,(bit_offset>>3) - (bit_offset_sav>>3)+1);
                }
            }
        }
    }
    gsm_rr_csn_padding_bits(subtree, tvb, bit_offset, tvb_len);
    return tvb_len - offset;
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
    "Report on cells with invalid BSIC and allowed NCC part of BSIC is allowed",
    "Report on cells with invalid BSIC and allowed NCC part of BSIC is not allowed"
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

/* The TS 45.008 is not that clear, but it should be understood: threshold = minimum reported value + 6 * resolution
 * The minimum reported value, resolution is, for the different access technologies:
 *  GSM:        -111 dBm, 1 dBm
 *  WCDMA/RSCP: -116 dBm, 1 dBm
 *  WCDMA/EcN0: -24.5 dB, 0.5 dB
 *  LTE/RSRP:   -140 dBm, 1 dB
 *  LTE/RSRQ:   -19.5 dB, 0.5 dB
 */
static const value_string gsm_a_rr_gsm_reporting_threshold_vals[] = {
    { 0, "Apply priority reporting if the reported value is above -111 dBm"},
    { 1, "Apply priority reporting if the reported value is above -105 dBm"},
    { 2, "Apply priority reporting if the reported value is above -99 dBm"},
    { 3, "Apply priority reporting if the reported value is above -93 dBm"},
    { 4, "Apply priority reporting if the reported value is above -87 dBm"},
    { 5, "Apply priority reporting if the reported value is above -81 dBm"},
    { 6, "Apply priority reporting if the reported value is above -75 dBm"},
    { 7, "Never apply priority reporting"},
    { 0, NULL }
};

static const value_string gsm_a_rr_wcdma_rscp_reporting_threshold_vals[] = {
    { 0, "Apply priority reporting if the reported value is above -116 dBm"},
    { 1, "Apply priority reporting if the reported value is above -110 dBm"},
    { 2, "Apply priority reporting if the reported value is above -104 dBm"},
    { 3, "Apply priority reporting if the reported value is above -98 dBm"},
    { 4, "Apply priority reporting if the reported value is above -92 dBm"},
    { 5, "Apply priority reporting if the reported value is above -86 dBm"},
    { 6, "Apply priority reporting if the reported value is above -80 dBm"},
    { 7, "Never apply priority reporting"},
    { 0, NULL }
};

static const value_string gsm_a_rr_wcdma_ecn0_reporting_threshold_vals[] = {
    { 0, "Apply priority reporting if the reported value is above -24.5 dB"},
    { 1, "Apply priority reporting if the reported value is above -21.5 dB"},
    { 2, "Apply priority reporting if the reported value is above -17.5 dB"},
    { 3, "Apply priority reporting if the reported value is above -14.5 dB"},
    { 4, "Apply priority reporting if the reported value is above -11.5 dB"},
    { 5, "Apply priority reporting if the reported value is above -8.5 dB"},
    { 6, "Apply priority reporting if the reported value is above -5.5 dB"},
    { 7, "Never apply priority reporting"},
    { 0, NULL }
};

static const value_string gsm_a_rr_lte_rsrp_reporting_threshold_vals[] = {
    { 0, "Apply priority reporting if the reported value is above -140 dBm"},
    { 1, "Apply priority reporting if the reported value is above -134 dBm"},
    { 2, "Apply priority reporting if the reported value is above -128 dBm"},
    { 3, "Apply priority reporting if the reported value is above -122 dBm"},
    { 4, "Apply priority reporting if the reported value is above -116 dBm"},
    { 5, "Apply priority reporting if the reported value is above -110 dBm"},
    { 6, "Apply priority reporting if the reported value is above -104 dBm"},
    { 7, "Never apply priority reporting"},
    { 0, NULL }
};

static const value_string gsm_a_rr_lte_rsrq_reporting_threshold_vals[] = {
    { 0, "Apply priority reporting if the reported value is above -19.5 dB"},
    { 1, "Apply priority reporting if the reported value is above -16.5 dB"},
    { 2, "Apply priority reporting if the reported value is above -13.5 dB"},
    { 3, "Apply priority reporting if the reported value is above -10.5 dB"},
    { 4, "Apply priority reporting if the reported value is above -7.5 dB"},
    { 5, "Apply priority reporting if the reported value is above -4.5 dB"},
    { 6, "Apply priority reporting if the reported value is above -1.5 dB"},
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

static gint
de_rr_si2quater_meas_info_utran_fdd_desc(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree, *subtree2;
    proto_item *item, *item2;
    gint        curr_bit_offset, idx;
    gint        xdd_cell_info, wsize, nwi, jwi, w[64], i, iused, xdd_indic0;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_FDD_DESC].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_UTRAN_FDD_DESC]);
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Bandwidth FDD", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bandwidth_fdd, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
    }
    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated UMTS FDD Neighbour Cells", "Present", "Not Present"))
    {
        gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Bit reserved for earlier version of protocol", "Earlier version", "Current version");
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_fdd_uarfcn, tvb, curr_bit_offset, 14, ENC_BIG_ENDIAN);
        curr_bit_offset += 14;
        xdd_indic0 = gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "the FDD_CELL_INFORMATION parameter value '0000000000' ", "is a member of the set", "is not a member of the set");
        idx = tvb_get_bits8(tvb,curr_bit_offset,5);
        proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 1, "Nr of FDD Cells : %d", idx);
        curr_bit_offset += 5;
        idx = convert_n_to_p[idx];
        item2 = proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, (idx>>3)+1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_FDD_DESC].strptr);
        subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_FDD_CELL_INFORMATION_FIELD]);
        proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, (idx>>3)+1, "Field is %d bits long", idx);
        if (xdd_indic0)
        {
            proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, 0, "Scrambling Code: %d", 0);
            proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, 0, "Diversity: %d", 0);
        }
        if (idx)
        {
            wsize = 10;
            nwi = 1;
            jwi = 0;
            i = 1;

            while (idx > 0)
            {
                w[i] = tvb_get_bits(tvb, curr_bit_offset, wsize, ENC_BIG_ENDIAN);
                curr_bit_offset += wsize;
                idx -= wsize;
                if (w[i] == 0)
                {
                    idx = 0;
                    break;
                }
                if (++jwi == nwi)
                {
                    jwi = 0;
                    nwi <<= 1;
                    wsize--;
                }
                i++;
            }
            if (idx < 0)
            {
                curr_bit_offset += idx;
            }
            iused = i-1;

            for (i=1; i <= iused; i++)
            {
                xdd_cell_info = f_k(i, w, 1024);
                proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, 0, "Scrambling Code: %d", xdd_cell_info & 0x01FF);
                proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, 0, "Diversity: %d", (xdd_cell_info >> 9) & 0x01);
            }
        }
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return (curr_bit_offset - bit_offset);
}

static gint
de_rr_si2quater_meas_info_utran_tdd_desc(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree, *subtree2;
    proto_item *item, *item2;
    gint        curr_bit_offset, idx;
    gint        xdd_cell_info, wsize, nwi, jwi, w[64], i, iused, xdd_indic0;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_TDD_DESC].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_UTRAN_TDD_DESC]);
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Bandwidth TDD", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bandwidth_tdd, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
    }
    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated UMTS TDD Neighbour Cells", "Present", "Not Present"))
    {
        gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Bit reserved for earlier version of protocol", "Earlier version", "Current version");
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_tdd_uarfcn, tvb, curr_bit_offset, 14, ENC_BIG_ENDIAN);
        curr_bit_offset += 14;
        xdd_indic0 = gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "the FDD_CELL_INFORMATION parameter value '0000000000' ", "is a member of the set", "is not a member of the set");
        idx = tvb_get_bits8(tvb,curr_bit_offset,5);
        proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 1, "Nr of TDD Cells : %d", idx);
        curr_bit_offset += 5;
        idx = convert_n_to_q[idx];
        item2 = proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, (idx>>3)+1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_TDD_DESC].strptr);
        subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_TDD_CELL_INFORMATION_FIELD]);
        proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, (idx>>3)+1, "Field is %d bits long", idx);
        if (xdd_indic0)
        {
            proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, 0, "Cell Parameter: %d", 0);
            proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, 0, "Sync Case TSTD: %d", 0);
            proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, 0, "Diversity TDD: %d", 0);
        }
        if (idx)
        {
            wsize = 9;
            nwi = 1;
            jwi = 0;
            i = 1;

            while (idx > 0)
            {
                w[i] = tvb_get_bits(tvb, curr_bit_offset, wsize, ENC_BIG_ENDIAN);
                curr_bit_offset += wsize;
                idx -= wsize;
                if (w[i] == 0)
                {
                    idx = 0;
                    break;
                }
                if (++jwi == nwi)
                {
                    jwi = 0;
                    nwi <<= 1;
                    wsize--;
                }
                i++;
            }
            if (idx < 0)
            {
                curr_bit_offset += idx;
            }
            iused = i-1;

            for (i=1; i <= iused; i++)
            {
                xdd_cell_info = f_k(i, w, 512);
                proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, 0, "Cell Parameter: %d", xdd_cell_info & 0x07F);
                proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, 0, "Sync Case TSTD: %d", (xdd_cell_info >> 7) & 0x01);
                proto_tree_add_text(subtree2,tvb, curr_bit_offset>>3, 0, "Diversity TDD: %d", (xdd_cell_info >> 8) & 0x01);
            }
        }
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return (curr_bit_offset - bit_offset);
}

static gint
de_rr_rtd_desc(tvbuff_t *tvb, proto_tree *tree, gint bit_offset, rr_rest_octets_elem_idx_t id)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset, idx;
    guint8      value;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[id].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[id]);
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "RTD6", "Present", "Not Present"))
    {
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "BA Index Start RTD", "Present", "Not Present"))
        {
            idx = tvb_get_bits8(tvb,curr_bit_offset,5);
            proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 1, "BA Index Start RTD: %d", idx);
            curr_bit_offset += 5;
        }
        else
            idx = 0;

        value = gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "RTD", "Not Present", "Present");
        while (value == 0)
        { /* all the RTDs on the first frequency */
            proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 1, "RTD index %d: %d TDMA frame(s) modulo 51 TDMA frames", idx, tvb_get_bits8(tvb,curr_bit_offset,6));
            curr_bit_offset += 6;
            value = gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "additional RTD", "Not Present", "Present");
        }

        value = gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "additional RTD struct", "Not Present", "Present");
        while(value == 0)
        { /* all other frequencies */
            idx += 1;
            value = gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "RTD", "Not Present", "Present");
            while (value == 0)
            { /* all the RTDs on the first frequency */
                proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 1, "RTD index %d: %d TDMA frame(s) modulo 51 TDMA frames", idx, tvb_get_bits8(tvb,curr_bit_offset,6));
                curr_bit_offset += 6;
                value = gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "additional RTD", "Not Present", "Present");
            }
            value = gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "additional RTD struct", "Not Present", "Present");
        }
    }
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "RTD12", "Present", "Not Present"))
    {
       if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "RTD12", "Present", "Not Present"))
       {
           if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "BA Index Start RTD", "Present", "Not Present"))
           {
               idx = tvb_get_bits8(tvb,curr_bit_offset,5);
               proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 1, "BA Index Start RTD: %d", idx);
               curr_bit_offset += 5;
           }
           else
               idx = 0;

           while (0 == gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated RTD", "Not Present", "Present"))
           { /* all the RTDs on the first frequency */
               proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 2, "RTD index %d: %d/64 TDMA frame(s) modulo 51 TDMA frames", idx, tvb_get_bits16(tvb,curr_bit_offset,12,ENC_BIG_ENDIAN));
               curr_bit_offset += 12;
           }

           while(0 == gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated RTD Frequency", "Not Present", "Present"))
           { /* all other frequencies */
               idx += 1;
               while (0 == gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated RTD", "Not Present", "Present"))
               { /* all the RTDs on the first frequency */
                   proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 2, "RTD index %d: %d/64 TDMA frame(s) modulo 51 TDMA frames", idx, tvb_get_bits16(tvb,curr_bit_offset,12,ENC_BIG_ENDIAN));
                   curr_bit_offset += 12;
               }
           }
       }
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return (curr_bit_offset - bit_offset);
}

static gint
de_rr_bsic_desc(tvbuff_t *tvb, proto_tree *tree, gint bit_offset, rr_rest_octets_elem_idx_t id)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset, idx;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[id].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[id]);
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "BA Index Start BSIC", "Present", "Not Present"))
    {
        proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 1, "BA Index Start BSIC: %d", tvb_get_bits8(tvb,curr_bit_offset,5));
        curr_bit_offset += 5;
    }
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bsic, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
    curr_bit_offset += 6;
    idx = tvb_get_bits8(tvb,curr_bit_offset,7);
    proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 1, "Number Remaining BSIC: %d", idx);
    curr_bit_offset += 7;
    while (idx)
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_frequency_scrolling, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bsic, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
        curr_bit_offset += 6;
        idx -= 1;
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_report_priority_desc(tvbuff_t *tvb, proto_tree *tree, gint bit_offset, rr_rest_octets_elem_idx_t id)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset, idx;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[id].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[id]);
    idx = tvb_get_bits8(tvb,curr_bit_offset,7);
    proto_tree_add_text(subtree,tvb, curr_bit_offset>>3, 1, "Number Cells: %d", idx);
    curr_bit_offset += 7;
    while (idx)
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rep_priority, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        idx -= 1;
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_meas_param_desc(tvbuff_t *tvb, proto_tree *tree, gint bit_offset, rr_rest_octets_elem_idx_t id)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[id].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[id]);
    if (id == DE_RR_REST_OCTETS_GPRS_MEAS_PARAM_DESC)
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_report_type, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_reporting_rate, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset +=1;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_invalid_bsic_reporting, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset +=1;
    }
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Multiband Reporting", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_multiband_reporting, tvb, curr_bit_offset, 2, ENC_BIG_ENDIAN);
        curr_bit_offset += 2;
    }
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Serving Reporting", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_serving_band_reporting, tvb, curr_bit_offset, 2, ENC_BIG_ENDIAN);
        curr_bit_offset += 2;
    }
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_scale_ord, tvb, curr_bit_offset, 2, ENC_BIG_ENDIAN);
    curr_bit_offset += 2;
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "900 Reporting", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_900_reporting_offset, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_900_reporting_threshold, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
    }
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "1800 Reporting", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_1800_reporting_offset, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_1800_reporting_threshold, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
    }
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "400 Reporting", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_400_reporting_offset, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_400_reporting_threshold, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
    }
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "1900 Reporting", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_1900_reporting_offset, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_1900_reporting_threshold, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
    }
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "850 Reporting", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_850_reporting_offset, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_850_reporting_threshold, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_3g_add_meas_param_desc2(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC2].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC2]);
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "FDD Reporting Threshold2", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_fdd_reporting_threshold_2, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
        curr_bit_offset += 6;
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

/* Additions in Rel-8 */
static const true_false_string priority_utran_start = {
    "This is the first instance of the message",
    "This is not the first instance of the message"
};

static const true_false_string priority_utran_stop = {
    "This is the last instance of the message",
    "This is not the last instance of the message"
};

static const true_false_string eutran_ccn_active = {
    "CCN towards E-UTRAN cells is enabled in the cell",
    "The broadcast E-UTRAN_CCN_ACTIVE parameter shall apply if applicable. Otherwise, CCN towards E-UTRAN cells is disabled in the cell"
};

static const true_false_string eutran_rep_quant = {
    "RSRQ",
    "RSRP"
};

static const value_string gsm_a_rr_pcid_psc_pattern_length[] = {
    { 0, "1"},
    { 1, "2"},
    { 2, "3"},
    { 3, "4"},
    { 4, "5"},
    { 5, "6"},
    { 6, "7"},
    { 7, "8"},
    { 0, NULL }
};

static const value_string gsm_a_rr_eutran_measurement_bandwidth[] = {
    { 0, "NRB = 6"},
    { 1, "NRB = 15"},
    { 2, "NRB = 25"},
    { 3, "NRB = 50"},
    { 4, "NRB = 75"},
    { 5, "NRB = 100"},
    { 6, "Reserved for future use"},
    { 7, "Reserved for future use"},
    { 0, NULL }
};

static const value_string gsm_a_rr_serving_cell_thresh_gsm_low[] = {
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
    {15, "Always allowed"},
    { 0, NULL }
};

static const value_string gsm_a_rr_serving_cell_thresh_priority_search[] = {
    { 0, "-98 dBm"},
    { 1, "-95 dBm"},
    { 2, "-92 dBm"},
    { 3, "-89 dBm"},
    { 4, "-86 dBm"},
    { 5, "-83 dBm"},
    { 6, "-80 dBm"},
    { 7, "-77 dBm"},
    { 8, "-74 dBm"},
    { 9, "-71 dBm"},
    {10, "-68 dBm"},
    {11, "-65 dBm"},
    {12, "-62 dBm"},
    {13, "-59 dBm"},
    {14, "-56 dBm"},
    {15, "Always search"},
    { 0, NULL }
};

static const value_string gsm_a_rr_utran_qrxlevmin[] = {
    { 0, "-119 dBm"},
    { 1, "-117 dBm"},
    { 2, "-115 dBm"},
    { 3, "-113 dBm"},
    { 4, "-111 dBm"},
    { 5, "-109 dBm"},
    { 6, "-107 dBm"},
    { 7, "-105 dBm"},
    { 8, "-103 dBm"},
    { 9, "-101 dBm"},
    {10, "-99 dBm"},
    {11, "-97 dBm"},
    {12, "-95 dBm"},
    {13, "-93 dBm"},
    {14, "-91 dBm"},
    {15, "-89 dBm"},
    {16, "-87 dBm"},
    {17, "-85 dBm"},
    {18, "-83 dBm"},
    {19, "-81 dBm"},
    {20, "-79 dBm"},
    {21, "-77 dBm"},
    {22, "-75 dBm"},
    {23, "-73 dBm"},
    {24, "-71 dBm"},
    {25, "-69 dBm"},
    {26, "-67 dBm"},
    {27, "-65 dBm"},
    {28, "-63 dBm"},
    {29, "-61 dBm"},
    {30, "-59 dBm"},
    {31, "-57 dBm"},
    { 0, NULL }
};

static const value_string gsm_a_rr_thresh_utran_eutran_high_low[] = {
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
    { 0, NULL }
};

static const value_string gsm_a_rr_eutran_qrxlevmin[] = {
    { 0, "-140 dBm"},
    { 1, "-138 dBm"},
    { 2, "-136 dBm"},
    { 3, "-134 dBm"},
    { 4, "-132 dBm"},
    { 5, "-130 dBm"},
    { 6, "-128 dBm"},
    { 7, "-126 dBm"},
    { 8, "-124 dBm"},
    { 9, "-122 dBm"},
    {10, "-120 dBm"},
    {11, "-118 dBm"},
    {12, "-116 dBm"},
    {13, "-114 dBm"},
    {14, "-112 dBm"},
    {15, "-110 dBm"},
    {16, "-108 dBm"},
    {17, "-106 dBm"},
    {18, "-104 dBm"},
    {19, "-102 dBm"},
    {20, "-100 dBm"},
    {21, "-98 dBm"},
    {22, "-96 dBm"},
    {23, "-94 dBm"},
    {24, "-92 dBm"},
    {25, "-90 dBm"},
    {26, "-88 dBm"},
    {27, "-86 dBm"},
    {28, "-84 dBm"},
    {29, "-82 dBm"},
    {30, "-80 dBm"},
    {31, "-78 dBm"},
    { 0, NULL }
};

static const value_string gsm_a_rr_serving_cell_priority_param_h_prio[] = {
    { 0, "disabled"},
    { 1, "5 dB"},
    { 2, "4 dB"},
    { 3, "3 dB"},
    { 0, NULL }
};

static const value_string gsm_a_rr_serving_cell_priority_param_t_reselection[] = {
    { 0, "5 s"},
    { 1, "10 s"},
    { 2, "15 s"},
    { 3, "20 s"},
    { 0, NULL }
};

static const value_string gsm_a_rr_qsearch_c_eutran_initial[] = {
    { 0, "search if signal is below -98 dBm"},
    { 1, "search if signal is below -94 dBm"},
    { 2, "search if signal is below -90 dBm"},
    { 3, "search if signal is below -86 dBm"},
    { 4, "search if signal is below -82 dBm"},
    { 5, "search if signal is below -78 dBm"},
    { 6, "search if signal is below -74 dBm"},
    { 7, "always search"},
    { 8, "search is signal is above -78 dBm"},
    { 9, "search is signal is above -74 dBm"},
    {10, "search is signal is above -70 dBm"},
    {11, "search is signal is above -66 dBm"},
    {12, "search is signal is above -62 dBm"},
    {13, "search is signal is above -58 dBm"},
    {14, "search is signal is above -54 dBm"},
    {15, "never search"},
    { 0, NULL }
};

static const true_false_string gsm_a_rr_pcid_pattern_sense = {
    "The group of identified cells are the one not belonging to the PCID_BITMAP_GROUP",
    "The group of identified cells are the one identified by the PCID_BITMAP_GROUP"
};

static const true_false_string measurement_control_utran = {
    "Frequency-specific search enabled: use Qsearch_C_E-UTRAN if received, otherwise use Qsearch_C_EUTRAN_Initial",
    "Frequency-specific search enabled: Never search"
};

static const true_false_string measurement_control_eutran = {
    "Frequency-specific search enabled: use Qsearch_C if received, otherwise use Qsearch_C_Initial",
    "Frequency-specific search enabled: Never search"
};

static gint
de_rr_3g_priority_param_desc(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_PRIORITY_PARAM_DESC].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_PRIORITY_PARAM_DESC]);

    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_priority_param_desc_utran_start, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
    curr_bit_offset += 1;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_priority_param_desc_utran_stop, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
    curr_bit_offset += 1;

    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Default UTRAN Priority Parameters", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_priority_param_desc_default_utran_prio, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_priority_param_desc_default_threshold_utran, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_priority_param_desc_default_utran_qrxlevmin, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
    }
    /* Repeated UTRAN Priority Parameters */
    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated UTRAN Priority Parameters", "Present", "Not Present"))
    {
        proto_tree *subtree_rep_utran_prio;
        proto_item *item_rep_utran_prio;
        gint rep_utran_prio_bit_offset = curr_bit_offset;

        item_rep_utran_prio = proto_tree_add_text(subtree, tvb, curr_bit_offset>>3, 1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_PRIO_PARAM].strptr);
        subtree_rep_utran_prio = proto_item_add_subtree(item_rep_utran_prio, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_UTRAN_PRIO_PARAM]);

        while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "UTRAN Frequency Index", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree_rep_utran_prio, hf_gsm_a_rr_utran_frequency_index, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
            curr_bit_offset += 5;
        }

        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "UTRAN Priority", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree_rep_utran_prio, hf_gsm_a_rr_utran_priority, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
            curr_bit_offset += 3;
        }
        proto_tree_add_bits_item(subtree_rep_utran_prio, hf_gsm_a_rr_thresh_utran_high, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;

        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Threshold UTRAN Low", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree_rep_utran_prio, hf_gsm_a_rr_thresh_utran_low, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
            curr_bit_offset += 5;
        }

        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "UTRAN Qrxlev Min", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree_rep_utran_prio, hf_gsm_a_rr_utran_qrxlevmin, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
            curr_bit_offset += 5;
        }
        proto_item_set_len(item_rep_utran_prio, (curr_bit_offset>>3) - (rep_utran_prio_bit_offset>>3)+1);
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_eutran_neighbour_cells(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_EUTRAN_NEIGHBOUR_CELLS].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_EUTRAN_NEIGHBOUR_CELLS]);

    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "E-UTRAN Neighbour Cells Struct", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_earfcn, tvb, curr_bit_offset, 16, ENC_BIG_ENDIAN);
        curr_bit_offset += 16;

        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Measurement Bandwidth", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_measurement_bandwidth, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
            curr_bit_offset += 3;
        }
    }

    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "E-UTRAN Priority", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_priority, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
    }
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_thresh_eutran_high, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
    curr_bit_offset += 5;

    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Threshold E-UTRAN Low", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_thresh_eutran_low, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
    }

    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "E-UTRAN Qrxlev Min", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_qrxlevmin, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_eutran_neighbour_cells_mi(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_EUTRAN_NEIGHBOUR_CELLS].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_EUTRAN_NEIGHBOUR_CELLS]);

    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_earfcn, tvb, curr_bit_offset, 16, ENC_BIG_ENDIAN);
    curr_bit_offset += 16;
    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated EARFCN", "Present", "Not Present"))
    {
       proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_earfcn, tvb, curr_bit_offset, 16, ENC_BIG_ENDIAN);
       curr_bit_offset += 16;
    }
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Measurement Bandwidth ", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_measurement_bandwidth, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_eutran_pcid(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    gint        curr_bit_offset = bit_offset;
    proto_item *item;

    while (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "Repeated PCID", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_pcid, tvb, curr_bit_offset, 9, ENC_BIG_ENDIAN);
        curr_bit_offset += 9;
    }

    if (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "PCID Bitmap Group", "Present", "Not Present"))
    {
        gint i;
        guint8 bitmap = tvb_get_bits8(tvb,curr_bit_offset,6);
        item = proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_pcid_bitmap_group, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
        if (bitmap > 0)
        {
            proto_item_append_text(item, ": Cells IDs addressed by the bitmap:");
        }
        for (i = 0; i < 6; i++)
        {
            if ((1 << i) & bitmap)
            {
                if ( i != 0)
                {
                    proto_item_append_text(item, ",");
                }
                proto_item_append_text(item, " %d to %d",i*84, (i+1)*84 - 1);
            }
        }
        curr_bit_offset += 6;
    }
    while (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "PCID Pattern", "Present", "Not Present"))
    {
        gint pcid_pattern_length;
        gint pcid_pattern;
        gint pattern_lower_bound, pattern_upper_bound;
        gint i;

        pcid_pattern_length = tvb_get_bits8(tvb,curr_bit_offset,3) + 1;
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_pcid_pattern_length, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
        pcid_pattern = tvb_get_bits8(tvb,curr_bit_offset, pcid_pattern_length);

        item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, 1, "%s = PCID_Pattern: %d",
                                   decode_bits_in_field(curr_bit_offset,pcid_pattern_length, pcid_pattern),
                                   pcid_pattern);

        pattern_lower_bound = pcid_pattern << (9 - pcid_pattern_length);
        pattern_upper_bound = pattern_lower_bound;
        for (i = 0; i < (9-pcid_pattern_length); i++)
        {
            pattern_upper_bound |= 1 << i;
        }
        proto_item_append_text(item, ": Cells IDs addressed by the pattern: %d to %d", pattern_lower_bound, pattern_upper_bound);

        curr_bit_offset += pcid_pattern_length;
        proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_pcid_pattern_sense, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
    }

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_eutran_not_allowed_cells(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_EUTRAN_NOT_ALLOWED_CELLS].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_EUTRAN_NOT_ALLOWED_CELLS]);

    /* dissect PCID group */
    curr_bit_offset += de_rr_eutran_pcid(tvb, subtree, curr_bit_offset);

    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated E-UTRAN Frequency Index", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_frequency_index, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_eutran_pcid_to_ta_mapping(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_EUTRAN_PCID_TO_TA_MAPPING].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_EUTRAN_PCID_TO_TA_MAPPING]);

    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeating PCID group", "Present", "Not Present"))
    {
        /* dissect PCID group */
        curr_bit_offset += de_rr_eutran_pcid(tvb, subtree, curr_bit_offset);
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_eutran_measurement_param_desc(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    gint        curr_bit_offset;
    proto_item *item;
    guint8      rep_quant;

    curr_bit_offset = bit_offset;

    /* E-UTRAN Measurement Parameters Description */
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_qsearch_c_eutran_initial, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
    curr_bit_offset += 4;
    rep_quant = gsm_rr_csn_flag(tvb, tree, curr_bit_offset, "E-UTRAN Reporting Quantity", "RSRQ", "RSRP");
    curr_bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_multirat_reporting, tvb, curr_bit_offset, 2, ENC_BIG_ENDIAN);
    curr_bit_offset += 2;


    if (!gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "Reporting", "3 bit", "6 bit"))
    {
        if (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "E-UTRAN FDD FDD 3 bit Reporting", "Present", "Not Present"))
        {
            if (rep_quant == 0)
            {
                proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_fdd_reporting_threshold_rsrp, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
            }
            else
            {
                proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_fdd_reporting_threshold_rsrq, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
            }
            curr_bit_offset += 3;

            if (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "E-UTRAN FDD Reporting Threshold2", "Present", "Not Present"))
            {
                item = proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_fdd_reporting_threshold_2, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
                if (rep_quant == 0)
                {
                    proto_item_append_text(item, " (%.1f dB)", (gfloat)tvb_get_bits8(tvb,curr_bit_offset,6)/2 - 19.5);
                }
                else
                {
                    proto_item_append_text(item, " (%d dBm)", tvb_get_bits8(tvb,curr_bit_offset,6) - 140);
                }
                curr_bit_offset += 6;
            }
            if (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "E-EUTRAN FDD Reporting Offset", "Present", "Not Present"))
            {
                proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_fdd_reporting_offset, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);

                curr_bit_offset += 3;
            }
        }

        if (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "E-UTRAN TDD TDD 3 bit Reporting", "Present", "Not Present"))
        {
            if (rep_quant == 0)
            {
                proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_tdd_reporting_threshold_rsrp, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
            }
            else
            {
                proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_tdd_reporting_threshold_rsrq, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
            }
            curr_bit_offset += 3;

            if (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "E-UTRAN TDD Reporting Threshold2", "Present", "Not Present"))
            {
                item = proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_tdd_reporting_threshold_2, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
                if (rep_quant == 0)
                {
                    proto_item_append_text(item, " (%.1f dB)", (gfloat)tvb_get_bits8(tvb,curr_bit_offset,6)/2 - 19.5);
                }
                else
                {
                    proto_item_append_text(item, " (%d dBm)", tvb_get_bits8(tvb,curr_bit_offset,6) - 140);
                }
                curr_bit_offset += 6;
            }
            if (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "E-EUTRAN TDD Reporting Offset", "Present", "Not Present"))
            {
                proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_tdd_reporting_offset, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);

                curr_bit_offset += 3;
            }
        }
    }
    else
    {
        if (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "E-EUTRAN FDD Reporting Threshold", "Present", "Not Present"))
        {
            item = proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_fdd_measurement_report_offset, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
            if (rep_quant == 0)
            {
                proto_item_append_text(item, " (%d dBm)", tvb_get_bits8(tvb,curr_bit_offset,6) - 140);
            }
            else
            {
                proto_item_append_text(item, " (%.1f dB)", (gfloat)tvb_get_bits8(tvb,curr_bit_offset,6)/2 - 19.5);
            }
            curr_bit_offset += 6;

            if (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "E-UTRAN FDD Reporting Threshold2", "Present", "Not Present"))
            {
                item = proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_fdd_reporting_threshold_2, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
                if (rep_quant == 0)
                {
                    proto_item_append_text(item, " (%.1f dB)", (gfloat)tvb_get_bits8(tvb,curr_bit_offset,6)/2 - 19.5);
                }
                else
                {
                    proto_item_append_text(item, " (%d dBm)", tvb_get_bits8(tvb,curr_bit_offset,6) - 140);
                }
                curr_bit_offset += 6;
            }
            if (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "E-UTRAN FDD Reporting Offset", "Present", "Not Present"))
            {
                proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_fdd_reporting_offset, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
                curr_bit_offset += 3;
            }
        }

        if (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "E-UTRAN TDD Reporting Offset", "Present", "Not Present"))
        {
            item = proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_tdd_measurement_report_offset, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
            if (rep_quant == 0)
            {
                proto_item_append_text(item, " (%d dBm)", tvb_get_bits8(tvb,curr_bit_offset,6) - 140);
            }
            else
            {
                proto_item_append_text(item, " (%.1f dB)", (gfloat)tvb_get_bits8(tvb,curr_bit_offset,6)/2 - 19.5);
            }
            curr_bit_offset += 6;

            if (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "E-UTRAN TDD Reporting Threshold2", "Present", "Not Present"))
            {
                item = proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_tdd_reporting_threshold_2, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
                if (rep_quant == 0)
                {
                    proto_item_append_text(item, " (%.1f dB)", (gfloat)tvb_get_bits8(tvb,curr_bit_offset,6)/2 - 19.5);
                }
                else
                {
                    proto_item_append_text(item, " (%d dBm)", tvb_get_bits8(tvb,curr_bit_offset,6) - 140);
                }
                curr_bit_offset += 6;
            }
            if (gsm_rr_csn_flag(tvb, tree, curr_bit_offset++, "E-UTRAN TDD Reporting Offset", "Present", "Not Present"))
            {
                proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_tdd_reporting_offset, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
                curr_bit_offset += 3;
            }
        }
        item = proto_tree_add_bits_item(tree, hf_gsm_a_rr_reporting_granularity, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        if (rep_quant == 0)
        {
            proto_item_append_text(item, " (%d dB step)", 2 + tvb_get_bits8(tvb,curr_bit_offset,1));
        }
        else
        {
            proto_item_append_text(item, " (%d dB step)", 1 + tvb_get_bits8(tvb,curr_bit_offset,1));
        }
        curr_bit_offset += 1;
    }

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_eutran_param_desc(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;
    guint8      rep_quant = 0;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_EUTRAN_PARAM_DESC].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_EUTRAN_PARAM_DESC]);

    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_ccn_active, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
    curr_bit_offset += 1;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_start, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
    curr_bit_offset += 1;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_stop, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
    curr_bit_offset += 1;

    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "E-UTRAN Measurement Parameters Description", "Present", "Not Present"))
    {
        /* E-UTRAN Measurement Parameters Description */
        curr_bit_offset += de_rr_eutran_measurement_param_desc(tvb, subtree, curr_bit_offset);
    }

    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "GPRS E-UTRAN Measurement Parameters Description", "Present", "Not Present"))
    {
        /* GPRS E-UTRAN Measurement Parameters Description */
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_qsearch_p_eutran, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
        curr_bit_offset += 4;
        rep_quant = gsm_rr_csn_flag(tvb, subtree, curr_bit_offset, "E-UTRAN Reporting Quantity", "RSRQ", "RSRP");
        curr_bit_offset++;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_multirat_reporting, tvb, curr_bit_offset, 2, ENC_BIG_ENDIAN);
        curr_bit_offset += 2;

        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "E-UTRAN FDD Reporting", "Present", "Not Present"))
        {
            if (rep_quant == 0)
            {
                proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_fdd_reporting_threshold_rsrp, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
            }
            else
            {
                proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_fdd_reporting_threshold_rsrq, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
            }
            curr_bit_offset += 3;

            if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "E-UTRAN FDD Reporting Threshold 2", "Present", "Not Present"))
            {
                item = proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_fdd_reporting_threshold_2, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
                if (rep_quant == 0)
                {
                    proto_item_append_text(item, " (%.1f dB)", (gfloat)tvb_get_bits8(tvb,curr_bit_offset,6)/2 - 19.5);
                }
                else
                {
                    proto_item_append_text(item, " (%d dBm)", tvb_get_bits8(tvb,curr_bit_offset,6) - 140);
                }
                curr_bit_offset += 6;
            }
            if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "E-UTRAN FDD Reporting Offset", "Present", "Not Present"))
            {
                item = proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_fdd_reporting_offset, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
                curr_bit_offset += 3;
            }
        }

        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "E-UTRAN TDD Reporting", "Present", "Not Present"))
        {
            if (rep_quant == 0)
            {
                proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_tdd_reporting_threshold_rsrp, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
            }
            else
            {
                proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_tdd_reporting_threshold_rsrq, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
            }
            curr_bit_offset += 3;

            if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "E-UTRAN TDD Reporting Threshold 2", "Present", "Not Present"))
            {
                item = proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_tdd_reporting_threshold_2, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
                if (rep_quant == 0)
                {
                    proto_item_append_text(item, " (%.1f dB)", (gfloat)tvb_get_bits8(tvb,curr_bit_offset,6)/2 - 19.5);
                }
                else
                {
                    proto_item_append_text(item, " (%d dBm)", tvb_get_bits8(tvb,curr_bit_offset,6) - 140);
                }
                curr_bit_offset += 6;
            }
            if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "E-UTRAN TDD Reporting Offset", "Present", "Not Present"))
            {
                item = proto_tree_add_bits_item(tree, hf_gsm_a_rr_eutran_tdd_reporting_offset, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
                curr_bit_offset += 3;
            }
        }
    }

    /* Repeated E-UTRAN Neighbour Cells */
    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated E-UTRAN Neighbour Cells", "Present", "Not Present"))
    {
        curr_bit_offset += de_rr_eutran_neighbour_cells(tvb, subtree, curr_bit_offset);
    }

    /* Repeated E-UTRAN Not Allowed Cells */
    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated E-UTRAN Not Allowed Cells", "Present", "Not Present"))
    {
        curr_bit_offset += de_rr_eutran_not_allowed_cells(tvb, subtree, curr_bit_offset);
    }

    /* Repeated E-UTRAN PCID to TA mapping */
    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated E-UTRAN PCID to TA mapping", "Present", "Not Present"))
    {
        curr_bit_offset += de_rr_eutran_pcid_to_ta_mapping(tvb, subtree, curr_bit_offset);
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_eutran_param_desc_mi(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_EUTRAN_PARAM_DESC].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_EUTRAN_PARAM_DESC]);

    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_start, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
    curr_bit_offset += 1;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_stop, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
    curr_bit_offset += 1;

    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "E-UTRAN Measurement Parameters Description", "Present", "Not Present"))
    {
        /* E-UTRAN Measurement Parameters Description */
        curr_bit_offset += de_rr_eutran_measurement_param_desc(tvb, subtree, curr_bit_offset);
    }

    /* Repeated E-UTRAN Neighbour Cells */
    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated E-UTRAN Neighbour Cells", "Present", "Not Present"))
    {
        curr_bit_offset += de_rr_eutran_neighbour_cells_mi(tvb, subtree, curr_bit_offset);
    }

    /* Repeated E-UTRAN Not Allowed Cells */
    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated E-UTRAN Not Allowed Cells", "Present", "Not Present"))
    {
        curr_bit_offset += de_rr_eutran_not_allowed_cells(tvb, subtree, curr_bit_offset);
    }

    /* Measurement Control Parameters Description */
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Measurement Control Parameters Description", "Present", "Not Present"))
    {
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Default Measurement Control E-UTRAN", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_default_measurement_control_eutran, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
            curr_bit_offset += 1;
        }
        while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated E-UTRAN Measurement Control Parameters", "Present", "Not Present"))
        {
            while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated E-UTRAN Frequency Index", "Present", "Not Present"))
            {
                proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_frequency_index, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
                curr_bit_offset += 3;
            }
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_measurement_control_eutran, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
            curr_bit_offset += 1;
        }
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_priority_and_eutran_param_desc(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_PRIORITY_AND_EUTRAN_PARAM_DESC].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_PRIORITY_AND_EUTRAN_PARAM_DESC]);


    /* Serving Cell Priority Parameters Description */
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Serving Cell Priority Parameters Description", "Present", "Not Present"))
    {
        proto_tree *subtree_serv;
        proto_item *item_serv;
        gint serv_bit_offset = curr_bit_offset;

        item_serv = proto_tree_add_text(subtree, tvb, curr_bit_offset>>3, ((curr_bit_offset+15)>>3)-(curr_bit_offset>>3) + 1 , "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_SERVING_CELL_PRIORITY_PARAM_DESC].strptr);
        subtree_serv = proto_item_add_subtree(item_serv, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_SERVING_CELL_PRIORITY_PARAM_DESC]);

        proto_tree_add_bits_item(subtree_serv, hf_gsm_a_rr_serving_cell_priority_param_geran_priority, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
        proto_tree_add_bits_item(subtree_serv, hf_gsm_a_rr_serving_cell_priority_param_thresh_prio_search, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
        curr_bit_offset += 4;
        proto_tree_add_bits_item(subtree_serv, hf_gsm_a_rr_serving_cell_priority_param_thresh_gsm_low, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
        curr_bit_offset += 4;
        proto_tree_add_bits_item(subtree_serv, hf_gsm_a_rr_serving_cell_priority_param_h_prio, tvb, curr_bit_offset, 2, ENC_BIG_ENDIAN);
        curr_bit_offset += 2;
        proto_tree_add_bits_item(subtree_serv, hf_gsm_a_rr_serving_cell_priority_param_t_reselection, tvb, curr_bit_offset, 2, ENC_BIG_ENDIAN);
        curr_bit_offset += 2;
        proto_item_set_len(item_serv, (curr_bit_offset>>3) - (serv_bit_offset>>3)+1);
    }

    /* 3G Priority Parameters Description */
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "3G Priority Parameters Description", "Present", "Not Present"))
    {
        curr_bit_offset += de_rr_3g_priority_param_desc(tvb, subtree, curr_bit_offset);
    }

    /* E-UTRAN Parameters Description */
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "E-UTRAN Parameters Description", "Present", "Not Present"))
    {
        curr_bit_offset += de_rr_eutran_param_desc(tvb, subtree, curr_bit_offset);
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return (curr_bit_offset - bit_offset);
}

static gint
de_rr_3g_csg_desc(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_CSG_DESC].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_CSG_DESC]);

    while (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Repeated CSG_PSC_SPLIT struct", "Present", "Not Present"))
    {
        /* CSG_PSC_SPLIT struct */
        while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "PSC", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_psc, tvb, curr_bit_offset, 9, ENC_BIG_ENDIAN);
            curr_bit_offset += 9;
        }
        while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "PSC Pattern", "Present", "Not Present"))
        {
            gint psc_pattern_length;
            gint psc_pattern;

            psc_pattern_length = tvb_get_bits8(tvb,curr_bit_offset,3) + 1;
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_utran_psc_pattern_length, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
            curr_bit_offset += 3;
            psc_pattern = tvb_get_bits8(tvb,curr_bit_offset, psc_pattern_length);

            item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, 1, "%s = PSC_Pattern: %d",
                                       decode_bits_in_field(curr_bit_offset,psc_pattern_length, psc_pattern),
                                       psc_pattern);

            curr_bit_offset += psc_pattern_length;
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_utran_psc_pattern_sense, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
            curr_bit_offset += 1;
        }

        while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated UTRAN Frequency Index", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_utran_frequency_index, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
            curr_bit_offset += 5;
        }
    }

    while(gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "repeated CSG FDD UARFCN", "Present", "Not Present"))
    {
        /* CSG_FDD_UARFCN */
        if (!gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Technology", "TDD", "FDD"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_utran_csg_fdd_uarfcn, tvb, curr_bit_offset, 14, ENC_BIG_ENDIAN);
            curr_bit_offset += 14;
        }
        else
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_utran_csg_tdd_uarfcn, tvb, curr_bit_offset, 14, ENC_BIG_ENDIAN);
            curr_bit_offset += 14;
        }
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_eutran_csg_desc(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_EUTRAN_CSG_DESC].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_EUTRAN_CSG_DESC]);

    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated PCID group", "Present", "Not Present"))
    {
        /* dissect PCID group */
        curr_bit_offset += de_rr_eutran_pcid(tvb, subtree, curr_bit_offset);
    }

    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated EARFCN", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_csg_earfcn, tvb, curr_bit_offset, 16, ENC_BIG_ENDIAN);
        curr_bit_offset += 16;
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_eutran_csg_desc_mi(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_EUTRAN_CSG_DESC].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_EUTRAN_CSG_DESC]);

    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated CSG PCI Split", "Present", "Not Present"))
    {
        /* dissect PCID group */
        curr_bit_offset += de_rr_eutran_pcid(tvb, subtree, curr_bit_offset);
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_utran_measurement_control_param_mi(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_UTRAN_MEASUREMENT_CONTROL_PARAM_DESC].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_UTRAN_MEASUREMENT_CONTROL_PARAM_DESC]);

    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated UTRAN Frequency Index", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_utran_frequency_index, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
    }
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_control_param_desc_meas_ctrl_utran, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
    curr_bit_offset += 1;

    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static gint
de_rr_3g_supplementary_param_desc_mi(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;
    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_SUPPLEMENTARY_PARAM_DESC].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_SUPPLEMENTARY_PARAM_DESC]);

    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_priority_param_desc_utran_start, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
    curr_bit_offset += 1;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_priority_param_desc_utran_stop, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
    curr_bit_offset += 1;

    /* 3G Measurement Control Parameters Description */
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "3G Measurement Control Parameters Description", "Present", "Not Present"))
    {
        /* 3G Measurement Control Parameters Description struct */
        if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "3G Measurement Control Parameters Description struct", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_control_param_desc_meas_ctrl_utran, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
            curr_bit_offset += 1;
        }
        while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "Repeated UTRAN Measurement Control Parameters struct", "Present", "Not Present"))
        {
            curr_bit_offset += de_rr_utran_measurement_control_param_mi(tvb, subtree, curr_bit_offset);
        }
    }
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

    return(curr_bit_offset - bit_offset);
}

static guint16
de_rr_si2quater_rest_oct(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree  *subtree2, *subtree3;
    proto_item  *item2, *item3;
    guint32      curr_offset;
    gint         bit_offset, bit_offset_sav, idx;
    guint8       value;
    guint8       tvb_len = tvb_length(tvb);
    guint16      bit_len = tvb_len << 3;

    curr_offset = offset;
    bit_offset  = curr_offset << 3;

    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_ba_ind, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_ba_ind, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_mp_change_mark, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si2quater_index, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset += 4;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si2quater_count, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset += 4;
    if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Measurement Parameters Description", "Present", "Not Present"))
    { /* Measurement Parameters Description */
        bit_offset_sav = bit_offset;
        item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_MEAS_PARAM_DESC].strptr);
        subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_MEAS_PARAM_DESC]);
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_gsm_report_type, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_serving_band_reporting, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset += 2;
        proto_item_set_len(item2, (bit_offset>>3) - (bit_offset_sav>>3)+1);
    }
    if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "GPRS Real Time Difference Description", "Present", "Not Present"))
    { /* GPRS Real Time Difference Description */
        bit_offset += de_rr_rtd_desc(tvb, subtree, bit_offset, DE_RR_REST_OCTETS_GPRS_RTD_DESC);
    }
    if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "GPRS BSIC Description", "Present", "Not Present"))
    { /* GPRS BSIC Description */
        bit_offset += de_rr_bsic_desc(tvb, subtree, bit_offset, DE_RR_REST_OCTETS_GPRS_BSIC_DESC);
    }
    if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "GPRS Report Priority Description", "Present", "Not Present"))
    { /* GPRS Report Priority Description */
        bit_offset += de_rr_report_priority_desc(tvb, subtree, bit_offset, DE_RR_REST_OCTETS_GPRS_REPORT_PRIO_DESC);
    }
    if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "GPRS Measurement Parameters Description", "Present", "Not Present"))
    { /* GPRS Measurement Parameters Description */
        bit_offset += de_rr_meas_param_desc(tvb, subtree, bit_offset, DE_RR_REST_OCTETS_GPRS_MEAS_PARAM_DESC);
    }
    if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "NC Measurement Parameters", "Present", "Not Present"))
    { /* NC Measurement Parameters */
        bit_offset_sav = bit_offset;
        item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_NC_MEAS_PARAM].strptr);
        subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_NC_MEAS_PARAM]);
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_network_control_order, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset += 2;
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "NC Periods", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_nc_non_drx_period, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_nc_reporting_period_i, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_nc_reporting_period_t, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
        }
        proto_item_set_len(item2, (bit_offset>>3) - (bit_offset_sav>>3)+1);
    }
    if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "SI 2quater Extension Information", "Present", "Not Present"))
    { /* SI 2quater Extension Information */
        bit_offset_sav = bit_offset;
        item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_SI2Q_EXT_INFO].strptr);
        subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_SI2Q_EXT_INFO]);
        idx = tvb_get_bits8(tvb,bit_offset,8);
        proto_tree_add_text(subtree2,tvb, bit_offset>>3, 1, "Extension Length: %d", idx);
        bit_offset += 8;
        proto_item_set_len(item2,((bit_offset+idx+1)>>3) - (bit_offset_sav>>3)+1);
        if (gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "CCN Support Description", "Present", "Not Present"))
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
            proto_item_set_len(item3, (bit_offset>>3) - (bit_offset_sav>>3)+1);
        }
        bit_offset += idx;
    }
    if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "3G Neighbour Cell Description", "Present", "Not Present"))
    { /* 3G Neighbour Cell Description */
        bit_offset_sav = bit_offset;
        item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_NEIGH_CELL_DESC].strptr);
        subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_NEIGH_CELL_DESC]);
        if (gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "Index Start 3G", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_index_start_3g, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
            bit_offset += 7;
        }
        if (gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "Absolute Index Start EMR", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_absolute_index_start_emr, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
            bit_offset += 7;
        }
        if (gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "UTRAN FDD Description", "Present", "Not Present"))
        { /* UTRAN FDD Description */
            bit_offset += de_rr_si2quater_meas_info_utran_fdd_desc(tvb, subtree2, bit_offset);
        }
        if (gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "UTRAN TDD Description", "Present", "Not Present"))
        { /* UTRAN TDD Description */
            bit_offset += de_rr_si2quater_meas_info_utran_tdd_desc(tvb, subtree2, bit_offset);
        }
        proto_item_set_len(item2, (bit_offset>>3) - (bit_offset_sav>>3)+1);
    }
    if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "3G Measurement Parameters Description", "Present", "Not Present"))
    { /* 3G Measurement Parameters Description */
        bit_offset_sav = bit_offset;
        item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_MEAS_PARAM_DESC].strptr);
        subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_MEAS_PARAM_DESC]);
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_qsearch_i, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset += 4;
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_qsearch_c_initial, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        if (gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "FDD Information", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_qoffset, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
            bit_offset += 4;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_rep_quant, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset += 1;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_multirat_reporting, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset += 2;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_qmin, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
        }
        if (gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "TDD Information", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_qoffset, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
            bit_offset += 4;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_multirat_reporting, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset += 2;
        }
        proto_item_set_len(item2, (bit_offset>>3) - (bit_offset_sav>>3)+1);
    }
    if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "GPRS 3G Measurement Parameters Description", "Present", "Not Present"))
    { /* GPRS 3G Measurement Parameters Description */
        guint8 reporting_quant = 0;
        bit_offset_sav = bit_offset;
        item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_3G_MEAS_PARAM_DESC].strptr);
        subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_3G_MEAS_PARAM_DESC]);
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_qsearch_p, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset += 4;
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_3g_search_prio, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        if (gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "FDD Parameters", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_rep_quant, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            reporting_quant = gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "Reporting Quantity", "Ec/No", "RSCP");
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_multirat_reporting, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset += 2;
        }
        if (gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "FDD Reporting Parameters", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_reporting_offset, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
            if (reporting_quant == 0)
            {
              proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_reporting_threshold_rscp, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            }
            else
            {
              proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_reporting_threshold_ecn0, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            }
            bit_offset += 3;
        }
        if (gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "TDD Multirat Reporting", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_multirat_reporting, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset += 2;
        }
        if (gsm_rr_csn_flag(tvb, subtree2, bit_offset++, "TDD Reporting Parameters", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_reporting_offset, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
            if (reporting_quant == 0)
            {
              proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_reporting_threshold_rscp, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            }
            else
            {
              proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_tdd_reporting_threshold_ecn0, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            }
            bit_offset += 3;
        }
        proto_item_set_len(item2, (bit_offset>>3) - (bit_offset_sav>>3)+1);
    }
    /* Null breakpoint */
    if (bit_len - bit_offset > 0)
    {
        /* There is still room left in the Rest Octets IE */
        if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Additions in Rel-5", "Present", "Not present"))
        { /* Additions in Rel-5 */
            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "3G Additional Measurement Parameters Description", "Present", "Not Present"))
            { /* 3G Additional Measurement Parameters Description */
                bit_offset_sav = bit_offset;
                item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC].strptr);
                subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_ADD_MEAS_PARAM_DESC]);
                proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_qmin_offset, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                bit_offset += 3;
                proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_fdd_rscpmin, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
                bit_offset += 4;
                proto_item_set_len(item2, (bit_offset>>3) - (bit_offset_sav>>3)+1);
            }
            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "3G Additional Measurement Parameters Description 2", "Present", "Not Present"))
            { /* 3G Additional Measurement Parameters Description 2 */
                bit_offset += de_rr_3g_add_meas_param_desc2(tvb, subtree, bit_offset);
            }
            /* Null breakpoint */
            if (bit_len - bit_offset > 0)
            {
                /* There is still room left in the Rest Octets IE */
                if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Additions in Rel-6", "Present", "Not present"))
                { /* Additions in Rel-6 */
                    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_ccn_active, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
                    bit_offset += 1;

                    /* Null breakpoint */
                    if (bit_len - bit_offset > 0)
                    {
                        /* There is still room left in the Rest Octets IE */
                        if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Additions in Rel-7", "Present", "Not present"))
                        { /* Additions in Rel-7 */
                            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "700 Reporting", "Present", "Not Present"))
                            {
                                proto_tree_add_bits_item(subtree, hf_gsm_a_rr_700_reporting_offset, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                                bit_offset += 3;
                                proto_tree_add_bits_item(subtree, hf_gsm_a_rr_700_reporting_threshold, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                                bit_offset += 3;
                            }
                            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "810 Reporting", "Present", "Not Present"))
                            {
                                proto_tree_add_bits_item(subtree, hf_gsm_a_rr_810_reporting_offset, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                                bit_offset += 3;
                                proto_tree_add_bits_item(subtree, hf_gsm_a_rr_810_reporting_threshold, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                                bit_offset += 3;
                            }

                            /* Null breakpoint */
                            if (bit_len - bit_offset > 0)
                            {
                              /* There is still room left in the Rest Octets IE */
                              if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Additions in Rel-8", "Present", "Not present"))
                              { /* Additions in Rel-8 */
                                if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "3G Supplementary Parameters Description ", "Present", "Not Present"))
                                {
                                  bit_offset += de_rr_priority_and_eutran_param_desc(tvb, subtree, bit_offset);
                                }
                                if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "3G CSG Description ", "Present", "Not Present"))
                                {
                                  bit_offset += de_rr_3g_csg_desc(tvb, subtree, bit_offset);
                                }
                                if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "EUTRAN CSG Description ", "Present", "Not Present"))
                                {
                                  bit_offset += de_rr_eutran_csg_desc(tvb, subtree, bit_offset);
                                }
                              }
                            }
                        }
                    }
                }
            }
        }
    }
    gsm_rr_csn_padding_bits(subtree, tvb, bit_offset, tvb_len);
    return tvb_len - offset;
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
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;

    if (gsm_rr_csn_HL_flag(tvb, tree, 0, curr_bit_offset++, "Selection Parameters", "Present", "Not present"))
    { /* Selection Parameters */
        item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_OPTIONAL_SEL_PARAM].strptr);
        subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_OPTIONAL_SEL_PARAM]);
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_cbq, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
        curr_bit_offset += 1;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_cell_reselect_offset, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
        curr_bit_offset += 6;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_temporary_offset, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_penalty_time, tvb, curr_bit_offset, 5, ENC_BIG_ENDIAN);
        curr_bit_offset += 5;
        proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));
    }

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
    gint        curr_bit_offset;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, 1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_INDICATOR].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_INDICATOR]);
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_gprs_ra_colour, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
    curr_bit_offset += 3;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si13_position, tvb, curr_bit_offset, 1, ENC_BIG_ENDIAN);
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

static guint16
de_rr_si3_rest_oct(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32  curr_offset;
    gint     bit_offset;
    gboolean gprs_indicator;
    guint8   tvb_len = tvb_length(tvb);

    curr_offset = offset;
    bit_offset = curr_offset << 3;

    bit_offset += de_rr_rest_oct_opt_sel_param(tvb, subtree, bit_offset);

    if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Optional Power Offset", "Present", "Not present"))
    { /* Optional Power Offset */
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_power_offset, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset += 2;
    }
    gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "SYSTEM INFORMATION TYPE 2ter", "Available", "Not Available");
    gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Early Classmark Sending", "Is allowed", "Is forbidden");
    if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Scheduling if and where", "Present", "Not present"))
    { /* Scheduling if and where */
        proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "Where: %d",tvb_get_bits8(tvb,bit_offset,3));
        bit_offset += 3;
    }
    gprs_indicator = gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "GPRS Indicator", "Present", "Not present");
    if (gprs_indicator)
    { /* GPRS indicator */
        bit_offset += de_rr_rest_oct_gprs_indicator(tvb, subtree, bit_offset);
    }
    gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "3G Early Classmark Sending Restriction",
                                    "The sending of UTRAN,CDMA2000 and GERAN IU MODE CLASSMARK CHANGE messages are controlled by the Early Classmark Sending Control parameter",
                                    "Neither UTRAN, CDMA2000 nor GERAN IU MODE CLASSMARK CHANGE message shall be sent with the Early classmark sending");
    if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "SI2quater Indicator", "Present", "Not present"))
    { /* SI2quater Indicator */
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si2quater_position, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
    }
    if (gprs_indicator == FALSE)
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si13alt_position, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
    }
    gsm_rr_csn_padding_bits(subtree, tvb, bit_offset, tvb_len);
    return tvb_len - offset;
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

static guint16
de_rr_si4_rest_oct(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    proto_tree *subtree2, *subtree3;
    proto_item *item2, *item3;
    guint32     curr_offset;
    gint        bit_offset, bit_offset_sav;
    guint8      tvb_len = tvb_length(tvb);
    guint16     bit_len = tvb_len << 3;

    curr_offset = offset;
    bit_offset = curr_offset << 3;

    item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_SI4_REST_OCTETS_O].strptr);

    subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_SI4_REST_OCTETS_O]);

    bit_offset += de_rr_rest_oct_opt_sel_param(tvb, subtree2, bit_offset);

    if (gsm_rr_csn_HL_flag(tvb, subtree2, bit_len, bit_offset++, "Optional Power Offset", "Present", "Not present"))
    { /* Optional Power Offset */
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_power_offset, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset += 2;
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree2, bit_len, bit_offset++, "GPRS Indicator", "Present", "Not present"))
    {
        bit_offset += de_rr_rest_oct_gprs_indicator(tvb, subtree2, bit_offset);
    }
    proto_item_set_len(item2,(bit_offset>>3) + 1 - curr_offset);

    if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "SI4 Rest Octets_S", "Present", "Not present"))
    { /* SI4 Rest Octets_S */
        bit_offset_sav = bit_offset;
        item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_SI4_REST_OCTETS_S].strptr);
        subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_SI4_REST_OCTETS_S]);

        if (gsm_rr_csn_HL_flag(tvb, subtree2, bit_len, bit_offset++, "LSA Parameters", "Present", "Not present"))
        { /* LSA Parameters */
            item3 = proto_tree_add_text(subtree2, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_LSA_PARAMETERS].strptr);
            subtree3 = proto_item_add_subtree(item3, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_LSA_PARAMETERS]);
            proto_tree_add_bits_item(subtree3, hf_gsm_a_rr_prio_thr, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
            proto_tree_add_bits_item(subtree3, hf_gsm_a_rr_lsa_offset, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
            if (gsm_rr_csn_flag(tvb,subtree3, bit_offset++,"MCC/MNC", "Present", "Not Present"))
            {
                proto_tree_add_text(subtree3, tvb, bit_offset>>3, 2, "MCC: %d", tvb_get_bits16(tvb,bit_offset,12,ENC_BIG_ENDIAN));
                bit_offset += 12;
                proto_tree_add_text(subtree3, tvb, bit_offset>>3, 2, "MNC: %d", tvb_get_bits16(tvb,bit_offset,12,ENC_BIG_ENDIAN));
                bit_offset += 12;
            }
            proto_item_set_len(item2, (bit_offset>>3) - (bit_offset_sav>>3)+1);
        }

        if (gsm_rr_csn_HL_flag(tvb, subtree2, bit_len, bit_offset++, "Cell Identity", "Present", "Not present"))
        { /* Cell Identity */
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_cell_id, tvb, bit_offset, 16, ENC_BIG_ENDIAN);
            bit_offset += 16;
        }

        if (gsm_rr_csn_HL_flag(tvb, subtree2, bit_len, bit_offset++, "LSA ID information", "Present", "Not present"))
        { /* LSA ID information */
            item3 = proto_tree_add_text(subtree2, tvb, bit_offset>>3, len, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_LSA_ID_INFO].strptr);
            subtree3 = proto_item_add_subtree(item3, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_LSA_ID_INFO]);
            do
            {
                if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Type", "Short LSA ID", "LSA ID"))
                {
                    proto_tree_add_text(subtree3, tvb, bit_offset>>3, 3, "Short LSA ID: %d",tvb_get_bits16(tvb,bit_offset,10,ENC_BIG_ENDIAN));
                    bit_offset += 10;
                }
                else
                {
                    proto_tree_add_text(subtree3, tvb, bit_offset>>3, 3, "LSA ID: %d",tvb_get_bits32(tvb,bit_offset,24,ENC_BIG_ENDIAN));
                    bit_offset += 24;
                }
            } while (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Additional LSA ID", "Present", "Not Present"));
        }
        if (gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "CBQ3", "Present", "Not present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_cbq3, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset += 3;
        }
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "SI3 alt position", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si13alt_position, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset += 1;
        }
        proto_item_set_len(item2, (bit_offset>>3) - (bit_offset_sav>>3)+1);
    }
    else
    { /* Break indicator */
        gsm_rr_csn_HL_flag(tvb, subtree, bit_len, bit_offset++, "Break Indicator",
                           "Additional parameters \"SI4 Rest Octets_S\" are sent in SYSTEM INFORMATION TYPE 7 and 8",
                           "Additional parameters \"SI4 Rest Octets_S\" are not sent in SYSTEM INFORMATION TYPE 7 and 8");
    }
    /* Truncation allowed (see 44.018 section 8.9 */
    gsm_rr_csn_padding_bits(subtree, tvb, bit_offset, tvb_len);
    return tvb_len - offset;
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

static guint16
de_rr_si6_rest_oct(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree *subtree2;
    proto_item *item2;
    guint32     curr_offset;
    gint        bit_offset, bit_offset_sav;
    guint8      value;
    guint8      tvb_len = tvb_length(tvb);

    curr_offset = offset;
    bit_offset = curr_offset << 3;

    if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "PCH and NCH Info", "Present", "Not present"))
    { /* PCH and NCH Info */
        bit_offset_sav = bit_offset;
        item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_PCH_AND_NCH_INFO].strptr);
        subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_PCH_AND_NCH_INFO]);
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_paging_channel_restructuring, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_nln_sacch, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset += 2;
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Call Priority", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree2, hf_gsm_a_call_prio, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
        }
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_nln_status_sacch, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_item_set_len(item2, (bit_offset>>3) - (bit_offset_sav>>3)+1);
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "VBS/VGCS options", "Present", "Not present"))
    { /* VBS/VGCS options */
        bit_offset_sav = bit_offset;
        item2 = proto_tree_add_text(subtree, tvb,bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_VBS_VGCS_OPTIONS].strptr);
        subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_VBS_VGCS_OPTIONS]);
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_vbs_vgcs_inband_notifications, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_vbs_vgcs_inband_pagings, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_item_set_len(item2, (bit_offset>>3) - (bit_offset_sav>>3)+1);
    }
    value = gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "DTM", "Supported in Serving cell", "Not Supported in Serving cell");
    if (value == TRUE)
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rac, tvb, bit_offset, 8, ENC_BIG_ENDIAN);
        bit_offset += 8;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_max_lapdm, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
    }
    gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Band Indicator", "1900", "1800");
    if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "GPRS MS PWR MAX CCCH", "Present", "Not present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_gprs_ms_txpwr_max_ccch, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
        bit_offset += 5;
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "MBMS Procedures", "Supported", "Not supported"))
    { /* MBMS Procedures */
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_dedicated_mode_mbms_notification_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_mnci_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
    }
    if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Additions in Rel-7", "Present", "Not present"))
    { /* Additions in Release 7 */
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "AMR Config", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_amr_config, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
            bit_offset += 4;
        }
    }
    gsm_rr_csn_padding_bits(subtree, tvb, bit_offset, tvb_len);
    return tvb_len - offset;
}

/* [3] 10.5.2.36 SI 7 Rest Octets
 * [3] 10.5.2.37 SI 8 Rest Octets
 * [3] 10.5.2.37a SI 9 Rest Octets
 */

/*
 * [3] 10.5.2.37b SI 13 Rest Octets
 */
static const value_string gsm_a_rr_si_change_field_vals[] = {
    {  0, "Update of unspecified SI message or SI messages"},
    {  1, "Update of SI1 message"},
    {  2, "Update of SI2, SI2 bis or SI2 ter message or any instance of SI2quater messages"},
    {  3, "Update of SI3, SI4, SI7, SI8, SI16 or SI17 message"},
    {  4, "Update of SI9 message"},
    {  5, "Update of SI18 or SI20 message"},
    {  6, "Update of SI19 message"},
    {  7, "Update of SI15 message"},
    {  8, "Update of SI2n message"},
    {  9, "Update of unknown SI message type"},
    { 10, "Update of unknown SI message type"},
    { 11, "Update of unknown SI message type"},
    { 12, "Update of unknown SI message type"},
    { 13, "Update of unknown SI message type"},
    { 14, "Update of unknown SI message type"},
    { 15, "Update of unknown SI message type"},
    {  0, NULL }
};

static const value_string gsm_a_rr_psi1_repeat_period_vals[] = {
    {  0, "1 multiframe"},
    {  1, "2 multiframes"},
    {  2, "3 multiframes"},
    {  3, "4 multiframes"},
    {  4, "5 multiframes"},
    {  5, "6 multiframes"},
    {  6, "7 multiframes"},
    {  7, "8 multiframes"},
    {  8, "9 multiframes"},
    {  9, "10 multiframes"},
    { 10, "11 multiframes"},
    { 11, "12 multiframes"},
    { 12, "13 multiframes"},
    { 13, "14 multiframes"},
    { 14, "15 multiframes"},
    { 15, "16 multiframes"},
    {  0, NULL }
};

static const value_string gsm_a_rr_pbcch_pb_vals[] = {
    {  0, "0 dB"},
    {  1, "-2 dB"},
    {  2, "-4 dB"},
    {  3, "-6 dB"},
    {  4, "-8 dB"},
    {  5, "-10 dB"},
    {  6, "-12 dB"},
    {  7, "-14 dB"},
    {  8, "-16 dB"},
    {  9, "-18 dB"},
    { 10, "-20 dB"},
    { 11, "-22 dB"},
    { 12, "-24 dB"},
    { 13, "-26 dB"},
    { 14, "-28 dB"},
    { 15, "-30 dB"},
    {  0, NULL }
};

static const true_false_string gsm_a_rr_spgc_ccch_sup_value = {
    "SPLIT_PG_CYCLE is supported on CCCH in this cell",
    "SPLIT_PG_CYCLE is not supported on CCCH in this cell"
};

static const value_string gsm_a_rr_priority_access_thr_vals[] = {
    {  0, "Packet access is not allowed in the cell"},
    {  1, "Packet access is not allowed in the cell"},
    {  2, "Packet access is not allowed in the cell"},
    {  3, "Packet access is allowed for priority level 1"},
    {  4, "Packet access is allowed for priority level 1 to 2"},
    {  5, "Packet access is allowed for priority level 1 to 3"},
    {  6, "Packet access is allowed for priority level 1 to 4"},
    {  7, "Packet access is allowed for priority level 1 to 4"},
    {  0, NULL }
};

static gint
de_rr_rest_oct_gprs_mobile_allocation(tvbuff_t *tvb, proto_tree *tree, gint bit_offset)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;
    guint8      value;
    guint64     ma_length;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_GPRS_MOBILE_ALLOC].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_GPRS_MOBILE_ALLOC]);
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_hsn, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
    curr_bit_offset += 6;
    while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "RFL number list", "Present", "Not Present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rfl_number, tvb, curr_bit_offset, 4, ENC_BIG_ENDIAN);
        curr_bit_offset += 4;
    }
    if (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "MA", "Not Present", "Present"))
    {
        while (gsm_rr_csn_flag(tvb, subtree, curr_bit_offset++, "ARFCN index list", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_arfcn_index, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
            curr_bit_offset += 6;
        }
    }
    else
    {
        proto_tree_add_bits_ret_val(subtree, hf_gsm_a_rr_ma_length, tvb, curr_bit_offset, 6, &ma_length, ENC_BIG_ENDIAN);
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
    proto_item_set_len(item,((curr_bit_offset>>3) - (bit_offset>>3) + 1));

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
    "Use EGPRS PACKET CHANNEL REQUEST message for uplink TBF establishment on the PRACH"
};

static const value_string gsm_a_rr_bep_period_vals[] = {
    {  0, "1"},
    {  1, "2"},
    {  2, "3"},
    {  3, "4"},
    {  4, "5"},
    {  5, "7"},
    {  6, "10"},
    {  7, "12"},
    {  8, "15"},
    {  9, "20"},
    { 10, "25"},
    { 11, "Reserved"},
    { 12, "Reserved"},
    { 13, "Reserved"},
    { 14, "Reserved"},
    { 15, "Reserved"},
    {  0, NULL }
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
    {  0, "0.0"},
    {  1, "0.1"},
    {  2, "0.2"},
    {  3, "0.3"},
    {  4, "0.4"},
    {  5, "0.5"},
    {  6, "0.6"},
    {  7, "0.7"},
    {  8, "0.8"},
    {  9, "0.9"},
    { 10, "1.0"},
    { 11, "1.0"},
    { 12, "1.0"},
    { 13, "1.0"},
    { 14, "1.0"},
    { 15, "1.0"},
    {  0, NULL }
};

static const value_string gsm_a_rr_t_avg_x_vals[] = {
    {  0, "2^(0/2) / 6 multiframes"},
    {  1, "2^(1/2) / 6 multiframes"},
    {  2, "2^(2/2) / 6 multiframes"},
    {  3, "2^(3/2) / 6 multiframes"},
    {  4, "2^(4/2) / 6 multiframes"},
    {  5, "2^(5/2) / 6 multiframes"},
    {  6, "2^(6/2) / 6 multiframes"},
    {  7, "2^(7/2) / 6 multiframes"},
    {  8, "2^(8/2) / 6 multiframes"},
    {  9, "2^(9/2) / 6 multiframes"},
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
    {  0, NULL }
};

static const true_false_string gsm_a_rr_pc_meas_chan_value = {
    "Downlink measurements for power control shall be made on PDCH",
    "Downlink measurements for power control shall be made on BCCH"
};

static const value_string gsm_a_rr_n_avg_i_vals[] = {
    {  0, "2^(0/2)"},
    {  1, "2^(1/2)"},
    {  2, "2^(2/2)"},
    {  3, "2^(3/2)"},
    {  4, "2^(4/2)"},
    {  5, "2^(5/2)"},
    {  6, "2^(6/2)"},
    {  7, "2^(7/2)"},
    {  8, "2^(8/2)"},
    {  9, "2^(9/2)"},
    { 10, "2^(10/2)"},
    { 11, "2^(11/2)"},
    { 12, "2^(12/2)"},
    { 13, "2^(13/2)"},
    { 14, "2^(14/2)"},
    { 15, "2^(15/2)"},
    {  0, NULL }
};

static const true_false_string gsm_a_rr_sgsnr_value = {
    "SGSN is Release '99 onwards",
    "SGSN is Release '98 or older"
};

static const true_false_string gsm_a_rr_si_status_ind_value = {
    "The network supports the PACKET SI STATUS message",
    "The network does not support the PACKET SI STATUS message"
};

static const value_string gsm_a_rr_lb_ms_txpwr_max_cch_vals[] = {
    {  0, "43 dBm"},
    {  1, "41 dBm"},
    {  2, "39 dBm"},
    {  3, "37 dBm"},
    {  4, "35 dBm"},
    {  5, "33 dBm"},
    {  6, "31 dBm"},
    {  7, "29 dBm"},
    {  8, "27 dBm"},
    {  9, "25 dBm"},
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
    {  0, NULL }
};

static const value_string gsm_a_rr_si2n_support_vals[] = {
    { 0, "SI2n is not supported"},
    { 1, "SI2n is supported on PACCH"},
    { 2, "SI2n is supported on PACCH and broadcast on BCCH"},
    { 3, "SI2n is supported on PACCH and broadcast on BCCH Ext"},
    { 0, NULL }
};

static guint16
de_rr_si13_rest_oct(tvbuff_t *tvb, proto_tree *subtree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree *subtree2;
    proto_item *item2;
    guint       bit_offset, bit_offset_sav;
    guint8      tvb_len = tvb_length(tvb);
    guint16     bit_len = tvb_len << 3;
    bit_offset          = offset << 3;

    if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "SI13 contents", "Present", "Not present"))
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bcch_change_mark, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si_change_field, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset += 4;
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "SI13 Change Mark", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si13_change_mark, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset += 2;
            bit_offset += de_rr_rest_oct_gprs_mobile_allocation(tvb, subtree, bit_offset);
        }
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "PBCCH", "Present In Cell", "Not Present In Cell"))
        { /* PBCCH present in the cell */
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_psi1_repeat_period, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
            bit_offset += 4;
            bit_offset_sav = bit_offset;
            item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_PBCCH_DESC].strptr);
            subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_PBCCH_DESC]);
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_pbcch_pb, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
            bit_offset += 4;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_pbcch_tsc, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
            proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_pbcch_tn, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "MAIO", "Present", "Not Present"))
            {
                proto_tree_add_text(subtree2, tvb, bit_offset>>3, 1, "MAIO: %d", tvb_get_bits8(tvb,bit_offset,6));
                bit_offset += 6;
            }
            else
            {
                if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "ARFCN", "Present", "Not Present"))
                {
                    proto_tree_add_bits_item(subtree2, hf_gsm_a_rr_arfcn, tvb, bit_offset, 10, ENC_BIG_ENDIAN);
                    bit_offset += 10;
                }
                else
                    proto_tree_add_text(subtree2, tvb, bit_offset>>3, 1, "PBCCH shall use the BCCH carrier");
            }
            proto_item_set_len(item2, (bit_offset>>3) - (bit_offset_sav>>3)+1);
        }
        else
        { /* PBCCH not present in the cell */
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rac, tvb, bit_offset, 8, ENC_BIG_ENDIAN);
            bit_offset += 8;
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_spgc_ccch_sup, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset += 1;
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_priority_access_thr, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_network_control_order, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset += 2;
            bit_offset += de_rr_rest_oct_gprs_cell_options(tvb, subtree, bit_offset);
            bit_offset += de_rr_rest_oct_gprs_power_control_parameters(tvb, subtree, bit_offset);
        }

        /* Null breakpoint */
        if (bit_offset < bit_len)
        {
           if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Additions in R99", "Present", "Not present"))
           { /* Additions in release 99 */
               proto_tree_add_bits_item(subtree, hf_gsm_a_rr_sgsnr, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
               bit_offset += 1;

               /* Null breakpoint */
               if (bit_offset < bit_len)
               {
                  if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Additions in Rel-4", "Present", "Not present"))
                  { /* Additions in release Rel-4 */
                      proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si_status_ind, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
                      bit_offset += 1;

                      /* Null breakpoint */
                      if (bit_offset < bit_len)
                      {
                         if (gsm_rr_csn_HL_flag(tvb, subtree, 0, bit_offset++, "Additions in Rel-6", "Present", "Not present"))
                         { /* Additions in release Rel-6 */
                             if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "LB MS TXPWR MAX CCH ", "Present", "Not Present"))
                             {
                                 proto_tree_add_bits_item(subtree, hf_gsm_a_rr_lb_ms_txpwr_max_cch, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
                                 bit_offset += 5;
                             }
                             proto_tree_add_bits_item(subtree, hf_gsm_a_rr_si2n_support, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
                             bit_offset += 2;
                         }
                      }
                  }
               }
           }
        }
    }
    gsm_rr_csn_padding_bits(subtree, tvb, bit_offset, tvb_len);
    return tvb_len - offset;
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
static guint16
de_rr_starting_time(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_item *item;
    guint32     curr_offset;
    guint16     rfn, fn;

    curr_offset = offset;

    fn = tvb_get_ntohs(tvb,curr_offset);
    rfn = reduced_frame_number(fn);
    proto_tree_add_item(tree, hf_gsm_a_rr_T1prim, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_rr_T3, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    curr_offset++;
    proto_tree_add_item(tree, hf_gsm_a_rr_T2, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;
    item = proto_tree_add_uint(tree, hf_gsm_a_rr_rfn, tvb, curr_offset-2, 2, rfn);
    PROTO_ITEM_SET_GENERATED(item);
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
    { 0, "Non-synchronized"},
    { 1, "Synchronized"},
    { 2, "Pre-synchronised"},
    { 3, "Pseudo-synchronised"},
    { 0, NULL }
};
/* NCI: Normal cell indication (octet 1, bit 4) */

static const true_false_string gsm_a_rr_sync_ind_nci_value = {
    "Out of range timing advance shall trigger a handover failure procedure",
    "Out of range timing advance is ignored"
};
static guint16
de_rr_sync_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    /*NCI */
    proto_tree_add_item(tree, hf_gsm_a_rr_sync_ind_nci, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /*ROT */
    proto_tree_add_item(tree, hf_gsm_a_rr_sync_ind_rot, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /*SI*/
    proto_tree_add_item(tree, hf_gsm_a_rr_sync_ind_si, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.40 Timing Advance
 */
static guint16
de_rr_timing_adv(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_timing_adv, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.41 Time Difference
 */
static guint16
de_rr_time_diff(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_time_diff, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.41a TLLI
 * The TLLI is encoded as a binary number with a length of 4 octets. TLLI is defined in 3GPP TS 23.003
 */
guint16
de_rr_tlli(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset, tlli;

    curr_offset = offset;

    tlli = tvb_get_ntohl(tvb, curr_offset);
    proto_tree_add_item(tree, hf_gsm_a_rr_tlli, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
    curr_offset = curr_offset + 4;
    if(add_string)
        g_snprintf(add_string, string_len, " - 0x%x", tlli);

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.42 TMSI/P-TMSI
 */
static guint16
de_rr_tmsi_ptmsi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree *subtree;
    proto_item *item;
    guint32     curr_offset;

    curr_offset = offset;

    item = proto_tree_add_text(tree, tvb, curr_offset, 3, "%s",
                               gsm_rr_elem_strings[DE_RR_TMSI_PTMSI].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_TMSI_PTMSI]);

    proto_tree_add_item(subtree, hf_gsm_a_rr_tmsi_ptmsi, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
    curr_offset = curr_offset + 4;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.42a VGCS target mode Indication
 */
/*
Target mode (octet 3)
Bit  8 7
     0 0    dedicated mode
     0 1    group transmit mode
     Other values are reserved for future use.
*/
static const value_string gsm_a_rr_target_mode_vals[] _U_ = {
    { 0, "Dedicated mode"},
    { 1, "Group transmit mode"},
    { 0, NULL }
};
static guint16
de_rr_vgcs_tar_mode_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_target_mode, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_rr_group_cipher_key_number, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.42b      VGCS Ciphering Parameters
 */
static guint16
de_rr_vgcs_cip_par(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_text(tree,tvb, curr_offset, len ,"Data(Not decoded)");

    curr_offset = curr_offset + 2;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.43 Wait Indication
 */
static guint16
de_rr_wait_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_wait_indication, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.44 SI10 rest octets $(ASCI)$
 */

/*
 * [3] 10.5.2.45 Extended Measurement Results
 */
static guint16
de_rr_ext_meas_result(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    gint    bit_offset, i;
    guint8  value;

    curr_offset = offset;
    bit_offset  = curr_offset << 3;

    proto_tree_add_bits_item(tree, hf_gsm_a_rr_seq_code, tvb,bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_dtx_used, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    for (i=0; i<21; i++)
    {
        value = tvb_get_bits8(tvb,bit_offset,6);
        proto_tree_add_text(tree, tvb, bit_offset>>3, 1, "RXLEV carrier %d: %s (%d)",i,val_to_str_ext_const(value, &gsm_a_rr_rxlev_vals_ext, "Unknown"),value);
        bit_offset += 6;
    }

    curr_offset = offset + len;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.46 Extended Measurement Frequency List
 */
static guint16
de_rr_ext_meas_freq_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
   guint32 curr_offset;

   curr_offset = offset;

   proto_tree_add_bits_item(tree, hf_gsm_a_rr_seq_code, tvb,(curr_offset<<3)+3, 1, ENC_BIG_ENDIAN);

   return dissect_arfcn_list(tvb, tree, pinfo, offset, 16, add_string, string_len);
}

/*
 * [3] 10.5.2.47 Suspension Cause
 */
/*Suspension cause value (octet 2)*/
static const value_string gsm_a_rr_suspension_cause_vals[] = {
    { 0, "Emergency call, mobile originating call or call re-establishment"},
    { 1, "Location Area Update"},
    { 2, "MO Short message service"},
    { 3, "Other procedure which can be completed with an SDCCH"},
    { 4, "MO Voice broadcast or group call"},
    { 5, "Mobile terminating CS connection"},
    { 6, "DTM not supported in the cell"},
    { 0, NULL }
};
guint16
de_rr_sus_cau(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_suspension_cause, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 1;

    return(curr_offset - offset);
}
/*
 * [3] 10.5.2.48 APDU ID
 */
static const value_string gsm_a_rr_apdu_id_vals[] = {
    { 0, "RRLP (GSM 04.31) LCS" },
    { 0, NULL },
};
static guint16
de_rr_apdu_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_gsm_a_rr_apdu_id, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 0;
}

/*
 * [3] 10.5.2.49 APDU Flags
 */
static const value_string gsm_a_rr_apdu_flags_vals[] = {
    { 1, "Last or only segment" },
    { 2, "First or only segment" },
    { 0, NULL },
};
static guint16
de_rr_apdu_flags(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree_add_item(tree, hf_gsm_a_rr_apdu_flags, tvb, offset, 1, ENC_BIG_ENDIAN);

    return 1;
}

/*
 * [3] 10.5.2.50 APDU Data
 */
static guint16
de_rr_apdu_data(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    tvbuff_t *sub_tvb;

    sub_tvb = tvb_new_subset(tvb, offset, len, len);

    if (rrlp_dissector)
        call_dissector(rrlp_dissector, sub_tvb,pinfo, tree);

    return len;
}

/*
 * [3] 10.5.2.51 Handover To UTRAN Command
 */
static guint16
de_rr_ho_to_utran_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    tvbuff_t *rrc_irat_ho_to_utran_cmd_tvb;

    curr_offset = offset;
    if (len)
    {
        rrc_irat_ho_to_utran_cmd_tvb = tvb_new_subset(tvb, curr_offset, len, len);
        if (rrc_irat_ho_to_utran_cmd_handle)
            call_dissector(rrc_irat_ho_to_utran_cmd_handle, rrc_irat_ho_to_utran_cmd_tvb, pinfo, tree);
    }

    curr_offset += len;
    return(curr_offset - offset);
}


/*
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
static guint16
de_rr_serv_sup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;
    /* bit 1
     * 0 mobile station does not require notification of broadcast MBMS services
     * 1 mobile station requires notification of broadcast MBMS services
     * bit 2
     * 0 mobile station does not require notification of multicast MBMS services
     * 1 mobile station requires notification of multicast MBMS services
     */
    /* MBMS Multicast */
    proto_tree_add_item(tree, hf_gsm_a_rr_MBMS_multicast, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    /* MBMS Broadcast */
    proto_tree_add_item(tree, hf_gsm_a_rr_MBMS_broadcast, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.59       Dedicated Service Information
 */
/*
Last Segment (octet 2)
bit 1
  0  mobile station shall not perform Service Information Sending procedure on new cell.
  1  mobile station shall perform Service Information Sending procedure on new cell.
*/
static const true_false_string gsm_a_rr_last_segment_value  = {
    "Mobile station shall perform Service Information Sending procedure on new cell.",
    "mobile station shall not perform Service Information Sending procedure on new cell."
};
static guint16
de_rr_ded_serv_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_last_segment, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset = curr_offset + 3;

    return(curr_offset - offset);
}

/*
 * [3] 10.5.2.69        Carrier Indication
 */
static const true_false_string gsm_a_rr_carrier_ind_value  = {
    "Carrier 2",
    "Carrier 1"
};

static guint16
de_rr_carrier_ind(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_tree *subtree;
    proto_item *item;
    guint32     curr_offset;

    curr_offset = offset;

    item = proto_tree_add_text(tree, tvb, curr_offset, 3, "%s",
                               gsm_rr_elem_strings[DE_RR_CARRIER_IND].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_rr_elem[DE_RR_CARRIER_IND]);

    proto_tree_add_item(subtree, hf_gsm_a_rr_carrier_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset += 1;

    return(curr_offset - offset);
}

guint16 (*rr_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len) = {
    /* Radio Resource Management  Information Elements 10.5.2, most are from 10.5.1 */

    de_rr_ba_range,                             /* [3]  10.5.2.1a       BA Range */
    de_rr_cell_ch_dsc,                          /* [3]  10.5.2.1b       Cell Channel Description        */
    de_rr_ba_list_pref,                         /* [3]  10.5.2.1c       BA List Pref                    */
    de_rr_utran_freq_list,                      /* [3]  10.5.2.1d       UTRAN Frequency List            */
    de_rr_cell_select_indic,                    /* [3]  10.5.2.1e       Cell selection indicator after release of all TCH and SDCCH IE */
    de_rr_cell_dsc,                             /* 10.5.2.2   RR Cell Description                       */
    de_rr_cell_opt_bcch,                        /* [3]  10.5.2.3        Cell Options (BCCH)             */
    de_rr_cell_opt_sacch,                       /* [3]  10.5.2.3a       Cell Options (SACCH)            */
    de_rr_cell_sel_param,                       /* [3]  10.5.2.4        Cell Selection Parameters       */
/*
 * [3]  10.5.2.4a       (void)
 */
    de_rr_ch_dsc,                               /* [3]  10.5.2.5        Channel Description             */
    de_rr_ch_dsc2,                              /* [3]  10.5.2.5a   RR Channel Description 2            */
    de_rr_ch_dsc3,                              /* [3]  10.5.2.5c   RR Channel Description 3            */
    de_rr_ch_mode,                              /* [3]  10.5.2.6        Channel Mode                    */
    de_rr_ch_mode2,                             /* [3]  10.5.2.7        Channel Mode 2                  */
    de_rr_utran_cm,                             /* [3]  10.5.2.7a       UTRAN Classmark */
/* [3]  10.5.2.7b       (void) */

    de_rr_cm_enq_mask,                          /* [3]  10.5.2.7c       Classmark Enquiry Mask          */
/* [3]  10.5.2.7d       GERAN Iu Mode Classmark information element                                     */
    de_rr_chnl_needed,                          /* [3]  10.5.2.8        Channel Needed
                                                 * [3]  10.5.2.8a       (void) */
    de_rr_chnl_req_desc2,                       /* [3]  10.5.2.8b       Channel Request Description 2   */
    /* Pos 20 */
    de_rr_cip_mode_set,                         /* [3]  10.5.2.9        Cipher Mode Setting             */
    de_rr_cip_mode_resp,                        /* [3]  10.5.2.10       Cipher Response */
    de_rr_ctrl_ch_desc,                         /* [3]  10.5.2.11       Control Channel Description     */
    de_rr_dtm_info_details,                     /* [3]  10.5.2.11a      DTM Information Details */
    de_rr_dyn_arfcn_map,                        /* [3]  10.5.2.11b      Dynamic ARFCN Mapping           */
    de_rr_freq_ch_seq,                          /* [3]  10.5.2.12       Frequency Channel Sequence      */
    de_rr_freq_list,                            /* [3]  10.5.2.13       Frequency List                  */
    de_rr_freq_short_list,                      /* [3]  10.5.2.14       Frequency Short List            */
    de_rr_freq_short_list2,                     /* [3]  10.5.2.14a      Frequency Short List 2          */
/* [3]  10.5.2.14b      Group Channel Description */
    de_rr_gprs_resumption,                      /* [3]  10.5.2.14c      GPRS Resumption                 */
    de_rr_gprs_broadcast_info,                  /* [3]  10.5.2.14d      GPRS broadcast information      */
/* [3]  10.5.2.14e      Enhanced DTM CS Release Indication */
    de_rr_ho_ref,                               /* 10.5.2.15  Handover Reference                        */
    de_rr_ia_rest_oct,                          /* [3] 10.5.2.16 IA Rest Octets                         */
    de_rr_iar_rest_oct,                         /* [3] 10.5.2.17 IAR Rest Octets                        */
    de_rr_iax_rest_oct,                         /* [3] 10.5.2.18 IAX Rest Octets                        */
    de_rr_l2_pseudo_len,                        /*[3] 10.5.2.19 L2 Pseudo Length                        */
    de_rr_meas_res,                             /* [3] 10.5.2.20 Measurement Results                    */
/*
 * [3] (void)
 */
    de_rr_mob_all,                              /* [3] 10.5.2.21 Mobile Allocation                      */
    de_rr_mob_time_diff,                        /* [3] 10.5.2.21a Mobile Time Difference                */
    de_rr_multirate_conf,                       /* [3] 10.5.2.21aa MultiRate configuration              */
    /* Pos 30 */
    de_rr_mult_all,                             /* [3] 10.5.2.21b Multislot Allocation                  */
/*
 * [3] 10.5.2.21c (void)
 */
    de_rr_neigh_cell_desc,                      /* [3] 10.5.2.22 Neighbour Cell Description             */
    de_rr_neigh_cell_desc2,                     /* [3] 10.5.2.22a Neighbour Cell Description 2          */
/*
 * [3] 10.5.2.22b (void)
 * [3] 10.5.2.22c NT/N Rest Octets */
    de_rr_p1_rest_oct,                          /* [3] 10.5.2.23 P1 Rest Octets                         */
    de_rr_p2_rest_oct,                          /* [3] 10.5.2.24 P2 Rest Octets                         */
    de_rr_p3_rest_oct,                          /* [3] 10.5.2.25 P3 Rest Octets                         */
    de_rr_packet_ch_desc,                       /* [3] 10.5.2.25a Packet Channel Description            */
    de_rr_ded_mod_or_tbf,                       /* [3] 10.5.2.25b Dedicated mode or TBF                 */
    de_rr_pkt_ul_ass,                           /* [3] 10.5.2.25c RR Packet Uplink Assignment           */
    de_rr_pkt_dl_ass,                           /* [3] 10.5.2.25d RR Packet Downlink Assignment         */
    de_rr_pkt_dl_ass_type2,                     /* [3] 10.5.2.25e RR Packet Downlink Assignment Type 2  */
    de_rr_page_mode,                            /* [3] 10.5.2.26 Page Mode                              */
/*
 * [3] 10.5.2.26a (void)
 * [3] 10.5.2.26b (void)
 * [3] 10.5.2.26c (void)
 * [3] 10.5.2.26d (void)
 */
    de_rr_ncc_perm,                             /* [3] 10.5.2.27 NCC Permitted                          */
    de_rr_pow_cmd,                              /* 10.5.2.28  Power Command                             */
    de_rr_pow_cmd_and_acc_type,                 /* 10.5.2.28a Power Command and access type             */
    de_rr_rach_ctrl_param,                      /* [3] 10.5.2.29 RACH Control Parameters                */
    de_rr_req_ref,                              /* [3] 10.5.2.30 Request Reference                      */
    de_rr_cause,                                /* 10.5.2.31  RR Cause                                  */
    de_rr_sync_ind,                             /* 10.5.2.39  Synchronization Indication                */
    de_rr_si1_rest_oct,                         /* [3] 10.5.2.32 SI1 Rest Octets                        */
/* [3] 10.5.2.33 SI 2bis Rest Octets */
    de_rr_si2ter_rest_oct,                      /* [3] 10.5.2.33a SI 2ter Rest Octets                   */
    de_rr_si2quater_rest_oct,                   /* [3] 10.5.2.33b SI 2quater Rest Octets                */
    de_rr_si3_rest_oct,                         /* [3] 10.5.2.34 SI3 Rest Octets                        */
    de_rr_si4_rest_oct,                         /* [3] 10.5.2.35 SI4 Rest Octets                        */
    de_rr_si6_rest_oct,                         /* [3] 10.5.2.35b SI6 Rest Octets                       */
/* [3] 10.5.2.36 SI 7 Rest Octets
 * [3] 10.5.2.37 SI 8 Rest Octets
 * [3] 10.5.2.37a SI 9 Rest Octets
 */
    de_rr_si13_rest_oct,                        /* [3] 10.5.2.37a SI13 Rest Octets                      */
/* [3] 10.5.2.37c (void)
 * [3] 10.5.2.37d (void)
 * [3] 10.5.2.37e SI 16 Rest Octets
 * [3] 10.5.2.37f SI 17 Rest Octets
 * [3] 10.5.2.37g SI 19 Rest Octets
 * [3] 10.5.2.37h SI 18 Rest Octets
 * [3] 10.5.2.37i SI 20 Rest Octets */
    de_rr_starting_time,                        /* [3] 10.5.2.38 Starting Time                          */
    de_rr_timing_adv,                           /* [3] 10.5.2.40 Timing Advance                         */
    de_rr_time_diff,                            /* [3] 10.5.2.41 Time Difference                        */
    de_rr_tlli,                                 /* [3] 10.5.2.41a TLLI                                  */
    de_rr_tmsi_ptmsi,                           /* [3] 10.5.2.42 TMSI/P-TMSI                            */
    de_rr_vgcs_tar_mode_ind,                    /* [3] 10.5.2.42a VGCS target mode Indication           */
    /* Pos 40 */
    de_rr_vgcs_cip_par,                         /* [3] 10.5.2.42b       VGCS Ciphering Parameters       */
    de_rr_wait_ind,                             /* [3] 10.5.2.43 Wait Indication                        */
/* [3] 10.5.2.44 SI10 rest octets $(ASCI)$ */
    de_rr_ext_meas_result,                      /* [3] 10.5.2.45 Extended Measurement Results           */
    de_rr_ext_meas_freq_list,                   /* [3] 10.5.2.46 Extended Measurement Frequency List    */
    de_rr_sus_cau,                              /* [3] 10.5.2.47 Suspension Cause                       */
    de_rr_apdu_id,                              /* [3] 10.5.2.48 APDU ID                                */
    de_rr_apdu_flags,                           /* [3] 10.5.2.49 APDU Flags                             */
    de_rr_apdu_data,                            /* [3] 10.5.2.50 APDU Data */
    de_rr_ho_to_utran_cmd,                      /* [3] 10.5.2.51 Handover To UTRAN Command              */
/* [3] 10.5.2.52 Handover To cdma2000 Command
 * [3] 10.5.2.53 (void)
 * [3] 10.5.2.54 (void)
 * [3] 10.5.2.55 (void)
 * [3] 10.5.2.56 3G Target Cell
 * 10.5.2.57 Service Support */
    de_rr_serv_sup,                             /* 10.5.2.57            Service Support                 */
/*
 * 10.5.2.58 MBMS p-t-m Channel Description
 */
    de_rr_ded_serv_inf,                         /* [3] 10.5.2.59        Dedicated Service Information   */
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
 */
    de_rr_carrier_ind,                          /* 10.5.2.69 Carrier Indication                         */
    NULL,       /* NONE */
};

/* MESSAGE FUNCTIONS */

/*
 * 9.1.1 Additional Assignment
 */
static void
dtap_rr_add_ass(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Channel Description  10.5.2.5  M V 3 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, NULL);

    /* Mobile Allocation  10.5.2.21  C TLV 3-10 */
    ELEM_OPT_TLV(0x72, GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, NULL);

    /* Starting Time  10.5.2.38  O TV 3 */
    ELEM_OPT_TV(0x7c, GSM_A_PDU_TYPE_RR, DE_RR_STARTING_TIME, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 9.1.2 Assignment command
 */
static void
dtap_rr_ass_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Channel Description 2                    10.5.2.5a       M V 3 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC2, " - Description of the First Channel, after time");

    /* Power Command                            10.5.2.28       M V 1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_POW_CMD, NULL);

    /* 05 Frequency List                        10.5.2.13       C TLV 4-132 */
    ELEM_OPT_TLV(0x05, GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, " - Frequency List, after time");

    /* 62 Cell Channel Description              10.5.2.1b       O TV 17 */
    ELEM_OPT_TV(0x62, GSM_A_PDU_TYPE_RR, DE_RR_CELL_CH_DSC, NULL);

    /* 10 Multislot Allocation                  10.5.2.21b      C TLV 3-12 */
    ELEM_OPT_TLV(0x10,GSM_A_PDU_TYPE_RR, DE_RR_MULT_ALL, " - Description of the multislot configuration");

    /* 63 Channel Mode                          10.5.2.6        O TV 2 */
    ELEM_OPT_TV(0x63,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of the First Channel(Channel Set 1)");

    /* 11 Channel Mode                          10.5.2.6        O TV 2 */
    ELEM_OPT_TV(0x11,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 2");

    /* 13 Channel Mode                          10.5.2.6        O TV 2 */
    ELEM_OPT_TV(0x13,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 3");

    /* 14 Channel Mode                          10.5.2.6        O TV 2 */
    ELEM_OPT_TV(0x14,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 4");

    /* 15 Channel Mode                          10.5.2.6        O TV 2 */
    ELEM_OPT_TV(0x15,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 5");

    /* 16 Channel Mode                          10.5.2.6        O TV 2 */
    ELEM_OPT_TV(0x16,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 6");

    /* 17 Channel Mode                          10.5.2.6        O TV 2 */
    ELEM_OPT_TV(0x17,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 7");

    /* 18 Channel Mode                          10.5.2.6        O TV 2 */
    ELEM_OPT_TV(0x18,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 8");

    /* 64 Channel Description           10.5.2.5        O TV 4 */
    ELEM_OPT_TV(0x64,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, "Description of the Second Channel, after time");

    /* 66  Channel Mode 2                       10.5.2.7        O TV 2 */
    ELEM_OPT_TV(0x66,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE2, " - Mode of the Second Channel");

    /* 72 Mobile Allocation                     10.5.2.21       C TLV 3-10 */
    ELEM_OPT_TLV(0x72,GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, " - Mobile Allocation, after time");

    /* 7C Starting Time                         10.5.2.38       O TV 3 */
    ELEM_OPT_TV(0x7C,GSM_A_PDU_TYPE_RR, DE_RR_STARTING_TIME, NULL);

    /* 19 Frequency List                        10.5.2.13       C TLV 4-132 */
    ELEM_OPT_TLV(0x19, GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, " - Frequency List, before time");

    /* 1C Channel Description 2                 10.5.2.5a       O TV 4 */
    ELEM_OPT_TV(0x1c,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC2, " - Description of the First Channel, before time");

    /* 1D Channel Description                   10.5.2.5        O TV 4 */
    ELEM_OPT_TV(0x1d,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, " - Description of the Second Channel, before time");

    /* 1E Frequency channel sequence            10.5.2.12  C TV 10 */
    ELEM_OPT_TV(0x1e,GSM_A_PDU_TYPE_RR, DE_RR_FREQ_CH_SEQ, " - Frequency channel sequence before time");

    /* 21 Mobile Allocation                     10.5.2.21       C TLV 3-10 */
    ELEM_OPT_TLV(0x21,GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, " - Mobile Allocation, before time");

    /* 9- Cipher Mode Setting                   10.5.2.9        O TV 1 */
    ELEM_OPT_TV_SHORT(0x90,GSM_A_PDU_TYPE_RR, DE_RR_CIP_MODE_SET, NULL);
    /* 01 VGCS target mode Indication VGCS target mode Indication 10.5.2.42a O TLV 3 */
    ELEM_OPT_TLV(0x01,GSM_A_PDU_TYPE_RR, DE_RR_VGCS_TAR_MODE_IND, NULL);

    /* 03 Multi-Rate configuration,     MultiRate configuration 10.5.2.21aa     O TLV 4-8 */
    ELEM_OPT_TLV(0x03,GSM_A_PDU_TYPE_RR, DE_RR_MULTIRATE_CONF, NULL);

    /* 04 VGCS Ciphering Parameters VGCS Ciphering Parameters 10.5.2.42b O TLV 3-15     */
    ELEM_OPT_TLV(0x04,GSM_A_PDU_TYPE_RR, DE_RR_VGCS_CIP_PAR, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.3 Assignment complete
 */
static void
dtap_rr_ass_comp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* RR Cause RR Cause 10.5.2.31 M V 1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.4 Assignment failure
 */
static void
dtap_rr_ass_fail(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* RR Cause RR Cause 10.5.2.31 M V 1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.5 Channel Mode Modify
 */
static void
dtap_rr_ch_mode_mod(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Channel Description 2    10.5.2.5a       M V 3 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC2, NULL);

    /* Channel Mode             10.5.2.6        M V 1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, NULL);

    /* 01 VGCS target mode Indication VGCS target mode Indication 10.5.2.42a O TLV 3 */
    ELEM_OPT_TLV(0x01,GSM_A_PDU_TYPE_RR, DE_RR_VGCS_TAR_MODE_IND, NULL);

    /* 03 Multi-Rate configuration,     MultiRate configuration 10.5.2.21aa     O TLV 4-8 */
    ELEM_OPT_TLV(0x03,GSM_A_PDU_TYPE_RR, DE_RR_MULTIRATE_CONF, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.6 Channel Mode Modify Acknowledge
 */
static void
dtap_rr_ch_mode_mod_ack(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Channel Description 2    10.5.2.5a       M V 3 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC2, NULL);

    /* Channel Mode             10.5.2.6        M V 1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.7 Channel Release
 */
static void
dtap_rr_ch_rel(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* RR Cause RR Cause 10.5.2.31 M V 1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE, NULL);

    /* 73 BA Range BA Range 10.5.2.1a O TLV 6-7 */
    ELEM_OPT_TLV(0x73, GSM_A_PDU_TYPE_RR, DE_RR_BA_RANGE, NULL);

    /* 74 Group Channel Description Group Channel Description 10.5.2.14b O TLV 5-13 */
    /* ELEM_OPT_TLV(0x74, GSM_A_PDU_TYPE_RR, DE_GRP_CH_DESC, NULL); */

    /* 8x Group Cipher Key Number Group Cipher Key Number 10.5.1.10 C TV 1 */
    /* ELEM_OPT_TV_SHORT(0x80, GSM_A_PDU_TYPE_RR, DE_GRP_CIP_KEY_NUM, NULL); */

    /* Cx GPRS Resumption GPRS Resumption 10.5.2.14c O TV 1 */
    ELEM_OPT_TV_SHORT(0xC0, GSM_A_PDU_TYPE_RR, DE_RR_GPRS_RESUMPTION, NULL);

    /* 75 BA List Pref BA List Pref 10.5.2.1c O TLV 3-? */
    ELEM_OPT_TLV(0x75, GSM_A_PDU_TYPE_RR, DE_RR_BA_LIST_PREF, NULL);

    /* 76 UTRAN Freq List 10.5.2.1d O TLV 3-? */
    ELEM_OPT_TLV(0x76, GSM_A_PDU_TYPE_RR, DE_RR_UTRAN_FREQ_LIST, NULL);

    /* 62 Cell Channel Description Cell Channel Description 10.5.2.1b O TV 17 */
    ELEM_OPT_TV(0x62, GSM_A_PDU_TYPE_RR, DE_RR_CELL_CH_DSC, NULL);

    /* 62 Cell selection indicator after release of all TCH and SDCCH 10.5.2.1e O TLV 4-? */
    ELEM_OPT_TLV(0x77, GSM_A_PDU_TYPE_RR, DE_RR_CELL_SELECT_INDIC, NULL);

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
dtap_rr_cip_mode_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Ciphering Mode Setting           10.5.2.9        M V 0.5 */
    /* Cipher Response                  10.5.2.10       M V 0.5 */
    ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_RR, DE_RR_CIP_MODE_SET,
                       GSM_A_PDU_TYPE_RR, DE_RR_CIP_MODE_RESP);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

}
/*
 * 9.1.10 Ciphering Mode Complete
 */
void
dtap_rr_cip_mode_cpte(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Mobile Equipment Identity                10.5.1.4        O TLV */
    ELEM_OPT_TLV(0x17, GSM_A_PDU_TYPE_COMMON, DE_MID, "Mobile Equipment Identity");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.11 Classmark change
 */
static void
dtap_rr_mm_cm_change(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Mobile Station Classmark 2               10.5.1.6        M LV 4 */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, NULL);
    /* 20 Mobile Station Classmark 3            10.5.1.7        C TLV 3-34 */
    ELEM_OPT_TLV(0x20, GSM_A_PDU_TYPE_COMMON, DE_MS_CM_3, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.11 UTRAN Classmark Change
 */
static void
dtap_rr_utran_classmark_change(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* UTRAN Classmark          10.5.2.7a       M LV 2-? */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_UTRAN_CM, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 9.1.12 Classmark enquiry
 */
static void
dtap_rr_cm_enq(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 10 Classmark Enquiry Mask        10.5.2.7c       O TLV 3 */
    ELEM_OPT_TLV(0x10, GSM_A_PDU_TYPE_RR, DE_RR_CM_ENQ_MASK, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.12b Configuration change command
 */
static void
dtap_rr_conf_change_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Multislot Allocation  10.5.2.21b  M LV 2-11 */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_MULT_ALL, NULL);

    /* Channel Mode  10.5.2.6  O TV 2 */
    ELEM_OPT_TV(0x63,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 1");

    /* Channel Mode  10.5.2.6  O TV 2 */
    ELEM_OPT_TV(0x11,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 2");

    /* Channel Mode  10.5.2.6  O TV 2 */
    ELEM_OPT_TV(0x13,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 3");

    /* Channel Mode  10.5.2.6  O TV 2 */
    ELEM_OPT_TV(0x14,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 4");

    /* Channel Mode  10.5.2.6  O TV 2 */
    ELEM_OPT_TV(0x15,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 5");

    /* Channel Mode  10.5.2.6  O TV 2 */
    ELEM_OPT_TV(0x16,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 6");

    /* Channel Mode  10.5.2.6  O TV 2 */
    ELEM_OPT_TV(0x17,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 7");

    /* Channel Mode  10.5.2.6  O TV 2 */
    ELEM_OPT_TV(0x18,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, " - Mode of Channel Set 8");

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);
}

/*
 * 9.1.12c      Configuration change acknowledge
 */
/* empty message */

/*
 * 9.1.12d      Configuration change reject
 */
static void
dtap_rr_conf_change_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* RR Cause  10.5.2.31  M V 1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 9.1.12e DTM Assignment Command
 */
static void
dtap_rr_dtm_ass_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* CS Power Command 10.5.2.28 M V 1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_POW_CMD, NULL);

    /* Description of the CS Channel 10.5.2.5 M V 3 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, NULL);

    /* GPRS broadcast information 10.5.2.14d M LV 7 - n */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_GPRS_BROADCAST_INFORMATION, NULL);

    /* 10 Cell Channel Description 10.5.2.1b O TV 17 */
    ELEM_OPT_TV(0x10, GSM_A_PDU_TYPE_RR, DE_RR_CELL_CH_DSC, NULL);

    /* 11 Channel mode Channel mode 10.5.2.6 O TV 2 */
    ELEM_OPT_TV(0x11,GSM_A_PDU_TYPE_RR, DE_RR_CH_MODE, NULL);
    /* 12 Frequency List Frequency List 10.5.2.13 C TLV 4 - 132 */
    ELEM_OPT_TLV(0x12, GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, NULL);
    /* 13 Mobile Allocation Mobile Allocation 10.5.2.21 C TLV 3 - 10 */
    ELEM_OPT_TLV(0x13, GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, NULL);

    /* 15 Description of the Uplink Packet Channel Assignment RR Packet Uplink Assignment 10.5.2.25c O TLV 3 - n */
    ELEM_OPT_TLV(0x15, GSM_A_PDU_TYPE_RR, DE_RR_PKT_UL_ASS, NULL);

    /* 16 Description of the Downlink Packet Channel Assignment RR Packet Downlink Assignment 10.5.2.25d O TLV 3 - n */
    ELEM_OPT_TLV(0x16, GSM_A_PDU_TYPE_RR, DE_RR_PKT_DL_ASS, NULL);

    /* 17 Multi-Rate configuration MultiRate configuration 10.5.2.21aa O TLV 4-8  */
    ELEM_OPT_TLV(0x17,GSM_A_PDU_TYPE_RR, DE_RR_MULTIRATE_CONF, NULL);

    /* 9- Ciphering Mode Setting Ciphering Mode Setting 10.5.2.9 O TV 1 */
    ELEM_OPT_TV_SHORT(0x90,GSM_A_PDU_TYPE_RR, DE_RR_CIP_MODE_SET, NULL);

    /* 18 Mobile Allocation C2 Mobile Allocation 10.5.2.21 C TLV 3 - 10 */
    ELEM_OPT_TLV(0x18, GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, " - C2");

    /* 19 Frequency List C2 Frequency List 10.5.2.13 C TLV 4 - 132 */
    ELEM_OPT_TLV(0x19, GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, " - C2");

    /* 20 Description of the Downlink Packet Channel Assignment Type 2 RR Packet Downlink Assignment Type 2 10.5.2.25e C TLV 3 n */
    ELEM_OPT_TLV(0x20, GSM_A_PDU_TYPE_RR, DE_RR_PKT_DL_ASS_TYPE2, NULL);

    /* 21 Channel Description C2 Channel Description 3 10.5.2.5c O TV 3 */
    ELEM_OPT_TV(0x21,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC3, " - Channel Description C2");

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 9.1.12f DTM Assignment Failure
 */
static void
dtap_rr_dtm_ass_fail(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* RR Cause RR Cause 10.5.2.31 M V 1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);
}

/*
 * 9.1.12g DTM Information
 */
static void
dtap_rr_dtm_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Routeing Area Identification 10.5.5.15 M V 6 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAI, NULL);

    /* DTM Information Details 10.5.2.11a M LV 4-n */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_DTM_INFO_DETAILS, NULL);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);
}

/*
 * 9.1.12h DTM Reject
 */
static void
dtap_rr_dtm_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Wait indication 10.5.2.43 M V 1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_WAIT_IND, " - DTM Wait Indication");

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);
}

/*
 * 9.1.12i DTM Request
 */
static void
dtap_rr_dtm_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* TLLI 10.5.2.41a M V 4 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TLLI, NULL);

    /* Channel Request Description 2 M LV 5-n */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_CHNL_REQ_DESC2, NULL);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);
}

/*
 * 9.1.13 Frequency Redefinition
 */
static void
dtap_rr_freq_redef(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Channel Description  10.5.2.5  M V 3 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, NULL);

    /* Mobile Allocation  10.5.2.21  M LV 1-9 */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, NULL);

    /* Starting Time  10.5.2.38  M V 2 */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_STARTING_TIME, NULL);

    /* Cell Channel Description  10.5.2.1b  O TV 17 */
    ELEM_OPT_TV(0x62,GSM_A_PDU_TYPE_RR, DE_RR_CELL_CH_DSC, NULL);

    /* Carrier Indication  10.5.2.69  O TV 1 */
    ELEM_OPT_TV_SHORT(0x90,GSM_A_PDU_TYPE_RR, DE_RR_CARRIER_IND,NULL);

    /* Mobile Allocation  10.5.2.21  O TLV 1-9 */
    ELEM_OPT_TLV(0x11, GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, " - Mobile Allocation C2");

    /* Channel Description 3  10.5.2.5c  O TV 3 */
    ELEM_OPT_TV(0x12,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC3, " - Channel Description C2");

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);
}

/*
 * 9.1.13b GPRS suspension request
 */
static void
dtap_rr_gprs_sus_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* TLLI                                                             10.5.2.41a      M V 4 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TLLI, NULL);

    /* Routeing Area Identification                     10.5.5.15       M V 6 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_GM, DE_RAI, NULL);
    /* Suspension cause                                 10.5.2.47       M V 1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SUS_CAU, NULL);

    /* 01 Service Support                               10.5.2.57       O TV 2 */
    ELEM_OPT_TV_SHORT(0x01,GSM_A_PDU_TYPE_RR, DE_RR_SERV_SUP,NULL);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

}

/*
 * 9.1.14 Handover Access
 */
/* This message does NOT follow the basic format, and is only found on DCH during initial handover access */

/* 3GPP TS 24.008 version 4.7.0 Release 4
 * [3] 9.1.15
 */
void
dtap_rr_ho_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Mandatory Elements
     * Cell description 10.5.2.2
     */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CELL_DSC, NULL);

    /* Description of the first channel,after time
     * Channel Description 2 10.5.2.5a
     */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC2, " - Description of the first channel, after time");

    /* Handover Reference 10.5.2.15 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_HO_REF, NULL);

    /* Power Command and Access type 10.5.2.28a */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_POW_CMD_AND_ACC_TYPE, NULL);

    /* optional elements */

    /* Synchronization Indication 10.5.2.39 */
    ELEM_OPT_TV_SHORT(0xD0,GSM_A_PDU_TYPE_RR, DE_RR_SYNC_IND,NULL);

    /* Frequency Short List 10.5.2.14 */
    ELEM_OPT_TV(0x02,GSM_A_PDU_TYPE_RR, DE_RR_FREQ_SHORT_LIST," - Frequency Short List, after time");

    /* Frequency List 10.5.2.13 */
    ELEM_OPT_TLV(0x05, GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, " - Frequency List, after time");

    /* Cell Channel Description 10.5.2.1b */
    ELEM_OPT_TV(0x62,GSM_A_PDU_TYPE_RR, DE_RR_CELL_CH_DSC, NULL);

    /* Multislot Allocation 10.5.2.21b */
    ELEM_OPT_TLV(0x10,GSM_A_PDU_TYPE_RR, DE_RR_MULT_ALL, NULL);

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
    ELEM_OPT_TV(0x7C,GSM_A_PDU_TYPE_RR, DE_RR_STARTING_TIME, NULL);

    /* Real Time Difference, Time Difference 10.5.2.41 */
    ELEM_OPT_TV(0x7B,GSM_A_PDU_TYPE_RR, DE_RR_TIME_DIFF, " - Real Time Difference");

    /* Timing Advance, Timing Advance 10.5.2.40 */
    ELEM_OPT_TV(0x7D,GSM_A_PDU_TYPE_RR, DE_RR_TIMING_ADV, NULL);

    /* Frequency Short List, before time, Frequency Short List 10.5.2.14 */
    ELEM_OPT_TV(0x12,GSM_A_PDU_TYPE_RR, DE_RR_FREQ_SHORT_LIST, " - Frequency Short List, before time");

    /* Frequency List, before time,     Frequency List 10.5.2.13 */
    ELEM_OPT_TLV(0x19,GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, " - Frequency List, before time");

    /* Description of the First Channel, before time,   Channel Description 2 10.5.2.5a*/
    ELEM_OPT_TV(0x1c,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC2, " - Description of the First Channel, before time");

    /* Description of the Second Channel, before time,  Channel Description 10.5.2.5*/
    ELEM_OPT_TV(0x1d,GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, " - Description of the Second Channel, before time");

    /* Frequency channel sequence before time,  Frequency channel sequence 10.5.2.12*/
    ELEM_OPT_TV(0x1e,GSM_A_PDU_TYPE_RR, DE_RR_FREQ_CH_SEQ, " - Frequency channel sequence before time");

    /* Mobile Allocation, before time,  Mobile Allocation 10.5.2.21 */
    ELEM_OPT_TLV(0x21,GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, " - Mobile Allocation, before time");

    /* Cipher Mode Setting,     Cipher Mode Setting 10.5.2.9 */
    ELEM_OPT_TV_SHORT(0x90,GSM_A_PDU_TYPE_RR, DE_RR_CIP_MODE_SET, NULL);

    /* VGCS target mode Indication,     VGCS target mode Indication 10.5.2.42a */
    ELEM_OPT_TLV(0x01,GSM_A_PDU_TYPE_RR, DE_RR_VGCS_TAR_MODE_IND, NULL);

    /* Multi-Rate configuration,        MultiRate configuration 10.5.2.21a */
    ELEM_OPT_TLV(0x03,GSM_A_PDU_TYPE_RR, DE_RR_MULTIRATE_CONF, NULL);

    /* Dynamic ARFCN Mapping,   Dynamic ARFCN Mapping 10.5.2.11b */
    ELEM_OPT_TLV(0x76,GSM_A_PDU_TYPE_RR, DE_RR_DYN_ARFCN_MAP, NULL);

    /* VGCS Ciphering Parameters,       VGCS Ciphering Parameters 10.5.2.42b */
    ELEM_OPT_TLV(0x04,GSM_A_PDU_TYPE_RR, DE_RR_VGCS_CIP_PAR, NULL);

    /* Dedicated Service Information,   Dedicated Service Information 10.5.2.59 */
    ELEM_OPT_TV(0x51,GSM_A_PDU_TYPE_RR, DE_RR_DED_SERV_INF, NULL);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

}

/*
 * 9.1.15a Inter System To UTRAN Handover Command
 */
static void
dtap_rr_inter_syst_to_utran_ho_cmd(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* UTRAN Classmark          10.5.2.51       M LV 2-? */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_HO_TO_UTRAN_CMD, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/* 3GPP TS 24.008 version 4.7.0 Release 4
 * [3] 9.1.16
 */
static void
dtap_rr_ho_cpte(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* RR Cause RR Cause 10.5.2.31 M V 1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE, NULL);

    /* 77 Mobile Observed Time Difference       Mobile Time Difference 10.5.2.21a */
    ELEM_OPT_TLV(0x77,GSM_A_PDU_TYPE_RR, DE_RR_MOB_TIME_DIFF, " - Mobile Observed Time Difference");

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

}

/*
 * 9.1.17 Handover failure
 */
static void
dtap_rr_ho_fail(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* RR Cause RR Cause 10.5.2.31 M V 1 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.1.18 Immediate assignment See 3GPP TS 44.018
 */
static void
dtap_rr_imm_ass(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;
    guint8  oct;

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

    /* Page Mode                        10.5.2.26       M V 1/2 */
    /* Dedicated mode or TBF            10.5.2.25b      M V 1/2 */
    ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_RR, DE_RR_PAGE_MODE,
                       GSM_A_PDU_TYPE_RR, DE_RR_DED_MOD_OR_TBF);

    if((oct&0x10) == 0){
        /* Channel Description                  10.5.2.5        C V 3m */
        ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, NULL);
    }else{
        /* Packet Channel Description   10.5.2.25a      C V 3
         * If the Dedicated mode or TBF IE indicates that the message assigns a Temporary Block Flow (TBF),
         * the mobile station shall consider this information element present in the message.
         * If the Dedicated mode or TBF IE indicates that this message is the first of two in a two-message
         * assignment of an uplink or downlink TBF, the mobile station shall ignore the contents
         * of this information element and regard it as an unnecessary IE.
         */
        if((oct&0x04) == 0){
            ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_PACKET_CH_DESC, NULL);
        }
    }
    /* Request Reference                        10.5.2.30       M V 3   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF, NULL);

    /* Timing Advance                           10.5.2.40       M V 1   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TIMING_ADV, NULL);
    /* Mobile Allocation                        10.5.2.21       M LV 1-9 */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, NULL);
    /* 7C Starting Time                         10.5.2.38       O TV 3  */
    ELEM_OPT_TV(0x7C,GSM_A_PDU_TYPE_RR, DE_RR_STARTING_TIME, NULL);
    /* IA Rest Octets                           10.5.2.16       M V 0-11 */
    if(tvb_length_remaining(tvb,curr_offset) > 0)
        ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_IA_REST_OCT, NULL);

}

/*
 * 9.1.19 Immediate assignment extended
 */
static void
dtap_rr_imm_ass_ext(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Page Mode                                                10.5.2.26       M V 1/2 */
    /* Spare Half Octet                                         10.5.1.8        M V 1/2 */
    ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_RR, DE_RR_PAGE_MODE,
                       GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE);
    /* Channel Description 1    Channel Description             10.5.2.5        M V 3 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, " - Channel Description 1");
    /* Request Reference 1      Request Reference               10.5.2.30       M V 3   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF, " - Request Reference 1");
    /* Timing Advance 1 Timing Advance                          10.5.2.40       M V 1   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TIMING_ADV, " - Timing Advance 1");
    /* Channel Description 2    Channel Description             10.5.2.5        M V 3 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, " - Channel Description 2");
    /* Request Reference 2      Request Reference               10.5.2.30       M V 3   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF, " - Request Reference 2");
    /* Timing Advance 2 Timing Advance                          10.5.2.40       M V 1   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TIMING_ADV, " - Timing Advance 2");
    /* Mobile Allocation                                        10.5.2.21       M LV 1-9 */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, NULL);
    /* 7C Starting Time                                         10.5.2.38       O TV 3  */
    ELEM_OPT_TV(0x7C,GSM_A_PDU_TYPE_RR, DE_RR_STARTING_TIME, NULL);
    /* IAX Rest Octets                                          10.5.2.18       M V 0-4 */
    if(tvb_length_remaining(tvb,curr_offset) > 0)
        ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_IAX_REST_OCT, NULL);

}

/*
 * 9.1.20 Immediate assignment reject
 */
static void
dtap_rr_imm_ass_rej(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Page Mode                                        10.5.2.26       M V 1/2 */
    /* Spare Half Octet         10.5.1.8        M V 1/2 */
    ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_RR, DE_RR_PAGE_MODE,
                       GSM_A_PDU_TYPE_COMMON, DE_SPARE_NIBBLE);
    /* Request Reference 1      Request Reference               10.5.2.30       M V 3   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF, " - Request Reference 1");
    /* Wait Indication 1        Wait Indication                 10.5.2.43       M V 1   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_WAIT_IND, " - Wait Indication 1");
    /* Request Reference 2      Request Reference               10.5.2.30       M V 3   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF, " - Request Reference 2");
    /* Wait Indication 2        Wait Indication                 10.5.2.43       M V 1   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_WAIT_IND, " - Wait Indication 2");
    /* Request Reference 3      Request Reference               10.5.2.30       M V 3   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF, " - Request Reference 3");
    /* Wait Indication 3        Wait Indication                 10.5.2.43       M V 1   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_WAIT_IND, " - Wait Indication 3");
    /* Request Reference 4      Request Reference               10.5.2.30       M V 3   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_REQ_REF, " - Request Reference 4");
    /* Wait Indication 4        Wait Indication                 10.5.2.43       M V 1   */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_WAIT_IND, " - Wait Indication 4");
    /* IAR Rest Octets                          10.5.2.19       M V 3 */
    if(tvb_length_remaining(tvb,curr_offset) > 0)
        ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_IAR_REST_OCT, NULL);

}

/*
 * 9.1.21 Measurement report
 */
static void
dtap_rr_meas_rep(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Measurement Results 10.5.2.20 M V 16 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_MEAS_RES, NULL);
}

/*
 * 9.1.21f Packet Assignment
 */
static void
dtap_rr_pkt_assign(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* GPRS broadcast information 10.5.2.14d M LV 7-n */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_GPRS_BROADCAST_INFORMATION, NULL);

    /* 0x22 RR Packet Uplink Assignment 10.5.2.25c O TLV 3-n */
    ELEM_OPT_TLV(0x22, GSM_A_PDU_TYPE_RR, DE_RR_PKT_UL_ASS, NULL);

    /* 0x23 RR Packet Downlink Assignment 10.5.2.25d O TLV 3-n */
    ELEM_OPT_TLV(0x23, GSM_A_PDU_TYPE_RR, DE_RR_PKT_DL_ASS, NULL);

    /* 0x12 Frequency List 10.5.2.13 C TLV 4-132 */
    ELEM_OPT_TLV(0x12, GSM_A_PDU_TYPE_RR, DE_RR_FREQ_LIST, " - Frequency List C2");

    /* 0x13 Mobile Allocation 10.5.2.21 C TLV 3-10 */
    ELEM_OPT_TLV(0x13, GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, " - Mobile Allocation C2");

    /* 0x14 Channel Description 3 10.5.2.5c O TV 3 */
    ELEM_OPT_TV(0x14, GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC3, " - Channel Description C2");

    /* 0x24 RR Packet Downlink Assignment Type 2 10.5.2.25e C TLV 3-n */
    ELEM_OPT_TLV(0x24, GSM_A_PDU_TYPE_RR, DE_RR_PKT_DL_ASS_TYPE2, NULL);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);
}

/*
 * 9.1.21g Packet Notification
 */
static void
dtap_rr_pkt_notif(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* 0x10 P-TMSI 10.5.2.42 C TV 5 */
    ELEM_OPT_TV(0x10, GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI, " - Packet TMSI");

    /* 0x11 Mobile Identity 10.5.1.4 C TLV 3-11 */
    ELEM_OPT_TLV(0x11, GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

    EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);
}

/*
 * 9.1.22 Paging Request Type 1
 */
static void
dtap_rr_paging_req_type_1(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* RR Page Mode 10.5.2.26 M V 1/2 */
    /* RR Channel Needed 10.5.2.8 M V 1/2 */
    ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_RR, DE_RR_PAGE_MODE,
                       GSM_A_PDU_TYPE_RR, DE_RR_CHNL_NEEDED);

    /* RR Mobile Identity 10.5.1.4 M LV 2-9 */
    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, " - Mobile Identity 1");

    /* RR Mobile Identity 10.5.1.4 O TLV 3-10 */
    ELEM_OPT_TLV(0x17, GSM_A_PDU_TYPE_COMMON, DE_MID, " - Mobile Identity 2");

    /* RR P1 Rest Octets 10.5.2.23 M V 0-17 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_P1_REST_OCT, NULL);

}

/*
 * 9.1.23 Paging Request Type 2
 */
static void
dtap_rr_paging_req_type_2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* RR Page Mode 10.5.2.26 M V 1/2 */
    /* RR Channel Needed 10.5.2.8 M V 1/2 */
    ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_RR, DE_RR_PAGE_MODE,
                       GSM_A_PDU_TYPE_RR, DE_RR_CHNL_NEEDED);

    /* RR TMSI/P-TMSI 10.5.2.42 M V 4 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI, " - Mobile Identity 1");

    /* RR TMSI/P-TMSI 10.5.2.42 M V 4 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI, " - Mobile Identity 2");

    /* RR Mobile Identity 10.5.1.4 O TLV 3-10 */
    ELEM_OPT_TLV(0x17, GSM_A_PDU_TYPE_COMMON, DE_MID, " - Mobile Identity 3");

    /* RR P2 Rest Octets 10.5.2.24 M V 1-11 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_P2_REST_OCT, NULL);

}

/*
 * 9.1.24 Paging Request Type 3
 */
static void
dtap_rr_paging_req_type_3(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* RR Page Mode 10.5.2.26 M V 1/2 */
    /* RR Channel Needed 10.5.2.8 M V 1/2 */
    ELEM_MAND_VV_SHORT(GSM_A_PDU_TYPE_RR, DE_RR_PAGE_MODE,
                       GSM_A_PDU_TYPE_RR, DE_RR_CHNL_NEEDED);

    /* RR TMSI/P-TMSI 10.5.2.42 M V 4 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI, " - Mobile Identity 1");

    /* RR TMSI/P-TMSI 10.5.2.42 M V 4 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI, " - Mobile Identity 2");

    /* RR TMSI/P-TMSI 10.5.2.42 M V 4 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI, " - Mobile Identity 3");

    /* RR TMSI/P-TMSI 10.5.2.42 M V 4 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TMSI_PTMSI, " - Mobile Identity 4");

    /* RR P3 Rest Octets 10.5.2.25 M V 3 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_P3_REST_OCT, NULL);

}

/*
 * [4] 9.1.25 Paging response
 */
static void
dtap_rr_paging_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32     curr_offset;
    guint32     consumed;
    guint       curr_len;
    guint8      oct;
    proto_tree *subtree;
    proto_item *item;

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

    if ((signed)curr_len <= 0) return;

    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MS_CM_2, NULL);

    ELEM_MAND_LV(GSM_A_PDU_TYPE_COMMON, DE_MID, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.1.26 Partial Release
 */
static void
dtap_rr_partial_rel(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Channel Description  10.5.2.5  M V 3 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.1.27 Partial Release Complete
 */
/* empty message */

/*
 * [4] 9.1.28 Physical Information
 */
static void
dtap_rr_phy_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_TIMING_ADV, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.1.29
 */
static void
dtap_rr_rr_status(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CAUSE, NULL);

    EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * [4] 9.1.31
 */
static void
dtap_rr_sys_info_1(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CELL_CH_DSC, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_RACH_CTRL_PARAM, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI1_REST_OCT, NULL);
}

/*
 * [4] 9.1.32
 */
static void
dtap_rr_sys_info_2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC, " - BCCH Frequency List");

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NCC_PERM, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_RACH_CTRL_PARAM, NULL);
}

/*
 * [4] 9.1.33
 */
static void
dtap_rr_sys_info_2bis(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC, " - Extended BCCH Frequency List");

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_RACH_CTRL_PARAM, NULL);
}

/*
 * [4] 9.1.34
 */
static void
dtap_rr_sys_info_2ter(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC2, " - Extended BCCH Frequency List");

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI2TER_REST_OCT, NULL);
}

/*
 * [4] 9.1.34a
 */
static void
dtap_rr_sys_info_2quater(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI2QUATER_REST_OCT, NULL);
}

/*
 * [4] 9.1.35
 */
static void
dtap_rr_sys_info_3(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_CELL_ID, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CTRL_CH_DESC, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CELL_OPT_BCCH, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CELL_SEL_PARAM, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_RACH_CTRL_PARAM, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI3_REST_OCT, NULL);
}

/*
 * [4] 9.1.36
 */
static void
dtap_rr_sys_info_4(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CELL_SEL_PARAM, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_RACH_CTRL_PARAM, NULL);

    ELEM_OPT_TV(0x64, GSM_A_PDU_TYPE_RR, DE_RR_CH_DSC, " - CBCH");

    ELEM_OPT_TLV(0x72, GSM_A_PDU_TYPE_RR, DE_RR_MOB_ALL, " - CBCH");

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI4_REST_OCT, NULL);
}

/*
 * [4] 9.1.37
 */
static void
dtap_rr_sys_info_5(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC, " - BCCH Frequency List");
}

/*
 * [4] 9.1.38
 */
static void
dtap_rr_sys_info_5bis(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC, " - Extended BCCH Frequency List");
}

/*
 * [4] 9.1.39
 */
static void
dtap_rr_sys_info_5ter(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NEIGH_CELL_DESC2, " - Extended BCCH Frequency List");
}

/*
 * [4] 9.1.40
 */
static void
dtap_rr_sys_info_6(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_CELL_ID, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_COMMON, DE_LAI, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_CELL_OPT_SACCH, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_NCC_PERM, NULL);

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI6_REST_OCT, NULL);
}

/*
 * [4] 9.1.43a
 */
static void
dtap_rr_sys_info_13(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_SI13_REST_OCT, NULL);
}

/*
 * [4] 9.1.51 Extended Measurement Order
 */
static void
dtap_rr_ext_meas_order(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Extended Measurement Frequency List  10.5.2.46  M V 16 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_EXT_MEAS_FREQ_LIST, NULL);
}

/*
 * [4] 9.1.52 Extended Measurement Report
 */
static void
dtap_rr_ext_meas_report(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len = len;

    /* Extended Measurement Result  10.5.2.45  M V 16 */
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_EXT_MEAS_RESULT, NULL);
}

/*
 * 9.1.53 Application Information
 */
static void
dtap_rr_app_inf(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    guint32 curr_offset;
    guint32 consumed;
    guint   curr_len;

    curr_offset = offset;
    curr_len    = len;

    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_APDU_ID, NULL);
    ELEM_MAND_V(GSM_A_PDU_TYPE_RR, DE_RR_APDU_FLAGS, NULL);
    ELEM_MAND_LV(GSM_A_PDU_TYPE_RR, DE_RR_APDU_DATA, NULL);
}

/*
 * [4] 9.1.54 Measurement Information
 */
static const value_string gsm_a_rr_3g_wait_vals[] = {
    { 0, "1 instance that contain 3G Neighbour Cell Description shall be received"},
    { 1, "2 instances that contain 3G Neighbour Cell Description shall be received"},
    { 2, "3 instances that contain 3G Neighbour Cell Description shall be received"},
    { 3, "4 instances that contain 3G Neighbour Cell Description shall be received"},
    { 4, "5 instances that contain 3G Neighbour Cell Description shall be received"},
    { 5, "6 instances that contain 3G Neighbour Cell Description shall be received"},
    { 6, "7 instances that contain 3G Neighbour Cell Description shall be received"},
    { 7, "8 instances that contain 3G Neighbour Cell Description shall be received"},
    { 0, NULL }
};


static void
sacch_rr_meas_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_)
{
    proto_tree *subtree = NULL, *subtree2 = NULL;
    proto_item *item, *item2;
    guint32     curr_offset;
    gint        bit_offset, bit_offset_sav, bit_offset_sav2;
    guint8      value, idx;
    guint8      tvb_len = tvb_length(tvb);
    guint16     bit_len = tvb_len << 3;

    curr_offset = offset;
    bit_offset = curr_offset << 3;

    proto_tree_add_bits_item(tree, hf_gsm_a_rr_ba_ind, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_3g_ba_ind, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_mp_change_mark, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_mi_index, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset += 4;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_mi_count, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    bit_offset += 4;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_pwrc, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_gsm_report_type, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_reporting_rate, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset +=1;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_invalid_bsic_reporting, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset +=1;
    if (gsm_rr_csn_flag(tvb, tree, bit_offset++, "Real Time Difference Description", "Present", "Not Present"))
    { /* Real Time Difference Description */
        bit_offset += de_rr_rtd_desc(tvb, tree, bit_offset, DE_RR_REST_OCTETS_RTD_DESC);
    }
    if (gsm_rr_csn_flag(tvb, tree, bit_offset++, "BSIC Description", "Present", "Not Present"))
    { /* BSIC Description */
        bit_offset += de_rr_bsic_desc(tvb, tree, bit_offset, DE_RR_REST_OCTETS_BSIC_DESC);
    }
    if (gsm_rr_csn_flag(tvb, tree, bit_offset++, "Report Priority Description", "Present", "Not Present"))
    { /* Report Priority Description */
        bit_offset += de_rr_report_priority_desc(tvb, tree, bit_offset, DE_RR_REST_OCTETS_REPORT_PRIO_DESC);
    }
    if (gsm_rr_csn_flag(tvb, tree, bit_offset++, "Measurement Parameters Description", "Present", "Not Present"))
    { /* Measurement Parameters Description */
        bit_offset += de_rr_meas_param_desc(tvb, tree, bit_offset, DE_RR_REST_OCTETS_MEAS_PARAM_DESC);
    }
    if (gsm_rr_csn_flag(tvb, tree, bit_offset++, "future extensions of the 2G parameters", "Present", "Not Present"))
    {  /* used for future extensions of the 2G parameters */
        value = tvb_get_bits8(tvb,bit_offset,8);
        bit_offset += 8 + value + 1;
    }
    if (gsm_rr_csn_flag(tvb, tree, bit_offset++, "3G Neighbour Cell Description", "Present", "Not Present"))
    { /* 3G Neighbour Cell Description */
        bit_offset_sav = bit_offset;
        item = proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_NEIGH_CELL_DESC].strptr);
        subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_NEIGH_CELL_DESC]);
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "3G Wait", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_wait, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
        }
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Index Start 3G", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_index_start_3g, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
            bit_offset += 7;
        }
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Absolute Index Start EMR", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_absolute_index_start_emr, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
            bit_offset += 7;
        }
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "UTRAN FDD Description", "Present", "Not Present"))
        { /* UTRAN FDD Description */
            bit_offset += de_rr_si2quater_meas_info_utran_fdd_desc(tvb, subtree, bit_offset);
        }
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "UTRAN TDD Description", "Present", "Not Present"))
        { /* UTRAN TDD Description */
            bit_offset += de_rr_si2quater_meas_info_utran_tdd_desc(tvb, subtree, bit_offset);
        }
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "CDMA2000 Description", "Present", "Not Present"))
        { /* CDMA2000 Description */
            bit_offset_sav2 = bit_offset;
            item2 = proto_tree_add_text(subtree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_CDMA2000_DESC].strptr);
            subtree2 = proto_item_add_subtree(item2, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_CDMA2000_DESC]);
            bit_offset += 16; /* cdma2000 frequency band + cdma2000 frequency */
            idx = tvb_get_bits8(tvb,bit_offset,5); /* number_cdma2000_cells */
            bit_offset += 5;
            while (idx)
            {
                bit_offset += 9; /* Pilot PN offset */
                if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "additional information for 3X Auxiliary Pilot", "Present", "Not Present"))
                {
                    value = tvb_get_bits8(tvb,bit_offset,3);
                    switch (value)
                    {
                    case 0:
                        bit_offset += 5; /* TD_MODE + TD_POWER_LEVEL */
                        break;
                    case 1:
                        bit_offset += 2; /* QOF */
                        bit_offset += tvb_get_bits8(tvb,bit_offset,3) + 3 + 6; /* WALSH_LEN_A + bit(val(WALSH_LEN_A)+6) */
                        break;
                    case 2:
                        bit_offset += 2; /* QOF */
                        bit_offset += tvb_get_bits8(tvb,bit_offset,3) + 3 + 6; /* WALSH_LEN_B + bit(val(WALSH_LEN_B)+6) */
                        bit_offset += 4; /* AUX_TD_POWER_LEVEL + TD_MODE */
                        break;
                    case 3:
                        bit_offset += 8; /* SR3_PRIM_PILOT + SR3_PILOT_POWER1 + SR3_PILOT_POWER2 */
                        break;
                    case 6:
                        bit_offset += 10; /* SR3_PRIM_PILOT + SR3_PILOT_POWER1 + SR3_PILOT_POWER2 + QOF */
                        bit_offset += tvb_get_bits8(tvb,bit_offset,3) + 3 + 6; /* WALSH_LEN_C + bit(val(WALSH_LEN_C)+6) */
                        if (tvb_get_bits8(tvb,bit_offset,1))
                        {
                            bit_offset += 3; /* 1 + QOF1 */
                            bit_offset += tvb_get_bits8(tvb,bit_offset,3) + 3 + 6; /* WALSH_LENGTH1 + bit(val(WALSH_LENGTH1)+6) */
                        }
                        else
                            bit_offset += 1;
                        if (tvb_get_bits8(tvb,bit_offset,1))
                        {
                            bit_offset += 3; /* 1 + QOF2 */
                            bit_offset += tvb_get_bits8(tvb,bit_offset,3) + 3 + 6; /* WALSH_LENGTH2 + bit(val(WALSH_LENGTH2)+6) */
                        }
                        else
                            bit_offset += 1;
                        break;
                    default:
                        /* decoding sequence is unknown ! */
                        return;
                    }
                }
                idx -= 1;
            }
            proto_tree_add_text(subtree2,tvb, bit_offset_sav2>>3, ((bit_offset-bit_offset_sav2)>>3)+1,"Data(Not decoded)");
            proto_item_set_len(item2, (bit_offset>>3) - (bit_offset_sav>>3)+1);
        }
        proto_item_set_len(item, (bit_offset>>3) - (bit_offset_sav>>3)+1);
    }
    if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "3G Measurement Parameters Description", "Present", "Not Present"))
    { /* 3G Measurement Parameters Description */
        guint8 reporting_quant = 0;
        bit_offset_sav = bit_offset;
        item = proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_3G_MEAS_PARAM_DESC].strptr);
        subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_3G_MEAS_PARAM_DESC]);
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_qsearch_c, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset += 4;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_3g_search_prio, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_fdd_rep_quant, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        reporting_quant = gsm_rr_csn_flag(tvb, subtree, bit_offset++, "3G Reporting Quantity", "Ec/No", "RSCP");
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "FDD Multirat Reporting", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_fdd_multirat_reporting, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset += 2;
        }
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "FDD Reporting Offset", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_fdd_reporting_offset, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
            if (reporting_quant == 0)
            {
              proto_tree_add_bits_item(subtree, hf_gsm_a_rr_fdd_reporting_threshold_rscp, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            }
            else
            {
              proto_tree_add_bits_item(subtree, hf_gsm_a_rr_fdd_reporting_threshold_ecn0, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            }
            bit_offset += 3;
        }
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "TDD Multirat Reporting", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_tdd_multirat_reporting, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset += 2;
        }
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "TDD Reporting Offset", "Present", "Not Present"))
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_rr_tdd_reporting_offset, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset += 3;
            if (reporting_quant == 0)
            {
              proto_tree_add_bits_item(subtree, hf_gsm_a_rr_tdd_reporting_threshold_rscp, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            }
            else
            {
              proto_tree_add_bits_item(subtree, hf_gsm_a_rr_tdd_reporting_threshold_ecn0, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            }
            bit_offset += 3;
        }
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "CDMA2000 Multirat Reporting", "Present", "Not Present"))
            bit_offset += 2; /* CDMA2000 Multirat Reporting */
        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "CDMA2000 Reporting Threshold", "Present", "Not Present"))
            bit_offset += 6; /* CDMA2000 Reporting Offset + CDMA2000 Reporting Threshold */
        proto_item_set_len(item, (bit_offset>>3) - (bit_offset_sav>>3)+1);
    }

    /* Null breakpoint */
    if (bit_len - bit_offset > 0)
    {
        /* There is still room left in the Rest Octets IE */
        if (gsm_rr_csn_HL_flag(tvb, tree, 0, bit_offset++, "Additions in Rel-5", "Present", "Not present"))
        { /* Additions in Rel-5 */
            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "3G Additional Measurement Parameters Description 2", "Present", "Not Present"))
            { /* 3G Additional Measurement Parameters Description 2 */
                bit_offset += de_rr_3g_add_meas_param_desc2(tvb, tree, bit_offset);
            }

            /* Null breakpoint */
            if (bit_len - bit_offset > 0)
            {
                /* There is still room left in the Rest Octets IE */
                if (gsm_rr_csn_HL_flag(tvb, tree, 0, bit_offset++,"Additions in Rel-7", "Present", "Not present"))
                { /* Additions in Rel-7 */
                    if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "700 Reporting", "Present", "Not Present"))
                    {
                        proto_tree_add_bits_item(tree, hf_gsm_a_rr_700_reporting_offset, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                        bit_offset += 3;
                        proto_tree_add_bits_item(tree, hf_gsm_a_rr_700_reporting_threshold, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                        bit_offset += 3;
                    }
                    if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "810 Reporting", "Present", "Not Present"))
                    {
                        proto_tree_add_bits_item(tree, hf_gsm_a_rr_810_reporting_offset, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                        bit_offset += 3;
                        proto_tree_add_bits_item(tree, hf_gsm_a_rr_810_reporting_threshold, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
                        bit_offset += 3;
                    }

                    /* Null breakpoint */
                    if (bit_len - bit_offset > 0)
                    {
                      /* There is still room left in the Rest Octets IE */
                       /* Additions in Rel-8 */
                      if (gsm_rr_csn_HL_flag(tvb, tree, 0, bit_offset++, "Additions in Rel-8", "Present", "Not present"))
                      { /* Additions in Rel-8 */
                        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "3G Supplementary Parameters Description", "Present", "Not Present"))
                        {
                          bit_offset += de_rr_3g_supplementary_param_desc_mi(tvb, tree, bit_offset);
                        }
                        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "E-UTRAN Parameters Description", "Present", "Not Present"))
                        {
                          bit_offset += de_rr_eutran_param_desc_mi(tvb, tree, bit_offset);
                        }
                        if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "E-UTRAN CSG Description", "Present", "Not Present"))
                        {
                          bit_offset += de_rr_eutran_csg_desc_mi(tvb, tree, bit_offset);
                        }
                      }
                    }
                }
            }
        }
    }
    gsm_rr_csn_padding_bits(tree, tvb, bit_offset, tvb_len);
}

static guint32
sacch_rr_eutran_meas_report(tvbuff_t *tvb, proto_tree *tree, guint32 bit_offset, guint len_in_bit _U_)
{
    proto_tree *subtree;
    proto_item *item;
    gint        curr_bit_offset;
    gint8       n_eutran;

    curr_bit_offset = bit_offset;

    item = proto_tree_add_text(tree, tvb, curr_bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_EUTRAN_MEASUREMENT_REPORT].strptr);
    subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_EUTRAN_MEASUREMENT_REPORT]);

    n_eutran = tvb_get_bits8(tvb,curr_bit_offset,2);
    n_eutran += 1;
    proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_mr_n_eutran, tvb, curr_bit_offset, 2, ENC_BIG_ENDIAN);
    curr_bit_offset += 2;

    while ( (n_eutran > 0) && (curr_bit_offset - bit_offset < len_in_bit) )
    {
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_mr_freq_idx, tvb, curr_bit_offset, 3, ENC_BIG_ENDIAN);
        curr_bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_mr_cell_id, tvb, curr_bit_offset, 9, ENC_BIG_ENDIAN);
        curr_bit_offset += 9;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_eutran_mr_rpt_quantity, tvb, curr_bit_offset, 6, ENC_BIG_ENDIAN);
        curr_bit_offset += 6;
        n_eutran -= 1;
    }

    return curr_bit_offset - bit_offset;
}

/*
 * [4] 9.1.55 Enhanced Measurement Information
 */
static const true_false_string gsm_a_rr_bsic_seen_value = {
    "One Cell or more with invalid BSIC and allowed NCC part of BSIC is seen",
    "No cell with invalid BSIC and allowed NCC part of BSIC is seen"
};

static const true_false_string gsm_a_rr_scale_value = {
    "+10 dB",
    "0 dB"
};

static const value_string gsm_a_rr_mean_bep_gmsk_vals[] = {
    {  0, "log10(BEP) > -0.60"},
    {  1, "-0.70 < log10(BEP) < -0.60"},
    {  2, "-0.80 < log10(BEP) < -0.70"},
    {  3, "-0.90 < log10(BEP) < -0.80"},
    {  4, "-1.00 < log10(BEP) < -0.90"},
    {  5, "-1.10 < log10(BEP) < -1.00"},
    {  6, "-1.20 < log10(BEP) < -1.10"},
    {  7, "-1.30 < log10(BEP) < -1.20"},
    {  8, "-1.40 < log10(BEP) < -1.30"},
    {  9, "-1.50 < log10(BEP) < -1.40"},
    { 10, "-1.60 < log10(BEP) < -1.50"},
    { 11, "-1.70 < log10(BEP) < -1.60"},
    { 12, "-1.80 < log10(BEP) < -1.70"},
    { 13, "-1.90 < log10(BEP) < -1.80"},
    { 14, "-2.00 < log10(BEP) < -1.90"},
    { 15, "-2.10 < log10(BEP) < -2.00"},
    { 16, "-2.20 < log10(BEP) < -2.10"},
    { 17, "-2.30 < log10(BEP) < -2.20"},
    { 18, "-2.40 < log10(BEP) < -2.30"},
    { 19, "-2.50 < log10(BEP) < -2.40"},
    { 20, "-2.60 < log10(BEP) < -2.50"},
    { 21, "-2.70 < log10(BEP) < -2.60"},
    { 22, "-2.80 < log10(BEP) < -2.70"},
    { 23, "-2.90 < log10(BEP) < -2.80"},
    { 24, "-3.00 < log10(BEP) < -2.90"},
    { 25, "-3.10 < log10(BEP) < -3.00"},
    { 26, "-3.20 < log10(BEP) < -3.10"},
    { 27, "-3.30 < log10(BEP) < -3.20"},
    { 28, "-3.40 < log10(BEP) < -3.30"},
    { 29, "-3.50 < log10(BEP) < -3.40"},
    { 30, "-3.60 < log10(BEP) < -3.50"},
    { 31, "log10(BEP) < -3.60"},
    {  0, NULL }
};

static const value_string gsm_a_rr_cv_bep_vals[] = {
    {  0, "1.75 < CV BEP < 2.00"},
    {  1, "1.50 < CV BEP < 1.75"},
    {  2, "1.25 < CV BEP < 1.50"},
    {  3, "1.00 < CV BEP < 1.25"},
    {  4, "0.75 < CV BEP < 1.00"},
    {  5, "0.50 < CV BEP < 0.75"},
    {  6, "0.25 < CV BEP < 0.50"},
    {  7, "0.00 < CV BEP < 0.25"},
    {  0, NULL }
};

static void
sacch_rr_enh_meas_report(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
    proto_tree *subtree;
    proto_item *item;
    guint32     curr_offset;
    guint       bit_offset, bit_offset_sav;
    guint8      tvb_len = tvb_length(tvb);
    guint16     bit_len = tvb_len << 3;
    guint8      idx;

    curr_offset = offset;
    bit_offset = curr_offset << 3;

    proto_tree_add_bits_item(tree, hf_gsm_a_rr_ba_used, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_3g_ba_used, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_bsic_seen, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    proto_tree_add_bits_item(tree, hf_gsm_a_rr_scale, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset += 1;
    if (gsm_rr_csn_flag(tvb, tree, bit_offset++, "Serving cell data", "Present", "Not Present"))
    { /* Serving cell data */
        bit_offset_sav = bit_offset;
        item = proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_SERVING_CELL_DATA].strptr);
        subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_SERVING_CELL_DATA]);
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_dtx_used, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rxlev_full_serv_cell, tvb, bit_offset, 6, ENC_BIG_ENDIAN);
        bit_offset += 6;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rxqual_full_serv_cell, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_mean_bep_gmsk, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
        bit_offset += 5;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_mean_cv_bep, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset += 3;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_nbr_rcvd_blocks, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
        bit_offset += 5;
        proto_item_set_len(item, (bit_offset>>3) - (bit_offset_sav>>3)+1);
    }
    while (gsm_rr_csn_flag(tvb, tree, bit_offset++, "Repeated Invalid BSIC Information", "Present", "Not Present"))
    { /* Repeated Invalid BSIC Information */
        bit_offset_sav = bit_offset;
        item = proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_REPEAT_INV_BSIC_INFO].strptr);
        subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_REPEAT_INV_BSIC_INFO]);
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bcch_freq_ncell, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
        bit_offset += 5;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_bsic_ncell, tvb, bit_offset, 6, ENC_BIG_ENDIAN);
        bit_offset += 6;
        proto_tree_add_bits_item(subtree, hf_gsm_a_rr_rxlev_ncell, tvb, bit_offset, 6, ENC_BIG_ENDIAN);
        bit_offset += 6;
        proto_item_set_len(item, (bit_offset>>3) - (bit_offset_sav>>3)+1);
    }
    if (gsm_rr_csn_flag(tvb, tree, bit_offset++, "Bitmap Type Reporting", "Present", "Not Present"))
    { /* Bitmap Type Reporting */
        item = proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_BITMAP_TYPE_REPORTING].strptr);
        subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_BITMAP_TYPE_REPORTING]);
        idx = 0;
        while (((guint)(bit_offset>>3) <= (offset + len)) && (idx < 96))
        {
            if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Reporting Quantity", "Present", "Not Present"))
            {
                proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "Neighbour Cell List index: %u", idx);
                proto_tree_add_bits_item(subtree, hf_gsm_a_rr_reporting_quantity, tvb, bit_offset, 6, ENC_BIG_ENDIAN);
                bit_offset += 6;
            }
            idx += 1;
        }
    }
    /* Null breakpoint */
    if (bit_offset < bit_len)
    {
       if (gsm_rr_csn_HL_flag(tvb, tree, 0, bit_offset++, "Additions in Rel-8", "Present", "Not Present"))
       {
           gint8  bitmap_length;
           bit_offset_sav = bit_offset;
           item = proto_tree_add_text(tree, tvb, bit_offset>>3, -1, "%s", gsm_rr_rest_octets_elem_strings[DE_RR_REST_OCTETS_REPORTING_QUANTITY].strptr);
           subtree = proto_item_add_subtree(item, ett_gsm_rr_rest_octets_elem[DE_RR_REST_OCTETS_REPORTING_QUANTITY]);

           bitmap_length = tvb_get_bits8(tvb,bit_offset,7);
           bitmap_length += 1;
           proto_tree_add_bits_item(subtree, hf_gsm_a_rr_emr_bitmap_length, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
           bit_offset += 7;

           /* REPORTING_QUANTITY */
           idx = 0;
           while ((guint)(bit_offset>>3) <= (offset + len) && (idx < bitmap_length) )
           {
              if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "Reporting Quantity", "Present", "Not Present"))
               {
                   proto_tree_add_text(subtree, tvb, bit_offset>>3, 1, "Neighbour Cell List index: %u", idx);
                   proto_tree_add_bits_item(subtree, hf_gsm_a_rr_reporting_quantity, tvb, bit_offset, 6, ENC_BIG_ENDIAN);
                   bit_offset += 6;
               }
               idx += 1;
           }

           /* E-UTRAN Measurement Report */
           if (gsm_rr_csn_flag(tvb, subtree, bit_offset++, "E-UTRAN Measurement Report", "Present", "Not Present"))
           {
               bit_offset += sacch_rr_eutran_meas_report(tvb, subtree, bit_offset, len*8-(bit_offset-offset*8));
           }
           proto_item_set_len(item, (bit_offset>>3) - (bit_offset_sav>>3)+1);
       }
    }
    gsm_rr_csn_padding_bits(tree, tvb, bit_offset, tvb_len);
}

#define NUM_GSM_DTAP_MSG_RR (sizeof(gsm_a_dtap_msg_rr_strings)/sizeof(value_string))
static gint ett_gsm_dtap_msg_rr[NUM_GSM_DTAP_MSG_RR];
static void (*dtap_msg_rr_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len) = {
    NULL,       /* Reserved */
    dtap_rr_add_ass,            /* Additional Assignment */
    dtap_rr_imm_ass,            /* 9.1.18 Immediate assignment  */
    dtap_rr_imm_ass_ext,        /* Immediate Assignment Extended */
    dtap_rr_imm_ass_rej,        /* Immediate Assignment Reject */

    dtap_rr_dtm_ass_fail,       /* DTM Assignment Failure */
    dtap_rr_dtm_rej,            /* DTM Reject */
    dtap_rr_dtm_req,            /* DTM Request */
    dtap_rr_pkt_assign,         /* Packet Assignment */
    dtap_rr_dtm_ass_cmd,        /* DTM Assignment Command */
    dtap_rr_dtm_info,           /* DTM Information */
    dtap_rr_pkt_notif,          /* Packet Notification */

    dtap_rr_cip_mode_cmd,       /* Ciphering Mode Command */
    dtap_rr_cip_mode_cpte,      /* Ciphering Mode Complete */

    dtap_rr_conf_change_cmd,    /* Configuration Change Command */
    NULL,                       /* Configuration Change Ack. */
    dtap_rr_conf_change_rej,    /* Configuration Change Reject */

    dtap_rr_ass_cmd,            /* 9.1.2 Assignment Command */
    dtap_rr_ass_comp,           /* Assignment Complete */
    dtap_rr_ass_fail,           /* Assignment Failure */
    dtap_rr_ho_cmd,             /* Handover Command */
    dtap_rr_ho_cpte,            /* Handover Complete */
    dtap_rr_ho_fail,            /* Handover Failure */
    dtap_rr_phy_info,           /* Physical Information */

    NULL,                       /* RR-cell Change Order */
    NULL,                       /* PDCH Assignment Command */

    dtap_rr_ch_rel,             /* Channel Release */
    dtap_rr_partial_rel,        /* Partial Release */
    NULL,                       /* Partial Release Complete */

    dtap_rr_paging_req_type_1,  /* Paging Request Type 1 */
    dtap_rr_paging_req_type_2,  /* Paging Request Type 2 */
    dtap_rr_paging_req_type_3,  /* Paging Request Type 3 */
    dtap_rr_paging_resp,        /* Paging Response */
    NULL,                       /* Notification/NCH */
    NULL,                       /* Reserved */
    NULL,                       /* Notification/Response */

    NULL,                       /* Reserved */

    dtap_rr_utran_classmark_change,     /* Utran Classmark Change  */
    NULL,                       /* cdma2000 Classmark Change */
    dtap_rr_inter_syst_to_utran_ho_cmd, /* Inter System to UTRAN Handover Command */
    NULL,                       /* Inter System to cdma2000 Handover Command */

    NULL,                       /* System Information Type 8 */
    dtap_rr_sys_info_1,         /* System Information Type 1 */
    dtap_rr_sys_info_2,         /* System Information Type 2 */
    dtap_rr_sys_info_3,         /* System Information Type 3 */
    dtap_rr_sys_info_4,         /* System Information Type 4 */
    dtap_rr_sys_info_5,         /* System Information Type 5 */
    dtap_rr_sys_info_6,         /* System Information Type 6 */
    NULL,                       /* System Information Type 7 */

    dtap_rr_sys_info_2bis,      /* System Information Type 2bis */
    dtap_rr_sys_info_2ter,      /* System Information Type 2ter */
    dtap_rr_sys_info_2quater,   /* System Information Type 2quater */
    dtap_rr_sys_info_5bis,      /* System Information Type 5bis */
    dtap_rr_sys_info_5ter,      /* System Information Type 5ter */
    NULL,                       /* System Information Type 9 */
    dtap_rr_sys_info_13,        /* System Information Type 13 */

    NULL,                       /* System Information Type 16 */
    NULL,                       /* System Information Type 17 */

    NULL,                       /* System Information Type 18 */
    NULL,                       /* System Information Type 19 */
    NULL,                       /* System Information Type 20 */

    dtap_rr_ch_mode_mod,        /* Channel Mode Modify */
    dtap_rr_rr_status,          /* RR Status */
    dtap_rr_ch_mode_mod_ack,    /* Channel Mode Modify Acknowledge */
    dtap_rr_freq_redef,         /* Frequency Redefinition */
    dtap_rr_meas_rep,           /* 9.1.21 Measurement report */
    dtap_rr_mm_cm_change,       /* 9.1.11 Classmark Change */
    dtap_rr_cm_enq,             /* Classmark Enquiry */
    dtap_rr_ext_meas_report,    /* Extended Measurement Report */
    dtap_rr_ext_meas_order,     /* Extended Measurement Order */
    dtap_rr_gprs_sus_req,       /* 9.1.13b GPRS Suspension Request */

    NULL,                       /* VGCS Uplink Grant */
    NULL,                       /* Uplink Release */
    NULL,                       /* Reserved */
    NULL,                       /* Uplink Busy */
    NULL,                       /* Talker Indication */

    NULL,                       /* UTRAN Classmark Change/Handover To UTRAN Command */  /* spec conflict */

    dtap_rr_app_inf,            /* Application Information */

    NULL,                       /* NONE */
};

void get_rr_msg_params(guint8 oct, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn_p)
{
    gint idx;

    *msg_str = match_strval_idx((guint32) (oct & DTAP_RR_IEI_MASK), gsm_a_dtap_msg_rr_strings, &idx);
    *hf_idx = hf_gsm_a_dtap_msg_rr_type;
    if (*msg_str != NULL) {
        *ett_tree = ett_gsm_dtap_msg_rr[idx];
        *msg_fcn_p  = dtap_msg_rr_fcn[idx];
    }

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

    static gsm_a_tap_rec_t  tap_rec[4];
    static gsm_a_tap_rec_t *tap_p;
    static guint            tap_current = 0;

    void                  (*msg_fcn_p)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len);
    guint8                  oct;
    guint8                  pd;
    guint32                 offset;
    guint32                 len;
    guint32                 oct_1, oct_2;
    proto_item             *ccch_item   = NULL;
    proto_tree             *ccch_tree   = NULL;
    proto_item             *oct_1_item  = NULL;
    proto_tree             *pd_tree     = NULL;
    const gchar            *msg_str;
    gint                    ett_tree;
    gint                    ti;
    int                     hf_idx;
    gboolean                nsd;

    len = tvb_length(tvb);

    if (len < 3){
        /*
         * too short to be CCCH
         */
        call_dissector(data_handle, tvb, pinfo, tree);
        return;
    }

    col_append_str(pinfo->cinfo, COL_INFO, "(CCCH) ");
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

    /* Skip pseudo hdr here - it is dissected later */
    offset += 1;

    /*
     * get protocol discriminator
     */
    oct_1 = tvb_get_guint8(tvb, offset++);

    if ((((oct_1 & DTAP_TI_MASK) >> 4) & DTAP_TIE_PRES_MASK) == DTAP_TIE_PRES_MASK){
        /*
         * even though we don't know if a TI should be in the message yet
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
    msg_fcn_p = NULL;
    nsd = FALSE;
    col_append_fstr(pinfo->cinfo, COL_INFO, "(%s) ",val_to_str(pd,gsm_a_pd_short_str_vals,"Unknown (%u)"));

    /*
     * octet 1
     */
    switch (pd){
    case 6:
        get_rr_msg_params(oct, &msg_str, &ett_tree, &hf_idx, &msg_fcn_p);
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

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", msg_str);

    /*  L2 Pseudo Length 10.5.2.19 */
    /* note: dissected out of sequence! */
    elem_v(tvb, ccch_tree, pinfo, GSM_A_PDU_TYPE_RR, DE_RR_L2_PSEUDO_LEN, 0, NULL);

    oct_1_item =
        proto_tree_add_text(ccch_tree,
                            tvb, 1, 1,
                            "Protocol Discriminator: %s",
                            val_to_str(pd, protocol_discriminator_vals, "Unknown (%u)"));

    pd_tree = proto_item_add_subtree(oct_1_item, ett_ccch_oct_1);
    proto_tree_add_item(pd_tree, hf_gsm_a_L3_protocol_discriminator, tvb, 1, 1, ENC_BIG_ENDIAN);

    if (ti == -1){
        proto_tree_add_item(pd_tree, hf_gsm_a_skip_ind, tvb, 1, 1, ENC_BIG_ENDIAN);
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


    if ((ti != -1) && (ti & DTAP_TIE_PRES_MASK) == DTAP_TIE_PRES_MASK){
        proto_tree_add_item(tree, hf_gsm_a_extension, tvb, 2, 1, ENC_BIG_ENDIAN);
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

    if (offset >= len)
        return;

    /*
     * decode elements
     */
    if (msg_fcn_p == NULL){
        proto_tree_add_text(ccch_tree, tvb, offset, len - offset,
                            "Message Elements");
    }else{
        (*msg_fcn_p)(tvb, ccch_tree, pinfo, offset, len - offset);
    }
}

const value_string gsm_a_rr_short_pd_msg_strings[] = {
    { 0x00, "System Information Type 10" },
    { 0x01, "Notification/FACCH" },
    { 0x02, "Uplink Free" },
    { 0x04, "Enhanced Measurement Report" },
    { 0x05, "Measurement Information" },
    { 0x06, "VBS/VGCS Reconfigure" },
    { 0x07, "VBS/VGCS Reconfigure2" },
    { 0x08, "VGCS Additional Information" },
    { 0x09, "VGCS SMS Information" },
    {    0, NULL }
};

#define NUM_GSM_SACCH_MSG_RR (sizeof(gsm_a_rr_short_pd_msg_strings)/sizeof(value_string))
static gint ett_gsm_sacch_msg_rr[NUM_GSM_SACCH_MSG_RR];
static void (*sacch_msg_rr_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len) = {
    NULL,                       /* System Information Type 10 */
    NULL,                       /* Notification/FACCH */
    NULL,                       /* Uplink Free  */
    sacch_rr_enh_meas_report,   /* Enhanced Measurement Report */
    sacch_rr_meas_info,         /* Measurement Information */
    NULL,                       /* VBS/VGCS Reconfigure */
    NULL,                       /* VBS/VGCS Reconfigure2 */
    NULL,                       /* VGCS Additional Information */
    NULL,                       /* VGCS SMS Information */
    NULL,                       /* NONE */
};

static void
get_rr_short_pd_msg_params(guint8 mess_type, const gchar **msg_str, int *ett_tree, int *hf_idx, msg_fcn *msg_fcn_p)
{
    gint idx;

    *msg_str = match_strval_idx((guint32) mess_type, gsm_a_rr_short_pd_msg_strings, &idx);
    *hf_idx = hf_gsm_a_rr_short_pd_msg_type;
    if (*msg_str != NULL) {
        *ett_tree = ett_gsm_sacch_msg_rr[idx];
        *msg_fcn_p = sacch_msg_rr_fcn[idx];
    }
}

const value_string short_protocol_discriminator_vals[] = {
    {0x0, "Radio Resources Management messages"},
    {  0, NULL }
};

static void
dissect_sacch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    static gsm_a_tap_rec_t  tap_rec[4];
    static gsm_a_tap_rec_t *tap_p;
    static guint            tap_current        = 0;

    void                  (*msg_fcn_p)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len);
    guint8                  oct, short_pd, mess_type;
    guint32                 offset, bit_offset = 0;
    guint32                 len;
    proto_item             *sacch_item         = NULL;
    proto_tree             *sacch_tree         = NULL;
    const gchar            *msg_str;
    gint                    ett_tree;
    int                     hf_idx;

    len = tvb_length(tvb);

    col_append_str(pinfo->cinfo, COL_INFO, "(SACCH) ");

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

    oct = tvb_get_guint8(tvb, offset);

    msg_str = NULL;
    ett_tree = -1;
    hf_idx = -1;
    msg_fcn_p = NULL;

    short_pd = (oct & 0x80) >> 7;
    mess_type = (oct & 0x7c) >> 2;

    if (short_pd == 0)
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "(RR) ");
        get_rr_short_pd_msg_params(mess_type, &msg_str, &ett_tree, &hf_idx, &msg_fcn_p);
    }
    else
    {
        col_append_fstr(pinfo->cinfo, COL_INFO, "(Unknown) ");
    }

    /*
     * create the protocol tree
     */
    if (msg_str == NULL){
        sacch_item = proto_tree_add_protocol_format(tree, proto_a_sacch, tvb, 0, len,
                                                    "GSM SACCH - Message Type (0x%02x)", mess_type);

        sacch_tree = proto_item_add_subtree(sacch_item, ett_sacch_msg);
    }else{
        sacch_item = proto_tree_add_protocol_format(tree, proto_a_sacch, tvb, 0, -1,
                                                    "GSM SACCH - %s", msg_str);

        sacch_tree = proto_item_add_subtree(sacch_item, ett_tree);

        col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", msg_str);
    }

    if (short_pd == 0)
       proto_tree_add_bits_item(sacch_tree, hf_gsm_a_rr_short_pd, tvb, offset * 8 + bit_offset++, 1, ENC_BIG_ENDIAN);

    if (hf_idx == -1)
        return;

    /*
     * add SACCH message name
     */
    proto_tree_add_bits_item(sacch_tree, hf_gsm_a_rr_short_pd_msg_type, tvb, offset * 8 + bit_offset, 5, ENC_BIG_ENDIAN);
    bit_offset += 5;

    proto_tree_add_bits_item(sacch_tree, hf_gsm_a_rr_short_l2_header, tvb, offset * 8 + bit_offset, 2, ENC_BIG_ENDIAN);
    offset++;

    tap_p->pdu_type = GSM_A_PDU_TYPE_SACCH;
    tap_p->message_type = mess_type;
    tap_p->protocol_disc = short_pd;

    tap_queue_packet(gsm_a_tap, pinfo, tap_p);

    if (msg_str == NULL)
        return;

    /*
     * decode elements
     */
    if (msg_fcn_p == NULL){
        proto_tree_add_text(sacch_tree, tvb, offset, len - offset,
                            "Message Elements");
    }else{
        (*msg_fcn_p)(tvb, sacch_tree, pinfo, offset, len - offset);
    }
}

/* Register the protocol with Wireshark */
void
proto_register_gsm_a_rr(void)
{
    guint i;
    guint last_offset;

    /* Setup list of header fields */

    static hf_register_info hf[] =
        {
            { &hf_gsm_a_dtap_msg_rr_type,
              { "DTAP Radio Resources Management Message Type", "gsm_a.dtap.msg_rr_type",
                FT_UINT8, BASE_HEX, VALS(gsm_a_dtap_msg_rr_strings), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_elem_id,
              { "Element ID",   "gsm_a.rr.elem_id",
                FT_UINT8, BASE_HEX, NULL, 0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_bcc,
              { "BCC","gsm_a.rr.bcc",
                FT_UINT8,BASE_DEC,  NULL, 0x07,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_ncc,
              { "NCC","gsm_a.rr.ncc",
                FT_UINT8,BASE_DEC,  NULL, 0x38,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_bcch_arfcn,
              { "BCCH ARFCN(RF channel number)","gsm_a.rr.bcch_arfcn",
                FT_UINT16,BASE_DEC,  NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_range_nb,
              { "Number of Ranges","gsm_a.rr.range_nb",
                FT_UINT8, BASE_DEC,  NULL, 0xff,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_range_lower,
              { "Range Lower","gsm_a.rr.range_lower",
                FT_UINT16, BASE_DEC,  NULL, 0x0000,
                "ARFCN used as the lower limit of a range of frequencies to be used by the mobile station in cell selection (Range Lower)", HFILL }
            },
            { &hf_gsm_a_rr_range_higher,
              { "Range Higher","gsm_a.rr.range_higher",
                FT_UINT16, BASE_DEC,  NULL, 0x0000,
                "ARFCN used as the higher limit of a range of frequencies to be used by the mobile station in cell selection (Range Higher)", HFILL }
            },
            { &hf_gsm_a_rr_ba_freq,
              { "BA Freq","gsm_a.rr.ba_freq",
                FT_UINT16, BASE_DEC,  NULL, 0x0000,
                "ARFCN indicating a single frequency to be used by the mobile station in cell selection and reselection (BA Freq)", HFILL }
            },
            { &hf_gsm_a_rr_ho_ref_val,
              { "Handover reference value","gsm_a.rr.ho_ref_val",
                FT_UINT8,BASE_DEC,  NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_L2_pseudo_len,
              { "L2 Pseudo Length value","gsm_a.rr.l2_pseudo_len",
                FT_UINT8, BASE_DEC, NULL, 0xfc,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_ba_used,
              { "BA-USED","gsm_a.rr.ba_used",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_dtx_used,
              { "DTX-USED","gsm_a.rr.dtx_used",
                FT_BOOLEAN, BASE_NONE,  TFS(&gsm_a_rr_dtx_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_3g_ba_used,
              { "3G-BA-USED","gsm_a.rr.3g_ba_used",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_meas_valid,
              { "MEAS-VALID","gsm_a.rr.meas_valid",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_mv_vals), 0x40,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_rxlev_full_serv_cell,
              { "RXLEV-FULL-SERVING-CELL","gsm_a.rr.rxlev_full_serv_cell",
                FT_UINT8,BASE_DEC|BASE_EXT_STRING,  &gsm_a_rr_rxlev_vals_ext, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_rxlev_sub_serv_cell,
              { "RXLEV-SUB-SERVING-CELL","gsm_a.rr.rxlev_sub_serv_cell",
                FT_UINT8,BASE_DEC|BASE_EXT_STRING,  &gsm_a_rr_rxlev_vals_ext, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_rxqual_full_serv_cell,
              { "RXQUAL-FULL-SERVING-CELL","gsm_a.rr.rxqual_full_serv_cell",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_rxqual_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_rxqual_sub_serv_cell,
              { "RXQUAL-SUB-SERVING-CELL","gsm_a.rr.rxqual_sub_serv_cell",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_rxqual_vals), 0x0e,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_no_ncell_m,
              { "NO-NCELL-M","gsm_a.rr.no_ncell_m",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_ncell_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_rxlev_ncell,
              { "RXLEV-NCELL","gsm_a.rr.rxlev_ncell",
                FT_UINT8,BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_bcch_freq_ncell,
              { "BCCH-FREQ-NCELL","gsm_a.rr.bcch_freq_ncell",
                FT_UINT8,BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_bsic_ncell,
              { "BSIC-NCELL","gsm_a.rr.bsic_ncell",
                FT_UINT8,BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_mobile_time_difference,
              { "Mobile Timing Difference value (in half bit periods)","gsm_a.rr.mobile_time_difference",
                FT_UINT32,BASE_DEC, NULL, 0xFFFFF8,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_pow_cmd_atc,
              { "ATC","gsm_a.rr.pow_cmd_atc",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_pow_cmd_atc_value), 0x80,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_page_mode,
              { "Page Mode","gsm_a.rr.page_mode",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_page_mode_vals), 0x0F,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_dedicated_mode_or_tbf,
              { "Dedicated mode or TBF","gsm_a.rr.dedicated_mode_or_tbf",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_dedicated_mode_or_tbf_vals), 0xF0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_pow_cmd_epc,
              { "EPC_mode","gsm_a.rr.pow_cmd_epc",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_pow_cmd_epc_value), 0x40,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_pow_cmd_fpcepc,
              { "FPC_EPC","gsm_a.rr.pow_cmd_fpcepc",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_pow_cmd_fpcepc_value), 0x20,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_pow_cmd_powlev,
              { "POWER LEVEL","gsm_a.rr.pow_cmd_pow",
                FT_UINT8,BASE_DEC,  NULL, 0x1f,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_sync_ind_nci,
              { "Normal cell indication(NCI)","gsm_a.rr.sync_ind_nci",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_sync_ind_nci_value), 0x08,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_sync_ind_rot,
              { "Report Observed Time Difference(ROT)","gsm_a.rr.sync_ind_rot",
                FT_BOOLEAN,8,  TFS(&sm_a_rr_sync_ind_rot_value), 0x04,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_sync_ind_si,
              { "Synchronization indication(SI)","gsm_a.rr.sync_ind_si",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_sync_ind_si_vals), 0x03,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_format_id,
              { "Format Identifier","gsm_a.rr.format_id",
                FT_UINT8,BASE_HEX,  VALS(gsm_a_rr_freq_list_format_id_vals), 0xce,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_format_id2,
              { "Format Identifier","gsm_a.rr.format_id",
                FT_UINT8,BASE_HEX,  VALS(gsm_a_rr_freq_list_format_id_vals), 0x8e,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_channel_mode,
              { "Channel Mode","gsm_a.rr.channel_mode",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_channel_mode_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_channel_mode2,
              { "Channel Mode 2","gsm_a.rr.channel_mode2",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_channel_mode2_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_sc,
              { "SC","gsm_a.rr.SC",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_sc_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_algorithm_id,
              { "Algorithm identifier","gsm_a.rr.algorithm_identifier",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_algorithm_identifier_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_cr,
              { "CR","gsm_a.rr.CR",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_cr_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_multirate_speech_ver,
              { "Multirate speech version","gsm_a.rr.multirate_speech_ver",
                FT_UINT8,BASE_DEC,  VALS(multirate_speech_ver_vals), 0xe0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_NCSB,
              { "NSCB: Noise Suppression Control Bit","gsm_a.rr.NCSB",
                FT_UINT8,BASE_DEC,  VALS(NSCB_vals), 0x10,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_ICMI,
              { "ICMI: Initial Codec Mode Indicator","gsm_a.rr.ICMI",
                FT_UINT8,BASE_DEC,  VALS(ICMI_vals), 0x8,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_start_mode,
              { "Start Mode","gsm_a.rr.start_mode",
                FT_UINT8,BASE_DEC,  NULL, 0x3,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_timing_adv,
              { "Timing advance value","gsm_a.rr.timing_adv",
                FT_UINT8,BASE_DEC,  NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_time_diff,
              { "Time difference value","gsm_a.rr.time_diff",
                FT_UINT8,BASE_DEC,  NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_tlli,
              { "TLLI","gsm_a.rr.tlli",
                FT_UINT32,BASE_HEX,  NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_tmsi_ptmsi,
              { "TMSI/P-TMSI Value","gsm_a.rr.tmsi_ptmsi",
                FT_UINT32,BASE_HEX,  NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_target_mode,
              { "Target mode","gsm_a.rr.target_mode",
                FT_UINT8,BASE_DEC,  NULL, 0xc0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_wait_indication,
              { "Wait Indication","gsm_a.rr.wait_indication",
                FT_UINT8,BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_seq_code,
              { "Sequence Code","gsm_a.rr.seq_code",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },

            { &hf_gsm_a_rr_group_cipher_key_number,
              { "Group cipher key number","gsm_a.rr.Group_cipher_key_number",
                FT_UINT8,BASE_DEC,  NULL, 0x3c,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_MBMS_broadcast,
              { "MBMS Broadcast","gsm_a.rr.MBMS_broadcast",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_MBMS_broadcast_value), 0x01,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_MBMS_multicast,
              { "MBMS Multicast","gsm_a.rr.MBMS_multicast",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_MBMS_multicast_value), 0x02,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_last_segment,
              { "Last Segment","gsm_a.rr.last_segment",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_last_segment_value), 0x01,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_carrier_ind,
              { "Carrier Indication","gsm_a.rr.carrier_ind",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_carrier_ind_value), 0x01,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_ra,
              { "Random Access Information (RA)", "gsm_a.rr.ra",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_T1prim,
              { "T1'",             "gsm_a.rr.T1prim",
                FT_UINT8, BASE_DEC, NULL, 0xf8,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_T3,
              { "T3",              "gsm_a.rr.T3",
                FT_UINT16, BASE_DEC, NULL, 0x07e0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_T2,
              { "T2",              "gsm_a.rr.T2",
                FT_UINT8, BASE_DEC, NULL, 0x1f,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_tbf_T1prim,
              { "T1' (TBF)",             "gsm_a.rr.tbf.T1prim",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_tbf_T3,
              { "T3 (TBF)",              "gsm_a.rr.tbf.T3",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_tbf_T2,
              { "T2 (TBF)",              "gsm_a.rr.tbf.T2",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_rfn,
              { "RFN",             "gsm_a.rr.rfn",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Reduced Frame Number", HFILL }
            },
            { &hf_gsm_a_rr_RR_cause,
              { "RR cause value","gsm_a.rr.RRcause",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_RR_cause_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_cm_cng_msg_req,
              { "CLASSMARK CHANGE","gsm_a.rr.cm_cng_msg_req",
                FT_BOOLEAN,8,  TFS(&gsm_a_msg_req_value), 0x80,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_utran_cm_cng_msg_req,
              { "UTRAN CLASSMARK CHANGE","gsm_a.rr.utran_cm_cng_msg_req",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_utran_cm_cng_msg_req_vals), 0x70,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_cdma200_cm_cng_msg_req,
              { "CDMA2000 CLASSMARK CHANGE","gsm_a.rr.cdma200_cm_cng_msg_req",
                FT_BOOLEAN,8,  TFS(&gsm_a_msg_req_value), 0x08,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_geran_iu_cm_cng_msg_req,
              { "GERAN IU MODE CLASSMARK CHANGE","gsm_a.rr.geran_iu_cm_cng_msg_req",
                FT_BOOLEAN,8,  TFS(&gsm_a_msg_req_value), 0x04,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_chnl_needed_ch1,
              { "Channel 1","gsm_a.rr.chnl_needed_ch1",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_channel_needed_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_chnl_needed_ch2,
              { "Channel 2","gsm_a.rr.chnl_needed_ch2",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_channel_needed_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_chnl_needed_ch3,
              { "Channel 3","gsm_a.rr.chnl_needed_ch3",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_channel_needed_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_chnl_needed_ch4,
              { "Channel 4","gsm_a.rr.chnl_needed_ch4",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_channel_needed_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_pkt_estab_cause,
              { "PACKET_ESTABLISHMENT_CAUSE","gsm_a.rr.pkt_estab_cause",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_pkt_estab_cause_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_peak_throughput_class,
              { "PEAK_THROUGHPUT_CLASS","gsm_a.rr.peak_throughput_class",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_radio_priority,
              { "RADIO_PRIORITY","gsm_a.rr.radio_priority",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_radio_priority_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_llc_pdu_type,
              { "LLC_PDU_TYPE","gsm_a.rr.llc_pdu_type",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_llc_pdu_type_value), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_rlc_octet_count,
              { "RLC_OCTET_COUNT","gsm_a.rr.rlc_octet_count",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_rlc_non_pers_mode_cap,
              { "RLC Non-persistent Mode Capability","gsm_a.rr.rlc_non_pers_mode_cap",
                FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_reduced_latency_cap,
              { "Reduced Latency Capability","gsm_a.rr.reduced_latency_cap",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_reduced_latency_cap_value), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_ul_egprs2,
              { "Uplink EGPRS2","gsm_a.rr.ul_egprs2",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_egprs2_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_dl_egprs2,
              { "Downlink EGPRS2","gsm_a.rr.dl_egprs2",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_egprs2_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_emst_ms_cap,
              { "EMST_MS_Capability","gsm_a.rr.emst_ms_cap",
                FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_suspension_cause,
              { "Suspension cause value","gsm_a.rr.suspension_cause",
                FT_UINT8,BASE_DEC,  VALS(gsm_a_rr_suspension_cause_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_apdu_id,
              { "APDU ID","gsm_a.rr.apdu_id",
                FT_UINT8,BASE_HEX,  VALS(gsm_a_rr_apdu_id_vals), 0x0f,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_apdu_flags,
              { "APDU Flags","gsm_a.rr.apdu_flags",
                FT_UINT8,BASE_HEX,  VALS(gsm_a_rr_apdu_flags_vals), 0xf0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b8,
              { "12,2 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b8",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x80,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b7,
              { "10,2 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b7",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x40,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b6,
              { "7,95 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b6",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x20,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b5,
              { "7,40 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b5",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x10,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b4,
              { "6,70 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b4",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x08,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b3,
              { "5,90 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b3",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x04,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b2,
              { "5,15 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b2",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x02,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_set_of_amr_codec_modes_v1_b1,
              { "4,75 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v1b1",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x01,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b5,
              { "23,85 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b5",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x10,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b4,
              { "15,85 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b4",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x08,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b3,
              { "12,65 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b3",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x04,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b2,
              { "8,85 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b2",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x02,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_set_of_amr_codec_modes_v2_b1,
              { "6,60 kbit/s codec rate", "gsm_a.rr.set_of_amr_codec_modes_v2b1",
                FT_BOOLEAN,8,  TFS(&gsm_a_rr_set_of_amr_codec_modes), 0x01,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_amr_threshold,
              { "AMR Threshold", "gsm_a.rr.amr_threshold",
                FT_UINT8, BASE_DEC|BASE_EXT_STRING,  &gsm_a_rr_amr_threshold_vals_ext, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_amr_hysteresis,
              { "AMR Hysteresis", "gsm_a.rr.amr_hysteresis",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_amr_hysteresis_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_pwrc,
              { "PWRC", "gsm_a.rr.pwrc",
                FT_BOOLEAN, BASE_NONE,  NULL, 0x0,
                "Power Control Indicator (PWRC)", HFILL }
            },
            { &hf_gsm_a_rr_dtx_bcch,
              { "DTX (BCCH)", "gsm_a.rr.dtx_bcch",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_dtx_bcch_vals), 0x30,
                "Discontinuous Transmission (DTX-BCCH)", HFILL }
            },
            { &hf_gsm_a_rr_dtx_sacch,
              { "DTX (SACCH)", "gsm_a.rr.dtx_sacch",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_dtx_sacch_vals), 0x00,
                "Discontinuous Transmission (DTX-SACCH)", HFILL }
            },
            { &hf_gsm_a_rr_radio_link_timeout,
              { "Radio Link Timeout", "gsm_a.rr.radio_link_timeout",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_radio_link_timeout_vals), 0x0f,
                "Radio Link Timeout (s)", HFILL }
            },
            { &hf_gsm_a_rr_cell_reselect_hyst,
              { "Cell Reselection Hysteresis", "gsm_a.rr.cell_reselect_hyst",
                FT_UINT8, BASE_DEC,  NULL, 0xe0,
                "Cell Reselection Hysteresis (dB)", HFILL }
            },
            { &hf_gsm_a_rr_ms_txpwr_max_cch,
              { "MS TXPWR MAX CCH", "gsm_a.rr.ms_txpwr_max_cch",
                FT_UINT8, BASE_DEC,  NULL, 0x1f,
                NULL, HFILL }
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
                FT_UINT8, BASE_DEC|BASE_EXT_STRING,  &gsm_a_rr_rxlev_vals_ext, 0x3f,
                NULL, HFILL }
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
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_cbq3,
              { "CBQ3", "gsm_a.rr.cbq3",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_cbq3_vals), 0x00,
                "Cell Bar Qualify 3", HFILL }
            },
            { &hf_gsm_a_rr_bs_pa_mfrms,
              { "BS-PA-MFRMS", "gsm_a.rr.bs_pa_mfrms",
                FT_UINT8, BASE_DEC,  NULL, 0x07,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_t3212,
              { "T3212", "gsm_a.rr.t3212",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                "Periodic Update period (T3212) (deci-hours)", HFILL }
            },
            { &hf_gsm_a_rr_gsm_band,
              { "GSM Band", "gsm_a.rr.gsm_band",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_gsm_band_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_arfcn_first,
              { "ARFCN First", "gsm_a.rr.arfcn_first",
                FT_UINT16, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_band_offset,
              { "Band Offset", "gsm_a.rr.band_offset",
                FT_UINT16, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_arfcn_range,
              { "ARFCN Range", "gsm_a.rr.arfcn_range",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_lowest_arfcn,
              { "Lowest ARFCN", "gsm_a.rr.lowest_arfcn",
                FT_UINT8, BASE_DEC,  NULL, 0x7f,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_inc_skip_arfcn,
              { "Increment skip ARFCN", "gsm_a.rr.inc_skip_arfcn",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_gprs_resumption_ack,
              { "Ack", "gsm_a.rr.gprs_resumption_ack",
                FT_BOOLEAN, 8,  TFS(&gsm_a_rr_gprs_resumption_ack_value), 0x01,
                "GPRS Resumption Ack bit", HFILL }
            },
            { &hf_gsm_a_rr_ext_ind,
              { "EXT-IND", "gsm_a.rr.ext_ind",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_ext_ind_vals), 0x20,
                "Extension Indication (EXT-IND)", HFILL }
            },
            { &hf_gsm_a_rr_ba_ind,
              { "BA-IND", "gsm_a.rr.ba_ind",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
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
                NULL, HFILL }
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
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_si2ter_mp_change_mark,
              { "SI2ter Measurement Parameter Change Mark", "gsm_a.rr.si2ter_mp_change_mark",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_si2ter_3g_change_mark,
              { "SI2ter 3G Change Mark", "gsm_a.rr.si2ter_3g_change_mark",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_si2ter_index,
              { "SI2ter Index", "gsm_a.rr.si2ter_index",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_si2ter_count,
              { "SI2ter Count", "gsm_a.rr.si2ter_count",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_fdd_uarfcn,
              { "FDD UARFCN", "gsm_a.rr.fdd_uarfcn",
                FT_UINT16, BASE_DEC,  NULL, 0x0000,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_bandwidth_fdd,
              { "Bandwidth FDD", "gsm_a.rr.bandwidth_fdd",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_tdd_uarfcn,
              { "TDD UARFCN", "gsm_a.rr.tdd_uarfcn",
                FT_UINT16, BASE_DEC,  NULL, 0x0000,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_bandwidth_tdd,
              { "Bandwidth TDD", "gsm_a.rr.bandwidth_tdd",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_arfcn,
              { "ARFCN", "gsm_a.rr.arfcn",
                FT_UINT16, BASE_DEC,  NULL, 0x0000,
                "Absolute Radio Frequency Channel Number (ARFCN)", HFILL }
            },
            { &hf_gsm_a_rr_bsic,
              { "BSIC", "gsm_a.rr.bsic",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                "Base Station Identify Code (BSIC)", HFILL }
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
            { &hf_gsm_a_rr_3g_ba_ind,
              { "3G BA-IND", "gsm_a.rr.3g_ba_ind",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                "3G BCCH Allocation Indication (3G BA-IND)", HFILL }
            },
            { &hf_gsm_a_rr_mp_change_mark,
              { "Measurement Parameter Change Mark", "gsm_a.rr.mp_change_mark",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_si2quater_index,
              { "SI2quater Index", "gsm_a.rr.si2quater_index",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_si2quater_count,
              { "SI2quater Count", "gsm_a.rr.si2quater_count",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_gsm_report_type,
              { "Report Type", "gsm_a.rr.gsm_report_type",
                FT_BOOLEAN, BASE_NONE,  TFS(&gsm_a_rr_gsm_report_type_value), 0x0,
                "Report type the MS shall use (Report Type)", HFILL }
            },
            { &hf_gsm_a_rr_serving_band_reporting,
              { "Serving Band Reporting", "gsm_a.rr.serving_band_reporting",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Number of cells reported from the GSM serving frequency band (Serving Band Reporting)", HFILL }
            },
            { &hf_gsm_a_rr_frequency_scrolling,
              { "Frequency Scrolling", "gsm_a.rr.frequency_scrolling",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_frequency_scrolling_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_rep_priority,
              { "Rep Priority", "gsm_a.rr.rep_priority",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_rep_priority_value), 0x0,
                "Reporting Priority", HFILL }
            },
            { &hf_gsm_a_rr_report_type,
              { "Report Type", "gsm_a.rr.report_type",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_report_type_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_reporting_rate,
              { "Reporting Rate", "gsm_a.rr.reporting_rate",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_reporting_rate_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_invalid_bsic_reporting,
              { "Invalid BSIC Reporting", "gsm_a.rr.invalid_bsic_reporting",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_invalid_bsic_reporting_value), 0x0,
                NULL, HFILL }
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
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_gsm_reporting_threshold_vals), 0x00,
                "Apply priority reporting if the reported value is above threshold for GSM frequency band 900 (900 Reporting Threshold)", HFILL }
            },
            { &hf_gsm_a_rr_1800_reporting_offset,
              { "1800 Reporting Offset", "gsm_a.rr.1800_reporting_offset",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
                "Offset to the reported value when prioritising the cells for reporting for GSM frequency band 1800 (1800 Reporting Offset)", HFILL }
            },
            { &hf_gsm_a_rr_1800_reporting_threshold,
              { "1800 Reporting Threshold", "gsm_a.rr.1800_reporting_threshold",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_gsm_reporting_threshold_vals), 0x00,
                "Apply priority reporting if the reported value is above threshold for GSM frequency band 1800 (1800 Reporting Threshold)", HFILL }
            },
            { &hf_gsm_a_rr_400_reporting_offset,
              { "400 Reporting Offset", "gsm_a.rr.400_reporting_offset",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
                "Offset to the reported value when prioritising the cells for reporting for GSM frequency band 400 (400 Reporting Offset)", HFILL }
            },
            { &hf_gsm_a_rr_400_reporting_threshold,
              { "400 Reporting Threshold", "gsm_a.rr.400_reporting_threshold",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_gsm_reporting_threshold_vals), 0x00,
                "Apply priority reporting if the reported value is above threshold for GSM frequency band 400 (400 Reporting Threshold)", HFILL }
            },
            { &hf_gsm_a_rr_1900_reporting_offset,
              { "1900 Reporting Offset", "gsm_a.rr.1900_reporting_offset",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
                "Offset to the reported value when prioritising the cells for reporting for GSM frequency band 1900 (1900 Reporting Offset)", HFILL }
            },
            { &hf_gsm_a_rr_1900_reporting_threshold,
              { "1900 Reporting Threshold", "gsm_a.rr.1900_reporting_threshold",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_gsm_reporting_threshold_vals), 0x00,
                "Apply priority reporting if the reported value is above threshold for GSM frequency band 1900 (1900 Reporting Threshold)", HFILL }
            },
            { &hf_gsm_a_rr_850_reporting_offset,
              { "850 Reporting Offset", "gsm_a.rr.850_reporting_offset",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
                "Offset to the reported value when prioritising the cells for reporting for GSM frequency band 850 (850 Reporting Offset)", HFILL }
            },
            { &hf_gsm_a_rr_850_reporting_threshold,
              { "850 Reporting Threshold", "gsm_a.rr.900_reporting_threshold",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_gsm_reporting_threshold_vals), 0x00,
                "Apply priority reporting if the reported value is above threshold for GSM frequency band 850 (850 Reporting Threshold)", HFILL }
            },
            { &hf_gsm_a_rr_network_control_order,
              { "Network Control Order", "gsm_a.rr.network_control_order",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_network_control_order_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_nc_non_drx_period,
              { "NC Non DRX Period", "gsm_a.rr.nc_non_drx_period",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_nc_non_drx_period_vals), 0x00,
                NULL, HFILL }
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
            { &hf_gsm_a_rr_index_start_3g,
              { "Index Start 3G", "gsm_a.rr.index_start_3g",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_absolute_index_start_emr,
              { "Absolute Index Start EMR", "gsm_a.rr.absolute_index_start_emr",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_qsearch_c_initial,
              { "QSearch C Initial", "gsm_a.rr.qsearch_c_initial",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_qsearch_c_initial_value), 0x0,
                "Qsearch value to be used in connected mode before Qsearch C is received (QSearch C Initial)", HFILL }
            },
            { &hf_gsm_a_rr_fdd_rep_quant,
              { "FDD Rep Quant", "gsm_a.rr.fdd_rep_quant",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_fdd_rep_quant_value), 0x0,
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
              { "3G Search Prio (ignored in Rel-8)", "gsm_a.rr.3g_search_prio",
                FT_BOOLEAN, BASE_NONE,  TFS(&gsm_a_rr_3g_search_prio_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_fdd_reporting_offset,
              { "FDD Reporting Offset", "gsm_a.rr.fdd_reporting_offset",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
                "Offset to the reported value when prioritising the cells for reporting for FDD access technology (FDD Reporting Offset)", HFILL }
            },
            { &hf_gsm_a_rr_fdd_reporting_threshold_rscp,
              { "FDD Reporting Threshold RSCP", "gsm_a.rr.fdd_reporting_threshold_rscp",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_wcdma_rscp_reporting_threshold_vals), 0x00,
                "Apply priority reporting if the reported value is above threshold for FDD access technology (FDD Reporting Threshold)", HFILL }
            },
            { &hf_gsm_a_rr_fdd_reporting_threshold_ecn0,
              { "FDD Reporting Threshold EcN0", "gsm_a.rr.fdd_reporting_threshold_ecn0",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_wcdma_ecn0_reporting_threshold_vals), 0x00,
                "Apply priority reporting if the reported value is above threshold for FDD access technology (FDD Reporting Threshold)", HFILL }
            },
            { &hf_gsm_a_rr_tdd_reporting_offset,
              { "TDD Reporting Offset", "gsm_a.rr.tdd_reporting_offset",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
                "Offset to the reported value when prioritising the cells for reporting for TDD access technology (TDD Reporting Offset)", HFILL }
            },
            { &hf_gsm_a_rr_tdd_reporting_threshold_rscp,
              { "TDD Reporting Threshold RSCP", "gsm_a.rr.tdd_reporting_threshold_rscp",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_wcdma_rscp_reporting_threshold_vals), 0x00,
                "Apply priority reporting if the reported value is above threshold for TDD access technology (TDD Reporting Threshold)", HFILL }
            },
            { &hf_gsm_a_rr_tdd_reporting_threshold_ecn0,
              { "TDD Reporting Threshold EcN0", "gsm_a.rr.tdd_reporting_threshold_ecn0",
                FT_UINT8, BASE_DEC,  VALS(gsm_a_rr_wcdma_ecn0_reporting_threshold_vals), 0x00,
                "Apply priority reporting if the reported value is above threshold for TDD access technology (TDD Reporting Threshold)", HFILL }
            },
            { &hf_gsm_a_rr_fdd_reporting_threshold_2,
              { "FDD Reporting Threshold 2", "gsm_a.rr.fdd_reporting_threshold_2",
                FT_UINT8, BASE_DEC,  NULL, 0x00,
                "Reporting threshold for the CPICH parameter (Ec/No or RSCP) that is not reported according to FDD_REP_QUANT (FDD Reporting Threshold 2)", HFILL }
            },
            { &hf_gsm_a_rr_3g_ccn_active,
              { "3G CCN Active", "gsm_a.rr.3g_ccn_active",
                FT_BOOLEAN, BASE_NONE,  TFS(&gsm_a_rr_3g_ccn_active_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_700_reporting_offset,
              { "700 Reporting Offset", "gsm_a.rr.700_reporting_offset",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
                "Offset to the reported value when prioritising the cells for reporting for GSM frequency band 700 (700 Reporting Offset)", HFILL }
            },
            { &hf_gsm_a_rr_700_reporting_threshold,
              { "700 Reporting Threshold", "gsm_a.rr.700_reporting_threshold",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_gsm_reporting_threshold_vals), 0x00,
                "Apply priority reporting if the reported value is above threshold for GSM frequency band 700 (700 Reporting Threshold)", HFILL }
            },
            { &hf_gsm_a_rr_810_reporting_offset,
              { "810 Reporting Offset", "gsm_a.rr.810_reporting_offset",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_xxx_reporting_offset_vals), 0x00,
                "Offset to the reported value when prioritising the cells for reporting for GSM frequency band 810 (810 Reporting Offset)", HFILL }
            },
            { &hf_gsm_a_rr_810_reporting_threshold,
              { "810 Reporting Threshold", "gsm_a.rr.810_reporting_threshold",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_gsm_reporting_threshold_vals), 0x00,
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
            { &hf_gsm_a_rr_gprs_ra_colour,
              { "GPRS RA Colour", "gsm_a.rr.gprs_ra_colour",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_si13_position,
              { "SI13 Position", "gsm_a.rr.si13_position",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_si13_position_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_power_offset,
              { "Power Offset", "gsm_a.rr.power_offset",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_power_offset_vals), 0x0,
                "Power offset used in conjunction with the MS TXPWR MAX CCH parameter by the class 3 DCS 1800 MS (Power Offset)", HFILL }
            },
            { &hf_gsm_a_rr_si2quater_position,
              { "SI2quater Position", "gsm_a.rr.si2quater_position",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_si2quater_position_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_si13alt_position,
              { "SI13alt Position", "gsm_a.rr.si13alt_position",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_si13alt_position_value), 0x0,
                NULL, HFILL }
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
            { &hf_gsm_a_rr_cell_id,
              { "Cell Identity", "gsm_a.rr.cell_id",
                FT_UINT16, BASE_HEX_DEC, 0, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_paging_channel_restructuring,
              { "Paging Channel Restructuring", "gsm_a.rr.paging_channel_restructuring",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_paging_channel_restructuring_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_nln_sacch,
              { "NLN (SACCH)", "gsm_a.rr.nln_sacch",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_nln_status_sacch,
              { "NLN Status (SACCH)", "gsm_a.rr.nln_status_sacch",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_nln_pch,
              { "NLN (PCH)", "gsm_a.rr.nln_pch",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_nln_status_pch,
              { "NLN Status (PCH)", "gsm_a.rr.nln_status_pch",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_vbs_vgcs_inband_notifications,
              { "Inband Notifications", "gsm_a.rr.vbs_vgcs_inband_notifications",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_vbs_vgcs_inband_notifications_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_vbs_vgcs_inband_pagings,
              { "Inband Pagings", "gsm_a.rr.vbs_vgcs_inband_pagings",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_vbs_vgcs_inband_pagings_value), 0x0,
                NULL, HFILL }
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
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_dedicated_mode_mbms_notification_support,
              { "Dedicated Mode MBMS Notification Support", "gsm_a.rr.dedicated_mode_mbms_notification_support",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_dedicated_mode_mbms_notification_support_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_mnci_support,
              { "MNCI Support", "gsm_a.rr.mnci_support",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_mnci_support_value), 0x0,
                "MBMS Neighbouring Cell Information Support (MNCI Support)", HFILL }
            },
            { &hf_gsm_a_rr_amr_config,
              { "AMR Configuration", "gsm_a.rr.amr_config",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_bcch_change_mark,
              { "BCCH Change Mark", "gsm_a.rr.bcch_change_mark",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_si_change_field,
              { "SI Change Field", "gsm_a.rr.si_change_field",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_si_change_field_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_si13_change_mark,
              { "SI13 Change Mark", "gsm_a.rr.si13_change_mark",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
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
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_ma_length,
              { "MA Length", "gsm_a.rr.ma_length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Mobile Allocation Length (MA Length)", HFILL }
            },
            { &hf_gsm_a_rr_psi1_repeat_period,
              { "PSI1 Repeat Period", "gsm_a.rr.psi1_repeat_period",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_psi1_repeat_period_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_pbcch_pb,
              { "Pb", "gsm_a.rr.pbcch_pb",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_pbcch_pb_vals), 0x0,
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
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_spgc_ccch_sup_value), 0x0,
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
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_t3192,
              { "T3192", "gsm_a.rr.t3192",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_t3192_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_drx_timer_max,
              { "DRX Timer Max", "gsm_a.rr.drx_timer_max",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_drx_timer_max_vals), 0x0,
                "Discontinuous Reception Timer Max (DRX Timer Max)", HFILL }
            },
            { &hf_gsm_a_rr_access_burst_type,
              { "Access Burst Type", "gsm_a.rr.access_burst_type",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_access_burst_type_value), 0x0,
                "Format used in the PACKET CHANNEL REQUEST message, the PS HANDOVER ACCESS message, the PTCCH uplink block and in the PACKET CONTROL ACKNOWLEDGMENT message (Access Burst Type)", HFILL }
            },
            { &hf_gsm_a_rr_control_ack_type,
              { "Control Ack Type", "gsm_a.rr.control_ack_type",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_control_ack_type_value), 0x0,
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
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_pan_inc,
              { "PAN Inc", "gsm_a.rr.pan_inc",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_pan_max,
              { "PAN Max", "gsm_a.rr.pan_max",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_pan_max_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_egprs_packet_channel_request,
              { "EGPRS Packet Channel Request", "gsm_a.rr.egprs_packet_channel_request",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_egprs_packet_channel_request_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_bep_period,
              { "BEP Period", "gsm_a.rr.bep_period",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_bep_period_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_pfc_feature_mode,
              { "PFC Feature Mode", "gsm_a.rr.pfc_feature_mode",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_pfc_feature_mode_value), 0x0,
                "Packet Flow Context Feature Mode (PFC Feature Mode)", HFILL }
            },
            { &hf_gsm_a_rr_dtm_support,
              { "DTM Support", "gsm_a.rr.dtm_support",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_dtm_support_value), 0x0,
                "Dual Transfer Mode Support (DTM Support)", HFILL }
            },
            { &hf_gsm_a_rr_bss_paging_coordination,
              { "BSS Paging Coordination", "gsm_a.rr.bss_paging_coordination",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_bss_paging_coordination_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_ccn_active,
              { "CCN Active", "gsm_a.rr.ccn_active",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_ccn_active_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_nw_ext_utbf,
              { "NW Ext UTBF", "gsm_a.rr.nw_ext_utbf",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_nw_ext_utbf_value), 0x0,
                "Network Extended Uplink TBF (NW Ext UTBF)", HFILL }
            },
            { &hf_gsm_a_rr_multiple_tbf_capability,
              { "Multiple TBF Capability", "gsm_a.rr.multiple_tbf_capability",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_multiple_tbf_capability_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_ext_utbf_no_data,
              { "Ext UTBF No Data", "gsm_a.rr.ext_utbf_no_data",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_ext_utbf_no_data_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_dtm_enhancements_capability,
              { "DTM Enhancements Capability", "gsm_a.rr.dtm_enhancements_capability",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_dtm_enhancements_capability_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_reduced_latency_access,
              { "Reduced Latency Access", "gsm_a.rr.reduced_latency_access",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_reduced_latency_access_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_alpha,
              { "Alpha", "gsm_a.rr.alpha",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_alpha_vals), 0x0,
                "Alpha parameter for GPR MS output power control (Alpha)", HFILL }
            },
            { &hf_gsm_a_rr_t_avg_w,
              { "T Avg W", "gsm_a.rr.t_avg_w",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_t_avg_x_vals), 0x0,
                "Signal strength filter period for power control in packet idle mode", HFILL }
            },
            { &hf_gsm_a_rr_t_avg_t,
              { "T Avg T", "gsm_a.rr.t_avg_t",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_t_avg_x_vals), 0x0,
                "Signal strength filter period for power control in packet transfer mode", HFILL }
            },
            { &hf_gsm_a_rr_pc_meas_chan,
              { "PC Meas Chan", "gsm_a.rr.pc_meas_chan",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_pc_meas_chan_value), 0x0,
                "Channel used to measure the received power level on the downlink for the purpose of the uplink power control (PC Meas Chan)", HFILL }
            },
            { &hf_gsm_a_rr_n_avg_i,
              { "N Avg I", "gsm_a.rr.n_avg_i",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_n_avg_i_vals), 0x0,
                "Interfering signal strength filter constant for power control (N Avg I)", HFILL }
            },
            { &hf_gsm_a_rr_sgsnr,
              { "SGSNR", "gsm_a.rr.sgsnr",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_sgsnr_value), 0x0,
                "SGSN Release (SGSNR)", HFILL }
            },
            { &hf_gsm_a_rr_si_status_ind,
              { "SI Status Ind", "gsm_a.rr.si_status_ind",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_si_status_ind_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_lb_ms_txpwr_max_cch,
              { "LB MS TxPwr Max CCCH", "gsm_a.rr.n_avg_i",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_n_avg_i_vals), 0x0,
                "Maximum TX power level an MS is allowed to use on all other than DCS 1800 and PCS 1900 frequency bands when accessing the system until otherwise commanded (LB MS TxPwr Max CCCH)", HFILL }
            },
            { &hf_gsm_a_rr_si2n_support,
              { "SI2n Support", "gsm_a.rr.si2n_support",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_si2n_support_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_mi_index,
              { "Measurement Information Index", "gsm_a.rr.mi_index",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_mi_count,
              { "Measurement Information Count", "gsm_a.rr.mi_count",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_3g_wait,
              { "3G Wait", "gsm_a.rr.3g_wait",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_3g_wait_vals), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_qsearch_c,
              { "Qsearch C", "gsm_a.rr.qsearch_c",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_qsearch_x_vals), 0x00,
                "Search for 3G cells if signal level is below (0 7) or above (8 15) threshold (Qsearch C)", HFILL }
            },
            { &hf_gsm_a_rr_bsic_seen,
              { "BSIC Seen", "gsm_a.rr.bsic_seen",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_bsic_seen_value), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_scale,
              { "Scale", "gsm_a.rr.scale",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_scale_value), 0x0,
                "Offset applied for the reported RXLEV values (Scale)", HFILL }
            },
            { &hf_gsm_a_rr_mean_bep_gmsk,
              { "Mean BEP GMSK", "gsm_a.rr.mean_bep_gmsk",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_mean_bep_gmsk_vals), 0x00,
                "Mean Bit Error Probability in GMSK (Mean BEP GMSK)", HFILL }
            },
            { &hf_gsm_a_rr_mean_cv_bep,
              { "CV BEP", "gsm_a.rr.cv_bep",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_cv_bep_vals), 0x00,
                "Coefficient of Variation of the Bit Error Probability (CV BEP)", HFILL }
            },
            { &hf_gsm_a_rr_nbr_rcvd_blocks,
              { "Nb Rcvd Blocks", "gsm_a.rr.nbr_rcvd_blocks",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Number of correctly decoded blocks that were completed during the measurement report period (Nb Rcvd Blocks)", HFILL }
            },
            { &hf_gsm_a_rr_reporting_quantity,
              { "Reporting Quantity", "gsm_a.rr.reporting_quantity",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_3g_priority_param_desc_utran_start,
              { "UTRAN Start", "gsm_a.rr.3g_priority.utran_start",
                FT_BOOLEAN, BASE_NONE, TFS(&priority_utran_start), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_3g_priority_param_desc_utran_stop,
              { "UTRAN Stop", "gsm_a.rr.3g_priority.utran_stop",
                FT_BOOLEAN, BASE_NONE, TFS(&priority_utran_stop), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_3g_priority_param_desc_default_utran_prio,
              { "DEFAULT_UTRAN_PRIORITY", "gsm_a.rr.3g_priority.default_utran_prio",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_3g_priority_param_desc_default_threshold_utran,
              { "DEFAULT_THRESH_UTRAN", "gsm_a.rr.3g_priority.default_threshold_utran",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_thresh_utran_eutran_high_low), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_3g_priority_param_desc_default_utran_qrxlevmin,
              { "DEFAULT_UTRAN_QRXLEVMIN", "gsm_a.rr.3g_priority.default_utran_qrxlevmin",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_utran_qrxlevmin), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_utran_frequency_index,
              { "UTRAN Frequency Index", "gsm_a.rr.3g_priority.utran_frequency_index",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_utran_priority,
              { "UTRAN_PRIORITY", "gsm_a.rr.3g_priority.utran_priority",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_thresh_utran_high,
              { "THRESH_UTRAN_high", "gsm_a.rr.3g_priority.thres_utran_high",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_thresh_utran_eutran_high_low), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_thresh_utran_low,
              { "THRESH_UTRAN_low", "gsm_a.rr.3g_priority.thres_utran_low",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_thresh_utran_eutran_high_low), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_utran_qrxlevmin,
              { "UTRAN_QRXLEVMIN", "gsm_a.rr.3g_priority.utran_qrxlevmin",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_utran_qrxlevmin), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_ccn_active,
              { "E-UTRAN_CCN_ACTIVE", "gsm_a.rr.3g_priority.eutran_ccn_active",
                FT_BOOLEAN, BASE_NONE, TFS(&eutran_ccn_active), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_start,
              { "E-UTRAN Start", "gsm_a.rr.3g_priority.eutran_start",
                FT_BOOLEAN, BASE_NONE, TFS(&priority_utran_start), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_stop,
              { "E-UTRAN Stop", "gsm_a.rr.3g_priority.utran_stop",
                FT_BOOLEAN, BASE_NONE, TFS(&priority_utran_stop), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_qsearch_c_eutran_initial,
              { "Qsearch_C_E-UTRAN_Initial", "gsm_a.rr.qsearch_c_eutran_initial",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_qsearch_c_eutran_initial), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_multirat_reporting,
              { "E-UTRAN_MULTIRAT_REPORTING (nb of E-UTRAN cells to be included in measurement report)", "gsm_a.rr.eutran_multirat_reporting",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_fdd_reporting_threshold_rsrp,
              { "E-UTRAN_FDD_REPORTING_THRESHOLD", "gsm_a.rr.eutran_fdd_reporting_threshold_rsrp",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_lte_rsrp_reporting_threshold_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_fdd_reporting_threshold_rsrq,
              { "E-UTRAN_FDD_REPORTING_THRESHOLD", "gsm_a.rr.eutran_fdd_reporting_threshold_rsrq",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_lte_rsrq_reporting_threshold_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_fdd_reporting_threshold_2,
              { "E-UTRAN_FDD_REPORTING_THRESHOLD_2", "gsm_a.rr.eutran_fdd_reporting_threshold_2",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_fdd_reporting_offset,
              { "E-UTRAN_FDD_REPORTING_OFFSET", "gsm_a.rr.eutran_fdd_reporting_offset",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_tdd_reporting_threshold_rsrp,
              { "E-UTRAN_TDD_REPORTING_THRESHOLD", "gsm_a.rr.eutran_tdd_reporting_threshold_rsrp",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_lte_rsrp_reporting_threshold_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_tdd_reporting_threshold_rsrq,
              { "E-UTRAN_TDD_REPORTING_THRESHOLD", "gsm_a.rr.eutran_tdd_reporting_threshold_rsrq",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_lte_rsrq_reporting_threshold_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_tdd_reporting_threshold_2,
              { "E-UTRAN_TDD_REPORTING_THRESHOLD_2", "gsm_a.rr.eutran_tdd_reporting_threshold_2",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_tdd_reporting_offset,
              { "E-UTRAN_TDD_REPORTING_OFFSET", "gsm_a.rr.eutran_tdd_reporting_offset",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_fdd_measurement_report_offset,
              { "E-UTRAN_FDD_MEASUREMENT_REPORT_OFFSET", "gsm_a.rr.eutran_fdd_measurement_report_offset",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_tdd_measurement_report_offset,
              { "E-UTRAN_TDD_MEASUREMENT_REPORT_OFFSET", "gsm_a.rr.eutran_tdd_measurement_report_offset",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_reporting_granularity,
              { "REPORTING_GRANULARITY", "gsm_a.rr.reporting_granularity",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_default_measurement_control_eutran,
              { "DEFAULT_Measurement_Control_E-UTRAN", "gsm_a.rr.eutran_default_measurement_control_eutran",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_measurement_control_eutran,
              { "Measurement_Control_E-UTRAN", "gsm_a.rr.eutran_measurement_control_eutran",
                FT_BOOLEAN, BASE_NONE, TFS(&measurement_control_eutran), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_qsearch_p_eutran,
              { "Qsearch_P_E-UTRAN", "gsm_a.rr.qsearch_p_eutran",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_serving_cell_priority_param_geran_priority,
              { "GERAN_PRIORITY", "gsm_a.rr.serving_cell_priority_param_geran_priority",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_serving_cell_priority_param_thresh_prio_search,
              { "THRESH_Priority_Search", "gsm_a.rr.serving_cell_priority_param_thresh_prio_search",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_serving_cell_thresh_priority_search), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_serving_cell_priority_param_thresh_gsm_low,
              { "THRESH_GSM_low", "gsm_a.rr.serving_cell_priority_param_thresh_gsm_low",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_serving_cell_thresh_gsm_low), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_serving_cell_priority_param_h_prio,
              { "H_PRIO", "gsm_a.rr.serving_cell_priority_param_h_prio",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_serving_cell_priority_param_h_prio), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_serving_cell_priority_param_t_reselection,
              { "T_Reselection", "gsm_a.rr.serving_cell_priority_param_t_reselection",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_serving_cell_priority_param_t_reselection), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_earfcn,
              { "EARFCN", "gsm_a.rr.earfcn",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_measurement_bandwidth,
              { "Measurement Bandwidth", "gsm_a.rr.eutran_measurement_bandwidth",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_eutran_measurement_bandwidth), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_priority,
              { "E-UTRAN_PRIORITY", "gsm_a.rr.eutran_priority",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_thresh_eutran_high,
              { "THRESH_EUTRAN_high", "gsm_a.rr.thresh_eutran_high",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_thresh_utran_eutran_high_low), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_thresh_eutran_low,
              { "THRESH_EUTRAN_low", "gsm_a.rr.thresh_eutran_low",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_thresh_utran_eutran_high_low), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_qrxlevmin,
              { "E-UTRAN_QRXLEVMIN", "gsm_a.rr.eutran_qrxlevmin",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_eutran_qrxlevmin), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_pcid,
              { "PCID", "gsm_a.rr.pcid",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_pcid_bitmap_group,
              { "PCID_BITMAP_GROUP", "gsm_a.rr.pcid_bitmap_group",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_pcid_pattern_length,
              { "PCID_Pattern_length", "gsm_a.rr.pcid_pattern_length",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_pcid_psc_pattern_length), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_pcid_pattern,
              { "PCID_Pattern", "gsm_a.rr.pcid_pattern",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_pcid_pattern_sense,
              { "PCID_pattern_sense", "gsm_a.rr.pcid_pattern_sense",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rr_pcid_pattern_sense), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_frequency_index,
              { "E-UTRAN_FREQUENCY_INDEX", "gsm_a.rr.eutran_frequency_index",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_psc,
              { "PSC", "gsm_a.rr.psc",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_utran_psc_pattern_length,
              { "PSC_Pattern_length", "gsm_a.rr.psc_pattern_length",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_pcid_psc_pattern_length), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_utran_psc_pattern_sense,
              { "PSC_pattern_sense", "gsm_a.rr.psc_pattern_sense",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_utran_csg_fdd_uarfcn,
              { "CSG FDD UARFCN", "gsm_a.rr.utran_csg_fdd_uarfcn",
                FT_UINT16, BASE_DEC,  NULL, 0x0000,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_utran_csg_tdd_uarfcn,
              { "CSG TDD UARFCN", "gsm_a.rr.utran_csg_tdd_uarfcn",
                FT_UINT16, BASE_DEC,  NULL, 0x0000,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_csg_earfcn,
              { "CSG_EARFCN", "gsm_a.rr.csg_earfcn",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_3g_control_param_desc_meas_ctrl_utran,
              { "PCID_pattern_sense", "gsm_a.rr.meas_ctrl_utran",
                FT_BOOLEAN, BASE_NONE, TFS(&measurement_control_utran), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_extended_ra,
              { "Extended_RA", "gsm_a.rr.extended_ra",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_access_tech_type,
              { "Access_Technology_Type", "gsm_a.rr.access_tech_type",
                FT_UINT8, BASE_DEC, VALS(gsm_a_access_tech_type_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_tfi_assignment,
              { "TFI_Assignment", "gsm_a.rr.tfi_assignment",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_polling,
              { "Polling", "gsm_a.rr.polling",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_polling_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_usf,
              { "USF", "gsm_a.rr.usf",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_usf_granularity,
              { "USF_granularity", "gsm_a.rr.usf_granularity",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_usf_granularity_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_p0,
              { "P0", "gsm_a.rr.p0",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_pr_mode,
              { "pr_mode", "gsm_a.rr.pr_mode",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_egprs_mcs,
              { "Egprs_Modulation_and_Coding_Scheme", "gsm_a.rr.egprs_mcs",
                FT_UINT8, BASE_DEC, VALS(gsm_a_egprs_mcs_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_tlli_block_channel_coding,
              { "TLLI_Block_Channel_Coding", "gsm_a.rr.tlli_block_cs",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_tlli_block_channel_coding_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_bep_period2,
              { "Bep_Period2", "gsm_a.rr.bep_period2",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_resegment,
              { "Resegment", "gsm_a.rr.resegment",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_resegment_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_egprs_window_size,
              { "Egprs_Windows_Size", "gsm_a.rr.egprs_win_size",
                FT_UINT8, BASE_DEC, VALS(gsm_a_egprs_windows_size_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_gamma,
              { "Gamma", "gsm_a.rr.gamma",
                FT_UINT8, BASE_DEC, VALS(gsm_a_rr_gamma_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_timing_adv_index,
              { "Timing_Advance_Index", "gsm_a.rr.timing_adv_idx",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_tbf_starting_time,
              { "TBF_Starting_Time", "gsm_a.rr.tvf_start_time",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_num_of_radio_block_allocated,
              { "Number_of_Radio_Block_Allocated", "gsm_a.rr.num_of_radio_blk_allocated",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_pfi,
              { "PFI", "gsm_a.rr.pfi",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_mbms_service_id,
              { "MBMS_Service_ID", "gsm_a.rr.mbms_service_id",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_ms_id,
              { "MS_ID", "gsm_a.rr.ms_id",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_timing_adv_timeslot_num,
              { "Timing_Advance_Timeslot_Number", "gsm_a.rr.timing_adv_ts",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_gprs_cs,
              { "Channel_Coding_Command", "gsm_a.rr.gprs_cs",
                FT_UINT8, BASE_DEC, VALS(gsm_a_gprs_cs_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_rlc_mode,
              { "RLC_Mode", "gsm_a.rr.rlc_mode",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_rlc_mode_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_ta_valid,
              { "TA_Valid", "gsm_a.rr.ta_valid",
                FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_ta_valid_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_link_quality_meas_mode,
              { "Link_Quality_Measure_Mode", "gsm_a.rr.link_qual_meas_mode",
                FT_UINT8, BASE_DEC, VALS(gsm_a_link_quality_meas_mode_vals), 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_emr_bitmap_length,
              { "BITMAP_LENGTH", "gsm_a.rr.emr_bitmap_len",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_mr_n_eutran,
              { "N_E-UTRAN", "gsm_a.rr.eutran_mr_n_eutran",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_mr_freq_idx,
              { "E-UTRAN_FREQUENCY_INDEX", "gsm_a.rr.eutran_mr_freq_idx",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_mr_cell_id,
              { "CELL IDENTITY", "gsm_a.rr.eutran_mr_cell_id",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_eutran_mr_rpt_quantity,
              { "REPORTING_QUANTITY", "gsm_a.rr.eutran_mr_rpt_quantity",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_ma_channel_set,
              { "Channel Set", "gsm_a.rr.ma_channel_set",
                FT_UINT8, BASE_HEX, NULL, 0x00,
                NULL, HFILL }
            },
            { &hf_n_range_orig_arfcn,
              { "ORIG-ARFCN", "gsm_a.rr.orig_arfcn",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                NULL, HFILL }
            },
        };

    static hf_register_info hf_rr_short_pd[] =
        {
           { &hf_gsm_a_rr_short_pd,
             { "Radio Resources Short Protocol Discriminator", "gsm_a.rr.short_pd",
               FT_UINT8, BASE_HEX, NULL, 0x0,
               NULL, HFILL }
           },
            { &hf_gsm_a_rr_short_pd_msg_type,
              { "Radio Resources Short PD Message Type", "gsm_a.rr.short_pd_type",
                FT_UINT8, BASE_HEX, VALS(gsm_a_rr_short_pd_msg_strings), 0x0,
                NULL, HFILL }
            },
            { &hf_gsm_a_rr_short_l2_header,
              { "Radio Resources Short L2 Header", "gsm_a.rr.short_l2_header",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
            }
        };

    /* Setup protocol subtree array */
#define NUM_INDIVIDUAL_ELEMS    3
    gint *ett[NUM_INDIVIDUAL_ELEMS +
              NUM_GSM_DTAP_MSG_RR +
              NUM_GSM_RR_ELEM +
              NUM_GSM_RR_REST_OCTETS_ELEM +
              NUM_GSM_SACCH_MSG_RR];

    ett[0] = &ett_ccch_msg;
    ett[1] = &ett_ccch_oct_1;
    ett[2] = &ett_sacch_msg;

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

    for (i=0; i < NUM_GSM_SACCH_MSG_RR; i++, last_offset++)
    {
        ett_gsm_sacch_msg_rr[i] = -1;
        ett[last_offset] = &ett_gsm_sacch_msg_rr[i];
    }

    /* Register the protocol name and description */
    proto_a_rr =
        proto_register_protocol("GSM A-I/F Radio Resource Management", "GSM RR", "gsm_a.rr");

    proto_register_field_array(proto_a_rr, hf, array_length(hf));

    /* Register the protocol name and description */
    proto_a_ccch =
        proto_register_protocol("GSM CCCH", "GSM CCCH", "gsm_a.ccch");

    /* subdissector code */
    register_dissector("gsm_a_ccch", dissect_ccch, proto_a_ccch);

    /* Register the protocol name and description */
    proto_a_sacch =
        proto_register_protocol("GSM SACCH", "GSM SACCH", "gsm_a.sacch");

    proto_register_field_array(proto_a_sacch, hf_rr_short_pd, array_length(hf_rr_short_pd));

    /* subdissector code */
    register_dissector("gsm_a_sacch", dissect_sacch, proto_a_sacch);

    /* subtree array (for both sub-dissectors) */
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_gsm_a_rr(void)
{
    data_handle = find_dissector("data");
    rrc_irat_ho_info_handle = find_dissector("rrc.irat.irat_ho_info");
    rrc_irat_ho_to_utran_cmd_handle = find_dissector("rrc.irat.ho_to_utran_cmd");
    rrlp_dissector = find_dissector("rrlp");
}
