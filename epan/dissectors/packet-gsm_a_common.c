/* packet-gsm_a_common.c
 * Common routines for GSM A Interface dissection
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Split from packet-gsm_a.c by Neil Piercy <Neil [AT] littlebriars.co.uk>
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

#include <math.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tap.h>

#include "packet-bssap.h"
#include "packet-sccp.h"
#include "packet-gsm_a_common.h"
#include "packet-e212.h"


const value_string gsm_common_elem_strings[] = {
    /* Common Information Elements 10.5.1 */
    { 0x00, "Cell Identity" },
    { 0x00, "Ciphering Key Sequence Number" },
    { 0x00, "Location Area Identification (LAI)" },
    { 0x00, "Mobile Identity" },
    { 0x00, "Mobile Station Classmark 1" },
    { 0x00, "Mobile Station Classmark 2" },
    { 0x00, "Mobile Station Classmark 3" },
    { 0x00, "Spare Half Octet" },
    { 0x00, "Descriptive group or broadcast call reference" },
    { 0x00, "Group Cipher Key Number" },
    { 0x00, "PD and SAPI $(CCBS)$" },
    { 0x00, "Priority Level" },
    { 0x00, "CN Common GSM-MAP NAS system information" },
    { 0x00, "CS domain specific system information" },
    { 0x00, "PS domain specific system information" },
    { 0x00, "PLMN List" },
    { 0x00, "NAS container for PS HO" },
    { 0x00, "MS network feature support" },
    { 0, NULL }
};

static const value_string gsm_a_skip_ind_vals[] = {
    { 0, "No indication of selected PLMN"},
    { 1, "First PLMN in the broadcast system information"},
    { 2, "Second PLMN in the broadcast system information"},
    { 3, "Third PLMN in the broadcast system information"},
    { 4, "Fourth PLMN in the broadcast sytem information"},
    { 5, "Fifth PLMN in the broadcast system information"},
    { 6, "Reserved"},
    { 7, "Reserved"},
    { 0, NULL }
};

static const true_false_string gsm_a_extension_value = {
    "No Extension",
    "Extended"
};


/* Mobile Station Classmark Value strings
 */

/* Mobile Station Classmark
 * Revision level
 */
static const value_string gsm_a_msc_rev_vals[] = {
    { 0,    "Reserved for GSM phase 1"},
    { 1,    "Used by GSM phase 2 mobile stations"},
    { 2,    "Used by mobile stations supporting R99 or later versions of the protocol"},
    { 3,    "Reserved for future use"},
    { 0,    NULL }
};

/* ES IND (octet 3, bit 5) "Controlled Early Classmark Sending" option implementation */
static const true_false_string ES_IND_vals = {
    "Controlled Early Classmark Sending option is implemented in the MS",
    "Controlled Early Classmark Sending option is not implemented in the MS"
};
/* A5/1 algorithm supported (octet 3, bit 4) */
static const true_false_string A5_1_algorithm_sup_vals = {
    "encryption algorithm A5/1 not available",
    "encryption algorithm A5/1 available"
};
/* RF Power Capability (Octet 3) */
static const value_string RF_power_capability_vals[] = {
    { 0,    "class 1"},
    { 1,    "class 2"},
    { 2,    "class 3"},
    { 3,    "class 4"},
    { 4,    "class 5"},
    { 7,    "RF Power capability is irrelevant in this information element"},
    { 0,    NULL }
};
/* PS capability (pseudo-synchronization capability) (octet 4) */
static const true_false_string ps_sup_cap_vals = {
    "PS capability present",
    "PS capability not present"
};
/* SS Screening Indicator (octet 4)defined in 3GPP TS 24.080 */
static const value_string SS_screening_indicator_vals[] = {
    { 0,    "Default value of phase 1"},
    { 1,    "Capability of handling of ellipsis notation and phase 2 error handling "},
    { 2,    "For future use"},
    { 3,    "For future use"},
    { 0,    NULL }
};
/* SM capability (MT SMS pt to pt capability) (octet 4)*/
static const true_false_string SM_capability_vals = {
    "Mobile station supports mobile terminated point to point SMS",
    "Mobile station does not support mobile terminated point to point SMS"
};
/* VBS notification reception (octet 4) */
static const true_false_string VBS_notification_rec_vals = {
    "VBS capability and notifications wanted",
    "no VBS capability or no notifications wanted"
};
/* VGCS notification reception (octet 4) */
static const true_false_string VGCS_notification_rec_vals = {
    "VGCS capability and notifications wanted",
    "no VGCS capability or no notifications wanted"
};
/* FC Frequency Capability (octet 4 ) */
static const true_false_string FC_frequency_cap_vals = {
    "The MS does support the E-GSM or R-GSM",
    "The MS does not support the E-GSM or R-GSM band"
};
/* CM3 (octet 5, bit 8) */
static const true_false_string CM3_vals = {
    "The MS supports options that are indicated in classmark 3 IE",
    "The MS does not support any options that are indicated in CM3"
};
/* LCS VA capability (LCS value added location request notification capability) (octet 5,bit 6) */
static const true_false_string LCS_VA_cap_vals = {
    "LCS value added location request notification capability supported",
    "LCS value added location request notification capability not supported"
};
/* UCS2 treatment (octet 5, bit 5) */
static const true_false_string UCS2_treatment_vals = {
    "the ME has no preference between the use of the default alphabet and the use of UCS2",
    "the ME has a preference for the default alphabet"
};
/* SoLSA (octet 5, bit 4) */
static const true_false_string SoLSA_vals = {
    "The ME supports SoLSA",
    "The ME does not support SoLSA"
};
/* CMSP: CM Service Prompt (octet 5, bit 3) */
static const true_false_string CMSP_vals = {
    "Network initiated MO CM connection request supported for at least one CM protocol",
    "Network initiated MO CM connection request not supported"
};
/* A5/7 algorithm supported */
static const true_false_string A5_7_algorithm_sup_vals = {
    "encryption algorithm A5/7 available",
    "encryption algorithm A5/7 not available"
};
/* A5/6 algorithm supported */
static const true_false_string A5_6_algorithm_sup_vals = {
    "encryption algorithm A5/6 available",
    "encryption algorithm A5/6 not available"
};
/* A5/5 algorithm supported */
static const true_false_string A5_5_algorithm_sup_vals = {
    "encryption algorithm A5/5 available",
    "encryption algorithm A5/5 not available"
};
/* A5/4 algorithm supported */
static const true_false_string A5_4_algorithm_sup_vals = {
    "encryption algorithm A5/4 available",
    "encryption algorithm A5/4 not available"
};
/* A5/3 algorithm supported (octet 5, bit 2) */
static const true_false_string A5_3_algorithm_sup_vals = {
    "encryption algorithm A5/3 available",
    "encryption algorithm A5/3 not available"
};
/* A5/2 algorithm supported (octet 5, bit 1) */
static const true_false_string A5_2_algorithm_sup_vals = {
    "encryption algorithm A5/2 available",
    "encryption algorithm A5/2 not available"
};

static const value_string mobile_identity_type_vals[] = {
    { 1,    "IMSI"},
    { 2,    "IMEI"},
    { 3,    "IMEISV"},
    { 4,    "TMSI/P-TMSI"},
    { 5,    "TMGI and optional MBMS Session Identity"}, /* ETSI TS 124 008 V6.8.0 (2005-03) p326 */
    { 0,    "No Identity"},
    { 0,    NULL }
};

static const true_false_string oddevenind_vals = {
    "Odd number of identity digits",
    "Even number of identity digits"
};

static const true_false_string true_false_vals = {
    "true",
    "false"
};

const value_string gsm_a_sms_vals[] = {
    {  0, "1/4 timeslot (~144 microseconds)" },
    {  1, "2/4 timeslot (~288 microseconds)" },
    {  2, "3/4 timeslot (~433 microseconds)" },
    {  3, "4/4 timeslot (~577 microseconds)" },
    {  4, "5/4 timeslot (~721 microseconds)" },
    {  5, "6/4 timeslot (~865 microseconds)" },
    {  6, "7/4 timeslot (~1009 microseconds)" },
    {  7, "8/4 timeslot (~1154 microseconds)" },
    {  8, "9/4 timeslot (~1298 microseconds)" },
    {  9, "10/4 timeslot (~1442 microseconds)" },
    { 10, "11/4 timeslot (~1586 microseconds)" },
    { 11, "12/4 timeslot (~1730 microseconds)" },
    { 12, "13/4 timeslot (~1874 microseconds)" },
    { 13, "14/4 timeslot (~2019 microseconds)" },
    { 14, "15/4 timeslot (~2163 microseconds)" },
    { 15, "16/4 timeslot (~2307 microseconds)" },
    {  0, NULL}
};

static const true_false_string ms_assisted_e_otd_vals = {
    "MS assisted E-OTD supported",
    "MS assisted E-OTD not supported"
};

static const true_false_string ms_based_e_otd_vals = {
    "MS based E-OTD supported",
    "MS based E-OTD not supported"
};

static const true_false_string ms_assisted_gps_vals = {
    "MS assisted GPS supported",
    "MS assisted GPS not supported"
};

static const true_false_string ms_based_gps_vals = {
    "MS based GPS supported",
    "MS based GPS not supported"
};

static const true_false_string ms_conventional_gps_vals = {
    "Conventional GPS supported",
    "Conventional GPS not supported"
};

static const true_false_string modulation_capability_vals = {
    "8-PSK supported for uplink transmission and downlink reception",
    "8-PSK supported for downlink reception only"
};

static const value_string eight_psk_rf_power_capability_vals[] = {
    { 0, "Reserved" },
    { 1, "Power class E1" },
    { 2, "Power class E2" },
    { 3, "Power class E3" },
    { 0, NULL}
};

static const value_string gsm_400_bands_supported_vals[] = {
    { 1, "GSM 480 supported, GSM 450 not supported" },
    { 2, "GSM 450 supported, GSM 480 not supported" },
    { 3, "GSM 450 supported, GSM 480 supported" },
    { 0, NULL}
};

static const true_false_string umts_fdd_rat_cap_vals = {
    "UMTS FDD supported",
    "UMTS FDD not supported"
};

static const true_false_string umts_384_mcps_tdd_rat_cap_vals = {
    "UMTS 3.84 Mcps TDD supported",
    "UMTS 3.84 Mcps TDD not supported"
};

static const true_false_string cdma_2000_rat_cap_vals = {
    "CDMA 2000 supported",
    "CDMA 2000 not supported"
};

static const value_string dtm_gprs_multi_slot_class_vals[] = {
    { 0, "Unused. If received, the network shall interpret this as 1" },
    { 1, "Multislot class 5 supported" },
    { 2, "Multislot class 9 supported" },
    { 3, "Multislot class 11 supported" },
    { 0, NULL}
};

static const true_false_string single_slot_dtm_vals = {
    "Single Slot DTM supported",
    "Single Slot DTM not supported"
};

static const value_string gsm_band_vals[] = {
    { 0, "E-GSM is supported" },
    { 1, "P-GSM is supported" },
    { 2, "GSM 1800 is supported" },
    { 3, "GSM 450 is supported" },
    { 4, "GSM 480 is supported" },
    { 5, "GSM 850 is supported" },
    { 6, "GSM 1900 is supported" },
    { 7, "GSM 750 is supported" },
    { 8, "GSM 710 is supported" },
    { 9, "T-GSM 810 is supported" },
    { 0, NULL}
};

static const true_false_string umts_128_mcps_tdd_rat_cap_vals = {
    "UMTS 1.28 Mcps TDD supported",
    "UMTS 1.28 Mcps TDD not supported"
};

static const true_false_string geran_feature_package_1_vals = {
    "GERAN feature package 1 supported",
    "GERAN feature package 1 not supported"
};

static const true_false_string flo_iu_cap_vals = {
    "FLO in GERAN Iu Mode supported",
    "FLO in GERAN Iu Mode not supported"
};

static const true_false_string geran_feature_package_2_vals = {
    "GERAN feature package 2 supported",
    "GERAN feature package 2 not supported"
};

static const value_string gmsk_multislot_power_prof_vals[] = {
    { 0, "GMSK_MULTISLOT_POWER_PROFILE 0" },
    { 1, "GMSK_MULTISLOT_POWER_PROFILE 1" },
    { 2, "GMSK_MULTISLOT_POWER_PROFILE 2" },
    { 3, "GMSK_MULTISLOT_POWER_PROFILE 3" },
    { 0, NULL}
};

static const value_string eight_psk_multislot_power_prof_vals[] = {
    { 0, "8-PSK_MULTISLOT_POWER_PROFILE 0" },
    { 1, "8-PSK_MULTISLOT_POWER_PROFILE 1" },
    { 2, "8-PSK_MULTISLOT_POWER_PROFILE 2" },
    { 3, "8-PSK_MULTISLOT_POWER_PROFILE 3" },
    { 0, NULL}
};

static const value_string t_gsm_400_bands_supported_vals[] = {
    { 1, "T-GSM 380 supported, T-GSM 410 not supported" },
    { 2, "T-GSM 410 supported, T-GSM 380 not supported" },
    { 3, "T-GSM 410 supported, T-GSM 380 supported" },
    { 0, NULL}
};

static const value_string downlink_adv_receiver_perf_vals[] = {
    { 0, "Downlink Advanced Receiver Performance not supported" },
    { 1, "Downlink Advanced Receiver Performance - phase I supported" },
    { 2, "Downlink Advanced Receiver Performance - phase II supported" },
    { 0, NULL}
};

static const true_false_string dtm_enhancements_cap_vals = {
    "The mobile station supports enhanced DTM CS establishment and release procedures",
    "The mobile station does not support enhanced DTM CS establishment and release procedures"
};

static const true_false_string offset_required_vals = {
    "The mobile station requires the offset",
    "The mobile station does not require the offset"
};

static const value_string dtm_gprs_high_multi_slot_class_vals[] = {
    { 0, "Unused. If received, the network shall interpret this as \"0 0 1\"" },
    { 1, "Multislot class 31 or 36 supported" },
    { 2, "Multislot class 32 or 37 supported" },
    { 3, "Multislot class 33 or 38 supported" },
    { 4, "Multislot class 41 supported" },
    { 5, "Multislot class 42 supported" },
    { 6, "Multislot class 43 supported" },
    { 7, "Multislot class 44 supported" },
    { 0, NULL}
};

static const true_false_string repeated_acch_cap_vals = {
    "The mobile station supports Repeated SACCH and Repeated Downlink FACCH",
    "The mobile station does not support Repeated SACCH"
};

static const true_false_string ciphering_mode_setting_cap_vals = {
    "The mobile station supports the Ciphering Mode Setting IE in the DTM ASSIGNMENT COMMAND message",
    "The mobile station does not support the Ciphering Mode Setting IE in the DTM ASSIGNMENT COMMAND message"
};

static const true_false_string additional_positioning_caps_vals = {
    "The mobile station supports additional positioning capabilities which can be retrieved using RRLP",
    "The mobile station does not support additional positioning capabilities which can be retrieved using RRLP"
};

static const true_false_string e_utra_fdd_support_vals = {
    "E-UTRA FDD supported",
    "E-UTRA FDD not supported"
};

static const true_false_string e_utra_tdd_support_vals = {
    "E-UTRA TDD supported",
    "E-UTRA TDD not supported"
};

static const true_false_string e_utra_meas_and_report_support_vals = {
    "E-UTRAN Neighbour Cell measurements and measurement reporting while having an RR connection supported",
    "E-UTRAN Neighbour Cell measurements and measurement reporting while having an RR connection not supported"
};

static const true_false_string prio_based_resel_support_vals = {
    "Priority-based cell reselection supported",
    "Priority-based cell reselection not supported"
};

static const true_false_string utra_csg_cells_reporting_vals = {
    "Reporting of UTRAN CSG cells supported",
    "Reporting of UTRAN CSG cells not supported"
};

static const value_string vamos_level_vals[] = {
    { 0, "VAMOS not supported" },
    { 1, "VAMOS I supported" },
    { 2, "VAMOS II supported" },
    { 3, "Unused. If received, the network shall interpret this as VAMOS II supported" },
    { 0, NULL}
};

const value_string tighter_cap_level_vals[] = {
    { 0, "TIGHTER not supported" },
    { 1, "TIGHTER supported for speech and signalling channels only" },
    { 2, "TIGHTER supported for speech and signalling channels and for GPRS and EGPRS, but not for EGPRS2" },
    { 3, "TIGHTER supported for speech and signalling channels and for GPRS, EGPRS and EGPRS2" },
    { 0, NULL}
};

static const value_string gsm_a_rr_rxlev_vals [] = {
    {  0, "< -110 dBm"},
    {  1, "-110 <= x < -109 dBm"},
    {  2, "-109 <= x < -108 dBm"},
    {  3, "-108 <= x < -107 dBm"},
    {  4, "-107 <= x < -106 dBm"},
    {  5, "-106 <= x < -105 dBm"},
    {  6, "-105 <= x < -104 dBm"},
    {  7, "-104 <= x < -103 dBm"},
    {  8, "-103 <= x < -102 dBm"},
    {  9, "-102 <= x < -101 dBm"},
    { 10, "-101 <= x < -100 dBm"},
    { 11, "-100 <= x < -99 dBm"},
    { 12, "-99 <= x < -98 dBm"},
    { 13, "-98 <= x < -97 dBm"},
    { 14, "-97 <= x < -96 dBm"},
    { 15, "-96 <= x < -95 dBm"},
    { 16, "-95 <= x < -94 dBm"},
    { 17, "-94 <= x < -93 dBm"},
    { 18, "-93 <= x < -92 dBm"},
    { 19, "-92 <= x < -91 dBm"},
    { 20, "-91 <= x < -90 dBm"},
    { 21, "-90 <= x < -89 dBm"},
    { 22, "-89 <= x < -88 dBm"},
    { 23, "-88 <= x < -87 dBm"},
    { 24, "-87 <= x < -86 dBm"},
    { 25, "-86 <= x < -85 dBm"},
    { 26, "-85 <= x < -84 dBm"},
    { 27, "-84 <= x < -83 dBm"},
    { 28, "-83 <= x < -82 dBm"},
    { 29, "-82 <= x < -81 dBm"},
    { 30, "-81 <= x < -80 dBm"},
    { 31, "-80 <= x < -79 dBm"},
    { 32, "-79 <= x < -78 dBm"},
    { 33, "-78 <= x < -77 dBm"},
    { 34, "-77 <= x < -76 dBm"},
    { 35, "-76 <= x < -75 dBm"},
    { 36, "-75 <= x < -74 dBm"},
    { 37, "-74 <= x < -73 dBm"},
    { 38, "-73 <= x < -72 dBm"},
    { 39, "-72 <= x < -71 dBm"},
    { 40, "-71 <= x < -70 dBm"},
    { 41, "-70 <= x < -69 dBm"},
    { 42, "-69 <= x < -68 dBm"},
    { 43, "-68 <= x < -67 dBm"},
    { 44, "-67 <= x < -66 dBm"},
    { 45, "-66 <= x < -65 dBm"},
    { 46, "-65 <= x < -64 dBm"},
    { 47, "-64 <= x < -63 dBm"},
    { 48, "-63 <= x < -62 dBm"},
    { 49, "-62 <= x < -61 dBm"},
    { 50, "-61 <= x < -60 dBm"},
    { 51, "-60 <= x < -59 dBm"},
    { 52, "-59 <= x < -58 dBm"},
    { 53, "-58 <= x < -57 dBm"},
    { 54, "-57 <= x < -56 dBm"},
    { 55, "-56 <= x < -55 dBm"},
    { 56, "-55 <= x < -54 dBm"},
    { 57, "-54 <= x < -53 dBm"},
    { 58, "-53 <= x < -52 dBm"},
    { 59, "-52 <= x < -51 dBm"},
    { 60, "-51 <= x < -50 dBm"},
    { 61, "-50 <= x < -49 dBm"},
    { 62, "-49 <= x < -48 dBm"},
    { 63, ">= -48 dBm"},
    { 0, NULL}
};
value_string_ext gsm_a_rr_rxlev_vals_ext = VALUE_STRING_EXT_INIT(gsm_a_rr_rxlev_vals);

/* Initialize the protocol and registered fields */
static int proto_a_common = -1;

int gsm_a_tap = -1;

int hf_gsm_a_common_elem_id = -1;
static int hf_gsm_a_l_ext = -1;
static int hf_gsm_a_imsi = -1;
int hf_gsm_a_tmsi = -1;
static int hf_gsm_a_imei = -1;
static int hf_gsm_a_imeisv = -1;

static int hf_gsm_a_MSC_rev = -1;
static int hf_gsm_a_ES_IND = -1;
static int hf_gsm_a_A5_1_algorithm_sup = -1;
static int hf_gsm_a_RF_power_capability = -1;
static int hf_gsm_a_ps_sup_cap = -1;
static int hf_gsm_a_SS_screening_indicator = -1;
static int hf_gsm_a_SM_capability = -1;
static int hf_gsm_a_VBS_notification_rec = -1;
static int hf_gsm_a_VGCS_notification_rec = -1;
static int hf_gsm_a_FC_frequency_cap = -1;
static int hf_gsm_a_CM3 = -1;
static int hf_gsm_a_LCS_VA_cap = -1;
static int hf_gsm_a_UCS2_treatment = -1;
static int hf_gsm_a_SoLSA = -1;
static int hf_gsm_a_CMSP = -1;
static int hf_gsm_a_A5_7_algorithm_sup = -1;
static int hf_gsm_a_A5_6_algorithm_sup = -1;
static int hf_gsm_a_A5_5_algorithm_sup = -1;
static int hf_gsm_a_A5_4_algorithm_sup = -1;
static int hf_gsm_a_A5_3_algorithm_sup = -1;
static int hf_gsm_a_A5_2_algorithm_sup = -1;

static int hf_gsm_a_odd_even_ind = -1;
static int hf_gsm_a_mobile_identity_type = -1;
static int hf_gsm_a_tmgi_mcc_mnc_ind = -1;
static int hf_gsm_a_mbs_ses_id_ind = -1;
static int hf_gsm_a_mbs_service_id = -1;
static int hf_gsm_a_mbs_session_id = -1;
static int hf_gsm_a_length = -1;
int hf_gsm_a_extension = -1;
int hf_gsm_a_L3_protocol_discriminator = -1;
int hf_gsm_a_call_prio = -1;
int hf_gsm_a_skip_ind = -1;
int hf_gsm_a_spare_bits = -1;
int hf_gsm_a_lac = -1;

static int hf_gsm_a_spare_nibble = -1;
static int hf_gsm_a_type_of_ciph_alg = -1;
static int hf_gsm_a_att = -1;
static int hf_gsm_a_nmo_1 = -1;
static int hf_gsm_a_nmo = -1;
static int hf_gsm_a_old_xid = -1;
static int hf_gsm_a_iov_ui = -1;
static int hf_gsm_a_ext_periodic_timers = -1;
static int hf_gsm_a_b7spare = -1;
int hf_gsm_a_b8spare = -1;
static int hf_gsm_a_multi_bnd_sup_fields = -1;
static int hf_gsm_a_pgsm_supported = -1;
static int hf_gsm_a_egsm_supported = -1;
static int hf_gsm_a_gsm1800_supported = -1;
static int hf_gsm_a_ass_radio_cap1 = -1;
static int hf_gsm_a_ass_radio_cap2 = -1;
static int hf_gsm_a_rsupport = -1;
static int hf_gsm_a_r_capabilities = -1;
static int hf_gsm_a_multislot_capabilities = -1;
static int hf_gsm_a_multislot_class = -1;
static int hf_gsm_a_ucs2_treatment = -1;
static int hf_gsm_a_extended_measurement_cap = -1;
static int hf_gsm_a_ms_measurement_capability = -1;
static int hf_gsm_a_sms_value =-1;
static int hf_gsm_a_sm_value =-1;
static int hf_gsm_a_key_seq = -1;
static int hf_gsm_a_ms_pos_method_cap_present = -1;
static int hf_gsm_a_ms_pos_method = -1;
static int hf_gsm_a_ms_assisted_e_otd = -1;
static int hf_gsm_a_ms_based_e_otd = -1;
static int hf_gsm_a_ms_assisted_gps = -1;
static int hf_gsm_a_ms_based_gps = -1;
static int hf_gsm_a_ms_conventional_gps = -1;
static int hf_gsm_a_ecsd_multi_slot_capability = -1;
static int hf_gsm_a_ecsd_multi_slot_class = -1;
static int hf_gsm_a_8_psk_struct_present = -1;
static int hf_gsm_a_8_psk_struct = -1;
static int hf_gsm_a_modulation_capability = -1;
static int hf_gsm_a_8_psk_rf_power_capability_1_present = -1;
static int hf_gsm_a_8_psk_rf_power_capability_1 = -1;
static int hf_gsm_a_8_psk_rf_power_capability_2_present = -1;
static int hf_gsm_a_8_psk_rf_power_capability_2 = -1;
static int hf_gsm_a_gsm_400_band_info_present = -1;
static int hf_gsm_a_gsm_400_bands_supported = -1;
static int hf_gsm_a_gsm_400_assoc_radio_cap = -1;
static int hf_gsm_a_gsm_850_assoc_radio_cap_present = -1;
static int hf_gsm_a_gsm_850_assoc_radio_cap = -1;
static int hf_gsm_a_gsm_1900_assoc_radio_cap_present = -1;
static int hf_gsm_a_gsm_1900_assoc_radio_cap = -1;
static int hf_gsm_a_cm3_A5_bits = -1;
static int hf_gsm_a_umts_fdd_rat_cap = -1;
static int hf_gsm_a_umts_384_mcps_tdd_rat_cap = -1;
static int hf_gsm_a_cdma_2000_rat_cap = -1;
static int hf_gsm_a_dtm_e_gprs_multi_slot_info_present = -1;
static int hf_gsm_a_dtm_gprs_multi_slot_class = -1;
static int hf_gsm_a_single_slot_dtm = -1;
static int hf_gsm_a_dtm_egprs_multi_slot_class_present = -1;
static int hf_gsm_a_dtm_egprs_multi_slot_class = -1;
static int hf_gsm_a_single_band_support = -1;
static int hf_gsm_a_gsm_band = -1;
static int hf_gsm_a_gsm_750_assoc_radio_cap_present = -1;
static int hf_gsm_a_gsm_750_assoc_radio_cap = -1;
static int hf_gsm_a_umts_128_mcps_tdd_rat_cap = -1;
static int hf_gsm_a_geran_feature_package_1 = -1;
static int hf_gsm_a_ext_dtm_e_gprs_multi_slot_info_present = -1;
static int hf_gsm_a_ext_dtm_gprs_multi_slot_class = -1;
static int hf_gsm_a_ext_dtm_egprs_multi_slot_class = -1;
static int hf_gsm_a_high_multislot_cap_present = -1;
static int hf_gsm_a_high_multislot_cap = -1;
static int hf_gsm_a_geran_iu_mode_support = -1;
static int hf_gsm_a_geran_iu_mode_cap = -1;
static int hf_gsm_a_geran_iu_mode_cap_length = -1;
static int hf_gsm_a_flo_iu_cap = -1;
static int hf_gsm_a_geran_feature_package_2 = -1;
static int hf_gsm_a_gmsk_multislot_power_prof = -1;
static int hf_gsm_a_8_psk_multislot_power_prof = -1;
static int hf_gsm_a_t_gsm_400_band_info_present = -1;
static int hf_gsm_a_t_gsm_400_bands_supported = -1;
static int hf_gsm_a_t_gsm_400_assoc_radio_cap = -1;
static int hf_gsm_a_t_gsm_900_assoc_radio_cap_present = -1;
static int hf_gsm_a_t_gsm_900_assoc_radio_cap = -1;
static int hf_gsm_a_downlink_adv_receiver_perf = -1;
static int hf_gsm_a_dtm_enhancements_cap = -1;
static int hf_gsm_a_dtm_e_gprs_high_multi_slot_info_present = -1;
static int hf_gsm_a_dtm_gprs_high_multi_slot_class = -1;
static int hf_gsm_a_offset_required = -1;
static int hf_gsm_a_dtm_egprs_high_multi_slot_class_present = -1;
static int hf_gsm_a_dtm_egprs_high_multi_slot_class = -1;
static int hf_gsm_a_repeated_acch_cap = -1;
static int hf_gsm_a_gsm_710_assoc_radio_cap_present = -1;
static int hf_gsm_a_gsm_710_assoc_radio_cap = -1;
static int hf_gsm_a_t_gsm_810_assoc_radio_cap_present = -1;
static int hf_gsm_a_t_gsm_810_assoc_radio_cap = -1;
static int hf_gsm_a_ciphering_mode_setting_cap = -1;
static int hf_gsm_a_additional_positioning_caps = -1;
static int hf_gsm_a_e_utra_fdd_support = -1;
static int hf_gsm_a_e_utra_tdd_support = -1;
static int hf_gsm_a_e_utra_meas_and_report_support = -1;
static int hf_gsm_a_prio_based_resel_support = -1;
static int hf_gsm_a_utra_csg_cells_reporting = -1;
static int hf_gsm_a_vamos_level = -1;
static int hf_gsm_a_tighter_cap = -1;
static int hf_gsm_a_selective_ciph_down_sacch = -1;

static int hf_gsm_a_geo_loc_type_of_shape = -1;
static int hf_gsm_a_geo_loc_sign_of_lat = -1;
static int hf_gsm_a_geo_loc_deg_of_lat =-1;
static int hf_gsm_a_geo_loc_deg_of_long =-1;
static int hf_gsm_a_geo_loc_uncertainty_code = -1;
static int hf_gsm_a_geo_loc_uncertainty_semi_major = -1;
static int hf_gsm_a_geo_loc_uncertainty_semi_minor = -1;
static int hf_gsm_a_geo_loc_orientation_of_major_axis = -1;
static int hf_gsm_a_geo_loc_uncertainty_altitude = -1;
static int hf_gsm_a_geo_loc_confidence = -1;
static int hf_gsm_a_geo_loc_no_of_points = -1;
static int hf_gsm_a_velocity_type = -1;
static int hf_gsm_a_bearing = -1;
static int hf_gsm_a_horizontal_speed = -1;
static int hf_gsm_a_uncertainty_speed = -1;
static int hf_gsm_a_h_uncertainty_speed = -1;
static int hf_gsm_a_v_uncertainty_speed = -1;
static int hf_gsm_a_vertical_speed = -1;
static int hf_gsm_a_d = -1;
static int hf_gsm_a_geo_loc_D = -1;
static int hf_gsm_a_geo_loc_altitude = -1;
static int hf_gsm_a_geo_loc_inner_radius = -1;
static int hf_gsm_a_geo_loc_uncertainty_radius = -1;
static int hf_gsm_a_geo_loc_offset_angle = -1;
static int hf_gsm_a_geo_loc_included_angle = -1;

static char a_bigbuf[1024];

sccp_msg_info_t* sccp_msg;
sccp_assoc_info_t* sccp_assoc;

#define NUM_GSM_COMMON_ELEM (sizeof(gsm_common_elem_strings)/sizeof(value_string))
gint ett_gsm_common_elem[NUM_GSM_COMMON_ELEM];


#define  ELLIPSOID_POINT 0
#define  ELLIPSOID_POINT_WITH_UNCERT_CIRC 1
#define  ELLIPSOID_POINT_WITH_UNCERT_ELLIPSE 3
#define  POLYGON 5
#define  ELLIPSOID_POINT_WITH_ALT 8
#define  ELLIPSOID_POINT_WITH_ALT_AND_UNCERT_ELLIPSOID 9
#define  ELLIPSOID_ARC 10
/*
4 3 2 1
0 0 0 0 Ellipsoid Point
0 0 0 1 Ellipsoid point with uncertainty Circle
0 0 1 1 Ellipsoid point with uncertainty Ellipse
0 1 0 1 Polygon
1 0 0 0 Ellipsoid point with altitude
1 0 0 1 Ellipsoid point with altitude and uncertainty Ellipsoid
1 0 1 0 Ellipsoid Arc
other values reserved for future use
*/

/* TS 23 032 Table 2a: Coding of Type of Shape */
static const value_string type_of_shape_vals[] = {
    { ELLIPSOID_POINT,                               "Ellipsoid Point"},
    { ELLIPSOID_POINT_WITH_UNCERT_CIRC,              "Ellipsoid point with uncertainty Circle"},
    { ELLIPSOID_POINT_WITH_UNCERT_ELLIPSE,           "Ellipsoid point with uncertainty Ellipse"},
    { POLYGON,                                       "Polygon"},
    { ELLIPSOID_POINT_WITH_ALT,                      "Ellipsoid point with altitude"},
    { ELLIPSOID_POINT_WITH_ALT_AND_UNCERT_ELLIPSOID, "Ellipsoid point with altitude and uncertainty Ellipsoid"},
    { ELLIPSOID_ARC,                                 "Ellipsoid Arc"},
    { 0,    NULL }
};

/* 3GPP TS 23.032 7.3.1 */
static const value_string sign_of_latitude_vals[] = {
    { 0,  "North"},
    { 1,  "South"},
    { 0,  NULL }
};

static const value_string dir_of_alt_vals[] = {
    { 0,  "Altitude expresses height"},
    { 1,  "Altitude expresses depth"},
    { 0,  NULL }
};

void
dissect_geographical_description(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree) {

    proto_item *lat_item, *long_item, *major_item, *minor_item, *alt_item, *uncer_item;
    /*proto_tree *subtree; */
    guint8      type_of_shape;
    /*guint8 no_of_points;*/
    int         offset = 0;
    int         length;
    guint8      value;
    guint32     value32;

    /*subtree = proto_item_add_subtree(item, ett_gsm_a_geo_desc);*/

    length = tvb_reported_length_remaining(tvb, 0);
    /* Geographical Location
     * The Location Estimate field is composed of 1 or more octets with an internal structure
     * according to section 7 in [23.032].
     */
    proto_tree_add_item(tree, hf_gsm_a_geo_loc_type_of_shape, tvb, 0, 1, ENC_BIG_ENDIAN);
    if (length < 2)
        return;
    type_of_shape = tvb_get_guint8(tvb,offset)>>4;
    switch (type_of_shape) {
    case ELLIPSOID_POINT:
        /* Ellipsoid Point */
    case ELLIPSOID_POINT_WITH_UNCERT_CIRC:
        /* Ellipsoid Point with uncertainty Circle */
    case ELLIPSOID_POINT_WITH_UNCERT_ELLIPSE:
        /* Ellipsoid Point with uncertainty Ellipse */
    case ELLIPSOID_POINT_WITH_ALT:
        /* Ellipsoid Point with Altitude */
    case ELLIPSOID_POINT_WITH_ALT_AND_UNCERT_ELLIPSOID:
        /* Ellipsoid Point with altitude and uncertainty ellipsoid */
    case ELLIPSOID_ARC:
        /* Ellipsoid Arc */
        offset++;
        if (length < 4)
            return;
        proto_tree_add_item(tree, hf_gsm_a_geo_loc_sign_of_lat, tvb, offset, 1, ENC_BIG_ENDIAN);

        value32  = tvb_get_ntoh24(tvb,offset)&0x7fffff;
        /* convert degrees (X/0x7fffff) * 90 = degrees */
        lat_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_deg_of_lat, tvb, offset, 3, ENC_BIG_ENDIAN);
        proto_item_append_text(lat_item, "(%.5f degrees)", (((double)value32/8388607) * 90));
        if (length < 7)
            return;
        offset    = offset + 3;
        value32   = tvb_get_ntoh24(tvb,offset)&0x7fffff;
        long_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_deg_of_long, tvb, offset, 3, ENC_BIG_ENDIAN);
        /* (X/0xffffff) *360 = degrees */
        proto_item_append_text(long_item, "(%.5f degrees)", (((double)value32/16777215) * 360));
        offset = offset + 3;
        if (type_of_shape == ELLIPSOID_POINT_WITH_UNCERT_CIRC) {
            /* Ellipsoid Point with uncertainty Circle */
            if (length < 8)
                return;
            /* Uncertainty code */
            value = tvb_get_guint8(tvb,offset)&0x7f;
            uncer_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_code, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(uncer_item, "(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
        }else if (type_of_shape == ELLIPSOID_POINT_WITH_UNCERT_ELLIPSE) {
            /* Ellipsoid Point with uncertainty Ellipse */
            /* Uncertainty semi-major octet 10
             * To convert to metres 10*(((1.1)^X)-1)
             */
            value      = tvb_get_guint8(tvb,offset) & 0x7f;
            major_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_semi_major, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(major_item, "(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
            offset++;
            /* Uncertainty semi-minor Octet 11
             * To convert to metres 10*(((1.1)^X)-1)
             */
            value      = tvb_get_guint8(tvb,offset)&0x7f;
            minor_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_semi_minor, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(minor_item, "(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
            offset++;
            /* Orientation of major axis octet 12
             * allowed value from 0-179 to convert
             * to actual degrees multiply by 2.
             */
            value = tvb_get_guint8(tvb,offset)&0x7f;
            proto_tree_add_uint(tree, hf_gsm_a_geo_loc_orientation_of_major_axis, tvb, offset, 1, value*2);
            offset++;
            /* Confidence */
            proto_tree_add_item(tree, hf_gsm_a_geo_loc_confidence, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
        }else if (type_of_shape == ELLIPSOID_POINT_WITH_ALT) {
            /* Ellipsoid Point with Altitude */
            /*D: Direction of Altitude */
            proto_tree_add_item(tree, hf_gsm_a_geo_loc_D, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* Altitude */
            proto_tree_add_item(tree, hf_gsm_a_geo_loc_altitude, tvb, offset, 2, ENC_BIG_ENDIAN);
        }else if (type_of_shape == ELLIPSOID_POINT_WITH_ALT_AND_UNCERT_ELLIPSOID) {
            /* Ellipsoid Point with altitude and uncertainty ellipsoid */
            /*D: Direction of Altitude octet 8,9 */
            proto_tree_add_item(tree, hf_gsm_a_geo_loc_D, tvb, offset, 1, ENC_BIG_ENDIAN);
            /* Altitude Octet 8,9*/
            proto_tree_add_item(tree, hf_gsm_a_geo_loc_altitude, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset = offset +2;
            /* Uncertainty semi-major octet 10
             * To convert to metres 10*(((1.1)^X)-1)
             */
            value      = tvb_get_guint8(tvb,offset)&0x7f;
            major_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_semi_major, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(major_item, "(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
            offset++;
            /* Uncertainty semi-minor Octet 11
             * To convert to metres 10*(((1.1)^X)-1)
             */
            value      = tvb_get_guint8(tvb,offset)&0x7f;
            minor_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_semi_minor, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(minor_item, "(%.1f m)", 10 * (pow(1.1, (double)value) - 1));
            offset++;
            /* Orientation of major axis octet 12
             * allowed value from 0-179 to convert
             * to actual degrees multiply by 2.
             */
            value = tvb_get_guint8(tvb,offset)&0x7f;
            proto_tree_add_uint(tree, hf_gsm_a_geo_loc_orientation_of_major_axis, tvb, offset, 1, value*2);
            offset++;
            /* Uncertainty Altitude 13
             * to convert to metres 45*(((1.025)^X)-1)
             */
            value = tvb_get_guint8(tvb,offset)&0x7f;
            alt_item = proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_altitude, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_item_append_text(alt_item, "(%.1f m)", 45 * (pow(1.025, (double)value) - 1));
            offset++;
            /* Confidence octet 14
             */
            proto_tree_add_item(tree, hf_gsm_a_geo_loc_confidence, tvb, offset, 1, ENC_BIG_ENDIAN);
        }else if (type_of_shape == ELLIPSOID_ARC) {
            /* Ellipsoid Arc */
            /* Inner radius */
            proto_tree_add_item(tree, hf_gsm_a_geo_loc_inner_radius, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset = offset + 2;
            /* Uncertainty radius */
            proto_tree_add_item(tree, hf_gsm_a_geo_loc_uncertainty_radius, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            /* Offset angle */
            proto_tree_add_item(tree, hf_gsm_a_geo_loc_offset_angle, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            /* Included angle */
            proto_tree_add_item(tree, hf_gsm_a_geo_loc_included_angle, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            /* Confidence */
            proto_tree_add_item(tree, hf_gsm_a_geo_loc_confidence, tvb, offset, 1, ENC_BIG_ENDIAN);
        }

        break;
    case POLYGON:                   /* Polygon */
        /* Number of points */
        proto_tree_add_item(tree, hf_gsm_a_geo_loc_no_of_points, tvb, offset, 1, ENC_BIG_ENDIAN);
#if 0
        no_of_points = tvb_get_guint8(tvb,offset)&0x0f;
        while ( no_of_points > 0) {
            offset++;

            no_of_points--;
        }
#endif
        break;
    default:
        break;
    }

}

/* TS 23.032
 * Ch. 8 Description of Velocity
 */
/* 8.6 Coding of Velocity Type */
static const value_string gsm_a_velocity_type_vals[] = {
    { 0,        "Horizontal Velocity"},
    { 1,        "Horizontal with Vertical Velocity"},
    { 2,        "Horizontal Velocity with Uncertainty"},
    { 3,        "Horizontal with Vertical Velocity and Uncertainty"},
    { 4,        "reserved for future use"},
    { 5,        "reserved for future use"},
    { 6,        "reserved for future use"},
    { 7,        "reserved for future use"},
    { 8,        "reserved for future use"},
    { 9,        "reserved for future use"},
    { 10,       "reserved for future use"},
    { 11,       "reserved for future use"},
    { 12,       "reserved for future use"},
    { 13,       "reserved for future use"},
    { 14,       "reserved for future use"},
    { 15,       "reserved for future use"},
    { 0,    NULL }
};

static const true_false_string gsm_a_dir_of_ver_speed_vals = {
    "Downward",
    "Upward"
};

guint16
dissect_description_of_velocity(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    proto_item *velocity_item;
    guint32     curr_offset;
    guint8      velocity_type, uncertainty_speed = 0;

    curr_offset = offset;

    /* Bit 8 - 5 Velocity Type */
    velocity_type = tvb_get_guint8(tvb,curr_offset);
    proto_tree_add_item(tree, hf_gsm_a_velocity_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    switch (velocity_type) {
    case 0:
        /* 8.12 Coding of Horizontal Velocity */
        /* Spare bits */
        proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 3, ENC_BIG_ENDIAN);
        /* Bearing is encoded in increments of 1 degree measured clockwise from North using a 9 bit binary coded number N. */
        proto_tree_add_bits_item(tree, hf_gsm_a_bearing, tvb, (curr_offset<<3)+7, 9, ENC_BIG_ENDIAN);
        curr_offset += 2;
        /* Horizontal speed is encoded in increments of 1 kilometre per hour using a 16 bit binary coded number N. */
        velocity_item = proto_tree_add_item(tree, hf_gsm_a_horizontal_speed, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(velocity_item, " km/h");
        curr_offset += 2;
        break;
    case 1:
        /* 8.13 Coding of Horizontal with Vertical Velocity */
        /* Spare bits */
        proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 2, ENC_BIG_ENDIAN);
        /* D: Direction of Vertical Speed */
        proto_tree_add_item(tree, hf_gsm_a_d, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* Bearing is encoded in increments of 1 degree measured clockwise from North using a 9 bit binary coded number N. */
        proto_tree_add_bits_item(tree, hf_gsm_a_bearing, tvb, (curr_offset<<3)+7, 9, ENC_BIG_ENDIAN);
        curr_offset += 2;
        /* Horizontal speed is encoded in increments of 1 kilometre per hour using a 16 bit binary coded number N. */
        velocity_item = proto_tree_add_item(tree, hf_gsm_a_horizontal_speed, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(velocity_item, " km/h");
        curr_offset += 2;
        /* Vertical Speed Octet 5
         * Vertical speed is encoded in increments of 1 kilometre per hour using 8 bits giving a number N between 0 and 28-1.
         */
        velocity_item = proto_tree_add_item(tree, hf_gsm_a_vertical_speed, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(velocity_item, " km/h");
        curr_offset++;
        break;
    case 2:
        /* 8.14 Coding of Horizontal Velocity with Uncertainty */
        /* Spare bits */
        proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 3, ENC_BIG_ENDIAN);
        /* Bearing is encoded in increments of 1 degree measured clockwise from North using a 9 bit binary coded number N. */
        proto_tree_add_bits_item(tree, hf_gsm_a_bearing, tvb, (curr_offset<<3)+7, 9, ENC_BIG_ENDIAN);
        curr_offset += 2;
        /* Horizontal speed is encoded in increments of 1 kilometre per hour using a 16 bit binary coded number N. */
        velocity_item = proto_tree_add_item(tree, hf_gsm_a_horizontal_speed, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(velocity_item, " km/h");
        curr_offset += 2;
        /* Uncertainty Speed Octet 5
         * Uncertainty speed is encoded in increments of 1 kilometre per hour using an 8 bit binary coded number N. The value of
         * N gives the uncertainty speed except for N=255 which indicates that the uncertainty is not specified.
         */
        uncertainty_speed = tvb_get_guint8(tvb,curr_offset);
        velocity_item = proto_tree_add_item(tree, hf_gsm_a_uncertainty_speed, tvb, offset, 2, ENC_BIG_ENDIAN);
        if (uncertainty_speed == 255) {
            proto_item_append_text(velocity_item, " not specified");
        }else{
            proto_item_append_text(velocity_item, " km/h");
        }
        offset++;
        break;
    case 3:
        /* 8.15 Coding of Horizontal with Vertical Velocity and Uncertainty */
        /* Spare bits */
        proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 2, ENC_BIG_ENDIAN);
        /* D: Direction of Vertical Speed */
        proto_tree_add_item(tree, hf_gsm_a_d, tvb, offset, 1, ENC_BIG_ENDIAN);
        /* Bearing is encoded in increments of 1 degree measured clockwise from North using a 9 bit binary coded number N. */
        proto_tree_add_bits_item(tree, hf_gsm_a_bearing, tvb, (curr_offset<<3)+7, 9, ENC_BIG_ENDIAN);
        curr_offset += 2;
        /* Horizontal speed is encoded in increments of 1 kilometre per hour using a 16 bit binary coded number N. */
        velocity_item = proto_tree_add_item(tree, hf_gsm_a_horizontal_speed, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(velocity_item, " km/h");
        curr_offset += 2;
        /* Vertical Speed Octet 5
         * Vertical speed is encoded in increments of 1 kilometre per hour using 8 bits giving a number N between 0 and 28-1.
         */
        velocity_item = proto_tree_add_item(tree, hf_gsm_a_vertical_speed, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(velocity_item, " km/h");
        curr_offset++;

        /* Horizontal Uncertainty Speed Octet 6 */
        uncertainty_speed = tvb_get_guint8(tvb,curr_offset);
        velocity_item = proto_tree_add_item(tree, hf_gsm_a_h_uncertainty_speed, tvb, offset, 2, ENC_BIG_ENDIAN);
        if (uncertainty_speed == 255) {
            proto_item_append_text(velocity_item, " not specified");
        }else{
            proto_item_append_text(velocity_item, " km/h");
        }
        offset++;

        /* Vertical Uncertainty Speed Octet 7 */
        uncertainty_speed = tvb_get_guint8(tvb,curr_offset);
        velocity_item = proto_tree_add_item(tree, hf_gsm_a_v_uncertainty_speed, tvb, offset, 2, ENC_BIG_ENDIAN);
        if (uncertainty_speed == 255) {
            proto_item_append_text(velocity_item, " not specified");
        }else{
            proto_item_append_text(velocity_item, " km/h");
        }
        offset++;

        break;
    default:
        break;
    }

    return(curr_offset-offset);
}

const char* get_gsm_a_msg_string(int pdu_type, int idx)
{
    const char *msg_string = NULL;

    switch (pdu_type) {
    case GSM_A_PDU_TYPE_BSSMAP:
        msg_string = gsm_bssmap_elem_strings[idx].strptr;
        break;
    case GSM_A_PDU_TYPE_DTAP:
        msg_string = gsm_dtap_elem_strings[idx].strptr;
        break;
    case GSM_A_PDU_TYPE_RP:
        msg_string = gsm_rp_elem_strings[idx].strptr;
        break;
    case GSM_A_PDU_TYPE_RR:
        msg_string = gsm_rr_elem_strings[idx].strptr;
        break;
    case GSM_A_PDU_TYPE_COMMON:
        msg_string = gsm_common_elem_strings[idx].strptr;
        break;
    case GSM_A_PDU_TYPE_GM:
        msg_string = gsm_gm_elem_strings[idx].strptr;
        break;
    case GSM_A_PDU_TYPE_BSSLAP:
        msg_string = gsm_bsslap_elem_strings[idx].strptr;
        break;
    case GSM_PDU_TYPE_BSSMAP_LE:
        msg_string = gsm_bssmap_le_elem_strings[idx].strptr;
        break;
    case NAS_PDU_TYPE_COMMON:
        msg_string = nas_eps_common_elem_strings[idx].strptr;
        break;
    case NAS_PDU_TYPE_EMM:
        msg_string = nas_emm_elem_strings[idx].strptr;
        break;
    case NAS_PDU_TYPE_ESM:
        msg_string = nas_esm_elem_strings[idx].strptr;
        break;
    case SGSAP_PDU_TYPE:
        msg_string = sgsap_elem_strings[idx].strptr;
        break;
    case BSSGP_PDU_TYPE:
        msg_string = bssgp_elem_strings[idx].strptr;
        break;
    case GMR1_IE_COMMON:
        msg_string = gmr1_ie_common_strings[idx].strptr;
        break;
    case GMR1_IE_RR:
        msg_string = gmr1_ie_rr_strings[idx].strptr;
        break;
    default:
        DISSECTOR_ASSERT_NOT_REACHED();
    }

    return msg_string;
}

static int get_hf_elem_id(int pdu_type)
{
    int         hf_elem_id = 0;

    switch (pdu_type) {
    case GSM_A_PDU_TYPE_BSSMAP:
        hf_elem_id = hf_gsm_a_bssmap_elem_id;
        break;
    case GSM_A_PDU_TYPE_DTAP:
        hf_elem_id = hf_gsm_a_dtap_elem_id;
        break;
    case GSM_A_PDU_TYPE_RP:
        hf_elem_id = hf_gsm_a_rp_elem_id;
        break;
    case GSM_A_PDU_TYPE_RR:
        hf_elem_id = hf_gsm_a_rr_elem_id;
        break;
    case GSM_A_PDU_TYPE_COMMON:
        hf_elem_id = hf_gsm_a_common_elem_id;
        break;
    case GSM_A_PDU_TYPE_GM:
        hf_elem_id = hf_gsm_a_gm_elem_id;
        break;
    case GSM_A_PDU_TYPE_BSSLAP:
        hf_elem_id = hf_gsm_a_bsslap_elem_id;
        break;
    case GSM_PDU_TYPE_BSSMAP_LE:
        hf_elem_id = hf_gsm_bssmap_le_elem_id;
        break;
    case NAS_PDU_TYPE_COMMON:
        hf_elem_id = hf_nas_eps_common_elem_id;
        break;
    case NAS_PDU_TYPE_EMM:
        hf_elem_id = hf_nas_eps_emm_elem_id;
        break;
    case NAS_PDU_TYPE_ESM:
        hf_elem_id = hf_nas_eps_esm_elem_id;
        break;
    case SGSAP_PDU_TYPE:
        hf_elem_id = hf_sgsap_elem_id;
        break;
    case BSSGP_PDU_TYPE:
        hf_elem_id = hf_bssgp_elem_id;
        break;
    case GMR1_IE_COMMON:
    case GMR1_IE_RR:
        hf_elem_id = hf_gmr1_elem_id;
        break;
    default:
        DISSECTOR_ASSERT_NOT_REACHED();
    }

    return hf_elem_id;
}

/*
 * Type Length Value (TLV) element dissector
 */
guint16 elem_tlv(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint8 iei, gint pdu_type, int idx, guint32 offset, guint len _U_, const gchar *name_add)
{
    guint8              oct;
    guint16             parm_len;
    guint8              lengt_length = 1;
    guint16             consumed;
    guint32             curr_offset;
    proto_tree         *subtree;
    proto_item         *item;
    const value_string *elem_names;
    gint               *elem_ett;
    guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len);

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == iei) {
        parm_len = tvb_get_guint8(tvb, curr_offset + 1);

        item =
        proto_tree_add_text(tree,
            tvb, curr_offset, parm_len + 1 + lengt_length,
            "%s%s",
            elem_names[idx].strptr,
            (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

        subtree = proto_item_add_subtree(item, elem_ett[idx]);

        proto_tree_add_uint(subtree,
            get_hf_elem_id(pdu_type), tvb,
            curr_offset, 1, oct);

        proto_tree_add_uint(subtree, hf_gsm_a_length, tvb,
            curr_offset + 1, lengt_length, parm_len);

        if (parm_len > 0)
        {
            if (elem_funcs[idx] == NULL)
            {
                proto_tree_add_text(subtree,
                    tvb, curr_offset + 1 + lengt_length, parm_len,
                    "Element Value");
                /* See ASSERT above */
                consumed = (guint8)parm_len;
            }
            else
            {
                gchar *a_add_string;

                a_add_string = (gchar *)ep_alloc(1024);
                a_add_string[0] = '\0';
                consumed =
                (*elem_funcs[idx])(tvb, subtree, pinfo, curr_offset + 2,
                    parm_len, a_add_string, 1024);

                if (a_add_string[0] != '\0')
                {
                    proto_item_append_text(item, "%s", a_add_string);
                }
            }
        }

        consumed += 1 + lengt_length;
    }

    return(consumed);
}

/*
 * Type Extendable Length Value (TELV) element dissector
 * This is a version where the length field can be one or two octets depending
 * if the extension bit is set or not (TS 48.016 p 10.1.2).
 *         8        7 6 5 4 3 2 1
 * octet 2 0/1 ext  length
 * octet 2a length
 */
guint16 elem_telv(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint8 iei, gint pdu_type, int idx, guint32 offset, guint len _U_, const gchar *name_add)
{
    guint8              oct;
    guint16             parm_len;
    guint8              lengt_length = 1;
    guint16             consumed;
    guint32             curr_offset;
    proto_tree         *subtree;
    proto_item         *item;
    const value_string *elem_names;
    gint               *elem_ett;
    guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len);

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == iei) {
        parm_len = tvb_get_guint8(tvb, curr_offset + 1);
        if ((parm_len&0x80) == 0) {
            /* length in 2 octets */
            parm_len = tvb_get_ntohs(tvb, curr_offset + 1);
            lengt_length = 2;
        }else{
            parm_len = parm_len & 0x7f;
        }

        item =
        proto_tree_add_text(tree,
            tvb, curr_offset, parm_len + 1 + lengt_length,
            "%s%s",
            elem_names[idx].strptr,
            (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

        subtree = proto_item_add_subtree(item, elem_ett[idx]);

        proto_tree_add_uint(subtree,
            get_hf_elem_id(pdu_type), tvb,
            curr_offset, 1, oct);

        proto_tree_add_item(subtree, hf_gsm_a_l_ext, tvb, curr_offset+1, 1, ENC_BIG_ENDIAN);

        proto_tree_add_uint(subtree, hf_gsm_a_length, tvb,
            curr_offset + 1, lengt_length, parm_len);

        if (parm_len > 0)
        {
            if (elem_funcs[idx] == NULL)
            {
                proto_tree_add_text(subtree,
                    tvb, curr_offset + 1 + lengt_length, parm_len,
                    "Element Value");
                /* See ASSERT above */
                consumed = parm_len;
            }
            else
            {
                gchar *a_add_string;

                a_add_string = (gchar*)ep_alloc(1024);
                a_add_string[0] = '\0';
                consumed =
                (*elem_funcs[idx])(tvb, subtree, pinfo, curr_offset + 1 + lengt_length,
                    parm_len, a_add_string, 1024);

                if (a_add_string[0] != '\0')
                {
                    proto_item_append_text(item, "%s", a_add_string);
                }
            }
        }

        consumed += 1 + lengt_length;
    }

    return(consumed);
}

/*
 * Type Length Value Extended(TLV-E) element dissector
 * TS 24.007
 * information elements of format LV-E or TLV-E with value part consisting of zero,
 * one or more octets and a maximum of 65535 octets (type 6). This category is used in EPS only.
 */
guint16 elem_tlv_e(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint8 iei, gint pdu_type, int idx, guint32 offset, guint len _U_, const gchar *name_add)
{
    guint8              oct;
    guint16             parm_len;
    guint16             consumed;
    guint32             curr_offset;
    proto_tree         *subtree;
    proto_item         *item;
    const value_string *elem_names;
    gint               *elem_ett;
    guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len);

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == iei) {
        parm_len = tvb_get_ntohs(tvb, curr_offset + 1);

        item = proto_tree_add_text(tree, tvb, curr_offset, parm_len + 1 + 2,
            "%s%s",
            elem_names[idx].strptr,
            (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

        subtree = proto_item_add_subtree(item, elem_ett[idx]);

        proto_tree_add_uint(subtree,
            get_hf_elem_id(pdu_type), tvb,
            curr_offset, 1, oct);

        proto_tree_add_uint(subtree, hf_gsm_a_length, tvb,
            curr_offset + 1, 2, parm_len);

        if (parm_len > 0)
        {
            if (elem_funcs[idx] == NULL)
            {
                proto_tree_add_text(subtree,
                    tvb, curr_offset + 1 + 2, parm_len,
                    "Element Value");
                /* See ASSERT above */
                consumed = parm_len;
            }
            else
            {
                gchar *a_add_string;

                a_add_string = (gchar*)ep_alloc(1024);
                a_add_string[0] = '\0';
                consumed =
                (*elem_funcs[idx])(tvb, subtree, pinfo, curr_offset + 1 + 2,
                    parm_len, a_add_string, 1024);

                if (a_add_string[0] != '\0')
                {
                    proto_item_append_text(item, "%s", a_add_string);
                }
            }
        }

        consumed += 1 + 2;
    }

    return(consumed);
}

/*
 * Type Value (TV) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
guint16 elem_tv(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
    guint8              oct;
    guint16             consumed;
    guint32             curr_offset;
    proto_tree         *subtree;
    proto_item         *item;
    const value_string *elem_names;
    gint               *elem_ett;
    guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len);

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == iei)
    {
        item =
            proto_tree_add_text(tree,
            tvb, curr_offset, -1,
            "%s%s",
            elem_names[idx].strptr,
                (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

        subtree = proto_item_add_subtree(item, elem_ett[idx]);

        proto_tree_add_uint(subtree,
            get_hf_elem_id(pdu_type), tvb,
            curr_offset, 1, oct);

        if (elem_funcs[idx] == NULL)
        {
            /* BAD THING, CANNOT DETERMINE LENGTH */

            proto_tree_add_text(subtree,
                tvb, curr_offset + 1, 1,
                "No element dissector, rest of dissection may be incorrect");

            consumed = 1;
        }
        else
        {
            gchar *a_add_string;

            a_add_string = (gchar*)ep_alloc(1024);
            a_add_string[0] = '\0';
            consumed = (*elem_funcs[idx])(tvb, subtree, pinfo, curr_offset + 1, -1, a_add_string, 1024);

            if (a_add_string[0] != '\0')
            {
                proto_item_append_text(item, "%s", a_add_string);
            }
        }

        consumed++;

        proto_item_set_len(item, consumed);
    }

    return(consumed);
}

/*
 * Type Value (TV) element dissector
 * Where top half nibble is IEI and bottom half nibble is value.
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
guint16 elem_tv_short(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
    guint8              oct;
    guint16             consumed;
    guint32             curr_offset;
    proto_tree         *subtree;
    proto_item         *item;
    const value_string *elem_names;
    gint               *elem_ett;
    guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len);
    char                buf[10+1];

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    oct = tvb_get_guint8(tvb, curr_offset);

    if ((oct & 0xf0) == (iei & 0xf0))
    {
        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, -1,
                "%s%s",
                elem_names[idx].strptr,
                (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

        subtree = proto_item_add_subtree(item, elem_ett[idx]);

        other_decode_bitfield_value(buf, oct, 0xf0, 8);
        proto_tree_add_text(subtree,
            tvb, curr_offset, 1,
            "%s = Element ID: 0x%1x-",
            buf, oct>>4);

        if (elem_funcs[idx] == NULL)
        {
            /* BAD THING, CANNOT DETERMINE LENGTH */

            proto_tree_add_text(subtree,
                tvb, curr_offset, 1,
                "No element dissector, rest of dissection may be incorrect");

            consumed++;
        }
        else
        {
            gchar *a_add_string;

            a_add_string = (gchar*)ep_alloc(1024);
            a_add_string[0] = '\0';
            consumed = (*elem_funcs[idx])(tvb, subtree, pinfo, curr_offset, RIGHT_NIBBLE, a_add_string, 1024);

            if (a_add_string[0] != '\0')
            {
                proto_item_append_text(item, "%s", a_add_string);
            }
        }

        proto_item_set_len(item, consumed);
    }

    return(consumed);
}

/*
 * Type (T) element dissector
 */
guint16 elem_t(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
    guint8              oct;
    guint32             curr_offset;
    guint16             consumed;
    const value_string *elem_names;
    gint               *elem_ett;
    guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len);

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == iei)
    {
        proto_tree_add_uint_format(tree,
            get_hf_elem_id(pdu_type), tvb,
            curr_offset, 1, oct,
            "%s%s",
            elem_names[idx].strptr,
            (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

        consumed = 1;
    }

    return(consumed);
}

/*
 * Length Value (LV) element dissector
 */
guint16
elem_lv(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint pdu_type, int idx, guint32 offset, guint len _U_, const gchar *name_add)
{
    guint8              parm_len;
    guint16             consumed;
    guint32             curr_offset;
    proto_tree         *subtree;
    proto_item         *item;
    const value_string *elem_names;
    gint               *elem_ett;
    guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len);

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    parm_len = tvb_get_guint8(tvb, curr_offset);

    item =
        proto_tree_add_text(tree,
            tvb, curr_offset, parm_len + 1,
            "%s%s",
            elem_names[idx].strptr,
            (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

    subtree = proto_item_add_subtree(item, elem_ett[idx]);

    proto_tree_add_uint(subtree, hf_gsm_a_length, tvb,
        curr_offset, 1, parm_len);

    if (parm_len > 0)
    {
        if (elem_funcs[idx] == NULL)
        {
            proto_tree_add_text(subtree,
                tvb, curr_offset + 1, parm_len,
                "Element Value");

            consumed = parm_len;
        }
        else
        {
            gchar *a_add_string;

            a_add_string = (gchar*)ep_alloc(1024);
            a_add_string[0] = '\0';
            consumed =
                (*elem_funcs[idx])(tvb, subtree, pinfo, curr_offset + 1,
                    parm_len, a_add_string, 1024);

            if (a_add_string[0] != '\0')
            {
                proto_item_append_text(item, "%s", a_add_string);
            }
        }
    }

    return(consumed + 1);
}

/*
 * Length Value Extended(LV-E) element dissector
 */
guint16 elem_lv_e(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint pdu_type, int idx, guint32 offset, guint len _U_, const gchar *name_add)
{
    guint16             parm_len;
    guint16             consumed;
    guint32             curr_offset;
    proto_tree         *subtree;
    proto_item         *item;
    const value_string *elem_names;
    gint               *elem_ett;
    guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len);

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    parm_len = tvb_get_ntohs(tvb, curr_offset);

    item = proto_tree_add_text(tree, tvb, curr_offset, parm_len + 2,
            "%s%s",
            elem_names[idx].strptr,
            (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

    subtree = proto_item_add_subtree(item, elem_ett[idx]);

    proto_tree_add_uint(subtree, hf_gsm_a_length, tvb,
        curr_offset, 2, parm_len);

    if (parm_len > 0)
    {
        if (elem_funcs[idx] == NULL)
        {
            proto_tree_add_text(subtree,
                tvb, curr_offset + 2, parm_len,
                "Element Value");

            consumed = parm_len;
        }
        else
        {
            gchar *a_add_string;

            a_add_string = (gchar*)ep_alloc(1024);
            a_add_string[0] = '\0';
            consumed =
                (*elem_funcs[idx])(tvb, subtree, pinfo, curr_offset + 2,
                    parm_len, a_add_string, 1024);

            if (a_add_string[0] != '\0')
            {
                proto_item_append_text(item, "%s", a_add_string);
            }
        }
    }

    return(consumed + 2);
}
/*
 * Value (V) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
guint16 elem_v(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
    guint16             consumed;
    guint32             curr_offset;
    proto_tree         *subtree;
    proto_item         *item;
    const value_string *elem_names;
    gint               *elem_ett;
    guint16 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len);

    curr_offset = offset;
    consumed = 0;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    if (elem_funcs[idx] == NULL)
    {
        /* BAD THING, CANNOT DETERMINE LENGTH */

        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "No element dissector, rest of dissection may be incorrect");

        consumed = 1;
    }
    else
    {
        gchar *a_add_string;

        item =
            proto_tree_add_text(tree,
                tvb, curr_offset, 0,
                "%s%s",
                elem_names[idx].strptr,
                (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

        subtree = proto_item_add_subtree(item, elem_ett[idx]);

        a_add_string= (gchar*)ep_alloc(1024);
        a_add_string[0] = '\0';
        consumed = (*elem_funcs[idx])(tvb, subtree, pinfo, curr_offset, -1, a_add_string, 1024);
        if (a_add_string[0] != '\0')
        {
            proto_item_append_text(item, "%s", a_add_string);
        }
        proto_item_set_len(item, consumed);
    }

    return(consumed);
}

/*
 * Short Value (V_SHORT) element dissector
 *
 * nibble is used in this function to indicate right or left nibble of the octet
 * This is expected to be used right nibble first, as the tables of 24.008.
 */

guint16 elem_v_short(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, gint pdu_type, int idx, guint32 offset, guint32 nibble)
{
    guint16             consumed = 1;
    guint32             curr_offset;
    proto_tree         *subtree;
    proto_item         *item;
    const value_string *elem_names;
    gint               *elem_ett;
    elem_fcn           *elem_funcs;
    gchar              *a_add_string;

    curr_offset = offset;

    SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

    item = proto_tree_add_text(tree,
            tvb, curr_offset, 0,
            "%s%s",
            elem_names[idx].strptr,
            "");

    subtree = proto_item_add_subtree(item, elem_ett[idx]);

    a_add_string= (gchar*)ep_alloc(1024);
    a_add_string[0] = '\0';

    if (elem_funcs[idx] == NULL)
    {
        /* NOT NECESSARILY A BAD THING - LENGTH IS HALF OCTET */
        (void)de_spare_nibble(tvb, subtree, pinfo, curr_offset, nibble, a_add_string, 1024);
    }
    else
    {
        (void)(*elem_funcs[idx])(tvb, subtree, pinfo, curr_offset, nibble, a_add_string, 1024);
    }

    if (a_add_string[0] != '\0')
    {
        proto_item_append_text(item, "%s", a_add_string);
    }
    proto_item_set_len(item, consumed);

    return(consumed);
}


static dgt_set_t Dgt_tbcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '0','1','2','3','4','5','6','7','8','9','?','B','C','*','#'
    }
};

static dgt_set_t Dgt1_9_bcd = {
    {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '0','1','2','3','4','5','6','7','8','9','?','?','?','?','?'
    }
};

/* FUNCTIONS */

/*
 * Unpack BCD input pattern into output ASCII pattern
 *
 * Input Pattern is supplied using the same format as the digits
 *
 * Returns: length of unpacked pattern
 */
int
my_dgt_tbcd_unpack(
    char    *out,       /* ASCII pattern out */
    guchar  *in,        /* packed pattern in */
    int     num_octs,   /* Number of octets to unpack */
    dgt_set_t   *dgt        /* Digit definitions */
    )
{
    int cnt = 0;
    unsigned char i;

    while (num_octs)
    {
        /*
         * unpack first value in byte
         */
        i = *in++;
        *out++ = dgt->out[i & 0x0f];
        cnt++;

        /*
         * unpack second value in byte
         */
        i >>= 4;

        if (i == 0x0f)  /* odd number bytes - hit filler */
            break;

        *out++ = dgt->out[i];
        cnt++;
        num_octs--;
    }

    *out = '\0';

    return(cnt);
}

/*
 * Decode the MCC/MNC from 3 octets in 'octs'
 */
static void
mcc_mnc_aux(guint8 *octs, gchar *mcc, gchar *mnc)
{
    if ((octs[0] & 0x0f) <= 9)
    {
        mcc[0] = Dgt_tbcd.out[octs[0] & 0x0f];
    }
    else
    {
        mcc[0] = (octs[0] & 0x0f) + 55;
    }

    if (((octs[0] & 0xf0) >> 4) <= 9)
    {
        mcc[1] = Dgt_tbcd.out[(octs[0] & 0xf0) >> 4];
    }
    else
    {
        mcc[1] = ((octs[0] & 0xf0) >> 4) + 55;
    }

    if ((octs[1] & 0x0f) <= 9)
    {
        mcc[2] = Dgt_tbcd.out[octs[1] & 0x0f];
    }
    else
    {
        mcc[2] = (octs[1] & 0x0f) + 55;
    }

    mcc[3] = '\0';

    if (((octs[1] & 0xf0) >> 4) <= 9)
    {
        mnc[2] = Dgt_tbcd.out[(octs[1] & 0xf0) >> 4];
    }
    else
    {
        mnc[2] = ((octs[1] & 0xf0) >> 4) + 55;
    }

    if ((octs[2] & 0x0f) <= 9)
    {
        mnc[0] = Dgt_tbcd.out[octs[2] & 0x0f];
    }
    else
    {
        mnc[0] = (octs[2] & 0x0f) + 55;
    }

    if (((octs[2] & 0xf0) >> 4) <= 9)
    {
        mnc[1] = Dgt_tbcd.out[(octs[2] & 0xf0) >> 4];
    }
    else
    {
        mnc[1] = ((octs[2] & 0xf0) >> 4) + 55;
    }

    if (mnc[1] == 'F')
    {
        /*
         * only a 1 digit MNC (very old)
         */
        mnc[1] = '\0';
    }
    else if (mnc[2] == 'F')
    {
        /*
         * only a 2 digit MNC
         */
        mnc[2] = '\0';
    }
    else
    {
        mnc[3] = '\0';
    }
}

/* 3GPP TS 24.008
 * [3] 10.5.1.1 Cell Identity
 */
guint16
de_cell_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint32 curr_offset;

    curr_offset = offset;

    curr_offset +=
    /* 0x02 CI */
    be_cell_id_aux(tvb, tree, pinfo, offset, len, add_string, string_len, 0x02);

    /* no length check possible */

    return(curr_offset - offset);
}
/*
 * 10.5.1.2 Ciphering Key Sequence Number
 */


/*
 * Key sequence (octet 1)
 * Bits
 * 3 2 1
 * 0 0 0
 * through
 * 1 1 0
 * Possible values for the ciphering key sequence number
 * 1 1 1 No key is available (MS to network);Reserved (network to MS)
 */

static const value_string gsm_a_key_seq_vals[] = {
    { 0, "Cipering key sequence number"},
    { 1, "Cipering key sequence number"},
    { 2, "Cipering key sequence number"},
    { 3, "Cipering key sequence number"},
    { 4, "Cipering key sequence number"},
    { 5, "Cipering key sequence number"},
    { 6, "Cipering key sequence number"},
    { 7, "No key is available (MS to network)"},
    { 0,    NULL }
};

static guint16
de_ciph_key_seq_num( tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_key_seq, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return(curr_offset - offset);
}


/*
 * [3] 10.5.1.3
 */

guint16
de_lai(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8      octs[3];
    guint16     value;
    guint32     curr_offset;
    proto_tree *subtree;
    proto_item *item;
    gchar       mcc[4];
    gchar       mnc[4];

    curr_offset = offset;

    item = proto_tree_add_text(tree,
                               tvb, curr_offset, 5, "%s",
                               gsm_common_elem_strings[DE_LAI].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_LAI]);

    octs[0] = tvb_get_guint8(tvb, curr_offset);
    octs[1] = tvb_get_guint8(tvb, curr_offset + 1);
    octs[2] = tvb_get_guint8(tvb, curr_offset + 2);

    mcc_mnc_aux(octs, mcc, mnc);

    curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, subtree, curr_offset, TRUE);

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_item(subtree, hf_gsm_a_lac, tvb, curr_offset, 2, ENC_BIG_ENDIAN);

    proto_item_append_text(item, " - %s/%s/%u", mcc,mnc,value);

    curr_offset += 2;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.4 Mobile Identity
 * 3GPP TS 24.008 version 7.8.0 Release 7
 */
static const true_false_string gsm_a_present_vals = {
    "Present" ,
    "Not present"
};

guint16
de_mid(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8    oct;
    guint32   curr_offset;
    guint8   *poctets;
    guint32   value;
    gboolean  odd;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    switch (oct & 0x07)
    {
    case 0: /* No Identity */
        other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s = Unused",
            a_bigbuf);

        proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        if (add_string)
            g_snprintf(add_string, string_len, " - No Identity Code");

        curr_offset++;

        if (len > 1)
        {
            proto_tree_add_text(tree, tvb, curr_offset, len - 1,
                "Format not supported");
        }

        curr_offset += len - 1;
        break;

    case 3: /* IMEISV */
        /* FALLTHRU */

    case 1: /* IMSI */
        other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s = Identity Digit 1: %c",
            a_bigbuf,
            Dgt1_9_bcd.out[(oct & 0xf0) >> 4]);

        odd = oct & 0x08;

        proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        a_bigbuf[0] = Dgt1_9_bcd.out[(oct & 0xf0) >> 4];
        curr_offset++;

        poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

        my_dgt_tbcd_unpack(&a_bigbuf[1], poctets, len - (curr_offset - offset),
            &Dgt1_9_bcd);

        proto_tree_add_string_format(tree,
            ((oct & 0x07) == 3) ? hf_gsm_a_imeisv : hf_gsm_a_imsi,
            tvb, curr_offset - 1, len - (curr_offset - offset) + 1,
            a_bigbuf,
            "BCD Digits: %s",
            a_bigbuf);

        if (sccp_assoc && ! sccp_assoc->calling_party) {
            sccp_assoc->calling_party = se_strdup_printf(
                ((oct & 0x07) == 3) ? "IMEISV: %s" : "IMSI: %s",
                a_bigbuf );
        }

        if (add_string)
            g_snprintf(add_string, string_len, " - %s (%s)",
                ((oct & 0x07) == 3) ? "IMEISV" : "IMSI",
                a_bigbuf);

        curr_offset += len - (curr_offset - offset);

        if (!odd)
        {
            oct = tvb_get_guint8(tvb, curr_offset - 1);

            other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
            proto_tree_add_text(tree,
                tvb, curr_offset - 1, 1,
                "%s = Filler",
                a_bigbuf);
        }
        break;

    case 2: /* IMEI */
        other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s = Identity Digit 1: %c",
            a_bigbuf,
            Dgt1_9_bcd.out[(oct & 0xf0) >> 4]);

        proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        a_bigbuf[0] = Dgt1_9_bcd.out[(oct & 0xf0) >> 4];
        curr_offset++;

        poctets = tvb_get_ephemeral_string(tvb, curr_offset, len - (curr_offset - offset));

        my_dgt_tbcd_unpack(&a_bigbuf[1], poctets, len - (curr_offset - offset),
            &Dgt1_9_bcd);

        proto_tree_add_string_format(tree,
            hf_gsm_a_imei,
            tvb, curr_offset, len - (curr_offset - offset),
            a_bigbuf,
            "BCD Digits: %s",
            a_bigbuf);

        if (add_string)
            g_snprintf(add_string, string_len, " - IMEI (%s)", a_bigbuf);

        curr_offset += len - (curr_offset - offset);
        break;

    case 4: /* TMSI/P-TMSI */
        other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
        proto_tree_add_text(tree,
            tvb, curr_offset, 1,
            "%s = Unused",
            a_bigbuf);

        proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

        curr_offset++;

        value = tvb_get_ntohl(tvb, curr_offset);

        proto_tree_add_uint(tree, hf_gsm_a_tmsi,
            tvb, curr_offset, 4,
            value);

        if (add_string)
            g_snprintf(add_string, string_len, " - TMSI/P-TMSI (0x%04x)", value);

        curr_offset += 4;
        break;

    case 5: /* TMGI and optional MBMS Session Identity */
        /* Spare bits (octet 3) Bits 8-7 */
        proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 2, ENC_BIG_ENDIAN);
        /* MBMS Session Identity indication (octet 3) Bit 6 */
        proto_tree_add_item(tree, hf_gsm_a_mbs_ses_id_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        /* MCC/MNC indication (octet 3) Bit 5 */
        proto_tree_add_item(tree, hf_gsm_a_tmgi_mcc_mnc_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        /* Odd/even indication (octet 3) Bit 4 */
        proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        /* Type of identity (octet 3) Bits 3-1 */
        proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        /* MBMS Service ID (octet 4, 5 and 6) */
        proto_tree_add_item(tree, hf_gsm_a_mbs_service_id, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
        curr_offset += 3;
        if ((oct&0x10) == 0x10) {
            /* MCC/MNC*/
            /* MCC, Mobile country code (octet 6a, octet 6b bits 1 to 4)*/
            /* MNC, Mobile network code (octet 6b bits 5 to 8, octet 6c) */
            curr_offset = dissect_e212_mcc_mnc(tvb, pinfo, tree, curr_offset, TRUE);
        }
        if ((oct&0x20) == 0x20) {
            /* MBMS Session Identity (octet 7)
             * The MBMS Session Identity field is encoded as the value part
             * of the MBMS Session Identity IE as specified in 3GPP TS 48.018 [86].
             */
            proto_tree_add_item(tree, hf_gsm_a_mbs_session_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset++;
        }
        break;

    default:    /* Reserved */
        proto_tree_add_item(tree, hf_gsm_a_odd_even_ind, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_gsm_a_mobile_identity_type, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_text(tree, tvb, curr_offset, len,
            "Mobile station identity Format %u, Format Unknown", (oct & 0x07));

        if (add_string)
            g_snprintf(add_string, string_len, " - Format Unknown");

        curr_offset += len;
        break;
    }

    EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.5
 */
guint16
de_ms_cm_1(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;
    proto_tree *subtree;
    proto_item *item;

    curr_offset = offset;

    item =
    proto_tree_add_text(tree,
        tvb, curr_offset, 1, "%s",
        gsm_common_elem_strings[DE_MS_CM_1].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_MS_CM_1]);

    proto_tree_add_item(subtree, hf_gsm_a_b8spare, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_gsm_a_MSC_rev, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_gsm_a_ES_IND, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_gsm_a_A5_1_algorithm_sup, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(subtree, hf_gsm_a_RF_power_capability, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.6 Mobile Station Classmark 2
 * 3GPP TS 24.008 version 7.8.0 Release 7
 */
guint16
de_ms_cm_2(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;
    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_b8spare, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_gsm_a_MSC_rev, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_gsm_a_ES_IND, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_gsm_a_A5_1_algorithm_sup, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_gsm_a_RF_power_capability, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    proto_tree_add_item(tree, hf_gsm_a_b8spare, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_gsm_a_ps_sup_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    proto_tree_add_item(tree, hf_gsm_a_SS_screening_indicator, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    /* SM capability (MT SMS pt to pt capability) (octet 4)*/
    proto_tree_add_item(tree, hf_gsm_a_SM_capability, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* VBS notification reception (octet 4) */
    proto_tree_add_item(tree, hf_gsm_a_VBS_notification_rec, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /*VGCS notification reception (octet 4)*/
    proto_tree_add_item(tree, hf_gsm_a_VGCS_notification_rec, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* FC Frequency Capability (octet 4 ) */
    proto_tree_add_item(tree, hf_gsm_a_FC_frequency_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    NO_MORE_DATA_CHECK(len);

    /* CM3 (octet 5, bit 8) */
    proto_tree_add_item(tree, hf_gsm_a_CM3, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* spare bit 7 */
    proto_tree_add_item(tree, hf_gsm_a_b7spare, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* LCS VA capability (LCS value added location request notification capability) (octet 5,bit 6) */
    proto_tree_add_item(tree, hf_gsm_a_LCS_VA_cap, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* UCS2 treatment (octet 5, bit 5) */
    proto_tree_add_item(tree, hf_gsm_a_UCS2_treatment, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* SoLSA (octet 5, bit 4) */
    proto_tree_add_item(tree, hf_gsm_a_SoLSA, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* CMSP: CM Service Prompt (octet 5, bit 3) */
    proto_tree_add_item(tree, hf_gsm_a_CMSP, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* A5/3 algorithm supported (octet 5, bit 2) */
    proto_tree_add_item(tree, hf_gsm_a_A5_3_algorithm_sup, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    /* A5/2 algorithm supported (octet 5, bit 1) */
    proto_tree_add_item(tree, hf_gsm_a_A5_2_algorithm_sup, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset,pinfo);

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.7 Mobile Station Classmark 3
 * 3GPP TS 24.008 version 10.6.1 Release 10
 */
#define AVAILABLE_BITS_CHECK(n) \
    bits_left = ((len + offset) << 3) - bit_offset; \
    if (bits_left < (n)) { \
        if (bits_left) \
            proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, bits_left, ENC_BIG_ENDIAN); \
        return(len); \
    }

guint16
de_ms_cm_3(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32     curr_offset;
    guint32     bit_offset;     /* Offset in bits */
    guint8      length;
    proto_tree *subtree;
    proto_item *item;
    guint32     bits_left, target_bit_offset, old_bit_offset;
    guint64     multi_bnd_sup_fields, rsupport, multislotCapability;
    guint64     msMeasurementCapability, msPosMethodCapPresent;
    guint64     ecsdMultiSlotCapability, eightPskStructPresent, eightPskStructRfPowerCapPresent;
    guint64     gsm400BandInfoPresent, gsm850AssocRadioCapabilityPresent;
    guint64     gsm1900AssocRadioCapabilityPresent, dtmEGprsMultiSlotInfoPresent;
    guint64     dtmEgprsMultiSlotClassPresent, singleBandSupport;
    guint64     gsm750AssocRadioCapabilityPresent, extDtmEGprsMultiSlotInfoPresent;
    guint64     highMultislotCapPresent, geranIuModeSupport;
    guint64     tGsm400BandInfoPresent, tGsm900AssocRadioCapabilityPresent, dtmEGprsHighMultiSlotInfoPresent;
    guint64     dtmEgprsHighMultiSlotClassPresent, gsm710AssocRadioCapabilityPresent;
    guint64     tGsm810AssocRadioCapabilityPresent;

    curr_offset = offset;

    bit_offset = curr_offset << 3;

    /* Spare bit */
    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    /* Multiband supported field
     * { < Multiband supported : { 000 } >
     * < A5 bits >
     * | < Multiband supported : { 101 | 110 } >
     * < A5 bits >
     * < Associated Radio Capability 2 : bit(4) >
     * < Associated Radio Capability 1 : bit(4) >
     * | < Multiband supported : { 001 | 010 | 100 } >
     * < A5 bits >
     * < spare bit >(4)
     * < Associated Radio Capability 1 : bit(4) > }
     */

    item = proto_tree_add_bits_ret_val(tree, hf_gsm_a_multi_bnd_sup_fields, tvb, bit_offset, 3, &multi_bnd_sup_fields, ENC_BIG_ENDIAN);
    subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_MS_CM_3]);

    proto_tree_add_bits_item(subtree, hf_gsm_a_gsm1800_supported, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    proto_tree_add_bits_item(subtree, hf_gsm_a_egsm_supported, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    proto_tree_add_bits_item(subtree, hf_gsm_a_pgsm_supported, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    item = proto_tree_add_bits_item(tree, hf_gsm_a_cm3_A5_bits, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
    subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_MS_CM_3]);

    /* < A5 bits > */
    proto_tree_add_bits_item(subtree, hf_gsm_a_A5_7_algorithm_sup, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(subtree, hf_gsm_a_A5_6_algorithm_sup, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(subtree, hf_gsm_a_A5_5_algorithm_sup, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(subtree, hf_gsm_a_A5_4_algorithm_sup, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    switch (multi_bnd_sup_fields) {
    case 0:
        /* A5 bits dissected is done */
        break;
        /*
         * | < Multiband supported : { 001 | 010 | 100 } >
         */
    case 1:
    case 2:
    case 4:
        /* < spare bit >(4) */
        proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset += 4;
        /* < Associated Radio Capability 1 : bit(4) > */
        proto_tree_add_bits_item(tree, hf_gsm_a_ass_radio_cap1, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset += 4;
        break;
        /* < Multiband supported : { 101 | 110 } > */
    case 5:
        /* fall trough */
    case 6:
        /* < Associated Radio Capability 2 : bit(4) > */
        proto_tree_add_bits_item(tree, hf_gsm_a_ass_radio_cap2, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset += 4;
        /* < Associated Radio Capability 1 : bit(4) > */
        proto_tree_add_bits_item(tree, hf_gsm_a_ass_radio_cap1, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset += 4;
        break;
    default:
        break;
    }
    /* Extract R Support */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_rsupport, tvb, bit_offset, 1, &rsupport, ENC_BIG_ENDIAN);
    bit_offset++;

    if (rsupport == 1)
    {
        /*
         * { 0 | 1 < R Support > }
         * Extract R Capabilities
         */
        proto_tree_add_bits_item(tree, hf_gsm_a_r_capabilities, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 3;
    }

    /*
     * { 0 | 1 < HSCSD Multi Slot Capability > }
     * Extract Multislot capability
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_multislot_capabilities, tvb, bit_offset, 1, &multislotCapability, ENC_BIG_ENDIAN);
    bit_offset++;

    if (multislotCapability == 1)
    {
        /* Extract Multislot Class */
        proto_tree_add_bits_item(tree, hf_gsm_a_multislot_class, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 5;
    }

    /* < UCS2 treatment: bit > */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_ucs2_treatment, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /* < Extended Measurement Capability : bit > */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_extended_measurement_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /* { 0 | 1 < MS measurement capability > }
     * Extract MS Measurement capability
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_ms_measurement_capability, tvb, bit_offset, 1, &msMeasurementCapability, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (msMeasurementCapability == 1)
    {
        /* Extract SMS Value n/4 */
        proto_tree_add_bits_item(tree, hf_gsm_a_sms_value, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 4;

        /* Extract SM Value n/4 */
        proto_tree_add_bits_item(tree, hf_gsm_a_sm_value, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 4;
    }

    /* { 0 | 1 < MS Positioning Method Capability > }
     * Extract MS Positioning Method Capability
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_ms_pos_method_cap_present, tvb, bit_offset, 1, &msPosMethodCapPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (msPosMethodCapPresent == 1)
    {
        /* Extract MS Positioning Method */
        item = proto_tree_add_bits_item(tree, hf_gsm_a_ms_pos_method, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
        subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_MS_CM_3]);

        proto_tree_add_bits_item(subtree, hf_gsm_a_ms_assisted_e_otd, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset++;

        proto_tree_add_bits_item(subtree, hf_gsm_a_ms_based_e_otd, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset++;

        proto_tree_add_bits_item(subtree, hf_gsm_a_ms_assisted_gps, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset++;

        proto_tree_add_bits_item(subtree, hf_gsm_a_ms_based_gps, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset++;

        proto_tree_add_bits_item(subtree, hf_gsm_a_ms_conventional_gps, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset++;
    }

    /* { 0 | 1 < ECSD Multi Slot Capability > }
     * Extract ECSD Multi Slot Capability
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_ecsd_multi_slot_capability, tvb, bit_offset, 1, &ecsdMultiSlotCapability, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (ecsdMultiSlotCapability == 1)
    {
        /* Extract ECSD Multi Slot Class */
        proto_tree_add_bits_item(tree, hf_gsm_a_ecsd_multi_slot_class, tvb, bit_offset, 5, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 5;
    }

    /* { 0 | 1 < 8-PSK Struct > }
     * Extract 8-PSK struct presence
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_8_psk_struct_present, tvb, bit_offset, 1, &eightPskStructPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (eightPskStructPresent == 1)
    {
        /* Extract 8-PSK struct */
        item = proto_tree_add_bits_item(tree, hf_gsm_a_8_psk_struct, tvb, bit_offset, -1, ENC_BIG_ENDIAN);
        subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_MS_CM_3]);
        old_bit_offset = bit_offset;

        /* Extract Modulation Capability */
        proto_tree_add_bits_item(subtree, hf_gsm_a_modulation_capability, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 1;

        /* Extract 8_PSK RF Power Capability 1 */
        proto_tree_add_bits_ret_val(subtree, hf_gsm_a_8_psk_rf_power_capability_1_present, tvb, bit_offset,
                                    1, &eightPskStructRfPowerCapPresent, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 1;
        if (eightPskStructRfPowerCapPresent == 1)
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_8_psk_rf_power_capability_1, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset = bit_offset + 2;
        }

        /* Extract 8_PSK RF Power Capability 2 */
        proto_tree_add_bits_ret_val(subtree, hf_gsm_a_8_psk_rf_power_capability_2_present, tvb, bit_offset,
                                    1, &eightPskStructRfPowerCapPresent, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 1;
        if (eightPskStructRfPowerCapPresent == 1)
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_8_psk_rf_power_capability_2, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset = bit_offset + 2;
        }
        length = (guint8)((bit_offset - old_bit_offset)>>3);
        if ((bit_offset - old_bit_offset) & 0x07)
            length++;
        proto_item_set_len(item, length);
    }

    /* { 0 | 1 < GSM 400 Bands Supported : { 01 | 10 | 11 } >
     *   < GSM 400 Associated Radio Capability: bit(4) > }
     * Extract GSM 400 Band Information presence
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_gsm_400_band_info_present, tvb, bit_offset, 1, &gsm400BandInfoPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (gsm400BandInfoPresent == 1)
    {
        /* Extract GSM 400 Bands Supported */
        proto_tree_add_bits_item(tree, hf_gsm_a_gsm_400_bands_supported, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 2;

        /* Extract GSM 400 Associated Radio Capability */
        proto_tree_add_bits_item(tree, hf_gsm_a_gsm_400_assoc_radio_cap, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 4;
    }

    /* { 0 | 1 <GSM 850 Associated Radio Capability : bit(4) > }
     * Extract GSM 850 Associated Radio Capability presence
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_gsm_850_assoc_radio_cap_present, tvb, bit_offset, 1, &gsm850AssocRadioCapabilityPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (gsm850AssocRadioCapabilityPresent == 1)
    {
        /* Extract GSM 850 Associated Radio Capability */
        proto_tree_add_bits_item(tree, hf_gsm_a_gsm_850_assoc_radio_cap, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 4;
    }

    /* { 0 | 1 <GSM 1900 Associated Radio Capability : bit(4) > }
     * Extract GSM 1900 Associated Radio Capability presence
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_gsm_1900_assoc_radio_cap_present, tvb, bit_offset, 1, &gsm1900AssocRadioCapabilityPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (gsm1900AssocRadioCapabilityPresent == 1)
    {
        /* Extract GSM 1900 Associated Radio Capability */
        proto_tree_add_bits_item(tree, hf_gsm_a_gsm_1900_assoc_radio_cap, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 4;
    }

    /* < UMTS FDD Radio Access Technology Capability : bit >
     * Extract UMTS FDD Radio Access Technology Capability
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_umts_fdd_rat_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /* < UMTS 3.84 Mcps TDD Radio Access Technology Capability : bit >
     * Extract UMTS 3.84 Mcps TDD Radio Access Technology Capability
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_umts_384_mcps_tdd_rat_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /* < CDMA 2000 Radio Access Technology Capability : bit >
     * Extract CDMA 2000 Radio Access Technology Capability
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_cdma_2000_rat_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /* { 0 | 1 < DTM GPRS Multi Slot Class : bit(2) >
     *   < Single Slot DTM : bit >
     *   {0 | 1< DTM EGPRS Multi Slot Class : bit(2) > } }
     * Extract DTM E/GPRS Information presence
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_dtm_e_gprs_multi_slot_info_present, tvb, bit_offset, 1, &dtmEGprsMultiSlotInfoPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (dtmEGprsMultiSlotInfoPresent == 1)
    {
        /* Extract DTM GPRS Multi Slot Class */
        proto_tree_add_bits_item(tree, hf_gsm_a_dtm_gprs_multi_slot_class, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 2;

        /* Extract Single Slot DTM */
        proto_tree_add_bits_item(tree, hf_gsm_a_single_slot_dtm, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 1;

        /* Extract DTM EGPRS Multi Slot Class Presence */
        proto_tree_add_bits_ret_val(tree, hf_gsm_a_dtm_egprs_multi_slot_class_present, tvb, bit_offset, 1, &dtmEgprsMultiSlotClassPresent, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 1;

        /* Extract DTM EGPRS Multi Slot Class */
        if (dtmEgprsMultiSlotClassPresent == 1)
        {
            proto_tree_add_bits_item(tree, hf_gsm_a_dtm_egprs_multi_slot_class, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
            bit_offset = bit_offset + 2;
        }
    }

    /*
     * Release 4 starts here
     *
     * { 0 | 1 < Single Band Support > } -- Release 4 starts here:
     * Extract Single Band Support
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_single_band_support, tvb, bit_offset, 1, &singleBandSupport, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (singleBandSupport == 1)
    {
        /* Extract Single Band Support */
        proto_tree_add_bits_item(tree, hf_gsm_a_gsm_band, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 4;
    }

    /* { 0 | 1 <GSM 750 Associated Radio Capability : bit(4) > }
     * Extract GSM 750 Associated Radio Capability presence
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_gsm_750_assoc_radio_cap_present, tvb, bit_offset, 1, &gsm750AssocRadioCapabilityPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (gsm750AssocRadioCapabilityPresent == 1)
    {
        /* Extract GSM 750 Associated Radio Capability */
        proto_tree_add_bits_item(tree, hf_gsm_a_gsm_750_assoc_radio_cap, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 4;
    }

    /* < UMTS 1.28 Mcps TDD Radio Access Technology Capability : bit >
     * Extract UMTS 1.28 Mcps TDD Radio Access Technology Capability
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_umts_128_mcps_tdd_rat_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /* < GERAN Feature Package 1 : bit >
     * Extract GERAN Feature Package 1
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_geran_feature_package_1, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /* { 0 | 1 < Extended DTM GPRS Multi Slot Class : bit(2) >
     *   < Extended DTM EGPRS Multi Slot Class : bit(2) > }
     * Extract Extended DTM E/GPRS Information presence
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_ext_dtm_e_gprs_multi_slot_info_present, tvb, bit_offset, 1, &extDtmEGprsMultiSlotInfoPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (extDtmEGprsMultiSlotInfoPresent == 1)
    {
        /* Extract Extended DTM GPRS Multi Slot Class */
        proto_tree_add_bits_item(tree, hf_gsm_a_ext_dtm_gprs_multi_slot_class, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 2;

        /* Extract Extended DTM EGPRS Multi Slot Class */
        proto_tree_add_bits_item(tree, hf_gsm_a_ext_dtm_egprs_multi_slot_class, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 2;
    }

    /*
     * Release 5 starts here
     *
     * { 0 | 1 < High Multislot Capability : bit(2) > } -- Release 5 starts here.
     * Extract High Multislot Capability presence
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_high_multislot_cap_present, tvb, bit_offset, 1, &highMultislotCapPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (highMultislotCapPresent == 1)
    {
        /* Extract High Multislot Capability */
        proto_tree_add_bits_item(tree, hf_gsm_a_high_multislot_cap, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 2;
    }

    /*
     * { 0 | 1 < GERAN Iu Mode Capabilities > } -- "1" also means support of GERAN Iu mode
     * Extract GERAN Iu Mode Capabilities presence
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_geran_iu_mode_support, tvb, bit_offset, 1, &geranIuModeSupport, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (geranIuModeSupport == 1)
    {
        /* Extract GERAN Iu Mode Capabilities Length */
        length = tvb_get_bits8(tvb, bit_offset, 4);

        /* Extract GERAN Iu Mode Capabilities */
        item = proto_tree_add_bits_item(tree, hf_gsm_a_geran_iu_mode_cap, tvb, bit_offset, length + 4, ENC_BIG_ENDIAN);
        subtree = proto_item_add_subtree(item, ett_gsm_common_elem[DE_MS_CM_3]);

        /* Add GERAN Iu Mode Capabilities Length in subtree */
        proto_tree_add_bits_item(subtree, hf_gsm_a_geran_iu_mode_cap_length, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset += 4;
        target_bit_offset = bit_offset + length;

        /* Extract FLO Iu Capability */
        proto_tree_add_bits_item(subtree, hf_gsm_a_flo_iu_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset += 1;

        /* If needed, add spare bits */
        if (target_bit_offset > bit_offset)
        {
            proto_tree_add_bits_item(subtree, hf_gsm_a_spare_bits, tvb, bit_offset, target_bit_offset - bit_offset, ENC_BIG_ENDIAN);
            bit_offset = target_bit_offset;
        }
    }

    /* < GERAN Feature Package 2 : bit >
     * Extract GERAN Feature Package 2
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_geran_feature_package_2, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /* < GMSK Multislot Power Profile : bit (2) >
     * Extract GMSK Multislot Power Profile
     */
    AVAILABLE_BITS_CHECK(2);
    proto_tree_add_bits_item(tree, hf_gsm_a_gmsk_multislot_power_prof, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 2;

    /* < 8-PSK Multislot Power Profile : bit (2) >
     * Extract GMSK Multislot Power Profile
     */
    AVAILABLE_BITS_CHECK(2);
    proto_tree_add_bits_item(tree, hf_gsm_a_8_psk_multislot_power_prof, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 2;

    /*
     * Release 6 starts here
     *
     * { 0 | 1 < T-GSM 400 Bands Supported : { 01 | 10 | 11 } > -- Release 6 starts here.
     *   < T-GSM 400 Associated Radio Capability: bit(4) > }
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_t_gsm_400_band_info_present, tvb, bit_offset, 1, &tGsm400BandInfoPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (tGsm400BandInfoPresent == 1)
    {
        /* Extract T-GSM 400 Bands Supported */
        proto_tree_add_bits_item(tree, hf_gsm_a_t_gsm_400_bands_supported, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 2;

        /* Extract T-GSM 400 Associated Radio Capability */
        proto_tree_add_bits_item(tree, hf_gsm_a_t_gsm_400_assoc_radio_cap, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 4;
    }

    /* { 0 | 1 < T-GSM 900 Associated Radio Capability: bit(4) > }
     * Extract T-GSM 900 Associated Radio Capability presence
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_t_gsm_900_assoc_radio_cap_present, tvb, bit_offset, 1, &tGsm900AssocRadioCapabilityPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (tGsm900AssocRadioCapabilityPresent == 1)
    {
        /* Extract T-GSM 900 Associated Radio Capability */
        proto_tree_add_bits_item(tree, hf_gsm_a_t_gsm_900_assoc_radio_cap, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 4;
    }

    /* < Downlink Advanced Receiver Performance : bit (2)>
     * Extract Downlink Advanced Receiver Performance
     */
    AVAILABLE_BITS_CHECK(2);
    proto_tree_add_bits_item(tree, hf_gsm_a_downlink_adv_receiver_perf, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 2;

    /* < DTM Enhancements Capability : bit >
     * Extract DTM Enhancements Capability
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_dtm_enhancements_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /* { 0 | 1 < DTM GPRS High Multi Slot Class : bit(3) >
     *   < Offset required : bit>
     *   { 0 | 1 < DTM EGPRS High Multi Slot Class : bit(3) > } }
     * Extract DTM E/GPRS High Multi Slot Information presence
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_dtm_e_gprs_high_multi_slot_info_present, tvb, bit_offset, 1, &dtmEGprsHighMultiSlotInfoPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (dtmEGprsHighMultiSlotInfoPresent == 1)
    {
        /* Extract DTM GPRS High Multi Slot Class */
        proto_tree_add_bits_item(tree, hf_gsm_a_dtm_gprs_high_multi_slot_class, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 3;

        /* Extract Offset Required */
        proto_tree_add_bits_item(tree, hf_gsm_a_offset_required, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 1;

        /* Extract DTM EGPRS High Multi Slot Class Presence */
        proto_tree_add_bits_ret_val(tree, hf_gsm_a_dtm_egprs_high_multi_slot_class_present, tvb, bit_offset, 1, &dtmEgprsHighMultiSlotClassPresent, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 1;

        /* Extract DTM EGPRS High Multi Slot Class */
        if (dtmEgprsHighMultiSlotClassPresent == 1)
        {
            proto_tree_add_bits_item(tree, hf_gsm_a_dtm_egprs_high_multi_slot_class, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
            bit_offset = bit_offset + 3;
        }
    }

    /* < Repeated ACCH Capability : bit >
     * Extract Repeated ACCH Capability
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_repeated_acch_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /*
     * Release 7 starts here
     *
     * { 0 | 1 <GSM 710 Associated Radio Capability : bit(4) > } -- Release 7 starts here.
     * Extract GSM 710 Associated Radio Capability presence
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_gsm_710_assoc_radio_cap_present, tvb, bit_offset, 1, &gsm710AssocRadioCapabilityPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (gsm710AssocRadioCapabilityPresent == 1)
    {
        /* Extract GSM 710 Associated Radio Capability */
        proto_tree_add_bits_item(tree, hf_gsm_a_gsm_710_assoc_radio_cap, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 4;
    }

    /* { 0 | 1 < T-GSM 810 Associated Radio Capability: bit(4) > }
     * Extract T-GSM 810 Associated Radio Capability presence
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_ret_val(tree, hf_gsm_a_t_gsm_810_assoc_radio_cap_present, tvb, bit_offset, 1, &tGsm810AssocRadioCapabilityPresent, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    if (tGsm810AssocRadioCapabilityPresent == 1)
    {
        /* Extract T-GSM 810 Associated Radio Capability */
        proto_tree_add_bits_item(tree, hf_gsm_a_t_gsm_810_assoc_radio_cap, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
        bit_offset = bit_offset + 4;
    }

    /* < Ciphering Mode Setting Capability : bit >
     * Extract Ciphering Mode Setting Capability
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_ciphering_mode_setting_cap, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /* < Additional Positioning Capabilities : bit >
     * Extract Additional Positioning Capabilities
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_additional_positioning_caps, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /*
     * Release 8 starts here
     *
     * <E-UTRA FDD support : bit > -- Release 8 starts here.
     * Extract E-UTRA FDD support
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_e_utra_fdd_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /*
     * <E-UTRA TDD support : bit >
     * Extract E-UTRA TDD support
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_e_utra_tdd_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /*
     * <E-UTRA Measurement and Reporting support : bit >
     * Extract E-UTRA Measurement and Reporting support
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_e_utra_meas_and_report_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /*
     * <Priority-based reselection support : bit >
     * Extract Priority-based reselection support
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_prio_based_resel_support, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /*
     * Release 9 starts here
     *
     * <UTRA CSG Cells Reporting : bit > -- Release 9 starts here.
     * Extract UTRA CSG Cells Reporting
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_utra_csg_cells_reporting, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /*
     * <VAMOS Level : bit(2) >
     * Extract VAMOS Level
     */
    AVAILABLE_BITS_CHECK(2);
    proto_tree_add_bits_item(tree, hf_gsm_a_vamos_level, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 2;

    /*
     * Release 10 starts here
     *
     * < TIGHTER Capability : bit(2) > -- Release 10 starts here.
     * Extract TIGHTER Capability
     */
    AVAILABLE_BITS_CHECK(2);
    proto_tree_add_bits_item(tree, hf_gsm_a_tighter_cap, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 2;

    /*
     * < Selective Ciphering of Downlink SACCH : bit >
     * Extract Selective Ciphering of Downlink SACCH
     */
    AVAILABLE_BITS_CHECK(1);
    proto_tree_add_bits_item(tree, hf_gsm_a_selective_ciph_down_sacch, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset = bit_offset + 1;

    /*
     * Add spare bits until we reach an octet boundary
     */
    bits_left = (((len + offset) << 3) - bit_offset) & 0x07;
    if (bits_left != 0)
    {
        proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, bits_left, ENC_BIG_ENDIAN);
        bit_offset += bits_left;
    }

    /* translate to byte offset (we already know that we are on an octet boundary) */
    curr_offset = bit_offset >> 3;
    EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

    return(len);
}
/*
 * [3] 10.5.1.8
 */
guint16 de_spare_nibble(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
   guint32 curr_offset;
   gint    bit_offset;

   curr_offset = offset;
   if (RIGHT_NIBBLE == len)
       bit_offset = 4;
   else
       bit_offset = 0;

   proto_tree_add_bits_item(tree, hf_gsm_a_spare_nibble, tvb, (curr_offset<<3)+bit_offset+3, 1, ENC_BIG_ENDIAN);
   curr_offset = curr_offset + 1;

   return(curr_offset - offset);
}

/*
 * [3] 10.5.1.9 Descriptive group or broadcast call reference
 */
guint16
de_d_gb_call_ref(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8       oct;
    guint32      value;
    guint32      curr_offset;
    const gchar *str;

    curr_offset = offset;

    value = tvb_get_ntohl(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, value, 0xffffffe0, 32);
    proto_tree_add_text(tree, tvb, curr_offset, 4,
        "%s = Group or Broadcast call reference: %u (0x%04x)",
        a_bigbuf,
        (value & 0xffffffe0) >> 5,
        (value & 0xffffffe0) >> 5);

    other_decode_bitfield_value(a_bigbuf, value, 0x00000010, 32);
    proto_tree_add_text(tree, tvb, curr_offset, 4,
        "%s = SF Service Flag: %s",
        a_bigbuf,
        (value & 0x00000010) ?
        "VGCS (Group call reference)" : "VBS (Broadcast call reference)");

    other_decode_bitfield_value(a_bigbuf, value, 0x00000008, 32);
    proto_tree_add_text(tree, tvb, curr_offset, 4,
        "%s = AF Acknowledgement Flag: acknowledgment is %srequired",
        a_bigbuf,
        (value & 0x00000008) ? "" : "not ");

    switch (value & 0x00000007)
    {
    case 1: str = "call priority level 4"; break;
    case 2: str = "call priority level 3"; break;
    case 3: str = "call priority level 2"; break;
    case 4: str = "call priority level 1"; break;
    case 5: str = "call priority level 0"; break;
    case 6: str = "call priority level B"; break;
    case 7: str = "call priority level A"; break;
    default:
    str = "no priority applied";
    break;
    }

    other_decode_bitfield_value(a_bigbuf, value, 0x00000007, 32);
    proto_tree_add_text(tree, tvb, curr_offset, 4,
        "%s = Call Priority: %s",
        a_bigbuf,
        str);

    curr_offset += 4;

    oct = tvb_get_guint8(tvb, curr_offset);

    other_decode_bitfield_value(a_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree, tvb, curr_offset, 1,
        "%s = Ciphering Information",
        a_bigbuf);

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3)+4, 4, ENC_BIG_ENDIAN);
    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.10a PD and SAPI $(CCBS)$
 */
static guint16
de_pd_sapi(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint8       oct;
    guint32      curr_offset;
    proto_tree  *subtree;
    proto_item  *item;
    const gchar *str;

    curr_offset = offset;

    oct = tvb_get_guint8(tvb, curr_offset);

    item =
    proto_tree_add_text(tree,
        tvb, curr_offset, 1, "%s",
        gsm_dtap_elem_strings[DE_PD_SAPI].strptr);

    subtree = proto_item_add_subtree(item, ett_gsm_dtap_elem[DE_PD_SAPI]);

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, curr_offset<<3, 2, ENC_BIG_ENDIAN);

    switch ((oct & 0x30) >> 4)
    {
    case 0: str = "SAPI 0"; break;
    case 3: str = "SAPI 3"; break;
    default:
    str = "Reserved";
    break;
    }

    other_decode_bitfield_value(a_bigbuf, oct, 0x30, 8);
    proto_tree_add_text(subtree, tvb, curr_offset, 1,
        "%s = SAPI (Service Access Point Identifier): %s",
        a_bigbuf,
        str);

    proto_tree_add_item(tree, hf_gsm_a_L3_protocol_discriminator, tvb, curr_offset, 1, ENC_BIG_ENDIAN);

    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.11 Priority Level
 */
static const value_string gsm_a_call_prio_vals[] = {
    { 0x00, "no priority applied" },
    { 0x01, "call priority level 4" },
    { 0x02, "call priority level 3" },
    { 0x03, "call priority level 2" },
    { 0x04, "call priority level 1" },
    { 0x05, "call priority level 0" },
    { 0x06, "call priority level B" },
    { 0x07, "call priority level A" },
    { 0,            NULL }
};

static guint16
de_prio(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_b8spare, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_bits_item(tree, hf_gsm_a_call_prio, tvb, (curr_offset<<3)+5, 3, ENC_BIG_ENDIAN);
    curr_offset++;

    /* no length check possible */

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.12.1 CN Common GSM-MAP NAS system information
 */
guint16
de_cn_common_gsm_map_nas_sys_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_lac, tvb, curr_offset, 2, ENC_BIG_ENDIAN);
    curr_offset += 2;

    EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.12.2 CS domain specific system information
 */
const true_false_string gsm_a_att_value = {
	"MSs shall apply IMSI attach and detach procedure",
	"MSs shall not apply IMSI attach and detach procedure"
};

guint16
de_cs_domain_spec_sys_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_rr_t3212, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;
    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3), 7, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_att, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.12.3 PS domain specific system information
 */
const true_false_string gsm_a_nmo_1_value = {
	"Network Mode of Operation I is used for MS configured for NMO_I_Behaviour",
	"Network Mode of Operation indicated in Bit 1 (NMO) is used for MS configured for NMO_I_Behaviour"
};

const true_false_string gsm_a_nmo_value = {
	"Network Mode of Operation II",
	"Network Mode of Operation I"
};

guint16
de_ps_domain_spec_sys_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    proto_tree_add_item(tree, hf_gsm_a_gm_rac, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;
    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, (curr_offset<<3), 6, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_nmo_1, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_nmo, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

    return(curr_offset - offset);
}

/*
 * [3] 10.5.1.13 PLMN list
 */
guint16
de_plmn_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len)
{
    guint8  octs[3];
    guint32 curr_offset;
    gchar   mcc[4];
    gchar   mnc[4];
    guint8  num_plmn;

    curr_offset = offset;

    num_plmn = 0;
    while ((len - (curr_offset - offset)) >= 3)
    {
    octs[0] = tvb_get_guint8(tvb, curr_offset);
    octs[1] = tvb_get_guint8(tvb, curr_offset + 1);
    octs[2] = tvb_get_guint8(tvb, curr_offset + 2);

    mcc_mnc_aux(octs, mcc, mnc);

    proto_tree_add_text(tree,
        tvb, curr_offset, 3,
        "PLMN[%u]  Mobile Country Code (MCC): %s, Mobile Network Code (MNC): %s",
        num_plmn + 1,
        mcc,
        mnc);

    curr_offset += 3;

    num_plmn++;
    }

    if (add_string)
    g_snprintf(add_string, string_len, " - %u PLMN%s",
        num_plmn, plurality(num_plmn, "", "s"));

    EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

    return(curr_offset - offset);
}

/*
 * 10.5.1.14 NAS container for PS HO
 */

static const value_string gsm_a_pld_xid_vals[] = {
    { 0x00, "The MS shall perform a Reset of LLC and SNDCP without old XID indicator" },
    { 0x01, "The MS shall perform a Reset of LLC and SNDCP with old XID indicator" },
    { 0,            NULL }
};

static guint16
de_nas_cont_for_ps_ho(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset;

    curr_offset = offset;

    /*     8     7     6     5     4     3     2      1
     *     0     0     0   old     0     Type of ciphering
     * spare  spare  spare XID  spare      algorithm
     */
    proto_tree_add_item(tree, hf_gsm_a_old_xid, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_a_type_of_ciph_alg, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    /* IOV-UI value (octet 2 to 5)
     * The IOV-UI value consists of 32 bits, the format is defined in 3GPP TS 44.064 [78a].
     */
    proto_tree_add_item(tree, hf_gsm_a_iov_ui, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
    curr_offset += 4;

    EXTRANEOUS_DATA_CHECK_EXPERT(len, curr_offset - offset, pinfo);

    return(curr_offset - offset);
}

/*
 * 10.5.1.15 MS network feature support
 */
static const true_false_string gsm_a_ext_periodic_timers_value = {
    "MS supports the extended periodic timer in this domain",
    "MS does not support the extended periodic timer in this domain"
};

static guint16
de_ms_net_feat_sup(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    guint32 curr_offset, bit_offset;

    curr_offset = offset;
    bit_offset  = (curr_offset<<3)+4;

    proto_tree_add_bits_item(tree, hf_gsm_a_spare_bits, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
    bit_offset += 3;
    proto_tree_add_bits_item(tree, hf_gsm_a_ext_periodic_timers, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    curr_offset++;

    return (curr_offset - offset);
}


guint16 (*common_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, guint32 offset, guint len, gchar *add_string, int string_len) = {
    /* Common Information Elements 10.5.1 */
    de_cell_id,                        /* Cell Identity */
    de_ciph_key_seq_num,               /* Ciphering Key Sequence Number */
    de_lai,                            /* Location Area Identification */
    de_mid,                            /* Mobile Identity */
    de_ms_cm_1,                        /* Mobile Station Classmark 1 */
    de_ms_cm_2,                        /* Mobile Station Classmark 2 */
    de_ms_cm_3,                        /* Mobile Station Classmark 3 */
    de_spare_nibble,                   /* Spare Half Octet */
    de_d_gb_call_ref,                  /* Descriptive group or broadcast call reference */
    NULL       /* handled inline */,   /* Group Cipher Key Number */
    de_pd_sapi,                        /* PD and SAPI $(CCBS)$ */
    /* Pos 10 */
    de_prio    /* handled inline */,   /* Priority Level */
    de_cn_common_gsm_map_nas_sys_info, /* 10.5.1.12.1 CN Common GSM-MAP NAS system information */
    de_cs_domain_spec_sys_info,        /* 10.5.1.12.2 CS domain specific system information */
    de_ps_domain_spec_sys_info,        /* 10.5.1.12.2 PS domain specific system information */
    de_plmn_list,                      /* 10.5.1.13 PLMN list */
    de_nas_cont_for_ps_ho,             /* 10.5.1.14 NAS container for PS HO */
    de_ms_net_feat_sup,                /* 10.5.1.15 MS network feature support */
    NULL,                   /* NONE */
};

/* Register the protocol with Wireshark */
void
proto_register_gsm_a_common(void)
{
    guint   i;
    guint   last_offset;

    /* Setup list of header fields */
    static hf_register_info hf[] =
    {
    { &hf_gsm_a_common_elem_id,
        { "Element ID", "gsm_a.common.elem_id",
        FT_UINT8, BASE_HEX, NULL, 0,
        NULL, HFILL }
    },
    { &hf_gsm_a_l_ext,
        { "ext",    "gsm_a.l_ext",
        FT_UINT8, BASE_DEC, NULL, 0x80,
        NULL, HFILL }
    },
    { &hf_gsm_a_imsi,
        { "IMSI",   "gsm_a.imsi",
        FT_STRING, BASE_NONE, 0, 0,
        NULL, HFILL }
    },
    { &hf_gsm_a_tmsi,
        { "TMSI/P-TMSI",    "gsm_a.tmsi",
        FT_UINT32, BASE_HEX, 0, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_imei,
        { "IMEI",   "gsm_a.imei",
        FT_STRING, BASE_NONE, 0, 0,
        NULL, HFILL }
    },
    { &hf_gsm_a_imeisv,
        { "IMEISV", "gsm_a.imeisv",
        FT_STRING, BASE_NONE, 0, 0,
        NULL, HFILL }
    },
    { &hf_gsm_a_MSC_rev,
        { "Revision Level", "gsm_a.MSC_rev",
        FT_UINT8, BASE_DEC, VALS(gsm_a_msc_rev_vals), 0x60,
        NULL, HFILL }
    },
    { &hf_gsm_a_ES_IND,
        { "ES IND", "gsm_a.ES_IND",
        FT_BOOLEAN, 8, TFS(&ES_IND_vals), 0x10,
            NULL, HFILL }
    },
    { &hf_gsm_a_A5_1_algorithm_sup,
        { "A5/1 algorithm supported", "gsm_a.A5_1_algorithm_sup",
        FT_BOOLEAN, 8, TFS(&A5_1_algorithm_sup_vals), 0x08,
        NULL, HFILL }
    },
    { &hf_gsm_a_RF_power_capability,
        { "RF Power Capability", "gsm_a.RF_power_capability",
        FT_UINT8, BASE_DEC, VALS(RF_power_capability_vals), 0x07,
        NULL, HFILL }
    },
    { &hf_gsm_a_ps_sup_cap,
        { "PS capability (pseudo-synchronization capability)", "gsm_a.ps_sup_cap",
        FT_BOOLEAN, 8, TFS(&ps_sup_cap_vals), 0x40,
        NULL, HFILL }
    },
    { &hf_gsm_a_SS_screening_indicator,
        { "SS Screening Indicator", "gsm_a.SS_screening_indicator",
        FT_UINT8, BASE_DEC, VALS(SS_screening_indicator_vals), 0x30,
        NULL, HFILL }
    },
    { &hf_gsm_a_SM_capability,
        { "SM capability (MT SMS pt to pt capability)", "gsm_a.SM_cap",
        FT_BOOLEAN, 8, TFS(&SM_capability_vals), 0x08,
        NULL, HFILL }
    },
    { &hf_gsm_a_VBS_notification_rec,
        { "VBS notification reception", "gsm_a.VBS_notification_rec",
        FT_BOOLEAN, 8, TFS(&VBS_notification_rec_vals), 0x04,
        NULL, HFILL }
    },
    { &hf_gsm_a_VGCS_notification_rec,
        { "VGCS notification reception", "gsm_a.VGCS_notification_rec",
        FT_BOOLEAN, 8, TFS(&VGCS_notification_rec_vals), 0x02,
        NULL, HFILL }
    },
    { &hf_gsm_a_FC_frequency_cap,
        { "FC Frequency Capability", "gsm_a.FC_frequency_cap",
        FT_BOOLEAN, 8, TFS(&FC_frequency_cap_vals), 0x01,
        NULL, HFILL }
    },
    { &hf_gsm_a_CM3,
        { "CM3", "gsm_a.CM3",
        FT_BOOLEAN, 8, TFS(&CM3_vals), 0x80,
        NULL, HFILL }
    },
    { &hf_gsm_a_LCS_VA_cap,
        { "LCS VA capability (LCS value added location request notification capability)", "gsm_a.LCS_VA_cap",
        FT_BOOLEAN, 8, TFS(&LCS_VA_cap_vals), 0x20,
        NULL, HFILL }
    },
    { &hf_gsm_a_UCS2_treatment,
        { "UCS2 treatment", "gsm_a.UCS2_treatment",
        FT_BOOLEAN, 8, TFS(&UCS2_treatment_vals), 0x10,
        NULL, HFILL }
    },
    { &hf_gsm_a_SoLSA,
        { "SoLSA", "gsm_a.SoLSA",
        FT_BOOLEAN, 8, TFS(&SoLSA_vals), 0x08,
        NULL, HFILL }
    },
    { &hf_gsm_a_CMSP,
        { "CMSP: CM Service Prompt", "gsm_a.CMSP",
        FT_BOOLEAN, 8, TFS(&CMSP_vals), 0x04,
        NULL, HFILL }
    },
    { &hf_gsm_a_A5_7_algorithm_sup,
        { "A5/7 algorithm supported", "gsm_a.A5_7_algorithm_sup",
        FT_BOOLEAN, BASE_NONE, TFS(&A5_7_algorithm_sup_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_A5_6_algorithm_sup,
        { "A5/6 algorithm supported", "gsm_a.A5_6_algorithm_sup",
        FT_BOOLEAN, BASE_NONE, TFS(&A5_6_algorithm_sup_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_A5_5_algorithm_sup,
        { "A5/5 algorithm supported", "gsm_a.A5_5_algorithm_sup",
        FT_BOOLEAN, BASE_NONE, TFS(&A5_5_algorithm_sup_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_A5_4_algorithm_sup,
        { "A5/4 algorithm supported", "gsm_a.A5_4_algorithm_sup",
        FT_BOOLEAN, BASE_NONE, TFS(&A5_4_algorithm_sup_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_A5_3_algorithm_sup,
        { "A5/3 algorithm supported", "gsm_a.A5_3_algorithm_sup",
        FT_BOOLEAN, 8, TFS(&A5_3_algorithm_sup_vals), 0x02,
        NULL, HFILL }
    },
    { &hf_gsm_a_A5_2_algorithm_sup,
        { "A5/2 algorithm supported", "gsm_a.A5_2_algorithm_sup",
        FT_BOOLEAN, 8, TFS(&A5_2_algorithm_sup_vals), 0x01,
        NULL, HFILL }
    },
    { &hf_gsm_a_mobile_identity_type,
        { "Mobile Identity Type", "gsm_a.ie.mobileid.type",
        FT_UINT8, BASE_DEC, VALS(mobile_identity_type_vals), 0x07,
        NULL, HFILL }
    },
    { &hf_gsm_a_odd_even_ind,
        { "Odd/even indication", "gsm_a.oddevenind",
        FT_BOOLEAN, 8, TFS(&oddevenind_vals), 0x08,
        NULL, HFILL }
    },
    { &hf_gsm_a_tmgi_mcc_mnc_ind,
        { "MCC/MNC indication", "gsm_a.tmgi_mcc_mnc_ind",
        FT_BOOLEAN, 8, TFS(&gsm_a_present_vals), 0x10,
        NULL, HFILL}
    },
    { &hf_gsm_a_mbs_ses_id_ind,
        { "MBMS Session Identity indication", "gsm_a.mbs_session_id_ind",
        FT_BOOLEAN, 8, TFS(&gsm_a_present_vals), 0x20,
        NULL, HFILL}
    },
    { &hf_gsm_a_mbs_service_id,
        { "MBMS Service ID", "gsm_a.mbs_service_id",
        FT_UINT24, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_mbs_session_id,
        { "MBMS Session ID", "gsm_a.mbs_session_id",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_length,
        { "Length",     "gsm_a.len",
        FT_UINT16, BASE_DEC, NULL, 0,
        NULL, HFILL }
    },
    { &hf_gsm_a_extension,
        { "Extension", "gsm_a.extension",
        FT_BOOLEAN, 8, TFS(&gsm_a_extension_value), 0x80,
        NULL, HFILL }
    },
    { &hf_gsm_a_L3_protocol_discriminator,
        { "Protocol discriminator", "gsm_a.L3_protocol_discriminator",
        FT_UINT8, BASE_HEX, VALS(protocol_discriminator_vals), 0x0f,
        NULL, HFILL }
    },
    { &hf_gsm_a_call_prio,
        { "Call priority", "gsm_a.call_prio",
        FT_UINT8, BASE_DEC, VALS(gsm_a_call_prio_vals), 0x00,
        NULL, HFILL }
    },
    { &hf_gsm_a_type_of_ciph_alg,
        { "Call priority", "gsm_a.call_prio",
        FT_UINT8, BASE_DEC, VALS(gsm_a_gm_type_of_ciph_alg_vals), 0x07,
        NULL, HFILL }
    },
    { &hf_gsm_a_att,
        { "ATT", "gsm_a.att",
        FT_BOOLEAN, 8, TFS(&gsm_a_att_value), 0x01,
        "ttach-detach allowed", HFILL }
    },
    { &hf_gsm_a_nmo_1,
        { "NMO I", "gsm_a.nmo_1",
        FT_BOOLEAN, 8, TFS(&gsm_a_nmo_1_value), 0x02,
        "Network Mode of Operation I", HFILL }
    },
    { &hf_gsm_a_nmo,
        { "NMO", "gsm_a.nmo",
        FT_BOOLEAN, 8, TFS(&gsm_a_nmo_value), 0x01,
        "Network Mode of Operation", HFILL }
    },
    { &hf_gsm_a_old_xid,
        { "Old XID", "gsm_a.old_xid",
        FT_UINT8, BASE_DEC, VALS(gsm_a_pld_xid_vals), 0x10,
        NULL, HFILL }
    },
    { &hf_gsm_a_iov_ui,
        { "IOV-UI", "gsm_a.iov_ui",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_ext_periodic_timers,
        { "Extended periodic timers", "gsm_a.ext_periodic_timers",
        FT_BOOLEAN, BASE_NONE, TFS(&gsm_a_ext_periodic_timers_value), 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_skip_ind,
        { "Skip Indicator", "gsm_a.skip.ind",
        FT_UINT8, BASE_DEC, VALS(gsm_a_skip_ind_vals), 0xf0,
        NULL, HFILL }
    },
    { &hf_gsm_a_b7spare,
        { "Spare", "gsm_a.spareb7",
        FT_UINT8, BASE_DEC, NULL, 0x40,
        NULL, HFILL }
    },
    { &hf_gsm_a_b8spare,
        { "Spare", "gsm_a.spareb8",
        FT_UINT8, BASE_DEC, NULL, 0x80,
        NULL, HFILL }
    },
    { &hf_gsm_a_spare_bits,
        { "Spare bit(s)", "gsm_a.spare_bits",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_multi_bnd_sup_fields,
        { "Multiband supported field", "gsm_a.multi_bnd_sup_fields",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_pgsm_supported,
        { "P-GSM Supported", "gsm_a.classmark3.pgsmSupported",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_egsm_supported,
        { "E-GSM or R-GSM Supported", "gsm_a.classmark3.egsmSupported",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_gsm1800_supported,
        { "GSM 1800 Supported", "gsm_a.classmark3.gsm1800Supported",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_ass_radio_cap1,
        { "Associated Radio Capability 1", "gsm_a.classmark3.ass_radio_cap1",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_ass_radio_cap2,
        { "Associated Radio Capability 2", "gsm_a.classmark3.ass_radio_cap2",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_cm3_A5_bits,
        { "A5 bits", "gsm_a.classmark3.a5_bits",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_rsupport,
        { "R Support", "gsm_a.classmark3.rsupport",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_r_capabilities,
        { "R-GSM band Associated Radio Capability", "gsm_a.classmark3.r_capabilities",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_multislot_capabilities,
        { "HSCSD Multi Slot Capability", "gsm_a.classmark3.multislot_capabilities",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_multislot_class,
        { "HSCSD Multi Slot Class", "gsm_a.classmark3.multislot_cap",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_ucs2_treatment,
        { "UCS2 treatment", "gsm_a.UCS2_treatment",
        FT_BOOLEAN, BASE_NONE, TFS(&UCS2_treatment_vals), 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_extended_measurement_cap,
        { "Extended Measurement Capability", "gsm_a.classmark3.ext_meas_cap",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_ms_measurement_capability,
        { "MS measurement capability", "gsm_a.classmark3.ms_measurement_capability",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_sms_value,
        { "SMS_VALUE (Switch-Measure-Switch)", "gsm_a.classmark3.sms_value",
        FT_UINT8, BASE_DEC, VALS(gsm_a_sms_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_sm_value,
        { "SM_VALUE (Switch-Measure)", "gsm_a.classmark3.sm_value",
        FT_UINT8, BASE_DEC, VALS(gsm_a_sms_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_ms_pos_method_cap_present,
        { "MS Positioning Method Capability present", "gsm_a.classmark3.ms_pos_method_cap_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_ms_pos_method,
        { "MS Positioning Method", "gsm_a.classmark3.ms_pos_method",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_ms_assisted_e_otd,
        { "MS assisted E-OTD", "gsm_a.classmark3.ms_assisted_e_otd",
        FT_BOOLEAN, BASE_NONE, TFS(&ms_assisted_e_otd_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_ms_based_e_otd,
        { "MS based E-OTD", "gsm_a.classmark3.ms_based_e_otd",
        FT_BOOLEAN, BASE_NONE, TFS(&ms_based_e_otd_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_ms_assisted_gps,
        { "MS assisted GPS", "gsm_a.classmark3.ms_assisted_gps",
        FT_BOOLEAN, BASE_NONE, TFS(&ms_assisted_gps_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_ms_based_gps,
        { "MS based GPS", "gsm_a.classmark3.ms_based_gps",
        FT_BOOLEAN, BASE_NONE, TFS(&ms_based_gps_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_ms_conventional_gps,
        { "MS Conventional GPS", "gsm_a.classmark3.ms_conventional_gps",
        FT_BOOLEAN, BASE_NONE, TFS(&ms_conventional_gps_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_ecsd_multi_slot_capability,
        { "ECSD Multi Slot Capability present", "gsm_a.classmark3.ecsd_multi_slot_capability",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_ecsd_multi_slot_class,
        { "ECSD Multi Slot Class", "gsm_a.classmark3.ecsd_multi_slot_class",
        FT_UINT8, BASE_DEC, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_8_psk_struct_present,
        { "8-PSK Struct present", "gsm_a.classmark3.8_psk_struct_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_8_psk_struct,
        { "8-PSK Struct", "gsm_a.classmark3.8_psk_struct",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_modulation_capability,
        { "Modulation Capability", "gsm_a.classmark3.modulation_capability",
        FT_BOOLEAN, BASE_NONE, TFS(&modulation_capability_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_8_psk_rf_power_capability_1_present,
        { "8-PSK RF Power Capability 1 present", "gsm_a.classmark3.8_psk_rf_power_capability_1_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_8_psk_rf_power_capability_1,
        { "8-PSK RF Power Capability 1", "gsm_a.classmark3.8_psk_rf_power_capability_1",
        FT_UINT8, BASE_HEX, VALS(eight_psk_rf_power_capability_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_8_psk_rf_power_capability_2_present,
        { "8-PSK RF Power Capability 2 present", "gsm_a.classmark3.8_psk_rf_power_capability_2_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_8_psk_rf_power_capability_2,
        { "8-PSK RF Power Capability 2", "gsm_a.classmark3.8_psk_rf_power_capability_2",
        FT_UINT8, BASE_HEX, VALS(eight_psk_rf_power_capability_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_gsm_400_band_info_present,
        { "GSM 400 Band Information present", "gsm_a.classmark3.gsm_400_band_info_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_gsm_400_bands_supported,
        { "GSM 400 Bands Supported", "gsm_a.classmark3.gsm_400_bands_supported",
        FT_UINT8, BASE_HEX, VALS(gsm_400_bands_supported_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_gsm_400_assoc_radio_cap,
        { "GSM 400 Associated Radio Capability", "gsm_a.classmark3.gsm_400_assoc_radio_cap",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_gsm_850_assoc_radio_cap_present,
        { "GSM 850 Associated Radio Capability present", "gsm_a.classmark3.gsm_850_assoc_radio_cap_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_gsm_850_assoc_radio_cap,
        { "GSM 850 Associated Radio Capability", "gsm_a.classmark3.gsm_850_assoc_radio_cap",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_gsm_1900_assoc_radio_cap_present,
        { "GSM 1900 Associated Radio Capability present", "gsm_a.classmark3.gsm_1900_assoc_radio_cap_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_gsm_1900_assoc_radio_cap,
        { "GSM 1900 Associated Radio Capability", "gsm_a.classmark3.gsm_1900_assoc_radio_cap",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_umts_fdd_rat_cap,
        { "UMTS FDD Radio Access Technology Capability", "gsm_a.classmark3.umts_fdd_rat_cap",
        FT_BOOLEAN, BASE_NONE, TFS(&umts_fdd_rat_cap_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_umts_384_mcps_tdd_rat_cap,
        { "UMTS 3.84 Mcps TDD Radio Access Technology Capability", "gsm_a.classmark3.umts_384_mcps_tdd_rat_cap",
        FT_BOOLEAN, BASE_NONE, TFS(&umts_384_mcps_tdd_rat_cap_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_cdma_2000_rat_cap,
        { "CDMA 2000 Radio Access Technology Capability", "gsm_a.classmark3.cdma_2000_rat_cap",
        FT_BOOLEAN, BASE_NONE, TFS(&cdma_2000_rat_cap_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_dtm_e_gprs_multi_slot_info_present,
        { "DTM E/GPRS Multi Slot Information present", "gsm_a.classmark3.dtm_e_gprs_multi_slot_info_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_dtm_gprs_multi_slot_class,
        { "DTM GPRS Multi Slot Class", "gsm_a.classmark3.dtm_gprs_multi_slot_class",
        FT_UINT8, BASE_DEC, VALS(dtm_gprs_multi_slot_class_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_single_slot_dtm,
        { "Single Slot DTM", "gsm_a.classmark3.single_slot_dtm_supported",
        FT_BOOLEAN, BASE_NONE, TFS(&single_slot_dtm_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_dtm_egprs_multi_slot_class_present,
        { "DTM EGPRS Multi Slot Class present", "gsm_a.classmark3.dtm_egprs_multi_slot_class_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_dtm_egprs_multi_slot_class,
        { "DTM EGPRS Multi Slot Class", "gsm_a.classmark3.dtm_egprs_multi_slot_class",
        FT_UINT8, BASE_DEC, VALS(dtm_gprs_multi_slot_class_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_single_band_support,
        { "Single Band Support", "gsm_a.classmark3.single_band_support",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_gsm_band,
        { "GSM Band", "gsm_a.classmark3.gsm_band",
        FT_UINT8, BASE_DEC, VALS(gsm_band_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_gsm_750_assoc_radio_cap_present,
        { "GSM 750 Associated Radio Capability present", "gsm_a.classmark3.gsm_750_assoc_radio_cap_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_gsm_750_assoc_radio_cap,
        { "GSM 750 Associated Radio Capability", "gsm_a.classmark3.gsm_750_assoc_radio_cap",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_umts_128_mcps_tdd_rat_cap,
        { "UMTS 1.28 Mcps TDD Radio Access Technology Capability", "gsm_a.classmark3.umts_128_mcps_tdd_rat_cap",
        FT_BOOLEAN, BASE_NONE, TFS(&umts_128_mcps_tdd_rat_cap_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_geran_feature_package_1,
        { "GERAN Feature Package 1", "gsm_a.classmark3.geran_feature_package_1",
        FT_BOOLEAN, BASE_NONE, TFS(&geran_feature_package_1_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_ext_dtm_e_gprs_multi_slot_info_present,
        { "Extended DTM E/GPRS Multi Slot Information present", "gsm_a.classmark3.ext_dtm_e_gprs_info_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_ext_dtm_gprs_multi_slot_class,
        { "Extended DTM GPRS Multi Slot Class", "gsm_a.classmark3.ext_dtm_gprs_multi_slot_class",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_ext_dtm_egprs_multi_slot_class,
        { "Extended DTM EGPRS Multi Slot Class", "gsm_a.classmark3.ext_dtm_egprs_multi_slot_class",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_high_multislot_cap_present,
        { "High Multislot Capability present", "gsm_a.classmark3.high_multislot_cap_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_high_multislot_cap,
        { "High Multislot Capability", "gsm_a.classmark3.high_multislot_cap",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_geran_iu_mode_support,
        { "GERAN Iu Mode Support", "gsm_a.classmark3.geran_iu_mode_support",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_geran_iu_mode_cap,
        { "GERAN Iu Mode Capabilities", "gsm_a.classmark3.geran_iu_mode_cap",
        FT_UINT24, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_geran_iu_mode_cap_length,
        { "Length", "gsm_a.classmark3.geran_iu_mode_cap.length",
        FT_UINT8, BASE_DEC, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_flo_iu_cap,
        { "FLO Iu Capability", "gsm_a.classmark3.geran_iu_mode_cap.flo_iu_cap",
        FT_BOOLEAN, BASE_NONE, TFS(&flo_iu_cap_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_geran_feature_package_2,
        { "GERAN Feature Package 2", "gsm_a.classmark3.geran_feature_package_2",
        FT_BOOLEAN, BASE_NONE, TFS(&geran_feature_package_2_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_gmsk_multislot_power_prof,
        { "GMSK Multislot Power Profile", "gsm_a.classmark3.gmsk_multislot_power_prof",
        FT_UINT8, BASE_DEC, VALS(gmsk_multislot_power_prof_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_8_psk_multislot_power_prof,
        { "8-PSK Multislot Power Profile", "gsm_a.classmark3.8_psk_multislot_power_prof",
        FT_UINT8, BASE_DEC, VALS(eight_psk_multislot_power_prof_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_t_gsm_400_band_info_present,
        { "T-GSM 400 Band Information present", "gsm_a.classmark3.gsm_400_band_info_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_t_gsm_400_bands_supported,
        { "T-GSM 400 Bands Supported", "gsm_a.classmark3.t_gsm_400_bands_supported",
        FT_UINT8, BASE_HEX, VALS(t_gsm_400_bands_supported_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_t_gsm_400_assoc_radio_cap,
        { "T-GSM 400 Associated Radio Capability", "gsm_a.classmark3.t_gsm_400_assoc_radio_cap",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_t_gsm_900_assoc_radio_cap_present,
        { "T-GSM 900 Associated Radio Capability present", "gsm_a.classmark3.t_gsm_900_assoc_radio_cap_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_t_gsm_900_assoc_radio_cap,
        { "T-GSM 900 Associated Radio Capability", "gsm_a.classmark3.t_gsm_900_assoc_radio_cap",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_downlink_adv_receiver_perf,
        { "Downlink Advanced Receiver Performance", "gsm_a.classmark3.downlink_adv_receiver_perf",
        FT_UINT8, BASE_DEC, VALS(downlink_adv_receiver_perf_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_dtm_enhancements_cap,
        { "DTM Enhancements Capability", "gsm_a.classmark3.dtm_enhancements_capability",
        FT_BOOLEAN, BASE_NONE, TFS(&dtm_enhancements_cap_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_dtm_e_gprs_high_multi_slot_info_present,
        { "DTM E/GPRS High Multi Slot Information present", "gsm_a.classmark3.dtm_e_gprs_high_mutli_slot_info_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_dtm_gprs_high_multi_slot_class,
        { "DTM GPRS Multi Slot Class", "gsm_a.classmark3.dtm_gprs_multi_slot_class",
        FT_UINT8, BASE_DEC, VALS(dtm_gprs_high_multi_slot_class_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_offset_required,
        { "Offset required", "gsm_a.classmark3.offset_required",
        FT_BOOLEAN, BASE_NONE, TFS(&offset_required_vals), 0x0,
        NULL, HFILL}
    },
    { &hf_gsm_a_dtm_egprs_high_multi_slot_class_present,
        { "DTM EGPRS High Multi Slot Class present", "gsm_a.classmark3.dtm_egprs_high_multi_slot_class_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_dtm_egprs_high_multi_slot_class,
        { "DTM EGPRS High Multi Slot Class", "gsm_a.classmark3.dtm_egprs_high_multi_slot_class",
        FT_UINT8, BASE_DEC, VALS(dtm_gprs_high_multi_slot_class_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_repeated_acch_cap,
        { "Repeated ACCH Capability", "gsm_a.classmark3.repeated_acch_cap",
        FT_BOOLEAN, BASE_NONE, TFS(&repeated_acch_cap_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_gsm_710_assoc_radio_cap_present,
        { "GSM 710 Associated Radio Capability present", "gsm_a.classmark3.gsm_710_assoc_radio_cap_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_gsm_710_assoc_radio_cap,
        { "GSM 710 Associated Radio Capability", "gsm_a.classmark3.gsm_710_assoc_radio_cap",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_t_gsm_810_assoc_radio_cap_present,
        { "T-GSM 810 Associated Radio Capability present", "gsm_a.classmark3.t_gsm_810_assoc_radio_cap_present",
        FT_BOOLEAN, BASE_NONE, TFS(&true_false_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_t_gsm_810_assoc_radio_cap,
        { "T-GSM 810 Associated Radio Capability", "gsm_a.classmark3.t_gsm_810_assoc_radio_cap",
        FT_UINT8, BASE_HEX, NULL, 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_ciphering_mode_setting_cap,
        { "Ciphering Mode Setting Capability", "gsm_a.classmark3.ciphering_mode_setting_cap",
        FT_BOOLEAN, BASE_NONE, TFS(&ciphering_mode_setting_cap_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_additional_positioning_caps,
        { "Additional Positioning Capabilities", "gsm_a.classmark3.additional_positioning_caps",
        FT_BOOLEAN, BASE_NONE, TFS(&additional_positioning_caps_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_e_utra_fdd_support,
        { "E-UTRA FDD support", "gsm_a.classmark3.e_utra_fdd_support",
        FT_BOOLEAN, BASE_NONE, TFS(&e_utra_fdd_support_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_e_utra_tdd_support,
        { "E-UTRA TDD support", "gsm_a.classmark3.e_utra_tdd_support",
        FT_BOOLEAN, BASE_NONE, TFS(&e_utra_tdd_support_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_e_utra_meas_and_report_support,
        { "E-UTRA Measurement and Reporting support", "gsm_a.classmark3.e_utra_meas_and_report_support",
        FT_BOOLEAN, BASE_NONE, TFS(&e_utra_meas_and_report_support_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_prio_based_resel_support,
        { "Priority-based reselection support", "gsm_a.classmark3.prio_based_resel_support",
        FT_BOOLEAN, BASE_NONE, TFS(&prio_based_resel_support_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_utra_csg_cells_reporting,
        { "UTRA CSG Cells Reporting", "gsm_a.classmark3.utra_csg_cells_reporting",
        FT_BOOLEAN, BASE_NONE, TFS(&utra_csg_cells_reporting_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_vamos_level,
        { "VAMOS Level", "gsm_a.classmark3.vamos_level",
        FT_UINT8, BASE_DEC, VALS(vamos_level_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_tighter_cap,
        { "TIGHTER Capability", "gsm_a.classmark3.tighter_cap",
        FT_UINT8, BASE_DEC, VALS(tighter_cap_level_vals), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_selective_ciph_down_sacch,
        { "Selective Ciphering of Downlink SACCH", "gsm_a.classmark3.selective_ciph_down_sacch",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x00,
        NULL, HFILL}
    },
    { &hf_gsm_a_geo_loc_type_of_shape,
        { "Location estimate", "gsm_a.gad.location_estimate",
        FT_UINT8, BASE_DEC, VALS(type_of_shape_vals), 0xf0,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_sign_of_lat,
        { "Sign of latitude", "gsm_a.gad.sign_of_latitude",
        FT_UINT8, BASE_DEC, VALS(sign_of_latitude_vals), 0x80,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_deg_of_lat,
        { "Degrees of latitude", "gsm_a.gad.sign_of_latitude",
        FT_UINT24, BASE_DEC, NULL, 0x7fffff,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_deg_of_long,
        { "Degrees of longitude", "gsm_a.gad.sign_of_longitude",
        FT_UINT24, BASE_DEC, NULL, 0xffffff,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_uncertainty_code,
        { "Uncertainty code", "gsm_a.gad.uncertainty_code",
        FT_UINT8, BASE_DEC, NULL, 0x7f,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_uncertainty_semi_major,
        { "Uncertainty semi-major", "gsm_a.gad.uncertainty_semi_major",
        FT_UINT8, BASE_DEC, NULL, 0x7f,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_uncertainty_semi_minor,
        { "Uncertainty semi-minor", "gsm_a.gad.uncertainty_semi_minor",
        FT_UINT8, BASE_DEC, NULL, 0x7f,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_orientation_of_major_axis,
        { "Orientation of major axis", "gsm_a.gad.orientation_of_major_axis",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_uncertainty_altitude,
        { "Uncertainty Altitude", "gsm_a.gad.uncertainty_altitude",
        FT_UINT8, BASE_DEC, NULL, 0x7f,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_confidence,
        { "Confidence(%)", "gsm_a.gad.confidence",
        FT_UINT8, BASE_DEC, NULL, 0x7f,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_no_of_points,
        { "Number of points", "gsm_a.gad.no_of_points",
        FT_UINT8, BASE_DEC, NULL, 0x0f,
        NULL, HFILL }
    },
    { &hf_gsm_a_velocity_type,
        { "Number of points", "gsm_a.gad.velocity_type",
        FT_UINT8, BASE_DEC, VALS(gsm_a_velocity_type_vals), 0xf0,
        NULL, HFILL }
    },
    { &hf_gsm_a_bearing,
        { "Bearing", "gsm_a.gad.bearing",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_horizontal_speed,
        { "Horizontal Speed", "gsm_a.gad.horizontal_velocity",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_vertical_speed,
        { "Vertical Speed", "gsm_a.gad.vertical_speed",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_uncertainty_speed,
        { "Uncertainty Speed", "gsm_a.gad.uncertainty_speed",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_h_uncertainty_speed,
        { "Horizontal Uncertainty Speed", "gsm_a.gad.v_uncertainty_speed",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_v_uncertainty_speed,
        { "Vertical Uncertainty Speed", "gsm_a.gad.h_uncertainty_speed",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_d,
        { "Direction of Vertical Speed", "gsm_a.gad.d",
          FT_BOOLEAN, 8, TFS(&gsm_a_dir_of_ver_speed_vals), 0x08,
        NULL, HFILL}
    },
    { &hf_gsm_a_geo_loc_D,
        { "D: Direction of Altitude", "gsm_a.gad.D",
        FT_UINT16, BASE_DEC, VALS(dir_of_alt_vals), 0x8000,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_altitude,
        { "Altitude in meters", "gsm_a.gad.altitude",
        FT_UINT16, BASE_DEC, NULL, 0x7fff,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_inner_radius,
        { "Inner radius", "gsm_a.gad.altitude",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_uncertainty_radius,
        { "Uncertainty radius", "gsm_a.gad.no_of_points",
        FT_UINT8, BASE_DEC, NULL, 0x7f,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_offset_angle,
        { "Offset angle", "gsm_a.gad.offset_angle",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_geo_loc_included_angle,
        { "Included angle", "gsm_a.gad.included_angle",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_a_key_seq,
        { "key sequence", "gsm_a.key_seq",
        FT_UINT8, BASE_DEC, VALS(gsm_a_key_seq_vals), 0x07,
        NULL, HFILL }
    },
    { &hf_gsm_a_lac,
        { "Location Area Code (LAC)", "gsm_a.lac",
        FT_UINT16, BASE_HEX_DEC, NULL, 0x00,
        NULL, HFILL }
    },
    { &hf_gsm_a_spare_nibble,
        { "Spare Nibble", "gsm_a.spare",
        FT_UINT8, BASE_DEC_HEX, NULL, 0x00,
        NULL, HFILL }
    },
    };

    /* Setup protocol subtree array */
#define NUM_INDIVIDUAL_ELEMS    0
    static gint *ett[NUM_INDIVIDUAL_ELEMS +
            NUM_GSM_COMMON_ELEM];

    last_offset = NUM_INDIVIDUAL_ELEMS;

    for (i=0; i < NUM_GSM_COMMON_ELEM; i++, last_offset++)
    {
        ett_gsm_common_elem[i] = -1;
        ett[last_offset]       = &ett_gsm_common_elem[i];
    }

    /* Register the protocol name and description */

    proto_a_common =
    proto_register_protocol("GSM A-I/F COMMON", "GSM COMMON", "gsm_a");

    proto_register_field_array(proto_a_common, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));

    gsm_a_tap = register_tap("gsm_a");
}

