/* packet-gsm_bssmap_le.c
 * Routines for GSM Lb Interface BSSMAP dissection
 *
 * Copyright 2008, Johnny Mitrevski <mitrevj@hotmail.com>
 *
 * 3GPP TS 49.031 version v7.4.0 (2009-09)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/tap.h>
#include <epan/tfs.h>
#include <wsutil/array.h>
#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>
#include "packet-bssap.h"
#include "packet-gsm_a_common.h"

void proto_register_gsm_bssmap_le(void);
void proto_reg_handoff_gsm_bssmap_le(void);

/* PROTOTYPES/FORWARDS */

/* Table 10.1 Message Type definitions */
#define BSSMAP_LE_PERFORM_LOCATION_REQUEST              43
#define BSSMAP_LE_PERFORM_LOCATION_RESPONSE             45
#define BSSMAP_LE_PERFORM_LOCATION_ABORT                46
#define BSSMAP_LE_PERFORM_LOCATION_INFORMATION          47
#define BSSMAP_LE_ASSISTANCE_INFORMATION_REQUEST        32
#define BSSMAP_LE_ASSISTANCE_INFORMATION_RESPONSE       33
#define BSSMAP_LE_CONNECTION_ORIENTED_INFORMATION       42
#define BSSMAP_LE_CONNECTIONLESS_INFORMATION            58
#define BSSMAP_LE_RESET                                 48
#define BSSMAP_LE_RESET_ACKNOWLEDGE                     49

static const value_string gsm_bssmap_le_msg_strings[] = {
	{ 0, "Reserved" },
	{ 1, "Reserved" },
	{ 2, "Reserved" },
	{ 3, "Reserved" },
	{ 4, "Reserved" },
	{ BSSMAP_LE_PERFORM_LOCATION_REQUEST,	     "Perform Location Request" },
	{ BSSMAP_LE_PERFORM_LOCATION_RESPONSE,	     "Perform Location Response" },
	{ BSSMAP_LE_PERFORM_LOCATION_ABORT,	     "Perform Location Abort" },
	{ BSSMAP_LE_PERFORM_LOCATION_INFORMATION,    "Perform Location Information" },
	{ BSSMAP_LE_ASSISTANCE_INFORMATION_REQUEST,  "Assistance Information Request" },
	{ BSSMAP_LE_ASSISTANCE_INFORMATION_RESPONSE, "Assistance Information Response" },
	{ BSSMAP_LE_CONNECTION_ORIENTED_INFORMATION, "Connection Oriented Information" },
	{ BSSMAP_LE_CONNECTIONLESS_INFORMATION,	     "Connectionless Information" },
	{ BSSMAP_LE_RESET,			     "Reset" },
	{ BSSMAP_LE_RESET_ACKNOWLEDGE,		     "Reset Acknowledge" },
	{ 0, NULL }
};

/* Table 10.2 Information Element definitions */
#define BSSMAP_LE_LCS_QOS                                    62
#define BSSMAP_LE_LCS_PRIORITY                               67
#define BSSMAP_LE_LOCATION_TYPE                              68
#define BSSMAP_LE_GANSS_LOCATION_TYPE                        130
#define BSSMAP_LE_GEOGRAPHIC_LOCATION                        69
#define BSSMAP_LE_POSITIONING_DATA                           70
#define BSSMAP_LE_GANSS_POSITIONING_DATA                     131
#define BSSMAP_LE_VELOCITY_DATA                              85
#define BSSMAP_LE_LCS_CAUSE                                  71
#define BSSMAP_LE_LCS_CLIENT_TYPE                            72
#define BSSMAP_LE_APDU                                       73
#define BSSMAP_LE_NETWORK_ELEMENT_IDENTITY                   74
#define BSSMAP_LE_REQUESTED_GPS_ASSISTANCE_DATA              75
#define BSSMAP_LE_REQUESTED_GANSS_ASSISTANCE_DATA            65
#define BSSMAP_LE_DECIPHERING_KEYS                           76
#define BSSMAP_LE_RETURN_ERROR_REQUEST                       77
#define BSSMAP_LE_RETURN_ERROR_CAUSE                         78
#define BSSMAP_LE_SEGMENTATION                               79
#define BSSMAP_LE_CLASSMARK_INFORMATION_TYPE_3               19
#define BSSMAP_LE_CAUSE                                      4
#define BSSMAP_LE_CELL_IDENTIFIER                            5
#define BSSMAP_LE_CHOSEN_CHANNEL                             33
#define BSSMAP_LE_IMSI                                       0
#define BSSMAP_LE_RESERVED_NOTE1                             1
#define BSSMAP_LE_RESERVED_NOTE2                             2
#define BSSMAP_LE_RESERVED_NOTE3                             3
#define BSSMAP_LE_LCS_CAPABILITY                             80
#define BSSMAP_LE_PACKET_MEASUREMENT_REPORT                  81
#define BSSMAP_LE_CELL_IDENTITY_LIST                         82
#define BSSMAP_LE_IMEI                                       128
#define BSSMAP_LE_BSS_MULTILATERATION_CAPABILITY             132
#define BSSMAP_LE_CELL_INFORMATION_LIST                      133
#define BSSMAP_LE_BTS_RECEPTION_ACCURACY_LEVEL               134
#define BSSMAP_LE_MULTILATERATION_POSITIONING_METHOD         135
#define BSSMAP_LE_MULTILATERATION_TIMING_ADVANCE             136
#define BSSMAP_LE_MS_SYNC_ACCURACY                           137
#define BSSMAP_LE_SHORT_ID_SET                               138
#define BSSMAP_LE_RANDOM_ID_SET                              139
#define BSSMAP_LE_SHORT_BSS_ID                               140
#define BSSMAP_LE_RANDOM_ID                                  141
#define BSSMAP_LE_SHORT_ID                                   142
#define BSSMAP_LE_COVERAGE_CLASS                             143
#define BSSMAP_LE_MTA_ACCESS_SECURITY_REQUIRED               144

static const value_string gsm_bssmap_le_elem_strings[] = {
	{ DE_BMAPLE_LCSQOS,		"LCS QoS" },
	{ DE_BMAPLE_LCS_PRIO,		"LCS Priority" },
	{ DE_BMAPLE_LOC_TYPE,		"Location Type" },
	{ DE_BMAPLE_GANSS_LOC_TYPE,	"GANSS Location Type" },
	{ DE_BMAPLE_GEO_LOC,		"Geographic Location" },
	{ DE_BMAPLE_POS_DATA,		"Positioning Data" },
	{ DE_BMAPLE_GANSS_POS_DATA,	"GANSS Positioning Data" },
	{ DE_BMAPLE_VELOC_DATA,		"Velocity Data" },
	{ DE_BMAPLE_LCS_CAUSE,		"LCS Cause" },
	{ DE_BMAPLE_LCS_CLIENT_TYPE,	"LCS Client Type" },
	{ DE_BMAPLE_APDU,		"APDU" },
	{ DE_BMAPLE_NETWORK_ELEM_ID,	"Network Element Identity" },
	{ DE_BMAPLE_REQ_GPS_ASSIST_D,	"Requested GPS Assistance Data" },
	{ DE_BMAPLE_REQ_GNSS_ASSIST_D,	"Requested GANSS Assistance Data" },
	{ DE_BMAPLE_DECIPH_KEYS,	"Deciphering Keys" },
	{ DE_BMAPLE_RETURN_ERROR_REQ,	"Return Error Request" },
	{ DE_BMAPLE_RETURN_ERROR_CAUSE, "Return Error Cause" },
	{ DE_BMAPLE_SEGMENTATION,	"Segmentation" },
	{ DE_BMAPLE_CLASSMARK_TYPE_3,	"Classmark Information Type 3" },
	{ DE_BMAPLE_CAUSE,		"Cause" },
	{ DE_BMAPLE_CELL_IDENTIFIER,	"Cell Identifier" },
	{ DE_BMAPLE_CHOSEN_CHANNEL,	"Chosen Channel" },
	{ DE_BMAPLE_IMSI,		"IMSI" },
	{ DE_BMAPLE_RES1,		"Reserved" },
	{ DE_BMAPLE_RES2,		"Reserved" },
	{ DE_BMAPLE_RES3,		"Reserved" },
	{ DE_BMAPLE_LCS_CAPABILITY,	"LCS Capability" },
	{ DE_BMAPLE_PACKET_MEAS_REP,	"Packet Measurement Report" },
	{ DE_BMAPLE_MEAS_CELL_ID,	"Cell Identity List" },
	{ DE_BMAPLE_IMEI,		"IMEI" },
	{ DE_BMAPLE_BSS_MLAT_CAP,	"BSS Multilateration Capability" },
	{ DE_BMAPLE_CELL_INFO_LIST,	"Cell Information List" },
	{ DE_BMAPLE_BTS_REC_ACC,	"BTS Reception Accuracy Level" },
	{ DE_BMAPLE_MLAT_POS_METHOD,	"Multilateration Positioning Method" },
	{ DE_BMAPLE_MLAT_TIMING_ADV,	"Multilateration Timing Advance" },
	{ DE_BMAPLE_MS_SYNC_ACC,	"MS Sync Accuracy" },
	{ DE_BMAPLE_SHORT_ID_SET,	"Short ID Set" },
	{ DE_BMAPLE_RANDOM_ID_SET,	"Random ID Set" },
	{ DE_BMAPLE_SHORT_BSS_ID,	"Short BSS ID" },
	{ DE_BMAPLE_RANDOM_ID,		"Random ID" },
	{ DE_BMAPLE_SHORT_ID,		"Short ID" },
	{ DE_BMAPLE_COVERAGE_CLASS,	"Coverage Class" },
	{ DE_BMAPLE_MTA_ACC_SEC_REQ,	"MTA Access Security Required" },
	{ 0, NULL }
};
/* Using the DE_ values from the enum for the value string ensures that these
 * are sorted in numerical order, unlike the values from Table 10.2 */
value_string_ext gsm_bssmap_le_elem_strings_ext = VALUE_STRING_EXT_INIT(gsm_bssmap_le_elem_strings);

static const value_string gsm_apdu_protocol_id_strings[] = {
	{ 0,	"reserved" },
	{ 1,	"BSSLAP" },
	{ 2,	"LLP" },
	{ 3,	"SMLCPP" },
	{ 0, NULL },
};

/* Velocity Requested definitions */
static const value_string bssmap_le_velocity_requested_vals[] = {
	{ 0, "do not report velocity" },
	{ 1, "report velocity if available" },
	{ 0, NULL}
};

/* Vertical Coordinate definitions */
static const value_string bssmap_le_vertical_coordinate_indicator_vals[] = {
	{ 0, "vertical coordinate not requested" },
	{ 1, "vertical coordinate is requested" },
	{ 0, NULL}
};

/* Horizontal Accuracy definitions */
static const value_string bssmap_le_horizontal_accuracy_indicator_vals[] = {
	{ 0, "horizontal accuracy is not specified" },
	{ 1, "horizontal accuracy is specified" },
	{ 0, NULL}
};

/* Vertical Accuracy definitions */
static const value_string bssmap_le_vertical_accuracy_indicator_vals[] = {
	{ 0, "vertical accuracy is not specified" },
	{ 1, "vertical accuracy is specified" },
	{ 0, NULL}
};

/* Response Time definitions */
static const value_string bssmap_le_response_time_definitions_vals[] = {
	{ 0, "Response Time is not specified" },
	{ 1, "Low Delay" },
	{ 2, "Delay Tolerant" },
	{ 3, "reserved" },
	{ 0, NULL}
};

static const value_string bssmap_le_loc_inf_vals[] = {
	{ 0, "Current Geographic Location" },
	{ 1, "Location Assistance Information for the target MS" },
	{ 2, "Deciphering keys for broadcast assistance data for the target MS" },
	{ 0, NULL }
};

static const value_string bssmap_le_pos_method_vals[] = {
	{ 0, "Reserved" },
	{ 1, "Mobile Assisted E-OTD" },
	{ 2, "Mobile Based E-OTD" },
	{ 3, "Assisted GPS" },
	{ 4, "Assisted GANSS" },
	{ 5, "Assisted GPS and Assisted GANSS" },
	{ 0, NULL }
};

static const value_string bssmap_le_pos_data_pos_method_vals[] = {
    { 0, "Timing Advance" },
    { 1, "Reserved" },
    { 2, "Reserved" },
    { 3, "Mobile Assisted E - OTD" },
    { 4, "Mobile Based E - OTD" },
    { 5, "Mobile Assisted GPS" },
    { 6, "Mobile Based GPS" },
    { 7, "Conventional GPS" },
    { 8, "U - TDOA" },
    { 9, "Reserved for UTRAN use only" },
    { 0xa, "Reserved for UTRAN use only" },
    { 0xb, "Reserved for UTRAN use only" },
    { 0xc, "Cell ID" },
    { 0, NULL }
};

static const value_string bssmap_le_pos_data_usage_vals[] = {
    { 0, "Attempted unsuccessfully due to failure or interruption" },
    { 1, "Attempted successfully : results not used to generate location" },
    { 2, "Attempted successfully : results used to verify but not generate location" },
    { 3, "Attempted successfully : results used to generate location" },
    { 4, "Attempted successfully : method or methods used by the MS cannot be determined" },
    { 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_bssmap_le;
int hf_gsm_bssmap_le_elem_id;

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_bssmap_le()
*/
static int hf_gsm_bssmap_le_msg_type;
static int hf_gsm_bssmap_le_apdu_protocol_id;
static int hf_gsm_bssmap_le_spare;
static int hf_gsm_bssmap_le_ciphering_key_flag;
static int hf_gsm_bssmap_le_current_deciphering_key_value;
static int hf_gsm_bssmap_le_next_deciphering_key_value;
static int hf_gsm_bssmap_le_acq_ass;
static int hf_gsm_bssmap_le_ref_time;
static int hf_gsm_bssmap_le_ref_loc;
static int hf_gsm_bssmap_le_dgps_corr;
static int hf_gsm_bssmap_le_nav_mod;
static int hf_gsm_bssmap_le_iono_mod;
static int hf_gsm_bssmap_le_utc_mod;
static int hf_gsm_bssmap_le_almanac;
static int hf_gsm_bssmap_le_ephemeris_ext_chk;
static int hf_gsm_bssmap_le_ephemeris_ext;
static int hf_gsm_bssmap_le_real_time_int;
static int hf_gsm_bssmap_le_lcs_cause_value;
static int hf_gsm_bssmap_le_diagnostic_value;
static int hf_gsm_bssmap_le_client_category;
static int hf_gsm_bssmap_le_client_subtype;
static int hf_gsm_bssmap_le_velocity_requested;
static int hf_gsm_bssmap_le_vertical_coordinate_indicator;
static int hf_gsm_bssmap_le_horizontal_accuracy_indicator;
static int hf_gsm_bssmap_le_horizontal_accuracy;
static int hf_gsm_bssmap_le_vertical_accuracy_indicator;
static int hf_gsm_bssmap_le_vertical_accuracy;
static int hf_gsm_bssmap_le_response_time_category;
static int hf_gsm_bssmap_le_apdu;
static int hf_gsm_bssmap_le_message_elements;
static int hf_gsm_bssmap_le_location_inf;
static int hf_gsm_bssmap_le_pos_method;
static int hf_gsm_bssmap_le_id_disc;
static int hf_gsm_bssmap_le_lmu_id;
static int hf_gsm_bssmap_le_pos_data_disc;
static int hf_gsm_bssmap_le_pos_data_pos_method;
static int hf_gsm_bssmap_le_pos_data_usage;
static int hf_gsm_bssmap_le_ret_err_req;
static int hf_gsm_bssmap_le_ret_err_cause;
static int hf_gsm_bssmap_le_bts_rec_acc;
static int hf_gsm_bssmap_le_tar;
static int hf_gsm_bssmap_le_mpm_timer;
static int hf_gsm_bssmap_le_mpm;
static int hf_gsm_bssmap_le_fmi;
static int hf_gsm_bssmap_le_mta;
static int hf_gsm_bssmap_le_ms_sync_acc;
static int hf_gsm_bssmap_le_random_id;
static int hf_gsm_bssmap_le_short_id;
static int hf_gsm_bssmap_le_coverage_class_dl;
static int hf_gsm_bssmap_le_coverage_class_ul;

/* Initialize the subtree pointers */
static int ett_bssmap_le_msg;

static expert_field ei_gsm_a_bssmap_le_not_decoded_yet;
static expert_field ei_gsm_a_bssmap_le_extraneous_data;
static expert_field ei_gsm_a_bssmap_le_missing_mandatory_element;

static dissector_handle_t gsm_bsslap_handle;
static dissector_handle_t bssmap_le_handle;

static proto_tree *g_tree;

#define	NUM_GSM_BSSMAP_LE_ELEM array_length(gsm_bssmap_le_elem_strings)
int ett_gsm_bssmap_le_elem[NUM_GSM_BSSMAP_LE_ELEM];

/*
 * 10.3 APDU
 */

static uint16_t
de_bmaple_apdu(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t  curr_offset;
	uint8_t   apdu_protocol_id;
	tvbuff_t *APDU_tvb;

	curr_offset = offset;

	proto_tree_add_item(tree, hf_gsm_bssmap_le_apdu, tvb, curr_offset, len, ENC_NA);

	/*
	 * dissect the embedded APDU message
	 * if someone writes a TS 09.31 dissector
	 *
	 * The APDU octets 4 to n are coded in the same way as the
	 * equivalent octet in the APDU element of 3GPP TS 49.031 BSSAP-LE.
	 */

	proto_tree_add_item_ret_uint8(tree, hf_gsm_bssmap_le_apdu_protocol_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &apdu_protocol_id);

	switch(apdu_protocol_id){
	case 1:
		/* BSSLAP
		 * the embedded message is as defined in 3GPP TS 08.71(3GPP TS 48.071 version 7.2.0 Release 7)
		 */
		APDU_tvb = tvb_new_subset_length(tvb, curr_offset+1, len-1);
		if(gsm_bsslap_handle)
			call_dissector(gsm_bsslap_handle, APDU_tvb, pinfo, g_tree);
		break;
	case 2:
		/* LLP
		 * The embedded message contains a Facility Information Element as defined in 3GPP TS 04.71
		 * excluding the Facility IEI and length of Facility IEI octets defined in 3GPP TS 04.71.(3GPP TS 44.071).
		 */
		break;
	case 3:
		/* SMLCPP
		 * The embedded message is as defined in 3GPP TS 08.31(TS 48.031).
		 */
		break;
	default:
		break;
	}

	curr_offset += len;

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_bssmap_le_extraneous_data);

	return curr_offset - offset;
}
/*
 * 10.4 Cause
 * coded as the value part of the Cause IE defined in 3GPP TS 48.008
 */
/*
 * 10.5 Cell Identifier
 * coded as the value part of the Cell Identifier IE defined in 3GPP TS 48.008
 */
/*
 * 10.6 Chosen Channel
 * coded as the value part of the Chosen Channel IE defined in 3GPP TS 48.008
 */
/*
 * 10.7 Classmark Information Type 3
 * coded as the value part of the Classmark Information Type 3 IE defined in 3GPP TS 48.008
 */
/*
 * 10.8 Deciphering Keys
 */
static uint16_t
de_bmaple_deciph_keys(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	int bit_offset;

	/* Spare bits */
	bit_offset = (offset<<3);
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
	bit_offset += 7;

	/* Extract the Ciphering Key Flag and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_ciphering_key_flag, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	/*offset++;*/

	/* Extract the Current Deciphering Key Value and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_current_deciphering_key_value, tvb, bit_offset, 56, ENC_NA);
	bit_offset += 56;
	/*offset += 7;*/

	/* Extract the Next Deciphering Key Value and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_next_deciphering_key_value, tvb, bit_offset, 56, ENC_NA);
	/*offset += 7;*/

	return len;
}
/*
 * 10.9 Geographic Location
 * contains an octet sequence identical to that for Geographical Information
 * defined in 3GPP TS 23.032..
 */
/*
 * 10.10 Requested GPS Assistance Data
 */
static uint16_t
de_bmaple_req_gps_ass_data(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;

	curr_offset = offset;

	/* Octet 3 H G F E D C B A */
	/* bit H Acquisition Assistance */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_acq_ass, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit G Reference Time */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_ref_time, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit F Reference Location */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_ref_loc, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit E DGPS Corrections */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_dgps_corr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit D Navigation Model */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_nav_mod, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit C Ionospheric Model */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_iono_mod, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit B UTC Model */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_utc_mod, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit A Almanac */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_almanac, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	/* Octet 4 P O N M L K J I
	 * bits L through P are Spare bits
	 */
	/* bit K Ephemeris Extension Check */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_ephemeris_ext_chk, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit J Ephemeris Extension */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_ephemeris_ext, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	/* bit I Real-Time Integrity */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_real_time_int, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	/* Octet 5 to Octet 8+2n Satellite related data */
	proto_tree_add_expert_format(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, curr_offset, len-2, "Satellite related data Not decoded yet");
	return len;
}
/*
 * 10.11 IMSI
 * coded as the value part of the Mobile Identity IE defined in 3GPP TS 24.008 (NOTE 1)
 * NOTE 1: The Type of identity field in the Mobile Identity IE shall
 * be ignored by the receiver
 */
/*
 * 10.12 (void)
 */
/*
 * 10.13 LCS Cause
 */
static const value_string bssmap_le_lcs_cause_values[] = {
	{ 0, "Unspecified" },
	{ 1, "System Failure" },
	{ 2, "Protocol Error" },
	{ 3, "Data missing in position request" },
	{ 4, "Unexpected data value in position request" },
	{ 5, "Position method failure" },
	{ 6, "Target MS Unreachable" },
	{ 7, "Location request aborted" },
	{ 8, "Facility not supported" },
	{ 9, "Inter-BSC Handover Ongoing" },
	{ 10, "Intra-BSC Handover Complete" },
	{ 11, "Congestion" },
	{ 12, "Inter NSE cell change" },
	{ 13, "Routing Area Update" },
	{ 14, "PTMSI reallocation" },
	{ 15, "Suspension of GPRS services" },
	{ 0, NULL}
};

static const value_string bssmap_le_position_method_failure_diagnostic_vals[] = {
	{ 0, "Congestion" },
	{ 1, "insufficientResources" },
	{ 2, "insufficientMeasurementData" },
	{ 3, "inconsistentMeasurementData" },
	{ 4, "locationProcedureNotCompleted" },
	{ 5, "locationProcedureNotSupportedByTargetMS" },
	{ 6, "qoSNotAttainable" },
	{ 7, "positionMethodNotAvailableInNetwork" },
	{ 8, "positionMethodNotAvailableInLocationArea" },
	{ 0, NULL}
};
static uint16_t
de_bmaple_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;

	curr_offset = offset;

	/* cause value  */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_lcs_cause_value, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	if (len == 2)
	{
		/* Diagnostic value (note) */
		proto_tree_add_item(tree, hf_gsm_bssmap_le_diagnostic_value, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
		curr_offset++;
	}

	return curr_offset - offset;
}
/*
 * 10.14 LCS Client Type
 */
/* Client Category definitions */
static const value_string bssmap_le_client_category[] = {
	{ 0, "Value Added Client" },
	{ 2, "PLMN Operator" },
	{ 3, "Emergency Services"},
	{ 4, "Lawful Intercept Services"},
	{ 0, NULL}
};

/* Client Subtype definitions */
static const value_string bssmap_le_client_subtype[] = {
	{ 0, "unspecified" },
	{ 1, "broadcast service" },
	{ 2, "O&M" },
	{ 3, "anonymous statistics" },
	{ 4, "Target MS service support" },
	{ 0, NULL}
};

static uint16_t
de_bmaple_client(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;
	uint8_t bitCount;

	bitCount = offset<<3;
	curr_offset = offset;

	/* Extract the client category and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_client_category, tvb, bitCount, 4, ENC_BIG_ENDIAN);
	bitCount = bitCount + 4;

	/* Extract the client subtype and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_client_subtype, tvb, bitCount, 4, ENC_BIG_ENDIAN);
	/*bitCount = bitCount + 4;*/
	curr_offset++;

	return curr_offset - offset;
}
/*
 * 10.15 LCS Priority
 * coded as the LCS-Priority octet in 3GPP TS 29.002
 */
/*
 * 10.16 LCS QoS
 */
static uint16_t
de_bmaple_lcs_qos(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint64_t verticalCoordIndicator, velocityRequested, horizontalAccuracyIndicator, verticalAccuracyIndicator;
	uint16_t bitCount;

	bitCount = offset << 3;

	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, bitCount, 6, ENC_BIG_ENDIAN);
	bitCount = bitCount + 6;

	/* Extract Velocity requested element */
	proto_tree_add_bits_ret_val(tree, hf_gsm_bssmap_le_velocity_requested, tvb, bitCount, 1, &velocityRequested, ENC_BIG_ENDIAN);
	bitCount++;

	/* Extract vertical coordinator element */
	proto_tree_add_bits_ret_val(tree, hf_gsm_bssmap_le_vertical_coordinate_indicator, tvb, bitCount, 1, &verticalCoordIndicator, ENC_BIG_ENDIAN);
	bitCount++;

	/* Extract horizontal accuracy element */
	proto_tree_add_bits_ret_val(tree, hf_gsm_bssmap_le_horizontal_accuracy_indicator, tvb, bitCount, 1, &horizontalAccuracyIndicator, ENC_BIG_ENDIAN);
	bitCount++;

	if(horizontalAccuracyIndicator == 1)
	{
		proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_horizontal_accuracy, tvb, bitCount, 7, ENC_BIG_ENDIAN);
		bitCount = bitCount + 7;
	}
	else
	{
		proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, bitCount, 7, ENC_BIG_ENDIAN);
		bitCount = bitCount + 7;
	}

	/* Extract vertical accuracy element */
	proto_tree_add_bits_ret_val(tree, hf_gsm_bssmap_le_vertical_accuracy_indicator, tvb, bitCount, 1, &verticalAccuracyIndicator, ENC_BIG_ENDIAN);
	bitCount++;

	if(verticalAccuracyIndicator == 1)
	{
		proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_vertical_accuracy, tvb, bitCount, 7, ENC_BIG_ENDIAN);
		bitCount = bitCount + 7;
	}
	else
	{
		proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, bitCount, 7, ENC_BIG_ENDIAN);
		bitCount = bitCount + 7;
	}

	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_response_time_category, tvb, bitCount, 2, ENC_BIG_ENDIAN);
	/*bitCount = bitCount + 2;*/

	return len;
}
/*
 * 10.17 (void)
 */
/*
 * 10.18 Location Type
 */
static uint16_t
de_bmaple_location_type(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t	curr_offset;

	curr_offset = offset;

	/* Location information (octet 3)  */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_location_inf, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;
	if (len == 1) {
		return len;
	}
	/* Positioning Method (octet 4) */
	proto_tree_add_item(tree, hf_gsm_bssmap_le_pos_method, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
	curr_offset++;

	return curr_offset - offset;
}

/*
 * 10.19 Network Element Identity
 */
static const value_string bssmap_le_id_disc_vals[] = {
	{ 0, "Identification using the MCC + MNC + LAC + CI"},
	{ 1, "Identification using the LAC + CI"},
	{ 4, "Identification using the MCC + MNC + LAC"},
	{ 5, "Identification using the LAC"},
	{ 6, "Identification using the LMU ID"},
	{ 0, NULL }
};
/* Dissector for the Network Element Identity element */
static uint16_t
de_bmaple_network_elem_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t  curr_offset;
	uint8_t disc;

	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, offset << 3, 4, ENC_NA);
	proto_tree_add_item_ret_uint8(tree, hf_gsm_bssmap_le_id_disc, tvb, offset, 1, ENC_NA, &disc);
	curr_offset = offset + 1;

	switch (disc) {
	case 0:
	case 1:
	case 4:
	case 5:
		curr_offset += be_cell_id_aux(tvb, tree, pinfo, curr_offset, len, add_string, string_len, disc);
		break;
	case 6:
		proto_tree_add_item(tree, hf_gsm_bssmap_le_lmu_id, tvb, offset, len - 1, ENC_NA);
		break;
	default:
		break;
	}

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset, pinfo, &ei_gsm_a_bssmap_le_extraneous_data);

	return curr_offset - offset;
}

/*
 * 10.20 Positioning Data
 */
static uint16_t
de_bmaple_pos_dta(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	uint32_t  curr_offset, value;

	curr_offset = offset;

	/* Octet 3	spare	Positioning Data Discriminator*/
	proto_tree_add_item_ret_uint(tree, hf_gsm_bssmap_le_pos_data_disc, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &value);
	curr_offset++;

	if (value != 0) {
		return len;
	}
	/* 0000	indicate usage of each positioning method that was attempted either successfully or unsuccessfully;
	 * 1 octet of data is provided for each positioning method included
	 */
	while (curr_offset < (offset +len)) {
		/* Octet x	positioning method	usage*/
		proto_tree_add_item(tree, hf_gsm_bssmap_le_pos_data_pos_method, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_gsm_bssmap_le_pos_data_usage, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
		curr_offset++;
	}

	return len;
}

/*
 * 10.21 Return Error Request
 */
static const value_string bssmap_le_ret_err_req_vals[] = {
	{ 0, "Return an unsegmented APDU or the first segment of a segmented APDU" },
	{ 0, NULL }
};

static uint16_t
de_bmaple_ret_err_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_item(tree, hf_gsm_bssmap_le_ret_err_req, tvb, offset, 1, ENC_NA);

	return len;
}

/*
 * 10.22 Return Error Cause
 */
static const value_string bssmap_le_ret_err_cause_vals[] = {
	{ 0, "Unspecified" },
	{ 1, "System Failure" },
	{ 2, "Protocol Error" },
	{ 3, "Destination unknown" },
	{ 4, "Destination unreachable" },
	{ 5, "Congestion" },
	{ 0, NULL }
};

static uint16_t
de_bmaple_ret_err_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_item(tree, hf_gsm_bssmap_le_ret_err_cause, tvb, offset, 1, ENC_NA);

	return len;
}
/*
 * 10.23 (void)
 */
/*
 * 10.24 Segmentation
 */
/*
 * 10.25 (void)
 */
/*
 * 10.26 LCS Capability
 * coded as the value part of the LCS Capability
 * information element in 3GPP TS 48.018, not including
 * 3GPP TS 48.018 IEI and length indicator
 */
/* Dissector for the LCS Capability element */
static uint16_t
be_lcs_capability(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	/* Extract the LCS Capability element and add to protocol tree */
	proto_tree_add_expert(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, offset, len);
	return len;
}

/*
 * 10.27 Packet Measurement Report
 * coded as the Packet Measurement Report
 * message or the Packet Enhanced Measurement Report message
 * starting with the 6-bit MESSAGE_TYPE (see clause 11 in
 * 3GPP TS 44.060) and ending with the Non-distribution contents
 * (i.e. the RLC/MAC padding bits are not included). The end of the
 * message is padded with 0-bits to the nearest octet boundary.
 */
/* Dissector for the Packet Measurement Report element */
static uint16_t
be_packet_meas_rep(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	/* Extract the Packet Measurement Report element and add to protocol tree */
	proto_tree_add_expert(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, offset, len);

	return len;
}

/*
 * 10.28 Cell Identity List
 * coded as the value part of the Cell Identity List IE
 * defined in 3GPP TS 48.071.
 */
/* Dissector for the Measured Cell Identity List element */
static uint16_t
be_measured_cell_identity(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	/* Extract the Measured Cell Identity List element and add to protocol tree */
	proto_tree_add_expert(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, offset, len);

	return len;
}

/*
 * 10.29 IMEI
 * IMEI coded as the value part of the Mobile Identity IE defined in
 * 3GPP TS 24.008 (NOTE 1)
 * NOTE 1: The Type of identity field in the Mobile Identity IE shall
 * be ignored by the receiver.
 */
/*
 * 10.30 Velocity Data
 * contains an octet sequence identical to that for Description of
 * Velocity defined in 3GPP TS 23.032.
 */
/*
 * 10.31 Requested GANSS Assistance Data
 */
/*
 * 10.32 GANSS Positioning Data
 */
/*
 * 10.33 GANSS Location Type
 */

/*
 * 10.34 BSS Multilateration Capability
 */
/* Dissector for the BSS Multilateration Capability element */
static uint16_t
de_bmaple_bss_mlat_cap(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_expert(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, offset, len);
	return len;
}

/*
 * 10.35 Cell Information List
 */
/* Dissector for the Cell Information List element */
static uint16_t
de_bmaple_cell_info_list(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_expert(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, offset, len);
	return len;
}

/*
 * 10.36 BTS Reception Accuracy Level
 */

static const value_string bssmap_le_bts_rec_acc_vals[] = {
	{ 0, "BTS Rec. Acc < 1/32 of a symbol period" },
	{ 1, "1/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 1/16 of a symbol period" },
	{ 2, "1/16 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 3/32 of a symbol period" },
	{ 3, "3/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 1/8 of a symbol period" },
	{ 4, "1/8 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 5/32 of a symbol period" },
	{ 5, "5/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 3/16 of a symbol period" },
	{ 6, "3/16 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 7/32 of a symbol period" },
	{ 7, "7/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 1/4 of a symbol period" },
	{ 8, "1/4 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 9/32 of a symbol period" },
	{ 9, "9/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 5/16 of a symbol period" },
	{ 10, "5/16 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 11/32 of a symbol period" },
	{ 11, "11/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 3/8 of a symbol period" },
	{ 12, "3/8 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 13/32 of a symbol period" },
	{ 13, "13/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 7/16 of a symbol period" },
	{ 14, "7/16 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 15/32 of a symbol period" },
	{ 15, "15/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 1/2 of a symbol period" },
	{ 16, "1/2 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 17/32 of a symbol period" },
	{ 17, "17/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 9/16 of a symbol period" },
	{ 18, "9/16 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 19/32 of a symbol period" },
	{ 19, "19/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 5/8 of a symbol period" },
	{ 20, "5/8 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 21/32 of a symbol period" },
	{ 21, "21/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 11/16 of a symbol period" },
	{ 22, "11/16 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 23/32 of a symbol period" },
	{ 23, "23/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 3/4 of a symbol period" },
	{ 24, "3/4 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 25/32 of a symbol period" },
	{ 25, "25/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 13/16 of a symbol period" },
	{ 26, "13/16 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 27/32 of a symbol period" },
	{ 27, "27/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 7/8 of a symbol period" },
	{ 28, "7/8 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 29/32 of a symbol period" },
	{ 29, "29/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 15/16 of a symbol period" },
	{ 30, "15/16 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 31/32 of a symbol period" },
	{ 31, "31/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " BTS Rec. Acc < 1 symbol period" },
	{ 0, NULL}
};

/* Dissector for the BTS Reception Accuracy Level element */
static uint16_t
de_bmaple_bts_rec_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, offset << 3, 3, ENC_NA);
	proto_tree_add_item(tree, hf_gsm_bssmap_le_bts_rec_acc, tvb, offset, 1, ENC_NA);

	return 1;
}

/*
 * 10.37 Multilateration Positioning Method
 */
static const value_string bssmap_le_mpm_vals[] = {
	{ 0, "RLC Data Block method trigger" },
	{ 1, "Access Burst method triggered" },
	{ 2, "Extended Access Burst method triggered"},
	{ 3, "reserved"},
	{ 0, NULL}
};

static const value_string bssmap_le_mpm_timer_vals[] = {
	{ 0, "2 seconds" },
	{ 1, "4 seconds" },
	{ 2, "6 seconds" },
	{ 3, "8 seconds" },
	{ 4, "10 seconds" },
	{ 5, "15 seconds" },
	{ 6, "20 seconds" },
	{ 7, "25 seconds" },
	{ 0, NULL}
};

/* Dissector for the Multilateration Positioning Method element */
static uint16_t
de_bmaple_mlat_pos_method(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, offset << 3, 2, ENC_NA);
	proto_tree_add_item(tree, hf_gsm_bssmap_le_tar, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_gsm_bssmap_le_mpm_timer, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_gsm_bssmap_le_mpm, tvb, offset, 1, ENC_NA);

	return 1;
}

/*
 * 10.38 Multilateration Timing Advance
 */
static const value_string bssmap_le_fmi_vals[] = {
	{ 0, "MTA information valid - additional MTA information pending" },
	{ 1, "MTA information valid - SMLC shall terminate MTA procedure" },
	{ 2, "MTA information not valid - SMLC shall terminate MTA procedure" },
	{ 3, "Reserved"},
	{ 0, NULL}
};

static const crumb_spec_t bssmap_le_mta_crumbs[] = {
	{ 4, 8 },
	{ 0, 4 },
	{ 0, 0 }
};

static void format_mta(char *label, uint32_t val)
{
	float symbols = (float)val / 64;
	snprintf(label, ITEM_LABEL_LENGTH, "%u (%g symbol period%s)", val, symbols, plurality(symbols, "", "s"));

}

/* Dissector for the Multilateration Timing Advance element */
static uint16_t
de_bmaple_mlat_timing_adv(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	uint32_t	bit_offset;

	bit_offset = offset << 3;

	proto_tree_add_item(tree, hf_gsm_bssmap_le_fmi, tvb, offset, 1, ENC_NA);
	bit_offset += 2;
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, bit_offset, 2, ENC_NA);
	bit_offset += 2;
	/* The bitmap looks a bit odd because the low bits are in the earlier
	 * octet. */
	proto_tree_add_split_bits_item_ret_val(tree, hf_gsm_bssmap_le_mta, tvb, bit_offset, bssmap_le_mta_crumbs, NULL);

	return 2;
}

/*
 * 10.39 MS Sync Accuracy
 */

static const value_string bssmap_le_ms_sync_acc_vals[] = {
	{ 0, "MS Sync. Acc < 1/32 of a symbol period" },
	{ 1, "1/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 1/16 of a symbol period" },
	{ 2, "1/16 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 3/32 of a symbol period" },
	{ 3, "3/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 1/8 of a symbol period" },
	{ 4, "1/8 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 5/32 of a symbol period" },
	{ 5, "5/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 3/16 of a symbol period" },
	{ 6, "3/16 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 7/32 of a symbol period" },
	{ 7, "7/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 1/4 of a symbol period" },
	{ 8, "1/4 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 9/32 of a symbol period" },
	{ 9, "9/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 5/16 of a symbol period" },
	{ 10, "5/16 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 11/32 of a symbol period" },
	{ 11, "11/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 3/8 of a symbol period" },
	{ 12, "3/8 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 13/32 of a symbol period" },
	{ 13, "13/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 7/16 of a symbol period" },
	{ 14, "7/16 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 15/32 of a symbol period" },
	{ 15, "15/32 of a symbol period " UTF8_LESS_THAN_OR_EQUAL_TO " MS Sync. Acc < 1/2 of a symbol period" },
	{ 0, NULL}
};

/* Dissector for the MS Sync Accuracy element */
static uint16_t
de_bmaple_ms_sync_acc(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, offset << 3, 4, ENC_NA);
	proto_tree_add_item(tree, hf_gsm_bssmap_le_ms_sync_acc, tvb, offset, 1, ENC_NA);

	return 1;
}

/*
 * 10.40 Short ID Set
 */
/* Dissector for the Short ID Set element */
static uint16_t
de_bmaple_short_id_set(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_expert(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, offset, len);
	return len;
}

/*
 * 10.41 Random ID Set
 */
/* Dissector for the Random ID Set element */
static uint16_t
de_bmaple_random_id_set(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_expert(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, offset, len);
	return len;
}

/*
 * 10.42 Short BSS ID
 */
/* Dissector for the Short BSS ID element */
static uint16_t
de_bmaple_short_bss_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_expert(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, offset, len);
	return len;
}

/*
 * 10.43 Random ID
 */
/* Dissector for the Random ID element */
static uint16_t
de_bmaple_random_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_item(tree, hf_gsm_bssmap_le_random_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
	return 2;
}

/*
 * 10.44 Short ID
 */
/* Dissector for the Short ID element */
static uint16_t
de_bmaple_short_id(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_item(tree, hf_gsm_bssmap_le_short_id, tvb, offset, 1, ENC_NA);
	return 1;
}

/*
 * 10.45 Coverage Class
 */
static const value_string bssmap_le_coverage_class_dl_vals[] = {
	{ 0, "reserved" },
	{ 1, "DL Coverage Class 1" },
	{ 2, "DL Coverage Class 2" },
	{ 3, "DL Coverage Class 3" },
	{ 4, "DL Coverage Class 4" },
	{ 5, "reserved" },
	{ 6, "reserved" },
	{ 7, "reserved" },
	{ 0, NULL },
};

static const value_string bssmap_le_coverage_class_ul_vals[] = {
	{ 0, "reserved" },
	{ 1, "UL Coverage Class 1" },
	{ 2, "UL Coverage Class 2" },
	{ 3, "UL Coverage Class 3" },
	{ 4, "UL Coverage Class 4" },
	{ 5, "UL Coverage Class 5" },
	{ 6, "reserved" },
	{ 7, "reserved" },
	{ 0, NULL },
};

/* Dissector for the Coverage Class element */
static uint16_t
de_bmaple_coverage_class(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len _U_, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, offset << 3, 2, ENC_NA);
	proto_tree_add_item(tree, hf_gsm_bssmap_le_coverage_class_dl, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_gsm_bssmap_le_coverage_class_ul, tvb, offset, 1, ENC_NA);

	return 1;
}

/*
 * 10.46 MTA Access Security Required
 */
/* Dissector for the MTA Access Security Required element */
static uint16_t
de_bmaple_mta_acc_sec_req(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, uint32_t offset, unsigned len, char *add_string _U_, int string_len _U_)
{
	proto_tree_add_expert(tree, pinfo, &ei_gsm_a_bssmap_le_not_decoded_yet, tvb, offset, len);
	return len;
}

#define	NUM_GSM_BSSMAP_LE_MSG array_length(gsm_bssmap_le_msg_strings)
static int ett_gsm_bssmap_le_msg[NUM_GSM_BSSMAP_LE_MSG];

/*
This enum is defined in packet-gsm_a_common.h to
make it possible to use element dissection from this dissector
in other dissectors.

It is shown here as a comment for easier reference.

Note this enum must be of the same size as the element decoding list below

typedef enum
{
	DE_BMAPLE_LCSQOS,			/ 10.16 LCS QoS /
	DE_BMAPLE_LCS_PRIO,			/ LCS Priority /
	DE_BMAPLE_LOC_TYPE,			/ 10.18 Location Type /
	DE_BMAPLE_GANSS_LOC_TYPE,	/ GANSS Location Type /
	DE_BMAPLE_GEO_LOC,			/ 10.9 Geographic Location /
	DE_BMAPLE_POS_DATA,			/ 10.20 Positioning Data /
	DE_BMAPLE_GANSS_POS_DATA,	/ GANSS Positioning Data /
	DE_BMAPLE_VELOC_DATA,		/ Velocity Data /
	DE_BMAPLE_LCS_CAUSE,		/ 10.13 LCS Cause /
	DE_BMAPLE_LCS_CLIENT_TYPE,	/ LCS Client Type /
	DE_BMAPLE_APDU,				/ 10.3 APDU /
	DE_BMAPLE_NETWORK_ELEM_ID,	/ Network Element Identity /
	DE_BMAPLE_REQ_GPS_ASSIST_D, / 10.10 Requested GPS Assistance Data /
	DE_BMAPLE_REQ_GNSS_ASSIST_D,/ Requested GANSS Assistance Data /
	DE_BMAPLE_DECIPH_KEYS,		/ 10.8 Deciphering Keys /
	DE_BMAPLE_RETURN_ERROR_REQ,	/ Return Error Request /
	DE_BMAPLE_RETURN_ERROR_CAUSE,	/ Return Error Cause /
	DE_BMAPLE_SEGMENTATION,		/ Segmentation /
	DE_BMAPLE_CLASSMARK_TYPE_3,	/ 10.7 Classmark Information Type 3 /
	DE_BMAPLE_CAUSE,			/ 10.4 Cause /
	DE_BMAPLE_CELL_IDENTIFIER,	/ 10.5 Cell Identifier /
	DE_BMAPLE_CHOSEN_CHANNEL,	/ 10.6 Chosen Channel /
	DE_BMAPLE_IMSI,				/ 10.11 IMSI /
	DE_BMAPLE_RES1,				/ Reserved /
	DE_BMAPLE_RES2,				/ Reserved /
	DE_BMAPLE_RES3,				/ Reserved /
	DE_BMAPLE_LCS_CAPABILITY,	/ LCS Capability /
	DE_BMAPLE_PACKET_MEAS_REP,	/ Packet Measurement Report /
	DE_BMAPLE_MEAS_CELL_ID,		/ Measured Cell Identity /
	DE_BMAPLE_IMEI,				/ IMEI /
	DE_BMAPLE_BSS_MLAT_CAP,         / 10.34 BSS Multilateration Capability /
	DE_BMAPLE_CELL_INFO_LIST,       / 10.35 Cell Information List /
	DE_BMAPLE_BTS_REC_ACC,          / 10.36 BTS Reception Accuracy Level /
	DE_BMAPLE_MLAT_POS_METHOD,	/ 10.37 Multilateration Positioning Method /
	DE_BMAPLE_MLAT_TIMING_ADV,	/ 10.38 Multilateration Timing Advance /
	DE_BMAPLE_MS_SYNC_ACC,		/ 10.39 MS Sync Accuracy /
	DE_BMAPLE_SHORT_ID_SET,		/ 10.40 Short ID Set /
	DE_BMAPLE_RANDOM_ID_SET,	/ 10.41 Random ID Set /
	DE_BMAPLE_SHORT_BSS_ID,		/ 10.42 Short BSS ID /
	DE_BMAPLE_RANDOM_ID,		/ 10.43 Random ID /
	DE_BMAPLE_SHORT_ID,		/ 10.44 Random ID /
	DE_BMAPLE_COVERAGE_CLASS,	/ 10.45 Coverage Class /
	DE_BMAPLE_MTA_ACC_SEC_REQ,	/ 10.46 MTA Access Security Required /
	BMAPLE_NONE					/ NONE /
}
bssmap_le_elem_idx_t;
*/


uint16_t (* const bssmap_le_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len, char *add_string, int string_len) = {
	/* NOTE: The null types below are defined elsewhere. i.e in packet-gsm_a_bssmap.c */
	de_bmaple_lcs_qos,				/* 10.16 LCS QoS */
	NULL,							/* LCS Priority */
	de_bmaple_location_type,		/* 10.18 Location Type */
	be_ganss_loc_type,				/* GANSS Location Type */
	NULL,							/* 10.9 Geographic Location */
	de_bmaple_pos_dta,				/* 10.20 Positioning Data */
	be_ganss_pos_dta,				/* GANSS Positioning Data */
	NULL,							/* Velocity Data */
	de_bmaple_cause,				/* 10.13 LCS Cause */
	de_bmaple_client,				/* LCS Client Type */
	de_bmaple_apdu,					/* APDU */
	de_bmaple_network_elem_id,			/* Network Element Identity */
	de_bmaple_req_gps_ass_data,		/* 10.10 Requested GPS Assistance Data */
	be_ganss_ass_dta,				/* Requested GANSS Assistance Data */
	de_bmaple_deciph_keys,			/* 10.8 Deciphering Keys */
	de_bmaple_ret_err_req,					/* Return Error Request */
	de_bmaple_ret_err_cause,				/* Return Error Cause */
	NULL,							/* Segmentation */
	NULL,							/* 10.7 Classmark Information Type 3 */
	NULL,							/* Cause */
	NULL,							/* Cell Identifier */
	NULL,							/* 10.6 Chosen Channel */
	de_mid,							/* 10.11 IMSI */
	NULL,							/* Reserved */
	NULL,							/* Reserved */
	NULL,							/* Reserved */
	be_lcs_capability,				/* LCS Capability */
	be_packet_meas_rep,				/* Packet Measurement Report */
	be_measured_cell_identity,		/* Measured Cell Identity List */
	de_mid,							/* IMEI (use same dissector as IMSI) */
	de_bmaple_bss_mlat_cap,			/* 10.34 BSS Multilateration Capability */
	de_bmaple_cell_info_list,		/* 10.35 Cell Information List */
	de_bmaple_bts_rec_acc,			/* 10.36 BTS Reception Accuracy Level */
	de_bmaple_mlat_pos_method,		/* 10.37 Multilateration Positioning Method */
	de_bmaple_mlat_timing_adv,		/* 10.38 Multilateration Timing Advance */
	de_bmaple_ms_sync_acc,			/* 10.39 MS Sync Accuracy */
	de_bmaple_short_id_set,			/* 10.40 Short ID Set */
	de_bmaple_random_id_set,		/* 10.41 Random ID Set */
	de_bmaple_short_bss_id,			/* 10.42 Short BSS ID */
	de_bmaple_random_id,			/* 10.43 Random ID */
	de_bmaple_short_id,			/* 10.44 Short ID */
	de_bmaple_coverage_class,		/* 10.45 Coverage Class */
	de_bmaple_mta_acc_sec_req,		/* 10.46 MTA Access Security Required */

	NULL,	/* NONE */

};

/*
 * 9.1 PERFORM LOCATION REQUEST
 */
static void
bssmap_le_perf_loc_request(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Location Type 9.1.1 M 3-n */
	ELEM_MAND_TLV(BSSMAP_LE_LOCATION_TYPE, GSM_A_PDU_TYPE_BSSMAP, BE_LOC_TYPE, NULL, ei_gsm_a_bssmap_le_missing_mandatory_element)
	/* Cell Identifier 9.1.2 O 5-10 */
	ELEM_MAND_TLV(BSSMAP_LE_CELL_IDENTIFIER, GSM_A_PDU_TYPE_BSSMAP, BE_CELL_ID, NULL, ei_gsm_a_bssmap_le_missing_mandatory_element);
	/* Classmark Information Type 3 9.1.3 O 3-14 */
	ELEM_OPT_TLV(BSSMAP_LE_CLASSMARK_INFORMATION_TYPE_3, GSM_A_PDU_TYPE_BSSMAP, BE_CM_INFO_3, NULL);
	/* LCS Client Type 9.1.4 C (note 3) 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_LCS_CLIENT_TYPE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CLIENT_TYPE, NULL);
	/* Chosen Channel 9.1.5 O 2 */
	ELEM_OPT_TLV(BSSMAP_LE_CHOSEN_CHANNEL, GSM_A_PDU_TYPE_BSSMAP, BE_CHOSEN_CHAN, NULL);
	/* LCS Priority 9.1.6 O 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_LCS_PRIORITY, GSM_A_PDU_TYPE_BSSMAP, BE_LCS_PRIO, NULL);
	/* LCS QoS 9.1.6a C (note 1) 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_LCS_QOS, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCSQOS, NULL);
	/* GPS Assistance Data 9.1.7 C (note 2) 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_REQUESTED_GPS_ASSISTANCE_DATA, GSM_A_PDU_TYPE_BSSMAP, BE_GPS_ASSIST_DATA, NULL);
	/* APDU 9.1.8 O 3-n */
	ELEM_OPT_TLV_E(BSSMAP_LE_APDU, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_APDU, NULL);
	/* LCS Capability 9.1.9 O */
	ELEM_OPT_TLV(BSSMAP_LE_LCS_CAPABILITY, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CAPABILITY, NULL);
	/* Packet Measurement Report 9.1.10 O*/
	ELEM_OPT_TLV(BSSMAP_LE_PACKET_MEASUREMENT_REPORT, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_PACKET_MEAS_REP, NULL);
	/* Measured Cell Identity List 9.1.11 O*/
	ELEM_OPT_TLV(BSSMAP_LE_CELL_IDENTITY_LIST, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_MEAS_CELL_ID, NULL);
	/* IMSI	9.1.12	O (note 4)	5-10 */
	ELEM_OPT_TLV(BSSMAP_LE_IMSI, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_IMSI, NULL);
	/* IMEI	9.1.13	O (note 4)	10 (use same decode as IMSI) */
	ELEM_OPT_TLV(BSSMAP_LE_IMEI, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_IMEI, NULL);
	/* GANSS Location Type	9.1.14	C	3 */
	ELEM_OPT_TLV(BSSMAP_LE_GANSS_LOCATION_TYPE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_GANSS_LOC_TYPE, NULL);
	/* GANSS Assistance Data	9.1.15	C (note 5)	3-n */
	ELEM_OPT_TLV(BSSMAP_LE_REQUESTED_GANSS_ASSISTANCE_DATA, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_REQ_GNSS_ASSIST_D, NULL);
	/* Table 9.1 claims the next two IEs are TLV, but they are clearly
	 * TV in the coding in section 10. Also MTA is TV in the connection
	 * oriented message. */
	/* BSS Multilateration Capability 9.1.16 C (note 3) 2 */
	ELEM_OPT_TV(BSSMAP_LE_BSS_MULTILATERATION_CAPABILITY, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_BSS_MLAT_CAP, NULL);
	/* Multilateration Timing Advance 9.1.17 C (note 2) 3 */
	ELEM_OPT_TV(BSSMAP_LE_MULTILATERATION_TIMING_ADVANCE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_MLAT_TIMING_ADV, NULL);
	/* MS Sync Accuracy 9.1.18 C (note 2) 2 */
	ELEM_OPT_TV(BSSMAP_LE_MS_SYNC_ACCURACY, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_MS_SYNC_ACC, NULL);
	/* BTS Reception Accuracy Level 9.1.19 C (note 3) 2 */
	ELEM_OPT_TV(BSSMAP_LE_BTS_RECEPTION_ACCURACY_LEVEL, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_BTS_REC_ACC, NULL);
	/* Coverage Class 9.1.20 C (note 2) 2 */
	ELEM_OPT_TV(BSSMAP_LE_COVERAGE_CLASS, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_COVERAGE_CLASS, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_bssmap_le_extraneous_data);

}

/*
 * 9.2 PERFORM LOCATION RESPONSE
 */
static void
bssmap_le_perf_loc_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Location Estimate 9.2.1 C (note 1) 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_GEOGRAPHIC_LOCATION, BSSAP_PDU_TYPE_BSSMAP, BE_LOC_EST, NULL);
	/* Positioning Data 9.2.2 O 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_POSITIONING_DATA, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_POS_DATA, NULL);
	/* Deciphering Keys 9.2.3 C (note 2) 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_DECIPHERING_KEYS, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_DECIPH_KEYS, NULL);
	/* LCS Cause 9.2.4 C (note 3) 3-n */
	ELEM_OPT_TLV(BSSMAP_LE_LCS_CAUSE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CAUSE, NULL);
	/* Velocity Estimate	9.2.5	O	3-n */
	ELEM_OPT_TLV(BSSMAP_LE_VELOCITY_DATA, BSSAP_PDU_TYPE_BSSMAP, BE_VEL_EST, NULL);
	/* GANSS Positioning Data	9.2.6	O	3-n */
	ELEM_OPT_TLV(BSSMAP_LE_GANSS_POSITIONING_DATA, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_GANSS_POS_DATA, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_bssmap_le_extraneous_data);
}

/*
 * 9.8 CONNECTION ORIENTED INFORMATION
 */
static void
bssmap_le_connection_oriented(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* APDU 9.8.1 M 3-n */
	ELEM_MAND_TLV_E(BSSMAP_LE_APDU, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_APDU, NULL, ei_gsm_a_bssmap_le_missing_mandatory_element);
	/* Segmentation 9.8.2 C 3 */
	ELEM_OPT_TLV(BSSMAP_LE_SEGMENTATION, BSSAP_PDU_TYPE_BSSMAP, BE_SEG, NULL);
	/* Multilateration Positioning Method 9.8.3 C (note 2) 2 */
	ELEM_OPT_TV(BSSMAP_LE_MULTILATERATION_POSITIONING_METHOD, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_MLAT_POS_METHOD, NULL);
	/* Cell Identifier 9.8.4 C (note 3) 7 */
	ELEM_OPT_TLV(BSSMAP_LE_CELL_IDENTIFIER, BSSAP_PDU_TYPE_BSSMAP, BE_CELL_ID, NULL);
	/* Multilateration Timing Advance 9.8.5 C (note 3) 3 */
	ELEM_OPT_TV(BSSMAP_LE_MULTILATERATION_TIMING_ADVANCE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_MLAT_TIMING_ADV, NULL);
	/* MS Sync Accuracy 9.8.6 C (note 4) 2 */
	ELEM_OPT_TV(BSSMAP_LE_MS_SYNC_ACCURACY, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_MS_SYNC_ACC, NULL);
	/* BTS Reception Accuracy Level 9.8.7 C (note 3) 2 */
	ELEM_OPT_TV(BSSMAP_LE_BTS_RECEPTION_ACCURACY_LEVEL, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_BTS_REC_ACC, NULL);
	/* Short ID 9.8.8 C (note 5) 2 */
	ELEM_OPT_TV(BSSMAP_LE_SHORT_ID, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_SHORT_ID, NULL);
	/* Random ID 9.8.9 C (note 4) 3 */
	ELEM_OPT_TV(BSSMAP_LE_RANDOM_ID, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_RANDOM_ID, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_bssmap_le_extraneous_data);
}

/*
 * 9.9	CONNECTIONLESS INFORMATION
 *
Network Element Identity (source)	3.2.2.69	Both	M	3-n
Network Element Identity (target)	3.2.2.69	Both	M	3-n
APDU	3.2.2.68	Both	M	3-n
Segmentation	3.2,2,74	Both	C (note 1)	5
Return Error Request	3.2.2.72	Both	C (note 2)	3-n
Return Error Cause	3.2.2.73	Both	C (note 3)	3-n
*/
static void
bssmap_le_connectionless(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len = len;

	ELEM_MAND_TLV(BSSMAP_LE_NETWORK_ELEMENT_IDENTITY, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_NETWORK_ELEM_ID, " (Source)", ei_gsm_a_bssmap_le_missing_mandatory_element);
	ELEM_MAND_TLV(BSSMAP_LE_NETWORK_ELEMENT_IDENTITY, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_NETWORK_ELEM_ID, " (Destination)", ei_gsm_a_bssmap_le_missing_mandatory_element);

	ELEM_OPT_TLV_E(BSSMAP_LE_APDU, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_APDU, NULL);

	ELEM_OPT_TLV(BSSMAP_LE_SEGMENTATION, BSSAP_PDU_TYPE_BSSMAP, BE_SEG, NULL);

	ELEM_OPT_TLV(BSSMAP_LE_RETURN_ERROR_REQUEST, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_RETURN_ERROR_REQ, NULL);

	ELEM_OPT_TLV(BSSMAP_LE_RETURN_ERROR_CAUSE, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_RETURN_ERROR_REQ, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_bssmap_le_extraneous_data);
}

/*
 * 9.11 RESET ACKNOWLEDGE
 * no data
 */

/*
 * 9.12 PERFORM LOCATION INFORMATION
 */
static void
bssmap_le_perf_loc_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len)
{
	uint32_t	curr_offset;
	uint32_t	consumed;
	unsigned	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Cell Identifier 9.12.1 M */
	ELEM_MAND_TLV(BSSMAP_LE_CELL_IDENTIFIER, GSM_A_PDU_TYPE_BSSMAP, BE_CELL_ID, NULL, ei_gsm_a_bssmap_le_missing_mandatory_element);
	/* APDU 9.1.8 O 3-n */
	ELEM_OPT_TLV_E(BSSMAP_LE_APDU, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_APDU, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0, pinfo, &ei_gsm_a_bssmap_le_extraneous_data);
}

/*
 * 9.13 ASSISTANCE INFORMATION REQUEST
 *
Serving Cell Identifier	10.5	M	7
Cell Identity List	10.28	M	2-n
Short ID Set		10.40	O	2-n
Random ID Set		10.41	O	19
*/

/*
 * 9.13 ASSISTANCE INFORMATION RESPONSE
 *
Cell Information List		10.35	M	2-n
Short BSS ID			10.42	C	2
MTA Access Security Required	10.46	O	3
*/

static void (* const bssmap_le_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, uint32_t offset, unsigned len) = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	bssmap_le_perf_loc_request,	/* Perform Location Request */
	bssmap_le_perf_loc_resp,	/* Perform Location Response */
	bssmap_perf_loc_abort,		/* Abort */
	bssmap_le_perf_loc_info,	/* Perform Location Information */
	NULL,				/* Assistance Information Request */
	NULL,				/* Assistance Information Response */
	bssmap_le_connection_oriented,	/* Connection Oriented Information */
	bssmap_le_connectionless,	/* Connectionless Information */
	bssmap_reset,				/* Reset */
	NULL,		/* Reset Acknowledge */

	NULL,	/* NONE */
};

static int
dissect_bssmap_le(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
	static gsm_a_tap_rec_t	tap_rec[4];
	static gsm_a_tap_rec_t *tap_p;
	static unsigned		tap_current=0;
	uint8_t	oct;
	uint32_t	offset, saved_offset;
	uint32_t	len;
	int	idx;
	proto_item	*bssmap_le_item = NULL;
	proto_tree	*bssmap_le_tree = NULL;
	const char	*str;
	sccp_msg_info_t *sccp_msg_p = (sccp_msg_info_t *)data;

	if (!(sccp_msg_p && sccp_msg_p->data.co.assoc)) {
		sccp_msg_p = NULL;
	}

	col_append_str(pinfo->cinfo, COL_INFO, "(BSSMAP LE) ");

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
	saved_offset = offset;

	g_tree = tree;

	len = tvb_reported_length(tvb);

	/*
	 * add BSSMAP message name
	 */
	oct = tvb_get_uint8(tvb, offset++);

	str = try_val_to_str_idx((uint32_t) oct, gsm_bssmap_le_msg_strings, &idx);

	if (sccp_msg_p && !sccp_msg_p->data.co.label) {
		sccp_msg_p->data.co.label = val_to_str(wmem_file_scope(), (uint32_t) oct, gsm_bssmap_le_msg_strings, "BSSMAP LE(0x%02x)");
	}

	/*
	 * create the protocol tree
	 */
	if (str == NULL)
	{
		bssmap_le_item =
		proto_tree_add_protocol_format(tree, proto_bssmap_le, tvb, 0, len,
			"Lb - I/F BSSMAP LE - Unknown BSSMAP Message Type (0x%02x)",
			oct);

		bssmap_le_tree = proto_item_add_subtree(bssmap_le_item, ett_bssmap_le_msg);
	}
	else
	{
		bssmap_le_item =
		proto_tree_add_protocol_format(tree, proto_bssmap_le, tvb, 0, -1,
			"Lb - I/F BSSMAP LE - %s",
			str);

		bssmap_le_tree = proto_item_add_subtree(bssmap_le_item, ett_gsm_bssmap_le_msg[idx]);

		col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", str);

		/*
		 * add BSSMAP message name
		 */
		proto_tree_add_uint_format(bssmap_le_tree, hf_gsm_bssmap_le_msg_type,
		tvb, saved_offset, 1, oct, "Message Type %s",str);
	}

	tap_p->pdu_type = BSSAP_PDU_TYPE_BSSMAP;
	tap_p->message_type = oct;

	tap_queue_packet(gsm_a_tap, pinfo, tap_p);

	if (str == NULL) return len;

	if (offset >= len) return len;

	/*
	 * decode elements
	 */
	if (bssmap_le_msg_fcn[idx] == NULL)
	{
		proto_tree_add_item(bssmap_le_tree, hf_gsm_bssmap_le_message_elements, tvb, offset, len - offset, ENC_NA);
	}
	else
	{
		(*bssmap_le_msg_fcn[idx])(tvb, bssmap_le_tree, pinfo, offset, len - offset);
	}

	return len;
}

/* Register the protocol with Wireshark */
void
proto_register_gsm_bssmap_le(void)
{
	unsigned i;
	unsigned last_offset;

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_gsm_bssmap_le_msg_type,
		  { "BSSMAP LE Message Type",	"gsm_bssmap_le.msgtype",
		    FT_UINT8, BASE_HEX, VALS(gsm_bssmap_le_msg_strings), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_elem_id,
		  { "Element ID",	"gsm_bssmap_le.elem_id",
		    FT_UINT8, BASE_HEX, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_apdu_protocol_id,
		  { "Protocol ID", "gsm_bssmap_le.apdu_protocol_id",
		    FT_UINT8, BASE_DEC, VALS(gsm_apdu_protocol_id_strings), 0x0,
		    "APDU embedded protocol id", HFILL }
		},
		{ &hf_gsm_bssmap_le_spare,
		  { "Spare", "gsm_bssmap_le.spare",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_ciphering_key_flag,
		  { "Ciphering Key Flag", "gsm_bssmap_le.decipheringKeys.flag",
		    FT_UINT8, BASE_DEC, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_current_deciphering_key_value,
		  { "Current Deciphering Key Value", "gsm_bssmap_le.decipheringKeys.current",
		    FT_UINT64, BASE_HEX, NULL, 0x0, NULL,
		    HFILL}
		},
		{ &hf_gsm_bssmap_le_next_deciphering_key_value,
		  { "Next Deciphering Key Value", "gsm_bssmap_le.decipheringKeys.next",
		    FT_UINT64, BASE_HEX, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_acq_ass,
		  { "Acquisition Assistance", "gsm_bssmap_le.acq_ass",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x80,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ref_time,
		  { "Reference Time", "gsm_bssmap_le.ref_time",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x40,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ref_loc,
		  { "Reference Location", "gsm_bssmap_le.ref_loc",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x20,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_dgps_corr,
		  { "DGPS Corrections", "gsm_bssmap_le.gps_corr",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x08,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_nav_mod,
		  { "Navigation Model", "gsm_bssmap_le.nav_mod",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x10,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_iono_mod,
		  { "Ionospheric Model", "gsm_bssmap_le.iono_mod",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x04,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_utc_mod,
		  { "UTC Model", "gsm_bssmap_le.utc_mod",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_almanac,
		  { "Almanac", "gsm_bssmap_le.almanac",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ephemeris_ext_chk,
		  { "Ephemeris Extension Check", "gsm_bssmap_le.ephemeris_ext_chk",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x04,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ephemeris_ext,
		  { "Ephemeris Extension", "gsm_bssmap_le.ephemeris_ext",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x02,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_real_time_int,
		  { "Real-Time Integrity", "gsm_bssmap_le.real_time_int",
		    FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_lcs_cause_value,
		  { "Cause Value", "gsm_bssmap_le.lcsCauseValue",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_lcs_cause_values), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_diagnostic_value,
		  { "Diagnostic Value", "gsm_bssmap_le.diagnosticValue",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_position_method_failure_diagnostic_vals), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_client_category,
		  { "Client Category", "gsm_bssmap_le.lcsClientType.clientCategory",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_client_category), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_client_subtype,
		  { "Client Subtype", "gsm_bssmap_le.lcsClientType.clientSubtype",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_client_subtype), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_velocity_requested,
		  { "Velocity Requested", "gsm_bssmap_le.lcsQos.velocityRequested",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_velocity_requested_vals), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_vertical_coordinate_indicator,
		  { "Vertical Coordinate Indicator", "gsm_bssmap_le.lcsQos.verticalCoordinateIndicator",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_vertical_coordinate_indicator_vals), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_horizontal_accuracy_indicator,
		  { "Horizontal Accuracy Indicator", "gsm_bssmap_le.lcsQos.horizontalAccuracyIndicator",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_horizontal_accuracy_indicator_vals), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_horizontal_accuracy,
		  { "Horizontal Accuracy", "gsm_bssmap_le.lcsQos.horizontalAccuracy",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_vertical_accuracy,
		  { "Vertical Accuracy", "gsm_bssmap_le.lcsQos.verticalAccuracy",
		    FT_UINT8, BASE_HEX, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_vertical_accuracy_indicator,
		  { "Vertical Accuracy Indicator", "gsm_bssmap_le.lcsQos.verticalAccuracyIndicator",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_vertical_accuracy_indicator_vals), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_response_time_category,
		  { "Response Time Category", "gsm_bssmap_le.lcsQos.responseTimeCategory",
		    FT_UINT8, BASE_HEX, VALS(bssmap_le_response_time_definitions_vals), 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_apdu,
		  { "APDU", "gsm_bssmap_le.apdu",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_message_elements,
		  { "Message Elements", "gsm_bssmap_le.message_elements",
		    FT_BYTES, BASE_NONE, NULL, 0x0,
		    NULL, HFILL}
		},
		{ &hf_gsm_bssmap_le_location_inf,
		{ "Location Information", "gsm_bssmap_le.location_inf",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_loc_inf_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_pos_method,
		{ "Positioning Method", "gsm_bssmap_le.pos_method",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_pos_method_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_id_disc,
		{ "Identity Discriminator", "gsm_bssmap_le.id_disc",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_id_disc_vals), 0xF,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_lmu_id,
		{ "LMU ID", "gsm_bssmap_le.lmu_id",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_pos_data_disc,
		{ "Positioning Data Discriminator", "gsm_bssmap_le.pos_data_disc",
			FT_UINT8, BASE_HEX, NULL, 0x0f,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_pos_data_pos_method,
		{ "Positioning Method", "gsm_bssmap_le.pos_data.pos_method",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_pos_data_pos_method_vals), 0xf8,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_pos_data_usage,
		{ "Usage", "gsm_bssmap_le.pos_data.usage",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_pos_data_usage_vals), 0x03,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ret_err_req,
		{ "Return Error Request", "gsm_bssmap_le.ret_err_req",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_ret_err_req_vals), 0x00,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ret_err_cause,
		{ "Return Error Cause", "gsm_bssmap_le.ret_err_cause",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_ret_err_cause_vals), 0x00,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_bts_rec_acc,
		{ "BTS Reception Accuracy", "gsm_bssmap_le.bts_rec_acc",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_bts_rec_acc_vals), 0x1F,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_tar,
		{ "Timing Advance Information", "gsm_bssmap_le.tar",
			FT_BOOLEAN, 8, TFS(&tfs_needed_not_needed), 0x20,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_mpm_timer,
		{ "MPM Timer", "gsm_bssmap_le.mpm_timer",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_mpm_timer_vals), 0x1C,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_mpm,
		{ "Multilateration Positioning Method", "gsm_bssmap_le.mpm",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_mpm_vals), 0x03,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_fmi,
		{ "Final MTA Information", "gsm_bssmap_le.fmi",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_fmi_vals), 0xC0,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_mta,
		{ "Multilateration Timing Advance", "gsm_bssmap_le.mta",
			FT_UINT16, BASE_CUSTOM, CF_FUNC(format_mta), 0x00,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ms_sync_acc,
		{ "MS Sync Accuracy", "gsm_bssmap_le.ms_sync_acc",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_ms_sync_acc_vals), 0x0F,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_random_id,
		{ "Random ID", "gsm_bssmap_le.random_id",
			FT_UINT16, BASE_HEX, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_short_id,
		{ "Short ID", "gsm_bssmap_le.short_id",
			FT_UINT8, BASE_HEX, NULL, 0x00,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_coverage_class_dl,
		{ "DL Coverage Class", "gsm_bssmap_le.coverage_class.dl",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_coverage_class_dl_vals), 0x07,
			NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_coverage_class_ul,
		{ "UL Coverage Class", "gsm_bssmap_le.coverage_class.ul",
			FT_UINT8, BASE_HEX, VALS(bssmap_le_coverage_class_ul_vals), 0x38,
			NULL, HFILL }
		},
	};

	expert_module_t* expert_gsm_a_bssmap_le;

	static ei_register_info ei[] = {
		{ &ei_gsm_a_bssmap_le_not_decoded_yet, { "gsm_bssmap_le.not_decoded_yet", PI_UNDECODED, PI_WARN, "Not decoded yet", EXPFILL }},
		{ &ei_gsm_a_bssmap_le_extraneous_data, { "gsm_bssmap_le.extraneous_data", PI_PROTOCOL, PI_NOTE, "Extraneous Data, dissector bug or later version spec (report to wireshark.org)", EXPFILL }},
		{ &ei_gsm_a_bssmap_le_missing_mandatory_element, { "gsm_bssmap_le.missing_mandatory_element", PI_PROTOCOL, PI_WARN, "Missing Mandatory element, rest of dissection is suspect", EXPFILL }},
	};

	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	1
	int *ett[NUM_INDIVIDUAL_ELEMS + NUM_GSM_BSSMAP_LE_MSG +
		  NUM_GSM_BSSMAP_LE_ELEM];

	ett[0] = &ett_bssmap_le_msg;

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i < NUM_GSM_BSSMAP_LE_MSG; i++, last_offset++)
	{
		ett[last_offset] = &ett_gsm_bssmap_le_msg[i];
	}

	for (i=0; i < NUM_GSM_BSSMAP_LE_ELEM; i++, last_offset++)
	{
		ett[last_offset] = &ett_gsm_bssmap_le_elem[i];
	}

	/* Register the protocol name and description */

	proto_bssmap_le =
		proto_register_protocol("Lb-I/F BSSMAP LE", "GSM BSSMAP LE", "gsm_bssmap_le");

	proto_register_field_array(proto_bssmap_le, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_gsm_a_bssmap_le = expert_register_protocol(proto_bssmap_le);
	expert_register_field_array(expert_gsm_a_bssmap_le, ei, array_length(ei));

	bssmap_le_handle = register_dissector("gsm_bssmap_le", dissect_bssmap_le, proto_bssmap_le);
}

void
proto_reg_handoff_gsm_bssmap_le(void)
{
	dissector_add_uint("bssap_le.pdu_type",  BSSAP_PDU_TYPE_BSSMAP, bssmap_le_handle);

	gsm_bsslap_handle = find_dissector_add_dependency("gsm_bsslap", proto_bssmap_le);
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
