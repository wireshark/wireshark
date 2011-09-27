/* packet-gsm_bssmap_le.c
 * Routines for GSM Lb Interface BSSMAP dissection
 *
 * Copyright 2008, Johnny Mitrevski <mitrevj@hotmail.com>
 *
 * 3GPP TS 49.031 version v7.4.0 (2009-09)
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

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/tap.h>
#include <epan/emem.h>

#include "packet-bssap.h"
#include "packet-sccp.h"
#include "packet-gsm_a_common.h"
#include "packet-e212.h"

/* PROTOTYPES/FORWARDS */

/* Message Type definitions */
#define BSSMAP_LE_PERFORM_LOCATION_REQUEST              43
#define BSSMAP_LE_PERFORM_LOCATION_RESPONSE             45
#define BSSMAP_LE_PERFORM_LOCATION_ABORT                46
#define BSSMAP_LE_PERFORM_LOCATION_INFORMATION          47
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
	{ BSSMAP_LE_PERFORM_LOCATION_REQUEST, "Perform Location Request" },
	{ BSSMAP_LE_PERFORM_LOCATION_RESPONSE, "Perform Location Response" },
	{ BSSMAP_LE_PERFORM_LOCATION_ABORT, "Perform Location Abort" },
	{ BSSMAP_LE_PERFORM_LOCATION_INFORMATION, "Perform Location Information" },
	{ BSSMAP_LE_CONNECTION_ORIENTED_INFORMATION, "Connection Oriented Information" },
	{ BSSMAP_LE_CONNECTIONLESS_INFORMATION, "Connectionless Information" },
	{ BSSMAP_LE_RESET, "Reset" },
	{ BSSMAP_LE_RESET_ACKNOWLEDGE, "Reset Acknowledge" },
	{ 0, NULL }    /*Null terminated list. Make sure we add this to our value/string structures. */
};

/* Information Element definitions */
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

const value_string gsm_bssmap_le_elem_strings[] = {
	{ BSSMAP_LE_LCS_QOS, "LCS QoS" },
	{ BSSMAP_LE_LCS_PRIORITY, "LCS Priority" },
	{ BSSMAP_LE_LOCATION_TYPE, "Location Type" },
	{ BSSMAP_LE_GANSS_LOCATION_TYPE, "GANSS Location Type" },
	{ BSSMAP_LE_GEOGRAPHIC_LOCATION, "Geographic Location" },
	{ BSSMAP_LE_POSITIONING_DATA, "Positioning Data" },
	{ BSSMAP_LE_GANSS_POSITIONING_DATA, "GANSS Positioning Data" },
	{ BSSMAP_LE_VELOCITY_DATA, "Velocity Data" },
	{ BSSMAP_LE_LCS_CAUSE, "LCS Cause" },
	{ BSSMAP_LE_LCS_CLIENT_TYPE, "LCS Client Type" },
	{ BSSMAP_LE_APDU, "APDU" },
	{ BSSMAP_LE_NETWORK_ELEMENT_IDENTITY, "Network Element Identity" },
	{ BSSMAP_LE_REQUESTED_GPS_ASSISTANCE_DATA, "Requested GPS Assistance Data" },
	{ BSSMAP_LE_REQUESTED_GANSS_ASSISTANCE_DATA, "Requested GANSS Assistance Data" },
	{ BSSMAP_LE_DECIPHERING_KEYS, "Deciphering Keys" },
	{ BSSMAP_LE_RETURN_ERROR_REQUEST, "Return Error Request" },
	{ BSSMAP_LE_RETURN_ERROR_CAUSE, "Return Error Cause" },
	{ BSSMAP_LE_SEGMENTATION, "Segmentation" },
	{ BSSMAP_LE_CLASSMARK_INFORMATION_TYPE_3, "Classmark Information Type 3" },
	{ BSSMAP_LE_CAUSE, "Cause" },
	{ BSSMAP_LE_CELL_IDENTIFIER, "Cell Identifier" },
	{ BSSMAP_LE_CHOSEN_CHANNEL, "Chosen Channel" },
	{ BSSMAP_LE_IMSI, "IMSI" },
	{ BSSMAP_LE_RESERVED_NOTE1, "Reserved" },
	{ BSSMAP_LE_RESERVED_NOTE2, "Reserved" },
	{ BSSMAP_LE_RESERVED_NOTE3, "Reserved" },
	{ BSSMAP_LE_LCS_CAPABILITY, "LCS Capability" },
	{ BSSMAP_LE_PACKET_MEASUREMENT_REPORT, "Packet Measurement Report" },
	{ BSSMAP_LE_CELL_IDENTITY_LIST, "Cell Identity List" },
	{ BSSMAP_LE_IMEI, "IMEI" },
	{ 0, NULL }
};

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

/* Initialize the protocol and registered fields */
static int proto_bssmap_le = -1;
int hf_gsm_bssmap_le_elem_id = -1;

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_bssmap_le()
*/
static int hf_gsm_bssmap_le_msg_type = -1;
static int hf_gsm_bssmap_le_apdu_protocol_id = -1;
static int hf_gsm_bssmap_le_spare = -1;
static int hf_gsm_bssmap_le_ciphering_key_flag = -1;
static int hf_gsm_bssmap_le_current_deciphering_key_value = -1;
static int hf_gsm_bssmap_le_next_deciphering_key_value = -1;
static int hf_gsm_bssmap_le_acq_ass = -1;
static int hf_gsm_bssmap_le_ref_time = -1;
static int hf_gsm_bssmap_le_ref_loc = -1;
static int hf_gsm_bssmap_le_dgps_corr = -1;
static int hf_gsm_bssmap_le_nav_mod = -1;
static int hf_gsm_bssmap_le_iono_mod = -1;
static int hf_gsm_bssmap_le_utc_mod = -1;
static int hf_gsm_bssmap_le_almanac = -1;
static int hf_gsm_bssmap_le_ephemeris_ext_chk = -1;
static int hf_gsm_bssmap_le_ephemeris_ext = -1;
static int hf_gsm_bssmap_le_real_time_int = -1;
static int hf_gsm_bssmap_le_lcs_cause_value =-1;
static int hf_gsm_bssmap_le_diagnostic_value = -1;
static int hf_gsm_bssmap_le_client_category = -1;
static int hf_gsm_bssmap_le_client_subtype = -1;
static int hf_gsm_bssmap_le_velocity_requested = -1;
static int hf_gsm_bssmap_le_vertical_coordinate_indicator = -1;
static int hf_gsm_bssmap_le_horizontal_accuracy_indicator = -1;
static int hf_gsm_bssmap_le_horizontal_accuracy = -1;
static int hf_gsm_bssmap_le_vertical_accuracy_indicator = -1;
static int hf_gsm_bssmap_le_vertical_accuracy = -1;
static int hf_gsm_bssmap_le_response_time_category = -1;

/* Initialize the subtree pointers */
static gint ett_bssmap_le_msg = -1;

static dissector_handle_t gsm_bsslap_handle = NULL;

static packet_info *g_pinfo;
static proto_tree *g_tree;

#define	NUM_GSM_BSSMAP_LE_ELEM (sizeof(gsm_bssmap_le_elem_strings)/sizeof(value_string))
gint ett_gsm_bssmap_le_elem[NUM_GSM_BSSMAP_LE_ELEM];

/*
 * 10.3 APDU
 */

static guint16
de_bmaple_apdu(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8	apdu_protocol_id;
	tvbuff_t *APDU_tvb;

	curr_offset = offset;

	/* curr_offset + 1 is a hack, the length part here is 2 octets and we are off by one */
	proto_tree_add_text(tree, tvb, curr_offset+1, len, "APDU");

	/*
	 * dissect the embedded APDU message
	 * if someone writes a TS 09.31 dissector
	 *
	 * The APDU octets 4 to n are coded in the same way as the
	 * equivalent octet in the APDU element of 3GPP TS 49.031 BSSAP-LE.
	 */

	apdu_protocol_id = tvb_get_guint8(tvb,curr_offset+1);
	proto_tree_add_item(tree, hf_gsm_bssmap_le_apdu_protocol_id, tvb, curr_offset+1, 1, ENC_BIG_ENDIAN);

	switch(apdu_protocol_id){
	case 1:
		/* BSSLAP
		 * the embedded message is as defined in 3GPP TS 08.71(3GPP TS 48.071 version 7.2.0 Release 7)
		 */
		APDU_tvb = tvb_new_subset(tvb, curr_offset+2, len-1, len-1);
		if(gsm_bsslap_handle)
			call_dissector(gsm_bsslap_handle, APDU_tvb, g_pinfo, g_tree);
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

	EXTRANEOUS_DATA_CHECK(len, curr_offset - offset);

	return(curr_offset - offset);
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
static guint16
de_bmaple_decihp_keys(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	gint bit_offset;

	/* Spare bits */
	bit_offset = (offset<<3);
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_spare, tvb, bit_offset, 7, ENC_BIG_ENDIAN);
	bit_offset += 7;

	/* Extract the Ciphering Key Flag and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_ciphering_key_flag, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
	bit_offset++;
	offset++;

	/* Extract the Current Deciphering Key Value and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_current_deciphering_key_value, tvb, bit_offset, 56, ENC_NA);
	bit_offset += 56;
	offset += 7;

	/* Extract the Next Deciphering Key Value and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_next_deciphering_key_value, tvb, bit_offset, 56, ENC_NA);
	offset += 7;

	return(len);
}
/*
 * 10.9 Geographic Location
 * contains an octet sequence identical to that for Geographical Information
 * defined in 3GPP TS 23.032..
 */
/*
 * 10.10 Requested GPS Assistance Data
 */
static guint16
de_bmaple_req_gps_ass_data(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

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
	proto_tree_add_text(tree, tvb, curr_offset, len-2, "Satellite related data Not decoded yet");
	return(len);
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
	{ 8, "positionMethodNotAvailableInLocaitonArea" },
	{ 0, NULL}
};
static guint16
de_bmaple_cause(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;

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

	return(curr_offset - offset);
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

static guint16
de_bmaple_client(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	guint32	curr_offset;
	guint8 bitCount;

	bitCount = offset<<3;
	curr_offset = offset;

	/* Extract the client category and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_client_category, tvb, bitCount, 4, ENC_BIG_ENDIAN);
	bitCount = bitCount + 4;

	/* Extract the client subtype and add to protocol tree */
	proto_tree_add_bits_item(tree, hf_gsm_bssmap_le_client_subtype, tvb, bitCount, 4, ENC_BIG_ENDIAN);
	bitCount = bitCount + 4;
	curr_offset++;

	return(curr_offset - offset);
}
/*
 * 10.15 LCS Priority
 * coded as the LCS-Priority octet in 3GPP TS 29.002
 */
/*
 * 10.16 LCS QoS
 */
static guint16
de_bmaple_lcs_qos(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	guint64 verticalCoordIndicator, velocityRequested, horizontalAccuracyIndicator, verticalAccuracyIndicator;
	guint16 bitCount;

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
	bitCount = bitCount + 2;

	return(len);
}
/*
 * 10.17 (void)
 */
/*
 * 10.18 Location Type
 */
/*
 * 10.19 Network Element Identity
 */
/*
 * 10.20 Positioning Data
 */
static guint16
de_bmaple_pos_dta(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	tvbuff_t *data_tvb;
	guint32	curr_offset;

	curr_offset = offset;

	data_tvb = tvb_new_subset(tvb, curr_offset, len, len);
	dissect_geographical_description(data_tvb, g_pinfo, tree);

	return(len);
}
/*
 * 10.21 Return Error Request
 */
/*
 * 10.22 Return Error Cause
 */
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
static guint16
be_lcs_capability(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	/* Extract the LCS Capability element and add to protocol tree */
	proto_tree_add_text(tree, tvb, offset, len, "Not decoded yet");
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
static guint16
be_packet_meas_rep(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	/* Extract the Packet Measurement Report element and add to protocol tree */
	proto_tree_add_text(tree, tvb, offset, len, "Not decoded yet");

	return len;
}

/*
 * 10.28 Cell Identity List
 * coded as the value part of the Cell Identity List IE
 * defined in 3GPP TS 48.071.
 */
/* Dissector for the Measured Cell Identity List element */
static guint16
be_measured_cell_identity(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
{
	/* Extract the Measured Cell Identity List element and add to protocol tree */
	proto_tree_add_text(tree, tvb, offset, len, "Not decoded yet");

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


#define	NUM_GSM_BSSMAP_LE_MSG (sizeof(gsm_bssmap_le_msg_strings)/sizeof(value_string))
static gint ett_gsm_bssmap_le_msg[NUM_GSM_BSSMAP_LE_MSG];

/*
This enum is defined in packet-gsm_a_common.h to
make it possible to use element dissecton from this dissector
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
	BMAPLE_NONE					/ NONE /
}
bssmap_le_elem_idx_t;
*/


guint16 (*bssmap_le_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len, gchar *add_string, int string_len) = {
	/* NOTE: The null types below are defined elsewhere. i.e in packet-gsm_a_bssmap.c */
	de_bmaple_lcs_qos,				/* 10.16 LCS QoS */
	NULL,							/* LCS Priority */
	NULL,							/* 10.18 Location Type */
	be_ganss_loc_type,				/* GANSS Location Type */
	NULL,							/* 10.9 Geographic Location */
	de_bmaple_pos_dta,				/* 10.20 Positioning Data */
	be_ganss_pos_dta,				/* GANSS Positioning Data */
	NULL,							/* Velocity Data */
	de_bmaple_cause,				/* 10.13 LCS Cause */
	de_bmaple_client,				/* LCS Client Type */
	de_bmaple_apdu,					/* APDU */
	NULL,							/* Network Element Identity */
	de_bmaple_req_gps_ass_data,		/* 10.10 Requested GPS Assistance Data */
	be_ganss_ass_dta,				/* Requested GANSS Assistance Data */
	de_bmaple_decihp_keys,			/* 10.8 Deciphering Keys */
	NULL,							/* Return Error Request */
	NULL,							/* Return Error Cause */
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

	NULL,	/* NONE */

};

/*
 * 9.1 PERFORM LOCATION REQUEST
 */
static void
bssmap_le_perf_loc_request(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Location Type 9.1.1 M 3-n */
	ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_LOC_TYPE].value, GSM_A_PDU_TYPE_BSSMAP, BE_LOC_TYPE, NULL)
	/* Cell Identifier 9.1.2 O 5-10 */
	ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, GSM_A_PDU_TYPE_BSSMAP, BE_CELL_ID, NULL);
	/* Classmark Information Type 3 9.1.3 O 3-14 */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CM_INFO_3].value, GSM_A_PDU_TYPE_BSSMAP, BE_CM_INFO_3, NULL);
	/* LCS Client Type 9.1.4 C (note 3) 3-n */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_LCS_CLIENT_TYPE].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CLIENT_TYPE, NULL);
	/* Chosen Channel 9.1.5 O 2 */
	ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CHOSEN_CHAN].value, GSM_A_PDU_TYPE_BSSMAP, BE_CHOSEN_CHAN, NULL);
	/* LCS Priority 9.1.6 O 3-n */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_LCS_PRIO].value, GSM_A_PDU_TYPE_BSSMAP, BE_LCS_PRIO, NULL);
	/* LCS QoS 9.1.6a C (note 1) 3-n */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_LCSQOS].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCSQOS, NULL);
	/* GPS Assistance Data 9.1.7 C (note 2) 3-n */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_GPS_ASSIST_DATA].value, GSM_A_PDU_TYPE_BSSMAP, BE_GPS_ASSIST_DATA, NULL);
	/* APDU 9.1.8 O 3-n */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_APDU].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_APDU, NULL);
	/* LCS Capability 9.1.9 O */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_LCS_CAPABILITY].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CAPABILITY, NULL);
	/* Packet Measurement Report 9.1.10 O*/
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_PACKET_MEAS_REP].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_PACKET_MEAS_REP, NULL);
	/* Measured Cell Identity List 9.1.11 O*/
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_MEAS_CELL_ID].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_MEAS_CELL_ID, NULL);
	/* IMSI	9.1.12	O (note 4)	5-10 */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_IMSI].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_IMSI, NULL);
	/* IMEI	9.1.13	O (note 4)	10 (use same decode as IMSI) */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_IMEI].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_IMEI, NULL);
	/* GANSS Location Type	9.1.14	C	3 */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_GANSS_LOC_TYPE].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_GANSS_LOC_TYPE, NULL);
	/* GANSS Assistance Data	9.1.15	C (note 5)	3-n */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_REQ_GNSS_ASSIST_D].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_REQ_GNSS_ASSIST_D, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.2 PERFORM LOCATION RESPONSE
 */
static void
bssmap_le_perf_loc_resp(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Location Estimate 9.2.1 C (note 1) 3-n */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_LOC_EST].value, BSSAP_PDU_TYPE_BSSMAP, BE_LOC_EST, NULL);
	/* Positioning Data 9.2.2 O 3-n */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_POS_DATA].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_POS_DATA, NULL);
	/* Deciphering Keys 9.2.3 C (note 2) 3-n */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_DECIPH_KEYS].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_DECIPH_KEYS, NULL);
	/* LCS Cause 9.2.4 C (note 3) 3-n */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_LCS_CAUSE].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CAUSE, NULL);
	/* Velocity Estimate	9.2.5	O	3-n */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_VEL_EST].value, BSSAP_PDU_TYPE_BSSMAP, BE_VEL_EST, NULL);
	/* GANSS Positioning Data	9.2.6	O	3-n */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_GANSS_POS_DATA].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_GANSS_POS_DATA, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 9.8 CONNECTION ORIENTED INFORMATION
 */
static void
bssmap_le_connection_oriented(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* APDU 9.8.1 M 3-n */
	ELEM_MAND_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_APDU].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_APDU, NULL);
	/* Segmentation 9.8.2 */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_SEG].value, BSSAP_PDU_TYPE_BSSMAP, BE_SEG, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
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

/*
 * 9.11 RESET ACKNOWLEDGE
 * no data
 */

/*
 * 9.12 PERFORM LOCATION INFORMATION
 */
static void
bssmap_le_perf_loc_info(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Cell Identifier 9.12.1 M */
	ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, GSM_A_PDU_TYPE_BSSMAP, BE_CELL_ID, NULL);
	/* APDU 9.1.8 O 3-n */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_APDU].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_APDU, NULL);

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void (*bssmap_le_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo _U_, guint32 offset, guint len) = {
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	bssmap_le_perf_loc_request,	/* Perform Location Request */
	bssmap_le_perf_loc_resp,	/* Perform Location Response */
	bssmap_perf_loc_abort,		/* Abort */
	bssmap_le_perf_loc_info,	/* Perform Location Information */
	bssmap_le_connection_oriented,	/* Connection Oriented Information */
	NULL,						/* Connectionless Information */
	bssmap_reset,				/* Reset */
	NULL,		/* Reset Acknowledge */

	NULL,	/* NONE */
};

void
dissect_bssmap_le(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	static gsm_a_tap_rec_t	tap_rec[4];
	static gsm_a_tap_rec_t	*tap_p;
	static guint			tap_current=0;
	guint8	oct;
	guint32	offset, saved_offset;
	guint32	len;
	gint	idx;
	proto_item	*bssmap_le_item = NULL;
	proto_tree	*bssmap_le_tree = NULL;
	const gchar	*str;
	sccp_msg_info_t* sccp_msg_p;

	sccp_msg_p = pinfo->sccp_info;

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

	g_pinfo = pinfo;
	g_tree = tree;

	len = tvb_length(tvb);

	/*
	 * add BSSMAP message name
	 */
	oct = tvb_get_guint8(tvb, offset++);

	str = match_strval_idx((guint32) oct, gsm_bssmap_le_msg_strings, &idx);

	if (sccp_msg_p && !sccp_msg_p->data.co.label) {
		sccp_msg_p->data.co.label = se_strdup(val_to_str((guint32) oct, gsm_bssmap_le_msg_strings, "BSSMAP LE(0x%02x)"));
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

	if (str == NULL) return;

	if (offset >= len) return;

	/*
	 * decode elements
	 */
	if (bssmap_le_msg_fcn[idx] == NULL)
	{
		proto_tree_add_text(bssmap_le_tree,
			tvb, offset, len - offset,
			"Message Elements");
	}
	else
	{
		(*bssmap_le_msg_fcn[idx])(tvb, bssmap_le_tree, pinfo, offset, len - offset);
	}
}

/* Register the protocol with Wireshark */
void
proto_register_gsm_bssmap_le(void)
{
	guint		i;
	guint		last_offset;

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_gsm_bssmap_le_msg_type,
		  { "BSSMAP LE Message Type",	"bssmap_le.msgtype",
		    FT_UINT8, BASE_HEX, VALS(gsm_bssmap_le_msg_strings), 0x0,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_elem_id,
		  { "Element ID",	"bssmap_le.elem_id",
		    FT_UINT8, BASE_DEC, NULL, 0,
		    NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_apdu_protocol_id,
		  { "Protocol ID", "bssmap_le.apdu_protocol_id",
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
          { "Acquisition Assistance", "bssap.acq_ass",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x80,
            NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ref_time,
          { "Reference Time", "bssap.ref_time",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x40,
            NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ref_loc,
          { "Reference Location", "bssap.ref_loc",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x20,
            NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_dgps_corr,
          { "DGPS Corrections", "bssap.gps_corr",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x08,
            NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_nav_mod,
          { "Navigation Model", "bssap.nav_mod",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x10,
            NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_iono_mod,
          { "Ionospheric Model", "bssap.iono_mod",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x04,
            NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_utc_mod,
          { "UTC Model", "bssap.utc_mod",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x02,
            NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_almanac,
          { "Almanac", "bssap.almanac",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x01,
            NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ephemeris_ext_chk,
          { "Ephemeris Extension Check", "bssap.ephemeris_ext_chk",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x04,
            NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_ephemeris_ext,
          { "Ephemeris Extension", "bssap.ephemeris_ext",
            FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x02,
            NULL, HFILL }
		},
		{ &hf_gsm_bssmap_le_real_time_int,
          { "Real-Time Integrity", "bssap.real_time_int",
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

	};
	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	1
	gint *ett[NUM_INDIVIDUAL_ELEMS + NUM_GSM_BSSMAP_LE_MSG +
		  NUM_GSM_BSSMAP_LE_ELEM];

	ett[0] = &ett_bssmap_le_msg;

	last_offset = NUM_INDIVIDUAL_ELEMS;

	for (i=0; i < NUM_GSM_BSSMAP_LE_MSG; i++, last_offset++)
	{
		ett_gsm_bssmap_le_msg[i] = -1;
		ett[last_offset] = &ett_gsm_bssmap_le_msg[i];
	}

	for (i=0; i < NUM_GSM_BSSMAP_LE_ELEM; i++, last_offset++)
	{
		ett_gsm_bssmap_le_elem[i] = -1;
		ett[last_offset] = &ett_gsm_bssmap_le_elem[i];
	}

	/* Register the protocol name and description */

	proto_bssmap_le =
		proto_register_protocol("Lb-I/F BSSMAP LE", "GSM BSSMAP LE", "gsm_bssmap_le");

	proto_register_field_array(proto_bssmap_le, hf, array_length(hf));

	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("gsm_bssmap_le", dissect_bssmap_le, proto_bssmap_le);
}

void
proto_reg_handoff_gsm_bssmap_le(void)
{
	dissector_handle_t bssmap_le_handle;

	bssmap_le_handle = find_dissector("gsm_bssmap_le");

	dissector_add_uint("bssap.pdu_type",  BSSAP_PDU_TYPE_BSSMAP, bssmap_le_handle);

	gsm_bsslap_handle = find_dissector("gsm_bsslap");
}
