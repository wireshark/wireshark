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

const value_string gsm_bssmap_le_msg_strings[] = {
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
    { BSSMAP_LE_REQUESTED_GPS_ASSISTANCE_DATA, "Requested GPS Assitance Data" },
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

/* Initialize the protocol and registered fields */
static int proto_bssmap_le = -1;
int hf_gsm_bssmap_le_elem_id = -1;

/* The following hf_* variables are used to hold the Wireshark IDs of
* our header fields; they are filled out when we call
* proto_register_field_array() in proto_register_bssmap_le()
*/
static int hf_gsm_bssmap_le_msg_type = -1;
static int hf_gsm_bssmap_le_apdu_protocol_id = -1;

/* Initialize the subtree pointers */
static gint ett_bssmap_le_msg = -1;

static dissector_handle_t gsm_bsslap_handle = NULL;

static packet_info *g_pinfo;
static proto_tree *g_tree;

#define	NUM_GSM_BSSMAP_LE_ELEM (sizeof(gsm_bssmap_le_elem_strings)/sizeof(value_string))
gint ett_gsm_bssmap_le_elem[NUM_GSM_BSSMAP_LE_ELEM];

/* Dissector for the LCS Capability element */
static guint8
be_lcs_capability(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	/* Extract the LCS Capability element and add to protocol tree */
	proto_tree_add_text(tree, tvb, offset, len, "Not decoded yet");
	return len;
}

/* Dissector for the Packet Measurement Report element */
static guint8
be_packet_meas_rep(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
    /* Extract the Packet Measurement Report element and add to protocol tree */
    proto_tree_add_text(tree, tvb, offset, len, "Not decoded yet");

	return len;
}

/* Dissector for the Measured Cell Identity List element */
static guint8
be_measured_cell_identity(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len _U_, gchar *add_string _U_, int string_len _U_)
{
	/* Extract the Measured Cell Identity List element and add to protocol tree */
    proto_tree_add_text(tree, tvb, offset, len, "Not decoded yet");

	return len;
}

static guint8
de_bmaple_apdu(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_)
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
	proto_tree_add_item(tree, hf_gsm_bssmap_le_apdu_protocol_id, tvb, curr_offset+1, 1, FALSE);

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
	DE_BMAPLE_LCSQOS,			/ LCS QOS /
	DE_BMAPLE_LCS_PRIO,			/ LCS Priority /
	DE_BMAPLE_LOC_TYPE,			/ Location Type /
	DE_BMAPLE_GANSS_LOC_TYPE,	/ GANSS Location Type /	
	DE_BMAPLE_GEO_LOC,			/ Geographic Location /	
	DE_BMAPLE_POS_DATA,			/ Positioning Data /			
	DE_BMAPLE_GANSS_POS_DATA,	/ GANSS Positioning Data /
	DE_BMAPLE_VELOC_DATA,		/ Velocity Data /
	DE_BMAPLE_LCS_CAUSE,		/ LCS Cause /	
	DE_BMAPLE_LCS_CLIENT_TYPE,	/ LCS Client Type /
	DE_BMAPLE_APDU,				/ APDU /		
	DE_BMAPLE_NETWORK_ELEM_ID,	/ Network Element Identity /
	DE_BMAPLE_REQ_GPS_ASSIST_D, / Requested GPS Assistance Data /	
	DE_BMAPLE_REQ_GNSS_ASSIST_D,/ Requested GANSS Assistance Data /
	DE_BMAPLE_DECIPH_KEYS,		/ Deciphering Keys /
	DE_BMAPLE_RETURN_ERROR_REQ,	/ Return Error Request /
	DE_BMAPLE_RETURN_ERROR_CAUSE,	/ Return Error Cause /
	DE_BMAPLE_SEGMENTATION,		/ Segmentation /
	DE_BMAPLE_CLASSMARK_TYPE_3,	/ Classmark Information Type 3 /
	DE_BMAPLE_CAUSE,			/ Cause /
	DE_BMAPLE_CELL_IDENTIFIER,	/ Cell Identifier /
	DE_BMAPLE_CHOSEN_CHANNEL,	/ Chosen Channel /
	DE_BMAPLE_IMSI,				/ IMSI /
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


guint8 (*bssmap_le_elem_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len) = {
	/* NOTE: The null types below are defined elsewhere. i.e in packet-gsm_a_bssmap.c */
	NULL,	/* LCS QoS */
	NULL,	/* LCS Priority */
	NULL,	/* Location Type */
	be_ganss_loc_type,   /* GANSS Location Type */
	NULL,   /* Geographic Location */
	NULL,   /* Positioning Data */
	be_ganss_pos_dta,   /* GANSS Positioning Data */
	NULL,	/* Velocity Data */
	NULL,   /* LCS Cause */
	NULL,   /* LCS Client Type */
	de_bmaple_apdu,	/* APDU */
	NULL,	/* Network Element Identity */
	NULL,   /* Requested GPS Assitance Data */
	be_ganss_ass_dta,   /* Requested GANSS Assistance Data */
	NULL,   /* Deciphering Keys */
	NULL,   /* Return Error Request */
	NULL,	/* Return Error Cause */
	NULL,   /* Segmentation */
	NULL,	/* Classmark Information Type 3 */
	NULL,   /* Cause */
	NULL,   /* Cell Identifier */
	NULL,   /* Chosen Channel */
	de_mid,   /* IMSI */
	NULL,   /* Reserved */
	NULL,   /* Reserved */
	NULL,   /* Reserved */
	be_lcs_capability, /* LCS Capability */
	be_packet_meas_rep, /* Packet Measurement Report */
	be_measured_cell_identity, /* Measured Cell Identity List */
	de_mid,    /* IMEI (use same dissector as IMSI) */

	NULL,	/* NONE */
	
};

/*
 * 9.1 PERFORM LOCATION REQUEST
 */
static void
bssmap_le_perf_loc_request(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Location Type 9.1.1 M 3-n */
	ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_LOC_TYPE].value, GSM_A_PDU_TYPE_BSSMAP, BE_LOC_TYPE , "");
	/* Cell Identifier 9.1.2 O 5-10 */
	ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, GSM_A_PDU_TYPE_BSSMAP, BE_CELL_ID, "");
	/* Classmark Information Type 3 9.1.3 O 3-14 */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_CM_INFO_3].value, GSM_A_PDU_TYPE_BSSMAP, BE_CM_INFO_3, "");
	/* LCS Client Type 9.1.4 C (note 3) 3-n */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_LCS_CLIENT].value, GSM_A_PDU_TYPE_BSSMAP, BE_LCS_CLIENT, "");
	/* Chosen Channel 9.1.5 O 2 */
	ELEM_OPT_TV(gsm_bssmap_elem_strings[BE_CHOSEN_CHAN].value, GSM_A_PDU_TYPE_BSSMAP, BE_CHOSEN_CHAN, "");
	/* LCS Priority 9.1.6 O 3-n */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_LCS_PRIO].value, GSM_A_PDU_TYPE_BSSMAP, BE_LCS_PRIO, "");
	/* LCS QoS 9.1.6a C (note 1) 3-n */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_LCS_QOS].value, GSM_A_PDU_TYPE_BSSMAP, BE_LCS_QOS, "");
	/* GPS Assistance Data 9.1.7 C (note 2) 3-n */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_GPS_ASSIST_DATA].value, GSM_A_PDU_TYPE_BSSMAP, BE_GPS_ASSIST_DATA, "");
	/* APDU 9.1.8 O 3-n */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_APDU].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_APDU, "");
	/* LCS Capability 9.1.9 O */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_LCS_CAPABILITY].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_LCS_CAPABILITY, "");
	/* Packet Measurement Report 9.1.10 O*/
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_PACKET_MEAS_REP].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_PACKET_MEAS_REP, "");
	/* Measured Cell Identity List 9.1.11 O*/
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_MEAS_CELL_ID].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_MEAS_CELL_ID, "");
	/* IMSI	9.1.12	O (note 4)	5-10 */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_IMSI].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_IMSI, "");
	/* IMEI	9.1.13	O (note 4)	10 (use same decode as IMSI) */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_IMEI].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_IMEI, "");
	/* GANSS Location Type	9.1.14	C	3 */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_GANSS_LOC_TYPE].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_GANSS_LOC_TYPE, "");
	/* GANSS Assistance Data	9.1.15	C (note 5)	3-n */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_REQ_GNSS_ASSIST_D].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_REQ_GNSS_ASSIST_D, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);

}

/*
 * 9.2 PERFORM LOCATION RESPONSE
 */
static void
bssmap_le_perf_loc_resp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Location Estimate 9.2.1 C (note 1) 3-n */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_LOC_EST].value, BSSAP_PDU_TYPE_BSSMAP, BE_LOC_EST, "");
	/* Positioning Data 9.2.2 O 3-n */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_POS_DATA].value, BSSAP_PDU_TYPE_BSSMAP, BE_POS_DATA, "");
	/* Deciphering Keys 9.2.3 C (note 2) 3-n */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_DECIPH_KEYS].value, BSSAP_PDU_TYPE_BSSMAP, BE_DECIPH_KEYS, "");
	/* LCS Cause 9.2.4 C (note 3) 3-n */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_LCS_CAUSE].value, BSSAP_PDU_TYPE_BSSMAP, BE_LCS_CAUSE, "");
	/* Velocity Estimate	9.2.5	O	3-n */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_VEL_EST].value, BSSAP_PDU_TYPE_BSSMAP, BE_VEL_EST, "");
	/* GANSS Positioning Data	9.2.6	O	3-n */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_GANSS_POS_DATA].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_GANSS_POS_DATA, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

/*
 * 9.8 CONNECTION ORIENTED INFORMATION
 */
static void
bssmap_le_connection_oriented(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* APDU 9.8.1 M 3-n */
	ELEM_MAND_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_APDU].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_APDU, "");
	/* Segmentation 9.8.2 */
	ELEM_OPT_TLV(gsm_bssmap_elem_strings[BE_SEG].value, BSSAP_PDU_TYPE_BSSMAP, BE_SEG, "");

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
bssmap_le_perf_loc_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len)
{
	guint32	curr_offset;
	guint32	consumed;
	guint	curr_len;

	curr_offset = offset;
	curr_len = len;

	/* Cell Identifier 9.12.1 M */
	ELEM_MAND_TLV(gsm_bssmap_elem_strings[BE_CELL_ID].value, GSM_A_PDU_TYPE_BSSMAP, BE_CELL_ID, "");
	/* APDU 9.1.8 O 3-n */
	ELEM_OPT_TLV(gsm_bssmap_le_elem_strings[DE_BMAPLE_APDU].value, GSM_PDU_TYPE_BSSMAP_LE, DE_BMAPLE_APDU, "");

	EXTRANEOUS_DATA_CHECK(curr_len, 0);
}

static void (*bssmap_le_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len) = {
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

/* Register the protocol with Wireshark */
void
proto_register_gsm_bssmap_le(void)
{
	guint		i;
	guint		last_offset;

	/* Setup list of header fields */
	static hf_register_info hf[] =
	{
	{ &hf_gsm_bssmap_le_msg_type,
		{ "BSSMAP LE Message Type",	"bssmap_le.msgtype",
		FT_UINT8, BASE_HEX, VALS(gsm_bssmap_le_msg_strings), 0x0,
		"", HFILL }
	},
	{ &hf_gsm_bssmap_le_elem_id,
		{ "Element ID",	"bssmap_le.elem_id",
		FT_UINT8, BASE_DEC, NULL, 0,
		"", HFILL }
	},
	{ &hf_gsm_bssmap_le_apdu_protocol_id,
		{ "Protocol ID", "bssmap_le.apdu_protocol_id",
		FT_UINT8, BASE_DEC, VALS(gsm_apdu_protocol_id_strings), 0x0,
		"APDU embedded protocol id", HFILL }
	},
	};
	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_ELEMS	1
	static gint *ett[NUM_INDIVIDUAL_ELEMS + NUM_GSM_BSSMAP_LE_MSG +
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
	sccp_msg_info_t* sccp_msg;

	sccp_msg = pinfo->sccp_info;

	if (!(sccp_msg && sccp_msg->data.co.assoc)) {
		sccp_msg = NULL;
	}

	if (check_col(pinfo->cinfo, COL_INFO))
	{
		col_append_str(pinfo->cinfo, COL_INFO, "(BSSMAP LE) ");
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
	saved_offset = offset;

	g_pinfo = pinfo;
	g_tree = tree;

	len = tvb_length(tvb);

	/*
	 * add BSSMAP message name
	 */
	oct = tvb_get_guint8(tvb, offset++);

	str = match_strval_idx((guint32) oct, gsm_bssmap_le_msg_strings, &idx);

	if (sccp_msg && !sccp_msg->data.co.label) {
		sccp_msg->data.co.label = se_strdup(val_to_str((guint32) oct, gsm_bssmap_le_msg_strings, "BSSMAP LE(0x%02x)"));
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

		if (check_col(pinfo->cinfo, COL_INFO))
		{
			col_append_fstr(pinfo->cinfo, COL_INFO, "%s ", str);
		}

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

	if ((len - offset) <= 0) return;

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
		(*bssmap_le_msg_fcn[idx])(tvb, bssmap_le_tree, offset, len - offset);
	}
}

void
proto_reg_handoff_gsm_bssmap_le(void)
{
	dissector_handle_t bssmap_le_handle;

	bssmap_le_handle = find_dissector("gsm_bssmap_le");

	dissector_add("bssap.pdu_type",  BSSAP_PDU_TYPE_BSSMAP, bssmap_le_handle);

	gsm_bsslap_handle = find_dissector("gsm_bsslap");
}
