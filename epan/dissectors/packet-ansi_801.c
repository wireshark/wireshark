/* packet-ansi_801.c
 * Routines for ANSI IS-801 (Location Services (PLD)) dissection
 *
 *   Location Services (Position Determination Service)
 *			3GPP2 C.S0022-0 v1.0	IS-801
 *
 *   Location Services (Position Determination Service)
 *			3GPP2 C.S0022-0-1 v1.0	IS-801 Addendum
 *
 * Copyright 2004, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 * Copyright 2007, Michael Lum <michael.lum [AT] utstar.com>
 * In association with UTStarcom Inc.
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

#include <stdlib.h>

#include <glib.h>
#include <math.h>

#include <epan/packet.h>
#include <epan/wmem/wmem.h>
#include <epan/to_str.h>

void proto_register_ansi_801(void);
void proto_reg_handoff_ansi_801(void);

static const char *ansi_proto_name = "ANSI IS-801 (Location Services (PLD))";
static const char *ansi_proto_name_short = "IS-801";

#define	ANSI_801_FORWARD	0
#define	ANSI_801_REVERSE	1


/* Initialize the subtree pointers */
static gint ett_ansi_801 = -1;
static gint ett_gps = -1;
static gint ett_loc = -1;

/* Initialize the protocol and registered fields */
static int proto_ansi_801 = -1;
static int hf_ansi_801_for_req_type = -1;
static int hf_ansi_801_for_rsp_type = -1;
static int hf_ansi_801_rev_req_type = -1;
static int hf_ansi_801_rev_rsp_type = -1;
static int hf_ansi_801_for_sess_tag = -1;
static int hf_ansi_801_rev_sess_tag = -1;
static int hf_ansi_801_sess_tag = -1;

static int hf_ansi_801_time_ref_cdma = -1;
static int hf_ansi_801_lat = -1;
static int hf_ansi_801_long = -1;
static int hf_ansi_801_loc_uncrtnty_ang = -1;
static int hf_ansi_801_loc_uncrtnty_a = -1;
static int hf_ansi_801_loc_uncrtnty_p = -1;
static int hf_ansi_801_fix_type = -1;
static int hf_ansi_801_velocity_incl = -1;
static int hf_ansi_801_velocity_hor = -1;
static int hf_ansi_801_heading = -1;
static int hf_ansi_801_velocity_ver = -1;
static int hf_ansi_801_clock_incl = -1;
static int hf_ansi_801_clock_bias = -1;
static int hf_ansi_801_clock_drift = -1;
static int hf_ansi_801_height_incl = -1;
static int hf_ansi_801_height = -1;
static int hf_ansi_801_loc_uncrtnty_v = -1;
static int hf_ansi_801_reserved_bits = -1;

static int hf_ansi_801_bad_sv_present = -1;
static int hf_ansi_801_num_bad_sv = -1;
static int hf_ansi_801_bad_sv_prn_num = -1;
static int hf_ansi_801_dopp_req = -1;
static int hf_ansi_801_add_dopp_req = -1;
static int hf_ansi_801_code_ph_par_req = -1;
static int hf_ansi_801_az_el_req = -1;

static int hf_ansi_801_pref_resp_qual = -1;
static int hf_ansi_801_num_fixes = -1;
static int hf_ansi_801_t_betw_fixes = -1;
static int hf_ansi_801_offset_req = -1;

/* Generated from convert_proto_tree_add_text.pl */
static int hf_ansi_801_for_message_number_responsesF0 = -1;
static int hf_ansi_801_apdc_id = -1;
static int hf_ansi_801_num_sv_p32 = -1;
static int hf_ansi_801_regulatory_services_indicator = -1;
static int hf_ansi_801_session_source = -1;
static int hf_ansi_801_reserved8_E0 = -1;
static int hf_ansi_801_action_time = -1;
static int hf_ansi_801_rev_message_number_responsesF0 = -1;
static int hf_ansi_801_reserved24_3 = -1;
static int hf_ansi_801_cancellation_type = -1;
static int hf_ansi_801_gps_navigation_message_bits = -1;
static int hf_ansi_801_num_dr_p = -1;
static int hf_ansi_801_rev_message_number_requests8 = -1;
static int hf_ansi_801_reserved8_F0 = -1;
static int hf_ansi_801_for_req_loc_clock_correction_for_gps_time = -1;
static int hf_ansi_801_for_response_length = -1;
static int hf_ansi_801_session_end = -1;
static int hf_ansi_801_reserved8_1F = -1;
static int hf_ansi_801_part_num = -1;
static int hf_ansi_801_dr_size = -1;
static int hf_ansi_801_reserved_24_700 = -1;
static int hf_ansi_801_for_message_number_responses0F = -1;
static int hf_ansi_801_rev_message_number_requests16 = -1;
static int hf_ansi_801_lcc_capable_using_location_assistance_spherical = -1;
static int hf_ansi_801_part_num32 = -1;
static int hf_ansi_801_part_num16 = -1;
static int hf_ansi_801_reserved8_07 = -1;
static int hf_ansi_801_reserved24_1 = -1;
static int hf_ansi_801_reserved_24_F80000 = -1;
static int hf_ansi_801_extended_base_station_almanac = -1;
static int hf_ansi_801_no_outstanding_request_element = -1;
static int hf_ansi_801_for_request_length = -1;
static int hf_ansi_801_week_num = -1;
static int hf_ansi_801_total_parts16 = -1;
static int hf_ansi_801_pd_message_type = -1;
static int hf_ansi_801_total_parts32 = -1;
static int hf_ansi_801_alpha_and_beta_parameters = -1;
static int hf_ansi_801_lcc_using_gps_ephemeris_assistance = -1;
static int hf_ansi_801_rev_request_length = -1;
static int hf_ansi_801_reserved8_7F = -1;
static int hf_ansi_801_unsolicited_response_indicator = -1;
static int hf_ansi_801_autonomous_location_calculation_capable = -1;
static int hf_ansi_801_gps_almanac_correction = -1;
static int hf_ansi_801_total_parts = -1;
static int hf_ansi_801_session_start = -1;
static int hf_ansi_801_ref_bit_num = -1;
static int hf_ansi_801_aflt_lcc = -1;
static int hf_ansi_801_reject_reason = -1;
static int hf_ansi_801_gps_ephemeris = -1;
static int hf_ansi_801_pre_programmed_location = -1;
static int hf_ansi_801_rev_response_length = -1;
static int hf_ansi_801_afltc_id = -1;
static int hf_ansi_801_rev_req_loc_height_information = -1;
static int hf_ansi_801_reserved8_01 = -1;
static int hf_ansi_801_pilot_ph_cap = -1;
static int hf_ansi_801_gps_acquisition_assistance = -1;
static int hf_ansi_801_coordinate_type_requested = -1;
static int hf_ansi_801_gps_almanac = -1;
static int hf_ansi_801_rev_req_loc_velocity_information = -1;
static int hf_ansi_801_gps_autonomous_acquisition_capable = -1;
static int hf_ansi_801_num_sv_p16 = -1;
static int hf_ansi_801_mob_sys_t_offset = -1;
static int hf_ansi_801_desired_pilot_phase_resolution = -1;
static int hf_ansi_801_for_req_loc_velocity_information = -1;
static int hf_ansi_801_reserved8_0F = -1;
static int hf_ansi_801_hybrid_gps_and_aflt_lcc = -1;
static int hf_ansi_801_gps_acq_cap = -1;
static int hf_ansi_801_gps_sensitivity_assistance = -1;
static int hf_ansi_801_ms_ls_rev = -1;
static int hf_ansi_801_reject_request_type = -1;
static int hf_ansi_801_ms_mode = -1;
static int hf_ansi_801_bs_ls_rev = -1;
static int hf_ansi_801_ref_pn = -1;
static int hf_ansi_801_rev_message_number_responses0F = -1;
static int hf_ansi_801_for_req_loc_height_information = -1;
static int hf_ansi_801_gps_capability_indicator = -1;
static int hf_ansi_801_rev_req_loc_clock_correction_for_gps_time = -1;
static int hf_ansi_801_data_records = -1;
static int hf_ansi_801_for_message_number_requests8 = -1;
static int hf_ansi_801_subframes_4_and_5 = -1;
static int hf_ansi_801_use_action_time_indicator = -1;
static int hf_ansi_801_lcc_using_gps_almanac_assistance = -1;
static int hf_ansi_801_lcc_using_gps_almanac_correction = -1;
static int hf_ansi_801_pd_message_len = -1;
static int hf_ansi_801_lcc_using_location_assistance_cartesian = -1;
static int hf_ansi_801_for_message_number_requests16 = -1;
static int hf_ansi_801_reserved_24_7 = -1;
static int hf_ansi_801_loc_calc_cap = -1;
static int hf_ansi_801_toa = -1;

static dissector_handle_t ansi_801_handle;

/* PARAM FUNCTIONS */

#define	EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len)			\
	if ((edc_len) > (edc_max_len))					\
	{								\
		proto_tree_add_text(tree, tvb,				\
				    offset, (edc_len) - (edc_max_len), "Extraneous Data"); \
	}

#define	SHORT_DATA_CHECK(sdc_len, sdc_min_len)				\
	if ((sdc_len) < (sdc_min_len))					\
	{								\
		proto_tree_add_text(tree, tvb,				\
				    offset, (sdc_len), "Short Data (?)"); \
		return;							\
	}

#define	EXACT_DATA_CHECK(edc_len, edc_eq_len)				\
	if ((edc_len) != (edc_eq_len))					\
	{								\
		proto_tree_add_text(tree, tvb,				\
				    offset, (edc_len), "Unexpected Data Length"); \
		return;							\
	}


/*
 * Table 3.2-4 for PD_MSG_TYPE = '0000000'
 */
static const value_string for_req_type_strings[] = {
	{ 0,	"Reserved" },
	{ 1,	"Request Location Response" },
	{ 2,	"Request MS Information" },
	{ 3,	"Request Autonomous Measurement Weighting Factors" },
	{ 4,	"Request Pseudorange Measurement" },
	{ 5,	"Request Pilot Phase Measurement" },
	{ 6,	"Request Time Offset Measurement" },
	{ 7,	"Request Cancellation" },
	{ 0, NULL },
};
#define	NUM_FOR_REQ_TYPE (sizeof(for_req_type_strings)/sizeof(value_string))
static gint ett_for_req_type[NUM_FOR_REQ_TYPE];

static const value_string for_rsp_type_strings[] = {
	{ 0,	"Reject" },
	{ 2,	"Provide BS Capabilities" },
	{ 4,	"Provide GPS Acquisition Assistance" },
	{ 6,	"Provide GPS Location Assistance Spherical Coordinates" },
	{ 7,	"Provide GPS Location Assistance Cartesian Coordinates" },
	{ 5,	"Provide GPS Sensitivity Assistance" },
	{ 3,	"Provide Base Station Almanac" },
	{ 8,	"Provide GPS Almanac" },
	{ 9,	"Provide GPS Ephemeris" },
	{ 10,	"Provide GPS Navigation Message Bits" },
	{ 1,	"Provide Location Response" },
	{ 11,	"Provide GPS Almanac Correction" },
	{ 12,	"Provide GPS Satellite Health Information" },
	{ 0, NULL },
};
#define	NUM_FOR_RSP_TYPE (sizeof(for_rsp_type_strings)/sizeof(value_string))
static gint ett_for_rsp_type[NUM_FOR_RSP_TYPE];


static const value_string rev_rsp_type_strings[] = {
	{ 0,	"Reject" },
	{ 2,	"Provide MS Information" },
	{ 3,	"Provide Autonomous Measurement Weighting Factors" },
	{ 4,	"Provide Pseudorange Measurement" },
	{ 5,	"Provide Pilot Phase Measurement" },
	{ 1,	"Provide Location Response" },
	{ 6,	"Provide Time Offset Measurement" },
	{ 7,	"Provide Cancellation Acknowledgement" },
	{ 0, NULL },
};
#define	NUM_REV_RSP_TYPE (sizeof(rev_rsp_type_strings)/sizeof(value_string))
static gint ett_rev_rsp_type[NUM_REV_RSP_TYPE];

/*
 * Table 2.2-5 for PD_MSG_TYPE = '0000000'
 */
static const value_string rev_req_type_strings[] = {
	{ 0,	"Reserved" },
	{ 2,	"Request BS Capabilities" },
	{ 4,	"Request GPS Acquisition Assistance" },
	{ 6,	"Request GPS Location Assistance" },
	{ 7,	"Reserved" },
	{ 5,	"Request GPS Sensitivity Assistance" },
	{ 3,	"Request Base Station Almanac" },
	{ 8,	"Request GPS Almanac" },
	{ 9,	"Request GPS Ephemeris" },
	{ 10,	"Request GPS Navigation Message Bits" },
	{ 1,	"Request Location Response" },
	{ 11,	"Request GPS Almanac Correction" },
	{ 12,	"Request GPS Satellite Health Information" },
	{ 0, NULL },
};
#define	NUM_REV_REQ_TYPE (sizeof(rev_req_type_strings)/sizeof(value_string))
static gint ett_rev_req_type[NUM_REV_REQ_TYPE];

static const value_string regulatory_services_indicator_vals[] = {
	{ 0,	"No Regulatory service" },
	{ 1,	"Emergency service" },
	{ 2,	"Reserved" },
	{ 3,	"Reserved" },
	{ 0, NULL },
};

const true_false_string tfs_desired_pilot_phase_resolution = { "at least 1/8th PN chip resolution", "at least 1 PN chip resolution" };
const true_false_string tfs_spherical_cartesian = { "Spherical", "Cartesian" };

static void
for_req_pseudo_meas(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32	saved_offset = offset;

	SHORT_DATA_CHECK(len, 3);

	/* PREF_RESP_QUAL */
	proto_tree_add_item(tree, hf_ansi_801_pref_resp_qual, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_num_fixes, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_t_betw_fixes, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_offset_req, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_reserved_24_7, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);

}

static void
for_req_pilot_ph_meas(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32	saved_offset;

	SHORT_DATA_CHECK(len, 3);

	saved_offset = offset;

	proto_tree_add_item(tree, hf_ansi_801_pref_resp_qual, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_num_fixes, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_t_betw_fixes, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_offset_req, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_desired_pilot_phase_resolution, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_reserved_24_7, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_req_loc_response(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32	saved_offset;

	SHORT_DATA_CHECK(len, 3);

	saved_offset = offset;

	proto_tree_add_item(tree, hf_ansi_801_pref_resp_qual, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_num_fixes, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_t_betw_fixes, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_for_req_loc_height_information, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_for_req_loc_clock_correction_for_gps_time, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_for_req_loc_velocity_information, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_reserved24_3, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_req_time_off_meas(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8	oct;
	guint32	saved_offset;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	oct = tvb_get_guint8(tvb, offset);

	proto_tree_add_item(tree, hf_ansi_801_use_action_time_indicator, tvb, offset, 1, ENC_NA);

	if (oct & 0x80)
	{
		proto_tree_add_item(tree, hf_ansi_801_action_time, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_ansi_801_reserved8_01, tvb, offset, 1, ENC_NA);
	}
	else
	{
		proto_tree_add_item(tree, hf_ansi_801_reserved8_7F, tvb, offset, 1, ENC_NA);
	}
	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_req_cancel(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8       oct;
	guint32      saved_offset;
	const gchar *str = NULL;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	oct = tvb_get_guint8(tvb, offset);

	str = val_to_str_const((oct & 0xf0) >> 4, for_req_type_strings, "Reserved");
	proto_tree_add_uint_format_value(tree, hf_ansi_801_cancellation_type, tvb, offset, 1,
			    oct, "(%u) %s", (oct & 0xf0) >> 4, str);

	proto_tree_add_item(tree, hf_ansi_801_reserved8_0F, tvb, offset, 1, ENC_NA);
	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_reject(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8       oct;
	guint32      saved_offset;
	const gchar *str = NULL;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 1);

	oct = tvb_get_guint8(tvb, offset);
	str = val_to_str_const((oct & 0xf0) >> 4, rev_req_type_strings, "Reserved");

	proto_tree_add_uint_format_value(tree, hf_ansi_801_reject_request_type, tvb, offset, 1, oct,
			    "(%u) %s", (oct & 0xf0) >> 4, str);

	switch ((oct & 0x0e) >> 1)
	{
	case 0x00: str = "Capability not supported by the base station"; break;
	case 0x01: str = "Capability normally supported by the base station but temporarily not available or not enabled"; break;
	default: str = "Reserved"; break;
	}

	proto_tree_add_uint_format_value(tree, hf_ansi_801_reject_reason, tvb, offset, 1, oct, "%s", str);
	proto_tree_add_item(tree, hf_ansi_801_reserved8_01, tvb, offset, 1, ENC_NA);
	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_pr_bs_cap(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8	oct;
	guint32	saved_offset;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 2);

	proto_tree_add_item(tree, hf_ansi_801_bs_ls_rev, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_gps_capability_indicator, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_afltc_id, tvb, offset, 1, ENC_NA);
	offset++;

	oct = tvb_get_guint8(tvb, offset);
	if (oct == 0x00)
	{
		proto_tree_add_uint_format(tree, hf_ansi_801_apdc_id, tvb, offset, 1, 0,
				    "APDC_ID: Autonomous position determination capability indicator: None");
	}
	else
	{
		proto_tree_add_item(tree, hf_ansi_801_apdc_id, tvb, offset, 1, ENC_NA);
	}

	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_pr_gps_sense_ass(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32	saved_offset;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 4);

	proto_tree_add_item(tree, hf_ansi_801_ref_bit_num, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_num_dr_p, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_item(tree, hf_ansi_801_dr_size, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_item(tree, hf_ansi_801_part_num, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_total_parts, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_data_records, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset++;

	proto_tree_add_text(tree, tvb, offset, (len - (offset - saved_offset)),
			    "Data records (LSB) + Reserved");

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_pr_gps_almanac(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8	num_sv;
	guint32	value;
	guint32	saved_offset;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 4);

	value  = tvb_get_ntohl(tvb, offset);
	num_sv = (value & 0xfc000000) >> 26;

	proto_tree_add_item(tree, hf_ansi_801_num_sv_p32, tvb, offset, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_week_num, tvb, offset, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_toa, tvb, offset, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_part_num32, tvb, offset, 4, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_total_parts32, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;

	proto_tree_add_text(tree, tvb, offset, (len - (offset - saved_offset)),
			    "%u Data records + Reserved",
			    num_sv);

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_pr_gps_nav_msg_bits(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8	num_sv;
	guint32	value;
	guint32	saved_offset;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 2);

	value  = tvb_get_ntohs(tvb, offset);
	num_sv = (value & 0xfc00) >> 10;

	proto_tree_add_item(tree, hf_ansi_801_num_sv_p16, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_part_num16, tvb, offset, 2, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_total_parts16, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	proto_tree_add_text(tree, tvb, offset, (len - (offset - saved_offset)),
			    "%u SUBF_4_5_INCL ... Data records + Reserved",
			    num_sv);

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

/*
 * shared for both forward/reverse directions
 */
static const true_false_string ansi_801_fix_type_vals = {
	"3D",
	"2D"
};

static void
pr_loc_response(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32      bit_offset, spare_bits;
	guint32      value;
	float        fl_value;
	guint32      saved_offset;
	guint64      fix_type, velocity_incl, clock_incl, height_incl;
	const gchar *str = NULL;

	SHORT_DATA_CHECK(len, 11);
	saved_offset = offset;
	bit_offset   = offset << 3;

	/* TIME_REF_CDMA */
	value = tvb_get_bits16(tvb, bit_offset, 14, ENC_BIG_ENDIAN);
	proto_tree_add_uint_bits_format_value(tree, hf_ansi_801_time_ref_cdma, tvb, bit_offset, 14, value * 50,
					      "%u frames (0x%04x)", value * 50, value);
	bit_offset += 14;

	/* LAT */
	value = tvb_get_bits32(tvb, bit_offset, 25, ENC_BIG_ENDIAN);
	fl_value = (float)(-90.0 + ((float)value * 180 / 33554432));
	proto_tree_add_float_bits_format_value(tree, hf_ansi_801_lat, tvb, bit_offset, 25, fl_value,
					       "%.5f degrees %s (0x%08x)", fabs(fl_value), fl_value < 0 ? "South" : "North", value);
	bit_offset += 25;

	/* LONG */
	value    = tvb_get_bits32(tvb, bit_offset, 26, ENC_BIG_ENDIAN);
	fl_value = (float)(-180.0 + ((float)value * 180 / 33554432));
	proto_tree_add_float_bits_format_value(tree, hf_ansi_801_long, tvb, bit_offset, 26, fl_value,
					       "%.5f degrees %s (0x%08x)", fabs(fl_value), fl_value < 0 ? "West" : "East", value);
	bit_offset += 26;

	/* LOC_UNCRTNTY_ANG */
	value    = tvb_get_bits8(tvb, bit_offset, 4);
	fl_value = (float)(5.625 * value);
	proto_tree_add_float_bits_format_value(tree, hf_ansi_801_loc_uncrtnty_ang, tvb, bit_offset, 4, fl_value,
					       "%.5f degrees (0x%02x)", fl_value, value);
	bit_offset += 4;

	/* LOC_UNCRTNTY_A */
	value = tvb_get_bits8(tvb, bit_offset, 5);
	switch (value)
	{
	case 0x1e: str = "> 12288.00 meters"; break;
	case 0x1f: str = "Not computable"; break;
	default:
		fl_value = (float)(0.5f * (1 << (value >> 1)));
		if (value & 0x01)
			fl_value *= 1.5f;
		str = wmem_strdup_printf(wmem_packet_scope(), "%.2f meters", fl_value);
	}
	proto_tree_add_uint_bits_format_value(tree, hf_ansi_801_loc_uncrtnty_a, tvb, bit_offset, 5, value,
					      "%s (0x%02x)", str, value);
	bit_offset += 5;

	/* LOC_UNCRTNTY_P */
	value = tvb_get_bits8(tvb, bit_offset, 5);
	switch (value)
	{
	case 0x1e: str = "> 12288.00 meters"; break;
	case 0x1f: str = "Not computable"; break;
	default:
		fl_value = (float)(0.5f * (1 << (value >> 1)));
		if (value & 0x01)
			fl_value *= 1.5f;
		str = wmem_strdup_printf(wmem_packet_scope(), "%.2f meters", fl_value);
	}
	proto_tree_add_uint_bits_format_value(tree, hf_ansi_801_loc_uncrtnty_p, tvb, bit_offset, 5, value,
					      "%s (0x%02x)", str, value);
	bit_offset += 5;

	/* FIX_TYPE */
	proto_tree_add_bits_ret_val(tree, hf_ansi_801_fix_type, tvb, bit_offset++, 1, &fix_type, ENC_BIG_ENDIAN);

	/* VELOCITY_INCL */
	proto_tree_add_bits_ret_val(tree, hf_ansi_801_velocity_incl, tvb, bit_offset++, 1, &velocity_incl, ENC_BIG_ENDIAN);


	if(velocity_incl)
	{
		/* VELOCITY_HOR */
		value = tvb_get_bits16(tvb, bit_offset, 9, ENC_BIG_ENDIAN);
		fl_value = (float)(0.25 * value);
		proto_tree_add_float_bits_format_value(tree, hf_ansi_801_velocity_hor, tvb, bit_offset, 9, fl_value,
						       "%.2f m/s (0x%04x)", fl_value, value);
		bit_offset += 9;

		/* HEADING */
		value = tvb_get_bits16(tvb, bit_offset, 10, ENC_BIG_ENDIAN);
		fl_value = (float)value * 360 / 1024;
		proto_tree_add_float_bits_format_value(tree, hf_ansi_801_heading, tvb, bit_offset, 10, fl_value,
						       "%.3f degrees (0x%04x)", fl_value, value);
		bit_offset += 10;

		if(fix_type)
		{
			/* VELOCITY_VER */
			value = tvb_get_bits8(tvb, bit_offset, 8);
			fl_value = (float)(-64 + 0.5 * value);
			proto_tree_add_float_bits_format_value(tree, hf_ansi_801_velocity_ver, tvb, bit_offset, 8, fl_value,
							       "%.1f m/s (0x%02x)", fl_value, value);
			bit_offset += 8;
		}
	}

	/* CLOCK_INCL */
	proto_tree_add_bits_ret_val(tree, hf_ansi_801_clock_incl, tvb, bit_offset++, 1, &clock_incl, ENC_BIG_ENDIAN);

	if(clock_incl)
	{
		/* CLOCK_BIAS */
		value = tvb_get_bits32(tvb, bit_offset, 18, ENC_BIG_ENDIAN);
		proto_tree_add_int_bits_format_value(tree, hf_ansi_801_clock_bias, tvb, bit_offset, 18, (gint32)value - 13000,
						     "%d ns (0x%06x)", (gint32)value - 13000, value);
		bit_offset += 18;

		/* CLOCK_DRIFT */
		value = tvb_get_bits16(tvb, bit_offset, 16, ENC_BIG_ENDIAN);
		proto_tree_add_int_bits_format_value(tree, hf_ansi_801_clock_drift, tvb, bit_offset, 16, (gint16)value,
						     "%d ppb (ns/s) (0x%04x)", (gint16)value, value);
		bit_offset += 16;
	}

	/* HEIGHT_INCL */
	proto_tree_add_bits_ret_val(tree, hf_ansi_801_height_incl, tvb, bit_offset++, 1, &height_incl, ENC_BIG_ENDIAN);

	if(height_incl)
	{
		/* HEIGHT */
		value = tvb_get_bits16(tvb, bit_offset, 14, ENC_BIG_ENDIAN);
		proto_tree_add_int_bits_format_value(tree, hf_ansi_801_height, tvb, bit_offset, 14, (gint32)value - 500,
						     "%d m (0x%04x)", (gint32)value - 500, value);
		bit_offset += 14;

		/* LOC_UNCRTNTY_V */
		value = tvb_get_bits8(tvb, bit_offset, 5);
		switch (value)
		{
		case 0x1e: str = "> 12288.00 meters"; break;
		case 0x1f: str = "Not computable"; break;
		default:
			fl_value = (float)(0.5f * (1 << (value >> 1)));
			if (value & 0x01)
				fl_value *= 1.5f;
			str = wmem_strdup_printf(wmem_packet_scope(), "%.2f meters", fl_value);
		}
		proto_tree_add_uint_bits_format_value(tree, hf_ansi_801_loc_uncrtnty_v, tvb, bit_offset, 5, value,
						      "%s (0x%02x)", str, value);
		bit_offset += 5;
	}

	if(bit_offset & 0x07)
	{
		spare_bits = 8 - (bit_offset & 0x07);
		proto_tree_add_bits_item(tree, hf_ansi_801_reserved_bits, tvb, bit_offset, spare_bits, ENC_BIG_ENDIAN);
		bit_offset += spare_bits;
	}

	offset = bit_offset >> 3;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_pr_loc_response(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	pr_loc_response(tvb, tree, len, offset);
}

static void
for_pr_gps_sat_health(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32	bit_offset, spare_bits;
	guint32	i;
	guint32	saved_offset, num_bad_sv, bad_sv_prn_num;
	guint64	bad_sv_present;

	SHORT_DATA_CHECK(len, 1);
	saved_offset = offset;
	bit_offset   = offset << 3;

	/* BAD_SV_PRESENT */
	proto_tree_add_bits_ret_val(tree, hf_ansi_801_bad_sv_present, tvb, bit_offset++, 1, &bad_sv_present, ENC_BIG_ENDIAN);

	if (bad_sv_present)
	{
		/* NUM_BAD_SV */
		num_bad_sv = tvb_get_bits8(tvb, bit_offset, 4) + 1;
		proto_tree_add_uint_bits_format_value(tree, hf_ansi_801_num_bad_sv, tvb, bit_offset, 4, num_bad_sv,
						      "%u", num_bad_sv);
		bit_offset += 4;

		for (i=0; i < num_bad_sv; i++)
		{
			/* BAD_SV_PRN_NUM */
			bad_sv_prn_num = tvb_get_bits8(tvb, bit_offset, 5) + 1;
			proto_tree_add_uint_bits_format_value(tree, hf_ansi_801_bad_sv_prn_num, tvb, bit_offset, 5, bad_sv_prn_num,
							      "%u", bad_sv_prn_num);
			bit_offset += 5;
		}
	}

	if(bit_offset & 0x07)
	{
		spare_bits = 8 - (bit_offset & 0x07);
		proto_tree_add_bits_item(tree, hf_ansi_801_reserved_bits, tvb, bit_offset, spare_bits, ENC_BIG_ENDIAN);
		bit_offset += spare_bits;
	}

	offset = bit_offset >> 3;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_req_gps_acq_ass(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32	saved_offset;
	guint32	bit_offset;

	SHORT_DATA_CHECK(len, 1);
	saved_offset = offset;
	bit_offset   = offset << 3;

	proto_tree_add_bits_item(tree, hf_ansi_801_dopp_req, tvb, bit_offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_ansi_801_add_dopp_req, tvb, bit_offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_ansi_801_code_ph_par_req, tvb, bit_offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_ansi_801_az_el_req, tvb, bit_offset++, 1, ENC_BIG_ENDIAN);
	proto_tree_add_bits_item(tree, hf_ansi_801_reserved_bits, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_req_gps_loc_ass(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32 saved_offset;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	proto_tree_add_item(tree, hf_ansi_801_coordinate_type_requested, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_reserved8_7F, tvb, offset, 1, ENC_NA);
	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_req_bs_alm(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32 saved_offset;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	proto_tree_add_item(tree, hf_ansi_801_extended_base_station_almanac, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_reserved8_7F, tvb, offset, 1, ENC_NA);
	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_req_gps_ephemeris(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32 saved_offset;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	proto_tree_add_item(tree, hf_ansi_801_alpha_and_beta_parameters, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_reserved8_7F, tvb, offset, 1, ENC_NA);
	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_req_gps_nav_msg_bits(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32 saved_offset;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	proto_tree_add_item(tree, hf_ansi_801_subframes_4_and_5, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_reserved8_7F, tvb, offset, 1, ENC_NA);

	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_req_loc_response(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32 saved_offset;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	proto_tree_add_item(tree, hf_ansi_801_rev_req_loc_height_information, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_rev_req_loc_clock_correction_for_gps_time, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_rev_req_loc_velocity_information, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_reserved8_1F, tvb, offset, 1, ENC_NA);
	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_req_gps_alm_correction(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32	saved_offset;

	SHORT_DATA_CHECK(len, 2);

	saved_offset = offset;

	proto_tree_add_text(tree, tvb, offset, 1,
			    "Time of almanac (in units of 4096 seconds)");

	offset++;
	proto_tree_add_text(tree, tvb, offset, 1,
			    "GPS week number (8 least significant bits)");

	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_reject(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8       oct;
	guint32      saved_offset;
	const gchar *str = NULL;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 1);

	oct = tvb_get_guint8(tvb, offset);

	str = val_to_str_const((oct & 0xf0) >> 4, for_req_type_strings, "Reserved");

    proto_tree_add_uint_format_value(tree, hf_ansi_801_reject_request_type, tvb, offset, 1, oct,
			    "(%u) %s", (oct & 0xf0) >> 4, str);

	switch ((oct & 0x0e) >> 1)
	{
	case 0x00: str = "Capability not supported by the mobile station"; break;
	case 0x01: str = "Capability normally supported by the mobile station but temporarily not available or not enabled"; break;
	default: str = "Reserved"; break;
	}

	proto_tree_add_uint_format_value(tree, hf_ansi_801_reject_reason, tvb, offset, 1,
			    oct, "%s", str);

	proto_tree_add_item(tree, hf_ansi_801_reserved8_01, tvb, offset, 1, ENC_NA);
	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_pr_ms_information(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32      value;
	guint32      saved_offset;
	const gchar *str = NULL;
    proto_item* ti;
    proto_tree *gps_tree, *loc_tree;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 5);

	value = tvb_get_ntohs(tvb, offset);

	proto_tree_add_item(tree, hf_ansi_801_ms_ls_rev, tvb, offset, 2, ENC_BIG_ENDIAN);

	proto_tree_add_item(tree, hf_ansi_801_ms_mode, tvb, offset, 2, ENC_BIG_ENDIAN);

	switch (value & 0x003f)
	{
	case 0x00: str = "Full Chip Measurement Capability"; break;
	case 0x01: str = "Half Chip Measurement Capability"; break;
	case 0x02: str = "Quarter Chip Measurement Capability"; break;
	case 0x03: str = "Eighth Chip Measurement Capability"; break;
	case 0x04: str = "One Sixteenth Chip Measurement Capability"; break;
	default: str = "Reserved"; break;
	}

	proto_tree_add_uint_format_value(tree, hf_ansi_801_pilot_ph_cap, tvb, offset, 2,
			    value, "(%u) %s", value & 0x3f, str);
	offset += 2;

	ti = proto_tree_add_item(tree, hf_ansi_801_gps_acq_cap, tvb, offset, 3, ENC_BIG_ENDIAN);
    gps_tree = proto_item_add_subtree(ti, ett_gps);

	proto_tree_add_item(gps_tree, hf_ansi_801_reserved_24_F80000, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(gps_tree, hf_ansi_801_gps_autonomous_acquisition_capable, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(gps_tree, hf_ansi_801_gps_almanac_correction, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(gps_tree, hf_ansi_801_gps_navigation_message_bits, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(gps_tree, hf_ansi_801_gps_ephemeris, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(gps_tree, hf_ansi_801_gps_almanac, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(gps_tree, hf_ansi_801_gps_sensitivity_assistance, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(gps_tree, hf_ansi_801_gps_acquisition_assistance, tvb, offset, 3, ENC_BIG_ENDIAN);

	ti = proto_tree_add_item(tree, hf_ansi_801_loc_calc_cap, tvb, offset, 3, ENC_BIG_ENDIAN);
    loc_tree = proto_item_add_subtree(ti, ett_loc);

	proto_tree_add_item(loc_tree, hf_ansi_801_pre_programmed_location, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(loc_tree, hf_ansi_801_reserved_24_700, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(loc_tree, hf_ansi_801_hybrid_gps_and_aflt_lcc, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(loc_tree, hf_ansi_801_autonomous_location_calculation_capable, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(loc_tree, hf_ansi_801_lcc_using_gps_almanac_correction, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(loc_tree, hf_ansi_801_lcc_using_gps_ephemeris_assistance, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(loc_tree, hf_ansi_801_lcc_using_gps_almanac_assistance, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(loc_tree, hf_ansi_801_aflt_lcc, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(loc_tree, hf_ansi_801_lcc_using_location_assistance_cartesian, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(loc_tree, hf_ansi_801_lcc_capable_using_location_assistance_spherical, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_pr_loc_response(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	pr_loc_response(tvb, tree, len, offset);
}

static void
rev_pr_time_off_meas(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32	saved_offset;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 6);

	proto_tree_add_text(tree, tvb, offset, 3,
			    "TIME_REF_MS:  The time of validity of the parameters reported in this response element.");
	offset += 3;

	proto_tree_add_item(tree, hf_ansi_801_ref_pn, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_mob_sys_t_offset, tvb, offset, 3, ENC_BIG_ENDIAN);
	proto_tree_add_item(tree, hf_ansi_801_reserved24_1, tvb, offset, 3, ENC_BIG_ENDIAN);
	offset += 3;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_pr_can_ack(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8       oct;
	guint32      saved_offset;
	const gchar *str;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 1);

	oct = tvb_get_guint8(tvb, offset);

	str = val_to_str_const((oct & 0xf0) >> 4, for_req_type_strings, "Reserved");
	proto_tree_add_uint_format_value(tree, hf_ansi_801_cancellation_type, tvb, offset, 1, oct,
			    "(%u) %s", (oct & 0xf0) >> 4, str);

	proto_tree_add_item(tree, hf_ansi_801_no_outstanding_request_element, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_reserved8_07, tvb, offset, 1, ENC_NA);
	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void (*for_req_type_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
	NULL, /* Reserved */
	NULL, /* no data */	/* Request MS Information */
	NULL, /* no data */	/* Request Autonomous Measurement Weighting Factors */
	for_req_pseudo_meas,	/* Request Pseudorange Measurement */
	for_req_pilot_ph_meas,	/* Request Pilot Phase Measurement */
	for_req_loc_response,	/* Request Location Response */
	for_req_time_off_meas,	/* Request Time Offset Measurement */
	for_req_cancel,		/* Request Cancellation */
	NULL, /* NONE */
};

static void (*for_rsp_type_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
	for_reject,              /* Reject */
	for_pr_bs_cap,           /* Provide BS Capabilities */
	NULL,                    /* Provide GPS Acquisition Assistance */
	NULL,                    /* Provide GPS Location Assistance Spherical Coordinates */
	NULL,                    /* Provide GPS Location Assistance Cartesian Coordinates */
	for_pr_gps_sense_ass,    /* Provide GPS Sensitivity Assistance */
	NULL,                    /* Provide Base Station Almanac */
	for_pr_gps_almanac,      /* Provide GPS Almanac */
	NULL,                    /* Provide GPS Ephemeris */
	for_pr_gps_nav_msg_bits, /* Provide GPS Navigation Message Bits */
	for_pr_loc_response,     /* Provide Location Response */
	NULL,                    /* Provide GPS Almanac Correction */
	for_pr_gps_sat_health,   /* Provide GPS Satellite Health Information */
	NULL,                    /* NONE */
};

static void (*rev_req_type_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
	NULL,	/* Reserved */
	NULL,   /* no data */		/* Request BS Capabilities */
	rev_req_gps_acq_ass,		/* Request GPS Acquisition Assistance */
	rev_req_gps_loc_ass,		/* Request GPS Location Assistance */
	NULL,	/* Reserved */
	NULL,   /* no data */		/* Request GPS Sensitivity Assistance */
	rev_req_bs_alm,			/* Request Base Station Almanac */
	NULL,   /* no data */		/* Request GPS Almanac */
	rev_req_gps_ephemeris,		/* Request GPS Ephemeris */
	rev_req_gps_nav_msg_bits,	/* Request GPS Navigation Message Bits */
	rev_req_loc_response,		/* Request Location Response */
	rev_req_gps_alm_correction,	/* Request GPS Almanac Correction */
	NULL,   /* no data */		/* Request GPS Satellite Health Information */
	NULL,	/* NONE */
};

static void (*rev_rsp_type_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
	rev_reject,            /* Reject */
	rev_pr_ms_information, /* Provide MS Information */
	NULL,                  /* Provide Autonomous Measurement Weighting Factors */
	NULL,                  /* Provide Pseudorange Measurement */
	NULL,                  /* Provide Pilot Phase Measurement */
	rev_pr_loc_response,   /* Provide Location Response */
	rev_pr_time_off_meas,  /* Provide Time Offset Measurement */
	rev_pr_can_ack,        /* Provide Cancellation Acknowledgement */
	NULL,                  /* NONE */
};

static void
for_request(tvbuff_t *tvb, proto_tree *tree, guint32 *offset_p, guint8 pd_msg_type)
{
	guint32      offset;
	guint8       oct;
	const gchar *str = NULL;
	gint         idx;
	proto_tree  *subtree;
	proto_item  *item;

	offset = *offset_p;
	oct    = tvb_get_guint8(tvb, offset);

	if (pd_msg_type == 0x00)
	{
		proto_tree_add_item(tree, hf_ansi_801_reserved8_F0, tvb, offset, 1, ENC_NA);

		str = try_val_to_str_idx(oct & 0x0f, for_req_type_strings, &idx);
		if (str == NULL)
		{
			return;
		}

		item = proto_tree_add_uint_format_value(tree, hf_ansi_801_for_req_type, tvb, offset, 1,
                            oct & 0x0f, "%s (%u)", str, oct & 0x0f);
	}
	else
	{
		/* TBD */
		/*
		 * It is unclear from TIA-801-A how this was meant to be decoded.
		 * Are the elements supposed to be byte aligned?
		 */
		return;
	}

	subtree = proto_item_add_subtree(item, ett_for_req_type[idx]);

	offset++;
	oct = tvb_get_guint8(tvb, offset);

	proto_tree_add_item(subtree, hf_ansi_801_for_request_length, tvb, offset, 1, ENC_NA);
	offset++;

	if (oct > 0)
	{
		if (for_req_type_fcn[idx] != NULL)
		{
			(*for_req_type_fcn[idx])(tvb, subtree, oct, offset);
		}
		else
		{
			proto_tree_add_text(subtree, tvb, offset, oct, "Data");
		}
	}

	*offset_p = offset + oct;
}

static void
for_response(tvbuff_t *tvb, proto_tree *tree, guint32 *offset_p)
{
	guint32      offset;
	guint8       oct;
	const gchar *str = NULL;
	gint         idx;
	proto_tree  *subtree;
	proto_item  *item;

	offset = *offset_p;
	oct    = tvb_get_guint8(tvb, offset);

	proto_tree_add_item(tree, hf_ansi_801_reserved8_E0, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_unsolicited_response_indicator, tvb, offset, 1, ENC_NA);

	str = try_val_to_str_idx(oct & 0x0f, for_rsp_type_strings, &idx);

	if (str == NULL)
	{
		return;
	}

	item = proto_tree_add_uint_format_value(tree, hf_ansi_801_for_rsp_type, tvb, offset, 1,
                                         oct & 0x0f, "%s (%u)", str, oct & 0x0f);
	subtree = proto_item_add_subtree(item, ett_for_rsp_type[idx]);

	offset++;
	oct = tvb_get_guint8(tvb, offset);

	proto_tree_add_item(subtree, hf_ansi_801_for_response_length, tvb, offset, 1, ENC_NA);

	offset++;

	if (for_rsp_type_fcn[idx] != NULL)
	{
		(*for_rsp_type_fcn[idx])(tvb, subtree, oct, offset);
	}
	else
	{
		proto_tree_add_text(subtree, tvb, offset, oct,
				    "Data");
	}

	*offset_p = offset + oct;
}

static void
rev_request(tvbuff_t *tvb, proto_tree *tree, guint32 *offset_p, guint8 pd_msg_type)
{
	guint32      offset;
	guint8       oct;
	const gchar *str = NULL;
	gint         idx;
	proto_tree  *subtree;
	proto_item  *item;

	offset = *offset_p;
	oct    = tvb_get_guint8(tvb, offset);

	if (pd_msg_type == 0x00)
	{
		proto_tree_add_item(tree, hf_ansi_801_reserved8_F0, tvb, offset, 1, ENC_NA);

		str = try_val_to_str_idx(oct & 0x0f, rev_req_type_strings, &idx);
		if (str == NULL)
		{
			return;
		}

		item = proto_tree_add_uint_format_value(tree, hf_ansi_801_rev_req_type, tvb, offset, 1,
                                             oct & 0x0f, "%s (%u)", str, oct & 0x0f);
	}
	else
	{
		/* TBD */
		/*
		 * It is unclear from TIA-801-A how this was meant to be decoded.
		 * Are the elements supposed to be byte aligned?
		 */
		return;
	}

	subtree = proto_item_add_subtree(item, ett_rev_req_type[idx]);

	offset++;
	oct = tvb_get_guint8(tvb, offset);

	proto_tree_add_item(subtree, hf_ansi_801_rev_request_length, tvb, offset, 1, ENC_NA);

	offset++;

	if (rev_req_type_fcn[idx] != NULL)
	{
		(*rev_req_type_fcn[idx])(tvb, subtree, oct, offset);
	}
	else
	{
		proto_tree_add_text(subtree, tvb, offset, oct,
				    "Data");
	}

	*offset_p = offset + oct;
}

static void
rev_response(tvbuff_t *tvb, proto_tree *tree, guint32 *offset_p)
{
	guint32      offset;
	guint8       oct;
	const gchar *str = NULL;
	gint         idx;
	proto_tree  *subtree;
	proto_item  *item;

	offset = *offset_p;
	oct    = tvb_get_guint8(tvb, offset);

	proto_tree_add_item(tree, hf_ansi_801_reserved8_E0, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_unsolicited_response_indicator, tvb, offset, 1, ENC_NA);

	str = try_val_to_str_idx(oct & 0x0f, rev_rsp_type_strings, &idx);

	if (str == NULL)
	{
		return;
	}

	item = proto_tree_add_uint_format_value(tree, hf_ansi_801_rev_rsp_type, tvb, offset, 1,
                                            oct & 0x0f, "%s (%u)", str, oct & 0x0f);
	subtree = proto_item_add_subtree(item, ett_rev_rsp_type[idx]);
	offset++;

	oct = tvb_get_guint8(tvb, offset);

	proto_tree_add_item(subtree, hf_ansi_801_rev_response_length, tvb, offset, 1, ENC_NA);

	offset++;

	if (rev_rsp_type_fcn[idx] != NULL)
	{
		(*rev_rsp_type_fcn[idx])(tvb, subtree, oct, offset);
	}
	else
	{
		proto_tree_add_text(subtree, tvb, offset, oct,
				    "Data");
	}

	*offset_p = offset + oct;
}

static void
dissect_ansi_801_for_message(tvbuff_t *tvb, proto_tree *tree)
{
	guint32      value;
	guint32      offset;
	guint8       oct, num_req, num_rsp, pd_msg_type;
	guint        rem_len;
	const gchar *str = NULL;
	proto_item  *hidden_item;

	offset = 0;

	proto_tree_add_item(tree, hf_ansi_801_session_start, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_session_end, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_session_source, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_for_sess_tag, tvb, offset, 1, ENC_NA);

	hidden_item = proto_tree_add_item(tree, hf_ansi_801_sess_tag, tvb, offset, 1, ENC_NA);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	offset++;
	oct = tvb_get_guint8(tvb, offset);
	pd_msg_type = oct;

	switch (pd_msg_type)
	{
	case 0x00: str = "Position Determination Data Message"; break;
	case 0x01: str = "Position Determination Data Message"; break;
	case 0xff: str = "Reserved"; break;
	default:
		if (pd_msg_type < 0xc0)
		{
			str = "Reserved for future standardization";
		}
		else
		{
			str = "Available for manufacturer-specific Position Determination "
				  "Data Message definition as specified in TSB-58";
		}
		break;
	}

	proto_tree_add_uint_format_value(tree, hf_ansi_801_pd_message_type, tvb, offset, 1, pd_msg_type,
			    "%s (%u)", str, pd_msg_type);

	offset++;

	if ((pd_msg_type != 0x00) &&
	    (pd_msg_type != 0x01))
	{
		proto_tree_add_text(tree, tvb, offset, -1, "Reserved/Proprietary/Future Data");
		return;
	}

	if (pd_msg_type == 0x01)
	{
		value = tvb_get_ntohs(tvb, offset);

		proto_tree_add_item(tree, hf_ansi_801_pd_message_len, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ansi_801_regulatory_services_indicator, tvb, offset, 2, ENC_BIG_ENDIAN);

		num_req = value & 0x000f;

		proto_tree_add_item(tree, hf_ansi_801_for_message_number_requests16, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		oct = tvb_get_guint8(tvb, offset);
		num_rsp = oct & 0xf0;

		proto_tree_add_item(tree, hf_ansi_801_for_message_number_responsesF0, tvb, offset, 1, ENC_NA);
		offset++;
	}
	else
	{
		oct = tvb_get_guint8(tvb, offset);

		num_req = (oct & 0xf0) >> 4;
		num_rsp = oct & 0x0f;

		proto_tree_add_item(tree, hf_ansi_801_for_message_number_requests8, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_ansi_801_for_message_number_responses0F, tvb, offset, 1, ENC_NA);
	}

	offset++;
	rem_len = tvb_length_remaining(tvb, offset);

	while ((num_req > 0) &&
	       (rem_len >= 2))
	{
		for_request(tvb, tree, &offset, pd_msg_type);

		rem_len = tvb_length_remaining(tvb, offset);
		num_req--;
	}

	if (num_req != 0)
	{
		proto_tree_add_text(tree, tvb,
				    offset, -1, "Short Data (?)");
		return;
	}

	while ((num_rsp > 0) &&
	       (rem_len >= 2))
	{
		for_response(tvb, tree, &offset);

		rem_len = tvb_length_remaining(tvb, offset);
		num_rsp--;
	}

	if (num_rsp != 0)
	{
		proto_tree_add_text(tree, tvb,
				    offset, -1, "Short Data (?)");
		return;
	}

	if (rem_len > 0)
	{
		proto_tree_add_text(tree, tvb, offset, rem_len,
				    "Extraneous Data");
	}
}

static void
dissect_ansi_801_rev_message(tvbuff_t *tvb, proto_tree *tree)
{
	guint32      value;
	guint32      offset;
	guint8       oct, num_req, num_rsp, pd_msg_type;
	guint        rem_len;
	const gchar *str = NULL;
	proto_item  *hidden_item;

	offset = 0;

	proto_tree_add_item(tree, hf_ansi_801_session_start, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_session_end, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_session_source, tvb, offset, 1, ENC_NA);
	proto_tree_add_item(tree, hf_ansi_801_rev_sess_tag, tvb, offset, 1, ENC_NA);

	hidden_item = proto_tree_add_item(tree, hf_ansi_801_sess_tag, tvb, offset, 1, ENC_NA);
	PROTO_ITEM_SET_HIDDEN(hidden_item);

	offset++;
	oct = tvb_get_guint8(tvb, offset);
	pd_msg_type = oct;

	switch (pd_msg_type)
	{
	case 0x00: str = "Position Determination Data Message"; break;
	case 0x01: str = "Position Determination Data Message"; break;
	case 0xff: str = "Reserved"; break;
	default:
		if (pd_msg_type < 0xc0)
		{
			str = "Reserved for future standardization";
		}
		else
		{
			str = "Available for manufacturer-specific Position Determination "
				"Data Message definition as specified in TSB-58";
		}
		break;
	}

	proto_tree_add_uint_format_value(tree, hf_ansi_801_pd_message_type, tvb, offset, 1, pd_msg_type,
			    "%s (%u)", str, pd_msg_type);
	offset++;

	if ((pd_msg_type != 0x00) &&
	    (pd_msg_type != 0x01))
	{
		proto_tree_add_text(tree, tvb, offset, -1, "Reserved/Proprietary/Future Data");
		return;
	}

	if (pd_msg_type == 0x01)
	{
		value = tvb_get_ntohs(tvb, offset);

		proto_tree_add_item(tree, hf_ansi_801_pd_message_len, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_ansi_801_regulatory_services_indicator, tvb, offset, 2, ENC_BIG_ENDIAN);

		num_req = value & 0x000f;

		proto_tree_add_item(tree, hf_ansi_801_rev_message_number_requests16, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		oct = tvb_get_guint8(tvb, offset);
		num_rsp = oct & 0xf0;

		proto_tree_add_item(tree, hf_ansi_801_rev_message_number_responsesF0, tvb, offset, 1, ENC_NA);
		offset++;
	}
	else
	{
		oct = tvb_get_guint8(tvb, offset);

		num_req = (oct & 0xf0) >> 4;
		num_rsp = oct & 0x0f;

		proto_tree_add_item(tree, hf_ansi_801_rev_message_number_requests8, tvb, offset, 1, ENC_NA);
		proto_tree_add_item(tree, hf_ansi_801_rev_message_number_responses0F, tvb, offset, 1, ENC_NA);
		offset++;
	}

	rem_len = tvb_length_remaining(tvb, offset);

	while ((num_req > 0) &&
	       (rem_len >= 2))
	{
		rev_request(tvb, tree, &offset, pd_msg_type);

		rem_len = tvb_length_remaining(tvb, offset);
		num_req--;
	}

	if (num_req != 0)
	{
		proto_tree_add_text(tree, tvb,
				    offset, -1, "Short Data (?)");
		return;
	}

	while ((num_rsp > 0) &&
	       (rem_len >= 2))
	{
		rev_response(tvb, tree, &offset);

		rem_len = tvb_length_remaining(tvb, offset);
		num_rsp--;
	}

	if (num_rsp != 0)
	{
		proto_tree_add_text(tree, tvb,
				    offset, -1, "Short Data (?)");
		return;
	}

	if (rem_len > 0)
	{
		proto_tree_add_text(tree, tvb, offset, rem_len,
				    "Extraneous Data");
	}
}

static void
dissect_ansi_801(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ansi_801_item;
	proto_tree *ansi_801_tree = NULL;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, ansi_proto_name_short);

	/* In the interest of speed, if "tree" is NULL, don't do any work not
	 * necessary to generate protocol tree items.
	 */
	if (tree)
	{
		/*
		 * create the ansi_801 protocol tree
		 */
		ansi_801_item =
			proto_tree_add_protocol_format(tree, proto_ansi_801, tvb, 0, -1,
						       "%s %s Link",
						       ansi_proto_name,
						       (pinfo->match_uint == ANSI_801_FORWARD) ? "Forward" : "Reverse");

		ansi_801_tree =
			proto_item_add_subtree(ansi_801_item, ett_ansi_801);

		if (pinfo->match_uint == ANSI_801_FORWARD)
		{
			dissect_ansi_801_for_message(tvb, ansi_801_tree);
		}
		else
		{
			dissect_ansi_801_rev_message(tvb, ansi_801_tree);
		}
	}
}


/* Register the protocol with Wireshark */
void
proto_register_ansi_801(void)
{
	guint i;
	gint  last_offset;

	/* Setup list of header fields */
	static hf_register_info hf[] =
		{
			{ &hf_ansi_801_for_req_type,
			  { "Forward Request Type",		"ansi_801.for_req_type",
			    FT_UINT8, BASE_DEC, NULL, 0,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_for_rsp_type,
			  { "Forward Response Type",		"ansi_801.for_rsp_type",
			    FT_UINT8, BASE_DEC, NULL, 0,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_rev_req_type,
			  { "Reverse Request Type",		"ansi_801.rev_req_type",
			    FT_UINT8, BASE_DEC, NULL, 0,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_rev_rsp_type,
			  { "Reverse Response Type",		"ansi_801.rev_rsp_type",
			    FT_UINT8, BASE_DEC, NULL, 0,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_for_sess_tag,
			  { "Forward Session Tag",		"ansi_801.for_sess_tag",
			    FT_UINT8, BASE_DEC, NULL, 0x1f,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_rev_sess_tag,
			  { "Reverse Session Tag",		"ansi_801.rev_sess_tag",
			    FT_UINT8, BASE_DEC, NULL, 0x1f,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_sess_tag,
			  { "Session Tag",			"ansi_801.sess_tag",
			    FT_UINT8, BASE_DEC, NULL, 0x1f,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_time_ref_cdma,
			  { "CDMA system time at the time the solution is valid (TIME_REF_CDMA)", "ansi_801.time_ref_cdma",
			    FT_UINT32, BASE_DEC, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_lat,
			  { "Latitude (LAT)", "ansi_801.lat",
			    FT_FLOAT, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_long,
			  { "Longitude (LONG)", "ansi_801.long",
			    FT_FLOAT, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_loc_uncrtnty_ang,
			  { "Angle of axis with respect to True North for pos uncertainty (LOC_UNCRTNTY_ANG)", "ansi_801.loc_uncrtnty_ang",
			    FT_FLOAT, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_loc_uncrtnty_a,
			  { "Std dev of axis along angle specified for pos uncertainty (LOC_UNCRTNTY_A)", "ansi_801.loc_uncrtnty_a",
			    FT_UINT8, BASE_DEC, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_loc_uncrtnty_p,
			  { "Std dev of axis perpendicular to angle specified for pos uncertainty (LOC_UNCRTNTY_P)", "ansi_801.loc_uncrtnty_p",
			    FT_UINT8, BASE_DEC, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_fix_type,
			  { "Fix type (FIX_TYPE)", "ansi_801.fix_type",
			    FT_BOOLEAN, BASE_NONE, TFS(&ansi_801_fix_type_vals), 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_velocity_incl,
			  { "Velocity information included (VELOCITY_INCL)", "ansi_801.velocity_incl",
			    FT_BOOLEAN, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_velocity_hor,
			  { "Horizontal velocity magnitude (VELOCITY_HOR)", "ansi_801.velocity_hor",
			    FT_FLOAT, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_heading,
			  { "Heading (HEADING)", "ansi_801.heading",
			    FT_FLOAT, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_velocity_ver,
			  { "Vertical velocity (VELOCITY_VER)", "ansi_801.velocity_ver",
			    FT_FLOAT, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_clock_incl,
			  { "Clock information included (CLOCK_INCL)", "ansi_801.clock_incl",
			    FT_BOOLEAN, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_clock_bias,
			  { "Clock bias (CLOCK_BIAS)", "ansi_801.clock_bias",
			    FT_INT24, BASE_DEC, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_clock_drift,
			  { "Clock drift (CLOCK_DRIFT)", "ansi_801.clock_drift",
			    FT_INT16, BASE_DEC, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_height_incl,
			  { "Height information included (HEIGHT_INCL)", "ansi_801.height_incl",
			    FT_BOOLEAN, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_height,
			  { "Height (HEIGHT)", "ansi_801.height",
			    FT_INT16, BASE_DEC, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_loc_uncrtnty_v,
			  { "Std dev of vertical error for pos uncertainty (LOC_UNCRTNTY_V)", "ansi_801.loc_uncrtnty_v",
			    FT_UINT8, BASE_DEC, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_reserved_bits,
			  { "Reserved bit(s)","ansi_801.reerved_bits",
			    FT_UINT8,BASE_DEC, NULL, 0x0,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_bad_sv_present,
			  { "Bad GPS satellites present (BAD_SV_PRESENT)", "ansi_801.bad_sv_present",
			    FT_BOOLEAN, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_num_bad_sv,
			  { "Number of bad GPS satellites (NUM_BAD_SV)", "ansi_801.num_bad_sv",
			    FT_UINT8, BASE_DEC, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_bad_sv_prn_num,
			  { "Satellite PRN number (SV_PRN_NUM)", "ansi_801.bad_sv_prn_num",
			    FT_UINT8, BASE_DEC, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_dopp_req,
			  { "Doppler (0th order) term requested (DOPP_REQ)", "ansi_801.dopp_req",
			    FT_BOOLEAN, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_add_dopp_req,
			  { "Additional Doppler terms requested (ADD_DOPP_REQ)", "ansi_801.add_dopp_req",
			    FT_BOOLEAN, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_code_ph_par_req,
			  { "Code phase parameters requested (CODE_PH_PAR_REQ)", "ansi_801.code_ph_par_req",
			    FT_BOOLEAN, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_az_el_req,
			  { "Azimuth and elevation angle requested (AZ_EL_REQ)", "ansi_801.az_el_req",
			    FT_BOOLEAN, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_pref_resp_qual,
			  { "Preferred response quality (PREF_RESP_QUAL)", "ansi_801.pref_resp_qual",
			    FT_UINT24, BASE_DEC, NULL, 0xe00000,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_num_fixes,
			  { "Number of fixes (NUM_FIXES)", "ansi_801.num_fixes",
			    FT_UINT24, BASE_DEC, NULL, 0x1fe000,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_t_betw_fixes,
			  { "Time between fixes (T_BETW_FIXES) (in seconds)", "ansi_801.t_betw_fixes",
			    FT_UINT24, BASE_DEC, NULL, 0x001fe0,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_offset_req,
			  { "Offset requested (OFFSET_REQ)", "ansi_801.offset_req",
			    FT_BOOLEAN, 24, TFS(&tfs_requested_not_requested), 0x000010,
			    NULL, HFILL }
			},

      /* Generated from convert_proto_tree_add_text.pl */
      { &hf_ansi_801_desired_pilot_phase_resolution, { "Desired pilot phase resolution", "ansi_801.desired_pilot_phase_resolution", FT_BOOLEAN, 24, TFS(&tfs_desired_pilot_phase_resolution), 0x08, NULL, HFILL }},
      { &hf_ansi_801_reserved_24_7, { "Reserved", "ansi_801.reserved", FT_UINT24, BASE_HEX, NULL, 0x07, NULL, HFILL }},
      { &hf_ansi_801_for_req_loc_height_information, { "Height information", "ansi_801.height_incl", FT_BOOLEAN, 24, TFS(&tfs_requested_not_requested), 0x10, NULL, HFILL }},
      { &hf_ansi_801_for_req_loc_clock_correction_for_gps_time, { "Clock correction for GPS time", "ansi_801.clock_correction_for_gps_time", FT_BOOLEAN, 24, TFS(&tfs_requested_not_requested), 0x08, NULL, HFILL }},
      { &hf_ansi_801_for_req_loc_velocity_information, { "Velocity information", "ansi_801.velocity_information", FT_BOOLEAN, 24, TFS(&tfs_requested_not_requested), 0x04, NULL, HFILL }},
      { &hf_ansi_801_reserved24_3, { "Reserved", "ansi_801.reserved", FT_UINT24, BASE_HEX, NULL, 0x03, NULL, HFILL }},
      { &hf_ansi_801_use_action_time_indicator, { "Use action time indicator", "ansi_801.use_action_time_indicator", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_ansi_801_action_time, { "Action time", "ansi_801.action_time", FT_UINT8, BASE_DEC, NULL, 0x7E, NULL, HFILL }},
      { &hf_ansi_801_reserved8_7F, { "Reserved", "ansi_801.reserved", FT_UINT8, BASE_HEX, NULL, 0x7F, NULL, HFILL }},
      { &hf_ansi_801_cancellation_type, { "Cancellation Type", "ansi_801.cancellation_type", FT_UINT8, BASE_DEC, VALS(for_req_type_strings), 0xF0, NULL, HFILL }},
      { &hf_ansi_801_reserved8_0F, { "Reserved", "ansi_801.reserved", FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }},
      { &hf_ansi_801_reject_request_type, { "Reject request type", "ansi_801.reject_request_type", FT_UINT8, BASE_DEC, VALS(rev_req_type_strings), 0xF0, NULL, HFILL }},
      { &hf_ansi_801_reject_reason, { "Reject reason", "ansi_801.reject_reason", FT_UINT8, BASE_DEC, NULL, 0x0E, NULL, HFILL }},
      { &hf_ansi_801_reserved8_01, { "Reserved", "ansi_801.reserved", FT_UINT8, BASE_HEX, NULL, 0x01, NULL, HFILL }},
      { &hf_ansi_801_bs_ls_rev, { "BS_LS_REV", "ansi_801.bs_ls_rev", FT_UINT8, BASE_HEX, NULL, 0xfc, NULL, HFILL }},
      { &hf_ansi_801_gps_capability_indicator, { "GPSC_ID: GPS capability indicator", "ansi_801.gps_capability_indicator", FT_UINT8, BASE_DEC, NULL, 0x02, NULL, HFILL }},
      { &hf_ansi_801_afltc_id, { "AFLTC_ID: Advanced forward link trilateration capability indicator", "ansi_801.afltc_id", FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }},
      { &hf_ansi_801_apdc_id, { "APDC_ID: Autonomous position determination capability indicator: Autonomous Location Technology Identifier", "ansi_801.apdc_id", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_801_ref_bit_num, { "REF_BIT_NUM", "ansi_801.ref_bit_num", FT_UINT16, BASE_DEC, NULL, 0xffe0, NULL, HFILL }},
      { &hf_ansi_801_num_dr_p, { "NUM_DR_P: Number of data records in this part", "ansi_801.num_dr_p", FT_UINT16, BASE_DEC, NULL, 0x001e, NULL, HFILL }},
      { &hf_ansi_801_dr_size, { "DR_SIZE: Data record size", "ansi_801.dr_size", FT_UINT24, BASE_DEC, NULL, 0x0001FE, NULL, HFILL }},
      { &hf_ansi_801_part_num, { "PART_NUM: The part number", "ansi_801.part_num", FT_UINT16, BASE_DEC, NULL, 0x01c0, NULL, HFILL }},
      { &hf_ansi_801_total_parts, { "TOTAL_PARTS: Total number of parts", "ansi_801.total_parts", FT_UINT16, BASE_DEC, NULL, 0x38, NULL, HFILL }},
      { &hf_ansi_801_data_records, { "Data records", "ansi_801.data_records", FT_UINT16, BASE_DEC, NULL, 0x07, NULL, HFILL }},
      { &hf_ansi_801_num_sv_p32, { "NUM_SV_P: Number of satellites in this part", "ansi_801.num_sv_p", FT_UINT32, BASE_DEC, NULL, 0xfc000000, NULL, HFILL }},
      { &hf_ansi_801_week_num, { "WEEK_NUM: The GPS week number of the almanac", "ansi_801.week_num", FT_UINT32, BASE_DEC, NULL, 0x03fc0000, NULL, HFILL }},
      { &hf_ansi_801_toa, { "TOA: The reference time of the almanac", "ansi_801.toa", FT_UINT32, BASE_DEC, NULL, 0x0003fc00, NULL, HFILL }},
      { &hf_ansi_801_part_num32, { "PART_NUM: The part number", "ansi_801.part_num", FT_UINT32, BASE_DEC, NULL, 0x000003e0, NULL, HFILL }},
      { &hf_ansi_801_total_parts32, { "TOTAL_PARTS: The total number of parts", "ansi_801.total_parts", FT_UINT32, BASE_DEC, NULL, 0x0000001f, NULL, HFILL }},
      { &hf_ansi_801_num_sv_p16, { "NUM_SV_P: Number of satellites in this part", "ansi_801.num_sv_p", FT_UINT16, BASE_DEC, NULL, 0xfc00, NULL, HFILL }},
      { &hf_ansi_801_part_num16, { "PART_NUM: The part number", "ansi_801.part_num", FT_UINT16, BASE_DEC, NULL, 0x03e0, NULL, HFILL }},
      { &hf_ansi_801_total_parts16, { "TOTAL_PARTS: The total number of parts", "ansi_801.total_parts", FT_UINT16, BASE_DEC, NULL, 0x001f, NULL, HFILL }},
      { &hf_ansi_801_coordinate_type_requested, { "Coordinate type requested", "ansi_801.coordinate_type_requested", FT_BOOLEAN, 8, TFS(&tfs_spherical_cartesian), 0x80, NULL, HFILL }},
      { &hf_ansi_801_extended_base_station_almanac, { "Extended base station almanac", "ansi_801.extended_base_station_almanac", FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x80, NULL, HFILL }},
      { &hf_ansi_801_alpha_and_beta_parameters, { "Alpha and Beta parameters", "ansi_801.alpha_and_beta_parameters", FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x80, NULL, HFILL }},
      { &hf_ansi_801_subframes_4_and_5, { "Subframes 4 and 5", "ansi_801.subframes_4_and_5", FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x80, NULL, HFILL }},
      { &hf_ansi_801_rev_req_loc_height_information, { "Height information", "ansi_801.height_information", FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x80, NULL, HFILL }},
      { &hf_ansi_801_rev_req_loc_clock_correction_for_gps_time, { "Clock correction for GPS time", "ansi_801.clock_correction_for_gps_time", FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x40, NULL, HFILL }},
      { &hf_ansi_801_rev_req_loc_velocity_information, { "Velocity information", "ansi_801.velocity_information", FT_BOOLEAN, 8, TFS(&tfs_requested_not_requested), 0x20, NULL, HFILL }},
      { &hf_ansi_801_reserved8_1F, { "Reserved", "ansi_801.reserved", FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }},
      { &hf_ansi_801_ms_ls_rev, { "MS_LS_REV", "ansi_801.ms_ls_rev", FT_UINT16, BASE_DEC, NULL, 0xfc00, NULL, HFILL }},
      { &hf_ansi_801_ms_mode, { "MS_MODE", "ansi_801.ms_mode", FT_UINT16, BASE_DEC, NULL, 0x03c0, NULL, HFILL }},
      { &hf_ansi_801_pilot_ph_cap, { "PILOT_PH_CAP", "ansi_801.pilot_ph_cap", FT_UINT16, BASE_DEC, NULL, 0x003f, NULL, HFILL }},
      { &hf_ansi_801_gps_acq_cap, { "GPS_ACQ_CAP", "ansi_801.gps_acq_cap", FT_UINT24, BASE_HEX, NULL, 0x000FFF, NULL, HFILL }},
      { &hf_ansi_801_reserved_24_F80000, { "Reserved", "ansi_801.reserved", FT_UINT24, BASE_HEX, NULL, 0xf80000, NULL, HFILL }},
      { &hf_ansi_801_gps_autonomous_acquisition_capable, { "GPS Autonomous Acquisition Capable", "ansi_801.gps_autonomous_acquisition_capable", FT_BOOLEAN, 24, NULL, 0x040000, NULL, HFILL }},
      { &hf_ansi_801_gps_almanac_correction, { "GPS Almanac Correction", "ansi_801.gps_almanac_correction", FT_BOOLEAN, 24, NULL, 0x020000, NULL, HFILL }},
      { &hf_ansi_801_gps_navigation_message_bits, { "GPS Navigation Message Bits", "ansi_801.gps_navigation_message_bits", FT_BOOLEAN, 24, NULL, 0x010000, NULL, HFILL }},
      { &hf_ansi_801_gps_ephemeris, { "GPS Ephemeris", "ansi_801.gps_ephemeris", FT_BOOLEAN, 24, NULL, 0x008000, NULL, HFILL }},
      { &hf_ansi_801_gps_almanac, { "GPS Almanac", "ansi_801.gps_almanac", FT_BOOLEAN, 24, NULL, 0x004000, NULL, HFILL }},
      { &hf_ansi_801_gps_sensitivity_assistance, { "GPS Sensitivity Assistance", "ansi_801.gps_sensitivity_assistance", FT_BOOLEAN, 24, NULL, 0x002000, NULL, HFILL }},
      { &hf_ansi_801_gps_acquisition_assistance, { "GPS Acquisition Assistance", "ansi_801.gps_acquisition_assistance", FT_BOOLEAN, 24, NULL, 0x001000, NULL, HFILL }},
      { &hf_ansi_801_loc_calc_cap, { "LOC_CALC_CAP", "ansi_801.loc_calc_cap", FT_UINT24, BASE_HEX, NULL, 0x000FFF, NULL, HFILL }},
      { &hf_ansi_801_pre_programmed_location, { "Pre-programmed Location", "ansi_801.pre_programmed_location", FT_BOOLEAN, 24, NULL, 0x000800, NULL, HFILL }},
      { &hf_ansi_801_reserved_24_700, { "Reserved", "ansi_801.reserved", FT_UINT24, BASE_HEX, NULL, 0x000700, NULL, HFILL }},
      { &hf_ansi_801_hybrid_gps_and_aflt_lcc, { "Hybrid GPS and AFLT Location Calculation Capable", "ansi_801.hybrid_gps_and_aflt_lcc", FT_BOOLEAN, 24, NULL, 0x000080, NULL, HFILL }},
      { &hf_ansi_801_autonomous_location_calculation_capable, { "Autonomous Location Calculation Capable", "ansi_801.autonomous_lcc", FT_BOOLEAN, 24, NULL, 0x000040, NULL, HFILL }},
      { &hf_ansi_801_lcc_using_gps_almanac_correction, { "Location Calculation Capable using GPS Almanac Correction", "ansi_801.lcc_using_gps_almanac_correction", FT_BOOLEAN, 24, NULL, 0x000020, NULL, HFILL }},
      { &hf_ansi_801_lcc_using_gps_ephemeris_assistance, { "Location Calculation Capable using GPS Ephemeris Assistance", "ansi_801.lcc_using_gps_ephemeris_assistance", FT_BOOLEAN, 24, NULL, 0x000010, NULL, HFILL }},
      { &hf_ansi_801_lcc_using_gps_almanac_assistance, { "Location Calculation Capable using GPS Almanac Assistance", "ansi_801.lcc_using_gps_almanac_assistance", FT_BOOLEAN, 24, NULL, 0x000008, NULL, HFILL }},
      { &hf_ansi_801_aflt_lcc, { "Advanced Forward Link Trilateration (AFLT) Location Calculation Capable", "ansi_801.aflt_lcc", FT_BOOLEAN, 24, NULL, 0x000004, NULL, HFILL }},
      { &hf_ansi_801_lcc_using_location_assistance_cartesian, { "Location Calculation Capable using Location Assistance - Cartesian", "ansi_801.lcc_using_location_assistance.cartesian", FT_BOOLEAN, 24, NULL, 0x000002, NULL, HFILL }},
      { &hf_ansi_801_lcc_capable_using_location_assistance_spherical, { "Location Calculation Capable using Location Assistance - Spherical", "ansi_801.lcc_using_location_assistance.spherical", FT_BOOLEAN, 24, NULL, 0x000001, NULL, HFILL }},
      { &hf_ansi_801_ref_pn, { "REF_PN", "ansi_801.ref_pn", FT_UINT24, BASE_DEC, NULL, 0xff8000, NULL, HFILL }},
      { &hf_ansi_801_mob_sys_t_offset, { "MOB_SYS_T_OFFSET", "ansi_801.mob_sys_t_offset", FT_UINT24, BASE_DEC, NULL, 0x007ffe, NULL, HFILL }},
      { &hf_ansi_801_reserved24_1, { "Reserved", "ansi_801.reserved", FT_UINT24, BASE_HEX, NULL, 0x000001, NULL, HFILL }},
      { &hf_ansi_801_no_outstanding_request_element, { "No outstanding request element", "ansi_801.no_outstanding_request_element", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
      { &hf_ansi_801_reserved8_07, { "Reserved", "ansi_801.reserved", FT_UINT8, BASE_HEX, NULL, 0x07, NULL, HFILL }},
      { &hf_ansi_801_reserved8_F0, { "Reserved", "ansi_801.reserved", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL }},
      { &hf_ansi_801_for_request_length, { "Length", "ansi_801.for_request_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_801_reserved8_E0, { "Reserved", "ansi_801.reserved", FT_UINT8, BASE_HEX, NULL, 0xE0, NULL, HFILL }},
      { &hf_ansi_801_unsolicited_response_indicator, { "Unsolicited response indicator", "ansi_801.unsolicited_response_indicator", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
      { &hf_ansi_801_for_response_length, { "Length", "ansi_801.for_response_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_801_rev_request_length, { "Length", "ansi_801.rev_request_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_801_rev_response_length, { "Length", "ansi_801.rev_response_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
      { &hf_ansi_801_session_start, { "Session Start", "ansi_801.session_start", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL }},
      { &hf_ansi_801_session_end, { "Session End", "ansi_801.session_end", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL }},
      { &hf_ansi_801_session_source, { "Session Source", "ansi_801.session_source", FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
      { &hf_ansi_801_pd_message_type, { "PD Message Type", "ansi_801.pd_message_type", FT_UINT8, BASE_DEC, NULL, 0xFF, NULL, HFILL }},
      { &hf_ansi_801_pd_message_len, { "PD Message Length", "ansi_801.pd_message_len", FT_UINT16, BASE_DEC, NULL, 0xffc0, NULL, HFILL }},
      { &hf_ansi_801_regulatory_services_indicator, { "Regulatory Services Indicator", "ansi_801.regulatory_services_indicator", FT_UINT16, BASE_DEC, VALS(regulatory_services_indicator_vals), 0x0030, NULL, HFILL }},
      { &hf_ansi_801_for_message_number_requests16, { "Number Requests", "ansi_801.for_message_number_requests", FT_UINT16, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_ansi_801_for_message_number_responsesF0, { "Number Responses", "ansi_801.for_message_number_responses", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
      { &hf_ansi_801_for_message_number_requests8, { "Number Requests", "ansi_801.for_message_number_requests", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
      { &hf_ansi_801_for_message_number_responses0F, { "Number Responses", "ansi_801.for_message_number_responses", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_ansi_801_rev_message_number_requests16, { "Number Requests", "ansi_801.rev_message_number_requests", FT_UINT16, BASE_DEC, NULL, 0x0F, NULL, HFILL }},
      { &hf_ansi_801_rev_message_number_responsesF0, { "Number Responses", "ansi_801.rev_message_number_responses", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
      { &hf_ansi_801_rev_message_number_requests8, { "Number Requests", "ansi_801.rev_message_number_requests", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }},
      { &hf_ansi_801_rev_message_number_responses0F, { "Number Responses", "ansi_801.rev_message_number_responses", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }},

		};


	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_PARAMS	3
	gint *ett[NUM_INDIVIDUAL_PARAMS+NUM_FOR_REQ_TYPE+NUM_FOR_RSP_TYPE+NUM_REV_REQ_TYPE+NUM_REV_RSP_TYPE];

	ett[0] = &ett_ansi_801;
    ett[1] = &ett_gps;
    ett[2] = &ett_loc;

	last_offset = NUM_INDIVIDUAL_PARAMS;

	for (i=0; i < NUM_FOR_REQ_TYPE; i++, last_offset++)
	{
		ett_for_req_type[i] = -1;
		ett[last_offset] = &ett_for_req_type[i];
	}

	for (i=0; i < NUM_FOR_RSP_TYPE; i++, last_offset++)
	{
		ett_for_rsp_type[i] = -1;
		ett[last_offset] = &ett_for_rsp_type[i];
	}

	for (i=0; i < NUM_REV_REQ_TYPE; i++, last_offset++)
	{
		ett_rev_req_type[i] = -1;
		ett[last_offset] = &ett_rev_req_type[i];
	}

	for (i=0; i < NUM_REV_RSP_TYPE; i++, last_offset++)
	{
		ett_rev_rsp_type[i] = -1;
		ett[last_offset] = &ett_rev_rsp_type[i];
	}

	/* Register the protocol name and description */
	proto_ansi_801 =
		proto_register_protocol(ansi_proto_name, "ANSI IS-801 (Location Services (PLD))", "ansi_801");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_ansi_801, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	ansi_801_handle = register_dissector("ansi_801", dissect_ansi_801, proto_ansi_801);
}


void
proto_reg_handoff_ansi_801(void)
{
	dissector_add_uint("ansi_map.pld", ANSI_801_FORWARD, ansi_801_handle);
	dissector_add_uint("ansi_map.pld", ANSI_801_REVERSE, ansi_801_handle);
	dissector_add_uint("ansi_a.pld",   ANSI_801_FORWARD, ansi_801_handle);
	dissector_add_uint("ansi_a.pld",   ANSI_801_REVERSE, ansi_801_handle);
}
