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

#include <stdlib.h>

#include <glib.h>
#include <math.h>

#include <epan/packet.h>


static const char *ansi_proto_name = "ANSI IS-801 (Location Services (PLD))";
static const char *ansi_proto_name_short = "IS-801";

#define	ANSI_801_FORWARD	0
#define	ANSI_801_REVERSE	1


/* Initialize the subtree pointers */
static gint ett_ansi_801 = -1;

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

static char bigbuf[1024];
static dissector_handle_t data_handle;
static packet_info *g_pinfo;
static proto_tree *g_tree;


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
	{ 2,	"Request MS Information" },
	{ 3,	"Request Autonomous Measurement Weighting Factors" },
	{ 4,	"Request Pseudorange Measurement" },
	{ 5,	"Request Pilot Phase Measurement" },
	{ 1,	"Request Location Response" },
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

static void
for_req_pseudo_meas(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32	bit_offset, spare_bits;
	guint32	saved_offset, value;

	SHORT_DATA_CHECK(len, 3);
	saved_offset = offset;
	bit_offset   = offset << 3;

	/* PREF_RESP_QUAL */
	proto_tree_add_bits_item(tree, hf_ansi_801_pref_resp_qual, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
	bit_offset += 3;

	/* NUM_FIXES */
	value = tvb_get_bits8(tvb, bit_offset, 8) + 1;
	proto_tree_add_uint_bits_format_value(tree, hf_ansi_801_num_fixes, tvb, bit_offset, 8, value, "%u", value);
	bit_offset += 8;

	/* T_BETW_FIXES */
	value = tvb_get_bits8(tvb, bit_offset, 8);
	proto_tree_add_uint_bits_format_value(tree, hf_ansi_801_t_betw_fixes, tvb, bit_offset, 8, value, "%u seconds", value);
	bit_offset += 8;

	/* OFFSET_REQ */
	proto_tree_add_bits_item(tree, hf_ansi_801_offset_req, tvb, bit_offset++, 1, ENC_BIG_ENDIAN);

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
for_req_pilot_ph_meas(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32	value;
	guint32	saved_offset;

	SHORT_DATA_CHECK(len, 3);

	saved_offset = offset;

	value = tvb_get_ntoh24(tvb, offset);

	other_decode_bitfield_value(bigbuf, value >> 16, 0xe0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Preferred response quality, %u",
			    bigbuf,
			    (value & 0xe00000) >> 21);

	other_decode_bitfield_value(bigbuf, value >> 16, 0x1f, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Number of fixes (MSB), %u",
			    bigbuf,
			    (value & 0x1fe000) >> 13);

	other_decode_bitfield_value(bigbuf, value >> 8, 0xe0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Number of fixes (LSB)",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value >> 8, 0x1f, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Time between fixes (MSB), %u",
			    bigbuf,
			    (value & 0x001fe0) >> 5);

	other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Time between fixes (LSB)",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x10, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Offset %srequested",
			    bigbuf,
			    (value & 0x10) ? "" : "not ");

	other_decode_bitfield_value(bigbuf, value, 0x08, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Desired pilot phase resolution: at least %s PN chip resolution",
			    bigbuf,
			    (value & 0x08) ? "1/8th" : "1");

	other_decode_bitfield_value(bigbuf, value, 0x07, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

	offset += 3;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_req_loc_response(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32	value;
	guint32	saved_offset;

	SHORT_DATA_CHECK(len, 3);

	saved_offset = offset;

	value = tvb_get_ntoh24(tvb, offset);

	other_decode_bitfield_value(bigbuf, value >> 16, 0xe0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Preferred response quality, %u",
			    bigbuf,
			    (value & 0xe00000) >> 21);

	other_decode_bitfield_value(bigbuf, value >> 16, 0x1f, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Number of fixes (MSB), %u",
			    bigbuf,
			    (value & 0x1fe000) >> 13);

	other_decode_bitfield_value(bigbuf, value >> 8, 0xe0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Number of fixes (LSB)",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value >> 8, 0x1f, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Time between fixes (MSB), %u",
			    bigbuf,
			    (value & 0x001fe0) >> 5);

	other_decode_bitfield_value(bigbuf, value, 0xe0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Time between fixes (LSB)",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x10, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Height information %srequested",
			    bigbuf,
			    (value & 0x10) ? "" : "not ");

	other_decode_bitfield_value(bigbuf, value, 0x08, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Clock correction for GPS time %srequested",
			    bigbuf,
			    (value & 0x08) ? "" : "not ");

	other_decode_bitfield_value(bigbuf, value, 0x04, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Velocity information %srequested",
			    bigbuf,
			    (value & 0x04) ? "" : "not ");

	other_decode_bitfield_value(bigbuf, value, 0x03, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

	offset += 3;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_req_time_off_meas(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8	oct;
	guint8	bit_mask;
	guint32	saved_offset;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	oct = tvb_get_guint8(tvb, offset);

	other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Use action time indicator",
			    bigbuf);

	if (oct & 0x80)
	{
		other_decode_bitfield_value(bigbuf, oct, 0x7e, 8);
		proto_tree_add_text(tree, tvb, offset, 1,
				    "%s :  Action time, %u",
				    bigbuf,
				    (oct & 0x7e) >> 1);

		bit_mask = 0x01;
	}
	else
	{
		bit_mask = 0x7f;
	}

	other_decode_bitfield_value(bigbuf, oct, bit_mask, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_req_cancel(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8       oct;
	guint32      saved_offset;
	const gchar *str = NULL;
	gint         idx;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	oct = tvb_get_guint8(tvb, offset);

	str = match_strval_idx((oct & 0xf0) >> 4, for_req_type_strings, &idx);
	if (str == NULL)
	{
		str = "Reserved";
	}

	other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Cancellation Type: (%u) %s",
			    bigbuf,
			    (oct & 0xf0) >> 4,
			    str);

	other_decode_bitfield_value(bigbuf, oct, 0x0f, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_reject(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8       oct;
	guint32      saved_offset;
	const gchar *str = NULL;
	gint         idx;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 1);

	oct = tvb_get_guint8(tvb, offset);

	str = match_strval_idx((oct & 0xf0) >> 4, rev_req_type_strings, &idx);
	if (str == NULL)
	{
		str = "Reserved";
	}

	other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reject request type: (%u) %s",
			    bigbuf,
			    (oct & 0xf0) >> 4,
			    str);

	switch ((oct & 0x0e) >> 1)
	{
	case 0x00: str = "Capability not supported by the base station"; break;
	case 0x01: str = "Capability normally supported by the base station but temporarily not available or not enabled"; break;
	default: str = "Reserved"; break;
	}

	other_decode_bitfield_value(bigbuf, oct, 0x0e, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reject reason: %s",
			    bigbuf,
			    str);

	other_decode_bitfield_value(bigbuf, oct, 0x01, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

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

	oct = tvb_get_guint8(tvb, offset);

	other_decode_bitfield_value(bigbuf, oct, 0xfc, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  BS_LS_REV",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x02, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  GPSC_ID: GPS capability indicator",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x01, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  AFLTC_ID: Advanced forward link trilateration capability indicator",
			    bigbuf);

	offset++;

	oct = tvb_get_guint8(tvb, offset);
	if (oct == 0x00)
	{
		proto_tree_add_text(tree, tvb, offset, 1,
				    "APDC_ID: Autonomous position determination capability indicator: None");
	}
	else
	{
		proto_tree_add_text(tree, tvb, offset, 1,
				    "APDC_ID: Autonomous position determination capability indicator: Autonomous Location Technology Identifier %u",
				    oct);
	}

	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
for_pr_gps_sense_ass(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8	oct;
	guint8	num_dr_p;
	guint32	value;
	guint32	saved_offset;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 4);

	value = tvb_get_ntohs(tvb, offset);

	other_decode_bitfield_value(bigbuf, value, 0xffe0, 16);
	proto_tree_add_text(tree, tvb, offset, 2,
			    "%s :  REF_BIT_NUM: %u",
			    bigbuf,
			    (value & 0xffe0) >> 5);

	num_dr_p = (value & 0x001e) >> 1;

	other_decode_bitfield_value(bigbuf, value, 0x001e, 16);
	proto_tree_add_text(tree, tvb, offset, 2,
			    "%s :  NUM_DR_P: Number of data records in this part: %u",
			    bigbuf,
			    num_dr_p);

	offset += 2;
	oct     = tvb_get_guint8(tvb, offset);

	other_decode_bitfield_value(bigbuf, value, 0x0001, 16);
	value = ((value & 0x0001) << 7) | ((oct & 0xfe) >> 1);

	proto_tree_add_text(tree, tvb, offset - 2, 2,
			    "%s :  DR_SIZE: Data record size in 2-bit units (MSB): %u",
			    bigbuf,
			    value);

	other_decode_bitfield_value(bigbuf, oct, 0xfe, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  DR_SIZE: (LSB)",
			    bigbuf);

	value = oct;
	offset++;

	oct = tvb_get_guint8(tvb, offset);

	other_decode_bitfield_value(bigbuf, value, 0x01, 8);
	value = ((value & 0x0001) << 2) | ((oct & 0xc0) >> 6);

	proto_tree_add_text(tree, tvb, offset - 1, 1,
			    "%s :  PART_NUM: The part number (MSB): %u",
			    bigbuf,
			    value);

	other_decode_bitfield_value(bigbuf, oct, 0xc0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  PART_NUM: (LSB)",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x38, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  TOTAL_PARTS: Total number of parts: %u",
			    bigbuf,
			    (oct & 0x38) >> 3);

	other_decode_bitfield_value(bigbuf, oct, 0x07, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Data records (MSB)",
			    bigbuf);

	offset++;

	proto_tree_add_text(tree, tvb, offset, (len - (offset - saved_offset)),
			    "%s :  Data records (LSB) + Reserved",
			    bigbuf);

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

	other_decode_bitfield_value(bigbuf, value, 0xfc000000, 32);
	proto_tree_add_text(tree, tvb, offset, 4,
			    "%s :  NUM_SV_P: Number of satellites in this part: %u",
			    bigbuf,
			    num_sv);

	other_decode_bitfield_value(bigbuf, value, 0x03fc0000, 32);
	proto_tree_add_text(tree, tvb, offset, 4,
			    "%s :  WEEK_NUM: The GPS week number of the almanac: %u",
			    bigbuf,
			    (value & 0x03fc0000) >> 18);

	other_decode_bitfield_value(bigbuf, value, 0x0003fc00, 32);
	proto_tree_add_text(tree, tvb, offset, 4,
			    "%s :  TOA: The reference time of the almanac: %u",
			    bigbuf,
			    (value & 0x0003fc00) >> 10);

	other_decode_bitfield_value(bigbuf, value, 0x000003e0, 32);
	proto_tree_add_text(tree, tvb, offset, 4,
			    "%s :  PART_NUM: The part number: %u",
			    bigbuf,
			    (value & 0x000003e0) >> 5);

	other_decode_bitfield_value(bigbuf, value, 0x0000001f, 32);
	proto_tree_add_text(tree, tvb, offset, 4,
			    "%s :  TOTAL_PARTS: The total number of parts: %u",
			    bigbuf,
			    (value & 0x0000001f));

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

	other_decode_bitfield_value(bigbuf, value, 0xfc00, 16);
	proto_tree_add_text(tree, tvb, offset, 2,
			    "%s :  NUM_SV_P: Number of satellites in this part: %u",
			    bigbuf,
			    num_sv);

	other_decode_bitfield_value(bigbuf, value, 0x03e0, 16);
	proto_tree_add_text(tree, tvb, offset, 2,
			    "%s :  PART_NUM: The part number: %u",
			    bigbuf,
			    (value & 0x03e0) >> 5);

	other_decode_bitfield_value(bigbuf, value, 0x001f, 16);
	proto_tree_add_text(tree, tvb, offset, 2,
			    "%s :  TOTAL_PARTS: The total number of parts: %u",
			    bigbuf,
			    (value & 0x001f));

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
		fl_value = (float)(0.5 * (1 << (value >> 1)));
		if (value & 0x01)
			fl_value *= 1.5;
		str = ep_strdup_printf("%.2f meters", fl_value);
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
		fl_value = (float)(0.5 * (1 << (value >> 1)));
		if (value & 0x01)
			fl_value *= 1.5;
		str = ep_strdup_printf("%.2f meters", fl_value);
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
			fl_value = (float)(0.5 * (1 << (value >> 1)));
			if (value & 0x01)
				fl_value *= 1.5;
			str = ep_strdup_printf("%.2f meters", fl_value);
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
	guint8  oct;
	guint32 saved_offset;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	oct = tvb_get_guint8(tvb, offset);

	other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Coordinate type requested: %s coordinates",
			    bigbuf,
			    (oct & 0x80) ? "Spherical" : "Cartesian");

	other_decode_bitfield_value(bigbuf, oct, 0x7f, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_req_bs_alm(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8  oct;
	guint32 saved_offset;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	oct = tvb_get_guint8(tvb, offset);

	other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Extended base station almanac %srequested",
			    bigbuf,
			    (oct & 0x80) ? "" : "not ");

	other_decode_bitfield_value(bigbuf, oct, 0x7f, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_req_gps_ephemeris(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8  oct;
	guint32 saved_offset;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	oct = tvb_get_guint8(tvb, offset);

	other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Alpha and Beta parameters %srequested",
			    bigbuf,
			    (oct & 0x80) ? "" : "not ");

	other_decode_bitfield_value(bigbuf, oct, 0x7f, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_req_gps_nav_msg_bits(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8  oct;
	guint32 saved_offset;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	oct = tvb_get_guint8(tvb, offset);

	other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Subframes 4 and 5 %srequested",
			    bigbuf,
			    (oct & 0x80) ? "" : "not ");

	other_decode_bitfield_value(bigbuf, oct, 0x7f, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_req_loc_response(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8  oct;
	guint32 saved_offset;

	SHORT_DATA_CHECK(len, 1);

	saved_offset = offset;

	oct = tvb_get_guint8(tvb, offset);

	other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Height information %srequested",
			    bigbuf,
			    (oct & 0x80) ? "" : "not ");

	other_decode_bitfield_value(bigbuf, oct, 0x40, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Clock correction for GPS time %srequested",
			    bigbuf,
			    (oct & 0x40) ? "" : "not ");

	other_decode_bitfield_value(bigbuf, oct, 0x20, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Velocity information %srequested",
			    bigbuf,
			    (oct & 0x20) ? "" : "not ");

	other_decode_bitfield_value(bigbuf, oct, 0x1f, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

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
	gint         idx;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 1);

	oct = tvb_get_guint8(tvb, offset);

	str = match_strval_idx((oct & 0xf0) >> 4, for_req_type_strings, &idx);
	if (str == NULL)
	{
		str = "Reserved";
	}

	other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reject request type: (%u) %s",
			    bigbuf,
			    (oct & 0xf0) >> 4,
			    str);

	switch ((oct & 0x0e) >> 1)
	{
	case 0x00: str = "Capability not supported by the mobile station"; break;
	case 0x01: str = "Capability normally supported by the mobile station but temporarily not available or not enabled"; break;
	default: str = "Reserved"; break;
	}

	other_decode_bitfield_value(bigbuf, oct, 0x0e, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reject reason: %s",
			    bigbuf,
			    str);

	other_decode_bitfield_value(bigbuf, oct, 0x01, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

	offset++;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_pr_ms_information(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint32      value;
	guint32      saved_offset;
	const gchar *str = NULL;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 5);

	value = tvb_get_ntohs(tvb, offset);

	other_decode_bitfield_value(bigbuf, value, 0xfc00, 16);
	proto_tree_add_text(tree, tvb, offset, 2,
			    "%s :  MS_LS_REV",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x03c0, 16);
	proto_tree_add_text(tree, tvb, offset, 2,
			    "%s :  MS_MODE",
			    bigbuf);

	switch (value & 0x003f)
	{
	case 0x00: str = "Full Chip Measurement Capability"; break;
	case 0x01: str = "Half Chip Measurement Capability"; break;
	case 0x02: str = "Quarter Chip Measurement Capability"; break;
	case 0x03: str = "Eighth Chip Measurement Capability"; break;
	case 0x04: str = "One Sixteenth Chip Measurement Capability"; break;
	default: str = "Reserved"; break;
	}

	other_decode_bitfield_value(bigbuf, value, 0x003f, 16);
	proto_tree_add_text(tree, tvb, offset, 2,
			    "%s :  PILOT_PH_CAP: (%u) %s",
			    bigbuf,
			    value & 0x3f,
			    str);

	offset += 2;
	value = tvb_get_ntoh24(tvb, offset);

	other_decode_bitfield_value(bigbuf, value, 0xf80000, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  GPS_ACQ_CAP:  Reserved",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x040000, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  GPS_ACQ_CAP:  GPS Autonomous Acquisition Capable",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x020000, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  GPS_ACQ_CAP:  GPS Almanac Correction",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x010000, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  GPS_ACQ_CAP:  GPS Navigation Message Bits",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x008000, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  GPS_ACQ_CAP:  GPS Ephemeris",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x004000, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  GPS_ACQ_CAP:  GPS Almanac",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x002000, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  GPS_ACQ_CAP:  GPS Sensitivity Assistance",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x001000, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  GPS_ACQ_CAP:  GPS Acquisition Assistance",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x000800, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  LOC_CALC_CAP:  Pre-programmed Location",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x000700, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  LOC_CALC_CAP:  Reserved",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x000080, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  LOC_CALC_CAP:  Hybrid GPS and AFLT Location Calculation Capable",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x000040, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  LOC_CALC_CAP:  Autonomous Location Calculation Capable",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x000020, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  LOC_CALC_CAP:  Location Calculation Capable using GPS Almanac Correction",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x000010, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  LOC_CALC_CAP:  Location Calculation Capable using GPS Ephemeris Assistance",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x000008, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  LOC_CALC_CAP:  Location Calculation Capable using GPS Almanac Assistance",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x000004, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  LOC_CALC_CAP:  Advanced Forward Link Trilateration (AFLT) Location Calculation Capable",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x000002, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  LOC_CALC_CAP:  Location Calculation Capable using Location Assistance - Cartesian",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, value, 0x000001, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  LOC_CALC_CAP:  Location Calculation Capable using Location Assistance - Spherical",
			    bigbuf);

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
	guint32	value;
	guint32	saved_offset;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 6);

	proto_tree_add_text(tree, tvb, offset, 3,
			    "TIME_REF_MS:  The time of validity of the parameters reported in this response element.");

	offset += 3;
	value = tvb_get_ntoh24(tvb, offset);

	other_decode_bitfield_value(bigbuf, value, 0xff8000, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  REF_PN: (%u)",
			    bigbuf,
			    (value & 0xff8000) >> 15);

	other_decode_bitfield_value(bigbuf, value, 0x007ffe, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  MOB_SYS_T_OFFSET: (%u)",
			    bigbuf,
			    (value & 0x007ffe) >> 1);

	other_decode_bitfield_value(bigbuf, value, 0x000001, 24);
	proto_tree_add_text(tree, tvb, offset, 3,
			    "%s :  Reserved",
			    bigbuf);

	offset += 3;

	EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_pr_can_ack(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
	guint8       oct;
	guint32      saved_offset;
	const gchar *str = NULL;
	gint         idx;

	saved_offset = offset;

	SHORT_DATA_CHECK(len, 1);

	oct = tvb_get_guint8(tvb, offset);

	str = match_strval_idx((oct & 0xf0) >> 4, for_req_type_strings, &idx);
	if (str == NULL)
	{
		str = "Reserved";
	}

	other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Cancellation Type: (%u) %s",
			    bigbuf,
			    (oct & 0xf0) >> 4,
			    str);

	other_decode_bitfield_value(bigbuf, oct, 0x08, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  No outstanding request element",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x07, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

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
		other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
		proto_tree_add_text(tree, tvb, offset, 1,
				    "%s :  Reserved",
				    bigbuf);

		str = match_strval_idx(oct & 0x0f, for_req_type_strings, &idx);
		if (str == NULL)
		{
			return;
		}

		other_decode_bitfield_value(bigbuf, oct, 0x0f, 8);
		item =
			proto_tree_add_uint_format(tree, hf_ansi_801_for_req_type, tvb, offset,
						   1, oct & 0x0f,
						   "%s :  Request Type, %s (%u)",
						   bigbuf,
						   str,
						   oct & 0x0f);
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

	proto_tree_add_text(subtree, tvb, offset, 1,
			    "Length: %u",
			    oct);

	offset++;

	if (oct > 0)
	{
		if (for_req_type_fcn[idx] != NULL)
		{
			(*for_req_type_fcn[idx])(tvb, subtree, oct, offset);
		}
		else
		{
			proto_tree_add_text(subtree, tvb, offset, oct,
					    "Data");
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

	other_decode_bitfield_value(bigbuf, oct, 0xe0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x10, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Unsolicited response indicator",
			    bigbuf);

	str = match_strval_idx(oct & 0x0f, for_rsp_type_strings, &idx);

	if (str == NULL)
	{
		return;
	}

	other_decode_bitfield_value(bigbuf, oct, 0x0f, 8);
	item =
		proto_tree_add_uint_format(tree, hf_ansi_801_for_rsp_type, tvb, offset,
					   1, oct & 0x0f,
					   "%s :  Response Type, %s (%u)",
					   bigbuf,
					   str,
					   oct & 0x0f);

	subtree = proto_item_add_subtree(item, ett_for_rsp_type[idx]);

	offset++;
	oct = tvb_get_guint8(tvb, offset);

	proto_tree_add_text(subtree, tvb, offset, 1,
			    "Length: %u",
			    oct);

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
		other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
		proto_tree_add_text(tree, tvb, offset, 1,
				    "%s :  Reserved",
				    bigbuf);

		str = match_strval_idx(oct & 0x0f, rev_req_type_strings, &idx);
		if (str == NULL)
		{
			return;
		}

		other_decode_bitfield_value(bigbuf, oct, 0x0f, 8);
		item =
			proto_tree_add_uint_format(tree, hf_ansi_801_rev_req_type, tvb, offset,
						   1, oct & 0x0f,
						   "%s :  Request Type, %s (%u)",
						   bigbuf,
						   str,
						   oct & 0x0f);
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

	proto_tree_add_text(subtree, tvb, offset, 1,
			    "Length: %u",
			    oct);

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

	other_decode_bitfield_value(bigbuf, oct, 0xe0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Reserved",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x10, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Unsolicited response indicator",
			    bigbuf);

	str = match_strval_idx(oct & 0x0f, rev_rsp_type_strings, &idx);

	if (str == NULL)
	{
		return;
	}

	other_decode_bitfield_value(bigbuf, oct, 0x0f, 8);
	item =
		proto_tree_add_uint_format(tree, hf_ansi_801_rev_rsp_type, tvb, offset,
					   1, oct & 0x0f,
					   "%s :  Response Type, %s (%u)",
					   bigbuf,
					   str,
					   oct & 0x0f);

	subtree = proto_item_add_subtree(item, ett_rev_rsp_type[idx]);

	offset++;
	oct = tvb_get_guint8(tvb, offset);

	proto_tree_add_text(subtree, tvb, offset, 1,
			    "Length: %u",
			    oct);

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
	oct    = tvb_get_guint8(tvb, offset);

	other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Session Start",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x40, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Session End",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x20, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Session Source",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x1f, 8);
	proto_tree_add_uint_format(tree, hf_ansi_801_for_sess_tag, tvb, offset,
				   1, oct & 0x1f,
				   "%s :  Session Tag (%u)",
				   bigbuf,
				   oct & 0x1f);

	hidden_item = proto_tree_add_uint(tree, hf_ansi_801_sess_tag, tvb, offset,
					  1, oct & 0x1f);
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
			str =
				"Available for manufacturer-specific Position Determination "
				"Data Message definition as specified in TSB-58";
		}
		break;
	}

	other_decode_bitfield_value(bigbuf, pd_msg_type, 0xff, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  PD Message Type, %s (%u)",
			    bigbuf,
			    str,
			    pd_msg_type);

	offset++;

	if ((pd_msg_type != 0x00) &&
	    (pd_msg_type != 0x01))
	{
		proto_tree_add_text(tree, tvb, offset, -1,
				    "Reserved/Proprietary/Future Data");
		return;
	}

	if (pd_msg_type == 0x01)
	{
		value = tvb_get_ntohs(tvb, offset);

		other_decode_bitfield_value(bigbuf, value, 0xffc0, 16);
		proto_tree_add_text(tree, tvb, offset, 2,
				    "%s :  PD Message Length, (%u)",
				    bigbuf,
				    (value & 0xffc0) >> 6);

		switch ((value & 0x0030) >> 4)
		{
		case 0x00: str = "No Regulatory service"; break;
		case 0x01: str = "Emergency service"; break;
		default:   str = "Reserved"; break;
		}

		other_decode_bitfield_value(bigbuf, value, 0x0030, 16);
		proto_tree_add_text(tree, tvb, offset, 2,
				    "%s :  Regulatory Services Indicator - %s (%u)",
				    bigbuf,
				    str,
				    (value & 0x0030) >> 4);

		num_req = value & 0x000f;

		other_decode_bitfield_value(bigbuf, value, 0x000f, 16);
		proto_tree_add_text(tree, tvb, offset, 2,
				    "%s :  Number Requests (%u)",
				    bigbuf,
				    num_req);

		offset += 2;

		oct = tvb_get_guint8(tvb, offset);

		num_rsp = oct & 0xf0;

		other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
		proto_tree_add_text(tree, tvb, offset, 1,
				    "%s :  Number Responses (%u)",
				    bigbuf,
				    num_rsp);

		offset++;
	}
	else
	{
		oct = tvb_get_guint8(tvb, offset);

		num_req = (oct & 0xf0) >> 4;
		num_rsp = oct & 0x0f;

		other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
		proto_tree_add_text(tree, tvb, offset, 1,
				    "%s :  Number Requests (%u)",
				    bigbuf,
				    num_req);

		other_decode_bitfield_value(bigbuf, oct, 0x0f, 8);
		proto_tree_add_text(tree, tvb, offset, 1,
				    "%s :  Number Responses (%u)",
				    bigbuf,
				    num_rsp);
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
	oct    = tvb_get_guint8(tvb, offset);

	other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Session Start",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x40, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Session End",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x20, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  Session Source",
			    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x1f, 8);
	proto_tree_add_uint_format(tree, hf_ansi_801_rev_sess_tag, tvb, offset,
				   1, oct & 0x1f,
				   "%s :  Session Tag (%u)",
				   bigbuf,
				   oct & 0x1f);

	hidden_item = proto_tree_add_uint(tree, hf_ansi_801_sess_tag, tvb, offset,
					  1, oct & 0x1f);
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
			str =
				"Available for manufacturer-specific Position Determination "
				"Data Message definition as specified in TSB-58";
		}
		break;
	}

	other_decode_bitfield_value(bigbuf, pd_msg_type, 0xff, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
			    "%s :  PD Message Type, %s (%u)",
			    bigbuf,
			    str,
			    pd_msg_type);

	offset++;

	if ((pd_msg_type != 0x00) &&
	    (pd_msg_type != 0x01))
	{
		proto_tree_add_text(tree, tvb, offset, -1,
				    "Reserved/Proprietary/Future Data");
		return;
	}

	if (pd_msg_type == 0x01)
	{
		value = tvb_get_ntohs(tvb, offset);

		other_decode_bitfield_value(bigbuf, value, 0xffc0, 16);
		proto_tree_add_text(tree, tvb, offset, 2,
				    "%s :  PD Message Length, (%u)",
				    bigbuf,
				    (value & 0xffc0) >> 6);

		switch ((value & 0x0030) >> 4)
		{
		case 0x00: str = "No Regulatory service"; break;
		case 0x01: str = "Emergency service"; break;
		default:   str = "Reserved"; break;
		}

		other_decode_bitfield_value(bigbuf, value, 0x0030, 16);
		proto_tree_add_text(tree, tvb, offset, 2,
				    "%s :  Regulatory Services Indicator - %s (%u)",
				    bigbuf,
				    str,
				    (value & 0x0030) >> 4);

		num_req = value & 0x000f;

		other_decode_bitfield_value(bigbuf, value, 0x000f, 16);
		proto_tree_add_text(tree, tvb, offset, 2,
				    "%s :  Number Requests (%u)",
				    bigbuf,
				    num_req);

		offset += 2;

		oct = tvb_get_guint8(tvb, offset);

		num_rsp = oct & 0xf0;

		other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
		proto_tree_add_text(tree, tvb, offset, 1,
				    "%s :  Number Responses (%u)",
				    bigbuf,
				    num_rsp);

		offset++;
	}
	else
	{
		oct = tvb_get_guint8(tvb, offset);

		num_req = (oct & 0xf0) >> 4;
		num_rsp = oct & 0x0f;

		other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
		proto_tree_add_text(tree, tvb, offset, 1,
				    "%s :  Number Requests (%u)",
				    bigbuf,
				    num_req);

		other_decode_bitfield_value(bigbuf, oct, 0x0f, 8);
		proto_tree_add_text(tree, tvb, offset, 1,
				    "%s :  Number Responses (%u)",
				    bigbuf,
				    num_rsp);

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

	g_pinfo = pinfo;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, ansi_proto_name_short);

	/* In the interest of speed, if "tree" is NULL, don't do any work not
	 * necessary to generate protocol tree items.
	 */
	if (tree)
	{
		g_tree = tree;

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
			    FT_UINT8, BASE_DEC, NULL, 0,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_rev_sess_tag,
			  { "Reverse Session Tag",		"ansi_801.rev_sess_tag",
			    FT_UINT8, BASE_DEC, NULL, 0,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_sess_tag,
			  { "Session Tag",			"ansi_801.sess_tag",
			    FT_UINT8, BASE_DEC, NULL, 0,
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
			    FT_UINT8, BASE_DEC, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_num_fixes,
			  { "Number of fixes (NUM_FIXES)", "ansi_801.num_fixes",
			    FT_UINT16, BASE_DEC, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_t_betw_fixes,
			  { "Time between fixes (T_BETW_FIXES)", "ansi_801.t_betw_fixes",
			    FT_UINT8, BASE_DEC, NULL, 0x00,
			    NULL, HFILL }
			},
			{ &hf_ansi_801_offset_req,
			  { "Offset requested (OFFSET_REQ)", "ansi_801.offset_req",
			    FT_BOOLEAN, BASE_NONE, NULL, 0x00,
			    NULL, HFILL }
			},
		};


	/* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_PARAMS	1
	gint *ett[NUM_INDIVIDUAL_PARAMS+NUM_FOR_REQ_TYPE+NUM_FOR_RSP_TYPE+NUM_REV_REQ_TYPE+NUM_REV_RSP_TYPE];

	ett[0] = &ett_ansi_801;

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
	register_dissector("ansi_801", dissect_ansi_801, proto_ansi_801);
}


void
proto_reg_handoff_ansi_801(void)
{
	dissector_handle_t ansi_801_handle;

	ansi_801_handle = create_dissector_handle(dissect_ansi_801, proto_ansi_801);

	dissector_add_uint("ansi_map.pld", ANSI_801_FORWARD, ansi_801_handle);
	dissector_add_uint("ansi_map.pld", ANSI_801_REVERSE, ansi_801_handle);
	dissector_add_uint("ansi_a.pld",   ANSI_801_FORWARD, ansi_801_handle);
	dissector_add_uint("ansi_a.pld",   ANSI_801_REVERSE, ansi_801_handle);

	data_handle = find_dissector("data");
}
