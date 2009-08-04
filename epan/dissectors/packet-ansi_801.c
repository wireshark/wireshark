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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <gmodule.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>

#include "epan/packet.h"


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

static char bigbuf[1024];
static dissector_handle_t data_handle;
static packet_info *g_pinfo;
static proto_tree *g_tree;


/* FUNCTIONS */

static const guint8 global_bit_mask[] = {
    0x01,
    0x03,
    0x07,
    0x0f,
    0x1f,
    0x3f,
    0x7f,
    0xff
};

static guint64
ansi_801_tvb_get_bits(tvbuff_t *tvb, guint32 *offset_p, guint8 *bit_offset_p, guint8 num_bits)
{
    guint64	bits;
    guint64	temp_octs;
    guint8	num_octs;
    guint8	shift_bits;
    guint8	remaining_bits;

    if (num_bits <= *bit_offset_p)
    {
	shift_bits = (*bit_offset_p) - num_bits;

	bits = (tvb_get_guint8(tvb, *offset_p) & global_bit_mask[(*bit_offset_p)-1]) >> shift_bits;

	if (shift_bits == 0)
	{
	    /* consumed everything in octet */
	    *offset_p += 1;
	}
	else
	{
	    /* consumed subset of bits available in current octet */
	    *bit_offset_p -= shift_bits;
	}

	return(bits);
    }

    shift_bits = (num_bits - *bit_offset_p);

    bits = (tvb_get_guint8(tvb, *offset_p) & global_bit_mask[(*bit_offset_p)-1]) << shift_bits;

    num_octs = (shift_bits / 8) + 1;
    remaining_bits = shift_bits % 8;

    switch (num_octs)
    {
    case 1:
	bits |= tvb_get_guint8(tvb, (*offset_p)+1) >> (8 - remaining_bits);
	break;
    case 2:
	bits |= tvb_get_ntohs(tvb, (*offset_p)+1) >> (8 - remaining_bits);
	break;
    case 3:
	bits |= tvb_get_ntoh24(tvb, (*offset_p)+1) >> (8 - remaining_bits);
	break;
    case 4:
	bits |= tvb_get_ntohl(tvb, (*offset_p)+1) >> (8 - remaining_bits);
	break;
    case 5:
	temp_octs = tvb_get_ntohl(tvb, (*offset_p)+1) << 8;
	temp_octs |= tvb_get_guint8(tvb, (*offset_p)+5);
	bits |= temp_octs >> (8 - remaining_bits);
	break;
    case 6:
	temp_octs = tvb_get_ntohl(tvb, (*offset_p)+1) << 16;
	temp_octs |= tvb_get_ntohs(tvb, (*offset_p)+5);
	bits |= temp_octs >> (8 - remaining_bits);
	break;
    case 7:
	temp_octs = tvb_get_ntohl(tvb, (*offset_p)+1) << 24;
	temp_octs |= tvb_get_ntoh24(tvb, (*offset_p)+5);
	bits |= temp_octs >> (8 - remaining_bits);
	break;
    case 8:
	bits |= tvb_get_ntoh64(tvb, (*offset_p)+1) >> (8 - remaining_bits);
	break;
    }

    *offset_p += num_octs;
    *bit_offset_p = 8 - remaining_bits;

    return(bits);
}

/* PARAM FUNCTIONS */

#define	EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
	proto_tree_add_text(tree, tvb, \
	    offset, (edc_len) - (edc_max_len), "Extraneous Data"); \
    }

#define	SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
    if ((sdc_len) < (sdc_min_len)) \
    { \
	proto_tree_add_text(tree, tvb, \
	    offset, (sdc_len), "Short Data (?)"); \
	return; \
    }

#define	EXACT_DATA_CHECK(edc_len, edc_eq_len) \
    if ((edc_len) != (edc_eq_len)) \
    { \
	proto_tree_add_text(tree, tvb, \
	    offset, (edc_len), "Unexpected Data Length"); \
	return; \
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

    other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Reserved",
	bigbuf);

    offset += 3;

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
    guint8	oct;
    guint32	saved_offset;
    const gchar	*str = NULL;
    gint	idx;

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
    guint8	oct;
    guint32	saved_offset;
    const gchar	*str = NULL;
    gint	idx;

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
    oct = tvb_get_guint8(tvb, offset);

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

    value = tvb_get_ntohl(tvb, offset);
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

    value = tvb_get_ntohs(tvb, offset);
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
static void
pr_loc_response(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    guint8	bit_mask;
    guint8	bit_offset;
    guint32	fix_type;
    guint32	value;
    guint64	temp_int;
    guint32	new_offset;
    guint32	saved_offset;
    const gchar	*str = NULL;

    saved_offset = offset;

    SHORT_DATA_CHECK(len, 11);

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xfffc, 16);
    proto_tree_add_text(tree, tvb, offset, 2,
	"%s :  TIME_REF_CDMA: CDMA system time at the time the solution is valid.",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x0003, 16);
    proto_tree_add_text(tree, tvb, offset, 2,
	"%s :  LAT (MSB)",
	bigbuf);

    offset += 2;
    value = tvb_get_ntoh24(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xfffffe, 24);
    proto_tree_add_text(tree, tvb, offset, 3,
	"%s :  LAT (LSB)",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x000001, 24);
    proto_tree_add_text(tree, tvb, offset, 3,
	"%s :  LONG (MSB)",
	bigbuf);

    offset += 3;
    value = tvb_get_ntoh24(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xffffff, 24);
    proto_tree_add_text(tree, tvb, offset, 3,
	"%s :  LONG",
	bigbuf);

    offset += 3;
    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x8000, 16);
    proto_tree_add_text(tree, tvb, offset, 2,
	"%s :  LONG (LSB)",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x7800, 16);
    proto_tree_add_text(tree, tvb, offset, 2,
	"%s :  LOC_UNCRTNTY_ANG",
	bigbuf);

    switch ((value & 0x07c0) >> 6)
    {
    case 0x00: str = "0.5"; break;
    case 0x01: str = "0.75"; break;
    case 0x02: str = "1"; break;
    case 0x03: str = "1.5"; break;
    case 0x04: str = "2"; break;
    case 0x05: str = "3"; break;
    case 0x06: str = "4"; break;
    case 0x07: str = "6"; break;
    case 0x08: str = "8"; break;
    case 0x09: str = "12"; break;
    case 0x0a: str = "16"; break;
    case 0x0b: str = "24"; break;
    case 0x0c: str = "32"; break;
    case 0x0d: str = "48"; break;
    case 0x0e: str = "64"; break;
    case 0x0f: str = "96"; break;
    case 0x10: str = "128"; break;
    case 0x11: str = "192"; break;
    case 0x12: str = "256"; break;
    case 0x13: str = "384"; break;
    case 0x14: str = "512"; break;
    case 0x15: str = "768"; break;
    case 0x16: str = "1,024"; break;
    case 0x17: str = "1,536"; break;
    case 0x18: str = "2,048"; break;
    case 0x19: str = "3,072"; break;
    case 0x1a: str = "4,096"; break;
    case 0x1b: str = "6,144"; break;
    case 0x1c: str = "8,192"; break;
    case 0x1d: str = "12,288"; break;
    case 0x1e: str = ">12,288"; break;
    case 0x1f: str = "Not computable"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x07c0, 16);
    proto_tree_add_text(tree, tvb, offset, 2,
	"%s :  LOC_UNCRTNTY_A: Standard deviation of axis along angle specified for position uncertainty (meters): %s",
	bigbuf,
	str);

    switch ((value & 0x003e) >> 1)
    {
    case 0x00: str = "0.5"; break;
    case 0x01: str = "0.75"; break;
    case 0x02: str = "1"; break;
    case 0x03: str = "1.5"; break;
    case 0x04: str = "2"; break;
    case 0x05: str = "3"; break;
    case 0x06: str = "4"; break;
    case 0x07: str = "6"; break;
    case 0x08: str = "8"; break;
    case 0x09: str = "12"; break;
    case 0x0a: str = "16"; break;
    case 0x0b: str = "24"; break;
    case 0x0c: str = "32"; break;
    case 0x0d: str = "48"; break;
    case 0x0e: str = "64"; break;
    case 0x0f: str = "96"; break;
    case 0x10: str = "128"; break;
    case 0x11: str = "192"; break;
    case 0x12: str = "256"; break;
    case 0x13: str = "384"; break;
    case 0x14: str = "512"; break;
    case 0x15: str = "768"; break;
    case 0x16: str = "1,024"; break;
    case 0x17: str = "1,536"; break;
    case 0x18: str = "2,048"; break;
    case 0x19: str = "3,072"; break;
    case 0x1a: str = "4,096"; break;
    case 0x1b: str = "6,144"; break;
    case 0x1c: str = "8,192"; break;
    case 0x1d: str = "12,288"; break;
    case 0x1e: str = ">12,288"; break;
    case 0x1f: str = "Not computable"; break;
    }

    other_decode_bitfield_value(bigbuf, value, 0x003e, 16);
    proto_tree_add_text(tree, tvb, offset, 2,
	"%s :  LOC_UNCRTNTY_P: Standard deviation of axis perpendicular to angle specified for position uncertainty (meters): %s",
	bigbuf,
	str);

    fix_type = value & 0x0001;

    other_decode_bitfield_value(bigbuf, value, 0x0001, 16);
    proto_tree_add_text(tree, tvb, offset, 2,
	"%s :  FIX_TYPE: %s",
	bigbuf,
	fix_type ? "3D" : "2D");

    offset += 2;
    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  VELOCITY_INCL: Velocity information %sincluded",
	bigbuf,
	(oct & 0x80) ? "" : "not ");

    if (oct & 0x80)
    {
	value = (oct & 0x7f) << 2;

	other_decode_bitfield_value(bigbuf, oct, 0x7f, 8);

	offset++;
	oct = tvb_get_guint8(tvb, offset);
	value |= ((oct & 0xc0) >> 6);

	proto_tree_add_text(tree, tvb, offset-1, 1,
	    "%s :  VELOCITY_HOR: Horizontal velocity magnitude (MSB) (%u)",
	    bigbuf,
	    value);

	other_decode_bitfield_value(bigbuf, oct, 0xc0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s :  VELOCITY_HOR: Horizontal velocity magnitude (LSB)",
	    bigbuf);

	value = (oct & 0x3f) << 4;

	other_decode_bitfield_value(bigbuf, oct, 0x3f, 8);

	offset++;
	oct = tvb_get_guint8(tvb, offset);
	value |= ((oct & 0xf0) >> 4);

	proto_tree_add_text(tree, tvb, offset-1, 1,
	    "%s :  HEADING: (MSB) (%u)",
	    bigbuf,
	    value);

	other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s :  HEADING: (LSB)",
	    bigbuf);

	if (fix_type)
	{
	    value = (oct & 0x0f) << 4;

	    other_decode_bitfield_value(bigbuf, oct, 0x0f, 8);

	    offset++;
	    oct = tvb_get_guint8(tvb, offset);
	    value |= ((oct & 0xf0) >> 4);

	    proto_tree_add_text(tree, tvb, offset-1, 1,
		"%s :  VELOCITY_VER: Vertical velocity magnitude (MSB) (%u)",
		bigbuf,
		value);

	    other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
	    proto_tree_add_text(tree, tvb, offset, 1,
		"%s :  VELOCITY_VER: Vertical velocity magnitude (LSB)",
		bigbuf);
	}

	/*
	 * in either case (fix_type) we have the low 4 bits
	 * left over from the octet pointed to by 'offset'
	 */
	bit_mask = 0x08;
	bit_offset = 3;
    }
    else
    {
	/*
	 * no code here just co-located comments for bit mask
	 */
	bit_mask = 0x40;
	bit_offset = 6;
    }

    other_decode_bitfield_value(bigbuf, oct, bit_mask, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  CLOCK_INCL: Clock information %sincluded",
	bigbuf,
	(oct & bit_mask) ? "" : "not ");

    if (oct & bit_mask)
    {
	new_offset = offset;
	temp_int = ansi_801_tvb_get_bits(tvb, &new_offset, &bit_offset, 18);

	proto_tree_add_text(tree, tvb, offset, new_offset - offset,
	    "CLOCK_BIAS: (%" G_GINT64_MODIFIER "u)", temp_int);

	offset = new_offset;
	temp_int = ansi_801_tvb_get_bits(tvb, &new_offset, &bit_offset, 16);

	proto_tree_add_text(tree, tvb, offset, new_offset - offset,
	    "CLOCK_DRIFT: (%" G_GINT64_MODIFIER "u)", temp_int);

	offset = new_offset;
	bit_mask = 0x80 >> (8 - bit_offset);
	oct = tvb_get_guint8(tvb, offset);

#ifdef MLUM
	other_decode_bitfield_value(bigbuf, value, bit_mask, 16);
	proto_tree_add_text(tree, tvb, offset, 2,
	    "%s :  CLOCK_BIAS: (LSB)",
	    bigbuf);

	if (bit_offset - (18 - 16) > 0)
	{
	    bit_offset -= (18 - 16);
	}
	else
	{
	    bit_offset = 8 + (bit_offset - (18 - 16));
	}

	bit_mask = (0xff << (8 - bit_offset));
	bit_mask >>= (8 - bit_offset);

	temp_int = (value & (guint32) bit_mask) << (16 - bit_offset);

	other_decode_bitfield_value(bigbuf, value, bit_mask, 8);

	offset += 2;
	value = tvb_get_ntohs(tvb, offset);

	bit_mask = (0xffff << (16 - (18 - bit_offset)));
	temp_int |= ((value & bit_mask) >> (16 - (18 - bit_offset)));

	proto_tree_add_text(tree, tvb, offset-1, 1,
	    "%s :  CLOCK_DRIFT: (MSB) (%" G_GINT64_MODIFIER "u)",
	    bigbuf,
	    temp_int);

	other_decode_bitfield_value(bigbuf, value, bit_mask, 16);
	proto_tree_add_text(tree, tvb, offset, 2,
	    "%s :  CLOCK_DRIFT: (LSB)",
	    bigbuf);

	if (bit_offset - 2 > 0)
	{
	    bit_offset -= 2;
	}
	else
	{
	    bit_offset = 8 + (bit_offset - 2);
	}

	/* NOT FINISHED */
#endif
    }
    else
    {
	/*
	 * no code here just co-located comments for bit mask
	 */
	bit_mask >>= 1;
	bit_offset--;
    }

    other_decode_bitfield_value(bigbuf, oct, bit_mask, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  HEIGHT_INCL: Height information %sincluded",
	bigbuf,
	(oct & bit_mask) ? "" : "not ");

    if (oct & bit_mask)
    {
	new_offset = offset;
	temp_int = ansi_801_tvb_get_bits(tvb, &new_offset, &bit_offset, 14);

	proto_tree_add_text(tree, tvb, offset, new_offset - offset,
	    "HEIGHT: (%" G_GINT64_MODIFIER "u)", temp_int);

	offset = new_offset;
	temp_int = ansi_801_tvb_get_bits(tvb, &new_offset, &bit_offset, 5);

	proto_tree_add_text(tree, tvb, offset, new_offset - offset,
	    "LOC_UNCRTNTY_V: (%" G_GINT64_MODIFIER "u)", temp_int);

	offset = new_offset;
	bit_mask = 0x80 >> (8 - bit_offset);
	oct = tvb_get_guint8(tvb, offset);

#ifdef MLUM
	/* NOT FINISHED */
#endif
    }
    else
    {
	/*
	 * no code here just co-located comments for bit mask
	 */
	bit_mask >>= 1;
	bit_offset--;
    }

    bit_mask = 0xff >> (8 - bit_offset);
    other_decode_bitfield_value(bigbuf, oct, bit_mask, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Reserved",
	bigbuf);

    offset++;

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
    guint8	oct;
    guint8	num_bad;
    guint8	i;
    guint8	bit_mask;
    guint8	bit_offset;
    guint32	new_offset;
    guint32	saved_offset;
    guint64	temp_int;

    saved_offset = offset;

    SHORT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  BAD_SV_PRESENT: Bad GPS satellites present",
	bigbuf);

    if (oct & 0x80)
    {
	num_bad = (oct & 0x78) >> 3;

	other_decode_bitfield_value(bigbuf, oct, 0x78, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s :  NUM_BAD_SV: The number of bad GPS satellites: (%u)",
	    bigbuf,
	    num_bad);

	bit_offset = 3;
	new_offset = offset;

	for (i=0; i < num_bad; i++)
	{
	    temp_int = ansi_801_tvb_get_bits(tvb, &new_offset, &bit_offset, 5);

	    proto_tree_add_text(tree, tvb, offset, 1,
		"BAD_SV_PRN_NUM: (%" G_GINT64_MODIFIER "u)", temp_int);

	    offset = new_offset;
	}

	bit_mask = 0xff >> (8 - bit_offset);
	oct = tvb_get_guint8(tvb, offset);
    }
    else
    {
	bit_mask = 0x7f;
    }

    if (bit_mask != 0x00)
    {
	other_decode_bitfield_value(bigbuf, oct, bit_mask, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s :  Reserved",
	    bigbuf);

	offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_req_gps_acq_ass(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    guint32	saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Doppler (0th order) term %srequested",
	bigbuf,
	(oct & 0x80) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, oct, 0x40, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Additional Doppler terms %srequested",
	bigbuf,
	(oct & 0x40) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, oct, 0x20, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Code phase parameters %srequested",
	bigbuf,
	(oct & 0x20) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, oct, 0x10, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Azimuth and elevation angle %srequested",
	bigbuf,
	(oct & 0x10) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Reserved",
	bigbuf);

    offset++;

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
rev_req_gps_loc_ass(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    guint32	saved_offset;

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
    guint8	oct;
    guint32	saved_offset;

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
    guint8	oct;
    guint32	saved_offset;

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
    guint8	oct;
    guint32	saved_offset;

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
    guint8	oct;
    guint32	saved_offset;

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
    guint8	oct;
    guint32	saved_offset;
    const gchar	*str = NULL;
    gint	idx;

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
    guint32	value;
    guint32	saved_offset;
    const gchar	*str = NULL;

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
    guint8	oct;
    guint32	saved_offset;
    const gchar	*str = NULL;
    gint	idx;

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
    NULL,	/* Reserved */
    NULL, /* no data */	/* Request MS Information */
    NULL, /* no data */	/* Request Autonomous Measurement Weighting Factors */
    for_req_pseudo_meas,	/* Request Pseudorange Measurement */
    for_req_pilot_ph_meas,	/* Request Pilot Phase Measurement */
    for_req_loc_response,	/* Request Location Response */
    for_req_time_off_meas,	/* Request Time Offset Measurement */
    for_req_cancel,	/* Request Cancellation */
    NULL,	/* NONE */
};

static void (*for_rsp_type_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    for_reject,	/* Reject */
    for_pr_bs_cap,	/* Provide BS Capabilities */
    NULL,	/* Provide GPS Acquisition Assistance */
    NULL,	/* Provide GPS Location Assistance Spherical Coordinates */
    NULL,	/* Provide GPS Location Assistance Cartesian Coordinates */
    for_pr_gps_sense_ass,	/* Provide GPS Sensitivity Assistance */
    NULL,	/* Provide Base Station Almanac */
    for_pr_gps_almanac,	/* Provide GPS Almanac */
    NULL,	/* Provide GPS Ephemeris */
    for_pr_gps_nav_msg_bits,	/* Provide GPS Navigation Message Bits */
    for_pr_loc_response,	/* Provide Location Response */
    NULL,	/* Provide GPS Almanac Correction */
    for_pr_gps_sat_health,	/* Provide GPS Satellite Health Information */
    NULL,	/* NONE */
};

static void (*rev_req_type_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    NULL,	/* Reserved */
    NULL, /* no data */	/* Request BS Capabilities */
    rev_req_gps_acq_ass,	/* Request GPS Acquisition Assistance */
    rev_req_gps_loc_ass,	/* Request GPS Location Assistance */
    NULL,	/* Reserved */
    NULL, /* no data */	/* Request GPS Sensitivity Assistance */
    rev_req_bs_alm,	/* Request Base Station Almanac */
    NULL, /* no data */	/* Request GPS Almanac */
    rev_req_gps_ephemeris,	/* Request GPS Ephemeris */
    rev_req_gps_nav_msg_bits,	/* Request GPS Navigation Message Bits */
    rev_req_loc_response,	/* Request Location Response */
    rev_req_gps_alm_correction,	/* Request GPS Almanac Correction */
    NULL, /* no data */	/* Request GPS Satellite Health Information */
    NULL,	/* NONE */
};

static void (*rev_rsp_type_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    rev_reject,	/* Reject */
    rev_pr_ms_information,	/* Provide MS Information */
    NULL,	/* Provide Autonomous Measurement Weighting Factors */
    NULL,	/* Provide Pseudorange Measurement */
    NULL,	/* Provide Pilot Phase Measurement */
    rev_pr_loc_response,	/* Provide Location Response */
    rev_pr_time_off_meas,	/* Provide Time Offset Measurement */
    rev_pr_can_ack,	/* Provide Cancellation Acknowledgement */
    NULL,	/* NONE */
};

static void
for_request(tvbuff_t *tvb, proto_tree *tree, guint32 *offset_p, guint8 pd_msg_type)
{
    guint32	offset;
    guint8	oct;
    const gchar	*str = NULL;
    gint	idx;
    proto_tree	*subtree;
    proto_item	*item;

    offset = *offset_p;
    oct = tvb_get_guint8(tvb, offset);

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
    guint32	offset;
    guint8	oct;
    const gchar	*str = NULL;
    gint	idx;
    proto_tree	*subtree;
    proto_item	*item;

    offset = *offset_p;
    oct = tvb_get_guint8(tvb, offset);

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
    guint32	offset;
    guint8	oct;
    const gchar	*str = NULL;
    gint	idx;
    proto_tree	*subtree;
    proto_item	*item;

    offset = *offset_p;
    oct = tvb_get_guint8(tvb, offset);

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
    guint32	offset;
    guint8	oct;
    const gchar	*str = NULL;
    gint	idx;
    proto_tree	*subtree;
    proto_item	*item;

    offset = *offset_p;
    oct = tvb_get_guint8(tvb, offset);

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
    guint32	value;
    guint32	offset;
    guint8	oct, num_req, num_rsp, pd_msg_type;
    guint	rem_len;
    const gchar	*str = NULL;
	proto_item *hidden_item;

    offset = 0;
    oct = tvb_get_guint8(tvb, offset);

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
    guint32	value;
    guint32	offset;
    guint8	oct, num_req, num_rsp, pd_msg_type;
    guint	rem_len;
    const gchar	*str = NULL;
	proto_item *hidden_item;

    offset = 0;
    oct = tvb_get_guint8(tvb, offset);

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
    proto_item	*ansi_801_item;
    proto_tree	*ansi_801_tree = NULL;

    g_pinfo = pinfo;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, ansi_proto_name_short);
    }

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
		(pinfo->match_port == ANSI_801_FORWARD) ? "Forward" : "Reverse");

	ansi_801_tree =
	    proto_item_add_subtree(ansi_801_item, ett_ansi_801);

	if (pinfo->match_port == ANSI_801_FORWARD)
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
    guint		i;
    gint		last_offset;

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
}


void
proto_reg_handoff_ansi_801(void)
{
    dissector_handle_t	ansi_801_handle;

    ansi_801_handle = create_dissector_handle(dissect_ansi_801, proto_ansi_801);

    dissector_add("ansi_map.pld", ANSI_801_FORWARD, ansi_801_handle);
    dissector_add("ansi_map.pld", ANSI_801_REVERSE, ansi_801_handle);
    dissector_add("ansi_a.pld", ANSI_801_FORWARD, ansi_801_handle);
    dissector_add("ansi_a.pld", ANSI_801_REVERSE, ansi_801_handle);

    data_handle = find_dissector("data");
}
