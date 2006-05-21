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
static void (*for_req_type_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    NULL,	/* Reserved */
    NULL,	/* Request MS Information */
    NULL,	/* Request Autonomous Measurement Weighting Factors */
    for_req_pseudo_meas,	/* Request Pseudorange Measurement */
    NULL,	/* Request Pilot Phase Measurement */
    NULL,	/* Request Location Response */
    NULL,	/* Request Time Offset Measurement */
    NULL,	/* Request Cancellation */
    NULL,	/* NONE */
};

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
static void (*for_rsp_type_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    NULL,	/* Reject */
    NULL,	/* Provide BS Capabilities */
    NULL,	/* Provide GPS Acquisition Assistance */
    NULL,	/* Provide GPS Location Assistance Spherical Coordinates */
    NULL,	/* Provide GPS Location Assistance Cartesian Coordinates */
    NULL,	/* Provide GPS Sensitivity Assistance */
    NULL,	/* Provide Base Station Almanac */
    NULL,	/* Provide GPS Almanac */
    NULL,	/* Provide GPS Ephemeris */
    NULL,	/* Provide GPS Navigation Message Bits */
    NULL,	/* Provide Location Response */
    NULL,	/* Provide GPS Almanac Correction */
    NULL,	/* Provide GPS Satellite Health Information */
    NULL,	/* NONE */
};

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
static void (*rev_req_type_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    NULL,	/* Reserved */
    NULL,	/* Request BS Capabilities */
    NULL,	/* Request GPS Acquisition Assistance */
    NULL,	/* Request GPS Location Assistance */
    NULL,	/* Reserved */
    NULL,	/* Request GPS Sensitivity Assistance */
    NULL,	/* Request Base Station Almanac */
    NULL,	/* Request GPS Almanac */
    NULL,	/* Request GPS Ephemeris */
    NULL,	/* Request GPS Navigation Message Bits */
    NULL,	/* Request Location Response */
    NULL,	/* Request GPS Almanac Correction */
    NULL,	/* Request GPS Satellite Health Information */
    NULL,	/* NONE */
};

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
static void (*rev_rsp_type_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    NULL,	/* Reject */
    NULL,	/* Provide MS Information */
    NULL,	/* Provide Autonomous Measurement Weighting Factors */
    NULL,	/* Provide Pseudorange Measurement */
    NULL,	/* Provide Pilot Phase Measurement */
    NULL,	/* Provide Location Response */
    NULL,	/* Provide Time Offset Measurement */
    NULL,	/* Provide Cancellation Acknowledgement */
    NULL,	/* NONE */
};

static void
for_request(tvbuff_t *tvb, proto_tree *tree, guint32 *offset_p)
{
    guint32	offset;
    guint8	oct;
    const gchar	*str = NULL;
    gint	idx;
    proto_tree	*subtree;
    proto_item	*item;

    offset = *offset_p;
    oct = tvb_get_guint8(tvb, offset);

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

    subtree = proto_item_add_subtree(item, ett_for_req_type[idx]);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(subtree, tvb, offset, 1,
	"Length: %u",
	oct);

    offset++;

    if (for_req_type_fcn[idx] != NULL)
    {
	(*for_req_type_fcn[idx])(tvb, subtree, oct, offset);
    }
    else
    {
	proto_tree_add_text(subtree, tvb, offset, oct,
	    "Data");
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
rev_request(tvbuff_t *tvb, proto_tree *tree, guint32 *offset_p)
{
    guint32	offset;
    guint8	oct;
    const gchar	*str = NULL;
    gint	idx;
    proto_tree	*subtree;
    proto_item	*item;

    offset = *offset_p;
    oct = tvb_get_guint8(tvb, offset);

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
    guint32	offset;
    guint8	oct, num_req, num_rsp;
    guint	rem_len;
    const gchar	*str = NULL;

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

    proto_tree_add_uint_hidden(tree, hf_ansi_801_sess_tag, tvb, offset,
	1, oct & 0x1f);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    switch (oct)
    {
    case 0x00: str = "Position Determination Data Message"; break;
    case 0xff: str = "Reserved"; break;
    default:
	if (oct < 0xc0)
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

    other_decode_bitfield_value(bigbuf, oct, 0xff, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  PD Message Type, %s (%u)",
	bigbuf,
	str,
	oct);

    offset++;

    if (oct == 0x00)
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
	rem_len = tvb_length_remaining(tvb, offset);

	while ((num_req > 0) &&
	    (rem_len >= 2))
	{
	    for_request(tvb, tree, &offset);

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
    else
    {
	proto_tree_add_text(tree, tvb, offset, -1,
	    "Reserved/Proprietary/Future Data");
    }
}

static void
dissect_ansi_801_rev_message(tvbuff_t *tvb, proto_tree *tree)
{
    guint32	offset;
    guint8	oct, num_req, num_rsp;
    guint	rem_len;
    const gchar	*str = NULL;

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

    proto_tree_add_uint_hidden(tree, hf_ansi_801_sess_tag, tvb, offset,
	1, oct & 0x1f);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    switch (oct)
    {
    case 0x00: str = "Position Determination Data Message"; break;
    case 0xff: str = "Reserved"; break;
    default:
	if (oct < 0xc0)
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

    other_decode_bitfield_value(bigbuf, oct, 0xff, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  PD Message Type, %s (%u)",
	bigbuf,
	str,
	oct);

    offset++;

    if (oct == 0x00)
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
	rem_len = tvb_length_remaining(tvb, offset);

	while ((num_req > 0) &&
	    (rem_len >= 2))
	{
	    rev_request(tvb, tree, &offset);

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
    else
    {
	proto_tree_add_text(tree, tvb, offset, -1,
	    "Reserved/Proprietary/Future Data");
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
	    "", HFILL }
	},
	{ &hf_ansi_801_for_rsp_type,
	    { "Forward Response Type",		"ansi_801.for_rsp_type",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_ansi_801_rev_req_type,
	    { "Reverse Request Type",		"ansi_801.rev_req_type",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_ansi_801_rev_rsp_type,
	    { "Reverse Response Type",		"ansi_801.rev_rsp_type",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_ansi_801_for_sess_tag,
	    { "Forward Session Tag",		"ansi_801.for_sess_tag",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_ansi_801_rev_sess_tag,
	    { "Reverse Session Tag",		"ansi_801.rev_sess_tag",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_ansi_801_sess_tag,
	    { "Session Tag",			"ansi_801.sess_tag",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
    };

    /* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_PARAMS	1
    gint *ett[NUM_INDIVIDUAL_PARAMS+NUM_FOR_REQ_TYPE+NUM_FOR_RSP_TYPE+NUM_REV_REQ_TYPE+NUM_REV_RSP_TYPE];

    ett[0] = &ett_ansi_801;

    last_offset = NUM_INDIVIDUAL_PARAMS;

    for (i=0; i < NUM_FOR_REQ_TYPE; i++, last_offset++)
    {
	ett[last_offset] = &ett_for_req_type[i];
    }

    for (i=0; i < NUM_FOR_RSP_TYPE; i++, last_offset++)
    {
	ett[last_offset] = &ett_for_rsp_type[i];
    }

    for (i=0; i < NUM_REV_REQ_TYPE; i++, last_offset++)
    {
	ett[last_offset] = &ett_rev_req_type[i];
    }

    for (i=0; i < NUM_REV_RSP_TYPE; i++, last_offset++)
    {
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
