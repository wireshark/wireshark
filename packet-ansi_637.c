/* packet-ansi_637.c
 * Routines for ANSI IS-637-A (SMS) dissection
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Title		3GPP2			Other
 *
 *   Short Message Service
 *			3GPP2 C.S0015-0		TIA/EIA-637-A
 *
 * $Id: packet-ansi_637.c,v 1.1 2003/10/06 19:25:20 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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


static char *ansi_proto_name = "ANSI IS-637-A (SMS)";
static char *ansi_proto_name_short = "IS-637-A";

static const value_string ansi_msg_type_strings[] = {
    { 1,	"Deliver (mobile-terminated only)" },
    { 2,	"Submit (mobile-originated only)" },
    { 3,	"Cancellation (mobile-originated only)" },
    { 4,	"Delivery Acknowledgement (mobile-terminated only)" },
    { 5,	"User Acknowledgement (either direction)" },
    { 0, NULL },
};

static const value_string ansi_tele_strings[] = {
    { 1,	"Reserved for maintenance" },
    { 4096,	"AMPS Extended Protocol Enhanced Services" },
    { 4097,	"CDMA Cellular Paging Teleservice" },
    { 4098,	"CDMA Cellular Messaging Teleservice" },
    { 4099,	"CDMA Voice Mail Notification" },
    { 32513,	"TDMA Cellular Messaging Teleservice" },
    { 32520,	"TDMA System Assisted Mobile Positioning through Satellite (SAMPS)" },
    { 32584,	"TDMA Segmented System Assisted Mobile Positioning Service" },
    { 0, NULL },
};

static const value_string ansi_param_strings[] = {
    { 0x00,	"Message Identifier" },
    { 0x01,	"User Data" },
    { 0x02,	"User Response Code" },
    { 0x03,	"Message Center Time Stamp" },
    { 0x04,	"Validity Period - Absolute" },
    { 0x05,	"Validity Period - Relative" },
    { 0x06,	"Deferred Delivery Time - Absolute" },
    { 0x07,	"Deferred Delivery Time - Relative" },
    { 0x08,	"Priority Indicator" },
    { 0x09,	"Privacy Indicator" },
    { 0x0a,	"Reply Option" },
    { 0x0b,	"Number of Messages" },
    { 0x0c,	"Alert on Message Delivery" },
    { 0x0d,	"Language Indicator" },
    { 0x0e,	"Call-Back Number" },
    { 0x0f,	"Message Display Mode" },
    { 0x10,	"Multiple Encoding User Data" },
    { 0, NULL },
};

/* Initialize the protocol and registered fields */
static int proto_ansi_637 = -1;
static int hf_ansi_637_none = -1;
static int hf_ansi_637_msg_type = -1;
static int hf_ansi_637_msg_id = -1;
static int hf_ansi_637_msg_junk = -1;
static int hf_ansi_637_length = -1;
static int hf_ansi_637_subparam_id = -1;

/* Initialize the subtree pointers */
static gint ett_ansi_637 = -1;
static gint ett_params = -1;

static char bigbuf[1024];
static dissector_handle_t data_handle;

/* FUNCTIONS */

static void
decode_7_bits(tvbuff_t *tvb, guint32 *offset, guint8 num_fields, guint8 *last_oct, guint8 *last_bit, gchar *buf)
{
    guint8	oct, oct2, bit;
    guint32	saved_offset;
    guint32	i;


    if (num_fields == 0)
    {
	return;
    }

    saved_offset = *offset;
    oct = oct2 = *last_oct;
    bit = *last_bit;

    if (bit == 1)
    {
	oct2 = tvb_get_guint8(tvb, *offset);
	(*offset)++;
    }

    for (i=0; i < num_fields; i++)
    {
	if (bit != 1)
	{
	    oct = oct2;

	    /*
	     * cannot grab an octet if we are getting
	     * the last field and bit is 7 or 8
	     * because there may not be another octet
	     */
	    if (((i + 1) != num_fields) ||
		((bit != 7) && (bit != 8)))
	    {
		oct2 = tvb_get_guint8(tvb, *offset);
		(*offset)++;
	    }
	}

	switch (bit)
	{
	case 1:
	    buf[i] = ((oct & 0x01) << 6) | ((oct2 & 0xfc) >> 2);
	    break;

	case 2:
	    buf[i] = ((oct & 0x03) << 5) | ((oct2 & 0xf8) >> 3);
	    break;

	case 3:
	    buf[i] = ((oct & 0x07) << 4) | ((oct2 & 0xf0) >> 4);
	    break;

	case 4:
	    buf[i] = ((oct & 0x0f) << 3) | ((oct2 & 0xe0) >> 5);
	    break;

	case 5:
	    buf[i] = ((oct & 0x1f) << 2) | ((oct2 & 0xc0) >> 6);
	    break;

	case 6:
	    buf[i] = ((oct & 0x3f) << 1) | ((oct2 & 0x80) >> 7);
	    break;

	case 7:
	    buf[i] = oct & 0x7f;
	    break;

	case 8:
	    buf[i] = (oct & 0xfe) >> 1;
	    break;
	}

	bit = (bit % 8) + 1;
    }

    buf[i] = '\0';
    *last_bit = bit;
    *last_oct = (bit == 1) ? oct : oct2;
}

/* Generate, into "buf", a string showing the bits of a bitfield.
 * Return a pointer to the character after that string.
 */
static char *
my_decode_bitfield_value(char *buf, guint32 val, guint32 mask, int width)
{
    int		i;
    guint32	bit;
    char	*p;

    i = 0;
    p = buf;
    bit = 1 << (width - 1);

    for (;;)
    {
	if (mask & bit)
	{
	    /* This bit is part of the field.  Show its value. */
	    if (val & bit)
	    {
		*p++ = '1';
	    }
	    else
	    {
		*p++ = '0';
	    }
	}
	else
	{
	    /* This bit is not part of the field. */
	    *p++ = '.';
	}

	bit >>= 1;
	i++;

	if (i >= width) break;

	if (i % 4 == 0) *p++ = ' ';
    }

    *p = '\0';

    return(p);
}

static gchar *
my_match_strval(guint32 val, const value_string *vs, gint *idx)
{
    gint i = 0;

    while (vs[i].strptr)
    {
	if (vs[i].value == val)
	{
	    *idx = i;
	    return(vs[i].strptr);
	}

	i++;
    }

    *idx = -1;
    return(NULL);
}


/* PARAM FUNCTIONS */

#define	EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
	proto_tree_add_none_format(tree, hf_ansi_637_none, tvb, \
	    offset, (edc_len) - (edc_max_len), "Extraneous Data"); \
    }

#define	SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
    if ((sdc_len) < (sdc_min_len)) \
    { \
	proto_tree_add_none_format(tree, hf_ansi_637_none, tvb, \
	    offset, (sdc_len), "Short Data (?)"); \
	return; \
    }

#define	EXACT_DATA_CHECK(edc_len, edc_eq_len) \
    if ((edc_len) != (edc_eq_len)) \
    { \
	proto_tree_add_none_format(tree, hf_ansi_637_none, tvb, \
	    offset, (edc_len), "Unexpected Data Length"); \
	return; \
    }

static void
param_user_data(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, oct2;
    guint8	encoding;
    guint8	msg_type;
    guint8	num_fields;
    guint8	used;
    guint8	bit;
    guint32	required_octs;
    guint32	saved_offset;
    guint32	i;
    gchar	*str = NULL;

    SHORT_DATA_CHECK(len, 2);

    /*
     * message encoding
     */
    oct = tvb_get_guint8(tvb, offset);
    oct2 = 0;
    msg_type = 0;
    used = 0;

    encoding = ((oct & 0xf8) >> 3);
    switch (encoding)
    {
    case 0x00: str = "Octet, unspecified"; break;
    case 0x01: str = "Extended Protocol Message";
	oct2 = tvb_get_guint8(tvb, offset+1);
	msg_type = ((oct & 0x07) << 5) | ((oct2 & 0xf8) >> 3);
	break;
    case 0x02: str = "7-bit ASCII"; break;
    case 0x03: str = "IA5"; break;
    case 0x04: str = "UNICODE"; break;
    case 0x05: str = "Shift-JIS"; break;
    case 0x06: str = "Korean"; break;
    case 0x07: str = "Latin/Hebrew"; break;
    case 0x08: str = "Latin"; break;
    case 0x09: str = "GSM 7-bit default alphabet"; break;
    default: str = "Reserved"; break;
    }

    my_decode_bitfield_value(bigbuf, oct, 0xf8, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  Encoding, %s",
	bigbuf,
	str);

    if (encoding == 0x01)
    {
	my_decode_bitfield_value(bigbuf, oct, 0x07, 8);
	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, offset, 1,
	    "%s :  Message type, see TIA/EIA/IS-91 (%d)",
	    bigbuf,
	    msg_type);

	my_decode_bitfield_value(bigbuf, oct2, 0xf8, 8);
	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, offset+1, 1,
	    "%s :  Message type",
	    bigbuf);

	oct = oct2;
	offset++;
	used++;
    }

    offset++;
    used++;

    /*
     * number of fields
     */
    oct2 = tvb_get_guint8(tvb, offset);
    num_fields = ((oct & 0x07) << 5) | ((oct2 & 0xf8) >> 3);

    my_decode_bitfield_value(bigbuf, oct, 0x07, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset-1, 1,
	"%s :  Number of fields (%d)",
	bigbuf,
	num_fields);

    my_decode_bitfield_value(bigbuf, oct2, 0xf8, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  Number of fields",
	bigbuf);

    my_decode_bitfield_value(bigbuf, oct2, 0x07, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  Most significant bits of first field",
	bigbuf);

    offset++;
    used++;
    oct = oct2;

    /* NOTE: there are now 3 bits remaining in 'oct' */

    if (len - used <= 0) return;

    /*
     * decode rest if 7-bit ASCII
     */
    if (encoding == 0x02)
    {
	/*
	 * magic numbers:
	 *	3 bits remaining from last octet
	 *	7 bit encoding
	 *	8 bits per octet
	 */
	i = (num_fields * 7) - 3;
	required_octs = (i / 8) + ((i % 8) ? 1 : 0);

	if (required_octs + used > len)
	{
	    proto_tree_add_none_format(tree, hf_ansi_637_none,
		tvb, offset, 1,
		"Missing %d octet(s) for number of fields",
		(required_octs + used) - len);

	    return;
	}

	bit = 3;
	saved_offset = offset;

	decode_7_bits(tvb, &offset, num_fields, &oct, &bit, bigbuf);

	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, saved_offset, offset - saved_offset,
	    "Encoded user data, %s",
	    bigbuf);

	switch (bit)
	{
	case 1: oct2 = 0x01; break;
	case 2: oct2 = 0x03; break;
	case 3: oct2 = 0x07; break;
	case 4: oct2 = 0x0f; break;
	case 5: oct2 = 0x1f; break;
	case 6: oct2 = 0x3f; break;
	case 7: oct2 = 0x7f; break;
	}

	if (bit != 8)
	{
	    my_decode_bitfield_value(bigbuf, oct, oct2, 8);
	    proto_tree_add_none_format(tree, hf_ansi_637_none,
		tvb, offset - 1, 1,
		"%s :  Reserved",
		bigbuf);
	}
    }
    else
    {
	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, offset, len - used,
	    "Encoded user data");
    }
}

static void
param_rsp_code(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;

    EXACT_DATA_CHECK(len, 1);

    /*
     * response code
     */
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"Response code (%d)",
	oct);
}

static void
param_timestamp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, oct2, oct3;

    EXACT_DATA_CHECK(len, 6);

    oct = tvb_get_guint8(tvb, offset);
    oct2 = tvb_get_guint8(tvb, offset+1);
    oct3 = tvb_get_guint8(tvb, offset+2);

    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 3,
	"Year %d%d, Month %d%d, Day %d%d",
	(oct & 0xf0) >> 4,
	oct & 0x0f,
	(oct2 & 0xf0) >> 4,
	oct2 & 0x0f,
	(oct3 & 0xf0) >> 4,
	oct3 & 0x0f);

    offset += 3;

    oct = tvb_get_guint8(tvb, offset);
    oct2 = tvb_get_guint8(tvb, offset+1);
    oct3 = tvb_get_guint8(tvb, offset+2);

    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 3,
	"Hour %d%d, Minutes %d%d, Seconds %d%d",
	(oct & 0xf0) >> 4,
	oct & 0x0f,
	(oct2 & 0xf0) >> 4,
	oct2 & 0x0f,
	(oct3 & 0xf0) >> 4,
	oct3 & 0x0f);
}

static void
param_rel_timestamp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    guint32	value = 0;
    gchar	*str = NULL;
    gchar	*str2 = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    switch (oct)
    {
    case 245: str = "Indefinite"; break;
    case 246: str = "Immediate"; break;
    case 247: str = "Valid until mobile becomes inactive/Deliver when mobile next becomes active"; break;
    case 248: str = "Valid until registration area changes, discard if not registered" ; break;
    default:
	if (oct <= 143) { value = (oct + 1) * 5; str2 = "Minutes"; break; }
	else if ((oct >= 144) && (oct <= 167)) { value = (oct - 143) * 30; str2 = "Minutes + 12 Hours"; break; }
	else if ((oct >= 168) && (oct <= 196)) { value = oct - 166; str2 = "Days"; break; }
	else if ((oct >= 197) && (oct <= 244)) { value = oct - 192; str2 = "Weeks"; break; }
	else { str = "Reserved"; break; }
    }

    if (str == NULL)
    {
	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, offset, 1,
	    "%s",
	    str2);
    }
    else
    {
	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, offset, 1,
	    "%d %s",
	    value, str2);
    }
}

static void
param_pri_ind(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    gchar	*str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    switch ((oct & 0xc0) >> 6)
    {
    case 0x00: str = "Normal"; break;
    case 0x01: str = "Interactive"; break;
    case 0x10: str = "Urgent"; break;
    case 0x11: str = "Emergency"; break;
    }

    my_decode_bitfield_value(bigbuf, oct, 0xc0, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  %s",
	bigbuf,
	str);

    my_decode_bitfield_value(bigbuf, oct, 0x3f, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  Reserved",
	bigbuf);
}

static void
param_priv_ind(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    gchar	*str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    switch ((oct & 0xc0) >> 6)
    {
    case 0: str = "Not restricted (privacy level 0)"; break;
    case 1: str = "Restricted (privacy level 1)"; break;
    case 2: str = "Confidential (privacy level 2)"; break;
    case 3: str = "Secret (privacy level 3)"; break;
    }

    my_decode_bitfield_value(bigbuf, oct, 0xc0, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  %s",
	bigbuf,
	str);

    my_decode_bitfield_value(bigbuf, oct, 0x3f, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  Reserved",
	bigbuf);
}

static void
param_reply_opt(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    my_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  %s",
	bigbuf,
	(oct & 0x80) ? "User (manual) acknowledgment is requested" : "No user (manual) acknowledgement is requested");

    my_decode_bitfield_value(bigbuf, oct, 0x40, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  %s",
	bigbuf,
	(oct & 0x40) ? "Delivery acknowledgment requested" : "No delivery acknowledgment requested");

    my_decode_bitfield_value(bigbuf, oct, 0x3f, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  Reserved",
	bigbuf);
}

static void
param_num_messages(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"Number of voice mail messages, %d%d",
	(oct & 0xf0) >> 4,
	oct & 0x0f);
}

static void
param_alert(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    gchar	*str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    switch ((oct & 0xc0) >> 6)
    {
    case 0: str = "Use Mobile default alert"; break;
    case 1: str = "Use Low-priority alert"; break;
    case 2: str = "Use Medium-priority alert"; break;
    case 3: str = "Use High-priority alert"; break;
    }

    my_decode_bitfield_value(bigbuf, oct, 0xc0, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  %s",
	bigbuf,
	str);

    my_decode_bitfield_value(bigbuf, oct, 0x3f, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  Reserved",
	bigbuf);
}

static void
param_lang_ind(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    gchar	*str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    switch (oct)
    {
    case 0x00: str = "Unknown or unspecified"; break;
    case 0x01: str = "English"; break;
    case 0x02: str = "French"; break;
    case 0x03: str = "Spanish"; break;
    case 0x04: str = "Japanese"; break;
    case 0x05: str = "Korean"; break;
    case 0x06: str = "Chinese"; break;
    case 0x07: str = "Hebrew"; break;
    default: str = "Reserved"; break;
    }

    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s",
	str);
}

static void
param_cb_num(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, oct2, num_fields, odd;
    guint32	saved_offset;
    guint32	required_octs;
    guint32	i;

    SHORT_DATA_CHECK(len, 2);

    oct = tvb_get_guint8(tvb, offset);

    my_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  Digit mode, %s",
	bigbuf,
	(oct & 0x80) ? "8-bit ASCII" : "4-bit DTMF");

    if (oct & 0x80)
    {
	my_decode_bitfield_value(bigbuf, oct, 0x70, 8);
	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, offset, 1,
	    "%s :  Type of number (%d)",
	    bigbuf,
	    (oct & 0x70) >> 4);

	my_decode_bitfield_value(bigbuf, oct, 0x0f, 8);
	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, offset, 1,
	    "%s :  Numbering plan (%d)",
	    bigbuf,
	    oct & 0x0f);

	offset++;
	num_fields = tvb_get_guint8(tvb, offset);

	my_decode_bitfield_value(bigbuf, oct, 0xff, 8);
	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, offset, 1,
	    "%s :  Number of fields (%d)",
	    bigbuf,
	    num_fields);

	if (num_fields == 0) return;

	if (num_fields > (len - 2))
	{
	    proto_tree_add_none_format(tree, hf_ansi_637_none,
		tvb, offset, 1,
		"Missing %d octet(s) for number of fields",
		(num_fields + 2) - len);

	    return;
	}

	offset++;

	i = 0;
	while (i < num_fields)
	{
	    bigbuf[i] = tvb_get_guint8(tvb, offset+i) & 0x7f;
	    i++;
	}
	bigbuf[i] = '\0';

	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, offset, num_fields,
	    "Number, %s",
	    bigbuf);
    }
    else
    {
	offset++;
	num_fields = (oct & 0x7f) << 1;
	oct2 = tvb_get_guint8(tvb, offset);
	num_fields |= ((oct2 & 0x80) >> 7);

	my_decode_bitfield_value(bigbuf, oct, 0x7f, 8);
	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, offset-1, 1,
	    "%s :  Number of fields (%d)",
	    bigbuf,
	    num_fields);

	my_decode_bitfield_value(bigbuf, oct2, 0x80, 8);
	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, offset, 1,
	    "%s :  Number of fields",
	    bigbuf);

	odd = FALSE;

	if (num_fields > 0)
	{
	    i = (num_fields - 1) * 4;
	    required_octs = (i / 8) + ((i % 8) ? 1 : 0);

	    if (required_octs + 2 > len)
	    {
		proto_tree_add_none_format(tree, hf_ansi_637_none,
		    tvb, offset, 1,
		    "Missing %d octet(s) for number of fields",
		    (required_octs + 2) - len);

		return;
	    }

	    odd = num_fields & 0x01;
	    memset((void *) bigbuf, 0, sizeof(bigbuf));
	    saved_offset = offset;
	    offset++;

	    i = 0;
	    while (i < num_fields)
	    {
		bigbuf[i] =
		    ((oct & 0x78) >> 3) |
		    0x30;

		if (!odd)
		{
		    oct2 = tvb_get_guint8(tvb, offset);
		    offset++;

		    i++;
		    bigbuf[i] =
			((oct & 0x07) << 1) |
			((oct2 & 0x80) >> 7) |
			0x30;

		    oct = oct2;
		}

		i++;
	    }

	    proto_tree_add_none_format(tree, hf_ansi_637_none,
		tvb, saved_offset, offset - saved_offset,
		"Number, %s",
		bigbuf);
	}

	my_decode_bitfield_value(bigbuf, oct, odd ? 0x07: 0x7f, 8);
	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, offset, 1,
	    "%s :  Reserved",
	    bigbuf);
    }
}

static void
param_disp_mode(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    gchar	*str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    switch ((oct & 0xc0) >> 6)
    {
    case 0x00: str = "Immediate Display: The mobile station is to display the received message as soon as possible."; break;
    case 0x01: str = "Mobile default setting: The mobile station is to display the received message based on a pre-defined mode in the mobile station."; break;
    case 0x10: str = "User Invoke: The mobile station is to display the received message based on the mode selected by the user."; break;
    case 0x11: str = "Reserved"; break;
    }

    my_decode_bitfield_value(bigbuf, oct, 0xc0, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  %s",
	bigbuf,
	str);

    my_decode_bitfield_value(bigbuf, oct, 0x3f, 8);
    proto_tree_add_none_format(tree, hf_ansi_637_none,
	tvb, offset, 1,
	"%s :  Reserved",
	bigbuf);
}

#define	NUM_PARAM (sizeof(ansi_param_strings)/sizeof(value_string))
static gint ett_ansi_param[NUM_PARAM];
static void (*ansi_637_param_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    NULL,	/* Message Identifier */
    param_user_data,	/* User Data */
    param_rsp_code,	/* User Response Code */
    param_timestamp,	/* Message Center Time Stamp */
    param_timestamp,	/* Validity Period  Absolute */
    param_rel_timestamp,	/* Validity Period  Relative */
    param_timestamp,	/* Deferred Delivery Time - Absolute */
    param_rel_timestamp,	/* Deferred Delivery Time - Relative */
    param_pri_ind,	/* Priority Indicator */
    param_priv_ind,	/* Privacy Indicator */
    param_reply_opt,	/* Reply Option */
    param_num_messages,	/* Number of Messages */
    param_alert,	/* Alert on Message Delivery */
    param_lang_ind,	/* Language Indicator */
    param_cb_num,	/* Call-Back Number */
    param_disp_mode,	/* Message Display Mode */
    NULL,	/* Multiple Encoding User Data */
    NULL,	/* NONE */
};

/* GENERIC IS-637 DISSECTOR FUNCTIONS */

static gboolean
dissect_ansi_637_param(tvbuff_t *tvb, proto_tree *tree, guint32	*offset)
{
    void (*param_fcn)(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = NULL;
    guint8	oct;
    guint8	len;
    guint32	curr_offset;
    gint	ett_param_idx, idx;
    proto_tree	*subtree;
    proto_item	*item;
    gchar	*str = NULL;


    curr_offset = *offset;

    oct = tvb_get_guint8(tvb, curr_offset);
    str = my_match_strval((guint32) oct, ansi_param_strings, &idx);

    if (NULL == str)
    {
	return(FALSE);
    }

    ett_param_idx = ett_ansi_param[idx];
    param_fcn = ansi_637_param_fcn[idx];

    item =
	proto_tree_add_none_format(tree, hf_ansi_637_none,
	    tvb, curr_offset, -1, str);

    subtree = proto_item_add_subtree(item, ett_param_idx);

    proto_tree_add_uint(subtree, hf_ansi_637_subparam_id,
	tvb, curr_offset, 1, oct);

    curr_offset++;

    len = tvb_get_guint8(tvb, curr_offset);

    proto_item_set_len(item, (curr_offset - *offset) + len + 1);

    proto_tree_add_uint(subtree, hf_ansi_637_length,
	tvb, curr_offset, 1, len);

    curr_offset++;

    if (len > 0)
    {
	if (param_fcn == NULL)
	{
	    proto_tree_add_none_format(subtree, hf_ansi_637_none,
		tvb, curr_offset, len, "Parameter Data");
	}
	else
	{
	    (*param_fcn)(tvb, subtree, len, curr_offset);
	}

	curr_offset += len;
    }

    *offset = curr_offset;

    return(TRUE);
}

static void
dissect_ansi_637_message(tvbuff_t *tvb, proto_tree *ansi_637_tree)
{
    guint8	oct;
    guint8	len;
    guint32	octs;
    guint32	curr_offset;
    guint32	msg_id;
    guint32	msg_type;
    gchar	*str = NULL;
    proto_item	*item;
    proto_tree	*subtree;


    oct = tvb_get_guint8(tvb, 0);
    if (oct != 0x00)
    {
	return;
    }

    len = tvb_get_guint8(tvb, 1);
    if (len != 3)
    {
	return;
    }

    octs = tvb_get_ntoh24(tvb, 2);
    msg_type = (octs >> 20) & 0x0f;
    msg_id = (octs >> 4) & 0xffff;

    str = match_strval(msg_type, ansi_msg_type_strings);

    /*
     * do not append to COL_INFO
     */

    item =
	proto_tree_add_none_format(ansi_637_tree, hf_ansi_637_none,
	    tvb, 0, -1, str);

    subtree = proto_item_add_subtree(item, ett_params);

    proto_tree_add_uint(subtree, hf_ansi_637_subparam_id,
	tvb, 0, 1, oct);

    proto_tree_add_uint(subtree, hf_ansi_637_length,
	tvb, 1, 1, len);

    proto_tree_add_uint(subtree, hf_ansi_637_msg_type,
	tvb, 2, 3, octs);

    proto_tree_add_uint(subtree, hf_ansi_637_msg_id,
	tvb, 2, 3, octs);

    proto_tree_add_uint(subtree, hf_ansi_637_msg_junk,
	tvb, 2, 3, octs);

    proto_item_set_len(item, 2 + len);

    curr_offset = 2 + len;
    len = tvb_length(tvb);

    while ((len - curr_offset) > 0)
    {
	if (!dissect_ansi_637_param(tvb, ansi_637_tree, &curr_offset))
	{
	    proto_tree_add_none_format(ansi_637_tree, hf_ansi_637_none,
		tvb, curr_offset, len - curr_offset,
		"Unknown Parameter Data");
	    break;
	}
    }
}

static void
dissect_ansi_637(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item	*ansi_637_item;
    proto_tree	*ansi_637_tree = NULL;
    gchar	*str = NULL;

    if (!proto_is_protocol_enabled(proto_ansi_637))
    {
	call_dissector(data_handle,tvb, pinfo, tree);
	return;
    }

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, ansi_proto_name_short);
    }

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree)
    {
	/*
	 * create the ansi_637 protocol tree
	 */
	str = match_strval(pinfo->match_port, ansi_tele_strings);

	if (NULL == str) str = "Unrecognized Teleservice ID";

	ansi_637_item =
	    proto_tree_add_protocol_format(tree, proto_ansi_637, tvb, 0, -1,
		"%s %s (%d)",
		ansi_proto_name,
		str,
		pinfo->match_port);

	ansi_637_tree =
	    proto_item_add_subtree(ansi_637_item, ett_ansi_637);

	dissect_ansi_637_message(tvb, ansi_637_tree);
    }
}


/* Register the protocol with Ethereal */
void
proto_register_ansi_637(void)
{
    guint		i;

    /* Setup list of header fields */
    static hf_register_info hf[] =
    {
	{ &hf_ansi_637_msg_type,
	  { "Message Type",
	    "ansi_637.msg_type",
	    FT_UINT24, BASE_DEC, VALS(ansi_msg_type_strings), 0xf00000,
	    "", HFILL }},
	{ &hf_ansi_637_msg_id,
	  { "Message ID",
	    "ansi_637.msg_id",
	    FT_UINT24, BASE_DEC, NULL, 0x0ffff0,
	    "", HFILL }},
	{ &hf_ansi_637_msg_junk,
	  { "Reserved",
	    "ansi_637.msg_junk",
	    FT_UINT24, BASE_DEC, NULL, 0x00000f,
	    "", HFILL }},
	{ &hf_ansi_637_length,
	    { "Length",		"ansi_637.len",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_ansi_637_none,
	    { "Sub tree",	"ansi_637.none",
	    FT_NONE, 0, 0, 0,
	    "", HFILL }
	},
	{ &hf_ansi_637_subparam_id,
	    { "Subparam ID",	"ansi_637.subparam_id",
	    FT_UINT8, BASE_DEC, VALS(ansi_param_strings), 0,
	    "", HFILL }
	},
    };

    /* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_PARAMS	2
    static gint *ett[NUM_INDIVIDUAL_PARAMS+NUM_PARAM];

    memset((void *) ett, 0, sizeof(ett));

    ett[0] = &ett_ansi_637;
    ett[1] = &ett_params;

    for (i=0; i < NUM_PARAM; i++)
    {
	ett_ansi_param[i] = -1;
	ett[NUM_INDIVIDUAL_PARAMS+i] = &ett_ansi_param[i];
    }

    /* Register the protocol name and description */
    proto_ansi_637 =
	proto_register_protocol(ansi_proto_name, "ANSI IS-637-A", "ansi_637");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ansi_637, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_ansi_637(void)
{
    dissector_handle_t	ansi_637_handle;
    guint		i;

    ansi_637_handle = create_dissector_handle(dissect_ansi_637, proto_ansi_637);

    /*
     * register for all known teleservices
     * '-1' is to stop before trailing '0' entry
     *
     * to add teleservices, modify 'ansi_tele_strings'
     */
    for (i=0; i < ((sizeof(ansi_tele_strings)/sizeof(value_string))-1); i++)
    {
	/*
	 * ANSI MAP dissector will push out teleservice ids
	 */
	dissector_add("ansi_map.tele_id", ansi_tele_strings[i].value, ansi_637_handle);

	/*
	 * ANSI A-interface dissector will push out teleservice ids after
	 * transport layer dissection
	 *
	 * This is for IOS or IS-634 variants.
	 */
	/* dissector_add("ansi_a.tele_id", ansi_tele_strings[i].value, ansi_637_handle); */
    }

    data_handle = find_dissector("data");
}
