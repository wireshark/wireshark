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
/* #include <stdlib.h> */
#include <gmodule.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>

#include "epan/packet.h"
#include "epan/emem.h"


static const char *ansi_proto_name_tele = "ANSI IS-637-A (SMS) Teleservice Layer";
static const char *ansi_proto_name_trans = "ANSI IS-637-A (SMS) Transport Layer";
static const char *ansi_proto_name_short = "IS-637-A";

static const value_string ansi_srvc_cat_strings[] = {
    { 0x0000,	"Unknown or unspecified" },
    { 0x0001,	"Emergency Broadcasts" },
    { 0x0002,	"Administrative" },
    { 0x0003,	"Maintenance" },
    { 0x0004,	"General News - Local" },
    { 0x0005,	"General News - Regional" },
    { 0x0006,	"General News - National" },
    { 0x0007,	"General News - International" },
    { 0x0008,	"Business/Financial News - Local" },
    { 0x0009,	"Business/Financial News - Regional" },
    { 0x000A,	"Business/Financial News - National" },
    { 0x000B,	"Business/Financial News - International" },
    { 0x000C,	"Sports News - Local" },
    { 0x000D,	"Sports News - Regional" },
    { 0x000E,	"Sports News - National" },
    { 0x000F,	"Sports News - International" },
    { 0x0010,	"Entertainment News - Local" },
    { 0x0011,	"Entertainment News - Regional" },
    { 0x0012,	"Entertainment News - National" },
    { 0x0013,	"Entertainment News - International" },
    { 0x0014,	"Local Weather" },
    { 0x0015,	"Area Traffic Reports" },
    { 0x0016,	"Local Airport Flight Schedules" },
    { 0x0017,	"Restaurants" },
    { 0x0018,	"Lodgings" },
    { 0x0019,	"Retail Directory" },
    { 0x001A,	"Advertisements" },
    { 0x001B,	"Stock Quotes" },
    { 0x001C,	"Employment Opportunities" },
    { 0x001D,	"Medical/Health/Hospitals" },
    { 0x001E,	"Technology News" },
    { 0x001F,	"Multi-category" },
    { 0, NULL },
};

static const value_string ansi_tele_msg_type_strings[] = {
    { 1,	"Deliver (mobile-terminated only)" },
    { 2,	"Submit (mobile-originated only)" },
    { 3,	"Cancellation (mobile-originated only)" },
    { 4,	"Delivery Acknowledgement (mobile-terminated only)" },
    { 5,	"User Acknowledgement (either direction)" },
    { 0, NULL },
};

static const value_string ansi_tele_id_strings[] = {
    { 1,	"Reserved for maintenance" },
    { 4096,	"AMPS Extended Protocol Enhanced Services" },
    { 4097,	"CDMA Cellular Paging Teleservice" },
    { 4098,	"CDMA Cellular Messaging Teleservice" },
    { 4099,	"CDMA Voice Mail Notification" },
    { 4100,	"CDMA Wireless Application Protocol (WAP)" },
    { 4101,	"CDMA Wireless Enhanced Messaging Teleservice (WEMT)" },
    { 0, NULL },
};

static const value_string ansi_tele_param_strings[] = {
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

static const value_string ansi_trans_msg_type_strings[] = {
    { 0,	"Point-to-Point" },
    { 1,	"Broadcast" },
    { 2,	"Acknowledge" },
    { 0, NULL },
};

static const value_string ansi_trans_param_strings[] = {
    { 0x00,	"Teleservice Identifier" },
    { 0x01,	"Service Category" },
    { 0x02,	"Originating Address" },
    { 0x03,	"Originating Subaddress" },
    { 0x04,	"Destination Address" },
    { 0x05,	"Destination Subaddress" },
    { 0x06,	"Bearer Reply Option" },
    { 0x07,	"Cause Codes" },
    { 0x08,	"Bearer Data" },
    { 0, NULL },
};

/*
 * from Table 2.7.1.3.2.4-4. Representation of DTMF Digits
 * 3GPP2 C.S0005-C (IS-2000 aka cdma2000)
 */
static unsigned char air_digits[] = {
  /*  0   1   2   3   4   5   6   7   8   9   a   b   c   d   e */
     '?','1','2','3','4','5','6','7','8','9','0','*','#','?','?'
};

/* Initialize the protocol and registered fields */
static int proto_ansi_637_tele = -1;
static int proto_ansi_637_trans = -1;
static int hf_ansi_637_none = -1;
static int hf_ansi_637_length = -1;
static int hf_ansi_637_bin_addr = -1;
static int hf_ansi_637_tele_msg_type = -1;
static int hf_ansi_637_tele_msg_id = -1;
static int hf_ansi_637_tele_msg_rsvd = -1;
static int hf_ansi_637_tele_subparam_id = -1;
static int hf_ansi_637_trans_msg_type = -1;
static int hf_ansi_637_trans_param_id = -1;

/* Initialize the subtree pointers */
static gint ett_ansi_637_tele = -1;
static gint ett_ansi_637_trans = -1;
static gint ett_params = -1;

static guint32 ansi_637_trans_tele_id;
static char ansi_637_bigbuf[1024];
/* static dissector_handle_t data_handle; */
static dissector_table_t tele_dissector_table;
static packet_info *g_pinfo;
static proto_tree *g_tree;

/* FUNCTIONS */

static void
decode_7_bits(tvbuff_t *tvb, guint32 *offset, guint8 num_fields, guint8 *last_oct, guint8 *last_bit, gchar *buf)
{
    guint8	oct, oct2, bit;
    /* guint32	saved_offset; */
    guint32	i;


    if (num_fields == 0)
    {
	return;
    }

    /* saved_offset = *offset; */
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

/* PARAM FUNCTIONS */

#define	EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
	proto_tree_add_text(tree, tvb, offset, \
	    (edc_len) - (edc_max_len), "Extraneous Data"); \
    }

#define	SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
    if ((sdc_len) < (sdc_min_len)) \
    { \
	proto_tree_add_text(tree, tvb, offset, \
	    (sdc_len), "Short Data (?)"); \
	return; \
    }

#define	EXACT_DATA_CHECK(edc_len, edc_eq_len) \
    if ((edc_len) != (edc_eq_len)) \
    { \
	proto_tree_add_text(tree, tvb, offset, \
	    (edc_len), "Unexpected Data Length"); \
	return; \
    }

static void
tele_param_user_data(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
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
    const gchar	*str = NULL;

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

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0xf8, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Encoding: %s",
	ansi_637_bigbuf,
	str);

    if (encoding == 0x01)
    {
	other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x07, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s :  Message type: see TIA/EIA/IS-91 (%d)",
	    ansi_637_bigbuf,
	    msg_type);

	other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0xf8, 8);
	proto_tree_add_text(tree, tvb, offset+1, 1,
	    "%s :  Message type",
	    ansi_637_bigbuf);

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

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x07, 8);
    proto_tree_add_text(tree, tvb, offset-1, 1,
	"%s :  Number of fields (MSB): %d",
	ansi_637_bigbuf,
	num_fields);

    other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0xf8, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Number of fields (LSB)",
	ansi_637_bigbuf);

    other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0x07, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Most significant bits of first field",
	ansi_637_bigbuf);

    offset++;
    used++;
    oct = oct2;

    /* NOTE: there are now 3 bits remaining in 'oct' */

    if (len <= used) return;

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
	    proto_tree_add_text(tree, tvb, offset, 1,
		"Missing %d octet(s) for number of fields",
		(required_octs + used) - len);

	    return;
	}

	bit = 3;
	saved_offset = offset;

	decode_7_bits(tvb, &offset, num_fields, &oct, &bit, ansi_637_bigbuf);

	proto_tree_add_text(tree, tvb, saved_offset, offset - saved_offset,
	    "Encoded user data: %s",
	    ansi_637_bigbuf);

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
	    other_decode_bitfield_value(ansi_637_bigbuf, oct, oct2, 8);
	    proto_tree_add_text(tree, tvb, offset - 1, 1,
		"%s :  Reserved",
		ansi_637_bigbuf);
	}
    }
    else
    {
	proto_tree_add_text(tree, tvb, offset, len - used,
	    "Encoded user data");
    }
}

static void
tele_param_rsp_code(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;

    EXACT_DATA_CHECK(len, 1);

    /*
     * response code
     */
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree, tvb, offset, 1,
	"Response code: %d",
	oct);
}

static void
tele_param_timestamp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, oct2, oct3;

    EXACT_DATA_CHECK(len, 6);

    oct = tvb_get_guint8(tvb, offset);
    oct2 = tvb_get_guint8(tvb, offset+1);
    oct3 = tvb_get_guint8(tvb, offset+2);

    proto_tree_add_text(tree, tvb, offset, 3,
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

    proto_tree_add_text(tree, tvb, offset, 3,
	"Hour %d%d, Minutes %d%d, Seconds %d%d",
	(oct & 0xf0) >> 4,
	oct & 0x0f,
	(oct2 & 0xf0) >> 4,
	oct2 & 0x0f,
	(oct3 & 0xf0) >> 4,
	oct3 & 0x0f);
}

static void
tele_param_rel_timestamp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    guint32	value = 0;
    const gchar	*str = NULL;
    const gchar	*str2 = NULL;

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
	proto_tree_add_text(tree, tvb, offset, 1,
	    str2);
    }
    else
    {
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%d %s",
	    value, str2);
    }
}

static const value_string tele_param_pri_ind_strings[] = {
	{ 0,	"Normal" },
	{ 1,	"Interactive" },
	{ 2,	"Urgent" },
	{ 3,	"Emergency" },
	{ 0, NULL }
};

static void
tele_param_pri_ind(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    const gchar	*str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    str=val_to_str((oct&0xc0)>>6, tele_param_pri_ind_strings, "Unknown");

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  %s",
	ansi_637_bigbuf,
	str);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x3f, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Reserved",
	ansi_637_bigbuf);
}

static void
tele_param_priv_ind(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    const gchar	*str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    switch ((oct & 0xc0) >> 6)
    {
    case 0: str = "Not restricted (privacy level 0)"; break;
    case 1: str = "Restricted (privacy level 1)"; break;
    case 2: str = "Confidential (privacy level 2)"; break;
    case 3: str = "Secret (privacy level 3)"; break;
    }

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  %s",
	ansi_637_bigbuf,
	str);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x3f, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Reserved",
	ansi_637_bigbuf);
}

static void
tele_param_reply_opt(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  %s (manual) acknowledgment is requested",
	ansi_637_bigbuf,
	(oct & 0x80) ? "User" : "No user");

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x40, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  %s acknowledgment requested",
	ansi_637_bigbuf,
	(oct & 0x40) ? "Delivery" : "No delivery");

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x3f, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Reserved",
	ansi_637_bigbuf);
}

static void
tele_param_num_messages(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree, tvb, offset, 1,
	"Number of voice mail messages: %d%d",
	(oct & 0xf0) >> 4,
	oct & 0x0f);
}

static void
tele_param_alert(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    const gchar	*str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    switch ((oct & 0xc0) >> 6)
    {
    case 0: str = "Use Mobile default alert"; break;
    case 1: str = "Use Low-priority alert"; break;
    case 2: str = "Use Medium-priority alert"; break;
    case 3: str = "Use High-priority alert"; break;
    }

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  %s",
	ansi_637_bigbuf,
	str);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x3f, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Reserved",
	ansi_637_bigbuf);
}

static void
tele_param_lang_ind(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    const gchar	*str = NULL;

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

    proto_tree_add_text(tree, tvb, offset, 1,
	str);
}

static void
tele_param_cb_num(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, oct2, num_fields, odd;
    guint32	saved_offset;
    guint32	required_octs;
    guint32	i;

    SHORT_DATA_CHECK(len, 2);

    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Digit mode: %s",
	ansi_637_bigbuf,
	(oct & 0x80) ? "8-bit ASCII" : "4-bit DTMF");

    if (oct & 0x80)
    {
	other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x70, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s :  Type of number: (%d)",
	    ansi_637_bigbuf,
	    (oct & 0x70) >> 4);

	other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x0f, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s :  Numbering plan: (%d)",
	    ansi_637_bigbuf,
	    oct & 0x0f);

	offset++;
	num_fields = tvb_get_guint8(tvb, offset);

	other_decode_bitfield_value(ansi_637_bigbuf, oct, 0xff, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s :  Number of fields: (%d)",
	    ansi_637_bigbuf,
	    num_fields);

	if (num_fields == 0) return;

	if (num_fields > (len - 2))
	{
	    proto_tree_add_text(tree, tvb, offset, 1,
		"Missing %d octet(s) for number of fields",
		(num_fields + 2) - len);

	    return;
	}

	offset++;

	i = 0;
	while (i < num_fields)
	{
	    ansi_637_bigbuf[i] = tvb_get_guint8(tvb, offset+i) & 0x7f;
	    i++;
	}
	ansi_637_bigbuf[i] = '\0';

	proto_tree_add_text(tree, tvb, offset, num_fields,
	    "Number: %s",
	    ansi_637_bigbuf);
    }
    else
    {
	offset++;
	num_fields = (oct & 0x7f) << 1;
	oct2 = tvb_get_guint8(tvb, offset);
	num_fields |= ((oct2 & 0x80) >> 7);

	other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x7f, 8);
	proto_tree_add_text(tree, tvb, offset-1, 1,
	    "%s :  Number of fields (MBS): (%d)",
	    ansi_637_bigbuf,
	    num_fields);

	other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0x80, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s :  Number of fields (LSB)",
	    ansi_637_bigbuf);

	oct = oct2;
	odd = FALSE;

	if (num_fields > 0)
	{
	    i = (num_fields - 1) * 4;
	    required_octs = (i / 8) + ((i % 8) ? 1 : 0);

	    if (required_octs + 2 > len)
	    {
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Missing %d octet(s) for number of fields",
		    (required_octs + 2) - len);

		return;
	    }

	    odd = num_fields & 0x01;
	    memset((void *) ansi_637_bigbuf, 0, sizeof(ansi_637_bigbuf));
	    saved_offset = offset;
	    offset++;

	    i = 0;
	    while (i < num_fields)
	    {
		ansi_637_bigbuf[i] =
		    air_digits[(oct & 0x78) >> 3];

		i++;
		if (i >= num_fields) break;

		oct2 = tvb_get_guint8(tvb, offset);
		offset++;

		ansi_637_bigbuf[i] =
		    air_digits[((oct & 0x07) << 1) | ((oct2 & 0x80) >> 7)];

		oct = oct2;

		i++;
	    }

	    proto_tree_add_text(tree, tvb, saved_offset, offset - saved_offset,
		"Number: %s",
		ansi_637_bigbuf);
	}

	other_decode_bitfield_value(ansi_637_bigbuf, oct, odd ? 0x07: 0x7f, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s :  Reserved",
	    ansi_637_bigbuf);
    }
}

static void
tele_param_disp_mode(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    const gchar	*str = NULL;

    EXACT_DATA_CHECK(len, 1);

    oct = tvb_get_guint8(tvb, offset);

    switch ((oct & 0xc0) >> 6)
    {
    case 0: str = "Immediate Display: The mobile station is to display the received message as soon as possible."; break;
    case 1: str = "Mobile default setting: The mobile station is to display the received message based on a pre-defined mode in the mobile station."; break;
    case 2: str = "User Invoke: The mobile station is to display the received message based on the mode selected by the user."; break;
    case 3: str = "Reserved"; break;
    }

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  %s",
	ansi_637_bigbuf,
	str);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x3f, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Reserved",
	ansi_637_bigbuf);
}

#define	NUM_TELE_PARAM (sizeof(ansi_tele_param_strings)/sizeof(value_string))
static gint ett_ansi_637_tele_param[NUM_TELE_PARAM];
static void (*ansi_637_tele_param_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    NULL,			/* Message Identifier */
    tele_param_user_data,	/* User Data */
    tele_param_rsp_code,	/* User Response Code */
    tele_param_timestamp,	/* Message Center Time Stamp */
    tele_param_timestamp,	/* Validity Period  Absolute */
    tele_param_rel_timestamp,	/* Validity Period  Relative */
    tele_param_timestamp,	/* Deferred Delivery Time - Absolute */
    tele_param_rel_timestamp,	/* Deferred Delivery Time - Relative */
    tele_param_pri_ind,		/* Priority Indicator */
    tele_param_priv_ind,	/* Privacy Indicator */
    tele_param_reply_opt,	/* Reply Option */
    tele_param_num_messages,	/* Number of Messages */
    tele_param_alert,		/* Alert on Message Delivery */
    tele_param_lang_ind,	/* Language Indicator */
    tele_param_cb_num,		/* Call-Back Number */
    tele_param_disp_mode,	/* Message Display Mode */
    NULL,			/* Multiple Encoding User Data */
    NULL,			/* NONE */
};

static void
trans_param_tele_id(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset, gchar *add_string, int string_len)
{
    guint32	value;
    const gchar	*str = NULL;

    EXACT_DATA_CHECK(len, 2);

    value = tvb_get_ntohs(tvb, offset);

    ansi_637_trans_tele_id = value;

    str = match_strval(value, ansi_tele_id_strings);

    if (NULL == str)
    {
	switch (value)
	{
	case 1:
	    str = "Reserved for maintenance";
	    break;
	case 4102:
	    str = "CDMA Service Category Programming Teleservice (SCPT)";
	    break;
	case 4103:
	    str = "CDMA Card Application Toolkit Protocol Teleservice (CATPT)";
	    break;
	case 32513:
	    str = "TDMA Cellular Messaging Teleservice";
	    break;
	case 32514:
	    str = "TDMA Cellular Paging Teleservice (CPT-136)";
	    break;
	case 32515:
	    str = "TDMA Over-the-Air Activation Teleservice (OATS)";
	    break;
	case 32520:
	    str = "TDMA System Assisted Mobile Positioning through Satellite (SAMPS)";
	    break;
	case 32584:
	    str = "TDMA Segmented System Assisted Mobile Positioning Service";
	    break;
	default:
	    if ((value >= 2) && (value <= 4095))
	    {
		str = "Reserved for assignment by TIA-41";
	    }
	    else if ((value >= 4104) && (value <= 4113))
	    {
		str = "Reserved for GSM1x Teleservice (CDMA)";
	    }
	    else if ((value >= 4114) && (value <= 32512))
	    {
		str = "Reserved for assignment by TIA-41";
	    }
	    else if ((value >= 32521) && (value <= 32575))
	    {
		str = "Reserved for assignment by this Standard for TDMA MS-based SMEs";
	    }
	    else if ((value >= 49152) && (value <= 65535))
	    {
		str = "Reserved for carrier specific teleservices";
	    }
	    else
	    {
		str = "Unrecognized Teleservice ID";
	    }
	    break;
	}
    }

    proto_tree_add_text(tree, tvb, offset, 2,
	"%s (%d)",
	str,
	value);

    g_snprintf(add_string, string_len, " - %s (%d)", str, value);
}

static void
trans_param_srvc_cat(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset, gchar *add_string, int string_len)
{
    guint32	value;
    const gchar	*str = NULL;

    EXACT_DATA_CHECK(len, 2);

    value = tvb_get_ntohs(tvb, offset);

    str = match_strval(value, ansi_srvc_cat_strings);

    if (NULL == str) str = "Reserved";

    proto_tree_add_text(tree, tvb, offset, 2,
	str);

    g_snprintf(add_string, string_len, " - %s (%d)", str, value);
}

static void
trans_param_address(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset, gchar *add_string _U_, int string_len _U_)
{
    guint8	oct, oct2, num_fields, odd;
    gboolean	email_addr;
    guint32	saved_offset;
    guint32	required_octs;
    guint32	i;
    const gchar	*str;

    SHORT_DATA_CHECK(len, 2);

    email_addr = FALSE;

    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x80, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Digit mode: %s",
	ansi_637_bigbuf,
	(oct & 0x80) ? "8-bit ASCII" : "4-bit DTMF");

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x40, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Number mode: %s",
	ansi_637_bigbuf,
	(oct & 0x40) ? "Data Network Address" : "ANSI T1.607");

    if (oct & 0x80)
    {
	if (oct & 0x40)
	{
	    switch ((oct & 0x38) >> 3)
	    {
	    case 0: str = "Unknown"; break;
	    case 1: str = "Internet Protocol (RFC 791)"; break;
	    case 2: str = "Internet Email Address (RFC 822)"; email_addr = TRUE; break;
	    default:
		str = "Reserved";
		break;
	    }

	    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x38, 8);
	    proto_tree_add_text(tree, tvb, offset, 1,
		"%s :  Type of number: %s (%d)",
		ansi_637_bigbuf,
		str,
		(oct & 0x38) >> 3);

	    offset++;
	    num_fields = (oct & 0x07) << 5;
	    oct2 = tvb_get_guint8(tvb, offset);
	    num_fields |= ((oct2 & 0xf8) >> 3);

	    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x07, 8);
	    proto_tree_add_text(tree, tvb, offset-1, 1,
		"%s :  Number of fields (MSB): (%d)",
		ansi_637_bigbuf,
		num_fields);

	    other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0xf8, 8);
	    proto_tree_add_text(tree, tvb, offset, 1,
		"%s :  Number of fields (LSB)",
		ansi_637_bigbuf);

	    if (num_fields == 0) return;

	    if (num_fields > (len - 2))
	    {
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Missing %d octet(s) for number of fields",
		    (num_fields + 2) - len);

		return;
	    }

	    other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0x07, 8);
	    proto_tree_add_text(tree, tvb, offset, 1,
		"%s :  Most significant bits of first field",
		ansi_637_bigbuf);

	    offset++;
	    oct = oct2;

	    i = 0;
	    while (i < num_fields)
	    {
		ansi_637_bigbuf[i] = (oct & 0x07) << 5;
		ansi_637_bigbuf[i] |= ((oct = tvb_get_guint8(tvb, offset+i)) & 0xf8) >> 3;
		i++;
	    }
	    ansi_637_bigbuf[i] = '\0';

	    if (email_addr)
	    {
		proto_tree_add_text(tree, tvb, offset, num_fields - 1,
		    "Number: %s",
		    ansi_637_bigbuf);
	    }
	    else
	    {
		proto_tree_add_bytes(tree, hf_ansi_637_bin_addr, tvb, offset, num_fields - 1,
		    ansi_637_bigbuf);
	    }

	    offset += (num_fields - 1);

	    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0xf8, 8);
	    proto_tree_add_text(tree, tvb, offset, 1,
		"%s :  Least significant bits of last field",
		ansi_637_bigbuf);

	    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x07, 8);
	    proto_tree_add_text(tree, tvb, offset, 1,
		"%s :  Reserved",
		ansi_637_bigbuf);
	}
	else
	{
	    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x38, 8);
	    proto_tree_add_text(tree, tvb, offset, 1,
		"%s :  Type of number: (%d)",
		ansi_637_bigbuf,
		(oct & 0x38) >> 3);

	    oct2 = tvb_get_guint8(tvb, offset + 1);

	    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x07, 8);
	    proto_tree_add_text(tree, tvb, offset, 1,
		"%s :  Numbering plan (MSB): (%d)",
		ansi_637_bigbuf,
		((oct & 0x07) << 1) | ((oct2 & 0x80) >> 7));

	    offset++;
	    oct = oct2;

	    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x80, 8);
	    proto_tree_add_text(tree, tvb, offset, 1,
		"%s :  Numbering plan (LSB)",
		ansi_637_bigbuf);

	    offset++;
	    num_fields = (oct & 0x7f) << 1;
	    oct2 = tvb_get_guint8(tvb, offset);
	    num_fields |= ((oct2 & 0x80) >> 7);

	    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x7f, 8);
	    proto_tree_add_text(tree, tvb, offset-1, 1,
		"%s :  Number of fields (MSB): (%d)",
		ansi_637_bigbuf,
		num_fields);

	    other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0x80, 8);
	    proto_tree_add_text(tree, tvb, offset, 1,
		"%s :  Number of fields (LSB)",
		ansi_637_bigbuf);

	    if (num_fields == 0) return;

	    if (num_fields > (len - 3))
	    {
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Missing %d octet(s) for number of fields",
		    (num_fields + 3) - len);

		return;
	    }

	    other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0x7f, 8);
	    proto_tree_add_text(tree, tvb, offset, 1,
		"%s :  Most significant bits of first field",
		ansi_637_bigbuf);

	    offset++;
	    oct = oct2;

	    i = 0;
	    while (i < num_fields)
	    {
		ansi_637_bigbuf[i] = (oct & 0x7f) << 1;
		ansi_637_bigbuf[i] |= ((oct = tvb_get_guint8(tvb, offset+i)) & 0x80) >> 7;
		i++;
	    }
	    ansi_637_bigbuf[i] = '\0';

	    proto_tree_add_text(tree, tvb, offset, num_fields - 1,
		"Number: %s",
		ansi_637_bigbuf);

	    offset += (num_fields - 1);

	    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x80, 8);
	    proto_tree_add_text(tree, tvb, offset, 1,
		"%s :  Least significant bit of last field",
		ansi_637_bigbuf);

	    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x7f, 8);
	    proto_tree_add_text(tree, tvb, offset, 1,
		"%s :  Reserved",
		ansi_637_bigbuf);
	}
    }
    else
    {
	offset++;
	num_fields = (oct & 0x3f) << 2;
	oct2 = tvb_get_guint8(tvb, offset);
	num_fields |= ((oct2 & 0xc0) >> 6);

	other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x3f, 8);
	proto_tree_add_text(tree, tvb, offset-1, 1,
	    "%s :  Number of fields (MSB): (%d)",
	    ansi_637_bigbuf,
	    num_fields);

	other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0xc0, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s :  Number of fields (LSB)",
	    ansi_637_bigbuf);

	oct = oct2;
	odd = FALSE;

	if (num_fields > 0)
	{
	    i = (num_fields - 1) * 4;
	    required_octs = (i / 8) + ((i % 8) ? 1 : 0);

	    if (required_octs + 2 > len)
	    {
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Missing %d octet(s) for number of fields",
		    (required_octs + 2) - len);

		return;
	    }

	    odd = num_fields & 0x01;
	    memset((void *) ansi_637_bigbuf, 0, sizeof(ansi_637_bigbuf));
	    saved_offset = offset;
	    offset++;

	    i = 0;
	    while (i < num_fields)
	    {
		ansi_637_bigbuf[i] =
		    air_digits[(oct & 0x3c) >> 2];

		i++;
		if (i >= num_fields) break;

		oct2 = tvb_get_guint8(tvb, offset);
		offset++;

		ansi_637_bigbuf[i] =
		    air_digits[((oct & 0x03) << 2) | ((oct2 & 0xc0) >> 6)];

		oct = oct2;

		i++;
	    }

	    proto_tree_add_text(tree, tvb, saved_offset, offset - saved_offset,
		"Number: %s",
		ansi_637_bigbuf);
	}

	other_decode_bitfield_value(ansi_637_bigbuf, oct, odd ? 0x03: 0x3f, 8);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s :  Reserved",
	    ansi_637_bigbuf);
    }
}

static void
trans_param_subaddress(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset, gchar *add_string _U_, int string_len)
{
    guint8	oct, oct2, num_fields;
    guint32	i;
    const gchar	*str;

    SHORT_DATA_CHECK(len, 2);

    oct = tvb_get_guint8(tvb, offset);

    switch ((oct & 0xe0) >> 5)
    {
    case 0: str = "NSAP (CCITT Recommendation X.213 or ISO 8348 AD2)"; break;
    case 1: str = "User-specified"; break;
    default:
	str = "Reserved";
	break;
    }

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0xe0, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Type: %s",
	ansi_637_bigbuf,
	str);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x10, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Odd",
	ansi_637_bigbuf);

    offset++;
    num_fields = (oct & 0x0f) << 4;
    oct2 = tvb_get_guint8(tvb, offset);
    num_fields |= ((oct2 & 0xf0) >> 4);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree, tvb, offset-1, 1,
	"%s :  Number of fields (MSB): (%d)",
	ansi_637_bigbuf,
	num_fields);

    other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0xf0, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Number of fields (LSB)",
	ansi_637_bigbuf);

    if (num_fields == 0) return;

    if (num_fields > (len - 2))
    {
	proto_tree_add_text(tree, tvb, offset, 1,
	    "Missing %d octet(s) for number of fields",
	    (num_fields + 2) - len);

	return;
    }

    other_decode_bitfield_value(ansi_637_bigbuf, oct2, 0x0f, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Most significant bits of first field",
	ansi_637_bigbuf);

    offset++;
    oct = oct2;

    i = 0;
    while (i < num_fields)
    {
	ansi_637_bigbuf[i] = (oct & 0x0f) << 4;
	ansi_637_bigbuf[i] |= ((oct = tvb_get_guint8(tvb, offset+i)) & 0xf0) >> 4;
	i++;
    }
    ansi_637_bigbuf[i] = '\0';

    proto_tree_add_bytes(tree, hf_ansi_637_bin_addr, tvb, offset, num_fields - 1,
	ansi_637_bigbuf);

    offset += (num_fields - 1);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0xf0, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Least significant bits of last field",
	ansi_637_bigbuf);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Reserved",
	ansi_637_bigbuf);
}

static void
trans_param_bearer_reply_opt(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset, gchar *add_string, int string_len)
{
    guint8	oct;

    len = len;
    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0xfc, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Reply Sequence Number: %d",
	ansi_637_bigbuf,
	(oct & 0xfc) >> 2);

    g_snprintf(add_string, string_len, " - Reply Sequence Number (%d)", (oct & 0xfc) >> 2);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x03, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Reserved",
	ansi_637_bigbuf);
}

static void
trans_param_cause_codes(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset, gchar *add_string, int string_len)
{
    guint8	oct;
    const gchar	*str = NULL;

    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0xfc, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Reply Sequence Number: %d",
	ansi_637_bigbuf,
	(oct & 0xfc) >> 2);

    switch (oct & 0x03)
    {
    case 0x00: str = "No error"; break;
    case 0x02: str = "Temporary Condition"; break;
    case 0x03: str = "Permanent Condition"; break;
    default:
	str = "Reserved";
	break;
    }

    g_snprintf(add_string, string_len, " - Reply Sequence Number (%d)", (oct & 0xfc) >> 2);

    other_decode_bitfield_value(ansi_637_bigbuf, oct, 0x03, 8);
    proto_tree_add_text(tree, tvb, offset, 1,
	"%s :  Error Class: %s",
	ansi_637_bigbuf,
	str);

    offset++;

    if (!(oct & 0x03)) return;

    if (len == 1) return;

    oct = tvb_get_guint8(tvb, offset);

    switch (oct)
    {
    case 0: str = "Address vacant"; break;
    case 1: str = "Address translation failure"; break;
    case 2: str = "Network resource shortage"; break;
    case 3: str = "Network failure"; break;
    case 4: str = "Invalid Teleservice ID"; break;
    case 5: str = "Other network problem"; break;
    case 6: str = "Unsupported network interface"; break;
    case 32: str = "No page response"; break;
    case 33: str = "Destination busy"; break;
    case 34: str = "No acknowledgement"; break;
    case 35: str = "Destination resource shortage"; break;
    case 36: str = "SMS delivery postponed"; break;
    case 37: str = "Destination out of service"; break;
    case 38: str = "Destination no longer at this address"; break;
    case 39: str = "Other terminal problem"; break;
    case 64: str = "Radio interface resource shortage"; break;
    case 65: str = "Radio interface incompatibility"; break;
    case 66: str = "Other radio interface problem"; break;
    case 67: str = "Unsupported Base Station Capability"; break;
    case 96: str = "Encoding problem"; break;
    case 97: str = "Service origination denied"; break;
    case 98: str = "Service termination denied"; break;
    case 99: str = "Supplementary service not supported"; break;
    case 100: str = "Service not supported"; break;
    case 101: str = "Reserved"; break;
    case 102: str = "Missing expected parameter"; break;
    case 103: str = "Missing mandatory parameter"; break;
    case 104: str = "Unrecognized parameter value"; break;
    case 105: str = "Unexpected parameter value"; break;
    case 106: str = "User Data size error"; break;
    case 107: str = "Other general problems"; break;
    case 108: str = "Session not active"; break;
    default:
	if ((oct >= 7) && (oct <= 31)) { str = "Reserved, treat as Other network problem"; }
	else if ((oct >= 40) && (oct <= 47)) { str = "Reserved, treat as Other terminal problem"; }
	else if ((oct >= 48) && (oct <= 63)) { str = "Reserved, treat as SMS delivery postponed"; }
	else if ((oct >= 68) && (oct <= 95)) { str = "Reserved, treat as Other radio interface problem"; }
	else if ((oct >= 109) && (oct <= 223)) { str = "Reserved, treat as Other general problems"; }
	else { str = "Reserved for protocol extension, treat as Other general problems"; }
	break;
    }

    proto_tree_add_text(tree, tvb, offset, 1,
	str);
}

static void
trans_param_bearer_data(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset, gchar *add_string _U_, int string_len)
{
    tvbuff_t	*tele_tvb;

    proto_tree_add_text(tree, tvb, offset, len,
	"Bearer Data");

    /*
     * dissect the embedded teleservice data
     */
    tele_tvb = tvb_new_subset(tvb, offset, len, len);

    dissector_try_port(tele_dissector_table, ansi_637_trans_tele_id,
	tele_tvb, g_pinfo, g_tree);
}

#define	NUM_TRANS_PARAM (sizeof(ansi_trans_param_strings)/sizeof(value_string))
static gint ett_ansi_637_trans_param[NUM_TRANS_PARAM];
static void (*ansi_637_trans_param_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset, gchar *add_string, int string_len) = {
    trans_param_tele_id,	/* Teleservice Identifier */
    trans_param_srvc_cat,	/* Service Category */
    trans_param_address,	/* Originating Address */
    trans_param_subaddress,	/* Originating Subaddress */
    trans_param_address,	/* Destination Address */
    trans_param_subaddress,	/* Destination Subaddress */
    trans_param_bearer_reply_opt,	/* Bearer Reply Option */
    trans_param_cause_codes,	/* Cause Codes */
    trans_param_bearer_data,	/* Bearer Data */
    NULL,	/* NONE */
};

#define	NUM_TRANS_MSG_TYPE (sizeof(ansi_trans_msg_type_strings)/sizeof(value_string))
static gint ett_ansi_637_trans_msg[NUM_TRANS_MSG_TYPE];

/* GENERIC IS-637 DISSECTOR FUNCTIONS */

static gboolean
dissect_ansi_637_tele_param(tvbuff_t *tvb, proto_tree *tree, guint32 *offset)
{
    void (*param_fcn)(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = NULL;
    guint8	oct;
    guint8	len;
    guint32	curr_offset;
    gint	ett_param_idx, idx;
    proto_tree	*subtree;
    proto_item	*item;
    const gchar	*str = NULL;


    curr_offset = *offset;

    oct = tvb_get_guint8(tvb, curr_offset);
    str = match_strval_idx((guint32) oct, ansi_tele_param_strings, &idx);

    if (NULL == str)
    {
	return(FALSE);
    }

    ett_param_idx = ett_ansi_637_tele_param[idx];
    param_fcn = ansi_637_tele_param_fcn[idx];

    item =
	proto_tree_add_text(tree, tvb, curr_offset, -1, str);

    subtree = proto_item_add_subtree(item, ett_param_idx);

    proto_tree_add_uint(subtree, hf_ansi_637_tele_subparam_id,
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
	    proto_tree_add_text(subtree, tvb, curr_offset,
		len, "Parameter Data");
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
dissect_ansi_637_tele_message(tvbuff_t *tvb, proto_tree *ansi_637_tree)
{
    guint8	oct;
    guint8	len;
    guint32	octs;
    guint32	curr_offset;
    /* guint32	msg_id; */
    guint32	msg_type;
    const gchar	*str = NULL;
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
    /* msg_id = (octs >> 4) & 0xffff; */

    str = match_strval(msg_type, ansi_tele_msg_type_strings);

    /*
     * do not append to COL_INFO
     */

    item =
	proto_tree_add_none_format(ansi_637_tree, hf_ansi_637_none,
	    tvb, 0, -1, str);

    subtree = proto_item_add_subtree(item, ett_params);

    proto_tree_add_uint(subtree, hf_ansi_637_tele_subparam_id,
	tvb, 0, 1, oct);

    proto_tree_add_uint(subtree, hf_ansi_637_length,
	tvb, 1, 1, len);

    proto_tree_add_uint(subtree, hf_ansi_637_tele_msg_type,
	tvb, 2, 3, octs);

    proto_tree_add_uint(subtree, hf_ansi_637_tele_msg_id,
	tvb, 2, 3, octs);

    proto_tree_add_uint(subtree, hf_ansi_637_tele_msg_rsvd,
	tvb, 2, 3, octs);

    proto_item_set_len(item, 2 + len);

    curr_offset = 2 + len;
    len = tvb_length(tvb);

    while ((len - curr_offset) > 0)
    {
	if (!dissect_ansi_637_tele_param(tvb, ansi_637_tree, &curr_offset))
	{
	    proto_tree_add_text(ansi_637_tree, tvb, curr_offset, len - curr_offset,
		"Unknown Parameter Data");
	    break;
	}
    }
}

static void
dissect_ansi_637_tele(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item	*ansi_637_item;
    proto_tree	*ansi_637_tree = NULL;
    const gchar	*str = NULL;
    guint32	value;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, ansi_proto_name_short);
    }

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree)
    {
	value = pinfo->match_port;

	/*
	 * create the ansi_637 protocol tree
	 */
	str = match_strval(value, ansi_tele_id_strings);

	if (NULL == str)
	{
	    switch (value)
	    {
	    case 1:
		str = "Reserved for maintenance";
		break;
	    case 4102:
		str = "CDMA Service Category Programming Teleservice (SCPT)";
		break;
	    case 4103:
		str = "CDMA Card Application Toolkit Protocol Teleservice (CATPT)";
		break;
	    case 32513:
		str = "TDMA Cellular Messaging Teleservice";
		break;
	    case 32514:
		str = "TDMA Cellular Paging Teleservice (CPT-136)";
		break;
	    case 32515:
		str = "TDMA Over-the-Air Activation Teleservice (OATS)";
		break;
	    case 32520:
		str = "TDMA System Assisted Mobile Positioning through Satellite (SAMPS)";
		break;
	    case 32584:
		str = "TDMA Segmented System Assisted Mobile Positioning Service";
		break;
	    default:
		if ((value >= 2) && (value <= 4095))
		{
		    str = "Reserved for assignment by TIA-41";
		}
		else if ((value >= 4104) && (value <= 4113))
		{
		    str = "Reserved for GSM1x Teleservice (CDMA)";
		}
		else if ((value >= 4114) && (value <= 32512))
		{
		    str = "Reserved for assignment by TIA-41";
		}
		else if ((value >= 32521) && (value <= 32575))
		{
		    str = "Reserved for assignment by this Standard for TDMA MS-based SMEs";
		}
		else if ((value >= 49152) && (value <= 65535))
		{
		    str = "Reserved for carrier specific teleservices";
		}
		else
		{
		    str = "Unrecognized Teleservice ID";
		}
		break;
	    }
	}

	ansi_637_item =
	    proto_tree_add_protocol_format(tree, proto_ansi_637_tele, tvb, 0, -1,
		"%s - %s (%d)",
		ansi_proto_name_tele,
		str,
		pinfo->match_port);

	ansi_637_tree =
	    proto_item_add_subtree(ansi_637_item, ett_ansi_637_tele);

	dissect_ansi_637_tele_message(tvb, ansi_637_tree);
    }
}

static gboolean
dissect_ansi_637_trans_param(tvbuff_t *tvb, proto_tree *tree, guint32 *offset)
{
    void (*param_fcn)(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset, gchar *add_string, int string_len) = NULL;
    guint8	oct;
    guint8	len;
    guint32	curr_offset;
    gint	ett_param_idx, idx;
    proto_tree	*subtree;
    proto_item	*item;
    const gchar	*str = NULL;

    curr_offset = *offset;

    oct = tvb_get_guint8(tvb, curr_offset);
    str = match_strval_idx((guint32) oct, ansi_trans_param_strings, &idx);

    if (NULL == str)
    {
	return(FALSE);
    }

    ett_param_idx = ett_ansi_637_trans_param[idx];
    param_fcn = ansi_637_trans_param_fcn[idx];

    item =
	proto_tree_add_text(tree, tvb, curr_offset, -1, str);

    subtree = proto_item_add_subtree(item, ett_param_idx);

    proto_tree_add_uint(subtree, hf_ansi_637_trans_param_id,
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
	    proto_tree_add_text(subtree, tvb, curr_offset,
		len, "Parameter Data");
	}
	else
	{
            gchar *ansi_637_add_string;

	    ansi_637_add_string = ep_alloc(1024);
	    ansi_637_add_string[0] = '\0';
	    (*param_fcn)(tvb, subtree, len, curr_offset, ansi_637_add_string, 1024);

	    if (ansi_637_add_string[0] != '\0')
	    {
		proto_item_append_text(item, "%s", ansi_637_add_string);
	    }
	}

	curr_offset += len;
    }

    *offset = curr_offset;

    return(TRUE);
}

static void
dissect_ansi_637_trans(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item	*ansi_637_item;
    proto_tree	*ansi_637_tree = NULL;
    guint32	curr_offset;
    gint	idx;
    const gchar	*str = NULL;
    guint8	oct;
    guint8	len;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, ansi_proto_name_short);
    }

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree)
    {
	g_pinfo = pinfo;
	g_tree = tree;

	/*
	 * create the ansi_637 protocol tree
	 */
	oct = tvb_get_guint8(tvb, 0);

	str = match_strval_idx(oct, ansi_trans_msg_type_strings, &idx);

	if (NULL == str)
	{
	    ansi_637_item =
		proto_tree_add_protocol_format(tree, proto_ansi_637_trans, tvb, 0, -1,
		    "%s - Unrecognized Transport Layer Message Type (%d)",
		    ansi_proto_name_trans,
		    oct);

	    ansi_637_tree =
		proto_item_add_subtree(ansi_637_item, ett_ansi_637_trans);
	}
	else
	{
	    ansi_637_item =
		proto_tree_add_protocol_format(tree, proto_ansi_637_trans, tvb, 0, -1,
		    "%s - %s",
		    ansi_proto_name_trans,
		    str);

	    ansi_637_tree =
		proto_item_add_subtree(ansi_637_item, ett_ansi_637_trans_msg[idx]);
	}

	curr_offset = 1;

	len = tvb_length(tvb);

	while ((len - curr_offset) > 0)
	{
	    if (!dissect_ansi_637_trans_param(tvb, ansi_637_tree, &curr_offset))
	    {
		proto_tree_add_text(ansi_637_tree, tvb, curr_offset, len - curr_offset,
		    "Unknown Parameter Data");
		break;
	    }
	}
    }
}

/* Register the protocol with Wireshark */
void
proto_register_ansi_637(void)
{
    guint		i;

    /* Setup list of header fields */
    static hf_register_info hf[] =
    {
	{ &hf_ansi_637_trans_msg_type,
	  { "Message Type",
	    "ansi_637.trans_msg_type",
	    FT_UINT24, BASE_DEC, VALS(ansi_trans_msg_type_strings), 0xf00000,
	    "", HFILL }},
	{ &hf_ansi_637_tele_msg_type,
	  { "Message Type",
	    "ansi_637.tele_msg_type",
	    FT_UINT24, BASE_DEC, VALS(ansi_tele_msg_type_strings), 0xf00000,
	    "", HFILL }},
	{ &hf_ansi_637_tele_msg_id,
	  { "Message ID",
	    "ansi_637.tele_msg_id",
	    FT_UINT24, BASE_DEC, NULL, 0x0ffff0,
	    "", HFILL }},
	{ &hf_ansi_637_tele_msg_rsvd,
	  { "Reserved",
	    "ansi_637.tele_msg_rsvd",
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
	{ &hf_ansi_637_tele_subparam_id,
	    { "Teleservice Subparam ID",	"ansi_637.tele_subparam_id",
	    FT_UINT8, BASE_DEC, VALS(ansi_tele_param_strings), 0,
	    "", HFILL }
	},
	{ &hf_ansi_637_trans_param_id,
	    { "Transport Param ID",	"ansi_637.trans_param_id",
	    FT_UINT8, BASE_DEC, VALS(ansi_trans_param_strings), 0,
	    "", HFILL }
	},
	{ &hf_ansi_637_bin_addr,
	    { "Binary Address",	"ansi_637.bin_addr",
	    FT_BYTES, BASE_HEX, 0, 0,
	    "", HFILL }
	},
    };

    /* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_PARAMS	3
    static gint *ett[NUM_INDIVIDUAL_PARAMS+NUM_TELE_PARAM+NUM_TRANS_MSG_TYPE+NUM_TRANS_PARAM];

    memset((void *) ett, 0, sizeof(ett));

    ett[0] = &ett_ansi_637_tele;
    ett[1] = &ett_ansi_637_trans;
    ett[2] = &ett_params;

    for (i=0; i < NUM_TELE_PARAM; i++)
    {
	ett_ansi_637_tele_param[i] = -1;
	ett[NUM_INDIVIDUAL_PARAMS+i] = &ett_ansi_637_tele_param[i];
    }

    for (i=0; i < NUM_TRANS_MSG_TYPE; i++)
    {
	ett_ansi_637_trans_msg[i] = -1;
	ett[NUM_INDIVIDUAL_PARAMS+NUM_TELE_PARAM+i] = &ett_ansi_637_trans_msg[i];
    }

    for (i=0; i < NUM_TRANS_PARAM; i++)
    {
	ett_ansi_637_trans_param[i] = -1;
	ett[NUM_INDIVIDUAL_PARAMS+NUM_TELE_PARAM+NUM_TRANS_MSG_TYPE+i] = &ett_ansi_637_trans_param[i];
    }

    /* Register the protocol name and description */
    proto_ansi_637_tele =
	proto_register_protocol(ansi_proto_name_tele, "ANSI IS-637-A Teleservice", "ansi_637_tele");

    proto_ansi_637_trans =
	proto_register_protocol(ansi_proto_name_trans, "ANSI IS-637-A Transport", "ansi_637_trans");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ansi_637_tele, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    tele_dissector_table =
	register_dissector_table("ansi_637.tele_id",
	    "ANSI IS-637-A Teleservice ID", FT_UINT8, BASE_DEC);
}


void
proto_reg_handoff_ansi_637(void)
{
    dissector_handle_t	ansi_637_tele_handle;
    dissector_handle_t	ansi_637_trans_handle;
    guint		i;

    ansi_637_tele_handle = create_dissector_handle(dissect_ansi_637_tele, proto_ansi_637_tele);
    ansi_637_trans_handle = create_dissector_handle(dissect_ansi_637_trans, proto_ansi_637_trans);

    /*
     * register for all known teleservices
     * '-1' is to stop before trailing '0' entry
     *
     * to add teleservices, modify 'ansi_tele_id_strings'
     */
    for (i=0; i < ((sizeof(ansi_tele_id_strings)/sizeof(value_string))-1); i++)
    {
	/*
	 * ANSI MAP dissector will push out teleservice ids
	 */
	dissector_add("ansi_map.tele_id", ansi_tele_id_strings[i].value, ansi_637_tele_handle);

	/*
	 * we will push out teleservice ids after Transport layer decode
	 */
	dissector_add("ansi_637.tele_id", ansi_tele_id_strings[i].value, ansi_637_tele_handle);
    }

    /*
     * ANSI A-interface will push out transport layer data
     */
    dissector_add("ansi_a.sms", 0, ansi_637_trans_handle);

    /* data_handle = find_dissector("data"); */
}
