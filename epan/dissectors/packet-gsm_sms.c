/* packet-gsm_sms.c
 * Routines for GSM SMS TPDU (GSM 03.40) dissection
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * TPDU User-Data unpack routines from GNOKII.
 *
 *   Reference [1]
 *   Universal Mobile Telecommunications System (UMTS);
 *   Technical realization of Short Message Service (SMS)
 *   (3GPP TS 23.040 version 5.4.0 Release 5)
 *
 * $Id$
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
#include <epan/prefs.h>

#include "packet-gsm_sms.h"


/* PROTOTYPES/FORWARDS */

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

#define	SMS_SHIFTMASK(m_val, m_bitmask, m_sval); \
    { \
	int	_temp_val = m_val; \
	int	_temp_bm = m_bitmask; \
	while (_temp_bm && !(_temp_bm & 0x01)) \
	{ \
	    _temp_bm = _temp_bm >> 1; \
	    _temp_val = _temp_val >> 1; \
	} \
	m_sval = _temp_val; \
    }


static const char *gsm_sms_proto_name = "GSM SMS TPDU (GSM 03.40)";
static const char *gsm_sms_proto_name_short = "GSM SMS";

/* Initialize the subtree pointers */
static gint ett_gsm_sms = -1;
static gint ett_pid = -1;
static gint ett_pi = -1;
static gint ett_fcs = -1;
static gint ett_vp = -1;
static gint ett_scts = -1;
static gint ett_dt = -1;
static gint ett_st = -1;
static gint ett_addr = -1;
static gint ett_dcs = -1;
static gint ett_ud = -1;
static gint ett_udh = -1;

/* Initialize the protocol and registered fields */
static int proto_gsm_sms = -1;

static char bigbuf[1024];
static dissector_handle_t data_handle;
static packet_info *g_pinfo;
static proto_tree *g_tree;

/*
 * this is the GSM 03.40 definition with the bit 2
 * set to 1 for uplink messages
 */
static const value_string msg_type_strings[] = {
    { 0,	"SMS-DELIVER" },
    { 4,	"SMS-DELIVER REPORT" },
    { 5,	"SMS-SUBMIT" },
    { 1,	"SMS-SUBMIT REPORT" },
    { 2,	"SMS-STATUS REPORT" },
    { 6,	"SMS-COMMAND" },
    { 3,	"Reserved" },
    { 7,	"Reserved" },
    { 0, NULL },
};

#define	NUM_UDH_IEIS	256
static gint ett_udh_ieis[NUM_UDH_IEIS];

/* FUNCTIONS */

/* 9.2.3.1 */
#define DIS_FIELD_MTI(m_tree, m_bitmask, m_offset) \
{ \
    other_decode_bitfield_value(bigbuf, oct, m_bitmask, 8); \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"%s :  TP-Message-Type-Indicator", \
	bigbuf); \
}

/* 9.2.3.2 */
#define DIS_FIELD_MMS(m_tree, m_bitmask, m_offset) \
{ \
    other_decode_bitfield_value(bigbuf, oct, m_bitmask, 8); \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"%s :  TP-More-Messages-to-Send: %s messages are waiting for the MS in this SC", \
	bigbuf, \
	(oct & m_bitmask) ? "No more" : "More"); \
}

/* 9.2.3.3 */
#define DIS_FIELD_VPF(m_tree, m_bitmask, m_offset, m_form) \
{ \
    SMS_SHIFTMASK(oct & m_bitmask, m_bitmask, *m_form); \
    switch (*m_form) \
    { \
    case 0: str = "TP-VP field not present"; break; \
    case 1: str = "TP-VP field present - enhanced format"; break; \
    case 2: str = "TP-VP field present - relative format"; break; \
    case 3: str = "TP-VP field present - absolute format"; break; \
    } \
    other_decode_bitfield_value(bigbuf, oct, m_bitmask, 8); \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"%s :  TP-Validity-Period-Format: %s", \
	bigbuf, \
	str); \
}

/* 9.2.3.4 */
#define DIS_FIELD_SRI(m_tree, m_bitmask, m_offset) \
{ \
    other_decode_bitfield_value(bigbuf, oct, m_bitmask, 8); \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"%s :  TP-Status-Report-Indication: A status report shall %sbe returned to the SME", \
	bigbuf, \
	(oct & m_bitmask) ? "" : "not "); \
}

/* 9.2.3.5 */
#define DIS_FIELD_SRR(m_tree, m_bitmask, m_offset) \
{ \
    other_decode_bitfield_value(bigbuf, oct, m_bitmask, 8); \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"%s :  TP-Status-Report-Request: A status report is %srequested", \
	bigbuf, \
	(oct & m_bitmask) ? "" : "not "); \
}

/* 9.2.3.6 */
#define DIS_FIELD_MR(m_tree, m_offset) \
{ \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"TP-Message-Reference %d", \
	oct); \
}

static void
dis_field_addr(tvbuff_t *tvb, proto_tree *tree, guint32 *offset_p, const gchar *title)
{
    static gchar	digit_table[] = {"0123456789*#abc\0"};
    proto_item		*item;
    proto_tree		*subtree = NULL;
    const gchar		*str = NULL;
    guint8		oct;
    guint32		offset;
    guint32		numdigocts;
    guint32		length;
    guint32		i, j;

    offset = *offset_p;

    oct = tvb_get_guint8(tvb, offset);
    numdigocts = (oct + 1) / 2;

    length = tvb_length_remaining(tvb, offset);

    if (length <= numdigocts)
    {
	proto_tree_add_text(tree,
	    tvb, offset, length,
	    "%s: Short Data (?)",
	    title);

	*offset_p += length;
	return;
    }

    item =
	proto_tree_add_text(tree, tvb,
	    offset, numdigocts + 2,
	    title);

    subtree = proto_item_add_subtree(item, ett_addr);

    proto_tree_add_text(subtree,
	tvb, offset, 1,
	"Length: %d address digits",
	oct);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_text(subtree, tvb,
	offset, 1,
	"%s :  %s",
	bigbuf,
	(oct & 0x80) ? "No extension" : "Extended");

    switch ((oct & 0x70) >> 4)
    {
    case 0x00: str = "Unknown"; break;
    case 0x01: str = "International"; break;
    case 0x02: str = "National"; break;
    case 0x03: str = "Network specific"; break;
    case 0x04: str = "Subscriber"; break;
    case 0x05: str = "Alphanumeric (coded according to 3GPP TS 23.038 GSM 7-bit default alphabet)"; break;
    case 0x06: str = "Abbreviated number"; break;
    case 0x07: str = "Reserved for extension"; break;
    default: str = "Unknown, reserved (?)"; break;
    }

    other_decode_bitfield_value(bigbuf, oct, 0x70, 8);
    proto_tree_add_text(subtree,
	tvb, offset, 1,
	"%s :  Type of number: (%d) %s",
	bigbuf,
	(oct & 0x70) >> 4,
	str);

    switch (oct & 0x0f)
    {
    case 0x00: str = "Unknown"; break;
    case 0x01: str = "ISDN/telephone (E.164/E.163)"; break;
    case 0x03: str = "Data numbering plan (X.121)"; break;
    case 0x04: str = "Telex numbering plan"; break;
    case 0x05: str = "Service Centre Specific plan"; break;
    case 0x06: str = "Service Centre Specific plan"; break;
    case 0x08: str = "National numbering plan"; break;
    case 0x09: str = "Private numbering plan"; break;
    case 0x0a: str = "ERMES numbering plan (ETSI DE/PS 3 01-3)"; break;
    case 0x0f: str = "Reserved for extension"; break;
    default: str = "Unknown, reserved (?)"; break;
    }

    other_decode_bitfield_value(bigbuf, oct, 0x0f, 8);
    proto_tree_add_text(subtree,
	tvb, offset, 1,
	"%s :  Numbering plan: (%d) %s",
	bigbuf,
	oct & 0x0f,
	str);

    offset++;

    j = 0;
    switch ((oct & 0x70) >> 4)
    {
    case 0x05: /* "Alphanumeric (coded according to 3GPP TS 23.038 GSM 7-bit default alphabet)" */
	i = gsm_sms_char_7bit_unpack(0, numdigocts, sizeof(bigbuf), tvb_get_ptr(tvb, offset, numdigocts), bigbuf);
	bigbuf[i] = '\0';
	gsm_sms_char_ascii_decode(bigbuf, bigbuf, i);
	break;
    default:
	for (i = 0; i < numdigocts; i++)
	{
	    oct = tvb_get_guint8(tvb, offset + i);

	    bigbuf[j++] = digit_table[oct & 0x0f];
	    bigbuf[j++] = digit_table[(oct & 0xf0) >> 4];
	}
	bigbuf[j++] = '\0';
	break;
    }

    proto_tree_add_text(subtree,
	tvb, offset, numdigocts,
	"Digits: %s",
	bigbuf);

    proto_item_append_text(item, " - (%s)", bigbuf);

    *offset_p = offset + numdigocts;
}

/* 9.2.3.7 */
/* use dis_field_addr() */

/* 9.2.3.8 */
/* use dis_field_addr() */

/* 9.2.3.9 */
static void
dis_field_pid(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 oct)
{
    proto_item	*item;
    proto_tree	*subtree = NULL;
    guint8	form;
    guint8	telematic;
    const gchar	*str = NULL;


    item =
	proto_tree_add_text(tree, tvb,
	    offset, 1,
	    "TP-Protocol-Identifier");

    subtree = proto_item_add_subtree(item, ett_pid);

    form = (oct & 0xc0) >> 6;

    switch (form)
    {
    case 0:
	other_decode_bitfield_value(bigbuf, oct, 0xc0, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  defines formatting for subsequent bits",
	    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x20, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  %s",
	    bigbuf,
	    (oct & 0x20) ?
	    "telematic interworking" :
	    "no telematic interworking, but SME-to-SME protocol");

	if (oct & 0x20)
	{
	    telematic = oct & 0x1f;

	    switch (telematic)
	    {
	    case 0x00: str = "implicit - device type is specific to this SC, or can be concluded on the basis of the address"; break;
	    case 0x01: str = "telex (or teletex reduced to telex format)"; break;
	    case 0x02: str = "group 3 telefax"; break;
	    case 0x03: str = "group 4 telefax"; break;
	    case 0x04: str = "voice telephone (i.e. conversion to speech)"; break;
	    case 0x05: str = "ERMES (European Radio Messaging System)"; break;
	    case 0x06: str = "National Paging system (known to the SC)"; break;
	    case 0x07: str = "Videotex (T.100 [20] /T.101 [21])"; break;
	    case 0x08: str = "teletex, carrier unspecified"; break;
	    case 0x09: str = "teletex, in PSPDN"; break;
	    case 0x0a: str = "teletex, in CSPDN"; break;
	    case 0x0b: str = "teletex, in analog PSTN"; break;
	    case 0x0c: str = "teletex, in digital ISDN"; break;
	    case 0x0d: str = "UCI (Universal Computer Interface, ETSI DE/PS 3 01-3)"; break;
	    case 0x10: str = "a message handling facility (known to the SC)"; break;
	    case 0x11: str = "any public X.400-based message handling system"; break;
	    case 0x12: str = "Internet Electronic Mail"; break;
	    case 0x1f: str = "A GSM/UMTS mobile station"; break;
	    default:
		if ((telematic >= 0x18) &&
		    (telematic <= 0x1e))
		{
		    str = "values specific to each SC";
		}
		else
		{
		    str = "reserved";
		}
		break;
	    }

	    other_decode_bitfield_value(bigbuf, oct, 0x1f, 8);
	    proto_tree_add_text(subtree, tvb,
		offset, 1,
		"%s :  device type: (%d) %s",
		bigbuf,
		telematic,
		str);
	}
	else
	{
	    other_decode_bitfield_value(bigbuf, oct, 0x1f, 8);
	    proto_tree_add_text(subtree, tvb,
		offset, 1,
		"%s :  the SM-AL protocol being used between the SME and the MS (%d)",
		bigbuf,
		oct & 0x1f);
	}
	break;

    case 1:
	other_decode_bitfield_value(bigbuf, oct, 0xc0, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  defines formatting for subsequent bits",
	    bigbuf);

	switch (oct & 0x3f)
	{
	case 0x00: str = "Short Message Type 0"; break;
	case 0x01: str = "Replace Short Message Type 1"; break;
	case 0x02: str = "Replace Short Message Type 2"; break;
	case 0x03: str = "Replace Short Message Type 3"; break;
	case 0x04: str = "Replace Short Message Type 4"; break;
	case 0x05: str = "Replace Short Message Type 5"; break;
	case 0x06: str = "Replace Short Message Type 6"; break;
	case 0x07: str = "Replace Short Message Type 7"; break;
	case 0x1e: str = "Enhanced Message Service (Obsolete)"; break;
	case 0x1f: str = "Return Call Message"; break;
	case 0x3c: str = "ANSI-136 R-DATA"; break;
	case 0x3d: str = "ME Data download"; break;
	case 0x3e: str = "ME De-personalization Short Message"; break;
	case 0x3f: str = "(U)SIM Data download"; break;
	default:
	    str = "Reserved"; break;
	}

	other_decode_bitfield_value(bigbuf, oct, 0x3f, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  (%d) %s",
	    bigbuf,
	    oct & 0x3f,
	    str);
	break;

    case 2:
	other_decode_bitfield_value(bigbuf, oct, 0xc0, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  Reserved",
	    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x3f, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  undefined",
	    bigbuf);
	break;

    case 3:
	other_decode_bitfield_value(bigbuf, oct, 0xc0, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  bits 0-5 for SC specific use",
	    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x3f, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  SC specific",
	    bigbuf);
	break;
    }
}

/* 9.2.3.10 */
static void
dis_field_dcs(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 oct,
    gboolean *seven_bit, gboolean *eight_bit, gboolean *ucs2, gboolean *compressed)
{
    proto_item	*item;
    proto_tree	*subtree = NULL;
    guint8	form;
    const gchar	*str = NULL;
    gboolean	default_5_bits;
    gboolean	default_3_bits;
    gboolean	default_data;


    *seven_bit = FALSE;
    *eight_bit = FALSE;
    *ucs2 = FALSE;
    *compressed = FALSE;

    item =
	proto_tree_add_text(tree, tvb,
	    offset, 1,
	    "TP-Data-Coding-Scheme (%d)",
	    oct);

    subtree = proto_item_add_subtree(item, ett_dcs);

    if (oct == 0x00)
    {
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "Special case, GSM 7 bit default alphabet");

	*seven_bit = TRUE;
	return;
    }

    default_5_bits = FALSE;
    default_3_bits = FALSE;
    default_data = FALSE;
    form = (oct & 0xc0) >> 6;

    switch (form)
    {
    case 0:
	other_decode_bitfield_value(bigbuf, oct, 0xc0, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  General Data Coding indication",
	    bigbuf);

	default_5_bits = TRUE;
	break;

    case 1:
	other_decode_bitfield_value(bigbuf, oct, 0xc0, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  Message Marked for Automatic Deletion Group",
	    bigbuf);

	default_5_bits = TRUE;
	break;

    case 2:
	/* use top four bits */
	other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  Reserved coding groups",
	    bigbuf);
	return;

    case 3:
	switch ((oct & 0x30) >> 4)
	{
	case 0x00: str = "Message Waiting Indication Group: Discard Message (GSM 7 bit default alphabet)";
	    default_3_bits = TRUE;
	    *seven_bit = TRUE;
	    break;
	case 0x01: str = "Message Waiting Indication Group: Store Message (GSM 7 bit default alphabet)";
	    default_3_bits = TRUE;
	    *seven_bit = TRUE;
	    break;
	case 0x02: str = "Message Waiting Indication Group: Store Message (uncompressed UCS2 alphabet)";
	    default_3_bits = TRUE;
	    break;
	case 0x03: str = "Data coding/message class";
	    default_data = TRUE;
	    break;
	}

	/* use top four bits */
	other_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  %s",
	    bigbuf,
	    str);
	break;
    }

    if (default_5_bits)
    {
	other_decode_bitfield_value(bigbuf, oct, 0x20, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  Text is %scompressed",
	    bigbuf,
	    (oct & 0x20) ?  "" : "not ");

	*compressed = (oct & 0x20) >> 5;

	other_decode_bitfield_value(bigbuf, oct, 0x10, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  %s",
	    bigbuf,
	    (oct & 0x10) ?  "Message class is defined below" :
		"Reserved, no message class");

	switch ((oct & 0x0c) >> 2)
	{
	case 0x00: str = "GSM 7 bit default alphabet";
	    *seven_bit = TRUE;
	    break;
	case 0x01: str = "8 bit data"; break;
	case 0x02: str = "UCS2 (16 bit)";
	    *ucs2 = TRUE;
	    break;
	case 0x03: str = "Reserved"; break;
	}

	other_decode_bitfield_value(bigbuf, oct, 0x0c, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  Character set: %s",
	    bigbuf,
	    str);

	switch (oct & 0x03)
	{
	case 0x00: str = "Class 0"; break;
	case 0x01: str = "Class 1 Default meaning: ME-specific"; break;
	case 0x02: str = "Class 2 (U)SIM specific message"; break;
	case 0x03: str = "Class 3 Default meaning: TE-specific"; break;
	}

	other_decode_bitfield_value(bigbuf, oct, 0x03, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  Message Class: %s%s",
	    bigbuf,
	    str,
	    (oct & 0x10) ?  "" : " (reserved)");
    }
    else if (default_3_bits)
    {
	other_decode_bitfield_value(bigbuf, oct, 0x08, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  Indication Sense: %s",
	    bigbuf,
	    (oct & 0x08) ?  "Set Indication Active" : "Set Indication Inactive");

	other_decode_bitfield_value(bigbuf, oct, 0x04, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  Reserved",
	    bigbuf);

	switch (oct & 0x03)
	{
	case 0x00: str = "Voicemail Message Waiting"; break;
	case 0x01: str = "Fax Message Waiting"; break;
	case 0x02: str = "Electronic Mail Message Waiting"; break;
	case 0x03: str = "Other Message Waiting"; break;
	}

	other_decode_bitfield_value(bigbuf, oct, 0x03, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  %s",
	    bigbuf,
	    str);
    }
    else if (default_data)
    {
	other_decode_bitfield_value(bigbuf, oct, 0x08, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  Reserved",
	    bigbuf);

	*seven_bit = !(*eight_bit = (oct & 0x04) ? TRUE : FALSE);

	other_decode_bitfield_value(bigbuf, oct, 0x04, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  Message coding: %s",
	    bigbuf,
	    (*eight_bit) ? "8 bit data" : "GSM 7 bit default alphabet");

	switch (oct & 0x03)
	{
	case 0x00: str = "Class 0"; break;
	case 0x01: str = "Class 1 Default meaning: ME-specific"; break;
	case 0x02: str = "Class 2 (U)SIM specific message"; break;
	case 0x03: str = "Class 3 Default meaning: TE-specific"; break;
	}

	other_decode_bitfield_value(bigbuf, oct, 0x03, 8);
	proto_tree_add_text(subtree, tvb,
	    offset, 1,
	    "%s :  Message Class: %s",
	    bigbuf,
	    str);
    }
}

static void
dis_field_scts_aux(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    guint8	oct, oct2, oct3;
    char sign;


    oct = tvb_get_guint8(tvb, offset);
    oct2 = tvb_get_guint8(tvb, offset+1);
    oct3 = tvb_get_guint8(tvb, offset+2);

    proto_tree_add_text(tree,
	tvb, offset, 3,
	"Year %d%d, Month %d%d, Day %d%d",
	oct & 0x0f,
	(oct & 0xf0) >> 4,
	oct2 & 0x0f,
	(oct2 & 0xf0) >> 4,
	oct3 & 0x0f,
	(oct3 & 0xf0) >> 4);

    offset += 3;

    oct = tvb_get_guint8(tvb, offset);
    oct2 = tvb_get_guint8(tvb, offset+1);
    oct3 = tvb_get_guint8(tvb, offset+2);

    proto_tree_add_text(tree,
	tvb, offset, 3,
	"Hour %d%d, Minutes %d%d, Seconds %d%d",
	oct & 0x0f,
	(oct & 0xf0) >> 4,
	oct2 & 0x0f,
	(oct2 & 0xf0) >> 4,
	oct3 & 0x0f,
	(oct3 & 0xf0) >> 4);

    offset += 3;

    oct = tvb_get_guint8(tvb, offset);

    sign = (oct & 0x08)?'-':'+';
    oct = (oct >> 4) + (oct & 0x07) * 10;

    proto_tree_add_text(tree,
	tvb, offset, 1,
	"Timezone: GMT %c %d hours %d minutes",
	sign, oct / 4, oct % 4 * 15);
}

/* 9.2.3.11 */
static void
dis_field_scts(tvbuff_t *tvb, proto_tree *tree, guint32 *offset_p)
{
    proto_item	*item;
    proto_tree	*subtree = NULL;
    guint32	offset;
    guint32	length;


    offset = *offset_p;

    length = tvb_length_remaining(tvb, offset);

    if (length < 7)
    {
	proto_tree_add_text(tree,
	    tvb, offset, length,
	    "TP-Service-Centre-Time-Stamp: Short Data (?)");

	*offset_p += length;
	return;
    }

    item =
	proto_tree_add_text(tree, tvb,
	    offset, 7,
	    "TP-Service-Centre-Time-Stamp");

    subtree = proto_item_add_subtree(item, ett_scts);

    dis_field_scts_aux(tvb, subtree, *offset_p);

    *offset_p += 7;
}

/* 9.2.3.12 */
static void
dis_field_vp(tvbuff_t *tvb, proto_tree *tree, guint32 *offset_p, guint8 vp_form)
{
    proto_item	*item;
    proto_tree	*subtree = NULL;
    guint32	offset;
    guint32	length;
    guint8	oct, oct2, oct3;
    guint8	loc_form;
    guint32	mins, hours;
    gboolean	done;


    if (vp_form == 0x00) return;

    offset = *offset_p;
    subtree = tree;

    done = FALSE;
    do
    {
	switch (vp_form)
	{
	case 1:
	    length = tvb_length_remaining(tvb, offset);

	    if (length < 7)
	    {
		proto_tree_add_text(tree,
		    tvb, offset, length,
		    "TP-Validity-Period: Short Data (?)");

		*offset_p += length;
		return;
	    }

	    item =
		proto_tree_add_text(tree, tvb,
		    offset, 7,
		    "TP-Validity-Period");

	    subtree = proto_item_add_subtree(item, ett_vp);

	    oct = tvb_get_guint8(tvb, offset);

	    other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
	    proto_tree_add_text(subtree, tvb,
		offset, 1,
		"%s :  %s",
		bigbuf,
		(oct & 0x80) ? "Extended" : "No extension");

	    if (oct & 0x80)
	    {
		proto_tree_add_text(subtree,
		    tvb, offset + 1, 6,
		    "Extension not implemented, ignored");

		*offset_p += 7;
		return;
	    }

	    other_decode_bitfield_value(bigbuf, oct, 0x40, 8);
	    proto_tree_add_text(subtree, tvb,
		offset, 1,
		"%s :  %s",
		bigbuf,
		(oct & 0x40) ? "Single shot SM" : "Not single shot SM");

	    other_decode_bitfield_value(bigbuf, oct, 0x38, 8);
	    proto_tree_add_text(subtree, tvb,
		offset, 1,
		"%s :  Reserved",
		bigbuf);

	    loc_form = oct & 0x7;

	    switch (loc_form)
	    {
	    case 0x00:
		other_decode_bitfield_value(bigbuf, oct, 0x07, 8);
		proto_tree_add_text(subtree, tvb,
		    offset, 1,
		    "%s :  No Validity Period specified",
		    bigbuf);

		done = TRUE;
		break;

	    case 0x01:
		other_decode_bitfield_value(bigbuf, oct, 0x07, 8);
		proto_tree_add_text(subtree, tvb,
		    offset, 1,
		    "%s :  Validity Period Format: relative",
		    bigbuf);

		offset++;
		/* go around again */
		vp_form = 2;
		break;

	    case 0x02:
		other_decode_bitfield_value(bigbuf, oct, 0x07, 8);
		proto_tree_add_text(subtree, tvb,
		    offset, 1,
		    "%s :  Validity Period Format: relative",
		    bigbuf);

		offset++;
		oct = tvb_get_guint8(tvb, offset);

		proto_tree_add_text(subtree, tvb,
		    offset, 1,
		    "%d seconds",
		    oct);

		done = TRUE;
		break;

	    case 0x03:
		other_decode_bitfield_value(bigbuf, oct, 0x07, 8);
		proto_tree_add_text(subtree, tvb,
		    offset, 1,
		    "%s :  Validity Period Format: relative",
		    bigbuf);

		offset++;
		oct = tvb_get_guint8(tvb, offset);
		oct2 = tvb_get_guint8(tvb, offset+1);
		oct3 = tvb_get_guint8(tvb, offset+2);

		proto_tree_add_text(subtree,
		    tvb, offset, 3,
		    "Hour %d%d, Minutes %d%d, Seconds %d%d",
		    oct & 0x0f,
		    (oct & 0xf0) >> 4,
		    oct2 & 0x0f,
		    (oct2 & 0xf0) >> 4,
		    oct3 & 0x0f,
		    (oct3 & 0xf0) >> 4);

		done = TRUE;
		break;

	    default:
		other_decode_bitfield_value(bigbuf, oct, 0x07, 8);
		proto_tree_add_text(subtree, tvb,
		    offset, 1,
		    "%s :  Validity Period Format: Reserved",
		    bigbuf);

		done = TRUE;
		break;
	    }
	    break;

	case 2:
	    oct = tvb_get_guint8(tvb, offset);

	    if (oct <= 143)
	    {
		mins = (oct + 1) * 5;
		if (mins >= 60)
		{
		    hours = mins / 60;
		    mins %= 60;

		    proto_tree_add_text(subtree, tvb,
			offset, 1,
			"TP-Validity-Period: %d hours %d minutes",
			hours,
			mins);
		}
		else
		{
		    proto_tree_add_text(subtree, tvb,
			offset, 1,
			"TP-Validity-Period: %d minutes",
			mins);
		}
	    }
	    else if ((oct >= 144) &&
		(oct <= 167))
	    {
		mins = (oct - 143) * 30;
		hours = 12 + (mins / 60);
		mins %= 60;

		proto_tree_add_text(subtree, tvb,
		    offset, 1,
		    "TP-Validity-Period: %d hours %d minutes",
		    hours,
		    mins);
	    }
	    else if ((oct >= 168) &&
		(oct <= 196))
	    {
		proto_tree_add_text(subtree, tvb,
		    offset, 1,
		    "TP-Validity-Period: %d day(s)",
		    oct - 166);
	    }
	    else if (oct >= 197)
	    {
		proto_tree_add_text(subtree, tvb,
		    offset, 1,
		    "TP-Validity-Period: %d week(s)",
		    oct - 192);
	    }

	    done = TRUE;
	    break;

	case 3:
	    length = tvb_length_remaining(tvb, offset);

	    if (length < 7)
	    {
		proto_tree_add_text(tree,
		    tvb, offset, length,
		    "TP-Validity-Period: Short Data (?)");

		*offset_p += length;
		return;
	    }

	    item =
		proto_tree_add_text(tree, tvb,
		    offset, 7,
		    "TP-Validity-Period: absolute");

	    subtree = proto_item_add_subtree(item, ett_vp);

	    dis_field_scts_aux(tvb, subtree, *offset_p);

	    done = TRUE;
	    break;
	}
    }
    while (!done);

    if (vp_form == 2)
    {
	(*offset_p)++;
    }
    else
    {
	*offset_p += 7;
    }
}

/* 9.2.3.13 */
static void
dis_field_dt(tvbuff_t *tvb, proto_tree *tree, guint32 *offset_p)
{
    proto_item	*item;
    proto_tree	*subtree = NULL;
    guint32	offset;
    guint32	length;


    offset = *offset_p;

    length = tvb_length_remaining(tvb, offset);

    if (length < 7)
    {
	proto_tree_add_text(tree,
	    tvb, offset, length,
	    "TP-Discharge-Time: Short Data (?)");

	*offset_p += length;
	return;
    }

    item =
	proto_tree_add_text(tree, tvb,
	    offset, 7,
	    "TP-Discharge-Time");

    subtree = proto_item_add_subtree(item, ett_dt);

    dis_field_scts_aux(tvb, subtree, *offset_p);

    *offset_p += 7;
}

/* 9.2.3.14 */
/* use dis_field_addr() */

/* 9.2.3.15 */
static void
dis_field_st(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 oct)
{
    static const gchar	*sc_complete = "Short message transaction completed";
    static const gchar	*sc_temporary = "Temporary error, SC still trying to transfer SM";
    static const gchar	*sc_perm = "Permanent error, SC is not making any more transfer attempts";
    static const gchar	*sc_tempfin = "Temporary error, SC is not making any more transfer attempts";
    proto_item		*item;
    proto_tree		*subtree = NULL;
    guint8		value;
    const gchar		*str = NULL;
    const gchar	*str2 = NULL;


    item =
	proto_tree_add_text(tree, tvb,
	    offset, 1,
	    "TP-Status");

    subtree = proto_item_add_subtree(item, ett_st);

    other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_text(subtree, tvb,
	offset, 1,
	"%s :  Definition of bits 0-6: %s",
	bigbuf,
	(oct & 0x80) ?  "Reserved" : "as follows");

    value = oct & 0x7f;

    switch (value)
    {
    case 0x00: str2 = sc_complete; str = "Short message received by the SME"; break;
    case 0x01: str2 = sc_complete; str = "Short message forwarded by the SC to the SME but the SC is unable to confirm delivery"; break;
    case 0x02: str2 = sc_complete; str = "Short message replaced by the SC Reserved values"; break;

    case 0x20: str2 = sc_temporary; str = "Congestion"; break;
    case 0x21: str2 = sc_temporary; str = "SME busy"; break;
    case 0x22: str2 = sc_temporary; str = "No response from SME"; break;
    case 0x23: str2 = sc_temporary; str = "Service rejected"; break;
    case 0x24: str2 = sc_temporary; str = "Quality of service not available"; break;
    case 0x25: str2 = sc_temporary; str = "Error in SME"; break;

    case 0x40: str2 = sc_perm; str = "Remote procedure error"; break;
    case 0x41: str2 = sc_perm; str = "Incompatible destination"; break;
    case 0x42: str2 = sc_perm; str = "Connection rejected by SME"; break;
    case 0x43: str2 = sc_perm; str = "Not obtainable"; break;
    case 0x44: str2 = sc_perm; str = "Quality of service not available"; break;
    case 0x45: str2 = sc_perm; str = "No interworking available"; break;
    case 0x46: str2 = sc_perm; str = "SM Validity Period Expired"; break;
    case 0x47: str2 = sc_perm; str = "SM Deleted by originating SME"; break;
    case 0x48: str2 = sc_perm; str = "SM Deleted by SC Administration"; break;
    case 0x49: str2 = sc_perm; str = "SM does not exist (The SM may have previously existed in the SC but the SC no longer has knowledge of it or the SM may never have previously existed in the SC)"; break;

    case 0x60: str2 = sc_tempfin; str = "Congestion"; break;
    case 0x61: str2 = sc_tempfin; str = "SME busy"; break;
    case 0x62: str2 = sc_tempfin; str = "No response from SME"; break;
    case 0x63: str2 = sc_tempfin; str = "Service rejected"; break;
    case 0x64: str2 = sc_tempfin; str = "Quality of service not available"; break;
    case 0x65: str2 = sc_tempfin; str = "Error in SME"; break;

    default:
	if ((value >= 0x03) &&
	    (value <= 0x0f))
	{
	    str2 = sc_complete;
	    str = "Reserved";
	}
	else if ((value >= 0x10) &&
	    (value <= 0x1f))
	{
	    str2 = sc_complete;
	    str = "Values specific to each SC";
	}
	else if ((value >= 0x26) &&
	    (value <= 0x2f))
	{
	    str2 = sc_temporary;
	    str = "Reserved";
	}
	else if ((value >= 0x30) &&
	    (value <= 0x3f))
	{
	    str2 = sc_temporary;
	    str = "Values specific to each SC";
	}
	else if ((value >= 0x4a) &&
	    (value <= 0x4f))
	{
	    str2 = sc_perm;
	    str = "Reserved";
	}
	else if ((value >= 0x50) &&
	    (value <= 0x5f))
	{
	    str2 = sc_perm;
	    str = "Values specific to each SC";
	}
	else if ((value >= 0x66) &&
	    (value <= 0x6f))
	{
	    str2 = sc_tempfin;
	    str = "Reserved";
	}
	else if ((value >= 0x70) &&
	    (value <= 0x7f))
	{
	    str2 = sc_tempfin;
	    str = "Values specific to each SC";
	}
	break;
    }

    other_decode_bitfield_value(bigbuf, oct, 0x7f, 8);
    proto_tree_add_text(subtree, tvb,
	offset, 1,
	"%s :  (%d) %s, %s",
	bigbuf,
	value,
	str2,
	str);
}

/* 9.2.3.16 */
#define DIS_FIELD_UDL(m_tree, m_offset) \
{ \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"TP-User-Data-Length: (%d) %s", \
	oct, \
	oct ? "depends on Data-Coding-Scheme" : "no User-Data");\
}

/* 9.2.3.17 */
#define DIS_FIELD_RP(m_tree, m_bitmask, m_offset) \
{ \
    other_decode_bitfield_value(bigbuf, oct, m_bitmask, 8); \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"%s :  TP-Reply-Path: parameter is %sset in this SMS-SUBMIT/DELIVER", \
	bigbuf, \
	(oct & m_bitmask) ? "" : "not "); \
}

/* 9.2.3.18 */
#define DIS_FIELD_MN(m_tree, m_offset) \
{ \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"TP-Message-Number: %d", \
	oct); \
}

/* 9.2.3.19 */
#define DIS_FIELD_CT(m_tree, m_offset) \
{ \
    switch (oct) \
    { \
    case 0: str = "Enquiry relating to previously submitted short message"; break; \
    case 1: str = "Cancel Status Report Request relating to previously submitted short message"; break; \
    case 2: str = "Delete previously submitted Short Message"; break; \
    case 3: str = "Enable Status Report Request relating to previously submitted short message"; break; \
    default: \
	if ((oct >= 0x04) && \
	    (oct <= 0x1f)) \
	{ \
	    str = "Reserved unspecified"; \
	} \
	else if (oct >= 0xe0) \
	{ \
	    str = "Values specific for each SC"; \
	} \
	else \
	{ \
	    str = "undefined"; \
	} \
	break; \
    } \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"TP-Command-Type: (%d), %s", \
	oct, \
	str); \
}

/* 9.2.3.20 */
#define DIS_FIELD_CDL(m_tree, m_offset) \
{ \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"TP-Command-Data-Length: (%d)%s", \
	oct, \
	oct ? "" : " no Command-Data");\
}

/* 9.2.3.21 */
/* done in-line in the message functions */

/* 9.2.3.22 */
static void
dis_field_fcs(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 oct)
{
    proto_item	*item;
    proto_tree	*subtree = NULL;
    const gchar	*str = NULL;


    item =
	proto_tree_add_text(tree, tvb,
	    offset, 1,
	    "TP-Failure-Cause");

    subtree = proto_item_add_subtree(item, ett_fcs);

    switch (oct)
    {
    case 0x80: str = "Telematic interworking not supported"; break;
    case 0x81: str = "Short message Type 0 not supported"; break;
    case 0x82: str = "Cannot replace short message"; break;
    case 0x8F: str = "Unspecified TP-PID error"; break;
    case 0x90: str = "Data coding scheme (alphabet) not supported"; break;
    case 0x91: str = "Message class not supported"; break;
    case 0x9F: str = "Unspecified TP-DCS error"; break;
    case 0xA0: str = "Command cannot be actioned"; break;
    case 0xA1: str = "Command unsupported"; break;
    case 0xAF: str = "Unspecified TP-Command error"; break;
    case 0xB0: str = "TPDU not supported"; break;
    case 0xC0: str = "SC busy"; break;
    case 0xC1: str = "No SC subscription"; break;
    case 0xC2: str = "SC system failure"; break;
    case 0xC3: str = "Invalid SME address"; break;
    case 0xC4: str = "Destination SME barred"; break;
    case 0xC5: str = "SM Rejected-Duplicate SM"; break;
    case 0xC6: str = "TP-VPF not supported"; break;
    case 0xC7: str = "TP-VP not supported"; break;
    case 0xD0: str = "(U)SIM SMS storage full"; break;
    case 0xD1: str = "No SMS storage capability in (U)SIM"; break;
    case 0xD2: str = "Error in MS"; break;
    case 0xD3: str = "Memory Capacity Exceeded"; break;
    case 0xD4: str = "(U)SIM Application Toolkit Busy"; break;
    case 0xD5: str = "(U)SIM data download error"; break;
    case 0xFF: str = "Unspecified error cause"; break;
    default:
	if ((oct >= 0x80) &&
	    (oct <= 0x8F))
	{
	    str = "TP-PID errors"; break;
	}
	else if ((oct >= 0x90) &&
	    (oct <= 0x9F))
	{
	    str = "TP-DCS errors"; break;
	}
	else if ((oct >= 0xA0) &&
	    (oct <= 0xAF))
	{
	    str = "TP-Command errors"; break;
	}
	else if ((oct >= 0xE0) &&
	    (oct <= 0xFE))
	{
	    str = "Values specific to an application"; break;
	}
	else
	{
	    str = "Reserved"; break;
	}
    }

    proto_tree_add_text(subtree, tvb,
	offset, 1,
	str);
}

/* 9.2.3.23 */
#define DIS_FIELD_UDHI(m_tree, m_bitmask, m_offset, m_udhi) \
{ \
    SMS_SHIFTMASK(oct & m_bitmask, m_bitmask, m_udhi); \
    other_decode_bitfield_value(bigbuf, oct, m_bitmask, 8); \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"%s :  TP-User-Data-Header-Indicator: %s short message", \
	bigbuf, \
	m_udhi ? \
	"The beginning of the TP-UD field contains a Header in addition to the" : \
	"The TP-UD field contains only the"); \
}

/*
 * FROM GNOKII
 * gsm-encoding.c
 * gsm-sms.c
 */
#define GN_BYTE_MASK ((1 << bits) - 1)

int
gsm_sms_char_7bit_unpack(unsigned int offset, unsigned int in_length, unsigned int out_length,
		     const guint8 *input, unsigned char *output)
{
    unsigned char *out_num = output; /* Current pointer to the output buffer */
    const guint8 *in_num = input;    /* Current pointer to the input buffer */
    unsigned char rest = 0x00;
    int bits;

    bits = offset ? offset : 7;

    while ((unsigned int)(in_num - input) < in_length)
    {
	*out_num = ((*in_num & GN_BYTE_MASK) << (7 - bits)) | rest;
	rest = *in_num >> bits;

	/* If we don't start from 0th bit, we shouldn't go to the
	   next char. Under *out_num we have now 0 and under Rest -
	   _first_ part of the char. */
	if ((in_num != input) || (bits == 7)) out_num++;
	in_num++;

	if ((unsigned int)(out_num - output) >= out_length) break;

	/* After reading 7 octets we have read 7 full characters but
	   we have 7 bits as well. This is the next character */
	if (bits == 1)
	{
	    *out_num = rest;
	    out_num++;
	    bits = 7;
	    rest = 0x00;
	}
	else
	{
	    bits--;
	}
    }

    return out_num - output;
}

#define GN_CHAR_ALPHABET_SIZE 128

#define GN_CHAR_ESCAPE 0x1b

static unsigned char gsm_default_alphabet[GN_CHAR_ALPHABET_SIZE] = {

    /* ETSI GSM 03.38, version 6.0.1, section 6.2.1; Default alphabet */
    /* Characters in hex position 10, [12 to 1a] and 24 are not present on
       latin1 charset, so we cannot reproduce on the screen, however they are
       greek symbol not present even on my Nokia */

    '@',  0xa3, '$',  0xa5, 0xe8, 0xe9, 0xf9, 0xec,
    0xf2, 0xc7, '\n', 0xd8, 0xf8, '\r', 0xc5, 0xe5,
    '?',  '_',  '?',  '?',  '?',  '?',  '?',  '?',
    '?',  '?',  '?',  '?',  0xc6, 0xe6, 0xdf, 0xc9,
    ' ',  '!',  '\"', '#',  0xa4,  '%',  '&',  '\'',
    '(',  ')',  '*',  '+',  ',',  '-',  '.',  '/',
    '0',  '1',  '2',  '3',  '4',  '5',  '6',  '7',
    '8',  '9',  ':',  ';',  '<',  '=',  '>',  '?',
    0xa1, 'A',  'B',  'C',  'D',  'E',  'F',  'G',
    'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
    'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',
    'X',  'Y',  'Z',  0xc4, 0xd6, 0xd1, 0xdc, 0xa7,
    0xbf, 'a',  'b',  'c',  'd',  'e',  'f',  'g',
    'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
    'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
    'x',  'y',  'z',  0xe4, 0xf6, 0xf1, 0xfc, 0xe0
};

static gboolean
char_is_escape(unsigned char value)
{
    return (value == GN_CHAR_ESCAPE);
}

static unsigned char
char_def_alphabet_ext_decode(unsigned char value)
{
    switch (value)
    {
    case 0x0a: return 0x0c; break; /* form feed */
    case 0x14: return '^';  break;
    case 0x28: return '{';  break;
    case 0x29: return '}';  break;
    case 0x2f: return '\\'; break;
    case 0x3c: return '[';  break;
    case 0x3d: return '~';  break;
    case 0x3e: return ']';  break;
    case 0x40: return '|';  break;
    case 0x65: return 0xa4; break; /* euro */
    default: return '?';    break; /* invalid character */
    }
}

static unsigned char
char_def_alphabet_decode(unsigned char value)
{
    if (value < GN_CHAR_ALPHABET_SIZE)
    {
	return gsm_default_alphabet[value];
    }
    else
    {
	return '?';
    }
}

void
gsm_sms_char_ascii_decode(unsigned char* dest, const unsigned char* src, int len)
{
    int i, j;

    for (i = 0, j = 0; j < len; i++, j++)
    {
	if (char_is_escape(src[j]))
	    dest[i] = char_def_alphabet_ext_decode(src[++j]);
	else
	    dest[i] = char_def_alphabet_decode(src[j]);
    }
    dest[i] = 0;
    return;
}

/*
 * END FROM GNOKII
 */

static void
dis_iei_apa_8bit(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    const gchar	*str = NULL;
    guint8	oct;


    EXACT_DATA_CHECK(length, 2);

    oct = tvb_get_guint8(tvb, offset);

    if (oct < 240)
    {
	str = "Reserved";
    }
    else
    {
	str = "Available for allocation by applications";
    }

    proto_tree_add_text(tree,
	tvb, offset, 1,
	"Destination port: %d, %s",
	oct,
	str);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    if (oct < 240)
    {
	str = "Reserved";
    }
    else
    {
	str = "Available for allocation by applications";
    }

    proto_tree_add_text(tree,
	tvb, offset, 1,
	"Originator port: %d, %s",
	oct,
	str);
}

static void
dis_iei_apa_16bit(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    const gchar	*str = NULL;
    guint32	value;


    EXACT_DATA_CHECK(length, 4);

    value = tvb_get_ntohs(tvb, offset);

    if (value < 16000)
    {
	str = "As allocated by IANA (http://www.IANA.com/)";
    }
    else if (value < 17000)
    {
	str = "Available for allocation by applications";
    }
    else
    {
	str = "Reserved";
    }

    proto_tree_add_text(tree,
	tvb, offset, 2,
	"Destination port: %d, %s",
	value,
	str);

    offset += 2;
    value = tvb_get_ntohs(tvb, offset);

    if (value < 16000)
    {
	str = "As allocated by IANA (http://www.IANA.com/)";
    }
    else if (value < 17000)
    {
	str = "Available for allocation by applications";
    }
    else
    {
	str = "Reserved";
    }

    proto_tree_add_text(tree,
	tvb, offset, 2,
	"Originator port: %d, %s",
	value,
	str);
}

static void
dis_field_ud_iei(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    void (*iei_fcn)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length);
    guint8	oct;
    proto_item	*item;
    proto_tree	*subtree = NULL;
    const gchar	*str = NULL;
    guint8	iei_len;


    while (length > 2)
    {
	iei_fcn = NULL;

	oct = tvb_get_guint8(tvb, offset);

	switch (oct)
	{
	case 0x00: str = "Concatenated short messages, 8-bit reference number (SMS Control)"; break;
	case 0x01: str = "Special SMS Message Indication (SMS Control)"; break;
	case 0x02: str = "Reserved N/A"; break;
	case 0x03: str = "Value not used to avoid misinterpretation as <LF> character N/A"; break;
	case 0x04: str = "Application port addressing scheme, 8 bit address (SMS Control)"; iei_fcn = dis_iei_apa_8bit; break;
	case 0x05: str = "Application port addressing scheme, 16 bit address (SMS Control)"; iei_fcn = dis_iei_apa_16bit; break;
	case 0x06: str = "SMSC Control Parameters (SMS Control)"; break;
	case 0x07: str = "UDH Source Indicator (SMS Control)"; break;
	case 0x08: str = "Concatenated short message, 16-bit reference number (SMS Control)"; break;
	case 0x09: str = "Wireless Control Message Protocol (SMS Control)"; break;
	case 0x0A: str = "Text Formatting (EMS Control)"; break;
	case 0x0B: str = "Predefined Sound (EMS Content)"; break;
	case 0x0C: str = "User Defined Sound (iMelody max 128 bytes) (EMS Content)"; break;
	case 0x0D: str = "Predefined Animation (EMS Content)"; break;
	case 0x0E: str = "Large Animation (16*16 times 4 = 32*4 =128 bytes) (EMS Content)"; break;
	case 0x0F: str = "Small Animation (8*8 times 4 = 8*4 =32 bytes) (EMS Content)"; break;
	case 0x10: str = "Large Picture (32*32 = 128 bytes) (EMS Content)"; break;
	case 0x11: str = "Small Picture (16*16 = 32 bytes) (EMS Content)"; break;
	case 0x12: str = "Variable Picture (EMS Content)"; break;
	case 0x13: str = "User prompt indicator (EMS Control)"; break;
	case 0x14: str = "Extended Object (EMS Content)"; break;
	case 0x15: str = "Reused Extended Object (EMS Control)"; break;
	case 0x16: str = "Compression Control (EMS Control)"; break;
	case 0x17: str = "Object Distribution Indicator (EMS Control)"; break;
	case 0x18: str = "Standard WVG object (EMS Content)"; break;
	case 0x19: str = "Character Size WVG object (EMS Content)"; break;
	case 0x1A: str = "Extended Object Data Request Command (EMS Control)"; break;
	case 0x20: str = "RFC 822 E-Mail Header (SMS Control)"; break;
	case 0x21: str = "Hyperlink format element (SMS Control)"; break;
	case 0x22: str = "Reply Address Element (SMS Control)"; break;
	default:
	    if ((oct >= 0x1b) &&
		(oct <= 0x1f))
	    {
		str = "Reserved for future EMS features (see subclause 3.10) N/A"; break;
	    }
	    else if ((oct >= 0x23) &&
		(oct <= 0x6f))
	    {
		str = "Reserved for future use N/A"; break;
	    }
	    else if ((oct >= 0x70) &&
		(oct <= 0x7f))
	    {
		str = "(U)SIM Toolkit Security Headers (SMS Control)"; break;
	    }
	    else if ((oct >= 0x80) &&
		(oct <= 0x9f))
	    {
		str = "SME to SME specific use (SMS Control)"; break;
	    }
	    else if ((oct >= 0xa0) &&
		(oct <= 0xbf))
	    {
		str = "Reserved for future use N/A"; break;
	    }
	    else if ((oct >= 0xc0) &&
		(oct <= 0xdf))
	    {
		str = "SC specific use (SMS Control)"; break;
	    }
	    else
	    {
		str = "Reserved for future use N/A"; break;
	    }
	}

	iei_len = tvb_get_guint8(tvb, offset + 1);

	item =
	    proto_tree_add_text(tree,
		tvb, offset, iei_len + 2,
		"IE: %s",
		str);

	subtree = proto_item_add_subtree(item, ett_udh_ieis[oct]);

	proto_tree_add_text(subtree,
	    tvb, offset, 1,
	    "Information Element Identifier: %d",
	    oct);

	offset++;

	proto_tree_add_text(subtree,
	    tvb, offset, 1,
	    "Length: %d",
	    iei_len);

	offset++;

	if (iei_len > 0)
	{
	    if (iei_fcn == NULL)
	    {
		proto_tree_add_text(subtree,
		    tvb, offset, iei_len,
		    "IE Data");
	    }
	    else
	    {
		iei_fcn(tvb, subtree, offset, iei_len);
	    }
	}

	length -= 2 + iei_len;
	offset += iei_len;
    }
}

/* 9.2.3.24 */
static void
dis_field_ud(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint32 length, gboolean udhi, guint8 udl,
    gboolean seven_bit, gboolean eight_bit, gboolean ucs2, gboolean compressed)
{
    static guint8	fill_bits_mask[] = { 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc };
    proto_item	*item;
    proto_item	*udh_item;
    proto_tree	*subtree = NULL;
    proto_tree	*udh_subtree = NULL;
    guint8	oct;
    guint8	fill_bits;
    guint32	out_len;
    char	*ustr;

    fill_bits = 0;

    item =
	proto_tree_add_text(tree, tvb,
	    offset, length,
	    "TP-User-Data");

    subtree = proto_item_add_subtree(item, ett_ud);

    oct = tvb_get_guint8(tvb, offset);

    if (udhi)
    {

		/* step over header */

		udh_item =
		    proto_tree_add_text(subtree, tvb,
			offset, oct + 1,
			"User-Data Header");

		udh_subtree = proto_item_add_subtree(udh_item, ett_udh);

		proto_tree_add_text(udh_subtree,
		    tvb, offset, 1,
		    "User Data Header Length (%d)",
		    oct);

		offset++;
		udl--;
		length--;

		dis_field_ud_iei(tvb, udh_subtree, offset, oct);

		offset += oct;
		udl -= oct;
		length -= oct;

		if (seven_bit)
			{
		    /* step over fill bits ? */

		    fill_bits = 7 - (((oct + 1) * 8) % 7);
		    if (fill_bits != 7)
			    {
				oct = tvb_get_guint8(tvb, offset);

				other_decode_bitfield_value(bigbuf, oct, fill_bits_mask[fill_bits], 8);
				proto_tree_add_text(udh_subtree,
					tvb, offset, 1,
					"%s :  Fill bits",
					bigbuf);
			}
		}
    }

    if (compressed)
    {
		proto_tree_add_text(subtree, tvb,
		    offset, length,
		    "Compressed data");
    }
    else
    {
		if (seven_bit)
		{
		    out_len =
			gsm_sms_char_7bit_unpack(fill_bits, length, sizeof(bigbuf),
		    tvb_get_ptr(tvb, offset, length), bigbuf);
		    bigbuf[out_len] = '\0';
		    gsm_sms_char_ascii_decode(bigbuf, bigbuf, out_len);
			bigbuf[udl] = '\0';

			proto_tree_add_text(subtree, tvb, offset, length, "%s", bigbuf);
		}
		else if (eight_bit)
			{
			proto_tree_add_text(subtree, tvb, offset, length, "%s",
	        tvb_format_text(tvb, offset, length));
		}
		else if (ucs2)
			{
			/* tvb_get_ephemeral_faked_unicode takes the lengt in number of guint16's */
			ustr = tvb_get_ephemeral_faked_unicode(tvb, offset, (length>>1), FALSE);
			proto_tree_add_text(subtree, tvb, offset, length, "%s", ustr);
		}
    }
}

/* 9.2.3.25 */
#define DIS_FIELD_RD(m_tree, m_bitmask, m_offset) \
{ \
    other_decode_bitfield_value(bigbuf, oct, m_bitmask, 8); \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"%s :  TP-Reject-Duplicates: Instruct SC to %s duplicates", \
	bigbuf, \
	(oct & m_bitmask) ? \
	"reject" : \
	"accept"); \
}

/* 9.2.3.26 */
#define DIS_FIELD_SRQ(m_tree, m_bitmask, m_offset) \
{ \
    other_decode_bitfield_value(bigbuf, oct, m_bitmask, 8); \
    proto_tree_add_text(m_tree, tvb, \
	m_offset, 1, \
	"%s :  TP-Status-Report-Qualifier: The SMS-STATUS-REPORT is the result of %s", \
	bigbuf, \
	(oct & m_bitmask) ? \
	"an SMS-COMMAND e.g. an Enquiry" : \
	"a SMS-SUBMIT"); \
}

/* 9.2.3.27 */
static void
dis_field_pi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 oct)
{
    proto_item	*item;
    proto_tree	*subtree = NULL;


    item =
	proto_tree_add_text(tree, tvb,
	    offset, 1,
	    "TP-Parameter-Indicator");

    subtree = proto_item_add_subtree(item, ett_pi);

    other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_text(subtree, tvb,
	offset, 1,
	"%s :  %s",
	bigbuf,
	(oct & 0x80) ? "Extended" : "No extension");

    other_decode_bitfield_value(bigbuf, oct, 0x78, 8);
    proto_tree_add_text(subtree, tvb,
	offset, 1,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, oct, 0x04, 8);
    proto_tree_add_text(subtree, tvb,
	offset, 1,
	"%s :  TP-UDL %spresent",
	bigbuf,
	(oct & 0x04) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, oct, 0x02, 8);
    proto_tree_add_text(subtree, tvb,
	offset, 1,
	"%s :  TP-DCS %spresent",
	bigbuf,
	(oct & 0x02) ? "" : "not ");

    other_decode_bitfield_value(bigbuf, oct, 0x01, 8);
    proto_tree_add_text(subtree, tvb,
	offset, 1,
	"%s :  TP-PID %spresent",
	bigbuf,
	(oct & 0x01) ? "" : "not ");
}

/*
 * Ref. GSM 03.40
 * Section 9.2.2
 */
static void
dis_msg_deliver(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    guint32	saved_offset;
    guint32	length;
    guint8	oct;
    guint8	udl;
    gboolean	seven_bit;
    gboolean	eight_bit;
    gboolean	ucs2;
    gboolean	compressed;
    gboolean	udhi;

    udl = 0;
    saved_offset = offset;
    length = tvb_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);

    DIS_FIELD_RP(tree, 0x80, offset);

    DIS_FIELD_UDHI(tree, 0x40, offset, udhi);

    DIS_FIELD_SRI(tree, 0x20, offset);

    DIS_FIELD_MMS(tree, 0x04, offset);

    DIS_FIELD_MTI(tree, 0x03, offset);

    offset++;

    dis_field_addr(tvb, tree, &offset, "TP-Originating-Address");

    oct = tvb_get_guint8(tvb, offset);

    dis_field_pid(tvb, tree, offset, oct);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    dis_field_dcs(tvb, tree, offset, oct, &seven_bit, &eight_bit, &ucs2, &compressed);

    offset++;
    dis_field_scts(tvb, tree, &offset);

    oct = tvb_get_guint8(tvb, offset);
    udl = oct;

    DIS_FIELD_UDL(tree, offset);

    if (udl > 0)
    {
	offset++;

	dis_field_ud(tvb, tree, offset, length - (offset - saved_offset), udhi, udl,
	    seven_bit, eight_bit, ucs2, compressed);
    }
}

/*
 * Ref. GSM 03.40
 * Section 9.2.2
 */
static void
dis_msg_deliver_report(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    guint32	saved_offset;
    guint32	length;
    guint8	oct;
    guint8	pi;
    guint8	udl;
    gboolean	seven_bit;
    gboolean	eight_bit;
    gboolean	ucs2;
    gboolean	compressed;
    gboolean	udhi;


    udl = 0;
    saved_offset = offset;
    length = tvb_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);

    DIS_FIELD_UDHI(tree, 0x40, offset, udhi);

	DIS_FIELD_MMS(tree, 0x04, offset); /* Bit 2			*/
    DIS_FIELD_MTI(tree, 0x03, offset); /* Bit 0 and 1	*/

    if (length < 2)
    {
	proto_tree_add_text(tree,
	    tvb, offset, length,
	    "Short Data (?)");
	return;
    }

    /*
     * there does not seem to be a way to determine that this
     * deliver report is from an RP-ERROR or RP-ACK other
     * than to look at the next octet
     *
     * FCS values are 0x80 and higher
     * PI uses bit 7 as an extension indicator
     *
     * will assume that if bit 7 is set then this octet
     * is an FCS otherwise PI
     */
    offset++;
    oct = tvb_get_guint8(tvb, offset);

    if (oct & 0x80)
    {
	dis_field_fcs(tvb, tree, offset, oct);
	offset++;
    }

    pi = tvb_get_guint8(tvb, offset);

    dis_field_pi(tvb, tree, offset, pi);

    if (pi & 0x01)
    {
	if (length <= (offset - saved_offset))
	{
	    proto_tree_add_text(tree,
		tvb, offset, -1,
		"Short Data (?)");
	    return;
	}

	offset++;
	oct = tvb_get_guint8(tvb, offset);

	dis_field_pid(tvb, tree, offset, oct);
    }

    if (pi & 0x02)
    {
	if (length <= (offset - saved_offset))
	{
	    proto_tree_add_text(tree,
		tvb, offset, -1,
		"Short Data (?)");
	    return;
	}

	offset++;
	oct = tvb_get_guint8(tvb, offset);

	dis_field_dcs(tvb, tree, offset, oct, &seven_bit, &eight_bit, &ucs2, &compressed);
    }

    if (pi & 0x04)
    {
	if (length <= (offset - saved_offset))
	{
	    proto_tree_add_text(tree,
		tvb, offset, -1,
		"Short Data (?)");
	    return;
	}

	offset++;
	oct = tvb_get_guint8(tvb, offset);
	udl = oct;

	DIS_FIELD_UDL(tree, offset);
    }

    if (udl > 0)
    {
	offset++;

	dis_field_ud(tvb, tree, offset, length - (offset - saved_offset), udhi, udl,
	    seven_bit, eight_bit, ucs2, compressed);
    }
}

/*
 * Ref. GSM 03.40
 * Section 9.2.2
 */
static void
dis_msg_submit(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    guint32	saved_offset;
    guint32	length;
    guint8	oct;
    guint8	vp_form;
    guint8	udl;
    const gchar	*str = NULL;
    gboolean	seven_bit;
    gboolean	eight_bit;
    gboolean	ucs2;
    gboolean	compressed;
    gboolean	udhi;


    saved_offset = offset;
    length = tvb_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);

    DIS_FIELD_RP(tree, 0x80, offset);

    DIS_FIELD_UDHI(tree, 0x40, offset, udhi);

    DIS_FIELD_SRR(tree, 0x20, offset);

    DIS_FIELD_VPF(tree, 0x18, offset, &vp_form);

    DIS_FIELD_RD(tree, 0x04, offset);

    DIS_FIELD_MTI(tree, 0x03, offset);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    DIS_FIELD_MR(tree, offset);

    offset++;

    dis_field_addr(tvb, tree, &offset, "TP-Destination-Address");

    oct = tvb_get_guint8(tvb, offset);

    dis_field_pid(tvb, tree, offset, oct);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    dis_field_dcs(tvb, tree, offset, oct, &seven_bit, &eight_bit, &ucs2, &compressed);

    offset++;
    dis_field_vp(tvb, tree, &offset, vp_form);

    oct = tvb_get_guint8(tvb, offset);
    udl = oct;

    DIS_FIELD_UDL(tree, offset);

    if (udl > 0)
    {
	offset++;

	dis_field_ud(tvb, tree, offset, length - (offset - saved_offset), udhi, udl,
	    seven_bit, eight_bit, ucs2, compressed);
    }
}

/*
 * Ref. GSM 03.40
 * Section 9.2.2
 */
static void
dis_msg_submit_report(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    guint32	saved_offset;
    guint32	length;
    guint8	oct;
    guint8	pi;
    guint8	udl;
    gboolean	seven_bit;
    gboolean	eight_bit;
    gboolean	ucs2;
    gboolean	compressed;
    gboolean	udhi;


    udl = 0;
    saved_offset = offset;
    length = tvb_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);

    DIS_FIELD_UDHI(tree, 0x40, offset, udhi);

    DIS_FIELD_MTI(tree, 0x03, offset);

    /*
     * there does not seem to be a way to determine that this
     * deliver report is from an RP-ERROR or RP-ACK other
     * than to look at the next octet
     *
     * FCS values are 0x80 and higher
     * PI uses bit 7 as an extension indicator
     *
     * will assume that if bit 7 is set then this octet
     * is an FCS otherwise PI
     */
    offset++;
    oct = tvb_get_guint8(tvb, offset);

    if (oct & 0x80)
    {
	dis_field_fcs(tvb, tree, offset, oct);
	offset++;
    }

    pi = tvb_get_guint8(tvb, offset);

    dis_field_pi(tvb, tree, offset, pi);
    offset++;

    dis_field_scts(tvb, tree, &offset);

    if (pi & 0x01) {
	if (length <= (offset - saved_offset)) {
	    proto_tree_add_text(tree,
		tvb, offset, -1,
		"Short Data (?)");
	    return;
	}

	oct = tvb_get_guint8(tvb, offset);

	dis_field_pid(tvb, tree, offset, oct);
	offset++;
    }

    if (pi & 0x02)
    {
	if (length <= (offset - saved_offset))
	{
	    proto_tree_add_text(tree,
		tvb, offset, -1,
		"Short Data (?)");
	    return;
	}

	oct = tvb_get_guint8(tvb, offset);

	dis_field_dcs(tvb, tree, offset, oct, &seven_bit, &eight_bit, &ucs2, &compressed);
	offset++;
    }

    if (pi & 0x04)
    {
	if (length <= (offset - saved_offset))
	{
	    proto_tree_add_text(tree,
		tvb, offset, -1,
		"Short Data (?)");
	    return;
	}

	oct = tvb_get_guint8(tvb, offset);
	udl = oct;

	DIS_FIELD_UDL(tree, offset);
	offset++;
    }

    if (udl > 0)
    {
	dis_field_ud(tvb, tree, offset, length - (offset - saved_offset), udhi, udl,
	    seven_bit, eight_bit, ucs2, compressed);
    }
}

/*
 * Ref. GSM 03.40
 * Section 9.2.2
 */
static void
dis_msg_status_report(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    guint32	saved_offset;
    guint32	length;
    guint8	oct;
    guint8	pi;
    guint8	udl;
    gboolean	seven_bit;
    gboolean	eight_bit;
    gboolean	ucs2;
    gboolean	compressed;
    gboolean	udhi;


    udl = 0;
    saved_offset = offset;
    length = tvb_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);

    DIS_FIELD_UDHI(tree, 0x40, offset, udhi);

    DIS_FIELD_SRQ(tree, 0x20, offset);

    DIS_FIELD_MMS(tree, 0x04, offset);

    DIS_FIELD_MTI(tree, 0x03, offset);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    DIS_FIELD_MR(tree, offset);

    offset++;

    dis_field_addr(tvb, tree, &offset, "TP-Recipient-Address");

    dis_field_scts(tvb, tree, &offset);

    dis_field_dt(tvb, tree, &offset);

    oct = tvb_get_guint8(tvb, offset);

    dis_field_st(tvb, tree, offset, oct);

    offset++;
	/* Parameter indicating the presence of any of
	 * the optional parameters which follow
	 * 4) Mandatory if any of the optional parameters following TP-PI is present, 
	 * otherwise optional.
	 */
	if (length <= (offset - saved_offset))
	{
	    return;
	}
    pi = tvb_get_guint8(tvb, offset);

    dis_field_pi(tvb, tree, offset, pi);

    if (pi & 0x01)
    {
	if (length <= (offset - saved_offset))
	{
	    proto_tree_add_text(tree,
		tvb, offset, -1,
		"Short Data (?)");
	    return;
	}

	offset++;
	oct = tvb_get_guint8(tvb, offset);

	dis_field_pid(tvb, tree, offset, oct);
    }

    if (pi & 0x02)
    {
	if (length <= (offset - saved_offset))
	{
	    proto_tree_add_text(tree,
		tvb, offset, -1,
		"Short Data (?)");
	    return;
	}

	offset++;
	oct = tvb_get_guint8(tvb, offset);

	dis_field_dcs(tvb, tree, offset, oct, &seven_bit, &eight_bit, &ucs2, &compressed);
    }

    if (pi & 0x04)
    {
	if (length <= (offset - saved_offset))
	{
	    proto_tree_add_text(tree,
		tvb, offset, -1,
		"Short Data (?)");
	    return;
	}

	offset++;
	oct = tvb_get_guint8(tvb, offset);
	udl = oct;

	DIS_FIELD_UDL(tree, offset);
    }

    if (udl > 0)
    {
	offset++;

	dis_field_ud(tvb, tree, offset, length - (offset - saved_offset), udhi, udl,
	    seven_bit, eight_bit, ucs2, compressed);
    }
}

/*
 * Ref. GSM 03.40
 * Section 9.2.2
 */
static void
dis_msg_command(tvbuff_t *tvb, proto_tree *tree, guint32 offset)
{
    guint32	saved_offset;
    guint32	length;
    guint8	oct;
    guint8	cdl;
    const gchar	*str = NULL;
    gboolean	udhi;


    cdl = 0;
    saved_offset = offset;
    length = tvb_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);

    DIS_FIELD_UDHI(tree, 0x40, offset, udhi);

    DIS_FIELD_SRR(tree, 0x20, offset);

    DIS_FIELD_MTI(tree, 0x03, offset);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    DIS_FIELD_MR(tree, offset);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    dis_field_pid(tvb, tree, offset, oct);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    DIS_FIELD_CT(tree, offset);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    DIS_FIELD_MN(tree, offset);

    offset++;

    dis_field_addr(tvb, tree, &offset, "TP-Destination-Address");

    oct = tvb_get_guint8(tvb, offset);
    cdl = oct;

    DIS_FIELD_CDL(tree, offset);

    if (cdl > 0)
    {
	offset++;

	proto_tree_add_text(tree,
	    tvb, offset, cdl,
	    "TP-Command-Data");
    }
}

#define	NUM_MSGS (sizeof(msg_type_strings)/sizeof(value_string))
static gint ett_msgs[NUM_MSGS];
static void (*gsm_sms_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset) = {
    dis_msg_deliver,		/* SMS-DELIVER */
    dis_msg_deliver_report,	/* SMS-DELIVER REPORT */
    dis_msg_submit,			/* SMS-SUBMIT */
    dis_msg_submit_report,	/* SMS-SUBMIT REPORT */
    dis_msg_status_report,	/* SMS-STATUS REPORT */
    dis_msg_command,		/* SMS-COMMAND */
    NULL,					/* Reserved */
    NULL,					/* Reserved */
    NULL,					/* NONE */
};

/* GENERIC DISSECTOR FUNCTIONS */

static void
dissect_gsm_sms(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    void (*msg_fcn)(tvbuff_t *tvb, proto_tree *tree, guint32 offset) = NULL;
    proto_item	*gsm_sms_item;
    proto_tree	*gsm_sms_tree = NULL;
    guint32	offset;
    guint8	msg_type;
    guint8	oct;
    gint	idx;
    const gchar	*str = NULL;
    gint	ett_msg_idx;


    g_pinfo = pinfo;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, gsm_sms_proto_name_short);
    }

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree)
    {
	g_tree = tree;

	offset = 0;

	oct = tvb_get_guint8(tvb, offset);

	oct &= 0x03;
	msg_type = oct;

	/*
	 * convert the 2 bit value to one based on direction
	 */
	if (pinfo->p2p_dir == P2P_DIR_UNKNOWN)
	{
	    /* Return Result ... */
	    if (msg_type == 0) /* SMS-DELIVER */
	    {
		msg_type |= 0x04; /* see the msg_type_strings */
	    }
	}
	else
	{
	    msg_type |= ((pinfo->p2p_dir == P2P_DIR_RECV) ? 0x04 : 0x00);
	}

	str = match_strval_idx(msg_type, msg_type_strings, &idx);

	/*
	 * create the GSM_SMS protocol tree
	 */
	gsm_sms_item =
	    proto_tree_add_protocol_format(tree, proto_gsm_sms, tvb, 0, -1,
		"%s %s",
		gsm_sms_proto_name,
		(str == NULL) ? "Unknown message identifier" : str);

	gsm_sms_tree =
	    proto_item_add_subtree(gsm_sms_item, ett_gsm_sms);

	if ((str == NULL) ||
	    (msg_type == 0x03) ||
	    (msg_type == 0x07))
	{
	    return;
	}
	else
	{
	    ett_msg_idx = ett_msgs[idx];
	    msg_fcn = gsm_sms_msg_fcn[idx];
	}

	if (msg_fcn == NULL)
	{
	    proto_tree_add_text(gsm_sms_tree,
		tvb, offset, -1,
		"Message dissector not implemented");
	}
	else
	{
	    (*msg_fcn)(tvb, gsm_sms_tree, offset);
	}
    }
}


/* Register the protocol with Ethereal */
void
proto_register_gsm_sms(void)
{
    guint		i;
    guint		last_offset;

#if 0
    /* Setup list of header fields */
    static hf_register_info hf[] =
    {
    };
#endif

    /* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_PARMS	12
    static gint *ett[NUM_INDIVIDUAL_PARMS+NUM_MSGS+NUM_UDH_IEIS];

    ett[0] = &ett_gsm_sms;
    ett[1] = &ett_pid;
    ett[2] = &ett_pi;
    ett[3] = &ett_fcs;
    ett[4] = &ett_vp;
    ett[5] = &ett_scts;
    ett[6] = &ett_dt;
    ett[7] = &ett_st;
    ett[8] = &ett_addr;
    ett[9] = &ett_dcs;
    ett[10] = &ett_ud;
    ett[11] = &ett_udh;

    last_offset = NUM_INDIVIDUAL_PARMS;

    for (i=0; i < NUM_MSGS; i++, last_offset++)
    {
	ett_msgs[i] = -1;
	ett[last_offset] = &ett_msgs[i];
    }

    for (i=0; i < NUM_UDH_IEIS; i++, last_offset++)
    {
	ett_udh_ieis[i] = -1;
	ett[last_offset] = &ett_udh_ieis[i];
    }

    /* Register the protocol name and description */

    proto_gsm_sms =
	proto_register_protocol(gsm_sms_proto_name, gsm_sms_proto_name_short, "gsm_sms");

#if 0
    proto_register_field_array(proto_gsm_sms, hf, array_length(hf));
#endif

    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_gsm_sms(void)
{
    dissector_handle_t	gsm_sms_handle;

    gsm_sms_handle = create_dissector_handle(dissect_gsm_sms, proto_gsm_sms);

    dissector_add("gsm_a.sms_tpdu", 0, gsm_sms_handle);
    dissector_add("gsm_map.sms_tpdu", 0, gsm_sms_handle);

    data_handle = find_dissector("data");
}
