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
 * Header field support for TPDU Parameters added by
 * Abhik Sarkar.
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

#include <glib.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <string.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>

#include "packet-gsm_sms.h"

#define MAX_SMS_FRAG_LEN		134

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

static gint ett_udh_tfm = -1;
static gint ett_udh_tfc = -1;

/* Initialize the protocol and registered fields */
static int proto_gsm_sms = -1;

static gint hf_gsm_sms_coding_group_bits2 = -1;
static gint hf_gsm_sms_coding_group_bits4 = -1;
static gint  hf_gsm_sms_ud_multiple_messages_msg_id = -1;
static gint  hf_gsm_sms_ud_multiple_messages_msg_parts = -1;
static gint  hf_gsm_sms_ud_multiple_messages_msg_part = -1;

/* TPDU Parameters */
static gint hf_gsm_sms_tp_mti_up = -1;
static gint hf_gsm_sms_tp_mti_down = -1;
static gint hf_gsm_sms_tp_mms = -1;
static gint hf_gsm_sms_tp_vpf = -1;
static gint hf_gsm_sms_tp_sri = -1;
static gint hf_gsm_sms_tp_srr = -1;
static gint hf_gsm_sms_tp_mr = -1;
static gint hf_gsm_sms_tp_oa = -1;
static gint hf_gsm_sms_tp_da = -1;
static gint hf_gsm_sms_tp_pid = -1;
static gint hf_gsm_sms_tp_dcs = -1;
static gint hf_gsm_sms_tp_ra = -1;
static gint hf_gsm_sms_tp_rp = -1;
static gint hf_gsm_sms_tp_udhi = -1;
static gint hf_gsm_sms_tp_rd = -1;
static gint hf_gsm_sms_tp_srq = -1;
static gint hf_gsm_sms_text = -1;
static gint hf_gsm_sms_tp_fail_cause = -1;
#if 0
static gint hf_gsm_sms_tp_scts = -1;
static gint hf_gsm_sms_tp_vp = -1;
static gint hf_gsm_sms_tp_dt = -1;
static gint hf_gsm_sms_tp_st = -1;
static gint hf_gsm_sms_tp_udl = -1;
static gint hf_gsm_sms_tp_mn = -1;
static gint hf_gsm_sms_tp_ct = -1;
static gint hf_gsm_sms_tp_cdl = -1;
static gint hf_gsm_sms_tp_cd = -1;
static gint hf_gsm_sms_tp_ud = -1;
#endif

static gboolean reassemble_sms = TRUE;
static char bigbuf[1024];
static packet_info *g_pinfo;
static proto_tree *g_tree;

/* 3GPP TS 23.038 version 7.0.0 Release 7
 * The TP-Data-Coding-Scheme field, defined in 3GPP TS 23.040 [4],
 * indicates the data coding scheme of the TP-UD field, and may indicate a message class.
 * Any reserved codings shall be assumed to be the GSM 7 bit default alphabet
 * (the same as codepoint 00000000) by a receiving entity.
 * The octet is used according to a coding group which is indicated in bits 7..4.
 */

/* Coding Group Bits */
static const value_string gsm_sms_coding_group_bits_vals[] = {
    { 0,	"General Data Coding indication" },			/* 00xx */
    { 1,	"General Data Coding indication" },			/* 00xx */
    { 2,	"General Data Coding indication" },			/* 00xx */
    { 3,	"General Data Coding indication" },			/* 00xx */
    { 4,	"Message Marked for Automatic Deletion Group" },	/* 01xx */
    { 5,	"Message Marked for Automatic Deletion Group" },	/* 01xx */
    { 6,	"Message Marked for Automatic Deletion Group" },	/* 01xx */
    { 7,	"Message Marked for Automatic Deletion Group" },	/* 01xx */
    { 8,	"Reserved coding groups" },				/* 1000..1011  */
    { 9,	"Reserved coding groups" },				/* 1000..1011  */
    { 10,	"Reserved coding groups" },				/* 1000..1011  */
    { 11,	"Reserved coding groups" },				/* 1000..1011  */
    { 12,	"Message Waiting Indication Group: Discard Message" },	/* 1100  */
    { 13,	"Message Waiting Indication Group: Store Message" },	/* 1101  */
    { 14,	"Message Waiting Indication Group: Store Message" },	/* 1110  */
    { 15,	"Data coding/message class" },  /* 1111  */
    { 0, NULL },
};

static guint16   g_sm_id;
static guint16   g_frags;
static guint16   g_frag;

static guint16   g_port_src;
static guint16   g_port_dst;
static gboolean	 g_is_wsp;

static dissector_table_t gsm_sms_dissector_tbl;
/* Short Message reassembly */
static GHashTable *g_sm_fragment_table = NULL;
static GHashTable *g_sm_reassembled_table = NULL;
static gint ett_gsm_sms_ud_fragment = -1;
static gint ett_gsm_sms_ud_fragments = -1;
 /*
 * Short Message fragment handling
 */
static int hf_gsm_sms_ud_fragments = -1;
static int hf_gsm_sms_ud_fragment = -1;
static int hf_gsm_sms_ud_fragment_overlap = -1;
static int hf_gsm_sms_ud_fragment_overlap_conflicts = -1;
static int hf_gsm_sms_ud_fragment_multiple_tails = -1;
static int hf_gsm_sms_ud_fragment_too_long_fragment = -1;
static int hf_gsm_sms_ud_fragment_error = -1;
static int hf_gsm_sms_ud_fragment_count = -1;
static int hf_gsm_sms_ud_reassembled_in = -1;
static int hf_gsm_sms_ud_reassembled_length = -1;

static const fragment_items sm_frag_items = {
    /* Fragment subtrees */
    &ett_gsm_sms_ud_fragment,
    &ett_gsm_sms_ud_fragments,
    /* Fragment fields */
    &hf_gsm_sms_ud_fragments,
    &hf_gsm_sms_ud_fragment,
    &hf_gsm_sms_ud_fragment_overlap,
    &hf_gsm_sms_ud_fragment_overlap_conflicts,
    &hf_gsm_sms_ud_fragment_multiple_tails,
    &hf_gsm_sms_ud_fragment_too_long_fragment,
    &hf_gsm_sms_ud_fragment_error,
    &hf_gsm_sms_ud_fragment_count,
    /* Reassembled in field */
    &hf_gsm_sms_ud_reassembled_in,
    /* Reassembled length field */
    &hf_gsm_sms_ud_reassembled_length,
    /* Tag */
    "Short Message fragments"
};


static void
gsm_sms_defragment_init (void)
{
    fragment_table_init (&g_sm_fragment_table);
    reassembled_table_init(&g_sm_reassembled_table);
}

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

static const value_string msg_type_strings_sc_to_ms[] = {
    { 0,	"SMS-DELIVER" },
    { 1,	"SMS-SUBMIT REPORT" },
    { 2,	"SMS-STATUS REPORT" },
    { 3,	"Reserved" },
    { 0, NULL },
};

static const value_string msg_type_strings_ms_to_sc[] = {
    { 0,	"SMS-DELIVER REPORT" },
    { 1,	"SMS-SUBMIT" },
    { 2,	"SMS-COMMAND" },
    { 3,	"Reserved" },
    { 0, NULL },
};

/* 9.2.3.3 TP-Validity-Period-Format (TP-VPF) */
static const value_string vp_type_strings[] = {
    { 0,	"TP-VP field not present"},
    { 2,	"TP-VP field present - relative format"},
    { 1,	"TP-VP field present - enhanced format"},
    { 3,	"TP-VP field present - absolute format"},
    { 0, NULL },
};

static const true_false_string mms_bool_strings = {
    "No more messages are waiting for the MS in this SC",
    "More messages are waiting for the MS in this SC"
};

static const true_false_string sri_bool_strings = {
    "A status report shall be returned to the SME",
    "A status report shall not be returned to the SME"
};

static const true_false_string srr_bool_strings = {
    "A status report is requested",
    "A status report is not requested"
};

static const true_false_string udhi_bool_strings = {
    "The beginning of the TP UD field contains a Header in addition to the short message",
    "The TP UD field contains only the short message"
};

static const true_false_string rp_bool_strings = {
    "TP Reply Path parameter is set in this SMS SUBMIT/DELIVER",
    "TP Reply Path parameter is not set in this SMS SUBMIT/DELIVER"
};

static const true_false_string rd_bool_strings = {
    "Instruct SC to reject duplicates",
    "Instruct SC to accept duplicates"
};

static const true_false_string srq_bool_strings = {
    "The SMS STATUS REPORT is the result of an SMS COMMAND e.g. an Enquiry.",
    "SMS STATUS REPORT is the result of a SMS SUBMIT."
};

#define	NUM_UDH_IEIS	256
static gint ett_udh_ieis[NUM_UDH_IEIS];

#define MAX_ADDR_SIZE 20
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
    char                addrbuf[MAX_ADDR_SIZE+1];
    gchar               *addrstr;

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

    item = proto_tree_add_text(tree, tvb,
	    offset, numdigocts + 2, "%s",
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
	i = gsm_sms_char_7bit_unpack(0, numdigocts, MAX_ADDR_SIZE, tvb_get_ptr(tvb, offset, numdigocts), addrbuf);
	addrbuf[i] = '\0';
	addrstr = gsm_sms_chars_to_utf8(addrbuf, i);
	break;
    default:
	addrstr = ep_alloc(numdigocts*2 + 1);
	for (i = 0; i < numdigocts; i++)
	{
	    oct = tvb_get_guint8(tvb, offset + i);

	    addrstr[j++] = digit_table[oct & 0x0f];
	    addrstr[j++] = digit_table[(oct & 0xf0) >> 4];
	}
	addrstr[j++] = '\0';
	break;
    }

    if (g_ascii_strncasecmp(title, "TP-O", 4) == 0) {
	proto_tree_add_string(subtree, hf_gsm_sms_tp_oa, tvb,
		offset, numdigocts, addrstr);
    } else if (g_ascii_strncasecmp(title, "TP-D", 4) == 0) {
	proto_tree_add_string(subtree, hf_gsm_sms_tp_da, tvb,
		offset, numdigocts, addrstr);
    } else if (g_ascii_strncasecmp(title, "TP-R", 4) == 0) {
	proto_tree_add_string(subtree, hf_gsm_sms_tp_ra, tvb,
		offset, numdigocts, addrstr);
    } else {
    	proto_tree_add_text(subtree,
	tvb, offset, numdigocts,
	"Digits: %s",
	addrstr);
    }

    proto_item_append_text(item, " - (%s)", addrstr);

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


    item = proto_tree_add_item(tree, hf_gsm_sms_tp_pid, tvb, offset, 1, ENC_BIG_ENDIAN);

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

    item = proto_tree_add_item(tree, hf_gsm_sms_tp_dcs, tvb, offset, 1, ENC_BIG_ENDIAN);

    subtree = proto_item_add_subtree(item, ett_dcs);
    if (oct&0x80) {
        proto_tree_add_item(subtree, hf_gsm_sms_coding_group_bits4, tvb, offset, 1, ENC_BIG_ENDIAN);
    } else {
        proto_tree_add_item(subtree, hf_gsm_sms_coding_group_bits2, tvb, offset, 1, ENC_BIG_ENDIAN);
    }

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
	case 0x01: str = "8 bit data";
		*eight_bit = TRUE;
		break;
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

/*
 * 9.2.3.22 TP-Failure-Cause (TP-FCS)
 */


static const value_string gsm_sms_tp_failure_cause_values[] = {
	/* 00 - 7F Reserved */
	/* 80 - 8F TP-PID errors */
  { 0x80,	"Telematic interworking not supported" },
  { 0x81,	"Short message Type 0 not supported" },
  { 0x82,	"Cannot replace short message" },
	/* 83 - 8E Reserved */
  { 0x83,	"Reserved" },
  { 0x84,	"Reserved" },
  { 0x85,	"Reserved" },
  { 0x86,	"Reserved" },
  { 0x87,	"Reserved" },
  { 0x88,	"Reserved" },
  { 0x89,	"Reserved" },
  { 0x8a,	"Reserved" },
  { 0x8b,	"Reserved" },
  { 0x8c,	"Reserved" },
  { 0x8d,	"Reserved" },
  { 0x8e,	"Reserved" },

  { 0x8F,	"Unspecified TP-PID error" },
	/* 90 - 9F TP-DCS errors */
  { 0x90,	"Data coding scheme (alphabet) not supported" },
  { 0x91,	"Message class not supported" },
	/* 92 - 9E Reserved */
  { 0x92,	"Reserved" },
  { 0x93,	"Reserved" },
  { 0x94,	"Reserved" },
  { 0x95,	"Reserved" },
  { 0x96,	"Reserved" },
  { 0x97,	"Reserved" },
  { 0x98,	"Reserved" },
  { 0x99,	"Reserved" },
  { 0x9a,	"Reserved" },
  { 0x9b,	"Reserved" },
  { 0x9c,	"Reserved" },
  { 0x9d,	"Reserved" },
  { 0x9e,	"Reserved" },

  { 0x9F,	"Unspecified TP-DCS error" },
	/* A0 - AF TP-Command Errors */
  { 0xA0,	"Command cannot be actioned" },
  { 0xA1,	"Command unsupported" },
	/* A2 - AE Reserved */
  { 0xa2,	"Reserved" },
  { 0xa3,	"Reserved" },
  { 0xa4,	"Reserved" },
  { 0xa5,	"Reserved" },
  { 0xa6,	"Reserved" },
  { 0xa7,	"Reserved" },
  { 0xa8,	"Reserved" },
  { 0xa9,	"Reserved" },
  { 0xaa,	"Reserved" },
  { 0xab,	"Reserved" },
  { 0xac,	"Reserved" },
  { 0xad,	"Reserved" },
  { 0xae,	"Reserved" },

  { 0xAF,	"Unspecified TP-Command error" },
  { 0xB0,	"TPDU not supported" },
	/* B1 - BF Reserved */
  { 0xb1,	"Reserved" },
  { 0xb2,	"Reserved" },
  { 0xb3,	"Reserved" },
  { 0xb4,	"Reserved" },
  { 0xb5,	"Reserved" },
  { 0xb6,	"Reserved" },
  { 0xb7,	"Reserved" },
  { 0xb8,	"Reserved" },
  { 0xb9,	"Reserved" },
  { 0xba,	"Reserved" },
  { 0xbb,	"Reserved" },
  { 0xbc,	"Reserved" },
  { 0xbd,	"Reserved" },
  { 0xbe,	"Reserved" },
  { 0xbf,	"Reserved" },

  { 0xC0,	"SC busy" },
  { 0xC1,	"No SC subscription" },
  { 0xC2,	"SC system failure" },
  { 0xC3,	"Invalid SME address" },
  { 0xC4,	"Destination SME barred" },
  { 0xC5,	"SM Rejected-Duplicate SM" },
  { 0xC6,	"TP-VPF not supported" },
  { 0xC7,	"TP-VP not supported" },
	/* C8 - CF Reserved */
  { 0xc8,	"Reserved" },
  { 0xc9,	"Reserved" },
  { 0xca,	"Reserved" },
  { 0xcb,	"Reserved" },
  { 0xcc,	"Reserved" },
  { 0xcd,	"Reserved" },
  { 0xce,	"Reserved" },
  { 0xcf,	"Reserved" },

  { 0xD0,	"(U)SIM SMS storage full" },
  { 0xD1,	"No SMS storage capability in (U)SIM" },
  { 0xD2,	"Error in MS" },
  { 0xD3,	"Memory Capacity Exceeded" },
  { 0xD4,	"(U)SIM Application Toolkit Busy" },
  { 0xD5,	"(U)SIM data download error" },
	/* D6 - DF Reserved */
  { 0xd6,	"Reserved" },
  { 0xd8,	"Reserved" },
  { 0xd9,	"Reserved" },
  { 0xda,	"Reserved" },
  { 0xdb,	"Reserved" },
  { 0xdc,	"Reserved" },
  { 0xdd,	"Reserved" },
  { 0xde,	"Reserved" },
  { 0xdf,	"Reserved" },

  /* E0 - FE Values specific to an application */
  { 0xe0,	"Value specific to an application" },
  { 0xe1,	"Value specific to an application" },
  { 0xe2,	"Value specific to an application" },
  { 0xe3,	"Value specific to an application" },
  { 0xe4,	"Value specific to an application" },
  { 0xe5,	"Value specific to an application" },
  { 0xe6,	"Value specific to an application" },
  { 0xe7,	"Value specific to an application" },
  { 0xe8,	"Value specific to an application" },
  { 0xe9,	"Value specific to an application" },
  { 0xea,	"Value specific to an application" },
  { 0xeb,	"Value specific to an application" },
  { 0xec,	"Value specific to an application" },
  { 0xed,	"Value specific to an application" },
  { 0xee,	"Value specific to an application" },
  { 0xef,	"Value specific to an application" },
  { 0xf0,	"Value specific to an application" },
  { 0xf1,	"Value specific to an application" },
  { 0xf2,	"Value specific to an application" },
  { 0xf3,	"Value specific to an application" },
  { 0xf4,	"Value specific to an application" },
  { 0xf5,	"Value specific to an application" },
  { 0xf6,	"Value specific to an application" },
  { 0xf7,	"Value specific to an application" },
  { 0xf8,	"Value specific to an application" },
  { 0xf9,	"Value specific to an application" },
  { 0xfa,	"Value specific to an application" },
  { 0xfb,	"Value specific to an application" },
  { 0xfc,	"Value specific to an application" },
  { 0xfd,	"Value specific to an application" },
  { 0xfe,	"Value specific to an application" },

  { 0xFF,	"Unspecified error cause" },
  { 0,		NULL }
 };
static value_string_ext gsm_sms_tp_failure_cause_values_ext = VALUE_STRING_EXT_INIT(gsm_sms_tp_failure_cause_values);

static void
dis_field_fcs(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 oct _U_)
{
	proto_tree_add_item(tree, hf_gsm_sms_tp_fail_cause, tvb, offset, 1, ENC_BIG_ENDIAN);
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

    return (int)(out_num - output);
}

#define GN_CHAR_ALPHABET_SIZE 128

#define GN_CHAR_ESCAPE 0x1b

static gunichar gsm_default_alphabet[GN_CHAR_ALPHABET_SIZE] = {

    /* ETSI GSM 03.38, version 6.0.1, section 6.2.1; Default alphabet */
    /* Fixed to use unicode */
    /* Characters in hex position 10, [12 to 1a] and 24 are not present on
       latin1 charset, so we cannot reproduce on the screen, however they are
       greek symbol not present even on my Nokia */

    '@',  0xa3, '$' , 0xa5, 0xe8, 0xe9, 0xf9, 0xec,
    0xf2, 0xc7, '\n', 0xd8, 0xf8, '\r', 0xc5, 0xe5,
   0x394, '_', 0x3a6,0x393,0x39b,0x3a9,0x3a0,0x3a8,
   0x3a3,0x398,0x39e, 0xa0, 0xc6, 0xe6, 0xdf, 0xc9,
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

static gunichar
char_def_alphabet_ext_decode(unsigned char value)
{
    switch (value)
    {
    case 0x0a: return 0x0c; /* form feed */
    case 0x14: return '^';
    case 0x28: return '{';
    case 0x29: return '}';
    case 0x2f: return '\\';
    case 0x3c: return '[';
    case 0x3d: return '~';
    case 0x3e: return ']';
    case 0x40: return '|';
    case 0x65: return 0x20ac; /* euro */
    default: return '?'; /* invalid character */
    }
}

static gunichar
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

gchar *
gsm_sms_chars_to_utf8(const unsigned char* src, int len)
{
    gint outlen, i, j;
    gunichar c;
    gchar *outbuf;

    /* Scan the input string to see how long the output string will be */
    for (outlen = 0, j = 0; j < len;  j++)
    {
	if (char_is_escape(src[j])) {
	    j++;
	    if (j == len)
		c = '?';	/* escape with nothing following it - error */
	    else
		c = char_def_alphabet_ext_decode(src[j]);
	}
	else
	    c = char_def_alphabet_decode(src[j]);
        outlen += g_unichar_to_utf8(c,NULL);
    }

    /* Now allocate a buffer for the output string and fill it in */
    outbuf = ep_alloc(outlen + 1);
    for (i = 0, j = 0; j < len;  j++)
    {
	if (char_is_escape(src[j])) {
	    j++;
	    if (j == len)
		c = '?';	/* escape with nothing following it - error */
	    else
		c = char_def_alphabet_ext_decode(src[j]);
	}
	else
	    c = char_def_alphabet_decode(src[j]);
        i += g_unichar_to_utf8(c,&(outbuf[i]));
    }
    outbuf[i] = '\0';
    return outbuf;
}

/*
 * END FROM GNOKII
 */

/* 9.2.3.24.1 */
static void
dis_iei_csm8(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    guint8	oct;

    EXACT_DATA_CHECK(length, 3);
    oct = tvb_get_guint8(tvb, offset);
    g_sm_id = oct;
    proto_tree_add_uint (tree,
                         hf_gsm_sms_ud_multiple_messages_msg_id,
                         tvb, offset, 1, g_sm_id);
    offset++;

    oct = tvb_get_guint8(tvb, offset);
    g_frags = oct;
    proto_tree_add_uint (tree,
                         hf_gsm_sms_ud_multiple_messages_msg_parts,
                         tvb , offset , 1, g_frags);
    offset++;
    oct = tvb_get_guint8(tvb, offset);
    g_frag = oct;
    proto_tree_add_uint (tree,
                         hf_gsm_sms_ud_multiple_messages_msg_part,
                         tvb, offset, 1, g_frag);

}

/* TODO 9.2.3.24.2 Special SMS Message Indication */

/* 9.2.3.24.3 */
static void
dis_iei_apa_8bit(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    const gchar	*str = NULL;
    guint8	oct;


    EXACT_DATA_CHECK(length, 2);

    oct = tvb_get_guint8(tvb, offset);
    g_port_dst = oct;
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
    g_port_src = oct;
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

/* 9.2.3.24.4 */
static void
dis_iei_apa_16bit(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    const gchar	*str = NULL;
    guint32	value;


    EXACT_DATA_CHECK(length, 4);

    value = tvb_get_ntohs(tvb, offset);
    g_port_dst = value;
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
    g_port_src = value;
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

	g_is_wsp = 1;
}

/* 9.2.3.24.5 */
static void
dis_iei_scp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    guint8	oct;

    EXACT_DATA_CHECK(length, 1);

    oct = tvb_get_guint8(tvb, offset);

    if (oct & 0x01)
    {
        proto_tree_add_text(tree,
                            tvb, offset, 1,
                            "Status Report for short message transaction completed");
    }
    else
    {
        proto_tree_add_text(tree,
                            tvb, offset, 1,
                            "No Status Report for short message transaction completed");
    }

    if (oct & 0x02)
    {
        proto_tree_add_text(tree,
                            tvb, offset, 1,
                            "Status Report for permanent error when SC is not making any more transfer attempts");
    }
    else
    {
        proto_tree_add_text(tree,
                            tvb, offset, 1,
                            "No Status Report for permanent error when SC is not making any more transfer attempts");
    }

    if (oct & 0x04)
    {
        proto_tree_add_text(tree,
                            tvb, offset, 1,
                            "Status Report for temporary error when SC is not making any more transfer attempts");
    }
    else
    {
        proto_tree_add_text(tree,
                            tvb, offset, 1,
                            "No Status Report for temporary error when SC is not making any more transfer attempts");
    }

    if (oct & 0x08)
    {

        proto_tree_add_text(tree,
                            tvb, offset, 1,
                            "Status Report for temporary error when SC is still trying to transfer SM");
    }
    else
    {
        proto_tree_add_text(tree,
                            tvb, offset, 1,
                            "No Status Report for temporary error when SC is still trying to transfer SM");
    }

    if (oct & 0x40)
    {

        proto_tree_add_text(tree,
                            tvb, offset, 1,
                            "A Status Report generated by this Short Message, due to a permanent error or last temporary error, cancels the SRR of the rest of the Short Messages in a concatenated message");
    }
    else
    {
        proto_tree_add_text(tree,
                            tvb, offset, 1,
                            "No activation");
    }

    if (oct & 0x80)
    {

        proto_tree_add_text(tree,
                            tvb, offset, 1,
                            "Include original UDH into the Status Report");
    }
    else
    {
        proto_tree_add_text(tree,
                            tvb, offset, 1,
                            "Do not include original UDH into the Status Report");
    }

}

/* 9.2.3.24.6 */
static void
dis_iei_udh_si(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    guint8	oct;

    EXACT_DATA_CHECK(length, 1);

    oct = tvb_get_guint8(tvb, offset);

    switch (oct)
    {
        case 1:
            proto_tree_add_text(tree,
                                tvb, offset, 1,
                                "The following part of the UDH is created by the original sender (valid in case of Status Report)");
            break;
        case 2:
            proto_tree_add_text(tree,
                                tvb, offset, 1,
                                "The following part of the UDH is created by the original receiver (valid in case of Status Report)");
            break;
        case 3:
            proto_tree_add_text(tree,
                                tvb, offset, 1,
                                "The following part of the UDH is created by the SMSC (can occur in any message or report)");
            break;
        default:
            proto_tree_add_text(tree,
                                tvb, offset, 1,
                                "The following part of the UDH is created by %d" , oct);
            break;
    }
}
/* 9.2.3.24.8 */
static void
dis_iei_csm16(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    guint8	oct;
    guint16	oct_ref;

    EXACT_DATA_CHECK(length, 4);
    oct_ref = tvb_get_ntohs(tvb, offset);
    g_sm_id = oct_ref;
    proto_tree_add_uint (tree,
                         hf_gsm_sms_ud_multiple_messages_msg_id,
                         tvb, offset, 2, g_sm_id);
    offset+=2;
    oct = tvb_get_guint8(tvb, offset);
    g_frags = oct;
    proto_tree_add_uint (tree,
                         hf_gsm_sms_ud_multiple_messages_msg_parts,
                         tvb , offset , 1, g_frags);

    offset++;
    oct = tvb_get_guint8(tvb, offset);
    g_frag = oct;
    proto_tree_add_uint (tree,
                         hf_gsm_sms_ud_multiple_messages_msg_part,
                         tvb, offset, 1, g_frag);
}

static const value_string text_color_values[] = {
  { 0x00,	"Black" },
  { 0x01,	"Dark Grey" },
  { 0x02,	"Dark Red" },
  { 0x03,	"Dark Yellow" },
  { 0x04,	"Dark Green" },
  { 0x05,	"Dark Cyan" },
  { 0x06,	"Dark Blue" },
  { 0x07,	"Dark Magenta" },
  { 0x08,	"Grey" },
  { 0x09,	"White" },
  { 0x0A,	"Bright Red" },
  { 0x0B,	"Bright Yellow" },
  { 0x0C,	"Bright Green" },
  { 0x0D,	"Bright Cyan" },
  { 0x0E,	"Bright Blue" },
  { 0x0F,	"Bright Magenta" },
  { 0,		NULL }
};

/* 9.2.3.24.10.1.1 */
static void
dis_iei_tf(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    const gchar *str = NULL;
    guint8	oct;
    proto_item	*item;
    proto_item	*item_colour;
    proto_tree	*subtree = NULL;
    proto_tree	*subtree_colour = NULL;


    EXACT_DATA_CHECK(length, 4);
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree, tvb, offset, 1,
                        "Start position of the text formatting: %d", oct);
    offset++;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree, tvb, offset, 1, "Text formatting length: %d",
                        oct);
    offset++;

    oct = tvb_get_guint8(tvb, offset);

    item = proto_tree_add_text(tree, tvb, offset, 1, "formatting mode");

    subtree = proto_item_add_subtree(item, ett_udh_tfm);
    switch(oct & 0x03)
    {
        case 0x00:
            str = "Left";
            break;
        case 0x01:
            str = "Center";
            break;
        case 0x02:
            str = "Right";
            break;
        case 0x03:
            str = "Language dependent";
            break;
    }

    proto_tree_add_text(subtree, tvb, offset, 1, "Alignment : %d %s",
                        oct & 0x03 , str);

    switch((oct >> 2) & 0x03)
    {
        case 0x00:
            str = "Normal";
            break;
        case 0x01:
            str = "Large";
            break;
        case 0x02:
            str = "Small";
            break;
        case 0x03:
            str = "reserved";
            break;
    }

    proto_tree_add_text(subtree, tvb, offset, 1, "Font Size : %d %s",
                        (oct >> 2) & 0x03 , str);

    if(oct & 0x10)
        str = "on";
    else
        str = "off";
    proto_tree_add_text(subtree, tvb, offset, 1, "Style bold : %d %s",
                        oct & 0x10 , str);

    if(oct & 0x20)
        str = "on";
    else
        str = "off";
    proto_tree_add_text(subtree, tvb, offset, 1, "Style Italic : %d %s",
                        oct & 0x20 , str);

    if(oct & 0x40)
        str = "on";
    else
        str = "off";
    proto_tree_add_text(subtree, tvb, offset, 1, "Style Underlined : %d %s",
                        oct & 0x40 , str);

    if(oct & 0x80)
        str = "on";
    else
        str = "off";
    proto_tree_add_text(subtree, tvb, offset, 1, "Style Strikethrough : %d %s",
                        oct & 0x80 , str);

    offset++;
    oct = tvb_get_guint8(tvb, offset);
    item_colour = proto_tree_add_text(tree, tvb, offset, 1, "Text Colour");

    subtree_colour = proto_item_add_subtree(item_colour, ett_udh_tfc);


    str = val_to_str(oct & 0x0f, text_color_values, "Unknown");
    proto_tree_add_text(subtree_colour, tvb, offset, 1,
                        "Foreground Colour : 0x%x %s",
                        oct & 0x0f , str);

    str = val_to_str((oct >> 4) & 0x0f, text_color_values, "Unknown");
    proto_tree_add_text(subtree_colour,
                        tvb, offset, 1,
                        "Background Colour : 0x%x %s",
                        (oct >> 4) & 0x0f , str);

}

/* 9.2.3.24.10.1.2 */
static void
dis_iei_ps(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    guint8	oct;

    EXACT_DATA_CHECK(length, 2);
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, 1,
                        "position: %d",
                        oct);
    offset++;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, 1,
                        "sound number: %d",
                        oct);
}

/* 9.2.3.24.10.1.3 */
static void
dis_iei_uds(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    guint8	oct;

    SHORT_DATA_CHECK(length, 2);
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, 1,
                        "position: %d",
                        oct);
    offset++;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, length - 1,
                        "User Defined Sound ");
}


/* 9.2.3.24.10.1.4 */
static void
dis_iei_pa(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    guint8	oct;

    EXACT_DATA_CHECK(length, 2);
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, 1,
                        "position: %d",
                        oct);
    offset++;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, 1,
                        "animation number: %d",
                        oct);
}


/* 9.2.3.24.10.1.5 */
static void
dis_iei_la(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    guint8	oct;

    SHORT_DATA_CHECK(length, 2);
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, 1,
                        "position: %d",
                        oct);
    offset++;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, length - 1,
                        "Large Animation ");
}

/* 9.2.3.24.10.1.6 */
static void
dis_iei_sa(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    guint8	oct;

    SHORT_DATA_CHECK(length, 2);
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, 1,
                        "position: %d",
                        oct);
    offset++;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, length - 1,
                        "Small Animation ");
}


/* 9.2.3.24.10.1.7 */
static void
dis_iei_lp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    guint8	oct;

    SHORT_DATA_CHECK(length, 2);
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, 1,
                        "position: %d",
                        oct);
    offset++;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, length - 1,
                        "Large Picture ");
}

/* 9.2.3.24.10.1.8 */
static void
dis_iei_sp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    guint8	oct;

    SHORT_DATA_CHECK(length, 2);
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, 1,
                        "position: %d",
                        oct);
    offset++;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, length - 1,
                        "Small Picture ");
}


/* 9.2.3.24.10.1.9 */
static void
dis_iei_vp(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    guint8	oct;

    SHORT_DATA_CHECK(length, 4);
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, 1,
                        "position: %d",
                        oct);
    offset++;

    oct = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree,
                        tvb, offset, 1,
                        "Horizontal dimension: %d",
                        oct);
    offset++;

    oct = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree,
                        tvb, offset, 1,
                        "Vertical dimension: %d",
                        oct);
    offset++;


    oct = tvb_get_guint8(tvb, offset);
    proto_tree_add_text(tree,
                        tvb, offset, length - 3,
                        "Variable Picture ");
}

/* 9.2.3.24.10.1.10 */
static void
dis_iei_upi(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    guint8	oct;

    EXACT_DATA_CHECK(length, 1);
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_text(tree,
                        tvb, offset, 1,
                        "Number of corresponding objects: %d",
                        oct);
    offset++;
}


/* */


static void
dis_field_ud_iei(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length)
{
    void (*iei_fcn)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint8 length);
    guint8	oct;
    proto_item	*item;
    proto_tree	*subtree = NULL;
    const gchar	*str = NULL;
    guint8	iei_len;


    while (length >= 2)
    {
	iei_fcn = NULL;

	oct = tvb_get_guint8(tvb, offset);

	switch (oct)
	{
            case 0x00: str = "Concatenated short messages, 8-bit reference number (SMS Control)"; iei_fcn = dis_iei_csm8; break;
            case 0x01: str = "Special SMS Message Indication (SMS Control)"; break;
            case 0x02: str = "Reserved N/A"; break;
            case 0x03: str = "Value not used to avoid misinterpretation as <LF> character N/A"; break;
            case 0x04: str = "Application port addressing scheme, 8 bit address (SMS Control)"; iei_fcn = dis_iei_apa_8bit; break;
            case 0x05: str = "Application port addressing scheme, 16 bit address (SMS Control)"; iei_fcn = dis_iei_apa_16bit; break;
            case 0x06: str = "SMSC Control Parameters (SMS Control)"; iei_fcn = dis_iei_scp; break;
            case 0x07: str = "UDH Source Indicator (SMS Control)"; iei_fcn  = dis_iei_udh_si; break;
            case 0x08: str = "Concatenated short message, 16-bit reference number (SMS Control)"; iei_fcn = dis_iei_csm16; break;
            case 0x09: str = "Wireless Control Message Protocol (SMS Control)"; break;
            case 0x0A: str = "Text Formatting (EMS Control)"; iei_fcn = dis_iei_tf;
            case 0x0B: str = "Predefined Sound (EMS Content)"; iei_fcn = dis_iei_ps;break;
            case 0x0C: str = "User Defined Sound (iMelody max 128 bytes) (EMS Content)"; iei_fcn = dis_iei_uds;break;
            case 0x0D: str = "Predefined Animation (EMS Content)"; iei_fcn = dis_iei_pa;break;
            case 0x0E: str = "Large Animation (16*16 times 4 = 32*4 =128 bytes) (EMS Content)"; iei_fcn = dis_iei_la;break;
            case 0x0F: str = "Small Animation (8*8 times 4 = 8*4 =32 bytes) (EMS Content)"; iei_fcn = dis_iei_sa;break;
            case 0x10: str = "Large Picture (32*32 = 128 bytes) (EMS Content)"; iei_fcn = dis_iei_lp;break;
            case 0x11: str = "Small Picture (16*16 = 32 bytes) (EMS Content)"; iei_fcn = dis_iei_sp;break;
            case 0x12: str = "Variable Picture (EMS Content)"; iei_fcn = dis_iei_vp;break;
            case 0x13: str = "User prompt indicator (EMS Control)"; iei_fcn = dis_iei_upi;break;
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
#define NUM_FILL_BITS_MASKS 6
#define SMS_MAX_MESSAGE_SIZE 160
static char    messagebuf[SMS_MAX_MESSAGE_SIZE+1];
static void
dis_field_ud(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint32 length, gboolean udhi, guint8 udl,
    gboolean seven_bit, gboolean eight_bit, gboolean ucs2, gboolean compressed)
{
    static guint8	fill_bits_mask[NUM_FILL_BITS_MASKS] =
	{ 0x80, 0xc0, 0xe0, 0xf0, 0xf8, 0xfc };
    proto_item	*item;
    proto_item	*udh_item;
    proto_tree	*subtree = NULL;
    proto_tree	*udh_subtree = NULL;
    tvbuff_t    *sm_tvb = NULL;
    fragment_data *fd_sm = NULL;
    guint8	oct;
    guint	fill_bits;
    guint32	out_len , total_sms_len , len_sms , length_ucs2 , i;
    char	*ustr;
    proto_item  *ucs2_item;
    gchar       *utf8_text = NULL;
    gchar save_byte = 0 , save_byte2 = 0;
    GIConv cd;
    GError *l_conv_error = NULL;

    gboolean    reassembled = FALSE;
    guint32     reassembled_in = 0;
    gboolean    is_fragmented = FALSE;
    gboolean    save_fragmented = FALSE, try_gsm_sms_ud_reassemble = FALSE;
    guint32     num_labels;

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
                            "User Data Header Length (%u)",
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
            if (fill_bits < NUM_FILL_BITS_MASKS)
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

    if (g_frags > 1)
        is_fragmented = TRUE;

    if ( is_fragmented && reassemble_sms)
    {
        try_gsm_sms_ud_reassemble = TRUE;
        save_fragmented = g_pinfo->fragmented;
        g_pinfo->fragmented = TRUE;
        fd_sm = fragment_add_seq_check (tvb, offset, g_pinfo,
                                        g_sm_id, /* guint32 ID for fragments belonging together */
                                        g_sm_fragment_table, /* list of message fragments */
                                        g_sm_reassembled_table, /* list of reassembled messages */
                                        g_frag-1, /* guint32 fragment sequence number */
                                        length, /* guint32 fragment length */
                                        (g_frag != g_frags)); /* More fragments? */
        if (fd_sm)
        {
            reassembled = TRUE;
            reassembled_in = fd_sm->reassembled_in;
        }

        sm_tvb = process_reassembled_data(tvb, offset, g_pinfo,
                                          "Reassembled Short Message", fd_sm, &sm_frag_items,
                                          NULL, tree);

	if(reassembled && g_pinfo->fd->num == reassembled_in)
        {
            /* Reassembled */
            col_append_str (g_pinfo->cinfo, COL_INFO,
                            " (Short Message Reassembled)");
        }
        else
        {
            /* Not last packet of reassembled Short Message */
            col_append_fstr (g_pinfo->cinfo, COL_INFO,
                             " (Short Message fragment %u of %u)", g_frag, g_frags);
        }
    } /* Else: not fragmented */
    if (! sm_tvb) /* One single Short Message, or not reassembled */
        sm_tvb = tvb_new_subset_remaining (tvb, offset);

    if (compressed)
    {
        proto_tree_add_text(subtree, tvb, offset, length, "Compressed data");
    }
    else
    {
	if (seven_bit)
	{
	    if(!(reassembled && g_pinfo->fd->num == reassembled_in))
	    {
		/* Show unassembled SMS */
		out_len =
		    gsm_sms_char_7bit_unpack(fill_bits, length , SMS_MAX_MESSAGE_SIZE,
					     tvb_get_ptr(tvb , offset , length) , messagebuf);
		messagebuf[out_len] = '\0';
		proto_tree_add_string(subtree, hf_gsm_sms_text, tvb, offset,
				      length,
				      gsm_sms_chars_to_utf8(messagebuf, out_len));
	    }
	    else
	    {
		/*  Show reassembled SMS.  We show each fragment separately
		 *  so that the text doesn't get truncated when we add it to
		 *  the tree.
		 */
		out_len = 0;

		total_sms_len = tvb_length(sm_tvb);
		for(i = 0 ; i < g_frags; i++)
		{
		    /* maximum len msg in 7 bit with csm8 header*/
		    if(total_sms_len > MAX_SMS_FRAG_LEN)
		    {
			total_sms_len -= MAX_SMS_FRAG_LEN;
			len_sms = MAX_SMS_FRAG_LEN;
		    }
		    else
			len_sms = total_sms_len;

		    out_len =
			gsm_sms_char_7bit_unpack(fill_bits, len_sms, SMS_MAX_MESSAGE_SIZE,
						 tvb_get_ptr(sm_tvb, i * MAX_SMS_FRAG_LEN, len_sms),
						 messagebuf);

		    messagebuf[out_len] = '\0';
		    proto_tree_add_string(subtree, hf_gsm_sms_text, sm_tvb,
					  i * MAX_SMS_FRAG_LEN, len_sms,
					  gsm_sms_chars_to_utf8(messagebuf, out_len));
		}
	    }
	}
	else if (eight_bit)
	{
	    /*proto_tree_add_text(subtree, tvb , offset , length, "%s",
	      tvb_format_text(tvb, offset, length));				*/
	    if (! dissector_try_uint(gsm_sms_dissector_tbl, g_port_src, sm_tvb, g_pinfo, subtree))
	    {
		if (! dissector_try_uint(gsm_sms_dissector_tbl, g_port_dst,sm_tvb, g_pinfo, subtree))
		{
		    if (subtree)
		    { /* Only display if needed */
			proto_tree_add_text (subtree, sm_tvb, 0, -1,
					     "Short Message body");
		    }
		}
	    }
	}
	else if (ucs2)
	{
	    if ((cd = g_iconv_open("UTF-8","UCS-2BE")) != (GIConv)-1)
	    {
		guint8 rep_len = tvb_reported_length(sm_tvb);

		if(!(reassembled && g_pinfo->fd->num == reassembled_in))
		{
		    /* Show unreassembled SMS */
		    utf8_text = g_convert_with_iconv(tvb_get_ptr(sm_tvb, 0, rep_len), rep_len , cd , NULL , NULL , &l_conv_error);
		    if(!l_conv_error) {
			/* XXX - using proto_tree_add_string() doesn't work */
			ucs2_item = proto_tree_add_string_format_value(subtree, hf_gsm_sms_text, tvb,
								       offset, length, utf8_text, "%s", utf8_text);
		    } else {
			ucs2_item = proto_tree_add_text(subtree, tvb, offset, length, "Failed to decode UCS2!");
		    }
		    PROTO_ITEM_SET_GENERATED(ucs2_item);
		} else {
		    /*  Show reassembled SMS.  We show each fragment separately
		     *  so that the text doesn't get truncated when we add it to
		     *  the tree.
		     */
		    utf8_text = g_convert_with_iconv(tvb_get_ptr(sm_tvb, 0, rep_len), rep_len , cd , NULL , NULL , &l_conv_error);
		    if(!l_conv_error)
		    {
			len_sms = (int)strlen(utf8_text);
			num_labels = len_sms / MAX_SMS_FRAG_LEN;
			num_labels += len_sms % MAX_SMS_FRAG_LEN ? 1 : 0;
			for(i = 0; i < num_labels;i++) {
			    if(i * MAX_SMS_FRAG_LEN < len_sms) {
				/* set '\0' to byte number 134 text_node MAX size*/
				save_byte =  utf8_text[i * MAX_SMS_FRAG_LEN];
				save_byte2 =  utf8_text[i * MAX_SMS_FRAG_LEN + 1];
				if(i > 0)
				{
				    utf8_text[i * MAX_SMS_FRAG_LEN] = '\0';
				    utf8_text[i * MAX_SMS_FRAG_LEN + 1] = '\0';
				}

				length_ucs2 = MAX_SMS_FRAG_LEN;
			    } else
				length_ucs2 = len_sms % MAX_SMS_FRAG_LEN;

                            /* XXX - using proto_tree_add_string() doesn't work */
                            ucs2_item = proto_tree_add_string_format_value(subtree, hf_gsm_sms_text, sm_tvb,
                                                                           i * MAX_SMS_FRAG_LEN, length_ucs2,
                                                                           &utf8_text[i * MAX_SMS_FRAG_LEN],
                                                                           "%s", &utf8_text[i * MAX_SMS_FRAG_LEN]);
                            PROTO_ITEM_SET_GENERATED(ucs2_item);

			    /* return the save byte to utf8 buffer*/
			    if(i * MAX_SMS_FRAG_LEN < len_sms) {
				utf8_text[i * MAX_SMS_FRAG_LEN] = save_byte;
				utf8_text[i * MAX_SMS_FRAG_LEN + 1] = save_byte2;
			    }
			}
		    } else {
			ucs2_item = proto_tree_add_text(subtree, tvb, offset, length, "Failed to decode UCS2!");
                        PROTO_ITEM_SET_GENERATED(ucs2_item);
		    }
		}

		g_free(utf8_text);
		g_iconv_close(cd);
	    } else {
		/* tvb_get_ephemeral_faked_unicode takes the length in number of guint16's */
		ustr = tvb_get_ephemeral_faked_unicode(tvb, offset, (length>>1), FALSE);
		proto_tree_add_text(subtree, tvb, offset, length, "%s", ustr);
	    }
	}
    }

    if (try_gsm_sms_ud_reassemble) /* Clean up defragmentation */
        g_pinfo->fragmented = save_fragmented;
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
    udhi = oct & 0x40;

    proto_tree_add_item(tree, hf_gsm_sms_tp_rp, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_udhi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_sri, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mms, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mti_down, tvb, offset, 1, ENC_BIG_ENDIAN);

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
    gboolean	seven_bit = FALSE;
    gboolean	eight_bit = FALSE;
    gboolean	ucs2 = FALSE;
    gboolean	compressed = FALSE;
    gboolean	udhi;


    udl = 0;
    saved_offset = offset;
    length = tvb_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);
    udhi = oct & 0x40;

    proto_tree_add_item(tree, hf_gsm_sms_tp_udhi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mms, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mti_up, tvb, offset, 1, ENC_BIG_ENDIAN);

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
    gboolean	seven_bit;
    gboolean	eight_bit;
    gboolean	ucs2;
    gboolean	compressed;
    gboolean	udhi;


    saved_offset = offset;
    length = tvb_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);
    udhi = oct & 0x40;
    vp_form = ((oct & 0x18) >> 3);

    proto_tree_add_item(tree, hf_gsm_sms_tp_rp, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_udhi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_srr, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_vpf, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_rd, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mti_up, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_gsm_sms_tp_mr, tvb, offset, 1, ENC_BIG_ENDIAN);

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
    gboolean	seven_bit = FALSE;
    gboolean	eight_bit = FALSE;
    gboolean	ucs2 = FALSE;
    gboolean	compressed = FALSE;
    gboolean	udhi;


    udl = 0;
    saved_offset = offset;
    length = tvb_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);
    udhi = oct & 0x40;

    proto_tree_add_item(tree, hf_gsm_sms_tp_udhi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mti_down, tvb, offset, 1, ENC_BIG_ENDIAN);

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
    gboolean	seven_bit = FALSE;
    gboolean	eight_bit = FALSE;
    gboolean	ucs2 = FALSE;
    gboolean	compressed = FALSE;
    gboolean	udhi;


    udl = 0;
    saved_offset = offset;
    length = tvb_length_remaining(tvb, offset);

    oct = tvb_get_guint8(tvb, offset);
    udhi = oct & 0x40;

    proto_tree_add_item(tree, hf_gsm_sms_tp_udhi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_srq, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mms, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mti_down, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;
    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_item(tree, hf_gsm_sms_tp_mr, tvb, offset, 1, ENC_BIG_ENDIAN);

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
    guint8	oct;
    guint8	cdl;
    const gchar	*str = NULL;


    cdl = 0;

    proto_tree_add_item(tree, hf_gsm_sms_tp_udhi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_srr, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_sms_tp_mti_up, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    proto_tree_add_item(tree, hf_gsm_sms_tp_mr, tvb, offset, 1, ENC_BIG_ENDIAN);

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

#if 0
#define	NUM_MSGS (sizeof(msg_type_strings)/sizeof(value_string))
static gint ett_msgs[NUM_MSGS];
#endif

static void (*gsm_sms_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint32 offset) = {
    dis_msg_deliver,        /* SMS-DELIVER */
    dis_msg_deliver_report, /* SMS-DELIVER REPORT */
    dis_msg_submit,         /* SMS-SUBMIT */
    dis_msg_submit_report,  /* SMS-SUBMIT REPORT */
    dis_msg_status_report,  /* SMS-STATUS REPORT */
    dis_msg_command,        /* SMS-COMMAND */
    NULL,                   /* Reserved */
    NULL,                   /* Reserved */
    NULL,                   /* NONE */
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
    /*gint	ett_msg_idx;*/


    g_pinfo = pinfo;
    g_is_wsp = 0;
    g_sm_id = 0;
    g_frags = 0;
    g_frag = 0;
    g_port_src = 0;
    g_port_dst = 0;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, gsm_sms_proto_name_short);

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree || reassemble_sms)
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
	    /*ett_msg_idx = ett_msgs[idx];*/ /* XXX: Not actually used */
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


/* Register the protocol with Wireshark */
void
proto_register_gsm_sms(void)
{
    guint     i;
    guint     last_offset;
    module_t *gsm_sms_module; /* Preferences for GSM SMS UD */

    /* Setup list of header fields */
    static hf_register_info hf[] =
        {
            { &hf_gsm_sms_coding_group_bits2,
              { "Coding Group Bits", "gsm_sms.coding_group_bits2",
                FT_UINT8, BASE_DEC, VALS(gsm_sms_coding_group_bits_vals), 0xc0,
                NULL, HFILL }
            },
            { &hf_gsm_sms_coding_group_bits4,
              { "Coding Group Bits", "gsm_sms.coding_group_bits4",
                FT_UINT8, BASE_DEC, VALS(gsm_sms_coding_group_bits_vals), 0xf0,
                NULL, HFILL }
            },

            /*
             * Short Message fragment reassembly
             */
            {	&hf_gsm_sms_ud_fragments,
                {	"Short Message fragments", "gsm_sms.fragments",
                        FT_NONE, BASE_NONE, NULL, 0x00,
                        "GSM Short Message fragments",
                        HFILL
                }
            },
            {	&hf_gsm_sms_ud_fragment,
                {	"Short Message fragment", "gsm_sms.fragment",
                        FT_FRAMENUM, BASE_NONE, NULL, 0x00,
                        "GSM Short Message fragment",
                        HFILL
                }
            },
            {	&hf_gsm_sms_ud_fragment_overlap,
                {	"Short Message fragment overlap", "gsm_sms.fragment.overlap",
                        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                        "GSM Short Message fragment overlaps with other fragment(s)",
                        HFILL
                }
            },
            {	&hf_gsm_sms_ud_fragment_overlap_conflicts,
                {	"Short Message fragment overlapping with conflicting data",
                        "gsm_sms.fragment.overlap.conflicts",
                        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                        "GSM Short Message fragment overlaps with conflicting data",
                        HFILL
                }
            },
            {	&hf_gsm_sms_ud_fragment_multiple_tails,
                {	"Short Message has multiple tail fragments",
                        "gsm_sms.fragment.multiple_tails",
                        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                        "GSM Short Message fragment has multiple tail fragments",
                        HFILL
                }
            },
            {	&hf_gsm_sms_ud_fragment_too_long_fragment,
                {	"Short Message fragment too long",
                        "gsm_sms.fragment.too_long_fragment",
                        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                        "GSM Short Message fragment data goes beyond the packet end",
                        HFILL
                }
            },
            {	&hf_gsm_sms_ud_fragment_error,
                {	"Short Message defragmentation error", "gsm_sms.fragment.error",
                        FT_FRAMENUM, BASE_NONE, NULL, 0x00,
                        "GSM Short Message defragmentation error due to illegal fragments",
                        HFILL
                }
            },
            {	&hf_gsm_sms_ud_fragment_count,
                {	"Short Message fragment count",
                        "gsm_sms.fragment.count",
                        FT_UINT32, BASE_DEC, NULL, 0x00,
                        NULL, HFILL
                }
            },
            {	&hf_gsm_sms_ud_reassembled_in,
                {	"Reassembled in",
                        "gsm_sms.reassembled.in",
                        FT_FRAMENUM, BASE_NONE, NULL, 0x00,
                        "GSM Short Message has been reassembled in this packet.", HFILL
                }
            },
            {	&hf_gsm_sms_ud_reassembled_length,
                {	"Reassembled Short Message length",
                        "gsm_sms.reassembled.length",
                        FT_UINT32, BASE_DEC, NULL, 0x00,
                        "The total length of the reassembled payload", HFILL
                }
            },
            {   &hf_gsm_sms_ud_multiple_messages_msg_id,
                {	"Message identifier", "gsm-sms.udh.mm.msg_id",
                        FT_UINT16, BASE_DEC, NULL, 0x00,
                        "Identification of the message",
                        HFILL
                }
            },
            {   &hf_gsm_sms_ud_multiple_messages_msg_parts,
                {	"Message parts", "gsm-sms.udh.mm.msg_parts",
                        FT_UINT8, BASE_DEC, NULL, 0x00,
                        "Total number of message parts (fragments)",
                        HFILL
                }
            },
            {   &hf_gsm_sms_ud_multiple_messages_msg_part,
                {	"Message part number", "gsm-sms.udh.mm.msg_part",
                        FT_UINT8, BASE_DEC, NULL, 0x00,
                        "Message part (fragment) sequence number",
                        HFILL
                }
            },
            /* TPDU parameters */
            { &hf_gsm_sms_tp_mti_up,
	      { "TP-MTI", "gsm_sms.tp-mti",
	        FT_UINT8, BASE_DEC, VALS(msg_type_strings_ms_to_sc), 0x03,
	        "TP-Message-Type-Indicator (in the direction MS to SC)", HFILL }
            },
            { &hf_gsm_sms_tp_mti_down,
	      { "TP-MTI", "gsm_sms.tp-mti",
	        FT_UINT8, BASE_DEC, VALS(msg_type_strings_sc_to_ms), 0x03,
	        "TP-Message-Type-Indicator (in the direction SC to MS)", HFILL }
            },
            { &hf_gsm_sms_tp_oa,
	      { "TP-OA Digits", "gsm_sms.tp-oa",
	        FT_STRING, BASE_NONE, NULL, 0x00,
	        "TP-Originating-Address Digits", HFILL }
            },
            { &hf_gsm_sms_tp_da,
	      { "TP-DA Digits", "gsm_sms.tp-da",
	        FT_STRING, BASE_NONE, NULL, 0x00,
	        "TP-Destination-Address Digits", HFILL }
            },
            { &hf_gsm_sms_tp_ra,
	      { "TP-RA Digits", "gsm_sms.tp-ra",
	        FT_STRING, BASE_NONE, NULL, 0x00,
	        "TP-Recipient-Address Digits", HFILL }
            },
            { &hf_gsm_sms_tp_pid,
	      { "TP-PID", "gsm_sms.tp-pid",
	        FT_UINT8, BASE_DEC, NULL, 0x00,
	        "TP-Protocol-Identifier", HFILL }
            },
            { &hf_gsm_sms_tp_dcs,
	      { "TP-DCS", "gsm_sms.tp-dcs",
	        FT_UINT8, BASE_DEC, NULL, 0x00,
	        "TP-Data-Coding-Scheme", HFILL }
            },
            { &hf_gsm_sms_tp_mr,
	      { "TP-MR", "gsm_sms.tp-mr",
	        FT_UINT8, BASE_DEC, NULL, 0x00,
	        "TP-Message-Reference", HFILL }
            },
            { &hf_gsm_sms_tp_mms,
	      { "TP-MMS", "gsm_sms.tp-mms",
	        FT_BOOLEAN, 8, TFS(&mms_bool_strings), 0x04,
	        "TP-More-Messages-to-Send", HFILL }
            },
            { &hf_gsm_sms_tp_sri,
	      { "TP-SRI", "gsm_sms.tp-sri",
	        FT_BOOLEAN, 8, TFS(&sri_bool_strings), 0x20,
	        "TP-Status-Report-Indication", HFILL }
            },
            { &hf_gsm_sms_tp_srr,
	      { "TP-SRR", "gsm_sms.tp-srr",
	        FT_BOOLEAN, 8, TFS(&srr_bool_strings), 0x20,
	        "TP-Status-Report-Request", HFILL }
            },
            { &hf_gsm_sms_tp_udhi,
	      { "TP-UDHI", "gsm_sms.tp-udhi",
	        FT_BOOLEAN, 8, TFS(&udhi_bool_strings), 0x40,
	        "TP-User-Data-Header-Indicator", HFILL }
            },
            { &hf_gsm_sms_tp_rp,
	      { "TP-RP", "gsm_sms.tp-rp",
	        FT_BOOLEAN, 8, TFS(&rp_bool_strings), 0x80,
	        "TP-Reply-Path", HFILL }
            },
            { &hf_gsm_sms_tp_vpf,
	      { "TP-VPF", "gsm_sms.tp-vpf",
	        FT_UINT8, BASE_DEC, VALS(vp_type_strings), 0x18,
	        "TP-Validity-Period-Format", HFILL }
            },
            { &hf_gsm_sms_tp_rd,
	      { "TP-RD", "gsm_sms.tp-rd",
	        FT_BOOLEAN, 8, TFS(&rd_bool_strings), 0x04,
	        "TP-Reject-Duplicates", HFILL }
            },
            { &hf_gsm_sms_tp_srq,
	      { "TP-SRQ", "gsm_sms.tp-srq",
	        FT_BOOLEAN, 8, TFS(&srq_bool_strings), 0x20,
	        "TP-Status-Report-Qualifier", HFILL }
            },
            { &hf_gsm_sms_text,
	      { "SMS text", "gsm_sms.sms_text",
	        FT_STRING, BASE_NONE, NULL, 0x00,
	        "The text of the SMS", HFILL }
            },
		  { &hf_gsm_sms_tp_fail_cause,
			{ "TP-Failure-Cause (TP-FCS)", "gsm_sms.tp-fcs",
	        FT_UINT8, BASE_HEX_DEC|BASE_EXT_STRING, &gsm_sms_tp_failure_cause_values_ext, 0x0,
	        "TP-Validity-Period-Format", HFILL }
            },
        };

    /* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_PARMS	12
    gint *ett[NUM_INDIVIDUAL_PARMS/*+NUM_MSGS*/+NUM_UDH_IEIS+2];

    ett[0]  = &ett_gsm_sms;
    ett[1]  = &ett_pid;
    ett[2]  = &ett_pi;
    ett[3]  = &ett_fcs;
    ett[4]  = &ett_vp;
    ett[5]  = &ett_scts;
    ett[6]  = &ett_dt;
    ett[7]  = &ett_st;
    ett[8]  = &ett_addr;
    ett[9]  = &ett_dcs;
    ett[10] = &ett_ud;
    ett[11] = &ett_udh;

    last_offset = NUM_INDIVIDUAL_PARMS;

#if 0
    for (i=0; i < NUM_MSGS; i++, last_offset++)
    {
	ett_msgs[i] = -1;
	ett[last_offset] = &ett_msgs[i];
    }
#endif

    for (i=0; i < NUM_UDH_IEIS; i++, last_offset++)
    {
	ett_udh_ieis[i] = -1;
	ett[last_offset] = &ett_udh_ieis[i];
    }

    ett[last_offset++] = &ett_gsm_sms_ud_fragment;
    ett[last_offset] = &ett_gsm_sms_ud_fragments;

    /* Register the protocol name and description */

    proto_gsm_sms =
	proto_register_protocol(gsm_sms_proto_name, gsm_sms_proto_name_short, "gsm_sms");


    proto_register_field_array(proto_gsm_sms, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));

    gsm_sms_dissector_tbl = register_dissector_table("gsm-sms.udh.port",
        "GSM SMS port IE in UDH", FT_UINT16, BASE_DEC);

    gsm_sms_module = prefs_register_protocol (proto_gsm_sms, NULL);

    prefs_register_obsolete_preference(gsm_sms_module,
				       "try_dissect_message_fragment");
    prefs_register_bool_preference (gsm_sms_module, "reassemble",
				    "Reassemble fragmented SMS",
				    "Whether the dissector should reassemble SMS spanning multiple packets",
				    &reassemble_sms);

    /* register_dissector("gsm-sms", dissect_gsm_sms, proto_gsm_sms); */

    /* GSM SMS UD dissector initialization routines */
    register_init_routine (gsm_sms_defragment_init);
}


void
proto_reg_handoff_gsm_sms(void)
{
    dissector_handle_t	gsm_sms_handle;

    gsm_sms_handle = create_dissector_handle(dissect_gsm_sms, proto_gsm_sms);

    dissector_add_uint("gsm_a.sms_tpdu", 0, gsm_sms_handle);
    dissector_add_uint("gsm_map.sms_tpdu", 0, gsm_sms_handle);
}
