/* packet-alcap.c
 * Routines for ALCAP (Q.2630.1) dissection
 * AAL type 2 signalling protocol - Capability set 1
 * 12/1999
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * $Id: packet-alcap.c,v 1.2 2003/10/06 14:48:00 jmayer Exp $
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


#define	ALCAP_MSG_HEADER_LEN	6
#define	ALCAP_PARM_HEADER_LEN	3

#define	ALCAP_SI		12

#define	EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
	proto_tree_add_none_format(tree, hf_alcap_none, tvb, \
	    curr_offset, (edc_len) - (edc_max_len), "Extraneous Data"); \
    }

#define	SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
    if ((sdc_len) < (sdc_min_len)) \
    { \
	proto_tree_add_none_format(tree, hf_alcap_none, tvb, \
	    curr_offset, (sdc_len), "Short Data (?)"); \
	return; \
    }

#define	EXACT_DATA_CHECK(edc_len, edc_eq_len) \
    if ((edc_len) != (edc_eq_len)) \
    { \
	proto_tree_add_none_format(tree, hf_alcap_none, tvb, \
	    curr_offset, (edc_len), "Unexpected Data Length"); \
	return; \
    }

static const value_string msg_parm_strings[] = {
    { 1,	"Cause (CAU)" },
    { 2,	"Connection element identifier (CEID)" },
    { 3,	"Destination E.164 service endpoint address (ESEA)" },
    { 4,	"Destination NSAP service endpoint address (NSEA)" },
    { 5,	"Link characteristics (ALC)" },
    { 6,	"Originating signalling association identifier (OSAID)" },
    { 7,	"Served user generated reference (SUGR)" },
    { 8,	"Served user transport (SUT)" },
    { 9,	"Service specific information (audio) (SSIA)" },
    { 10,	"Service specific information (multirate) (SSIM)" },
    { 11,	"Service specific information (SAR-assured) (SSISA)" },
    { 12,	"Service specific information (SAR-unassured) (SSISU)" },
    { 13,	"Test connection identifier (TCI)" },
    { 0, NULL },
};
define	NUM_PARMS (sizeof(msg_parm_strings)/sizeof(value_string))

static char *alcap_proto_name = "AAL type 2 signalling protocol - Capability set 1 (Q.2630.1)";
static char *alcap_proto_name_short = "ALCAP";

/* Initialize the subtree pointers */
static gint ett_alcap = -1;
static gint ett_parm = -1;

/* Initialize the protocol and registered fields */
static int proto_alcap = -1;
static int hf_alcap_msg_type = -1;
static int hf_alcap_length = -1;
static int hf_alcap_parm_id = -1;
static int hf_alcap_none = -1;
static int hf_alcap_dsaid = -1;
static int hf_alcap_osaid = -1;
static int hf_alcap_aal2_path_id = -1;
static int hf_alcap_channel_id = -1;
static int hf_alcap_organizational_unique_id = -1;
static int hf_alcap_served_user_gen_ref = -1;
static int hf_alcap_nsap_address = -1;

static char bigbuf[1024];
static char bigbuf2[1024];
static dissector_handle_t data_handle;
static packet_info *g_pinfo;
static proto_tree *g_tree;

#define	FIELD_COMPATIBILITY		0
#define	FIELD_SIGNALLING_ASSOC_ID	1
#define	FIELD_AAL2_PATH_ID		2
#define	FIELD_CHANNEL_ID		3
#define	FIELD_ORGANIZATIONAL_UNIQUE_ID	4
#define	FIELD_AUDIO_SERVICE		5
#define	FIELD_MULTIRATE_SERVICE		6
#define	FIELD_SEG_REASSEMBLY_ASS	7
#define	FIELD_SEG_REASSEMBLY_UNASS	8
#define	FIELD_SERVED_USER_GEN_REF	9
#define	FIELD_MAX_CPS_SDU_BIT_RATE	10
#define	FIELD_AVG_CPS_SDU_BIT_RATE	11
#define	FIELD_MAX_CPS_SDU_SIZE		12
#define	FIELD_AVG_CPS_SDU_SIZE		13
#define	FIELD_NATURE_OF_ADDRESS		14
#define	FIELD_E164_ADDRESS		15
#define	FIELD_NSAP_ADDRESS		16
#define	FIELD_CAUSE_VALUE		17
#define	FIELD_DIAGNOSTICS		18
#define	FIELD_SERVED_USER_TRANSPORT	19
static const char * field_strings[] = {
    "Compatibility",
    "Signalling association identifier",
    "AAL type 2 path identifier",
    "Channel identifier (CID)",
    "Organizational unique identifier (OUI)",
    "Audio service",
    "Multirate service",
    "Segmentation and reassembly (assured data transfer)",
    "Segmentation and reassembly (unassured data transfer)",
    "Served user generated reference",
    "Maximum CPS-SDU bit rate",
    "Average CPS-SDU bit rate",
    "Maximum CPS-SDU size",
    "Average CPS-SDU size",
    "Nature of address",
    "E.164 address",
    "NSAP address",
    "Cause value",
    "Diagnostics",
    "Served user transport"
};
#define	NUM_FIELDS (sizeof(field_strings)/sizeof(char *))
static gint ett_fields[NUM_FIELDS];

static const value_string msg_type_strings[] = {
    { 1,	"Block confirm (BLC)" },
    { 2,	"Block request (BLO)" },
    { 3,	"Confusion (CFN)" },
    { 4,	"Establish confirm (ECF)" },
    { 5,	"Establish request (ERQ)" },
    { 6,	"Release confirm (RLC)" },
    { 7,	"Release request (REL)" },
    { 8,	"Reset confirm (RSC)" },
    { 9,	"Reset request (RES)" },
    { 10,	"Unblock confirm (UBC)" },
    { 11,	"Unblock request (UBL)" },
    { 0, NULL },
};

/* FUNCTIONS */

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
	    *p++ = '1';
	    else
	    *p++ = '0';
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

    while (vs[i].strptr) {
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

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.1
 */
static void
dis_field_compatibility(tvbuff_t *tvb, proto_tree *tree, guint32 *offset, gboolean message)
{
    guint32	curr_offset;
    guint8	compat;
    proto_item	*item;
    proto_tree	*subtree;
    gchar	*str = NULL;

    curr_offset = *offset;

    item =
	proto_tree_add_none_format(tree, hf_alcap_none, tvb,
	    curr_offset, 1, "%s %s",
	    message ? "Message" : "Parameter",
	    field_strings[FIELD_COMPATIBILITY]);

    subtree = proto_item_add_subtree(item, ett_fields[FIELD_COMPATIBILITY]);

    compat = tvb_get_guint8(tvb, curr_offset);

    my_decode_bitfield_value(bigbuf, compat, 0x80, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Reserved",
	bigbuf);

    my_decode_bitfield_value(bigbuf, compat, 0x40, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Pass-on not possible - %s",
	bigbuf,
	(compat & 0x40) ? "Send notification" : "Do not send notification");

    switch ((compat & 0x30) >> 4)
    {
    case 0x00:
	str = "Pass on message or parameter (Release connection)";
	break;

    case 0x01:
	if (message)
	{
	    str = "Discard parameter (Discard message)";
	}
	else
	{
	    str = "Discard parameter";
	}
	break;

    case 0x02:
	str = "Discard message";
	break;

    case 0x03:
	str = "Release connection";
	break;
    }

    my_decode_bitfield_value(bigbuf, compat, 0x30, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Pass-on not possible, instruction - %s",
	bigbuf,
	str);

    my_decode_bitfield_value(bigbuf, compat, 0x08, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Reserved",
	bigbuf);

    my_decode_bitfield_value(bigbuf, compat, 0x04, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  General action - %s",
	bigbuf,
	(compat & 0x04) ? "Send notification" : "Do not send notification");

    switch (compat & 0x03)
    {
    case 0x00:
	str = "Pass on message or parameter";
	break;

    case 0x01:
	if (message)
	{
	    str = "Discard parameter (Discard message)";
	}
	else
	{
	    str = "Discard parameter";
	}
	break;

    case 0x02:
	str = "Discard message";
	break;

    case 0x03:
	str = "Release connection";
	break;
    }

    my_decode_bitfield_value(bigbuf, compat, 0x03, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  General action, instruction - %s",
	bigbuf,
	str);

    *offset += 1;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.2
 */
static void
dis_field_signalling_assoc_id(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset, gboolean destination)
{
    guint32	curr_offset;
    guint32	value;

    curr_offset = *offset;

#define	FIELD_SIGNALLING_ASSOC_ID_LEN	4

    SHORT_DATA_CHECK(*len, FIELD_SIGNALLING_ASSOC_ID_LEN);

    value = tvb_get_ntohl(tvb, curr_offset);

    if (destination)
    {
	proto_tree_add_uint_format(tree, hf_alcap_dsaid, tvb,
	    curr_offset, FIELD_SIGNALLING_ASSOC_ID_LEN, value,
	    "Destination signalling association identifier: %d%s",
	    value,
	    value ? "" : " (unknown)");
    }
    else
    {
	proto_tree_add_uint(tree, hf_alcap_osaid, tvb,
	    curr_offset, FIELD_SIGNALLING_ASSOC_ID_LEN, value);
    }

    curr_offset += FIELD_SIGNALLING_ASSOC_ID_LEN;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.3
 */
static void
dis_field_aal2_path_id(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset)
{
    guint32	curr_offset;
    guint32	value;

    curr_offset = *offset;

#define	FIELD_AAL2_PATH_ID_LEN	4

    SHORT_DATA_CHECK(*len, FIELD_AAL2_PATH_ID_LEN);

    value = tvb_get_ntohl(tvb, curr_offset);

    proto_tree_add_uint_format(tree, hf_alcap_aal2_path_id, tvb,
	curr_offset, FIELD_AAL2_PATH_ID_LEN, value,
	"AAL2 path identifier: %d%s",
	value,
	value ? "" : " (Null)");

    curr_offset += FIELD_AAL2_PATH_ID_LEN;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.4
 */
static void
dis_field_channel_id(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset)
{
    guint32	curr_offset;
    guint8	oct;

    curr_offset = *offset;

    SHORT_DATA_CHECK(*len, 1);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_uint_format(tree, hf_alcap_channel_id, tvb,
	curr_offset, 1, oct,
	"Channel identifier (CID): %d%s",
	oct,
	oct ? "" : " (Null)");

    curr_offset++;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.5
 */
static void
dis_field_organizational_unique_id(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset)
{
    guint32	curr_offset;
    guint32	octs;

    curr_offset = *offset;

#define	FIELD_ORGANIZATIONAL_UNIQUE_ID_LEN	3

    SHORT_DATA_CHECK(*len, FIELD_ORGANIZATIONAL_UNIQUE_ID_LEN);

    octs = tvb_get_ntoh24(tvb, curr_offset);

    proto_tree_add_uint(tree, hf_alcap_organizational_unique_id, tvb,
	curr_offset, FIELD_ORGANIZATIONAL_UNIQUE_ID_LEN, octs);

    curr_offset += FIELD_ORGANIZATIONAL_UNIQUE_ID_LEN;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.6
 */
static void
dis_field_audio_service(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset)
{
    guint32	curr_offset;
    guint32	value;
    guint8	oct;
    proto_item	*item;
    proto_tree	*subtree;
    gchar	*str = NULL;

    curr_offset = *offset;

#define	FIELD_AUDIO_SERVICE_LEN	5

    SHORT_DATA_CHECK(*len, FIELD_AUDIO_SERVICE_LEN);

    item =
	proto_tree_add_none_format(tree, hf_alcap_none, tvb,
	    curr_offset, FIELD_AUDIO_SERVICE_LEN, field_strings[FIELD_AUDIO_SERVICE]);

    subtree = proto_item_add_subtree(item, ett_fields[FIELD_AUDIO_SERVICE]);

    oct = tvb_get_guint8(tvb, curr_offset);

    switch ((oct & 0xc0) >> 6)
    {
    case 0x00: str = "Designates a profile specified by ITU-T Rec. I.366.2; ignore organizational unique identifier"; break;
    case 0x01: str = "Designates a profile specified by organizational unique identifier"; break;
    case 0x02: str = "Designates a custom profile; ignore organizational unique identifier"; break;
    case 0x03: str = "Reserved"; break;
    }

    my_decode_bitfield_value(bigbuf, oct, 0xc0, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Profile type, %s",
	bigbuf, str);

    my_decode_bitfield_value(bigbuf, oct, 0x3f, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Reserved",
	bigbuf);

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"Profile identifier (%d)",
	oct);

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    my_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  FRM, transport of frame mode data %s",
	bigbuf,
	(oct & 0x80) ? "enabled" : "disabled");

    my_decode_bitfield_value(bigbuf, oct, 0x40, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  CMD, transport of circuit mode data (64 kbit/s) %s",
	bigbuf,
	(oct & 0x40) ? "enabled" : "disabled");

    my_decode_bitfield_value(bigbuf, oct, 0x20, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  MF-R2, transport of multi-frequency R2 dialled digits %s",
	bigbuf,
	(oct & 0x20) ? "enabled" : "disabled");

    my_decode_bitfield_value(bigbuf, oct, 0x10, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  MF-R1, transport of multi-frequency R1 dialled digits %s",
	bigbuf,
	(oct & 0x10) ? "enabled" : "disabled");

    my_decode_bitfield_value(bigbuf, oct, 0x08, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  DTMF, transport of dual tone multi-frequency dialled digits %s",
	bigbuf,
	(oct & 0x08) ? "enabled" : "disabled");

    my_decode_bitfield_value(bigbuf, oct, 0x04, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  CAS, transport of channel associated signalling %s",
	bigbuf,
	(oct & 0x04) ? "enabled" : "disabled");

    my_decode_bitfield_value(bigbuf, oct, 0x02, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  FAX, transport of demodulated facsimile data %s",
	bigbuf,
	(oct & 0x02) ? "enabled" : "disabled");

    my_decode_bitfield_value(bigbuf, oct, 0x01, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  A/mu-law, interpretation of generic PCM coding: %s-law",
	bigbuf,
	(oct & 0x01) ? "mu" : "A");

    curr_offset++;

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 2,
	"Maximum length of frame mode data (%d)",
	value);

    curr_offset += 2;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.7
 */
static void
dis_field_multirate_service(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset)
{
    guint32	curr_offset;
    guint32	value;
    guint8	oct;
    proto_item	*item;
    proto_tree	*subtree;

    curr_offset = *offset;

#define	FIELD_MULTIRATE_SERVICE_LEN	3

    SHORT_DATA_CHECK(*len, FIELD_MULTIRATE_SERVICE_LEN);

    item =
	proto_tree_add_none_format(tree, hf_alcap_none, tvb,
	    curr_offset, FIELD_MULTIRATE_SERVICE_LEN, field_strings[FIELD_MULTIRATE_SERVICE]);

    subtree = proto_item_add_subtree(item, ett_fields[FIELD_MULTIRATE_SERVICE]);

    oct = tvb_get_guint8(tvb, curr_offset);

    my_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  FRM, transport of frame mode data %s",
	bigbuf,
	(oct & 0x80) ? "enabled" : "disabled");

    my_decode_bitfield_value(bigbuf, oct, 0x60, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Reserved",
	bigbuf);

    my_decode_bitfield_value(bigbuf, oct, 0x1f, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Multiplier (%d) for n x 64 kbit/s",
	bigbuf,
	oct & 0x1f);

    curr_offset++;

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 2,
	"Maximum length of frame mode data (%d)",
	value);

    curr_offset += 2;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.8
 */
static void
dis_field_seg_reassembly_ass(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset)
{
    guint32	curr_offset;
    guint32	value;
    proto_item	*item;
    proto_tree	*subtree;

    curr_offset = *offset;

#define	FIELD_SEG_REASSEMBLY_ASS_LEN	14

    SHORT_DATA_CHECK(*len, FIELD_SEG_REASSEMBLY_ASS_LEN);

    item =
	proto_tree_add_none_format(tree, hf_alcap_none, tvb,
	    curr_offset, FIELD_SEG_REASSEMBLY_ASS_LEN, field_strings[FIELD_SEG_REASSEMBLY_ASS]);

    subtree = proto_item_add_subtree(item, ett_fields[FIELD_SEG_REASSEMBLY_ASS]);

    value = tvb_get_ntoh24(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 3,
	"Maximum length of SSSAR-SDU in the forward direction (%d)",
	value);

    curr_offset += 3;

    value = tvb_get_ntoh24(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 3,
	"Maximum length of SSSAR-SDU in the backward direction (%d)",
	value);

    curr_offset += 3;

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 2,
	"Maximum length of SSCOP-SDU in the forward direction (%d)",
	value);

    curr_offset += 2;

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 2,
	"Maximum length of SSCOP-SDU in the backward direction (%d)",
	value);

    curr_offset += 2;

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 2,
	"Maximum length of SSCOP-UU in the forward direction (%d)",
	value);

    curr_offset += 2;

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 2,
	"Maximum length of SSCOP-UU in the backward direction (%d)",
	value);

    curr_offset += 2;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.9
 */
static void
dis_field_seg_reassembly_unass(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset)
{
    guint32	curr_offset;
    guint32	value;
    guint8	oct;
    proto_item	*item;
    proto_tree	*subtree;

    curr_offset = *offset;

#define	FIELD_SEG_REASSEMBLY_UNASS_LEN	7

    SHORT_DATA_CHECK(*len, FIELD_SEG_REASSEMBLY_UNASS_LEN);

    item =
	proto_tree_add_none_format(tree, hf_alcap_none, tvb,
	    curr_offset, FIELD_SEG_REASSEMBLY_UNASS_LEN, field_strings[FIELD_SEG_REASSEMBLY_UNASS]);

    subtree = proto_item_add_subtree(item, ett_fields[FIELD_SEG_REASSEMBLY_UNASS]);

    value = tvb_get_ntoh24(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 3,
	"Maximum length of SSSAR-SDU in the forward direction (%d)",
	value);

    curr_offset += 3;

    value = tvb_get_ntoh24(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 3,
	"Maximum length of SSSAR-SDU in the backward direction (%d)",
	value);

    curr_offset += 3;

    oct = tvb_get_guint8(tvb, curr_offset);

    my_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  TED, transmission error detection %s",
	bigbuf,
	oct & 0x80 ? "enabled" : "disabled");

    my_decode_bitfield_value(bigbuf, oct, 0x7f, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Reserved",
	bigbuf);

    curr_offset++;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.10
 */
static void
dis_field_served_user_gen_ref(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset)
{
    guint32	curr_offset;
    guint32	value;

    curr_offset = *offset;

#define	FIELD_SERVED_USER_GEN_REF_LEN	4

    SHORT_DATA_CHECK(*len, FIELD_SERVED_USER_GEN_REF_LEN);

    value = tvb_get_ntohl(tvb, curr_offset);

    proto_tree_add_uint(tree, hf_alcap_served_user_gen_ref, tvb,
	curr_offset, FIELD_SERVED_USER_GEN_REF_LEN, value);

    curr_offset += FIELD_SERVED_USER_GEN_REF_LEN;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.11
 */
static void
dis_field_cps_sdu_bit_rate(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset, gboolean maximum)
{
    guint32	curr_offset;
    guint32	value;
    proto_item	*item;
    proto_tree	*subtree;

    curr_offset = *offset;

#define	FIELD_CPS_SDU_BIT_RATE_LEN	4

    SHORT_DATA_CHECK(*len, FIELD_CPS_SDU_BIT_RATE_LEN);

    item =
	proto_tree_add_none_format(tree, hf_alcap_none, tvb,
	    curr_offset, FIELD_CPS_SDU_BIT_RATE_LEN, field_strings[FIELD_MAX_CPS_SDU_BIT_RATE + (maximum ? 0 : 1)]);

    subtree = proto_item_add_subtree(item, ett_fields[FIELD_MAX_CPS_SDU_BIT_RATE + (maximum ? 0 : 1)]);

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 2,
	"CPS-SDU bit rate in the forward direction (%d)",
	value);

    curr_offset += 2;

    value = tvb_get_ntohs(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 2,
	"CPS-SDU bit rate in the backward direction (%d)",
	value);

    curr_offset += 2;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.12
 */
static void
dis_field_cps_sdu_size(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset, gboolean maximum)
{
    guint32	curr_offset;
    guint8	oct;
    proto_item	*item;
    proto_tree	*subtree;

    curr_offset = *offset;

#define	FIELD_CPS_SDU_SIZE_LEN	2

    SHORT_DATA_CHECK(*len, FIELD_CPS_SDU_SIZE_LEN);

    item =
	proto_tree_add_none_format(tree, hf_alcap_none, tvb,
	    curr_offset, FIELD_CPS_SDU_SIZE_LEN, field_strings[FIELD_MAX_CPS_SDU_SIZE + (maximum ? 0 : 1)]);

    subtree = proto_item_add_subtree(item, ett_fields[FIELD_MAX_CPS_SDU_SIZE + (maximum ? 0 : 1)]);

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 1,
	"CPS-SDU size in the forward direction (%d)",
	oct);

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	curr_offset, 1,
	"CPS-SDU size in the backward direction (%d)",
	oct);

    curr_offset++;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.13
 */
static void
dis_field_nature_of_address(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset)
{
    guint32	curr_offset;
    guint32	value;
    guint8	oct;
    proto_item	*item;
    proto_tree	*subtree;
    gchar	*str = NULL;

    curr_offset = *offset;

#define	FIELD_NATURE_OF_ADDRESS_LEN	1

    SHORT_DATA_CHECK(*len, FIELD_NATURE_OF_ADDRESS_LEN);

    item =
	proto_tree_add_none_format(tree, hf_alcap_none, tvb,
	    curr_offset, FIELD_NATURE_OF_ADDRESS_LEN, field_strings[FIELD_NATURE_OF_ADDRESS]);

    subtree = proto_item_add_subtree(item, ett_fields[FIELD_NATURE_OF_ADDRESS]);

    oct = tvb_get_guint8(tvb, curr_offset);

    my_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Reserved",
	bigbuf);

    value = oct & 0x7f;

    switch (value)
    {
    case 0x00: str = "spare"; break;
    case 0x01: str = "subscriber number (national use)"; break;
    case 0x02: str = "unknown (national use)"; break;
    case 0x03: str = "national (significant) number"; break;
    case 0x04: str = "international number"; break;
    case 0x05: str = "network-specific number (national use)"; break;
    default:
	if ((value >= 0x06) && (value <= 0x6f)) { str = "spare"; break; }
	else if ((value >= 0x70) && (value <= 0xfe)) { str = "reserved for national use"; break; }
	else { str = "not given in spec. ???"; break; }
    }

    my_decode_bitfield_value(bigbuf, oct, 0x7f, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Nature of address code, %s (%d)",
	bigbuf,
	str,
	value);

    curr_offset++;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.14
 */
static void
dis_field_e164_address(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset)
{
    guint32	curr_offset;
    proto_item	*item;
    proto_tree	*subtree;
    guint8	parm_len;
    guint8	oct;
    guint8	i;

    curr_offset = *offset;

    SHORT_DATA_CHECK(*len, 1);

    item =
	proto_tree_add_none_format(tree, hf_alcap_none, tvb,
	    curr_offset, -1, field_strings[FIELD_E164_ADDRESS]);

    subtree = proto_item_add_subtree(item, ett_fields[FIELD_E164_ADDRESS]);

    parm_len = tvb_get_guint8(tvb, curr_offset);

    proto_item_set_len(item, parm_len + 1);

    proto_tree_add_uint(subtree, hf_alcap_length, tvb, curr_offset, 1, parm_len);

    curr_offset++;

    if (parm_len > 0)
    {
	i=0;
	while (i < parm_len)
	{
	    oct = tvb_get_guint8(tvb, curr_offset);

	    my_decode_bitfield_value(bigbuf, oct, 0xf0, 8);
	    proto_tree_add_text(subtree, tvb,
		curr_offset, 1,
		"%s :  Reserved",
		bigbuf);

	    bigbuf2[i] = (oct & 0x0f) + 0x30;

	    my_decode_bitfield_value(bigbuf, oct, 0x0f, 8);
	    proto_tree_add_text(subtree, tvb,
		curr_offset, 1,
		"%s :  Digit %d of address (%d)",
		bigbuf,
		i+1,
		oct & 0x0f);

	    curr_offset++;
	    i++;
	}

	bigbuf2[i] = '\0';

	proto_item_append_text(item, " (%s)", bigbuf2);
    }

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.15
 */
static void
dis_field_nsap_address(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset)
{
    guint32	curr_offset;

    curr_offset = *offset;

#define	FIELD_NSAP_ADDRESS_LEN	20

    SHORT_DATA_CHECK(*len, FIELD_NSAP_ADDRESS_LEN);

    proto_tree_add_item(tree, hf_alcap_nsap_address, tvb,
	curr_offset, FIELD_NSAP_ADDRESS_LEN, FALSE);

    curr_offset += FIELD_NSAP_ADDRESS_LEN;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.16
 */
static void
dis_field_cause_value(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset, gboolean *compat)
{
    guint32	curr_offset;
    guint8	oct;
    proto_item	*item;
    proto_tree	*subtree;
    gchar	*str = NULL;

    *compat = FALSE;
    curr_offset = *offset;

#define	FIELD_CAUSE_VALUE_LEN	2

    SHORT_DATA_CHECK(*len, FIELD_CAUSE_VALUE_LEN);

    item =
	proto_tree_add_none_format(tree, hf_alcap_none, tvb,
	    curr_offset, FIELD_CAUSE_VALUE_LEN, field_strings[FIELD_CAUSE_VALUE]);

    subtree = proto_item_add_subtree(item, ett_fields[FIELD_CAUSE_VALUE]);

    oct = tvb_get_guint8(tvb, curr_offset);

    my_decode_bitfield_value(bigbuf, oct, 0xfc, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Reserved",
	bigbuf);

    switch (oct & 0x3)
    {
    case 0x00: str = "ITU-T standardized coding as described in ITU-T Rec. Q.850 and Q.2610"; break;
    case 0x01: str = "ISO/IEC standard"; break;
    case 0x02: str = "national standard"; break;
    case 0x03: str = "standard defined for the network (either public or private) present on the network side of the interface"; break;
    }

    my_decode_bitfield_value(bigbuf, oct, 0x03, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Coding standard, %s",
	bigbuf,
	str);

    curr_offset++;

    oct = tvb_get_guint8(tvb, curr_offset);

    my_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Reserved",
	bigbuf);

    switch (oct & 0x7f)
    {
    case 1: str = "Unallocated (unassigned) number"; break;
    case 3: str = "No route to destination"; break;
    case 31: str = "Normal, unspecified"; break;
    case 34: str = "No circuit/channel available"; break;
    case 38: str = "Network out of order"; break;
    case 41: str = "Temporary failure"; break;
    case 42: str = "Switching equipment congestion"; break;
    case 44: str = "Requested circuit/channel not available"; break;
    case 47: str = "Resource unavailable, unspecified"; break;
    case 93: str = "AAL parameters cannot be supported"; break;
    case 95: str = "Invalid message, unspecified"; break;
    case 96: str = "Mandatory information element is missing"; break;
    case 97: str = "Message type non-existent or not implemented"; *compat = TRUE; break;
    case 99: str = "Information element/parameter non-existent or not implemented"; *compat = TRUE; break;
    case 100: str = "Invalid information element contents"; break;
    case 102: str = "Recovery on timer expiry"; break;
    case 110: str = "Message with unrecognized parameter, discarded"; *compat = TRUE; break;
    default: str = "Unknown"; break;
    }

    my_decode_bitfield_value(bigbuf, oct, 0x7f, 8);
    proto_tree_add_text(subtree, tvb,
	curr_offset, 1,
	"%s :  Cause (%d), %s",
	bigbuf,
	oct & 0x7f,
	str);

    curr_offset++;

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.17
 */
static void
dis_field_diagnostics(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset, gboolean compat)
{
    guint32	curr_offset;
    guint8	oct;
    proto_item	*item;
    proto_tree	*subtree;
    guint8	parm_len;
    gchar	*str = NULL;
    gint	idx;
    guint8	i;

    curr_offset = *offset;

    SHORT_DATA_CHECK(*len, 1);

    item =
	proto_tree_add_none_format(tree, hf_alcap_none, tvb,
	    curr_offset, -1, field_strings[FIELD_DIAGNOSTICS]);

    subtree = proto_item_add_subtree(item, ett_fields[FIELD_DIAGNOSTICS]);

    parm_len = tvb_get_guint8(tvb, curr_offset);

    proto_item_set_len(item, parm_len + 1);

    proto_tree_add_uint(subtree, hf_alcap_length, tvb, curr_offset, 1, parm_len);

    curr_offset++;

    if (parm_len > 0)
    {
	if (compat)
	{
	    /*
	     * compatibility diagnostics
	     */
	    oct = tvb_get_guint8(tvb, curr_offset);

	    str = my_match_strval(oct, msg_type_strings, &idx);

	    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
		curr_offset, 1, (str == NULL) ? "Unknown message identifier" : str);

	    curr_offset++;

	    i=1;
	    while ((i+2) <= parm_len)
	    {
		oct = tvb_get_guint8(tvb, curr_offset);

		str = my_match_strval(oct, msg_parm_strings, &idx);

		proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
		    curr_offset, 1, (str == NULL) ? "Unknown parameter" : str);

		curr_offset++;

		oct = tvb_get_guint8(tvb, curr_offset);

		if (oct == 0)
		{
		    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
			curr_offset, 1, "Whole parameter");
		}
		else
		{
		    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
			curr_offset, 1, "Field number %d", oct);
		}

		curr_offset++;
		i += 2;
	    }

	    if (i != parm_len)
	    {
		proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
		    curr_offset, parm_len - i, "Extraneous Data ???");

		curr_offset += (parm_len - i);
	    }
	}
	else
	{
	    proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
		curr_offset, parm_len, "Coded as per ITU-T Rec. Q.2610");

	    curr_offset += parm_len;
	}
    }

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.4.18
 */
static void
dis_field_served_user_transport(tvbuff_t *tvb, proto_tree *tree, guint *len, guint32 *offset)
{
    guint32	curr_offset;
    proto_item	*item;
    proto_tree	*subtree;
    guint8	parm_len;

    curr_offset = *offset;

    SHORT_DATA_CHECK(*len, 1);

    item =
	proto_tree_add_none_format(tree, hf_alcap_none, tvb,
	    curr_offset, -1, field_strings[FIELD_SERVED_USER_TRANSPORT]);

    subtree = proto_item_add_subtree(item, ett_fields[FIELD_SERVED_USER_TRANSPORT]);

    parm_len = tvb_get_guint8(tvb, curr_offset);

    proto_item_set_len(item, parm_len + 1);

    proto_tree_add_uint(subtree, hf_alcap_length, tvb, curr_offset, 1, parm_len);

    curr_offset++;

    if (parm_len > 0)
    {
	proto_tree_add_none_format(subtree, hf_alcap_none, tvb,
	    curr_offset, parm_len, "Value");

	curr_offset += parm_len;
    }

    *len -= (curr_offset - *offset);
    *offset = curr_offset;
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.3.1
 */
static void
dis_parm_cause(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 curr_offset)
{
    gboolean	compat;

    dis_field_cause_value(tvb, tree, &len, &curr_offset, &compat);

    dis_field_diagnostics(tvb, tree, &len, &curr_offset, compat);

    EXTRANEOUS_DATA_CHECK(len, 0);
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.3.2
 */
static void
dis_parm_conn_element_id(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 curr_offset)
{

    dis_field_aal2_path_id(tvb, tree, &len, &curr_offset);

    dis_field_channel_id(tvb, tree, &len, &curr_offset);

    EXTRANEOUS_DATA_CHECK(len, 0);
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.3.3
 */
static void
dis_parm_dest_e164_sea(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 curr_offset)
{

    dis_field_nature_of_address(tvb, tree, &len, &curr_offset);

    dis_field_e164_address(tvb, tree, &len, &curr_offset);

    EXTRANEOUS_DATA_CHECK(len, 0);
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.3.4
 */
static void
dis_parm_dest_nsap_sea(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 curr_offset)
{

    dis_field_nsap_address(tvb, tree, &len, &curr_offset);

    EXTRANEOUS_DATA_CHECK(len, 0);
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.3.5
 */
static void
dis_parm_link_characteristics(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 curr_offset)
{

    dis_field_cps_sdu_bit_rate(tvb, tree, &len, &curr_offset, TRUE);

    dis_field_cps_sdu_bit_rate(tvb, tree, &len, &curr_offset, FALSE);

    dis_field_cps_sdu_size(tvb, tree, &len, &curr_offset, TRUE);

    dis_field_cps_sdu_size(tvb, tree, &len, &curr_offset, FALSE);

    EXTRANEOUS_DATA_CHECK(len, 0);
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.3.6
 */
static void
dis_parm_osai(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 curr_offset)
{

    dis_field_signalling_assoc_id(tvb, tree, &len, &curr_offset, FALSE);

    EXTRANEOUS_DATA_CHECK(len, 0);
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.3.7
 */
static void
dis_parm_served_user_gen_ref(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 curr_offset)
{

    dis_field_served_user_gen_ref(tvb, tree, &len, &curr_offset);

    EXTRANEOUS_DATA_CHECK(len, 0);
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.3.8
 */
static void
dis_parm_served_user_transport(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 curr_offset)
{

    dis_field_served_user_transport(tvb, tree, &len, &curr_offset);

    EXTRANEOUS_DATA_CHECK(len, 0);
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.3.9
 */
static void
dis_parm_service_specific_info_audio(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 curr_offset)
{

    dis_field_audio_service(tvb, tree, &len, &curr_offset);

    dis_field_organizational_unique_id(tvb, tree, &len, &curr_offset);

    EXTRANEOUS_DATA_CHECK(len, 0);
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.3.10
 */
static void
dis_parm_service_specific_info_multirate(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 curr_offset)
{

    dis_field_multirate_service(tvb, tree, &len, &curr_offset);

    EXTRANEOUS_DATA_CHECK(len, 0);
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.3.11
 */
static void
dis_parm_service_specific_info_ass(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 curr_offset)
{

    dis_field_seg_reassembly_ass(tvb, tree, &len, &curr_offset);

    EXTRANEOUS_DATA_CHECK(len, 0);
}

/*
 * Ref. ITU-T Q.2630.1 (12/1999)
 * Section 7.3.12
 */
static void
dis_parm_service_specific_info_unass(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 curr_offset)
{

    dis_field_seg_reassembly_unass(tvb, tree, &len, &curr_offset);

    EXTRANEOUS_DATA_CHECK(len, 0);
}

static gint ett_parms[NUM_PARMS];
static void (*alcap_parm_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    dis_parm_cause,				/* Cause */
    dis_parm_conn_element_id,				/* Connection element identifier */
    dis_parm_dest_e164_sea,			/* Destination E.164 service endpoint address */
    dis_parm_dest_nsap_sea,			/* Destination NSAP service endpoint address */
    dis_parm_link_characteristics,		/* Link characteristics */
    dis_parm_osai,				/* Originating signalling association identifier */
    dis_parm_served_user_gen_ref,		/* Served user generated reference */
    dis_parm_served_user_transport,		/* Served user transport */
    dis_parm_service_specific_info_audio,	/* Service specific information (audio) */
    dis_parm_service_specific_info_multirate,	/* Service specific information (multirate) */
    dis_parm_service_specific_info_ass,		/* Service specific information (SAR-assured) */
    dis_parm_service_specific_info_unass,	/* Service specific information (SAR-unassured) */
    NULL /* no parms */,			/* Test connection identifier */
    NULL,	/* NONE */
};

/* GENERIC ALCAP DISSECTOR FUNCTIONS */

static void
dissect_alcap_parms(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint32 len)
{
    void (*parm_fcn)(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = NULL;
    guint8	parm;
    guint8	parm_len;
    guint32	curr_offset, saved_offset;
    gint	idx;
    gchar	*str = NULL;
    proto_item	*item;
    proto_tree	*subtree;
    gint	ett_parm_idx;


    curr_offset = offset;

    while (len >= ALCAP_PARM_HEADER_LEN)
    {
	saved_offset = curr_offset;

	parm = tvb_get_guint8(tvb, curr_offset);

	str = my_match_strval(parm, msg_parm_strings, &idx);

	if (str == NULL)
	{
	    ett_parm_idx = ett_parm;
	    parm_fcn = NULL;
	}
	else
	{
	    ett_parm_idx = ett_parms[idx];
	    parm_fcn = alcap_parm_fcn[idx];
	}

	item =
	    proto_tree_add_none_format(tree, hf_alcap_none, tvb,
		curr_offset, -1, (str == NULL) ? "Unknown parameter" : str);

	subtree = proto_item_add_subtree(item, ett_parm_idx);

	proto_tree_add_uint(subtree, hf_alcap_parm_id, tvb,
	    curr_offset, 1, parm);

	curr_offset++;

	dis_field_compatibility(tvb, subtree, &curr_offset, FALSE);

	parm_len = tvb_get_guint8(tvb, curr_offset);

	proto_tree_add_uint(subtree, hf_alcap_length, tvb, curr_offset, 1, parm_len);

	curr_offset++;

	proto_item_set_len(item, (curr_offset - saved_offset) + parm_len);

	if (parm_len > 0)
	{
	    if (parm_fcn == NULL)
	    {
		proto_tree_add_none_format(subtree, hf_alcap_none,
		    tvb, curr_offset, parm_len, "Parameter data");
	    }
	    else
	    {
		(*parm_fcn)(tvb, subtree, parm_len, curr_offset);
	    }
	}

	len -= (ALCAP_PARM_HEADER_LEN + parm_len);
	curr_offset += parm_len;
    }

    EXTRANEOUS_DATA_CHECK(len, 0);
}

static void
dissect_alcap_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *alcap_tree)
{
    guint32	temp_len;
    guint32	len;
    guint32	offset;
    guint8	msg_type;
    gint	idx;
    gchar	*str = NULL;

    offset = 0;

    len = tvb_length(tvb);
    temp_len = len;

    if (len < ALCAP_MSG_HEADER_LEN)
    {
	proto_tree_add_none_format(alcap_tree, hf_alcap_none, tvb,
	    offset, len, "Message header too short");

	return;
    }

    dis_field_signalling_assoc_id(tvb, alcap_tree, &temp_len, &offset, TRUE);

    msg_type = tvb_get_guint8(tvb, offset);

    str = my_match_strval(msg_type, msg_type_strings, &idx);

    if (str == NULL)
    {
	proto_tree_add_none_format(alcap_tree, hf_alcap_none, tvb,
	    offset, 1, "Unknown message identifier");

	return;
    }

    if (check_col(pinfo->cinfo, COL_INFO))
    {
	col_set_str(pinfo->cinfo, COL_INFO, str);
    }

    proto_tree_add_uint(alcap_tree, hf_alcap_msg_type, tvb,
	offset, 1, msg_type);

    offset++;

    dis_field_compatibility(tvb, alcap_tree, &offset, TRUE);

    if (len > ALCAP_MSG_HEADER_LEN)
    {
	dissect_alcap_parms(tvb, alcap_tree, offset, len - ALCAP_MSG_HEADER_LEN);
    }
}

static void
dissect_alcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item	*alcap_item;
    proto_tree	*alcap_tree = NULL;

    if (!proto_is_protocol_enabled(proto_alcap))
    {
	call_dissector(data_handle,tvb, pinfo, tree);
	return;
    }

    g_pinfo = pinfo;

    /*
     * Don't change the Protocol column on summary display
     */
    if (check_col(pinfo->cinfo, COL_PROTOCOL))
    {
	col_set_str(pinfo->cinfo, COL_PROTOCOL, alcap_proto_name_short);
    }

    /* In the interest of speed, if "tree" is NULL, don't do any work not
     * necessary to generate protocol tree items.
     */
    if (tree)
    {
	g_tree = tree;

	/*
	 * create the ALCAP protocol tree
	 */
	alcap_item =
	    proto_tree_add_protocol_format(tree, proto_alcap, tvb, 0, -1,
		alcap_proto_name);

	alcap_tree =
	    proto_item_add_subtree(alcap_item, ett_alcap);

	dissect_alcap_message(tvb, pinfo, alcap_tree);
    }
}


/* Register the protocol with Ethereal */
void
proto_register_alcap(void)
{
    guint		i;

    /* Setup list of header fields */
    static hf_register_info hf[] =
    {
	{ &hf_alcap_msg_type,
	  { "Message Type",
	    "alcap.msg_type",
	    FT_UINT8, BASE_DEC, VALS(msg_type_strings), 0,
	    "", HFILL }},
	{ &hf_alcap_dsaid,
	  { "Destination signalling association identifier",
	    "alcap.dsai",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_alcap_osaid,
	  { "Originating signalling association identifier",
	    "alcap.osai",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_alcap_aal2_path_id,
	  { "AAL2 path identifier",
	    "alcap.aal2_path_id",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_alcap_channel_id,
	  { "Channel identifier (CID)",
	    "alcap.channel_id",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_alcap_organizational_unique_id,
	  { "Organizational unique identifier (OUI)",
	    "alcap.organizational_unique_id",
	    FT_UINT24, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_alcap_served_user_gen_ref,
	  { "Served user generated reference",
	    "alcap.served_user_gen_ref",
	    FT_UINT32, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_alcap_nsap_address,
	  { "NSAP address",
	    "alcap.nsap_address",
	    FT_BYTES, BASE_NONE, NULL, 0,
	    "", HFILL }
	},
	{ &hf_alcap_parm_id,
	  { "Parameter identifier",
	    "alcap.param_id",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }},
	{ &hf_alcap_length,
	    { "Length",		"alcap.len",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_alcap_none,
	    { "Subtree",	"alcap.none",
	    FT_NONE, 0, 0, 0,
	    "", HFILL }
	},
    };

    /* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_PARMS	2
    static gint *ett[NUM_INDIVIDUAL_PARMS+NUM_PARMS+NUM_FIELDS];

    memset((void *) ett, 0, sizeof(ett));

    ett[0] = &ett_alcap;
    ett[1] = &ett_parm;

    for (i=0; i < NUM_PARMS; i++)
    {
	ett_parms[i] = -1;
	ett[NUM_INDIVIDUAL_PARMS+i] = &ett_parms[i];
    }

    for (i=0; i < NUM_FIELDS; i++)
    {
	ett_fields[i] = -1;
	ett[NUM_INDIVIDUAL_PARMS+NUM_PARMS+i] = &ett_fields[i];
    }

    /* Register the protocol name and description */
    proto_alcap =
	proto_register_protocol(alcap_proto_name, alcap_proto_name_short, "alcap");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_alcap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_alcap(void)
{
    dissector_handle_t	alcap_handle;

    alcap_handle = create_dissector_handle(dissect_alcap, proto_alcap);

    dissector_add("mtp3.service_indicator", ALCAP_SI, alcap_handle);

    data_handle = find_dissector("data");
}
