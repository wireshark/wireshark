/* packet-ansi_683.c
 * Routines for ANSI IS-683-A (OTA (Mobile)) dissection
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
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


static const char *ansi_proto_name = "ANSI IS-683-A (OTA (Mobile))";
static const char *ansi_proto_name_short = "IS-683-A";

#define	ANSI_683_FORWARD	0
#define	ANSI_683_REVERSE	1


/* Initialize the subtree pointers */
static gint ett_ansi_683 = -1;
static gint ett_for_nam_block = -1;
static gint ett_for_sspr_block = -1;
static gint ett_rev_sspr_block = -1;
static gint ett_rev_nam_block = -1;
static gint ett_key_p = -1;
static gint ett_key_g = -1;
static gint ett_rev_feat = -1;
static gint ett_for_val_block = -1;
static gint ett_band_cap = -1;

/* Initialize the protocol and registered fields */
static int proto_ansi_683 = -1;
static int hf_ansi_683_none = -1;
static int hf_ansi_683_for_msg_type = -1;
static int hf_ansi_683_rev_msg_type = -1;
static int hf_ansi_683_length = -1;

static char bigbuf[1024];
static dissector_handle_t data_handle;
static packet_info *g_pinfo;
static proto_tree *g_tree;


/* FUNCTIONS */

/* PARAM FUNCTIONS */

#define	EXTRANEOUS_DATA_CHECK(edc_len, edc_max_len) \
    if ((edc_len) > (edc_max_len)) \
    { \
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb, \
	    offset, (edc_len) - (edc_max_len), "Extraneous Data"); \
    }

#define	SHORT_DATA_CHECK(sdc_len, sdc_min_len) \
    if ((sdc_len) < (sdc_min_len)) \
    { \
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb, \
	    offset, (sdc_len), "Short Data (?)"); \
	return; \
    }

#define	EXACT_DATA_CHECK(edc_len, edc_eq_len) \
    if ((edc_len) != (edc_eq_len)) \
    { \
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb, \
	    offset, (edc_len), "Unexpected Data Length"); \
	return; \
    }

static const gchar *
rev_feat_id_type(guint8 feat_id)
{
    const gchar	*str;

    switch (feat_id)
    {
    case 0: str = "NAM Download (DATA_P_REV)"; break;
    case 1: str = "Key Exchange (A_KEY_P_REV)"; break;
    case 2: str = "System Selection for Preferred Roaming (SSPR_P_REV)"; break;
    case 3: str = "Service Programming Lock (SPL_P_REV)"; break;
    case 4: str = "Over-The-Air Parameter Administration (OTAPA_P_REV)"; break;
    default:
	if ((feat_id >= 5) && (feat_id <= 191)) { str = "Reserved for future standardization"; break; }
	else if ((feat_id >= 192) && (feat_id <= 254)) { str = "Available for manufacturer-specific features"; break; }
	else { str = "Reserved"; break; }
    }

    return(str);
}

static const gchar *
rev_res_code_type(guint8 res_code)
{
    const gchar	*str;

    switch (res_code)
    {
    case 0: str = "Accepted - Operation successful"; break;
    case 1: str = "Rejected - Unknown reason"; break;
    case 2: str = "Rejected - Data size mismatch"; break;
    case 3: str = "Rejected - Protocol version mismatch"; break;
    case 4: str = "Rejected - Invalid parameter"; break;
    case 5: str = "Rejected - SID/NID length mismatch"; break;
    case 6: str = "Rejected - Message not expected in this mode"; break;
    case 7: str = "Rejected - BLOCK_ID value not supported"; break;
    case 8: str = "Rejected - Preferred roaming list length mismatch"; break;
    case 9: str = "Rejected - CRC error"; break;
    case 10: str = "Rejected - Mobile station locked"; break;
    case 11: str = "Rejected - Invalid SPC"; break;
    case 12: str = "Rejected - SPC change denied by the user"; break;
    case 13: str = "Rejected - Invalid SPASM"; break;
    case 14: str = "Rejected - BLOCK_ID not expected in this mode"; break;
    default:
	if ((res_code >= 15) && (res_code <= 127)) { str = "Reserved for future standardization"; break; }
	else if ((res_code >= 128) && (res_code <= 254)) { str = "Available for manufacturer-specific Result Code definitions"; break; }
	else { str = "Reserved"; break; }
    }

    return(str);
}

#define	VERIFY_SPC_VAL_BLOCK		0
#define	CHANGE_SPC_VAL_BLOCK		1
#define	VALDATE_SPASM_VAL_BLOCK		2

static const gchar *
for_val_param_block_type(guint8 block_type)
{
    const gchar	*str;

    switch (block_type)
    {
    case 0: str = "Verify SPC"; break;
    case 1: str = "Change SPC"; break;
    case 2: str = "Validate SPASM"; break;
    default:
	if ((block_type >= 3) && (block_type <= 127)) { str = "Reserved for future standardization"; break; }
	else if ((block_type >= 128) && (block_type <= 254)) { str = "Available for manufacturer-specific parameter block definitions"; break; }
	else { str = "Reserved"; break; }
    }

    return(str);
}

static const gchar *
rev_sspr_param_block_type(guint8 block_type)
{
    const gchar	*str;

    switch (block_type)
    {
    case 0: str = "Preferred Roaming List Dimensions"; break;
    case 1: str = "Preferred Roaming List"; break;
    default:
	if ((block_type >= 2) && (block_type <= 127)) { str = "Reserved for future standardization"; break; }
	else if ((block_type >= 128) && (block_type <= 254)) { str = "Available for manufacturer-specific parameter block definitions"; break; }
	else { str = "Reserved"; break; }
    }

    return(str);
}

static const gchar *
for_sspr_param_block_type(guint8 block_type)
{
    const gchar	*str;

    switch (block_type)
    {
    case 0: str = "Preferred Roaming List"; break;
    default:
	if ((block_type >= 1) && (block_type <= 127)) { str = "Reserved for future standardization"; break; }
	else if ((block_type >= 128) && (block_type <= 254)) { str = "Available for manufacturer-specific parameter block definitions"; break; }
	else { str = "Reserved"; break; }
    }

    return(str);
}

#define	CDMA_ANALOG_NAM_BLOCK	0
#define	MDN_NAM_BLOCK		1
#define	CDMA_NAM_BLOCK		2
#define	IMSI_T_NAM_BLOCK	3

static const gchar *
rev_nam_param_block_type(guint8 block_type)
{
    const gchar	*str;

    switch (block_type)
    {
    case 0: str = "CDMA/Analog NAM"; break;
    case 1: str = "Mobile Directory Number"; break;
    case 2: str = "CDMA NAM"; break;
    case 3: str = "IMSI_T"; break;
    default:
	if ((block_type >= 4) && (block_type <= 127)) { str = "Reserved for future standardization"; break; }
	else if ((block_type >= 128) && (block_type <= 254)) { str = "Available for manufacturer-specific parameter block definitions"; break; }
	else { str = "Reserved"; break; }
    }

    return(str);
}

static const gchar *
for_nam_param_block_type(guint8 block_type)
{
    const gchar	*str;

    switch (block_type)
    {
    case 0: str = "CDMA/Analog NAM Download"; break;
    case 1: str = "Mobile Directory Number"; break;
    case 2: str = "CDMA NAM Download"; break;
    case 3: str = "IMSI_T"; break;
    default:
	if ((block_type >= 4) && (block_type <= 127)) { str = "Reserved for future standardization"; break; }
	else if ((block_type >= 128) && (block_type <= 254)) { str = "Available for manufacturer-specific parameter block definitions"; break; }
	else { str = "Reserved"; break; }
    }

    return(str);
}

static void
param_verify_spc_val_block(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32	saved_offset;
    guint32	value;


    EXACT_DATA_CHECK(len, 3);

    saved_offset = offset;

    value = tvb_get_ntoh24(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, len,
	"Service programming code (%d)",
	value);
}

static void
param_cdma_analog_nam_block(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32	saved_offset;
    guint32	value;
    guint32	count;

    saved_offset = offset;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xffe0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  First paging channel (FIRSTCHP) used in the home system (%d)",
	bigbuf,
	(value & 0xffe0) >> 5);

    offset++;

    value = tvb_get_ntoh24(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x1fffc0, 24);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 3,
	"%s :  Home system identification (HOME_SID) (%d)",
	bigbuf,
	(value & 0x1fffc0) >> 6);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset + 2, 1,
	"%s :  Extended address indicator (EX)",
	bigbuf);

    offset += 2;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x1fe0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  Station class mark (SCM) (%d)",
	bigbuf,
	(value & 0x1fe0) >> 5);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x1fe0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  Mobile station protocol revision number (MOB_P_REV) (%d)",
	bigbuf,
	(value & 0x1fe0) >> 5);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset + 1, 1,
	"%s :  IMSI_M Class assignment of the mobile station (IMSI_M_CLASS), Class %d",
	bigbuf,
	(value & 0x10) >> 4);

    other_decode_bitfield_value(bigbuf, value, 0x0e, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset + 1, 1,
	"%s :  Number of IMSI_M address digits (IMSI_M_ADDR_NUM) (%d), %d digits in NMSI",
	bigbuf,
	(value & 0x0e) >> 1,
	(value & 0x10) ? ((value & 0x0e) >> 1) + 4 : 0);

    offset++;

    value = tvb_get_ntoh24(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x01ff80, 24);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 3,
	"%s :  Mobile country code (MCC_M)",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x7f, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset + 2, 1,
	"%s :  11th and 12th digits of the IMSI_M (IMSI__M_11_12)",
	bigbuf);

    offset += 3;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 5,
	"The least significant 10 digits of the IMSI_M (IMSI_M_S) (34 bits)");

    offset += 4;

    value = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x3c, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Access overload class (ACCOLC) (%d)",
	bigbuf,
	(value & 0x3c) >> 2);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Local control status (LOCAL_CONTROL)",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Termination indicator for the home system (MOB_TERM_HOME)",
	bigbuf);

    offset++;

    value = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Termination indicator for SID roaming (MOB_TERM_FOR_SID)",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x40, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Termination indicator for NID roaming (MOB_TERM_FOR_NID)",
	bigbuf);

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x3fc0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  Maximum stored SID/NID pairs (MAX_SID_NID) (%d)",
	bigbuf,
	(value & 0x3fc0) >> 6);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    count = (value & 0x3fc0) >> 6;

    other_decode_bitfield_value(bigbuf, value, 0x3fc0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  Number of stored SID/NID pairs (STORED_SID_NID) (%d)",
	bigbuf,
	count);

    other_decode_bitfield_value(bigbuf, value, 0x003f, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  SID/NID pairs (MSB)",
	bigbuf);

    offset += 2;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, len - (offset - saved_offset),
	"SID/NID pairs, Reserved");
}

static void
param_mdn_nam_block(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32	saved_offset;
    guint32	value, count, i;

    memset((void *) bigbuf, 0, sizeof(bigbuf));

    saved_offset = offset;

    value = tvb_get_guint8(tvb, offset);

    count = (value & 0xf0) >> 4;

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Number of digits (N_DIGITS) (%d)",
	bigbuf,
	count);

    for (i=0; i < count; i++)
    {
	bigbuf[i] = 0x30 + (value & 0x0f);

	if ((i + 1) < count)
	{
	    offset++;
	    value = tvb_get_guint8(tvb, offset);
	    bigbuf[i+1] = 0x30 + (value & 0xf0);
	    i++;
	}
    }

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, saved_offset, len,
	"Mobile directory number, %s",
	bigbuf);

    if (!(count & 0x01))
    {
	other_decode_bitfield_value(bigbuf, value, 0x0f, 8);
	proto_tree_add_none_format(tree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "%s :  Reserved",
	    bigbuf);
    }
}

static void
param_cdma_nam_block(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32	saved_offset;
    guint32	value;
    guint32	count;

    saved_offset = offset;

    value = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xc0, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x20, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Slotted Mode",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x1f, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Reserved",
	bigbuf);

    offset++;

    value = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xff, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Mobile station protocol revision number (MOB_P_REV) (%d)",
	bigbuf,
	value);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x8000, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  IMSI_M Class assignment of the mobile station (IMSI_M_CLASS), Class %d",
	bigbuf,
	(value & 0x8000) >> 15);

    other_decode_bitfield_value(bigbuf, value, 0x7000, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  Number of IMSI_M address digits (IMSI_M_ADDR_NUM) (%d), %d digits in NMSI",
	bigbuf,
	(value & 0x7000) >> 12,
	(value & 0x8000) ? ((value & 0x7000) >> 12) + 4 : 0);

    other_decode_bitfield_value(bigbuf, value, 0x0ffc, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  Mobile country code (MCC_M)",
	bigbuf);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x3f80, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  11th and 12th digits of the IMSI_M (IMSI__M_11_12)",
	bigbuf);

    offset++;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 5,
	"The least significant 10 digits of the IMSI_M (IMSI_M_S) (34 bits)");

    offset += 4;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x01e0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  Access overload class (ACCOLC) (%d)",
	bigbuf,
	(value & 0x01e0) >> 5);

    other_decode_bitfield_value(bigbuf, value, 0x10, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset+1, 1,
	"%s :  Local control status (LOCAL_CONTROL)",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset+1, 1,
	"%s :  Termination indicator for the home system (MOB_TERM_HOME)",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset+1, 1,
	"%s :  Termination indicator for SID roaming (MOB_TERM_FOR_SID)",
	bigbuf);

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset+1, 1,
	"%s :  Termination indicator for NID roaming (MOB_TERM_FOR_NID)",
	bigbuf);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x01fe, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  Maximum stored SID/NID pairs (MAX_SID_NID) (%d)",
	bigbuf,
	(value & 0x01fe) >> 1);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    count = (value & 0x01fe) >> 1;

    other_decode_bitfield_value(bigbuf, value, 0x01fe, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  Number of stored SID/NID pairs (STORED_SID_NID) (%d)",
	bigbuf,
	count);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset+1, 1,
	"%s :  SID/NID pairs (MSB)",
	bigbuf);

    offset += 2;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, len - (offset - saved_offset),
	"SID/NID pairs, Reserved");
}

static void
param_imsi_t_nam_block(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32	saved_offset;
    guint32	value;

    /*
     * XXX avoid warning for now, may use this variable
     * for validation later
     */
    len = len;

    saved_offset = offset;

    value = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x80, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  IMSI_T Class assignment of the mobile station (IMSI_T_CLASS), Class %d",
	bigbuf,
	(value & 0x80) >> 7);

    other_decode_bitfield_value(bigbuf, value, 0x70, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Number of IMSI_T address digits (IMSI_T_ADDR_NUM ) (%d), %d digits in NMSI",
	bigbuf,
	(value & 0x70) >> 4,
	(value & 0x80) ? ((value & 0x70) >> 4) + 4 : 0);

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x0ffc, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  Mobile country code (MCC_T)",
	bigbuf);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x03f8, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  11th and 12th digits of the IMSI_T (IMSI__T_11_12)",
	bigbuf);

    offset++;

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 5,
	"The least significant 10 digits of the IMSI_T (IMSI_T_S) (34 bits)");

    offset += 4;

    value = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Reserved",
	bigbuf);
}

static void
msg_config_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, num_blocks;
    const gchar	*str = NULL;
    guint32	i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"Number of parameter blocks (%d)",
	num_blocks);

    offset++;

    if (num_blocks > (len - (offset - saved_offset)))
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb,
	    offset, len - (offset - saved_offset), "Short Data (?)");
	return;
    }

    for (i=0; i < num_blocks; i++)
    {
	oct = tvb_get_guint8(tvb, offset);

	str = rev_nam_param_block_type(oct);

	proto_tree_add_none_format(tree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "%s (%d)",
	    str,
	    oct);

	offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
msg_download_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, block_id, block_len;
    const gchar	*str = NULL;
    proto_tree	*subtree;
    proto_item	*item;
    guint32	i, saved_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"Number of parameter blocks (%d)",
	oct);

    offset++;

    for (i=0; i < oct; i++)
    {
	block_id = tvb_get_guint8(tvb, offset);

	str = for_nam_param_block_type(block_id);

	item =
	    proto_tree_add_none_format(tree, hf_ansi_683_none,
		tvb, offset, 1,
		"%s (%d)",
		str,
		block_id);

	subtree = proto_item_add_subtree(item, ett_for_nam_block);
	offset++;

	block_len = tvb_get_guint8(tvb, offset);

	proto_tree_add_uint(subtree, hf_ansi_683_length,
	    tvb, offset, 1, block_len);
	offset++;

	if (block_len > (len - (offset - saved_offset)))
	{
	    proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
		offset, len - (offset - saved_offset), "Short Data (?)");
	    return;
	}

	if (block_len > 0)
	{
	    switch (block_id)
	    {
	    case CDMA_ANALOG_NAM_BLOCK:
		param_cdma_analog_nam_block(tvb, subtree, block_len, offset);
		break;

	    case MDN_NAM_BLOCK:
		param_mdn_nam_block(tvb, subtree, block_len, offset);
		break;

	    case CDMA_NAM_BLOCK:
		param_cdma_nam_block(tvb, subtree, block_len, offset);
		break;

	    case IMSI_T_NAM_BLOCK:
		param_imsi_t_nam_block(tvb, subtree, block_len, offset);
		break;

	    default:
		proto_tree_add_none_format(subtree, hf_ansi_683_none,
		    tvb, offset, block_len, "Block Data");
		break;
	    }

	    offset += block_len;
	}
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
msg_ms_key_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, param_len;
    proto_tree	*subtree;
    proto_item	*item;
    guint32	saved_offset;

    SHORT_DATA_CHECK(len, 3);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"A-Key Protocol Revision (%d)",
	oct);
    offset++;

    param_len = tvb_get_guint8(tvb, offset);

    item =
	proto_tree_add_none_format(tree, hf_ansi_683_none,
	    tvb, offset, param_len + 1,
	    "Key exchange parameter P");
    subtree = proto_item_add_subtree(item, ett_key_p);

    proto_tree_add_uint(subtree, hf_ansi_683_length,
	tvb, offset, 1, param_len);
    offset++;

    if (param_len > 0)
    {
	proto_tree_add_none_format(subtree, hf_ansi_683_none,
	    tvb, offset, param_len,
	    "Parameter P");
	offset += param_len;
    }

    param_len = tvb_get_guint8(tvb, offset);

    item =
	proto_tree_add_none_format(tree, hf_ansi_683_none,
	    tvb, offset, param_len + 1,
	    "Key exchange parameter G");
    subtree = proto_item_add_subtree(item, ett_key_g);

    proto_tree_add_uint(subtree, hf_ansi_683_length,
	tvb, offset, 1, param_len);
    offset++;

    if (param_len > 0)
    {
	proto_tree_add_none_format(subtree, hf_ansi_683_none,
	    tvb, offset, param_len,
	    "Parameter G");
	offset += param_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
msg_key_gen_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	param_len;
    guint32	saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    param_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
	tvb, offset, 1, param_len);
    offset++;

    if (param_len > (len - (offset - saved_offset)))
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb,
	    offset, len - (offset - saved_offset), "Short Data (?)");
	return;
    }

    if (param_len > 0)
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none,
	    tvb, offset, param_len,
	    "Calculation Result");
	offset += param_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
msg_reauth_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{

    EXACT_DATA_CHECK(len, 4);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 4,
	"Random Challenge value");
}

static void
msg_sspr_config_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    const gchar	*str = NULL;
    guint32	saved_offset;
    guint32	value;
    proto_tree	*subtree;
    proto_item	*item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_sspr_param_block_type(oct);

    item =
	proto_tree_add_none_format(tree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "%s (%d)",
	    str,
	    oct);

    offset++;

    if (oct == 0x01)
    {
	subtree = proto_item_add_subtree(item, ett_rev_sspr_block);

	if ((len - (offset - saved_offset)) < 3)
	{
	    proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
		offset, len - (offset - saved_offset), "Short Data (?)");
	    return;
	}

	value = tvb_get_ntohs(tvb, offset);

	proto_tree_add_none_format(subtree, hf_ansi_683_none,
	    tvb, offset, 2,
	    "Segment offset (%d)",
	    value);
	offset += 2;

	oct = tvb_get_guint8(tvb, offset);

	proto_tree_add_none_format(subtree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "Maximum segment size (%d)",
	    oct);
	offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
msg_sspr_download_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, block_len;
    const gchar	*str = NULL;
    guint32	saved_offset;
    proto_tree	*subtree;
    proto_item	*item;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = for_sspr_param_block_type(oct);

    item =
	proto_tree_add_none_format(tree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "%s (%d)",
	    str,
	    oct);

    subtree = proto_item_add_subtree(item, ett_for_sspr_block);
    offset++;

    block_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(subtree, hf_ansi_683_length,
	tvb, offset, 1, block_len);
    offset++;

    if (block_len > (len - (offset - saved_offset)))
    {
	proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
	    offset, len - (offset - saved_offset), "Short Data (?)");
	return;
    }

    if (block_len > 0)
    {
	proto_tree_add_none_format(subtree, hf_ansi_683_none,
	    tvb, offset, block_len, "Block Data");
	offset += block_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
msg_validate_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, block_id, block_len;
    const gchar	*str = NULL;
    proto_tree	*subtree;
    proto_item	*item;
    guint32	i, saved_offset, block_offset;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"Number of parameter blocks (%d)",
	oct);

    offset++;

    if ((guint32)(oct * 2) > (len - (offset - saved_offset)))
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb,
	    offset, len - (offset - saved_offset), "Short Data (?)");
	return;
    }

    for (i=0; i < oct; i++)
    {
	block_offset = offset;
	block_id = tvb_get_guint8(tvb, offset);

	str = for_val_param_block_type(block_id);

	item =
	    proto_tree_add_none_format(tree, hf_ansi_683_none,
		tvb, offset, -1,
		str);

	subtree = proto_item_add_subtree(item, ett_for_val_block);

	proto_tree_add_none_format(subtree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "Block ID (%d)",
	    block_id);

	offset++;

	block_len = tvb_get_guint8(tvb, offset);

	proto_tree_add_uint(subtree, hf_ansi_683_length,
	    tvb, offset, 1, block_len);

	offset++;

	proto_item_set_len(item, (offset - block_offset) + block_len);

	if (block_len > (len - (offset - saved_offset)))
	{
	    proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
		offset, len - (offset - saved_offset), "Short Data (?)");
	    return;
	}

	if (block_len > 0)
	{
	    switch (block_id)
	    {
	    case VERIFY_SPC_VAL_BLOCK:
		param_verify_spc_val_block(tvb, subtree, block_len, offset);
		break;

	    case CHANGE_SPC_VAL_BLOCK:
	    case VALDATE_SPASM_VAL_BLOCK:
	    default:
		proto_tree_add_none_format(subtree, hf_ansi_683_none,
		    tvb, offset, block_len, "Block Data");
		break;
	    }

	    offset += block_len;
	}
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
msg_otapa_req(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    guint32	saved_offset;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  %s OTAPA session",
	bigbuf,
	(oct & 0x80) ? "Start" : "Stop");

    other_decode_bitfield_value(bigbuf, oct, 0x7f, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Reserved",
	bigbuf);

    offset++;
}

static void
msg_config_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, num_blocks, block_len;
    const gchar	*str = NULL;
    guint32	i, saved_offset;
    proto_tree	*subtree;
    proto_item	*item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"Number of parameter blocks (%d)",
	num_blocks);

    offset++;

    if ((guint32)(num_blocks * 2) > (len - (offset - saved_offset)))
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb,
	    offset, len - (offset - saved_offset), "Short Data (?)");
	return;
    }

    for (i=0; i < num_blocks; i++)
    {
	oct = tvb_get_guint8(tvb, offset);

	str = rev_nam_param_block_type(oct);

	item =
	    proto_tree_add_none_format(tree, hf_ansi_683_none,
		tvb, offset, 1,
		"%s (%d)",
		str,
		oct);

	subtree = proto_item_add_subtree(item, ett_rev_nam_block);
	offset++;

	block_len = tvb_get_guint8(tvb, offset);

	proto_tree_add_uint(subtree, hf_ansi_683_length,
	    tvb, offset, 1, block_len);
	offset++;

	if (block_len > (len - (offset - saved_offset)))
	{
	    proto_tree_add_none_format(subtree, hf_ansi_683_none, tvb,
		offset, len - (offset - saved_offset), "Short Data (?)");
	    return;
	}

	if (block_len > 0)
	{
	    proto_tree_add_none_format(subtree, hf_ansi_683_none,
		tvb, offset, block_len, "Block Data");
	    offset += block_len;
	}
    }

    if (num_blocks > (len - (offset - saved_offset)))
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb,
	    offset, len - (offset - saved_offset), "Short Data (?)");
	return;
    }

    for (i=0; i < num_blocks; i++)
    {
	oct = tvb_get_guint8(tvb, offset);

	str = rev_res_code_type(oct);

	proto_tree_add_none_format(tree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "%s (%d)",
	    str,
	    oct);

	offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
msg_download_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, num_blocks;
    const gchar	*str = NULL;
    guint32	i, saved_offset;
    proto_tree	*subtree;
    proto_item	*item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"Number of parameter blocks (%d)",
	num_blocks);

    offset++;

    if ((guint32)(num_blocks * 2) > (len - (offset - saved_offset)))
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb,
	    offset, len - (offset - saved_offset), "Short Data (?)");
	return;
    }

    for (i=0; i < num_blocks; i++)
    {
	oct = tvb_get_guint8(tvb, offset);

	str = for_nam_param_block_type(oct);

	item =
	    proto_tree_add_none_format(tree, hf_ansi_683_none,
		tvb, offset, 1,
		"%s (%d)",
		str,
		oct);

	subtree = proto_item_add_subtree(item, ett_for_nam_block);
	offset++;

	oct = tvb_get_guint8(tvb, offset);

	str = rev_res_code_type(oct);

	proto_tree_add_none_format(subtree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "%s (%d)",
	    str,
	    oct);

	offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
msg_ms_key_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    const gchar	*str = NULL;
    guint32	saved_offset;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"Key exchange result code, %s (%d)",
	str,
	oct);

    offset++;
}

static void
msg_key_gen_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, result_len;
    const gchar	*str = NULL;
    guint32	saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"Key exchange result code, %s (%d)",
	str,
	oct);

    offset++;

    result_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
	tvb, offset, 1, result_len);
    offset++;

    if (result_len > (len - (offset - saved_offset)))
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb,
	    offset, len - (offset - saved_offset), "Short Data (?)");
	return;
    }

    if (result_len > 0)
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none,
	    tvb, offset, result_len, "Calculation Result");
	offset += result_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
msg_reauth_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint32	saved_offset;
    guint32	value;

    EXACT_DATA_CHECK(len, 7);

    saved_offset = offset;

    value = tvb_get_ntoh24(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xffffc0, 24);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 3,
	"%s :  Authentication signature data (AUTHR) (%d)",
	bigbuf,
	(value & 0xffffc0) >> 6);

    offset += 2;

    value = tvb_get_ntohs(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0x3fc0, 16);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"%s :  Random challenge value (RANDC) (%d)",
	bigbuf,
	(value & 0x3fc0) >> 6);

    other_decode_bitfield_value(bigbuf, value, 0x3f, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset + 1, 1,
	"%s :  Call history parameter (COUNT) (%d)",
	bigbuf,
	value & 0x3f);

    offset += 2;

    value = tvb_get_ntoh24(tvb, offset);

    other_decode_bitfield_value(bigbuf, value, 0xffffff, 24);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 3,
	"%s :  Authentication Data input parameter (AUTH_DATA) (%d)",
	bigbuf,
	value);
}

static void
msg_commit_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    const gchar	*str = NULL;
    guint32	saved_offset;

    EXACT_DATA_CHECK(len, 1);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"Data commit result code, %s (%d)",
	str,
	oct);

    offset++;
}

static void
msg_protocap_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, num_feat, add_len;
    const gchar	*str = NULL;
    guint32	i, saved_offset;
    guint32	value;
    proto_tree	*subtree;
    proto_item	*item;

    SHORT_DATA_CHECK(len, 5);

    saved_offset = offset;

    value = tvb_get_ntohs(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"Mobile station firmware revision number (%d)",
	value);

    offset += 2;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"Mobile station manufacturer’s model number (%d)",
	oct);

    offset++;

    num_feat = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"Number of features (%d)",
	num_feat);

    offset++;

    if ((guint32)(num_feat * 2) > (len - (offset - saved_offset)))
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb,
	    offset, len - (offset - saved_offset), "Short Data (?)");
	return;
    }

    for (i=0; i < num_feat; i++)
    {
	oct = tvb_get_guint8(tvb, offset);

	str = rev_feat_id_type(oct);

	item =
	    proto_tree_add_none_format(tree, hf_ansi_683_none,
		tvb, offset, 1,
		"Feature ID, %s (%d)",
		str,
		oct);

	subtree = proto_item_add_subtree(item, ett_rev_feat);
	offset++;

	oct = tvb_get_guint8(tvb, offset);

	proto_tree_add_none_format(subtree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "Feature protocol version (%d)",
	    oct);

	offset++;
    }

    add_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
	tvb, offset, 1, add_len);
    offset++;

    if (add_len > (len - (offset - saved_offset)))
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb,
	    offset, len - (offset - saved_offset), "Short Data (?)");
	return;
    }

    if (add_len > 0)
    {
	oct = tvb_get_guint8(tvb, offset);

	item =
	    proto_tree_add_none_format(tree, hf_ansi_683_none,
		tvb, offset, 1,
		"Band/Mode Capability Information");

	subtree = proto_item_add_subtree(item, ett_band_cap);

	other_decode_bitfield_value(bigbuf, oct, 0x80, 8);
	proto_tree_add_none_format(subtree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "%s :  Band Class 0 Analog",
	    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x40, 8);
	proto_tree_add_none_format(subtree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "%s :  Band Class 0 CDMA",
	    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x20, 8);
	proto_tree_add_none_format(subtree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "%s :  Band Class 1 CDMA",
	    bigbuf);

	other_decode_bitfield_value(bigbuf, oct, 0x1f, 8);
	proto_tree_add_none_format(subtree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "%s :  Reserved",
	    bigbuf);

	offset++;

	if (add_len > 1)
	{
	    proto_tree_add_none_format(tree, hf_ansi_683_none,
		tvb, offset, add_len - 1,
		"More Additional Fields");
	    offset += (add_len - 1);
	}
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
msg_sspr_config_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, block_len;
    const gchar	*str = NULL;
    guint32	saved_offset;

    SHORT_DATA_CHECK(len, 3);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_sspr_param_block_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s (%d)",
	str,
	oct);

    offset++;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"SSPR Configuration result code, %s (%d)",
	str,
	oct);

    offset++;

    block_len = tvb_get_guint8(tvb, offset);

    proto_tree_add_uint(tree, hf_ansi_683_length,
	tvb, offset, 1, block_len);
    offset++;

    if (block_len > (len - (offset - saved_offset)))
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb,
	    offset, len - (offset - saved_offset), "Short Data (?)");
	return;
    }

    if (block_len > 0)
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none,
	    tvb, offset, block_len, "Block Data");
	offset += block_len;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
msg_sspr_download_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    const gchar	*str = NULL;
    guint32	saved_offset;
    guint32	value;

    EXACT_DATA_CHECK(len, 5);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = for_sspr_param_block_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s (%d)",
	str,
	oct);

    offset++;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"SSPR Download result code, %s (%d)",
	str,
	oct);

    offset++;

    value = tvb_get_ntohs(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 2,
	"Segment offset (%d)",
	value);
    offset += 2;

    oct = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"Maximum segment size (%d)",
	oct);
    offset++;
}

static void
msg_validate_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct, block_id, num_blocks;
    const gchar	*str = NULL;
    guint32	i, saved_offset;
    proto_tree	*subtree;
    proto_item	*item;

    SHORT_DATA_CHECK(len, 1);

    saved_offset = offset;

    num_blocks = tvb_get_guint8(tvb, offset);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"Number of parameter blocks (%d)",
	num_blocks);

    offset++;

    if ((guint32)(num_blocks * 2) > (len - (offset - saved_offset)))
    {
	proto_tree_add_none_format(tree, hf_ansi_683_none, tvb,
	    offset, len - (offset - saved_offset), "Short Data (?)");
	return;
    }

    for (i=0; i < num_blocks; i++)
    {
	block_id = tvb_get_guint8(tvb, offset);

	str = for_val_param_block_type(block_id);

	item =
	    proto_tree_add_none_format(tree, hf_ansi_683_none,
		tvb, offset, 1,
		"%s (%d)",
		str,
		block_id);

	subtree = proto_item_add_subtree(item, ett_for_val_block);
	offset++;

	oct = tvb_get_guint8(tvb, offset);

	str = rev_res_code_type(oct);

	proto_tree_add_none_format(subtree, hf_ansi_683_none,
	    tvb, offset, 1,
	    "%s (%d)",
	    str,
	    oct);

	offset++;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static void
msg_otapa_rsp(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset)
{
    guint8	oct;
    const gchar	*str = NULL;
    guint32	saved_offset;

    SHORT_DATA_CHECK(len, 2);

    saved_offset = offset;

    oct = tvb_get_guint8(tvb, offset);

    str = rev_res_code_type(oct);

    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s (%d)",
	str,
	oct);

    offset++;

    oct = tvb_get_guint8(tvb, offset);

    other_decode_bitfield_value(bigbuf, oct, 0xfe, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  Reserved",
	bigbuf);

    other_decode_bitfield_value(bigbuf, oct, 0x01, 8);
    proto_tree_add_none_format(tree, hf_ansi_683_none,
	tvb, offset, 1,
	"%s :  NAM_LOCK indicator",
	bigbuf);

    offset++;

    if (oct & 0x01)
    {
	if (4 > (len - (offset - saved_offset)))
	{
	    proto_tree_add_none_format(tree, hf_ansi_683_none, tvb,
		offset, len - (offset - saved_offset), "Short Data (?)");
	    return;
	}

	proto_tree_add_none_format(tree, hf_ansi_683_none,
	    tvb, offset, 4,
	    "SPASM random challenge");
	offset += 4;
    }

    EXTRANEOUS_DATA_CHECK(len, offset - saved_offset);
}

static const value_string for_msg_type_strings[] = {
    { 0,	"Configuration Request" },
    { 1,	"Download Request" },
    { 2,	"MS Key Request" },
    { 3,	"Key Generation Request" },
    { 4,	"Re-Authenticate Request" },
    { 5,	"Commit Request" },
    { 6,	"Protocol Capability Request" },
    { 7,	"SSPR Configuration Request" },
    { 8,	"SSPR Download Request" },
    { 9,	"Validation Request" },
    { 10,	"OTAPA Request" },
    { 0, NULL },
};
#define	NUM_FOR_MSGS (sizeof(for_msg_type_strings)/sizeof(value_string))
static void (*ansi_683_for_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    msg_config_req,	/* Configuration Request */
    msg_download_req,	/* Download Request */
    msg_ms_key_req,	/* MS Key Request */
    msg_key_gen_req,	/* Key Generation Request */
    msg_reauth_req,	/* Re-Authenticate Request */
    NULL /* No data */,	/* Commit Request */
    NULL /* No data */,	/* Protocol Capability Request */
    msg_sspr_config_req,	/* SSPR Configuration Request */
    msg_sspr_download_req,	/* SSPR Download Request */
    msg_validate_req,	/* Validation Request */
    msg_otapa_req,	/* OTAPA Request */
    NULL,	/* NONE */
};

static const value_string rev_msg_type_strings[] = {
    { 0,	"Configuration Response" },
    { 1,	"Download Response" },
    { 2,	"MS Key Response" },
    { 3,	"Key Generation Response" },
    { 4,	"Re-Authenticate Response" },
    { 5,	"Commit Response" },
    { 6,	"Protocol Capability Response" },
    { 7,	"SSPR Configuration Response" },
    { 8,	"SSPR Download Response" },
    { 9,	"Validation Response" },
    { 10,	"OTAPA Response" },
    { 0, NULL },
};
#define	NUM_REV_MSGS (sizeof(rev_msg_type_strings)/sizeof(value_string))
static void (*ansi_683_rev_msg_fcn[])(tvbuff_t *tvb, proto_tree *tree, guint len, guint32 offset) = {
    msg_config_rsp,	/* Configuration Response */
    msg_download_rsp,	/* Download Response */
    msg_ms_key_rsp,	/* MS Key Response */
    msg_key_gen_rsp,	/* Key Generation Response */
    msg_reauth_rsp,	/* Re-Authenticate Response */
    msg_commit_rsp,	/* Commit Response */
    msg_protocap_rsp,	/* Protocol Capability Response */
    msg_sspr_config_rsp,	/* SSPR Configuration Response */
    msg_sspr_download_rsp,	/* SSPR Download Response */
    msg_validate_rsp,	/* Validation Response */
    msg_otapa_rsp,	/* OTAPA Response */
    NULL,	/* NONE */
};


static void
dissect_ansi_683_for_message(tvbuff_t *tvb, proto_tree *ansi_683_tree)
{
    guint8	msg_type;
    gint	idx;
    const gchar	*str = NULL;


    msg_type = tvb_get_guint8(tvb, 0);

    str = match_strval_idx(msg_type, for_msg_type_strings, &idx);

    if (str == NULL)
    {
	return;
    }

    /*
     * No Information column data
     */

    proto_tree_add_uint(ansi_683_tree, hf_ansi_683_for_msg_type,
	tvb, 0, 1, msg_type);

    if (ansi_683_for_msg_fcn[idx] != NULL)
    {
	(*ansi_683_for_msg_fcn[idx])(tvb, ansi_683_tree, tvb_length(tvb) - 1, 1);
    }
}

static void
dissect_ansi_683_rev_message(tvbuff_t *tvb, proto_tree *ansi_683_tree)
{
    guint8	msg_type;
    gint	idx;
    const gchar	*str = NULL;


    msg_type = tvb_get_guint8(tvb, 0);

    str = match_strval_idx(msg_type, rev_msg_type_strings, &idx);

    if (str == NULL)
    {
	return;
    }

    /*
     * No Information column data
     */

    proto_tree_add_uint(ansi_683_tree, hf_ansi_683_rev_msg_type,
	tvb, 0, 1, msg_type);

    (*ansi_683_rev_msg_fcn[idx])(tvb, ansi_683_tree, tvb_length(tvb) - 1, 1);
}

static void
dissect_ansi_683(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item	*ansi_683_item;
    proto_tree	*ansi_683_tree = NULL;

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
	 * create the ansi_683 protocol tree
	 */
	ansi_683_item =
	    proto_tree_add_protocol_format(tree, proto_ansi_683, tvb, 0, -1,
		"%s %s Link",
		ansi_proto_name,
		(pinfo->match_port == ANSI_683_FORWARD) ? "Forward" : "Reverse");

	ansi_683_tree =
	    proto_item_add_subtree(ansi_683_item, ett_ansi_683);

	if (pinfo->match_port == ANSI_683_FORWARD)
	{
	    dissect_ansi_683_for_message(tvb, ansi_683_tree);
	}
	else
	{
	    dissect_ansi_683_rev_message(tvb, ansi_683_tree);
	}
    }
}


/* Register the protocol with Wireshark */
void
proto_register_ansi_683(void)
{

    /* Setup list of header fields */
    static hf_register_info hf[] =
    {
	{ &hf_ansi_683_for_msg_type,
	  { "Forward Link Message Type",
	    "ansi_683.for_msg_type",
	    FT_UINT8, BASE_DEC, VALS(for_msg_type_strings), 0,
	    "", HFILL }},
	{ &hf_ansi_683_rev_msg_type,
	  { "Reverse Link Message Type",
	    "ansi_683.rev_msg_type",
	    FT_UINT8, BASE_DEC, VALS(rev_msg_type_strings), 0,
	    "", HFILL }},
	{ &hf_ansi_683_length,
	    { "Length",		"ansi_683.len",
	    FT_UINT8, BASE_DEC, NULL, 0,
	    "", HFILL }
	},
	{ &hf_ansi_683_none,
	    { "Sub tree",	"ansi_683.none",
	    FT_NONE, 0, 0, 0,
	    "", HFILL }
	},
    };

    /* Setup protocol subtree array */
#define	NUM_INDIVIDUAL_PARAMS	10
    static gint *ett[NUM_INDIVIDUAL_PARAMS];

    memset((void *) ett, 0, sizeof(ett));

    ett[0] = &ett_ansi_683;
    ett[1] = &ett_for_nam_block;
    ett[2] = &ett_rev_nam_block;
    ett[3] = &ett_key_p;
    ett[4] = &ett_key_g;
    ett[5] = &ett_rev_feat;
    ett[6] = &ett_for_val_block;
    ett[7] = &ett_for_sspr_block;
    ett[8] = &ett_band_cap;
    ett[9] = &ett_rev_sspr_block;

    /* Register the protocol name and description */
    proto_ansi_683 =
	proto_register_protocol(ansi_proto_name, "ANSI IS-683-A (OTA (Mobile))", "ansi_683");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_ansi_683, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}


void
proto_reg_handoff_ansi_683(void)
{
    dissector_handle_t	ansi_683_handle;

    ansi_683_handle = create_dissector_handle(dissect_ansi_683, proto_ansi_683);

    dissector_add("ansi_map.ota", ANSI_683_FORWARD, ansi_683_handle);
    dissector_add("ansi_map.ota", ANSI_683_REVERSE, ansi_683_handle);
    dissector_add("ansi_a.ota", ANSI_683_FORWARD, ansi_683_handle);
    dissector_add("ansi_a.ota", ANSI_683_REVERSE, ansi_683_handle);

    data_handle = find_dissector("data");
}
