/* packet-gsm_a_common.c
 * Common routines for GSM A Interface dissection
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Split from packet-gsm_a.c by Neil Piercy <Neil [AT] littlebriars.co.uk>
 *
 * $Id:$
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

#include <string.h>

#include <epan/packet.h>

#include "packet-bssap.h"
#include "packet-gsm_a_common.h"

/* nasty globals as a result of the split of packet-gsm_a.c in need of further restructure */
/* nasty static for handling half octet mandatory V IEs */
gboolean lower_nibble=FALSE;

static int get_hf_elem_id(int pdu_type)
{
	int			hf_elem_id;

	switch (pdu_type) {
		case GSM_A_PDU_TYPE_BSSMAP:
			hf_elem_id = hf_gsm_a_bssmap_elem_id;
			break;
		case GSM_A_PDU_TYPE_DTAP:
			hf_elem_id = hf_gsm_a_bssmap_elem_id;
			break;
		case GSM_A_PDU_TYPE_RP:
			hf_elem_id = hf_gsm_a_rp_elem_id;
			break;
		default:
			hf_elem_id = NULL;
	}

	return hf_elem_id;
}

/*
 * Type Length Value (TLV) element dissector
 */
guint8 elem_tlv(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, guint len, const gchar *name_add)
{
    guint8		oct;
	guint16		parm_len;
	guint8		lengt_length = 1;
	guint8		consumed;
	guint32		curr_offset;
	proto_tree		*subtree;
	proto_item		*item;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	len = len;
	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	oct = tvb_get_guint8(tvb, curr_offset);

    if (oct == iei){
		if (oct == GSM_BSSMAP_APDU_IE){
			/* This elements length is in two octets (a bit of a hack here)*/
			lengt_length = 2;
			parm_len = tvb_get_ntohs(tvb, curr_offset + 1);
			lengt_length = 2;
			if(parm_len > 255){
				/* The rest of the logic can't handle length > 255 */
				DISSECTOR_ASSERT_NOT_REACHED();
			}
		}else{
	parm_len = tvb_get_guint8(tvb, curr_offset + 1);
		}

	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, parm_len + 1 + lengt_length,
		"%s%s",
		elem_names[idx].strptr,
		(name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

	subtree = proto_item_add_subtree(item, elem_ett[idx]);

	proto_tree_add_uint(subtree,
	    get_hf_elem_id(pdu_type), tvb,
	    curr_offset, 1, oct);

	proto_tree_add_uint(subtree, hf_gsm_a_length, tvb,
	    curr_offset + 1, lengt_length, parm_len);

	if (parm_len > 0)
	{
	    if (elem_funcs[idx] == NULL)
	    {
		proto_tree_add_text(subtree,
		    tvb, curr_offset + 1 + lengt_length, parm_len,
		    "Element Value");
		/* See ASSERT above */
		consumed = (guint8)parm_len;
	    }
	    else
	    {
				gchar *a_add_string;

		a_add_string=ep_alloc(1024);
		a_add_string[0] = '\0';
		consumed =
		    (*elem_funcs[idx])(tvb, subtree, curr_offset + 2,
			parm_len, a_add_string, 1024);

		if (a_add_string[0] != '\0')
		{
		    proto_item_append_text(item, "%s", a_add_string);
		}
	    }
	}

	consumed += 1 + lengt_length;
	}

	return(consumed);
}

/*
 * Type Value (TV) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
guint8 elem_tv(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
	guint8		oct;
	guint8		consumed;
	guint32		curr_offset;
	proto_tree		*subtree;
	proto_item		*item;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == iei)
	{
	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, -1,
		"%s%s",
		elem_names[idx].strptr,
		(name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

	subtree = proto_item_add_subtree(item, elem_ett[idx]);

	proto_tree_add_uint(subtree,
	    get_hf_elem_id(pdu_type), tvb,
	    curr_offset, 1, oct);

	if (elem_funcs[idx] == NULL)
	{
	    /* BAD THING, CANNOT DETERMINE LENGTH */

	    proto_tree_add_text(subtree,
		tvb, curr_offset + 1, 1,
		"No element dissector, rest of dissection may be incorrect");

	    consumed = 1;
	}
	else
	{
			gchar *a_add_string;

	    a_add_string=ep_alloc(1024);
	    a_add_string[0] = '\0';
	    consumed = (*elem_funcs[idx])(tvb, subtree, curr_offset + 1, -1, a_add_string, 1024);

	    if (a_add_string[0] != '\0')
	    {
		proto_item_append_text(item, "%s", a_add_string);
	    }
	}

	consumed++;

	proto_item_set_len(item, consumed);
	}

	return(consumed);
}

/*
 * Type Value (TV) element dissector
 * Where top half nibble is IEI and bottom half nibble is value.
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
guint8 elem_tv_short(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
	guint8		oct;
	guint8		consumed;
	guint32		curr_offset;
	proto_tree		*subtree;
	proto_item		*item;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
	char buf[10+1];

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	oct = tvb_get_guint8(tvb, curr_offset);

	if ((oct & 0xf0) == (iei & 0xf0))
	{
	item =
	    proto_tree_add_text(tree,
		tvb, curr_offset, -1,
		"%s%s",
		elem_names[idx].strptr,
		(name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

	subtree = proto_item_add_subtree(item, elem_ett[idx]);

	other_decode_bitfield_value(buf, oct, 0xf0, 8);
	proto_tree_add_text(subtree,
	    tvb, curr_offset, 1,
	    "%s :  Element ID",
	    buf);

	if (elem_funcs[idx] == NULL)
	{
	    /* BAD THING, CANNOT DETERMINE LENGTH */

	    proto_tree_add_text(subtree,
		tvb, curr_offset, 1,
		"No element dissector, rest of dissection may be incorrect");

	    consumed++;
	}
	else
	{
			gchar *a_add_string;

	    a_add_string=ep_alloc(1024);
	    a_add_string[0] = '\0';
	    consumed = (*elem_funcs[idx])(tvb, subtree, curr_offset, -1, a_add_string, 1024);

	    if (a_add_string[0] != '\0')
	    {
		proto_item_append_text(item, "%s", a_add_string);
	    }
	}

	proto_item_set_len(item, consumed);
	}

	return(consumed);
}

/*
 * Type (T) element dissector
 */
guint8 elem_t(tvbuff_t *tvb, proto_tree *tree, guint8 iei, gint pdu_type, int idx, guint32 offset, const gchar *name_add)
{
	guint8		oct;
	guint32		curr_offset;
	guint8		consumed;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	oct = tvb_get_guint8(tvb, curr_offset);

	if (oct == iei)
	{
	proto_tree_add_uint_format(tree,
	    get_hf_elem_id(pdu_type), tvb,
	    curr_offset, 1, oct,
	    "%s%s",
	    elem_names[idx].strptr,
	    (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

	consumed = 1;
	}

	return(consumed);
}

/*
 * Length Value (LV) element dissector
 */
guint8 elem_lv(tvbuff_t *tvb, proto_tree *tree, gint pdu_type, int idx, guint32 offset, guint len, const gchar *name_add)
{
	guint8		parm_len;
	guint8		consumed;
	guint32		curr_offset;
	proto_tree		*subtree;
	proto_item		*item;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	len = len;
	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	parm_len = tvb_get_guint8(tvb, curr_offset);

	item =
	proto_tree_add_text(tree,
	    tvb, curr_offset, parm_len + 1,
	    "%s%s",
	    elem_names[idx].strptr,
	    (name_add == NULL) || (name_add[0] == '\0') ? "" : name_add);

	subtree = proto_item_add_subtree(item, elem_ett[idx]);

	proto_tree_add_uint(subtree, hf_gsm_a_length, tvb,
	curr_offset, 1, parm_len);

	if (parm_len > 0)
	{
	if (elem_funcs[idx] == NULL)
	{
	    proto_tree_add_text(subtree,
		tvb, curr_offset + 1, parm_len,
		"Element Value");

	    consumed = parm_len;
	}
	else
	{
			gchar *a_add_string;

	    a_add_string=ep_alloc(1024);
	    a_add_string[0] = '\0';
	    consumed =
		(*elem_funcs[idx])(tvb, subtree, curr_offset + 1,
		    parm_len, a_add_string, 1024);

	    if (a_add_string[0] != '\0')
	    {
		proto_item_append_text(item, "%s", a_add_string);
	    }
	}
	}

	return(consumed + 1);
}

/*
 * Value (V) element dissector
 *
 * Length cannot be used in these functions, big problem if a element dissector
 * is not defined for these.
 */
guint8 elem_v(tvbuff_t *tvb, proto_tree *tree, gint pdu_type, int idx, guint32 offset)
{
	guint8		consumed;
	guint32		curr_offset;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	if (elem_funcs[idx] == NULL)
	{
	/* BAD THING, CANNOT DETERMINE LENGTH */

	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "No element dissector, rest of dissection may be incorrect");

	consumed = 1;
	}
	else
	{
		gchar *a_add_string;

	a_add_string=ep_alloc(1024);
	a_add_string[0] = '\0';
	consumed = (*elem_funcs[idx])(tvb, tree, curr_offset, -1, a_add_string, 1024);
	}

	return(consumed);
}

/*
 * Short Value (V_SHORT) element dissector
 *
 * Length is (ab)used in these functions to indicate upper nibble of the octet (-2) or lower nibble (-1)
 * noting that the tv_short dissector always sets the length to -1, as the upper nibble is the IEI.
 * This is expected to be used upper nibble first, as the tables of 24.008.
 */

guint8 elem_v_short(tvbuff_t *tvb, proto_tree *tree, gint pdu_type, int idx, guint32 offset)
{
	guint8		consumed;
	guint32		curr_offset;
	const value_string	*elem_names;
	gint		*elem_ett;
	guint8 (**elem_funcs)(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

	curr_offset = offset;
	consumed = 0;

	SET_ELEM_VARS(pdu_type, elem_names, elem_ett, elem_funcs);

	if (elem_funcs[idx] == NULL)
	{
	/* NOT A BAD THING - LENGTH IS HALF NIBBLE */

	proto_tree_add_text(tree,
	    tvb, curr_offset, 1,
	    "No element dissector");

	consumed = 1;
	}
	else
	{
		gchar *a_add_string;

		a_add_string=ep_alloc(1024);
		a_add_string[0] = '\0';
		consumed = (*elem_funcs[idx])(tvb, tree, curr_offset, (lower_nibble?LOWER_NIBBLE:UPPER_NIBBLE), a_add_string, 1024);
	}
	if (!lower_nibble)	/* is this the first (upper) nibble ? */
	{
		consumed--; /* only half a nibble has been consumed, but all ie dissectors assume they consume 1 octet */
		lower_nibble = TRUE;
	}
	else	/* if it is the second (lower) nibble, move on... */
		lower_nibble = FALSE;

	return(consumed);
}
