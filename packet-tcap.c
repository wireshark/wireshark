/* packet-tcap.c
 * Routines for TCAP dissection
 *
 * Copyright 2000, Samuel Qu <samuel.qu [AT] utstar.com>,
 *
 * Michael Lum <mlum [AT] telostech.com>,
 * Modified for ANSI TCAP support and many changes for
 * EOC matching.  (2003)
 *
 * (append your name here for newer version)
 *
 * $Id: packet-tcap.c,v 1.5 2003/12/29 00:41:07 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
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
#include <gmodule.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include <epan/packet.h>
#include "prefs.h"
#include "packet-tcap.h"
#include "asn1.h"

Tcap_Standard_Type tcap_standard = ITU_TCAP_STANDARD;

/* saved pinfo */
static packet_info *g_pinfo = NULL;
static proto_tree *g_tcap_tree = NULL;
static gboolean g_tcap_ends_def_len = FALSE;

/* Initialize the protocol and registered fields */
static int proto_tcap = -1;
static int hf_tcap_message_type = -1;
static int hf_ansi_tcap_message_type = -1;
static int hf_tcap_none = -1;
static int hf_tcap_tag = -1;
static int hf_tcap_length = -1;
static int hf_tcap_bytes = -1;
static int hf_tcap_app_con_name = -1;
static int hf_tcap_id = -1;
static int hf_tcap_tid = -1;
static int hf_tcap_ssn = -1; /* faked */
static int hf_tcap_dlg_type = -1;
static int hf_tcap_int = -1;

/* Initialize the subtree pointers */
static gint ett_tcap = -1;
/* Samuel */
static gint ett_otid = -1;
static gint ett_dtid = -1;
static gint ett_dlg_portion = -1;
static gint ett_dlg_req = -1;
static gint ett_dlg_rsp = -1;
static gint ett_dlg_abort = -1;
static gint ett_cmp_portion = -1;
static gint ett_reason = -1;
static gint ett_component = -1;
static gint ett_problem = -1;
static gint ett_error = -1;
static gint ett_params = -1;
static gint ett_param = -1;

static dissector_handle_t data_handle;
static dissector_table_t tcap_itu_ssn_dissector_table; /* map use ssn in sccp */
static dissector_table_t tcap_ansi_ssn_dissector_table; /* map use ssn in sccp */
static gboolean lock_info_col = TRUE;

#define TC_SEQ_TAG 0x30
#define TC_SET_TAG 0x31

#define TC_EOC_LEN	2 /* 0x00 0x00 */

/* TCAP transaction message type definition - Samuel */
#define ST_MSG_TYP_UNI 0x61 /*0b01100001*/
#define ST_MSG_TYP_BGN 0x62 /*0b01100010*/
#define ST_MSG_TYP_CNT 0x65 /*0b01100101*/
#define ST_MSG_TYP_END 0x64 /*0b01100100*/
#define ST_MSG_TYP_PABT 0x67 /*0b01100111*/
static const value_string msg_type_strings[] = {
	{ ST_MSG_TYP_UNI, "TC-UNI" },
	{ ST_MSG_TYP_BGN, "TC-BEGIN" },
	{ ST_MSG_TYP_CNT, "TC-CONTINUE" },
	{ ST_MSG_TYP_END, "TC-END" },
	{ ST_MSG_TYP_PABT, "TC-PABORT" },
	{ 0, NULL },
};

/* ANSI TCAP transaction message type definition */
#define ANSI_ST_MSG_TYP_UNI 0xe1
#define ANSI_ST_MSG_TYP_QWP 0xe2
#define ANSI_ST_MSG_TYP_QWOP 0xe3
#define ANSI_ST_MSG_TYP_RSP 0xe4
#define ANSI_ST_MSG_TYP_CWP 0xe5
#define ANSI_ST_MSG_TYP_CWOP 0xe6
#define ANSI_ST_MSG_TYP_ABT 0xf6
static const value_string ansi_msg_type_strings[] = {
	{ ANSI_ST_MSG_TYP_UNI, "TC-UNI" },
	{ ANSI_ST_MSG_TYP_QWP, "TC-QUERY W PERM" },
	{ ANSI_ST_MSG_TYP_QWOP, "TC-QUERY WO PERM" },
	{ ANSI_ST_MSG_TYP_RSP, "TC-RESPONSE" },
	{ ANSI_ST_MSG_TYP_CWP, "TC-CONV W PERM" },
	{ ANSI_ST_MSG_TYP_CWOP, "TC-CONV WO PERM" },
	{ ANSI_ST_MSG_TYP_ABT, "TC-ABORT" },
	{ 0, NULL },
};

#define ST_ANSI_CMP_TAG 0xe8
#define ST_ANSI_TID_TAG 0xc7

/* TCAP TID tag value - Samuel */
#define ST_TID_SOURCE 0
#define ST_TID_DEST 1
#define ST_ITU_ORG_TID_TAG 0x48 /*0b01001000*/
#define ST_ITU_DST_TID_TAG 0x49 /*0b01001001*/
#define ST_ITU_PABT_TAG 0x4a /*0b01001010*/
#define ST_ITU_DLG_TAG 0x6b
#define ST_ITU_CMP_TAG 0x6c

static const value_string tid_strings[] = {
	{ ST_ITU_ORG_TID_TAG, "Source Transaction ID" },
	{ ST_ITU_DST_TID_TAG, "Destination Transaction ID" },
	{ 0, NULL },
};

/* TCAP dialog type */
#define TC_DLG_REQ 0x60
#define TC_DLG_RSP 0x61
#define TC_DLG_ABRT 0x64

static const value_string dlg_type_strings[] = {
	{ TC_DLG_REQ , "Dialogue Request" },
	{ TC_DLG_RSP , "Dialogue Response" },
	{ TC_DLG_ABRT, "Dialogue Abort" },
	{ 0, NULL },
};

/* TCAP component type */
#define TC_INVOKE 0xa1
#define TC_RRL 0xa2
#define TC_RE 0xa3
#define TC_REJECT 0xa4
#define TC_RRN 0xa7

/* ANSI TCAP component type */
#define ANSI_TC_INVOKE_L 0xe9
#define ANSI_TC_RRL 0xea
#define ANSI_TC_RE 0xeb
#define ANSI_TC_REJECT 0xec
#define ANSI_TC_INVOKE_N 0xed
#define ANSI_TC_RRN 0xee

#define TC_DS_OK 1
#define TC_DS_FAIL 0


/* dissect length */
static int
dissect_tcap_len(ASN1_SCK *asn1, proto_tree *tree, gboolean *def_len, guint *len)
{
    guint saved_offset;
    int ret;

    saved_offset = asn1->offset;
    *len = 0;
    *def_len = FALSE;
    ret = asn1_length_decode(asn1, def_len, len);

    if (*def_len)
    {
	proto_tree_add_uint(tree, hf_tcap_length, asn1->tvb, saved_offset, asn1->offset - saved_offset, *len);
    }
    else
    {
	proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, "Length: Indefinite");
    }

    return TC_DS_OK;
}

static int
dissect_tcap_eoc(ASN1_SCK *asn1, proto_tree *tree)
{
    guint saved_offset, ret;

    saved_offset = asn1->offset;

    if (tvb_length_remaining(asn1->tvb, saved_offset) <= 0)
    {
	return TC_DS_FAIL;
    }

    if (!asn1_eoc(asn1, -1))
    {
	return TC_DS_FAIL;
    }

    ret = asn1_eoc_decode(asn1, -1);

    proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, "End of Contents");

    return TC_DS_OK;
}

static int
dissect_tcap_tag(ASN1_SCK *asn1, proto_tree *tree, guint *tag, guchar * str)
{
    guint saved_offset, real_tag;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &real_tag);
    if ((*tag != (guint) -1) && (real_tag != *tag))
    {
	asn1->offset = saved_offset;
	return TC_DS_FAIL;
    }
    proto_tree_add_uint_format(tree, hf_tcap_tag, asn1->tvb, saved_offset, asn1->offset - saved_offset,
	    real_tag, str);
    return TC_DS_OK;
}

static int
dissect_tcap_octet(ASN1_SCK *asn1, proto_tree *tree, guchar * str)
{
    guint saved_offset;
    guchar my_oct;

    saved_offset = asn1->offset;
    asn1_octet_decode(asn1, &my_oct);
    proto_tree_add_uint_format(tree, hf_tcap_id, asn1->tvb, saved_offset, asn1->offset - saved_offset,
					    my_oct, "%s %d", str, my_oct);
    return TC_DS_OK;
}

static int
dissect_tcap_integer(ASN1_SCK *asn1, proto_tree *tree, guint len, guchar * str)
{
    guint saved_offset;
    gint32 invokeId;

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, len, &invokeId);
    proto_tree_add_int_format(tree, hf_tcap_int, asn1->tvb, saved_offset, asn1->offset - saved_offset,
					    invokeId, "%s %d", str, invokeId);
    return TC_DS_OK;
}

static gboolean
check_tcap_tag(ASN1_SCK *asn1, guint tag)
{
    guint saved_offset, real_tag;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0)
    {
	return (FALSE);
    }

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &real_tag);
    asn1->offset = saved_offset;
    return (tag == real_tag);
}

/* dissect tid */
static int
dissect_tcap_tid(ASN1_SCK *asn1, proto_tree *tcap_tree, proto_item *ti, int type)
{
    guint saved_offset, org_offset = 0;
    guint len;
    guint tag;
    int ret;
    proto_item *tid_item;
    proto_tree *subtree;
    guchar *poctets;
    guint32 val;
    gboolean def_len;

    org_offset = asn1->offset;
    if ( ST_TID_SOURCE == type)
    {
	tid_item = proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb, asn1->offset, -1, "Source Transaction ID");
	subtree = proto_item_add_subtree(tid_item, ett_otid);
    }
    else
    {
	tid_item = proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb, asn1->offset, -1, "Destination Transaction ID");
	subtree = proto_item_add_subtree(tid_item, ett_dtid);
    }

    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);
    proto_tree_add_uint(subtree, hf_tcap_tid, asn1->tvb, saved_offset, asn1->offset - saved_offset, tag);

    /* error handling */
    switch(type)
    {
    case ST_TID_SOURCE:
	if (ST_ITU_ORG_TID_TAG != tag)
	{
	    asn1->offset = saved_offset;
	    return TC_DS_FAIL;
	}
	break;
    case ST_TID_DEST:
	if (ST_ITU_DST_TID_TAG != tag)
	{
	    asn1->offset = saved_offset;
	    return TC_DS_FAIL;
	}
	break;
    default:
	break;
    }


    dissect_tcap_len(asn1, subtree, &def_len, &len);

    saved_offset = asn1->offset;
    ret = asn1_string_value_decode(asn1, len, &poctets);
    val = 0;
    memcpy(&val, poctets, len);

    ti = proto_tree_add_uint(subtree, hf_tcap_id, asn1->tvb, saved_offset, asn1->offset - saved_offset, val);
    g_free(poctets);

    proto_item_set_len(tid_item, asn1->offset - org_offset);

    if (type == ST_TID_DEST)
    {
	if (check_col(g_pinfo->cinfo, COL_INFO))
	    col_append_fstr(g_pinfo->cinfo, COL_INFO, "dtid(%x) ", val);
    }
    else
    {
	if (check_col(g_pinfo->cinfo, COL_INFO))
	    col_append_fstr(g_pinfo->cinfo, COL_INFO, "stid(%x) ", val);
    }

    return TC_DS_OK;
}

/* Samuel */
/* dissect operation portion */
static int
dissect_tcap_invokeId(ASN1_SCK *asn1, proto_tree *tree)
{
    guint len;
    guint tag;
    gboolean def_len;

#define INVOKE_ID_TAG 0x2
    if (check_tcap_tag(asn1, INVOKE_ID_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, tree, &tag, "Invoke ID Tag");
	dissect_tcap_len(asn1, tree, &def_len, &len);
	dissect_tcap_integer(asn1, tree, len, "Invoke ID:");
    }

    return TC_DS_OK;
}

static int
dissect_tcap_lnkId(ASN1_SCK *asn1, proto_tree *tree)
{
    guint len;
    guint tag;
    gboolean def_len;

#define LINK_ID_TAG 0x80
    if (check_tcap_tag(asn1, LINK_ID_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, tree, &tag, "Linked ID Tag");
	dissect_tcap_len(asn1, tree, &def_len, &len);
	dissect_tcap_integer(asn1, tree, len, "Linked ID:");
    }

    return TC_DS_OK;
}

static void
dissect_tcap_opr_code(ASN1_SCK *asn1, proto_tree *tree)
{
    guint len;
    guint tag;
    gboolean got_it = FALSE;
    gboolean def_len;

#define TCAP_LOC_OPR_CODE_TAG 0x02
    if (check_tcap_tag(asn1, TCAP_LOC_OPR_CODE_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, tree, &tag, "Local Operation Code Tag");
	got_it = TRUE;
    }
#define TCAP_GLB_OPR_CODE_TAG 0x06
    else if (check_tcap_tag(asn1, TCAP_GLB_OPR_CODE_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, tree, &tag, "Global Operation Code Tag");
	got_it = TRUE;
    }

    if (got_it)
    {
	dissect_tcap_len(asn1, tree, &def_len, &len);

	proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb, asn1->offset, len, "Operation Code");

	asn1->offset += len;
    }
}

static int
dissect_tcap_param(ASN1_SCK *asn1, proto_tree *tree)
{
    guint off_tree[100], saved_offset, len_offset;
    int num_seq;
    guint tag, len;
    gboolean def_len;
    proto_item *item_tree[100], *item;
    proto_tree *seq_tree[100], *use_tree, *subtree;

    num_seq = 0;
    use_tree = tree;

#define TC_INVALID_TAG 0
    while ((tvb_length_remaining(asn1->tvb, asn1->offset) > 0) &&
	(!check_tcap_tag(asn1, 0)))
    {
	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);
	len_offset = asn1->offset;
	asn1_length_decode(asn1, &def_len, &len);

	if (tag == TC_SEQ_TAG)
	{
	    item =
		proto_tree_add_none_format(use_tree, hf_tcap_none, asn1->tvb,
		    saved_offset, -1, "Sequence");

	    subtree = proto_item_add_subtree(item, ett_params);

	    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb,
		saved_offset, len_offset - saved_offset, tag, "Sequence Tag");

	    if (!def_len)
	    {
		proto_tree_add_none_format(subtree, hf_tcap_none, asn1->tvb,
		    len_offset, asn1->offset - len_offset, "Length: Indefinite");

		seq_tree[num_seq] = subtree;
		item_tree[num_seq] = item;
		off_tree[num_seq] = saved_offset;
		num_seq++;
	    }
	    else
	    {
		proto_tree_add_uint(subtree, hf_tcap_length, asn1->tvb,
		    len_offset, asn1->offset - len_offset, len);

		proto_item_set_len(item, (asn1->offset - saved_offset) + len);
	    }

	    use_tree = subtree;
	    continue;
	}

	if (!def_len)
	{
	    proto_tree_add_uint_format(use_tree, hf_tcap_tag, asn1->tvb,
		saved_offset, len_offset - saved_offset, tag, "Parameter Tag");
	    proto_tree_add_none_format(use_tree, hf_tcap_none, asn1->tvb,
		len_offset, asn1->offset - len_offset, "Length: Indefinite");

	    seq_tree[num_seq] = use_tree;
	    item_tree[num_seq] = NULL;
	    num_seq++;
	    continue;
	}
	else
	{
	    item =
		proto_tree_add_none_format(use_tree, hf_tcap_none, asn1->tvb,
		    saved_offset, -1, "Parameter");

	    subtree = proto_item_add_subtree(item, ett_param);

	    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb,
		saved_offset, len_offset - saved_offset, tag, "Parameter Tag");

	    proto_tree_add_uint(subtree, hf_tcap_length, asn1->tvb,
		len_offset, asn1->offset - len_offset, len);

	    proto_item_set_len(item, (asn1->offset - saved_offset) + len);

	    proto_tree_add_none_format(subtree, hf_tcap_none, asn1->tvb,
		asn1->offset, len, "Parameter Data");

	    asn1->offset += len;
	}

	if (tvb_length_remaining(asn1->tvb, asn1->offset) <=0) break;

	while ((num_seq > 0) &&
	    asn1_eoc(asn1, -1))
	{
	    saved_offset = asn1->offset;
	    asn1_eoc_decode(asn1, -1);

	    proto_tree_add_none_format(seq_tree[num_seq-1], hf_tcap_none, asn1->tvb,
		saved_offset, asn1->offset - saved_offset, "End of Contents");

	    if (item_tree[num_seq-1] != NULL)
	    {
		proto_item_set_len(item_tree[num_seq-1], asn1->offset - off_tree[num_seq-1]);
	    }

	    num_seq--;
	}
    }

    return TC_DS_OK;
}

static proto_tree *
dissect_tcap_component(ASN1_SCK *asn1, proto_tree *tree, guint *len_p)
{
    guint saved_offset;
    guint tag;
    proto_item *item;
    proto_tree *subtree;
    gboolean def_len;


    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    item =
	proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb,
	    saved_offset, -1, "Component ID");

    subtree = proto_item_add_subtree(item, ett_component);

    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, tag,
	"Component ID Identifier");

    dissect_tcap_len(asn1, subtree, &def_len, len_p);

    proto_item_set_len(item, (asn1->offset - saved_offset) + *len_p);

    return(subtree);
}

static void
dissect_tcap_problem(ASN1_SCK *asn1, proto_tree *tree)
{
    guint orig_offset, saved_offset = 0;
    guint len, tag_len;
    guint tag;
    proto_tree *subtree;
    proto_item *item = NULL;
    gchar *str = NULL;
    gchar *type_str = NULL;
    gint32 spec;
    gboolean def_len;


    orig_offset = asn1->offset;
    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);
    tag_len = asn1->offset - saved_offset;

    item =
	proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb,
	    saved_offset, -1, "Problem Code");

    subtree = proto_item_add_subtree(item, ett_problem);

    dissect_tcap_len(asn1, subtree, &def_len, &len);
    proto_item_set_len(item, (asn1->offset - saved_offset) + len);

    if (len != 1)
    {
	proto_tree_add_none_format(subtree, hf_tcap_none, asn1->tvb,
	    asn1->offset, len, "Unknown encoding of Problem Code");

	asn1->offset += len;
	return;
    }

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 1, &spec);

    switch (tag)
    {
    case 0x80:
	type_str = "General Problem";
	switch (spec)
	{
	case 0: str = "Unrecognized Component"; break;
	case 1: str = "Mistyped Component"; break;
	case 2: str = "Badly Structured Component"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    case 0x81:
	type_str = "Invoke";
	switch (spec)
	{
	case 0: str = "Duplicate Invoke ID"; break;
	case 1: str = "Unrecognized Operation"; break;
	case 2: str = "Mistyped Parameter"; break;
	case 3: str = "Resource Limitation"; break;
	case 4: str = "Initiating Release"; break;
	case 5: str = "Unrecognized Linked ID"; break;
	case 6: str = "Linked Response Unexpected"; break;
	case 7: str = "Unexpected Linked Operation"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    case 0x82:
	type_str = "Return Result";
	switch (spec)
	{
	case 0: str = "Unrecognized Invoke ID"; break;
	case 1: str = "Return Result Unexpected"; break;
	case 2: str = "Mistyped Parameter"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    case 0x83:
	type_str = "Return Error";
	switch (spec)
	{
	case 0: str = "Unrecognized Invoke ID"; break;
	case 1: str = "Return Error Unexpected"; break;
	case 2: str = "Unrecognized Error"; break;
	case 3: str = "Unexpected Error"; break;
	case 4: str = "Mistyped Parameter"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    default:
	type_str = "Undefined";
	break;
    }

    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb,
	orig_offset, tag_len, tag, type_str);

    proto_tree_add_none_format(subtree, hf_tcap_none, asn1->tvb,
	saved_offset, 1, "Problem Specifier %s", str);
}


static void
dissect_ansi_opr_code(ASN1_SCK *asn1, proto_tree *tree)
{
    guint len;
    guint tag;
    gboolean got_it = FALSE;
    gboolean def_len;

#define TCAP_NAT_OPR_CODE_TAG 0xd0
    if (check_tcap_tag(asn1, TCAP_NAT_OPR_CODE_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, tree, &tag, "National TCAP Operation Code Identifier");
	got_it = TRUE;
    }
#define TCAP_PRIV_OPR_CODE_TAG 0xd1
    else if (check_tcap_tag(asn1, TCAP_PRIV_OPR_CODE_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, tree, &tag, "Private TCAP Operation Code Identifier");
	got_it = TRUE;
    }

    if (got_it)
    {
	dissect_tcap_len(asn1, tree, &def_len, &len);

	proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb, asn1->offset, len, "Operation Code");

	asn1->offset += len;
    }
}

static void
dissect_ansi_problem(ASN1_SCK *asn1, proto_tree *tree)
{
    guint saved_offset = 0;
    guint len;
    guint tag;
    proto_tree *subtree;
    proto_item *item = NULL;
    gchar *str = NULL;
    gchar *type_str = NULL;
    gint32 type, spec;
    gboolean def_len;


#define TCAP_PROB_CODE_TAG 0xd5
    if (check_tcap_tag(asn1, TCAP_PROB_CODE_TAG))
    {
	str = "Problem Code Identifier";
    }
    else
    {
	/* XXX */
	return;
    }

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    item =
	proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb,
	    saved_offset, -1, "Problem Code");

    subtree = proto_item_add_subtree(item, ett_problem);

    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, tag, str);

    dissect_tcap_len(asn1, subtree, &def_len, &len);
    proto_item_set_len(item, (asn1->offset - saved_offset) + len);

    if (len != 2)
    {
	proto_tree_add_none_format(subtree, hf_tcap_none, asn1->tvb,
	    asn1->offset, len, "Unknown encoding of Problem Code");

	asn1->offset += len;
	return;
    }

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, 1, &type);
    asn1_int32_value_decode(asn1, 1, &spec);

    switch (type)
    {
    case 0: type_str = "Not used"; break;

    case 1:
	type_str = "General";
	switch (spec)
	{
	case 1: str = "Unrecognized Component Type"; break;
	case 2: str = "Incorrect Component Portion"; break;
	case 3: str = "Badly Structured Component Portion"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    case 2:
	type_str = "Invoke";
	switch (spec)
	{
	case 1: str = "Duplicate Invoke ID"; break;
	case 2: str = "Unrecognized Operation Code"; break;
	case 3: str = "Incorrect Parameter"; break;
	case 4: str = "Unrecognized Correlation ID"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    case 3:
	type_str = "Return Result";
	switch (spec)
	{
	case 1: str = "Unrecognized Correlation ID"; break;
	case 2: str = "Unexpected Return Result"; break;
	case 3: str = "Incorrect Parameter"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    case 4:
	type_str = "Return Error";
	switch (spec)
	{
	case 1: str = "Unrecognized Correlation ID"; break;
	case 2: str = "Unexpected Return Error"; break;
	case 3: str = "Unrecognized Error"; break;
	case 4: str = "Unexpected Error"; break;
	case 5: str = "Incorrect Parameter"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    case 5:
	type_str = "Transaction Portion";
	switch (spec)
	{
	case 1: str = "Unrecognized Package Type"; break;
	case 2: str = "Incorrect Transaction Portion"; break;
	case 3: str = "Badly Structured Transaction Portion"; break;
	case 4: str = "Unrecognized Transaction ID"; break;
	case 5: str = "Permission to Release"; break;
	case 6: str = "Resource Unavailable"; break;
	default:
	    str = "Undefined";
	    break;
	}
	break;

    default:
	type_str = "Undefined";
	break;
    }

    if (spec == 255) { str = "Reserved"; }
    else if (spec == 0) { str = "Not used"; }

    proto_tree_add_none_format(subtree, hf_tcap_none, asn1->tvb,
	saved_offset, 1, "Problem Type %s", type_str);

    proto_tree_add_none_format(subtree, hf_tcap_none, asn1->tvb,
	saved_offset + 1, 1, "Problem Specifier %s", str);
}


static void
dissect_ansi_error(ASN1_SCK *asn1, proto_tree *tree)
{
    guint saved_offset = 0;
    guint len;
    guint tag;
    proto_tree *subtree;
    proto_item *item = NULL;
    gchar *str = NULL;
    gboolean def_len;


#define TCAP_NAT_ERR_CODE_TAG 0xd3
    if (check_tcap_tag(asn1, TCAP_NAT_ERR_CODE_TAG))
    {
	str = "National TCAP Error Code Identifier";
    }
#define TCAP_PRIV_ERR_CODE_TAG 0xd4
    else if (check_tcap_tag(asn1, TCAP_PRIV_ERR_CODE_TAG))
    {
	str = "Private TCAP Error Code Identifier";
    }
    else
    {
	/* XXX */
	return;
    }

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    item =
	proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb,
	    saved_offset, -1, "TCAP Error Code");

    subtree = proto_item_add_subtree(item, ett_error);

    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, tag, str);

    dissect_tcap_len(asn1, subtree, &def_len, &len);
    proto_item_set_len(item, (asn1->offset - saved_offset) + len);

    proto_tree_add_none_format(subtree, hf_tcap_none, asn1->tvb,
	asn1->offset, len, "Error Code");

    asn1->offset += len;
}


static void
dissect_ansi_param(ASN1_SCK *asn1, proto_tree *tree)
{
    guint len;
    guint tag;
    gboolean got_it = FALSE;
    gboolean def_len;

#define TCAP_PARAM_SET_TAG 0xf2
    if (check_tcap_tag(asn1, TCAP_PARAM_SET_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, tree, &tag, "Parameter Set Identifier");
	got_it = TRUE;
    }
#define TCAP_PARAM_SEQ_TAG 0x30
    else if (check_tcap_tag(asn1, TCAP_PARAM_SEQ_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, tree, &tag, "Parameter Sequence Identifier");
	got_it = TRUE;
    }

    if (got_it)
    {
	dissect_tcap_len(asn1, tree, &def_len, &len);

	proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb, asn1->offset, len, "Parameter Data");

	asn1->offset += len;
    }
}

static void
dissect_ansi_tcap_reject(ASN1_SCK *asn1, proto_tree *tree)
{
    guint len;
    proto_tree *subtree;

#define COMPONENT_ID_TAG 0xcf
    if (check_tcap_tag(asn1, COMPONENT_ID_TAG))
    {
	subtree = dissect_tcap_component(asn1, tree, &len);

	switch (len)
	{
	case 1:
	    dissect_tcap_octet(asn1, subtree, "Correlation ID:");
	    break;
	}
    }

    dissect_ansi_problem(asn1, tree);

    dissect_ansi_param(asn1, tree);
}

static void
dissect_ansi_tcap_re(ASN1_SCK *asn1, proto_tree *tree)
{
    guint len;
    proto_tree *subtree;

#define COMPONENT_ID_TAG 0xcf
    if (check_tcap_tag(asn1, COMPONENT_ID_TAG))
    {
	subtree = dissect_tcap_component(asn1, tree, &len);

	switch (len)
	{
	case 1:
	    dissect_tcap_octet(asn1, tree, "Correlation ID:");
	    break;
	}
    }

    dissect_ansi_error(asn1, tree);

    dissect_ansi_param(asn1, tree);
}

static void
dissect_ansi_tcap_rr(ASN1_SCK *asn1, proto_tree *tree)
{
    guint len;
    proto_tree *subtree;

#define COMPONENT_ID_TAG 0xcf
    if (check_tcap_tag(asn1, COMPONENT_ID_TAG))
    {
	subtree = dissect_tcap_component(asn1, tree, &len);

	switch (len)
	{
	case 1:
	    dissect_tcap_octet(asn1, tree, "Correlation ID:");
	    break;
	}
    }

    dissect_ansi_param(asn1, tree);
}

static void
dissect_ansi_tcap_invoke(ASN1_SCK *asn1, proto_tree *tree)
{
    guint len;
    proto_tree *subtree;

#define COMPONENT_ID_TAG 0xcf
    if (check_tcap_tag(asn1, COMPONENT_ID_TAG))
    {
	subtree = dissect_tcap_component(asn1, tree, &len);

	switch (len)
	{
	case 1:
	    dissect_tcap_octet(asn1, tree, "Invoke ID:");
	    break;

	case 2:
	    dissect_tcap_octet(asn1, tree, "Invoke ID:");
	    dissect_tcap_octet(asn1, tree, "Correlation ID:");
	    break;
	}
    }

    dissect_ansi_opr_code(asn1, tree);

    dissect_ansi_param(asn1, tree);
}

static void
dissect_tcap_invoke(ASN1_SCK *asn1, proto_tree *tree)
{
    proto_tree *subtree;
    guint saved_offset = 0;
    guint len;
    guint tag;
    int ret;
    proto_item *item;
    guint start = asn1->offset;
    gboolean def_len;

    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);
    item = proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Components");
    subtree = proto_item_add_subtree(item, ett_component);
    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset, asn1->offset - saved_offset,
	tag, "Invoke Type Tag");

    dissect_tcap_len(asn1, subtree, &def_len, &len);

    if (def_len)
    {
	proto_item_set_len(item, (asn1->offset - start) + len);
    }

    dissect_tcap_invokeId(asn1, subtree);

    dissect_tcap_lnkId(asn1, subtree);

    dissect_tcap_opr_code(asn1, subtree);

    dissect_tcap_param(asn1, subtree);

    if (!def_len)
    {
	dissect_tcap_eoc(asn1, subtree);
    }
}

static void
dissect_tcap_rr(ASN1_SCK *asn1, proto_tree *tree, gchar *str)
{
    guint tag, len, comp_len;
    guint saved_offset;
    proto_item *item;
    proto_tree *subtree;
    gboolean def_len;
    gboolean comp_def_len;

    tag = -1;
    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);
    item = proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Components");
    subtree = proto_item_add_subtree(item, ett_component);
    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset, asn1->offset - saved_offset,
					    tag, str);

    dissect_tcap_len(asn1, subtree, &comp_def_len, &comp_len);

    if (comp_def_len)
    {
	proto_item_set_len(item, (asn1->offset - saved_offset) + comp_len);
    }

    dissect_tcap_invokeId(asn1, subtree);

    tag = TC_SEQ_TAG;
    if (check_tcap_tag(asn1, TC_SEQ_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, subtree, &tag, "Sequence Tag");
	dissect_tcap_len(asn1, subtree, &def_len, &len);
    }

    dissect_tcap_opr_code(asn1, subtree);

    dissect_tcap_param(asn1, subtree);

    if (!comp_def_len)
    {
	dissect_tcap_eoc(asn1, subtree);
    }
}

static int
dissect_tcap_re(ASN1_SCK *asn1, proto_tree *tree)
{
    guint tag, len, comp_len;
    guint saved_offset;
    proto_item *item;
    proto_tree *subtree;
    gboolean def_len;

    tag = -1;
    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);
    item = proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Components");
    subtree = proto_item_add_subtree(item, ett_component);
    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset, asn1->offset - saved_offset,
					    tag, "Return Error Type Tag");

    dissect_tcap_len(asn1, subtree, &def_len, &comp_len);

    if (def_len)
    {
	proto_item_set_len(item, (asn1->offset - saved_offset) + comp_len);
    }

    saved_offset = asn1->offset;
    dissect_tcap_invokeId(asn1, subtree);

#define TC_LOCAL_ERR_CODE_TAG 0x2
#define TC_GBL_ERR_CODE_TAG 0x6
    if (check_tcap_tag(asn1, TC_LOCAL_ERR_CODE_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, subtree, &tag, "Local Error Code Tag");
    }
    else if (check_tcap_tag(asn1, TC_GBL_ERR_CODE_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, subtree, &tag, "Global Error Code Tag");
    }
    else
    {
	proto_tree_add_none_format(subtree, hf_tcap_none, asn1->tvb, asn1->offset, comp_len,
	    "Unknown Error Code");

	asn1->offset += (comp_len - (asn1->offset - saved_offset));
	return(TC_DS_OK);
    }

    dissect_tcap_len(asn1, subtree, &def_len, &len);
    dissect_tcap_integer(asn1, subtree, len, "Error Code:");

    dissect_tcap_param(asn1, subtree);

    if (!def_len)
    {
	dissect_tcap_eoc(asn1, subtree);
    }

    return(TC_DS_OK);
}

static void
dissect_tcap_reject(ASN1_SCK *asn1, proto_tree *tree)
{
    guint tag, comp_len;
    guint saved_offset;
    proto_item *item;
    proto_tree *subtree;
    gboolean def_len;

    tag = -1;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    item = proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Components");

    subtree = proto_item_add_subtree(item, ett_component);

    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset, asn1->offset - saved_offset,
					    tag, "Reject Type Tag");

    dissect_tcap_len(asn1, subtree, &def_len, &comp_len);

    if (def_len)
    {
	proto_item_set_len(item, (asn1->offset - saved_offset) + comp_len);
    }

    dissect_tcap_invokeId(asn1, subtree);

    dissect_tcap_problem(asn1, tree);

    if (!def_len)
    {
	dissect_tcap_eoc(asn1, subtree);
    }
}

static void
dissect_ansi_tcap_next_tvb(ASN1_SCK *asn1, guint len, proto_tree *tree)
{
    tvbuff_t *next_tvb;
    guint saved_offset;
    int ret;
    gboolean flag = TRUE;
    guint tag;
    proto_item *item, *tag_item;
    proto_tree *subtree, *tag_subtree;
    gboolean def_len;


    if (lock_info_col) col_set_fence(g_pinfo->cinfo, COL_INFO);

    next_tvb = tvb_new_subset(asn1->tvb, asn1->offset, len, len);

    /* process components data */
    if (!dissector_try_port(tcap_ansi_ssn_dissector_table, g_pinfo->match_port, next_tvb, g_pinfo, g_tcap_tree))
    {
	/* dissect cmp */

	saved_offset = asn1->offset;
	ret = asn1_id_decode1(asn1, &tag);

	/*
	 * verify tag type is known
	 */
	switch (tag)
	{
	case ANSI_TC_INVOKE_L :
	case ANSI_TC_RRL :
	case ANSI_TC_RE :
	case ANSI_TC_REJECT :
	case ANSI_TC_INVOKE_N :
	case ANSI_TC_RRN :
	    flag = TRUE;
	    break;

	default:
	    flag = FALSE;
	    break;
	}

	if (flag != FALSE)
	{
	    item = proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Components");
	    subtree = proto_item_add_subtree(item, ett_component);

	    switch (tag)
	    {
	    case ANSI_TC_INVOKE_L :
		tag_item = proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset,
			    asn1->offset - saved_offset, tag, "Invoke(Last)");
		dissect_tcap_len(asn1, subtree, &def_len, &len);
		tag_subtree = proto_item_add_subtree(tag_item, ett_component);

		dissect_ansi_tcap_invoke(asn1, tag_subtree);
		break;
	    case ANSI_TC_RRL :
		tag_item = proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset,
			    asn1->offset - saved_offset, tag, "Return Result(Last)");
		dissect_tcap_len(asn1, subtree, &def_len, &len);
		tag_subtree = proto_item_add_subtree(tag_item, ett_component);

		dissect_ansi_tcap_rr(asn1, tag_subtree);
		break;
	    case ANSI_TC_RE :
		tag_item = proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset,
			    asn1->offset - saved_offset, tag, "Return Error");
		dissect_tcap_len(asn1, subtree, &def_len, &len);
		tag_subtree = proto_item_add_subtree(tag_item, ett_component);

		dissect_ansi_tcap_re(asn1, tag_subtree);
		break;
	    case ANSI_TC_REJECT :
		tag_item = proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset,
			    asn1->offset - saved_offset, tag, "Reject");
		dissect_tcap_len(asn1, subtree, &def_len, &len);
		tag_subtree = proto_item_add_subtree(tag_item, ett_component);

		dissect_ansi_tcap_reject(asn1, tag_subtree);
		break;
	    case ANSI_TC_INVOKE_N :
		tag_item = proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset,
			    asn1->offset - saved_offset, tag, "Invoke(Not Last)");
		dissect_tcap_len(asn1, subtree, &def_len, &len);
		tag_subtree = proto_item_add_subtree(tag_item, ett_component);

		dissect_ansi_tcap_invoke(asn1, tag_subtree);
		break;
	    case ANSI_TC_RRN :
		tag_item = proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset,
			    asn1->offset - saved_offset, tag, "Return Result(Not Last)");
		dissect_tcap_len(asn1, subtree, &def_len, &len);
		tag_subtree = proto_item_add_subtree(tag_item, ett_component);

		dissect_ansi_tcap_rr(asn1, tag_subtree);
		break;
	    }

	    proto_item_set_len(item, asn1->offset - saved_offset);
	}
    }

    if (!flag)
    {
	/* No sub-dissection occured, treat it as raw data */
	call_dissector(data_handle, next_tvb, g_pinfo, g_tcap_tree);
    }
}

static void
dissect_tcap_next_tvb(ASN1_SCK *asn1, guint len, proto_tree *tree)
{
    tvbuff_t *next_tvb;
    guint saved_offset;
    int ret;
    guint tag;

    if (lock_info_col) col_set_fence(g_pinfo->cinfo, COL_INFO);

    next_tvb = tvb_new_subset(asn1->tvb, asn1->offset, len, len);

    /* process components data */
    if (dissector_try_port(tcap_itu_ssn_dissector_table, g_pinfo->match_port, next_tvb, g_pinfo, g_tcap_tree))
    {
	asn1->offset += len;
    }
    else
    {
	saved_offset = asn1->offset;
	ret = asn1_id_decode1(asn1, &tag);
	asn1->offset = saved_offset;

	switch (tag)
	{
	case TC_INVOKE :
	    dissect_tcap_invoke(asn1, tree);
	    break;
	case TC_RRL :
	    dissect_tcap_rr(asn1, tree, "Return Result(Last) Type Tag");
	    break;
	case TC_RE :
	    dissect_tcap_re(asn1, tree);
	    break;
	case TC_REJECT :
	    dissect_tcap_reject(asn1, tree);
	    break;
	case TC_RRN :
	    /* same definition as RRL */
	    dissect_tcap_rr(asn1, tree, "Return Result(Not Last) Type Tag");
	    break;
	default:
	    /* treat it as raw data */
	    call_dissector(data_handle, next_tvb, g_pinfo, g_tcap_tree);
	    break;
	}
    }
}

static int
dissect_tcap_components(ASN1_SCK *asn1, proto_tree *tcap_tree)
{
    proto_tree *subtree;
    guint saved_offset = 0;
    guint len, next_tvb_len;
    guint tag;
    int ret;
    proto_item *cmp_item;
    guint cmp_start = asn1->offset;
    gboolean def_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0)
    {
	return TC_DS_FAIL;
    }

    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);

    if (ST_ITU_CMP_TAG != tag)
    {
	asn1->offset = saved_offset;
	return TC_DS_FAIL;
    }

    cmp_item = proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Components Portion");
    subtree = proto_item_add_subtree(cmp_item, ett_cmp_portion);

    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset, asn1->offset - saved_offset, tag,
				    "Component Portion Tag");

    dissect_tcap_len(asn1, subtree, &def_len, &len);

    if (def_len)
    {
	proto_item_set_len(cmp_item, (asn1->offset - cmp_start) + len);
    }

    /* call next dissector */

    if (!def_len)
    {
	/*
	 * take remaining length minus the EOC for the indefinite
	 * component length
	 */
	next_tvb_len =
	    tvb_length_remaining(asn1->tvb, asn1->offset) - TC_EOC_LEN;
    }
    else
    {
	next_tvb_len = len;
    }

    /*
     * take length minus the EOC for the indefinite
     * transaction message length
     */
    next_tvb_len -= g_tcap_ends_def_len ? 0 : TC_EOC_LEN;

    dissect_tcap_next_tvb(asn1, next_tvb_len, subtree);

    if (!def_len)
    {
	dissect_tcap_eoc(asn1, subtree);
    }

    proto_item_set_len(cmp_item, asn1->offset - cmp_start);

    return TC_DS_OK;
}

/* dissect dialog portion */
static int
dissect_tcap_dlg_protocol_version(ASN1_SCK *asn1, proto_tree *tcap_tree, proto_item *ti)
{
    guint saved_offset = 0;
    guint len;
    guint tag;
    int ret;
    gboolean def_len;

#define TC_DLG_PROTO_VER_TAG 0x80
    if (check_tcap_tag(asn1, TC_DLG_PROTO_VER_TAG))
    {
	saved_offset = asn1->offset;
	ret = asn1_id_decode1(asn1, &tag);
	proto_tree_add_uint_format(tcap_tree, hf_tcap_tag, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, tag,
	    "Protocol Version Tag: 0x%x", tag);

	dissect_tcap_len(asn1, tcap_tree, &def_len, &len);
	saved_offset = asn1->offset;
	ti =
	    proto_tree_add_bytes(tcap_tree, hf_tcap_bytes, asn1->tvb, saved_offset, len,
		(guchar*)(tvb_get_ptr(asn1->tvb, saved_offset, len)));
	asn1->offset += len;
    }

    return TC_DS_OK;
}

static int
dissect_tcap_dlg_application_context_name(ASN1_SCK *asn1, proto_tree *tcap_tree)
{
    guint saved_offset = 0;
    guint name_len, len, len2;
    guint tag;
    subid_t *oid;
    int ret;
    gboolean def_len;

    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);
    proto_tree_add_uint_format(tcap_tree, hf_tcap_tag, asn1->tvb, saved_offset, asn1->offset - saved_offset, tag,
			    "Application Context Name Tag: 0x%x", tag);

    dissect_tcap_len(asn1, tcap_tree, &def_len, &name_len);

    saved_offset = asn1->offset;
    ret = asn1_oid_decode (asn1, &oid, &len, &len2);
    proto_tree_add_bytes(tcap_tree, hf_tcap_app_con_name, asn1->tvb, saved_offset, len2, tvb_get_ptr(asn1->tvb, saved_offset, len2));
    if (ret == ASN1_ERR_NOERROR) g_free(oid);

    if (!def_len)
    {
	/* for Application Context Name Tag */
	dissect_tcap_eoc(asn1, tcap_tree);
    }

    return TC_DS_OK;
}

static int
dissect_tcap_dlg_result(ASN1_SCK *asn1, proto_tree *tree)
{
    guint tag, rtag_len, itag_len;
    guint saved_offset = 0;
    gint32 value;
    gchar *str;
    gboolean def_len;
    gboolean rtag_def_len;

    tag = -1;
    dissect_tcap_tag(asn1, tree, &tag, "Result Tag");

    dissect_tcap_len(asn1, tree, &rtag_def_len, &rtag_len);

    tag = -1;
    dissect_tcap_tag(asn1, tree, &tag, "Integer Tag");

    dissect_tcap_len(asn1, tree, &def_len, &itag_len);

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, itag_len, &value);

    switch (value)
    {
    case 0x00: str = "Accepted"; break;
    case 0x01: str = "Reject-permanent"; break;
    default: str = "Unknown value"; break;
    }

    proto_tree_add_int_format(tree, hf_tcap_int, asn1->tvb, saved_offset, asn1->offset - saved_offset,
	value, "%s %d", str, value);

    if (!rtag_def_len)
    {
	/* for Result Tag */
	dissect_tcap_eoc(asn1, tree);
    }

    return TC_DS_OK;
}

static int
dissect_tcap_dlg_result_src_diag(ASN1_SCK *asn1, proto_tree *tree)
{
    guint saved_offset = 0;
    guint len, tag;
    gint32 value;
    gboolean user;
    gchar *str;
    gboolean def_len;
    gboolean serv_def_len;
    gboolean diag_def_len;

    tag = -1;
    dissect_tcap_tag(asn1, tree, &tag, "Result Source Diagnostic Tag");

    dissect_tcap_len(asn1, tree, &diag_def_len, &len);

#define TC_DIAG_SERV_USER_TAG 0xa1
#define TC_DIAG_SERV_PROV_TAG 0xa2
    if (check_tcap_tag(asn1, TC_DIAG_SERV_USER_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, tree, &tag, "Dialogue Service User Tag");
	user = TRUE;
    }
    else if (check_tcap_tag(asn1, TC_DIAG_SERV_PROV_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, tree, &tag, "Dialogue Service Provider Tag");
	user = FALSE;
    }
    else
    {
	proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb, asn1->offset, len,
	    "Unknown Result Source Diagnostic");

	asn1->offset += len;
	return(TC_DS_OK);
    }

    dissect_tcap_len(asn1, tree, &serv_def_len, &len);

    tag = -1;
    dissect_tcap_tag(asn1, tree, &tag, "Integer Tag");

    dissect_tcap_len(asn1, tree, &def_len, &len);

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, len, &value);

    if (user)
    {
	switch (value)
	{
	case 0x00: str = "Null"; break;
	case 0x01: str = "No reason given"; break;
	case 0x02: str = "Application Context Name not supplied"; break;
	default: str = "Unknown value"; break;
	}
    }
    else
    {
	switch (value)
	{
	case 0x00: str = "Null"; break;
	case 0x01: str = "No reason given"; break;
	case 0x02: str = "No common dialogue portion"; break;
	default: str = "Unknown value"; break;
	}
    }

    proto_tree_add_int_format(tree, hf_tcap_int, asn1->tvb, saved_offset, asn1->offset - saved_offset,
	value, "%s %d", str, value);

    if (!serv_def_len)
    {
	/* for Dialogue Service User/Provider Tag */
	dissect_tcap_eoc(asn1, tree);
    }

    if (!diag_def_len)
    {
	/* for Result Source Diagnostic Tag */
	dissect_tcap_eoc(asn1, tree);
    }

    return TC_DS_OK;
}

static int
dissect_tcap_dlg_user_info(ASN1_SCK *asn1, proto_tree *tree)
{
    guint tag, len;
    guint saved_offset = 0;
    gboolean def_len;
    gboolean user_info_def_len;

#define TC_USR_INFO_TAG 0xbe
    if (check_tcap_tag(asn1, TC_USR_INFO_TAG))
    {
	tag = -1;
	dissect_tcap_tag(asn1, tree, &tag, "User Info Tag");
	dissect_tcap_len(asn1, tree, &user_info_def_len, &len);

#define TC_EXT_TAG 0x28
	if (check_tcap_tag(asn1, TC_EXT_TAG))
	{
	    saved_offset = asn1->offset;
	    asn1_id_decode1(asn1, &tag);
	    proto_tree_add_uint_format(tree, hf_tcap_length, asn1->tvb, saved_offset, asn1->offset - saved_offset,
		tag, "External Tag: 0x%x", tag);

	    dissect_tcap_len(asn1, tree, &def_len, &len);
	}

	proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb, asn1->offset, len, "Parameter Data");
	asn1->offset += len;

	if (!user_info_def_len)
	{
	    /* for User Information Tag */
	    dissect_tcap_eoc(asn1, tree);
	}
    }

    return TC_DS_OK;
}

static int
dissect_tcap_dlg_req(ASN1_SCK *asn1, proto_tree *tcap_tree)
{
    proto_tree *subtree;
    guint saved_offset = 0;
    guint len;
    guint tag;
    int ret;
    proto_item *req_item;
    guint req_start = asn1->offset;
    gboolean def_len;

    /* dissect dialog portion */
    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);
    req_item = proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Dialogue Request");
    subtree = proto_item_add_subtree(req_item, ett_dlg_req);
    proto_tree_add_uint(subtree, hf_tcap_dlg_type, asn1->tvb, saved_offset, asn1->offset - saved_offset, tag);

    dissect_tcap_len(asn1, subtree, &def_len, &len);

    dissect_tcap_dlg_protocol_version(asn1, subtree, NULL);

    dissect_tcap_dlg_application_context_name(asn1, subtree);

    dissect_tcap_dlg_user_info(asn1, subtree);

    /* decode end of sequence */

    if (!def_len)
    {
	/* for Dialogue Request Tag */
	dissect_tcap_eoc(asn1, subtree);
    }

    proto_item_set_len(req_item, asn1->offset - req_start);

    return TC_DS_OK;
}

static int
dissect_tcap_dlg_rsp(ASN1_SCK *asn1, proto_tree *tcap_tree)
{
    proto_tree *subtree;
    guint saved_offset = 0;
    guint len;
    guint tag;
    int ret;
    proto_item *req_item;
    guint req_start = asn1->offset;
    gboolean def_len;

    /* dissect dialog portion */
    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);
    req_item = proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Dialogue Response");
    subtree = proto_item_add_subtree(req_item, ett_dlg_rsp);
    proto_tree_add_uint(subtree, hf_tcap_dlg_type, asn1->tvb, saved_offset, asn1->offset - saved_offset, tag);

    dissect_tcap_len(asn1, subtree, &def_len, &len);

    dissect_tcap_dlg_protocol_version(asn1, subtree, NULL);

    dissect_tcap_dlg_application_context_name(asn1, subtree);

    /* result */
    dissect_tcap_dlg_result(asn1, subtree);

    /* result source diag */
    dissect_tcap_dlg_result_src_diag(asn1, subtree);

    dissect_tcap_dlg_user_info(asn1, subtree);

    if (!def_len)
    {
	/* for Dialogue Response Tag */
	dissect_tcap_eoc(asn1, subtree);
    }

    proto_item_set_len(req_item, asn1->offset - req_start);

    return TC_DS_OK;
}

static int
dissect_tcap_dlg_abrt(ASN1_SCK *asn1, proto_tree *tree)
{
    proto_tree *subtree;
    guint saved_offset = 0;
    guint len;
    guint tag;
    int ret;
    proto_item *req_item;
    gint32 value;
    gchar *str;
    gboolean def_len, abort_def_len;

    /* dissect dialog pabort portion */
    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);
    req_item = proto_tree_add_none_format(tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Dialogue Abort");
    subtree = proto_item_add_subtree(req_item, ett_dlg_abort );
    proto_tree_add_uint(subtree, hf_tcap_dlg_type, asn1->tvb, saved_offset, asn1->offset - saved_offset, tag);

    dissect_tcap_len(asn1, subtree, &abort_def_len, &len);

    tag = -1;
    dissect_tcap_tag(asn1, subtree, &tag, "Abort Source Tag");
    dissect_tcap_len(asn1, subtree, &def_len, &len);

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, len, &value);

    switch (value)
    {
    case 0x00: str = "Dialogue Service User"; break;
    case 0x01: str = "Dialogue Service Provider"; break;
    default: str = "Unknown value"; break;
    }

    proto_tree_add_int_format(subtree, hf_tcap_int, asn1->tvb, saved_offset, asn1->offset - saved_offset,
	value, "Abort Source: %s %d", str, value);

    dissect_tcap_dlg_user_info(asn1, subtree);

    if (!abort_def_len)
    {
	/* for Dialogue Abort Tag */
	dissect_tcap_eoc(asn1, subtree);
    }

    return TC_DS_OK;
}

static int
dissect_tcap_dialog_portion(ASN1_SCK *asn1, proto_tree *tcap_tree, proto_item *ti)
{
    proto_tree *subtree;
    guint saved_offset = 0;
    guint len;
    guint tag;
    int ret;
    proto_item *dlg_item;
    guint dlg_start = asn1->offset;
    gboolean def_len, ext_tag_def_len, portion_def_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0)
    {
	return TC_DS_FAIL;
    }

    /* dissect dialog portion */
    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);

    /* error handling */
    if (ST_ITU_DLG_TAG != tag)
    {
	asn1->offset = saved_offset;
	return TC_DS_FAIL;
    }

    dlg_item =
	proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb,
	    saved_offset, -1, "Dialogue Portion");

    subtree = proto_item_add_subtree(dlg_item, ett_dlg_portion);

    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, tag, "Dialogue Portion Tag");

    dissect_tcap_len(asn1, subtree, &portion_def_len, &len);

    if (portion_def_len)
    {
	proto_item_set_len(dlg_item, len);
    }

    ext_tag_def_len = FALSE;
    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);
#define TC_EXT_TAG 0x28
    if (TC_EXT_TAG != tag)
    {
	asn1->offset = saved_offset;
    }
    else
    {
	proto_tree_add_uint_format(subtree, hf_tcap_length, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, tag,
	    "External Tag: 0x%x", tag);

	dissect_tcap_len(asn1, subtree, &ext_tag_def_len, &len);
    }

    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);
#define TC_OID_TAG 0x06
    if (TC_OID_TAG != tag)
    {
	asn1->offset = saved_offset;
    }
    else
    {
	proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, tag,
	    "Object Identifier Tag");

	dissect_tcap_len(asn1, subtree, &def_len, &len);

	saved_offset = asn1->offset;
	ti =
	    proto_tree_add_bytes(subtree, hf_tcap_bytes, asn1->tvb, saved_offset, len,
		(guchar*)(tvb_get_ptr(asn1->tvb, saved_offset, len)));

	asn1->offset += len;
    }

    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);

    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, tag,
	"Single-ASN.1-type Tag");

    dissect_tcap_len(asn1, subtree, &def_len, &len);

    proto_item_set_len(dlg_item, asn1->offset - dlg_start);

    /* dialogue PDU */
    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);
    asn1->offset = saved_offset;

    switch(tag)
    {
    case TC_DLG_REQ:
	dissect_tcap_dlg_req(asn1, subtree);
	break;
    case TC_DLG_RSP:
	dissect_tcap_dlg_rsp(asn1, subtree);
	break;
    case TC_DLG_ABRT:
	dissect_tcap_dlg_abrt(asn1, subtree);
	break;
    default:
	break;
    }

    /* decode end of sequence */

    if (!def_len)
    {
	dissect_tcap_eoc(asn1, subtree);
    }

    if (!ext_tag_def_len)
    {
	dissect_tcap_eoc(asn1, subtree);
    }

    if (!portion_def_len)
    {
	dissect_tcap_eoc(asn1, subtree);
    }

    proto_item_set_len(dlg_item, asn1->offset - dlg_start);

    return TC_DS_OK;
}

/* dissect reason */
static int
dissect_tcap_abort_reason(ASN1_SCK *asn1, proto_tree *tcap_tree)
{
    guint saved_offset = 0;
    guint tag, len;
    proto_tree *subtree;
    proto_item *item;
    gint32 value;
    gchar *str = NULL;
    gboolean def_len;

#define TC_PABRT_REASON_TAG 0x4a
    tag = TC_PABRT_REASON_TAG;
    if (check_tcap_tag(asn1, tag))
    {
	saved_offset = asn1->offset;
	item =
	    proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb,
		saved_offset, -1, "PAbort Cause");

	subtree = proto_item_add_subtree(item, ett_reason);

	tag = -1;
	dissect_tcap_tag(asn1, subtree, &tag, "PAbort Cause Tag");
	dissect_tcap_len(asn1, subtree, &def_len, &len);

	proto_item_set_len(item, (asn1->offset - saved_offset) + len);

	saved_offset = asn1->offset;
	asn1_int32_value_decode(asn1, len, &value);

	switch (value)
	{
	case 0x00: str = "Unrecognized Message Type"; break;
	case 0x01: str = "Unrecognized Transaction ID"; break;
	case 0x02: str = "Badly Formatted Transaction Portion"; break;
	case 0x03: str = "Incorrect Transaction Portion"; break;
	case 0x04: str = "Resource Limitation"; break;
	default:
	    str = "Undefined";
	    break;
	}

	proto_tree_add_none_format(subtree, hf_tcap_none, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, "Cause Value %s (%d)",
	    str, value);
    }

    return TC_DS_OK;
}

/* dissect each type of message */

static void
dissect_tcap_unidirectional(ASN1_SCK *asn1, proto_tree *tcap_tree)
{

    dissect_tcap_dialog_portion(asn1, tcap_tree, NULL);

    dissect_tcap_components(asn1, tcap_tree);
}

static void
dissect_tcap_begin(ASN1_SCK *asn1, proto_tree *tcap_tree, proto_item *ti)
{

    dissect_tcap_tid(asn1, tcap_tree, ti, ST_TID_SOURCE);

    dissect_tcap_dialog_portion(asn1, tcap_tree, NULL);

    dissect_tcap_components(asn1, tcap_tree);
}

static void
dissect_tcap_continue(ASN1_SCK *asn1, proto_tree *tcap_tree, proto_item *ti)
{

    dissect_tcap_tid(asn1, tcap_tree, ti, ST_TID_SOURCE);

    dissect_tcap_tid(asn1, tcap_tree, ti, ST_TID_DEST);

    dissect_tcap_dialog_portion(asn1, tcap_tree, NULL);

    dissect_tcap_components(asn1, tcap_tree);

}

static void
dissect_tcap_end(ASN1_SCK *asn1, proto_tree *tcap_tree, proto_item *ti)
{

    dissect_tcap_tid(asn1, tcap_tree, ti, ST_TID_DEST);

    dissect_tcap_dialog_portion(asn1, tcap_tree, NULL);

    dissect_tcap_components(asn1, tcap_tree);
}

static void
dissect_tcap_abort(ASN1_SCK *asn1, proto_tree *tree, proto_item *ti)
{

    dissect_tcap_tid(asn1, tree, ti, ST_TID_DEST);

    dissect_tcap_abort_reason(asn1, tree);

    dissect_tcap_dialog_portion(asn1, tree, NULL);
}

/* Samuel */
static void
dissect_tcap_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tcap_tree)
{
    ASN1_SCK asn1;
    guint msg_type_tag;
    proto_item *ti;
    guint offset = 0;
    guint saved_offset = 0;
    guint len;
    gchar *str = NULL;

    asn1_open(&asn1, tvb, offset);

    asn1_id_decode1(&asn1, &msg_type_tag);

    str = match_strval(msg_type_tag, msg_type_strings);

    if (str == NULL)
    {
	proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1.tvb, offset, -1, "Unknown message type, ignoring");
	return;
    }

    if (check_col(pinfo->cinfo, COL_INFO))
    {
	col_set_str(pinfo->cinfo, COL_INFO, str);
	col_append_str(pinfo->cinfo, COL_INFO, " ");
    }

    proto_tree_add_uint_hidden(tcap_tree, hf_tcap_ssn, asn1.tvb, offset,
	0, pinfo->match_port); /* len -1 is unacceptable */

    ti = proto_tree_add_uint(tcap_tree, hf_tcap_message_type, asn1.tvb, offset, asn1.offset - saved_offset,
	    msg_type_tag);

    dissect_tcap_len(&asn1, tcap_tree, &g_tcap_ends_def_len, &len);

    switch(msg_type_tag)
    {
    case ST_MSG_TYP_UNI:
	dissect_tcap_unidirectional(&asn1, tcap_tree);
	break;
    case ST_MSG_TYP_BGN:
	dissect_tcap_begin(&asn1, tcap_tree, ti);
	break;
    case ST_MSG_TYP_CNT:
	dissect_tcap_continue(&asn1, tcap_tree, ti);
	break;
    case ST_MSG_TYP_END:
	dissect_tcap_end(&asn1, tcap_tree, ti);
	break;
    case ST_MSG_TYP_PABT:
	dissect_tcap_abort(&asn1, tcap_tree, ti);
	break;
    default:
	proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1.tvb, offset, -1,
	    "Message type not handled, ignoring");
	break;
    }

    if (!g_tcap_ends_def_len)
    {
	dissect_tcap_eoc(&asn1, tcap_tree);
    }

    asn1_close(&asn1, &saved_offset);
}

static int
dissect_ansi_tcap_components(ASN1_SCK *asn1, proto_tree *tcap_tree)
{
    proto_tree *subtree;
    guint saved_offset = 0;
    guint len;
    guint tag;
    int ret;
    proto_item *cmp_item;
    guint cmp_start = asn1->offset;
    gboolean def_len;

    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);

    if (ST_ANSI_CMP_TAG != tag)
    {
	asn1->offset = saved_offset;
	return TC_DS_FAIL;
    }

    cmp_item = proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Components Portion");

    subtree = proto_item_add_subtree(cmp_item, ett_cmp_portion);

    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset, asn1->offset - saved_offset, tag,
	"Component Sequence Identifier");

    dissect_tcap_len(asn1, tcap_tree, &def_len, &len);

    /* call next dissector */

    dissect_ansi_tcap_next_tvb(asn1, len, subtree);

    proto_item_set_len(cmp_item, asn1->offset - cmp_start);

    return TC_DS_OK;
}

static int
dissect_ansi_tcap_unidirectional(ASN1_SCK *asn1, proto_tree *tcap_tree)
{
    guint saved_offset = 0;
    guint len;
    guint tag;
    int ret;
    proto_item *trans_item;
    guint trans_start = asn1->offset;
    gboolean def_len;

    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);

    if (ST_ANSI_TID_TAG != tag)
    {
	asn1->offset = saved_offset;
	return TC_DS_FAIL;
    }

    trans_item = proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Transaction Portion");

    dissect_tcap_len(asn1, tcap_tree, &def_len, &len);

    if (len != 0)
    {
	return TC_DS_FAIL;
    }

    proto_item_set_len(trans_item, asn1->offset - trans_start);

    dissect_ansi_tcap_components(asn1, tcap_tree);

    return TC_DS_OK;
}

static int
dissect_ansi_tcap_qwp_qwop(ASN1_SCK *asn1, proto_tree *tcap_tree, proto_item *ti)
{
    proto_tree *subtree;
    guint saved_offset = 0;
    guint len;
    guint tag;
    int ret;
    proto_item *trans_item;
    guint trans_start = asn1->offset;
    guchar *poctets;
    guint32 val;
    gboolean def_len;

    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);

    if (ST_ANSI_TID_TAG != tag)
    {
	asn1->offset = saved_offset;
	return TC_DS_FAIL;
    }

    trans_item = proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Transaction Portion");
    subtree = proto_item_add_subtree(trans_item, ett_dlg_portion);

    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset, asn1->offset - saved_offset, tag,
	"Originating Transaction ID Identifier");

    dissect_tcap_len(asn1, tcap_tree, &def_len, &len);

    if (len != 4)
    {
	return TC_DS_FAIL;
    }

    saved_offset = asn1->offset;
    ret = asn1_string_value_decode(asn1, len, &poctets);
    val = 0;
    memcpy(&val, poctets, len);
    ti = proto_tree_add_uint(subtree, hf_tcap_id, asn1->tvb, saved_offset, asn1->offset - saved_offset, val);
    g_free(poctets);

    if (check_col(g_pinfo->cinfo, COL_INFO))
	col_append_fstr(g_pinfo->cinfo, COL_INFO, "otid(%x) ", val);

    proto_item_set_len(trans_item, asn1->offset - trans_start);

    dissect_ansi_tcap_components(asn1, tcap_tree);

    return TC_DS_OK;
}

static int
dissect_ansi_tcap_abort(ASN1_SCK *asn1, proto_tree *tcap_tree, proto_item *ti)
{
    proto_tree *subtree;
    guint saved_offset = 0;
    guint len;
    guint tag;
    int ret;
    proto_item *trans_item;
    guint trans_start = asn1->offset;
    guchar *poctets;
    guint32 val;
    gint32 value;
    gboolean def_len;
    gchar *str;

    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);

    if (ST_ANSI_TID_TAG != tag)
    {
	asn1->offset = saved_offset;
	return TC_DS_FAIL;
    }

    trans_item =
	proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb,
	saved_offset, -1, "Transaction Portion");

    subtree = proto_item_add_subtree(trans_item, ett_dlg_portion);

    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb,
	saved_offset, asn1->offset - saved_offset, tag,
	"Responding Transaction ID Identifier");

    dissect_tcap_len(asn1, subtree, &def_len, &len);

    if (len != 4)
    {
	return TC_DS_FAIL;
    }

    saved_offset = asn1->offset;
    ret = asn1_string_value_decode(asn1, len, &poctets);

    val = 0;
    memcpy(&val, poctets, len);
    ti = proto_tree_add_uint(subtree, hf_tcap_id, asn1->tvb, saved_offset, asn1->offset - saved_offset, val);
    g_free(poctets);

    if (check_col(g_pinfo->cinfo, COL_INFO))
	col_append_fstr(g_pinfo->cinfo, COL_INFO, "rtid(%x) ", val);

    proto_item_set_len(trans_item, asn1->offset - trans_start);

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0)
    {
	proto_tree_add_text(tcap_tree, asn1->tvb, asn1->offset, -1,
	    "!!! Missing Component Portion !!!");

	return TC_DS_FAIL;
    }

    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);

#define ANSI_TC_PABRT_CAUSE_TAG 0xd7
    if (tag == ANSI_TC_PABRT_CAUSE_TAG)
    {
	trans_item =
	    proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb,
		saved_offset, -1, "P-Abort Portion");

	subtree = proto_item_add_subtree(trans_item, ett_dlg_abort);

	dissect_tcap_len(asn1, subtree, &def_len, &len);

	proto_item_set_len(trans_item, (asn1->offset - saved_offset) + len);

	saved_offset = asn1->offset;
	asn1_int32_value_decode(asn1, len, &value);

	switch (value)
	{
	case 1: str = "Unrecognized Package Type"; break;
	case 2: str = "Incorrect Transaction Portion"; break;
	case 3: str = "Badly Structured Transaction Portion"; break;
	case 4: str = "Unrecognized Transaction ID"; break;
	case 5: str = "Permission to Release"; break;
	case 6: str = "Resource Unavailable"; break;
	default:
	    str = "Undefined";
	    break;
	}

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, "P-Abort Cause Value %s (%d)",
	    str, value);
    }
#define ANSI_TC_UABRT_INFO_TAG 0xd8
    else if (tag == ANSI_TC_UABRT_INFO_TAG)
    {
	trans_item =
	    proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb,
		saved_offset, -1, "U-Abort Portion");

	subtree = proto_item_add_subtree(trans_item, ett_dlg_abort);

	dissect_tcap_len(asn1, subtree, &def_len, &len);
	if (len > 0)
	{
	    dissect_tcap_integer(asn1, subtree, len, "User Abort Information:");
	}
    }

    return TC_DS_OK;
}

static int
dissect_ansi_tcap_rsp(ASN1_SCK *asn1, proto_tree *tcap_tree, proto_item *ti)
{
    proto_tree *subtree;
    guint saved_offset = 0;
    guint len;
    guint tag;
    int ret;
    proto_item *trans_item;
    guint trans_start = asn1->offset;
    guchar *poctets;
    guint32 val;
    gboolean def_len;

    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);

    if (ST_ANSI_TID_TAG != tag)
    {
	asn1->offset = saved_offset;
	return TC_DS_FAIL;
    }

    trans_item = proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Transaction Portion");
    subtree = proto_item_add_subtree(trans_item, ett_dlg_portion);

    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset, asn1->offset - saved_offset, tag,
	"Responding Transaction ID Identifier");

    dissect_tcap_len(asn1, tcap_tree, &def_len, &len);

    if (len != 4)
    {
	return TC_DS_FAIL;
    }

    saved_offset = asn1->offset;
    ret = asn1_string_value_decode(asn1, len, &poctets);
    val = 0;
    memcpy(&val, poctets, len);
    ti = proto_tree_add_uint(subtree, hf_tcap_id, asn1->tvb, saved_offset, asn1->offset - saved_offset, val);
    g_free(poctets);

    if (check_col(g_pinfo->cinfo, COL_INFO))
	col_append_fstr(g_pinfo->cinfo, COL_INFO, "rtid(%x) ", val);

    proto_item_set_len(trans_item, asn1->offset - trans_start);

    dissect_ansi_tcap_components(asn1, tcap_tree);

    return TC_DS_OK;
}

static int
dissect_ansi_tcap_cwp_cwop(ASN1_SCK *asn1, proto_tree *tcap_tree, proto_item *ti)
{
    proto_tree *subtree;
    guint saved_offset = 0;
    guint len;
    guint tag;
    int ret;
    proto_item *trans_item;
    guint trans_start = asn1->offset;
    guchar *poctets;
    guint32 val;
    gboolean def_len;

    saved_offset = asn1->offset;
    ret = asn1_id_decode1(asn1, &tag);

    if (ST_ANSI_TID_TAG != tag)
    {
	asn1->offset = saved_offset;
	return TC_DS_FAIL;
    }

    trans_item = proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1->tvb, saved_offset, -1, "Transaction Portion");
    subtree = proto_item_add_subtree(trans_item, ett_dlg_portion);

    proto_tree_add_uint_format(subtree, hf_tcap_tag, asn1->tvb, saved_offset, asn1->offset - saved_offset, tag,
	"Transaction ID Identifier");

    dissect_tcap_len(asn1, tcap_tree, &def_len, &len);

    if (len != 8)
    {
	return TC_DS_FAIL;
    }

    saved_offset = asn1->offset;
    ret = asn1_string_value_decode(asn1, 4, &poctets);
    val = 0;
    memcpy(&val, poctets, 4);
    ti = proto_tree_add_uint(subtree, hf_tcap_id, asn1->tvb, saved_offset, asn1->offset - saved_offset, val);
    g_free(poctets);

    if (check_col(g_pinfo->cinfo, COL_INFO))
	col_append_fstr(g_pinfo->cinfo, COL_INFO, "otid(%x) ", val);

    saved_offset = asn1->offset;
    ret = asn1_string_value_decode(asn1, 4, &poctets);
    val = 0;
    memcpy(&val, poctets, 4);
    ti = proto_tree_add_uint(subtree, hf_tcap_id, asn1->tvb, saved_offset, asn1->offset - saved_offset, val);
    g_free(poctets);

    if (check_col(g_pinfo->cinfo, COL_INFO))
	col_append_fstr(g_pinfo->cinfo, COL_INFO, "rtid(%x) ", val);

    proto_item_set_len(trans_item, asn1->offset - trans_start);

    dissect_ansi_tcap_components(asn1, tcap_tree);

    return TC_DS_OK;
}

static void
dissect_ansi_tcap_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tcap_tree)
{
    ASN1_SCK asn1;
    guint msg_type_tag;
    proto_item *ti;
    guint offset = 0;
    guint saved_offset = 0;
    guint len;
    gchar *str = NULL;
    gboolean def_len;

    asn1_open(&asn1, tvb, offset);

    asn1_id_decode1(&asn1, &msg_type_tag);

    str = match_strval(msg_type_tag, ansi_msg_type_strings);

    if (str == NULL)
    {
	proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1.tvb, offset, -1, "Unknown message type, ignoring");
	return;
    }

    if (check_col(pinfo->cinfo, COL_INFO))
    {
	col_set_str(pinfo->cinfo, COL_INFO, str);
	col_append_str(pinfo->cinfo, COL_INFO, " ");
    }

    proto_tree_add_uint_hidden(tcap_tree, hf_tcap_ssn, asn1.tvb, offset,
	0, pinfo->match_port); /* len -1 is unacceptable */

    ti = proto_tree_add_uint(tcap_tree, hf_ansi_tcap_message_type, asn1.tvb, offset, asn1.offset - saved_offset,
	    msg_type_tag);

    dissect_tcap_len(&asn1, tcap_tree, &def_len, &len);

    switch(msg_type_tag)
    {
    case ANSI_ST_MSG_TYP_UNI:
	dissect_ansi_tcap_unidirectional(&asn1, tcap_tree);
	break;
    case ANSI_ST_MSG_TYP_QWP:
	dissect_ansi_tcap_qwp_qwop(&asn1, tcap_tree, ti);
	break;
    case ANSI_ST_MSG_TYP_QWOP:
	dissect_ansi_tcap_qwp_qwop(&asn1, tcap_tree, ti);
	break;
    case ANSI_ST_MSG_TYP_RSP:
	dissect_ansi_tcap_rsp(&asn1, tcap_tree, ti);
	break;
    case ANSI_ST_MSG_TYP_CWP:
	dissect_ansi_tcap_cwp_cwop(&asn1, tcap_tree, ti);
	break;
    case ANSI_ST_MSG_TYP_CWOP:
	dissect_ansi_tcap_cwp_cwop(&asn1, tcap_tree, ti);
	break;
    case ANSI_ST_MSG_TYP_ABT:
	dissect_ansi_tcap_abort(&asn1, tcap_tree, ti);
	break;
    default:
	proto_tree_add_none_format(tcap_tree, hf_tcap_none, asn1.tvb, offset, -1,
	    "Message type not handled, ignoring");
	break;
    }

    asn1_close(&asn1, &saved_offset);
}

/* Code to actually dissect the packets */
static void
dissect_tcap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *tcap_tree;

    g_pinfo = pinfo;

    if (check_col(pinfo->cinfo, COL_PROTOCOL))
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TCAP");

    /* In the interest of speed, if "tree" is NULL, don't do any
     * work not necessary to generate protocol tree items.
     */
    if (tree)
    {
	ti = proto_tree_add_item(tree, proto_tcap, tvb, 0, -1, FALSE);
	tcap_tree = proto_item_add_subtree(ti, ett_tcap);
	g_tcap_tree = tree;

	if (tcap_standard == ITU_TCAP_STANDARD)
	{
	    dissect_tcap_message(tvb, pinfo, tcap_tree);
	}
	else
	{
	    dissect_ansi_tcap_message(tvb, pinfo, tcap_tree);
	}
    }
}


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/
void
proto_register_tcap(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
	/*{ &hf_tcap_FIELDABBREV,
		{ "FIELDNAME",           "PROTOABBREV.FIELDABBREV",
		FIELDTYPE, FIELDBASE, FIELDCONVERT, BITMASK,
		"FIELDDESCR" }
	},*/
	{ &hf_tcap_tag,
		{ "Tag",           "tcap.msgtype",
		FT_UINT8, BASE_HEX, NULL, 0,
		"", HFILL }
	},
	{ &hf_tcap_length,
		{ "Length", "tcap.len",
		FT_UINT8, BASE_HEX, NULL, 0,
		"", HFILL }
	},
	{ &hf_tcap_id,
		{ "Value", "tcap.id",
		FT_UINT8, BASE_HEX, NULL, 0,
		"", HFILL }
	},
	{ &hf_tcap_message_type,
		{ "Message Type", "tcap.msgtype",
		FT_UINT8, BASE_HEX, VALS(msg_type_strings), 0,
		"", HFILL }
	},
	{ &hf_ansi_tcap_message_type,
		{ "Message Type", "tcap.msgtype",
		FT_UINT8, BASE_HEX, VALS(ansi_msg_type_strings), 0,
		"", HFILL }
	},
	{ &hf_tcap_none,
		{ "Sub tree", "tcap.none",
		FT_NONE, 0, 0, 0,
		"", HFILL }
	},
	{ &hf_tcap_tid,
		{ "Transaction Id", "tcap.tid",
		FT_UINT32, BASE_DEC, VALS(tid_strings), 0,
		"", HFILL }
	},
	{ &hf_tcap_ssn,
		{ "Called or Calling SubSystem Number", "tcap.ssn",
		FT_UINT8, BASE_DEC, 0x0, 0x0,
		"", HFILL }
	},
	{ &hf_tcap_dlg_type,
		{ "Dialogue Type", "tcap.dlgtype",
		FT_UINT8, BASE_HEX, VALS(dlg_type_strings), 0,
		"", HFILL }
	},
	{ &hf_tcap_app_con_name,
		{ "Application Context Name", "tcap.dlg.appconname",
		FT_BYTES, BASE_HEX, 0, 0,
		"", HFILL }
	},
	{ &hf_tcap_bytes,
		{ "Binary Data", "tcap.data",
		FT_BYTES, BASE_HEX, 0, 0,
		"", HFILL }
	},
	{ &hf_tcap_int,
		{ "Integer Data", "tcap.data",
		FT_INT32, BASE_DEC, 0, 0,
		"", HFILL }
	},
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
	&ett_tcap,
	&ett_otid,
	&ett_dtid,
	&ett_dlg_portion,
	&ett_cmp_portion,
	&ett_reason,
	&ett_dlg_req,
	&ett_dlg_rsp,
	&ett_dlg_abort,
	&ett_component,
	&ett_error,
	&ett_problem,
	&ett_params,
	&ett_param,
    };

    static enum_val_t tcap_options[] = {
	{ "ITU",  ITU_TCAP_STANDARD },
	{ "ANSI", ANSI_TCAP_STANDARD },
	{ NULL, 0 }
    };

    module_t *tcap_module;

/* Register the protocol name and description */
    proto_tcap = proto_register_protocol("Transaction Capabilities Application Part",
	"TCAP", "tcap");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_tcap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    tcap_module = prefs_register_protocol(proto_tcap, NULL);

    prefs_register_enum_preference(tcap_module, "standard", "TCAP standard",
	"The SS7 standard used in TCAP packets",
	(gint *)&tcap_standard, tcap_options, FALSE);

    prefs_register_bool_preference(tcap_module, "lock_info_col", "Lock Info column",
	"Always show TCAP in Info column",
	&lock_info_col);

    /* we will fake a ssn subfield which has the same value obtained from sccp */
    tcap_itu_ssn_dissector_table = register_dissector_table("tcap.itu_ssn", "ITU TCAP SSN", FT_UINT8, BASE_DEC);
    tcap_ansi_ssn_dissector_table = register_dissector_table("tcap.ansi_ssn", "ANSI TCAP SSN", FT_UINT8, BASE_DEC);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_tcap(void)
{
    dissector_handle_t tcap_handle;

    tcap_handle = create_dissector_handle(dissect_tcap,
	proto_tcap);

    dissector_add("sccp.ssn", 5, tcap_handle); /* MAP*/
    dissector_add("sccp.ssn", 6, tcap_handle); /* HLR*/
    dissector_add("sccp.ssn", 7, tcap_handle); /* VLR */
    dissector_add("sccp.ssn", 8, tcap_handle); /* MSC */
    dissector_add("sccp.ssn", 9, tcap_handle); /* EIR */
    dissector_add("sccp.ssn", 10, tcap_handle); /* EIR */
    dissector_add("sccp.ssn", 11, tcap_handle); /* SMS/MC */
    dissector_add("sccp.ssn", 12, tcap_handle); /* IS41 OTAF */

    dissector_add("sua.ssn", 5, tcap_handle); /* MAP*/
    dissector_add("sua.ssn", 6, tcap_handle); /* HLR*/
    dissector_add("sua.ssn", 7, tcap_handle); /* VLR */
    dissector_add("sua.ssn", 8, tcap_handle); /* MSC */
    dissector_add("sua.ssn", 9, tcap_handle); /* EIR */
    dissector_add("sua.ssn", 10, tcap_handle); /* EIR */
    dissector_add("sua.ssn", 11, tcap_handle); /* SMS/MC */
    dissector_add("sua.ssn", 12, tcap_handle); /* IS41 OTAF */

    data_handle = find_dissector("data");
}
