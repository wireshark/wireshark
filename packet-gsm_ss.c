/* packet-gsm_ss.c
 * Routines for GSM Supplementary Services dissection
 *
 * NOTE:
 *	Routines are shared by GSM MAP/GSM A dissectors.
 *	This file provides SHARED routines and is NOT a
 *	standalone dissector.
 *
 * Copyright 2004, Michael Lum <mlum [AT] telostech.com>
 * In association with Telos Technology Inc.
 *
 * Title		3GPP			Other
 *
 *   Reference [1]
 *   Mobile radio Layer 3 supplementary service specification;
 *   Formats and coding
 *   (3GPP TS 24.080 version 4.3.0 Release 4)
 *
 * Michael Lum <mlum [AT] telostech.com>,
 * Created (2004).
 *
 * $Id: packet-gsm_ss.c,v 1.1 2004/03/19 07:54:57 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-gsm_map.c (where "WHATEVER_FILE_YOU_USED"
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

#include "epan/packet.h"
#include "tap.h"
#include "asn1.h"

#include "packet-tcap.h"
#include "packet-gsm_ss.h"


const value_string gsm_ss_opr_code_strings[] = {
    { 10,	"RegisterSS" },
    { 11,	"EraseSS" },
    { 12,	"ActivateSS" },
    { 13,	"DeactivateSS" },
    { 14,	"InterrogateSS" },
    { 16,	"NotifySS" },
    { 17,	"RegisterPassword" },
    { 18,	"GetPassword" },
    { 19,	"ProcessUnstructuredSS-Data" },
    { 38,	"ForwardCheckSS-Indication" },
    { 59,	"ProcessUnstructuredSS-Request" },
    { 60,	"UnstructuredSS-Request" },
    { 61,	"UnstructuredSS-Notify" },
    { 77,	"EraseCC-Entry" },
    { 119,	"AccessRegisterCCEntry" },
    { 120,	"ForwardCUG-Info" },
    { 121,	"SplitMPTY" },
    { 122,	"RetrieveMPTY" },
    { 123,	"HoldMPTY" },
    { 124,	"BuildMPTY" },
    { 125,	"ForwardChargeAdvice" },
    { 126,	"ExplicitCT" },
    { 0, NULL }
};


/* never initialize in field array */
static int hf_null = -1;
#define	HF_NULL		&hf_null

gint gsm_ss_ett_sequence = -1;
gint gsm_ss_ett_param = -1;


/* GENERIC HELPER FUNCTIONS */

static gchar *
my_match_strval(guint32 val, const value_string *vs, gint *idx)
{
    gint	i = 0;

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

/* PARAMETER dissection */

static void
param_ssCode(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field)
{
    guint	saved_offset;
    gint32	value;
    gchar	*str = NULL;

    hf_field = hf_field;

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, len, &value);

    switch (value)
    {
    case 0x00:
	str = "allSS - all SS";
	break;

    case 0x10:
	str = "allLineIdentificationSS - all line identification SS";
	break;

    case 0x11:
	str = "clip - calling line identification presentation";
	break;

    case 0x12:
	str = "clir - calling line identification restriction";
	break;

    case 0x13:
	str = "colp - connected line identification presentation";
	break;

    case 0x14:
	str = "colr - connected line identification restriction";
	break;

    case 0x15:
	str = "mci - malicious call identification";
	break;

    case 0x18:
	str = "allNameIdentificationSS - all name indentification SS";
	break;

    case 0x19:
	str = "cnap - calling name presentation";
	break;

    case 0x20:
	str = "allForwardingSS - all forwarding SS";
	break;

    case 0x21:
	str = "cfu - call forwarding unconditional";
	break;

    case 0x28:
	str = "allCondForwardingSS - all conditional forwarding SS";
	break;

    case 0x29:
	str = "cfb - call forwarding busy";
	break;

    case 0x2a:
	str = "cfnry - call forwarding on no reply";
	break;

    case 0x2b:
	str = "cfnrc - call forwarding on mobile subscriber not reachable";
	break;

    case 0x24:
	str = "cd - call deflection";
	break;

    case 0x30:
	str = "allCallOfferingSS - all call offering SS includes also all forwarding SS";
	break;

    case 0x31:
	str = "ect - explicit call transfer";
	break;

    case 0x32:
	str = "mah - mobile access hunting";
	break;

    case 0x40:
	str = "allCallCompletionSS - all Call completion SS";
	break;

    case 0x41:
	str = "cw - call waiting";
	break;

    case 0x42:
	str = "hold - call hold";
	break;

    case 0x43:
	str = "ccbs-A - completion of call to busy subscribers, originating side";
	break;

    case 0x44:
	str = "ccbs-B - completion of call to busy subscribers, destination side";
	break;

    case 0x45:
	str = "mc - multicall";
	break;

    case 0x50:
	str = "allMultiPartySS - all multiparty SS";
	break;

    case 0x51:
	str = "multiPTY - multiparty";
	break;

    case 0x60:
	str = "allCommunityOfInterestSS - all community of interest SS";
	break;

    case 0x61:
	str = "cug - closed user group";
	break;

    case 0x70:
	str = "allChargingSS - all charging SS";
	break;

    case 0x71:
	str = "aoci - advice of charge information";
	break;

    case 0x72:
	str = "aocc - advice of charge charging";
	break;

    case 0x80:
	str = "allAdditionalInfoTransferSS - all additional information transfer SS";
	break;

    case 0x81:
	str = "uus1 - UUS1 user-to-user signalling";
	break;

    case 0x82:
	str = "uus2 - UUS2 user-to-user signalling";
	break;

    case 0x83:
	str = "uus3 - UUS3 user-to-user signalling";
	break;

    case 0x90:
	str = "allBarringSS - all barring SS";
	break;

    case 0x91:
	str = "barringOfOutgoingCalls";
	break;

    case 0x92:
	str = "baoc - barring of all outgoing calls";
	break;

    case 0x93:
	str = "boic - barring of outgoing international calls";
	break;

    case 0x94:
	str = "boicExHC - barring of outgoing international calls except those directed to the home PLMN";
	break;

    case 0x99:
	str = "barringOfIncomingCalls";
	break;

    case 0x9a:
	str = "baic - barring of all incoming calls";
	break;

    case 0x9b:
	str = "bicRoam - barring of incoming calls when roaming outside home PLMN Country";
	break;

    case 0xf0:
	str = "allPLMN-specificSS";
	break;

    case 0xa0:
	str = "allCallPrioritySS - all call priority SS";
	break;

    case 0xa1:
	str = "emlpp - enhanced Multilevel Precedence Pre-emption (EMLPP) service";
	break;

    case 0xb0:
	str = "allLCSPrivacyException - all LCS Privacy Exception Classes";
	break;

    case 0xb1:
	str = "universal - allow location by any LCS client";
	break;

    case 0xb2:
	str = "callrelated - allow location by any value added LCS client to which a call is established from the target MS";
	break;

    case 0xb3:
	str = "callunrelated - allow location by designated external value added LCS clients";
	break;

    case 0xb4:
	str = "plmnoperator - allow location by designated PLMN operator LCS clients";
	break;

    case 0xc0:
	str = "allMOLR-SS - all Mobile Originating Location Request Classes";
	break;

    case 0xc1:
	str = "basicSelfLocation - allow an MS to request its own location";
	break;

    case 0xc2:
	str = "autonomousSelfLocation - allow an MS to perform self location without interaction with the PLMN for a predetermined period of time";
	break;

    case 0xc3:
	str = "transferToThirdParty - allow an MS to request transfer of its location to another LCS client";
	break;

    default:
	/*
	 * XXX
	 */
	str = "reserved for future use";
	break;
    }

    proto_tree_add_text(tree, asn1->tvb, saved_offset, len, str);
}

/*
 * See GSM 03.11
 */
static void
param_ssStatus(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field)
{
    guint	saved_offset;
    gint32	value;
    char	bigbuf[1024];

    hf_field = hf_field;

    saved_offset = asn1->offset;
    asn1_int32_value_decode(asn1, len, &value);

    other_decode_bitfield_value(bigbuf, value, 0xf0, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  Unused",
	bigbuf);

    /*
     * Q bit is valid only if A bit is "Active"
     */
    other_decode_bitfield_value(bigbuf, value, 0x08, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  Q bit: %s",
	bigbuf,
	(value & 0x01) ?
	    ((value & 0x08) ? "Quiescent" : "Operative") : "N/A");

    other_decode_bitfield_value(bigbuf, value, 0x04, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  P bit: %sProvisioned",
	bigbuf,
	(value & 0x04) ? "" : "Not ");

    other_decode_bitfield_value(bigbuf, value, 0x02, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  R bit: %sRegistered",
	bigbuf,
	(value & 0x02) ? "" : "Not ");

    other_decode_bitfield_value(bigbuf, value, 0x01, 8);
    proto_tree_add_text(tree, asn1->tvb,
	saved_offset, 1,
	"%s :  A bit: %sActive",
	bigbuf,
	(value & 0x01) ? "" : "Not ");
}


typedef enum
{
    GSM_SS_P_SS_CODE,			/* SS-Code */
    GSM_SS_P_SS_STATUS,			/* SS-Status */
    GSM_SS_P_NONE			/* NONE */
}
param_idx_t;

#define	NUM_PARAM_1 (GSM_SS_P_NONE+1)
static gint ett_param_1[NUM_PARAM_1];
static void (*param_1_fcn[])(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field) = {
    param_ssCode,			/* SS-Code */
    param_ssStatus,			/* SS-Status */
    NULL				/* NONE */
};

static int *param_1_hf[] = {
    HF_NULL,				/* SS-Code */
    HF_NULL,				/* SS-Status */
    NULL				/* NONE */
};

#define	GSM_SS_START_SUBTREE(_Gtree, _Gsaved_offset, _Gtag, _Gstr1, _Gett, _Gdef_len_p, _Glen_p, _Gsubtree_p) \
    { \
	guint		_len_offset; \
	proto_item	*_item; \
 \
	_len_offset = asn1->offset; \
	asn1_length_decode(asn1, _Gdef_len_p, _Glen_p); \
 \
	_item = \
	    proto_tree_add_text(_Gtree, asn1->tvb, _Gsaved_offset, -1, _Gstr1); \
 \
	_Gsubtree_p = proto_item_add_subtree(_item, _Gett); \
 \
	proto_tree_add_text(_Gsubtree_p, asn1->tvb, \
	    _Gsaved_offset, _len_offset - _Gsaved_offset, "Tag: 0x%02x", _Gtag); \
 \
	if (*_Gdef_len_p) \
	{ \
	    proto_tree_add_text(_Gsubtree_p, asn1->tvb, \
		_len_offset, asn1->offset - _len_offset, "Length: %d", *_Glen_p); \
	} \
	else \
	{ \
	    proto_tree_add_text(_Gsubtree_p, asn1->tvb, \
		_len_offset, asn1->offset - _len_offset, "Length: Indefinite"); \
 \
	    *_Glen_p = tcap_find_eoc(asn1); \
	} \
 \
	proto_item_set_len(_item, (asn1->offset - _Gsaved_offset) + *_Glen_p + \
	    (*_Gdef_len_p ? 0 : TCAP_EOC_LEN)); \
    }


#define	GSM_SS_PARAM_DISPLAY(Gtree, Goffset, Gtag, Ga1, Ga2) \
    { \
	gint		_ett_param_idx; \
	guint		_len; \
	void		(*_param_fcn)(ASN1_SCK *asn1, proto_tree *tree, guint len, int hf_field) = NULL; \
	int		*_param_hf = NULL; \
	proto_tree	*_subtree; \
	gboolean	_def_len; \
 \
	if (Ga1 == GSM_SS_P_NONE) \
	{ \
	    _ett_param_idx = gsm_ss_ett_param; \
	    _param_fcn = NULL; \
	    _param_hf = HF_NULL; \
	} \
	else \
	{ \
	    _ett_param_idx = ett_param_1[Ga1]; \
	    _param_fcn = param_1_fcn[Ga1]; \
	    _param_hf = param_1_hf[Ga1]; \
	} \
 \
	GSM_SS_START_SUBTREE(Gtree, Goffset, Gtag, Ga2, _ett_param_idx, &_def_len, &_len, _subtree); \
 \
	if (_len > 0) \
	{ \
	    if (Ga1 == GSM_SS_P_NONE || _param_fcn == NULL) \
	    { \
		proto_tree_add_text(_subtree, asn1->tvb, \
		    asn1->offset, _len, "Parameter Data"); \
 \
		asn1->offset += _len; \
	    } \
	    else \
	    { \
		(*_param_fcn)(asn1, _subtree, _len, *_param_hf); \
	    } \
	} \
 \
	if (!_def_len) \
	{ \
	    guint	_saved_offset; \
 \
	    _saved_offset = asn1->offset; \
	    asn1_eoc_decode(asn1, -1); \
 \
	    proto_tree_add_text(Gtree, asn1->tvb, \
		_saved_offset, asn1->offset - _saved_offset, "End of Contents"); \
	} \
    }


static void
op_generic_ss(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	orig_offset, saved_offset, len_offset;
    guint	tag, len;
    gboolean	def_len = FALSE;
    proto_item	*item;
    proto_tree	*subtree;

    orig_offset = asn1->offset;

    while ((tvb_length_remaining(asn1->tvb, asn1->offset) > 0) &&
	(!tcap_check_tag(asn1, 0)))
    {
	if ((exp_len != 0) &&
	    ((asn1->offset - orig_offset) >= exp_len))
	{
	    break;
	}

	saved_offset = asn1->offset;
	asn1_id_decode1(asn1, &tag);

	if (TCAP_CONSTRUCTOR(tag))
	{
	    GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Sequence",
		gsm_ss_ett_sequence,
		&def_len, &len, subtree);

	    op_generic_ss(asn1, subtree, len);

	    if (!def_len)
	    {
		saved_offset = asn1->offset;
		asn1_eoc_decode(asn1, -1);

		proto_tree_add_text(subtree, asn1->tvb,
		    saved_offset, asn1->offset - saved_offset, "End of Contents");
	    }
	    continue;
	}

	len_offset = asn1->offset;
	asn1_length_decode(asn1, &def_len, &len);

	if (!def_len)
	{
	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, len_offset - saved_offset,
		"Tag: 0x%02x", tag);

	    proto_tree_add_text(tree, asn1->tvb,
		len_offset, asn1->offset - len_offset, "Length: Indefinite");

	    len = tcap_find_eoc(asn1);

	    op_generic_ss(asn1, tree, len);

	    saved_offset = asn1->offset;
	    asn1_eoc_decode(asn1, -1);

	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, asn1->offset - saved_offset, "End of Contents");
	    continue;
	}

	item =
	    proto_tree_add_text(tree, asn1->tvb,
		saved_offset, (asn1->offset - saved_offset) + len, "Parameter");

	subtree = proto_item_add_subtree(item, gsm_ss_ett_param);

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, len_offset - saved_offset,
	    "Tag: 0x%02x", tag);

	proto_tree_add_text(subtree, asn1->tvb,
	    len_offset, asn1->offset - len_offset, "Length: %d", len);

	if (len > 0)
	{
	    proto_tree_add_text(subtree, asn1->tvb,
		asn1->offset, len, "Parameter Data");

	    asn1->offset += len;
	}
    }
}

static void
op_interrogate_ss(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset, start_offset;
    guint	tag, len;
    gboolean	def_len = FALSE;
    proto_tree	*subtree;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    if (TCAP_CONSTRUCTOR(tag) == FALSE)
    {
	/*
	 * Hmmm, unexpected
	 */
	return;
    }

    GSM_SS_START_SUBTREE(tree, saved_offset, tag, "Sequence",
	gsm_ss_ett_sequence,
	&def_len, &len, subtree);

    start_offset = asn1->offset;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    GSM_SS_PARAM_DISPLAY(subtree, saved_offset, tag, GSM_SS_P_SS_CODE, "SS-Code");

    op_generic_ss(asn1, subtree, len - (asn1->offset - start_offset));

    if (!def_len)
    {
	saved_offset = asn1->offset;
	asn1_eoc_decode(asn1, -1);

	proto_tree_add_text(subtree, asn1->tvb,
	    saved_offset, asn1->offset - saved_offset, "End of Contents");
    }
}

static void
op_interrogate_ss_rr(ASN1_SCK *asn1, proto_tree *tree, guint exp_len)
{
    guint	saved_offset;
    guint	tag;

    exp_len = exp_len;

    if (tvb_length_remaining(asn1->tvb, asn1->offset) <= 0) return;

    saved_offset = asn1->offset;
    asn1_id_decode1(asn1, &tag);

    switch (tag)
    {
    case 0x80:	/* SS-Status */
	GSM_SS_PARAM_DISPLAY(tree, saved_offset, tag, GSM_SS_P_SS_STATUS, "SS-Status");
	return;

    case 0x82:	/* BasicServiceGroupList */
	/* FALLTHRU */
    case 0x83:	/* ForwardingFeatureList */
	/* FALLTHRU */

    case 0x84:	/* GenericServiceInfo */
	/*
	 * XXX
	 * needs implementing, let "generic" parameter dissector handle it for now
	 */
	break;

    default:
	/* do nothing - unexpected tag */
	break;
    }

    op_generic_ss(asn1, tree, 0);
}

#define	GSM_SS_NUM_OP (sizeof(gsm_ss_opr_code_strings)/sizeof(value_string))
static void (*op_fcn[])(ASN1_SCK *asn1, proto_tree *tree, guint exp_len) = {
    NULL,	/* RegisterSS */
    NULL,	/* EraseSS */
    NULL,	/* ActivateSS */
    NULL,	/* DeactivateSS */
    op_interrogate_ss,	/* InterrogateSS */
    NULL,	/* NotifySS */
    NULL,	/* RegisterPassword */
    NULL,	/* GetPassword */
    NULL,	/* ProcessUnstructuredSS-Data */
    NULL,	/* ForwardCheckSS-Indication */
    NULL,	/* ProcessUnstructuredSS-Request */
    NULL,	/* UnstructuredSS-Request */
    NULL,	/* UnstructuredSS-Notify */
    NULL,	/* EraseCC-Entry */
    NULL,	/* AccessRegisterCCEntry */
    NULL,	/* ForwardCUG-Info */
    NULL,	/* SplitMPTY */
    NULL,	/* RetrieveMPTY */
    NULL,	/* HoldMPTY */
    NULL,	/* BuildMPTY */
    NULL,	/* ForwardChargeAdvice */
    NULL,	/* ExplicitCT */

    NULL	/* NONE */
};

static void (*op_fcn_rr[])(ASN1_SCK *asn1, proto_tree *tree, guint exp_len) = {
    NULL,	/* RegisterSS */
    NULL,	/* EraseSS */
    NULL,	/* ActivateSS */
    NULL,	/* DeactivateSS */
    op_interrogate_ss_rr,	/* InterrogateSS */
    NULL,	/* NotifySS */
    NULL,	/* RegisterPassword */
    NULL,	/* GetPassword */
    NULL,	/* ProcessUnstructuredSS-Data */
    NULL,	/* ForwardCheckSS-Indication */
    NULL,	/* ProcessUnstructuredSS-Request */
    NULL,	/* UnstructuredSS-Request */
    NULL,	/* UnstructuredSS-Notify */
    NULL,	/* EraseCC-Entry */
    NULL,	/* AccessRegisterCCEntry */
    NULL,	/* ForwardCUG-Info */
    NULL,	/* SplitMPTY */
    NULL,	/* RetrieveMPTY */
    NULL,	/* HoldMPTY */
    NULL,	/* BuildMPTY */
    NULL,	/* ForwardChargeAdvice */
    NULL,	/* ExplicitCT */

    NULL	/* NONE */
};

void
gsm_ss_dissect(ASN1_SCK *asn1, proto_tree *tree, guint exp_len,
    guint opr_code, guint comp_type_tag)
{
    void (*dissect_fcn)(ASN1_SCK *asn1, proto_tree *tree, guint exp_len);
    gchar	*str;
    gint	op_idx;


    dissect_fcn = NULL;

    str = my_match_strval(opr_code, gsm_ss_opr_code_strings, &op_idx);

    if (str != NULL)
    {
	switch (comp_type_tag)
	{
	case TCAP_COMP_INVOKE:
	    dissect_fcn = op_fcn[op_idx];
	    break;

	case TCAP_COMP_RRL:
	    dissect_fcn = op_fcn_rr[op_idx];
	    break;

	case TCAP_COMP_RE:
	    /* XXX */
	    break;

	default:
	    /*
	     * no parameters should be present in the component types
	     * ignore
	     */
	    return;
	}
    }

    if (dissect_fcn == NULL)
    {
	op_generic_ss(asn1, tree, exp_len);
    }
    else
    {
	(*dissect_fcn)(asn1, tree, exp_len);
    }
}
