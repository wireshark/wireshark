/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-rtse.c                                                              */
/* ../../tools/asn2wrs.py -b -e -p rtse -c ./rtse.cnf -s ./packet-rtse-template -D . rtse.asn */

/* Input file: packet-rtse-template.c */

#line 1 "../../asn1/rtse/packet-rtse-template.c"
/* packet-rtse_asn1.c
 * Routines for RTSE packet dissection
 * Graeme Lunt 2005
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/prefs.h>
#include <epan/reassemble.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-pres.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"

#define PNAME  "X.228 OSI Reliable Transfer Service"
#define PSNAME "RTSE"
#define PFNAME "rtse"

/* Initialize the protocol and registered fields */
static int proto_rtse = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;

static gboolean open_request=FALSE;
static guint32 app_proto=0;

static proto_tree *top_tree=NULL;

/* Preferences */
static gboolean rtse_reassemble = TRUE;


/*--- Included file: packet-rtse-hf.c ---*/
#line 1 "../../asn1/rtse/packet-rtse-hf.c"
static int hf_rtse_rtorq_apdu = -1;               /* RTORQapdu */
static int hf_rtse_rtoac_apdu = -1;               /* RTOACapdu */
static int hf_rtse_rtorj_apdu = -1;               /* RTORJapdu */
static int hf_rtse_rttp_apdu = -1;                /* RTTPapdu */
static int hf_rtse_rttr_apdu = -1;                /* RTTRapdu */
static int hf_rtse_rtab_apdu = -1;                /* RTABapdu */
static int hf_rtse_checkpointSize = -1;           /* INTEGER */
static int hf_rtse_windowSize = -1;               /* INTEGER */
static int hf_rtse_dialogueMode = -1;             /* T_dialogueMode */
static int hf_rtse_connectionDataRQ = -1;         /* ConnectionData */
static int hf_rtse_applicationProtocol = -1;      /* T_applicationProtocol */
static int hf_rtse_connectionDataAC = -1;         /* ConnectionData */
static int hf_rtse_refuseReason = -1;             /* RefuseReason */
static int hf_rtse_userDataRJ = -1;               /* T_userDataRJ */
static int hf_rtse_abortReason = -1;              /* AbortReason */
static int hf_rtse_reflectedParameter = -1;       /* BIT_STRING */
static int hf_rtse_userdataAB = -1;               /* T_userdataAB */
static int hf_rtse_open = -1;                     /* T_open */
static int hf_rtse_recover = -1;                  /* SessionConnectionIdentifier */
static int hf_rtse_callingSSuserReference = -1;   /* CallingSSuserReference */
static int hf_rtse_commonReference = -1;          /* CommonReference */
static int hf_rtse_additionalReferenceInformation = -1;  /* AdditionalReferenceInformation */
static int hf_rtse_t61String = -1;                /* T_t61String */
static int hf_rtse_octetString = -1;              /* T_octetString */

/*--- End of included file: packet-rtse-hf.c ---*/
#line 62 "../../asn1/rtse/packet-rtse-template.c"

/* Initialize the subtree pointers */
static gint ett_rtse = -1;

/*--- Included file: packet-rtse-ett.c ---*/
#line 1 "../../asn1/rtse/packet-rtse-ett.c"
static gint ett_rtse_RTSE_apdus = -1;
static gint ett_rtse_RTORQapdu = -1;
static gint ett_rtse_RTOACapdu = -1;
static gint ett_rtse_RTORJapdu = -1;
static gint ett_rtse_RTABapdu = -1;
static gint ett_rtse_ConnectionData = -1;
static gint ett_rtse_SessionConnectionIdentifier = -1;
static gint ett_rtse_CallingSSuserReference = -1;

/*--- End of included file: packet-rtse-ett.c ---*/
#line 66 "../../asn1/rtse/packet-rtse-template.c"


static dissector_table_t rtse_oid_dissector_table=NULL;
static GHashTable *oid_table=NULL;
static gint ett_rtse_unknown = -1;

static GHashTable *rtse_segment_table = NULL;
static GHashTable *rtse_reassembled_table = NULL;

static int hf_rtse_segment_data = -1;
static int hf_rtse_fragments = -1;
static int hf_rtse_fragment = -1;
static int hf_rtse_fragment_overlap = -1;
static int hf_rtse_fragment_overlap_conflicts = -1;
static int hf_rtse_fragment_multiple_tails = -1;
static int hf_rtse_fragment_too_long_fragment = -1;
static int hf_rtse_fragment_error = -1;
static int hf_rtse_fragment_count = -1;
static int hf_rtse_reassembled_in = -1;
static int hf_rtse_reassembled_length = -1;

static gint ett_rtse_fragment = -1;
static gint ett_rtse_fragments = -1;

static const fragment_items rtse_frag_items = {
	/* Fragment subtrees */
	&ett_rtse_fragment,
	&ett_rtse_fragments,
	/* Fragment fields */
	&hf_rtse_fragments,
	&hf_rtse_fragment,
	&hf_rtse_fragment_overlap,
	&hf_rtse_fragment_overlap_conflicts,
	&hf_rtse_fragment_multiple_tails,
	&hf_rtse_fragment_too_long_fragment,
	&hf_rtse_fragment_error,
	&hf_rtse_fragment_count,
	/* Reassembled in field */
	&hf_rtse_reassembled_in,
	/* Reassembled length field */
	&hf_rtse_reassembled_length,
	/* Tag */
	"RTSE fragments"
};

void
register_rtse_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto, const char *name, gboolean uses_ros)
{
/* XXX: Note that this fcn is called from proto_reg_handoff in *other* dissectors ... */

  static  dissector_handle_t rtse_handle = NULL;
  static  dissector_handle_t ros_handle = NULL;

  if (rtse_handle == NULL)
    rtse_handle = find_dissector("rtse");
  if (ros_handle == NULL)
    ros_handle = find_dissector("ros");

  /* save the name - but not used */
  g_hash_table_insert(oid_table, (gpointer)oid, (gpointer)name);

  /* register RTSE with the BER (ACSE) */
  register_ber_oid_dissector_handle(oid, rtse_handle, proto, name);

  if(uses_ros) {
    /* make sure we call ROS ... */
    dissector_add_string("rtse.oid", oid, ros_handle);

    /* and then tell ROS how to dissect the AS*/
    register_ros_oid_dissector_handle(oid, dissector, proto, name, TRUE);

  } else {
    /* otherwise we just remember how to dissect the AS */
    dissector_add_string("rtse.oid", oid, dissector);
  }
}

static int
call_rtse_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;

	next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), tvb_reported_length_remaining(tvb, offset));
	if(!dissector_try_string(rtse_oid_dissector_table, oid, next_tvb, pinfo, tree)){
		proto_item *item=proto_tree_add_text(tree, next_tvb, 0, tvb_length_remaining(tvb, offset), "RTSE: Dissector for OID:%s not implemented. Contact Wireshark developers if you want this supported", oid);
		proto_tree *next_tree=proto_item_add_subtree(item, ett_rtse_unknown);

		expert_add_info_format (pinfo, item, PI_UNDECODED, PI_WARN,
                                        "RTSE: Dissector for OID %s not implemented", oid);
		dissect_unknown_ber(pinfo, next_tvb, offset, next_tree);
	}

	/*XXX until we change the #.REGISTER signature for _PDU()s 
	 * into new_dissector_t   we have to do this kludge with
	 * manually step past the content in the ANY type.
	 */
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}

static int
call_rtse_external_type_callback(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_)
{
	const char	*oid = NULL;

        if (actx->external.indirect_ref_present) {
		oid = (const char *)find_oid_by_pres_ctx_id(actx->pinfo, actx->external.indirect_reference);
	} else if (actx->external.direct_ref_present) {
    		oid = actx->external.direct_reference;
	}

	if (oid)
    		offset = call_rtse_oid_callback(oid, tvb, offset, actx->pinfo, top_tree ? top_tree : tree);

	return offset;
}


/*--- Included file: packet-rtse-fn.c ---*/
#line 1 "../../asn1/rtse/packet-rtse-fn.c"


static int
dissect_rtse_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string rtse_T_dialogueMode_vals[] = {
  {   0, "monologue" },
  {   1, "twa" },
  { 0, NULL }
};


static int
dissect_rtse_T_dialogueMode(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_rtse_T_open(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 53 "../../asn1/rtse/rtse.cnf"

	char *oid = NULL;

	switch(app_proto)  {
	case 1:		/* mts-transfer-protocol-1984 */
		oid = "applicationProtocol.1";
		break;
	case 12: 	/* mts-transfer-protocol */
		oid = "applicationProtocol.12";
		break;
	default:
		if(session && session->pres_ctx_id)
			oid = find_oid_by_pres_ctx_id(actx->pinfo, session->pres_ctx_id);
		break;
	}
	
	if(!oid) /* XXX: problem here is we haven't decoded the applicationProtocol yet - so we make assumptions! */
		oid = "applicationProtocol.12";

	if(oid) {

		offset = call_rtse_oid_callback(oid, tvb, offset, actx->pinfo, top_tree ? top_tree : tree);
	}

	/* else XXX: need to flag we can't find the presentation context */



  return offset;
}



static int
dissect_rtse_T_t61String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 108 "../../asn1/rtse/rtse.cnf"
  tvbuff_t *string = NULL;
    offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            &string);

  if(open_request && string && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", tvb_format_text(string, 0, tvb_length(string)));



  return offset;
}



static int
dissect_rtse_T_octetString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 124 "../../asn1/rtse/rtse.cnf"
  tvbuff_t *string = NULL;
    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &string);

  if(open_request && string && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", tvb_format_text(string, 0, tvb_length(string)));



  return offset;
}


static const value_string rtse_CallingSSuserReference_vals[] = {
  {   0, "t61String" },
  {   1, "octetString" },
  { 0, NULL }
};

static const ber_choice_t CallingSSuserReference_choice[] = {
  {   0, &hf_rtse_t61String      , BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_rtse_T_t61String },
  {   1, &hf_rtse_octetString    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_rtse_T_octetString },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_rtse_CallingSSuserReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CallingSSuserReference_choice, hf_index, ett_rtse_CallingSSuserReference,
                                 NULL);

  return offset;
}



static int
dissect_rtse_CommonReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 116 "../../asn1/rtse/rtse.cnf"
  tvbuff_t *string = NULL;
    offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  if(open_request && string && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", tvb_format_text(string, 0, tvb_length(string)));



  return offset;
}



static int
dissect_rtse_AdditionalReferenceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t SessionConnectionIdentifier_sequence[] = {
  { &hf_rtse_callingSSuserReference, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_rtse_CallingSSuserReference },
  { &hf_rtse_commonReference, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_rtse_CommonReference },
  { &hf_rtse_additionalReferenceInformation, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_AdditionalReferenceInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_rtse_SessionConnectionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 101 "../../asn1/rtse/rtse.cnf"
  if(open_request && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_str(actx->pinfo->cinfo, COL_INFO, "Recover");
    offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SessionConnectionIdentifier_sequence, hf_index, ett_rtse_SessionConnectionIdentifier);




  return offset;
}


static const value_string rtse_ConnectionData_vals[] = {
  {   0, "open" },
  {   1, "recover" },
  { 0, NULL }
};

static const ber_choice_t ConnectionData_choice[] = {
  {   0, &hf_rtse_open           , BER_CLASS_CON, 0, 0, dissect_rtse_T_open },
  {   1, &hf_rtse_recover        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_rtse_SessionConnectionIdentifier },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_rtse_ConnectionData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ConnectionData_choice, hf_index, ett_rtse_ConnectionData,
                                 NULL);

  return offset;
}


static const value_string rtse_T_applicationProtocol_vals[] = {
  {  12, "mts-transfer-protocol" },
  {   1, "mts-transfer-protocol-1984" },
  { 0, NULL }
};


static int
dissect_rtse_T_applicationProtocol(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 97 "../../asn1/rtse/rtse.cnf"

  offset = dissect_ber_integer(TRUE, actx, tree, tvb, offset, hf_index, &app_proto);



  return offset;
}


static const ber_sequence_t RTORQapdu_set[] = {
  { &hf_rtse_checkpointSize , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_INTEGER },
  { &hf_rtse_windowSize     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_INTEGER },
  { &hf_rtse_dialogueMode   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_T_dialogueMode },
  { &hf_rtse_connectionDataRQ, BER_CLASS_CON, 3, BER_FLAGS_NOTCHKTAG, dissect_rtse_ConnectionData },
  { &hf_rtse_applicationProtocol, BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_T_applicationProtocol },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_rtse_RTORQapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 38 "../../asn1/rtse/rtse.cnf"

  if((session = (struct SESSION_DATA_STRUCTURE*)(actx->pinfo->private_data)) != NULL)
	session->ros_op = (ROS_OP_BIND | ROS_OP_ARGUMENT);
  open_request=TRUE;
    offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RTORQapdu_set, hf_index, ett_rtse_RTORQapdu);

  open_request=FALSE;



  return offset;
}


static const ber_sequence_t RTOACapdu_set[] = {
  { &hf_rtse_checkpointSize , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_INTEGER },
  { &hf_rtse_windowSize     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_INTEGER },
  { &hf_rtse_connectionDataAC, BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_rtse_ConnectionData },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_rtse_RTOACapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 46 "../../asn1/rtse/rtse.cnf"

  if((session = (struct SESSION_DATA_STRUCTURE*)(actx->pinfo->private_data)) != NULL)
	session->ros_op = (ROS_OP_BIND | ROS_OP_RESULT);

    offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RTOACapdu_set, hf_index, ett_rtse_RTOACapdu);




  return offset;
}


static const value_string rtse_RefuseReason_vals[] = {
  {   0, "rtsBusy" },
  {   1, "cannotRecover" },
  {   2, "validationFailure" },
  {   3, "unacceptableDialogueMode" },
  { 0, NULL }
};


static int
dissect_rtse_RefuseReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 148 "../../asn1/rtse/rtse.cnf"
  int reason = -1;
 
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &reason);


  if(reason != -1)
   col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%s)", val_to_str(reason, rtse_RefuseReason_vals, "reason(%d)"));



  return offset;
}



static int
dissect_rtse_T_userDataRJ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 9 "../../asn1/rtse/rtse.cnf"
	char *oid = NULL;

	switch(app_proto)  {
	case 1:		/* mts-transfer-protocol-1984 */
		oid = "applicationProtocol.1";
		break;
	case 12: 	/* mts-transfer-protocol */
		oid = "applicationProtocol.12";
		break;
	default:
		if(session && session->pres_ctx_id)
			oid = find_oid_by_pres_ctx_id(actx->pinfo, session->pres_ctx_id);
		break;
	}
	
	if(!oid) /* XXX: problem here is we haven't decoded the applicationProtocol yet - so we make assumptions! */
		oid = "applicationProtocol.12";

	if(oid) {
	  if((session = (struct SESSION_DATA_STRUCTURE*)(actx->pinfo->private_data)) != NULL)
		session->ros_op = (ROS_OP_BIND | ROS_OP_ERROR);

		offset = call_rtse_oid_callback(oid, tvb, offset, actx->pinfo, top_tree ? top_tree : tree);
	}



  return offset;
}


static const ber_sequence_t RTORJapdu_set[] = {
  { &hf_rtse_refuseReason   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_RefuseReason },
  { &hf_rtse_userDataRJ     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_rtse_T_userDataRJ },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_rtse_RTORJapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 140 "../../asn1/rtse/rtse.cnf"
  col_append_fstr(actx->pinfo->cinfo, COL_INFO, "Refuse");

    offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RTORJapdu_set, hf_index, ett_rtse_RTORJapdu);




  return offset;
}



static int
dissect_rtse_RTTPapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 130 "../../asn1/rtse/rtse.cnf"
  int priority = -1;

  col_append_fstr(actx->pinfo->cinfo, COL_INFO, "Turn-Please");

    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &priority);


  if(priority != -1)
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%d)", priority);



  return offset;
}



static int
dissect_rtse_RTTRapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 80 "../../asn1/rtse/rtse.cnf"
	tvbuff_t *next_tvb = NULL;

	offset = dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &next_tvb);

	if(next_tvb) {

		/* XXX: we should check is this is an EXTERNAL first */

		/* ROS won't do this for us */
		if(session)
			session->ros_op = (ROS_OP_INVOKE | ROS_OP_ARGUMENT);

		offset = dissect_ber_external_type(FALSE, tree, next_tvb, 0, actx,  -1, call_rtse_external_type_callback);
	}




  return offset;
}


static const value_string rtse_AbortReason_vals[] = {
  {   0, "localSystemProblem" },
  {   1, "invalidParameter" },
  {   2, "unrecognizedActivity" },
  {   3, "temporaryProblem" },
  {   4, "protocolError" },
  {   5, "permanentProblem" },
  {   6, "userError" },
  {   7, "transferCompleted" },
  { 0, NULL }
};


static int
dissect_rtse_AbortReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 164 "../../asn1/rtse/rtse.cnf"
  int reason = -1;
 
    offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                &reason);


  if(reason != -1)
   col_append_fstr(actx->pinfo->cinfo, COL_INFO, " (%s)", val_to_str(reason, rtse_AbortReason_vals, "reason(%d)"));



  return offset;
}



static int
dissect_rtse_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_rtse_T_userdataAB(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 35 "../../asn1/rtse/rtse.cnf"
/*XXX not implemented yet */



  return offset;
}


static const ber_sequence_t RTABapdu_set[] = {
  { &hf_rtse_abortReason    , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_AbortReason },
  { &hf_rtse_reflectedParameter, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_rtse_BIT_STRING },
  { &hf_rtse_userdataAB     , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_rtse_T_userdataAB },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_rtse_RTABapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 156 "../../asn1/rtse/rtse.cnf"
  col_append_fstr(actx->pinfo->cinfo, COL_INFO, "Abort");

    offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              RTABapdu_set, hf_index, ett_rtse_RTABapdu);




  return offset;
}


static const value_string rtse_RTSE_apdus_vals[] = {
  {   0, "rtorq-apdu" },
  {   1, "rtoac-apdu" },
  {   2, "rtorj-apdu" },
  {   3, "rttp-apdu" },
  {   4, "rttr-apdu" },
  {   5, "rtab-apdu" },
  { 0, NULL }
};

static const ber_choice_t RTSE_apdus_choice[] = {
  {   0, &hf_rtse_rtorq_apdu     , BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_rtse_RTORQapdu },
  {   1, &hf_rtse_rtoac_apdu     , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_rtse_RTOACapdu },
  {   2, &hf_rtse_rtorj_apdu     , BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_rtse_RTORJapdu },
  {   3, &hf_rtse_rttp_apdu      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_rtse_RTTPapdu },
  {   4, &hf_rtse_rttr_apdu      , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_rtse_RTTRapdu },
  {   5, &hf_rtse_rtab_apdu      , BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_rtse_RTABapdu },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_rtse_RTSE_apdus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RTSE_apdus_choice, hf_index, ett_rtse_RTSE_apdus,
                                 NULL);

  return offset;
}


/*--- End of included file: packet-rtse-fn.c ---*/
#line 185 "../../asn1/rtse/packet-rtse-template.c"

/*
* Dissect RTSE PDUs inside a PPDU.
*/
static void
dissect_rtse(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	proto_tree *next_tree=NULL;
	tvbuff_t *next_tvb = NULL;
	tvbuff_t *data_tvb = NULL;
	fragment_data *frag_msg = NULL;
	guint32 fragment_length;
	guint32 rtse_id = 0;
	gboolean data_handled = FALSE;
	conversation_t *conversation = NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	/* save parent_tree so subdissectors can create new top nodes */
	top_tree=parent_tree;

	/* do we have application context from the acse dissector?  */
	if( !pinfo->private_data ){
		if(parent_tree){
			proto_tree_add_text(parent_tree, tvb, offset, -1,
				"Internal error:can't get application context from ACSE dissector.");
		} 
		return  ;
	} else {
		session  = ( (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data) );

	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTSE");
  	col_clear(pinfo->cinfo, COL_INFO);

	if (rtse_reassemble && 
	    ((session->spdu_type == SES_DATA_TRANSFER) ||
	     (session->spdu_type == SES_MAJOR_SYNC_POINT))) {
		/* Use conversation index as fragment id */
		conversation  = find_conversation (pinfo->fd->num, 
						   &pinfo->src, &pinfo->dst, pinfo->ptype, 
						   pinfo->srcport, pinfo->destport, 0);
		if (conversation != NULL) { 
			rtse_id = conversation->index;
		} 
		session->rtse_reassemble = TRUE;
	}
	if (rtse_reassemble && session->spdu_type == SES_MAJOR_SYNC_POINT) {
		frag_msg = fragment_end_seq_next (pinfo, rtse_id, rtse_segment_table,
						  rtse_reassembled_table);
		next_tvb = process_reassembled_data (tvb, offset, pinfo, "Reassembled RTSE", 
						     frag_msg, &rtse_frag_items, NULL, parent_tree);
	}
	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_rtse, next_tvb ? next_tvb : tvb, 0, -1, ENC_BIG_ENDIAN);
		tree = proto_item_add_subtree(item, ett_rtse);
	}
	if (rtse_reassemble && session->spdu_type == SES_DATA_TRANSFER) {
		/* strip off the OCTET STRING encoding - including any CONSTRUCTED OCTET STRING */
		dissect_ber_octet_string(FALSE, &asn1_ctx, tree, tvb, offset, hf_rtse_segment_data, &data_tvb);

		if (data_tvb) {
			fragment_length = tvb_length_remaining (data_tvb, 0);
			proto_item_append_text(asn1_ctx.created_item, " (%u byte%s)", fragment_length,
      	                              plurality(fragment_length, "", "s"));
			frag_msg = fragment_add_seq_next (data_tvb, 0, pinfo, 
							  rtse_id, rtse_segment_table,
							  rtse_reassembled_table, fragment_length, TRUE);
			if (frag_msg && pinfo->fd->num != frag_msg->reassembled_in) {
				/* Add a "Reassembled in" link if not reassembled in this frame */
				proto_tree_add_uint (tree, *(rtse_frag_items.hf_reassembled_in),
						     data_tvb, 0, 0, frag_msg->reassembled_in);
			}
			pinfo->fragmented = TRUE;
			data_handled = TRUE;
		} else {
			fragment_length = tvb_length_remaining (tvb, offset);
		}

		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, "[RTSE fragment, %u byte%s]",
					fragment_length, plurality(fragment_length, "", "s"));
	} else if (rtse_reassemble && session->spdu_type == SES_MAJOR_SYNC_POINT) {
		if (next_tvb) {
			/* ROS won't do this for us */
			session->ros_op = (ROS_OP_INVOKE | ROS_OP_ARGUMENT);
			offset=dissect_ber_external_type(FALSE, tree, next_tvb, 0, &asn1_ctx, -1, call_rtse_external_type_callback);
		} else {
			offset = tvb_length (tvb);
		}
		pinfo->fragmented = FALSE;
		data_handled = TRUE;
	} 

	if (!data_handled) {
		while (tvb_reported_length_remaining(tvb, offset) > 0){
			old_offset=offset;
			offset=dissect_rtse_RTSE_apdus(TRUE, tvb, offset, &asn1_ctx, tree, -1);
			if(offset == old_offset){
				item = proto_tree_add_text(tree, tvb, offset, -1, "Unknown RTSE PDU");

				if(item){
					expert_add_info_format (pinfo, item, PI_UNDECODED, PI_WARN, "Unknown RTSE PDU");
					next_tree=proto_item_add_subtree(item, ett_rtse_unknown);
					dissect_unknown_ber(pinfo, tvb, offset, next_tree);
				}

				offset = tvb_length(tvb);
				break;
			}
		}
	}

	top_tree = NULL;
}

static void rtse_reassemble_init (void)
{
	fragment_table_init (&rtse_segment_table);
	reassembled_table_init (&rtse_reassembled_table);
}

/*--- proto_register_rtse -------------------------------------------*/
void proto_register_rtse(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
    /* Fragment entries */
    { &hf_rtse_segment_data,
      { "RTSE segment data", "rtse.segment", FT_NONE, BASE_NONE,
	NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_fragments,
      { "RTSE fragments", "rtse.fragments", FT_NONE, BASE_NONE,
	NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_fragment,
      { "RTSE fragment", "rtse.fragment", FT_FRAMENUM, BASE_NONE,
	NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_fragment_overlap,
      { "RTSE fragment overlap", "rtse.fragment.overlap", FT_BOOLEAN,
	BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_rtse_fragment_overlap_conflicts,
      { "RTSE fragment overlapping with conflicting data",
	"rtse.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE,
	NULL, 0x0, NULL, HFILL } },
    { &hf_rtse_fragment_multiple_tails,
      { "RTSE has multiple tail fragments",
	"rtse.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
	NULL, 0x0, NULL, HFILL } },
    { &hf_rtse_fragment_too_long_fragment,
      { "RTSE fragment too long", "rtse.fragment.too_long_fragment",
	FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    { &hf_rtse_fragment_error,
      { "RTSE defragmentation error", "rtse.fragment.error", FT_FRAMENUM,
	BASE_NONE, NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_fragment_count,
      { "RTSE fragment count", "rtse.fragment.count", FT_UINT32, BASE_DEC,
	NULL, 0x00, NULL, HFILL } },
    { &hf_rtse_reassembled_in,
      { "Reassembled RTSE in frame", "rtse.reassembled.in", FT_FRAMENUM, BASE_NONE,
	NULL, 0x00, "This RTSE packet is reassembled in this frame", HFILL } },
    { &hf_rtse_reassembled_length,
      { "Reassembled RTSE length", "rtse.reassembled.length", FT_UINT32, BASE_DEC,
	NULL, 0x00, "The total length of the reassembled payload", HFILL } },


/*--- Included file: packet-rtse-hfarr.c ---*/
#line 1 "../../asn1/rtse/packet-rtse-hfarr.c"
    { &hf_rtse_rtorq_apdu,
      { "rtorq-apdu", "rtse.rtorq_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTORQapdu", HFILL }},
    { &hf_rtse_rtoac_apdu,
      { "rtoac-apdu", "rtse.rtoac_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTOACapdu", HFILL }},
    { &hf_rtse_rtorj_apdu,
      { "rtorj-apdu", "rtse.rtorj_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTORJapdu", HFILL }},
    { &hf_rtse_rttp_apdu,
      { "rttp-apdu", "rtse.rttp_apdu",
        FT_INT32, BASE_DEC, NULL, 0,
        "RTTPapdu", HFILL }},
    { &hf_rtse_rttr_apdu,
      { "rttr-apdu", "rtse.rttr_apdu",
        FT_BYTES, BASE_NONE, NULL, 0,
        "RTTRapdu", HFILL }},
    { &hf_rtse_rtab_apdu,
      { "rtab-apdu", "rtse.rtab_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTABapdu", HFILL }},
    { &hf_rtse_checkpointSize,
      { "checkpointSize", "rtse.checkpointSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_rtse_windowSize,
      { "windowSize", "rtse.windowSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_rtse_dialogueMode,
      { "dialogueMode", "rtse.dialogueMode",
        FT_INT32, BASE_DEC, VALS(rtse_T_dialogueMode_vals), 0,
        NULL, HFILL }},
    { &hf_rtse_connectionDataRQ,
      { "connectionDataRQ", "rtse.connectionDataRQ",
        FT_UINT32, BASE_DEC, VALS(rtse_ConnectionData_vals), 0,
        "ConnectionData", HFILL }},
    { &hf_rtse_applicationProtocol,
      { "applicationProtocol", "rtse.applicationProtocol",
        FT_INT32, BASE_DEC, VALS(rtse_T_applicationProtocol_vals), 0,
        NULL, HFILL }},
    { &hf_rtse_connectionDataAC,
      { "connectionDataAC", "rtse.connectionDataAC",
        FT_UINT32, BASE_DEC, VALS(rtse_ConnectionData_vals), 0,
        "ConnectionData", HFILL }},
    { &hf_rtse_refuseReason,
      { "refuseReason", "rtse.refuseReason",
        FT_INT32, BASE_DEC, VALS(rtse_RefuseReason_vals), 0,
        NULL, HFILL }},
    { &hf_rtse_userDataRJ,
      { "userDataRJ", "rtse.userDataRJ",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rtse_abortReason,
      { "abortReason", "rtse.abortReason",
        FT_INT32, BASE_DEC, VALS(rtse_AbortReason_vals), 0,
        NULL, HFILL }},
    { &hf_rtse_reflectedParameter,
      { "reflectedParameter", "rtse.reflectedParameter",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_rtse_userdataAB,
      { "userdataAB", "rtse.userdataAB",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rtse_open,
      { "open", "rtse.open",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rtse_recover,
      { "recover", "rtse.recover",
        FT_NONE, BASE_NONE, NULL, 0,
        "SessionConnectionIdentifier", HFILL }},
    { &hf_rtse_callingSSuserReference,
      { "callingSSuserReference", "rtse.callingSSuserReference",
        FT_UINT32, BASE_DEC, VALS(rtse_CallingSSuserReference_vals), 0,
        NULL, HFILL }},
    { &hf_rtse_commonReference,
      { "commonReference", "rtse.commonReference",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rtse_additionalReferenceInformation,
      { "additionalReferenceInformation", "rtse.additionalReferenceInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rtse_t61String,
      { "t61String", "rtse.t61String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_rtse_octetString,
      { "octetString", "rtse.octetString",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- End of included file: packet-rtse-hfarr.c ---*/
#line 356 "../../asn1/rtse/packet-rtse-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_rtse,
    &ett_rtse_unknown,
    &ett_rtse_fragment,
    &ett_rtse_fragments,

/*--- Included file: packet-rtse-ettarr.c ---*/
#line 1 "../../asn1/rtse/packet-rtse-ettarr.c"
    &ett_rtse_RTSE_apdus,
    &ett_rtse_RTORQapdu,
    &ett_rtse_RTOACapdu,
    &ett_rtse_RTORJapdu,
    &ett_rtse_RTABapdu,
    &ett_rtse_ConnectionData,
    &ett_rtse_SessionConnectionIdentifier,
    &ett_rtse_CallingSSuserReference,

/*--- End of included file: packet-rtse-ettarr.c ---*/
#line 365 "../../asn1/rtse/packet-rtse-template.c"
  };

  module_t *rtse_module;

  /* Register protocol */
  proto_rtse = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("rtse", dissect_rtse, proto_rtse);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rtse, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  register_init_routine (&rtse_reassemble_init);
  rtse_module = prefs_register_protocol_subtree("OSI", proto_rtse, NULL);

  prefs_register_bool_preference(rtse_module, "reassemble",
				 "Reassemble segmented RTSE datagrams",
				 "Whether segmented RTSE datagrams should be reassembled."
				 " To use this option, you must also enable"
				 " \"Allow subdissectors to reassemble TCP streams\""
				 " in the TCP protocol settings.", &rtse_reassemble);

  rtse_oid_dissector_table = register_dissector_table("rtse.oid", "RTSE OID Dissectors", FT_STRING, BASE_NONE);
  oid_table=g_hash_table_new(g_str_hash, g_str_equal);


}


/*--- proto_reg_handoff_rtse --- */
void proto_reg_handoff_rtse(void) {


}
