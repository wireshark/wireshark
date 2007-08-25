/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* ./packet-rtse.c                                                            */
/* ../../tools/asn2wrs.py -b -e -p rtse -c rtse.cnf -s packet-rtse-template rtse.asn */

/* Input file: packet-rtse-template.c */

#line 1 "packet-rtse-template.c"
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

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-pres.h"
#include "packet-acse.h"
#include "packet-ros.h"
#include "packet-rtse.h"

#define PNAME  "X.228 OSI Reliable Transfer Service"
#define PSNAME "RTSE"
#define PFNAME "rtse"

/* Initialize the protocol and registered fields */
int proto_rtse = -1;

static struct SESSION_DATA_STRUCTURE* session = NULL;

static char* object_identifier_id;
static gboolean open_request=FALSE;
/* indirect_reference, used to pick up the signalling so we know what
   kind of data is transferred in SES_DATA_TRANSFER_PDUs */
static guint32 indir_ref=0;
static guint32 app_proto=0;

static proto_tree *top_tree=NULL;

static  dissector_handle_t rtse_handle = NULL;
static  dissector_handle_t ros_handle = NULL;

/* Preferences */
static gboolean rtse_reassemble = TRUE;


/*--- Included file: packet-rtse-hf.c ---*/
#line 1 "packet-rtse-hf.c"
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
static int hf_rtse_direct_reference = -1;         /* OBJECT_IDENTIFIER */
static int hf_rtse_indirect_reference = -1;       /* T_indirect_reference */
static int hf_rtse_data_value_descriptor = -1;    /* ObjectDescriptor */
static int hf_rtse_encoding = -1;                 /* T_encoding */
static int hf_rtse_single_ASN1_type = -1;         /* T_single_ASN1_type */
static int hf_rtse_octet_aligned = -1;            /* OCTET_STRING */
static int hf_rtse_arbitrary = -1;                /* BIT_STRING */

/*--- End of included file: packet-rtse-hf.c ---*/
#line 71 "packet-rtse-template.c"

/* Initialize the subtree pointers */
static gint ett_rtse = -1;

/*--- Included file: packet-rtse-ett.c ---*/
#line 1 "packet-rtse-ett.c"
static gint ett_rtse_RTSE_apdus = -1;
static gint ett_rtse_RTORQapdu = -1;
static gint ett_rtse_RTOACapdu = -1;
static gint ett_rtse_RTORJapdu = -1;
static gint ett_rtse_RTABapdu = -1;
static gint ett_rtse_ConnectionData = -1;
static gint ett_rtse_SessionConnectionIdentifier = -1;
static gint ett_rtse_CallingSSuserReference = -1;
static gint ett_rtse_EXTERNALt = -1;
static gint ett_rtse_T_encoding = -1;

/*--- End of included file: packet-rtse-ett.c ---*/
#line 75 "packet-rtse-template.c"


static dissector_table_t rtse_oid_dissector_table=NULL;
static GHashTable *oid_table=NULL;
static gint ett_rtse_unknown = -1;

static GHashTable *rtse_segment_table = NULL;
static GHashTable *rtse_reassembled_table = NULL;
 
static int hf_rtse_fragments = -1;
static int hf_rtse_fragment = -1;
static int hf_rtse_fragment_overlap = -1;
static int hf_rtse_fragment_overlap_conflicts = -1;
static int hf_rtse_fragment_multiple_tails = -1;
static int hf_rtse_fragment_too_long_fragment = -1;
static int hf_rtse_fragment_error = -1;
static int hf_rtse_reassembled_in = -1;

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
	/* Reassembled in field */
	&hf_rtse_reassembled_in,
	/* Tag */
	"RTSE fragments"
};

void
register_rtse_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto _U_, const char *name, gboolean uses_ros)
{

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
		proto_item *item=NULL;
		proto_tree *next_tree=NULL;

		item=proto_tree_add_text(tree, next_tvb, 0, tvb_length_remaining(tvb, offset), "RTSE: Dissector for OID:%s not implemented. Contact Wireshark developers if you want this supported", oid);
		if(item){
			next_tree=proto_item_add_subtree(item, ett_rtse_unknown);
		}
		dissect_unknown_ber(pinfo, next_tvb, offset, next_tree);
	}

	/*XXX until we change the #.REGISTER signature for _PDU()s 
	 * into new_dissector_t   we have to do this kludge with
	 * manually step past the content in the ANY type.
	 */
	offset+=tvb_length_remaining(tvb, offset);

	return offset;
}


/*--- Included file: packet-rtse-fn.c ---*/
#line 1 "packet-rtse-fn.c"
/*--- Fields for imported types ---*/




static int
dissect_rtse_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_checkpointSize_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_INTEGER(TRUE, tvb, offset, actx, tree, hf_rtse_checkpointSize);
}
static int dissect_windowSize_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_INTEGER(TRUE, tvb, offset, actx, tree, hf_rtse_windowSize);
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
static int dissect_dialogueMode_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_T_dialogueMode(TRUE, tvb, offset, actx, tree, hf_rtse_dialogueMode);
}



static int
dissect_rtse_T_open(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 53 "rtse.cnf"

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
static int dissect_open(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_T_open(FALSE, tvb, offset, actx, tree, hf_rtse_open);
}



static int
dissect_rtse_T_t61String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 145 "rtse.cnf"
  tvbuff_t *string = NULL;
    offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            &string);

  if(open_request && string && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", tvb_format_text(string, 0, tvb_length(string)));



  return offset;
}
static int dissect_t61String(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_T_t61String(FALSE, tvb, offset, actx, tree, hf_rtse_t61String);
}



static int
dissect_rtse_T_octetString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 161 "rtse.cnf"
  tvbuff_t *string = NULL;
    offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       &string);

  if(open_request && string && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", tvb_format_text(string, 0, tvb_length(string)));



  return offset;
}
static int dissect_octetString(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_T_octetString(FALSE, tvb, offset, actx, tree, hf_rtse_octetString);
}


static const value_string rtse_CallingSSuserReference_vals[] = {
  {   0, "t61String" },
  {   1, "octetString" },
  { 0, NULL }
};

static const ber_old_choice_t CallingSSuserReference_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_t61String },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_octetString },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_rtse_CallingSSuserReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     CallingSSuserReference_choice, hf_index, ett_rtse_CallingSSuserReference,
                                     NULL);

  return offset;
}
static int dissect_callingSSuserReference(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_CallingSSuserReference(FALSE, tvb, offset, actx, tree, hf_rtse_callingSSuserReference);
}



static int
dissect_rtse_CommonReference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 153 "rtse.cnf"
  tvbuff_t *string = NULL;
    offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTCTime,
                                            actx, tree, tvb, offset, hf_index,
                                            &string);

  if(open_request && string && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, " %s", tvb_format_text(string, 0, tvb_length(string)));



  return offset;
}
static int dissect_commonReference(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_CommonReference(FALSE, tvb, offset, actx, tree, hf_rtse_commonReference);
}



static int
dissect_rtse_AdditionalReferenceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_additionalReferenceInformation_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_AdditionalReferenceInformation(TRUE, tvb, offset, actx, tree, hf_rtse_additionalReferenceInformation);
}


static const ber_old_sequence_t SessionConnectionIdentifier_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_callingSSuserReference },
  { BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_commonReference },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additionalReferenceInformation_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_rtse_SessionConnectionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 138 "rtse.cnf"
  if(open_request && check_col(actx->pinfo->cinfo, COL_INFO))
    col_append_fstr(actx->pinfo->cinfo, COL_INFO, "Recover");
    offset = dissect_ber_old_sequence(implicit_tag, actx, tree, tvb, offset,
                                       SessionConnectionIdentifier_sequence, hf_index, ett_rtse_SessionConnectionIdentifier);




  return offset;
}
static int dissect_recover_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_SessionConnectionIdentifier(TRUE, tvb, offset, actx, tree, hf_rtse_recover);
}


static const value_string rtse_ConnectionData_vals[] = {
  {   0, "open" },
  {   1, "recover" },
  { 0, NULL }
};

static const ber_old_choice_t ConnectionData_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_open },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_recover_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_rtse_ConnectionData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     ConnectionData_choice, hf_index, ett_rtse_ConnectionData,
                                     NULL);

  return offset;
}
static int dissect_connectionDataRQ(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_ConnectionData(FALSE, tvb, offset, actx, tree, hf_rtse_connectionDataRQ);
}
static int dissect_connectionDataAC(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_ConnectionData(FALSE, tvb, offset, actx, tree, hf_rtse_connectionDataAC);
}


static const value_string rtse_T_applicationProtocol_vals[] = {
  {  12, "mts-transfer-protocol" },
  {   1, "mts-transfer-protocol-1984" },
  { 0, NULL }
};


static int
dissect_rtse_T_applicationProtocol(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 134 "rtse.cnf"

  offset = dissect_ber_integer(TRUE, actx, tree, tvb, offset, hf_index, &app_proto);



  return offset;
}
static int dissect_applicationProtocol_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_T_applicationProtocol(TRUE, tvb, offset, actx, tree, hf_rtse_applicationProtocol);
}


static const ber_old_sequence_t RTORQapdu_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_checkpointSize_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_windowSize_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dialogueMode_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_NOTCHKTAG, dissect_connectionDataRQ },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_applicationProtocol_impl },
  { 0, 0, 0, NULL }
};

int
dissect_rtse_RTORQapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 38 "rtse.cnf"

  if((session = (struct SESSION_DATA_STRUCTURE*)(actx->pinfo->private_data)) != NULL)
	session->ros_op = (ROS_OP_BIND | ROS_OP_ARGUMENT);
  open_request=TRUE;
    offset = dissect_ber_old_set(implicit_tag, actx, tree, tvb, offset,
                                  RTORQapdu_set, hf_index, ett_rtse_RTORQapdu);

  open_request=FALSE;



  return offset;
}
static int dissect_rtorq_apdu_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_RTORQapdu(TRUE, tvb, offset, actx, tree, hf_rtse_rtorq_apdu);
}


static const ber_old_sequence_t RTOACapdu_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_checkpointSize_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_windowSize_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_connectionDataAC },
  { 0, 0, 0, NULL }
};

int
dissect_rtse_RTOACapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 46 "rtse.cnf"

  if((session = (struct SESSION_DATA_STRUCTURE*)(actx->pinfo->private_data)) != NULL)
	session->ros_op = (ROS_OP_BIND | ROS_OP_RESULT);

    offset = dissect_ber_old_set(implicit_tag, actx, tree, tvb, offset,
                                  RTOACapdu_set, hf_index, ett_rtse_RTOACapdu);




  return offset;
}
static int dissect_rtoac_apdu_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_RTOACapdu(TRUE, tvb, offset, actx, tree, hf_rtse_rtoac_apdu);
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
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_refuseReason_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_RefuseReason(TRUE, tvb, offset, actx, tree, hf_rtse_refuseReason);
}



static int
dissect_rtse_T_userDataRJ(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 9 "rtse.cnf"
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
static int dissect_userDataRJ(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_T_userDataRJ(FALSE, tvb, offset, actx, tree, hf_rtse_userDataRJ);
}


static const ber_old_sequence_t RTORJapdu_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_refuseReason_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_userDataRJ },
  { 0, 0, 0, NULL }
};

int
dissect_rtse_RTORJapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_set(implicit_tag, actx, tree, tvb, offset,
                                  RTORJapdu_set, hf_index, ett_rtse_RTORJapdu);

  return offset;
}
static int dissect_rtorj_apdu_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_RTORJapdu(TRUE, tvb, offset, actx, tree, hf_rtse_rtorj_apdu);
}



static int
dissect_rtse_RTTPapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_rttp_apdu(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_RTTPapdu(FALSE, tvb, offset, actx, tree, hf_rtse_rttp_apdu);
}



static int
dissect_rtse_RTTRapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 80 "rtse.cnf"
	tvbuff_t *next_tvb = NULL;

	offset = dissect_ber_octet_string(FALSE, actx, tree, tvb, offset, hf_index, &next_tvb);

	if(next_tvb) {

		/* XXX: we should check is this is an EXTERNAL first */

		/* ROS won't do this for us */
		if(session)
			session->ros_op = (ROS_OP_INVOKE | ROS_OP_ARGUMENT);

		offset = dissect_rtse_EXTERNALt(FALSE, next_tvb, 0, actx, tree, -1);

	}



  return offset;
}
static int dissect_rttr_apdu(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_RTTRapdu(FALSE, tvb, offset, actx, tree, hf_rtse_rttr_apdu);
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
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_abortReason_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_AbortReason(TRUE, tvb, offset, actx, tree, hf_rtse_abortReason);
}



static int
dissect_rtse_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_reflectedParameter_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_BIT_STRING(TRUE, tvb, offset, actx, tree, hf_rtse_reflectedParameter);
}
static int dissect_arbitrary_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_BIT_STRING(TRUE, tvb, offset, actx, tree, hf_rtse_arbitrary);
}



static int
dissect_rtse_T_userdataAB(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 35 "rtse.cnf"
/*XXX not implemented yet */



  return offset;
}
static int dissect_userdataAB(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_T_userdataAB(FALSE, tvb, offset, actx, tree, hf_rtse_userdataAB);
}


static const ber_old_sequence_t RTABapdu_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_abortReason_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reflectedParameter_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_userdataAB },
  { 0, 0, 0, NULL }
};

int
dissect_rtse_RTABapdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_set(implicit_tag, actx, tree, tvb, offset,
                                  RTABapdu_set, hf_index, ett_rtse_RTABapdu);

  return offset;
}
static int dissect_rtab_apdu_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_RTABapdu(TRUE, tvb, offset, actx, tree, hf_rtse_rtab_apdu);
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

static const ber_old_choice_t RTSE_apdus_choice[] = {
  {   0, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_rtorq_apdu_impl },
  {   1, BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_rtoac_apdu_impl },
  {   2, BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_rtorj_apdu_impl },
  {   3, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_rttp_apdu },
  {   4, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_rttr_apdu },
  {   5, BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_rtab_apdu_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_rtse_RTSE_apdus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     RTSE_apdus_choice, hf_index, ett_rtse_RTSE_apdus,
                                     NULL);

  return offset;
}



static int
dissect_rtse_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_direct_reference(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_OBJECT_IDENTIFIER(FALSE, tvb, offset, actx, tree, hf_rtse_direct_reference);
}



static int
dissect_rtse_T_indirect_reference(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 115 "rtse.cnf"
  char *oid;

  offset = dissect_ber_integer(FALSE, actx, tree, tvb, offset,
                hf_rtse_indirect_reference,
                &indir_ref);

  /* look up the indirect reference */
  if((oid = find_oid_by_pres_ctx_id(actx->pinfo, indir_ref)) != NULL) {
    object_identifier_id = ep_strdup_printf("%s", oid);
  } else {
	*object_identifier_id = '\0';
  }
	



  return offset;
}
static int dissect_indirect_reference(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_T_indirect_reference(FALSE, tvb, offset, actx, tree, hf_rtse_indirect_reference);
}



static int
dissect_rtse_ObjectDescriptor(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_ObjectDescriptor,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_data_value_descriptor(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_ObjectDescriptor(FALSE, tvb, offset, actx, tree, hf_rtse_data_value_descriptor);
}



static int
dissect_rtse_T_single_ASN1_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 130 "rtse.cnf"
  offset=call_rtse_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, top_tree);




  return offset;
}
static int dissect_single_ASN1_type(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_T_single_ASN1_type(FALSE, tvb, offset, actx, tree, hf_rtse_single_ASN1_type);
}



static int
dissect_rtse_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_octet_aligned_impl(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_OCTET_STRING(TRUE, tvb, offset, actx, tree, hf_rtse_octet_aligned);
}


static const value_string rtse_T_encoding_vals[] = {
  {   0, "single-ASN1-type" },
  {   1, "octet-aligned" },
  {   2, "arbitrary" },
  { 0, NULL }
};

static const ber_old_choice_t T_encoding_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_single_ASN1_type },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_octet_aligned_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_arbitrary_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_rtse_T_encoding(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_old_choice(actx, tree, tvb, offset,
                                     T_encoding_choice, hf_index, ett_rtse_T_encoding,
                                     NULL);

  return offset;
}
static int dissect_encoding(proto_tree *tree _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_) {
  return dissect_rtse_T_encoding(FALSE, tvb, offset, actx, tree, hf_rtse_encoding);
}


static const ber_old_sequence_t EXTERNALt_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_direct_reference },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_indirect_reference },
  { BER_CLASS_UNI, BER_UNI_TAG_ObjectDescriptor, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_data_value_descriptor },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_encoding },
  { 0, 0, 0, NULL }
};

int
dissect_rtse_EXTERNALt(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 97 "rtse.cnf"
  gint8 class;
  gboolean pc, ind_field;
  gint32 tag;
  guint32 len1;

  if(!implicit_tag) {
    /* XXX  asn2wrs can not yet handle tagged assignment so for the
     * time being  just remove this tag manually inside the EXTERNAL
     * dissector.
     */
     offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
     offset = get_ber_length(tvb, offset, &len1, &ind_field);
   }

   offset = dissect_ber_old_sequence(TRUE, actx, tree, tvb, offset,
                                EXTERNALt_sequence, hf_index, ett_rtse_EXTERNALt);



  return offset;
}


/*--- End of included file: packet-rtse-fn.c ---*/
#line 164 "packet-rtse-template.c"

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

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTSE");
  	if (check_col(pinfo->cinfo, COL_INFO))
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
		item = proto_tree_add_item(parent_tree, proto_rtse, next_tvb ? next_tvb : tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_rtse);
	}
	if (rtse_reassemble && session->spdu_type == SES_DATA_TRANSFER) {
		/* strip off the OCTET STRING encoding - including any CONSTRUCTED OCTET STRING */
		dissect_ber_octet_string(FALSE, &asn1_ctx, NULL, tvb, offset, 0, &data_tvb);

		if (data_tvb) {
			fragment_length = tvb_length_remaining (data_tvb, 0);
			proto_tree_add_text(tree, data_tvb, 0, (fragment_length) ? -1 : 0,
					    "RTSE segment data (%u byte%s)", fragment_length,
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
			offset=dissect_rtse_EXTERNALt(FALSE, next_tvb, 0, &asn1_ctx, tree, -1);
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
				proto_tree_add_text(tree, tvb, offset, -1, "Internal error, zero-byte RTSE PDU");
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
    { &hf_rtse_fragments,
      { "RTSE fragments", "rtse.fragments", FT_NONE, BASE_NONE,
	NULL, 0x00, "Message fragments", HFILL } },
    { &hf_rtse_fragment,
      { "RTSE fragment", "rtse.fragment", FT_FRAMENUM, BASE_NONE,
	NULL, 0x00, "Message fragment", HFILL } },
    { &hf_rtse_fragment_overlap,
      { "RTSE fragment overlap", "rtse.fragment.overlap", FT_BOOLEAN,
	BASE_NONE, NULL, 0x00, "Message fragment overlap", HFILL } },
    { &hf_rtse_fragment_overlap_conflicts,
      { "RTSE fragment overlapping with conflicting data",
	"rtse.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL,
	0x00, "Message fragment overlapping with conflicting data", HFILL } },
    { &hf_rtse_fragment_multiple_tails,
      { "RTSE has multiple tail fragments",
	"rtse.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE,
	NULL, 0x00, "Message has multiple tail fragments", HFILL } },
    { &hf_rtse_fragment_too_long_fragment,
      { "RTSE fragment too long", "rtse.fragment.too_long_fragment",
	FT_BOOLEAN, BASE_NONE, NULL, 0x00, "Message fragment too long",
	HFILL } },
    { &hf_rtse_fragment_error,
      { "RTSE defragmentation error", "rtse.fragment.error", FT_FRAMENUM,
	BASE_NONE, NULL, 0x00, "Message defragmentation error", HFILL } },
    { &hf_rtse_reassembled_in,
      { "Reassembled RTSE in frame", "rtse.reassembled.in", FT_FRAMENUM, BASE_NONE,
	NULL, 0x00, "This RTSE packet is reassembled in this frame", HFILL } },


/*--- Included file: packet-rtse-hfarr.c ---*/
#line 1 "packet-rtse-hfarr.c"
    { &hf_rtse_rtorq_apdu,
      { "rtorq-apdu", "rtse.rtorq_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "rtse.RTORQapdu", HFILL }},
    { &hf_rtse_rtoac_apdu,
      { "rtoac-apdu", "rtse.rtoac_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "rtse.RTOACapdu", HFILL }},
    { &hf_rtse_rtorj_apdu,
      { "rtorj-apdu", "rtse.rtorj_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "rtse.RTORJapdu", HFILL }},
    { &hf_rtse_rttp_apdu,
      { "rttp-apdu", "rtse.rttp_apdu",
        FT_INT32, BASE_DEC, NULL, 0,
        "rtse.RTTPapdu", HFILL }},
    { &hf_rtse_rttr_apdu,
      { "rttr-apdu", "rtse.rttr_apdu",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rtse.RTTRapdu", HFILL }},
    { &hf_rtse_rtab_apdu,
      { "rtab-apdu", "rtse.rtab_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "rtse.RTABapdu", HFILL }},
    { &hf_rtse_checkpointSize,
      { "checkpointSize", "rtse.checkpointSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "rtse.INTEGER", HFILL }},
    { &hf_rtse_windowSize,
      { "windowSize", "rtse.windowSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "rtse.INTEGER", HFILL }},
    { &hf_rtse_dialogueMode,
      { "dialogueMode", "rtse.dialogueMode",
        FT_INT32, BASE_DEC, VALS(rtse_T_dialogueMode_vals), 0,
        "rtse.T_dialogueMode", HFILL }},
    { &hf_rtse_connectionDataRQ,
      { "connectionDataRQ", "rtse.connectionDataRQ",
        FT_UINT32, BASE_DEC, VALS(rtse_ConnectionData_vals), 0,
        "rtse.ConnectionData", HFILL }},
    { &hf_rtse_applicationProtocol,
      { "applicationProtocol", "rtse.applicationProtocol",
        FT_INT32, BASE_DEC, VALS(rtse_T_applicationProtocol_vals), 0,
        "rtse.T_applicationProtocol", HFILL }},
    { &hf_rtse_connectionDataAC,
      { "connectionDataAC", "rtse.connectionDataAC",
        FT_UINT32, BASE_DEC, VALS(rtse_ConnectionData_vals), 0,
        "rtse.ConnectionData", HFILL }},
    { &hf_rtse_refuseReason,
      { "refuseReason", "rtse.refuseReason",
        FT_INT32, BASE_DEC, VALS(rtse_RefuseReason_vals), 0,
        "rtse.RefuseReason", HFILL }},
    { &hf_rtse_userDataRJ,
      { "userDataRJ", "rtse.userDataRJ",
        FT_NONE, BASE_NONE, NULL, 0,
        "rtse.T_userDataRJ", HFILL }},
    { &hf_rtse_abortReason,
      { "abortReason", "rtse.abortReason",
        FT_INT32, BASE_DEC, VALS(rtse_AbortReason_vals), 0,
        "rtse.AbortReason", HFILL }},
    { &hf_rtse_reflectedParameter,
      { "reflectedParameter", "rtse.reflectedParameter",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rtse.BIT_STRING", HFILL }},
    { &hf_rtse_userdataAB,
      { "userdataAB", "rtse.userdataAB",
        FT_NONE, BASE_NONE, NULL, 0,
        "rtse.T_userdataAB", HFILL }},
    { &hf_rtse_open,
      { "open", "rtse.open",
        FT_NONE, BASE_NONE, NULL, 0,
        "rtse.T_open", HFILL }},
    { &hf_rtse_recover,
      { "recover", "rtse.recover",
        FT_NONE, BASE_NONE, NULL, 0,
        "rtse.SessionConnectionIdentifier", HFILL }},
    { &hf_rtse_callingSSuserReference,
      { "callingSSuserReference", "rtse.callingSSuserReference",
        FT_UINT32, BASE_DEC, VALS(rtse_CallingSSuserReference_vals), 0,
        "rtse.CallingSSuserReference", HFILL }},
    { &hf_rtse_commonReference,
      { "commonReference", "rtse.commonReference",
        FT_STRING, BASE_NONE, NULL, 0,
        "rtse.CommonReference", HFILL }},
    { &hf_rtse_additionalReferenceInformation,
      { "additionalReferenceInformation", "rtse.additionalReferenceInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "rtse.AdditionalReferenceInformation", HFILL }},
    { &hf_rtse_t61String,
      { "t61String", "rtse.t61String",
        FT_STRING, BASE_NONE, NULL, 0,
        "rtse.T_t61String", HFILL }},
    { &hf_rtse_octetString,
      { "octetString", "rtse.octetString",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rtse.T_octetString", HFILL }},
    { &hf_rtse_direct_reference,
      { "direct-reference", "rtse.direct_reference",
        FT_OID, BASE_NONE, NULL, 0,
        "rtse.OBJECT_IDENTIFIER", HFILL }},
    { &hf_rtse_indirect_reference,
      { "indirect-reference", "rtse.indirect_reference",
        FT_INT32, BASE_DEC, NULL, 0,
        "rtse.T_indirect_reference", HFILL }},
    { &hf_rtse_data_value_descriptor,
      { "data-value-descriptor", "rtse.data_value_descriptor",
        FT_STRING, BASE_NONE, NULL, 0,
        "rtse.ObjectDescriptor", HFILL }},
    { &hf_rtse_encoding,
      { "encoding", "rtse.encoding",
        FT_UINT32, BASE_DEC, VALS(rtse_T_encoding_vals), 0,
        "rtse.T_encoding", HFILL }},
    { &hf_rtse_single_ASN1_type,
      { "single-ASN1-type", "rtse.single_ASN1_type",
        FT_NONE, BASE_NONE, NULL, 0,
        "rtse.T_single_ASN1_type", HFILL }},
    { &hf_rtse_octet_aligned,
      { "octet-aligned", "rtse.octet_aligned",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rtse.OCTET_STRING", HFILL }},
    { &hf_rtse_arbitrary,
      { "arbitrary", "rtse.arbitrary",
        FT_BYTES, BASE_HEX, NULL, 0,
        "rtse.BIT_STRING", HFILL }},

/*--- End of included file: packet-rtse-hfarr.c ---*/
#line 322 "packet-rtse-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_rtse,
    &ett_rtse_unknown,
    &ett_rtse_fragment,
    &ett_rtse_fragments,

/*--- Included file: packet-rtse-ettarr.c ---*/
#line 1 "packet-rtse-ettarr.c"
    &ett_rtse_RTSE_apdus,
    &ett_rtse_RTORQapdu,
    &ett_rtse_RTOACapdu,
    &ett_rtse_RTORJapdu,
    &ett_rtse_RTABapdu,
    &ett_rtse_ConnectionData,
    &ett_rtse_SessionConnectionIdentifier,
    &ett_rtse_CallingSSuserReference,
    &ett_rtse_EXTERNALt,
    &ett_rtse_T_encoding,

/*--- End of included file: packet-rtse-ettarr.c ---*/
#line 331 "packet-rtse-template.c"
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

  rtse_handle = find_dissector("rtse");
  ros_handle = find_dissector("ros");

}


/*--- proto_reg_handoff_rtse --- */
void proto_reg_handoff_rtse(void) {


}
