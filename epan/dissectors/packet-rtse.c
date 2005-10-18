/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-rtse.c                                                            */
/* ../../tools/asn2eth.py -X -b -e -p rtse -c rtse.cnf -s packet-rtse-template rtse.asn */

/* Input file: packet-rtse-template.c */

/* packet-rtse_asn1.c
 * Routines for RTSE packet dissection
 * Graeme Lunt 2005
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

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

static char object_identifier_id[MAX_OID_STR_LEN];
/* indirect_reference, used to pick up the signalling so we know what
   kind of data is transferred in SES_DATA_TRANSFER_PDUs */
static guint32 indir_ref=0;
static guint32 app_proto=0;

static proto_tree *top_tree=NULL;

int dissect_rtse_EXTERNAL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_);



/*--- Included file: packet-rtse-hf.c ---*/

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
static int hf_rtse_t61String = -1;                /* T61String */
static int hf_rtse_octetString = -1;              /* OCTET_STRING */
static int hf_rtse_direct_reference = -1;         /* OBJECT_IDENTIFIER */
static int hf_rtse_indirect_reference = -1;       /* T_indirect_reference */
static int hf_rtse_data_value_descriptor = -1;    /* ObjectDescriptor */
static int hf_rtse_encoding = -1;                 /* T_encoding */
static int hf_rtse_single_ASN1_type = -1;         /* T_single_ASN1_type */
static int hf_rtse_octet_aligned = -1;            /* OCTET_STRING */
static int hf_rtse_arbitrary = -1;                /* BIT_STRING */

/*--- End of included file: packet-rtse-hf.c ---*/


/* Initialize the subtree pointers */
static gint ett_rtse = -1;

/*--- Included file: packet-rtse-ett.c ---*/

static gint ett_rtse_RTSE_apdus = -1;
static gint ett_rtse_RTORQapdu = -1;
static gint ett_rtse_RTOACapdu = -1;
static gint ett_rtse_RTORJapdu = -1;
static gint ett_rtse_RTABapdu = -1;
static gint ett_rtse_ConnectionData = -1;
static gint ett_rtse_SessionConnectionIdentifier = -1;
static gint ett_rtse_CallingSSuserReference = -1;
static gint ett_rtse_EXTERNAL = -1;
static gint ett_rtse_T_encoding = -1;

/*--- End of included file: packet-rtse-ett.c ---*/



static dissector_table_t rtse_oid_dissector_table=NULL;
static GHashTable *oid_table=NULL;
static gint ett_rtse_unknown = -1;

void
register_rtse_oid_dissector_handle(const char *oid, dissector_handle_t dissector, int proto _U_, const char *name)
{
	dissector_add_string("rtse.oid", oid, dissector);
	g_hash_table_insert(oid_table, (gpointer)oid, (gpointer)name);
}

static int
call_rtse_oid_callback(const char *oid, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;

	next_tvb = tvb_new_subset(tvb, offset, tvb_length_remaining(tvb, offset), tvb_reported_length_remaining(tvb, offset));
	if(!dissector_try_string(rtse_oid_dissector_table, oid, next_tvb, pinfo, tree)){
		proto_item *item=NULL;
		proto_tree *next_tree=NULL;

		item=proto_tree_add_text(tree, next_tvb, 0, tvb_length_remaining(tvb, offset), "RTSE: Dissector for OID:%s not implemented. Contact Ethereal developers if you want this supported", oid);
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

/*--- Fields for imported types ---*/




static int
dissect_rtse_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_checkpointSize_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_rtse_checkpointSize);
}
static int dissect_windowSize_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_rtse_windowSize);
}


static const value_string rtse_T_dialogueMode_vals[] = {
  {   0, "monologue" },
  {   1, "twa" },
  { 0, NULL }
};


static int
dissect_rtse_T_dialogueMode(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_dialogueMode_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_T_dialogueMode(TRUE, tvb, offset, pinfo, tree, hf_rtse_dialogueMode);
}



static int
dissect_rtse_T_open(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

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
			oid = find_oid_by_pres_ctx_id(pinfo, session->pres_ctx_id);
		break;
	}
	
	if(!oid) /* XXX: problem here is we haven't decoded the applicationProtocol yet - so we make assumptions! */
		oid = "applicationProtocol.12";

	if(oid) {

		offset = call_rtse_oid_callback(oid, tvb, offset, pinfo, top_tree ? top_tree : tree);
	}

	/* else XXX: need to flag we can't find the presentation context */


  return offset;
}
static int dissect_open(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_T_open(FALSE, tvb, offset, pinfo, tree, hf_rtse_open);
}



static int
dissect_rtse_T61String(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_t61String(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_T61String(FALSE, tvb, offset, pinfo, tree, hf_rtse_t61String);
}



static int
dissect_rtse_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_octetString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_rtse_octetString);
}
static int dissect_octet_aligned_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_rtse_octet_aligned);
}


static const value_string rtse_CallingSSuserReference_vals[] = {
  {   0, "t61String" },
  {   1, "octetString" },
  { 0, NULL }
};

static const ber_choice_t CallingSSuserReference_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_t61String },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_octetString },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_rtse_CallingSSuserReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CallingSSuserReference_choice, hf_index, ett_rtse_CallingSSuserReference,
                                 NULL);

  return offset;
}
static int dissect_callingSSuserReference(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_CallingSSuserReference(FALSE, tvb, offset, pinfo, tree, hf_rtse_callingSSuserReference);
}



static int
dissect_rtse_CommonReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTCTime,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_commonReference(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_CommonReference(FALSE, tvb, offset, pinfo, tree, hf_rtse_commonReference);
}



static int
dissect_rtse_AdditionalReferenceInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_additionalReferenceInformation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_AdditionalReferenceInformation(TRUE, tvb, offset, pinfo, tree, hf_rtse_additionalReferenceInformation);
}


static const ber_sequence_t SessionConnectionIdentifier_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_callingSSuserReference },
  { BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_commonReference },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_additionalReferenceInformation_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_rtse_SessionConnectionIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SessionConnectionIdentifier_sequence, hf_index, ett_rtse_SessionConnectionIdentifier);

  return offset;
}
static int dissect_recover_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_SessionConnectionIdentifier(TRUE, tvb, offset, pinfo, tree, hf_rtse_recover);
}


static const value_string rtse_ConnectionData_vals[] = {
  {   0, "open" },
  {   1, "recover" },
  { 0, NULL }
};

static const ber_choice_t ConnectionData_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_open },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_recover_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_rtse_ConnectionData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ConnectionData_choice, hf_index, ett_rtse_ConnectionData,
                                 NULL);

  return offset;
}
static int dissect_connectionDataRQ(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_ConnectionData(FALSE, tvb, offset, pinfo, tree, hf_rtse_connectionDataRQ);
}
static int dissect_connectionDataAC(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_ConnectionData(FALSE, tvb, offset, pinfo, tree, hf_rtse_connectionDataAC);
}


static const value_string rtse_T_applicationProtocol_vals[] = {
  {  12, "mts-transfer-protocol" },
  {   1, "mts-transfer-protocol-1984" },
  { 0, NULL }
};


static int
dissect_rtse_T_applicationProtocol(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

  offset = dissect_ber_integer(TRUE, pinfo, tree, tvb, offset, hf_index, &app_proto);


  return offset;
}
static int dissect_applicationProtocol_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_T_applicationProtocol(TRUE, tvb, offset, pinfo, tree, hf_rtse_applicationProtocol);
}


static const ber_sequence_t RTORQapdu_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_checkpointSize_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_windowSize_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_dialogueMode_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_NOTCHKTAG, dissect_connectionDataRQ },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_applicationProtocol_impl },
  { 0, 0, 0, NULL }
};

int
dissect_rtse_RTORQapdu(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

  if((session = (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data)) != NULL)
	session->ros_op = (ROS_OP_BIND | ROS_OP_ARGUMENT);

  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RTORQapdu_set, hf_index, ett_rtse_RTORQapdu);



  return offset;
}
static int dissect_rtorq_apdu_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_RTORQapdu(TRUE, tvb, offset, pinfo, tree, hf_rtse_rtorq_apdu);
}


static const ber_sequence_t RTOACapdu_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_checkpointSize_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_windowSize_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_NOTCHKTAG, dissect_connectionDataAC },
  { 0, 0, 0, NULL }
};

int
dissect_rtse_RTOACapdu(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {

  if((session = (struct SESSION_DATA_STRUCTURE*)(pinfo->private_data)) != NULL)
	session->ros_op = (ROS_OP_BIND | ROS_OP_RESULT);

  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RTOACapdu_set, hf_index, ett_rtse_RTOACapdu);



  return offset;
}
static int dissect_rtoac_apdu_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_RTOACapdu(TRUE, tvb, offset, pinfo, tree, hf_rtse_rtoac_apdu);
}


static const value_string rtse_RefuseReason_vals[] = {
  {   0, "rtsBusy" },
  {   1, "cannotRecover" },
  {   2, "validationFailure" },
  {   3, "unacceptableDialogueMode" },
  { 0, NULL }
};


static int
dissect_rtse_RefuseReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_refuseReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_RefuseReason(TRUE, tvb, offset, pinfo, tree, hf_rtse_refuseReason);
}



static int
dissect_rtse_T_userDataRJ(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
/*XXX not implemented yet */


  return offset;
}
static int dissect_userDataRJ(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_T_userDataRJ(FALSE, tvb, offset, pinfo, tree, hf_rtse_userDataRJ);
}


static const ber_sequence_t RTORJapdu_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_refuseReason_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_userDataRJ },
  { 0, 0, 0, NULL }
};

int
dissect_rtse_RTORJapdu(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RTORJapdu_set, hf_index, ett_rtse_RTORJapdu);

  return offset;
}
static int dissect_rtorj_apdu_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_RTORJapdu(TRUE, tvb, offset, pinfo, tree, hf_rtse_rtorj_apdu);
}



static int
dissect_rtse_RTTPapdu(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_rttp_apdu(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_RTTPapdu(FALSE, tvb, offset, pinfo, tree, hf_rtse_rttp_apdu);
}



static int
dissect_rtse_RTTRapdu(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
	tvbuff_t *next_tvb = NULL;

	offset = dissect_ber_octet_string(FALSE, pinfo, tree, tvb, offset, hf_index, &next_tvb);

	if(next_tvb) {

		/* XXX: we should check is this is an EXTERNAL first */

		/* ROS won't do this for us */
		if(session)
			session->ros_op = (ROS_OP_INVOKE | ROS_OP_ARGUMENT);

		offset = dissect_rtse_EXTERNAL(FALSE, next_tvb, 0, pinfo, tree, -1);

	}


  return offset;
}
static int dissect_rttr_apdu(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_RTTRapdu(FALSE, tvb, offset, pinfo, tree, hf_rtse_rttr_apdu);
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
dissect_rtse_AbortReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_abortReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_AbortReason(TRUE, tvb, offset, pinfo, tree, hf_rtse_abortReason);
}



static int
dissect_rtse_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_reflectedParameter_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_BIT_STRING(TRUE, tvb, offset, pinfo, tree, hf_rtse_reflectedParameter);
}
static int dissect_arbitrary_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_BIT_STRING(TRUE, tvb, offset, pinfo, tree, hf_rtse_arbitrary);
}



static int
dissect_rtse_T_userdataAB(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
/*XXX not implemented yet */


  return offset;
}
static int dissect_userdataAB(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_T_userdataAB(FALSE, tvb, offset, pinfo, tree, hf_rtse_userdataAB);
}


static const ber_sequence_t RTABapdu_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_abortReason_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_reflectedParameter_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_userdataAB },
  { 0, 0, 0, NULL }
};

int
dissect_rtse_RTABapdu(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
                              RTABapdu_set, hf_index, ett_rtse_RTABapdu);

  return offset;
}
static int dissect_rtab_apdu_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_RTABapdu(TRUE, tvb, offset, pinfo, tree, hf_rtse_rtab_apdu);
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
  {   0, BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_rtorq_apdu_impl },
  {   1, BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_rtoac_apdu_impl },
  {   2, BER_CLASS_CON, 18, BER_FLAGS_IMPLTAG, dissect_rtorj_apdu_impl },
  {   3, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_rttp_apdu },
  {   4, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_rttr_apdu },
  {   5, BER_CLASS_CON, 22, BER_FLAGS_IMPLTAG, dissect_rtab_apdu_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_rtse_RTSE_apdus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 RTSE_apdus_choice, hf_index, ett_rtse_RTSE_apdus,
                                 NULL);

  return offset;
}



static int
dissect_rtse_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_direct_reference(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_rtse_direct_reference);
}



static int
dissect_rtse_T_indirect_reference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  char *oid;

  offset = dissect_ber_integer(FALSE, pinfo, tree, tvb, offset,
                hf_rtse_indirect_reference,
                &indir_ref);

  /* look up the indirect reference */
  if((oid = find_oid_by_pres_ctx_id(pinfo, indir_ref)) != NULL) {
    g_snprintf(object_identifier_id, MAX_OID_STR_LEN, "%s", oid);
  }
	


  return offset;
}
static int dissect_indirect_reference(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_T_indirect_reference(FALSE, tvb, offset, pinfo, tree, hf_rtse_indirect_reference);
}



static int
dissect_rtse_ObjectDescriptor(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_ObjectDescriptor,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_data_value_descriptor(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_ObjectDescriptor(FALSE, tvb, offset, pinfo, tree, hf_rtse_data_value_descriptor);
}



static int
dissect_rtse_T_single_ASN1_type(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset=call_rtse_oid_callback(object_identifier_id, tvb, offset, pinfo, top_tree);



  return offset;
}
static int dissect_single_ASN1_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_T_single_ASN1_type(FALSE, tvb, offset, pinfo, tree, hf_rtse_single_ASN1_type);
}


static const value_string rtse_T_encoding_vals[] = {
  {   0, "single-ASN1-type" },
  {   1, "octet-aligned" },
  {   2, "arbitrary" },
  { 0, NULL }
};

static const ber_choice_t T_encoding_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_single_ASN1_type },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_octet_aligned_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_arbitrary_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_rtse_T_encoding(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_encoding_choice, hf_index, ett_rtse_T_encoding,
                                 NULL);

  return offset;
}
static int dissect_encoding(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_rtse_T_encoding(FALSE, tvb, offset, pinfo, tree, hf_rtse_encoding);
}


static const ber_sequence_t EXTERNAL_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_direct_reference },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_indirect_reference },
  { BER_CLASS_UNI, BER_UNI_TAG_ObjectDescriptor, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_data_value_descriptor },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_encoding },
  { 0, 0, 0, NULL }
};

int
dissect_rtse_EXTERNAL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  gint8 class;
  gboolean pc, ind_field;
  gint32 tag;
  guint32 len1;

  if(!implicit_tag) {
    /* XXX  asn2eth can not yet handle tagged assignment so for the
     * time being  just remove this tag manually inside the EXTERNAL
     * dissector.
     */
     offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
     offset = get_ber_length(tree, tvb, offset, &len1, &ind_field);
   }

   offset = dissect_ber_sequence(TRUE, pinfo, tree, tvb, offset,
                                EXTERNAL_sequence, hf_index, ett_rtse_EXTERNAL);


  return offset;
}


/*--- End of included file: packet-rtse-fn.c ---*/


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

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_rtse, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_rtse);
	}
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTSE");
  	if (check_col(pinfo->cinfo, COL_INFO))
  		col_clear(pinfo->cinfo, COL_INFO);

	while (tvb_reported_length_remaining(tvb, offset) > 0){
		old_offset=offset;
		offset=dissect_rtse_RTSE_apdus(FALSE, tvb, offset, pinfo , tree, -1);
		if(offset == old_offset){
			proto_tree_add_text(tree, tvb, offset, -1,"Internal error, zero-byte RTSE PDU");
			offset = tvb_length(tvb);
			break;
		}
	}

	top_tree = NULL;
}


/*--- proto_register_rtse -------------------------------------------*/
void proto_register_rtse(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {

/*--- Included file: packet-rtse-hfarr.c ---*/

    { &hf_rtse_rtorq_apdu,
      { "rtorq-apdu", "rtse.rtorq_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTSE-apdus/rtorq-apdu", HFILL }},
    { &hf_rtse_rtoac_apdu,
      { "rtoac-apdu", "rtse.rtoac_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTSE-apdus/rtoac-apdu", HFILL }},
    { &hf_rtse_rtorj_apdu,
      { "rtorj-apdu", "rtse.rtorj_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTSE-apdus/rtorj-apdu", HFILL }},
    { &hf_rtse_rttp_apdu,
      { "rttp-apdu", "rtse.rttp_apdu",
        FT_INT32, BASE_DEC, NULL, 0,
        "RTSE-apdus/rttp-apdu", HFILL }},
    { &hf_rtse_rttr_apdu,
      { "rttr-apdu", "rtse.rttr_apdu",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RTSE-apdus/rttr-apdu", HFILL }},
    { &hf_rtse_rtab_apdu,
      { "rtab-apdu", "rtse.rtab_apdu",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTSE-apdus/rtab-apdu", HFILL }},
    { &hf_rtse_checkpointSize,
      { "checkpointSize", "rtse.checkpointSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rtse_windowSize,
      { "windowSize", "rtse.windowSize",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_rtse_dialogueMode,
      { "dialogueMode", "rtse.dialogueMode",
        FT_INT32, BASE_DEC, VALS(rtse_T_dialogueMode_vals), 0,
        "RTORQapdu/dialogueMode", HFILL }},
    { &hf_rtse_connectionDataRQ,
      { "connectionDataRQ", "rtse.connectionDataRQ",
        FT_UINT32, BASE_DEC, VALS(rtse_ConnectionData_vals), 0,
        "RTORQapdu/connectionDataRQ", HFILL }},
    { &hf_rtse_applicationProtocol,
      { "applicationProtocol", "rtse.applicationProtocol",
        FT_INT32, BASE_DEC, VALS(rtse_T_applicationProtocol_vals), 0,
        "RTORQapdu/applicationProtocol", HFILL }},
    { &hf_rtse_connectionDataAC,
      { "connectionDataAC", "rtse.connectionDataAC",
        FT_UINT32, BASE_DEC, VALS(rtse_ConnectionData_vals), 0,
        "RTOACapdu/connectionDataAC", HFILL }},
    { &hf_rtse_refuseReason,
      { "refuseReason", "rtse.refuseReason",
        FT_INT32, BASE_DEC, VALS(rtse_RefuseReason_vals), 0,
        "RTORJapdu/refuseReason", HFILL }},
    { &hf_rtse_userDataRJ,
      { "userDataRJ", "rtse.userDataRJ",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTORJapdu/userDataRJ", HFILL }},
    { &hf_rtse_abortReason,
      { "abortReason", "rtse.abortReason",
        FT_INT32, BASE_DEC, VALS(rtse_AbortReason_vals), 0,
        "RTABapdu/abortReason", HFILL }},
    { &hf_rtse_reflectedParameter,
      { "reflectedParameter", "rtse.reflectedParameter",
        FT_BYTES, BASE_HEX, NULL, 0,
        "RTABapdu/reflectedParameter", HFILL }},
    { &hf_rtse_userdataAB,
      { "userdataAB", "rtse.userdataAB",
        FT_NONE, BASE_NONE, NULL, 0,
        "RTABapdu/userdataAB", HFILL }},
    { &hf_rtse_open,
      { "open", "rtse.open",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConnectionData/open", HFILL }},
    { &hf_rtse_recover,
      { "recover", "rtse.recover",
        FT_NONE, BASE_NONE, NULL, 0,
        "ConnectionData/recover", HFILL }},
    { &hf_rtse_callingSSuserReference,
      { "callingSSuserReference", "rtse.callingSSuserReference",
        FT_UINT32, BASE_DEC, VALS(rtse_CallingSSuserReference_vals), 0,
        "SessionConnectionIdentifier/callingSSuserReference", HFILL }},
    { &hf_rtse_commonReference,
      { "commonReference", "rtse.commonReference",
        FT_STRING, BASE_NONE, NULL, 0,
        "SessionConnectionIdentifier/commonReference", HFILL }},
    { &hf_rtse_additionalReferenceInformation,
      { "additionalReferenceInformation", "rtse.additionalReferenceInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "SessionConnectionIdentifier/additionalReferenceInformation", HFILL }},
    { &hf_rtse_t61String,
      { "t61String", "rtse.t61String",
        FT_STRING, BASE_NONE, NULL, 0,
        "CallingSSuserReference/t61String", HFILL }},
    { &hf_rtse_octetString,
      { "octetString", "rtse.octetString",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CallingSSuserReference/octetString", HFILL }},
    { &hf_rtse_direct_reference,
      { "direct-reference", "rtse.direct_reference",
        FT_STRING, BASE_NONE, NULL, 0,
        "EXTERNAL/direct-reference", HFILL }},
    { &hf_rtse_indirect_reference,
      { "indirect-reference", "rtse.indirect_reference",
        FT_INT32, BASE_DEC, NULL, 0,
        "EXTERNAL/indirect-reference", HFILL }},
    { &hf_rtse_data_value_descriptor,
      { "data-value-descriptor", "rtse.data_value_descriptor",
        FT_STRING, BASE_NONE, NULL, 0,
        "EXTERNAL/data-value-descriptor", HFILL }},
    { &hf_rtse_encoding,
      { "encoding", "rtse.encoding",
        FT_UINT32, BASE_DEC, VALS(rtse_T_encoding_vals), 0,
        "EXTERNAL/encoding", HFILL }},
    { &hf_rtse_single_ASN1_type,
      { "single-ASN1-type", "rtse.single_ASN1_type",
        FT_NONE, BASE_NONE, NULL, 0,
        "EXTERNAL/encoding/single-ASN1-type", HFILL }},
    { &hf_rtse_octet_aligned,
      { "octet-aligned", "rtse.octet_aligned",
        FT_BYTES, BASE_HEX, NULL, 0,
        "EXTERNAL/encoding/octet-aligned", HFILL }},
    { &hf_rtse_arbitrary,
      { "arbitrary", "rtse.arbitrary",
        FT_BYTES, BASE_HEX, NULL, 0,
        "EXTERNAL/encoding/arbitrary", HFILL }},

/*--- End of included file: packet-rtse-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_rtse,
    &ett_rtse_unknown,

/*--- Included file: packet-rtse-ettarr.c ---*/

    &ett_rtse_RTSE_apdus,
    &ett_rtse_RTORQapdu,
    &ett_rtse_RTOACapdu,
    &ett_rtse_RTORJapdu,
    &ett_rtse_RTABapdu,
    &ett_rtse_ConnectionData,
    &ett_rtse_SessionConnectionIdentifier,
    &ett_rtse_CallingSSuserReference,
    &ett_rtse_EXTERNAL,
    &ett_rtse_T_encoding,

/*--- End of included file: packet-rtse-ettarr.c ---*/

  };

  /* Register protocol */
  proto_rtse = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("rtse", dissect_rtse, proto_rtse);
  /* Register fields and subtrees */
  proto_register_field_array(proto_rtse, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  rtse_oid_dissector_table = register_dissector_table("rtse.oid", "RTSE OID Dissectors", FT_STRING, BASE_NONE);
  oid_table=g_hash_table_new(g_str_hash, g_str_equal);

}


/*--- proto_reg_handoff_rtse --- */
void proto_reg_handoff_rtse(void) {
}
