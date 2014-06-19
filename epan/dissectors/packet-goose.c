/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-goose.c                                                             */
/* ../../tools/asn2wrs.py -b -p goose -c ./goose.cnf -s ./packet-goose-template -D . -O ../../epan/dissectors goose.asn */

/* Input file: packet-goose-template.c */

#line 1 "../../asn1/goose/packet-goose-template.c"
/* packet-goose.c
 * Routines for IEC 61850 GOOSE packet dissection
 * Martin Lutz 2008
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/etypes.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-acse.h"

#define PNAME  "GOOSE"
#define PSNAME "GOOSE"
#define PFNAME "goose"

void proto_register_goose(void);
void proto_reg_handoff_goose(void);

/* Initialize the protocol and registered fields */
static int proto_goose = -1;
static int hf_goose_appid = -1;
static int hf_goose_length = -1;
static int hf_goose_reserve1 = -1;
static int hf_goose_reserve2 = -1;

static expert_field ei_goose_mal_utctime = EI_INIT;


/*--- Included file: packet-goose-hf.c ---*/
#line 1 "../../asn1/goose/packet-goose-hf.c"
static int hf_goose_gseMngtPdu = -1;              /* GSEMngtPdu */
static int hf_goose_goosePdu = -1;                /* IECGoosePdu */
static int hf_goose_stateID = -1;                 /* INTEGER */
static int hf_goose_requestResp = -1;             /* RequestResponse */
static int hf_goose_requests = -1;                /* GSEMngtRequests */
static int hf_goose_responses = -1;               /* GSEMngtResponses */
static int hf_goose_getGoReference = -1;          /* GetReferenceRequestPdu */
static int hf_goose_getGOOSEElementNumber = -1;   /* GetElementRequestPdu */
static int hf_goose_getGsReference = -1;          /* GetReferenceRequestPdu */
static int hf_goose_getGSSEDataOffset = -1;       /* GetElementRequestPdu */
static int hf_goose_gseMngtNotSupported = -1;     /* NULL */
static int hf_goose_gseMngtResponses_GetGOReference = -1;  /* GSEMngtResponsePdu */
static int hf_goose_gseMngtResponses_GetGOOSEElementNumber = -1;  /* GSEMngtResponsePdu */
static int hf_goose_gseMngtResponses_GetGSReference = -1;  /* GSEMngtResponsePdu */
static int hf_goose_gseMngtResponses_GetGSSEDataOffset = -1;  /* GSEMngtResponsePdu */
static int hf_goose_ident = -1;                   /* VisibleString */
static int hf_goose_getReferenceRequestPDU_offset = -1;  /* T_getReferenceRequestPDU_offset */
static int hf_goose_getReferenceRequestPDU_offset_item = -1;  /* INTEGER */
static int hf_goose_references = -1;              /* T_references */
static int hf_goose_references_item = -1;         /* VisibleString */
static int hf_goose_confRev = -1;                 /* INTEGER */
static int hf_goose_posNeg = -1;                  /* PositiveNegative */
static int hf_goose_responsePositive = -1;        /* T_responsePositive */
static int hf_goose_datSet = -1;                  /* VisibleString */
static int hf_goose_result = -1;                  /* SEQUENCE_OF_RequestResults */
static int hf_goose_result_item = -1;             /* RequestResults */
static int hf_goose_responseNegative = -1;        /* GlbErrors */
static int hf_goose_offset = -1;                  /* INTEGER */
static int hf_goose_reference = -1;               /* IA5String */
static int hf_goose_error = -1;                   /* ErrorReason */
static int hf_goose_gocbRef = -1;                 /* VisibleString */
static int hf_goose_timeAllowedtoLive = -1;       /* INTEGER */
static int hf_goose_goID = -1;                    /* VisibleString */
static int hf_goose_t = -1;                       /* UtcTime */
static int hf_goose_stNum = -1;                   /* INTEGER */
static int hf_goose_sqNum = -1;                   /* INTEGER */
static int hf_goose_test = -1;                    /* BOOLEAN */
static int hf_goose_ndsCom = -1;                  /* BOOLEAN */
static int hf_goose_numDatSetEntries = -1;        /* INTEGER */
static int hf_goose_allData = -1;                 /* SEQUENCE_OF_Data */
static int hf_goose_allData_item = -1;            /* Data */
static int hf_goose_array = -1;                   /* SEQUENCE_OF_Data */
static int hf_goose_array_item = -1;              /* Data */
static int hf_goose_structure = -1;               /* SEQUENCE_OF_Data */
static int hf_goose_structure_item = -1;          /* Data */
static int hf_goose_boolean = -1;                 /* BOOLEAN */
static int hf_goose_bit_string = -1;              /* BIT_STRING */
static int hf_goose_integer = -1;                 /* INTEGER */
static int hf_goose_unsigned = -1;                /* INTEGER */
static int hf_goose_floating_point = -1;          /* FloatingPoint */
static int hf_goose_real = -1;                    /* REAL */
static int hf_goose_octet_string = -1;            /* OCTET_STRING */
static int hf_goose_visible_string = -1;          /* VisibleString */
static int hf_goose_binary_time = -1;             /* TimeOfDay */
static int hf_goose_bcd = -1;                     /* INTEGER */
static int hf_goose_booleanArray = -1;            /* BIT_STRING */
static int hf_goose_objId = -1;                   /* OBJECT_IDENTIFIER */
static int hf_goose_mMSString = -1;               /* MMSString */
static int hf_goose_utc_time = -1;                /* UtcTime */

/*--- End of included file: packet-goose-hf.c ---*/
#line 52 "../../asn1/goose/packet-goose-template.c"

/* Initialize the subtree pointers */
static int ett_goose = -1;


/*--- Included file: packet-goose-ett.c ---*/
#line 1 "../../asn1/goose/packet-goose-ett.c"
static gint ett_goose_GOOSEpdu = -1;
static gint ett_goose_GSEMngtPdu = -1;
static gint ett_goose_RequestResponse = -1;
static gint ett_goose_GSEMngtRequests = -1;
static gint ett_goose_GSEMngtResponses = -1;
static gint ett_goose_GetReferenceRequestPdu = -1;
static gint ett_goose_T_getReferenceRequestPDU_offset = -1;
static gint ett_goose_GetElementRequestPdu = -1;
static gint ett_goose_T_references = -1;
static gint ett_goose_GSEMngtResponsePdu = -1;
static gint ett_goose_PositiveNegative = -1;
static gint ett_goose_T_responsePositive = -1;
static gint ett_goose_SEQUENCE_OF_RequestResults = -1;
static gint ett_goose_RequestResults = -1;
static gint ett_goose_IECGoosePdu = -1;
static gint ett_goose_SEQUENCE_OF_Data = -1;
static gint ett_goose_Data = -1;

/*--- End of included file: packet-goose-ett.c ---*/
#line 57 "../../asn1/goose/packet-goose-template.c"


/*--- Included file: packet-goose-fn.c ---*/
#line 1 "../../asn1/goose/packet-goose-fn.c"
/*--- Cyclic dependencies ---*/

/* Data -> Data/array -> Data */
static int dissect_goose_Data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_goose_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_goose_VisibleString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t T_getReferenceRequestPDU_offset_sequence_of[1] = {
  { &hf_goose_getReferenceRequestPDU_offset_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_goose_INTEGER },
};

static int
dissect_goose_T_getReferenceRequestPDU_offset(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_getReferenceRequestPDU_offset_sequence_of, hf_index, ett_goose_T_getReferenceRequestPDU_offset);

  return offset;
}


static const ber_sequence_t GetReferenceRequestPdu_sequence[] = {
  { &hf_goose_ident         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_goose_VisibleString },
  { &hf_goose_getReferenceRequestPDU_offset, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_goose_T_getReferenceRequestPDU_offset },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_GetReferenceRequestPdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetReferenceRequestPdu_sequence, hf_index, ett_goose_GetReferenceRequestPdu);

  return offset;
}


static const ber_sequence_t T_references_sequence_of[1] = {
  { &hf_goose_references_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_goose_VisibleString },
};

static int
dissect_goose_T_references(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_references_sequence_of, hf_index, ett_goose_T_references);

  return offset;
}


static const ber_sequence_t GetElementRequestPdu_sequence[] = {
  { &hf_goose_ident         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_goose_VisibleString },
  { &hf_goose_references    , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_goose_T_references },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_GetElementRequestPdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetElementRequestPdu_sequence, hf_index, ett_goose_GetElementRequestPdu);

  return offset;
}


static const value_string goose_GSEMngtRequests_vals[] = {
  {   1, "getGoReference" },
  {   2, "getGOOSEElementNumber" },
  {   3, "getGsReference" },
  {   4, "getGSSEDataOffset" },
  { 0, NULL }
};

static const ber_choice_t GSEMngtRequests_choice[] = {
  {   1, &hf_goose_getGoReference, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_goose_GetReferenceRequestPdu },
  {   2, &hf_goose_getGOOSEElementNumber, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_goose_GetElementRequestPdu },
  {   3, &hf_goose_getGsReference, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_goose_GetReferenceRequestPdu },
  {   4, &hf_goose_getGSSEDataOffset, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_goose_GetElementRequestPdu },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_GSEMngtRequests(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GSEMngtRequests_choice, hf_index, ett_goose_GSEMngtRequests,
                                 NULL);

  return offset;
}



static int
dissect_goose_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_goose_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string goose_ErrorReason_vals[] = {
  {   0, "other" },
  {   1, "notFound" },
  { 0, NULL }
};


static int
dissect_goose_ErrorReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string goose_RequestResults_vals[] = {
  {   0, "offset" },
  {   1, "reference" },
  {   2, "error" },
  { 0, NULL }
};

static const ber_choice_t RequestResults_choice[] = {
  {   0, &hf_goose_offset        , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_goose_INTEGER },
  {   1, &hf_goose_reference     , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_goose_IA5String },
  {   2, &hf_goose_error         , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_goose_ErrorReason },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_RequestResults(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RequestResults_choice, hf_index, ett_goose_RequestResults,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_RequestResults_sequence_of[1] = {
  { &hf_goose_result_item   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_goose_RequestResults },
};

static int
dissect_goose_SEQUENCE_OF_RequestResults(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_RequestResults_sequence_of, hf_index, ett_goose_SEQUENCE_OF_RequestResults);

  return offset;
}


static const ber_sequence_t T_responsePositive_sequence[] = {
  { &hf_goose_datSet        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_goose_VisibleString },
  { &hf_goose_result        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_goose_SEQUENCE_OF_RequestResults },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_T_responsePositive(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_responsePositive_sequence, hf_index, ett_goose_T_responsePositive);

  return offset;
}


static const value_string goose_GlbErrors_vals[] = {
  {   0, "other" },
  {   1, "unknownControlBlock" },
  {   2, "responseTooLarge" },
  {   3, "controlBlockConfigurationError" },
  { 0, NULL }
};


static int
dissect_goose_GlbErrors(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string goose_PositiveNegative_vals[] = {
  {   2, "responsePositive" },
  {   3, "responseNegative" },
  { 0, NULL }
};

static const ber_choice_t PositiveNegative_choice[] = {
  {   2, &hf_goose_responsePositive, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_goose_T_responsePositive },
  {   3, &hf_goose_responseNegative, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_goose_GlbErrors },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_PositiveNegative(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PositiveNegative_choice, hf_index, ett_goose_PositiveNegative,
                                 NULL);

  return offset;
}


static const ber_sequence_t GSEMngtResponsePdu_sequence[] = {
  { &hf_goose_ident         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_goose_VisibleString },
  { &hf_goose_confRev       , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_goose_INTEGER },
  { &hf_goose_posNeg        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_goose_PositiveNegative },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_GSEMngtResponsePdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GSEMngtResponsePdu_sequence, hf_index, ett_goose_GSEMngtResponsePdu);

  return offset;
}


static const value_string goose_GSEMngtResponses_vals[] = {
  {   0, "gseMngtNotSupported" },
  {   1, "getGoReference" },
  {   2, "getGOOSEElementNumber" },
  {   3, "getGsReference" },
  {   4, "getGSSEDataOffset" },
  { 0, NULL }
};

static const ber_choice_t GSEMngtResponses_choice[] = {
  {   0, &hf_goose_gseMngtNotSupported, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_goose_NULL },
  {   1, &hf_goose_gseMngtResponses_GetGOReference, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_goose_GSEMngtResponsePdu },
  {   2, &hf_goose_gseMngtResponses_GetGOOSEElementNumber, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_goose_GSEMngtResponsePdu },
  {   3, &hf_goose_gseMngtResponses_GetGSReference, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_goose_GSEMngtResponsePdu },
  {   4, &hf_goose_gseMngtResponses_GetGSSEDataOffset, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_goose_GSEMngtResponsePdu },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_GSEMngtResponses(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GSEMngtResponses_choice, hf_index, ett_goose_GSEMngtResponses,
                                 NULL);

  return offset;
}


static const value_string goose_RequestResponse_vals[] = {
  {   1, "requests" },
  {   2, "responses" },
  { 0, NULL }
};

static const ber_choice_t RequestResponse_choice[] = {
  {   1, &hf_goose_requests      , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_goose_GSEMngtRequests },
  {   2, &hf_goose_responses     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_goose_GSEMngtResponses },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_RequestResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RequestResponse_choice, hf_index, ett_goose_RequestResponse,
                                 NULL);

  return offset;
}


static const ber_sequence_t GSEMngtPdu_sequence[] = {
  { &hf_goose_stateID       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_goose_INTEGER },
  { &hf_goose_requestResp   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_goose_RequestResponse },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_GSEMngtPdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GSEMngtPdu_sequence, hf_index, ett_goose_GSEMngtPdu);

  return offset;
}



static int
dissect_goose_UtcTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 17 "../../asn1/goose/goose.cnf"

	guint32 len;
	guint32 seconds;
	guint32	fraction;
	guint32 nanoseconds;
	nstime_t ts;
	gchar *	ptime;

	len = tvb_length_remaining(tvb, offset);

	if(len != 8)
	{
		proto_tree_add_expert(tree, actx->pinfo, &ei_goose_mal_utctime, tvb, offset, len);
		if(hf_index >= 0)
		{
			proto_tree_add_string(tree, hf_index, tvb, offset, len, "????");
		}
		return offset;
	}

	seconds = tvb_get_ntohl(tvb, offset);
	fraction = tvb_get_ntoh24(tvb, offset+4) * 0x100; /* Only 3 bytes are recommended */
	nanoseconds = (guint32)( ((guint64)fraction * G_GUINT64_CONSTANT(1000000000)) / G_GUINT64_CONSTANT(0x100000000) ) ;

	ts.secs = seconds;
	ts.nsecs = nanoseconds;

	ptime = abs_time_to_str(wmem_packet_scope(), &ts, ABSOLUTE_TIME_UTC, TRUE);

	if(hf_index >= 0)
	{
		proto_tree_add_string(tree, hf_index, tvb, offset, len, ptime);
	}

	return offset;





  return offset;
}



static int
dissect_goose_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Data_sequence_of[1] = {
  { &hf_goose_allData_item  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_goose_Data },
};

static int
dissect_goose_SEQUENCE_OF_Data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Data_sequence_of, hf_index, ett_goose_SEQUENCE_OF_Data);

  return offset;
}



static int
dissect_goose_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_goose_FloatingPoint(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_goose_REAL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_real(implicit_tag, actx, tree, tvb, offset, hf_index,
                               NULL);

  return offset;
}



static int
dissect_goose_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_goose_TimeOfDay(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_goose_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_goose_MMSString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string goose_Data_vals[] = {
  {   1, "array" },
  {   2, "structure" },
  {   3, "boolean" },
  {   4, "bit-string" },
  {   5, "integer" },
  {   6, "unsigned" },
  {   7, "floating-point" },
  {   8, "real" },
  {   9, "octet-string" },
  {  10, "visible-string" },
  {  12, "binary-time" },
  {  13, "bcd" },
  {  14, "booleanArray" },
  {  15, "objId" },
  {  16, "mMSString" },
  {  17, "utc-time" },
  { 0, NULL }
};

static const ber_choice_t Data_choice[] = {
  {   1, &hf_goose_array         , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_goose_SEQUENCE_OF_Data },
  {   2, &hf_goose_structure     , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_goose_SEQUENCE_OF_Data },
  {   3, &hf_goose_boolean       , BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_goose_BOOLEAN },
  {   4, &hf_goose_bit_string    , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_goose_BIT_STRING },
  {   5, &hf_goose_integer       , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_goose_INTEGER },
  {   6, &hf_goose_unsigned      , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_goose_INTEGER },
  {   7, &hf_goose_floating_point, BER_CLASS_CON, 7, BER_FLAGS_IMPLTAG, dissect_goose_FloatingPoint },
  {   8, &hf_goose_real          , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_goose_REAL },
  {   9, &hf_goose_octet_string  , BER_CLASS_CON, 9, BER_FLAGS_IMPLTAG, dissect_goose_OCTET_STRING },
  {  10, &hf_goose_visible_string, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_goose_VisibleString },
  {  12, &hf_goose_binary_time   , BER_CLASS_CON, 12, BER_FLAGS_IMPLTAG, dissect_goose_TimeOfDay },
  {  13, &hf_goose_bcd           , BER_CLASS_CON, 13, BER_FLAGS_IMPLTAG, dissect_goose_INTEGER },
  {  14, &hf_goose_booleanArray  , BER_CLASS_CON, 14, BER_FLAGS_IMPLTAG, dissect_goose_BIT_STRING },
  {  15, &hf_goose_objId         , BER_CLASS_CON, 15, BER_FLAGS_IMPLTAG, dissect_goose_OBJECT_IDENTIFIER },
  {  16, &hf_goose_mMSString     , BER_CLASS_CON, 16, BER_FLAGS_IMPLTAG, dissect_goose_MMSString },
  {  17, &hf_goose_utc_time      , BER_CLASS_CON, 17, BER_FLAGS_IMPLTAG, dissect_goose_UtcTime },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_Data(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Data_choice, hf_index, ett_goose_Data,
                                 NULL);

  return offset;
}


static const ber_sequence_t IECGoosePdu_sequence[] = {
  { &hf_goose_gocbRef       , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_goose_VisibleString },
  { &hf_goose_timeAllowedtoLive, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_goose_INTEGER },
  { &hf_goose_datSet        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_goose_VisibleString },
  { &hf_goose_goID          , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_goose_VisibleString },
  { &hf_goose_t             , BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_goose_UtcTime },
  { &hf_goose_stNum         , BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_goose_INTEGER },
  { &hf_goose_sqNum         , BER_CLASS_CON, 6, BER_FLAGS_IMPLTAG, dissect_goose_INTEGER },
  { &hf_goose_test          , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_goose_BOOLEAN },
  { &hf_goose_confRev       , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_goose_INTEGER },
  { &hf_goose_ndsCom        , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_goose_BOOLEAN },
  { &hf_goose_numDatSetEntries, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_goose_INTEGER },
  { &hf_goose_allData       , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_goose_SEQUENCE_OF_Data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_IECGoosePdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IECGoosePdu_sequence, hf_index, ett_goose_IECGoosePdu);

  return offset;
}


static const ber_choice_t GOOSEpdu_choice[] = {
  {   0, &hf_goose_gseMngtPdu    , BER_CLASS_APP, 0, BER_FLAGS_IMPLTAG, dissect_goose_GSEMngtPdu },
  {   1, &hf_goose_goosePdu      , BER_CLASS_APP, 1, BER_FLAGS_IMPLTAG, dissect_goose_IECGoosePdu },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_GOOSEpdu(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GOOSEpdu_choice, hf_index, ett_goose_GOOSEpdu,
                                 NULL);

  return offset;
}


/*--- End of included file: packet-goose-fn.c ---*/
#line 59 "../../asn1/goose/packet-goose-template.c"

/*
* Dissect GOOSE PDUs inside a PPDU.
*/
static void
dissect_goose(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	int old_offset;
	guint16 length;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PNAME);
	col_clear(pinfo->cinfo, COL_INFO);

	if (parent_tree){
		item = proto_tree_add_item(parent_tree, proto_goose, tvb, 0, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_goose);


		/* APPID */
		proto_tree_add_item(tree, hf_goose_appid, tvb, offset, 2, ENC_BIG_ENDIAN);

		/* Length */
		length = tvb_get_ntohs(tvb, offset + 2);
		proto_tree_add_item(tree, hf_goose_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);

		/* Reserved 1 */
		proto_tree_add_item(tree, hf_goose_reserve1, tvb, offset + 4, 2, ENC_BIG_ENDIAN);

		/* Reserved 2 */
		proto_tree_add_item(tree, hf_goose_reserve2, tvb, offset + 6, 2, ENC_BIG_ENDIAN);

		offset = 8;
		while (offset < length){
			old_offset = offset;
			offset = dissect_goose_GOOSEpdu(FALSE, tvb, offset, &asn1_ctx , tree, -1);
			if (offset == old_offset) {
				proto_tree_add_text(tree, tvb, offset, -1, "Internal error, zero-byte GOOSE PDU");
				return;
			}
		}
	}
}


/*--- proto_register_goose -------------------------------------------*/
void proto_register_goose(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
  	{ &hf_goose_appid,
	{ "APPID",	"goose.appid", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

  	{ &hf_goose_length,
	{ "Length",	"goose.length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

  	{ &hf_goose_reserve1,
	{ "Reserved 1",	"goose.reserve1", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

  	{ &hf_goose_reserve2,
	{ "Reserved 2",	"goose.reserve2", FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},


/*--- Included file: packet-goose-hfarr.c ---*/
#line 1 "../../asn1/goose/packet-goose-hfarr.c"
    { &hf_goose_gseMngtPdu,
      { "gseMngtPdu", "goose.gseMngtPdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_goose_goosePdu,
      { "goosePdu", "goose.goosePdu_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "IECGoosePdu", HFILL }},
    { &hf_goose_stateID,
      { "stateID", "goose.stateID",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_goose_requestResp,
      { "requestResp", "goose.requestResp",
        FT_UINT32, BASE_DEC, VALS(goose_RequestResponse_vals), 0,
        "RequestResponse", HFILL }},
    { &hf_goose_requests,
      { "requests", "goose.requests",
        FT_UINT32, BASE_DEC, VALS(goose_GSEMngtRequests_vals), 0,
        "GSEMngtRequests", HFILL }},
    { &hf_goose_responses,
      { "responses", "goose.responses",
        FT_UINT32, BASE_DEC, VALS(goose_GSEMngtResponses_vals), 0,
        "GSEMngtResponses", HFILL }},
    { &hf_goose_getGoReference,
      { "getGoReference", "goose.getGoReference_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetReferenceRequestPdu", HFILL }},
    { &hf_goose_getGOOSEElementNumber,
      { "getGOOSEElementNumber", "goose.getGOOSEElementNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetElementRequestPdu", HFILL }},
    { &hf_goose_getGsReference,
      { "getGsReference", "goose.getGsReference_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetReferenceRequestPdu", HFILL }},
    { &hf_goose_getGSSEDataOffset,
      { "getGSSEDataOffset", "goose.getGSSEDataOffset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GetElementRequestPdu", HFILL }},
    { &hf_goose_gseMngtNotSupported,
      { "gseMngtNotSupported", "goose.gseMngtNotSupported_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_goose_gseMngtResponses_GetGOReference,
      { "getGoReference", "goose.getGoReference_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSEMngtResponsePdu", HFILL }},
    { &hf_goose_gseMngtResponses_GetGOOSEElementNumber,
      { "getGOOSEElementNumber", "goose.getGOOSEElementNumber_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSEMngtResponsePdu", HFILL }},
    { &hf_goose_gseMngtResponses_GetGSReference,
      { "getGsReference", "goose.getGsReference_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSEMngtResponsePdu", HFILL }},
    { &hf_goose_gseMngtResponses_GetGSSEDataOffset,
      { "getGSSEDataOffset", "goose.getGSSEDataOffset_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "GSEMngtResponsePdu", HFILL }},
    { &hf_goose_ident,
      { "ident", "goose.ident",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_goose_getReferenceRequestPDU_offset,
      { "offset", "goose.offset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_getReferenceRequestPDU_offset", HFILL }},
    { &hf_goose_getReferenceRequestPDU_offset_item,
      { "offset item", "goose.offset_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_goose_references,
      { "references", "goose.references",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_goose_references_item,
      { "references item", "goose.references_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_goose_confRev,
      { "confRev", "goose.confRev",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_goose_posNeg,
      { "posNeg", "goose.posNeg",
        FT_UINT32, BASE_DEC, VALS(goose_PositiveNegative_vals), 0,
        "PositiveNegative", HFILL }},
    { &hf_goose_responsePositive,
      { "responsePositive", "goose.responsePositive_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_goose_datSet,
      { "datSet", "goose.datSet",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_goose_result,
      { "result", "goose.result",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_RequestResults", HFILL }},
    { &hf_goose_result_item,
      { "RequestResults", "goose.RequestResults",
        FT_UINT32, BASE_DEC, VALS(goose_RequestResults_vals), 0,
        NULL, HFILL }},
    { &hf_goose_responseNegative,
      { "responseNegative", "goose.responseNegative",
        FT_INT32, BASE_DEC, VALS(goose_GlbErrors_vals), 0,
        "GlbErrors", HFILL }},
    { &hf_goose_offset,
      { "offset", "goose.offset",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_goose_reference,
      { "reference", "goose.reference",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_goose_error,
      { "error", "goose.error",
        FT_INT32, BASE_DEC, VALS(goose_ErrorReason_vals), 0,
        "ErrorReason", HFILL }},
    { &hf_goose_gocbRef,
      { "gocbRef", "goose.gocbRef",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_goose_timeAllowedtoLive,
      { "timeAllowedtoLive", "goose.timeAllowedtoLive",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_goose_goID,
      { "goID", "goose.goID",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_goose_t,
      { "t", "goose.t",
        FT_STRING, BASE_NONE, NULL, 0,
        "UtcTime", HFILL }},
    { &hf_goose_stNum,
      { "stNum", "goose.stNum",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_goose_sqNum,
      { "sqNum", "goose.sqNum",
        FT_UINT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_goose_test,
      { "test", "goose.test",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_goose_ndsCom,
      { "ndsCom", "goose.ndsCom",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_goose_numDatSetEntries,
      { "numDatSetEntries", "goose.numDatSetEntries",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_goose_allData,
      { "allData", "goose.allData",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Data", HFILL }},
    { &hf_goose_allData_item,
      { "Data", "goose.Data",
        FT_UINT32, BASE_DEC, VALS(goose_Data_vals), 0,
        NULL, HFILL }},
    { &hf_goose_array,
      { "array", "goose.array",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Data", HFILL }},
    { &hf_goose_array_item,
      { "Data", "goose.Data",
        FT_UINT32, BASE_DEC, VALS(goose_Data_vals), 0,
        NULL, HFILL }},
    { &hf_goose_structure,
      { "structure", "goose.structure",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Data", HFILL }},
    { &hf_goose_structure_item,
      { "Data", "goose.Data",
        FT_UINT32, BASE_DEC, VALS(goose_Data_vals), 0,
        NULL, HFILL }},
    { &hf_goose_boolean,
      { "boolean", "goose.boolean",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_goose_bit_string,
      { "bit-string", "goose.bit_string",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_goose_integer,
      { "integer", "goose.integer",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_goose_unsigned,
      { "unsigned", "goose.unsigned",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_goose_floating_point,
      { "floating-point", "goose.floating_point",
        FT_BYTES, BASE_NONE, NULL, 0,
        "FloatingPoint", HFILL }},
    { &hf_goose_real,
      { "real", "goose.real",
        FT_DOUBLE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_goose_octet_string,
      { "octet-string", "goose.octet_string",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_goose_visible_string,
      { "visible-string", "goose.visible_string",
        FT_STRING, BASE_NONE, NULL, 0,
        "VisibleString", HFILL }},
    { &hf_goose_binary_time,
      { "binary-time", "goose.binary_time",
        FT_BYTES, BASE_NONE, NULL, 0,
        "TimeOfDay", HFILL }},
    { &hf_goose_bcd,
      { "bcd", "goose.bcd",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_goose_booleanArray,
      { "booleanArray", "goose.booleanArray",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_goose_objId,
      { "objId", "goose.objId",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_goose_mMSString,
      { "mMSString", "goose.mMSString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_goose_utc_time,
      { "utc-time", "goose.utc_time",
        FT_STRING, BASE_NONE, NULL, 0,
        "UtcTime", HFILL }},

/*--- End of included file: packet-goose-hfarr.c ---*/
#line 127 "../../asn1/goose/packet-goose-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_goose,

/*--- Included file: packet-goose-ettarr.c ---*/
#line 1 "../../asn1/goose/packet-goose-ettarr.c"
    &ett_goose_GOOSEpdu,
    &ett_goose_GSEMngtPdu,
    &ett_goose_RequestResponse,
    &ett_goose_GSEMngtRequests,
    &ett_goose_GSEMngtResponses,
    &ett_goose_GetReferenceRequestPdu,
    &ett_goose_T_getReferenceRequestPDU_offset,
    &ett_goose_GetElementRequestPdu,
    &ett_goose_T_references,
    &ett_goose_GSEMngtResponsePdu,
    &ett_goose_PositiveNegative,
    &ett_goose_T_responsePositive,
    &ett_goose_SEQUENCE_OF_RequestResults,
    &ett_goose_RequestResults,
    &ett_goose_IECGoosePdu,
    &ett_goose_SEQUENCE_OF_Data,
    &ett_goose_Data,

/*--- End of included file: packet-goose-ettarr.c ---*/
#line 133 "../../asn1/goose/packet-goose-template.c"
  };

  static ei_register_info ei[] = {
     { &ei_goose_mal_utctime, { "goose.malformed.utctime", PI_MALFORMED, PI_WARN, "BER Error: malformed UTCTime encoding", EXPFILL }},
  };

  expert_module_t* expert_goose;

	/* Register protocol */
	proto_goose = proto_register_protocol(PNAME, PSNAME, PFNAME);
	register_dissector("goose", dissect_goose, proto_goose);

	/* Register fields and subtrees */
	proto_register_field_array(proto_goose, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_goose = expert_register_protocol(proto_goose);
	expert_register_field_array(expert_goose, ei, array_length(ei));
}

/*--- proto_reg_handoff_goose --- */
void proto_reg_handoff_goose(void) {

	dissector_handle_t goose_handle;
	goose_handle = find_dissector("goose");

	dissector_add_uint("ethertype", ETHERTYPE_IEC61850_GOOSE, goose_handle);
}
