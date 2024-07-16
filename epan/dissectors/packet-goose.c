/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-goose.c                                                             */
/* asn2wrs.py -b -q -L -p goose -c ./goose.cnf -s ./packet-goose-template -D . -O ../.. goose.asn */

/* packet-goose.c
 * Routines for IEC 61850 GOOSE packet dissection
 * Martin Lutz 2008
 *
 * Routines for IEC 61850 R-GOOSE packet dissection
 * Dordije Manojlovic 2020
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/proto_data.h>
#include <epan/etypes.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-acse.h"

#define GOOSE_PNAME  "GOOSE"
#define GOOSE_PSNAME "GOOSE"
#define GOOSE_PFNAME "goose"

#define R_GOOSE_PNAME  "R-GOOSE"
#define R_GOOSE_PSNAME "R-GOOSE"
#define R_GOOSE_PFNAME "r-goose"

void proto_register_goose(void);
void proto_reg_handoff_goose(void);

/* Initialize the protocol and registered fields */
static int proto_goose;
static int proto_r_goose;

static int hf_goose_session_header;
static int hf_goose_spdu_id;
static int hf_goose_session_hdr_length;
static int hf_goose_hdr_length;
static int hf_goose_content_id;
static int hf_goose_spdu_lenth;
static int hf_goose_spdu_num;
static int hf_goose_version;
static int hf_goose_security_info;
static int hf_goose_current_key_t;
static int hf_goose_next_key_t;
static int hf_goose_key_id;
static int hf_goose_init_vec_length;
static int hf_goose_init_vec;
static int hf_goose_session_user_info;
static int hf_goose_payload;
static int hf_goose_payload_length;
static int hf_goose_apdu_tag;
static int hf_goose_apdu_simulation;
static int hf_goose_apdu_appid;
static int hf_goose_apdu_length;
static int hf_goose_padding_tag;
static int hf_goose_padding_length;
static int hf_goose_padding;
static int hf_goose_hmac;
static int hf_goose_appid;
static int hf_goose_length;
static int hf_goose_reserve1;
static int hf_goose_reserve1_s_bit;
static int hf_goose_reserve2;
static int hf_goose_float_value;


/* Bit fields in the Reserved fields */
#define F_RESERVE1_S_BIT  0x8000

/* GOOSE stored data for expert info verifications */
typedef struct _goose_chk_data{
	bool s_bit;
}goose_chk_data_t;
#define GOOSE_CHK_DATA_LEN	(sizeof(goose_chk_data_t))

static expert_field ei_goose_mal_utctime;
static expert_field ei_goose_zero_pdu;
static expert_field ei_goose_invalid_sim;

#define SINGLE_FLOAT_EXP_BITS	8
#define FLOAT_ENC_LENGTH		5

static int hf_goose_gseMngtPdu;                   /* GSEMngtPdu */
static int hf_goose_goosePdu;                     /* IECGoosePdu */
static int hf_goose_stateID;                      /* INTEGER */
static int hf_goose_requestResp;                  /* RequestResponse */
static int hf_goose_requests;                     /* GSEMngtRequests */
static int hf_goose_responses;                    /* GSEMngtResponses */
static int hf_goose_getGoReference;               /* GetReferenceRequestPdu */
static int hf_goose_getGOOSEElementNumber;        /* GetElementRequestPdu */
static int hf_goose_getGsReference;               /* GetReferenceRequestPdu */
static int hf_goose_getGSSEDataOffset;            /* GetElementRequestPdu */
static int hf_goose_gseMngtNotSupported;          /* NULL */
static int hf_goose_gseMngtResponses_GetGOReference;  /* GSEMngtResponsePdu */
static int hf_goose_gseMngtResponses_GetGOOSEElementNumber;  /* GSEMngtResponsePdu */
static int hf_goose_gseMngtResponses_GetGSReference;  /* GSEMngtResponsePdu */
static int hf_goose_gseMngtResponses_GetGSSEDataOffset;  /* GSEMngtResponsePdu */
static int hf_goose_ident;                        /* VisibleString */
static int hf_goose_getReferenceRequest_offset;   /* T_getReferenceRequest_offset */
static int hf_goose_getReferenceRequest_offset_item;  /* INTEGER */
static int hf_goose_references;                   /* T_references */
static int hf_goose_references_item;              /* VisibleString */
static int hf_goose_confRev;                      /* INTEGER */
static int hf_goose_posNeg;                       /* PositiveNegative */
static int hf_goose_responsePositive;             /* T_responsePositive */
static int hf_goose_datSet;                       /* VisibleString */
static int hf_goose_result;                       /* SEQUENCE_OF_RequestResults */
static int hf_goose_result_item;                  /* RequestResults */
static int hf_goose_responseNegative;             /* GlbErrors */
static int hf_goose_offset;                       /* INTEGER */
static int hf_goose_reference;                    /* IA5String */
static int hf_goose_error;                        /* ErrorReason */
static int hf_goose_gocbRef;                      /* VisibleString */
static int hf_goose_timeAllowedtoLive;            /* INTEGER */
static int hf_goose_goID;                         /* VisibleString */
static int hf_goose_t;                            /* UtcTime */
static int hf_goose_stNum;                        /* INTEGER */
static int hf_goose_sqNum;                        /* INTEGER */
static int hf_goose_simulation;                   /* T_simulation */
static int hf_goose_ndsCom;                       /* BOOLEAN */
static int hf_goose_numDatSetEntries;             /* INTEGER */
static int hf_goose_allData;                      /* SEQUENCE_OF_Data */
static int hf_goose_allData_item;                 /* Data */
static int hf_goose_array;                        /* SEQUENCE_OF_Data */
static int hf_goose_array_item;                   /* Data */
static int hf_goose_structure;                    /* SEQUENCE_OF_Data */
static int hf_goose_structure_item;               /* Data */
static int hf_goose_boolean;                      /* BOOLEAN */
static int hf_goose_bit_string;                   /* BIT_STRING */
static int hf_goose_integer;                      /* INTEGER */
static int hf_goose_unsigned;                     /* INTEGER */
static int hf_goose_floating_point;               /* FloatingPoint */
static int hf_goose_real;                         /* REAL */
static int hf_goose_octet_string;                 /* OCTET_STRING */
static int hf_goose_visible_string;               /* VisibleString */
static int hf_goose_binary_time;                  /* TimeOfDay */
static int hf_goose_bcd;                          /* INTEGER */
static int hf_goose_booleanArray;                 /* BIT_STRING */
static int hf_goose_objId;                        /* OBJECT_IDENTIFIER */
static int hf_goose_mMSString;                    /* MMSString */
static int hf_goose_utc_time;                     /* UtcTime */

/* Initialize the subtree pointers */
static int ett_r_goose;
static int ett_session_header;
static int ett_security_info;
static int ett_session_user_info;
static int ett_payload;
static int ett_padding;
static int ett_goose;
static int ett_reserve1;
static int ett_expert_inf_sim;

static int ett_goose_GOOSEpdu;
static int ett_goose_GSEMngtPdu;
static int ett_goose_RequestResponse;
static int ett_goose_GSEMngtRequests;
static int ett_goose_GSEMngtResponses;
static int ett_goose_GetReferenceRequestPdu;
static int ett_goose_T_getReferenceRequest_offset;
static int ett_goose_GetElementRequestPdu;
static int ett_goose_T_references;
static int ett_goose_GSEMngtResponsePdu;
static int ett_goose_PositiveNegative;
static int ett_goose_T_responsePositive;
static int ett_goose_SEQUENCE_OF_RequestResults;
static int ett_goose_RequestResults;
static int ett_goose_IECGoosePdu;
static int ett_goose_SEQUENCE_OF_Data;
static int ett_goose_Data;

/*--- Cyclic dependencies ---*/

/* Data -> Data/array -> Data */
static int dissect_goose_Data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_goose_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_goose_VisibleString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t T_getReferenceRequest_offset_sequence_of[1] = {
  { &hf_goose_getReferenceRequest_offset_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_goose_INTEGER },
};

static int
dissect_goose_T_getReferenceRequest_offset(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_getReferenceRequest_offset_sequence_of, hf_index, ett_goose_T_getReferenceRequest_offset);

  return offset;
}


static const ber_sequence_t GetReferenceRequestPdu_sequence[] = {
  { &hf_goose_ident         , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_goose_VisibleString },
  { &hf_goose_getReferenceRequest_offset, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_goose_T_getReferenceRequest_offset },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_GetReferenceRequestPdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GetReferenceRequestPdu_sequence, hf_index, ett_goose_GetReferenceRequestPdu);

  return offset;
}


static const ber_sequence_t T_references_sequence_of[1] = {
  { &hf_goose_references_item, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_goose_VisibleString },
};

static int
dissect_goose_T_references(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_goose_GetElementRequestPdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_goose_GSEMngtRequests(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GSEMngtRequests_choice, hf_index, ett_goose_GSEMngtRequests,
                                 NULL);

  return offset;
}



static int
dissect_goose_NULL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_goose_IA5String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_goose_ErrorReason(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_goose_RequestResults(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 RequestResults_choice, hf_index, ett_goose_RequestResults,
                                 NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_RequestResults_sequence_of[1] = {
  { &hf_goose_result_item   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_goose_RequestResults },
};

static int
dissect_goose_SEQUENCE_OF_RequestResults(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_goose_T_responsePositive(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_goose_GlbErrors(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_goose_PositiveNegative(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_goose_GSEMngtResponsePdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_goose_GSEMngtResponses(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_goose_RequestResponse(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_goose_GSEMngtPdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   GSEMngtPdu_sequence, hf_index, ett_goose_GSEMngtPdu);

  return offset;
}



static int
dissect_goose_UtcTime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

	uint32_t len;
	uint32_t seconds;
	uint32_t	fraction;
	uint32_t nanoseconds;
	nstime_t ts;
	char *	ptime;

	len = tvb_reported_length_remaining(tvb, offset);

	if(len != 8)
	{
		proto_tree_add_expert(tree, actx->pinfo, &ei_goose_mal_utctime, tvb, offset, len);
		if(hf_index > 0)
		{
			proto_tree_add_string(tree, hf_index, tvb, offset, len, "????");
		}
		return offset;
	}

	seconds = tvb_get_ntohl(tvb, offset);
	fraction = tvb_get_ntoh24(tvb, offset+4) * 0x100; /* Only 3 bytes are recommended */
	nanoseconds = (uint32_t)( ((uint64_t)fraction * UINT64_C(1000000000)) / UINT64_C(0x100000000) ) ;

	ts.secs = seconds;
	ts.nsecs = nanoseconds;

	ptime = abs_time_to_str(actx->pinfo->pool, &ts, ABSOLUTE_TIME_UTC, true);

	if(hf_index > 0)
	{
		proto_tree_add_string(tree, hf_index, tvb, offset, len, ptime);
	}


  return offset;
}



static int
dissect_goose_T_simulation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
	bool value;
	uint32_t len = tvb_reported_length_remaining(tvb, offset);
	int origin_offset = offset;
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, &value);

	if((actx->private_data) && (actx->created_item)){
		goose_chk_data_t *data_chk = (goose_chk_data_t *)actx->private_data;
		proto_tree *expert_inf_tree = NULL;
		/* S bit set and Simulation attribute clear: reject as invalid GOOSE */
		if((data_chk->s_bit == true) && (value == false)){
			/* It really looks better showed as a new subtree */
			expert_inf_tree = proto_item_add_subtree(actx->created_item, ett_expert_inf_sim);
			proto_tree_add_expert(expert_inf_tree, actx->pinfo, &ei_goose_invalid_sim, tvb, origin_offset, len);
		}
	}

  return offset;
}



static int
dissect_goose_BOOLEAN(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Data_sequence_of[1] = {
  { &hf_goose_allData_item  , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_goose_Data },
};

static int
dissect_goose_SEQUENCE_OF_Data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Data_sequence_of, hf_index, ett_goose_SEQUENCE_OF_Data);

  return offset;
}



static int
dissect_goose_BIT_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_goose_FloatingPoint(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {

	int len = tvb_reported_length_remaining(tvb, offset);

	  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

	if ((len == FLOAT_ENC_LENGTH) && (tvb_get_uint8(tvb,0) == SINGLE_FLOAT_EXP_BITS) ){
		/* IEEE 754 single precision floating point */
		proto_item_set_hidden(actx->created_item);
		proto_tree_add_item(tree, hf_goose_float_value, tvb, 1, (FLOAT_ENC_LENGTH-1), ENC_BIG_ENDIAN);
	}


  return offset;
}



static int
dissect_goose_REAL(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_real(implicit_tag, actx, tree, tvb, offset, hf_index,
                               NULL);

  return offset;
}



static int
dissect_goose_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_goose_TimeOfDay(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_goose_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_goose_MMSString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_goose_Data(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  // Data -> Data/array -> Data
  actx->pinfo->dissection_depth += 2;
  increment_dissection_depth(actx->pinfo);
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Data_choice, hf_index, ett_goose_Data,
                                 NULL);

  actx->pinfo->dissection_depth -= 2;
  decrement_dissection_depth(actx->pinfo);
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
  { &hf_goose_simulation    , BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_goose_T_simulation },
  { &hf_goose_confRev       , BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_goose_INTEGER },
  { &hf_goose_ndsCom        , BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_goose_BOOLEAN },
  { &hf_goose_numDatSetEntries, BER_CLASS_CON, 10, BER_FLAGS_IMPLTAG, dissect_goose_INTEGER },
  { &hf_goose_allData       , BER_CLASS_CON, 11, BER_FLAGS_IMPLTAG, dissect_goose_SEQUENCE_OF_Data },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_goose_IECGoosePdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
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
dissect_goose_GOOSEpdu(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 GOOSEpdu_choice, hf_index, ett_goose_GOOSEpdu,
                                 NULL);

  return offset;
}


static dissector_handle_t goose_handle;


#define OSI_SPDU_TUNNELED 0xA0 /* Tunneled */
#define OSI_SPDU_GOOSE    0xA1 /* GOOSE */
#define OSI_SPDU_SV       0xA2 /* Sample Value */
#define OSI_SPDU_MNGT     0xA3 /* Management */

static const value_string ositp_spdu_id[] = {
	{ OSI_SPDU_TUNNELED, "Tunneled" },
	{ OSI_SPDU_GOOSE,    "GOOSE" },
	{ OSI_SPDU_SV,       "Sample value" },
	{ OSI_SPDU_MNGT,     "Management" },
	{ 0,       NULL }
};

#define OSI_PDU_GOOSE     0x81
#define OSI_PDU_SV        0x82
#define OSI_PDU_TUNNELED  0x83
#define OSI_PDU_MNGT      0x84

static const value_string ositp_pdu_id[] = {
	{ OSI_PDU_GOOSE,     "GOOSE" },
	{ OSI_PDU_SV,        "SV" },
	{ OSI_PDU_TUNNELED,  "Tunnel" },
	{ OSI_PDU_MNGT,      "MNGT" },
	{ 0,       NULL }
};

#define APDU_HEADER_SIZE 6

/*
* Dissect GOOSE PDUs inside a PPDU.
*/
static int
dissect_goose(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			  void* data _U_)
{
	uint32_t offset = 0;
	uint32_t old_offset;
	uint32_t length;
	uint32_t reserve1_val;
	proto_item *item = NULL;
	proto_tree *tree = NULL;
	goose_chk_data_t *data_chk = NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	static int * const reserve1_flags[] = {
		&hf_goose_reserve1_s_bit,
		NULL
	};

	asn1_ctx.private_data = wmem_alloc(pinfo->pool, GOOSE_CHK_DATA_LEN);
	data_chk = (goose_chk_data_t *)asn1_ctx.private_data;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, GOOSE_PNAME);
	col_clear(pinfo->cinfo, COL_INFO);

	item = proto_tree_add_item(parent_tree, proto_goose, tvb, 0, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_goose);
	add_ber_encoded_label(tvb, pinfo, parent_tree);


	/* APPID */
	proto_tree_add_item(tree, hf_goose_appid, tvb, offset, 2, ENC_BIG_ENDIAN);

	/* Length */
	proto_tree_add_item_ret_uint(tree, hf_goose_length, tvb, offset + 2, 2,
						ENC_BIG_ENDIAN, &length);

	/* Reserved 1 */
	reserve1_val = tvb_get_uint16(tvb, offset + 4, ENC_BIG_ENDIAN);
	proto_tree_add_bitmask_value(tree, tvb, offset + 4, hf_goose_reserve1, ett_reserve1,
						reserve1_flags, reserve1_val);

	/* Store the header sim value for later expert info checks */
	if(data_chk){
		if(reserve1_val & F_RESERVE1_S_BIT){
			data_chk->s_bit = true;
		}else{
			data_chk->s_bit = false;
		}
	}


	/* Reserved 2 */
	proto_tree_add_item(tree, hf_goose_reserve2, tvb, offset + 6, 2,
						ENC_BIG_ENDIAN);

	offset = 8;
	while (offset < length){
		old_offset = offset;
		offset = dissect_goose_GOOSEpdu(false, tvb, offset, &asn1_ctx , tree, -1);
		if (offset == old_offset) {
			proto_tree_add_expert(tree, pinfo, &ei_goose_zero_pdu, tvb, offset, -1);
			break;
		}
	}

	return tvb_captured_length(tvb);
}

/*
* Dissect RGOOSE PDUs inside ISO 8602/X.234 CLTP ConnecteionLess
* Transport Protocol.
*/
static int
dissect_rgoose(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
			   void* data _U_)
{
	unsigned offset = 0, old_offset = 0;
	uint32_t init_v_length, payload_tag, padding_length, length;
	uint32_t payload_length, apdu_offset = 0, apdu_length, apdu_simulation;
	proto_item *item = NULL;
	proto_tree *tree = NULL, *r_goose_tree = NULL, *sess_user_info_tree = NULL;
	goose_chk_data_t *data_chk = NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);

	asn1_ctx.private_data = wmem_alloc(pinfo->pool, GOOSE_CHK_DATA_LEN);
	data_chk = (goose_chk_data_t *)asn1_ctx.private_data;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, R_GOOSE_PNAME);
	col_clear(pinfo->cinfo, COL_INFO);

	item = proto_tree_add_item(parent_tree, proto_r_goose, tvb, 0, -1, ENC_NA);
	r_goose_tree = proto_item_add_subtree(item, ett_r_goose);

	/* Session header subtree */
	item = proto_tree_add_item(r_goose_tree, hf_goose_session_header, tvb, 0,
							   -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_session_header);

	/* SPDU ID */
	proto_tree_add_item(tree, hf_goose_spdu_id, tvb, offset++, 1,
						ENC_BIG_ENDIAN);
	/* Session header length */
	proto_tree_add_item_ret_uint(tree, hf_goose_session_hdr_length, tvb, offset++, 1,
						ENC_BIG_ENDIAN, &length);
	proto_item_set_len(item, length + 2);

	/* Header content indicator */
	proto_tree_add_item(tree, hf_goose_content_id, tvb, offset++, 1,
						ENC_BIG_ENDIAN);
	/* Length */
	proto_tree_add_item(tree, hf_goose_hdr_length, tvb, offset++, 1,
						ENC_BIG_ENDIAN);
	/* SPDU length */
	proto_tree_add_item(tree, hf_goose_spdu_lenth, tvb, offset, 4,
						ENC_BIG_ENDIAN);
	offset += 4;
	/* SPDU number */
	proto_tree_add_item(tree, hf_goose_spdu_num, tvb, offset, 4,
						ENC_BIG_ENDIAN);
	offset += 4;
	/* Version */
	proto_tree_add_item(tree, hf_goose_version, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	/* Security information subtree */
	item = proto_tree_add_item(tree, hf_goose_security_info, tvb, offset, -1,
							   ENC_NA);
	tree = proto_item_add_subtree(item, ett_security_info);
	/* Time of current key */
	proto_tree_add_item(tree, hf_goose_current_key_t, tvb, offset, 4,
						ENC_BIG_ENDIAN);
	offset += 4;
	/* Time of next key */
	proto_tree_add_item(tree, hf_goose_next_key_t, tvb, offset, 2,
						ENC_BIG_ENDIAN);
	offset += 2;
	/* Key ID */
	proto_tree_add_item(tree, hf_goose_key_id, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset += 4;
	/* Initialization vector length */
	proto_tree_add_item_ret_uint(tree, hf_goose_init_vec_length, tvb, offset++, 1,
						ENC_BIG_ENDIAN, &init_v_length);
	proto_item_set_len(item, init_v_length + 11);

	if (init_v_length > 0) {
		/* Initialization vector bytes */
		proto_tree_add_item(tree, hf_goose_init_vec, tvb, offset, init_v_length,
							ENC_NA);
	}
	offset += init_v_length;

	/* Session user information subtree */
	item = proto_tree_add_item(r_goose_tree, hf_goose_session_user_info, tvb,
							   offset, -1, ENC_NA);
	sess_user_info_tree = proto_item_add_subtree(item, ett_payload);

	/* Payload subtree */
	item = proto_tree_add_item(sess_user_info_tree, hf_goose_payload, tvb,
							   offset, -1, ENC_NA);
	tree = proto_item_add_subtree(item, ett_payload);
	/* Payload length */
	proto_tree_add_item_ret_uint(tree, hf_goose_payload_length, tvb, offset, 4,
						ENC_BIG_ENDIAN, &payload_length);
	offset += 4;

	while (apdu_offset < payload_length){
		/* APDU tag */
		proto_tree_add_item_ret_uint(tree, hf_goose_apdu_tag, tvb, offset++, 1,
							ENC_BIG_ENDIAN, &payload_tag);
		/* Simulation flag */
		proto_tree_add_item_ret_uint(tree, hf_goose_apdu_simulation, tvb, offset++,
							1, ENC_BIG_ENDIAN, &apdu_simulation);
		/* APPID */
		proto_tree_add_item(tree, hf_goose_apdu_appid, tvb, offset, 2,
							ENC_BIG_ENDIAN);
		offset += 2;

		if (payload_tag != OSI_PDU_GOOSE) {
			return tvb_captured_length(tvb);
		}

		/* Store the header sim value for later expert info checks */
		if(data_chk){
			if(apdu_simulation){
				data_chk->s_bit = true;
			}else{
				data_chk->s_bit = false;
			}
		}

		/* APDU length */
		proto_tree_add_item_ret_uint(tree, hf_goose_apdu_length, tvb, offset, 2,
							ENC_BIG_ENDIAN, &apdu_length);

		apdu_offset += (APDU_HEADER_SIZE + apdu_length);
		offset += 2;

		old_offset = offset;
		offset = dissect_goose_GOOSEpdu(false, tvb, offset, &asn1_ctx , tree, -1);
		if (offset == old_offset) {
			proto_tree_add_expert(tree, pinfo, &ei_goose_zero_pdu, tvb, offset, -1);
			break;
		}
	}

	/* Check do we have padding bytes */
	if ((tvb_captured_length(tvb) > offset) &&
		(tvb_get_uint8(tvb, offset) == 0xAF)) {
		/* Padding subtree */
		item = proto_tree_add_item(sess_user_info_tree, hf_goose_padding, tvb,
								   offset, -1, ENC_NA);
		tree = proto_item_add_subtree(item, ett_padding);

		/* Padding tag */
		proto_tree_add_item(tree, hf_goose_padding_tag, tvb, offset++, 1,
							ENC_NA);
		/* Padding length */
		proto_tree_add_item_ret_uint(tree, hf_goose_padding_length, tvb, offset++, 1,
							ENC_BIG_ENDIAN, &padding_length);
		proto_item_set_len(item, padding_length + 1);

		/* Padding bytes */
		proto_tree_add_item(tree, hf_goose_padding, tvb, offset, padding_length,
							ENC_NA);
		offset += padding_length;
	}

	/* Check do we have HMAC bytes */
	if (tvb_captured_length(tvb) > offset) {
		/* HMAC bytes */
		proto_tree_add_item(sess_user_info_tree, hf_goose_hmac, tvb, offset,
			tvb_captured_length(tvb) - offset, ENC_NA);
	}

	return tvb_captured_length(tvb);
}

static bool
dissect_rgoose_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree,
					void *data)
{
	uint8_t spdu;

	/* Check do we have at least min size of Session header bytes */
	if (tvb_captured_length(tvb) < 27) {
		return false;
	}

	/* Is it R-GOOSE? */
	spdu = tvb_get_uint8(tvb, 0);
	if (spdu != OSI_SPDU_GOOSE) {
		return false;
	}

	dissect_rgoose(tvb, pinfo, parent_tree, data);
	return true;
}

/*--- proto_register_goose -------------------------------------------*/
void proto_register_goose(void) {

	/* List of fields */
	static hf_register_info hf[] =
	{
		{ &hf_goose_session_header,
		{ "Session header", "rgoose.session_hdr",
		  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_spdu_id,
		{ "Session identifier", "rgoose.spdu_id",
		  FT_UINT8, BASE_HEX_DEC, VALS(ositp_spdu_id), 0x0, NULL, HFILL }},

		{ &hf_goose_session_hdr_length,
		{ "Session header length", "rgoose.session_hdr_len",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_content_id,
		{ "Common session header identifier", "rgoose.common_session_id",
		  FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_hdr_length,
		{ "Header length", "rgoose.hdr_len",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_spdu_lenth,
		{ "SPDU length", "rgoose.spdu_len",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_spdu_num,
		{ "SPDU number", "rgoose.spdu_num",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_version,
		{ "Version", "rgoose.version",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_security_info,
		{ "Security information", "rgoose.sec_info",
		  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_current_key_t,
		{ "Time of current key", "rgoose.curr_key_t",
		   FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_next_key_t,
		{ "Time of next key", "rgoose.next_key_t",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_key_id,
		{ "Key ID", "rgoose.key_id",
		  FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_init_vec_length,
		{ "Initialization vector length", "rgoose.init_v_len",
		  FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_init_vec,
		{ "Initialization vector", "rgoose.init_v",
		  FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_session_user_info,
		{ "Session user information", "rgoose.session_user_info",
		  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_payload,
		{ "Payload", "rgoose.payload",
		  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_payload_length,
		{ "Payload length", "rgoose.payload_len",
		  FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_apdu_tag,
		{ "Payload type tag", "rgoose.pdu_tag",
		  FT_UINT8, BASE_HEX_DEC, VALS(ositp_pdu_id), 0x0, NULL, HFILL }},

		{ &hf_goose_apdu_simulation,
		{ "Simulation flag", "rgoose.simulation",
		  FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_apdu_appid,
		{ "APPID", "rgoose.appid",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_apdu_length,
		{ "APDU length", "rgoose.apdu_len",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_padding_tag,
		{ "Padding", "rgoose.padding_tag",
		  FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_padding_length,
		{ "Padding length", "rgoose.padding_len",
		  FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_padding,
		{ "Padding", "rgoose.padding",
		  FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_hmac,
		{ "HMAC", "rgoose.hmac",
		  FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_appid,
		{ "APPID", "goose.appid",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_length,
		{ "Length", "goose.length",
		  FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_reserve1,
		{ "Reserved 1", "goose.reserve1",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_reserve1_s_bit,
		{ "Simulated",	"goose.reserve1.s_bit",
		  FT_BOOLEAN, 16, NULL, F_RESERVE1_S_BIT, NULL, HFILL } },

		{ &hf_goose_reserve2,
		{ "Reserved 2", "goose.reserve2",
		  FT_UINT16, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL }},

		{ &hf_goose_float_value,
		{ "float value", "goose.float_value",
		  FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL }},

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
    { &hf_goose_getReferenceRequest_offset,
      { "offset", "goose.getReferenceRequest.offset",
        FT_UINT32, BASE_DEC, NULL, 0,
        "T_getReferenceRequest_offset", HFILL }},
    { &hf_goose_getReferenceRequest_offset_item,
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
    { &hf_goose_simulation,
      { "simulation", "goose.simulation",
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
	};

	/* List of subtrees */
	static int *ett[] = {
		&ett_r_goose,
		&ett_session_header,
		&ett_security_info,
		&ett_session_user_info,
		&ett_payload,
		&ett_padding,
		&ett_goose,
		&ett_reserve1,
		&ett_expert_inf_sim,
    &ett_goose_GOOSEpdu,
    &ett_goose_GSEMngtPdu,
    &ett_goose_RequestResponse,
    &ett_goose_GSEMngtRequests,
    &ett_goose_GSEMngtResponses,
    &ett_goose_GetReferenceRequestPdu,
    &ett_goose_T_getReferenceRequest_offset,
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
	};

	static ei_register_info ei[] = {
		{ &ei_goose_mal_utctime,
		{ "goose.malformed.utctime", PI_MALFORMED, PI_WARN,
		  "BER Error: malformed UTCTime encoding", EXPFILL }},
		{ &ei_goose_zero_pdu,
		{ "goose.zero_pdu", PI_PROTOCOL, PI_ERROR,
		  "Internal error, zero-byte GOOSE PDU", EXPFILL }},
		{ &ei_goose_invalid_sim,
		{ "goose.invalid_sim", PI_PROTOCOL, PI_WARN,
		  "Invalid GOOSE: S bit set and Simulation attribute clear", EXPFILL }},
	};

	expert_module_t* expert_goose;

	/* Register protocol */
	proto_goose = proto_register_protocol(GOOSE_PNAME, GOOSE_PSNAME, GOOSE_PFNAME);
	proto_r_goose = proto_register_protocol(R_GOOSE_PNAME, R_GOOSE_PSNAME, R_GOOSE_PFNAME);

	goose_handle = register_dissector("goose", dissect_goose, proto_goose);

	/* Register fields and subtrees */
	proto_register_field_array(proto_goose, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
	expert_goose = expert_register_protocol(proto_goose);
	expert_register_field_array(expert_goose, ei, array_length(ei));

}

/*--- proto_reg_handoff_goose --- */
void proto_reg_handoff_goose(void) {

	dissector_add_uint("ethertype", ETHERTYPE_IEC61850_GOOSE, goose_handle);

	heur_dissector_add("cltp", dissect_rgoose_heur,
		"R-GOOSE (GOOSE over CLTP)", "rgoose_cltp", proto_goose, HEURISTIC_ENABLE);
}
