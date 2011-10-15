/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-ocsp.c                                                              */
/* ../../tools/asn2wrs.py -b -p ocsp -c ./ocsp.cnf -s ./packet-ocsp-template -D . -O ../../epan/dissectors OCSP.asn */

/* Input file: packet-ocsp-template.c */

#line 1 "../../asn1/ocsp/packet-ocsp-template.c"
/* packet-ocsp.c
 * Routines for Online Certificate Status Protocol (RFC2560) packet dissection
 *  Ronnie Sahlberg 2004
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

#include <asn1.h>

#include "packet-ber.h"
#include "packet-ocsp.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-pkix1implicit.h"
#include "packet-pkix1explicit.h"

#define PNAME  "Online Certificate Status Protocol"
#define PSNAME "OCSP"
#define PFNAME "ocsp"

/* Initialize the protocol and registered fields */
int proto_ocsp = -1;
static int hf_ocsp_responseType_id = -1;

/*--- Included file: packet-ocsp-hf.c ---*/
#line 1 "../../asn1/ocsp/packet-ocsp-hf.c"
static int hf_ocsp_BasicOCSPResponse_PDU = -1;    /* BasicOCSPResponse */
static int hf_ocsp_ArchiveCutoff_PDU = -1;        /* ArchiveCutoff */
static int hf_ocsp_AcceptableResponses_PDU = -1;  /* AcceptableResponses */
static int hf_ocsp_ServiceLocator_PDU = -1;       /* ServiceLocator */
static int hf_ocsp_CrlID_PDU = -1;                /* CrlID */
static int hf_ocsp_NULL_PDU = -1;                 /* NULL */
static int hf_ocsp_tbsRequest = -1;               /* TBSRequest */
static int hf_ocsp_optionalSignature = -1;        /* Signature */
static int hf_ocsp_version = -1;                  /* Version */
static int hf_ocsp_requestorName = -1;            /* GeneralName */
static int hf_ocsp_requestList = -1;              /* SEQUENCE_OF_Request */
static int hf_ocsp_requestList_item = -1;         /* Request */
static int hf_ocsp_requestExtensions = -1;        /* Extensions */
static int hf_ocsp_signatureAlgorithm = -1;       /* AlgorithmIdentifier */
static int hf_ocsp_signature = -1;                /* BIT_STRING */
static int hf_ocsp_certs = -1;                    /* SEQUENCE_OF_Certificate */
static int hf_ocsp_certs_item = -1;               /* Certificate */
static int hf_ocsp_reqCert = -1;                  /* CertID */
static int hf_ocsp_singleRequestExtensions = -1;  /* Extensions */
static int hf_ocsp_hashAlgorithm = -1;            /* AlgorithmIdentifier */
static int hf_ocsp_issuerNameHash = -1;           /* OCTET_STRING */
static int hf_ocsp_issuerKeyHash = -1;            /* OCTET_STRING */
static int hf_ocsp_serialNumber = -1;             /* CertificateSerialNumber */
static int hf_ocsp_responseStatus = -1;           /* OCSPResponseStatus */
static int hf_ocsp_responseBytes = -1;            /* ResponseBytes */
static int hf_ocsp_responseType = -1;             /* T_responseType */
static int hf_ocsp_response = -1;                 /* T_response */
static int hf_ocsp_tbsResponseData = -1;          /* ResponseData */
static int hf_ocsp_responderID = -1;              /* ResponderID */
static int hf_ocsp_producedAt = -1;               /* GeneralizedTime */
static int hf_ocsp_responses = -1;                /* SEQUENCE_OF_SingleResponse */
static int hf_ocsp_responses_item = -1;           /* SingleResponse */
static int hf_ocsp_responseExtensions = -1;       /* Extensions */
static int hf_ocsp_byName = -1;                   /* Name */
static int hf_ocsp_byKey = -1;                    /* KeyHash */
static int hf_ocsp_certID = -1;                   /* CertID */
static int hf_ocsp_certStatus = -1;               /* CertStatus */
static int hf_ocsp_thisUpdate = -1;               /* GeneralizedTime */
static int hf_ocsp_nextUpdate = -1;               /* GeneralizedTime */
static int hf_ocsp_singleExtensions = -1;         /* Extensions */
static int hf_ocsp_good = -1;                     /* NULL */
static int hf_ocsp_revoked = -1;                  /* RevokedInfo */
static int hf_ocsp_unknown = -1;                  /* UnknownInfo */
static int hf_ocsp_revocationTime = -1;           /* GeneralizedTime */
static int hf_ocsp_revocationReason = -1;         /* CRLReason */
static int hf_ocsp_AcceptableResponses_item = -1;  /* OBJECT_IDENTIFIER */
static int hf_ocsp_issuer = -1;                   /* Name */
static int hf_ocsp_locator = -1;                  /* AuthorityInfoAccessSyntax */
static int hf_ocsp_crlUrl = -1;                   /* IA5String */
static int hf_ocsp_crlNum = -1;                   /* INTEGER */
static int hf_ocsp_crlTime = -1;                  /* GeneralizedTime */

/*--- End of included file: packet-ocsp-hf.c ---*/
#line 50 "../../asn1/ocsp/packet-ocsp-template.c"

/* Initialize the subtree pointers */
static gint ett_ocsp = -1;

/*--- Included file: packet-ocsp-ett.c ---*/
#line 1 "../../asn1/ocsp/packet-ocsp-ett.c"
static gint ett_ocsp_OCSPRequest = -1;
static gint ett_ocsp_TBSRequest = -1;
static gint ett_ocsp_SEQUENCE_OF_Request = -1;
static gint ett_ocsp_Signature = -1;
static gint ett_ocsp_SEQUENCE_OF_Certificate = -1;
static gint ett_ocsp_Request = -1;
static gint ett_ocsp_CertID = -1;
static gint ett_ocsp_OCSPResponse = -1;
static gint ett_ocsp_ResponseBytes = -1;
static gint ett_ocsp_BasicOCSPResponse = -1;
static gint ett_ocsp_ResponseData = -1;
static gint ett_ocsp_SEQUENCE_OF_SingleResponse = -1;
static gint ett_ocsp_ResponderID = -1;
static gint ett_ocsp_SingleResponse = -1;
static gint ett_ocsp_CertStatus = -1;
static gint ett_ocsp_RevokedInfo = -1;
static gint ett_ocsp_AcceptableResponses = -1;
static gint ett_ocsp_ServiceLocator = -1;
static gint ett_ocsp_CrlID = -1;

/*--- End of included file: packet-ocsp-ett.c ---*/
#line 54 "../../asn1/ocsp/packet-ocsp-template.c"

static const char *responseType_id;



/*--- Included file: packet-ocsp-fn.c ---*/
#line 1 "../../asn1/ocsp/packet-ocsp-fn.c"

static const value_string ocsp_Version_vals[] = {
  {   0, "v1" },
  { 0, NULL }
};


static int
dissect_ocsp_Version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_ocsp_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t CertID_sequence[] = {
  { &hf_ocsp_hashAlgorithm  , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_ocsp_issuerNameHash , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ocsp_OCTET_STRING },
  { &hf_ocsp_issuerKeyHash  , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ocsp_OCTET_STRING },
  { &hf_ocsp_serialNumber   , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_CertificateSerialNumber },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_CertID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertID_sequence, hf_index, ett_ocsp_CertID);

  return offset;
}


static const ber_sequence_t Request_sequence[] = {
  { &hf_ocsp_reqCert        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_CertID },
  { &hf_ocsp_singleRequestExtensions, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Request_sequence, hf_index, ett_ocsp_Request);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Request_sequence_of[1] = {
  { &hf_ocsp_requestList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_Request },
};

static int
dissect_ocsp_SEQUENCE_OF_Request(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Request_sequence_of, hf_index, ett_ocsp_SEQUENCE_OF_Request);

  return offset;
}


static const ber_sequence_t TBSRequest_sequence[] = {
  { &hf_ocsp_version        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_Version },
  { &hf_ocsp_requestorName  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_GeneralName },
  { &hf_ocsp_requestList    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_SEQUENCE_OF_Request },
  { &hf_ocsp_requestExtensions, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_TBSRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TBSRequest_sequence, hf_index, ett_ocsp_TBSRequest);

  return offset;
}



static int
dissect_ocsp_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_Certificate_sequence_of[1] = {
  { &hf_ocsp_certs_item     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_Certificate },
};

static int
dissect_ocsp_SEQUENCE_OF_Certificate(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_Certificate_sequence_of, hf_index, ett_ocsp_SEQUENCE_OF_Certificate);

  return offset;
}


static const ber_sequence_t Signature_sequence[] = {
  { &hf_ocsp_signatureAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_ocsp_signature      , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_ocsp_BIT_STRING },
  { &hf_ocsp_certs          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_SEQUENCE_OF_Certificate },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_Signature(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Signature_sequence, hf_index, ett_ocsp_Signature);

  return offset;
}


static const ber_sequence_t OCSPRequest_sequence[] = {
  { &hf_ocsp_tbsRequest     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_TBSRequest },
  { &hf_ocsp_optionalSignature, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_Signature },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_OCSPRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OCSPRequest_sequence, hf_index, ett_ocsp_OCSPRequest);

  return offset;
}


static const value_string ocsp_OCSPResponseStatus_vals[] = {
  {   0, "successful" },
  {   1, "malformedRequest" },
  {   2, "internalError" },
  {   3, "tryLater" },
  {   5, "sigRequired" },
  {   6, "unauthorized" },
  { 0, NULL }
};


static int
dissect_ocsp_OCSPResponseStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_ocsp_T_responseType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_ocsp_responseType_id, &responseType_id);

  return offset;
}



static int
dissect_ocsp_T_response(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 38 "../../asn1/ocsp/ocsp.cnf"
  gint8 class;
  gboolean pc, ind;
  gint32 tag;
  guint32 len;
  /* skip past the T and L  */
  offset = dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
  offset = dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, &ind);
  offset=call_ber_oid_callback(responseType_id, tvb, offset, actx->pinfo, tree);



  return offset;
}


static const ber_sequence_t ResponseBytes_sequence[] = {
  { &hf_ocsp_responseType   , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ocsp_T_responseType },
  { &hf_ocsp_response       , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_ocsp_T_response },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_ResponseBytes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResponseBytes_sequence, hf_index, ett_ocsp_ResponseBytes);

  return offset;
}


static const ber_sequence_t OCSPResponse_sequence[] = {
  { &hf_ocsp_responseStatus , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_ocsp_OCSPResponseStatus },
  { &hf_ocsp_responseBytes  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_ResponseBytes },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_ocsp_OCSPResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   OCSPResponse_sequence, hf_index, ett_ocsp_OCSPResponse);

  return offset;
}



static int
dissect_ocsp_KeyHash(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string ocsp_ResponderID_vals[] = {
  {   1, "byName" },
  {   2, "byKey" },
  { 0, NULL }
};

static const ber_choice_t ResponderID_choice[] = {
  {   1, &hf_ocsp_byName         , BER_CLASS_CON, 1, 0, dissect_pkix1explicit_Name },
  {   2, &hf_ocsp_byKey          , BER_CLASS_CON, 2, 0, dissect_ocsp_KeyHash },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_ResponderID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ResponderID_choice, hf_index, ett_ocsp_ResponderID,
                                 NULL);

  return offset;
}



static int
dissect_ocsp_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_ocsp_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t RevokedInfo_sequence[] = {
  { &hf_ocsp_revocationTime , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_ocsp_GeneralizedTime },
  { &hf_ocsp_revocationReason, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509ce_CRLReason },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_RevokedInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   RevokedInfo_sequence, hf_index, ett_ocsp_RevokedInfo);

  return offset;
}



static int
dissect_ocsp_UnknownInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string ocsp_CertStatus_vals[] = {
  {   0, "good" },
  {   1, "revoked" },
  {   2, "unknown" },
  { 0, NULL }
};

static const ber_choice_t CertStatus_choice[] = {
  {   0, &hf_ocsp_good           , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_ocsp_NULL },
  {   1, &hf_ocsp_revoked        , BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_ocsp_RevokedInfo },
  {   2, &hf_ocsp_unknown        , BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_ocsp_UnknownInfo },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_CertStatus(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CertStatus_choice, hf_index, ett_ocsp_CertStatus,
                                 NULL);

  return offset;
}


static const ber_sequence_t SingleResponse_sequence[] = {
  { &hf_ocsp_certID         , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_CertID },
  { &hf_ocsp_certStatus     , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ocsp_CertStatus },
  { &hf_ocsp_thisUpdate     , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_ocsp_GeneralizedTime },
  { &hf_ocsp_nextUpdate     , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_GeneralizedTime },
  { &hf_ocsp_singleExtensions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_SingleResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SingleResponse_sequence, hf_index, ett_ocsp_SingleResponse);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_SingleResponse_sequence_of[1] = {
  { &hf_ocsp_responses_item , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_SingleResponse },
};

static int
dissect_ocsp_SEQUENCE_OF_SingleResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_SingleResponse_sequence_of, hf_index, ett_ocsp_SEQUENCE_OF_SingleResponse);

  return offset;
}


static const ber_sequence_t ResponseData_sequence[] = {
  { &hf_ocsp_version        , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_Version },
  { &hf_ocsp_responderID    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_ocsp_ResponderID },
  { &hf_ocsp_producedAt     , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_ocsp_GeneralizedTime },
  { &hf_ocsp_responses      , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_SEQUENCE_OF_SingleResponse },
  { &hf_ocsp_responseExtensions, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_pkix1explicit_Extensions },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_ResponseData(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ResponseData_sequence, hf_index, ett_ocsp_ResponseData);

  return offset;
}


static const ber_sequence_t BasicOCSPResponse_sequence[] = {
  { &hf_ocsp_tbsResponseData, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_ocsp_ResponseData },
  { &hf_ocsp_signatureAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_ocsp_signature      , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_ocsp_BIT_STRING },
  { &hf_ocsp_certs          , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_SEQUENCE_OF_Certificate },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_BasicOCSPResponse(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BasicOCSPResponse_sequence, hf_index, ett_ocsp_BasicOCSPResponse);

  return offset;
}



static int
dissect_ocsp_ArchiveCutoff(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_ocsp_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t AcceptableResponses_sequence_of[1] = {
  { &hf_ocsp_AcceptableResponses_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ocsp_OBJECT_IDENTIFIER },
};

static int
dissect_ocsp_AcceptableResponses(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AcceptableResponses_sequence_of, hf_index, ett_ocsp_AcceptableResponses);

  return offset;
}


static const ber_sequence_t ServiceLocator_sequence[] = {
  { &hf_ocsp_issuer         , BER_CLASS_ANY, -1, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Name },
  { &hf_ocsp_locator        , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_AuthorityInfoAccessSyntax },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_ServiceLocator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ServiceLocator_sequence, hf_index, ett_ocsp_ServiceLocator);

  return offset;
}



static int
dissect_ocsp_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ocsp_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t CrlID_sequence[] = {
  { &hf_ocsp_crlUrl         , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_ocsp_IA5String },
  { &hf_ocsp_crlNum         , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_ocsp_INTEGER },
  { &hf_ocsp_crlTime        , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_ocsp_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_ocsp_CrlID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CrlID_sequence, hf_index, ett_ocsp_CrlID);

  return offset;
}

/*--- PDUs ---*/

static void dissect_BasicOCSPResponse_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ocsp_BasicOCSPResponse(FALSE, tvb, 0, &asn1_ctx, tree, hf_ocsp_BasicOCSPResponse_PDU);
}
static void dissect_ArchiveCutoff_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ocsp_ArchiveCutoff(FALSE, tvb, 0, &asn1_ctx, tree, hf_ocsp_ArchiveCutoff_PDU);
}
static void dissect_AcceptableResponses_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ocsp_AcceptableResponses(FALSE, tvb, 0, &asn1_ctx, tree, hf_ocsp_AcceptableResponses_PDU);
}
static void dissect_ServiceLocator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ocsp_ServiceLocator(FALSE, tvb, 0, &asn1_ctx, tree, hf_ocsp_ServiceLocator_PDU);
}
static void dissect_CrlID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ocsp_CrlID(FALSE, tvb, 0, &asn1_ctx, tree, hf_ocsp_CrlID_PDU);
}
static void dissect_NULL_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_ocsp_NULL(FALSE, tvb, 0, &asn1_ctx, tree, hf_ocsp_NULL_PDU);
}


/*--- End of included file: packet-ocsp-fn.c ---*/
#line 59 "../../asn1/ocsp/packet-ocsp-template.c"


static int
dissect_ocsp_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "OCSP");

	col_set_str(pinfo->cinfo, COL_INFO, "Request");


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_ocsp, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_ocsp);
	}

	return dissect_ocsp_OCSPRequest(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}


static int
dissect_ocsp_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "OCSP");

	col_set_str(pinfo->cinfo, COL_INFO, "Response");


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_ocsp, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_ocsp);
	}

	return dissect_ocsp_OCSPResponse(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

/*--- proto_register_ocsp ----------------------------------------------*/
void proto_register_ocsp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_ocsp_responseType_id,
      { "ResponseType Id", "x509af.responseType.id",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},

/*--- Included file: packet-ocsp-hfarr.c ---*/
#line 1 "../../asn1/ocsp/packet-ocsp-hfarr.c"
    { &hf_ocsp_BasicOCSPResponse_PDU,
      { "BasicOCSPResponse", "ocsp.BasicOCSPResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_ArchiveCutoff_PDU,
      { "ArchiveCutoff", "ocsp.ArchiveCutoff",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_AcceptableResponses_PDU,
      { "AcceptableResponses", "ocsp.AcceptableResponses",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_ServiceLocator_PDU,
      { "ServiceLocator", "ocsp.ServiceLocator",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_CrlID_PDU,
      { "CrlID", "ocsp.CrlID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_NULL_PDU,
      { "NULL", "ocsp.NULL",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_tbsRequest,
      { "tbsRequest", "ocsp.tbsRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_optionalSignature,
      { "optionalSignature", "ocsp.optionalSignature",
        FT_NONE, BASE_NONE, NULL, 0,
        "Signature", HFILL }},
    { &hf_ocsp_version,
      { "version", "ocsp.version",
        FT_INT32, BASE_DEC, VALS(pkix1explicit_Version_vals), 0,
        NULL, HFILL }},
    { &hf_ocsp_requestorName,
      { "requestorName", "ocsp.requestorName",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "GeneralName", HFILL }},
    { &hf_ocsp_requestList,
      { "requestList", "ocsp.requestList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Request", HFILL }},
    { &hf_ocsp_requestList_item,
      { "Request", "ocsp.Request",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_requestExtensions,
      { "requestExtensions", "ocsp.requestExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_ocsp_signatureAlgorithm,
      { "signatureAlgorithm", "ocsp.signatureAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_ocsp_signature,
      { "signature", "ocsp.signature",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},
    { &hf_ocsp_certs,
      { "certs", "ocsp.certs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_Certificate", HFILL }},
    { &hf_ocsp_certs_item,
      { "Certificate", "ocsp.Certificate",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_reqCert,
      { "reqCert", "ocsp.reqCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertID", HFILL }},
    { &hf_ocsp_singleRequestExtensions,
      { "singleRequestExtensions", "ocsp.singleRequestExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_ocsp_hashAlgorithm,
      { "hashAlgorithm", "ocsp.hashAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_ocsp_issuerNameHash,
      { "issuerNameHash", "ocsp.issuerNameHash",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_ocsp_issuerKeyHash,
      { "issuerKeyHash", "ocsp.issuerKeyHash",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_ocsp_serialNumber,
      { "serialNumber", "ocsp.serialNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "CertificateSerialNumber", HFILL }},
    { &hf_ocsp_responseStatus,
      { "responseStatus", "ocsp.responseStatus",
        FT_UINT32, BASE_DEC, VALS(ocsp_OCSPResponseStatus_vals), 0,
        "OCSPResponseStatus", HFILL }},
    { &hf_ocsp_responseBytes,
      { "responseBytes", "ocsp.responseBytes",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_responseType,
      { "responseType", "ocsp.responseType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_response,
      { "response", "ocsp.response",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_tbsResponseData,
      { "tbsResponseData", "ocsp.tbsResponseData",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResponseData", HFILL }},
    { &hf_ocsp_responderID,
      { "responderID", "ocsp.responderID",
        FT_UINT32, BASE_DEC, VALS(ocsp_ResponderID_vals), 0,
        NULL, HFILL }},
    { &hf_ocsp_producedAt,
      { "producedAt", "ocsp.producedAt",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_ocsp_responses,
      { "responses", "ocsp.responses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_SingleResponse", HFILL }},
    { &hf_ocsp_responses_item,
      { "SingleResponse", "ocsp.SingleResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_responseExtensions,
      { "responseExtensions", "ocsp.responseExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_ocsp_byName,
      { "byName", "ocsp.byName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Name", HFILL }},
    { &hf_ocsp_byKey,
      { "byKey", "ocsp.byKey",
        FT_BYTES, BASE_NONE, NULL, 0,
        "KeyHash", HFILL }},
    { &hf_ocsp_certID,
      { "certID", "ocsp.certID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_certStatus,
      { "certStatus", "ocsp.certStatus",
        FT_UINT32, BASE_DEC, VALS(ocsp_CertStatus_vals), 0,
        NULL, HFILL }},
    { &hf_ocsp_thisUpdate,
      { "thisUpdate", "ocsp.thisUpdate",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_ocsp_nextUpdate,
      { "nextUpdate", "ocsp.nextUpdate",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_ocsp_singleExtensions,
      { "singleExtensions", "ocsp.singleExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Extensions", HFILL }},
    { &hf_ocsp_good,
      { "good", "ocsp.good",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ocsp_revoked,
      { "revoked", "ocsp.revoked",
        FT_NONE, BASE_NONE, NULL, 0,
        "RevokedInfo", HFILL }},
    { &hf_ocsp_unknown,
      { "unknown", "ocsp.unknown",
        FT_NONE, BASE_NONE, NULL, 0,
        "UnknownInfo", HFILL }},
    { &hf_ocsp_revocationTime,
      { "revocationTime", "ocsp.revocationTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_ocsp_revocationReason,
      { "revocationReason", "ocsp.revocationReason",
        FT_UINT32, BASE_DEC, VALS(x509ce_CRLReason_vals), 0,
        "CRLReason", HFILL }},
    { &hf_ocsp_AcceptableResponses_item,
      { "AcceptableResponses item", "ocsp.AcceptableResponses_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_ocsp_issuer,
      { "issuer", "ocsp.issuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Name", HFILL }},
    { &hf_ocsp_locator,
      { "locator", "ocsp.locator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AuthorityInfoAccessSyntax", HFILL }},
    { &hf_ocsp_crlUrl,
      { "crlUrl", "ocsp.crlUrl",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_ocsp_crlNum,
      { "crlNum", "ocsp.crlNum",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_ocsp_crlTime,
      { "crlTime", "ocsp.crlTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},

/*--- End of included file: packet-ocsp-hfarr.c ---*/
#line 114 "../../asn1/ocsp/packet-ocsp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ocsp,

/*--- Included file: packet-ocsp-ettarr.c ---*/
#line 1 "../../asn1/ocsp/packet-ocsp-ettarr.c"
    &ett_ocsp_OCSPRequest,
    &ett_ocsp_TBSRequest,
    &ett_ocsp_SEQUENCE_OF_Request,
    &ett_ocsp_Signature,
    &ett_ocsp_SEQUENCE_OF_Certificate,
    &ett_ocsp_Request,
    &ett_ocsp_CertID,
    &ett_ocsp_OCSPResponse,
    &ett_ocsp_ResponseBytes,
    &ett_ocsp_BasicOCSPResponse,
    &ett_ocsp_ResponseData,
    &ett_ocsp_SEQUENCE_OF_SingleResponse,
    &ett_ocsp_ResponderID,
    &ett_ocsp_SingleResponse,
    &ett_ocsp_CertStatus,
    &ett_ocsp_RevokedInfo,
    &ett_ocsp_AcceptableResponses,
    &ett_ocsp_ServiceLocator,
    &ett_ocsp_CrlID,

/*--- End of included file: packet-ocsp-ettarr.c ---*/
#line 120 "../../asn1/ocsp/packet-ocsp-template.c"
  };

  /* Register protocol */
  proto_ocsp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ocsp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}

/*--- proto_reg_handoff_ocsp -------------------------------------------*/
void proto_reg_handoff_ocsp(void) {
	dissector_handle_t ocsp_request_handle;
	dissector_handle_t ocsp_response_handle;

	ocsp_request_handle = new_create_dissector_handle(dissect_ocsp_request, proto_ocsp);
	ocsp_response_handle = new_create_dissector_handle(dissect_ocsp_response, proto_ocsp);

	dissector_add_string("media_type", "application/ocsp-request", ocsp_request_handle);
	dissector_add_string("media_type", "application/ocsp-response", ocsp_response_handle);


/*--- Included file: packet-ocsp-dis-tab.c ---*/
#line 1 "../../asn1/ocsp/packet-ocsp-dis-tab.c"
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.1", dissect_BasicOCSPResponse_PDU, proto_ocsp, "id-pkix-ocsp-basic");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.3", dissect_CrlID_PDU, proto_ocsp, "id-pkix-ocsp-crl");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.4", dissect_AcceptableResponses_PDU, proto_ocsp, "id-pkix-ocsp-response");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.5", dissect_NULL_PDU, proto_ocsp, "id-pkix-ocsp-nocheck");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.6", dissect_ArchiveCutoff_PDU, proto_ocsp, "id-pkix-ocsp-archive-cutoff");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.7", dissect_ServiceLocator_PDU, proto_ocsp, "id-pkix-ocsp-service-locator");


/*--- End of included file: packet-ocsp-dis-tab.c ---*/
#line 143 "../../asn1/ocsp/packet-ocsp-template.c"
}

