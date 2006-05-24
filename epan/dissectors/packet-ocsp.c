/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-ocsp.c                                                            */
/* ../../tools/asn2wrs.py -b -e -p ocsp -c ocsp.cnf -s packet-ocsp-template OCSP.asn */

/* Input file: packet-ocsp-template.c */

#line 1 "packet-ocsp-template.c"
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

#include <stdio.h>
#include <string.h>

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
static int proto_ocsp = -1;
static int hf_ocsp_responseType_id = -1;

/*--- Included file: packet-ocsp-hf.c ---*/
#line 1 "packet-ocsp-hf.c"
static int hf_ocsp_BasicOCSPResponse_PDU = -1;    /* BasicOCSPResponse */
static int hf_ocsp_ArchiveCutoff_PDU = -1;        /* ArchiveCutoff */
static int hf_ocsp_AcceptableResponses_PDU = -1;  /* AcceptableResponses */
static int hf_ocsp_ServiceLocator_PDU = -1;       /* ServiceLocator */
static int hf_ocsp_CrlID_PDU = -1;                /* CrlID */
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
#line 51 "packet-ocsp-template.c"

/* Initialize the subtree pointers */
static gint ett_ocsp = -1;

/*--- Included file: packet-ocsp-ett.c ---*/
#line 1 "packet-ocsp-ett.c"
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
#line 55 "packet-ocsp-template.c"

static const char *responseType_id;



/*--- Included file: packet-ocsp-fn.c ---*/
#line 1 "packet-ocsp-fn.c"
/*--- Fields for imported types ---*/

static int dissect_requestorName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_GeneralName(FALSE, tvb, offset, pinfo, tree, hf_ocsp_requestorName);
}
static int dissect_requestExtensions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Extensions(FALSE, tvb, offset, pinfo, tree, hf_ocsp_requestExtensions);
}
static int dissect_signatureAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_ocsp_signatureAlgorithm);
}
static int dissect_certs_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_Certificate(FALSE, tvb, offset, pinfo, tree, hf_ocsp_certs_item);
}
static int dissect_singleRequestExtensions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Extensions(FALSE, tvb, offset, pinfo, tree, hf_ocsp_singleRequestExtensions);
}
static int dissect_hashAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_ocsp_hashAlgorithm);
}
static int dissect_serialNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_CertificateSerialNumber(FALSE, tvb, offset, pinfo, tree, hf_ocsp_serialNumber);
}
static int dissect_responseExtensions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Extensions(FALSE, tvb, offset, pinfo, tree, hf_ocsp_responseExtensions);
}
static int dissect_byName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Name(FALSE, tvb, offset, pinfo, tree, hf_ocsp_byName);
}
static int dissect_singleExtensions(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Extensions(FALSE, tvb, offset, pinfo, tree, hf_ocsp_singleExtensions);
}
static int dissect_revocationReason(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_CRLReason(FALSE, tvb, offset, pinfo, tree, hf_ocsp_revocationReason);
}
static int dissect_issuer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Name(FALSE, tvb, offset, pinfo, tree, hf_ocsp_issuer);
}
static int dissect_locator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_AuthorityInfoAccessSyntax(FALSE, tvb, offset, pinfo, tree, hf_ocsp_locator);
}


static const value_string ocsp_Version_vals[] = {
  {   0, "v1" },
  { 0, NULL }
};


static int
dissect_ocsp_Version(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_version(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_Version(FALSE, tvb, offset, pinfo, tree, hf_ocsp_version);
}



static int
dissect_ocsp_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_issuerNameHash(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_ocsp_issuerNameHash);
}
static int dissect_issuerKeyHash(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_ocsp_issuerKeyHash);
}


static const ber_sequence_t CertID_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_hashAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_issuerNameHash },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_issuerKeyHash },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serialNumber },
  { 0, 0, 0, NULL }
};

static int
dissect_ocsp_CertID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertID_sequence, hf_index, ett_ocsp_CertID);

  return offset;
}
static int dissect_reqCert(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_CertID(FALSE, tvb, offset, pinfo, tree, hf_ocsp_reqCert);
}
static int dissect_certID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_CertID(FALSE, tvb, offset, pinfo, tree, hf_ocsp_certID);
}


static const ber_sequence_t Request_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_reqCert },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_singleRequestExtensions },
  { 0, 0, 0, NULL }
};

static int
dissect_ocsp_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Request_sequence, hf_index, ett_ocsp_Request);

  return offset;
}
static int dissect_requestList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_Request(FALSE, tvb, offset, pinfo, tree, hf_ocsp_requestList_item);
}


static const ber_sequence_t SEQUENCE_OF_Request_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_requestList_item },
};

static int
dissect_ocsp_SEQUENCE_OF_Request(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_Request_sequence_of, hf_index, ett_ocsp_SEQUENCE_OF_Request);

  return offset;
}
static int dissect_requestList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_SEQUENCE_OF_Request(FALSE, tvb, offset, pinfo, tree, hf_ocsp_requestList);
}


static const ber_sequence_t TBSRequest_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_version },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_requestorName },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_requestList },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_requestExtensions },
  { 0, 0, 0, NULL }
};

static int
dissect_ocsp_TBSRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TBSRequest_sequence, hf_index, ett_ocsp_TBSRequest);

  return offset;
}
static int dissect_tbsRequest(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_TBSRequest(FALSE, tvb, offset, pinfo, tree, hf_ocsp_tbsRequest);
}



static int
dissect_ocsp_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_signature(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_ocsp_signature);
}


static const ber_sequence_t SEQUENCE_OF_Certificate_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certs_item },
};

static int
dissect_ocsp_SEQUENCE_OF_Certificate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_Certificate_sequence_of, hf_index, ett_ocsp_SEQUENCE_OF_Certificate);

  return offset;
}
static int dissect_certs(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_SEQUENCE_OF_Certificate(FALSE, tvb, offset, pinfo, tree, hf_ocsp_certs);
}


static const ber_sequence_t Signature_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signatureAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_signature },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_certs },
  { 0, 0, 0, NULL }
};

static int
dissect_ocsp_Signature(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Signature_sequence, hf_index, ett_ocsp_Signature);

  return offset;
}
static int dissect_optionalSignature(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_Signature(FALSE, tvb, offset, pinfo, tree, hf_ocsp_optionalSignature);
}


static const ber_sequence_t OCSPRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_tbsRequest },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_optionalSignature },
  { 0, 0, 0, NULL }
};

static int
dissect_ocsp_OCSPRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
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
dissect_ocsp_OCSPResponseStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_responseStatus(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_OCSPResponseStatus(FALSE, tvb, offset, pinfo, tree, hf_ocsp_responseStatus);
}



static int
dissect_ocsp_T_responseType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_ocsp_responseType_id, &responseType_id);

  return offset;
}
static int dissect_responseType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_T_responseType(FALSE, tvb, offset, pinfo, tree, hf_ocsp_responseType);
}



static int
dissect_ocsp_T_response(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 36 "ocsp.cnf"
  gint8 class;
  gboolean pc, ind;
  gint32 tag;
  guint32 len;
  /* skip past the T and L  */
  offset = dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
  offset = dissect_ber_length(pinfo, tree, tvb, offset, &len, &ind);
  offset=call_ber_oid_callback(responseType_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_response(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_T_response(FALSE, tvb, offset, pinfo, tree, hf_ocsp_response);
}


static const ber_sequence_t ResponseBytes_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_responseType },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_response },
  { 0, 0, 0, NULL }
};

static int
dissect_ocsp_ResponseBytes(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ResponseBytes_sequence, hf_index, ett_ocsp_ResponseBytes);

  return offset;
}
static int dissect_responseBytes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_ResponseBytes(FALSE, tvb, offset, pinfo, tree, hf_ocsp_responseBytes);
}


static const ber_sequence_t OCSPResponse_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_responseStatus },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_responseBytes },
  { 0, 0, 0, NULL }
};

static int
dissect_ocsp_OCSPResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OCSPResponse_sequence, hf_index, ett_ocsp_OCSPResponse);

  return offset;
}



static int
dissect_ocsp_KeyHash(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_byKey(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_KeyHash(FALSE, tvb, offset, pinfo, tree, hf_ocsp_byKey);
}


static const value_string ocsp_ResponderID_vals[] = {
  {   1, "byName" },
  {   2, "byKey" },
  { 0, NULL }
};

static const ber_choice_t ResponderID_choice[] = {
  {   1, BER_CLASS_CON, 1, 0, dissect_byName },
  {   2, BER_CLASS_CON, 2, 0, dissect_byKey },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ocsp_ResponderID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ResponderID_choice, hf_index, ett_ocsp_ResponderID,
                                 NULL);

  return offset;
}
static int dissect_responderID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_ResponderID(FALSE, tvb, offset, pinfo, tree, hf_ocsp_responderID);
}



static int
dissect_ocsp_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_producedAt(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_ocsp_producedAt);
}
static int dissect_thisUpdate(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_ocsp_thisUpdate);
}
static int dissect_nextUpdate(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_ocsp_nextUpdate);
}
static int dissect_revocationTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_ocsp_revocationTime);
}
static int dissect_crlTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_ocsp_crlTime);
}



static int
dissect_ocsp_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_good_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_NULL(TRUE, tvb, offset, pinfo, tree, hf_ocsp_good);
}


static const ber_sequence_t RevokedInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_revocationTime },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_revocationReason },
  { 0, 0, 0, NULL }
};

static int
dissect_ocsp_RevokedInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   RevokedInfo_sequence, hf_index, ett_ocsp_RevokedInfo);

  return offset;
}
static int dissect_revoked_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_RevokedInfo(TRUE, tvb, offset, pinfo, tree, hf_ocsp_revoked);
}



static int
dissect_ocsp_UnknownInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_unknown_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_UnknownInfo(TRUE, tvb, offset, pinfo, tree, hf_ocsp_unknown);
}


static const value_string ocsp_CertStatus_vals[] = {
  {   0, "good" },
  {   1, "revoked" },
  {   2, "unknown" },
  { 0, NULL }
};

static const ber_choice_t CertStatus_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_good_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_revoked_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_unknown_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_ocsp_CertStatus(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CertStatus_choice, hf_index, ett_ocsp_CertStatus,
                                 NULL);

  return offset;
}
static int dissect_certStatus(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_CertStatus(FALSE, tvb, offset, pinfo, tree, hf_ocsp_certStatus);
}


static const ber_sequence_t SingleResponse_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certID },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_certStatus },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_thisUpdate },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_nextUpdate },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_singleExtensions },
  { 0, 0, 0, NULL }
};

static int
dissect_ocsp_SingleResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SingleResponse_sequence, hf_index, ett_ocsp_SingleResponse);

  return offset;
}
static int dissect_responses_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_SingleResponse(FALSE, tvb, offset, pinfo, tree, hf_ocsp_responses_item);
}


static const ber_sequence_t SEQUENCE_OF_SingleResponse_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_responses_item },
};

static int
dissect_ocsp_SEQUENCE_OF_SingleResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_SingleResponse_sequence_of, hf_index, ett_ocsp_SEQUENCE_OF_SingleResponse);

  return offset;
}
static int dissect_responses(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_SEQUENCE_OF_SingleResponse(FALSE, tvb, offset, pinfo, tree, hf_ocsp_responses);
}


static const ber_sequence_t ResponseData_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_version },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_responderID },
  { BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_producedAt },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_responses },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_responseExtensions },
  { 0, 0, 0, NULL }
};

static int
dissect_ocsp_ResponseData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ResponseData_sequence, hf_index, ett_ocsp_ResponseData);

  return offset;
}
static int dissect_tbsResponseData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_ResponseData(FALSE, tvb, offset, pinfo, tree, hf_ocsp_tbsResponseData);
}


static const ber_sequence_t BasicOCSPResponse_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_tbsResponseData },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_signatureAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_signature },
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_certs },
  { 0, 0, 0, NULL }
};

static int
dissect_ocsp_BasicOCSPResponse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   BasicOCSPResponse_sequence, hf_index, ett_ocsp_BasicOCSPResponse);

  return offset;
}



static int
dissect_ocsp_ArchiveCutoff(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_ocsp_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_AcceptableResponses_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_ocsp_AcceptableResponses_item);
}


static const ber_sequence_t AcceptableResponses_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_AcceptableResponses_item },
};

static int
dissect_ocsp_AcceptableResponses(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      AcceptableResponses_sequence_of, hf_index, ett_ocsp_AcceptableResponses);

  return offset;
}


static const ber_sequence_t ServiceLocator_sequence[] = {
  { BER_CLASS_ANY, -1, BER_FLAGS_NOOWNTAG, dissect_issuer },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_locator },
  { 0, 0, 0, NULL }
};

static int
dissect_ocsp_ServiceLocator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ServiceLocator_sequence, hf_index, ett_ocsp_ServiceLocator);

  return offset;
}



static int
dissect_ocsp_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_crlUrl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_IA5String(FALSE, tvb, offset, pinfo, tree, hf_ocsp_crlUrl);
}



static int
dissect_ocsp_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_crlNum(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ocsp_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_ocsp_crlNum);
}


static const ber_sequence_t CrlID_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_crlUrl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_crlNum },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_crlTime },
  { 0, 0, 0, NULL }
};

static int
dissect_ocsp_CrlID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CrlID_sequence, hf_index, ett_ocsp_CrlID);

  return offset;
}

/*--- PDUs ---*/

static void dissect_BasicOCSPResponse_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ocsp_BasicOCSPResponse(FALSE, tvb, 0, pinfo, tree, hf_ocsp_BasicOCSPResponse_PDU);
}
static void dissect_ArchiveCutoff_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ocsp_ArchiveCutoff(FALSE, tvb, 0, pinfo, tree, hf_ocsp_ArchiveCutoff_PDU);
}
static void dissect_AcceptableResponses_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ocsp_AcceptableResponses(FALSE, tvb, 0, pinfo, tree, hf_ocsp_AcceptableResponses_PDU);
}
static void dissect_ServiceLocator_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ocsp_ServiceLocator(FALSE, tvb, 0, pinfo, tree, hf_ocsp_ServiceLocator_PDU);
}
static void dissect_CrlID_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_ocsp_CrlID(FALSE, tvb, 0, pinfo, tree, hf_ocsp_CrlID_PDU);
}


/*--- End of included file: packet-ocsp-fn.c ---*/
#line 60 "packet-ocsp-template.c"


static int
dissect_ocsp_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "OCSP");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		
		col_add_fstr(pinfo->cinfo, COL_INFO, "Request");
	}


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_ocsp, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_ocsp);
	}

	return dissect_ocsp_OCSPRequest(FALSE, tvb, 0, pinfo, tree, -1);
}


static int
dissect_ocsp_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "OCSP");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		
		col_add_fstr(pinfo->cinfo, COL_INFO, "Response");
	}


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_ocsp, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_ocsp);
	}

	return dissect_ocsp_OCSPResponse(FALSE, tvb, 0, pinfo, tree, -1);
}

/*--- proto_register_ocsp ----------------------------------------------*/
void proto_register_ocsp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_ocsp_responseType_id,
      { "ResponseType Id", "x509af.responseType.id",
        FT_STRING, BASE_NONE, NULL, 0,
        "ResponseType Id", HFILL }},

/*--- Included file: packet-ocsp-hfarr.c ---*/
#line 1 "packet-ocsp-hfarr.c"
    { &hf_ocsp_BasicOCSPResponse_PDU,
      { "BasicOCSPResponse", "ocsp.BasicOCSPResponse",
        FT_NONE, BASE_NONE, NULL, 0,
        "BasicOCSPResponse", HFILL }},
    { &hf_ocsp_ArchiveCutoff_PDU,
      { "ArchiveCutoff", "ocsp.ArchiveCutoff",
        FT_STRING, BASE_NONE, NULL, 0,
        "ArchiveCutoff", HFILL }},
    { &hf_ocsp_AcceptableResponses_PDU,
      { "AcceptableResponses", "ocsp.AcceptableResponses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "AcceptableResponses", HFILL }},
    { &hf_ocsp_ServiceLocator_PDU,
      { "ServiceLocator", "ocsp.ServiceLocator",
        FT_NONE, BASE_NONE, NULL, 0,
        "ServiceLocator", HFILL }},
    { &hf_ocsp_CrlID_PDU,
      { "CrlID", "ocsp.CrlID",
        FT_NONE, BASE_NONE, NULL, 0,
        "CrlID", HFILL }},
    { &hf_ocsp_tbsRequest,
      { "tbsRequest", "ocsp.tbsRequest",
        FT_NONE, BASE_NONE, NULL, 0,
        "OCSPRequest/tbsRequest", HFILL }},
    { &hf_ocsp_optionalSignature,
      { "optionalSignature", "ocsp.optionalSignature",
        FT_NONE, BASE_NONE, NULL, 0,
        "OCSPRequest/optionalSignature", HFILL }},
    { &hf_ocsp_version,
      { "version", "ocsp.version",
        FT_INT32, BASE_DEC, VALS(x509af_Version_vals), 0,
        "", HFILL }},
    { &hf_ocsp_requestorName,
      { "requestorName", "ocsp.requestorName",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "TBSRequest/requestorName", HFILL }},
    { &hf_ocsp_requestList,
      { "requestList", "ocsp.requestList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TBSRequest/requestList", HFILL }},
    { &hf_ocsp_requestList_item,
      { "Item", "ocsp.requestList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "TBSRequest/requestList/_item", HFILL }},
    { &hf_ocsp_requestExtensions,
      { "requestExtensions", "ocsp.requestExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TBSRequest/requestExtensions", HFILL }},
    { &hf_ocsp_signatureAlgorithm,
      { "signatureAlgorithm", "ocsp.signatureAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ocsp_signature,
      { "signature", "ocsp.signature",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_ocsp_certs,
      { "certs", "ocsp.certs",
        FT_UINT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_ocsp_certs_item,
      { "Item", "ocsp.certs_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_ocsp_reqCert,
      { "reqCert", "ocsp.reqCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "Request/reqCert", HFILL }},
    { &hf_ocsp_singleRequestExtensions,
      { "singleRequestExtensions", "ocsp.singleRequestExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Request/singleRequestExtensions", HFILL }},
    { &hf_ocsp_hashAlgorithm,
      { "hashAlgorithm", "ocsp.hashAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertID/hashAlgorithm", HFILL }},
    { &hf_ocsp_issuerNameHash,
      { "issuerNameHash", "ocsp.issuerNameHash",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CertID/issuerNameHash", HFILL }},
    { &hf_ocsp_issuerKeyHash,
      { "issuerKeyHash", "ocsp.issuerKeyHash",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CertID/issuerKeyHash", HFILL }},
    { &hf_ocsp_serialNumber,
      { "serialNumber", "ocsp.serialNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "CertID/serialNumber", HFILL }},
    { &hf_ocsp_responseStatus,
      { "responseStatus", "ocsp.responseStatus",
        FT_UINT32, BASE_DEC, VALS(ocsp_OCSPResponseStatus_vals), 0,
        "OCSPResponse/responseStatus", HFILL }},
    { &hf_ocsp_responseBytes,
      { "responseBytes", "ocsp.responseBytes",
        FT_NONE, BASE_NONE, NULL, 0,
        "OCSPResponse/responseBytes", HFILL }},
    { &hf_ocsp_responseType,
      { "responseType", "ocsp.responseType",
        FT_OID, BASE_NONE, NULL, 0,
        "ResponseBytes/responseType", HFILL }},
    { &hf_ocsp_response,
      { "response", "ocsp.response",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ResponseBytes/response", HFILL }},
    { &hf_ocsp_tbsResponseData,
      { "tbsResponseData", "ocsp.tbsResponseData",
        FT_NONE, BASE_NONE, NULL, 0,
        "BasicOCSPResponse/tbsResponseData", HFILL }},
    { &hf_ocsp_responderID,
      { "responderID", "ocsp.responderID",
        FT_UINT32, BASE_DEC, VALS(ocsp_ResponderID_vals), 0,
        "ResponseData/responderID", HFILL }},
    { &hf_ocsp_producedAt,
      { "producedAt", "ocsp.producedAt",
        FT_STRING, BASE_NONE, NULL, 0,
        "ResponseData/producedAt", HFILL }},
    { &hf_ocsp_responses,
      { "responses", "ocsp.responses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResponseData/responses", HFILL }},
    { &hf_ocsp_responses_item,
      { "Item", "ocsp.responses_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "ResponseData/responses/_item", HFILL }},
    { &hf_ocsp_responseExtensions,
      { "responseExtensions", "ocsp.responseExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResponseData/responseExtensions", HFILL }},
    { &hf_ocsp_byName,
      { "byName", "ocsp.byName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ResponderID/byName", HFILL }},
    { &hf_ocsp_byKey,
      { "byKey", "ocsp.byKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ResponderID/byKey", HFILL }},
    { &hf_ocsp_certID,
      { "certID", "ocsp.certID",
        FT_NONE, BASE_NONE, NULL, 0,
        "SingleResponse/certID", HFILL }},
    { &hf_ocsp_certStatus,
      { "certStatus", "ocsp.certStatus",
        FT_UINT32, BASE_DEC, VALS(ocsp_CertStatus_vals), 0,
        "SingleResponse/certStatus", HFILL }},
    { &hf_ocsp_thisUpdate,
      { "thisUpdate", "ocsp.thisUpdate",
        FT_STRING, BASE_NONE, NULL, 0,
        "SingleResponse/thisUpdate", HFILL }},
    { &hf_ocsp_nextUpdate,
      { "nextUpdate", "ocsp.nextUpdate",
        FT_STRING, BASE_NONE, NULL, 0,
        "SingleResponse/nextUpdate", HFILL }},
    { &hf_ocsp_singleExtensions,
      { "singleExtensions", "ocsp.singleExtensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SingleResponse/singleExtensions", HFILL }},
    { &hf_ocsp_good,
      { "good", "ocsp.good",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertStatus/good", HFILL }},
    { &hf_ocsp_revoked,
      { "revoked", "ocsp.revoked",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertStatus/revoked", HFILL }},
    { &hf_ocsp_unknown,
      { "unknown", "ocsp.unknown",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertStatus/unknown", HFILL }},
    { &hf_ocsp_revocationTime,
      { "revocationTime", "ocsp.revocationTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "RevokedInfo/revocationTime", HFILL }},
    { &hf_ocsp_revocationReason,
      { "revocationReason", "ocsp.revocationReason",
        FT_UINT32, BASE_DEC, VALS(x509ce_CRLReason_vals), 0,
        "RevokedInfo/revocationReason", HFILL }},
    { &hf_ocsp_AcceptableResponses_item,
      { "Item", "ocsp.AcceptableResponses_item",
        FT_OID, BASE_NONE, NULL, 0,
        "AcceptableResponses/_item", HFILL }},
    { &hf_ocsp_issuer,
      { "issuer", "ocsp.issuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServiceLocator/issuer", HFILL }},
    { &hf_ocsp_locator,
      { "locator", "ocsp.locator",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ServiceLocator/locator", HFILL }},
    { &hf_ocsp_crlUrl,
      { "crlUrl", "ocsp.crlUrl",
        FT_STRING, BASE_NONE, NULL, 0,
        "CrlID/crlUrl", HFILL }},
    { &hf_ocsp_crlNum,
      { "crlNum", "ocsp.crlNum",
        FT_INT32, BASE_DEC, NULL, 0,
        "CrlID/crlNum", HFILL }},
    { &hf_ocsp_crlTime,
      { "crlTime", "ocsp.crlTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "CrlID/crlTime", HFILL }},

/*--- End of included file: packet-ocsp-hfarr.c ---*/
#line 121 "packet-ocsp-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_ocsp,

/*--- Included file: packet-ocsp-ettarr.c ---*/
#line 1 "packet-ocsp-ettarr.c"
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
#line 127 "packet-ocsp-template.c"
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
#line 1 "packet-ocsp-dis-tab.c"
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.1", dissect_BasicOCSPResponse_PDU, proto_ocsp, "id-pkix-ocsp-basic");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.3", dissect_CrlID_PDU, proto_ocsp, "id-pkix-ocsp-crl");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.4", dissect_AcceptableResponses_PDU, proto_ocsp, "id-pkix-ocsp-response");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.6", dissect_ArchiveCutoff_PDU, proto_ocsp, "id-pkix-ocsp-archive-cutoff");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1.7", dissect_ServiceLocator_PDU, proto_ocsp, "id-pkix-ocsp-service-locator");


/*--- End of included file: packet-ocsp-dis-tab.c ---*/
#line 150 "packet-ocsp-template.c"
}

