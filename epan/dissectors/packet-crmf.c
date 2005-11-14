/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-crmf.c                                                            */
/* ../../tools/asn2eth.py -X -b -e -p crmf -c crmf.cnf -s packet-crmf-template CRMF.asn */

/* Input file: packet-crmf-template.c */

/* packet-crmf.c
 * Routines for RFC2511 Certificate Request Message Format packet dissection
 *   Ronnie Sahlberg 2004
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
#include "packet-crmf.h"
#include "packet-cms.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"

#define PNAME  "Certificate Request Message Format"
#define PSNAME "CRMF"
#define PFNAME "crmf"

/* Initialize the protocol and registered fields */
int proto_crmf = -1;
static int hf_crmf_type_oid = -1;

/*--- Included file: packet-crmf-hf.c ---*/

static int hf_crmf_PBMParameter_PDU = -1;         /* PBMParameter */
static int hf_crmf_utcTime = -1;                  /* UTCTime */
static int hf_crmf_generalTime = -1;              /* GeneralizedTime */
static int hf_crmf_CertReqMessages_item = -1;     /* CertReqMsg */
static int hf_crmf_certReq = -1;                  /* CertRequest */
static int hf_crmf_pop = -1;                      /* ProofOfPossession */
static int hf_crmf_regInfo = -1;                  /* SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue */
static int hf_crmf_regInfo_item = -1;             /* AttributeTypeAndValue */
static int hf_crmf_certReqId = -1;                /* INTEGER */
static int hf_crmf_certTemplate = -1;             /* CertTemplate */
static int hf_crmf_controls = -1;                 /* Controls */
static int hf_crmf_version = -1;                  /* Version */
static int hf_crmf_serialNumber = -1;             /* INTEGER */
static int hf_crmf_signingAlg = -1;               /* AlgorithmIdentifier */
static int hf_crmf_template_issuer = -1;          /* Name */
static int hf_crmf_validity = -1;                 /* OptionalValidity */
static int hf_crmf_subject = -1;                  /* Name */
static int hf_crmf_publicKey = -1;                /* SubjectPublicKeyInfo */
static int hf_crmf_issuerUID = -1;                /* UniqueIdentifier */
static int hf_crmf_subjectUID = -1;               /* UniqueIdentifier */
static int hf_crmf_extensions = -1;               /* Extensions */
static int hf_crmf_notBefore = -1;                /* Time */
static int hf_crmf_notAfter = -1;                 /* Time */
static int hf_crmf_Controls_item = -1;            /* AttributeTypeAndValue */
static int hf_crmf_type = -1;                     /* T_type */
static int hf_crmf_value = -1;                    /* T_value */
static int hf_crmf_raVerified = -1;               /* NULL */
static int hf_crmf_signature = -1;                /* POPOSigningKey */
static int hf_crmf_keyEncipherment = -1;          /* POPOPrivKey */
static int hf_crmf_keyAgreement = -1;             /* POPOPrivKey */
static int hf_crmf_poposkInput = -1;              /* POPOSigningKeyInput */
static int hf_crmf_algorithmIdentifier = -1;      /* AlgorithmIdentifier */
static int hf_crmf_sk_signature = -1;             /* BIT_STRING */
static int hf_crmf_authInfo = -1;                 /* T_authInfo */
static int hf_crmf_sender = -1;                   /* GeneralName */
static int hf_crmf_publicKeyMAC = -1;             /* PKMACValue */
static int hf_crmf_algId = -1;                    /* AlgorithmIdentifier */
static int hf_crmf_pkmac_value = -1;              /* BIT_STRING */
static int hf_crmf_salt = -1;                     /* OCTET_STRING */
static int hf_crmf_owf = -1;                      /* AlgorithmIdentifier */
static int hf_crmf_iterationCount = -1;           /* INTEGER */
static int hf_crmf_mac = -1;                      /* AlgorithmIdentifier */
static int hf_crmf_thisMessage = -1;              /* BIT_STRING */
static int hf_crmf_subsequentMessage = -1;        /* SubsequentMessage */
static int hf_crmf_dhMAC = -1;                    /* BIT_STRING */
static int hf_crmf_action = -1;                   /* T_action */
static int hf_crmf_pubInfos = -1;                 /* SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo */
static int hf_crmf_pubInfos_item = -1;            /* SinglePubInfo */
static int hf_crmf_pubMethod = -1;                /* T_pubMethod */
static int hf_crmf_pubLocation = -1;              /* GeneralName */
static int hf_crmf_encryptedPrivKey = -1;         /* EncryptedKey */
static int hf_crmf_keyGenParameters = -1;         /* KeyGenParameters */
static int hf_crmf_archiveRemGenPrivKey = -1;     /* BOOLEAN */
static int hf_crmf_encryptedValue = -1;           /* EncryptedValue */
static int hf_crmf_envelopedData = -1;            /* EnvelopedData */
static int hf_crmf_intendedAlg = -1;              /* AlgorithmIdentifier */
static int hf_crmf_symmAlg = -1;                  /* AlgorithmIdentifier */
static int hf_crmf_encSymmKey = -1;               /* BIT_STRING */
static int hf_crmf_keyAlg = -1;                   /* AlgorithmIdentifier */
static int hf_crmf_valueHint = -1;                /* OCTET_STRING */
static int hf_crmf_encValue = -1;                 /* BIT_STRING */
static int hf_crmf_issuer = -1;                   /* GeneralName */

/*--- End of included file: packet-crmf-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-crmf-ett.c ---*/

static gint ett_crmf_Time = -1;
static gint ett_crmf_CertReqMessages = -1;
static gint ett_crmf_CertReqMsg = -1;
static gint ett_crmf_SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue = -1;
static gint ett_crmf_CertRequest = -1;
static gint ett_crmf_CertTemplate = -1;
static gint ett_crmf_OptionalValidity = -1;
static gint ett_crmf_Controls = -1;
static gint ett_crmf_AttributeTypeAndValue = -1;
static gint ett_crmf_ProofOfPossession = -1;
static gint ett_crmf_POPOSigningKey = -1;
static gint ett_crmf_POPOSigningKeyInput = -1;
static gint ett_crmf_T_authInfo = -1;
static gint ett_crmf_PKMACValue = -1;
static gint ett_crmf_PBMParameter = -1;
static gint ett_crmf_POPOPrivKey = -1;
static gint ett_crmf_PKIPublicationInfo = -1;
static gint ett_crmf_SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo = -1;
static gint ett_crmf_SinglePubInfo = -1;
static gint ett_crmf_PKIArchiveOptions = -1;
static gint ett_crmf_EncryptedKey = -1;
static gint ett_crmf_EncryptedValue = -1;
static gint ett_crmf_CertId = -1;

/*--- End of included file: packet-crmf-ett.c ---*/


static const char *object_identifier_id;


/*--- Included file: packet-crmf-fn.c ---*/

/*--- Fields for imported types ---*/

static int dissect_signingAlg_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(TRUE, tvb, offset, pinfo, tree, hf_crmf_signingAlg);
}
static int dissect_template_issuer_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Name(TRUE, tvb, offset, pinfo, tree, hf_crmf_template_issuer);
}
static int dissect_subject_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Name(TRUE, tvb, offset, pinfo, tree, hf_crmf_subject);
}
static int dissect_publicKey(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_SubjectPublicKeyInfo(FALSE, tvb, offset, pinfo, tree, hf_crmf_publicKey);
}
static int dissect_publicKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_SubjectPublicKeyInfo(TRUE, tvb, offset, pinfo, tree, hf_crmf_publicKey);
}
static int dissect_extensions_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Extensions(TRUE, tvb, offset, pinfo, tree, hf_crmf_extensions);
}
static int dissect_algorithmIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_crmf_algorithmIdentifier);
}
static int dissect_sender_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_GeneralName(TRUE, tvb, offset, pinfo, tree, hf_crmf_sender);
}
static int dissect_algId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_crmf_algId);
}
static int dissect_owf(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_crmf_owf);
}
static int dissect_mac(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_crmf_mac);
}
static int dissect_pubLocation(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_GeneralName(FALSE, tvb, offset, pinfo, tree, hf_crmf_pubLocation);
}
static int dissect_envelopedData_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_EnvelopedData(TRUE, tvb, offset, pinfo, tree, hf_crmf_envelopedData);
}
static int dissect_intendedAlg_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(TRUE, tvb, offset, pinfo, tree, hf_crmf_intendedAlg);
}
static int dissect_symmAlg_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(TRUE, tvb, offset, pinfo, tree, hf_crmf_symmAlg);
}
static int dissect_keyAlg_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(TRUE, tvb, offset, pinfo, tree, hf_crmf_keyAlg);
}
static int dissect_issuer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1implicit_GeneralName(FALSE, tvb, offset, pinfo, tree, hf_crmf_issuer);
}


static const value_string crmf_Version_vals[] = {
  {   0, "v1" },
  {   1, "v2" },
  {   2, "v3" },
  { 0, NULL }
};


static int
dissect_crmf_Version(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_version_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_Version(TRUE, tvb, offset, pinfo, tree, hf_crmf_version);
}



static int
dissect_crmf_UniqueIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_issuerUID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_UniqueIdentifier(TRUE, tvb, offset, pinfo, tree, hf_crmf_issuerUID);
}
static int dissect_subjectUID_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_UniqueIdentifier(TRUE, tvb, offset, pinfo, tree, hf_crmf_subjectUID);
}



static int
dissect_crmf_UTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTCTime,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_utcTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_UTCTime(FALSE, tvb, offset, pinfo, tree, hf_crmf_utcTime);
}



static int
dissect_crmf_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_generalTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_crmf_generalTime);
}


static const value_string crmf_Time_vals[] = {
  {   0, "utcTime" },
  {   1, "generalTime" },
  { 0, NULL }
};

static const ber_choice_t Time_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_UTCTime, BER_FLAGS_NOOWNTAG, dissect_utcTime },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_generalTime },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_crmf_Time(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Time_choice, hf_index, ett_crmf_Time,
                                 NULL);

  return offset;
}
static int dissect_notBefore_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_Time(TRUE, tvb, offset, pinfo, tree, hf_crmf_notBefore);
}
static int dissect_notAfter_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_Time(TRUE, tvb, offset, pinfo, tree, hf_crmf_notAfter);
}



static int
dissect_crmf_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_certReqId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_crmf_certReqId);
}
static int dissect_serialNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_crmf_serialNumber);
}
static int dissect_serialNumber_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_INTEGER(TRUE, tvb, offset, pinfo, tree, hf_crmf_serialNumber);
}
static int dissect_iterationCount(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_crmf_iterationCount);
}


static const ber_sequence_t OptionalValidity_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_notBefore_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG|BER_FLAGS_NOTCHKTAG, dissect_notAfter_impl },
  { 0, 0, 0, NULL }
};

int
dissect_crmf_OptionalValidity(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   OptionalValidity_sequence, hf_index, ett_crmf_OptionalValidity);

  return offset;
}
static int dissect_validity_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_OptionalValidity(TRUE, tvb, offset, pinfo, tree, hf_crmf_validity);
}


static const ber_sequence_t CertTemplate_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_version_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_serialNumber_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_signingAlg_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_template_issuer_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_validity_impl },
  { BER_CLASS_CON, 5, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_subject_impl },
  { BER_CLASS_CON, 6, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_publicKey_impl },
  { BER_CLASS_CON, 7, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_issuerUID_impl },
  { BER_CLASS_CON, 8, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_subjectUID_impl },
  { BER_CLASS_CON, 9, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_extensions_impl },
  { 0, 0, 0, NULL }
};

int
dissect_crmf_CertTemplate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertTemplate_sequence, hf_index, ett_crmf_CertTemplate);

  return offset;
}
static int dissect_certTemplate(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_CertTemplate(FALSE, tvb, offset, pinfo, tree, hf_crmf_certTemplate);
}



static int
dissect_crmf_T_type(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_crmf_type_oid, &object_identifier_id);

  return offset;
}
static int dissect_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_T_type(FALSE, tvb, offset, pinfo, tree, hf_crmf_type);
}



static int
dissect_crmf_T_value(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);


  return offset;
}
static int dissect_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_T_value(FALSE, tvb, offset, pinfo, tree, hf_crmf_value);
}


static const ber_sequence_t AttributeTypeAndValue_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_value },
  { 0, 0, 0, NULL }
};

int
dissect_crmf_AttributeTypeAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttributeTypeAndValue_sequence, hf_index, ett_crmf_AttributeTypeAndValue);

  return offset;
}
static int dissect_regInfo_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_AttributeTypeAndValue(FALSE, tvb, offset, pinfo, tree, hf_crmf_regInfo_item);
}
static int dissect_Controls_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_AttributeTypeAndValue(FALSE, tvb, offset, pinfo, tree, hf_crmf_Controls_item);
}


static const ber_sequence_t Controls_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_Controls_item },
};

int
dissect_crmf_Controls(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Controls_sequence_of, hf_index, ett_crmf_Controls);

  return offset;
}
static int dissect_controls(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_Controls(FALSE, tvb, offset, pinfo, tree, hf_crmf_controls);
}


static const ber_sequence_t CertRequest_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_certReqId },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certTemplate },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_controls },
  { 0, 0, 0, NULL }
};

int
dissect_crmf_CertRequest(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertRequest_sequence, hf_index, ett_crmf_CertRequest);

  return offset;
}
static int dissect_certReq(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_CertRequest(FALSE, tvb, offset, pinfo, tree, hf_crmf_certReq);
}



static int
dissect_crmf_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_raVerified_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_NULL(TRUE, tvb, offset, pinfo, tree, hf_crmf_raVerified);
}



static int
dissect_crmf_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_sk_signature(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_crmf_sk_signature);
}
static int dissect_pkmac_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_crmf_pkmac_value);
}
static int dissect_thisMessage_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_BIT_STRING(TRUE, tvb, offset, pinfo, tree, hf_crmf_thisMessage);
}
static int dissect_dhMAC_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_BIT_STRING(TRUE, tvb, offset, pinfo, tree, hf_crmf_dhMAC);
}
static int dissect_encSymmKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_BIT_STRING(TRUE, tvb, offset, pinfo, tree, hf_crmf_encSymmKey);
}
static int dissect_encValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_crmf_encValue);
}


static const ber_sequence_t PKMACValue_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algId },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_pkmac_value },
  { 0, 0, 0, NULL }
};

int
dissect_crmf_PKMACValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PKMACValue_sequence, hf_index, ett_crmf_PKMACValue);

  return offset;
}
static int dissect_publicKeyMAC(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_PKMACValue(FALSE, tvb, offset, pinfo, tree, hf_crmf_publicKeyMAC);
}


static const value_string crmf_T_authInfo_vals[] = {
  {   0, "sender" },
  {   1, "publicKeyMAC" },
  { 0, NULL }
};

static const ber_choice_t T_authInfo_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_sender_impl },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_publicKeyMAC },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_crmf_T_authInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_authInfo_choice, hf_index, ett_crmf_T_authInfo,
                                 NULL);

  return offset;
}
static int dissect_authInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_T_authInfo(FALSE, tvb, offset, pinfo, tree, hf_crmf_authInfo);
}


static const ber_sequence_t POPOSigningKeyInput_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_authInfo },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_publicKey },
  { 0, 0, 0, NULL }
};

int
dissect_crmf_POPOSigningKeyInput(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   POPOSigningKeyInput_sequence, hf_index, ett_crmf_POPOSigningKeyInput);

  return offset;
}
static int dissect_poposkInput_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_POPOSigningKeyInput(TRUE, tvb, offset, pinfo, tree, hf_crmf_poposkInput);
}


static const ber_sequence_t POPOSigningKey_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_poposkInput_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_algorithmIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_sk_signature },
  { 0, 0, 0, NULL }
};

int
dissect_crmf_POPOSigningKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   POPOSigningKey_sequence, hf_index, ett_crmf_POPOSigningKey);

  return offset;
}
static int dissect_signature_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_POPOSigningKey(TRUE, tvb, offset, pinfo, tree, hf_crmf_signature);
}


const value_string crmf_SubsequentMessage_vals[] = {
  {   0, "encrCert" },
  {   1, "challengeResp" },
  { 0, NULL }
};


int
dissect_crmf_SubsequentMessage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_subsequentMessage_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_SubsequentMessage(TRUE, tvb, offset, pinfo, tree, hf_crmf_subsequentMessage);
}


const value_string crmf_POPOPrivKey_vals[] = {
  {   0, "thisMessage" },
  {   1, "subsequentMessage" },
  {   2, "dhMAC" },
  { 0, NULL }
};

static const ber_choice_t POPOPrivKey_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_thisMessage_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_subsequentMessage_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_dhMAC_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_crmf_POPOPrivKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 POPOPrivKey_choice, hf_index, ett_crmf_POPOPrivKey,
                                 NULL);

  return offset;
}
static int dissect_keyEncipherment_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_POPOPrivKey(TRUE, tvb, offset, pinfo, tree, hf_crmf_keyEncipherment);
}
static int dissect_keyAgreement_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_POPOPrivKey(TRUE, tvb, offset, pinfo, tree, hf_crmf_keyAgreement);
}


const value_string crmf_ProofOfPossession_vals[] = {
  {   0, "raVerified" },
  {   1, "signature" },
  {   2, "keyEncipherment" },
  {   3, "keyAgreement" },
  { 0, NULL }
};

static const ber_choice_t ProofOfPossession_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_raVerified_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_signature_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_keyEncipherment_impl },
  {   3, BER_CLASS_CON, 3, 0, dissect_keyAgreement_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_crmf_ProofOfPossession(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 ProofOfPossession_choice, hf_index, ett_crmf_ProofOfPossession,
                                 NULL);

  return offset;
}
static int dissect_pop(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_ProofOfPossession(FALSE, tvb, offset, pinfo, tree, hf_crmf_pop);
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_regInfo_item },
};

static int
dissect_crmf_SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue_sequence_of, hf_index, ett_crmf_SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue);

  return offset;
}
static int dissect_regInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue(FALSE, tvb, offset, pinfo, tree, hf_crmf_regInfo);
}


static const ber_sequence_t CertReqMsg_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_certReq },
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pop },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_regInfo },
  { 0, 0, 0, NULL }
};

int
dissect_crmf_CertReqMsg(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertReqMsg_sequence, hf_index, ett_crmf_CertReqMsg);

  return offset;
}
static int dissect_CertReqMessages_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_CertReqMsg(FALSE, tvb, offset, pinfo, tree, hf_crmf_CertReqMessages_item);
}


static const ber_sequence_t CertReqMessages_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_CertReqMessages_item },
};

int
dissect_crmf_CertReqMessages(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      CertReqMessages_sequence_of, hf_index, ett_crmf_CertReqMessages);

  return offset;
}



static int
dissect_crmf_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_salt(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_crmf_salt);
}
static int dissect_valueHint_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_OCTET_STRING(TRUE, tvb, offset, pinfo, tree, hf_crmf_valueHint);
}


static const ber_sequence_t PBMParameter_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_salt },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_owf },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_iterationCount },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_mac },
  { 0, 0, 0, NULL }
};

int
dissect_crmf_PBMParameter(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PBMParameter_sequence, hf_index, ett_crmf_PBMParameter);

  return offset;
}



int
dissect_crmf_RegToken(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



int
dissect_crmf_Authenticator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string crmf_T_action_vals[] = {
  {   0, "dontPublish" },
  {   1, "pleasePublish" },
  { 0, NULL }
};


static int
dissect_crmf_T_action(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_action(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_T_action(FALSE, tvb, offset, pinfo, tree, hf_crmf_action);
}


static const value_string crmf_T_pubMethod_vals[] = {
  {   0, "dontCare" },
  {   1, "x500" },
  {   2, "web" },
  {   3, "ldap" },
  { 0, NULL }
};


static int
dissect_crmf_T_pubMethod(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_pubMethod(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_T_pubMethod(FALSE, tvb, offset, pinfo, tree, hf_crmf_pubMethod);
}


static const ber_sequence_t SinglePubInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pubMethod },
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pubLocation },
  { 0, 0, 0, NULL }
};

int
dissect_crmf_SinglePubInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SinglePubInfo_sequence, hf_index, ett_crmf_SinglePubInfo);

  return offset;
}
static int dissect_pubInfos_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_SinglePubInfo(FALSE, tvb, offset, pinfo, tree, hf_crmf_pubInfos_item);
}


static const ber_sequence_t SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pubInfos_item },
};

static int
dissect_crmf_SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo_sequence_of, hf_index, ett_crmf_SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo);

  return offset;
}
static int dissect_pubInfos(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo(FALSE, tvb, offset, pinfo, tree, hf_crmf_pubInfos);
}


static const ber_sequence_t PKIPublicationInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_action },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pubInfos },
  { 0, 0, 0, NULL }
};

int
dissect_crmf_PKIPublicationInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PKIPublicationInfo_sequence, hf_index, ett_crmf_PKIPublicationInfo);

  return offset;
}


static const ber_sequence_t EncryptedValue_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_intendedAlg_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_symmAlg_impl },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_encSymmKey_impl },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_keyAlg_impl },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_valueHint_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_encValue },
  { 0, 0, 0, NULL }
};

int
dissect_crmf_EncryptedValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EncryptedValue_sequence, hf_index, ett_crmf_EncryptedValue);

  return offset;
}
static int dissect_encryptedValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_EncryptedValue(FALSE, tvb, offset, pinfo, tree, hf_crmf_encryptedValue);
}


const value_string crmf_EncryptedKey_vals[] = {
  {   0, "encryptedValue" },
  {   1, "envelopedData" },
  { 0, NULL }
};

static const ber_choice_t EncryptedKey_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_encryptedValue },
  {   1, BER_CLASS_CON, 0, 0, dissect_envelopedData_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_crmf_EncryptedKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 EncryptedKey_choice, hf_index, ett_crmf_EncryptedKey,
                                 NULL);

  return offset;
}
static int dissect_encryptedPrivKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_EncryptedKey(TRUE, tvb, offset, pinfo, tree, hf_crmf_encryptedPrivKey);
}



int
dissect_crmf_KeyGenParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_keyGenParameters_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_KeyGenParameters(TRUE, tvb, offset, pinfo, tree, hf_crmf_keyGenParameters);
}



static int
dissect_crmf_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_archiveRemGenPrivKey_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_crmf_BOOLEAN(TRUE, tvb, offset, pinfo, tree, hf_crmf_archiveRemGenPrivKey);
}


const value_string crmf_PKIArchiveOptions_vals[] = {
  {   0, "encryptedPrivKey" },
  {   1, "keyGenParameters" },
  {   2, "archiveRemGenPrivKey" },
  { 0, NULL }
};

static const ber_choice_t PKIArchiveOptions_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_encryptedPrivKey_impl },
  {   1, BER_CLASS_CON, 1, 0, dissect_keyGenParameters_impl },
  {   2, BER_CLASS_CON, 2, 0, dissect_archiveRemGenPrivKey_impl },
  { 0, 0, 0, 0, NULL }
};

int
dissect_crmf_PKIArchiveOptions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PKIArchiveOptions_choice, hf_index, ett_crmf_PKIArchiveOptions,
                                 NULL);

  return offset;
}


static const ber_sequence_t CertId_sequence[] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_issuer },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_serialNumber },
  { 0, 0, 0, NULL }
};

int
dissect_crmf_CertId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   CertId_sequence, hf_index, ett_crmf_CertId);

  return offset;
}



int
dissect_crmf_OldCertId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_crmf_CertId(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



int
dissect_crmf_ProtocolEncrKey(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_pkix1explicit_SubjectPublicKeyInfo(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



int
dissect_crmf_UTF8Pairs(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



int
dissect_crmf_CertReq(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_crmf_CertRequest(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}

/*--- PDUs ---*/

static void dissect_PBMParameter_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_crmf_PBMParameter(FALSE, tvb, 0, pinfo, tree, hf_crmf_PBMParameter_PDU);
}


/*--- End of included file: packet-crmf-fn.c ---*/



/*--- proto_register_crmf ----------------------------------------------*/
void proto_register_crmf(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_crmf_type_oid,
      { "Type", "crmf.type.oid",
        FT_STRING, BASE_NONE, NULL, 0,
        "Type of AttributeTypeAndValue", HFILL }},

/*--- Included file: packet-crmf-hfarr.c ---*/

    { &hf_crmf_PBMParameter_PDU,
      { "PBMParameter", "crmf.PBMParameter",
        FT_NONE, BASE_NONE, NULL, 0,
        "PBMParameter", HFILL }},
    { &hf_crmf_utcTime,
      { "utcTime", "crmf.utcTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time/utcTime", HFILL }},
    { &hf_crmf_generalTime,
      { "generalTime", "crmf.generalTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "Time/generalTime", HFILL }},
    { &hf_crmf_CertReqMessages_item,
      { "Item", "crmf.CertReqMessages_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertReqMessages/_item", HFILL }},
    { &hf_crmf_certReq,
      { "certReq", "crmf.certReq",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertReqMsg/certReq", HFILL }},
    { &hf_crmf_pop,
      { "pop", "crmf.pop",
        FT_UINT32, BASE_DEC, VALS(crmf_ProofOfPossession_vals), 0,
        "CertReqMsg/pop", HFILL }},
    { &hf_crmf_regInfo,
      { "regInfo", "crmf.regInfo",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertReqMsg/regInfo", HFILL }},
    { &hf_crmf_regInfo_item,
      { "Item", "crmf.regInfo_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertReqMsg/regInfo/_item", HFILL }},
    { &hf_crmf_certReqId,
      { "certReqId", "crmf.certReqId",
        FT_INT32, BASE_DEC, NULL, 0,
        "CertRequest/certReqId", HFILL }},
    { &hf_crmf_certTemplate,
      { "certTemplate", "crmf.certTemplate",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertRequest/certTemplate", HFILL }},
    { &hf_crmf_controls,
      { "controls", "crmf.controls",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertRequest/controls", HFILL }},
    { &hf_crmf_version,
      { "version", "crmf.version",
        FT_INT32, BASE_DEC, VALS(crmf_Version_vals), 0,
        "CertTemplate/version", HFILL }},
    { &hf_crmf_serialNumber,
      { "serialNumber", "crmf.serialNumber",
        FT_INT32, BASE_DEC, NULL, 0,
        "", HFILL }},
    { &hf_crmf_signingAlg,
      { "signingAlg", "crmf.signingAlg",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertTemplate/signingAlg", HFILL }},
    { &hf_crmf_template_issuer,
      { "issuer", "crmf.issuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertTemplate/issuer", HFILL }},
    { &hf_crmf_validity,
      { "validity", "crmf.validity",
        FT_NONE, BASE_NONE, NULL, 0,
        "CertTemplate/validity", HFILL }},
    { &hf_crmf_subject,
      { "subject", "crmf.subject",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertTemplate/subject", HFILL }},
    { &hf_crmf_publicKey,
      { "publicKey", "crmf.publicKey",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_crmf_issuerUID,
      { "issuerUID", "crmf.issuerUID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CertTemplate/issuerUID", HFILL }},
    { &hf_crmf_subjectUID,
      { "subjectUID", "crmf.subjectUID",
        FT_BYTES, BASE_HEX, NULL, 0,
        "CertTemplate/subjectUID", HFILL }},
    { &hf_crmf_extensions,
      { "extensions", "crmf.extensions",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertTemplate/extensions", HFILL }},
    { &hf_crmf_notBefore,
      { "notBefore", "crmf.notBefore",
        FT_UINT32, BASE_DEC, VALS(crmf_Time_vals), 0,
        "OptionalValidity/notBefore", HFILL }},
    { &hf_crmf_notAfter,
      { "notAfter", "crmf.notAfter",
        FT_UINT32, BASE_DEC, VALS(crmf_Time_vals), 0,
        "OptionalValidity/notAfter", HFILL }},
    { &hf_crmf_Controls_item,
      { "Item", "crmf.Controls_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Controls/_item", HFILL }},
    { &hf_crmf_type,
      { "type", "crmf.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "AttributeTypeAndValue/type", HFILL }},
    { &hf_crmf_value,
      { "value", "crmf.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeTypeAndValue/value", HFILL }},
    { &hf_crmf_raVerified,
      { "raVerified", "crmf.raVerified",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProofOfPossession/raVerified", HFILL }},
    { &hf_crmf_signature,
      { "signature", "crmf.signature",
        FT_NONE, BASE_NONE, NULL, 0,
        "ProofOfPossession/signature", HFILL }},
    { &hf_crmf_keyEncipherment,
      { "keyEncipherment", "crmf.keyEncipherment",
        FT_UINT32, BASE_DEC, VALS(crmf_POPOPrivKey_vals), 0,
        "ProofOfPossession/keyEncipherment", HFILL }},
    { &hf_crmf_keyAgreement,
      { "keyAgreement", "crmf.keyAgreement",
        FT_UINT32, BASE_DEC, VALS(crmf_POPOPrivKey_vals), 0,
        "ProofOfPossession/keyAgreement", HFILL }},
    { &hf_crmf_poposkInput,
      { "poposkInput", "crmf.poposkInput",
        FT_NONE, BASE_NONE, NULL, 0,
        "POPOSigningKey/poposkInput", HFILL }},
    { &hf_crmf_algorithmIdentifier,
      { "algorithmIdentifier", "crmf.algorithmIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "POPOSigningKey/algorithmIdentifier", HFILL }},
    { &hf_crmf_sk_signature,
      { "signature", "crmf.signature",
        FT_BYTES, BASE_HEX, NULL, 0,
        "POPOSigningKey/signature", HFILL }},
    { &hf_crmf_authInfo,
      { "authInfo", "crmf.authInfo",
        FT_UINT32, BASE_DEC, VALS(crmf_T_authInfo_vals), 0,
        "POPOSigningKeyInput/authInfo", HFILL }},
    { &hf_crmf_sender,
      { "sender", "crmf.sender",
        FT_UINT32, BASE_DEC, NULL, 0,
        "POPOSigningKeyInput/authInfo/sender", HFILL }},
    { &hf_crmf_publicKeyMAC,
      { "publicKeyMAC", "crmf.publicKeyMAC",
        FT_NONE, BASE_NONE, NULL, 0,
        "POPOSigningKeyInput/authInfo/publicKeyMAC", HFILL }},
    { &hf_crmf_algId,
      { "algId", "crmf.algId",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKMACValue/algId", HFILL }},
    { &hf_crmf_pkmac_value,
      { "value", "crmf.value",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PKMACValue/value", HFILL }},
    { &hf_crmf_salt,
      { "salt", "crmf.salt",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PBMParameter/salt", HFILL }},
    { &hf_crmf_owf,
      { "owf", "crmf.owf",
        FT_NONE, BASE_NONE, NULL, 0,
        "PBMParameter/owf", HFILL }},
    { &hf_crmf_iterationCount,
      { "iterationCount", "crmf.iterationCount",
        FT_INT32, BASE_DEC, NULL, 0,
        "PBMParameter/iterationCount", HFILL }},
    { &hf_crmf_mac,
      { "mac", "crmf.mac",
        FT_NONE, BASE_NONE, NULL, 0,
        "PBMParameter/mac", HFILL }},
    { &hf_crmf_thisMessage,
      { "thisMessage", "crmf.thisMessage",
        FT_BYTES, BASE_HEX, NULL, 0,
        "POPOPrivKey/thisMessage", HFILL }},
    { &hf_crmf_subsequentMessage,
      { "subsequentMessage", "crmf.subsequentMessage",
        FT_INT32, BASE_DEC, VALS(crmf_SubsequentMessage_vals), 0,
        "POPOPrivKey/subsequentMessage", HFILL }},
    { &hf_crmf_dhMAC,
      { "dhMAC", "crmf.dhMAC",
        FT_BYTES, BASE_HEX, NULL, 0,
        "POPOPrivKey/dhMAC", HFILL }},
    { &hf_crmf_action,
      { "action", "crmf.action",
        FT_INT32, BASE_DEC, VALS(crmf_T_action_vals), 0,
        "PKIPublicationInfo/action", HFILL }},
    { &hf_crmf_pubInfos,
      { "pubInfos", "crmf.pubInfos",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PKIPublicationInfo/pubInfos", HFILL }},
    { &hf_crmf_pubInfos_item,
      { "Item", "crmf.pubInfos_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "PKIPublicationInfo/pubInfos/_item", HFILL }},
    { &hf_crmf_pubMethod,
      { "pubMethod", "crmf.pubMethod",
        FT_INT32, BASE_DEC, VALS(crmf_T_pubMethod_vals), 0,
        "SinglePubInfo/pubMethod", HFILL }},
    { &hf_crmf_pubLocation,
      { "pubLocation", "crmf.pubLocation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SinglePubInfo/pubLocation", HFILL }},
    { &hf_crmf_encryptedPrivKey,
      { "encryptedPrivKey", "crmf.encryptedPrivKey",
        FT_UINT32, BASE_DEC, VALS(crmf_EncryptedKey_vals), 0,
        "PKIArchiveOptions/encryptedPrivKey", HFILL }},
    { &hf_crmf_keyGenParameters,
      { "keyGenParameters", "crmf.keyGenParameters",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PKIArchiveOptions/keyGenParameters", HFILL }},
    { &hf_crmf_archiveRemGenPrivKey,
      { "archiveRemGenPrivKey", "crmf.archiveRemGenPrivKey",
        FT_BOOLEAN, 8, NULL, 0,
        "PKIArchiveOptions/archiveRemGenPrivKey", HFILL }},
    { &hf_crmf_encryptedValue,
      { "encryptedValue", "crmf.encryptedValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedKey/encryptedValue", HFILL }},
    { &hf_crmf_envelopedData,
      { "envelopedData", "crmf.envelopedData",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedKey/envelopedData", HFILL }},
    { &hf_crmf_intendedAlg,
      { "intendedAlg", "crmf.intendedAlg",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedValue/intendedAlg", HFILL }},
    { &hf_crmf_symmAlg,
      { "symmAlg", "crmf.symmAlg",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedValue/symmAlg", HFILL }},
    { &hf_crmf_encSymmKey,
      { "encSymmKey", "crmf.encSymmKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "EncryptedValue/encSymmKey", HFILL }},
    { &hf_crmf_keyAlg,
      { "keyAlg", "crmf.keyAlg",
        FT_NONE, BASE_NONE, NULL, 0,
        "EncryptedValue/keyAlg", HFILL }},
    { &hf_crmf_valueHint,
      { "valueHint", "crmf.valueHint",
        FT_BYTES, BASE_HEX, NULL, 0,
        "EncryptedValue/valueHint", HFILL }},
    { &hf_crmf_encValue,
      { "encValue", "crmf.encValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "EncryptedValue/encValue", HFILL }},
    { &hf_crmf_issuer,
      { "issuer", "crmf.issuer",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CertId/issuer", HFILL }},

/*--- End of included file: packet-crmf-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-crmf-ettarr.c ---*/

    &ett_crmf_Time,
    &ett_crmf_CertReqMessages,
    &ett_crmf_CertReqMsg,
    &ett_crmf_SEQUENCE_SIZE_1_MAX_OF_AttributeTypeAndValue,
    &ett_crmf_CertRequest,
    &ett_crmf_CertTemplate,
    &ett_crmf_OptionalValidity,
    &ett_crmf_Controls,
    &ett_crmf_AttributeTypeAndValue,
    &ett_crmf_ProofOfPossession,
    &ett_crmf_POPOSigningKey,
    &ett_crmf_POPOSigningKeyInput,
    &ett_crmf_T_authInfo,
    &ett_crmf_PKMACValue,
    &ett_crmf_PBMParameter,
    &ett_crmf_POPOPrivKey,
    &ett_crmf_PKIPublicationInfo,
    &ett_crmf_SEQUENCE_SIZE_1_MAX_OF_SinglePubInfo,
    &ett_crmf_SinglePubInfo,
    &ett_crmf_PKIArchiveOptions,
    &ett_crmf_EncryptedKey,
    &ett_crmf_EncryptedValue,
    &ett_crmf_CertId,

/*--- End of included file: packet-crmf-ettarr.c ---*/

  };

  /* Register protocol */
  proto_crmf = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_crmf, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_crmf -------------------------------------------*/
void proto_reg_handoff_crmf(void) {

/*--- Included file: packet-crmf-dis-tab.c ---*/

  register_ber_oid_dissector("1.2.840.113533.7.66.13", dissect_PBMParameter_PDU, proto_crmf, "PasswordBasedMac");


/*--- End of included file: packet-crmf-dis-tab.c ---*/

}

