/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkcs10.c                                                            */
/* asn2wrs.py -b -p pkcs10 -c ./pkcs10.cnf -s ./packet-pkcs10-template -D . -O ../.. PKCS10.asn */

/* Input file: packet-pkcs10-template.c */

#line 1 "./asn1/pkcs10/packet-pkcs10-template.c"
/* packet-p10.c
 *
 * Routines for PKCS10 packet dissection
 *   Martin Peylo <wireshark@izac.de> 2018
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

#include <epan/packet.h>

#include <epan/oids.h>
#include <epan/asn1.h>
#include "packet-ber.h"
#include "packet-pkcs10.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include <epan/prefs.h>

#define PNAME  "PKCS10 Certification Request"
#define PSNAME "PKCS10"
#define PFNAME "pkcs10"

void proto_register_pkcs10(void);

/* Initialize the protocol and registered fields */
static int proto_pkcs10 = -1;

/*--- Included file: packet-pkcs10-hf.c ---*/
#line 1 "./asn1/pkcs10/packet-pkcs10-hf.c"
static int hf_pkcs10_Attributes_PDU = -1;         /* Attributes */
static int hf_pkcs10_CertificationRequest_PDU = -1;  /* CertificationRequest */
static int hf_pkcs10_version = -1;                /* T_version */
static int hf_pkcs10_subject = -1;                /* Name */
static int hf_pkcs10_subjectPKInfo = -1;          /* SubjectPublicKeyInfo */
static int hf_pkcs10_attributes = -1;             /* Attributes */
static int hf_pkcs10_Attributes_item = -1;        /* Attribute */
static int hf_pkcs10_type = -1;                   /* T_type */
static int hf_pkcs10_values = -1;                 /* T_values */
static int hf_pkcs10_values_item = -1;            /* T_values_item */
static int hf_pkcs10_certificationRequestInfo = -1;  /* CertificationRequestInfo */
static int hf_pkcs10_signatureAlgorithm = -1;     /* AlgorithmIdentifier */
static int hf_pkcs10_signature = -1;              /* BIT_STRING */

/*--- End of included file: packet-pkcs10-hf.c ---*/
#line 46 "./asn1/pkcs10/packet-pkcs10-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-pkcs10-ett.c ---*/
#line 1 "./asn1/pkcs10/packet-pkcs10-ett.c"
static gint ett_pkcs10_CertificationRequestInfo = -1;
static gint ett_pkcs10_Attributes = -1;
static gint ett_pkcs10_Attribute = -1;
static gint ett_pkcs10_T_values = -1;
static gint ett_pkcs10_CertificationRequest = -1;

/*--- End of included file: packet-pkcs10-ett.c ---*/
#line 49 "./asn1/pkcs10/packet-pkcs10-template.c"

/*--- Included file: packet-pkcs10-fn.c ---*/
#line 1 "./asn1/pkcs10/packet-pkcs10-fn.c"

static const value_string pkcs10_T_version_vals[] = {
  {   0, "v1" },
  { 0, NULL }
};


static int
dissect_pkcs10_T_version(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_pkcs10_T_type(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_pkcs10_type, &actx->external.direct_reference);

  return offset;
}



static int
dissect_pkcs10_T_values_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 29 "./asn1/pkcs10/pkcs10.cnf"
    offset=call_ber_oid_callback(actx->external.direct_reference, tvb, offset, actx->pinfo, tree, NULL);



  return offset;
}


static const ber_sequence_t T_values_set_of[1] = {
  { &hf_pkcs10_values_item  , BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_pkcs10_T_values_item },
};

static int
dissect_pkcs10_T_values(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_values_set_of, hf_index, ett_pkcs10_T_values);

  return offset;
}


static const ber_sequence_t Attribute_sequence[] = {
  { &hf_pkcs10_type         , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkcs10_T_type },
  { &hf_pkcs10_values       , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_pkcs10_T_values },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs10_Attribute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Attribute_sequence, hf_index, ett_pkcs10_Attribute);

  return offset;
}


static const ber_sequence_t Attributes_set_of[1] = {
  { &hf_pkcs10_Attributes_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkcs10_Attribute },
};

static int
dissect_pkcs10_Attributes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 Attributes_set_of, hf_index, ett_pkcs10_Attributes);

  return offset;
}


static const ber_sequence_t CertificationRequestInfo_sequence[] = {
  { &hf_pkcs10_version      , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkcs10_T_version },
  { &hf_pkcs10_subject      , BER_CLASS_ANY, -1, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_Name },
  { &hf_pkcs10_subjectPKInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_SubjectPublicKeyInfo },
  { &hf_pkcs10_attributes   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_pkcs10_Attributes },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkcs10_CertificationRequestInfo(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificationRequestInfo_sequence, hf_index, ett_pkcs10_CertificationRequestInfo);

  return offset;
}



static int
dissect_pkcs10_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, 0, hf_index, -1,
                                    NULL);

  return offset;
}


static const ber_sequence_t CertificationRequest_sequence[] = {
  { &hf_pkcs10_certificationRequestInfo, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkcs10_CertificationRequestInfo },
  { &hf_pkcs10_signatureAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1explicit_AlgorithmIdentifier },
  { &hf_pkcs10_signature    , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_pkcs10_BIT_STRING },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_pkcs10_CertificationRequest(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CertificationRequest_sequence, hf_index, ett_pkcs10_CertificationRequest);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Attributes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_pkcs10_Attributes(FALSE, tvb, offset, &asn1_ctx, tree, hf_pkcs10_Attributes_PDU);
  return offset;
}
static int dissect_CertificationRequest_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_pkcs10_CertificationRequest(FALSE, tvb, offset, &asn1_ctx, tree, hf_pkcs10_CertificationRequest_PDU);
  return offset;
}


/*--- End of included file: packet-pkcs10-fn.c ---*/
#line 50 "./asn1/pkcs10/packet-pkcs10-template.c"

/*--- proto_register_pkcs10 ----------------------------------------------*/
void proto_register_pkcs10(void) {

	/* List of fields */
	static hf_register_info hf[] = {

/*--- Included file: packet-pkcs10-hfarr.c ---*/
#line 1 "./asn1/pkcs10/packet-pkcs10-hfarr.c"
    { &hf_pkcs10_Attributes_PDU,
      { "Attributes", "pkcs10.Attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs10_CertificationRequest_PDU,
      { "CertificationRequest", "pkcs10.CertificationRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs10_version,
      { "version", "pkcs10.version",
        FT_UINT32, BASE_DEC, VALS(pkcs10_T_version_vals), 0,
        NULL, HFILL }},
    { &hf_pkcs10_subject,
      { "subject", "pkcs10.subject",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Name", HFILL }},
    { &hf_pkcs10_subjectPKInfo,
      { "subjectPKInfo", "pkcs10.subjectPKInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubjectPublicKeyInfo", HFILL }},
    { &hf_pkcs10_attributes,
      { "attributes", "pkcs10.attributes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs10_Attributes_item,
      { "Attribute", "pkcs10.Attribute_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs10_type,
      { "type", "pkcs10.type",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs10_values,
      { "values", "pkcs10.values",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs10_values_item,
      { "values item", "pkcs10.values_item_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs10_certificationRequestInfo,
      { "certificationRequestInfo", "pkcs10.certificationRequestInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkcs10_signatureAlgorithm,
      { "signatureAlgorithm", "pkcs10.signatureAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_pkcs10_signature,
      { "signature", "pkcs10.signature",
        FT_BYTES, BASE_NONE, NULL, 0,
        "BIT_STRING", HFILL }},

/*--- End of included file: packet-pkcs10-hfarr.c ---*/
#line 57 "./asn1/pkcs10/packet-pkcs10-template.c"
	};

	/* List of subtrees */
	static gint *ett[] = {

/*--- Included file: packet-pkcs10-ettarr.c ---*/
#line 1 "./asn1/pkcs10/packet-pkcs10-ettarr.c"
    &ett_pkcs10_CertificationRequestInfo,
    &ett_pkcs10_Attributes,
    &ett_pkcs10_Attribute,
    &ett_pkcs10_T_values,
    &ett_pkcs10_CertificationRequest,

/*--- End of included file: packet-pkcs10-ettarr.c ---*/
#line 62 "./asn1/pkcs10/packet-pkcs10-template.c"
	};
	/* Register protocol */
	proto_pkcs10 = proto_register_protocol(PNAME, PSNAME, PFNAME);

	/* Register fields and subtrees */
	proto_register_field_array(proto_pkcs10, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

  register_ber_syntax_dissector("CertificationRequest", proto_pkcs10, dissect_CertificationRequest_PDU);
  register_ber_oid_syntax(".p10", NULL, "CertificationRequest");
  register_ber_oid_syntax(".csr", NULL, "CertificationRequest");
}


/*--- proto_reg_handoff_pkcs10 -------------------------------------------*/
void proto_reg_handoff_pkcs10(void) {
  dissector_handle_t csr_handle;


/*--- Included file: packet-pkcs10-dis-tab.c ---*/
#line 1 "./asn1/pkcs10/packet-pkcs10-dis-tab.c"
  register_ber_oid_dissector("1.2.840.113549.1.9.9", dissect_Attributes_PDU, proto_pkcs10, "pkcs-9-at-extendedCertificateAttributes");


/*--- End of included file: packet-pkcs10-dis-tab.c ---*/
#line 81 "./asn1/pkcs10/packet-pkcs10-template.c"

  csr_handle = create_dissector_handle(dissect_CertificationRequest_PDU, proto_pkcs10);
  dissector_add_string("media_type", "application/pkcs10", csr_handle); /* RFC 5967 */
  dissector_add_string("rfc7468.preeb_label", "CERTIFICATE REQUEST", csr_handle); /* RFC 7468 */
  dissector_add_string("rfc7468.preeb_label", "NEW CERTIFICATE REQUEST", csr_handle); /* RFC 7468 Appendix A. Non-conforming expample*/
}
