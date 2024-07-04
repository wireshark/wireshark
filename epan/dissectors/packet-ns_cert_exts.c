/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-ns_cert_exts.c                                                      */
/* asn2wrs.py -b -q -L -p ns_cert_exts -c ./ns_cert_exts.cnf -s ./packet-ns_cert_exts-template -D . -O ../.. NETSCAPE-CERT-EXTS.asn */

/* packet-ns_cert_exts.c
 * Routines for NetScape Certificate Extensions packet dissection
 *   Ronnie Sahlberg 2004
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include "packet-ber.h"

#define PNAME  "NetScape Certificate Extensions"
#define PSNAME "NS_CERT_EXTS"
#define PFNAME "ns_cert_exts"

void proto_register_ns_cert_exts(void);
void proto_reg_handoff_ns_cert_exts(void);

/* Initialize the protocol and registered fields */
static int proto_ns_cert_exts;
static int hf_ns_cert_exts_BaseUrl_PDU;           /* BaseUrl */
static int hf_ns_cert_exts_RevocationUrl_PDU;     /* RevocationUrl */
static int hf_ns_cert_exts_CaRevocationUrl_PDU;   /* CaRevocationUrl */
static int hf_ns_cert_exts_CaPolicyUrl_PDU;       /* CaPolicyUrl */
static int hf_ns_cert_exts_Comment_PDU;           /* Comment */
static int hf_ns_cert_exts_SslServerName_PDU;     /* SslServerName */
static int hf_ns_cert_exts_CertRenewalUrl_PDU;    /* CertRenewalUrl */
static int hf_ns_cert_exts_CertType_PDU;          /* CertType */
/* named bits */
static int hf_ns_cert_exts_CertType_ssl_client;
static int hf_ns_cert_exts_CertType_ssl_server;
static int hf_ns_cert_exts_CertType_smime;
static int hf_ns_cert_exts_CertType_object_signing;
static int hf_ns_cert_exts_CertType_reserved_for_future_use;
static int hf_ns_cert_exts_CertType_ssl_ca;
static int hf_ns_cert_exts_CertType_smime_ca;
static int hf_ns_cert_exts_CertType_object_signing_ca;

/* Initialize the subtree pointers */
static int ett_ns_cert_exts_CertType;



static int
dissect_ns_cert_exts_BaseUrl(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ns_cert_exts_RevocationUrl(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ns_cert_exts_CaRevocationUrl(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ns_cert_exts_CaPolicyUrl(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ns_cert_exts_Comment(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ns_cert_exts_SslServerName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_ns_cert_exts_CertRenewalUrl(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static int * const CertType_bits[] = {
  &hf_ns_cert_exts_CertType_ssl_client,
  &hf_ns_cert_exts_CertType_ssl_server,
  &hf_ns_cert_exts_CertType_smime,
  &hf_ns_cert_exts_CertType_object_signing,
  &hf_ns_cert_exts_CertType_reserved_for_future_use,
  &hf_ns_cert_exts_CertType_ssl_ca,
  &hf_ns_cert_exts_CertType_smime_ca,
  &hf_ns_cert_exts_CertType_object_signing_ca,
  NULL
};

static int
dissect_ns_cert_exts_CertType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    CertType_bits, 8, hf_index, ett_ns_cert_exts_CertType,
                                    NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_BaseUrl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ns_cert_exts_BaseUrl(false, tvb, offset, &asn1_ctx, tree, hf_ns_cert_exts_BaseUrl_PDU);
  return offset;
}
static int dissect_RevocationUrl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ns_cert_exts_RevocationUrl(false, tvb, offset, &asn1_ctx, tree, hf_ns_cert_exts_RevocationUrl_PDU);
  return offset;
}
static int dissect_CaRevocationUrl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ns_cert_exts_CaRevocationUrl(false, tvb, offset, &asn1_ctx, tree, hf_ns_cert_exts_CaRevocationUrl_PDU);
  return offset;
}
static int dissect_CaPolicyUrl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ns_cert_exts_CaPolicyUrl(false, tvb, offset, &asn1_ctx, tree, hf_ns_cert_exts_CaPolicyUrl_PDU);
  return offset;
}
static int dissect_Comment_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ns_cert_exts_Comment(false, tvb, offset, &asn1_ctx, tree, hf_ns_cert_exts_Comment_PDU);
  return offset;
}
static int dissect_SslServerName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ns_cert_exts_SslServerName(false, tvb, offset, &asn1_ctx, tree, hf_ns_cert_exts_SslServerName_PDU);
  return offset;
}
static int dissect_CertRenewalUrl_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ns_cert_exts_CertRenewalUrl(false, tvb, offset, &asn1_ctx, tree, hf_ns_cert_exts_CertRenewalUrl_PDU);
  return offset;
}
static int dissect_CertType_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_ns_cert_exts_CertType(false, tvb, offset, &asn1_ctx, tree, hf_ns_cert_exts_CertType_PDU);
  return offset;
}



/*--- proto_register_ns_cert_exts -------------------------------------------*/
void proto_register_ns_cert_exts(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_ns_cert_exts_BaseUrl_PDU,
      { "BaseUrl", "ns_cert_exts.BaseUrl",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ns_cert_exts_RevocationUrl_PDU,
      { "RevocationUrl", "ns_cert_exts.RevocationUrl",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ns_cert_exts_CaRevocationUrl_PDU,
      { "CaRevocationUrl", "ns_cert_exts.CaRevocationUrl",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ns_cert_exts_CaPolicyUrl_PDU,
      { "CaPolicyUrl", "ns_cert_exts.CaPolicyUrl",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ns_cert_exts_Comment_PDU,
      { "Comment", "ns_cert_exts.Comment",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ns_cert_exts_SslServerName_PDU,
      { "SslServerName", "ns_cert_exts.SslServerName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ns_cert_exts_CertRenewalUrl_PDU,
      { "CertRenewalUrl", "ns_cert_exts.CertRenewalUrl",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ns_cert_exts_CertType_PDU,
      { "CertType", "ns_cert_exts.CertType",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_ns_cert_exts_CertType_ssl_client,
      { "ssl-client", "ns.cert.exts.CertType.ssl.client",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_ns_cert_exts_CertType_ssl_server,
      { "ssl-server", "ns.cert.exts.CertType.ssl.server",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_ns_cert_exts_CertType_smime,
      { "smime", "ns.cert.exts.CertType.smime",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_ns_cert_exts_CertType_object_signing,
      { "object-signing", "ns.cert.exts.CertType.object.signing",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_ns_cert_exts_CertType_reserved_for_future_use,
      { "reserved-for-future-use", "ns.cert.exts.CertType.reserved.for.future.use",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_ns_cert_exts_CertType_ssl_ca,
      { "ssl-ca", "ns.cert.exts.CertType.ssl.ca",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_ns_cert_exts_CertType_smime_ca,
      { "smime-ca", "ns.cert.exts.CertType.smime.ca",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_ns_cert_exts_CertType_object_signing_ca,
      { "object-signing-ca", "ns.cert.exts.CertType.object.signing.ca",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_ns_cert_exts_CertType,
  };

  /* Register protocol */
  proto_ns_cert_exts = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ns_cert_exts, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_ns_cert_exts ---------------------------------------*/
void proto_reg_handoff_ns_cert_exts(void) {
  register_ber_oid_dissector("2.16.840.1.113730.1.1", dissect_CertType_PDU, proto_ns_cert_exts, "ns_cert_exts.cert_type");
  register_ber_oid_dissector("2.16.840.1.113730.1.2", dissect_BaseUrl_PDU, proto_ns_cert_exts, "ns_cert_exts.base_url");
  register_ber_oid_dissector("2.16.840.1.113730.1.3", dissect_RevocationUrl_PDU, proto_ns_cert_exts, "ns_cert_exts.revocation-url");
  register_ber_oid_dissector("2.16.840.1.113730.1.4", dissect_CaRevocationUrl_PDU, proto_ns_cert_exts, "ns_cert_exts.ca-revocation-url");
  register_ber_oid_dissector("2.16.840.1.113730.1.7", dissect_CertRenewalUrl_PDU, proto_ns_cert_exts, "ns_cert_exts.cert-renewal-url");
  register_ber_oid_dissector("2.16.840.1.113730.1.8", dissect_CaPolicyUrl_PDU, proto_ns_cert_exts, "ns_cert_exts.ca-policy-url");
  register_ber_oid_dissector("2.16.840.1.113730.1.12", dissect_SslServerName_PDU, proto_ns_cert_exts, "ns_cert_exts.ssl-server-name");
  register_ber_oid_dissector("2.16.840.1.113730.1.13", dissect_Comment_PDU, proto_ns_cert_exts, "ns_cert_exts.comment");

}

