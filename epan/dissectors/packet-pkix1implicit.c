/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkix1implicit.c                                                     */
/* asn2wrs.py -b -q -L -p pkix1implicit -c ./pkix1implicit.cnf -s ./packet-pkix1implicit-template -D . -O ../.. PKIX1IMPLICIT93.asn */

/* packet-pkix1implicit.c
 * Routines for PKIX1Implitic packet dissection
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
#include "packet-ber.h"
#include "packet-pkix1implicit.h"
#include "packet-pkix1explicit.h"
#include "packet-x509ce.h"

#define PNAME  "PKIX1Implicit"
#define PSNAME "PKIX1IMPLICIT"
#define PFNAME "pkix1implicit"

void proto_register_pkix1implicit(void);
void proto_reg_handoff_pkix1implicit(void);

/* Initialize the protocol and registered fields */
static int proto_pkix1implicit;
static int hf_pkix1implicit_Dummy_PDU;            /* Dummy */
static int hf_pkix1implicit_AuthorityInfoAccessSyntax_PDU;  /* AuthorityInfoAccessSyntax */
static int hf_pkix1implicit_UserNotice_PDU;       /* UserNotice */
static int hf_pkix1implicit_AuthorityInfoAccessSyntax_item;  /* AccessDescription */
static int hf_pkix1implicit_accessMethod;         /* OBJECT_IDENTIFIER */
static int hf_pkix1implicit_accessLocation;       /* GeneralName */
static int hf_pkix1implicit_noticeRef;            /* NoticeReference */
static int hf_pkix1implicit_explicitText;         /* DisplayText */
static int hf_pkix1implicit_organization;         /* DisplayText */
static int hf_pkix1implicit_noticeNumbers;        /* T_noticeNumbers */
static int hf_pkix1implicit_noticeNumbers_item;   /* INTEGER */
static int hf_pkix1implicit_ia5String;            /* IA5String */
static int hf_pkix1implicit_visibleString;        /* VisibleString */
static int hf_pkix1implicit_bmpString;            /* BMPString */
static int hf_pkix1implicit_utf8String;           /* UTF8String */

/* Initialize the subtree pointers */
static int ett_pkix1implicit_AuthorityInfoAccessSyntax;
static int ett_pkix1implicit_AccessDescription;
static int ett_pkix1implicit_UserNotice;
static int ett_pkix1implicit_NoticeReference;
static int ett_pkix1implicit_T_noticeNumbers;
static int ett_pkix1implicit_DisplayText;


int
dissect_pkix1implicit_ReasonFlags(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509ce_ReasonFlags(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}
int
dissect_pkix1implicit_GeneralName(bool implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509ce_GeneralName(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



int
dissect_pkix1implicit_KeyIdentifier(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_pkix1implicit_Dummy(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_pkix1implicit_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t AccessDescription_sequence[] = {
  { &hf_pkix1implicit_accessMethod, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_OBJECT_IDENTIFIER },
  { &hf_pkix1implicit_accessLocation, BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralName },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkix1implicit_AccessDescription(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AccessDescription_sequence, hf_index, ett_pkix1implicit_AccessDescription);

  return offset;
}


static const ber_sequence_t AuthorityInfoAccessSyntax_sequence_of[1] = {
  { &hf_pkix1implicit_AuthorityInfoAccessSyntax_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_AccessDescription },
};

int
dissect_pkix1implicit_AuthorityInfoAccessSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      AuthorityInfoAccessSyntax_sequence_of, hf_index, ett_pkix1implicit_AuthorityInfoAccessSyntax);

  return offset;
}



static int
dissect_pkix1implicit_IA5String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_pkix1implicit_VisibleString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_pkix1implicit_BMPString(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_BMPString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_pkix1implicit_UTF8String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string pkix1implicit_DisplayText_vals[] = {
  {   0, "ia5String" },
  {   1, "visibleString" },
  {   2, "bmpString" },
  {   3, "utf8String" },
  { 0, NULL }
};

static const ber_choice_t DisplayText_choice[] = {
  {   0, &hf_pkix1implicit_ia5String, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_IA5String },
  {   1, &hf_pkix1implicit_visibleString, BER_CLASS_UNI, BER_UNI_TAG_VisibleString, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_VisibleString },
  {   2, &hf_pkix1implicit_bmpString, BER_CLASS_UNI, BER_UNI_TAG_BMPString, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_BMPString },
  {   3, &hf_pkix1implicit_utf8String, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_UTF8String },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_pkix1implicit_DisplayText(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DisplayText_choice, hf_index, ett_pkix1implicit_DisplayText,
                                 NULL);

  return offset;
}



static int
dissect_pkix1implicit_INTEGER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t T_noticeNumbers_sequence_of[1] = {
  { &hf_pkix1implicit_noticeNumbers_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_INTEGER },
};

static int
dissect_pkix1implicit_T_noticeNumbers(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      T_noticeNumbers_sequence_of, hf_index, ett_pkix1implicit_T_noticeNumbers);

  return offset;
}


static const ber_sequence_t NoticeReference_sequence[] = {
  { &hf_pkix1implicit_organization, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pkix1implicit_DisplayText },
  { &hf_pkix1implicit_noticeNumbers, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_T_noticeNumbers },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkix1implicit_NoticeReference(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NoticeReference_sequence, hf_index, ett_pkix1implicit_NoticeReference);

  return offset;
}


static const ber_sequence_t UserNotice_sequence[] = {
  { &hf_pkix1implicit_noticeRef, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkix1implicit_NoticeReference },
  { &hf_pkix1implicit_explicitText, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pkix1implicit_DisplayText },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_pkix1implicit_UserNotice(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UserNotice_sequence, hf_index, ett_pkix1implicit_UserNotice);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Dummy_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkix1implicit_Dummy(false, tvb, offset, &asn1_ctx, tree, hf_pkix1implicit_Dummy_PDU);
  return offset;
}
static int dissect_AuthorityInfoAccessSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkix1implicit_AuthorityInfoAccessSyntax(false, tvb, offset, &asn1_ctx, tree, hf_pkix1implicit_AuthorityInfoAccessSyntax_PDU);
  return offset;
}
static int dissect_UserNotice_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkix1implicit_UserNotice(false, tvb, offset, &asn1_ctx, tree, hf_pkix1implicit_UserNotice_PDU);
  return offset;
}



/*--- proto_register_pkix1implicit ----------------------------------------------*/
void proto_register_pkix1implicit(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_pkix1implicit_Dummy_PDU,
      { "Dummy", "pkix1implicit.Dummy_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkix1implicit_AuthorityInfoAccessSyntax_PDU,
      { "AuthorityInfoAccessSyntax", "pkix1implicit.AuthorityInfoAccessSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkix1implicit_UserNotice_PDU,
      { "UserNotice", "pkix1implicit.UserNotice_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkix1implicit_AuthorityInfoAccessSyntax_item,
      { "AccessDescription", "pkix1implicit.AccessDescription_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkix1implicit_accessMethod,
      { "accessMethod", "pkix1implicit.accessMethod",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkix1implicit_accessLocation,
      { "accessLocation", "pkix1implicit.accessLocation",
        FT_UINT32, BASE_DEC, NULL, 0,
        "GeneralName", HFILL }},
    { &hf_pkix1implicit_noticeRef,
      { "noticeRef", "pkix1implicit.noticeRef_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "NoticeReference", HFILL }},
    { &hf_pkix1implicit_explicitText,
      { "explicitText", "pkix1implicit.explicitText",
        FT_UINT32, BASE_DEC, VALS(pkix1implicit_DisplayText_vals), 0,
        "DisplayText", HFILL }},
    { &hf_pkix1implicit_organization,
      { "organization", "pkix1implicit.organization",
        FT_UINT32, BASE_DEC, VALS(pkix1implicit_DisplayText_vals), 0,
        "DisplayText", HFILL }},
    { &hf_pkix1implicit_noticeNumbers,
      { "noticeNumbers", "pkix1implicit.noticeNumbers",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkix1implicit_noticeNumbers_item,
      { "noticeNumbers item", "pkix1implicit.noticeNumbers_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_pkix1implicit_ia5String,
      { "ia5String", "pkix1implicit.ia5String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkix1implicit_visibleString,
      { "visibleString", "pkix1implicit.visibleString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkix1implicit_bmpString,
      { "bmpString", "pkix1implicit.bmpString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkix1implicit_utf8String,
      { "utf8String", "pkix1implicit.utf8String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_pkix1implicit_AuthorityInfoAccessSyntax,
    &ett_pkix1implicit_AccessDescription,
    &ett_pkix1implicit_UserNotice,
    &ett_pkix1implicit_NoticeReference,
    &ett_pkix1implicit_T_noticeNumbers,
    &ett_pkix1implicit_DisplayText,
  };

  /* Register protocol */
  proto_pkix1implicit = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkix1implicit, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkix1implicit -------------------------------------------*/
void proto_reg_handoff_pkix1implicit(void) {
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.1", dissect_AuthorityInfoAccessSyntax_PDU, proto_pkix1implicit, "id-pe-authorityInfoAccess");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.1", dissect_Dummy_PDU, proto_pkix1implicit, "id-ad-ocsp");
  register_ber_oid_dissector("1.3.6.1.5.5.7.48.2", dissect_Dummy_PDU, proto_pkix1implicit, "id-ad-caIssuers");
  register_ber_oid_dissector("1.3.6.1.5.5.7.3.1", dissect_Dummy_PDU, proto_pkix1implicit, "id-kp-serverAuth");
  register_ber_oid_dissector("1.3.6.1.5.5.7.3.2", dissect_Dummy_PDU, proto_pkix1implicit, "id-kp-clientAuth");
  register_ber_oid_dissector("1.3.6.1.5.5.7.3.3", dissect_Dummy_PDU, proto_pkix1implicit, "id-kp-codeSigning");
  register_ber_oid_dissector("1.3.6.1.5.5.7.3.4", dissect_Dummy_PDU, proto_pkix1implicit, "id-kp-emailProtection");
  register_ber_oid_dissector("1.3.6.1.5.5.7.3.5", dissect_Dummy_PDU, proto_pkix1implicit, "id-kp-ip-kp-ipsecEndSystem");
  register_ber_oid_dissector("1.3.6.1.5.5.7.3.6", dissect_Dummy_PDU, proto_pkix1implicit, "id-kp-ipsecTunnel");
  register_ber_oid_dissector("1.3.6.1.5.5.7.3.7", dissect_Dummy_PDU, proto_pkix1implicit, "id-kp-ipsecUser");
  register_ber_oid_dissector("1.3.6.1.5.5.7.3.8", dissect_Dummy_PDU, proto_pkix1implicit, "id-kp-timeStamping");
  register_ber_oid_dissector("1.3.6.1.5.5.7.3.9", dissect_Dummy_PDU, proto_pkix1implicit, "OCSPSigning");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.12.1", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-any-application-policy");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.3.1", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-kp-ctl-usage-signing");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.3.2", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-kp-time-stamp-signing");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.3.4", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-kp-efs");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.3.4.1", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-efs-recovery");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.3.5", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-whql-crypto");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.3.6", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-nt5-crypto");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.3.7", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-oem-whql-crypto");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.3.8", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-embedded-nt-crypto");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.3.9", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-root-list-signer");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.3.10", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-kp-qualified-subordination");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.3.11", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-kp-key-recovery");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.3.12", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-kp-document-signing");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.3.13", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-kp-lifetime-signing");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.5.1", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-drm");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.6.1", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-licenses");
  register_ber_oid_dissector("1.3.6.1.4.1.311.10.6.2", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-license-server");
  register_ber_oid_dissector("1.3.6.1.4.1.311.20.1", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-auto-enroll-ctl-usage");
  register_ber_oid_dissector("1.3.6.1.4.1.311.20.2.1", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-enrollment-agent");
  register_ber_oid_dissector("1.3.6.1.4.1.311.20.2.2", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-kp-smartcard-logon");
  register_ber_oid_dissector("1.3.6.1.4.1.311.21.5", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-kp-ca-exchange");
  register_ber_oid_dissector("1.3.6.1.4.1.311.21.6", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-kp-key-recovery-agent");
  register_ber_oid_dissector("1.3.6.1.4.1.311.21.19", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-ds-email-replication");
  register_ber_oid_dissector("1.3.6.1.5.5.8.2.2", dissect_Dummy_PDU, proto_pkix1implicit, "id-ms-ipsec-kp-ike-intermediate");
  register_ber_oid_dissector("1.3.6.1.5.5.7.2.2", dissect_UserNotice_PDU, proto_pkix1implicit, "id-qt-unotice");

}

