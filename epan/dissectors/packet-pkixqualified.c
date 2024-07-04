/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-pkixqualified.c                                                     */
/* asn2wrs.py -b -q -L -p pkixqualified -c ./pkixqualified.cnf -s ./packet-pkixqualified-template -D . -O ../.. PKIXqualified.asn PKIXServiceNameSAN88.asn PKIXServiceNameSAN93.asn */

/* packet-pkixqualified.c
 * Routines for RFC3739 PKIXqualified packet dissection
 *  Ronnie Sahlberg 2004
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
#include "packet-pkixqualified.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509sat.h"

#define PNAME  "PKIX Qualified"
#define PSNAME "PKIXQUALIFIED"
#define PFNAME "pkixqualified"

void proto_register_pkixqualified(void);
void proto_reg_handoff_pkixqualified(void);


/* Initialize the protocol and registered fields */
static int proto_pkixqualified;
static int hf_pkixqualified_Generalizedtime_PDU;  /* Generalizedtime */
static int hf_pkixqualified_Directorystring_PDU;  /* Directorystring */
static int hf_pkixqualified_Printablestring_PDU;  /* Printablestring */
static int hf_pkixqualified_BiometricSyntax_PDU;  /* BiometricSyntax */
static int hf_pkixqualified_QCStatements_PDU;     /* QCStatements */
static int hf_pkixqualified_SemanticsInformation_PDU;  /* SemanticsInformation */
static int hf_pkixqualified_XmppAddr_PDU;         /* XmppAddr */
static int hf_pkixqualified_SRVName_PDU;          /* SRVName */
static int hf_pkixqualified_BiometricSyntax_item;  /* BiometricData */
static int hf_pkixqualified_typeOfBiometricData;  /* TypeOfBiometricData */
static int hf_pkixqualified_hashAlgorithm;        /* AlgorithmIdentifier */
static int hf_pkixqualified_biometricDataHash;    /* OCTET_STRING */
static int hf_pkixqualified_sourceDataUri;        /* IA5String */
static int hf_pkixqualified_predefinedBiometricType;  /* PredefinedBiometricType */
static int hf_pkixqualified_biometricDataOid;     /* OBJECT_IDENTIFIER */
static int hf_pkixqualified_QCStatements_item;    /* QCStatement */
static int hf_pkixqualified_statementId;          /* T_statementId */
static int hf_pkixqualified_statementInfo;        /* T_statementInfo */
static int hf_pkixqualified_semanticsIdentifier;  /* OBJECT_IDENTIFIER */
static int hf_pkixqualified_nameRegistrationAuthorities;  /* NameRegistrationAuthorities */
static int hf_pkixqualified_NameRegistrationAuthorities_item;  /* GeneralName */

/* Initialize the subtree pointers */
static int ett_pkixqualified_BiometricSyntax;
static int ett_pkixqualified_BiometricData;
static int ett_pkixqualified_TypeOfBiometricData;
static int ett_pkixqualified_QCStatements;
static int ett_pkixqualified_QCStatement;
static int ett_pkixqualified_SemanticsInformation;
static int ett_pkixqualified_NameRegistrationAuthorities;

static const char *object_identifier_id;



static int
dissect_pkixqualified_Generalizedtime(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_pkixqualified_Directorystring(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_x509sat_DirectoryString(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}



static int
dissect_pkixqualified_Printablestring(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string pkixqualified_PredefinedBiometricType_vals[] = {
  {   0, "picture" },
  {   1, "handwritten-signature" },
  { 0, NULL }
};


static int
dissect_pkixqualified_PredefinedBiometricType(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_pkixqualified_OBJECT_IDENTIFIER(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string pkixqualified_TypeOfBiometricData_vals[] = {
  {   0, "predefinedBiometricType" },
  {   1, "biometricDataOid" },
  { 0, NULL }
};

static const ber_choice_t TypeOfBiometricData_choice[] = {
  {   0, &hf_pkixqualified_predefinedBiometricType, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pkixqualified_PredefinedBiometricType },
  {   1, &hf_pkixqualified_biometricDataOid, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkixqualified_OBJECT_IDENTIFIER },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixqualified_TypeOfBiometricData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TypeOfBiometricData_choice, hf_index, ett_pkixqualified_TypeOfBiometricData,
                                 NULL);

  return offset;
}



static int
dissect_pkixqualified_OCTET_STRING(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_pkixqualified_IA5String(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t BiometricData_sequence[] = {
  { &hf_pkixqualified_typeOfBiometricData, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_pkixqualified_TypeOfBiometricData },
  { &hf_pkixqualified_hashAlgorithm, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509af_AlgorithmIdentifier },
  { &hf_pkixqualified_biometricDataHash, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_pkixqualified_OCTET_STRING },
  { &hf_pkixqualified_sourceDataUri, BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixqualified_IA5String },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixqualified_BiometricData(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   BiometricData_sequence, hf_index, ett_pkixqualified_BiometricData);

  return offset;
}


static const ber_sequence_t BiometricSyntax_sequence_of[1] = {
  { &hf_pkixqualified_BiometricSyntax_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkixqualified_BiometricData },
};

static int
dissect_pkixqualified_BiometricSyntax(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      BiometricSyntax_sequence_of, hf_index, ett_pkixqualified_BiometricSyntax);

  return offset;
}



static int
dissect_pkixqualified_T_statementId(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, actx, tree, tvb, offset, hf_pkixqualified_statementId, &object_identifier_id);

  return offset;
}



static int
dissect_pkixqualified_T_statementInfo(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, actx->pinfo, tree, NULL);


  return offset;
}


static const ber_sequence_t QCStatement_sequence[] = {
  { &hf_pkixqualified_statementId, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_pkixqualified_T_statementId },
  { &hf_pkixqualified_statementInfo, BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixqualified_T_statementInfo },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixqualified_QCStatement(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  object_identifier_id = NULL;

  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   QCStatement_sequence, hf_index, ett_pkixqualified_QCStatement);

  return offset;
}


static const ber_sequence_t QCStatements_sequence_of[1] = {
  { &hf_pkixqualified_QCStatements_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_pkixqualified_QCStatement },
};

static int
dissect_pkixqualified_QCStatements(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      QCStatements_sequence_of, hf_index, ett_pkixqualified_QCStatements);

  return offset;
}


static const ber_sequence_t NameRegistrationAuthorities_sequence_of[1] = {
  { &hf_pkixqualified_NameRegistrationAuthorities_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509ce_GeneralName },
};

static int
dissect_pkixqualified_NameRegistrationAuthorities(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      NameRegistrationAuthorities_sequence_of, hf_index, ett_pkixqualified_NameRegistrationAuthorities);

  return offset;
}


static const ber_sequence_t SemanticsInformation_sequence[] = {
  { &hf_pkixqualified_semanticsIdentifier, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixqualified_OBJECT_IDENTIFIER },
  { &hf_pkixqualified_nameRegistrationAuthorities, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pkixqualified_NameRegistrationAuthorities },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_pkixqualified_SemanticsInformation(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   SemanticsInformation_sequence, hf_index, ett_pkixqualified_SemanticsInformation);

  return offset;
}



static int
dissect_pkixqualified_XmppAddr(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_pkixqualified_SRVName(bool implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_Generalizedtime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixqualified_Generalizedtime(false, tvb, offset, &asn1_ctx, tree, hf_pkixqualified_Generalizedtime_PDU);
  return offset;
}
static int dissect_Directorystring_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixqualified_Directorystring(false, tvb, offset, &asn1_ctx, tree, hf_pkixqualified_Directorystring_PDU);
  return offset;
}
static int dissect_Printablestring_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixqualified_Printablestring(false, tvb, offset, &asn1_ctx, tree, hf_pkixqualified_Printablestring_PDU);
  return offset;
}
static int dissect_BiometricSyntax_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixqualified_BiometricSyntax(false, tvb, offset, &asn1_ctx, tree, hf_pkixqualified_BiometricSyntax_PDU);
  return offset;
}
static int dissect_QCStatements_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixqualified_QCStatements(false, tvb, offset, &asn1_ctx, tree, hf_pkixqualified_QCStatements_PDU);
  return offset;
}
static int dissect_SemanticsInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixqualified_SemanticsInformation(false, tvb, offset, &asn1_ctx, tree, hf_pkixqualified_SemanticsInformation_PDU);
  return offset;
}
static int dissect_XmppAddr_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixqualified_XmppAddr(false, tvb, offset, &asn1_ctx, tree, hf_pkixqualified_XmppAddr_PDU);
  return offset;
}
static int dissect_SRVName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
  offset = dissect_pkixqualified_SRVName(false, tvb, offset, &asn1_ctx, tree, hf_pkixqualified_SRVName_PDU);
  return offset;
}



/*--- proto_register_pkixqualified ----------------------------------------------*/
void proto_register_pkixqualified(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_pkixqualified_Generalizedtime_PDU,
      { "Generalizedtime", "pkixqualified.Generalizedtime",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixqualified_Directorystring_PDU,
      { "Directorystring", "pkixqualified.Directorystring",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        NULL, HFILL }},
    { &hf_pkixqualified_Printablestring_PDU,
      { "Printablestring", "pkixqualified.Printablestring",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixqualified_BiometricSyntax_PDU,
      { "BiometricSyntax", "pkixqualified.BiometricSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixqualified_QCStatements_PDU,
      { "QCStatements", "pkixqualified.QCStatements",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixqualified_SemanticsInformation_PDU,
      { "SemanticsInformation", "pkixqualified.SemanticsInformation_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixqualified_XmppAddr_PDU,
      { "XmppAddr", "pkixqualified.XmppAddr",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixqualified_SRVName_PDU,
      { "SRVName", "pkixqualified.SRVName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixqualified_BiometricSyntax_item,
      { "BiometricData", "pkixqualified.BiometricData_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixqualified_typeOfBiometricData,
      { "typeOfBiometricData", "pkixqualified.typeOfBiometricData",
        FT_UINT32, BASE_DEC, VALS(pkixqualified_TypeOfBiometricData_vals), 0,
        NULL, HFILL }},
    { &hf_pkixqualified_hashAlgorithm,
      { "hashAlgorithm", "pkixqualified.hashAlgorithm_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "AlgorithmIdentifier", HFILL }},
    { &hf_pkixqualified_biometricDataHash,
      { "biometricDataHash", "pkixqualified.biometricDataHash",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_pkixqualified_sourceDataUri,
      { "sourceDataUri", "pkixqualified.sourceDataUri",
        FT_STRING, BASE_NONE, NULL, 0,
        "IA5String", HFILL }},
    { &hf_pkixqualified_predefinedBiometricType,
      { "predefinedBiometricType", "pkixqualified.predefinedBiometricType",
        FT_INT32, BASE_DEC, VALS(pkixqualified_PredefinedBiometricType_vals), 0,
        NULL, HFILL }},
    { &hf_pkixqualified_biometricDataOid,
      { "biometricDataOid", "pkixqualified.biometricDataOid",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkixqualified_QCStatements_item,
      { "QCStatement", "pkixqualified.QCStatement_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixqualified_statementId,
      { "statementId", "pkixqualified.statementId",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixqualified_statementInfo,
      { "statementInfo", "pkixqualified.statementInfo_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixqualified_semanticsIdentifier,
      { "semanticsIdentifier", "pkixqualified.semanticsIdentifier",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkixqualified_nameRegistrationAuthorities,
      { "nameRegistrationAuthorities", "pkixqualified.nameRegistrationAuthorities",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_pkixqualified_NameRegistrationAuthorities_item,
      { "GeneralName", "pkixqualified.GeneralName",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        NULL, HFILL }},
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_pkixqualified_BiometricSyntax,
    &ett_pkixqualified_BiometricData,
    &ett_pkixqualified_TypeOfBiometricData,
    &ett_pkixqualified_QCStatements,
    &ett_pkixqualified_QCStatement,
    &ett_pkixqualified_SemanticsInformation,
    &ett_pkixqualified_NameRegistrationAuthorities,
  };

  /* Register protocol */
  proto_pkixqualified = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkixqualified, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkixqualified -------------------------------------------*/
void proto_reg_handoff_pkixqualified(void) {
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.2", dissect_BiometricSyntax_PDU, proto_pkixqualified, "id-pe-biometricInfo");
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.3", dissect_QCStatements_PDU, proto_pkixqualified, "id-pe-qcStatements");
  register_ber_oid_dissector("1.3.6.1.5.5.7.11.1", dissect_SemanticsInformation_PDU, proto_pkixqualified, "id-qcs-pkixQCSyntax-v1");
  register_ber_oid_dissector("1.3.6.1.5.5.7.11.2", dissect_SemanticsInformation_PDU, proto_pkixqualified, "id-qcs-pkixQCSyntax-v2");
  register_ber_oid_dissector("1.3.6.1.5.5.7.8.5", dissect_XmppAddr_PDU, proto_pkixqualified, "id-on-xmppAddr");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.1", dissect_Generalizedtime_PDU, proto_pkixqualified, "id-pda-dateOfBirth");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.2", dissect_Directorystring_PDU, proto_pkixqualified, "id-pda-placeOfBirth");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.3", dissect_Printablestring_PDU, proto_pkixqualified, "id-pda-gender");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.4", dissect_Printablestring_PDU, proto_pkixqualified, "id-pda-countryOfCitizenship");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.5", dissect_Printablestring_PDU, proto_pkixqualified, "id-pda-countryOfResidence");
  register_ber_oid_dissector("1.3.6.1.5.5.7.8.7", dissect_SRVName_PDU, proto_pkixqualified, "id-on-dnsSRV");

}

