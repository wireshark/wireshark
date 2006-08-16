/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-pkixqualified.c                                                   */
/* ../../tools/asn2wrs.py -b -e -p pkixqualified -c pkixqualified.cnf -s packet-pkixqualified-template PKIXqualified.asn */

/* Input file: packet-pkixqualified-template.c */

#line 1 "packet-pkixqualified-template.c"
/* packet-pkixqualified.c
 * Routines for RFC3739 PKIXqualified packet dissection
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
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-pkixqualified.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509sat.h"

#define PNAME  "PKIX Qualified"
#define PSNAME "PKIXQUALIFIED"
#define PFNAME "pkixqualified"

/* Initialize the protocol and registered fields */
int proto_pkixqualified = -1;

/*--- Included file: packet-pkixqualified-hf.c ---*/
#line 1 "packet-pkixqualified-hf.c"
static int hf_pkixqualified_Generalizedtime_PDU = -1;  /* Generalizedtime */
static int hf_pkixqualified_Directorystring_PDU = -1;  /* Directorystring */
static int hf_pkixqualified_Printablestring_PDU = -1;  /* Printablestring */
static int hf_pkixqualified_BiometricSyntax_PDU = -1;  /* BiometricSyntax */
static int hf_pkixqualified_QCStatements_PDU = -1;  /* QCStatements */
static int hf_pkixqualified_SemanticsInformation_PDU = -1;  /* SemanticsInformation */
static int hf_pkixqualified_BiometricSyntax_item = -1;  /* BiometricData */
static int hf_pkixqualified_typeOfBiometricData = -1;  /* TypeOfBiometricData */
static int hf_pkixqualified_hashAlgorithm = -1;   /* AlgorithmIdentifier */
static int hf_pkixqualified_biometricDataHash = -1;  /* OCTET_STRING */
static int hf_pkixqualified_sourceDataUri = -1;   /* IA5String */
static int hf_pkixqualified_predefinedBiometricType = -1;  /* PredefinedBiometricType */
static int hf_pkixqualified_biometricDataOid = -1;  /* OBJECT_IDENTIFIER */
static int hf_pkixqualified_QCStatements_item = -1;  /* QCStatement */
static int hf_pkixqualified_statementId = -1;     /* T_statementId */
static int hf_pkixqualified_statementInfo = -1;   /* T_statementInfo */
static int hf_pkixqualified_semanticsIdentifier = -1;  /* OBJECT_IDENTIFIER */
static int hf_pkixqualified_nameRegistrationAuthorities = -1;  /* NameRegistrationAuthorities */
static int hf_pkixqualified_NameRegistrationAuthorities_item = -1;  /* GeneralName */

/*--- End of included file: packet-pkixqualified-hf.c ---*/
#line 50 "packet-pkixqualified-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-pkixqualified-ett.c ---*/
#line 1 "packet-pkixqualified-ett.c"
static gint ett_pkixqualified_BiometricSyntax = -1;
static gint ett_pkixqualified_BiometricData = -1;
static gint ett_pkixqualified_TypeOfBiometricData = -1;
static gint ett_pkixqualified_QCStatements = -1;
static gint ett_pkixqualified_QCStatement = -1;
static gint ett_pkixqualified_SemanticsInformation = -1;
static gint ett_pkixqualified_NameRegistrationAuthorities = -1;

/*--- End of included file: packet-pkixqualified-ett.c ---*/
#line 53 "packet-pkixqualified-template.c"

static const char *object_identifier_id;


/*--- Included file: packet-pkixqualified-fn.c ---*/
#line 1 "packet-pkixqualified-fn.c"
/*--- Fields for imported types ---*/

static int dissect_hashAlgorithm(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509af_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_pkixqualified_hashAlgorithm);
}
static int dissect_NameRegistrationAuthorities_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralName(FALSE, tvb, offset, pinfo, tree, hf_pkixqualified_NameRegistrationAuthorities_item);
}



static int
dissect_pkixqualified_Generalizedtime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_pkixqualified_Directorystring(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509sat_DirectoryString(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



static int
dissect_pkixqualified_Printablestring(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string pkixqualified_PredefinedBiometricType_vals[] = {
  {   0, "picture" },
  {   1, "handwritten-signature" },
  { 0, NULL }
};


static int
dissect_pkixqualified_PredefinedBiometricType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_predefinedBiometricType(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixqualified_PredefinedBiometricType(FALSE, tvb, offset, pinfo, tree, hf_pkixqualified_predefinedBiometricType);
}



static int
dissect_pkixqualified_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_biometricDataOid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixqualified_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_pkixqualified_biometricDataOid);
}
static int dissect_semanticsIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixqualified_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_pkixqualified_semanticsIdentifier);
}


static const value_string pkixqualified_TypeOfBiometricData_vals[] = {
  {   0, "predefinedBiometricType" },
  {   1, "biometricDataOid" },
  { 0, NULL }
};

static const ber_choice_t TypeOfBiometricData_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_predefinedBiometricType },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_biometricDataOid },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_pkixqualified_TypeOfBiometricData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 TypeOfBiometricData_choice, hf_index, ett_pkixqualified_TypeOfBiometricData,
                                 NULL);

  return offset;
}
static int dissect_typeOfBiometricData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixqualified_TypeOfBiometricData(FALSE, tvb, offset, pinfo, tree, hf_pkixqualified_typeOfBiometricData);
}



static int
dissect_pkixqualified_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_biometricDataHash(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixqualified_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_pkixqualified_biometricDataHash);
}



static int
dissect_pkixqualified_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_sourceDataUri(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixqualified_IA5String(FALSE, tvb, offset, pinfo, tree, hf_pkixqualified_sourceDataUri);
}


static const ber_sequence_t BiometricData_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_typeOfBiometricData },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_hashAlgorithm },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_biometricDataHash },
  { BER_CLASS_UNI, BER_UNI_TAG_IA5String, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_sourceDataUri },
  { 0, 0, 0, NULL }
};

static int
dissect_pkixqualified_BiometricData(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   BiometricData_sequence, hf_index, ett_pkixqualified_BiometricData);

  return offset;
}
static int dissect_BiometricSyntax_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixqualified_BiometricData(FALSE, tvb, offset, pinfo, tree, hf_pkixqualified_BiometricSyntax_item);
}


static const ber_sequence_t BiometricSyntax_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_BiometricSyntax_item },
};

static int
dissect_pkixqualified_BiometricSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      BiometricSyntax_sequence_of, hf_index, ett_pkixqualified_BiometricSyntax);

  return offset;
}



static int
dissect_pkixqualified_T_statementId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_pkixqualified_statementId, &object_identifier_id);

  return offset;
}
static int dissect_statementId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixqualified_T_statementId(FALSE, tvb, offset, pinfo, tree, hf_pkixqualified_statementId);
}



static int
dissect_pkixqualified_T_statementInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 33 "pkixqualified.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_statementInfo(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixqualified_T_statementInfo(FALSE, tvb, offset, pinfo, tree, hf_pkixqualified_statementInfo);
}


static const ber_sequence_t QCStatement_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_statementId },
  { BER_CLASS_ANY, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_statementInfo },
  { 0, 0, 0, NULL }
};

static int
dissect_pkixqualified_QCStatement(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   QCStatement_sequence, hf_index, ett_pkixqualified_QCStatement);

  return offset;
}
static int dissect_QCStatements_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixqualified_QCStatement(FALSE, tvb, offset, pinfo, tree, hf_pkixqualified_QCStatements_item);
}


static const ber_sequence_t QCStatements_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_QCStatements_item },
};

static int
dissect_pkixqualified_QCStatements(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      QCStatements_sequence_of, hf_index, ett_pkixqualified_QCStatements);

  return offset;
}


static const ber_sequence_t NameRegistrationAuthorities_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_NameRegistrationAuthorities_item },
};

static int
dissect_pkixqualified_NameRegistrationAuthorities(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      NameRegistrationAuthorities_sequence_of, hf_index, ett_pkixqualified_NameRegistrationAuthorities);

  return offset;
}
static int dissect_nameRegistrationAuthorities(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkixqualified_NameRegistrationAuthorities(FALSE, tvb, offset, pinfo, tree, hf_pkixqualified_nameRegistrationAuthorities);
}


static const ber_sequence_t SemanticsInformation_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_semanticsIdentifier },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_nameRegistrationAuthorities },
  { 0, 0, 0, NULL }
};

static int
dissect_pkixqualified_SemanticsInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   SemanticsInformation_sequence, hf_index, ett_pkixqualified_SemanticsInformation);

  return offset;
}

/*--- PDUs ---*/

static void dissect_Generalizedtime_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkixqualified_Generalizedtime(FALSE, tvb, 0, pinfo, tree, hf_pkixqualified_Generalizedtime_PDU);
}
static void dissect_Directorystring_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkixqualified_Directorystring(FALSE, tvb, 0, pinfo, tree, hf_pkixqualified_Directorystring_PDU);
}
static void dissect_Printablestring_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkixqualified_Printablestring(FALSE, tvb, 0, pinfo, tree, hf_pkixqualified_Printablestring_PDU);
}
static void dissect_BiometricSyntax_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkixqualified_BiometricSyntax(FALSE, tvb, 0, pinfo, tree, hf_pkixqualified_BiometricSyntax_PDU);
}
static void dissect_QCStatements_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkixqualified_QCStatements(FALSE, tvb, 0, pinfo, tree, hf_pkixqualified_QCStatements_PDU);
}
static void dissect_SemanticsInformation_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkixqualified_SemanticsInformation(FALSE, tvb, 0, pinfo, tree, hf_pkixqualified_SemanticsInformation_PDU);
}


/*--- End of included file: packet-pkixqualified-fn.c ---*/
#line 57 "packet-pkixqualified-template.c"


/*--- proto_register_pkixqualified ----------------------------------------------*/
void proto_register_pkixqualified(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-pkixqualified-hfarr.c ---*/
#line 1 "packet-pkixqualified-hfarr.c"
    { &hf_pkixqualified_Generalizedtime_PDU,
      { "Generalizedtime", "pkixqualified.Generalizedtime",
        FT_STRING, BASE_NONE, NULL, 0,
        "pkixqualified.Generalizedtime", HFILL }},
    { &hf_pkixqualified_Directorystring_PDU,
      { "Directorystring", "pkixqualified.Directorystring",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "pkixqualified.Directorystring", HFILL }},
    { &hf_pkixqualified_Printablestring_PDU,
      { "Printablestring", "pkixqualified.Printablestring",
        FT_STRING, BASE_NONE, NULL, 0,
        "pkixqualified.Printablestring", HFILL }},
    { &hf_pkixqualified_BiometricSyntax_PDU,
      { "BiometricSyntax", "pkixqualified.BiometricSyntax",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkixqualified.BiometricSyntax", HFILL }},
    { &hf_pkixqualified_QCStatements_PDU,
      { "QCStatements", "pkixqualified.QCStatements",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkixqualified.QCStatements", HFILL }},
    { &hf_pkixqualified_SemanticsInformation_PDU,
      { "SemanticsInformation", "pkixqualified.SemanticsInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkixqualified.SemanticsInformation", HFILL }},
    { &hf_pkixqualified_BiometricSyntax_item,
      { "Item", "pkixqualified.BiometricSyntax_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkixqualified.BiometricData", HFILL }},
    { &hf_pkixqualified_typeOfBiometricData,
      { "typeOfBiometricData", "pkixqualified.typeOfBiometricData",
        FT_UINT32, BASE_DEC, VALS(pkixqualified_TypeOfBiometricData_vals), 0,
        "pkixqualified.TypeOfBiometricData", HFILL }},
    { &hf_pkixqualified_hashAlgorithm,
      { "hashAlgorithm", "pkixqualified.hashAlgorithm",
        FT_NONE, BASE_NONE, NULL, 0,
        "x509af.AlgorithmIdentifier", HFILL }},
    { &hf_pkixqualified_biometricDataHash,
      { "biometricDataHash", "pkixqualified.biometricDataHash",
        FT_BYTES, BASE_HEX, NULL, 0,
        "pkixqualified.OCTET_STRING", HFILL }},
    { &hf_pkixqualified_sourceDataUri,
      { "sourceDataUri", "pkixqualified.sourceDataUri",
        FT_STRING, BASE_NONE, NULL, 0,
        "pkixqualified.IA5String", HFILL }},
    { &hf_pkixqualified_predefinedBiometricType,
      { "predefinedBiometricType", "pkixqualified.predefinedBiometricType",
        FT_INT32, BASE_DEC, VALS(pkixqualified_PredefinedBiometricType_vals), 0,
        "pkixqualified.PredefinedBiometricType", HFILL }},
    { &hf_pkixqualified_biometricDataOid,
      { "biometricDataOid", "pkixqualified.biometricDataOid",
        FT_OID, BASE_NONE, NULL, 0,
        "pkixqualified.OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkixqualified_QCStatements_item,
      { "Item", "pkixqualified.QCStatements_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkixqualified.QCStatement", HFILL }},
    { &hf_pkixqualified_statementId,
      { "statementId", "pkixqualified.statementId",
        FT_OID, BASE_NONE, NULL, 0,
        "pkixqualified.T_statementId", HFILL }},
    { &hf_pkixqualified_statementInfo,
      { "statementInfo", "pkixqualified.statementInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkixqualified.T_statementInfo", HFILL }},
    { &hf_pkixqualified_semanticsIdentifier,
      { "semanticsIdentifier", "pkixqualified.semanticsIdentifier",
        FT_OID, BASE_NONE, NULL, 0,
        "pkixqualified.OBJECT_IDENTIFIER", HFILL }},
    { &hf_pkixqualified_nameRegistrationAuthorities,
      { "nameRegistrationAuthorities", "pkixqualified.nameRegistrationAuthorities",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkixqualified.NameRegistrationAuthorities", HFILL }},
    { &hf_pkixqualified_NameRegistrationAuthorities_item,
      { "Item", "pkixqualified.NameRegistrationAuthorities_item",
        FT_UINT32, BASE_DEC, VALS(x509ce_GeneralName_vals), 0,
        "x509ce.GeneralName", HFILL }},

/*--- End of included file: packet-pkixqualified-hfarr.c ---*/
#line 65 "packet-pkixqualified-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-pkixqualified-ettarr.c ---*/
#line 1 "packet-pkixqualified-ettarr.c"
    &ett_pkixqualified_BiometricSyntax,
    &ett_pkixqualified_BiometricData,
    &ett_pkixqualified_TypeOfBiometricData,
    &ett_pkixqualified_QCStatements,
    &ett_pkixqualified_QCStatement,
    &ett_pkixqualified_SemanticsInformation,
    &ett_pkixqualified_NameRegistrationAuthorities,

/*--- End of included file: packet-pkixqualified-ettarr.c ---*/
#line 70 "packet-pkixqualified-template.c"
  };

  /* Register protocol */
  proto_pkixqualified = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkixqualified, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkixqualified -------------------------------------------*/
void proto_reg_handoff_pkixqualified(void) {

/*--- Included file: packet-pkixqualified-dis-tab.c ---*/
#line 1 "packet-pkixqualified-dis-tab.c"
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.2", dissect_BiometricSyntax_PDU, proto_pkixqualified, "id-pe-biometricInfo");
  register_ber_oid_dissector("1.3.6.1.5.5.7.1.3", dissect_QCStatements_PDU, proto_pkixqualified, "id-pe-qcStatements");
  register_ber_oid_dissector("1.3.6.1.5.5.7.11.1", dissect_SemanticsInformation_PDU, proto_pkixqualified, "id-qcs-pkixQCSyntax-v1");
  register_ber_oid_dissector("1.3.6.1.5.5.7.11.2", dissect_SemanticsInformation_PDU, proto_pkixqualified, "id-qcs-pkixQCSyntax-v2");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.1", dissect_Generalizedtime_PDU, proto_pkixqualified, "id-pda-dateOfBirth");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.2", dissect_Directorystring_PDU, proto_pkixqualified, "id-pda-placeOfBirth");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.3", dissect_Printablestring_PDU, proto_pkixqualified, "id-pda-gender");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.4", dissect_Printablestring_PDU, proto_pkixqualified, "id-pda-countryOfCitizenship");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.5", dissect_Printablestring_PDU, proto_pkixqualified, "id-pda-countryOfResidence");


/*--- End of included file: packet-pkixqualified-dis-tab.c ---*/
#line 85 "packet-pkixqualified-template.c"
}

