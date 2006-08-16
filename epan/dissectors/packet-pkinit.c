/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* .\packet-pkinit.c                                                          */
/* ../../tools/asn2wrs.py -e -b -p pkinit -c pkinit.cnf -s packet-pkinit-template PKINIT.asn */

/* Input file: packet-pkinit-template.c */

#line 1 "packet-pkinit-template.c"
/* packet-pkinit.c
 * Routines for PKINIT packet dissection
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
#include "packet-pkinit.h"
#include "packet-cms.h"
#include "packet-pkix1explicit.h"
#include "packet-kerberos.h"

#define PNAME  "PKINIT"
#define PSNAME "PKInit"
#define PFNAME "pkinit"

/* Initialize the protocol and registered fields */
static int proto_pkinit = -1;

/*--- Included file: packet-pkinit-hf.c ---*/
#line 1 "packet-pkinit-hf.c"
static int hf_pkinit_AuthPack_PDU = -1;           /* AuthPack */
static int hf_pkinit_KDCDHKeyInfo_PDU = -1;       /* KDCDHKeyInfo */
static int hf_pkinit_signedAuthPack = -1;         /* ContentInfo */
static int hf_pkinit_trustedCertifiers = -1;      /* SEQUENCE_OF_TrustedCA */
static int hf_pkinit_trustedCertifiers_item = -1;  /* TrustedCA */
static int hf_pkinit_kdcCert = -1;                /* IssuerAndSerialNumber */
static int hf_pkinit_caName = -1;                 /* Name */
static int hf_pkinit_issuerAndSerial = -1;        /* IssuerAndSerialNumber */
static int hf_pkinit_pkAuthenticator = -1;        /* PKAuthenticator */
static int hf_pkinit_clientPublicValue = -1;      /* SubjectPublicKeyInfo */
static int hf_pkinit_supportedCMSTypes = -1;      /* SEQUENCE_OF_AlgorithmIdentifier */
static int hf_pkinit_supportedCMSTypes_item = -1;  /* AlgorithmIdentifier */
static int hf_pkinit_cusec = -1;                  /* INTEGER */
static int hf_pkinit_ctime = -1;                  /* KerberosTime */
static int hf_pkinit_paNonce = -1;                /* INTEGER_0_4294967295 */
static int hf_pkinit_paChecksum = -1;             /* Checksum */
static int hf_pkinit_dhSignedData = -1;           /* ContentInfo */
static int hf_pkinit_encKeyPack = -1;             /* ContentInfo */
static int hf_pkinit_subjectPublicKey = -1;       /* BIT_STRING */
static int hf_pkinit_dhNonce = -1;                /* INTEGER */
static int hf_pkinit_dhKeyExpiration = -1;        /* KerberosTime */

/*--- End of included file: packet-pkinit-hf.c ---*/
#line 50 "packet-pkinit-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-pkinit-ett.c ---*/
#line 1 "packet-pkinit-ett.c"
static gint ett_pkinit_PaPkAsReq = -1;
static gint ett_pkinit_SEQUENCE_OF_TrustedCA = -1;
static gint ett_pkinit_TrustedCA = -1;
static gint ett_pkinit_AuthPack = -1;
static gint ett_pkinit_SEQUENCE_OF_AlgorithmIdentifier = -1;
static gint ett_pkinit_PKAuthenticator = -1;
static gint ett_pkinit_PaPkAsRep = -1;
static gint ett_pkinit_KDCDHKeyInfo = -1;

/*--- End of included file: packet-pkinit-ett.c ---*/
#line 53 "packet-pkinit-template.c"

static int dissect_KerberosV5Spec2_KerberosTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index _U_);
static int dissect_KerberosV5Spec2_Checksum(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index _U_);


/*--- Included file: packet-pkinit-fn.c ---*/
#line 1 "packet-pkinit-fn.c"
/*--- Fields for imported types ---*/

static int dissect_signedAuthPack(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ContentInfo(FALSE, tvb, offset, pinfo, tree, hf_pkinit_signedAuthPack);
}
static int dissect_kdcCert(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_IssuerAndSerialNumber(FALSE, tvb, offset, pinfo, tree, hf_pkinit_kdcCert);
}
static int dissect_caName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Name(FALSE, tvb, offset, pinfo, tree, hf_pkinit_caName);
}
static int dissect_issuerAndSerial(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_IssuerAndSerialNumber(FALSE, tvb, offset, pinfo, tree, hf_pkinit_issuerAndSerial);
}
static int dissect_clientPublicValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_SubjectPublicKeyInfo(FALSE, tvb, offset, pinfo, tree, hf_pkinit_clientPublicValue);
}
static int dissect_supportedCMSTypes_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_pkinit_supportedCMSTypes_item);
}
static int dissect_ctime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_KerberosV5Spec2_KerberosTime(FALSE, tvb, offset, pinfo, tree, hf_pkinit_ctime);
}
static int dissect_paChecksum(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_KerberosV5Spec2_Checksum(FALSE, tvb, offset, pinfo, tree, hf_pkinit_paChecksum);
}
static int dissect_dhSignedData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ContentInfo(FALSE, tvb, offset, pinfo, tree, hf_pkinit_dhSignedData);
}
static int dissect_encKeyPack(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ContentInfo(FALSE, tvb, offset, pinfo, tree, hf_pkinit_encKeyPack);
}
static int dissect_dhKeyExpiration(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_KerberosV5Spec2_KerberosTime(FALSE, tvb, offset, pinfo, tree, hf_pkinit_dhKeyExpiration);
}


static const value_string pkinit_TrustedCA_vals[] = {
  {   0, "caName" },
  {   2, "issuerAndSerial" },
  { 0, NULL }
};

static const ber_choice_t TrustedCA_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_caName },
  {   2, BER_CLASS_CON, 2, 0, dissect_issuerAndSerial },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_pkinit_TrustedCA(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 TrustedCA_choice, hf_index, ett_pkinit_TrustedCA,
                                 NULL);

  return offset;
}
static int dissect_trustedCertifiers_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkinit_TrustedCA(FALSE, tvb, offset, pinfo, tree, hf_pkinit_trustedCertifiers_item);
}


static const ber_sequence_t SEQUENCE_OF_TrustedCA_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_trustedCertifiers_item },
};

static int
dissect_pkinit_SEQUENCE_OF_TrustedCA(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_TrustedCA_sequence_of, hf_index, ett_pkinit_SEQUENCE_OF_TrustedCA);

  return offset;
}
static int dissect_trustedCertifiers(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkinit_SEQUENCE_OF_TrustedCA(FALSE, tvb, offset, pinfo, tree, hf_pkinit_trustedCertifiers);
}


static const ber_sequence_t PaPkAsReq_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_signedAuthPack },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_trustedCertifiers },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kdcCert },
  { 0, 0, 0, NULL }
};

static int
dissect_pkinit_PaPkAsReq(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PaPkAsReq_sequence, hf_index, ett_pkinit_PaPkAsReq);

  return offset;
}



static int
dissect_pkinit_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_cusec(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkinit_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkinit_cusec);
}
static int dissect_dhNonce(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkinit_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkinit_dhNonce);
}



static int
dissect_pkinit_INTEGER_0_4294967295(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_paNonce(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkinit_INTEGER_0_4294967295(FALSE, tvb, offset, pinfo, tree, hf_pkinit_paNonce);
}


static const ber_sequence_t PKAuthenticator_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_cusec },
  { BER_CLASS_CON, 1, 0, dissect_ctime },
  { BER_CLASS_CON, 2, 0, dissect_paNonce },
  { BER_CLASS_CON, 3, 0, dissect_paChecksum },
  { 0, 0, 0, NULL }
};

static int
dissect_pkinit_PKAuthenticator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PKAuthenticator_sequence, hf_index, ett_pkinit_PKAuthenticator);

  return offset;
}
static int dissect_pkAuthenticator(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkinit_PKAuthenticator(FALSE, tvb, offset, pinfo, tree, hf_pkinit_pkAuthenticator);
}


static const ber_sequence_t SEQUENCE_OF_AlgorithmIdentifier_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_supportedCMSTypes_item },
};

static int
dissect_pkinit_SEQUENCE_OF_AlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_AlgorithmIdentifier_sequence_of, hf_index, ett_pkinit_SEQUENCE_OF_AlgorithmIdentifier);

  return offset;
}
static int dissect_supportedCMSTypes(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkinit_SEQUENCE_OF_AlgorithmIdentifier(FALSE, tvb, offset, pinfo, tree, hf_pkinit_supportedCMSTypes);
}


static const ber_sequence_t AuthPack_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_pkAuthenticator },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_clientPublicValue },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_supportedCMSTypes },
  { 0, 0, 0, NULL }
};

static int
dissect_pkinit_AuthPack(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AuthPack_sequence, hf_index, ett_pkinit_AuthPack);

  return offset;
}


static const value_string pkinit_PaPkAsRep_vals[] = {
  {   0, "dhSignedData" },
  {   1, "encKeyPack" },
  { 0, NULL }
};

static const ber_choice_t PaPkAsRep_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_dhSignedData },
  {   1, BER_CLASS_CON, 1, 0, dissect_encKeyPack },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_pkinit_PaPkAsRep(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 PaPkAsRep_choice, hf_index, ett_pkinit_PaPkAsRep,
                                 NULL);

  return offset;
}



static int
dissect_pkinit_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_subjectPublicKey(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkinit_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_pkinit_subjectPublicKey);
}


static const ber_sequence_t KDCDHKeyInfo_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_subjectPublicKey },
  { BER_CLASS_CON, 1, 0, dissect_dhNonce },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_dhKeyExpiration },
  { 0, 0, 0, NULL }
};

static int
dissect_pkinit_KDCDHKeyInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   KDCDHKeyInfo_sequence, hf_index, ett_pkinit_KDCDHKeyInfo);

  return offset;
}

/*--- PDUs ---*/

static void dissect_AuthPack_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkinit_AuthPack(FALSE, tvb, 0, pinfo, tree, hf_pkinit_AuthPack_PDU);
}
static void dissect_KDCDHKeyInfo_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkinit_KDCDHKeyInfo(FALSE, tvb, 0, pinfo, tree, hf_pkinit_KDCDHKeyInfo_PDU);
}


/*--- End of included file: packet-pkinit-fn.c ---*/
#line 58 "packet-pkinit-template.c"

int
dissect_pkinit_PA_PK_AS_REQ(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  offset = dissect_pkinit_PaPkAsReq(FALSE, tvb, offset, pinfo, tree, -1);
  return offset;
}

int
dissect_pkinit_PA_PK_AS_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  offset = dissect_pkinit_PaPkAsRep(FALSE, tvb, offset, pinfo, tree, -1);
  return offset;
}

static int
dissect_KerberosV5Spec2_KerberosTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_ctime(pinfo, tree, tvb, offset);
  return offset;
}

static int
dissect_KerberosV5Spec2_Checksum(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_Checksum(pinfo, tree, tvb, offset);
  return offset;
}


/*--- proto_register_pkinit ----------------------------------------------*/
void proto_register_pkinit(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-pkinit-hfarr.c ---*/
#line 1 "packet-pkinit-hfarr.c"
    { &hf_pkinit_AuthPack_PDU,
      { "AuthPack", "pkinit.AuthPack",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkinit.AuthPack", HFILL }},
    { &hf_pkinit_KDCDHKeyInfo_PDU,
      { "KDCDHKeyInfo", "pkinit.KDCDHKeyInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkinit.KDCDHKeyInfo", HFILL }},
    { &hf_pkinit_signedAuthPack,
      { "signedAuthPack", "pkinit.signedAuthPack",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.ContentInfo", HFILL }},
    { &hf_pkinit_trustedCertifiers,
      { "trustedCertifiers", "pkinit.trustedCertifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkinit.SEQUENCE_OF_TrustedCA", HFILL }},
    { &hf_pkinit_trustedCertifiers_item,
      { "Item", "pkinit.trustedCertifiers_item",
        FT_UINT32, BASE_DEC, VALS(pkinit_TrustedCA_vals), 0,
        "pkinit.TrustedCA", HFILL }},
    { &hf_pkinit_kdcCert,
      { "kdcCert", "pkinit.kdcCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.IssuerAndSerialNumber", HFILL }},
    { &hf_pkinit_caName,
      { "caName", "pkinit.caName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkix1explicit.Name", HFILL }},
    { &hf_pkinit_issuerAndSerial,
      { "issuerAndSerial", "pkinit.issuerAndSerial",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.IssuerAndSerialNumber", HFILL }},
    { &hf_pkinit_pkAuthenticator,
      { "pkAuthenticator", "pkinit.pkAuthenticator",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkinit.PKAuthenticator", HFILL }},
    { &hf_pkinit_clientPublicValue,
      { "clientPublicValue", "pkinit.clientPublicValue",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkix1explicit.SubjectPublicKeyInfo", HFILL }},
    { &hf_pkinit_supportedCMSTypes,
      { "supportedCMSTypes", "pkinit.supportedCMSTypes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkinit.SEQUENCE_OF_AlgorithmIdentifier", HFILL }},
    { &hf_pkinit_supportedCMSTypes_item,
      { "Item", "pkinit.supportedCMSTypes_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "pkix1explicit.AlgorithmIdentifier", HFILL }},
    { &hf_pkinit_cusec,
      { "cusec", "pkinit.cusec",
        FT_INT32, BASE_DEC, NULL, 0,
        "pkinit.INTEGER", HFILL }},
    { &hf_pkinit_ctime,
      { "ctime", "pkinit.ctime",
        FT_NONE, BASE_NONE, NULL, 0,
        "KerberosV5Spec2.KerberosTime", HFILL }},
    { &hf_pkinit_paNonce,
      { "nonce", "pkinit.nonce",
        FT_UINT32, BASE_DEC, NULL, 0,
        "pkinit.INTEGER_0_4294967295", HFILL }},
    { &hf_pkinit_paChecksum,
      { "paChecksum", "pkinit.paChecksum",
        FT_NONE, BASE_NONE, NULL, 0,
        "KerberosV5Spec2.Checksum", HFILL }},
    { &hf_pkinit_dhSignedData,
      { "dhSignedData", "pkinit.dhSignedData",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.ContentInfo", HFILL }},
    { &hf_pkinit_encKeyPack,
      { "encKeyPack", "pkinit.encKeyPack",
        FT_NONE, BASE_NONE, NULL, 0,
        "cms.ContentInfo", HFILL }},
    { &hf_pkinit_subjectPublicKey,
      { "subjectPublicKey", "pkinit.subjectPublicKey",
        FT_BYTES, BASE_HEX, NULL, 0,
        "pkinit.BIT_STRING", HFILL }},
    { &hf_pkinit_dhNonce,
      { "nonce", "pkinit.nonce",
        FT_INT32, BASE_DEC, NULL, 0,
        "pkinit.INTEGER", HFILL }},
    { &hf_pkinit_dhKeyExpiration,
      { "dhKeyExpiration", "pkinit.dhKeyExpiration",
        FT_NONE, BASE_NONE, NULL, 0,
        "KerberosV5Spec2.KerberosTime", HFILL }},

/*--- End of included file: packet-pkinit-hfarr.c ---*/
#line 90 "packet-pkinit-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-pkinit-ettarr.c ---*/
#line 1 "packet-pkinit-ettarr.c"
    &ett_pkinit_PaPkAsReq,
    &ett_pkinit_SEQUENCE_OF_TrustedCA,
    &ett_pkinit_TrustedCA,
    &ett_pkinit_AuthPack,
    &ett_pkinit_SEQUENCE_OF_AlgorithmIdentifier,
    &ett_pkinit_PKAuthenticator,
    &ett_pkinit_PaPkAsRep,
    &ett_pkinit_KDCDHKeyInfo,

/*--- End of included file: packet-pkinit-ettarr.c ---*/
#line 95 "packet-pkinit-template.c"
  };

  /* Register protocol */
  proto_pkinit = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkinit, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkinit -------------------------------------------*/
void proto_reg_handoff_pkinit(void) {

/*--- Included file: packet-pkinit-dis-tab.c ---*/
#line 1 "packet-pkinit-dis-tab.c"
  register_ber_oid_dissector("1.3.6.1.5.2.3.1", dissect_AuthPack_PDU, proto_pkinit, "id-pkauthdata");
  register_ber_oid_dissector("1.3.6.1.5.2.3.2", dissect_KDCDHKeyInfo_PDU, proto_pkinit, "id-pkdhkeydata");


/*--- End of included file: packet-pkinit-dis-tab.c ---*/
#line 110 "packet-pkinit-template.c"
}

