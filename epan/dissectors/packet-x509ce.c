/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce.c                                                            */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

/* Input file: packet-x509ce-template.c */
/* Include files: packet-x509ce-hf.c, packet-x509ce-ett.c, packet-x509ce-fn.c, packet-x509ce-hfarr.c, packet-x509ce-ettarr.c, packet-x509ce-val.h */

/* packet-x509ce.c
 * Routines for X.509 Certificate Extensions packet dissection
 *
 * $Id: packet-x509ce-template.c,v 1.2 2004/05/25 21:07:43 guy Exp $
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
#include "packet-x509ce.h"
#include "packet-x509if.h"

#define PNAME  "X.509 Certificate Extensions"
#define PSNAME "X509CE"
#define PFNAME "x509ce"

/* Initialize the protocol and registered fields */
int proto_x509ce = -1;
static int hf_x509ce_id_ce_subjectDirectoryAttributes = -1;
static int hf_x509ce_id_ce_subjectKeyIdentifier = -1;
static int hf_x509ce_id_ce_keyUsage = -1;
static int hf_x509ce_id_ce_privateKeyUsagePeriod = -1;
static int hf_x509ce_id_ce_subjectAltName = -1;
static int hf_x509ce_id_ce_issuerAltName = -1;
static int hf_x509ce_id_ce_basicConstraints = -1;
static int hf_x509ce_id_ce_cRLNumber = -1;
static int hf_x509ce_id_ce_reasonCode = -1;

/*--- Included file: packet-x509ce-hf.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-hf.c                                                         */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

static int hf_x509ce_notBefore = -1;              /* GeneralizedTime */
static int hf_x509ce_notAfter = -1;               /* GeneralizedTime */
static int hf_x509ce_GeneralNames_item = -1;      /* GeneralName */
static int hf_x509ce_rfc822Name = -1;             /* IA5String */
static int hf_x509ce_dNSName = -1;                /* IA5String */
static int hf_x509ce_uniformResourceIdentifier = -1;  /* IA5String */
static int hf_x509ce_iPAddress = -1;              /* OCTET_STRING */
static int hf_x509ce_registeredID = -1;           /* OBJECT_IDENTIFIER */
static int hf_x509ce_AttributesSyntax_item = -1;  /* Attribute */
static int hf_x509ce_cA = -1;                     /* BOOLEAN */
static int hf_x509ce_pathLenConstraint = -1;      /* INTEGER */
/* named bits */
static int hf_x509ce_KeyUsage_digitalSignature = -1;
static int hf_x509ce_KeyUsage_nonRepudiation = -1;
static int hf_x509ce_KeyUsage_keyEncipherment = -1;
static int hf_x509ce_KeyUsage_dataEncipherment = -1;
static int hf_x509ce_KeyUsage_keyAgreement = -1;
static int hf_x509ce_KeyUsage_keyCertSign = -1;
static int hf_x509ce_KeyUsage_cRLSign = -1;
static int hf_x509ce_KeyUsage_encipherOnly = -1;
static int hf_x509ce_KeyUsage_decipherOnly = -1;

/*--- End of included file: packet-x509ce-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-x509ce-ett.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-ett.c                                                        */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

static gint ett_x509ce_KeyUsage = -1;
static gint ett_x509ce_PrivateKeyUsagePeriod = -1;
static gint ett_x509ce_GeneralNames = -1;
static gint ett_x509ce_GeneralName = -1;
static gint ett_x509ce_AttributesSyntax = -1;
static gint ett_x509ce_BasicConstraintsSyntax = -1;

/*--- End of included file: packet-x509ce-ett.c ---*/



/*--- Included file: packet-x509ce-fn.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-fn.c                                                         */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

static int dissect_AttributesSyntax_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_x509ce_AttributesSyntax_item);
}

static int
dissect_x509ce_KeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}


static int
dissect_x509ce_SubjectKeyIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509ce_KeyIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}

static asn_namedbit KeyUsage_bits[] = {
  {  0, &hf_x509ce_KeyUsage_digitalSignature, -1, -1, NULL, NULL },
  {  1, &hf_x509ce_KeyUsage_nonRepudiation, -1, -1, NULL, NULL },
  {  2, &hf_x509ce_KeyUsage_keyEncipherment, -1, -1, NULL, NULL },
  {  3, &hf_x509ce_KeyUsage_dataEncipherment, -1, -1, NULL, NULL },
  {  4, &hf_x509ce_KeyUsage_keyAgreement, -1, -1, NULL, NULL },
  {  5, &hf_x509ce_KeyUsage_keyCertSign, -1, -1, NULL, NULL },
  {  6, &hf_x509ce_KeyUsage_cRLSign, -1, -1, NULL, NULL },
  {  7, &hf_x509ce_KeyUsage_encipherOnly, -1, -1, NULL, NULL },
  {  8, &hf_x509ce_KeyUsage_decipherOnly, -1, -1, NULL, NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x509ce_KeyUsage(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 KeyUsage_bits, hf_index, ett_x509ce_KeyUsage,
                                 NULL);

  return offset;
}


static int
dissect_x509ce_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_generalized_time(pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_notBefore(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_x509ce_notBefore);
}
static int dissect_notAfter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_x509ce_notAfter);
}

static ber_sequence PrivateKeyUsagePeriod_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_notBefore },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_notAfter },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_PrivateKeyUsagePeriod(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PrivateKeyUsagePeriod_sequence, hf_index, ett_x509ce_PrivateKeyUsagePeriod);

  return offset;
}


static int
dissect_x509ce_IA5String(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, 1,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}
static int dissect_rfc822Name(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_IA5String(FALSE, tvb, offset, pinfo, tree, hf_x509ce_rfc822Name);
}
static int dissect_dNSName(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_IA5String(FALSE, tvb, offset, pinfo, tree, hf_x509ce_dNSName);
}
static int dissect_uniformResourceIdentifier(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_IA5String(FALSE, tvb, offset, pinfo, tree, hf_x509ce_uniformResourceIdentifier);
}


static int
dissect_x509ce_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_iPAddress(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_x509ce_iPAddress);
}


static int
dissect_x509ce_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset,
                                         hf_index, NULL);

  return offset;
}
static int dissect_registeredID(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509ce_registeredID);
}


static const value_string GeneralName_vals[] = {
  {   1, "rfc822Name" },
  {   2, "dNSName" },
  {   6, "uniformResourceIdentifier" },
  {   7, "iPAddress" },
  {   8, "registeredID" },
  { 0, NULL }
};

static ber_choice GeneralName_choice[] = {
  {   1, BER_CLASS_CON, 1, 0, dissect_rfc822Name },
  {   2, BER_CLASS_CON, 2, 0, dissect_dNSName },
  {   6, BER_CLASS_CON, 6, 0, dissect_uniformResourceIdentifier },
  {   7, BER_CLASS_CON, 7, 0, dissect_iPAddress },
  {   8, BER_CLASS_CON, 8, 0, dissect_registeredID },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509ce_GeneralName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              GeneralName_choice, hf_index, ett_x509ce_GeneralName);

  return offset;
}
static int dissect_GeneralNames_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_GeneralName(FALSE, tvb, offset, pinfo, tree, hf_x509ce_GeneralNames_item);
}

static ber_sequence GeneralNames_sequence_of[1] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_GeneralNames_item },
};

int
dissect_x509ce_GeneralNames(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   GeneralNames_sequence_of, hf_index, ett_x509ce_GeneralNames);

  return offset;
}

static ber_sequence AttributesSyntax_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_AttributesSyntax_item },
};

static int
dissect_x509ce_AttributesSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   AttributesSyntax_sequence_of, hf_index, ett_x509ce_AttributesSyntax);

  return offset;
}


static int
dissect_x509ce_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_boolean(pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_cA(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_x509ce_cA);
}



static int
dissect_x509ce_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_pathLenConstraint(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509ce_pathLenConstraint);
}

static ber_sequence BasicConstraintsSyntax_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_cA },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_pathLenConstraint },
  { 0, 0, 0, NULL }
};

static int
dissect_x509ce_BasicConstraintsSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                BasicConstraintsSyntax_sequence, hf_index, ett_x509ce_BasicConstraintsSyntax);

  return offset;
}



static int
dissect_x509ce_CRLNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string CRLReason_vals[] = {
  {   0, "unspecified" },
  {   1, "keyCompromise" },
  {   2, "cACompromise" },
  {   3, "affiliationChanged" },
  {   4, "superseded" },
  {   5, "cessationOfOperation" },
  {   6, "certificateHold" },
  {   8, "removeFromCRL" },
  {   9, "privilegeWithdrawn" },
  {  10, "aaCompromise" },
  { 0, NULL }
};


static int
dissect_x509ce_CRLReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer(pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}


/*--- End of included file: packet-x509ce-fn.c ---*/



static void
dissect_x509ce_subjectDirectoryAttributes_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_AttributesSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_subjectDirectoryAttributes);
}

static void
dissect_x509ce_subjectKeyIdentifier_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_SubjectKeyIdentifier(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_subjectKeyIdentifier);
}

static void
dissect_x509ce_keyUsage_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_KeyUsage(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_keyUsage);
}

static void
dissect_x509ce_privateKeyUsagePeriod_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_PrivateKeyUsagePeriod(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_privateKeyUsagePeriod);
}

static void
dissect_x509ce_subjectAltName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralNames(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_subjectAltName);
}

static void
dissect_x509ce_issuerAltName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralNames(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_issuerAltName);
}

static void
dissect_x509ce_basicConstraints_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_BasicConstraintsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_basicConstraints);
}

static void
dissect_x509ce_cRLNumber_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CRLNumber(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_cRLNumber);
}

static void
dissect_x509ce_reasonCode_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CRLReason(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_reasonCode);
}

/*--- proto_register_x509ce ----------------------------------------------*/
void proto_register_x509ce(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509ce_id_ce_reasonCode,
      { "reasonCode", "x509ce.id_ce_reasonCode",
        FT_UINT32, BASE_DEC, VALS(CRLReason_vals), 0,
        "reasonCode", HFILL }},
    { &hf_x509ce_id_ce_cRLNumber,
      { "cRLNumber", "x509ce.id_ce_cRLNumber",
        FT_UINT32, BASE_DEC, NULL, 0,
        "cRLNumber", HFILL }},
    { &hf_x509ce_id_ce_basicConstraints,
      { "basicConstraints", "x509ce.id_ce_basicConstraints",
        FT_NONE, BASE_NONE, NULL, 0,
        "basicConstraints", HFILL }},
    { &hf_x509ce_id_ce_issuerAltName,
      { "issuerAltName", "x509ce.id_ce_issuerAltName",
        FT_NONE, BASE_NONE, NULL, 0,
        "issuerAltName", HFILL }},
    { &hf_x509ce_id_ce_subjectAltName,
      { "subjectAltName", "x509ce.id_ce_subjectAltName",
        FT_NONE, BASE_NONE, NULL, 0,
        "subjectAltName", HFILL }},
    { &hf_x509ce_id_ce_privateKeyUsagePeriod,
      { "privateKeyUsagePeriod", "x509ce.id_ce_privateKeyUsagePeriod",
        FT_NONE, BASE_NONE, NULL, 0,
        "privateKeyUsagePeriod", HFILL }},
    { &hf_x509ce_id_ce_subjectDirectoryAttributes,
      { "subjectDirectoryAttributes", "x509ce.id_ce_subjectDirectoryAttributes",
        FT_NONE, BASE_NONE, NULL, 0,
        "subjectDirectoryAttributes", HFILL }},
    { &hf_x509ce_id_ce_subjectKeyIdentifier,
      { "subjectKeyIdentifier", "x509ce.id_ce_subjectKeyIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "subjectKeyIdentifier", HFILL }},
    { &hf_x509ce_id_ce_keyUsage,
      { "keyUsage", "x509ce.id_ce_keyUsage",
        FT_BYTES, BASE_HEX, NULL, 0,
        "keyUsage", HFILL }},

/*--- Included file: packet-x509ce-hfarr.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-hfarr.c                                                      */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

    { &hf_x509ce_notBefore,
      { "notBefore", "x509ce.notBefore",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrivateKeyUsagePeriod/notBefore", HFILL }},
    { &hf_x509ce_notAfter,
      { "notAfter", "x509ce.notAfter",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrivateKeyUsagePeriod/notAfter", HFILL }},
    { &hf_x509ce_GeneralNames_item,
      { "Item[##]", "x509ce.GeneralNames_item",
        FT_UINT32, BASE_DEC, VALS(GeneralName_vals), 0,
        "GeneralNames/_item", HFILL }},
    { &hf_x509ce_rfc822Name,
      { "rfc822Name", "x509ce.rfc822Name",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralName/rfc822Name", HFILL }},
    { &hf_x509ce_dNSName,
      { "dNSName", "x509ce.dNSName",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralName/dNSName", HFILL }},
    { &hf_x509ce_uniformResourceIdentifier,
      { "uniformResourceIdentifier", "x509ce.uniformResourceIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralName/uniformResourceIdentifier", HFILL }},
    { &hf_x509ce_iPAddress,
      { "iPAddress", "x509ce.iPAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "GeneralName/iPAddress", HFILL }},
    { &hf_x509ce_registeredID,
      { "registeredID", "x509ce.registeredID",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralName/registeredID", HFILL }},
    { &hf_x509ce_AttributesSyntax_item,
      { "Item[##]", "x509ce.AttributesSyntax_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributesSyntax/_item", HFILL }},
    { &hf_x509ce_cA,
      { "cA", "x509ce.cA",
        FT_BOOLEAN, 8, NULL, 0,
        "BasicConstraintsSyntax/cA", HFILL }},
    { &hf_x509ce_pathLenConstraint,
      { "pathLenConstraint", "x509ce.pathLenConstraint",
        FT_INT32, BASE_DEC, NULL, 0,
        "BasicConstraintsSyntax/pathLenConstraint", HFILL }},
    { &hf_x509ce_KeyUsage_digitalSignature,
      { "digitalSignature", "x509ce.digitalSignature",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_nonRepudiation,
      { "nonRepudiation", "x509ce.nonRepudiation",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_keyEncipherment,
      { "keyEncipherment", "x509ce.keyEncipherment",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_dataEncipherment,
      { "dataEncipherment", "x509ce.dataEncipherment",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_keyAgreement,
      { "keyAgreement", "x509ce.keyAgreement",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_keyCertSign,
      { "keyCertSign", "x509ce.keyCertSign",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_cRLSign,
      { "cRLSign", "x509ce.cRLSign",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_encipherOnly,
      { "encipherOnly", "x509ce.encipherOnly",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_x509ce_KeyUsage_decipherOnly,
      { "decipherOnly", "x509ce.decipherOnly",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},

/*--- End of included file: packet-x509ce-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-x509ce-ettarr.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-ettarr.c                                                     */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

    &ett_x509ce_KeyUsage,
    &ett_x509ce_PrivateKeyUsagePeriod,
    &ett_x509ce_GeneralNames,
    &ett_x509ce_GeneralName,
    &ett_x509ce_AttributesSyntax,
    &ett_x509ce_BasicConstraintsSyntax,

/*--- End of included file: packet-x509ce-ettarr.c ---*/

  };

  /* Register protocol */
  proto_x509ce = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509ce, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x509ce -------------------------------------------*/
void proto_reg_handoff_x509ce(void) {
	register_ber_oid_dissector("2.5.29.9", dissect_x509ce_subjectDirectoryAttributes_callback, proto_x509ce, "id-ce-subjectDirectoryAttributes");
	register_ber_oid_dissector("2.5.29.14", dissect_x509ce_subjectKeyIdentifier_callback, proto_x509ce, "id-ce-subjectKeyIdentifier");
	register_ber_oid_dissector("2.5.29.15", dissect_x509ce_keyUsage_callback, proto_x509ce, "id-ce-keyUsage");
	register_ber_oid_dissector("2.5.29.16", dissect_x509ce_privateKeyUsagePeriod_callback, proto_x509ce, "id-ce-privateKeyUsagePeriod");
	register_ber_oid_dissector("2.5.29.17", dissect_x509ce_subjectAltName_callback, proto_x509ce, "id-ce-subjectAltName");
	register_ber_oid_dissector("2.5.29.18", dissect_x509ce_issuerAltName_callback, proto_x509ce, "id-ce-issuerAltName");
	register_ber_oid_dissector("2.5.29.19", dissect_x509ce_basicConstraints_callback, proto_x509ce, "id-ce-basicConstraints");
	register_ber_oid_dissector("2.5.29.20", dissect_x509ce_cRLNumber_callback, proto_x509ce, "id-ce-cRLNumber");
	register_ber_oid_dissector("2.5.29.21", dissect_x509ce_reasonCode_callback, proto_x509ce, "id-ce-reasonCode");
}

