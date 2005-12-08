/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-pkix1explicit.c                                                   */
/* ../../tools/asn2eth.py -e -X -b -p pkix1explicit -c pkix1explicit.cnf -s packet-pkix1explicit-template PKIX1EXPLICIT93.asn */

/* Input file: packet-pkix1explicit-template.c */

#line 1 "packet-pkix1explicit-template.c"
#define BER_UNI_TAG_TeletexString	    20  /* workaround bug in asn2eth */

/* packet-pkix1explicit.c
 * Routines for PKIX1Explitic packet dissection
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
#include "packet-pkix1explicit.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-x509ce.h"

#define PNAME  "PKIX1Explitit"
#define PSNAME "PKIX1EXPLICIT"
#define PFNAME "pkix1explicit"

/* Initialize the protocol and registered fields */
static int proto_pkix1explicit = -1;
static int hf_pkix1explicit_object_identifier_id = -1;

/*--- Included file: packet-pkix1explicit-hf.c ---*/
#line 1 "packet-pkix1explicit-hf.c"
static int hf_pkix1explicit_DomainParameters_PDU = -1;  /* DomainParameters */
static int hf_pkix1explicit_DirectoryString_PDU = -1;  /* DirectoryString */
static int hf_pkix1explicit_Extensions_item = -1;  /* Extension */
static int hf_pkix1explicit_extnId = -1;          /* T_extnId */
static int hf_pkix1explicit_critical = -1;        /* BOOLEAN */
static int hf_pkix1explicit_extnValue = -1;       /* T_extnValue */
static int hf_pkix1explicit_p = -1;               /* INTEGER */
static int hf_pkix1explicit_g = -1;               /* INTEGER */
static int hf_pkix1explicit_q = -1;               /* INTEGER */
static int hf_pkix1explicit_j = -1;               /* INTEGER */
static int hf_pkix1explicit_validationParms = -1;  /* ValidationParms */
static int hf_pkix1explicit_seed = -1;            /* BIT_STRING */
static int hf_pkix1explicit_pgenCounter = -1;     /* INTEGER */
static int hf_pkix1explicit_type = -1;            /* OBJECT_IDENTIFIER */
static int hf_pkix1explicit_value = -1;           /* T_value */
static int hf_pkix1explicit_RDNSequence_item = -1;  /* RelativeDistinguishedName */
static int hf_pkix1explicit_RelativeDistinguishedName_item = -1;  /* AttributeTypeAndValue */
static int hf_pkix1explicit_type1 = -1;           /* TeletexString */
static int hf_pkix1explicit_value1 = -1;          /* TeletexString */

/*--- End of included file: packet-pkix1explicit-hf.c ---*/
#line 52 "packet-pkix1explicit-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-pkix1explicit-ett.c ---*/
#line 1 "packet-pkix1explicit-ett.c"
static gint ett_pkix1explicit_Extensions = -1;
static gint ett_pkix1explicit_Extension = -1;
static gint ett_pkix1explicit_DomainParameters = -1;
static gint ett_pkix1explicit_ValidationParms = -1;
static gint ett_pkix1explicit_AttributeTypeAndValue = -1;
static gint ett_pkix1explicit_RDNSequence = -1;
static gint ett_pkix1explicit_RelativeDistinguishedName = -1;
static gint ett_pkix1explicit_TeletexDomainDefinedAttribute = -1;

/*--- End of included file: packet-pkix1explicit-ett.c ---*/
#line 55 "packet-pkix1explicit-template.c"


static const char *object_identifier_id;

int
dissect_pkix1explicit_Certificate(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_Certificate(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
int
dissect_pkix1explicit_CertificateList(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_CertificateList(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
int
dissect_pkix1explicit_GeneralName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509ce_GeneralName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
int
dissect_pkix1explicit_Name(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509if_Name(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
int
dissect_pkix1explicit_AlgorithmIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_AlgorithmIdentifier(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}

int
dissect_pkix1explicit_SubjectPublicKeyInfo(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_SubjectPublicKeyInfo(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}



/*--- Included file: packet-pkix1explicit-fn.c ---*/
#line 1 "packet-pkix1explicit-fn.c"
/*--- Fields for imported types ---*/




int
dissect_pkix1explicit_CertificateSerialNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_pkix1explicit_T_extnId(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier_str(implicit_tag, pinfo, tree, tvb, offset, hf_pkix1explicit_object_identifier_id, &object_identifier_id);

  return offset;
}
static int dissect_extnId(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_T_extnId(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_extnId);
}



static int
dissect_pkix1explicit_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_critical(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_critical);
}



static int
dissect_pkix1explicit_T_extnValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 44 "pkix1explicit.cnf"
  gint8 class;
  gboolean pc, ind;
  gint32 tag;
  guint32 len;
  /* skip past the T and L  */
  offset = dissect_ber_identifier(pinfo, tree, tvb, offset, &class, &pc, &tag);
  offset = dissect_ber_length(pinfo, tree, tvb, offset, &len, &ind);
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);




  return offset;
}
static int dissect_extnValue(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_T_extnValue(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_extnValue);
}


static const ber_sequence_t Extension_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_extnId },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_critical },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_extnValue },
  { 0, 0, 0, NULL }
};

int
dissect_pkix1explicit_Extension(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Extension_sequence, hf_index, ett_pkix1explicit_Extension);

  return offset;
}
static int dissect_Extensions_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_Extension(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_Extensions_item);
}


static const ber_sequence_t Extensions_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_Extensions_item },
};

int
dissect_pkix1explicit_Extensions(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      Extensions_sequence_of, hf_index, ett_pkix1explicit_Extensions);

  return offset;
}



static int
dissect_pkix1explicit_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_p(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_p);
}
static int dissect_g(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_g);
}
static int dissect_q(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_q);
}
static int dissect_j(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_j);
}
static int dissect_pgenCounter(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_pgenCounter);
}



static int
dissect_pkix1explicit_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_seed(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_seed);
}


static const ber_sequence_t ValidationParms_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_seed },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pgenCounter },
  { 0, 0, 0, NULL }
};

static int
dissect_pkix1explicit_ValidationParms(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ValidationParms_sequence, hf_index, ett_pkix1explicit_ValidationParms);

  return offset;
}
static int dissect_validationParms(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_ValidationParms(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_validationParms);
}


static const ber_sequence_t DomainParameters_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_p },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_g },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_q },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_j },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_validationParms },
  { 0, 0, 0, NULL }
};

static int
dissect_pkix1explicit_DomainParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DomainParameters_sequence, hf_index, ett_pkix1explicit_DomainParameters);

  return offset;
}



static int
dissect_pkix1explicit_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_type);
}



static int
dissect_pkix1explicit_T_value(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 38 "pkix1explicit.cnf"
  offset=call_ber_oid_callback(object_identifier_id, tvb, offset, pinfo, tree);



  return offset;
}
static int dissect_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_T_value(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_value);
}


static const ber_sequence_t AttributeTypeAndValue_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_ANY, 0, BER_FLAGS_NOOWNTAG, dissect_value },
  { 0, 0, 0, NULL }
};

int
dissect_pkix1explicit_AttributeTypeAndValue(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   AttributeTypeAndValue_sequence, hf_index, ett_pkix1explicit_AttributeTypeAndValue);

  return offset;
}
static int dissect_RelativeDistinguishedName_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_AttributeTypeAndValue(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_RelativeDistinguishedName_item);
}


static const ber_sequence_t RelativeDistinguishedName_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_RelativeDistinguishedName_item },
};

int
dissect_pkix1explicit_RelativeDistinguishedName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 RelativeDistinguishedName_set_of, hf_index, ett_pkix1explicit_RelativeDistinguishedName);

  return offset;
}
static int dissect_RDNSequence_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_RelativeDistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_RDNSequence_item);
}


static const ber_sequence_t RDNSequence_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_RDNSequence_item },
};

int
dissect_pkix1explicit_RDNSequence(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      RDNSequence_sequence_of, hf_index, ett_pkix1explicit_RDNSequence);

  return offset;
}



int
dissect_pkix1explicit_DirectoryString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
#line 32 "pkix1explicit.cnf"
	offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);



  return offset;
}


const value_string pkix1explicit_TerminalType_vals[] = {
  {   3, "telex" },
  {   4, "teletex" },
  {   5, "g3-facsimile" },
  {   6, "g4-facsimile" },
  {   7, "ia5-terminal" },
  {   8, "videotex" },
  { 0, NULL }
};


int
dissect_pkix1explicit_TerminalType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_pkix1explicit_TeletexString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_type1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_TeletexString(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_type1);
}
static int dissect_value1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_TeletexString(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_value1);
}


static const ber_sequence_t TeletexDomainDefinedAttribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_type1 },
  { BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_value1 },
  { 0, 0, 0, NULL }
};

int
dissect_pkix1explicit_TeletexDomainDefinedAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TeletexDomainDefinedAttribute_sequence, hf_index, ett_pkix1explicit_TeletexDomainDefinedAttribute);

  return offset;
}

/*--- PDUs ---*/

static void dissect_DomainParameters_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkix1explicit_DomainParameters(FALSE, tvb, 0, pinfo, tree, hf_pkix1explicit_DomainParameters_PDU);
}
static void dissect_DirectoryString_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkix1explicit_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_pkix1explicit_DirectoryString_PDU);
}


/*--- End of included file: packet-pkix1explicit-fn.c ---*/
#line 99 "packet-pkix1explicit-template.c"


/*--- proto_register_pkix1explicit ----------------------------------------------*/
void proto_register_pkix1explicit(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_pkix1explicit_object_identifier_id, 
      { "Id", "pkix1explicit.id", FT_STRING, BASE_NONE, NULL, 0,
	"Object identifier Id", HFILL }},

/*--- Included file: packet-pkix1explicit-hfarr.c ---*/
#line 1 "packet-pkix1explicit-hfarr.c"
    { &hf_pkix1explicit_DomainParameters_PDU,
      { "DomainParameters", "pkix1explicit.DomainParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "DomainParameters", HFILL }},
    { &hf_pkix1explicit_DirectoryString_PDU,
      { "DirectoryString", "pkix1explicit.DirectoryString",
        FT_STRING, BASE_NONE, NULL, 0,
        "DirectoryString", HFILL }},
    { &hf_pkix1explicit_Extensions_item,
      { "Item", "pkix1explicit.Extensions_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Extensions/_item", HFILL }},
    { &hf_pkix1explicit_extnId,
      { "extnId", "pkix1explicit.extnId",
        FT_OID, BASE_NONE, NULL, 0,
        "Extension/extnId", HFILL }},
    { &hf_pkix1explicit_critical,
      { "critical", "pkix1explicit.critical",
        FT_BOOLEAN, 8, NULL, 0,
        "Extension/critical", HFILL }},
    { &hf_pkix1explicit_extnValue,
      { "extnValue", "pkix1explicit.extnValue",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Extension/extnValue", HFILL }},
    { &hf_pkix1explicit_p,
      { "p", "pkix1explicit.p",
        FT_INT32, BASE_DEC, NULL, 0,
        "DomainParameters/p", HFILL }},
    { &hf_pkix1explicit_g,
      { "g", "pkix1explicit.g",
        FT_INT32, BASE_DEC, NULL, 0,
        "DomainParameters/g", HFILL }},
    { &hf_pkix1explicit_q,
      { "q", "pkix1explicit.q",
        FT_INT32, BASE_DEC, NULL, 0,
        "DomainParameters/q", HFILL }},
    { &hf_pkix1explicit_j,
      { "j", "pkix1explicit.j",
        FT_INT32, BASE_DEC, NULL, 0,
        "DomainParameters/j", HFILL }},
    { &hf_pkix1explicit_validationParms,
      { "validationParms", "pkix1explicit.validationParms",
        FT_NONE, BASE_NONE, NULL, 0,
        "DomainParameters/validationParms", HFILL }},
    { &hf_pkix1explicit_seed,
      { "seed", "pkix1explicit.seed",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ValidationParms/seed", HFILL }},
    { &hf_pkix1explicit_pgenCounter,
      { "pgenCounter", "pkix1explicit.pgenCounter",
        FT_INT32, BASE_DEC, NULL, 0,
        "ValidationParms/pgenCounter", HFILL }},
    { &hf_pkix1explicit_type,
      { "type", "pkix1explicit.type",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeTypeAndValue/type", HFILL }},
    { &hf_pkix1explicit_value,
      { "value", "pkix1explicit.value",
        FT_NONE, BASE_NONE, NULL, 0,
        "AttributeTypeAndValue/value", HFILL }},
    { &hf_pkix1explicit_RDNSequence_item,
      { "Item", "pkix1explicit.RDNSequence_item",
        FT_UINT32, BASE_DEC, NULL, 0,
        "RDNSequence/_item", HFILL }},
    { &hf_pkix1explicit_RelativeDistinguishedName_item,
      { "Item", "pkix1explicit.RelativeDistinguishedName_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "RelativeDistinguishedName/_item", HFILL }},
    { &hf_pkix1explicit_type1,
      { "type", "pkix1explicit.type",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexDomainDefinedAttribute/type", HFILL }},
    { &hf_pkix1explicit_value1,
      { "value", "pkix1explicit.value",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexDomainDefinedAttribute/value", HFILL }},

/*--- End of included file: packet-pkix1explicit-hfarr.c ---*/
#line 110 "packet-pkix1explicit-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-pkix1explicit-ettarr.c ---*/
#line 1 "packet-pkix1explicit-ettarr.c"
    &ett_pkix1explicit_Extensions,
    &ett_pkix1explicit_Extension,
    &ett_pkix1explicit_DomainParameters,
    &ett_pkix1explicit_ValidationParms,
    &ett_pkix1explicit_AttributeTypeAndValue,
    &ett_pkix1explicit_RDNSequence,
    &ett_pkix1explicit_RelativeDistinguishedName,
    &ett_pkix1explicit_TeletexDomainDefinedAttribute,

/*--- End of included file: packet-pkix1explicit-ettarr.c ---*/
#line 115 "packet-pkix1explicit-template.c"
  };

  /* Register protocol */
  proto_pkix1explicit = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkix1explicit, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkix1explicit -------------------------------------------*/
void proto_reg_handoff_pkix1explicit(void) {

/*--- Included file: packet-pkix1explicit-dis-tab.c ---*/
#line 1 "packet-pkix1explicit-dis-tab.c"
  register_ber_oid_dissector("1.3.6.1.5.5.7.2.1", dissect_DirectoryString_PDU, proto_pkix1explicit, "id-qt-cps");
  register_ber_oid_dissector("1.2.840.10046.2.1", dissect_DomainParameters_PDU, proto_pkix1explicit, "dhpublicnumber");


/*--- End of included file: packet-pkix1explicit-dis-tab.c ---*/
#line 130 "packet-pkix1explicit-template.c"
}

