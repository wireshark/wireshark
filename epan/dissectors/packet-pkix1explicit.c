/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-pkix1explicit.c                                                   */
/* ../../tools/asn2eth.py -e -X -b -p pkix1explicit -c pkix1explicit.cnf -s packet-pkix1explicit-template PKIX1EXPLICIT93.asn */

/* Input file: packet-pkix1explicit-template.c */

#define BER_UNI_TAG_TeletexString	    20  /* workaround bug in asn2eth */

/* packet-pkix1explicit.c
 * Routines for PKIX1Explitic packet dissection
 *
 * $Id: packet-pkix1explicit-template.c 12465 2004-11-01 18:11:48Z gerald $
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

#define PNAME  "PKIX1Explitit"
#define PSNAME "PKIX1EXPLICIT"
#define PFNAME "pkix1explicit"

/* Initialize the protocol and registered fields */
static int proto_pkix1explicit = -1;

/*--- Included file: packet-pkix1explicit-hf.c ---*/

static int hf_pkix1explicit_DomainParameters_PDU = -1;  /* DomainParameters */
static int hf_pkix1explicit_p = -1;               /* INTEGER */
static int hf_pkix1explicit_g = -1;               /* INTEGER */
static int hf_pkix1explicit_q = -1;               /* INTEGER */
static int hf_pkix1explicit_j = -1;               /* INTEGER */
static int hf_pkix1explicit_validationParms = -1;  /* ValidationParms */
static int hf_pkix1explicit_seed = -1;            /* BIT_STRING */
static int hf_pkix1explicit_pgenCounter = -1;     /* INTEGER */
static int hf_pkix1explicit_type = -1;            /* TeletexString */
static int hf_pkix1explicit_value = -1;           /* TeletexString */

/*--- End of included file: packet-pkix1explicit-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-pkix1explicit-ett.c ---*/

static gint ett_pkix1explicit_DomainParameters = -1;
static gint ett_pkix1explicit_ValidationParms = -1;
static gint ett_pkix1explicit_TeletexDomainDefinedAttribute = -1;

/*--- End of included file: packet-pkix1explicit-ett.c ---*/



int
dissect_pkix1explicit_CertificateSerialNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_x509af_CertificateSerialNumber(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}

int
dissect_pkix1explicit_Name(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index) {
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

/*--- Fields for imported types ---*/





static int
dissect_pkix1explicit_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer_new(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

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
dissect_pkix1explicit_BIT_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 NULL, hf_index, -1,
                                 NULL);

  return offset;
}
static int dissect_seed(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_BIT_STRING(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_seed);
}

static const ber_sequence ValidationParms_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_seed },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_pgenCounter },
  { 0, 0, 0, NULL }
};

static int
dissect_pkix1explicit_ValidationParms(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                ValidationParms_sequence, hf_index, ett_pkix1explicit_ValidationParms);

  return offset;
}
static int dissect_validationParms(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_ValidationParms(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_validationParms);
}

static const ber_sequence DomainParameters_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_p },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_g },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_q },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_j },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_validationParms },
  { 0, 0, 0, NULL }
};

static int
dissect_pkix1explicit_DomainParameters(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                DomainParameters_sequence, hf_index, ett_pkix1explicit_DomainParameters);

  return offset;
}


const value_string TerminalType_vals[] = {
  {   3, "telex" },
  {   4, "teletex" },
  {   5, "g3-facsimile" },
  {   6, "g4-facsimile" },
  {   7, "ia5-terminal" },
  {   8, "videotex" },
  { 0, NULL }
};


int
dissect_pkix1explicit_TerminalType(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_integer_new(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static int
dissect_pkix1explicit_TeletexString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}
static int dissect_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_TeletexString(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_type);
}
static int dissect_value(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkix1explicit_TeletexString(FALSE, tvb, offset, pinfo, tree, hf_pkix1explicit_value);
}

static const ber_sequence TeletexDomainDefinedAttribute_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_type },
  { BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_value },
  { 0, 0, 0, NULL }
};

int
dissect_pkix1explicit_TeletexDomainDefinedAttribute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                TeletexDomainDefinedAttribute_sequence, hf_index, ett_pkix1explicit_TeletexDomainDefinedAttribute);

  return offset;
}

/*--- PDUs ---*/

static void dissect_DomainParameters_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_pkix1explicit_DomainParameters(FALSE, tvb, 0, pinfo, tree, hf_pkix1explicit_DomainParameters_PDU);
}


/*--- End of included file: packet-pkix1explicit-fn.c ---*/



/*--- proto_register_pkix1explicit ----------------------------------------------*/
void proto_register_pkix1explicit(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-pkix1explicit-hfarr.c ---*/

    { &hf_pkix1explicit_DomainParameters_PDU,
      { "DomainParameters", "pkix1explicit.DomainParameters",
        FT_NONE, BASE_NONE, NULL, 0,
        "DomainParameters", HFILL }},
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
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexDomainDefinedAttribute/type", HFILL }},
    { &hf_pkix1explicit_value,
      { "value", "pkix1explicit.value",
        FT_STRING, BASE_NONE, NULL, 0,
        "TeletexDomainDefinedAttribute/value", HFILL }},

/*--- End of included file: packet-pkix1explicit-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-pkix1explicit-ettarr.c ---*/

    &ett_pkix1explicit_DomainParameters,
    &ett_pkix1explicit_ValidationParms,
    &ett_pkix1explicit_TeletexDomainDefinedAttribute,

/*--- End of included file: packet-pkix1explicit-ettarr.c ---*/

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

 register_ber_oid_dissector("1.2.840.10046.2.1", dissect_DomainParameters_PDU, proto_pkix1explicit, "dhpublicnumber");


/*--- End of included file: packet-pkix1explicit-dis-tab.c ---*/

}

