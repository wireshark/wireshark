/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-pkinit.c                                                          */
/* ../../tools/asn2eth.py -e -X -b -p pkinit -c pkinit.cnf -s packet-pkinit-template PKINIT.asn */

/* Input file: packet-pkinit-template.c */

/* packet-pkinit.c
 * Routines for PKINIT packet dissection
 *
 * $Id: packet-pkinit-template.c 12203 2004-10-05 09:18:55Z guy $
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
#include "packet-pkinit.h"
#include "packet-cms.h"
#include "packet-pkix1explicit.h"

#define PNAME  "PKINIT"
#define PSNAME "PKInit"
#define PFNAME "pkinit"

/* Initialize the protocol and registered fields */
static int proto_pkinit = -1;

/*--- Included file: packet-pkinit-hf.c ---*/

static int hf_pkinit_signedAuthPack = -1;         /* ContentInfo */
static int hf_pkinit_trustedCertifiers = -1;      /* SEQUNCE_OF_TrustedCA */
static int hf_pkinit_trustedCertifiers_item = -1;  /* TrustedCA */
static int hf_pkinit_kdcCert = -1;                /* IssuerAndSerialNumber */
static int hf_pkinit_caName = -1;                 /* Name */
static int hf_pkinit_issuerAndSerial = -1;        /* IssuerAndSerialNumber */
static int hf_pkinit_dhSignedData = -1;           /* ContentInfo */
static int hf_pkinit_encKeyPack = -1;             /* ContentInfo */

/*--- End of included file: packet-pkinit-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-pkinit-ett.c ---*/

static gint ett_pkinit_PaPkAsReq = -1;
static gint ett_pkinit_SEQUNCE_OF_TrustedCA = -1;
static gint ett_pkinit_TrustedCA = -1;
static gint ett_pkinit_PaPkAsRep = -1;

/*--- End of included file: packet-pkinit-ett.c ---*/




/*--- Included file: packet-pkinit-fn.c ---*/

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
static int dissect_dhSignedData(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ContentInfo(FALSE, tvb, offset, pinfo, tree, hf_pkinit_dhSignedData);
}
static int dissect_encKeyPack(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_cms_ContentInfo(FALSE, tvb, offset, pinfo, tree, hf_pkinit_encKeyPack);
}


static const value_string TrustedCA_vals[] = {
  {   0, "caName" },
  {   2, "issuerAndSerial" },
  { 0, NULL }
};

static const ber_choice TrustedCA_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_caName },
  {   2, BER_CLASS_CON, 2, 0, dissect_issuerAndSerial },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_pkinit_TrustedCA(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              TrustedCA_choice, hf_index, ett_pkinit_TrustedCA);

  return offset;
}
static int dissect_trustedCertifiers_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkinit_TrustedCA(FALSE, tvb, offset, pinfo, tree, hf_pkinit_trustedCertifiers_item);
}

static const ber_sequence SEQUNCE_OF_TrustedCA_sequence_of[1] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_trustedCertifiers_item },
};

static int
dissect_pkinit_SEQUNCE_OF_TrustedCA(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   SEQUNCE_OF_TrustedCA_sequence_of, hf_index, ett_pkinit_SEQUNCE_OF_TrustedCA);

  return offset;
}
static int dissect_trustedCertifiers(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_pkinit_SEQUNCE_OF_TrustedCA(FALSE, tvb, offset, pinfo, tree, hf_pkinit_trustedCertifiers);
}

static const ber_sequence PaPkAsReq_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_signedAuthPack },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_trustedCertifiers },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_kdcCert },
  { 0, 0, 0, NULL }
};

static int
dissect_pkinit_PaPkAsReq(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                PaPkAsReq_sequence, hf_index, ett_pkinit_PaPkAsReq);

  return offset;
}


static const value_string PaPkAsRep_vals[] = {
  {   0, "dhSignedData" },
  {   1, "encKeyPack" },
  { 0, NULL }
};

static const ber_choice PaPkAsRep_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_dhSignedData },
  {   1, BER_CLASS_CON, 1, 0, dissect_encKeyPack },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_pkinit_PaPkAsRep(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              PaPkAsRep_choice, hf_index, ett_pkinit_PaPkAsRep);

  return offset;
}


/*--- End of included file: packet-pkinit-fn.c ---*/


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


/*--- proto_register_pkinit ----------------------------------------------*/
void proto_register_pkinit(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-pkinit-hfarr.c ---*/

    { &hf_pkinit_signedAuthPack,
      { "signedAuthPack", "pkinit.signedAuthPack",
        FT_NONE, BASE_NONE, NULL, 0,
        "PaPkAsReq/signedAuthPack", HFILL }},
    { &hf_pkinit_trustedCertifiers,
      { "trustedCertifiers", "pkinit.trustedCertifiers",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PaPkAsReq/trustedCertifiers", HFILL }},
    { &hf_pkinit_trustedCertifiers_item,
      { "Item", "pkinit.trustedCertifiers_item",
        FT_UINT32, BASE_DEC, VALS(TrustedCA_vals), 0,
        "PaPkAsReq/trustedCertifiers/_item", HFILL }},
    { &hf_pkinit_kdcCert,
      { "kdcCert", "pkinit.kdcCert",
        FT_NONE, BASE_NONE, NULL, 0,
        "PaPkAsReq/kdcCert", HFILL }},
    { &hf_pkinit_caName,
      { "caName", "pkinit.caName",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TrustedCA/caName", HFILL }},
    { &hf_pkinit_issuerAndSerial,
      { "issuerAndSerial", "pkinit.issuerAndSerial",
        FT_NONE, BASE_NONE, NULL, 0,
        "TrustedCA/issuerAndSerial", HFILL }},
    { &hf_pkinit_dhSignedData,
      { "dhSignedData", "pkinit.dhSignedData",
        FT_NONE, BASE_NONE, NULL, 0,
        "PaPkAsRep/dhSignedData", HFILL }},
    { &hf_pkinit_encKeyPack,
      { "encKeyPack", "pkinit.encKeyPack",
        FT_NONE, BASE_NONE, NULL, 0,
        "PaPkAsRep/encKeyPack", HFILL }},

/*--- End of included file: packet-pkinit-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-pkinit-ettarr.c ---*/

    &ett_pkinit_PaPkAsReq,
    &ett_pkinit_SEQUNCE_OF_TrustedCA,
    &ett_pkinit_TrustedCA,
    &ett_pkinit_PaPkAsRep,

/*--- End of included file: packet-pkinit-ettarr.c ---*/

  };

  /* Register protocol */
  proto_pkinit = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkinit, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkinit -------------------------------------------*/
void proto_reg_handoff_pkinit(void) {
}

