/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-x509sat.c                                                         */
/* ../../tools/asn2eth.py -X -b -p x509sat -c x509sat.cnf -s packet-x509sat-template SelectedAttributeTypes.asn */

/* Input file: packet-x509sat-template.c */

#define BER_UNI_TAG_TeletexString	    20  /* until we fix the bug in asn2eth */
/* packet-x509sat.c
 * Routines for X.509 Selected Attribute Types packet dissection
 *
 * $Id: packet-x509sat-template.c 12545 2004-11-20 05:58:13Z sahlberg $
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
#include "packet-x509sat.h"
#include "packet-x509if.h"

#define PNAME  "X.509 Selected Attribute Types"
#define PSNAME "X509SAT"
#define PFNAME "x509sat"

/* Initialize the protocol and registered fields */
int proto_x509sat = -1;
/*aaa*/

/*--- Included file: packet-x509sat-hf.c ---*/

static int hf_x509sat_DirectoryString_PDU = -1;   /* DirectoryString */
static int hf_x509sat_CountryName_PDU = -1;       /* CountryName */
static int hf_x509sat_TelephoneNumber_PDU = -1;   /* TelephoneNumber */
static int hf_x509sat_TelexNumber_PDU = -1;       /* TelexNumber */
static int hf_x509sat_equality = -1;              /* AttributeType */
static int hf_x509sat_substrings = -1;            /* AttributeType */
static int hf_x509sat_greaterOrEqual = -1;        /* AttributeType */
static int hf_x509sat_lessOrEqual = -1;           /* AttributeType */
static int hf_x509sat_approximateMatch = -1;      /* AttributeType */
static int hf_x509sat_telexNumber = -1;           /* PrintableString */
static int hf_x509sat_countryCode = -1;           /* PrintableString */
static int hf_x509sat_answerback = -1;            /* PrintableString */

/*--- End of included file: packet-x509sat-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-x509sat-ett.c ---*/

static gint ett_x509sat_CriteriaItem = -1;
static gint ett_x509sat_TelexNumber = -1;

/*--- End of included file: packet-x509sat-ett.c ---*/



/*--- Included file: packet-x509sat-fn.c ---*/

/*--- Fields for imported types ---*/

static int dissect_equality(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509sat_equality);
}
static int dissect_substrings(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509sat_substrings);
}
static int dissect_greaterOrEqual(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509sat_greaterOrEqual);
}
static int dissect_lessOrEqual(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509sat_lessOrEqual);
}
static int dissect_approximateMatch(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509sat_approximateMatch);
}


int
dissect_x509sat_DirectoryString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
	offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);


  return offset;
}


int
dissect_x509sat_UniqueIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 NULL, hf_index, -1,
                                 NULL);

  return offset;
}


static int
dissect_x509sat_CountryName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}


static const value_string CriteriaItem_vals[] = {
  {   0, "equality" },
  {   1, "substrings" },
  {   2, "greaterOrEqual" },
  {   3, "lessOrEqual" },
  {   4, "approximateMatch" },
  { 0, NULL }
};

static const ber_choice CriteriaItem_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_equality },
  {   1, BER_CLASS_CON, 1, 0, dissect_substrings },
  {   2, BER_CLASS_CON, 2, 0, dissect_greaterOrEqual },
  {   3, BER_CLASS_CON, 3, 0, dissect_lessOrEqual },
  {   4, BER_CLASS_CON, 4, 0, dissect_approximateMatch },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509sat_CriteriaItem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              CriteriaItem_choice, hf_index, ett_x509sat_CriteriaItem);

  return offset;
}


static int
dissect_x509sat_TelephoneNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}


static int
dissect_x509sat_PrintableString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                         pinfo, tree, tvb, offset, hf_index,
                                         NULL);

  return offset;
}
static int dissect_telexNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x509sat_telexNumber);
}
static int dissect_countryCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x509sat_countryCode);
}
static int dissect_answerback(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x509sat_answerback);
}

static const ber_sequence TelexNumber_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_telexNumber },
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_countryCode },
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_answerback },
  { 0, 0, 0, NULL }
};

static int
dissect_x509sat_TelexNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                TelexNumber_sequence, hf_index, ett_x509sat_TelexNumber);

  return offset;
}

/*--- PDUs ---*/

static void dissect_DirectoryString_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_DirectoryString_PDU);
}
static void dissect_CountryName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_CountryName(FALSE, tvb, 0, pinfo, tree, hf_x509sat_CountryName_PDU);
}
static void dissect_TelephoneNumber_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_TelephoneNumber(FALSE, tvb, 0, pinfo, tree, hf_x509sat_TelephoneNumber_PDU);
}
static void dissect_TelexNumber_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_TelexNumber(FALSE, tvb, 0, pinfo, tree, hf_x509sat_TelexNumber_PDU);
}


/*--- End of included file: packet-x509sat-fn.c ---*/


/*bbb*/

/*--- proto_register_x509sat ----------------------------------------------*/
void proto_register_x509sat(void) {

  /* List of fields */
  static hf_register_info hf[] = {
/*ccc*/

/*--- Included file: packet-x509sat-hfarr.c ---*/

    { &hf_x509sat_DirectoryString_PDU,
      { "DirectoryString", "x509sat.DirectoryString",
        FT_STRING, BASE_NONE, NULL, 0,
        "DirectoryString", HFILL }},
    { &hf_x509sat_CountryName_PDU,
      { "CountryName", "x509sat.CountryName",
        FT_STRING, BASE_NONE, NULL, 0,
        "CountryName", HFILL }},
    { &hf_x509sat_TelephoneNumber_PDU,
      { "TelephoneNumber", "x509sat.TelephoneNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "TelephoneNumber", HFILL }},
    { &hf_x509sat_TelexNumber_PDU,
      { "TelexNumber", "x509sat.TelexNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "TelexNumber", HFILL }},
    { &hf_x509sat_equality,
      { "equality", "x509sat.equality",
        FT_NONE, BASE_NONE, NULL, 0,
        "CriteriaItem/equality", HFILL }},
    { &hf_x509sat_substrings,
      { "substrings", "x509sat.substrings",
        FT_NONE, BASE_NONE, NULL, 0,
        "CriteriaItem/substrings", HFILL }},
    { &hf_x509sat_greaterOrEqual,
      { "greaterOrEqual", "x509sat.greaterOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        "CriteriaItem/greaterOrEqual", HFILL }},
    { &hf_x509sat_lessOrEqual,
      { "lessOrEqual", "x509sat.lessOrEqual",
        FT_NONE, BASE_NONE, NULL, 0,
        "CriteriaItem/lessOrEqual", HFILL }},
    { &hf_x509sat_approximateMatch,
      { "approximateMatch", "x509sat.approximateMatch",
        FT_NONE, BASE_NONE, NULL, 0,
        "CriteriaItem/approximateMatch", HFILL }},
    { &hf_x509sat_telexNumber,
      { "telexNumber", "x509sat.telexNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "TelexNumber/telexNumber", HFILL }},
    { &hf_x509sat_countryCode,
      { "countryCode", "x509sat.countryCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "TelexNumber/countryCode", HFILL }},
    { &hf_x509sat_answerback,
      { "answerback", "x509sat.answerback",
        FT_STRING, BASE_NONE, NULL, 0,
        "TelexNumber/answerback", HFILL }},

/*--- End of included file: packet-x509sat-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-x509sat-ettarr.c ---*/

    &ett_x509sat_CriteriaItem,
    &ett_x509sat_TelexNumber,

/*--- End of included file: packet-x509sat-ettarr.c ---*/

  };

  /* Register protocol */
  proto_x509sat = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509sat, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x509sat -------------------------------------------*/
void proto_reg_handoff_x509sat(void) {

/*--- Included file: packet-x509sat-dis-tab.c ---*/

 register_ber_oid_dissector("2.5.4.6", dissect_CountryName_PDU, proto_x509sat, "id-at-countryName");
 register_ber_oid_dissector("2.5.4.2", dissect_DirectoryString_PDU, proto_x509sat, "id-at-knowledgeInformation");
 register_ber_oid_dissector("2.5.4.10", dissect_DirectoryString_PDU, proto_x509sat, "id-at-organizationName");
 register_ber_oid_dissector("2.5.4.7.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveLocalityName");
 register_ber_oid_dissector("2.5.4.3", dissect_DirectoryString_PDU, proto_x509sat, "id-at-commonName");
 register_ber_oid_dissector("2.5.4.4", dissect_DirectoryString_PDU, proto_x509sat, "id-at-surname");
 register_ber_oid_dissector("2.5.4.42", dissect_DirectoryString_PDU, proto_x509sat, "id-at-givenName");
 register_ber_oid_dissector("2.5.4.43", dissect_DirectoryString_PDU, proto_x509sat, "id-at-initials");
 register_ber_oid_dissector("2.5.4.44", dissect_DirectoryString_PDU, proto_x509sat, "id-at-generationQualifier");
 register_ber_oid_dissector("2.5.4.51", dissect_DirectoryString_PDU, proto_x509sat, "id-at-houseIdentifier");
 register_ber_oid_dissector("2.5.4.54", dissect_DirectoryString_PDU, proto_x509sat, "id-at-dmdName");
 register_ber_oid_dissector("2.5.4.65", dissect_DirectoryString_PDU, proto_x509sat, "id-at-pseudonym");
 register_ber_oid_dissector("2.5.4.41", dissect_DirectoryString_PDU, proto_x509sat, "id-at-name");
 register_ber_oid_dissector("2.5.4.8.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveStateOrProvinceName");
 register_ber_oid_dissector("2.5.4.8", dissect_DirectoryString_PDU, proto_x509sat, "id-at-stateOrProvinceName");
 register_ber_oid_dissector("2.5.4.9", dissect_DirectoryString_PDU, proto_x509sat, "id-at-streetAddress");
 register_ber_oid_dissector("2.5.4.9.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveStreetAddress");
 register_ber_oid_dissector("2.5.4.10.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveOrganizationName");
 register_ber_oid_dissector("2.5.4.7", dissect_DirectoryString_PDU, proto_x509sat, "id-at-localityName");
 register_ber_oid_dissector("2.5.4.11", dissect_DirectoryString_PDU, proto_x509sat, "id-at-organizationalUnitName");
 register_ber_oid_dissector("2.5.4.11.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveOrganizationalUnitName");
 register_ber_oid_dissector("2.5.4.12", dissect_DirectoryString_PDU, proto_x509sat, "id-at-title");
 register_ber_oid_dissector("2.5.4.13", dissect_DirectoryString_PDU, proto_x509sat, "id-at-description");
 register_ber_oid_dissector("2.5.4.15", dissect_DirectoryString_PDU, proto_x509sat, "id-at-businessCategory");
 register_ber_oid_dissector("2.5.4.17", dissect_DirectoryString_PDU, proto_x509sat, "id-at-postalCode");
 register_ber_oid_dissector("2.5.4.17.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectivePostalCode");
 register_ber_oid_dissector("2.5.4.18", dissect_DirectoryString_PDU, proto_x509sat, "id-at-postOfficeBox");
 register_ber_oid_dissector("2.5.4.18.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectivePostOfficeBox");
 register_ber_oid_dissector("2.5.4.19", dissect_DirectoryString_PDU, proto_x509sat, "id-at-physicalDeliveryOfficeName");
 register_ber_oid_dissector("2.5.4.19.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectivePhysicalDeliveryOfficeName");
 register_ber_oid_dissector("2.5.4.20", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-telephoneNumber");
 register_ber_oid_dissector("2.5.4.20.1", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-collectiveTelephoneNumber");
 register_ber_oid_dissector("2.5.4.21", dissect_TelexNumber_PDU, proto_x509sat, "id-at-telexNumber");
 register_ber_oid_dissector("2.5.4.21.1", dissect_TelexNumber_PDU, proto_x509sat, "id-at-collectiveTelexNumber");


/*--- End of included file: packet-x509sat-dis-tab.c ---*/


/*ddd*/
}



