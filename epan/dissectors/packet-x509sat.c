/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-x509sat.c                                                         */
/* ../../tools/asn2eth.py -X -b -p x509sat -c x509sat.cnf -s packet-x509sat-template SelectedAttributeTypes.asn */

/* Input file: packet-x509sat-template.c */

/* packet-x509sat.c
 * Routines for X.509 Selected Attribute Types packet dissection
 *
 * $Id: packet-x509sat-template.c 12203 2004-10-05 09:18:55Z guy $
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
int hf_x509sat_countryName = -1;
int hf_x509sat_organizationName = -1;
int hf_x509sat_knowledgeInformation = -1;
int hf_x509sat_name = -1;
int hf_x509sat_commonName = -1;
int hf_x509sat_surname = -1;
int hf_x509sat_givenName = -1;
int hf_x509sat_initials = -1;
int hf_x509sat_generationQualifier = -1;
int hf_x509sat_pseudonym = -1;
int hf_x509sat_localityName = -1;
int hf_x509sat_collectiveLocalityName = -1;
int hf_x509sat_stateOrProvinceName = -1;
int hf_x509sat_collectiveStateOrProvinceName = -1;
int hf_x509sat_streetAddress = -1;
int hf_x509sat_collectiveStreetAddress = -1;
int hf_x509sat_houseIdentifier = -1;
int hf_x509sat_collectiveOrganizationName = -1;
int hf_x509sat_organizationalUnitName = -1;
int hf_x509sat_collectiveOrganizationalUnitName = -1;
int hf_x509sat_title = -1;
int hf_x509sat_description = -1;
int hf_x509sat_businessCategory = -1;
int hf_x509sat_postalCode = -1;
int hf_x509sat_collectivePostalCode = -1;
int hf_x509sat_postOfficeBox = -1;
int hf_x509sat_collectivePostOfficeBox = -1;
int hf_x509sat_physicalDeliveryOfficeName = -1;
int hf_x509sat_collectivePhysicalDeliveryOfficeName = -1;
int hf_x509sat_dmdName = -1;
int hf_x509sat_id_at_telexNumber = -1;
int hf_x509sat_id_at_collectiveTelexNumber = -1;
int hf_x509sat_id_at_telephoneNumber = -1;
int hf_x509sat_id_at_collectiveTelephoneNumber = -1;
/*aaa*/

/*--- Included file: packet-x509sat-hf.c ---*/

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
static gint ett_x509sat_DirectoryString = -1;

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


/*--- End of included file: packet-x509sat-fn.c ---*/





static int DirectoryString_hf_index;

static int
dissect_teletextString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ber_restricted_string(FALSE, BER_UNI_TAG_TeletextString, 
              pinfo, tree, tvb, offset, DirectoryString_hf_index, NULL);
}
static int
dissect_printableString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ber_restricted_string(FALSE, BER_UNI_TAG_PrintableString, 
              pinfo, tree, tvb, offset, DirectoryString_hf_index, NULL);
}
static int
dissect_universalString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ber_restricted_string(FALSE, BER_UNI_TAG_UniversalString,
              pinfo, tree, tvb, offset, DirectoryString_hf_index, NULL);
}
static int
dissect_bmpString(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ber_restricted_string(FALSE, BER_UNI_TAG_BMPString,
              pinfo, tree, tvb, offset, DirectoryString_hf_index, NULL);
}
static int
dissect_uTF8String(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_ber_restricted_string(FALSE, BER_UNI_TAG_UTF8String,
              pinfo, tree, tvb, offset, DirectoryString_hf_index, NULL);
}

static const value_string DirectoryString_vals[] = {
  {   0, "teletextString" },
  {   1, "printableString" },
  {   2, "universalString" },
  {   3, "bmpString" },
  {   4, "uTF8String" },
  { 0, NULL }
};

static ber_choice DirectoryString_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_TeletextString, BER_FLAGS_NOOWNTAG, dissect_teletextString },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_printableString },
  {   2, BER_CLASS_UNI, BER_UNI_TAG_UniversalString, BER_FLAGS_NOOWNTAG, dissect_universalString },
  {   3, BER_CLASS_UNI, BER_UNI_TAG_BMPString, BER_FLAGS_NOOWNTAG, dissect_bmpString },
  {   4, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_uTF8String },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509sat_DirectoryString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index) {
  DirectoryString_hf_index = hf_index;
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              DirectoryString_choice, -1, ett_x509sat_DirectoryString);

  return offset;
}




static void
dissect_x509sat_countryName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_CountryName(FALSE, tvb, 0, pinfo, tree, hf_x509sat_countryName);
}

static void
dissect_x509sat_organizationName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_organizationName);
}

static void
dissect_x509sat_knowledgeInformation_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_knowledgeInformation);
}

static void
dissect_x509sat_name_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_name);
}

static void
dissect_x509sat_commonName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_commonName);
}

static void
dissect_x509sat_surname_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_surname);
}

static void
dissect_x509sat_givenName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_givenName);
}

static void
dissect_x509sat_initials_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_initials);
}

static void
dissect_x509sat_generationQualifier_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_generationQualifier);
}

static void
dissect_x509sat_pseudonym_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_pseudonym);
}

static void
dissect_x509sat_localityName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_localityName);
}

static void
dissect_x509sat_collectiveLocalityName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_collectiveLocalityName);
}

static void
dissect_x509sat_stateOrProvinceName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_stateOrProvinceName);
}

static void
dissect_x509sat_collectiveStateOrProvinceName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_collectiveStateOrProvinceName);
}

static void
dissect_x509sat_streetAddress_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_streetAddress);
}

static void
dissect_x509sat_collectiveStreetAddress_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_collectiveStreetAddress);
}

static void
dissect_x509sat_houseIdentifier_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_houseIdentifier);
}

static void
dissect_x509sat_collectiveOrganizationName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_collectiveOrganizationName);
}

static void
dissect_x509sat_organizationalUnitName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_organizationalUnitName);
}

static void
dissect_x509sat_collectiveOrganizationalUnitName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_collectiveOrganizationalUnitName);
}

static void
dissect_x509sat_title_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_title);
}

static void
dissect_x509sat_description_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_description);
}

static void
dissect_x509sat_businessCategory_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_businessCategory);
}

static void
dissect_x509sat_postalCode_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_postalCode);
}

static void
dissect_x509sat_collectivePostalCode_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_collectivePostalCode);
}

static void
dissect_x509sat_postOfficeBox_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_postOfficeBox);
}

static void
dissect_x509sat_collectivePostOfficeBox_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_collectivePostOfficeBox);
}

static void
dissect_x509sat_physicalDeliveryOfficeName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_physicalDeliveryOfficeName);
}

static void
dissect_x509sat_collectivePhysicalDeliveryOfficeName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_collectivePhysicalDeliveryOfficeName);
}

static void
dissect_x509sat_dmdName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_dmdName);
}


static void
dissect_x509sat_telexNumber_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_TelexNumber(FALSE, tvb, 0, pinfo, tree, hf_x509sat_id_at_telexNumber);
}

static void
dissect_x509sat_collectiveTelexNumber_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_TelexNumber(FALSE, tvb, 0, pinfo, tree, hf_x509sat_id_at_collectiveTelexNumber);
}

static void
dissect_x509sat_telephoneNumber_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_TelephoneNumber(FALSE, tvb, 0, pinfo, tree, hf_x509sat_id_at_telephoneNumber);
}

static void
dissect_x509sat_collectiveTelephoneNumber_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_TelephoneNumber(FALSE, tvb, 0, pinfo, tree, hf_x509sat_id_at_collectiveTelephoneNumber);
}
/*bbb*/

/*--- proto_register_x509sat ----------------------------------------------*/
void proto_register_x509sat(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509sat_countryName,
      { "countryName", "x509sat.countryName",
        FT_STRING, BASE_NONE, NULL, 0,
        "Country Name", HFILL }},
    { &hf_x509sat_organizationName,
      { "organizationName", "x509sat.organizationName",
        FT_STRING, BASE_NONE, NULL, 0,
        "Organization Name", HFILL }},
    { &hf_x509sat_knowledgeInformation,
      { "knowledgeInformation", "x509sat.knowledgeInformation",
        FT_STRING, BASE_NONE, NULL, 0,
        "knowledgeInformation", HFILL }},
    { &hf_x509sat_name,
      { "name", "x509sat.name",
        FT_STRING, BASE_NONE, NULL, 0,
        "name", HFILL }},
    { &hf_x509sat_commonName,
      { "commonName", "x509sat.commonName",
        FT_STRING, BASE_NONE, NULL, 0,
        "commonName", HFILL }},
    { &hf_x509sat_surname,
      { "surname", "x509sat.surname",
        FT_STRING, BASE_NONE, NULL, 0,
        "surname", HFILL }},
    { &hf_x509sat_givenName,
      { "givenName", "x509sat.givenName",
        FT_STRING, BASE_NONE, NULL, 0,
        "givenName", HFILL }},
    { &hf_x509sat_initials,
      { "initials", "x509sat.initials",
        FT_STRING, BASE_NONE, NULL, 0,
        "initials", HFILL }},
    { &hf_x509sat_generationQualifier,
      { "generationQualifier", "x509sat.generationQualifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "generationQualifier", HFILL }},
    { &hf_x509sat_pseudonym,
      { "pseudonym", "x509sat.pseudonym",
        FT_STRING, BASE_NONE, NULL, 0,
        "pseudonym", HFILL }},
    { &hf_x509sat_localityName,
      { "localityName", "x509sat.localityName",
        FT_STRING, BASE_NONE, NULL, 0,
        "localityName", HFILL }},
    { &hf_x509sat_collectiveLocalityName,
      { "collectiveLocalityName", "x509sat.collectiveLocalityName",
        FT_STRING, BASE_NONE, NULL, 0,
        "collectiveLocalityName", HFILL }},
    { &hf_x509sat_stateOrProvinceName,
      { "stateOrProvinceName", "x509sat.stateOrProvinceName",
        FT_STRING, BASE_NONE, NULL, 0,
        "stateOrProvinceName", HFILL }},
    { &hf_x509sat_collectiveStateOrProvinceName,
      { "collectiveStateOrProvinceName", "x509sat.collectiveStateOrProvinceName",
        FT_STRING, BASE_NONE, NULL, 0,
        "collectiveStateOrProvinceName", HFILL }},
    { &hf_x509sat_streetAddress,
      { "streetAddress", "x509sat.streetAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "streetAddress", HFILL }},
    { &hf_x509sat_collectiveStreetAddress,
      { "collectiveStreetAddress", "x509sat.collectiveStreetAddress",
        FT_STRING, BASE_NONE, NULL, 0,
        "collectiveStreetAddress", HFILL }},
    { &hf_x509sat_houseIdentifier,
      { "houseIdentifier", "x509sat.houseIdentifier",
        FT_STRING, BASE_NONE, NULL, 0,
        "houseIdentifier", HFILL }},
    { &hf_x509sat_collectiveOrganizationName,
      { "collectiveOrganizationName", "x509sat.collectiveOrganizationName",
        FT_STRING, BASE_NONE, NULL, 0,
        "collectiveOrganizationName", HFILL }},
    { &hf_x509sat_organizationalUnitName,
      { "organizationalUnitName", "x509sat.organizationalUnitName",
        FT_STRING, BASE_NONE, NULL, 0,
        "organizationalUnitName", HFILL }},
    { &hf_x509sat_collectiveOrganizationalUnitName,
      { "collectiveOrganizationalUnitName", "x509sat.collectiveOrganizationalUnitName",
        FT_STRING, BASE_NONE, NULL, 0,
        "collectiveOrganizationalUnitName", HFILL }},
    { &hf_x509sat_title,
      { "title", "x509sat.title",
        FT_STRING, BASE_NONE, NULL, 0,
        "title", HFILL }},
    { &hf_x509sat_description,
      { "description", "x509sat.description",
        FT_STRING, BASE_NONE, NULL, 0,
        "description", HFILL }},
    { &hf_x509sat_businessCategory,
      { "businessCategory", "x509sat.businessCategory",
        FT_STRING, BASE_NONE, NULL, 0,
        "businessCategory", HFILL }},
    { &hf_x509sat_postalCode,
      { "postalCode", "x509sat.postalCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "postalCode", HFILL }},
    { &hf_x509sat_collectivePostalCode,
      { "collectivePostalCode", "x509sat.collectivePostalCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "collectivePostalCode", HFILL }},
    { &hf_x509sat_postOfficeBox,
      { "postOfficeBox", "x509sat.postOfficeBox",
        FT_STRING, BASE_NONE, NULL, 0,
        "postOfficeBox", HFILL }},
    { &hf_x509sat_collectivePostOfficeBox,
      { "collectivePostOfficeBox", "x509sat.collectivePostOfficeBox",
        FT_STRING, BASE_NONE, NULL, 0,
        "collectivePostOfficeBox", HFILL }},
    { &hf_x509sat_physicalDeliveryOfficeName,
      { "physicalDeliveryOfficeName", "x509sat.physicalDeliveryOfficeName",
        FT_STRING, BASE_NONE, NULL, 0,
        "physicalDeliveryOfficeName", HFILL }},
    { &hf_x509sat_collectivePhysicalDeliveryOfficeName,
      { "collectivePhysicalDeliveryOfficeName", "x509sat.collectivePhysicalDeliveryOfficeName",
        FT_STRING, BASE_NONE, NULL, 0,
        "collectivePhysicalDeliveryOfficeName", HFILL }},
    { &hf_x509sat_dmdName,
      { "dmdName", "x509sat.dmdName",
        FT_STRING, BASE_NONE, NULL, 0,
        "dmdName", HFILL }},
    { &hf_x509sat_id_at_telexNumber,
      { "telexNumber", "x509sat.id_at_telexNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "telexNumber", HFILL }},
    { &hf_x509sat_id_at_collectiveTelexNumber,
      { "collectiveTelexNumber", "x509sat.id_at_collectiveTelexNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "collectiveTelexNumber", HFILL }},
    { &hf_x509sat_id_at_telephoneNumber,
      { "telephoneNumber", "x509sat.id_at_telephoneNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "telephoneNumber", HFILL }},
    { &hf_x509sat_id_at_collectiveTelephoneNumber,
      { "collectiveTelephoneNumber", "x509sat.id_at_collectiveTelephoneNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "collectiveTelephoneNumber", HFILL }},
/*ccc*/

/*--- Included file: packet-x509sat-hfarr.c ---*/

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
    &ett_x509sat_DirectoryString,

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
	register_ber_oid_dissector("2.5.4.2", dissect_x509sat_knowledgeInformation_callback, proto_x509sat, "id-at-knowledgeInformation");
	register_ber_oid_dissector("2.5.4.3", dissect_x509sat_commonName_callback, proto_x509sat, "id-at-commonName");
	register_ber_oid_dissector("2.5.4.4", dissect_x509sat_surname_callback, proto_x509sat, "id-at-surname");
	register_ber_oid_dissector("2.5.4.6", dissect_x509sat_countryName_callback, proto_x509sat, "id-at-countryName");
	register_ber_oid_dissector("2.5.4.7", dissect_x509sat_localityName_callback, proto_x509sat, "id-at-localityName");
	register_ber_oid_dissector("2.5.4.7.1", dissect_x509sat_collectiveLocalityName_callback, proto_x509sat, "id-at-collectiveLocalityName");
	register_ber_oid_dissector("2.5.4.8", dissect_x509sat_stateOrProvinceName_callback, proto_x509sat, "id-at-stateOrProvinceName");
	register_ber_oid_dissector("2.5.4.8.1", dissect_x509sat_collectiveStateOrProvinceName_callback, proto_x509sat, "id-at-collectiveStateOrProvinceName");
	register_ber_oid_dissector("2.5.4.9", dissect_x509sat_streetAddress_callback, proto_x509sat, "id-at-streetAddress");
	register_ber_oid_dissector("2.5.4.9.1", dissect_x509sat_collectiveStreetAddress_callback, proto_x509sat, "id-at-collectiveStreetAddress");
	register_ber_oid_dissector("2.5.4.10", dissect_x509sat_organizationName_callback, proto_x509sat, "id-at-organizationName");
	register_ber_oid_dissector("2.5.4.10.1", dissect_x509sat_collectiveOrganizationName_callback, proto_x509sat, "id-at-collectiveOrganizationName");
	register_ber_oid_dissector("2.5.4.11", dissect_x509sat_organizationalUnitName_callback, proto_x509sat, "id-at-organizationalUnitName");
	register_ber_oid_dissector("2.5.4.11.1", dissect_x509sat_collectiveOrganizationalUnitName_callback, proto_x509sat, "id-at-collectiveOrganizationalUnitName");
	register_ber_oid_dissector("2.5.4.12", dissect_x509sat_title_callback, proto_x509sat, "id-at-title");
	register_ber_oid_dissector("2.5.4.13", dissect_x509sat_description_callback, proto_x509sat, "id-at-description");
	register_ber_oid_dissector("2.5.4.15", dissect_x509sat_businessCategory_callback, proto_x509sat, "id-at-businessCategory");
	register_ber_oid_dissector("2.5.4.17", dissect_x509sat_postalCode_callback, proto_x509sat, "id-at-postalCode");
	register_ber_oid_dissector("2.5.4.17.1", dissect_x509sat_collectivePostalCode_callback, proto_x509sat, "id-at-collectivePostalCode");
	register_ber_oid_dissector("2.5.4.18", dissect_x509sat_postOfficeBox_callback, proto_x509sat, "id-at-postOfficeBox");
	register_ber_oid_dissector("2.5.4.18.1", dissect_x509sat_collectivePostOfficeBox_callback, proto_x509sat, "id-at-collectivePostOfficeBox");
	register_ber_oid_dissector("2.5.4.19", dissect_x509sat_physicalDeliveryOfficeName_callback, proto_x509sat, "id-at-physicalDeliveryOfficeName");
	register_ber_oid_dissector("2.5.4.19.1", dissect_x509sat_collectivePhysicalDeliveryOfficeName_callback, proto_x509sat, "id-at-collectivePhysicalDeliveryOfficeName");
	register_ber_oid_dissector("2.5.4.20", dissect_x509sat_telephoneNumber_callback, proto_x509sat, "id-at-telephoneNumber");
	register_ber_oid_dissector("2.5.4.20.1", dissect_x509sat_collectiveTelephoneNumber_callback, proto_x509sat, "id-at-collectiveTelephoneNumber");
	register_ber_oid_dissector("2.5.4.21", dissect_x509sat_telexNumber_callback, proto_x509sat, "id-at-telexNumber");
	register_ber_oid_dissector("2.5.4.21.1", dissect_x509sat_collectiveTelexNumber_callback, proto_x509sat, "id-at-collectiveTelexNumber");
	register_ber_oid_dissector("2.5.4.41", dissect_x509sat_name_callback, proto_x509sat, "id-at-name");
	register_ber_oid_dissector("2.5.4.42", dissect_x509sat_givenName_callback, proto_x509sat, "id-at-givenName");
	register_ber_oid_dissector("2.5.4.43", dissect_x509sat_initials_callback, proto_x509sat, "id-at-initials");
	register_ber_oid_dissector("2.5.4.44", dissect_x509sat_generationQualifier_callback, proto_x509sat, "id-at-generationQualifier");
	register_ber_oid_dissector("2.5.4.51", dissect_x509sat_houseIdentifier_callback, proto_x509sat, "id-at-houseIdentifier");
	register_ber_oid_dissector("2.5.4.54", dissect_x509sat_dmdName_callback, proto_x509sat, "id-at-dmdName");
	register_ber_oid_dissector("2.5.4.65", dissect_x509sat_pseudonym_callback, proto_x509sat, "id-at-pseudonym");

/*ddd*/
}



