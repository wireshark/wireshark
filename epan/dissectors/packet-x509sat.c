/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509sat.c                                                           */
/* ../../tools/asn2eth.py -X -b -p x509sat -c x509sat.cnf -s packet-x509sat-template SelectedAttributeTypes.asn */

/* Input file: packet-x509sat-template.c */
/* Include files: packet-x509sat-hf.c, packet-x509sat-ett.c, packet-x509sat-fn.c, packet-x509sat-hfarr.c, packet-x509sat-ettarr.c, packet-x509sat-val.h */

/* packet-x509sat.c
 * Routines for X.509 Selected Attribute Types packet dissection
 *
 * $Id: packet-x509sat-template.c,v 1.2 2004/05/25 21:07:43 guy Exp $
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

/*--- Included file: packet-x509sat-hf.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509sat-hf.c                                                        */
/* ../../tools/asn2eth.py -X -b -p x509sat -c x509sat.cnf -s packet-x509sat-template SelectedAttributeTypes.asn */

static int hf_x509sat_equality = -1;              /* AttributeType */
static int hf_x509sat_substrings = -1;            /* AttributeType */
static int hf_x509sat_greaterOrEqual = -1;        /* AttributeType */
static int hf_x509sat_lessOrEqual = -1;           /* AttributeType */
static int hf_x509sat_approximateMatch = -1;      /* AttributeType */

/*--- End of included file: packet-x509sat-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-x509sat-ett.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509sat-ett.c                                                       */
/* ../../tools/asn2eth.py -X -b -p x509sat -c x509sat.cnf -s packet-x509sat-template SelectedAttributeTypes.asn */

static gint ett_x509sat_CriteriaItem = -1;

/*--- End of included file: packet-x509sat-ett.c ---*/



/*--- Included file: packet-x509sat-fn.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509sat-fn.c                                                        */
/* ../../tools/asn2eth.py -X -b -p x509sat -c x509sat.cnf -s packet-x509sat-template SelectedAttributeTypes.asn */

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
dissect_x509sat_UniqueIdentifier(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                 NULL, hf_index, -1,
                                 NULL);

  return offset;
}


static int
dissect_x509sat_CountryName(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
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

static ber_choice CriteriaItem_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_equality },
  {   1, BER_CLASS_CON, 1, 0, dissect_substrings },
  {   2, BER_CLASS_CON, 2, 0, dissect_greaterOrEqual },
  {   3, BER_CLASS_CON, 3, 0, dissect_lessOrEqual },
  {   4, BER_CLASS_CON, 4, 0, dissect_approximateMatch },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509sat_CriteriaItem(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              CriteriaItem_choice, hf_index, ett_x509sat_CriteriaItem);

  return offset;
}


/*--- End of included file: packet-x509sat-fn.c ---*/



static void
dissect_x509sat_countryName_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509sat_CountryName(FALSE, tvb, 0, pinfo, tree, hf_x509sat_countryName);
}

/*--- proto_register_x509sat ----------------------------------------------*/
void proto_register_x509sat(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509sat_countryName,
      { "countryName", "x509sat.countryName",
        FT_STRING, BASE_NONE, NULL, 0,
        "Country Name", HFILL }},

/*--- Included file: packet-x509sat-hfarr.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509sat-hfarr.c                                                     */
/* ../../tools/asn2eth.py -X -b -p x509sat -c x509sat.cnf -s packet-x509sat-template SelectedAttributeTypes.asn */

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

/*--- End of included file: packet-x509sat-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-x509sat-ettarr.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509sat-ettarr.c                                                    */
/* ../../tools/asn2eth.py -X -b -p x509sat -c x509sat.cnf -s packet-x509sat-template SelectedAttributeTypes.asn */

    &ett_x509sat_CriteriaItem,

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
	register_ber_oid_dissector("2.5.4.6", dissect_x509sat_countryName_callback, proto_x509sat, "id-at-countryName");
}

