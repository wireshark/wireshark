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
int hf_x509sat_organizationName = -1;
/*aaa*/
#include "packet-x509sat-hf.c"

/* Initialize the subtree pointers */
static gint ett_x509sat_DirectoryString = -1;
#include "packet-x509sat-ett.c"

#include "packet-x509sat-fn.c"




static int DirectoryString_hf_index;

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
  {   0, "printableString" },
  {   1, "universalString" },
  {   2, "bmpString" },
  {   3, "uTF8String" },
  { 0, NULL }
};

static ber_choice DirectoryString_choice[] = {
/*XXX needs to add TeletexString */
  {   0, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_printableString },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_UniversalString, BER_FLAGS_NOOWNTAG, dissect_universalString },
  {   2, BER_CLASS_UNI, BER_UNI_TAG_BMPString, BER_FLAGS_NOOWNTAG, dissect_bmpString },
  {   3, BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_uTF8String },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509sat_DirectoryString(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index) {
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
/*ccc*/
#include "packet-x509sat-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_x509sat_DirectoryString,
#include "packet-x509sat-ettarr.c"
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
	register_ber_oid_dissector("2.5.4.10", dissect_x509sat_organizationName_callback, proto_x509sat, "id-at-organizationName");
/*ddd*/
}

