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

#define PNAME  "X.509 Certificate Extensions"
#define PSNAME "X509CE"
#define PFNAME "x509ce"

/* Initialize the protocol and registered fields */
int proto_x509ce = -1;

/*--- Included file: packet-x509ce-hf.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-hf.c                                                         */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

static int hf_x509ce_GeneralNames_item = -1;      /* GeneralName */
static int hf_x509ce_rfc822Name = -1;             /* IA5String */
static int hf_x509ce_dNSName = -1;                /* IA5String */
static int hf_x509ce_uniformResourceIdentifier = -1;  /* IA5String */
static int hf_x509ce_iPAddress = -1;              /* OCTET_STRING */
static int hf_x509ce_registeredID = -1;           /* OBJECT_IDENTIFIER */

/*--- End of included file: packet-x509ce-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-x509ce-ett.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-ett.c                                                        */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

static gint ett_x509ce_GeneralNames = -1;
static gint ett_x509ce_GeneralName = -1;

/*--- End of included file: packet-x509ce-ett.c ---*/



/*--- Included file: packet-x509ce-fn.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-fn.c                                                         */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */


static int
dissect_x509ce_IA5String(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
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
dissect_x509ce_OCTET_STRING(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_iPAddress(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509ce_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_x509ce_iPAddress);
}


static int
dissect_x509ce_OBJECT_IDENTIFIER(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
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
dissect_x509ce_GeneralName(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
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
dissect_x509ce_GeneralNames(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                   GeneralNames_sequence_of, hf_index, ett_x509ce_GeneralNames);

  return offset;
}


/*--- End of included file: packet-x509ce-fn.c ---*/



/*--- proto_register_x509ce ----------------------------------------------*/
void proto_register_x509ce(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-x509ce-hfarr.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-hfarr.c                                                      */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

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

/*--- End of included file: packet-x509ce-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-x509ce-ettarr.c ---*/

/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* packet-x509ce-ettarr.c                                                     */
/* ../../tools/asn2eth.py -X -b -p x509ce -c x509ce.cnf -s packet-x509ce-template CertificateExtensions.asn */

    &ett_x509ce_GeneralNames,
    &ett_x509ce_GeneralName,

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
}

