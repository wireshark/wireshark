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
#include "packet-x509ce-hf.c"

/* Initialize the subtree pointers */
#include "packet-x509ce-ett.c"

#include "packet-x509ce-fn.c"


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
#include "packet-x509ce-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-x509ce-ettarr.c"
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

