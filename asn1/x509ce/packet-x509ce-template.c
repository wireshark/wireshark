/* packet-x509ce.c
 * Routines for X.509 Certificate Extensions packet dissection
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
#include "packet-x509ce.h"
#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"

#define PNAME  "X.509 Certificate Extensions"
#define PSNAME "X509CE"
#define PFNAME "x509ce"

/* Initialize the protocol and registered fields */
int proto_x509ce = -1;
static int hf_x509ce_id_ce_invalidityDate = -1;
static int hf_x509ce_id_ce_baseUpdateTime = -1;
#include "packet-x509ce-hf.c"

/* Initialize the subtree pointers */
#include "packet-x509ce-ett.c"

#include "packet-x509ce-fn.c"


static void
dissect_x509ce_invalidityDate_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralizedTime(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_invalidityDate);
}

static void
dissect_x509ce_baseUpdateTime_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralizedTime(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_baseUpdateTime);
}

/*--- proto_register_x509ce ----------------------------------------------*/
void proto_register_x509ce(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509ce_id_ce_baseUpdateTime,
      { "baseUpdateTime", "x509ce.id_ce_baseUpdateTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "baseUpdateTime", HFILL }},
    { &hf_x509ce_id_ce_invalidityDate,
      { "invalidityDate", "x509ce.id_ce_invalidityDate",
        FT_STRING, BASE_NONE, NULL, 0,
        "invalidityDate", HFILL }},
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
	register_ber_oid_dissector("2.5.29.9", dissect_AttributesSyntax_PDU, proto_x509ce, "id-ce-subjectDirectoryAttributes");
	register_ber_oid_dissector("2.5.29.14", dissect_SubjectKeyIdentifier_PDU, proto_x509ce, "id-ce-subjectKeyIdentifier");
	register_ber_oid_dissector("2.5.29.15", dissect_KeyUsage_PDU, proto_x509ce, "id-ce-keyUsage");
	register_ber_oid_dissector("2.5.29.16", dissect_PrivateKeyUsagePeriod_PDU, proto_x509ce, "id-ce-privateKeyUsagePeriod");
	register_ber_oid_dissector("2.5.29.17", dissect_GeneralNames_PDU, proto_x509ce, "id-ce-subjectAltName");
	register_ber_oid_dissector("2.5.29.18", dissect_GeneralNames_PDU, proto_x509ce, "id-ce-issuerAltName");
	register_ber_oid_dissector("2.5.29.19", dissect_BasicConstraintsSyntax_PDU, proto_x509ce, "id-ce-basicConstraints");
	register_ber_oid_dissector("2.5.29.20", dissect_CRLNumber_PDU, proto_x509ce, "id-ce-cRLNumber");
	register_ber_oid_dissector("2.5.29.21", dissect_CRLReason_PDU, proto_x509ce, "id-ce-reasonCode");
	register_ber_oid_dissector("2.5.29.23", dissect_HoldInstruction_PDU, proto_x509ce, "id-ce-instructionCode");
	register_ber_oid_dissector("2.5.29.24", dissect_x509ce_invalidityDate_callback, proto_x509ce, "id-ce-invalidityDate");
	register_ber_oid_dissector("2.5.29.27", dissect_BaseCRLNumber_PDU, proto_x509ce, "id-ce-deltaCRLIndicator");
	register_ber_oid_dissector("2.5.29.28", dissect_IssuingDistPointSyntax_PDU, proto_x509ce, "id-ce-issuingDistributionPoint");
	register_ber_oid_dissector("2.5.29.29", dissect_GeneralNames_PDU, proto_x509ce, "id-ce-certificateIssuer");
	register_ber_oid_dissector("2.5.29.30", dissect_NameConstraintsSyntax_PDU, proto_x509ce, "id-ce-nameConstraints");
	register_ber_oid_dissector("2.5.29.31", dissect_CRLDistPointsSyntax_PDU, proto_x509ce, "id-ce-cRLDistributionPoints");
	register_ber_oid_dissector("2.5.29.32", dissect_CertificatePoliciesSyntax_PDU, proto_x509ce, "id-ce-certificatePolicies");
	register_ber_oid_dissector("2.5.29.33", dissect_PolicyMappingsSyntax_PDU, proto_x509ce, "id-ce-policyMappings");
	register_ber_oid_dissector("2.5.29.35", dissect_AuthorityKeyIdentifier_PDU, proto_x509ce, "id-ce-authorityKeyIdentifier");
	register_ber_oid_dissector("2.5.29.36", dissect_PolicyConstraintsSyntax_PDU, proto_x509ce, "id-ce-policyConstraints");
	register_ber_oid_dissector("2.5.29.37", dissect_KeyPurposeIDs_PDU, proto_x509ce, "id-ce-extKeyUsage");
	register_ber_oid_dissector("2.5.29.40", dissect_CRLStreamIdentifier_PDU, proto_x509ce, "id-ce-cRLStreamIdentifier");
	register_ber_oid_dissector("2.5.29.44", dissect_CRLScopeSyntax_PDU, proto_x509ce, "id-ce-cRLScope");
	register_ber_oid_dissector("2.5.29.45", dissect_StatusReferrals_PDU, proto_x509ce, "id-ce-statusReferrals");
	register_ber_oid_dissector("2.5.29.46", dissect_CRLDistPointsSyntax_PDU, proto_x509ce, "id-ce-freshestCRL");
	register_ber_oid_dissector("2.5.29.47", dissect_OrderedListSyntax_PDU, proto_x509ce, "id-ce-orderedList");
	register_ber_oid_dissector("2.5.29.51", dissect_x509ce_baseUpdateTime_callback, proto_x509ce, "id-ce-baseUpdateTime");
	register_ber_oid_dissector("2.5.29.53", dissect_DeltaInformation_PDU, proto_x509ce, "id-ce-deltaInfo");
	register_ber_oid_dissector("2.5.29.54", dissect_SkipCerts_PDU, proto_x509ce, "id-ce-inhibitAnyPolicy");
}

