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
#include "packet-x509af.h"
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
static int hf_x509ce_id_ce_instructionCode = -1;
static int hf_x509ce_id_ce_invalidityDate = -1;
static int hf_x509ce_id_ce_deltaCRLIndicator = -1;
static int hf_x509ce_id_ce_issuingDistributionPoint = -1;
static int hf_x509ce_id_ce_certificateIssuer = -1;
static int hf_x509ce_id_ce_nameConstraints = -1;
static int hf_x509ce_id_ce_cRLDistributionPoints = -1;
static int hf_x509ce_id_ce_certificatePolicies = -1;
static int hf_x509ce_id_ce_policyMappings = -1;
static int hf_x509ce_id_ce_authorityKeyIdentifier = -1;
static int hf_x509ce_id_ce_policyConstraints = -1;
static int hf_x509ce_id_ce_extKeyUsage = -1;
static int hf_x509ce_id_ce_cRLStreamIdentifier = -1;
static int hf_x509ce_id_ce_cRLScope = -1;
static int hf_x509ce_id_ce_statusReferrals = -1;
static int hf_x509ce_id_ce_freshestCRL = -1;
static int hf_x509ce_id_ce_orderedList = -1;
static int hf_x509ce_id_ce_baseUpdateTime = -1;
static int hf_x509ce_id_ce_deltaInfo = -1;
static int hf_x509ce_id_ce_inhibitAnyPolicy = -1;
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

static void
dissect_x509ce_instructionCode_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_HoldInstruction(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_instructionCode);
}

static void
dissect_x509ce_invalidityDate_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralizedTime(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_invalidityDate);
}

static void
dissect_x509ce_deltaCRLIndicator_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_BaseCRLNumber(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_deltaCRLIndicator);
}

static void
dissect_x509ce_issuingDistributionPoint_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_IssuingDistPointSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_issuingDistributionPoint);
}

static void
dissect_x509ce_certificateIssuer_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralNames(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_certificateIssuer);
}

static void
dissect_x509ce_nameConstraints_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_NameConstraintsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_nameConstraints);
}

static void
dissect_x509ce_cRLDistributionPoints_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CRLDistPointsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_cRLDistributionPoints);
}

static void
dissect_x509ce_certificatePolicies_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CertificatePoliciesSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_certificatePolicies);
}

static void
dissect_x509ce_policyMappings_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_PolicyMappingsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_policyMappings);
}

static void
dissect_x509ce_authorityKeyIdentifier_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_AuthorityKeyIdentifier(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_authorityKeyIdentifier);
}

static void
dissect_x509ce_policyConstraints_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_PolicyConstraintsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_policyConstraints);
}

static void
dissect_x509ce_extKeyUsage_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_KeyPurposeIDs(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_extKeyUsage);
}

static void
dissect_x509ce_cRLStreamIdentifier_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CRLStreamIdentifier(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_cRLStreamIdentifier);
}

static void
dissect_x509ce_cRLScope_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CRLScopeSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_cRLScope);
}

static void
dissect_x509ce_statusReferrals_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_StatusReferrals(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_statusReferrals);
}

static void
dissect_x509ce_freshestCRL_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_CRLDistPointsSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_freshestCRL);
}

static void
dissect_x509ce_orderedList_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_OrderedListSyntax(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_orderedList);
}

static void
dissect_x509ce_baseUpdateTime_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_GeneralizedTime(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_baseUpdateTime);
}

static void
dissect_x509ce_deltaInfo_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_DeltaInformation(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_deltaInfo);
}

static void
dissect_x509ce_inhibitAnyPolicy_callback(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	dissect_x509ce_SkipCerts(FALSE, tvb, 0, pinfo, tree, hf_x509ce_id_ce_inhibitAnyPolicy);
}

/*--- proto_register_x509ce ----------------------------------------------*/
void proto_register_x509ce(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_x509ce_id_ce_inhibitAnyPolicy,
      { "inhibitAnyPolicy", "x509ce.id_ce_inhibitAnyPolicy",
        FT_UINT32, BASE_DEC, NULL, 0,
        "inhibitAnyPolicy", HFILL }},
    { &hf_x509ce_id_ce_deltaInfo,
      { "deltaInfo", "x509ce.id_ce_deltaInfo",
        FT_NONE, BASE_NONE, NULL, 0,
        "deltaInfo", HFILL }},
    { &hf_x509ce_id_ce_baseUpdateTime,
      { "baseUpdateTime", "x509ce.id_ce_baseUpdateTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "baseUpdateTime", HFILL }},
    { &hf_x509ce_id_ce_orderedList,
      { "orderedList", "x509ce.id_ce_orderedList",
        FT_UINT32, BASE_DEC, VALS(OrderedListSyntax_vals), 0,
        "orderedList", HFILL }},
    { &hf_x509ce_id_ce_freshestCRL,
      { "freshestCRL", "x509ce.id_ce_freshestCRL",
        FT_NONE, BASE_NONE, NULL, 0,
        "freshestCRL", HFILL }},
    { &hf_x509ce_id_ce_statusReferrals,
      { "statusReferrals", "x509ce.id_ce_statusReferrals",
        FT_NONE, BASE_NONE, NULL, 0,
        "statusReferrals", HFILL }},
    { &hf_x509ce_id_ce_cRLScope,
      { "cRLScope", "x509ce.id_ce_cRLScope",
        FT_NONE, BASE_NONE, NULL, 0,
        "cRLScope", HFILL }},
    { &hf_x509ce_id_ce_cRLStreamIdentifier,
      { "cRLStreamIdentifier", "x509ce.id_ce_cRLStreamIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "cRLStreamIdentifier", HFILL }},
    { &hf_x509ce_id_ce_extKeyUsage,
      { "extKeyUsage", "x509ce.id_ce_extKeyUsage",
        FT_NONE, BASE_NONE, NULL, 0,
        "extKeyUsage", HFILL }},
    { &hf_x509ce_id_ce_policyConstraints,
      { "policyConstraints", "x509ce.id_ce_policyConstraints",
        FT_NONE, BASE_NONE, NULL, 0,
        "policyConstraints", HFILL }},
    { &hf_x509ce_id_ce_authorityKeyIdentifier,
      { "authorityKeyIdentifier", "x509ce.id_ce_authorityKeyIdentifier",
        FT_NONE, BASE_NONE, NULL, 0,
        "authorityKeyIdentifier", HFILL }},
    { &hf_x509ce_id_ce_policyMappings,
      { "policyMappings", "x509ce.id_ce_policyMappings",
        FT_NONE, BASE_NONE, NULL, 0,
        "policyMappings", HFILL }},
    { &hf_x509ce_id_ce_certificatePolicies,
      { "certificatePolicies", "x509ce.id_ce_certificatePolicies",
        FT_NONE, BASE_NONE, NULL, 0,
        "certificatePolicies", HFILL }},
    { &hf_x509ce_id_ce_cRLDistributionPoints,
      { "cRLDistributionPoints", "x509ce.id_ce_cRLDistributionPoints",
        FT_NONE, BASE_NONE, NULL, 0,
        "cRLDistributionPoints", HFILL }},
    { &hf_x509ce_id_ce_nameConstraints,
      { "nameConstraints", "x509ce.id_ce_nameConstraints",
        FT_NONE, BASE_NONE, NULL, 0,
        "nameConstraints", HFILL }},
    { &hf_x509ce_id_ce_certificateIssuer,
      { "certificateIssuer", "x509ce.id_ce_certificateIssuer",
        FT_NONE, BASE_NONE, NULL, 0,
        "certificateIssuer", HFILL }},
    { &hf_x509ce_id_ce_issuingDistributionPoint,
      { "issuingDistributionPoint", "x509ce.id_ce_issuingDistributionPoint",
        FT_NONE, BASE_NONE, NULL, 0,
        "issuingDistributionPoint", HFILL }},
    { &hf_x509ce_id_ce_deltaCRLIndicator,
      { "deltaCRLIndicator", "x509ce.id_ce_deltaCRLIndicator",
        FT_UINT32, BASE_DEC, VALS(CRLReason_vals), 0,
        "deltaCRLIndicator", HFILL }},
    { &hf_x509ce_id_ce_invalidityDate,
      { "invalidityDate", "x509ce.id_ce_invalidityDate",
        FT_STRING, BASE_NONE, NULL, 0,
        "invalidityDate", HFILL }},
    { &hf_x509ce_id_ce_instructionCode,
      { "instructionCode", "x509ce.id_ce_instructionCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "instructionCode", HFILL }},
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
        FT_BYTES, BASE_HEX, NULL, 0,
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
	register_ber_oid_dissector("2.5.29.23", dissect_x509ce_instructionCode_callback, proto_x509ce, "id-ce-instructionCode");
	register_ber_oid_dissector("2.5.29.24", dissect_x509ce_invalidityDate_callback, proto_x509ce, "id-ce-invalidityDate");
	register_ber_oid_dissector("2.5.29.27", dissect_x509ce_deltaCRLIndicator_callback, proto_x509ce, "id-ce-deltaCRLIndicator");
	register_ber_oid_dissector("2.5.29.28", dissect_x509ce_issuingDistributionPoint_callback, proto_x509ce, "id-ce-issuingDistributionPoint");
	register_ber_oid_dissector("2.5.29.29", dissect_x509ce_certificateIssuer_callback, proto_x509ce, "id-ce-certificateIssuer");
	register_ber_oid_dissector("2.5.29.30", dissect_x509ce_nameConstraints_callback, proto_x509ce, "id-ce-nameConstraints");
	register_ber_oid_dissector("2.5.29.31", dissect_x509ce_cRLDistributionPoints_callback, proto_x509ce, "id-ce-cRLDistributionPoints");
	register_ber_oid_dissector("2.5.29.32", dissect_x509ce_certificatePolicies_callback, proto_x509ce, "id-ce-certificatePolicies");
	register_ber_oid_dissector("2.5.29.33", dissect_x509ce_policyMappings_callback, proto_x509ce, "id-ce-policyMappings");
	register_ber_oid_dissector("2.5.29.35", dissect_x509ce_authorityKeyIdentifier_callback, proto_x509ce, "id-ce-authorityKeyIdentifier");
	register_ber_oid_dissector("2.5.29.36", dissect_x509ce_policyConstraints_callback, proto_x509ce, "id-ce-policyConstraints");
	register_ber_oid_dissector("2.5.29.37", dissect_x509ce_extKeyUsage_callback, proto_x509ce, "id-ce-extKeyUsage");
	register_ber_oid_dissector("2.5.29.40", dissect_x509ce_cRLStreamIdentifier_callback, proto_x509ce, "id-ce-cRLStreamIdentifier");
	register_ber_oid_dissector("2.5.29.44", dissect_x509ce_cRLScope_callback, proto_x509ce, "id-ce-cRLScope");
	register_ber_oid_dissector("2.5.29.45", dissect_x509ce_statusReferrals_callback, proto_x509ce, "id-ce-statusReferrals");
	register_ber_oid_dissector("2.5.29.46", dissect_x509ce_freshestCRL_callback, proto_x509ce, "id-ce-freshestCRL");
	register_ber_oid_dissector("2.5.29.47", dissect_x509ce_orderedList_callback, proto_x509ce, "id-ce-orderedList");
	register_ber_oid_dissector("2.5.29.51", dissect_x509ce_baseUpdateTime_callback, proto_x509ce, "id-ce-baseUpdateTime");
	register_ber_oid_dissector("2.5.29.53", dissect_x509ce_deltaInfo_callback, proto_x509ce, "id-ce-deltaInfo");
	register_ber_oid_dissector("2.5.29.54", dissect_x509ce_inhibitAnyPolicy_callback, proto_x509ce, "id-ce-inhibitAnyPolicy");
}

