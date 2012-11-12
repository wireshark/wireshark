/* packet-acp133.c
 * Routines for ACP133 specific syntaxes in X.500 packet dissection
 * Graeme Lunt 2005
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>
#include <epan/oids.h>

#include "packet-ber.h"

#include "packet-p1.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509if.h"
#include "packet-x509sat.h"

#include "packet-acp133.h"

#define PNAME  "ACP133 Attribute Syntaxes"
#define PSNAME "ACP133"
#define PFNAME "acp133"

/* Initialize the protocol and registered fields */
static int proto_acp133 = -1;


#include "packet-acp133-hf.c"

/* Initialize the subtree pointers */
static gint ett_acp133 = -1;
#include "packet-acp133-ett.c"

#include "packet-acp133-fn.c"


/*--- proto_register_acp133 -------------------------------------------*/
void proto_register_acp133(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-acp133-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_acp133,
#include "packet-acp133-ettarr.c"
  };

  /* Register protocol */
  proto_acp133 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_acp133, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_acp133 --- */
void proto_reg_handoff_acp133(void) {

#include "packet-acp133-dis-tab.c" 

  /* X.402 Object Classes */
  oid_add_from_string("id-oc-mhs-distribution-list","2.6.5.1.0");
  oid_add_from_string("id-oc-mhs-message-store","2.6.5.1.1");
  oid_add_from_string("id-oc-mhs-message-transfer-agent","2.6.5.1.2");
  oid_add_from_string("id-oc-mhs-user","2.6.5.1.3");

  /* SDN.701 Object Classes */
  oid_add_from_string("id-oc-secure-user","2.16.840.1.101.2.1.4.13");
  oid_add_from_string("id-oc-ukms","2.16.840.1.101.2.1.4.16");

  /* ACP133 Object Classes */
  oid_add_from_string("id-oc-plaData","2.16.840.1.101.2.2.3.26");
  oid_add_from_string("id-oc-cadACP127","2.16.840.1.101.2.2.3.28");
  oid_add_from_string("id-oc-mLA","2.16.840.1.101.2.2.3.31");
  oid_add_from_string("id-oc-orgACP127","2.16.840.1.101.2.2.3.34");
  oid_add_from_string("id-oc-plaCollectiveACP127","2.16.840.1.101.2.2.3.35");
  oid_add_from_string("id-oc-routingIndicator","2.16.840.1.101.2.2.3.37");
  oid_add_from_string("id-oc-sigintPLA","2.16.840.1.101.2.2.3.38");
  oid_add_from_string("id-oc-sIPLA","2.16.840.1.101.2.2.3.39");
  oid_add_from_string("id-oc-spotPLA","2.16.840.1.101.2.2.3.40");
  oid_add_from_string("id-oc-taskForceACP127","2.16.840.1.101.2.2.3.41");
  oid_add_from_string("id-oc-tenantACP127","2.16.840.1.101.2.2.3.42");
  oid_add_from_string("id-oc-plaACP127","2.16.840.1.101.2.2.3.47");
  oid_add_from_string("id-oc-aliasCommonName","2.16.840.1.101.2.2.3.52");
  oid_add_from_string("id-oc-aliasOrganizationalUnit","2.16.840.1.101.2.2.3.53");
  oid_add_from_string("id-oc-distributionCodesHandled","2.16.840.1.101.2.2.3.54");
  oid_add_from_string("id-oc-distributionCodeDescription","2.16.840.1.101.2.2.3.55");
  oid_add_from_string("id-oc-plaUser","2.16.840.1.101.2.2.3.56");
  oid_add_from_string("id-oc-addressList","2.16.840.1.101.2.2.3.57");
  oid_add_from_string("id-oc-altSpellingACP127","2.16.840.1.101.2.2.3.58");
  oid_add_from_string("id-oc-messagingGateway","2.16.840.1.101.2.2.3.59");
  oid_add_from_string("id-oc-network","2.16.840.1.101.2.2.3.60");
  oid_add_from_string("id-oc-networkInstructions","2.16.840.1.101.2.2.3.61");
  oid_add_from_string("id-oc-otherContactInformation","2.16.840.1.101.2.2.3.62");
  oid_add_from_string("id-oc-releaseAuthorityPerson","2.16.840.1.101.2.2.3.63");
  oid_add_from_string("id-oc-mLAgent","2.16.840.1.101.2.2.3.64");
  oid_add_from_string("id-oc-releaseAuthorityPersonA","2.16.840.1.101.2.2.3.65");
  oid_add_from_string("id-oc-securePkiUser","2.16.840.1.101.2.2.3.66");
  oid_add_from_string("id-oc-dSSCSPLA","2.16.840.1.101.2.2.3.67");
  oid_add_from_string("id-oc-aCPNetworkEdB","2.16.840.1.101.2.2.3.68");
  oid_add_from_string("id-oc-aCPNetworkInstructionsEdB","2.16.840.1.101.2.2.3.69");
  oid_add_from_string("id-oc-aCPAddressList","2.16.840.1.101.2.2.3.70");
  oid_add_from_string("id-oc-aCPAliasCommonName","2.16.840.1.101.2.2.3.71");
  oid_add_from_string("id-oc-aCPAliasOrganizationalUnit","2.16.840.1.101.2.2.3.72");
  oid_add_from_string("id-oc-aCPDevice","2.16.840.1.101.2.2.3.73");
  oid_add_from_string("id-oc-aCPDistributionCodeDescription","2.16.840.1.101.2.2.3.74");
  oid_add_from_string("id-oc-aCPGroupOfNames","2.16.840.1.101.2.2.3.75");
  oid_add_from_string("id-oc-aCPLocality","2.16.840.1.101.2.2.3.76");
  oid_add_from_string("id-oc-aCPOrganization","2.16.840.1.101.2.2.3.77");
  oid_add_from_string("id-oc-aCPOrganizationalPerson","2.16.840.1.101.2.2.3.78");
  oid_add_from_string("id-oc-aCPOrganizationalRole","2.16.840.1.101.2.2.3.79");
  oid_add_from_string("id-oc-aCPOrganizationalUnit","2.16.840.1.101.2.2.3.80");
  oid_add_from_string("id-oc-aCPDistributionCodesHandled","2.16.840.1.101.2.2.3.81");
  oid_add_from_string("id-oc-aCPMhsCapabilitiesInformation","2.16.840.1.101.2.2.3.82");
  oid_add_from_string("id-oc-aCPOtherContactInformation","2.16.840.1.101.2.2.3.83");
  oid_add_from_string("id-oc-aCPPlaUser","2.16.840.1.101.2.2.3.84");
  oid_add_from_string("id-oc-aCPCRLDistributionPoint","2.16.840.1.101.2.2.3.85");
  oid_add_from_string("id-oc-aCPSecurePKIUser","2.16.840.1.101.2.2.3.86");
  oid_add_from_string("id-oc-aCPAltSpellingACP127","2.16.840.1.101.2.2.3.87");
  oid_add_from_string("id-oc-aCPCadACP127","2.16.840.1.101.2.2.3.88");
  oid_add_from_string("id-oc-aCPDSSCSPLA","2.16.840.1.101.2.2.3.89");
  oid_add_from_string("id-oc-aCPOrgACP127","2.16.840.1.101.2.2.3.90");
  oid_add_from_string("id-oc-aCPPLACollectiveACP127","2.16.840.1.101.2.2.3.91");
  oid_add_from_string("id-oc-aCPRoutingIndicator","2.16.840.1.101.2.2.3.92");
  oid_add_from_string("id-oc-aCPSigIntPLA","2.16.840.1.101.2.2.3.93");
  oid_add_from_string("id-oc-aCPSIPLA","2.16.840.1.101.2.2.3.94");
  oid_add_from_string("id-oc-aCPSpotPLA","2.16.840.1.101.2.2.3.95");
  oid_add_from_string("id-oc-aCPTaskForceACP127","2.16.840.1.101.2.2.3.96");
  oid_add_from_string("id-oc-aCPTenantACP127","2.16.840.1.101.2.2.3.97");
  oid_add_from_string("id-oc-aCPPlaACP127","2.16.840.1.101.2.2.3.98");
  oid_add_from_string("id-oc-aCPPlaData","2.16.840.1.101.2.2.3.99");
  oid_add_from_string("id-oc-aCPEntryAdmin","2.16.840.1.101.2.2.3.102");
  oid_add_from_string("id-oc-aCPOrganizationalLocation","2.16.840.1.101.2.2.3.103");
  oid_add_from_string("id-oc-aCPEntryCharacteristics","2.16.840.1.101.2.2.3.104");
  oid_add_from_string("id-oc-aCPPrivilege","2.16.840.1.101.2.2.3.105");

  /* gateway types */
  oid_add_from_string("acp120-acp127","2.16.840.1.101.2.2.5.0");
  oid_add_from_string("acp120-janap128","2.16.840.1.101.2.2.5.1");
  oid_add_from_string("acp120-mhs","2.16.840.1.101.2.2.5.2");
  oid_add_from_string("acp120-mmhs","2.16.840.1.101.2.2.5.3");
  oid_add_from_string("acp120-rfc822","2.16.840.1.101.2.2.5.4");
  oid_add_from_string("boundaryMTA","2.16.840.1.101.2.2.5.5");
  oid_add_from_string("mmhs-mhs","2.16.840.1.101.2.2.5.6");
  oid_add_from_string("mmhs-rfc822","2.16.840.1.101.2.2.5.7");
  oid_add_from_string("mta-acp127","2.16.840.1.101.2.2.5.8");

}
