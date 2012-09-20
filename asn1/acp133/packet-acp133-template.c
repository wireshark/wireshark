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

#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-x509ce.h"
#include "packet-p1.h"

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
