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

#include "packet-x509af.h"
#include "packet-x509if.h"
#include "packet-x509ce.h"
#include "packet-x411.h"

#include "packet-acp133.h"

#define PNAME  "ACP133 Attribute Syntaxes"
#define PSNAME "ACP133"
#define PFNAME "acp133"

/* Initialize the protocol and registered fields */
int proto_acp133 = -1;


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
  register_ber_oid_name("2.6.5.1.0","id-oc-mhs-distribution-list");
  register_ber_oid_name("2.6.5.1.1","id-oc-mhs-message-store");
  register_ber_oid_name("2.6.5.1.2","id-oc-mhs-message-transfer-agent");
  register_ber_oid_name("2.6.5.1.3","id-oc-mhs-user");

  /* SDN.701 Object Classes */
  register_ber_oid_name("2.16.840.1.101.2.1.4.13", "id-oc-secure-user");
  register_ber_oid_name("2.16.840.1.101.2.1.4.16", "id-oc-ukms");

  /* ACP133 Object Classes */
  register_ber_oid_name("2.16.840.1.101.2.2.3.26", "id-oc-plaData");
  register_ber_oid_name("2.16.840.1.101.2.2.3.28", "id-oc-cadACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.31", "id-oc-mLA");
  register_ber_oid_name("2.16.840.1.101.2.2.3.34", "id-oc-orgACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.35", "id-oc-plaCollectiveACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.37", "id-oc-routingIndicator");
  register_ber_oid_name("2.16.840.1.101.2.2.3.38", "id-oc-sigintPLA");
  register_ber_oid_name("2.16.840.1.101.2.2.3.39", "id-oc-sIPLA");
  register_ber_oid_name("2.16.840.1.101.2.2.3.40", "id-oc-spotPLA");
  register_ber_oid_name("2.16.840.1.101.2.2.3.41", "id-oc-taskForceACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.42", "id-oc-tenantACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.47", "id-oc-plaACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.52", "id-oc-aliasCommonName");
  register_ber_oid_name("2.16.840.1.101.2.2.3.53", "id-oc-aliasOrganizationalUnit");
  register_ber_oid_name("2.16.840.1.101.2.2.3.54", "id-oc-distributionCodesHandled");
  register_ber_oid_name("2.16.840.1.101.2.2.3.55", "id-oc-distributionCodeDescription");
  register_ber_oid_name("2.16.840.1.101.2.2.3.56", "id-oc-plaUser");
  register_ber_oid_name("2.16.840.1.101.2.2.3.57", "id-oc-addressList");
  register_ber_oid_name("2.16.840.1.101.2.2.3.58", "id-oc-altSpellingACP127");
  register_ber_oid_name("2.16.840.1.101.2.2.3.59", "id-oc-messagingGateway");
  register_ber_oid_name("2.16.840.1.101.2.2.3.60", "id-oc-network");
  register_ber_oid_name("2.16.840.1.101.2.2.3.61", "id-oc-networkInstructions");
  register_ber_oid_name("2.16.840.1.101.2.2.3.62", "id-oc-otherContactInformation");
  register_ber_oid_name("2.16.840.1.101.2.2.3.63", "id-oc-releaseAuthorityPerson");
  register_ber_oid_name("2.16.840.1.101.2.2.3.64", "id-oc-mLAgent");
  register_ber_oid_name("2.16.840.1.101.2.2.3.65", "id-oc-releaseAuthorityPersonA");
  register_ber_oid_name("2.16.840.1.101.2.2.3.66", "id-oc-securePkiUser");
  register_ber_oid_name("2.16.840.1.101.2.2.3.67", "id-oc-dSSCSPLA");
  register_ber_oid_name("2.16.840.1.101.2.2.3.68", "id-oc-aCPNetworkEdB");
  register_ber_oid_name("2.16.840.1.101.2.2.3.69", "id-oc-aCPNetworkInstructionsEdB");

  /* gateway types */
  register_ber_oid_name("2.16.840.1.101.2.2.5.0", "acp120-acp127");
  register_ber_oid_name("2.16.840.1.101.2.2.5.1", "acp120-janap128");
  register_ber_oid_name("2.16.840.1.101.2.2.5.2", "acp120-mhs");
  register_ber_oid_name("2.16.840.1.101.2.2.5.3", "acp120-mmhs");
  register_ber_oid_name("2.16.840.1.101.2.2.5.4", "acp120-rfc822");
  register_ber_oid_name("2.16.840.1.101.2.2.5.5", "boundaryMTA");
  register_ber_oid_name("2.16.840.1.101.2.2.5.6", "mmhs-mhs");
  register_ber_oid_name("2.16.840.1.101.2.2.5.7", "mmhs-rfc822");
  register_ber_oid_name("2.16.840.1.101.2.2.5.8", "mta-acp127");

}
