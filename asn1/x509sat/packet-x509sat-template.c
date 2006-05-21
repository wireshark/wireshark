/* packet-x509sat.c
 * Routines for X.509 Selected Attribute Types packet dissection
 *  Ronnie Sahlberg 2004
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
#include "packet-x509sat.h"
#include "packet-x509if.h"

#define PNAME  "X.509 Selected Attribute Types"
#define PSNAME "X509SAT"
#define PFNAME "x509sat"

/* Initialize the protocol and registered fields */
int proto_x509sat = -1;
#include "packet-x509sat-hf.c"

/* Initialize the subtree pointers */
#include "packet-x509sat-ett.c"

#include "packet-x509sat-fn.c"


/*--- proto_register_x509sat ----------------------------------------------*/
void proto_register_x509sat(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-x509sat-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
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
#include "packet-x509sat-dis-tab.c"

  /* OBJECT CLASSES */

  register_ber_oid_name("2.5.6.0", "top");
  register_ber_oid_name("2.5.6.1", "alias");
  register_ber_oid_name("2.5.6.2", "country");
  register_ber_oid_name("2.5.6.3", "locality");
  register_ber_oid_name("2.5.6.4", "organization");
  register_ber_oid_name("2.5.6.1", "organizationalUnit");
  register_ber_oid_name("2.5.6.6", "person");
  register_ber_oid_name("2.5.6.7", "organizationalPerson");
  register_ber_oid_name("2.5.6.8", "organizationalRole");
  register_ber_oid_name("2.5.6.9", "groupOfNames");
  register_ber_oid_name("2.5.6.10", "residentialPerson");
  register_ber_oid_name("2.5.6.11", "applicationProcess");
  register_ber_oid_name("2.5.6.12", "applicationEntity");
  register_ber_oid_name("2.5.6.13", "dSA");
  register_ber_oid_name("2.5.6.14", "device");
  register_ber_oid_name("2.5.6.15", "strongAuthenticationUser");
  register_ber_oid_name("2.5.6.16", "certificationAuthority");
  register_ber_oid_name("2.5.6.16.2", "certificationAuthorityV2");
  register_ber_oid_name("2.5.6.17", "groupOfUniqueNames");
  register_ber_oid_name("2.5.6.18", "userSecurityInformation");
  register_ber_oid_name("2.5.6.19", "cRLDistributionPoint");
  register_ber_oid_name("2.5.6.20", "dmd");
  register_ber_oid_name("2.5.6.21", "pkiUser");
  register_ber_oid_name("2.5.6.22", "pkiCA");
  
  register_ber_oid_name("2.5.6.28", "parent");
  register_ber_oid_name("2.5.6.29", "child");
}



