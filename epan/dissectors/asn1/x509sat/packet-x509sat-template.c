/* packet-x509sat.c
 * Routines for X.509 Selected Attribute Types packet dissection
 *  Ronnie Sahlberg 2004
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

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-p1.h"
#include "packet-x509sat.h"
#include "packet-x509if.h"

#define PNAME  "X.509 Selected Attribute Types"
#define PSNAME "X509SAT"
#define PFNAME "x509sat"

void proto_register_x509sat(void);
void proto_reg_handoff_x509sat(void);

/* Initialize the protocol and registered fields */
static int proto_x509sat = -1;
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

#include "packet-x509sat-syn-reg.c"

}


/*--- proto_reg_handoff_x509sat -------------------------------------------*/
void proto_reg_handoff_x509sat(void) {
#include "packet-x509sat-dis-tab.c"

  /* OBJECT CLASSES */

  oid_add_from_string("top","2.5.6.0");
  oid_add_from_string("alias","2.5.6.1");
  oid_add_from_string("country","2.5.6.2");
  oid_add_from_string("locality","2.5.6.3");
  oid_add_from_string("organization","2.5.6.4");
  oid_add_from_string("organizationalUnit","2.5.6.5");
  oid_add_from_string("person","2.5.6.6");
  oid_add_from_string("organizationalPerson","2.5.6.7");
  oid_add_from_string("organizationalRole","2.5.6.8");
  oid_add_from_string("groupOfNames","2.5.6.9");
  oid_add_from_string("residentialPerson","2.5.6.10");
  oid_add_from_string("applicationProcess","2.5.6.11");
  oid_add_from_string("applicationEntity","2.5.6.12");
  oid_add_from_string("dSA","2.5.6.13");
  oid_add_from_string("device","2.5.6.14");
  oid_add_from_string("strongAuthenticationUser","2.5.6.15");
  oid_add_from_string("certificationAuthority","2.5.6.16");
  oid_add_from_string("certificationAuthorityV2","2.5.6.16.2");
  oid_add_from_string("groupOfUniqueNames","2.5.6.17");
  oid_add_from_string("userSecurityInformation","2.5.6.18");
  oid_add_from_string("cRLDistributionPoint","2.5.6.19");
  oid_add_from_string("dmd","2.5.6.20");
  oid_add_from_string("pkiUser","2.5.6.21");
  oid_add_from_string("pkiCA","2.5.6.22");

  oid_add_from_string("parent","2.5.6.28");
  oid_add_from_string("child","2.5.6.29");

  /* RFC 2247 */
  oid_add_from_string("dcObject","1.3.6.1.4.1.1446.344");
  oid_add_from_string("domain","0.9.2342.19200300.100.4.13");

  /* RFC 2798 */
  oid_add_from_string("inetOrgPerson","2.16.840.1.113730.3.2.2");
}



