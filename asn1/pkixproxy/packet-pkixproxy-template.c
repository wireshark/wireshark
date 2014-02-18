/* packet-pkixproxy.c
 * Routines for RFC3820 PKIXProxy packet dissection
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-pkixproxy.h"

#define PNAME  "PKIXProxy (RFC3820)"
#define PSNAME "PKIXPROXY"
#define PFNAME "pkixproxy"

void proto_register_pkixproxy(void);
void proto_reg_handoff_pkixproxy(void);

/* Initialize the protocol and registered fields */
static int proto_pkixproxy = -1;
#include "packet-pkixproxy-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkixproxy-ett.c"

#include "packet-pkixproxy-fn.c"


/*--- proto_register_pkixproxy ----------------------------------------------*/
void proto_register_pkixproxy(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-pkixproxy-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-pkixproxy-ettarr.c"
  };

  /* Register protocol */
  proto_pkixproxy = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkixproxy, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkixproxy -------------------------------------------*/
void proto_reg_handoff_pkixproxy(void) {
#include "packet-pkixproxy-dis-tab.c"
  oid_add_from_string("id-ppl-anyLanguage","1.3.6.1.5.5.7.21.0");
  oid_add_from_string("id-ppl-inheritAll","1.3.6.1.5.5.7.21.1");
  oid_add_from_string("id-ppl-independent","1.3.6.1.5.5.7.21.2");
}

