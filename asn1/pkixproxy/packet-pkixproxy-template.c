/* packet-pkixproxy.c
 * Routines for RFC3820 PKIXProxy packet dissection
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
#include <epan/oid_resolv.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-pkixproxy.h"

#define PNAME  "PKIXProxy (RFC3820)"
#define PSNAME "PKIXPROXY"
#define PFNAME "pkixproxy"

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
  add_oid_str_name("1.3.6.1.5.5.7.21.0", "id-ppl-anyLanguage");
  add_oid_str_name("1.3.6.1.5.5.7.21.1", "id-ppl-inheritAll");
  add_oid_str_name("1.3.6.1.5.5.7.21.2", "id-ppl-independent");
}

