/* packet-pkixqualified.c
 * Routines for RFC3739 PKIXqualified packet dissection
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-pkixqualified.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509sat.h"

#define PNAME  "PKIX Qualified"
#define PSNAME "PKIXQUALIFIED"
#define PFNAME "pkixqualified"

/* Initialize the protocol and registered fields */
static int proto_pkixqualified = -1;
#include "packet-pkixqualified-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkixqualified-ett.c"

static const char *object_identifier_id;

#include "packet-pkixqualified-fn.c"


/*--- proto_register_pkixqualified ----------------------------------------------*/
void proto_register_pkixqualified(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-pkixqualified-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-pkixqualified-ettarr.c"
  };

  /* Register protocol */
  proto_pkixqualified = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkixqualified, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkixqualified -------------------------------------------*/
void proto_reg_handoff_pkixqualified(void) {
#include "packet-pkixqualified-dis-tab.c"
}

