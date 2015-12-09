/* packet-HI2Operations.c
 * Routines for HI2 (ETSI TS 101 671 V3.5.1 (2009-11))
 *  Erwin van Eijk 2010
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
#include <epan/conversation.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"

#define PNAME  "HI2Operations"
#define PSNAME "HI2OPERATIONS"
#define PFNAME "hi2operations"

void proto_register_HI2Operations(void);
void proto_reg_handoff_HI2Operations(void);

/* Initialize the protocol and registered fields */
int proto_HI2Operations = -1;
#include "packet-HI2Operations-hf.c"

/* Initialize the subtree pointers */
#include "packet-HI2Operations-ett.c"

#include "packet-HI2Operations-fn.c"


/*--- proto_register_HI2Operations ----------------------------------------------*/
void proto_register_HI2Operations(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-HI2Operations-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-HI2Operations-ettarr.c"
  };

  /* Register protocol */
  proto_HI2Operations = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_HI2Operations, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("HI2Operations", dissect_IRIsContent_PDU, proto_HI2Operations);
}


/*--- proto_reg_handoff_HI2Operations -------------------------------------------*/
void proto_reg_handoff_HI2Operations(void) {
}

