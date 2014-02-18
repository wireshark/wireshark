/* packet-logotypecertextn.c
 * Routines for RFC3709 Logotype Certificate Extensions packet dissection
 *   Ronnie Sahlberg 2004
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

#include "packet-ber.h"
#include "packet-logotypecertextn.h"
#include "packet-x509af.h"

#define PNAME  "Logotype Certificate Extensions"
#define PSNAME "LogotypeCertExtn"
#define PFNAME "logotypecertextn"

void proto_register_logotypecertextn(void);
void proto_reg_handoff_logotypecertextn(void);

/* Initialize the protocol and registered fields */
static int proto_logotypecertextn = -1;
#include "packet-logotypecertextn-hf.c"

/* Initialize the subtree pointers */
#include "packet-logotypecertextn-ett.c"


#include "packet-logotypecertextn-fn.c"


/*--- proto_register_logotypecertextn ----------------------------------------------*/
void proto_register_logotypecertextn(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-logotypecertextn-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-logotypecertextn-ettarr.c"
  };

  /* Register protocol */
  proto_logotypecertextn = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_logotypecertextn, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_logotypecertextn -------------------------------------------*/
void proto_reg_handoff_logotypecertextn(void) {
#include "packet-logotypecertextn-dis-tab.c"
}

