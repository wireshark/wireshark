/* packet-pkix1implicit.c
 * Routines for PKIX1Implitic packet dissection
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
#include "packet-pkix1implicit.h"
#include "packet-pkix1explicit.h"
#include "packet-x509ce.h"

#define PNAME  "PKIX1Implitit"
#define PSNAME "PKIX1IMPLICIT"
#define PFNAME "pkix1implicit"

/* Initialize the protocol and registered fields */
static int proto_pkix1implicit = -1;
#include "packet-pkix1implicit-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkix1implicit-ett.c"


int
dissect_pkix1implicit_ReasonFlags(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509ce_ReasonFlags(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}
int
dissect_pkix1implicit_GeneralName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_x509ce_GeneralName(implicit_tag, tvb, offset, pinfo, tree, hf_index);

  return offset;
}

#include "packet-pkix1implicit-fn.c"


/*--- proto_register_pkix1implicit ----------------------------------------------*/
void proto_register_pkix1implicit(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-pkix1implicit-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-pkix1implicit-ettarr.c"
  };

  /* Register protocol */
  proto_pkix1implicit = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkix1implicit, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkix1implicit -------------------------------------------*/
void proto_reg_handoff_pkix1implicit(void) {
#include "packet-pkix1implicit-dis-tab.c"
}

