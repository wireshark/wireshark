/* packet-pkinit.c
 * Routines for PKINIT packet dissection
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
#include "packet-pkinit.h"
#include "packet-cms.h"
#include "packet-pkix1explicit.h"
#include "packet-kerberos.h"

#define PNAME  "PKINIT"
#define PSNAME "PKInit"
#define PFNAME "pkinit"

/* Initialize the protocol and registered fields */
static int proto_pkinit = -1;
#include "packet-pkinit-hf.c"

/* Initialize the subtree pointers */
#include "packet-pkinit-ett.c"

static int dissect_KerberosV5Spec2_KerberosTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index _U_);
static int dissect_KerberosV5Spec2_Checksum(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index _U_);

#include "packet-pkinit-fn.c"

int
dissect_pkinit_PA_PK_AS_REQ(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  offset = dissect_pkinit_PaPkAsReq(FALSE, tvb, offset, pinfo, tree, -1);
  return offset;
}

int
dissect_pkinit_PA_PK_AS_REP(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  offset = dissect_pkinit_PaPkAsRep(FALSE, tvb, offset, pinfo, tree, -1);
  return offset;
}

static int
dissect_KerberosV5Spec2_KerberosTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_ctime(pinfo, tree, tvb, offset);
  return offset;
}

static int
dissect_KerberosV5Spec2_Checksum(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index _U_) {
  offset = dissect_krb5_Checksum(pinfo, tree, tvb, offset);
  return offset;
}


/*--- proto_register_pkinit ----------------------------------------------*/
void proto_register_pkinit(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-pkinit-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-pkinit-ettarr.c"
  };

  /* Register protocol */
  proto_pkinit = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_pkinit, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_pkinit -------------------------------------------*/
void proto_reg_handoff_pkinit(void) {
#include "packet-pkinit-dis-tab.c"
}

