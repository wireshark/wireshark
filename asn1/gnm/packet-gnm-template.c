/* packet-gnm.c
 * Routines for GENERIC NETWORK INFORMATION MODEL Data dissection
 *
 * Copyright 2005 , Anders Broman <anders.broman [AT] ericsson.com>
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
 *
 *
 * References:
 * ITU-T recommendatiom M.3100
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-cmip.h"
#include "packet-gnm.h"

#define PNAME  "ITU M.3100 Generic Network Information Model"
#define PSNAME "GNM"
#define PFNAME "gnm"

/* Initialize the protocol and registered fields */
static int proto_gnm = -1;

#include "packet-gnm-hf.c"

/* Initialize the subtree pointers */
#include "packet-gnm-ett.c"

#include "packet-gnm-fn.c"



static void
dissect_gnm_attribute_ObjectInstance(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	asn1_ctx_t asn1_ctx;

	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	dissect_cmip_ObjectInstance(FALSE, tvb, 0, &asn1_ctx, parent_tree, -1);

}

void
dissect_gnm(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *parent_tree _U_)
{
  /* Dymmy function */
}

/*--- proto_register_gnm -------------------------------------------*/
void proto_register_gnm(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-gnm-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-gnm-ettarr.c"
  };

  /* Register protocol */
  proto_gnm = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("gnm", dissect_gnm, proto_gnm);
  /* Register fields and subtrees */
  proto_register_field_array(proto_gnm, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_gnm ---------------------------------------*/
void proto_reg_handoff_gnm(void) {
#include "packet-gnm-dis-tab.c"
	/* Wrapper to call CMIP */
	register_ber_oid_dissector("0.0.13.3100.0.7.9", dissect_gnm_attribute_ObjectInstance, proto_gnm, "clientConnection(9)");
	register_ber_oid_dissector("0.0.13.3100.0.7.10", dissect_gnm_attribute_ObjectInstance, proto_gnm, "clientTrail(10)");
	register_ber_oid_dissector("0.0.13.3100.0.7.31", dissect_gnm_attribute_ObjectInstance, proto_gnm, "networkLevelPointer(31)");
	register_ber_oid_dissector("0.0.13.3100.0.7.46", dissect_gnm_attribute_ObjectInstance, proto_gnm, "networkLevelPointer(31)");

}
