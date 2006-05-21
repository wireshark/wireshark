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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 * References:
 * ITU-T recommendatiom M.3100
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>
#include "packet-cmip.h"
#include "packet-ber.h"
#include "packet-gnm.h"

#define PNAME  "ITU M.3100 Generic Network Information Model"
#define PSNAME "GNM"
#define PFNAME "gnm"

/* Initialize the protocol and registered fields */
int proto_gnm = -1;

static int hf_gnm_AdministrativeState = -1;
#include "packet-gnm-hf.c"

/* Initialize the subtree pointers */
#include "packet-gnm-ett.c"

#include "packet-gnm-fn.c"



static void
dissect_gnm_attribute_ObjectInstance(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{

	dissect_cmip_ObjectInstance(FALSE, tvb, 0, pinfo, parent_tree, -1);

}

void
dissect_gnm(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  /* Dymmy function */
}

/*--- proto_register_gnm -------------------------------------------*/
void proto_register_gnm(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_gnm_AdministrativeState,
      { "AdministrativeState", "gnm.AdministrativeState",
        FT_UINT32, BASE_DEC, VALS(gnm_AdministrativeState_vals), 0,
        "", HFILL }},

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
	register_ber_oid_dissector("0.0.13.3100.0.7.9", dissect_gnm_attribute_ObjectInstance, proto_gnm, "clientConnection(9)");
	register_ber_oid_dissector("0.0.13.3100.0.7.10", dissect_gnm_attribute_ObjectInstance, proto_gnm, "clientTrail(10)");
	register_ber_oid_dissector("0.0.13.3100.0.7.31", dissect_gnm_attribute_ObjectInstance, proto_gnm, "networkLevelPointer(31)");
	register_ber_oid_dissector("0.0.13.3100.0.7.46", dissect_gnm_attribute_ObjectInstance, proto_gnm, "networkLevelPointer(31)");

}
