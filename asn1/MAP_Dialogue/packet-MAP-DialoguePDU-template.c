/* packet-MAP_DialoguePDU_asn1.c
 * Routines for MAP_DialoguePDU packet dissection
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
#include "packet-gsm_map.h"

#define PNAME  "MAP_DialoguePDU"
#define PSNAME "MAP_DialoguePDU"
#define PFNAME "map_dialoguepdu"

/* Initialize the protocol and registered fields */
int proto_MAP_DialoguePDU = -1;
#include "packet-MAP_DialoguePDU-hf.c"

/* Initialize the subtree pointers */
#include "packet-MAP_DialoguePDU-ett.c"

#include "packet-MAP_DialoguePDU-fn.c"

static void
dissect_MAP_Dialogue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  dissect_MAP_DialoguePDU_MAP_DialoguePDU(FALSE, tvb, 0, pinfo, parent_tree, -1);
}

/*--- proto_register_MAP_DialoguePDU -------------------------------------------*/
void proto_register_MAP_DialoguePDU(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-MAP_DialoguePDU-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-MAP_DialoguePDU-ettarr.c"
  };

  /* Register protocol */
  proto_MAP_DialoguePDU = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("MAP_DialoguePDU", dissect_MAP_Dialogue, proto_MAP_DialoguePDU);
  /* Register fields and subtrees */
  proto_register_field_array(proto_MAP_DialoguePDU, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_MAP_DialoguePDU ---------------------------------------*/
void proto_reg_handoff_MAP_DialoguePDU(void) {
	register_ber_oid_dissector("0.4.0.0.1.1.1.1", dissect_MAP_Dialogue, proto_MAP_DialoguePDU, 
	  "itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) abstractSyntax(1) map-DialoguePDU(1) version1(1)");

}
