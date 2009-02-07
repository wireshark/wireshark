/* packet-lte-rrc-template.c
 * Routines for Evolved Universal Terrestrial Radio Access (E-UTRA);
 * Radio Resource Control (RRC) protocol specification
 * (3GPP TS 36.331 V8.3.0 Release 8) packet dissection
 * Copyright 2008, Vincent Helfre
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
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/asn1.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"
#include "packet-per.h"


#define PNAME  "LTE Radio Resource Control (RRC) protocol"
#define PSNAME "LTE RRC"
#define PFNAME "lte_rrc"

static dissector_handle_t nas_eps_handle = NULL;

/* Include constants */
#include "packet-lte-rrc-val.h"

/* Initialize the protocol and registered fields */
static int proto_lte_rrc = -1;

#include "packet-lte-rrc-hf.c"

/* Initialize the subtree pointers */
static int ett_lte_rrc = -1;

#include "packet-lte-rrc-ett.c"

/* Global variables */
static proto_tree *top_tree;

/* Forward declarations */
static int dissect_DL_DCCH_Message_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_);
#include "packet-lte-rrc-fn.c"

/*--- proto_register_rrc -------------------------------------------*/
void proto_register_lte_rrc(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-lte-rrc-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_lte_rrc,
#include "packet-lte-rrc-ettarr.c"
  };


  /* Register protocol */
  proto_lte_rrc = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_lte_rrc, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register the dissectors defined in lte-rrc.conf */
#include "packet-lte-rrc-dis-reg.c"

}


/*--- proto_reg_handoff_rrc ---------------------------------------*/
void
proto_reg_handoff_lte_rrc(void)
{

	nas_eps_handle = find_dissector("nas-eps");
}


