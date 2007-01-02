/* packet-umts_rrc_internode_defs.c
 * Routines for Universal Mobile Telecommunications System (UMTS);
 * Radio Resource Control (RRC) protocol specification
 * (3GPP TS 25.331 version 6.7.0 Release 6) Chapter 11.5 Internode-definitions dissection
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.com>
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
 * Ref: 3GPP TS 25.423 version 6.7.0 Release 6
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
#include "packet-per.h"
#include "packet-umts_rrc_internode_defs.h"
#include "packet-umts_rrc_ies.h"
#include "packet-umts_rrc_pdu_def.h"

#define PNAME  "Universal Mobile Telecommunications System (UMTS) Radio Resource Control (RRC) Internode-definitions"
#define PSNAME "UMTS_RRC_INTERNODE_DEFS"
#define PFNAME "umts_rrc_internode_defs"

static dissector_handle_t umts_rrc_internode_defs_handle=NULL;

/* Include constants */
/*#include "packet-umts_rrc_internode_defs-val.h"*/

/* Initialize the protocol and registered fields */
static int proto_umts_rrc_internode_defs = -1;


#include "packet-umts_rrc_internode_defs-hf.c"

/* Initialize the subtree pointers */
static int ett_umts_rrc_internode_defs = -1;

#include "packet-umts_rrc_internode_defs-ett.c"

/* Global variables */
static proto_tree *top_tree;

#include "packet-umts_rrc_internode_defs-fn.c"


static void
dissect_umts_rrc_internode_defs(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* FIX ME Currently don't know the 'starting point' of this protocol
	 * exported DL-DCCH-Message is the entry point.
	 */
	proto_item	*umts_rrc_internode_defs_item = NULL;
	proto_tree	*umts_rrc_internode_defs_tree = NULL;
	int			offset = 0;

	top_tree = tree;

	/* make entry in the Protocol column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "UMTS_RRC_INTERENODE_DEFS");

    /* create the umts_rrc_internode_defs protocol tree */
    umts_rrc_internode_defs_item = proto_tree_add_item(tree, proto_umts_rrc_internode_defs, tvb, 0, -1, FALSE);
    umts_rrc_internode_defs_tree = proto_item_add_subtree(umts_rrc_internode_defs_item, ett_umts_rrc_internode_defs);

}
/*--- proto_register_umts_rrc_internode_defs -------------------------------------------*/
void proto_register_umts_rrc_internode_defs(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-umts_rrc_internode_defs-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_umts_rrc_internode_defs,
#include "packet-umts_rrc_internode_defs-ettarr.c"
  };


  /* Register protocol */
  proto_umts_rrc_internode_defs = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_umts_rrc_internode_defs, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

 
  register_dissector("umts_rrc_internode_defs", dissect_umts_rrc_internode_defs, proto_umts_rrc_internode_defs);


}


/*--- proto_reg_handoff_umts_rrc_internode_defs ---------------------------------------*/
void
proto_reg_handoff_umts_rrc_internode_defs(void)
{

	umts_rrc_internode_defs_handle = find_dissector("umts_rrc_internode_defs");

}


