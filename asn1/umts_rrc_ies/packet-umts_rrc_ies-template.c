/* packet-umts_rrc_ies.c
 * Routines for Universal Mobile Telecommunications System (UMTS);
 * Radio Resource Control (RRC) protocol specification 	
 * (3GPP TS 25.331 version 6.7.0 Release 6) chapter 11.3 Information element dissection
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
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
#include "packet-umts_rrc_ies.h"

#define PNAME  "Universal Mobile Telecommunications System (UMTS) Radio Resource Control (RRC) protocol Information element"
#define PSNAME "UMTS_RRC_IES"
#define PFNAME "umts_rrc_ies"

static dissector_handle_t umts_rrc_ies_handle=NULL;

/* Include constants */
#include "packet-umts_rrc_ies-val.h"

/* Initialize the protocol and registered fields */
static int proto_umts_rrc_ies = -1;


#include "packet-umts_rrc_ies-hf.c"

/* Initialize the subtree pointers */
static int ett_umts_rrc_ies = -1;

#include "packet-umts_rrc_ies-ett.c"

#include "packet-umts_rrc_ies-fn.c"


static void
dissect_umts_rrc_ies(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* 
	 * Dummy function, currently not used
	 */

}
/*--- proto_register_umts_rrc_ies -------------------------------------------*/
void proto_register_umts_rrc_ies(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-umts_rrc_ies-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
		  &ett_umts_rrc_ies,
#include "packet-umts_rrc_ies-ettarr.c"
  };


  /* Register protocol */
  proto_umts_rrc_ies = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_umts_rrc_ies, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

 
  register_dissector("umts_rrc_ies", dissect_umts_rrc_ies, proto_umts_rrc_ies);


}


/*--- proto_reg_handoff_umts_rrc_ies ---------------------------------------*/
void
proto_reg_handoff_umts_rrc_ies(void)
{

	umts_rrc_ies_handle = find_dissector("umts_rrc_ies");

}


