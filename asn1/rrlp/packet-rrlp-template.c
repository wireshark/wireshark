/* packet-rrlp.c
 * Routines for 3GPP Radio Resource LCS Protocol (RRLP) packet dissection
 * Copyright 2006, Anders Broman <anders.broman@ericsson.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Ref 3GPP TS 44.031 version 6.8.0 Release 6
 * http://www.3gpp.org
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-rrlp.h"

#include "packet-ber.h"
#include "packet-per.h"
#include "packet-gsm_map.h"

#define PNAME  "Radio Resource LCS Protocol (RRLP)"
#define PSNAME "RRLP"
#define PFNAME "rrlp"

static dissector_handle_t rrlp_handle=NULL;


/* Initialize the protocol and registered fields */
static int proto_rrlp = -1;


#include "packet-rrlp-hf.c"

/* Initialize the subtree pointers */
static gint ett_rrlp = -1;
#include "packet-rrlp-ett.c"

/* Include constants */
#include "packet-rrlp-val.h"

/* If trying to use module import the "dissect_gsm_map_ExtensionContainer" will be wrongly constructed
 * presumably because it assumes it will be PER encoded
 */
static int
dissect_MAP_ExtensionDataTypes_ExtensionContainer(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index){

	return dissect_gsm_map_ExtensionContainer(TRUE, tvb, offset, pinfo, tree, hf_index);
}

static int
dissect_MAP_LCS_DataTypes_Ext_GeographicalInformation(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index){

	return dissect_gsm_map_Ext_GeographicalInformation(TRUE, tvb, offset, pinfo, tree, hf_index);
}

#include "packet-rrlp-fn.c"


/*--- proto_register_rrlp -------------------------------------------*/
void proto_register_rrlp(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-rrlp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_rrlp,
#include "packet-rrlp-ettarr.c"
  };


  /* Register protocol */
  proto_rrlp = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("rrlp", dissect_PDU_PDU, proto_rrlp);

  /* Register fields and subtrees */
  proto_register_field_array(proto_rrlp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

 
}


/*--- proto_reg_handoff_rrlp ---------------------------------------*/
void
proto_reg_handoff_rrlp(void)
{

	rrlp_handle = create_dissector_handle(dissect_PDU_PDU, proto_rrlp);


}


