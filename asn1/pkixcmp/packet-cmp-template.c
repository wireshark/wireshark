/* packet-cmp.c
 * Routines for RFC2510 Certificate Management Protocol packet dissection
 *   Ronnie Sahlberg 2004
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
#include "packet-cmp.h"
#include "packet-crmf.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"

#define PNAME  "Certificate Management Protocol"
#define PSNAME "CMP"
#define PFNAME "cmp"

/* Initialize the protocol and registered fields */
int proto_cmp = -1;
static int hf_cmp_type_oid = -1;
#include "packet-cmp-hf.c"

/* Initialize the subtree pointers */
static gint ett_cmp = -1;
#include "packet-cmp-ett.c"

static char object_identifier_id[BER_MAX_OID_STR_LEN];


#include "packet-cmp-fn.c"

static int
dissect_cmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	proto_item *item=NULL;
	proto_tree *tree=NULL;

	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "CMP");

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_clear(pinfo->cinfo, COL_INFO);
		
		col_add_fstr(pinfo->cinfo, COL_INFO, "PKIXCMP");
	}


	if(parent_tree){
		item=proto_tree_add_item(parent_tree, proto_cmp, tvb, 0, -1, FALSE);
		tree = proto_item_add_subtree(item, ett_cmp);
	}

	return dissect_cmp_PKIMessage(FALSE, tvb, 0, pinfo, tree, -1);
}

/*--- proto_register_cmp ----------------------------------------------*/
void proto_register_cmp(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cmp_type_oid,
      { "InfoType", "cmp.type.oid",
        FT_STRING, BASE_NONE, NULL, 0,
        "Type of InfoTypeAndValue", HFILL }},
#include "packet-cmp-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_cmp,
#include "packet-cmp-ettarr.c"
  };

  /* Register protocol */
  proto_cmp = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cmp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_cmp -------------------------------------------*/
void proto_reg_handoff_cmp(void) {
	dissector_handle_t cmp_handle;

	cmp_handle = new_create_dissector_handle(dissect_cmp, proto_cmp);
	dissector_add_string("media_type", "application/pkixcmp", cmp_handle);

/*#include "packet-cmp-dis-tab.c"*/
}

