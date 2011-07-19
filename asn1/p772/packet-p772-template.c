/* packet-p772.c
 * Routines for STANAG 4406 (X.400 Military Message Extensions)  packet dissection
 * Graeme Lunt 2005
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
#include <epan/asn1.h>

#include "packet-ber.h"

#include "packet-x509if.h"

#include "packet-p772.h"
#include "packet-p1.h" 
#include "packet-p22.h" 

#define PNAME  "STANAG 4406 Message"
#define PSNAME "P772"
#define PFNAME "p772"

/* Initialize the protocol and registered fields */
static int proto_p772 = -1;

#include "packet-p772-val.h"

#include "packet-p772-hf.c"

/* Initialize the subtree pointers */
static gint ett_p772 = -1;
#include "packet-p772-ett.c"

#include "packet-p772-fn.c"


/*
* Dissect STANAG 4406 PDUs inside a PPDU.
*/
static void
dissect_p772(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
	int offset = 0;
	proto_item *item=NULL;
	proto_tree *tree=NULL;
	asn1_ctx_t asn1_ctx;
	asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

	if(parent_tree){
		item = proto_tree_add_item(parent_tree, proto_p772, tvb, 0, -1, ENC_BIG_ENDIAN);
		tree = proto_item_add_subtree(item, ett_p772);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "P772");
	col_set_str(pinfo->cinfo, COL_INFO, "Military");

	dissect_p772_InformationObject(TRUE, tvb, offset, &asn1_ctx , tree, -1);
}



/*--- proto_register_p772 -------------------------------------------*/
void proto_register_p772(void) {

  /* List of fields */
  static hf_register_info hf[] =
  {
#include "packet-p772-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_p772,
#include "packet-p772-ettarr.c"
  };

  /* Register protocol */
  proto_p772 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_p772, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_ber_syntax_dissector("STANAG 4406", proto_p772, dissect_p772); 
  register_ber_oid_syntax(".p772", NULL, "STANAG 4406");
}


/*--- proto_reg_handoff_p772 --- */
void proto_reg_handoff_p772(void) {
#include "packet-p772-dis-tab.c"

  register_ber_oid_dissector("1.3.26.0.4406.0.4.1", dissect_p772, proto_p772, "STANAG 4406");
}
