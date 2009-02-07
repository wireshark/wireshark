/* packet-t125.c
 * Routines for t125 packet dissection
 * Copyright 2007, Ronnie Sahlberg
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

#include <stdio.h>
#include <string.h>

#include <epan/asn1.h>
#include "packet-ber.h"

#define PNAME  "MULTIPOINT-COMMUNICATION-SERVICE T.125"
#define PSNAME "T.125"
#define PFNAME "t125"


/* Initialize the protocol and registered fields */
int proto_t125 = -1;
#include "packet-t125-hf.c"

/* Initialize the subtree pointers */
static int ett_t125 = -1;
#include "packet-t125-ett.c"

#include "packet-t125-fn.c"

static int
dissect_t125(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *parent_tree)
{
  proto_item *item = NULL;
  proto_tree *tree = NULL;
  gint8 class;
  gboolean pc;
  gint32 tag;

  if (check_col(pinfo->cinfo, COL_PROTOCOL)){
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "T.125");
  }
  if (check_col(pinfo->cinfo, COL_INFO)){
    col_clear(pinfo->cinfo, COL_INFO);
  }

  item = proto_tree_add_item(parent_tree, proto_t125, tvb, 0, tvb_length(tvb), FALSE);
  tree = proto_item_add_subtree(item, ett_t125);

  get_ber_identifier(tvb, 0, &class, &pc, &tag);

  if ( (class==BER_CLASS_APP) && (tag>=101) && (tag<=104) ){
    dissect_ConnectMCSPDU_PDU(tvb, pinfo, tree);
  } else {
    if (check_col(pinfo->cinfo, COL_INFO)){
      col_set_str(pinfo->cinfo, COL_INFO, "T.125 payload");
    }
    proto_tree_add_text(tree, tvb, 0, -1, "T.125 payload");
  }

  return tvb_length(tvb);
}


/*--- proto_register_t125 -------------------------------------------*/
void proto_register_t125(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-t125-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
	  &ett_t125,
#include "packet-t125-ettarr.c"
  };

  /* Register protocol */
  proto_t125 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  /* Register fields and subtrees */
  proto_register_field_array(proto_t125, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  new_register_dissector("t125", dissect_t125, proto_t125);
}


/*--- proto_reg_handoff_t125 ---------------------------------------*/
void proto_reg_handoff_t125(void) {
}
