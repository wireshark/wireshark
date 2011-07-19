/* packet-cdt.c
 *
 * Routines for Compressed Data Type packet dissection.
 *
 * Copyright 2005, Stig Bjorlykke <stig@bjorlykke.org>, Thales Norway AS
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
 * Ref: STANAG 4406 Annex E
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/expert.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-p1.h"

#include "packet-cdt.h"

#define CDT_UNDEFINED  0
#define CDT_EXTERNAL   1
#define CDT_P1         2
#define CDT_P3         3
#define CDT_P7         4

#define PNAME  "Compressed Data Type"
#define PSNAME "CDT"
#define PFNAME "cdt"

static proto_tree *top_tree = NULL;
static proto_item *cdt_item = NULL;

static guint32 content_type = 0;

/* Initialize the protocol and registered fields */
static int proto_cdt = -1;
#include "packet-cdt-hf.c"

static dissector_handle_t data_handle = NULL;

/* Initialize the subtree pointers */
#include "packet-cdt-ett.c"

#include "packet-cdt-fn.c"


/*--- proto_register_cdt -------------------------------------------*/

/*
** Dissect Compressed Data Type
*/
void dissect_cdt (tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  proto_tree *tree = NULL;

  /* save parent_tree so subdissectors can create new top nodes */
  top_tree = parent_tree;

  if (parent_tree) {
    cdt_item = proto_tree_add_item (parent_tree, proto_cdt, tvb, 0, -1, ENC_BIG_ENDIAN);
    tree = proto_item_add_subtree (cdt_item, ett_cdt_CompressedData);
  }

  col_set_str (pinfo->cinfo, COL_PROTOCOL, "CDT");
  col_clear (pinfo->cinfo, COL_INFO);

  dissect_CompressedData_PDU (tvb, pinfo, tree);
}

void proto_register_cdt (void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-cdt-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-cdt-ettarr.c"
  };

  /* Register protocol */
  proto_cdt = proto_register_protocol (PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array (proto_cdt, hf, array_length(hf));
  proto_register_subtree_array (ett, array_length(ett));

}


/*--- proto_reg_handoff_cdt ---------------------------------------*/
void proto_reg_handoff_cdt (void) {
#include "packet-cdt-dis-tab.c"

  data_handle = find_dissector ("data");
}
