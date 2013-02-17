/* packet-isdn-sup-template.c
 * Routines for ETSI Integrated Services Digital Network (ISDN) 
 * supplementary services
 * Copyright 2013, Anders Broman <anders.broman@ericsson.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 * References: ETSI 300 374
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>


#include "packet-ber.h"

#define PNAME  "ISDN supplementary services"
#define PSNAME "ISDN_SUP"
#define PFNAME "isdn_sup"

/* Initialize the protocol and registered fields */
static int proto_isdn_sup = -1;
static int hf_isdn_sup_operation = -1;

/* Global variables */

/* ROSE context */
static rose_ctx_t isdn_sup_rose_ctx;

typedef struct _isdn_sup_op_t {
  gint32 opcode;
  new_dissector_t arg_pdu;
  new_dissector_t res_pdu;
} isdn_sup_op_t;

static const value_string isdn_sup_str_operation[] = {
#include "packet-isdn-sup-table10.c"
  {   0, NULL}
};

#if 0
static const value_string isdn_sup_str_error[] = {
#include "packet-isdn-sup-table20.c"
  {   0, NULL}
};
#endif
static int hf_isdn_sup = -1;

#include "packet-isdn-sup-hf.c"


/* Initialize the subtree pointers */
static gint ett_isdn_sup = -1;

#include "packet-isdn-sup-ett.c"


/* Preference settings default */

/* Global variables */

#include "packet-isdn-sup-fn.c"

static const isdn_sup_op_t isdn_sup_op_tab[] = {
#include "packet-isdn-sup-table11.c"
};

#if 0
static const isdn_sup_err_t isdn_sup_err_tab[] = {
#include "packet-isdn-sup-table21.c"
};
#endif

static const isdn_sup_op_t *get_op(gint32 opcode) {
  int i;

  /* search from the end to get the last occurence if the operation is redefined in some newer specification */
  for (i = array_length(isdn_sup_op_tab) - 1; i >= 0; i--)
    if (isdn_sup_op_tab[i].opcode == opcode)
      return &isdn_sup_op_tab[i];
  return NULL;
}

/*--- dissect_isdn_sup_arg ------------------------------------------------------*/
static int
dissect_isdn_sup_arg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  int offset;
  rose_ctx_t *rctx;
  gint32 opcode = 0;
  const gchar *p;
  const isdn_sup_op_t *op_ptr;
  proto_item *ti;
  proto_tree *isdn_sup_tree;

  offset = 0;
  rctx = get_rose_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(rctx);
  if (rctx->d.pdu != 1)  /* invoke */
    return offset;
  if (rctx->d.code == 0) {  /* local */
    opcode = rctx->d.code_local;
  } else {
    return offset;
  }
  op_ptr = get_op(opcode);
  if (!op_ptr)
    return offset;

  ti = proto_tree_add_item(tree, proto_isdn_sup, tvb, offset, tvb_length(tvb), ENC_NA);
  isdn_sup_tree = proto_item_add_subtree(ti, ett_isdn_sup);

  proto_tree_add_uint(isdn_sup_tree, hf_isdn_sup_operation, tvb, 0, 0, opcode);
  p = match_strval(opcode, VALS(isdn_sup_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (op_ptr->arg_pdu)
    offset = op_ptr->arg_pdu(tvb, pinfo, isdn_sup_tree, NULL);
  else
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(isdn_sup_tree, tvb, offset, -1, "UNSUPPORTED ARGUMENT TYPE (ETSI Sup)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_isdn_sup_res -------------------------------------------------------*/
static int
dissect_isdn_sup_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  gint offset;
  rose_ctx_t *rctx;
  gint32 opcode = 0;
  const gchar *p;
  const isdn_sup_op_t *op_ptr;
  proto_item *ti;
  proto_tree *isdn_sup_tree;

  offset = 0;
  rctx = get_rose_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(rctx);
  if (rctx->d.pdu != 2)  /* returnResult */
    return offset;
  if (rctx->d.code != 0)  /* local */
    return offset;
  opcode = rctx->d.code_local;
  op_ptr = get_op(opcode);
  if (!op_ptr)
    return offset;

  ti = proto_tree_add_item(tree, proto_isdn_sup, tvb, offset, tvb_length(tvb), ENC_NA);
  isdn_sup_tree = proto_item_add_subtree(ti, ett_isdn_sup);

  proto_tree_add_uint(isdn_sup_tree, hf_isdn_sup_operation, tvb, 0, 0, opcode);
  p = match_strval(opcode, VALS(isdn_sup_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (op_ptr->res_pdu)
    offset = op_ptr->res_pdu(tvb, pinfo, isdn_sup_tree, NULL);
  else
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(isdn_sup_tree, tvb, offset, -1, "UNSUPPORTED RESULT TYPE (ETSI sup)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}




/*--- proto_reg_handoff_isdn_sup ---------------------------------------*/

void proto_reg_handoff_isdn_sup(void) {
  int i;
  dissector_handle_t q931_handle;
  dissector_handle_t isdn_sup_arg_handle;
  dissector_handle_t isdn_sup_res_handle;

  q931_handle = find_dissector("q931");

  isdn_sup_arg_handle = new_create_dissector_handle(dissect_isdn_sup_arg, proto_isdn_sup);
  isdn_sup_res_handle = new_create_dissector_handle(dissect_isdn_sup_res, proto_isdn_sup);
  for (i=0; i<(int)array_length(isdn_sup_op_tab); i++) {
    dissector_add_uint("q932.ros.etsi.local.arg", isdn_sup_op_tab[i].opcode, isdn_sup_arg_handle);
    dissector_add_uint("q932.ros.etsi.local.res", isdn_sup_op_tab[i].opcode, isdn_sup_res_handle);
  }

}

void proto_register_isdn_sup(void) {

	/* List of fields */
  static hf_register_info hf[] = {
    { &hf_isdn_sup,
      { "isdn_sup", "isdn_sup.1",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
	},
    { &hf_isdn_sup_operation, 
	  { "Operation", "isdn_sup.operation",
        FT_UINT8, BASE_DEC, VALS(isdn_sup_str_operation), 0x0,
        NULL, HFILL }
	},
#include "packet-isdn-sup-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_isdn_sup,

#include "packet-isdn-sup-ettarr.c"
  };

  /* Register fields and subtrees */
  proto_register_field_array(proto_isdn_sup, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register protocol */
  proto_isdn_sup = proto_register_protocol(PNAME, PSNAME, PFNAME);

}
