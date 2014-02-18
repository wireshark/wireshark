/* packet-h450.c
 * Routines for h450 packet dissection
 * Based on the previous h450 dissector by:
 * 2003  Graeme Reid (graeme.reid@norwoodsystems.com)
 * Copyright 2005, Anders Broman <anders.broman@ericsson.com>
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
 *
 * Credit to Tomas Kukosa for developing the asn2wrs compiler.
 *
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>

#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-h225.h"

#include "packet-h450-ros.h"

#define PNAME  "H.450 Supplementary Services"
#define PSNAME "H.450"
#define PFNAME "h450"

void proto_register_h450(void);
void proto_reg_handoff_h450(void);


/* Initialize the protocol and registered fields */
static int proto_h450 = -1;
static int hf_h450_operation = -1;
static int hf_h450_error = -1;
#include "packet-h450-hf.c"

/* Initialize the subtree pointers */
#include "packet-h450-ett.c"

static const value_string h450_str_operation[] = {
#include "packet-h450-table10.c"
  {   0, NULL}
};

static const value_string h450_str_error[] = {
#include "packet-h450-table20.c"
  {   0, NULL}
};

/* ROSE context */
static rose_ctx_t h450_rose_ctx;

/* Global variables */

#include "packet-h450-fn.c"

typedef struct _h450_op_t {
  gint32 opcode;
  new_dissector_t arg_pdu;
  new_dissector_t res_pdu;
} h450_op_t;

static const h450_op_t h450_op_tab[] = {
#include "packet-h450-table11.c"
};

typedef struct _h450_err_t {
  gint32 errcode;
  new_dissector_t err_pdu;
} h450_err_t;

static const h450_err_t h450_err_tab[] = {
#include "packet-h450-table21.c"
};

static const h450_op_t *get_op(gint32 opcode) {
  int i;

  /* search from the end to get the last occurrence if the operation is redefined in some newer specification */
  for (i = array_length(h450_op_tab) - 1; i >= 0; i--)
    if (h450_op_tab[i].opcode == opcode)
      return &h450_op_tab[i];
  return NULL;
}

static const h450_err_t *get_err(gint32 errcode) {
  int i;

  /* search from the end to get the last occurrence if the operation is redefined in some newer specification */
  for (i = array_length(h450_err_tab) - 1; i >= 0; i--)
    if (h450_err_tab[i].errcode == errcode)
      return &h450_err_tab[i];
  return NULL;
}

/*--- dissect_h450_arg ------------------------------------------------------*/
static int
dissect_h450_arg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  proto_item *hidden_item;
  int offset = 0;
  rose_ctx_t *rctx;
  gint32 opcode;
  const h450_op_t *op_ptr;
  const gchar *p;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
  DISSECTOR_ASSERT(rctx);

  if (rctx->d.pdu != 1)  /* invoke */
    return offset;
  if (rctx->d.code != 0)  /* local */
    return offset;
  opcode = rctx->d.code_local;
  op_ptr = get_op(opcode);
  if (!op_ptr)
    return offset;

  hidden_item = proto_tree_add_uint(tree, hf_h450_operation, tvb, 0, 0, opcode);
  PROTO_ITEM_SET_HIDDEN(hidden_item);
  p = try_val_to_str(opcode, VALS(h450_str_operation));
  if (p) {
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (op_ptr->arg_pdu && (tvb_length_remaining(tvb, offset) > 0))
    offset = op_ptr->arg_pdu(tvb, pinfo, tree, NULL);
  else
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(tree, tvb, offset, -1, "UNSUPPORTED ARGUMENT TYPE (H.450)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_h450_res ------------------------------------------------------*/
static int
dissect_h450_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  proto_item *hidden_item;
  int offset = 0;
  rose_ctx_t *rctx;
  gint32 opcode;
  const h450_op_t *op_ptr;
  const gchar *p;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
  DISSECTOR_ASSERT(rctx);

  if (rctx->d.pdu != 2)  /* returnResult */
    return offset;
  if (rctx->d.code != 0)  /* local */
    return offset;
  opcode = rctx->d.code_local;
  op_ptr = get_op(opcode);
  if (!op_ptr)
    return offset;

  hidden_item = proto_tree_add_uint(tree, hf_h450_operation, tvb, 0, 0, opcode);
  PROTO_ITEM_SET_HIDDEN(hidden_item);
  p = try_val_to_str(opcode, VALS(h450_str_operation));
  if (p) {
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (op_ptr->res_pdu && (tvb_length_remaining(tvb, offset) > 0))
    offset = op_ptr->res_pdu(tvb, pinfo, tree, NULL);
  else
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(tree, tvb, offset, -1, "UNSUPPORTED RESULT TYPE (H.450)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_h450_err ------------------------------------------------------*/
static int
dissect_h450_err(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  proto_item *hidden_item;
  int offset = 0;
  rose_ctx_t *rctx;
  gint32 errcode;
  const h450_err_t *err_ptr;
  const gchar *p;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
  DISSECTOR_ASSERT(rctx);

  if (rctx->d.pdu != 3)  /* returnError */
    return offset;
  if (rctx->d.code != 0)  /* local */
    return offset;
  errcode = rctx->d.code_local;
  err_ptr = get_err(errcode);
  if (!err_ptr)
    return offset;

  hidden_item = proto_tree_add_uint(tree, hf_h450_error, tvb, 0, 0, errcode);
  PROTO_ITEM_SET_HIDDEN(hidden_item);
  p = try_val_to_str(errcode, VALS(h450_str_error));
  if (p) {
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (err_ptr->err_pdu && (tvb_length_remaining(tvb, offset) > 0))
    offset = err_ptr->err_pdu(tvb, pinfo, tree, NULL);
  else
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(tree, tvb, offset, -1, "UNSUPPORTED ERROR TYPE (H.450)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- proto_register_h450 -------------------------------------------*/
void proto_register_h450(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_h450_operation, { "Operation", "h450.operation",
                           FT_UINT8, BASE_DEC, VALS(h450_str_operation), 0x0,
                           NULL, HFILL }},
    { &hf_h450_error,     { "Error", "h450.error",
                           FT_UINT8, BASE_DEC, VALS(h450_str_error), 0x0,
                           NULL, HFILL }},
#include "packet-h450-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-h450-ettarr.c"
  };


  /* Register protocol */
  proto_h450 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  new_register_dissector("h4501", dissect_h450_H4501SupplementaryService_PDU, proto_h450);
  /* Register fields and subtrees */
  proto_register_field_array(proto_h450, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  rose_ctx_init(&h450_rose_ctx);

  /* Register dissector tables */
  h450_rose_ctx.arg_global_dissector_table = register_dissector_table("h450.ros.global.arg", "H.450 Operation Argument (global opcode)", FT_STRING, BASE_NONE);
  h450_rose_ctx.res_global_dissector_table = register_dissector_table("h450.ros.global.res", "H.450 Operation Result (global opcode)", FT_STRING, BASE_NONE);
  h450_rose_ctx.arg_local_dissector_table = register_dissector_table("h450.ros.local.arg", "H.450 Operation Argument (local opcode)", FT_UINT32, BASE_HEX);
  h450_rose_ctx.res_local_dissector_table = register_dissector_table("h450.ros.local.res", "H.450 Operation Result (local opcode)", FT_UINT32, BASE_HEX);
  h450_rose_ctx.err_global_dissector_table = register_dissector_table("h450.ros.global.err", "H.450 Error (global opcode)", FT_STRING, BASE_NONE);
  h450_rose_ctx.err_local_dissector_table = register_dissector_table("h450.ros.local.err", "H.450 Error (local opcode)", FT_UINT32, BASE_HEX);

}


/*--- proto_reg_handoff_h450 ---------------------------------------*/
void
proto_reg_handoff_h450(void)
{
  int i;
  dissector_handle_t h450_arg_handle;
  dissector_handle_t h450_res_handle;
  dissector_handle_t h450_err_handle;

  h450_arg_handle = new_create_dissector_handle(dissect_h450_arg, proto_h450);
  h450_res_handle = new_create_dissector_handle(dissect_h450_res, proto_h450);
  for (i=0; i<(int)array_length(h450_op_tab); i++) {
    dissector_add_uint("h450.ros.local.arg", h450_op_tab[i].opcode, h450_arg_handle);
    dissector_add_uint("h450.ros.local.res", h450_op_tab[i].opcode, h450_res_handle);
  }
  h450_err_handle = new_create_dissector_handle(dissect_h450_err, proto_h450);
  for (i=0; i<(int)array_length(h450_err_tab); i++) {
    dissector_add_uint("h450.ros.local.err", h450_err_tab[i].errcode, h450_err_handle);
  }

}
