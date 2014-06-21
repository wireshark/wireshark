/* packet-isdn-sup-template.c
 * Routines for ETSI Integrated Services Digital Network (ISDN)
 * supplementary services
 * Copyright 2013, Anders Broman <anders.broman@ericsson.com>
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

void proto_register_isdn_sup(void);
void proto_reg_handoff_isdn_sup(void);

#include "packet-isdn-sup-val.h"

/* Initialize the protocol and registered fields */
static int proto_isdn_sup = -1;
static int hf_isdn_sup_operation = -1;
static int hf_isdn_sup_error = -1;

/* Global variables */

#if 0
/* ROSE context */
static rose_ctx_t isdn_sup_rose_ctx;
#endif

typedef struct _isdn_sup_op_t {
  gint32 opcode;
  new_dissector_t arg_pdu;
  new_dissector_t res_pdu;
} isdn_sup_op_t;

typedef struct _isdn_global_sup_op_t {
  const char*  oid;
  new_dissector_t arg_pdu;
  new_dissector_t res_pdu;
} isdn_sup_global_op_t;


typedef struct isdn_sup_err_t {
  gint32 errcode;
  new_dissector_t err_pdu;
} isdn_sup_err_t;

static const value_string isdn_sup_str_operation[] = {
#include "packet-isdn-sup-table10.c"
  {   0, NULL}
};


static const value_string isdn_sup_str_error[] = {
#include "packet-isdn-sup-table20.c"
  {   0, NULL}
};

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


static const isdn_sup_global_op_t isdn_sup_global_op_tab[] = {

#include "packet-isdn-sup-table31.c"
};

static const isdn_sup_err_t isdn_sup_err_tab[] = {
#include "packet-isdn-sup-table21.c"
};


static const isdn_sup_op_t *get_op(gint32 opcode) {
  int i;

  /* search from the end to get the last occurrence if the operation is redefined in some newer specification */
  for (i = array_length(isdn_sup_op_tab) - 1; i >= 0; i--)
    if (isdn_sup_op_tab[i].opcode == opcode)
      return &isdn_sup_op_tab[i];
  return NULL;
}

static const isdn_sup_err_t *get_err(gint32 errcode) {
  int i;

  /* search from the end to get the last occurrence if the operation is redefined in some newer specification */
  for (i = array_length(isdn_sup_err_tab) - 1; i >= 0; i--)
    if (isdn_sup_err_tab[i].errcode == errcode)
      return &isdn_sup_err_tab[i];
  return NULL;
}

/*--- dissect_isdn_sup_arg ------------------------------------------------------*/
static int
dissect_isdn_sup_arg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  int offset = 0;
  rose_ctx_t *rctx;
  gint32 opcode = 0;
  const gchar *p;
  const isdn_sup_op_t *op_ptr;
  proto_item *ti;
  proto_tree *isdn_sup_tree;

  /* Reject the packet if data is NULL */
  if (data == NULL)
    return 0;
  rctx = get_rose_ctx(data);
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

  ti = proto_tree_add_item(tree, proto_isdn_sup, tvb, offset, -1, ENC_NA);
  isdn_sup_tree = proto_item_add_subtree(ti, ett_isdn_sup);

  proto_tree_add_uint(isdn_sup_tree, hf_isdn_sup_operation, tvb, 0, 0, opcode);
  p = try_val_to_str(opcode, VALS(isdn_sup_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (op_ptr->arg_pdu)
    offset = op_ptr->arg_pdu(tvb, pinfo, isdn_sup_tree, NULL);
  else
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(isdn_sup_tree, tvb, offset, -1, "UNSUPPORTED ARGUMENT TYPE (ETSI Sup)");
      offset += tvb_reported_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_isdn_sup_res -------------------------------------------------------*/
static int
dissect_isdn_sup_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  gint offset = 0;
  rose_ctx_t *rctx;
  gint32 opcode = 0;
  const gchar *p;
  const isdn_sup_op_t *op_ptr;
  proto_item *ti;
  proto_tree *isdn_sup_tree;

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

  ti = proto_tree_add_item(tree, proto_isdn_sup, tvb, offset, -1, ENC_NA);
  isdn_sup_tree = proto_item_add_subtree(ti, ett_isdn_sup);

  proto_tree_add_uint(isdn_sup_tree, hf_isdn_sup_operation, tvb, 0, 0, opcode);
  p = try_val_to_str(opcode, VALS(isdn_sup_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (op_ptr->res_pdu)
    offset = op_ptr->res_pdu(tvb, pinfo, isdn_sup_tree, NULL);
  else
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(isdn_sup_tree, tvb, offset, -1, "UNSUPPORTED RESULT TYPE (ETSI sup)");
      offset += tvb_reported_length_remaining(tvb, offset);
    }

  return offset;
}


/*--- dissect_isdn_sup_err ------------------------------------------------------*/
static int
dissect_isdn_sup_err(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  int offset = 0;
  rose_ctx_t *rctx;
  gint32 errcode;
  const isdn_sup_err_t *err_ptr;
  const gchar *p;
  proto_item *ti;
  proto_tree *isdn_sup_tree;

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

  ti = proto_tree_add_item(tree, proto_isdn_sup, tvb, offset, -1, ENC_NA);
  isdn_sup_tree = proto_item_add_subtree(ti, ett_isdn_sup);

  proto_tree_add_uint(isdn_sup_tree, hf_isdn_sup_error, tvb, 0, 0, errcode);
  p = try_val_to_str(errcode, VALS(isdn_sup_str_error));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (err_ptr->err_pdu)
    offset = err_ptr->err_pdu(tvb, pinfo, isdn_sup_tree, NULL);
  else
    if (tvb_reported_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(isdn_sup_tree, tvb, offset, -1, "UNSUPPORTED ERROR TYPE (ETSI sup)");
      offset += tvb_reported_length_remaining(tvb, offset);
    }

  return offset;
}


/*--- proto_reg_handoff_isdn_sup ---------------------------------------*/

void proto_reg_handoff_isdn_sup(void) {
  int i;
#if 0
  dissector_handle_t q931_handle;
#endif
  dissector_handle_t isdn_sup_arg_handle;
  dissector_handle_t isdn_sup_res_handle;
  dissector_handle_t isdn_sup_err_handle;

#if 0
  q931_handle = find_dissector("q931");
#endif

  isdn_sup_arg_handle = new_create_dissector_handle(dissect_isdn_sup_arg, proto_isdn_sup);
  isdn_sup_res_handle = new_create_dissector_handle(dissect_isdn_sup_res, proto_isdn_sup);
  for (i=0; i<(int)array_length(isdn_sup_op_tab); i++) {
    dissector_add_uint("q932.ros.etsi.local.arg", isdn_sup_op_tab[i].opcode, isdn_sup_arg_handle);
    dissector_add_uint("q932.ros.etsi.local.res", isdn_sup_op_tab[i].opcode, isdn_sup_res_handle);
  }

  for (i=0; i<(int)array_length(isdn_sup_global_op_tab); i++) {
	  if(isdn_sup_global_op_tab->arg_pdu)
		  dissector_add_string("q932.ros.global.arg", isdn_sup_global_op_tab[i].oid, new_create_dissector_handle(isdn_sup_global_op_tab[i].arg_pdu, proto_isdn_sup));
	  if(isdn_sup_global_op_tab->res_pdu)
		  dissector_add_string("q932.ros.global.res", isdn_sup_global_op_tab[i].oid, new_create_dissector_handle(isdn_sup_global_op_tab[i].res_pdu, proto_isdn_sup));
  }

  isdn_sup_err_handle = new_create_dissector_handle(dissect_isdn_sup_err, proto_isdn_sup);

  for (i=0; i<(int)array_length(isdn_sup_err_tab); i++) {
    dissector_add_uint("q932.ros.etsi.local.err", isdn_sup_err_tab[i].errcode, isdn_sup_err_handle);
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
    { &hf_isdn_sup_error,
	  { "Error", "isdn_sup.error",
        FT_UINT8, BASE_DEC, VALS(isdn_sup_str_error), 0x0,
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
