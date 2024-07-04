/* packet-h323.c
 * Routines for H.323 packet dissection
 * 2007  Tomas Kukosa
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-h225.h"
#include "packet-h323.h"

#define PNAME  "H.323"
#define PSNAME "H.323"
#define PFNAME "h323"

void proto_register_h323(void);
void proto_reg_handoff_h323(void);

/* Generic Extensible Framework */
gef_ctx_t* gef_ctx_alloc(wmem_allocator_t *pool, gef_ctx_t *parent, const char *type) {
  gef_ctx_t *gefx;

  gefx = wmem_new0(pool, gef_ctx_t);
  gefx->signature = GEF_CTX_SIGNATURE;
  gefx->parent = parent;
  gefx->type = type;
  return gefx;
}

bool gef_ctx_check_signature(gef_ctx_t *gefx) {
  return gefx && (gefx->signature == GEF_CTX_SIGNATURE);
}

gef_ctx_t* gef_ctx_get(void *ptr) {
  gef_ctx_t *gefx = (gef_ctx_t*)ptr;
  asn1_ctx_t *actx = (asn1_ctx_t*)ptr;

  if (!asn1_ctx_check_signature(actx))
    actx = NULL;

  if (actx)
    gefx = (gef_ctx_t *)actx->private_data;

  if (!gef_ctx_check_signature(gefx))
    gefx = NULL;

  return gefx;
}

void gef_ctx_update_key(wmem_allocator_t *pool, gef_ctx_t *gefx) {
  const char *parent_key;

  if (!gefx) return;
  parent_key = (gefx->parent) ? gefx->parent->key : NULL;
  gefx->key = wmem_strdup_printf(pool,
    "%s%s"    /* parent prefix */
    "%s%s%s"  /* type, id */
    "%s%s"    /* subid */,
    (parent_key) ? parent_key : "", (parent_key) ? "/" : "",
    (gefx->type) ? gefx->type : "", (gefx->type && (gefx->id || gefx->subid)) ? "/" : "", (gefx->id) ? gefx->id : "",
    (gefx->subid) ? "-" : "", (gefx->subid) ? gefx->subid : ""
  );
}

/* Initialize the protocol and registered fields */
static int proto_h323;
#include "packet-h323-hf.c"

/* Initialize the subtree pointers */
#include "packet-h323-ett.c"

#include "packet-h323-fn.c"

/*--- proto_register_h323 ----------------------------------------------*/
void proto_register_h323(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-h323-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-h323-ettarr.c"
  };

  /* Register protocol */
  proto_h323 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h323, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_h323 -------------------------------------------*/
void proto_reg_handoff_h323(void)
{
  dissector_handle_t q931_handle;

  q931_handle = find_dissector("q931");

  /* H.323, Annex M1, Tunnelling of signalling protocols (QSIG) in H.323 */
  dissector_add_string("h225.tp", "1.3.12.9", q931_handle);

  /* H.323, Annex M4, Tunnelling of narrow-band signalling syntax (NSS) for H.323 */
  dissector_add_string("h225.gef.content", "GenericData/1000/1",
                       create_dissector_handle(dissect_RasTunnelledSignallingMessage_PDU, proto_h323));

  /* H.323, Annex R, Robustness methods for H.323 entities */
  dissector_add_string("h225.gef.content", "GenericData/1/1",
                       create_dissector_handle(dissect_RobustnessData_PDU, proto_h323));
}

