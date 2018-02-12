/* packet-h283.c
 * Routines for H.283 packet dissection
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

#define PNAME  "H.283 Logical Channel Transport"
#define PSNAME "LCT"
#define PFNAME "lct"

void proto_register_h283(void);
void proto_reg_handoff_h283(void);

/* Initialize the protocol and registered fields */
static int proto_h283 = -1;
#include "packet-h283-hf.c"

/* Initialize the subtree pointers */
static int ett_h283 = -1;
#include "packet-h283-ett.c"

/* Subdissectors */
static dissector_handle_t rdc_pdu_handle;
static dissector_handle_t rdc_device_list_handle;
static dissector_handle_t data_handle;
static dissector_handle_t h283_udp_handle;


static gboolean info_is_set;

#include "packet-h283-fn.c"

static int
dissect_h283_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item  *ti = NULL;
  proto_tree  *h283_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  info_is_set = FALSE;

  ti = proto_tree_add_item(tree, proto_h283, tvb, 0, -1, ENC_NA);
  h283_tree = proto_item_add_subtree(ti, ett_h283);

  return dissect_LCTPDU_PDU(tvb, pinfo, h283_tree, NULL);
}

/*--- proto_register_h283 ----------------------------------------------*/
void proto_register_h283(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-h283-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_h283,
#include "packet-h283-ettarr.c"
  };

  /* Register protocol */
  proto_h283 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h283, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  h283_udp_handle = register_dissector(PFNAME, dissect_h283_udp, proto_h283);

}

/*--- proto_reg_handoff_h283 -------------------------------------------*/
void proto_reg_handoff_h283(void)
{
  dissector_add_for_decode_as_with_preference("udp.port", h283_udp_handle);

  rdc_pdu_handle = find_dissector_add_dependency("rdc", proto_h283);
  rdc_device_list_handle = find_dissector_add_dependency("rdc.device_list", proto_h283);
  data_handle = find_dissector("data");
}

