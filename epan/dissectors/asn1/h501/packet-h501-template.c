/* packet-h501.c
 * Routines for H.501 packet dissection
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
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-tpkt.h"
#include "packet-per.h"
#include "packet-h225.h"
#include "packet-h235.h"

#define PNAME  "H.501 Mobility"
#define PSNAME "H.501"
#define PFNAME "h501"

void proto_register_h501(void);

/* Initialize the protocol and registered fields */
static int proto_h501 = -1;
#include "packet-h501-hf.c"

/* Initialize the subtree pointers */
static int ett_h501 = -1;
#include "packet-h501-ett.c"

/* Dissectors */
static dissector_handle_t h501_pdu_handle;

/* Preferences */
#define H501_PORT 2099
static gboolean h501_desegment_tcp = TRUE;

void proto_reg_handoff_h501(void);

#include "packet-h501-fn.c"

static int
dissect_h501_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item  *ti = NULL;
  proto_tree  *h501_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  ti = proto_tree_add_item(tree, proto_h501, tvb, 0, -1, ENC_NA);
  h501_tree = proto_item_add_subtree(ti, ett_h501);

  return dissect_Message_PDU(tvb, pinfo, h501_tree, NULL);
}

static int
dissect_h501_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  dissect_tpkt_encap(tvb, pinfo, tree, FALSE, h501_pdu_handle);
  return tvb_captured_length(tvb);
}

static int
dissect_h501_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  dissect_tpkt_encap(tvb, pinfo, tree, h501_desegment_tcp, h501_pdu_handle);
  return tvb_captured_length(tvb);
}

/*--- proto_register_h501 ----------------------------------------------*/
void proto_register_h501(void) {
  module_t *h501_module;

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-h501-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_h501,
#include "packet-h501-ettarr.c"
  };

  /* Register protocol */
  proto_h501 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h501, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  h501_pdu_handle = register_dissector(PFNAME, dissect_h501_pdu, proto_h501);

  h501_module = prefs_register_protocol(proto_h501, NULL);
  prefs_register_bool_preference(h501_module, "desegment",
                                 "Desegment H.501 over TCP",
                                 "Desegment H.501 messages that span more TCP segments",
                                 &h501_desegment_tcp);

}

/*--- proto_reg_handoff_h501 -------------------------------------------*/
void proto_reg_handoff_h501(void)
{
  dissector_handle_t h501_udp_handle;
  dissector_handle_t h501_tcp_handle;

  h501_udp_handle = create_dissector_handle(dissect_h501_udp, proto_h501);
  h501_tcp_handle = create_dissector_handle(dissect_h501_tcp, proto_h501);
  dissector_add_uint_with_preference("tcp.port", H501_PORT, h501_tcp_handle);
  dissector_add_uint_with_preference("udp.port", H501_PORT, h501_udp_handle);
}

