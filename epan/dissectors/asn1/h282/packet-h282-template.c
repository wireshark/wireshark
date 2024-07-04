/* packet-h282.c
 * Routines for H.282 packet dissection
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

#define PNAME  "H.282 Remote Device Control"
#define PSNAME "RDC"
#define PFNAME "rdc"

void proto_register_h282(void);
void proto_reg_handoff_h282(void);

/* Initialize the protocol and registered fields */
static int proto_h282;
#include "packet-h282-hf.c"

/* Initialize the subtree pointers */
static int ett_h282;
#include "packet-h282-ett.c"

/* Dissectors */

/* Subdissectors */

#include "packet-h282-fn.c"

static int
dissect_h282(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item  *ti = NULL;
  proto_tree  *h282_tree = NULL;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, PSNAME);

  ti = proto_tree_add_item(tree, proto_h282, tvb, 0, -1, ENC_NA);
  h282_tree = proto_item_add_subtree(ti, ett_h282);

  return dissect_RDCPDU_PDU(tvb, pinfo, h282_tree, NULL);
}

/*--- proto_register_h282 ----------------------------------------------*/
void proto_register_h282(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-h282-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_h282,
#include "packet-h282-ettarr.c"
  };

  /* Register protocol */
  proto_h282 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h282, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector(PFNAME, dissect_h282, proto_h282);
  register_dissector(PFNAME".device_list", dissect_NonCollapsingCapabilities_PDU, proto_h282);

}

/*--- proto_reg_handoff_h282 -------------------------------------------*/
void proto_reg_handoff_h282(void)
{

}

