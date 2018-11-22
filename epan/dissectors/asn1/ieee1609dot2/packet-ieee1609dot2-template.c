/* packet-IEEE1609dot2.c
 * Routines for IEEE 1609.2
 * Copyright 2018, Anders Broman <anders.broman@ericsson.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-oer.h"

#define PNAME  "IEEE1609dot2"
#define PSNAME "IEEE1609dot2"
#define PFNAME "ieee1609dot2"

void proto_register_IEEE1609dot2(void);
void proto_reg_handoff_IEEE1609dot2(void);

/* Initialize the protocol and registered fields */
int proto_ieee1609dot2 = -1;
#include "packet-ieee1609dot2-hf.c"

/* Initialize the subtree pointers */
#include "packet-ieee1609dot2-ett.c"

static dissector_handle_t j2735_handle;

#include "packet-ieee1609dot2-fn.c"


/*--- proto_register_ieee1609dot2 ----------------------------------------------*/
void proto_register_ieee1609dot2(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-ieee1609dot2-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-ieee1609dot2-ettarr.c"
  };

  /* Register protocol */
  proto_ieee1609dot2 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_ieee1609dot2, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("ieee1609dot2.data", dissect_Ieee1609Dot2Data_PDU, proto_ieee1609dot2);
}

void
proto_reg_handoff_IEEE1609dot2(void)
{

    j2735_handle = find_dissector_add_dependency("j2735", proto_ieee1609dot2);
}
