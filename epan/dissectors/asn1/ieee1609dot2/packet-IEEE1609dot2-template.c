/* packet-IEEE1609dot2.c
 * Routines for HI2 (ETSI TS 101 671 V3.5.1 (2009-11))
 *  Erwin van Eijk 2010
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
int proto_IEEE1609dot2 = -1;
#include "packet-IEEE1609dot2-hf.c"

/* Initialize the subtree pointers */
#include "packet-IEEE1609dot2-ett.c"

#include "packet-IEEE1609dot2-fn.c"


/*--- proto_register_IEEE1609dot2 ----------------------------------------------*/
void proto_register_IEEE1609dot2(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-IEEE1609dot2-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-IEEE1609dot2-ettarr.c"
  };

  /* Register protocol */
  proto_IEEE1609dot2 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_IEEE1609dot2, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("IEEE1609dot2.data", dissect_Ieee1609Dot2Data_PDU, proto_IEEE1609dot2);
}


/*--- proto_reg_handoff_IEEE1609dot2 -------------------------------------------*/
void proto_reg_handoff_IEEE1609dot2(void) {
}

