/* packet-mudurl-template.c
 * Routines for mudurl found in draft-ietf-opsawg-mud
 * by Eliot Lear
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-ber.h"
/* #include "packet-mudurl.h" */ // At the moment we are not exporting.
#include "packet-x509af.h"

#define PNAME  "MUDURL"
#define PSNAME "MUDURL"
#define PFNAME "mudurl"

void proto_register_mudurl(void);
void proto_reg_handoff_mudurl(void);


/* Initialize the protocol and registered fields */
static int proto_mudurl = -1;
#include "packet-mudurl-hf.c"

/* Initialize the subtree pointers */
/* #include "packet-mudurl-ett.c" */

// static const char *object_identifier_id;

#include "packet-mudurl-fn.c"


/*--- proto_register_mudurl ----------------------------------------------*/
void proto_register_mudurl(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-mudurl-hfarr.c"
  };

  /* List of subtrees */
  /*  static gint *ett[] = {
#include "packet-mudurl-ettarr.c"
  }; */

  /* Register protocol */
  proto_mudurl = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_mudurl, hf, array_length(hf));
  //  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_mudurl -------------------------------------------*/
void proto_reg_handoff_mudurl(void) {
#include "packet-mudurl-dis-tab.c"
}
