/* packet-wlancertextn.c
 * Routines for Wireless Certificate Extension (RFC3770)
 *  Ronnie Sahlberg 2005
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

#include "packet-ber.h"
#include "packet-wlancertextn.h"
#include "packet-x509af.h"
#include "packet-x509ce.h"
#include "packet-x509sat.h"

#define PNAME  "Wlan Certificate Extension"
#define PSNAME "WLANCERTEXTN"
#define PFNAME "wlancertextn"

void proto_register_wlancertextn(void);
void proto_reg_handoff_wlancertextn(void);

/* Initialize the protocol and registered fields */
static int proto_wlancertextn;
#include "packet-wlancertextn-hf.c"

/* Initialize the subtree pointers */
#include "packet-wlancertextn-ett.c"

#include "packet-wlancertextn-fn.c"


/*--- proto_register_wlancertextn ----------------------------------------------*/
void proto_register_wlancertextn(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-wlancertextn-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-wlancertextn-ettarr.c"
  };

  /* Register protocol */
  proto_wlancertextn = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_wlancertextn, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_wlancertextn -------------------------------------------*/
void proto_reg_handoff_wlancertextn(void) {
#include "packet-wlancertextn-dis-tab.c"
  oid_add_from_string("id-kp-eapOverPPP","1.3.6.1.5.5.7.3.13");
  oid_add_from_string("id-kp-eapOverLAN","1.3.6.1.5.5.7.3.14");
}

