/* packet-HI2Operations.c
 * Routines for HI2 (ETSI TS 101 671 V3.15.1 (2018-06))
 *  Erwin van Eijk 2010
 *  Joakim Karlsson 2023
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

#include <wsutil/array.h>

#include "packet-ber.h"
#include "packet-HI2Operations.h"
#include "packet-e212.h"
#include "packet-gsm_a_common.h"
#include "packet-gtpv2.h"
#include "packet-isup.h"
#include "packet-q931.h"

void proto_register_HI2Operations(void);
void proto_reg_handoff_HI2Operations(void);

/* Initialize the protocol and registered fields */
int proto_HI2Operations;
int hf_HI2Operations_apn_str;
#include "packet-HI2Operations-hf.c"

/* Initialize the subtree pointers */
static int ett_HI2Operations_eps_paa;
static int ett_HI2Operations_eps_qos;
static int ett_HI2Operations_eps_apn_ambr;
static int ett_HI2Operations_eps_uli;
static int ett_HI2Operations_eps_tft;
static int ett_HI2Operations_eps_network;
#include "packet-HI2Operations-ett.c"

#include "packet-HI2Operations-fn.c"

static bool
dissect_UUS1_Content_PDU_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
  return dissect_UUS1_Content_PDU(tvb, pinfo, tree, data) > 0;
}

/*--- proto_register_HI2Operations ----------------------------------------------*/
void proto_register_HI2Operations(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    {&hf_HI2Operations_apn_str,
         {"APN (Access Point Name)", "gtpv2.apn",
          FT_STRING, BASE_NONE, NULL, 0x0,
          NULL, HFILL}
        },

#include "packet-HI2Operations-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
    &ett_HI2Operations_eps_paa,
    &ett_HI2Operations_eps_qos,
    &ett_HI2Operations_eps_apn_ambr,
    &ett_HI2Operations_eps_uli,
    &ett_HI2Operations_eps_tft,
    &ett_HI2Operations_eps_network,
#include "packet-HI2Operations-ettarr.c"
  };

  /* Register protocol */
  proto_HI2Operations = proto_register_protocol("HI2Operations", "HI2OPERATIONS", "HI2operations");

  /* Register fields and subtrees */
  proto_register_field_array(proto_HI2Operations, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("HI2Operations", dissect_IRIsContent_PDU, proto_HI2Operations);


}


/*--- proto_reg_handoff_HI2Operations -------------------------------------------*/
void proto_reg_handoff_HI2Operations(void) {

    heur_dissector_add("q931_user", dissect_UUS1_Content_PDU_heur, "HI3CCLinkData", "hi3cclinkdata",
        proto_HI2Operations, HEURISTIC_ENABLE);

}

