/* packet-lix2-template.c
 * Routines for Lawful Interception X2 xIRI event dissection
 *
 * See 3GPP TS33.128 V18.5.0
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
#include <epan/asn1.h>

#include "packet-ber.h"

#define PNAME  "X2 xIRI payload"
#define PSNAME "xIRI"
#define PFNAME "xiri"

void proto_reg_handoff_lix2(void);
void proto_register_lix2(void);

/* Initialize the protocol and registered fields */
static int proto_lix2;
static dissector_handle_t lix2_handle;


#include "packet-lix2-hf.c"

#include "packet-lix2-ett.c"

#include "packet-lix2-fn.c"

/*--- proto_register_lix2 -------------------------------------------*/
void proto_register_lix2(void) {

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-lix2-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
#include "packet-lix2-ettarr.c"
  };

  /* Register protocol */
  proto_lix2 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lix2, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  lix2_handle = register_dissector("xiri", dissect_XIRIPayload_PDU, proto_lix2);

  /* Get rid of unused code warnings */
  (void)&dissect_lix2_MMSElementDescriptor;
  (void)&dissect_lix2_MMSCancelStatus;
  (void)&lix2_MMSCancelStatus_vals;
  (void)&dissect_lix2_LINotificationPayload;
  (void)&dissect_lix2_CCPayload;
  (void)&dissect_lix2_IRIPayload;
  (void)&hf_lix2_bCCRecipients_item;
  (void)&hf_lix2_cCRecipients_item;
  (void)&hf_lix2_expectedTimeAndDayOfWeekInTrajectory_item;
  (void)&hf_lix2_globalENbIDList_item;
  (void)&hf_lix2_originatingMMSParty_item;
  (void)&hf_lix2_pTCHoldID_item;
  (void)&hf_lix2_pTCIDList_item;
}
