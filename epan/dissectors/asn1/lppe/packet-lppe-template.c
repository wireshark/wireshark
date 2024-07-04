/* packet-lppe.c
 * Routines for LPP Extensions (LLPe) packet dissection
 * Copyright 2012-2021, Pascal Quantin <pascal@wireshark.org>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Ref Open Mobile Alliance OMA-TS-LPPe-V1_0-20200630-D
 * https://gitlab.com/wireshark/wireshark/uploads/e1059f6dc0fc9e3b875b37a9732df39a/OMA-TS-LPPe-V1_0-20200630-D.doc
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/asn1.h>

#include "packet-per.h"
#include "packet-lpp.h"

#define PNAME  "LTE Positioning Protocol Extensions (LLPe)"
#define PSNAME "LPPe"
#define PFNAME "lppe"

#ifdef _MSC_VER
/* disable: "warning C4146: unary minus operator applied to unsigned type, result still unsigned" */
#pragma warning(disable:4146)
#endif

void proto_register_lppe(void);
void proto_reg_handoff_lppe(void);

/* Initialize the protocol and registered fields */
static int proto_lppe;

static dissector_handle_t xml_handle;

#include "packet-lppe-hf.c"

/* Initialize the subtree pointers */
static int ett_lppe;
static int ett_lppe_civicLocation;
#include "packet-lppe-ett.c"

/* Include constants */
#include "packet-lppe-val.h"


#include "packet-lppe-fn.c"


/*--- proto_register_lpp -------------------------------------------*/
void proto_register_lppe(void) {

  /* List of fields */
  static hf_register_info hf[] = {

#include "packet-lppe-hfarr.c"
  };

  /* List of subtrees */
  static int *ett[] = {
	  &ett_lppe,
      &ett_lppe_civicLocation,
#include "packet-lppe-ettarr.c"
  };


  /* Register protocol */
  proto_lppe = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("lppe", dissect_OMA_LPPe_MessageExtension_PDU, proto_lppe);

  /* Register fields and subtrees */
  proto_register_field_array(proto_lppe, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


}


/*--- proto_reg_handoff_lpp ---------------------------------------*/
void
proto_reg_handoff_lppe(void)
{
  xml_handle = find_dissector_add_dependency("xml", proto_lppe);
}


