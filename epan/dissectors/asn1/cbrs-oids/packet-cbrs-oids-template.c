/* packet-cbrs-oids.c
 *
 * Citizens Broadband Radio Service - Object Identifiers
 *
 * Extracted from
 * - WInnForum CBRS COMSEC TS WINNF-15-S-0065-V2.0.0
 *   https://www.wirelessinnovation.org/assets/work_products/Specifications/winnf-15-s-0065-v2.0.0%20cbrs%20communications%20security%20technical%20specification.pdf
 * - WInnForum CBRS Certificate Policy Document WINNF-17-S-0022
 *   https://www.wirelessinnovation.org/assets/work_products/Specifications/winnf-17-s-0022%20v1.0.0%20cbrs%20pki%20certificate%20policy.pdf
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

#define PNAME  "Citizen Broadband Radio Service - Object Identifiers"
#define PSNAME "CBRS_OIDS"
#define PFNAME "cbrs_oids"

void proto_register_cbrs_oids(void);
void proto_reg_handoff_cbrs_oids(void);

/* Initialize the protocol and registered fields */
static int proto_cbrs_oids = -1;
#include "packet-cbrs-oids-hf.c"
static int hf_cbrs_oids_UTF8String_PDU = -1;

/* Initialize the subtree pointers */
#include "packet-cbrs-oids-fn.c"

/*--- proto_register_cbrs_oids ----------------------------------------------*/
void proto_register_cbrs_oids(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_cbrs_oids_UTF8String_PDU,
      { "UTF8String", "cbrs-oids.UTF8String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
#include "packet-cbrs-oids-hfarr.c"
  };

  /* Register protocol */
  proto_cbrs_oids = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_cbrs_oids, hf, array_length(hf));
/*  proto_register_subtree_array(ett, array_length(ett)); */
}

/*--- proto_reg_handoff_cbrs_oids -------------------------------------------*/
void proto_reg_handoff_cbrs_oids(void) {
#include "packet-cbrs-oids-dis-tab.c"
  oid_add_from_string("CBRS Policy Documents","1.3.6.1.4.1.46609.2");
  oid_add_from_string("CBRS Certificates issued pursuant to CPS","1.3.6.1.4.1.46609.2.1");
  oid_add_from_string("CBRS ROLE","1.3.6.1.4.1.46609.1.1");
  oid_add_from_string("CBRS SAS","1.3.6.1.4.1.46609.1.1.1");
  oid_add_from_string("CBRS INSTALLER","1.3.6.1.4.1.46609.1.1.2");
  oid_add_from_string("CBRS CBSD","1.3.6.1.4.1.46609.1.1.3");
  oid_add_from_string("CBRS OPERATOR (Domain Proxy Operator)","1.3.6.1.4.1.46609.1.1.4");
  oid_add_from_string("CBRS CA","1.3.6.1.4.1.46609.1.1.5");
  oid_add_from_string("CBRS PAL","1.3.6.1.4.1.46609.1.1.6");
  oid_add_from_string("CBRS ESC","1.3.6.1.4.1.46609.1.1.7");
}
