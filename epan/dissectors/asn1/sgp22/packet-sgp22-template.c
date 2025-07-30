/* packet-sgp22.c
 * Routines for SGP.22 packet dissection.
 *
 * Copyright 2025, Stig Bjorlykke <stig@bjorlykke.org>
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

#include "packet-ber.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-sgp22.h"

#define PNAME  "SGP.22 GSMA Remote SIM Provisioning (RSP)"
#define PSNAME "SGP.22"
#define PFNAME "sgp22"

void proto_register_sgp22(void);
void proto_reg_handoff_sgp22(void);

static int proto_sgp22;
#include "packet-sgp22-hf.c"

#include "packet-sgp22-ett.c"

#include "packet-sgp22-fn.c"

void proto_register_sgp22(void)
{
  static hf_register_info hf[] = {
#include "packet-sgp22-hfarr.c"
  };

  static int *ett[] = {
#include "packet-sgp22-ettarr.c"
  };

  proto_sgp22 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_register_field_array(proto_sgp22, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector_table("sgp22.request", "SGP.22 Request", proto_sgp22, FT_UINT16, BASE_HEX);
  register_dissector_table("sgp22.response", "SGP.22 Response", proto_sgp22, FT_UINT16, BASE_HEX);
}

void proto_reg_handoff_sgp22(void)
{
  oid_add_from_string("id-rsp", id_rsp);
  oid_add_from_string("id-rsp-metadata", id_rsp_metadata);
  oid_add_from_string("id-rsp-metadata-serviceSpecificOIDs", id_rsp_metadata_serviceSpecificOIDs);
  oid_add_from_string("id-rsp-cert-objects", id_rsp_cert_objects);
  oid_add_from_string("id-rspExt", id_rspExt);
  oid_add_from_string("id-rspRole", id_rspRole);
  oid_add_from_string("id-rspRole-ci", id_rspRole_ci);
  oid_add_from_string("id-rspRole-euicc", id_rspRole_euicc);
  oid_add_from_string("id-rspRole-eum", id_rspRole_eum);
  oid_add_from_string("id-rspRole-dp-tls", id_rspRole_dp_tls);
  oid_add_from_string("id-rspRole-dp-auth", id_rspRole_dp_auth);
  oid_add_from_string("id-rspRole-dp-pb", id_rspRole_dp_pb);
  oid_add_from_string("id-rspRole-ds-tls", id_rspRole_ds_tls);
  oid_add_from_string("id-rspRole-ds-auth", id_rspRole_ds_auth);

#include "packet-sgp22-dis-tab.c"
}
