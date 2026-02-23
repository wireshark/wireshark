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
#include "packet-media-type.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-sgp22.h"

void proto_register_sgp22(void);
void proto_reg_handoff_sgp22(void);

static int proto_sgp22;
#include "packet-sgp22-hf.c"

static int ett_sgp22;
#include "packet-sgp22-ett.c"

#include "packet-sgp22-fn.c"

static dissector_handle_t sgp22_handle;

static int dissect_sgp22(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  media_content_info_t *content_info = (media_content_info_t *)data;
  proto_item *sgp22_ti;
  proto_tree *sgp22_tree;
  int offset;

  if (!content_info ||
      ((content_info->type != MEDIA_CONTAINER_HTTP_REQUEST) &&
       (content_info->type != MEDIA_CONTAINER_HTTP_RESPONSE))) {
    return 0;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SGP.22");
  col_clear(pinfo->cinfo, COL_INFO);

  sgp22_ti = proto_tree_add_item(tree, proto_sgp22, tvb, 0, -1, ENC_NA);
  sgp22_tree = proto_item_add_subtree(sgp22_ti, ett_sgp22);

  if (content_info->type == MEDIA_CONTAINER_HTTP_REQUEST) {
    offset = dissect_RemoteProfileProvisioningRequest_PDU(tvb, pinfo, sgp22_tree, NULL);
  } else {
    offset = dissect_RemoteProfileProvisioningResponse_PDU(tvb, pinfo, sgp22_tree, NULL);
  }

  return offset;
}

void proto_register_sgp22(void)
{
  static hf_register_info hf[] = {
#include "packet-sgp22-hfarr.c"
  };

  static int *ett[] = {
    &ett_sgp22,
#include "packet-sgp22-ettarr.c"
  };

  proto_sgp22 = proto_register_protocol("SGP.22 GSMA Remote SIM Provisioning (RSP)", "SGP.22", "sgp22");
  proto_register_field_array(proto_sgp22, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  sgp22_handle = register_dissector("sgp22", dissect_sgp22, proto_sgp22);

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

  dissector_add_for_decode_as("media_type", sgp22_handle);

#include "packet-sgp22-dis-tab.c"
}
