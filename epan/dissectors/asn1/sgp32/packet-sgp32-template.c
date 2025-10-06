/* packet-sgp32.c
 * Routines for SGP.32 packet dissection.
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

#include "packet-ber.h"
#include "packet-media-type.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-sgp22.h"
#include "packet-sgp32.h"

#define PNAME  "SGP.32 GSMA Remote SIM Provisioning (RSP)"
#define PSNAME "SGP.32"
#define PFNAME "sgp32"

void proto_register_sgp32(void);
void proto_reg_handoff_sgp32(void);

static int proto_sgp32;
#include "packet-sgp32-hf.c"

static int ett_sgp32;
#include "packet-sgp32-ett.c"

#include "packet-sgp32-fn.c"

static dissector_handle_t sgp32_handle;

/* Dissector tables */
static dissector_table_t sgp22_request_dissector_table;
static dissector_table_t sgp22_response_dissector_table;
static dissector_table_t sgp32_request_dissector_table;
static dissector_table_t sgp32_response_dissector_table;

static int get_sgp32_tag(tvbuff_t *tvb, uint32_t *tag)
{
  int offset = 0;

  *tag = tvb_get_uint8(tvb, offset++);
  if ((*tag & 0x1F) == 0x1F) {
    *tag = (*tag << 8) | tvb_get_uint8(tvb, offset++);
  }

  return offset;
}

static bool is_asn1_header(tvbuff_t *tvb, uint32_t *tag)
{
  uint32_t length = 0;
  int offset;

  offset = get_sgp32_tag(tvb, tag);
  offset = get_ber_length(tvb, offset, &length, NULL);

  return ((offset + length) == tvb_reported_length(tvb));
}

bool is_sgp32_request(tvbuff_t *tvb)
{
  uint32_t tag;

  if (!is_asn1_header(tvb, &tag)) {
    return false;
  }

  return dissector_get_uint_handle(sgp32_request_dissector_table, tag) ||
         dissector_get_uint_handle(sgp22_request_dissector_table, tag);
}

bool is_sgp32_response(tvbuff_t *tvb)
{
  uint32_t tag;

  if (!is_asn1_header(tvb, &tag)) {
    return false;
  }

  return dissector_get_uint_handle(sgp32_response_dissector_table, tag) ||
         dissector_get_uint_handle(sgp22_response_dissector_table, tag);
}

int dissect_sgp32_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *sgp32_ti;
  proto_tree *sgp32_tree;
  uint32_t tag = 0;
  int offset;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SGP.32");

  sgp32_ti = proto_tree_add_item(tree, proto_sgp32, tvb, 0, -1, ENC_NA);
  sgp32_tree = proto_item_add_subtree(sgp32_ti, ett_sgp32);

  get_sgp32_tag(tvb, &tag);
  offset = dissector_try_uint(sgp32_request_dissector_table, tag, tvb, pinfo, sgp32_tree);
  if (offset == 0) {
    offset = dissector_try_uint(sgp22_request_dissector_table, tag, tvb, pinfo, sgp32_tree);
  }

  return offset;
}

int dissect_sgp32_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *sgp32_ti;
  proto_tree *sgp32_tree;
  uint32_t tag = 0;
  int offset;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SGP.32");

  sgp32_ti = proto_tree_add_item(tree, proto_sgp32, tvb, 0, -1, ENC_NA);
  sgp32_tree = proto_item_add_subtree(sgp32_ti, ett_sgp32);

  get_sgp32_tag(tvb, &tag);
  offset = dissector_try_uint(sgp32_response_dissector_table, tag, tvb, pinfo, sgp32_tree);
  if (offset == 0) {
    offset = dissector_try_uint(sgp22_response_dissector_table, tag, tvb, pinfo, sgp32_tree);
  }

  return offset;
}

static int dissect_sgp32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  media_content_info_t *content_info = (media_content_info_t *)data;
  proto_item *sgp32_ti;
  proto_tree *sgp32_tree;
  int offset;

  if (!content_info ||
      ((content_info->type != MEDIA_CONTAINER_HTTP_REQUEST) &&
       (content_info->type != MEDIA_CONTAINER_HTTP_RESPONSE))) {
    return 0;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SGP.32");
  col_clear(pinfo->cinfo, COL_INFO);

  sgp32_ti = proto_tree_add_item(tree, proto_sgp32, tvb, 0, -1, ENC_NA);
  sgp32_tree = proto_item_add_subtree(sgp32_ti, ett_sgp32);

  if (content_info->type == MEDIA_CONTAINER_HTTP_REQUEST) {
    offset = dissect_EsipaMessageFromIpaToEim_PDU(tvb, pinfo, sgp32_tree, NULL);
  } else {
    offset = dissect_EsipaMessageFromEimToIpa_PDU(tvb, pinfo, sgp32_tree, NULL);
  }

  return offset;
}

void proto_register_sgp32(void)
{
  static hf_register_info hf[] = {
#include "packet-sgp32-hfarr.c"
  };

  static int *ett[] = {
    &ett_sgp32,
#include "packet-sgp32-ettarr.c"
  };

  proto_sgp32 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  proto_register_field_array(proto_sgp32, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  sgp32_handle = register_dissector("sgp32", dissect_sgp32, proto_sgp32);
  register_dissector("sgp32.request", dissect_sgp32_request, proto_sgp32);
  register_dissector("sgp32.response", dissect_sgp32_response, proto_sgp32);

  sgp32_request_dissector_table = register_dissector_table("sgp32.request", "SGP.32 Request", proto_sgp32, FT_UINT16, BASE_HEX);
  sgp32_response_dissector_table = register_dissector_table("sgp32.response", "SGP.32 Response", proto_sgp32, FT_UINT16, BASE_HEX);

  register_ber_syntax_dissector("SGP.32 Request", proto_sgp32, dissect_sgp32_request);
  register_ber_syntax_dissector("SGP.32 Response", proto_sgp32, dissect_sgp32_response);
}

void proto_reg_handoff_sgp32(void)
{
  sgp22_request_dissector_table = find_dissector_table("sgp22.request");
  sgp22_response_dissector_table = find_dissector_table("sgp22.response");

  dissector_add_string("media_type", "application/x-gsma-rsp-asn1", sgp32_handle);

#include "packet-sgp32-dis-tab.c"
}
