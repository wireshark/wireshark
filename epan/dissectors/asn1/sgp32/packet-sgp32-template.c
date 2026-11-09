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
#include "packet-e212.h"
#include "packet-pkix1explicit.h"
#include "packet-pkix1implicit.h"
#include "packet-sgp22.h"
#include "packet-sgp32.h"

void proto_register_sgp32(void);
void proto_reg_handoff_sgp32(void);

static int proto_sgp32;
static int hf_sgp32_tag_len1;
static int hf_sgp32_tag_len2;
#include "packet-sgp32-hf.c"

static int ett_sgp32;
static int ett_sgp32_rPLMN;
static int ett_sgp32_tagList;
#include "packet-sgp32-ett.c"

static dissector_handle_t sgp22_handle;
static dissector_handle_t sgp32_handle;
static dissector_handle_t gsma_rsp_asn1_handle;

/* Dissector tables */
static dissector_table_t sgp32_request_dissector_table;
static dissector_table_t sgp32_response_dissector_table;

static const value_string sgp32_tag_vals[] = {
  { 0x81, "defaultSmdpAddress" },
  { 0x83, "rootSmdsAddress" },
  { 0x84, "associationToken" },
  { 0xA0, "notificationsList" },
  { 0xA2, "euiccPackageResultList" },
  { 0xA5, "eumCertificate" },
  { 0xA6, "euiccCertificate" },
  { 0xA8, "ipaCapabilities" },
  { 0xA9, "deviceInfo" },
  { 0xBF20, "eUICCInfo1" },
  { 0xBF22, "eUICCInfo2" },
  { 0, NULL }
};

static int dissect_sgp32_taglist(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  unsigned offset = 0;

  while (tvb_reported_length_remaining(tvb, offset)) {
    if ((tvb_get_uint8(tvb, offset) & 0x1F) == 0x1F) { /* Continue */
      proto_tree_add_item(tree, hf_sgp32_tag_len2, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    } else {
      proto_tree_add_item(tree, hf_sgp32_tag_len1, tvb, offset, 1, ENC_NA);
      offset += 1;
    }
  }

  return offset;
}

#include "packet-sgp32-fn.c"

bool is_sgp32_request(tvbuff_t *tvb)
{
  uint32_t tag;

  if (!is_rsp_asn1_header(tvb, &tag)) {
    return false;
  }

  return dissector_get_uint_handle(sgp32_request_dissector_table, tag) != NULL;
}

bool is_sgp32_response(tvbuff_t *tvb)
{
  uint32_t tag;

  if (!is_rsp_asn1_header(tvb, &tag)) {
    return false;
  }

  return dissector_get_uint_handle(sgp32_response_dissector_table, tag) != NULL;
}

static int dissect_sgp32_table(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, dissector_table_t table)
{
  proto_item *sgp32_ti;
  proto_tree *sgp32_tree;
  uint32_t tag = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SGP.32");

  sgp32_ti = proto_tree_add_item(tree, proto_sgp32, tvb, 0, -1, ENC_NA);
  sgp32_tree = proto_item_add_subtree(sgp32_ti, ett_sgp32);

  get_rsp_tag(tvb, &tag);

  return dissector_try_uint(table, tag, tvb, pinfo, sgp32_tree);
}

int dissect_sgp32_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return dissect_sgp32_table(tvb, pinfo, tree, sgp32_request_dissector_table);
}

int dissect_sgp32_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return dissect_sgp32_table(tvb, pinfo, tree, sgp32_response_dissector_table);
}

static int dissect_sgp32_esipa_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *sgp32_ti;
  proto_tree *sgp32_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SGP.32");

  sgp32_ti = proto_tree_add_item(tree, proto_sgp32, tvb, 0, -1, ENC_NA);
  sgp32_tree = proto_item_add_subtree(sgp32_ti, ett_sgp32);

  return dissect_EsipaMessageFromIpaToEim_PDU(tvb, pinfo, sgp32_tree, NULL);
}

static int dissect_sgp32_esipa_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *sgp32_ti;
  proto_tree *sgp32_tree;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "SGP.32");

  sgp32_ti = proto_tree_add_item(tree, proto_sgp32, tvb, 0, -1, ENC_NA);
  sgp32_tree = proto_item_add_subtree(sgp32_ti, ett_sgp32);

  return dissect_EsipaMessageFromEimToIpa_PDU(tvb, pinfo, sgp32_tree, NULL);
}

static int dissect_sgp32(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  media_content_info_t *content_info = (media_content_info_t *)data;

  if (!content_info ||
      ((content_info->type != MEDIA_CONTAINER_HTTP_REQUEST) &&
       (content_info->type != MEDIA_CONTAINER_HTTP_RESPONSE))) {
    return 0;
  }

  col_clear(pinfo->cinfo, COL_INFO);

  if (content_info->type == MEDIA_CONTAINER_HTTP_REQUEST) {
    return dissect_sgp32_esipa_request(tvb, pinfo, tree, NULL);
  }

  return dissect_sgp32_esipa_response(tvb, pinfo, tree, NULL);
}

/*
 * SGP.22 (ES9+/ES11) and SGP.32 (ESipa) use the same media type.
 * This dispatcher has no protocol, so only the dissector actually
 * decoding the message is added to the protocol layers.
 */
static int dissect_gsma_rsp_asn1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  uint32_t tag;

  /* SGP.22 RemoteProfileProvisioningRequest/Response -- Tag 'A2' */
  get_rsp_tag(tvb, &tag);
  if (tag == 0xA2) {
    return call_dissector_only(sgp22_handle, tvb, pinfo, tree, data);
  }

  return call_dissector_only(sgp32_handle, tvb, pinfo, tree, data);
}

void proto_register_sgp32(void)
{
  static hf_register_info hf[] = {
    { &hf_sgp32_tag_len1,
      { "Tag", "sgp32.tag",
        FT_UINT8, BASE_HEX, VALS(sgp32_tag_vals), 0,
        NULL, HFILL }},
    { &hf_sgp32_tag_len2,
      { "Tag", "sgp32.tag",
        FT_UINT16, BASE_HEX, VALS(sgp32_tag_vals), 0,
        NULL, HFILL }},
#include "packet-sgp32-hfarr.c"
  };

  static int *ett[] = {
    &ett_sgp32,
    &ett_sgp32_rPLMN,
    &ett_sgp32_tagList,
#include "packet-sgp32-ettarr.c"
  };

  proto_sgp32 = proto_register_protocol("SGP.32 GSMA Remote SIM Provisioning (RSP)", "SGP.32", "sgp32");
  proto_register_field_array(proto_sgp32, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  sgp32_handle = register_dissector("sgp32", dissect_sgp32, proto_sgp32);
  register_dissector("sgp32.request", dissect_sgp32_request, proto_sgp32);
  register_dissector("sgp32.response", dissect_sgp32_response, proto_sgp32);

  sgp32_request_dissector_table = register_dissector_table("sgp32.request", "SGP.32 Request", proto_sgp32, FT_UINT16, BASE_HEX);
  sgp32_response_dissector_table = register_dissector_table("sgp32.response", "SGP.32 Response", proto_sgp32, FT_UINT16, BASE_HEX);

  register_ber_syntax_dissector("SGP.32 Request", proto_sgp32, dissect_sgp32_request);
  register_ber_syntax_dissector("SGP.32 Response", proto_sgp32, dissect_sgp32_response);
  register_ber_syntax_dissector("SGP.32 ESipa Request", proto_sgp32, dissect_sgp32_esipa_request);
  register_ber_syntax_dissector("SGP.32 ESipa Response", proto_sgp32, dissect_sgp32_esipa_response);

  gsma_rsp_asn1_handle = create_dissector_handle_with_name_and_description(dissect_gsma_rsp_asn1, -1, "gsma_rsp_asn1", "GSMA RSP ASN.1");
}

void proto_reg_handoff_sgp32(void)
{
  sgp22_handle = find_dissector("sgp22");

  dissector_add_string("media_type", "application/x-gsma-rsp-asn1", gsma_rsp_asn1_handle);
  dissector_add_string("coap_uri_path", "/gsma/rsp2/asn1", gsma_rsp_asn1_handle);
  dissector_add_for_decode_as("media_type", sgp32_handle);

#include "packet-sgp32-dis-tab.c"
}
