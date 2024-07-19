/* packet-dns.c
 * Routines for TSDNS (TeamSpeak3 DNS) packet disassembly
 * Copyright 2018, Maciej Krueger <mkg20001@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/strutil.h>
#include <wsutil/strtoi.h>

#define TSDNS_PORT  41144   /* Not IANA registered */

void proto_register_tsdns(void);
void proto_reg_handoff_tsdns(void);
static dissector_handle_t tsdns_handle;

static int proto_tsdns;

static int hf_tsdns_data;
static int hf_tsdns_request;
static int hf_tsdns_request_domain;
static int hf_tsdns_response;
static int hf_tsdns_response_ip;
static int hf_tsdns_response_address;
static int hf_tsdns_response_port;

static expert_field ei_response_port_malformed;

static int ett_tsdns;

static int dissect_tsdns(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{

  int         offset    = 0;
  bool        request   = false;

  if (pinfo->destport == pinfo->match_uint) {
    request = true;
  }

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "TSDNS");

  int pLen = tvb_reported_length(tvb);

  if (request) {
    col_set_str(pinfo->cinfo, COL_INFO, "Request");
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", tvb_get_string_enc(pinfo->pool, tvb, 0, pLen - 5, ENC_ASCII));
  } else {
    col_set_str(pinfo->cinfo, COL_INFO, "Response");
    col_append_fstr(pinfo->cinfo, COL_INFO, " %s", tvb_get_string_enc(pinfo->pool, tvb, 0, pLen, ENC_ASCII));
  }

  proto_tree *tsdns_tree;
  proto_item *ti, *hidden_item, *address_item;

  ti = proto_tree_add_item(tree, proto_tsdns, tvb, offset, -1, ENC_NA);
  tsdns_tree = proto_item_add_subtree(ti, ett_tsdns);

  hidden_item = proto_tree_add_item(tsdns_tree, hf_tsdns_data, tvb, offset, -1, ENC_ASCII);
  proto_item_set_hidden(hidden_item);

  if (request) { // request is DOMAIN\n\r\r\r\n
    hidden_item = proto_tree_add_boolean(tsdns_tree, hf_tsdns_request, tvb, 0, 0, 1); // using pLen - 5 as the last chars are \n\r\r\r\n which are just indicating the end of the request
    proto_tree_add_item(tsdns_tree, hf_tsdns_request_domain, tvb, offset, pLen - 5, ENC_ASCII);
  } else { // response is IP:PORT
    hidden_item = proto_tree_add_boolean(tsdns_tree, hf_tsdns_response, tvb, 0, 0, 1);
    address_item = proto_tree_add_item(tsdns_tree, hf_tsdns_response_address, tvb, offset, pLen, ENC_ASCII);
    char** splitAddress;
    splitAddress = wmem_strsplit(pinfo->pool, tvb_format_text(pinfo->pool, tvb, 0, pLen), ":", 1); // unsure if TSDNS also does IPv6...
    if (splitAddress == NULL || splitAddress[0] == NULL || splitAddress[1] == NULL) {
      expert_add_info(pinfo, address_item, &ei_response_port_malformed);
    } else {
      proto_tree_add_string(tsdns_tree, hf_tsdns_response_ip, tvb, 0, pLen, splitAddress[0]);
      uint32_t port;
      if (ws_strtou32(splitAddress[1], NULL, &port))
        proto_tree_add_uint(tsdns_tree, hf_tsdns_response_port, tvb, 0, pLen, port);
    }
  }
  proto_item_set_hidden(hidden_item);

  return tvb_captured_length(tvb);

} /* dissect_tsdns */

void proto_register_tsdns(void)
{

  static hf_register_info hf[] = {
    { &hf_tsdns_data,
      { "Data",    "tsdns.data",
        FT_STRING,       BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},
    { &hf_tsdns_request,
      { "Request", "tsdns.request",
        FT_BOOLEAN,     BASE_NONE,      NULL,   0x0,
        "true if TSDNS Request", HFILL }},
    { &hf_tsdns_request_domain,
      { "Requested Domain", "tsdns.request.domain",
        FT_STRING,     BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},
    { &hf_tsdns_response,
      { "Response","tsdns.response",
        FT_BOOLEAN,     BASE_NONE,      NULL,   0x0,
        "true if TSDNS Response", HFILL }},
    { &hf_tsdns_response_address,
       { "Response Address","tsdns.response.address",
         FT_STRING,     BASE_NONE,      NULL,   0x0,
         NULL, HFILL }},
    { &hf_tsdns_response_ip,
      { "Response IP","tsdns.response.ip",
        FT_STRING,     BASE_NONE,      NULL,   0x0,
        NULL, HFILL }},
    { &hf_tsdns_response_port,
      { "Response Port","tsdns.response.port",
        FT_UINT16,     BASE_DEC,      NULL,   0x0,
        NULL, HFILL }}
  };

  static ei_register_info ei[] = {
          { &ei_response_port_malformed, { "tsdns.response.port.malformed", PI_MALFORMED, PI_ERROR, "Address port is not an integer or not contained in address", EXPFILL }}
  };
  expert_module_t* expert_tsdns;

  static int *ett[] = {
    &ett_tsdns
  };

  proto_tsdns = proto_register_protocol("TeamSpeak3 DNS", "TSDNS", "tsdns");
  proto_register_field_array(proto_tsdns, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_tsdns = expert_register_protocol(proto_tsdns);
  expert_register_field_array(expert_tsdns, ei, array_length(ei));

  tsdns_handle = register_dissector("tsdns", dissect_tsdns, proto_tsdns);
}

void proto_reg_handoff_tsdns(void)
{
  /* Default port to not dissect the protocol*/
  dissector_add_uint_with_preference("tcp.port", 0, tsdns_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
