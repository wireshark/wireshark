/* packet-monero.c
 * Routines for Monero protocol dissection
 * Copyright 2023, snicket2100 <snicket2100@protonmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/prefs.h>
#include <epan/expert.h>

#include "packet-tcp.h"

#define MONERO_LEVIN_SIGNATURE 0x0101010101012101

static const value_string monero_commands[] =
{
  { 1001, "Handshake" },
  { 1002, "TimedSync" },
  { 1003, "Ping" },
  { 1007, "SupportFlags" },
  { 2001, "NewBlock" },
  { 2002, "NewTransactions" },
  { 2003, "GetObjectsRequest" },
  { 2004, "GetObjectsResponse" },
  { 2006, "ChainRequest" },
  { 2007, "ChainResponse" },
  { 2008, "NewFluffyBlock" },
  { 2009, "FluffyMissingTxsRequest" },
  { 2010, "GetTxPoolCompliment" },
  { 0, NULL }
};

/*
 * Monero message header.
 * - Network signature - 8 bytes
 * - Body size - 8 bytes
 * - Have to return data - 1 byte
 * - Command - 4 bytes
 * - Return code - 4 bytes
 * - Flags - 4 bytes
 * - Protocol version - 4 bytes
 */
#define MONERO_HEADER_LENGTH 8+8+1+4+4+4+4

void proto_register_monero(void);
void proto_reg_handoff_monero(void);

static dissector_handle_t monero_handle;

static int proto_monero;

static int hf_monero_signature;
static int hf_monero_length;
static int hf_monero_havetoreturn;
static int hf_monero_command;
static int hf_monero_return_code;
static int hf_monero_flags;
static int hf_monero_flags_request;
static int hf_monero_flags_response;
static int hf_monero_flags_start_fragment;
static int hf_monero_flags_end_fragment;
static int hf_monero_flags_reserved;
static int hf_monero_protocol;
static int hf_monero_payload;

static int * const flags_hf_flags[] = {
  &hf_monero_flags_request,
  &hf_monero_flags_response,
  &hf_monero_flags_start_fragment,
  &hf_monero_flags_end_fragment,
  &hf_monero_flags_reserved,
  NULL
};

static gint ett_monero;
static gint ett_flags;

static bool monero_desegment  = true;

static guint
get_monero_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb,
                       int offset, void *data _U_)
{
  guint32 length;
  length = MONERO_HEADER_LENGTH;

  /* add payload length */
  length += tvb_get_letoh64(tvb, offset+8);

  return length;
}
static int dissect_monero_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item   *ti;
  guint32       command;
  const gchar*  command_label;
  guint32       offset = 0;
  guint64       size;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Monero");

  ti   = proto_tree_add_item(tree, proto_monero, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_monero);

  /* header fields */
  proto_tree_add_item(tree,          hf_monero_signature,    tvb,   0,  8, ENC_BIG_ENDIAN);
  proto_tree_add_item(tree,          hf_monero_length,       tvb,   8,  8, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree,          hf_monero_havetoreturn, tvb,  16,  1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item_ret_uint(tree, hf_monero_command,      tvb,  17,  4, ENC_LITTLE_ENDIAN, &command);
  proto_tree_add_item(tree,          hf_monero_return_code,  tvb,  21,  4, ENC_LITTLE_ENDIAN);
  proto_tree_add_bitmask(tree, tvb, 25, hf_monero_flags, ett_flags, flags_hf_flags, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree,          hf_monero_protocol,     tvb,  29,  4, ENC_LITTLE_ENDIAN);
  offset += MONERO_HEADER_LENGTH;

  command_label = val_to_str(command, monero_commands, "[Unknown command %d]");
  col_add_str(pinfo->cinfo, COL_INFO, command_label);

  /* data payload */
  size = tvb_get_letoh64(tvb, 8);
  proto_tree_add_item(tree, hf_monero_payload, tvb, offset, (guint) size, ENC_NA);
  // offset += size;

  return tvb_reported_length(tvb);
}

static int
dissect_monero(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  col_clear(pinfo->cinfo, COL_INFO);
  tcp_dissect_pdus(tvb, pinfo, tree, monero_desegment, MONERO_HEADER_LENGTH,
      get_monero_pdu_length, dissect_monero_tcp_pdu, data);

  return tvb_reported_length(tvb);
}

static bool
dissect_monero_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  guint64 signature;
  conversation_t *conversation;

  if (tvb_captured_length(tvb) < 8)
      return false;

  signature = tvb_get_letoh64(tvb, 0);
  if (signature != MONERO_LEVIN_SIGNATURE)
     return false;

  /* Ok: This connection should always use the monero dissector */
  conversation = find_or_create_conversation(pinfo);
  conversation_set_dissector(conversation, monero_handle);

  dissect_monero(tvb, pinfo, tree, data);
  return true;
}

void
proto_register_monero(void)
{
  static hf_register_info hf[] = {
    { &hf_monero_signature,
      { "Signature", "monero.signature",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_length,
      { "Payload Length", "monero.length",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_havetoreturn,
      { "Have to return data", "monero.have_to_return_data",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_command,
      { "Command", "monero.command",
        FT_UINT32, BASE_DEC, VALS(monero_commands), 0x0,
        NULL, HFILL }
    },
    { &hf_monero_return_code,
      { "Return Code", "monero.return_code",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_flags,
      { "Flags", "monero.flags",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_flags_request,
      { "Request", "monero.flags.request",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001,
        NULL, HFILL }
    },
    { &hf_monero_flags_response,
      { "Response", "monero.flags.response",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002,
        NULL, HFILL }
    },
    { &hf_monero_flags_start_fragment,
      { "Start fragment", "monero.flags.start_fragment",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004,
        NULL, HFILL }
    },
    { &hf_monero_flags_end_fragment,
      { "End fragment", "monero.flags.end_fragment",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000008,
        NULL, HFILL }
    },
    { &hf_monero_flags_reserved,
      { "Reserved", "monero.flags.reserved",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0xfffffff0,
        NULL, HFILL }
    },
    { &hf_monero_protocol,
      { "Protocol version", "monero.version",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload,
      { "Payload", "monero.payload",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
  };

  static gint *ett[] = {
    &ett_monero,
    &ett_flags,
  };

  module_t *monero_module;

  proto_monero = proto_register_protocol("Monero protocol", "Monero", "monero");

  proto_register_subtree_array(ett, array_length(ett));
  proto_register_field_array(proto_monero, hf, array_length(hf));

  monero_handle = register_dissector("monero", dissect_monero, proto_monero);

  monero_module = prefs_register_protocol(proto_monero, NULL);
  prefs_register_bool_preference(monero_module, "desegment",
                                 "Desegment all Monero messages spanning multiple TCP segments",
                                 "Whether the Monero dissector should desegment all messages"
                                 " spanning multiple TCP segments",
                                 &monero_desegment);

}

void
proto_reg_handoff_monero(void)
{
  dissector_add_for_decode_as_with_preference("tcp.port", monero_handle);

  heur_dissector_add( "tcp", dissect_monero_heur, "Monero over TCP", "monero_tcp", proto_monero, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
