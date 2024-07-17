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
#define MONERO_PAYLOAD_MAGIC 0x011101010101020101
#define MONERO_PAYLOAD_TYPE_INT64 1
#define MONERO_PAYLOAD_TYPE_INT32 2
#define MONERO_PAYLOAD_TYPE_INT16 3
#define MONERO_PAYLOAD_TYPE_INT8 4
#define MONERO_PAYLOAD_TYPE_UINT64 5
#define MONERO_PAYLOAD_TYPE_UINT32 6
#define MONERO_PAYLOAD_TYPE_UINT16 7
#define MONERO_PAYLOAD_TYPE_UINT8 8
#define MONERO_PAYLOAD_TYPE_FLOAT64 9
#define MONERO_PAYLOAD_TYPE_STRING 10
#define MONERO_PAYLOAD_TYPE_BOOLEAN 11
#define MONERO_PAYLOAD_TYPE_STRUCT 12
#define MONERO_PAYLOAD_ARRAY 0x80

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

static const value_string payload_types[] =
{
  { MONERO_PAYLOAD_TYPE_INT64, "int64" },
  { MONERO_PAYLOAD_TYPE_INT32, "int32" },
  { MONERO_PAYLOAD_TYPE_INT16, "int16" },
  { MONERO_PAYLOAD_TYPE_INT8, "int8" },
  { MONERO_PAYLOAD_TYPE_UINT64, "uint64" },
  { MONERO_PAYLOAD_TYPE_UINT32, "uint32" },
  { MONERO_PAYLOAD_TYPE_UINT16, "uint16" },
  { MONERO_PAYLOAD_TYPE_UINT8, "uint8" },
  { MONERO_PAYLOAD_TYPE_FLOAT64, "float64" },
  { MONERO_PAYLOAD_TYPE_STRING, "string" },
  { MONERO_PAYLOAD_TYPE_BOOLEAN, "boolean" },
  { MONERO_PAYLOAD_TYPE_STRUCT, "struct" },

  { MONERO_PAYLOAD_ARRAY | MONERO_PAYLOAD_TYPE_INT64, "array[int64]" },
  { MONERO_PAYLOAD_ARRAY | MONERO_PAYLOAD_TYPE_INT32, "array[int32]" },
  { MONERO_PAYLOAD_ARRAY | MONERO_PAYLOAD_TYPE_INT16, "array[int16]" },
  { MONERO_PAYLOAD_ARRAY | MONERO_PAYLOAD_TYPE_INT8, "array[int8]" },
  { MONERO_PAYLOAD_ARRAY | MONERO_PAYLOAD_TYPE_UINT64, "array[uint64]" },
  { MONERO_PAYLOAD_ARRAY | MONERO_PAYLOAD_TYPE_UINT32, "array[uint32]" },
  { MONERO_PAYLOAD_ARRAY | MONERO_PAYLOAD_TYPE_UINT16, "array[uint16]" },
  { MONERO_PAYLOAD_ARRAY | MONERO_PAYLOAD_TYPE_UINT8, "array[uint8]" },
  { MONERO_PAYLOAD_ARRAY | MONERO_PAYLOAD_TYPE_FLOAT64, "array[float64]" },
  { MONERO_PAYLOAD_ARRAY | MONERO_PAYLOAD_TYPE_STRING, "array[string]" },
  { MONERO_PAYLOAD_ARRAY | MONERO_PAYLOAD_TYPE_BOOLEAN, "array[boolean]" },
  { MONERO_PAYLOAD_ARRAY | MONERO_PAYLOAD_TYPE_STRUCT, "array[struct]" },

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
static int hf_monero_payload_magic;
static int hf_monero_payload_item;
static int hf_monero_payload_item_key;
static int hf_monero_payload_item_type;
static int hf_monero_payload_item_size;
static int hf_monero_payload_item_length;
static int hf_monero_payload_item_value_int8;
static int hf_monero_payload_item_value_int16;
static int hf_monero_payload_item_value_int32;
static int hf_monero_payload_item_value_int64;
static int hf_monero_payload_item_value_uint8;
static int hf_monero_payload_item_value_uint16;
static int hf_monero_payload_item_value_uint32;
static int hf_monero_payload_item_value_uint64;
static int hf_monero_payload_item_value_float64;
static int hf_monero_payload_item_value_string;
static int hf_monero_payload_item_value_boolean;
static int hf_monero_payload_item_value_struct;
static int hf_monero_payload_item_value_array;

static int * const flags_hf_flags[] = {
  &hf_monero_flags_request,
  &hf_monero_flags_response,
  &hf_monero_flags_start_fragment,
  &hf_monero_flags_end_fragment,
  &hf_monero_flags_reserved,
  NULL
};

static int ett_monero;
static int ett_payload;
static int ett_struct;
static int ett_flags;

static bool monero_desegment  = true;

static expert_field ei_monero_type_unknown;

static unsigned
get_monero_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb,
                       int offset, void *data _U_)
{
  uint32_t length;
  length = MONERO_HEADER_LENGTH;

  /* add payload length */
  length += tvb_get_letoh64(tvb, offset+8);

  return length;
}

static void
get_varint(tvbuff_t *tvb, const int offset, uint8_t *length, uint64_t *ret)
{
  uint8_t flag = tvb_get_uint8(tvb, offset) & 0x03;

  switch (flag)
  {
  case 0:
    *ret = tvb_get_uint8(tvb, offset) >> 2;
    *length = 1;
    break;
  case 1:
    *ret = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN) >> 2;
    *length = 2;
    break;
  case 2:
    *ret = tvb_get_uint32(tvb, offset, ENC_LITTLE_ENDIAN) >> 2;
    *length = 4;
    break;
  case 3:
    *ret = tvb_get_uint64(tvb, offset, ENC_LITTLE_ENDIAN) >> 2;
    *length = 8;
    break;
  }
}

static int dissect_encoded_value(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *ti, int offset, uint32_t type);

// we are parsing generic data structures, recursion is a first class citizen here
// NOLINTNEXTLINE(misc-no-recursion)
static int dissect_encoded_dictionary(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset)
{
  uint8_t       length;
  uint64_t      count;
  proto_item   *sti;
  proto_tree   *stree;
  uint32_t      type;
  const uint8_t* key;

  // number of keys in the dictionary
  get_varint(tvb, offset, &length, &count);
  offset += length;

  for (; count > 0; count--)
  {
    sti   = proto_tree_add_item(tree, hf_monero_payload_item, tvb, offset, -1, ENC_NA);
    stree = proto_item_add_subtree(sti, ett_payload);

    // key
    length = tvb_get_uint8(tvb, offset);
    offset += 1;
    proto_tree_add_item_ret_string(stree, hf_monero_payload_item_key, tvb, offset, length, ENC_ASCII|ENC_NA, pinfo->pool, &key);
    if(key)
        proto_item_set_text(sti, "%s", key);
    offset += length;

    // type
    proto_tree_add_item_ret_uint(stree, hf_monero_payload_item_type, tvb, offset, 1, ENC_NA, &type);
    offset += 1;

    // value
    offset = dissect_encoded_value(tvb, pinfo, stree, sti, offset, type);

    proto_item_set_end(sti, tvb, offset);
  }

  return offset;
}

// we are parsing generic data structures, recursion is a first class citizen here
// NOLINTNEXTLINE(misc-no-recursion)
static int dissect_encoded_value(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, proto_item *ti, int offset, uint32_t type)
{
  uint8_t       length;
  uint64_t      size;
  uint64_t      string_length;
  proto_item   *struct_ti;
  proto_tree   *struct_tree;

  // array of values
  if (type & MONERO_PAYLOAD_ARRAY) {
    get_varint(tvb, offset, &length, &size);
    proto_tree_add_int64(tree, hf_monero_payload_item_size, tvb, offset, length, size);
    offset += length;

    type -= MONERO_PAYLOAD_ARRAY;

    for (; size > 0; size--) {
      if (type == MONERO_PAYLOAD_TYPE_STRING) {
        struct_ti   = proto_tree_add_item(tree, hf_monero_payload_item_value_array, tvb, offset, -1, ENC_NA);
        struct_tree = proto_item_add_subtree(struct_ti, ett_struct);

        offset = dissect_encoded_value(tvb, pinfo, struct_tree, ti, offset, type);

        proto_item_set_end(struct_ti, tvb, offset);
      }
      else {
        offset = dissect_encoded_value(tvb, pinfo, tree, ti, offset, type);
      }
    }
    return offset;
  }

  switch (type)
  {
    case MONERO_PAYLOAD_TYPE_INT64:
      proto_tree_add_item(tree, hf_monero_payload_item_value_int64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
      offset += 8;
      break;

    case MONERO_PAYLOAD_TYPE_INT32:
      proto_tree_add_item(tree, hf_monero_payload_item_value_int32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      offset += 4;
      break;

    case MONERO_PAYLOAD_TYPE_INT16:
      proto_tree_add_item(tree, hf_monero_payload_item_value_int16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      offset += 2;
      break;

    case MONERO_PAYLOAD_TYPE_INT8:
      proto_tree_add_item(tree, hf_monero_payload_item_value_int8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      offset += 1;
      break;

    case MONERO_PAYLOAD_TYPE_UINT64:
      proto_tree_add_item(tree, hf_monero_payload_item_value_uint64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
      offset += 8;
      break;

    case MONERO_PAYLOAD_TYPE_UINT32:
      proto_tree_add_item(tree, hf_monero_payload_item_value_uint32, tvb, offset, 4, ENC_LITTLE_ENDIAN);
      offset += 4;
      break;

    case MONERO_PAYLOAD_TYPE_UINT16:
      proto_tree_add_item(tree, hf_monero_payload_item_value_uint16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
      offset += 2;
      break;

    case MONERO_PAYLOAD_TYPE_UINT8:
      proto_tree_add_item(tree, hf_monero_payload_item_value_uint8, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      offset += 1;
      break;

    case MONERO_PAYLOAD_TYPE_FLOAT64:
      proto_tree_add_item(tree, hf_monero_payload_item_value_float64, tvb, offset, 8, ENC_LITTLE_ENDIAN);
      offset += 8;
      break;

    case MONERO_PAYLOAD_TYPE_STRING:
      get_varint(tvb, offset, &length, &string_length);
      proto_tree_add_int64(tree, hf_monero_payload_item_length, tvb, offset, length, string_length);
      offset += length;

      proto_tree_add_item(tree, hf_monero_payload_item_value_string, tvb, offset, (int) string_length, ENC_NA);
      offset += string_length;
      break;

    case MONERO_PAYLOAD_TYPE_BOOLEAN:
      proto_tree_add_item(tree, hf_monero_payload_item_value_int64, tvb, offset, 1, ENC_LITTLE_ENDIAN);
      offset += 1;
      break;

    case MONERO_PAYLOAD_TYPE_STRUCT:
      struct_ti   = proto_tree_add_item(tree, hf_monero_payload_item_value_struct, tvb, offset, -1, ENC_NA);
      struct_tree = proto_item_add_subtree(struct_ti, ett_struct);

      offset = dissect_encoded_dictionary(tvb, pinfo, struct_tree, offset);
      proto_item_set_end(struct_ti, tvb, offset);
      break;

    default:
      expert_add_info(pinfo, ti, &ei_monero_type_unknown);
      break;
  }

  return offset;
}

static void dissect_encoded_payload(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_monero_payload_magic, tvb, 0, 9, ENC_NA);
  dissect_encoded_dictionary(tvb, pinfo, tree, 9);
}

static int dissect_monero_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item   *ti, *payload_ti;
  proto_tree   *payload_tree;
  uint32_t      command;
  const char*  command_label;
  uint64_t      length;
  uint32_t      offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Monero");

  ti   = proto_tree_add_item(tree, proto_monero, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_monero);

  /* header fields */
  proto_tree_add_item(tree,             hf_monero_signature,    tvb,   0,  8, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_uint64(tree,  hf_monero_length,       tvb,   8,  8, ENC_LITTLE_ENDIAN, &length);
  proto_tree_add_item(tree,             hf_monero_havetoreturn, tvb,  16,  1, ENC_LITTLE_ENDIAN);
  proto_tree_add_item_ret_uint(tree,    hf_monero_command,      tvb,  17,  4, ENC_LITTLE_ENDIAN, &command);
  proto_tree_add_item(tree,             hf_monero_return_code,  tvb,  21,  4, ENC_LITTLE_ENDIAN);
  proto_tree_add_bitmask(tree, tvb, 25, hf_monero_flags, ett_flags, flags_hf_flags, ENC_LITTLE_ENDIAN);
  proto_tree_add_item(tree,             hf_monero_protocol,     tvb,  29,  4, ENC_LITTLE_ENDIAN);
  offset += MONERO_HEADER_LENGTH;

  command_label = val_to_str(command, monero_commands, "[Unknown command %d]");
  col_add_str(pinfo->cinfo, COL_INFO, command_label);

  /* data payload */
  payload_ti = proto_tree_add_item(tree, hf_monero_payload, tvb, offset, (int) length, ENC_NA);
  payload_tree = proto_item_add_subtree(payload_ti, ett_payload);
  dissect_encoded_payload(tvb_new_subset_length(tvb, offset, (int) length), pinfo, payload_tree);
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
  uint64_t signature;
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
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_magic,
      { "Magic number", "monero.payload.magic",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item,
      { "Entry", "monero.payload.item",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_key,
      { "Key", "monero.payload.item.key",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_type,
      { "Type", "monero.payload.item.type",
        FT_UINT8, BASE_DEC, VALS(payload_types), 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_size,
      { "Size", "monero.payload.item.size",
        FT_INT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_length,
      { "Length", "monero.payload.item.length",
        FT_INT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_value_int8,
      { "Value", "monero.payload.item.value.int8",
        FT_INT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_value_int16,
      { "Value", "monero.payload.item.value.int16",
        FT_INT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_value_int32,
      { "Value", "monero.payload.item.value.int32",
        FT_INT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_value_int64,
      { "Value", "monero.payload.item.value.int64",
        FT_INT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_value_uint8,
      { "Value", "monero.payload.item.value.uint8",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_value_uint16,
      { "Value", "monero.payload.item.value.uint16",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_value_uint32,
      { "Value", "monero.payload.item.value.uint32",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_value_uint64,
      { "Value", "monero.payload.item.value.uint64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_value_float64,
      { "Value", "monero.payload.item.value.float64",
        FT_DOUBLE, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_value_string,
      { "Value", "monero.payload.item.value.string",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_value_boolean,
      { "Value", "monero.payload.item.value.boolean",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_value_struct,
      { "Value", "monero.payload.item.value.struct",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_monero_payload_item_value_array,
      { "Value", "monero.payload.item.value.array",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
  };

  static int *ett[] = {
    &ett_monero,
    &ett_payload,
    &ett_struct,
    &ett_flags,
  };

  module_t *monero_module;
  expert_module_t* expert_monero;

  proto_monero = proto_register_protocol("Monero protocol", "Monero", "monero");

  proto_register_subtree_array(ett, array_length(ett));
  proto_register_field_array(proto_monero, hf, array_length(hf));

  static ei_register_info ei[] = {
     { &ei_monero_type_unknown, { "monero.payload.item.type.unknown", PI_PROTOCOL, PI_WARN, "Unknown type", EXPFILL }},
  };

  expert_monero = expert_register_protocol(proto_monero);
  expert_register_field_array(expert_monero, ei, array_length(ei));

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
