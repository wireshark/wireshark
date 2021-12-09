/* packet-bitcoin.c
 * Routines for bitcoin dissection
 * Copyright 2011, Christian Svensson <blue@cmd.nu>
 * Bitcoin address: 15Y2EN5mLnsTt3CZBfgpnZR5SeLwu7WEHz
 *
 * See https://en.bitcoin.it/wiki/Protocol_specification
 *
 * Updated 2015, Laurenz Kamp <laurenz.kamp@gmx.de>
 * Changes made:
 *   Updated dissectors:
 *     -> ping: ping packets now have a nonce.
 *     -> version: If version >= 70002, version messages have a relay flag.
 *     -> Messages with no payload: Added mempool and filterclear messages.
 *   Added dissectors:
 *     -> pong message
 *     -> notfound message
 *     -> reject message
 *     -> filterload
 *     -> filteradd
 *     -> merkleblock
 *     -> headers
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

#define BITCOIN_MAIN_MAGIC_NUMBER       0xD9B4BEF9
#define BITCOIN_TESTNET_MAGIC_NUMBER    0xDAB5BFFA
#define BITCOIN_TESTNET3_MAGIC_NUMBER   0x0709110B

static const value_string inv_types[] =
{
  { 0, "ERROR" },
  { 1, "MSG_TX" },
  { 2, "MSG_BLOCK" },
  { 0, NULL }
};

static const value_string reject_ccode[] =
{
  { 0x01, "REJECT_MALFORMED" },
  { 0x10, "REJECT_INVALID" },
  { 0x11, "REJECT_OBSOLETE" },
  { 0x12, "REJECT_DUPLICATE" },
  { 0x40, "REJECT_NONSTANDARD" },
  { 0x41, "REJECT_DUST" },
  { 0x42, "REJECT_INSUFFICIENTFEE" },
  { 0x43, "REJECT_CHECKPOINT" },
  { 0, NULL }
};

static const value_string filterload_nflags[] =
{
  { 0, "BLOOM_UPDATE_NONE" },
  { 1, "BLOOM_UPDATE_ALL" },
  { 2, "BLOOM_UPDATE_P2PUBKEY_ONLY" },
  { 0, NULL }
};

/*
 * Minimum bitcoin identification header.
 * - Magic - 4 bytes
 * - Command - 12 bytes
 * - Payload length - 4 bytes
 * - Checksum - 4 bytes
 */
#define BITCOIN_HEADER_LENGTH 4+12+4+4

void proto_register_bitcoin(void);
void proto_reg_handoff_bitcoin(void);

static dissector_handle_t bitcoin_handle;

static dissector_table_t bitcoin_command_table;

static int proto_bitcoin = -1;

static int hf_address_address = -1;
static int hf_address_port = -1;
static int hf_address_services = -1;
static int hf_bitcoin_checksum = -1;
static int hf_bitcoin_command = -1;
static int hf_bitcoin_length = -1;
static int hf_bitcoin_magic = -1;
static int hf_bitcoin_msg_addr = -1;
static int hf_bitcoin_msg_block = -1;
static int hf_bitcoin_msg_filteradd = -1;
static int hf_bitcoin_msg_filterload = -1;
static int hf_bitcoin_msg_getblocks = -1;
static int hf_bitcoin_msg_getdata = -1;
static int hf_bitcoin_msg_getheaders = -1;
static int hf_bitcoin_msg_headers = -1;
static int hf_bitcoin_msg_inv = -1;
static int hf_bitcoin_msg_merkleblock = -1;
static int hf_bitcoin_msg_notfound = -1;
static int hf_bitcoin_msg_ping = -1;
static int hf_bitcoin_msg_pong = -1;
static int hf_bitcoin_msg_reject = -1;
static int hf_bitcoin_msg_tx = -1;
static int hf_bitcoin_msg_version = -1;
static int hf_data_value = -1;
static int hf_data_varint_count16 = -1;
static int hf_data_varint_count32 = -1;
static int hf_data_varint_count64 = -1;
static int hf_data_varint_count8 = -1;
static int hf_msg_addr_address = -1;
static int hf_msg_addr_count16 = -1;
static int hf_msg_addr_count32 = -1;
static int hf_msg_addr_count64 = -1;
static int hf_msg_addr_count8 = -1;
static int hf_msg_addr_timestamp = -1;
static int hf_msg_block_bits = -1;
static int hf_msg_block_merkle_root = -1;
static int hf_msg_block_nonce = -1;
static int hf_msg_block_prev_block = -1;
static int hf_msg_block_time = -1;
static int hf_msg_block_transactions16 = -1;
static int hf_msg_block_transactions32 = -1;
static int hf_msg_block_transactions64 = -1;
static int hf_msg_block_transactions8 = -1;
static int hf_msg_block_version = -1;
static int hf_msg_filteradd_data = -1;
static int hf_msg_filterload_filter = -1;
static int hf_msg_filterload_nflags = -1;
static int hf_msg_filterload_nhashfunc = -1;
static int hf_msg_filterload_ntweak = -1;
static int hf_msg_getblocks_count16 = -1;
static int hf_msg_getblocks_count32 = -1;
static int hf_msg_getblocks_count64 = -1;
static int hf_msg_getblocks_count8 = -1;
static int hf_msg_getblocks_start = -1;
static int hf_msg_getblocks_stop = -1;
static int hf_msg_getdata_count16 = -1;
static int hf_msg_getdata_count32 = -1;
static int hf_msg_getdata_count64 = -1;
static int hf_msg_getdata_count8 = -1;
static int hf_msg_getdata_hash = -1;
static int hf_msg_getdata_type = -1;
static int hf_msg_getheaders_count16 = -1;
static int hf_msg_getheaders_count32 = -1;
static int hf_msg_getheaders_count64 = -1;
static int hf_msg_getheaders_count8 = -1;
static int hf_msg_getheaders_start = -1;
static int hf_msg_getheaders_stop = -1;
static int hf_msg_getheaders_version = -1;
static int hf_msg_headers_bits = -1;
static int hf_msg_headers_count16 = -1;
static int hf_msg_headers_count32 = -1;
static int hf_msg_headers_count64 = -1;
static int hf_msg_headers_count8 = -1;
static int hf_msg_headers_merkle_root = -1;
static int hf_msg_headers_nonce = -1;
static int hf_msg_headers_prev_block = -1;
static int hf_msg_headers_time = -1;
static int hf_msg_headers_version = -1;
static int hf_msg_inv_count16 = -1;
static int hf_msg_inv_count32 = -1;
static int hf_msg_inv_count64 = -1;
static int hf_msg_inv_count8 = -1;
static int hf_msg_inv_hash = -1;
static int hf_msg_inv_type = -1;
static int hf_msg_merkleblock_bits = -1;
static int hf_msg_merkleblock_flags_data = -1;
static int hf_msg_merkleblock_flags_size16 = -1;
static int hf_msg_merkleblock_flags_size32 = -1;
static int hf_msg_merkleblock_flags_size64 = -1;
static int hf_msg_merkleblock_flags_size8 = -1;
static int hf_msg_merkleblock_hashes_count16 = -1;
static int hf_msg_merkleblock_hashes_count32 = -1;
static int hf_msg_merkleblock_hashes_count64 = -1;
static int hf_msg_merkleblock_hashes_count8 = -1;
static int hf_msg_merkleblock_hashes_hash = -1;
static int hf_msg_merkleblock_merkle_root = -1;
static int hf_msg_merkleblock_nonce = -1;
static int hf_msg_merkleblock_prev_block = -1;
static int hf_msg_merkleblock_time = -1;
static int hf_msg_merkleblock_transactions = -1;
static int hf_msg_merkleblock_version = -1;
static int hf_msg_notfound_count16 = -1;
static int hf_msg_notfound_count32 = -1;
static int hf_msg_notfound_count64 = -1;
static int hf_msg_notfound_count8 = -1;
static int hf_msg_notfound_hash = -1;
static int hf_msg_notfound_type = -1;
static int hf_msg_ping_nonce = -1;
static int hf_msg_pong_nonce = -1;
static int hf_msg_reject_ccode = -1;
static int hf_msg_reject_data = -1;
static int hf_msg_reject_message = -1;
static int hf_msg_reject_reason = -1;
static int hf_msg_tx_in = -1;
static int hf_msg_tx_in_count16 = -1;
static int hf_msg_tx_in_count32 = -1;
static int hf_msg_tx_in_count64 = -1;
static int hf_msg_tx_in_count8 = -1;
static int hf_msg_tx_in_prev_outp_hash = -1;
static int hf_msg_tx_in_prev_outp_index = -1;
static int hf_msg_tx_in_prev_output = -1;
static int hf_msg_tx_in_script16 = -1;
static int hf_msg_tx_in_script32 = -1;
static int hf_msg_tx_in_script64 = -1;
static int hf_msg_tx_in_script8 = -1;
static int hf_msg_tx_in_seq = -1;
static int hf_msg_tx_in_sig_script = -1;
static int hf_msg_tx_lock_time = -1;
static int hf_msg_tx_out = -1;
static int hf_msg_tx_out_count16 = -1;
static int hf_msg_tx_out_count32 = -1;
static int hf_msg_tx_out_count64 = -1;
static int hf_msg_tx_out_count8 = -1;
static int hf_msg_tx_out_script = -1;
static int hf_msg_tx_out_script16 = -1;
static int hf_msg_tx_out_script32 = -1;
static int hf_msg_tx_out_script64 = -1;
static int hf_msg_tx_out_script8 = -1;
static int hf_msg_tx_out_value = -1;
static int hf_msg_tx_version = -1;
static int hf_msg_version_addr_me = -1;
static int hf_msg_version_addr_you = -1;
static int hf_msg_version_nonce = -1;
static int hf_msg_version_relay = -1;
static int hf_msg_version_services = -1;
static int hf_msg_version_start_height = -1;
static int hf_msg_version_timestamp = -1;
static int hf_msg_version_user_agent = -1;
static int hf_msg_version_version = -1;
static int hf_services_network = -1;
static int hf_string_value = -1;
static int hf_string_varint_count16 = -1;
static int hf_string_varint_count32 = -1;
static int hf_string_varint_count64 = -1;
static int hf_string_varint_count8 = -1;

static gint ett_bitcoin = -1;
static gint ett_bitcoin_msg = -1;
static gint ett_services = -1;
static gint ett_address = -1;
static gint ett_string = -1;
static gint ett_addr_list = -1;
static gint ett_inv_list = -1;
static gint ett_getdata_list = -1;
static gint ett_notfound_list = -1;
static gint ett_getblocks_list = -1;
static gint ett_getheaders_list = -1;
static gint ett_tx_in_list = -1;
static gint ett_tx_in_outp = -1;
static gint ett_tx_out_list = -1;

static expert_field ei_bitcoin_command_unknown = EI_INIT;
static expert_field ei_bitcoin_script_len = EI_INIT;


static gboolean bitcoin_desegment  = TRUE;

static guint
get_bitcoin_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb,
                       int offset, void *data _U_)
{
  guint32 length;
  length = BITCOIN_HEADER_LENGTH;

  /* add payload length */
  length += tvb_get_letohl(tvb, offset+16);

  return length;
}

/**
 * Create a services sub-tree for bit-by-bit display
 */
static proto_tree *
create_services_tree(tvbuff_t *tvb, proto_item *ti, guint32 offset)
{
  proto_tree *tree;
  guint64 services;

  tree = proto_item_add_subtree(ti, ett_services);

  /* start of services */
  /* NOTE:
   *  - 2011-06-05
   *    Currently the boolean tree only supports a maximum of
   *    32 bits - so we split services in two
   */
  services = tvb_get_letoh64(tvb, offset);

  /* service = NODE_NETWORK */
  proto_tree_add_boolean(tree, hf_services_network, tvb, offset, 4, (guint32)services);

  /* end of services */

  return tree;
}

/**
 * Create a sub-tree and fill it with a net_addr structure
 */
static proto_tree *
create_address_tree(tvbuff_t *tvb, proto_item *ti, guint32 offset)
{
  proto_tree *tree;

  tree = proto_item_add_subtree(ti, ett_address);

  /* services */
  ti = proto_tree_add_item(tree, hf_address_services, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  create_services_tree(tvb, ti, offset);
  offset += 8;

  /* IPv6 address */
  proto_tree_add_item(tree, hf_address_address, tvb, offset, 16, ENC_NA);
  offset += 16;

  /* port */
  proto_tree_add_item(tree, hf_address_port, tvb, offset, 2, ENC_BIG_ENDIAN);

  return tree;
}

/**
 * Extract a variable length integer from a tvbuff
 */
static void
get_varint(tvbuff_t *tvb, const gint offset, gint *length, guint64 *ret)
{
  guint value;

  /* Note: just throw an exception if not enough  bytes are available in the tvbuff */

  /* calculate variable length */
  value = tvb_get_guint8(tvb, offset);
  if (value < 0xfd)
  {
    *length = 1;
    *ret = value;
    return;
  }

  if (value == 0xfd)
  {
    *length = 3;
    *ret = tvb_get_letohs(tvb, offset+1);
    return;
  }
  if (value == 0xfe)
  {
    *length = 5;
    *ret = tvb_get_letohl(tvb, offset+1);
    return;
  }

  *length = 9;
  *ret = tvb_get_letoh64(tvb, offset+1);
  return;

}

static void add_varint_item(proto_tree *tree, tvbuff_t *tvb, const gint offset, gint length,
                            int hfi8, int hfi16, int hfi32, int hfi64)
{
  switch (length)
  {
  case 1:
    proto_tree_add_item(tree, hfi8,  tvb, offset, 1, ENC_LITTLE_ENDIAN);
    break;
  case 3:
    proto_tree_add_item(tree, hfi16, tvb, offset+1, 2, ENC_LITTLE_ENDIAN);
    break;
  case 5:
    proto_tree_add_item(tree, hfi32, tvb, offset+1, 4, ENC_LITTLE_ENDIAN);
    break;
  case 9:
    proto_tree_add_item(tree, hfi64, tvb, offset+1, 8, ENC_LITTLE_ENDIAN);
    break;
  }
}

static proto_tree *
create_string_tree(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint32* offset)
{
  proto_tree *subtree;
  proto_item *ti;
  gint        varint_length;
  guint64     varint;
  gint        string_length;

  /* First is the length of the following string as a varint  */
  get_varint(tvb, *offset, &varint_length, &varint);
  string_length = (gint) varint;

  ti = proto_tree_add_item(tree, hfindex, tvb, *offset, varint_length + string_length, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_string);

  /* length */
  add_varint_item(subtree, tvb, *offset, varint_length, hf_string_varint_count8,
                  hf_string_varint_count16, hf_string_varint_count32,
                  hf_string_varint_count64);
  *offset += varint_length;

  /* string */
  proto_tree_add_item(subtree, hf_string_value, tvb, *offset, string_length,
                      ENC_ASCII|ENC_NA);
  *offset += string_length;

  return subtree;
}

static proto_tree *
create_data_tree(proto_tree *tree, int hfindex, tvbuff_t *tvb, guint32* offset)
{
  proto_tree *subtree;
  proto_item *ti;
  gint        varint_length;
  guint64     varint;
  gint        data_length;

  /* First is the length of the following string as a varint  */
  get_varint(tvb, *offset, &varint_length, &varint);
  data_length = (gint) varint;

  ti = proto_tree_add_item(tree, hfindex, tvb, *offset, varint_length + data_length, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_string);

  /* length */
  add_varint_item(subtree, tvb, *offset, varint_length, hf_data_varint_count8,
                  hf_data_varint_count16, hf_data_varint_count32,
                  hf_data_varint_count64);
  *offset += varint_length;

  /* data */
  proto_tree_add_item(subtree, hf_data_value, tvb, *offset, data_length,
                      ENC_ASCII|ENC_NA);
  *offset += data_length;

  return subtree;
}

/* Note: A number of the following message handlers include code of the form:
 *          ...
 *          guint64     count;
 *          ...
 *          for (; count > 0; count--)
 *          {
 *            proto_tree_add_item9...);
 *            offset += ...;
 *            proto_tree_add_item9...);
 *            offset += ...;
 *            ...
 *          }
 *          ...
 *
 * Issue if 'count' is a very large number:
 *    If 'tree' is NULL, then the result will be effectively (but not really)
 *    an infinite loop. This is true because if 'tree' is NULL then
 *    proto_tree_add_item(tree, ...) is effectively a no-op and will not throw
 *    an exception.
 *    So: the loop should be executed only when 'tree' is defined so that the
 *        proto_ calls will throw an exception when the tvb is used up;
 *        This should only take a few-hundred loops at most.
 *           https://gitlab.com/wireshark/wireshark/-/issues/8312
 */

/**
 * Handler for version messages
 */
static int
dissect_bitcoin_msg_version(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     version;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_version, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  version = tvb_get_letohl(tvb, offset);

  proto_tree_add_item(tree, hf_msg_version_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  ti = proto_tree_add_item(tree, hf_msg_version_services, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  create_services_tree(tvb, ti, offset);
  offset += 8;

  proto_tree_add_item(tree, hf_msg_version_timestamp, tvb, offset, 8, ENC_TIME_SECS_NSECS|ENC_LITTLE_ENDIAN);
  offset += 8;

  ti = proto_tree_add_item(tree, hf_msg_version_addr_you, tvb, offset, 26, ENC_NA);
  create_address_tree(tvb, ti, offset);
  offset += 26;

  if (version >= 106)
  {
    ti = proto_tree_add_item(tree, hf_msg_version_addr_me, tvb, offset, 26, ENC_NA);
    create_address_tree(tvb, ti, offset);
    offset += 26;

    proto_tree_add_item(tree, hf_msg_version_nonce, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    create_string_tree(tree, hf_msg_version_user_agent, tvb, &offset);
  }

  if (version >= 209)
  {
    proto_tree_add_item(tree, hf_msg_version_start_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
  }

  if (version >= 70002)
  {
    proto_tree_add_item(tree, hf_msg_version_relay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;
  }

  return offset;
}

/**
 * Handler for address messages
 */
static int
dissect_bitcoin_msg_addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_addr, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, hf_msg_addr_count8, hf_msg_addr_count16,
                  hf_msg_addr_count32, hf_msg_addr_count64);
  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;

    ti = proto_tree_add_item(tree, hf_msg_addr_address, tvb, offset, 30, ENC_NA);
    subtree = create_address_tree(tvb, ti, offset+4);

    proto_tree_add_item(subtree, hf_msg_addr_timestamp, tvb, offset, 4, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
    offset += 26;
    offset += 4;
  }

  return offset;
}

/**
 * Handler for inventory messages
 */
static int
dissect_bitcoin_msg_inv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_inv, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, hf_msg_inv_count8, hf_msg_inv_count16,
                  hf_msg_inv_count32, hf_msg_inv_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 36, ett_inv_list, NULL, "Inventory vector");

    proto_tree_add_item(subtree, hf_msg_inv_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_msg_inv_hash, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  return offset;
}

/**
 * Handler for getdata messages
 */
static int
dissect_bitcoin_msg_getdata(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_getdata, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, hf_msg_getdata_count8, hf_msg_getdata_count16,
                  hf_msg_getdata_count32, hf_msg_getdata_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 36, ett_getdata_list, NULL, "Inventory vector");

    proto_tree_add_item(subtree, hf_msg_getdata_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_msg_getdata_hash, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  return offset;
}

/**
 * Handler for notfound messages
 */
static int
dissect_bitcoin_msg_notfound(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_notfound, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, hf_msg_notfound_count8, hf_msg_notfound_count16,
                  hf_msg_notfound_count32, hf_msg_notfound_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 36, ett_notfound_list, NULL, "Inventory vector");

    proto_tree_add_item(subtree, hf_msg_notfound_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_msg_notfound_hash, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  return offset;
}

/**
 * Handler for getblocks messages
 */
static int
dissect_bitcoin_msg_getblocks(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_getblocks, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  /* why the protcol version is sent here nobody knows */
  proto_tree_add_item(tree, hf_msg_version_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, hf_msg_getblocks_count8, hf_msg_getblocks_count16,
                  hf_msg_getblocks_count32, hf_msg_getblocks_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree_add_item(tree, hf_msg_getblocks_start, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  proto_tree_add_item(tree, hf_msg_getblocks_stop, tvb, offset, 32, ENC_NA);
  offset += 32;

  return offset;
}

/**
 * Handler for getheaders messages
 * UNTESTED
 */
static int
dissect_bitcoin_msg_getheaders(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_getheaders, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  proto_tree_add_item(tree, hf_msg_headers_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, hf_msg_getheaders_count8, hf_msg_getheaders_count16,
                  hf_msg_getheaders_count32, hf_msg_getheaders_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree_add_item(tree, hf_msg_getheaders_start, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  proto_tree_add_item(tree, hf_msg_getheaders_stop, tvb, offset, 32, ENC_NA);
  offset += 32;

  return offset;
}

/**
 * Handler for tx message body
 */
static guint32
dissect_bitcoin_msg_tx_common(tvbuff_t *tvb, guint32 offset, packet_info *pinfo, proto_tree *tree, guint msgnum)
{
  proto_item *rti;
  gint        count_length;
  guint64     in_count;
  guint64     out_count;

  if (msgnum == 0) {
    rti  = proto_tree_add_item(tree, hf_bitcoin_msg_tx, tvb, offset, -1, ENC_NA);
  } else {
    rti  = proto_tree_add_none_format(tree, hf_bitcoin_msg_tx, tvb, offset, -1, "Tx message [ %4d ]", msgnum);
  }
  tree = proto_item_add_subtree(rti, ett_bitcoin_msg);

  proto_tree_add_item(tree, hf_msg_tx_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  /* TxIn[] */
  get_varint(tvb, offset, &count_length, &in_count);
  add_varint_item(tree, tvb, offset, count_length, hf_msg_tx_in_count8, hf_msg_tx_in_count16,
                  hf_msg_tx_in_count32, hf_msg_tx_in_count64);

  offset += count_length;

  /* TxIn
   *   [36]  previous_output    outpoint
   *   [1+]  script length      var_int
   *   [ ?]  signature script   uchar[]
   *   [ 4]  sequence           uint32_t
   *
   * outpoint (aka previous output)
   *   [32]  hash               char[32
   *   [ 4]  index              uint32_t
   *
   */
  for (; in_count > 0; in_count--)
  {
    proto_tree *subtree;
    proto_tree *prevtree;
    proto_item *ti;
    proto_item *pti;
    guint64     script_length;
    guint32     scr_len_offset;

    scr_len_offset = offset+36;
    get_varint(tvb, scr_len_offset, &count_length, &script_length);

    /* A funny script_length won't cause an exception since the field type is FT_NONE */
    ti = proto_tree_add_item(tree, hf_msg_tx_in, tvb, offset,
        36 + count_length + (guint)script_length + 4, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_tx_in_list);

    /* previous output */
    pti = proto_tree_add_item(subtree, hf_msg_tx_in_prev_output, tvb, offset, 36, ENC_NA);
    prevtree = proto_item_add_subtree(pti, ett_tx_in_outp);

    proto_tree_add_item(prevtree, hf_msg_tx_in_prev_outp_hash, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(prevtree, hf_msg_tx_in_prev_outp_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* end previous output */

    add_varint_item(subtree, tvb, offset, count_length, hf_msg_tx_in_script8, hf_msg_tx_in_script16,
                    hf_msg_tx_in_script32, hf_msg_tx_in_script64);

    offset += count_length;

    if ((offset + script_length) > G_MAXINT) {
      proto_tree_add_expert(tree, pinfo, &ei_bitcoin_script_len,
          tvb, scr_len_offset, count_length);
      return G_MAXINT;
    }

    proto_tree_add_item(subtree, hf_msg_tx_in_sig_script, tvb, offset, (guint)script_length, ENC_NA);
    offset += (guint)script_length;

    proto_tree_add_item(subtree, hf_msg_tx_in_seq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
  }

  /* TxOut[] */
  get_varint(tvb, offset, &count_length, &out_count);
  add_varint_item(tree, tvb, offset, count_length, hf_msg_tx_out_count8, hf_msg_tx_out_count16,
                  hf_msg_tx_out_count32, hf_msg_tx_out_count64);

  offset += count_length;

  /*  TxOut
   *    [ 8] value
   *    [1+] script length [var_int]
   *    [ ?] script
   */
  for (; out_count > 0; out_count--)
  {
    proto_item *ti;
    proto_tree *subtree;
    guint64     script_length;
    guint32     scr_len_offset;

    scr_len_offset = offset+8;
    get_varint(tvb, scr_len_offset, &count_length, &script_length);

    /* A funny script_length won't cause an exception since the field type is FT_NONE */
    ti = proto_tree_add_item(tree, hf_msg_tx_out, tvb, offset,
                             8 + count_length + (guint)script_length , ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_tx_out_list);

    proto_tree_add_item(subtree, hf_msg_tx_out_value, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    add_varint_item(subtree, tvb, offset, count_length, hf_msg_tx_out_script8, hf_msg_tx_out_script16,
                    hf_msg_tx_out_script32, hf_msg_tx_out_script64);

    offset += count_length;

    if ((offset + script_length) > G_MAXINT) {
      proto_tree_add_expert(tree, pinfo, &ei_bitcoin_script_len,
          tvb, scr_len_offset, count_length);
      return G_MAXINT;
    }

    proto_tree_add_item(subtree, hf_msg_tx_out_script, tvb, offset, (guint)script_length, ENC_NA);
    offset += (guint)script_length;
  }

  proto_tree_add_item(tree, hf_msg_tx_lock_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  /* needed for block nesting */
  proto_item_set_len(rti, offset);

  return offset;
}

/**
 * Handler for tx message
 */
static int
dissect_bitcoin_msg_tx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  return dissect_bitcoin_msg_tx_common(tvb, 0, pinfo, tree, 0);
}


/**
 * Handler for block messages
 */
static int
dissect_bitcoin_msg_block(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint       msgnum;
  guint32     offset = 0;

  /*  Block
   *    [ 4] version         uint32_t
   *    [32] prev_block      char[32]
   *    [32] merkle_root     char[32]
   *    [ 4] timestamp       uint32_t  A unix timestamp ... (Currently limited to dates before the year 2106!)
   *    [ 4] bits            uint32_t
   *    [ 4] nonce           uint32_t
   *    [ ?] txn_count       var_int
   *    [ ?] txns            tx[]      Block transactions, in format of "tx" command
   */

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_block, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  proto_tree_add_item(tree, hf_msg_block_version,     tvb, offset,  4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_msg_block_prev_block,  tvb, offset, 32, ENC_NA);
  offset += 32;

  proto_tree_add_item(tree, hf_msg_block_merkle_root, tvb, offset, 32, ENC_NA);
  offset += 32;

  proto_tree_add_item(tree, hf_msg_block_time,        tvb, offset,  4, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_msg_block_bits,        tvb, offset,  4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_msg_block_nonce,       tvb, offset,  4, ENC_LITTLE_ENDIAN);
  offset += 4;

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, hf_msg_block_transactions8, hf_msg_block_transactions16,
                  hf_msg_block_transactions32, hf_msg_block_transactions64);

  offset += length;

  msgnum = 0;
  for (; count>0 && offset<G_MAXINT; count--)
  {
    msgnum += 1;
    offset = dissect_bitcoin_msg_tx_common(tvb, offset, pinfo, tree, msgnum);
  }

  return offset;
}

/**
 * Handler for headers messages
 */
static int
dissect_bitcoin_msg_headers(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_headers, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, hf_msg_headers_count8, hf_msg_headers_count16,
                  hf_msg_headers_count32, hf_msg_headers_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;
    guint64     txcount;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_bitcoin_msg, NULL, "Header");

    proto_tree_add_item(subtree, hf_msg_headers_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_msg_headers_prev_block, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(subtree, hf_msg_headers_merkle_root, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(subtree, hf_msg_headers_time, tvb, offset, 4, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_msg_headers_bits, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, hf_msg_headers_nonce, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    get_varint(tvb, offset, &length, &txcount);

    add_varint_item(subtree, tvb, offset, length, hf_msg_headers_count8, hf_msg_headers_count16,
                    hf_msg_headers_count32, hf_msg_headers_count64);

    offset += length;

    proto_item_set_len(subtree, 80 + length);
  }

  return offset;
}

/**
 * Handler for ping messages
 */
static int
dissect_bitcoin_msg_ping(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_ping, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  proto_tree_add_item(tree, hf_msg_ping_nonce, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  return offset;
}

/**
 * Handler for pong messages
 */
static int
dissect_bitcoin_msg_pong(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_pong, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  proto_tree_add_item(tree, hf_msg_pong_nonce, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  return offset;
}

/**
 * Handler for reject messages
 */
static int
dissect_bitcoin_msg_reject(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_reject, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  create_string_tree(tree, hf_msg_reject_message, tvb, &offset);

  proto_tree_add_item(tree, hf_msg_reject_ccode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  create_string_tree(tree, hf_msg_reject_reason, tvb, &offset);

  if ((tvb_reported_length(tvb) - offset) > 0)
  {
    proto_tree_add_item(tree, hf_msg_reject_data,  tvb, offset, tvb_reported_length(tvb) - offset, ENC_NA);
  }

  return offset;
}

/**
 * Handler for filterload messages
 */
static int
dissect_bitcoin_msg_filterload(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_filterload, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  create_data_tree(tree, hf_msg_filterload_filter, tvb, &offset);

  proto_tree_add_item(tree, hf_msg_filterload_nhashfunc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_msg_filterload_ntweak, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_msg_filterload_nflags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  return offset;
}

/**
 * Handler for filteradd messages
 */
static int
dissect_bitcoin_msg_filteradd(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_filteradd, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  create_data_tree(tree, hf_msg_filteradd_data, tvb, &offset);

  return offset;
}

/**
 * Handler for merkleblock messages
 */

static int
dissect_bitcoin_msg_merkleblock(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  proto_item *subtree;
  gint        length;
  guint64     count;
  guint32     offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_merkleblock, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  proto_tree_add_item(tree, hf_msg_merkleblock_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_msg_merkleblock_prev_block, tvb, offset, 32, ENC_NA);
  offset += 32;

  proto_tree_add_item(tree, hf_msg_merkleblock_merkle_root, tvb, offset, 32, ENC_NA);
  offset += 32;

  proto_tree_add_item(tree, hf_msg_merkleblock_time, tvb, offset, 4, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_msg_merkleblock_bits, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_msg_merkleblock_nonce, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, hf_msg_merkleblock_transactions, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  get_varint(tvb, offset, &length, &count);

  subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_bitcoin_msg, NULL, "Hashes");

  add_varint_item(subtree, tvb, offset, length, hf_msg_merkleblock_hashes_count8, hf_msg_merkleblock_hashes_count16,
      hf_msg_merkleblock_hashes_count32, hf_msg_merkleblock_hashes_count64);
  offset += length;

  for (; count > 0; count--)
  {
    proto_tree_add_item(subtree, hf_msg_merkleblock_hashes_hash, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  get_varint(tvb, offset, &length, &count);

  subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_bitcoin_msg, NULL, "Flags");

  add_varint_item(subtree, tvb, offset, length, hf_msg_merkleblock_flags_size8, hf_msg_merkleblock_flags_size16,
                  hf_msg_merkleblock_flags_size32, hf_msg_merkleblock_flags_size64);
  offset += length;

  /* The cast to guint is save because bitcoin messages are always smaller than 0x02000000 bytes. */
  proto_tree_add_item(subtree, hf_msg_merkleblock_flags_data, tvb, offset, (guint)count, ENC_ASCII|ENC_NA);
  offset += (guint32)count;

  return offset;
}

/**
 * Handler for unimplemented or payload-less messages
 */
static int
dissect_bitcoin_msg_empty(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_)
{
    return tvb_captured_length(tvb);
}

static int dissect_bitcoin_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
  proto_item   *ti;
  guint32       offset = 0;
  const guint8* command;
  dissector_handle_t command_handle;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Bitcoin");

  ti   = proto_tree_add_item(tree, proto_bitcoin, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin);

  /* add basic protocol data */
  proto_tree_add_item(tree, hf_bitcoin_magic,   tvb,  0,  4, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_string(tree, hf_bitcoin_command, tvb,  4, 12, ENC_ASCII|ENC_NA, pinfo->pool, &command);
  proto_tree_add_item(tree, hf_bitcoin_length,  tvb, 16,  4, ENC_LITTLE_ENDIAN);
  proto_tree_add_checksum(tree, tvb, 20, hf_bitcoin_checksum, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);

  offset = 24;

  command_handle = dissector_get_string_handle(bitcoin_command_table, command);
  if (command_handle != NULL)
  {
    /* handle command specific message part */
    tvbuff_t *tvb_sub;

    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", command);
    tvb_sub = tvb_new_subset_remaining(tvb, offset);
    call_dissector(command_handle, tvb_sub, pinfo, tree);
  }
  else
  {
    /* no handler found */
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "[unknown command]");

    expert_add_info(pinfo, ti, &ei_bitcoin_command_unknown);
  }

  return tvb_reported_length(tvb);
}

static int
dissect_bitcoin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  col_clear(pinfo->cinfo, COL_INFO);
  tcp_dissect_pdus(tvb, pinfo, tree, bitcoin_desegment, BITCOIN_HEADER_LENGTH,
      get_bitcoin_pdu_length, dissect_bitcoin_tcp_pdu, data);

  return tvb_reported_length(tvb);
}

static gboolean
dissect_bitcoin_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  guint32 magic_number;
  conversation_t *conversation;

  if (tvb_captured_length(tvb) < 4)
      return FALSE;

  magic_number = tvb_get_letohl(tvb, 0);
  if ((magic_number != BITCOIN_MAIN_MAGIC_NUMBER) &&
      (magic_number != BITCOIN_TESTNET_MAGIC_NUMBER) &&
      (magic_number != BITCOIN_TESTNET3_MAGIC_NUMBER))
     return FALSE;

  /* Ok: This connection should always use the bitcoin dissector */
  conversation = find_or_create_conversation(pinfo);
  conversation_set_dissector(conversation, bitcoin_handle);

  dissect_bitcoin(tvb, pinfo, tree, data);
  return TRUE;
}

void
proto_register_bitcoin(void)
{
  static hf_register_info hf[] = {
    { &hf_bitcoin_magic,
      { "Packet magic", "bitcoin.magic",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_command,
      { "Command name", "bitcoin.command",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_length,
      { "Payload Length", "bitcoin.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_checksum,
      { "Payload checksum", "bitcoin.checksum",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_version,
      { "Version message", "bitcoin.version",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_version_version,
      { "Protocol version", "bitcoin.version.version",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_version_services,
      { "Node services", "bitcoin.version.services",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_version_timestamp,
      { "Node timestamp", "bitcoin.version.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_version_addr_me,
      { "Address of emmitting node", "bitcoin.version.addr_me",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_version_addr_you,
      { "Address as receiving node", "bitcoin.version.addr_you",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_version_nonce,
      { "Random nonce", "bitcoin.version.nonce",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_version_user_agent,
      { "User agent", "bitcoin.version.user_agent",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_version_start_height,
      { "Block start height", "bitcoin.version.start_height",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_version_relay,
      { "Relay flag", "bitcoin.version.relay",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addr_count8,
      { "Count", "bitcoin.addr.count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addr_count16,
      { "Count", "bitcoin.addr.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addr_count32,
      { "Count", "bitcoin.addr.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addr_count64,
      { "Count", "bitcoin.addr.count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_addr,
      { "Address message", "bitcoin.addr",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addr_address,
      { "Address", "bitcoin.addr.address",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addr_timestamp,
      { "Address timestamp", "bitcoin.addr.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_inv_count8,
      { "Count", "bitcoin.inv.count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_inv_count16,
      { "Count", "bitcoin.inv.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_inv_count32,
      { "Count", "bitcoin.inv.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_inv_count64,
      { "Count", "bitcoin.inv.count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_inv,
      { "Inventory message", "bitcoin.inv",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_inv_type,
      { "Type", "bitcoin.inv.type",
        FT_UINT32, BASE_DEC, VALS(inv_types), 0x0,
        NULL, HFILL }
    },
    { &hf_msg_inv_hash,
      { "Data hash", "bitcoin.inv.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_getdata,
      { "Getdata message", "bitcoin.getdata",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getdata_count8,
      { "Count", "bitcoin.getdata.count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getdata_count16,
      { "Count", "bitcoin.getdata.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getdata_count32,
      { "Count", "bitcoin.getdata.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getdata_count64,
      { "Count", "bitcoin.getdata.count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getdata_type,
      { "Type", "bitcoin.getdata.type",
        FT_UINT32, BASE_DEC, VALS(inv_types), 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getdata_hash,
      { "Data hash", "bitcoin.getdata.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_notfound_count8,
      { "Count", "bitcoin.notfound.count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_notfound_count16,
      { "Count", "bitcoin.notfound.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_notfound_count32,
      { "Count", "bitcoin.notfound.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_notfound_count64,
      { "Count", "bitcoin.notfound.count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_notfound,
      { "Getdata message", "bitcoin.notfound",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_notfound_type,
      { "Type", "bitcoin.notfound.type",
        FT_UINT32, BASE_DEC, VALS(inv_types), 0x0,
        NULL, HFILL }
    },
    { &hf_msg_notfound_hash,
      { "Data hash", "bitcoin.notfound.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getblocks_count8,
      { "Count", "bitcoin.getblocks.count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getblocks_count16,
      { "Count", "bitcoin.getblocks.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getblocks_count32,
      { "Count", "bitcoin.getblocks.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getblocks_count64,
      { "Count", "bitcoin.getblocks.count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_getblocks,
      { "Getdata message", "bitcoin.getblocks",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getblocks_start,
      { "Starting hash", "bitcoin.getblocks.hash_start",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getblocks_stop,
      { "Stopping hash", "bitcoin.getblocks.hash_stop",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getheaders_count8,
      { "Count", "bitcoin.getheaders.count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getheaders_count16,
      { "Count", "bitcoin.getheaders.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getheaders_count32,
      { "Count", "bitcoin.getheaders.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getheaders_count64,
      { "Count", "bitcoin.getheaders.count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getheaders_version,
      { "Protocol version", "bitcoin.headers.version",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_getheaders,
      { "Getheaders message", "bitcoin.getheaders",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getheaders_start,
      { "Starting hash", "bitcoin.getheaders.hash_start",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_getheaders_stop,
      { "Stopping hash", "bitcoin.getheaders.hash_stop",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in_count8,
      { "Input Count", "bitcoin.tx.input_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in_count16,
      { "Input Count", "bitcoin.tx.input_count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in_count32,
      { "Input Count", "bitcoin.tx.input_count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in_count64,
      { "Input Count", "bitcoin.tx.input_count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_tx,
      { "Tx message", "bitcoin.tx",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_version,
      { "Transaction version", "bitcoin.tx.version",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in_script8,
      { "Script Length", "bitcoin.tx.in.script_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in_script16,
      { "Script Length", "bitcoin.tx.in.script_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in_script32,
      { "Script Length", "bitcoin.tx.in.script_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in_script64,
      { "Script Length", "bitcoin.tx.in.script_length64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in,
      { "Transaction input", "bitcoin.tx.in",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in_prev_output,
      { "Previous output", "bitcoin.tx.in.prev_output",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in_prev_outp_hash,
      { "Hash", "bitcoin.tx.in.prev_output.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in_prev_outp_index,
      { "Index", "bitcoin.tx.in.prev_output.index",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in_sig_script,
      { "Signature script", "bitcoin.tx.in.sig_script",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_in_seq,
      { "Sequence", "bitcoin.tx.in.seq",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_out_count8,
      { "Output Count", "bitcoin.tx.output_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_out_count16,
      { "Output Count", "bitcoin.tx.output_count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_out_count32,
      { "Output Count", "bitcoin.tx.output_count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_out_count64,
      { "Output Count", "bitcoin.tx.output_count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_out,
      { "Transaction output", "bitcoin.tx.out",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_out_value,
      { "Value", "bitcoin.tx.out.value",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_out_script8,
      { "Script Length", "bitcoin.tx.out.script_length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_out_script16,
      { "Script Length", "bitcoin.tx.out.script_length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_out_script32,
      { "Script Length", "bitcoin.tx.out.script_length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_out_script64,
      { "Script Length", "bitcoin.tx.out.script_length64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_out_script,
      { "Script", "bitcoin.tx.out.script",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_lock_time,
      { "Block lock time or block ID", "bitcoin.tx.lock_time",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_block_transactions8,
      { "Number of transactions", "bitcoin.block.num_transactions",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_block_transactions16,
      { "Number of transactions", "bitcoin.block.num_transactions",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_block_transactions32,
      { "Number of transactions", "bitcoin.block.num_transactions",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_block_transactions64,
      { "Number of transactions", "bitcoin.block.num_transactions64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_block,
      { "Block message", "bitcoin.block",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_block_version,
      { "Block version", "bitcoin.block.version",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_block_prev_block,
      { "Previous block", "bitcoin.block.prev_block",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_block_merkle_root,
      { "Merkle root", "bitcoin.block.merkle_root",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_block_time,
      { "Block timestamp", "bitcoin.block.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_block_bits,
      { "Bits", "bitcoin.block.bits",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_block_nonce,
      { "Nonce", "bitcoin.block.nonce",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_headers,
      { "Headers message", "bitcoin.headers",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_headers_version,
      { "Block version", "bitcoin.headers.version",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_headers_prev_block,
      { "Previous block", "bitcoin.headers.prev_block",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_headers_merkle_root,
      { "Merkle root", "bitcoin.headers.merkle_root",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_headers_time,
      { "Block timestamp", "bitcoin.headers.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_headers_bits,
      { "Bits", "bitcoin.headers.bits",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_headers_nonce,
      { "Nonce", "bitcoin.headers.nonce",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_headers_count8,
      { "Count", "bitcoin.headers.count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_headers_count16,
      { "Count", "bitcoin.headers.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_headers_count32,
      { "Count", "bitcoin.headers.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_headers_count64,
      { "Count", "bitcoin.headers.count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_ping,
      { "Ping message", "bitcoin.ping",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_ping_nonce,
      { "Random nonce", "bitcoin.ping.nonce",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_pong,
      { "Pong message", "bitcoin.pong",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_pong_nonce,
      { "Random nonce", "bitcoin.pong.nonce",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_reject,
      { "Reject message", "bitcoin.reject",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_reject_message,
      { "Message rejected", "bitcoin.reject.message",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_reject_reason,
      { "Reason", "bitcoin.reject.reason",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_reject_ccode,
      { "CCode", "bitcoin.reject.ccode",
        FT_UINT8, BASE_HEX, VALS(reject_ccode), 0x0,
        NULL, HFILL }
    },
    { &hf_msg_reject_data,
      { "Data", "bitcoin.reject.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_filterload,
      { "Filterload message", "bitcoin.filterload",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_filterload_filter,
      { "Filter", "bitcoin.filterload.filter",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_filterload_nhashfunc,
      { "nHashFunc", "bitcoin.filterload.nhashfunc",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_filterload_ntweak,
      { "nTweak", "bitcoin.filterload.ntweak",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_filterload_nflags,
      { "nFlags", "bitcoin.filterload.nflags",
        FT_UINT8, BASE_HEX, VALS(filterload_nflags), 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_filteradd,
      { "Filteradd message", "bitcoin.filteradd",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_filteradd_data,
      { "Data", "bitcoin.filteradd.data",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_merkleblock,
      { "Merkleblock message", "bitcoin.merkleblock",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_transactions,
      { "Number of transactions", "bitcoin.merkleblock.num_transactions",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_version,
      { "Block version", "bitcoin.merkleblock.version",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_prev_block,
      { "Previous block", "bitcoin.merkleblock.prev_block",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_merkle_root,
      { "Merkle root", "bitcoin.merkleblock.merkle_root",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_time,
      { "Block timestamp", "bitcoin.merkleblock.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_bits,
      { "Bits", "bitcoin.merkleblock.bits",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_nonce,
      { "Nonce", "bitcoin.merkleblock.nonce",
        FT_UINT32, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_hashes_count8,
      { "Count", "bitcoin.merkleblock.hashes.count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_hashes_count16,
      { "Count", "bitcoin.merkleblock.hashes.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_hashes_count32,
      { "Count", "bitcoin.merkleblock.hashes.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_hashes_count64,
      { "Count", "bitcoin.merkleblock.hashes.count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_hashes_hash,
      { "Hash", "bitcoin.merkleblock.hashes.hash",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_flags_size8,
      { "Size", "bitcoin.merkleblock.flags.count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_flags_size16,
      { "Size", "bitcoin.merkleblock.flags.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_flags_size32,
      { "Size", "bitcoin.merkleblock.flags.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_flags_size64,
      { "Size", "bitcoin.merkleblock.flags.count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_merkleblock_flags_data,
      { "Data", "bitcoin.merkleblock.flags.data",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_services_network,
      { "Network node", "bitcoin.services.network",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x1,
        NULL, HFILL }
    },
    { &hf_address_services,
      { "Node services", "bitcoin.address.services",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_address_address,
      { "Node address", "bitcoin.address.address",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_address_port,
      { "Node port", "bitcoin.address.port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_string_value,
      { "String value", "bitcoin.string.value",
        FT_STRING, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_string_varint_count8,
      { "Count", "bitcoin.string.count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_string_varint_count16,
      { "Count", "bitcoin.string.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_string_varint_count32,
      { "Count", "bitcoin.string.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_string_varint_count64,
      { "Count", "bitcoin.string.count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_data_value,
      { "Data", "bitcoin.data.value",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_data_varint_count8,
      { "Count", "bitcoin.data.count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_data_varint_count16,
      { "Count", "bitcoin.data.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_data_varint_count32,
      { "Count", "bitcoin.data.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_data_varint_count64,
      { "Count", "bitcoin.data.count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
  };

  static gint *ett[] = {
    &ett_bitcoin,
    &ett_bitcoin_msg,
    &ett_services,
    &ett_address,
    &ett_string,
    &ett_addr_list,
    &ett_inv_list,
    &ett_getdata_list,
    &ett_notfound_list,
    &ett_getblocks_list,
    &ett_getheaders_list,
    &ett_tx_in_list,
    &ett_tx_in_outp,
    &ett_tx_out_list,
  };

  static ei_register_info ei[] = {
     { &ei_bitcoin_command_unknown, { "bitcoin.command.unknown", PI_PROTOCOL, PI_WARN, "Unknown command", EXPFILL }},
     { &ei_bitcoin_script_len, { "bitcoin.script_length.invalid", PI_MALFORMED, PI_ERROR, "script_len too large", EXPFILL }}
  };

  module_t *bitcoin_module;
  expert_module_t* expert_bitcoin;

  proto_bitcoin = proto_register_protocol("Bitcoin protocol", "Bitcoin", "bitcoin");

  proto_register_subtree_array(ett, array_length(ett));
  proto_register_field_array(proto_bitcoin, hf, array_length(hf));

  expert_bitcoin = expert_register_protocol(proto_bitcoin);
  expert_register_field_array(expert_bitcoin, ei, array_length(ei));

  bitcoin_command_table = register_dissector_table("bitcoin.command", "Bitcoin Command", proto_bitcoin, FT_STRING, BASE_NONE);

  bitcoin_handle = register_dissector("bitcoin", dissect_bitcoin, proto_bitcoin);

  bitcoin_module = prefs_register_protocol(proto_bitcoin, NULL);
  prefs_register_bool_preference(bitcoin_module, "desegment",
                                 "Desegment all Bitcoin messages spanning multiple TCP segments",
                                 "Whether the Bitcoin dissector should desegment all messages"
                                 " spanning multiple TCP segments",
                                 &bitcoin_desegment);

}

void
proto_reg_handoff_bitcoin(void)
{
  dissector_handle_t command_handle;

  dissector_add_for_decode_as_with_preference("tcp.port", bitcoin_handle);

  heur_dissector_add( "tcp", dissect_bitcoin_heur, "Bitcoin over TCP", "bitcoin_tcp", proto_bitcoin, HEURISTIC_ENABLE);

  /* Register all of the commands */
  command_handle = create_dissector_handle( dissect_bitcoin_msg_version, proto_bitcoin );
  dissector_add_string("bitcoin.command", "version", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_addr, proto_bitcoin );
  dissector_add_string("bitcoin.command", "addr", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_inv, proto_bitcoin );
  dissector_add_string("bitcoin.command", "inv", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_getdata, proto_bitcoin );
  dissector_add_string("bitcoin.command", "getdata", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_getblocks, proto_bitcoin );
  dissector_add_string("bitcoin.command", "getblocks", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_getheaders, proto_bitcoin );
  dissector_add_string("bitcoin.command", "getheaders", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_tx, proto_bitcoin );
  dissector_add_string("bitcoin.command", "tx", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_block, proto_bitcoin );
  dissector_add_string("bitcoin.command", "block", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_ping, proto_bitcoin );
  dissector_add_string("bitcoin.command", "ping", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_pong, proto_bitcoin );
  dissector_add_string("bitcoin.command", "pong", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_notfound, proto_bitcoin );
  dissector_add_string("bitcoin.command", "notfound", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_reject, proto_bitcoin );
  dissector_add_string("bitcoin.command", "reject", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_headers, proto_bitcoin );
  dissector_add_string("bitcoin.command", "headers", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_filterload, proto_bitcoin );
  dissector_add_string("bitcoin.command", "filterload", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_filteradd, proto_bitcoin );
  dissector_add_string("bitcoin.command", "filteradd", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_merkleblock, proto_bitcoin );
  dissector_add_string("bitcoin.command", "merkleblock", command_handle);

  /* messages with no payload */
  command_handle = create_dissector_handle( dissect_bitcoin_msg_empty, proto_bitcoin );
  dissector_add_string("bitcoin.command", "verack", command_handle);
  dissector_add_string("bitcoin.command", "getaddr", command_handle);
  dissector_add_string("bitcoin.command", "mempool", command_handle);
  dissector_add_string("bitcoin.command", "filterclear", command_handle);

  /* messages not implemented */
  /* command_handle = create_dissector_handle( dissect_bitcoin_msg_empty, proto_bitcoin ); */
  dissector_add_string("bitcoin.command", "checkorder", command_handle);
  dissector_add_string("bitcoin.command", "submitorder", command_handle);
  dissector_add_string("bitcoin.command", "reply", command_handle);
  dissector_add_string("bitcoin.command", "alert", command_handle);
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
