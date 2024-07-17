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
  { 3, "MSG_FILTERED_BLOCK" },
  { 4, "MSG_CMPCT_BLOCK" },
  { 5, "MSG_WTX" },
  { 0x40000001, "MSG_WITNESS_TX" },
  { 0x40000002, "MSG_WITNESS_BLOCK" },
  { 0, NULL }
};

static const value_string network_ids[] =
{
  { 0x01, "IPv4" },
  { 0x02, "IPv6" },
  { 0x03, "Tor v2" },
  { 0x04, "Tor v3" },
  { 0x05, "I2P" },
  { 0x06, "Cjdns" },
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

static int proto_bitcoin;

static int hf_address_address;
static int hf_address_port;
static int hf_address_services;
static int hf_bitcoin_checksum;
static int hf_bitcoin_command;
static int hf_bitcoin_length;
static int hf_bitcoin_magic;
static int hf_bitcoin_msg_addr;
static int hf_bitcoin_msg_addrv2;
static int hf_bitcoin_msg_block;
static int hf_bitcoin_msg_feefilter;
static int hf_bitcoin_msg_filteradd;
static int hf_bitcoin_msg_filterload;
static int hf_bitcoin_msg_getblocks;
static int hf_bitcoin_msg_getdata;
static int hf_bitcoin_msg_getheaders;
static int hf_bitcoin_msg_headers;
static int hf_bitcoin_msg_inv;
static int hf_bitcoin_msg_merkleblock;
static int hf_bitcoin_msg_notfound;
static int hf_bitcoin_msg_ping;
static int hf_bitcoin_msg_pong;
static int hf_bitcoin_msg_reject;
static int hf_bitcoin_msg_sendcmpct;
static int hf_bitcoin_msg_tx;
static int hf_bitcoin_msg_version;
static int hf_data_value;
static int hf_data_varint_count16;
static int hf_data_varint_count32;
static int hf_data_varint_count64;
static int hf_data_varint_count8;
static int hf_msg_addr_address;
static int hf_msg_addr_count16;
static int hf_msg_addr_count32;
static int hf_msg_addr_count64;
static int hf_msg_addr_count8;
static int hf_msg_addr_timestamp;
static int hf_msg_addrv2_count16;
static int hf_msg_addrv2_count32;
static int hf_msg_addrv2_count64;
static int hf_msg_addrv2_count8;
static int hf_msg_addrv2_item;
static int hf_msg_addrv2_timestamp;
static int hf_msg_addrv2_services;
static int hf_msg_addrv2_network;
static int hf_msg_addrv2_address_ipv4;
static int hf_msg_addrv2_address_ipv6;
static int hf_msg_addrv2_address_other;
static int hf_msg_addrv2_port;
static int hf_msg_block_bits;
static int hf_msg_block_merkle_root;
static int hf_msg_block_nonce;
static int hf_msg_block_prev_block;
static int hf_msg_block_time;
static int hf_msg_block_transactions16;
static int hf_msg_block_transactions32;
static int hf_msg_block_transactions64;
static int hf_msg_block_transactions8;
static int hf_msg_block_version;
static int hf_msg_feefilter_value;
static int hf_msg_filteradd_data;
static int hf_msg_filterload_filter;
static int hf_msg_filterload_nflags;
static int hf_msg_filterload_nhashfunc;
static int hf_msg_filterload_ntweak;
static int hf_msg_getblocks_count16;
static int hf_msg_getblocks_count32;
static int hf_msg_getblocks_count64;
static int hf_msg_getblocks_count8;
static int hf_msg_getblocks_start;
static int hf_msg_getblocks_stop;
static int hf_msg_getdata_count16;
static int hf_msg_getdata_count32;
static int hf_msg_getdata_count64;
static int hf_msg_getdata_count8;
static int hf_msg_getdata_hash;
static int hf_msg_getdata_type;
static int hf_msg_getheaders_count16;
static int hf_msg_getheaders_count32;
static int hf_msg_getheaders_count64;
static int hf_msg_getheaders_count8;
static int hf_msg_getheaders_start;
static int hf_msg_getheaders_stop;
static int hf_msg_getheaders_version;
static int hf_msg_headers_bits;
static int hf_msg_headers_count16;
static int hf_msg_headers_count32;
static int hf_msg_headers_count64;
static int hf_msg_headers_count8;
static int hf_msg_headers_merkle_root;
static int hf_msg_headers_nonce;
static int hf_msg_headers_prev_block;
static int hf_msg_headers_time;
static int hf_msg_headers_version;
static int hf_msg_inv_count16;
static int hf_msg_inv_count32;
static int hf_msg_inv_count64;
static int hf_msg_inv_count8;
static int hf_msg_inv_hash;
static int hf_msg_inv_type;
static int hf_msg_merkleblock_bits;
static int hf_msg_merkleblock_flags_data;
static int hf_msg_merkleblock_flags_size16;
static int hf_msg_merkleblock_flags_size32;
static int hf_msg_merkleblock_flags_size64;
static int hf_msg_merkleblock_flags_size8;
static int hf_msg_merkleblock_hashes_count16;
static int hf_msg_merkleblock_hashes_count32;
static int hf_msg_merkleblock_hashes_count64;
static int hf_msg_merkleblock_hashes_count8;
static int hf_msg_merkleblock_hashes_hash;
static int hf_msg_merkleblock_merkle_root;
static int hf_msg_merkleblock_nonce;
static int hf_msg_merkleblock_prev_block;
static int hf_msg_merkleblock_time;
static int hf_msg_merkleblock_transactions;
static int hf_msg_merkleblock_version;
static int hf_msg_notfound_count16;
static int hf_msg_notfound_count32;
static int hf_msg_notfound_count64;
static int hf_msg_notfound_count8;
static int hf_msg_notfound_hash;
static int hf_msg_notfound_type;
static int hf_msg_ping_nonce;
static int hf_msg_pong_nonce;
static int hf_msg_reject_ccode;
static int hf_msg_reject_data;
static int hf_msg_reject_message;
static int hf_msg_reject_reason;
static int hf_msg_sendcmpct_announce;
static int hf_msg_sendcmpct_version;
static int hf_msg_tx_in;
static int hf_msg_tx_in_count16;
static int hf_msg_tx_in_count32;
static int hf_msg_tx_in_count64;
static int hf_msg_tx_in_count8;
static int hf_msg_tx_in_prev_outp_hash;
static int hf_msg_tx_in_prev_outp_index;
static int hf_msg_tx_in_prev_output;
static int hf_msg_tx_in_script16;
static int hf_msg_tx_in_script32;
static int hf_msg_tx_in_script64;
static int hf_msg_tx_in_script8;
static int hf_msg_tx_in_seq;
static int hf_msg_tx_in_sig_script;
static int hf_msg_tx_lock_time;
static int hf_msg_tx_out;
static int hf_msg_tx_out_count16;
static int hf_msg_tx_out_count32;
static int hf_msg_tx_out_count64;
static int hf_msg_tx_out_count8;
static int hf_msg_tx_out_script;
static int hf_msg_tx_out_script16;
static int hf_msg_tx_out_script32;
static int hf_msg_tx_out_script64;
static int hf_msg_tx_out_script8;
static int hf_msg_tx_out_value;
static int hf_msg_tx_witness;
static int hf_msg_tx_witness_components16;
static int hf_msg_tx_witness_components32;
static int hf_msg_tx_witness_components64;
static int hf_msg_tx_witness_components8;
static int hf_msg_tx_witness_component;
static int hf_msg_tx_witness_component_length16;
static int hf_msg_tx_witness_component_length32;
static int hf_msg_tx_witness_component_length64;
static int hf_msg_tx_witness_component_length8;
static int hf_msg_tx_witness_component_data;
static int hf_msg_tx_version;
static int hf_msg_tx_flag;
static int hf_msg_version_addr_me;
static int hf_msg_version_addr_you;
static int hf_msg_version_nonce;
static int hf_msg_version_relay;
static int hf_msg_version_services;
static int hf_msg_version_start_height;
static int hf_msg_version_timestamp;
static int hf_msg_version_user_agent;
static int hf_msg_version_version;
static int hf_services_network;
static int hf_services_getutxo;
static int hf_services_bloom;
static int hf_services_witness;
static int hf_services_xthin;
static int hf_services_compactfilters;
static int hf_services_networklimited;
static int hf_services_p2pv2;
static int hf_string_value;
static int hf_string_varint_count16;
static int hf_string_varint_count32;
static int hf_string_varint_count64;
static int hf_string_varint_count8;

static int * const services_hf_flags[] = {
  &hf_services_network,
  &hf_services_getutxo,
  &hf_services_bloom,
  &hf_services_witness,
  &hf_services_xthin,
  &hf_services_compactfilters,
  &hf_services_networklimited,
  &hf_services_p2pv2,
  NULL
};

static int ett_bitcoin;
static int ett_bitcoin_msg;
static int ett_services;
static int ett_address;
static int ett_string;
static int ett_addr_list;
static int ett_inv_list;
static int ett_getdata_list;
static int ett_notfound_list;
static int ett_getblocks_list;
static int ett_getheaders_list;
static int ett_tx_in_list;
static int ett_tx_in_outp;
static int ett_tx_out_list;
static int ett_tx_witness_list;
static int ett_tx_witness_component_list;

static expert_field ei_bitcoin_command_unknown;
static expert_field ei_bitcoin_address_length;
static expert_field ei_bitcoin_script_len;


static bool bitcoin_desegment  = true;

static unsigned
get_bitcoin_pdu_length(packet_info *pinfo _U_, tvbuff_t *tvb,
                       int offset, void *data _U_)
{
  uint32_t length;
  length = BITCOIN_HEADER_LENGTH;

  /* add payload length */
  length += tvb_get_letohl(tvb, offset+16);

  return length;
}

static void
format_feefilter_value(char *buf, int64_t value) {
  snprintf(buf, ITEM_LABEL_LENGTH, "%.3f sat/B", ((double) value) / 1000);
}

/**
 * Create a sub-tree and fill it with a net_addr structure
 */
static proto_tree *
create_address_tree(tvbuff_t *tvb, proto_item *ti, uint32_t offset)
{
  proto_tree *tree;

  tree = proto_item_add_subtree(ti, ett_address);

  /* services */
  proto_tree_add_bitmask(tree, tvb, offset, hf_address_services,
                         ett_services, services_hf_flags, ENC_LITTLE_ENDIAN);
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
get_varint(tvbuff_t *tvb, const int offset, int *length, uint64_t *ret)
{
  unsigned value;

  /* Note: just throw an exception if not enough  bytes are available in the tvbuff */

  /* calculate variable length */
  value = tvb_get_uint8(tvb, offset);
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

static void add_varint_item(proto_tree *tree, tvbuff_t *tvb, const int offset, int length,
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
create_string_tree(proto_tree *tree, int hfindex, tvbuff_t *tvb, uint32_t* offset)
{
  proto_tree *subtree;
  proto_item *ti;
  int         varint_length;
  uint64_t    varint;
  int         string_length;

  /* First is the length of the following string as a varint  */
  get_varint(tvb, *offset, &varint_length, &varint);
  string_length = (int) varint;

  ti = proto_tree_add_item(tree, hfindex, tvb, *offset, varint_length + string_length, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_string);

  /* length */
  add_varint_item(subtree, tvb, *offset, varint_length, hf_string_varint_count8,
                  hf_string_varint_count16, hf_string_varint_count32,
                  hf_string_varint_count64);
  *offset += varint_length;

  /* string */
  proto_tree_add_item(subtree, hf_string_value, tvb, *offset, string_length,
                      ENC_ASCII);
  *offset += string_length;

  return subtree;
}

static proto_tree *
create_data_tree(proto_tree *tree, int hfindex, tvbuff_t *tvb, uint32_t* offset)
{
  proto_tree *subtree;
  proto_item *ti;
  int         varint_length;
  uint64_t    varint;
  int         data_length;

  /* First is the length of the following string as a varint  */
  get_varint(tvb, *offset, &varint_length, &varint);
  data_length = (int) varint;

  ti = proto_tree_add_item(tree, hfindex, tvb, *offset, varint_length + data_length, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_string);

  /* length */
  add_varint_item(subtree, tvb, *offset, varint_length, hf_data_varint_count8,
                  hf_data_varint_count16, hf_data_varint_count32,
                  hf_data_varint_count64);
  *offset += varint_length;

  /* data */
  proto_tree_add_item(subtree, hf_data_value, tvb, *offset, data_length,
                      BASE_SHOW_UTF_8_PRINTABLE);
  *offset += data_length;

  return subtree;
}

/* Note: A number of the following message handlers include code of the form:
 *          ...
 *          uint64_t    count;
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
  uint32_t    version;
  uint32_t    offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_version, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  version = tvb_get_letohl(tvb, offset);

  proto_tree_add_item(tree, hf_msg_version_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_bitmask(tree, tvb, offset, hf_msg_version_services,
                         ett_services, services_hf_flags, ENC_LITTLE_ENDIAN);
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
  int         length;
  uint64_t    count;
  uint32_t    offset = 0;

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
 * Handler for addrv2 messages
 */
static int
dissect_bitcoin_msg_addrv2(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  int         length;
  uint64_t    count;
  uint32_t    offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_addrv2, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, hf_msg_addrv2_count8, hf_msg_addrv2_count16,
                  hf_msg_addrv2_count32, hf_msg_addrv2_count64);
  offset += length;

  for (; count > 0; count--)
  {
    proto_item *sti;
    proto_item *sti_services;
    proto_tree *subtree;
    uint64_t    services;
    uint8_t     network;
    uint64_t    address_length;

    sti = proto_tree_add_item(tree, hf_msg_addrv2_item, tvb, offset, -1, ENC_NA);
    subtree = proto_item_add_subtree(sti, ett_addr_list);

    proto_tree_add_item(subtree, hf_msg_addrv2_timestamp, tvb, offset, 4, ENC_TIME_SECS|ENC_LITTLE_ENDIAN);
    offset += 4;

    get_varint(tvb, offset, &length, &services);
    sti_services = proto_tree_add_bitmask_value(subtree, tvb, offset, hf_msg_addrv2_services,
                                                ett_services, services_hf_flags, services);
    proto_item_set_len(sti_services, length);
    offset += length;

    network = tvb_get_uint8(tvb, offset);
    proto_tree_add_item(subtree, hf_msg_addrv2_network, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset += 1;

    get_varint(tvb, offset, &length, &address_length);
    offset += length;

    switch (network)
    {
      case 1:
        proto_tree_add_item(subtree, hf_msg_addrv2_address_ipv4, tvb, offset, (unsigned) address_length, ENC_NA);
        if (address_length != 4) {
          proto_tree_add_expert(subtree, pinfo, &ei_bitcoin_address_length,
                                tvb, offset, (unsigned) address_length);
        }
        break;

      case 2:
        proto_tree_add_item(subtree, hf_msg_addrv2_address_ipv6, tvb, offset, (unsigned) address_length, ENC_NA);
        if (address_length != 16) {
          proto_tree_add_expert(subtree, pinfo, &ei_bitcoin_address_length,
                                tvb, offset, (unsigned) address_length);
        }
        break;

      default:
        proto_tree_add_item(subtree, hf_msg_addrv2_address_other, tvb, offset, (unsigned) address_length, ENC_NA);
        break;
    }
    offset += address_length;

    proto_tree_add_item(subtree, hf_msg_addrv2_port, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_item_set_end(sti, tvb, offset);
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
  int         length;
  uint64_t    count;
  uint32_t    offset = 0;

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
  int         length;
  uint64_t    count;
  uint32_t    offset = 0;

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
  int         length;
  uint64_t    count;
  uint32_t    offset = 0;

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
  int         length;
  uint64_t    count;
  uint32_t    offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_getblocks, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  /* why the protocol version is sent here nobody knows */
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
  int         length;
  uint64_t    count;
  uint32_t    offset = 0;

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
static uint32_t
dissect_bitcoin_msg_tx_common(tvbuff_t *tvb, uint32_t offset, packet_info *pinfo, proto_tree *tree, unsigned msgnum)
{
  proto_item *rti;
  int         count_length;
  uint64_t    in_count;
  uint64_t    out_count;

  if (msgnum == 0) {
    rti  = proto_tree_add_item(tree, hf_bitcoin_msg_tx, tvb, offset, -1, ENC_NA);
  } else {
    rti  = proto_tree_add_none_format(tree, hf_bitcoin_msg_tx, tvb, offset, -1, "Tx message [ %4d ]", msgnum);
  }
  tree = proto_item_add_subtree(rti, ett_bitcoin_msg);

  proto_tree_add_item(tree, hf_msg_tx_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  /* If present, "flag" always starts with 0x00. */
  /* Otherwise we proceed straight to "in_count". */
  uint8_t flag = tvb_get_uint8(tvb, offset);
  if (flag == 0) {
    proto_tree_add_item(tree, hf_msg_tx_flag, tvb, offset, 2, ENC_NA);
    offset += 2;
  }

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
  for (uint64_t idx = 0; idx < in_count; idx++)
  {
    proto_tree *subtree;
    proto_tree *prevtree;
    proto_item *ti;
    proto_item *pti;
    uint64_t    script_length;
    uint32_t    scr_len_offset;

    scr_len_offset = offset+36;
    get_varint(tvb, scr_len_offset, &count_length, &script_length);

    /* A funny script_length won't cause an exception since the field type is FT_NONE */
    ti = proto_tree_add_item(tree, hf_msg_tx_in, tvb, offset,
        36 + count_length + (unsigned)script_length + 4, ENC_NA);
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

    if ((offset + script_length) > INT_MAX) {
      proto_tree_add_expert(tree, pinfo, &ei_bitcoin_script_len,
          tvb, scr_len_offset, count_length);
      return INT_MAX;
    }

    proto_tree_add_item(subtree, hf_msg_tx_in_sig_script, tvb, offset, (unsigned)script_length, ENC_NA);
    offset += (unsigned)script_length;

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
    uint64_t    script_length;
    uint32_t    scr_len_offset;

    scr_len_offset = offset+8;
    get_varint(tvb, scr_len_offset, &count_length, &script_length);

    /* A funny script_length won't cause an exception since the field type is FT_NONE */
    ti = proto_tree_add_item(tree, hf_msg_tx_out, tvb, offset,
                             8 + count_length + (unsigned)script_length , ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_tx_out_list);

    proto_tree_add_item(subtree, hf_msg_tx_out_value, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    add_varint_item(subtree, tvb, offset, count_length, hf_msg_tx_out_script8, hf_msg_tx_out_script16,
                    hf_msg_tx_out_script32, hf_msg_tx_out_script64);

    offset += count_length;

    if ((offset + script_length) > INT_MAX) {
      proto_tree_add_expert(tree, pinfo, &ei_bitcoin_script_len,
          tvb, scr_len_offset, count_length);
      return INT_MAX;
    }

    proto_tree_add_item(subtree, hf_msg_tx_out_script, tvb, offset, (unsigned)script_length, ENC_NA);
    offset += (unsigned)script_length;
  }

  if (flag == 0) {
    /*  TxWitness
    */
    for (; in_count > 0; in_count--)
    {
      proto_item *ti;
      proto_tree *subtree;

      ti = proto_tree_add_item(tree, hf_msg_tx_witness, tvb, offset, -1, ENC_NA);
      subtree = proto_item_add_subtree(ti, ett_tx_witness_list);

      // count of witness data components
      int         component_count_length;
      uint64_t    component_count;

      get_varint(tvb, offset, &component_count_length, &component_count);
      add_varint_item(subtree, tvb, offset, component_count_length, hf_msg_tx_witness_components8,
                      hf_msg_tx_witness_components16, hf_msg_tx_witness_components32,
                      hf_msg_tx_witness_components64);
      offset += component_count_length;

      for (; component_count > 0; component_count--)
      {
        proto_item *subti;
        proto_tree *subsubtree;

        int         component_size_length;
        uint64_t    component_size;

        get_varint(tvb, offset, &component_size_length, &component_size);

        subti = proto_tree_add_item(subtree, hf_msg_tx_witness_component, tvb, offset,
                                    component_size_length + (int) component_size, ENC_NA);
        subsubtree = proto_item_add_subtree(subti, ett_tx_witness_component_list);

        add_varint_item(subsubtree, tvb, offset, component_size_length, hf_msg_tx_witness_component_length8,
                        hf_msg_tx_witness_component_length16, hf_msg_tx_witness_component_length32,
                        hf_msg_tx_witness_component_length64);
        offset += component_size_length;

        proto_tree_add_item(subsubtree, hf_msg_tx_witness_component_data, tvb, offset, (int) component_size, ENC_NA);
        offset += component_size;
      }

      proto_item_set_end(ti, tvb, offset);
    }
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
  int         length;
  uint64_t    count;
  unsigned    msgnum;
  uint32_t    offset = 0;

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
  for (; count>0 && offset<INT_MAX; count--)
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
  int         length;
  uint64_t    count;
  uint32_t    offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_headers, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, hf_msg_headers_count8, hf_msg_headers_count16,
                  hf_msg_headers_count32, hf_msg_headers_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;
    uint64_t    txcount;

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
  uint32_t    offset = 0;

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
  uint32_t    offset = 0;

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
  uint32_t    offset = 0;

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
 * Handler for feefilter messages
 */
static int
dissect_bitcoin_msg_feefilter(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  uint32_t    offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_feefilter, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  proto_tree_add_item(tree, hf_msg_feefilter_value, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

  return offset;
}

/**
 * Handler for filterload messages
 */
static int
dissect_bitcoin_msg_filterload(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  uint32_t    offset = 0;

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
  uint32_t    offset = 0;

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
  int         length;
  uint64_t    count;
  uint32_t    offset = 0;

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

  /* The cast to unsigned is save because bitcoin messages are always smaller than 0x02000000 bytes. */
  proto_tree_add_item(subtree, hf_msg_merkleblock_flags_data, tvb, offset, (unsigned)count, BASE_SHOW_UTF_8_PRINTABLE);
  offset += (uint32_t)count;

  return offset;
}

/**
 * Handler for sendcmpct messages
 */

static int
dissect_bitcoin_msg_sendcmpct(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
  proto_item *ti;
  uint32_t    offset = 0;

  ti   = proto_tree_add_item(tree, hf_bitcoin_msg_sendcmpct, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  proto_tree_add_item(tree, hf_msg_sendcmpct_announce, tvb, offset, 1, ENC_NA);
  offset += 1;

  proto_tree_add_item(tree, hf_msg_sendcmpct_version, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  offset += 8;

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
  uint32_t      offset = 0;
  const uint8_t* command;
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

static bool
dissect_bitcoin_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
  uint32_t magic_number;
  conversation_t *conversation;

  if (tvb_captured_length(tvb) < 4)
      return false;

  magic_number = tvb_get_letohl(tvb, 0);
  if ((magic_number != BITCOIN_MAIN_MAGIC_NUMBER) &&
      (magic_number != BITCOIN_TESTNET_MAGIC_NUMBER) &&
      (magic_number != BITCOIN_TESTNET3_MAGIC_NUMBER))
     return false;

  /* Ok: This connection should always use the bitcoin dissector */
  conversation = find_or_create_conversation(pinfo);
  conversation_set_dissector(conversation, bitcoin_handle);

  dissect_bitcoin(tvb, pinfo, tree, data);
  return true;
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
      { "Address of emitting node", "bitcoin.version.addr_me",
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
    { &hf_msg_addrv2_count8,
      { "Count", "bitcoin.addrv2.count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addrv2_count16,
      { "Count", "bitcoin.addrv2.count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addrv2_count32,
      { "Count", "bitcoin.addrv2.count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addrv2_count64,
      { "Count", "bitcoin.addrv2.count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addrv2_item,
      { "Address", "bitcoin.addrv2.item",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addrv2_timestamp,
      { "Timestamp", "bitcoin.addrv2.timestamp",
        FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addrv2_services,
      { "Node services", "bitcoin.addrv2.services",
        FT_UINT64, BASE_HEX, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addrv2_network,
      { "Node network", "bitcoin.addrv2.network",
        FT_UINT8, BASE_DEC, VALS(network_ids), 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addrv2_address_ipv4,
      { "Node address", "bitcoin.addrv2.address.ipv4",
        FT_IPv4, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addrv2_address_ipv6,
      { "Node address", "bitcoin.addrv2.address.ipv6",
        FT_IPv6, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addrv2_address_other,
      { "Node address", "bitcoin.addrv2.address.other",
        FT_BYTES, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_addrv2_port,
      { "Node port", "bitcoin.addrv2.port",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_addrv2,
      { "Addrv2 message", "bitcoin.addrv2",
        FT_NONE, BASE_NONE, NULL, 0x0,
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
    { &hf_msg_tx_flag,
      { "Flag", "bitcoin.tx.flag",
        FT_BYTES, BASE_NONE, NULL, 0x0,
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
    { &hf_msg_tx_witness,
      { "Transaction witness", "bitcoin.tx.witness",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_witness_components8,
      { "Number of components", "bitcoin.tx.witness.component_count",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_witness_components16,
      { "Number of components", "bitcoin.tx.witness.component_count",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_witness_components32,
      { "Number of components", "bitcoin.tx.witness.component_count",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_witness_components64,
      { "Number of components", "bitcoin.tx.witness.component_count64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_witness_component,
      { "Witness component", "bitcoin.tx.witness.component",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_witness_component_length8,
      { "Length", "bitcoin.tx.witness.component.length",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_witness_component_length16,
      { "Length", "bitcoin.tx.witness.component.length",
        FT_UINT16, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_witness_component_length32,
      { "Length", "bitcoin.tx.witness.component.length",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_witness_component_length64,
      { "Length", "bitcoin.tx.witness.component.length64",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_tx_witness_component_data,
      { "Data", "bitcoin.tx.witness.component.data",
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
    { &hf_bitcoin_msg_sendcmpct,
      { "Sendcmpct message", "bitcoin.sendcmpct",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_sendcmpct_announce,
      { "Announce", "bitcoin.sendcmpct.announce",
        FT_BOOLEAN, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_sendcmpct_version,
      { "Version", "bitcoin.sendcmpct.version",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_bitcoin_msg_feefilter,
      { "Feefilter message", "bitcoin.feefilter",
        FT_NONE, BASE_NONE, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_msg_feefilter_value,
      { "Minimal fee", "bitcoin.feefilter.value",
        FT_UINT64, BASE_CUSTOM, CF_FUNC(format_feefilter_value), 0x0,
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
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001,
        NULL, HFILL }
    },
    { &hf_services_getutxo,
      { "Getutxo node", "bitcoin.services.getutxo",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000002,
        NULL, HFILL }
    },
    { &hf_services_bloom,
      { "Bloom filter node", "bitcoin.services.bloom",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000004,
        NULL, HFILL }
    },
    { &hf_services_witness,
      { "Witness node", "bitcoin.services.witness",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000008,
        NULL, HFILL }
    },
    { &hf_services_xthin,
      { "Xtreme Thinblocks node", "bitcoin.services.xthin",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000010,
        NULL, HFILL }
    },
    { &hf_services_compactfilters,
      { "Compact filters node", "bitcoin.services.compactfilters",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000040,
        NULL, HFILL }
    },
    { &hf_services_networklimited,
      { "Limited network node", "bitcoin.services.networklimited",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000400,
        NULL, HFILL }
    },
    { &hf_services_p2pv2,
      { "Version 2 P2P node", "bitcoin.services.p2pv2",
        FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000800,
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

  static int *ett[] = {
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
    &ett_tx_witness_list,
    &ett_tx_witness_component_list,
  };

  static ei_register_info ei[] = {
     { &ei_bitcoin_command_unknown, { "bitcoin.command.unknown", PI_PROTOCOL, PI_WARN, "Unknown command", EXPFILL }},
     { &ei_bitcoin_address_length, { "bitcoin.address_length.invalid", PI_MALFORMED, PI_WARN, "Address length does not match network type", EXPFILL }},
     { &ei_bitcoin_script_len, { "bitcoin.script_length.invalid", PI_MALFORMED, PI_ERROR, "script_len too large", EXPFILL }}
  };

  module_t *bitcoin_module;
  expert_module_t* expert_bitcoin;

  proto_bitcoin = proto_register_protocol("Bitcoin protocol", "Bitcoin", "bitcoin");

  proto_register_subtree_array(ett, array_length(ett));
  proto_register_field_array(proto_bitcoin, hf, array_length(hf));

  expert_bitcoin = expert_register_protocol(proto_bitcoin);
  expert_register_field_array(expert_bitcoin, ei, array_length(ei));

  bitcoin_command_table = register_dissector_table("bitcoin.command", "Bitcoin Command", proto_bitcoin, FT_STRING, STRING_CASE_SENSITIVE);

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
  command_handle = create_dissector_handle( dissect_bitcoin_msg_addrv2, proto_bitcoin );
  dissector_add_string("bitcoin.command", "addrv2", command_handle);
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
  command_handle = create_dissector_handle( dissect_bitcoin_msg_feefilter, proto_bitcoin );
  dissector_add_string("bitcoin.command", "feefilter", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_filterload, proto_bitcoin );
  dissector_add_string("bitcoin.command", "filterload", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_filteradd, proto_bitcoin );
  dissector_add_string("bitcoin.command", "filteradd", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_merkleblock, proto_bitcoin );
  dissector_add_string("bitcoin.command", "merkleblock", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_sendcmpct, proto_bitcoin );
  dissector_add_string("bitcoin.command", "sendcmpct", command_handle);

  /* messages with no payload */
  command_handle = create_dissector_handle( dissect_bitcoin_msg_empty, proto_bitcoin );
  dissector_add_string("bitcoin.command", "verack", command_handle);
  dissector_add_string("bitcoin.command", "getaddr", command_handle);
  dissector_add_string("bitcoin.command", "mempool", command_handle);
  dissector_add_string("bitcoin.command", "filterclear", command_handle);
  dissector_add_string("bitcoin.command", "sendaddrv2", command_handle);
  dissector_add_string("bitcoin.command", "sendheaders", command_handle);
  dissector_add_string("bitcoin.command", "wtxidrelay", command_handle);

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
