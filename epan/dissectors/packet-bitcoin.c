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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define NEW_PROTO_TREE_API

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

static header_field_info *hfi_bitcoin = NULL;

#define BITCOIN_HFI_INIT HFI_INIT(proto_bitcoin)

static header_field_info hfi_bitcoin_magic BITCOIN_HFI_INIT =
  { "Packet magic", "bitcoin.magic", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_bitcoin_command BITCOIN_HFI_INIT =
  { "Command name", "bitcoin.command", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_bitcoin_length BITCOIN_HFI_INIT =
  { "Payload Length", "bitcoin.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_bitcoin_checksum BITCOIN_HFI_INIT =
  { "Payload checksum", "bitcoin.checksum", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

/* version message */
static header_field_info hfi_bitcoin_msg_version BITCOIN_HFI_INIT =
  { "Version message", "bitcoin.version", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_version BITCOIN_HFI_INIT =
  { "Protocol version", "bitcoin.version.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_services BITCOIN_HFI_INIT =
  { "Node services", "bitcoin.version.services", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_timestamp BITCOIN_HFI_INIT =
  { "Node timestamp", "bitcoin.version.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_addr_me BITCOIN_HFI_INIT =
  { "Address of emmitting node", "bitcoin.version.addr_me", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_addr_you BITCOIN_HFI_INIT =
  { "Address as receiving node", "bitcoin.version.addr_you", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_nonce BITCOIN_HFI_INIT =
  { "Random nonce", "bitcoin.version.nonce", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_user_agent BITCOIN_HFI_INIT =
  { "User agent", "bitcoin.version.user_agent", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_start_height BITCOIN_HFI_INIT =
  { "Block start height", "bitcoin.version.start_height", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_version_relay BITCOIN_HFI_INIT =
  { "Relay flag", "bitcoin.version.relay", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* addr message */
static header_field_info hfi_msg_addr_count8 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.addr.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_count16 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.addr.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_count32 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.addr.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_count64 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.addr.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_bitcoin_msg_addr BITCOIN_HFI_INIT =
  { "Address message", "bitcoin.addr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_address BITCOIN_HFI_INIT =
  { "Address", "bitcoin.addr.address", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_addr_timestamp BITCOIN_HFI_INIT =
  { "Address timestamp", "bitcoin.addr.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

/* inv message */
static header_field_info hfi_msg_inv_count8 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.inv.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_count16 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.inv.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_count32 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.inv.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_count64 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.inv.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_bitcoin_msg_inv BITCOIN_HFI_INIT =
  { "Inventory message", "bitcoin.inv", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_type BITCOIN_HFI_INIT =
  { "Type", "bitcoin.inv.type", FT_UINT32, BASE_DEC, VALS(inv_types), 0x0, NULL, HFILL };

static header_field_info hfi_msg_inv_hash BITCOIN_HFI_INIT =
  { "Data hash", "bitcoin.inv.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* getdata message */
static header_field_info hfi_bitcoin_msg_getdata BITCOIN_HFI_INIT =
  { "Getdata message", "bitcoin.getdata", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_count8 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.getdata.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_count16 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.getdata.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_count32 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.getdata.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_count64 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.getdata.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_type BITCOIN_HFI_INIT =
  { "Type", "bitcoin.getdata.type", FT_UINT32, BASE_DEC, VALS(inv_types), 0x0, NULL, HFILL };

static header_field_info hfi_msg_getdata_hash BITCOIN_HFI_INIT =
  { "Data hash", "bitcoin.getdata.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* notfound message */
static header_field_info hfi_msg_notfound_count8 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.notfound.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_notfound_count16 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.notfound.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_notfound_count32 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.notfound.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_notfound_count64 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.notfound.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_bitcoin_msg_notfound BITCOIN_HFI_INIT =
  { "Getdata message", "bitcoin.notfound", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_notfound_type BITCOIN_HFI_INIT =
  { "Type", "bitcoin.notfound.type", FT_UINT32, BASE_DEC, VALS(inv_types), 0x0, NULL, HFILL };

static header_field_info hfi_msg_notfound_hash BITCOIN_HFI_INIT =
  { "Data hash", "bitcoin.notfound.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* getblocks message */
static header_field_info hfi_msg_getblocks_count8 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.getblocks.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_count16 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.getblocks.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_count32 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.getblocks.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_count64 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.getblocks.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_bitcoin_msg_getblocks BITCOIN_HFI_INIT =
  { "Getdata message", "bitcoin.getblocks", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_start BITCOIN_HFI_INIT =
  { "Starting hash", "bitcoin.getblocks.hash_start", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getblocks_stop BITCOIN_HFI_INIT =
  { "Stopping hash", "bitcoin.getblocks.hash_stop", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* getheaders message */
static header_field_info hfi_msg_getheaders_count8 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.getheaders.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_count16 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.getheaders.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_count32 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.getheaders.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_count64 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.getheaders.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

#if 0
static header_field_info hfi_msg_getheaders_version BITCOIN_HFI_INIT =
  { "Protocol version", "bitcoin.headers.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };
#endif

static header_field_info hfi_bitcoin_msg_getheaders BITCOIN_HFI_INIT =
  { "Getheaders message", "bitcoin.getheaders", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_start BITCOIN_HFI_INIT =
  { "Starting hash", "bitcoin.getheaders.hash_start", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_getheaders_stop BITCOIN_HFI_INIT =
  { "Stopping hash", "bitcoin.getheaders.hash_stop", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* tx message */
static header_field_info hfi_msg_tx_in_count8 BITCOIN_HFI_INIT =
  { "Input Count", "bitcoin.tx.input_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_count16 BITCOIN_HFI_INIT =
  { "Input Count", "bitcoin.tx.input_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_count32 BITCOIN_HFI_INIT =
  { "Input Count", "bitcoin.tx.input_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_count64 BITCOIN_HFI_INIT =
  { "Input Count", "bitcoin.tx.input_count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_bitcoin_msg_tx BITCOIN_HFI_INIT =
  { "Tx message", "bitcoin.tx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_version BITCOIN_HFI_INIT =
  { "Transaction version", "bitcoin.tx.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_script8 BITCOIN_HFI_INIT =
  { "Script Length", "bitcoin.tx.in.script_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_script16 BITCOIN_HFI_INIT =
  { "Script Length", "bitcoin.tx.in.script_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_script32 BITCOIN_HFI_INIT =
  { "Script Length", "bitcoin.tx.in.script_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_script64 BITCOIN_HFI_INIT =
  { "Script Length", "bitcoin.tx.in.script_length64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in BITCOIN_HFI_INIT =
  { "Transaction input", "bitcoin.tx.in", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_prev_output BITCOIN_HFI_INIT =
  { "Previous output", "bitcoin.tx.in.prev_output", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_prev_outp_hash BITCOIN_HFI_INIT =
  { "Hash", "bitcoin.tx.in.prev_output.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_prev_outp_index BITCOIN_HFI_INIT =
  { "Index", "bitcoin.tx.in.prev_output.index", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_sig_script BITCOIN_HFI_INIT =
  { "Signature script", "bitcoin.tx.in.sig_script", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_in_seq BITCOIN_HFI_INIT =
  { "Sequence", "bitcoin.tx.in.seq", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_count8 BITCOIN_HFI_INIT =
  { "Output Count", "bitcoin.tx.output_count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_count16 BITCOIN_HFI_INIT =
  { "Output Count", "bitcoin.tx.output_count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_count32 BITCOIN_HFI_INIT =
  { "Output Count", "bitcoin.tx.output_count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_count64 BITCOIN_HFI_INIT =
  { "Output Count", "bitcoin.tx.output_count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out BITCOIN_HFI_INIT =
  { "Transaction output", "bitcoin.tx.out", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_value BITCOIN_HFI_INIT =
  { "Value", "bitcoin.tx.out.value", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script8 BITCOIN_HFI_INIT =
  { "Script Length", "bitcoin.tx.out.script_length", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script16 BITCOIN_HFI_INIT =
  { "Script Length", "bitcoin.tx.out.script_length", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script32 BITCOIN_HFI_INIT =
  { "Script Length", "bitcoin.tx.out.script_length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script64 BITCOIN_HFI_INIT =
  { "Script Length", "bitcoin.tx.out.script_length64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_out_script BITCOIN_HFI_INIT =
  { "Script", "bitcoin.tx.out.script", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_tx_lock_time BITCOIN_HFI_INIT =
  { "Block lock time or block ID", "bitcoin.tx.lock_time", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* block message */
static header_field_info hfi_msg_block_transactions8 BITCOIN_HFI_INIT =
  { "Number of transactions", "bitcoin.block.num_transactions", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_transactions16 BITCOIN_HFI_INIT =
  { "Number of transactions", "bitcoin.block.num_transactions", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_transactions32 BITCOIN_HFI_INIT =
  { "Number of transactions", "bitcoin.block.num_transactions", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_transactions64 BITCOIN_HFI_INIT =
  { "Number of transactions", "bitcoin.block.num_transactions64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_bitcoin_msg_block BITCOIN_HFI_INIT =
  { "Block message", "bitcoin.block", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_version BITCOIN_HFI_INIT =
  { "Block version", "bitcoin.block.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_prev_block BITCOIN_HFI_INIT =
  { "Previous block", "bitcoin.block.prev_block", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_merkle_root BITCOIN_HFI_INIT =
  { "Merkle root", "bitcoin.block.merkle_root", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_time BITCOIN_HFI_INIT =
  { "Block timestamp", "bitcoin.block.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_bits BITCOIN_HFI_INIT =
  { "Bits", "bitcoin.block.bits", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_block_nonce BITCOIN_HFI_INIT =
  { "Nonce", "bitcoin.block.nonce", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

/* headers message */
static header_field_info hfi_bitcoin_msg_headers BITCOIN_HFI_INIT =
  { "Headers message", "bitcoin.headers", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_version BITCOIN_HFI_INIT =
  { "Block version", "bitcoin.headers.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_prev_block BITCOIN_HFI_INIT =
  { "Previous block", "bitcoin.headers.prev_block", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_merkle_root BITCOIN_HFI_INIT =
  { "Merkle root", "bitcoin.headers.merkle_root", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_time BITCOIN_HFI_INIT =
  { "Block timestamp", "bitcoin.headers.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_bits BITCOIN_HFI_INIT =
  { "Bits", "bitcoin.headers.bits", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_nonce BITCOIN_HFI_INIT =
  { "Nonce", "bitcoin.headers.nonce", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_count8 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.headers.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_count16 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.headers.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_count32 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.headers.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_headers_count64 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.headers.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* ping message */
static header_field_info hfi_bitcoin_msg_ping BITCOIN_HFI_INIT =
  { "Ping message", "bitcoin.ping", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_ping_nonce BITCOIN_HFI_INIT =
  { "Random nonce", "bitcoin.ping.nonce", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

/* pong message */
static header_field_info hfi_bitcoin_msg_pong BITCOIN_HFI_INIT =
  { "Pong message", "bitcoin.pong", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_pong_nonce BITCOIN_HFI_INIT =
  { "Random nonce", "bitcoin.pong.nonce", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

/* reject message */
static header_field_info hfi_bitcoin_msg_reject BITCOIN_HFI_INIT =
  { "Reject message", "bitcoin.reject", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_reject_message BITCOIN_HFI_INIT =
  { "Message rejected", "bitcoin.reject.message", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_reject_reason BITCOIN_HFI_INIT =
  { "Reason", "bitcoin.reject.reason", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_reject_ccode BITCOIN_HFI_INIT =
  { "CCode", "bitcoin.reject.ccode", FT_UINT8, BASE_HEX, VALS(reject_ccode), 0x0, NULL, HFILL };

static header_field_info hfi_msg_reject_data BITCOIN_HFI_INIT =
  { "Data", "bitcoin.reject.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* filterload message */
static header_field_info hfi_bitcoin_msg_filterload BITCOIN_HFI_INIT =
  { "Filterload message", "bitcoin.filterload", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_filterload_filter BITCOIN_HFI_INIT =
  { "Filter", "bitcoin.filterload.filter", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_filterload_nhashfunc BITCOIN_HFI_INIT =
  { "nHashFunc", "bitcoin.filterload.nhashfunc", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_filterload_ntweak BITCOIN_HFI_INIT =
  { "nTweak", "bitcoin.filterload.ntweak", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_filterload_nflags BITCOIN_HFI_INIT =
  { "nFlags", "bitcoin.filterload.nflags", FT_UINT8, BASE_HEX, VALS(filterload_nflags), 0x0, NULL, HFILL };

/* filteradd message */
static header_field_info hfi_bitcoin_msg_filteradd BITCOIN_HFI_INIT =
  { "Filteradd message", "bitcoin.filteradd", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_filteradd_data BITCOIN_HFI_INIT =
  { "Data", "bitcoin.filteradd.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* merkleblock message */
static header_field_info hfi_bitcoin_msg_merkleblock BITCOIN_HFI_INIT =
  { "Merkleblock message", "bitcoin.merkleblock", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_transactions BITCOIN_HFI_INIT =
  { "Number of transactions", "bitcoin.merkleblock.num_transactions", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_version BITCOIN_HFI_INIT =
  { "Block version", "bitcoin.merkleblock.version", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_prev_block BITCOIN_HFI_INIT =
  { "Previous block", "bitcoin.merkleblock.prev_block", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_merkle_root BITCOIN_HFI_INIT =
  { "Merkle root", "bitcoin.merkleblock.merkle_root", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_time BITCOIN_HFI_INIT =
  { "Block timestamp", "bitcoin.merkleblock.timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_bits BITCOIN_HFI_INIT =
  { "Bits", "bitcoin.merkleblock.bits", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_nonce BITCOIN_HFI_INIT =
  { "Nonce", "bitcoin.merkleblock.nonce", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_hashes_count8 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.merkleblock.hashes.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_hashes_count16 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.merkleblock.hashes.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_hashes_count32 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.merkleblock.hashes.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_hashes_count64 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.merkleblock.hashes.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_hashes_hash BITCOIN_HFI_INIT =
  { "Hash", "bitcoin.merkleblock.hashes.hash", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_flags_size8 BITCOIN_HFI_INIT =
  { "Size", "bitcoin.merkleblock.flags.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_flags_size16 BITCOIN_HFI_INIT =
  { "Size", "bitcoin.merkleblock.flags.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_flags_size32 BITCOIN_HFI_INIT =
  { "Size", "bitcoin.merkleblock.flags.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_flags_size64 BITCOIN_HFI_INIT =
  { "Size", "bitcoin.merkleblock.flags.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_msg_merkleblock_flags_data BITCOIN_HFI_INIT =
  { "Data", "bitcoin.merkleblock.flags.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

/* services */
static header_field_info hfi_services_network BITCOIN_HFI_INIT =
  { "Network node", "bitcoin.services.network", FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x1, NULL, HFILL };

/* address */
static header_field_info hfi_address_services BITCOIN_HFI_INIT =
  { "Node services", "bitcoin.address.services", FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_address_address BITCOIN_HFI_INIT =
  { "Node address", "bitcoin.address.address", FT_IPv6, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_address_port BITCOIN_HFI_INIT =
  { "Node port", "bitcoin.address.port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* variable string */
static header_field_info hfi_string_value BITCOIN_HFI_INIT =
  { "String value", "bitcoin.string.value", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_string_varint_count8 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.string.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_string_varint_count16 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.string.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_string_varint_count32 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.string.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_string_varint_count64 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.string.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };

/* variable data */
static header_field_info hfi_data_value BITCOIN_HFI_INIT =
  { "Data", "bitcoin.data.value", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_data_varint_count8 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.data.count", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_data_varint_count16 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.data.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_data_varint_count32 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.data.count", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL };

static header_field_info hfi_data_varint_count64 BITCOIN_HFI_INIT =
  { "Count", "bitcoin.data.count64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL };


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
  proto_tree_add_boolean(tree, &hfi_services_network, tvb, offset, 4, (guint32)services);

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
  ti = proto_tree_add_item(tree, &hfi_address_services, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  create_services_tree(tvb, ti, offset);
  offset += 8;

  /* IPv6 address */
  proto_tree_add_item(tree, &hfi_address_address, tvb, offset, 16, ENC_NA);
  offset += 16;

  /* port */
  proto_tree_add_item(tree, &hfi_address_port, tvb, offset, 2, ENC_BIG_ENDIAN);

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
                            header_field_info *hfi8, header_field_info *hfi16, header_field_info *hfi32, header_field_info *hfi64)
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
create_string_tree(proto_tree *tree, header_field_info* hfi, tvbuff_t *tvb, guint32* offset)
{
  proto_tree *subtree;
  proto_item *ti;
  gint        varint_length;
  guint64     varint;
  gint        string_length;

  /* First is the length of the following string as a varint  */
  get_varint(tvb, *offset, &varint_length, &varint);
  string_length = (gint) varint;

  ti = proto_tree_add_item(tree, hfi, tvb, *offset, varint_length + string_length, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_string);

  /* length */
  add_varint_item(subtree, tvb, *offset, varint_length, &hfi_string_varint_count8,
                  &hfi_string_varint_count16, &hfi_string_varint_count32,
                  &hfi_string_varint_count64);
  *offset += varint_length;

  /* string */
  proto_tree_add_item(subtree, &hfi_string_value, tvb, *offset, string_length,
                      ENC_ASCII|ENC_NA);
  *offset += string_length;

  return subtree;
}

static proto_tree *
create_data_tree(proto_tree *tree, header_field_info* hfi, tvbuff_t *tvb, guint32* offset)
{
  proto_tree *subtree;
  proto_item *ti;
  gint        varint_length;
  guint64     varint;
  gint        data_length;

  /* First is the length of the following string as a varint  */
  get_varint(tvb, *offset, &varint_length, &varint);
  data_length = (gint) varint;

  ti = proto_tree_add_item(tree, hfi, tvb, *offset, varint_length + data_length, ENC_NA);
  subtree = proto_item_add_subtree(ti, ett_string);

  /* length */
  add_varint_item(subtree, tvb, *offset, varint_length, &hfi_data_varint_count8,
                  &hfi_data_varint_count16, &hfi_data_varint_count32,
                  &hfi_data_varint_count64);
  *offset += varint_length;

  /* data */
  proto_tree_add_item(subtree, &hfi_data_value, tvb, *offset, data_length,
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
 *           https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=8312
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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_version, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  version = tvb_get_letohl(tvb, offset);

  proto_tree_add_item(tree, &hfi_msg_version_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  ti = proto_tree_add_item(tree, &hfi_msg_version_services, tvb, offset, 8, ENC_LITTLE_ENDIAN);
  create_services_tree(tvb, ti, offset);
  offset += 8;

  proto_tree_add_item(tree, &hfi_msg_version_timestamp, tvb, offset, 8, ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN);
  offset += 8;

  ti = proto_tree_add_item(tree, &hfi_msg_version_addr_you, tvb, offset, 26, ENC_NA);
  create_address_tree(tvb, ti, offset);
  offset += 26;

  if (version >= 106)
  {
    ti = proto_tree_add_item(tree, &hfi_msg_version_addr_me, tvb, offset, 26, ENC_NA);
    create_address_tree(tvb, ti, offset);
    offset += 26;

    proto_tree_add_item(tree, &hfi_msg_version_nonce, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    create_string_tree(tree, &hfi_msg_version_user_agent, tvb, &offset);
  }

  if (version >= 209)
  {
    proto_tree_add_item(tree, &hfi_msg_version_start_height, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
  }

  if (version >= 70002)
  {
    proto_tree_add_item(tree, &hfi_msg_version_relay, tvb, offset, 1, ENC_LITTLE_ENDIAN);
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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_addr, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_addr_count8, &hfi_msg_addr_count16,
                  &hfi_msg_addr_count32, &hfi_msg_addr_count64);
  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;

    ti = proto_tree_add_item(tree, &hfi_msg_addr_address, tvb, offset, 30, ENC_NA);
    subtree = create_address_tree(tvb, ti, offset+4);

    proto_tree_add_item(subtree, &hfi_msg_addr_timestamp, tvb, offset, 4, ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN);
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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_inv, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_inv_count8, &hfi_msg_inv_count16,
                  &hfi_msg_inv_count32, &hfi_msg_inv_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 36, ett_inv_list, NULL, "Inventory vector");

    proto_tree_add_item(subtree, &hfi_msg_inv_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, &hfi_msg_inv_hash, tvb, offset, 32, ENC_NA);
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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_getdata, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_getdata_count8, &hfi_msg_getdata_count16,
                  &hfi_msg_getdata_count32, &hfi_msg_getdata_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 36, ett_getdata_list, NULL, "Inventory vector");

    proto_tree_add_item(subtree, &hfi_msg_getdata_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, &hfi_msg_getdata_hash, tvb, offset, 32, ENC_NA);
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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_notfound, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_notfound_count8, &hfi_msg_notfound_count16,
                  &hfi_msg_notfound_count32, &hfi_msg_notfound_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;

    subtree = proto_tree_add_subtree(tree, tvb, offset, 36, ett_notfound_list, NULL, "Inventory vector");

    proto_tree_add_item(subtree, &hfi_msg_notfound_type, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, &hfi_msg_notfound_hash, tvb, offset, 32, ENC_NA);
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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_getblocks, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  /* why the protcol version is sent here nobody knows */
  proto_tree_add_item(tree, &hfi_msg_version_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_getblocks_count8, &hfi_msg_getblocks_count16,
                  &hfi_msg_getblocks_count32, &hfi_msg_getblocks_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree_add_item(tree, &hfi_msg_getblocks_start, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  proto_tree_add_item(tree, &hfi_msg_getblocks_stop, tvb, offset, 32, ENC_NA);
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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_getheaders, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  proto_tree_add_item(tree, &hfi_msg_headers_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_getheaders_count8, &hfi_msg_getheaders_count16,
                  &hfi_msg_getheaders_count32, &hfi_msg_getheaders_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree_add_item(tree, &hfi_msg_getheaders_start, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  proto_tree_add_item(tree, &hfi_msg_getheaders_stop, tvb, offset, 32, ENC_NA);
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
    rti  = proto_tree_add_item(tree, &hfi_bitcoin_msg_tx, tvb, offset, -1, ENC_NA);
  } else {
    rti  = proto_tree_add_none_format(tree, hfi_bitcoin_msg_tx.id, tvb, offset, -1, "Tx message [ %4d ]", msgnum);
  }
  tree = proto_item_add_subtree(rti, ett_bitcoin_msg);

  proto_tree_add_item(tree, &hfi_msg_tx_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  /* TxIn[] */
  get_varint(tvb, offset, &count_length, &in_count);
  add_varint_item(tree, tvb, offset, count_length, &hfi_msg_tx_in_count8, &hfi_msg_tx_in_count16,
                  &hfi_msg_tx_in_count32, &hfi_msg_tx_in_count64);

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
    ti = proto_tree_add_item(tree, &hfi_msg_tx_in, tvb, offset,
        36 + count_length + (guint)script_length + 4, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_tx_in_list);

    /* previous output */
    pti = proto_tree_add_item(subtree, &hfi_msg_tx_in_prev_output, tvb, offset, 36, ENC_NA);
    prevtree = proto_item_add_subtree(pti, ett_tx_in_outp);

    proto_tree_add_item(prevtree, &hfi_msg_tx_in_prev_outp_hash, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(prevtree, &hfi_msg_tx_in_prev_outp_index, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
    /* end previous output */

    add_varint_item(subtree, tvb, offset, count_length, &hfi_msg_tx_in_script8, &hfi_msg_tx_in_script16,
                    &hfi_msg_tx_in_script32, &hfi_msg_tx_in_script64);

    offset += count_length;

    if ((offset + script_length) > G_MAXINT) {
      proto_tree_add_expert(tree, pinfo, &ei_bitcoin_script_len,
          tvb, scr_len_offset, count_length);
      return G_MAXINT;
    }

    proto_tree_add_item(subtree, &hfi_msg_tx_in_sig_script, tvb, offset, (guint)script_length, ENC_NA);
    offset += (guint)script_length;

    proto_tree_add_item(subtree, &hfi_msg_tx_in_seq, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;
  }

  /* TxOut[] */
  get_varint(tvb, offset, &count_length, &out_count);
  add_varint_item(tree, tvb, offset, count_length, &hfi_msg_tx_out_count8, &hfi_msg_tx_out_count16,
                  &hfi_msg_tx_out_count32, &hfi_msg_tx_out_count64);

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
    ti = proto_tree_add_item(tree, &hfi_msg_tx_out, tvb, offset,
                             8 + count_length + (guint)script_length , ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_tx_out_list);

    proto_tree_add_item(subtree, &hfi_msg_tx_out_value, tvb, offset, 8, ENC_LITTLE_ENDIAN);
    offset += 8;

    add_varint_item(subtree, tvb, offset, count_length, &hfi_msg_tx_out_script8, &hfi_msg_tx_out_script16,
                    &hfi_msg_tx_out_script32, &hfi_msg_tx_out_script64);

    offset += count_length;

    if ((offset + script_length) > G_MAXINT) {
      proto_tree_add_expert(tree, pinfo, &ei_bitcoin_script_len,
          tvb, scr_len_offset, count_length);
      return G_MAXINT;
    }

    proto_tree_add_item(subtree, &hfi_msg_tx_out_script, tvb, offset, (guint)script_length, ENC_NA);
    offset += (guint)script_length;
  }

  proto_tree_add_item(tree, &hfi_msg_tx_lock_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);
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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_block, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  proto_tree_add_item(tree, &hfi_msg_block_version,     tvb, offset,  4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_msg_block_prev_block,  tvb, offset, 32, ENC_NA);
  offset += 32;

  proto_tree_add_item(tree, &hfi_msg_block_merkle_root, tvb, offset, 32, ENC_NA);
  offset += 32;

  proto_tree_add_item(tree, &hfi_msg_block_time,        tvb, offset,  4, ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_msg_block_bits,        tvb, offset,  4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_msg_block_nonce,       tvb, offset,  4, ENC_LITTLE_ENDIAN);
  offset += 4;

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_block_transactions8, &hfi_msg_block_transactions16,
                  &hfi_msg_block_transactions32, &hfi_msg_block_transactions64);

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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_headers, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  get_varint(tvb, offset, &length, &count);
  add_varint_item(tree, tvb, offset, length, &hfi_msg_headers_count8, &hfi_msg_headers_count16,
                  &hfi_msg_headers_count32, &hfi_msg_headers_count64);

  offset += length;

  for (; count > 0; count--)
  {
    proto_tree *subtree;
    guint64     txcount;

    subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_bitcoin_msg, NULL, "Header");

    proto_tree_add_item(subtree, &hfi_msg_headers_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, &hfi_msg_headers_prev_block, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(subtree, &hfi_msg_headers_merkle_root, tvb, offset, 32, ENC_NA);
    offset += 32;

    proto_tree_add_item(subtree, &hfi_msg_headers_time, tvb, offset, 4, ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, &hfi_msg_headers_bits, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    proto_tree_add_item(subtree, &hfi_msg_headers_nonce, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset += 4;

    get_varint(tvb, offset, &length, &txcount);

    add_varint_item(subtree, tvb, offset, length, &hfi_msg_headers_count8, &hfi_msg_headers_count16,
                    &hfi_msg_headers_count32, &hfi_msg_headers_count64);

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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_ping, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  proto_tree_add_item(tree, &hfi_msg_ping_nonce, tvb, offset, 8, ENC_LITTLE_ENDIAN);
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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_pong, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  proto_tree_add_item(tree, &hfi_msg_pong_nonce, tvb, offset, 8, ENC_LITTLE_ENDIAN);
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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_reject, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  create_string_tree(tree, &hfi_msg_reject_message, tvb, &offset);

  proto_tree_add_item(tree, &hfi_msg_reject_ccode, tvb, offset, 1, ENC_LITTLE_ENDIAN);
  offset += 1;

  create_string_tree(tree, &hfi_msg_reject_reason, tvb, &offset);

  if ((tvb_reported_length(tvb) - offset) > 0)
  {
    proto_tree_add_item(tree, &hfi_msg_reject_data,  tvb, offset, tvb_reported_length(tvb) - offset, ENC_NA);
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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_filterload, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  create_data_tree(tree, &hfi_msg_filterload_filter, tvb, &offset);

  proto_tree_add_item(tree, &hfi_msg_filterload_nhashfunc, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_msg_filterload_ntweak, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_msg_filterload_nflags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_filteradd, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  create_data_tree(tree, &hfi_msg_filteradd_data, tvb, &offset);

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

  ti   = proto_tree_add_item(tree, &hfi_bitcoin_msg_merkleblock, tvb, offset, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin_msg);

  proto_tree_add_item(tree, &hfi_msg_merkleblock_version, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_msg_merkleblock_prev_block, tvb, offset, 32, ENC_NA);
  offset += 32;

  proto_tree_add_item(tree, &hfi_msg_merkleblock_merkle_root, tvb, offset, 32, ENC_NA);
  offset += 32;

  proto_tree_add_item(tree, &hfi_msg_merkleblock_time, tvb, offset, 4, ENC_TIME_TIMESPEC|ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_msg_merkleblock_bits, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_msg_merkleblock_nonce, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  proto_tree_add_item(tree, &hfi_msg_merkleblock_transactions, tvb, offset, 4, ENC_LITTLE_ENDIAN);
  offset += 4;

  get_varint(tvb, offset, &length, &count);

  subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_bitcoin_msg, NULL, "Hashes");

  add_varint_item(subtree, tvb, offset, length, &hfi_msg_merkleblock_hashes_count8, &hfi_msg_merkleblock_hashes_count16,
      &hfi_msg_merkleblock_hashes_count32, &hfi_msg_merkleblock_hashes_count64);
  offset += length;

  for (; count > 0; count--)
  {
    proto_tree_add_item(subtree, &hfi_msg_merkleblock_hashes_hash, tvb, offset, 32, ENC_NA);
    offset += 32;
  }

  get_varint(tvb, offset, &length, &count);

  subtree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_bitcoin_msg, NULL, "Flags");

  add_varint_item(subtree, tvb, offset, length, &hfi_msg_merkleblock_flags_size8, &hfi_msg_merkleblock_flags_size16,
                  &hfi_msg_merkleblock_flags_size32, &hfi_msg_merkleblock_flags_size64);
  offset += length;

  /* The cast to guint is save because bitcoin messages are always smaller than 0x02000000 bytes. */
  proto_tree_add_item(subtree, &hfi_msg_merkleblock_flags_data, tvb, offset, (guint)count, ENC_ASCII|ENC_NA);
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

  ti   = proto_tree_add_item(tree, hfi_bitcoin, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(ti, ett_bitcoin);

  /* add basic protocol data */
  proto_tree_add_item(tree, &hfi_bitcoin_magic,   tvb,  0,  4, ENC_BIG_ENDIAN);
  proto_tree_add_item_ret_string(tree, hfi_bitcoin_command.id, tvb,  4, 12, ENC_ASCII|ENC_NA, wmem_packet_scope(), &command);
  proto_tree_add_item(tree, &hfi_bitcoin_length,  tvb, 16,  4, ENC_LITTLE_ENDIAN);
  proto_tree_add_checksum(tree, tvb, 20, hfi_bitcoin_checksum.id, -1, NULL, pinfo, 0, ENC_BIG_ENDIAN, PROTO_CHECKSUM_NO_FLAGS);

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
#ifndef HAVE_HFI_SECTION_INIT
  static header_field_info *hfi[] = {
    &hfi_bitcoin_magic,
    &hfi_bitcoin_command,
    &hfi_bitcoin_length,
    &hfi_bitcoin_checksum,

    /* version message */
    &hfi_bitcoin_msg_version,
    &hfi_msg_version_version,
    &hfi_msg_version_services,
    &hfi_msg_version_addr_me,
    &hfi_msg_version_addr_you,
    &hfi_msg_version_timestamp,
    &hfi_msg_version_nonce,
    &hfi_msg_version_user_agent,
    &hfi_msg_version_start_height,
    &hfi_msg_version_relay,

    /* addr message */
    &hfi_msg_addr_count8,
    &hfi_msg_addr_count16,
    &hfi_msg_addr_count32,
    &hfi_msg_addr_count64,
    &hfi_bitcoin_msg_addr,
    &hfi_msg_addr_address,
    &hfi_msg_addr_timestamp,

    /* inv message */
    &hfi_msg_inv_count8,
    &hfi_msg_inv_count16,
    &hfi_msg_inv_count32,
    &hfi_msg_inv_count64,
    &hfi_bitcoin_msg_inv,
    &hfi_msg_inv_type,
    &hfi_msg_inv_hash,

    /* getdata message */
    &hfi_msg_getdata_count8,
    &hfi_msg_getdata_count16,
    &hfi_msg_getdata_count32,
    &hfi_msg_getdata_count64,
    &hfi_bitcoin_msg_getdata,
    &hfi_msg_getdata_type,
    &hfi_msg_getdata_hash,

    /* notfound message */
    &hfi_msg_notfound_count8,
    &hfi_msg_notfound_count16,
    &hfi_msg_notfound_count32,
    &hfi_msg_notfound_count64,
    &hfi_bitcoin_msg_notfound,
    &hfi_msg_notfound_type,
    &hfi_msg_notfound_hash,

    /* getblocks message */
    &hfi_msg_getblocks_count8,
    &hfi_msg_getblocks_count16,
    &hfi_msg_getblocks_count32,
    &hfi_msg_getblocks_count64,
    &hfi_bitcoin_msg_getblocks,
    &hfi_msg_getblocks_start,
    &hfi_msg_getblocks_stop,

    /* getheaders message */
    &hfi_msg_getheaders_count8,
    &hfi_msg_getheaders_count16,
    &hfi_msg_getheaders_count32,
    &hfi_msg_getheaders_count64,
    &hfi_bitcoin_msg_getheaders,
#if 0
    &hfi_msg_getheaders_version,
#endif
    &hfi_msg_getheaders_start,
    &hfi_msg_getheaders_stop,

    /* tx message */
    &hfi_bitcoin_msg_tx,
    &hfi_msg_tx_version,

    /* tx message - input */
    &hfi_msg_tx_in_count8,
    &hfi_msg_tx_in_count16,
    &hfi_msg_tx_in_count32,
    &hfi_msg_tx_in_count64,

    &hfi_msg_tx_in,
    &hfi_msg_tx_in_prev_output,

    &hfi_msg_tx_in_prev_outp_hash,
    &hfi_msg_tx_in_prev_outp_index,

    &hfi_msg_tx_in_script8,
    &hfi_msg_tx_in_script16,
    &hfi_msg_tx_in_script32,
    &hfi_msg_tx_in_script64,
    &hfi_msg_tx_in_sig_script,
    &hfi_msg_tx_in_seq,

    /* tx message - output */
    &hfi_msg_tx_out_count8,
    &hfi_msg_tx_out_count16,
    &hfi_msg_tx_out_count32,
    &hfi_msg_tx_out_count64,
    &hfi_msg_tx_out,
    &hfi_msg_tx_out_value,
    &hfi_msg_tx_out_script8,
    &hfi_msg_tx_out_script16,
    &hfi_msg_tx_out_script32,
    &hfi_msg_tx_out_script64,
    &hfi_msg_tx_out_script,

    &hfi_msg_tx_lock_time,

    /* block message */
    &hfi_msg_block_transactions8,
    &hfi_msg_block_transactions16,
    &hfi_msg_block_transactions32,
    &hfi_msg_block_transactions64,
    &hfi_bitcoin_msg_block,
    &hfi_msg_block_version,
    &hfi_msg_block_prev_block,
    &hfi_msg_block_merkle_root,
    &hfi_msg_block_time,
    &hfi_msg_block_bits,
    &hfi_msg_block_nonce,

    /* headers message */
    &hfi_bitcoin_msg_headers,
    &hfi_msg_headers_count8,
    &hfi_msg_headers_count16,
    &hfi_msg_headers_count32,
    &hfi_msg_headers_count64,
    &hfi_msg_headers_version,
    &hfi_msg_headers_prev_block,
    &hfi_msg_headers_merkle_root,
    &hfi_msg_headers_time,
    &hfi_msg_headers_bits,
    &hfi_msg_headers_nonce,

    /* ping message */
    &hfi_bitcoin_msg_ping,
    &hfi_msg_ping_nonce,

    /* pong message */
    &hfi_bitcoin_msg_pong,
    &hfi_msg_pong_nonce,

    /* reject message */
    &hfi_bitcoin_msg_reject,
    &hfi_msg_reject_ccode,
    &hfi_msg_reject_message,
    &hfi_msg_reject_reason,
    &hfi_msg_reject_data,

    /* filterload message */
    &hfi_bitcoin_msg_filterload,
    &hfi_msg_filterload_filter,
    &hfi_msg_filterload_nflags,
    &hfi_msg_filterload_nhashfunc,
    &hfi_msg_filterload_ntweak,

    /* filteradd message */
    &hfi_bitcoin_msg_filteradd,
    &hfi_msg_filteradd_data,

    /* merkleblock message */
    &hfi_bitcoin_msg_merkleblock,
    &hfi_msg_merkleblock_transactions,
    &hfi_msg_merkleblock_version,
    &hfi_msg_merkleblock_prev_block,
    &hfi_msg_merkleblock_merkle_root,
    &hfi_msg_merkleblock_time,
    &hfi_msg_merkleblock_bits,
    &hfi_msg_merkleblock_nonce,
    &hfi_msg_merkleblock_flags_data,
    &hfi_msg_merkleblock_flags_size8,
    &hfi_msg_merkleblock_flags_size16,
    &hfi_msg_merkleblock_flags_size32,
    &hfi_msg_merkleblock_flags_size64,
    &hfi_msg_merkleblock_hashes_count8,
    &hfi_msg_merkleblock_hashes_count16,
    &hfi_msg_merkleblock_hashes_count32,
    &hfi_msg_merkleblock_hashes_count64,
    &hfi_msg_merkleblock_hashes_hash,

    /* services */
    &hfi_services_network,

    /* address */
    &hfi_address_services,
    &hfi_address_address,
    &hfi_address_port,

    /* variable string */
    &hfi_string_value,
    &hfi_string_varint_count8,
    &hfi_string_varint_count16,
    &hfi_string_varint_count32,
    &hfi_string_varint_count64,

    /* variable data */
    &hfi_data_value,
    &hfi_data_varint_count8,
    &hfi_data_varint_count16,
    &hfi_data_varint_count32,
    &hfi_data_varint_count64,
  };
#endif

  static gint *ett[] = {
    &ett_bitcoin,
    &ett_bitcoin_msg,
    &ett_services,
    &ett_address,
    &ett_string,
    &ett_addr_list,
    &ett_inv_list,
    &ett_getdata_list,
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

  int proto_bitcoin;

  proto_bitcoin = proto_register_protocol("Bitcoin protocol", "Bitcoin", "bitcoin");
  hfi_bitcoin = proto_registrar_get_nth(proto_bitcoin);

  proto_register_subtree_array(ett, array_length(ett));
  proto_register_fields(proto_bitcoin, hfi, array_length(hfi));

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

  dissector_add_for_decode_as("tcp.port", bitcoin_handle);

  heur_dissector_add( "tcp", dissect_bitcoin_heur, "Bitcoin over TCP", "bitcoin_tcp", hfi_bitcoin->id, HEURISTIC_ENABLE);

  /* Register all of the commands */
  command_handle = create_dissector_handle( dissect_bitcoin_msg_version, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "version", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_addr, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "addr", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_inv, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "inv", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_getdata, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "getdata", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_getblocks, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "getblocks", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_getheaders, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "getheaders", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_tx, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "tx", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_block, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "block", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_ping, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "ping", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_pong, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "pong", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_notfound, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "notfound", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_reject, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "reject", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_headers, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "headers", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_filterload, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "filterload", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_filteradd, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "filteradd", command_handle);
  command_handle = create_dissector_handle( dissect_bitcoin_msg_merkleblock, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "merkleblock", command_handle);

  /* messages with no payload */
  command_handle = create_dissector_handle( dissect_bitcoin_msg_empty, hfi_bitcoin->id );
  dissector_add_string("bitcoin.command", "verack", command_handle);
  dissector_add_string("bitcoin.command", "getaddr", command_handle);
  dissector_add_string("bitcoin.command", "mempool", command_handle);
  dissector_add_string("bitcoin.command", "filterclear", command_handle);

  /* messages not implemented */
  /* command_handle = create_dissector_handle( dissect_bitcoin_msg_empty, hfi_bitcoin->id ); */
  dissector_add_string("bitcoin.command", "checkorder", command_handle);
  dissector_add_string("bitcoin.command", "submitorder", command_handle);
  dissector_add_string("bitcoin.command", "reply", command_handle);
  dissector_add_string("bitcoin.command", "alert", command_handle);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
